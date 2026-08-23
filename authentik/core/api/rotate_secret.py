"""rotate_secret mixin"""

from drf_spectacular.utils import extend_schema
from rest_framework.decorators import action
from rest_framework.fields import CharField
from rest_framework.request import Request
from rest_framework.response import Response

from authentik.core.api.utils import PassiveSerializer
from authentik.events.middleware import audit_ignore
from authentik.events.models import Event, EventAction
from authentik.events.utils import model_to_dict
from authentik.rbac.filters import ObjectFilter
from authentik.rbac.permissions import ObjectPermissions


class RotatedSecretSerializer(PassiveSerializer):
    """The newly generated secret, or null when the field is not readable on the object"""

    secret = CharField(read_only=True, allow_null=True)


class RotateSecretPermissions(ObjectPermissions):
    """POST on a detail route is a write to an existing object, not a create,
    so it requires `change_`, not the `add_` that DRF maps POST to by default."""

    perms_map = ObjectPermissions.perms_map | {"POST": ["%(app_label)s.change_%(model_name)s"]}


class RotatableSecretMixin:
    """Mixin to add a rotate_secret endpoint which regenerates one secret field in place,
    using that field's own model default."""

    rotatable_secret: str

    @extend_schema(request=None, responses={200: RotatedSecretSerializer})
    @action(
        detail=True,
        methods=["POST"],
        filter_backends=[ObjectFilter],
        permission_classes=[RotateSecretPermissions],
    )
    def rotate_secret(self, request: Request, *args, **kwargs) -> Response:
        """Replace the secret with a newly generated value. The old value stops working
        immediately."""
        instance = self.get_object()
        name = self.rotatable_secret
        setattr(instance, name, instance._meta.get_field(name).get_default())
        # The audit middleware would log a second, less specific model_updated event
        with audit_ignore():
            instance.save(update_fields=[name])
        Event.new(
            EventAction.SECRET_ROTATE,
            app=instance._meta.app_config.name,
            model=model_to_dict(instance),
            field=name,
        ).from_http(request)
        # Hand the new value back only when a read would return it anyway; token keys stay behind
        # their own view_key endpoint.
        field = self.get_serializer().fields.get(name)
        secret = getattr(instance, name) if field and not field.write_only else None
        return Response(RotatedSecretSerializer({"secret": secret}).data)
