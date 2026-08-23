"""rotate_secret mixin"""

from drf_spectacular.utils import extend_schema
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from authentik.events.middleware import audit_ignore
from authentik.events.models import Event, EventAction
from authentik.events.utils import model_to_dict
from authentik.rbac.filters import ObjectFilter
from authentik.rbac.permissions import ObjectPermissions


class RotateSecretPermissions(ObjectPermissions):
    """POST on a detail route is a write to an existing object, not a create,
    so it requires `change_`, not the `add_` that DRF maps POST to by default."""

    perms_map = ObjectPermissions.perms_map | {"POST": ["%(app_label)s.change_%(model_name)s"]}


class RotatableSecretMixin:
    """Mixin to add a rotate_secret endpoint which regenerates one secret field in place,
    using that field's own model default."""

    rotatable_secret: str

    @extend_schema(request=None)
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
        field = self.rotatable_secret
        setattr(instance, field, instance._meta.get_field(field).get_default())
        # The audit middleware would log a second, less specific model_updated event
        with audit_ignore():
            instance.save(update_fields=[field])
        Event.new(
            EventAction.SECRET_ROTATE,
            app=instance._meta.app_config.name,
            model=model_to_dict(instance),
            field=field,
        ).from_http(request)
        return Response(self.get_serializer(instance).data)
