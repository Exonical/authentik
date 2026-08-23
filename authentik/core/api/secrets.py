from drf_spectacular.utils import extend_schema
from rest_framework.decorators import action
from rest_framework.fields import CharField
from rest_framework.request import Request
from rest_framework.response import Response

from authentik.core.api.utils import PassiveSerializer
from authentik.core.secrets import rotate_secret
from authentik.rbac.filters import ObjectFilter
from authentik.rbac.permissions import ObjectPermissions


class GeneratedFieldsMixin:
    """Serializer mixin: a blank `generated_fields` entry on create means "generate it".

    Being generated does not make a field rotatable. A client ID identifies a provider to its
    clients, so replacing it renames the client rather than re-securing it.
    """

    generated_fields: tuple[str, ...] = ()

    def to_internal_value(self, data):
        if not self.instance and isinstance(data, dict):
            blank = [field for field in self.generated_fields if data.get(field) == ""]
            if blank:
                data = data.copy()
                for field in blank:
                    del data[field]
        return super().to_internal_value(data)


class RotatedSecretSerializer(PassiveSerializer):
    """The newly generated secret, or null when the field is not readable on the object"""

    secret = CharField(read_only=True, allow_null=True)


class RotateSecretPermissions(ObjectPermissions):
    """A POST on a detail route writes to an object that already exists, so it takes `change_`
    rather than the `add_` that DRF maps POST to."""

    perms_map = {**ObjectPermissions.perms_map, "POST": ["%(app_label)s.change_%(model_name)s"]}


class RotatableSecretMixin:
    """Viewset mixin adding `rotate_secret` for the field named by `rotatable_secret`."""

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
        value = rotate_secret(instance, name, request)
        # Hand the new value back only when a read would return it anyway; token keys stay behind
        # their own view_key endpoint.
        field = self.get_serializer().fields.get(name)
        readable = field and not field.write_only
        return Response(RotatedSecretSerializer({"secret": value if readable else None}).data)
