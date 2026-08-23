"""Secrets that authentik generates for itself, and how they are replaced.

authentik issues some secrets on its own: OAuth2 client secrets, RADIUS shared secrets, token
keys, agent enrollment token keys. Every one of them takes its value from the model field's own
default, so a secret has the same strength wherever it comes from, be that the Admin interface,
the API, or a blueprint. Nothing generates credentials in the browser.

Two declarations cover the whole feature:

`generated_fields` on a serializer lists the fields authentik fills in. Sending one of them blank
on create means "generate it", the same as leaving it out.

`rotatable_secret` on a viewset names the single field that can be replaced later, which adds the
`rotate_secret` endpoint. Not every generated field is rotatable: a client ID is generated once
and then identifies the provider to its clients, so replacing it renames the client rather than
re-securing it.

Rotation is an operation, not an endpoint. `rotate_secret()` is the whole of it, so the paths that
replace a secret without anyone pressing a button go through the same function and record the same
`secret_rotate` event, such as an API token whose key is replaced when it expires
(see `authentik.core.models.Token.expire_action`).
"""

from django.db.models import Model
from django.http import HttpRequest
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


def rotate_secret(instance: Model, field: str, request: HttpRequest | None = None) -> str:
    """Replace `field` with a newly generated value, taken from the field's own model default.

    The old value stops working at once. Returns the new value, and records a `secret_rotate`
    event for the object and the field.
    """
    value = instance._meta.get_field(field).get_default()
    setattr(instance, field, value)
    # The audit middleware would log a second, less specific model_updated event
    with audit_ignore():
        instance.save(update_fields=[field])
    event = Event.new(
        EventAction.SECRET_ROTATE,
        app=instance._meta.app_config.name,
        model=model_to_dict(instance),
        field=field,
    )
    if request:
        event.from_http(request)
    else:
        event.save()
    return value


class GeneratedFieldsMixin:
    """Serializer mixin: a blank `generated_fields` entry on create means "generate it"."""

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
