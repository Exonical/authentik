"""Secrets authentik generates for itself: token keys, client secrets, shared secrets.

Each takes its value from its model field's default, so a secret is the same strength wherever it
is created. Rotation is this function, not the endpoint in `authentik.core.api.secrets` that calls
it: an API token whose key is replaced when it expires rotates through here too.
"""

from django.db.models import Model
from django.http import HttpRequest

from authentik.events.middleware import audit_ignore
from authentik.events.models import Event, EventAction
from authentik.events.utils import model_to_dict


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
