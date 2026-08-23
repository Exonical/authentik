from django.db.models import Model
from django.http import HttpRequest

from authentik.events.middleware import audit_ignore
from authentik.events.models import Event, EventAction
from authentik.events.utils import model_to_dict


def rotate_secret(instance: Model, field: str, request: HttpRequest | None = None) -> str:
    """Replace `field` with a newly generated value, taken from the field's own model default.

    Returns the new value, and records a `secret_rotate` event for the object and the field.
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
