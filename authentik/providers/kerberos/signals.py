"""Kerberos provider signals."""

import base64

from django.dispatch import receiver

from authentik.core.models import User
from authentik.core.signals import password_changed
from authentik.providers.kerberos.crypto import string2key
from authentik.providers.kerberos.models import KerberosProvider, KerberosUserKeys


@receiver(password_changed)
def kerberos_update_user_keys(sender, user: User, password: str, **_):
    """Derive and persist a user's keys for every active Kerberos provider.

    Users who have never set or changed a password after provider creation do not
    have a record; the outpost treats those principals as unknown.
    """
    for provider in KerberosProvider.objects.filter(enabled=True):
        salt = f"{provider.realm_name}{user.username}"
        keys = {
            str(enctype): base64.b64encode(string2key(password, salt, enctype)).decode()
            for enctype in provider.allowed_enctypes
        }
        user_keys, created = KerberosUserKeys.objects.get_or_create(
            user=user,
            provider=provider,
            defaults={"keys": keys, "salt": salt},
        )
        if not created:
            user_keys.kvno += 1
            user_keys.keys = keys
            user_keys.salt = salt
            user_keys.save(update_fields=["kvno", "keys", "salt"])
