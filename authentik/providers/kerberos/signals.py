"""Kerberos provider signals."""

import base64

from django.dispatch import receiver

from authentik.core.models import User
from authentik.core.signals import password_changed, password_validated
from authentik.providers.kerberos.crypto import string2key
from authentik.providers.kerberos.models import KerberosProvider, KerberosUserKeys


def derive_user_keys(
    provider: KerberosProvider, user: User, password: str
) -> tuple[str, dict[str, str]]:
    """Derive a user's Kerberos keys for a provider."""
    salt = f"{provider.realm_name}{user.username}"
    keys = {
        str(enctype): base64.b64encode(string2key(password, salt, enctype)).decode()
        for enctype in provider.allowed_enctypes
    }
    return salt, keys


@receiver(password_changed)
def kerberos_update_user_keys(sender, user: User, password: str, **_):
    """Derive and persist a user's keys for every configured Kerberos provider.

    Users who have never set or changed a password after provider creation do not
    have a record; the outpost treats those principals as unknown.
    """
    for provider in KerberosProvider.objects.all():
        salt, keys = derive_user_keys(provider, user, password)
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


@receiver(password_validated)
def kerberos_backfill_user_keys(sender, user: User, password: str, **_):
    """Backfill a user's Kerberos keys after successful password validation."""
    for provider in KerberosProvider.objects.all():
        if KerberosUserKeys.objects.filter(user=user, provider=provider).exists():
            continue
        salt, keys = derive_user_keys(provider, user, password)
        KerberosUserKeys.objects.create(user=user, provider=provider, keys=keys, salt=salt)
