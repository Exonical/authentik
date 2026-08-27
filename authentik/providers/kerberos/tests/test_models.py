"""Kerberos provider model and signal tests."""

import base64

from django.test import TestCase

from authentik.core.signals import password_validated
from authentik.core.tests.utils import create_test_user
from authentik.lib.generators import generate_id
from authentik.providers.kerberos.crypto import string2key
from authentik.providers.kerberos.models import (
    KerberosProvider,
    KerberosServicePrincipal,
    KerberosUserKeys,
)


class KerberosProviderTests(TestCase):
    """Test Kerberos provider models."""

    def test_service_principal_keys(self):
        """Service principal keys are generated per allowed enctype."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name=generate_id())
        principal = KerberosServicePrincipal.objects.create(
            provider=provider,
            spn="HTTP/app.example.com",
        )
        self.assertEqual(set(principal.keys), {"18", "20"})
        self.assertEqual(len(base64.b64decode(principal.keys["18"])), 32)
        self.assertEqual(len(base64.b64decode(principal.keys["20"])), 32)

    def test_service_principal_key_lengths_follow_enctypes(self):
        """AES-128 service keys contain 128 bits."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name=generate_id(),
            allowed_enctypes=[17, 19],
        )
        principal = KerberosServicePrincipal.objects.create(
            provider=provider,
            spn="HTTP/app.example.com",
        )
        self.assertEqual(len(base64.b64decode(principal.keys["17"])), 16)
        self.assertEqual(len(base64.b64decode(principal.keys["19"])), 16)

    def test_password_change_updates_keys(self):
        """Password changes create keys and increment kvno."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        user = create_test_user()
        keys = KerberosUserKeys.objects.get(provider=provider, user=user)
        self.assertEqual(keys.kvno, 1)
        user.set_password("first-password")
        keys.refresh_from_db()
        self.assertEqual(keys.kvno, 2)
        user.set_password("second-password")
        keys.refresh_from_db()
        self.assertEqual(keys.kvno, 3)

    def test_password_validation_backfills_keys(self):
        """Successful password validation creates keys for existing users."""
        user = create_test_user()
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        password = "validated-password"

        password_validated.send(sender=self.__class__, user=user, password=password)

        keys = KerberosUserKeys.objects.get(provider=provider, user=user)
        self.assertEqual(keys.kvno, 1)
        self.assertEqual(keys.salt, f"{provider.realm_name}{user.username}")
        self.assertEqual(
            keys.keys["18"],
            base64.b64encode(string2key(password, keys.salt, 18)).decode(),
        )
        self.assertNotIn(password, keys.salt)
        self.assertNotIn(password, keys.keys.values())

    def test_password_validation_does_not_modify_existing_keys(self):
        """Subsequent successful password validation leaves existing keys unchanged."""
        user = create_test_user()
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        password = "validated-password"
        password_validated.send(sender=self.__class__, user=user, password=password)
        keys = KerberosUserKeys.objects.get(provider=provider, user=user)
        original_keys = keys.keys
        original_salt = keys.salt

        password_validated.send(sender=self.__class__, user=user, password="another-password")

        keys.refresh_from_db()
        self.assertEqual(keys.kvno, 1)
        self.assertEqual(keys.keys, original_keys)
        self.assertEqual(keys.salt, original_salt)
