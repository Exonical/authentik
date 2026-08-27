"""Kerberos provider model and signal tests."""

import base64

from django.test import TestCase

from authentik.core.tests.utils import create_test_user
from authentik.lib.generators import generate_id
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
