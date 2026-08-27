"""Kerberos keytab export tests."""

import base64
import struct

from django.test import TestCase

from authentik.lib.generators import generate_id
from authentik.providers.kerberos.api.providers import build_keytab
from authentik.providers.kerberos.models import KerberosProvider, KerberosServicePrincipal


class KerberosKeytabTests(TestCase):
    """Test MIT keytab v2 export."""

    def test_keytab(self):
        """The export has a valid version and principal record."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        principal = KerberosServicePrincipal.objects.create(
            provider=provider,
            spn="HTTP/app.example.com",
        )
        keytab = build_keytab(principal)
        self.assertEqual(keytab[:2], b"\x05\x02")
        offset = 2
        entries = 0
        while offset < len(keytab):
            entry_length = struct.unpack(">i", keytab[offset : offset + 4])[0]
            offset += 4 + entry_length
            entries += 1
        self.assertEqual(offset, len(keytab))
        self.assertEqual(entries, 2)
        self.assertTrue(base64.b64decode(principal.keys["18"]) in keytab)
