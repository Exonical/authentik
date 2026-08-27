"""Kerberos crypto tests."""

from django.test import SimpleTestCase

from authentik.providers.kerberos.crypto import derive_krbtgt_key, string2key


class KerberosCryptoTests(SimpleTestCase):
    """Test standards-compliant Kerberos key derivation."""

    def test_rfc3962_vectors(self):
        """Test RFC 3962 Appendix B vectors."""
        salt = b"ATHENA.MIT.EDUraeburn"
        self.assertEqual(
            string2key(b"password", salt, 17, 1).hex(),
            "42263c6e89f4fc28b8df68ee09799f15",
        )
        self.assertEqual(
            string2key(b"password", salt, 18, 1).hex(),
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
        )

    def test_rfc8009_vectors(self):
        """Test RFC 8009 Appendix A vectors."""
        salt = (
            b"\x10\xdf\x9d\xd7\x83\xe5\xbc\x8a\xce\xa1\x73\x0e\x74\x35\x5f\x61"
            b"ATHENA.MIT.EDUraeburn"
        )
        self.assertEqual(
            string2key(b"password", salt, 19).hex(),
            "089bca48b105ea6ea77ca5d2f39dc5e7",
        )
        self.assertEqual(
            string2key(b"password", salt, 20).hex(),
            "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467",
        )

    def test_krbtgt_derivation_is_deterministic(self):
        """Master key derivation is stable and enctype-specific."""
        master_key = b"m" * 64
        self.assertEqual(derive_krbtgt_key(master_key, 18), derive_krbtgt_key(master_key, 18))
        self.assertNotEqual(derive_krbtgt_key(master_key, 17), derive_krbtgt_key(master_key, 18))
