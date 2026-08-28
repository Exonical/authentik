"""Kerberos provider API tests."""

from json import loads

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_user
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.generators import generate_id
from authentik.providers.kerberos.models import (
    KerberosProvider,
    KerberosServicePrincipal,
    KerberosUserKeys,
)


class KerberosProviderAPITests(APITestCase):
    """Test Kerberos outpost configuration API."""

    def test_outpost_config(self):
        """An application-backed provider is visible to outposts."""
        certificate = create_test_cert()
        client_ca = CertificateKeyPair.objects.create(
            name=generate_id(),
            certificate_data=certificate.certificate_data,
        )
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            pkinit_certificate=certificate,
            pkinit_client_ca=client_ca,
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        self.client.force_login(create_test_admin_user())
        response = self.client.get(reverse("authentik_api:kerberosprovideroutpost-list"))
        self.assertEqual(response.status_code, 200)
        payload = loads(response.content)
        self.assertEqual(payload["pagination"]["count"], 1)
        self.assertEqual(payload["results"][0]["pkinit_certificate"], str(certificate.pk))
        self.assertEqual(payload["results"][0]["pkinit_client_ca"], str(client_ca.pk))
        provider_response = self.client.get(
            reverse("authentik_api:kerberosprovider-detail", kwargs={"pk": provider.pk})
        )
        self.assertEqual(provider_response.status_code, 200)
        self.assertEqual(provider_response.json()["pkinit_certificate"], str(certificate.pk))
        self.assertEqual(provider_response.json()["pkinit_client_ca"], str(client_ca.pk))

    def test_outpost_service_principals_is_paginated(self):
        """Service principals use the paginated response declared by the schema."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        KerberosServicePrincipal.objects.create(provider=provider, spn="host/example")
        KerberosServicePrincipal.objects.create(provider=provider, spn="http/example")
        self.client.force_login(create_test_admin_user())

        response = self.client.get(
            reverse(
                "authentik_api:kerberosprovideroutpost-service-principals",
                kwargs={"pk": provider.pk},
            )
        )

        self.assertEqual(response.status_code, 200)
        payload = loads(response.content)
        self.assertEqual(payload["pagination"]["count"], 2)
        self.assertEqual(
            [item["spn"] for item in payload["results"]], ["host/example", "http/example"]
        )

    def test_user_key_uses_email_mapping(self):
        """User keys can be looked up by the configured email attribute."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            principal_username_attribute="email",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        user = create_test_user(username=generate_id(), email="user@example.com")
        KerberosUserKeys.objects.update_or_create(
            provider=provider,
            user=user,
            defaults={"salt": "EXAMPLE.COMuser", "keys": {"18": "key"}},
        )
        self.client.force_login(create_test_admin_user())

        response = self.client.get(
            reverse(
                "authentik_api:kerberosprovideroutpost-user-key",
                kwargs={"pk": provider.pk},
            ),
            {"username": "user@example.com"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], user.username)

    def test_user_key_uses_upn_with_username_fallback(self):
        """UPN mapping uses the attribute and falls back to username."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            principal_username_attribute="upn",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        user = create_test_user(username=generate_id())
        user.attributes = {"upn": "user@example.com"}
        user.save(update_fields=["attributes"])
        KerberosUserKeys.objects.update_or_create(
            provider=provider,
            user=user,
            defaults={"salt": "EXAMPLE.COMuser", "keys": {"18": "key"}},
        )
        self.client.force_login(create_test_admin_user())

        upn_response = self.client.get(
            reverse(
                "authentik_api:kerberosprovideroutpost-user-key",
                kwargs={"pk": provider.pk},
            ),
            {"username": "user@example.com"},
        )
        fallback_response = self.client.get(
            reverse(
                "authentik_api:kerberosprovideroutpost-user-key",
                kwargs={"pk": provider.pk},
            ),
            {"username": user.username},
        )

        self.assertEqual(upn_response.status_code, 200)
        self.assertEqual(fallback_response.status_code, 200)

    def test_set_password_changes_user_password_and_keys(self):
        """The outpost can change a user's password through the provider."""
        user = create_test_user()
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        keys, _ = KerberosUserKeys.objects.update_or_create(
            user=user,
            provider=provider,
            defaults={"salt": "EXAMPLE.COM" + user.username, "keys": {"18": "old-key"}},
        )
        self.client.force_login(create_test_admin_user())

        response = self.client.post(
            reverse(
                "authentik_api:kerberosprovideroutpost-set-password",
                kwargs={"pk": provider.pk},
            ),
            {"username": user.username, "password": "new-password"},
            format="json",
        )

        self.assertEqual(response.status_code, 204)
        user.refresh_from_db()
        keys.refresh_from_db()
        self.assertTrue(user.check_password("new-password"))
        self.assertEqual(keys.kvno, 2)
        self.assertNotEqual(keys.keys, {"18": "old-key"})

    def test_set_password_honors_username_mapping(self):
        """Password changes use the provider's principal username attribute."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            principal_username_attribute="email",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        user = create_test_user(email="user@example.com")
        self.client.force_login(create_test_admin_user())

        response = self.client.post(
            reverse(
                "authentik_api:kerberosprovideroutpost-set-password",
                kwargs={"pk": provider.pk},
            ),
            {"username": user.email, "password": "mapped-password"},
            format="json",
        )

        self.assertEqual(response.status_code, 204)
        user.refresh_from_db()
        self.assertTrue(user.check_password("mapped-password"))

    def test_set_password_allows_users_without_keys(self):
        """Password changes do not require a pre-existing key record."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        user = create_test_user()
        self.client.force_login(create_test_admin_user())

        response = self.client.post(
            reverse(
                "authentik_api:kerberosprovideroutpost-set-password",
                kwargs={"pk": provider.pk},
            ),
            {"username": user.username, "password": "new-password"},
            format="json",
        )

        self.assertEqual(response.status_code, 204)
        self.assertTrue(KerberosUserKeys.objects.filter(user=user, provider=provider).exists())

    def test_set_password_disabled_or_unknown_user_returns_not_found(self):
        """Disabled providers and unknown users are hidden from outposts."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            kpasswd_enabled=False,
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-set-password",
            kwargs={"pk": provider.pk},
        )

        disabled_response = self.client.post(
            url,
            {"username": "missing", "password": "new-password"},
            format="json",
        )
        self.assertEqual(disabled_response.status_code, 404)

        provider.kpasswd_enabled = True
        provider.save(update_fields=["kpasswd_enabled"])
        missing_response = self.client.post(
            url,
            {"username": "missing", "password": "new-password"},
            format="json",
        )
        self.assertEqual(missing_response.status_code, 404)
