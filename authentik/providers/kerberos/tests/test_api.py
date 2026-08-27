"""Kerberos provider API tests."""

from json import loads

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user, create_test_user
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
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        self.client.force_login(create_test_admin_user())
        response = self.client.get(reverse("authentik_api:kerberosprovideroutpost-list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(loads(response.content)["pagination"]["count"], 1)

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
