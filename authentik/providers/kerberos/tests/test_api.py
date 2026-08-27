"""Kerberos provider API tests."""

from json import loads

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user
from authentik.lib.generators import generate_id
from authentik.providers.kerberos.models import KerberosProvider, KerberosServicePrincipal


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
        self.assertEqual([item["spn"] for item in payload["results"]], ["host/example", "http/example"])
