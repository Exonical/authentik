"""Test RADIUS provider API"""

from unittest.mock import patch

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_flow
from authentik.lib.generators import generate_id
from authentik.outposts.models import Outpost, OutpostType
from authentik.providers.radius.models import RadiusProvider


class TestRadiusProviderAPI(APITestCase):
    """Test RADIUS provider API"""

    def setUp(self) -> None:
        self.user = create_test_admin_user()
        self.client.force_login(self.user)
        self.provider = RadiusProvider.objects.create(
            name=generate_id(), authorization_flow=create_test_flow()
        )

    def test_create_generates_secret(self):
        """An omitted or blank shared secret on create is generated with the model default"""
        for shared_secret in ({}, {"shared_secret": ""}):
            response = self.client.post(
                reverse("authentik_api:radiusprovider-list"),
                data={
                    "name": generate_id(),
                    "authorization_flow": create_test_flow().pk,
                    "invalidation_flow": create_test_flow().pk,
                    **shared_secret,
                },
                format="json",
            )
            self.assertEqual(response.status_code, 201)
            secret = response.json()["shared_secret"]
            self.assertEqual(len(secret), 40)
            self.assertTrue(secret.isalnum())

    def test_rotate_secret_notifies_outpost(self):
        """Rotating the shared secret sends the outpost its new configuration"""
        outpost = Outpost.objects.create(name=generate_id(), type=OutpostType.RADIUS)
        outpost.providers.add(self.provider)
        with patch("authentik.outposts.signals.outpost_send_update.send_with_options") as send:
            response = self.client.post(
                reverse(
                    "authentik_api:radiusprovider-rotate-secret", kwargs={"pk": self.provider.pk}
                )
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual([call.kwargs["args"] for call in send.call_args_list], [(outpost.pk,)])
