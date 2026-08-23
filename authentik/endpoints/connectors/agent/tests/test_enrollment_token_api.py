"""Test enrollment token API"""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user
from authentik.endpoints.connectors.agent.models import AgentConnector, EnrollmentToken
from authentik.lib.generators import generate_id


class TestEnrollmentTokenAPI(APITestCase):
    """Test enrollment token API"""

    def setUp(self):
        self.user = create_test_admin_user()
        self.client.force_login(self.user)
        self.connector = AgentConnector.objects.create(name=generate_id())
        self.token = EnrollmentToken.objects.create(name=generate_id(), connector=self.connector)

    def test_rotate_secret(self):
        """Rotating replaces the key without returning it"""
        old_key = self.token.key
        response = self.client.post(
            reverse(
                "authentik_api:enrollmenttoken-rotate-secret",
                kwargs={"pk": self.token.token_uuid},
            )
        )
        self.assertEqual(response.status_code, 200)
        self.token.refresh_from_db()
        self.assertNotEqual(self.token.key, old_key)
        self.assertNotIn("key", response.json())
        response = self.client.get(
            reverse("authentik_api:enrollmenttoken-view-key", kwargs={"pk": self.token.token_uuid})
        )
        self.assertEqual(response.json()["key"], self.token.key)
