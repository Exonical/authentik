"""Test rotate_secret mixin, using tokens as the core model that carries it"""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.models import Token, TokenIntents
from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.events.models import Event, EventAction
from authentik.lib.generators import generate_id


class TestRotateSecret(APITestCase):
    """Test rotate_secret mixin"""

    def setUp(self) -> None:
        super().setUp()
        self.admin = create_test_admin_user()
        self.token = Token.objects.create(
            identifier=generate_id(), user=self.admin, intent=TokenIntents.INTENT_API
        )
        self.url = reverse(
            "authentik_api:token-rotate-secret", kwargs={"identifier": self.token.identifier}
        )

    def test_rotate(self):
        """Rotating replaces the key, does not return it, and is audited once without the secret"""
        self.client.force_login(self.admin)
        old_key = self.token.key
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.token.refresh_from_db()
        self.assertNotEqual(self.token.key, old_key)
        self.assertNotIn("key", response.json())
        events = Event.objects.filter(context__model__pk=self.token.pk.hex)
        self.assertEqual([event.action for event in events], [EventAction.SECRET_ROTATE])
        event = events.first()
        self.assertEqual(event.context["field"], "key")
        self.assertNotIn(self.token.key, str(event.context))

    def test_rotate_change_permission(self):
        """A user with change_ but not add_ can rotate"""
        user = create_test_user()
        user.assign_perms_to_managed_role("authentik_core.view_token")
        user.assign_perms_to_managed_role("authentik_core.change_token")
        self.client.force_login(user)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)

    def test_rotate_add_permission(self):
        """A user with add_ but not change_ cannot rotate"""
        user = create_test_user()
        user.assign_perms_to_managed_role("authentik_core.view_token")
        user.assign_perms_to_managed_role("authentik_core.add_token")
        self.client.force_login(user)
        old_key = self.token.key
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.token.refresh_from_db()
        self.assertEqual(self.token.key, old_key)

    def test_rotate_owner(self):
        """Owners can rotate their own tokens without explicit permissions"""
        user = create_test_user()
        token = Token.objects.create(
            identifier=generate_id(), user=user, intent=TokenIntents.INTENT_API
        )
        self.client.force_login(user)
        old_key = token.key
        response = self.client.post(
            reverse("authentik_api:token-rotate-secret", kwargs={"identifier": token.identifier})
        )
        self.assertEqual(response.status_code, 200)
        token.refresh_from_db()
        self.assertNotEqual(token.key, old_key)

    def test_rotate_not_owner(self):
        """A user without permissions cannot rotate someone else's token"""
        user = create_test_user()
        self.client.force_login(user)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 404)

    def test_update_after_rotate(self):
        """An update of an unrelated field after a rotate keeps the rotated key"""
        self.client.force_login(self.admin)
        self.client.post(self.url)
        self.token.refresh_from_db()
        rotated_key = self.token.key
        response = self.client.patch(
            reverse("authentik_api:token-detail", kwargs={"identifier": self.token.identifier}),
            {"description": generate_id()},
        )
        self.assertEqual(response.status_code, 200)
        self.token.refresh_from_db()
        self.assertEqual(self.token.key, rotated_key)
