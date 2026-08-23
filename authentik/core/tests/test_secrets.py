"""Test generated secrets: the rotate_secret endpoint, and rotation without a request"""

from django.urls import reverse
from rest_framework.routers import BaseRouter
from rest_framework.test import APITestCase

from authentik.api.v3.urls import router
from authentik.core.api.secrets import RotatableSecretMixin
from authentik.core.models import Token, TokenIntents
from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.events.models import Event, EventAction
from authentik.lib.generators import generate_id


class TestRotatableSecrets(APITestCase):
    """Every viewset that offers rotation, checked the same way"""

    def rotatable_viewsets(self, router: BaseRouter = router):
        """Viewsets that mix in rotation, with the route prefix they are registered under"""
        for registration in router.registry:
            prefix, viewset = registration[0], registration[1]
            if issubclass(viewset, RotatableSecretMixin):
                yield prefix, viewset

    def test_rotatable_secret_declared(self):
        """Each one names a model field that generates its own value"""
        viewsets = list(self.rotatable_viewsets())
        self.assertNotEqual(viewsets, [])
        for prefix, viewset in viewsets:
            with self.subTest(prefix):
                field = viewset.queryset.model._meta.get_field(viewset.rotatable_secret)
                self.assertTrue(callable(field.get_default()) or field.get_default())

    def test_rotatable_secret_readable(self):
        """The endpoint returns the new value only where a read of the object returns it too"""
        for prefix, viewset in self.rotatable_viewsets():
            with self.subTest(prefix):
                field = viewset.serializer_class().fields.get(viewset.rotatable_secret)
                readable = bool(field) and not field.write_only
                self.assertEqual(readable, viewset.rotatable_secret != "key")


class TestRotateSecret(APITestCase):
    """Rotation of one secret, using tokens as the model that carries the mixin"""

    def setUp(self) -> None:
        super().setUp()
        self.admin = create_test_admin_user()
        self.token = Token.objects.create(
            identifier=generate_id(), user=self.admin, intent=TokenIntents.INTENT_API
        )
        self.url = reverse(
            "authentik_api:token-rotate-secret", kwargs={"identifier": self.token.identifier}
        )

    def events(self, token: Token) -> list[Event]:
        return list(Event.objects.filter(context__model__pk=token.pk.hex))

    def test_rotate(self):
        """Rotating replaces the key, withholds it, and is audited once without the secret"""
        self.client.force_login(self.admin)
        old_key = self.token.key
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.token.refresh_from_db()
        self.assertNotEqual(self.token.key, old_key)
        self.assertIsNone(response.json()["secret"])
        events = self.events(self.token)
        self.assertEqual([event.action for event in events], [EventAction.SECRET_ROTATE])
        self.assertEqual(events[0].context["field"], "key")
        self.assertNotIn(self.token.key, str(events[0].context))

    def test_rotate_without_request(self):
        """An expiring API token rotates through the same operation, recording the same event"""
        token = Token.objects.create(
            identifier=generate_id(), user=self.admin, intent=TokenIntents.INTENT_API
        )
        old_key = token.key
        token.expire_action()
        token.refresh_from_db()
        self.assertNotEqual(token.key, old_key)
        events = self.events(token)
        self.assertEqual([event.action for event in events], [EventAction.SECRET_ROTATE])
        self.assertEqual(events[0].context["field"], "key")
        self.assertNotIn(token.key, str(events[0].context))

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
