"""Test OAuth2 API"""

from json import loads
from sys import version_info
from unittest import skipUnless
from unittest.mock import patch

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.blueprints.tests import apply_blueprint
from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user, create_test_flow
from authentik.lib.generators import generate_id
from authentik.outposts.models import Outpost, OutpostType
from authentik.providers.oauth2.models import (
    ClientType,
    OAuth2Provider,
    RedirectURI,
    RedirectURIMatchingMode,
    ScopeMapping,
)
from authentik.providers.proxy.models import ProxyProvider


class TestAPI(APITestCase):
    """Test api view"""

    @apply_blueprint("system/providers-oauth2.yaml")
    def setUp(self) -> None:
        self.provider: OAuth2Provider = OAuth2Provider.objects.create(
            name="test",
            authorization_flow=create_test_flow(),
            redirect_uris=[RedirectURI(RedirectURIMatchingMode.STRICT, "http://testserver")],
        )
        self.provider.property_mappings.set(ScopeMapping.objects.all())
        self.app = Application.objects.create(name="test", slug="test", provider=self.provider)
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

    def test_preview(self):
        """Test Preview API Endpoint"""
        response = self.client.get(
            reverse("authentik_api:oauth2provider-preview-user", kwargs={"pk": self.provider.pk})
        )
        self.assertEqual(response.status_code, 200)
        body = loads(response.content.decode())["preview"]
        self.assertEqual(body["iss"], "http://testserver/application/o/test/")

    def test_setup_urls(self):
        """Test Setup URLs API Endpoint"""
        response = self.client.get(
            reverse("authentik_api:oauth2provider-setup-urls", kwargs={"pk": self.provider.pk})
        )
        self.assertEqual(response.status_code, 200)
        body = loads(response.content.decode())
        self.assertEqual(body["issuer"], "http://testserver/application/o/test/")

    # https://github.com/goauthentik/authentik/pull/5918
    @skipUnless(version_info >= (3, 11, 4), "This behaviour is only Python 3.11.4 and up")
    def test_launch_url(self):
        """Test launch_url"""
        self.provider.redirect_uris = [
            RedirectURI(
                RedirectURIMatchingMode.REGEX,
                "https://[\\d\\w]+.pr.test.goauthentik.io/source/oauth/callback/authentik/",
            ),
        ]
        self.provider.save()
        self.provider.refresh_from_db()
        self.assertIsNone(self.provider.launch_url)

    def test_validate_client_id(self):
        """Test redirect_uris API"""
        response = self.client.post(
            reverse("authentik_api:oauth2provider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "client_id": "ú",
                "redirect_uris": [],
            },
        )
        self.assertJSONEqual(
            response.content,
            {"client_id": ["Client ID must consist of only ASCII characters."]},
        )

    def test_validate_client_secret(self):
        """Test redirect_uris API"""
        response = self.client.post(
            reverse("authentik_api:oauth2provider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "client_secret": "ú",
                "redirect_uris": [],
            },
        )
        self.assertJSONEqual(
            response.content,
            {"client_secret": ["Client secret must consist of only ASCII characters."]},
        )

    def test_validate_redirect_uris(self):
        """Test redirect_uris API"""
        response = self.client.post(
            reverse("authentik_api:oauth2provider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "redirect_uris": [
                    {"matching_mode": "strict", "url": "http://goauthentik.io"},
                    {"matching_mode": "regex", "url": "**"},
                ],
            },
        )
        self.assertJSONEqual(response.content, {"redirect_uris": ["Invalid Regex Pattern: **"]})

    def test_logout_uri_validation(self):
        """Test logout_uri API validation"""
        response = self.client.post(
            reverse("authentik_api:oauth2provider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "redirect_uris": [
                    {"matching_mode": "strict", "url": "http://goauthentik.io"},
                ],
                "logout_uri": "invalid-url",
                "logout_method": "backchannel",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_logout_uri_create_and_retrieve(self):
        """Test creating and retrieving logout URI with method"""
        response = self.client.post(
            reverse("authentik_api:oauth2provider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "redirect_uris": [
                    {"matching_mode": "strict", "url": "http://goauthentik.io"},
                ],
                "logout_uri": "http://goauthentik.io/logout",
                "logout_method": "backchannel",
            },
        )
        self.assertEqual(response.status_code, 201)
        provider_data = response.json()
        self.assertEqual(provider_data["logout_uri"], "http://goauthentik.io/logout")
        self.assertEqual(provider_data["logout_method"], "backchannel")

        # Test retrieving the provider
        provider_pk = provider_data["pk"]
        response = self.client.get(
            reverse("authentik_api:oauth2provider-detail", kwargs={"pk": provider_pk})
        )
        self.assertEqual(response.status_code, 200)
        retrieved_data = response.json()
        self.assertEqual(retrieved_data["logout_uri"], "http://goauthentik.io/logout")
        self.assertEqual(retrieved_data["logout_method"], "backchannel")

    def _create_data(self, **overrides) -> dict:
        data = {
            "name": generate_id(),
            "authorization_flow": create_test_flow().pk,
            "invalidation_flow": create_test_flow().pk,
            "redirect_uris": [],
        }
        data.update(overrides)
        return data

    def test_create_generates_credentials(self):
        """Omitted or blank credentials on create are generated with the model defaults"""
        for data in (self._create_data(), self._create_data(client_id="", client_secret="")):
            response = self.client.post(
                reverse("authentik_api:oauth2provider-list"), data=data, format="json"
            )
            self.assertEqual(response.status_code, 201)
            body = response.json()
            self.assertEqual(len(body["client_id"]), 40)
            self.assertTrue(body["client_id"].isalnum())
            self.assertEqual(len(body["client_secret"]), 128)
            self.assertTrue(body["client_secret"].isalnum())

    def test_create_explicit_client_id(self):
        """An explicit client_id is kept"""
        client_id = generate_id()
        response = self.client.post(
            reverse("authentik_api:oauth2provider-list"),
            data=self._create_data(client_id=client_id),
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["client_id"], client_id)

    def test_blank_secret_confidential(self):
        """A confidential client cannot end up with an empty secret"""
        url = reverse("authentik_api:oauth2provider-detail", kwargs={"pk": self.provider.pk})
        response = self.client.patch(url, data={"client_secret": ""}, format="json")
        self.assertJSONEqual(
            response.content,
            {"client_secret": ["Confidential clients require a client secret."]},
        )
        self.provider.client_type = ClientType.PUBLIC
        self.provider.client_secret = ""
        self.provider.save()
        response = self.client.patch(
            url, data={"client_type": ClientType.CONFIDENTIAL}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_blank_secret_public(self):
        """A public client can have an empty secret"""
        response = self.client.patch(
            reverse("authentik_api:oauth2provider-detail", kwargs={"pk": self.provider.pk}),
            data={"client_type": ClientType.PUBLIC, "client_secret": ""},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["client_secret"], "")

    def test_rotate_secret_proxy_provider(self):
        """A proxy provider is reachable through the OAuth2 endpoint by multi-table
        inheritance, and its outpost is still told about the change"""
        proxy = ProxyProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            external_host="http://localhost",
            internal_host="http://localhost",
        )
        outpost = Outpost.objects.create(name=generate_id(), type=OutpostType.PROXY)
        outpost.providers.add(proxy)
        old_secret = proxy.client_secret
        with patch("authentik.outposts.signals.outpost_send_update.send_with_options") as send:
            response = self.client.post(
                reverse("authentik_api:oauth2provider-rotate-secret", kwargs={"pk": proxy.pk})
            )
        self.assertEqual(response.status_code, 200)
        proxy.refresh_from_db()
        self.assertNotEqual(proxy.client_secret, old_secret)
        self.assertEqual([call.kwargs["args"] for call in send.call_args_list], [(outpost.pk,)])
