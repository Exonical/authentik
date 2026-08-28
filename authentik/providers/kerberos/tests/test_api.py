"""Kerberos provider API tests."""

from json import loads

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_user
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.generators import generate_id
from authentik.policies.dummy.models import DummyPolicy
from authentik.policies.models import PolicyBinding
from authentik.providers.kerberos.api.providers import KerberosServicePrincipalSerializer
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
        KerberosServicePrincipal.objects.create(
            provider=provider,
            spn="host/example",
            ok_to_auth_as_delegate=True,
            allowed_delegation_targets=["nfs/example"],
        )
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
        self.assertEqual(payload["results"][0]["ok_to_auth_as_delegate"], True)
        self.assertEqual(payload["results"][0]["allowed_delegation_targets"], ["nfs/example"])

    def test_service_principal_serializer_round_trip(self):
        """Service principal delegation settings round-trip through the serializer."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        serializer = KerberosServicePrincipalSerializer(
            data={
                "provider": provider.pk,
                "spn": "HTTP/example",
                "ok_to_auth_as_delegate": True,
                "allowed_delegation_targets": ["nfs/example", "HTTP/other"],
            }
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        principal = serializer.save()
        self.assertTrue(principal.ok_to_auth_as_delegate)
        self.assertEqual(
            principal.allowed_delegation_targets,
            ["nfs/example", "HTTP/other"],
        )
        self.assertEqual(
            KerberosServicePrincipalSerializer(principal).data["allowed_delegation_targets"],
            ["nfs/example", "HTTP/other"],
        )

    def test_service_principal_serializer_rejects_non_string_targets(self):
        """Delegation targets must be non-empty strings."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        serializer = KerberosServicePrincipalSerializer(
            data={
                "provider": provider.pk,
                "spn": "HTTP/example",
                "allowed_delegation_targets": ["nfs/example", 42],
            }
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("allowed_delegation_targets", serializer.errors)

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
        self.assertEqual(response.json()["principal"], user.email)

        alias_response = self.client.get(
            reverse(
                "authentik_api:kerberosprovideroutpost-user-key",
                kwargs={"pk": provider.pk},
            ),
            {"username": user.username},
        )
        self.assertEqual(alias_response.status_code, 200)
        self.assertEqual(alias_response.json()["username"], user.username)
        self.assertEqual(alias_response.json()["principal"], user.email)

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
        self.assertEqual(upn_response.json()["principal"], "user@example.com")
        self.assertEqual(fallback_response.json()["principal"], "user@example.com")

    def test_user_key_uses_username_as_canonical_principal(self):
        """Username mapping returns the username as the canonical principal."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            principal_username_attribute="username",
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
            defaults={"salt": "EXAMPLE.COM" + user.username, "keys": {"18": "key"}},
        )
        self.client.force_login(create_test_admin_user())

        response = self.client.get(
            reverse(
                "authentik_api:kerberosprovideroutpost-user-key",
                kwargs={"pk": provider.pk},
            ),
            {"username": user.email},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["principal"], user.username)

    def test_user_key_alias_miss_returns_not_found(self):
        """Unknown aliases and blank canonical values are not returned."""
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
        user = create_test_user(username=generate_id(), email="")
        KerberosUserKeys.objects.update_or_create(
            provider=provider,
            user=user,
            defaults={"salt": "EXAMPLE.COM" + user.username, "keys": {"18": "key"}},
        )
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-user-key",
            kwargs={"pk": provider.pk},
        )

        self.assertEqual(self.client.get(url, {"username": "missing"}).status_code, 404)
        self.assertEqual(self.client.get(url, {"username": user.username}).status_code, 404)

    def test_access_check_application_policy(self):
        """Application policy bindings allow or deny Kerberos access."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        application = Application.objects.create(
            name=generate_id(), slug=generate_id(), provider=provider
        )
        user = create_test_user()
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-access-check",
            kwargs={"pk": provider.pk},
        )

        allowed = self.client.get(url, {"username": user.username})
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.json()["access"]["passing"])

        PolicyBinding.objects.create(
            target=application,
            policy=DummyPolicy.objects.create(
                name=generate_id(), result=False, wait_min=0, wait_max=1
            ),
            order=0,
        )
        denied = self.client.get(url, {"username": user.username})
        self.assertEqual(denied.status_code, 200)
        self.assertFalse(denied.json()["access"]["passing"])

    def test_access_check_service_principal_policy(self):
        """Service-principal bindings gate only the matching service ticket."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        Application.objects.create(name=generate_id(), slug=generate_id(), provider=provider)
        user = create_test_user()
        service = KerberosServicePrincipal.objects.create(provider=provider, spn="host/example")
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-access-check",
            kwargs={"pk": provider.pk},
        )

        self.assertTrue(
            self.client.get(url, {"username": user.username, "spn": service.spn}).json()["access"][
                "passing"
            ]
        )
        PolicyBinding.objects.create(
            target=service,
            policy=DummyPolicy.objects.create(
                name=generate_id(), result=False, wait_min=0, wait_max=1
            ),
            order=0,
        )
        denied = self.client.get(url, {"username": user.username, "spn": service.spn})
        self.assertEqual(denied.status_code, 200)
        self.assertFalse(denied.json()["access"]["passing"])

        PolicyBinding.objects.filter(target=service).delete()
        PolicyBinding.objects.create(
            target=service,
            policy=DummyPolicy.objects.create(
                name=generate_id(), result=True, wait_min=0, wait_max=1
            ),
            order=0,
        )
        allowed = self.client.get(url, {"username": user.username, "spn": service.spn})
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.json()["access"]["passing"])

    def test_access_check_alias_and_unknown_service(self):
        """Access checks resolve aliases and ignore unmanaged service names."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            principal_username_attribute="email",
        )
        Application.objects.create(name=generate_id(), slug=generate_id(), provider=provider)
        user = create_test_user(email="user@example.com")
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-access-check",
            kwargs={"pk": provider.pk},
        )

        response = self.client.get(url, {"username": user.username, "spn": "kadmin/changepw"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["access"]["passing"])
        missing = self.client.get(url, {"username": "missing@example.com"})
        self.assertEqual(missing.status_code, 404)

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
