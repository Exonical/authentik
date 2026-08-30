"""Kerberos provider API tests."""

import base64
from datetime import timedelta
from json import loads

from django.urls import reverse
from rest_framework.exceptions import ValidationError
from rest_framework.test import APITestCase

from authentik.core.models import Application, Group
from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_user
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.generators import generate_id
from authentik.policies.dummy.models import DummyPolicy
from authentik.policies.expiry.models import PasswordExpiryPolicy
from authentik.policies.models import PolicyBinding
from authentik.providers.kerberos.api.providers import (
    KerberosOutpostConfigSerializer,
    KerberosProviderSerializer,
    KerberosRealmTrustSerializer,
    KerberosRealmTrustViewSet,
    KerberosServicePrincipalSerializer,
    KerberosUserKeyOutpostSerializer,
)
from authentik.providers.kerberos.models import (
    KerberosProvider,
    KerberosRealmTrust,
    KerberosServicePrincipal,
    KerberosUserKeys,
)
from authentik.stages.authenticator.oath import TOTP
from authentik.stages.authenticator_static.models import StaticDevice, StaticToken
from authentik.stages.authenticator_totp.models import TOTPDevice


class KerberosProviderAPITests(APITestCase):
    """Test Kerberos outpost configuration API."""

    def test_advanced_protocol_settings_serializer_round_trip(self):
        """Advanced protocol settings round-trip through both serializers."""
        certificate = create_test_cert()
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            spake_enabled=True,
            pkinit_require_freshness=True,
            anonymous_pkinit_enabled=True,
            kkdcp_enabled=True,
            kkdcp_certificate=certificate,
            pkinit_indicators=["pkinit"],
            spake_indicators=["spake", "hardware"],
            encrypted_challenge_indicator="encrypted",
        )
        serializer = KerberosProviderSerializer(provider)
        self.assertTrue(serializer.data["spake_enabled"])
        self.assertTrue(serializer.data["pkinit_require_freshness"])
        self.assertTrue(serializer.data["anonymous_pkinit_enabled"])
        self.assertTrue(serializer.data["kkdcp_enabled"])
        self.assertEqual(serializer.data["kkdcp_certificate"], certificate.pk)
        self.assertEqual(serializer.data["pkinit_indicators"], ["pkinit"])
        self.assertEqual(serializer.data["spake_indicators"], ["spake", "hardware"])
        self.assertEqual(serializer.data["encrypted_challenge_indicator"], "encrypted")

        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        outpost_data = KerberosOutpostConfigSerializer(provider).data
        self.assertTrue(outpost_data["spake_enabled"])
        self.assertTrue(outpost_data["pkinit_require_freshness"])
        self.assertTrue(outpost_data["anonymous_pkinit_enabled"])
        self.assertTrue(outpost_data["kkdcp_enabled"])
        self.assertEqual(outpost_data["kkdcp_certificate"], certificate.pk)
        self.assertEqual(outpost_data["pkinit_indicators"], ["pkinit"])
        self.assertEqual(outpost_data["spake_indicators"], ["spake", "hardware"])
        self.assertEqual(outpost_data["encrypted_challenge_indicator"], "encrypted")

    def test_realm_trust_serializer_round_trip(self):
        """Realm trust settings round-trip through the serializer."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.TEST",
        )
        trust = KerberosRealmTrust.objects.create(
            provider=provider,
            remote_realm="Remote.Test",
            capaths=["HUB.TEST"],
        )
        serializer = KerberosRealmTrustSerializer(trust)
        self.assertEqual(serializer.data["remote_realm"], "Remote.Test")
        self.assertEqual(serializer.data["capaths"], ["HUB.TEST"])
        self.assertEqual(serializer.data["provider"], provider.pk)
        self.assertTrue(serializer.data["outgoing_keys"])
        self.assertTrue(serializer.data["incoming_keys"])

    def test_realm_trust_rejects_invalid_direction(self):
        """Realm trust directional actions reject unknown directions."""
        request = type("Request", (), {"query_params": {"direction": "sideways"}})()
        with self.assertRaises(ValidationError):
            KerberosRealmTrustViewSet._direction(request)

    def test_realm_trust_directional_keytab_and_rotation(self):
        """Realm trust keytabs and rotations are scoped to one direction."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.TEST",
        )
        trust = KerberosRealmTrust.objects.create(
            provider=provider,
            remote_realm="REMOTE.TEST",
        )
        viewset = KerberosRealmTrustViewSet()
        viewset.get_object = lambda: trust
        viewset.format_kwarg = None

        incoming_request = type("Request", (), {"query_params": {"direction": "incoming"}})()
        viewset.request = incoming_request
        incoming_response = viewset.keytab(incoming_request)
        incoming_keytab = base64.b64decode(incoming_response.data["keytab"])
        self.assertIn(b"REMOTE.TEST", incoming_keytab)
        self.assertIn(b"krbtgt", incoming_keytab)
        self.assertIn(b"EXAMPLE.TEST", incoming_keytab)

        outgoing_kvno = trust.outgoing_kvno
        incoming_kvno = trust.incoming_kvno
        outgoing_keys = trust.outgoing_keys
        incoming_keys = trust.incoming_keys
        outgoing_request = type("Request", (), {"query_params": {"direction": "outgoing"}})()
        viewset.rotate(outgoing_request)
        trust.refresh_from_db()
        self.assertEqual(trust.outgoing_kvno, outgoing_kvno + 1)
        self.assertEqual(trust.incoming_kvno, incoming_kvno)
        self.assertNotEqual(trust.outgoing_keys, outgoing_keys)
        self.assertEqual(trust.incoming_keys, incoming_keys)

        viewset.rotate(incoming_request)
        trust.refresh_from_db()
        self.assertEqual(trust.outgoing_kvno, outgoing_kvno + 1)
        self.assertEqual(trust.incoming_kvno, incoming_kvno + 1)
        self.assertNotEqual(trust.incoming_keys, incoming_keys)

    def test_otp_settings_serializer_round_trip(self):
        """OTP settings round-trip through both provider serializers."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            otp_enabled=True,
            otp_indicators=["otp"],
        )
        serializer = KerberosProviderSerializer(provider)
        self.assertTrue(serializer.data["otp_enabled"])
        self.assertEqual(serializer.data["otp_indicators"], ["otp"])
        Application.objects.create(name=generate_id(), slug=generate_id(), provider=provider)
        outpost_data = KerberosOutpostConfigSerializer(provider).data
        self.assertTrue(outpost_data["otp_enabled"])
        self.assertEqual(outpost_data["otp_indicators"], ["otp"])

    def test_otp_check_verifies_confirmed_devices_and_aliases(self):
        """OTP checks resolve aliases and consume static tokens."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            principal_username_attribute="email",
        )
        Application.objects.create(name=generate_id(), slug=generate_id(), provider=provider)
        user = create_test_user(email="otp@example.com")
        totp_device = TOTPDevice.objects.create(user=user, name="totp", confirmed=True)
        static_device = StaticDevice.objects.create(user=user, name="static", confirmed=True)
        StaticToken.objects.create(device=static_device, token="static-token")
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-otp-check",
            kwargs={"pk": provider.pk},
        )

        response = self.client.get(
            url, {"username": user.email, "value": TOTP(totp_device.bin_key).token()}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["allowed"])
        response = self.client.get(url, {"username": user.email, "value": "static-token"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["allowed"])
        self.assertFalse(StaticToken.objects.filter(token="static-token").exists())
        response = self.client.get(url, {"username": user.email, "value": "static-token"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["allowed"])

    def test_pac_settings_serializer_round_trip(self):
        """PAC settings round-trip through both provider serializers."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
            pac_enabled=True,
            realm_sid="S-1-5-21-1-2-3",
        )
        serializer = KerberosProviderSerializer(provider)
        self.assertTrue(serializer.data["pac_enabled"])
        self.assertEqual(serializer.data["realm_sid"], "S-1-5-21-1-2-3")
        Application.objects.create(name=generate_id(), slug=generate_id(), provider=provider)
        outpost_data = KerberosOutpostConfigSerializer(provider).data
        self.assertTrue(outpost_data["pac_enabled"])
        self.assertEqual(outpost_data["realm_sid"], "S-1-5-21-1-2-3")

    def test_user_key_password_expiration_uses_shortest_bound_policy(self):
        """User key payload maps the shortest application password expiry policy."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        application = Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        user = create_test_user()
        user_keys, _ = KerberosUserKeys.objects.update_or_create(
            user=user,
            provider=provider,
            defaults={"salt": "salt", "keys": {"18": "a2V5"}},
        )
        self.assertIsNone(KerberosUserKeyOutpostSerializer(user_keys).data["password_expiration"])
        longer = PasswordExpiryPolicy.objects.create(name=generate_id(), days=90)
        shorter = PasswordExpiryPolicy.objects.create(name=generate_id(), days=30)
        PolicyBinding.objects.create(target=application, policy=longer, order=0)
        PolicyBinding.objects.create(target=application, policy=shorter, order=1)
        payload = KerberosUserKeyOutpostSerializer(user_keys).data
        self.assertEqual(
            payload["password_expiration"],
            user.password_change_date + timedelta(days=30),
        )

    def test_user_key_account_state_and_lifetime_overrides(self):
        """User key payload maps account state and valid lifetime attributes."""
        provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name="EXAMPLE.COM",
        )
        user = create_test_user()
        user.is_active = False
        user.attributes = {
            "krb5MaxLife": "3600",
            "krb5MaxRenew": 7200,
        }
        user.save()
        user_keys, _ = KerberosUserKeys.objects.update_or_create(
            user=user,
            provider=provider,
            defaults={"salt": "salt", "keys": {"18": "a2V5"}},
        )

        payload = KerberosUserKeyOutpostSerializer(user_keys).data
        self.assertFalse(payload["enabled"])
        self.assertEqual(payload["max_ticket_lifetime"], 3600)
        self.assertEqual(payload["max_renew_lifetime"], 7200)

        user.attributes = {
            "krb5MaxLife": "-1",
            "krb5MaxRenew": "not-a-number",
        }
        user.save()
        user_keys.user.refresh_from_db()
        payload = KerberosUserKeyOutpostSerializer(user_keys).data
        self.assertIsNone(payload["max_ticket_lifetime"])
        self.assertIsNone(payload["max_renew_lifetime"])

        user.is_active = True
        user.save()
        user_keys.user.refresh_from_db()
        self.assertTrue(KerberosUserKeyOutpostSerializer(user_keys).data["enabled"])

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
        service_account = create_test_user(username=generate_id())
        serializer = KerberosServicePrincipalSerializer(
            data={
                "provider": provider.pk,
                "spn": "HTTP/example",
                "service_account": service_account.pk,
                "ok_to_auth_as_delegate": True,
                "allowed_delegation_targets": ["nfs/example", "HTTP/other"],
                "required_auth_indicators": ["pkinit", "hardware"],
            }
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        principal = serializer.save()
        self.assertEqual(principal.service_account, service_account)
        self.assertTrue(principal.ok_to_auth_as_delegate)
        self.assertEqual(
            principal.allowed_delegation_targets,
            ["nfs/example", "HTTP/other"],
        )
        self.assertEqual(principal.required_auth_indicators, ["pkinit", "hardware"])
        self.assertEqual(
            KerberosServicePrincipalSerializer(principal).data["allowed_delegation_targets"],
            ["nfs/example", "HTTP/other"],
        )
        self.assertEqual(
            KerberosServicePrincipalSerializer(principal).data["service_account"],
            service_account.pk,
        )
        self.assertEqual(
            KerberosServicePrincipalSerializer(principal).data["required_auth_indicators"],
            ["pkinit", "hardware"],
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

    def test_user_key_includes_pac_identity_mapping(self):
        """Outpost user payloads expose LDAP-compatible PAC RIDs."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        Application.objects.create(name=generate_id(), slug=generate_id(), provider=provider)
        user = create_test_user(username=generate_id(), email="user@example.com")
        user.attributes = {"uidNumber": "1234", "upn": "user@EXAMPLE.COM"}
        user.save(update_fields=["attributes"])
        group = Group.objects.create(name=generate_id(), attributes={"gidNumber": "5678"})
        user.groups.add(group)
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
            {"username": user.username},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["pac_user_id"], 1234)
        self.assertEqual(response.json()["pac_primary_group_id"], 1234)
        self.assertEqual(response.json()["pac_group_ids"], [5678])
        self.assertEqual(response.json()["pac_upn"], "user@EXAMPLE.COM")

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

    def test_access_check_service_account_and_validation(self):
        """Linked service accounts use their policies, while unlinked clients allow access."""
        provider = KerberosProvider.objects.create(name=generate_id(), realm_name="EXAMPLE.COM")
        application = Application.objects.create(
            name=generate_id(), slug=generate_id(), provider=provider
        )
        service_account = create_test_user(username=generate_id())
        linked = KerberosServicePrincipal.objects.create(
            provider=provider,
            spn="host/client",
            service_account=service_account,
        )
        target = KerberosServicePrincipal.objects.create(provider=provider, spn="host/target")
        self.client.force_login(create_test_admin_user())
        url = reverse(
            "authentik_api:kerberosprovideroutpost-access-check",
            kwargs={"pk": provider.pk},
        )

        PolicyBinding.objects.create(
            target=application,
            policy=DummyPolicy.objects.create(
                name=generate_id(), result=False, wait_min=0, wait_max=1
            ),
            order=0,
        )
        denied = self.client.get(url, {"client_spn": linked.spn})
        self.assertEqual(denied.status_code, 200)
        self.assertFalse(denied.json()["access"]["passing"])

        PolicyBinding.objects.filter(target=application).delete()
        PolicyBinding.objects.create(
            target=target,
            policy=DummyPolicy.objects.create(
                name=generate_id(), result=False, wait_min=0, wait_max=1
            ),
            order=0,
        )
        target_denied = self.client.get(
            url,
            {"client_spn": linked.spn, "spn": target.spn},
        )
        self.assertEqual(target_denied.status_code, 200)
        self.assertFalse(target_denied.json()["access"]["passing"])

        PolicyBinding.objects.filter(target=target).delete()
        target_allowed = self.client.get(
            url,
            {"client_spn": linked.spn, "spn": target.spn},
        )
        self.assertEqual(target_allowed.status_code, 200)
        self.assertTrue(target_allowed.json()["access"]["passing"])

        unlinked = self.client.get(url, {"client_spn": "host/unmanaged"})
        self.assertEqual(unlinked.status_code, 200)
        self.assertTrue(unlinked.json()["access"]["passing"])

        both = self.client.get(
            url, {"username": service_account.username, "client_spn": linked.spn}
        )
        neither = self.client.get(url)
        self.assertEqual(both.status_code, 400)
        self.assertEqual(neither.status_code, 400)

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
