"""Kerberos provider API views."""

import base64
import struct
import time
from datetime import datetime, timedelta

from django.db.models import Q
from django.http import Http404
from django.utils.translation import gettext_lazy as _
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.fields import (
    BooleanField,
    CharField,
    ChoiceField,
    IntegerField,
    ListField,
    SerializerMethodField,
)
from rest_framework.mixins import ListModelMixin
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from authentik.api.validation import validate
from authentik.core.api.providers import ProviderSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import ModelSerializer, PassiveSerializer
from authentik.core.apps import AppAccessWithoutBindings
from authentik.core.models import User
from authentik.events.models import Event, EventAction
from authentik.lib.utils.time import timedelta_from_string
from authentik.policies.api.exec import PolicyTestResultSerializer
from authentik.policies.engine import PolicyEngine
from authentik.policies.expiry.models import PasswordExpiryPolicy
from authentik.policies.password.models import PasswordPolicy
from authentik.policies.models import PolicyBinding
from authentik.policies.types import PolicyRequest, PolicyResult
from authentik.providers.kerberos.models import (
    KERBEROS_TICKET_FLAGS,
    KerberosProvider,
    KerberosRealmTrust,
    KerberosServicePrincipal,
    KerberosUserKeys,
    generate_key,
)
from authentik.stages.authenticator_static.models import StaticDevice
from authentik.stages.authenticator_totp.models import TOTPDevice

KEYTAB_KVNO_MAX = 255


class KerberosProviderSerializer(ProviderSerializer):
    """KerberosProvider serializer."""

    outpost_set = ListField(child=CharField(), read_only=True, source="outpost_set.all")
    kprop_targets = ListField(
        child=CharField(allow_blank=False, min_length=1),
        required=False,
        default=list,
    )
    kadmin_acl = ListField(
        child=CharField(allow_blank=False, min_length=1),
        required=False,
        default=list,
    )

    def to_internal_value(self, data: dict) -> dict:
        """Reject malformed kprop targets before JSON values are accepted."""
        targets = data.get("kprop_targets")
        if targets is not None and (
            not isinstance(targets, list)
            or any(not isinstance(target, str) or not target.strip() for target in targets)
        ):
            raise ValidationError(
                {"kprop_targets": _("Kprop targets must be a list of non-empty strings.")}
            )
        acl = data.get("kadmin_acl")
        if acl is not None and (
            not isinstance(acl, list)
            or any(not isinstance(line, str) or not line.strip() for line in acl)
        ):
            raise ValidationError(
                {"kadmin_acl": _("Kadmin ACL must be a list of non-empty strings.")}
            )
        return super().to_internal_value(data)

    def validate(self, attrs: dict) -> dict:
        """Validate the kprop identity against this provider's principals."""
        enabled = attrs.get("kprop_enabled", getattr(self.instance, "kprop_enabled", False))
        if not enabled:
            return attrs
        client_spn = attrs.get(
            "kprop_client_spn", getattr(self.instance, "kprop_client_spn", "")
        )
        if not client_spn:
            raise ValidationError({"kprop_client_spn": _("This field is required when kprop is enabled.")})
        provider = self.instance
        if provider is None or not KerberosServicePrincipal.objects.filter(
            provider=provider, spn=client_spn
        ).exists():
            raise ValidationError(
                {"kprop_client_spn": _("This service principal does not belong to this provider.")}
            )
        targets = attrs.get("kprop_targets", getattr(self.instance, "kprop_targets", []))
        if not targets:
            raise ValidationError({"kprop_targets": _("At least one kprop target is required.")})
        password = attrs.get(
            "kprop_master_password", getattr(self.instance, "kprop_master_password", "")
        )
        if not password:
            raise ValidationError(
                {"kprop_master_password": _("This field is required when kprop is enabled.")}
            )
        return attrs

    class Meta:
        model = KerberosProvider
        fields = ProviderSerializer.Meta.fields + [
            "realm_name",
            "default_domain",
            "maximum_ticket_lifetime",
            "maximum_ticket_renew_lifetime",
            "default_ticket_lifetime",
            "default_ticket_renew_lifetime",
            "allowed_enctypes",
            "require_preauthentication",
            "spake_enabled",
            "udp_enabled",
            "tcp_enabled",
            "kpasswd_enabled",
            "forwardable",
            "renewable",
            "proxiable",
            "principal_username_attribute",
            "pkinit_certificate",
            "pkinit_client_ca",
            "pkinit_require_freshness",
            "pkinit_indicators",
            "spake_indicators",
            "encrypted_challenge_indicator",
            "otp_enabled",
            "otp_indicators",
            "anonymous_pkinit_enabled",
            "kkdcp_enabled",
            "kkdcp_certificate",
            "pac_enabled",
            "realm_sid",
            "kprop_enabled",
            "kprop_targets",
            "kprop_client_spn",
            "kprop_master_password",
            "kprop_interval",
            "kdc_audit_enabled",
            "kadmin_enabled",
            "kadmin_acl",
            "master_key",
            "outpost_set",
        ]
        extra_kwargs = {
            "authentication_flow": {"required": False, "allow_null": True},
            "authorization_flow": {"required": False, "allow_null": True},
            "invalidation_flow": {"required": False, "allow_null": True},
            "master_key": {"read_only": True},
            "kprop_master_password": {"write_only": True},
        }


class KerberosProviderViewSet(UsedByMixin, ModelViewSet):
    """KerberosProvider viewset."""

    queryset = KerberosProvider.objects.all()
    serializer_class = KerberosProviderSerializer
    ordering = ["name"]
    search_fields = ["name", "realm_name"]
    filterset_fields = {"application": ["isnull"], "name": ["iexact"], "realm_name": ["iexact"]}


class KerberosServicePrincipalSerializer(ModelSerializer):
    """Kerberos service principal serializer."""

    allowed_delegation_targets = ListField(
        child=CharField(allow_blank=False, min_length=1),
        required=False,
        default=list,
    )
    ticket_flags = ListField(
        child=ChoiceField(choices=KERBEROS_TICKET_FLAGS),
        required=False,
        default=list,
    )

    def to_internal_value(self, data: dict) -> dict:
        """Reject non-string targets before the child field can coerce them."""
        targets = data.get("allowed_delegation_targets")
        if targets is not None and (
            not isinstance(targets, list)
            or any(not isinstance(target, str) or not target.strip() for target in targets)
        ):
            raise ValidationError(
                {"allowed_delegation_targets": _("Delegation targets must be non-empty strings.")}
            )
        flags = data.get("ticket_flags")
        if flags is not None and (
            not isinstance(flags, list)
            or any(not isinstance(flag, str) for flag in flags)
        ):
            raise ValidationError({"ticket_flags": _("Ticket flags must be strings.")})
        return super().to_internal_value(data)

    class Meta:
        model = KerberosServicePrincipal
        fields = [
            "uuid",
            "provider",
            "spn",
            "service_account",
            "kvno",
            "keys",
            "ok_to_auth_as_delegate",
            "allowed_delegation_targets",
            "required_auth_indicators",
            "ticket_flags",
        ]
        extra_kwargs = {"keys": {"read_only": True}, "kvno": {"read_only": True}}


class KerberosUserKeysSerializer(ModelSerializer):
    """Kerberos user keys serializer."""

    class Meta:
        model = KerberosUserKeys
        fields = ["uuid", "user", "provider", "kvno", "keys", "salt"]
        extra_kwargs = {"keys": {"read_only": True}, "kvno": {"read_only": True}}


def _keytab_entry(spn: str, realm: str, kvno: int, enctype: int, key: bytes) -> bytes:
    components = spn.split("/")
    body = struct.pack(">H", len(components))
    for component in [realm, *components]:
        encoded = component.encode()
        body += struct.pack(">H", len(encoded)) + encoded
    body += struct.pack(">IIBH", 1, int(time.time()), kvno & 0xFF, enctype)
    body += struct.pack(">H", len(key)) + key
    if kvno > KEYTAB_KVNO_MAX:
        body += struct.pack(">I", kvno)
    return struct.pack(">i", len(body)) + body


def build_keytab(principal: KerberosServicePrincipal) -> bytes:
    """Build a MIT keytab version 2 containing a service principal's keys."""
    return build_keytab_entries(
        principal.spn,
        principal.provider.realm_name,
        principal.kvno,
        principal.keys,
    )


def build_keytab_entries(spn: str, realm: str, kvno: int, keys: dict) -> bytes:
    """Build a MIT keytab containing keys for a principal."""
    entries = [
        _keytab_entry(spn, realm, kvno, int(enctype), base64.b64decode(key))
        for enctype, key in keys.items()
    ]
    return b"\x05\x02" + b"".join(entries)


class KerberosServicePrincipalViewSet(ModelViewSet):
    """Kerberos service principal viewset."""

    queryset = KerberosServicePrincipal.objects.all()
    serializer_class = KerberosServicePrincipalSerializer
    ordering = ["spn"]
    search_fields = ["spn"]
    filterset_fields = {"provider": ["exact"], "spn": ["iexact"]}

    @action(detail=True, methods=["GET"])
    def keytab(self, request: Request, pk=None) -> Response:
        """Export this service principal as a base64-encoded MIT keytab."""
        principal = self.get_object()
        return Response({"keytab": base64.b64encode(build_keytab(principal)).decode()})

    @action(detail=True, methods=["POST"])
    def rotate(self, request: Request, pk=None) -> Response:
        """Rotate this service principal's keys and increment its kvno."""
        principal = self.get_object()
        principal.kvno += 1
        principal.keys = {
            str(enctype): generate_key(enctype) for enctype in principal.provider.allowed_enctypes
        }
        principal.save(update_fields=["kvno", "keys"])
        return Response(self.get_serializer(principal).data)


class KerberosRealmTrustSerializer(ModelSerializer):
    """Kerberos realm trust serializer."""

    class Meta:
        model = KerberosRealmTrust
        fields = [
            "uuid",
            "provider",
            "remote_realm",
            "capaths",
            "outgoing_kvno",
            "outgoing_keys",
            "incoming_kvno",
            "incoming_keys",
        ]
        extra_kwargs = {
            "outgoing_keys": {"read_only": True},
            "outgoing_kvno": {"read_only": True},
            "incoming_keys": {"read_only": True},
            "incoming_kvno": {"read_only": True},
        }


class KerberosRealmTrustViewSet(ModelViewSet):
    """Kerberos realm trust viewset."""

    queryset = KerberosRealmTrust.objects.all()
    serializer_class = KerberosRealmTrustSerializer
    ordering = ["remote_realm"]
    search_fields = ["remote_realm"]
    filterset_fields = {"provider": ["exact"], "remote_realm": ["iexact"]}

    @staticmethod
    def _direction(request: Request) -> str:
        direction = request.query_params.get("direction", "outgoing")
        if direction not in ("outgoing", "incoming"):
            raise ValidationError({"direction": _("Direction must be outgoing or incoming.")})
        return direction

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "direction",
                OpenApiTypes.STR,
                location="query",
                description="Trust key direction.",
                enum=["outgoing", "incoming"],
            )
        ],
    )
    @action(detail=True, methods=["GET"])
    def keytab(self, request: Request, pk=None) -> Response:
        """Export one directional trust keytab."""
        trust = self.get_object()
        direction = self._direction(request)
        if direction == "outgoing":
            spn, realm, kvno, keys = (
                f"krbtgt/{trust.remote_realm}",
                trust.provider.realm_name,
                trust.outgoing_kvno,
                trust.outgoing_keys,
            )
        else:
            spn, realm, kvno, keys = (
                f"krbtgt/{trust.provider.realm_name}",
                trust.remote_realm,
                trust.incoming_kvno,
                trust.incoming_keys,
            )
        return Response(
            {"keytab": base64.b64encode(build_keytab_entries(spn, realm, kvno, keys)).decode()}
        )

    @extend_schema(
        request=None,
        parameters=[
            OpenApiParameter(
                "direction",
                OpenApiTypes.STR,
                location="query",
                description="Trust key direction.",
                enum=["outgoing", "incoming"],
            )
        ],
    )
    @action(detail=True, methods=["POST"])
    def rotate(self, request: Request, pk=None) -> Response:
        """Rotate one directional trust key set."""
        trust = self.get_object()
        direction = self._direction(request)
        keys = {
            str(enctype): generate_key(enctype) for enctype in trust.provider.allowed_enctypes
        }
        if direction == "outgoing":
            trust.outgoing_kvno += 1
            trust.outgoing_keys = keys
            trust.save(update_fields=["outgoing_kvno", "outgoing_keys"])
        else:
            trust.incoming_kvno += 1
            trust.incoming_keys = keys
            trust.save(update_fields=["incoming_kvno", "incoming_keys"])
        return Response(self.get_serializer(trust).data)


class KerberosServicePrincipalOutpostSerializer(PassiveSerializer):
    """Service principal data consumed by the KDC outpost."""

    spn = CharField()
    kvno = IntegerField()
    keys = SerializerMethodField()
    ok_to_auth_as_delegate = BooleanField()
    allowed_delegation_targets = ListField(child=CharField())
    required_auth_indicators = ListField(child=CharField())
    ticket_flags = ListField(child=CharField())

    def get_keys(self, obj: KerberosServicePrincipal) -> dict:
        return obj.keys


def _canonical_principal(provider: KerberosProvider, user: User) -> str | None:
    match provider.principal_username_attribute:
        case "email":
            value = user.email
        case "upn":
            value = user.attributes.get("upn") or user.username
        case _:
            value = user.username
    if not isinstance(value, str) or not value.strip():
        return None
    return value


class KerberosRealmTrustOutpostSerializer(PassiveSerializer):
    """Realm trust data consumed by the KDC outpost."""

    remote_realm = CharField()
    capaths = ListField(child=CharField())
    outgoing_kvno = IntegerField()
    outgoing_keys = SerializerMethodField()
    incoming_kvno = IntegerField()
    incoming_keys = SerializerMethodField()

    def get_outgoing_keys(self, obj: KerberosRealmTrust) -> dict:
        return obj.outgoing_keys

    def get_incoming_keys(self, obj: KerberosRealmTrust) -> dict:
        return obj.incoming_keys


class KerberosUserKeyOutpostSerializer(PassiveSerializer):
    """User key data consumed by the KDC outpost."""

    username = CharField(source="user.username")
    enabled = BooleanField(source="user.is_active")
    principal = SerializerMethodField()
    kvno = IntegerField()
    salt = CharField()
    keys = SerializerMethodField()
    max_ticket_lifetime = SerializerMethodField()
    max_renew_lifetime = SerializerMethodField()
    requires_password_change = SerializerMethodField()
    pac_user_id = SerializerMethodField()
    pac_primary_group_id = SerializerMethodField()
    pac_group_ids = SerializerMethodField()
    pac_name = CharField(source="user.name")
    pac_upn = SerializerMethodField()
    password_expiration = SerializerMethodField()
    flags = SerializerMethodField()

    def get_principal(self, obj: KerberosUserKeys) -> str:
        return _canonical_principal(obj.provider, obj.user) or ""

    def get_keys(self, obj: KerberosUserKeys) -> dict:
        return obj.keys

    @staticmethod
    def _attribute_number(attributes: dict, name: str) -> int | None:
        value = attributes.get(name)
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, str) and value.isdigit():
            parsed = int(value)
        else:
            return None
        if parsed >= 0:
            return parsed
        return None

    def get_max_ticket_lifetime(self, obj: KerberosUserKeys) -> int | None:
        return self._attribute_number(obj.user.attributes, "krb5MaxLife")

    def get_max_renew_lifetime(self, obj: KerberosUserKeys) -> int | None:
        return self._attribute_number(obj.user.attributes, "krb5MaxRenew")

    def get_flags(self, obj: KerberosUserKeys) -> list[str]:
        flags = obj.user.attributes.get("krb5Flags")
        if not isinstance(flags, list):
            return []
        return [flag for flag in flags if isinstance(flag, str) and flag in KERBEROS_TICKET_FLAGS]

    def get_requires_password_change(self, obj: KerberosUserKeys) -> bool:
        return obj.user.attributes.get("reset_password") is True

    def get_pac_user_id(self, obj: KerberosUserKeys) -> int:
        value = self._attribute_number(obj.user.attributes, "uidNumber")
        return 2000 + obj.user.pk if value is None else value

    def get_pac_primary_group_id(self, obj: KerberosUserKeys) -> int:
        return self.get_pac_user_id(obj)

    def get_pac_group_ids(self, obj: KerberosUserKeys) -> list[int]:
        group_ids = []
        for group in obj.user.groups.all():
            value = self._attribute_number(group.attributes, "gidNumber")
            group_ids.append(4000 + group.num_pk if value is None else value)
        return group_ids

    def get_pac_upn(self, obj: KerberosUserKeys) -> str:
        upn = obj.user.attributes.get("upn")
        return upn if isinstance(upn, str) and upn else obj.user.email or ""

    def get_password_expiration(self, obj: KerberosUserKeys) -> datetime | None:
        application = getattr(obj.provider, "application", None)
        if application is None:
            return None
        days = (
            PasswordExpiryPolicy.objects.filter(
                pk__in=PolicyBinding.objects.filter(
                    target=application,
                    enabled=True,
                ).values("policy_id")
            )
            .order_by("days")
            .values_list("days", flat=True)
            .first()
        )
        if days is None:
            return None
        return obj.user.password_change_date + timedelta(days=days)


class KerberosCheckAccessSerializer(PassiveSerializer):
    """Policy access data consumed by the KDC outpost."""

    access = PolicyTestResultSerializer()


class KerberosOTPCheckSerializer(PassiveSerializer):
    """OTP validation data consumed by the KDC outpost."""

    allowed = BooleanField()


class KerberosSetPasswordSerializer(PassiveSerializer):
    """Password change request for the Kerberos outpost."""

    username = CharField()
    password = CharField(write_only=True)


class KerberosPasswordPolicyErrorSerializer(PassiveSerializer):
    """Password policy failure returned by the Kerberos outpost."""

    messages = ListField(child=CharField())


class KerberosAuditEventSerializer(PassiveSerializer):
    """KDC audit event data submitted by the Kerberos outpost."""

    event = ChoiceField(choices=["as_req", "tgs_req", "s4u2self", "s4u2proxy", "u2u"])
    success = BooleanField()
    client = CharField()
    service = CharField()
    status = CharField()
    preauth_type = CharField()
    remote_addr = CharField()
    s4u2self_user = CharField(allow_blank=True)
    auth_indicators = ListField(child=CharField())
    error_code = IntegerField()
    request_id = CharField()
    ticket_id = CharField(allow_blank=True)


class KerberosServicePrincipalAdminSerializer(PassiveSerializer):
    """Service principal management request for the kadm5 outpost."""

    spn = CharField(allow_blank=False, min_length=1)


class KerberosServicePrincipalUpdateSerializer(KerberosServicePrincipalAdminSerializer):
    """Service principal ticket flag update request for the kadm5 outpost."""

    ticket_flags = ListField(
        child=ChoiceField(choices=KERBEROS_TICKET_FLAGS),
        allow_empty=True,
    )


class KerberosOutpostConfigSerializer(ModelSerializer):
    """Kerberos provider serializer for outposts."""

    application_slug = CharField(source="application.slug")
    kprop_targets = ListField(
        child=CharField(allow_blank=False, min_length=1),
        required=False,
        default=list,
    )
    kadmin_acl = ListField(
        child=CharField(allow_blank=False, min_length=1),
        required=False,
        default=list,
    )
    maximum_ticket_lifetime = SerializerMethodField()
    maximum_ticket_renew_lifetime = SerializerMethodField()

    def get_maximum_ticket_lifetime(self, obj: KerberosProvider) -> int:
        return int(timedelta_from_string(obj.maximum_ticket_lifetime).total_seconds())

    def get_maximum_ticket_renew_lifetime(self, obj: KerberosProvider) -> int:
        return int(timedelta_from_string(obj.maximum_ticket_renew_lifetime).total_seconds())

    class Meta:
        model = KerberosProvider
        fields = [
            "pk",
            "name",
            "realm_name",
            "default_domain",
            "maximum_ticket_lifetime",
            "maximum_ticket_renew_lifetime",
            "default_ticket_lifetime",
            "default_ticket_renew_lifetime",
            "allowed_enctypes",
            "require_preauthentication",
            "spake_enabled",
            "udp_enabled",
            "tcp_enabled",
            "kpasswd_enabled",
            "forwardable",
            "renewable",
            "proxiable",
            "principal_username_attribute",
            "pkinit_certificate",
            "pkinit_client_ca",
            "pkinit_require_freshness",
            "pkinit_indicators",
            "spake_indicators",
            "encrypted_challenge_indicator",
            "otp_enabled",
            "otp_indicators",
            "anonymous_pkinit_enabled",
            "kkdcp_enabled",
            "kkdcp_certificate",
            "pac_enabled",
            "realm_sid",
            "kprop_enabled",
            "kprop_targets",
            "kprop_client_spn",
            "kprop_master_password",
            "kprop_interval",
            "kdc_audit_enabled",
            "kadmin_enabled",
            "kadmin_acl",
            "master_key",
            "application_slug",
        ]


class KerberosOutpostConfigViewSet(ListModelMixin, GenericViewSet):
    """Kerberos provider configuration viewset for outposts."""

    queryset = KerberosProvider.objects.filter(application__isnull=False)
    serializer_class = KerberosOutpostConfigSerializer
    ordering = ["name"]
    search_fields = ["name"]
    filterset_fields = ["name"]

    def _require_kadmin(self, provider: KerberosProvider) -> None:
        if not provider.kadmin_enabled:
            raise Http404

    @staticmethod
    def _kadmin_event(provider: KerberosProvider, operation: str, spn: str) -> None:
        Event.new(
            "kerberos_kadmin",
            app=provider.application.slug,
            operation=operation,
            spn=spn,
        ).save()

    @staticmethod
    def _resolve_user(provider: KerberosProvider, username: str) -> User | None:
        """Resolve a principal component using the provider attribute and aliases."""
        users = User.objects.all()
        match provider.principal_username_attribute:
            case "email":
                user = users.filter(email=username).first()
            case "upn":
                user = users.filter(attributes__upn=username).first()
                if user is None:
                    user = users.filter(username=username).first()
            case _:
                user = users.filter(username=username).first()
        if user is None:
            user = users.filter(
                Q(username=username) | Q(email=username) | Q(attributes__upn=username)
            ).first()
        if user is None or _canonical_principal(provider, user) is None:
            return None
        return user

    @extend_schema(
        responses={200: KerberosServicePrincipalOutpostSerializer(many=True)},
    )
    @action(detail=True, methods=["GET"])
    def service_principals(self, request: Request, pk=None) -> Response:
        """List the configured service principals."""
        provider = self.get_object()
        principals = provider.kerberosserviceprincipal_set.all().order_by("spn")
        page = self.paginate_queryset(principals)
        return self.get_paginated_response(
            KerberosServicePrincipalOutpostSerializer(page, many=True).data
        )

    @extend_schema(
        responses={200: KerberosUserKeyOutpostSerializer(many=True)},
    )
    @action(detail=True, methods=["GET"])
    def user_keys(self, request: Request, pk=None) -> Response:
        """List all users with password-derived keys."""
        provider = self.get_object()
        user_keys = (
            KerberosUserKeys.objects.select_related("user", "provider")
            .filter(provider=provider)
            .order_by("user__username")
        )
        page = self.paginate_queryset(user_keys)
        return self.get_paginated_response(
            KerberosUserKeyOutpostSerializer(page, many=True).data
        )

    @extend_schema(
        request=KerberosServicePrincipalAdminSerializer,
        responses={200: KerberosServicePrincipalOutpostSerializer()},
        operation_id="outposts_kerberos_service_principal_create",
    )
    @action(detail=True, methods=["POST"])
    @validate(KerberosServicePrincipalAdminSerializer)
    def service_principal_create(self, request: Request, pk=None, body=None) -> Response:
        """Create a service principal for kadm5."""
        provider = self.get_object()
        self._require_kadmin(provider)
        spn = body.validated_data["spn"]
        if KerberosServicePrincipal.objects.filter(provider=provider, spn=spn).exists():
            return Response({"detail": _("This service principal already exists.")}, status=409)
        principal = KerberosServicePrincipal(provider=provider, spn=spn)
        principal.save()
        self._kadmin_event(provider, "create", spn)
        return Response(KerberosServicePrincipalOutpostSerializer(principal).data)

    @extend_schema(
        request=KerberosServicePrincipalAdminSerializer,
        responses={204: None},
        operation_id="outposts_kerberos_service_principal_delete",
    )
    @action(detail=True, methods=["POST"])
    @validate(KerberosServicePrincipalAdminSerializer)
    def service_principal_delete(self, request: Request, pk=None, body=None) -> Response:
        """Delete a service principal for kadm5."""
        provider = self.get_object()
        self._require_kadmin(provider)
        spn = body.validated_data["spn"]
        principal = KerberosServicePrincipal.objects.filter(provider=provider, spn=spn).first()
        if principal is None:
            raise Http404
        principal.delete()
        self._kadmin_event(provider, "delete", spn)
        return Response(status=204)

    @extend_schema(
        request=KerberosServicePrincipalAdminSerializer,
        responses={200: KerberosServicePrincipalOutpostSerializer()},
        operation_id="outposts_kerberos_service_principal_rotate",
    )
    @action(detail=True, methods=["POST"])
    @validate(KerberosServicePrincipalAdminSerializer)
    def service_principal_rotate(self, request: Request, pk=None, body=None) -> Response:
        """Rotate a service principal for kadm5."""
        provider = self.get_object()
        self._require_kadmin(provider)
        spn = body.validated_data["spn"]
        principal = KerberosServicePrincipal.objects.filter(provider=provider, spn=spn).first()
        if principal is None:
            raise Http404
        principal.kvno += 1
        principal.keys = {
            str(enctype): generate_key(enctype) for enctype in provider.allowed_enctypes
        }
        principal.save(update_fields=["kvno", "keys"])
        self._kadmin_event(provider, "rotate", spn)
        return Response(KerberosServicePrincipalOutpostSerializer(principal).data)

    @extend_schema(
        request=KerberosServicePrincipalUpdateSerializer,
        responses={200: KerberosServicePrincipalOutpostSerializer()},
        operation_id="outposts_kerberos_service_principal_update",
    )
    @action(detail=True, methods=["POST"])
    @validate(KerberosServicePrincipalUpdateSerializer)
    def service_principal_update(self, request: Request, pk=None, body=None) -> Response:
        """Update a service principal's ticket flags for kadm5."""
        provider = self.get_object()
        self._require_kadmin(provider)
        spn = body.validated_data["spn"]
        principal = KerberosServicePrincipal.objects.filter(provider=provider, spn=spn).first()
        if principal is None:
            raise Http404
        principal.ticket_flags = body.validated_data["ticket_flags"]
        principal.save(update_fields=["ticket_flags"])
        self._kadmin_event(provider, "update", spn)
        return Response(KerberosServicePrincipalOutpostSerializer(principal).data)

    @extend_schema(
        request=KerberosAuditEventSerializer,
        responses={204: None},
    )
    @action(detail=True, methods=["POST"])
    @validate(KerberosAuditEventSerializer)
    def audit_event(self, request: Request, pk=None, body=None) -> Response:
        """Record a KDC audit event."""
        provider = self.get_object()
        data = body.validated_data
        event = Event.new("kerberos_kdc", app=provider.application.slug, **data)
        client = data["client"].rsplit("@", 1)[0].replace(r"\@", "@")
        user = self._resolve_user(provider, client)
        if user is not None:
            event.set_user(user)
        event.save()
        return Response(status=204)

    @extend_schema(
        responses={200: KerberosRealmTrustOutpostSerializer(many=True)},
    )
    @action(detail=True, methods=["GET"])
    def realm_trusts(self, request: Request, pk=None) -> Response:
        """List the configured realm trusts."""
        provider = self.get_object()
        trusts = provider.realm_trusts.all().order_by("remote_realm")
        page = self.paginate_queryset(trusts)
        return self.get_paginated_response(
            KerberosRealmTrustOutpostSerializer(page, many=True).data
        )

    @extend_schema(
        parameters=[
            OpenApiParameter("username", OpenApiTypes.STR, required=True),
        ],
        responses={200: KerberosUserKeyOutpostSerializer()},
    )
    @action(detail=True, methods=["GET"])
    def user_key(self, request: Request, pk=None) -> Response:
        """Get one user's password-derived key set."""
        provider = self.get_object()
        username = request.query_params.get("username")
        if not username:
            return Response({"username": [_("This query parameter is required.")]}, status=400)

        user = self._resolve_user(provider, username)
        if user is None:
            raise Http404
        user_keys = (
            KerberosUserKeys.objects.select_related("user", "provider")
            .filter(provider=provider, user=user)
            .first()
        )
        if user_keys is None:
            raise Http404
        return Response(KerberosUserKeyOutpostSerializer(user_keys).data)

    @extend_schema(
        parameters=[
            OpenApiParameter("username", OpenApiTypes.STR, required=False),
            OpenApiParameter("client_spn", OpenApiTypes.STR, required=False),
            OpenApiParameter("spn", OpenApiTypes.STR, required=False),
        ],
        responses={200: KerberosCheckAccessSerializer()},
        operation_id="outposts_kerberos_access_check",
    )
    @action(detail=True, methods=["GET"])
    def access_check(self, request: Request, pk=None) -> Response:
        """Check application and optional service-principal policy access."""
        provider = self.get_object()
        username = request.query_params.get("username")
        client_spn = request.query_params.get("client_spn")
        if bool(username) == bool(client_spn):
            return Response(
                {
                    "non_field_errors": [
                        _("Exactly one of username and client_spn must be provided.")
                    ]
                },
                status=400,
            )
        if client_spn:
            client = KerberosServicePrincipal.objects.filter(
                provider=provider, spn=client_spn
            ).first()
            if client is None or client.service_account is None:
                result = PolicyResult(True)
                response = KerberosCheckAccessSerializer(instance={"access": result})
                return Response(response.data)
            user = client.service_account
        else:
            user = self._resolve_user(provider, username)
            if user is None or not user.is_active:
                raise Http404

        app_engine = PolicyEngine(provider.application, user, request)
        app_engine.empty_result = AppAccessWithoutBindings.get()
        app_engine.use_cache = False
        app_engine.build()
        result = app_engine.result

        spn = request.query_params.get("spn")
        if spn:
            service = KerberosServicePrincipal.objects.filter(provider=provider, spn=spn).first()
            if service:
                service_engine = PolicyEngine(service, user, request)
                service_engine.use_cache = False
                service_engine.build()
                result = PolicyResult(result.passing and service_engine.result.passing)

        response = KerberosCheckAccessSerializer(instance={"access": result})
        return Response(response.data)

    @extend_schema(
        parameters=[
            OpenApiParameter("username", OpenApiTypes.STR, required=True),
            OpenApiParameter("value", OpenApiTypes.STR, required=True),
        ],
        responses={200: KerberosOTPCheckSerializer()},
        operation_id="outposts_kerberos_otp_check",
    )
    @action(detail=True, methods=["GET"])
    def otp_check(self, request: Request, pk=None) -> Response:
        """Check a user's authentik TOTP or static authentication token."""
        provider = self.get_object()
        username = request.query_params.get("username")
        value = request.query_params.get("value")
        user = self._resolve_user(provider, username or "")
        allowed = False
        if user is not None and value:
            try:
                for device in TOTPDevice.objects.devices_for_user(user, confirmed=True):
                    if device.verify_token(value):
                        allowed = True
                        break
                if not allowed:
                    for device in StaticDevice.objects.devices_for_user(user, confirmed=True):
                        if device.verify_token(value):
                            allowed = True
                            break
            except Exception:  # noqa: BLE001
                allowed = False
        if not allowed:
            Event.new(
                EventAction.LOGIN_FAILED,
                username=username or "",
                reason="kerberos_otp_denied",
            ).from_http(request, user=user)
        return Response({"allowed": allowed})

    @extend_schema(
        request=KerberosSetPasswordSerializer,
        responses={204: None, 400: KerberosPasswordPolicyErrorSerializer()},
    )
    @action(detail=True, methods=["POST"])
    @validate(KerberosSetPasswordSerializer)
    def set_password(self, request: Request, pk=None, body=None) -> Response:
        """Set a user's password through the Kerberos outpost."""
        provider = self.get_object()
        if not provider.kpasswd_enabled:
            raise Http404
        username = body.validated_data["username"]
        match provider.principal_username_attribute:
            case "email":
                user = User.objects.filter(email=username).first()
            case "upn":
                user = User.objects.filter(attributes__upn=username).first()
                if user is None:
                    user = User.objects.filter(username=username).first()
            case _:
                user = User.objects.filter(username=username).first()
        if user is None:
            raise Http404
        if not user.is_active:
            raise Http404
        password = body.validated_data["password"]
        policy_request = PolicyRequest(user)
        policy_request.context["password"] = password
        policies = PasswordPolicy.objects.filter(
            pk__in=PolicyBinding.objects.filter(
                target=provider.application,
                enabled=True,
            ).values("policy_id")
        )
        messages = []
        for policy in policies:
            policy_request.context[policy.password_field] = password
            try:
                result = policy.passes(policy_request)
            except Exception:  # noqa: BLE001
                messages.append(_("Password policy evaluation failed."))
                continue
            if not result.passing:
                messages.extend(result.messages)
        if messages:
            return Response({"messages": messages}, status=400)
        user.set_password(password, request=request)
        user.save()
        if user.attributes.get("reset_password") is True:
            user.attributes["reset_password"] = False
            user.save(update_fields=["attributes"])
        return Response(status=204)
