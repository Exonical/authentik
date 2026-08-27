"""Kerberos provider API views."""

import base64
import struct
import time

from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework.decorators import action
from rest_framework.fields import CharField, IntegerField, ListField, SerializerMethodField
from rest_framework.mixins import ListModelMixin
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from authentik.core.api.providers import ProviderSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import ModelSerializer, PassiveSerializer
from authentik.lib.utils.time import timedelta_from_string
from authentik.providers.kerberos.models import (
    KerberosProvider,
    KerberosServicePrincipal,
    KerberosUserKeys,
    generate_key,
)

KEYTAB_KVNO_MAX = 255


class KerberosProviderSerializer(ProviderSerializer):
    """KerberosProvider serializer."""

    outpost_set = ListField(child=CharField(), read_only=True, source="outpost_set.all")

    class Meta:
        model = KerberosProvider
        fields = ProviderSerializer.Meta.fields + [
            "realm_name",
            "maximum_ticket_lifetime",
            "maximum_ticket_renew_lifetime",
            "allowed_enctypes",
            "master_key",
            "outpost_set",
        ]
        extra_kwargs = {
            "authentication_flow": {"required": False, "allow_null": True},
            "authorization_flow": {"required": False, "allow_null": True},
            "invalidation_flow": {"required": False, "allow_null": True},
            "master_key": {"read_only": True},
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

    class Meta:
        model = KerberosServicePrincipal
        fields = ["uuid", "provider", "spn", "kvno", "keys"]
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
    entries = []
    for enctype, key in principal.keys.items():
        entries.append(
            _keytab_entry(
                principal.spn,
                principal.provider.realm_name,
                principal.kvno,
                int(enctype),
                base64.b64decode(key),
            )
        )
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


class KerberosServicePrincipalOutpostSerializer(PassiveSerializer):
    """Service principal data consumed by the KDC outpost."""

    spn = CharField()
    kvno = IntegerField()
    keys = SerializerMethodField()

    def get_keys(self, obj: KerberosServicePrincipal) -> dict:
        return obj.keys


class KerberosUserKeyOutpostSerializer(PassiveSerializer):
    """User key data consumed by the KDC outpost."""

    username = CharField(source="user.username")
    kvno = IntegerField()
    salt = CharField()
    keys = SerializerMethodField()

    def get_keys(self, obj: KerberosUserKeys) -> dict:
        return obj.keys


class KerberosOutpostConfigSerializer(ModelSerializer):
    """Kerberos provider serializer for outposts."""

    application_slug = CharField(source="application.slug")
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
            "maximum_ticket_lifetime",
            "maximum_ticket_renew_lifetime",
            "allowed_enctypes",
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

    @extend_schema(
        responses={200: KerberosServicePrincipalOutpostSerializer(many=True)},
    )
    @action(detail=True, methods=["GET"])
    def service_principals(self, request: Request, pk=None) -> Response:
        """List the configured service principals."""
        provider = self.get_object()
        principals = provider.kerberosserviceprincipal_set.all().order_by("spn")
        return Response(KerberosServicePrincipalOutpostSerializer(principals, many=True).data)

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
        user_keys = get_object_or_404(
            KerberosUserKeys.objects.select_related("user"),
            provider=provider,
            user__username=username,
        )
        return Response(KerberosUserKeyOutpostSerializer(user_keys).data)
