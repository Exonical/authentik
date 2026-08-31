"""Kerberos provider models."""

from __future__ import annotations

import base64
import re
import secrets
from collections.abc import Iterable
from uuid import uuid4

from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.db import models
from django.templatetags.static import static
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from authentik.core.models import Provider, User
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.models import SerializerModel
from authentik.lib.utils.time import timedelta_string_validator
from authentik.outposts.models import OutpostModel
from authentik.policies.models import PolicyBindingModel

ENCTYPE_CHOICES = (
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
)

KERBEROS_TICKET_FLAGS = (
    "requires_preauth",
    "requires_hwauth",
    "disallow_postdated",
    "disallow_forwardable",
    "disallow_proxiable",
    "disallow_renewable",
    "disallow_tgt_based",
    "disallow_server",
)


class PrincipalUsernameAttribute(models.TextChoices):
    """User attribute used as the Kerberos principal component."""

    USERNAME = "username", _("Username")
    EMAIL = "email", _("Email")
    UPN = "upn", _("UPN")


def generate_master_key() -> str:
    """Generate a base64-encoded provider master key."""
    return base64.b64encode(secrets.token_bytes(64)).decode()


def generate_key(enctype: int) -> str:
    """Generate a base64-encoded random enctype key."""
    return base64.b64encode(secrets.token_bytes(16 if enctype in (17, 19) else 32)).decode()


def default_enctypes() -> list[int]:
    """Return the default allowed enctypes."""
    return [18, 20]


REALM_SID_PATTERN = re.compile(r"^S-1-5-21-(\d+)-(\d+)-(\d+)$")


def validate_realm_sid(value: str):
    """Validate the domain SID format used by MS-PAC identities."""
    match = REALM_SID_PATTERN.fullmatch(value)
    if match is None or any(int(part) > 0xFFFFFFFF for part in match.groups()):
        raise ValidationError(_("Realm SID must match S-1-5-21-<a>-<b>-<c>."))


class KerberosProvider(OutpostModel, Provider):
    """Provide Kerberos authentication through a KDC outpost."""

    realm_name = models.CharField(max_length=255, unique=True)
    default_domain = models.CharField(max_length=255, blank=True, default="")
    maximum_ticket_lifetime = models.TextField(
        default="hours=10",
        validators=[timedelta_string_validator],
    )
    maximum_ticket_renew_lifetime = models.TextField(
        default="days=7",
        validators=[timedelta_string_validator],
    )
    allowed_enctypes = ArrayField(
        models.IntegerField(choices=ENCTYPE_CHOICES),
        default=default_enctypes,
    )
    master_key = models.TextField(default=generate_master_key)
    default_ticket_lifetime = models.TextField(
        default="hours=10",
        validators=[timedelta_string_validator],
    )
    default_ticket_renew_lifetime = models.TextField(
        default="days=7",
        validators=[timedelta_string_validator],
    )
    require_preauthentication = models.BooleanField(default=True)
    spake_enabled = models.BooleanField(
        default=False,
        help_text=_("Advertise PA-SPAKE preauthentication (RFC 9588)."),
    )
    udp_enabled = models.BooleanField(default=True)
    tcp_enabled = models.BooleanField(default=True)
    kpasswd_enabled = models.BooleanField(
        default=True,
        help_text=_("Enable RFC 3244 password changes through the Kerberos outpost."),
    )
    forwardable = models.BooleanField(default=True)
    renewable = models.BooleanField(default=True)
    proxiable = models.BooleanField(default=False)
    principal_username_attribute = models.CharField(
        max_length=16,
        choices=PrincipalUsernameAttribute.choices,
        default=PrincipalUsernameAttribute.USERNAME,
    )
    pkinit_certificate = models.ForeignKey(
        CertificateKeyPair,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text=_(
            "Certificate/key pair the KDC uses to sign PKINIT replies. Requires a private key."
        ),
    )
    pkinit_client_ca = models.ForeignKey(
        CertificateKeyPair,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text=_("CA certificate used to validate PKINIT client certificates."),
    )
    pkinit_require_freshness = models.BooleanField(
        default=False,
        help_text=_("Require RFC 8070 freshness tokens on PKINIT requests."),
    )
    pkinit_indicators = ArrayField(
        models.TextField(),
        default=list,
        blank=True,
        help_text=_("Authentication indicators asserted after successful PKINIT."),
    )
    spake_indicators = ArrayField(
        models.TextField(),
        default=list,
        blank=True,
        help_text=_("Indicators asserted after SPAKE preauthentication."),
    )
    encrypted_challenge_indicator = models.TextField(
        default="",
        blank=True,
        help_text=_("Indicator asserted after encrypted-challenge preauthentication."),
    )
    otp_enabled = models.BooleanField(
        default=False,
        help_text=_(
            "Enable RFC 6560 OTP preauthentication backed by the user's authentik "
            "TOTP and static authenticator devices."
        ),
    )
    otp_indicators = ArrayField(
        models.TextField(),
        default=list,
        blank=True,
        help_text=_("Authentication indicators asserted after successful OTP preauthentication."),
    )
    anonymous_pkinit_enabled = models.BooleanField(
        default=False,
        help_text=_("Allow anonymous PKINIT requests."),
    )
    kkdcp_enabled = models.BooleanField(
        default=False,
        help_text=_("Enable KDC Proxy over HTTPS (MS-KKDCP)."),
    )
    kkdcp_certificate = models.ForeignKey(
        CertificateKeyPair,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text=_("Certificate/key pair the KDC Proxy listener uses for TLS."),
    )
    pac_enabled = models.BooleanField(
        default=False,
        help_text=_("Include an MS-PAC in issued tickets."),
    )
    realm_sid = models.TextField(
        blank=True,
        default="",
        validators=[validate_realm_sid],
        help_text=_("Domain SID used for MS-PAC identities, for example S-1-5-21-1-2-3."),
    )

    def save(self, *args, **kwargs):
        if self.realm_sid:
            validate_realm_sid(self.realm_sid)
        elif self.pac_enabled:
            self.realm_sid = "S-1-5-21-" + "-".join(str(secrets.randbits(32)) for _ in range(3))
        return super().save(*args, **kwargs)

    @property
    def component(self) -> str:
        return "ak-provider-kerberos-form"

    @property
    def launch_url(self) -> str | None:
        return None

    @property
    def icon_url(self) -> str | None:
        return static("authentik/sources/kerberos.svg")

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.kerberos.api.providers import KerberosProviderSerializer

        return KerberosProviderSerializer

    def __str__(self) -> str:
        return f"Kerberos Provider {self.name}"

    def get_required_objects(self) -> Iterable[models.Model | str | tuple[str, models.Model]]:
        required = [
            self,
            "authentik_providers_kerberos.view_kerberosserviceprincipal",
            "authentik_providers_kerberos.view_kerberosuserkeys",
        ]
        if self.pkinit_certificate:
            required.extend(
                [
                    ("authentik_crypto.view_certificatekeypair", self.pkinit_certificate),
                    (
                        "authentik_crypto.view_certificatekeypair_certificate",
                        self.pkinit_certificate,
                    ),
                    ("authentik_crypto.view_certificatekeypair_key", self.pkinit_certificate),
                ]
            )
        if self.pkinit_client_ca:
            required.extend(
                [
                    ("authentik_crypto.view_certificatekeypair", self.pkinit_client_ca),
                    (
                        "authentik_crypto.view_certificatekeypair_certificate",
                        self.pkinit_client_ca,
                    ),
                ]
            )
        if self.kkdcp_certificate:
            required.extend(
                [
                    ("authentik_crypto.view_certificatekeypair", self.kkdcp_certificate),
                    (
                        "authentik_crypto.view_certificatekeypair_certificate",
                        self.kkdcp_certificate,
                    ),
                    ("authentik_crypto.view_certificatekeypair_key", self.kkdcp_certificate),
                ]
            )
        return required

    class Meta:
        verbose_name = _("Kerberos Provider")
        verbose_name_plural = _("Kerberos Providers")


class KerberosServicePrincipal(SerializerModel, PolicyBindingModel):
    """A service principal and its long-term keys."""

    uuid = models.UUIDField(default=uuid4, editable=False, primary_key=True)
    provider = models.ForeignKey(KerberosProvider, on_delete=models.CASCADE)
    spn = models.CharField(max_length=1024)
    service_account = models.ForeignKey(
        "authentik_core.User",
        null=True,
        blank=True,
        default=None,
        on_delete=models.SET_NULL,
        related_name="+",
        help_text=_(
            "Optional authentik user (typically a service account) whose policies are "
            "evaluated when this principal acts as a Kerberos client."
        ),
    )
    kvno = models.PositiveIntegerField(default=1)
    keys = models.JSONField(default=dict)
    ok_to_auth_as_delegate = models.BooleanField(
        default=False,
        help_text=_("Allow this service principal to authenticate as a user for delegation."),
    )
    allowed_delegation_targets = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "Service principals this service principal may use for constrained delegation."
        ),
    )
    required_auth_indicators = ArrayField(
        models.TextField(),
        default=list,
        blank=True,
        help_text=_("Authentication indicators required to obtain tickets for this service."),
    )
    ticket_flags = models.JSONField(
        default=list,
        blank=True,
        help_text=_("Ticket flags applied to this service principal."),
    )

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.kerberos.api.providers import KerberosServicePrincipalSerializer

        return KerberosServicePrincipalSerializer

    def save(self, *args, **kwargs):
        if not self.keys:
            self.keys = {
                str(enctype): generate_key(enctype) for enctype in self.provider.allowed_enctypes
            }
        return super().save(*args, **kwargs)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("provider", "spn"), name="kerberos_provider_spn_unique")
        ]
        verbose_name = _("Kerberos Service Principal")
        verbose_name_plural = _("Kerberos Service Principals")

    def __str__(self) -> str:
        return f"{self.spn} ({self.provider.realm_name})"


class KerberosRealmTrust(SerializerModel):
    """A trust relationship with a remote Kerberos realm."""

    uuid = models.UUIDField(default=uuid4, editable=False, primary_key=True)
    provider = models.ForeignKey(
        KerberosProvider,
        on_delete=models.CASCADE,
        related_name="realm_trusts",
    )
    remote_realm = models.TextField(validators=[MinLengthValidator(1)])
    capaths = ArrayField(
        models.TextField(),
        default=list,
        blank=True,
        help_text=_("Intermediate realms for transited-path checking."),
    )
    outgoing_kvno = models.PositiveIntegerField(default=1)
    outgoing_keys = models.JSONField(default=dict)
    incoming_kvno = models.PositiveIntegerField(default=1)
    incoming_keys = models.JSONField(default=dict)

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.kerberos.api.providers import KerberosRealmTrustSerializer

        return KerberosRealmTrustSerializer

    def save(self, *args, **kwargs):
        if self._state.adding and not self.outgoing_keys:
            self.outgoing_keys = {
                str(enctype): generate_key(enctype) for enctype in self.provider.allowed_enctypes
            }
        if self._state.adding and not self.incoming_keys:
            self.incoming_keys = {
                str(enctype): generate_key(enctype) for enctype in self.provider.allowed_enctypes
            }
        return super().save(*args, **kwargs)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("provider", "remote_realm"),
                name="kerberos_provider_remote_realm_unique",
            )
        ]
        verbose_name = _("Kerberos Realm Trust")
        verbose_name_plural = _("Kerberos Realm Trusts")

    def __str__(self) -> str:
        return f"{self.provider.realm_name} ↔ {self.remote_realm}"


class KerberosUserKeys(SerializerModel):
    """A user's recoverable password-derived Kerberos key material."""

    uuid = models.UUIDField(default=uuid4, editable=False, primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.ForeignKey(KerberosProvider, on_delete=models.CASCADE)
    kvno = models.PositiveIntegerField(default=1)
    keys = models.JSONField(default=dict)
    salt = models.CharField(max_length=1024)

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.kerberos.api.providers import KerberosUserKeysSerializer

        return KerberosUserKeysSerializer

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("user", "provider"),
                name="kerberos_user_provider_unique",
            )
        ]
        verbose_name = _("Kerberos User Keys")
        verbose_name_plural = _("Kerberos User Keys")

    def __str__(self) -> str:
        return f"{self.user.username} ({self.provider.realm_name})"
