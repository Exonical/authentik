"""Kerberos provider models."""

from __future__ import annotations

import base64
import secrets
from collections.abc import Iterable
from uuid import uuid4

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.templatetags.static import static
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from authentik.core.models import Provider, User
from authentik.lib.models import SerializerModel
from authentik.lib.utils.time import timedelta_string_validator
from authentik.outposts.models import OutpostModel

ENCTYPE_CHOICES = (
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
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
    udp_enabled = models.BooleanField(default=True)
    tcp_enabled = models.BooleanField(default=True)
    forwardable = models.BooleanField(default=True)
    renewable = models.BooleanField(default=True)
    proxiable = models.BooleanField(default=False)
    principal_username_attribute = models.CharField(
        max_length=16,
        choices=PrincipalUsernameAttribute.choices,
        default=PrincipalUsernameAttribute.USERNAME,
    )

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
        return [
            self,
            "authentik_providers_kerberos.view_kerberosserviceprincipal",
            "authentik_providers_kerberos.view_kerberosuserkeys",
        ]

    class Meta:
        verbose_name = _("Kerberos Provider")
        verbose_name_plural = _("Kerberos Providers")


class KerberosServicePrincipal(SerializerModel):
    """A service principal and its long-term keys."""

    uuid = models.UUIDField(default=uuid4, editable=False, primary_key=True)
    provider = models.ForeignKey(KerberosProvider, on_delete=models.CASCADE)
    spn = models.CharField(max_length=1024)
    kvno = models.PositiveIntegerField(default=1)
    keys = models.JSONField(default=dict)

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
