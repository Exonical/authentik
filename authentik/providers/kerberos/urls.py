"""Kerberos provider API URLs."""

from authentik.providers.kerberos.api.providers import (
    KerberosOutpostConfigViewSet,
    KerberosProviderViewSet,
    KerberosRealmTrustViewSet,
    KerberosServicePrincipalViewSet,
)

api_urlpatterns = [
    ("outposts/kerberos", KerberosOutpostConfigViewSet, "kerberosprovideroutpost"),
    ("providers/kerberos", KerberosProviderViewSet),
    ("providers/kerberos_service_principals", KerberosServicePrincipalViewSet),
    ("providers/kerberos_realm_trusts", KerberosRealmTrustViewSet),
]
