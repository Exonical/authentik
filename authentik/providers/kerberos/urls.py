"""Kerberos provider API URLs."""

from authentik.providers.kerberos.api.providers import (
    KerberosOutpostConfigViewSet,
    KerberosProviderViewSet,
    KerberosServicePrincipalViewSet,
)

api_urlpatterns = [
    ("outposts/kerberos", KerberosOutpostConfigViewSet, "kerberosprovideroutpost"),
    ("providers/kerberos", KerberosProviderViewSet),
    ("providers/kerberos_service_principals", KerberosServicePrincipalViewSet),
]
