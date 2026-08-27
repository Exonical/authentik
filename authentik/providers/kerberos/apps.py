"""authentik kerberos provider app config"""

from authentik.blueprints.apps import ManagedAppConfig


class AuthentikProviderKerberosConfig(ManagedAppConfig):
    """authentik kerberos provider app config"""

    name = "authentik.providers.kerberos"
    label = "authentik_providers_kerberos"
    verbose_name = "authentik Providers.Kerberos"
    default = True
