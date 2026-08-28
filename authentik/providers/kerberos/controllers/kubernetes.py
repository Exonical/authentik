"""Kerberos provider Kubernetes controller."""

from authentik.outposts.controllers.base import DeploymentPort
from authentik.outposts.controllers.kubernetes import KubernetesController
from authentik.outposts.models import KubernetesServiceConnection, Outpost


class KerberosKubernetesController(KubernetesController):
    """Kerberos provider Kubernetes controller."""

    def __init__(self, outpost: Outpost, connection: KubernetesServiceConnection):
        super().__init__(outpost, connection)
        self.deployment_ports = [
            DeploymentPort(3088, "krb", "tcp", 3088),
            DeploymentPort(3088, "krb", "udp", 3088),
            DeploymentPort(3464, "kpasswd", "tcp", 3464),
            DeploymentPort(3464, "kpasswd", "udp", 3464),
        ]
