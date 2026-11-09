//! authentik policy bindings as a KDC policy module.

use std::sync::Arc;

use krb5_rs::kdc::{
    kdb::mit::parse_name_with_default,
    plugins::{KdcPolicy, PolicyLimits, PolicyRefusal, PolicyRequest},
};

use super::store::{ProviderStore, components};

const KDC_ERR_POLICY: i32 = 12;

pub(crate) struct AccessPolicy {
    pub(crate) store: Arc<ProviderStore>,
}

impl AccessPolicy {
    fn check(&self, client: Option<&str>, server: &str) -> Result<PolicyLimits, PolicyRefusal> {
        let refused = || PolicyRefusal {
            code: KDC_ERR_POLICY,
            status: "authentik policy denied access".to_owned(),
        };
        let Some(client) = client else {
            return Ok(PolicyLimits::default());
        };
        let realm = &self.store.settings().realm;
        let (Ok((cname, crealm)), Ok((sname, srealm))) = (
            parse_name_with_default(client, realm),
            parse_name_with_default(server, realm),
        ) else {
            return Err(refused());
        };
        let (ccomps, scomps) = (components(&cname), components(&sname));
        let store = Arc::clone(&self.store);
        let authorize = store.authorize((&ccomps, &crealm), (&scomps, &srealm));
        let allowed = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(authorize)),
            Err(_) => false,
        };
        if allowed {
            Ok(PolicyLimits::default())
        } else {
            Err(refused())
        }
    }
}

impl KdcPolicy for AccessPolicy {
    fn name(&self) -> &'static str {
        "authentik"
    }

    fn init(&self) -> Result<(), i32> {
        Ok(())
    }

    fn fini(&self) {}

    fn check_as(&self, req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        self.check(req.client.as_deref(), &req.server)
    }

    fn check_tgs(&self, req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        self.check(req.ticket_client.as_deref(), &req.server)
    }
}
