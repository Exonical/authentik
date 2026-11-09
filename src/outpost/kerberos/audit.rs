//! KDC audit events forwarded to authentik.

use std::{net::SocketAddr, sync::Arc};

use ak_client::{
    apis::{configuration::Configuration, outposts_api::outposts_kerberos_audit_event_create},
    models::{EventEnum, KerberosAuditEventRequest},
};
use krb5_rs::kdc::plugins::{Audit, AuditState};
use tokio::sync::mpsc;
use tracing::warn;

const QUEUE_SIZE: usize = 256;

pub(crate) struct ApiAudit {
    tx: mpsc::Sender<KerberosAuditEventRequest>,
}

impl ApiAudit {
    /// Start a sender for `provider_id`; it stops once the module is dropped.
    pub(crate) fn spawn(api: Configuration, provider_id: i32) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel(QUEUE_SIZE);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(err) =
                    outposts_kerberos_audit_event_create(&api, provider_id, event).await
                {
                    warn!(?err, "failed to send KDC audit event");
                }
            }
        });
        Arc::new(Self { tx })
    }

    fn send(&self, event: EventEnum, success: bool, state: &AuditState) {
        if self.tx.try_send(request(event, success, state)).is_err() {
            warn!("dropping KDC audit event: queue is full");
        }
    }
}

fn request(event: EventEnum, success: bool, state: &AuditState) -> KerberosAuditEventRequest {
    let preauth = state
        .reply
        .as_ref()
        .and_then(|r| r.pa_types.as_ref())
        .and_then(|t| t.first())
        .map(ToString::to_string)
        .unwrap_or_default();
    let remote = state
        .cl_addr
        .map(|ip| SocketAddr::new(ip, state.cl_port).to_string())
        .unwrap_or_default();
    let ticket = state
        .tkt_out_id
        .clone()
        .filter(|t| !t.is_empty())
        .or_else(|| state.tkt_in_id.clone())
        .unwrap_or_default();
    KerberosAuditEventRequest::new(
        event,
        success,
        state.client.clone().unwrap_or_default(),
        state.server.clone().unwrap_or_default(),
        state.status.clone().unwrap_or_default(),
        preauth,
        remote,
        state.s4u2self_user.clone().unwrap_or_default(),
        Vec::new(),
        state.error_code,
        state.req_id.clone(),
        ticket,
    )
}

#[expect(
    clippy::missing_trait_methods,
    reason = "only request events are forwarded"
)]
impl Audit for ApiAudit {
    #[expect(clippy::unnecessary_literal_bound, reason = "trait signature")]
    fn name(&self) -> &str {
        "authentik"
    }

    fn as_req(&self, success: bool, state: &AuditState) {
        self.send(EventEnum::AsReq, success, state);
    }

    fn tgs_req(&self, success: bool, state: &AuditState) {
        self.send(EventEnum::TgsReq, success, state);
    }

    fn s4u2self(&self, success: bool, state: &AuditState) {
        self.send(EventEnum::S4u2self, success, state);
    }

    fn s4u2proxy(&self, success: bool, state: &AuditState) {
        self.send(EventEnum::S4u2proxy, success, state);
    }

    fn u2u(&self, success: bool, state: &AuditState) {
        self.send(EventEnum::U2u, success, state);
    }
}
