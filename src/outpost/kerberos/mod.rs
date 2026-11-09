//! The authentik Kerberos outpost, a KDC built on krb5-rs.

use std::{fmt::Write as _, net::SocketAddr, sync::Arc, time::Duration};

use ak_client::{
    apis::outposts_api::{
        outposts_kerberos_list, outposts_kerberos_realm_trusts_list,
        outposts_kerberos_service_principals_list,
    },
    models::KerberosOutpostConfig,
};
use ak_common::{Tasks, api::fetch_all, config};
use arc_swap::ArcSwapOption;
use argh::FromArgs;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use eyre::{Result, eyre};
use krb5_rs::{
    kdc::{
        Kdc, KdcConfig, KdcRealms, KdcService, PrincipalAttributes, RequestSummary, ServeOptions,
        Transport, serve_tcp_with, serve_udp_with,
    },
    profile::Profile,
};
use tokio::sync::watch;
use tracing::{debug, error, info, instrument, warn};

use self::{
    policy::AccessPolicy,
    store::{ProviderStore, StoreSettings, StoreSources},
};
use crate::outpost::{Outpost, OutpostController, event::EventSessionEnd};

mod policy;
mod store;

const PAGE_SIZE: i32 = 100;

#[derive(Debug, Default, FromArgs, PartialEq, Eq)]
/// Run the authentik Kerberos outpost.
#[argh(subcommand, name = "kerberos")]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "argh doesn't support unit structs"
)]
pub(crate) struct Cli {}

type ProviderKdc = Kdc<Arc<ProviderStore>>;

/// Routes requests to the realms of the most recent refresh.
#[derive(Default)]
struct Dispatcher {
    realms: ArcSwapOption<KdcRealms<Arc<ProviderStore>>>,
}

impl KdcService for Dispatcher {
    async fn handle_summarized_from(
        &self,
        request: &[u8],
        transport: Transport,
        peer: Option<SocketAddr>,
    ) -> (Vec<u8>, Option<RequestSummary>) {
        let Some(realms) = self.realms.load_full() else {
            return (Vec::new(), None);
        };
        realms
            .handle_summarized_from(request, transport, peer)
            .await
    }

    fn bare_error(&self, code: i32, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        self.realms
            .load_full()
            .map(|realms| realms.bare_error(code, now))
            .unwrap_or_default()
    }
}

pub(crate) struct KerberosOutpost {
    controller: Arc<OutpostController>,
    dispatcher: Arc<Dispatcher>,
}

fn seconds(value: i32) -> Duration {
    Duration::from_secs(u64::try_from(value).unwrap_or_default())
}

fn enctypes(provider: &KerberosOutpostConfig) -> Vec<i32> {
    provider
        .allowed_enctypes
        .iter()
        .flatten()
        .filter_map(|e| serde_json::to_value(e).ok()?.as_i64())
        .filter_map(|e| i32::try_from(e).ok())
        .collect()
}

fn base_attributes(provider: &KerberosOutpostConfig) -> PrincipalAttributes {
    let mut attrs = PrincipalAttributes::empty();
    if provider.forwardable == Some(false) {
        attrs |= PrincipalAttributes::DISALLOW_FORWARDABLE;
    }
    if provider.renewable == Some(false) {
        attrs |= PrincipalAttributes::DISALLOW_RENEWABLE;
    }
    if provider.proxiable == Some(false) {
        attrs |= PrincipalAttributes::DISALLOW_PROXIABLE;
    }
    attrs
}

/// `[capaths]` for the realm trusts, as krb5.conf text.
fn capaths(realm: &str, trusts: &[ak_client::models::KerberosRealmTrustOutpost]) -> String {
    let mut out = String::from("[capaths]\n");
    for (client, server, path) in trusts.iter().flat_map(|t| {
        [
            (realm, t.remote_realm.as_str(), &t.capaths),
            (t.remote_realm.as_str(), realm, &t.capaths),
        ]
    }) {
        let _ = writeln!(out, "\t{client} = {{");
        if path.is_empty() {
            let _ = writeln!(out, "\t\t{server} = .");
        }
        for hop in path {
            let _ = writeln!(out, "\t\t{server} = {hop}");
        }
        out.push_str("\t}\n");
    }
    out
}

impl KerberosOutpost {
    async fn build_provider(&self, provider: &KerberosOutpostConfig) -> Result<ProviderKdc> {
        let api = &self.controller.api_config;
        let master_key = STANDARD.decode(provider.master_key.as_deref().unwrap_or_default())?;
        if master_key.is_empty() {
            return Err(eyre!("provider has no master key"));
        }
        let services = fetch_all(
            |page| {
                outposts_kerberos_service_principals_list(
                    api,
                    provider.pk,
                    None,
                    None,
                    Some(page),
                    Some(PAGE_SIZE),
                    None,
                )
            },
            |r| &r.pagination,
            |r| r.results,
        )
        .await?;
        let trusts = fetch_all(
            |page| {
                outposts_kerberos_realm_trusts_list(
                    api,
                    provider.pk,
                    None,
                    None,
                    Some(page),
                    Some(PAGE_SIZE),
                    None,
                )
            },
            |r| &r.pagination,
            |r| r.results,
        )
        .await?;

        let realm = provider.realm_name.clone();
        let enctypes = enctypes(provider);
        let iprop_spn = provider
            .iprop_enabled
            .unwrap_or_default()
            .then(|| provider.iprop_spn.clone())
            .flatten()
            .filter(|s| !s.is_empty());
        let store = Arc::new(ProviderStore::new(
            api.clone(),
            provider.pk,
            StoreSettings {
                realm: realm.clone(),
                enctypes: enctypes.clone(),
                base_attributes: base_attributes(provider),
                require_preauth: provider.require_preauthentication.unwrap_or(true),
                anonymous_pkinit: provider.anonymous_pkinit_enabled.unwrap_or_default(),
            },
            &StoreSources {
                master_key: &master_key,
                services: &services,
                trusts: &trusts,
                iprop_spn: iprop_spn.as_deref(),
            },
        )?);

        let mut cfg = KdcConfig::new(realm.clone());
        cfg.max_life = seconds(provider.maximum_ticket_lifetime);
        cfg.max_renewable_life = seconds(provider.maximum_ticket_renew_lifetime);
        if !enctypes.is_empty() {
            cfg.supported_enctypes = enctypes;
        }
        if let Some(size) = provider.max_datagram_reply_size.filter(|s| *s > 0) {
            cfg.max_dgram_reply_size = usize::try_from(size)?;
        }
        cfg.disable_pac = true;
        cfg.spake_indicators = provider.spake_indicators.clone().unwrap_or_default();
        cfg.encrypted_challenge_indicator = provider
            .encrypted_challenge_indicator
            .clone()
            .filter(|s| !s.is_empty());
        cfg.otp_token_types = None;
        if !trusts.is_empty() {
            cfg.realm_profile = Some(
                Profile::parse(&capaths(&realm, &trusts))
                    .map_err(|err| eyre!("capaths: {err:?}"))?,
            );
        }

        Ok(Kdc::builder(cfg, Arc::clone(&store))
            .kdcpolicy(vec![Arc::new(AccessPolicy { store })])
            .build())
    }

    fn spawn_listeners(&self, tasks: &mut Tasks, shutdown: &watch::Receiver<bool>) -> Result<()> {
        for addr in config::get().listen.kerberos.iter().copied() {
            let options = ServeOptions {
                logger: None,
                shutdown: Some(shutdown.clone()),
            };
            let udp = std::net::UdpSocket::bind(addr)?;
            udp.set_nonblocking(true)?;
            let udp = tokio::net::UdpSocket::from_std(udp)?;
            let dispatcher = Arc::clone(&self.dispatcher);
            let udp_options = options.clone();
            tasks
                .build_task()
                .name(&format!("{}::udp::{addr}", module_path!()))
                .spawn(async move { Ok(serve_udp_with(dispatcher, udp, udp_options).await?) })?;

            let tcp = std::net::TcpListener::bind(addr)?;
            tcp.set_nonblocking(true)?;
            let tcp = tokio::net::TcpListener::from_std(tcp)?;
            let dispatcher = Arc::clone(&self.dispatcher);
            tasks
                .build_task()
                .name(&format!("{}::tcp::{addr}", module_path!()))
                .spawn(async move { Ok(serve_tcp_with(dispatcher, tcp, options).await?) })?;
            info!(%addr, "Kerberos KDC listening");
        }
        Ok(())
    }
}

impl Outpost for KerberosOutpost {
    type Cli = Cli;

    const OUTPOST_TYPE: &'static str = "kerberos";

    #[expect(clippy::unused_async_trait_impl, reason = "trait signature")]
    async fn new(controller: Arc<OutpostController>) -> Result<Self> {
        Ok(Self {
            controller,
            dispatcher: Arc::new(Dispatcher::default()),
        })
    }

    fn start(self: Arc<Self>, tasks: &mut Tasks) -> Result<()> {
        let (tx, rx) = watch::channel(false);
        let arbiter = tasks.arbiter();
        tasks
            .build_task()
            .name(&format!("{}::shutdown", module_path!()))
            .spawn(async move {
                arbiter.shutdown().await;
                let _ = tx.send(true);
                Ok(())
            })?;
        self.spawn_listeners(tasks, &rx)
    }

    #[instrument(skip_all)]
    async fn refresh(&self) -> Result<()> {
        let api = &self.controller.api_config;
        let providers = fetch_all(
            |page| outposts_kerberos_list(api, None, None, Some(page), Some(PAGE_SIZE), None),
            |r| &r.pagination,
            |r| r.results,
        )
        .await
        .inspect_err(|err| error!(?err, "failed to fetch providers"))?;
        debug!(count = providers.len(), "fetched providers");
        if providers.is_empty() {
            warn!(
                "no providers assigned to this outpost, check outpost configuration in authentik"
            );
        }

        let mut realms = Vec::with_capacity(providers.len());
        for provider in &providers {
            match self.build_provider(provider).await {
                Ok(kdc) => {
                    info!(
                        name = provider.name,
                        realm = provider.realm_name,
                        "loaded provider"
                    );
                    realms.push(Arc::new(kdc));
                }
                Err(err) => warn!(
                    ?err,
                    name = provider.name,
                    "failed to set up provider, skipping"
                ),
            }
        }
        self.dispatcher
            .realms
            .store((!realms.is_empty()).then(|| Arc::new(KdcRealms::new(realms))));
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "Kerberos tickets aren't tied to sessions"
    )]
    async fn end_session(&self, _event: EventSessionEnd) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ak_client::models::KerberosRealmTrustOutpost;

    use super::*;

    #[test]
    fn capaths_cover_both_directions() {
        let trusts = vec![KerberosRealmTrustOutpost {
            remote_realm: "REMOTE.TEST".to_owned(),
            capaths: vec!["MID.TEST".to_owned()],
            outgoing_kvno: 1,
            outgoing_keys: HashMap::default(),
            incoming_kvno: 1,
            incoming_keys: HashMap::default(),
        }];
        let text = capaths("LOCAL.TEST", &trusts);
        assert_eq!(
            text,
            "[capaths]\n\tLOCAL.TEST = {\n\t\tREMOTE.TEST = MID.TEST\n\t}\n\tREMOTE.TEST = \
             {\n\t\tLOCAL.TEST = MID.TEST\n\t}\n"
        );
        Profile::parse(&text).expect("parse capaths profile");
    }
}
