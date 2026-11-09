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
    kpasswd::{Kpasswd, KpasswdRealm},
    policy::AccessPolicy,
    store::{ProviderStore, StoreSettings, StoreSources},
};
use crate::outpost::{Outpost, OutpostController, event::EventSessionEnd};

mod audit;
mod kkdcp;
mod kpasswd;
mod otp;
mod pac;
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

/// Routes requests to the realms of the most recent refresh that accept the
/// request's transport.
#[derive(Default)]
struct Dispatcher {
    udp: ArcSwapOption<KdcRealms<Arc<ProviderStore>>>,
    tcp: ArcSwapOption<KdcRealms<Arc<ProviderStore>>>,
}

fn kdc_realms(realms: Vec<Arc<ProviderKdc>>) -> Option<Arc<KdcRealms<Arc<ProviderStore>>>> {
    (!realms.is_empty()).then(|| Arc::new(KdcRealms::new(realms)))
}

impl KdcService for Dispatcher {
    async fn handle_summarized_from(
        &self,
        request: &[u8],
        transport: Transport,
        peer: Option<SocketAddr>,
    ) -> (Vec<u8>, Option<RequestSummary>) {
        let realms = match transport {
            Transport::Udp => &self.udp,
            Transport::Tcp => &self.tcp,
        };
        let Some(realms) = realms.load_full() else {
            return (Vec::new(), None);
        };
        realms
            .handle_summarized_from(request, transport, peer)
            .await
    }

    fn bare_error(&self, code: i32, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        self.tcp
            .load_full()
            .or_else(|| self.udp.load_full())
            .map(|realms| realms.bare_error(code, now))
            .unwrap_or_default()
    }
}

pub(crate) struct KerberosOutpost {
    controller: Arc<OutpostController>,
    dispatcher: Arc<Dispatcher>,
    kpasswd: Arc<Kpasswd>,
    kkdcp: Arc<kkdcp::Kkdcp>,
    certificates: ak_common::tls::store::CertificateStore,
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
    async fn build_provider(
        &self,
        provider: &KerberosOutpostConfig,
    ) -> Result<(ProviderKdc, Arc<ProviderStore>)> {
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
        let realm_sid = provider
            .pac_enabled
            .unwrap_or_default()
            .then_some(provider.realm_sid.as_deref())
            .flatten()
            .filter(|s| !s.is_empty())
            .and_then(|sid| {
                pac::Sid::parse(sid)
                    .inspect_err(|err| warn!(?err, "ignoring invalid PAC realm SID"))
                    .ok()
            });
        let otp_enabled = provider.otp_enabled.unwrap_or_default();
        let otp_indicators = provider.otp_indicators.clone().unwrap_or_default();
        let store = Arc::new(ProviderStore::new(
            api.clone(),
            provider.pk,
            StoreSettings {
                realm: realm.clone(),
                enctypes: enctypes.clone(),
                base_attributes: base_attributes(provider),
                require_preauth: provider.require_preauthentication.unwrap_or(true),
                anonymous_pkinit: provider.anonymous_pkinit_enabled.unwrap_or_default(),
                realm_sid: realm_sid.clone(),
                otp: otp_enabled,
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
        cfg.disable_pac = realm_sid.is_none();
        cfg.spake_indicators = provider.spake_indicators.clone().unwrap_or_default();
        cfg.encrypted_challenge_indicator = provider
            .encrypted_challenge_indicator
            .clone()
            .filter(|s| !s.is_empty());
        cfg.otp_token_types = otp_enabled.then(|| vec![otp::token_type(otp_indicators.clone())]);
        if !trusts.is_empty() {
            cfg.realm_profile = Some(
                Profile::parse(&capaths(&realm, &trusts))
                    .map_err(|err| eyre!("capaths: {err:?}"))?,
            );
        }

        let mut builder =
            Kdc::builder(cfg, Arc::clone(&store)).kdcpolicy(vec![Arc::new(AccessPolicy {
                store: Arc::clone(&store),
            })]);
        if provider.kdc_audit_enabled.unwrap_or_default() {
            builder = builder.audit(vec![audit::ApiAudit::spawn(api.clone(), provider.pk)]);
        }
        if otp_enabled {
            builder = builder.otp_verifier(Arc::new(otp::ApiOtp {
                store: Arc::clone(&store),
                indicators: otp_indicators,
            }));
        }
        let kdc = builder.build();
        Ok((kdc, store))
    }

    async fn kkdcp_certificate(
        &self,
        provider: &KerberosOutpostConfig,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if !provider.kkdcp_enabled.unwrap_or_default() {
            return None;
        }
        let Some(uuid) = provider.kkdcp_certificate.flatten() else {
            warn!(
                provider = provider.name,
                "KKDCP is enabled but no TLS certificate is configured"
            );
            return None;
        };
        self.certificates
            .ensure_keypair(&self.controller.api_config, uuid)
            .await
            .inspect_err(|err| {
                warn!(
                    ?err,
                    provider = provider.name,
                    "failed to fetch KKDCP TLS certificate"
                );
            })
            .ok()
            .map(|cert| Arc::clone(&cert.certified_key))
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
        for addr in config::get().listen.kpasswd.iter().copied() {
            let udp = std::net::UdpSocket::bind(addr)?;
            udp.set_nonblocking(true)?;
            let udp = tokio::net::UdpSocket::from_std(udp)?;
            let (svc, rx) = (Arc::clone(&self.kpasswd), shutdown.clone());
            tasks
                .build_task()
                .name(&format!("{}::kpasswd::udp::{addr}", module_path!()))
                .spawn(kpasswd::serve_udp(svc, udp, rx))?;

            let tcp = std::net::TcpListener::bind(addr)?;
            tcp.set_nonblocking(true)?;
            let tcp = tokio::net::TcpListener::from_std(tcp)?;
            let (svc, rx) = (Arc::clone(&self.kpasswd), shutdown.clone());
            tasks
                .build_task()
                .name(&format!("{}::kpasswd::tcp::{addr}", module_path!()))
                .spawn(kpasswd::serve_tcp(svc, tcp, rx))?;
            info!(%addr, "kpasswd listening");
        }
        for addr in config::get().listen.kkdcp.iter().copied() {
            let resolver: Arc<dyn rustls::server::ResolvesServerCert> =
                Arc::<kkdcp::Kkdcp>::clone(&self.kkdcp);
            let tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            ak_axum::server::start_tls(
                tasks,
                "kerberos-kkdcp",
                Arc::clone(&self.kkdcp).router(),
                addr,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
            )?;
            info!(%addr, "KKDCP listening");
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
            kpasswd: Arc::new(Kpasswd::default()),
            kkdcp: Arc::new(kkdcp::Kkdcp::new(Arc::new(
                ak_common::tls::self_signed::generate_certifiedkey()?,
            ))),
            certificates: ak_common::tls::store::CertificateStore::new(),
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

        let (mut udp, mut tcp, mut kkdcp) = (Vec::new(), Vec::new(), Vec::new());
        let mut kkdcp_cert = None;
        let mut kpasswd = std::collections::HashMap::new();
        for provider in &providers {
            match self.build_provider(provider).await {
                Ok((kdc, store)) => {
                    if provider.kpasswd_enabled.unwrap_or_default() {
                        kpasswd.insert(
                            provider.realm_name.clone(),
                            Arc::new(KpasswdRealm {
                                store,
                                udp: provider.udp_enabled.unwrap_or_default(),
                                tcp: provider.tcp_enabled.unwrap_or_default(),
                            }),
                        );
                    }
                    info!(
                        name = provider.name,
                        realm = provider.realm_name,
                        "loaded provider"
                    );
                    let kdc = Arc::new(kdc);
                    if let Some(cert) = self.kkdcp_certificate(provider).await {
                        kkdcp_cert.get_or_insert(cert);
                        kkdcp.push(Arc::clone(&kdc));
                    }
                    if provider.udp_enabled.unwrap_or_default() {
                        udp.push(Arc::clone(&kdc));
                    }
                    if provider.tcp_enabled.unwrap_or_default() {
                        tcp.push(kdc);
                    }
                }
                Err(err) => warn!(
                    ?err,
                    name = provider.name,
                    "failed to set up provider, skipping"
                ),
            }
        }
        self.kpasswd.realms.store(Arc::new(kpasswd));
        self.dispatcher.udp.store(kdc_realms(udp));
        self.dispatcher.tcp.store(kdc_realms(tcp));
        self.kkdcp.realms.store(kdc_realms(kkdcp));
        self.kkdcp.certificate.store(kkdcp_cert);
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
