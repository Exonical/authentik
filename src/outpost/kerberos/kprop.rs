//! Full database propagation (kprop) to MIT replica KDCs.

use std::{io::Cursor, sync::Arc, time::Duration};

use ak_client::{
    apis::outposts_api::outposts_kerberos_user_keys_list, models::KerberosOutpostConfig,
};
use ak_common::api::fetch_all;
use eyre::{Result, eyre};
use krb5_rs::{
    Krb5Error,
    client::KerberosClient,
    kdc::{
        KeyEntry, PrincipalAttributes, PrincipalEntry, Transport,
        kdb::{
            kprop::{self, ErrorParties},
            master::{master_key_from_password, master_principal_named},
            mit::{
                MitEntry,
                dump::{DumpVersion, write_dump},
                mkey::MasterKeys,
                parse_name_with_default,
            },
        },
        replication::StoredPrincipal,
    },
    protocol::AsExchangeConfig,
    transport::KdcTransport,
    types::EncryptionKey,
};
use tokio::{net::TcpStream, sync::Mutex, task::AbortHandle};
use tracing::{info, warn};

use super::{
    PAGE_SIZE, ProviderKdc,
    iprop::Mirror,
    store::{ProviderStore, components, new_entry},
};

const KPROP_PORT: u16 = 754;
const CLOCKSKEW: Duration = Duration::from_secs(300);
const MASTER_ENCTYPE: i32 = 18;

/// Sends AS and TGS requests to the provider's own KDC without a socket.
struct LocalTransport(Arc<ProviderKdc>);

impl KdcTransport for LocalTransport {
    async fn send_recv(&self, _realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let (reply, _) = self
            .0
            .handle_summarized_from(message, Transport::Tcp, None)
            .await;
        if reply.is_empty() {
            return Err(Krb5Error::ReplyValidation("local KDC returned no reply"));
        }
        Ok(reply)
    }
}

/// A provider's principals as MIT entries, and the kprop client that sends them.
pub(crate) struct Source {
    name: String,
    store: Arc<ProviderStore>,
    kdc: Arc<ProviderKdc>,
    client: Option<String>,
    master: EncryptionKey,
}

impl Source {
    /// The source for `provider`, or `None` without a master password.
    pub(crate) fn new(
        provider: &KerberosOutpostConfig,
        store: Arc<ProviderStore>,
        kdc: Arc<ProviderKdc>,
    ) -> Result<Option<Arc<Self>>> {
        let password = provider.kprop_master_password.clone().unwrap_or_default();
        if password.is_empty() {
            return Ok(None);
        }
        let master = master_key_from_password(&provider.realm_name, &password, MASTER_ENCTYPE)
            .map_err(|err| eyre!("derive kprop master key: {err}"))?;
        Ok(Some(Arc::new(Self {
            name: provider.name.clone(),
            store,
            kdc,
            client: provider
                .kprop_client_spn
                .clone()
                .filter(|c| !c.trim().is_empty()),
            master,
        })))
    }

    pub(crate) fn has_client(&self) -> bool {
        self.client.is_some()
    }

    /// Every principal with keys, except `kadmin/admin`, with keys encrypted
    /// under the master key.
    pub(crate) async fn entries(&self) -> Result<Vec<MitEntry>> {
        let realm = &self.store.settings().realm;
        let masters = MasterKeys::single(self.master.clone());
        let km_name = master_principal_named("K/M").map_err(|err| eyre!("{err}"))?;
        let km = new_entry(
            km_name,
            realm,
            PrincipalAttributes::DISALLOW_ALL_TIX
                | PrincipalAttributes::REQUIRES_PRE_AUTH
                | PrincipalAttributes::LOCKDOWN_KEYS,
            vec![KeyEntry {
                kvno: 1,
                key: self.master.clone(),
                salt: None,
                s2kparams: None,
            }],
        );
        let mut entries = vec![km];
        entries.extend(
            self.store
                .entries()
                .filter(|e| !is_kadmin_admin(e))
                .cloned(),
        );
        let users = fetch_all(
            |page| {
                outposts_kerberos_user_keys_list(
                    self.store.api(),
                    self.store.provider_id(),
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
        for user in &users {
            entries.push(self.store.user_entry(user)?);
        }
        entries
            .iter()
            .filter(|e| !e.keys.is_empty())
            .map(|e| {
                StoredPrincipal::from_entry(e, None, None, &masters)
                    .and_then(|stored| stored.to_mit(&masters))
                    .map_err(|err| eyre!("{}: {err}", components(&e.name).join("/")))
            })
            .collect()
    }

    /// Authenticate as the kprop client SPN and send `dump` to `target`.
    pub(crate) async fn push(&self, target: &str, dump: &[u8]) -> Result<()> {
        let spn = self
            .client
            .as_deref()
            .ok_or_else(|| eyre!("no kprop client SPN configured"))?;
        let realm = &self.store.settings().realm;
        let (host, port) = target_address(target)?;
        let (name, _) = parse_name_with_default(spn, realm)
            .map_err(|err| eyre!("parse kprop client SPN: {err}"))?;
        let comps = components(&name);
        let comps: Vec<&str> = comps.iter().map(String::as_str).collect();
        let entry = self
            .store
            .entry(&comps)
            .ok_or_else(|| eyre!("kprop client SPN {spn} not found"))?;
        let kvno = entry.keys.iter().map(|k| k.kvno).max();
        let keys: Vec<EncryptionKey> = entry
            .keys
            .iter()
            .filter(|k| Some(k.kvno) == kvno)
            .map(|k| k.key.clone())
            .collect();
        if keys.is_empty() {
            return Err(eyre!("kprop client SPN {spn} has no keys"));
        }
        let client = KerberosClient::new(realm.clone(), LocalTransport(Arc::clone(&self.kdc)));
        let tgt = Box::pin(
            client.acquire_tgt_with_keys(AsExchangeConfig::new_no_pac(name, realm.clone()), keys),
        )
        .await
        .map_err(|err| eyre!("obtain kprop client TGT: {err}"))?;
        let cred = client
            .get_service_ticket(&tgt, &format!("host/{}", host.to_ascii_lowercase()))
            .await
            .map_err(|err| eyre!("obtain kprop service ticket: {err}"))?;
        let mut stream = TcpStream::connect((host.as_str(), port)).await?;
        let local = stream.local_addr()?;
        let mut ctx = kprop::new_auth_context(&local, CLOCKSKEW);
        kprop::sendauth(&mut stream, &mut ctx, &cred)
            .await
            .map_err(|err| eyre!("authenticate to kpropd: {err}"))?;
        let parties = ErrorParties {
            realm,
            server: &cred.server,
            client: Some((&cred.client, &cred.crealm)),
        };
        kprop::xmit_database(
            &mut stream,
            &mut ctx,
            parties,
            &mut Cursor::new(dump),
            u64::try_from(dump.len())?,
        )
        .await
        .map_err(|err| eyre!("send database: {err}"))
    }
}

/// Periodic full kprop pushes and iprop mirror updates for one provider.
pub(crate) struct KpropJob {
    source: Arc<Source>,
    targets: Vec<String>,
    mirror: Option<Arc<std::sync::Mutex<Mirror>>>,
    interval: Duration,
}

impl KpropJob {
    /// The job for `provider`, or `None` when there's nothing to replicate.
    pub(crate) fn new(
        provider: &KerberosOutpostConfig,
        source: Arc<Source>,
        mirror: Option<Arc<std::sync::Mutex<Mirror>>>,
    ) -> Option<Self> {
        let targets: Vec<String> =
            if provider.kprop_enabled.unwrap_or_default() && source.has_client() {
                provider
                    .kprop_targets
                    .iter()
                    .flatten()
                    .map(|t| t.trim().to_owned())
                    .filter(|t| !t.is_empty())
                    .collect()
            } else {
                Vec::new()
            };
        let interval = provider.kprop_interval.unwrap_or_default();
        if interval == 0 || (targets.is_empty() && mirror.is_none()) {
            return None;
        }
        Some(Self {
            source,
            targets,
            mirror,
            interval: Duration::from_secs(u64::from(interval)),
        })
    }

    #[expect(clippy::infinite_loop, reason = "aborted on refresh")]
    async fn run(self) {
        loop {
            Box::pin(self.tick()).await;
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn tick(&self) {
        let name = &self.source.name;
        let entries = match self.source.entries().await {
            Ok(entries) => entries,
            Err(err) => {
                warn!(?err, name, "failed to snapshot principals for replication");
                return;
            }
        };
        if let Some(mirror) = &self.mirror {
            mirror
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sync(entries.clone());
        }
        if self.targets.is_empty() {
            return;
        }
        let dump = write_dump(DumpVersion::R111, &entries, &[]);
        for target in &self.targets {
            match Box::pin(self.source.push(target, &dump)).await {
                Ok(()) => info!(name, target, "propagated database"),
                Err(err) => warn!(?err, name, target, "failed to propagate database"),
            }
        }
    }
}

fn is_kadmin_admin(entry: &PrincipalEntry) -> bool {
    matches!(components(&entry.name).as_slice(), [a, b] if a == "kadmin" && b == "admin")
}

/// `host`, `host:port`, `[v6]:port` or a bare IPv6 address.
fn target_address(target: &str) -> Result<(String, u16)> {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok((ip.to_string(), KPROP_PORT));
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .map_err(|_err| eyre!("invalid kprop target {target:?}"))?,
        ),
        None => (target, KPROP_PORT),
    };
    if host.is_empty() || host.contains(':') {
        return Err(eyre!("invalid kprop target {target:?}"));
    }
    Ok((host.to_owned(), port))
}

/// The running kprop loops, replaced on every refresh.
#[derive(Default)]
pub(crate) struct Kprop {
    tasks: Mutex<Vec<AbortHandle>>,
}

impl Kprop {
    pub(crate) async fn replace(&self, jobs: Vec<KpropJob>) {
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        tasks.extend(
            jobs.into_iter()
                .map(|job| tokio::spawn(job.run()).abort_handle()),
        );
    }
}

impl Drop for Kprop {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_addresses() {
        assert_eq!(
            target_address("kdc2").expect("host"),
            ("kdc2".to_owned(), 754)
        );
        assert_eq!(
            target_address("kdc2.example.test:1754").expect("port"),
            ("kdc2.example.test".to_owned(), 1754)
        );
        assert_eq!(
            target_address("[::1]:99").expect("v6"),
            ("::1".to_owned(), 99)
        );
        assert_eq!(
            target_address("::1").expect("bare v6"),
            ("::1".to_owned(), 754)
        );
        let err = target_address("kdc2:").expect_err("empty port");
        assert!(err.to_string().contains("invalid kprop target"));
        let err = target_address(":754").expect_err("empty host");
        assert!(err.to_string().contains("invalid kprop target"));
    }
}
