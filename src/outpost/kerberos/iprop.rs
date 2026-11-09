//! Incremental propagation (iprop) to MIT replica KDCs, served from an
//! in-memory update log.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

use ak_client::models::KerberosOutpostConfig;
use arc_swap::ArcSwapOption;
use eyre::{Result, eyre};
use krb5_rs::{
    gssapi::krb5::Krb5Acceptor,
    kdc::kdb::mit::{
        MitEntry,
        dump::{DumpVersion, IpropHeader, write_dump},
        parse_name_with_default,
        ulog::{Last, Time, Update, UpdateStatus, XdrReader, XdrWriter, update_from_entry},
        unparse_name,
    },
    protocol::ap::{ApError, KeySource},
    rpc::{
        AcceptStat, AuthStat, Call, CallError, Reply,
        gss::{GssServer, ServerStep},
        read_record, write_record,
    },
    types::{EncryptionKey, PrincipalName},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tracing::{info, warn};

use super::{
    kprop::Source,
    store::{ProviderStore, components},
};

const IPROP_PROG: u32 = 100_423;
const IPROP_VERS: u32 = 1;
const IPROP_NULL: u32 = 0;
const IPROP_GET_UPDATES: u32 = 1;
const IPROP_FULL_RESYNC: u32 = 2;
const IPROP_FULL_RESYNC_EXT: u32 = 3;
const DEFAULT_ULOG_SIZE: usize = 1000;

/// The replicated database and the updates that led to it.
pub(crate) struct Mirror {
    entries: BTreeMap<Vec<u8>, MitEntry>,
    log: VecDeque<Update>,
    /// The serial number and time just before the oldest logged update.
    base: Last,
    last: Last,
    capacity: usize,
}

impl Mirror {
    fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            log: VecDeque::new(),
            base: Last::default(),
            last: Last::default(),
            capacity: capacity.max(1),
        }
    }

    fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
        self.trim();
    }

    fn trim(&mut self) {
        while self.log.len() > self.capacity {
            if let Some(oldest) = self.log.pop_front() {
                self.base = Last {
                    sno: oldest.sno,
                    time: oldest.time,
                };
            }
        }
    }

    /// Replace the database with `entries`, logging one update per change.
    /// The first sync only sets the database; replicas fully resync to it.
    pub(crate) fn sync(&mut self, entries: Vec<MitEntry>) {
        let new: BTreeMap<Vec<u8>, MitEntry> = entries
            .into_iter()
            .map(|e| (unparse_name(&e.principal, &e.realm), e))
            .collect();
        if self.last.sno == 0 {
            self.entries = new;
            self.last = Last {
                sno: 1,
                time: Time::now(),
            };
            self.base = self.last;
            return;
        }
        let mut updates: Vec<Update> = new
            .iter()
            .filter(|(name, entry)| self.entries.get(*name) != Some(*entry))
            .map(|(name, entry)| update_from_entry(self.entries.get(name), entry))
            .collect();
        updates.extend(
            self.entries
                .keys()
                .filter(|name| !new.contains_key(*name))
                .map(|name| Update::deletion(name.clone())),
        );
        self.entries = new;
        for mut update in updates {
            update.sno = self.last.sno.wrapping_add(1);
            update.time = Time::now();
            update.commit = true;
            self.last = Last {
                sno: update.sno,
                time: update.time,
            };
            self.log.push_back(update);
        }
        self.trim();
    }

    /// `ulog_get_entries`: the status, the updates after `last` and the
    /// log's last serial number and time.
    fn get_entries(&self, last: &Last) -> (UpdateStatus, Vec<Update>, Last) {
        if last.sno == self.last.sno && last.time == self.last.time {
            return (UpdateStatus::Nil, Vec::new(), Last::default());
        }
        let in_range = last.sno >= self.base.sno && last.sno < self.last.sno;
        let Some(skip) = in_range
            .then(|| usize::try_from(last.sno - self.base.sno).ok())
            .flatten()
        else {
            return (UpdateStatus::FullResyncNeeded, Vec::new(), Last::default());
        };
        let known = if skip == 0 {
            self.base.time
        } else {
            match self.log.get(skip - 1) {
                Some(update) => update.time,
                None => return (UpdateStatus::FullResyncNeeded, Vec::new(), Last::default()),
            }
        };
        if known != last.time {
            return (UpdateStatus::FullResyncNeeded, Vec::new(), Last::default());
        }
        (
            UpdateStatus::Ok,
            self.log.iter().skip(skip).cloned().collect(),
            self.last,
        )
    }

    /// The database as an iprop dump (`kdb5_util dump -i`, or `-i1` when
    /// `extensible`), headed with the log position it reflects.
    fn dump(&self, extensible: bool) -> Vec<u8> {
        let entries: Vec<MitEntry> = self.entries.values().cloned().collect();
        let body = write_dump(DumpVersion::R111, &entries, &[]);
        let header = IpropHeader {
            extensible,
            sno: self.last.sno,
            seconds: self.last.time.seconds,
            useconds: self.last.time.useconds,
        };
        let mut out = header.line().into_bytes();
        out.extend_from_slice(&body[DumpVersion::R111.header().len()..]);
        out
    }
}

/// The realm served on the iprop listeners.
pub(crate) struct IpropRealm {
    store: Arc<ProviderStore>,
    source: Arc<Source>,
    mirror: Arc<Mutex<Mirror>>,
    allowed: Vec<String>,
}

impl IpropRealm {
    pub(crate) fn new(
        provider: &KerberosOutpostConfig,
        store: Arc<ProviderStore>,
        source: Arc<Source>,
        mirror: Arc<Mutex<Mirror>>,
    ) -> Self {
        Self {
            store,
            source,
            mirror,
            allowed: provider.iprop_allowed_replicas.clone().unwrap_or_default(),
        }
    }

    fn authorized(&self, client: &PrincipalName, crealm: &str) -> bool {
        let realm = &self.store.settings().realm;
        self.allowed.iter().any(|allowed| {
            parse_name_with_default(allowed.trim(), realm)
                .is_ok_and(|(name, r)| r == crealm && name.name_string == client.name_string)
        })
    }

    fn mirror(&self) -> std::sync::MutexGuard<'_, Mirror> {
        self.mirror.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn get_updates(&self, client: &PrincipalName, crealm: &str, last: &Last) -> Result<Vec<u8>> {
        let mut w = XdrWriter::default();
        if !self.authorized(client, crealm) {
            info!(client = %unparsed(client, crealm), "unauthorized iprop request");
            w.last(Last::default());
            w.u32(0);
            w.u32(status_code(UpdateStatus::PermDenied));
            return Ok(w.0);
        }
        let (status, updates, end) = self.mirror().get_entries(last);
        w.last(end);
        w.u32(u32::try_from(updates.len())?);
        for update in &updates {
            w.update(update).map_err(|err| eyre!("{err}"))?;
        }
        w.u32(status_code(status));
        Ok(w.0)
    }

    /// `ipropx_resync`: send the mirror to the client's host with kprop.
    fn full_resync(&self, client: &PrincipalName, crealm: &str, vers: u32) -> Vec<u8> {
        let comps = components(client);
        let status = match comps.as_slice() {
            _ if !self.authorized(client, crealm) => UpdateStatus::PermDenied,
            _ if vers > 1 || !self.source.has_client() => UpdateStatus::Error,
            [kiprop, host] if kiprop == "kiprop" => {
                let dump = self.mirror().dump(vers == 1);
                let (source, host) = (Arc::clone(&self.source), host.clone());
                tokio::spawn(async move {
                    match Box::pin(source.push(&host, &dump)).await {
                        Ok(()) => info!(host, "full iprop resync sent"),
                        Err(err) => warn!(?err, host, "full iprop resync failed"),
                    }
                });
                UpdateStatus::Ok
            }
            _ => UpdateStatus::PermDenied,
        };
        let mut w = XdrWriter::default();
        w.last(Last::default());
        w.u32(status_code(status));
        w.0
    }
}

const fn status_code(status: UpdateStatus) -> u32 {
    match status {
        UpdateStatus::Ok => 0,
        UpdateStatus::Error => 1,
        UpdateStatus::FullResyncNeeded => 2,
        UpdateStatus::Busy => 3,
        UpdateStatus::Nil => 4,
        UpdateStatus::PermDenied => 5,
    }
}

fn unparsed(name: &PrincipalName, realm: &str) -> String {
    String::from_utf8_lossy(&unparse_name(name, realm)).into_owned()
}

#[derive(Default)]
pub(crate) struct Iprop {
    pub(crate) realm: ArcSwapOption<IpropRealm>,
    mirrors: Mutex<HashMap<i32, Arc<Mutex<Mirror>>>>,
}

impl Iprop {
    /// The provider's mirror, kept across refreshes.
    pub(crate) fn mirror(&self, provider: &KerberosOutpostConfig, id: i32) -> Arc<Mutex<Mirror>> {
        let capacity = provider
            .iprop_ulog_size
            .and_then(|s| usize::try_from(s).ok())
            .filter(|s| *s > 0)
            .unwrap_or(DEFAULT_ULOG_SIZE);
        let mut mirrors = self.mirrors.lock().unwrap_or_else(PoisonError::into_inner);
        let mirror = mirrors
            .entry(id)
            .or_insert_with(|| Arc::new(Mutex::new(Mirror::new(capacity))));
        mirror
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set_capacity(capacity);
        Arc::clone(mirror)
    }

    /// Drop the mirrors of providers that no longer replicate.
    pub(crate) fn retain(&self, ids: &[i32]) {
        self.mirrors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| ids.contains(id));
    }
}

/// `kiprop/*` keys for the GSS acceptor.
struct IpropKeys(Arc<ProviderStore>);

impl KeySource for IpropKeys {
    fn get_key(
        &self,
        server: &PrincipalName,
        _realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        let comps = components(server);
        let comps: Vec<&str> = comps.iter().map(String::as_str).collect();
        if !matches!(comps.as_slice(), ["kiprop", _]) {
            return Err(ApError::NoKey);
        }
        let entry = self.0.entry(&comps).ok_or(ApError::NoKey)?;
        let mut keys = entry.keys.iter().filter(|k| k.key.keytype == etype);
        match kvno.filter(|v| *v > 0_i32) {
            None => keys.next(),
            Some(kvno) => keys.find(|k| i64::from(k.kvno) == i64::from(kvno)),
        }
        .map(|k| k.key.clone())
        .ok_or(ApError::NoKey)
    }
}

pub(crate) async fn serve_tcp(
    iprop: Arc<Iprop>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let (stream, remote) = tokio::select! {
            accept = listener.accept() => match accept {
                Ok(r) => r,
                Err(err) => {
                    warn!(?err, "iprop accept failed");
                    continue;
                }
            },
            _ = shutdown.wait_for(|v| *v) => return Ok(()),
        };
        let Some(realm) = iprop.realm.load_full() else {
            continue;
        };
        tokio::spawn(async move {
            if let Err(err) = serve_stream(realm, stream).await {
                warn!(?err, %remote, "iprop connection failed");
            }
        });
    }
}

async fn serve_stream(realm: Arc<IpropRealm>, mut stream: TcpStream) -> Result<()> {
    let store = Arc::clone(&realm.store);
    let mut gss = GssServer::new(Box::new(move || {
        Krb5Acceptor::new(Box::new(IpropKeys(Arc::clone(&store))), None, None)
    }));
    while let Some(record) = read_record(&mut stream).await? {
        let out = match Call::decode(&record) {
            Ok(call) => match gss.handle(&call) {
                ServerStep::Send(reply) => reply,
                ServerStep::Dispatch { proc_, args, seq } => {
                    dispatch(&realm, &mut gss, &call, proc_, &args, seq)?
                }
            },
            Err(CallError::RpcMismatch(xid)) => Reply::RpcMismatch(2, 2).encode(xid),
            Err(CallError::Garbage(err)) => return Err(eyre!("undecodable call: {err:?}")),
        };
        write_record(&mut stream, &out).await?;
    }
    Ok(())
}

/// `krb5_iprop_prog_1` and `check_iprop_rpcsec_auth` (`ipropd_svc.c`).
fn dispatch(
    realm: &IpropRealm,
    gss: &mut GssServer,
    call: &Call,
    proc_: u32,
    args: &[u8],
    seq: u32,
) -> Result<Vec<u8>> {
    let xid = call.header.xid;
    let reject = |gss: &mut GssServer, stat| {
        gss.reply_error(xid, seq, stat)
            .map_err(|err| eyre!("{err:?}"))
    };
    if call.header.prog != IPROP_PROG {
        return reject(gss, AcceptStat::ProgUnavail);
    }
    if call.header.vers != IPROP_VERS {
        return reject(gss, AcceptStat::ProgMismatch(IPROP_VERS, IPROP_VERS));
    }
    let Some(ctx) = gss.context() else {
        return Ok(Reply::AuthError(AuthStat::BadCred).encode(xid));
    };
    if !matches!(components(ctx.acceptor()).as_slice(), [k, _] if k == "kiprop") {
        return Ok(Reply::AuthError(AuthStat::TooWeak).encode(xid));
    }
    let client = ctx.initiator().clone();
    let crealm = ctx.initiator_realm().to_owned();
    let results = match proc_ {
        IPROP_NULL => Vec::new(),
        IPROP_GET_UPDATES => {
            let mut r = XdrReader::new(args);
            match r.last() {
                Ok(last) if r.remaining() == 0 => realm.get_updates(&client, &crealm, &last)?,
                _ => return reject(gss, AcceptStat::GarbageArgs),
            }
        }
        IPROP_FULL_RESYNC if args.is_empty() => realm.full_resync(&client, &crealm, 0),
        IPROP_FULL_RESYNC_EXT => {
            let mut r = XdrReader::new(args);
            match r.u32() {
                Ok(vers) if r.remaining() == 0 => realm.full_resync(&client, &crealm, vers),
                _ => return reject(gss, AcceptStat::GarbageArgs),
            }
        }
        IPROP_FULL_RESYNC => return reject(gss, AcceptStat::GarbageArgs),
        _ => return reject(gss, AcceptStat::ProcUnavail),
    };
    gss.reply(xid, seq, &results)
        .map_err(|err| eyre!("{err:?}"))
}

#[cfg(test)]
mod tests {
    use krb5_rs::kdc::kdb::mit::KeyData;

    use super::*;

    fn entry(name: &str, kvno: u16) -> MitEntry {
        MitEntry {
            principal: PrincipalName::new_principal(name),
            realm: "EXAMPLE.TEST".to_owned(),
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            expiration: 0,
            pw_expiration: 0,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            tl_data: Vec::new(),
            key_data: vec![KeyData {
                ver: 1,
                kvno,
                fields: vec![(18, vec![1, 2, 3])],
            }],
        }
    }

    #[test]
    fn mirror_logs_changes_and_reports_status() {
        let mut mirror = Mirror::new(2);
        mirror.sync(vec![entry("a", 1), entry("b", 1)]);
        let start = mirror.last;
        assert_eq!(start.sno, 1);
        assert!(mirror.log.is_empty());
        assert_eq!(
            mirror.get_entries(&Last::default()).0,
            UpdateStatus::FullResyncNeeded
        );
        assert_eq!(mirror.get_entries(&start).0, UpdateStatus::Nil);

        mirror.sync(vec![entry("a", 2), entry("b", 1), entry("c", 1)]);
        let (status, updates, end) = mirror.get_entries(&start);
        assert_eq!(status, UpdateStatus::Ok);
        assert_eq!(updates.len(), 2);
        assert_eq!(end, mirror.last);
        assert_eq!(
            updates.iter().map(|u| u.sno).collect::<Vec<_>>(),
            vec![2, 3]
        );

        mirror.sync(vec![entry("a", 2), entry("c", 1)]);
        let (status, updates, _) = mirror.get_entries(&start);
        assert_eq!(
            status,
            UpdateStatus::FullResyncNeeded,
            "trimmed: {updates:?}"
        );
        let mid = mirror.base;
        assert_eq!(mid.sno, 2);
        let (status, updates, _) = mirror.get_entries(&mid);
        assert_eq!(status, UpdateStatus::Ok);
        assert_eq!(updates.len(), 2);
        assert!(updates[1].deleted);

        let stale = Last {
            sno: 3,
            time: Time {
                seconds: 1,
                useconds: 0,
            },
        };
        assert_eq!(mirror.get_entries(&stale).0, UpdateStatus::FullResyncNeeded);
    }

    #[test]
    fn dump_has_iprop_header() {
        let mut mirror = Mirror::new(10);
        mirror.sync(vec![entry("a", 1)]);
        let dump = String::from_utf8(mirror.dump(true)).expect("utf8");
        let first = dump.lines().next().expect("header");
        assert!(first.starts_with("ipropx 1 1 "), "{first}");
        assert!(!dump.contains("kdb5_util load_dump"));
    }
}
