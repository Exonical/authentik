//! kadm5 admin service (`kadmind`) backed by the authentik API.
//!
//! Only the operations authentik models are supported: listing and reading
//! principals, creating, deleting, re-flagging and re-keying service
//! principals, and changing user passwords.

use std::sync::Arc;

use ak_client::{
    apis::{
        Error as ApiError, ResponseContent,
        outposts_api::{
            OutpostsKerberosSetPasswordCreateError, outposts_kerberos_service_principal_create,
            outposts_kerberos_service_principal_delete, outposts_kerberos_service_principal_rotate,
            outposts_kerberos_service_principal_update, outposts_kerberos_set_password_create,
            outposts_kerberos_user_keys_list,
        },
    },
    models::{
        KerberosServicePrincipalAdminRequest, KerberosServicePrincipalUpdateRequest,
        KerberosSetPasswordRequest, TicketFlagsEnum,
    },
};
use ak_common::api::fetch_all;
use arc_swap::ArcSwapOption;
use eyre::{Result, eyre};
use krb5_rs::{
    gssapi::krb5::Krb5Acceptor,
    kdc::{
        PrincipalAttributes, PrincipalEntry, PrincipalStore as _,
        kdb::{
            acl::{
                ACL_ADD, ACL_CHANGEPW, ACL_DELETE, ACL_INQUIRE, ACL_LIST, ACL_MODIFY, AclEntry,
                acl_check, parse_acl,
            },
            kadm5::{
                self, Glob, KADM_PROG, KADM_VERS, KeyBlock, PrincipalEnt, ReadArgs, WriteArgs,
                code, proc_,
            },
            mit::{parse_name_with_default, unparse_name},
        },
    },
    protocol::ap::{ApError, KeySource},
    rpc::{
        AcceptStat, AuthStat, Call, CallError, Reply,
        gss::{GssServer, ServerStep},
        read_record, write_record,
    },
    types::{EncryptionKey, PrincipalName},
};
use reqwest::StatusCode;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tracing::{info, warn};

use super::store::{ProviderStore, components, decode_keys};

const PAGE_SIZE: i32 = 100;

/// The provider served by kadmin; kadmin is single-realm.
pub(crate) struct KadminRealm {
    store: Arc<ProviderStore>,
    acl: Vec<AclEntry>,
}

impl KadminRealm {
    /// Parse the provider's `kadm5.acl` lines; a client without a realm is
    /// in the provider's realm.
    pub(crate) fn new(store: Arc<ProviderStore>, lines: &[String]) -> Result<Self> {
        let realm = store.settings().realm.clone();
        let text = qualify_acl(lines, &realm);
        let acl = parse_acl(&text, &realm).map_err(|err| eyre!("kadmin ACL: {err}"))?;
        Ok(Self { store, acl })
    }

    fn realm(&self) -> &str {
        &self.store.settings().realm
    }
}

/// Append `@realm` to ACL clients without a realm, like the Go outpost.
fn qualify_acl(lines: &[String], realm: &str) -> String {
    lines
        .iter()
        .map(|line| {
            let mut fields: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
            match fields.first_mut() {
                Some(first)
                    if !line.trim().starts_with('#') && first != "*" && !first.contains('@') =>
                {
                    first.push('@');
                    first.push_str(realm);
                    fields.join(" ")
                }
                _ => line.clone(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Default)]
pub(crate) struct Kadmin {
    pub(crate) realm: ArcSwapOption<KadminRealm>,
}

/// `kadmin/admin` and `kadmin/changepw` keys for the GSS acceptor.
struct AdminKeys(Arc<ProviderStore>);

impl KeySource for AdminKeys {
    fn get_key(
        &self,
        server: &PrincipalName,
        _realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        let comps = components(server);
        let comps: Vec<&str> = comps.iter().map(String::as_str).collect();
        if !matches!(comps.as_slice(), ["kadmin", "admin" | "changepw"]) {
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

/// The authenticated caller of one request.
struct Caller {
    client: PrincipalName,
    crealm: String,
    /// Authenticated to `kadmin/changepw`: only self password changes.
    changepw: bool,
}

impl Caller {
    fn is(&self, name: &PrincipalName, realm: &str) -> bool {
        self.crealm == realm && self.client.name_string == name.name_string
    }

    fn name(&self) -> String {
        String::from_utf8_lossy(&unparse_name(&self.client, &self.crealm)).into_owned()
    }
}

pub(crate) async fn serve_tcp(
    kadmin: Arc<Kadmin>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let (stream, remote) = tokio::select! {
            accept = listener.accept() => match accept {
                Ok(r) => r,
                Err(err) => {
                    warn!(?err, "kadmin accept failed");
                    continue;
                }
            },
            _ = shutdown.wait_for(|v| *v) => return Ok(()),
        };
        let Some(realm) = kadmin.realm.load_full() else {
            continue;
        };
        tokio::spawn(async move {
            if let Err(err) = serve_stream(realm, stream).await {
                warn!(?err, %remote, "kadmin connection failed");
            }
        });
    }
}

async fn serve_stream(realm: Arc<KadminRealm>, mut stream: TcpStream) -> Result<()> {
    let store = Arc::clone(&realm.store);
    let mut gss = GssServer::new(Box::new(move || {
        Krb5Acceptor::new(Box::new(AdminKeys(Arc::clone(&store))), None, None)
    }));
    while let Some(record) = read_record(&mut stream).await? {
        let out = match Call::decode(&record) {
            Ok(call) => match gss.handle(&call) {
                ServerStep::Send(reply) => reply,
                ServerStep::Dispatch { proc_, args, seq } => {
                    dispatch(&realm, &mut gss, &call, proc_, &args, seq).await?
                }
            },
            Err(CallError::RpcMismatch(xid)) => Reply::RpcMismatch(2, 2).encode(xid),
            Err(CallError::Garbage(err)) => return Err(eyre!("undecodable call: {err:?}")),
        };
        write_record(&mut stream, &out).await?;
    }
    Ok(())
}

/// `kadm_1` and `check_rpcsec_auth` (`kadm_rpc_svc.c`).
async fn dispatch(
    realm: &KadminRealm,
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
    if call.header.prog != KADM_PROG {
        return reject(gss, AcceptStat::ProgUnavail);
    }
    if call.header.vers != KADM_VERS {
        return reject(gss, AcceptStat::ProgMismatch(KADM_VERS, KADM_VERS));
    }
    let Some(ctx) = gss.context() else {
        return Ok(Reply::AuthError(AuthStat::BadCred).encode(xid));
    };
    let service = components(ctx.acceptor());
    let changepw = match service.as_slice() {
        [k, h] if k == "kadmin" && h != "history" => h == "changepw",
        _ => return Ok(Reply::AuthError(AuthStat::TooWeak).encode(xid)),
    };
    let caller = Caller {
        client: ctx.initiator().clone(),
        crealm: ctx.initiator_realm().to_owned(),
        changepw,
    };
    if proc_ == proc_::NULL {
        return gss.reply(xid, seq, &[]).map_err(|err| eyre!("{err:?}"));
    }
    let results = if let Some(parsed) = WriteArgs::decode(proc_, args) {
        let Ok(parsed) = parsed else {
            return reject(gss, AcceptStat::GarbageArgs);
        };
        realm.write(&caller, parsed).await
    } else if let Some(parsed) = ReadArgs::decode(proc_, args) {
        let Ok(parsed) = parsed else {
            return reject(gss, AcceptStat::GarbageArgs);
        };
        match realm.read(&caller, proc_, parsed).await {
            Some(results) => results,
            None => return reject(gss, AcceptStat::ProcUnavail),
        }
    } else {
        return reject(gss, AcceptStat::ProcUnavail);
    };
    gss.reply(xid, seq, &results)
        .map_err(|err| eyre!("{err:?}"))
}

/// Attribute bits that map to authentik service principal ticket flags.
const TICKET_FLAGS: [(PrincipalAttributes, TicketFlagsEnum); 8] = [
    (
        PrincipalAttributes::REQUIRES_PRE_AUTH,
        TicketFlagsEnum::RequiresPreauth,
    ),
    (
        PrincipalAttributes::REQUIRES_HW_AUTH,
        TicketFlagsEnum::RequiresHwauth,
    ),
    (
        PrincipalAttributes::DISALLOW_POSTDATED,
        TicketFlagsEnum::DisallowPostdated,
    ),
    (
        PrincipalAttributes::DISALLOW_FORWARDABLE,
        TicketFlagsEnum::DisallowForwardable,
    ),
    (
        PrincipalAttributes::DISALLOW_PROXIABLE,
        TicketFlagsEnum::DisallowProxiable,
    ),
    (
        PrincipalAttributes::DISALLOW_RENEWABLE,
        TicketFlagsEnum::DisallowRenewable,
    ),
    (
        PrincipalAttributes::DISALLOW_TGT_BASED,
        TicketFlagsEnum::DisallowTgtBased,
    ),
    (
        PrincipalAttributes::DISALLOW_SVR,
        TicketFlagsEnum::DisallowServer,
    ),
];

fn ticket_flags(attributes: u32) -> Vec<TicketFlagsEnum> {
    let attributes = PrincipalAttributes::from_bits_truncate(attributes);
    TICKET_FLAGS
        .iter()
        .filter(|(bit, _)| attributes.contains(*bit))
        .map(|(_, flag)| *flag)
        .collect()
}

fn status<T>(err: &ApiError<T>) -> Option<StatusCode> {
    match err {
        ApiError::ResponseError(ResponseContent { status, .. }) => Some(*status),
        _ => None,
    }
}

fn duration_secs(d: Option<std::time::Duration>) -> u32 {
    d.map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

fn time_secs(t: Option<krb5_rs::types::KerberosTime>) -> u32 {
    t.map_or(0, |t| u32::try_from(t.timestamp()).unwrap_or(0))
}

fn principal_ent(entry: &PrincipalEntry, mask: i32) -> PrincipalEnt {
    let kvno = entry.keys.iter().map(|k| k.kvno).max().unwrap_or(0);
    let mut ent = PrincipalEnt {
        principal: Some(unparse_name(&entry.name, &entry.realm)),
        mod_name: Some(unparse_name(
            &PrincipalName::new_srv_inst("kadmin", "admin"),
            &entry.realm,
        )),
        princ_expire_time: time_secs(entry.expiration),
        pw_expiration: time_secs(entry.pw_expiration),
        max_life: duration_secs(entry.max_life),
        max_renewable_life: duration_secs(entry.max_renewable_life),
        attributes: entry.attributes.bits(),
        kvno,
        mkvno: 1,
        ..PrincipalEnt::default()
    };
    if mask & kadm5::mask::KEY_DATA != 0_i32 {
        ent.key_data = entry
            .keys
            .iter()
            .map(|k| {
                (
                    if k.salt.is_some() { 2 } else { 1 },
                    u16::try_from(k.kvno).unwrap_or(u16::MAX),
                    i16::try_from(k.key.keytype).unwrap_or(0),
                    0,
                )
            })
            .collect();
    }
    ent
}

impl KadminRealm {
    fn parse(&self, name: &str) -> Option<(PrincipalName, String)> {
        parse_name_with_default(name, self.realm()).ok()
    }

    /// Whether the ACL grants `op` on `target` without restrictions.
    fn permits(&self, caller: &Caller, op: u32, target: Option<(&PrincipalName, &str)>) -> bool {
        if caller.changepw {
            return false;
        }
        acl_check(&self.acl, op, (&caller.client, &caller.crealm), target)
            .is_some_and(|restrictions| restrictions.is_none())
    }

    /// The SPN of a modifiable local service principal.
    fn service(&self, name: &PrincipalName, realm: &str) -> Option<String> {
        let comps = components(name);
        let protected = match comps.as_slice() {
            [first, ..] if first.eq_ignore_ascii_case("krbtgt") => true,
            [first, second] => {
                first.eq_ignore_ascii_case("kadmin") && second.eq_ignore_ascii_case("changepw")
                    || first.eq_ignore_ascii_case("kadmin") && second.eq_ignore_ascii_case("admin")
            }
            _ => false,
        };
        (realm == self.realm() && comps.len() >= 2 && !protected).then(|| comps.join("/"))
    }

    /// The username of a local user principal.
    fn user(&self, name: &PrincipalName, realm: &str) -> Option<String> {
        match components(name).as_slice() {
            [username] if realm == self.realm() => Some(username.clone()),
            _ => None,
        }
    }

    async fn read(&self, caller: &Caller, proc_: u32, args: ReadArgs) -> Option<Vec<u8>> {
        Some(match (proc_, args) {
            (proc_::INIT, ReadArgs::Api(api)) => {
                let c = kadm5::check_api_version(api);
                if c == code::OK {
                    kadm5::generic_ret(api, code::OK)
                } else {
                    kadm5::generic_ret(0, c)
                }
            }
            (proc_::GET_PRIVS, ReadArgs::Api(api)) => {
                let c = kadm5::check_api_version(api);
                if c == code::OK {
                    kadm5::getprivs_ret(api, code::OK, !0)
                } else {
                    kadm5::getprivs_ret(0, c, 0)
                }
            }
            (
                _,
                ReadArgs::GetPrincipal {
                    api_version,
                    princ,
                    mask,
                },
            ) => {
                self.get_principal(caller, api_version, princ.as_deref(), mask)
                    .await
            }
            (proc_::GET_PRINCS, ReadArgs::Name { api_version, name }) => {
                self.list(caller, api_version, name.as_deref()).await
            }
            (proc_::GET_POLS, ReadArgs::Name { api_version, .. }) => {
                if self.permits(caller, ACL_LIST, None) {
                    kadm5::names_ret(api_version, code::OK, &[])
                } else {
                    kadm5::names_ret(api_version, code::AUTH_LIST, &[])
                }
            }
            (proc_::GET_POLICY, ReadArgs::Name { api_version, .. }) => {
                kadm5::gpol_ret(api_version, code::UNK_POLICY, None)
            }
            _ => return None,
        })
    }

    async fn get_principal(
        &self,
        caller: &Caller,
        api: u32,
        princ: Option<&str>,
        mask: i32,
    ) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::gprinc_ret(0, c, None);
        }
        let Some((name, realm)) = princ.and_then(|p| self.parse(p)) else {
            return kadm5::gprinc_ret(api, code::BAD_PRINCIPAL, None);
        };
        if !caller.is(&name, &realm) && !self.permits(caller, ACL_INQUIRE, Some((&name, &realm))) {
            return kadm5::gprinc_ret(api, code::AUTH_GET, None);
        }
        match self.store.lookup(&name, &realm).await {
            Ok(Some(entry)) => kadm5::gprinc_ret(api, code::OK, Some(&principal_ent(&entry, mask))),
            Ok(None) => kadm5::gprinc_ret(api, code::UNK_PRINC, None),
            Err(err) => {
                warn!(?err, "kadmin get_principal failed");
                kadm5::gprinc_ret(api, code::FAILURE, None)
            }
        }
    }

    async fn list(&self, caller: &Caller, api: u32, exp: Option<&str>) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::names_ret(0, c, &[]);
        }
        if !self.permits(caller, ACL_LIST, None) {
            return kadm5::names_ret(api, code::AUTH_LIST, &[]);
        }
        let Some(glob) = Glob::new(exp, true) else {
            return kadm5::names_ret(api, code::EINVAL, &[]);
        };
        let mut names: Vec<Vec<u8>> = self
            .store
            .entries()
            .iter()
            .map(|e| unparse_name(&e.name, &e.realm))
            .collect();
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
        .await;
        match users {
            Ok(users) => names.extend(users.into_iter().filter_map(|u| {
                self.parse(&u.principal)
                    .map(|(name, realm)| unparse_name(&name, &realm))
            })),
            Err(err) => {
                warn!(?err, "kadmin failed to list users");
                return kadm5::names_ret(api, code::FAILURE, &[]);
            }
        }
        names.retain(|n| glob.matches(n));
        names.sort();
        names.dedup();
        kadm5::names_ret(api, code::OK, &names)
    }

    async fn write(&self, caller: &Caller, args: WriteArgs) -> Vec<u8> {
        match args {
            WriteArgs::CreatePrincipal {
                api_version, rec, ..
            } => {
                let name = rec
                    .principal
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default();
                self.create(caller, api_version, &name).await
            }
            WriteArgs::DeletePrincipal { api_version, princ } => {
                self.delete(caller, api_version, princ.as_deref()).await
            }
            WriteArgs::ModifyPrincipal {
                api_version,
                rec,
                mask,
            } => self.modify(caller, api_version, &rec, mask).await,
            WriteArgs::ChpassPrincipal {
                api_version,
                princ,
                keepold,
                pass,
                ..
            } => {
                self.chpass(
                    caller,
                    api_version,
                    princ.as_deref(),
                    keepold,
                    pass.as_deref(),
                )
                .await
            }
            WriteArgs::ChrandPrincipal {
                api_version,
                princ,
                keepold,
                ..
            } => {
                self.chrand(caller, api_version, princ.as_deref(), keepold)
                    .await
            }
            other => {
                let api = write_api_version(&other);
                kadm5::generic_ret(api, code::FAILURE)
            }
        }
    }

    async fn create(&self, caller: &Caller, api: u32, name: &str) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::generic_ret(0, c);
        }
        let Some((name, realm)) = self.parse(name) else {
            return kadm5::generic_ret(api, code::BAD_PRINCIPAL);
        };
        if !self.permits(caller, ACL_ADD, Some((&name, &realm))) {
            return kadm5::generic_ret(api, code::AUTH_ADD);
        }
        let Some(spn) = self.service(&name, &realm) else {
            return kadm5::generic_ret(api, code::FAILURE);
        };
        let request = KerberosServicePrincipalAdminRequest::new(spn.clone());
        let c = match outposts_kerberos_service_principal_create(
            self.store.api(),
            self.store.provider_id(),
            request,
        )
        .await
        {
            Ok(principal) => {
                self.store.apply_service(&principal);
                code::OK
            }
            Err(err) if status(&err) == Some(StatusCode::CONFLICT) => code::DUP,
            Err(err) => {
                warn!(?err, spn, "kadmin create failed");
                code::FAILURE
            }
        };
        info!(
            client = caller.name(),
            spn,
            code = c,
            "kadm5_create_principal"
        );
        kadm5::generic_ret(api, c)
    }

    async fn delete(&self, caller: &Caller, api: u32, princ: Option<&str>) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::generic_ret(0, c);
        }
        let Some((name, realm)) = princ.and_then(|p| self.parse(p)) else {
            return kadm5::generic_ret(api, code::BAD_PRINCIPAL);
        };
        if !self.permits(caller, ACL_DELETE, Some((&name, &realm))) {
            return kadm5::generic_ret(api, code::AUTH_DELETE);
        }
        let Some(spn) = self.service(&name, &realm) else {
            return kadm5::generic_ret(api, code::FAILURE);
        };
        let request = KerberosServicePrincipalAdminRequest::new(spn.clone());
        let c = match outposts_kerberos_service_principal_delete(
            self.store.api(),
            self.store.provider_id(),
            request,
        )
        .await
        {
            Ok(()) => {
                self.store.remove_service(&spn);
                code::OK
            }
            Err(err) if status(&err) == Some(StatusCode::NOT_FOUND) => code::UNK_PRINC,
            Err(err) => {
                warn!(?err, spn, "kadmin delete failed");
                code::FAILURE
            }
        };
        info!(
            client = caller.name(),
            spn,
            code = c,
            "kadm5_delete_principal"
        );
        kadm5::generic_ret(api, c)
    }

    async fn modify(&self, caller: &Caller, api: u32, rec: &PrincipalEnt, mask: i32) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::generic_ret(0, c);
        }
        let name = rec
            .principal
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        let Some((name, realm)) = self.parse(&name) else {
            return kadm5::generic_ret(api, code::BAD_PRINCIPAL);
        };
        if !self.permits(caller, ACL_MODIFY, Some((&name, &realm))) {
            return kadm5::generic_ret(api, code::AUTH_MODIFY);
        }
        if mask & !kadm5::mask::ATTRIBUTES != 0_i32 {
            return kadm5::generic_ret(api, code::BAD_MASK);
        }
        let Some(spn) = self.service(&name, &realm) else {
            return kadm5::generic_ret(api, code::FAILURE);
        };
        let request =
            KerberosServicePrincipalUpdateRequest::new(spn.clone(), ticket_flags(rec.attributes));
        let c = match outposts_kerberos_service_principal_update(
            self.store.api(),
            self.store.provider_id(),
            request,
        )
        .await
        {
            Ok(principal) => {
                self.store.apply_service(&principal);
                code::OK
            }
            Err(err) if status(&err) == Some(StatusCode::NOT_FOUND) => code::UNK_PRINC,
            Err(err) => {
                warn!(?err, spn, "kadmin modify failed");
                code::FAILURE
            }
        };
        info!(
            client = caller.name(),
            spn,
            code = c,
            "kadm5_modify_principal"
        );
        kadm5::generic_ret(api, c)
    }

    async fn chpass(
        &self,
        caller: &Caller,
        api: u32,
        princ: Option<&str>,
        keepold: bool,
        pass: Option<&str>,
    ) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::generic_ret(0, c);
        }
        let Some((name, realm)) = princ.and_then(|p| self.parse(p)) else {
            return kadm5::generic_ret(api, code::BAD_PRINCIPAL);
        };
        if !caller.is(&name, &realm) && !self.permits(caller, ACL_CHANGEPW, Some((&name, &realm))) {
            return kadm5::generic_ret(api, code::AUTH_CHANGEPW);
        }
        let (Some(username), Some(pass), false) = (self.user(&name, &realm), pass, keepold) else {
            return kadm5::generic_ret(api, code::FAILURE);
        };
        let request = KerberosSetPasswordRequest::new(username.clone(), pass.to_owned());
        let c = match outposts_kerberos_set_password_create(
            self.store.api(),
            self.store.provider_id(),
            request,
        )
        .await
        {
            Ok(()) => {
                self.store.invalidate_user(&username);
                code::OK
            }
            Err(ApiError::ResponseError(ResponseContent {
                entity: Some(OutpostsKerberosSetPasswordCreateError::Status400(_)),
                ..
            })) => code::PASS_Q_GENERIC,
            Err(err) => {
                warn!(?err, username, "kadmin password change failed");
                code::FAILURE
            }
        };
        info!(
            client = caller.name(),
            username,
            code = c,
            "kadm5_chpass_principal"
        );
        kadm5::generic_ret(api, c)
    }

    async fn chrand(
        &self,
        caller: &Caller,
        api: u32,
        princ: Option<&str>,
        keepold: bool,
    ) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::chrand_ret(0, c, &[]);
        }
        let Some((name, realm)) = princ.and_then(|p| self.parse(p)) else {
            return kadm5::chrand_ret(api, code::BAD_PRINCIPAL, &[]);
        };
        if !self.permits(caller, ACL_CHANGEPW, Some((&name, &realm))) {
            return kadm5::chrand_ret(api, code::AUTH_CHANGEPW, &[]);
        }
        let (Some(spn), false) = (self.service(&name, &realm), keepold) else {
            return kadm5::chrand_ret(api, code::FAILURE, &[]);
        };
        let request = KerberosServicePrincipalAdminRequest::new(spn.clone());
        let response = match outposts_kerberos_service_principal_rotate(
            self.store.api(),
            self.store.provider_id(),
            request,
        )
        .await
        {
            Ok(response) => {
                self.store.apply_service(&response);
                response
            }
            Err(err) => {
                let c = if status(&err) == Some(StatusCode::NOT_FOUND) {
                    code::UNK_PRINC
                } else {
                    warn!(?err, spn, "kadmin randkey failed");
                    code::FAILURE
                };
                return kadm5::chrand_ret(api, c, &[]);
            }
        };
        let keys = match decode_keys(
            &response.keys,
            &self.store.settings().enctypes,
            response.kvno,
            None,
        ) {
            Ok(keys) => keys,
            Err(err) => {
                warn!(?err, spn, "kadmin randkey returned invalid keys");
                return kadm5::chrand_ret(api, code::FAILURE, &[]);
            }
        };
        let keys: Vec<KeyBlock> = keys
            .iter()
            .map(|k| KeyBlock {
                enctype: k.key.keytype,
                contents: k.key.key_bytes().to_vec(),
            })
            .collect();
        info!(client = caller.name(), spn, "kadm5_randkey_principal");
        kadm5::chrand_ret(api, code::OK, &keys)
    }
}

fn write_api_version(args: &WriteArgs) -> u32 {
    match args {
        WriteArgs::CreatePrincipal { api_version, .. }
        | WriteArgs::DeletePrincipal { api_version, .. }
        | WriteArgs::ModifyPrincipal { api_version, .. }
        | WriteArgs::RenamePrincipal { api_version, .. }
        | WriteArgs::ChpassPrincipal { api_version, .. }
        | WriteArgs::ChrandPrincipal { api_version, .. }
        | WriteArgs::SetkeyPrincipal { api_version, .. }
        | WriteArgs::CreatePolicy { api_version, .. }
        | WriteArgs::DeletePolicy { api_version, .. }
        | WriteArgs::ModifyPolicy { api_version, .. }
        | WriteArgs::Purgekeys { api_version, .. }
        | WriteArgs::SetString { api_version, .. }
        | WriteArgs::ExtractKeys { api_version, .. }
        | WriteArgs::CreateAlias { api_version, .. } => *api_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_clients_get_the_realm() {
        let lines = [
            "admin/admin *".to_owned(),
            "ops@OTHER.TEST l".to_owned(),
            "* i".to_owned(),
        ];
        let text = qualify_acl(&lines, "EXAMPLE.TEST");
        assert_eq!(text, "admin/admin@EXAMPLE.TEST *\nops@OTHER.TEST l\n* i");
        let acl = parse_acl(&text, "EXAMPLE.TEST").expect("ACL");
        let (admin, _) = parse_name_with_default("admin/admin", "EXAMPLE.TEST").expect("principal");
        let (user, _) = parse_name_with_default("user", "EXAMPLE.TEST").expect("principal");
        assert!(acl_check(&acl, ACL_ADD, (&admin, "EXAMPLE.TEST"), None).is_some());
        assert!(acl_check(&acl, ACL_ADD, (&user, "EXAMPLE.TEST"), None).is_none());
        assert!(acl_check(&acl, ACL_INQUIRE, (&user, "EXAMPLE.TEST"), None).is_some());
    }

    #[test]
    fn attributes_map_to_ticket_flags() {
        let attrs = PrincipalAttributes::REQUIRES_PRE_AUTH | PrincipalAttributes::DISALLOW_SVR;
        assert_eq!(
            ticket_flags(attrs.bits()),
            vec![
                TicketFlagsEnum::RequiresPreauth,
                TicketFlagsEnum::DisallowServer
            ]
        );
    }
}
