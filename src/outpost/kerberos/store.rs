//! Principal store backed by the authentik API.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
    time::Duration,
};

use ak_client::{
    apis::{
        Error as ApiError,
        configuration::Configuration,
        outposts_api::{outposts_kerberos_access_check, outposts_kerberos_user_key_retrieve},
    },
    models::{KerberosRealmTrustOutpost, KerberosServicePrincipalOutpost, KerberosUserKeyOutpost},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use eyre::{Result, eyre};
use hkdf::Hkdf;
use krb5_rs::{
    crypto::find_etype,
    kdc::{
        IssuePac, KeyEntry, PrincipalAttributes, PrincipalEntry, PrincipalStore, StoreError,
        kdb::mit::parse_name_with_default,
    },
    pac::{
        PAC_CLIENT_INFO, PAC_DELEGATION_INFO, PAC_FULL_CHECKSUM, PAC_LOGON_INFO,
        PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM, PAC_UPN_DNS_INFO,
    },
    types::{EncryptionKey, PrincipalName},
};
use moka::{future::Cache, sync::Cache as SyncCache};
use reqwest::StatusCode;
use sha2::Sha256;
use tracing::{info, warn};

use super::pac::{PacIdentity, Sid};

const CACHE_TTL: Duration = Duration::from_mins(1);
const CACHE_CAPACITY: u64 = 10_000;

type EntryKey = (String, Vec<String>);

/// Provider-wide settings applied to every entry.
#[derive(Debug, Clone)]
pub(crate) struct StoreSettings {
    pub(crate) realm: String,
    pub(crate) enctypes: Vec<i32>,
    pub(crate) base_attributes: PrincipalAttributes,
    pub(crate) require_preauth: bool,
    pub(crate) anonymous_pkinit: bool,
    pub(crate) realm_sid: Option<Sid>,
    pub(crate) otp: bool,
}

/// The identity authentik returned for a user, kept for PAC generation.
#[derive(Debug)]
pub(crate) struct UserRecord {
    pub(crate) entry: PrincipalEntry,
    pub(crate) identity: KerberosUserKeyOutpost,
}

pub(crate) struct ProviderStore {
    api: Configuration,
    provider_id: i32,
    settings: StoreSettings,
    entries: HashMap<EntryKey, PrincipalEntry>,
    /// Service principals changed through kadmin since the last refresh;
    /// `None` marks a deletion.
    changes: RwLock<HashMap<EntryKey, Option<PrincipalEntry>>>,
    users: SyncCache<String, Option<std::sync::Arc<UserRecord>>>,
    access: Cache<(bool, String, String), bool>,
}

pub(crate) fn components(name: &PrincipalName) -> Vec<String> {
    name.name_string
        .iter()
        .map(|c| String::from_utf8_lossy(c.as_ref()).into_owned())
        .collect()
}

fn is_tgs_or_changepw(comps: &[String]) -> bool {
    matches!(comps, [a, _] if a == "krbtgt")
        || matches!(comps, [a, b] if a == "kadmin" && b == "changepw")
}

fn derive_key(master: &[u8], etype: i32, prefix: &str) -> Result<EncryptionKey> {
    let profile = find_etype(etype).map_err(|err| eyre!("enctype {etype}: {err:?}"))?;
    let mut out = vec![0_u8; profile.key_bytes()];
    Hkdf::<Sha256>::new(None, master)
        .expand(format!("{prefix}-{etype}").as_bytes(), &mut out)
        .map_err(|err| eyre!("derive {prefix} key: {err}"))?;
    Ok(EncryptionKey::new(etype, out))
}

pub(crate) fn decode_keys(
    values: &HashMap<String, serde_json::Value>,
    enctypes: &[i32],
    kvno: i32,
    salt: Option<&str>,
) -> Result<Vec<KeyEntry>> {
    let kvno = u32::try_from(kvno)?;
    let mut keys = Vec::with_capacity(values.len());
    for (raw, value) in values {
        let etype: i32 = raw.parse()?;
        if !enctypes.contains(&etype) {
            continue;
        }
        let encoded = value
            .as_str()
            .ok_or_else(|| eyre!("key {raw} is not a string"))?;
        let bytes = STANDARD.decode(encoded)?;
        let profile = find_etype(etype).map_err(|err| eyre!("enctype {etype}: {err:?}"))?;
        if bytes.len() != profile.key_bytes() {
            return Err(eyre!("key {raw} has invalid length {}", bytes.len()));
        }
        keys.push(KeyEntry {
            kvno,
            key: EncryptionKey::new(etype, bytes),
            salt: salt
                .filter(|s| !s.is_empty())
                .map(|s| s.as_bytes().to_vec()),
            s2kparams: None,
        });
    }
    keys.sort_by_key(|k| enctypes.iter().position(|e| *e == k.key.keytype));
    Ok(keys)
}

fn ticket_flags(flags: &[String]) -> PrincipalAttributes {
    let mut attrs = PrincipalAttributes::empty();
    for flag in flags {
        attrs |= match flag.as_str() {
            "requires_preauth" => PrincipalAttributes::REQUIRES_PRE_AUTH,
            "requires_hwauth" => PrincipalAttributes::REQUIRES_HW_AUTH,
            "disallow_postdated" => PrincipalAttributes::DISALLOW_POSTDATED,
            "disallow_forwardable" => PrincipalAttributes::DISALLOW_FORWARDABLE,
            "disallow_proxiable" => PrincipalAttributes::DISALLOW_PROXIABLE,
            "disallow_renewable" => PrincipalAttributes::DISALLOW_RENEWABLE,
            "disallow_tgt_based" => PrincipalAttributes::DISALLOW_TGT_BASED,
            "disallow_server" => PrincipalAttributes::DISALLOW_SVR,
            _ => PrincipalAttributes::empty(),
        };
    }
    attrs
}

pub(crate) fn new_entry(
    name: PrincipalName,
    realm: &str,
    attributes: PrincipalAttributes,
    keys: Vec<KeyEntry>,
) -> PrincipalEntry {
    PrincipalEntry {
        name,
        realm: realm.to_owned(),
        attributes,
        max_life: None,
        max_renewable_life: None,
        expiration: None,
        pw_expiration: None,
        keys,
        allowed_to_delegate_to: Vec::new(),
        allowed_to_delegate_from: Vec::new(),
        require_auth: None,
        otp: None,
        pkinit_cert_match: None,
        policy: None,
        security_epoch: 0,
        last_admin_unlock: None,
    }
}

fn service_entry(
    spn: &KerberosServicePrincipalOutpost,
    settings: &StoreSettings,
) -> Result<PrincipalEntry> {
    let (name, prealm) = parse(&spn.spn, &settings.realm)?;
    let keys = decode_keys(&spn.keys, &settings.enctypes, spn.kvno, None)
        .map_err(|err| eyre!("service principal {}: {err}", spn.spn))?;
    let mut attrs = settings.base_attributes | ticket_flags(&spn.ticket_flags);
    if spn.ok_to_auth_as_delegate {
        attrs |= PrincipalAttributes::OK_TO_AUTH_AS_DELEGATE;
    }
    let mut entry = new_entry(name, &prealm, attrs, keys);
    entry
        .allowed_to_delegate_to
        .clone_from(&spn.allowed_delegation_targets);
    if !spn.required_auth_indicators.is_empty() {
        entry.require_auth = Some(spn.required_auth_indicators.join(" "));
    }
    Ok(entry)
}

fn parse(name: &str, realm: &str) -> Result<(PrincipalName, String)> {
    parse_name_with_default(name, realm).map_err(|err| eyre!("parse principal {name}: {err:?}"))
}

/// What [`ProviderStore::new`] builds the static entries from.
pub(crate) struct StoreSources<'a> {
    pub(crate) master_key: &'a [u8],
    pub(crate) services: &'a [KerberosServicePrincipalOutpost],
    pub(crate) trusts: &'a [KerberosRealmTrustOutpost],
    pub(crate) iprop_spn: Option<&'a str>,
}

impl ProviderStore {
    pub(crate) fn new(
        api: Configuration,
        provider_id: i32,
        settings: StoreSettings,
        sources: &StoreSources<'_>,
    ) -> Result<Self> {
        let realm = settings.realm.clone();
        let base = settings.base_attributes;
        let mut entries = HashMap::new();
        let mut insert = |entry: PrincipalEntry| {
            entries.insert((entry.realm.clone(), components(&entry.name)), entry);
        };

        for spn in sources.services {
            insert(service_entry(spn, &settings)?);
        }

        let mut synthetic = vec![
            (
                format!("krbtgt/{realm}"),
                "krbtgt",
                PrincipalAttributes::empty(),
            ),
            (
                "kadmin/changepw".to_owned(),
                "kadmin-changepw",
                PrincipalAttributes::PWCHANGE_SERVICE,
            ),
            (
                "kadmin/admin".to_owned(),
                "kadmin-admin",
                PrincipalAttributes::empty(),
            ),
        ];
        if let Some(iprop) = sources.iprop_spn {
            synthetic.push((iprop.to_owned(), "kiprop", PrincipalAttributes::empty()));
        }
        for (spn, prefix, attrs) in synthetic {
            let (name, prealm) = parse(&spn, &realm)?;
            let keys = settings
                .enctypes
                .iter()
                .map(|etype| {
                    Ok(KeyEntry {
                        kvno: 1,
                        key: derive_key(sources.master_key, *etype, prefix)?,
                        salt: None,
                        s2kparams: None,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            insert(new_entry(name, &prealm, base | attrs, keys));
        }

        for trust in sources.trusts {
            let remote = &trust.remote_realm;
            for (spn, prealm, kvno, keys) in [
                (
                    format!("krbtgt/{remote}"),
                    realm.as_str(),
                    trust.outgoing_kvno,
                    &trust.outgoing_keys,
                ),
                (
                    format!("krbtgt/{realm}"),
                    remote.as_str(),
                    trust.incoming_kvno,
                    &trust.incoming_keys,
                ),
            ] {
                let (name, prealm) = parse(&spn, prealm)?;
                let keys = decode_keys(keys, &settings.enctypes, kvno, None)
                    .map_err(|err| eyre!("realm trust {remote}: {err}"))?;
                insert(new_entry(name, &prealm, base, keys));
            }
        }

        Ok(Self {
            api,
            provider_id,
            settings,
            entries,
            changes: RwLock::default(),
            users: SyncCache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
            access: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .time_to_live(CACHE_TTL)
                .build(),
        })
    }

    pub(crate) fn api(&self) -> &Configuration {
        &self.api
    }

    pub(crate) fn provider_id(&self) -> i32 {
        self.provider_id
    }

    /// Every service, synthetic and trust principal, including kadmin changes.
    pub(crate) fn entries(&self) -> Vec<PrincipalEntry> {
        let changes = self.changes.read().unwrap_or_else(PoisonError::into_inner);
        let mut entries: Vec<PrincipalEntry> = self
            .entries
            .iter()
            .filter(|(key, _)| !changes.contains_key(*key))
            .map(|(_, entry)| entry.clone())
            .collect();
        entries.extend(changes.values().flatten().cloned());
        entries
    }

    /// Apply a service principal created or changed through kadmin until the
    /// next refresh reloads it.
    pub(crate) fn apply_service(&self, spn: &KerberosServicePrincipalOutpost) {
        match service_entry(spn, &self.settings) {
            Ok(entry) => {
                self.changes
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert((entry.realm.clone(), components(&entry.name)), Some(entry));
            }
            Err(err) => warn!(?err, spn = spn.spn, "failed to apply kadmin change"),
        }
    }

    /// Hide a service principal deleted through kadmin until the next refresh.
    pub(crate) fn remove_service(&self, spn: &str) {
        match parse(spn, &self.settings.realm) {
            Ok((name, realm)) => {
                self.changes
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert((realm, components(&name)), None);
            }
            Err(err) => warn!(?err, spn, "failed to apply kadmin deletion"),
        }
    }

    /// A principal loaded at refresh time (service, synthetic or trust).
    pub(crate) fn entry(&self, comps: &[&str]) -> Option<&PrincipalEntry> {
        self.entries.get(&(
            self.settings.realm.clone(),
            comps.iter().map(|c| (*c).to_owned()).collect(),
        ))
    }

    pub(crate) fn invalidate_user(&self, username: &str) {
        self.users.invalidate(username);
    }

    pub(crate) fn settings(&self) -> &StoreSettings {
        &self.settings
    }

    pub(crate) fn user_entry(&self, identity: &KerberosUserKeyOutpost) -> Result<PrincipalEntry> {
        let realm = &self.settings.realm;
        let keys = decode_keys(
            &identity.keys,
            &self.settings.enctypes,
            identity.kvno,
            Some(&identity.salt),
        )?;
        let mut attrs = self.settings.base_attributes | ticket_flags(&identity.flags);
        if self.settings.require_preauth {
            attrs |= PrincipalAttributes::REQUIRES_PRE_AUTH;
        }
        if !identity.enabled {
            attrs |= PrincipalAttributes::DISALLOW_ALL_TIX;
        }
        if identity.requires_password_change {
            attrs |= PrincipalAttributes::REQUIRES_PWCHANGE;
        }
        let mut entry = new_entry(
            PrincipalName::new_principal(&identity.principal),
            realm,
            attrs,
            keys,
        );
        entry.max_life = identity
            .max_ticket_lifetime
            .and_then(|s| u64::try_from(s).ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs);
        entry.max_renewable_life = identity
            .max_renew_lifetime
            .and_then(|s| u64::try_from(s).ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs);
        entry.pw_expiration = identity.password_expiration;
        if self.settings.otp {
            entry.otp = Some("[]".to_owned());
        }
        Ok(entry)
    }

    async fn fetch_user(
        &self,
        username: &str,
    ) -> Result<Option<std::sync::Arc<UserRecord>>, StoreError> {
        match outposts_kerberos_user_key_retrieve(&self.api, self.provider_id, username).await {
            Ok(identity) => {
                let entry = self.user_entry(&identity).map_err(|err| {
                    StoreError::corrupt(format!("user key for {username}: {err}"))
                })?;
                Ok(Some(std::sync::Arc::new(UserRecord { entry, identity })))
            }
            Err(ApiError::ResponseError(response)) if response.status == StatusCode::NOT_FOUND => {
                Ok(None)
            }
            Err(err) => Err(StoreError::unavailable(format!(
                "retrieve user key for {username}: {err}"
            ))),
        }
    }

    /// The user record for `username`, from the cache or the API.
    pub(crate) async fn user(
        &self,
        username: &str,
    ) -> Result<Option<std::sync::Arc<UserRecord>>, StoreError> {
        if let Some(cached) = self.users.get(username) {
            return Ok(cached);
        }
        let record = self.fetch_user(username).await?;
        self.users.insert(username.to_owned(), record.clone());
        if let Some(record) = &record
            && record.identity.principal != username
        {
            self.users.insert(
                record.identity.principal.clone(),
                Some(std::sync::Arc::clone(record)),
            );
        }
        Ok(record)
    }

    /// Enforce authentik policy bindings for a ticket request
    /// (`client` and `server` as parsed names with their realms).
    pub(crate) async fn authorize(
        &self,
        client: (&[String], &str),
        server: (&[String], &str),
    ) -> bool {
        let (ccomps, crealm) = client;
        if matches!(ccomps, [a, b] if a == "WELLKNOWN" && b == "ANONYMOUS") {
            return self.settings.anonymous_pkinit;
        }
        if crealm != self.settings.realm || ccomps.is_empty() {
            return true;
        }
        let is_spn = ccomps.len() > 1;
        if is_spn && is_tgs_or_changepw(ccomps) {
            return true;
        }
        let subject = ccomps.join("/");
        let (scomps, srealm) = server;
        let spn =
            if srealm == self.settings.realm && scomps.len() > 1 && !is_tgs_or_changepw(scomps) {
                scomps.join("/")
            } else {
                String::new()
            };
        let key = (is_spn, subject.clone(), spn.clone());
        if let Some(allowed) = self.access.get(&key).await {
            return allowed;
        }
        let (username, client_spn) = if is_spn {
            (None, Some(subject.as_str()))
        } else {
            (Some(subject.as_str()), None)
        };
        let spn_param = (!spn.is_empty()).then_some(spn.as_str());
        let allowed = match outposts_kerberos_access_check(
            &self.api,
            self.provider_id,
            client_spn,
            spn_param,
            username,
        )
        .await
        {
            Ok(response) => response.access.passing,
            Err(err) => {
                warn!(?err, subject, spn, "Kerberos policy access check failed");
                return false;
            }
        };
        if !allowed {
            info!(subject, spn, "Kerberos policy denied access");
        }
        self.access.insert(key, allowed).await;
        allowed
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "S4U X.509 lookup uses the krb5-rs default"
)]
impl PrincipalStore for ProviderStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        let comps = components(name);
        let key = (realm.to_owned(), comps.clone());
        if let Some(change) = self
            .changes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(change.clone());
        }
        if let Some(entry) = self.entries.get(&key) {
            return Ok(Some(entry.clone()));
        }
        if realm != self.settings.realm {
            return Ok(None);
        }
        let [username] = comps.as_slice() else {
            return Ok(None);
        };
        let record = self.user(username).await?;
        Ok(record
            .filter(|r| r.identity.principal == *username && !r.entry.keys.is_empty())
            .map(|r| r.entry.clone()))
    }

    fn issue_pac(&self, req: IssuePac<'_>) -> Result<(), StoreError> {
        let pac_err = |err: &dyn std::fmt::Display| StoreError::corrupt(format!("PAC: {err}"));
        if let Some(old) = req.old_pac
            && !(req.client.is_some() && req.protocol_transition)
        {
            for ty in old.types() {
                if matches!(
                    ty,
                    PAC_SERVER_CHECKSUM
                        | PAC_PRIVSVR_CHECKSUM
                        | PAC_TICKET_CHECKSUM
                        | PAC_FULL_CHECKSUM
                        | PAC_CLIENT_INFO
                        | PAC_DELEGATION_INFO
                ) {
                    continue;
                }
                let data = old
                    .get_buffer(ty)
                    .map_err(|err| pac_err(&format!("{err:?}")))?;
                req.new_pac
                    .add_buffer(ty, data)
                    .map_err(|err| pac_err(&format!("{err:?}")))?;
            }
            return Ok(());
        }
        let (Some(client), Some(domain_sid)) = (req.client, &self.settings.realm_sid) else {
            return Ok(());
        };
        let comps = components(&client.name);
        let [username] = comps.as_slice() else {
            return Ok(());
        };
        if client.realm != self.settings.realm {
            return Ok(());
        }
        let Some(Some(record)) = self.users.get(username) else {
            return Ok(());
        };
        let identity = &record.identity;
        let id = |v: i32| u32::try_from(v).map_err(|err| pac_err(&err));
        let pac = PacIdentity {
            username: &identity.username,
            full_name: &identity.pac_name,
            user_id: id(identity.pac_user_id)?,
            primary_group_id: id(identity.pac_primary_group_id)?,
            group_ids: identity
                .pac_group_ids
                .iter()
                .map(|g| id(*g))
                .collect::<Result<_, _>>()?,
            upn: &identity.pac_upn,
            realm: &self.settings.realm,
            domain_sid,
        };
        for (ty, data) in [
            (PAC_LOGON_INFO, pac.logon_info()),
            (PAC_UPN_DNS_INFO, pac.upn_dns_info()),
        ] {
            let data = data.map_err(|err| pac_err(&err))?;
            req.new_pac
                .add_buffer(ty, &data)
                .map_err(|err| pac_err(&format!("{err:?}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn synthetic_keys_match_go_outpost() {
        let master = [1_u8; 32];
        let key = derive_key(&master, 18, "krbtgt").expect("derive aes256 key");
        assert_eq!(
            hex(key.key_bytes()),
            "e7e0492f561f0954c0d15f5a91cd1cd1deb89e8d749a62160dc1bf53ab0cc8ae"
        );
        let key = derive_key(&master, 17, "kadmin-changepw").expect("derive aes128 key");
        assert_eq!(hex(key.key_bytes()), "36914c02090b8cf0b76105cdafc83248");
    }

    #[test]
    fn decode_keys_filters_and_validates() {
        let values = HashMap::from([
            (
                "18".to_owned(),
                serde_json::Value::from(STANDARD.encode([2_u8; 32])),
            ),
            (
                "17".to_owned(),
                serde_json::Value::from(STANDARD.encode([3_u8; 16])),
            ),
            (
                "20".to_owned(),
                serde_json::Value::from(STANDARD.encode([4_u8; 32])),
            ),
        ]);
        let keys =
            decode_keys(&values, &[17_i32, 18_i32], 3_i32, Some("REALMuser")).expect("decode keys");
        assert_eq!(
            keys.iter().map(|k| k.key.keytype).collect::<Vec<_>>(),
            vec![17_i32, 18_i32]
        );
        assert!(keys.iter().all(|k| k.kvno == 3));
        assert_eq!(keys[0].salt.as_deref(), Some(b"REALMuser".as_slice()));

        let short = HashMap::from([(
            "18".to_owned(),
            serde_json::Value::from(STANDARD.encode([2_u8; 16])),
        )]);
        let err = decode_keys(&short, &[18_i32], 1_i32, None).expect_err("reject short key");
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn ticket_flags_map_to_attributes() {
        let attrs = ticket_flags(&[
            "requires_preauth".to_owned(),
            "disallow_server".to_owned(),
            "unknown".to_owned(),
        ]);
        assert_eq!(
            attrs,
            PrincipalAttributes::REQUIRES_PRE_AUTH | PrincipalAttributes::DISALLOW_SVR
        );
    }
}
