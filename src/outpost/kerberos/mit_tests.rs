//! MIT interoperability tests: serve a provider against a mocked authentik
//! API and drive it with the MIT client tools. Skipped when they're missing.

use std::{
    collections::HashMap,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use ak_client::{apis::configuration::Configuration, models::KerberosOutpostConfig};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use eyre::{Result, eyre};
use krb5_rs::{
    crypto::find_etype,
    kdc::{ServeOptions, serve_tcp_with, serve_udp_with},
};
use serde_json::{Value, json};
use tokio::{
    io::AsyncWriteExt as _, net::TcpListener, net::UdpSocket, process::Command, sync::watch,
};

use super::{
    Dispatcher, build_provider, kdc_realms,
    kpasswd::{self, Kpasswd, KpasswdRealm},
};

const REALM: &str = "MITKDC.TEST";
const USER: &str = "alice";
const PASSWORD: &str = "alice-password";
const SERVICE: &str = "host/svc.mitkdc.test";
const ENCTYPES: [i32; 2] = [18, 17];

type Rule = fn(Option<&str>, Option<&str>, Option<&str>) -> bool;

#[derive(Default)]
struct Api {
    users: Mutex<HashMap<String, Value>>,
    services: Mutex<Vec<Value>>,
    denied: Mutex<Vec<String>>,
    rule: Mutex<Option<Rule>>,
    certs: Mutex<HashMap<String, (String, Option<String>)>>,
    trusts: Mutex<Vec<Value>>,
    key_seed: std::sync::atomic::AtomicU8,
    audit: Mutex<Vec<Value>>,
}

impl Api {
    fn users(&self) -> std::sync::MutexGuard<'_, HashMap<String, Value>> {
        self.users.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn password_keys(password: &str, salt: &str) -> Result<Value> {
    let mut keys = serde_json::Map::new();
    for etype in ENCTYPES {
        let key = find_etype(etype)
            .map_err(|err| eyre!("{err:?}"))?
            .string_to_key(password.as_bytes(), salt.as_bytes(), None)
            .map_err(|err| eyre!("{err:?}"))?;
        keys.insert(etype.to_string(), Value::String(STANDARD.encode(&*key)));
    }
    Ok(Value::Object(keys))
}

fn user(username: &str, password: &str, kvno: i64) -> Result<Value> {
    let salt = format!("{REALM}{username}");
    Ok(json!({
        "username": username,
        "enabled": true,
        "principal": username,
        "kvno": kvno,
        "salt": salt,
        "keys": password_keys(password, &salt)?,
        "max_ticket_lifetime": null,
        "max_renew_lifetime": null,
        "requires_password_change": false,
        "pac_user_id": 1000,
        "pac_primary_group_id": 513,
        "pac_group_ids": [],
        "pac_name": username,
        "pac_upn": format!("{username}@example.com"),
        "password_expiration": null,
        "flags": [],
    }))
}

fn service() -> Value {
    json!({
        "spn": SERVICE,
        "kvno": 1,
        "keys": {"18": STANDARD.encode([18_u8; 32]), "17": STANDARD.encode([17_u8; 16])},
        "ok_to_auth_as_delegate": false,
        "allowed_delegation_targets": [],
        "required_auth_indicators": [],
        "ticket_flags": [],
    })
}

fn page(results: &[Value]) -> Json<Value> {
    let n = results.len();
    Json(json!({
        "pagination": {
            "next": 0, "previous": 0, "count": n, "current": 1,
            "total_pages": 1, "start_index": 1, "end_index": n,
        },
        "results": results.to_vec(),
        "autocomplete": {},
    }))
}

type Params = Query<HashMap<String, String>>;

async fn user_key(
    State(api): State<Arc<Api>>,
    Query(q): Params,
) -> Result<Json<Value>, StatusCode> {
    let name = q.get("username").ok_or(StatusCode::BAD_REQUEST)?;
    let name = if name == ALIAS { USER } else { name.as_str() };
    api.users()
        .get(name)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn service_principals(State(api): State<Arc<Api>>) -> Json<Value> {
    page(&api.services.lock().unwrap_or_else(PoisonError::into_inner))
}

async fn user_keys(State(api): State<Arc<Api>>) -> Json<Value> {
    page(&api.users().values().cloned().collect::<Vec<_>>())
}

async fn access_check(State(api): State<Arc<Api>>, Query(q): Params) -> Json<Value> {
    let denied = api.denied.lock().unwrap_or_else(PoisonError::into_inner);
    let param = |k: &str| q.get(k).map(String::as_str);
    let rule = *api.rule.lock().unwrap_or_else(PoisonError::into_inner);
    let passing = !q.get("username").is_some_and(|u| denied.contains(u))
        && rule.is_none_or(|r| r(param("username"), param("client_spn"), param("spn")));
    Json(json!({"access": {"passing": passing, "messages": [], "log_messages": []}}))
}

async fn audit_event(State(api): State<Arc<Api>>, Json(body): Json<Value>) -> StatusCode {
    api.audit
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(body);
    StatusCode::NO_CONTENT
}

fn spn_json(api: &Api, spn: &str, kvno: i64) -> Value {
    let seed = api
        .key_seed
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .wrapping_add(100);
    json!({
        "spn": spn,
        "kvno": kvno,
        "keys": {"18": STANDARD.encode([seed; 32]), "17": STANDARD.encode([seed; 16])},
        "ok_to_auth_as_delegate": false,
        "allowed_delegation_targets": [],
        "required_auth_indicators": [],
        "ticket_flags": [],
    })
}

fn bare_spn(body: &Value) -> String {
    let spn = body["spn"].as_str().unwrap_or_default();
    spn.strip_suffix(&format!("@{REALM}"))
        .unwrap_or(spn)
        .to_owned()
}

async fn spn_create(State(api): State<Arc<Api>>, Json(body): Json<Value>) -> Json<Value> {
    let created = spn_json(&api, &bare_spn(&body), 1);
    api.services
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(created.clone());
    Json(created)
}

async fn spn_update(
    State(api): State<Arc<Api>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let spn = bare_spn(&body);
    let mut services = api.services.lock().unwrap_or_else(PoisonError::into_inner);
    let entry = services
        .iter_mut()
        .find(|s| s["spn"] == json!(spn))
        .ok_or(StatusCode::NOT_FOUND)?;
    entry["ticket_flags"] = body["ticket_flags"].clone();
    Ok(Json(entry.clone()))
}

async fn spn_rotate(
    State(api): State<Arc<Api>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    let spn = bare_spn(&body);
    let mut services = api.services.lock().unwrap_or_else(PoisonError::into_inner);
    let entry = services
        .iter_mut()
        .find(|s| s["spn"] == json!(spn))
        .ok_or(StatusCode::NOT_FOUND)?;
    let kvno = entry["kvno"].as_i64().unwrap_or(1) + 1;
    *entry = spn_json(&api, &spn, kvno);
    Ok(Json(entry.clone()))
}

async fn spn_delete(State(api): State<Arc<Api>>, Json(body): Json<Value>) -> StatusCode {
    let spn = bare_spn(&body);
    api.services
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|s| s["spn"] != json!(spn));
    StatusCode::NO_CONTENT
}

async fn keypair(axum::extract::Path(id): axum::extract::Path<String>) -> Json<Value> {
    Json(json!({
        "pk": id, "name": id, "fingerprint_sha256": format!("fp-{id}"), "fingerprint_sha1": null,
        "cert_expiry": null, "cert_subject": null, "private_key_available": true, "key_type": null,
        "certificate_download_url": "", "private_key_download_url": "", "managed": null,
    }))
}

async fn view_certificate(
    State(api): State<Arc<Api>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let certs = api.certs.lock().unwrap_or_else(PoisonError::into_inner);
    let (cert, _) = certs.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({"data": cert})))
}

async fn view_private_key(
    State(api): State<Arc<Api>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let certs = api.certs.lock().unwrap_or_else(PoisonError::into_inner);
    let (_, Some(key)) = certs.get(&id).ok_or(StatusCode::NOT_FOUND)? else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(json!({"data": key})))
}

const OTP_CODE: &str = "424242";

async fn otp_check(Json(body): Json<Value>) -> Json<Value> {
    Json(json!({"allowed": body["username"] == json!(USER) && body["value"] == json!(OTP_CODE)}))
}

async fn set_password(State(api): State<Arc<Api>>, Json(body): Json<Value>) -> StatusCode {
    let (Some(username), Some(password)) = (body["username"].as_str(), body["password"].as_str())
    else {
        return StatusCode::BAD_REQUEST;
    };
    let mut users = api.users();
    let Some(entry) = users.get_mut(username) else {
        return StatusCode::NOT_FOUND;
    };
    let kvno = entry["kvno"].as_i64().unwrap_or(1) + 1;
    match user(username, password, kvno) {
        Ok(updated) => {
            *entry = updated;
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn router(api: Arc<Api>) -> Router {
    Router::new()
        .route(
            "/outposts/kerberos/{id}/service_principals/",
            get(service_principals),
        )
        .route(
            "/outposts/kerberos/{id}/realm_trusts/",
            get(async |State(api): State<Arc<Api>>| {
                page(&api.trusts.lock().unwrap_or_else(PoisonError::into_inner))
            }),
        )
        .route("/outposts/kerberos/{id}/user_key/", get(user_key))
        .route("/outposts/kerberos/{id}/user_keys/", get(user_keys))
        .route("/outposts/kerberos/{id}/access_check/", get(access_check))
        .route("/outposts/kerberos/{id}/audit_event/", post(audit_event))
        .route("/outposts/kerberos/{id}/set_password/", post(set_password))
        .route("/outposts/kerberos/{id}/otp_check/", post(otp_check))
        .route("/crypto/certificatekeypairs/{id}/", get(keypair))
        .route(
            "/crypto/certificatekeypairs/{id}/view_certificate/",
            get(view_certificate),
        )
        .route(
            "/crypto/certificatekeypairs/{id}/view_private_key/",
            get(view_private_key),
        )
        .route(
            "/outposts/kerberos/{id}/service_principal_create/",
            post(spn_create),
        )
        .route(
            "/outposts/kerberos/{id}/service_principal_update/",
            post(spn_update),
        )
        .route(
            "/outposts/kerberos/{id}/service_principal_rotate/",
            post(spn_rotate),
        )
        .route(
            "/outposts/kerberos/{id}/service_principal_delete/",
            post(spn_delete),
        )
        .with_state(api)
}

fn provider(extra: &Value) -> Result<KerberosOutpostConfig> {
    let mut provider = json!({
        "pk": 1_i32,
        "name": "mit",
        "realm_name": REALM,
        "maximum_ticket_lifetime": 36_000_i32,
        "maximum_ticket_renew_lifetime": 604_800_i32,
        "application_slug": "mit",
        "allowed_enctypes": ENCTYPES,
        "udp_enabled": true,
        "tcp_enabled": true,
        "kpasswd_enabled": true,
        "require_preauthentication": true,
        "master_key": STANDARD.encode([7_u8; 32]),
    });
    if let (Some(base), Some(extra)) = (provider.as_object_mut(), extra.as_object()) {
        base.extend(extra.clone());
    }
    Ok(serde_json::from_value(provider)?)
}

fn have_tools(tools: &[&str]) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    tools
        .iter()
        .all(|tool| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
}

/// A UDP socket and TCP listener on the same loopback port.
async fn bind_pair() -> Result<(UdpSocket, TcpListener, u16)> {
    for _ in 0_i32..20_i32 {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let port = tcp.local_addr()?.port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)).await {
            return Ok((udp, tcp, port));
        }
    }
    Err(eyre!("no free port pair"))
}

struct Harness {
    dir: tempfile::TempDir,
    api: Arc<Api>,
    kdc: Arc<super::ProviderKdc>,
    store: Arc<super::store::ProviderStore>,
    _shutdown: watch::Sender<bool>,
}

impl Harness {
    async fn start(extra: Value, force_tcp: bool) -> Result<Option<Self>> {
        Self::start_with(extra, force_tcp, vec![service()], |_| {}).await
    }

    async fn start_with(
        extra: Value,
        force_tcp: bool,
        services: Vec<Value>,
        user_setup: impl FnOnce(&mut Value),
    ) -> Result<Option<Self>> {
        if !have_tools(&["kinit", "kvno", "klist", "kpasswd"]) {
            eprintln!("skipping: MIT client tools not installed");
            return Ok(None);
        }
        drop(rustls::crypto::aws_lc_rs::default_provider().install_default());
        let api = Arc::new(Api::default());
        if let Some(trusts) = extra.get("mock_trusts").and_then(Value::as_array) {
            api.trusts
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone_from(trusts);
        }
        if let Some(certs) = extra.get("mock_certificates").and_then(Value::as_object) {
            let mut map = api.certs.lock().unwrap_or_else(PoisonError::into_inner);
            for (id, pair) in certs {
                map.insert(
                    id.clone(),
                    (
                        pair["certificate"].as_str().unwrap_or_default().to_owned(),
                        pair["key"].as_str().map(str::to_owned),
                    ),
                );
            }
        }
        let mut alice = user(USER, PASSWORD, 1)?;
        user_setup(&mut alice);
        api.users().insert(USER.to_owned(), alice);
        *api.services.lock().unwrap_or_else(PoisonError::into_inner) = services;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base_path = format!("http://{}", listener.local_addr()?);
        tokio::spawn(axum::serve(listener, router(Arc::clone(&api))).into_future());
        let config = Configuration {
            base_path,
            ..Configuration::default()
        };
        let certificates = ak_common::tls::store::CertificateStore::new();
        let provider = provider(&extra)?;
        let (kdc, store) = build_provider(&config, &certificates, &provider).await?;
        let harness_store = Arc::clone(&store);

        let kadmin = Arc::new(super::kadmin::Kadmin::default());
        kadmin
            .realm
            .store(Some(Arc::new(super::kadmin::KadminRealm::new(
                Arc::clone(&store),
                provider.kadmin_acl.as_deref().unwrap_or_default(),
            )?)));
        let kadmin_listener = TcpListener::bind("127.0.0.1:0").await?;
        let kadmin_port = kadmin_listener.local_addr()?.port();

        let (tx, rx) = watch::channel(false);
        let options = ServeOptions {
            logger: None,
            shutdown: Some(rx.clone()),
        };
        let kdc = Arc::new(kdc);
        let dispatcher = Arc::new(Dispatcher::default());
        dispatcher.udp.store(kdc_realms(vec![Arc::clone(&kdc)]));
        dispatcher.tcp.store(kdc_realms(vec![Arc::clone(&kdc)]));
        let (udp, tcp, kdc_port) = bind_pair().await?;
        tokio::spawn(serve_udp_with(
            Arc::clone(&dispatcher),
            udp,
            options.clone(),
        ));
        tokio::spawn(serve_tcp_with(dispatcher, tcp, options));

        let kpasswd = Arc::new(Kpasswd::default());
        kpasswd.realms.store(Arc::new(HashMap::from([(
            REALM.to_owned(),
            Arc::new(KpasswdRealm {
                store,
                udp: true,
                tcp: true,
            }),
        )])));
        let (udp, tcp, kpasswd_port) = bind_pair().await?;
        tokio::spawn(kpasswd::serve_udp(Arc::clone(&kpasswd), udp, rx.clone()));
        tokio::spawn(kpasswd::serve_tcp(kpasswd, tcp, rx.clone()));
        tokio::spawn(super::kadmin::serve_tcp(kadmin, kadmin_listener, rx));

        let dir = tempfile::tempdir()?;
        let udp_limit = if force_tcp { 1_u32 } else { 1465_u32 };
        std::fs::write(
            dir.path().join("krb5.conf"),
            format!(
                "[libdefaults]\n\
                 \tdefault_realm = {REALM}\n\
                 \tdns_lookup_kdc = false\n\
                 \tdns_lookup_realm = false\n\
                 \trdns = false\n\
                 \tudp_preference_limit = {udp_limit}\n\
                 \tpermitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n\
                 [realms]\n\
                 \t{REALM} = {{\n\
                 \t\tkdc = 127.0.0.1:{kdc_port}\n\
                 \t\tkpasswd_server = 127.0.0.1:{kpasswd_port}\n\
                 \t\tadmin_server = 127.0.0.1:{kadmin_port}\n\
                 \t}}\n"
            ),
        )?;
        Ok(Some(Self {
            dir,
            api,
            kdc,
            store: harness_store,
            _shutdown: tx,
        }))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Run an MIT tool, returning whether it succeeded and its output.
    async fn run(&self, input: &str, tool: &str, args: &[&str]) -> Result<(bool, String)> {
        self.run_cache("ccache", input, tool, args).await
    }

    /// Like [`Self::run`], with the credential cache file `cache`.
    async fn run_cache(
        &self,
        cache: &str,
        input: &str,
        tool: &str,
        args: &[&str],
    ) -> Result<(bool, String)> {
        let mut child = Command::new(tool)
            .args(args)
            .env("KRB5_CONFIG", self.path("krb5.conf"))
            .env("KRB5CCNAME", format!("FILE:{}", self.path(cache).display()))
            .env("KRB5_TRACE", self.path("trace.log"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input.as_bytes()).await?;
        }
        let output =
            tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok((output.status.success(), text))
    }

    async fn ok(&self, input: &str, tool: &str, args: &[&str]) -> Result<String> {
        let (ok, out) = self.run(input, tool, args).await?;
        if !ok {
            let trace = std::fs::read_to_string(self.path("trace.log")).unwrap_or_default();
            return Err(eyre!("{tool} {args:?} failed: {out}\ntrace:\n{trace}"));
        }
        Ok(out)
    }

    async fn kinit(&self, password: &str) -> Result<(bool, String)> {
        self.run(&format!("{password}\n"), "kinit", &[USER]).await
    }
}

async fn flow(force_tcp: bool) -> Result<()> {
    let Some(h) = Harness::start(json!({}), force_tcp).await? else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    h.ok("", "kvno", &[SERVICE]).await?;
    let klist = h.ok("", "klist", &[]).await?;
    eyre::ensure!(
        klist.contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{klist}"
    );
    eyre::ensure!(klist.contains(&format!("{SERVICE}@{REALM}")), "{klist}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_udp() -> Result<()> {
    flow(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_tcp() -> Result<()> {
    flow(true).await
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_wrong_password() -> Result<()> {
    let Some(h) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    let (ok, out) = h.kinit("not-the-password").await?;
    eyre::ensure!(!ok, "{out}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_authorization() -> Result<()> {
    let Some(h) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    h.api
        .denied
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(USER.to_owned());
    let (ok, out) = h.kinit(PASSWORD).await?;
    eyre::ensure!(!ok, "denied user got a TGT: {out}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_kpasswd() -> Result<()> {
    let Some(h) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    let new = "alice-new-password";
    let out = h
        .ok(&format!("{PASSWORD}\n{new}\n{new}\n"), "kpasswd", &[USER])
        .await?;
    eyre::ensure!(out.contains("Password changed"), "{out}");
    eyre::ensure!(
        h.api.users()[USER]["kvno"] == json!(2_i64),
        "kvno not bumped"
    );
    let (ok, out) = h.kinit(new).await?;
    eyre::ensure!(ok, "kinit with the new password failed: {out}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_audit() -> Result<()> {
    let Some(h) = Harness::start(json!({"kdc_audit_enabled": true}), false).await? else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    h.ok("", "kvno", &[SERVICE]).await?;
    for _ in 0_i32..50_i32 {
        let events: Vec<String> = h
            .api
            .audit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|e| e["success"] == json!(true))
            .filter_map(|e| e["event"].as_str().map(str::to_owned))
            .collect();
        if events.iter().any(|e| e == "as_req") && events.iter().any(|e| e == "tgs_req") {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(eyre!(
        "missing audit events: {:?}",
        h.api.audit.lock().unwrap_or_else(PoisonError::into_inner)
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_disabled_user() -> Result<()> {
    let Some(h) = Harness::start_with(json!({}), false, vec![service()], |u| {
        u["enabled"] = json!(false);
    })
    .await?
    else {
        return Ok(());
    };
    let (ok, out) = h.kinit(PASSWORD).await?;
    eyre::ensure!(!ok, "disabled user got a TGT: {out}");
    eyre::ensure!(out.to_lowercase().contains("revoked"), "{out}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_user_lifetime() -> Result<()> {
    let Some(h) = Harness::start_with(json!({}), false, vec![service()], |u| {
        u["max_ticket_lifetime"] = json!(90_i32);
    })
    .await?
    else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    let klist = h.ok("", "klist", &[]).await?;
    let line = klist
        .lines()
        .find(|l| l.contains(&format!("krbtgt/{REALM}@{REALM}")))
        .ok_or_else(|| eyre!("no TGT: {klist}"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let parse =
        |f: &[&str]| chrono::NaiveDateTime::parse_from_str(&f.join(" "), "%m/%d/%y %H:%M:%S").ok();
    let (Some(start), Some(end)) = (
        fields.get(0..2).and_then(parse),
        fields.get(2..4).and_then(parse),
    ) else {
        return Err(eyre!("unparsable klist: {klist}"));
    };
    let lifetime = (end - start).num_seconds();
    eyre::ensure!(
        (60_i64..=120_i64).contains(&lifetime),
        "lifetime {lifetime}s: {klist}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_user_ticket_flags() -> Result<()> {
    let Some(h) = Harness::start_with(json!({}), false, vec![service()], |u| {
        u["flags"] = json!(["disallow_forwardable"]);
    })
    .await?
    else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &["-f", USER])
        .await?;
    let klist = h.ok("", "klist", &["-f"]).await?;
    let flags = klist
        .lines()
        .find_map(|l| l.split_once("Flags:").map(|(_, f)| f.trim().to_owned()))
        .ok_or_else(|| eyre!("no flags: {klist}"))?;
    eyre::ensure!(
        !flags.contains('F'),
        "forwardable flag was not removed: {klist}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_spake() -> Result<()> {
    let Some(h) = Harness::start(json!({"spake_enabled": true}), false).await? else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    let trace = std::fs::read_to_string(h.path("trace.log"))?;
    eyre::ensure!(
        trace.to_lowercase().contains("spake"),
        "no SPAKE in trace:\n{trace}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_auth_indicators() -> Result<()> {
    let mut restricted = service();
    restricted["required_auth_indicators"] = json!(["pkinit"]);
    let Some(h) = Harness::start_with(json!({}), false, vec![restricted], |_| {}).await? else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    let (ok, out) = h.run("", "kvno", &[SERVICE]).await?;
    eyre::ensure!(!ok, "password ticket satisfied a pkinit requirement: {out}");
    eyre::ensure!(out.to_lowercase().contains("policy"), "{out}");
    Ok(())
}

const BACKEND: &str = "HTTP/backend.test";

fn backend() -> Value {
    let mut b = service();
    b["spn"] = json!(BACKEND);
    b
}

impl Harness {
    fn set_rule(&self, rule: Rule) {
        *self.api.rule.lock().unwrap_or_else(PoisonError::into_inner) = Some(rule);
    }

    fn service_keytab(&self) -> Result<String> {
        use krb5_rs::keytab::{FileKeytab, Keytab as _, KeytabEntry};
        let path = self.path("service.keytab");
        FileKeytab::new(path.clone())
            .add_entry(&KeytabEntry {
                principal: krb5_rs::types::PrincipalName::new_srv_inst("host", "svc.mitkdc.test"),
                realm: REALM.to_owned(),
                timestamp: 0,
                kvno: 1,
                key: krb5_rs::types::EncryptionKey::new(18, vec![18_u8; 32]),
            })
            .map_err(|err| eyre!("write keytab: {err}"))?;
        Ok(path.display().to_string())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_policies() -> Result<()> {
    let Some(h) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    h.ok(&format!("{PASSWORD}\n"), "kinit", &["-p", "-r", "2h", USER])
        .await?;
    let klist = h.ok("", "klist", &["-f"]).await?;
    let flags = klist
        .lines()
        .find_map(|l| l.split_once("Flags:").map(|(_, f)| f.trim().to_owned()))
        .ok_or_else(|| eyre!("no flags: {klist}"))?;
    eyre::ensure!(flags.contains('P'), "not proxiable: {klist}");
    eyre::ensure!(
        klist.to_lowercase().contains("renew until"),
        "not renewable: {klist}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_service_account_authorization() -> Result<()> {
    let Some(denied) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    denied.set_rule(|_, client_spn, _| client_spn.is_none());
    let keytab = denied.service_keytab()?;
    let (ok, out) = denied
        .run("", "kinit", &["-f", "-kt", &keytab, SERVICE])
        .await?;
    eyre::ensure!(!ok, "service kinit ignored the policy denial: {out}");
    eyre::ensure!(out.to_lowercase().contains("policy"), "{out}");

    let Some(allowed) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    let keytab = allowed.service_keytab()?;
    allowed
        .ok("", "kinit", &["-f", "-kt", &keytab, SERVICE])
        .await?;
    Ok(())
}

async fn s4u(targets: &[&str], rule: Option<Rule>) -> Result<Option<(bool, String)>> {
    let mut front = service();
    front["ok_to_auth_as_delegate"] = json!(true);
    front["allowed_delegation_targets"] = json!(targets);
    let Some(h) = Harness::start_with(
        json!({"pac_enabled": true, "realm_sid": "S-1-5-21-1-2-3"}),
        false,
        vec![front, backend()],
        |_| {},
    )
    .await?
    else {
        return Ok(None);
    };
    if let Some(rule) = rule {
        h.set_rule(rule);
    }
    let keytab = h.service_keytab()?;
    h.ok("", "kinit", &["-f", "-kt", &keytab, SERVICE]).await?;
    let own = h.ok("", "kvno", &["-U", USER, SERVICE]).await?;
    eyre::ensure!(
        own.contains(&format!("{SERVICE}@{REALM}")) && own.contains("kvno = 1"),
        "S4U2Self: {own}"
    );
    h.run("", "kvno", &["-U", USER, "-P", BACKEND])
        .await
        .map(Some)
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_s4u() -> Result<()> {
    let Some((ok, out)) = s4u(&[BACKEND], None).await? else {
        return Ok(());
    };
    eyre::ensure!(
        ok && out.contains(&format!("{BACKEND}@{REALM}")) && out.contains("kvno = 1"),
        "S4U2Proxy: {out}"
    );

    let Some((ok, out)) = s4u(&[], None).await? else {
        return Ok(());
    };
    eyre::ensure!(!ok, "S4U2Proxy to a target that is not allowed: {out}");
    eyre::ensure!(
        out.to_lowercase()
            .contains("can't fulfill requested option"),
        "{out}"
    );

    let Some((ok, out)) = s4u(
        &[BACKEND],
        Some(|user, _, spn| user != Some(USER) || spn != Some(BACKEND)),
    )
    .await?
    else {
        return Ok(());
    };
    eyre::ensure!(
        !ok,
        "S4U2Proxy ignored the impersonated user's policy: {out}"
    );
    eyre::ensure!(
        out.to_lowercase()
            .contains("can't fulfill requested option"),
        "{out}"
    );
    Ok(())
}

const NEWNODE: &str = "host/newnode.test";
const UPDATED: &str = "alice-password-updated";

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_kadmin() -> Result<()> {
    if !have_tools(&["kadmin"]) {
        return Ok(());
    }
    let Some(h) = Harness::start(
        json!({"kadmin_enabled": true, "kadmin_acl": ["alice *"]}),
        false,
    )
    .await?
    else {
        return Ok(());
    };
    let kadmin = |pw: &'static str, query: String| {
        let h = &h;
        async move {
            h.run("", "kadmin", &["-p", USER, "-w", pw, "-q", &query])
                .await
        }
    };
    let ok = |(ok, out): (bool, String)| -> Result<String> {
        eyre::ensure!(ok, "kadmin failed: {out}");
        Ok(out)
    };
    let out = ok(kadmin(PASSWORD, format!("getprinc {USER}")).await?)?;
    eyre::ensure!(out.contains(&format!("Principal: {USER}@{REALM}")), "{out}");
    ok(kadmin(PASSWORD, format!("addprinc -randkey {NEWNODE}")).await?)?;
    let out = ok(kadmin(PASSWORD, format!("getprinc {NEWNODE}")).await?)?;
    eyre::ensure!(
        out.contains(&format!("Principal: {NEWNODE}@{REALM}")),
        "{out}"
    );

    let keytab = h.path("newnode.keytab").display().to_string();
    ok(kadmin(PASSWORD, format!("ktadd -k {keytab} {NEWNODE}")).await?)?;
    h.ok("", "kinit", &["-k", "-t", &keytab, NEWNODE]).await?;
    h.ok("", "kdestroy", &[]).await?;
    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    h.ok("", "kvno", &[NEWNODE]).await?;

    ok(kadmin(PASSWORD, format!("cpw -pw {UPDATED} {USER}")).await?)?;
    h.ok("", "kdestroy", &[]).await?;
    h.ok(&format!("{UPDATED}\n"), "kinit", &[USER]).await?;

    ok(kadmin(UPDATED, format!("delprinc -force {NEWNODE}")).await?)?;
    let (_, out) = kadmin(UPDATED, format!("getprinc {NEWNODE}")).await?;
    eyre::ensure!(
        !out.contains(&format!("Principal: {NEWNODE}@{REALM}")),
        "deleted principal still resolves: {out}"
    );
    let out = ok(kadmin(UPDATED, "listprincs".to_owned()).await?)?;
    eyre::ensure!(
        out.contains(&format!("{USER}@{REALM}")) && out.contains(&format!("{SERVICE}@{REALM}")),
        "{out}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_kadmin_denied() -> Result<()> {
    if !have_tools(&["kadmin"]) {
        return Ok(());
    }
    let Some(h) = Harness::start(
        json!({"kadmin_enabled": true, "kadmin_acl": ["other *"]}),
        false,
    )
    .await?
    else {
        return Ok(());
    };
    let query = format!("addprinc -randkey {NEWNODE}");
    let (_, out) = h
        .run("", "kadmin", &["-p", USER, "-w", PASSWORD, "-q", &query])
        .await?;
    let lower = out.to_lowercase();
    eyre::ensure!(
        lower.contains("permission") || lower.contains("privilege"),
        "unlisted principal was not denied: {out}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_otp() -> Result<()> {
    if !std::path::Path::new("/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/otp.so").exists()
        && !std::path::Path::new("/usr/lib64/krb5/plugins/preauth/otp.so").exists()
    {
        return Ok(());
    }
    let Some(h) = Harness::start(
        json!({"otp_enabled": true, "otp_indicators": ["otp"], "pac_enabled": true, "realm_sid": "S-1-5-21-1-2-3"}),
        false,
    )
    .await?
    else {
        return Ok(());
    };
    let keytab = h.service_keytab()?;
    let (ok, out) = h
        .run_cache("armor", "", "kinit", &["-f", "-kt", &keytab, SERVICE])
        .await?;
    eyre::ensure!(ok, "armor kinit failed: {out}");
    let armor = h.path("armor").display().to_string();

    let (ok, out) = h.run("000000\n", "kinit", &["-T", &armor, USER]).await?;
    eyre::ensure!(!ok, "wrong OTP code was accepted: {out}");
    h.ok(&format!("{OTP_CODE}\n"), "kinit", &["-T", &armor, USER])
        .await?;
    let out = h.ok("", "klist", &[]).await?;
    eyre::ensure!(out.contains(&format!("krbtgt/{REALM}@{REALM}")), "{out}");
    h.ok("", "kvno", &[SERVICE]).await?;
    Ok(())
}

const ALIAS: &str = "alice@example.com";

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_alias_canonicalization() -> Result<()> {
    let Some(h) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    let alias = ALIAS.replace('@', "\\@");
    let (ok, out) = h.run(&format!("{PASSWORD}\n"), "kinit", &[&alias]).await?;
    let lower = out.to_lowercase();
    eyre::ensure!(
        !ok && lower.contains("client") && lower.contains("not found"),
        "alias kinit without canonicalization: {out}"
    );
    h.ok(&format!("{PASSWORD}\n"), "kinit", &["-C", &alias])
        .await?;
    let out = h.ok("", "klist", &[]).await?;
    eyre::ensure!(
        out.contains(&format!("Default principal: {USER}@{REALM}")),
        "klist does not show the canonical principal: {out}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_kkdcp() -> Result<()> {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let Some(h) = Harness::start(json!({}), false).await? else {
        return Ok(());
    };
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "KKDCP test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate()?;
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf = leaf_params.signed_by(&leaf_key, &issuer)?;
    let private_key = PrivateKeyDer::try_from(leaf_key.serialize_der()).map_err(|e| eyre!(e))?;
    let certified = rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(leaf.der().to_vec())],
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)?,
    );

    let kkdcp = Arc::new(super::kkdcp::Kkdcp::new(Arc::new(certified)));
    kkdcp.realms.store(kdc_realms(vec![Arc::clone(&h.kdc)]));
    let resolver: Arc<dyn rustls::server::ResolvesServerCert> =
        Arc::<super::kkdcp::Kkdcp>::clone(&kkdcp);
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let server = axum_server::from_tcp_rustls(
        listener,
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
    )?;
    tokio::spawn(
        server.serve(
            kkdcp
                .router()
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        ),
    );

    let anchors = h.path("kkdcp-ca.pem");
    std::fs::write(&anchors, pem("CERTIFICATE", ca.der()))?;
    let conf = std::fs::read_to_string(h.path("krb5.conf"))?
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("kdc = ") {
                format!(
                    "\t\tkdc = https://127.0.0.1:{port}/KdcProxy\n\t\thttp_anchors = FILE:{}",
                    anchors.display()
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(h.path("krb5.conf"), conf)?;

    h.ok(&format!("{PASSWORD}\n"), "kinit", &[USER]).await?;
    let out = h.ok("", "klist", &[]).await?;
    eyre::ensure!(out.contains(&format!("krbtgt/{REALM}@{REALM}")), "{out}");
    h.ok("", "kvno", &[SERVICE]).await?;
    let trace = std::fs::read_to_string(h.path("trace.log"))?;
    eyre::ensure!(
        trace.contains("HTTPS"),
        "KDC was not reached over HTTPS:\n{trace}"
    );
    Ok(())
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let body = b64
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()) {
        Ok(len) if len < 0x80 => out.push(len),
        _ => {
            let len = content
                .len()
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect::<Vec<u8>>();
            out.push(0x80 | u8::try_from(len.len()).unwrap_or_default());
            out.extend_from_slice(&len);
        }
    }
    out.extend_from_slice(content);
    out
}

/// A subjectAltName holding an id-pkinit-san `KRB5PrincipalName` (RFC 4556).
fn pkinit_san(name_type: u8, components: &[&str]) -> Vec<u8> {
    let names: Vec<u8> = components
        .iter()
        .flat_map(|c| der_tlv(0x1b, c.as_bytes()))
        .collect();
    let name = der_tlv(
        0x30,
        &[
            der_tlv(0xa0, &der_tlv(0x02, &[name_type])),
            der_tlv(0xa1, &der_tlv(0x30, &names)),
        ]
        .concat(),
    );
    let principal = der_tlv(
        0x30,
        &[
            der_tlv(0xa0, &der_tlv(0x1b, REALM.as_bytes())),
            der_tlv(0xa1, &name),
        ]
        .concat(),
    );
    let other_name = der_tlv(
        0xa0,
        &[
            vec![0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x02],
            der_tlv(0xa0, &principal),
        ]
        .concat(),
    );
    der_tlv(0x30, &other_name)
}

struct PkinitCerts {
    ca: String,
    kdc: (String, String),
    client: (String, String),
}

fn pkinit_certificates() -> Result<PkinitCerts> {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256,
    };
    let ca_key = KeyPair::generate_for(&PKCS_RSA_SHA256)?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "PKINIT CA");
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf =
        |cn: &str, name_type: u8, components: &[&str], eku: u64| -> Result<(String, String)> {
            let key = KeyPair::generate_for(&PKCS_RSA_SHA256)?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.distinguished_name.push(DnType::CommonName, cn);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![
                1, 3, 6, 1, 5, 2, 3, eku,
            ])];
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[2, 5, 29, 17],
                pkinit_san(name_type, components),
            )];
            let cert = params.signed_by(&key, &issuer)?;
            Ok((
                pem("CERTIFICATE", cert.der()),
                pem("PRIVATE KEY", &key.serialize_der()),
            ))
        };
    Ok(PkinitCerts {
        ca: pem("CERTIFICATE", ca.der()),
        kdc: leaf("krbtgt", 2, &["krbtgt", REALM], 5)?,
        client: leaf(USER, 1, &[USER], 4)?,
    })
}

/// A harness whose provider has PKINIT set up, with the `kinit -X` options
/// for the client's trust anchor and identity.
async fn pkinit_harness(extra: Value) -> Result<Option<(Harness, [String; 2])>> {
    if !std::path::Path::new("/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/pkinit.so").exists()
        && !std::path::Path::new("/usr/lib64/krb5/plugins/preauth/pkinit.so").exists()
    {
        return Ok(None);
    }
    let certs = pkinit_certificates()?;
    let mut cfg = json!({
        "pkinit_certificate": "00000000-0000-0000-0000-00000000000a",
        "pkinit_client_ca": "00000000-0000-0000-0000-00000000000b",
        "mock_certificates": {
            "00000000-0000-0000-0000-00000000000a": {"certificate": certs.kdc.0, "key": certs.kdc.1},
            "00000000-0000-0000-0000-00000000000b": {"certificate": certs.ca},
        },
    });
    if let (Some(cfg), Some(extra)) = (cfg.as_object_mut(), extra.as_object()) {
        cfg.extend(extra.clone());
    }
    let Some(h) = Harness::start(cfg, false).await? else {
        return Ok(None);
    };
    let (ca, cert, key) = (h.path("ca.pem"), h.path("client.pem"), h.path("client.key"));
    std::fs::write(&ca, &certs.ca)?;
    std::fs::write(&cert, &certs.client.0)?;
    std::fs::write(&key, &certs.client.1)?;
    let options = [
        format!("X509_anchors=FILE:{}", ca.display()),
        format!(
            "X509_user_identity=FILE:{},{}",
            cert.display(),
            key.display()
        ),
    ];
    Ok(Some((h, options)))
}

async fn pkinit_kinit(extra: Value) -> Result<()> {
    let Some((h, [anchors, identity])) = pkinit_harness(extra).await? else {
        return Ok(());
    };
    h.ok("", "kinit", &["-X", &anchors, "-X", &identity, USER])
        .await?;
    let out = h.ok("", "klist", &[]).await?;
    eyre::ensure!(out.contains(&format!("krbtgt/{REALM}@{REALM}")), "{out}");
    let trace = std::fs::read_to_string(h.path("trace.log"))?;
    eyre::ensure!(
        trace.contains("PKINIT"),
        "kinit did not use PKINIT:\n{trace}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_pkinit() -> Result<()> {
    pkinit_kinit(json!({})).await
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_pkinit_freshness() -> Result<()> {
    pkinit_kinit(json!({"pkinit_require_freshness": true})).await
}

#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_anonymous_pkinit() -> Result<()> {
    let Some((h, [anchors, _])) = pkinit_harness(json!({"anonymous_pkinit_enabled": true})).await?
    else {
        return Ok(());
    };
    h.ok("", "kinit", &["-n", "-X", &anchors]).await?;
    let out = h.ok("", "klist", &[]).await?;
    eyre::ensure!(
        out.contains("Default principal: WELLKNOWN/ANONYMOUS@"),
        "anonymous klist: {out}"
    );

    let Some((h, [anchors, _])) = pkinit_harness(json!({})).await? else {
        return Ok(());
    };
    let (ok, out) = h.run("", "kinit", &["-n", "-X", &anchors]).await?;
    eyre::ensure!(!ok, "anonymous PKINIT succeeded while disabled: {out}");
    Ok(())
}

const PEER_REALM: &str = "MIT.TEST";

async fn peer_tool(h: &Harness, tool: &str, args: &[&str]) -> Result<()> {
    mit_tool(&h.path("krb5.conf"), &h.path("kdc.conf"), tool, args).await
}

async fn mit_tool(
    config: &std::path::Path,
    profile: &std::path::Path,
    tool: &str,
    args: &[&str],
) -> Result<()> {
    let out = Command::new(tool)
        .args(args)
        .env("KRB5_CONFIG", config)
        .env("KRB5_KDC_PROFILE", profile)
        .stdin(Stdio::null())
        .output()
        .await?;
    eyre::ensure!(
        out.status.success(),
        "{tool} {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// A user of a real MIT KDC in a peer realm gets a service ticket from the
/// Rust KDC across an authentik realm trust.
#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_cross_realm() -> Result<()> {
    if !have_tools(&["krb5kdc", "kdb5_util", "kadmin.local"]) {
        eprintln!("skipping: MIT KDC tools not installed");
        return Ok(());
    }
    let trust_key = find_etype(18)
        .map_err(|err| eyre!("{err:?}"))?
        .string_to_key(
            b"trust-password",
            format!("{PEER_REALM}krbtgt{REALM}").as_bytes(),
            None,
        )
        .map_err(|err| eyre!("{err:?}"))?;
    let keys = json!({"18": STANDARD.encode(&*trust_key)});
    let trust = json!({
        "remote_realm": PEER_REALM, "capaths": [],
        "outgoing_kvno": 1_i32, "outgoing_keys": keys,
        "incoming_kvno": 1_i32, "incoming_keys": keys,
    });
    let Some(h) = Harness::start(json!({"mock_trusts": [trust]}), false).await? else {
        return Ok(());
    };
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let config = std::fs::read_to_string(h.path("krb5.conf"))?.replace(
        "[realms]\n",
        &format!("[realms]\n\t{PEER_REALM} = {{\n\t\tkdc = 127.0.0.1:{port}\n\t}}\n"),
    );
    std::fs::write(h.path("krb5.conf"), config)?;
    let db = h.path("principal");
    std::fs::write(h.path("kadm5.acl"), format!("*/admin@{PEER_REALM} *\n"))?;
    std::fs::write(
        h.path("kdc.conf"),
        format!(
            "[kdcdefaults]\n\tkdc_ports = {port}\n\tkdc_tcp_ports = {port}\n\
             [realms]\n\t{PEER_REALM} = {{\n\
             \t\tdatabase_name = {db}\n\
             \t\tacl_file = {acl}\n\
             \t\tkey_stash_file = {stash}\n\t}}\n",
            db = db.display(),
            acl = h.path("kadm5.acl").display(),
            stash = h.path("stash").display(),
        ),
    )?;
    let db = db.display().to_string();
    peer_tool(
        &h,
        "kdb5_util",
        &[
            "create",
            "-r",
            PEER_REALM,
            "-d",
            &db,
            "-s",
            "-P",
            "master-password",
        ],
    )
    .await?;
    for query in [
        format!("addprinc -pw {PASSWORD} {USER}"),
        format!("addprinc -e aes256-cts-hmac-sha1-96:normal -pw trust-password krbtgt/{REALM}"),
    ] {
        peer_tool(
            &h,
            "kadmin.local",
            &["-r", PEER_REALM, "-d", &db, "-q", &query],
        )
        .await?;
    }
    let _kdc = Command::new("krb5kdc")
        .args(["-n", "-r", PEER_REALM])
        .env("KRB5_CONFIG", h.path("krb5.conf"))
        .env("KRB5_KDC_PROFILE", h.path("kdc.conf"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    wait_port(port, "MIT KDC").await?;

    h.ok(
        &format!("{PASSWORD}\n"),
        "kinit",
        &[&format!("{USER}@{PEER_REALM}")],
    )
    .await?;
    let service = format!("{SERVICE}@{REALM}");
    h.ok("", "kvno", &[&service]).await?;
    let out = h.ok("", "klist", &[]).await?;
    for principal in [format!("krbtgt/{REALM}@{PEER_REALM}"), service] {
        eyre::ensure!(out.contains(&principal), "missing {principal}: {out}");
    }
    Ok(())
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

async fn wait_port(port: u16, what: &str) -> Result<()> {
    for _ in 0..50_u32 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(eyre!("{what} did not start"))
}

const KPROP_MASTER: &str = "kprop-master-password";

fn named_service(spn: &str) -> Value {
    let mut service = service();
    service["spn"] = json!(spn);
    service
}

async fn replica_command(
    h: &Harness,
    input: &str,
    tool: &str,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut child = Command::new(tool)
        .args(args)
        .env("KRB5_CONFIG", h.path("replica.conf"))
        .env("KRB5_KDC_PROFILE", h.path("replica-kdc.conf"))
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", h.path("replica.ccache").display()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).await?;
    }
    Ok(child.wait_with_output().await?)
}

/// The Rust outpost propagates its database to a real MIT `kpropd`, and the
/// replica's own `krb5kdc` then issues tickets from it.
#[tokio::test(flavor = "multi_thread")]
async fn mit_interop_kprop() -> Result<()> {
    use krb5_rs::{
        kdc::kdb::mit::dump::{DumpVersion, write_dump},
        keytab::{FileKeytab, Keytab as _, KeytabEntry},
    };
    if !have_tools(&["kpropd", "krb5kdc", "kdb5_util", "kadmin.local"]) {
        eprintln!("skipping: MIT KDC tools not installed");
        return Ok(());
    }
    let extra = json!({
        "kprop_master_password": KPROP_MASTER,
        "kprop_client_spn": "host/kprop-client",
    });
    // kpropd accepts tickets for host/<its hostname>, which is the host the
    // outpost connects to.
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")?
        .trim()
        .to_ascii_lowercase();
    let services = vec![
        service(),
        named_service("host/kprop-client"),
        named_service(&format!("host/{host}")),
    ];
    let Some(h) = Harness::start_with(extra.clone(), false, services, |_| {}).await? else {
        return Ok(());
    };
    let keytab = h.path("kpropd.keytab");
    FileKeytab::new(keytab.clone())
        .add_entry(&KeytabEntry {
            principal: krb5_rs::types::PrincipalName::new_srv_inst("host", &host),
            realm: REALM.to_owned(),
            timestamp: 0,
            kvno: 1,
            key: krb5_rs::types::EncryptionKey::new(18, vec![18_u8; 32]),
        })
        .map_err(|err| eyre!("write keytab: {err}"))?;

    let (kprop_port, kdc_port) = (free_port()?, free_port()?);
    let (config, profile) = (h.path("replica.conf"), h.path("replica-kdc.conf"));
    let db = h.path("replica-db").display().to_string();
    std::fs::write(
        &config,
        format!(
            "[libdefaults]\n\tdefault_realm = {REALM}\n\tdns_lookup_kdc = false\n\
             \tudp_preference_limit = 1\n\tdns_canonicalize_hostname = false\n\tqualify_shortname = \"\"\n\trdns = false\n\
             [realms]\n\t{REALM} = {{\n\t\tkdc = 127.0.0.1:{kdc_port}\n\t}}\n"
        ),
    )?;
    std::fs::write(h.path("kpropd.acl"), format!("host/kprop-client@{REALM}\n"))?;
    std::fs::write(h.path("kadm5.acl"), "")?;
    std::fs::write(
        &profile,
        format!(
            "[kdcdefaults]\n\tkdc_ports = {kdc_port}\n\tkdc_tcp_ports = {kdc_port}\n\
             [realms]\n\t{REALM} = {{\n\
             \t\tdatabase_name = {db}\n\
             \t\tacl_file = {acl}\n\
             \t\tkey_stash_file = {stash}\n\t}}\n",
            acl = h.path("kadm5.acl").display(),
            stash = h.path("replica-stash").display(),
        ),
    )?;
    mit_tool(
        &config,
        &profile,
        "kdb5_util",
        &["create", "-r", REALM, "-d", &db, "-s", "-P", KPROP_MASTER],
    )
    .await?;

    let log = std::fs::File::create(h.path("kpropd.log"))?;
    let _kpropd = Command::new("kpropd")
        .args(["-d", "-S", "-r", REALM, "-P", &kprop_port.to_string()])
        .arg("-s")
        .arg(&keytab)
        .arg("-a")
        .arg(h.path("kpropd.acl"))
        .arg("-f")
        .arg(h.path("from_master"))
        .env("KRB5_CONFIG", &config)
        .env("KRB5_KDC_PROFILE", &profile)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()?;
    wait_port(kprop_port, "kpropd").await?;

    let provider = provider(&extra)?;
    let source = super::kprop::Source::new(&provider, Arc::clone(&h.store), Arc::clone(&h.kdc))?
        .ok_or_else(|| eyre!("kprop source not configured"))?;
    let dump = write_dump(DumpVersion::R111, &source.entries().await?, &[]);
    Box::pin(source.push(&format!("{host}:{kprop_port}"), &dump))
        .await
        .map_err(|err| {
            let log = std::fs::read_to_string(h.path("kpropd.log")).unwrap_or_default();
            eyre!(
                "{err}
kpropd:
{log}"
            )
        })?;

    let mut loaded = false;
    for _ in 0..50_u32 {
        let out = replica_command(
            &h,
            "",
            "kadmin.local",
            &["-r", REALM, "-d", &db, "-q", "getprinc alice"],
        )
        .await?;
        if String::from_utf8_lossy(&out.stdout).contains(&format!("Principal: {USER}@{REALM}")) {
            loaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eyre::ensure!(
        loaded,
        "replica did not load the database: {}",
        std::fs::read_to_string(h.path("kpropd.log"))?
    );

    let _kdc = Command::new("krb5kdc")
        .args(["-n", "-r", REALM])
        .env("KRB5_CONFIG", &config)
        .env("KRB5_KDC_PROFILE", &profile)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    wait_port(kdc_port, "replica KDC").await?;
    for (input, tool, args) in [
        (format!("{PASSWORD}\n"), "kinit", [USER]),
        (String::new(), "kvno", [SERVICE]),
    ] {
        let out = replica_command(&h, &input, tool, &args).await?;
        eyre::ensure!(
            out.status.success(),
            "replica {tool} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}
