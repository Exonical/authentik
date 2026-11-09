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

#[derive(Default)]
struct Api {
    users: Mutex<HashMap<String, Value>>,
    services: Mutex<Vec<Value>>,
    denied: Mutex<Vec<String>>,
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
    let passing = !q.get("username").is_some_and(|u| denied.contains(u));
    Json(json!({"access": {"passing": passing, "messages": [], "log_messages": []}}))
}

async fn audit_event(State(api): State<Arc<Api>>, Json(body): Json<Value>) -> StatusCode {
    api.audit
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(body);
    StatusCode::NO_CONTENT
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
            get(async || page(&[])),
        )
        .route("/outposts/kerberos/{id}/user_key/", get(user_key))
        .route("/outposts/kerberos/{id}/user_keys/", get(user_keys))
        .route("/outposts/kerberos/{id}/access_check/", get(access_check))
        .route("/outposts/kerberos/{id}/audit_event/", post(audit_event))
        .route("/outposts/kerberos/{id}/set_password/", post(set_password))
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
        let api = Arc::new(Api::default());
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
        let (kdc, store) = build_provider(&config, &certificates, &provider(&extra)?).await?;

        let (tx, rx) = watch::channel(false);
        let options = ServeOptions {
            logger: None,
            shutdown: Some(rx.clone()),
        };
        let kdc = Arc::new(kdc);
        let dispatcher = Arc::new(Dispatcher::default());
        dispatcher.udp.store(kdc_realms(vec![Arc::clone(&kdc)]));
        dispatcher.tcp.store(kdc_realms(vec![kdc]));
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
        tokio::spawn(kpasswd::serve_tcp(kpasswd, tcp, rx));

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
                 \t}}\n"
            ),
        )?;
        Ok(Some(Self {
            dir,
            api,
            _shutdown: tx,
        }))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Run an MIT tool, returning whether it succeeded and its output.
    async fn run(&self, input: &str, tool: &str, args: &[&str]) -> Result<(bool, String)> {
        let mut child = Command::new(tool)
            .args(args)
            .env("KRB5_CONFIG", self.path("krb5.conf"))
            .env(
                "KRB5CCNAME",
                format!("FILE:{}", self.path("ccache").display()),
            )
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
