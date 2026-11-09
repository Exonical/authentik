//! kpasswd (RFC 3244) backed by authentik's set-password endpoint.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use ak_client::{
    apis::{
        Error, ResponseContent,
        outposts_api::{
            OutpostsKerberosSetPasswordCreateError, outposts_kerberos_set_password_create,
        },
    },
    models::KerberosSetPasswordRequest,
};
use arc_swap::ArcSwap;
use eyre::Result;
use krb5_rs::{
    kdc::{
        PrincipalEntry,
        kdb::{
            kpasswd::{PasswordChanger, Service, parse_request, process_request_with},
            kprop::ReplayCache,
        },
    },
    protocol::{
        ap::{ApError, KeySource},
        kpasswd::{KPASSWD_ACCESSDENIED, KPASSWD_HARDERROR, KPASSWD_SOFTERROR, KPASSWD_SUCCESS},
    },
    types::{ApReq, EncryptionKey, PrincipalName},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UdpSocket},
    runtime::Handle,
    sync::watch,
    time::timeout,
};
use tracing::{info, warn};

use super::store::{ProviderStore, components};

const MAX_REQUEST_SIZE: usize = 65536;
const CLOCKSKEW: Duration = Duration::from_secs(300);
const TCP_TIMEOUT: Duration = Duration::from_secs(30);

/// A realm that accepts password changes.
pub(crate) struct KpasswdRealm {
    pub(crate) store: Arc<ProviderStore>,
    pub(crate) udp: bool,
    pub(crate) tcp: bool,
}

#[derive(Default)]
pub(crate) struct Kpasswd {
    pub(crate) realms: ArcSwap<HashMap<String, Arc<KpasswdRealm>>>,
    replay: ReplayCache,
}

struct ChangepwKeys<'a>(&'a PrincipalEntry);

impl KeySource for ChangepwKeys<'_> {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        let mut keys = self.0.keys.iter().filter(|k| k.key.keytype == etype);
        match kvno.filter(|v| *v > 0_i32) {
            None => keys.next(),
            Some(kvno) => keys.find(|k| i64::from(k.kvno) == i64::from(kvno)),
        }
        .map(|k| k.key.clone())
        .ok_or(ApError::NoKey)
    }
}

/// Self-service password changes through the authentik API.
struct ApiChanger<'a> {
    store: &'a ProviderStore,
}

impl PasswordChanger for ApiChanger<'_> {
    async fn change_password(
        &self,
        client: (&PrincipalName, &str),
        target: (&PrincipalName, &str),
        _initial: bool,
        password: &str,
    ) -> (u16, String) {
        let realm = self.store.settings().realm.as_str();
        let comps = components(client.0);
        let [username] = comps.as_slice() else {
            return (KPASSWD_ACCESSDENIED, "Unauthorized request".to_owned());
        };
        if client.1 != realm || target.1 != realm || components(target.0) != comps {
            return (KPASSWD_ACCESSDENIED, "Unauthorized request".to_owned());
        }
        let request = KerberosSetPasswordRequest::new(username.clone(), password.to_owned());
        match outposts_kerberos_set_password_create(
            self.store.api(),
            self.store.provider_id(),
            request,
        )
        .await
        {
            Ok(()) => {
                self.store.invalidate_user(username);
                (KPASSWD_SUCCESS, String::new())
            }
            Err(Error::ResponseError(ResponseContent {
                entity: Some(OutpostsKerberosSetPasswordCreateError::Status400(policy)),
                ..
            })) if !policy.messages.is_empty() => (KPASSWD_SOFTERROR, policy.messages.join("\n")),
            Err(err) => {
                warn!(?err, username, "kpasswd password change failed");
                (KPASSWD_HARDERROR, "password change failed".to_owned())
            }
        }
    }
}

impl Kpasswd {
    /// Handle one request. Blocks on the runtime, so call it from a blocking task.
    fn handle(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        req: &[u8],
        udp: bool,
    ) -> Option<Vec<u8>> {
        let parsed = parse_request(req).ok()?;
        let ap_req: ApReq = rasn::der::decode(parsed.ap_req).ok()?;
        let realm = String::from_utf8_lossy(ap_req.ticket.realm.as_bytes()).into_owned();
        let realms = self.realms.load();
        let provider = realms.get(&realm)?;
        if !(if udp { provider.udp } else { provider.tcp }) {
            return None;
        }
        let entry = provider.store.entry(&["kadmin", "changepw"])?;
        let keys = ChangepwKeys(entry);
        let unused = |_: &PrincipalName, _: &str, _: &PrincipalName, _: &str| false;
        let svc = Service {
            realm: &realm,
            keys: &keys,
            replay: Some(&self.replay),
            clockskew: CLOCKSKEW,
            authorize: &unused,
        };
        let changer = ApiChanger {
            store: &provider.store,
        };
        let done =
            Handle::current().block_on(process_request_with(&changer, &svc, &local, &remote, req));
        info!(realm, %remote, "{}", done.log);
        done.reply
    }

    async fn dispatch(
        self: Arc<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        req: Vec<u8>,
        udp: bool,
    ) -> Option<Vec<u8>> {
        tokio::task::spawn_blocking(move || self.handle(local, remote, &req, udp))
            .await
            .ok()
            .flatten()
    }
}

pub(crate) async fn serve_udp(
    kpasswd: Arc<Kpasswd>,
    socket: UdpSocket,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let socket = Arc::new(socket);
    let local = socket.local_addr()?;
    let mut buf = vec![0_u8; MAX_REQUEST_SIZE];
    loop {
        let (n, remote) = tokio::select! {
            recv = socket.recv_from(&mut buf) => match recv {
                Ok(r) => r,
                Err(err) => {
                    warn!(?err, "kpasswd recv failed");
                    continue;
                }
            },
            _ = shutdown.wait_for(|v| *v) => return Ok(()),
        };
        let req = buf.get(..n).unwrap_or_default().to_vec();
        let (kpasswd, socket) = (Arc::clone(&kpasswd), Arc::clone(&socket));
        tokio::spawn(async move {
            if let Some(reply) = kpasswd.dispatch(local, remote, req, true).await
                && let Err(err) = socket.send_to(&reply, remote).await
            {
                warn!(?err, %remote, "kpasswd send failed");
            }
        });
    }
}

async fn serve_stream(
    kpasswd: Arc<Kpasswd>,
    mut stream: tokio::net::TcpStream,
    remote: SocketAddr,
) -> Result<()> {
    let local = stream.local_addr()?;
    let len = usize::try_from(timeout(TCP_TIMEOUT, stream.read_u32()).await??)?;
    if len > MAX_REQUEST_SIZE {
        return Ok(());
    }
    let mut req = vec![0_u8; len];
    timeout(TCP_TIMEOUT, stream.read_exact(&mut req)).await??;
    if let Some(reply) = kpasswd.dispatch(local, remote, req, false).await {
        stream.write_u32(u32::try_from(reply.len())?).await?;
        stream.write_all(&reply).await?;
        stream.shutdown().await?;
    }
    Ok(())
}

pub(crate) async fn serve_tcp(
    kpasswd: Arc<Kpasswd>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let (stream, remote) = tokio::select! {
            accept = listener.accept() => match accept {
                Ok(r) => r,
                Err(err) => {
                    warn!(?err, "kpasswd accept failed");
                    continue;
                }
            },
            _ = shutdown.wait_for(|v| *v) => return Ok(()),
        };
        let kpasswd = Arc::clone(&kpasswd);
        tokio::spawn(async move {
            if let Err(err) = serve_stream(kpasswd, stream, remote).await {
                warn!(?err, %remote, "kpasswd connection failed");
            }
        });
    }
}
