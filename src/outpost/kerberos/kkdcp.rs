//! MS-KKDCP: Kerberos over HTTPS.

use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwapOption;
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::post,
};
use krb5_rs::{
    kdc::{KdcRealms, KdcService as _, Transport},
    types::KdcProxyMessage,
};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use super::store::ProviderStore;

const CONTENT_TYPE: &str = "application/kerberos";
const MAX_MESSAGE_SIZE: usize = 65536;
const PATH: &str = "/KdcProxy";

pub(crate) struct Kkdcp {
    pub(crate) realms: ArcSwapOption<KdcRealms<Arc<ProviderStore>>>,
    pub(crate) certificate: ArcSwapOption<CertifiedKey>,
    fallback: Arc<CertifiedKey>,
}

impl std::fmt::Debug for Kkdcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kkdcp").finish_non_exhaustive()
    }
}

impl Kkdcp {
    pub(crate) fn new(fallback: Arc<CertifiedKey>) -> Self {
        Self {
            realms: ArcSwapOption::empty(),
            certificate: ArcSwapOption::empty(),
            fallback,
        }
    }

    pub(crate) fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route(PATH, post(handle))
            .layer(DefaultBodyLimit::max(MAX_MESSAGE_SIZE + 4096))
            .with_state(self)
    }

    async fn forward(&self, body: &[u8], peer: SocketAddr) -> Result<Vec<u8>, StatusCode> {
        let mut message: KdcProxyMessage =
            rasn::der::decode(body).map_err(|_err| StatusCode::BAD_REQUEST)?;
        let framed = message.kerb_message.as_ref();
        let (len, request) = framed
            .split_first_chunk::<4>()
            .ok_or(StatusCode::BAD_REQUEST)?;
        if usize::try_from(u32::from_be_bytes(*len)).ok() != Some(request.len()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let realms = self
            .realms
            .load_full()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let (reply, _) = realms
            .handle_summarized_from(request, Transport::Tcp, Some(peer))
            .await;
        let reply_len = u32::try_from(reply.len()).map_err(|_err| StatusCode::BAD_GATEWAY)?;
        if reply.is_empty() || reply.len() > MAX_MESSAGE_SIZE {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let mut kerb_message = Vec::with_capacity(reply.len() + 4);
        kerb_message.extend_from_slice(&reply_len.to_be_bytes());
        kerb_message.extend_from_slice(&reply);
        message.kerb_message = kerb_message.into();
        rasn::der::encode(&message).map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl ResolvesServerCert for Kkdcp {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.certificate
                .load_full()
                .unwrap_or_else(|| Arc::clone(&self.fallback)),
        )
    }

    fn only_raw_public_keys(&self) -> bool {
        false
    }
}

fn is_kerberos(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(CONTENT_TYPE))
}

async fn handle(
    State(kkdcp): State<Arc<Kkdcp>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_kerberos(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match kkdcp.forward(&body, peer).await {
        Ok(reply) => ([(header::CONTENT_TYPE, CONTENT_TYPE)], reply).into_response(),
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn content_type() {
        let mut headers = HeaderMap::new();
        assert!(!is_kerberos(&headers));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/Kerberos; charset=binary"),
        );
        assert!(is_kerberos(&headers));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!is_kerberos(&headers));
    }
}
