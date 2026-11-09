//! PKINIT configuration from authentik certificate/key pairs.

use std::sync::Arc;

use ak_client::{
    apis::{
        configuration::Configuration,
        crypto_api::crypto_certificatekeypairs_view_certificate_retrieve,
    },
    models::KerberosOutpostConfig,
};
use ak_common::tls::store::CertificateStore;
use eyre::{Result, eyre};
use krb5_rs::pkinit::{
    cms::Identity,
    server::ServerConfig,
    x509::{Cert, TrustStore},
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use tracing::warn;

fn anchors(pem: &str) -> Result<Vec<Cert>> {
    let certs = CertificateDer::pem_reader_iter(pem.as_bytes())
        .map(|der| Cert::from_der(der?.as_ref()).map_err(|err| eyre!("{err}")))
        .collect::<Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(eyre!("PKINIT client CA has no certificate data"));
    }
    Ok(certs)
}

/// The provider's PKINIT settings; `None` when PKINIT is not configured.
pub(crate) async fn server_config(
    api: &Configuration,
    certificates: &CertificateStore,
    provider: &KerberosOutpostConfig,
) -> Result<Option<Arc<ServerConfig>>> {
    let (kdc_cert, client_ca) = (
        provider.pkinit_certificate.flatten(),
        provider.pkinit_client_ca.flatten(),
    );
    let (Some(kdc_cert), Some(client_ca)) = (kdc_cert, client_ca) else {
        if kdc_cert.is_some() || client_ca.is_some() {
            warn!(
                provider = provider.name,
                "PKINIT requires both a KDC certificate and client CA certificate"
            );
        }
        return Ok(None);
    };
    let keypair = certificates
        .ensure_keypair(api, kdc_cert)
        .await
        .map_err(|err| eyre!("fetch KDC certificate: {err}"))?;
    let identity = Identity::from_pem(&keypair.certificate, &keypair.key)
        .map_err(|err| eyre!("load KDC certificate: {err}"))?;
    let ca =
        crypto_certificatekeypairs_view_certificate_retrieve(api, &client_ca.to_string(), None)
            .await
            .map_err(|err| eyre!("fetch PKINIT client CA: {err}"))?;
    let store = TrustStore {
        anchors: anchors(&ca.data)?,
        ..TrustStore::default()
    };
    let mut server = ServerConfig::new(identity, store);
    server.require_freshness = provider.pkinit_require_freshness.unwrap_or_default();
    server.indicators = provider.pkinit_indicators.clone().unwrap_or_default();
    Ok(Some(Arc::new(server)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_require_a_certificate() {
        let err = anchors("").expect_err("empty PEM");
        assert!(err.to_string().contains("no certificate data"));
        let cert =
            rcgen::generate_simple_self_signed(vec!["ca.test".to_owned()]).expect("certificate");
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            cert.cert.der().as_ref(),
        );
        let body = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
        let parsed = anchors(&pem).expect("anchors");
        assert_eq!(parsed.len(), 1);
    }
}
