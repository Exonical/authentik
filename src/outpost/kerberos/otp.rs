//! OTP pre-authentication validated by authentik.

use std::{pin::Pin, sync::Arc, time::Duration};

use ak_client::{
    apis::outposts_api::outposts_kerberos_otp_check, models::KerberosOtpCheckRequestRequest,
};
use krb5_rs::kdc::{OtpTokenType, OtpVerifier};
use tracing::{info, warn};

use super::store::ProviderStore;

/// The token type that enables OTP in krb5-rs. Its RADIUS settings are unused
/// because [`ApiOtp`] does the validation.
pub(crate) fn token_type(indicators: Vec<String>) -> OtpTokenType {
    OtpTokenType {
        name: "DEFAULT".to_owned(),
        server: String::new(),
        secret: String::new(),
        timeout: Duration::from_secs(5),
        retries: 0,
        strip_realm: true,
        indicators,
    }
}

pub(crate) struct ApiOtp {
    pub(crate) store: Arc<ProviderStore>,
    pub(crate) indicators: Vec<String>,
}

impl OtpVerifier for ApiOtp {
    fn verify<'a>(
        &'a self,
        principal: &'a str,
        value: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let realm = &self.store.settings().realm;
            let username = principal.strip_suffix(realm.as_str())?.strip_suffix('@')?;
            if username.is_empty() || username.contains('/') {
                return None;
            }
            let value = std::str::from_utf8(value).ok()?;
            let request =
                KerberosOtpCheckRequestRequest::new(username.to_owned(), value.to_owned());
            match outposts_kerberos_otp_check(self.store.api(), self.store.provider_id(), request)
                .await
            {
                Ok(check) if check.allowed => Some(self.indicators.clone()),
                Ok(_) => {
                    info!(username, "Kerberos OTP validation denied");
                    None
                }
                Err(err) => {
                    warn!(?err, username, "Kerberos OTP validation failed");
                    None
                }
            }
        })
    }
}
