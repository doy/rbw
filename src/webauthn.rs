use anyhow::Context;
use reqwest::Url;
use webauthn_authenticator_rs::{transport::{AnyTransport, Transport}, AuthenticatorBackend, ui::UiCallback, ctap2::EnrollSampleStatus, types::{CableRequestType, CableState}};
use webauthn_rs_proto::PublicKeyCredentialRequestOptions;

use crate::locked::Password;

pub async fn webauthn(challenge: PublicKeyCredentialRequestOptions, pin: &str) -> Result<Password, Box<dyn std::error::Error + Send + Sync>> {
    let mut trans = AnyTransport::new().await.ok().ok_or("Failed to set up webauthn transport")?;

    let ui = Pinentry { pin: pin.to_string() };
    let mut authenticator = trans.connect_all(&ui).ok().ok_or("Failed to connect to authenticator")?;
    let authenticator = authenticator.get_mut(0).ok_or("Failed to get authenticator")?;

    let origin = crate::config::Config::load_async().await.ok().ok_or("error loading config")?.base_url.ok_or("error loading base_url")?;
    let origin = Url::parse(&origin).context("Failed to parse origin")?;

    let result = authenticator.perform_auth(origin, challenge, 60000);
    // required, so that the JSON is parsed corretly by the server
    let out = serde_json::to_string(&result.unwrap())?
        .replace("\"appid\":null,\"hmac_get_secret\":null", "\"appid\":false")
        .replace("clientDataJSON", "clientDataJson");

    let mut buf = crate::locked::Vec::new();
    buf.extend(out.as_bytes().iter().copied());
    Ok(Password::new(buf))
}

#[derive(Debug)]
struct Pinentry {
    pin: String,
}

impl UiCallback for Pinentry {
    fn request_pin(&self) -> Option<String> {
        return Some(self.pin.clone());
    }

    fn request_touch(&self) {
        println!("Called unimplemented method: request_touch")
    }

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        println!("Called unimplemented method: fingerprint_enrollment_feedback")
    }

    fn cable_qr_code(&self, request_type: CableRequestType, url: String) {
        println!("Called unimplemented method: cable_qr_code")
    }

    fn dismiss_qr_code(&self) {
        println!("Called unimplemented method: dismiss_qr_code")
    }

    fn cable_status_update(&self, state: CableState) {
        println!("Called unimplemented method: cable_status_update")
    }
}
