use anyhow::Context as _;
use futures::StreamExt as _;
use webauthn_authenticator_rs::{
    ctap2::CtapAuthenticator,
    transport::{AnyTransport, TokenEvent, Transport as _},
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
    AuthenticatorBackend as _,
};
use webauthn_rs_proto::PublicKeyCredentialRequestOptions;

use crate::locked::Password;

pub async fn webauthn(
    challenge: PublicKeyCredentialRequestOptions,
    pinentry: String,
    environment: crate::protocol::Environment,
) -> anyhow::Result<Password> {
    let transport = AnyTransport::new()
        .await
        .context("failed to set up webauthn transport")?;

    let ui = Ui {
        pinentry,
        environment,
    };

    let mut events = transport
        .watch()
        .await
        .context("failed to watch webauthn transport")?;

    let mut authenticator = loop {
        match events.next().await {
            Some(TokenEvent::Added(token)) => {
                if let Some(auth) = CtapAuthenticator::new(token, &ui).await {
                    break auth;
                }
            }
            Some(TokenEvent::EnumerationComplete) => {
                log::info!(
                    "rbw: connect a FIDO2 security key to continue"
                );
            }
            Some(TokenEvent::Removed(_)) => {}
            None => {
                anyhow::bail!(
                    "webauthn transport closed before a token connected"
                );
            }
        }
    };

    // Derive the origin from the challenge's rp_id rather than rbw's
    // configured vault URL: the authenticator enforces that origin's host
    // matches (or is a subdomain of) rp_id, and Bitwarden registers
    // credentials against the web vault host. Using rp_id directly avoids
    // mismatches on self-hosted setups where the user's configured ui_url
    // doesn't line up with the host the credential was registered against.
    let origin = reqwest::Url::parse(&format!("https://{}", challenge.rp_id))
        .context("failed to construct webauthn origin from rp_id")?;

    // perform_auth is synchronous and blocks for up to the timeout waiting
    // on USB HID. Use block_in_place so it doesn't stall other tasks on
    // the tokio worker. The authenticator borrows from `ui`, so we can't
    // move it across a spawn_blocking boundary.
    let result = tokio::task::block_in_place(|| {
        authenticator.perform_auth(origin, challenge, u32::MAX)
    })
    .map_err(|e| anyhow::anyhow!("webauthn authentication failed: {e:?}"))?;

    let out = serde_json::to_string(&BitwardenAssertion::from(result))
        .context("failed to serialize webauthn assertion")?;

    let mut buf = crate::locked::Vec::new();
    buf.extend(out.as_bytes().iter().copied());
    Ok(Password::new(buf))
}

// Bitwarden's server expects a slightly different shape than what
// webauthn-rs-proto serializes by default: the response field is camelCase
// `clientDataJson` rather than the W3C-spec `clientDataJSON`, and the
// extensions object must use a non-nullable `appid: bool`. We build a
// dedicated wire type instead of munging the JSON.
#[derive(serde::Serialize)]
struct BitwardenAssertion {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: base64urlsafedata::Base64UrlSafeData,
    response: BitwardenAssertionResponse,
    extensions: BitwardenAssertionExtensions,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BitwardenAssertionResponse {
    authenticator_data: base64urlsafedata::Base64UrlSafeData,
    client_data_json: base64urlsafedata::Base64UrlSafeData,
    signature: base64urlsafedata::Base64UrlSafeData,
    user_handle: Option<base64urlsafedata::Base64UrlSafeData>,
}

#[derive(serde::Serialize)]
struct BitwardenAssertionExtensions {
    appid: bool,
}

impl From<webauthn_rs_proto::PublicKeyCredential> for BitwardenAssertion {
    fn from(c: webauthn_rs_proto::PublicKeyCredential) -> Self {
        Self {
            id: c.id,
            raw_id: c.raw_id,
            response: BitwardenAssertionResponse {
                authenticator_data: c.response.authenticator_data,
                client_data_json: c.response.client_data_json,
                signature: c.response.signature,
                user_handle: c.response.user_handle,
            },
            extensions: BitwardenAssertionExtensions {
                appid: c.extensions.appid.unwrap_or(false),
            },
            type_: c.type_,
        }
    }
}

#[derive(Debug)]
struct Ui {
    pinentry: String,
    environment: crate::protocol::Environment,
}

impl UiCallback for Ui {
    // The library calls this synchronously from inside `perform_auth` only
    // when the authenticator actually demands a PIN (Required/Preferred
    // policy, or the key has client_pin set). Bridge into async pinentry
    // by spawning on the current runtime and waiting on a sync channel —
    // safe under `block_in_place`, which is how `perform_auth` is invoked.
    fn request_pin(&self) -> Option<String> {
        let pinentry = self.pinentry.clone();
        let environment = self.environment.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        tokio::runtime::Handle::current().spawn(async move {
            let provider = crate::api::TwoFactorProviderType::WebAuthn;
            let res = crate::pinentry::getpin(
                &pinentry,
                provider.header(),
                provider.message(),
                None,
                &environment,
                provider.grab(),
            )
            .await;
            let _ = tx.send(res);
        });
        match rx.recv().ok()? {
            Ok(pw) => std::str::from_utf8(pw.password())
                .ok()
                .map(str::to_string),
            Err(e) => {
                log::warn!("webauthn: pinentry failed: {e}");
                None
            }
        }
    }

    fn request_touch(&self) {
        log::debug!("webauthn: waiting for user presence (touch the key)");
    }

    fn fingerprint_enrollment_feedback(
        &self,
        _remaining_samples: u32,
        _feedback: Option<EnrollSampleStatus>,
    ) {
        log::warn!("webauthn: fingerprint_enrollment_feedback unimplemented");
    }

    fn cable_qr_code(&self, _request_type: CableRequestType, _url: String) {
        log::warn!("webauthn: cable_qr_code unimplemented");
    }

    fn dismiss_qr_code(&self) {
        log::warn!("webauthn: dismiss_qr_code unimplemented");
    }

    fn cable_status_update(&self, _state: CableState) {
        log::warn!("webauthn: cable_status_update unimplemented");
    }

    fn processing(&self) {
        log::debug!("webauthn: processing...");
    }
}
