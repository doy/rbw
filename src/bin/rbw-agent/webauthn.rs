use anyhow::{ensure, Context as _};
use authenticator::{
    authenticatorservice::{AuthenticatorService, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    },
    statecallback::StateCallback,
    StatusPinUv, StatusUpdate,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::Digest as _;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    challenge: String,
    rp_id: Option<String>,
    allow_credentials: Vec<Credential>,
    timeout: Option<u64>,
    user_verification: Option<String>,
    #[serde(default)]
    extensions: Extensions,
}

#[derive(serde::Deserialize)]
struct Credential {
    id: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Default, serde::Deserialize)]
struct Extensions {
    appid: Option<String>,
}

struct Authentication {
    args: SignArgs,
    client_data: Vec<u8>,
    timeout: std::time::Duration,
}

fn decode(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig,
    };
    GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
    .decode(value)
    .context("invalid base64url in WebAuthn challenge")
}

fn prepare(
    ui_url: &str,
    challenge: serde_json::Value,
) -> anyhow::Result<Authentication> {
    let request: Request = serde_json::from_value(challenge)
        .context("invalid WebAuthn request from server")?;
    let url = url::Url::parse(ui_url).context("invalid web vault URL")?;
    let host = url.domain().context("WebAuthn requires a domain name")?;
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http" && host == "localhost"),
        "WebAuthn requires HTTPS (except on localhost)"
    );
    let origin = url.origin().ascii_serialization();
    let rp_id = request.rp_id.unwrap_or_else(|| host.to_owned());
    // Require an exact match rather than accepting arbitrary domain suffixes
    // without a public suffix list. Use ui_url for split hosts.
    ensure!(
        rp_id == host,
        "WebAuthn relying party must match the configured web vault host"
    );
    if let Some(appid) = &request.extensions.appid {
        let appid =
            url::Url::parse(appid).context("invalid WebAuthn AppID")?;
        ensure!(
            appid.origin() == url.origin(),
            "WebAuthn AppID must belong to the configured web vault origin"
        );
    }
    let challenge = decode(&request.challenge)?;
    ensure!(!challenge.is_empty(), "empty WebAuthn challenge");
    // Hash and submit exactly the same client data bytes.
    let client_data = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get",
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": origin,
        "crossOrigin": false,
    }))?;
    ensure!(
        !request.allow_credentials.is_empty(),
        "WebAuthn 2FA requires registered credential IDs"
    );
    let allow_list = request
        .allow_credentials
        .into_iter()
        .map(|credential| {
            ensure!(
                credential.kind == "public-key",
                "unsupported WebAuthn credential type"
            );
            let id = decode(&credential.id)?;
            ensure!(!id.is_empty(), "empty WebAuthn credential ID");
            Ok(PublicKeyCredentialDescriptor {
                id,
                transports: vec![],
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let user_verification_req = match request.user_verification.as_deref() {
        Some("discouraged") => UserVerificationRequirement::Discouraged,
        Some("required") => UserVerificationRequirement::Required,
        Some("preferred") | None => UserVerificationRequirement::Preferred,
        Some(_) => {
            anyhow::bail!("invalid WebAuthn user verification requirement")
        }
    };
    Ok(Authentication {
        args: SignArgs {
            client_data_hash: sha2::Sha256::digest(&client_data).into(),
            origin,
            relying_party_id: rp_id,
            allow_list,
            user_verification_req,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                app_id: request.extensions.appid,
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: true,
        },
        client_data,
        timeout: std::time::Duration::from_millis(
            request.timeout.unwrap_or(60_000).clamp(1_000, 120_000),
        ),
    })
}

fn assertion_token(
    result: authenticator::SignResult,
    authentication: &Authentication,
) -> anyhow::Result<String> {
    let assertion = result.assertion;
    let credential = assertion
        .credentials
        .as_ref()
        .or_else(|| {
            (authentication.args.allow_list.len() == 1)
                .then(|| &authentication.args.allow_list[0])
        })
        .context("security key did not identify the credential")?;
    ensure!(
        authentication
            .args
            .allow_list
            .iter()
            .any(|allowed| allowed.id == credential.id),
        "security key returned an unrequested credential"
    );
    let id = URL_SAFE_NO_PAD.encode(&credential.id);
    let mut extensions = serde_json::Map::new();
    if let Some(appid) = result.extensions.app_id {
        extensions.insert("appid".into(), appid.into());
    }
    Ok(serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode(assertion.auth_data.to_vec()),
            "clientDataJson": URL_SAFE_NO_PAD.encode(&authentication.client_data),
            "signature": URL_SAFE_NO_PAD.encode(assertion.signature),
            "userHandle": assertion.user.map(|user| URL_SAFE_NO_PAD.encode(user.id)),
        },
        "extensions": extensions,
    }).to_string())
}

// Cancel on PIN cancellation, socket failure, timeout, or cancellation of login.
struct Service(AuthenticatorService);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.cancel();
    }
}

async fn progress(
    sock: &mut crate::sock::Sock,
    message: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Progress {
        message: message.to_owned(),
    })
    .await
}

pub async fn authenticate(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
    config: &rbw::config::Config,
    challenge: serde_json::Value,
) -> anyhow::Result<String> {
    let authentication = prepare(&config.ui_url(), challenge)?;
    let mut service = Service(
        AuthenticatorService::new().context("failed to initialize FIDO")?,
    );
    service.0.add_detected_transports();
    let (status_tx, status_rx) = std::sync::mpsc::channel();
    let (updates_tx, mut updates_rx) = tokio::sync::mpsc::unbounded_channel();
    // Forward the synchronous status channel without blocking the executor.
    tokio::task::spawn_blocking(move || {
        while let Ok(status) = status_rx.recv() {
            if updates_tx.send(status).is_err() {
                break;
            }
        }
    });
    let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
    progress(
        sock,
        "Insert your FIDO security key and touch it when it blinks.",
    )
    .await?;
    service
        .0
        .sign(
            u64::try_from(authentication.timeout.as_millis())?,
            authentication.args.clone(),
            status_tx,
            StateCallback::new(Box::new(move |result| {
                let _ = result_tx.send(result);
            })),
        )
        .context("failed to start FIDO authentication")?;
    let result = tokio::time::timeout(authentication.timeout, async {
        loop {
            tokio::select! {
                result = &mut result_rx => {
                    return result.context("FIDO operation ended without a result")?
                        .context("security key authentication failed");
                }
                Some(status) = updates_rx.recv() => {
                    handle_status(status, sock, environment, config).await?;
                }
            }
        }
    }).await.context("timed out waiting for the FIDO security key")??;
    assertion_token(result, &authentication)
}

async fn handle_status(
    status: StatusUpdate,
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
    config: &rbw::config::Config,
) -> anyhow::Result<()> {
    match status {
        StatusUpdate::PresenceRequired | StatusUpdate::SelectDeviceNotice => {
            progress(sock, "Touch the FIDO security key you want to use.")
                .await?;
        }
        StatusUpdate::PinUvError(status) => {
            let (sender, error) = match status {
                StatusPinUv::PinRequired(sender) => (sender, None),
                StatusPinUv::InvalidPin(sender, attempts) => {
                    let error = attempts.map_or_else(
                        || "Incorrect security key PIN".to_owned(),
                        |attempts| format!(
                            "Incorrect security key PIN ({attempts} attempts remaining)"
                        ),
                    );
                    (sender, Some(error))
                }
                StatusPinUv::InvalidUv(_) => {
                    progress(sock, "Security key verification failed; try again on the key.").await?;
                    return Ok(());
                }
                status => anyhow::bail!(
                    "security key PIN/verification failed: {status:?}"
                ),
            };
            let pin = rbw::pinentry::getpin(
                &config.pinentry,
                "Security Key PIN",
                "Enter the PIN for your FIDO security key.",
                error.as_deref(),
                environment,
                true,
            )
            .await
            .context("failed to read security key PIN")?;
            let pin = std::str::from_utf8(pin.password())
                .context("security key PIN is not UTF-8")?;
            sender
                .send(authenticator::Pin::new(pin))
                .context("security key stopped waiting for a PIN")?;
        }
        StatusUpdate::SelectResultNotice(sender, _) => {
            // All allowed credentials belong to this login account.
            sender
                .send(Some(0))
                .context("failed to select security key credential")?;
        }
        StatusUpdate::InteractiveManagement(_) => {
            anyhow::bail!("unexpected FIDO management request")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn challenge() -> serde_json::Value {
        json!({
            "challenge": "AQIDBA", "rpId": "vault.example.com",
            "allowCredentials": [{"type": "public-key", "id": "BQYH"}],
            "userVerification": "discouraged",
            "extensions": {"appid": "https://vault.example.com/app-id.json"},
            "timeout": 60000,
        })
    }

    #[test]
    fn prepares_vaultwarden_request_and_hashes_exact_client_data() {
        let authentication =
            prepare("https://vault.example.com/path/", challenge()).unwrap();
        assert_eq!(authentication.args.relying_party_id, "vault.example.com");
        assert_eq!(authentication.args.allow_list[0].id, [5, 6, 7]);
        assert_eq!(
            authentication.args.user_verification_req,
            UserVerificationRequirement::Discouraged
        );
        assert!(authentication.args.user_presence_req);
        let data: serde_json::Value =
            serde_json::from_slice(&authentication.client_data).unwrap();
        assert_eq!(
            data,
            json!({
                "type": "webauthn.get", "challenge": "AQIDBA",
                "origin": "https://vault.example.com", "crossOrigin": false,
            })
        );
        let hash: [u8; 32] =
            sha2::Sha256::digest(&authentication.client_data).into();
        assert_eq!(authentication.args.client_data_hash, hash);
    }

    #[test]
    fn rejects_untrusted_origins_and_appids_before_accessing_token() {
        for url in [
            "http://vault.example.com",
            "https://evil.example",
            "file:///tmp/vault",
            "https://127.0.0.1",
        ] {
            assert!(prepare(url, challenge()).is_err(), "{url}");
        }
        for rp_id in [
            "example.com",
            "com",
            "evil.example",
            "vault.example.com.evil.example",
        ] {
            let mut request = challenge();
            request["rpId"] = rp_id.into();
            assert!(
                prepare("https://vault.example.com", request).is_err(),
                "{rp_id}"
            );
        }
        let mut request = challenge();
        request["extensions"]["appid"] =
            "https://evil.example/app-id.json".into();
        assert!(prepare("https://vault.example.com", request).is_err());
    }

    #[test]
    fn preserves_required_verification_and_bounds_timeout() {
        let mut request = challenge();
        request["userVerification"] = "required".into();
        request["timeout"] = u64::MAX.into();
        let authentication =
            prepare("https://vault.example.com", request).unwrap();
        assert_eq!(
            authentication.args.user_verification_req,
            UserVerificationRequirement::Required
        );
        assert_eq!(authentication.timeout.as_secs(), 120);
    }

    #[test]
    fn rejects_malformed_or_discoverable_requests() {
        for (key, value) in [
            ("challenge", json!("!invalid!")),
            ("challenge", json!("")),
            ("allowCredentials", json!([])),
            (
                "allowCredentials",
                json!([{"type": "public-key", "id": ""}]),
            ),
            (
                "allowCredentials",
                json!([{"type": "password", "id": "AQID"}]),
            ),
            ("userVerification", json!("ignore")),
        ] {
            let mut request = challenge();
            request[key] = value;
            assert!(
                prepare("https://vault.example.com", request).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn supports_padded_base64_and_default_rp_id() {
        let mut request = challenge();
        request["challenge"] = "AQIDBA==".into();
        request.as_object_mut().unwrap().remove("rpId");
        request["extensions"] = json!({});
        let authentication =
            prepare("https://vault.example.com:8443/path", request).unwrap();
        let data: serde_json::Value =
            serde_json::from_slice(&authentication.client_data).unwrap();
        assert_eq!(data["challenge"], "AQIDBA");
        assert_eq!(data["origin"], "https://vault.example.com:8443");
    }

    fn result() -> authenticator::SignResult {
        use authenticator::ctap2::{
            attestation::{
                AuthenticatorData, AuthenticatorDataFlags, Extension,
            },
            commands::get_assertion::{Assertion, GetAssertionResult},
            server::{
                AuthenticationExtensionsClientOutputs,
                AuthenticatorAttachment, RpIdHash,
            },
        };
        GetAssertionResult {
            assertion: Assertion {
                credentials: None,
                auth_data: AuthenticatorData {
                    rp_id_hash: RpIdHash::from(&[0; 32][..]).unwrap(),
                    flags: AuthenticatorDataFlags::USER_PRESENT,
                    counter: 1,
                    credential_data: None,
                    extensions: Extension::default(),
                },
                signature: vec![8, 9, 10],
                user: None,
            },
            attachment: AuthenticatorAttachment::CrossPlatform,
            extensions: AuthenticationExtensionsClientOutputs {
                app_id: Some(true),
                ..Default::default()
            },
        }
    }

    #[test]
    fn serializes_assertion_in_vaultwarden_wire_format() {
        let authentication =
            prepare("https://vault.example.com", challenge()).unwrap();
        let token: serde_json::Value = serde_json::from_str(
            &assertion_token(result(), &authentication).unwrap(),
        )
        .unwrap();
        assert_eq!(token["id"], "BQYH");
        assert_eq!(token["rawId"], token["id"]);
        assert_eq!(token["type"], "public-key");
        assert_eq!(token["response"]["signature"], "CAkK");
        assert_eq!(token["extensions"], json!({"appid": true}));
        assert!(token["response"]["userHandle"].is_null());
        assert_eq!(
            decode(token["response"]["clientDataJson"].as_str().unwrap())
                .unwrap(),
            authentication.client_data
        );
        let auth_data =
            decode(token["response"]["authenticatorData"].as_str().unwrap())
                .unwrap();
        assert_eq!(auth_data.len(), 37);
        assert_eq!(&auth_data[32..], &[1, 0, 0, 0, 1]);
    }

    #[test]
    fn rejects_unknown_or_ambiguous_credentials() {
        let mut authentication =
            prepare("https://vault.example.com", challenge()).unwrap();
        let mut unknown = result();
        unknown.assertion.credentials = Some(PublicKeyCredentialDescriptor {
            id: vec![99],
            transports: vec![],
        });
        assert!(assertion_token(unknown, &authentication).is_err());
        authentication
            .args
            .allow_list
            .push(PublicKeyCredentialDescriptor {
                id: vec![99],
                transports: vec![],
            });
        assert!(assertion_token(result(), &authentication).is_err());
    }
}
