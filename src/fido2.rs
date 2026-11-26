use crate::prelude::*;

use sha2::Digest as _;
use zeroize::Zeroize as _;

pub const fn is_supported() -> bool {
    cfg!(feature = "fido2")
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UvPolicy {
    Discouraged,
    Preferred,
    Required,
}

impl UvPolicy {
    pub fn from_webauthn_str(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_lowercase).as_deref() {
            Some("required") => Self::Required,
            Some("preferred") => Self::Preferred,
            _ => Self::Discouraged,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub product_string: String,
    pub aaguid: String,
    pub supports_hmac_secret: bool,
    pub has_client_pin: bool,
    pub has_builtin_uv: bool,
    pub always_uv: bool,
    pub supports_rk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinDecision {
    NoPinNeeded,
    UseBuiltinUv,
    PromptPin { product_string: String },
    PinNotSet,
}

pub fn decide_uv_for_device(
    info: &DeviceInfo,
    policy: UvPolicy,
) -> PinDecision {
    let effective = if info.always_uv {
        UvPolicy::Required
    } else {
        policy
    };

    match effective {
        UvPolicy::Required => {
            if info.has_builtin_uv {
                PinDecision::UseBuiltinUv
            } else if info.has_client_pin {
                PinDecision::PromptPin {
                    product_string: info.product_string.clone(),
                }
            } else {
                PinDecision::PinNotSet
            }
        }
        UvPolicy::Preferred => {
            if info.has_builtin_uv {
                PinDecision::UseBuiltinUv
            } else if info.has_client_pin {
                PinDecision::PromptPin {
                    product_string: info.product_string.clone(),
                }
            } else {
                PinDecision::NoPinNeeded
            }
        }
        UvPolicy::Discouraged => PinDecision::NoPinNeeded,
    }
}

pub fn webauthn_origin_from_ui_url(ui_url: &str) -> Result<String> {
    let parsed = url::Url::parse(ui_url).map_err(|e| Error::Fido2 {
        message: format!("failed to parse ui_url '{ui_url}': {e}"),
    })?;
    let origin = parsed.origin();
    if !origin.is_tuple() {
        return Err(Error::Fido2 {
            message: format!("ui_url '{ui_url}' does not have a valid origin"),
        });
    }
    Ok(origin.ascii_serialization())
}

pub fn rp_id_from_ui_url(ui_url: &str) -> Result<String> {
    let parsed = url::Url::parse(ui_url).map_err(|e| Error::Fido2 {
        message: format!("failed to parse ui_url '{ui_url}': {e}"),
    })?;
    parsed
        .host_str()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| Error::Fido2 {
            message: format!("ui_url '{ui_url}' does not contain a host"),
        })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectedClientData<'a> {
    #[serde(rename = "type")]
    ty: &'static str,
    challenge: &'a str,
    origin: &'a str,
    cross_origin: bool,
}

pub fn build_client_data_json(challenge: &str, origin: &str) -> String {
    let data = CollectedClientData {
        ty: "webauthn.get",
        challenge,
        origin,
        cross_origin: false,
    };
    // Serializing a flat struct of &str and bool cannot fail.
    serde_json::to_string(&data).unwrap()
}

/// Computes the exact 32-byte CTAP2 `hmac-secret` salt for Bitwarden's
/// passwordless passkey login (WebAuthn PRF).
///
/// Bitwarden client passes `SHA-256("passwordless-login")` as
/// `extensions.prf.eval.first`, and W3C WebAuthn Level 3 maps PRF inputs to
/// CTAP2 `hmac-secret` as `SHA-256("WebAuthn PRF\x00" || prfInput)`.
pub fn bitwarden_webauthn_prf_ctap2_salt() -> [u8; 32] {
    let prf_input = sha2::Sha256::digest(b"passwordless-login");
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"WebAuthn PRF\x00");
    hasher.update(prf_input);
    hasher.finalize().into()
}

#[derive(serde::Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct WebAuthnClientExtensionOutputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appid: Option<bool>,
}

#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnAssertionResponseData {
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// Serializes identically to what both Bitwarden (`Fido2NetLib`) and
/// Vaultwarden (`webauthn-rs` `PublicKeyCredentialCopy`) expect.
///
/// SECURITY: `extensions` MUST NEVER contain PRF / `hmac-secret` outputs.
#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnAssertionPayload {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub response: WebAuthnAssertionResponseData,
    pub extensions: WebAuthnClientExtensionOutputs,
}

pub fn build_assertion_payload(
    credential_id: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    user_handle: Option<&[u8]>,
    used_appid: bool,
) -> WebAuthnAssertionPayload {
    let id = crate::base64::encode_url_safe_no_pad(credential_id);
    WebAuthnAssertionPayload {
        id: id.clone(),
        raw_id: id,
        ty: "public-key",
        response: WebAuthnAssertionResponseData {
            authenticator_data: crate::base64::encode_url_safe_no_pad(
                authenticator_data,
            ),
            client_data_json: crate::base64::encode_url_safe_no_pad(
                client_data_json,
            ),
            signature: crate::base64::encode_url_safe_no_pad(signature),
            user_handle: user_handle
                .filter(|h| !h.is_empty())
                .map(crate::base64::encode_url_safe_no_pad),
        },
        extensions: WebAuthnClientExtensionOutputs {
            appid: used_appid.then_some(true),
        },
    }
}

#[derive(Debug, Clone)]
pub struct CreatedHmacCredential {
    pub credential_id: Vec<u8>,
    pub aaguid: String,
    pub product_string: String,
    pub uv: bool,
}

#[derive(Debug)]
pub struct PasskeyAssertionResult {
    pub payload_json: String,
    pub credential_id: String,
    pub user_handle: Vec<u8>,
    pub prf_output: Option<[u8; 32]>,
}

impl Drop for PasskeyAssertionResult {
    fn drop(&mut self) {
        if let Some(ref mut prf) = self.prf_output {
            prf.zeroize();
        }
    }
}

#[derive(Debug)]
pub struct HmacSecretResult {
    pub credential_id: Vec<u8>,
    pub secret: [u8; 32],
}

impl Drop for HmacSecretResult {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[cfg(feature = "fido2")]
mod transport {
    use crate::prelude::*;

    use ctap_hid_fido2::{
        FidoKeyHid, FidoKeyHidFactory, HidInfo, LibCfg,
        fidokey::{
            get_assertion::{
                Extension as GetExtension, GetAssertionArgsBuilder,
            },
            make_credential::{
                Extension as MakeExtension, MakeCredentialArgsBuilder,
            },
        },
        public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    };
    use rand::Rng as _;
    use zeroize::Zeroize as _;

    use super::{
        CreatedHmacCredential, DeviceInfo, HmacSecretResult,
        PasskeyAssertionResult, PinDecision, UvPolicy,
        bitwarden_webauthn_prf_ctap2_salt, build_assertion_payload,
        build_client_data_json, decide_uv_for_device,
    };

    fn lib_cfg() -> LibCfg {
        let mut cfg = LibCfg::init();
        cfg.enable_log = false;
        cfg.enable_keep_alive_msg = false;
        cfg
    }

    fn list_devices() -> Vec<HidInfo> {
        std::panic::catch_unwind(ctap_hid_fido2::get_fidokey_devices)
            .unwrap_or_default()
    }

    fn open_device(dev: &HidInfo) -> Result<(FidoKeyHid, DeviceInfo)> {
        let cfg = lib_cfg();
        let mut key = FidoKeyHidFactory::create_by_params(
            std::slice::from_ref(&dev.param),
            &cfg,
        )
        .map_err(|e| Error::Fido2 {
            message: format!("failed to open security key: {e}"),
        })?;
        // Upgrade to PIN/UV Auth Protocol 2 if supported by the authenticator.
        let _ = key.set_pin_uv_auth_protocol_two();
        let info = read_device_info(&key, &dev.product_string)?;
        Ok((key, info))
    }

    fn read_device_info(
        key: &FidoKeyHid,
        product_string: &str,
    ) -> Result<DeviceInfo> {
        let info = key.get_info().map_err(|e| Error::Fido2 {
            message: format!("failed to query security key capabilities: {e}"),
        })?;

        let option_is_true = |name: &str| {
            info.options
                .iter()
                .find(|(k, _)| k == name)
                .is_some_and(|(_, v)| *v)
        };

        let aaguid = info
            .aaguid
            .iter()
            .fold(String::with_capacity(32), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            });

        Ok(DeviceInfo {
            product_string: if product_string.is_empty() {
                "FIDO2 Security Key".to_string()
            } else {
                product_string.to_string()
            },
            aaguid,
            supports_hmac_secret: info
                .extensions
                .iter()
                .any(|ext| ext == "hmac-secret"),
            has_client_pin: option_is_true("clientPin"),
            has_builtin_uv: option_is_true("uv"),
            always_uv: option_is_true("alwaysUv"),
            supports_rk: option_is_true("rk"),
        })
    }

    fn is_no_credentials_err(err: &anyhow::Error) -> bool {
        let msg = err.to_string();
        msg.contains("CTAP2_ERR_NO_CREDENTIALS") || msg.contains("0x2E")
    }

    fn is_uv_retryable_err(err: &anyhow::Error) -> bool {
        let msg = err.to_string();
        msg.contains("CTAP2_ERR_UV_INVALID")
            || msg.contains("CTAP2_ERR_UV_BLOCKED")
            || msg.contains("CTAP2_ERR_UNSUPPORTED_OPTION")
    }

    fn classify_ctap_error(key: &FidoKeyHid, err: &anyhow::Error) -> Error {
        let msg = err.to_string();
        if msg.contains("CTAP2_ERR_PIN_INVALID")
            || msg.contains("CTAP2_ERR_PIN_AUTH_INVALID")
        {
            let retries = key.get_pin_retries().ok();
            return Error::Fido2PinInvalid { retries };
        }
        if msg.contains("CTAP2_ERR_PIN_BLOCKED")
            || msg.contains("CTAP2_ERR_PIN_AUTH_BLOCKED")
        {
            return Error::Fido2PinBlocked;
        }
        if msg.contains("CTAP2_ERR_PIN_REQUIRED")
            || msg.contains("CTAP2_ERR_PIN_NOT_SET")
        {
            return Error::Fido2PinRequired;
        }
        if msg.contains("CTAP2_ERR_KEEPALIVE_CANCEL")
            || msg.contains("CTAP2_ERR_USER_ACTION_TIMEOUT")
            || msg.contains("CTAP2_ERR_ACTION_TIMEOUT")
        {
            return Error::Fido2Cancelled;
        }
        Error::Fido2 { message: msg }
    }

    fn silent_probe_device(
        key: &FidoKeyHid,
        rp_id: &str,
        credential_ids: &[Vec<u8>],
    ) -> bool {
        if credential_ids.is_empty() {
            return true;
        }
        let dummy = [0_u8; 32];
        let mut builder = GetAssertionArgsBuilder::new(rp_id, &dummy)
            .without_up()
            .without_pin_and_uv();
        for cred_id in credential_ids {
            builder = builder.add_credential_id(cred_id);
        }
        let args = builder.build();
        match key.get_assertion_with_args(&args) {
            Ok(_) => true,
            Err(e) => !is_no_credentials_err(&e),
        }
    }

    fn select_device(
        rp_id: Option<&str>,
        allow_credentials: &[Vec<u8>],
        require_hmac_secret: bool,
        require_rk: bool,
    ) -> Result<(FidoKeyHid, DeviceInfo)> {
        let devs = list_devices();
        if devs.is_empty() {
            return Err(Error::Fido2NoDevice);
        }

        if devs.len() == 1 {
            let (key, info) = open_device(&devs[0])?;
            if require_hmac_secret && !info.supports_hmac_secret {
                return Err(Error::Fido2Unsupported {
                    message: format!(
                        "{} does not support the hmac-secret extension",
                        info.product_string
                    ),
                });
            }
            if require_rk && !info.supports_rk {
                return Err(Error::Fido2Unsupported {
                    message: format!(
                        "{} does not support discoverable credentials (passkeys)",
                        info.product_string
                    ),
                });
            }
            return Ok((key, info));
        }

        let mut candidates = Vec::new();
        for dev in &devs {
            let Ok((key, info)) = open_device(dev) else {
                continue;
            };
            if require_hmac_secret && !info.supports_hmac_secret {
                continue;
            }
            if require_rk && !info.supports_rk {
                continue;
            }
            if let Some(rp_id) = rp_id
                && !allow_credentials.is_empty()
                && silent_probe_device(&key, rp_id, allow_credentials)
            {
                return Ok((key, info));
            }
            candidates.push((key, info));
        }

        candidates.into_iter().next().ok_or(Error::Fido2NoDevice)
    }

    pub fn has_connected_device() -> bool {
        !list_devices().is_empty()
    }

    pub fn has_matching_credential(
        rp_id: &str,
        credential_ids: &[Vec<u8>],
    ) -> bool {
        let devs = list_devices();
        if devs.is_empty() || credential_ids.is_empty() {
            return false;
        }
        for dev in &devs {
            if let Ok((key, _)) = open_device(dev)
                && silent_probe_device(&key, rp_id, credential_ids)
            {
                return true;
            }
        }
        false
    }

    pub fn inspect_device(
        rp_id: Option<&str>,
        allow_credentials: &[Vec<u8>],
        require_hmac_secret: bool,
        require_rk: bool,
    ) -> Result<DeviceInfo> {
        let (_, info) = select_device(
            rp_id,
            allow_credentials,
            require_hmac_secret,
            require_rk,
        )?;
        Ok(info)
    }

    pub fn make_hmac_secret_credential(
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        uv_policy: UvPolicy,
        pin: Option<&str>,
    ) -> Result<CreatedHmacCredential> {
        let (key, info) = select_device(None, &[], true, false)?;

        let mut challenge = [0_u8; 32];
        rand::rng().fill_bytes(&mut challenge);

        let user_entity = PublicKeyCredentialUserEntity::new(
            Some(user_id),
            Some(user_name),
            Some(user_name),
        );
        let extensions = [MakeExtension::HmacSecret(Some(true))];

        let decision = decide_uv_for_device(&info, uv_policy);
        let mut builder = MakeCredentialArgsBuilder::new(rp_id, &challenge)
            .user_entity(&user_entity)
            .extensions(&extensions);

        let used_uv = match (pin, decision) {
            (Some(pin), _) => {
                builder = builder.pin(pin);
                true
            }
            (None, PinDecision::UseBuiltinUv) => true,
            (None, PinDecision::NoPinNeeded) => {
                builder = builder.without_pin_and_uv();
                false
            }
            (None, PinDecision::PromptPin { .. } | PinDecision::PinNotSet) => {
                return Err(Error::Fido2PinRequired);
            }
        };

        let args = builder.build();
        let attestation =
            key.make_credential_with_args(&args).map_err(|e| {
                if pin.is_none()
                    && info.has_builtin_uv
                    && info.has_client_pin
                    && is_uv_retryable_err(&e)
                {
                    Error::Fido2PinRequired
                } else {
                    classify_ctap_error(&key, &e)
                }
            })?;

        let hmac_enabled = attestation.extensions.iter().any(|ext| {
            matches!(ext, MakeExtension::HmacSecret(Some(true)))
        });
        if !hmac_enabled {
            return Err(Error::Fido2Unsupported {
                message: format!(
                    "{} did not enable hmac-secret on the new credential",
                    info.product_string
                ),
            });
        }

        if attestation.credential_descriptor.id.is_empty() {
            return Err(Error::Fido2 {
                message: "authenticator returned an empty credential ID"
                    .to_string(),
            });
        }

        Ok(CreatedHmacCredential {
            credential_id: attestation.credential_descriptor.id,
            aaguid: info.aaguid,
            product_string: info.product_string,
            uv: used_uv,
        })
    }

    fn extract_hmac_secret(extensions: &[GetExtension]) -> Option<[u8; 32]> {
        for ext in extensions {
            match ext {
                GetExtension::HmacSecret(Some(secret)) => return Some(*secret),
                GetExtension::HmacSecret2(Some((secret1, _))) => {
                    return Some(*secret1);
                }
                _ => {}
            }
        }
        None
    }

    pub fn get_hmac_secret(
        rp_id: &str,
        credential_ids: &[Vec<u8>],
        salt: &[u8; 32],
        uv: bool,
        pin: Option<&str>,
    ) -> Result<HmacSecretResult> {
        let (key, info) =
            select_device(Some(rp_id), credential_ids, true, false)?;

        let mut challenge = [0_u8; 32];
        rand::rng().fill_bytes(&mut challenge);
        let extensions = [GetExtension::HmacSecret(Some(*salt))];

        let mut builder = GetAssertionArgsBuilder::new(rp_id, &challenge)
            .extensions(&extensions);
        for cred_id in credential_ids {
            builder = builder.add_credential_id(cred_id);
        }

        if uv || info.always_uv {
            if let Some(pin) = pin {
                builder = builder.pin(pin);
            } else if !info.has_builtin_uv {
                return Err(Error::Fido2PinRequired);
            }
        } else {
            builder = builder.without_pin_and_uv();
        }

        let args = builder.build();
        let assertions = key.get_assertion_with_args(&args).map_err(|e| {
            if pin.is_none()
                && info.has_builtin_uv
                && info.has_client_pin
                && is_uv_retryable_err(&e)
            {
                Error::Fido2PinRequired
            } else {
                classify_ctap_error(&key, &e)
            }
        })?;

        let assertion = assertions.first().ok_or_else(|| Error::Fido2 {
            message: "authenticator returned no assertions".to_string(),
        })?;

        let secret =
            extract_hmac_secret(&assertion.extensions).ok_or_else(|| {
                Error::Fido2 {
                    message:
                        "authenticator did not return an hmac-secret output"
                            .to_string(),
                }
            })?;

        let credential_id = if assertion.credential_id.is_empty()
            && credential_ids.len() == 1
        {
            credential_ids[0].clone()
        } else {
            assertion.credential_id.clone()
        };

        Ok(HmacSecretResult {
            credential_id,
            secret,
        })
    }

    fn apply_uv_to_builder<'a>(
        mut builder: GetAssertionArgsBuilder<'a>,
        info: &DeviceInfo,
        uv_policy: UvPolicy,
        pin: Option<&'a str>,
    ) -> Result<GetAssertionArgsBuilder<'a>> {
        if let Some(pin) = pin {
            builder = builder.pin(pin);
            return Ok(builder);
        }

        match decide_uv_for_device(info, uv_policy) {
            PinDecision::NoPinNeeded => {
                builder = builder.without_pin_and_uv();
                Ok(builder)
            }
            PinDecision::UseBuiltinUv => Ok(builder),
            PinDecision::PromptPin { .. } | PinDecision::PinNotSet => {
                Err(Error::Fido2PinRequired)
            }
        }
    }

    pub fn assert_webauthn_2fa(
        rp_id: &str,
        origin: &str,
        challenge: &str,
        allow_credentials: &[Vec<u8>],
        appid: Option<&str>,
        uv_policy: UvPolicy,
        pin: Option<&str>,
    ) -> Result<String> {
        enum AttemptErr {
            NoCredentials(anyhow::Error),
            Ctap(anyhow::Error),
            App(Error),
        }

        let (key, info) =
            select_device(Some(rp_id), allow_credentials, false, false)?;
        let client_data_json = build_client_data_json(challenge, origin);

        let run_once = |effective_rp_id: &str| {
            let mut builder = GetAssertionArgsBuilder::new(
                effective_rp_id,
                client_data_json.as_bytes(),
            );
            for cred_id in allow_credentials {
                builder = builder.add_credential_id(cred_id);
            }
            let builder = apply_uv_to_builder(builder, &info, uv_policy, pin)
                .map_err(AttemptErr::App)?;
            let args = builder.build();
            key.get_assertion_with_args(&args).map_err(|e| {
                if is_no_credentials_err(&e) {
                    AttemptErr::NoCredentials(e)
                } else {
                    AttemptErr::Ctap(e)
                }
            })
        };

        let (assertions, used_appid) = match run_once(rp_id) {
            Ok(assertions) => (assertions, false),
            Err(AttemptErr::NoCredentials(_)) if appid.is_some() => {
                let app_id = appid.unwrap();
                match run_once(app_id) {
                    Ok(assertions) => (assertions, true),
                    Err(AttemptErr::App(err)) => return Err(err),
                    Err(
                        AttemptErr::NoCredentials(err) | AttemptErr::Ctap(err),
                    ) => {
                        return Err(classify_ctap_error(&key, &err));
                    }
                }
            }
            Err(AttemptErr::App(err)) => return Err(err),
            Err(AttemptErr::NoCredentials(err) | AttemptErr::Ctap(err)) => {
                if pin.is_none()
                    && info.has_builtin_uv
                    && info.has_client_pin
                    && is_uv_retryable_err(&err)
                {
                    return Err(Error::Fido2PinRequired);
                }
                return Err(classify_ctap_error(&key, &err));
            }
        };

        let assertion = assertions.first().ok_or_else(|| Error::Fido2 {
            message: "authenticator returned no assertions".to_string(),
        })?;

        let cred_id = if assertion.credential_id.is_empty()
            && allow_credentials.len() == 1
        {
            allow_credentials[0].as_slice()
        } else {
            assertion.credential_id.as_slice()
        };

        if cred_id.is_empty() {
            return Err(Error::Fido2 {
                message: "authenticator returned an empty credential ID"
                    .to_string(),
            });
        }

        let user_handle = (!assertion.user.id.is_empty())
            .then_some(assertion.user.id.as_slice());

        let payload = build_assertion_payload(
            cred_id,
            &assertion.auth_data,
            client_data_json.as_bytes(),
            &assertion.signature,
            user_handle,
            used_appid,
        );

        serde_json::to_string(&payload).map_err(|e| Error::Fido2 {
            message: format!("failed to serialize WebAuthn assertion: {e}"),
        })
    }

    pub fn assert_passkey_login(
        rp_id: &str,
        origin: &str,
        challenge: &str,
        preferred_email: Option<&str>,
        pin: Option<&str>,
    ) -> Result<PasskeyAssertionResult> {
        let (key, info) = select_device(None, &[], false, true)?;
        let client_data_json = build_client_data_json(challenge, origin);

        let mut prf_salt = bitwarden_webauthn_prf_ctap2_salt();
        let extensions = if info.supports_hmac_secret {
            Some(vec![GetExtension::HmacSecret(Some(prf_salt))])
        } else {
            None
        };

        let mut builder = GetAssertionArgsBuilder::new(
            rp_id,
            client_data_json.as_bytes(),
        );
        if let Some(ref exts) = extensions {
            builder = builder.extensions(exts);
        }
        let builder =
            apply_uv_to_builder(builder, &info, UvPolicy::Required, pin)?;
        let args = builder.build();

        let assertions = match key.get_assertion_with_args(&args) {
            Ok(assertions) => assertions,
            Err(err) => {
                prf_salt.zeroize();
                if pin.is_none()
                    && info.has_builtin_uv
                    && info.has_client_pin
                    && is_uv_retryable_err(&err)
                {
                    return Err(Error::Fido2PinRequired);
                }
                return Err(classify_ctap_error(&key, &err));
            }
        };

        if assertions.is_empty() {
            prf_salt.zeroize();
            return Err(Error::Fido2 {
                message: format!(
                    "no Bitwarden passkey credentials found on {} for '{rp_id}'",
                    info.product_string
                ),
            });
        }

        let selected_idx = preferred_email
            .and_then(|email| {
                let target = email.trim().to_ascii_lowercase();
                assertions.iter().position(|a| {
                    a.user.name.trim().to_ascii_lowercase() == target
                })
            })
            .unwrap_or(0);

        let mut chosen = assertions[selected_idx].clone();
        let mut prf_output = extract_hmac_secret(&chosen.extensions);

        // `ctap-hid-fido2`'s `get_next_assertion` does not decrypt
        // `hmac-secret` for index > 0. If the matching account was not the
        // first resident credential, re-assert targeting that credential ID
        // so we get the decrypted PRF secret as well.
        if selected_idx > 0
            && info.supports_hmac_secret
            && prf_output.is_none()
            && !chosen.credential_id.is_empty()
        {
            let exts = [GetExtension::HmacSecret(Some(prf_salt))];
            let mut targeted = GetAssertionArgsBuilder::new(
                rp_id,
                client_data_json.as_bytes(),
            )
            .credential_id(&chosen.credential_id)
            .extensions(&exts);
            targeted =
                apply_uv_to_builder(targeted, &info, UvPolicy::Required, pin)?;
            let targeted_args = targeted.build();
            if let Ok(mut targeted_assertions) =
                key.get_assertion_with_args(&targeted_args)
                && let Some(first) = targeted_assertions.pop()
            {
                prf_output = extract_hmac_secret(&first.extensions);
                let orig_cred_id = chosen.credential_id.clone();
                let orig_user = chosen.user.clone();
                chosen = first;
                if chosen.credential_id.is_empty() {
                    chosen.credential_id = orig_cred_id;
                }
                if chosen.user.id.is_empty() {
                    chosen.user = orig_user;
                }
            }
        }

        prf_salt.zeroize();

        if chosen.credential_id.is_empty() {
            return Err(Error::Fido2 {
                message: "authenticator returned an empty credential ID"
                    .to_string(),
            });
        }

        if chosen.user.id.is_empty() {
            return Err(Error::Fido2 {
                message: "passkey credential did not return a userHandle"
                    .to_string(),
            });
        }

        // SECURITY: `used_appid` is false and `extensions` stays `{}` so PRF
        // material is never sent to the server.
        let payload = build_assertion_payload(
            &chosen.credential_id,
            &chosen.auth_data,
            client_data_json.as_bytes(),
            &chosen.signature,
            Some(&chosen.user.id),
            false,
        );
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| Error::Fido2 {
                message: format!(
                    "failed to serialize WebAuthn assertion: {e}"
                ),
            })?;

        Ok(PasskeyAssertionResult {
            payload_json,
            credential_id: payload.id,
            user_handle: chosen.user.id,
            prf_output,
        })
    }

    pub fn eval_bitwarden_prf(
        rp_id: &str,
        credential_id: &[u8],
        pin: Option<&str>,
    ) -> Result<[u8; 32]> {
        let mut salt = bitwarden_webauthn_prf_ctap2_salt();
        let res = get_hmac_secret(
            rp_id,
            std::slice::from_ref(&credential_id.to_vec()),
            &salt,
            true,
            pin,
        );
        salt.zeroize();
        res.map(|r| r.secret)
    }
}

#[cfg(not(feature = "fido2"))]
mod transport {
    use crate::prelude::*;

    use super::{
        CreatedHmacCredential, DeviceInfo, HmacSecretResult,
        PasskeyAssertionResult, UvPolicy,
    };

    fn unsupported() -> Error {
        Error::Fido2Unsupported {
            message: "rbw was compiled without the `fido2` feature".to_string(),
        }
    }

    pub fn has_connected_device() -> bool {
        false
    }

    pub fn has_matching_credential(
        _rp_id: &str,
        _credential_ids: &[Vec<u8>],
    ) -> bool {
        false
    }

    pub fn inspect_device(
        _rp_id: Option<&str>,
        _allow_credentials: &[Vec<u8>],
        _require_hmac_secret: bool,
        _require_rk: bool,
    ) -> Result<DeviceInfo> {
        Err(unsupported())
    }

    pub fn make_hmac_secret_credential(
        _rp_id: &str,
        _user_id: &[u8],
        _user_name: &str,
        _uv_policy: UvPolicy,
        _pin: Option<&str>,
    ) -> Result<CreatedHmacCredential> {
        Err(unsupported())
    }

    pub fn get_hmac_secret(
        _rp_id: &str,
        _credential_ids: &[Vec<u8>],
        _salt: &[u8; 32],
        _uv: bool,
        _pin: Option<&str>,
    ) -> Result<HmacSecretResult> {
        Err(unsupported())
    }

    pub fn assert_webauthn_2fa(
        _rp_id: &str,
        _origin: &str,
        _challenge: &str,
        _allow_credentials: &[Vec<u8>],
        _appid: Option<&str>,
        _uv_policy: UvPolicy,
        _pin: Option<&str>,
    ) -> Result<String> {
        Err(unsupported())
    }

    pub fn assert_passkey_login(
        _rp_id: &str,
        _origin: &str,
        _challenge: &str,
        _preferred_email: Option<&str>,
        _pin: Option<&str>,
    ) -> Result<PasskeyAssertionResult> {
        Err(unsupported())
    }

    pub fn eval_bitwarden_prf(
        _rp_id: &str,
        _credential_id: &[u8],
        _pin: Option<&str>,
    ) -> Result<[u8; 32]> {
        Err(unsupported())
    }
}

pub fn has_connected_device() -> bool {
    transport::has_connected_device()
}

pub fn has_matching_credential(
    rp_id: &str,
    credential_ids: &[Vec<u8>],
) -> bool {
    transport::has_matching_credential(rp_id, credential_ids)
}

pub fn inspect_device(
    rp_id: Option<&str>,
    allow_credentials: &[Vec<u8>],
    require_hmac_secret: bool,
    require_rk: bool,
) -> Result<DeviceInfo> {
    transport::inspect_device(
        rp_id,
        allow_credentials,
        require_hmac_secret,
        require_rk,
    )
}

pub fn make_hmac_secret_credential(
    rp_id: &str,
    user_id: &[u8],
    user_name: &str,
    uv_policy: UvPolicy,
    pin: Option<&str>,
) -> Result<CreatedHmacCredential> {
    transport::make_hmac_secret_credential(
        rp_id, user_id, user_name, uv_policy, pin,
    )
}

pub fn get_hmac_secret(
    rp_id: &str,
    credential_ids: &[Vec<u8>],
    salt: &[u8; 32],
    uv: bool,
    pin: Option<&str>,
) -> Result<HmacSecretResult> {
    transport::get_hmac_secret(rp_id, credential_ids, salt, uv, pin)
}

pub fn assert_webauthn_2fa(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    allow_credentials: &[Vec<u8>],
    appid: Option<&str>,
    uv_policy: UvPolicy,
    pin: Option<&str>,
) -> Result<String> {
    transport::assert_webauthn_2fa(
        rp_id,
        origin,
        challenge,
        allow_credentials,
        appid,
        uv_policy,
        pin,
    )
}

pub fn assert_passkey_login(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    preferred_email: Option<&str>,
    pin: Option<&str>,
) -> Result<PasskeyAssertionResult> {
    transport::assert_passkey_login(
        rp_id,
        origin,
        challenge,
        preferred_email,
        pin,
    )
}

pub fn eval_bitwarden_prf(
    rp_id: &str,
    credential_id: &[u8],
    pin: Option<&str>,
) -> Result<[u8; 32]> {
    transport::eval_bitwarden_prf(rp_id, credential_id, pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_origin_and_rp_id_from_ui_url() {
        assert_eq!(
            webauthn_origin_from_ui_url("https://vault.bitwarden.com")
                .unwrap(),
            "https://vault.bitwarden.com"
        );
        assert_eq!(
            webauthn_origin_from_ui_url("https://vault.bitwarden.eu/")
                .unwrap(),
            "https://vault.bitwarden.eu"
        );
        assert_eq!(
            webauthn_origin_from_ui_url(
                "https://vault.example.com:8443/#/login"
            )
            .unwrap(),
            "https://vault.example.com:8443"
        );
        assert_eq!(
            rp_id_from_ui_url("https://vault.example.com:8443/#/login")
                .unwrap(),
            "vault.example.com"
        );
    }

    #[test]
    fn test_bitwarden_prf_ctap2_salt_spec_vector() {
        // Verify deterministic W3C WebAuthn L3 derivation:
        // SHA-256("WebAuthn PRF\x00" || SHA-256("passwordless-login"))
        let step1 = sha2::Sha256::digest(b"passwordless-login");
        let mut h = sha2::Sha256::new();
        h.update(b"WebAuthn PRF");
        h.update([0x00]);
        h.update(step1);
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(bitwarden_webauthn_prf_ctap2_salt(), expected);
    }

    #[test]
    fn test_build_client_data_json() {
        let json =
            build_client_data_json("abc123", "https://vault.bitwarden.com");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "webauthn.get");
        assert_eq!(parsed["challenge"], "abc123");
        assert_eq!(parsed["origin"], "https://vault.bitwarden.com");
        assert_eq!(parsed["crossOrigin"], false);
    }

    #[test]
    fn test_assertion_payload_format_and_no_prf_leak() {
        let payload = build_assertion_payload(
            b"cred-id",
            b"auth-data",
            br#"{"type":"webauthn.get"}"#,
            b"sig-bytes",
            Some(b"user-handle"),
            false,
        );
        let json = serde_json::to_string(&payload).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(val["type"], "public-key");
        assert_eq!(val["id"], val["rawId"]);
        assert!(val["response"]["clientDataJSON"].is_string());
        assert!(val["response"]["authenticatorData"].is_string());
        assert!(val["response"]["signature"].is_string());
        assert!(val["response"]["userHandle"].is_string());
        assert_eq!(val["extensions"], serde_json::json!({}));
        assert!(!json.contains("prf"));
        assert!(!json.contains("hmac"));

        let appid_payload = build_assertion_payload(
            b"cred-id",
            b"auth-data",
            b"{}",
            b"sig",
            None,
            true,
        );
        let val2 = serde_json::to_value(&appid_payload).unwrap();
        assert!(val2["response"].get("userHandle").is_none());
        assert_eq!(val2["extensions"], serde_json::json!({"appid": true}));
    }

    #[test]
    fn test_decide_uv_for_device() {
        let yubikey_with_pin = DeviceInfo {
            product_string: "YubiKey 5C".to_string(),
            aaguid: "00".repeat(16),
            supports_hmac_secret: true,
            has_client_pin: true,
            has_builtin_uv: false,
            always_uv: false,
            supports_rk: true,
        };
        assert_eq!(
            decide_uv_for_device(&yubikey_with_pin, UvPolicy::Discouraged),
            PinDecision::NoPinNeeded
        );
        assert!(matches!(
            decide_uv_for_device(&yubikey_with_pin, UvPolicy::Preferred),
            PinDecision::PromptPin { .. }
        ));
        assert!(matches!(
            decide_uv_for_device(&yubikey_with_pin, UvPolicy::Required),
            PinDecision::PromptPin { .. }
        ));

        let yubikey_no_pin = DeviceInfo {
            has_client_pin: false,
            ..yubikey_with_pin.clone()
        };
        assert_eq!(
            decide_uv_for_device(&yubikey_no_pin, UvPolicy::Preferred),
            PinDecision::NoPinNeeded
        );
        assert_eq!(
            decide_uv_for_device(&yubikey_no_pin, UvPolicy::Required),
            PinDecision::PinNotSet
        );

        let yubikey_bio = DeviceInfo {
            has_builtin_uv: true,
            always_uv: true,
            ..yubikey_with_pin
        };
        assert_eq!(
            decide_uv_for_device(&yubikey_bio, UvPolicy::Discouraged),
            PinDecision::UseBuiltinUv
        );
    }
}
