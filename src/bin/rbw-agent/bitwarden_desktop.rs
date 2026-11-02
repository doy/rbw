// Client for the Bitwarden desktop app's browser-integration IPC interface.
// This is the same protocol the official browser extension uses for "unlock
// with biometrics": we ask the desktop app to unlock the account, it shows
// the OS biometric prompt, and on success it hands back the account's user
// key.
//
// Upstream calls this message format "legacy" (see LegacyMessageWrapper in
// apps/desktop/src/models/native-messaging in bitwarden/clients), but it is
// the protocol the current browser extension speaks. The message shapes,
// validation, and timeouts here mirror the extension's implementation in
// apps/browser/src/background/nativeMessaging.background.ts.
//
// The protocol is internal to Bitwarden and can change between desktop app
// releases.

use anyhow::Context as _;
use serde::Deserialize as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// the desktop app frames its ipc messages with a 4-byte native-endian
// length prefix (tokio's LengthDelimitedCodec configured as native_endian,
// max frame 1MiB)
const MAX_FRAME_LEN: u32 = 1024 * 1024;

// the browser extension ignores messages whose timestamp deviates more than
// this from the local clock (MessageValidTimeout upstream)
const MESSAGE_VALID_TIMEOUT_MS: u64 = 10 * 1000;

// the browser extension gives up on a request after this long without a
// response (MessageNoResponseTimeout upstream); the os biometric prompt has
// to be answered within this window
const NO_RESPONSE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);

// establishing the encrypted channel requires no user interaction, so it
// should complete quickly
const HANDSHAKE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

fn user_id_from_access_token(access_token: &str) -> anyhow::Result<String> {
    #[derive(serde::Deserialize)]
    struct Claims {
        sub: String,
    }

    let payload = access_token
        .split('.')
        .nth(1)
        .context("access token is not a jwt")?;
    let payload = rbw::base64::decode_url_safe_no_pad(payload)
        .context("failed to decode jwt payload")?;
    let claims: Claims = serde_json::from_slice(&payload)
        .context("failed to parse jwt claims")?;
    Ok(claims.sub)
}

fn now_millis() -> anyhow::Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

// convert a CipherString into the EncStringObj format expected by the
// desktop app (matching the browser extension's serialization)
fn cipherstring_to_enc_obj(
    cs: &rbw::cipherstring::CipherString,
) -> anyhow::Result<EncStringObj> {
    match cs {
        rbw::cipherstring::CipherString::Symmetric {
            iv,
            ciphertext,
            mac,
        } => Ok(EncStringObj {
            encrypted_string: cs.to_string(),
            encryption_type: 2,
            data: rbw::base64::encode(ciphertext),
            iv: rbw::base64::encode(iv),
            mac: mac.as_ref().map(rbw::base64::encode),
        }),
        rbw::cipherstring::CipherString::Asymmetric { .. } => {
            Err(anyhow::anyhow!(
                "asymmetric cipherstring not supported for ipc"
            ))
        }
    }
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> anyhow::Result<()> {
    let len = u32::try_from(data.len()).context("ipc message too large")?;
    if len > MAX_FRAME_LEN {
        return Err(anyhow::anyhow!("ipc message too large ({len} bytes)"));
    }
    stream.write_all(&len.to_ne_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> anyhow::Result<Vec<u8>> {
    let mut len = [0; 4];
    stream.read_exact(&mut len).await?;
    let len = u32::from_ne_bytes(len);
    if len > MAX_FRAME_LEN {
        return Err(anyhow::anyhow!("oversized ipc frame ({len} bytes)"));
    }
    let mut buf = vec![0; usize::try_from(len)?];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[derive(serde::Serialize)]
struct SetupEncryption<'a> {
    command: &'static str,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "userId")]
    user_id: &'a str,
    #[serde(rename = "messageId")]
    message_id: u32,
    timestamp: u64,
}

// encrypted messages are wrapped as { "appId": ..., "message": <EncString> }
// (matching the browser extension's postMessage())
#[derive(serde::Serialize)]
struct EncryptedWrapper<'a> {
    #[serde(rename = "appId")]
    app_id: &'a str,
    message: EncStringObj,
}

// the desktop app expects the encrypted message as an object (matching
// the browser extension's EncString serialization), not a plain string.
// see: apps/browser/src/background/nativeMessaging.background.ts postMessage()
#[derive(serde::Serialize)]
struct EncStringObj {
    #[serde(rename = "encryptedString")]
    encrypted_string: String,
    #[serde(rename = "encryptionType")]
    encryption_type: u8,
    data: String,
    iv: String,
    mac: Option<String>,
}

#[derive(serde::Serialize)]
struct UnlockRequest<'a> {
    command: &'static str,
    #[serde(rename = "userId")]
    user_id: &'a str,
    #[serde(rename = "messageId")]
    message_id: u32,
    timestamp: u64,
}

// the desktop app expects all messages wrapped as
// { "appId": <client uuid>, "message": <inner message> }
#[derive(serde::Serialize)]
struct LegacyMessageWrapper<'a, T> {
    #[serde(rename = "appId")]
    app_id: &'a str,
    message: T,
}

// frames from the app are a mix of plaintext control messages and
// encrypted wrappers; parse leniently and pick out what we need
#[derive(serde::Deserialize)]
struct IncomingFrame {
    command: Option<String>,
    #[serde(rename = "appId")]
    app_id: Option<String>,
    #[serde(rename = "sharedSecret")]
    shared_secret: Option<String>,
    #[serde(default, deserialize_with = "deserialize_enc_string")]
    message: Option<String>,
}

// the desktop app may send the encrypted message as either a plain
// string ("2.iv|ct|mac") or as an EncString object
// ({encryptedString, encryptionType, data, iv, mac}). extract the
// string form either way.
fn deserialize_enc_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(serde_json::Value::Object(obj)) => obj
            .get("encryptedString")
            .and_then(|v| v.as_str())
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "EncString object missing encryptedString field",
                )
            }),
        _ => Err(serde::de::Error::custom(
            "expected message to be a string or EncString object",
        )),
    }
}

#[derive(serde::Deserialize)]
struct UnlockResponse {
    command: Option<String>,
    response: Option<serde_json::Value>,
    #[serde(rename = "messageId")]
    message_id: Option<i64>,
    timestamp: Option<u64>,
    #[serde(rename = "userKeyB64")]
    user_key_b64: Option<String>,
}

// distinguishes "the app answered, but didn't hand out a usable key" (the
// user cancelled the prompt, biometric unlock isn't set up, ...) from a
// broken channel. only the latter is worth retrying on a fresh connection;
// retrying the former would pop up a second biometric prompt.
#[derive(Debug)]
enum UnlockError {
    Refused(String),
    Channel(anyhow::Error),
}

// an established encrypted channel to the desktop app. the browser
// extension keeps its channel alive for the whole browser session so that
// unlock requests don't have to wait for connection + rsa handshake; we get
// the same effect by caching this in the agent state and reusing it.
pub struct Channel<S> {
    stream: S,
    keys: rbw::locked::Keys,
    app_id: String,
    user_id: String,
    next_message_id: u32,
}

pub type DesktopChannel = Channel<tokio::net::UnixStream>;

// establish a channel to the locally running desktop app, with the
// encryption handshake already done
pub async fn connect_channel(
    access_token: &str,
) -> anyhow::Result<DesktopChannel> {
    let user_id = user_id_from_access_token(access_token)?;
    let stream = connect().await?;
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        Channel::handshake(stream, user_id),
    )
    .await
    .context("timed out establishing channel to bitwarden desktop app")?
}

// unlock via the desktop app, reusing a previously established channel when
// possible (this is what makes the biometric prompt appear immediately, and
// matches the browser extension keeping its connection alive). returns the
// channel for reuse if it is still usable.
pub async fn unlock_user_key(
    cached: Option<DesktopChannel>,
    access_token: &str,
) -> (anyhow::Result<rbw::locked::Keys>, Option<DesktopChannel>) {
    let user_id = match user_id_from_access_token(access_token) {
        Ok(user_id) => user_id,
        Err(e) => return (Err(e), None),
    };

    if let Some(mut channel) = cached {
        if channel.user_id == user_id {
            match tokio::time::timeout(NO_RESPONSE_TIMEOUT, channel.unlock())
                .await
            {
                Ok(Ok(keys)) => return (Ok(keys), Some(channel)),
                Ok(Err(UnlockError::Refused(msg))) => {
                    return (Err(anyhow::anyhow!(msg)), Some(channel));
                }
                Ok(Err(UnlockError::Channel(e))) => {
                    log::debug!(
                        "cached bitwarden desktop app channel failed \
                         ({e:#}), reconnecting"
                    );
                }
                Err(_) => {
                    return (
                        Err(anyhow::anyhow!(
                            "timed out waiting for biometric unlock"
                        )),
                        None,
                    );
                }
            }
        }
    }

    let mut channel = match connect_channel(access_token).await {
        Ok(channel) => channel,
        Err(e) => return (Err(e), None),
    };
    match tokio::time::timeout(NO_RESPONSE_TIMEOUT, channel.unlock()).await {
        Ok(Ok(keys)) => (Ok(keys), Some(channel)),
        Ok(Err(UnlockError::Refused(msg))) => {
            (Err(anyhow::anyhow!(msg)), Some(channel))
        }
        Ok(Err(UnlockError::Channel(e))) => (Err(e), None),
        Err(_) => (
            Err(anyhow::anyhow!("timed out waiting for biometric unlock")),
            None,
        ),
    }
}

fn candidate_socket_paths() -> Vec<std::path::PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from)
    else {
        return vec![];
    };
    let mut paths = vec![];
    if cfg!(target_os = "macos") {
        paths.push(home.join(
            "Library/Group Containers/LTZ2PFU5D6.com.bitwarden.desktop/s.bw",
        ));
        // non-sandboxed (e.g. homebrew) desktop app uses the rust cache
        // dir, which is ~/Library/Caches on macos
        paths.push(home.join("Library/Caches/com.bitwarden.desktop/s.bw"));
    }
    paths.push(home.join(".cache/com.bitwarden.desktop/s.bw"));
    // a flatpak-sandboxed desktop app can't use the path above, so it
    // creates its socket inside browser config dirs instead
    for path in [
        ".var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/.app.bw.socket",
        ".var/app/com.google.Chrome/config/google-chrome/NativeMessagingHosts/.app.bw.socket",
        ".var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/.app.bw.socket",
        ".var/app/com.microsoft.Edge/config/microsoft-edge/NativeMessagingHosts/.app.bw.socket",
        ".mozilla/native-messaging-hosts/.app.bw.socket",
        ".config/google-chrome/NativeMessagingHosts/.app.bw.socket",
        ".config/chromium/NativeMessagingHosts/.app.bw.socket",
        ".config/microsoft-edge/NativeMessagingHosts/.app.bw.socket",
    ] {
        paths.push(home.join(path));
    }
    paths
}

async fn connect() -> anyhow::Result<tokio::net::UnixStream> {
    for path in candidate_socket_paths() {
        if let Ok(stream) = tokio::net::UnixStream::connect(&path).await {
            log::debug!(
                "connected to bitwarden desktop app at {}",
                path.display()
            );
            return Ok(stream);
        }
    }
    Err(anyhow::anyhow!(
        "couldn't find the bitwarden desktop app socket (is the app \
         running with browser integration enabled?)"
    ))
}

impl<S> Channel<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // establish the encrypted channel: send an ephemeral rsa public key,
    // get back a 64-byte shared secret encrypted to it
    async fn handshake(
        mut stream: S,
        user_id: String,
    ) -> anyhow::Result<Self> {
        // items before statements, or clippy::items_after_statements fires
        use rsa::pkcs8::EncodePublicKey as _;
        use zeroize::Zeroize as _;

        write_frame(&mut stream, br#"{"clientType":"cli"}"#).await?;

        let mut rng = rand_8::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
            .context("failed to generate rsa key")?;

        let public_key_der = private_key
            .to_public_key()
            .to_public_key_der()
            .context("failed to encode rsa public key")?;

        let app_id = uuid::Uuid::new_v4().hyphenated().to_string();

        let setup_msg = serde_json::to_vec(&LegacyMessageWrapper {
            app_id: &app_id,
            message: SetupEncryption {
                command: "setupEncryption",
                public_key: rbw::base64::encode(public_key_der.as_bytes()),
                user_id: &user_id,
                message_id: 0,
                timestamp: now_millis()?,
            },
        })?;
        write_frame(&mut stream, &setup_msg).await?;
        log::debug!("sent setupEncryption request to bitwarden desktop app");

        let shared_secret = loop {
            let frame = read_frame(&mut stream).await?;
            let msg: IncomingFrame = serde_json::from_slice(&frame)?;
            // the desktop app broadcasts its responses to all connected
            // clients (e.g. a real browser extension running next to us);
            // only look at frames that are actually addressed to us
            if msg.app_id.as_deref() != Some(app_id.as_str()) {
                log::debug!(
                    "skipping ipc message for a different client: {:?}",
                    msg.command
                );
                continue;
            }
            if let Some(shared_secret) = msg.shared_secret {
                break shared_secret;
            }
            if msg.command.as_deref() == Some("wrongUserId") {
                return Err(anyhow::anyhow!(
                    "bitwarden desktop app doesn't recognize this user \
                     id (is the same account logged in in the desktop \
                     app?)"
                ));
            }
            // the app can broadcast unrelated messages at any time
            log::debug!("skipping ipc message: {:?}", msg.command);
        };

        let shared_secret = rbw::base64::decode(&shared_secret)
            .map_err(|e| anyhow::anyhow!("invalid shared secret: {e}"))?;
        let mut shared_secret = private_key
            .decrypt(rsa::Oaep::new::<sha1::Sha1>(), &shared_secret)
            .context("failed to decrypt shared secret")?;
        if shared_secret.len() != 64 {
            let len = shared_secret.len();
            shared_secret.zeroize();
            return Err(anyhow::anyhow!(
                "unexpected shared secret length {len}"
            ));
        }
        let mut secret = rbw::locked::Vec::new();
        secret.extend(shared_secret.iter().copied());
        shared_secret.zeroize();
        log::debug!("secure channel to bitwarden desktop app established");

        Ok(Self {
            stream,
            keys: rbw::locked::Keys::new(secret),
            app_id,
            user_id,
            next_message_id: 1,
        })
    }

    // ask the app to unlock; it shows the os biometric prompt and answers
    // with the account's user key
    async fn unlock(&mut self) -> Result<rbw::locked::Keys, UnlockError> {
        // items before statements, or clippy::items_after_statements fires
        use zeroize::Zeroize as _;

        fn broken(e: impl Into<anyhow::Error>) -> UnlockError {
            UnlockError::Channel(e.into())
        }

        let message_id = self.next_message_id;
        self.next_message_id += 1;

        let mut inner = serde_json::to_vec(&UnlockRequest {
            command: "unlockWithBiometricsForUser",
            user_id: &self.user_id,
            message_id,
            timestamp: now_millis().map_err(broken)?,
        })
        .map_err(broken)?;
        let encrypted = rbw::cipherstring::CipherString::encrypt_symmetric(
            &self.keys, &inner,
        )
        .map_err(broken)?;
        inner.zeroize();
        let enc_obj = cipherstring_to_enc_obj(&encrypted).map_err(broken)?;
        let unlock_msg = serde_json::to_vec(&EncryptedWrapper {
            app_id: &self.app_id,
            message: enc_obj,
        })
        .map_err(broken)?;
        write_frame(&mut self.stream, &unlock_msg)
            .await
            .map_err(broken)?;
        log::debug!(
            "sent biometric unlock request, waiting for the os prompt..."
        );

        loop {
            let frame =
                read_frame(&mut self.stream).await.map_err(broken)?;
            let msg: IncomingFrame =
                serde_json::from_slice(&frame).map_err(broken)?;
            if msg.app_id.as_deref() != Some(self.app_id.as_str()) {
                log::debug!(
                    "skipping ipc message for a different client: {:?}",
                    msg.command
                );
                continue;
            }
            let Some(message) = msg.message else {
                match msg.command.as_deref() {
                    Some("invalidateEncryption") => {
                        return Err(broken(anyhow::anyhow!(
                            "bitwarden desktop app invalidated the \
                             encryption channel"
                        )));
                    }
                    Some("wrongUserId") => {
                        return Err(broken(anyhow::anyhow!(
                            "bitwarden desktop app doesn't recognize \
                             this user id (is the same account logged \
                             in in the desktop app?)"
                        )));
                    }
                    command => {
                        log::debug!("skipping ipc message: {command:?}");
                        continue;
                    }
                }
            };
            let Ok(cipherstring) =
                rbw::cipherstring::CipherString::new(&message)
            else {
                log::debug!("skipping ipc message: not a cipherstring");
                continue;
            };
            // frames for other clients were filtered out by app id above,
            // so a message addressed to us that doesn't decrypt means our
            // channel key is no longer valid
            let mut plaintext = cipherstring
                .decrypt_symmetric(&self.keys, None)
                .map_err(|e| {
                    broken(anyhow::anyhow!(
                        "failed to decrypt ipc message: {e}"
                    ))
                })?;
            let response: Result<UnlockResponse, _> =
                serde_json::from_slice(&plaintext);
            plaintext.zeroize();
            let Ok(response) = response else {
                log::debug!("skipping ipc message: failed to parse");
                continue;
            };
            if response.command.as_deref()
                != Some("unlockWithBiometricsForUser")
            {
                log::debug!("skipping ipc message: {:?}", response.command);
                continue;
            }
            // like the browser extension, only accept the response that
            // matches the request we sent, and ignore stale or replayed
            // responses
            if response.message_id != Some(i64::from(message_id)) {
                log::debug!(
                    "skipping unlock response for message {:?}",
                    response.message_id
                );
                continue;
            }
            let fresh = response.timestamp.is_some_and(|timestamp| {
                now_millis().is_ok_and(|now| {
                    now.abs_diff(timestamp) <= MESSAGE_VALID_TIMEOUT_MS
                })
            });
            if !fresh {
                log::debug!(
                    "skipping unlock response with a stale timestamp"
                );
                continue;
            }
            let Some(mut user_key_b64) = response.user_key_b64 else {
                return Err(UnlockError::Refused(format!(
                    "bitwarden desktop app refused to unlock: {:?}",
                    response.response
                )));
            };
            let user_key = rbw::base64::decode(&user_key_b64);
            user_key_b64.zeroize();
            let mut user_key = user_key.map_err(|e| {
                UnlockError::Refused(format!("invalid user key: {e}"))
            })?;
            if user_key.len() != 64 {
                let len = user_key.len();
                user_key.zeroize();
                return Err(UnlockError::Refused(format!(
                    "unexpected user key length {len}"
                )));
            }
            let mut key = rbw::locked::Vec::new();
            key.extend(user_key.iter().copied());
            user_key.zeroize();
            return Ok(rbw::locked::Keys::new(key));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    fn now() -> u64 {
        super::now_millis().unwrap()
    }

    #[test]
    fn user_id_from_access_token() {
        // only the payload matters; header and signature are not validated
        let token = format!(
            "x.{}.y",
            rbw::base64::encode_url_safe_no_pad(
                br#"{"sub":"11111111-2222-3333-4444-555555555555","email":"me@example.com"}"#
            )
        );
        assert_eq!(
            super::user_id_from_access_token(&token).unwrap(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert!(super::user_id_from_access_token("garbage").is_err());

        // payload isn't valid base64url
        assert!(super::user_id_from_access_token("x.!!!.y").is_err());

        // payload is valid base64url but not json
        let token = format!(
            "x.{}.y",
            rbw::base64::encode_url_safe_no_pad(b"notjson")
        );
        assert!(super::user_id_from_access_token(&token).is_err());

        // valid json but missing the sub claim
        let token = format!(
            "x.{}.y",
            rbw::base64::encode_url_safe_no_pad(br#"{"email":"a@b.c"}"#)
        );
        assert!(super::user_id_from_access_token(&token).is_err());
    }

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        super::write_frame(&mut a, b"{\"hello\":true}").await.unwrap();
        assert_eq!(
            super::read_frame(&mut b).await.unwrap(),
            b"{\"hello\":true}"
        );
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let oversized_len = 2 * 1024 * 1024_u32;
        a.write_all(&oversized_len.to_ne_bytes()).await.unwrap();
        assert!(super::read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let (mut a, _b) = tokio::io::duplex(4096);
        let data = vec![0; 2 * 1024 * 1024];
        assert!(super::write_frame(&mut a, &data).await.is_err());
    }

    // server side of the handshake; returns the shared channel keys and
    // the client's app id
    async fn mock_handshake<S>(server: &mut S) -> (rbw::locked::Keys, String)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use rsa::pkcs8::DecodePublicKey as _;

        let frame = super::read_frame(server).await.unwrap();
        let announcement: serde_json::Value =
            serde_json::from_slice(&frame).unwrap();
        assert_eq!(announcement, serde_json::json!({"clientType": "cli"}));

        let frame = super::read_frame(server).await.unwrap();
        let msg: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(msg["message"]["command"], "setupEncryption");
        assert_eq!(msg["message"]["userId"], "some-user");
        assert!(msg["message"]["timestamp"].is_u64());
        let app_id = msg["appId"].as_str().unwrap().to_string();
        let client_pubkey = rsa::RsaPublicKey::from_public_key_der(
            &rbw::base64::decode(
                msg["message"]["publicKey"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let secret: Vec<u8> = (100..164).collect(); // 64 bytes
        let mut rng = rand_8::rngs::OsRng;
        let encrypted_secret = client_pubkey
            .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), &secret)
            .unwrap();
        super::write_frame(
            server,
            &serde_json::to_vec(&serde_json::json!({
                "command": "setupEncryption",
                "appId": app_id,
                "messageId": -1,
                "sharedSecret": rbw::base64::encode(&encrypted_secret),
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let mut locked = rbw::locked::Vec::new();
        locked.extend(secret.iter().copied());
        (rbw::locked::Keys::new(locked), app_id)
    }

    // read and validate the client's unlock request; returns its message id
    async fn mock_read_unlock_request<S>(
        server: &mut S,
        keys: &rbw::locked::Keys,
    ) -> i64
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let frame = super::read_frame(server).await.unwrap();
        let msg: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        // message is an EncString object, not a plain string
        let enc_str = msg["message"]["encryptedString"].as_str().unwrap();
        let cipherstring =
            rbw::cipherstring::CipherString::new(enc_str).unwrap();
        let inner = cipherstring.decrypt_symmetric(keys, None).unwrap();
        let inner: serde_json::Value =
            serde_json::from_slice(&inner).unwrap();
        assert_eq!(inner["command"], "unlockWithBiometricsForUser");
        assert_eq!(inner["userId"], "some-user");
        assert!(inner["timestamp"].is_u64());
        inner["messageId"].as_i64().unwrap()
    }

    async fn mock_send_encrypted<S>(
        server: &mut S,
        keys: &rbw::locked::Keys,
        app_id: &str,
        body: &serde_json::Value,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let response = serde_json::to_vec(body).unwrap();
        let encrypted = rbw::cipherstring::CipherString::encrypt_symmetric(
            keys, &response,
        )
        .unwrap();
        super::write_frame(
            server,
            &serde_json::to_vec(&serde_json::json!({
                "appId": app_id,
                "messageId": body["messageId"],
                "message": encrypted.to_string(),
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handshake_and_unlock() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let user_key: Vec<u8> = (0..64).collect();
        let expected = user_key.clone();
        let server_task = tokio::spawn(async move {
            let (keys, app_id) = mock_handshake(&mut server).await;
            let message_id =
                mock_read_unlock_request(&mut server, &keys).await;
            mock_send_encrypted(
                &mut server,
                &keys,
                &app_id,
                &serde_json::json!({
                    "command": "unlockWithBiometricsForUser",
                    "response": true,
                    "messageId": message_id,
                    "timestamp": now(),
                    "userKeyB64": rbw::base64::encode(&user_key),
                }),
            )
            .await;
        });

        let mut channel =
            super::Channel::handshake(client, "some-user".to_string())
                .await
                .unwrap();
        let keys = channel.unlock().await.unwrap();
        assert_eq!(keys.enc_key(), &expected[..32]);
        assert_eq!(keys.mac_key(), &expected[32..]);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn channel_reuse() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let user_key: Vec<u8> = (0..64).collect();
        let expected = user_key.clone();
        let server_task = tokio::spawn(async move {
            let (keys, app_id) = mock_handshake(&mut server).await;
            for expected_message_id in [1, 2] {
                let message_id =
                    mock_read_unlock_request(&mut server, &keys).await;
                assert_eq!(message_id, expected_message_id);
                mock_send_encrypted(
                    &mut server,
                    &keys,
                    &app_id,
                    &serde_json::json!({
                        "command": "unlockWithBiometricsForUser",
                        "response": true,
                        "messageId": message_id,
                        "timestamp": now(),
                        "userKeyB64": rbw::base64::encode(&user_key),
                    }),
                )
                .await;
            }
        });

        let mut channel =
            super::Channel::handshake(client, "some-user".to_string())
                .await
                .unwrap();
        for _ in 0..2 {
            let keys = channel.unlock().await.unwrap();
            assert_eq!(keys.enc_key(), &expected[..32]);
            assert_eq!(keys.mac_key(), &expected[32..]);
        }
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn unlock_refused() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let (keys, app_id) = mock_handshake(&mut server).await;
            let message_id =
                mock_read_unlock_request(&mut server, &keys).await;
            mock_send_encrypted(
                &mut server,
                &keys,
                &app_id,
                &serde_json::json!({
                    "command": "unlockWithBiometricsForUser",
                    "response": false,
                    "messageId": message_id,
                    "timestamp": now(),
                }),
            )
            .await;
        });

        let mut channel =
            super::Channel::handshake(client, "some-user".to_string())
                .await
                .unwrap();
        assert!(matches!(
            channel.unlock().await,
            Err(super::UnlockError::Refused(_))
        ));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn interleaved_and_invalid_frames_are_skipped() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let user_key: Vec<u8> = (0..64).collect();
        let expected = user_key.clone();
        let server_task = tokio::spawn(async move {
            let (keys, app_id) = mock_handshake(&mut server).await;
            let message_id =
                mock_read_unlock_request(&mut server, &keys).await;

            // (a) unrelated plaintext broadcast frame without an app id
            super::write_frame(
                &mut server,
                &serde_json::to_vec(&serde_json::json!({
                    "command": "status",
                }))
                .unwrap(),
            )
            .await
            .unwrap();

            // (b) frame addressed to a different client (the desktop app
            // broadcasts responses to everyone connected)
            super::write_frame(
                &mut server,
                &serde_json::to_vec(&serde_json::json!({
                    "appId": "some-other-app",
                    "message": "2.notavalidcipherstring",
                }))
                .unwrap(),
            )
            .await
            .unwrap();

            // (c) encrypted frame for us, but an unrelated command
            mock_send_encrypted(
                &mut server,
                &keys,
                &app_id,
                &serde_json::json!({
                    "command": "status",
                    "timestamp": now(),
                }),
            )
            .await;

            // (d) unlock response with the wrong message id
            mock_send_encrypted(
                &mut server,
                &keys,
                &app_id,
                &serde_json::json!({
                    "command": "unlockWithBiometricsForUser",
                    "response": true,
                    "messageId": message_id + 1000,
                    "timestamp": now(),
                    "userKeyB64": rbw::base64::encode([0x41; 64]),
                }),
            )
            .await;

            // (e) unlock response with a stale timestamp (replay)
            mock_send_encrypted(
                &mut server,
                &keys,
                &app_id,
                &serde_json::json!({
                    "command": "unlockWithBiometricsForUser",
                    "response": true,
                    "messageId": message_id,
                    "timestamp": now() - 60 * 1000,
                    "userKeyB64": rbw::base64::encode([0x41; 64]),
                }),
            )
            .await;

            // (f) the real response
            mock_send_encrypted(
                &mut server,
                &keys,
                &app_id,
                &serde_json::json!({
                    "command": "unlockWithBiometricsForUser",
                    "response": true,
                    "messageId": message_id,
                    "timestamp": now(),
                    "userKeyB64": rbw::base64::encode(&user_key),
                }),
            )
            .await;
        });

        let mut channel =
            super::Channel::handshake(client, "some-user".to_string())
                .await
                .unwrap();
        let keys = channel.unlock().await.unwrap();
        assert_eq!(keys.enc_key(), &expected[..32]);
        assert_eq!(keys.mac_key(), &expected[32..]);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn undecryptable_frame_for_us_breaks_the_channel() {
        let (client, mut server) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let (keys, app_id) = mock_handshake(&mut server).await;
            let _ = mock_read_unlock_request(&mut server, &keys).await;

            // encrypted with a different key: our channel key must be
            // stale, so the client should give up rather than hang
            let mut other = rbw::locked::Vec::new();
            other.extend((0..64).map(|_| 0x42));
            let other_keys = rbw::locked::Keys::new(other);
            mock_send_encrypted(
                &mut server,
                &other_keys,
                &app_id,
                &serde_json::json!({
                    "command": "unlockWithBiometricsForUser",
                    "response": true,
                    "messageId": 1,
                    "timestamp": now(),
                }),
            )
            .await;
        });

        let mut channel =
            super::Channel::handshake(client, "some-user".to_string())
                .await
                .unwrap();
        assert!(matches!(
            channel.unlock().await,
            Err(super::UnlockError::Channel(_))
        ));
        server_task.await.unwrap();
    }
}
