use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl SshAgent {
    pub fn new(
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self { state }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = rbw::dirs::ssh_agent_socket_file();

        let _ = std::fs::remove_file(&socket); // Ignore error if it doesn't exist

        let listener = tokio::net::UnixListener::bind(socket)?;
        ssh_agent_lib::agent::listen(listener, self).await?;

        Ok(())
    }
}

impl ssh_agent_lib::agent::Agent<tokio::net::UnixListener> for SshAgent {
    fn new_session(
        &mut self,
        #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
        socket: &tokio::net::UnixStream,
    ) -> impl ssh_agent_lib::agent::Session {
        SshSession {
            state: self.state.clone(),
            #[cfg(target_os = "macos")]
            peer: crate::presence::describe_peer(socket),
        }
    }
}

// One connection from an ssh client.
pub struct SshSession {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    // Who is asking, for the Touch ID prompt.
    #[cfg(target_os = "macos")]
    peer: String,
}

#[cfg(target_os = "macos")]
impl SshSession {
    async fn confirm_sign(
        &self,
        key_name: &str,
    ) -> Result<(), ssh_agent_lib::error::AgentError> {
        if !self.state.lock().await.touch_id_ssh {
            return Ok(());
        }
        // macOS shows this as "rbw-agent is trying to <reason>."
        let reason =
            format!("sign with the SSH key \"{key_name}\" for {}", self.peer);
        crate::presence::confirm(&reason).await.map_err(|e| {
            log::warn!("refused to sign with \"{key_name}\": {e}");
            ssh_agent_lib::error::AgentError::Other(e.into())
        })
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshSession {
    async fn request_identities(
        &mut self,
    ) -> Result<
        Vec<ssh_agent_lib::proto::Identity>,
        ssh_agent_lib::error::AgentError,
    > {
        crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?
            .into_iter()
            .map(|p| {
                p.parse::<ssh_agent_lib::ssh_key::PublicKey>()
                    .map(|pk| ssh_agent_lib::proto::Identity {
                        pubkey: pk.key_data().clone(),
                        comment: p.splitn(3, ' ').nth(2).unwrap_or("").to_string(),
                    })
                    .map_err(ssh_agent_lib::error::AgentError::other)
            })
            .collect()
    }

    async fn sign(
        &mut self,
        request: ssh_agent_lib::proto::SignRequest,
    ) -> Result<
        ssh_agent_lib::ssh_key::Signature,
        ssh_agent_lib::error::AgentError,
    > {
        let pubkey =
            ssh_agent_lib::ssh_key::PublicKey::new(request.pubkey, "");

        let (key_name, private_key) =
            crate::actions::find_ssh_private_key(self.state.clone(), pubkey)
                .await
                .map_err(|e| {
                    ssh_agent_lib::error::AgentError::Other(e.into())
                })?;

        #[cfg(target_os = "macos")]
        self.confirm_sign(&key_name).await?;
        #[cfg(not(target_os = "macos"))]
        let _ = key_name;

        match private_key.key_data() {
            ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(key) => key
                .try_sign(&request.data)
                .map_err(ssh_agent_lib::error::AgentError::other),

            ssh_agent_lib::ssh_key::private::KeypairData::Rsa(key) => {
                let p = rsa::BigUint::from_bytes_be(key.private.p.as_bytes());
                let q = rsa::BigUint::from_bytes_be(key.private.q.as_bytes());
                let e = rsa::BigUint::from_bytes_be(key.public.e.as_bytes());
                let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;

                let mut rng = rand_8::rngs::OsRng;

                let (algorithm, sig_bytes) = if request.flags
                    & SSH_AGENT_RSA_SHA2_512
                    != 0
                {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("rsa-sha2-512", signature.to_bytes())
                } else if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("rsa-sha2-256", signature.to_bytes())
                } else {
                    let signing_key = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(rsa_key);
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("ssh-rsa", signature.to_bytes())
                };

                Ok(ssh_agent_lib::ssh_key::Signature::new(
                    ssh_agent_lib::ssh_key::Algorithm::new(algorithm)
                        .map_err(ssh_agent_lib::error::AgentError::other)?,
                    sig_bytes,
                )
                .map_err(ssh_agent_lib::error::AgentError::other)?)
            }

            // TODO: Check which other key types are supported by bitwarden
            other => Err(ssh_agent_lib::error::AgentError::Other(
                format!("Unsupported key type: {other:?}").into(),
            )),
        }
    }
}
