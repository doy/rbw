use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_agent_lib::ssh_key;

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

#[derive(Clone)]
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

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshAgent {
    async fn request_identities(
        &mut self,
    ) -> Result<Vec<Identity>, AgentError> {
        crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|e| AgentError::Other(e.into()))?
            .into_iter()
            .map(|p| {
                p.parse::<ssh_key::PublicKey>()
                    .map(|pk| Identity {
                        pubkey: pk.key_data().clone(),
                        comment: String::new(),
                    })
                    .map_err(AgentError::other)
            })
            .collect()
    }

    async fn sign(
        &mut self,
        request: SignRequest,
    ) -> Result<ssh_key::Signature, AgentError> {
        let pubkey = ssh_key::PublicKey::new(request.pubkey, "");

        let private_key =
            crate::actions::find_ssh_private_key(self.state.clone(), pubkey)
                .await
                .map_err(|e| AgentError::Other(e.into()))?;

        match private_key.key_data() {
            ssh_key::private::KeypairData::Ed25519(key) => {
                key.try_sign(&request.data).map_err(AgentError::other)
            }

            ssh_key::private::KeypairData::Rsa(key) => {
                let p = rsa::BigUint::from_bytes_be(key.private.p.as_bytes());
                let q = rsa::BigUint::from_bytes_be(key.private.q.as_bytes());
                let e = rsa::BigUint::from_bytes_be(key.public.e.as_bytes());
                let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)
                    .map_err(AgentError::other)?;

                let mut rng = rand::rngs::OsRng;

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
                        .map_err(AgentError::other)?;

                    ("rsa-sha2-512", signature.to_bytes())
                } else if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(AgentError::other)?;

                    ("rsa-sha2-256", signature.to_bytes())
                } else {
                    let signing_key = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(rsa_key);
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(AgentError::other)?;

                    ("ssh-rsa", signature.to_bytes())
                };

                Ok(ssh_key::Signature::new(
                    ssh_key::Algorithm::new(algorithm)
                        .map_err(AgentError::other)?,
                    sig_bytes,
                )
                .map_err(AgentError::other)?)
            }

            // TODO: Check which other key types are supported by bitwarden
            other => Err(AgentError::Other(
                format!("Unsupported key type: {other:?}").into(),
            )),
        }
    }
}
