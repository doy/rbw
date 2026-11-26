use signature::{SignatureEncoding as _, Signer as _};

fn sign_ssh_key(
    key: &impl ssh_agent_lib::ssh_key::SigningKey,
    data: &[u8],
) -> Result<ssh_agent_lib::ssh_key::Signature, ssh_agent_lib::error::AgentError>
{
    key.try_sign(data)
        .map_err(ssh_agent_lib::error::AgentError::other)
}

fn mpint_to_boxed_uint(
    mpint: &ssh_agent_lib::ssh_key::Mpint,
) -> Result<rsa::BoxedUint, ssh_agent_lib::error::AgentError> {
    let bytes = mpint.as_positive_bytes().ok_or_else(|| {
        ssh_agent_lib::error::AgentError::Other(
            "RSA key component must be positive".into(),
        )
    })?;
    let bits = bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| u32::try_from(bits).ok())
        .ok_or_else(|| {
            ssh_agent_lib::error::AgentError::Other(
                "RSA key component too large".into(),
            )
        })?;
    rsa::BoxedUint::from_be_slice(bytes, bits)
        .map_err(ssh_agent_lib::error::AgentError::other)
}

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
                        credential: pk.key_data().clone().into(),
                        comment: String::new(),
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
        let pubkey = ssh_agent_lib::ssh_key::PublicKey::new(
            request.credential.key_data().clone(),
            "",
        );

        let private_key =
            crate::actions::find_ssh_private_key(self.state.clone(), pubkey)
                .await
                .map_err(|e| {
                    ssh_agent_lib::error::AgentError::Other(e.into())
                })?;

        sign_with_private_key(&private_key, &request.data, request.flags)
    }
}

fn sign_with_private_key(
    private_key: &ssh_agent_lib::ssh_key::PrivateKey,
    data: &[u8],
    flags: u32,
) -> Result<ssh_agent_lib::ssh_key::Signature, ssh_agent_lib::error::AgentError>
{
    match private_key.key_data() {
        ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(_) => {
            sign_ssh_key(private_key, data)
        }

        ssh_agent_lib::ssh_key::private::KeypairData::Rsa(key) => {
            let p = mpint_to_boxed_uint(&key.private.p)?;
            let q = mpint_to_boxed_uint(&key.private.q)?;
            let e = mpint_to_boxed_uint(&key.public.e)?;
            let rsa_key = rsa::PrivateKey::from_p_q(p, q, e)
                .map_err(ssh_agent_lib::error::AgentError::other)?;

            let (algorithm, sig_bytes) = if flags
                & ssh_agent_lib::proto::signature::RSA_SHA2_512
                != 0
            {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(rsa_key);
                let signature = signing_key
                    .try_sign(data)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;

                ("rsa-sha2-512", signature.to_bytes())
            } else if flags & ssh_agent_lib::proto::signature::RSA_SHA2_256
                != 0
            {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(rsa_key);
                let signature = signing_key
                    .try_sign(data)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;

                ("rsa-sha2-256", signature.to_bytes())
            } else {
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(
                        rsa_key,
                    );
                let signature = signing_key
                    .try_sign(data)
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

#[cfg(test)]
mod test {
    use super::*;
    use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};
    use signature::Verifier as _;

    #[test]
    fn test_sign_ed25519() {
        let keypair =
            ssh_agent_lib::ssh_key::private::Ed25519Keypair::from_seed(
                &[0x42_u8; 32],
            );
        let private_key = ssh_agent_lib::ssh_key::PrivateKey::from(keypair);
        let sig = sign_with_private_key(&private_key, b"hello", 0).unwrap();
        assert_eq!(
            sig.algorithm(),
            ssh_agent_lib::ssh_key::Algorithm::Ed25519
        );
        assert_eq!(sig.as_bytes().len(), 64);
    }

    #[test]
    fn test_sign_rsa() {
        let generated = rsa::PrivateKey::new(&mut rand::rng(), 1024).unwrap();
        let mpint = |bytes: &[u8]| {
            ssh_agent_lib::ssh_key::Mpint::from_positive_bytes(bytes).unwrap()
        };
        let keypair = ssh_agent_lib::ssh_key::private::RsaKeypair {
            public: ssh_agent_lib::ssh_key::public::RsaPublicKey {
                e: mpint(&generated.e().to_be_bytes()),
                n: mpint(&generated.n().to_be_bytes()),
            },
            private: ssh_agent_lib::ssh_key::private::RsaPrivateKey {
                d: mpint(&generated.d().to_be_bytes()),
                iqmp: mpint(&[1]),
                p: mpint(&generated.primes()[0].to_be_bytes()),
                q: mpint(&generated.primes()[1].to_be_bytes()),
            },
        };
        let private_key = ssh_agent_lib::ssh_key::PrivateKey::from(keypair);

        let sig512 = sign_with_private_key(
            &private_key,
            b"hello",
            ssh_agent_lib::proto::signature::RSA_SHA2_512,
        )
        .unwrap();
        assert_eq!(sig512.algorithm().as_str(), "rsa-sha2-512");
        let vk512 = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(
            generated.to_public_key(),
        );
        vk512
            .verify(
                b"hello",
                &rsa::pkcs1v15::Signature::try_from(sig512.as_bytes())
                    .unwrap(),
            )
            .unwrap();

        let sig256 = sign_with_private_key(
            &private_key,
            b"hello",
            ssh_agent_lib::proto::signature::RSA_SHA2_256,
        )
        .unwrap();
        assert_eq!(sig256.algorithm().as_str(), "rsa-sha2-256");
        let vk256 = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(
            generated.to_public_key(),
        );
        vk256
            .verify(
                b"hello",
                &rsa::pkcs1v15::Signature::try_from(sig256.as_bytes())
                    .unwrap(),
            )
            .unwrap();
    }
}
