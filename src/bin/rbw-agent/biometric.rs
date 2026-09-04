use std::io::{Read as _, Write as _};
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

use sha2::Digest as _;
use zeroize::Zeroize as _;

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{
    Algorithm, GenerateKeyOptions, KeyType, SecKey, Token,
};
use security_framework::passwords::AccessControlOptions;

pub const HELPER_ARGUMENT: &str = "--biometric-helper";

const VAULT_KEY_LEN: usize = 64;
const REQUEST_UNLOCK: u8 = 1;
const RESPONSE_SUCCESS: u8 = 0;
const RESPONSE_CANCELED: u8 = 1;
const RESPONSE_PASSWORD_REQUESTED: u8 = 2;
const RESPONSE_UNAVAILABLE: u8 = 3;
const RESPONSE_HARDENED: u8 = 4;
const RESPONSE_READY: u8 = 5;
const HELPER_INIT_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_AUTHENTICATION_ERROR_DOMAIN: &str =
    "com.apple.LocalAuthentication";
const OS_STATUS_ERROR_DOMAIN: &str = "NSOSStatusErrorDomain";

// Security framework does not present Touch ID reliably from the daemon's
// Tokio workers. This private child owns the Secure Enclave key and performs
// authentication on its main thread, communicating only over anonymous pipes.
pub struct Session {
    helper: std::sync::Mutex<Helper>,
    protected_key_digest: [u8; 32],
}

struct Helper {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

struct KeyMaterial {
    private_key: SecKey,
    wrapped_vault_key: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("Touch ID was canceled")]
    Canceled,
    #[error("master password requested")]
    PasswordRequested,
    #[error("Touch ID is unavailable: {0}")]
    Unavailable(String),
}

impl Session {
    pub fn new(
        vault_key: &rbw::locked::Keys,
        protected_key: &str,
    ) -> Result<Self, UnlockError> {
        let mut helper = Helper::spawn()?;

        // The helper acknowledges only after PT_DENY_ATTACH and RLIMIT_CORE
        // succeed. Never place the vault key in the pipe before that boundary.
        if helper.read_init_response()? != RESPONSE_HARDENED {
            return Err(UnlockError::Unavailable(
                "biometric helper did not enter its hardened state"
                    .to_string(),
            ));
        }
        helper
            .stdin
            .write_all(vault_key.as_bytes())
            .map_err(unavailable)?;
        helper.stdin.flush().map_err(unavailable)?;
        if helper.read_init_response()? != RESPONSE_READY {
            return Err(UnlockError::Unavailable(
                "biometric helper failed to initialize".to_string(),
            ));
        }

        Ok(Self {
            helper: std::sync::Mutex::new(helper),
            protected_key_digest: protected_key_digest(protected_key),
        })
    }

    pub fn matches(&self, protected_key: &str) -> bool {
        self.protected_key_digest == protected_key_digest(protected_key)
    }

    pub fn unlock(&self) -> Result<rbw::locked::Keys, UnlockError> {
        let mut helper = self.helper.lock().map_err(|_| {
            UnlockError::Unavailable(
                "biometric helper lock was poisoned".to_string(),
            )
        })?;
        helper
            .stdin
            .write_all(&[REQUEST_UNLOCK])
            .map_err(unavailable)?;
        helper.stdin.flush().map_err(unavailable)?;

        let mut response = [0_u8; 1];
        helper
            .stdout
            .read_exact(&mut response)
            .map_err(unavailable)?;
        match response[0] {
            RESPONSE_SUCCESS => {
                let mut key = rbw::locked::Vec::new();
                key.zero();
                if let Err(error) = helper
                    .stdout
                    .read_exact(&mut key.data_mut()[..VAULT_KEY_LEN])
                {
                    return Err(unavailable(error));
                }
                key.truncate(VAULT_KEY_LEN);
                Ok(rbw::locked::Keys::new(key))
            }
            RESPONSE_CANCELED => Err(UnlockError::Canceled),
            RESPONSE_PASSWORD_REQUESTED => {
                Err(UnlockError::PasswordRequested)
            }
            RESPONSE_UNAVAILABLE => Err(UnlockError::Unavailable(
                "biometric helper could not unlock the vault key".to_string(),
            )),
            response => Err(UnlockError::Unavailable(format!(
                "biometric helper returned unknown response {response}"
            ))),
        }
    }
}

impl Helper {
    fn spawn() -> Result<Self, UnlockError> {
        let executable = std::env::current_exe().map_err(unavailable)?;
        let mut child = std::process::Command::new(executable)
            .arg(HELPER_ARGUMENT)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(unavailable)?;
        let Some(stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(UnlockError::Unavailable(
                "failed to open biometric helper stdin".to_string(),
            ));
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(UnlockError::Unavailable(
                "failed to open biometric helper stdout".to_string(),
            ));
        };
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    fn read_init_response(&mut self) -> Result<u8, UnlockError> {
        read_byte_with_timeout(&mut self.stdout, HELPER_INIT_TIMEOUT)
            .map_err(unavailable)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl KeyMaterial {
    fn new(vault_key: &[u8]) -> Result<Self, UnlockError> {
        let flags = AccessControlOptions::PRIVATE_KEY_USAGE
            | AccessControlOptions::BIOMETRY_CURRENT_SET;
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            flags.bits(),
        )
        .map_err(unavailable)?;

        let mut options = GenerateKeyOptions::default();
        // Deliberately omit a keychain Location. security-framework then sets
        // kSecAttrIsPermanent=false, so the key dies with this helper process
        // and needs no signing entitlement or cleanup after a crash.
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_label("rbw session Touch ID unlock")
            .set_token(Token::SecureEnclave)
            .set_access_control(access_control);

        let private_key = SecKey::new(&options).map_err(unavailable)?;
        let public_key = private_key.public_key().ok_or_else(|| {
            UnlockError::Unavailable(
                "failed to copy the Secure Enclave public key".to_string(),
            )
        })?;
        let wrapped_vault_key = public_key
            .encrypt_data(
                Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
                vault_key,
            )
            .map_err(unavailable)?;

        Ok(Self {
            private_key,
            wrapped_vault_key,
        })
    }

    fn unlock(&self) -> Result<rbw::locked::Vec, UnlockError> {
        let mut plaintext = self
            .private_key
            .decrypt_data(
                Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM,
                &self.wrapped_vault_key,
            )
            .map_err(|error| {
                classify_authentication_error(
                    &error.domain().to_string(),
                    error.code(),
                    error.to_string(),
                )
            })?;
        if plaintext.len() != VAULT_KEY_LEN {
            plaintext.zeroize();
            return Err(UnlockError::Unavailable(
                "Secure Enclave returned an invalid vault key".to_string(),
            ));
        }
        // security-framework necessarily returns a pageable Vec copied from
        // CFData. Minimize that unavoidable window before zeroizing it.
        let mut locked = rbw::locked::Vec::new();
        locked.zero();
        locked.data_mut()[..VAULT_KEY_LEN].copy_from_slice(&plaintext);
        locked.truncate(VAULT_KEY_LEN);
        plaintext.zeroize();
        Ok(locked)
    }
}

pub fn helper_main() -> anyhow::Result<()> {
    // Bypass stdio's global user-space buffers so plaintext key bytes cannot
    // remain in a Stdin/Stdout allocation after the pipe operation completes.
    // SAFETY: these descriptors remain open for the helper process lifetime.
    let stdin = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    // SAFETY: same as above.
    let stdout = unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) };

    write_all_fd(stdout, &[RESPONSE_HARDENED])?;
    let mut vault_key = rbw::locked::Vec::new();
    vault_key.zero();
    read_exact_fd(stdin, &mut vault_key.data_mut()[..VAULT_KEY_LEN])?;
    let key_material = KeyMaterial::new(&vault_key.data()[..VAULT_KEY_LEN]);
    drop(vault_key);

    let key_material = match key_material {
        Ok(key_material) => key_material,
        Err(error) => {
            eprintln!("failed to initialize biometric helper: {error}");
            write_all_fd(stdout, &[RESPONSE_UNAVAILABLE])?;
            return Ok(());
        }
    };
    write_all_fd(stdout, &[RESPONSE_READY])?;

    loop {
        let mut request = [0_u8; 1];
        match read_exact_fd(stdin, &mut request) {
            Ok(()) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(())
            }
            Err(error) => return Err(error.into()),
        }
        if request[0] != REQUEST_UNLOCK {
            anyhow::bail!("unknown biometric helper request {}", request[0]);
        }

        match key_material.unlock() {
            Ok(plaintext) => {
                write_all_fd(stdout, &[RESPONSE_SUCCESS])?;
                let result = write_all_fd(stdout, plaintext.data());
                drop(plaintext);
                result?;
            }
            Err(UnlockError::Canceled) => {
                write_all_fd(stdout, &[RESPONSE_CANCELED])?;
            }
            Err(UnlockError::PasswordRequested) => {
                write_all_fd(stdout, &[RESPONSE_PASSWORD_REQUESTED])?;
            }
            Err(UnlockError::Unavailable(error)) => {
                eprintln!("Touch ID is unavailable: {error}");
                write_all_fd(stdout, &[RESPONSE_UNAVAILABLE])?;
            }
        }
    }
}

fn protected_key_digest(protected_key: &str) -> [u8; 32] {
    sha2::Sha256::digest(protected_key).into()
}

fn classify_authentication_error(
    domain: &str,
    code: isize,
    description: String,
) -> UnlockError {
    // Error numbers overlap between LocalAuthentication and OSStatus. Only
    // explicit user choices suppress the master-password fallback; system and
    // app cancellation are environmental failures and should fall back.
    match (domain, code) {
        (LOCAL_AUTHENTICATION_ERROR_DOMAIN, -2)
        | (OS_STATUS_ERROR_DOMAIN, -128) => UnlockError::Canceled,
        (LOCAL_AUTHENTICATION_ERROR_DOMAIN, -3) => {
            UnlockError::PasswordRequested
        }
        _ => UnlockError::Unavailable(description),
    }
}

fn read_byte_with_timeout<R: std::io::Read + std::os::fd::AsFd>(
    reader: &mut R,
    timeout: Duration,
) -> std::io::Result<u8> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for biometric helper",
            ));
        }
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap(),
            tv_nsec: remaining.subsec_nanos().into(),
        };
        let ready = {
            let mut descriptor = [rustix::event::PollFd::new(
                reader,
                rustix::event::PollFlags::IN,
            )];
            rustix::event::poll(&mut descriptor, Some(&timeout))
        };
        match ready {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out waiting for biometric helper",
                ))
            }
            Ok(_) => {
                let mut response = [0_u8; 1];
                reader.read_exact(&mut response)?;
                return Ok(response[0]);
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn read_exact_fd(
    fd: BorrowedFd<'_>,
    mut buffer: &mut [u8],
) -> std::io::Result<()> {
    while !buffer.is_empty() {
        match rustix::io::read(fd, &mut *buffer) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "biometric helper pipe closed",
                ))
            }
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all_fd(
    fd: BorrowedFd<'_>,
    mut buffer: &[u8],
) -> std::io::Result<()> {
    while !buffer.is_empty() {
        match rustix::io::write(fd, buffer) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write biometric helper pipe",
                ))
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn unavailable(error: impl std::fmt::Display) -> UnlockError {
    UnlockError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn protected_key_digest_is_stable_and_distinguishes_keys() {
        assert_eq!(
            protected_key_digest("protected key"),
            protected_key_digest("protected key")
        );
        assert_ne!(
            protected_key_digest("protected key"),
            protected_key_digest("rotated key")
        );
    }

    #[test]
    fn authentication_errors_preserve_user_intent() {
        assert!(matches!(
            classify_authentication_error(
                LOCAL_AUTHENTICATION_ERROR_DOMAIN,
                -2,
                "canceled".to_string()
            ),
            UnlockError::Canceled
        ));
        assert!(matches!(
            classify_authentication_error(
                LOCAL_AUTHENTICATION_ERROR_DOMAIN,
                -3,
                "fallback".to_string()
            ),
            UnlockError::PasswordRequested
        ));
        assert!(matches!(
            classify_authentication_error(
                LOCAL_AUTHENTICATION_ERROR_DOMAIN,
                -4,
                "system canceled".to_string()
            ),
            UnlockError::Unavailable(_)
        ));
        assert!(matches!(
            classify_authentication_error(
                OS_STATUS_ERROR_DOMAIN,
                -4,
                "unimplemented".to_string()
            ),
            UnlockError::Unavailable(_)
        ));
        assert!(matches!(
            classify_authentication_error(
                OS_STATUS_ERROR_DOMAIN,
                -128,
                "canceled".to_string()
            ),
            UnlockError::Canceled
        ));
    }

    #[test]
    fn unbuffered_pipe_io_roundtrips() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        write_all_fd(writer.as_fd(), b"vault key bytes").unwrap();
        let mut output = [0_u8; 15];
        read_exact_fd(reader.as_fd(), &mut output).unwrap();
        assert_eq!(&output, b"vault key bytes");
    }

    #[test]
    fn helper_response_wait_is_bounded() {
        let (reader, _writer) = rustix::pipe::pipe().unwrap();
        let mut reader = std::fs::File::from(reader);
        let error =
            read_byte_with_timeout(&mut reader, Duration::from_millis(10))
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn helper_response_is_read_before_timeout() {
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        write_all_fd(writer.as_fd(), &[RESPONSE_HARDENED]).unwrap();
        let mut reader = std::fs::File::from(reader);
        assert_eq!(
            read_byte_with_timeout(&mut reader, Duration::from_secs(1))
                .unwrap(),
            RESPONSE_HARDENED
        );
    }
}
