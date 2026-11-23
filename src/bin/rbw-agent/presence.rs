// Asks the person at the Mac to approve an action with Touch ID, an Apple
// Watch, or their login password.
//
// The prompt runs in a short-lived child process, for the same reason as the
// biometric unlock helper: macOS does not reliably present LocalAuthentication
// UI from the daemon's Tokio workers. The child gets the prompt text on stdin
// and reports the outcome through its exit status. It never sees key material.

use std::io::Read as _;

pub const HELPER_ARGUMENT: &str = "--confirm-presence";

const EXIT_APPROVED: i32 = 0;
const EXIT_DENIED: i32 = 1;
const EXIT_UNAVAILABLE: i32 = 2;
const MAX_REASON_LEN: u64 = 1024;

// A prompt nobody answers should not hold the ssh client forever.
const PROMPT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum ConfirmError {
    #[error("the request was not approved")]
    Denied,
    #[error("Touch ID confirmation is unavailable: {0}")]
    Unavailable(String),
}

// The caller makes sure only one prompt is up at a time.
pub async fn confirm(reason: &str) -> Result<(), ConfirmError> {
    use tokio::io::AsyncWriteExt as _;

    let executable = std::env::current_exe().map_err(unavailable)?;
    let mut child = tokio::process::Command::new(executable)
        .arg(HELPER_ARGUMENT)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(unavailable)?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        ConfirmError::Unavailable(
            "failed to open confirmation helper stdin".to_string(),
        )
    })?;
    stdin
        .write_all(reason.as_bytes())
        .await
        .map_err(unavailable)?;
    drop(stdin);

    let status = tokio::time::timeout(PROMPT_TIMEOUT, child.wait())
        .await
        .map_err(|_| {
            ConfirmError::Unavailable(
                "timed out waiting for confirmation".to_string(),
            )
        })?
        .map_err(unavailable)?;

    match status.code() {
        Some(EXIT_APPROVED) => Ok(()),
        Some(EXIT_DENIED) => Err(ConfirmError::Denied),
        _ => Err(ConfirmError::Unavailable(format!(
            "confirmation helper exited with {status}"
        ))),
    }
}

// Runs on the helper's main thread. Never returns.
pub fn helper_main() -> ! {
    let mut reason = String::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_REASON_LEN)
        .read_to_string(&mut reason)
    {
        eprintln!("failed to read confirmation reason: {e}");
        std::process::exit(EXIT_UNAVAILABLE);
    }
    if reason.trim().is_empty() {
        eprintln!("confirmation reason is empty");
        std::process::exit(EXIT_UNAVAILABLE);
    }
    std::process::exit(evaluate(&reason));
}

fn evaluate(reason: &str) -> i32 {
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    // DeviceOwnerAuthentication accepts Touch ID, a paired Apple Watch, or
    // the login password, so a Mac with its lid closed still works.
    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: LAContext has no preconditions for creation.
    let context = unsafe { LAContext::new() };
    // SAFETY: plain query on a valid context.
    if let Err(e) = unsafe { context.canEvaluatePolicy_error(policy) } {
        eprintln!(
            "cannot ask for confirmation: {}",
            e.localizedDescription()
        );
        return EXIT_UNAVAILABLE;
    }

    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let reply = block2::RcBlock::new(
        move |success: objc2::runtime::Bool, _error: *mut NSError| {
            let _ = tx.send(success.as_bool());
        },
    );
    let reason = NSString::from_str(reason);
    // SAFETY: the context, reason and reply block outlive the call; the
    // block only sends on a channel, which is safe from any thread.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(policy, &reason, &reply);
    }

    match rx.recv() {
        Ok(true) => EXIT_APPROVED,
        Ok(false) => EXIT_DENIED,
        Err(_) => EXIT_UNAVAILABLE,
    }
}

fn unavailable(error: impl std::fmt::Display) -> ConfirmError {
    ConfirmError::Unavailable(error.to_string())
}
