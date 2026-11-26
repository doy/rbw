use crate::prelude::*;

pub enum AuthOutcome {
    Authenticated(crate::locked::Keys),
    Fallback,
    Cancelled,
}

pub fn keychain_service(profile: &str) -> String {
    format!("{profile}-touchid")
}

pub fn keychain_account(server: &str, email: &str) -> String {
    format!("{server}:{email}")
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::prelude::*;

    use std::sync::Mutex;

    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAError, LAPolicy};
    use zeroize::Zeroize as _;

    use super::{AuthOutcome, keychain_account, keychain_service};

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    pub fn has_key(profile: &str, server: &str, email: &str) -> bool {
        let service = keychain_service(profile);
        let account = keychain_account(server, email);
        security_framework::item::ItemSearchOptions::new()
            .class(security_framework::item::ItemClass::generic_password())
            .service(&service)
            .account(&account)
            .load_attributes(true)
            .search()
            .is_ok_and(|results| !results.is_empty())
    }

    pub fn store_key(
        profile: &str,
        server: &str,
        email: &str,
        keys: &crate::locked::Keys,
    ) -> Result<()> {
        let service = keychain_service(profile);
        let account = keychain_account(server, email);
        // Delete first so that any rebuilt/upgraded binary recreates the
        // keychain item with its own ACL ownership.
        delete_key(profile, server, email)?;
        security_framework::passwords::set_generic_password(
            &service,
            &account,
            keys.as_bytes(),
        )
        .map_err(|e| Error::Keychain {
            message: e.to_string(),
        })
    }

    pub fn delete_key(
        profile: &str,
        server: &str,
        email: &str,
    ) -> Result<()> {
        let service = keychain_service(profile);
        let account = keychain_account(server, email);
        match security_framework::passwords::delete_generic_password(
            &service, &account,
        ) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(Error::Keychain {
                message: e.to_string(),
            }),
        }
    }

    pub(super) fn load_key(
        profile: &str,
        server: &str,
        email: &str,
    ) -> Result<Option<crate::locked::Keys>> {
        let service = keychain_service(profile);
        let account = keychain_account(server, email);
        let opts =
            security_framework::passwords::PasswordOptions::new_generic_password(
                &service, &account,
            );
        match security_framework::passwords::generic_password(opts) {
            Ok(mut bytes) => {
                let keys = crate::locked::Keys::from_bytes(&bytes);
                bytes.zeroize();
                keys.map_or_else(
                    || {
                        Err(Error::Keychain {
                            message: "stored key has invalid length"
                                .to_string(),
                        })
                    },
                    |keys| Ok(Some(keys)),
                )
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(Error::Keychain {
                message: e.to_string(),
            }),
        }
    }

    pub fn unlock(
        profile: &str,
        server: &str,
        email: &str,
        reason: &str,
    ) -> AuthOutcome {
        if !has_key(profile, server, email) {
            return AuthOutcome::Fallback;
        }

        let policy =
            LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion;

        // SAFETY: LAContext methods are called with valid Objective-C objects
        // and pointers, and `context` stays alive until the reply block fires.
        let auth_result = unsafe {
            let context = LAContext::new();
            let fallback_title = NSString::from_str("Use Master Password");
            context.setLocalizedFallbackTitle(Some(&fallback_title));

            if let Err(err) = context.canEvaluatePolicy_error(policy) {
                log::info!(
                    "touch id unavailable ({err}); falling back to master password"
                );
                context.invalidate();
                return AuthOutcome::Fallback;
            }

            let reason_str = NSString::from_str(reason);
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let tx = Mutex::new(Some(tx));
            let block = block2::RcBlock::new(
                move |success: Bool, err: *mut NSError| {
                    let res = if success.as_bool() {
                        Ok(())
                    } else if let Some(err_ref) = err.as_ref() {
                        Err(err_ref.code())
                    } else {
                        Err(LAError::AuthenticationFailed.0)
                    };
                    if let Ok(mut guard) = tx.lock()
                        && let Some(sender) = guard.take()
                    {
                        let _ = sender.send(res);
                    }
                },
            );

            context.evaluatePolicy_localizedReason_reply(
                policy,
                &reason_str,
                &block,
            );
            let res = rx.recv();
            context.invalidate();
            res
        };

        match auth_result {
            Ok(Ok(())) => match load_key(profile, server, email) {
                Ok(Some(keys)) => AuthOutcome::Authenticated(keys),
                Ok(None) => AuthOutcome::Fallback,
                Err(e) => {
                    log::warn!(
                        "failed to load touch id key from keychain: {e}"
                    );
                    AuthOutcome::Fallback
                }
            },
            Ok(Err(code)) if LAError(code) == LAError::UserCancel => {
                AuthOutcome::Cancelled
            }
            Ok(Err(code)) if LAError(code) == LAError::UserFallback => {
                AuthOutcome::Fallback
            }
            Ok(Err(code)) => {
                log::warn!("touch id authentication failed (code {code})");
                AuthOutcome::Fallback
            }
            Err(e) => {
                log::warn!("touch id reply channel closed unexpectedly: {e}");
                AuthOutcome::Fallback
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use crate::prelude::*;

    use super::AuthOutcome;

    pub fn has_key(_profile: &str, _server: &str, _email: &str) -> bool {
        false
    }

    pub fn store_key(
        _profile: &str,
        _server: &str,
        _email: &str,
        _keys: &crate::locked::Keys,
    ) -> Result<()> {
        Ok(())
    }

    pub fn delete_key(
        _profile: &str,
        _server: &str,
        _email: &str,
    ) -> Result<()> {
        Ok(())
    }

    pub fn unlock(
        _profile: &str,
        _server: &str,
        _email: &str,
        _reason: &str,
    ) -> AuthOutcome {
        AuthOutcome::Fallback
    }
}

pub fn has_key(profile: &str, server: &str, email: &str) -> bool {
    platform::has_key(profile, server, email)
}

pub fn store_key(
    profile: &str,
    server: &str,
    email: &str,
    keys: &crate::locked::Keys,
) -> Result<()> {
    platform::store_key(profile, server, email, keys)
}

pub fn delete_key(profile: &str, server: &str, email: &str) -> Result<()> {
    platform::delete_key(profile, server, email)
}

pub fn unlock(
    profile: &str,
    server: &str,
    email: &str,
    reason: &str,
) -> AuthOutcome {
    platform::unlock(profile, server, email, reason)
}

#[test]
fn test_keychain_naming() {
    assert_eq!(keychain_service("rbw"), "rbw-touchid");
    assert_eq!(keychain_service("rbw-work"), "rbw-work-touchid");
    assert_eq!(
        keychain_account("default", "user@example.com"),
        "default:user@example.com"
    );
    assert_eq!(
        keychain_account("https://vault.example.com", "user@example.com"),
        "https://vault.example.com:user@example.com"
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires unlocked macOS login keychain"]
fn test_macos_keychain_roundtrip() {
    let profile = format!("rbw-test-{}", uuid::Uuid::new_v4());
    let server = "default";
    let email = "test@example.com";

    // Clean state
    assert!(!has_key(&profile, server, email));
    delete_key(&profile, server, email).unwrap();

    // Store and verify
    let keys =
        crate::locked::Keys::from_bytes(&[0x5a_u8; crate::locked::KEYS_LEN])
            .unwrap();
    store_key(&profile, server, email, &keys).unwrap();
    assert!(has_key(&profile, server, email));

    let loaded = platform::load_key(&profile, server, email)
        .unwrap()
        .expect("stored key should exist");
    assert_eq!(loaded.as_bytes(), keys.as_bytes());

    // Overwrite and verify
    let keys2 =
        crate::locked::Keys::from_bytes(&[0xa5_u8; crate::locked::KEYS_LEN])
            .unwrap();
    store_key(&profile, server, email, &keys2).unwrap();
    let loaded2 = platform::load_key(&profile, server, email)
        .unwrap()
        .expect("updated key should exist");
    assert_eq!(loaded2.as_bytes(), keys2.as_bytes());

    // Delete and verify idempotency
    delete_key(&profile, server, email).unwrap();
    assert!(!has_key(&profile, server, email));
    assert!(
        platform::load_key(&profile, server, email)
            .unwrap()
            .is_none()
    );
    delete_key(&profile, server, email).unwrap();
}
