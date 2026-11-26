use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

const PROTOCOL_REVISION: u32 = 1;

pub const VERSION: u32 = {
    const fn unwrap(res: &Result<u32, std::num::ParseIntError>) -> u32 {
        match res {
            Ok(t) => *t,
            Err(_) => panic!("failed to parse cargo version"),
        }
    }

    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    unwrap(&u32::from_str_radix(major, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(minor, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(patch, 10)) * 1_000_000
        + PROTOCOL_REVISION
};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    tty: Option<String>,
    environment: Option<Environment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    action: Action,
}

impl Request {
    pub fn new(environment: Environment, action: Action) -> Self {
        Self::new_for_account(environment, None, action)
    }

    pub fn new_for_account(
        environment: Environment,
        account: Option<String>,
        action: Action,
    ) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            account,
            action,
        }
    }

    pub fn into_parts(self) -> (Action, Environment, Option<String>) {
        (
            self.action,
            self.environment.unwrap_or_else(|| Environment {
                tty: self.tty.map(|tty| SerializableOsString(tty.into())),
                env_vars: vec![],
            }),
            self.account,
        )
    }
}

// Taken from https://github.com/gpg/gnupg/blob/36dbca3e6944d13e75e96eace634e58a7d7e201d/common/session-env.c#L62-L91
pub const ENVIRONMENT_VARIABLES: &[&str] = &[
    // Used to set ttytype
    "TERM",
    // The X display
    "DISPLAY",
    // Xlib Authentication
    "XAUTHORITY",
    // Used by Xlib to select X input modules (e.g. "@im=SCIM")
    "XMODIFIERS",
    // For the Wayland display engine.
    "WAYLAND_DISPLAY",
    // Used by Qt and other non-GTK toolkits to check for X11 or Wayland
    "XDG_SESSION_TYPE",
    // Used by Qt to explicitly request X11 or Wayland; in particular, needed to
    // make Qt use Wayland on GNOME
    "QT_QPA_PLATFORM",
    // Used by GTK to select GTK input modules (e.g. "scim-bridge")
    "GTK_IM_MODULE",
    // Used by GNOME 3 to talk to gcr over dbus
    "DBUS_SESSION_BUS_ADDRESS",
    // Used by Qt to select Qt input modules (e.g. "xim")
    "QT_IM_MODULE",
    // Used for communication with non-standard Pinentries
    "PINENTRY_USER_DATA",
    // Used to pass window information
    "PINENTRY_GEOM_HINT",
];

pub static ENVIRONMENT_VARIABLES_OS: std::sync::LazyLock<
    Vec<std::ffi::OsString>,
> = std::sync::LazyLock::new(|| {
    ENVIRONMENT_VARIABLES
        .iter()
        .map(std::ffi::OsString::from)
        .collect()
});

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
struct SerializableOsString(std::ffi::OsString);

impl serde::Serialize for SerializableOsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(self.0.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for SerializableOsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SerializableOsString;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("base64 encoded os string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SerializableOsString(std::ffi::OsString::from_vec(
                    crate::base64::decode(s).map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?,
                )))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct Environment {
    tty: Option<SerializableOsString>,
    env_vars: Vec<(SerializableOsString, SerializableOsString)>,
}

impl Environment {
    pub fn new(
        tty: Option<std::ffi::OsString>,
        env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Self {
        Self {
            tty: tty.map(SerializableOsString),
            env_vars: env_vars
                .into_iter()
                .map(|(k, v)| {
                    (SerializableOsString(k), SerializableOsString(v))
                })
                .collect(),
        }
    }

    pub fn tty(&self) -> Option<&std::ffi::OsStr> {
        self.tty.as_ref().map(|tty| tty.0.as_os_str())
    }

    pub fn env_vars(
        &self,
    ) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
    {
        self.env_vars
            .iter()
            .map(|(var, val)| (var.0.clone(), val.0.clone()))
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            .collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    LoginPasskey,
    Register,
    Unlock,
    CheckLock,
    Lock,
    LockAll,
    AccountStates,
    EvictAccount {
        server: String,
        email: String,
    },
    Sync,
    YubikeyEnroll {
        label: Option<String>,
    },
    DeleteTouchIdKey {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        email: Option<String>,
    },
    Decrypt {
        cipherstring: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    Encrypt {
        plaintext: String,
        org_id: Option<String>,
    },
    ClipboardStore {
        text: String,
    },
    Quit,
    Version,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Status {
        message: String,
    },
    Error {
        error: String,
    },
    Decrypt {
        plaintext: String,
    },
    Encrypt {
        cipherstring: String,
    },
    Version {
        version: u32,
    },
    AccountStates {
        unlocked: Vec<crate::config::AccountKey>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_account_request_and_responses_serde() {
        let req = Request::new_for_account(
            Environment::default(),
            Some("work".to_string()),
            Action::Unlock,
        );
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"account\":\"work\""));
        let decoded: Request = serde_json::from_str(&json).unwrap();
        let (action, _, account) = decoded.into_parts();
        assert!(matches!(action, Action::Unlock));
        assert_eq!(account.as_deref(), Some("work"));

        // Requests without account omit the field and deserialize to None
        let req_no_acct =
            Request::new(Environment::default(), Action::LockAll);
        let json_no_acct = serde_json::to_string(&req_no_acct).unwrap();
        assert!(!json_no_acct.contains("account"));
        let decoded: Request = serde_json::from_str(&json_no_acct).unwrap();
        let (action, _, account) = decoded.into_parts();
        assert!(matches!(action, Action::LockAll));
        assert!(account.is_none());

        let states = Response::AccountStates {
            unlocked: vec![crate::config::AccountKey {
                server: "default".to_string(),
                email: "user@example.com".to_string(),
            }],
        };
        let states_json = serde_json::to_string(&states).unwrap();
        let decoded_states: Response =
            serde_json::from_str(&states_json).unwrap();
        match decoded_states {
            Response::AccountStates { unlocked } => {
                assert_eq!(unlocked.len(), 1);
                assert_eq!(unlocked[0].server, "default");
                assert_eq!(unlocked[0].email, "user@example.com");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
