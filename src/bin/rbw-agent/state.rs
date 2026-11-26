use sha2::Digest as _;

#[derive(Debug, Clone)]
pub enum AgentEvent {
    Timeout(rbw::config::AccountKey),
    Sync(rbw::config::AccountKey),
}

pub struct AccountState {
    pub priv_key: Option<rbw::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub notifications_handler: crate::notifications::Handler,
    pub master_password_reprompt: std::collections::HashSet<[u8; 32]>,
    pub master_password_reprompt_initialized: bool,
    forward_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl AccountState {
    pub fn new(
        key: rbw::config::AccountKey,
        config: &rbw::config::Config,
        event_tx: tokio::sync::mpsc::UnboundedSender<AgentEvent>,
    ) -> Self {
        let timeout_duration =
            std::time::Duration::from_secs(config.lock_timeout);
        let sync_timeout_duration =
            std::time::Duration::from_secs(config.sync_interval);
        let (timeout, mut timer_r) = crate::timeout::Timeout::new();
        let (sync_timeout, mut sync_timer_r) = crate::timeout::Timeout::new();
        if sync_timeout_duration > std::time::Duration::ZERO {
            sync_timeout.set(sync_timeout_duration);
        }
        let (notifications_handler, mut notif_r) =
            crate::notifications::Handler::with_channel();

        let tx_timeout = event_tx.clone();
        let key_timeout = key.clone();
        let h_timeout = tokio::spawn(async move {
            while timer_r.recv().await.is_some() {
                if tx_timeout
                    .send(AgentEvent::Timeout(key_timeout.clone()))
                    .is_err()
                {
                    break;
                }
            }
        });

        let tx_sync = event_tx.clone();
        let key_sync = key.clone();
        let h_sync = tokio::spawn(async move {
            while sync_timer_r.recv().await.is_some() {
                if tx_sync.send(AgentEvent::Sync(key_sync.clone())).is_err() {
                    break;
                }
            }
        });

        let h_notif = tokio::spawn(async move {
            while let Some(message) = notif_r.recv().await {
                let event = match message {
                    crate::notifications::Message::Logout => {
                        AgentEvent::Timeout(key.clone())
                    }
                    crate::notifications::Message::Sync => {
                        AgentEvent::Sync(key.clone())
                    }
                };
                if event_tx.send(event).is_err() {
                    break;
                }
            }
        });

        Self {
            priv_key: None,
            org_keys: None,
            timeout,
            timeout_duration,
            sync_timeout,
            sync_timeout_duration,
            notifications_handler,
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            forward_handles: vec![h_timeout, h_sync, h_notif],
        }
    }

    pub fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }

    pub fn set_timeout(&self) {
        self.timeout.set(self.timeout_duration);
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        self.timeout.clear();
    }

    pub fn set_sync_timeout(&self) {
        if self.sync_timeout_duration > std::time::Duration::ZERO {
            self.sync_timeout.set(self.sync_timeout_duration);
        } else {
            self.sync_timeout.clear();
        }
    }

    pub fn update_timeouts(&mut self, config: &rbw::config::Config) {
        self.timeout_duration =
            std::time::Duration::from_secs(config.lock_timeout);
        let new_sync = std::time::Duration::from_secs(config.sync_interval);
        if self.sync_timeout_duration != new_sync {
            self.sync_timeout_duration = new_sync;
            self.set_sync_timeout();
        }
    }

    pub async fn shutdown(mut self) {
        self.clear();
        self.sync_timeout.clear();
        self.notifications_handler.shutdown().await;
        for handle in self.forward_handles.drain(..) {
            handle.abort();
        }
    }

    // the way we structure the client/agent split in rbw makes the master
    // password reprompt feature a bit complicated to implement - it would be
    // a lot easier to just have the client do the prompting, but that would
    // leave it open to someone reading the cipherstring from the local
    // database and passing it to the agent directly, bypassing the client.
    // the agent is the thing that holds the unlocked secrets, so it also
    // needs to be the thing guarding access to master password reprompt
    // entries. we only pass individual cipherstrings to the agent though, so
    // the agent needs to be able to recognize the cipherstrings that need
    // reprompting, without the additional context of the entry they came
    // from. in addition, because the reprompt state is stored in the sync db
    // in plaintext, we can't just read it from the db directly, because
    // someone could just edit the file on disk before making the request.
    //
    // therefore, the solution we choose here is to keep an in-memory set of
    // cipherstrings that we know correspond to entries with master password
    // reprompt enabled. this set is only updated when the agent itself does
    // a sync, so it can't be bypassed by editing the on-disk file directly.
    // if the agent gets a request for any of those cipherstrings that it saw
    // marked as master password reprompt during the most recent sync, it
    // forces a reprompt.
    pub fn set_master_password_reprompt(
        &mut self,
        entries: &[rbw::db::Entry],
    ) {
        self.master_password_reprompt.clear();

        let mut hasher = sha2::Sha256::new();
        let mut insert = |s: Option<&str>| {
            if let Some(s) = s
                && !s.is_empty()
            {
                hasher.update(s);
                self.master_password_reprompt
                    .insert(hasher.finalize_reset().into());
            }
        };

        for entry in entries {
            if !entry.master_password_reprompt() {
                continue;
            }

            match &entry.data {
                rbw::db::EntryData::Login { password, totp, .. } => {
                    insert(password.as_deref());
                    insert(totp.as_deref());
                }
                rbw::db::EntryData::Card { number, code, .. } => {
                    insert(number.as_deref());
                    insert(code.as_deref());
                }
                rbw::db::EntryData::Identity {
                    ssn,
                    passport_number,
                    ..
                } => {
                    insert(ssn.as_deref());
                    insert(passport_number.as_deref());
                }
                rbw::db::EntryData::SecureNote => {}
                rbw::db::EntryData::SshKey { private_key, .. } => {
                    insert(private_key.as_deref());
                }
            }

            for field in &entry.fields {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    insert(field.value.as_deref());
                }
            }
        }

        self.master_password_reprompt_initialized = true;
    }

    pub fn master_password_reprompt_initialized(&self) -> bool {
        self.master_password_reprompt_initialized
    }
}

impl Drop for AccountState {
    fn drop(&mut self) {
        for handle in self.forward_handles.drain(..) {
            handle.abort();
        }
    }
}

pub struct State {
    pub accounts:
        std::collections::HashMap<rbw::config::AccountKey, AccountState>,
    pub event_tx: tokio::sync::mpsc::UnboundedSender<AgentEvent>,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: rbw::protocol::Environment,

    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

impl State {
    pub fn new(
        event_tx: tokio::sync::mpsc::UnboundedSender<AgentEvent>,
        #[cfg(feature = "clipboard")] clipboard: Option<arboard::Clipboard>,
    ) -> Self {
        Self {
            accounts: std::collections::HashMap::new(),
            event_tx,
            last_environment: rbw::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard,
        }
    }

    pub fn ensure_account(
        &mut self,
        key: &rbw::config::AccountKey,
        config: &rbw::config::Config,
    ) -> &mut AccountState {
        if self.accounts.contains_key(key) {
            let acct = self.accounts.get_mut(key).unwrap();
            acct.update_timeouts(config);
            acct
        } else {
            let acct =
                AccountState::new(key.clone(), config, self.event_tx.clone());
            self.accounts.entry(key.clone()).or_insert(acct)
        }
    }

    pub fn account(
        &self,
        key: &rbw::config::AccountKey,
    ) -> Option<&AccountState> {
        self.accounts.get(key)
    }

    pub fn account_mut(
        &mut self,
        key: &rbw::config::AccountKey,
    ) -> Option<&mut AccountState> {
        self.accounts.get_mut(key)
    }

    pub fn needs_unlock(&self, key: &rbw::config::AccountKey) -> bool {
        self.accounts
            .get(key)
            .is_none_or(AccountState::needs_unlock)
    }

    pub fn clear_account(&mut self, key: &rbw::config::AccountKey) {
        if let Some(acct) = self.accounts.get_mut(key) {
            acct.clear();
        }
    }

    pub fn clear_all(&mut self) {
        for acct in self.accounts.values_mut() {
            acct.clear();
        }
    }

    pub fn evict_account(
        &mut self,
        key: &rbw::config::AccountKey,
    ) -> Option<AccountState> {
        let mut removed = self.accounts.remove(key)?;
        removed.clear();
        Some(removed)
    }

    pub fn unlocked_accounts(&self) -> Vec<rbw::config::AccountKey> {
        let mut unlocked: Vec<_> = self
            .accounts
            .iter()
            .filter(|(_, v)| !v.needs_unlock())
            .map(|(k, _)| k.clone())
            .collect();
        unlocked.sort();
        unlocked
    }

    pub fn last_environment(&self) -> &rbw::protocol::Environment {
        &self.last_environment
    }

    pub fn set_last_environment(
        &mut self,
        environment: rbw::protocol::Environment,
    ) {
        self.last_environment = environment;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_keys(byte: u8) -> rbw::locked::Keys {
        rbw::locked::Keys::from_bytes(&[byte; rbw::locked::KEYS_LEN]).unwrap()
    }

    #[tokio::test]
    async fn test_multi_account_state_isolation() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut state = State::new(
            tx,
            #[cfg(feature = "clipboard")]
            None,
        );

        let key1 = rbw::config::AccountKey {
            server: "https://vault.nullbyte.ninja".to_string(),
            email: "dat.nguyen@bitbytelab.io".to_string(),
        };
        let key2 = rbw::config::AccountKey {
            server: "default".to_string(),
            email: "dat.nguyen@bitbytelab.io".to_string(),
        };
        let cfg = rbw::config::Config {
            sync_interval: 0,
            ..rbw::config::Config::default()
        };

        assert!(state.needs_unlock(&key1));
        assert!(state.needs_unlock(&key2));

        {
            let a1 = state.ensure_account(&key1, &cfg);
            a1.priv_key = Some(dummy_keys(0x11));
            a1.org_keys = Some(std::collections::HashMap::new());
            a1.set_master_password_reprompt(&[rbw::db::Entry {
                id: "1".to_string(),
                org_id: None,
                folder: None,
                folder_id: None,
                name: "secret".to_string(),
                data: rbw::db::EntryData::Login {
                    username: None,
                    password: Some("2.cipher1|iv|mac".to_string()),
                    totp: None,
                    uris: vec![],
                },
                fields: vec![],
                notes: None,
                history: vec![],
                key: None,
                master_password_reprompt:
                    rbw::api::CipherRepromptType::Password,
            }]);
        }
        {
            let a2 = state.ensure_account(&key2, &cfg);
            a2.priv_key = Some(dummy_keys(0x22));
            a2.org_keys = Some(std::collections::HashMap::new());
            a2.set_master_password_reprompt(&[]);
        }

        assert!(!state.needs_unlock(&key1));
        assert!(!state.needs_unlock(&key2));
        assert_eq!(state.unlocked_accounts().len(), 2);
        assert_eq!(
            state.account(&key1).unwrap().key(None).unwrap().as_bytes(),
            dummy_keys(0x11).as_bytes()
        );
        assert_eq!(
            state.account(&key2).unwrap().key(None).unwrap().as_bytes(),
            dummy_keys(0x22).as_bytes()
        );
        assert!(
            !state
                .account(&key1)
                .unwrap()
                .master_password_reprompt
                .is_empty()
        );
        assert!(
            state
                .account(&key2)
                .unwrap()
                .master_password_reprompt
                .is_empty()
        );

        // Lock only key1; key2 must stay unlocked
        state.clear_account(&key1);
        assert!(state.needs_unlock(&key1));
        assert!(!state.needs_unlock(&key2));
        assert_eq!(state.unlocked_accounts(), vec![key2.clone()]);

        // Re-unlock key1, then lock all
        {
            let a1 = state.ensure_account(&key1, &cfg);
            a1.priv_key = Some(dummy_keys(0x11));
            a1.org_keys = Some(std::collections::HashMap::new());
        }
        state.clear_all();
        assert!(state.needs_unlock(&key1));
        assert!(state.needs_unlock(&key2));
        assert_eq!(state.unlocked_accounts(), Vec::new());

        // Evict key1 leaves key2 intact
        let evicted = state.evict_account(&key1);
        assert!(evicted.is_some());
        evicted.unwrap().shutdown().await;
        assert!(state.account(&key1).is_none());
        assert!(state.account(&key2).is_some());
    }
}
