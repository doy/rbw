use anyhow::Context as _;
use futures_util::StreamExt as _;

pub struct Agent {
    event_r: tokio::sync::mpsc::UnboundedReceiver<crate::state::AgentEvent>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl Agent {
    pub fn new(
        event_r: tokio::sync::mpsc::UnboundedReceiver<
            crate::state::AgentEvent,
        >,
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self { event_r, state }
    }

    pub async fn run(
        self,
        listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        pub enum Event {
            Request(std::io::Result<tokio::net::UnixStream>),
            Agent(crate::state::AgentEvent),
        }

        let mut stream = futures_util::stream::select_all([
            tokio_stream::wrappers::UnixListenerStream::new(listener)
                .map(Event::Request)
                .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.event_r,
            )
            .map(Event::Agent)
            .boxed(),
        ]);
        while let Some(event) = stream.next().await {
            match event {
                Event::Request(res) => {
                    let mut sock = crate::sock::Sock::new(
                        res.context("failed to accept incoming connection")?,
                    );
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let res =
                            handle_request(&mut sock, state.clone()).await;
                        if let Err(e) = res
                            && let Err(send_err) = sock
                                .send(&rbw::protocol::Response::Error {
                                    error: format!("{e:#}"),
                                })
                                .await
                        {
                            log::warn!(
                                "failed to send error response to client: {send_err:#}"
                            );
                        }
                    });
                }
                Event::Agent(crate::state::AgentEvent::Timeout(key)) => {
                    self.state.lock().await.clear_account(&key);
                }
                Event::Agent(crate::state::AgentEvent::Sync(key)) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let config_opt =
                            rbw::config::ConfigFile::load_async()
                                .await
                                .ok()
                                .and_then(|cf| cf.find_by_key(&key))
                                .map(|(_, cfg)| cfg);

                        let Some(config) = config_opt else {
                            let evicted =
                                state.lock().await.evict_account(&key);
                            if let Some(acct) = evicted {
                                acct.shutdown().await;
                            }
                            return;
                        };

                        // this could fail if we aren't logged in, but we
                        // don't care about that
                        if let Err(e) = crate::actions::sync_for_config(
                            None,
                            state.clone(),
                            &config,
                            &key,
                        )
                        .await
                        {
                            eprintln!("failed to sync: {e:#}");
                        }

                        let mut guard = state.lock().await;
                        if let Some(acct) = guard.account_mut(&key) {
                            acct.update_timeouts(&config);
                            acct.set_sync_timeout();
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

async fn handle_request(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> anyhow::Result<()> {
    let req = sock.recv().await?;
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&rbw::protocol::Response::Error { error }).await?;
            return Ok(());
        }
    };
    let (action, environment, account) = req.into_parts();
    let timeout_key: Option<rbw::config::AccountKey> = match &action {
        rbw::protocol::Action::Register => Some(
            crate::actions::register(sock, account.as_deref(), &environment)
                .await?,
        ),
        rbw::protocol::Action::Login => Some(
            crate::actions::login(
                sock,
                state.clone(),
                account.as_deref(),
                &environment,
            )
            .await?,
        ),
        rbw::protocol::Action::LoginPasskey => Some(
            crate::actions::login_passkey(
                sock,
                state.clone(),
                account.as_deref(),
                &environment,
            )
            .await?,
        ),
        rbw::protocol::Action::Unlock => Some(
            crate::actions::unlock(
                sock,
                state.clone(),
                account.as_deref(),
                &environment,
            )
            .await?,
        ),
        rbw::protocol::Action::YubikeyEnroll { label } => Some(
            crate::actions::yubikey_enroll(
                sock,
                state.clone(),
                account.as_deref(),
                &environment,
                label.as_deref(),
            )
            .await?,
        ),
        rbw::protocol::Action::DeleteTouchIdKey { server, email } => {
            crate::actions::delete_touchid_key(
                sock,
                account.as_deref(),
                server.as_deref(),
                email.as_deref(),
            )
            .await?;
            None
        }
        rbw::protocol::Action::CheckLock => {
            crate::actions::check_lock(
                sock,
                state.clone(),
                account.as_deref(),
            )
            .await?;
            None
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone(), account.as_deref())
                .await?;
            None
        }
        rbw::protocol::Action::LockAll => {
            crate::actions::lock_all(sock, state.clone()).await?;
            None
        }
        rbw::protocol::Action::AccountStates => {
            crate::actions::account_states(sock, state.clone()).await?;
            None
        }
        rbw::protocol::Action::EvictAccount { server, email } => {
            crate::actions::evict_account(sock, state.clone(), server, email)
                .await?;
            None
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(
                Some(sock),
                state.clone(),
                account.as_deref(),
            )
            .await?;
            None
        }
        rbw::protocol::Action::Decrypt {
            cipherstring,
            entry_key,
            org_id,
        } => {
            let cipherstring = cipherstring.clone();
            let entry_key = entry_key.clone();
            let org_id = org_id.clone();
            Some(
                crate::actions::decrypt(
                    sock,
                    state.clone(),
                    account.as_deref(),
                    &environment,
                    &cipherstring,
                    entry_key.as_deref(),
                    org_id.as_deref(),
                )
                .await?,
            )
        }
        rbw::protocol::Action::Encrypt { plaintext, org_id } => Some(
            crate::actions::encrypt(
                sock,
                state.clone(),
                account.as_deref(),
                plaintext,
                org_id.as_deref(),
            )
            .await?,
        ),
        rbw::protocol::Action::ClipboardStore { text } => {
            crate::actions::clipboard_store(sock, state.clone(), text)
                .await?;
            None
        }
        rbw::protocol::Action::Quit => std::process::exit(0),
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            None
        }
    };

    let mut state = state.lock().await;
    state.set_last_environment(environment);
    if let Some(key) = timeout_key
        && let Some(acct) = state.account(&key)
    {
        acct.set_timeout();
    }

    Ok(())
}
