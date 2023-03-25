use anyhow::Context as _;
use futures_util::StreamExt as _;

pub struct State {
    pub priv_key: Option<rbw::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }

    pub fn set_timeout(&mut self) {
        self.timeout.set(self.timeout_duration);
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        self.timeout.clear();
    }

    pub fn set_sync_timeout(&mut self) {
        self.sync_timeout.set(self.sync_timeout_duration);
    }
}

pub struct Agent {
    timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
}

impl Agent {
    pub fn new() -> anyhow::Result<Self> {
        let config = rbw::config::Config::load()?;
        let timeout_duration =
            std::time::Duration::from_secs(config.lock_timeout);
        let sync_timeout_duration =
            std::time::Duration::from_secs(config.sync_interval);
        let (timeout, timer_r) = crate::timeout::Timeout::new();
        let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();
        if sync_timeout_duration > std::time::Duration::ZERO {
            sync_timeout.set(sync_timeout_duration);
        }
        Ok(Self {
            timer_r,
            sync_timer_r,
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                priv_key: None,
                org_keys: None,
                timeout,
                timeout_duration,
                sync_timeout,
                sync_timeout_duration,
            })),
        })
    }

    pub async fn run(
        self,
        listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        enum Event {
            Request(std::io::Result<tokio::net::UnixStream>),
            Timeout(()),
            Sync(()),
        }
        let mut stream = futures_util::stream::select_all([
            tokio_stream::wrappers::UnixListenerStream::new(listener)
                .map(Event::Request)
                .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.timer_r,
            )
            .map(Event::Timeout)
            .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.sync_timer_r,
            )
            .map(Event::Sync)
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
                        if let Err(e) = res {
                            // unwrap is the only option here
                            sock.send(&rbw::protocol::Response::Error {
                                error: format!("{e:#}"),
                            })
                            .await
                            .unwrap();
                        }
                    });
                }
                Event::Timeout(()) => {
                    self.state.write().await.clear();
                }
                Event::Sync(()) => {
                    // this could fail if we aren't logged in, but we don't
                    // care about that
                    tokio::spawn(async move {
                        let _ = crate::actions::sync(None).await;
                    });
                    self.state.write().await.set_sync_timeout();
                }
            }
        }
        Ok(())
    }
}

async fn handle_request(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) -> anyhow::Result<()> {
    let req = sock.recv().await?;
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&rbw::protocol::Response::Error { error }).await?;
            return Ok(());
        }
    };
    let set_timeout = match &req.action {
        rbw::protocol::Action::Register => {
            crate::actions::register(sock, req.tty.as_deref()).await?;
            true
        }
        rbw::protocol::Action::Login => {
            crate::actions::login(sock, state.clone(), req.tty.as_deref())
                .await?;
            true
        }
        rbw::protocol::Action::Unlock => {
            crate::actions::unlock(sock, state.clone(), req.tty.as_deref())
                .await?;
            true
        }
        rbw::protocol::Action::CheckLock => {
            crate::actions::check_lock(
                sock,
                state.clone(),
                req.tty.as_deref(),
            )
            .await?;
            false
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await?;
            false
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(Some(sock)).await?;
            false
        }
        rbw::protocol::Action::Decrypt {
            cipherstring,
            org_id,
        } => {
            crate::actions::decrypt(
                sock,
                state.clone(),
                cipherstring,
                org_id.as_deref(),
            )
            .await?;
            true
        }
        rbw::protocol::Action::Encrypt { plaintext, org_id } => {
            crate::actions::encrypt(
                sock,
                state.clone(),
                plaintext,
                org_id.as_deref(),
            )
            .await?;
            true
        }
        rbw::protocol::Action::Quit => std::process::exit(0),
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            true
        }
    };

    if set_timeout {
        state.write().await.set_timeout();
    }

    Ok(())
}
