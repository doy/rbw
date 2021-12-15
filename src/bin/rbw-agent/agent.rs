use anyhow::Context as _;

#[derive(Debug)]
pub enum TimeoutEvent {
    Set,
    Clear,
}

pub struct State {
    pub priv_key: Option<rbw::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, rbw::locked::Keys>>,
    pub timeout_chan: tokio::sync::mpsc::UnboundedSender<TimeoutEvent>,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&rbw::locked::Keys> {
        match org_id {
            Some(id) => self.org_keys.as_ref().and_then(|h| h.get(id)),
            None => self.priv_key.as_ref(),
        }
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }

    pub fn set_timeout(&mut self) {
        // no real better option to unwrap here
        self.timeout_chan.send(TimeoutEvent::Set).unwrap();
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        // no real better option to unwrap here
        self.timeout_chan.send(TimeoutEvent::Clear).unwrap();
    }
}

pub struct Agent {
    timeout_duration: tokio::time::Duration,
    timeout: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    timeout_chan: tokio::sync::mpsc::UnboundedReceiver<TimeoutEvent>,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
}

impl Agent {
    pub fn new() -> anyhow::Result<Self> {
        let config = rbw::config::Config::load()?;
        let timeout_duration =
            tokio::time::Duration::from_secs(config.lock_timeout);
        let (w, r) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            timeout_duration,
            timeout: None,
            timeout_chan: r,
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                priv_key: None,
                org_keys: None,
                timeout_chan: w,
            })),
        })
    }

    fn set_timeout(&mut self) {
        self.timeout =
            Some(Box::pin(tokio::time::sleep(self.timeout_duration)));
    }

    fn clear_timeout(&mut self) {
        self.timeout = None;
    }

    pub async fn run(
        &mut self,
        listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        // tokio only supports timeouts up to 2^36 milliseconds
        let mut forever = Box::pin(tokio::time::sleep(
            tokio::time::Duration::from_secs(60 * 60 * 24 * 365 * 2),
        ));
        loop {
            let timeout = self.timeout.as_mut().unwrap_or(&mut forever);
            tokio::select! {
                sock = listener.accept() => {
                    let mut sock = crate::sock::Sock::new(
                        sock.context("failed to accept incoming connection")?.0
                    );
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let res
                            = handle_request(&mut sock, state.clone()).await;
                        if let Err(e) = res {
                            // unwrap is the only option here
                            sock.send(&rbw::protocol::Response::Error {
                                error: format!("{:#}", e),
                            }).await.unwrap();
                        }
                    });
                }
                _ = timeout => {
                    let state = self.state.clone();
                    tokio::spawn(async move{
                        state.write().await.clear();
                    });
                }
                Some(ev) = self.timeout_chan.recv() => {
                    match ev {
                        TimeoutEvent::Set => self.set_timeout(),
                        TimeoutEvent::Clear => self.clear_timeout(),
                    }
                }
            }
        }
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
            crate::actions::sync(sock, true).await?;
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
