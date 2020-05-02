use anyhow::Context as _;
use tokio::stream::StreamExt as _;

#[derive(Debug)]
pub enum TimeoutEvent {
    Set,
    Clear,
}

pub struct State {
    pub priv_key: Option<rbw::locked::Keys>,
    pub timeout_chan: tokio::sync::mpsc::UnboundedSender<TimeoutEvent>,
}

impl State {
    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none()
    }

    pub fn set_timeout(&mut self) {
        // no real better option to unwrap here
        self.timeout_chan.send(TimeoutEvent::Set).unwrap();
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        // no real better option to unwrap here
        self.timeout_chan.send(TimeoutEvent::Clear).unwrap();
    }
}

pub struct Agent {
    timeout_duration: tokio::time::Duration,
    timeout: Option<tokio::time::Delay>,
    timeout_chan: tokio::sync::mpsc::UnboundedReceiver<TimeoutEvent>,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
}

impl Agent {
    pub fn new() -> anyhow::Result<Self> {
        let config =
            rbw::config::Config::load().context("failed to load config")?;
        let timeout_duration =
            tokio::time::Duration::from_secs(config.lock_timeout);
        let (w, r) = tokio::sync::mpsc::unbounded_channel();
        Ok(Self {
            timeout_duration,
            timeout: None,
            timeout_chan: r,
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                priv_key: None,
                timeout_chan: w,
            })),
        })
    }

    fn set_timeout(&mut self) {
        self.timeout = Some(tokio::time::delay_for(self.timeout_duration));
    }

    fn clear_timeout(&mut self) {
        self.timeout = None;
    }

    pub async fn run(
        &mut self,
        mut listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        // tokio only supports timeouts up to 2^36 milliseconds
        let mut forever = tokio::time::delay_for(
            tokio::time::Duration::from_secs(60 * 60 * 24 * 365 * 2),
        );
        loop {
            let timeout = if let Some(timeout) = &mut self.timeout {
                timeout
            } else {
                &mut forever
            };
            tokio::select! {
                Some(sock) = listener.next() => {
                    let mut sock = crate::sock::Sock::new(
                        sock.context("failed to accept incoming connection")?
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
                Some(ev) = &mut self.timeout_chan.next() => {
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
    let req = sock
        .recv()
        .await
        .context("failed to receive incoming message")?;
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&rbw::protocol::Response::Error { error })
                .await
                .context("failed to send response")?;
            return Ok(());
        }
    };
    let set_timeout = match &req.action {
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
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await?;
            false
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(sock).await?;
            false
        }
        rbw::protocol::Action::Decrypt { cipherstring } => {
            crate::actions::decrypt(sock, state.clone(), &cipherstring)
                .await?;
            true
        }
        rbw::protocol::Action::Encrypt { plaintext } => {
            crate::actions::encrypt(sock, state.clone(), &plaintext).await?;
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
