use anyhow::Context as _;
use tokio::stream::StreamExt as _;

pub struct State {
    pub priv_key: Option<rbw::locked::Keys>,
}

impl State {
    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none()
    }
}

pub struct Agent {
    timeout: tokio::time::Delay,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
}

impl Agent {
    pub fn new() -> anyhow::Result<Self> {
        let config =
            rbw::config::Config::load().context("failed to load config")?;
        Ok(Self {
            timeout: tokio::time::delay_for(
                tokio::time::Duration::from_secs(config.lock_timeout),
            ),
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                priv_key: None,
            })),
        })
    }

    pub async fn run(
        &mut self,
        mut listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                sock = listener.next() => {
                    let sock = if let Some(sock) = sock {
                        sock
                    } else {
                        return Ok(());
                    };
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
                _ = &mut self.timeout => {
                    let state = self.state.clone();
                    tokio::spawn(async move{
                        state.write().await.priv_key = None
                    });
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
    match &req.action {
        rbw::protocol::Action::Login => {
            crate::actions::login(sock, state.clone(), req.tty.as_deref())
                .await
        }
        rbw::protocol::Action::Unlock => {
            crate::actions::unlock(sock, state.clone(), req.tty.as_deref())
                .await
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await
        }
        rbw::protocol::Action::Sync => crate::actions::sync(sock).await,
        rbw::protocol::Action::Decrypt { cipherstring } => {
            crate::actions::decrypt(sock, state.clone(), &cipherstring).await
        }
        rbw::protocol::Action::Quit => std::process::exit(0),
    }
}
