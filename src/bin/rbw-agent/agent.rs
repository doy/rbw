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
    pub fn new() -> Self {
        let config = rbw::config::Config::load().unwrap();
        Self {
            timeout: tokio::time::delay_for(
                tokio::time::Duration::from_secs(config.lock_timeout),
            ),
            state: std::sync::Arc::new(tokio::sync::RwLock::new(State {
                priv_key: None,
            })),
        }
    }

    pub async fn run(&mut self, mut listener: tokio::net::UnixListener) {
        loop {
            tokio::select! {
                sock = listener.next() => {
                    let mut sock
                        = crate::sock::Sock::new(sock.unwrap().unwrap());
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let req = sock.recv().await;
                        handle_request(&req, &mut sock, state.clone()).await;
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
    req: &rbw::agent::Request,
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::RwLock<State>>,
) {
    match &req.action {
        rbw::agent::Action::Login => {
            crate::actions::login(sock, state.clone(), req.tty.as_deref())
                .await
        }
        rbw::agent::Action::Unlock => {
            crate::actions::unlock(sock, state.clone(), req.tty.as_deref())
                .await
        }
        rbw::agent::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await
        }
        rbw::agent::Action::Sync => crate::actions::sync(sock).await,
        rbw::agent::Action::Decrypt { cipherstring } => {
            crate::actions::decrypt(sock, state.clone(), &cipherstring).await
        }
        rbw::agent::Action::Quit => std::process::exit(0),
    }
}
