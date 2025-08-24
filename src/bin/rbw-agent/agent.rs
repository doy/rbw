use anyhow::Context as _;
use futures_util::StreamExt as _;

pub struct Agent {
    timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl Agent {
    pub fn new(
        timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self {
            timer_r,
            sync_timer_r,
            state,
        }
    }

    pub async fn run(
        self,
        listener: tokio::net::UnixListener,
    ) -> anyhow::Result<()> {
        pub enum Event {
            Request(std::io::Result<tokio::net::UnixStream>),
            Timeout(()),
            Sync(()),
        }

        let notifications = self
            .state
            .lock()
            .await
            .notifications_handler
            .get_channel()
            .await;
        let notifications =
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                notifications,
            )
            .map(|message| match message {
                crate::notifications::Message::Logout => Event::Timeout(()),
                crate::notifications::Message::Sync => Event::Sync(()),
            })
            .boxed();

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
            notifications,
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
                    self.state.lock().await.clear();
                }
                Event::Sync(()) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        // this could fail if we aren't logged in, but we
                        // don't care about that
                        if let Err(e) =
                            crate::actions::sync(None, state.clone()).await
                        {
                            eprintln!("failed to sync: {e:#}");
                        }
                    });
                    self.state.lock().await.set_sync_timeout();
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
    let (action, environment) = req.into_parts();
    let set_timeout = match &action {
        rbw::protocol::Action::Register => {
            crate::actions::register(sock, &environment).await?;
            true
        }
        rbw::protocol::Action::Login => {
            crate::actions::login(sock, state.clone(), &environment).await?;
            true
        }
        rbw::protocol::Action::Unlock => {
            crate::actions::unlock(sock, state.clone(), &environment).await?;
            true
        }
        rbw::protocol::Action::CheckLock => {
            crate::actions::check_lock(sock, state.clone()).await?;
            false
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await?;
            false
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(Some(sock), state.clone()).await?;
            false
        }
        rbw::protocol::Action::Decrypt {
            cipherstring,
            entry_key,
            org_id,
        } => {
            let cipherstring = cipherstring.clone();
            let entry_key = entry_key.clone();
            let org_id = org_id.clone();
            crate::actions::decrypt(
                sock,
                state.clone(),
                &environment,
                &cipherstring,
                entry_key.as_deref(),
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
        rbw::protocol::Action::ClipboardStore { text } => {
            crate::actions::clipboard_store(sock, state.clone(), text)
                .await?;
            true
        }
        rbw::protocol::Action::Quit => std::process::exit(0),
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            false
        }
    };

    let mut state = state.lock().await;
    state.set_last_environment(environment);
    if set_timeout {
        state.set_timeout();
    }

    Ok(())
}
