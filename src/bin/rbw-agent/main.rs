use anyhow::Context as _;

mod actions;
mod agent;
mod daemon;
mod debugger;
mod notifications;
mod sock;
mod ssh_agent;
mod state;
mod timeout;

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
) -> anyhow::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let (event_tx, event_r) = tokio::sync::mpsc::unbounded_channel();
    let mut initial_state = crate::state::State::new(
        event_tx,
        #[cfg(feature = "clipboard")]
        arboard::Clipboard::new()
            .inspect_err(|e| {
                log::warn!("couldn't create clipboard context: {e}");
            })
            .ok(),
    );

    if let Ok(config) = rbw::config::Config::load()
        && let Some(key) = config.account_key()
    {
        initial_state.ensure_account(&key, &config);
    }

    let state = std::sync::Arc::new(tokio::sync::Mutex::new(initial_state));

    let agent = crate::agent::Agent::new(event_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    tokio::try_join!(agent.run(listener), ssh_agent.run())?;

    Ok(())
}

fn real_main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let no_daemonize = std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--no-daemonize");

    rbw::dirs::make_all()?;

    let startup_ack =
        daemon::daemonize(no_daemonize).context("failed to daemonize")?;

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    let (w, r) = std::sync::mpsc::channel();
    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    // unwrap is fine here because there's no good reason that this should
    // ever fail
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        if let Err(e) = tokio_main(startup_ack).await {
            // this unwrap is fine because it's the only real option here
            w.send(e).unwrap();
        }
    });

    if let Ok(e) = r.recv() {
        return Err(e);
    }

    Ok(())
}

fn main() {
    let res = real_main();

    if let Err(e) = res {
        // XXX log file?
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
