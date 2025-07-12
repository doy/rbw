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
    let notifications_handler = crate::notifications::Handler::new();
    let state =
        std::sync::Arc::new(tokio::sync::Mutex::new(crate::state::State {
            priv_key: None,
            org_keys: None,
            timeout,
            timeout_duration,
            sync_timeout,
            sync_timeout_duration,
            notifications_handler,
            #[cfg(feature = "clipboard")]
            clipboard: arboard::Clipboard::new()
                .inspect_err(|e| {
                    log::warn!("couldn't create clipboard context: {e}");
                })
                .ok(),
        }));

    let agent =
        crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    tokio::try_join!(agent.run(listener), ssh_agent.run(),)?;

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

    let startup_ack = if no_daemonize {
        None
    } else {
        Some(daemon::daemonize().context("failed to daemonize")?)
    };

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
