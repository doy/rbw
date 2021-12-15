#![warn(clippy::cargo)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::as_conversions)]
#![warn(clippy::get_unwrap)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]

use anyhow::Context as _;

mod actions;
mod agent;
mod daemon;
mod debugger;
mod sock;

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
) -> anyhow::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let mut agent = crate::agent::Agent::new()?;
    agent.run(listener).await?;

    Ok(())
}

fn real_main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let no_daemonize = std::env::args()
        .nth(1)
        .map_or(false, |arg| arg == "--no-daemonize");

    let startup_ack = if no_daemonize {
        None
    } else {
        Some(daemon::daemonize().context("failed to daemonize")?)
    };

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{}", e);
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
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}
