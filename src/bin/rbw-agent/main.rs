#![allow(clippy::too_many_arguments)]

use anyhow::Context as _;

mod actions;
mod agent;
mod daemon;
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

    let no_daemonize = if let Some(arg) = std::env::args().nth(1) {
        arg == "--no-daemonize"
    } else {
        false
    };

    let startup_ack = if no_daemonize {
        None
    } else {
        Some(daemon::daemonize().context("failed to daemonize")?)
    };

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

const PR_SET_DUMPABLE: i32 = 4;

#[cfg(target_os = "linux")]
fn disable_tracing() {
    let ret = unsafe { libc::prctl(PR_SET_DUMPABLE, 0) };
    if ret != 0 {
        println!("rbw-agent: Failed to disable PTRACE_ATTACH. Agent memory may be dumpable by other processes.");
    }
}

#[cfg(not(target_os = "linux"))]
fn disable_tracing() {
    println!("rbw-agent: Unable to disable PTRACE_ATTACH on this platform: not implemented. Agent memory may be dumpable by other processes.");
}

fn main() {
    // Prevent other user processes from attaching to the rbw agent and dumping memory
    // This is not perfect protection, but closes a door. Unfortunately, prctl only works
    // on Linux.
    disable_tracing();
    let res = real_main();

    if let Err(e) = res {
        // XXX log file?
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}
