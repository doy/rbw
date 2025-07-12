use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;

pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        let mut pidfile = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o666)
            .open(rbw::dirs::pid_file())
            .context("failed to open pid file")?;
        rustix::fs::flock(
            &pidfile,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .context("failed to lock pid file")?;
        writeln!(pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);

        return Ok(None);
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;
    let daemonize = daemonize::Daemonize::new()
        .pid_file(rbw::dirs::pid_file())
        .stdout(stdout)
        .stderr(stderr);
    let res = match daemonize.execute() {
        daemonize::Outcome::Parent(_) => {
            drop(w);
            let mut buf = [0; 1];
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            rustix::io::read(&r, &mut buf).unwrap();
            drop(r);
            std::process::exit(0);
        }
        daemonize::Outcome::Child(res) => res,
    };

    drop(r);

    match res {
        Ok(_) => (),
        Err(e) => {
            // XXX super gross, but daemonize removed the ability to match
            // on specific error types for some reason?
            if e.to_string().contains("unable to lock pid file") {
                // this means that there is already an agent running, so
                // return a special exit code to allow the cli to detect
                // this case and not error out
                std::process::exit(23);
            } else {
                panic!("failed to daemonize: {e}");
            }
        }
    }

    Ok(Some(StartupAck { writer: w }))
}
