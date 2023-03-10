pub struct StartupAck {
    writer: std::os::unix::io::RawFd,
}

impl StartupAck {
    pub fn ack(&self) -> anyhow::Result<()> {
        nix::unistd::write(self.writer, &[0])?;
        nix::unistd::close(self.writer)?;
        Ok(())
    }
}

impl Drop for StartupAck {
    fn drop(&mut self) {
        // best effort close here, can't do better in a destructor
        let _ = nix::unistd::close(self.writer);
    }
}

pub fn daemonize() -> anyhow::Result<StartupAck> {
    rbw::dirs::make_all()?;

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = nix::unistd::pipe()?;
    let daemonize = daemonize::Daemonize::new()
        .pid_file(rbw::dirs::pid_file())
        .stdout(stdout)
        .stderr(stderr);
    let res = match daemonize.execute() {
        daemonize::Outcome::Parent(_) => {
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            let _ = nix::unistd::close(w);
            let mut buf = [0; 1];
            nix::unistd::read(r, &mut buf).unwrap();
            nix::unistd::close(r).unwrap();
            std::process::exit(0);
        }
        daemonize::Outcome::Child(res) => res,
    };

    let _ = nix::unistd::close(r);

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

    Ok(StartupAck { writer: w })
}
