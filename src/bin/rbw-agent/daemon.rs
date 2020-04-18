use anyhow::Context as _;

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
    let runtime_dir = rbw::dirs::runtime_dir();
    std::fs::create_dir_all(&runtime_dir)
        .context("failed to create runtime directory")?;

    let data_dir = rbw::dirs::data_dir();
    std::fs::create_dir_all(&data_dir)
        .context("failed to create data directory")?;
    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(data_dir.join("agent.out"))?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(data_dir.join("agent.err"))?;

    let (r, w) = nix::unistd::pipe()?;
    let res = daemonize::Daemonize::new()
        .pid_file(runtime_dir.join("pidfile"))
        .stdout(stdout)
        .stderr(stderr)
        .exit_action(move || {
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            let _ = nix::unistd::close(w);
            let mut buf = [0; 1];
            nix::unistd::read(r, &mut buf).unwrap();
            nix::unistd::close(r).unwrap();
        })
        .start();
    let _ = nix::unistd::close(r);

    match res {
        Ok(_) => (),
        Err(e) => {
            match e {
                daemonize::DaemonizeError::LockPidfile(_) => {
                    // this means that there is already an agent running, so
                    // return a special exit code to allow the cli to detect
                    // this case and not error out
                    std::process::exit(23);
                }
                _ => panic!("failed to daemonize: {}", e),
            }
        }
    }

    Ok(StartupAck { writer: w })
}
