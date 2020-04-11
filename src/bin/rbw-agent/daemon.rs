pub struct StartupAck {
    writer: std::os::unix::io::RawFd,
}

impl StartupAck {
    pub fn ack(&self) {
        nix::unistd::write(self.writer, &[0]).unwrap();
        nix::unistd::close(self.writer).unwrap();
    }
}

impl Drop for StartupAck {
    fn drop(&mut self) {
        nix::unistd::close(self.writer).unwrap();
    }
}

pub fn daemonize() -> StartupAck {
    let runtime_dir = rbw::dirs::runtime_dir();
    std::fs::create_dir_all(&runtime_dir).unwrap();

    let (r, w) = nix::unistd::pipe().unwrap();
    let res = daemonize::Daemonize::new()
        .pid_file(runtime_dir.join("pidfile"))
        .exit_action(move || {
            nix::unistd::close(w).unwrap();
            let mut buf = [0; 1];
            nix::unistd::read(r, &mut buf).unwrap();
            nix::unistd::close(r).unwrap();
        })
        .start();
    nix::unistd::close(r).unwrap();

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

    StartupAck { writer: w }
}
