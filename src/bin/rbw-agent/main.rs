mod actions;
mod agent;
mod daemon;
mod sock;

fn main() {
    env_logger::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let startup_ack = daemon::daemonize();

    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let listener = crate::sock::listen();

        startup_ack.ack();

        let mut agent = crate::agent::Agent::new();
        agent.run(listener.unwrap()).await;
    })
}
