use anyhow::Context as _;

mod actions;
mod commands;
mod sock;

fn main() {
    env_logger::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let matches = clap::App::new("rbw")
        .about("unofficial bitwarden cli")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .subcommand(
            clap::SubCommand::with_name("config")
                .subcommand(clap::SubCommand::with_name("show"))
                .subcommand(
                    clap::SubCommand::with_name("set")
                        .arg(clap::Arg::with_name("key").required(true))
                        .arg(clap::Arg::with_name("value").required(true)),
                ),
        )
        .subcommand(clap::SubCommand::with_name("login"))
        .subcommand(clap::SubCommand::with_name("unlock"))
        .subcommand(clap::SubCommand::with_name("sync"))
        .subcommand(
            clap::SubCommand::with_name("list")
                .arg(
                    clap::Arg::with_name("fields")
                        .long("fields")
                        .takes_value(true)
                        .use_delimiter(true)
                        .multiple(true),
                )
                .alias("ls"),
        )
        .subcommand(
            clap::SubCommand::with_name("get")
                .arg(clap::Arg::with_name("name").required(true))
                .arg(clap::Arg::with_name("user"))
                .arg(clap::Arg::with_name("full").long("full")),
        )
        .subcommand(
            clap::SubCommand::with_name("add")
                .arg(clap::Arg::with_name("name").required(true))
                .arg(clap::Arg::with_name("user"))
                .arg(
                    clap::Arg::with_name("uri")
                        .long("uri")
                        .takes_value(true)
                        .multiple(true)
                        .number_of_values(1)
                        .use_delimiter(false),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("generate")
                .arg(clap::Arg::with_name("len").required(true))
                .arg(clap::Arg::with_name("name"))
                .arg(clap::Arg::with_name("user"))
                .arg(
                    clap::Arg::with_name("uri")
                        .long("uri")
                        .takes_value(true)
                        .multiple(true)
                        .number_of_values(1)
                        .use_delimiter(false),
                )
                .arg(clap::Arg::with_name("no-symbols").long("no-symbols"))
                .arg(
                    clap::Arg::with_name("only-numbers").long("only-numbers"),
                )
                .arg(
                    clap::Arg::with_name("nonconfusables")
                        .long("nonconfusables"),
                )
                .arg(clap::Arg::with_name("diceware").long("diceware"))
                .group(clap::ArgGroup::with_name("password-type").args(&[
                    "no-symbols",
                    "only-numbers",
                    "nonconfusables",
                    "diceware",
                ]))
                .alias("gen"),
        )
        .subcommand(
            clap::SubCommand::with_name("edit")
                .arg(clap::Arg::with_name("name").required(true))
                .arg(clap::Arg::with_name("user")),
        )
        .subcommand(
            clap::SubCommand::with_name("remove")
                .arg(clap::Arg::with_name("name").required(true))
                .arg(clap::Arg::with_name("user"))
                .alias("rm"),
        )
        .subcommand(
            clap::SubCommand::with_name("history")
                .arg(clap::Arg::with_name("name").required(true))
                .arg(clap::Arg::with_name("user")),
        )
        .subcommand(clap::SubCommand::with_name("lock"))
        .subcommand(clap::SubCommand::with_name("purge"))
        .subcommand(clap::SubCommand::with_name("stop-agent").alias("logout"))
        .get_matches();

    let res = match matches.subcommand() {
        ("config", Some(smatches)) => match smatches.subcommand() {
            ("show", Some(_)) => {
                commands::config_show().context("config show")
            }
            // these unwraps are fine because key and value are both marked
            // .required(true)
            ("set", Some(ssmatches)) => commands::config_set(
                ssmatches.value_of("key").unwrap(),
                ssmatches.value_of("value").unwrap(),
            )
            .context("config set"),
            _ => {
                eprintln!("{}", smatches.usage());
                std::process::exit(1);
            }
        },
        ("login", Some(_)) => commands::login().context("login"),
        ("unlock", Some(_)) => commands::unlock().context("unlock"),
        ("sync", Some(_)) => commands::sync().context("sync"),
        ("list", Some(smatches)) => commands::list(
            &smatches
                .values_of("fields")
                .map(|it| it.collect())
                .unwrap_or_else(|| vec!["name"]),
        )
        .context("list"),
        // this unwrap is safe because name is marked .required(true)
        ("get", Some(smatches)) => commands::get(
            smatches.value_of("name").unwrap(),
            smatches.value_of("user"),
            smatches.is_present("full"),
        )
        .context("get"),
        // this unwrap is safe because name is marked .required(true)
        ("add", Some(smatches)) => commands::add(
            smatches.value_of("name").unwrap(),
            smatches.value_of("user"),
            smatches
                .values_of("uri")
                .map(|it| it.collect())
                .unwrap_or_else(|| vec![]),
        )
        .context("add"),
        ("generate", Some(smatches)) => {
            let ty = if smatches.is_present("no-symbols") {
                rbw::pwgen::Type::NoSymbols
            } else if smatches.is_present("only-numbers") {
                rbw::pwgen::Type::Numbers
            } else if smatches.is_present("nonconfusables") {
                rbw::pwgen::Type::NonConfusables
            } else if smatches.is_present("diceware") {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            // this unwrap is fine because len is marked as .required(true)
            let len = smatches.value_of("len").unwrap();
            match len.parse() {
                Ok(len) => commands::generate(
                    smatches.value_of("name"),
                    smatches.value_of("user"),
                    smatches
                        .values_of("uri")
                        .map(|it| it.collect())
                        .unwrap_or_else(|| vec![]),
                    len,
                    ty,
                )
                .context("generate"),
                Err(e) => Err(e.into()),
            }
        }
        // this unwrap is safe because name is marked .required(true)
        ("edit", Some(smatches)) => commands::edit(
            smatches.value_of("name").unwrap(),
            smatches.value_of("user"),
        )
        .context("edit"),
        // this unwrap is safe because name is marked .required(true)
        ("remove", Some(smatches)) => commands::remove(
            smatches.value_of("name").unwrap(),
            smatches.value_of("user"),
        )
        .context("remove"),
        // this unwrap is safe because name is marked .required(true)
        ("history", Some(smatches)) => commands::history(
            smatches.value_of("name").unwrap(),
            smatches.value_of("user"),
        )
        .context("history"),
        ("lock", Some(_)) => commands::lock().context("lock"),
        ("purge", Some(_)) => commands::purge().context("purge"),
        ("stop-agent", Some(_)) => {
            commands::stop_agent().context("stop-agent")
        }
        _ => {
            eprintln!("{}", matches.usage());
            std::process::exit(1);
        }
    }
    .context("rbw");

    if let Err(e) = res {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}
