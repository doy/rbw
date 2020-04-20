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
        .about("Unofficial Bitwarden CLI")
        .author(clap::crate_authors!())
        .version(clap::crate_version!())
        .subcommand(
            clap::SubCommand::with_name("config")
                .about("Get or set configuration options")
                .subcommand(
                    clap::SubCommand::with_name("show").about(
                        "Show the values of all configuration settings",
                    ),
                )
                .subcommand(
                    clap::SubCommand::with_name("set")
                        .about("Set a configuration option")
                        .arg(
                            clap::Arg::with_name("key")
                                .required(true)
                                .help("Configuration key to set"),
                        )
                        .arg(
                            clap::Arg::with_name("value")
                                .required(true)
                                .help(
                                "Value to set the configuration option to",
                            ),
                        ),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("login")
                .about("Log in to the Bitwarden server"),
        )
        .subcommand(
            clap::SubCommand::with_name("unlock")
                .about("Unlock the local Bitwarden database"),
        )
        .subcommand(
            clap::SubCommand::with_name("sync")
                .about("Update the local copy of the Bitwarden database"),
        )
        .subcommand(
            clap::SubCommand::with_name("list")
                .about("List all entries in the local Bitwarden database")
                .arg(
                    clap::Arg::with_name("fields")
                        .long("fields")
                        .takes_value(true)
                        .use_delimiter(true)
                        .multiple(true)
                        .help(
                            "Fields to display. \
                            Available options are id, name, user, folder. \
                            Multiple fields will be separated by tabs.",
                        ),
                )
                .visible_alias("ls"),
        )
        .subcommand(
            clap::SubCommand::with_name("get")
                .about("Display the password for a given entry")
                .arg(
                    clap::Arg::with_name("name")
                        .required(true)
                        .help("Name of the entry to display"),
                )
                .arg(
                    clap::Arg::with_name("user")
                        .help("Username of the entry to display"),
                )
                .arg(
                    clap::Arg::with_name("full").long("full").help(
                        "Display the notes in addition to the password",
                    ),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("add")
                .about("Add a new password to the database")
                .long_about(
                    "Add a new password to the database\n\n\
                    This command will open a text editor to enter \
                    the password and notes. The editor to use is determined \
                    by the value of the $EDITOR environment variable. The \
                    first line will be saved as the password and the \
                    remainder will be saved as a note.",
                )
                .arg(
                    clap::Arg::with_name("name")
                        .required(true)
                        .help("Name of the password entry"),
                )
                .arg(
                    clap::Arg::with_name("user")
                        .help("Username for the password entry"),
                )
                .arg(
                    clap::Arg::with_name("uri")
                        .long("uri")
                        .takes_value(true)
                        .multiple(true)
                        .number_of_values(1)
                        .use_delimiter(false)
                        .help("URI for the password entry"),
                )
                .arg(
                    clap::Arg::with_name("folder")
                        .long("folder")
                        .takes_value(true)
                        .help("Folder for the password entry"),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("generate")
                .about("Generate a new password")
                .long_about(
                    "Generate a new password\n\n\
                    If given a password entry name, also save the generated \
                    password to the database.",
                )
                .arg(
                    clap::Arg::with_name("len")
                        .required(true)
                        .help("Length of the password to generate"),
                )
                .arg(
                    clap::Arg::with_name("name")
                        .help("Name of the password entry"),
                )
                .arg(
                    clap::Arg::with_name("user")
                        .help("Username for the password entry"),
                )
                .arg(
                    clap::Arg::with_name("uri")
                        .long("uri")
                        .takes_value(true)
                        .multiple(true)
                        .number_of_values(1)
                        .use_delimiter(false)
                        .help("URI for the password entry"),
                )
                .arg(
                    clap::Arg::with_name("folder")
                        .long("folder")
                        .takes_value(true)
                        .help("Folder for the password entry"),
                )
                .arg(
                    clap::Arg::with_name("no-symbols")
                        .long("no-symbols")
                        .help(
                            "Generate a password with no special characters",
                        ),
                )
                .arg(
                    clap::Arg::with_name("only-numbers")
                        .long("only-numbers")
                        .help(
                            "Generate a password consisting of only numbers",
                        ),
                )
                .arg(
                    clap::Arg::with_name("nonconfusables")
                        .long("nonconfusables")
                        .help(
                            "Generate a password without visually similar \
                            characters (useful for passwords intended to be \
                            written down)",
                        ),
                )
                .arg(clap::Arg::with_name("diceware").long("diceware").help(
                    "Generate a password of multiple dictionary \
                    words chosen from the EFF word list. The len \
                    parameter for this option will set the number \
                    of words to generate, rather than characters.",
                ))
                .group(clap::ArgGroup::with_name("password-type").args(&[
                    "no-symbols",
                    "only-numbers",
                    "nonconfusables",
                    "diceware",
                ]))
                .visible_alias("gen"),
        )
        .subcommand(
            clap::SubCommand::with_name("edit")
                .about("Modify an existing password")
                .long_about(
                    "Modify an existing password\n\n\
                    This command will open a text editor with the existing \
                    password and notes of the given entry for editing. \
                    The editor to use is determined  by the value of the \
                    $EDITOR environment variable. The first line will be \
                    saved as the password and the remainder will be saved \
                    as a note.",
                )
                .arg(
                    clap::Arg::with_name("name")
                        .required(true)
                        .help("Name of the password entry"),
                )
                .arg(
                    clap::Arg::with_name("user")
                        .help("Username for the password entry"),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("remove")
                .about("Remove a given entry")
                .arg(
                    clap::Arg::with_name("name")
                        .required(true)
                        .help("Name of the password entry"),
                )
                .arg(
                    clap::Arg::with_name("user")
                        .help("Username for the password entry"),
                )
                .visible_alias("rm"),
        )
        .subcommand(
            clap::SubCommand::with_name("history")
                .about("View the password history for a given entry")
                .arg(
                    clap::Arg::with_name("name")
                        .required(true)
                        .help("Name of the password entry"),
                )
                .arg(
                    clap::Arg::with_name("user")
                        .help("Username for the password entry"),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("lock")
                .about("Lock the password database"),
        )
        .subcommand(
            clap::SubCommand::with_name("purge")
                .about("Remove the local copy of the password database"),
        )
        .subcommand(
            clap::SubCommand::with_name("stop-agent")
                .about("Terminate the background agent")
                .visible_alias("logout"),
        )
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
            smatches.value_of("folder"),
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
                    smatches.value_of("folder"),
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
