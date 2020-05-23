#![allow(clippy::large_enum_variant)]

use anyhow::Context as _;
use std::io::Write as _;

mod actions;
mod commands;
mod sock;

#[derive(Debug, structopt::StructOpt)]
#[structopt(about = "Unofficial Bitwarden CLI")]
enum Opt {
    #[structopt(about = "Get or set configuration options")]
    Config {
        #[structopt(subcommand)]
        config: Config,
    },

    #[structopt(about = "Log in to the Bitwarden server")]
    Login,

    #[structopt(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[structopt(about = "Update the local copy of the Bitwarden database")]
    Sync,

    #[structopt(
        about = "List all entries in the local Bitwarden database",
        visible_alias = "ls"
    )]
    List {
        #[structopt(
            long,
            help = "Fields to display. \
                Available options are id, name, user, folder. \
                Multiple fields will be separated by tabs.",
            default_value = "name",
            use_delimiter = true
        )]
        fields: Vec<String>,
    },

    #[structopt(about = "Display the password for a given entry")]
    Get {
        #[structopt(help = "Name of the entry to display")]
        name: String,
        #[structopt(help = "Username of the entry to display")]
        user: Option<String>,
        #[structopt(
            long,
            help = "Display the notes in addition to the password"
        )]
        full: bool,
    },

    #[structopt(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $EDITOR environment variable. The \
            first line will be saved as the password and the \
            remainder will be saved as a note."
    )]
    Add {
        #[structopt(help = "Name of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
        #[structopt(
            long,
            help = "URI for the password entry",
            multiple = true,
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[structopt(long, help = "Folder for the password entry")]
        folder: Option<String>,
    },

    #[structopt(
        about = "Generate a new password",
        long_about = "Generate a new password\n\n\
            If given a password entry name, also save the generated \
            password to the database.",
        visible_alias = "gen",
        group = clap::ArgGroup::with_name("password-type").args(&[
            "no-symbols",
            "only-numbers",
            "nonconfusables",
            "diceware",
        ])
    )]
    Generate {
        #[structopt(help = "Length of the password to generate")]
        len: usize,
        #[structopt(help = "Name of the password entry")]
        name: Option<String>,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
        #[structopt(
            long,
            help = "URI for the password entry",
            multiple = true,
            number_of_values = 1
        )]
        uri: Vec<String>,
        #[structopt(long, help = "Folder for the password entry")]
        folder: Option<String>,
        #[structopt(
            long = "no-symbols",
            help = "Generate a password with no special characters"
        )]
        no_symbols: bool,
        #[structopt(
            long = "only-numbers",
            help = "Generate a password consisting of only numbers"
        )]
        only_numbers: bool,
        #[structopt(
            long,
            help = "Generate a password without visually similar \
                characters (useful for passwords intended to be \
                written down)"
        )]
        nonconfusables: bool,
        #[structopt(
            long,
            help = "Generate a password of multiple dictionary \
                words chosen from the EFF word list. The len \
                parameter for this option will set the number \
                of words to generate, rather than characters."
        )]
        diceware: bool,
    },

    #[structopt(
        about = "Modify an existing password",
        long_about = "Modify an existing password\n\n\
            This command will open a text editor with the existing \
            password and notes of the given entry for editing. \
            The editor to use is determined  by the value of the \
            $EDITOR environment variable. The first line will be \
            saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[structopt(help = "Name of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
    },

    #[structopt(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[structopt(help = "Name of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
    },

    #[structopt(about = "View the password history for a given entry")]
    History {
        #[structopt(help = "Name of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
    },

    #[structopt(about = "Lock the password database")]
    Lock,

    #[structopt(about = "Remove the local copy of the password database")]
    Purge,

    #[structopt(
        name = "stop-agent",
        about = "Terminate the background agent"
    )]
    StopAgent,
}

#[derive(Debug, structopt::StructOpt)]
enum Config {
    #[structopt(about = "Show the values of all configuration settings")]
    Show,
    #[structopt(about = "Set a configuration option")]
    Set {
        #[structopt(help = "Configuration key to set")]
        key: String,
        #[structopt(help = "Value to set the configuration option to")]
        value: String,
    },
    #[structopt(about = "Reset a configuration option to its default")]
    Unset {
        #[structopt(help = "Configuration key to unset")]
        key: String,
    },
}

#[paw::main]
fn main(opt: Opt) {
    env_logger::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        writeln!(buf, "{}: {}", record.level(), record.args())
    })
    .init();

    let res = match opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show().context("config show"),
            Config::Set { key, value } => {
                commands::config_set(&key, &value).context("config set")
            }
            Config::Unset { key } => {
                commands::config_unset(&key).context("config unset")
            }
        },
        Opt::Login => commands::login().context("login"),
        Opt::Unlock => commands::unlock().context("unlock"),
        Opt::Sync => commands::sync().context("sync"),
        Opt::List { fields } => commands::list(&fields).context("list"),
        Opt::Get { name, user, full } => {
            commands::get(&name, user.as_deref(), full).context("get")
        }
        Opt::Add {
            name,
            user,
            uri,
            folder,
        } => commands::add(&name, user.as_deref(), uri, folder.as_deref())
            .context("add"),
        Opt::Generate {
            len,
            name,
            user,
            uri,
            folder,
            no_symbols,
            only_numbers,
            nonconfusables,
            diceware,
        } => {
            let ty = if no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if only_numbers {
                rbw::pwgen::Type::Numbers
            } else if nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                uri,
                folder.as_deref(),
                len,
                ty,
            )
            .context("generate")
        }
        Opt::Edit { name, user } => {
            commands::edit(&name, user.as_deref()).context("edit")
        }
        Opt::Remove { name, user } => {
            commands::remove(&name, user.as_deref()).context("remove")
        }
        Opt::History { name, user } => {
            commands::history(&name, user.as_deref()).context("history")
        }
        Opt::Lock => commands::lock().context("lock"),
        Opt::Purge => commands::purge().context("purge"),
        Opt::StopAgent => commands::stop_agent().context("stop-agent"),
    }
    .context("rbw");

    if let Err(e) = res {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}
