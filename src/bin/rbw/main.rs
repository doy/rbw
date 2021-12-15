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
use std::io::Write as _;
use structopt::StructOpt as _;

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

    #[structopt(
        about = "Register this device with the Bitwarden server",
        long_about = "Register this device with the Bitwarden server\n\n\
            The official Bitwarden server includes bot detection to prevent \
            brute force attacks. In order to avoid being detected as bot \
            traffic, you will need to use this command to log in with your \
            personal API key (instead of your password) first before regular \
            logins will work."
    )]
    Register,

    #[structopt(about = "Log in to the Bitwarden server")]
    Login,

    #[structopt(about = "Unlock the local Bitwarden database")]
    Unlock,

    #[structopt(about = "Check if the local Bitwarden database is unlocked")]
    Unlocked,

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
        #[structopt(help = "Name or UUID of the entry to display")]
        name: String,
        #[structopt(help = "Username of the entry to display")]
        user: Option<String>,
        #[structopt(long, help = "Folder name to search in")]
        folder: Option<String>,
        #[structopt(
            long,
            help = "Display the notes in addition to the password"
        )]
        full: bool,
    },

    #[structopt(about = "Display the authenticator code for a given entry")]
    Code {
        #[structopt(help = "Name or UUID of the entry to display")]
        name: String,
        #[structopt(help = "Username of the entry to display")]
        user: Option<String>,
        #[structopt(long, help = "Folder name to search in")]
        folder: Option<String>,
    },

    #[structopt(
        about = "Add a new password to the database",
        long_about = "Add a new password to the database\n\n\
            This command will open a text editor to enter \
            the password and notes. The editor to use is determined \
            by the value of the $VISUAL or $EDITOR environment variables.
            The first line will be saved as the password and the \
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
        group = structopt::clap::ArgGroup::with_name("password-type").args(&[
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
            $VISUAL or $EDITOR environment variables. The first line \
            will be saved as the password and the remainder will be saved \
            as a note."
    )]
    Edit {
        #[structopt(help = "Name or UUID of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
        #[structopt(long, help = "Folder name to search in")]
        folder: Option<String>,
    },

    #[structopt(about = "Remove a given entry", visible_alias = "rm")]
    Remove {
        #[structopt(help = "Name or UUID of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
        #[structopt(long, help = "Folder name to search in")]
        folder: Option<String>,
    },

    #[structopt(about = "View the password history for a given entry")]
    History {
        #[structopt(help = "Name or UUID of the password entry")]
        name: String,
        #[structopt(help = "Username for the password entry")]
        user: Option<String>,
        #[structopt(long, help = "Folder name to search in")]
        folder: Option<String>,
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
    #[structopt(
        name = "gen-completions",
        about = "Generate completion script for the given shell"
    )]
    GenCompletions { shell: String },
}

impl Opt {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Config { config } => {
                format!("config {}", config.subcommand_name())
            }
            Self::Register => "register".to_string(),
            Self::Login => "login".to_string(),
            Self::Unlock => "unlock".to_string(),
            Self::Unlocked => "unlocked".to_string(),
            Self::Sync => "sync".to_string(),
            Self::List { .. } => "list".to_string(),
            Self::Get { .. } => "get".to_string(),
            Self::Code { .. } => "code".to_string(),
            Self::Add { .. } => "add".to_string(),
            Self::Generate { .. } => "generate".to_string(),
            Self::Edit { .. } => "edit".to_string(),
            Self::Remove { .. } => "remove".to_string(),
            Self::History { .. } => "history".to_string(),
            Self::Lock => "lock".to_string(),
            Self::Purge => "purge".to_string(),
            Self::StopAgent => "stop-agent".to_string(),
            Self::GenCompletions { .. } => "gen-completions".to_string(),
        }
    }
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

impl Config {
    fn subcommand_name(&self) -> String {
        match self {
            Self::Show => "show",
            Self::Set { .. } => "set",
            Self::Unset { .. } => "unset",
        }
        .to_string()
    }
}

#[paw::main]
fn main(opt: Opt) {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((w, _)) = term_size::dimensions() {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, w - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let res = match &opt {
        Opt::Config { config } => match config {
            Config::Show => commands::config_show(),
            Config::Set { key, value } => commands::config_set(key, value),
            Config::Unset { key } => commands::config_unset(key),
        },
        Opt::Register => commands::register(),
        Opt::Login => commands::login(),
        Opt::Unlock => commands::unlock(),
        Opt::Unlocked => commands::unlocked(),
        Opt::Sync => commands::sync(),
        Opt::List { fields } => commands::list(fields),
        Opt::Get {
            name,
            user,
            folder,
            full,
        } => commands::get(name, user.as_deref(), folder.as_deref(), *full),
        Opt::Code { name, user, folder } => {
            commands::code(name, user.as_deref(), folder.as_deref())
        }
        Opt::Add {
            name,
            user,
            uri,
            folder,
        } => commands::add(
            name,
            user.as_deref(),
            &uri.iter()
                // XXX not sure what the ui for specifying the match type
                // should be
                .map(|uri| (uri.clone(), None))
                .collect::<Vec<_>>(),
            folder.as_deref(),
        ),
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
            let ty = if *no_symbols {
                rbw::pwgen::Type::NoSymbols
            } else if *only_numbers {
                rbw::pwgen::Type::Numbers
            } else if *nonconfusables {
                rbw::pwgen::Type::NonConfusables
            } else if *diceware {
                rbw::pwgen::Type::Diceware
            } else {
                rbw::pwgen::Type::AllChars
            };
            commands::generate(
                name.as_deref(),
                user.as_deref(),
                &uri.iter()
                    // XXX not sure what the ui for specifying the match type
                    // should be
                    .map(|uri| (uri.clone(), None))
                    .collect::<Vec<_>>(),
                folder.as_deref(),
                *len,
                ty,
            )
        }
        Opt::Edit { name, user, folder } => {
            commands::edit(name, user.as_deref(), folder.as_deref())
        }
        Opt::Remove { name, user, folder } => {
            commands::remove(name, user.as_deref(), folder.as_deref())
        }
        Opt::History { name, user, folder } => {
            commands::history(name, user.as_deref(), folder.as_deref())
        }
        Opt::Lock => commands::lock(),
        Opt::Purge => commands::purge(),
        Opt::StopAgent => commands::stop_agent(),
        Opt::GenCompletions { shell } => gen_completions(shell),
    }
    .context(format!("rbw {}", opt.subcommand_name()));

    if let Err(e) = res {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}

fn gen_completions(shell: &str) -> anyhow::Result<()> {
    let shell = match shell {
        "bash" => structopt::clap::Shell::Bash,
        "zsh" => structopt::clap::Shell::Zsh,
        "fish" => structopt::clap::Shell::Fish,
        "powershell" => structopt::clap::Shell::PowerShell,
        "elvish" => structopt::clap::Shell::Elvish,
        _ => return Err(anyhow::anyhow!("unknown shell {}", shell)),
    };
    Opt::clap().gen_completions_to("rbw", shell, &mut std::io::stdout());
    Ok(())
}
