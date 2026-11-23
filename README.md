# rbw-ng

`rbw-ng` is a maintained continuation of [`rbw`](https://github.com/doy/rbw),
the unofficial command line client for [Bitwarden](https://bitwarden.com/) and
[Vaultwarden](https://github.com/dani-garcia/vaultwarden). It is a drop-in
replacement. The commands are still `rbw` and `rbw-agent`, and it reads the
same configuration and local database, so switching needs no setup.

The official Bitwarden CLI is stateless. You unlock it, then pass a session key
around in an environment variable for every command. `rbw` runs a background
agent that holds the keys in memory instead, the way `ssh-agent` and
`gpg-agent` do, so `rbw get github` just works until the agent locks again.

`rbw` has had no commits since its 1.15.0 release in December 2025, while
Bitwarden and Vaultwarden kept changing (see the [maintainership
discussion](https://github.com/doy/rbw/issues/338)). `rbw-ng` merges the
pending pull requests that hold up to review, fixes what is still broken and
keeps up with server changes. Contributors' commits keep their authorship.

Documentation lives in the [wiki](https://github.com/TimotheFCN/rbw-ng/wiki).

## Features

* A background agent that keeps the vault unlocked between commands, locks
  after a timeout and syncs on its own.
* Read logins, secure notes, custom fields, TOTP codes and password history.
  Output as text or JSON, or copy to the clipboard.
* Add and edit entries from the editor or stdin, down to a single field with
  `rbw edit --field`.
* A password generator, including diceware passphrases from the EFF word list.
* A built-in SSH agent that serves the SSH keys stored in your vault, and can
  ask before every signature.
* Touch ID unlock on macOS, backed by a Secure Enclave key that never leaves
  the chip.
* Self-hosted servers and Vaultwarden, SSO login, email, authenticator app and
  YubiKey OTP two-factor, client certificates and extra HTTP headers for
  servers behind Cloudflare Access or another proxy.
* Profiles, to use several accounts side by side.

What changed since `rbw` 1.15.0 is in the [changelog](CHANGELOG.md).

## Getting started

### Install

| Platform | Command |
| --- | --- |
| macOS, Linux (Homebrew) | `brew install timothefcn/tap/rbw-ng` |
| Arch Linux (AUR) | `yay -S rbw-ng-bin` |
| Debian, Ubuntu | download the `.deb` from the [latest release](https://github.com/TimotheFCN/rbw-ng/releases/latest), then `sudo apt install ./rbw-ng_*.deb` |
| Any, with Rust 1.88+ | `cargo install --locked rbw-ng` |
| Any, prebuilt | `cargo binstall rbw-ng` |

The [releases page](https://github.com/TimotheFCN/rbw-ng/releases) also has
archives for Linux (x86_64 and arm64, statically linked) and macOS (Intel and
Apple Silicon). The [Installation](https://github.com/TimotheFCN/rbw-ng/wiki/Installation)
page covers each method and building from source.

Coming from `rbw`? Uninstall it first, since both packages install `rbw` and
`rbw-agent`, then run `rbw stop-agent` so the new agent starts. Your
configuration and vault carry over.

`rbw` asks for your master password through
[pinentry](https://www.gnupg.org/related_software/pinentry/). Most Linux
desktops have one installed. On macOS, install `pinentry-mac` and select it:

```sh
brew install pinentry-mac
rbw config set pinentry pinentry-mac
```

### First run

```sh
rbw config set email you@example.com
# Only for a self-hosted server or Vaultwarden:
rbw config set base_url https://vault.example.com

rbw register   # only for bitwarden.com, see below
rbw sync       # log in and download the vault
rbw ls         # list entries, unlocking the vault if needed
rbw get github
rbw get github --field username
rbw code github   # current TOTP code
```

Commands log in and unlock on their own as needed. `rbw lock` locks the vault
and `rbw purge` logs out. `rbw help <command>` describes each command.

The official server at bitwarden.com tends to block command line clients as
bots. Run `rbw register` once per device before logging in. It asks for your
[personal API key](https://bitwarden.com/help/personal-api-key/).

To go further, see
[Configuration](https://github.com/TimotheFCN/rbw-ng/wiki/Configuration),
[the SSH agent](https://github.com/TimotheFCN/rbw-ng/wiki/SSH-agent) and
[Touch ID](https://github.com/TimotheFCN/rbw-ng/wiki/Touch-ID).

## Development

You need Rust 1.88 or newer, and a pinentry to try commands by hand.

```sh
git clone https://github.com/TimotheFCN/rbw-ng
cd rbw-ng
cargo build
cargo test
```

The code is in three parts:

* `src/bin/rbw` is the command line client. It parses arguments and talks to
  the agent over a Unix socket.
* `src/bin/rbw-agent` is the agent. It holds the keys, talks to the server,
  syncs, and runs the SSH agent and the Touch ID prompts.
* `src/` holds the library both share: the API client (`api.rs`), the
  encryption (`cipherstring.rs`, `identity.rs`), the local database (`db.rs`),
  the configuration (`config.rs`) and the agent protocol (`protocol.rs`).

To try a development build without touching your own vault and agent, use a
separate profile and point `rbw` at the agent you just built:

```sh
export RBW_PROFILE=dev RBW_AGENT="$PWD/target/debug/rbw-agent"
target/debug/rbw config set email you@example.com
target/debug/rbw config set base_url http://localhost:8000
target/debug/rbw sync
```

A local [Vaultwarden](https://github.com/dani-garcia/vaultwarden) container
makes a good test server. The agent logs to `~/.local/share/rbw-dev/agent.err`
on Linux.

CI runs these on Linux and macOS. Run them before opening a pull request:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -Dwarnings
cargo test --all-features
cargo deny check   # needs cargo-deny
```

Add a line under the next version in [CHANGELOG.md](CHANGELOG.md) for
anything a user would notice. Pull requests first opened against `rbw` are
welcome too, and keep their author.

Releases are built and published by
[.github/workflows/release.yaml](.github/workflows/release.yaml) when a version
tag is pushed. The [Releasing](https://github.com/TimotheFCN/rbw-ng/wiki/Releasing)
page lists the steps.

## License

MIT. See [LICENSE](LICENSE).
