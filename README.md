# rbw-ng

`rbw-ng` is a maintained continuation of [`rbw`](https://github.com/doy/rbw),
the unofficial command line client for [Bitwarden](https://bitwarden.com/).
It is a drop-in replacement: the commands are still `rbw` and `rbw-agent`, and
it reads the same configuration and local database, so switching needs no
setup.

Although Bitwarden does come with its own
[command line client](https://help.bitwarden.com/article/cli/), it is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. `rbw` avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Why this fork

`rbw` has had no commits since its 1.15.0 release in December 2025, while
Bitwarden and Vaultwarden kept changing. Fixes piled up as unmerged pull
requests (see the [maintainership
discussion](https://github.com/doy/rbw/issues/338)). `rbw-ng` merges the ones
that hold up to review, fixes what is still broken, and keeps up with server
changes. Contributors' commits are kept with their authorship.

Compared to `rbw` 1.15.0, it adds:

* Touch ID unlock on macOS, backed by a Secure Enclave key that never leaves
  the chip (see [Touch ID](#touch-id)).
* Touch ID approval before each SSH signature on macOS, with the requesting
  program named in the prompt.
* Fixes for `rbw edit` corrupting items that have their own encryption key,
  for edits refused by the server, for `rbw add` and `rbw edit` on
  Vaultwarden 1.37, and for requests that ignored `client_cert_path`.
* Dependency updates for the RustSec advisories open against `rbw`.

The full list is in the [changelog](CHANGELOG.md). Bug reports and pull
requests are welcome, including ones first opened against `rbw`.

## Installation

`rbw-ng` is not packaged yet. With a working Rust installation, install it
from this repository:

```sh
cargo install --locked --git https://github.com/TimotheFCN/rbw-ng
```

This installs the `rbw` and `rbw-agent` binaries. If `rbw` is already
installed from a package manager, remove it first (or make sure
`~/.cargo/bin` comes first in your `PATH`), then run `rbw stop-agent` so the
new agent starts.

Password prompts need a
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program. On macOS, install `pinentry-mac` and point `rbw` at it:

```sh
brew install pinentry-mac
rbw config set pinentry pinentry-mac
```

## Configuration

Configuration options are set using the `rbw config` command. Available
configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `sso_id`: The SSO organization ID. Defaults to regular login process if unset.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `ui_url`: The URL of the Bitwarden UI to use. If unset,
  will default to `https://vault.bitwarden.com/`.
* `notifications_url`: The URL of the Bitwarden notifications server to use.
  If unset, will use the `/notifications` path on the configured `base_url`,
  or `https://notifications.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: The number of seconds to keep the master keys in memory before
  requiring the database to be unlocked again. Defaults to `3600` (one hour).
* `sync_interval`: `rbw` will automatically sync the database from the server
  at an interval of this many seconds, while the agent is running. Setting
  this value to `0` disables this behavior. Defaults to `3600` (one hour).
* `pinentry`: The
  [pinentry](https://www.gnupg.org/related_software/pinentry/index.html)
  executable to use. Defaults to `pinentry`.
* `touch_id_unlock`: On macOS, allow Touch ID to unlock the database again
  after the master password has unlocked it once in the current agent process.
  The Secure Enclave key and wrapped vault key are kept only in memory and are
  discarded when the agent exits. Defaults to `false`.
* `touch_id_ssh`: On macOS, ask for Touch ID before the SSH agent signs
  anything. Defaults to `false`.

### Profiles

`rbw` supports different configuration profiles, which can be switched
between by using the `RBW_PROFILE` environment variable. Setting it to a name
(for example, `RBW_PROFILE=work` or `RBW_PROFILE=personal`) can be used to
switch between several different vaults - each will use its own separate
configuration, local vault, and agent.

## Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will run `rbw unlock` to
unlock the password database before generating the list of entries (but will
not attempt to log in to the server), `rbw sync` will automatically run `rbw
login` to log in to the server before downloading the password database (but
will not unlock the database), and `rbw add` will do both.

Logging into the server and unlocking the database will only be done as
necessary, so running `rbw login` when you are already logged in will do
nothing, and similarly for `rbw unlock`. If necessary, you can explicitly log
out by running `rbw purge`, and you can explicitly lock the database by running
`rbw lock` or `rbw stop-agent`.

`rbw help` can be used to get more information about the available
functionality.

### Touch ID

On macOS, `rbw` can use Touch ID to unlock the database again after it has been
unlocked once with the master password in the current agent process. Enable it
with:

```sh
rbw config set touch_id_unlock true
```

The first unlock after enabling this setting, rebooting, or running `rbw
stop-agent` still requires the master password. During that agent process,
automatic timeout and `rbw lock` discard the decrypted vault keys but allow the
next unlock to use Touch ID. `rbw purge`, a logout notification from the server,
or a change to the account's protected vault key also discards the Touch ID
session.

The private key is generated in the Secure Enclave and is not exportable. Both
it and the wrapped vault key exist only for the lifetime of `rbw-agent`; no
master password or additional vault key material is written to disk. Entries
configured to require master password reprompt continue to require the master
password.

The SSH agent can also ask before every signature:

```sh
rbw config set touch_id_ssh true
```

The prompt names the key and the program asking for it, for example "sign
with the SSH key "github" for ssh (pid 4242), started by git". Touch ID, a
paired Apple Watch or the login password can approve it, so this also works
with the lid closed. If nobody approves, the signature is refused. With both
settings on and a locked database, the first signature asks twice: once to
unlock the database and once to approve the signature.

Run `rbw get <name>` to get your passwords. If you also want to get the username
or the note associated, you can use the flag `--full`. You can also use the flag
`--field={field}` to get whatever default or custom field you want. The `--raw`
flag will show the output as JSON. In addition to matching against the name,
you can pass a UUID as the name to search for the entry with that id, or a
URL to search for an entry with a matching website entry.

*Note to users of the official Bitwarden server (at bitwarden.com)*: The
official server has a tendency to detect command line traffic as bot traffic
(see [this issue](https://github.com/bitwarden/cli/issues/383) for details). In
order to use `rbw` with the official Bitwarden server, you will need to first
run `rbw register` to register each device using `rbw` with the Bitwarden
server. This will prompt you for your personal API key which you can find using
the instructions [here](https://bitwarden.com/help/article/personal-api-key/).

### SSH Agent

`rbw-agent` includes a built-in SSH agent for signing SSH authentication
challenges directly. To use it, ensure that rbw is running (in order to make
it start handling ssh agent requests), and then point your SSH client to the
SSH agent socket:

```sh
rbw unlock
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent-socket"
```

If you're using a profile, the socket will be located at
`"XDG_RUNTIME_DIR/rbw-<profile>/ssh-agent-socket"`.

macOS has no `XDG_RUNTIME_DIR`, so the socket is in the per-user temporary
directory instead:

```sh
export SSH_AUTH_SOCK="${TMPDIR%/}/rbw-$(id -u)/ssh-agent-socket"
```

To approve each signature with Touch ID, see [Touch ID](#touch-id).

### 2FA support

`rbw` supports the following 2FA mechanisms :

* Email
* Authenticator App
* Yubico OTP security key (https://support.yubico.com/hc/en-us/articles/360013712639-Testing-Yubico-OTP)

WebAuthn / Passkey and Duo security are unsupported 2FA mechanisms.

If you use only unsupported 2FA mechanism, you need to add a supported 2FA
mechanism on your bitwarden account to use rbw. It allows you to use rbw
with a supported mechanism, and use other clients with you preferred
2FA mechanism.

## Related projects

* [rofi-rbw](https://github.com/fdw/rofi-rbw): A rofi frontend for Bitwarden
* [bw-ssh](https://framagit.org/Glandos/bw-ssh/): Manage SSH key passphrases in Bitwarden
* [rbw-menu](https://github.com/rbuchberger/rbw-menu): Tiny menu picker for rbw
* [ulauncher-rbw](https://0xacab.org/varac-projects/ulauncher-rbw): [Ulauncher](https://ulauncher.io/) rbw extension
* [fuzzel-rbw](https://github.com/sammhansen/fuzzel-rbw): A fuzzel frontend for Bitwarden
