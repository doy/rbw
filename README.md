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
* Approval before each SSH signature, with Touch ID on macOS and a pinentry
  dialog elsewhere, naming the key and the requesting program (see
  [Approving SSH signatures](#approving-ssh-signatures)).
* Fixes for `rbw edit` corrupting items that have their own encryption key,
  for edits refused by the server, for `rbw add` and `rbw edit` on
  Vaultwarden 1.37, and for requests that ignored `client_cert_path`.
* `rbw add --secure-note`, custom fields on new entries, and `rbw edit
  --field` to change a single field (see [Adding and editing
  entries](#adding-and-editing-entries)).
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
* `pinentry_timeout`: Seconds an unanswered pinentry prompt stays open before
  it is dismissed, or `0` to wait forever. Defaults to `120`.
* `touch_id_unlock`: On macOS, allow Touch ID to unlock the database again
  after the master password has unlocked it once in the current agent process.
  The Secure Enclave key and wrapped vault key are kept only in memory and are
  discarded when the agent exits. Defaults to `false`.
* `ssh_confirm`: Ask before the SSH agent signs anything, with Touch ID on
  macOS and a pinentry dialog elsewhere. See [Approving SSH
  signatures](#approving-ssh-signatures). Defaults to `false`.
* `touch_id_ssh`: Deprecated name for `ssh_confirm`, from 1.17.0. A config
  file with `touch_id_ssh` set to `true` keeps asking, and setting or unsetting
  it with `rbw config` sets `ssh_confirm` instead.
* `client_cert_path`: Path to a PEM file holding a client certificate and its
  private key, for servers that require mutual TLS. Unset by default.
* `extra_headers`: HTTP headers to send with every request to the server,
  for a server behind Cloudflare Access or another proxy that checks a
  header. See [Extra HTTP headers](#extra-http-headers). Unset by default.

### Extra HTTP headers

`extra_headers` adds headers to every request `rbw` sends to the server: the
API, identity and notifications URLs, including the notifications websocket.
The SSO login page opens in your browser, which doesn't send them. Set one
header per command:

```sh
rbw config set extra_headers.CF-Access-Client-Id 0123abcd.access
rbw config set extra_headers.CF-Access-Client-Secret 0123456789abcdef
rbw config unset extra_headers.CF-Access-Client-Secret  # remove one
rbw config unset extra_headers                          # remove all
```

In the config file they are an object of names and values:

```json
"extra_headers": {
  "CF-Access-Client-Id": "0123abcd.access",
  "CF-Access-Client-Secret": "0123456789abcdef"
}
```

Header names are case-insensitive, so setting a header again under another
spelling replaces it. Headers that `rbw` sets itself or that belong to the
connection can't be set: `Authorization`, `Auth-Email`, `Content-Type`,
`Content-Length`, `Device-Type`, `Host`, `User-Agent`, `Bitwarden-*`, the
connection headers (`Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`,
`Trailer`, `Transfer-Encoding`, `Upgrade`) and `Sec-WebSocket-*`. A proxy that
wants HTTP basic authentication in `Authorization` can't work, since the
Bitwarden API uses that header; `Proxy-Authorization` and `Cookie` are allowed.
An invalid or reserved header is refused by `rbw config set`, and if one is
written into the file by hand, commands that contact the server fail with an
error naming it.

The values are stored in plain text in the config file, like the rest of the
configuration, and `rbw config show` prints them. `rbw` makes the config file
readable only by its owner once it holds extra headers. A value given to
`rbw config set` also ends up in your shell history.

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

The SSH agent can also ask for Touch ID before every signature, see
[Approving SSH signatures](#approving-ssh-signatures).

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

### Adding and editing entries

`rbw add <name> [user]` creates a login. It opens the editor for the password
(the first line) and notes (the rest), or reads them from stdin when stdin is
not a terminal. `--uri` (repeatable) and `--folder` set the login's URIs and
folder. With `--secure-note`, it creates a secure note instead, and the editor
contents or stdin become the note; a secure note has no username or URIs, so
`--secure-note` can't be combined with them.

`--field NAME=VALUE` adds a text custom field and `--hidden-field NAME=VALUE` a
hidden one. Both can be repeated. The name ends at the first `=`, so values can
contain `=`, and each name can only be given once.

Values given as arguments end up in your shell history and, while `rbw` runs,
are visible to other users of the machine through `ps`. For secrets, create the
entry first and then add the field with `rbw edit --field`, which reads the
value from the editor or stdin:

```sh
rbw add example
rbw edit example --field api_token --create   # opens the editor
printf '%s' "$TOKEN" | rbw edit example --field api_token --create
```

`rbw edit <name>` opens the editor with the password and notes of a login, or
the notes of a secure note. `rbw edit <name> --field <field>` changes one field
instead: `name`, `notes`, a login's `username`, `password`, `totp` or `uris`
(one per line), or a custom field of any entry except an SSH key. A custom
field is found by its exact name, or else by a name that differs only in case;
the built-in names take precedence, as with `rbw get --field`. When stdin is a
terminal, the editor opens with the current value; otherwise the value is read
from stdin as is, without one trailing newline. `--create` adds the custom
field as a hidden field if the entry doesn't have it. Boolean fields take
`true` or `false`, and linked fields can't be edited.

Changing a password moves the old one to the password history (`rbw history`).
Before saving an edit, `rbw` fetches the entry from the server and keeps what
it doesn't manage itself, such as the favorite and master password reprompt
settings, passkeys and URI checksums. `rbw edit` syncs before opening the
editor, so it starts from the entry's current version.

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

#### Approving SSH signatures

The SSH agent can ask before every signature, so a program that reaches the
agent socket (or a forwarded agent on another machine) can't use your keys
without you noticing:

```sh
rbw config set ssh_confirm true
```

The prompt names the key, after its entry in the vault, and the program asking
for it, for example "Allow ssh (pid 4242), started by git to sign with the SSH
key "github"?". The program name comes from the process itself, which can call
itself anything, so take it as a hint rather than proof.

On macOS, Touch ID, a paired Apple Watch or the login password approves the
signature, so this also works with the lid closed. Elsewhere, the configured
`pinentry` shows an Allow/Deny dialog. Like the unlock prompt of the SSH agent,
it uses the display and terminal of the last `rbw` command, skipping a terminal
that has since been closed, and is dismissed after `pinentry_timeout` seconds.
A terminal pinentry such as `pinentry-curses` can only ask on a terminal that
is still open, so a graphical pinentry works better here.

Only an explicit approval signs. Denying, closing the dialog, a timeout, or a
pinentry that can't be shown refuse the signature, and the SSH client reports
that the agent refused. Requests that arrive while a prompt is open wait for
it, one prompt at a time. With a locked database, the first signature asks
twice: once to unlock the database and once to approve the signature.

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
