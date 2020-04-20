# rbw

This is an unofficial command line client for
[Bitwarden](https://bitwarden.com/). Although it does come with its own
[command line client](https://help.bitwarden.com/article/cli/), this client is
limited by being stateless - to use it, you're required to manually lock and
unlock the client, and pass the temporary keys around in environment variables,
which makes it very difficult to use. This client avoids this problem by
maintaining a background process which is able to hold the keys in memory,
similar to the way that `ssh-agent` or `gpg-agent` work. This allows the client
to be used in a much simpler way, with the background agent taking care of
maintaining the necessary state.

## Requirements

This program relies on the
[`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)
program for password prompts.

## Configuration

Configuration options are set using the `rbw config` command. Available
configuration options:

* `email`: The email address to use as the account name when logging into the
  Bitwarden server. Required.
* `base_url`: The URL of the Bitwarden server to use. Defaults to the official
  server at `https://api.bitwarden.com/` if unset.
* `identity_url`: The URL of the Bitwarden identity server to use. If unset,
  will use the `/identity` path on the configured `base_url`, or
  `https://identity.bitwarden.com/` if no `base_url` is set.
* `lock_timeout`: The number of seconds to keep the master keys in memory for
  before requiring the password to be entered again. Defaults to `3600` (one
  hour).

## Usage

Commands can generally be used directly, and will handle logging in or
unlocking as necessary. For instance, running `rbw ls` will unlock the password
database before generating the list of entries (but will not attempt to log in
to the server), `rbw sync` will log in to the server before downloading the
password database (but will not unlock the database), and `rbw generate` will
do both.

`rbw help` can be used to get more information about the available
functionality.
