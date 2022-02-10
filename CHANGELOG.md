# Changelog

## [1.4.3] - 2022-02-10

### Fixed

* Restored packaged scripts to the crate bundle, since they are used by some
  downstream packages (no functional changes) (#81)

## [1.4.2] - 2022-02-10

### Changed

* Device id is now stored in a separate file in the local data directory
  instead of as part of the config (#74)

### Fixed

* Fix api renaming in official bitwarden server (#80)

## [1.4.1] - 2021-10-28

### Added

* `bin/git-credential-rbw` to be used as a
  [git credential helper](https://git-scm.com/docs/gitcredentials#_custom_helpers)
  (#41, xPMo)

### Changed

* Also disable swap and viminfo files when using `EDITOR=nvim` (#70, Dophin2009)

### Fixed

* Properly handle a couple folder name edge cases in `bin/rbw-fzf` (#66,
  mattalexx)
* Support passing command line arguments via `EDITOR`/`VISUAL` (#61, xPMo)

## [1.4.0] - 2021-10-27

### Fixed

* Add `rbw register` to allow `rbw` to work with the official Bitwarden server
  again - see the README for details (#71)

## [1.3.0] - 2021-07-05

### Changed

* Use the system's native TLS certificate store when making HTTP requests.

### Fixed

* Correctly handle TOTP secret strings that copy with spaces (#56, TamasBarta, niki-on-github)

## [1.2.0] - 2021-04-18

### Added

* Shell completion for bash, zsh, and fish (#18)

### Changed

* Prebuilt binaries are now statically linked using musl, to prevent glibc
  version issues once and for all (#47)
* Standardize on RustCrypto in preference to ring or openssl

### Fixed

* `rbw generate` can now choose the same character more than once (#54, rjc)
* Improved handling of password history for entries with no password (#51/#53,
  simias)
* Fix configuring base_url with a trailing slash when using a self-hosted
  version of the official bitwarden server (#49, phylor)

## [1.1.2] - 2021-03-06

### Fixed

* Send warnings about failure to disable PTRACE_ATTACH to the agent logs rather
  than stderr

## [1.1.1] - 2021-03-05

### Fixed

* Fix non-Linux platforms (#44, rjc)

## [1.1.0] - 2021-03-02

### Added

* You can now `rbw config set pinentry pinentry-curses` to change the pinentry
  program used by `rbw` (#39, djmattyg007)

### Changed

* On Linux, the `rbw-agent` process can no longer be attached to by debuggers,
  and no longer produces core dumps (#42, oranenj)
* Suggest rotating the user's encryption key if we see an old cipherstring type
  (#40, rjc)
* Prefer the value of `$VISUAL` when trying to find an editor to run, before
  falling back to `$EDITOR` (#43, rjc)

## [1.0.0] - 2021-02-21

### Added

* Clarified the maintenance policy for this project in the README

### Fixed

* Stop hardcoding /tmp when using the fallback runtime directory (#37, pschmitt)
* Fix `rbw edit` clearing the match detection setting for websites associated
  with the edited password (#34, AdmiralNemo)
  * Note that you will need to `rbw sync` after upgrading and before running
    `rbw edit` in order to correctly update the local database.

## [0.5.2] - 2020-12-02

### Fixed

* `rbw` should once again be usable on systems with glibc-2.28 (such as Debian
  stable).

## [0.5.1] - 2020-12-02

### Fixed

* `rbw code` now always displays the correct number of digits. (#25, Tyilo)
* TOTP secrets can now also be supplied as `otpauth` urls.
* Logging into bitwarden.com with 2fa enabled now works again.

## [0.5.0] - 2020-10-12

### Added

* Add support for cipherstring type 6 (fixes some vaults using an older format
  for organizations data). (Jake Swenson)
* `rbw get --full` now displays URIs, TOTP secrets, and custom fields.
* Add `rbw code` for generating TOTP codes based on secrets stored in
  Bitwarden.
* Add `rbw unlocked` which will exit with success if the agent is unlocked and
  failure if the agent is locked.

### Fixed

* Don't display deleted items (#22, GnunuX)

## [0.4.6] - 2020-07-11

### Fixed

* Login passwords containing a `%` now work properly (albakham).

## [0.4.5] - 2020-07-11

### Fixed

* The pinentry window now no longer times out.

## [0.4.4] - 2020-06-23

### Fixed

* Fix regression in `rbw get` when not specifying a folder.

## [0.4.3] - 2020-06-23

### Added

* `rbw get` now accepts a `--folder` option to pick the folder to search in.

### Changed

* `rbw get --full` now also includes the username. (Jarkko Oranen)

### Fixed

* `rbw` should now be usable on systems with glibc-2.28 (such as Debian
  stable). (incredible-machine)

## [0.4.2] - 2020-05-30

### Fixed

* `rbw` now no longer requires the `XDG_RUNTIME_DIR` environment variable to be
  set.

## [0.4.1] - 2020-05-28

### Fixed

* More improved error messages.

## [0.4.0] - 2020-05-28

### Added

* Authenticator-based two-step login is now supported.

### Fixed

* Correctly handle password retries when entering an invalid password on the
  official Bitwarden server.
* Fix hang when giving an empty string to pinentry.
* The error message from the server is now shown when logging in fails.

## [0.3.5] - 2020-05-25

### Fixed

* Terminal-based pinentry methods should now work correctly (Glandos).
* Further error message improvements.

## [0.3.4] - 2020-05-24

### Fixed

* Handle edge case where a URI entry is set for a cipher but that entry has a
  null URI string (Adrien CLERC).

## [0.3.3] - 2020-05-23

### Fixed

* Set the correct default lock timeout when first creating the config file.
* Add a more useful error when `rbw` is run without being configured first.
* Don't throw an error when attempting to configure the base url before
  configuring the email.
* More improvements to error output.

## [0.3.2] - 2020-05-23

### Fixed

* Improve warning and error output a bit.

## [0.3.1] - 2020-05-23

### Fixed

* Fix option parsing for `rbw list --fields` and `rbw <add|generate> --uri`
  which was inadvertently broken in the previous release.

## [0.3.0] - 2020-05-22

### Fixed

* Better error message if the agent fails to start after daemonizing.
* Always automatically upgrade rbw-agent on new releases.
* Changing configuration now automatically drops in-memory keys (this should
  avoid errors when switching between different servers or accounts).
* Disallow setting `lock_timeout` to `0`, since this will cause the agent to
  immediately drop the decrypted keys before they can be used for decryption,
  even within a single run of the `rbw` client.

## [0.2.2] - 2020-05-17

### Fixed

* Fix syncing from the official Bitwarden server (thanks the_fdw).

### Added

* Added a couple example scripts to the repository for searching using fzf and
  rofi. Contributions and improvements welcome!

## [0.2.1] - 2020-05-03

### Fixed

* Properly maintain folder and URIs when editing an entry.

## [0.2.0] - 2020-05-03

### Added

* Multi-server support - you can now switch between multiple different
  bitwarden servers with `rbw config set base_url` without needing to
  redownload the password database each time.
* `rbw config unset` to reset configuration items back to the default
* `rbw list` and `rbw get` now support card, identity, and secure note entry
  types

### Fixed

* `rbw` is now able to decrypt secrets from organizations you are a member of.
* `rbw stop-agent` now waits for the agent to exit before returning.

### Changed

* Move to the `ring` crate for a bunch of the cryptographic functionality.
* The agent protocol is now versioned, to allow for seamless updates.

## [0.1.1] - 2020-05-01

### Fixed

* Some packaging changes.

## [0.1.0] - 2020-04-20

### Added

* Initial release
