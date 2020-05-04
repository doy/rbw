# Changelog

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
