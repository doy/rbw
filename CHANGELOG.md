# Changelog

## Unreleased

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
