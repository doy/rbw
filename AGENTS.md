# Repository Guidelines

## Project Structure & Module Organization
The core crate lives in `src/`, with `lib.rs` wiring modules such as `actions.rs`, `api.rs`, and `protocol.rs`. CLI entry points live under `src/bin/`: `rbw` hosts the command-line interface, and `rbw-agent` runs the background unlocker. Helper scripts in `bin/` (for example `git-credential-rbw` and `rbw-fzf`) integrate with external tooling. Shared traits and type aliases flow through `src/prelude.rs`; import from there to keep signatures aligned. Asset tooling like `tools/generate_wordlist` supports the password generator pipeline.

## Build, Test, and Development Commands
Use `cargo build` for local compilation and `cargo run --bin rbw -- list --fields=id,name,user,folder,type` for a quick smoke check (also exposed as `just ls`). `cargo check` offers fast diagnostics. Reach for `make build` or `make release` when you need musl-target binaries, and `make test` to exercise tests against that target. Keep `cargo clippy --all-targets --all-features` and `cargo fmt` clean before committing.

## Coding Style & Naming Conventions
Rustfmt defaults (4-space indentation, trailing commas) apply; run `cargo fmt` before review. Clippy runs with pedantic and nursery groups enabled via `Cargo.toml`, so resolve warnings unless explicitly allowed. Functions, modules, and files use `snake_case`; types stay `CamelCase`, constants `SCREAMING_SNAKE_CASE`. Favor `anyhow::Result` and the helpers in `src/error.rs` for error propagation, and keep stateful components in `locked.rs` or `config.rs` rather than spreading logic into binaries.

## Testing Guidelines
Tests sit beside the code inside `#[cfg(test)]` modules. Name cases after the behavior (`stores_master_key_on_unlock`). `cargo test` covers day-to-day work; add `RUST_BACKTRACE=1` when debugging. Before release work, run `make test` to mirror the packaged musl target. Stub HTTP flows with the protocol helpers instead of hitting Bitwarden services.

## Commit & Pull Request Guidelines
Commit history favors short imperative subjects ("Add option to display entry type"). Group mechanical formatting into separate commits. PRs should summarize intent, highlight affected paths (`src/bin/rbw`, `src/config.rs`, etc.), and list the commands executed. Link issues or changelog entries and include CLI screenshots when output changes.

## Security & Configuration Tips
Never log decrypted secrets handled by the agent or credential helpers. Document new configuration keys in `README.md` and validate them in `config.rs`. When adding dependencies, run `cargo deny check` to satisfy the policies codified in `deny.toml`.

## Local PIN unlock implementation status

### Implemented
- Core wrapping flow uses XChaCha20-Poly1305 with Argon2id/HMAC-derived KEK and per-profile pepper stored in the OS keyring (`src/local_unlock.rs`).
- Basic agent/CLI commands exist for `pin set`, `pin unlock`, `pin clear`, and `pin status`, with fail-count bookkeeping persisted alongside the local secret (`src/bin/rbw-agent/actions.rs`, `src/bin/rbw/commands.rs`).
- Blob metadata captures version, AEAD, profile, counter, created-at timestamp, nonce, salt, and the selected KDF parameters; writes occur via an atomic tmp-then-rename helper (`src/local_unlock.rs`).
- TTL enforcement defaults to 30 days and the cache is automatically cleared after three incorrect PIN attempts.

### Outstanding work
- Add remaining metadata fields (e.g., explicit AEAD context notes) plus canonical AAD validation and unknown-field rejection.
- Explore hardware-backed binding (TPM/Secure Enclave) for stronger portability restrictions without reintroducing complex policy knobs.
- Extend status reporting with keyring backend strength and TTL/expiry details; surface weak-backend warnings and policy gating.
- Harden storage by synchronizing the parent directory (fsync), introducing a cross-process file lock around writes, and re-reading post-rename to verify permissions/structure.
- Add unit/integration tests and fuzz guards for blob tampering, plus concurrency tests around rewrap/rollback handling.
