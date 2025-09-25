# Local PIN Unlock Context

## Design Snapshot
- Trust anchor: per-profile `local-secret@v1` and `pin-metadata@v1` stored in the OS keyring under `rbw/<profile>/pin` service namespace.
- Envelope encryption: derive a KEK from the user PIN and local secret via Argon2id; encrypt the 64-byte master DEK (`locked::Keys`) with XChaCha20-Poly1305; authenticate deterministic metadata as AEAD AAD.
- Wrapped blob (`wrapped_master.v1.json`): versioned JSON with nonce, salt, Argon2 parameters, profile context, creation timestamp, monotonically increasing counter, and ciphertext. Atomic write (0600) ensures crash-safe updates.
- Unlock flow: load blob + keyring state, derive KEK, decrypt DEK, hydrate agent key cache without server contact. On failure, increment fail count and clear the cache after three bad attempts.
- Lifecycle: `pin set` wraps current keys; `pin unlock` unwraps; `pin status` inspects metadata; `pin clear` removes blob and keyring entries. Future extensions: richer TTL policy, hardware-backed binding, backend classification.

## Implementation So Far
- `src/local_unlock.rs`: handles set/unlock/clear/status with peppered Argon2id KDFs, XChaCha20-Poly1305 sealing, atomic writes guarded by fsync + lock files, TTL-aware metadata, rollback rewraps, and fail-count tracking that clears the cache after three incorrect PINs.
- `src/protocol.rs`: IPC actions/responses expose the PIN status payload (expiry, kdf params, keyring info).
- `src/bin/rbw-agent/actions.rs`: pinentry loop surfaces expiry/backend errors and reports when the PIN cache is cleared after repeated failures.
- `src/bin/rbw/commands.rs` & `main.rs`: CLI subcommands report expiry/keyring data.
- `src/config.rs`: introduces `pin_unlock` policy toggles (`enabled`, `ttl_secs`, `allow_weak_keyring`).
- `README.md`: documents TTL, fail-count reset behaviour, and policy knobs; `LOCAL_PIN_CONTEXT.md` tracks state.
- Tests (`local_unlock::tests`) cover TTL arithmetic, AAD tamper detection, and policy floor enforcement; `cargo test aad_binding_detects_metadata_changes` runs during development.

## Outstanding Work
- Improve keyring backend classification (Secret Service vs file fallbacks) and consider surfacing warnings for unknown backends.
- Provide a user-facing command to reset fail counters without clearing the PIN (if product wants it) and improve messaging around automatic clears.
- Extend automated tests to cover fail-count driven deletion and simulated rollback races (requires keyring mocking).
- Evaluate cross-platform behaviour for the `.lock` file strategy (Windows testing still pending).
- Add release notes / CHANGELOG entries once the feature stabilises.

## Issues to fix
- none logged; manual regression once Windows keyring coverage lands.
