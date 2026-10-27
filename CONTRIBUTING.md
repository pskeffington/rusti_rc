# Contributing to rusti_rc

Contributions are welcome as focused, reviewable modules, but **no feature is approved for field deployment merely because it compiles**.

## Core rules

1. Keep all `crates/rusti-*` modules dependency-light, default inactive, `#![forbid(unsafe_code)]`, and Rust 2021-compatible; current MSRV target is 1.70. Any MSRV increase requires a documented compatibility assessment.
2. Every parser, transport, certificate, key-store, listener, or installer change needs its own threat model and negative tests. Include malformed, oversized, unsafe, disconnected, old-system and rollback cases as appropriate.
3. Keep untrusted IRC fields separate from Rust Boy identities. Do not link nickname/account/channel to Vault Command, tasks, jobs, assignments or peer trust.
4. Do not copy code from other IRC projects without recording the exact commit, license, attribution, and compatibility with the repository's eventual license choice.
5. No new network I/O, background polling, public bind, credentials, DCC, file upload or auto-discovery in a crate initializer. Explicit operator opt-in remains mandatory.
6. Do not weaken TLS/certificate validation for old machines. Use a separately reviewed, isolated gateway if a device cannot meet security requirements.
7. Add unit/property/fuzz tests and reproducible toolchain/per-target evidence; runtime hardware claims must show real measurements and device model/OS/ABI.
8. Keep release bundle signatures, trust-root provisioning, metadata expiry, version floors, backup, migration and rollback independently reviewed. Do not add an unsigned 'emergency' shortcut.
9. Keep tests and fixtures synthetic. No operator journals, location records, user credentials, PHI, tokens or host keys committed or printed.
10. Until a license is selected, avoid publishing crates or redistributing derived binaries.

## Development smoke

```sh
cargo test --workspace --all-targets
cargo run -p rusti-standalone-cli
```

The tests are offline and the CLI smoke does not connect to any server. Verify against Rust 1.70 as well as stable; the GitHub CI workflow is the automation scaffold.

Review [compatibility](docs/deployment/LEGACY_COMPATIBILITY.md), [integration](docs/integration/RUST_BOY_ADAPTER_CONTRACT.md) and [release checklist](docs/security/RELEASE_CHECKLIST.md).
