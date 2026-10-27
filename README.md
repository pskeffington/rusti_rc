# rusti_rc

**Rust-native IRC protocol research and security-gated communications adapter for [Rust Boy](https://github.com/pskeffington/pip_boy).**

**Current state (2026-10-26): an offline-only, disabled-by-default scaffold, not a usable IRC client or server.** No sockets, TLS/SASL sessions, background discovery, persisted messages, server listener, signed installer or Rust Boy imports are implemented. A Rust Boy IRC connection should appear only after the separately documented security, compatibility and operator-consent gates pass.

## Purpose

Build a modular IRC stack, independently distributable for portable Linux and older ARM hardware, with an optional future import into Rust Boy's LINK UI as an **alternative chat path**. An IRC network requires reachable IP and an IRC server: this project does not create a mesh bearer, guarantee delivery, implement E2EE or authenticate Vault Command assignments.

## Source index

| Path | Actual scaffold state |
|---|---|
| [rusti-proto](crates/rusti-proto/src/lib.rs) | Dependency-free bounded IRC line parser and PRIVMSG encoder, offline unit tests; not a complete RFC/IRCv3 implementation |
| [rusti-client](crates/rusti-client/src/lib.rs) | Disabled-by-default TLS-required connection policy; all networking returns not implemented |
| [rusti-server](crates/rusti-server/src/lib.rs) | Disabled-by-default, loopback/TLS/limits policy; no actual listener |
| [rusti-adapter](crates/rusti-adapter/src/lib.rs) | Untrusted read-only IRC chat framing for future Rust Boy import; no Vault/peer privileges |
| [rusti-testkit](crates/rusti-testkit/src/lib.rs) | Synthetic offline wire fixtures |
| [standalone-cli](examples/standalone-cli/src/main.rs) | Offline smoke test only, prints fixture result |
| [CI](.github/workflows/ci.yml) | Rust 1.70 and stable on Linux/macOS/Windows runners; **workflow execution must be verified** |

## Local scaffold test

```sh
cargo test --workspace --all-targets
cargo run -p rusti-standalone-cli
```

These commands do **not** connect to IRC. No third-party crates are required for the current scaffolding. The minimum supported Rust toolchain **candidate** for the portable workspace is 1.70, with Rust 2021 edition; verify this in CI and on hardware before publishing a compatibility claim. Rust Boy's independently maintained workspace currently uses Rust 1.90.

## Research, security and integration documentation

- [Rust IRC projects and implementation matrix](docs/research/IRC_LITERATURE_MATRIX.md)
- [Security and legacy system literature matrix](docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md)
- [Legacy target and hardware compatibility profile](docs/deployment/LEGACY_COMPATIBILITY.md)
- [Offline redeployment and rollback runbook](docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Release acceptance checklist](docs/security/RELEASE_CHECKLIST.md)
- [Rust Boy adapter contract](docs/integration/RUST_BOY_ADAPTER_CONTRACT.md)
- [Architecture and phased development roadmap](docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md)
- [Security disclosure and deployment limitations](SECURITY.md)
- [Contribution rules](CONTRIBUTING.md)

## Security and deployment posture

- No IRC nickname, tag, channel mode or server can authorize Rust Boy organizational actions.
- Do not weaken TLS/certificate validation, authentication, code-signing or rollback protections for legacy OSes.
- Build cross-target, inspect glibc/musl, crypto provider and CPU constraints; then test on real hardware. Cross compilation alone is not validation.
- Treat package digest and **publisher signature** as separate checks. This repo has no signer or release verifier yet.
- Modern Windows target support starts with Windows 10 / Server 2016; EOL hosts require a separately reviewed isolation strategy.
- A ported IRC client is not a protected medical, emergency or mission-critical communications system without independent security assessment.

**Licensing decision pending.** This repository does not currently include a license grant; `publish = false` is set for each crate. Before code redistribution, select a compatible license, review upstream notices and record approval.
