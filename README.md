# rusti_rc

**Rust-native IRC protocol research and security-gated communications adapter for [Rust Boy](https://github.com/pskeffington/pip_boy).**

**Current state (2026-10-26): a portable offline-first protocol core plus an isolated, explicitly activated TLS transport preview.** The portable root workspace opens no sockets; the separately built net/ crate can make one caller-requested, certificate-verified IRC TCP/TLS connection. No SASL, automatic discovery, persisted messages, LAN server, signed installer or Rust Boy integration exists. This is not a deployable field communications system.

## Purpose

Build a modular IRC stack, independently distributable for portable Linux and older ARM hardware, with an optional future import into Rust Boy's LINK UI as an **alternative chat path**. An IRC network requires reachable IP and an IRC server: this project does not create a mesh bearer, guarantee delivery, implement E2EE or authenticate Vault Command assignments.

## Source index

| Path | Actual scaffold state |
|---|---|
| [rusti-proto](crates/rusti-proto/src/lib.rs) | Dependency-free bounded IRC parser, tag decoding, CAP 302 planner, incremental byte framing and offline tests; not a complete RFC/IRCv3 implementation |
| [rusti-client](crates/rusti-client/src/lib.rs) | Disabled-by-default, Rust 1.70-compatible connection policy; core alone still returns not implemented |
| [rusti-server](crates/rusti-server/src/lib.rs) | Disabled-by-default, loopback/TLS/limits policy; no actual listener |
| [rusti-adapter](crates/rusti-adapter/src/lib.rs) | Untrusted read-only IRC chat framing for future Rust Boy import; no Vault/peer privileges |
| [rusti-testkit](crates/rusti-testkit/src/lib.rs) | Synthetic offline wire fixtures |
| [standalone-cli](examples/standalone-cli/src/main.rs) | Offline smoke test only, prints fixture result |
| [TLS networking preview](net/README.md) | Separate modern rustls/ring workspace: explicit verified TLS connection, basic IRC commands and localhost certificate tests; no Rust Boy import |
| [Portable CI](.github/workflows/ci.yml) | [G2b run #33 passed 10/10](https://github.com/pskeffington/rusti_rc/actions/runs/40443606057): Rust 1.70/stable Linux/macOS/Windows and ARMv6/ARMv7/ARM64/musl compile-only checks |
| [TLS CI](.github/workflows/verified-tls.yml) | [G2b run #18 passed 3/3](https://github.com/pskeffington/rusti_rc/actions/runs/40443606042): locked-dependency verified-TLS loopback tests and Clippy on Linux/macOS/Windows |

## Local scaffold test

```sh
cargo test --workspace --all-targets
cargo run -p rusti-standalone-cli
```

These root-workspace commands do **not** connect to IRC. No third-party crates are required for the portable workspace; the separate nightly fuzz harness uses a dev-only `libfuzzer-sys` dependency and the independent net/ TLS workspace uses its own frozen dependency graph. The minimum Rust toolchain **candidate** for the portable workspace is 1.70, with Rust 2021 edition. Rust 1.70 CI passed on the tested host runners; hardware, OS ABI and field deployment claims remain unverified. Rust Boy's independently maintained workspace currently uses Rust 1.90.

## Research, security and integration documentation

- [Rust IRC projects and implementation matrix](docs/research/IRC_LITERATURE_MATRIX.md)
- [Security and legacy system literature matrix](docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md)
- [Legacy target and hardware compatibility profile](docs/deployment/LEGACY_COMPATIBILITY.md)
- [Offline redeployment and rollback runbook](docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Release acceptance checklist](docs/security/RELEASE_CHECKLIST.md)
- [Rust Boy adapter contract](docs/integration/RUST_BOY_ADAPTER_CONTRACT.md)
- [G2 secure TLS transport and legacy-target decision](docs/architecture/G2_SECURE_TRANSPORT_DECISION.md)
- [G2 TLS source and test evidence](docs/security/G2_TLS_IMPLEMENTATION_EVIDENCE.md)
- [G2b IRC registration and recovery implementation](docs/architecture/G2B_REGISTRATION_RECOVERY.md)
- [G2c independent Ergo IRCd and credential-reference design](docs/architecture/G2C_INDEPENDENT_IRCD_CREDENTIALS.md)
- [Architecture and phased development roadmap](docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md)
- [G1b protocol implementation and pending evidence](docs/security/G1B_PROTOCOL_EVIDENCE.md)
- [Nightly-only isolated fuzz harness](fuzz/README.md)
- [Security disclosure and deployment limitations](SECURITY.md)
- [Contribution rules](CONTRIBUTING.md)

## Security and deployment posture

- No IRC nickname, tag, channel mode or server can authorize Rust Boy organizational actions.
- Do not weaken TLS/certificate validation, authentication, code-signing or rollback protections for legacy OSes.
- Build cross-target, inspect glibc/musl, crypto provider and CPU constraints; then test on real hardware. Cross compilation alone is not validation.
- Treat package digest and **publisher signature** as separate checks. This repo has no signer or release verifier yet.
- Modern Windows target support starts with Windows 10 / Server 2016; EOL hosts require a separately reviewed isolation strategy.
- A ported IRC client is not a protected medical, emergency or mission-critical communications system without independent security assessment.

**License: [MIT](LICENSE).** Cargo packages inherit `MIT` from the workspace. Publication remains disabled (`publish = false`) until interoperability, vulnerability review, and distribution security gates pass. Attribution and license compatibility are required for imported third-party code.
