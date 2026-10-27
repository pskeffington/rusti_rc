# rusti_rc

**Rust-native IRC protocol research and security-gated communications adapter for [Rust Boy](https://github.com/pskeffington/pip_boy).**

**Current state (2026-10-26): Rust 1.70 portable IRC core plus an isolated opt-in verified-TLS client, IRCv3 SASL PLAIN and optional desktop OS credential adapter.** Importing the portable root crates starts no sockets. The modern net/ crate requires a caller-requested TLS connection and explicit IRC/SASL registration. macOS Keychain and Windows Credential Manager support is feature-gated; Linux headless credential storage is not implemented. There is no automatic discovery, persistent chat, LAN server, signed installer or Rust Boy import. **Not a deployable field communications system.**

## Purpose

Build a modular IRC stack, independently distributable for portable Linux and older ARM hardware, with an optional future import into Rust Boy's LINK UI as an **alternative chat path**. An IRC network requires reachable IP and an IRC server: this project does not create a mesh bearer, guarantee delivery, implement E2EE or authenticate Vault Command assignments.

## Source index

| Path | Actual scaffold state |
|---|---|
| [rusti-proto](crates/rusti-proto/src/lib.rs) | Dependency-free bounded IRC parser, tag decoding, CAP 302/registration, incremental framing and control-stripped display helpers; not complete RFC/IRCv3 |
| [rusti-client](crates/rusti-client/src/lib.rs) | Disabled-by-default Rust 1.70 policy, finite recovery planner, redacted credential references; no OS I/O in portable core |
| [rusti-server](crates/rusti-server/src/lib.rs) | Disabled-by-default, loopback/TLS/limits policy; no actual listener |
| [rusti-adapter](crates/rusti-adapter/src/lib.rs) | Untrusted read-only IRC framing, sanitized display methods and redacted debug output; no Vault/peer privileges |
| [rusti-testkit](crates/rusti-testkit/src/lib.rs) | Synthetic offline wire fixtures |
| [standalone-cli](examples/standalone-cli/src/main.rs) | Offline smoke test only, prints fixture result |
| [TLS networking preview](net/README.md) | Separate rustls/ring workspace: explicit verified TLS, IRC CAP and optional SASL PLAIN; feature-gated macOS/Windows native keyring; no Rust Boy import |
| [Portable CI](.github/workflows/ci.yml) | [G2d 10/10 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40445991514): Rust 1.70/stable Linux/macOS/Windows and ARMv6/ARMv7/ARM64/musl compile-only checks |
| [Independent IRCd CI](.github/workflows/ergo-interop.yml) | [G2d 1/1 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40445991593): digest-pinned localhost Ergo v2.19.1, ephemeral CA and two-client channel delivery. Not hardware acceptance | 
| [TLS CI](.github/workflows/verified-tls.yml) | [G2d 3/3 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40445991564): locked-dependency verified-TLS loopback tests and Clippy on Linux/macOS/Windows |

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
- [G2d SASL PLAIN and native credential-store matrix](docs/architecture/G2D_SASL_NATIVE_CREDENTIALS.md)
- [G2e independent SASL account and headless legacy key matrix](docs/architecture/G2E_INDEPENDENT_SASL_LEGACY_KEYS.md)
- [Architecture and phased development roadmap](docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md)
- [G1b protocol implementation and pending evidence](docs/security/G1B_PROTOCOL_EVIDENCE.md)
- [Nightly-only isolated fuzz harness](fuzz/README.md)
- [Security disclosure and deployment limitations](SECURITY.md)
- [Contribution rules](CONTRIBUTING.md)

## Security and deployment posture

- No IRC nickname, tag, channel mode or server can authorize Rust Boy organizational actions.
- Independent Ergo ordinary IRC interoperability passes in isolated CI. Synthetic TLS SASL PLAIN tests now pass; optional desktop OS keyring access is compiled and negative-tested, but actual Keychain/Credential Manager provisioning and independent IRCd SASL account authentication remain unverified.
- Do not weaken TLS/certificate validation, authentication, code-signing or rollback protections for legacy OSes.
- Build cross-target, inspect glibc/musl, crypto provider and CPU constraints; then test on real hardware. Cross compilation alone is not validation.
- Treat package digest and **publisher signature** as separate checks. This repo has no signer or release verifier yet.
- Modern Windows target support starts with Windows 10 / Server 2016; EOL hosts require a separately reviewed isolation strategy.
- A ported IRC client is not a protected medical, emergency or mission-critical communications system without independent security assessment.

**License: [MIT](LICENSE).** Cargo packages inherit `MIT` from the workspace. Publication remains disabled (`publish = false`) until interoperability, vulnerability review, and distribution security gates pass. Attribution and license compatibility are required for imported third-party code.
