# rusti_rc

**Rust-native IRC protocol research and security-gated communications adapter for [Rust Boy](https://github.com/pskeffington/pip_boy).**

**Current state (2026-10-27): Rust 1.70 portable IRC core plus an isolated opt-in verified-TLS client, IRCv3 SASL PLAIN and optional desktop OS credential adapter.** Importing the portable root crates starts no sockets. The modern net/ crate requires a caller-requested TLS connection and explicit IRC/SASL registration. macOS Keychain and Windows Credential Manager support is feature-gated; Linux headless credential storage is not implemented. G2f adds bounded cancellable registration and an offline legacy host preflight, **not** a hardware credential store. There is no automatic discovery, persistent chat, LAN server, production release signer/installer or Rust Boy import. G2g-A has a **laboratory-only** detached-signature verifier that never deploys. **Not a deployable field communications system.**

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
| [Offline signed-bundle lab CI](.github/workflows/offline-release-lab.yml) | [G2g-A run passed 14/14 tests](https://github.com/pskeffington/rusti_rc/actions/runs/40457172972): synthetic Ed25519 verify, tamper, wrong key/target and untrusted test-floor rejection; always deployment blocked |
| [Rustfmt style CI](.github/workflows/repo-index.yml) | Pinned Rust 1.90.0 formatter checks portable, standalone TLS, and isolated fuzz Rust sources without rewriting them; no runtime feature is enabled |
| [Portable CI](.github/workflows/ci.yml) | [G2f 10/10 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40456201437): Rust 1.70/stable Linux/macOS/Windows and ARMv6/ARMv7/ARM64/musl compile-only checks |
| [Independent IRCd CI](.github/workflows/ergo-interop.yml) | [G2g-A 1/1 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40457172616): digest-pinned localhost Ergo v2.19.1, ephemeral CA, ordinary channel chat and 3 real-account synthetic SASL tests. Not hardware acceptance | 
| [TLS CI](.github/workflows/verified-tls.yml) | [G2g-A 3/3 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40457172858): locked TLS/Clippy on Linux/macOS/Windows, including G2g-A cancellation during blocked credential retrieval and G2f interrupted registration |

## G3a/G3b operator outbox and verified-TLS send (development branch)

The portable `rusti-client::outbox` module adds a bounded RAM-only FIFO for operator-authored chat drafts. It validates each draft against the existing IRC PRIVMSG encoder, requires explicit registration and fresh operator confirmation before releasing one draft, and clears unsubmitted drafts on disconnect. Messages that leave the queue are never automatically replayed. This is **not** a persistent queue, UI integration, transport-level send confirmation, recipient delivery receipt, or Rust Boy import. The G3b `TlsIrcSession::operator_submit_next` bridge now uses the session's real registered state, requires one explicit send confirmation, returns a `SubmittedUnconfirmed` outcome, and discards remaining drafts on an unknown write outcome. `operator_read_once` clears drafts on EOF/errors, and `operator_disconnect` clears them on manual stop. No connection, message, or resend occurs automatically. This remains a standalone development feature: **no operator UI, durable queue, recipient receipt, or Rust Boy import**.

## Local scaffold test

```sh
cargo test --workspace --all-targets
cargo run -p rusti-standalone-cli
```

These root-workspace commands do **not** connect to IRC. No third-party crates are required for the portable workspace; the separate nightly fuzz harness uses a dev-only `libfuzzer-sys` dependency and the independent net/ TLS workspace uses its own frozen dependency graph. The minimum Rust toolchain **candidate** for the portable workspace is 1.70, with Rust 2021 edition. Rust 1.70 CI passed on the tested host runners; hardware, OS ABI and field deployment claims remain unverified. Rust Boy's independently maintained workspace currently uses Rust 1.90.

## Formatting and code maintenance

The shared TLS registration guard is implemented once in `TlsIrcSession::run_registration_once`; anonymous CAP and opt-in SASL retain their separate state machines and never retry an aborted session. Source formatting is **check-only in CI** and uses pinned `rustfmt 1.90.0` for reproducibility. Run from the repository root:

```sh
cargo +1.90.0 fmt --all --manifest-path Cargo.toml -- --check
cargo +1.90.0 fmt --all --manifest-path net/Cargo.toml -- --check
cargo +1.90.0 fmt --all --manifest-path fuzz/Cargo.toml -- --check
```

This is a style gate, not an IRC security, older-hardware, or signed-release certification.

## Machine indexing and documentation

Start with [AGENTS.md](AGENTS.md) for agent-safe development guidance and [docs/INDEX.md](docs/INDEX.md) for the generated human-readable repository map. [index/MACHINE_INDEX.json](index/MACHINE_INDEX.json) is the compact, versioned machine inventory: stable file paths, module ownership, release maturity, trust boundaries, and task-to-source routes. [index/catalog.json](index/catalog.json) is the authoritative curated routing source.

Indexing is **offline and metadata-only** (no embeddings, external crawler, secrets, or duplicated source bodies). The generated inventory includes its own entry, and every file is assigned to one owner. Task lookups rank curated routes; exact path lookup returns the owning module and its trust boundary. Every PR checks drift. Stage newly created files before regeneration, then update the catalog when adding a module or changing ownership.

```sh
python3 scripts/repo_index.py --query 'SASL authentication'
python3 scripts/repo_index.py --path net/src/sasl.rs
python3 scripts/repo_index.py --write
python3 scripts/repo_index.py --check
```

For deeper evidence, follow [IRC literature](docs/research/IRC_LITERATURE_MATRIX.md), [security release gates](docs/security/RELEASE_CHECKLIST.md), [Rust Boy import contract](docs/integration/RUST_BOY_ADAPTER_CONTRACT.md), and [offline deployment runbook](docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md). The full architecture, test evidence, and research navigation lives in [docs/INDEX.md](docs/INDEX.md).

## Security and deployment posture

- No IRC nickname, tag, channel mode or server can authorize Rust Boy organizational actions.
- Independent Ergo **ordinary IRC and disposable real-account SASL PLAIN** interoperability passed in isolated CI, including bad-password/no-downgrade and wrong-server checks. Desktop keyring support is compiled and negative-tested, but **actual Keychain/Credential Manager lifecycle and physical legacy runtime remain unverified**. G2f verifies cancelled and stalled registration stops before anonymous fallback or credential reuse.
- Do not weaken TLS/certificate validation, authentication, code-signing or rollback protections for legacy OSes.
- Build cross-target, inspect glibc/musl, crypto provider and CPU constraints; then test on real hardware. Cross compilation alone is not validation.
- Treat package digest and **publisher signature** as separate checks. G2g-A adds **lab-only signed-manifest verification**, but there is no production publisher signer, protected trust-root updater, monotonic anti-rollback counter or deployable installer.
- Modern Windows target support starts with Windows 10 / Server 2016; EOL hosts require a separately reviewed isolation strategy.
- A ported IRC client is not a protected medical, emergency or mission-critical communications system without independent security assessment.

**License: [MIT](LICENSE).** Cargo packages inherit `MIT` from the workspace. Publication remains disabled (`publish = false`) until interoperability, vulnerability review, and distribution security gates pass. Attribution and license compatibility are required for imported third-party code.
