# G2 secure transport / legacy deployment selection gate

Status: **design plus G2 TLS implementation preview in review**, 2026-10-26. The Rust 1.70 framing core has passed CI. A separate net/ workspace provides an operator-invoked rustls client, synthetic localhost TLS tests and explicit trust roots; live IRC server interoperability, SASL, credential vault, revocation and supported legacy hardware remain unverified.

## Decision: separate protocol MSRV from network crypto MSRV

The protocol/parser crates retain the Rust 2021 / 1.70 source compatibility target. **Do not pin cryptography to an out-of-support version simply to preserve that compiler minimum.**

The separate net/ implementation uses a newer audited Rust compiler while producing target-specific binaries for an older operating system/CPU, provided the actual kernel/ABI, crypto provider and runtime minimum are independently verified. The nested net/ workspace is independent from the portable root workspace. Merely importing the parser never links TLS or opens sockets.

## Literature / engineering matrix

| Option | Evidence | Benefits | Legacy/security concerns | Decision |
|---|---|---|---|---|
| rustls with current supported provider | [rustls current documentation](https://rustls.dev/docs/rustls/index.html) | TLS 1.2/1.3, modern certificate validation and secure defaults | Actual version MSRV and provider target/toolchain prerequisites must be verified; do not assume Rust 1.70 | 0.23.46 selected for the isolated preview, no production acceptance yet |
| aws-lc-rs crypto provider | [rustls provider docs](https://docs.rs/rustls/latest/rustls/) | Well-maintained crypto primitives | More C/assembly/build-system dependencies, ARMv6 and old libc uncertain | Require per-target compile+run and audit |
| ring crypto provider | [rustls ring support](https://docs.rs/rustls/latest/rustls/) | Potentially simpler build on some targets | Its CPU/OS support differs by architecture; requires target evidence and updates | ring explicitly selected for preview; ARMv6/v7 support must be proven |
| Platform native TLS | OS security APIs or OpenSSL bindings | Can reuse host CA stores | Legacy EOL host has stale TLS/CA, patch and ABI risks; OS API behavior differs | Do not use to bypass validated TLS requirements |
| Plain TCP port 6667 | Historical IRC compatibility | Broad old-server compatibility | No server identity, no confidentiality, credential exposure | **Rejected for operational use** |

Normative guidance: [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) (TLS >=1.2, prefer 1.3), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) (service identity matching), [IRCv3 SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2), [Rust target support](https://forge.rust-lang.org/platform-support.html).

## Architecture and acceptance

1. The network crate must require explicit operator activation. Pure-data import, parsing, UI inspection, role selection and profile loading cannot initiate DNS lookup, TCP, reconnect timers or listeners.
2. Require verified TLS to configured hostname/IP, hostname/SAN and trust-chain validation, certificate expiry, and authenticated time; no `dangerous` verifier, TLS downgrade, unsolicited redirects, or default trust-on-first-use.
3. Use reviewed trust-root provisioning and protected references to credentials; no key bytes in JSON, logs, process arguments, portable bundle or Rust Boy's public catalog.
4. Add SASL only after verified TLS is established and CAP SASL support is negotiated, using reviewed mechanisms; no automatic SASL or credential-bearing CAP flow in the G1b planner. IRC identity remains **untrusted by Rust Boy** even after IRC account authentication.
5. Use bounded queues, per-connection I/O limits, timeouts, explicit cancellation, finite reconnect budgets and operator-visible `SUBMITTED / UNCONFIRMED` status. A server response does not imply authenticated Rust Boy STORED receipt.
6. On ARMv6/ARMv7 and older x86: record libc, CPU instruction set, root-store policy, CA rotation, RTC reliability, memory/CPU, linker and C toolchain; test on actual device and refuse unsupported combinations. Compiling is not sufficient.
7. A network listener is a separate server gate: loopback default, explicit binding approval, least-privilege service account, client/channel limits, rate limiting and rigorous flood testing.
8. Build with `Cargo.lock --locked`, static SBOM and RustSec/cargo-deny review. Require license/patch support and update/rollback plan before deployment.

## G2 stop conditions

- TLS 1.0/1.1, plaintext fallback after TLS failure or weak certificate validation.
- Unsupported crypto provider/CPU or unpatched EOL TLS stack merely to keep older systems online.
- Any IRC nickname/account tag used as Vault, task, 9-line emergency or organizational auth.
- Hidden outbound contacts, credential logging, unbounded buffering/reconnect loops.
- Calling a cross-compiled binary `supported` before a hardware test.

## Implementation status and CI

- Current source: [net/src/lib.rs](../../net/src/lib.rs), [synthetic certificate tests](../../net/tests/verified_tls_loopback.rs), [net README](../../net/README.md), [G2 evidence](../security/G2_TLS_IMPLEMENTATION_EVIDENCE.md).
- Only explicit connect_tls can create a socket; it uses a supplied SocketAddr instead of DNS, validates server_host through rustls and rejects TLS-required=false.
- This is synchronous/bounded I/O meant for a worker thread, not a UI event thread. Cancellation, automatic reconnect, credential storage and full IRCv3 orchestration are pending.
- Tests are in GitHub Actions; do not claim production/legacy acceptance until test results and hardware evidence are reviewed.

## Exit criteria

Two offline-controlled test clients use authenticated TLS to an independently configured IRC server, successfully negotiate only allowlisted CAP behavior, show direct/channel chat state without false receipts, survive forced network loss with bounded reconnect, and demonstrably reject expired/wrong-name/untrusted certificates. Replay tests, signed bundle and supported target evidence remain separate release gates.
