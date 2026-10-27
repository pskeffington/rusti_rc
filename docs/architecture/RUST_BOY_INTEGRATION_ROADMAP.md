# rusti_rc architecture and Rust Boy integration gates

Baseline: 2026-10-27. **Current status: standalone TLS IRC and independently verified synthetic-account SASL authentication tests pass; Rust Boy import and field deployment remain unimplemented.** This roadmap describes proposed capabilities and gates, not verified functionality.

## Module and trust boundaries

- `crates/rusti-proto` — dependency-free, bounded IRC framing/encoding and synthetic unit tests. No network.
- `crates/rusti-client` — TLS-required, disabled-by-default connection configuration; the connection method currently fails with `NetworkingNotImplemented`.
- `crates/rusti-server` — disabled-by-default and loopback/TLS/quotas policy; no listening socket; public binds are refused.
- `crates/rusti-adapter` — read-only, untrusted IRC chat preview for eventual Rust Boy LINK import. Nick/prefix is never an organizational grant.
- `crates/rusti-testkit` — offline deterministic malformed/normal fixture smoke checks.
- `examples/standalone-cli` — fixture smoke, no IRC network access.
- `docs/` — evidence matrix, threat model, compatibility, secure redeploy and integration contracts.

The portable core remains dependency-light and Rust 1.70-compatible. The separate modern networking workspace uses pinned rustls/ring with an opt-in desktop-native credential adapter; Tokio and a production IRC server are not part of this implementation. The separate nightly-only fuzz harness depends on libfuzzer-sys, not the portable workspace. The future client/server stack must use reviewed cryptography, bounded message queues and an explicit operator lifecycle.

## Phased development

| Gate | Planned deliverable | Present result |
|---|---|---|
| G0 | Source/project matrix, threat model, license and compatibility review | Literature/security matrices and threat model drafted; MIT license selected; upstream notice/security review still pending |
| G1a | Strict framing and baseline encoding | Portable `rusti-proto` parser/PRIVMSG preview + unit tests; PR CI succeeded on tested host runners, hardware not verified |
| G1b | Complete protocol and fuzzing | Opaque tags, decoded tag escaping, bounded streaming reader, limited CAP 302 planner, deterministic tests and a fuzz harness **authored**; complete CAP, RFC numerics, fuzz execution and interoperability remain pending (10/10 configured CI jobs passed) |
| G2 | Authenticated transport | G2f verified cancellation/absolute-deadline protections for standalone CAP and SASL over TLS, independent Ergo IRC/SASL interoperability, and a safe offline ARM/Linux preflight. Native desktop keyring feature compiled; real keychain lifecycle, second IRCd, headless key storage, legacy runtime and signed release acceptance remain open |
| G3 | Operator chat | JOIN and PRIVMSG submission implemented in standalone TLS module. G3a portable bounded in-memory operator drafts and explicit release policy authored; TLS send hookup, integration tests, durable state and delivery receipts remain pending |
| G4 | Optional LAN server | Explicit operator enable, loopback first, quota/flood tests, trusted LAN provisioning; **pending** |
| G5 | Rust Boy import | Feature-gated `rusti-adapter` into existing LINK UI, explicit send, no new permissions or storage leaks; **pending** |
| G6 | Legacy build/redeploy | Real ARMv6/v7/ARM64, x86 Linux, Mac/Windows tests, signed offline A/B installer and protected rollback; **pending** |

## Transport truth

- Reachable IP plus authenticated IRC server: IRC can provide ordinary chat **after G2/G3**.
- Shared local IP plus opt-in server: local IRC can provide same-LAN chat **after G4**.
- No IP/server path: IRC cannot deliver; continue to show unavailable and use a separately implemented transport if one exists.
- A message accepted by a socket/IRC server is **not** a confirmed, authenticated Rust Boy receiver-storage receipt.
- IRC TLS is ordinarily client-server transport security; **not E2EE**. No IRC server trust is sufficient for Vault Command orders or emergency reporting.
- Importing the crate or selecting the LINK UI must never connect, discover networks, bind sockets, grant privileges, or send messages without a separately authorized operator action.

## Deployment gates

The standalone module targets Rust 2021 and Rust 1.70 to allow legacy experiments; Rust Boy currently targets Rust 1.90. Validate [real target support](../deployment/LEGACY_COMPATIBILITY.md) independently of the compiler MSRV. Use [release checklist](../security/RELEASE_CHECKLIST.md) and [signed offline redeployment runbook](../deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md) before any product claim.

## Definition of a useful later prototype

Two independently controlled test hosts on one lab LAN connect through an independently configured IRCd with verified TLS, explicitly join allowlisted channels, exchange plain chat with visible submit/unconfirmed status, survive reconnect without uncontrolled resend, log no credentials, and keep Rust Boy vault/organizational identity inaccessible. Real-device and adversarial tests must be recorded before promotion.
