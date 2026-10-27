# Security, integration and legacy deployment literature matrix

Baseline: 2026-10-26. Evidence classification: **normative** (published standard or vendor documentation); **upstream guidance** (maintainer documentation); **design decision** (rusti_rc requirement); **implementation** (checked-in scaffold, not yet independently compiled); **field pending** (hardware/interoperability test not run). Research is not a security certification.

Purpose: support the separately maintained, optional `rusti_rc` module inside `pip_boy`, older Linux/ARM hardware, and offline reinstallation **without weakening cryptography or implying IRC is a mesh, E2EE, authenticated command, or guaranteed-delivery system**.

| ID | Source / authority | Established guidance / constraint | rusti_rc application | Gate / evidence |
|---|---|---|---|---|
| S01 | [RFC 1459](https://www.rfc-editor.org/rfc/rfc1459), Oikarinen & Reed, IETF (1993) | Baseline IRC message syntax and commands | Bound all received and emitted protocol frames; reject framing injection | P0, implementation limited to framing; full compliance pending |
| S02 | [RFC 2812](https://www.rfc-editor.org/rfc/rfc2812), Kalt, IETF (2000) | Client protocol, 512-byte line limit including CRLF and command numerics | Strict parser, explicit protocol compatibility fixtures | P0, partial; full numeric/CAP tests pending |
| S03 | [IRCv3 message-tags](https://ircv3.net/specs/extensions/message-tags.html), IRCv3 WG | Opaque UTF-8 tags, negotiated support and independent 8191-byte inbound tag-prefix limit; client tags untrusted | Treat metadata as untrusted and cap prefix independently of the 512-byte base line | P0, tag unescape and bounded framing implemented/tested in PR CI; full negotiation and interoperable networking pending |
| S04 | [IRCv3 SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2), IRCv3 WG | SASL mechanism advertisement, capability negotiation, auth error behavior | Only enable SASL PLAIN after verified TLS; EXTERNAL only with controlled cert identity | P0, no authentication implementation |
| S05 | [IRCv3 Strict Transport Security](https://ircv3.net/specs/extensions/sts), IRCv3 WG | Protect server transport policy; no easy bypass on secure connection failure | Pre-configured TLS required, no plaintext fallback; revisit STS persistence | P0, fail-closed policy scaffold; STS pending |
| S06 | [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), Sheffer et al., IETF (2022) | TLS 1.2 minimum for modern deployments, prefer TLS 1.3; no SSL/TLS 1.0/1.1 | Separate modern TLS stack from legacy OS root store; do not downgrade for old machines | P0, TLS implementation pending |
| S07 | [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), Saint-Andre et al., IETF (2023) | Validate service name/IP identifiers independently of presented certificate | Explicit host configured; enforce SAN DNS/IP identity, chain and expiration | P0, TLS implementation pending |
| S08 | [rustls documentation](https://docs.rs/rustls/latest/rustls/), rustls maintainers | Modern TLS; default crypto backend is aws-lc-rs, alternate provider can change target portability | Benchmark/test selected crypto provider on x86-64, ARMv6/v7 and ARM64 **before** adding dependency | P0, backend decision pending |
| S09 | [Tokio bounded mpsc](https://docs.rs/tokio/latest/tokio/sync/mpsc/), Tokio maintainers | Bounded queues provide backpressure unlike unbounded send | Enforce memory budgets and nonblocking cancellation when networking is introduced | P0, Tokio not yet used |
| S10 | [Rust target support](https://forge.rust-lang.org/platform-support.html), Rust project | Rust targets have unequal CI/support tiers; targets have specific kernel, OS and CPU minima | Publish per-target hardware evidence instead of a blanket older-system promise | P0, ARMv6/v7/ARM64/musl compile-only checks passed; field pending |
| S11 | [Windows MSVC target requirements](https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html), Rust project | Current supported client OS starts at Windows 10, server at Windows Server 2016 | No Windows 7/8 release claim; use isolated intermediary for EOL nodes | P0, documented design decision |
| S12 | [Cargo rust-version](https://doc.rust-lang.org/stable/cargo/reference/rust-version.html), Rust project | A declared MSRV must be continually checked; dependency MSRV may drift | Set workspace MSRV 1.70, use 2021 edition; verify 1.70 and stable; avoid 2024-only resolver | P0, Rust 1.70/stable host CI passed; physical target compatibility pending |
| S13 | [Cargo resolver compatibility](https://doc.rust-lang.org/edition-guide/rust-2024/cargo-resolver.html), Rust project | Rust-version fallback resolver support begins at Cargo 1.84 | Do not rely on modern resolver tricks in the portable package; pin tested dependencies | P0, no third-party portable-workspace dependencies; fuzz-only libfuzzer-sys isolated |
| S14 | [Cargo.lock guidance](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html), Rust project | Lockfile records precise dependency versions; important for applications/release | Generate lock with Cargo, commit it before release, build with `--locked` | P0, lockfile/release gate pending |
| S15 | [NIST SP 800-218 v1.1](https://csrc.nist.gov/pubs/sp/800/218/final), Souppaya, Scarfone & Dodson, NIST (2022) | Prepare, protect, produce secure software, respond to vulnerabilities | Threat model, reviews, CI, controlled release, incident/revocation plan | P0, design scaffold only |
| S16 | [NIST SP 800-218 rev.1 draft](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd), NIST (2025) | Proposed v1.2 changes; **draft**, not final v1.1 replacement | Monitor for final publication; avoid representing as binding published standard | P2, watch item |
| S17 | [cargo-deny](https://github.com/EmbarkStudios/cargo-deny), Embark Studios | License, sources, bans and advisory policy checks | Approve upstream licenses and dependency source list before vendor/import | P0, tooling pending |
| S18 | [RustSec cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit), RustSec | Detect published advisories in transitive Rust dependencies | Scan frozen lockfile for every release and emergency backport | P0, tooling pending |
| S19 | [SLSA v1.0 build levels](https://slsa.dev/spec/v1.0/levels), SLSA project | Build provenance levels provide increasing assurance about build and provenance integrity | Require digest + source revision; target signed provenance from hosted controlled build | P1, signing pipeline pending |
| S20 | [TUF security model](https://theupdateframework.io/docs/security/), TUF project | Threats include rollback, freeze, mix-and-match and malicious updates | Signed metadata with versions/expiry and pinned trust roots; offline expiry recovery runbook | P0, planned only; no updater implemented |
| S21 | [OpenSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/beginner-checks.md), OpenSSF | Supply chain checks for permissions, review, vulnerabilities and dependencies | Read-only CI token, pinned checkout, protected release approvals | P1, some CI choices checked in |
| S22 | [Rust Boy PACE contract](https://github.com/pskeffington/pip_boy/blob/main/docs/PACE_MESSAGING.md), project-owned primary source | Only explicit operator send, storage receipt semantics, real route limitations | IRC remains separate alternative chat transport; cannot assert STORED/READ | P0, adapter boundary documented; integration pending |
| S23 | [Rust Boy security policy](https://github.com/pskeffington/pip_boy/blob/main/SECURITY.md), project-owned primary source | PIPBOY_HOME and role/UI/authorization limits, explicit same-origin POST and key boundaries | Never use chat nick to grant Vault or operator permissions; never place keys in JSON/IRC logs | P0, no direct integration yet |
| S24 | [Rust Boy Cargo workspace](https://github.com/pskeffington/pip_boy/blob/main/Cargo.toml), project-owned primary source | Rust Boy workspace MSRV 1.90 and edition 2021 | Keep rusti_rc library independently buildable on 1.70; later pin Git dependency/revision | P0, verified repository contract |

## Prioritization / evidence gates

**P0 / release blocking:** protocol framing, TLS identity verification, explicit opt-in and default-deny network, tested MSRV and per-target operation, supply-chain dependency review, installer signature verification, rollback protection, Rust Boy authorization boundary.

**P1 / after secure prototype:** SASL EXTERNAL, IRCv3 CAP/tag decoding, channel state, test server interoperability, controlled LAN listener, signed build provenance and measured resource budgets.

**P2 / research:** EOL bridge mode with physically isolated gateways, Rustless legacy endpoint, portable persistence migration, protocol interoperability extension matrix.

## Acceptance assertions (no implied completion)

1. `cargo +1.70.0 test --workspace --all-targets` and stable tests pass on supported CI hosts.
2. Malformed, oversized, truncated, multi-line and bidi-spoofed frames are rejected or safely encoded; fuzz test runs on parser.
3. Client with no operator action makes zero sockets, writes, scans or background connections.
4. TLS failure never falls back to insecure IRC; verify DNS/IP SAN, expiry and trust root on a physical legacy target.
5. An IRC nick/account tag cannot issue jobs, register devices, authorize vault access or generate cryptographic delivery receipts.
6. ARMv6, ARMv7 and ARM64 target builds are cross-compiled and **booted on real hardware** with memory/CPU observations.
7. Offline redeploy verifies signed manifest and exact target ABI, preserves state, and restores only a still-approved non-vulnerable release.
8. Build SBOM, lockfile, compiler version, source commit, package hash and signer identify exact deployed bytes.

Do not claim these gates have passed until independent test evidence and release receipts are recorded.
