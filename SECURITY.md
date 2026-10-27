# Security policy

**Status:** experimental, offline protocol core plus a separate opt-in TLS networking preview in net/. No production-grade IRC session manager, secure listener, organizational authorization, E2EE, signed offline updater or real hardware acceptance is implemented. Do not use for protected records, clinical/patient data, operational emergency dispatch, safety-of-life instructions or live privileged command and control.

## Reporting

If GitHub private vulnerability reporting is enabled for this repository, use that channel; otherwise coordinate a private report with repository maintainers before publicly disclosing exploit details or secrets. Do not post credentials, device identifiers, private network information, medical data or live logs in issues.

## Current safeguards and limitations

- Every source crate forbids `unsafe`; no external runtime dependencies exist in this scaffold.
- A bounded IRC wire-frame parser, optional IRCv3 tag unescape, limited CAP 302 planner and incremental stream decoder have been authored. The streaming decoder caps per-connection frame buffering at 8703 bytes plus allocator overhead and refuses malformed lines. This is **not** an authenticated network reader, a complete protocol decoder, or a security audit.
- Client and server policy entrypoints default to disabled. When enabled in a test, they explicitly return `NetworkingNotImplemented` / `ListenerNotImplemented`, and open no connection.
- A read-only IRC adapter always describes chat sender identity as unverified; it cannot assign Rust Boy tasks, approve devices or authenticate an organization.
- Authenticated TLS client code with explicitly supplied trust roots and a single manually provided socket target exists separately under net/; its synthetic localhost tests and CI must pass before acceptance. SASL, production reconnect, secure key storage, executed parser fuzzing, dependency audit, credential revocation, vulnerability response and signed deployment verification have not been completed. The isolated cargo-fuzz source harness is present but not yet executed.
- [GitHub CI run #15](https://github.com/pskeffington/rusti_rc/actions/runs/40440406547) passed 10/10 jobs (six Rust 1.70/stable host combinations and four source-only ARM/musl cross-target checks). This does **not** certify older operating systems, hardware, TLS interoperability or production security.
- Source is [MIT-licensed](LICENSE), but crate publication and deployable releases remain gated pending protocol, dependency, security and signed-distribution validation.

Read [G1b evidence](docs/security/G1B_PROTOCOL_EVIDENCE.md), [threat model](docs/security/THREAT_MODEL.md), [security research](docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md) and [offline release runbook](docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md).

## Non-negotiable release checks

No plaintext TLS downgrade, no auto-DCC, no network listener on import, no unreviewed credentials in configuration, no IRC-to-Vault role or command mapping, no unsigned install, no vulnerable rollback, and no unsupported-OS promises. A high-trust deployment requires independent security and physical acceptance.
