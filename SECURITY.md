# Security policy

**Status:** experimental, documentation and offline-only Rust scaffold. No production IRC network transport, secure listener, organizational authorization, E2EE, signed offline updater or hardware interoperability is implemented. Do not use for protected records, clinical/patient data, operational emergency dispatch, safety-of-life instructions or live privileged command and control.

## Reporting

If GitHub private vulnerability reporting is enabled for this repository, use that channel; otherwise coordinate a private report with repository maintainers before publicly disclosing exploit details or secrets. Do not post credentials, device identifiers, private network information, medical data or live logs in issues.

## Current safeguards and limitations

- Every source crate forbids `unsafe`; no external runtime dependencies exist in this scaffold.
- A strict bounded wire-frame preview rejects CRLF injection, ASCII control bytes, bidi controls, overlong frames and malformed commands. This is **not** a full protocol decoder or network read limiter.
- Client and server policy entrypoints default to disabled. When enabled in a test, they explicitly return `NetworkingNotImplemented` / `ListenerNotImplemented`, and open no connection.
- A read-only IRC adapter always describes chat sender identity as unverified; it cannot assign Rust Boy tasks, approve devices or authenticate an organization.
- TLS, SASL, real socket handling, secure key storage, parser fuzzing, external dependency audit, credential revocation, vulnerability response and signed deployment verification have not been built.
- The six-host/toolchain GitHub Actions matrix tests **only what the workflow actually executes**; CI cross-target success does not certify older operating systems or hardware.
- This repo has no selected redistribution license yet. Before publishing a reusable crate or signed release, choose and record licensing and audit third-party notices.

Read [threat model](docs/security/THREAT_MODEL.md), [security research](docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md) and [offline release runbook](docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md).

## Non-negotiable release checks

No plaintext TLS downgrade, no auto-DCC, no network listener on import, no unreviewed credentials in configuration, no IRC-to-Vault role or command mapping, no unsigned install, no vulnerable rollback, and no unsupported-OS promises. A high-trust deployment requires independent security and physical acceptance.
