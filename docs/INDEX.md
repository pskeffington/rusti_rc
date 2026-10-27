# Repository navigation

> Generated from index/catalog.json by scripts/repo_index.py. Do not edit; update the catalog or source and regenerate.

Start with [AGENTS.md](../AGENTS.md) for agent safety rules, [README](../README.md) for scope, and [MACHINE_INDEX.json](../index/MACHINE_INDEX.json) for machine retrieval.

**Status:** Experimental IRC communications module. TLS/SASL are not Rust Boy organizational authority; field deployment remains gated.

## Task routing

| Search terms | Primary source | Related source |
| --- | --- | --- |
| literature, matrix, evidence | [docs/research/IRC_LITERATURE_MATRIX.md](../docs/research/IRC_LITERATURE_MATRIX.md) | [docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md](../docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md) |
| raspberry pi, armv6, armv7 | [docs/deployment/LEGACY_COMPATIBILITY.md](../docs/deployment/LEGACY_COMPATIBILITY.md) | [scripts/legacy_host_preflight.sh](../scripts/legacy_host_preflight.sh) |
| irc frame, ircv3, decoder | [crates/rusti-proto/src/lib.rs](../crates/rusti-proto/src/lib.rs) | [crates/rusti-proto/src/decoder.rs](../crates/rusti-proto/src/decoder.rs) |
| server, listener, lan server | [crates/rusti-server/src/lib.rs](../crates/rusti-server/src/lib.rs) | [docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md](../docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md) |
| machine indexing, index, source lookup | [scripts/repo_index.py](../scripts/repo_index.py) | [index/MACHINE_INDEX.json](../index/MACHINE_INDEX.json) |
| offline install, bundle, signature | [docs/deployment/G2G_SIGNED_BUNDLE_LAB.md](../docs/deployment/G2G_SIGNED_BUNDLE_LAB.md) | [scripts/verify_offline_bundle_lab.py](../scripts/verify_offline_bundle_lab.py) |
| registration, capability negotiation, cap 302 | [crates/rusti-proto/src/registration.rs](../crates/rusti-proto/src/registration.rs) | [net/src/registration.rs](../net/src/registration.rs) |
| rust boy, pip boy, link ui | [docs/integration/RUST_BOY_ADAPTER_CONTRACT.md](../docs/integration/RUST_BOY_ADAPTER_CONTRACT.md) | [crates/rusti-adapter/src/lib.rs](../crates/rusti-adapter/src/lib.rs) |
| sasl, authentication, nickserv | [crates/rusti-proto/src/sasl.rs](../crates/rusti-proto/src/sasl.rs) | [net/src/sasl.rs](../net/src/sasl.rs) |
| keychain, credential, os keyring | [crates/rusti-client/src/credential_ref.rs](../crates/rusti-client/src/credential_ref.rs) | [net/src/native_store.rs](../net/src/native_store.rs) |
| ci, tests, interop | [.github/workflows/ci.yml](../.github/workflows/ci.yml) | [.github/workflows/verified-tls.yml](../.github/workflows/verified-tls.yml) |
| cancellation, retry, timeout | [net/src/cancel.rs](../net/src/cancel.rs) | [net/tests/registration_interruptions.rs](../net/tests/registration_interruptions.rs) |
| tls, rustls, certificate | [net/src/lib.rs](../net/src/lib.rs) | [net/README.md](../net/README.md) |

## Module ownership and boundaries

| Module | Maturity | Entry point | Trust boundary |
| --- | --- | --- | --- |
| ci | active-ci | [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Cross-target cargo check does not demonstrate real hardware runtime or clinical reliability. |
| client-policy | tested-development | [crates/rusti-client/src/lib.rs](../crates/rusti-client/src/lib.rs) | Credential references are not secrets and recovery proposals do not trigger I/O. |
| demo | offline-smoke | [examples/standalone-cli/src/main.rs](../examples/standalone-cli/src/main.rs) | Demo startup must not open sockets. |
| deployment-schema | proposal-not-verifier | [deployment/release-manifest.schema.json](../deployment/release-manifest.schema.json) | JSON Schema validity is not proof of signed authenticity or safe rollback. |
| documentation | mixed-implemented-and-proposed | [docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md](../docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md) | Proposed milestones and source claims are not automatically verified field capabilities. |
| fuzz | harness-authored-execution-pending | [fuzz/fuzz_targets/irc_frames.rs](../fuzz/fuzz_targets/irc_frames.rs) | Harness existence is not proof of executed fuzz coverage. |
| indexing | generated-and-ci-checked | [index/catalog.json](../index/catalog.json) | Index metadata is not a trusted command source or a replacement for source review. |
| protocol | tested-development | [crates/rusti-proto/src/lib.rs](../crates/rusti-proto/src/lib.rs) | Untrusted IRC text must never authorize Rust Boy actions. |
| release-lab | lab-tested-not-installer | [scripts/legacy_host_preflight.sh](../scripts/legacy_host_preflight.sh) | A successful lab signature check never authorizes a production update or protects a version floor. |
| repository | active | [README.md](../README.md) | Safety and release gates in SECURITY.md and the release checklist override summaries. |
| rustboy-adapter | read-only-preview | [crates/rusti-adapter/src/lib.rs](../crates/rusti-adapter/src/lib.rs) | IRC account, nickname and channel never grant Vault, task or organizational authority. |
| server-policy | policy-only-no-listener | [crates/rusti-server/src/lib.rs](../crates/rusti-server/src/lib.rs) | Do not claim a live IRC server or enable public binds. |
| testkit | synthetic-fixtures | [crates/rusti-testkit/src/lib.rs](../crates/rusti-testkit/src/lib.rs) | No real credentials, locations or operator data in fixtures. |
| tls-transport | tested-development-not-production | [net/src/lib.rs](../net/src/lib.rs) | Verified TLS/SASL do not provide E2EE, receiver receipts or Rust Boy authorization. |

## Documentation

### .

- [AGENTS](../AGENTS.md)
- [CONTRIBUTING](../CONTRIBUTING.md)
- [README](../README.md)
- [SECURITY](../SECURITY.md)

### deployment

- [README](../deployment/README.md)

### docs/architecture

- [G2B REGISTRATION RECOVERY](../docs/architecture/G2B_REGISTRATION_RECOVERY.md)
- [G2C INDEPENDENT IRCD CREDENTIALS](../docs/architecture/G2C_INDEPENDENT_IRCD_CREDENTIALS.md)
- [G2D SASL NATIVE CREDENTIALS](../docs/architecture/G2D_SASL_NATIVE_CREDENTIALS.md)
- [G2E INDEPENDENT SASL LEGACY KEYS](../docs/architecture/G2E_INDEPENDENT_SASL_LEGACY_KEYS.md)
- [G2F REGISTRATION HARDWARE GATES](../docs/architecture/G2F_REGISTRATION_HARDWARE_GATES.md)
- [G2 SECURE TRANSPORT DECISION](../docs/architecture/G2_SECURE_TRANSPORT_DECISION.md)
- [RUST BOY INTEGRATION ROADMAP](../docs/architecture/RUST_BOY_INTEGRATION_ROADMAP.md)

### docs/deployment

- [G2G SIGNED BUNDLE LAB](../docs/deployment/G2G_SIGNED_BUNDLE_LAB.md)
- [LEGACY COMPATIBILITY](../docs/deployment/LEGACY_COMPATIBILITY.md)
- [OFFLINE REDEPLOYMENT RUNBOOK](../docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md)

### docs/integration

- [RUST BOY ADAPTER CONTRACT](../docs/integration/RUST_BOY_ADAPTER_CONTRACT.md)

### docs/research

- [IRC LITERATURE MATRIX](../docs/research/IRC_LITERATURE_MATRIX.md)
- [SECURITY LEGACY DEPLOYMENT MATRIX](../docs/research/SECURITY_LEGACY_DEPLOYMENT_MATRIX.md)

### docs/security

- [G1B PROTOCOL EVIDENCE](../docs/security/G1B_PROTOCOL_EVIDENCE.md)
- [G2 TLS IMPLEMENTATION EVIDENCE](../docs/security/G2_TLS_IMPLEMENTATION_EVIDENCE.md)
- [RELEASE CHECKLIST](../docs/security/RELEASE_CHECKLIST.md)
- [THREAT MODEL](../docs/security/THREAT_MODEL.md)

### fuzz

- [README](../fuzz/README.md)

### net

- [README](../net/README.md)

## Maintain the index

From the repository root:

    python3 scripts/repo_index.py --write
    python3 scripts/repo_index.py --check
    python3 scripts/repo_index.py --query 'SASL authentication'
    python3 scripts/repo_index.py --path net/src/sasl.rs

CI rejects stale output, missing links in curated routes, unindexed directories, and sensitive file extensions. The index is a navigation aid, never a security approval.
