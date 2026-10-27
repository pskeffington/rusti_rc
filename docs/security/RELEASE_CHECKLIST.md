# Security release and redeploy checklist

Status: proposed acceptance criteria. **There are no releases or verified hardware targets.**

| Gate | Required evidence | Current state |
|---|---|---|
| Code review | Two-person security review of parser, adapter, transport, config and updater changes | NOT DONE |
| License | Repository license approved; upstream licenses and notices reviewed | NOT DONE |
| MSRV | Rust 1.70 (portable core) and stable build/test, 2021 edition retained | [10/10 PR checks pass](https://github.com/pskeffington/rusti_rc/actions/runs/40440406547); OS/hardware release support not verified |
| Lock + provenance | Cargo-generated lockfiles committed, builds with `--locked`, SBOM, compiler/sysroot digest and source SHA captured | Separate net/Cargo.lock pinned with 66 packages; locked CI awaiting final validation; release SBOM/provenance NOT DONE |
| Supply chain | RustSec/cargo-deny and CI action pin reviews; findings triaged | NOT DONE |
| Parser security | Fuzz, memory limits, tag/CTCP/Unicode/control tests | Bounded decoder, tags, CAP and deterministic tests passed in CI; fuzz harness not executed; protocol audit NOT DONE |
| TLS identity | Modern rustls provider selected; TLS 1.2/1.3, SAN validation, expired/revoked CA, no downgrade | NOT DONE |
| Auth/secrets | SASL policy, OS-backed credentials, redacted logs, compartmentalized trust roots | NOT DONE |
| Authorization | IRC nick never yields authenticated Rust Boy/Vault/organizational access | Source boundary authored, integration NOT DONE |
| Server safety | Default disabled, loopback-only unless approved, flood control and no public bind | Policy stub only |
| Target builds | x86 Linux, ARMv6/v7/ARM64, Intel/ARM Mac, Windows supported OS targets compiled | ARMv6/v7/ARM64 + musl source-only checks passed; actual target linking/runtime NOT DONE |
| Real hardware | CPU, RAM, storage, kernel/ABI, TLS/CA, network loss/restart and failure injection | NOT DONE |
| Offline package | Trusted verifier, signed manifest, controlled version floor, revocation metadata, verified payload and target | NOT DONE |
| A/B redeploy | Power-loss-safe activation, state migration, recovery after corrupted USB or aborted update | NOT DONE |
| Rollback protection | Signed prior slot, security floor, protected release history, migration compatibility | NOT DONE |
| Rust Boy integration | Feature-flag import, 0 sockets on disabled import, explicit operator POST, one-screen accessible HUD | NOT DONE |

## Evidence record template

- Product / version / commit / Cargo.lock digest:
- Test rig architecture, CPU model, kernel/OS, glibc/musl version:
- Exact Rust compiler + target, linker/sysroot and cargo command:
- Binary checksum, signature verification and release identity:
- Upstream dependency inventory/license/advisory report:
- Unit/fuzz/interoperability outcomes (failure logs sanitized):
- TLS/SASL and active network listener validation:
- Offline redeploy and rollback attempts (result and security floor):
- Reviewer/approver and date, residual risks and accepted mitigation:

**Promotion rule:** `supported` and `securely redeployable` are separate claims. Both require evidenced passes, not just build jobs or a working screenshot.

Research sources: [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final), [TUF](https://theupdateframework.io/docs/security/), [SLSA](https://slsa.dev/spec/v1.0/levels), [Rust target support](https://forge.rust-lang.org/platform-support.html).
