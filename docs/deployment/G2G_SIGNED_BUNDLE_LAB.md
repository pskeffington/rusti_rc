# G2g-A — Offline signed-bundle verification laboratory

**Status:** G2g-A merged to `main` on 2026-10-27 in [PR #11](https://github.com/pskeffington/rusti_rc/pull/11), merge commit `cc5ba74d57a1da61f6cc627202e4be1fc8493441`. The exact tested PR head `84fef80eda2e5ee7f307abcfb6d5642c06e98326` passed [offline lab CI](https://github.com/pskeffington/rusti_rc/actions/runs/40457172972), [TLS CI](https://github.com/pskeffington/rusti_rc/actions/runs/40457172858) and [independent Ergo CI](https://github.com/pskeffington/rusti_rc/actions/runs/40457172616). This is a **laboratory verifier only**. It cannot install, execute, stage, activate, roll back, or approve a release. No actual device, TPM, native desktop keychain, or anti-rollback counter is tested or provisioned.

## Evidence and best-practice matrix

| Reference | Security property | Implementation and limitation |
|---|---|---|
| [TUF update security model](https://theupdateframework.io/docs/security/) and [TUF specification](https://theupdateframework.github.io/specification/v1.0.36/) | Protect against malicious repository, rollback, freeze, mix-and-match and other update attacks; store verified version metadata | G2g-A **only** tests one detached release signature, one digest and a *caller-supplied lab floor*. It is NOT a TUF client, persistent protected floor, expiry protection or threshold-signing system |
| [TUF metadata roles](https://theupdateframework.io/docs/metadata/) | Separate trusted root, targets, snapshots and timestamp roles; use thresholds and signed expiration | No root-rotation, revocation, threshold signatures, signed time or protected monotonic version state exists; keep deployment blocked |
| [OpenSSL pkeyutl](https://docs.openssl.org/3.3/man1/openssl-pkeyutl/) | Use reviewed Ed25519 verification through `pkeyutl -verify -rawin`; EdDSA needs a seekable input | The bounded manifest snapshot is verified via an ephemeral file using the **pre-provisioned external public key**, then parsed exactly. No homemade signature algorithm |
| [SLSA supply-chain levels](https://slsa.dev/spec/v1.0/levels) | Reproducible dependencies, provenance and trusted build boundaries | Source Git SHA is a signed data field, not independently verified build provenance. No SLSA claim or release attestation |
| [NIST SSDF, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Build verification, code review, tamper detection, incident and release management | Unit negative tests and a documented acceptance boundary; no production signing/revocation process yet |
| [systemd credentials](https://systemd.io/CREDENTIALS/) | Newer systemd can use TPM2 and service-scoped credentials, subject to actual hardware/boot policy | Neither the verifier nor preflight probes TPM or unwraps keys. Hardware root/secure clock are still required independently |

## Implemented code

- [`scripts/verify_offline_bundle_lab.py`](../../scripts/verify_offline_bundle_lab.py): Python standard-library CLI calling the local OpenSSL provider for **Ed25519 signature verification**, with strict duplicate-free JSON metadata schema, exact fixed payload name, SHA-256 and size checking, hardcoded target allowlist and input caps. Rejects symlinks/hardlinks, bundle extras, wrong target, invalid signature, wrong key, unknown/duplicate fields, changed payload and an older sequence than the explicit **untrusted lab floor**. No socket or subprocess shell, no key generation or write into the bundle; always prints `deployment=blocked` on verification success.
- [`scripts/tests/test_offline_bundle_lab.py`](../../scripts/tests/test_offline_bundle_lab.py): synthetic temporary Ed25519 keypair, ephemeral signed bundle and negative tests for payload/manifest tampering, key mismatch, signature corruption, path safety, duplicate/unrecognized fields, mistaken numeric values and rollback relative to supplied floor. Key is deleted with the test temporary directory. No real signing material in the repo or CI.
- [`offline-release-lab.yml`](../../.github/workflows/offline-release-lab.yml): Ubuntu-only synthetic lab tests, read-only GitHub permissions, no release or artifact uploads. OpenSSL is required; this does not establish support on older OS versions or ARM hardware.

## Supported lab manifest contract

Exact files, no others:

```text
bundle/
  manifest.json    # small UTF-8 JSON metadata, detached Ed25519 signature required
  manifest.sig     # exactly 64 raw signature bytes
  rusti_rc.bin     # synthetic payload, never executed; maximum 64 MiB
```

The manifest is signed **as bytes**, so its exact JSON formatting is authenticated. Fields are:

| Field | Type and validation |
|---|---|
| schema | literal `rusti-offline-lab-v1` |
| sequence | integer in [1, 2^31-1]; tested against untrusted operator-supplied floor |
| target | approved explicit Rust target triple, must exactly equal expected target argument |
| source_commit | exactly 40 lowercase hex characters; evidence value, not verified provenance |
| payload_name | literal `rusti_rc.bin`, no path or traversal accepted |
| payload_sha256 | exactly 64 lowercase hex characters |
| payload_size | positive int no larger than 64 MiB |

No archive extraction, shell scripts from bundle, systemd units, privileged execution, slot pointer changes, credential writes, network, trust root bootstrap or counters are performed by this verifier.

### Demonstration-only invocation

Public key must come from a separately controlled directory. The bundle **cannot** ship its own trusted key.

```sh
python3 scripts/verify_offline_bundle_lab.py --lab-only \
  --bundle /path/to/synthetic/bundle \
  --trusted-public-key /path/from/separate/trust-store/test-publisher.pem \
  --expected-target armv7-unknown-linux-gnueabihf \
  --minimum-sequence 12
```

The floor `12` is a **test parameter**, not a protected boot counter. A malicious local caller can lower it. The verifier therefore refuses to label any bundle installable. Do not use this command as an updater or production trust decision.

## Release barriers still open

- [ ] Protected, monotonically increasing version floor anchored outside a replaceable SD card; old host anti-rollback/anti-replay evidence.
- [ ] Threshold-signed publisher roots, rotation, delegation, revocation, timestamp freshness and offline expiry policy using an independently reviewed update framework.
- [ ] Trusted keys provisioned independently and immutable/revocable on each supported device; no shipped private key or self-authorizing bundle key.
- [ ] Signed/verifiable SBOM and build provenance, reproducible target/sysroot, RustSec and third-party license audit.
- [ ] Safe staged A/B installation and rollback using verified slots and protected settings; interrupted install/power-loss tests.
- [ ] Real ARMv6/ARMv7/ARM64 and older OS runtime, crypto provider, TLS, trusted time and resource measurements; no cross-compile-only support claim.
- [ ] Real Mac/Windows keychain lifecycle and headless TPM2/secure-element root; no plaintext fallback.
- [ ] Rust Boy import behind a reviewed feature flag, with independent organizational authentication.

**Security status:** a demonstration of signature and payload integrity, not a secure update mechanism. The signed release can still be stale or malicious if its private signing key is compromised. Release signing, hardware enrollment and physical redeployment are pending.

## G2g-A verified CI evidence

- [x] [Offline signed-bundle lab 1/1 CI](https://github.com/pskeffington/rusti_rc/actions/runs/40457172972): **14/14 ephemeral synthetic Ed25519 and tamper/negative tests passed**. Test signer exists only in a temporary directory and no signing key was checked into the repository.
- [x] [Locked modern TLS 3/3 CI](https://github.com/pskeffington/rusti_rc/actions/runs/40457172858): Linux/macOS/Windows integration tests and Clippy passed. The synthetic localhost regression `cancellation_during_blocking_secret_lookup_prevents_payload_transmission` passed; it does not certify any real native keychain.
- [x] [Independent pinned Ergo IRCd 1/1 CI](https://github.com/pskeffington/rusti_rc/actions/runs/40457172616): existing localhost IRC and synthetic registered-account SASL interoperability remained green.
- [ ] No real legacy-ARM or supported OS runtime acceptance, protected publisher trust, monotonic floor, revocation freshness, signed actual installer or atomic offline redeploy exists.

**Source boundary:** The portable Rust 1.70 core was unchanged by this PR. Previously passing 10/10 portable CI remains evidence for its earlier tested revision, not a claimed fresh G2g-A re-run.

**Promotion decision:** remain lab-only and never activate bundles from these tools. The next security milestone must provide a protected public trust root, anti-rollback and signed time/revocation metadata, plus independently reviewed staging and physical hardware validation.
