# G2e — Independent SASL account acceptance and legacy credential boundary

Status: **G2e merged to main** via [PR #8](https://github.com/pskeffington/rusti_rc/pull/8), squash commit `dd29e02186db036120e2630461a1987a4fd03568`, 2026-10-27. Exact tested source head `df9047109edc26cd5c8290f85d0bb867d40609fe` passed [portable 10/10](https://github.com/pskeffington/rusti_rc/actions/runs/40448428217), [locked TLS 3/3](https://github.com/pskeffington/rusti_rc/actions/runs/40448428222) and [independent Ergo workflow 1/1](https://github.com/pskeffington/rusti_rc/actions/runs/40448428240). Laboratory evidence only; not Rust Boy authorization, native credential lifecycle acceptance or signed field release.

## Literature and engineering decisions

| Source | Best practice | Application and remaining gate |
|---|---|---|
| [Ergo account documentation](https://github.com/ergochat/ergo/blob/master/docs/USERGUIDE.md) | Bootstrap a disposable NickServ account, then prove SASL authentication against the *independent* server | Locally pinned Ergo and synthetic account only; no public IRC endpoint |
| [IRCv3 SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2.html) / [CAP](https://ircv3.net/specs/extensions/capability-negotiation.html) | Require CAP LS/REQ/ACK, PLAIN challenge, server 903 success before CAP END, then welcome 001 | Positive, negative, wrong-server preflight tests against real IRCd |
| [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) | Verify server identity with authenticated TLS | Python bootstrap and Rust client each verify a throwaway localhost CA + SAN |
| [keyring 3.6.3](https://docs.rs/keyring/3.6.3/keyring/) | Native OS credential lifecycle needs real interactive tests | Ignored, explicit, manual macOS/Windows test with a unique synthetic entry |
| [systemd credentials](https://systemd.io/CREDENTIALS/) | Service-scoped secrets may use device-bound TPM2 encryption | Candidate for supported hardware only; no automatic ARMv6 claim |
| [systemd-creds](https://www.freedesktop.org/software/systemd/man/260/systemd-creds.html) | Host-key-only credentials rely on filesystem security; null-key gives no protection | Disallow null-key or plaintext fallback for high-trust field credentials |
| [Rust platform support](https://forge.rust-lang.org/platform-support.html), [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) | Build does not equal OS security or physical device acceptance | Signed bundles and real ARM/old-Linux validation remain separate gates |

## Implemented G2e source

- **net/tests/bootstrap_ergo_account.py:** Python TLS bootstrap, only 127.0.0.1:16697, pinned runner-created CA and a publicly known disposable synthetic fixture. No real account or organizational secret; never use in deployment.
- **net/tests/ergo_sasl.rs:** ignored-by-default test of real SASL PLAIN 903 success, wrong-password rejection without anonymous downgrade, and mismatched server-name reference rejected *before* secret lookup. Uses an in-memory fixture store, NOT an OS keychain.
- **.github/workflows/ergo-interop.yml:** keeps immutable-digest-pinned Ergo and a localhost-only TLS port; runs existing ordinary chat interop, synthetic account creation and G2e real-account SASL tests; deletes the container and temporary CA afterwards.
- **net/tests/native_keyring_lifecycle.rs:** ignored by default, macOS/Windows only with optional os-keyring feature. Requires explicit local test approval, generates a unique synthetic account key, tests write/read/rotate/revoke/denial and best-effort cleanup. Not run automatically in public CI. The approval string is a test guard, NOT a verified operator session.

## Headless Linux and old-device credential alternatives

| Candidate | Deployment interpretation | Gate |
|---|---|---|
| Device TPM2 + PCR/boot-policy-bound secret | Could provide hardware-bound encryption, but not every Raspberry Pi has a TPM; replacement devices require re-enrollment | Prefer on equipped, verified units; select hardware, review measured boot and anti-cloning |
| TPM-backed systemd-creds | Decrypts service-scoped credential at activation on supported systemd/TPM2 | Only if systemd, boot chain, TPM and policy are actually available; older ARM support unproven |
| External secure element / HSM | May provide identity binding without integrated TPM | Hardware/vendor/toolchain, issuance and revocation testing required |
| Trusted current gateway paired to old Pi | Keep unsupported legacy Pi as limited terminal; modern gateway holds keys and authenticates to IRC | Feasible fallback architecture, not implemented |
| Filesystem plaintext / environment variables / argv / mock provider / null-key encrypted credential | Clonable or exposes secrets, does not meet field trust requirements | **Rejected for production** |

Raspberry Pi models cannot be assumed to provide an RTC, TPM2, Secure Boot, usable systemd version or crypto-provider instructions. Cross compilation only proves source compatibility.

## Acceptance gates

- [x] [G2e portable Rust 1.70/stable and ARM/musl compile-only checks 10/10 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40448428217).
- [x] [G2e locked TLS tests/Clippy and native feature compile tests 3/3 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40448428222).
- [x] [Pinned independent Ergo 1/1 job passed](https://github.com/pskeffington/rusti_rc/actions/runs/40448428240): 1 ordinary IRC channel test plus 3 real-account SASL tests (903 accepted, wrong-password rejection, wrong-host pre-secret policy).
- [x] Reviewed G2e test fixture: only a publicly known synthetic account password on ephemeral, localhost TLS; test outputs use typed protocol events, not raw SASL payloads. This is a code/log-scope check, not an independent audit.
- [ ] Run manual native keychain lifecycle tests with explicit local operator permission on macOS and Windows; record redacted evidence.
- [ ] Test keychain lock/denial and rotation, and do not substitute a mock on an old Pi.
- [ ] Validate future headless TPM/security provider on *real* hardware, signed bundle and A/B redeployment.
- [ ] Add SASL slow-peer/cancellation cases, second independent IRCd, RustSec/license audit and device-vs-IRC identity separation.

## Manual desktop keychain test

On a permissioned desktop workstation, from the repository root, execute:

    RUSTI_ALLOW_LOCAL_KEYRING_TEST=I_ACCEPT_SYNTHETIC_ENTRY cargo +stable test --manifest-path net/Cargo.toml --locked --features os-keyring --test native_keyring_lifecycle -- --ignored

This creates and deletes only a unique synthetic keychain entry; it must not be run on shared CI, a service account or an unapproved workstation. If interrupted, inspect the isolated test entry for cleanup.

**Trust boundary:** real IRC SASL authenticates an account to that server only. It does not grant Rust Boy Vault rights, RB-to-RB device trust, E2EE or a reliable recipient-storage receipt.

## Independent interoperability finding

The first positive SASL test exposed a registration mismatch: Ergo supplied numeric 903 using a pre-registration wildcard target. The portable SaslPlainFlow now permits '*' **only for numeric 903 after verified TLS, CAP ACK and the credential-response write**. Final numeric 001 still requires the expected nickname. Explicit unit tests verify a wildcard 903 followed by a rejected wildcard 001, and reject a 903 targeted at an unrelated named user. Failure diagnostics contain only the pre-failure protocol stage and a fixed event category; no raw frame or secret bytes are logged.

**Not established by this pass:** actual native macOS Keychain or Windows Credential Manager provision/read/delete (manual opt-in test source only), legacy runtime or TPM-backed storage, independent second IRCd, signed offline updater/rollback, organizational command authority, or recipient delivery acknowledgments.
