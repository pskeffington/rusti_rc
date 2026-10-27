# G2f — Bounded registration, cancellation and legacy hardware deployment gates

Status: **merged to main**, 2026-10-27, via [G2f PR #9](https://github.com/pskeffington/rusti_rc/pull/9), squash commit `2044f63f909debae2a722315138c8b77b7b535bc`. Tested PR head `25984a969711e70705240c5297dcc3d0f4fa3495` passed [portable 10/10](https://github.com/pskeffington/rusti_rc/actions/runs/40456201437), [locked TLS 3/3](https://github.com/pskeffington/rusti_rc/actions/runs/40456201424), and [independent Ergo 1/1](https://github.com/pskeffington/rusti_rc/actions/runs/40456201422). This is **not** approval for Rust Boy production, medical messaging, or Vault Command assignments.

## Source-backed engineering literature matrix

| ID | Primary reference | Specific practice | G2f implementation / release gate |
|---|---|---|---|
| F01 | [Rust std::net::TcpStream timeouts](https://doc.rust-lang.org/std/net/struct.TcpStream.html) | Read timeout errors may be WouldBlock (Unix) or TimedOut (Windows). A per-read timeout is **not** an entire registration deadline | Both SASL and anonymous CAP registration now use monotonic absolute deadlines plus a 200ms or shorter cancellation polling read limit |
| F02 | [RFC 9325 — secure TLS](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525 — service identity](https://www.rfc-editor.org/rfc/rfc9525) | Bound and authenticate the TLS session to a reviewed host/certificate | Existing rustls CA/SAN verification retained; cancelled/expired negotiation shuts down rather than retrying on plaintext |
| F03 | [IRCv3 capability negotiation](https://ircv3.net/specs/extensions/capability-negotiation.html), [SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2.html) | CAP/SASL must end with explicit protocol success before normal messages | Cancellation cannot convert a failed SASL attempt to anonymous success; verified 903 and 001 remain separate |
| F04 | [systemd credentials](https://systemd.io/CREDENTIALS/) | LoadCredentialEncrypted and TPM2/host key combinations depend on systemd, TPM and provisioning | Candidate on supported, equipped Linux; no implicit key-store backend or automatic downgrade |
| F05 | [systemd-creds reference](https://www.freedesktop.org/software/systemd/man/256/systemd-creds.html) | A host-only encryption key is filesystem-bound, while null-key provides no security | Field devices must disallow unbound/null-key credentials; do not assume legacy systemd has modern features |
| F06 | [Rust platform support](https://forge.rust-lang.org/platform-support.html) | Cross-target compilation does not prove old OS ABI, clock, entropy or hardware runtime | Offline host probe is read-only and always reports field approval blocked; physical acceptance is mandatory |
| F07 | [NIST SP 800-218 SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) | Trace secure development, change review, evidence and release provenance | CI regression suite and documented open signed/offline redeployment gates |

## Implemented source contracts

- **net/src/cancel.rs:** A shareable atomic RegistrationCancellation; no spontaneous networking, background thread, or automatic retry. The operator's worker may invoke cancel() from another thread.
- **net/src/lib.rs:** A saved I/O timeout, monotonic deadline enforcement and a read timeout limited to the smallest of deadline remaining, configured I/O limit and 200ms. Every failed or cancelled attempt shuts down the underlying socket and permanently consumes the registration attempt. Successful registration restores the original I/O timeout.
- **net/src/sasl.rs:** Existing register_sasl_plain remains source-compatible. The new register_sasl_plain_cancellable accepts explicit cancellation and checks it before/after each read, before protocol writes, and before transmitting credential-derived bytes. SASL password buffers remain zeroized.
- **net/src/registration.rs:** Anonymous (no-SASL) registration likewise supports cancellation through register_with_capabilities_cancellable and is terminal on timeout or peer/protocol failure.
- **net/tests/registration_interruptions.rs:** Localhost-only, ephemeral-TLS tests check silent peers, unfinished frame trickle, SASL and anonymous CAP deadlines, cancellation responsiveness, blocking chat sends and refusing re-registration. No test uses external IRC servers or real credentials.
- **scripts/legacy_host_preflight.sh:** POSIX sh, read-only offline inventory of CPU architecture, OS/kernel, libc hint, systemd release, TPM *device-node* presence, RTC and EFI directory presence. No DNS/socket, environment-secret lookup, serial number, account/hostname collection or TPM command invocation. Every output explicitly states credential_provider=unverified, hardware_runtime=unverified and field_deployment=blocked.
- **TLS CI (Linux/macOS/Windows):** Rust integration tests and Clippy. The Linux step checks preflight script syntax, expected output schema, and lack of hostname, serial or password fields. No physical device is enrolled.

## Failure and timing boundaries

1. Total registration time is measured from the beginning of IRC registration, not reset by individual server bytes or repeated read timeouts. The configured per-socket timeout is restored only after a successful registration. OS scheduling and blocking OS keychain unlock UI can extend wall-clock behavior; this is **not** a hard real-time deadline.
2. Cancellation is cooperative: a shared atomic token is polled between I/O operations. A current socket read can be delayed by at most its 200ms polling budget plus scheduling latency; a keychain lookup or OS prompt may still block and must remain on a dedicated cancellable *application worker*.
3. Failures, early cancellation and timeouts close the TCP/TLS connection and stop future JOIN/PRIVMSG submissions; no secret, credential downgrade or retry is authorized. The pure-data retry *proposal* from G2b is not a background reconnect implementation.
4. SASL credentials are looked up only after the server's negotiated challenge over verified TLS. If cancellation occurs during a synchronous credential-store callback, the returned secret is **not** sent after the deadline/cancellation check.
5. Transport encryption covers the client-to-IRC-server leg. IRC messages remain server-visible, are not an E2EE messenger, and an IRC account grants no Rust Boy command or organizational privilege.
6. The probe only reports availability hints. Presence of /dev/tpmrm0, UEFI directories or a systemd version does **not** prove correct key binding, provisioning, secure boot, RTC validity or tamper resistance.

## Legacy-device redeployment acceptance matrix

| Device class | Approved credential path candidate | Before production acceptance |
|---|---|---|
| Modern Linux with verified TPM2 and supported systemd | Hardware-bound per-device sealed credential via reviewed policy (TPM2; potentially supported systemd-creds) | Prove device-exclusive decryption, PCR/firmware policy, recoverable enrollment, secure clocks and revocation |
| Linux with independent non-exportable secure element | Device-unique issued key with hardware-bound proof; adapter still to be developed | Choose hardware/driver, validate secure key storage and revocation against cloned storage |
| Headless ARMv6/v7 without a verified hardware root | No local long-term organizational IRC password; act as limited display/transport endpoint for a separately authenticated modern gateway | Field-test gateway mutual authentication and ensure legacy terminal cannot hold Vault permissions or retrieve org credentials |
| macOS and Windows desktop | OS Keychain / Credential Manager behind opt-in feature | Manual synthetic provision, read, rotate, refusal, lock and revoke tests on actual allowed operator sessions |
| Unsupported kernel/libc/RTC/entropy/crypto ABI | None | Stop high-trust deployment; do not weaken certificate checks or ship a mock credential store |

For a **field acceptance report**, record only coarse OS/platform metadata and test outcome in version control. Store device IDs, private network information, and hardware credential evidence in separately controlled internal records. For each actual ARMv6/v7/ARM64 target, capture kernel/libc and toolchain compatibility, TLS handshake tests, clock integrity on cold boot, memory footprint and thermal soak, power-loss recovery, trust-root rotation, revocation without stale keys, offline authenticated A/B update, anti-rollback floor, and signed release verification. A cross-compile-only green check never completes this gate.

Run the safe, offline preflight on a consenting test device:

    sh scripts/legacy_host_preflight.sh

Do **not** parse the preflight as a release authorization. No Linux TPM device is opened and no stored credential is accessed.

## G2f acceptance

- [x] [Portable Rust 1.70/stable and ARM/musl source-only CI 10/10 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40456201437).
- [x] [Locked Linux/macOS/Windows TLS CI 3/3 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40456201424), including 5 new SASL/CAP cancellation/slow-peer tests, Clippy and Linux offline preflight checks.
- [x] [Digest-pinned independent Ergo IRC and synthetic registered-account SASL CI 1/1 passed](https://github.com/pskeffington/rusti_rc/actions/runs/40456201422).
- [x] Preflight source and CI output schema reviewed for absence of user identifiers, serials or secret-store reads; test fixture continues to use only a deliberately public disposable account credential. This is **not an external security audit**.
- [ ] Physical ARMv6/ARMv7/ARM64 host runs and real desktop OS keychain lifecycle evidence.
- [ ] Real TPM2/external-secure-element provisioning, protected time and recovery on redeployed hardware.
- [ ] Signed offline distributable with verified provenance, staged A/B recovery, reproducible toolchains, advisory/license SBOM and blocked rollback.
- [ ] Rust Boy integration behind an explicit feature and independently verified Vault permission boundary.

**Release classification:** G2f is a standalone network security and device-readiness development pass. No medical/emergency delivery assurances, RB-to-RB identity, E2EE, secure OS credential provisioning or deployment grant is implied.

## Exact G2f CI evidence

- Merge commit: `2044f63f909debae2a722315138c8b77b7b535bc`, [PR #9](https://github.com/pskeffington/rusti_rc/pull/9); tested head `25984a969711e70705240c5297dcc3d0f4fa3495`.
- [Portable CI](https://github.com/pskeffington/rusti_rc/actions/runs/40456201437): 10/10 host + compile-only targets passed. This does not prove real ARM runtime.
- [TLS CI](https://github.com/pskeffington/rusti_rc/actions/runs/40456201424): 3/3 Linux/macOS/Windows passed. Linux logs show 5/5 G2f interruption tests passed, plus read-only preflight output policy checks.
- [Independent Ergo CI](https://github.com/pskeffington/rusti_rc/actions/runs/40456201422): 1/1 isolated digest-pinned server job, including existing ordinary IRC and disposable SASL account login.

**Remaining acceptance boundary:** the cancellation latency guarantee is cooperative, not hard real-time, and OS native-store unlock operations remain synchronous. No physical ARM device was tested; no per-device hardware identity, TPM-backed credential, signed offline image, anti-rollback floor, OS keychain real lifecycle or Rust Boy authorization was provisioned.
