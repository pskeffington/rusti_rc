# G2d — Explicit SASL authentication and protected native credential stores

Baseline: 2026-10-26. **Source implementation in PR #6; not a field release or integrated Rust Boy module.** An IRC SASL account is not an authenticated Rust Boy operator, organizational grant, device identity, emergency receipt or end-to-end encrypted chat.

## Source-backed design matrix

| ID | Primary reference | Engineering requirement | G2d implementation / remaining gate |
|---|---|---|---|
| A01 | [IRCv3 SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2) | Request SASL capability, await ACK, AUTHENTICATE mechanism, process challenge and numeric 903 before CAP END | Separate explicit SASL PLAIN state machine; required mechanism prevents anonymous downgrade |
| A02 | [IRCv3 SASL 3.1](https://ircv3.net/specs/extensions/sasl-3.1) | Base64 payloads use max 400-byte chunks; 0 length uses +, exactly 400 requires final +; errors 904–907 reject | Strictly limit account and secret size so a **single payload under 400 bytes** is supported; reject larger secrets rather than implement unchecked chunking |
| A03 | [IRCv3 CAP 302](https://ircv3.net/specs/extensions/capability-negotiation.html) | CAP LS, REQ, ACK and END must respect write ordering | Every SASL control action has a confirmed local write barrier; 001 is accepted only after 903 and CAP END write |
| A04 | [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) | Only authenticate over modern verified TLS, bound to explicit DNS/IP service identity | Existing rustls verified transport required; credential reference bound to originally authenticated host and TCP port |
| A05 | [Rust keyring 3.6.3](https://docs.rs/keyring/3.6.3/keyring/) | Native macOS Keychain and Windows Credential Manager, no passwords in arguments or configuration | Optional build feature uses native secure stores on supported desktops; headless Linux and unsupported OSes explicitly refuse operations |
| A06 | [zeroize 1.9.1](https://docs.rs/zeroize/1.9.1/zeroize/) | Clear ephemeral secret buffers without an optimizing compiler removing the wipes | Password-derived raw/plain, base64 and IRC frames stored in Zeroizing Vec; retrieved native secrets wrapped in Zeroizing before callback |
| A07 | [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Reproducible dependency resolution, threat modeling, credentials/lifecycle testing | Cargo lockfile, PR CI, synthetic negative tests; independent vulnerability and hardware review still pending |
| A08 | [Rust supported platforms](https://forge.rust-lang.org/platform-support.html) | Toolchain support distinct from binary compatibility and OS secret-store availability | Rust 1.70 core unchanged. Modern TLS and keyring compile/run separately; older ARM/Windows EOL systems not guaranteed |

## Trust boundary and code inventory

- `crates/rusti-proto/src/sasl.rs`: zero-I/O Rust 1.70 data-only SASL state machine, no secrets. Requires `sasl=PLAIN` advertisement, exact ACK, server `AUTHENTICATE +`, required 903, CAP END and 001; rejects 904–908, malformed replies, early welcome, mismatched recipient and capability revocation.
- `net/src/sasl.rs`: explicit `TlsIrcSession::register_sasl_plain`, using the already verified TLS stream and a server/port-bound `CredentialRef`. Only obtains credentials when the TLS-authenticated server requests a challenge. Limits password length to 192 bytes, generates a single bounded AUTHENTICATE frame, and zeroizes password-derived buffers. Socket is shut down on any authentication failure.
- `net/src/native_store.rs` behind feature `os-keyring`: macOS Keychain / Windows Credential Manager access via pinned Rust keyring crate; operator-approved provision/revoke calls, no env, CLI, file or fallback secret storage. On Linux or unsupported platforms, operations fail closed.
- `net/tests/sasl_loopback.rs`: synthetic in-memory secret fixture and localhost TLS IRCd. Tests successful 903→CAP END→001, 904 rejection, unavailable PLAIN, and premature welcome. No real secrets or external account service used.
- `net/Cargo.lock`: must be regenerated with Cargo and committed after dependency selection; `--locked` test CI is required before merge.

## Security invariants

1. Ordinary IRC registration remains a separate operator mode with no SASL credentials. The SASL method never silently downgrades to anonymous IRC after a missing PLAIN mechanism, invalid certificate, 904 failure, early 001, mismatched identity, or keychain error.
2. The `CredentialRef` does not embed secret bytes and cannot be used against another host/port. The initial verified TLS identity is stored in the session; the caller cannot supply a different identity when requesting secret use.
3. A successful TLS write means **submitted/unconfirmed**, not IRC server delivery or Rust Boy receiver receipt.
4. No keychain call happens upon import, initial CLI launch, rendering, disabled profile, or passive probing. Native credential I/O requires an operator-invoked method.
5. Linux headless units cannot use the desktop backend. A future hardware-secured or approved secret-service implementation needs independent investigation; **never** substitute plaintext files, environment variables, test mocks or weak crypto to 'support' an older Pi.
6. The code zeroizes temporary buffers within the Rust process, but cannot guarantee OS swap, allocator copies, panic unwinding outside the guarded path, or complete secret erasure from the OS keychain.
7. Keyring approval is scoped to IRC credentials only. An authenticated IRC account grants no Rust Boy Vault Command authority or organizational trust.
8. User interfaces must render IRC content with control stripping and text-only DOM widgets. Never show SASL AUTHENTICATE frames or password-equivalent base64 payloads in logs, traces or telemetry.

## Acceptance evidence to capture

- [ ] Rust 1.70/stable portable CI and ARM/musl compile-only checks.
- [ ] Linux/macOS/Windows locked modern TLS CI plus synthetic SASL success/failure.
- [ ] Optional macOS/Windows native-store feature build/lint; test only non-mutating refusal paths in CI.
- [ ] Independently built Ergo interop remains green for ordinary TLS/CAP/chat.
- [ ] Freeze regenerated modern Cargo.lock with no ad-hoc dependency drift.
- [ ] Real, permissioned test on macOS Keychain and Windows Credential Manager for provisioning, retrieval, rotation, denial, and revocation, without logging secrets.
- [ ] New independent IRCd account test verifying SASL 903 success, 904 failure, and no anonymous fallback; synthetic tests alone do **not** prove external SASL compatibility.
- [ ] Revocation propagation, secure hardware time, offline key provisioning and signed A/B redeployment on actual old Linux/ARM devices.

**Stop conditions:** no unvalidated cert roots, no plaintext fallback, no keychain test mock on a field device, no credentials in source/environment/argv/logs, and no IRC account role -> Vault grant conversion.
