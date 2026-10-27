# Verified TLS IRC transport (G2 implementation preview)

**Not a public release or Rust Boy import.** This nested Cargo workspace uses Rust 2021 with a modern security-maintained TLS dependency separately from the root Rust 1.70 protocol workspace. It does not run at program startup, open a background listener, or send data to any public server by default.

## Exact implementation

- `net/Cargo.toml`: maintained `rustls = 0.23.46`, explicit `ring` provider, `webpki-roots = 1.0.9`; `rcgen` is used **only in tests** to create ephemeral in-memory localhost certificates.
- `net/src/lib.rs`: `TlsIrcSession::connect_tls` takes a validated `rusti_client::ClientConfig`, a concrete IP/port `SocketAddr`, a reviewed `RootCertStore`, and bounded timeouts. **Calling it is an explicit network action.** There is no DNS lookup, provider guessing, certificate-skip option, plaintext fallback, discovery, or automatic reconnect. SASL PLAIN is an explicit separate registration mode using a validated credential reference.
- `TlsIrcSession` offers bounded read callbacks, explicit CAP registration over authenticated TLS, JOIN, PING/PONG response, and `PRIVMSG`. JOIN and PRIVMSG reject sends until IRC registration succeeds, and a mandatory capability's revocation disables sending. A write reports `SubmittedUnconfirmed`, never Rust Boy `STORED`.
- `register_with_capabilities` is intentionally anonymous, while `register_sasl_plain` is the separate **opt-in**, blocking SASL PLAIN flow. Both use the private `TlsIrcSession::run_registration_once` guard: one attempt, restore timeouts only on success, and terminal socket shutdown on error. Missing PLAIN, rejected SASL, premature 001, and TLS trust errors never become an anonymous downgrade. See [G2d design](../docs/architecture/G2D_SASL_NATIVE_CREDENTIALS.md).
- `net/tests/verified_tls_loopback.rs` generates ephemeral certificates in memory and validates success, hostname mismatch, untrusted roots, preflight TLS policy, and safe message framing on localhost. Synthetic TLS tests and Clippy passed in the [Linux/macOS/Windows locked G2b CI matrix](https://github.com/pskeffington/rusti_rc/actions/runs/40443606042) (3/3). The original TLS client merged in [PR #3](https://github.com/pskeffington/rusti_rc/pull/3); explicit registration and certificate-validity tests merged in [PR #4](https://github.com/pskeffington/rusti_rc/pull/4).

## Offline-only test on a development machine

```sh
cargo +1.90.0 fmt --all --manifest-path net/Cargo.toml -- --check
cargo +stable test --manifest-path net/Cargo.toml --all-targets --locked
cargo +stable clippy --manifest-path net/Cargo.toml --all-targets --locked -- -D warnings
# On macOS/Windows, compile/test optional native secure-store feature (no real secrets)
cargo +stable test --manifest-path net/Cargo.toml --all-targets --all-features --locked
cargo +1.70.0 test --workspace --all-targets
```

The first run needs crates.io access to obtain the approved dependencies. The Cargo-generated **`net/Cargo.lock` is committed** with 87 resolved packages from the GitHub Ubuntu test job, and CI now uses `--locked`. This pins dependency resolution, but a complete SBOM, security advisory/license audit, release signature, and offline vendor bundle have **not** been produced.

## G3b operator-send boundary (development preview)

The portable `rusti_client::outbox::OperatorOutbox` contains bounded in-memory drafts (default 16 messages, 8 KiB of encoded IRC data), validated with the same PRIVMSG encoder as the transport. Import is inert and no draft is persisted.

`TlsIrcSession::operator_submit_next(&mut outbox, operator_confirmed)` permits **one** FIFO draft only when the actual IRC session is registered and the caller has obtained fresh explicit user confirmation. A successful TLS write yields `OperatorSendOutcome::SubmittedUnconfirmed`, not delivery to a recipient. A write error yields `OperatorSendError::OutcomeUnknown`, closes the socket, and discards all other drafts; it **never** retries a possibly accepted message.

Call `operator_read_once(&mut outbox, callback)` when monitoring an active operator session: EOF, malformed server frames, lost capabilities and TLS read errors terminate the session and discard unsubmitted drafts. `operator_disconnect(&mut outbox)` provides explicit teardown. Do not call blocking TLS I/O on the desktop/handheld render thread, keep messages out of logs, and do not treat an IRC nickname or account as a Vault Command identity. This is not persistent offline chat or a safe emergency messaging channel.

Tests: `cargo test --manifest-path net/Cargo.toml --all-targets --locked` exercises simulated send failure, denied confirmation, queue drain, a real localhost verified-TLS submission, and server disconnect. Physical host and second IRCd validation remain necessary.

## Legacy OS / ARM policy

The root parser stays Rust 1.70. This TLS crate is currently evaluated with modern Rust (declared minimum 1.85; actual dependency MSRV and old OS ABI still require testing). The `ring` provider must be validated separately on ARMv6/ARMv7, musl and older Linux kernels; an ARM cross-check or source compilation alone does not prove functionality. Under no circumstance disable TLS name verification merely to reach an old server.

Do not use the current transport for clinical records, safety-of-life messaging, mission assignments, organizational authorization or E2EE. Standalone TLS protects the client-server leg only, not the IRC server or any other participants.

## Next gates

- [G2e independent Ergo SASL test suite](tests/ergo_sasl.rs) and [throwaway registered-account bootstrap](tests/bootstrap_ergo_account.py) are isolated to a localhost-only CI job. [G2e independent CI passed](https://github.com/pskeffington/rusti_rc/actions/runs/40448428240) using synthetic fixture credentials. A passing test proves real third-party IRCd account flow, NOT protected OS credentials.
- [Ignored manual native Keychain/Credential Manager lifecycle test](tests/native_keyring_lifecycle.rs) covers synthetic provisioning/rotation/revocation with explicit local permission and is never automatically executed in CI. See [G2e architecture](../docs/architecture/G2E_INDEPENDENT_SASL_LEGACY_KEYS.md).
- [G2f cancellable IRC/CAP and SASL registration](src/cancel.rs) now uses a monotonic overall deadline and terminal failure shutdown; [silent-peer, trickle and cancellation regression tests](tests/registration_interruptions.rs) cover verified TLS localhost cases. The opt-in APIs do **not** launch threads or retries. See [G2f security and legacy deployment gates](../docs/architecture/G2F_REGISTRATION_HARDWARE_GATES.md).
- [Offline legacy host preflight](../scripts/legacy_host_preflight.sh) reports only coarse capability hints; hardware approval is always blocked until real-device testing.
- Broader IRC registration and capability edge cases across a second independent IRCd. [Ergo interoperability](../.github/workflows/ergo-interop.yml) has already passed using a digest-pinned server image.
- Test actual native macOS/Windows secret provisioning, retrieval, rotation and denial. Ergo **already passed** synthetic-account SASL success/failure; a second independent IRCd and real native OS keyring lifecycle remain open.
- Security and license audit, vulnerabilities/SBOM, and hardening against slow peers and reconnect floods. Cargo.lock is already pinned.
 - Feature-gated [macOS/Windows native credential adapter](src/native_store.rs) is implemented and compile/negative-tested, while the portable [CredentialRef](../crates/rusti-client/src/credential_ref.rs) itself remains a no-I/O identity handle. Linux headless protected storage and actual OS-backed secret lifecycle are pending.
- Actual Pi/older host hardware tests and signed offline redeployment.
- Optional, feature-gated Rust Boy LINK import only after verified integration acceptance.

See [G2 architecture](../docs/architecture/G2_SECURE_TRANSPORT_DECISION.md) and [Rust Boy adapter contract](../docs/integration/RUST_BOY_ADAPTER_CONTRACT.md).
