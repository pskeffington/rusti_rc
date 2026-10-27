# Verified TLS IRC transport (G2 implementation preview)

**Not a public release or Rust Boy import.** This nested Cargo workspace uses Rust 2021 with a modern security-maintained TLS dependency separately from the root Rust 1.70 protocol workspace. It does not run at program startup, open a background listener, or send data to any public server by default.

## Exact implementation

- `net/Cargo.toml`: maintained `rustls = 0.23.46`, explicit `ring` provider, `webpki-roots = 1.0.9`; `rcgen` is used **only in tests** to create ephemeral in-memory localhost certificates.
- `net/src/lib.rs`: `TlsIrcSession::connect_tls` takes a validated `rusti_client::ClientConfig`, a concrete IP/port `SocketAddr`, a reviewed `RootCertStore`, and bounded timeouts. **Calling it is an explicit network action.** There is no DNS lookup, provider guessing, certificate-skip option, plaintext fallback, secret-bearing SASL, discovery, or automatic reconnect.
- `TlsIrcSession` offers bounded read callbacks, restricted IRC registration, JOIN, PING/PONG response, and `PRIVMSG`. A write reports `SubmittedUnconfirmed`, never Rust Boy `STORED`.
- `net/tests/verified_tls_loopback.rs` generates ephemeral certificates in memory and validates success, hostname mismatch, untrusted roots, preflight TLS policy, and safe message framing on localhost. Tests must pass CI before any merge.

## Offline-only test on a development machine

```sh
cargo +stable test --manifest-path net/Cargo.toml --all-targets
cargo +stable clippy --manifest-path net/Cargo.toml --all-targets -- -D warnings
cargo +1.70.0 test --workspace --all-targets
```

The first run needs crates.io access to obtain the approved dependencies. After a Cargo-generated `net/Cargo.lock` is committed, builds can use `--locked` with a vendor cache. **No release lockfile, SBOM, signature or offline vendor bundle is yet committed.**

## Legacy OS / ARM policy

The root parser stays Rust 1.70. This TLS crate is currently evaluated with modern Rust (declared minimum 1.85; actual dependency MSRV and old OS ABI still require testing). The `ring` provider must be validated separately on ARMv6/ARMv7, musl and older Linux kernels; an ARM cross-check or source compilation alone does not prove functionality. Under no circumstance disable TLS name verification merely to reach an old server.

Do not use the current transport for clinical records, safety-of-life messaging, mission assignments, organizational authorization or E2EE. Standalone TLS protects the client-server leg only, not the IRC server or any other participants.

## Next gates

- Full IRC registration/CAP state handling and independent IRCd integration.
- Trust-root enrollment and rotation, credential handling and SASL where justified, plus certificate expiry and MITM coverage.
- Security and license audit, Cargo.lock, vulnerabilities/SBOM, and hardening against slow peers and reconnect floods.
- Actual Pi/older host hardware tests and signed offline redeployment.
- Optional, feature-gated Rust Boy LINK import only after verified integration acceptance.

See [G2 architecture](../docs/architecture/G2_SECURE_TRANSPORT_DECISION.md) and [Rust Boy adapter contract](../docs/integration/RUST_BOY_ADAPTER_CONTRACT.md).
