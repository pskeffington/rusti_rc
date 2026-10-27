# G2 authenticated TLS client implementation and validation record

Date: 2026-10-26. Status: **G2 TLS preview merged to main via PR #3 (`f0cd7c9801b435a11c4067fdac33b0fa2a2693f3`); not a production networking release.** [Final locked TLS CI passed 3/3 jobs](https://github.com/pskeffington/rusti_rc/actions/runs/40442639269) on Linux/macOS/Windows, including synthetic localhost TLS tests and Clippy. [Portable core passed 10/10](https://github.com/pskeffington/rusti_rc/actions/runs/40442639261). These are not independent IRC server interoperability or ARM hardware acceptance.

| Control | Implemented in source | Evidence still required |
|---|---|---|
| Separate modern TLS MSRV | Independent `net/` workspace; root Rust 1.70 protocol tests remained green | Net workspace compiled/tested on stable; Rust 1.85 exact MSRV unverified |
| TLS provider and supported protocols | `rustls 0.23.46`, explicit `ring`, TLS 1.2/1.3; no insecure verifier | ABI/crypto provider audit and real-device tests |
| Explicit socket connect | `connect_tls` requires enabled client, explicit socket address matching configured port | Test disabled config creates zero sockets |
| Server authentication | `ServerName::try_from(config.server_host)` + `RootCertStore` + default rustls validation | Local wrong-name and untrusted-CA rejection passed; enterprise root enrollment review pending |
| No TLS downgrade | ClientConfig rejects `tls_required=false`; only rustls StreamOwned can send IRC | Local negative preflight test passed; independent pentest pending |
| Time limits | Connect, full TLS handshake deadline, and I/O timeouts capped at 30s | Artificial slow server / boundary and cancellation tests |
| Bounded app framing | 1 KiB per-call plaintext reads into existing FrameDecoder with max 8703-byte frame budget | Flood/latency/hardware memory tests |
| Untrusted chat state | Restricted encoders, no SASL, IRC nick remains untrusted, writes are `SubmittedUnconfirmed` | Independent security and Rust Boy integration review |
| Legacy compatibility | Root protocol Rust 1.70 preserved; TLS workspace modern | ARMv6/ARMv7, old Linux, macOS/Windows real tests |
| Locked dependencies | Cargo-generated net/Cargo.lock committed with 66 packages; --locked tests and lint passed on Linux/macOS/Windows | Independent CVE/license/SBOM review pending |
| Offline redeployment | No installer or versioned, signed trust-root bundle added | G6 signed release and rollback drills |

Source basis: [rustls 0.23](https://docs.rs/rustls/0.23.46/rustls/), [webpki-roots 1.0.9](https://docs.rs/webpki-roots/1.0.9/webpki_roots/), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), [rcgen 0.14.10](https://docs.rs/rcgen/0.14.10/rcgen/).

The TLS client intentionally does **not** offer background reconnect or arbitrary raw command execution. Control of roles and Vault assignment is held by Rust Boy, not by IRC server nicknames or authenticated IRC accounts.

**Blocking caveats:** CRL/OCSP revocation verification and offline time attestation are not solved here; the root store is caller-provisioned and must be managed by an approved trust workflow. The current examples/test certificates are synthetic and never checked in as private keys. A successful localhost test must not be interpreted as secure production field deployment.

## G2b registration/validity extension (merged 2026-10-26)

The [G2b registration and recovery contract](../architecture/G2B_REGISTRATION_RECOVERY.md) adds gated CAP 302 + NICK/USER/001 processing, blocks chat sends until registration, recognizes mandatory-capability revocation, and introduces an operator-authorized **pure-data** retry policy with no automatic connections. Local ephemeral-CA tests verify rejection of expired and not-yet-valid end-entity certificates before IRC registration. [G2b portable CI 10/10](https://github.com/pskeffington/rusti_rc/actions/runs/40443606057) and [G2b locked TLS CI 3/3](https://github.com/pskeffington/rusti_rc/actions/runs/40443606042) passed on tested PR head `1c2786de9e623cc85a45b9d27fc8a30f79e2b41b` (merge `cfd0f38ede273a778dd31ba160a876930899c3d8`). External IRCd interoperability, certificate revocation freshness, OS credential store, TAS/signed release, and actual legacy hardware acceptance remain pending.
