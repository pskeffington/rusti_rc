# G2 authenticated TLS client implementation and validation record

Date: 2026-10-26. Status: **implementation under G2 PR; not a production networking release.** Tests are synthetic loopback-only, not real IRC server interoperability or ARM hardware acceptance.

| Control | Implemented in source | Evidence still required |
|---|---|---|
| Separate modern TLS MSRV | Independent `net/` Cargo workspace; root Rust 1.70 crates excluded from dependency resolution | CI confirmation and exact dependency MSRV |
| TLS provider and supported protocols | `rustls 0.23.46`, explicit `ring`, TLS 1.2/1.3; no insecure verifier | ABI/crypto provider audit and real-device tests |
| Explicit socket connect | `connect_tls` requires enabled client, explicit socket address matching configured port | Test disabled config creates zero sockets |
| Server authentication | `ServerName::try_from(config.server_host)` + `RootCertStore` + default rustls validation | Negative local cert tests; enterprise root enrollment review |
| No TLS downgrade | ClientConfig rejects `tls_required=false`; only rustls StreamOwned can send IRC | Negative preflight and invalid certificate tests |
| Time limits | Connect, full TLS handshake deadline, and I/O timeouts capped at 30s | Artificial slow server / boundary and cancellation tests |
| Bounded app framing | 1 KiB per-call plaintext reads into existing FrameDecoder with max 8703-byte frame budget | Flood/latency/hardware memory tests |
| Untrusted chat state | Restricted encoders, no SASL, IRC nick remains untrusted, writes are `SubmittedUnconfirmed` | Independent security and Rust Boy integration review |
| Legacy compatibility | Root protocol Rust 1.70 preserved; TLS workspace modern | ARMv6/ARMv7, old Linux, macOS/Windows real tests |
| Offline redeployment | No installer or versioned, signed trust-root bundle added | G6 signed release and rollback drills |

Source basis: [rustls 0.23](https://docs.rs/rustls/0.23.46/rustls/), [webpki-roots 1.0.9](https://docs.rs/webpki-roots/1.0.9/webpki_roots/), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525), [rcgen 0.14.10](https://docs.rs/rcgen/0.14.10/rcgen/).

The TLS client intentionally does **not** offer background reconnect or arbitrary raw command execution. Control of roles and Vault assignment is held by Rust Boy, not by IRC server nicknames or authenticated IRC accounts.

**Blocking caveats:** CRL/OCSP revocation verification and offline time attestation are not solved here; the root store is caller-provisioned and must be managed by an approved trust workflow. The current examples/test certificates are synthetic and never checked in as private keys. A successful localhost test must not be interpreted as secure production field deployment.
