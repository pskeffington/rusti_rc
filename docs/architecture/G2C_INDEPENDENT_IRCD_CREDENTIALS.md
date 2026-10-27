# G2c — Independent IRCd interoperability and protected credential boundary

Status: **implementation and CI in review**, 2026-10-26. This is not a release, an account login implementation, or a real Rust Boy integration.

## External evidence and protocol source matrix

| ID | Reference | Relevant requirement | Application / gate |
|---|---|---|---|
| C01 | [Ergo Docker deployment](https://github.com/ergochat/ergo/blob/master/distrib/docker/README.md) | Official independently implemented Go IRCd; TLS listener at 6697; default config and certificates generated inside container | Pin Ergo **release tag** `v2.19.1`, localhost-only port; copy throwaway ephemeral test certificates; record image digest in CI logs; final promotion still requires immutable digest pin |
| C02 | [Ergo v2.19.1 release](https://github.com/ergochat/ergo/releases/tag/v2.19.1) | August 2026 security release | Prefer latest security-patched published release rather than older sample versions; re-evaluate later |
| C03 | [Ergo default config](https://github.com/ergochat/ergo/blob/master/default.yaml) | Separate plaintext/TLS ports and certificate paths; configurable history and account behavior | Only TLS 6697 is mapped, **to 127.0.0.1**; never export plain 6667 or copy real IRC credentials into tests |
| C04 | [IRCv3 capability negotiation](https://ircv3.net/specs/extensions/capability-negotiation.html) | CAP LS 302 / REQ / ACK / END | Test required `message-tags`, optional `server-time`, registration numerics and post-registration message exchange against non-rusti IRCd |
| C05 | [IRCv3 SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2.html) | Authentication requires negotiated SASL capability; refusal when no authentication backend available | **No SASL traffic yet.** The credential ref cannot be resolved until real protected OS storage, explicit operator consent and TLS/CAP gating are reviewed |
| C06 | [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) | Modern TLS and verified service identity | Test client must trust **only** runner-created ephemeral CA, validate `localhost` certificate SAN, and never disable verifier |
| C07 | [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Secure development and supply-chain evidence | CI read-only permissions, pinned checkout SHA, versioned test image, isolated no-secret test fixture, exact lockfile |
| C08 | [Rust platform support](https://forge.rust-lang.org/platform-support.html) | Cross-compile support is distinct from physical-device support | Do not describe older Pi/OS systems as runtime-validated until hardware measurements and TLS provider checks pass |

## Implemented G2c architecture

- `crates/rusti-client/src/credential_ref.rs`: redacted `CredentialRef` with constrained opaque item ID, explicit credential purpose and server identity binding; `ProtectedCredentialStore` callback interface has **no implementation**. There is no stored password, plaintext config, file-backed secret, credential retrieval, or SASL command in this pass. The endpoint and trust root are configured separately.
- `net/tests/ergo_interop.rs`: ignored-by-default Rust test that requires `RUSTI_ERGO_ADDR` and `RUSTI_ERGO_CA_DER`; two real TLS sessions explicitly register via CAP, JOIN the same synthetic channel, and verify that one sender's message reaches the other through Ergo.
- `.github/workflows/ergo-interop.yml`: Docker-based independent IRCd test on a fresh Linux runner, version-tagged Ergo v2.19.1, throwaway CA/leaf cert with `localhost` SAN, localhost-only published TLS port, no real credentials and cleanup on exit. Docker digest logged, but **not yet locked by immutable sha256**.
- Existing `G2b` and `G2` test suites remain mandatory and separate. No startup/init hook creates a socket. Ordinary unit tests do not start Ergo or require Docker.

## Acceptance and security limits

1. A passing synthetic TLS mock-server test does **not** establish interoperability. Ergo test must independently pass and produce logs showing its exact image digest and the success of two-client registration and PRIVMSG routing.
2. No operational server may be contacted by the CI job. The Docker port is published to local loopback only; plaintext port 6667 is not published to the host.
3. A copied transient certificate/private key is acceptable only inside the isolated synthetic CI lab. Real keys are never made world readable, logged, committed or packed into a distributed artifact.
4. `CredentialRef` is **not a protected OS credential store**. It cannot be resolved through environment variables, CLI args or plaintext files in a production build. The platform adapters for Windows Credential Manager, macOS Keychain and approved Linux secure storage still require separate security and deployment review (headless Pi may lack a desktop keyring).
5. Future SASL PLAIN must be opt-in and conditional on verified TLS, `sasl` CAP ACK, compatible mechanism advertisement, and successfully loaded protected account credentials; any failure must disconnect without a plaintext or unauthenticated fallback if authentication was required.
6. Even successful SASL verifies an IRC account **on that server only**, not Rust Boy organizational authority, end-to-end identity, Vault assignments, or a delivery receipt.
7. CI image tag is reproducible by version label but mutable by registry owner; require recording the digest and pinning it in a subsequent supply-chain gate before release.
8. The test performs no throughput, reliable delivery, reconnection, field RF, medical dispatch, or old-device performance claim.

## Next engineering gates

- Freeze Ergo image by immutable digest, rerun against another independent IRCd such as InspIRCd, and compare outbound/inbound numeric cases.
- Implement one platform-vetted `ProtectedCredentialStore` backend with secure provisioning/rotation and no secrets in logs, config or test artifacts.
- Develop SASL PLAIN/EXTERNAL only with a reviewed authenticated TLS handshake and matching server capability.
- Add disconnect/cancellation and slow-trickle security tests. Address any CAP/command parser disagreement found with independent IRCd.
- Complete real Pi Zero ARMv6/ARMv7/ARM64 and old supported Linux runtime tests.
- Run dependency/advisory audits, signed offline release and rollback tests before adding a Rust Boy LINK UI feature gate.

**Promotion rule:** No G2c readiness claim until the independent Ergo workflow and both existing matrices pass. Do not infer results from a green earlier PR.
