# G2b: IRC registration, certificate validity and bounded recovery

**Status:** G2b foundation merged to main in [PR #4](https://github.com/pskeffington/rusti_rc/pull/4) (merge commit `cfd0f38ede273a778dd31ba160a876930899c3d8`). [Portable CI #33](https://github.com/pskeffington/rusti_rc/actions/runs/40443606057) passed **10/10**, and [TLS CI #18](https://github.com/pskeffington/rusti_rc/actions/runs/40443606042) passed **3/3** on tested PR head `1c2786de9e623cc85a45b9d27fc8a30f79e2b41b`. Independent IRCd interoperability and real legacy hardware/security acceptance remain pending.

## Purpose and source alignment

The Rust Boy IRC alternative must not allow a logged-in transport connection to be mistaken for an IRC-registered operator, much less an authenticated organization. IRCv3 recommends `CAP LS 302`, `NICK`, `USER`, explicit capability selection and `CAP END` before registration completes. A successful `001` indicates an IRC server welcome, **not peer identity, a receipt, a job, or authorization**.

Normative references: [IRCv3 Capability Negotiation](https://ircv3.net/specs/extensions/capability-negotiation.html); [IRCv3 SASL 3.2](https://ircv3.net/specs/extensions/sasl-3.2); [IRC client protocol](https://modern.ircdocs.horse/); [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325).

## Implementation inventory

| Component | Actual source contract | Security consequence |
|---|---|---|
| [Pure-data registration](../../crates/rusti-proto/src/registration.rs) | Rust 1.70-compatible typed state, CAP LS/REQ/ACK/END, numeric 001, PING/PONG proposals, terminal error numerics | No welcome accepted before CAP END is actually written; no network by importing |
| [Pure-data recovery](../../crates/rusti-client/src/recovery.rs) | Bounded exponential delay with capped deterministic jitter and maximum three attempts by default | **No** timer/network/auto retry; certificate, identity, auth and invalid-protocol failures never eligible |
| [TLS coordination](../../net/src/registration.rs) | One explicitly invoked registration over a previously authenticated rustls session; maximum 30-second registration deadline | Must have authenticated server transport; no credentials or SASL flows |
| [TLS client](../../net/src/lib.rs) | JOIN and PRIVMSG return `NotRegistered` until welcome; post-register CAP DEL of mandatory capability terminates writable session | Prevents chat sends on a TLS-only or revoked IRC state |
| [Synthetic TLS IRCd](../../net/tests/registration_loopback.rs) | Local-only ephemeral test CA, signed leaves, CAP multipart script, NICK/USER/ACK/END/001, JOIN and PRIVMSG | Exercises real TLS and protocol framing, **not** independent production IRCd |
| [TLS client negatives](../../net/tests/verified_tls_loopback.rs) | Wrong name/root, plaintext attempt, injection and disabled client checks | TLS identity and unsafe output failure gates retained |

## Required behavior

1. **Connect only on explicit operator action** using a supplied socket and configured server name; reject missing/invalid roots, wrong name, invalid port and plaintext downgrade before issuing IRC commands.
2. Start with `CAP LS 302`, `NICK`, `USER` on a TLS-authenticated connection. Control responses are constructed from the tightly allowed CAP subset rather than accepting arbitrary remote command strings.
3. Wait for a CAP LS response, request only configured allowed capabilities, then wait for exact ACK. Do not silently assume an offered, unacknowledged or revoked capability is active.
4. Send `CAP END` and only accept `001` **after** the TLS write for that command completes. An early welcome, missing mandatory capability, nickname rejection, invalid PING, malformed frame or transport failure aborts registration.
5. For a legacy IRCd that does not support CAP, allow a TLS-secured connection **only if no capability is mandatory**. A required capability always fails closed.
6. Permit JOIN/PRIVMSG only in registered state. After CAP DEL revokes a mandatory capability, clear registered state and prevent further chat sends; require operator-controlled fresh connection.
7. Reconnect is *not automatically scheduled*. Pure-data RecoveryPolicy only proposes finite delays for transient TCP outage or unexpected connection loss **when separately approved by an operator**. No retry after TLS/authentication/identity failures.
8. Ordinary IRC chat remains server-readable and untrusted from Rust Boy's organization standpoint. There is no E2EE, protected job dispatch, device synchronization, safety-of-life channel, or acknowledged delivery in this component.

## Validation matrix

| Scenario | Expected result | Coverage |
|---|---|---|
| Verified TLS + CAP multiline + NICK/USER/REQ/ACK/END/001 | Registered, JOIN/PRIVMSG allowed | Synthetic localhost integration |
| Early PRIVMSG or premature 001 | Error, no IRC chat transmission | Unit + integration |
| Required capability absent or DEL revoked | Fail or immediately block further channel text | Unit + integration |
| Legacy server with no CAP and no mandatory capability | Explicit compatible fallback only | Unit + integration |
| Expired/not-yet-valid CA-signed leaf | Reject before IRC registration | Synthetic localhost TLS |
| Certificate mismatch/untrusted CA | Reject before IRC registration | Existing TLS loopback tests |
| Parser injection, malformed frame, oversized messages | Reject, bounded buffering | Existing portable tests |
| TCP outage with operator retry enabled | Proposed finite backoff, no automatic network effect | Pure-data unit tests |
| Certificate, identity or auth failure | Permanent retry stop | Pure-data unit tests |

## Unresolved acceptance gates

- [x] Capture 10/10 portable host/cross-target CI and 3/3 locked TLS CI on the exact G2b PR revision: [portable run](https://github.com/pskeffington/rusti_rc/actions/runs/40443606057), [TLS run](https://github.com/pskeffington/rusti_rc/actions/runs/40443606042). These confirm software tests, not external IRCd or hardware support.
- [ ] Interoperate with at least one independently built IRC daemon (e.g., Ergo or InspIRCd) using synthetic accounts on a test LAN; compare CAP and numeric transcripts.
- [ ] End-to-end cancellation, timeouts on trickled frames, reconnect budgets and shutdown tests; no optimistic resends.
- [ ] Secure credential-reference API, OS key-store provisioning and rotation; SASL PLAIN only under verified TLS and explicit capability/credential consent.
- [ ] Test actual ARMv6/v7/ARM64 hardware and older supported Linux OS ABI. Cross compilation is not sufficient.
- [ ] Cargo audit/deny, SBOM, signed releases, offline revocation/version floor and independently validated redeployment.
- [ ] Rust Boy UI feature-flag import and independently authenticated organizational control boundary. Do not map IRC names/account tags to Vault roles.

**Release classification:** development preview only; no automatic connect, production account login, server deployment, or live Rust Boy command endpoint.
