# rusti_rc threat model and isolation controls

Status: security architecture proposal; not assessed for deployment. Baseline: 2026-10-26.

## Assets
- Rust Boy task/vault state, organization trust graph, assigned roles and protected peer keys.
- IRC operator text, server/channels, endpoint addresses, nickname and optional credentials.
- Availability during degraded / isolated-network conditions; accurate delivery-state reporting.
- Verified release binaries, local configuration, rollback metadata and trusted update keys.

## Trust boundaries
1. **External IRC peers / server are untrusted content providers.** Prefix, nick, account tags, channel modes and server-time are not cryptographic Rust Boy device identity.
2. **TLS only authenticates the configured client-server transport** when hostname/IP and certificate validation succeed. An IRC server can read normal channel messages. No E2EE claim.
3. **Rust Boy retains task and organizational authorization**, `pipboy-core` message journal and PACE semantics; an IRC message may only be shown as read-only untrusted chat until a separate reviewed authorization path exists.
4. **Storage and display remain local.** No automatic IP scanning, public listeners, persistent contact list synchronization, or exposure through existing Rust Boy dashboard endpoints.
5. **Release distributor and removable media are untrusted** until signature/trust root, target/ABI, expiry and version floor checks succeed.

## Threat -> control -> validation

| Threat | Mandatory control | Status and test |
|---|---|---|
| Malicious server sends unbounded IRCv3 tag line | Separate 8191-byte inbound tag-prefix and 512-byte base frame bounds; network reader additionally requires an incremental bounded buffer and timeout | Parser bound implemented; network framing pending |
| CRLF/CTCP and terminal control injection | Reject control and bidi characters from preview, render only escaped text; no terminal escapes in logs | Prototype parser/encoder tests authored; UI pending |
| Fake nick "OVERSEER" issues commands | No server user field maps to org trust root; no import into job/command API | Adapter data type is `UnverifiedRemoteLabel`; integration tests pending |
| TLS interception / stale CA / clock | Explicit TLS required; RFC 9525 matching, authenticated trust roots, fail closed and reliable time | Policy type implemented; TLS stack/hardware pending |
| Plaintext downgrade or SASL credential leak | No insecure fallback, PLAIN only inside validated TLS, no secret in args/logs; support OS key store when implemented | No network or SASL implementation |
| Flood, reconnect storm, disk exhaustion | Length limits, bounded channels, peer/channel quotas, jittered backoff, no unbounded persistence | Static length limits; async and storage pending |
| Unsolicited LAN reachability | Server disabled by default and loopback-only until explicit reviewed exposure gate | Server policy type implemented; no listener |
| Unsupported OS compromised | No direct credentialed installation or trusted commands on EOL host; isolate via approved gateway | Deployment policy drafted |
| Malicious USB redeployment or mirrored artifact | Offline signature verification over manifest + payload hashes, monotonic release policy, pinned public trust roots | Requirements documented; not implemented |
| Signed but vulnerable rollback | Store security floor independently of active slot; reject versions below floor; dual-slot only for approved releases | Requirements documented; not implemented |
| Cloned storage image replays identities | Per-device key provisioning, isolated backup state, monotonically protected counter or authenticated server ledger where necessary | Not implemented; organizational controls belong to Rust Boy |
| Confused deputy via role-only UI | Operator role is presentation, not an authorization grant; require separate authenticated action approval | Policy only |

## Invariants
- Importing any `rusti_*` crate opens no socket or listener. The current scaffold satisfies this structurally, without hardware verification.
- No IRC data may initiate tasks, device enrollment, Vault Command actions, safety-of-life emergency acknowledgement, or rebroadcast onto another adapter without separate explicit authorization and origin tracking.
- A successful IRC `PRIVMSG` write (once implemented) will mean **submitted to a transport**, not `STORED`, `READ`, or delivered to the intended human.
- Default config has `enabled=false`; enabling chat or server requires an explicit reviewed action; no silent server discovery or reconnect on import.
- Never use a shared organizational private key for a chat nick, and never assume public IRC channels provide confidentiality.
- There is no custom crypto protocol; use a reviewed TLS library and authenticated peer identities where applicable. Consider separate E2EE only after independent design review.
- No release claims of HIPAA, emergency dispatch, safety-of-life, E2EE or corporate authorization until independent assessment.

## Security-specific acceptance gates
A. Fuzz line parser, enforce memory and CPU quotas, test CTCP/control/codepoint vectors.
B. Confirm zero network calls on crate import, startup, local GET/UI render and route selection.
C. MITM/expired/name-mismatch/revoked server certificate and old-system trust-store tests.
D. Build sandbox IRCd with user impersonation, flooding, malformed metadata, duplicate/reordered messages and disconnects.
E. Validate signed offline deployments and compromised-media simulation, including rollback refusal.
F. Separate penetration review of any bridge that might map IRC traffic into protected Rust Boy workflows.

Primary standards: [IRCv3 message tags](https://ircv3.net/specs/extensions/message-tags.html), [RFC 9325 TLS](https://www.rfc-editor.org/rfc/rfc9325), [RFC 9525 service identity](https://www.rfc-editor.org/rfc/rfc9525), [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final), [TUF update security](https://theupdateframework.io/docs/security/).
