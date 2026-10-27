# rusti_rc architecture and Rust Boy integration gates

Status: proposed design, not implemented. Baseline: 2026-10-26.

## Purpose
A standalone Rust-native IRC client and optional small LAN IRC server, imported into Rust Boy as an **alternative communications adapter**, not as the system of record for authenticated orders, protected vault messages, emergency acknowledgments or RB-to-RB store-and-forward. Keep offline and network availability explicit.

## Intended workspace
- `crates/rusti-proto`: strict IRC line/message parser, capabilities, command encoding and limits
- `crates/rusti-client`: Tokio client lifecycle, reconnect and bounded send/receive channels
- `crates/rusti-server`: optional explicitly enabled LAN-only IRC service, disabled by default
- `crates/rusti-adapter`: Rust Boy bridge, state/events/command API; no UI dependency
- `crates/rusti-testkit`: synthetic network test scenarios and wire fixtures
- `examples/standalone-cli`: minimal isolated smoketest
This is a suggested directory structure; no crates have been created.

## Generic adapter contract
Configuration: server address, port, TLS policy, nickname, channel allowlist, optional SASL identity reference; never log credentials.
Commands: connect/disconnect, join/part, channel message, direct message (IRC PRIVMSG), list channel peers, status.
Events: connection state, channel state, inbound messages, notices, structured errors, upstream server capabilities.
Message metadata: transport=`irc`, scope, sender nickname (unverified identity), server/channel, local receive time, optional upstream server-time, opaque transport message ID if provided.
Never equate nick identity with Rust Boy organizational identity. Never interpret IRC lines as Vault Command tasks without a separate authenticated and authorized workflow.

## Protocol gates
G0 research and licensing: lock upstream commits and licenses, dependency audit and normative feature checklist.
G1 wire core: TCP and TLS clients, RFC 1459/2812 baseline, IRCv3 CAP and message-tags, strict line limits; deterministic parser fixtures and fuzzing.
G2 secure connect: enforce certificate validation, certificate pinning only via controlled config if justified, SASL PLAIN only inside verified TLS, EXTERNAL where supported; refuse downgrade from required TLS.
G3 operator chat: reconnect with jitter, bounded queues, channel list and scoped direct messages; clearly signal disconnected and unsent states, never report "delivered" without suitable semantics.
G4 LAN server: opt-in, non-public bind by default, access control, channel and client quotas, flood protection, controlled shutdown, auditable config; verify hostname/IP identity and safe discovery behavior.
G5 Rust Boy import: feature-gated adapter crate, display inside existing Radio/Comms UI, no external app, 1-screen compact layout, accessible controls, role-specific presentation without role-based auth assumptions.
G6 interoperability and hardware: connect to independent test IRCd, IPv4/IPv6, Wi-Fi LAN, no-internet conditions, Pi ARM64 cross-build, Mac desktop tests, sleep/resume, packet loss and reordering simulations.

## Availability model
- Wi-Fi / IP + external IRC server => network IRC possible.
- Wi-Fi / local IP + embedded LAN server => local IRC possible if peers can reach same service.
- No routable IP / no server => IRC unavailable; Rust Boy must use a different PACE adapter (e.g. authenticated device-local queue / radio transport); no fabricated mesh mode.
- IRC bridges are separate opt-in gateways requiring provenance, rate limits, loop suppression and explicit trust boundaries.

## Security stop conditions
No plaintext fallback when TLS required; no credentials in logs; no default internet-facing listener; no message/command execution from unverified nicknames; no auto-DCC; no shared org private keys in IRC configs; no optimistic acknowledgments; no unbounded buffers. Verify licenses and CVEs before adoption.

## Definition of done for first useful prototype
Two independent Rust Boy instances on the same test LAN connect to a sandbox IRC server, join an allowlisted channel, exchange text, disconnect/reconnect, visibly show delivery uncertainty, and do not expose organizational vault or device keys. Tests are deterministic, integration tests pass, and project documentation includes threat model plus protocol compatibility evidence.
