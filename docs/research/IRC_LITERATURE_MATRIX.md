# Rust IRC literature and implementation matrix

Research baseline: 2026-10-26. Scope: upstream implementations and normative protocol specifications. Feature descriptions are upstream claims until source-level or executable validation. Do not interpret this as a verified dependency or security assessment.

| ID | Source | Category | Evidence and relevant design | Rust Boy application | Priority | Validation gate |
|---|---|---|---|---|---|---|
| L01 | https://github.com/aatxe/irc | Rust client library | Async IRC client, IRCv3, client/protocol separation; MPL-2.0 | Client reference; assess adapter boundary | P0 | Compile sample, inspect feature flags, license and audit |
| L02 | https://docs.rs/irc-proto/latest/irc_proto/ | Protocol crate | Tokio codec, typed commands/messages/capabilities | Candidate parser/codec, not wholesale application | P0 | Parser fuzzing, malformed lines, protocol compliance |
| L03 | https://github.com/squidowl/halloy | Rust GUI IRC client | Cross-platform Iced UI; multi-network and IRCv3 features | Compact operator UX reference; avoid copying whole UI | P0 | Inspect source and current license at commit |
| L04 | https://github.com/KaraZajac/rIRCd | Rust IRC server | IRCv3-oriented IRCd implementation | Embedded/local server design reference | P0 | Inspect implementation, license, bind configuration and security |
| L05 | https://github.com/doublegate/RustIRC | Rust client | Upstream reports Tokio/rustls, modular workspace, reconnection, GUI/TUI, IRCv3 | Crate boundaries and test harness | P1 | Independently verify build/test claims and license |
| L06 | https://github.com/faratech/linefeed | Rust GUI client | Upstream reports TLS, SASL, CAP negotiation, reconnection | Failure-state and authentication reference | P1 | Validate TLS defaults and unsafe compatibility options |
| L07 | https://ircv3.net/ | Standards | IRCv3 capabilities and extensions | Normative modern interoperability baseline | P0 | Map mandatory vs optional extensions |
| L08 | https://ircv3.github.io/specs/extensions/labeled-response.html | Standard | Labeled responses rely on message-tags and batch, correlate client requests with responses | Command acknowledgement correlation; not delivery guarantee | P0 | Test tagged responses and batches |
| L09 | https://www.rfc-editor.org/rfc/rfc1459 | Standard | Original IRC protocol | Legacy interoperability | P1 | Ensure parser accepts supported baseline syntax |
| L10 | https://www.rfc-editor.org/rfc/rfc2812 | Standard | IRC client protocol | Commands/numerics protocol baseline | P0 | Golden wire fixtures |

## Interpretation rules

- A normal IRC connection requires network reachability to a server; disconnected direct devices cannot communicate simply because they implement IRC.
- TLS secures the client-server hop, not necessarily the entire route or a bridged channel. Do not represent TLS/SASL as end-to-end encryption.
- IRC delivery, ordering and history semantics vary by server and extensions. Do not promise guaranteed delivery or offline delivery.
- Do not connect an organizational trust root, credential store or vault access to unauthenticated IRC nicknames.
- Defer DCC and automatic file transfer pending a dedicated threat model.
- Inspect dependency licenses before incorporating source code; citations do not grant reuse rights.

## Next evidence collection

For each P0 source: capture upstream commit hash, latest release, actual licensing, active maintainer status, architecture, protocol feature implementation, MSRV, dependency audit, and reproducible test results. Record `verified`, `upstream claimed`, or `not evaluated` individually. Avoid manufacturing benchmark scores.
