# G1b protocol hardening evidence and known limitations

Baseline: 2026-10-26. **Implementation authored on the MIT/G1b development branch; build, lint and fuzz runtime results require independent CI evidence.**

## Scope implemented in source

| Gate / claim | Implementation | Evidence status |
|---|---|---|
| Standard MIT licensing | Root LICENSE, Cargo workspace and each package's inherited SPDX identifier | Repository source confirmed; upstream code attribution required before copying |
| IRC baseline frame sizes | rusti-proto::parse_frame and encode_privmsg enforce 512-byte base incl. CRLF | Deterministic tests authored; cross-target CI pending |
| IRCv3 inbound tag sizes | Tag-prefix limit 8191 bytes separate from 512-byte base | Boundary tests authored; network interoperability pending |
| IRCv3 tags | Case-sensitive opaque keys, last duplicate wins, standard value unescape | Unit/integration tests authored; decoded tag content must remain untrusted |
| Incremental byte stream | FrameDecoder processes fragmented, repeated, invalid UTF-8 and oversized bytes, bounded to 8703 bytes plus Vec overhead | Deterministic tests authored; operational TLS reader not implemented |
| IRCv3 CAP 302 (limited subset) | Pure-data LS multiline aggregator, REQ, ACK/NAK and required-capability DEL handling | Tests authored; no SASL, NEW activation, full ACK multi-line support or complete protocol FSM |
| Parser fuzz | Isolated cargo-fuzz nightly libFuzzer target + deterministic pseudo-random stream regression | Source committed; execution NOT VERIFIED |
| Rust Boy trust boundary | Adapter only produces UntrustedChat with UnverifiedRemoteLabel | No production Rust Boy import or org command path |
| TLS/SASL, IRC networks, queues, and LAN server | No runtime transport code | NOT IMPLEMENTED |

## Protocol source basis

- [RFC 2812](https://www.rfc-editor.org/rfc/rfc2812), IRC client message framing and command syntax.
- [IRCv3 message tags](https://ircv3.net/specs/extensions/message-tags.html), 8191-byte inbound tag limit including @ and trailing separator, 4094-byte per-sender limits, duplicate last wins, tag escaping and opaque unknown keys.
- [IRCv3 capability negotiation](https://ircv3.net/specs/extensions/capability-negotiation.html), CAP LS 302, multiline LS, values, ACK/NAK, END, NEW/DEL.
- [cargo-fuzz official project](https://github.com/rust-fuzz/cargo-fuzz) and [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html), nightly-only compiler instrumentation and libFuzzer usage.

## Remaining G1b work before "complete"

1. Enforce and test **outbound** IRCv3 tagged-message limit of 4094 tag-data bytes only after negotiated support is available. This scaffold does not send tagged messages.
2. Implement complete CAP ACK multiline behavior, LIST/NEW/DEL state and capability requirements (incl. batching, labeled-response). Never grant SASL automatically.
3. Reconcile RFC-compliant inbound display with sanitization policy: the parser intentionally rejects raw control/bidi code points; decoded IRCv3 tag values can contain CR/LF, and require explicit output sanitization at the UI boundary.
4. Add full command/numeric semantic tests against independent IRCd fixtures and strict routing of responses. The parser currently validates command shapes but not command-specific arity.
5. Execute sanitizers, fuzzing, deterministic regression, clippy and rustfmt in a reviewed environment. Collect exact compiler, target and test logs.
6. Validate against real low-memory ARMv6/v7/ARM64 and x86 Linux hosts before making legacy runtime claims.
7. Implement and independently audit authenticated TLS, SASL opt-in, and credential storage at G2; neither parser correctness nor MIT licensing makes IRC transport secure.

## Commands (offline parser tests)

From repository root:

```sh
cargo +1.70.0 test --workspace --all-targets
cargo +stable test --workspace --all-targets
cargo +stable run -p rusti-standalone-cli
```

Optional host-only fuzzing is documented at [fuzz/README.md](../../fuzz/README.md), and must not run on field devices.

## Security acceptance

No IRC prefix, account tag, nickname, or CAP reply constitutes Rust Boy identity or authorization. A line accepted by the parser is **not** a message delivered to, stored by, or read by any device. Both client and server remain networking-disabled / not implemented.
