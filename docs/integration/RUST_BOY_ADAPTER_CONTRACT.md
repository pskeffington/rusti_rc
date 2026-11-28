# Rust Boy import contract: rusti_rc

Status: interface scaffold only. **No code has been added to pip_boy by this pass.**

## Existing ownership in Rust Boy (2026-10-26)

- `pipboy-core::messenger` and `message_pace` own existing message, queue and route semantics.
- `crates/pipboy/src/dashboard/messenger_routes.rs` owns existing same-origin LINK messenger routes.
- `crates/pipboy/src/peer.rs` owns paired, pinned-SSH peer delivery.
- `PIPBOY_HOME` owns saved local operator state; repo/catalog fixtures must not contain real journals.
- `crates/pipboy-core/src/organization_*` holds draft organizational structure/trust work; role selection does not equal authentication.

See [PACE](https://github.com/pskeffington/pip_boy/blob/main/docs/PACE_MESSAGING.md), [Messenger](https://github.com/pskeffington/pip_boy/blob/main/docs/MESSENGER.md) and [Security](https://github.com/pskeffington/pip_boy/blob/main/SECURITY.md) before modifying the host.

## Import contract

1. Integrate as an optional Cargo dependency behind `irc` feature in the **Rust Boy** workspace after G2 security and standalone interop pass; pin exact version or reviewed commit; do not automatically pull HEAD of this repository into a device release.
2. Import `rusti-adapter` (not standalone CLI or any server) in `pipboy` only. Parsing from `rusti-proto` and display-only `UntrustedChat` is available now for offline fixtures.
3. Keep IRC in **LINK / alternate chat** as an operator-selected transport *category*, not automatically labeled the P/A/C/E route type or assigned to tasks/vault sync. IRC can depend on the same IP/server failure domain as existing SSH; no independence claim.
4. Route any future chat send through a separate explicit `POST` action, with strict Host/Origin, content-type/size checks, current-session operator confirmation, bounded requests, visible disconnected/error state and no background retry.
5. Never map `nick`, `prefix`, IRC account tag, channel mode or TLS server identity into `Organization` / `Appointment` / `Grant`. Future authenticated org messaging needs a distinct independently reviewed end-to-end envelope and authorization service.
6. No IRC message triggers camera, network scan, SDR, medical emergency, Mission/Task/Job assignment, RB-to-RB sync or remote command. Those require their own ownership and permission gates.
7. Render text via DOM `textContent` or equivalent safe text widget; no HTML/terminal escape interpretation; show server, channel, and the label **Unverified IRC identity**.
8. Preserve transport state terms: `DISABLED`, `DISCONNECTED`, `CONNECTING`, `CONNECTED`, `SUBMITTED / UNCONFIRMED`, `ERROR`; never use `STORED` unless a separately authenticated Rust Boy receiver receipt actually exists.
9. Feature disabled by default, no listener; importing the dependency must not change `pipboy dashboard` loopback behavior or app startup; no public port/external player launch.
10. Store future credential **references** only in protected OS-managed key storage; no secrets in `PIPBOY_HOME` chat config, logs, environment inheritance, CLI argv, or examples.

## Feature gate and tests

G0 standalone parser, adapter and lab fixtures; no host modifications — **scaffolded**.
G1 standalone TLS-backed IRC client, IRCv3 CAP/SASL and independent synthetic-account Ergo interoperability — **validated in standalone tests; Rust Boy import not implemented**.
G2 verified-TLS localhost rejection tests and certificate-bound credentials — **partially tested**; independent audits, OS keychain lifecycle and real Linux/ARM smoke **pending**.
G3 standalone G3a/G3b bounded operator drafts and verified-TLS one-at-a-time submission — **authored in rusti_rc only**. Feature-gated `pipboy` import and read-only LINK fixture integration — **pending**.
G4 explicit network send UI, bounded connection state, real interoperable server and desktop/micro screen tests — **pending**.
G5 signed dual-target offline redeploy and security review — **pending**.

The G3b standalone API is `TlsIrcSession::operator_submit_next`; it is synchronous and must run on an explicitly authorized worker, never automatically from rendering, route selection, reconnect, or incoming IRC text. It does not authenticate an organizational sender or produce receiver receipts.

A successful import needs a CI test asserting `--no-default-features` starts Rust Boy with zero additional sockets, routes, listeners, token reads or changes to existing message schemas. **Do not merge the import merely because code compiles.**
