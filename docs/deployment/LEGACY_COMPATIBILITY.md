# Legacy system portability and compatibility policy

Baseline: 2026-10-26. Design targets, **not** verified running configurations.

The Rust toolchain minimum is not the same as the host OS minimum. The declared `rusti_rc` library MSRV is **Rust 1.70**; Rust Boy currently uses **Rust 1.90**. Testing MSRV does not establish kernel ABI, glibc, crypto provider, CPU instruction set, radio driver or OS patch-level support.

| Profile | Rust target / host | Intent | Release acceptance |
|---|---|---|---|
| D1 modern x86 Linux | `x86_64-unknown-linux-gnu` | Desktop and servers | Compile, test, TLS and real-host smoke |
| D2 older x86 Linux | `x86_64-unknown-linux-musl` or GNU built against audited old sysroot | Older field workstations | Inspect dynamically linked libraries, DNS behavior, CPU baseline and real-host TLS |
| D3 Raspberry Pi ARMv6 | `arm-unknown-linux-gnueabihf` or `arm-unknown-linux-musleabihf` | Pi 1 / original Pi Zero | Correct ABI/hardfloat, selected crypto provider, SD wear, CPU/RAM, real-host smoke |
| D4 Raspberry Pi ARMv7 | `armv7-unknown-linux-gnueabihf` | Pi 2 / 32-bit Pi 3 OS | Hardware smoke, kernel and glibc audit, bounded memory |
| D5 Raspberry Pi ARM64 | `aarch64-unknown-linux-gnu` or `aarch64-unknown-linux-musl` | Modern Pi/server | Native LAN client tests, separate server gate |
| D6 Intel macOS | `x86_64-apple-darwin` | Existing Intel Macs | Actual deployment OS must meet target minimum; binary/signing tests |
| D7 Apple Silicon | `aarch64-apple-darwin` | Current Mac devices | macOS 11+ per Rust target support, native smoke |
| D8 Windows 10+ | `x86_64-pc-windows-msvc` | Modern Windows host | Test ACL, trusted certificate store, installer and runtime on real Windows |
| D9 EOL Windows 7/8 | No committed modern Rust target | **Not supported as a direct security endpoint** | Isolated supported gateway; do not disable certificate verification |

Authority: [Rust platform support](https://forge.rust-lang.org/platform-support.html), [Windows target requirements](https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html), [rustls crypto provider and platform notes](https://docs.rs/rustls/latest/rustls/).

## Two-build rule

- **Portable core:** dependency-light, edition 2021, Rust 1.70, no bundled UI engine, no runtime network by import, and zero `unsafe` in this scaffold. This allows compilation experiments with lower-end CPUs and older package-manager environments.
- **Modern integration:** Rust Boy uses its current Rust 1.90 workspace and imports a vetted release of `rusti-adapter` through an explicit opt-in feature. It must not force an older MSRV upon the host, or bring unsupported native crypto dependencies into legacy builds.

## Resource and compatibility budgets

Proposed acceptance measurements (not benchmarks): maximum resident memory under sustained 100-message test, binary size and shared-library dependencies, CPU duty cycle at idle and during a sustained burst, cold-start time, file-descriptor count, SD-card write rate, queue overflow behavior. The design objective is bounded memory, zero idle sockets when disabled, and no background discovery. No numerical performance claim is made without a measured hardware baseline.

**Legacy build traps:** `-C target-cpu=native` on release machines; overly new glibc dependency; unexpected C compiler/crypto-provider requirements; loading host OS root CAs that are expired/stale; timekeeping and expiry failures on RTC-less boards; ARMv6 hardfloat/softfloat mismatch; weak entropy during first boot; relying on unsupported Windows versions; silent port 6667 downgrade; low storage / disk full; platform-specific ACL assumptions. Test each deliberately.

## Unsupported host handling

Do not install on unpatched, unsupported OSes with real credentials or sensitive chat. Prefer an isolated, managed, updatable Raspberry Pi/gateway providing a controlled, audited relay to the old system as a display-only endpoint where allowed. A gateway does not make the old OS trustworthy; segregate it and avoid forwarding organizational credentials/commands to it.

## Promotion rules

All of these must pass for each target before `supported` is written in a release note: toolchain + sysroot pinned, CI cross-build, local real-hardware tests, authenticating TLS 1.2/1.3, known-good time and trust roots, dependency license/security check, nonnative CPU baseline, offline redeploy test, explicit rollback drill, operator acknowledgement of residual limits. A CI cross-build alone means **build-only**, not supported.
