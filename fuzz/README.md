# Optional protocol fuzzer (nightly-only; NOT a release dependency)

This directory is an **independent workspace**, so neither the Rust 1.70 portable-core tests nor ordinary Cargo builds pull in `libfuzzer-sys`.

Follow the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html) instructions on a supported Unix development host with a reviewed nightly toolchain and C++ build dependencies:

```sh
cargo +nightly install cargo-fuzz
cd fuzz
cargo +nightly fuzz run irc_frames -- -max_total_time=60
```

The `libfuzzer-sys` dependency is only for offline testing. Review its actual resolved version, license and advisory status before use. Do **not** run the fuzz target in production or on legacy field devices.

Deterministic regression tests remain in `crates/rusti-proto/tests/`. Every discovered crash must be minimized, scrubbed of sensitive contents, and added as a synthetic fixed regression test before closing a protocol gate.

Status: harness committed, **not executed or independently verified**.
