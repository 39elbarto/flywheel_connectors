# Dependency Upgrade Log

**Date:** 2026-02-19 | **Project:** flywheel_connectors | **Language:** Rust (workspace)

## Summary
- **Updated:** 22 | **Skipped:** 8 (pre-release only) | **Failed:** 0 | **Already latest:** 6

## Toolchain

### Rust Nightly: floating -> nightly-2026-02-19 (pinned)
- `rust-toolchain.toml` pinned to `nightly-2026-02-19` (rustc 1.95.0-nightly)
- Previously used floating `nightly` channel

## Workspace Dependency Updates

### tokio: 1.43 -> 1.49
- **Breaking:** None
- **Tests:** Passed

### toml: 0.8 -> 1.0
- **Breaking:** `Deserializer::new` returns `Result`; `FromStr for Value` parses values not documents
- **Migration:** No code changes needed (existing usage patterns compatible)
- **Tests:** Passed

### coset: 0.3 -> 0.4
- **Breaking:** Minor API changes
- **Tests:** Passed

### uuid: 1.11 -> 1.21
- **Breaking:** None (minor)
- **Tests:** Passed

### bytes: 1.9 -> 1.11
- **Breaking:** None (minor)
- **Tests:** Passed

### bitflags: 2.6 -> 2.11
- **Breaking:** None (minor)
- **Tests:** Passed

### regex: 1.11 -> 1.12
- **Breaking:** None (minor)
- **Tests:** Passed

### proptest: 1.6 -> 1.10
- **Breaking:** None (minor)
- **Tests:** Passed

### wasmtime: 29.0 -> 41.0
- **Breaking:** `WasiView::ctx()` returns `WasiCtxView<'_>` instead of `&mut WasiCtx`; `WasiView::table()` removed (now part of `WasiCtxView`); `wasmtime_wasi::add_to_linker_async` moved to `wasmtime_wasi::p2::add_to_linker_async`
- **Migration:** Updated `fcp-sandbox/src/wasi.rs` WasiView impl and linker setup
- **Tests:** Passed

### reqwest: 0.12 -> 0.13
- **Breaking:** `rustls-tls` feature renamed to `rustls`; `.form()` requires `form` feature; `.query()` requires `query` feature
- **Migration:** Updated feature flags in workspace Cargo.toml, fcp-cli, fcp-oauth, and connectors/telegram
- **Tests:** Passed

### tokio-tungstenite: 0.26 -> 0.28
- **Breaking:** Message payload uses `Bytes`/`Utf8Bytes` types
- **Migration:** No code changes needed (usage patterns compatible)
- **Tests:** Passed

### criterion: 0.5 -> 0.8
- **Breaking:** `criterion::black_box` deprecated; use `std::hint::black_box()`
- **Migration:** Updated 6 benchmark files to use `std::hint::black_box`
- **Tests:** Passed

### jsonschema: 0.29 -> 0.42
- **Breaking:** `ValidationError::instance_path` changed from field to method
- **Migration:** Updated `fcp-sdk/src/lib.rs` and `fcp-conformance/tests/fzpf_schema_validation.rs`
- **Tests:** Passed

### sigstore-trust-root: 0.4.0 -> 0.6
- **Breaking:** Minor API changes
- **Tests:** Passed

## Crate-Specific Updates

### fcp-telemetry: opentelemetry 0.27 -> 0.31
- **Breaking:** `Resource::new()` private; use `Resource::builder_empty().with_attributes()`; `SdkTracerProvider` replaces `TracerProvider`; `shutdown_tracer_provider()` removed from global; `opentelemetry-otlp` feature `tonic` renamed to `grpc-tonic`
- **Migration:** Rewrote `export.rs` OTLP initialization and resource creation
- **Also updated:** metrics-exporter-prometheus 0.16 -> 0.18

### fcp-host: axum 0.7 -> 0.8, tokio 1.44 -> 1.49
- **Breaking:** Minor route API changes
- **Migration:** No code changes needed
- **Tests:** Passed

### fcp-bootstrap: windows 0.61 -> 0.62
- **Breaking:** None significant
- **Tests:** Passed

### fcp-mesh: constant_time_eq 0.3 -> 0.4
- **Breaking:** None significant
- **Tests:** Passed

## Skipped (Pre-Release Only)

These crates only have pre-release/RC versions available. Kept at current stable:

| Crate | Current | Latest Pre-Release | Reason |
|-------|---------|-------------------|--------|
| ed25519-dalek | 2.1 | 3.0.0-pre.6 | Pre-release; also needed for rand_core 0.6 compat |
| x25519-dalek | 2.0 | 3.0.0-pre.6 | Pre-release; also needed for rand_core 0.6 compat |
| hmac | 0.12.1 | 0.13.0-rc.5 | Release candidate |
| hkdf | 0.12 | 0.13.0-rc.5 | Release candidate |
| sha2 | 0.10 | 0.11.0-rc.5 | Release candidate |
| chacha20poly1305 | 0.10 | 0.11.0-rc.3 | Release candidate |
| hpke | 0.12 | 0.14.0-pre.1 | Pre-release |
| rand (workspace) | 0.8 | 0.9+ | Kept for rand_core 0.6 compat with crypto crates |

**Note:** The RustCrypto ecosystem (ed25519-dalek, x25519-dalek, chacha20poly1305, etc.) uses `rand_core = "0.6"`. Upgrading workspace `rand` beyond 0.8 would break trait compatibility with these crates. Non-crypto crates (fcp-streaming, fcp-ratelimit, fcp-telemetry, fcp-core tests) already use their own `rand = "0.9"`.

## Already at Latest

| Crate | Version |
|-------|---------|
| ciborium | 0.2.2 |
| semver | 1.0.27 |
| blake3 | 1.8.3 |
| raptorq | 2.0.0 |
| sigstore | 0.13.0 |
| tough | 0.21.0 |

## Pre-Existing Issues Fixed During Upgrade

These bugs were discovered during compilation and fixed opportunistically:

1. **connectors/discord/src/gateway.rs** - Extra closing parentheses in `return Err(e.into()))` (4 instances)
2. **crates/fcp-conformance/src/vectors/fcpc.rs** - Duplicate `verify()` method with stray `vec![]` code
3. **crates/fcp-core/src/revocation.rs** - Bloom filter `u64 as usize` cast flagged by newer nightly clippy

## Pre-Existing Test Failures (Not From Upgrade)

- `fcp-anthropic::connector::tests::test_get_usage` - Assertion mismatch on mock value
- `fcp-cli::package_metadata_roundtrip_and_sbom` - Integration test failure

## Verification

- `cargo check --workspace --all-targets` - Clean (zero errors)
- `cargo fmt --check` - Clean
- `cargo test --workspace` - All passing except 2 pre-existing failures
