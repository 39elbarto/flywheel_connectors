# Crypto Backend Evidence

Bead: `flywheel_connectors-angoc.14.3`

## ChaCha20-Poly1305

`fcp-crypto-hw` exposes stable backend labels for ChaCha20-Poly1305:

- `scalar`
- `x86_sse3`
- `x86_avx2`

The wrapper deliberately delegates low-level block-function acceleration to the
RustCrypto `chacha20poly1305` crate. The FCP layer owns feature-based backend
selection, operator override parsing via `FCP_CRYPTO_BACKEND`, parity tests, and
future benchmark evidence.

## Required Proof Commands

```bash
rch exec -- cargo fmt -p fcp-crypto-hw -- --check
rch exec -- cargo test -p fcp-crypto-hw --test chacha20_parity -- --nocapture
rch exec -- cargo clippy -p fcp-crypto-hw --all-targets -- -D warnings
```

Optional throughput lane:

```bash
rch exec -- cargo bench -p fcp-crypto-hw --bench chacha20_dispatch
```

## Evidence Matrix

| Backend | Correctness status | Throughput status |
|---------|--------------------|-------------------|
| scalar | proven 2026-05-15 in `/data/projects/flywheel_connectors_angoc143_proof_20260515T020400Z` | missing StatPack |
| x86_sse3 | proven 2026-05-15 in `/data/projects/flywheel_connectors_angoc143_proof_20260515T020400Z` | missing StatPack |
| x86_avx2 | proven 2026-05-15 in `/data/projects/flywheel_connectors_angoc143_proof_20260515T020400Z` | missing 4x-scalar StatPack |

`rch` was attempted first, but refused local fallback because no workers passed
health thresholds. The fresh remote proof checkout above passed:

- `cargo fmt -p fcp-crypto-hw -- --check`
- `cargo test -p fcp-crypto-hw --test chacha20_parity -- --nocapture`
- `cargo test -p fcp-crypto-hw --test hw_feature_set_detection -- --nocapture`
- `cargo clippy -p fcp-crypto-hw --all-targets -- -D warnings`

## Closeout Rule

Do not mark `flywheel_connectors-angoc.14.3` complete until correctness proof is
green and this document cites redaction-safe throughput evidence showing AVX2 at
least 4x scalar on a declared x86_64 server class. Until then, this document is
a proof scaffold rather than a performance claim.
