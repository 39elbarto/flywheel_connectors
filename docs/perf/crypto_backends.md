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
benchmark evidence.

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
| scalar | proven 2026-05-15 in `/data/projects/flywheel_connectors_angoc143_proof_20260515T020400Z` | 2026-06-03 remote Criterion label benchmark median 14.487 us |
| x86_sse3 | proven 2026-05-15 in `/data/projects/flywheel_connectors_angoc143_proof_20260515T020400Z` | 2026-06-03 remote Criterion label benchmark median 14.638 us, 0.99x scalar |
| x86_avx2 | proven 2026-05-15 in `/data/projects/flywheel_connectors_angoc143_proof_20260515T020400Z` | 2026-06-03 remote Criterion label benchmark median 14.762 us, 0.98x scalar; not a 4x proof |

`rch` was attempted first, but refused local fallback because no workers passed
health thresholds. The fresh remote proof checkout above passed:

- `cargo fmt -p fcp-crypto-hw -- --check`
- `cargo test -p fcp-crypto-hw --test chacha20_parity -- --nocapture`
- `cargo test -p fcp-crypto-hw --test hw_feature_set_detection -- --nocapture`
- `cargo clippy -p fcp-crypto-hw --all-targets -- -D warnings`

## Throughput Evidence

2026-06-03 remote `rch` run on worker `vmi1149989`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- \
  env CARGO_TARGET_DIR=/tmp/fcp-angoc143-sagestork-bench CARGO_INCREMENTAL=0 \
  cargo bench -p fcp-crypto-hw --bench chacha20_dispatch -- \
  --noplot --sample-size 20 --warm-up-time 1 --measurement-time 3
```

Benchmark payload: 16 KiB plaintext, fixed 32-byte key, fixed 12-byte nonce,
and AAD `fcp-crypto-hw-bench`.

| Benchmark | Criterion estimate |
|-----------|--------------------|
| `chacha20_poly1305_seal_scalar` | 14.487 us, CI [14.363 us, 14.592 us] |
| `chacha20_poly1305_seal_x86_sse3` | 14.638 us, CI [14.477 us, 14.788 us] |
| `chacha20_poly1305_seal_x86_avx2` | 14.762 us, CI [14.410 us, 15.187 us] |

Lower latency is better. On this evidence, the AVX2-labeled path is about
0.98x scalar throughput, not at least 4x scalar throughput.

Important limitation: the current implementation routes `seal_scalar`,
`seal_sse3`, and `seal_avx2` through the same `seal_with_rustcrypto` helper.
This benchmark exercises the FCP backend-label dispatch surface, but it does not
prove distinct scalar, SSE3, or AVX2 kernel performance.

## Closeout Rule

Do not mark `flywheel_connectors-angoc.14.3` complete until correctness proof is
green and this document cites redaction-safe throughput evidence showing AVX2 at
least 4x scalar on a declared x86_64 server class. Until then, this document is
a proof scaffold rather than a performance claim.
