# BLAKE3 Hardware Dispatch Evidence

Bead: `flywheel_connectors-angoc.14.2`

## Current Status

`fcp-crypto-hw` now exposes an FCP-facing BLAKE3 dispatch surface:

- `Blake3Hasher`
- `Blake3Tier`
- `FCP_FORCE_BLAKE3_TIER` parsing through `Blake3Hasher::from_env`
- function-table wiring through `FunctionTable::blake3`

The implementation delegates low-level SIMD selection to the upstream `blake3`
crate. The FCP layer owns the stable tier labels, operator override parsing, and
byte-equivalence tests. This is intentionally conservative while the workspace
keeps `unsafe_code = deny` for this crate.

Focused x86_64 byte-equivalence proof passed on 2026-05-15 in the remote proof
checkout `/data/projects/flywheel_connectors_angoc142_proof_20260515T015100Z`
at base `11d0dcdf017d0fa3a1cc2c50d46cb6c9b1719bc7` plus the
`flywheel_connectors-angoc.14.2` patch. This is not AVX-512 throughput proof and
does not cover aarch64/NEON hardware.

## Proof Lanes

Required focused checks:

```bash
rch exec -- cargo fmt -p fcp-crypto-hw -- --check
rch exec -- cargo test -p fcp-crypto-hw --test feature_detection_consistency -- --nocapture
rch exec -- cargo test -p fcp-crypto-hw --test hw_feature_set_detection -- --nocapture
rch exec -- cargo clippy -p fcp-crypto-hw --all-targets -- -D warnings
```

## Evidence Matrix

| Machine class | Required tier evidence | Current status |
|---------------|------------------------|----------------|
| x86_64 generic | portable + available x86 tier byte-equivalence | passed focused fmt/test/clippy proof on 2026-05-15 |
| x86_64 AVX-512 server | AVX-512 throughput >= 8 GB/s StatPack | missing live AVX-512 run |
| aarch64 Linux/macOS | NEON byte-equivalence | missing live aarch64 run |

## Closeout Rule

Do not mark `flywheel_connectors-angoc.14.2` complete until this document cites
fresh redaction-safe proof artifacts for the available x86_64 tier, AVX-512
throughput, and aarch64/NEON byte-equivalence. Until then, this file is a proof
scaffold and not a PROVEN performance claim.
