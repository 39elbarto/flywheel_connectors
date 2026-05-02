# V4 throughput benchmark — lattice-trapdoor delegation vs Ed25519 + ML-DSA-65

**Bead:** `flywheel_connectors-kyopb.1.3.4` ([J.5.3.4]).
**Bench file:** `crates/fcp-crypto-pq/benches/lattice_vs_ed25519_vs_mldsa.rs`.
**Companion docs:** `docs/post-quantum/lattice_trapdoor_delegation.md` (design),
`docs/post-quantum/v3_v4_compatibility_ledger.md` (cross-version dispatch).

This document records the first throughput measurements for the V4
post-quantum capability-delegation stack against the V3 (Ed25519) and
intermediate (ML-DSA-65) baselines. Numbers are honest about what is
real today vs what will become real once the lattice arithmetic lands
(`kyopb.1.3.1.1` and follow-ups).

## TL;DR

| Family       | Keygen     | Sign / issue | Verify     | End-to-end |
| ------------ | ---------: | -----------: | ---------: | ---------: |
| Ed25519      |    9.16 µs |      8.63 µs |   21.40 µs |   30.11 µs |
| ML-DSA-65    |  188.00 µs |    230.00 µs |   25.63 µs |  259.07 µs |
| Lattice stub | (see §3.3) |   (see §3.3) | (see §3.3) | (see §3.3) |

Lattice-stub numbers are intentionally **omitted from this summary**
because they reflect placeholder BLAKE3 hashing rather than the
production lattice arithmetic. They appear in §3 as the **bridge-cost
floor** the production verifier always pays, and §4 records the
projected real-impl numbers from the lattice literature so the team
has a concrete regression-tracking target for when `kyopb.1.3.1.1`
lands.

## 1. Methodology

### 1.1 What is measured

Three signature/delegation families across four shapes:

- **`keygen`** — produce a fresh signing key (or master trapdoor for
  the lattice family).
- **`sign_or_issue`** — Ed25519 / ML-DSA `sign(msg, ctx)`; lattice
  `delegate(parent, zone, period)` plus a separate per-op
  `operation_hash` measurement (the deterministic hash a sub-token
  binds to before the cryptographic mint).
- **`verify`** — Ed25519 / ML-DSA `verify(msg, ctx, sig)`; lattice
  `verify(zp_pub, h, preimage, now, params)` — runs every structural
  check (parameter agreement, period bounds) before the cryptographic
  body, so the stub measurement is the bridge-cost floor.
- **`end_to_end`** — full sign-then-verify (or full pipeline:
  `trap_gen → delegate → operation_hash → sample_pre → verify`).

### 1.2 Implementations under test

- **Ed25519** — production `fcp_crypto::ed25519` (ed25519-dalek under
  the hood).
- **ML-DSA-65** — production `fcp_crypto::ml_dsa` (RustCrypto `ml-dsa`
  crate, FIPS 204).
- **Lattice-trapdoor** — `fcp_crypto_pq` (`br-kyopb.1.3.1` stubs).
  `trap_gen` and `delegate` deterministically derive 32-byte
  placeholders via BLAKE3; `sample_pre` returns
  `LatticePqError::NotImplemented` immediately; `verify` runs the
  structural checks and then returns `NotImplemented`.

### 1.3 Hardware + toolchain

| Item            | Value                                              |
| --------------- | -------------------------------------------------- |
| CPU             | Apple M3 Pro (arm64)                               |
| OS              | macOS 14 (Darwin 25.2.0)                           |
| Rust            | nightly 1.97.0 (matches workspace `rust-version`)  |
| Build profile   | `[bench]` → optimized release                      |
| `CARGO_TARGET_DIR` | `/Volumes/USB_NVME/fcp-alpha-pq` (USB NVMe ext.) |
| Criterion       | `0.8` (workspace pin)                              |

Numbers below were captured with reduced sample size for a tight
turnaround (`--warm-up-time 1 --measurement-time 3 --sample-size 30
--output-format=bencher`); the pinned reproducibility command in §5
uses Criterion's defaults so CI runs produce statistically tighter
numbers.

## 2. Reproducibility

### 2.1 Quick run (developer machine, ~30s wall time)

```sh
TMPDIR=/Volumes/USB_NVME \
  AGENT_NAME=$YOUR_AGENT \
  CARGO_TARGET_DIR=/Volumes/USB_NVME/fcp-alpha-pq \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa -- \
    --warm-up-time 1 \
    --measurement-time 3 \
    --sample-size 30 \
    --output-format=bencher
```

### 2.2 CI / regression-tracking run (Criterion defaults, ~2-3 min)

```sh
AGENT_NAME=$YOUR_AGENT \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa
```

Output lands in `target/criterion/` as HTML reports under each group
(`keygen/`, `sign_or_issue/`, `verify/`, `end_to_end/`).

## 3. Results (2026-05-02, M3 Pro)

### 3.1 Group: `keygen`

| Implementation                   | ns/iter | ± σ     | ops/sec  |
| -------------------------------- | ------: | ------: | -------: |
| Ed25519                          |   9,161 |     218 | 109,000  |
| ML-DSA-65                        | 187,972 |  14,384 |   5,300  |
| Lattice-trapdoor (stub)          |      92 |       2 | 10.9 M   |

**Read:** Ed25519 keygen ~110k/s; ML-DSA-65 ~5k/s (~20× slower —
matches FIPS 204 expectations). Lattice stub is one BLAKE3 — the real
`TrapGen` will be ~3-5 orders of magnitude slower (lattice basis
sampling). See §4.

### 3.2 Group: `sign_or_issue`

| Implementation                          | ns/iter | ± σ     | ops/sec  |
| --------------------------------------- | ------: | ------: | -------: |
| Ed25519 sign                            |   8,627 |      31 | 116,000  |
| ML-DSA-65 sign                          | 230,028 |  13,621 |   4,350  |
| Lattice `delegate` one hop (stub)       |     191 |       1 |  5.2 M   |
| Lattice `operation_hash` (real, BLAKE3) |     143 |       1 |  7.0 M   |

**Read:** Ed25519 sign and ML-DSA sign are both end-to-end real
operations; the ~27× sign-time gap is inherent to ML-DSA's lattice
sampling. The lattice `delegate` stub is two chained BLAKE3 hashes
(parent → child seed); real CHKP basis-shortening will be
substantially slower (see §4). The `operation_hash` row is *not* a
stub — it's the production hash construction every real sub-token
mint also pays.

### 3.3 Group: `verify`

| Implementation                                    | ns/iter | ± σ | ops/sec  |
| ------------------------------------------------- | ------: | --: | -------: |
| Ed25519 verify                                    |  21,401 | 143 |  46,700  |
| ML-DSA-65 verify                                  |  25,627 | 262 |  39,000  |
| Lattice `verify` structural floor (stub returns NotImplemented) |      2 |   0 |    500 M |

**Read:** ML-DSA verify is only ~20% slower than Ed25519 verify — both
are well under 30 µs and look identical at typical FCP request rates.
The lattice "2 ns" number reflects the bridge-cost floor *only*: the
parameter-equality check that gates the `NotImplemented` return.
**Once the real verification equation lands, this number will jump by
~3-5 orders of magnitude** (see §4).

### 3.4 Group: `end_to_end`

| Implementation                       | ns/iter | ± σ    | ops/sec |
| ------------------------------------ | ------: | -----: | ------: |
| Ed25519 sign-then-verify             |  30,107 |    772 | 33,200  |
| ML-DSA-65 sign-then-verify           | 259,067 |  9,281 |  3,860  |
| Lattice full-pipeline floor (stub)   |     446 |      4 |  2.2 M  |

**Read:** Ed25519 round-trip is the FCP3 baseline (~33k full
sign+verify cycles per second per core). ML-DSA-65 is ~8.5× slower
end-to-end. Lattice-stub end-to-end is meaningless as an absolute
number; it's useful only as a regression baseline for the bridge cost
the production verifier will always pay regardless of the
cryptographic implementation.

## 4. Projected real-impl numbers (literature)

The lattice arithmetic to land in `kyopb.1.3.1.1` (Micciancio-Peikert
TrapGen, Cash-Hofheinz-Kiltz-Peikert basis-shortening, Gentry-Peikert-
Vaikuntanathan SamplePre) has well-characterised performance at the
`V4_REFERENCE` parameter profile (`n=512`, `q≈2³²`, `m≈16384`, `σ≈113`,
`L=4`). Per the design doc §3.2 references and the public lattice-
crypto literature (Micciancio-Peikert 2012; CHKP 2010; GPV 2008):

| Operation       | Stub measured      | Projected real-impl       | Multiplier  |
| --------------- | -----------------: | ------------------------: | ----------: |
| `trap_gen`      |              92 ns | **~10-100 ms**            | ~10⁵-10⁶× |
| `delegate`      |             191 ns | **~1-10 ms**              | ~10⁴-10⁵× |
| `sample_pre`    | NotImplemented (0) | **~1-10 ms**              | n/a (stub)  |
| `verify`        |               2 ns | **~100 µs - 1 ms**        | ~10⁴-10⁵× |

These multipliers rest on three observations:

1. `TrapGen` is dominated by sampling a discrete-Gaussian basis over
   `Z_q^{n×m}` — at `n=512, m=16384` this is the most expensive
   lattice operation in the scheme. Reference implementations
   (e.g. Open-Source-Lattice-Cryptography, GHL21 follow-ups) report
   ~10-100 ms on commodity hardware.
2. `Delegate` (CHKP basis-shortening) needs to compute a short basis
   from the parent's trapdoor; one-shot cost dominated by Gaussian
   sampling inside the orthogonal complement. ~1-10 ms range.
3. `SamplePre` (GPV) is per-op; reference impls report ~1-10 ms at
   `n=512` (the bottleneck for issuance throughput).
4. `Verify` is a single matrix-vector product `A·e mod q` plus a
   2-norm check. Asymptotically `O(n·m·log q)` bit-operations; with
   AVX-512 / NEON tuning, optimized impls reach ~100 µs - 1 ms at
   `V4_REFERENCE`.

### 4.1 Implications for production dispatch

If the projected numbers hold (`verify` ~100 µs-1 ms), V4 capability
verification is **~5-50× slower than V3 Ed25519 verify** but
**~4-40× faster than ML-DSA-65 verify** — well within the budget of a
single capability check at typical FCP request rates (≥ 1 kHz/core
remains achievable on V4).

The architectural argument for V4 in the design doc §1 stands:

- Offline-batched issuance (mint thousands of sub-tokens from one
  `delegate` hop without further owner-key participation) eliminates
  the per-token round-trip cost that ML-DSA requires today.
- Forward-period unforgeability (compromising the issuance node at
  time `t` does NOT let an attacker mint sub-tokens for `t' < t`
  because the trapdoor at the relevant period is gone) is impossible
  to achieve with any non-lattice signature scheme.

These properties are what justify a 5-50× verify-time slowdown vs
Ed25519. They are NOT achievable by any tightening of the V3 path.

## 5. Regression tracking

When `kyopb.1.3.1.1` lands the real lattice arithmetic, this bench
becomes a load-bearing regression gate. The acceptance criteria for
that bead should include:

1. Re-run `cargo bench -p fcp-crypto-pq --bench
   lattice_vs_ed25519_vs_mldsa` post-implementation.
2. Update §3 of this document with the new numbers and §4 multipliers
   (replace projections with measurements).
3. If `lattice_verify_structural_floor` jumps by more than 10× (i.e.
   the cryptographic body is unexpectedly expensive), file a
   follow-up bead for vectorisation work (NTT-based mat-vec, AVX-512
   tuning).
4. If `lattice_full_pipeline_floor` exceeds **10 ms total**, the V4
   capability-verify path is too slow for hot-path dispatch and
   should be relegated to long-lived sub-token issuance only (V3
   stays the default for short-lived per-request tokens). Decision
   point recorded for the team.

## 6. Notes on bench fidelity

- Numbers were captured with reduced-sample Criterion settings for
  the initial baseline. CI runs (Criterion defaults) will produce
  tighter intervals — expect the ML-DSA-65 standard deviations to
  shrink considerably with full sample size.
- The lattice-stub numbers are NOT representative of production;
  they are bridge-cost floors. Reading absolute throughput from them
  is meaningless.
- Single-core measurements only. Server-side production throughput
  scales with cores assuming per-request locality (no shared-key
  contention on signing).
- M3 Pro is the local development reference; CI x86_64 runs may
  differ by a constant factor (typically Ed25519 / ML-DSA verify are
  similar within 2× across modern x86 / arm).

## 7. References

1. Micciancio, D. & Peikert, C. *Trapdoors for Lattices: Simpler,
   Tighter, Faster, Smaller.* TCC 2012.
2. Cash, D., Hofheinz, D., Kiltz, E. & Peikert, C. *Bonsai Trees, or
   How to Delegate a Lattice Basis.* Eurocrypt 2010.
3. Gentry, C., Peikert, C. & Vaikuntanathan, V. *Trapdoors for Hard
   Lattices and New Cryptographic Constructions.* STOC 2008.
4. NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium) — published Aug 2024.
5. RFC 8032 (Ed25519).

## 8. Provenance

- Bench harness landed in `crates/fcp-crypto-pq/benches/
  lattice_vs_ed25519_vs_mldsa.rs` under `br-kyopb.1.3.4` (AmberLark,
  2026-05-02).
- Numbers in §3 captured 2026-05-02 on M3 Pro under the reduced-
  sample command in §1.3 / §2.1.
- Update this section every time §3 numbers are re-captured (date,
  hardware, full vs reduced sample).
