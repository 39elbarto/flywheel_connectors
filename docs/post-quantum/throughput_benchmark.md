# V4 Throughput Benchmark: Lattice Delegation vs Ed25519 and ML-DSA-65

**Beads:** `flywheel_connectors-kyopb.1.3.1.1.5` ([J.5.3.1.1.e]),
`flywheel_connectors-kyopb.1.3.1.1.12` ([J.5.3.1.1.g]), and
`flywheel_connectors-kyopb.1.3.1.1.13` ([J.5.3.1.1.h]), and
`flywheel_connectors-kyopb.1.3.1.1.14` ([J.5.3.1.1.i]).
**Bench file:** `crates/fcp-crypto-pq/benches/lattice_vs_ed25519_vs_mldsa.rs`.
**E2E harness:** `crates/fcp-host/tests/lattice_policy_dispatcher_e2e.rs`.
**Companion docs:** `docs/post-quantum/lattice_trapdoor_delegation.md` and
`docs/post-quantum/v3_v4_compatibility_ledger.md`.

This document records the 2026-05-08 real-route benchmark closeout for the V4
post-quantum lattice delegation path. The previous 2026-05-02 report measured
stub bridge costs and projected the real lattice implementation. Those stub
numbers are now obsolete: the benchmark exercises real `TrapGen -> Delegate ->
SamplePre -> Verify` code for `V4_REFERENCE`, and the host e2e harness routes a
real lattice sub-token through policy enforcement.

## Summary

| Family | Keygen / setup | Sign / issue | Verify | End-to-end |
| --- | ---: | ---: | ---: | ---: |
| Ed25519 | 36.523 us | 38.531 us | 82.795 us | 104.99 us |
| ML-DSA-65 | 771.99 us | 1.2600 ms | 130.22 us | 1.5139 ms |
| V4 lattice real route, `.13` optimized | 68.724 ms | 143.84 ms delegate / 69.130 ms sample_pre | 64.649 ms | 337.18 ms |
| V4 lattice real route, `.12` optimized | 90.730 ms | 182.59 ms delegate / 91.276 ms sample_pre | 96.026 ms | 460.30 ms |
| V4 lattice real route, `.5` baseline | 480.29 ms | 1.6327 s delegate / 536.96 ms sample_pre | 498.33 ms | 2.1870 s |

Read this as a correctness closeout, not a production performance closeout. The
new route is real and no longer hides behind `NotImplemented`. The `.12`
sparse-support materialization pass cuts setup/delegation by about 5x-9x, and
the `.13` buffered selected-row verifier pass cuts another 28%-34% from the V4
lattice timings. The `.14` dispatcher pass shows that the host policy pipeline
is not adding meaningful non-check overhead; the remaining hot-dispatch cost is
the V4 lattice verifier inside `capability_verify`. The route is still above
hot-path latency targets and still needs deeper verifier optimization.

The `.5` closeout filed follow-up beads for the three measured bottlenecks:

- `flywheel_connectors-kyopb.1.3.1.1.12`: optimize `trap_gen` and `delegate` setup latency. The first closeout pass now streams only sparse `R` support columns while materializing V4 public tail coefficients.
- `flywheel_connectors-kyopb.1.3.1.1.13`: optimize `sample_pre` and verifier latency. The first closeout pass now buffers selected-row XOF reads and verifies V4 route preimages from nonzero `A_bar` support columns instead of scanning every `A_bar` coefficient.
- `flywheel_connectors-kyopb.1.3.1.1.14`: optimize host policy dispatcher pipeline latency. The closeout reclassified the old e2e `policy_dispatcher_ms` sum as duplicate measurement, exposes `capability_verify` per-check timing, and leaves the residual hot-path work in the lattice verifier itself.
- `flywheel_connectors-kyopb.1.3.1.1.15`: follow-up for the remaining V4 verifier crypto hot path now that `.14` proved host pipeline overhead is not the bottleneck.

## 2026-05-08 `.12` Optimization Update

The `.12` pass removes avoidable dense-row work from V4 public-matrix tail
materialization. The previous route generated and reduced every coefficient in
each public `A_bar` row before multiplying by the sparse `R` supports. The
optimized route indexes the selected support columns once, streams the same
row-domain SHAKE output in order, retains only the selected coefficients, and
computes the tail products from those selected coefficients. It does not change
the domain separation, public seed, request/zone/period binding, public material
format, or verifier-computable `ZonePeriodPublicKey` material.

The after benchmark command was:

```sh
CARGO_TARGET_DIR=/tmp/fcp-pq-opt12-bench \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa lattice -- --noplot
```

| Benchmark | `.5` before mean | `.12` after interval | `.12` after mean | Change |
| --- | ---: | ---: | ---: | ---: |
| `keygen/lattice_trapdoor_master_setup` | 480.29 ms | 90.177 ms - 91.687 ms | 90.730 ms | about 5.3x faster |
| `sign_or_issue/lattice_delegate_one_hop` | 1.6327 s | 181.33 ms - 185.02 ms | 182.59 ms | about 8.9x faster |
| `sign_or_issue/lattice_sample_pre_real_route` | 536.96 ms | 90.660 ms - 92.192 ms | 91.276 ms | about 5.9x faster |
| `verify/lattice_verify_real_route` | 498.33 ms | 92.877 ms - 98.068 ms | 96.026 ms | about 5.2x faster |
| `end_to_end/lattice_full_crypto_route` | 2.1870 s | 453.27 ms - 469.05 ms | 460.30 ms | about 4.8x faster |

The unit proof added for this optimization compares selected V4 `A_bar`
coefficients and sparse tail products against the previous full-row expansion
for representative rows, and the existing V4 public-matrix route test continues
to reconstruct, digest, and reject malformed material. The redaction-safe route
JSONL evidence now includes `V4_REFERENCE` records with command line, git
revision, primitive route id/revision, representation version, parameter
profile, hashed fixture/zone/period identifiers, matrix dimensions, allocation
summary, separate `trap_gen`/`delegate`/relation-check timings, cleanup, result,
and skip reason fields.

## 2026-05-08 `.13` Optimization Update

The `.13` pass keeps the `.12` selected-column semantics but removes a lower
level bottleneck: selected V4 `A_bar` rows now read SHAKE output in fixed-size
coefficient chunks instead of calling the XOF reader once per skipped public
coefficient. The verifier also indexes nonzero `A_bar` coefficients from the
route preimage and feeds those columns to the selected-row stream, while the
tail half and norm bound remain unchanged. The test proof compares the sparse
verifier product against full-row products for representative V4 rows and still
checks the full lattice equation against the operation RHS.

The after benchmark command was:

```sh
CARGO_TARGET_DIR=/tmp/fcp-pq-opt13-bench \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa lattice -- --noplot
```

| Benchmark | `.12` before mean | `.13` after interval | `.13` after mean | Change |
| --- | ---: | ---: | ---: | ---: |
| `keygen/lattice_trapdoor_master_setup` | 90.730 ms | 68.494 ms - 68.975 ms | 68.724 ms | about 1.3x faster |
| `sign_or_issue/lattice_delegate_one_hop` | 182.59 ms | 139.06 ms - 153.66 ms | 143.84 ms | about 1.3x faster |
| `sign_or_issue/lattice_sample_pre_real_route` | 91.276 ms | 68.974 ms - 69.251 ms | 69.130 ms | about 1.3x faster |
| `verify/lattice_verify_real_route` | 96.026 ms | 64.373 ms - 64.795 ms | 64.649 ms | about 1.5x faster |
| `end_to_end/lattice_full_crypto_route` | 460.30 ms | 335.61 ms - 338.52 ms | 337.18 ms | about 1.4x faster |

This pass does not change the public matrix material version, primitive route
revision, operation-hash RHS expansion, norm cap, period check, parameter
agreement, or malformed/forged preimage rejection behavior.

## 2026-05-08 `.14` Dispatcher Evidence Update

The `.14` pass does not change the lattice arithmetic. It fixes the host e2e
evidence so operators can distinguish the production `EnforcementPipeline` hot
path from the harness's standalone verifier comparison. The previous host e2e
summary added standalone `policy_verify_ms` and `dispatcher_ms` together as
`policy_dispatcher_ms`; that double-counted lattice verification because
`dispatcher_ms` already runs `CapabilityVerifyCheck`, which calls
`LatticeDelegationVerifierImpl::verify_sub_token`.

The after command was:

```sh
CARGO_TARGET_DIR=/tmp/fcp-pq-dispatch14-check \
  cargo test -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture
```

The updated JSONL artifact still records the standalone verifier timing for
comparison, but it now also records the production pipeline total, the
`capability_verify` check timing, non-check pipeline overhead, per-check timing
records, build profile, host class, a hashed `CARGO_TARGET_DIR` fingerprint,
and a stable relative artifact path. The raw target directory path is not
written to the evidence artifact.

| V4 host e2e field | Before `.14` baseline | After `.14` evidence | Meaning |
| --- | ---: | ---: | --- |
| `standalone_policy_verify_ms` / old `policy_verify_ms` | 2569.290 ms | 2624.742 ms | Harness-only comparison verifier call |
| `pipeline_total_ms` / old `dispatcher_ms` | 2565.295 ms | 2660.044 ms | Production `EnforcementPipeline` latency |
| `pipeline_capability_verify_ms` | not recorded | 2660.041 ms | Time spent in `CapabilityVerifyCheck` |
| `pipeline_non_check_overhead_ms` | not recorded | 0.003 ms | Pipeline overhead outside checks |
| old `policy_dispatcher_ms` / duplicate sum | 5134.585 ms | 5284.786 ms | Duplicate measurement retained only as a diagnostic |

The optimized evidence also adds V4 denial coverage through the production
pipeline:

| Scenario | Pipeline total | Error mapping |
| --- | ---: | --- |
| `allow_v4_reference` | 2660.044 ms | allow |
| `deny_forged_v4_reference` | 2641.901 ms | `LATTICE_VERIFICATION_EQUATION_FAILED` |
| `deny_trust_set_replay_v4_reference` | 0.027 ms | `LATTICE_REQUEST_BINDING_MISMATCH` |

This proves the host dispatcher is not the current bottleneck: the V4 allow and
forged-denial paths are dominated by the verifier crypto check, while replay
denial fails at request-binding speed. The remaining `>10ms` hot-dispatch gap
therefore belongs in a verifier-crypto follow-up rather than another host
dispatcher bead: `flywheel_connectors-kyopb.1.3.1.1.15`.

## Methodology

The benchmark command was run through `rch` on worker `vmi1153651`:

```sh
rch exec -- cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa
```

The harness uses Criterion with `sample_size(10)`, `warm_up_time(1s)`, and
`measurement_time(10s)` for the benchmark groups so the seconds-scale lattice
operations complete in an operator-friendly time while still producing intervals.
The remote run completed with exit code 0 on 2026-05-08.

The host/policy e2e harness was run separately and wrote redaction-safe JSONL to:

```text
target/fcp-host/lattice-policy-dispatcher-evidence.jsonl
```

That e2e artifact records command line, git revision, build profile, hashed
`CARGO_TARGET_DIR` fingerprint, host class, parameter profile, fixture hash,
zone/period/certificate/trust-set/request hashes, matrix dimensions, primitive
timings, per-check pipeline timings, verifier result, dispatcher decision,
error mapping, cleanup result, artifact path, and skip reason fields. It
intentionally stores hashes and buckets rather than raw principals, zones,
operation names, preimages, trapdoors, raw target paths, or credentials.

## Criterion Results

### Keygen / Setup

| Benchmark | Mean interval |
| --- | ---: |
| `keygen/ed25519` | 33.470 us - 39.665 us, mean 36.523 us |
| `keygen/ml_dsa_65` | 679.32 us - 898.16 us, mean 771.99 us |
| `keygen/lattice_trapdoor_master_setup` | 467.75 ms - 491.34 ms, mean 480.29 ms |

The V4 master setup path is roughly 13,000x slower than Ed25519 keygen on this
run. That is acceptable for an offline setup operation only if it is amortized
and not on a request path. It still violates the closeout threshold that files a
follow-up when `trap_gen` exceeds 1s in e2e and is close enough to that ceiling
that setup/delegation profiling is mandatory.

### Sign / Issue

| Benchmark | Mean interval |
| --- | ---: |
| `sign_or_issue/ed25519_sign` | 36.096 us - 40.861 us, mean 38.531 us |
| `sign_or_issue/ml_dsa_65_sign` | 1.1910 ms - 1.3692 ms, mean 1.2600 ms |
| `sign_or_issue/lattice_delegate_one_hop` | 1.3067 s - 1.9624 s, mean 1.6327 s |
| `sign_or_issue/lattice_operation_hash` | 347.88 ns - 397.43 ns, mean 371.27 ns |
| `sign_or_issue/lattice_sample_pre_real_route` | 488.34 ms - 593.05 ms, mean 536.96 ms |

`operation_hash` is already negligible. `delegate` and `sample_pre` are the real
issue: a one-hop delegate takes seconds, and each per-operation `sample_pre`
takes about half a second. This rules out hot per-request issuance until the
lattice path is optimized or moved behind a long-lived sub-token issuance model.

### Verify

| Benchmark | Mean interval |
| --- | ---: |
| `verify/ed25519_verify` | 73.552 us - 90.897 us, mean 82.795 us |
| `verify/ml_dsa_65_verify` | 122.77 us - 134.66 us, mean 130.22 us |
| `verify/lattice_verify_real_route` | 481.79 ms - 514.93 ms, mean 498.33 ms |

The measured verifier is roughly 6,000x slower than Ed25519 verify and roughly
3,800x slower than ML-DSA-65 verify in this run. That is far above the intended
`100 us - 1 ms` verifier band from the design target and far above the hot-path
threshold of 10ms.

### End-to-End

| Benchmark | Mean interval |
| --- | ---: |
| `end_to_end/ed25519_sign_then_verify` | 102.85 us - 106.24 us, mean 104.99 us |
| `end_to_end/ml_dsa_65_sign_then_verify` | 1.3925 ms - 1.6755 ms, mean 1.5139 ms |
| `end_to_end/lattice_full_crypto_route` | 2.1249 s - 2.2625 s, mean 2.1870 s |

The full crypto route is real and passes, but it is not production-fast. It is
about 20,800x slower than Ed25519 sign-then-verify and about 1,400x slower than
ML-DSA-65 sign-then-verify on this worker.

## Host Policy Dispatcher E2E

The no-mock host e2e harness exercises the real policy dispatcher branch rather
than relying on legacy string capability claims. It covers allow paths for
`SMALL_TEST` and `V4_REFERENCE`, plus denials for forged preimage, mismatched
zone, mismatched period, mismatched operation, mismatched principal, malformed
preimage, missing certificate, incomplete delegation chain, chain too deep, and
trust-set/request-binding replay mismatch.

The original `.5` `V4_REFERENCE` record measured:

| Primitive | Time |
| --- | ---: |
| `trap_gen_ms` | 3497.744 ms |
| `delegate_ms` | 7001.602 ms |
| `sample_pre_ms` | 3520.432 ms |
| `policy_verify_ms` | 3512.016 ms |
| `dispatcher_ms` | 3528.587 ms |
| `policy_dispatcher_ms` | 7040.603 ms |

The `.14` evidence shows that `policy_dispatcher_ms` was a duplicate
measurement rather than the production dispatcher latency. The production path
is `pipeline_total_ms`; for the current debug run it was 2660.044 ms, with
2660.041 ms inside `capability_verify` and only 0.003 ms outside check records.
The evidence still proves the user-facing enforcement behavior: once a lattice
token is present, the dispatcher requires a configured
`LatticeDelegationVerifierImpl`, denies forged lattice material even if legacy
string claims include wildcard capability, rejects request-binding replay, and
maps policy failures to stable `LATTICE_*` reason codes.

## Decision Thresholds

The closeout does not relax security or remove functionality to hit a number.
Instead it keeps the real route intact, records measured behavior, and opens
optimization work where the system is not yet user-optimal.

| Area | Threshold | 2026-05-08 result | Follow-up |
| --- | ---: | ---: | --- |
| `trap_gen` / setup | file follow-up if setup exceeds 1s in e2e | 3.498s e2e, 480ms isolated | `.12` |
| `delegate` | file follow-up if one-hop delegate blocks issuance UX | 7.002s e2e, 1.633s isolated | `.12` |
| `sample_pre` | target <=10ms for hot issuance | 3.520s e2e, 537ms isolated | `.13` |
| `verify` | target <=10ms for hot dispatch | 3.512s e2e, 498ms isolated | `.13` |
| policy dispatcher | target <=10ms total hot path | 2.660s debug e2e pipeline total; 0.003ms non-check overhead | `.14` diagnosis complete; `.15` tracks verifier follow-up |

## Reproducibility

Run the benchmark:

```sh
rch exec -- cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa
```

Run the host e2e harness with detailed logging:

```sh
rch exec -- cargo test -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture
```

Run the policy property/integration lane:

```sh
rch exec -- cargo test -p fcp-policy --test lattice_delegation_proptest -- --nocapture
rch exec -- cargo test -p fcp-policy lattice_delegation -- --nocapture
```

Before closing performance-sensitive changes, also run:

```sh
rch exec -- cargo check -p fcp-policy -p fcp-host -p fcp-crypto-pq --tests --benches
rch exec -- cargo clippy -p fcp-policy -p fcp-host -p fcp-crypto-pq --tests --benches -- -D warnings
rch exec -- cargo fmt --check
```

## Historical Note

The 2026-05-02 report listed `Lattice stub` bridge-cost floors and projected
real implementation numbers. Those rows were useful while `sample_pre` and
`verify` returned `NotImplemented`; they are no longer valid performance data.
Use the 2026-05-08 tables above as the baseline for regression tracking and for
all future optimization beads.

## References

1. Micciancio, D. and Peikert, C. *Trapdoors for Lattices: Simpler, Tighter,
   Faster, Smaller.* TCC 2012.
2. Cash, D., Hofheinz, D., Kiltz, E. and Peikert, C. *Bonsai Trees, or How to
   Delegate a Lattice Basis.* Eurocrypt 2010.
3. Gentry, C., Peikert, C. and Vaikuntanathan, V. *Trapdoors for Hard Lattices
   and New Cryptographic Constructions.* STOC 2008.
4. NIST FIPS 204, ML-DSA / CRYSTALS-Dilithium.
5. RFC 8032, Ed25519.
