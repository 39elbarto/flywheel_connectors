# V4 Throughput Benchmark: Lattice Delegation vs Ed25519 and ML-DSA-65

**Beads:** `flywheel_connectors-kyopb.1.3.1.1.5` ([J.5.3.1.1.e]),
`flywheel_connectors-kyopb.1.3.1.1.12` ([J.5.3.1.1.g]),
`flywheel_connectors-kyopb.1.3.1.1.13` ([J.5.3.1.1.h]),
`flywheel_connectors-kyopb.1.3.1.1.14` ([J.5.3.1.1.i]), and
`flywheel_connectors-kyopb.1.3.1.1.15` ([J.5.3.1.1.j]).
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
| V4 lattice verifier hot path, `.15` warm materialization | unchanged from `.13` | unchanged from `.13` | 412.29 us | host debug pipeline 8.398 ms allow / 8.280 ms forged denial |
| V4 lattice real route, `.13` optimized | 68.724 ms | 143.84 ms delegate / 69.130 ms sample_pre | 64.649 ms | 337.18 ms |
| V4 lattice real route, `.12` optimized | 90.730 ms | 182.59 ms delegate / 91.276 ms sample_pre | 96.026 ms | 460.30 ms |
| V4 lattice real route, `.5` baseline | 480.29 ms | 1.6327 s delegate / 536.96 ms sample_pre | 498.33 ms | 2.1870 s |

Read this as a correctness closeout, not a production performance closeout. The
new route is real and no longer hides behind `NotImplemented`. The `.12`
sparse-support materialization pass cuts setup/delegation by about 5x-9x, and
the `.13` buffered selected-row verifier pass cuts another 28%-34% from the V4
lattice timings. The `.14` dispatcher pass shows that the host policy pipeline
is not adding meaningful non-check overhead; the remaining hot-dispatch cost is
the V4 lattice verifier inside `capability_verify`. The `.15` pass moves the
release warmed V4 verifier path under 1ms and puts both warmed debug allow and
forged-denial paths under the 10ms dispatcher target. It does this by caching
only public selected `A_bar` material, scheduling row products with Rayon, and
using a V4-specific public-tail coefficient decoder inside the row product.
Cold materialization is still visible in debug evidence and should stay visible
in operator logs; it is not hidden or counted as pipeline overhead.

The `.5` closeout filed follow-up beads for the three measured bottlenecks:

- `flywheel_connectors-kyopb.1.3.1.1.12`: optimize `trap_gen` and `delegate` setup latency. The first closeout pass now streams only sparse `R` support columns while materializing V4 public tail coefficients.
- `flywheel_connectors-kyopb.1.3.1.1.13`: optimize `sample_pre` and verifier latency. The first closeout pass now buffers selected-row XOF reads and verifies V4 route preimages from nonzero `A_bar` support columns instead of scanning every `A_bar` coefficient.
- `flywheel_connectors-kyopb.1.3.1.1.14`: optimize host policy dispatcher pipeline latency. The closeout reclassified the old e2e `policy_dispatcher_ms` sum as duplicate measurement, exposes `capability_verify` per-check timing, and leaves the residual hot-path work in the lattice verifier itself.
- `flywheel_connectors-kyopb.1.3.1.1.15`: optimize the remaining V4 verifier crypto hot path by separating fast header validation from tail-coefficient decoding, specializing V4 public-tail decoding, parallelizing V4 row products, and reusing bounded public selected-`A_bar` material across repeated verifies.

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

## 2026-05-08 `.15` Verifier Hot Path Update

The `.15` pass keeps the full V4 lattice equation and all request-binding
checks intact. It does not cache verification decisions, receipts, preimages,
operation hashes, principals, zones, periods, certificates, trust sets, or
request bindings. The only reusable verifier material is public selected
`A_bar` coefficients derived from the public seed and the nonzero `A_bar`
columns in the preimage. The cache key includes route id, route revision,
parameter hash, public seed, selected-column hash, and selected-column count;
the public tail block is still decoded and multiplied during verification so
malformed tail material remains rejected.

The before benchmark command was:

```sh
CARGO_TARGET_DIR=/tmp/fcp-pq-verify15-before \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa lattice_verify_real_route -- --sample-size 10
```

The after benchmark command was:

```sh
CARGO_TARGET_DIR=/tmp/fcp-pq-verify15-cache-bench-final \
  cargo bench -p fcp-crypto-pq --bench lattice_vs_ed25519_vs_mldsa lattice_verify_real_route -- --sample-size 10
```

| Benchmark | `.14`/pre-`.15` mean | `.15` after interval | `.15` after mean | Change |
| --- | ---: | ---: | ---: | ---: |
| `verify/lattice_verify_real_route` | 65.268 ms | 410.96 us - 414.48 us | 412.29 us | about 158x faster on the warmed verifier path |

Before the selected-`A_bar` material cache, the best release verifier precursor
in this pass was still around 10.813 ms with Rayon row products and chunked XOF
reads. That precursor is useful for understanding cold/cache-miss cost, but the
hot repeated-verifier path is the warmed materialized path measured above.

The no-mock host e2e command was:

```sh
CARGO_TARGET_DIR=/tmp/fcp-pq-verify15-host-final2 \
  cargo test -p fcp-host --test lattice_policy_dispatcher_e2e -- --nocapture
```

The `.15` host artifact records both the standalone comparison verifier and the
production pipeline timing. In this debug run, the first standalone
`V4_REFERENCE` allow comparison includes public materialization and measured
450.457 ms; the subsequent production pipeline check reuses the bounded public
material cache and measured 8.398 ms. The forged-token path still maps to
`LATTICE_VERIFICATION_EQUATION_FAILED`, and request-binding replay still
short-circuits before crypto-heavy verification.

| Scenario | Standalone verifier | Pipeline total | Pipeline `capability_verify` | Error mapping |
| --- | ---: | ---: | ---: | --- |
| `allow_v4_reference` | 450.457 ms | 8.401 ms | 8.398 ms | allow |
| `deny_forged_v4_reference` | 435.410 ms | 8.282 ms | 8.280 ms | `LATTICE_VERIFICATION_EQUATION_FAILED` |
| `deny_trust_set_replay_v4_reference` | 0.021 ms | 0.022 ms | 0.022 ms | `LATTICE_REQUEST_BINDING_MISMATCH` |

The e2e JSONL redaction scan over the emitted records found no raw target
paths, principals, zones, operations, preimage bytes, trapdoor material, bearer
strings, or token material. The unit proof compares the parallel/cached V4
product against a serial product, rejects a different operation hash after the
cache is warm, rejects malformed tail coefficients after fast header
validation and specialized V4 tail decoding, and verifies cache-key
invalidation for public seed, route id, route revision, parameter profile, and
selected-column changes.

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

The `.15` evidence keeps the `.14` distinction that `policy_dispatcher_ms` was a duplicate
measurement rather than the production dispatcher latency. The production path
is `pipeline_total_ms`; for the current warmed debug run it was 8.401 ms, with
8.398 ms inside `capability_verify` and only 0.003 ms outside check records.
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
| `verify` | target <=10ms for hot dispatch | 412.29us warmed Criterion; 8.398ms warmed debug e2e allow; 8.280ms warmed debug e2e forged denial; cold debug materialization remains visible at about 450ms | `.15` hot path complete; keep cold/cache-miss evidence visible |
| policy dispatcher | target <=10ms total hot path | 8.401ms warmed debug e2e pipeline total; 0.003ms non-check overhead | `.14` diagnosis complete; `.15` verifier follow-up complete for warmed hot path |

## Reproducibility

Run the full assurance gauntlet when preparing reviewer or closeout evidence:

```sh
scripts/e2e/lattice_delegation_assurance_gauntlet.sh
```

Operators can set `RCH_BIN=/path/to/rch` when validating a patched RCH build
without overwriting the installed `rch` binary. The gauntlet still records the
stable `rch exec` command shape and only captures the selected binary's
`--version` output, not the private filesystem path.

That script is the highest-level command bundle for the KYOPB lattice proof
chain. It runs the Lean ID checks, Rust/Lean correspondence fixtures,
`fcp-crypto-pq` representation and V4 unit coverage, the no-mock
`fcp-host` dispatcher e2e, Criterion lattice benchmarks, formatting,
check/clippy, `git diff --check`, UBS, artifact hashing, and redaction scans.
Before emitting a passing summary, it also validates the generated JSONL
contracts for required provenance fields, theorem and assumption IDs, host
dispatcher scenarios, and stable `LATTICE_*` error mappings. The Lean build is
mandatory for reusable gauntlet evidence: a missing `lake` binary fails
preflight instead of producing a passing artifact with a skip record. The
gauntlet self-contract also fails closed unless every record is a passing record,
the `tool_versions` record contains populated Cargo, Rust, RCH, Lean, jq, git,
and UBS versions, and every component artifact hash record names its stable
artifact path with a
`sha256:<64 lowercase hex>` digest. Every top-level gauntlet record must also
carry its hashed `CARGO_TARGET_DIR` provenance in the same
`sha256:<64 lowercase hex>` shape, so a free-form target-dir label cannot pass
as reusable reviewer evidence. Its internal Git probes use the current checkout
as an explicit `safe.directory`, so evidence runs from external worker volumes
still fail on real dirty-tree or diff-check findings instead of Git ownership
guardrails. The component JSONL contracts also validate the hash-bearing fields
they consume: raw digest fields must be exactly 64 lowercase hex characters,
existing tagged fixture IDs must be `hash:<64 lowercase hex>`,
and optional material digests may only be null or exact lowercase hex. The
numeric fields consumed by the component contracts are integer quantities:
representation and route/material versions are positive integers, timings and
duration fields are non-negative integer milliseconds or seconds as named, norm
squares are non-negative integers, and timing sample counts are positive
integers. Fractional JSON numbers fail the contract instead of being rounded by
review tooling. The nested representation, route, public-matrix, SamplePre, and
host-dispatcher objects are also shape-checked: matrix dimensions, encoded
lengths, allocation estimates, public material summaries, and crypto primitive
timing objects must carry the typed integer fields emitted by their Rust
fixtures, not only an arbitrary JSON object. Public matrix material kinds are
limited to the serialized Rust enum labels `FixtureSeedOnly` and
`RouteTailCoefficients`, and representation profile records must prove the
redaction and policy-bridge compatibility booleans that their fixture emits.
Trapdoor relation, trapdoor norm-quality, and secret-storage bucket fields are
likewise limited to their serialized Rust enum labels; route, public-matrix,
and SamplePre records must also use the stable result, cleanup, reconstruction,
norm-bucket, and verifier outcome labels emitted by the evidence fixtures.
The representation profile contract requires exactly one `SMALL_TEST` record and
one `V4_REFERENCE` record. The host dispatcher contract applies the same strict
shape to every consumed `*_hash` field, including the optional receipt hash when
present, and requires exactly one record for each of the 14 dispatcher scenarios
emitted by `lattice_policy_dispatcher_e2e`: both allow profiles, forged
preimage denials, zone/period/operation/principal mismatch denials, malformed
preimage denial, missing-certificate denial, incomplete/too-deep chain denials,
and SMALL_TEST plus V4 trust-set replay denials.
Host dispatcher records also use stable evidence labels: request binding is one
of `match`, `not_reached`, `field_mismatch`, or `mismatch`; norm buckets are one
of `within_quarter_bound`, `within_bound`, `exceeds_bound`, or
`norm_unavailable`; cleanup is exactly `artifact_flushed`; skip reason is null;
and the pipeline-check list must include a `capability_verify` record with a
non-negative elapsed time. The primitive timing object must carry the concrete
non-negative timing fields emitted by the host e2e, and benchmark summaries must
name the standalone verifier, pipeline total, capability-verify, non-check, and
duplicate-measurement fields rather than an arbitrary string.
It also fails closed unless every allow row reports `verifier_result="ok"` with
no `error_mapping`, and every deny row reports a stable `LATTICE_*` mapping that
exactly matches `verifier_result` with no receipt id.
The route artifact contract likewise requires exactly one record for the two
successful primitive profiles and each explicit denial scenario. The public
matrix artifact contract requires exactly one record for the two successful
primitive profiles plus each public-tail, binding, seed, route, and unsupported
custom-profile denial. The SamplePre/Verify artifact contract requires the
success, forged-equation, wrong-norm, wrong-zone, wrong-period, malformed
preimage, and outside-period scenarios for both profiles. The crypto and policy
formal correspondence contracts require exactly one record for each supported
profile, exact theorem and assumption ID vectors, and all correspondence check
booleans set to true. The gauntlet summary record
must also enumerate the exact expected profile, 14-scenario dispatcher, theorem,
assumption, and benchmark sets plus stable error mapping and cleanup fields
before the script can print reusable evidence.
The top-level gauntlet self-contract also requires a single consistent run id,
git revision, target-dir class/hash, build profile, and worker host class across
all JSONL records so reviewer evidence cannot be stitched together from
different runs. Run ids and worker host classes must be non-empty
redaction-safe label tokens using only ASCII letters, digits, `.`, `_`, and
`-`; `..` is rejected by the self-contract. Run ids containing secret, provider
payload, reviewer-contact, trapdoor, preimage, or credential marker names are
rejected before the script creates artifact directories or JSONL files, and
stderr reports only a `sha256:<64 lowercase hex>` hash of the rejected value.
The top-level build profile must be `dev-test-bench`. Because command records are contracted
to `target/fcp-crypto-pq/<run_id>.<step>.log`, `OUT_DIR` must remain
`target/fcp-crypto-pq`; an override fails before the script creates evidence
directories. The staged remote evidence root is likewise pinned to
`target/fcp-crypto-pq/rch-lattice-evidence/<run_id>` so private absolute staging
paths cannot influence evidence materialization before redaction checks. The
top-level and component artifact revisions must be actual 7- to 40-character
hexadecimal Git commit ids; `unknown` is a preflight or contract failure, not
reusable evidence. Top-level target-dir classes are limited to `ephemeral_tmp`,
`repo_relative_target`, or `custom_hashed`; exact `/tmp`, `/private/tmp`, and
`target` roots are classified the same way as their children. The host
dispatcher component artifact is limited to `tmp_absolute`, `absolute`,
`relative`, or `unset`, so a novel label cannot bypass target-dir provenance
review.
The narrower `scripts/e2e/lattice_delegation_formal_correspondence.sh` proof
script also validates its own JSONL envelope before printing the artifact path:
it requires exact Lean theorem/assumption ID arrays, stable command log hashes,
an explicit redaction-scan pass record, the expected `SMALL_TEST` and
`V4_REFERENCE` summary profiles, one consistent run id and git revision, and a
separate final artifact SHA printed only after the final self-contract validates
the finished JSONL envelope. Its
Git revision probe also applies the checkout root as a per-command
`safe.directory`, matching the top-level gauntlet on shared or external volumes.
The standalone formal script also treats Lean/Lake proof as mandatory: a missing
`lake` binary fails `prerequisite_lake`, and the self-contract requires passing
`lean_lake_workspace_probe` and `lean_lake_build` command records instead of
accepting a skip record.
The summary record must name the actual formal-correspondence JSONL artifact
being emitted, and both run-id-derived and operator-supplied artifact paths are
limited to a single relative `target/fcp-crypto-pq/*.jsonl` file before the
script creates or truncates evidence. The standalone formal script applies the
same redaction-sensitive run-id marker preflight as the top-level gauntlet.
It also pins `OUT_DIR` to `target/fcp-crypto-pq` before creating log or evidence
directories, matching the command-record contract that every local log is a
target-relative evidence artifact rather than a private absolute path.
Operator-supplied artifact filenames are also rejected if they contain the same
secret, provider-payload, reviewer-contact, trapdoor, preimage, or credential
marker names; the failure message reports only a SHA-256 hash of the rejected
path.
Its command records must name their exact log artifact as
`target/fcp-crypto-pq/<run_id>.<step>.log`, and the standalone self-contract
rejects passing command records whose `log_artifact` does not match the
record's own run id and step. The older `log_artifact_class` marker remains a
coarse review label, but it is not enough by itself to make a formal
correspondence command record reusable evidence.
The standalone formal script now mirrors the top-level gauntlet's post-summary
redaction posture: the first `redaction_scan` covers the command and proof
records before `summary`, then `final_redaction_scan` scans the summary-bearing
artifact before success output prints the reusable JSONL path and SHA. Passing
redaction-scan records identify the case-insensitive policy version instead of
echoing the raw forbidden marker list, so the scan records themselves do not
make the finished artifact fail its own redaction checks. That policy covers
private paths, raw operation/principal/zone labels, secret material,
auth/header markers, provider-body markers, reviewer-contact markers, and the
host-dispatcher fixture literals `send_message`, `agent-alpha`, and
`agent-beta`.
Its command records carry the same execution-proof fields as the top-level
gauntlet: non-`rch` lanes must report `fallback_decision:"not_needed"`,
`worker_execution_class:"not_applicable"`, and `rch_summary:null`; `rch`-backed
lanes must report `worker_execution_class:"remote"` with an observed
accepted `[RCH] remote` summary before the formal correspondence self-contract
can pass. Summaries such as `[RCH] remote required; refusing local fallback`
are classified as refused local fallback, not remote execution proof.
For each top-level gauntlet `rch exec` lane, the JSONL records include the
observed `[RCH]` summary, worker execution class, and fallback decision. Local
fallback and remote-worker failure summaries are still recorded in the failure
artifact when they occur, but the gauntlet sets `RCH_REQUIRE_REMOTE=1` and
`RCH_FORCE_REMOTE=1` for every Cargo-backed lane so local fallback is refused
before expensive Cargo work can start. They are not reusable gauntlet proof: a
command that was requested through `rch exec` must finish with
`worker_execution_class:"remote"` before the script can append a passing command
record. The gauntlet self-contract
requires every command-run record, local or `rch`-backed, to carry a stable log
artifact, non-empty command line, `sha256:<64 lowercase hex>` log hash,
duration, retry count, fallback decision, worker execution class, cache
decision, cleanup result, and the RCH summary field. The duration must be
non-negative, and retry count must be a
non-negative integer. Non-`rch` command records must report
`fallback_decision:"not_needed"`,
`worker_execution_class:"not_applicable"`, and `rch_summary:null`. Passing
`rch exec` records must carry an observed accepted `[RCH] remote` summary;
unobserved, unclassified, local-fallback, refused-local-fallback, or
remote-failure RCH summaries are not reusable evidence. The same self-contract
also requires each command record's `log_artifact` to equal
`target/fcp-crypto-pq/<run_id>.<step>.log`, matching the path emitted by the
gauntlet itself instead of accepting an arbitrary non-empty label. It also
requires every named command lane in the
gauntlet to be represented by a passing command-run record, including Lean, Rust
test, Criterion, format, check, clippy, diff-check, and UBS lanes, so a partial
artifact cannot pass by carrying only a summary and materialized hashes. The
Lean lane first runs `lake env lean --version` as a workspace/load preflight
before `lake build`, so filesystem-level Lake configuration failures such as
unsupported file locking are attributed to a precise probe step rather than
being collapsed into the proof build itself. Both Lean command records are
required for reusable evidence. The
Cargo test command lanes must also carry a positive parsed `passed_tests` count
before the gauntlet can pass, so a truncated or non-test log cannot satisfy the
reviewer evidence contract.
The critical proof steps must appear exactly once in the top-level JSONL:
`tool_versions`, `validate_lean_ids`, every named command lane, every
materialized artifact hash lane, `jsonl_contract_validation`, `redaction_scan`,
`summary`, and `final_redaction_scan`. Duplicate critical records fail the
self-contract instead of being treated as harmless extra evidence. Unexpected
top-level gauntlet steps also fail the self-contract, so a passing artifact
cannot carry unreviewed supplemental records before the summary.
The normal `redaction_scan` must be ordered after every materialized artifact
hash lane and after `jsonl_contract_validation`, and it must appear before the
summary. This prevents a reusable artifact from moving the scan ahead of the
artifact records it claims to cover.
Benchmark coverage is also checked from the command records, not just the final
summary: the Criterion command record must report observed `trap_gen`,
`delegate`, `sample_pre`, `verify`, and `full_crypto_route` groups from its log,
and the host dispatcher e2e command record must report the
`host_dispatcher_pipeline` coverage source before the self-contract can pass.
The redaction scan treats raw zone, operation, and principal labels plus
authorization headers, bearer strings, access, refresh, or ID tokens, common
credential/key fields (`client_secret`, `api_key`, `private_key`,
`secret_key`, `password`, cookies, and credential key/value markers), exact or
child `/tmp` and `/private/tmp` paths, `/private/var/`, `/var/folders/`,
`/Volumes/`, macOS `/Users/`, Linux worker `/home/` and `/data/projects/`,
Windows `C:\Users\`, provider body payload markers, reviewer private-contact
markers, and the host dispatcher fixture literals `send_message`,
`agent-alpha`, and `agent-beta` as failures.
Private path markers, raw-label markers, secret material markers, provider-body
markers, and reviewer-contact markers are checked case-insensitively, so
normalized lowercase macOS or Windows user paths and differently cased payload
labels cannot pass as reusable JSONL evidence.
Because the summary record is appended after the normal redaction scan, the
script scans the finished JSONL again and requires a `final_redaction_scan`
pass record before printing the artifact path and final hash. The self-contract
requires the normal redaction scan to cover all eight expected JSONL artifacts
by exact path, not just by count, and requires the final redaction scan to cover
the summary-bearing gauntlet artifact by exact path. The summary artifact path
must be a redaction-safe relative single-file `target/fcp-crypto-pq/*.jsonl`
path, never an absolute local/private path, arbitrary repo-relative path, nested
subdirectory, or a `..` traversal; an unsafe `ARTIFACT` override is rejected
before the script creates the artifact directory or JSONL file. The final scan
must appear immediately after the summary record and as the final JSONL record,
with a
`post_summary_artifact_hash` over the summary-bearing artifact state. This keeps
omitted component scans, duplicate scan-count padding, absolute-path echoing,
and append-only records after the final scan from passing the reusable-evidence
self-contract.
The script prints both the JSONL path and final JSONL SHA-256 on stdout. The
summary record's embedded `pre_summary_artifact_hash` intentionally covers only
the records before the summary, avoiding a misleading self-referential hash.

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
