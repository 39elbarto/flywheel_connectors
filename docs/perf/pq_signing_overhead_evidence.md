# PQ Signing Overhead Evidence

Date: 2026-05-12

Bead: `flywheel_connectors-angoc.8.2`

README SLO row: `Hybrid verify p99 | <= 2ms | Phase N PQ signing gate`

## Status

Pending real StatPack artifacts.

This repository snapshot does not yet contain `artifacts/perf/pq_signing/*.json`,
and the Phase B.2 `StatPack` helper referenced by
`docs/reality/2026-05-12-reality-check-bridge-plan.md` is still tracked by
`flywheel_connectors-angoc.1.1`. This document therefore records the gate shape
and the required evidence contract, not a pass verdict for the three hardware
classes.

## Required Artifact Shape

Each run must write one JSON StatPack under `artifacts/perf/pq_signing/` for
each machine class:

- `csd`
- `contabo`
- `laptop`

The conformance gate accepts either a class marker in the filename or a JSON
field at `machine_class`, `machine.class`, `machine.machine_class`, or
`host.machine_class`.

The hybrid verify p99 must be available as one of:

- `benchmarks.verify_hybrid.p99_ms`
- `benchmarks.hybrid_verify.p99_ms`
- `statpack.verify_hybrid.p99_ms`
- `verify_hybrid.p99_ms`
- `hybrid_verify.p99_ms`
- `hybrid_verify_p99_ms`
- `p99_ms`
- `hybrid_verify_p99_us` / `p99_us`
- `hybrid_verify_p99_ns` / `p99_ns`

The gate converts microseconds or nanoseconds to milliseconds and fails if the
observed p99 is greater than `2.0ms`.

## Statistical Requirements

The full closeout evidence must include the Phase B.2 fields for each machine
class:

- p50, p99, p999, mean, and standard deviation for `verify_classical`,
  `verify_pq`, and `verify_hybrid`
- Welch t-test versus the latest accepted baseline
- bootstrap 95% confidence interval for p99
- tail amplification ratio
- git SHA, date, machine class, kernel and CPU model, and noise calibration
- exact reproduction command

## Current Gate

`crates/fcp-conformance/tests/pq_perf_budget_held.rs` now defines:

- `test_hybrid_verify_p99_under_2ms_csd`
- `test_hybrid_verify_p99_under_2ms_contabo`
- `test_hybrid_verify_p99_under_2ms_laptop`
- `test_p99_breach_triggers_gate`

If `artifacts/perf/pq_signing/` is absent, the machine-class tests print a skip
message and return successfully so normal source builds are not blocked before
the StatPack-producing pipeline exists. If the directory exists, missing class
artifacts or p99 values fail the test. The synthetic breach test always runs and
asserts that a `3.0ms` p99 fails the `2.0ms` gate.

## Reproduction Command

After `flywheel_connectors-angoc.1.1` and the artifact producer land, run the
class-specific harness on each target host, then verify with:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fcp-conformance --test pq_perf_budget_held -- --nocapture
```

## Verdict

No pass verdict yet. Downgrade-attack rejection can be proven in this slice, but
the hybrid verify p99 budget cannot be honestly marked held until the required
StatPack artifacts exist for `csd`, `contabo`, and `laptop`.
