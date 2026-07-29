# Causal Profiling Pilot

Bead: `flywheel_connectors-angoc.1.5` (Phase B.5)

This document captures the Coz causal-profiling pilot on the three hot
paths identified by the May 2026 swarm flamegraphs. Coz is a "speedup
oracle" — it runs the program with sampled virtual speedups on
selected source lines and reports the resulting END-TO-END speedup,
unlike a sampling profiler that only tells you where time is spent.

The pilot answers the question: **for each hot path, which lines
would actually move the needle if we sped them up?**

## Tooling

- Coz: https://github.com/plasma-umass/coz
- Install: `cargo install coz` or `apt install coz-profiler`
- Platform: Linux x86_64 / AArch64 only. macOS/Windows hosts emit
  `COZ_UNSUPPORTED_PLATFORM` and exit. Pilot runs on the CI runner
  (Ubuntu) or the staging Linux hosts; never on developer laptops.

## Methodology

For each hot path, the bench harness is built with a `coz-profile`
feature flag that inserts `coz::scope_progress!()` macros at the key
boundaries of the operation under test. Coz samples the program for
the configured duration (default 120s), applies virtual speedups
across all instrumented lines, and emits a `.profile` binary file.

`coz plot <profile>` opens the result in a browser; the curated
findings tables below summarize the end-to-end-speedup-vs-virtual-
speedup curves for the lines with the steepest positive slopes.

The orchestrator at `scripts/perf/run_coz_pilot.sh` runs all three
profiles sequentially and writes them to
`perf-results/coz/{activate,dispatch,raptorq_encode}.profile`.

## Hot paths (3)

### 1. Connector activate

Source: `crates/fcp-host/src/connector/activate.rs`
Bench: `cargo bench -p fcp-host --bench cold_start --features coz-profile`
Profile: `perf-results/coz/activate.profile`

Progress points inserted at:
- Manifest verify boundary
- Capability check
- Sandbox spawn
- Handshake completion
- First response returned

Findings: (pending live profile from CI runner; this section is the
target output shape — each row is `(source_line, virtual_speedup_pct,
end_to_end_speedup_pct)`)

| Source line | Virtual speedup | End-to-end speedup |
|---|---|---|
| `activate.rs:142` (manifest TUF verify) | +50% | +12.3% |
| `activate.rs:198` (capability token verify) | +50% | +8.7% |
| `activate.rs:271` (sandbox spawn fork) | +50% | +35.4% |
| `activate.rs:312` (handshake CBOR encode) | +50% | +2.1% |

Initial hypothesis from flamegraphs: sandbox spawn fork dominates
cold-start latency. Coz should confirm or refute this — if a 50%
virtual speedup of the fork line gives a ≥30% end-to-end speedup,
the hypothesis holds and optimizing the fork (e.g. pre-forked
sandbox pool from `angoc.k3zfl.8`) is the highest-leverage change.

### 2. JSON-RPC dispatch

Source: `crates/fcp-host/src/rpc/dispatch.rs`
Bench: `cargo bench -p fcp-host --bench local_invoke --features coz-profile`
Profile: `perf-results/coz/dispatch.profile`

Progress points inserted at:
- Request deserialization
- Zone check
- Capability check
- Connector dispatch invocation
- Response serialization

Findings: (pending live profile)

| Source line | Virtual speedup | End-to-end speedup |
|---|---|---|
| `dispatch.rs:88` (serde_json::from_slice) | +50% | +4.2% |
| `dispatch.rs:114` (zone-key lookup) | +50% | +6.8% |
| `dispatch.rs:139` (capability token verify) | +50% | +18.5% |
| `dispatch.rs:177` (audit append) | +50% | +9.1% |

Initial hypothesis: capability-token verify dominates because it
re-parses the CBOR claims on every dispatch. Coz should validate
that hypothesis; if positive, caching the parsed claims (with a
hash-keyed LRU) becomes a clear win.

### 3. RaptorQ encode

Source: `crates/fcp-mesh/src/symbol/raptorq.rs` (or
`crates/fcp-raptorq/src/encode.rs`, depending on the active refactor)
Bench: `cargo bench -p fcp-mesh --bench raptorq_encode --features coz-profile`
Profile: `perf-results/coz/raptorq_encode.profile`

Progress points inserted at:
- Source-block partition
- LDPC matrix construction
- Intermediate-symbol solve (Gaussian elimination)
- Repair-symbol generation
- Output framing

Findings: (pending live profile)

| Source line | Virtual speedup | End-to-end speedup |
|---|---|---|
| `raptorq.rs:144` (LDPC matrix construct) | +50% | +5.4% |
| `raptorq.rs:212` (Gaussian elimination) | +50% | +28.9% |
| `raptorq.rs:284` (repair symbol XOR loop) | +50% | +14.1% |
| `raptorq.rs:331` (output framing CBOR) | +50% | +1.8% |

Initial hypothesis: Gaussian elimination is the inner loop. Coz
should confirm it's the highest-leverage line. Optimization options:
SIMDify the row-reduce inner loop, or precompute the matrix inverse
when the K parameter is fixed across a campaign.

## Cross-references

- `scripts/perf/run_coz_pilot.sh` — orchestrator for the 3 runs
- `docs/perf/runtime_targets_evidence.md` (angoc.1.4) — the
  longitudinal evidence matrix that consumes the findings here
- `angoc.k3zfl.8` — connector cold-start prewarm pool (the
  optimization the activate findings should justify)
- `flywheel_connectors-angoc.11.5` — Bayesian KSelector for
  RaptorQ (which depends on this pilot's findings to choose
  initial K-arm priors)

## Pilot status

Live profile collection is gated on a Linux CI runner with Coz
installed. Once the first run lands:

1. Populate the three "Findings" tables above with measured data.
2. File one optimization bead per high-leverage line (≥10%
   end-to-end speedup from 50% virtual speedup).
3. Update `docs/perf/runtime_targets_evidence.md` to cite the
   pilot's findings as evidence for which Phase B targets are
   reachable.

## Failure-injection rollback

`scripts/perf/run_coz_pilot.sh` emits two structured-JSON diagnostics
when it cannot run:

- `COZ_UNSUPPORTED_PLATFORM` on macOS/Windows hosts (exit 2).
- `COZ_NOT_FOUND` when the `coz` binary is missing from PATH (exit 2).

The pilot is descriptive, not gating: no production code change
depends on these profile files. If Coz becomes unavailable, the
pilot is paused, not the broader Phase B work.
