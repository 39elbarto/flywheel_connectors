# Runtime Targets Evidence Matrix

Bead: `flywheel_connectors-angoc.1.4` (Phase B.4)

This document pins the canonical evidence matrix for the seven non-memory
runtime performance targets declared in `README.md` (memory has its own
evidence doc at `memory_overhead_evidence.md`; PQ-signing has its own at
`pq_signing_overhead_evidence.md`). The matrix covers three machine classes
that we exercise: `laptop_m2` (developer macOS ARM), `server_x86` (Contabo
VPS or csd reference Linux), and `ci_runner` (the GitHub Actions ubuntu
runner used by `.github/workflows/`).

The corresponding gate at `scripts/ci/perf_regression_gate.sh` consumes the
JSONL files referenced below; the thresholds live in `perf-targets.toml`.
Conformance for "every cell has a non-empty JSONL file" is at
`crates/fcp-conformance/tests/runtime_targets_evidence_present.rs`.

## Evidence shape

Each cell points to a JSONL file at
`perf-results/runtime_targets/<machine_class>/<target>.jsonl`. Every line
in the file is one StatPack sample record matching `fcp-bench::stats::StatPack`
methodology (see `stats_pack_methodology.md`). Required fields per record:

```json
{
  "schema": "fcp.runtime-target.v1",
  "target": "cold_start_ms",
  "machine_class": "laptop_m2",
  "p50": 78.4,
  "p95": 142.0,
  "p99": 198.6,
  "p999": 245.1,
  "tail_amp": 0.85,
  "samples": 10000,
  "commit_sha": "ce886559b",
  "timestamp": "2026-05-13T14:30:00Z",
  "verdict": "pass"
}
```

## The 7 targets

### 1. `cold_start_ms` — connector activate

Workspace p99 target: 500ms. Measured via `cargo bench -p fcp-host --bench
cold_start` driving a representative connector (default: `github`) from
host-spawn to first-successful invoke.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/cold_start_ms.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/cold_start_ms.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/cold_start_ms.jsonl` |

Reproduction:
```bash
bash scripts/perf/collect_runtime_targets.sh --target cold_start_ms --machine-class <class>
```

### 2. `local_invoke_us` — same-host JSON-RPC dispatch

Workspace p99 target: 10ms (10000us). Measured via `cargo bench -p fcp-host
--bench local_invoke` with a no-op connector handler so the cost is purely
the host JSON-RPC + zone check + capability check pipeline.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/local_invoke_us.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/local_invoke_us.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/local_invoke_us.jsonl` |

### 3. `lan_invoke_us` — cross-node mesh dispatch (LAN)

Workspace p99 target: 100ms (100000us). Measured via `cargo bench -p fcp-mesh
--bench mesh_dispatch_lan` against two mesh nodes on the same LAN. The
README mesh-native cutover (Phase A) is the gate on actually running this
beyond the bench harness.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/lan_invoke_us.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/lan_invoke_us.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/lan_invoke_us.jsonl` |

### 4. `derp_invoke_ms` — cross-node mesh dispatch via DERP relay

Workspace p99 target: 500ms. Measured against a Tailscale DERP-relayed pair
of mesh nodes. DERP relay introduces a round-trip via the relay so this
target is intentionally generous.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/derp_invoke_ms.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/derp_invoke_ms.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/derp_invoke_ms.jsonl` |

### 5. `symbol_reconciliation_us` — RaptorQ symbol exchange

Workspace p99 target: 100ms (100000us). Measured via `cargo bench -p
fcp-raptorq --bench symbol_reconciliation` over a synthetic 1 MiB payload
split into 100 symbols with 30% loss simulation.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/symbol_reconciliation_us.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/symbol_reconciliation_us.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/symbol_reconciliation_us.jsonl` |

### 6. `secret_reconciliation_ms` — FROST secret-share reconstruction

Workspace p99 target: 100ms. Measured via `cargo bench -p fcp-bootstrap
--bench frost_recon` over a 3-of-4 share reconstruction.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/secret_reconciliation_ms.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/secret_reconciliation_ms.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/secret_reconciliation_ms.jsonl` |

### 7. `cpu_overhead_pct` — fcp-host idle CPU %

Workspace p99 target: 1.0%. Measured via a 60-second idle observation
against a fcp-host process with one connector loaded but no requests
inbound. Compared against a no-fcp-host baseline daemon for delta.

| Machine class | Status | Evidence path |
| --- | --- | --- |
| `laptop_m2` | fixture | `perf-results/runtime_targets/laptop_m2/cpu_overhead_pct.jsonl` |
| `server_x86` | fixture | `perf-results/runtime_targets/server_x86/cpu_overhead_pct.jsonl` |
| `ci_runner` | fixture | `perf-results/runtime_targets/ci_runner/cpu_overhead_pct.jsonl` |

## Collection orchestrator

`scripts/perf/collect_runtime_targets.sh` runs the seven `cargo bench`
invocations sequentially (parallel runs would cross-contaminate latency
measurements), captures stdout/stderr per target, and writes one StatPack
JSONL line per benchmark iteration to the per-target file under
`perf-results/runtime_targets/<machine_class>/`.

The script is idempotent: re-running appends new JSONL lines (each tagged
with `timestamp` and `commit_sha`) so the gate consumes the most recent
validated row per machine class. Old rows remain for longitudinal trend
analysis.

## Ratchet model

Like the coverage scanner (Phase H.3) and the StatPack registry (Phase B.2),
this matrix uses a ratchet:

1. Every cell starts as a `fixture` placeholder pointing to an empty or
   single-line JSONL file.
2. As live evidence is collected (manually for now, via CI automation in
   `angoc.1.2`), the cell flips to `live` with the live JSONL line.
3. The conformance test enforces that no live cell regresses to fixture;
   adding a new target without updating this doc fails CI.

## Gate alignment

The `scripts/ci/perf_regression_gate.sh` script reads thresholds from
`perf-targets.toml` and the latest JSONL line from each
`perf-results/runtime_targets/<machine_class>/<target>.jsonl`. A pass is
`measured_p99 <= target_p99 * (1 + tolerance_pct / 100)`. The 7 targets
above plus `memory_overhead` (already covered) plus `pq_signing` (Phase N)
give 9 total targets the gate verifies.

## Failure-injection rollback

A corrupt JSONL line (malformed JSON, missing field, bad timestamp) is
rejected by the gate with a structured diagnostic; the gate exits non-zero
without consulting the rest of the file. This is the same defense-in-depth
the `coverage_scanner_conformance.rs` test uses for malformed scanner
output.

## Cross-references

- `docs/perf/memory_overhead_evidence.md` — existing memory budget evidence
- `docs/perf/pq_signing_overhead_evidence.md` — PQ verify budget evidence
  (Phase N.2)
- `docs/perf/stats_pack_methodology.md` — the StatPack schema this matrix uses
- `docs/perf/perf-targets.toml` — canonical thresholds
- `scripts/ci/perf_regression_gate.sh` — the consuming gate (Phase B.9)
- `crates/fcp-conformance/tests/runtime_targets_evidence_present.rs` — the
  conformance test that asserts every cell has a JSONL file
