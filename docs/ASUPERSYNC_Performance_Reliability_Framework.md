# ASUPERSYNC Performance + Reliability Framework

> **Status**: PREPARATORY framework for execution track  
> **Date**: 2026-02-28  
> **Owner Bead**: `flywheel_connectors-235t.28`  
> **Program Epic**: `flywheel_connectors-235t`

---

## 1. Purpose

Define the deterministic measurement and decision framework used by beads:
- `flywheel_connectors-235t.28.1` (benchmark harness + baseline/delta pack)
- `flywheel_connectors-235t.28.2` (soak + adversarial stress scripts)
- `flywheel_connectors-235t.28.3` (runtime/queue/admission tuning)
- `flywheel_connectors-235t.28.4` (terminal gate artifact + config freeze)

This framework is intentionally executable and machine-consumable, not prose-only.

---

## 2. Execution Preconditions

No terminal performance freeze is valid unless these dependency gates are complete:

1. Logging/forensics standard: `flywheel_connectors-235t.32`
2. Validation release-gate artifact: `flywheel_connectors-235t.27.4`
3. Forensics actionability gate: `flywheel_connectors-235t.26.7.3`

Interim benchmark/soak dry-runs are allowed before those gates, but must be marked `pre-gate`.

Normative schema details for item (1) are defined in:

- `docs/ASUPERSYNC_Logging_Forensics_Standard.md` (`schema_version: asupersync-forensics/v1`)

---

## 3. Canonical Metric Contract

All performance artifacts must emit these normalized fields:

- `run_id`
- `scenario_id`
- `phase` (`baseline` | `delta` | `soak` | `adversarial` | `tuning`)
- `metric_name`
- `value`
- `unit`
- `component` (crate/connector/runtime surface)
- `sample_count`
- `window_ms`
- `captured_at` (RFC3339 UTC)

### 3.1 Required Metrics

| Metric ID | Definition | Required For |
|---|---|---|
| `latency_p50_ms` | Median end-to-end operation latency | 28.1, 28.3, 28.4 |
| `latency_p95_ms` | p95 end-to-end operation latency | 28.1, 28.2, 28.3, 28.4 |
| `latency_p99_ms` | p99 end-to-end operation latency | 28.2, 28.3, 28.4 |
| `throughput_ops_s` | Sustained operations/sec | 28.1, 28.2, 28.4 |
| `rss_mb` | Resident memory footprint | 28.1, 28.2, 28.4 |
| `queue_depth_p95` | p95 queue occupancy | 28.1, 28.2, 28.3 |
| `reconnect_success_rate` | Successful reconnect ratio | 28.2, 28.4 |
| `cancel_storm_recovery_ms` | Time to stable state after cancellation storm | 28.2, 28.4 |
| `error_budget_burn_rate` | Error budget consumption over window | 28.2, 28.3, 28.4 |

---

## 4. Scenario Matrix Contract

### 4.1 Baseline/Delta Scenarios (`28.1`)
- request/response hot path
- streaming path (steady)
- streaming path (disconnect/reconnect)
- timeout-heavy path
- cancellation-heavy path

### 4.2 Soak/Adversarial Scenarios (`28.2`)
- 2h soak steady-state profile
- burst traffic profile (short spikes)
- sustained near-capacity profile
- reconnect storm profile
- cancellation storm profile
- degraded symbol repair pressure profile

### 4.3 Tuning Experiments (`28.3`)
- queue bound sweeps
- retry budget sweeps
- admission threshold sweeps
- scheduler/worker tuning sweeps

Every scenario must produce deterministic replay instructions.

---

## 5. Artifact Layout and Replay Contract

```text
artifacts/asupersync/perf/<run-id>/
  manifest.json
  steps.jsonl
  summary.json
  metrics.jsonl
  metrics_template.json
  normalized_summary.json
  delta_summary.json
  scenario_plan.json
  scenarios/
  tuning/
  gate/
  replay.sh
```

`manifest.json` must include:
- git commit hash
- command set
- environment fingerprint (toolchain/runtime profile)
- scenario list
- pass/fail summary
- metric normalization classification and missing-required-metric count

`replay.sh` must be executable and reproduce the measurement run from the same repo state.

---

## 6. Decision Rules

### 6.1 Acceptance Rule

A tuning/config change is admissible only if:
1. no critical reliability metric regresses beyond configured threshold
2. tail latency (`p95`/`p99`) does not regress while improving only median
3. diagnosability is preserved (required forensic/log fields present)

### 6.2 Classification

Each candidate run must be labeled:
- `accept`
- `reject`
- `requires_followup`

with machine-readable rationale.

---

## 7. RCH Command Pack (for heavy workloads)

Use offloaded commands for CPU-intensive benchmark/soak gates:

```bash
# Orchestrated baseline run (pre-gate allowed)
bash scripts/e2e/asupersync_performance_pack.sh --phase baseline --pre-gate --metrics-input artifacts/asupersync/perf/input/metrics_baseline.jsonl

# Orchestrated delta run (compare against baseline normalized summary)
bash scripts/e2e/asupersync_performance_pack.sh --phase delta --pre-gate \
  --metrics-input artifacts/asupersync/perf/input/metrics_delta.jsonl \
  --baseline-summary artifacts/asupersync/perf/<baseline-run-id>/normalized_summary.json

# Baseline checks
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo test --workspace --all-targets -- --nocapture

# Performance harness and soak packs (to be wired by 28.1/28.2)
rch exec -- cargo test -p fcp-e2e -- --nocapture
rch exec -- cargo test -p fcp-streaming -- --nocapture
```

If `rch` fails open in a run window, retain the `rch exec -- ...` invocation in logs and record fallback behavior in the artifact manifest.

---

## 8. Child-Bead Mapping

| Bead | Framework Deliverables Consumed |
|---|---|
| `235t.28.1` | Sections 3, 4.1, 5, 7 |
| `235t.28.2` | Sections 3, 4.2, 5, 6, 7 |
| `235t.28.3` | Sections 3, 4.3, 6 |
| `235t.28.4` | Sections 2, 5, 6 + consolidated outputs from 28.1-28.3 |

This framework should be treated as the contract source for all `.28.*` execution artifacts.
