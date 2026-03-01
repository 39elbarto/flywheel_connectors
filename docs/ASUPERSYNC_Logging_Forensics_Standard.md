# ASUPERSYNC Structured Logging + Failure Forensics Standard

> **Status**: NORMATIVE migration contract  
> **Date**: 2026-02-28  
> **Owner Bead**: `flywheel_connectors-235t.32`  
> **Program Epic**: `flywheel_connectors-235t`

---

## 1. Goal

Define one machine-parseable logging/forensics contract for ASUPERSYNC migration evidence across:

- unit/integration test gates
- scripted E2E validation gates
- performance/reliability runs

This standard is the required diagnostic baseline for marking migration beads complete.

---

## 2. Canonical Forensics Schema

Schema identifier:

- `schema_version = "asupersync-forensics/v1"`

Required fields for every step-level forensic record:

- `run_id` (stable run identifier)
- `scenario_id` (stable scenario/step identifier)
- `trace_id` (trace key for correlation)
- `correlation_id` (cross-tool correlation key; may equal `trace_id`)
- `connector` (connector id or `n/a`)
- `zone` (zone id or `n/a`)
- `operation` (operation/step label)
- `attempt` (attempt index, integer)
- `timeout_budget_ms` (budget used for this step)
- `cancellation_reason` (nullable string)
- `queue_depth` (nullable numeric snapshot)
- `decode_budget` (nullable numeric snapshot)
- `outcome` (`pass` | `fail` | `planned`)
- `elapsed_ms` (measured step duration)

Implementation note:

- Existing harness-level E2E JSONL shape remains governed by [docs/testing/e2e_log_schema.md](/Users/jemanuel/projects/flywheel_connectors/docs/testing/e2e_log_schema.md).
- ASUPERSYNC step forensics extends migration pack artifacts with the schema above.
- Reusable async fixture utilities live in `crates/fcp-testkit/src/async_harness.rs` for run/scenario correlation IDs, timeout/cancellation helpers, and bounded queue test fixtures.

---

## 3. Artifact Contract

Every ASUPERSYNC run must produce replayable, stable artifacts under one run root.

Validation pack root:

- `artifacts/asupersync/validation/<run-id>/`

Performance pack root:

- `artifacts/asupersync/perf/<run-id>/`

E2E matrix root:

- `artifacts/asupersync/e2e/<run-id>/`

Required files:

- `steps.jsonl` (step-level forensic records, one per step)
- `summary.json` (rollup + pointers + pass/fail envelope)
- `replay.sh` (deterministic rerun entrypoint)

Performance pack additionally requires:

- `manifest.json`
- `metrics.jsonl`
- `metrics_template.json`
- `normalized_summary.json`
- `delta_summary.json`
- `scenario_plan.json`

E2E matrix additionally requires:

- `manifest.json`
- `scenario_plan.json`
- `results.jsonl`
- `scenarios/<scenario>/command.txt`
- `scenarios/<scenario>/execution.log`
- `scenarios/<scenario>/scenario.json`

---

## 4. Required Logging Assertions

Migration gates must assert forensic completeness for critical failure classes:

- reconnect storm handling
- cancellation storm handling
- decode pressure / repair pressure
- retry exhaustion
- deadline/timeout budget exhaustion

Each failing scenario must retain enough artifact data to reproduce triage without rerunning with ad-hoc flags.

---

## 5. Enforcement Points

Current enforcement is wired into:

- [scripts/e2e/asupersync_validation_pack.sh](/Users/jemanuel/projects/flywheel_connectors/scripts/e2e/asupersync_validation_pack.sh)
- [scripts/e2e/asupersync_performance_pack.sh](/Users/jemanuel/projects/flywheel_connectors/scripts/e2e/asupersync_performance_pack.sh)
- [scripts/e2e/run_matrix.sh](/Users/jemanuel/projects/flywheel_connectors/scripts/e2e/run_matrix.sh)
- [scripts/e2e/unit_gate_executor.sh](/Users/jemanuel/projects/flywheel_connectors/scripts/e2e/unit_gate_executor.sh)
- [scripts/e2e/integration_gate_executor.sh](/Users/jemanuel/projects/flywheel_connectors/scripts/e2e/integration_gate_executor.sh)
- [scripts/e2e/validate_asupersync_forensics_bundle.sh](/Users/jemanuel/projects/flywheel_connectors/scripts/e2e/validate_asupersync_forensics_bundle.sh)

These scripts validate `steps.jsonl` records against `asupersync-forensics/v1` before writing final summaries.
They also emit a deterministic gate report at:

- `forensics_validator_report.json`

Runbook commands:

```bash
# Validation gate
bash scripts/e2e/asupersync_validation_pack.sh

# Performance/reliability gate
bash scripts/e2e/asupersync_performance_pack.sh --phase baseline --pre-gate
```

CPU-intensive subcommands are executed through `rch exec -- ...` inside these scripts.

---

## 6. Downstream Dependency Contract

Any bead depending on `flywheel_connectors-235t.32` must treat this file as normative when defining:

- log schema assertions
- evidence bundle structure
- replay instructions
- CI/local gate pass criteria
