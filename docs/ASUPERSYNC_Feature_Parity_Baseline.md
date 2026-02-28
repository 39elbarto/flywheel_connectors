# ASUPERSYNC Feature Parity Baseline + Golden Behavior Contracts

> **Status**: NORMATIVE migration baseline artifact  
> **Date**: 2026-02-28  
> **Owner Bead**: `flywheel_connectors-235t.30`  
> **Program Epic**: `flywheel_connectors-235t`

---

## 1. Purpose

Define the pre-migration behavior contract that prevents user-visible regressions during ASUPERSYNC runtime migration.

This baseline is required before declaring any migration bead complete.

---

## 2. Contract Scope

The parity baseline explicitly captures:
1. Connector API behavior (request/response envelopes, error codes, capability denials)
2. Streaming ordering and termination semantics
3. Timeout and cancellation outcomes
4. RaptorQ repair behavior under partial symbol availability
5. CLI UX/error semantics

---

## 3. Golden Behavior Contract Catalog

Contract IDs are mandatory references for migration PRs and bead completion notes.

| Contract ID | Surface | Behavior Contract | Required Baseline Evidence |
|---|---|---|---|
| `PAR-RUNTIME-001` | Handshake | Successful handshake envelope shape and required fields are stable | JSON response fixtures + schema validation log |
| `PAR-RUNTIME-002` | Invoke success | `InvokeResponse` status/result envelope remains shape-compatible | Golden JSON/CBOR fixtures |
| `PAR-RUNTIME-003` | Invoke denial | Denials include stable reason code and evidence pointers | DecisionReceipt fixtures + deny-path logs |
| `PAR-RUNTIME-004` | Retry semantics | Retryable external failures preserve retry classification and backoff behavior | Integration logs with retry metadata |
| `PAR-RUNTIME-005` | Idempotency | Repeated idempotency keys return prior receipt instead of duplicate side effects | Receipt-chain evidence and idempotency trace |
| `PAR-STREAM-001` | Ordering | Stream chunks/events preserve ordering guarantees per connector/harness contract | Scripted E2E logs with sequence assertions |
| `PAR-STREAM-002` | Termination | Stream terminal states (`complete`, `error`, cancellation) are unambiguous and stable | Terminal event logs + status summary |
| `PAR-STREAM-003` | Backpressure | Subscriber backpressure behavior and overflow outcomes are explicit and stable | Structured logs with queue/backpressure fields |
| `PAR-CANCEL-001` | Pre-dispatch cancel | Cancellation before dispatch yields deterministic error/status outcome | Cancellation-flow script logs |
| `PAR-CANCEL-002` | In-flight cancel | Cancellation during execution preserves bounded cleanup and final state semantics | In-flight cancellation traces |
| `PAR-TIMEOUT-001` | Deadline timeout | Deadline/timeout outcomes preserve stable error classification and no hang behavior | Timeout-flow traces + duration metrics |
| `PAR-RAPTORQ-001` | Decode threshold | Partial symbol availability reaches decode at expected thresholds | Repair/decode logs with symbol counts |
| `PAR-RAPTORQ-002` | Targeted repair | Targeted repair requests and acks remain deterministic and bounded | Targeted repair script logs |
| `PAR-RAPTORQ-003` | Degraded mode | Degraded repair behavior has explicit, stable fallback outcomes | Degraded-path scenario logs |
| `PAR-CLI-001` | Exit semantics | CLI commands preserve pass/fail exit code semantics | CLI invocation log + exit code record |
| `PAR-CLI-002` | Human output | Human-readable diagnostics retain actionable sections and reasons | Snapshot outputs for `doctor/explain/repair` |
| `PAR-CLI-003` | JSON output | Machine-readable command output retains schema/field stability | JSON schema validation results |

---

## 4. Before-State Evidence Capture Spec

### 4.1 Required Artifact Layout

All baseline evidence must be published under a deterministic directory layout:

```text
artifacts/asupersync/parity-baseline/
  contract-index.json
  runtime/
  stream/
  cancel-timeout/
  raptorq/
  cli/
  logs/
  summaries/
```

### 4.2 Required Record Fields

Each evidence record must include:

- `contract_id`
- `scenario_id`
- `command`
- `result` (`pass` or `fail`)
- `exit_code`
- `duration_ms`
- `artifact_paths[]`
- `log_paths[]`
- `captured_at` (RFC3339 UTC)
- `notes` (optional)

### 4.3 Structured Log Requirements

All scripted and harness evidence must validate against:
- `docs/testing/e2e_log_schema.md`
- `crates/fcp-conformance/src/schemas/E2E_Log_v1.schema.json`
- `crates/fcp-conformance/src/schemas/E2E_Log_v2.schema.json`

---

## 5. Baseline Capture Command Set

Use deterministic command packs and preserve exact command lines in artifacts.

Core command set (examples):

```bash
# Conformance/integration baseline
rch exec -- cargo test -p fcp-conformance -- --nocapture

# Core runtime-focused coverage
rch exec -- cargo test -p fcp-core -- --nocapture
rch exec -- cargo test -p fcp-protocol -- --nocapture
rch exec -- cargo test -p fcp-streaming -- --nocapture

# Mesh + repair surfaces
rch exec -- cargo test -p fcp-mesh -- --nocapture
rch exec -- cargo test -p fcp-store -- --nocapture

# Scripted E2E matrix
./scripts/e2e/run_matrix.sh
./scripts/e2e/asupersync_validation_pack.sh
```

Any additional command used for a contract must be recorded in `contract-index.json`.

---

## 6. No-Regression Checklist by Migration Wave

### Wave A: Foundation (`235t.1` to `235t.6`)
- Parity references required: `PAR-RUNTIME-*`, `PAR-CLI-*`, `PAR-CANCEL-*`
- Must not ship runtime substrate/policy changes without baseline records for those contracts

### Wave B: Runtime Core (`235t.7` to `235t.13`)
- Parity references required: `PAR-RUNTIME-*`, `PAR-STREAM-*`, `PAR-CANCEL-*`, `PAR-TIMEOUT-*`
- Any changed behavior requires explicit approved delta note with user impact

### Wave C: Connectors (`235t.14` to `235t.19`)
- Parity references required: `PAR-RUNTIME-*`, `PAR-STREAM-*`, `PAR-CANCEL-*`, `PAR-CLI-*`
- Connector PRs must attach scenario IDs and contract IDs for changed flows

### Wave D: RaptorQ + Repair (`235t.20` to `235t.25`)
- Parity references required: `PAR-RAPTORQ-*`, plus `PAR-RUNTIME-003` for deny/failure paths
- Degraded-mode and partial-symbol scenarios are mandatory
- Contract baseline required: `docs/RFC_RaptorQ_Integration.md`

### Wave E: Validation/Cutover (`235t.26` to `235t.34`)
- Parity references required: all contracts
- Cutover can only proceed with complete contract matrix and explicit drift classifications

---

## 7. Regression and Drift Rules

1. Any behavior difference from baseline must be labeled as one of:
   - `approved_delta`
   - `regression`
   - `inconclusive`
2. `approved_delta` entries must include rationale and user impact.
3. `regression` entries block bead completion until fixed or explicitly waived.
4. `inconclusive` entries require rerun instructions and ownership assignment.

---

## 8. Mandatory Bead/PR Linkage

Before a migration bead is closed:
1. Bead comments must list relevant `PAR-*` IDs.
2. Evidence paths must be attached or linked.
3. Any deltas must be classified and justified.

Before a migration PR is approved:
1. PR description must include a `Parity Contracts` section.
2. The section must list affected `PAR-*` IDs and evidence links.
