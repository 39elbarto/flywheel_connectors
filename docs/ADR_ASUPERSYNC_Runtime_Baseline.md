# ADR: ASUPERSYNC-First Runtime Baseline (Tokio Prohibition Contract)

> **Status**: ACCEPTED  
> **Date**: 2026-02-28  
> **Owner Bead**: `flywheel_connectors-235t.1`  
> **Program Epic**: `flywheel_connectors-235t`

---

## 1. Goal

Define the non-negotiable runtime contract for the FCP ASUPERSYNC migration so crate owners cannot reintroduce mixed-runtime behavior.

This ADR is the normative baseline for all child beads in `flywheel_connectors-235t`.

---

## 2. Context

The current workspace has broad Tokio surface area and inconsistent async behavior across host, sdk, mesh, store, and connectors.

Observed baseline on 2026-02-28:
- Tokio references: 466 lines across 68 Rust files
- `#[tokio::test]` usage: 314
- `tokio::runtime::Builder` usage: 19
- `tokio::spawn` usage: 16
- `tokio::select!` usage: 6

Without one contract, migration work will drift into incompatible cancellation, timeout, and backpressure semantics.

---

## 3. Decision

### 3.1 Runtime Architecture Contract

1. FCP runtime code MUST converge to ASUPERSYNC-first orchestration.
2. Runtime APIs MUST be consumed through a shared substrate crate (`fcp-async-core`) backed by ASUPERSYNC primitives.
3. Application crates MUST NOT introduce local runtime wrappers that bypass `fcp-async-core`.

### 3.2 Canonical Terms (Normative Vocabulary)

- `ExecutionContext`: task root containing trace context, deadline budget, and cancellation lineage.
- `OperationDeadline`: absolute deadline propagated end-to-end; no unbounded waits.
- `CancellationEdge`: explicit boundary where cancellation is checked and acted on.
- `BoundedQueue`: queue with fixed capacity and explicit overflow strategy.
- `SupervisorDomain`: owned task group with restart policy, failure budget, and deterministic shutdown semantics.

### 3.3 Cancellation and Deadlines

1. Every externally initiated operation MUST have an `OperationDeadline`.
2. Cancellation MUST propagate via `ExecutionContext` through connector, host, mesh, and store boundaries.
3. Blocking waits without deadline propagation are forbidden.

### 3.4 Queue and Backpressure Rules

1. Runtime message passing MUST use bounded queues by default.
2. Every queue MUST declare one overflow policy: `drop_oldest`, `drop_newest`, `reject`, or `block_with_deadline`.
3. Unbounded queue usage is forbidden unless explicitly approved under the exception policy below.

### 3.5 Network Client Standard

1. Outbound network IO MUST use a unified client stack selected by the migration program.
2. Retries MUST be deadline-aware and cancellation-aware.
3. Connection lifecycle behavior (reconnect, jitter, failure budget) MUST be explicit and testable.

### 3.6 Test Runtime Standard

1. Runtime tests MUST migrate from `#[tokio::test]` to the shared ASUPERSYNC test harness exposed by `fcp-async-core`.
2. Test harness behavior MUST be deterministic where feasible (seeded randomness, bounded timeouts, stable logs).

---

## 4. Hard Tokio Policy

### 4.1 Forbidden Usage (Post-Cutover Target)

The following are forbidden in FCP-owned runtime paths unless covered by approved temporary exceptions:
- `tokio::runtime::Builder`
- `tokio::spawn` / `tokio::task::spawn`
- `tokio::select!`
- `tokio::sync::*` runtime channels
- `tokio::time::{sleep, timeout, interval}`
- `#[tokio::test]`

### 4.2 Temporary Exceptions Policy

Temporary exceptions are allowed only when all conditions are met:
1. Tracked in Beads with explicit owner and rationale.
2. Linked to a migration bead and planned removal date.
3. Time-bounded to a maximum window of 14 calendar days.
4. Included in CI allowlist checks with expiry metadata.

If the removal date passes, CI must fail until exception is removed or explicitly re-approved.

---

## 5. CI Enforcement Hooks (Required by Later Beads)

Implementation beads must add these gates:

1. **Tokio reintroduction scanner**
   - Fail CI on direct `tokio::` usage outside approved allowlist paths.

2. **Runtime wrapper policy check**
   - Fail CI when crates define ad hoc runtime abstractions instead of `fcp-async-core`.

3. **Exception expiry check**
   - Fail CI when exception entries exceed their approved window.

4. **Test harness check**
   - Fail CI when new `#[tokio::test]` appears outside approved temporary exceptions.

### 5.1 Implemented Guardrail Surface (Delivered by `flywheel_connectors-235t.5`)

The initial mechanical enforcement surface is now implemented and bead-linked:

- Guardrail runner: `scripts/ci/asupersync_tokio_guard.sh`
- Exception ledger: `.config/asupersync/tokio_exception_ledger.json`
- CI gate: `.github/workflows/ci.yml` job `asupersync-guardrails`
- Local command:
  - `bash scripts/ci/asupersync_tokio_guard.sh`

The guardrail currently enforces:
1. Forbidden direct dependency detection for `tokio`, `tokio-stream`, and `tokio-tungstenite` across workspace crates.
2. Required active exception entries for every forbidden dependency.
3. Hard failure on expired dependency exception entries.
4. Baseline-growth caps for key Tokio usage patterns (`tokio::`, `#[tokio::test]`, runtime builder, spawn/select/sync/time usage).

---

## 6. Migration Anti-Patterns (Do Not Allow)

- Hidden runtime bootstrap in helper functions.
- Implicit unbounded channels.
- Mixed timeout semantics across crates.
- Retrying without deadline budget checks.
- Connector-local async wrappers that diverge from shared substrate behavior.

---

## 7. Tokio-to-ASUPERSYNC Mapping Table

Use ASUPERSYNC through `fcp-async-core` APIs.

| Legacy Tokio Pattern | Approved Replacement | Notes |
|---|---|---|
| `tokio::spawn(fut)` | `fcp_async_core::task::spawn(cx, fut)` | Spawn must attach `ExecutionContext`. |
| `tokio::task::spawn` | `fcp_async_core::task::spawn` | Same policy as above. |
| `tokio::select!` | `fcp_async_core::select::race` or `fcp_async_core::select::biased_race` | Choice must be explicit and documented. |
| `tokio::sync::mpsc` | `fcp_async_core::queue::bounded` | Capacity + overflow strategy required. |
| `tokio::time::sleep(d)` | `fcp_async_core::time::sleep_until(deadline)` | Prefer absolute deadlines over relative sleeps. |
| `tokio::time::timeout(d, fut)` | `fcp_async_core::time::with_deadline(deadline, fut)` | Deadline propagates through context. |
| `tokio::join!` / `tokio::try_join!` | `fcp_async_core::task::join_set` | Aggregate failures through supervisor policy. |
| `tokio::runtime::Builder` | `fcp_async_core::runtime::init` | Single runtime bootstrap path only. |
| `#[tokio::test]` | `#[fcp_async_test]` | Standardized deterministic runtime harness. |

---

## 8. Tradeoff Decision Table

| Decision Area | Default Choice | Rationale | Allowed Override |
|---|---|---|---|
| Throughput vs fairness | Fair scheduling baseline | Avoid starvation and hidden tail latency spikes | Override only with benchmark evidence and bead approval |
| Eager vs lazy spawn | Lazy spawn where possible | Limits runaway task fan-out | Eager allowed for latency-critical hot paths with failure-budget controls |
| Strict vs permissive timeout defaults | Strict deadline defaults | Eliminates silent hangs and drift | Permissive only in explicitly documented long-poll scenarios |
| Queue pressure handling | Reject or bounded block with deadline | Keeps failure explicit and observable | Drop policies only where loss is semantically acceptable |

---

## 9. One-Page Cheat Sheet

### Replace This
- `tokio::spawn`
- `tokio::select!`
- `tokio::sync::mpsc`
- `tokio::time::{sleep, timeout}`
- `tokio::runtime::Builder`
- `#[tokio::test]`

### With This
- `fcp_async_core::task::spawn(cx, fut)`
- `fcp_async_core::select::{race, biased_race}`
- `fcp_async_core::queue::bounded(capacity, overflow_policy)`
- `fcp_async_core::time::{sleep_until, with_deadline}`
- `fcp_async_core::runtime::init(config)`
- `#[fcp_async_test]`

### Required Every Time
- Carry `ExecutionContext`
- Carry an `OperationDeadline`
- Use bounded queues
- Define overflow behavior
- Keep cancellation edges explicit

### PR Checklist Snippet
- No new direct `tokio::` usage in runtime paths
- No new `#[tokio::test]` unless exception-tracked
- Deadline + cancellation propagation shown in code/tests
- Queue capacity + overflow semantics documented

---

## 10. Adoption and References

- This ADR is normative for all `flywheel_connectors-235t.*` migration beads.
- Follow-up enforcement is delivered by dependency and CI guardrail beads (especially `235t.5` and test/validation tracks).
- Tokio-coupled dependency replacement strategy is defined in `docs/ASUPERSYNC_Transport_Runtime_Replacement_Plan.md` (`235t.31`).
- Update this ADR only through explicit bead-linked changes.
