# ASUPERSYNC Capability Matrix + Gap/Risk Register

> **Status**: NORMATIVE migration planning artifact  
> **Date**: 2026-02-28  
> **Owner Bead**: `flywheel_connectors-235t.2`  
> **Program Epic**: `flywheel_connectors-235t`

---

## 1. Purpose

This document is the mechanical inventory and migration planning baseline for ASUPERSYNC-first runtime convergence.

It delivers:
- crate-by-crate async/runtime inventory
- primitive capability matrix
- strategy classification (`direct replacement`, `requires adapter`, `staged workaround`)
- owner-tagged high-risk register with mitigation checkpoints
- dependency-surgery linkage to `docs/ASUPERSYNC_Transport_Runtime_Replacement_Plan.md`

---

## 2. Data Sources and Method

This inventory is derived from:
1. `cargo metadata --no-deps --format-version 1` (dependency surface)
2. source scans (`rg`) for runtime assumptions and Tokio usage

Primary probes used:
- `tokio::` reference lines
- `#[tokio::test]` attributes
- `tokio::runtime::Builder`
- `tokio::spawn` / `tokio::task::spawn`
- `tokio::select!`
- `tokio::sync::{mpsc,broadcast,watch,oneshot}`
- `tokio::time::{sleep,timeout,interval}`

Snapshot totals (2026-02-28):
- Tokio references: 466 lines
- Tokio-referencing files: 68
- Tokio test attributes: 314
- Runtime builder occurrences: 19

---

## 3. Primitive Row IDs

| Row ID | Primitive | Definition |
|---|---|---|
| `P1` | Runtime bootstrap | Process/runtime initialization and runtime ownership |
| `P2` | Task supervision | Spawn, join, supervisor domains, failure budgets |
| `P3` | Channels/backpressure | Async queues, boundedness, overflow behavior |
| `P4` | Timers/deadlines | Sleep/timeout/interval semantics and deadline propagation |
| `P5` | WebSocket transport | Streaming websocket client/runtime integration |
| `P6` | HTTP+TLS client stack | Outbound HTTP transport, TLS behavior, retry integration |
| `P7` | RaptorQ pipeline | Encode/decode/repair orchestration integration |
| `P8` | Test runtime harness | Async test macros, deterministic runtime behavior in tests |
| `P9` | Cancellation/context | Explicit cancellation edges + context propagation |

---

## 4. Crate-by-Crate Runtime Inventory

`Tokio refs/tests` and assumption hotspots were measured directly from source scans.

| Crate | Tokio refs | Tokio tests | Runtime builder | Spawn | Select | Sync channels | Timers | WebSocket | HTTP | TLS | RaptorQ | Cancellation hotspots |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|---|---|
| `fcp-sdk` | 76 | 43 | 2 | 3 | 5 | 14 | 5 | No | Yes | Yes | No | High |
| `fcp-ratelimit` | 66 | 59 | 0 | 0 | 0 | 0 | 6 | No | No | No | No | High |
| `fcp-discord` | 34 | 17 | 1 | 3 | 1 | 0 | 6 | Yes | Yes | Yes | No | High |
| `fcp-host` | 32 | 21 | 0 | 1 | 0 | 0 | 1 | No | No | No | No | Medium |
| `fcp-telegram` | 26 | 17 | 1 | 1 | 0 | 0 | 4 | No | Yes | Yes | No | Medium |
| `fcp-mesh` | 24 | 20 | 4 | 0 | 0 | 0 | 0 | No | No | No | Yes | Low |
| `fcp-openai` | 23 | 19 | 1 | 0 | 0 | 0 | 2 | No | Yes | Yes | No | Medium |
| `fcp-graphql` | 23 | 14 | 0 | 2 | 0 | 1 | 2 | Yes | Yes | Yes | No | Medium |
| `fcp-streaming` | 21 | 11 | 0 | 0 | 0 | 0 | 5 | Yes | Yes | Yes | No | High |
| `fcp-twitter` | 19 | 6 | 1 | 3 | 0 | 1 | 4 | No | Yes | Yes | No | Medium |
| `fcp-testkit` | 17 | 10 | 0 | 2 | 0 | 2 | 3 | No | Yes | Yes | No | Medium |
| `fcp-anthropic` | 16 | 12 | 1 | 0 | 0 | 0 | 2 | No | Yes | Yes | No | Medium |
| `fcp-e2e` | 15 | 9 | 0 | 1 | 0 | 0 | 0 | No | Yes | Yes | No | Low |
| `fcp-conformance` | 14 | 14 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fwc` | 11 | 8 | 2 | 0 | 0 | 0 | 1 | No | Yes | Yes | Yes | Medium |
| `fcp-tailscale` | 10 | 9 | 0 | 0 | 0 | 0 | 0 | No | Yes | Yes | No | Low |
| `fcp-telemetry` | 10 | 9 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-store` | 9 | 1 | 5 | 0 | 0 | 0 | 0 | No | No | No | Yes | Low |
| `fcp-vectordb` | 9 | 9 | 0 | 0 | 0 | 0 | 0 | No | Yes | Yes | No | Low |
| `fcp-core` | 8 | 5 | 0 | 0 | 0 | 0 | 2 | No | No | No | No | Medium |
| `fcp-registry` | 1 | 0 | 1 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-sandbox` | 1 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-bootstrap` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-audit` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-cbor` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-crypto` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-manifest` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-oauth` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | Yes | Yes | No | Low |
| `fcp-protocol` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |
| `fcp-raptorq` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | Yes | Low |
| `fcp-webhook` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | No | No | No | No | Low |

Notes:
- Runtime hotspot crates by Tokio references: `fcp-sdk`, `fcp-ratelimit`, `fcp-discord`, `fcp-host`.
- Builder-heavy crates: `fcp-store` and `fcp-mesh` (multiple local runtime builders).

---

## 5. Primitive Strategy Classification

| Row ID | Primitive | Current State | Strategy | Rationale | Primary Owner Beads |
|---|---|---|---|---|---|
| `P1` | Runtime bootstrap | 19 explicit builder sites | Requires adapter | Need one shared bootstrap path in `fcp-async-core` | `235t.3`, `235t.5` |
| `P2` | Task supervision | Spawn patterns and ad hoc join handling | Requires adapter | Must standardize supervisor semantics and failure budgets | `235t.3`, `235t.7`, `235t.8` |
| `P3` | Channels/backpressure | Tokio sync primitives in runtime-heavy crates | Direct replacement | Bounded queue primitives are first-class migration baseline | `235t.3`, `235t.4`, `235t.7` |
| `P4` | Timers/deadlines | Sleep/timeout spread across connectors and libs | Direct replacement | Deadline-aware timers can map to shared substrate APIs | `235t.4`, `235t.7`, `235t.9` |
| `P5` | WebSocket transport | `tokio-tungstenite` + reconnect behavior coupling | Requires adapter | Behavior-preserving wrapper needed before direct cutover | `235t.9`, `235t.10`, `235t.16-18` |
| `P6` | HTTP+TLS client stack | Broad `reqwest` coupling across crates/connectors | Staged workaround | Keep existing client behind adapter first, then swap transport | `235t.11`, `235t.31`, connector beads |
| `P7` | RaptorQ pipeline | Split across `fcp-raptorq`, mesh, store, cli | Staged workaround | Needs architecture contract (`docs/RFC_RaptorQ_Integration.md`) and phased cutover | `235t.20`, `235t.21`, `235t.22`, `235t.23`, `235t.24` |
| `P8` | Test runtime harness | 314 Tokio async test attributes | Requires adapter | Requires unified test macro/harness with deterministic behavior | `235t.26`, `235t.32` |
| `P9` | Cancellation/context | Inconsistent explicit cancellation edges | Requires adapter | Must enforce uniform context+deadline propagation | `235t.4`, `235t.30`, `235t.31` |

Classification summary:
- `direct replacement`: `P3`, `P4`
- `requires adapter`: `P1`, `P2`, `P5`, `P8`, `P9`
- `staged workaround`: `P6`, `P7`

---

## 6. High-Risk Register

| Risk ID | Risk | Impact | Owner | Mitigation | Checkpoint Date |
|---|---|---|---|---|---|
| `R1` | Fragmented runtime bootstrap (`P1`) across host/cli/connectors/store/mesh | Mixed runtime semantics and hidden deadlocks | `235t.3` | Introduce single bootstrap API in `fcp-async-core`; ban local builders via CI guardrail | 2026-03-07 |
| `R2` | HTTP/TLS transport replacement drift (`P6`) | Retry/timeout regressions and inconsistent TLS behavior | `235t.31` | Adapter phase preserving `reqwest` behavior; parity contract checks before swap | 2026-03-10 |
| `R3` | WebSocket reconnection semantic drift (`P5`) | Stream ordering/recovery regressions user-visible | `235t.9` | Build behavior-locking adapter + scripted E2E stream scenarios | 2026-03-10 |
| `R4` | Async test harness migration scale (`P8`) | False confidence from partial migration and flaky tests | `235t.26` | Introduce migration test macro, enforce no new `#[tokio::test]` | 2026-03-12 |
| `R5` | RaptorQ pipeline coupling across crates (`P7`) | Data loss/repair regressions in degraded paths | `235t.20` | Ship architecture contract first (`docs/RFC_RaptorQ_Integration.md`), then staged crate migration with vectors + adversarial tests | 2026-03-14 |
| `R6` | Cancellation edge inconsistency (`P9`) | Orphan tasks, leaked work, and timeout ambiguity | `235t.4` | Formal cancellation model + context propagation contract and lints | 2026-03-08 |
| `R7` | Guardrail gaps allow Tokio reintroduction (`P1-P9`) | Migration churn and policy backsliding | `235t.5` | Enforce `scripts/ci/asupersync_tokio_guard.sh` with `.config/asupersync/tokio_exception_ledger.json` in CI + local workflow | 2026-03-06 |
| `R8` | Telemetry runtime coupling | Observability regressions and context propagation breaks | `235t.12` | Isolate telemetry runtime boundary behind substrate facade | 2026-03-11 |

---

## 7. Migration Task-to-Row Mapping

All `flywheel_connectors-235t.*` migration beads must reference matrix rows.

| Bead | Required Row IDs |
|---|---|
| `235t.1` | `P1`, `P3`, `P4`, `P8`, `P9` |
| `235t.2` | `P1-P9` |
| `235t.3` | `P1`, `P2`, `P3`, `P4`, `P9` |
| `235t.4` | `P4`, `P9`, `P3` |
| `235t.5` | `P1-P9` |
| `235t.6` | `P1`, `P8`, `P9` |
| `235t.7` | `P2`, `P3`, `P4`, `P9` |
| `235t.8` | `P1`, `P2`, `P4`, `P9` |
| `235t.9` | `P2`, `P4`, `P5`, `P9` |
| `235t.10` | `P5`, `P6`, `P9` |
| `235t.11` | `P4`, `P6`, `P9` |
| `235t.12` | `P1`, `P3`, `P4`, `P9` |
| `235t.13` | `P2`, `P5`, `P6`, `P8`, `P9` |
| `235t.14` | `P1`, `P4`, `P6`, `P8`, `P9` |
| `235t.15` | `P1`, `P4`, `P6`, `P8`, `P9` |
| `235t.16` | `P1`, `P2`, `P4`, `P5`, `P6`, `P8`, `P9` |
| `235t.17` | `P1`, `P2`, `P4`, `P6`, `P8`, `P9` |
| `235t.18` | `P1`, `P2`, `P4`, `P5`, `P6`, `P8`, `P9` |
| `235t.19` | `P1`, `P4`, `P6`, `P8`, `P9` |
| `235t.20` | `P7`, `P3`, `P9` |
| `235t.21` | `P7`, `P2`, `P4`, `P9` |
| `235t.22` | `P7`, `P1`, `P2`, `P4`, `P9` |
| `235t.23` | `P7`, `P2`, `P3`, `P4`, `P9` |
| `235t.24` | `P1`, `P4`, `P7`, `P8`, `P9` |
| `235t.25` | `P7`, `P8`, `P9` |
| `235t.26` | `P8`, `P1`, `P4`, `P9` |
| `235t.27` | `P8`, `P9`, `P5`, `P6`, `P7` |
| `235t.28` | `P2`, `P3`, `P4`, `P5`, `P6`, `P7`, `P9` |
| `235t.29` | `P1-P9` |
| `235t.30` | `P5`, `P6`, `P7`, `P8`, `P9` |
| `235t.31` | `P1`, `P5`, `P6`, `P9` |
| `235t.32` | `P8`, `P9`, `P1` |
| `235t.33` | `P6`, `P8`, `P9` |
| `235t.34` | `P8`, `P9`, `P1`, `P4`, `P7` |

---

## 8. Migration Usage Rules

1. Every new migration PR must cite relevant row IDs (`P*`) in PR notes and bead comments.
2. Any new high-risk gap must be added to Section 6 with owner bead and checkpoint date.
3. Any temporary Tokio exception must link to:
   - this matrix row ID
   - the exception owner bead
   - explicit removal date

---

## 9. Dependency Surgery Plan (Delivered in `235t.5`)

This section defines the dependency-level migration policy used by guardrails and CI.

### 9.1 Forbidden Runtime Dependency Set

Direct workspace crate dependencies are forbidden by default unless exception-ledger approved:
- `tokio`
- `tokio-stream`
- `tokio-tungstenite`

### 9.2 Replacement Strategy by Dependency

| Dependency | Strategy | Target Surface | Owning Beads |
|---|---|---|---|
| `tokio` | Eliminate direct use via `fcp-async-core` substrate and crate-by-crate migration | Runtime bootstrap, spawn/supervision, channels, timers, cancellation | `235t.3`, `235t.4`, `235t.7-19`, `235t.21-24`, `235t.26` |
| `tokio-stream` | Replace with substrate stream abstractions or direct ASUPERSYNC stream primitives | Streaming/connectors and async test utilities | `235t.9`, `235t.10`, `235t.14-19`, `235t.26` |
| `tokio-tungstenite` | Adapter-first migration, then transport cutover per parity contracts | WebSocket/subscription/reconnect behavior | `235t.9`, `235t.10`, `235t.16-18`, `235t.31` |

### 9.3 Exception Ledger Contract

All temporary exceptions are stored in:
- `.config/asupersync/tokio_exception_ledger.json`
- `docs/ASUPERSYNC_Transport_Runtime_Replacement_Plan.md` (adapter debt register)

Each exception entry MUST include:
- `crate`
- `dependency`
- `owner_bead`
- `expires_on` (RFC3339 UTC)
- `reason`

Expired entries are a hard failure in both CI and local runs.

### 9.4 Local + CI Guardrail Commands

- Local:
  - `bash scripts/ci/asupersync_tokio_guard.sh`
- CI:
  - `.github/workflows/ci.yml` job `asupersync-guardrails`

Guardrail behavior:
1. Fail when forbidden direct dependency appears without active exception.
2. Fail when any exception is expired.
3. Fail when key Tokio source patterns exceed baseline caps.
