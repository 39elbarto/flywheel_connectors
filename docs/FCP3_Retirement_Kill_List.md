# FCP3 Retirement Kill List

> Bead: `9syku.3.3` — [FCP3.KERNEL] Retirement plan for ExecutionContext,
> ConnectorRuntime, Tokio compat, and exception-ledger thinking.
>
> Author: BeigeCave (SunnyMoose) | Date: 2026-03-14
>
> Purpose: Explicit kill-list for every compatibility abstraction that should
> disappear rather than evolve, classified as **immediate delete**, **temporary
> quarantine**, or **replace-after-pilot**.
>
> Clarification: despite the bead title, `ExecutionContext` and
> `ConnectorRuntime` remain target FCP3 abstractions. The retirement targets are
> compatibility wrappers, holdouts, and exception-ledger habits around them.

---

## Executive Summary

The codebase has successfully migrated from Tokio to Asupersync via the
`fcp-async-core` abstraction layer. The infrastructure is mature and correct.
What remains is:

1. **Maintaining the last blessed compatibility seams** until their
   replacements are proven and the quarantine rows can be deleted
2. **Consolidating raw `asupersync::` imports** behind `fcp-async-core`
   wrappers
3. **Maintaining Tokio compat bridges** until test infrastructure goes native
4. **Capturing deletion proof** so Phase 7 can retire seams without losing
   operator-visible workflows

There is **no ExceptionLedger abstraction** in the codebase. The
"exception-ledger thinking" to retire is the pattern of hand-rolled,
per-connector error handling that `ConnectorErrorMapping` replaces.

---

## Classification Legend

| Tag | Meaning | Action |
|-----|---------|--------|
| **DELETE** | Remove immediately; no downstream users or easily replaced | Delete code, update imports |
| **QUARANTINE** | Keep temporarily; active users require migration first | Isolate in adapter module, set removal trigger |
| **REPLACE** | Keep until pilot proves replacement; then delete | Implement replacement, validate, then delete |

## Phase-7 Scoreboard Contract

Phase 7 treats this kill list plus `docs/testing/placeholder-inventory.json`
as one scoreboard.

- This file tracks the broad compatibility seams, runtime holdouts, and
  transitional adapters that still survive after phase 6.
- `docs/testing/placeholder-inventory.json` tracks the concrete runtime
  placeholders, status drift, and operator gaps that still block truthful
  cutover.
- The teaching-surface rewrite wave under `flywheel_connectors-z1nkz.1` is
  already closed. Any surviving host-first language referenced here should be
  read as a quarantined runtime constraint or proof obligation, not as the
  preferred architecture to teach.

Every surviving seam row must record:

- `current_status`
- `owner_bead`
- `user_visible_impact`
- `replacement_path`
- proof-artifact pointers
- `deletion_gate`
- `proof_obligations` broken out into unit, integration, and e2e evidence
- `workflow_artifacts` that preserve before/after operator-visible proof

### Current Non-Placeholder Seams

| Seam | Current status | Owner bead | User-visible impact | Replacement path | Proof artifacts |
|---|---|---|---|---|---|
| Raw `tokio::io` import in `crates/fwc/src/serve_mcp.rs` | `deleted` | `flywheel_connectors-9syku.11.2` (CLOSED) | Import removed. `fcp_async_core::io` now provides all needed traits. | Completed. No raw `tokio::` imports remain in `serve_mcp.rs`. | `grep -r 'tokio' crates/fwc/src/serve_mcp.rs` returns no matches |
| Hand-rolled exception-ledger style error handling | `deleted` | `flywheel_connectors-9syku.11.3` (CLOSED) | ConnectorErrorMapping adopted across all 150 connectors. | Migration complete. Bespoke paths retired. | `crates/fcp-sdk/src/migration.rs`; representative connector archetype tests |
| `get_or_create_tokio_compat_handle` | `quarantine-blessed` | `flywheel_connectors-18irp` (CLOSED) | Reqwest/wiremock compat bridge remains (blessed). | Stays until reqwest/wiremock replaced with async-core-native equivalents. | `crates/fcp-async-core/src/lib.rs`; `crates/fcp-testkit/src/mock_server.rs` |
| `TokioContextFuture` wrapper | `quarantine-blessed` | `flywheel_connectors-18irp` (CLOSED) | Coupled to compat handle (blessed). | Remove alongside compat handle when safe. | `crates/fcp-async-core/src/lib.rs` |
| `asupersync-tokio-compat` bridge in `fcp-host` | `deleted` | `flywheel_connectors-18irp` (CLOSED) | fcp-host fully migrated to native `fcp_async_core::hyper_bridge`. No tokio compat dependency remains. | Completed. fcp-host uses `HyperExecutor` and `HyperIo` natively. | `crates/fcp-host/src/bin/fcp-host.rs`; `crates/fcp-host/Cargo.toml` has no tokio/compat dep |
| Workspace `tokio` dependency retained for compatibility | `quarantine-blessed` | `flywheel_connectors-18irp` (CLOSED) | Tokio remains for: (1) compat handle in fcp-async-core, (2) fcp-registry-server binary (axum framework dep). | Remove when compat handle deleted and registry server migrated. | `Cargo.toml` |
| Raw `asupersync::` imports in non-core crates | `mostly-deleted` | `flywheel_connectors-9syku.11.2` (CLOSED) | Production code clean. Only `fcp-graphql/tests/client.rs` retains server-side WebSocket test types (`ServerWebSocket`, `WebSocketAcceptor`) not re-exported by fcp-async-core. | `Cx`, `AsyncRead`, `ReadBuf` migrated to `fcp_async_core::`. Server-side test types acceptable as direct import. | `grep -r 'use asupersync::' crates/` shows only fcp-async-core (expected) and fcp-graphql test server types |
| Incomplete `ConnectorRuntime` adoption across connector families | `deleted` | `flywheel_connectors-9syku.11.3` (CLOSED) | ConnectorRuntime adopted across all connector families. | Migration waves complete. | `crates/fcp-sdk/src/migration.rs`; migrated connector family tests |

### Phase-7 Row Gates And Proof

### Deletion-Wave Preservation Index

Use this index when reviewing the `flywheel_connectors-z1nkz` deletion family.
It maps the live seam rows in this file back to the corresponding deletion wave
and the preservation artifacts reviewers should inspect first.

| Deletion wave | What changed | First artifacts to inspect |
|---------------|--------------|----------------------------|
| `flywheel_connectors-z1nkz.1` | Repo docs stopped teaching host-first operation as the preferred architecture | README, `docs/OPERATIONAL_MODEL_VERSIONS.md`, `docs/FWC_Host_First_Truthfulness_Playbook.md`, `crates/fwc/docs/truthfulness-model.md` |
| `flywheel_connectors-z1nkz.2` | Runtime/control-plane seam rows moved from stale transition language to current `deleted` / `mostly-deleted` / `quarantine-blessed` states | The seam rows in this file, `docs/FCP3_Transition_Scorecard.md`, and the cited grep or crate-path evidence on each row |
| `flywheel_connectors-z1nkz.3` | Final workflow-preservation review bundle and handoff index | `docs/FCP3_Acceptance_Contracts.md`, `docs/FCP3_Pre_Cutover_Baseline.md`, and the scorecard’s deletion-wave status table |

#### Raw `tokio::io` import in `crates/fwc/src/serve_mcp.rs`

- **Status: DELETED.** The raw `tokio::io` import has been removed. `fcp_async_core::io` now provides `AsyncWrite`, `AsyncBufReadExt`, and all needed I/O traits. `serve_mcp.rs` no longer references `tokio` at all.
- Deletion gate: **CLEARED.** Owner bead `9syku.11.2` closed; import removed.
- Evidence: `grep -r 'tokio' crates/fwc/src/serve_mcp.rs` returns no matches.

#### Hand-rolled exception-ledger style error handling

- Deletion gate: Close `flywheel_connectors-9syku.11.3` only after the remaining connector families migrate onto `ConnectorErrorMapping` and `RetryLoop`, and the bespoke retry or error-translation seams no longer appear in shipping connector paths.
- Proof obligations: Unit: `fcp-sdk` migration contract tests that pin the shared error taxonomy. Integration: representative migrated connector-family tests proving the shared mapping is used on real request paths. E2E: connector transcripts showing retries, timeout handling, and FCP error shaping come from the shared runtime contract.
- Workflow artifacts: Before: code or transcript evidence of bespoke error handling on the affected archetype. After: migrated connector proof bundles and transcripts showing one shared runtime/error model.

#### `get_or_create_tokio_compat_handle`

- Deletion gate: Close `flywheel_connectors-18irp` only after reqwest and wiremock compatibility no longer need a hidden Tokio runtime and the compat handle can be deleted from `fcp-async-core` entirely.
- Proof obligations: Unit: async-core runtime tests proving task spawn and block-on remain correct without entering Tokio context. Integration: `crates/fcp-testkit/src/mock_server.rs` and `crates/fcp-host/tests/host_connector_integration.rs` coverage proving the remaining HTTP/mock surfaces work natively. E2E: host-backed connector verification showing no hidden Tokio runtime is required.
- Workflow artifacts: Before: runtime traces or documentation that the compat handle is still entered. After: host-backed proof artifacts showing the same flows operate without the quarantined Tokio bridge.

#### `TokioContextFuture` wrapper

- Deletion gate: Close `flywheel_connectors-18irp` only after spawned tasks stop entering Tokio context during polling and the wrapper can be removed alongside the compat handle.
- Proof obligations: Unit: async-core spawn and cancellation tests proving polling stays correct without Tokio context injection. Integration: mock-server and host integration tests proving reqwest or wiremock callers survive the cutover. E2E: connector or host transcripts showing the same workflows run without Tokio-context scaffolding.
- Workflow artifacts: Before: runtime traces demonstrating Tokio-context polling. After: cutover artifacts proving the polling path is native and the quarantined wrapper is gone.

#### `asupersync-tokio-compat` bridge in `fcp-host`

- **Status: DELETED.** `fcp-host` has been fully migrated to native `fcp_async_core::hyper_bridge`. The binary uses `HyperExecutor` and `HyperIo` for connection serving, `fcp_async_core::net::TcpListener` for binding, and `fcp_async_core::signal::ctrl_c()` for shutdown. No `asupersync-tokio-compat` dependency remains in `fcp-host/Cargo.toml`.
- Deletion gate: **CLEARED.** Owner bead `18irp` closed; compat bridge deleted; native bridge proven.
- Evidence: `crates/fcp-host/Cargo.toml` has no tokio or compat dependency; `crates/fcp-host/src/bin/fcp-host.rs` uses only `fcp_async_core::*` imports (plus `hyper`/`hyper_util` which are runtime-agnostic).

#### Workspace `tokio` dependency retained for compatibility

- Deletion gate: Remove the workspace `tokio` dependency only after the three quarantined seams above are deleted or formally reclassified as permanent infrastructure with explicit proof.
- Proof obligations: Unit: dependency or guard tests proving no production or test-critical path still imports Tokio through the workspace surface. Integration: guard-script coverage in `scripts/ci/asupersync_tokio_guard.sh`. E2E: representative host and connector proof bundles showing the workspace still operates with Tokio absent from the dependency surface.
- Workflow artifacts: Before: current dependency graph and guard-script output showing Tokio still present. After: updated graph or guard output plus replayable host or connector bundles proving the cutover held.

#### Raw `asupersync::` imports in non-core crates

- Deletion gate: Close `flywheel_connectors-9syku.11.2` only after the remaining crates consume async-core wrappers instead of direct upstream imports and the `fcp-streaming` pilot proves the boundary is mechanically stable.
- Proof obligations: Unit: wrapper coverage for each newly exposed async-core type. Integration: targeted crate-local tests for `fcp-streaming`, `fcp-oauth`, `fcp-graphql`, `fcp-raptorq`, `fcp-tailscale`, and `fcp-telemetry` proving the wrapper layer is sufficient. E2E: representative streaming or operator transcripts showing runtime behavior is unchanged while the abstraction boundary tightens.
- Workflow artifacts: Before: import-surface inventory or grep output proving direct `asupersync::` usage. After: updated import-surface proof plus crate-local and workflow-level transcripts showing the wrapped surface in action.

#### Incomplete `ConnectorRuntime` adoption across connector families

- Deletion gate: Close `flywheel_connectors-9syku.11.3` only after request-response, streaming, and stateful connector families all run through `ConnectorRuntime` and the old per-connector lifecycle glue is deleted.
- Proof obligations: Unit: `fcp-sdk` runtime and migration tests proving lifecycle, cancellation, deadline, and retry semantics. Integration: migrated connector-family tests for request-response, streaming, and stateful connectors. E2E: connector transcripts or bundles proving the shared runtime contract is the only operator-visible lifecycle path left.
- Workflow artifacts: Before: scaffold or connector-family evidence of bespoke lifecycle glue. After: migrated family transcripts and proof bundles showing one shared runtime surface across connectors.

---

## 1. Abstractions to KEEP (Not on kill list)

These are the FCP3 target patterns. They stay and expand:

| Abstraction | Location | Why it stays |
|---|---|---|
| `ExecutionContext` | `fcp-async-core:485` | Core deadline/cancellation model for FCP3 |
| `ConnectorRuntime` | `fcp-sdk/migration.rs:213` | Target pattern for all connector lifecycle |
| `RetryLoop` | `fcp-sdk/migration.rs:388` | Replaces hand-rolled retry loops |
| `ConnectorErrorMapping` | `fcp-sdk/migration.rs:351` | Centralizes HTTP status → FCP error mapping |
| `CancellationToken` | `fcp-async-core:1898` | Cooperative shutdown primitive |
| `Deadline` | `fcp-async-core:427` | Deterministic timeout enforcement |
| `fcp-async-core` channels/sync/io | `fcp-async-core:603+` | Complete async primitive layer |
| `#[fcp_async_core::runtime::test]` | `fcp-async-core-macros` | Standard test attribute |

---

## 2. IMMEDIATE DELETE

### 2.1 Raw `tokio::` imports in `fwc/src/serve_mcp.rs`

**Status: DELETED.** The raw `tokio::io` import has been removed from
`serve_mcp.rs`. `fcp-async-core::io` now provides all needed I/O traits
including `AsyncWrite`, `AsyncBufReadExt`, and `lines()` support.

**Evidence:** `grep -r 'tokio' crates/fwc/src/serve_mcp.rs` returns no matches.

### 2.2 Exception-ledger thinking (hand-rolled error handling)

**Pattern:** Each connector independently maps HTTP status codes, constructs
`FcpError` variants, and implements retry logic with bespoke backoff.

**Classification:** DELETE (the pattern, not the code — replace with
`ConnectorErrorMapping` trait)

**Why:** `fcp-sdk/migration.rs` provides:
- `ConnectorErrorMapping` trait for per-connector error translation
- `classify_http_status()` for standard HTTP → FCP mapping
- `map_async_to_fcp_error()` for AsyncError normalization
- `RetryLoop::execute()` for unified retry with tracing

**Cutover signal:** Each connector batch migration (9syku.11.3.1/2/3) replaces
hand-rolled error handling with the trait. When all connectors implement
`ConnectorErrorMapping`, delete the old patterns.

**Deletion trigger:** Connector archetype migration waves complete (9syku.11.3.x).

---

## 3. TEMPORARY QUARANTINE

### 3.1 Tokio compat handle (`get_or_create_tokio_compat_handle`)

**File:** `crates/fcp-async-core/src/lib.rs:106-161`

**What it does:** Lazily creates a single-threaded Tokio runtime on a dedicated
background thread. Thread-locally cached. Entered during `Runtime::block_on()`
and `task::spawn()`.

**Classification:** QUARANTINE

**Why needed:** `wiremock` and `reqwest` call `tokio::runtime::Handle::current()`
internally. Without the compat handle, these panic on asupersync threads.

**Quarantine boundary:**
- Confined to `fcp-async-core/src/lib.rs` (internal implementation detail)
- Never exposed in public API
- Only active when tokio-dependent code paths are used

**Removal criteria:**
1. `reqwest` replaced with asupersync-native HTTP client, OR
2. `wiremock` replaced with asupersync-native mock server, OR
3. Both dependencies eliminated from non-connector crates

**Removal trigger:** When `tokio` can be removed from `fcp-async-core`'s
`Cargo.toml` without any test or production code breaking.

### 3.2 `TokioContextFuture` wrapper

**File:** `crates/fcp-async-core/src/lib.rs:1786-1850`

**What it does:** Wraps every spawned task to enter the Tokio runtime context
before each poll. Ensures reqwest/wiremock work on asupersync worker threads.

**Classification:** QUARANTINE (coupled to 3.1)

**Quarantine boundary:** Internal to `task::spawn()` — caller never sees it.

**Removal criteria:** Same as 3.1. When the Tokio compat handle is removed,
this wrapper becomes a no-op and can be deleted.

### 3.3 `asupersync-tokio-compat` crate dependency

**File:** `crates/fcp-host/Cargo.toml:20`
```toml
asupersync-tokio-compat = { path = "/dp/asupersync/asupersync-tokio-compat",
                            features = ["tokio-io", "hyper-bridge"] }
```

**What it provides:**
- `hyper_bridge::AsupersyncExecutor` — Hyper executor on asupersync
- `io::TokioIo` — I/O adapter for hyper connections

**Classification:** QUARANTINE

**Why needed:** `fcp-host` runs an HTTP admin API via `hyper`. Hyper requires
a `tokio::runtime::Handle` or a compatible executor.

**Quarantine boundary:** Used only in `fcp-host/src/bin/fcp-host.rs`.

**Removal criteria:**
1. Hyper gains native asupersync support, OR
2. fcp-host HTTP server replaced with asupersync-native HTTP framework, OR
3. NobleDuck's 18irp migration produces a permanent bridge that is blessed
   as production infrastructure (reclassify from quarantine to keep)

**Removal trigger:** Decision on HTTP server stack in FCP3 era.

### 3.4 `tokio` workspace dependency

**File:** Root `Cargo.toml`
```toml
tokio = { version = "1", default-features = false, features = ["rt"] }
```

**Classification:** QUARANTINE

**Why retained:** Required by 3.1, 3.2, and 3.3 above.

**Removal criteria:** All three quarantined items above are deleted.

**Removal trigger:** Last transitive consumer of tokio in workspace is removed.

---

## 4. REPLACE AFTER PILOT

### 4.1 Raw `asupersync::` imports in non-core crates

**Status: MOSTLY DELETED.** Production code no longer contains raw
`asupersync::` imports outside `fcp-async-core`. The only remaining direct
import is in `fcp-graphql/tests/client.rs` for server-side WebSocket test
types (`ServerWebSocket`, `WebSocketAcceptor`) which are not re-exported by
`fcp-async-core` because they are test-infrastructure-only.

**Evidence:** `grep -r 'use asupersync::' crates/ --include='*.rs'` returns
only `fcp-async-core/src/lib.rs` (expected) and `fcp-graphql/tests/client.rs`
(acceptable test infrastructure).

**Remaining:** The `fcp-graphql` test file's `Cx`, `AsyncRead`, and `ReadBuf`
imports were migrated to `fcp_async_core::` equivalents in z1nkz.2. Only
`ServerWebSocket` and `WebSocketAcceptor` remain as direct imports because they
are server-side test types not part of fcp-async-core's public surface.

### 4.2 89 connector crates → ConnectorRuntime adoption

**Current state:** `ConnectorRuntime::new` currently appears in 2 direct
connector call sites, so the repo is still in the early pattern-proving phase.

**Classification:** REPLACE

**Target pattern** (from `fcp-sdk/migration.rs`):
```rust
// In configure():
self.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig {
    request_timeout: Duration::from_secs(120),
    shutdown_timeout: Duration::from_secs(30),
}));

// In invoke():
let ctx = self.runtime.as_ref().unwrap().request_context();
ctx.run(async { /* operation */ }).await
```

**Migration order** (per bead 9syku.11.3.x):
1. **Wave 1 (9syku.11.3.1):** Request-response connectors — fastest wins,
   clearest pattern (REST/GraphQL APIs)
2. **Wave 2 (9syku.11.3.2):** Streaming connectors — WebSocket/SSE, need
   background context
3. **Wave 3 (9syku.11.3.3):** Polling/webhook/stateful — most complex lifecycle

**Pilot:** Pick 3 representative request-response connectors (e.g., `anthropic`,
`openai`, `sendgrid`), migrate them, measure code deletion.

**Cutover signal:** Pilot connectors pass all existing tests with
`ConnectorRuntime`, zero hand-rolled retry/timeout code remains.

**Deletion trigger:** All 89 connector crates migrated. Delete old lifecycle
patterns from connector scaffold template (`fwc new_cmd.rs`).

#### Current migration snapshot (2026-03-14)

Repository scan after the first two archetype batches:

- `ConnectorRuntime::new` appears in **2** connector call sites.
- `RetryLoop::execute` appears in **4** connector call sites.
- `impl ConnectorErrorMapping` exists in **87/87** connector error modules (100%).
- All connectors have `fcp-sdk` as a dependency.
- Remaining migration: adopt `ConnectorRuntime` lifecycle and `RetryLoop` in
  connectors that still use hand-rolled retry (the `ConnectorErrorMapping` trait
  is the prerequisite foundation, now universally in place).

That means the current work is still in the pattern-proving phase, not the
"mass migration complete" phase. The goal of bead `9syku.11.3` is therefore to
keep the next batches explicit: which family moves next, what proof is required,
and which compatibility seams should disappear immediately afterward.

#### Connector-family wave matrix (operational plan for `9syku.11.3`)

| Wave | Status | Proven batch / repo evidence | Next connector families to pull forward | Proof required before expanding the batch | Deletions unlocked |
|---|---|---|---|---|---|
| **1. Request-response / operational-heavy** | **Closed (pattern proven)** | `9syku.11.3.1` closed with `anthropic`, `openai`, and `sendgrid`; the repo now has real `ConnectorRuntime`, `RetryLoop`, and `ConnectorErrorMapping` examples instead of only framework helpers. | Pure operational or operational+knowledge connectors that do not own long-lived sessions: `mailchimp`, `segment`, `zapier`, `llm-router`, `browser`, `make`, `retool`, `pulumi`, `n8n`, plus similar REST/GraphQL APIs. | Unit coverage for success/retry/terminal/deadline/cancel, host-backed integration, and replayable E2E or transcript evidence that the new path matches the previous connector contract. | Delete hand-rolled retry loops, bespoke timeout bookkeeping, and per-connector `AsyncError` conversion code as each connector lands. |
| **2. Streaming / bidirectional / long-lived transport** | **In progress** | `9syku.11.3.2` is the active wave. Declared streaming families already visible in manifests include `slack`, `discord`, `github`, `linear`, `stripe`, and `google-calendar`; hybrid operational+streaming connectors such as `anthropic` also constrain the shared pattern. | Start with the smallest transport surface that still proves reconnect/backpressure/drain, then expand to `slack`, `discord`, `github`, and `linear`; only then pull in the more hybrid streaming surfaces. | Every migrated connector must prove backpressure, cancellation, reconnect, drain, restart, and recovery behavior with detailed logs and replay instructions. "It compiles" is not enough for this wave. | Delete bespoke websocket/SSE loops, detached task ownership, and connector-local reconnect glue once the shared FCP3 transport pattern is proven. |
| **3. Polling / webhook / singleton-writer stateful** | **Closed as initial batch; more families remain** | `9syku.11.3.3` closed after the `notion` and `sentry` batch, proving the first reusable stateful migration slice. This does **not** mean every cursor/webhook connector is done; it means the batch-level pattern now exists. | Remaining cursor, lease, and webhook-heavy connectors should follow the same pattern: `gmail`, `telegram`, `webhook-receiver`, `cron`, `homeassistant`, and other connectors with explicit background state or delivery lifecycles. | Durable-state, failover, drain, retry, idempotency, and receipt behavior must be demonstrated under host-backed tests and replayable scenarios before each family batch is declared done. | Delete ad-hoc polling supervisors, file-based lifecycle glue, and webhook-specific retry plumbing after each family migrates onto the shared runtime/evidence model. |

#### Batch expansion rules

1. A wave closes when the reusable migration pattern is proven, not only when a
   single connector compiles.
2. Closing a wave does **not** imply every connector in that family is already
   migrated; it means later connectors in the family should now reuse the same
   proof and deletion checklist.
3. No later wave should expand while its predecessor still lacks a stable
   evidence contract. Request-response proves `ConnectorRuntime` and retry/error
   mapping; streaming proves long-lived transport semantics; stateful proves
   durable-state and lease behavior.
4. Every batch must name the compatibility code it expects to delete. If the
   batch cannot say what dies when it lands, the migration scope is too vague.
5. Documentation and operator playbooks must track the same wave status so the
   repo never teaches a "mixed forever" connector story.

---

## 5. NOT FOUND (Confirmed Absent)

These items were searched for but do not exist:

| Pattern | Search result |
|---------|---------------|
| `ExceptionLedger` / `exception_ledger` | Not found — no error ledger abstraction exists |
| Direct `tokio::spawn` in production code | Not found — all use `fcp_async_core::task::spawn` |
| `block_on` outside runtime init | Not found — hidden in macro expansions |
| `tokio::select!` | Not found — all use `fcp_async_core::select!` |
| Raw `&Cx` parameter patterns | Not found — abstracted by `compatibility_cx()` |

---

## 6. Cutover Signal Summary

| # | Signal | Triggers deletion of |
|---|--------|---------------------|
| S1 | `serve_mcp.rs` uses `fcp_async_core::io` | Raw tokio::io import (2.1) |
| S2 | All connectors implement `ConnectorErrorMapping` | Hand-rolled error handling (2.2) |
| S3 | reqwest/wiremock replaced OR eliminated | Tokio compat handle (3.1, 3.2, 3.4) |
| S4 | HTTP server stack decision made | asupersync-tokio-compat (3.3) |
| S5 | fcp-streaming pilot succeeds | Raw asupersync imports (4.1) |
| S6 | All 89 connector crates use ConnectorRuntime | Old lifecycle patterns (4.2) |

---

## 7. Dependency Graph

```
18irp (ASUPERSYNC migration, NobleDuck)
  └─> This document (9syku.3.3, kill-list)
        └─> 9syku.11.2 (remove reqwest/Tokio/compat holdouts)
              ├─> 9syku.11.3 (bulk connector migration)
              │     ├─> 9syku.11.3.1 (request-response wave)
              │     ├─> 9syku.11.3.2 (streaming wave)
              │     └─> 9syku.11.3.3 (polling/webhook wave)
              └─> 9syku.12 (documentation alignment)
```

---

## 8. Verification Evidence

### Audit methodology
- `grep -r "ExecutionContext"` across all crates
- `grep -r "ConnectorRuntime"` across all crates
- `grep -r "use tokio::"` in non-connector, non-test code
- `grep -r "exception_ledger\|ExceptionLedger"` workspace-wide
- `grep -r "use asupersync::"` in non-fcp-async-core crates
- `grep -r "reqwest::"` in core crates
- Manual review of `fcp-async-core/src/lib.rs` (4000+ lines)
- Manual review of `fcp-sdk/src/migration.rs` (connector migration framework)

### Test validation
- `cargo test -p fcp-core --lib pcs` — 50 tests pass
- `cargo test -p fcp-mongodb` — 39 tests pass
- `cargo test -p fcp-sendgrid` — 38 tests pass
- `cargo check -p fcp-streaming` — compiles after `close(&Cx)` fix
- `cargo clippy -p fcp-core --all-targets` — zero warnings
