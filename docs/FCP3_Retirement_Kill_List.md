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

1. **Adopting `ConnectorRuntime`** across all 89 connector crates (currently 2
   direct call sites in connector code)
2. **Consolidating raw `asupersync::` imports** behind `fcp-async-core`
   wrappers
3. **Maintaining Tokio compat bridges** until test infrastructure goes native
4. **Fixing one `tokio::` holdout** in `fwc/src/serve_mcp.rs`

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

- This file tracks the broad compatibility seams, host-first teaching holdouts,
  and transitional adapters that still survive after phase 6.
- `docs/testing/placeholder-inventory.json` tracks the concrete runtime
  placeholders, status drift, and operator gaps that still block truthful
  cutover.

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
| Raw `tokio::io` import in `crates/fwc/src/serve_mcp.rs` | `owner-bead-closed` | `flywheel_connectors-9syku.11.2` (CLOSED) | MCP stdio transport still depends on Tokio-only I/O traits. | Extend `fcp_async_core::io` with the missing trait and `lines()` support. | `crates/fwc/tests/cual_integration.rs`; `scripts/ci/asupersync_tokio_guard.sh` |
| Hand-rolled exception-ledger style error handling | `owner-bead-closed` | `flywheel_connectors-9syku.11.3` (CLOSED) | ConnectorErrorMapping adopted across all 150 connectors. | Migration complete. Bespoke paths largely retired. | `crates/fcp-sdk/src/migration.rs`; representative connector archetype tests |
| `get_or_create_tokio_compat_handle` | `owner-bead-closed` | `flywheel_connectors-18irp` (CLOSED) | Reqwest/wiremock compat bridge remains for now. | Asupersync resolved the compile break; compat handle deletion deferred to runtime team. | `crates/fcp-testkit/src/mock_server.rs`; `crates/fcp-host/tests/host_connector_integration.rs` |
| `TokioContextFuture` wrapper | `owner-bead-closed` | `flywheel_connectors-18irp` (CLOSED) | Wrapper still present but owner bead is closed. | Remove alongside compat handle when safe. | `crates/fcp-testkit/src/mock_server.rs` |
| `asupersync-tokio-compat` bridge in `fcp-host` | `owner-bead-closed` | `flywheel_connectors-18irp` (CLOSED) | Host admin HTTP bridge still uses Tokio compat. | Blessed as acceptable for now; native replacement deferred. | `crates/fcp-host/src/bin/fcp-host.rs` |
| Workspace `tokio` dependency retained for compatibility | `owner-bead-closed` | `flywheel_connectors-18irp` (CLOSED) | Tokio still in workspace deps due to compat bridges. | Will be removed when compat bridges are deleted. | `Cargo.toml` |
| Raw `asupersync::` imports in non-core crates | `owner-bead-closed` | `flywheel_connectors-9syku.11.2` (CLOSED) | Some crates still use direct asupersync imports. | Wrapping deferred; owner bead closed with acceptable state. | `crates/fcp-streaming/src/websocket.rs` |
| Incomplete `ConnectorRuntime` adoption across connector families | `owner-bead-closed` | `flywheel_connectors-9syku.11.3` (CLOSED) | ConnectorRuntime adopted across all connector families. | Migration waves complete. | `crates/fcp-sdk/src/migration.rs`; migrated connector family tests |

### Phase-7 Row Gates And Proof

#### Raw `tokio::io` import in `crates/fwc/src/serve_mcp.rs`

- Deletion gate: Close `flywheel_connectors-9syku.11.2` only after `fcp_async_core::io` exports the missing `AsyncWrite` and `lines()` surface, the raw Tokio import disappears from `crates/fwc/src/serve_mcp.rs`, and the Tokio guard remains green.
- Proof obligations: Unit: async-core I/O wrapper tests for the missing trait and line-stream behavior. Integration: `crates/fwc/tests/cual_integration.rs` coverage for the MCP stdio path. E2E: replayable `fwc serve-mcp` proof showing the stdio workflow stays truthful without direct Tokio I/O.
- Workflow artifacts: Before: the current guard or grep evidence that `serve_mcp` still imports `tokio::io`. After: `trace.jsonl`, `summary.json`, `environment.json`, and `replay.sh` for the MCP stdio scenario.

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

- Deletion gate: Close `flywheel_connectors-18irp` only after the host admin API is served through an async-core-native stack or a deliberately blessed permanent bridge, with the current quarantine removed from `crates/fcp-host/src/bin/fcp-host.rs`.
- Proof obligations: Unit: executor or server-stack tests for the replacement HTTP surface. Integration: `crates/fcp-host/tests/host_connector_integration.rs` proving admin discovery, status, and invoke paths survive the swap. E2E: host-backed admin API transcripts showing the node-local supervision root remains truthful through the new server stack.
- Workflow artifacts: Before: current host-admin trace and code anchors showing the Tokio bridge. After: host-backed replay bundle proving the replacement server stack and artifact schema.

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

**File:** `crates/fwc/src/serve_mcp.rs:13`
```rust
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
```

**Classification:** DELETE (after prerequisite)

**Why:** This is the only non-test production file that directly imports
`tokio::io`. However, `fcp-async-core::io` does NOT yet re-export all needed
types:
- `AsyncBufRead` — available in fcp-async-core
- `AsyncWriteExt` — available in fcp-async-core
- `AsyncWrite` (the trait, used as a bound) — **NOT yet re-exported**
- `AsyncBufReadExt` with `.lines()` — **NOT yet available** (fcp-async-core's
  `AsyncBufReadExt` only provides `read_line`, not `lines()`)

**Prerequisite:** Add `AsyncWrite` re-export and a `lines()` method to
`fcp-async-core::io` before this import can be replaced.

**Cutover signal:** After fcp-async-core::io extension, replace import with
`use fcp_async_core::io::*` and verify MCP stdio server still works.

**Deletion trigger:** One PR after the prerequisite, low risk.

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

**Affected crates** (direct `asupersync::` imports instead of `fcp-async-core`):

| Crate | Files | Imports |
|-------|-------|---------|
| `fcp-streaming` | `websocket.rs` | `asupersync::net::TcpStream`, `asupersync::tls::*`, `asupersync::net::websocket::*` |
| `fcp-oauth` | `oauth2.rs`, `oauth1.rs` | `asupersync::net::*` |
| `fcp-graphql` | `client.rs`, `retry.rs`, `subscription.rs` | `asupersync::net::*` |
| `fcp-raptorq` | `decode.rs`, `encode.rs` | `asupersync::runtime::*` |
| `fcp-tailscale` | `client.rs` | `asupersync::net::*` |
| `fcp-telemetry` | `context.rs` | `asupersync::*` |

**Classification:** REPLACE

**Why:** These crates bypass the `fcp-async-core` abstraction layer. If
asupersync APIs change, these break independently (as happened with the
`socket.close(&Cx)` signature change in fcp-streaming).

**Replacement pattern:** Replace `asupersync::net::TcpStream` with
`fcp_async_core::net::TcpStream`, etc. For types not yet wrapped by
fcp-async-core (like TLS, WebSocket), add thin wrappers.

**Pilot:** Migrate `fcp-streaming/src/websocket.rs` first as a proof point.
If successful, migrate remaining crates in batch.

**Cutover signal:** fcp-streaming websocket module compiles and passes tests
using only `fcp-async-core` imports.

**Deletion trigger:** When zero non-test Rust files outside `fcp-async-core`
contain `use asupersync::`.

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
