# ASUPERSYNC Transport/Runtime Replacement Plan (Tokio-Coupled Dependencies)

> **Status**: NORMATIVE migration planning artifact  
> **Date**: 2026-02-28  
> **Owner Bead**: `flywheel_connectors-235t.31`  
> **Program Epic**: `flywheel_connectors-235t`

---

## 1. Goal

Define a dependency-by-dependency replacement plan for Tokio-coupled runtime and transport surfaces, with explicit behavior-equivalence criteria and time-bounded adapter debt.

This artifact closes the "TBD transport/runtime" gap before crate-level migration beads proceed.

---

## 2. Baseline Evidence Snapshot (2026-02-28)

Evidence sources:
- `cargo metadata --format-version 1 --no-deps`
- Source scan probes (`rg`) for timeout/retry/cancellation/process/runtime primitives

Current coupling highlights:
- `reqwest` is used across runtime-critical crates and connectors (`fcp-graphql`, `fcp-streaming`, `fcp-oauth`, `fcp-sdk`, `fcp-testkit`, `fcp-tailscale`, `fcp-e2e`, connectors `anthropic/openai/discord/telegram/twitter/vectordb`).
- `tokio-stream` is present in runtime/connector surfaces (`fcp-core`, `fcp-streaming`, `fcp-graphql`, `fcp-testkit`, connectors `anthropic/openai/discord/telegram/twitter`).
- `tokio-tungstenite` is concentrated in WebSocket surfaces (`fcp-streaming`, `fcp-graphql`, `fcp-discord`).
- `tokio::process` is currently in host/e2e subprocess orchestration (`crates/fcp-host/src/bin/fcp-host.rs`, `crates/fcp-e2e/src/subprocess.rs`).

Representative hotspot files:
- `crates/fcp-streaming/src/websocket.rs`
- `crates/fcp-graphql/src/subscription.rs`
- `connectors/discord/src/gateway.rs`
- `connectors/anthropic/src/client.rs`
- `connectors/openai/src/client.rs`
- `connectors/telegram/src/client.rs`
- `connectors/twitter/src/client.rs`

---

## 3. Dependency-by-Dependency Migration Plan

| Surface ID | Current Coupling | Replacement Strategy | Required Behavior Equivalence | Owning Beads |
|---|---|---|---|---|
| `TR-HTTP-REQWEST` | `reqwest::Client` in connector/GraphQL/OAuth/Tailscale paths | Introduce `fcp_async_core::http` adapter facade. Phase A wraps `reqwest`; Phase B swaps internal transport to ASUPERSYNC-native client. | Preserve timeout defaults, retryability classification (`is_timeout`, `is_connect`, HTTP 429/5xx), `Retry-After` handling, TLS profile semantics. | `235t.11`, `235t.10`, `235t.14-19`, `235t.31` |
| `TR-WS-TUNGSTENITE` | `tokio-tungstenite` in streaming + subscriptions + discord gateway | Keep WebSocket behavior behind `fcp_async_core::ws` facade. Preserve existing framing and reconnect semantics first, then internal transport swap. | Preserve connect timeout behavior, ping/pong handling, close semantics, reconnect backoff policy, message ordering guarantees. | `235t.9`, `235t.10`, `235t.16-18`, `235t.31` |
| `TR-STREAM-TOKIOSTREAM` | `tokio_stream::Stream` usage in streaming connectors and GraphQL | Replace public/internal stream boundaries with substrate stream trait aliases and receiver adapters. | Preserve stream item ordering, termination semantics (`complete`/`error`), and backpressure behavior. | `235t.9`, `235t.10`, `235t.14-19`, `235t.26`, `235t.31` |
| `TR-PROC-TOKIOPROCESS` | `tokio::process::{Command, Child...}` for host/e2e subprocess runners | Introduce `fcp_async_core::process` wrapper exposing spawn/request/terminate contract. | Preserve JSONL IPC semantics, stderr capture behavior, timeout/cancellation around subprocess lifecycle, deterministic shutdown ordering. | `235t.8`, `235t.26`, `235t.31` |
| `TR-TIME-TOKIO` | `tokio::time::{sleep, timeout, interval}` in retry/reconnect paths | Route all timer/deadline behavior through `fcp_async_core::time` APIs. | Preserve relative delays, absolute deadline behavior, and interval cadence behavior under cancellation storms. | `235t.4`, `235t.7-12`, `235t.14-23`, `235t.31` |
| `TR-SYNC-TOKIO` | `tokio::sync::{mpsc,watch,broadcast,oneshot}` in sdk/streaming/connectors | Replace with `fcp_async_core::queue` and substrate channel contracts. | Preserve queue capacity/overflow semantics, shutdown signal semantics, and bounded memory behavior. | `235t.3`, `235t.7-13`, `235t.26`, `235t.31` |
| `TR-TASK-TOKIO` | `tokio::spawn` and `tokio::select!` control flow | Replace with substrate task/supervisor + select/race abstractions. | Preserve cancellation edges, failure propagation, and supervisor restart policy behavior. | `235t.3`, `235t.4`, `235t.7-13`, `235t.31` |

No runtime-critical primitive remains without an owner path in this plan.

---

## 4. API Compatibility Strategy (Mechanical Criteria)

Every adapter/replacement PR in this track must attach these equivalence checks:

1. `EQ-TIMEOUT-001`: timeout/deadline behavior unchanged for success, timeout, and cancellation paths.
2. `EQ-RETRY-001`: retry decision logic unchanged for transport vs API errors (including 429 + `Retry-After` behavior).
3. `EQ-CANCEL-001`: cancellation leaves no orphan tasks/processes and preserves deterministic terminal state.
4. `EQ-ERROR-001`: error taxonomy mapping remains stable (connector-visible and CLI-visible reason classes).
5. `EQ-CLEANUP-001`: resource cleanup order unchanged (ingress stop -> in-flight drain -> worker/process termination -> final flush).

These equivalence checks are mandatory links in bead comments and PR notes for all affected beads.

---

## 5. Adapter Debt Register (Owner + Trigger + Expiry)

All temporary adapter debt below is hard-expiring and must be removed or explicitly renewed before expiration.

| Adapter ID | Temporary Adapter | Owner Bead | Removal Trigger | Expires On (UTC) |
|---|---|---|---|---|
| `AD-HTTP-REQWEST` | `fcp_async_core::http` wraps `reqwest` internally | `235t.11` | `235t.11` complete and `PAR-RUNTIME-004` + `PAR-TIMEOUT-001` evidence green for affected crates | 2026-03-21T00:00:00Z |
| `AD-WS-TUNGSTENITE` | `fcp_async_core::ws` wraps `tokio-tungstenite` internals | `235t.9` | `235t.9` and `235t.10` complete with `PAR-STREAM-001/002/003` evidence | 2026-03-21T00:00:00Z |
| `AD-STREAM-TOKIOSTREAM` | Stream compatibility wrapper around `tokio-stream` adapters | `235t.10` | `235t.10` and connector wave beads (`235t.14-19`) complete with stream parity evidence | 2026-03-21T00:00:00Z |
| `AD-PROC-TOKIOPROCESS` | Subprocess wrapper around `tokio::process` | `235t.8` | `235t.8` and `235t.26` complete with deterministic shutdown evidence | 2026-03-21T00:00:00Z |
| `AD-TIME-TOKIO` | `fcp_async_core::time` temporarily delegates to Tokio timers | `235t.4` | `235t.4` complete and cancellation/deadline equivalence checks pass | 2026-03-21T00:00:00Z |
| `AD-SYNC-TOKIO` | Substrate queue/channel adapters still backed by Tokio sync primitives | `235t.3` | `235t.3` complete and bounded queue invariants validated | 2026-03-21T00:00:00Z |
| `AD-TASK-TOKIO` | Substrate task adapter still backed by `tokio::spawn/select` | `235t.3` | `235t.3` + `235t.4` complete with no orphaned task test evidence | 2026-03-21T00:00:00Z |

This register is mirrored operationally in `.config/asupersync/tokio_exception_ledger.json`.

---

## 6. No-Unresolved-Blockers Checklist

Before any migration bead depending on `235t.31` is closed:

1. The bead references one or more `TR-*` rows from Section 3.
2. Any temporary adapter introduced is added to Section 5 and the ledger.
3. `EQ-*` criteria are linked to concrete evidence artifacts.
4. No "TBD transport/runtime" text remains in PR/bead notes.

---

## 7. Validation Commands (Policy + Evidence)

Run the guardrail and migration checks with offloaded cargo commands where possible:

```bash
# Tokio guardrail policy (local/CI parity)
bash scripts/ci/asupersync_tokio_guard.sh

# Standard workspace gates (offload through rch)
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

If `rch` fails open in a given window, keep the `rch exec -- ...` invocation but record fallback behavior in bead/migration logs.
