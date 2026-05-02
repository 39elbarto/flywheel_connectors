# /deadlock-finder-and-fixer audit — 2026-05-02

**Auditor:** AmberLark.
**Scope:** Alpha domain (`fcp-policy`, `fcp-host`, `fcp-mesh`) + spot
extension into `fcp-async-core` + `fcp-store`.
**Trigger:** User invocation while cod panes were rate-limited until
08:53; cc-bandwidth productive use.

## Summary

| Category | Count | Disposition |
| -------- | ----: | ----------- |
| (a) Confirmed deadlock — needs fix | 0 | None — no production deadlock found |
| (b) Lock-ordering risk worth documenting | 1 | Bead `utiw3` filed (audit-only) |
| (c) False positive (initial flag → cleared on inspection) | several | See §3 |
| Already-tested deadlock paths (skipped) | 1 | symbol_store nested-lock stress test (br-13fb51d4a) |

**Headline:** Zero category-(a) findings. The async + sync lock
discipline in the alpha crates is genuinely tight. The single
category-(b) finding is an existing intentional pattern with bounded
hold time and explicit code comments; the bead documents *why* it
deserves a future hardening pass without claiming it's broken today.

## 1. Audit method

Five sweep types per crate:

1. **Lock acquisition pairs.** `rg "(Mutex|RwLock)::new\("` per crate
   to enumerate state-bearing structs; cross-checked each `.lock()` /
   `.read()` / `.write()` site for two-lock overlap with another
   field of the same struct.
2. **Async-mutex held across await.** Manual inspection of every
   `lock().await` / `read().await` / `write().await` for whether a
   subsequent `await` is performed before the guard is dropped.
3. **`.recv().await` loops.** All `recv().await` patterns checked for
   sender-drop bound vs unbounded wait. Also checked for accompanying
   `timeout()` wrappers on companion `.send()`.
4. **`Drop` impls.** All `impl Drop for ... {` enumerated; bodies
   checked for lock acquisition that could deadlock against the same
   struct's regular methods.
5. **Cross-task channel cycles.** `oneshot::channel()` /
   `mpsc::channel()` paths checked for the request-side awaiting a
   reply that the receiver-side may never send.

Cross-cut tools:

```sh
rg -n "(Mutex|RwLock)::new\(" --type=rust crates/<C>/src
rg -n "\.lock\(\)|\.read\(\)|\.write\(\)" --type=rust crates/<C>/src
rg -n "\.recv\(\)\.await" --type=rust crates/<C>/src
rg -n "impl Drop for" --type=rust crates/<C>/src
rg -n "oneshot::channel|mpsc::channel" --type=rust crates/<C>/src
```

## 2. Per-crate findings

### 2.1 `fcp-policy/src` — clean

**Lock count:** 0. The crate is purely functional / type-state; all
state is passed through `&mut self` or `&self` borrows. No locks
means no lock-ordering deadlocks possible.

### 2.2 `fcp-host/src` — 1 (b) finding

| File:line | Pattern | Verdict |
| --------- | ------- | ------- |
| `bin/fcp-host.rs:383` | async Mutex held across two awaits in `rpc_in_handshaken_zone` | **(b)** Filed bead `utiw3`. Detail in §4. |
| `admin_state.rs:2820` | `apply_mutation`: persist_lock → state.read → drop → state.write | (c) Single ordering, well-documented |
| `budget.rs:362-393` | Inner-scope `policies.read()` drop before `tracker.lock()` | (c) Strict order, never overlap |
| `cancellation.rs:159, 232` | `operations.lock()` (inner scope) then `audit_log.lock()` after drop | (c) Never overlap |
| `rollout.rs:336-366` | Single `state.lock()` in inner scope; `records: RwLock` is on a SEPARATE test fixture struct | (c) No cross-struct interaction |
| `discovery.rs:1322-1369` | Read cache → drop → registry.list().await → write cache | (c) Cache-stampede possible (perf, not deadlock) |
| `resilience.rs:945-966` | Read-then-write TOCTOU via `entry().or_insert_with()` | (c) Standard-pattern; safe |
| `progress.rs`, `invoke_audit.rs`, `supply_chain.rs` | Single-lock structs | (c) No two-lock pattern possible |
| `supervisor.rs:1063 (Drop)` | `ConnectionGuard::drop` does `fetch_sub` only | (c) No lock taken in Drop |
| `bin/fcp-host.rs:276+` | 9 `runner_rx.recv().await` loops | (c) All bounded by sender drop; sender side is `runner_tx.send()` wrapped in `timeout()` and `oneshot::recv()` wrapped in `timeout()` (line 309 + 327) |

**Concentration risk:** All host locks are `fcp_async_core::sync::Mutex`
/ `RwLock` (asupersync wrappers around tokio-style async primitives).
None are `tokio::sync::*` direct or `std::sync::*` held across `.await`
— the host crate enforces the async-mutex discipline uniformly.

### 2.3 `fcp-mesh/src` — clean

| File:line | Pattern | Verdict |
| --------- | ------- | ------- |
| `gossip.rs:313, 385, 437` | `built: Mutex<Option<Xor8>>` — `contains()` calls `ensure_built()` BEFORE acquiring its own lock | (c) Single lock, no recursion. PoisonError swallowed via `if let Ok(...)` — defensive pattern, could mask poisoning but not a deadlock |
| `degraded.rs:980, 1079` | `state: std::sync::Mutex<InMemoryReplayState>` with explicit `drop(state)` at 1100 | (c) Single lock, bounded hold |

### 2.4 `fcp-async-core/src` (spot extension) — clean

The `sync` module at `lib.rs:1680` re-exports asupersync wrappers as
the workspace's canonical `Mutex` / `RwLock`. No internal multi-lock
state — the wrapper structs hold a single `inner` field each.

### 2.5 `fcp-store/src` (spot extension) — 1 prior-tested risk

| File:line | Pattern | Verdict |
| --------- | ------- | ------- |
| `symbol_store.rs:313-329, 437-617, 620-636` | THREE locks: `objects: RwLock<HashMap<_, RwLock<_>>>`, `used_bytes: RwLock<u64>`, `coverage_scan_hook: Mutex<...>`. Two patterns coexist: (A) drop outer before taking `used_bytes`, (B) hold `objects` + per-object + `used_bytes` nested. | (c) — both patterns observe the SAME global lock order (`objects` < `obj_lock` < `used_bytes`); no path takes `used_bytes` first. Already covered by stress test landed in `13fb51d4a test(fcp-store): stress symbol store nested locks` per project memory. **Skipped per audit instruction.** |
| `durable.rs:692, 694, 861, 863` | `state` + `write_guard` Mutex pairs (two flavours: tokio + parking_lot) | Not deeply audited; out of scope for this round |
| `object_store.rs:390, 391` | `objects: RwLock` + `zone_index: RwLock` | Not deeply audited; out of scope for this round |

## 3. False-positive sources (worth knowing for next audit)

1. **Test fixtures with locks.** `fcp-host/src/batch.rs:1164,2142,2342,
   2475` use `std::sync::Mutex::new(Vec::new())` to capture call order
   in tests — flagged by the lock-construction grep but irrelevant.
2. **Test-only Mock structs with locks.** `fcp-host/src/bin/
   fcp-test-connector.rs:462,910,928,946` — `handshake_count` Mutex
   inside a test connector binary. Not production state.
3. **Multiple lock fields on the same struct that are never co-acquired.**
   `cancellation.rs` has `operations` + `audit_log` Mutexes; manual
   inspection of every call site confirms they are taken in non-overlapping
   inner scopes.
4. **`if let Ok(...)` on PoisonError.** Common defensive pattern in
   `gossip.rs` — silently bypasses a poisoned lock rather than panicking.
   Not a deadlock, but worth a separate audit pass for poisoning
   recoverability if/when scheduled.

## 4. The single (b) finding

### `utiw3` — `rpc_in_handshaken_zone` lock-held-across-await

**File:** `crates/fcp-host/src/bin/fcp-host.rs:365-420`.

**Pattern:**

```rust
let mut handshaken_zone = self.handshaken_zone.lock().await;          // L383
if handshaken_zone.as_ref() != Some(zone) {
    // ...build handshake request...
    let response: HandshakeResponse = serde_json::from_value(
        self.rpc("handshake", handshake_params).await?,               // L401 — await #1
    )?;
    // ...response checks...
    *handshaken_zone = Some(zone.clone());
}
self.rpc(method, params).await                                        // L419 — await #2
```

**Why intentional:** the comment block at lines 376-382 explains the
race that happens if the lock drops between handshake and first RPC —
a cross-zone caller could re-handshake the connector and invalidate
the earlier session. This is the documented fix for `br-j1pjg`.

**Why bounded:** `self.rpc()` wraps both `runner_tx.send` (line 309)
and the `oneshot::recv` (line 327) in
`fcp_async_core::time::timeout(CONNECTOR_RPC_IO_TIMEOUT, ...)`. Worst-
case lock-hold time = 2 × `CONNECTOR_RPC_IO_TIMEOUT`.

**Why audit-only:** today's call graph contains no recursion from
`rpc()` back into `rpc_in_handshaken_zone()` for the same connector,
so the non-reentrant async Mutex never gets re-acquired by the same
task. If a future change introduces such recursion (e.g. a connector
callback that tunnels through a meta-RPC), the second acquisition
will deadlock.

**Recommended hardening (see bead `utiw3` for full text):**

1. Debug-only assertion in `self.rpc()` that the current task is not
   already inside `rpc_in_handshaken_zone` for this connector.
2. A 30s structured-trace span to surface tuning regressions if the
   lock starts blocking under load.
3. (Most invasive) replace the per-connector Mutex with an enum-state
   RwLock (`Idle | Handshaking | Bound(zone)`) so concurrent same-zone
   RPCs can fan out without serialising on the Mutex.

## 5. Why so few findings

The alpha crates already exhibit four hardening practices that
together account for the clean audit result:

1. **Async-mutex discipline is universal.** Every `.lock()` /
   `.read()` / `.write()` is `.await`-ed via `fcp_async_core::sync`.
   No `std::sync::Mutex` is held across an `.await`. The single
   `std::sync` Mutex usage in `fcp-mesh/src/degraded.rs` is acquired
   inside synchronous code and explicitly `drop()`-ed.
2. **Inner-scope drops over explicit `drop()`.** The dominant
   pattern is `let read = lock.read().await; ...use it...; }` with the
   guard going out of scope before the next lock is acquired. This
   makes lock-overlap auditable from the structure alone.
3. **`oneshot` + `mpsc` always wrapped in `timeout()`.** Every
   request-reply pattern has timeouts on BOTH the send and the recv,
   so a dropped responder never wedges the requester indefinitely.
4. **Single-state-bearing struct per concern.** Most state is co-
   located in one struct with one lock; even where multiple fields
   exist (admin_state.rs has `state: RwLock` + `persist_lock: Mutex`),
   only ONE call site acquires both, eliminating opposite-order risk
   by construction.

## 6. Recommendations

1. **Repeat this audit every quarter.** The asupersync abstraction
   layer absorbs a lot of the deadlock risk surface; if it ever changes
   (e.g. switches its underlying Mutex to a non-yielding implementation
   or introduces reentrancy), the entire alpha layer's safety
   characteristics shift. A regular sweep catches drift early.
2. **Add a CI lint for async-mutex held across await.** `clippy`'s
   `await_holding_lock` lint detects the std-mutex variant; for the
   asupersync wrappers, a custom `dylint` pass over `*.rs` files in
   alpha crates that flags any `await` between `(Mutex|RwLock)::lock|
   read|write().await` and the guard going out of scope would catch
   regressions automatically.
3. **Prioritise the `utiw3` hardening (debug-assert + trace-span)
   when an unrelated change modifies `bin/fcp-host.rs` near the
   `rpc_in_handshaken_zone` function.** No need for a dedicated PR —
   piggyback on the next host-binary touch.
4. **Sweep `fcp-store/src/durable.rs` + `object_store.rs`
   independently next round.** The store crate has more lock-bearing
   structs than I audited fully here; the symbol-store stress test
   covers one of them but not all.

## 7. Provenance

- Audit run: 2026-05-02 by AmberLark via `/deadlock-finder-and-fixer`
  user invocation (cod panes rate-limited until 08:53).
- Beads filed: `utiw3` (P3, audit-only, lock-ordering risk).
- Code edits: none (no fixes required for category-(b) findings per
  audit-only protocol).
- Highest-priority (a) fix: skipped because no (a) finding exists.
- MCP Agent Mail file reservation: not used (no patches landed).
