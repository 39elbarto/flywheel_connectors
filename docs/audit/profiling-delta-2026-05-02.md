# Delta Profiling Audit - 2026-05-02

Scope: `fcp-streaming`, `fcp-webhook`, `fcp-graphql`, and `fcp-oauth`.

Method: static hot-path review using the `profiling-software-performance` workflow. The pass focused on subscription processing, webhook delivery, GraphQL execution and subscription receive loops, OAuth token/state paths, per-request allocations/clones, lock contention, backpressure behavior, and algorithmic complexity. No runtime profiler baseline was collected in this sweep; findings below are limited to code paths with direct evidence or missing benchmark coverage.

## Findings Filed

| Bead | Crate | Classification | Summary |
| --- | --- | --- | --- |
| `flywheel_connectors-gqpn5` | `fcp-streaming` | confirmed-hotspot-needs-fix | SSE parsing rescans retained buffers from byte 0 under chunked long lines, making split-line inputs quadratic before the buffer cap. |
| `flywheel_connectors-7j7fa` | `fcp-webhook` | confirmed-hotspot-needs-fix | Webhook delivery routing does per-delivery IP `to_string()` allocation and O(subscriptions * matched_handlers) duplicate detection. |
| `flywheel_connectors-0q8eh` | `fcp-graphql` | confirmed-hotspot-needs-fix | GraphQL subscription socket reader awaits a bounded result channel send, so slow consumers can block ping/pong/close handling. |
| `flywheel_connectors-p36a0` | `fcp-oauth` | confirmed-hotspot-needs-fix | OAuth single-flight refresh waiters spin/yield while one task performs a network refresh, creating avoidable scheduler churn under contention. |
| `flywheel_connectors-a4uf2` | all four | benches-missing-add-coverage | Delta crates have no crate-local benchmark targets for SSE parse, webhook routing/HMAC, GraphQL execution/subscription limits, or OAuth token refresh/state lookup hot paths. |

`br sync --flush-only` was run after each bead create.

## Evidence

### fcp-streaming

`crates/fcp-streaming/src/sse.rs` keeps a retained `BytesMut` and appends each input chunk before repeatedly calling `find_line_end`. The helper scans `self.buffer.iter().enumerate()` from byte 0 each time. A long SSE field split across many chunks with no newline therefore causes repeated scans of the same retained prefix until the newline or size limit arrives.

The parser also converts each complete line through `String::from_utf8_lossy`, copies field values into `String`s, and joins multi-line data fields. Those copies are expected for the current owned event API, but the rescanning behavior is an algorithmic hotspot and should be fixed before deeper allocation tuning.

### fcp-webhook

`crates/fcp-webhook/src/handler.rs` checks IP allowlists by building `ip.to_string()` for each checked delivery. The same file routes events by scanning every subscription and calling `handlers.contains(&handler)` before pushing, making duplicate suppression O(n) per match.

`crates/fcp-webhook/src/event.rs` also scans subscription patterns for every event. Pattern scanning is expected, but the router should avoid making duplicate handler checks quadratic when many subscriptions map to overlapping handlers.

### fcp-graphql

`crates/fcp-graphql/src/subscription.rs` creates a fixed `mpsc::channel(16)` and runs websocket receive, control-frame handling, JSON parse, and result delivery in one spawned task. For `next` messages, the task awaits `tx.send(Ok(response))`. If the consumer is slow and the result channel fills, the reader cannot continue handling ping, pong, close, or subsequent protocol messages until the consumer drains the channel.

`crates/fcp-graphql/src/operation.rs` now enforces query size, depth, alias, and root-field limits before execution. Its tokenizer allocates a token vector, but the query-size guard bounds that work to 64 KiB, so this was not filed as a separate hotspot.

### fcp-oauth

`crates/fcp-oauth/src/token.rs` implements token refresh single-flight. The acquiring task performs the refresh, while losers loop on `gate.refreshing.load(Ordering::Acquire)` and `yield_now().await`. That preserves correctness, but under a delayed provider refresh every concurrent waiter wakes and rechecks until the network operation completes.

The same token store returns cloned owned token structures from read APIs. That may be worth revisiting in a later API design pass, but it was not filed because the current ownership contract makes those clones expected and there is no benchmark evidence that they dominate the hot path.

## False Positives

- `fcp-graphql` query-limit token allocation is linear and bounded by the max query size, so benchmark coverage is enough for now.
- `fcp-webhook` `WebhookEvent::header` lowercases keys during lookup, but provider verification hot paths use direct case-insensitive header helpers instead.
- `fcp-webhook` `DeadLetterQueue::all` clones the retained queue, but that is an operator inspection path rather than per-delivery processing.
- `fcp-oauth` `TokenStore::get` and `get_with_metadata` clone owned token state by API contract; no standalone bead without measurement.
- `fcp-streaming` `BatchStream` carries a `Clone` bound, but the current batching implementation does not clone each item on the hot path.

## Quick-Win Patch Decision

No inline quick-win patch was applied. The obvious webhook allowlist allocation cleanup overlaps dirty local webhook files from other work, and the GraphQL subscription and OAuth waiter findings require small design changes rather than safe mechanical edits. The filed beads include acceptance criteria for targeted fixes and benchmark coverage.
