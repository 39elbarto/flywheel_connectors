# HLC Audit Entries and HierVV Revocation Freshness

Status: partially implemented under `flywheel_connectors-angoc.17.3`.

This note describes the shipped HLC and hierarchical version-vector behavior for
audit chains and mesh revocation freshness. It is a design contract for the code
in `fcp-audit`, `fcp-host`, and `fcp-mesh`; it is not a claim that the remaining
mesh registry persistence item is complete.

## Goals

- Every audit-chain entry carries a causal timestamp that survives wall-clock
  skew and participates in canonical entry identity.
- Revocation freshness decisions use causal frontier dominance instead of
  receiver wall-clock order.
- Parent zone frontiers can compactly dominate child-zone frontiers, so large
  zone subtrees do not require one counter per child when their revocation state
  is uniform.
- Replays or older revocation pushes must not downgrade local revocation state.

## Audit HLC

`fcp-audit` exposes `HybridLogicalTimestamp` and `HybridLogicalClock` from
`crates/fcp-audit/src/hlc.rs`.

`AuditEntry` has a serialized `hlc` field. New entries should provide a causal
HLC when one is available. Legacy construction paths that only have the existing
Unix-seconds `occurred_at` value use `audit_entry_hlc_from_occurred_at`, which
maps seconds to milliseconds and uses the actor as the default node id.

The HLC participates in the canonical audit-entry id material through
`AuditEntryIdFields`. Changing only the HLC changes the computed entry id. This
keeps causal order part of the signed/hash-linked audit payload rather than a
side-channel attribute.

`fcp-host::invoke_audit` stores the last HLC per zone chain. On append:

1. The requested wall-clock timestamp is clamped to non-decreasing seconds for
   compatibility with existing chain verification.
2. `next_audit_hlc` merges the previous per-zone HLC with the current physical
   milliseconds.
3. The computed id and materialized `AuditEntry` both include that HLC.
4. Optimistic CAS and serialized fallback paths update the same per-zone HLC
   state after a successful append.

This means equal or backwards wall-clock samples still produce strictly
advancing HLCs in same-zone commit order.

When the requested wall-clock timestamp moves backwards for a same-zone audit
chain, `fcp-host::invoke_audit` keeps the append valid by clamping the entry's
`occurred_at` to the previous chain timestamp and advancing the HLC logical
counter. The entry metadata is annotated with:

- `alert = "clock_anomaly"`
- `clock_anomaly = true`
- `clock_anomaly_kind = "wall_clock_regressed"`
- requested, previous, clamped, and skew second fields

The chain metrics increment `clock_anomalies`, and a structured warning is
emitted under target `fcp.audit.clock_anomaly` with the same timing fields plus
the entry id, zone id, and actor.

## HierVV Revocation Freshness

`fcp-mesh` exposes `HierarchicalVersionVector`,
`RevocationFreshnessFrontier`, `RevocationFreshnessDecision`, and
`RevocationFreshnessAction` from `crates/fcp-mesh/src/revocation/hier_vv.rs`.

A vector entry is keyed by a zone-like scope such as `z:work` or
`z:work:team-a`. A child scope inherits the nearest ancestor counter when it has
no explicit counter. For example, `z:work = 10` is fresh enough for
`z:work:team-a` unless the child has an explicit newer independent counter.

The partial order is:

- `equal`: neither frontier is newer.
- `dominates`: the incoming frontier is at least as fresh for every compared
  scope and newer for at least one.
- `dominated_by`: local state already dominates the incoming frontier.
- `concurrent`: each side is newer for at least one independent scope.

`RevocationFreshnessFrontier::observe` accepts `equal`, `dominates`, and
`concurrent` updates. It rejects only `dominated_by`, preserving local state.
Accepted updates merge by keeping the maximum effective counter for each
explicit scope in either vector.

## Mesh Priority Push Path

`MeshNode::handle_revocation_push` verifies the peer signature, zone-owner
signature, and peer zone authorization before evaluating HierVV freshness.
It then compares the incoming push frontier, represented by
`push.zone_id -> push.new_rev_seq`, with the node's local
`RevocationFreshnessFrontier`.

If the incoming frontier is dominated by local state, the node returns
`MeshNodeError::StaleRevocationFrontier` and does not increment gossip metrics
or mutate the local frontier. Otherwise, the normal gossip timestamp freshness
window still applies, and accepted pushes merge into the local frontier.

The path emits a debug event under target `fcp.mesh.revocation.freshness` with
at least:

- `hier_vv_status`
- `decision`
- `zone_id`
- `incoming_seq`
- `local_seq`

The same path records a histogram named
`fcp.mesh.revocation.hiervv_size_bytes` with labels `zone`,
`hier_vv_status`, and `decision` after accepted updates and dominated
rejections. This gives operators per-zone visibility into frontier growth
without relying on wall-clock freshness decisions.

Structured runtime OTLP promotion for these mesh metrics remains follow-up work.

## Invariants

- HLC values are part of the audit-entry canonical id and serialized payload.
- Same-zone audit appends advance HLC even when physical seconds are equal or
  clamped.
- A parent revocation frontier can dominate child frontiers.
- A dominated revocation push cannot downgrade local frontier state.
- Equal revocation pushes are accepted as idempotent replays.
- Concurrent revocation frontiers are accepted and merged instead of being
  rejected as stale by wall-clock order.

## Verification

Focused proof lanes for the current implementation:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc173-hiervv-target-20260516 CARGO_INCREMENTAL=0 cargo test -p fcp-audit --test hlc_monotonic -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc173-hiervv-target-20260516 CARGO_INCREMENTAL=0 cargo test -p fcp-mesh --test hier_vv -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc173-hiervv-target-20260516 CARGO_INCREMENTAL=0 cargo test -p fcp-mesh --lib handle_revocation_push -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc173-clock-target-20260516 CARGO_INCREMENTAL=0 cargo test -p fcp-host --lib invoke_audit_chain_clock_step_back -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc173-hiervv-target-20260516 CARGO_INCREMENTAL=0 cargo test -p fcp-conformance --test hlc_hiervv_conformance -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-angoc173-hiervv-target-20260516 CARGO_INCREMENTAL=0 cargo clippy -p fcp-mesh --lib --no-deps -- -D warnings
rch exec -- cargo fmt -p fcp-audit -p fcp-mesh -p fcp-host -p fcp-conformance --check
```

## Remaining Work

- Persist or reconcile the mesh revocation frontier beyond the current
  in-memory `MeshNode` priority-push path where the registry owner needs it.
