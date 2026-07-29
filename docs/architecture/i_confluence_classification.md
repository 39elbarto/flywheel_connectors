# I-CONFLUENCE Operation Classification

Bead: `flywheel_connectors-angoc.11.1` (Phase Q.C)

Every connector operation gets a `coordination_class` declaring how
the mesh-native invoke transport (Phase A.bis) must coordinate the
dispatch. Three classes exist:

| Class | Coordination | Operational shape |
|---|---|---|
| `IConfluent` | none (Bailis et al. 2014 I-CONFLUENCE) | read-only or commutative; safe to execute on any peer without coordination |
| `RequiresQuorum` | quorum round | mutating; needs a quorum of peers to acknowledge before dispatch returns |
| `RequiresFencing` | HRW lease + fencing token | exclusive-write; the lease holder is the unique writer; concurrent attempts get fenced |

This is the heart of the bridge plan's Phase Q.C alien-graveyard
accretion: classify which operations can SKIP coordination entirely
(I-confluent reads are the common case), which need quorum, and which
need exclusive leases. Without this classification, every mesh
dispatch pays the quorum-round cost regardless of whether it's a
trivial GET.

## Component layout

```
crates/fcp-protocol/src/operation_info.rs  (CoordinationClass enum + field)
crates/fcp-manifest/src/                    (manifest schema extension)
crates/fcp-mesh/src/dispatch.rs             (MeshInvokeTransport consumes the field)
crates/fcp-conformance/tests/i_confluence_operation_classification.rs
crates/fcp-e2e/tests/i_confluent_dispatch_throughput_e2e.rs
crates/fcp-conformance/tests/fixtures/i_confluence/  (golden classification table)
docs/architecture/i_confluence_classification.md  (THIS FILE)
```

## CoordinationClass enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationClass {
    IConfluent,
    RequiresQuorum,
    RequiresFencing,
}

impl OperationInfo {
    pub fn coordination_class(&self) -> CoordinationClass;
}
```

Wire shape (manifest TOML):

```toml
[operations.list_charges]
description = "List all charges (read-only)"
coordination_class = "i_confluent"
side_effects = false

[operations.create_charge]
description = "Create a new charge"
coordination_class = "requires_quorum"
side_effects = true

[operations.refund_charge]
description = "Refund a charge by id (must serialize per charge)"
coordination_class = "requires_fencing"
side_effects = true
```

## Classification rubric

For every operation, the connector author classifies:

| Heuristic | Class |
|---|---|
| `side_effects = false` AND operation name matches `^(get\|list\|read\|count\|describe\|head\|fetch\|search\|introspect)` | `IConfluent` |
| `side_effects = true` AND `idempotency_class = "strict"` AND operation has no concurrent-write conflict semantics | `RequiresQuorum` |
| `side_effects = true` AND (per-resource serialization required OR exclusive-write semantics) | `RequiresFencing` |

The classification rubric is the LOAD-BEARING decision: a misclassified
I-confluent op that actually mutates is a correctness bug. The
conformance test below enforces the rubric mechanically.

## Conformance rules

`crates/fcp-conformance/tests/i_confluence_operation_classification.rs`
asserts (in addition to the named tests in the bead body):

1. **No I-confluent + side-effects=true**: any manifest with
   `coordination_class = "i_confluent"` AND `side_effects = true` is
   a configuration error. This is the rubric's primary safety gate.
2. **Every op has a class**: every `[operations.*]` block in every
   connector manifest must declare `coordination_class`. Default-on
   strict (no fall-through to RequiresQuorum) prevents silent
   misclassification when a new op is added without explicit thought.
3. **Read-shaped ops are i-confluent**: ops whose name matches
   `^(get|list|read|count|describe|head|fetch|search|introspect)`
   MUST be classified `i_confluent`. (Operators that genuinely have
   side-effects in a read-named op must rename it.)
4. **Introspect surfaces the class**: a connector's `introspect`
   response includes `coordination_class` per op.

## Dispatch routing in fcp-mesh

`crates/fcp-mesh/src/dispatch.rs::MeshInvokeTransport` reads the
class and routes:

```
match op_info.coordination_class() {
    CoordinationClass::IConfluent => {
        // Pick any peer holding the connector lease; no quorum round.
        let peer = lease_table.any_peer_for(connector_id)?;
        dispatch_direct(peer, request).await
    }
    CoordinationClass::RequiresQuorum => {
        // Standard quorum round: pick t-of-n peers, dispatch parallel,
        // commit when t replies match.
        let quorum_set = lease_table.quorum_set_for(connector_id, threshold)?;
        dispatch_with_quorum(quorum_set, request).await
    }
    CoordinationClass::RequiresFencing => {
        // Exclusive: take the HRW lease for (connector_id, resource_key),
        // dispatch only on the holder. Concurrent attempts get fenced
        // by lease.epoch comparison.
        let holder = lease_table.hrw_lease(connector_id, request.resource_key())?;
        dispatch_with_fencing(holder, request).await
    }
}
```

The `FCP_FORCE_QUORUM_ALL=1` operator env var forces every dispatch
through the `RequiresQuorum` path regardless of classification — a
panic-button for emergency rollback when a classification turns out
to be wrong in production.

## Performance expectation

The bead body asserts 3× throughput for I-confluent reads vs.
forced-quorum dispatch on a synthetic 1000-op 50%-read workload. The
end-to-end test:

```rust
#[fcp_async_core::runtime::test]
async fn iconfluent_read_3x_throughput_vs_quorum() {
    let workload = synthetic_workload(1000, 0.5 /* read ratio */);

    // (a) Force every op through RequiresQuorum.
    std::env::set_var("FCP_FORCE_QUORUM_ALL", "1");
    let elapsed_quorum = run_workload(&workload).await;
    std::env::remove_var("FCP_FORCE_QUORUM_ALL");

    // (b) Classify reads as IConfluent.
    let elapsed_classified = run_workload(&workload).await;

    let throughput_quorum = workload.len() as f64 / elapsed_quorum.as_secs_f64();
    let throughput_classified = workload.len() as f64 / elapsed_classified.as_secs_f64();

    assert!(
        throughput_classified >= 3.0 * throughput_quorum,
        "I-confluent classification must yield ≥3× throughput; \
         classified={throughput_classified:.1}/s vs forced-quorum={throughput_quorum:.1}/s"
    );
}
```

The 3× target is conservative: a synthetic 50%-read workload with
quorum threshold 3-of-5 and direct dispatch should yield ~5× in
practice. The conformance test uses 3× as the budget so noise doesn't
falsely fail CI.

## Rollback path

A misclassified I-confluent op that actually mutates is a silent
correctness bug. Mitigations (in order of operator response speed):

1. **Build-time gate**: the no-i-confluent-with-side-effects=true
   conformance test prevents the manifest from declaring this
   contradiction.
2. **Runtime audit flag**: audit-chain entries for I-confluent ops
   carry a `coordination_class: "i_confluent"` field. The audit
   explorer (`fwc audit explain --kind i_confluent`) surfaces them.
3. **Emergency override**: `FCP_FORCE_QUORUM_ALL=1` forces every
   dispatch through RequiresQuorum. Restart the host with this env
   set; all subsequent dispatch is conservative.

The failure-injection test
`test_force_quorum_env_overrides` asserts the env var actually does
override every dispatch even for I-confluent-classified ops.

## OTLP / observability

| Attribute | Value |
|---|---|
| `fcp.mesh.dispatch.connector` | connector slug |
| `fcp.mesh.dispatch.operation` | operation id |
| `fcp.mesh.dispatch.coordination_class` | `i_confluent` / `requires_quorum` / `requires_fencing` |
| `fcp.mesh.dispatch.peer_count` | 1 for I-confluent, t for quorum, 1 for fencing |
| `fcp.mesh.dispatch.latency_ms` | total dispatch latency |
| `fcp.mesh.dispatch.quorum_round_skipped` | bool — true iff classification skipped the round |

## Cross-references

- `crates/fcp-protocol/src/operation_info.rs` — extends `OperationInfo` (deferred to `angoc.11.1.1`)
- `crates/fcp-mesh/src/dispatch.rs` — MeshInvokeTransport routing (deferred)
- `crates/fcp-conformance/tests/fixtures/i_confluence/operation_classification.json` — golden classification table for the 4 rubric tests (this commit)
- Bailis et al. 2014, "Coordination Avoidance in Database Systems" — the foundational paper for I-CONFLUENCE
- Phase A.bis (angoc.17) — the mesh accretions that consume this classification
- `OperationInfo.idempotency_class` (existing field) — the related-but-distinct property of "can this op be retried safely without re-execution side-effects"

## Deferred Rust implementation

Filed as `angoc.11.1.1`. The runtime work needs:

1. Extend `OperationInfo` in `fcp-protocol` with the field + default-strict serde derive
2. Extend the manifest schema in `fcp-manifest`
3. Route `MeshInvokeTransport` in `fcp-mesh` (this is the load-bearing change)
4. Classify every operation in every of the 176 connector manifests (mechanical)
5. Conformance test + 3× throughput E2E

Estimated 8-12h once the writer has a clean working tree.
