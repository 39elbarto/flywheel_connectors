# Mesh Cutover Gates Configuration

> Bead: `flywheel_connectors-hr0rr.2.1`

`fwc mesh cutover-gates --json` is the operator-facing guardrail for deciding
whether the Mesh-Native Architecture README row can graduate beyond
`STEADY-STATE TARGET (NOT YET OPERATIONAL)`. Graduation requires every gate to
be `green`. `skip` is not a failure, but it is not a pass.

## Defaults

The CLI uses these defaults when no host configuration is available:

| Setting | Default | CLI flag | Meaning |
|---------|---------|----------|---------|
| `min_connectors_with_mesh_replicas` | `3` | `--min-connectors` | Minimum connector count that must satisfy connector-level gates. |
| `min_replica_count` | `2` | `--replica-count` | Minimum mesh replica count per connector or state object. |
| `max_state_replication_staleness_secs` | `60` | `--state-staleness-seconds` | Maximum age for lifecycle state replication evidence. |
| `max_audit_checkpoint_staleness_secs` | `60` | `--audit-staleness-seconds` | Maximum age for audit quorum checkpoint evidence. |
| `min_policy_peer_count` | `2` | `--policy-peer-count` | Minimum mesh peers that must hold verified policy bundles. |

The `60s` staleness budget is four times the default `15s` gossip interval.
It is intentionally small enough to catch stalled replication while allowing
one missed gossip interval before a gate turns non-green.

## Host Config Shape

When fcp-host grows live cutover-gate telemetry, use this TOML shape:

```toml
[mesh.cutover_gates]
min_connectors_with_mesh_replicas = 3
min_replica_count = 2
max_state_replication_staleness_secs = 60
max_audit_checkpoint_staleness_secs = 60
min_policy_peer_count = 2

[mesh.cutover_gates.zone_overrides."z:owner"]
min_connectors_with_mesh_replicas = 1
max_state_replication_staleness_secs = 30

[mesh.cutover_gates.zone_overrides."z:community"]
min_connectors_with_mesh_replicas = 5
max_state_replication_staleness_secs = 120
```

Zone overrides exist because private owner zones and broad community zones have
different operational SLOs. A zone override may tighten or relax only the fields
that differ from the global defaults.

## Status Semantics

| Status | Meaning | README graduation impact |
|--------|---------|--------------------------|
| `green` | The predicate was evaluated from direct live telemetry and met its target. | Counts as a pass. |
| `red` | The predicate was evaluated from direct live telemetry and missed its target. | Blocks graduation. |
| `skip` | The predicate could not be evaluated because dependent live infrastructure or telemetry is unavailable. | Blocks graduation. |

The evaluator must not infer green from proxy signals such as README wording,
the presence of mesh crates, unit tests for mesh internals, or host-first status
without mesh placement and replication fields.

## Operator Commands

```bash
fwc mesh cutover-gates --json
fwc mesh cutover-gates --min-connectors 5 --replica-count 3 --json
fwc mesh explain-availability github --host "$FCP_HOST" --json
```

The JSON schema lives at
`crates/fwc/schemas/mesh_cutover_gates.schema.json`. Schema changes follow
semantic versioning: removing or renaming a field is a major version bump;
adding a field is a minor version bump.
