# Computation Migration Cost Model

Status: planner + deterministic five-device conformance surface for
`flywheel_connectors-angoc.4.3`.

The mesh planner exposes an explainable computation-migration placement model through
`fcp_mesh::planner::DeviceCostModel`. Callers attach live observations with
`PlannerInput::with_compute_migration_costs(...)`; when present, `ExecutionPlanner`
keeps the existing hard-constraint filters and then ranks eligible candidates by
lower weighted cost. The decision emits a `CostExplanation` containing every
ranked candidate's `CostBreakdown` plus the winning `NodeId`.

## Formula

Each raw input is normalized to `[0.0, 1.0]` before weighting:

```text
cost(d) =
  w_latency * norm(latency_ms_p50, 2000ms)
  + w_network * norm(network_lat_ms, 500ms)
  + w_mem * mem_pressure
  + w_cpu * cpu_load
  + w_energy * norm(energy_w, 100W)
  + w_derp * norm(derp_hop_count, 5 hops)
```

Default weights:

| Component | Weight | Reason |
| --- | ---: | --- |
| `latency_ms_p50` | 0.25 | Keeps observed operation latency load-bearing. |
| `network_lat_ms` | 0.20 | Prefers local/LAN placement when compute pressure is equal. |
| `mem_pressure` | 0.20 | Avoids checkpoint restore onto memory-constrained nodes. |
| `cpu_load` | 0.20 | Avoids overloaded execution targets. |
| `energy_w` | 0.10 | Breaks ties toward lower-power devices. |
| `derp_hop_count` | 0.05 | Penalizes relay paths without dominating compute health. |

The ranking is deterministic: candidates sort by `total_cost` ascending and then
by `NodeId` string for exact ties.

## Proven Coverage

- `crates/fcp-mesh/tests/cost_model_monotonicity.rs` covers monotonicity for
  legacy device-cost inputs plus computation-migration latency, memory pressure,
  and CPU load.
- `crates/fcp-conformance/tests/computation_migration_5device_e2e.rs` builds a
  deterministic five-device topology (`local-fast`, `local-busy`,
  `lan-balanced`, `lan-slow`, `derp-relay`) and verifies 50 sample operations
  route to the lowest-cost eligible device while preserving output bytes.
- The same conformance test asserts that placement evidence serializes the full
  `compute_migration_cost` ranking with all five candidates and the selected
  winner.
- Inline planner tests verify that cost observations do not bypass hard
  connector eligibility constraints and that the rollback override classifier
  disables the cost model only for `0`, `false`, and `off`.

## Rollback

The existing deterministic `ExecutionPlanner` ranking remains intact when no
compute-migration observations are supplied. Operators can also disable the
reranker with `FCP_COMPUTE_MIGRATION_COST_MODEL=0`, `false`, or `off`; hard
constraints continue to run either way. The deterministic five-device
conformance harness is local and hermetic; a future live multi-machine soak can
reuse the same evidence contract when physical devices are available.
