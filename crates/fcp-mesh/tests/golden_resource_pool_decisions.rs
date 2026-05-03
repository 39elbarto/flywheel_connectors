//! Golden vector for fcp-mesh planner resource-pool decisions
//! (br-evxvv.3, commits 9ba0c5a40 + 64b0e9510).
//!
//! Freezes the per-node admission decision (admitted vs rejected with
//! refusal-reason taxonomy) AND the aggregated ResourcePoolDecisionSummary
//! for a fixed matrix of canonical topologies. This pins the operator-
//! readable summary that downstream tooling (admission-rejection
//! dashboards, evidence bundles attached to placement decisions) reads
//! off the planner.
//!
//! Matrix:
//!   - single_node_admitted             — pool has headroom on both axes
//!   - single_node_no_matching_pool     — pool absent for node+class+zone
//!   - single_node_cpu_exhausted        — pool CPU usage exceeds capacity
//!     after admission
//!   - single_node_memory_exhausted     — pool memory usage exceeds floor
//!   - mixed_4_nodes_one_per_outcome    — 4 nodes, one admitted + one of
//!     each refusal type (verifies summary aggregation arithmetic)
//!
//! Each row pins:
//!   - per-node decision (admitted/rejected + refusal_reason class)
//!   - aggregated summary (evaluated, admitted, rejected, plus refusal
//!     buckets)
//!
//! The summary aggregation arithmetic (admitted + rejected == evaluated;
//! sum of refusal-bucket counts <= rejected) is invariant under refactor;
//! this golden catches any drift between the per-node verdicts and the
//! summary counts. Pre-fix the summary was added in 9ba0c5a40 with one
//! happy-path test; this file extends coverage to every refusal type
//! and the cross-product 4-node case.
//!
//! Update flow:
//!   UPDATE_GOLDENS=1 cargo test -p fcp-mesh --test golden_resource_pool_decisions
//!   cargo insta review
//!   git diff crates/fcp-mesh/tests/snapshots/

use fcp_mesh::device::{
    AvailabilityProfile, DeviceProfile, InstalledConnector, LatencyClass, PowerSource,
};
use fcp_mesh::planner::{
    ExecutionPlanner, NodeInfo, PlannerContext, PlannerInput, ResourcePoolClass,
    ResourcePoolDecision, ResourcePoolDecisionSummary, ResourcePoolRefusalReason,
    ResourcePoolStatus,
};
use fcp_prelude::{ConnectorId, ObjectId, ZoneId};
use fcp_tailscale::NodeId;

fn connector_id() -> ConnectorId {
    ConnectorId::new("fcp", "test", "1.0.0").expect("valid connector id")
}

fn node_id(suffix: &str) -> NodeId {
    NodeId::new(format!("node-{suffix}"))
}

fn make_node(suffix: &str, memory_mb: u32, zones: Vec<ZoneId>) -> NodeInfo {
    let connector = InstalledConnector::new(
        connector_id(),
        "1.0.0",
        ObjectId::from_bytes([0xAA; 32]),
    );
    let profile = DeviceProfile::builder(node_id(suffix))
        .memory_mb(memory_mb)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .add_connector(connector)
        .build();

    NodeInfo {
        profile,
        local_symbols: Default::default(),
        held_leases: Vec::new(),
        zones,
    }
}

/// Render one decision in a stable shape: node id + admitted-or-class.
fn render_decision(decision: &ResourcePoolDecision) -> String {
    let label = if decision.admitted {
        "ADMIT".to_string()
    } else {
        match decision.refusal.as_ref() {
            Some(ResourcePoolRefusalReason::NoMatchingPool { .. }) => {
                "REJECT class=no_matching_pool".to_string()
            }
            Some(ResourcePoolRefusalReason::CpuExhausted { .. }) => {
                "REJECT class=cpu_exhausted".to_string()
            }
            Some(ResourcePoolRefusalReason::MemoryExhausted { .. }) => {
                "REJECT class=memory_exhausted".to_string()
            }
            None => "REJECT class=none".to_string(),
        }
    };
    format!("    {:<32} | {label}", decision.node_id.as_str())
}

fn render_summary(summary: &ResourcePoolDecisionSummary) -> String {
    let bucket_total = summary
        .no_matching_pool
        .saturating_add(summary.cpu_exhausted)
        .saturating_add(summary.memory_exhausted);
    let bucket_check = if bucket_total == summary.rejected {
        "OK"
    } else {
        "MISMATCH"
    };
    let admitted_plus_rejected = summary.admitted.saturating_add(summary.rejected);
    let conservation = if admitted_plus_rejected == summary.evaluated {
        "OK"
    } else {
        "MISMATCH"
    };
    format!(
        "  summary: evaluated={} admitted={} rejected={} \
         no_matching_pool={} cpu_exhausted={} memory_exhausted={} \
         conservation={conservation} bucket-vs-rejected={bucket_check}",
        summary.evaluated,
        summary.admitted,
        summary.rejected,
        summary.no_matching_pool,
        summary.cpu_exhausted,
        summary.memory_exhausted,
    )
}

fn render_scenario(
    label: &str,
    planner: &ExecutionPlanner,
    input: PlannerInput,
    context: PlannerContext,
) -> String {
    let mut decisions = planner.resource_pool_decisions(&input, &context);
    // Sort by node id so the row order is stable across HashMap
    // iteration drift.
    decisions.sort_by(|a, b| a.node_id.as_str().cmp(b.node_id.as_str()));
    let summary = ResourcePoolDecisionSummary::from_decisions(&decisions);

    let mut out = vec![format!("scenario: {label}")];
    for d in &decisions {
        out.push(render_decision(d));
    }
    out.push(render_summary(&summary));
    out.join("\n")
}

fn render_golden() -> String {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();
    let mut sections: Vec<String> = vec![
        "# Resource-pool decisions canonical golden (br-evxvv.3)".to_string(),
        "# Format: per-scenario list of (node, ADMIT | REJECT class=<refusal>) ".to_string(),
        "#         + aggregated summary line.".to_string(),
        "# Conservation invariants asserted in the summary line:".to_string(),
        "#   conservation OK     => admitted + rejected == evaluated".to_string(),
        "#   bucket-vs-rejected  => no_matching_pool + cpu_exhausted +".to_string(),
        "#                          memory_exhausted == rejected".to_string(),
        "# Any 'MISMATCH' marker means the summary aggregation drifted from".to_string(),
        "# the per-node verdicts — that's the most concerning regression class".to_string(),
        "# this golden catches.".to_string(),
        String::new(),
    ];

    // (1) single_node_admitted — pool has headroom on both axes.
    sections.push(render_scenario(
        "single_node_admitted",
        &planner,
        PlannerInput::new(vec![make_node("alpha", 4096, vec![work.clone()])], 1000)
            .with_resource_pools(vec![
                ResourcePoolStatus::new(
                    "rr-work-alpha",
                    node_id("alpha"),
                    Some(work.clone()),
                    ResourcePoolClass::RequestResponse,
                    8,
                    4096,
                )
                .with_usage(2, 512),
            ]),
        PlannerContext::new(connector_id())
            .with_target_zone(work.clone())
            .with_resource_pool_class(ResourcePoolClass::RequestResponse)
            .with_requested_cpu_cores(4)
            .with_min_memory_mb(1024),
    ));
    sections.push(String::new());

    // (2) single_node_no_matching_pool — node has no matching pool.
    sections.push(render_scenario(
        "single_node_no_matching_pool",
        &planner,
        PlannerInput::new(vec![make_node("beta", 4096, vec![work.clone()])], 1000),
        PlannerContext::new(connector_id())
            .with_target_zone(work.clone())
            .with_resource_pool_class(ResourcePoolClass::RequestResponse)
            .with_requested_cpu_cores(4)
            .with_min_memory_mb(1024),
    ));
    sections.push(String::new());

    // (3) single_node_cpu_exhausted — pool CPU usage exceeds capacity.
    sections.push(render_scenario(
        "single_node_cpu_exhausted",
        &planner,
        PlannerInput::new(vec![make_node("gamma", 4096, vec![work.clone()])], 1000)
            .with_resource_pools(vec![
                ResourcePoolStatus::new(
                    "rr-work-gamma",
                    node_id("gamma"),
                    Some(work.clone()),
                    ResourcePoolClass::RequestResponse,
                    8,
                    4096,
                )
                .with_usage(7, 0),
            ]),
        PlannerContext::new(connector_id())
            .with_target_zone(work.clone())
            .with_resource_pool_class(ResourcePoolClass::RequestResponse)
            .with_requested_cpu_cores(4)
            .with_min_memory_mb(1024),
    ));
    sections.push(String::new());

    // (4) single_node_memory_exhausted — pool memory below floor.
    sections.push(render_scenario(
        "single_node_memory_exhausted",
        &planner,
        PlannerInput::new(vec![make_node("delta", 4096, vec![work.clone()])], 1000)
            .with_resource_pools(vec![
                ResourcePoolStatus::new(
                    "rr-work-delta",
                    node_id("delta"),
                    Some(work.clone()),
                    ResourcePoolClass::RequestResponse,
                    8,
                    1024,
                )
                .with_usage(0, 768),
            ]),
        PlannerContext::new(connector_id())
            .with_target_zone(work.clone())
            .with_resource_pool_class(ResourcePoolClass::RequestResponse)
            .with_requested_cpu_cores(4)
            .with_min_memory_mb(1024),
    ));
    sections.push(String::new());

    // (5) mixed_4_nodes_one_per_outcome — 1 admitted + 3 refusal types.
    sections.push(render_scenario(
        "mixed_4_nodes_one_per_outcome",
        &planner,
        PlannerInput::new(
            vec![
                make_node("admit",        4096, vec![work.clone()]),
                make_node("no-pool",      4096, vec![work.clone()]),
                make_node("cpu-hot",      4096, vec![work.clone()]),
                make_node("mem-hot",      4096, vec![work.clone()]),
            ],
            1000,
        )
        .with_resource_pools(vec![
            ResourcePoolStatus::new(
                "rr-work-admit",
                node_id("admit"),
                Some(work.clone()),
                ResourcePoolClass::RequestResponse,
                8,
                4096,
            )
            .with_usage(1, 512),
            ResourcePoolStatus::new(
                "rr-work-cpu-hot",
                node_id("cpu-hot"),
                Some(work.clone()),
                ResourcePoolClass::RequestResponse,
                8,
                4096,
            )
            .with_usage(7, 0),
            ResourcePoolStatus::new(
                "rr-work-mem-hot",
                node_id("mem-hot"),
                Some(work.clone()),
                ResourcePoolClass::RequestResponse,
                8,
                1024,
            )
            .with_usage(0, 768),
        ]),
        PlannerContext::new(connector_id())
            .with_target_zone(work)
            .with_resource_pool_class(ResourcePoolClass::RequestResponse)
            .with_requested_cpu_cores(4)
            .with_min_memory_mb(1024),
    ));
    sections.push(String::new());

    sections.join("\n") + "\n"
}

#[test]
fn golden_resource_pool_decisions_canonical_topologies() {
    let actual = render_golden();
    insta::assert_snapshot!("resource_pool_decisions_canonical_topologies", actual);
}
