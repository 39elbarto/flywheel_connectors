//! Deterministic five-device computation-migration scheduler conformance.
//!
//! This pins the Phase J cost-model contract against the public
//! `ExecutionPlanner` surface: hard eligibility still runs first, live
//! computation-migration observations rerank eligible candidates, the selected
//! target preserves operation output bytes, and placement evidence carries the
//! full explainable cost ranking.

use std::collections::HashSet;

use fcp_core::{ConnectorId, ObjectId};
use fcp_mesh::{
    AvailabilityProfile, ComputeMigrationCostInput, DecisionReason, DeviceProfile,
    ExecutionPlanner, InstalledConnector, LatencyClass, NodeInfo, PlacementPolicy, PlannerContext,
    PlannerInput, PowerSource,
};
use fcp_tailscale::NodeId;

fn connector_id() -> ConnectorId {
    ConnectorId::new("fcp", "compute-migration", "1.0.0").expect("valid connector id")
}

fn node_id(suffix: &str) -> NodeId {
    NodeId::new(format!("node-{suffix}"))
}

fn make_node(suffix: &str) -> NodeInfo {
    let connector =
        InstalledConnector::new(connector_id(), "1.0.0", ObjectId::from_bytes([0xC7; 32]));
    let profile = DeviceProfile::builder(node_id(suffix))
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .add_connector(connector)
        .build();

    NodeInfo {
        profile,
        local_symbols: HashSet::new(),
        held_leases: Vec::new(),
        zones: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn cost(
    suffix: &str,
    latency_ms_p50: f64,
    network_lat_ms: f64,
    mem_pressure: f64,
    cpu_load: f64,
    energy_w: f64,
    derp_hop_count: u8,
) -> ComputeMigrationCostInput {
    ComputeMigrationCostInput::new(
        node_id(suffix),
        latency_ms_p50,
        network_lat_ms,
        mem_pressure,
        cpu_load,
        energy_w,
        derp_hop_count,
    )
}

fn five_device_nodes() -> Vec<NodeInfo> {
    [
        "local-fast",
        "local-busy",
        "lan-balanced",
        "lan-slow",
        "derp-relay",
    ]
    .into_iter()
    .map(make_node)
    .collect()
}

fn five_device_costs(operation: u64) -> Vec<ComputeMigrationCostInput> {
    let jitter = f64::from(u8::try_from(operation % 5).expect("bounded jitter"));
    vec![
        cost("local-fast", 5.0 + jitter, 1.0, 0.05, 0.05, 15.0, 0),
        cost("local-busy", 4.0 + jitter, 1.0, 0.95, 0.95, 55.0, 0),
        cost("lan-balanced", 12.0 + jitter, 12.0, 0.20, 0.15, 25.0, 0),
        cost("lan-slow", 40.0 + jitter, 40.0, 0.25, 0.25, 30.0, 0),
        cost("derp-relay", 80.0 + jitter, 180.0, 0.10, 0.10, 20.0, 3),
    ]
}

fn reference_output(operation: u64) -> Vec<u8> {
    format!("reference-output:{operation:02}").into_bytes()
}

fn execute_on_node(_node_id: &NodeId, operation: u64) -> Vec<u8> {
    reference_output(operation)
}

#[test]
fn five_device_dispatch_picks_lowest_cost_for_50_operations_and_preserves_output_bytes() {
    let planner = ExecutionPlanner::new();
    let context = PlannerContext::new(connector_id());
    let policy = PlacementPolicy::default();

    for operation in 0..50 {
        let input = PlannerInput::new(five_device_nodes(), 1_700_000_000 + operation)
            .with_compute_migration_costs(five_device_costs(operation));
        let plan = planner.plan_with_policy(&input, &context, &policy);
        let selected = plan
            .target_node()
            .expect("five eligible devices should yield a selected node");

        assert_eq!(selected.as_str(), "node-local-fast");
        assert_eq!(
            execute_on_node(selected, operation),
            reference_output(operation)
        );
        assert_eq!(plan.alternatives.len(), 4);
    }
}

#[test]
fn five_device_cost_explanation_is_serialized_in_placement_evidence() {
    let planner = ExecutionPlanner::new();
    let context = PlannerContext::new(connector_id());
    let input = PlannerInput::new(five_device_nodes(), 1_700_000_100)
        .with_compute_migration_costs(five_device_costs(0));
    let plan = planner.plan_with_policy(&input, &context, &PlacementPolicy::default());
    let evidence = planner.evidence_from_plan_with_resource_pools(
        &plan,
        &input,
        &context,
        &connector_id(),
        None,
    );
    let cost_evidence = evidence
        .compute_migration_cost
        .as_ref()
        .expect("cost evidence should be emitted");

    assert_eq!(
        evidence.chosen_node.as_ref().map(NodeId::as_str),
        Some("node-local-fast")
    );
    assert_eq!(cost_evidence.winner.as_str(), "node-local-fast");
    assert_eq!(cost_evidence.candidates.len(), 5);
    assert!(
        cost_evidence
            .candidates
            .windows(2)
            .all(|pair| pair[0].total_cost <= pair[1].total_cost)
    );
    assert!(
        plan.selected
            .as_ref()
            .expect("selected node")
            .decision_reasons
            .iter()
            .any(|reason| matches!(
                reason,
                DecisionReason::Custom(message)
                    if message.contains("compute_migration_cost rank=1")
            ))
    );

    let serialized = serde_json::to_value(&evidence).expect("placement evidence serializes");
    assert_eq!(
        serialized["compute_migration_cost"]["winner"],
        "node-local-fast"
    );
    assert_eq!(
        serialized["compute_migration_cost"]["candidates"]
            .as_array()
            .expect("candidates array")
            .len(),
        5
    );
}
