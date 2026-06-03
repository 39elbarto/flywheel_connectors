use fcp_mesh::planner::{ComputeMigrationCostInput, DeviceCostInput, DeviceCostModel};
use fcp_tailscale::NodeId;
use proptest::prelude::*;

fn ordered_pair(a: f64, b: f64) -> (f64, f64) {
    if a <= b { (a, b) } else { (b, a) }
}

fn node(name: &str) -> NodeId {
    NodeId::new(name)
}

#[allow(clippy::too_many_arguments)]
fn migration_input(
    name: &str,
    latency_ms_p50: f64,
    network_lat_ms: f64,
    mem_pressure: f64,
    cpu_load: f64,
    energy_w: f64,
    derp_hop_count: u8,
) -> ComputeMigrationCostInput {
    ComputeMigrationCostInput::new(
        node(name),
        latency_ms_p50,
        network_lat_ms,
        mem_pressure,
        cpu_load,
        energy_w,
        derp_hop_count,
    )
}

proptest! {
    #[test]
    fn test_increasing_load_increases_cost(a in 0.0_f64..1.0, b in 0.0_f64..1.0) {
        let model = DeviceCostModel::default();
        let (low, high) = ordered_pair(a, b);

        let low_cost = model.cost(DeviceCostInput::new(low, 0.5, 0.5, 0.5));
        let high_cost = model.cost(DeviceCostInput::new(high, 0.5, 0.5, 0.5));

        prop_assert!(high_cost + f64::EPSILON >= low_cost);
    }

    #[test]
    fn test_cost_weight_increases_cost(a in 0.0_f64..1.0, b in 0.0_f64..1.0) {
        let model = DeviceCostModel::default();
        let (low, high) = ordered_pair(a, b);

        let low_cost = model.cost(DeviceCostInput::new(0.5, low, 0.5, 0.5));
        let high_cost = model.cost(DeviceCostInput::new(0.5, high, 0.5, 0.5));

        prop_assert!(high_cost + f64::EPSILON >= low_cost);
    }

    #[test]
    fn test_latency_weight_increases_cost(a in 0.0_f64..1.0, b in 0.0_f64..1.0) {
        let model = DeviceCostModel::default();
        let (low, high) = ordered_pair(a, b);

        let low_cost = model.cost(DeviceCostInput::new(0.5, 0.5, low, 0.5));
        let high_cost = model.cost(DeviceCostInput::new(0.5, 0.5, high, 0.5));

        prop_assert!(high_cost + f64::EPSILON >= low_cost);
    }

    #[test]
    fn test_stability_score_decreases_cost(a in 0.0_f64..1.0, b in 0.0_f64..1.0) {
        let model = DeviceCostModel::default();
        let (low_stability, high_stability) = ordered_pair(a, b);

        let low_stability_cost = model.cost(DeviceCostInput::new(0.5, 0.5, 0.5, low_stability));
        let high_stability_cost = model.cost(DeviceCostInput::new(0.5, 0.5, 0.5, high_stability));

        prop_assert!(low_stability_cost + f64::EPSILON >= high_stability_cost);
    }
}

proptest! {
    #[test]
    fn test_compute_migration_cost_monotone_in_latency(a in 0.0_f64..2_000.0, b in 0.0_f64..2_000.0) {
        let model = DeviceCostModel::default();
        let (low, high) = ordered_pair(a, b);

        let low_cost = model.compute_migration_cost(&migration_input("node-a", low, 20.0, 0.4, 0.4, 20.0, 0));
        let high_cost = model.compute_migration_cost(&migration_input("node-a", high, 20.0, 0.4, 0.4, 20.0, 0));

        prop_assert!(high_cost.total_cost + f64::EPSILON >= low_cost.total_cost);
    }

    #[test]
    fn test_compute_migration_cost_monotone_in_mem_pressure(a in 0.0_f64..1.0, b in 0.0_f64..1.0) {
        let model = DeviceCostModel::default();
        let (low, high) = ordered_pair(a, b);

        let low_cost = model.compute_migration_cost(&migration_input("node-a", 50.0, 20.0, low, 0.4, 20.0, 0));
        let high_cost = model.compute_migration_cost(&migration_input("node-a", 50.0, 20.0, high, 0.4, 20.0, 0));

        prop_assert!(high_cost.total_cost + f64::EPSILON >= low_cost.total_cost);
    }

    #[test]
    fn test_compute_migration_cost_monotone_in_cpu_load(a in 0.0_f64..1.0, b in 0.0_f64..1.0) {
        let model = DeviceCostModel::default();
        let (low, high) = ordered_pair(a, b);

        let low_cost = model.compute_migration_cost(&migration_input("node-a", 50.0, 20.0, 0.4, low, 20.0, 0));
        let high_cost = model.compute_migration_cost(&migration_input("node-a", 50.0, 20.0, 0.4, high, 20.0, 0));

        prop_assert!(high_cost.total_cost + f64::EPSILON >= low_cost.total_cost);
    }
}

#[test]
fn test_cost_model_prefers_local_over_lan() {
    let model = DeviceCostModel::default();
    let candidates = vec![
        migration_input("lan", 50.0, 35.0, 0.4, 0.4, 20.0, 0),
        migration_input("local", 50.0, 1.0, 0.4, 0.4, 20.0, 0),
    ];

    let explanation = model
        .pick_optimal_device(&candidates)
        .expect("two candidates should produce a winner");

    assert_eq!(explanation.winner, node("local"));
}

#[test]
fn test_cost_model_breaks_ties_by_energy() {
    let model = DeviceCostModel::default();
    let candidates = vec![
        migration_input("higher-energy", 50.0, 10.0, 0.4, 0.4, 80.0, 0),
        migration_input("lower-energy", 50.0, 10.0, 0.4, 0.4, 20.0, 0),
    ];

    let explanation = model
        .pick_optimal_device(&candidates)
        .expect("two candidates should produce a winner");

    assert_eq!(explanation.winner, node("lower-energy"));
}

#[test]
fn test_cost_model_explanation_orders_all_candidates() {
    let model = DeviceCostModel::default();
    let candidates = vec![
        migration_input("derp", 60.0, 420.0, 0.4, 0.4, 25.0, 5),
        migration_input("local", 40.0, 1.0, 0.4, 0.4, 25.0, 0),
        migration_input("busy", 30.0, 1.0, 0.9, 0.9, 25.0, 0),
    ];

    let explanation = model
        .pick_optimal_device(&candidates)
        .expect("candidate set should produce a winner");

    assert_eq!(explanation.winner, node("local"));
    assert_eq!(explanation.candidates.len(), 3);
    assert_eq!(explanation.candidates[0].node_id, node("local"));
    assert_eq!(explanation.candidates[2].node_id, node("derp"));
    assert!(explanation.candidates[0].total_cost <= explanation.candidates[1].total_cost);
    assert!(explanation.candidates[1].total_cost <= explanation.candidates[2].total_cost);
}
