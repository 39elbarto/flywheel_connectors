use fcp_mesh::planner::{DeviceCostInput, DeviceCostModel};
use proptest::prelude::*;

fn ordered_pair(a: f64, b: f64) -> (f64, f64) {
    if a <= b { (a, b) } else { (b, a) }
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
