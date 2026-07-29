use fcp_mesh::planner::{BetaPosterior, ResourcePoolClass, ThompsonScheduler};
use fcp_tailscale::NodeId;
use proptest::prelude::*;
use rand::{Rng, SeedableRng, rngs::StdRng};

fn node(index: usize) -> NodeId {
    NodeId::new(format!("node-{index}"))
}

fn node_index(node_id: &NodeId) -> usize {
    node_id
        .as_str()
        .strip_prefix("node-")
        .unwrap()
        .parse::<usize>()
        .unwrap()
}

#[test]
fn test_picks_best_device_by_500_trials() {
    let nodes: Vec<_> = (0..5).map(node).collect();
    let means = [0.1, 0.3, 0.5, 0.7, 0.9];
    let mut scheduler = ThompsonScheduler::new();
    let mut rng = StdRng::seed_from_u64(0xFC04_2001);
    let mut best_picks_after_500 = 0_u32;

    for trial in 0..1000 {
        let choice = scheduler
            .choose_with_rng(&nodes, ResourcePoolClass::RequestResponse, &mut rng)
            .unwrap();
        let index = node_index(&choice.node_id);
        if trial >= 500 && index == 4 {
            best_picks_after_500 += 1;
        }
        scheduler.record_outcome(
            choice.node_id,
            ResourcePoolClass::RequestResponse,
            rng.gen_bool(means[index]),
        );
    }

    assert!(
        best_picks_after_500 >= 475,
        "expected >=95% best-device picks after trial 500, got {best_picks_after_500}/500"
    );
}

proptest! {
    #[test]
    fn test_exploration_proportional_to_uncertainty(successes in 1_u32..200) {
        let uncertain = BetaPosterior::new(successes, successes);
        let certain = BetaPosterior::new(successes + 250, successes + 250);

        prop_assert!(uncertain.variance() > certain.variance());
        prop_assert!((uncertain.mean() - certain.mean()).abs() < f64::EPSILON);
    }
}

#[test]
fn test_converges_under_drift() {
    let nodes: Vec<_> = (0..5).map(node).collect();
    let mut scheduler = ThompsonScheduler::new();
    let mut rng = StdRng::seed_from_u64(0xFC04_2002);

    for _ in 0..450 {
        scheduler.record_outcome(nodes[4].clone(), ResourcePoolClass::RequestResponse, true);
    }
    for _ in 0..50 {
        scheduler.record_outcome(nodes[4].clone(), ResourcePoolClass::RequestResponse, false);
    }
    for _ in 0..350 {
        scheduler.record_outcome(nodes[3].clone(), ResourcePoolClass::RequestResponse, true);
    }
    for _ in 0..150 {
        scheduler.record_outcome(nodes[3].clone(), ResourcePoolClass::RequestResponse, false);
    }

    scheduler.decay_all(0.05);

    for _ in 0..250 {
        scheduler.record_outcome(nodes[3].clone(), ResourcePoolClass::RequestResponse, true);
        scheduler.record_outcome(nodes[4].clone(), ResourcePoolClass::RequestResponse, false);
    }

    assert!(
        scheduler
            .posterior(&nodes[3], ResourcePoolClass::RequestResponse)
            .mean()
            > scheduler
                .posterior(&nodes[4], ResourcePoolClass::RequestResponse)
                .mean()
    );

    let mut new_best_picks = 0_u32;
    for _ in 0..1000 {
        let choice = scheduler
            .choose_with_rng(&nodes, ResourcePoolClass::RequestResponse, &mut rng)
            .unwrap();
        let index = node_index(&choice.node_id);
        if index == 3 {
            new_best_picks += 1;
        }
    }

    assert!(
        new_best_picks >= 900,
        "expected scheduler to re-converge to node-3 after drift, got {new_best_picks}/1000"
    );
}

#[test]
fn test_dead_device_marked_low_via_failure_updates() {
    let dead = node(0);
    let healthy = node(1);
    let nodes = vec![dead.clone(), healthy];
    let mut scheduler = ThompsonScheduler::new();
    for _ in 0..200 {
        scheduler.record_outcome(dead.clone(), ResourcePoolClass::RequestResponse, false);
    }

    let posterior = scheduler.posterior(&dead, ResourcePoolClass::RequestResponse);
    assert!(posterior.mean() <= 0.02);

    let mut rng = StdRng::seed_from_u64(0xFC04_2003);
    let mut dead_picks = 0_u32;
    for _ in 0..1000 {
        let choice = scheduler
            .choose_with_rng(&nodes, ResourcePoolClass::RequestResponse, &mut rng)
            .unwrap();
        if choice.node_id == dead {
            dead_picks += 1;
        }
    }

    assert!(
        dead_picks <= 10,
        "expected dead-device sampling rate <=1%, got {dead_picks}/1000"
    );
}
