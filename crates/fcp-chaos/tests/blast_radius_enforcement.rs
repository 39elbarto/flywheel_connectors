use fcp_chaos::{ChaosError, ChaosInjector, ChaosScenario, ChaosStatus, Env};
use proptest::prelude::*;

fn scenario(radius: u32) -> ChaosScenario {
    ChaosScenario::from_toml_str(&format!(
        r#"
name = "blast_radius_{radius}"
blast_radius = {radius}
recovery_objective_secs = 30

[[rollback_steps]]
name = "restore_network"
action = "restore_link"
"#
    ))
    .expect("scenario")
}

proptest! {
    #[test]
    fn test_scenario_exceeding_declared_radius_aborted(radius in 1_u32..100) {
        let injector = ChaosInjector::new(Env::Staging);
        let outcome = injector.run_scenario_with_observed_radius(&scenario(radius), radius + 1);
        prop_assert_eq!(outcome.status, ChaosStatus::Aborted);
        prop_assert_eq!(
            outcome.error,
            Some(ChaosError::BlastRadiusExceeded {
                declared: radius,
                observed: radius + 1,
            })
        );
        prop_assert_eq!(outcome.rollback_steps_executed, vec!["restore_network".to_string()]);
    }
}

#[test]
fn test_within_radius_completes() {
    let injector = ChaosInjector::new(Env::Staging);
    let outcome = injector.run_scenario_with_observed_radius(&scenario(3), 2);
    assert_eq!(outcome.status, ChaosStatus::Completed);
    assert!(outcome.error.is_none());
    assert_eq!(outcome.rollback_steps_executed, vec!["restore_network"]);
}

#[test]
fn test_rollback_executes_on_blast_radius_breach() {
    let injector = ChaosInjector::new(Env::Staging);
    let outcome = injector.run_scenario_with_observed_radius(&scenario(1), 2);
    assert_eq!(outcome.status, ChaosStatus::Aborted);
    assert_eq!(outcome.rollback_steps_executed, vec!["restore_network"]);
}

#[test]
fn test_net_partition_bisecting_runs_in_staging() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios/net/net_partition_bisecting.toml");
    let scenario = ChaosScenario::from_path(&path).expect("net partition scenario parses");
    let outcome = ChaosInjector::new(Env::Staging).run_scenario(&scenario);
    assert_eq!(outcome.status, ChaosStatus::Completed);
    assert_eq!(outcome.scenario, "net_partition_bisecting");
    assert!(!outcome.rollback_steps_executed.is_empty());
}
