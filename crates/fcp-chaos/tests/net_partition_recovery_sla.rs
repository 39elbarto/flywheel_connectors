use std::path::PathBuf;

use fcp_chaos::scenarios::net::{
    dry_run_network_scenario_with_observed_radius, verify_bisecting_partition_recovery_sla,
};
use fcp_chaos::{ChaosScenario, ChaosStatus, Env};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scenario_path() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios/net/net_partition_bisecting.toml")
}

fn load_scenario() -> Result<ChaosScenario, fcp_chaos::DslError> {
    ChaosScenario::from_path(&scenario_path())
}

#[test]
fn test_bisecting_partition_recovers_under_recovery_objective() -> TestResult {
    let scenario = load_scenario()?;
    let report = verify_bisecting_partition_recovery_sla(
        &scenario,
        5,
        scenario.recovery_objective_secs - 1,
    )?;

    assert!(report.slo_held);
    assert_eq!(report.reconvergence_secs, 1);
    assert_eq!(report.peer_count, 5);
    Ok(())
}

#[test]
fn test_iptables_restored_after_partition() -> TestResult {
    let scenario = load_scenario()?;
    let dry_run = dry_run_network_scenario_with_observed_radius(
        &scenario,
        Env::Staging,
        scenario.blast_radius + 1,
    )?;

    assert_eq!(dry_run.outcome.status, ChaosStatus::Aborted);
    assert!(dry_run.rollback_network_state_restored);
    assert!(
        dry_run
            .outcome
            .rollback_steps_executed
            .contains(&"restore_partitioned_links".to_string())
    );
    Ok(())
}
