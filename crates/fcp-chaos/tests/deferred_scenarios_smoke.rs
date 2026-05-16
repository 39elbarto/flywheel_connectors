use std::path::{Path, PathBuf};

use fcp_chaos::scenarios::{
    disk_io::{dry_run_disk_io_scenario, dry_run_disk_io_scenario_with_observed_radius},
    process::dry_run_process_scenario,
    transport::dry_run_transport_scenario,
};
use fcp_chaos::{ChaosError, ChaosScenario, ChaosStatus, Env};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scenario_path(family: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios")
        .join(family)
        .join(format!("{name}.toml"))
}

fn load_scenario(family: &str, name: &str) -> Result<ChaosScenario, fcp_chaos::DslError> {
    ChaosScenario::from_path(&scenario_path(family, name))
}

#[test]
fn test_disk_full_aborts_with_wal_rollback() -> TestResult {
    let scenario = load_scenario("disk", "disk_full")?;
    let dry_run = dry_run_disk_io_scenario_with_observed_radius(
        &scenario,
        Env::Staging,
        scenario.blast_radius + 1,
    )?;

    assert_eq!(dry_run.outcome.status, ChaosStatus::Aborted);
    assert!(matches!(
        dry_run.outcome.error,
        Some(ChaosError::BlastRadiusExceeded { .. })
    ));
    assert!(dry_run.rollback_storage_state_restored);
    assert!(
        dry_run
            .steps_traced
            .contains(&"append_audit_entry_under_pressure")
    );
    Ok(())
}

#[test]
fn test_disk_quota_and_atomicity_plans_complete() -> TestResult {
    for name in ["quota_exhaustion", "audit_write_atomicity"] {
        let scenario = load_scenario("disk", name)?;
        let dry_run = dry_run_disk_io_scenario(&scenario, Env::Staging)?;

        assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
        assert!(dry_run.rollback_storage_state_restored);
        assert_eq!(
            dry_run.outcome.rollback_steps_executed.len(),
            scenario.rollback_steps.len()
        );
    }
    Ok(())
}

#[test]
fn test_process_plans_restore_process_state() -> TestResult {
    for name in ["oom_kill", "cgroup_memory_pressure"] {
        let scenario = load_scenario("process", name)?;
        let dry_run = dry_run_process_scenario(&scenario, Env::Staging)?;

        assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
        assert!(dry_run.rollback_process_state_restored);
        assert!(!dry_run.steps_traced.is_empty());
    }
    Ok(())
}

#[test]
fn test_transport_plans_restore_transport_state() -> TestResult {
    for name in ["tcp_rst_mid_handshake", "tcp_rst_during_rpc"] {
        let scenario = load_scenario("transport", name)?;
        let dry_run = dry_run_transport_scenario(&scenario, Env::Staging)?;

        assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
        assert!(dry_run.rollback_transport_state_restored);
        assert!(dry_run.plan.span_name.starts_with("fcp.chaos.transport."));
    }
    Ok(())
}
