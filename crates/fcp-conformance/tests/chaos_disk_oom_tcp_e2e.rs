//! Conformance coverage for deferred disk, process, and transport chaos plans.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fcp_chaos::scenarios::{
    disk_io::{self, dry_run_disk_io_scenario, dry_run_disk_io_scenario_with_observed_radius},
    process::{dry_run_process_scenario, plan_for_scenario as process_plan_for_scenario},
    transport::{dry_run_transport_scenario, plan_for_scenario as transport_plan_for_scenario},
};
use fcp_chaos::{ChaosError, ChaosScenario, ChaosStatus, Env};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scenario_path(family: &str, name: &str) -> PathBuf {
    repo_root()
        .join("scenarios")
        .join(family)
        .join(format!("{name}.toml"))
}

fn load_scenario(family: &str, name: &str) -> Result<ChaosScenario, fcp_chaos::DslError> {
    ChaosScenario::from_path(&scenario_path(family, name))
}

#[test]
fn test_disk_full_dry_run_restores_wal_after_abort() -> TestResult {
    let scenario = load_scenario("disk", "disk_full")?;
    let dry_run = dry_run_disk_io_scenario_with_observed_radius(
        &scenario,
        Env::Staging,
        scenario.blast_radius + 1,
    )?;

    assert_eq!(dry_run.outcome.status, ChaosStatus::Aborted);
    assert!(matches!(
        dry_run.outcome.error,
        Some(ChaosError::BlastRadiusExceeded {
            declared: 1,
            observed: 2
        })
    ));
    assert!(dry_run.rollback_storage_state_restored);
    assert!(
        dry_run
            .steps_traced
            .contains(&"append_audit_entry_under_pressure")
    );
    assert!(
        dry_run
            .outcome
            .rollback_steps_executed
            .iter()
            .any(|step| step == "verify_wal_replay")
    );
    Ok(())
}

#[test]
fn test_quota_exhaustion_plan_preserves_namespace_and_budget() -> TestResult {
    let scenario = load_scenario("disk", "quota_exhaustion")?;
    let plan = disk_io::plan_for_scenario("quota_exhaustion")
        .expect("quota exhaustion plan is registered");
    let dry_run = dry_run_disk_io_scenario(&scenario, Env::Staging)?;

    assert_eq!(plan.fault_class.as_str(), "quota_exhaustion");
    assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
    assert_eq!(dry_run.outcome.affected_units, 1);
    assert!(dry_run.rollback_storage_state_restored);
    assert!(
        scenario
            .rollback_steps
            .iter()
            .any(|step| step.target.as_deref() == Some("z:project:chaos"))
    );
    Ok(())
}

#[test]
fn test_audit_write_atomicity_replays_chain_head() -> TestResult {
    let scenario = load_scenario("disk", "audit_write_atomicity")?;
    let dry_run = dry_run_disk_io_scenario(&scenario, Env::Staging)?;

    assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
    assert!(dry_run.steps_traced.contains(&"replay_audit_wal"));
    assert!(
        scenario
            .rollback_steps
            .iter()
            .any(|step| step.action == "verify_wal_replay_chain_head")
    );
    Ok(())
}

#[test]
fn test_oom_kill_and_cgroup_memory_pressure_restore_process_state() -> TestResult {
    for name in ["oom_kill", "cgroup_memory_pressure"] {
        let scenario = load_scenario("process", name)?;
        let plan = process_plan_for_scenario(name).expect("process plan is registered");
        let dry_run = dry_run_process_scenario(&scenario, Env::Staging)?;

        assert_eq!(plan.fault_class.as_str(), name);
        assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
        assert!(dry_run.rollback_process_state_restored);
        assert_eq!(
            dry_run.outcome.rollback_steps_executed.len(),
            scenario.rollback_steps.len()
        );
    }
    Ok(())
}

#[test]
fn test_tcp_rst_scenarios_restore_transport_state() -> TestResult {
    for name in ["tcp_rst_mid_handshake", "tcp_rst_during_rpc"] {
        let scenario = load_scenario("transport", name)?;
        let plan = transport_plan_for_scenario(name).expect("transport plan is registered");
        let dry_run = dry_run_transport_scenario(&scenario, Env::Staging)?;

        assert_eq!(plan.fault_class.as_str(), name);
        assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
        assert!(dry_run.rollback_transport_state_restored);
        assert!(dry_run.plan.span_name.starts_with("fcp.chaos.transport."));
        assert_eq!(
            dry_run.outcome.rollback_steps_executed.len(),
            scenario.rollback_steps.len()
        );
    }
    Ok(())
}

#[test]
fn test_kill_switch_aborts_within_30s() -> TestResult {
    let scratch = scratch_root()?;
    let kill_switch = scratch.join("kill-switch");
    fs::write(&kill_switch, b"abort")?;

    let campaign_id = "kill-switch-selftest";
    let started_at = Instant::now();
    let output = Command::new("bash")
        .arg(repo_root().join("scripts/chaos/staging_7day_campaign.sh"))
        .arg("--campaign-id")
        .arg(campaign_id)
        .arg("--duration-secs")
        .arg("60")
        .arg("--scenario-dir")
        .arg(repo_root().join("scenarios"))
        .arg("--kill-switch")
        .arg(&kill_switch)
        .arg("--dry-run")
        .env("FCP_ENV", "staging")
        .env("REPO_ROOT", &scratch)
        .output()?;
    let elapsed = started_at.elapsed();

    assert!(
        output.status.success(),
        "campaign failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed <= Duration::from_secs(30),
        "kill switch took {elapsed:?}"
    );

    let events = fs::read_to_string(
        scratch
            .join("chaos-results")
            .join(campaign_id)
            .join("events.jsonl"),
    )?;
    assert!(events.contains("\"phase\":\"kill_switch_triggered\""));
    assert!(events.contains("\"phase\":\"kill_switch_abort_complete\""));
    Ok(())
}

fn scratch_root() -> std::io::Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "fcp-chaos-kill-switch-{}-{now}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    Ok(root)
}
