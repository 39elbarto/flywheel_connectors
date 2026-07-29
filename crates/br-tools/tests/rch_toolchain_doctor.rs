use std::{ffi::OsString, fs, path::Path, process::Command};

use br_tools::rch_toolchain_doctor::{
    RchToolchainDoctorConfig, ToolchainDoctorStatus, ToolchainObservationClass,
    WorkerObservationSource, build_rch_toolchain_doctor_report, parse_diagnose_evidence,
    parse_toolchain_requirement,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tempfile::tempdir;

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .expect("test timestamp is valid")
}

fn config(required_toolchain: &str) -> RchToolchainDoctorConfig {
    RchToolchainDoctorConfig {
        now: ts("2026-05-28T10:00:00Z"),
        git_revision: Some("abc123".to_string()),
        required_toolchain_override: Some(required_toolchain.to_string()),
    }
}

const fn source(value: Value) -> WorkerObservationSource {
    WorkerObservationSource {
        source_path: None,
        value: Some(value),
        error: None,
    }
}

fn report_for(worker: Value) -> br_tools::rch_toolchain_doctor::RchToolchainDoctorReport {
    let repo_toolchain = parse_toolchain_requirement(
        None,
        r#"[toolchain]
channel = "nightly"
components = ["rustfmt", "clippy"]
"#,
    );
    let diagnose = parse_diagnose_evidence(
        None,
        &[json!({
            "error": "missing nightly-2026-05-26-x86_64-unknown-linux-gnu",
            "worker_user": "ubuntu",
            "worker_home": "/home/ubuntu"
        })],
        &[],
        &[],
    );
    build_rch_toolchain_doctor_report(
        repo_toolchain,
        diagnose,
        &[source(worker)],
        &config("nightly-2026-05-26-x86_64-unknown-linux-gnu"),
    )
}

fn has_reason(report: &Value, reason: &str) -> bool {
    report["reason_codes"]
        .as_array()
        .expect("reason_codes is an array")
        .iter()
        .any(|value| value.as_str() == Some(reason))
}

fn run_cli_json(toolchain_toml: &Path, diagnose_json: &Path, worker: &Path) -> Value {
    let args = vec![
        OsString::from("--toolchain-toml"),
        toolchain_toml.as_os_str().to_os_string(),
        OsString::from("--diagnose-json"),
        diagnose_json.as_os_str().to_os_string(),
        OsString::from("--worker-observation"),
        worker.as_os_str().to_os_string(),
        OsString::from("--git-revision"),
        OsString::from("abc123"),
        OsString::from("--now"),
        OsString::from("2026-05-28T10:00:00Z"),
        OsString::from("--json"),
    ];

    let output = Command::new(env!("CARGO_BIN_EXE_rch-toolchain-doctor"))
        .args(args)
        .output()
        .expect("rch-toolchain-doctor CLI runs");
    assert!(
        output.status.success(),
        "rch-toolchain-doctor exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI emits JSON report")
}

#[test]
fn diagnose_missing_but_direct_worker_installed_reports_stale_preflight() {
    let report = report_for(json!({
        "worker_id": "vmi1152480",
        "user": "ubuntu",
        "home": "/home/ubuntu",
        "toolchain_list": ["stable-x86_64-unknown-linux-gnu", "nightly-2026-05-26-x86_64-unknown-linux-gnu"],
        "rustup_run_success": true,
        "rustc_version": "rustc 1.89.0-nightly"
    }));

    assert_eq!(report.overall_status, ToolchainDoctorStatus::Blocked);
    assert_eq!(
        report.workers[0].direct_observation_class,
        ToolchainObservationClass::PreflightCacheStaleOrWrongEnv
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "preflight_cache_stale_or_wrong_env")
    );
    assert!(!report.direct_ssh_accepted_as_proof);
    assert!(!report.mutation_attempted);
}

#[test]
fn diagnose_and_direct_worker_missing_reports_worker_toolchain_missing() {
    let report = report_for(json!({
        "worker_id": "vmi1152480",
        "user": "ubuntu",
        "home": "/home/ubuntu",
        "toolchain_list": ["stable-x86_64-unknown-linux-gnu"],
        "rustup_run_success": false
    }));

    assert_eq!(
        report.workers[0].direct_observation_class,
        ToolchainObservationClass::WorkerToolchainMissing
    );
    assert!(
        report
            .recommended_actions
            .iter()
            .any(|action| action.contains("human approval"))
    );
}

#[test]
fn generic_nightly_without_dated_nightly_reports_dated_toolchain_missing() {
    let report = report_for(json!({
        "worker_id": "vmi1152480",
        "user": "ubuntu",
        "home": "/home/ubuntu",
        "toolchain_list": ["nightly-x86_64-unknown-linux-gnu"],
        "rustup_run_success": false
    }));

    assert_eq!(
        report.workers[0].direct_observation_class,
        ToolchainObservationClass::DatedToolchainMissing
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "dated_toolchain_missing")
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "generic_nightly_vs_dated_nightly_drift")
    );
}

#[test]
fn direct_worker_user_or_home_mismatch_reports_env_mismatch() {
    let report = report_for(json!({
        "worker_id": "vmi1152480",
        "user": "root",
        "home": "/root",
        "toolchain_list": ["nightly-2026-05-26-x86_64-unknown-linux-gnu"],
        "rustup_run_success": true
    }));

    assert_eq!(
        report.workers[0].direct_observation_class,
        ToolchainObservationClass::WorkerUserEnvMismatch
    );
    assert!(
        report
            .recommended_actions
            .iter()
            .any(|action| action.contains("service account HOME"))
    );
}

#[test]
fn malformed_worker_evidence_fails_closed_as_inconclusive() {
    let repo_toolchain = parse_toolchain_requirement(None, r#"[toolchain] channel = "nightly""#);
    let diagnose = parse_diagnose_evidence(
        None,
        &[json!({"error": "missing nightly-2026-05-26-x86_64-unknown-linux-gnu"})],
        &[],
        &[],
    );
    let source = WorkerObservationSource {
        source_path: None,
        value: None,
        error: Some("redacted or malformed".to_string()),
    };
    let report = build_rch_toolchain_doctor_report(
        repo_toolchain,
        diagnose,
        &[source],
        &config("nightly-2026-05-26-x86_64-unknown-linux-gnu"),
    );

    assert_eq!(report.overall_status, ToolchainDoctorStatus::Blocked);
    assert_eq!(
        report.workers[0].direct_observation_class,
        ToolchainObservationClass::ToolchainEvidenceInconclusive
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "toolchain_evidence_inconclusive")
    );
}

#[test]
fn cli_fixture_replays_ha7bs_style_transcript_without_mutation() {
    let tmp = tempdir().expect("tempdir");
    let toolchain = tmp.path().join("rust-toolchain.toml");
    let diagnose = tmp.path().join("diagnose.json");
    let worker = tmp.path().join("worker.json");
    fs::write(
        &toolchain,
        r#"[toolchain]
channel = "nightly"
components = ["rustfmt", "clippy"]
"#,
    )
    .expect("toolchain fixture writes");
    fs::write(
        &diagnose,
        serde_json::to_vec_pretty(&json!({
            "error": "missing nightly-2026-05-26-x86_64-unknown-linux-gnu",
            "worker_user": "ubuntu",
            "worker_home": "/home/ubuntu"
        }))
        .expect("diagnose JSON serializes"),
    )
    .expect("diagnose fixture writes");
    fs::write(
        &worker,
        serde_json::to_vec_pretty(&json!({
            "worker_id": "vmi1152480",
            "user": "ubuntu",
            "home": "/home/ubuntu",
            "toolchain_list": ["stable-x86_64-unknown-linux-gnu", "nightly-2026-05-26-x86_64-unknown-linux-gnu"],
            "rustup_run_success": true,
            "rustc_version": "rustc 1.89.0-nightly"
        }))
        .expect("worker JSON serializes"),
    )
    .expect("worker fixture writes");

    let report = run_cli_json(&toolchain, &diagnose, &worker);

    assert_eq!(report["schema_version"], "fcp.rch-toolchain-doctor.v1");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["direct_ssh_accepted_as_proof"], false);
    assert_eq!(report["overall_status"], "blocked");
    assert_eq!(
        report["workers"][0]["direct_observation_class"],
        "preflight_cache_stale_or_wrong_env"
    );
    assert!(has_reason(&report, "preflight_cache_stale_or_wrong_env"));
    assert!(
        report["recommended_actions"]
            .as_array()
            .expect("recommended_actions array")
            .iter()
            .any(|action| action
                .as_str()
                .is_some_and(|text| text.contains("do not run rustup")))
    );
}
