use std::{fs, path::PathBuf};

use br_tools::incident_fixture_corpus::{
    IncidentClassification, IncidentReplayConfig, IncidentSourceClass, build_replay_report,
    classify_fixture, default_fixture_dir, load_fixture_dir, parse_fixture, redaction_violations,
    replay_fixture, validate_fixture, write_report_outputs,
};
use chrono::{DateTime, Utc};

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .expect("test timestamp is valid")
}

fn fixture_dir() -> PathBuf {
    default_fixture_dir()
}

#[test]
fn bundled_corpus_replays_all_required_classes() {
    let fixture_dir = fixture_dir();
    let fixtures = load_fixture_dir(&fixture_dir).expect("bundled fixtures load");
    let report = build_replay_report(
        &fixtures,
        &IncidentReplayConfig {
            now: ts("2026-05-28T17:00:00Z"),
            corpus_dir: Some(fixture_dir),
        },
    );

    assert_eq!(report.summary.total, 5);
    assert_eq!(report.summary.failed, 0);
    assert!(!report.mutation_attempted);
    assert_eq!(report.summary.by_source_class["rch"], 1);
    assert_eq!(report.summary.by_source_class["beads"], 1);
    assert_eq!(report.summary.by_source_class["agent_mail"], 1);
    assert_eq!(report.summary.by_source_class["disk_pressure"], 1);
    assert_eq!(report.summary.by_source_class["shared_tree_drift"], 1);
    assert_eq!(report.summary.by_classification["proof_infra_blocker"], 1);
    assert_eq!(report.summary.by_classification["tracker_state_blocker"], 1);
    assert_eq!(report.summary.by_classification["degraded_coordination"], 1);
    assert_eq!(
        report.summary.by_classification["disk_pressure_requires_plan"],
        1
    );
    assert_eq!(report.summary.by_classification["shared_tree_noise"], 1);
}

#[test]
fn parser_validates_required_fields_and_redaction_markers() {
    let fixture = parse_fixture(
        r#"{
          "schema_version":"fcp.incident-fixture.v1",
          "id":"missing-marker",
          "source_class":"rch",
          "summary":"summary",
          "transcript":"RCH local fallback in shared checkout",
          "expected_classification":"proof_infra_blocker",
          "expected_agent_action":"report blocker",
          "forbidden_actions":["run local cargo as proof"],
          "redaction_markers":["<repo>"]
        }"#,
    )
    .expect("fixture parses");

    let reasons = validate_fixture(&fixture);
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "fixture_invalid:missing_marker:<repo>")
    );
}

#[test]
fn rch_missing_toolchain_or_stale_cache_is_proof_infra() {
    let fixtures = load_fixture_dir(&fixture_dir()).expect("bundled fixtures load");
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.id == "rch-stale-preflight-001")
        .expect("rch fixture exists");

    assert_eq!(fixture.source_class, IncidentSourceClass::Rch);
    assert_eq!(
        classify_fixture(fixture),
        IncidentClassification::ProofInfraBlocker
    );
    let event = replay_fixture(fixture);
    assert!(event.passed);
    assert!(
        event
            .forbidden_actions
            .iter()
            .any(|action| action == "run local cargo as proof")
    );
}

#[test]
fn beads_db_jsonl_divergence_is_tracker_state_blocker() {
    let fixtures = load_fixture_dir(&fixture_dir()).expect("bundled fixtures load");
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.id == "beads-db-jsonl-drift-001")
        .expect("beads fixture exists");

    assert_eq!(
        classify_fixture(fixture),
        IncidentClassification::TrackerStateBlocker
    );
    assert!(replay_fixture(fixture).passed);
}

#[test]
fn agent_mail_unavailable_forbids_service_repair() {
    let fixtures = load_fixture_dir(&fixture_dir()).expect("bundled fixtures load");
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.id == "agent-mail-degraded-001")
        .expect("agent mail fixture exists");
    let event = replay_fixture(fixture);

    assert_eq!(
        event.actual_classification,
        IncidentClassification::DegradedCoordination
    );
    assert!(event.passed);
    assert!(
        event
            .forbidden_actions
            .iter()
            .any(|action| action == "am service restart")
    );
}

#[test]
fn disk_pressure_recommends_plan_not_deletion() {
    let fixtures = load_fixture_dir(&fixture_dir()).expect("bundled fixtures load");
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.id == "disk-pressure-no-space-001")
        .expect("disk fixture exists");
    let event = replay_fixture(fixture);

    assert_eq!(
        event.actual_classification,
        IncidentClassification::DiskPressureRequiresPlan
    );
    assert!(event.passed);
    assert!(
        event
            .forbidden_actions
            .iter()
            .any(|action| action == "delete files without written approval")
    );
}

#[test]
fn redaction_scan_rejects_private_paths_and_tokens() {
    let violations = redaction_violations(
        "failed in /Users/example/project with token=secret and Bearer abc123",
    );

    assert!(
        violations
            .iter()
            .any(|violation| violation == "mac_private_path")
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation == "token_assignment")
    );
    assert!(
        violations
            .iter()
            .any(|violation| violation == "bearer_token")
    );
}

#[test]
fn replay_writes_summary_json_and_event_jsonl() {
    let fixture_dir = fixture_dir();
    let fixtures = load_fixture_dir(&fixture_dir).expect("bundled fixtures load");
    let report = build_replay_report(
        &fixtures,
        &IncidentReplayConfig {
            now: ts("2026-05-28T17:00:00Z"),
            corpus_dir: Some(fixture_dir),
        },
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let summary = temp.path().join("summary.json");
    let events = temp.path().join("events.jsonl");

    write_report_outputs(&report, Some(&summary), Some(&events)).expect("writes reports");

    let summary_raw = fs::read_to_string(summary).expect("summary readable");
    let events_raw = fs::read_to_string(events).expect("events readable");
    assert!(summary_raw.contains("\"schema_version\": \"fcp.incident-fixture-replay.v1\""));
    assert_eq!(events_raw.lines().count(), 5);
    assert!(events_raw.contains("\"fixture_id\":\"rch-stale-preflight-001\""));
}
