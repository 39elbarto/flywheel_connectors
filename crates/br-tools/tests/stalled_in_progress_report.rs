use std::{collections::BTreeSet, fs};

use br_tools::stalled_in_progress::{
    ProcessSnapshot, RecommendedAction, ReportConfig, build_report, load_issue_records,
};
use chrono::{DateTime, Duration, Utc};
use tempfile::tempdir;

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .expect("test timestamp is valid")
}

const fn base_config(now: DateTime<Utc>) -> ReportConfig {
    ReportConfig {
        now,
        stale_after: Duration::hours(72),
        recent_comment_after: Duration::hours(24),
        lock_path: None,
        lock_present: false,
        active_processes: Vec::new(),
        known_agents: BTreeSet::new(),
    }
}

fn load_fixture(lines: &[&str]) -> Vec<br_tools::stalled_in_progress::IssueRecord> {
    let tmp = tempdir().expect("tempdir");
    let path = tmp.path().join("issues.jsonl");
    fs::write(&path, lines.join("\n")).expect("write fixture");
    load_issue_records(&path).expect("load fixture")
}

#[test]
fn stale_unassigned_issue_recommends_reopen_command() {
    let issues = load_fixture(&[
        r#"{"id":"flywheel_connectors-stale","title":"old claim","status":"in_progress","updated_at":"2026-05-01T00:00:00Z"}"#,
    ]);

    let report = build_report(&issues, &base_config(ts("2026-05-14T00:00:00Z")));

    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.recommended_action, RecommendedAction::Reopen);
    assert_eq!(
        finding.safe_reopen_command.as_deref(),
        Some("br update flywheel_connectors-stale --status open --assignee ''")
    );
    assert!(
        finding
            .reason_codes
            .iter()
            .any(|code| code == "missing_assignee")
    );
}

#[test]
fn active_matching_process_leaves_claimed_issue_alone() {
    let issues = load_fixture(&[
        r#"{"id":"flywheel_connectors-active","title":"active claim","status":"in_progress","assignee":"BlueLake","updated_at":"2026-05-01T00:00:00Z"}"#,
    ]);
    let mut config = base_config(ts("2026-05-14T00:00:00Z"));
    config.active_processes.push(ProcessSnapshot::new(
        Some(4242),
        "cargo test flywheel_connectors-active --api-key supersecret",
    ));

    let report = build_report(&issues, &config);

    let finding = &report.findings[0];
    assert_eq!(finding.recommended_action, RecommendedAction::LeaveClaimed);
    assert_eq!(finding.active_process_evidence.len(), 1);
    assert_eq!(
        finding.active_process_evidence[0].matched_on,
        "issue_id:flywheel_connectors-active"
    );
    assert_eq!(
        finding.active_process_evidence[0].command,
        "cargo test flywheel_connectors-active --api-key <redacted>"
    );
}

#[test]
fn recently_updated_issue_is_not_reopened() {
    let issues = load_fixture(&[
        r#"{"id":"flywheel_connectors-recent","title":"recent claim","status":"in_progress","updated_at":"2026-05-13T23:00:00Z"}"#,
    ]);

    let report = build_report(&issues, &base_config(ts("2026-05-14T00:00:00Z")));

    let finding = &report.findings[0];
    assert_eq!(finding.recommended_action, RecommendedAction::LeaveClaimed);
    assert!(!finding.stale);
    assert!(finding.safe_reopen_command.is_none());
}

#[test]
fn stale_assigned_issue_without_evidence_requires_investigation() {
    let issues = load_fixture(&[
        r#"{"id":"flywheel_connectors-dead","title":"assigned but quiet","status":"in_progress","assignee":"PurpleHill","updated_at":"2026-05-01T00:00:00Z"}"#,
    ]);

    let report = build_report(&issues, &base_config(ts("2026-05-14T00:00:00Z")));

    let finding = &report.findings[0];
    assert_eq!(finding.recommended_action, RecommendedAction::Investigate);
    assert!(
        finding
            .reason_codes
            .iter()
            .any(|code| code == "unknown_assignee:PurpleHill")
    );
}

#[test]
fn stale_unassigned_issue_is_blocked_by_write_lock() {
    let issues = load_fixture(&[
        r#"{"id":"flywheel_connectors-locked","title":"locked claim","status":"in_progress","updated_at":"2026-05-01T00:00:00Z"}"#,
    ]);
    let mut config = base_config(ts("2026-05-14T00:00:00Z"));
    config.lock_present = true;

    let report = build_report(&issues, &config);

    let finding = &report.findings[0];
    assert_eq!(finding.recommended_action, RecommendedAction::BlockedByLock);
    assert!(finding.safe_reopen_command.is_none());
    assert!(
        finding
            .reason_codes
            .iter()
            .any(|code| code == "beads_write_lock_present")
    );
}

#[test]
fn stale_issue_with_recent_comment_requires_investigation() {
    let issues = load_fixture(&[
        r#"{"id":"flywheel_connectors-commented","title":"commented claim","status":"in_progress","updated_at":"2026-05-01T00:00:00Z","comments":[{"created_at":"2026-05-13T23:30:00Z"}]}"#,
    ]);

    let report = build_report(&issues, &base_config(ts("2026-05-14T00:00:00Z")));

    let finding = &report.findings[0];
    assert_eq!(finding.recommended_action, RecommendedAction::Investigate);
    assert!(
        finding
            .reason_codes
            .iter()
            .any(|code| code == "recent_comment")
    );
}
