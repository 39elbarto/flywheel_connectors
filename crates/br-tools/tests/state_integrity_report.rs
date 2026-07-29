use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

use br_tools::state_integrity::{
    BvProjectionFindingKind, IssueQueryStatus, LockState, ProcessSnapshot, ProjectionFindingKind,
    SourceErrorKind, StateIntegrityConfig, StateIntegrityStatus, build_state_integrity_report,
    load_live_db_source, parse_bv_graph_source, parse_db_snapshot_source, parse_jsonl_source,
};
use chrono::{DateTime, Duration, Utc};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::tempdir;

const CLI_TARGET_ISSUE: &str = "flywheel_connectors-target";

struct CliFixture {
    issues: PathBuf,
    db: PathBuf,
    bv: PathBuf,
    lock: PathBuf,
}

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .expect("test timestamp is valid")
}

const fn base_config(now: DateTime<Utc>) -> StateIntegrityConfig {
    StateIntegrityConfig {
        now,
        lock_path: None,
        lock_stale_after: Duration::seconds(300),
        active_processes: Vec::new(),
        query_issue_id: None,
    }
}

fn push_path_arg(args: &mut Vec<OsString>, flag: &str, path: &Path) {
    args.push(OsString::from(flag));
    args.push(path.as_os_str().to_os_string());
}

fn push_str_arg(args: &mut Vec<OsString>, flag: &str, value: &str) {
    args.push(OsString::from(flag));
    args.push(OsString::from(value));
}

fn run_cli_json(
    issues: &Path,
    db_snapshot: Option<&Path>,
    bv_graph: Option<&Path>,
    lock_path: &Path,
    query_issue: Option<&str>,
    processes: &[String],
) -> Value {
    let mut args = Vec::new();
    push_path_arg(&mut args, "--issues", issues);
    match db_snapshot {
        Some(path) => push_path_arg(&mut args, "--db-snapshot", path),
        None => args.push(OsString::from("--no-db")),
    }
    if let Some(path) = bv_graph {
        push_path_arg(&mut args, "--bv-graph", path);
    }
    push_path_arg(&mut args, "--lock-path", lock_path);
    push_str_arg(&mut args, "--now", "2026-05-28T04:00:00Z");
    for process in processes {
        push_str_arg(&mut args, "--process", process);
    }
    if let Some(issue_id) = query_issue {
        push_str_arg(&mut args, "--issue", issue_id);
    }
    args.push(OsString::from("--no-ps"));
    args.push(OsString::from("--json"));

    let output = Command::new(env!("CARGO_BIN_EXE_beads-state-integrity"))
        .args(args)
        .output()
        .expect("beads-state-integrity CLI runs");
    assert!(
        output.status.success(),
        "beads-state-integrity exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI emits JSON report")
}

fn has_reason(report: &Value, reason: &str) -> bool {
    report["reason_codes"]
        .as_array()
        .expect("reason_codes is an array")
        .iter()
        .any(|value| value.as_str() == Some(reason))
}

fn has_recommended_action(report: &Value, expected: &str) -> bool {
    report["recommended_actions"]
        .as_array()
        .expect("recommended_actions is an array")
        .iter()
        .any(|action| action.as_str().is_some_and(|text| text.contains(expected)))
}

fn write_healthy_cli_fixture(root: &Path) -> CliFixture {
    let fixture = CliFixture {
        issues: root.join("healthy-issues.jsonl"),
        db: root.join("healthy-db.json"),
        bv: root.join("healthy-bv.json"),
        lock: root.join(".write.lock"),
    };
    fs::write(
        &fixture.issues,
        r#"{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}"#,
    )
    .expect("write healthy issues");
    fs::write(
        &fixture.db,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}]}"#,
    )
    .expect("write healthy DB snapshot");
    fs::write(
        &fixture.bv,
        r#"{"format":"json","adjacency":{"nodes":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}]}}"#,
    )
    .expect("write healthy bv graph");
    fixture
}

#[test]
fn db_jsonl_issue_projection_divergence_blocks_claiming() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-angoc.6.3.1","title":"[Phase L.5.1] Normalize RCH worker telemetry into proof-capacity decisions","status":"blocked","priority":2,"updated_at":"2026-05-18T22:17:26Z"}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-angoc.6.3.1","title":"[proof-governor][A] Define fail-closed rch evidence schema and state taxonomy","status":"closed","priority":1,"updated_at":"2026-05-16T02:29:43Z"}]}"#,
    );

    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        None,
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Blocked);
    assert_eq!(report.issue_findings.len(), 1);
    assert_eq!(
        report.issue_findings[0].kind,
        ProjectionFindingKind::IssueProjectionDiverged
    );
    assert_eq!(
        report.issue_findings[0].jsonl_status.as_deref(),
        Some("blocked")
    );
    assert_eq!(
        report.issue_findings[0].db_status.as_deref(),
        Some("closed")
    );
    assert!(!report.mutation_attempted);
}

#[test]
fn db_only_issue_warns_against_lossy_flush() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-present","title":"present","status":"open"}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-present","title":"present","status":"open"},{"id":"flywheel_connectors-db-only","title":"would be lost","status":"open"}]}"#,
    );

    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        None,
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Blocked);
    assert!(
        report
            .issue_findings
            .iter()
            .any(|finding| finding.kind == ProjectionFindingKind::DbOnly
                && finding.id == "flywheel_connectors-db-only")
    );
    assert!(
        report
            .recommended_actions
            .iter()
            .any(|action| action.contains("do not run force export"))
    );
}

#[test]
fn live_sqlite_db_source_compares_against_jsonl_without_mutation() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("beads.db");
    let connection = Connection::open(&db_path).expect("open sqlite fixture");
    connection
        .execute_batch(
            r"
            CREATE TABLE issues (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER NOT NULL,
                updated_at TEXT,
                deleted_at TEXT
            );
            CREATE TABLE comments (
                id INTEGER PRIMARY KEY,
                issue_id TEXT NOT NULL,
                author TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE dependencies (
                issue_id TEXT NOT NULL,
                depends_on_id TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                metadata TEXT,
                thread_id TEXT
            );
            INSERT INTO issues (id, title, status, priority, updated_at, deleted_at)
            VALUES ('flywheel_connectors-live', 'live db', 'open', 2, '2026-05-28T04:00:00Z', NULL);
            INSERT INTO issues (id, title, status, priority, updated_at, deleted_at)
            VALUES ('flywheel_connectors-deleted', 'deleted db', 'closed', 2, '2026-05-28T04:00:00Z', '2026-05-28T04:01:00Z');
            INSERT INTO comments (id, issue_id, author, text, created_at)
            VALUES (9, 'flywheel_connectors-live', 'SwiftGull', 'matched comment', '2026-05-28T04:02:00Z');
            INSERT INTO dependencies (issue_id, depends_on_id, type, created_at, created_by, metadata, thread_id)
            VALUES ('flywheel_connectors-live', 'flywheel_connectors-parent', 'related', '2026-05-28T04:03:00Z', 'SwiftGull', '{}', '');
            ",
        )
        .expect("seed sqlite fixture");
    drop(connection);

    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-live","title":"live db","status":"open","priority":2,"updated_at":"2026-05-28T04:00:00Z","comments":[{"id":9,"issue_id":"flywheel_connectors-live","author":"SwiftGull","text":"matched comment","created_at":"2026-05-28T04:02:00Z"}],"dependencies":[{"issue_id":"flywheel_connectors-live","depends_on_id":"flywheel_connectors-parent","type":"related","created_at":"2026-05-28T04:03:00Z","created_by":"SwiftGull","metadata":"{}","thread_id":""}]}"#,
    );
    let db = load_live_db_source(&db_path);
    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        None,
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Healthy);
    assert_eq!(report.db.as_ref().expect("db summary").source, "db");
    assert_eq!(report.db.as_ref().expect("db summary").issue_count, 1);
    assert!(report.issue_findings.is_empty());
    assert!(!report.mutation_attempted);
}

#[test]
fn comment_projection_divergence_blocks_claiming() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-comments","title":"same","status":"open","comments":[{"id":1,"issue_id":"flywheel_connectors-comments","author":"SwiftGull","text":"jsonl truth","created_at":"2026-05-28T04:02:00Z"}]}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-comments","title":"same","status":"open","comments":[{"id":1,"issue_id":"flywheel_connectors-comments","author":"SwiftGull","text":"db truth","created_at":"2026-05-28T04:02:00Z"}]}]}"#,
    );

    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        None,
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Blocked);
    assert_eq!(report.issue_findings.len(), 1);
    assert_eq!(
        report.issue_findings[0].kind,
        ProjectionFindingKind::IssueProjectionDiverged
    );
    assert_eq!(
        report.issue_findings[0].diverged_fields,
        vec!["comments".to_string()]
    );
    assert!(
        report.issue_findings[0]
            .recommendation
            .contains("comments/dependencies")
    );
    assert!(!report.mutation_attempted);
}

#[test]
fn dependency_projection_divergence_blocks_claiming() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-deps","title":"same","status":"open","dependencies":[{"issue_id":"flywheel_connectors-deps","depends_on_id":"flywheel_connectors-parent-a","type":"related","created_at":"2026-05-28T04:03:00Z","created_by":"SwiftGull","metadata":"{}","thread_id":""}]}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-deps","title":"same","status":"open","dependencies":[{"issue_id":"flywheel_connectors-deps","depends_on_id":"flywheel_connectors-parent-b","type":"related","created_at":"2026-05-28T04:03:00Z","created_by":"SwiftGull","metadata":"{}","thread_id":""}]}]}"#,
    );

    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        None,
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Blocked);
    assert_eq!(report.issue_findings.len(), 1);
    assert_eq!(
        report.issue_findings[0].kind,
        ProjectionFindingKind::IssueProjectionDiverged
    );
    assert_eq!(
        report.issue_findings[0].diverged_fields,
        vec!["dependencies".to_string()]
    );
    assert!(!report.mutation_attempted);
}

#[test]
fn issue_query_reports_selected_issue_without_unrelated_findings() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        concat!(
            r#"{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}"#,
            "\n",
            r#"{"id":"flywheel_connectors-other","title":"jsonl","status":"open","priority":2}"#
        ),
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1},{"id":"flywheel_connectors-other","title":"db","status":"closed","priority":2}]}"#,
    );
    let mut config = base_config(ts("2026-05-28T04:00:00Z"));
    config.query_issue_id = Some("flywheel_connectors-target".to_string());

    let report = build_state_integrity_report(jsonl, Some(db), None, &config);

    let query = report.query.as_ref().expect("query report");
    assert_eq!(query.id, "flywheel_connectors-target");
    assert_eq!(query.status, IssueQueryStatus::SourcesAgree);
    assert_eq!(
        query.jsonl.as_ref().map(|issue| issue.status.as_str()),
        Some("open")
    );
    assert_eq!(
        query.db.as_ref().map(|issue| issue.status.as_str()),
        Some("open")
    );
    assert!(query.finding.is_none());
    assert!(report.issue_findings.is_empty());
    assert!(!report.mutation_attempted);
}

#[test]
fn issue_query_reports_selected_divergence() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-target","title":"jsonl","status":"open","priority":1}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"db","status":"closed","priority":1}]}"#,
    );
    let mut config = base_config(ts("2026-05-28T04:00:00Z"));
    config.query_issue_id = Some("flywheel_connectors-target".to_string());

    let report = build_state_integrity_report(jsonl, Some(db), None, &config);

    let query = report.query.as_ref().expect("query report");
    assert_eq!(query.status, IssueQueryStatus::Diverged);
    assert_eq!(
        query.finding.as_ref().map(|finding| finding.kind),
        Some(ProjectionFindingKind::IssueProjectionDiverged)
    );
    assert_eq!(report.issue_findings.len(), 1);
    assert_eq!(report.issue_findings[0].id, "flywheel_connectors-target");
    assert!(!report.mutation_attempted);
}

#[test]
fn bv_graph_query_reports_selected_issue_without_unrelated_findings() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        concat!(
            r#"{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}"#,
            "\n",
            r#"{"id":"flywheel_connectors-other","title":"jsonl","status":"open","priority":2}"#
        ),
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1},{"id":"flywheel_connectors-other","title":"jsonl","status":"open","priority":2}]}"#,
    );
    let bv = parse_bv_graph_source(
        "bv_graph",
        None,
        r#"{"format":"json","adjacency":{"nodes":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1},{"id":"flywheel_connectors-other","title":"bv-stale","status":"closed","priority":2}]}}"#,
    );
    let mut config = base_config(ts("2026-05-28T04:00:00Z"));
    config.query_issue_id = Some("flywheel_connectors-target".to_string());

    let report = build_state_integrity_report(jsonl, Some(db), Some(bv), &config);

    let query = report.query.as_ref().expect("query report");
    assert_eq!(query.status, IssueQueryStatus::SourcesAgree);
    assert_eq!(
        query.bv.as_ref().map(|issue| issue.status.as_str()),
        Some("open")
    );
    assert!(query.bv_finding.is_none());
    assert!(report.issue_findings.is_empty());
    assert!(report.bv_findings.is_empty());
    assert!(!report.mutation_attempted);
}

#[test]
fn bv_graph_query_reports_selected_divergence() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}]}"#,
    );
    let bv = parse_bv_graph_source(
        "bv_graph",
        None,
        r#"{"format":"json","adjacency":{"nodes":[{"id":"flywheel_connectors-target","title":"target","status":"closed","priority":1}]}}"#,
    );
    let mut config = base_config(ts("2026-05-28T04:00:00Z"));
    config.query_issue_id = Some("flywheel_connectors-target".to_string());

    let report = build_state_integrity_report(jsonl, Some(db), Some(bv), &config);

    let query = report.query.as_ref().expect("query report");
    assert_eq!(query.status, IssueQueryStatus::Diverged);
    assert_eq!(
        query.bv_finding.as_ref().map(|finding| finding.kind),
        Some(BvProjectionFindingKind::BvProjectionDiverged)
    );
    assert_eq!(report.bv_findings.len(), 1);
    assert_eq!(
        report.bv_findings[0].diverged_fields,
        vec!["status".to_string()]
    );
    assert!(
        report
            .reason_codes
            .iter()
            .any(|code| code == "bv_projection_diverged")
    );
    assert!(!report.mutation_attempted);
}

#[test]
fn malformed_bv_graph_blocks_without_mutation() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        r#"{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}"#,
    );
    let db = parse_db_snapshot_source(
        "db_snapshot",
        None,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"target","status":"open","priority":1}]}"#,
    );
    let bv = parse_bv_graph_source("bv_graph", None, r#"{"nodes":[]}"#);

    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        Some(bv),
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Blocked);
    assert_eq!(
        report
            .bv
            .as_ref()
            .and_then(|summary| summary.error.as_ref())
            .map(|error| error.kind),
        Some(SourceErrorKind::BvGraphShapeUnsupported)
    );
    assert!(!report.mutation_attempted);
}

#[test]
fn jsonl_conflict_markers_block_parsing_without_mutation() {
    let jsonl = parse_jsonl_source(
        "jsonl",
        None,
        "<<<<<<< HEAD\n{\"id\":\"one\",\"status\":\"open\"}\n=======\n",
    );

    let report =
        build_state_integrity_report(jsonl, None, None, &base_config(ts("2026-05-28T04:00:00Z")));

    assert_eq!(report.overall_status, StateIntegrityStatus::Blocked);
    let error = report.jsonl.error.as_ref().expect("jsonl parse error");
    assert_eq!(error.kind, SourceErrorKind::JsonlConflictMarkers);
    assert!(!report.mutation_attempted);
}

#[test]
fn write_lock_with_process_is_held_not_stale() {
    let tmp = tempdir().expect("tempdir");
    let lock = tmp.path().join(".write.lock");
    fs::write(&lock, "lock").expect("write lock");
    let mut config = base_config(DateTime::<Utc>::from(SystemTime::now()));
    config.lock_path = Some(lock.clone());
    config.active_processes.push(ProcessSnapshot::new(
        Some(1234),
        format!("br update --lock {}", lock.display()),
    ));

    let jsonl = parse_jsonl_source("jsonl", None, "");
    let report = build_state_integrity_report(jsonl, None, None, &config);

    assert_eq!(report.lock.state, LockState::Held);
    assert_eq!(report.lock.matching_processes.len(), 1);
}

#[test]
fn old_write_lock_without_process_is_stale_suspected() {
    let tmp = tempdir().expect("tempdir");
    let lock = tmp.path().join(".write.lock");
    fs::write(&lock, "lock").expect("write lock");
    let mut config = base_config(DateTime::<Utc>::from(SystemTime::now()) + Duration::hours(1));
    config.lock_path = Some(lock);
    config.lock_stale_after = Duration::seconds(1);

    let jsonl = parse_jsonl_source("jsonl", None, "");
    let report = build_state_integrity_report(jsonl, None, None, &config);

    assert_eq!(report.lock.state, LockState::StaleSuspected);
    assert!(
        report
            .lock
            .recommendation
            .contains("ask the human before any lock removal")
    );
}

#[test]
fn matching_sources_without_lock_are_healthy() {
    let raw = r#"{"id":"flywheel_connectors-ok","title":"ok","status":"open","priority":2}"#;
    let jsonl = parse_jsonl_source("jsonl", None, raw);
    let db = parse_db_snapshot_source("db_snapshot", None, &format!(r#"{{"issues":[{raw}]}}"#));

    let report = build_state_integrity_report(
        jsonl,
        Some(db),
        None,
        &base_config(ts("2026-05-28T04:00:00Z")),
    );

    assert_eq!(report.overall_status, StateIntegrityStatus::Healthy);
    assert!(report.issue_findings.is_empty());
    assert!(!report.mutation_attempted);
}

#[test]
fn cli_fixture_reports_healthy_sources_without_mutation() {
    let tmp = tempdir().expect("tempdir");
    let fixture = write_healthy_cli_fixture(tmp.path());

    let report = run_cli_json(
        &fixture.issues,
        Some(&fixture.db),
        Some(&fixture.bv),
        &fixture.lock,
        Some(CLI_TARGET_ISSUE),
        &[],
    );
    assert_eq!(report["overall_status"], "healthy");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["jsonl"]["issue_count"], 1);
    assert_eq!(report["db"]["issue_count"], 1);
    assert_eq!(report["bv"]["issue_count"], 1);
    assert_eq!(report["query"]["status"], "sources_agree");
    assert_eq!(report["lock"]["state"], "missing");
}

#[test]
fn cli_fixture_reports_stale_db_and_flush_refusal_without_mutation() {
    let tmp = tempdir().expect("tempdir");
    let fixture = write_healthy_cli_fixture(tmp.path());

    let stale_db_issues = tmp.path().join("stale-db-issues.jsonl");
    let stale_db = tmp.path().join("stale-db.json");
    fs::write(
        &stale_db_issues,
        r#"{"id":"flywheel_connectors-target","title":"jsonl truth","status":"open","priority":1}"#,
    )
    .expect("write stale DB issues");
    fs::write(&stale_db, r#"{"issues":[]}"#).expect("write stale DB snapshot");
    let report = run_cli_json(
        &stale_db_issues,
        Some(&stale_db),
        None,
        &fixture.lock,
        Some(CLI_TARGET_ISSUE),
        &[],
    );
    assert_eq!(report["overall_status"], "warning");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["issue_findings"][0]["kind"], "jsonl_only");
    assert_eq!(report["query"]["status"], "jsonl_only");
    assert!(has_reason(&report, "issue_count_mismatch"));

    let flush_refusal_issues = tmp.path().join("flush-refusal-issues.jsonl");
    let flush_refusal_db = tmp.path().join("flush-refusal-db.json");
    fs::write(&flush_refusal_issues, "").expect("write flush-refusal issues");
    fs::write(
        &flush_refusal_db,
        r#"{"issues":[{"id":"flywheel_connectors-target","title":"db only","status":"open","priority":1}]}"#,
    )
    .expect("write flush-refusal DB snapshot");
    let report = run_cli_json(
        &flush_refusal_issues,
        Some(&flush_refusal_db),
        None,
        &fixture.lock,
        Some(CLI_TARGET_ISSUE),
        &[],
    );
    assert_eq!(report["overall_status"], "blocked");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["issue_findings"][0]["kind"], "db_only");
    assert_eq!(report["query"]["status"], "db_only");
    assert!(has_recommended_action(&report, "do not run force export"));
}

#[test]
fn cli_fixture_reports_stale_bv_and_conflict_markers_without_mutation() {
    let tmp = tempdir().expect("tempdir");
    let fixture = write_healthy_cli_fixture(tmp.path());

    let stale_bv = tmp.path().join("stale-bv.json");
    fs::write(
        &stale_bv,
        r#"{"format":"json","adjacency":{"nodes":[{"id":"flywheel_connectors-target","title":"target","status":"closed","priority":1}]}}"#,
    )
    .expect("write stale bv graph");
    let report = run_cli_json(
        &fixture.issues,
        Some(&fixture.db),
        Some(&stale_bv),
        &fixture.lock,
        Some(CLI_TARGET_ISSUE),
        &[],
    );
    assert_eq!(report["overall_status"], "blocked");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["bv_findings"][0]["kind"], "bv_projection_diverged");
    assert_eq!(report["query"]["status"], "diverged");
    assert!(has_reason(&report, "bv_projection_diverged"));

    let conflict_issues = tmp.path().join("conflict-issues.jsonl");
    fs::write(&conflict_issues, "<<<<<<< HEAD\n").expect("write conflict issues");
    let report = run_cli_json(
        &conflict_issues,
        Some(&fixture.db),
        None,
        &fixture.lock,
        Some(CLI_TARGET_ISSUE),
        &[],
    );
    assert_eq!(report["overall_status"], "blocked");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["jsonl"]["error"]["kind"], "jsonl_conflict_markers");
    assert!(has_reason(&report, "jsonl_jsonl_conflict_markers"));
}

#[test]
fn cli_fixture_reports_held_lock_without_mutation() {
    let tmp = tempdir().expect("tempdir");
    let fixture = write_healthy_cli_fixture(tmp.path());

    fs::write(&fixture.lock, "lock").expect("write fixture lock");
    let lock_process = format!("br update --lock {}", fixture.lock.display());
    let report = run_cli_json(
        &fixture.issues,
        Some(&fixture.db),
        Some(&fixture.bv),
        &fixture.lock,
        Some(CLI_TARGET_ISSUE),
        &[lock_process],
    );
    assert_eq!(report["overall_status"], "warning");
    assert_eq!(report["mutation_attempted"], false);
    assert_eq!(report["lock"]["state"], "held");
    assert_eq!(
        report["lock"]["matching_processes"]
            .as_array()
            .expect("matching_processes is an array")
            .len(),
        1
    );
    assert!(has_reason(&report, "write_lock_held"));
}
