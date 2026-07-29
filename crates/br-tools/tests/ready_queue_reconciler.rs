use br_tools::ready_queue_reconciler::{
    ReadyQueueConfig, ReadyQueueState, ReadyQueueStatus, build_ready_queue_report,
    parse_br_snapshot_source, parse_bv_triage_source, parse_jsonl_source,
};
use chrono::{DateTime, Utc};
use serde_json::json;

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(DateTime::from)
        .expect("test timestamp is valid")
}

fn bv_recommendations(ids: &[&str]) -> String {
    let recommendations = ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "title": format!("title for {id}"),
                "status": "open",
            })
        })
        .collect::<Vec<_>>();
    json!({ "triage": { "recommendations": recommendations } }).to_string()
}

fn report(jsonl: &[&str], bv_ids: &[&str]) -> br_tools::ready_queue_reconciler::ReadyQueueReport {
    build_ready_queue_report(
        parse_jsonl_source(None, &jsonl.join("\n")),
        parse_bv_triage_source(None, &bv_recommendations(bv_ids)),
        None,
        &ReadyQueueConfig::default_with_now(ts("2026-05-28T12:00:00Z")),
    )
}

#[test]
fn closed_in_jsonl_recommendation_is_not_claimable() {
    let report = report(
        &[r#"{"id":"flywheel_connectors-closed","title":"done","status":"closed"}"#],
        &["flywheel_connectors-closed"],
    );

    let row = &report.recommendations[0];
    assert_eq!(row.state, ReadyQueueState::ClosedInJsonl);
    assert!(!row.claimable);
    assert_eq!(
        row.suggested_next_command,
        "br show flywheel_connectors-closed --json --no-db"
    );
    assert!(
        row.reason_codes
            .iter()
            .any(|code| code == "jsonl_status:closed")
    );
}

#[test]
fn blocked_parent_points_at_open_executable_child() {
    let report = report(
        &[
            r#"{"id":"flywheel_connectors-parent","title":"umbrella","status":"blocked","priority":1}"#,
            r#"{"id":"flywheel_connectors-child","title":"child","status":"open","priority":2,"dependencies":[{"depends_on_id":"flywheel_connectors-parent","type":"parent-child"}]}"#,
        ],
        &["flywheel_connectors-parent"],
    );

    let row = &report.recommendations[0];
    assert_eq!(row.state, ReadyQueueState::BlockedLivePrereq);
    assert_eq!(
        row.suggested_issue_id.as_deref(),
        Some("flywheel_connectors-child")
    );
    assert_eq!(
        row.suggested_next_command,
        "br show flywheel_connectors-child --json"
    );
    assert!(
        row.reason_codes
            .iter()
            .any(|code| code == "blocked_parent_has_open_child")
    );
}

#[test]
fn db_jsonl_divergence_blocks_claiming() {
    let jsonl = parse_jsonl_source(
        None,
        r#"{"id":"flywheel_connectors-drift","title":"current title","status":"open","priority":2}"#,
    );
    let bv = parse_bv_triage_source(None, &bv_recommendations(&["flywheel_connectors-drift"]));
    let br_snapshot = parse_br_snapshot_source(
        None,
        r#"{"id":"flywheel_connectors-drift","title":"stale title","status":"open","priority":2}"#,
    );

    let report = build_ready_queue_report(
        jsonl,
        bv,
        Some(br_snapshot),
        &ReadyQueueConfig::default_with_now(ts("2026-05-28T12:00:00Z")),
    );

    let row = &report.recommendations[0];
    assert_eq!(row.state, ReadyQueueState::DbJsonlDiverged);
    assert!(!row.claimable);
    assert_eq!(
        row.suggested_next_command,
        "br show flywheel_connectors-drift --json && br show flywheel_connectors-drift --json --no-db"
    );
}

#[test]
fn clean_open_unassigned_issue_is_claimable() {
    let report = report(
        &[r#"{"id":"flywheel_connectors-claimable","title":"ready","status":"open","priority":2}"#],
        &["flywheel_connectors-claimable"],
    );

    let row = &report.recommendations[0];
    assert_eq!(row.state, ReadyQueueState::Claimable);
    assert!(row.claimable);
    assert_eq!(report.overall_status, ReadyQueueStatus::Healthy);
    assert_eq!(
        row.suggested_next_command,
        "br update flywheel_connectors-claimable --status in_progress"
    );
    assert!(!report.mutation_attempted);
}

#[test]
fn live_endpoint_or_remote_proof_recommendation_requires_prereq_review() {
    let report = report(
        &[
            r#"{"id":"flywheel_connectors-live","title":"Live endpoint remote proof for SaaS connector","status":"open","labels":["live-proof"],"priority":1}"#,
        ],
        &["flywheel_connectors-live"],
    );

    let row = &report.recommendations[0];
    assert_eq!(row.state, ReadyQueueState::BlockedLivePrereq);
    assert!(!row.claimable);
    assert_eq!(report.overall_status, ReadyQueueStatus::Blocked);
    assert!(
        row.reason_codes
            .iter()
            .any(|code| code == "live_or_remote_prereq")
    );
}
