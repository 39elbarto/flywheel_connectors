//! CLI coverage for `fwc audit explain` artifact filtering.

use std::path::Path;
use std::process::{Command, Output};

use fcp_audit::{AuditEntry, AuditEntryBuilder, Decision, DecisionReceipt, Severity, event_types};
use serde_json::{Value, json};

const NOW: u64 = 1_700_086_400;

fn audit_entry(
    id: &str,
    zone_id: &str,
    seq: u64,
    occurred_at: u64,
    event_type: &str,
    metadata: Vec<(&str, Value)>,
) -> AuditEntry {
    metadata
        .into_iter()
        .fold(
            AuditEntryBuilder::new()
                .id(id)
                .event_type(event_type)
                .severity(Severity::Info)
                .actor("agent:codex")
                .zone_id(zone_id)
                .seq(seq)
                .occurred_at(occurred_at)
                .correlation_id("corr-work")
                .connector_id("fcp.slack:base:v1")
                .operation_id("messages.send"),
            |builder, (key, value)| builder.meta(key, value),
        )
        .build()
        .expect("audit entry builds")
}

fn invocation(id: &str, zone_id: &str, seq: u64, occurred_at: u64) -> AuditEntry {
    audit_entry(
        id,
        zone_id,
        seq,
        occurred_at,
        event_types::CAPABILITY_INVOKE,
        vec![],
    )
}

fn receipt_for(entry: &AuditEntry) -> DecisionReceipt {
    DecisionReceipt {
        id: format!("receipt-{}", entry.id),
        request_id: format!("request-{}", entry.id),
        decision: Decision::Allow,
        reason_code: "policy.allow.zone_work".to_string(),
        evidence: vec![entry.id.clone()],
        audit_entry_id: Some(entry.id.clone()),
        explanation: Some("work zone policy allowed messages.send".to_string()),
        decided_at: entry.occurred_at,
        zone_id: entry.zone_id.clone(),
        correlation_id: Some(entry.correlation_id.clone()),
        trace_context: None,
        connector_id: entry.connector_id.clone(),
        operation_id: entry.operation_id.clone(),
        confidence: None,
        issuer_kid: None,
        signature: None,
    }
}

fn write_bundle(path: &Path, entries: &[AuditEntry], receipts: &[DecisionReceipt]) {
    let bundle = json!({
        "audit_entries": entries,
        "capability_tokens": [{
            "id": "tok-work",
            "capability_id": "messages.send",
            "connector_id": "fcp.slack:base:v1",
            "operation_id": "messages.send",
            "correlation_id": "corr-work",
            "issuer_kid": "kid-work"
        }],
        "receipts": receipts
    });
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&bundle).expect("bundle serializes"),
    )
    .expect("bundle writes");
}

fn run_fwc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwc"))
        .args(args)
        .output()
        .expect("fwc process should launch")
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout should be JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn entry_ids(payload: &Value) -> Vec<String> {
    payload["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|entry| entry["id"].as_str().expect("entry id").to_string())
        .collect()
}

#[test]
fn test_zone_filter_excludes_other_zones() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let path = tempdir.path().join("bundle.json");
    let work = invocation("entry-work", "z:work", 1, NOW - 60);
    let private = invocation("entry-private", "z:private", 2, NOW);
    write_bundle(&path, &[work.clone(), private], &[receipt_for(&work)]);

    let output = run_fwc(&[
        "audit",
        "explain",
        path.to_str().expect("temp path UTF-8"),
        "--zone",
        "z:work",
        "--json",
    ]);

    assert!(output.status.success());
    let payload = stdout_json(&output);
    assert_eq!(payload["filters"]["zone_id"], "z:work");
    assert_eq!(entry_ids(&payload), vec!["entry-work"]);
    assert_eq!(payload["entries"][0]["zone_id"], "z:work");
}

#[test]
fn test_since_filter_excludes_older_entries() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let path = tempdir.path().join("bundle.json");
    let old = invocation("entry-old", "z:work", 1, NOW - 90_000);
    let recent = invocation("entry-recent", "z:work", 2, NOW);
    write_bundle(&path, &[old, recent.clone()], &[receipt_for(&recent)]);

    let output = run_fwc(&[
        "audit",
        "explain",
        path.to_str().expect("temp path UTF-8"),
        "--since",
        "24h",
        "--json",
    ]);

    assert!(output.status.success());
    let payload = stdout_json(&output);
    assert_eq!(payload["filters"]["since_seconds"], 86_400);
    assert_eq!(entry_ids(&payload), vec!["entry-recent"]);
}

#[test]
fn test_tombstoned_entries_surfaced_with_marker() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let path = tempdir.path().join("bundle.json");
    let invocation = invocation("entry-invoke", "z:work", 1, NOW);
    let tombstone = audit_entry(
        "entry-tombstone",
        "z:work",
        2,
        NOW,
        "capability.tombstone",
        vec![("tombstoned", json!(true))],
    );
    write_bundle(
        &path,
        &[invocation.clone(), tombstone],
        &[receipt_for(&invocation)],
    );

    let output = run_fwc(&[
        "audit",
        "explain",
        path.to_str().expect("temp path UTF-8"),
        "--zone",
        "z:work",
        "--json",
    ]);

    assert!(output.status.success());
    let payload = stdout_json(&output);
    let tombstone = payload["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .find(|entry| entry["id"] == "entry-tombstone")
        .expect("tombstone entry");
    assert!(
        tombstone["tombstoned"]
            .as_bool()
            .expect("tombstoned marker is bool")
    );
}

#[test]
fn test_quorum_height_signers_present() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let path = tempdir.path().join("bundle.json");
    let invocation = audit_entry(
        "entry-quorum",
        "z:work",
        7,
        NOW,
        event_types::CAPABILITY_INVOKE,
        vec![
            ("quorum_height", json!(42)),
            ("signers", json!(["node-a", "node-b", "node-c"])),
        ],
    );
    write_bundle(
        &path,
        std::slice::from_ref(&invocation),
        &[receipt_for(&invocation)],
    );

    let output = run_fwc(&[
        "audit",
        "explain",
        path.to_str().expect("temp path UTF-8"),
        "--json",
    ]);

    assert!(output.status.success());
    let payload = stdout_json(&output);
    assert_eq!(payload["entries"][0]["quorum_height"], 42);
    assert_eq!(
        payload["entries"][0]["quorum_signers"],
        json!(["node-a", "node-b", "node-c"])
    );
}

#[test]
fn test_decision_rationale_present() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let path = tempdir.path().join("bundle.json");
    let invocation = invocation("entry-rationale", "z:work", 3, NOW);
    write_bundle(
        &path,
        std::slice::from_ref(&invocation),
        &[receipt_for(&invocation)],
    );

    let output = run_fwc(&[
        "audit",
        "explain",
        path.to_str().expect("temp path UTF-8"),
        "--json",
    ]);

    assert!(output.status.success());
    let payload = stdout_json(&output);
    assert_eq!(
        payload["entries"][0]["decision_rationale"],
        "work zone policy allowed messages.send"
    );
    assert_eq!(
        payload["entries"][0]["reason_code"],
        "policy.allow.zone_work"
    );
}

#[test]
fn audit_explain_appears_in_help_output() {
    let output = run_fwc(&["audit", "--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(stdout.contains("explain"));
    assert!(stdout.contains("causal audit narrative"));
}
