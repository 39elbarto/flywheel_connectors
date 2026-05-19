//! CLI coverage for `fwc audit chain status --json`.

use std::process::{Command, Output};

use serde_json::{Value, json};

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

fn write_json(path: &std::path::Path, value: &Value) {
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture serializes"),
    )
    .expect("fixture writes");
}

#[test]
fn missing_status_is_fail_closed_and_parseable() {
    let output = run_fwc(&["audit", "chain", "status", "--json"]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_chain_status.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["command"], "audit");
    assert_eq!(payload["subcommand"], "chain status");
    assert_eq!(payload["status"], "missing");
    assert_eq!(payload["telemetry_state"], "missing");
    assert_eq!(payload["source"]["kind"], "none");
    assert_eq!(payload["source"]["live"], false);
    assert_eq!(payload["quorum_signed_checkpoints"], 0);
    assert_eq!(payload["quorum_signers"], 0);
    assert!(payload["last_quorum_height"].is_null());
    assert_eq!(
        payload["warnings"]
            .as_array()
            .expect("warnings array")
            .len(),
        1
    );
}

#[test]
fn signed_head_status_derives_quorum_from_attached_signatures() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let head_path = tempdir.path().join("head.json");
    let events_path = tempdir.path().join("events.json");
    write_json(
        &head_path,
        &json!({
            "zone_id": "z:work",
            "head_entry": "entry-work-head",
            "head_seq": 42,
            "coverage": 0.95,
            "epoch_id": "epoch-7",
            "signature_count": 2,
            "signatures": [
                {"issuer_kid": "kid-a", "signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                {"issuer_kid": "kid-b", "signature": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
            ]
        }),
    );
    write_json(
        &events_path,
        &json!([
            {
                "id": "entry-work-head",
                "event_type": "audit.checkpoint",
                "severity": "info",
                "actor": "node-a",
                "zone_id": "z:work",
                "seq": 42,
                "occurred_at": 1_700_000_000,
                "hlc": {
                    "physical_ms": 1_700_000_000_123_u64,
                    "logical": 0,
                    "node_id": "node-a"
                }
            }
        ]),
    );

    let output = run_fwc(&[
        "audit",
        "chain",
        "status",
        "--head",
        head_path.to_str().expect("head path UTF-8"),
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--now-unix-secs",
        "1700000030",
        "--max-age-seconds",
        "60",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["status"], "fresh");
    assert_eq!(payload["telemetry_state"], "artifact");
    assert_eq!(payload["source"]["kind"], "signed-head-artifact");
    assert_eq!(payload["source"]["live"], false);
    assert_eq!(payload["zone_id"], "z:work");
    assert_eq!(payload["head_seq"], 42);
    assert_eq!(payload["last_quorum_height"], 42);
    assert_eq!(payload["quorum_signed_checkpoints"], 1);
    assert_eq!(payload["quorum_signers"], 2);
    assert_eq!(payload["quorum_signer_ids"], json!(["kid-a", "kid-b"]));
    assert_eq!(payload["producer_signature_count"], 2);
    assert_eq!(payload["signature_count_consistent"], true);
    assert_eq!(payload["quorum_freshness_secs"], 30);
    assert_eq!(payload["quorum_rotation_epoch"], "epoch-7");
    assert_eq!(payload["hlc_physical_drift_ms"], 29_877);
    assert_eq!(payload["warnings"], json!([]));
}

#[test]
fn bare_signature_count_does_not_create_quorum() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let head_path = tempdir.path().join("head.json");
    write_json(
        &head_path,
        &json!({
            "zone_id": "z:work",
            "head_entry": "entry-forged",
            "head_seq": 9,
            "coverage": 1.0,
            "epoch_id": "epoch-forged",
            "signature_count": 7
        }),
    );

    let output = run_fwc(&[
        "audit",
        "chain",
        "status",
        "--head",
        head_path.to_str().expect("head path UTF-8"),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["status"], "degraded");
    assert_eq!(payload["quorum_signed_checkpoints"], 0);
    assert_eq!(payload["quorum_signers"], 0);
    assert!(payload["last_quorum_height"].is_null());
    assert_eq!(payload["producer_signature_count"], 7);
    assert_eq!(payload["signature_count_consistent"], false);
    let warnings = payload["warnings"].as_array().expect("warnings array");
    assert!(warnings.iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|text| text.contains("attached signatures"))
    }));
}

#[test]
fn chain_status_require_any_live_fails_with_truth_source_unavailable() {
    let output = run_fwc(&[
        "audit",
        "chain",
        "status",
        "--json",
        "--require-source",
        "any-live",
    ]);

    assert!(
        !output.status.success(),
        "fwc unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["command"], "audit");
    assert_eq!(payload["subcommand"], "chain status");
    assert_eq!(payload["schema_version"], "fcp.fwc.truth-source.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["error"]["type"], "truth-source-unavailable");
    assert_eq!(payload["error"]["required"], "any-live");
    assert_eq!(payload["error"]["actual"], "offline");
}

#[test]
fn audit_verify_json_reports_offline_truth_source() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let events_path = tempdir.path().join("events.jsonl");
    std::fs::write(&events_path, "").expect("events writes");

    let output = run_fwc(&[
        "audit",
        "verify",
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "fwc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["schema_version"], "fcp.fwc.audit_verify.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["status"], "warn");
    assert_eq!(payload["chain_len"], 0);
    assert_eq!(payload["issues"][0]["code"], "audit.chain.empty");
}

#[test]
fn audit_verify_require_any_live_fails_with_truth_source_unavailable() {
    let tempdir = tempfile::tempdir().expect("tempdir creates");
    let events_path = tempdir.path().join("events.jsonl");
    std::fs::write(&events_path, "").expect("events writes");

    let output = run_fwc(&[
        "audit",
        "verify",
        "--events",
        events_path.to_str().expect("events path UTF-8"),
        "--json",
        "--require-source",
        "any-live",
    ]);

    assert!(
        !output.status.success(),
        "fwc unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = stdout_json(&output);
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["command"], "audit");
    assert_eq!(payload["subcommand"], "verify");
    assert_eq!(payload["schema_version"], "fcp.fwc.truth-source.v1");
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["error"]["type"], "truth-source-unavailable");
    assert_eq!(payload["error"]["required"], "any-live");
    assert_eq!(payload["error"]["actual"], "offline");
}
