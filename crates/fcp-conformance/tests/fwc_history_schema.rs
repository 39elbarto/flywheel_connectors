//! Conformance coverage for `fwc history --json`.

use chrono::Utc;
use fwc::readiness::{CommandAvailability, CommandEnvelope};
use jsonschema::Validator;
use serde_json::{Value, json};
use std::path::PathBuf;

const HISTORY_SCHEMA_VERSION: &str = "fcp.fwc.truth-source.v1";

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("history.schema.json")
}

fn load_schema() -> Value {
    let schema = std::fs::read_to_string(schema_path()).expect("failed to read history schema");
    serde_json::from_str(&schema).expect("failed to parse history schema JSON")
}

fn validator() -> Validator {
    Validator::new(&load_schema()).expect("history schema must compile")
}

fn availability() -> Value {
    serde_json::to_value(CommandEnvelope::new(
        CommandAvailability::OfflineArtifact,
        "history",
    ))
    .expect("availability envelope must serialize")
}

fn unavailable_availability() -> Value {
    serde_json::to_value(CommandEnvelope::new(
        CommandAvailability::Unavailable,
        "history",
    ))
    .expect("availability envelope must serialize")
}

fn sample_entry(status: &str) -> Value {
    json!({
        "entry_id": "hist-001",
        "timestamp": Utc::now().to_rfc3339(),
        "connector_id": "fcp.github",
        "operation_id": "github.list_repos",
        "zone": "z:work",
        "input_hash": "0123456789abcdef",
        "input_summary": "per_page=10",
        "output_hash": "fedcba9876543210",
        "output_summary": "repos=[0 items]",
        "status": status,
        "latency_ms": 12,
        "agent_session": "agent-session-001",
    })
}

fn history_list_payload() -> Value {
    json!({
        "status": "ok",
        "command": "history",
        "scope": "list",
        "schema_version": HISTORY_SCHEMA_VERSION,
        "_truth_source": "offline",
        "total_entries": 1,
        "returned": 1,
        "filter": {
            "connector": "fcp.github",
            "status": "success",
            "since": "1h",
            "limit": 20
        },
        "entries": [sample_entry("success")],
        "next_actions": [
            "fwc history <entry_id>",
            "fwc history --connector github"
        ],
        "availability": availability()
    })
}

fn history_entry_payload() -> Value {
    json!({
        "status": "ok",
        "command": "history",
        "scope": "entry",
        "schema_version": HISTORY_SCHEMA_VERSION,
        "_truth_source": "offline",
        "entry": sample_entry("denied"),
        "availability": availability()
    })
}

fn not_found_payload() -> Value {
    json!({
        "status": "error",
        "command": "history",
        "schema_version": HISTORY_SCHEMA_VERSION,
        "_truth_source": "offline",
        "error": {
            "type": "not-found",
            "message": "No history entry with ID 'missing'."
        },
        "next_actions": ["fwc history"]
    })
}

fn truth_source_unavailable_payload() -> Value {
    json!({
        "status": "error",
        "command": "history",
        "schema_version": HISTORY_SCHEMA_VERSION,
        "_truth_source": "offline",
        "error": {
            "type": "truth-source-unavailable",
            "required": "any-live",
            "actual": "offline",
            "message": "`fwc history` resolved from `offline` truth, which does not satisfy `--require-source any-live`.",
            "recoverable": true
        },
        "next_actions": [
            "Retry after the required live truth source is reachable.",
            "Relax the requirement if `offline` truth is acceptable for this workflow."
        ],
        "availability": unavailable_availability()
    })
}

fn assert_valid(instance: &Value) {
    let validator = validator();
    let errors = validator
        .iter_errors(instance)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "history payload must validate: {errors:?}"
    );
}

fn assert_invalid(instance: &Value, reason: &str) {
    let validator = validator();
    assert!(
        !validator.is_valid(instance),
        "history payload must be invalid: {reason}"
    );
}

#[test]
fn history_schema_validates_list_payload() {
    let payload = history_list_payload();

    assert_valid(&payload);
    assert_eq!(payload["schema_version"], HISTORY_SCHEMA_VERSION);
    assert_eq!(payload["_truth_source"], "offline");
    assert_eq!(payload["scope"], "list");
}

#[test]
fn history_schema_accepts_registered_truth_source_tags() {
    for source in [
        "mesh",
        "host",
        "node-local",
        "offline",
        "degraded",
        "fallback-derived",
        "simulated",
        "unavailable",
    ] {
        let mut payload = history_list_payload();
        payload["_truth_source"] = json!(source);

        assert_valid(&payload);
    }
}

#[test]
fn history_schema_validates_entry_payload() {
    let payload = history_entry_payload();

    assert_valid(&payload);
    assert_eq!(payload["scope"], "entry");
    assert_eq!(payload["entry"]["status"], "denied");
}

#[test]
fn history_schema_validates_not_found_payload() {
    let payload = not_found_payload();

    assert_valid(&payload);
    assert_eq!(payload["error"]["type"], "not-found");
}

#[test]
fn history_schema_validates_truth_source_unavailable_payload() {
    let payload = truth_source_unavailable_payload();

    assert_valid(&payload);
    assert_eq!(payload["error"]["type"], "truth-source-unavailable");
    assert_eq!(payload["availability"]["availability"], "unavailable");
}

#[test]
fn history_schema_rejects_missing_schema_version() {
    let mut payload = history_list_payload();
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("schema_version");

    assert_invalid(&payload, "schema_version is required");
}

#[test]
fn history_schema_rejects_unknown_top_level_field() {
    let mut payload = history_list_payload();
    payload["undocumented"] = json!(true);

    assert_invalid(&payload, "top-level schema is fail-closed");
}

#[test]
fn history_schema_rejects_unknown_entry_status() {
    let mut payload = history_list_payload();
    payload["entries"][0]["status"] = json!("maybe");

    assert_invalid(&payload, "history status is a closed enum");
}

#[test]
fn history_schema_rejects_unknown_truth_source_requirement() {
    let mut payload = truth_source_unavailable_payload();
    payload["error"]["required"] = json!("offline");

    assert_invalid(&payload, "require-source values are a closed enum");
}
