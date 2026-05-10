//! Conformance coverage for `fwc mesh cutover-gates --json`.

use fwc::mesh_cmd::{
    CutoverGateStatus, MESH_CUTOVER_GATES_SCHEMA_VERSION, MeshCutoverGateArgs,
    cutover_gate_overall_status, mesh_cutover_gates,
};
use fwc::readiness::{CommandAvailability, CommandEnvelope};
use jsonschema::Validator;
use serde_json::{Value, json};
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("mesh_cutover_gates.schema.json")
}

fn load_schema() -> Value {
    let schema =
        std::fs::read_to_string(schema_path()).expect("failed to read mesh cutover gates schema");
    serde_json::from_str(&schema).expect("failed to parse mesh cutover gates schema JSON")
}

fn validator() -> Validator {
    Validator::new(&load_schema()).expect("mesh cutover gates schema must compile")
}

fn valid_cutover_gates_payload() -> Value {
    let args = MeshCutoverGateArgs::default();
    let gates = mesh_cutover_gates(&args);
    let red_gate_ids = gates
        .iter()
        .filter(|gate| matches!(gate.status, CutoverGateStatus::Red))
        .map(|gate| gate.gate_id.clone())
        .collect::<Vec<_>>();
    let availability = serde_json::to_value(CommandEnvelope::new(
        CommandAvailability::OfflineArtifact,
        "mesh",
    ))
    .expect("command envelope must serialize");

    json!({
        "status": "ok",
        "command": "mesh",
        "subcommand": "cutover-gates",
        "schema_version": MESH_CUTOVER_GATES_SCHEMA_VERSION,
        "data_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "live_telemetry": {
            "source": "none",
            "state": "not-requested",
            "reason_code": "host-not-requested",
            "direct_gate_telemetry_available": false,
            "endpoint_hash": Value::Null,
            "catalog_connector_count": Value::Null,
            "missing_routes": [
                "connector-state-root-replication",
                "audit-chain-quorum",
                "policy-object-distribution"
            ],
            "message": "No live host endpoint was provided, so cutover gates remain a fail-closed offline contract."
        },
        "overall_status": cutover_gate_overall_status(&gates).tag(),
        "gate_count": gates.len(),
        "red_gate_ids": red_gate_ids,
        "targets": {
            "min_connectors": args.min_connectors,
            "replica_count": args.replica_count,
            "state_staleness_seconds": args.state_staleness_seconds,
            "audit_staleness_seconds": args.audit_staleness_seconds,
            "policy_peer_count": args.policy_peer_count,
        },
        "measurement_contract": {
            "truth_model": "fail-closed",
            "green_requires": "direct live mesh telemetry for every predicate",
            "proxy_signals_rejected": [
                "README wording",
                "presence of mesh crates",
                "passing unit tests without live gate telemetry",
                "host-first connector status without mesh placement/state evidence"
            ],
        },
        "gates": gates,
        "next_actions": [
            "Run `fwc mesh explain-availability <connector> --host <endpoint> --json` to inspect available connector placement provenance.",
            "Keep the README Mesh-Native Architecture row at `STEADY-STATE TARGET (NOT YET OPERATIONAL)` while any gate is not green.",
            "Add live telemetry routes for the missing gate fields before attempting a mesh-native default flip."
        ],
        "availability": availability,
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
        "mesh cutover gates payload must validate: {errors:?}"
    );
}

fn assert_invalid(instance: &Value, reason: &str) {
    let validator = validator();
    assert!(
        !validator.is_valid(instance),
        "mesh cutover gates payload must be invalid: {reason}"
    );
}

#[test]
fn mesh_cutover_gates_schema_validates_skip_payload() {
    let payload = valid_cutover_gates_payload();

    assert_valid(&payload);
    assert_eq!(payload["schema_version"], "1.2.0");
    assert_eq!(
        payload["data_hash"],
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(payload["overall_status"], "skip");
    assert_eq!(payload["live_telemetry"]["state"], "not-requested");
    assert_eq!(payload["gates"].as_array().map(Vec::len), Some(4));
}

#[test]
fn mesh_cutover_gates_schema_rejects_missing_schema_version() {
    let mut payload = valid_cutover_gates_payload();
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("schema_version");

    assert_invalid(&payload, "schema_version is required");
}

#[test]
fn mesh_cutover_gates_schema_rejects_missing_data_hash() {
    let mut payload = valid_cutover_gates_payload();
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("data_hash");

    assert_invalid(&payload, "data_hash is required for snapshot stability");
}

#[test]
fn mesh_cutover_gates_schema_rejects_malformed_data_hash() {
    let mut payload = valid_cutover_gates_payload();
    payload["data_hash"] = json!("not-a-sha256");

    assert_invalid(&payload, "data_hash must be a prefixed sha256 digest");
}

#[test]
fn mesh_cutover_gates_schema_rejects_missing_live_telemetry() {
    let mut payload = valid_cutover_gates_payload();
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("live_telemetry");

    assert_invalid(&payload, "live telemetry is required for skip provenance");
}

#[test]
fn mesh_cutover_gates_schema_rejects_unknown_live_telemetry_state() {
    let mut payload = valid_cutover_gates_payload();
    payload["live_telemetry"]["state"] = json!("maybe");

    assert_invalid(&payload, "live telemetry state is a closed enum");
}

#[test]
fn mesh_cutover_gates_schema_rejects_unknown_top_level_fields() {
    let mut payload = valid_cutover_gates_payload();
    payload["undocumented_field"] = json!(true);

    assert_invalid(&payload, "top-level schema is fail-closed");
}

#[test]
fn mesh_cutover_gates_schema_rejects_unknown_gate_status() {
    let mut payload = valid_cutover_gates_payload();
    payload["gates"][0]["status"] = json!("amber");

    assert_invalid(&payload, "gate status is a closed enum");
}

#[test]
fn mesh_cutover_gates_schema_rejects_gate_without_remediation() {
    let mut payload = valid_cutover_gates_payload();
    payload["gates"][0]
        .as_object_mut()
        .expect("gate must be an object")
        .remove("remediation");

    assert_invalid(&payload, "each gate must include remediation");
}
