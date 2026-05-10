//! Conformance coverage for `fwc connector state explain --json`.

use fwc::connector_state::{
    CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION, ConnectorStateExplainRequest,
    connector_state_explain_payload,
};
use fwc::readiness::DiscoveryCatalog;
use jsonschema::Validator;
use serde_json::{Value, json};
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("connector_state_explain.schema.json")
}

fn load_schema() -> Value {
    let schema =
        std::fs::read_to_string(schema_path()).expect("failed to read connector state schema");
    serde_json::from_str(&schema).expect("failed to parse connector state schema JSON")
}

fn validator() -> Validator {
    Validator::new(&load_schema()).expect("connector state explain schema must compile")
}

fn state_root_fixture() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fcp-connector-state-schema-nonexistent-{}",
        uuid::Uuid::new_v4()
    ))
}

fn github_explain_payload(zone: Option<&str>, explicit_host: Option<&str>) -> Value {
    let state_root = state_root_fixture();
    let catalog = DiscoveryCatalog::load_for_connector_filter(Some("github"))
        .expect("github connector catalog should load");
    let connector = catalog
        .resolve_connector("github")
        .expect("github connector should resolve");
    let request = ConnectorStateExplainRequest {
        connector_selector: "github",
        zone,
        state_root: Some(&state_root),
        explicit_host,
    };

    connector_state_explain_payload(connector, &request)
}

fn assert_valid(instance: &Value) {
    let validator = validator();
    let errors = validator
        .iter_errors(instance)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "connector state explain payload must validate: {errors:?}"
    );
}

fn assert_invalid(instance: &Value, reason: &str) {
    let validator = validator();
    assert!(
        !validator.is_valid(instance),
        "connector state explain payload must be invalid: {reason}"
    );
}

#[test]
fn connector_state_explain_schema_validates_local_payload() {
    let payload = github_explain_payload(Some("z:work"), None);

    assert_valid(&payload);
    assert_eq!(
        payload["schema_version"],
        CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION
    );
    assert_eq!(payload["command"], "connector");
    assert_eq!(payload["subcommand"], "state explain");
    assert_eq!(payload["canonical_storage"], "local");
    assert_eq!(payload["connector"]["canonical_id"], "fcp.github");
    assert_eq!(payload["zone"]["requested"], "z:work");
    assert_eq!(payload["live_host"]["state"], "not-requested");
    assert_eq!(payload["availability"]["availability"], "offline-artifact");
}

#[test]
fn connector_state_explain_schema_validates_host_requested_payload() {
    let payload = github_explain_payload(None, Some("https://host.example.invalid:8443"));

    assert_valid(&payload);
    assert_eq!(payload["zone"]["requested"], Value::Null);
    assert_eq!(payload["live_host"]["requested"], true);
    assert_eq!(payload["live_host"]["state"], "not-queried");
    assert!(
        payload["live_host"]["endpoint_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
    );
}

#[test]
fn connector_state_explain_schema_rejects_missing_schema_version() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload
        .as_object_mut()
        .expect("payload must be an object")
        .remove("schema_version");

    assert_invalid(&payload, "schema_version is required");
}

#[test]
fn connector_state_explain_schema_rejects_unknown_top_level_fields() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["undocumented_field"] = json!(true);

    assert_invalid(&payload, "top-level schema is fail-closed");
}

#[test]
fn connector_state_explain_schema_rejects_unknown_canonical_storage() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["canonical_storage"] = json!("maybe");

    assert_invalid(&payload, "canonical storage is a closed enum");
}

#[test]
fn connector_state_explain_schema_rejects_non_numeric_sequence() {
    let mut payload = github_explain_payload(Some("z:work"), None);
    payload["last_canonical_seq"] = json!("100");

    assert_invalid(
        &payload,
        "last canonical sequence must be null or an integer",
    );
}

#[test]
fn connector_state_explain_schema_is_fail_closed() {
    let schema = load_schema();

    assert_eq!(
        schema.get("additionalProperties"),
        Some(&Value::Bool(false)),
        "top-level connector state explain schema must reject unknown fields"
    );
    assert!(
        schema.get("$defs").is_some(),
        "schema should define reusable closed shapes"
    );
}
