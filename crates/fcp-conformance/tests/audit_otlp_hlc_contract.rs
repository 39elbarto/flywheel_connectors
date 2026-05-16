//! Conformance guard for the audit-chain OTLP HLC attribute contract.

use std::path::{Path, PathBuf};

use jsonschema::Validator;
use serde_json::Value;

fn fwc_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("schemas")
        .join("audit_otlp_span.schema.json")
}

fn fwc_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fwc")
        .join("tests")
        .join("fixtures")
        .join("audit_otlp_parity")
        .join("golden_accepted_span.json")
}

fn load_json(path: &Path) -> Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn assert_valid(schema: &Value, instance: &Value) {
    let validator = Validator::new(schema).expect("audit OTLP schema must compile");
    let errors = validator
        .iter_errors(instance)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "audit OTLP golden fixture must validate: {errors:?}"
    );
}

#[test]
fn audit_otlp_span_requires_explicit_hlc_components() {
    let schema = load_json(&fwc_schema_path());
    let attributes = &schema["properties"]["attributes"];
    let required = attributes["required"]
        .as_array()
        .expect("attributes.required must be an array");
    let properties = attributes["properties"]
        .as_object()
        .expect("attributes.properties must be an object");

    for field in [
        "fcp.audit.entry.hlc",
        "fcp.audit.entry.hlc.l",
        "fcp.audit.entry.hlc.c",
        "fcp.audit.entry.hlc.node_id",
    ] {
        assert!(
            required.iter().any(|value| value.as_str() == Some(field)),
            "{field} must be required"
        );
        assert!(properties.contains_key(field), "{field} must be defined");
    }

    assert_eq!(properties["fcp.audit.entry.hlc.l"]["type"], "integer");
    assert_eq!(properties["fcp.audit.entry.hlc.c"]["type"], "integer");
    assert_eq!(properties["fcp.audit.entry.hlc.node_id"]["type"], "string");
}

#[test]
fn audit_otlp_golden_span_carries_hlc_components() {
    let schema = load_json(&fwc_schema_path());
    let fixture = load_json(&fwc_fixture_path());
    assert_valid(&schema, &fixture);

    let attributes = fixture["attributes"]
        .as_object()
        .expect("golden span must carry attributes");
    let hlc_l = attributes["fcp.audit.entry.hlc.l"]
        .as_u64()
        .expect("hlc.l must be an integer");
    let hlc_c = attributes["fcp.audit.entry.hlc.c"]
        .as_u64()
        .expect("hlc.c must be an integer");
    let hlc_node = attributes["fcp.audit.entry.hlc.node_id"]
        .as_str()
        .expect("hlc.node_id must be a string");

    assert_eq!(fixture["start_time_unix_nano"].as_u64(), Some(hlc_l));
    let expected_hlc = format!("{hlc_l}.{hlc_c}");
    assert_eq!(
        attributes["fcp.audit.entry.hlc"].as_str(),
        Some(expected_hlc.as_str())
    );
    assert_eq!(hlc_node, "host-alpha-01");
}
