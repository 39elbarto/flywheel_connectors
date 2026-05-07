#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::{BTreeMap, BTreeSet};

use fcp_tlon::TlonConnector;
use serde_json::Value;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_COUNT: usize = 3;

fn manifest() -> toml::Table {
    MANIFEST_TOML
        .parse::<toml::Table>()
        .expect("Tlon manifest should parse as TOML")
}

fn manifest_operations(manifest: &toml::Table) -> &toml::map::Map<String, toml::Value> {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("Tlon manifest should declare operations")
}

fn manifest_schema(manifest: &toml::Table, operation_id: &str, field: &str) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_id)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get(field))
        .expect("manifest operation should declare requested schema field");
    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn validator_for(schema: &Value) -> jsonschema::Validator {
    jsonschema::Validator::new(schema).expect("operation schema should compile as JSON Schema")
}

async fn runtime_operations() -> Vec<Value> {
    let connector = TlonConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("Tlon introspection should succeed");
    introspection["operations"]
        .as_array()
        .expect("operations should be an array")
        .clone()
}

fn as_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .expect("runtime operation should have requested string field")
}

#[fcp_async_core::runtime::test]
async fn runtime_catalog_matches_manifest_operation_contracts() {
    let manifest = manifest();
    let manifest_operations = manifest_operations(&manifest);
    let runtime_operations = runtime_operations().await;

    assert_eq!(
        manifest_operations.len(),
        EXPECTED_OPERATION_COUNT,
        "manifest operation count changed; update Tlon conformance expectations"
    );
    assert_eq!(
        runtime_operations.len(),
        EXPECTED_OPERATION_COUNT,
        "runtime operation count changed; update Tlon conformance expectations"
    );

    let runtime_by_id: BTreeMap<&str, &Value> = runtime_operations
        .iter()
        .map(|operation| (as_str(operation, "id"), operation))
        .collect();
    let manifest_ids = manifest_operations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let runtime_ids = runtime_by_id.keys().copied().collect::<BTreeSet<_>>();
    assert_eq!(manifest_ids, runtime_ids);

    for (operation_id, manifest_operation) in manifest_operations {
        let manifest_operation = manifest_operation
            .as_table()
            .expect("manifest operation should be a table");
        let runtime_operation = runtime_by_id
            .get(operation_id.as_str())
            .expect("runtime catalog should expose manifest operation");

        assert_eq!(
            as_str(runtime_operation, "capability"),
            manifest_operation["capability"]
                .as_str()
                .expect("manifest operation capability")
        );
        assert_eq!(
            as_str(runtime_operation, "risk_level"),
            manifest_operation["risk_level"]
                .as_str()
                .expect("manifest operation risk_level")
        );
        assert_eq!(
            as_str(runtime_operation, "safety_tier"),
            manifest_operation["safety_tier"]
                .as_str()
                .expect("manifest operation safety_tier")
        );
        assert_eq!(
            as_str(runtime_operation, "idempotency"),
            manifest_operation["idempotency"]
                .as_str()
                .expect("manifest operation idempotency")
        );
        assert_eq!(runtime_operation["implemented"], false);

        validator_for(&runtime_operation["input_schema"]);
        validator_for(&runtime_operation["output_schema"]);
        validator_for(&manifest_schema(&manifest, operation_id, "input_schema"));
        validator_for(&manifest_schema(&manifest, operation_id, "output_schema"));

        assert!(
            runtime_operation["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|hint| !hint.trim().is_empty()),
            "{operation_id} should advertise runtime ai_hints.when_to_use"
        );
        assert!(
            manifest_operation
                .get("ai_hints")
                .and_then(toml::Value::as_table)
                .and_then(|hints| hints.get("when_to_use"))
                .and_then(toml::Value::as_str)
                .is_some_and(|hint| !hint.trim().is_empty()),
            "{operation_id} should advertise manifest ai_hints.when_to_use"
        );
    }
}

#[test]
fn manifest_schemas_are_strict_and_cover_required_fields() {
    let manifest = manifest();

    for operation_id in manifest_operations(&manifest).keys() {
        for field in ["input_schema", "output_schema"] {
            let schema = manifest_schema(&manifest, operation_id, field);
            validator_for(&schema);
            assert_eq!(schema["type"], "object", "{operation_id} {field}");
            assert_eq!(
                schema["additionalProperties"], false,
                "{operation_id} {field} should reject unknown top-level fields"
            );
            let required = schema["required"]
                .as_array()
                .expect("schema should declare required fields");
            let properties = schema["properties"]
                .as_object()
                .expect("schema should declare properties");
            for required_field in required {
                let required_field = required_field
                    .as_str()
                    .expect("required field should be a string");
                assert!(
                    properties.contains_key(required_field),
                    "{operation_id} {field} requires {required_field} but does not declare it"
                );
            }
        }
    }
}

#[fcp_async_core::runtime::test]
async fn operation_risk_safety_idempotency_and_incubation_are_stable() {
    let runtime_operations = runtime_operations().await;
    let by_id: BTreeMap<&str, &Value> = runtime_operations
        .iter()
        .map(|operation| (as_str(operation, "id"), operation))
        .collect();

    for operation_id in ["tlon.dm.send", "tlon.channel.send"] {
        let operation = by_id
            .get(operation_id)
            .expect("send operation should be present");
        assert_eq!(operation["risk_level"], "medium");
        assert_eq!(operation["safety_tier"], "safe");
        assert_eq!(operation["idempotency"], "best_effort");
        assert_eq!(operation["implemented"], false);
    }

    let resolve = by_id
        .get("tlon.target.resolve")
        .expect("target resolve operation should be present");
    assert_eq!(resolve["risk_level"], "low");
    assert_eq!(resolve["safety_tier"], "safe");
    assert_eq!(resolve["idempotency"], "strict");
    assert_eq!(resolve["implemented"], false);

    let connector = TlonConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should succeed");
    assert_eq!(introspection["surface_status"], "incubating");
    assert_eq!(
        introspection["surface_status_rationale"],
        "Runtime path is incomplete or lacks production evidence"
    );
}
