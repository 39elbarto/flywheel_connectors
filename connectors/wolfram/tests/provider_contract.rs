use fcp_manifest::ConnectorManifest;
use fcp_wolfram::{WolframConnector, connector::wolfram_operations};
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 3] = [
    "wolfram.query",
    "wolfram.short_answer",
    "wolfram.spoken_result",
];

fn wolfram_manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(MANIFEST_TOML).expect("Wolfram manifest should validate")
}

fn manifest_input_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
    &manifest
        .provides
        .operations
        .get(operation_id)
        .expect("manifest operation should be declared")
        .input_schema
}

fn manifest_output_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
    &manifest
        .provides
        .operations
        .get(operation_id)
        .expect("manifest operation should be declared")
        .output_schema
}

fn validator_for(schema: &Value) -> jsonschema::Validator {
    jsonschema::Validator::new(schema).expect("manifest operation schema should compile")
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = validator_for(schema);
    let errors: Vec<_> = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "schema should accept {payload}; errors: {errors:?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = validator_for(schema);
    assert!(
        validator.iter_errors(payload).next().is_some(),
        "schema should reject {payload}"
    );
}

#[test]
fn wolfram_manifest_declares_canonical_operations_and_network_constraints() {
    let manifest = wolfram_manifest();
    assert_eq!(manifest.connector.id.as_str(), "fcp.wolfram");
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_IDS.len()
    );
    assert!(
        manifest
            .capabilities
            .optional
            .iter()
            .any(|capability| capability.as_str() == "wolfram.query")
    );

    for operation_id in EXPECTED_OPERATION_IDS {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared");
        assert_eq!(operation.capability.as_str(), "wolfram.query");
        assert_eq!(operation.input_schema["type"], "object");
        assert_eq!(operation.output_schema["type"], "object");
        assert!(!operation.ai_hints.when_to_use.trim().is_empty());
        let network = operation
            .network_constraints
            .as_ref()
            .expect("network constraints should be present");
        assert_eq!(network.host_allow, ["api.wolframalpha.com"]);
        assert_eq!(network.port_allow, [443]);
        assert!(network.require_sni);
        assert!(network.deny_localhost);
        assert!(network.deny_private_ranges);
        assert!(network.deny_tailnet_ranges);
    }
}

#[test]
fn wolfram_runtime_operations_are_manifest_backed_and_stable() {
    let manifest = wolfram_manifest();
    let runtime_ids: Vec<_> = wolfram_operations()
        .into_iter()
        .map(|operation| operation.id.as_ref().to_string())
        .collect();
    assert_eq!(runtime_ids, EXPECTED_OPERATION_IDS);
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_IDS.len()
    );

    let connector = WolframConnector::new();
    let introspection = connector
        .handle_introspect()
        .expect("introspection should serialize");
    let operations = introspection["operations"]
        .as_array()
        .expect("introspection operations should be an array");
    let introspect_ids: Vec<_> = operations
        .iter()
        .map(|operation| operation["id"].as_str().expect("operation id"))
        .collect();
    assert_eq!(introspect_ids, EXPECTED_OPERATION_IDS);

    for operation_id in EXPECTED_OPERATION_IDS {
        let manifest_operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("manifest operation should exist");
        let runtime_operation = operations
            .iter()
            .find(|operation| operation["id"].as_str() == Some(operation_id))
            .expect("runtime operation should exist");
        assert_eq!(
            runtime_operation["capability"].as_str(),
            Some(manifest_operation.capability.as_str())
        );
        assert_eq!(
            runtime_operation.get("input_schema"),
            Some(&manifest_operation.input_schema)
        );
        assert_eq!(
            runtime_operation.get("output_schema"),
            Some(&manifest_operation.output_schema)
        );
        assert_eq!(
            runtime_operation["network_constraints"]["host_allow"],
            json!(["api.wolframalpha.com"])
        );
        assert!(
            runtime_operation["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }
}

#[test]
fn wolfram_manifest_schemas_cover_input_boundaries_and_outputs() {
    let manifest = wolfram_manifest();
    for operation_id in EXPECTED_OPERATION_IDS {
        let schema = manifest_input_schema(&manifest, operation_id);
        assert_schema_accepts(
            schema,
            &json!({"input": "integrate x^2 dx", "app_id": "test-app-id"}),
        );
        assert_schema_accepts(
            schema,
            &json!({"query": "population of Tokyo", "app_id": "test-app-id"}),
        );
        assert_schema_rejects(schema, &json!({}));
        assert_schema_rejects(schema, &json!({"input": "", "app_id": "test-app-id"}));
        assert_schema_rejects(schema, &json!({"input": "2+2"}));
        assert_schema_rejects(
            schema,
            &json!({"input": "x".repeat(4097), "app_id": "test"}),
        );
    }

    assert_schema_accepts(
        manifest_output_schema(&manifest, "wolfram.query"),
        &json!({"success": true, "numpods": 1, "pods": [], "assumptions": []}),
    );
    assert_schema_rejects(
        manifest_output_schema(&manifest, "wolfram.query"),
        &json!({"numpods": 1}),
    );
    assert_schema_accepts(
        manifest_output_schema(&manifest, "wolfram.short_answer"),
        &json!({"answer": "4"}),
    );
    assert_schema_rejects(
        manifest_output_schema(&manifest, "wolfram.short_answer"),
        &json!({"spoken": "4"}),
    );
    assert_schema_accepts(
        manifest_output_schema(&manifest, "wolfram.spoken_result"),
        &json!({"spoken": "The answer is 4"}),
    );
    assert_schema_rejects(
        manifest_output_schema(&manifest, "wolfram.spoken_result"),
        &json!({"answer": "4"}),
    );
}
