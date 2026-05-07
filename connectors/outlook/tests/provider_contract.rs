use fcp_manifest::ConnectorManifest;
use fcp_outlook::OutlookConnector;
use fcp_prelude::FcpConnector;
use jsonschema::Validator;
use serde_json::{Value, json};

const EXPECTED_OPERATIONS: [&str; 7] = [
    "outlook.list_messages",
    "outlook.get_message",
    "outlook.search_messages",
    "outlook.send_message",
    "outlook.list_events",
    "outlook.create_event",
    "outlook.list_folders",
];

fn manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("Outlook manifest should validate")
}

fn validator_for(schema: &Value) -> Validator {
    Validator::new(schema).expect("manifest schema should compile")
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
fn manifest_declares_graph_surface_and_all_runtime_operations() {
    let manifest = manifest();
    assert_eq!(manifest.connector.id.as_str(), "fcp.outlook");
    assert_eq!(manifest.zones.home.as_str(), "z:work");
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATIONS.len()
    );

    for operation_id in EXPECTED_OPERATIONS {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared");
        assert!(matches!(
            operation.capability.as_str(),
            "outlook.read" | "outlook.send" | "outlook.calendar"
        ));
        assert_eq!(operation.input_schema["type"], "object");
        assert_eq!(operation.output_schema["type"], "object");
        assert!(!operation.ai_hints.when_to_use.trim().is_empty());
        assert!(
            operation
                .ai_hints
                .common_mistakes
                .iter()
                .any(|hint| hint.contains("log") || hint.contains("id")),
            "{operation_id} should include user-safety guidance"
        );
    }
}

#[test]
fn manifest_runtime_introspection_are_equivalent() {
    let manifest = manifest();
    let connector = OutlookConnector::new();
    let introspection = connector.introspect();
    assert_eq!(introspection.operations.len(), EXPECTED_OPERATIONS.len());

    for (operation, expected_id) in introspection.operations.iter().zip(EXPECTED_OPERATIONS) {
        let manifest_operation = manifest
            .provides
            .operations
            .get(expected_id)
            .expect("operation should be declared");
        assert_eq!(operation.id.as_str(), expected_id);
        assert_eq!(operation.summary, manifest_operation.description);
        assert_eq!(
            operation.description.as_deref(),
            Some(manifest_operation.description.as_str())
        );
        assert_eq!(operation.capability, manifest_operation.capability);
        assert_eq!(operation.risk_level, manifest_operation.risk_level);
        assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
        assert_eq!(operation.idempotency, manifest_operation.idempotency);
        assert_eq!(operation.input_schema, manifest_operation.input_schema);
        assert_eq!(operation.output_schema, manifest_operation.output_schema);
        assert_eq!(
            operation
                .rate_limit
                .as_ref()
                .map(|rate| (rate.max, rate.per_ms)),
            manifest_operation
                .rate_limit
                .as_ref()
                .map(|rate| (rate.0.max, rate.0.per_ms))
        );
    }
}

#[test]
fn manifest_operation_hosts_are_microsoft_graph_only() {
    let manifest = manifest();
    for operation_id in EXPECTED_OPERATIONS {
        let network = manifest.provides.operations[operation_id]
            .network_constraints
            .as_ref()
            .expect("network constraints should be present");
        assert_eq!(
            network.host_allow,
            vec![
                "graph.microsoft.com".to_string(),
                "graph.microsoft.us".to_string()
            ]
        );
        assert_eq!(network.port_allow, vec![443]);
        assert!(network.deny_localhost);
        assert!(network.deny_private_ranges);
        assert!(network.deny_tailnet_ranges);
        assert!(network.require_sni);
        assert!(network.deny_ip_literals);
        assert_eq!(network.max_redirects, 0);
    }
}

#[test]
fn schema_contract_covers_happy_path_and_core_rejections() {
    let manifest = manifest();
    let input = |operation_id: &str| &manifest.provides.operations[operation_id].input_schema;

    assert_schema_accepts(
        input("outlook.list_messages"),
        &json!({ "folder_id": "Inbox", "top": 25 }),
    );
    assert_schema_rejects(input("outlook.list_messages"), &json!({ "top": 0 }));
    assert_schema_accepts(
        input("outlook.get_message"),
        &json!({ "message_id": "AAMkExampleMessageId" }),
    );
    assert_schema_rejects(input("outlook.get_message"), &json!({}));
    assert_schema_accepts(
        input("outlook.search_messages"),
        &json!({ "query": "invoice", "top": 10 }),
    );
    assert_schema_rejects(input("outlook.search_messages"), &json!({ "query": "" }));
    assert_schema_accepts(
        input("outlook.send_message"),
        &json!({
            "to": ["recipient@example.com"],
            "subject": "",
            "body": ""
        }),
    );
    assert_schema_rejects(
        input("outlook.send_message"),
        &json!({ "to": [], "subject": "Hello", "body": "World" }),
    );
    assert_schema_accepts(input("outlook.list_events"), &json!({ "top": 5 }));
    assert_schema_rejects(input("outlook.list_events"), &json!({ "top": "five" }));
    assert_schema_accepts(
        input("outlook.create_event"),
        &json!({
            "subject": "Meeting",
            "start": "2026-04-01T10:00:00-04:00",
            "end": "2026-04-01T11:00:00-04:00"
        }),
    );
    assert_schema_rejects(
        input("outlook.create_event"),
        &json!({
            "subject": "Meeting",
            "start": "2026-04-01T10:00:00-04:00"
        }),
    );
    assert_schema_accepts(input("outlook.list_folders"), &json!({}));
}

#[test]
fn output_schema_contract_covers_graph_success_shapes() {
    let manifest = manifest();
    let output = |operation_id: &str| &manifest.provides.operations[operation_id].output_schema;

    for operation_id in [
        "outlook.list_messages",
        "outlook.search_messages",
        "outlook.list_events",
        "outlook.list_folders",
    ] {
        assert_schema_accepts(output(operation_id), &json!({ "value": [] }));
        assert_schema_rejects(output(operation_id), &json!({ "value": "not-an-array" }));
    }
    assert_schema_accepts(
        output("outlook.get_message"),
        &json!({ "id": "message-id", "subject": null, "body": {} }),
    );
    assert_schema_accepts(output("outlook.send_message"), &json!({ "status": "ok" }));
    assert_schema_rejects(
        output("outlook.send_message"),
        &json!({ "status": "queued" }),
    );
    assert_schema_accepts(
        output("outlook.create_event"),
        &json!({ "id": "event-id", "subject": "Meeting" }),
    );
}
