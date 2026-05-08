#![allow(clippy::expect_used, clippy::too_many_lines)]

use std::collections::BTreeSet;

use fcp_bluebubbles::error::BlueBubblesError;
use fcp_bluebubbles::{CONNECTOR_ID, new_connector};
use fcp_prelude::{FcpConnector, FcpError, IdempotencyClass, SafetyTier};
use fcp_sdk::migration::ConnectorErrorMapping;
use fcp_testkit::{OperationContract, assert_operation_contracts};
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[test]
fn bluebubbles_schema_operation_and_error_contracts_are_advertised() {
    let connector = new_connector();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "imessage.send_message",
                capability: "imessage.send",
                required_input_fields: &["chat_guid", "message"],
                output_fields: &["status", "message", "data", "send_method"],
            },
            OperationContract {
                id: "imessage.ingest_webhook_request",
                capability: "imessage.read",
                required_input_fields: &["method", "url", "body"],
                output_fields: &["accepted", "status_code", "reason_code", "logs"],
            },
        ],
    );

    let server_info = introspection_operations(&introspection)
        .iter()
        .find(|operation| operation["id"] == "imessage.get_server_info")
        .expect("get_server_info operation should be advertised");
    assert_eq!(
        server_info["capability"], "imessage.admin",
        "get_server_info capability drifted"
    );
    assert_eq!(
        server_info["input_schema"],
        serde_json::json!({ "type": "object" }),
        "get_server_info should remain a zero-input operation"
    );
    assert!(server_info["output_schema"]["properties"]["os_version"].is_object());
    assert!(server_info["output_schema"]["properties"]["server_version"].is_object());
    assert!(server_info["output_schema"]["properties"]["private_api"].is_object());

    assert!(matches!(
        BlueBubblesError::Api {
            status_code: 429,
            message: "rate limited".into(),
        }
        .to_fcp_error(),
        FcpError::RateLimited { .. }
    ));
    assert!(matches!(
        BlueBubblesError::NotConfigured.to_fcp_error(),
        FcpError::NotConfigured
    ));
}

#[test]
fn bluebubbles_advertises_full_shared_operation_matrix_with_user_facing_metadata() {
    let connector = new_connector();
    let introspection = connector.introspect();
    let expected = [
        (
            "imessage.send_message",
            "imessage.send",
            SafetyTier::Risky,
            IdempotencyClass::None,
        ),
        (
            "imessage.send_media",
            "imessage.send",
            SafetyTier::Risky,
            IdempotencyClass::None,
        ),
        (
            "imessage.resolve_send_target",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.create_chat",
            "imessage.send",
            SafetyTier::Risky,
            IdempotencyClass::None,
        ),
        (
            "imessage.get_action_availability",
            "imessage.admin",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.edit_message",
            "imessage.send",
            SafetyTier::Risky,
            IdempotencyClass::None,
        ),
        (
            "imessage.unsend_message",
            "imessage.send",
            SafetyTier::Dangerous,
            IdempotencyClass::None,
        ),
        (
            "imessage.send_reaction",
            "imessage.send",
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.set_typing",
            "imessage.send",
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.get_chats",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.get_chat",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.get_messages",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.sync_events",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.download_attachment",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.mark_read",
            "imessage.send",
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.register_webhook",
            "imessage.admin",
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.list_webhooks",
            "imessage.admin",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
        (
            "imessage.unregister_webhook",
            "imessage.admin",
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.ingest_webhook_event",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.ingest_webhook_request",
            "imessage.read",
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
        ),
        (
            "imessage.get_server_info",
            "imessage.admin",
            SafetyTier::Safe,
            IdempotencyClass::Strict,
        ),
    ];

    assert_eq!(
        introspection.operations.len(),
        expected.len(),
        "BlueBubbles wrapper should expose every shared BlueBubbles operation"
    );
    for (operation_id, capability, safety_tier, idempotency) in expected {
        let operation = introspection
            .operations
            .iter()
            .find(|candidate| candidate.id.as_str() == operation_id)
            .expect("expected operation contract to be advertised");
        assert_eq!(operation.capability.as_str(), capability);
        assert_eq!(
            operation.safety_tier, safety_tier,
            "{operation_id} safety tier drifted"
        );
        assert_eq!(
            operation.idempotency, idempotency,
            "{operation_id} idempotency drifted"
        );
        assert!(
            !operation.summary.trim().is_empty(),
            "{operation_id} has empty summary"
        );
        assert!(
            operation
                .description
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} has no useful description"
        );
        assert_object_schema(&operation.input_schema, operation_id, "input_schema");
        assert_object_schema(&operation.output_schema, operation_id, "output_schema");
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} has no operator guidance"
        );
    }
}

#[test]
fn bluebubbles_manifest_keeps_bridge_security_and_operator_hints_in_sync() {
    assert!(MANIFEST_TOML.contains("id = \"fcp.bluebubbles\""));
    assert!(MANIFEST_TOML.contains("home = \"z:private\""));
    assert!(MANIFEST_TOML.contains("forbidden = [\"system.privileged\"]"));
    assert!(MANIFEST_TOML.contains("deny_exec = true"));
    assert!(MANIFEST_TOML.contains("host_allow = [\"localhost\", \"127.0.0.1\"]"));
    assert!(MANIFEST_TOML.contains("max_redirects = 0"));

    let manifest_ops = [
        "send_message",
        "send_media",
        "resolve_send_target",
        "create_chat",
        "get_action_availability",
        "edit_message",
        "unsend_message",
        "send_reaction",
        "set_typing",
        "get_chats",
        "get_chat",
        "get_messages",
        "sync_events",
        "download_attachment",
        "mark_read",
        "register_webhook",
        "list_webhooks",
        "unregister_webhook",
        "ingest_webhook_event",
        "ingest_webhook_request",
        "get_server_info",
    ];
    for manifest_op in manifest_ops {
        let section = format!("[provides.operations.{manifest_op}]");
        let hint_section = format!("[provides.operations.{manifest_op}.ai_hints]");
        let network_section = format!("[provides.operations.{manifest_op}.network_constraints]");
        assert!(
            MANIFEST_TOML.contains(&section),
            "manifest missing {section}"
        );
        assert!(
            MANIFEST_TOML.contains(&hint_section),
            "manifest missing {hint_section}"
        );
        assert!(
            MANIFEST_TOML.contains(&network_section),
            "manifest missing {network_section}"
        );
    }
}

#[test]
fn bluebubbles_manifest_operation_schemas_compile_and_match_runtime_catalog() {
    let manifest = bluebubbles_manifest();
    let manifest_ops = manifest_operations(&manifest);
    let connector = new_connector();
    let introspection = connector.introspect();

    assert_eq!(
        manifest_ops.len(),
        introspection.operations.len(),
        "manifest and runtime operation catalogs should stay aligned"
    );

    for (operation_key, operation_spec) in manifest_ops {
        let operation_id = format!("imessage.{operation_key}");
        let runtime_operation = introspection
            .operations
            .iter()
            .find(|candidate| candidate.id.as_str() == operation_id.as_str())
            .expect("runtime introspection should include manifest operation");

        for (schema_key, runtime_schema) in [
            ("input_schema", &runtime_operation.input_schema),
            ("output_schema", &runtime_operation.output_schema),
        ] {
            let manifest_schema = operation_spec
                .get(schema_key)
                .expect("manifest operation should define schema");
            let manifest_schema =
                serde_json::to_value(manifest_schema).expect("schema should convert to JSON");

            assert!(
                jsonschema::validator_for(&manifest_schema).is_ok(),
                "{operation_id} manifest {schema_key} should compile"
            );
            assert!(
                jsonschema::validator_for(runtime_schema).is_ok(),
                "{operation_id} runtime {schema_key} should compile"
            );
            assert_eq!(
                manifest_schema.get("type"),
                runtime_schema.get("type"),
                "{operation_id} {schema_key}.type drifted"
            );
            for keyword in ["required", "oneOf", "anyOf"] {
                assert_eq!(
                    manifest_schema.get(keyword),
                    runtime_schema.get(keyword),
                    "{operation_id} {schema_key}.{keyword} drifted"
                );
            }
            assert_eq!(
                schema_property_names(&manifest_schema),
                schema_property_names(runtime_schema),
                "{operation_id} {schema_key}.properties drifted"
            );
        }
    }

    let send_message = manifest_operation_schema(&manifest, "send_message", "input_schema");
    assert_schema_accepts(
        &send_message,
        &json!({ "chat_guid": "chat-1", "message": "hello" }),
    );
    assert_schema_rejects(&send_message, &json!({ "chat_guid": "chat-1" }));

    let send_media = manifest_operation_schema(&manifest, "send_media", "input_schema");
    assert_schema_accepts(
        &send_media,
        &json!({ "chat_guid": "chat-1", "local_path": "/tmp/photo.png" }),
    );
    assert_schema_rejects(&send_media, &json!({ "local_path": "/tmp/photo.png" }));

    let ingest_request =
        manifest_operation_schema(&manifest, "ingest_webhook_request", "input_schema");
    assert_schema_accepts(
        &ingest_request,
        &json!({
            "method": "POST",
            "url": "http://localhost:8645/bluebubbles-webhook",
            "body": {}
        }),
    );
    assert_schema_rejects(&ingest_request, &json!({ "method": "POST" }));

    let server_info = manifest_operation_schema(&manifest, "get_server_info", "output_schema");
    assert_schema_accepts(
        &server_info,
        &json!({
            "os_version": "26.0",
            "server_version": "1.10.0-test",
            "private_api": true,
            "proxy_service": "none"
        }),
    );
    assert_schema_rejects(&server_info, &json!([]));
}

fn introspection_operations(introspection: &Value) -> &[Value] {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection should expose operations array")
}

fn bluebubbles_manifest() -> toml::Value {
    toml::from_str(MANIFEST_TOML).expect("BlueBubbles manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should contain provides.operations")
}

fn manifest_operation_schema(
    manifest: &toml::Value,
    operation_key: &str,
    schema_key: &str,
) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get(schema_key))
        .expect("operation should define requested schema");

    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn schema_property_names(schema: &Value) -> BTreeSet<String> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default()
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept payload {payload:#}: {errors:#?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    assert!(
        validator.iter_errors(payload).next().is_some(),
        "schema should reject payload {payload:#}"
    );
}

fn assert_object_schema(schema: &Value, operation_id: &str, field: &str) {
    assert_eq!(
        schema.get("type").and_then(Value::as_str),
        Some("object"),
        "{operation_id} {field} should be an object schema"
    );
    assert!(
        schema.get("properties").is_some_and(|properties| properties
            .as_object()
            .is_some_and(|object| !object.is_empty()))
            || schema.get("oneOf").is_some_and(|alternatives| alternatives
                .as_array()
                .is_some_and(|items| !items.is_empty()))
            || schema.get("anyOf").is_some_and(|alternatives| alternatives
                .as_array()
                .is_some_and(|items| !items.is_empty()))
            || schema == &serde_json::json!({ "type": "object" }),
        "{operation_id} {field} should declare properties or composition"
    );
}
