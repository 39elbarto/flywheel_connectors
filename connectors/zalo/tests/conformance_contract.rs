#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};

use fcp_manifest::{ConnectorManifest, ConnectorStatus, OperationSection};
use fcp_prelude::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;
use fcp_zalo::{ZaloConnector, ZaloError};
use serde::Serialize;
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_COUNT: usize = 9;

fn manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(MANIFEST_TOML).expect("Zalo manifest should validate")
}

async fn runtime_operations() -> Vec<Value> {
    let connector = ZaloConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("Zalo introspection should serialize");
    introspection["operations"]
        .as_array()
        .expect("operations should be an array")
        .clone()
}

fn serialized_str(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .expect("serialize manifest enum")
        .as_str()
        .expect("manifest enum should serialize as a string")
        .to_string()
}

fn assert_object_schema(schema: &Value, operation_id: &str, label: &str) {
    assert_eq!(
        schema["type"], "object",
        "{operation_id} {label}_schema should be an object"
    );
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("required schemas should declare properties");
        for field in required {
            let field = field
                .as_str()
                .expect("required schema entries should be strings");
            assert!(
                properties.contains_key(field),
                "{operation_id} {label}_schema requires `{field}` but does not declare it"
            );
        }
    }
}

fn assert_manifest_operation_contract(id: &str, op: &OperationSection) {
    assert!(
        !op.description.trim().is_empty(),
        "{id} should have a manifest description"
    );
    assert!(
        !op.capability.as_str().trim().is_empty(),
        "{id} should declare a capability"
    );
    assert!(
        !serialized_str(&op.risk_level).trim().is_empty(),
        "{id} should declare risk_level"
    );
    assert!(
        !serialized_str(&op.safety_tier).trim().is_empty(),
        "{id} should declare safety_tier"
    );
    assert!(
        !serialized_str(&op.idempotency).trim().is_empty(),
        "{id} should declare idempotency"
    );
    assert_object_schema(&op.input_schema, id, "input");
    assert_object_schema(&op.output_schema, id, "output");
    assert!(
        !op.ai_hints.when_to_use.trim().is_empty(),
        "{id} should advertise ai_hints.when_to_use"
    );
}

fn assert_bot_api_network_constraints(id: &str, op: &OperationSection) {
    let constraints = op
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{id} should declare network_constraints"));
    assert_eq!(
        constraints.host_allow,
        ["bot-api.zaloplatforms.com"],
        "{id} should only allow the production Zalo Bot API host"
    );
    assert_eq!(constraints.port_allow, [443], "{id}");
    assert!(constraints.require_sni, "{id} should require SNI");
    assert!(constraints.deny_localhost, "{id} should deny localhost");
    assert!(
        constraints.deny_private_ranges,
        "{id} should deny private ranges"
    );
    assert!(
        constraints.deny_tailnet_ranges,
        "{id} should deny tailnet ranges"
    );
    assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
    assert_eq!(constraints.max_redirects, 0, "{id}");
}

fn assert_no_connector_egress_network_constraints(id: &str, op: &OperationSection) {
    let constraints = op
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{id} should declare network_constraints"));
    assert_eq!(
        constraints.host_allow,
        ["none.invalid"],
        "{id} should advertise no connector-owned egress"
    );
    assert_eq!(constraints.port_allow, [0], "{id}");
    assert!(
        !constraints.require_sni,
        "{id} should not require SNI for a no-egress sentinel"
    );
    assert!(constraints.deny_localhost, "{id} should deny localhost");
    assert!(
        constraints.deny_private_ranges,
        "{id} should deny private ranges"
    );
    assert_eq!(constraints.dns_max_ips, 0, "{id}");
    assert_eq!(constraints.max_redirects, 0, "{id}");
}

fn assert_runtime_schema_covers_manifest(
    operation_id: &str,
    runtime_schema: &Value,
    manifest_schema: &Value,
    label: &str,
) {
    assert_object_schema(runtime_schema, operation_id, label);
    assert_eq!(
        runtime_schema.get("required"),
        manifest_schema.get("required"),
        "{operation_id} runtime {label}_schema required fields should match manifest"
    );

    let Some(manifest_properties) = manifest_schema.get("properties").and_then(Value::as_object)
    else {
        return;
    };
    let runtime_properties = runtime_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("runtime schema should declare manifest properties");
    for (field, manifest_property) in manifest_properties {
        let runtime_property = runtime_properties
            .get(field)
            .expect("runtime schema should include manifest property");
        assert_eq!(
            runtime_property.get("type"),
            manifest_property.get("type"),
            "{operation_id} runtime {label}_schema property `{field}` type should match manifest"
        );
    }
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
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty(),
        "schema should reject payload {payload:#}"
    );
}

fn input_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
    &manifest
        .provides
        .operations
        .get(operation_id)
        .expect("operation should exist")
        .input_schema
}

#[fcp_async_core::runtime::test]
async fn runtime_catalog_matches_manifest_operation_contracts() {
    let manifest = manifest();
    let runtime_ops = runtime_operations().await;

    assert_eq!(manifest.provides.operations.len(), EXPECTED_OPERATION_COUNT);
    assert_eq!(runtime_ops.len(), EXPECTED_OPERATION_COUNT);

    let runtime_by_id: BTreeMap<&str, &Value> = runtime_ops
        .iter()
        .map(|op| (op["id"].as_str().expect("runtime operation id"), op))
        .collect();
    let manifest_ids: BTreeSet<&str> = manifest
        .provides
        .operations
        .keys()
        .map(String::as_str)
        .collect();
    let runtime_ids: BTreeSet<&str> = runtime_by_id.keys().copied().collect();
    assert_eq!(manifest_ids, runtime_ids);

    for (id, manifest_op) in &manifest.provides.operations {
        assert_manifest_operation_contract(id, manifest_op);
        let runtime_op = runtime_by_id
            .get(id.as_str())
            .expect("manifest operation should be present in runtime introspection");

        assert_eq!(
            runtime_op["capability"],
            manifest_op.capability.as_str(),
            "{id}"
        );
        assert_eq!(
            runtime_op["risk_level"],
            serialized_str(&manifest_op.risk_level),
            "{id}"
        );
        assert_eq!(
            runtime_op["safety_tier"],
            serialized_str(&manifest_op.safety_tier),
            "{id}"
        );
        assert_eq!(
            runtime_op["idempotency"],
            serialized_str(&manifest_op.idempotency),
            "{id}"
        );
        assert_runtime_schema_covers_manifest(
            id,
            &runtime_op["input_schema"],
            &manifest_op.input_schema,
            "input",
        );
        assert_runtime_schema_covers_manifest(
            id,
            &runtime_op["output_schema"],
            &manifest_op.output_schema,
            "output",
        );
        assert_eq!(
            runtime_op["ai_hints"]["when_to_use"], manifest_op.ai_hints.when_to_use,
            "{id} runtime ai_hints should mirror manifest"
        );
        assert!(
            runtime_op["implemented"].as_bool() == Some(true),
            "{id} should be marked implemented"
        );
    }
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    let manifest = manifest();
    for (id, operation) in &manifest.provides.operations {
        assert!(
            jsonschema::validator_for(&operation.input_schema).is_ok(),
            "{id} input_schema should compile"
        );
        assert!(
            jsonschema::validator_for(&operation.output_schema).is_ok(),
            "{id} output_schema should compile"
        );
    }

    assert_schema_accepts(
        input_schema(&manifest, "zalo.messages.send"),
        &json!({"recipient_id": "user-1", "message": "hello"}),
    );
    assert_schema_rejects(
        input_schema(&manifest, "zalo.messages.send"),
        &json!({"recipient_id": "user-1"}),
    );
    assert_schema_accepts(
        input_schema(&manifest, "zalo.messages.send_photo"),
        &json!({"recipient_id": "user-1", "photo_url": "https://example.com/photo.jpg"}),
    );
    assert_schema_rejects(
        input_schema(&manifest, "zalo.messages.send_photo"),
        &json!({"recipient_id": "user-1"}),
    );
    assert_schema_accepts(input_schema(&manifest, "zalo.self.get_me"), &json!({}));
    assert_schema_accepts(
        input_schema(&manifest, "zalo.updates.poll"),
        &json!({"offset": 42, "timeout_seconds": 0}),
    );
    assert_schema_accepts(input_schema(&manifest, "zalo.webhook.delete"), &json!({}));
    assert_schema_accepts(input_schema(&manifest, "zalo.webhook.info"), &json!({}));
    assert_schema_accepts(
        input_schema(&manifest, "zalo.webhook.ingest"),
        &json!({
            "method": "POST",
            "path": "/zalo/inbound",
            "headers": {"x-bot-api-secret-token": "redacted"},
            "body": "{}"
        }),
    );
    assert_schema_rejects(
        input_schema(&manifest, "zalo.webhook.ingest"),
        &json!({"method": "POST", "path": "/zalo/inbound"}),
    );
    assert_schema_accepts(
        input_schema(&manifest, "zalo.webhook.set"),
        &json!({"url": "https://hooks.example.com/zalo"}),
    );
    assert_schema_rejects(input_schema(&manifest, "zalo.webhook.set"), &json!({}));
    assert_schema_accepts(
        input_schema(&manifest, "zalo.webhook.verify"),
        &json!({"token": "redacted"}),
    );
    assert_schema_rejects(input_schema(&manifest, "zalo.webhook.verify"), &json!({}));
}

#[test]
fn manifest_declares_zalo_security_boundary() {
    let manifest = manifest();
    assert_eq!(manifest.connector.id.as_str(), "fcp.zalo");
    assert_eq!(manifest.connector.status, ConnectorStatus::Experimental);

    let required = manifest
        .capabilities
        .required
        .iter()
        .map(fcp_prelude::CapabilityId::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required,
        BTreeSet::from(["network.dns", "network.egress", "network.tls.sni"])
    );

    let forbidden = manifest
        .capabilities
        .forbidden
        .iter()
        .map(fcp_prelude::CapabilityId::as_str)
        .collect::<BTreeSet<_>>();
    assert!(forbidden.contains("network.listen"));
    assert!(forbidden.contains("system.exec"));
}

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = manifest();
    for operation_id in [
        "zalo.messages.send",
        "zalo.messages.send_photo",
        "zalo.self.get_me",
        "zalo.updates.poll",
        "zalo.webhook.delete",
        "zalo.webhook.info",
        "zalo.webhook.set",
    ] {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should exist");
        assert_bot_api_network_constraints(operation_id, operation);
    }

    for operation_id in ["zalo.webhook.ingest", "zalo.webhook.verify"] {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should exist");
        assert_no_connector_egress_network_constraints(operation_id, operation);
    }
}

#[test]
fn connector_error_taxonomy_is_stable() {
    let rate_limited = ZaloError::RateLimited {
        retry_after_ms: 2_500,
    };
    assert!(matches!(
        ConnectorErrorMapping::to_fcp_error(&rate_limited),
        FcpError::RateLimited {
            retry_after_ms: 2_500,
            ..
        }
    ));
    assert!(ConnectorErrorMapping::is_retryable(&rate_limited));

    let provider = ZaloError::Api {
        status_code: 503,
        message: "provider unavailable".to_string(),
    };
    assert!(matches!(
        ConnectorErrorMapping::to_fcp_error(&provider),
        FcpError::External {
            ref service,
            status_code: Some(503),
            retryable: true,
            ..
        } if service == "zalo"
    ));

    let invalid = ZaloError::InvalidInput("bad recipient id".to_string());
    assert!(matches!(
        ConnectorErrorMapping::to_fcp_error(&invalid),
        FcpError::InvalidRequest { code: 1005, .. }
    ));

    let webhook = ZaloError::Webhook("invalid webhook token".to_string());
    assert!(matches!(
        ConnectorErrorMapping::to_fcp_error(&webhook),
        FcpError::InvalidRequest { code: 1007, .. }
    ));

    let async_error =
        ZaloError::from_async_error(fcp_async_core::AsyncError::Timeout { timeout_ms: 50 });
    assert!(matches!(
        ConnectorErrorMapping::to_fcp_error(&async_error),
        FcpError::Internal { .. }
    ));
}
