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
use serde_json::Value;

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
