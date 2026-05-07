#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::{BTreeMap, BTreeSet};

use fcp_google_meet::{connector::GoogleMeetConnector, error::GoogleMeetError};
use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_prelude::FcpError;
use serde::Serialize;
use serde_json::Value;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_COUNT: usize = 23;

fn manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("Google Meet manifest should parse and validate")
}

async fn runtime_operations() -> Vec<Value> {
    let connector = GoogleMeetConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("Google Meet introspection should serialize");
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
        let properties = schema.get("properties").and_then(Value::as_object);
        assert!(
            properties.is_some(),
            "{operation_id} {label}_schema has required fields but no properties"
        );
        let properties = properties.expect("schema properties existence was asserted");
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
    assert_object_schema(&op.input_schema, id, "input");
    assert_object_schema(&op.output_schema, id, "output");
    assert!(
        !op.ai_hints.when_to_use.trim().is_empty(),
        "{id} should advertise ai_hints.when_to_use"
    );
    assert!(
        !op.ai_hints.common_mistakes.is_empty(),
        "{id} should advertise ai_hints.common_mistakes"
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
}

#[fcp_async_core::runtime::test]
async fn runtime_catalog_matches_manifest_operation_contracts() {
    let manifest = manifest();
    let runtime_ops = runtime_operations().await;

    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_COUNT,
        "manifest operation count changed; update connector-local conformance expectations"
    );
    assert_eq!(
        runtime_ops.len(),
        EXPECTED_OPERATION_COUNT,
        "runtime operation count changed; update connector-local conformance expectations"
    );

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
        assert_object_schema(&runtime_op["input_schema"], id, "runtime input");
        assert_object_schema(&runtime_op["output_schema"], id, "runtime output");
        assert!(
            runtime_op["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
            "{id} should advertise runtime ai_hints.when_to_use"
        );
        assert!(
            runtime_op["ai_hints"]["common_mistakes"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{id} should advertise runtime ai_hints.common_mistakes"
        );
    }
}

#[test]
fn manifest_network_constraints_are_complete_for_all_declared_operations() {
    let manifest = manifest();

    for (id, op) in &manifest.provides.operations {
        let constraints = op
            .network_constraints
            .as_ref()
            .expect("operation should declare operation-level network constraints");
        assert!(
            !constraints.host_allow.is_empty(),
            "{id} should have host_allow"
        );
        assert_eq!(
            constraints.port_allow,
            vec![443],
            "{id} should stay TLS-only"
        );
        assert!(constraints.deny_localhost, "{id} should deny localhost");
        assert!(
            constraints.deny_private_ranges,
            "{id} should deny private ranges"
        );
        assert!(
            constraints.deny_tailnet_ranges,
            "{id} should deny tailnet ranges"
        );
        assert!(constraints.require_sni, "{id} should require SNI");
        assert!(constraints.deny_ip_literals, "{id} should deny IP literals");
        assert!(
            constraints.require_host_canonicalization,
            "{id} should require host canonicalization"
        );
        assert_eq!(constraints.max_redirects, 0, "{id} should forbid redirects");
        assert!(
            constraints.connect_timeout_ms <= constraints.total_timeout_ms,
            "{id} connect timeout should fit inside total timeout"
        );
        assert!(
            constraints.max_response_bytes <= 10 * 1_048_576,
            "{id} should keep response caps bounded"
        );
    }
}

#[test]
fn error_taxonomy_maps_to_fcp_error_classes() {
    assert!(matches!(
        GoogleMeetError::Unauthorized.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));
    assert!(matches!(
        GoogleMeetError::Api {
            code: 403,
            message: "workspace policy denied".into(),
        }
        .to_fcp_error(),
        FcpError::Unauthorized { code: 2003, .. }
    ));
    assert!(matches!(
        GoogleMeetError::Api {
            code: 404,
            message: "conferenceRecords/missing".into(),
        }
        .to_fcp_error(),
        FcpError::ResourceNotFound { resource } if resource == "conferenceRecords/missing"
    ));
    assert!(matches!(
        GoogleMeetError::RateLimited {
            retry_after_secs: 7,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 7_000,
            ..
        }
    ));
    assert!(matches!(
        GoogleMeetError::Api {
            code: 503,
            message: "backend unavailable".into(),
        }
        .to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            status_code: Some(503),
            ..
        } if service == "google-meet"
    ));
    assert!(matches!(
        GoogleMeetError::InvalidConfig {
            message: "bad base URL".into(),
        }
        .to_fcp_error(),
        FcpError::InvalidRequest { code: 1003, .. }
    ));
    assert!(matches!(
        GoogleMeetError::ResponseTooLarge {
            context: "Google Drive files.export".into(),
            max_bytes: 1024,
        }
        .to_fcp_error(),
        FcpError::External {
            service,
            retryable: false,
            ..
        } if service == "google-meet"
    ));
    assert!(matches!(
        GoogleMeetError::AsyncCheckpoint {
            checkpoint: "artifact read".into(),
            message: "timeout budget exhausted".into(),
        }
        .to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "google-meet"
    ));
}
