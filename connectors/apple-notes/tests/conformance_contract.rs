#![allow(clippy::expect_used, clippy::too_many_lines)]

use fcp_apple_notes::AppleNotesConnector;
use fcp_apple_notes::error::AppleNotesError;
use fcp_prelude::{ApprovalMode, FcpConnector, FcpError, IdempotencyClass, SafetyTier};
use fcp_testkit::{OperationContract, assert_operation_contracts};
use serde_json::Value;
use std::collections::BTreeSet;

const CONNECTOR_ID: &str = "fcp.apple-notes";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_HEALTH: &str = "apple_notes.health";
const OP_LIST_NOTES: &str = "apple_notes.list_notes";
const OP_SEARCH_NOTES: &str = "apple_notes.search_notes";
const OP_GET_NOTE: &str = "apple_notes.get_note";
const OP_CREATE_NOTE: &str = "apple_notes.create_note";

const CAP_READ: &str = "apple_notes.read";
const CAP_WRITE: &str = "apple_notes.write";

#[test]
fn apple_notes_schema_operation_and_error_contracts_are_advertised() {
    let connector = AppleNotesConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: OP_HEALTH,
                capability: CAP_READ,
                required_input_fields: &[],
                output_fields: &["status", "platform", "manifest_hash"],
            },
            OperationContract {
                id: OP_LIST_NOTES,
                capability: CAP_READ,
                required_input_fields: &[],
                output_fields: &["notes"],
            },
            OperationContract {
                id: OP_SEARCH_NOTES,
                capability: CAP_READ,
                required_input_fields: &["query"],
                output_fields: &["notes"],
            },
            OperationContract {
                id: OP_GET_NOTE,
                capability: CAP_READ,
                required_input_fields: &["note_id"],
                output_fields: &["id", "title", "folder", "body"],
            },
            OperationContract {
                id: OP_CREATE_NOTE,
                capability: CAP_WRITE,
                required_input_fields: &["title", "body"],
                output_fields: &["id", "title", "folder"],
            },
        ],
    );

    let event_caps = introspection
        .get("event_caps")
        .expect("Apple Notes should advertise event capabilities");
    assert_eq!(event_caps["streaming"], false);
    assert_eq!(event_caps["replay"], false);
    assert_eq!(event_caps["min_buffer_events"], 0);
    assert!(
        introspection
            .get("events")
            .and_then(Value::as_array)
            .expect("events should serialize as an array")
            .is_empty(),
        "Apple Notes is a local request-response connector with no event stream"
    );

    assert!(matches!(
        AppleNotesError::Config("blank query".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1003, .. }
    ));
    assert!(matches!(
        AppleNotesError::UnsupportedPlatform("linux".into()).to_fcp_error(),
        FcpError::ConnectorUnavailable { code: 5001, .. }
    ));
    assert!(matches!(
        AppleNotesError::Process("automation denied".into()).to_fcp_error(),
        FcpError::Internal { .. }
    ));
    assert!(matches!(
        AppleNotesError::Timeout { timeout_secs: 1 }.to_fcp_error(),
        FcpError::Internal { .. }
    ));
    assert!(!AppleNotesError::Timeout { timeout_secs: 1 }.is_retryable());
}

#[test]
fn apple_notes_advertises_complete_operation_matrix_with_user_facing_metadata() {
    let connector = AppleNotesConnector::new();
    let introspection = connector.introspect();
    let expected = [
        (
            OP_HEALTH,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            ApprovalMode::None,
        ),
        (
            OP_LIST_NOTES,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            ApprovalMode::None,
        ),
        (
            OP_SEARCH_NOTES,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            ApprovalMode::None,
        ),
        (
            OP_GET_NOTE,
            CAP_READ,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            ApprovalMode::None,
        ),
        (
            OP_CREATE_NOTE,
            CAP_WRITE,
            SafetyTier::Risky,
            IdempotencyClass::None,
            ApprovalMode::Policy,
        ),
    ];

    assert_eq!(
        introspection.operations.len(),
        expected.len(),
        "Apple Notes should expose its complete local operation matrix"
    );
    for (operation_id, capability, safety_tier, idempotency, approval) in expected {
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
        assert_eq!(
            operation.requires_approval,
            Some(approval),
            "{operation_id} approval policy drifted"
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
        assert_eq!(operation.input_schema["type"], "object");
        assert_eq!(operation.output_schema["type"], "object");
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} has no operator guidance"
        );
        assert!(
            !operation.ai_hints.common_mistakes.is_empty(),
            "{operation_id} should teach agents what not to do"
        );
        assert!(
            !operation.ai_hints.examples.is_empty(),
            "{operation_id} should include a synthetic example"
        );
        for example in &operation.ai_hints.examples {
            let parsed: Value =
                serde_json::from_str(example).expect("ai_hints examples should be JSON objects");
            assert!(
                parsed.is_object(),
                "{operation_id} example should be a JSON object"
            );
            assert_redacted(example);
        }
    }
}

#[test]
fn apple_notes_manifest_matches_introspection_and_local_bridge_security_contract() {
    let manifest: toml::Value =
        toml::from_str(MANIFEST_TOML).expect("Apple Notes manifest should parse as TOML");
    let connector = AppleNotesConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("introspection should serialize");

    assert_eq!(string_at(&manifest, &["connector", "id"]), CONNECTOR_ID);
    assert_eq!(string_at(&manifest, &["connector", "format"]), "native");
    assert_eq!(string_at(&manifest, &["zones", "home"]), "z:owner");
    assert_array_contains(&manifest, &["zones", "allowed_sources"], "z:owner");
    assert_array_contains(&manifest, &["zones", "allowed_sources"], "z:private");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:public");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:community");
    assert_array_contains(&manifest, &["zones", "forbidden"], "z:work");
    assert_array_contains(&manifest, &["capabilities", "required"], CAP_READ);
    assert_array_contains(&manifest, &["capabilities", "required"], CAP_WRITE);
    assert_array_contains(&manifest, &["capabilities", "forbidden"], "network.listen");
    assert_array_contains(
        &manifest,
        &["capabilities", "forbidden"],
        "network.outbound",
    );
    assert_array_contains(&manifest, &["capabilities", "forbidden"], "system.exec");
    assert_array_contains(
        &manifest,
        &["capabilities", "forbidden"],
        "system.privileged",
    );
    assert_eq!(string_at(&manifest, &["sandbox", "profile"]), "strict");
    assert_eq!(integer_at(&manifest, &["sandbox", "memory_mb"]), 64);
    assert_eq!(
        integer_at(&manifest, &["sandbox", "wall_clock_timeout_ms"]),
        30_000
    );
    assert!(
        !bool_at(&manifest, &["sandbox", "deny_exec"]),
        "Apple Notes has a bounded osascript carveout, not ambient shell execution"
    );

    let introspection_ids = introspection_operation_ids(&introspection);
    let manifest_ids = manifest_operation_ids(&manifest);
    assert_eq!(
        introspection_ids, manifest_ids,
        "manifest and connector operation catalog drifted"
    );

    for operation_id in introspection_ids {
        let manifest_op = value_at(&manifest, &["provides", "operations", operation_id]);
        let introspection_op = introspection_operation(&introspection, operation_id);
        assert_eq!(
            manifest_op["capability"].as_str(),
            introspection_op["capability"].as_str(),
            "{operation_id} capability drifted"
        );
        assert_eq!(
            manifest_op["safety_tier"].as_str(),
            introspection_op["safety_tier"].as_str(),
            "{operation_id} safety tier drifted"
        );
        assert_eq!(
            manifest_op["idempotency"].as_str(),
            introspection_op["idempotency"].as_str(),
            "{operation_id} idempotency drifted"
        );
        assert_eq!(
            manifest_op["requires_approval"].as_str(),
            introspection_op["requires_approval"].as_str(),
            "{operation_id} approval mode drifted"
        );
        assert!(
            manifest_op["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} manifest ai_hints are empty"
        );
    }
}

fn introspection_operation_ids(introspection: &Value) -> BTreeSet<&str> {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection should expose operations array")
        .iter()
        .map(|operation| {
            operation
                .get("id")
                .and_then(Value::as_str)
                .expect("operation id should be a string")
        })
        .collect()
}

fn introspection_operation<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection should expose operations array")
        .iter()
        .find(|operation| operation.get("id").and_then(Value::as_str) == Some(operation_id))
        .expect("expected operation should be advertised")
}

fn manifest_operation_ids(manifest: &toml::Value) -> BTreeSet<&str> {
    value_at(manifest, &["provides", "operations"])
        .as_table()
        .expect("manifest provides.operations should be a table")
        .keys()
        .map(String::as_str)
        .collect()
}

fn value_at<'a>(value: &'a toml::Value, path: &[&str]) -> &'a toml::Value {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .expect("manifest path segment should exist");
    }
    current
}

fn string_at<'a>(value: &'a toml::Value, path: &[&str]) -> &'a str {
    value_at(value, path)
        .as_str()
        .expect("manifest path should contain a string")
}

fn integer_at(value: &toml::Value, path: &[&str]) -> i64 {
    value_at(value, path)
        .as_integer()
        .expect("manifest path should contain an integer")
}

fn bool_at(value: &toml::Value, path: &[&str]) -> bool {
    value_at(value, path)
        .as_bool()
        .expect("manifest path should contain a bool")
}

fn assert_array_contains(value: &toml::Value, path: &[&str], expected: &str) {
    let array = value_at(value, path)
        .as_array()
        .expect("manifest path should contain an array");
    assert!(
        array.iter().any(|item| item.as_str() == Some(expected)),
        "{} should contain {expected}",
        path.join(".")
    );
}

fn assert_redacted(value: &str) {
    for forbidden in [
        "password",
        "secret",
        "token",
        "@example.com",
        "/Users/",
        "/tmp/",
    ] {
        assert!(
            !value.to_ascii_lowercase().contains(forbidden),
            "operator-facing guidance leaked forbidden marker: {forbidden}"
        );
    }
}
