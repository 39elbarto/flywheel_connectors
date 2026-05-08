use fcp_imessage::BlueBubblesConnector;
use fcp_prelude::{FcpConnector, IdempotencyClass, RiskLevel, SafetyTier};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[test]
fn operation_manifest_and_introspection_contracts_stay_aligned() {
    let connector = BlueBubblesConnector::new();
    let introspection = connector.introspect();

    assert_eq!(connector.id().as_str(), "fcp.imessage");

    let expected = expected_operations();
    assert_eq!(
        introspection.operations.len(),
        expected.len(),
        "new operations must be added to this conformance inventory"
    );

    let operations = introspection
        .operations
        .iter()
        .map(|operation| (operation.id.as_str(), operation))
        .collect::<BTreeMap<_, _>>();

    for expected_operation in expected {
        let operation = operations
            .get(expected_operation.id)
            .unwrap_or_else(|| panic!("missing operation {}", expected_operation.id));

        assert_eq!(
            operation.capability.as_str(),
            expected_operation.capability,
            "{} capability",
            expected_operation.id
        );
        assert_eq!(
            operation.risk_level, expected_operation.risk_level,
            "{} risk level",
            expected_operation.id
        );
        assert_eq!(
            operation.safety_tier, expected_operation.safety_tier,
            "{} safety tier",
            expected_operation.id
        );
        assert_eq!(
            operation.idempotency, expected_operation.idempotency,
            "{} idempotency",
            expected_operation.id
        );
        assert!(
            !operation.summary.trim().is_empty(),
            "{} must carry an operator-facing summary",
            expected_operation.id
        );
        let description = operation
            .description
            .as_deref()
            .unwrap_or_else(|| panic!("{} must carry a description", expected_operation.id));
        assert!(
            !description.trim().is_empty(),
            "{} must carry an operator-facing description",
            expected_operation.id
        );
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{} must expose actionable ai_hints.when_to_use",
            expected_operation.id
        );
        assert_object_schema(expected_operation.id, "input", &operation.input_schema);
        assert_object_schema(expected_operation.id, "output", &operation.output_schema);
        assert_manifest_mentions_operation(expected_operation.id);
    }

    assert_required_fields(
        &operations["imessage.send_message"].input_schema,
        &["chat_guid", "message"],
    );
    assert_required_fields(
        &operations["imessage.send_media"].input_schema,
        &["local_path"],
    );
    assert!(
        operations["imessage.send_media"]
            .input_schema
            .get("oneOf")
            .is_some(),
        "send_media must require exactly one destination selector"
    );
    assert_required_fields(
        &operations["imessage.ingest_webhook_request"].input_schema,
        &["method", "url", "body"],
    );
}

#[test]
fn events_capabilities_and_manifest_guardrails_are_declared() {
    let connector = BlueBubblesConnector::new();
    let introspection = connector.introspect();

    let capabilities = introspection
        .operations
        .iter()
        .map(|operation| operation.capability.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        capabilities,
        BTreeSet::from(["imessage.admin", "imessage.read", "imessage.send"])
    );

    let event_topics = introspection
        .events
        .iter()
        .map(|event| event.topic.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        event_topics,
        BTreeSet::from([
            "imessage.message.inbound",
            "imessage.message.outbound",
            "imessage.message.tapback",
            "imessage.message.updated"
        ])
    );
    for event in &introspection.events {
        assert_object_schema(event.topic.as_str(), "event", &event.schema);
    }

    for needle in [
        r#"id = "fcp.imessage""#,
        r#"home = "z:private""#,
        r#"[provides.operations.send_message.network_constraints]"#,
        r#"host_allow = ["localhost", "127.0.0.1"]"#,
        r#"port_allow = [1234]"#,
        r#"max_redirects = 0"#,
        r#"[provides.events.message_inbound]"#,
        r#"[provides.events.message_outbound]"#,
        r#"[provides.events.message_updated]"#,
        r#"[provides.events.message_tapback]"#,
        r#"topic = "imessage.message.inbound""#,
        r#"topic = "imessage.message.tapback""#,
    ] {
        assert!(
            MANIFEST_TOML.contains(needle),
            "manifest must contain guardrail: {needle}"
        );
    }
}

fn assert_object_schema(operation_id: &str, direction: &str, schema: &Value) {
    assert_eq!(
        schema.get("type").and_then(Value::as_str),
        Some("object"),
        "{operation_id} {direction} schema must be an object"
    );
    assert!(
        schema.get("properties").is_some()
            || schema.get("oneOf").is_some()
            || schema.get("anyOf").is_some()
            || is_declared_zero_input_operation(operation_id, direction),
        "{operation_id} {direction} schema must expose machine-readable shape"
    );
}

fn is_declared_zero_input_operation(operation_id: &str, direction: &str) -> bool {
    direction == "input"
        && matches!(
            operation_id,
            "imessage.get_action_availability"
                | "imessage.list_webhooks"
                | "imessage.get_server_info"
        )
}

fn assert_required_fields(schema: &Value, required_fields: &[&str]) {
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("schema must declare required fields"));
    for field in required_fields {
        assert!(
            required.iter().any(|value| value.as_str() == Some(*field)),
            "schema must require {field}"
        );
    }
}

fn assert_manifest_mentions_operation(operation_id: &str) {
    let short_name = operation_id
        .strip_prefix("imessage.")
        .unwrap_or(operation_id)
        .replace('.', "_");
    let section = format!("[provides.operations.{short_name}]");
    assert!(
        MANIFEST_TOML.contains(&section),
        "manifest missing operation section {section}"
    );
}

struct ExpectedOperation {
    id: &'static str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
}

fn expected_operations() -> Vec<ExpectedOperation> {
    use IdempotencyClass::{BestEffort, None, Strict};
    use RiskLevel::{High, Low, Medium};
    use SafetyTier::{Dangerous, Risky, Safe};

    vec![
        ExpectedOperation {
            id: "imessage.send_message",
            capability: "imessage.send",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: None,
        },
        ExpectedOperation {
            id: "imessage.send_media",
            capability: "imessage.send",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: None,
        },
        ExpectedOperation {
            id: "imessage.resolve_send_target",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.create_chat",
            capability: "imessage.send",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: None,
        },
        ExpectedOperation {
            id: "imessage.get_action_availability",
            capability: "imessage.admin",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.edit_message",
            capability: "imessage.send",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: None,
        },
        ExpectedOperation {
            id: "imessage.unsend_message",
            capability: "imessage.send",
            risk_level: High,
            safety_tier: Dangerous,
            idempotency: None,
        },
        ExpectedOperation {
            id: "imessage.send_reaction",
            capability: "imessage.send",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: BestEffort,
        },
        ExpectedOperation {
            id: "imessage.set_typing",
            capability: "imessage.send",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: BestEffort,
        },
        ExpectedOperation {
            id: "imessage.get_chats",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.get_chat",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.get_messages",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.sync_events",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.download_attachment",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.mark_read",
            capability: "imessage.send",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: BestEffort,
        },
        ExpectedOperation {
            id: "imessage.get_server_info",
            capability: "imessage.admin",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.register_webhook",
            capability: "imessage.admin",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: BestEffort,
        },
        ExpectedOperation {
            id: "imessage.list_webhooks",
            capability: "imessage.admin",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: Strict,
        },
        ExpectedOperation {
            id: "imessage.unregister_webhook",
            capability: "imessage.admin",
            risk_level: Medium,
            safety_tier: Risky,
            idempotency: BestEffort,
        },
        ExpectedOperation {
            id: "imessage.ingest_webhook_event",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: BestEffort,
        },
        ExpectedOperation {
            id: "imessage.ingest_webhook_request",
            capability: "imessage.read",
            risk_level: Low,
            safety_tier: Safe,
            idempotency: BestEffort,
        },
    ]
}
