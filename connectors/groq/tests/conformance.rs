use fcp_groq::GroqConnector;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn manifest_declares_required_operations_and_network_policy() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    let operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");

    for operation in [
        "groq.chat.completions",
        "groq.chat.completions_stream",
        "groq.models.list",
        "groq.health",
        "groq.embeddings.create",
        "groq.completions.legacy",
    ] {
        let op = operations
            .get(operation)
            .expect("operation should be declared");
        let constraints = op
            .get("network_constraints")
            .and_then(toml::Value::as_table)
            .expect("network constraints should exist");
        assert_eq!(
            constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }

    assert_eq!(
        operations
            .get("groq.embeddings.create")
            .and_then(|op| op.get("availability"))
            .and_then(toml::Value::as_str),
        Some("not_supported")
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = GroqConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"groq.chat.completions"));
    assert!(ids.contains(&"groq.chat.completions_stream"));
    assert!(ids.contains(&"groq.models.list"));
    assert!(ids.contains(&"groq.health"));
    assert!(ids.contains(&"groq.embeddings.create"));
    assert!(ids.contains(&"groq.completions.legacy"));

    for operation in introspection.operations {
        let value = serde_json::to_value(&operation).expect("operation serializes");
        assert!(matches!(value["input_schema"], Value::Object(_)));
        assert!(matches!(value["output_schema"], Value::Object(_)));
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "operation {} should have AI guidance",
            operation.id
        );
    }
}
