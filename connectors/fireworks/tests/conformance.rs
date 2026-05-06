use fcp_fireworks::FireworksConnector;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn manifest_declares_required_operations_network_policy_and_deferred_images() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    let operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");

    for operation in [
        "fireworks.chat.completions",
        "fireworks.chat.completions_stream",
        "fireworks.embeddings.create",
        "fireworks.models.list",
        "fireworks.health",
        "fireworks.completions.legacy",
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
                .get("host_allow")
                .and_then(toml::Value::as_array)
                .and_then(|hosts| hosts.first())
                .and_then(toml::Value::as_str),
            Some("api.fireworks.ai")
        );
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

    assert!(
        operations.get("fireworks.images.generate").is_none(),
        "workflow image generation must remain out of the text-focused operation surface"
    );
    let chat_hints = operations
        .get("fireworks.chat.completions")
        .and_then(|operation| operation.get("ai_hints"))
        .and_then(|hints| hints.get("common_mistakes"))
        .and_then(toml::Value::as_array)
        .expect("chat operation should include guidance");
    assert!(
        chat_hints.iter().any(|hint| hint
            .as_str()
            .is_some_and(|text| text.contains("workflow image generation"))),
        "deferred workflow image generation must be documented in supported ai_hints"
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = FireworksConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"fireworks.chat.completions"));
    assert!(ids.contains(&"fireworks.chat.completions_stream"));
    assert!(ids.contains(&"fireworks.embeddings.create"));
    assert!(ids.contains(&"fireworks.models.list"));
    assert!(ids.contains(&"fireworks.health"));
    assert!(ids.contains(&"fireworks.completions.legacy"));
    assert!(!ids.contains(&"fireworks.images.generate"));

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
