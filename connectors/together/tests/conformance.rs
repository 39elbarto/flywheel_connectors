use fcp_prelude::FcpConnector;
use fcp_together::TogetherConnector;
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
        "together.chat.completions",
        "together.chat.completions_stream",
        "together.embeddings.create",
        "together.models.list",
        "together.health",
        "together.completions.legacy",
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
            Some("api.together.ai")
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
        operations.get("together.images.generate").is_none(),
        "image generation must remain out of the text-focused operation surface"
    );
    assert_eq!(
        manifest
            .get("metadata")
            .and_then(|value| value.get("deferred"))
            .and_then(|value| value.get("images.generate"))
            .and_then(|value| value.get("availability"))
            .and_then(toml::Value::as_str),
        Some("deferred-to-media-generation")
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = TogetherConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"together.chat.completions"));
    assert!(ids.contains(&"together.chat.completions_stream"));
    assert!(ids.contains(&"together.embeddings.create"));
    assert!(ids.contains(&"together.models.list"));
    assert!(ids.contains(&"together.health"));
    assert!(ids.contains(&"together.completions.legacy"));
    assert!(!ids.contains(&"together.images.generate"));

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
