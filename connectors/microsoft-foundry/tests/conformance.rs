use fcp_microsoft_foundry::MicrosoftFoundryConnector;
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
        "microsoft_foundry.responses.create",
        "microsoft_foundry.responses.cancel",
        "microsoft_foundry.responses.input_items.list",
        "microsoft_foundry.chat.completions",
        "microsoft_foundry.chat.completions_stream",
        "microsoft_foundry.embeddings.create",
        "microsoft_foundry.deployments.list",
        "microsoft_foundry.health",
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
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = MicrosoftFoundryConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    for operation in [
        "microsoft_foundry.responses.create",
        "microsoft_foundry.responses.cancel",
        "microsoft_foundry.responses.input_items.list",
        "microsoft_foundry.chat.completions",
        "microsoft_foundry.chat.completions_stream",
        "microsoft_foundry.embeddings.create",
        "microsoft_foundry.deployments.list",
        "microsoft_foundry.health",
    ] {
        assert!(ids.contains(&operation));
    }

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
