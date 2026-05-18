use fcp_microsoft_foundry::MicrosoftFoundryConnector;
use fcp_microsoft_foundry::connector::CONNECTOR_ID;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn manifest_declares_required_operations_network_and_capabilities() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");

    assert_eq!(
        manifest
            .get("connector")
            .and_then(|value| value.get("id"))
            .and_then(toml::Value::as_str),
        Some(CONNECTOR_ID)
    );
    assert_eq!(
        manifest
            .get("connector")
            .and_then(|value| value.get("archetypes"))
            .and_then(toml::Value::as_array)
            .expect("archetypes should exist")
            .iter()
            .map(toml::Value::as_str)
            .collect::<Option<Vec<_>>>()
            .expect("archetypes should be strings"),
        vec!["operational", "streaming"]
    );

    let optional_capabilities = manifest
        .get("capabilities")
        .and_then(|value| value.get("optional"))
        .and_then(toml::Value::as_array)
        .expect("optional capabilities should exist")
        .iter()
        .map(toml::Value::as_str)
        .collect::<Option<Vec<_>>>()
        .expect("optional capabilities should be strings");
    for capability in [
        "microsoft_foundry.responses",
        "microsoft_foundry.chat",
        "microsoft_foundry.embeddings",
        "microsoft_foundry.deployments.read",
        "microsoft_foundry.health",
    ] {
        assert!(
            optional_capabilities.contains(&capability),
            "missing capability {capability}"
        );
    }

    let operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");
    assert_eq!(operations.len(), 8);
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
        let constraints = operations
            .get(operation)
            .and_then(|op| op.get("network_constraints"))
            .and_then(toml::Value::as_table)
            .expect("network constraints should exist");
        assert_eq!(
            constraints
                .get("host_allow")
                .and_then(toml::Value::as_array)
                .expect("host allow")
                .iter()
                .map(toml::Value::as_str)
                .collect::<Option<Vec<_>>>()
                .expect("host allow strings"),
            vec!["*.openai.azure.com", "*.services.ai.azure.com"]
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

    assert_eq!(
        operations
            .get("microsoft_foundry.responses.cancel")
            .and_then(|op| op.get("idempotency"))
            .and_then(toml::Value::as_str),
        Some("best_effort")
    );
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
        assert!(ids.contains(&operation), "missing operation {operation}");
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
