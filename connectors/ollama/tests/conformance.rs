use fcp_ollama::OllamaConnector;
use fcp_ollama::connector::CONNECTOR_ID;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn manifest_declares_local_service_operations_network_and_capabilities() {
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
    assert_eq!(
        manifest
            .get("sandbox")
            .and_then(|value| value.get("profile"))
            .and_then(toml::Value::as_str),
        Some("moderate")
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
        "ollama.chat",
        "ollama.embeddings",
        "ollama.models.read",
        "ollama.health.read",
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
    assert_eq!(operations.len(), 5);
    for operation in [
        "ollama.chat.completions",
        "ollama.chat.completions_stream",
        "ollama.embeddings.create",
        "ollama.models.list",
        "ollama.health",
    ] {
        let operation = operations
            .get(operation)
            .expect("operation should be declared");
        assert_local_service_network_constraints(operation);
    }
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = OllamaConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    for operation in [
        "ollama.chat.completions",
        "ollama.chat.completions_stream",
        "ollama.embeddings.create",
        "ollama.models.list",
        "ollama.health",
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

fn assert_local_service_network_constraints(operation: &toml::Value) {
    let constraints = operation
        .get("network_constraints")
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
        vec!["localhost", "127.0.0.1", "::1"]
    );
    assert_eq!(
        constraints
            .get("require_sni")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        constraints
            .get("deny_localhost")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        constraints
            .get("deny_private_ranges")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        constraints
            .get("max_redirects")
            .and_then(toml::Value::as_integer),
        Some(0)
    );
}
