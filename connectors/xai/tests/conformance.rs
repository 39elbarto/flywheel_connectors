use fcp_prelude::FcpConnector;
use fcp_xai::XaiConnector;
use fcp_xai::connector::CONNECTOR_ID;
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
        "xai.chat",
        "xai.models.read",
        "xai.responses.web_search",
        "xai.health.read",
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
    for operation in [
        "xai.chat.completions",
        "xai.chat.completions_stream",
        "xai.responses.create",
        "xai.models.list",
        "xai.health",
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
            vec!["api.x.ai"]
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
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = XaiConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"xai.chat.completions"));
    assert!(ids.contains(&"xai.chat.completions_stream"));
    assert!(ids.contains(&"xai.responses.create"));
    assert!(ids.contains(&"xai.models.list"));
    assert!(ids.contains(&"xai.health"));

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
