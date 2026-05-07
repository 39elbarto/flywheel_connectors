use fcp_comfyui::ComfyUiConnector;
use fcp_comfyui::connector::CONNECTOR_ID;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn manifest_declares_self_hosted_operations_and_network_policy() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    assert_eq!(
        manifest
            .get("connector")
            .and_then(|value| value.get("id"))
            .and_then(toml::Value::as_str),
        Some(CONNECTOR_ID)
    );
    let operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");

    for operation in [
        "comfyui.workflow.submit",
        "comfyui.workflow.status",
        "comfyui.workflow.result",
        "comfyui.workflow.cancel",
        "comfyui.workflow.wait_until_complete",
        "comfyui.health",
    ] {
        let op = operations
            .get(operation)
            .expect("operation should be declared");
        let constraints = op
            .get("network_constraints")
            .and_then(toml::Value::as_table)
            .expect("network constraints should exist");
        let hosts = constraints
            .get("host_allow")
            .and_then(toml::Value::as_array)
            .expect("host allowlist should exist")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>();
        assert!(hosts.contains(&"localhost"));
        assert!(hosts.contains(&"127.0.0.1"));
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
                .get("deny_tailnet_ranges")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
    }

    assert!(
        include_str!("../manifest.toml").contains("Do not log workflow JSON"),
        "manifest guidance should warn against workflow logging"
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = ComfyUiConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"comfyui.workflow.submit"));
    assert!(ids.contains(&"comfyui.workflow.status"));
    assert!(ids.contains(&"comfyui.workflow.result"));
    assert!(ids.contains(&"comfyui.workflow.cancel"));
    assert!(ids.contains(&"comfyui.workflow.wait_until_complete"));
    assert!(ids.contains(&"comfyui.health"));

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
