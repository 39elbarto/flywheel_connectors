use fcp_prelude::FcpConnector;
use fcp_qwen::QwenConnector;
use fcp_qwen::connector::CONNECTOR_ID;
use serde_json::Value;

#[test]
fn manifest_declares_required_operations_network_policy_and_no_native_dashscope() {
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
        "qwen.chat.completions",
        "qwen.chat.completions_stream",
        "qwen.embeddings.create",
        "qwen.models.list",
        "qwen.health",
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
        assert!(hosts.contains(&"dashscope-intl.aliyuncs.com"));
        assert!(hosts.contains(&"dashscope.aliyuncs.com"));
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
        operations.get("qwen.dashscope_native.generate").is_none(),
        "DashScope-native endpoints must stay out of this compatible-mode connector"
    );
    let chat_hints = operations
        .get("qwen.chat.completions")
        .and_then(|value| value.get("ai_hints"))
        .and_then(|value| value.get("common_mistakes"))
        .and_then(toml::Value::as_array)
        .expect("chat operation should carry common mistake hints");
    assert!(
        chat_hints
            .iter()
            .filter_map(toml::Value::as_str)
            .any(|hint| hint.contains("image_url")),
        "Qwen-VL image_url guidance should be visible in supported ai_hints"
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = QwenConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"qwen.chat.completions"));
    assert!(ids.contains(&"qwen.chat.completions_stream"));
    assert!(ids.contains(&"qwen.embeddings.create"));
    assert!(ids.contains(&"qwen.models.list"));
    assert!(ids.contains(&"qwen.health"));
    assert!(!ids.contains(&"qwen.dashscope_native.generate"));

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
