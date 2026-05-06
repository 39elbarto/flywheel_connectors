use fcp_moonshot::MoonshotConnector;
use fcp_moonshot::connector::CONNECTOR_ID;
use fcp_prelude::FcpConnector;
use serde_json::Value;

fn manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse")
}

#[test]
fn manifest_declares_required_operations_network_policy_and_context_guidance() {
    let manifest = manifest();
    assert_eq!(manifest["connector"]["id"].as_str(), Some(CONNECTOR_ID));
    assert_eq!(manifest["sandbox"]["memory_mb"].as_integer(), Some(192));
    let operations = manifest["provides"]["operations"]
        .as_table()
        .expect("operations table");
    for operation in [
        "moonshot.chat.completions",
        "moonshot.chat.completions_stream",
        "moonshot.models.list",
        "moonshot.health",
        "moonshot.embeddings.create",
    ] {
        assert!(operations.contains_key(operation), "missing {operation}");
    }
    assert!(
        operations["moonshot.embeddings.create"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("do not expose"))
    );
    let hosts = operations["moonshot.chat.completions"]["network_constraints"]["host_allow"]
        .as_array()
        .expect("host allow");
    assert!(
        hosts
            .iter()
            .any(|host| host.as_str() == Some("api.moonshot.ai"))
    );
    assert!(
        hosts
            .iter()
            .any(|host| host.as_str() == Some("api.moonshot.cn"))
    );
    assert_eq!(
        operations["moonshot.chat.completions"]["input_schema"]["properties"]
            ["context_window_tokens"]["minimum"]
            .as_integer(),
        Some(1)
    );
    assert!(
        operations["moonshot.chat.completions"]["ai_hints"]["common_mistakes"]
            .as_array()
            .expect("chat common mistakes")
            .iter()
            .any(|value| value
                .as_str()
                .is_some_and(|text| text.contains("estimated_input_tokens")))
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let connector = MoonshotConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str().to_string())
        .collect::<Vec<_>>();
    let manifest = manifest();
    let operations = manifest["provides"]["operations"]
        .as_table()
        .expect("operations table");
    assert_eq!(ids.len(), operations.len());
    for id in operations.keys() {
        assert!(ids.contains(id), "introspection missing {id}");
    }

    let serialized = serde_json::to_value(introspection).expect("introspection should serialize");
    assert!(
        serialized
            .to_string()
            .contains("refusing to silently truncate")
            || serialized.to_string().contains("estimated_input_tokens"),
        "introspection should advertise context-limit behavior"
    );
}

#[test]
fn manifest_examples_do_not_contain_secrets_or_prompt_corpus() {
    let manifest = manifest();
    let manifest_json: Value = serde_json::to_value(manifest).expect("manifest to json");
    let text = manifest_json.to_string();
    assert!(!text.contains(concat!("MOONSHOT", "_API", "_KEY")));
    assert!(!text.contains("Bearer "));
    assert!(!text.contains("long document content"));
}
