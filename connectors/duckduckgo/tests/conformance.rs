use serde_json::Value;

#[test]
fn manifest_declares_privacy_search_surface() {
    let manifest: Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    assert_eq!(manifest["connector"]["id"], "fcp.duckduckgo");
    assert_eq!(manifest["zones"]["home"], "z:public");
    assert!(
        manifest["connector"]["description"]
            .as_str()
            .expect("description should be present")
            .contains("Privacy-preserving")
    );
    let host_allow = manifest["network_constraints"]["host_allow"]
        .as_array()
        .expect("host_allow should be an array");
    assert!(host_allow.contains(&Value::String("html.duckduckgo.com".into())));
    assert!(host_allow.contains(&Value::String("api.duckduckgo.com".into())));
    assert!(host_allow.contains(&Value::String("duckduckgo.com".into())));
}

#[test]
fn manifest_sandbox_is_strict_no_listener_no_exec() {
    let manifest: Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    assert_eq!(manifest["sandbox"]["profile"], "strict");
    assert_eq!(manifest["sandbox"]["deny_exec"], true);
    assert!(
        manifest["capabilities"]["forbidden"]
            .as_array()
            .expect("forbidden capabilities should be present")
            .contains(&Value::String("network.listen".into()))
    );
}
