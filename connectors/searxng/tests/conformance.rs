use serde_json::Value;

#[test]
fn manifest_declares_self_hosted_privacy_boundary() {
    let manifest: Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    assert_eq!(manifest["connector"]["id"], "fcp.searxng");
    assert_eq!(manifest["zones"]["home"], "z:work");
    assert!(
        manifest["connector"]["description"]
            .as_str()
            .expect("description should be present")
            .contains("Self-hosted")
    );

    let operations = manifest["provides"]["operations"]
        .as_object()
        .expect("operations should be declared");
    assert_eq!(operations.len(), 4);
    for (operation_id, operation) in operations {
        let constraints = &operation["network_constraints"];
        assert_eq!(
            constraints["host_allow"][0],
            Value::String("operator-configured".into()),
            "{operation_id} should only target the configured SearXNG host"
        );
        assert_eq!(constraints["deny_localhost"], false);
        assert_eq!(constraints["deny_private_ranges"], false);
        assert_eq!(constraints["deny_tailnet_ranges"], false);
    }
}

#[test]
fn manifest_sandbox_blocks_listener_and_exec() {
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
    assert!(
        manifest["connector"]["description"]
            .as_str()
            .expect("description should be present")
            .contains("no commercial fallback")
    );
}
