use serde_json::Value;

const EXPECTED_OPERATIONS: [&str; 5] = [
    "duckduckgo.search.text",
    "duckduckgo.search.images",
    "duckduckgo.search.news",
    "duckduckgo.search.suggestions",
    "duckduckgo.health",
];

#[test]
fn manifest_declares_privacy_search_surface_and_operations() {
    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("manifest should validate");
    assert_eq!(manifest.connector.id.as_str(), "fcp.duckduckgo");
    assert_eq!(manifest.zones.home.as_str(), "z:public");
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATIONS.len()
    );
    assert!(
        manifest
            .connector
            .description
            .contains("Privacy-preserving")
    );

    for operation_id in EXPECTED_OPERATIONS {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared");
        assert_eq!(operation.capability.as_str(), "duckduckgo.search.read");
        assert_eq!(operation.input_schema["type"], "object");
        assert_eq!(operation.output_schema["type"], "object");
        assert!(!operation.ai_hints.when_to_use.trim().is_empty());
        assert!(
            !operation
                .network_constraints
                .as_ref()
                .expect("network constraints should be present")
                .host_allow
                .is_empty()
        );
    }
}

#[test]
fn manifest_operation_hosts_are_per_operation_not_broad_defaults() {
    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("manifest should validate");
    let hosts_for = |operation_id: &str| {
        manifest.provides.operations[operation_id]
            .network_constraints
            .as_ref()
            .expect("network constraints should be present")
            .host_allow
            .clone()
    };
    assert_eq!(
        hosts_for("duckduckgo.search.text"),
        ["html.duckduckgo.com", "lite.duckduckgo.com"]
    );
    assert_eq!(
        hosts_for("duckduckgo.search.images"),
        [
            "html.duckduckgo.com",
            "lite.duckduckgo.com",
            "duckduckgo.com"
        ]
    );
    assert_eq!(
        hosts_for("duckduckgo.search.news"),
        [
            "html.duckduckgo.com",
            "lite.duckduckgo.com",
            "duckduckgo.com"
        ]
    );
    assert_eq!(
        hosts_for("duckduckgo.search.suggestions"),
        ["duckduckgo.com"]
    );
    assert_eq!(hosts_for("duckduckgo.health"), ["api.duckduckgo.com"]);
}

#[test]
fn legacy_toml_view_still_declares_no_listener_no_exec() {
    let manifest: Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest TOML should parse");
    assert_eq!(manifest["connector"]["id"], "fcp.duckduckgo");
    assert_eq!(manifest["zones"]["home"], "z:public");
    assert!(
        manifest["connector"]["description"]
            .as_str()
            .expect("description should be present")
            .contains("Privacy-preserving")
    );
    assert_eq!(manifest["sandbox"]["profile"], "strict");
    assert_eq!(manifest["sandbox"]["deny_exec"], true);
    assert!(
        manifest["capabilities"]["forbidden"]
            .as_array()
            .expect("forbidden capabilities should be present")
            .contains(&Value::String("network.listen".into()))
    );
}
