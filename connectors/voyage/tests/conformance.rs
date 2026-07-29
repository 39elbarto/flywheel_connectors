#![allow(clippy::panic)]

use serde_json::Value;

#[test]
fn manifest_matches_connector_id_and_declares_voyage_surface() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    assert_eq!(
        manifest
            .get("connector")
            .and_then(|connector| connector.get("id"))
            .and_then(toml::Value::as_str),
        Some("fcp.voyage")
    );
    assert_eq!(
        manifest
            .get("connector")
            .and_then(|connector| connector.get("archetypes"))
            .and_then(toml::Value::as_array)
            .map(|archetypes| {
                archetypes
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            }),
        Some(vec!["operational"])
    );
    assert_eq!(
        manifest
            .get("capabilities")
            .and_then(|capabilities| capabilities.get("optional"))
            .and_then(toml::Value::as_array)
            .map(|capabilities| {
                capabilities
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            }),
        Some(vec![
            "voyage.embeddings",
            "voyage.rerank",
            "voyage.models.read",
            "voyage.health.read",
        ])
    );

    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");
    assert_eq!(operations.len(), 5);
    for operation in [
        "voyage.embeddings.create",
        "voyage.embeddings.create_multimodal",
        "voyage.rerank",
        "voyage.models.list",
        "voyage.health",
    ] {
        assert!(operations.contains_key(operation), "{operation} missing");
    }
}

#[test]
fn manifest_sandbox_is_strict_and_evidence_friendly() {
    let manifest: Value = serde_json::to_value(
        toml::from_str::<toml::Value>(include_str!("../manifest.toml"))
            .expect("manifest should parse"),
    )
    .expect("manifest should convert");
    assert_eq!(manifest["sandbox"]["profile"], "strict");
    assert_eq!(manifest["sandbox"]["deny_exec"], true);
    assert_eq!(manifest["sandbox"]["memory_mb"], 128);

    let operations = manifest["provides"]["operations"]
        .as_object()
        .expect("operations object");
    for (operation_id, operation) in operations {
        let constraints = &operation["network_constraints"];
        assert_eq!(
            constraints["host_allow"]
                .as_array()
                .expect("host_allow array"),
            &[Value::String("api.voyageai.com".to_string())],
            "{operation_id} must only allow the canonical Voyage API host"
        );
        assert_eq!(
            constraints["require_sni"], true,
            "{operation_id} must require SNI"
        );
        assert_eq!(constraints["deny_private_ranges"], true);
        assert_eq!(constraints["deny_localhost"], true);
        assert_eq!(constraints["deny_tailnet_ranges"], true);
        assert_eq!(constraints["deny_ip_literals"], true);
        assert_eq!(constraints["max_redirects"], 3);
    }
}

#[test]
fn manifest_operations_have_capabilities_schemas_and_ai_hints() {
    let manifest: Value = serde_json::to_value(
        toml::from_str::<toml::Value>(include_str!("../manifest.toml"))
            .expect("manifest should parse"),
    )
    .expect("manifest should convert");
    let operations = manifest["provides"]["operations"]
        .as_object()
        .expect("operations object");

    let expected = [
        ("voyage.embeddings.create", "voyage.embeddings"),
        ("voyage.embeddings.create_multimodal", "voyage.embeddings"),
        ("voyage.rerank", "voyage.rerank"),
        ("voyage.models.list", "voyage.models.read"),
        ("voyage.health", "voyage.health.read"),
    ];
    for (operation_id, capability) in expected {
        let operation = operations
            .get(operation_id)
            .expect("expected Voyage operation missing");
        assert_eq!(operation["capability"], capability);
        assert_eq!(operation["risk_level"], "low");
        assert_eq!(operation["safety_tier"], "safe");
        assert_eq!(operation["requires_approval"], "none");
        assert_eq!(operation["idempotency"], "strict");
        assert_eq!(operation["input_schema"]["type"], "object");
        assert_eq!(operation["output_schema"]["type"], "object");

        let hints = operation["ai_hints"]
            .as_object()
            .expect("expected Voyage operation AI hints missing");
        assert!(hints.contains_key("when_to_use"));
        assert!(hints.contains_key("common_mistakes"));
        assert!(hints.contains_key("examples"));
        assert!(hints.contains_key("related"));
    }
}
