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

    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");
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
    for (_, operation) in operations {
        let constraints = &operation["network_constraints"];
        assert_eq!(constraints["host_allow"][0], "api.voyageai.com");
        assert_eq!(constraints["deny_private_ranges"], true);
        assert_eq!(constraints["deny_ip_literals"], true);
    }
}
