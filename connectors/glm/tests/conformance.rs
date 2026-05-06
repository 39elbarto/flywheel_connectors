use fcp_glm::connector::CONNECTOR_ID;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    connector: Connector,
    capabilities: Capabilities,
    sandbox: Sandbox,
}

#[derive(Debug, Deserialize)]
struct Connector {
    id: String,
    archetypes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Capabilities {
    optional: Vec<String>,
    forbidden: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Sandbox {
    profile: String,
    memory_mb: u32,
    wall_clock_timeout_ms: u64,
    deny_exec: bool,
}

#[test]
fn manifest_matches_connector_id_and_declares_glm_surface() {
    let manifest: Manifest =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");

    assert_eq!(manifest.connector.id, CONNECTOR_ID);
    assert!(
        manifest
            .connector
            .archetypes
            .contains(&"request-response".to_string())
    );
    assert!(
        manifest
            .connector
            .archetypes
            .contains(&"streaming".to_string())
    );
    assert!(
        manifest
            .capabilities
            .optional
            .contains(&"glm.chat".to_string())
    );
    assert!(
        manifest
            .capabilities
            .optional
            .contains(&"glm.embeddings".to_string())
    );
    assert!(
        manifest
            .capabilities
            .optional
            .contains(&"glm.models.read".to_string())
    );
    assert!(
        manifest
            .capabilities
            .forbidden
            .contains(&"system.exec".to_string())
    );
}

#[test]
fn manifest_sandbox_is_strict_and_long_enough_for_glm_completion() {
    let manifest: Manifest =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");

    assert_eq!(manifest.sandbox.profile, "strict");
    assert_eq!(manifest.sandbox.memory_mb, 128);
    assert!(manifest.sandbox.wall_clock_timeout_ms >= 180_000);
    assert!(manifest.sandbox.deny_exec);
}
