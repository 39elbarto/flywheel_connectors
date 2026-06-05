use fcp_manifest::ConnectorManifest;
use fcp_runway::RunwayConnector;
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 8] = [
    "runway.video.image_to_video",
    "runway.video.text_to_video",
    "runway.video.video_to_video",
    "runway.image.text_to_image",
    "runway.job.status",
    "runway.job.cancel",
    "runway.job.wait_until_complete",
    "runway.health",
];

fn manifest_toml() -> toml::Value {
    toml::from_str(MANIFEST_TOML).expect("manifest should parse")
}

fn manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(MANIFEST_TOML).expect("manifest should parse")
}

#[test]
fn manifest_declares_required_operations_network_policy_and_redaction() {
    let manifest = manifest_toml();
    let operations = manifest["provides"]["operations"]
        .as_table()
        .expect("operations table");
    for operation in EXPECTED_OPERATION_IDS {
        assert!(
            operations.contains_key(operation),
            "missing operation {operation}"
        );
        let constraints = &operations[operation]["network_constraints"];
        assert!(
            constraints["host_allow"]
                .as_array()
                .expect("host allow array")
                .iter()
                .any(|host| host.as_str() == Some("api.dev.runwayml.com")),
            "{operation} should allow Runway API host"
        );
        assert_eq!(constraints["deny_private_ranges"].as_bool(), Some(true));
    }

    let text = serde_json::to_string(&serde_json::to_value(manifest).expect("manifest to json"))
        .expect("manifest json string");
    assert!(text.contains("2024-11-06"));
    assert!(text.contains("Do not log promptText"));
    assert!(!text.contains("RUNWAY_API_KEY"));
    assert!(!text.contains("Bearer "));
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let manifest = manifest();
    let introspection: Value =
        fcp_async_core::runtime::block_on_sync(RunwayConnector::new().handle_introspect())
            .expect("runtime should run")
            .expect("introspection should work");
    let runtime_operations = introspection["operations"]
        .as_array()
        .expect("runtime operations array");
    let ids = runtime_operations
        .iter()
        .map(|operation| operation["id"].as_str().expect("operation id"))
        .collect::<Vec<_>>();
    assert_eq!(ids, EXPECTED_OPERATION_IDS);
    assert_eq!(runtime_operations.len(), manifest.provides.operations.len());

    for runtime_operation in runtime_operations {
        let id = runtime_operation["id"].as_str().expect("operation id");
        let manifest_operation = manifest
            .provides
            .operations
            .get(id)
            .unwrap_or_else(|| panic!("manifest operation {id}"));
        assert_eq!(runtime_operation["summary"], manifest_operation.description);
        assert_eq!(
            runtime_operation["description"],
            json!(manifest_operation.description)
        );
        assert_eq!(
            runtime_operation["capability"],
            json!(manifest_operation.capability)
        );
        assert_eq!(
            runtime_operation["risk_level"],
            json!(manifest_operation.risk_level)
        );
        assert_eq!(
            runtime_operation["safety_tier"],
            json!(manifest_operation.safety_tier)
        );
        assert_eq!(
            runtime_operation["idempotency"],
            json!(manifest_operation.idempotency)
        );
        assert_eq!(
            runtime_operation["requires_approval"],
            json!(manifest_operation.requires_approval)
        );
        assert_eq!(
            runtime_operation["input_schema"],
            manifest_operation.input_schema
        );
        assert_eq!(
            runtime_operation["output_schema"],
            manifest_operation.output_schema
        );
        assert_eq!(
            runtime_operation["ai_hints"],
            json!(manifest_operation.ai_hints)
        );
        assert_eq!(
            runtime_operation["revocation_freshness"],
            json!(manifest_operation.revocation_freshness)
        );
        assert_eq!(
            runtime_operation["network_constraints"],
            json!(manifest_operation.network_constraints)
        );
    }
}

#[test]
fn manifest_documents_current_runway_version_and_timeout_behavior() {
    let text = serde_json::to_value(manifest_toml())
        .expect("manifest to json")
        .to_string();
    assert!(text.contains("X-Runway-Version"));
    assert!(text.contains("Timeout does not cancel"));
    assert!(text.contains("runway.job.cancel"));
}
