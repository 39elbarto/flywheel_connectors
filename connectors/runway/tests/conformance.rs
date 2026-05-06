use fcp_runway::RunwayConnector;
use serde_json::Value;

fn manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse")
}

#[test]
fn manifest_declares_required_operations_network_policy_and_redaction() {
    let manifest = manifest();
    let operations = manifest["provides"]["operations"]
        .as_table()
        .expect("operations table");
    for operation in [
        "runway.video.image_to_video",
        "runway.video.text_to_video",
        "runway.video.video_to_video",
        "runway.image.text_to_image",
        "runway.job.status",
        "runway.job.cancel",
        "runway.job.wait_until_complete",
        "runway.health",
    ] {
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
    let operations = manifest["provides"]["operations"]
        .as_table()
        .expect("operations table");
    let introspection: Value =
        fcp_async_core::runtime::block_on_sync(RunwayConnector::new().handle_introspect())
            .expect("runtime should run")
            .expect("introspection should work");
    let ids = introspection["operations"]
        .as_array()
        .expect("operations array")
        .iter()
        .map(|operation| operation["id"].as_str().expect("operation id").to_string())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), operations.len());
    for id in operations.keys() {
        assert!(ids.contains(id), "introspection missing {id}");
    }
    assert!(introspection.to_string().contains("signed URLs"));
}

#[test]
fn manifest_documents_current_runway_version_and_timeout_behavior() {
    let text = serde_json::to_value(manifest())
        .expect("manifest to json")
        .to_string();
    assert!(text.contains("X-Runway-Version"));
    assert!(text.contains("Timeout does not cancel"));
    assert!(text.contains("runway.job.cancel"));
}
