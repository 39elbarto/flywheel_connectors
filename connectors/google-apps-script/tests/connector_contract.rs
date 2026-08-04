use std::collections::BTreeSet;

use fcp_google_apps_script::{
    client::{AppsScriptClient, source_inventory, validate_files},
    connector::AppsScriptConnector,
    types::{FileType, ScriptFile},
};
use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use fcp_manifest::ConnectorManifest;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn auth() -> GoogleMaterializedAuth {
    GoogleMaterializedAuth::BearerToken {
        access_token: test_token(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: vec![],
        quota_project_id: None,
    }
}

fn test_token() -> String {
    ["test", "token", "never", "log"].join("-")
}

fn complete_files() -> Vec<ScriptFile> {
    vec![
        ScriptFile {
            name: "appsscript".into(),
            file_type: FileType::Json,
            source: r#"{"timeZone":"Etc/UTC"}"#.into(),
        },
        ScriptFile {
            name: "Code".into(),
            file_type: FileType::ServerJs,
            source: "function harmless() { return true; }".into(),
        },
    ]
}

#[test]
fn manifest_validates_and_contains_only_typed_non_delete_operations() {
    let manifest = ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("Apps Script manifest should validate");
    let ids = manifest
        .provides
        .operations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 14);
    assert!(ids.iter().all(|id| !id.contains("delete")));
    assert!(!ids.contains("scripts.run"));
    assert!(!ids.iter().any(|id| id.contains("raw")));
}

#[fcp_async_core::runtime::test]
async fn runtime_introspection_matches_manifest_and_excludes_execution() {
    let connector = AppsScriptConnector::new();
    let introspection = connector.handle_introspect().await.expect("introspection");
    let operations = introspection["operations"].as_array().expect("operations");
    let manifest = ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("Apps Script manifest should validate");
    let ids = operations
        .iter()
        .map(|operation| operation["id"].as_str().expect("operation id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 14);
    assert!(!ids.contains("scripts.run"));
    assert!(
        ids.iter()
            .all(|id| !id.contains("delete") && !id.contains("raw"))
    );
    for operation in operations {
        let id = operation["id"].as_str().expect("operation id");
        let declared = manifest
            .provides
            .operations
            .get(id)
            .expect("introspection operation must be declared");
        assert_eq!(operation["input_schema"], declared.input_schema, "{id}");
        assert_eq!(operation["output_schema"], declared.output_schema, "{id}");
        assert_eq!(
            operation["capability"],
            declared.capability.as_str(),
            "{id}"
        );
        assert_eq!(
            operation["risk_level"],
            serde_json::to_value(declared.risk_level).unwrap(),
            "{id}"
        );
        assert_eq!(
            operation["safety_tier"],
            serde_json::to_value(declared.safety_tier).unwrap(),
            "{id}"
        );
        assert_eq!(
            operation["idempotency"],
            serde_json::to_value(declared.idempotency).unwrap(),
            "{id}"
        );
        assert_eq!(
            operation.get("requires_approval").and_then(|v| v.as_str()),
            (declared.requires_approval != fcp_manifest::ManifestApprovalMode::None)
                .then_some("policy"),
            "{id}"
        );
    }
}

#[test]
fn source_inventory_is_order_independent_and_never_contains_source() {
    let files = complete_files();
    let (inventory, digest) = source_inventory(&files).expect("inventory");
    let mut reversed = files;
    reversed.reverse();
    let (_, reversed_digest) = source_inventory(&reversed).expect("inventory");
    assert_eq!(digest, reversed_digest);
    let encoded = serde_json::to_string(&inventory).expect("serialize inventory");
    assert!(!encoded.contains("harmless"));
    assert!(!encoded.contains("timeZone"));
}

#[test]
fn source_validation_rejects_omitted_manifest_duplicate_names_and_oversize() {
    let no_manifest = vec![ScriptFile {
        name: "Code".into(),
        file_type: FileType::ServerJs,
        source: "x".into(),
    }];
    assert!(validate_files(&no_manifest).is_err());

    let mut duplicate = complete_files();
    duplicate.push(duplicate[1].clone());
    assert!(validate_files(&duplicate).is_err());

    let mut oversized = complete_files();
    oversized[1].source = "x".repeat(5 * 1024 * 1024 + 1);
    assert!(validate_files(&oversized).is_err());
}

#[fcp_async_core::runtime::test]
async fn client_get_project_uses_exact_path_and_bearer_auth() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/projects/script_123"))
        .and(header("authorization", "Bearer test-token-never-log"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scriptId": "script_123",
            "title": "Fixture"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = AppsScriptClient::new_with_auth(auth())
        .expect("client")
        .with_base_url(format!("{}/v1", server.uri()));
    let project = client.get_project("script_123").await.expect("project");
    assert_eq!(project.script_id, "script_123");
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_non_google_remote_host() {
    let mut connector = AppsScriptConnector::new();
    let error = connector
        .handle_configure(json!({
            "access_token": test_token(),
            "base_url": "https://evil.example/v1"
        }))
        .await
        .expect_err("remote host must be rejected");
    assert!(error.to_string().contains("script.googleapis.com"));
}

#[fcp_async_core::runtime::test]
async fn shutdown_clears_configured_runtime_state() {
    let mut connector = AppsScriptConnector::new();
    connector
        .handle_configure(json!({"access_token": test_token()}))
        .await
        .expect("configure");
    assert_eq!(
        connector.handle_health().await.expect("health")["status"],
        "healthy"
    );
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown");
    assert_eq!(
        connector.handle_health().await.expect("health")["status"],
        "not_configured"
    );
}
