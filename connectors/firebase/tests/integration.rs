//! Integration smoke tests for the Firebase connector surface.

use serde_json::json;

use fcp_firebase::connector::FirebaseConnector;

#[fcp_async_core::runtime::test]
async fn configure_then_introspect_returns_operations() {
    let mut connector = FirebaseConnector::new();
    connector
        .handle_configure(json!({
            "project_id": "demo-project",
            "access_token": "ya29.test-token"
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({ "session_id": "sess_1" }))
        .await
        .unwrap();

    let intro = connector.handle_introspect().await.unwrap();
    assert_eq!(intro["connector_id"], "fcp.firebase");
    assert!(intro["operations"].as_array().unwrap().len() >= 10);
}
