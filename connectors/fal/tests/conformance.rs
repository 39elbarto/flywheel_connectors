use fcp_fal::{CONNECTOR_ID, FalConnector};
use serde_json::json;

#[fcp_async_core::runtime::test]
async fn connector_lifecycle_conformance_smoke() {
    let mut connector = FalConnector::new();
    let configured = connector
        .handle_configure(json!({
            "api_key": "fal_test_key",
            "queue_base_url": "http://localhost:18080"
        }))
        .await
        .expect("configure should succeed");
    assert_eq!(configured["connector_id"], CONNECTOR_ID);
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    let health = connector.handle_health().await.expect("health should work");
    assert_eq!(health["status"], "healthy");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    let after_shutdown = connector.handle_health().await.expect("health should work");
    assert_eq!(after_shutdown["configured"], false);
}
