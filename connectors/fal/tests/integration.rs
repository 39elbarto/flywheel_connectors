#![allow(clippy::needless_pass_by_value)]

use std::time::Duration;

use fcp_fal::{FalConnector, redacted_media_summary};
use fcp_prelude::FcpError;
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

const OP_SUBMIT: &str = "fal.media.submit";
const OP_STATUS: &str = "fal.job.status";
const OP_RESULT: &str = "fal.job.result";
const OP_CANCEL: &str = "fal.job.cancel";
const OP_WAIT: &str = "fal.job.wait_until_complete";
const OP_HEALTH: &str = "fal.health";

#[fcp_async_core::runtime::test]
async fn submit_sends_key_auth_and_returns_provider_urls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/fal-ai/flux/schnell"))
        .and(header("authorization", "Key fal_test_key"))
        .and(body_json(
            json!({"prompt": "secret prompt", "image_size": "square"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(handle_payload(&server, "req_1")))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let response = connector
        .handle_invoke(invoke(
            OP_SUBMIT,
            json!({
                "model_route": "fal-ai/flux/schnell",
                "params": {"prompt": "secret prompt", "image_size": "square"}
            }),
        ))
        .await
        .expect("submit should succeed");

    assert_eq!(response["provider"], "fal");
    assert_eq!(response["model_route"], "fal-ai/flux/schnell");
    assert_eq!(response["request_id"], "req_1");
    assert_eq!(
        response["status_url"],
        format!("{}/fal-ai/flux/schnell/requests/req_1/status", server.uri())
    );
}

#[fcp_async_core::runtime::test]
async fn status_result_cancel_and_wait_cover_queue_cycle() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/req_2/status"))
        .and(query_param("logs", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "COMPLETED",
            "request_id": "req_2",
            "response_url": format!("{}/fal-ai/flux/schnell/requests/req_2/response", server.uri()),
            "logs": [{"message": "done"}],
            "metrics": {"inference_time": 0.1}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/req_2/response"))
        .respond_with(ResponseTemplate::new(200).set_body_json(result_payload()))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/fal-ai/flux/schnell/requests/req_2/cancel"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "status": "CANCELLATION_REQUESTED"
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let status = connector
        .handle_invoke(invoke(
            OP_STATUS,
            json!({
                "model_route": "fal-ai/flux/schnell",
                "request_id": "req_2",
                "logs": true
            }),
        ))
        .await
        .expect("status should succeed");
    assert_eq!(status["status"], "COMPLETED");
    assert_eq!(status["logs_present"], true);

    let result = connector
        .handle_invoke(invoke(
            OP_RESULT,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "req_2"}),
        ))
        .await
        .expect("result should succeed");
    assert_eq!(result["output_summary"]["output_count"], 2);
    assert_eq!(result["output_summary"]["byte_count"], 4200);
    assert!(
        !result["output_summary"]["url_hashes"][0]
            .as_str()
            .expect("hash should be string")
            .contains("https://")
    );

    let wait = connector
        .handle_invoke(invoke(
            OP_WAIT,
            json!({
                "model_route": "fal-ai/flux/schnell",
                "request_id": "req_2",
                "timeout_ms": 1000,
                "poll_interval_ms": 1,
                "logs": true
            }),
        ))
        .await
        .expect("wait should succeed");
    assert_eq!(wait["status"], "COMPLETED");
    assert_eq!(wait["result"]["output_summary"]["output_count"], 2);

    let cancel = connector
        .handle_invoke(invoke(
            OP_CANCEL,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "req_2"}),
        ))
        .await
        .expect("cancel should succeed");
    assert_eq!(cancel["cancel_status"], "CANCELLATION_REQUESTED");
}

#[fcp_async_core::runtime::test]
async fn provider_errors_rate_limits_and_timeouts_map_to_fcp_errors() {
    let limited = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/rate/status"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "4")
                .set_body_string("rate limited"),
        )
        .expect(1)
        .mount(&limited)
        .await;
    let connector = configured_connector_with(&limited, 1_000, 0).await;
    let err = connector
        .handle_invoke(invoke(
            OP_STATUS,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "rate"}),
        ))
        .await
        .expect_err("rate limit should fail");
    assert!(
        matches!(
            err,
            FcpError::RateLimited {
                retry_after_ms: 4_000,
                ..
            }
        ),
        "expected rate limit error, got {err:?}",
    );

    let slow = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/slow/status"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({"status": "IN_QUEUE"})),
        )
        .mount(&slow)
        .await;
    let timeout_connector = configured_connector_with(&slow, 10, 0).await;
    let timeout = timeout_connector
        .handle_invoke(invoke(
            OP_STATUS,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "slow"}),
        ))
        .await
        .expect_err("timeout should fail");
    assert!(matches!(timeout, FcpError::UpstreamTimeout { .. }));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_and_validation_are_redaction_safe() {
    let server = MockServer::start().await;
    let mut connector = FalConnector::new();
    let configured = connector
        .handle_configure(json!({
            "api_key": "fal_test_secret",
            "queue_base_url": server.uri()
        }))
        .await
        .expect("configure should succeed");
    assert_eq!(configured["auth_mode"], "key:redacted");
    assert!(!configured.to_string().contains("fal_test_secret"));
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    let health = connector.handle_health().await.expect("health should work");
    assert_eq!(health["status"], "healthy");
    let introspect = connector
        .handle_introspect()
        .await
        .expect("introspect should work");
    assert!(
        introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .any(|operation| operation["id"] == OP_CANCEL)
    );
    let simulate = connector
        .handle_simulate(json!({"operation_id": OP_HEALTH}))
        .await
        .expect("simulate should work");
    assert_eq!(simulate["allowed"], true);

    let invalid_route = connector
        .handle_invoke(invoke(
            OP_SUBMIT,
            json!({"model_route": "../bad", "params": {}}),
        ))
        .await
        .expect_err("route traversal should fail");
    assert!(invalid_route.to_string().contains("model_route"));

    let summary = redacted_media_summary(&result_payload());
    assert_eq!(summary.output_count, 2);
}

fn handle_payload(server: &MockServer, request_id: &str) -> Value {
    json!({
        "request_id": request_id,
        "status_url": format!("{}/fal-ai/flux/schnell/requests/{request_id}/status", server.uri()),
        "response_url": format!("{}/fal-ai/flux/schnell/requests/{request_id}/response", server.uri()),
        "cancel_url": format!("{}/fal-ai/flux/schnell/requests/{request_id}/cancel", server.uri()),
        "queue_position": 0
    })
}

fn result_payload() -> Value {
    json!({
        "images": [{
            "url": "https://v3.fal.media/files/rabbit/image.png?sig=secret",
            "width": 1024,
            "height": 1024,
            "content_type": "image/png",
            "file_size": 4096
        }],
        "video": {
            "url": "https://fal.media/video/movie.mp4?sig=secret",
            "content_type": "video/mp4",
            "file_size_bytes": 104
        },
        "seed": 123
    })
}

async fn configured_connector(server: &MockServer) -> FalConnector {
    configured_connector_with(server, 30_000, 2).await
}

async fn configured_connector_with(
    server: &MockServer,
    request_timeout_ms: u64,
    max_retries: u32,
) -> FalConnector {
    let mut connector = FalConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "fal_test_key",
            "queue_base_url": server.uri(),
            "request_timeout_ms": request_timeout_ms,
            "max_retries": max_retries,
            "retry_backoff_ms": 1
        }))
        .await
        .expect("configure should succeed");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    connector
}

fn invoke(operation: &str, input: Value) -> Value {
    json!({"operation_id": operation, "input": input})
}
