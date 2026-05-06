#![allow(clippy::needless_pass_by_value)]

use std::time::Duration;

use fcp_prelude::FcpError;
use fcp_runway::{RunwayConnector, redacted_task_output_summary};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

const OP_IMAGE_TO_VIDEO: &str = "runway.video.image_to_video";
const OP_TEXT_TO_VIDEO: &str = "runway.video.text_to_video";
const OP_VIDEO_TO_VIDEO: &str = "runway.video.video_to_video";
const OP_TEXT_TO_IMAGE: &str = "runway.image.text_to_image";
const OP_STATUS: &str = "runway.job.status";
const OP_CANCEL: &str = "runway.job.cancel";
const OP_WAIT: &str = "runway.job.wait_until_complete";
const OP_HEALTH: &str = "runway.health";

#[fcp_async_core::runtime::test]
async fn submit_operations_send_required_headers_and_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/image_to_video"))
        .and(header("authorization", "Bearer runway_test_key"))
        .and(header("x-runway-version", "2024-11-06"))
        .and(body_json(json!({
            "model": "gen4_turbo",
            "promptText": "redacted motion",
            "promptImage": "https://example.com/start.jpg",
            "duration": 5
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "task-image"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/text_to_video"))
        .and(header("x-runway-version", "2024-11-06"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "task-text"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/video_to_video"))
        .and(header("x-runway-version", "2024-11-06"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "task-video"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/text_to_image"))
        .and(header("x-runway-version", "2024-11-06"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "task-image-gen"})))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let image_to_video = connector
        .handle_invoke(invoke(
            OP_IMAGE_TO_VIDEO,
            json!({
                "model": "gen4_turbo",
                "promptText": "redacted motion",
                "promptImage": "https://example.com/start.jpg",
                "duration": 5
            }),
        ))
        .await
        .expect("image-to-video submit should succeed");
    assert_eq!(image_to_video["task_id"], "task-image");
    assert_eq!(image_to_video["binary_proxying"], false);

    let text_to_video = connector
        .handle_invoke(invoke(
            OP_TEXT_TO_VIDEO,
            json!({"model": "gen4.5", "promptText": "redacted scene"}),
        ))
        .await
        .expect("text-to-video submit should succeed");
    assert_eq!(text_to_video["task_id"], "task-text");

    let video_to_video = connector
        .handle_invoke(invoke(
            OP_VIDEO_TO_VIDEO,
            json!({"model": "gen4_aleph", "videoUri": "https://example.com/input.mp4"}),
        ))
        .await
        .expect("video-to-video submit should succeed");
    assert_eq!(video_to_video["task_id"], "task-video");

    let text_to_image = connector
        .handle_invoke(invoke(
            OP_TEXT_TO_IMAGE,
            json!({"model": "gen4_image", "promptText": "redacted image"}),
        ))
        .await
        .expect("text-to-image submit should succeed");
    assert_eq!(text_to_image["task_id"], "task-image-gen");
}

#[fcp_async_core::runtime::test]
async fn status_wait_cancel_and_health_cover_task_lifecycle() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/tasks/task-done"))
        .respond_with(ResponseTemplate::new(200).set_body_json(done_task()))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/tasks/task-done"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tier": {"models": {}},
            "creditBalance": 42
        })))
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;
    let status = connector
        .handle_invoke(invoke(OP_STATUS, json!({"task_id": "task-done"})))
        .await
        .expect("status should succeed");
    assert_eq!(status["status"], "SUCCEEDED");
    assert_eq!(status["output_summary"]["output_count"], 2);
    assert_eq!(status["output_summary"]["byte_count"], 4096);
    assert!(
        !status["output_summary"]["url_hashes"][0]
            .as_str()
            .expect("hash should be string")
            .contains("https://")
    );

    let wait = connector
        .handle_invoke(invoke(
            OP_WAIT,
            json!({"task_id": "task-done", "timeout_ms": 1000, "poll_interval_ms": 1}),
        ))
        .await
        .expect("wait should succeed");
    assert_eq!(wait["status"], "SUCCEEDED");
    assert_eq!(wait["transitions"], json!(["SUCCEEDED"]));

    let cancel = connector
        .handle_invoke(invoke(OP_CANCEL, json!({"task_id": "task-done"})))
        .await
        .expect("cancel should succeed");
    assert_eq!(cancel["cancel_status"], "accepted");

    let health = connector
        .handle_invoke(invoke(OP_HEALTH, json!({})))
        .await
        .expect("health should succeed");
    assert_eq!(health["credit_balance_present"], true);
}

#[fcp_async_core::runtime::test]
async fn provider_errors_rate_limits_timeout_and_cancel_404_are_mapped() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/tasks/rate"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "3")
                .set_body_string("rate limited"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/tasks/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/tasks/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({"id": "slow", "status": "PENDING"})),
        )
        .mount(&server)
        .await;

    let connector = configured_connector_with(&server, 1_000, 0).await;
    let limited = connector
        .handle_invoke(invoke(OP_STATUS, json!({"task_id": "rate"})))
        .await
        .expect_err("rate limit should fail");
    assert!(
        matches!(
            limited,
            FcpError::RateLimited {
                retry_after_ms: 3_000,
                ..
            }
        ),
        "expected rate limit, got {limited:?}",
    );

    let ignored = connector
        .handle_invoke(invoke(OP_CANCEL, json!({"task_id": "missing"})))
        .await
        .expect("cancel 404 is idempotently safe");
    assert_eq!(ignored["cancel_status"], "not_found_ignored");

    let timeout_connector = configured_connector_with(&server, 10, 0).await;
    let timeout = timeout_connector
        .handle_invoke(invoke(OP_STATUS, json!({"task_id": "slow"})))
        .await
        .expect_err("timeout should fail");
    assert!(matches!(timeout, FcpError::UpstreamTimeout { .. }));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_validation_and_redaction_are_safe() {
    let server = MockServer::start().await;
    let mut connector = RunwayConnector::new();
    let configured = connector
        .handle_configure(json!({
            "api_key": "runway_secret_key",
            "base_url": format!("{}/v1", server.uri()),
            "api_version": "2024-11-06"
        }))
        .await
        .expect("configure should succeed");
    assert_eq!(configured["auth_mode"], "bearer:redacted");
    assert!(!configured.to_string().contains("runway_secret_key"));
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should succeed");
    let health = connector.handle_health().await.expect("health should work");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor should work");
    assert!(!doctor.to_string().contains("runway_secret_key"));
    assert!(doctor.to_string().contains("2024-11-06"));
    let introspect = connector
        .handle_introspect()
        .await
        .expect("introspect should work");
    assert!(
        introspect["operations"]
            .as_array()
            .expect("operations should be an array")
            .iter()
            .any(|operation| operation["id"] == OP_TEXT_TO_VIDEO)
    );
    assert!(!introspect.to_string().contains("redacted motion"));

    let bad_version = RunwayConnector::new()
        .handle_configure(json!({
            "api_key": "runway_secret_key",
            "api_version": "2024-01-01"
        }))
        .await
        .expect_err("wrong API version should fail");
    assert!(bad_version.to_string().contains("2024-11-06"));

    let bad_submit = connector
        .handle_invoke(invoke(
            OP_IMAGE_TO_VIDEO,
            json!({"model": "gen4_turbo", "promptText": "missing image"}),
        ))
        .await
        .expect_err("missing promptImage should fail locally");
    assert!(bad_submit.to_string().contains("promptImage"));

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    let health = connector
        .handle_health()
        .await
        .expect("health still responds");
    assert_eq!(health["status"], "unconfigured");
}

#[test]
fn redacted_summary_never_exposes_signed_urls() {
    let summary = redacted_task_output_summary(&done_task());
    assert_eq!(summary.output_count, 2);
    assert_eq!(summary.byte_count, 4096);
    assert_eq!(summary.url_hosts, vec!["cdn.runway.example"]);
    assert!(
        summary
            .url_hashes
            .iter()
            .all(|hash| hash.starts_with("blake3:"))
    );
    assert!(!format!("{summary:?}").contains("signature=secret"));
}

async fn configured_connector(server: &MockServer) -> RunwayConnector {
    configured_connector_with(server, 30_000, 2).await
}

async fn configured_connector_with(
    server: &MockServer,
    request_timeout_ms: u64,
    max_retries: u32,
) -> RunwayConnector {
    let mut connector = RunwayConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "runway_test_key",
            "base_url": format!("{}/v1", server.uri()),
            "request_timeout_ms": request_timeout_ms,
            "max_retries": max_retries,
            "default_poll_interval_ms": 1
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
    json!({
        "operation": operation,
        "input": input
    })
}

fn done_task() -> Value {
    json!({
        "id": "task-done",
        "status": "SUCCEEDED",
        "createdAt": "2026-05-06T00:00:00Z",
        "updatedAt": "2026-05-06T00:01:00Z",
        "creditsUsed": 12,
        "output": [
            "https://cdn.runway.example/video.mp4?signature=secret",
            {"url": "https://cdn.runway.example/poster.png?signature=secret", "contentType": "image/png", "sizeBytes": 4096}
        ]
    })
}
