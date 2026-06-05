#![allow(clippy::needless_pass_by_value)]

use std::time::Duration;

use fcp_fal::{FalConnector, redacted_media_summary};
use fcp_manifest::ConnectorManifest;
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
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 6] = [
    OP_SUBMIT, OP_STATUS, OP_RESULT, OP_CANCEL, OP_WAIT, OP_HEALTH,
];

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

#[fcp_async_core::runtime::test]
async fn fal_manifest_operations_match_runtime_introspection() {
    let manifest = fal_manifest_unchecked();
    manifest
        .validate()
        .expect("Fal manifest should validate with its checked interface hash");

    let connector = FalConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let runtime_operations = introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection operations should be an array");
    let runtime_ids: Vec<_> = runtime_operations
        .iter()
        .map(|operation| {
            operation
                .get("id")
                .and_then(Value::as_str)
                .expect("operation id should be a string")
        })
        .collect();
    assert_eq!(runtime_ids, EXPECTED_OPERATION_IDS);
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_IDS.len()
    );

    for operation_id in EXPECTED_OPERATION_IDS {
        let manifest_operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("manifest operation should be declared");
        let runtime_operation = operation(&introspection, operation_id);

        assert_eq!(
            runtime_operation.get("summary").and_then(Value::as_str),
            Some(manifest_operation.description.as_str())
        );
        assert_eq!(
            runtime_operation.get("description").and_then(Value::as_str),
            Some(manifest_operation.description.as_str())
        );
        assert_eq!(
            runtime_operation.get("capability").and_then(Value::as_str),
            Some(manifest_operation.capability.as_str())
        );
        assert_eq!(
            runtime_operation
                .get("risk_level")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.risk_level))
        );
        assert_eq!(
            runtime_operation
                .get("safety_tier")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.safety_tier))
        );
        assert_eq!(
            runtime_operation
                .get("idempotency")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.idempotency))
        );
        assert_eq!(
            runtime_operation
                .get("requires_approval")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.requires_approval))
        );
        assert_eq!(
            runtime_operation.get("input_schema"),
            Some(&manifest_operation.input_schema)
        );
        assert_eq!(
            runtime_operation.get("output_schema"),
            Some(&manifest_operation.output_schema)
        );

        let expected_network_constraints = serde_json::to_value(
            manifest_operation
                .network_constraints
                .as_ref()
                .expect("Fal operation should declare network constraints"),
        )
        .expect("network constraints should serialize");
        assert_eq!(
            runtime_operation.get("network_constraints"),
            Some(&expected_network_constraints)
        );

        assert!(
            !manifest_operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} should declare AI guidance"
        );
        let expected_ai_hints =
            serde_json::to_value(&manifest_operation.ai_hints).expect("AI hints should serialize");
        assert_eq!(runtime_operation.get("ai_hints"), Some(&expected_ai_hints));
    }
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

fn fal_manifest_unchecked() -> ConnectorManifest {
    ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("Fal manifest should parse before hash validation")
}

fn json_string<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("value should serialize")
        .as_str()
        .expect("serialized value should be a string")
        .to_string()
}

fn operation<'a>(introspection: &'a Value, id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("operations should be advertised")
        .iter()
        .find(|operation| operation.get("id").and_then(Value::as_str) == Some(id))
        .expect("expected operation should be advertised")
}
