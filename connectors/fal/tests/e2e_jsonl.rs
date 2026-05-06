#![allow(clippy::needless_pass_by_value)]

use fcp_fal::{FalConnector, redacted_media_summary};
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

const OP_SUBMIT: &str = "fal.media.submit";
const OP_STATUS: &str = "fal.job.status";
const OP_RESULT: &str = "fal.job.result";
const OP_CANCEL: &str = "fal.job.cancel";

#[fcp_async_core::runtime::test]
async fn fal_wiremock_and_live_skip_jsonl_matrix() {
    let git_revision =
        std::env::var("FAL_E2E_GIT_REVISION").unwrap_or_else(|_| "test-worktree".into());
    let command_line = "cargo test -p fcp-fal --test e2e_jsonl fal_wiremock_and_live_skip_jsonl_matrix -- --nocapture";
    let server = MockServer::start().await;
    mount_queue_cycle(&server).await;
    let connector = configured_connector(&server).await;

    let submit = connector
        .handle_invoke(invoke(
            OP_SUBMIT,
            json!({
                "model_route": "fal-ai/flux/schnell",
                "params": {"prompt": "redacted prompt", "image_size": "square"}
            }),
        ))
        .await
        .expect("submit fixture should succeed");
    print_record(json!({
        "event": "fal_queue_fixture",
        "fixture_id": "submit",
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "model_route": "fal-ai/flux/schnell",
        "request_id_hash": hash_value(submit["request_id"].as_str().unwrap_or_default()),
        "operation": OP_SUBMIT,
        "status_transitions": ["IN_QUEUE"],
        "content_type": null,
        "output_count": 0,
        "request_bytes": 58,
        "response_bytes": submit.to_string().len(),
        "http_status": 200,
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let status = connector
        .handle_invoke(invoke(
            OP_STATUS,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "req_jsonl"}),
        ))
        .await
        .expect("status fixture should succeed");
    print_record(json!({
        "event": "fal_queue_fixture",
        "fixture_id": "status-complete",
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "model_route": "fal-ai/flux/schnell",
        "request_id_hash": hash_value("req_jsonl"),
        "operation": OP_STATUS,
        "status_transitions": [status["status"]],
        "content_type": null,
        "output_count": 0,
        "request_bytes": 40,
        "response_bytes": status.to_string().len(),
        "http_status": 200,
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let result = connector
        .handle_invoke(invoke(
            OP_RESULT,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "req_jsonl"}),
        ))
        .await
        .expect("result fixture should succeed");
    let summary = redacted_media_summary(&result["payload"]);
    print_record(json!({
        "event": "fal_queue_fixture",
        "fixture_id": "result-redacted",
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "model_route": "fal-ai/flux/schnell",
        "request_id_hash": hash_value("req_jsonl"),
        "operation": OP_RESULT,
        "status_transitions": ["COMPLETED"],
        "content_type": summary.content_types.first().cloned(),
        "output_count": summary.output_count,
        "request_bytes": 40,
        "response_bytes": result.to_string().len(),
        "http_status": 200,
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": summary.url_hosts.first().map(|host| hash_value(host)),
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let cancel = connector
        .handle_invoke(invoke(
            OP_CANCEL,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "req_jsonl"}),
        ))
        .await
        .expect("cancel fixture should succeed");
    print_record(json!({
        "event": "fal_queue_fixture",
        "fixture_id": "cancel",
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "model_route": "fal-ai/flux/schnell",
        "request_id_hash": hash_value("req_jsonl"),
        "operation": OP_CANCEL,
        "status_transitions": [cancel["cancel_status"]],
        "content_type": null,
        "output_count": 0,
        "request_bytes": 40,
        "response_bytes": cancel.to_string().len(),
        "http_status": 202,
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "completed",
        "skip_reason": null,
        "status": "passed"
    }));

    let provider_error = connector
        .handle_invoke(invoke(
            OP_STATUS,
            json!({"model_route": "fal-ai/flux/schnell", "request_id": "missing"}),
        ))
        .await
        .expect_err("missing request should map to FCP error");
    print_record(error_record(
        "missing-request",
        OP_STATUS,
        &provider_error,
        404,
        "terminal",
        &git_revision,
        command_line,
    ));

    let live_status = if std::env::var("FAL_KEY").is_ok() {
        "skipped_live_key_present_but_live_generation_disabled_in_default_ci"
    } else {
        "FAL_KEY not set"
    };
    print_record(json!({
        "event": "fal_queue_fixture",
        "fixture_id": "live-smoke",
        "mode": "live",
        "command_line": command_line,
        "git_revision": git_revision,
        "model_route": "fal-ai/flux/schnell",
        "request_id_hash": null,
        "operation": OP_SUBMIT,
        "status_transitions": [],
        "content_type": null,
        "output_count": 0,
        "request_bytes": 0,
        "response_bytes": 0,
        "http_status": null,
        "retry_decision": "not_applicable",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "not_started",
        "skip_reason": live_status,
        "status": "skipped"
    }));
}

async fn mount_queue_cycle(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/fal-ai/flux/schnell"))
        .and(body_string_contains("redacted prompt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "request_id": "req_jsonl",
            "status_url": format!("{}/fal-ai/flux/schnell/requests/req_jsonl/status", server.uri()),
            "response_url": format!("{}/fal-ai/flux/schnell/requests/req_jsonl/response", server.uri()),
            "cancel_url": format!("{}/fal-ai/flux/schnell/requests/req_jsonl/cancel", server.uri()),
            "queue_position": 0
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/req_jsonl/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "COMPLETED",
            "request_id": "req_jsonl",
            "response_url": format!("{}/fal-ai/flux/schnell/requests/req_jsonl/response", server.uri())
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/req_jsonl/response"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": [{
                "url": "https://v3.fal.media/files/rabbit/jsonl.png?sig=secret",
                "content_type": "image/png",
                "file_size": 2048
            }]
        })))
        .mount(server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/fal-ai/flux/schnell/requests/req_jsonl/cancel"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "status": "CANCELLATION_REQUESTED"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fal-ai/flux/schnell/requests/missing/status"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(server)
        .await;
}

async fn configured_connector(server: &MockServer) -> FalConnector {
    let mut connector = FalConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "fal_test_key",
            "queue_base_url": server.uri(),
            "max_retries": 0
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

fn print_record(record: Value) {
    println!("FAL_E2E_JSONL {}", serde_json::to_string(&record).unwrap());
}

fn error_record(
    fixture_id: &str,
    operation: &str,
    error: &FcpError,
    http_status: u16,
    retry_decision: &str,
    git_revision: &str,
    command_line: &str,
) -> Value {
    json!({
        "event": "fal_queue_fixture",
        "fixture_id": fixture_id,
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "model_route": "fal-ai/flux/schnell",
        "request_id_hash": hash_value("missing"),
        "operation": operation,
        "status_transitions": [],
        "content_type": null,
        "output_count": 0,
        "request_bytes": 40,
        "response_bytes": 9,
        "http_status": http_status,
        "retry_decision": retry_decision,
        "fcp_error_mapping": fcp_error_kind(error),
        "artifact_url_host_hash": null,
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    })
}

const fn fcp_error_kind(error: &FcpError) -> &'static str {
    match error {
        FcpError::RateLimited { .. } => "RateLimited",
        FcpError::ResourceNotFound { .. } => "ResourceNotFound",
        FcpError::Unauthorized { .. } => "Unauthorized",
        FcpError::UpstreamTimeout { .. } => "UpstreamTimeout",
        FcpError::External { .. } => "External",
        _ => "Other",
    }
}

fn hash_value(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}
