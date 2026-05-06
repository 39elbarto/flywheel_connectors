#![allow(clippy::needless_pass_by_value)]

use fcp_prelude::FcpError;
use fcp_runway::{RunwayConnector, redacted_task_output_summary};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

const OP_IMAGE_TO_VIDEO: &str = "runway.video.image_to_video";
const OP_STATUS: &str = "runway.job.status";
const OP_CANCEL: &str = "runway.job.cancel";
const OP_WAIT: &str = "runway.job.wait_until_complete";

#[fcp_async_core::runtime::test]
async fn runway_wiremock_and_live_skip_jsonl_matrix() {
    let git_revision =
        std::env::var("RUNWAY_E2E_GIT_REVISION").unwrap_or_else(|_| "test-worktree".into());
    let command_line = "cargo test -p fcp-runway --test e2e_jsonl runway_wiremock_and_live_skip_jsonl_matrix -- --nocapture";
    let server = MockServer::start().await;
    mount_runway_cycle(&server).await;
    let connector = configured_connector(&server).await;

    let submit = connector
        .handle_invoke(invoke(
            OP_IMAGE_TO_VIDEO,
            json!({
                "model": "gen4_turbo",
                "promptText": "redacted prompt",
                "promptImage": "https://example.com/input.jpg",
                "duration": 5
            }),
        ))
        .await
        .expect("submit fixture should succeed");
    print_record(json!({
        "event": "runway_task_fixture",
        "fixture_id": "submit",
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "operation": OP_IMAGE_TO_VIDEO,
        "model_id": "gen4_turbo",
        "job_id_hash": hash_value(submit["task_id"].as_str().unwrap_or_default()),
        "status_transitions": ["PENDING"],
        "credits_used": null,
        "content_type": null,
        "output_count": 0,
        "byte_count": 0,
        "http_status": 200,
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let status = connector
        .handle_invoke(invoke(OP_STATUS, json!({"task_id": "task-jsonl"})))
        .await
        .expect("status fixture should succeed");
    print_record(task_record(
        "status-succeeded",
        OP_STATUS,
        &status,
        &git_revision,
        command_line,
    ));

    let wait = connector
        .handle_invoke(invoke(
            OP_WAIT,
            json!({"task_id": "task-jsonl", "timeout_ms": 1000, "poll_interval_ms": 1}),
        ))
        .await
        .expect("wait fixture should succeed");
    print_record(task_record(
        "wait-succeeded",
        OP_WAIT,
        &wait,
        &git_revision,
        command_line,
    ));

    let cancel = connector
        .handle_invoke(invoke(OP_CANCEL, json!({"task_id": "task-jsonl"})))
        .await
        .expect("cancel fixture should succeed");
    print_record(json!({
        "event": "runway_task_fixture",
        "fixture_id": "cancel",
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "operation": OP_CANCEL,
        "model_id": null,
        "job_id_hash": hash_value("task-jsonl"),
        "status_transitions": [cancel["cancel_status"]],
        "credits_used": null,
        "content_type": null,
        "output_count": 0,
        "byte_count": 0,
        "http_status": cancel["http_status"],
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "completed",
        "skip_reason": null,
        "status": "passed"
    }));

    let failed = connector
        .handle_invoke(invoke(
            OP_WAIT,
            json!({"task_id": "task-failed", "timeout_ms": 1000}),
        ))
        .await
        .expect_err("failed task should map to FCP error");
    print_record(error_record(
        "failed-task",
        OP_WAIT,
        &failed,
        200,
        &git_revision,
        command_line,
    ));

    let live_skip = if std::env::var("RUNWAY_API_KEY").is_ok() {
        "skipped_live_key_present_but_live_generation_disabled_in_default_ci"
    } else {
        "RUNWAY_API_KEY not set"
    };
    print_record(json!({
        "event": "runway_task_fixture",
        "fixture_id": "live-smoke",
        "mode": "live",
        "command_line": command_line,
        "git_revision": git_revision,
        "operation": OP_IMAGE_TO_VIDEO,
        "model_id": "gen4_turbo",
        "job_id_hash": null,
        "status_transitions": [],
        "credits_used": null,
        "content_type": null,
        "output_count": 0,
        "byte_count": 0,
        "http_status": null,
        "retry_decision": "not_started",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": null,
        "cleanup_result": "not_started",
        "skip_reason": live_skip,
        "status": "skipped"
    }));
}

async fn mount_runway_cycle(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/image_to_video"))
        .and(body_string_contains("gen4_turbo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "task-jsonl"})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/tasks/task-jsonl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(done_task()))
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/tasks/task-jsonl"))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/tasks/task-failed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "task-failed",
            "status": "FAILED",
            "failure": "provider rejected request"
        })))
        .mount(server)
        .await;
}

async fn configured_connector(server: &MockServer) -> RunwayConnector {
    let mut connector = RunwayConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "runway_fixture_key",
            "base_url": format!("{}/v1", server.uri()),
            "default_poll_interval_ms": 1,
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
    json!({
        "operation": operation,
        "input": input
    })
}

fn done_task() -> Value {
    json!({
        "id": "task-jsonl",
        "status": "SUCCEEDED",
        "creditsUsed": 12,
        "output": [
            "https://cdn.runway.example/video.mp4?signature=secret",
            {"url": "https://cdn.runway.example/poster.png?signature=secret", "contentType": "image/png", "sizeBytes": 4096}
        ]
    })
}

fn task_record(
    fixture_id: &str,
    operation: &str,
    value: &Value,
    git_revision: &str,
    command_line: &str,
) -> Value {
    let summary = redacted_task_output_summary(&value["payload"]);
    json!({
        "event": "runway_task_fixture",
        "fixture_id": fixture_id,
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "operation": operation,
        "model_id": null,
        "job_id_hash": value["task_id"].as_str().map(hash_value),
        "status_transitions": value.get("transitions").cloned().unwrap_or_else(|| json!([value["status"].clone()])),
        "credits_used": value["credits_used"],
        "content_type": summary.content_types.first().cloned(),
        "output_count": summary.output_count,
        "byte_count": summary.byte_count,
        "http_status": 200,
        "retry_decision": "none",
        "fcp_error_mapping": null,
        "artifact_url_host_hash": summary.url_hosts.first().map(|host| hash_value(host)),
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    })
}

fn error_record(
    fixture_id: &str,
    operation: &str,
    error: &FcpError,
    http_status: u16,
    git_revision: &str,
    command_line: &str,
) -> Value {
    json!({
        "event": "runway_task_fixture",
        "fixture_id": fixture_id,
        "mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "operation": operation,
        "model_id": null,
        "job_id_hash": hash_value("task-failed"),
        "status_transitions": ["FAILED"],
        "credits_used": null,
        "content_type": null,
        "output_count": 0,
        "byte_count": 0,
        "http_status": http_status,
        "retry_decision": "terminal",
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

fn print_record(value: Value) {
    println!("RUNWAY_E2E_JSONL {value}");
}

fn hash_value(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}
