#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    process::Command,
    time::{Duration, Instant},
};

use fcp_prelude::FcpError;
use fcp_zalo::ZaloConnector;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};

const BEAD_ID: &str = "flywheel_connectors-4kw5f.11.15";
const CONNECTOR_ID: &str = "fcp.zalo";
const FIXTURE_TOKEN: &str = "fixture-zalo-access-token";
const FIXTURE_WEBHOOK_SECRET: &str = "fixture-zalo-webhook-secret";
const SEND_MESSAGE_OP: &str = "zalo.messages.send";
const POLL_UPDATES_OP: &str = "zalo.updates.poll";
const GET_ME_OP: &str = "zalo.self.get_me";
const DELETE_WEBHOOK_OP: &str = "zalo.webhook.delete";
const WEBHOOK_INFO_OP: &str = "zalo.webhook.info";
const WEBHOOK_VERIFY_OP: &str = "zalo.webhook.verify";
const WEBHOOK_INGEST_OP: &str = "zalo.webhook.ingest";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ZaloEvidenceLog {
    schema_version: String,
    bead_id: String,
    command_line: String,
    git_revision: String,
    connector_id: String,
    operation_id: String,
    capability: String,
    zone: String,
    instance_id: String,
    fixture_id: String,
    recipient_id_hash: Option<String>,
    webhook_event_id_hash: Option<String>,
    lifecycle_phase: String,
    latency_ms: u64,
    result: String,
    error_code: Option<String>,
    audit_receipt_id: String,
    cleanup_result: String,
    skip_reason: Option<String>,
    redaction: String,
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-git-revision".to_string())
}

fn stable_hash(input: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv64:{hash:016x}")
}

fn elapsed_millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn evidence_log(
    operation_id: &str,
    capability: &str,
    recipient_id: Option<&str>,
    webhook_event_id: Option<&str>,
    lifecycle_phase: &str,
    latency_ms: u64,
    result: &str,
    error_code: Option<String>,
    cleanup_result: &str,
    skip_reason: Option<&str>,
) -> ZaloEvidenceLog {
    ZaloEvidenceLog {
        schema_version: "zalo_connector_local_evidence.v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        command_line: "cargo test -p fcp-zalo --test integration".to_string(),
        git_revision: git_revision(),
        connector_id: CONNECTOR_ID.to_string(),
        operation_id: operation_id.to_string(),
        capability: capability.to_string(),
        zone: "z:community".to_string(),
        instance_id: stable_hash("zalo-loopback-instance"),
        fixture_id: "zalo-bot-api-loopback-fixture.v1".to_string(),
        recipient_id_hash: recipient_id.map(stable_hash),
        webhook_event_id_hash: webhook_event_id.map(stable_hash),
        lifecycle_phase: lifecycle_phase.to_string(),
        latency_ms,
        result: result.to_string(),
        error_code,
        audit_receipt_id: format!("audit:{BEAD_ID}:{operation_id}"),
        cleanup_result: cleanup_result.to_string(),
        skip_reason: skip_reason.map(str::to_string),
        redaction:
            "access_tokens_message_bodies_recipient_names_phone_numbers_provider_bodies_paths_not_logged"
                .to_string(),
    }
}

fn assert_log_shape_and_redaction(logs: &[ZaloEvidenceLog]) {
    assert!(!logs.is_empty(), "expected at least one evidence log");
    for entry in logs {
        let value = serde_json::to_value(entry).expect("evidence log JSON");
        for field in [
            "command_line",
            "git_revision",
            "connector_id",
            "operation_id",
            "capability",
            "zone",
            "instance_id",
            "fixture_id",
            "recipient_id_hash",
            "webhook_event_id_hash",
            "lifecycle_phase",
            "latency_ms",
            "result",
            "error_code",
            "audit_receipt_id",
            "cleanup_result",
            "skip_reason",
        ] {
            assert!(value.get(field).is_some(), "missing evidence field {field}");
        }
        eprintln!("{}", serde_json::to_string(entry).expect("log JSONL"));
    }

    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    for forbidden in [
        FIXTURE_TOKEN,
        FIXTURE_WEBHOOK_SECRET,
        "secret message body",
        "provider raw body",
        "recipient-fixture",
        "+15551234567",
        "Alice Example",
        "/Users/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
}

fn base_config(base_url: &str, request_timeout_ms: u64) -> Value {
    json!({
        "access_token": FIXTURE_TOKEN,
        "base_url": base_url,
        "request_timeout_ms": request_timeout_ms,
        "webhook_verify_challenge": FIXTURE_WEBHOOK_SECRET,
        "webhook_path": "/zalo/inbound",
        "allowed_sender_ids": ["sender-fixture"],
        "allowed_chat_ids": ["chat-fixture"],
        "rate_limit_window_ms": 60_000,
        "rate_limit_max": 100,
        "replay_cache_entries": 32
    })
}

async fn configured_connector(base_url: &str, request_timeout_ms: u64) -> ZaloConnector {
    let mut connector = ZaloConnector::new();
    connector
        .handle_configure(base_config(base_url, request_timeout_ms))
        .await
        .expect("configure should accept loopback base URL");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should complete");
    connector
}

fn webhook_headers(secret: &str) -> Value {
    json!({
        "content-type": "application/json; charset=utf-8",
        "x-bot-api-secret-token": secret
    })
}

fn webhook_ingest_input(update: &Value) -> Value {
    json!({
        "operation_id": WEBHOOK_INGEST_OP,
        "input": {
            "method": "POST",
            "path": "/zalo/inbound",
            "headers": webhook_headers(FIXTURE_WEBHOOK_SECRET),
            "client_id": "loopback-client",
            "account_id": "acct-fixture",
            "body": update.to_string()
        }
    })
}

#[fcp_async_core::runtime::test]
async fn lifecycle_webhook_ingest_verify_and_simulate_denials_emit_redacted_logs() {
    let mut logs = Vec::new();
    let mut connector = ZaloConnector::new();

    let start = Instant::now();
    connector
        .handle_configure(base_config("http://127.0.0.1:1", 1_000))
        .await
        .expect("configure should accept local loopback URL");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("handshake should complete");
    logs.push(evidence_log(
        "lifecycle.configure_handshake",
        "zalo.messages",
        None,
        None,
        "handshake",
        elapsed_millis(start),
        "ok",
        None,
        "not_started",
        None,
    ));

    let health = connector
        .handle_health()
        .await
        .expect("health should remain callable");
    assert_eq!(health["status"], "ready");

    let start = Instant::now();
    let verified = connector
        .handle_invoke(json!({
            "operation_id": WEBHOOK_VERIFY_OP,
            "input": { "token": FIXTURE_WEBHOOK_SECRET }
        }))
        .await
        .expect("matching webhook token should verify");
    assert_eq!(verified["verified"], true);
    logs.push(evidence_log(
        WEBHOOK_VERIFY_OP,
        "zalo.webhook",
        None,
        Some("event-verify"),
        "invoke",
        elapsed_millis(start),
        "ok",
        None,
        "not_started",
        None,
    ));

    let simulate_denied = connector
        .handle_simulate(json!({"operation_id": "zalo.unknown"}))
        .await
        .expect("simulate should return unsupported for unknown operation");
    assert_eq!(simulate_denied["allowed"], false);
    assert_eq!(simulate_denied["simulate_capability"], "unsupported");

    let start = Instant::now();
    let accepted = connector
        .handle_invoke(webhook_ingest_input(&json!({
            "update_id": 41,
            "message": {
                "message_id": "msg-41",
                "from": { "id": "sender-fixture", "name": "Alice Example" },
                "chat": { "id": "chat-fixture", "type": "private" },
                "text": "secret message body"
            }
        })))
        .await
        .expect("authorized webhook should ingest");
    assert_eq!(accepted["accepted"], 1);
    assert_eq!(accepted["events"][0]["topic"], "zalo.message.text");
    assert_eq!(accepted["events"][0]["policy_reason"], "sender_allowed");
    logs.push(evidence_log(
        WEBHOOK_INGEST_OP,
        "zalo.events",
        Some("recipient-fixture"),
        Some("msg-41"),
        "invoke",
        elapsed_millis(start),
        "ok",
        None,
        "accepted_event_no_live_credentials",
        None,
    ));

    let duplicate = connector
        .handle_invoke(webhook_ingest_input(&json!({
            "update_id": 41,
            "message": {
                "message_id": "msg-41",
                "from": { "id": "sender-fixture" },
                "chat": { "id": "chat-fixture", "type": "private" },
                "text": "secret message body"
            }
        })))
        .await
        .expect("duplicate webhook should be idempotent");
    assert_eq!(duplicate["duplicates"], 1);

    let unauthorized_ingest = connector
        .handle_invoke(json!({
            "operation_id": WEBHOOK_INGEST_OP,
            "input": {
                "method": "POST",
                "path": "/zalo/inbound",
                "headers": webhook_headers("wrong-secret"),
                "body": "{}"
            }
        }))
        .await
        .expect_err("bad webhook secret should be unauthorized");
    assert!(matches!(unauthorized_ingest, FcpError::Unauthorized { .. }));

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should clear state");
    logs.push(evidence_log(
        "lifecycle.shutdown",
        "zalo.messages",
        None,
        None,
        "shutdown",
        0,
        "ok",
        None,
        "state_cleared",
        None,
    ));

    assert_log_shape_and_redaction(&logs);
}

#[fcp_async_core::runtime::test]
async fn bot_api_loopback_covers_success_errors_polling_timeout_and_redaction() {
    let mut logs = Vec::new();
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/botfixture-zalo-access-token/sendMessage"))
        .and(body_partial_json(json!({
            "chat_id": "recipient-fixture",
            "text": "secret message body"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": { "message_id": "msg-loopback" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/botfixture-zalo-access-token/getUpdates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": [{
                "update_id": 80,
                "message": {
                    "message_id": "msg-80",
                    "from": { "id": "sender-fixture" },
                    "chat": { "id": "chat-fixture", "type": "private" },
                    "text": "secret message body"
                }
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/botfixture-zalo-access-token/getMe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error_code": 401,
            "description": "Unauthorized"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/botfixture-zalo-access-token/deleteWebhook"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({
                    "ok": false,
                    "error_code": 429,
                    "description": "Too many requests"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/botfixture-zalo-access-token/getWebhookInfo"))
        .respond_with(ResponseTemplate::new(200).set_body_string("provider raw body"))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server.uri(), 1_000).await;

    let start = Instant::now();
    let sent = connector
        .handle_invoke(json!({
            "operation_id": SEND_MESSAGE_OP,
            "input": {
                "recipient_id": "recipient-fixture",
                "message": "secret message body"
            }
        }))
        .await
        .expect("sendMessage should succeed against loopback");
    assert_eq!(sent["result"]["message_id"], "msg-loopback");
    logs.push(evidence_log(
        SEND_MESSAGE_OP,
        "zalo.messages",
        Some("recipient-fixture"),
        None,
        "invoke",
        elapsed_millis(start),
        "ok",
        None,
        "loopback_message_sent",
        None,
    ));

    let start = Instant::now();
    let updates = connector
        .handle_invoke(json!({
            "operation_id": POLL_UPDATES_OP,
            "input": { "offset": 70, "timeout_seconds": 0 }
        }))
        .await
        .expect("polling response should normalize authorized events");
    assert_eq!(updates["events"][0]["topic"], "zalo.message.text");
    assert_eq!(updates["events"][0]["source"], "polling");
    assert_eq!(updates["cursor"]["next_offset"], json!(81));
    logs.push(evidence_log(
        POLL_UPDATES_OP,
        "zalo.updates",
        Some("recipient-fixture"),
        Some("msg-80"),
        "invoke",
        elapsed_millis(start),
        "ok",
        None,
        "loopback_poll_normalized",
        None,
    ));

    let unauthorized = connector
        .handle_invoke(json!({"operation_id": GET_ME_OP}))
        .await
        .expect_err("provider auth failure should map to external error");
    assert!(matches!(
        unauthorized,
        FcpError::External {
            status_code: Some(401),
            retryable: false,
            ..
        }
    ));

    let rate_limited = connector
        .handle_invoke(json!({"operation_id": DELETE_WEBHOOK_OP}))
        .await
        .expect_err("429 should map to FCP rate limit");
    assert!(matches!(rate_limited, FcpError::RateLimited { .. }));

    let malformed = connector
        .handle_invoke(json!({"operation_id": WEBHOOK_INFO_OP}))
        .await
        .expect_err("malformed provider response should map to internal parse error");
    assert!(matches!(malformed, FcpError::Internal { .. }));

    let timeout_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/botfixture-zalo-access-token/getMe"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(75))
                .set_body_json(json!({ "ok": true, "result": { "id": "bot-timeout" } })),
        )
        .expect(1)
        .mount(&timeout_server)
        .await;
    let timeout_connector = configured_connector(&timeout_server.uri(), 1).await;
    let timeout = timeout_connector
        .handle_invoke(json!({"operation_id": GET_ME_OP}))
        .await
        .expect_err("delayed loopback should hit request timeout");
    assert!(timeout.to_string().contains("deadline exceeded"));
    logs.push(evidence_log(
        GET_ME_OP,
        "zalo.messages",
        None,
        None,
        "invoke",
        75,
        "error",
        Some(timeout.error_code()),
        "timeout_mapped",
        None,
    ));

    assert_log_shape_and_redaction(&logs);
}

#[test]
fn absent_live_zalo_credentials_emit_structured_skip_artifact() {
    let has_live_env = ["ZALO_ACCESS_TOKEN", "ZALO_RECIPIENT_ID"]
        .iter()
        .all(|key| std::env::var_os(key).is_some());
    if has_live_env {
        return;
    }

    let logs = vec![evidence_log(
        "live_verification",
        "zalo.messages",
        None,
        None,
        "skip",
        0,
        "skipped",
        None,
        "no_live_state_created",
        Some("ZALO_ACCESS_TOKEN and ZALO_RECIPIENT_ID are not both configured"),
    )];
    assert_log_shape_and_redaction(&logs);
}
