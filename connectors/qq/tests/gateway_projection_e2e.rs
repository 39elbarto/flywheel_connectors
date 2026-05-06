use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ShutdownRequest, ZoneId,
};
use fcp_qq::QqConnector;
use fcp_sdk::prelude::*;
use serde_json::{Value, json};

const OP_GATEWAY_PROJECT_EVENT: &str = "qq.gateway.project_event";
const CAP_EVENTS_READ: &str = "qq.events.read";

fn open_jsonl_log() -> (File, PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-qq-gateway-projection-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create QQ gateway e2e log dir");
    let path = dir.join("qq_gateway_projection_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open QQ gateway e2e log");
    (file, path)
}

fn log_step(logs: &mut File, step: &str, status: &str, details: &Value) {
    let record = json!({
        "step": step,
        "status": status,
        "details": details,
    });
    writeln!(logs, "{record}").expect("write QQ gateway e2e log line");
    logs.flush().expect("flush QQ gateway e2e log");
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        })
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unavailable".into())
}

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::community(),
        zone_dir: None,
        host_public_key,
        nonce: [7_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn build_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_EVENTS_READ)
        .zone_id("z:community")
        .principal("agent:test")
        .operations(&[OP_GATEWAY_PROJECT_EVENT])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

async fn invoke_projection(
    connector: &QqConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &str,
    event: Value,
) -> Value {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(id),
            connector_id: ConnectorId::from_static("fcp.qq"),
            operation: OperationId::from_static(OP_GATEWAY_PROJECT_EVENT),
            zone_id: ZoneId::community(),
            input: json!({ "event": event }),
            capability_token: build_token(signing_key, instance_id),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await
        .expect("project QQ gateway event");
    response.result.expect("projection result")
}

#[fcp_async_core::runtime::test]
async fn qq_gateway_projection_logs_policy_replay_and_shutdown() {
    let (mut logs, log_path) = open_jsonl_log();
    println!("qq_gateway_projection_e2e_log={}", log_path.display());
    log_step(
        &mut logs,
        "log_start",
        "ok",
        &json!({
            "path": log_path.display().to_string(),
            "command_line": std::env::args().collect::<Vec<_>>(),
            "git_revision": git_revision(),
        }),
    );

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let mut connector = QqConnector::new();
    connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "max_queue_depth": 2,
                "dedupe_window_size": 8,
                "policy": {
                    "group_policy": "allowlist",
                    "group_allow_from": ["group-allowed"],
                    "group_require_mention": true,
                    "bot_user_id": "bot-openid"
                }
            }
        }))
        .await
        .expect("configure QQ connector");
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake QQ connector");

    let hello = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-hello",
        json!({
            "op": 10,
            "d": { "session_id": "session-1" },
            "id": "hello-1"
        }),
    )
    .await;
    assert_eq!(hello["reason_code"], "hello");
    assert_eq!(hello["runtime"]["session_id"], "session-1");
    log_step(&mut logs, "hello_session_restore", "ok", &hello);

    let accepted = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-accepted",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-accepted",
            "d": {
                "id": "msg-accepted",
                "content": "bot-openid deploy status?",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1",
                "author": { "id": "member-1", "username": "Alice" }
            }
        }),
    )
    .await;
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["topic"], "qq.message.authorized");
    assert_eq!(accepted["policy"]["reason_code"], "group_allowed");
    log_step(&mut logs, "allowed_group_mention", "ok", &accepted);

    let missing_mention = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-missing-mention",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-missing-mention",
            "d": {
                "id": "msg-missing-mention",
                "content": "general chatter",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1"
            }
        }),
    )
    .await;
    assert_eq!(missing_mention["accepted"], false);
    assert_eq!(missing_mention["reason_code"], "missing_group_mention");
    log_step(
        &mut logs,
        "missing_group_mention_drop",
        "ok",
        &missing_mention,
    );

    let duplicate = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-duplicate",
        json!({
            "op": 0,
            "s": 3,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-accepted",
            "d": {
                "id": "msg-accepted",
                "content": "bot-openid deploy status?",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1"
            }
        }),
    )
    .await;
    assert_eq!(duplicate["accepted"], false);
    assert_eq!(duplicate["reason_code"], "duplicate_event");
    log_step(&mut logs, "duplicate_drop", "ok", &duplicate);

    let heartbeat = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-heartbeat",
        json!({
            "op": 11
        }),
    )
    .await;
    assert_eq!(heartbeat["reason_code"], "heartbeat_ack");
    assert_eq!(heartbeat["runtime"]["heartbeat_ack_count"], 1);
    log_step(&mut logs, "heartbeat_ack", "ok", &heartbeat);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("qq-gateway-e2e-complete".into()),
        })
        .await
        .expect("shutdown QQ connector");
    log_step(&mut logs, "shutdown", "ok", &json!({}));
}
