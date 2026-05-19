use std::fs::{File, OpenOptions, create_dir_all, read_to_string};
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
use sha2::{Digest, Sha256};

const OP_GATEWAY_PROJECT_EVENT: &str = "qq.gateway.project_event";
const OP_GATEWAY_DRAIN_EVENTS: &str = "qq.gateway.drain_events";
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
    println!("QQ_GATEWAY_PROJECTION_JSONL {record}");
    writeln!(logs, "{record}").expect("write QQ gateway e2e log line");
    logs.flush().expect("flush QQ gateway e2e log");
}

fn log_projection_step(logs: &mut File, step: &str, status: &str, projection: &Value) {
    log_step(logs, step, status, &redacted_projection(projection));
}

fn log_drain_step(logs: &mut File, step: &str, status: &str, drain: &Value) {
    log_step(logs, step, status, &redacted_drain_result(drain));
}

fn redacted_projection(projection: &Value) -> Value {
    json!({
        "accepted": bool_field(projection, "accepted"),
        "topic": str_field(projection, "topic"),
        "reason_code": str_field(projection, "reason_code"),
        "sequence": u64_field(projection, "sequence"),
        "event_id_hash": hash_field(projection, "event_id"),
        "normalized": projection
            .get("normalized")
            .filter(|value| !value.is_null())
            .map(redacted_normalized_event),
        "policy": projection
            .get("policy")
            .filter(|value| !value.is_null())
            .map(redacted_policy_decision),
        "runtime": projection
            .get("runtime")
            .filter(|value| !value.is_null())
            .map(redacted_runtime_snapshot),
        "lifecycle": projection
            .get("lifecycle")
            .filter(|value| !value.is_null())
            .map(redacted_lifecycle_directive),
    })
}

fn redacted_drain_result(drain: &Value) -> Value {
    let events = drain
        .get("events")
        .and_then(Value::as_array)
        .map(|events| events.iter().map(redacted_queued_event).collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "drained_count": u64_field(drain, "drained_count"),
        "remaining_count": u64_field(drain, "remaining_count"),
        "events": events,
        "runtime": drain
            .get("runtime")
            .filter(|value| !value.is_null())
            .map(redacted_runtime_snapshot),
    })
}

fn redacted_queued_event(event: &Value) -> Value {
    json!({
        "topic": str_field(event, "topic"),
        "sequence": u64_field(event, "sequence"),
        "event_id_hash": hash_field(event, "event_id"),
        "normalized": event
            .get("normalized")
            .filter(|value| !value.is_null())
            .map(redacted_normalized_event),
        "policy": event
            .get("policy")
            .filter(|value| !value.is_null())
            .map(redacted_policy_decision),
    })
}

fn redacted_normalized_event(event: &Value) -> Value {
    json!({
        "event_type": str_field(event, "event_type"),
        "routing": str_field(event, "routing"),
        "message_id_hash": hash_field(event, "message_id"),
        "channel_id_hash": hash_field(event, "channel_id"),
        "guild_id_hash": hash_field(event, "guild_id"),
        "group_id_hash": hash_field(event, "group_id"),
        "sender_id_hash": hash_field(event, "sender_id"),
        "has_sender_name": str_field(event, "sender_name").is_some(),
        "text_len": text_len(event),
        "text_hash": hash_field(event, "text"),
        "timestamp_present": str_field(event, "timestamp").is_some(),
        "is_reply": bool_field(event, "is_reply"),
        "reply_to_hash": hash_field(event, "reply_to"),
        "has_attachments": bool_field(event, "has_attachments"),
        "interaction_kind": str_field(event, "interaction_kind"),
        "command_name_hash": hash_field(event, "command_name"),
        "approval_action": str_field(event, "approval_action"),
        "attachment_count": attachment_count(event),
        "attachment_total_bytes": attachment_total_bytes(event),
        "attachment_content_types": attachment_content_types(event),
        "attachment_filename_hashes": attachment_filename_hashes(event),
        "attachment_url_hashes": attachment_url_hashes(event),
    })
}

fn redacted_policy_decision(policy: &Value) -> Value {
    json!({
        "allowed": bool_field(policy, "allowed"),
        "reason_code": str_field(policy, "reason_code"),
        "routing": str_field(policy, "routing"),
        "sender_id_hash": hash_field(policy, "sender_id"),
        "target_id_hash": hash_field(policy, "target_id"),
        "mentioned_bot": bool_field(policy, "mentioned_bot"),
    })
}

fn redacted_runtime_snapshot(runtime: &Value) -> Value {
    json!({
        "enabled": bool_field(runtime, "enabled"),
        "session_id_hash": hash_field(runtime, "session_id"),
        "last_sequence": u64_field(runtime, "last_sequence"),
        "heartbeat_interval_ms": u64_field(runtime, "heartbeat_interval_ms"),
        "heartbeat_sent_count": u64_field(runtime, "heartbeat_sent_count"),
        "heartbeat_ack_count": u64_field(runtime, "heartbeat_ack_count"),
        "reconnect_attempts": u64_field(runtime, "reconnect_attempts"),
        "max_reconnect_attempts": u64_field(runtime, "max_reconnect_attempts"),
        "terminal_reconnect_failures": u64_field(runtime, "terminal_reconnect_failures"),
        "reconnect_backoff_ms": u64_field(runtime, "reconnect_backoff_ms"),
        "max_reconnect_backoff_ms": u64_field(runtime, "max_reconnect_backoff_ms"),
        "queue_depth": u64_field(runtime, "queue_depth"),
        "max_queue_depth": u64_field(runtime, "max_queue_depth"),
        "peer_queue_count": u64_field(runtime, "peer_queue_count"),
        "largest_peer_queue_depth": u64_field(runtime, "largest_peer_queue_depth"),
        "max_peer_queue_depth": u64_field(runtime, "max_peer_queue_depth"),
        "dedupe_size": u64_field(runtime, "dedupe_size"),
        "dedupe_window_size": u64_field(runtime, "dedupe_window_size"),
        "reply_reference_count": u64_field(runtime, "reply_reference_count"),
        "max_reply_references": u64_field(runtime, "max_reply_references"),
        "known_reply_references": u64_field(runtime, "known_reply_references"),
        "unknown_reply_references": u64_field(runtime, "unknown_reply_references"),
        "accepted_events": u64_field(runtime, "accepted_events"),
        "dropped_events": u64_field(runtime, "dropped_events"),
        "duplicate_events": u64_field(runtime, "duplicate_events"),
        "stale_sequence_events": u64_field(runtime, "stale_sequence_events"),
    })
}

fn redacted_lifecycle_directive(lifecycle: &Value) -> Value {
    json!({
        "action": str_field(lifecycle, "action"),
        "reason_code": str_field(lifecycle, "reason_code"),
        "resume_session_id_hash": hash_field(lifecycle, "resume_session_id"),
        "resume_sequence": u64_field(lifecycle, "resume_sequence"),
        "heartbeat_interval_ms": u64_field(lifecycle, "heartbeat_interval_ms"),
        "reconnect_after_ms": u64_field(lifecycle, "reconnect_after_ms"),
    })
}

fn str_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn u64_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn hash_field(value: &Value, field: &str) -> Option<String> {
    str_field(value, field).map(evidence_hash)
}

fn text_len(value: &Value) -> Option<usize> {
    str_field(value, "text").map(|text| text.chars().count())
}

fn attachment_count(event: &Value) -> usize {
    attachments(event).map_or(0, <[Value]>::len)
}

fn attachment_total_bytes(event: &Value) -> Option<u64> {
    let mut total = 0_u64;
    let mut saw_size = false;
    for size in attachments(event)?
        .iter()
        .filter_map(|attachment| attachment.get("size").and_then(Value::as_u64))
    {
        saw_size = true;
        total = total.saturating_add(size);
    }
    saw_size.then_some(total)
}

fn attachment_content_types(event: &Value) -> Vec<String> {
    attachments(event)
        .map(|attachments| {
            attachments
                .iter()
                .filter_map(|attachment| str_field(attachment, "content_type"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn attachment_url_hashes(event: &Value) -> Vec<String> {
    attachments(event)
        .map(|attachments| {
            attachments
                .iter()
                .filter_map(|attachment| str_field(attachment, "url"))
                .map(evidence_hash)
                .collect()
        })
        .unwrap_or_default()
}

fn attachment_filename_hashes(event: &Value) -> Vec<String> {
    attachments(event)
        .map(|attachments| {
            attachments
                .iter()
                .filter_map(|attachment| str_field(attachment, "filename"))
                .map(evidence_hash)
                .collect()
        })
        .unwrap_or_default()
}

fn attachments(event: &Value) -> Option<&[Value]> {
    event
        .get("raw")
        .and_then(|raw| raw.get("attachments"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn evidence_hash(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fcp-qq-gateway-evidence-v1:");
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let mut prefix = [0_u8; 12];
    for (slot, byte) in prefix.iter_mut().zip(digest.iter().copied()) {
        *slot = byte;
    }
    hex::encode(prefix)
}

fn typed_evidence_hash(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fcp-qq-gateway-metadata-v1:");
    hasher.update(raw.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
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

fn build_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &'static str,
) -> CapabilityToken {
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
        .operations(&[operation])
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
    try_invoke_projection(connector, signing_key, instance_id, id, event)
        .await
        .expect("project QQ gateway event")
}

async fn try_invoke_projection(
    connector: &QqConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &str,
    event: Value,
) -> Result<Value, String> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(id),
            connector_id: ConnectorId::from_static("fcp.qq"),
            operation: OperationId::from_static(OP_GATEWAY_PROJECT_EVENT),
            zone_id: ZoneId::community(),
            input: json!({ "event": event }),
            capability_token: build_token(signing_key, instance_id, OP_GATEWAY_PROJECT_EVENT),
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
        .map_err(|error| format!("{}: {error}", error.error_code()))?;
    if response.status != InvokeStatus::Ok {
        return Err(format!(
            "projection status {:?}: {:?}",
            response.status, response.error
        ));
    }
    response
        .result
        .ok_or_else(|| "projection response missing result".to_string())
}

async fn invoke_drain(
    connector: &QqConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &str,
    input: Value,
) -> Value {
    try_invoke_drain(connector, signing_key, instance_id, id, input)
        .await
        .expect("drain QQ gateway events")
}

async fn try_invoke_drain(
    connector: &QqConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &str,
    input: Value,
) -> Result<Value, String> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(id),
            connector_id: ConnectorId::from_static("fcp.qq"),
            operation: OperationId::from_static(OP_GATEWAY_DRAIN_EVENTS),
            zone_id: ZoneId::community(),
            input,
            capability_token: build_token(signing_key, instance_id, OP_GATEWAY_DRAIN_EVENTS),
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
        .map_err(|error| error.to_string())?;
    if response.status != InvokeStatus::Ok {
        return Err(format!(
            "drain status {:?}: {:?}",
            response.status, response.error
        ));
    }
    response
        .result
        .ok_or_else(|| "drain response missing result".to_string())
}

#[fcp_async_core::runtime::test]
async fn qq_gateway_projection_logs_policy_replay_and_shutdown() {
    let (mut logs, log_path) = open_jsonl_log();
    println!("qq_gateway_projection_e2e_log={}", log_path.display());
    let artifact_path = log_path.display().to_string();
    let command_line = std::env::args().collect::<Vec<_>>();
    log_step(
        &mut logs,
        "log_start",
        "ok",
        &json!({
            "artifact_path_hash": typed_evidence_hash(&artifact_path),
            "artifact_path_class": "temp_jsonl",
            "command_line_hash": typed_evidence_hash(&command_line.join("\0")),
            "command_arg_count": command_line.len(),
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
                "max_queue_depth": 3,
                "dedupe_window_size": 8,
                "policy": {
                    "group_policy": "allowlist",
                    "group_allow_from": ["group-allowed"],
                    "group_require_mention": true,
                    "bot_user_id": "bot-openid",
                    "max_attachment_bytes": 4096
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

    let disabled_instance_id = InstanceId::new();
    let mut disabled_connector = QqConnector::new();
    disabled_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": false,
                "policy": {
                    "group_policy": "open",
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure disabled QQ connector");
    disabled_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            disabled_instance_id.clone(),
        ))
        .await
        .expect("handshake disabled QQ connector");
    let disabled = invoke_projection(
        &disabled_connector,
        &signing_key,
        &disabled_instance_id,
        "qq-gateway-disabled",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-disabled",
            "d": {
                "id": "msg-disabled",
                "content": "gateway disabled should not authorize",
                "group_openid": "group-disabled",
                "group_member_openid": "member-disabled"
            }
        }),
    )
    .await;
    assert_eq!(disabled["accepted"], false);
    assert_eq!(disabled["reason_code"], "gateway_disabled");
    assert_eq!(disabled["lifecycle"]["action"], "none");
    assert_eq!(disabled["normalized"], Value::Null);
    assert_eq!(disabled["policy"], Value::Null);
    assert_eq!(disabled["runtime"]["last_sequence"], 0);
    assert_eq!(disabled["runtime"]["accepted_events"], 0);
    log_projection_step(&mut logs, "gateway_disabled_drop", "ok", &disabled);

    let binding_instance_id = InstanceId::new();
    let mut binding_connector = QqConnector::new();
    binding_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "group_policy": "open",
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure binding QQ connector");
    binding_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            binding_instance_id.clone(),
        ))
        .await
        .expect("handshake binding QQ connector");
    let missing_binding = invoke_projection(
        &binding_connector,
        &signing_key,
        &binding_instance_id,
        "qq-gateway-missing-binding",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-missing-binding",
            "d": {
                "id": "msg-missing-binding",
                "content": "event missing sender binding",
                "group_openid": "group-binding"
            }
        }),
    )
    .await;
    assert_eq!(missing_binding["accepted"], false);
    assert_eq!(missing_binding["reason_code"], "group_sender_missing");
    assert_eq!(
        missing_binding["policy"]["reason_code"],
        "group_sender_missing"
    );
    assert_eq!(missing_binding["runtime"]["accepted_events"], 0);
    assert_eq!(missing_binding["runtime"]["queue_depth"], 0);
    log_projection_step(
        &mut logs,
        "missing_route_binding_drop",
        "ok",
        &missing_binding,
    );

    let missing_message_id = invoke_projection(
        &binding_connector,
        &signing_key,
        &binding_instance_id,
        "qq-gateway-missing-message-id",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-missing-message-id",
            "d": {
                "content": "event missing message id",
                "group_openid": "group-binding",
                "group_member_openid": "member-1"
            }
        }),
    )
    .await;
    assert_eq!(missing_message_id["accepted"], false);
    assert_eq!(missing_message_id["reason_code"], "message_id_missing");
    assert_eq!(
        missing_message_id["policy"]["reason_code"],
        "message_id_missing"
    );
    assert_eq!(missing_message_id["runtime"]["accepted_events"], 0);
    assert_eq!(missing_message_id["runtime"]["queue_depth"], 0);
    log_projection_step(
        &mut logs,
        "missing_message_identity_drop",
        "ok",
        &missing_message_id,
    );

    let missing_reply_target = invoke_projection(
        &binding_connector,
        &signing_key,
        &binding_instance_id,
        "qq-gateway-missing-reply-target",
        json!({
            "op": 0,
            "s": 3,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-missing-reply-target",
            "d": {
                "id": "msg-missing-reply-target",
                "content": "bot-openid blank reply target",
                "group_openid": "group-binding",
                "group_member_openid": "member-1",
                "message_reference": { "message_id": "   " }
            }
        }),
    )
    .await;
    assert_eq!(missing_reply_target["accepted"], false);
    assert_eq!(missing_reply_target["reason_code"], "reply_target_missing");
    assert_eq!(
        missing_reply_target["policy"]["reason_code"],
        "reply_target_missing"
    );
    assert_eq!(missing_reply_target["runtime"]["accepted_events"], 0);
    assert_eq!(missing_reply_target["runtime"]["queue_depth"], 0);
    log_projection_step(
        &mut logs,
        "missing_reply_target_drop",
        "ok",
        &missing_reply_target,
    );

    let channel_policy_instance_id = InstanceId::new();
    let mut channel_policy_connector = QqConnector::new();
    channel_policy_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "channel_policy": "allowlist",
                    "channel_allow_from": ["channel-allowed"],
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure channel policy QQ connector");
    channel_policy_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            channel_policy_instance_id.clone(),
        ))
        .await
        .expect("handshake channel policy QQ connector");
    let channel_denied = invoke_projection(
        &channel_policy_connector,
        &signing_key,
        &channel_policy_instance_id,
        "qq-gateway-channel-denied",
        json!({
            "op": 0,
            "s": 1,
            "t": "MESSAGE_CREATE",
            "id": "evt-channel-denied",
            "d": {
                "id": "msg-channel-denied",
                "channel_id": "channel-denied",
                "guild_id": "guild-denied",
                "author": {"id": "sender-denied"},
                "content": "channel allowlist should deny"
            }
        }),
    )
    .await;
    assert_eq!(channel_denied["accepted"], false);
    assert_eq!(channel_denied["reason_code"], "channel_not_allowed");
    assert_eq!(
        channel_denied["policy"]["reason_code"],
        "channel_not_allowed"
    );
    assert_eq!(channel_denied["runtime"]["accepted_events"], 0);
    assert_eq!(channel_denied["runtime"]["queue_depth"], 0);
    log_projection_step(&mut logs, "channel_policy_denied", "ok", &channel_denied);

    let channel_allowed = invoke_projection(
        &channel_policy_connector,
        &signing_key,
        &channel_policy_instance_id,
        "qq-gateway-channel-allowed",
        json!({
            "op": 0,
            "s": 2,
            "t": "AT_MESSAGE_CREATE",
            "id": "evt-channel-allowed",
            "d": {
                "id": "msg-channel-allowed",
                "channel_id": "channel-allowed",
                "guild_id": "guild-denied",
                "author": {"id": "sender-denied"},
                "content": "channel allowlist should authorize"
            }
        }),
    )
    .await;
    assert_eq!(channel_allowed["accepted"], true);
    assert_eq!(channel_allowed["topic"], "qq.message.authorized");
    assert_eq!(channel_allowed["policy"]["reason_code"], "channel_allowed");
    assert_eq!(channel_allowed["policy"]["target_id"], "channel-allowed");
    assert_eq!(channel_allowed["policy"]["mentioned_bot"], true);
    assert_eq!(channel_allowed["runtime"]["accepted_events"], 1);
    assert_eq!(channel_allowed["runtime"]["queue_depth"], 1);
    log_projection_step(&mut logs, "channel_policy_allowed", "ok", &channel_allowed);

    let c2c_policy_instance_id = InstanceId::new();
    let mut c2c_policy_connector = QqConnector::new();
    c2c_policy_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "dm_policy": "allowlist",
                    "dm_allow_from": ["member-c2c-allowed"],
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure C2C policy QQ connector");
    c2c_policy_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            c2c_policy_instance_id.clone(),
        ))
        .await
        .expect("handshake C2C policy QQ connector");
    let c2c_denied = invoke_projection(
        &c2c_policy_connector,
        &signing_key,
        &c2c_policy_instance_id,
        "qq-gateway-c2c-denied",
        json!({
            "op": 0,
            "s": 1,
            "t": "C2C_MESSAGE_CREATE",
            "id": "evt-c2c-denied",
            "d": {
                "id": "msg-c2c-denied",
                "content": "c2c allowlist should deny",
                "author": {"id": "member-c2c-denied"}
            }
        }),
    )
    .await;
    assert_eq!(c2c_denied["accepted"], false);
    assert_eq!(c2c_denied["reason_code"], "c2c_sender_not_allowed");
    assert_eq!(
        c2c_denied["policy"]["reason_code"],
        "c2c_sender_not_allowed"
    );
    assert_eq!(c2c_denied["normalized"]["routing"], "c2c");
    assert_eq!(c2c_denied["runtime"]["accepted_events"], 0);
    assert_eq!(c2c_denied["runtime"]["queue_depth"], 0);
    log_projection_step(&mut logs, "c2c_policy_denied", "ok", &c2c_denied);

    let c2c_allowed = invoke_projection(
        &c2c_policy_connector,
        &signing_key,
        &c2c_policy_instance_id,
        "qq-gateway-c2c-allowed",
        json!({
            "op": 0,
            "s": 2,
            "t": "C2C_MESSAGE_CREATE",
            "id": "evt-c2c-allowed",
            "d": {
                "id": "msg-c2c-allowed",
                "content": "c2c allowlist should authorize",
                "author": {"id": "member-c2c-allowed"}
            }
        }),
    )
    .await;
    assert_eq!(c2c_allowed["accepted"], true);
    assert_eq!(c2c_allowed["topic"], "qq.message.authorized");
    assert_eq!(c2c_allowed["policy"]["reason_code"], "c2c_allowed");
    assert_eq!(c2c_allowed["policy"]["target_id"], "member-c2c-allowed");
    assert_eq!(c2c_allowed["policy"]["mentioned_bot"], true);
    assert_eq!(c2c_allowed["normalized"]["routing"], "c2c");
    assert_eq!(c2c_allowed["runtime"]["accepted_events"], 1);
    assert_eq!(c2c_allowed["runtime"]["queue_depth"], 1);
    log_projection_step(&mut logs, "c2c_policy_allowed", "ok", &c2c_allowed);

    let queue_instance_id = InstanceId::new();
    let mut queue_connector = QqConnector::new();
    queue_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "max_queue_depth": 1,
                "policy": {
                    "group_policy": "allowlist",
                    "group_allow_from": ["group-queue"],
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure queue-bound QQ connector");
    queue_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            queue_instance_id.clone(),
        ))
        .await
        .expect("handshake queue-bound QQ connector");
    let queue_fill = invoke_projection(
        &queue_connector,
        &signing_key,
        &queue_instance_id,
        "qq-gateway-queue-fill",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-queue-fill",
            "d": {
                "id": "msg-queue-fill",
                "content": "queue fill message",
                "group_openid": "group-queue",
                "group_member_openid": "member-queue"
            }
        }),
    )
    .await;
    assert_eq!(queue_fill["accepted"], true);
    assert_eq!(queue_fill["runtime"]["queue_depth"], 1);
    assert_eq!(queue_fill["runtime"]["max_queue_depth"], 1);
    assert_eq!(queue_fill["runtime"]["accepted_events"], 1);
    let queue_full_policy_denied = invoke_projection(
        &queue_connector,
        &signing_key,
        &queue_instance_id,
        "qq-gateway-queue-full-policy-denied",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-queue-full-policy-denied",
            "d": {
                "id": "msg-queue-full-policy-denied",
                "content": "queue should not hide denied sender policy",
                "group_openid": "group-denied",
                "group_member_openid": "member-denied"
            }
        }),
    )
    .await;
    assert_eq!(queue_full_policy_denied["accepted"], false);
    assert_eq!(queue_full_policy_denied["reason_code"], "group_not_allowed");
    assert_eq!(
        queue_full_policy_denied["policy"]["reason_code"],
        "group_not_allowed"
    );
    assert_eq!(queue_full_policy_denied["runtime"]["queue_depth"], 1);
    assert_eq!(queue_full_policy_denied["runtime"]["accepted_events"], 1);
    assert_eq!(queue_full_policy_denied["runtime"]["dropped_events"], 1);
    log_projection_step(
        &mut logs,
        "queue_full_policy_denied",
        "ok",
        &queue_full_policy_denied,
    );
    let queue_full = invoke_projection(
        &queue_connector,
        &signing_key,
        &queue_instance_id,
        "qq-gateway-queue-full",
        json!({
            "op": 0,
            "s": 3,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-queue-full",
            "d": {
                "id": "msg-queue-full",
                "content": "queue backpressure message",
                "group_openid": "group-queue",
                "group_member_openid": "member-queue"
            }
        }),
    )
    .await;
    assert_eq!(queue_full["accepted"], false);
    assert_eq!(queue_full["reason_code"], "queue_full");
    assert_eq!(queue_full["normalized"], Value::Null);
    assert_eq!(queue_full["policy"], Value::Null);
    assert_eq!(queue_full["runtime"]["queue_depth"], 1);
    assert_eq!(queue_full["runtime"]["max_queue_depth"], 1);
    assert_eq!(queue_full["runtime"]["accepted_events"], 1);
    assert_eq!(queue_full["runtime"]["dropped_events"], 2);
    assert_eq!(queue_full["lifecycle"]["action"], "none");
    log_projection_step(&mut logs, "queue_full_backpressure_drop", "ok", &queue_full);

    let peer_queue_instance_id = InstanceId::new();
    let mut peer_queue_connector = QqConnector::new();
    peer_queue_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "max_queue_depth": 3,
                "max_peer_queue_depth": 1,
                "policy": {
                    "group_policy": "allowlist",
                    "group_allow_from": ["group-peer-a", "group-peer-b"],
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure peer-queue QQ connector");
    peer_queue_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            peer_queue_instance_id.clone(),
        ))
        .await
        .expect("handshake peer-queue QQ connector");
    let peer_first = invoke_projection(
        &peer_queue_connector,
        &signing_key,
        &peer_queue_instance_id,
        "qq-gateway-peer-queue-first",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-peer-queue-first",
            "d": {
                "id": "msg-peer-queue-first",
                "content": "first peer queue message",
                "group_openid": "group-peer-a",
                "group_member_openid": "member-peer-1"
            }
        }),
    )
    .await;
    assert_eq!(peer_first["accepted"], true);
    assert_eq!(peer_first["runtime"]["queue_depth"], 1);
    assert_eq!(peer_first["runtime"]["peer_queue_count"], 1);
    assert_eq!(peer_first["runtime"]["largest_peer_queue_depth"], 1);
    assert_eq!(peer_first["runtime"]["max_peer_queue_depth"], 1);
    log_projection_step(&mut logs, "peer_queue_first_accepted", "ok", &peer_first);

    let peer_full = invoke_projection(
        &peer_queue_connector,
        &signing_key,
        &peer_queue_instance_id,
        "qq-gateway-peer-queue-full",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-peer-queue-full",
            "d": {
                "id": "msg-peer-queue-full",
                "content": "same peer should hit per-peer cap",
                "group_openid": "group-peer-a",
                "group_member_openid": "member-peer-2"
            }
        }),
    )
    .await;
    assert_eq!(peer_full["accepted"], false);
    assert_eq!(peer_full["reason_code"], "peer_queue_full");
    assert_eq!(peer_full["normalized"], Value::Null);
    assert_eq!(peer_full["policy"], Value::Null);
    assert_eq!(peer_full["runtime"]["queue_depth"], 1);
    assert_eq!(peer_full["runtime"]["peer_queue_count"], 1);
    assert_eq!(peer_full["runtime"]["largest_peer_queue_depth"], 1);
    assert_eq!(peer_full["runtime"]["dropped_events"], 1);
    log_projection_step(&mut logs, "peer_queue_full_drop", "ok", &peer_full);

    let peer_other = invoke_projection(
        &peer_queue_connector,
        &signing_key,
        &peer_queue_instance_id,
        "qq-gateway-peer-queue-other",
        json!({
            "op": 0,
            "s": 3,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-peer-queue-other",
            "d": {
                "id": "msg-peer-queue-other",
                "content": "different peer should still drain later",
                "group_openid": "group-peer-b",
                "group_member_openid": "member-peer-3"
            }
        }),
    )
    .await;
    assert_eq!(peer_other["accepted"], true);
    assert_eq!(peer_other["runtime"]["queue_depth"], 2);
    assert_eq!(peer_other["runtime"]["peer_queue_count"], 2);
    assert_eq!(peer_other["runtime"]["largest_peer_queue_depth"], 1);
    log_projection_step(
        &mut logs,
        "peer_queue_other_peer_allowed",
        "ok",
        &peer_other,
    );

    let hello = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-hello",
        json!({
            "op": 10,
            "d": {
                "session_id": "session-1",
                "heartbeat_interval": 41_250
            },
            "id": "hello-1"
        }),
    )
    .await;
    assert_eq!(hello["reason_code"], "hello");
    assert_eq!(hello["runtime"]["session_id"], "session-1");
    assert_eq!(hello["lifecycle"]["action"], "resume");
    assert_eq!(hello["lifecycle"]["resume_session_id"], "session-1");
    assert_eq!(hello["lifecycle"]["resume_sequence"], 0);
    assert_eq!(hello["runtime"]["heartbeat_interval_ms"], 41_250);
    assert_eq!(hello["lifecycle"]["heartbeat_interval_ms"], 41_250);
    log_projection_step(&mut logs, "hello_session_restore", "ok", &hello);

    let malformed_control_id = "x".repeat(257);
    let malformed_control = try_invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-malformed-control-envelope",
        json!({
            "op": 10,
            "id": malformed_control_id,
            "d": { "session_id": "session-should-not-stick" }
        }),
    )
    .await;
    let malformed_control_error =
        malformed_control.expect_err("malformed control envelope should fail closed");
    assert!(
        malformed_control_error.contains("FCP-1005"),
        "malformed control envelope should map to FCP-1005: {malformed_control_error}"
    );
    assert!(
        malformed_control_error.contains("gateway event id exceeds parser bounds"),
        "malformed control envelope should report a bounded parser failure: {malformed_control_error}"
    );
    log_step(
        &mut logs,
        "malformed_control_envelope_denied",
        "ok",
        &json!({
            "project_denied": true,
            "error_code_present": malformed_control_error.contains("FCP-1005"),
            "error_mentions_bounds": malformed_control_error.contains("gateway event id exceeds parser bounds"),
            "raw_event_logged": false,
        }),
    );

    let malformed_data_event_id = format!("evt-malformed-data-id-{}", "d".repeat(257));
    let malformed_data_event = try_invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-malformed-data-event-id",
        json!({
            "op": 0,
            "s": 2,
            "t": "THREAD_CREATE",
            "d": { "id": malformed_data_event_id }
        }),
    )
    .await;
    let malformed_data_event_error =
        malformed_data_event.expect_err("malformed data event id should fail closed");
    assert!(
        malformed_data_event_error.contains("FCP-1005"),
        "malformed data event id should map to FCP-1005: {malformed_data_event_error}"
    );
    assert!(
        malformed_data_event_error.contains("gateway event id exceeds parser bounds"),
        "malformed data event id should report a bounded parser failure: {malformed_data_event_error}"
    );
    log_step(
        &mut logs,
        "malformed_data_id_envelope_denied",
        "ok",
        &json!({
            "project_denied": true,
            "error_code_present": malformed_data_event_error.contains("FCP-1005"),
            "error_mentions_bounds": malformed_data_event_error.contains("gateway event id exceeds parser bounds"),
            "raw_event_logged": false,
        }),
    );

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
    assert_eq!(accepted["lifecycle"]["action"], "drain_events");
    assert_eq!(accepted["runtime"]["reply_reference_count"], 1);
    assert_eq!(accepted["runtime"]["known_reply_references"], 0);
    assert_eq!(accepted["runtime"]["unknown_reply_references"], 0);
    log_projection_step(&mut logs, "allowed_group_mention", "ok", &accepted);

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
    log_projection_step(
        &mut logs,
        "missing_group_mention_drop",
        "ok",
        &missing_mention,
    );

    let untyped_message_id = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-untyped-message-id",
        json!({
            "op": 0,
            "s": 3,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-untyped-message-id",
            "d": {
                "id": "msg-untyped-message-id",
                "content": "plain message",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1",
                "message": {
                    "id": "bot-openid",
                    "text": "not a mention segment"
                }
            }
        }),
    )
    .await;
    assert_eq!(untyped_message_id["accepted"], false);
    assert_eq!(untyped_message_id["reason_code"], "missing_group_mention");
    assert_eq!(untyped_message_id["policy"]["mentioned_bot"], false);
    log_projection_step(
        &mut logs,
        "untyped_message_id_not_mention",
        "ok",
        &untyped_message_id,
    );

    let structured_mention = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-structured-mention",
        json!({
            "op": 0,
            "s": 4,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-structured-mention",
            "d": {
                "id": "msg-structured-mention",
                "content": "please inspect this",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1",
                "mentions": [
                    { "type": "at", "user_openid": "bot-openid" }
                ]
            }
        }),
    )
    .await;
    assert_eq!(structured_mention["accepted"], true);
    assert_eq!(structured_mention["topic"], "qq.message.authorized");
    assert_eq!(structured_mention["policy"]["mentioned_bot"], true);
    log_projection_step(
        &mut logs,
        "structured_group_mention",
        "ok",
        &structured_mention,
    );

    let text_mention_instance_id = InstanceId::new();
    let mut text_mention_connector = QqConnector::new();
    text_mention_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "group_policy": "open",
                    "group_require_mention": true,
                    "bot_user_id": "bot-openid"
                }
            }
        }))
        .await
        .expect("configure text mention QQ connector");
    text_mention_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            text_mention_instance_id.clone(),
        ))
        .await
        .expect("handshake text mention QQ connector");
    let text_substring = invoke_projection(
        &text_mention_connector,
        &signing_key,
        &text_mention_instance_id,
        "qq-gateway-text-substring",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-text-substring",
            "d": {
                "id": "msg-text-substring",
                "content": "prefix not-bot-openid suffix",
                "group_openid": "group-text",
                "group_member_openid": "member-text"
            }
        }),
    )
    .await;
    assert_eq!(text_substring["accepted"], false);
    assert_eq!(text_substring["reason_code"], "missing_group_mention");
    assert_eq!(text_substring["policy"]["mentioned_bot"], false);
    log_projection_step(
        &mut logs,
        "text_substring_not_mention",
        "ok",
        &text_substring,
    );
    let explicit_text_mention = invoke_projection(
        &text_mention_connector,
        &signing_key,
        &text_mention_instance_id,
        "qq-gateway-explicit-text-mention",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-explicit-text-mention",
            "d": {
                "id": "msg-explicit-text-mention",
                "content": "please @bot-openid check this",
                "group_openid": "group-text",
                "group_member_openid": "member-text"
            }
        }),
    )
    .await;
    assert_eq!(explicit_text_mention["accepted"], true);
    assert_eq!(explicit_text_mention["topic"], "qq.message.authorized");
    assert_eq!(explicit_text_mention["policy"]["mentioned_bot"], true);
    assert_eq!(
        explicit_text_mention["policy"]["reason_code"],
        "group_allowed"
    );
    log_projection_step(
        &mut logs,
        "explicit_text_group_mention",
        "ok",
        &explicit_text_mention,
    );

    let oversized_media = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-oversized-media",
        json!({
            "op": 0,
            "s": 5,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-oversized-media",
            "d": {
                "id": "msg-oversized-media",
                "content": "bot-openid too large",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1",
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/oversized.bin",
                        "filename": "oversized.bin",
                        "content_type": "application/octet-stream",
                        "size": 4097
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(oversized_media["accepted"], false);
    assert_eq!(oversized_media["reason_code"], "attachment_bytes_exceeded");
    assert_eq!(
        oversized_media["policy"]["reason_code"],
        "attachment_bytes_exceeded"
    );
    log_projection_step(
        &mut logs,
        "oversized_media_policy_drop",
        "ok",
        &oversized_media,
    );

    let unknown_size_media = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-unknown-size-media",
        json!({
            "op": 0,
            "s": 6,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-unknown-size-media",
            "d": {
                "id": "msg-unknown-size-media",
                "content": "bot-openid missing size metadata",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1",
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/missing-size.pdf",
                        "filename": "missing-size.pdf",
                        "content_type": "application/pdf"
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(unknown_size_media["accepted"], false);
    assert_eq!(unknown_size_media["reason_code"], "attachment_size_unknown");
    assert_eq!(
        unknown_size_media["policy"]["reason_code"],
        "attachment_size_unknown"
    );
    log_projection_step(
        &mut logs,
        "unknown_media_size_policy_drop",
        "ok",
        &unknown_size_media,
    );

    let media_type_instance_id = InstanceId::new();
    let mut media_type_connector = QqConnector::new();
    media_type_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "group_policy": "open",
                    "group_require_mention": true,
                    "bot_user_id": "bot-openid",
                    "max_attachment_bytes": 4096,
                    "allowed_attachment_content_types": ["image/png"]
                }
            }
        }))
        .await
        .expect("configure media-type QQ connector");
    media_type_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            media_type_instance_id.clone(),
        ))
        .await
        .expect("handshake media-type QQ connector");
    let media_type_denied = invoke_projection(
        &media_type_connector,
        &signing_key,
        &media_type_instance_id,
        "qq-gateway-media-type-denied",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-media-type-denied",
            "d": {
                "id": "msg-media-type-denied",
                "content": "bot-openid blocked media type",
                "group_openid": "group-media-type",
                "group_member_openid": "member-media-type",
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/disallowed.exe",
                        "filename": "disallowed.exe",
                        "content_type": "application/x-msdownload",
                        "size": 512
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(media_type_denied["accepted"], false);
    assert_eq!(
        media_type_denied["reason_code"],
        "attachment_content_type_not_allowed"
    );
    assert_eq!(
        media_type_denied["policy"]["reason_code"],
        "attachment_content_type_not_allowed"
    );
    assert_eq!(media_type_denied["runtime"]["accepted_events"], 0);
    assert_eq!(media_type_denied["runtime"]["queue_depth"], 0);
    log_projection_step(
        &mut logs,
        "media_content_type_policy_drop",
        "ok",
        &media_type_denied,
    );

    let media_type_malformed = invoke_projection(
        &media_type_connector,
        &signing_key,
        &media_type_instance_id,
        "qq-gateway-media-type-malformed",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-media-type-malformed",
            "d": {
                "id": "msg-media-type-malformed",
                "content": "bot-openid malformed media type",
                "group_openid": "group-media-type",
                "group_member_openid": "member-media-type",
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/malformed.png",
                        "filename": "malformed.png",
                        "content_type": "image/png/extra",
                        "size": 512
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(media_type_malformed["accepted"], false);
    assert_eq!(
        media_type_malformed["reason_code"],
        "attachment_content_type_missing"
    );
    assert_eq!(
        media_type_malformed["policy"]["reason_code"],
        "attachment_content_type_missing"
    );
    assert_eq!(media_type_malformed["runtime"]["accepted_events"], 0);
    assert_eq!(media_type_malformed["runtime"]["queue_depth"], 0);
    log_projection_step(
        &mut logs,
        "media_content_type_malformed_drop",
        "ok",
        &media_type_malformed,
    );

    let media_url_denied = invoke_projection(
        &media_type_connector,
        &signing_key,
        &media_type_instance_id,
        "qq-gateway-media-url-denied",
        json!({
            "op": 0,
            "s": 3,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-media-url-denied",
            "d": {
                "id": "msg-media-url-denied",
                "content": "bot-openid unsafe media url",
                "group_openid": "group-media-type",
                "group_member_openid": "member-media-type",
                "attachments": [
                    {
                        "url": "https://user:secret@cdn.qq.example/private/credentialed.png",
                        "filename": "credentialed.png",
                        "content_type": "image/png",
                        "size": 512
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(media_url_denied["accepted"], false);
    assert_eq!(
        media_url_denied["reason_code"],
        "attachment_url_not_allowed"
    );
    assert_eq!(
        media_url_denied["policy"]["reason_code"],
        "attachment_url_not_allowed"
    );
    assert_eq!(media_url_denied["runtime"]["accepted_events"], 0);
    assert_eq!(media_url_denied["runtime"]["queue_depth"], 0);
    log_projection_step(&mut logs, "media_url_policy_drop", "ok", &media_url_denied);

    let media_type_allowed = invoke_projection(
        &media_type_connector,
        &signing_key,
        &media_type_instance_id,
        "qq-gateway-media-type-allowed",
        json!({
            "op": 0,
            "s": 4,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-media-type-allowed",
            "d": {
                "id": "msg-media-type-allowed",
                "content": "bot-openid allowed media type",
                "group_openid": "group-media-type",
                "group_member_openid": "member-media-type",
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/allowed.png",
                        "filename": "allowed.png",
                        "content_type": "image/png; charset=binary",
                        "size": 512
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(media_type_allowed["accepted"], true);
    assert_eq!(media_type_allowed["policy"]["reason_code"], "group_allowed");
    assert_eq!(media_type_allowed["normalized"]["has_attachments"], true);
    assert_eq!(media_type_allowed["runtime"]["accepted_events"], 1);
    assert_eq!(media_type_allowed["runtime"]["queue_depth"], 1);
    log_projection_step(
        &mut logs,
        "media_content_type_policy_allowed",
        "ok",
        &media_type_allowed,
    );

    let reply_media = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-reply-media",
        json!({
            "op": 0,
            "s": 7,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-reply-media",
            "d": {
                "id": "msg-reply-media",
                "content": "bot-openid see attached trace",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1",
                "message_reference": { "message_id": "msg-accepted" },
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/trace.png",
                        "filename": "trace.png",
                        "content_type": "image/png",
                        "size": 2048
                    }
                ],
                "author": { "id": "member-1", "username": "Alice" }
            }
        }),
    )
    .await;
    assert_eq!(reply_media["accepted"], true);
    assert_eq!(reply_media["topic"], "qq.message.authorized");
    assert_eq!(reply_media["normalized"]["is_reply"], true);
    assert_eq!(reply_media["normalized"]["reply_to"], "msg-accepted");
    assert_eq!(reply_media["normalized"]["has_attachments"], true);
    assert_eq!(reply_media["runtime"]["reply_reference_count"], 3);
    assert_eq!(reply_media["runtime"]["known_reply_references"], 1);
    assert_eq!(reply_media["runtime"]["unknown_reply_references"], 0);
    log_projection_step(&mut logs, "reply_media_projection", "ok", &reply_media);

    let voice_instance_id = InstanceId::new();
    let mut voice_connector = QqConnector::new();
    voice_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "group_policy": "open",
                    "group_require_mention": true,
                    "max_attachment_bytes": 4096
                }
            }
        }))
        .await
        .expect("configure voice QQ connector");
    voice_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            voice_instance_id.clone(),
        ))
        .await
        .expect("handshake voice QQ connector");
    let voice_asr = invoke_projection(
        &voice_connector,
        &signing_key,
        &voice_instance_id,
        "qq-gateway-voice-asr",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-voice-asr",
            "d": {
                "id": "msg-voice-asr",
                "content": "   ",
                "group_openid": "group-voice",
                "group_member_openid": "member-voice",
                "attachments": [
                    {
                        "url": "https://cdn.qq.example/private/voice.amr",
                        "filename": "voice.amr",
                        "content_type": "audio/amr",
                        "size": 1024,
                        "asr_refer_text": "bot-openid approve deployment from voice"
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(voice_asr["accepted"], true);
    assert_eq!(
        voice_asr["normalized"]["text"],
        "bot-openid approve deployment from voice"
    );
    assert_eq!(voice_asr["normalized"]["has_attachments"], true);
    assert_eq!(voice_asr["policy"]["reason_code"], "group_allowed");
    log_projection_step(&mut logs, "voice_asr_projection", "ok", &voice_asr);

    let slash_instance_id = InstanceId::new();
    let mut slash_connector = QqConnector::new();
    slash_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "policy": {
                    "group_policy": "allowlist",
                    "group_allow_from": ["group-slash"],
                    "group_require_mention": true,
                    "bot_user_id": "bot-openid"
                }
            }
        }))
        .await
        .expect("configure slash QQ connector");
    slash_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            slash_instance_id.clone(),
        ))
        .await
        .expect("handshake slash QQ connector");
    let slash_approval = invoke_projection(
        &slash_connector,
        &signing_key,
        &slash_instance_id,
        "qq-gateway-slash-approval",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-slash-approval",
            "d": {
                "id": "msg-slash-approval",
                "content": "/approve rollout-42",
                "group_openid": "group-slash",
                "group_member_openid": "member-slash"
            }
        }),
    )
    .await;
    assert_eq!(slash_approval["accepted"], true);
    assert_eq!(slash_approval["topic"], "qq.message.authorized");
    assert_eq!(slash_approval["normalized"]["interaction_kind"], "approval");
    assert_eq!(slash_approval["normalized"]["command_name"], "approve");
    assert_eq!(slash_approval["normalized"]["approval_action"], "approve");
    assert_eq!(slash_approval["policy"]["reason_code"], "group_allowed");
    log_projection_step(
        &mut logs,
        "slash_approval_projection",
        "ok",
        &slash_approval,
    );

    let duplicate = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-duplicate",
        json!({
            "op": 0,
            "s": 8,
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
    log_projection_step(&mut logs, "duplicate_drop", "ok", &duplicate);

    let stale_sequence = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-stale-sequence",
        json!({
            "op": 0,
            "s": 7,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-stale-sequence",
            "d": {
                "id": "msg-stale-sequence",
                "content": "bot-openid stale sequence should drop",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1"
            }
        }),
    )
    .await;
    assert_eq!(stale_sequence["accepted"], false);
    assert_eq!(stale_sequence["reason_code"], "stale_sequence");
    assert_eq!(stale_sequence["normalized"], Value::Null);
    assert_eq!(stale_sequence["policy"], Value::Null);
    assert_eq!(stale_sequence["runtime"]["stale_sequence_events"], 1);
    assert_eq!(stale_sequence["lifecycle"]["action"], "none");
    log_projection_step(
        &mut logs,
        "stale_sequence_replay_drop",
        "ok",
        &stale_sequence,
    );

    let unmatched_heartbeat_ack = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-unmatched-heartbeat-ack",
        json!({
            "op": 11
        }),
    )
    .await;
    assert_eq!(
        unmatched_heartbeat_ack["reason_code"],
        "heartbeat_ack_unmatched"
    );
    assert_eq!(
        unmatched_heartbeat_ack["runtime"]["heartbeat_sent_count"],
        0
    );
    assert_eq!(unmatched_heartbeat_ack["runtime"]["heartbeat_ack_count"], 0);
    assert_eq!(unmatched_heartbeat_ack["lifecycle"]["action"], "none");
    log_projection_step(
        &mut logs,
        "heartbeat_ack_unmatched",
        "ok",
        &unmatched_heartbeat_ack,
    );

    let heartbeat_request = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-heartbeat-request",
        json!({
            "op": 1
        }),
    )
    .await;
    assert_eq!(heartbeat_request["reason_code"], "heartbeat_request");
    assert_eq!(heartbeat_request["lifecycle"]["action"], "send_heartbeat");
    assert_eq!(heartbeat_request["lifecycle"]["resume_sequence"], 7);
    assert_eq!(heartbeat_request["runtime"]["heartbeat_sent_count"], 1);
    assert_eq!(heartbeat_request["runtime"]["heartbeat_ack_count"], 0);
    log_projection_step(&mut logs, "heartbeat_request", "ok", &heartbeat_request);

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
    assert_eq!(heartbeat["runtime"]["heartbeat_sent_count"], 1);
    assert_eq!(heartbeat["runtime"]["heartbeat_ack_count"], 1);
    assert_eq!(heartbeat["lifecycle"]["action"], "none");
    log_projection_step(&mut logs, "heartbeat_ack", "ok", &heartbeat);

    let reconnect = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-reconnect",
        json!({
            "op": 7,
            "id": "evt-reconnect-requested"
        }),
    )
    .await;
    assert_eq!(reconnect["accepted"], false);
    assert_eq!(reconnect["reason_code"], "reconnect_requested");
    assert_eq!(reconnect["runtime"]["reconnect_attempts"], 1);
    assert_eq!(reconnect["runtime"]["max_reconnect_backoff_ms"], 30000);
    assert_eq!(reconnect["lifecycle"]["action"], "reconnect_resume");
    assert_eq!(reconnect["lifecycle"]["resume_session_id"], "session-1");
    assert_eq!(reconnect["lifecycle"]["reconnect_after_ms"], 1000);
    log_projection_step(&mut logs, "reconnect_requested", "ok", &reconnect);

    let invalid_session = invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-invalid-session",
        json!({
            "op": 9,
            "id": "evt-invalid-session",
            "d": true
        }),
    )
    .await;
    assert_eq!(invalid_session["accepted"], false);
    assert_eq!(invalid_session["reason_code"], "invalid_session_resumable");
    assert_eq!(invalid_session["runtime"]["reconnect_attempts"], 2);
    assert_eq!(invalid_session["lifecycle"]["action"], "reconnect_resume");
    assert_eq!(invalid_session["lifecycle"]["reconnect_after_ms"], 2000);
    log_projection_step(
        &mut logs,
        "invalid_session_resumable",
        "ok",
        &invalid_session,
    );

    let restored_instance_id = InstanceId::new();
    let mut restored_connector = QqConnector::new();
    restored_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "restore_session_id": "restored-session",
                "restore_sequence": 44,
                "reconnect_backoff_ms": 125,
                "max_reconnect_backoff_ms": 500,
                "max_reconnect_attempts": 3,
                "policy": {
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure restored session QQ connector");
    restored_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            restored_instance_id.clone(),
        ))
        .await
        .expect("handshake restored session QQ connector");
    let restored_reconnect = invoke_projection(
        &restored_connector,
        &signing_key,
        &restored_instance_id,
        "qq-gateway-restored-reconnect",
        json!({
            "op": 7,
            "id": "evt-restored-reconnect"
        }),
    )
    .await;
    assert_eq!(restored_reconnect["accepted"], false);
    assert_eq!(restored_reconnect["reason_code"], "reconnect_requested");
    assert_eq!(
        restored_reconnect["lifecycle"]["action"],
        "reconnect_resume"
    );
    assert_eq!(
        restored_reconnect["lifecycle"]["resume_session_id"],
        "restored-session"
    );
    assert_eq!(restored_reconnect["lifecycle"]["resume_sequence"], 44);
    assert_eq!(restored_reconnect["lifecycle"]["reconnect_after_ms"], 125);
    assert_eq!(
        restored_reconnect["runtime"]["session_id"],
        "restored-session"
    );
    assert_eq!(restored_reconnect["runtime"]["last_sequence"], 44);
    assert_eq!(restored_reconnect["runtime"]["reconnect_attempts"], 1);
    log_projection_step(
        &mut logs,
        "restored_session_reconnect_resume",
        "ok",
        &restored_reconnect,
    );

    let ready_resumed_instance_id = InstanceId::new();
    let mut ready_resumed_connector = QqConnector::new();
    ready_resumed_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "reconnect_backoff_ms": 125,
                "max_reconnect_backoff_ms": 500,
                "policy": {
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure ready/resumed QQ connector");
    ready_resumed_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            ready_resumed_instance_id.clone(),
        ))
        .await
        .expect("handshake ready/resumed QQ connector");
    let ready_dispatch = invoke_projection(
        &ready_resumed_connector,
        &signing_key,
        &ready_resumed_instance_id,
        "qq-gateway-ready-dispatch",
        json!({
            "op": 0,
            "s": 1,
            "t": "READY",
            "id": "evt-ready-dispatch",
            "d": {
                "session_id": "session-ready-dispatch"
            }
        }),
    )
    .await;
    assert_eq!(ready_dispatch["accepted"], false);
    assert_eq!(ready_dispatch["reason_code"], "gateway_ready");
    assert_eq!(
        ready_dispatch["runtime"]["session_id"],
        "session-ready-dispatch"
    );
    assert_eq!(ready_dispatch["runtime"]["last_sequence"], 1);
    assert_eq!(ready_dispatch["runtime"]["reconnect_attempts"], 0);
    assert_eq!(ready_dispatch["runtime"]["dedupe_size"], 1);
    assert_eq!(ready_dispatch["lifecycle"]["action"], "none");
    log_projection_step(
        &mut logs,
        "ready_dispatch_session_persisted",
        "ok",
        &ready_dispatch,
    );

    let resumed_dispatch = invoke_projection(
        &ready_resumed_connector,
        &signing_key,
        &ready_resumed_instance_id,
        "qq-gateway-resumed-dispatch",
        json!({
            "op": 0,
            "s": 2,
            "t": "RESUMED",
            "id": "evt-resumed-dispatch",
            "d": {}
        }),
    )
    .await;
    assert_eq!(resumed_dispatch["accepted"], false);
    assert_eq!(resumed_dispatch["reason_code"], "gateway_resumed");
    assert_eq!(
        resumed_dispatch["runtime"]["session_id"],
        "session-ready-dispatch"
    );
    assert_eq!(resumed_dispatch["runtime"]["last_sequence"], 2);
    assert_eq!(resumed_dispatch["runtime"]["reconnect_attempts"], 0);
    assert_eq!(resumed_dispatch["runtime"]["dedupe_size"], 2);
    assert_eq!(resumed_dispatch["lifecycle"]["action"], "none");
    log_projection_step(
        &mut logs,
        "resumed_dispatch_replay_complete",
        "ok",
        &resumed_dispatch,
    );

    let identify_required_instance_id = InstanceId::new();
    let mut identify_required_connector = QqConnector::new();
    identify_required_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "restore_session_id": "session-identify-before",
                "restore_sequence": 12,
                "max_reconnect_attempts": 2,
                "reconnect_backoff_ms": 300,
                "max_reconnect_backoff_ms": 900
            }
        }))
        .await
        .expect("configure invalid-session identify QQ connector");
    identify_required_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            identify_required_instance_id.clone(),
        ))
        .await
        .expect("handshake invalid-session identify QQ connector");
    let identify_required = invoke_projection(
        &identify_required_connector,
        &signing_key,
        &identify_required_instance_id,
        "qq-gateway-invalid-session-identify-required",
        json!({
            "op": 9,
            "id": "evt-invalid-session-identify-required",
            "d": false
        }),
    )
    .await;
    assert_eq!(identify_required["accepted"], false);
    assert_eq!(
        identify_required["reason_code"],
        "invalid_session_identify_required"
    );
    assert_eq!(
        identify_required["lifecycle"]["action"],
        "reconnect_identify"
    );
    assert_eq!(
        identify_required["lifecycle"]["resume_session_id"],
        Value::Null
    );
    assert_eq!(identify_required["lifecycle"]["resume_sequence"], 12);
    assert_eq!(identify_required["lifecycle"]["reconnect_after_ms"], 300);
    assert_eq!(identify_required["runtime"]["reconnect_attempts"], 1);
    assert_eq!(
        identify_required["runtime"]["terminal_reconnect_failures"],
        0
    );
    log_projection_step(
        &mut logs,
        "invalid_session_identify_required",
        "ok",
        &identify_required,
    );

    let reconnect_cap_instance_id = InstanceId::new();
    let mut reconnect_cap_connector = QqConnector::new();
    reconnect_cap_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "max_reconnect_attempts": 2,
                "reconnect_backoff_ms": 250,
                "max_reconnect_backoff_ms": 300
            }
        }))
        .await
        .expect("configure reconnect cap QQ connector");
    reconnect_cap_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            reconnect_cap_instance_id.clone(),
        ))
        .await
        .expect("handshake reconnect cap QQ connector");
    let reconnect_cap_first = invoke_projection(
        &reconnect_cap_connector,
        &signing_key,
        &reconnect_cap_instance_id,
        "qq-gateway-reconnect-cap-first",
        json!({
            "op": 7,
            "id": "evt-reconnect-cap-first"
        }),
    )
    .await;
    assert_eq!(reconnect_cap_first["reason_code"], "reconnect_requested");
    assert_eq!(reconnect_cap_first["runtime"]["reconnect_attempts"], 1);
    assert_eq!(
        reconnect_cap_first["lifecycle"]["action"],
        "reconnect_identify"
    );
    assert_eq!(reconnect_cap_first["lifecycle"]["reconnect_after_ms"], 250);
    let reconnect_backoff_capped = invoke_projection(
        &reconnect_cap_connector,
        &signing_key,
        &reconnect_cap_instance_id,
        "qq-gateway-reconnect-backoff-capped",
        json!({
            "op": 7,
            "id": "evt-reconnect-cap-capped"
        }),
    )
    .await;
    assert_eq!(
        reconnect_backoff_capped["reason_code"],
        "reconnect_requested"
    );
    assert_eq!(reconnect_backoff_capped["runtime"]["reconnect_attempts"], 2);
    assert_eq!(
        reconnect_backoff_capped["runtime"]["max_reconnect_attempts"],
        2
    );
    assert_eq!(
        reconnect_backoff_capped["runtime"]["terminal_reconnect_failures"],
        0
    );
    assert_eq!(
        reconnect_backoff_capped["lifecycle"]["action"],
        "reconnect_identify"
    );
    assert_eq!(
        reconnect_backoff_capped["lifecycle"]["reconnect_after_ms"],
        300
    );
    log_projection_step(
        &mut logs,
        "reconnect_backoff_capped",
        "ok",
        &reconnect_backoff_capped,
    );
    let reconnect_exhausted = invoke_projection(
        &reconnect_cap_connector,
        &signing_key,
        &reconnect_cap_instance_id,
        "qq-gateway-reconnect-exhausted",
        json!({
            "op": 9,
            "id": "evt-reconnect-exhausted",
            "d": false
        }),
    )
    .await;
    assert_eq!(
        reconnect_exhausted["reason_code"],
        "reconnect_attempts_exhausted"
    );
    assert_eq!(reconnect_exhausted["runtime"]["reconnect_attempts"], 3);
    assert_eq!(reconnect_exhausted["runtime"]["max_reconnect_attempts"], 2);
    assert_eq!(
        reconnect_exhausted["runtime"]["terminal_reconnect_failures"],
        1
    );
    assert_eq!(reconnect_exhausted["runtime"]["reconnect_backoff_ms"], 250);
    assert_eq!(
        reconnect_exhausted["runtime"]["max_reconnect_backoff_ms"],
        300
    );
    assert_eq!(reconnect_exhausted["lifecycle"]["action"], "stop_reconnect");
    assert_eq!(
        reconnect_exhausted["lifecycle"]["reconnect_after_ms"],
        Value::Null
    );
    log_projection_step(
        &mut logs,
        "reconnect_attempts_exhausted",
        "ok",
        &reconnect_exhausted,
    );

    let hello_after_exhaustion = invoke_projection(
        &reconnect_cap_connector,
        &signing_key,
        &reconnect_cap_instance_id,
        "qq-gateway-hello-after-exhaustion",
        json!({
            "op": 10,
            "id": "evt-hello-after-exhaustion",
            "d": { "session_id": "session-after-exhaustion" }
        }),
    )
    .await;
    assert_eq!(hello_after_exhaustion["accepted"], false);
    assert_eq!(hello_after_exhaustion["reason_code"], "hello");
    assert_eq!(hello_after_exhaustion["runtime"]["reconnect_attempts"], 0);
    assert_eq!(
        hello_after_exhaustion["runtime"]["terminal_reconnect_failures"],
        1
    );
    assert_eq!(
        hello_after_exhaustion["runtime"]["session_id"],
        "session-after-exhaustion"
    );
    assert_eq!(hello_after_exhaustion["lifecycle"]["action"], "resume");
    assert_eq!(
        hello_after_exhaustion["lifecycle"]["resume_session_id"],
        "session-after-exhaustion"
    );
    assert_eq!(
        hello_after_exhaustion["lifecycle"]["reconnect_after_ms"],
        Value::Null
    );
    log_projection_step(
        &mut logs,
        "hello_after_reconnect_exhaustion",
        "ok",
        &hello_after_exhaustion,
    );

    let post_hello_reconnect = invoke_projection(
        &reconnect_cap_connector,
        &signing_key,
        &reconnect_cap_instance_id,
        "qq-gateway-post-hello-reconnect",
        json!({
            "op": 7,
            "id": "evt-post-hello-reconnect"
        }),
    )
    .await;
    assert_eq!(post_hello_reconnect["accepted"], false);
    assert_eq!(post_hello_reconnect["reason_code"], "reconnect_requested");
    assert_eq!(post_hello_reconnect["runtime"]["reconnect_attempts"], 1);
    assert_eq!(
        post_hello_reconnect["runtime"]["terminal_reconnect_failures"],
        1
    );
    assert_eq!(
        post_hello_reconnect["lifecycle"]["action"],
        "reconnect_resume"
    );
    assert_eq!(
        post_hello_reconnect["lifecycle"]["resume_session_id"],
        "session-after-exhaustion"
    );
    assert_eq!(post_hello_reconnect["lifecycle"]["reconnect_after_ms"], 250);
    log_projection_step(
        &mut logs,
        "post_hello_reconnect_resume",
        "ok",
        &post_hello_reconnect,
    );

    let first_drain = invoke_drain(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-drain-first",
        json!({"limit": 2}),
    )
    .await;
    assert_eq!(first_drain["drained_count"], 2);
    assert_eq!(first_drain["remaining_count"], 1);
    assert_eq!(first_drain["runtime"]["queue_depth"], 1);
    let first_drain_events = first_drain["events"]
        .as_array()
        .expect("first drain events array");
    assert_eq!(first_drain_events[0]["event_id"], "evt-accepted");
    assert_eq!(first_drain_events[1]["event_id"], "evt-structured-mention");
    assert_eq!(
        first_drain_events[0]["normalized"]["message_id"],
        "msg-accepted"
    );
    log_drain_step(&mut logs, "gateway_drain_first_batch", "ok", &first_drain);

    let final_drain = invoke_drain(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-drain-final",
        json!({}),
    )
    .await;
    assert_eq!(final_drain["drained_count"], 1);
    assert_eq!(final_drain["remaining_count"], 0);
    assert_eq!(final_drain["runtime"]["queue_depth"], 0);
    let final_drain_events = final_drain["events"]
        .as_array()
        .expect("final drain events array");
    assert_eq!(final_drain_events[0]["event_id"], "evt-reply-media");
    assert_eq!(
        final_drain_events[0]["normalized"]["reply_to"],
        "msg-accepted"
    );
    assert_eq!(final_drain["runtime"]["reply_reference_count"], 3);
    assert_eq!(final_drain["runtime"]["known_reply_references"], 1);
    log_drain_step(&mut logs, "gateway_drain_final_batch", "ok", &final_drain);

    let pending_shutdown_instance_id = InstanceId::new();
    let mut pending_shutdown_connector = QqConnector::new();
    pending_shutdown_connector
        .configure(json!({
            "base_url": "http://localhost:9999",
            "token_base_url": "http://localhost:9999",
            "app_id": "qq-app",
            "client_secret": "test-secret",
            "gateway": {
                "enabled": true,
                "max_queue_depth": 2,
                "policy": {
                    "group_policy": "open",
                    "group_require_mention": false
                }
            }
        }))
        .await
        .expect("configure pending-shutdown QQ connector");
    pending_shutdown_connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            pending_shutdown_instance_id.clone(),
        ))
        .await
        .expect("handshake pending-shutdown QQ connector");
    let pending_before_shutdown = invoke_projection(
        &pending_shutdown_connector,
        &signing_key,
        &pending_shutdown_instance_id,
        "qq-gateway-pending-before-shutdown",
        json!({
            "op": 0,
            "s": 1,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-pending-before-shutdown",
            "d": {
                "id": "msg-pending-before-shutdown",
                "content": "pending event must not orphan fan-out",
                "group_openid": "group-pending-shutdown",
                "group_member_openid": "member-pending-shutdown"
            }
        }),
    )
    .await;
    assert_eq!(pending_before_shutdown["accepted"], true);
    assert_eq!(pending_before_shutdown["runtime"]["queue_depth"], 1);
    assert_eq!(pending_before_shutdown["runtime"]["accepted_events"], 1);
    pending_shutdown_connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: false,
            reason: Some("qq-gateway-pending-drop-proof".into()),
        })
        .await
        .expect("shutdown pending-queue QQ connector");
    let pending_shutdown_health = pending_shutdown_connector.health().await;
    let pending_shutdown_status = format!("{:?}", pending_shutdown_health.status);
    let pending_shutdown_projection = try_invoke_projection(
        &pending_shutdown_connector,
        &signing_key,
        &pending_shutdown_instance_id,
        "qq-gateway-pending-after-shutdown-projection",
        json!({
            "op": 0,
            "s": 2,
            "t": "GROUP_MESSAGE_CREATE",
            "id": "evt-pending-after-shutdown",
            "d": {
                "id": "msg-pending-after-shutdown",
                "content": "after shutdown must not fan out",
                "group_openid": "group-pending-shutdown",
                "group_member_openid": "member-pending-shutdown"
            }
        }),
    )
    .await;
    let pending_shutdown_drain = try_invoke_drain(
        &pending_shutdown_connector,
        &signing_key,
        &pending_shutdown_instance_id,
        "qq-gateway-pending-after-shutdown-drain",
        json!({}),
    )
    .await;
    assert_eq!(pending_shutdown_status, "Starting");
    assert!(pending_shutdown_health.details.is_none());
    assert!(pending_shutdown_projection.is_err());
    assert!(pending_shutdown_drain.is_err());
    log_step(
        &mut logs,
        "shutdown_pending_queue_drop",
        "ok",
        &json!({
            "accepted_before_shutdown": true,
            "queued_before_shutdown": 1,
            "health_status": pending_shutdown_status,
            "gateway_runtime_present": pending_shutdown_health.details.is_some(),
            "project_after_shutdown_denied": pending_shutdown_projection.is_err(),
            "drain_after_shutdown_denied": pending_shutdown_drain.is_err(),
        }),
    );

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("qq-gateway-e2e-complete".into()),
        })
        .await
        .expect("shutdown QQ connector");
    let post_shutdown_health = connector.health().await;
    let post_shutdown_status = format!("{:?}", post_shutdown_health.status);
    assert_eq!(post_shutdown_status, "Starting");
    assert!(post_shutdown_health.details.is_none());
    let post_shutdown_projection = try_invoke_projection(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-after-shutdown-projection",
        json!({
            "op": 0,
            "s": 8,
            "t": "GROUP_AT_MESSAGE_CREATE",
            "id": "evt-after-shutdown",
            "d": {
                "id": "msg-after-shutdown",
                "content": "bot-openid after shutdown should deny",
                "group_openid": "group-allowed",
                "group_member_openid": "member-1"
            }
        }),
    )
    .await;
    let post_shutdown_drain = try_invoke_drain(
        &connector,
        &signing_key,
        &instance_id,
        "qq-gateway-after-shutdown-drain",
        json!({}),
    )
    .await;
    assert!(post_shutdown_projection.is_err());
    assert!(post_shutdown_drain.is_err());
    log_step(
        &mut logs,
        "shutdown",
        "ok",
        &json!({
            "health_status": post_shutdown_status,
            "gateway_runtime_present": post_shutdown_health.details.is_some(),
            "project_after_shutdown_denied": post_shutdown_projection.is_err(),
            "drain_after_shutdown_denied": post_shutdown_drain.is_err(),
        }),
    );

    let log_contents = read_to_string(&log_path).expect("read QQ gateway e2e log");
    let log_records = log_contents
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("QQ gateway log line is JSON"))
        .collect::<Vec<_>>();
    let log_start = log_records
        .iter()
        .find(|record| record.get("step").and_then(Value::as_str) == Some("log_start"))
        .expect("QQ gateway log_start record exists");
    let log_start_details = log_start
        .get("details")
        .and_then(Value::as_object)
        .expect("QQ gateway log_start details are an object");
    assert!(
        !log_start_details.contains_key("path"),
        "QQ gateway log_start must not include a raw artifact path"
    );
    assert!(
        !log_start_details.contains_key("command_line"),
        "QQ gateway log_start must not include raw command-line arguments"
    );
    assert_eq!(
        log_start_details
            .get("artifact_path_class")
            .and_then(Value::as_str),
        Some("temp_jsonl")
    );
    for field in ["artifact_path_hash", "command_line_hash"] {
        let hash = log_start_details
            .get(field)
            .and_then(Value::as_str)
            .expect("QQ gateway log_start hash field exists");
        assert!(
            hash.strip_prefix("sha256:").is_some_and(|digest| {
                digest.len() == 64 && digest.chars().all(|ch| ch.is_ascii_hexdigit())
            }),
            "QQ gateway log_start field `{field}` must be a full SHA-256 digest"
        );
    }
    assert!(
        log_start_details
            .get("command_arg_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0),
        "QQ gateway log_start must record a nonzero command arg count"
    );
    for forbidden in [
        "/Users/",
        "/home/",
        "/data/projects/",
        "/private/var/",
        "/var/folders/",
        "/Volumes/",
        "C:\\Users\\",
        "Bearer",
        "Authorization",
        "authorization",
        "access_token",
        "refresh_token",
        concat!("token", "="),
        "sk-live-",
        "AKIA",
        "-----BEGIN",
        "principal:",
        "provider_body",
        "test-secret",
        "session-1",
        "restored-session",
        "session-ready-dispatch",
        "session-should-not-stick",
        "session-after-exhaustion",
        "hello-1",
        "evt-accepted",
        "evt-untyped-message-id",
        "evt-structured-mention",
        "evt-reply-media",
        "evt-voice-asr",
        "evt-slash-approval",
        "evt-oversized-media",
        "evt-unknown-size-media",
        "evt-media-type-denied",
        "evt-media-url-denied",
        "evt-media-type-allowed",
        "evt-disabled",
        "evt-missing-binding",
        "evt-missing-message-id",
        "evt-missing-reply-target",
        "evt-channel-denied",
        "evt-channel-allowed",
        "evt-c2c-denied",
        "evt-c2c-allowed",
        "evt-queue-fill",
        "evt-queue-full-policy-denied",
        "evt-queue-full",
        "evt-peer-queue-first",
        "evt-peer-queue-full",
        "evt-peer-queue-other",
        "evt-stale-sequence",
        "evt-reconnect-requested",
        "evt-invalid-session",
        "evt-restored-reconnect",
        "evt-ready-dispatch",
        "evt-resumed-dispatch",
        "evt-reconnect-cap-first",
        "evt-reconnect-cap-capped",
        "evt-reconnect-exhausted",
        "evt-hello-after-exhaustion",
        "evt-post-hello-reconnect",
        "evt-after-shutdown",
        "msg-accepted",
        "msg-untyped-message-id",
        "msg-structured-mention",
        "msg-reply-media",
        "msg-voice-asr",
        "msg-slash-approval",
        "msg-oversized-media",
        "msg-unknown-size-media",
        "msg-media-type-denied",
        "msg-media-url-denied",
        "msg-media-type-allowed",
        "msg-disabled",
        "msg-missing-binding",
        "msg-missing-message-id",
        "msg-missing-reply-target",
        "msg-channel-denied",
        "msg-channel-allowed",
        "msg-c2c-denied",
        "msg-c2c-allowed",
        "msg-queue-fill",
        "msg-queue-full-policy-denied",
        "msg-queue-full",
        "msg-peer-queue-first",
        "msg-peer-queue-full",
        "msg-peer-queue-other",
        "msg-stale-sequence",
        "msg-after-shutdown",
        "bot-openid",
        "group-allowed",
        "group-slash",
        "group-disabled",
        "group-binding",
        "group-denied",
        "group-queue",
        "group-peer-a",
        "group-peer-b",
        "group-voice",
        "group-media-type",
        "channel-denied",
        "channel-allowed",
        "guild-denied",
        "sender-denied",
        "member-1",
        "member-slash",
        "member-disabled",
        "member-queue",
        "member-peer",
        "member-voice",
        "member-media-type",
        "member-c2c-denied",
        "member-c2c-allowed",
        "Alice",
        "gateway disabled should not authorize",
        "event missing sender binding",
        "event missing message id",
        "blank reply target",
        "c2c allowlist should deny",
        "c2c allowlist should authorize",
        "queue fill message",
        "queue should not hide denied sender policy",
        "queue backpressure message",
        "first peer queue message",
        "same peer should hit per-peer cap",
        "different peer should still drain later",
        "stale sequence should drop",
        "deploy status",
        "plain message",
        "not a mention segment",
        "please inspect this",
        "see attached trace",
        "too large",
        "missing size metadata",
        "blocked media type",
        "unsafe media url",
        "allowed media type",
        "after shutdown should deny",
        "approve deployment from voice",
        "/approve rollout-42",
        "rollout-42",
        "cdn.qq.example",
        "user:secret",
        "trace.png",
        "voice.amr",
        "oversized.bin",
        "missing-size.pdf",
        "disallowed.exe",
        "malformed.png",
        "credentialed.png",
        "allowed.png",
    ] {
        assert!(
            !log_contents.contains(forbidden),
            "QQ gateway e2e log leaked raw fixture value `{forbidden}`"
        );
    }
    assert!(log_contents.contains("message_id_hash"));
    assert!(log_contents.contains("reply_to_hash"));
    assert!(log_contents.contains("known_reply_references"));
    assert!(log_contents.contains("reply_reference_count"));
    assert!(log_contents.contains("interaction_kind"));
    assert!(log_contents.contains("command_name_hash"));
    assert!(log_contents.contains("approval_action"));
    assert!(log_contents.contains("slash_approval_projection"));
    assert!(log_contents.contains("attachment_count"));
    assert!(log_contents.contains("attachment_total_bytes"));
    assert!(log_contents.contains("attachment_filename_hashes"));
    assert!(log_contents.contains("attachment_url_hashes"));
    assert!(log_contents.contains("attachment_bytes_exceeded"));
    assert!(log_contents.contains("attachment_size_unknown"));
    assert!(log_contents.contains("attachment_content_type_not_allowed"));
    assert!(log_contents.contains("attachment_content_type_missing"));
    assert!(log_contents.contains("attachment_url_not_allowed"));
    assert!(log_contents.contains("media_url_policy_drop"));
    assert!(log_contents.contains("media_content_type_malformed_drop"));
    assert!(log_contents.contains("media_content_type_policy_allowed"));
    assert!(log_contents.contains("queue_full_policy_denied"));
    assert!(log_contents.contains("queue_full_backpressure_drop"));
    assert!(log_contents.contains("queue_full"));
    assert!(log_contents.contains("stale_sequence_replay_drop"));
    assert!(log_contents.contains("stale_sequence_events"));
    assert!(log_contents.contains("reconnect_requested"));
    assert!(log_contents.contains("invalid_session_resumable"));
    assert!(log_contents.contains("reconnect_backoff_capped"));
    assert!(log_contents.contains("reconnect_attempts_exhausted"));
    assert!(log_contents.contains("terminal_reconnect_failures"));
    assert!(log_contents.contains("shutdown_pending_queue_drop"));
}
