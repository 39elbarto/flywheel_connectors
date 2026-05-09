#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cbc::{
    Encryptor, cipher::BlockEncryptMut, cipher::KeyIvInit, cipher::block_padding::NoPadding,
};
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, OperationId, RequestId, ShutdownRequest, ZoneId,
};
use fcp_wecom::WeComConnector;
use serde_json::{Value, json};
use sha1::{Digest as _, Sha1};

type Aes256CbcEnc = Encryptor<Aes256>;

const OP_VERIFY_CALLBACK_URL: &str = "wecom.callback.verify_url";
const OP_INGEST_CALLBACK_EVENT: &str = "wecom.callback.ingest_event";
const CAP_EVENTS_READ: &str = "wecom.events.read";

const fn sample_callback_key_bytes() -> [u8; 32] {
    [7_u8; 32]
}

fn sample_callback_key() -> String {
    BASE64
        .encode(sample_callback_key_bytes())
        .trim_end_matches('=')
        .to_string()
}

fn encrypt_callback_message(message: &str, receive_id: &str) -> String {
    let key = sample_callback_key_bytes();
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(b"0123456789ABCDEF");
    let message_len = u32::try_from(message.len()).expect("test fixture should fit u32");
    plaintext.extend_from_slice(&message_len.to_be_bytes());
    plaintext.extend_from_slice(message.as_bytes());
    plaintext.extend_from_slice(receive_id.as_bytes());

    let pad_len = 32 - (plaintext.len() % 32);
    let pad_byte = u8::try_from(pad_len).expect("pad length fits u8");
    plaintext.extend(std::iter::repeat_n(pad_byte, pad_len));
    let padded_len = plaintext.len();
    let iv = key.get(..16).expect("sample key has IV prefix");
    let ciphertext = Aes256CbcEnc::new_from_slices(&key, iv)
        .expect("valid callback key")
        .encrypt_padded_mut::<NoPadding>(&mut plaintext, padded_len)
        .expect("test encryption should succeed");

    BASE64.encode(ciphertext)
}

fn callback_signature(encrypted: &str, timestamp: &str, nonce: &str) -> String {
    let mut parts = vec!["token-123", timestamp, nonce, encrypted];
    parts.sort_unstable();
    let mut material = String::new();
    for part in parts {
        material.push_str(part);
    }
    hex::encode(Sha1::digest(material.as_bytes()))
}

fn test_constraints_cbor() -> Vec<u8> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    cbor
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_EVENTS_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&test_constraints_cbor())
        .expect("test constraints cbor should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(raw)
}

fn handshake_request(
    host_public_key: [u8; 32],
    requested_instance_id: InstanceId,
    zone_dir: &Path,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: Some(zone_dir.to_string_lossy().into_owned()),
        host_public_key,
        nonce: [23_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_EVENTS_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(requested_instance_id),
    }
}

fn callback_body(encrypted: &str) -> String {
    format!(
        "<xml><ToUserName><![CDATA[corp]]></ToUserName><AgentID><![CDATA[1000002]]></AgentID><Encrypt><![CDATA[{encrypted}]]></Encrypt></xml>"
    )
}

fn callback_input(plaintext: &str, timestamp: &str, nonce: &str) -> Value {
    let encrypted = encrypt_callback_message(plaintext, "corp");
    json!({
        "msg_signature": callback_signature(&encrypted, timestamp, nonce),
        "timestamp": timestamp,
        "nonce": nonce,
        "body": callback_body(&encrypted),
    })
}

fn invoke_request(
    operation: &'static str,
    input: Value,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &str,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.wecom"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: capability_token(signing_key, operation, instance_id),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn log_event(path: &Path, event: &Value) {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("e2e log should be writable");
    writeln!(file, "{event}").expect("e2e log line should be writable");
}

#[test]
fn wecom_manifest_ai_hints_cover_all_operations() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
    let manifest_text = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let manifest: toml::Value = toml::from_str(&manifest_text).expect("manifest should parse");
    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should declare operations");

    let expected_operations = [
        "messages_send_text",
        "messages_send_markdown",
        "messages_send_image",
        "messages_send_file",
        "media_upload",
        "media_download",
        "users_get",
        "departments_list",
        "callback_verify_url",
        "callback_ingest_event",
        "health",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let actual_operations = operations.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        actual_operations, expected_operations,
        "manifest operation inventory changed; update ai_hints coverage expectations"
    );

    let mut missing_when_to_use = Vec::new();
    let mut missing_common_mistakes = Vec::new();
    let mut missing_examples = Vec::new();
    let mut invalid_examples = Vec::new();
    let mut secret_shaped_examples = Vec::new();

    for (operation_id, operation) in operations {
        let Some(ai_hints) = operation.get("ai_hints").and_then(toml::Value::as_table) else {
            missing_when_to_use.push(operation_id.clone());
            missing_common_mistakes.push(operation_id.clone());
            missing_examples.push(operation_id.clone());
            continue;
        };

        let when_to_use = ai_hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .trim();
        if when_to_use.is_empty() {
            missing_when_to_use.push(operation_id.clone());
        }

        let common_mistakes = ai_hints
            .get("common_mistakes")
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if common_mistakes.is_empty()
            || common_mistakes
                .iter()
                .any(|mistake| mistake.as_str().unwrap_or_default().trim().is_empty())
        {
            missing_common_mistakes.push(operation_id.clone());
        }

        let examples = ai_hints
            .get("examples")
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if examples.is_empty() {
            missing_examples.push(operation_id.clone());
            continue;
        }

        for example in examples {
            let Some(example_text) = example.as_str().map(str::trim) else {
                invalid_examples.push(format!("{operation_id}: example is not a string"));
                continue;
            };
            if example_text.is_empty() {
                invalid_examples.push(format!("{operation_id}: example is empty"));
                continue;
            }
            if let Err(error) = serde_json::from_str::<Value>(example_text) {
                invalid_examples.push(format!("{operation_id}: {error}"));
            }

            let lower = example_text.to_ascii_lowercase();
            if ["api_key", "bearer", "password", "secret", "token"]
                .iter()
                .any(|needle| lower.contains(needle))
            {
                secret_shaped_examples.push(operation_id.clone());
            }
        }
    }

    assert!(
        missing_when_to_use.is_empty(),
        "operations missing ai_hints.when_to_use: {missing_when_to_use:?}"
    );
    assert!(
        missing_common_mistakes.is_empty(),
        "operations missing concrete common_mistakes: {missing_common_mistakes:?}"
    );
    assert!(
        missing_examples.is_empty(),
        "operations missing realistic examples: {missing_examples:?}"
    );
    assert!(
        invalid_examples.is_empty(),
        "operations have invalid JSON examples: {invalid_examples:?}"
    );
    assert!(
        secret_shaped_examples.is_empty(),
        "examples contain secret-shaped values or labels: {secret_shaped_examples:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn host_forwarded_callback_replay_policy_and_logging_e2e() {
    let artifact_dir = std::env::temp_dir().join(format!(
        "fcp-wecom-host-forwarded-callback-e2e-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir_all(&artifact_dir).expect("artifact dir should be creatable");
    let log_path = artifact_dir.join("wecom_callback_e2e.jsonl");

    let mut connector = WeComConnector::new();
    connector
        .configure(json!({
            "base_url": "https://qyapi.weixin.qq.com",
            "corp_id": "corp",
            "agent_id": 1_000_002_u64,
            "agent_secret": "secret",
            "callback_token": "token-123",
            "callback_encoding_aes_key": sample_callback_key(),
            "callback_allowed_user_ids": ["alice"],
            "callback_allowed_room_ids": ["room-1"],
            "callback_require_room_mention": true,
            "callback_mention_patterns": ["@opsbot"],
            "callback_timestamp_skew_secs": 600,
            "callback_replay_window_secs": 600,
        }))
        .await
        .expect("configure should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
            artifact_dir.as_path(),
        ))
        .await
        .expect("handshake should succeed");

    let timestamp = Utc::now().timestamp().to_string();
    let challenge = encrypt_callback_message("verify-challenge", "corp");
    let verify = connector
        .invoke(invoke_request(
            OP_VERIFY_CALLBACK_URL,
            json!({
                "msg_signature": callback_signature(&challenge, &timestamp, "nonce-verify"),
                "timestamp": timestamp,
                "nonce": "nonce-verify",
                "echostr": challenge,
            }),
            &signing_key,
            &instance_id,
            "verify-url",
        ))
        .await
        .expect("verify_url should succeed");
    log_event(
        &log_path,
        &json!({
            "scenario": "verify_url",
            "operation": OP_VERIFY_CALLBACK_URL,
            "result": "ok",
            "http_status": verify.result.as_ref().expect("result")["http_response"]["status"],
            "redaction_status": "challenge_returned_only_to_host_forwarder",
        }),
    );

    let accepted_plaintext = r"<xml><ToUserName><![CDATA[corp]]></ToUserName><FromUserName><![CDATA[alice]]></FromUserName><CreateTime>1710000000</CreateTime><MsgType><![CDATA[text]]></MsgType><OpenChatId><![CDATA[room-1]]></OpenChatId><Content><![CDATA[@opsbot hello]]></Content><MsgId>msg-1</MsgId></xml>";
    let accepted_input = callback_input(
        accepted_plaintext,
        &Utc::now().timestamp().to_string(),
        "nonce-ok",
    );
    let accepted = connector
        .invoke(invoke_request(
            OP_INGEST_CALLBACK_EVENT,
            accepted_input.clone(),
            &signing_key,
            &instance_id,
            "accepted-callback",
        ))
        .await
        .expect("accepted callback should succeed");
    let accepted_result = accepted.result.as_ref().expect("result");
    log_event(
        &log_path,
        &json!({
            "scenario": "accepted_callback",
            "operation": OP_INGEST_CALLBACK_EVENT,
            "delivery_id": accepted_result["delivery"]["id"],
            "policy_decision": accepted_result["policy"]["decision"],
            "event_topic": accepted_result["event"]["topic"],
            "result": "ok",
            "redaction_status": accepted_result["policy"]["redaction_status"],
        }),
    );
    assert_eq!(accepted_result["policy"]["decision"], "accepted");
    assert_eq!(accepted_result["event"]["topic"], "wecom.message.text");

    let replay = connector
        .invoke(invoke_request(
            OP_INGEST_CALLBACK_EVENT,
            accepted_input,
            &signing_key,
            &instance_id,
            "replay-callback",
        ))
        .await
        .expect("duplicate callback should be acknowledged as duplicate");
    let replay_result = replay.result.as_ref().expect("result");
    log_event(
        &log_path,
        &json!({
            "scenario": "replay_callback",
            "operation": OP_INGEST_CALLBACK_EVENT,
            "policy_decision": replay_result["policy"]["decision"],
            "reason": replay_result["policy"]["reason"],
            "event_emitted": !replay_result["event"].is_null(),
            "result": "ok",
            "redaction_status": replay_result["policy"]["redaction_status"],
        }),
    );
    assert_eq!(replay_result["policy"]["decision"], "duplicate");
    assert!(replay_result["event"].is_null());

    let disallowed_plaintext = r"<xml><ToUserName><![CDATA[corp]]></ToUserName><FromUserName><![CDATA[bob]]></FromUserName><CreateTime>1710000001</CreateTime><MsgType><![CDATA[text]]></MsgType><OpenChatId><![CDATA[room-1]]></OpenChatId><Content><![CDATA[@opsbot hello]]></Content><MsgId>msg-2</MsgId></xml>";
    let disallowed = connector
        .invoke(invoke_request(
            OP_INGEST_CALLBACK_EVENT,
            callback_input(
                disallowed_plaintext,
                &Utc::now().timestamp().to_string(),
                "nonce-disallowed",
            ),
            &signing_key,
            &instance_id,
            "disallowed-callback",
        ))
        .await
        .expect("disallowed sender should return a policy drop");
    let disallowed_result = disallowed.result.as_ref().expect("result");
    log_event(
        &log_path,
        &json!({
            "scenario": "disallowed_sender",
            "operation": OP_INGEST_CALLBACK_EVENT,
            "policy_decision": disallowed_result["policy"]["decision"],
            "reason": disallowed_result["policy"]["reason"],
            "event_emitted": !disallowed_result["event"].is_null(),
            "result": "ok",
            "redaction_status": disallowed_result["policy"]["redaction_status"],
        }),
    );
    assert_eq!(disallowed_result["policy"]["decision"], "rejected");
    assert!(disallowed_result["event"].is_null());

    let bad_signature = connector
        .invoke(invoke_request(
            OP_INGEST_CALLBACK_EVENT,
            json!({
                "msg_signature": "bad",
                "timestamp": Utc::now().timestamp().to_string(),
                "nonce": "nonce-bad",
                "body": callback_body(&encrypt_callback_message(accepted_plaintext, "corp")),
            }),
            &signing_key,
            &instance_id,
            "bad-signature",
        ))
        .await
        .expect_err("bad signature should fail before policy");
    log_event(
        &log_path,
        &json!({
            "scenario": "bad_signature",
            "operation": OP_INGEST_CALLBACK_EVENT,
            "result": "error",
            "error": bad_signature.to_string(),
            "redaction_status": "no_plaintext_or_signature_logged",
        }),
    );

    let malformed_xml = connector
        .invoke(invoke_request(
            OP_INGEST_CALLBACK_EVENT,
            json!({
                "msg_signature": "unused",
                "timestamp": Utc::now().timestamp().to_string(),
                "nonce": "nonce-malformed",
                "body": "<xml><Encrypt>",
            }),
            &signing_key,
            &instance_id,
            "malformed-xml",
        ))
        .await
        .expect_err("malformed XML should fail");
    log_event(
        &log_path,
        &json!({
            "scenario": "malformed_xml",
            "operation": OP_INGEST_CALLBACK_EVENT,
            "result": "error",
            "error": malformed_xml.to_string(),
            "redaction_status": "malformed_body_not_logged",
        }),
    );

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            reason: Some("e2e clean shutdown".into()),
            deadline_ms: 1_000,
            drain: true,
        })
        .await
        .expect("shutdown should be clean");
    log_event(
        &log_path,
        &json!({
            "scenario": "clean_shutdown",
            "operation": "shutdown",
            "result": "ok",
            "artifact": log_path.display().to_string(),
            "redaction_status": "jsonl_contains_hashes_and_policy_enums_only",
        }),
    );

    let log_contents = fs::read_to_string(&log_path).expect("jsonl log should exist");
    assert!(log_contents.contains("accepted_callback"));
    assert!(log_contents.contains("replay_callback"));
    assert!(log_contents.contains("bad_signature"));
    assert!(
        artifact_dir
            .join("wecom_callback_replay_state.json")
            .exists()
    );
}
