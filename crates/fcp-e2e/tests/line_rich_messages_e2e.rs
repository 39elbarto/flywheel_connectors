//! E2E LINE rich-message send-path proof.
//!
//! Exercises Template and Flex messages through the FCP invoke boundary against
//! a local HTTP server. The evidence log intentionally records message metadata
//! only; full message text, alt text, and Flex contents stay out of JSONL logs.

#![cfg(feature = "line")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{
    AssertionsSummary, E2eLogEntry, E2eReport, scan_log_jsonl, validate_log_entry_value,
};
use fcp_line::LineConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "line_test_token";
const OP_REPLY: &str = "line.messages.reply";

fn handshake_req(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("line.messages.write")],
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
        .capability_id("line.messages.write")
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_REPLY])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor accepted")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (LineConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = LineConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "channel_access_token": TOKEN,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 1_000
        }))
        .await
        .expect("configure LINE connector");
    connector
        .handshake(handshake_req(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .expect("handshake LINE connector");
    (connector, signing_key, instance_id)
}

fn invoke_req(
    message: &serde_json::Value,
    capability_token: CapabilityToken,
    suffix: &str,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("line-rich-message-{suffix}")),
        connector_id: ConnectorId::from_static("fcp.line"),
        operation: OperationId::from_static(OP_REPLY),
        zone_id: ZoneId::work(),
        input: json!({
            "reply_token": format!("reply-token-{suffix}"),
            "messages": [message.clone()]
        }),
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

fn log_entry(event: &str, message_type: &str, context: serde_json::Value) -> E2eLogEntry {
    E2eLogEntry::new(
        "info",
        "line_rich_messages",
        "fcp-e2e",
        "execute",
        "line-rich-message-e2e",
        "pass",
        0,
        AssertionsSummary::new(1, 0),
        json!({
            "event": event,
            "connector": "line",
            "op": OP_REPLY,
            "message_type": message_type,
            "evidence": context
        }),
    )
    .with_scenario_id("line.rich_messages.send")
}

fn message_metadata(message: &serde_json::Value) -> serde_json::Value {
    let message_type = message
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let alt_text = message
        .get("altText")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let action_count = match message
        .pointer("/template/type")
        .and_then(serde_json::Value::as_str)
    {
        Some("confirm") | Some("buttons") => message
            .pointer("/template/actions")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len),
        Some("carousel") => message
            .pointer("/template/columns")
            .and_then(serde_json::Value::as_array)
            .map(|columns| {
                columns
                    .iter()
                    .filter_map(|column| {
                        column.get("actions").and_then(serde_json::Value::as_array)
                    })
                    .map(Vec::len)
                    .sum::<usize>()
            })
            .unwrap_or(0),
        Some("image_carousel") => message
            .pointer("/template/columns")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len),
        _ => 0,
    };

    json!({
        "alt_text_len": alt_text.chars().count(),
        "action_count": action_count,
        "flex_contents_logged": false,
        "full_text_logged": false,
        "template_type": message.pointer("/template/type"),
        "wire_type": message_type
    })
}

fn rich_messages() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    vec![
        (
            "confirm",
            "template",
            json!({
                "type": "template",
                "altText": "Confirm deployment",
                "template": {
                    "type": "confirm",
                    "text": "Deploy now?",
                    "actions": [
                        { "type": "message", "label": "Yes", "text": "deploy yes" },
                        { "type": "postback", "label": "No", "data": "deploy=no", "displayText": "No" }
                    ]
                }
            }),
        ),
        (
            "buttons",
            "template",
            json!({
                "type": "template",
                "altText": "Open menu",
                "template": {
                    "type": "buttons",
                    "title": "Menu",
                    "text": "Pick one",
                    "actions": [
                        { "type": "message", "label": "A", "text": "a" },
                        { "type": "uri", "label": "Docs", "uri": "https://example.com/docs" }
                    ]
                }
            }),
        ),
        (
            "carousel",
            "template",
            json!({
                "type": "template",
                "altText": "Carousel options",
                "template": {
                    "type": "carousel",
                    "columns": [{
                        "text": "First option",
                        "actions": [{ "type": "message", "label": "Pick", "text": "pick first" }]
                    }]
                }
            }),
        ),
        (
            "image_carousel",
            "template",
            json!({
                "type": "template",
                "altText": "Image options",
                "template": {
                    "type": "image_carousel",
                    "columns": [{
                        "imageUrl": "https://example.com/image.png",
                        "action": { "type": "uri", "label": "Open", "uri": "line://app/123" }
                    }]
                }
            }),
        ),
        (
            "flex",
            "flex",
            json!({
                "type": "flex",
                "altText": "Status card",
                "contents": {
                    "type": "bubble",
                    "body": {
                        "type": "box",
                        "layout": "vertical",
                        "contents": [{ "type": "text", "text": "Ready" }]
                    }
                }
            }),
        ),
    ]
}

#[fcp_async_core::runtime::test]
async fn line_rich_messages_emit_redacted_jsonl_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/reply"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let mut logs = Vec::new();

    for (suffix, message_type, message) in rich_messages() {
        logs.push(log_entry(
            "message_built",
            message_type,
            message_metadata(&message),
        ));
        let response = connector
            .invoke(invoke_req(
                &message,
                build_token(&signing_key, &instance_id),
                suffix,
            ))
            .await
            .expect("rich message invoke succeeds");
        assert_eq!(response.status, InvokeStatus::Ok);
        logs.push(log_entry(
            "reply_dispatched",
            message_type,
            json!({
                "http_status": 200,
                "sent_message_count": 1,
                "alt_text_len": message["altText"]
                    .as_str()
                    .map(|value| value.chars().count())
                    .unwrap_or(0)
            }),
        ));
        logs.push(log_entry(
            "audit_receipt",
            message_type,
            json!({
                "receipt_id": format!("line-rich-message-{suffix}"),
                "kind": "connector_send",
                "message_body_logged": false,
                "flex_contents_logged": false
            }),
        ));
    }

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 5);
    let wire_types = requests
        .iter()
        .map(|request| {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("request body JSON");
            body["messages"][0]["type"]
                .as_str()
                .expect("message type")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        wire_types,
        vec!["template", "template", "template", "template", "flex"]
    );

    let report = E2eReport {
        test_name: "line_rich_messages".into(),
        passed: true,
        duration_ms: 0,
        logs,
    };
    let jsonl = report.to_stable_json_lines();
    assert!(!jsonl.trim().is_empty());
    assert!(!jsonl.contains("Confirm deployment"));
    assert!(!jsonl.contains("Deploy now?"));
    assert!(!jsonl.contains("Ready"));
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("jsonl line");
        validate_log_entry_value(&value).expect("jsonl schema");
    }
    assert_eq!(scan_log_jsonl(&jsonl).error_count, 0);
}
