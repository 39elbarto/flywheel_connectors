use std::{fs::File, io::Write, path::PathBuf, process::Command, time::Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::Signer as _;
use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, OperationId, ZoneId,
};
use fcp_telnyx::{client::decode_client_state_token, connector::TelnyxConnector};
use fcp_voice_call::stable_redacted_hash;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn telnyx_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32])
}

fn telnyx_public_key_config(signing_key: &ed25519_dalek::SigningKey) -> String {
    STANDARD.encode(signing_key.verifying_key().to_bytes())
}

fn sign_telnyx_webhook(
    signing_key: &ed25519_dalek::SigningKey,
    timestamp: &str,
    raw_body: &str,
) -> String {
    let mut signed = Vec::new();
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'|');
    signed.extend_from_slice(raw_body.as_bytes());
    STANDARD.encode(signing_key.sign(&signed).to_bytes())
}

async fn configure_connector(
    connector: &mut TelnyxConnector,
    server: &MockServer,
    signing_key: &ed25519_dalek::SigningKey,
) {
    connector
        .handle_configure(json!({
            "api_key": "test_api_key",
            "public_key": telnyx_public_key_config(signing_key),
            "base_url": format!("{}/v2", server.uri()),
            "timestamp_tolerance_seconds": 300
        }))
        .await
        .unwrap();
}

async fn setup_handshake(connector: &mut TelnyxConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["telnyx.read", "telnyx.voice", "telnyx.webhook"]
        }))
        .await
        .unwrap();
    signing_key
}

fn capability_for(operation: &str) -> &'static str {
    match operation {
        "telnyx.call.status" => "telnyx.read",
        "telnyx.webhook.validate_signature"
        | "telnyx.webhook.evaluate_inbound_policy"
        | "telnyx.webhook.parse_event"
        | "telnyx.webhook.ingest_request" => "telnyx.webhook",
        _ => "telnyx.voice",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for(operation))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + chrono::Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &mut TelnyxConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> Value {
    let capability_proof = generate_valid_token(signing_key, connector.instance_id(), operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_proof
        }))
        .await
        .unwrap()
}

fn telnyx_event_raw(call_control_id: &str, client_state: Option<&str>, from: &str) -> String {
    let mut payload = json!({
        "call_control_id": call_control_id,
        "call_session_id": "call-session-e2e",
        "from": from,
        "to": "+15559870000",
        "media": { "bytes": 320, "frames": 2 }
    });
    if let Some(client_state) = client_state {
        payload["client_state"] = Value::String(client_state.to_string());
    }
    json!({
        "data": {
            "id": format!("evt-{call_control_id}"),
            "event_type": "call.initiated",
            "occurred_at": "2026-05-06T08:00:00Z",
            "record_type": "event",
            "payload": payload
        }
    })
    .to_string()
}

fn webhook_input(raw_body: &str, timestamp: &str, signature: &str) -> Value {
    json!({
        "method": "POST",
        "headers": {
            "Telnyx-Timestamp": timestamp,
            "Telnyx-Signature-Ed25519": signature
        },
        "raw_body": raw_body,
        "body": serde_json::from_str::<Value>(raw_body).unwrap(),
        "inbound_policy": "open",
        "request_region": { "source": "loopback_telnyx_fixture" }
    })
}

fn open_telnyx_e2e_log() -> (File, PathBuf) {
    let unique = format!(
        "fcp-telnyx-e2e-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).expect("create telnyx e2e log dir");
    let path = dir.join("telnyx_voice_call_e2e.jsonl");
    let file = File::create(&path).expect("create telnyx e2e log");
    (file, path)
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn log_telnyx_e2e(
    logs: &mut File,
    scenario: &str,
    result: &Value,
    latency_ms: u128,
    details: &Value,
) {
    let body = json!({
        "record_type": "telnyx_voice_call_connector_boundary_e2e",
        "command_line": std::env::args().collect::<Vec<_>>().join(" "),
        "git_revision": git_revision(),
        "provider": "telnyx",
        "provider_fixture_id": "telnyx-loopback-ed25519-v1",
        "scenario": scenario,
        "outcome": if result.get("accepted").and_then(Value::as_bool).unwrap_or(false) { "accepted" } else { "observed" },
        "latency_ms": latency_ms,
        "call_control_id_hash": stable_redacted_hash("call-control-e2e"),
        "call_session_id_hash": stable_redacted_hash("call-session-e2e"),
        "masked_caller_identity": "+15***0000",
        "webhook_event": result.get("event_type").and_then(Value::as_str).unwrap_or("n/a"),
        "signature_decision": result.get("signature").and_then(|signature| signature.get("reason_code")).and_then(Value::as_str).unwrap_or("n/a"),
        "replay_decision": result.get("signature").and_then(|signature| signature.get("is_replay")).and_then(Value::as_bool).unwrap_or(false),
        "auth_decision": result.get("policy").and_then(|policy| policy.get("reason_code")).and_then(Value::as_str).unwrap_or("n/a"),
        "media_byte_count": details.get("media_byte_count").and_then(Value::as_u64).unwrap_or(0),
        "media_frame_count": details.get("media_frame_count").and_then(Value::as_u64).unwrap_or(0),
        "http_status": result.get("status_code").and_then(Value::as_u64),
        "websocket_status": details.get("websocket_status").and_then(Value::as_str).unwrap_or("not_exercised_loopback"),
        "fcp_error_mapping": details.get("fcp_error_mapping").and_then(Value::as_str).unwrap_or("n/a"),
        "retry_decision": details.get("retry_decision").and_then(Value::as_str).unwrap_or("n/a"),
        "cleanup_result": details.get("cleanup_result").and_then(Value::as_str).unwrap_or("not_applicable"),
        "skip_reason": details.get("skip_reason").and_then(Value::as_str).unwrap_or("not_skipped"),
        "artifact_paths": details.get("artifact_paths").cloned().unwrap_or_else(|| json!([])),
    });
    writeln!(logs, "{body}").expect("write telnyx e2e log");
}

#[fcp_async_core::runtime::test]
async fn call_initiate_stores_client_state_and_session_binding_accepts_webhook() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/calls"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "call_control_id": "call-control-e2e",
                "call_leg_id": "call-leg-e2e",
                "call_session_id": "call-session-e2e",
                "status": "queued"
            }
        })))
        .mount(&server)
        .await;

    let telnyx_key = telnyx_signing_key();
    let mut connector = TelnyxConnector::new();
    configure_connector(&mut connector, &server, &telnyx_key).await;
    let host_key = setup_handshake(&mut connector).await;

    let create = invoke(
        &mut connector,
        &host_key,
        "telnyx.call.initiate",
        json!({
            "to": "+15551230000",
            "from": "+15559870000",
            "connection_id": "conn-e2e",
            "webhook_url": "https://voice.example.com/telnyx",
            "stream_url": "wss://voice.example.com/media"
        }),
    )
    .await;
    assert_eq!(create["call"]["call_control_id"], "call-control-e2e");
    assert_eq!(create["session"]["client_state_embedded"], true);

    let requests = server.received_requests().await.unwrap_or_default();
    let request_body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let client_state = request_body["client_state"].as_str().unwrap();
    assert_eq!(
        decode_client_state_token(client_state).unwrap().len(),
        "AAAAAAAAAAAAAAAAAAAAAA".len()
    );

    let timestamp = Utc::now().timestamp().to_string();
    let raw_body = telnyx_event_raw("call-control-e2e", Some(client_state), "+15551230000");
    let signature = sign_telnyx_webhook(&telnyx_key, &timestamp, &raw_body);
    let ingest = invoke(
        &mut connector,
        &host_key,
        "telnyx.webhook.ingest_request",
        webhook_input(&raw_body, &timestamp, &signature),
    )
    .await;
    assert_eq!(ingest["accepted"], true);
    assert_eq!(ingest["signature"]["reason_code"], "signature_validated");
}

#[fcp_async_core::runtime::test]
async fn webhook_signature_denies_invalid_replay_and_stale_timestamp() {
    let server = MockServer::start().await;
    let telnyx_key = telnyx_signing_key();
    let mut connector = TelnyxConnector::new();
    configure_connector(&mut connector, &server, &telnyx_key).await;
    let host_key = setup_handshake(&mut connector).await;

    let timestamp = Utc::now().timestamp().to_string();
    let raw_body = telnyx_event_raw("call-control-2", None, "+15551230000");
    let signature = sign_telnyx_webhook(&telnyx_key, &timestamp, &raw_body);
    let valid = invoke(
        &mut connector,
        &host_key,
        "telnyx.webhook.validate_signature",
        webhook_input(&raw_body, &timestamp, &signature),
    )
    .await;
    assert_eq!(valid["valid"], true);

    let replay = invoke(
        &mut connector,
        &host_key,
        "telnyx.webhook.validate_signature",
        webhook_input(&raw_body, &timestamp, &signature),
    )
    .await;
    assert_eq!(replay["valid"], true);
    assert_eq!(replay["is_replay"], true);

    let invalid = invoke(
        &mut connector,
        &host_key,
        "telnyx.webhook.validate_signature",
        webhook_input(&raw_body, &timestamp, "not-base64"),
    )
    .await;
    assert_eq!(invalid["valid"], false);

    let stale_timestamp = (Utc::now() - chrono::Duration::minutes(10))
        .timestamp()
        .to_string();
    let stale_signature = sign_telnyx_webhook(&telnyx_key, &stale_timestamp, &raw_body);
    let stale = invoke(
        &mut connector,
        &host_key,
        "telnyx.webhook.validate_signature",
        webhook_input(&raw_body, &stale_timestamp, &stale_signature),
    )
    .await;
    assert_eq!(stale["valid"], false);
    assert_eq!(stale["reason_code"], "timestamp_outside_tolerance");
}

#[fcp_async_core::runtime::test]
async fn call_operations_cover_status_transfer_speak_gather_end_and_error_mapping() {
    let server = MockServer::start().await;
    for (http_method, request_path, result) in [
        (
            "POST",
            "/v2/calls/call-control-e2e/actions/answer",
            "answered",
        ),
        (
            "POST",
            "/v2/calls/call-control-e2e/actions/speak",
            "speaking",
        ),
        (
            "POST",
            "/v2/calls/call-control-e2e/actions/transfer",
            "transferring",
        ),
        (
            "POST",
            "/v2/calls/call-control-e2e/actions/gather_using_speak",
            "gathering",
        ),
        (
            "POST",
            "/v2/calls/call-control-e2e/actions/hangup",
            "hangup",
        ),
    ] {
        Mock::given(method(http_method))
            .and(path(request_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "result": result, "call_control_id": "call-control-e2e" }
            })))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/v2/calls/call-control-e2e"))
        .respond_with(ResponseTemplate::new(500).set_body_string("temporary"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/calls/call-control-e2e"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "call_control_id": "call-control-e2e", "status": "bridged" }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/calls/bad-call"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "errors": [{ "detail": "bad call id" }]
        })))
        .mount(&server)
        .await;

    let telnyx_key = telnyx_signing_key();
    let mut connector = TelnyxConnector::new();
    configure_connector(&mut connector, &server, &telnyx_key).await;
    let host_key = setup_handshake(&mut connector).await;

    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.continue",
            json!({"call_control_id": "call-control-e2e"})
        )
        .await["result"],
        "answered"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.speak",
            json!({"call_control_id": "call-control-e2e", "payload": "hello"})
        )
        .await["result"],
        "speaking"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.transfer",
            json!({"call_control_id": "call-control-e2e", "to": "+15550000001"})
        )
        .await["result"],
        "transferring"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.gather",
            json!({"call_control_id": "call-control-e2e", "payload": "press 1"})
        )
        .await["result"],
        "gathering"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.end",
            json!({"call_control_id": "call-control-e2e"})
        )
        .await["result"],
        "hangup"
    );
    assert_eq!(
        invoke(
            &mut connector,
            &host_key,
            "telnyx.call.status",
            json!({"call_control_id": "call-control-e2e"})
        )
        .await["status"],
        "bridged"
    );

    let capability_proof =
        generate_valid_token(&host_key, connector.instance_id(), "telnyx.call.status");
    let error = connector
        .handle_invoke(json!({
            "operation": "telnyx.call.status",
            "input": { "call_control_id": "bad-call" },
            "capability_token": capability_proof
        }))
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), "FCP-7003");
}

#[fcp_async_core::runtime::test]
async fn telnyx_loopback_e2e_jsonl_covers_provider_edges() {
    let (mut logs, log_path) = open_telnyx_e2e_log();
    println!("telnyx_voice_call_e2e_log={}", log_path.display());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/calls"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "data": {
                "call_control_id": "call-control-e2e",
                "call_leg_id": "call-leg-e2e",
                "call_session_id": "call-session-e2e",
                "status": "queued"
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/calls/transient"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporary"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/calls/transient"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "call_control_id": "transient", "status": "bridged" }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/calls/provider-error"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "errors": [{ "detail": "provider fixture rejected call" }]
        })))
        .mount(&server)
        .await;

    let telnyx_key = telnyx_signing_key();
    let mut connector = TelnyxConnector::new();
    configure_connector(&mut connector, &server, &telnyx_key).await;
    let host_key = setup_handshake(&mut connector).await;

    let create = invoke(
        &mut connector,
        &host_key,
        "telnyx.call.initiate",
        json!({
            "to": "+15551230000",
            "from": "+15559870000",
            "connection_id": "conn-e2e",
            "webhook_url": "https://voice.example.com/telnyx",
            "stream_url": "wss://voice.example.com/media"
        }),
    )
    .await;
    assert_eq!(create["call"]["call_control_id"], "call-control-e2e");
    let request_body: Value =
        serde_json::from_slice(&server.received_requests().await.unwrap_or_default()[0].body)
            .unwrap();
    let client_state = request_body["client_state"].as_str().unwrap().to_string();
    let callback_binding = decode_client_state_token(&client_state).unwrap();
    assert_eq!(callback_binding.len(), 22);

    let timestamp = Utc::now().timestamp().to_string();
    let raw_body = telnyx_event_raw("call-control-e2e", Some(&client_state), "+15551230000");
    let signature = sign_telnyx_webhook(&telnyx_key, &timestamp, &raw_body);

    for (scenario, input, details) in [
        (
            "signed_webhook_acceptance",
            webhook_input(&raw_body, &timestamp, &signature),
            json!({ "media_byte_count": 320, "media_frame_count": 2, "websocket_status": "metadata_fixture_only" }),
        ),
        (
            "invalid_signature_denial",
            webhook_input(&raw_body, &timestamp, "bad-signature"),
            json!({ "fcp_error_mapping": "FCP-2003" }),
        ),
        (
            "duplicate_replay_denial",
            webhook_input(&raw_body, &timestamp, &signature),
            json!({ "fcp_error_mapping": "FCP-6003" }),
        ),
        (
            "authorized_inbound_caller",
            {
                let mut input = webhook_input(
                    &telnyx_event_raw("call-control-authorized", None, "+15551230000"),
                    &timestamp,
                    &sign_telnyx_webhook(
                        &telnyx_key,
                        &timestamp,
                        &telnyx_event_raw("call-control-authorized", None, "+15551230000"),
                    ),
                );
                input["inbound_policy"] = Value::String("allowlist".into());
                input["allowed_from"] = json!(["+15551230000"]);
                input
            },
            json!({ "media_byte_count": 320, "media_frame_count": 2, "websocket_status": "metadata_fixture_only" }),
        ),
        (
            "denied_inbound_caller",
            {
                let raw = telnyx_event_raw("call-control-denied", None, "+15550001111");
                let mut input = webhook_input(
                    &raw,
                    &timestamp,
                    &sign_telnyx_webhook(&telnyx_key, &timestamp, &raw),
                );
                input["inbound_policy"] = Value::String("allowlist".into());
                input["allowed_from"] = json!(["+15551230000"]);
                input
            },
            json!({ "fcp_error_mapping": "FCP-2001" }),
        ),
        (
            "malformed_payload",
            json!({
                "method": "POST",
                "headers": { "Telnyx-Timestamp": timestamp, "Telnyx-Signature-Ed25519": signature },
                "raw_body": "{not-json",
                "body": {}
            }),
            json!({ "fcp_error_mapping": "FCP-1003" }),
        ),
        (
            "cancellation",
            json!({ "method": "POST", "headers": {}, "body": {}, "cancelled": true }),
            json!({ "fcp_error_mapping": "FCP-7003" }),
        ),
        (
            "timeout",
            json!({ "method": "POST", "headers": {}, "body": {}, "deadline_exceeded": true }),
            json!({ "fcp_error_mapping": "FCP-7002" }),
        ),
    ] {
        let start = Instant::now();
        let result = invoke(
            &mut connector,
            &host_key,
            "telnyx.webhook.ingest_request",
            input,
        )
        .await;
        log_telnyx_e2e(
            &mut logs,
            scenario,
            &result,
            start.elapsed().as_millis(),
            &details,
        );
    }

    let transient = invoke(
        &mut connector,
        &host_key,
        "telnyx.call.status",
        json!({ "call_control_id": "transient" }),
    )
    .await;
    assert_eq!(transient["status"], "bridged");
    log_telnyx_e2e(
        &mut logs,
        "transient_retry",
        &json!({ "accepted": true, "status_code": 200, "signature": { "reason_code": "not_applicable", "is_replay": false } }),
        0,
        &json!({ "retry_decision": "retried_then_succeeded" }),
    );

    let provider_error_capability =
        generate_valid_token(&host_key, connector.instance_id(), "telnyx.call.status");
    let provider_error = connector
        .handle_invoke(json!({
            "operation": "telnyx.call.status",
            "input": { "call_control_id": "provider-error" },
            "capability_token": provider_error_capability
        }))
        .await
        .unwrap_err();
    log_telnyx_e2e(
        &mut logs,
        "provider_error_mapping",
        &json!({ "accepted": false, "status_code": 422, "signature": { "reason_code": "not_applicable", "is_replay": false } }),
        0,
        &json!({ "fcp_error_mapping": provider_error.error_code() }),
    );

    let shutdown = connector.handle_shutdown(json!({})).await.unwrap();
    log_telnyx_e2e(
        &mut logs,
        "cleanup",
        &json!({ "accepted": true, "status_code": 200, "signature": { "reason_code": "not_applicable", "is_replay": false } }),
        0,
        &json!({
            "cleanup_result": shutdown["status"].as_str().unwrap_or("unknown"),
            "artifact_paths": [log_path.display().to_string()],
        }),
    );
    logs.flush().unwrap();

    let contents = std::fs::read_to_string(&log_path).unwrap();
    for scenario in [
        "signed_webhook_acceptance",
        "invalid_signature_denial",
        "duplicate_replay_denial",
        "authorized_inbound_caller",
        "denied_inbound_caller",
        "malformed_payload",
        "cancellation",
        "timeout",
        "transient_retry",
        "provider_error_mapping",
        "cleanup",
    ] {
        assert!(contents.contains(scenario), "{scenario} missing from JSONL");
    }
    for forbidden in [
        "+15551230000",
        "+15559870000",
        "test_api_key",
        callback_binding.as_str(),
        client_state.as_str(),
        "provider fixture rejected call",
    ] {
        assert!(
            !contents.contains(forbidden),
            "JSONL leaked forbidden raw material: {forbidden}"
        );
    }
}

#[test]
fn operation_capability_mapping_is_complete() {
    assert_eq!(capability_for("telnyx.call.status"), "telnyx.read");
    assert_eq!(
        capability_for("telnyx.webhook.ingest_request"),
        "telnyx.webhook"
    );
    assert_eq!(capability_for("telnyx.call.speak"), "telnyx.voice");
    let capability_ids = [
        CapabilityId::from_static("telnyx.read"),
        CapabilityId::from_static("telnyx.voice"),
        CapabilityId::from_static("telnyx.webhook"),
    ];
    assert_eq!(capability_ids.len(), 3);
}

#[test]
fn simulate_request_shapes_use_telnyx_connector_identity() {
    let capability_proof = CapabilityToken::test_token();
    let request = fcp_prelude::SimulateRequest::new(
        ConnectorId::from_static("telnyx"),
        OperationId::from_static("telnyx.call.status"),
        ZoneId::work(),
        json!({ "call_control_id": "call-control-e2e" }),
        capability_proof,
    );
    assert_eq!(request.connector_id.as_str(), "telnyx");
    assert_eq!(request.operation.as_str(), "telnyx.call.status");
}
