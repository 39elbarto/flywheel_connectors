#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::str::FromStr as _;
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_apple_notes::AppleNotesConnector;
use fcp_apple_notes::client::AppleNotesClient;
use fcp_apple_notes::types::AppleNotesConfig;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, HealthState, InstanceId, InvokeRequest, OperationId, RequestId,
    ShutdownRequest, SimulateRequest, SubscribeRequest, UnsubscribeRequest, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const CONNECTOR_ID: &str = "fcp.apple-notes";
const OP_HEALTH: &str = "apple_notes.health";
const OP_LIST_NOTES: &str = "apple_notes.list_notes";
const OP_SEARCH_NOTES: &str = "apple_notes.search_notes";
const OP_CREATE_NOTE: &str = "apple_notes.create_note";

const CAP_READ: &str = "apple_notes.read";
const CAP_WRITE: &str = "apple_notes.write";

const NOTE_ID: &str = "x-coredata://private-note-id";
const NOTE_TITLE: &str = "Private planning note";
const NOTE_BODY: &str = "body containing user-private note text";
const FOLDER_NAME: &str = "Project Plans";

#[fcp_async_core::runtime::test]
async fn lifecycle_health_simulate_shutdown_and_jsonl_logging() {
    let instance_id = make_instance_id("lifecycle");
    let (mut connector, signing_key) = configure_and_handshake(&instance_id).await;

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));
    let doctor = serde_json::to_value(connector.doctor()).expect("doctor should serialize");
    assert!(
        doctor["checks"]
            .as_array()
            .expect("doctor checks should be an array")
            .iter()
            .any(|check| check["name"] == "platform")
    );

    let started_at = Instant::now();
    let output = connector
        .invoke(invoke_request(
            connector.id(),
            OP_HEALTH,
            &ZoneId::private(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_HEALTH,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect("health invoke should succeed without touching Notes.app")
        .result
        .expect("health invoke should include output");
    assert_eq!(output["status"], "ok");
    assert_eq!(output["platform"], std::env::consts::OS);
    assert!(
        output["manifest_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:"))
    );

    let simulation = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_HEALTH),
            ZoneId::private(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_HEALTH,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect("health simulation should be policy-evaluable");
    assert!(simulation.would_succeed);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("apple-notes lifecycle test complete".into()),
        })
        .await
        .expect("shutdown should clear connector state");

    emit_proof_log(&ProofLog {
        event: "lifecycle_health",
        operation: OP_HEALTH,
        capability: CAP_READ,
        zone: ZoneId::private().as_str(),
        instance_id: instance_id.as_str(),
        platform: std::env::consts::OS,
        fixture_id: "apple-notes-health-no-live-state-v1",
        note_id_hash: None,
        folder_id_hash: None,
        lifecycle_phase: "configure-handshake-health-simulate-shutdown",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        audit_receipt_id: "not-issued:connector-local-health",
        cleanup_result: "no-live-state-created",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn capability_zone_instance_and_missing_instance_denials_are_explicit() {
    let instance_id = make_instance_id("denials");
    let (connector, signing_key) = configure_and_handshake(&instance_id).await;

    let wrong_zone = connector
        .invoke(invoke_request(
            connector.id(),
            OP_HEALTH,
            &ZoneId::private(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_HEALTH,
                CAP_READ,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("wrong-zone token should fail before any Notes.app access");
    assert!(matches!(
        wrong_zone,
        FcpError::ZoneViolation { message, .. }
            if message.contains("Token audience mismatch") || message.contains("Token zone mismatch")
    ));

    let wrong_instance = connector
        .invoke(invoke_request(
            connector.id(),
            OP_HEALTH,
            &ZoneId::private(),
            json!({}),
            valid_token(
                &signing_key,
                &make_instance_id("other"),
                OP_HEALTH,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect_err("wrong-instance token should fail before any Notes.app access");
    assert!(matches!(
        wrong_instance,
        FcpError::ZoneViolation { message, .. } if message.contains("Token instance mismatch")
    ));

    let missing_instance = connector
        .invoke(invoke_request(
            connector.id(),
            OP_HEALTH,
            &ZoneId::private(),
            json!({}),
            token_without_instance(&signing_key, OP_HEALTH, CAP_READ, &ZoneId::private()),
        ))
        .await
        .expect_err("missing-instance token should fail before any Notes.app access");
    assert!(matches!(
        missing_instance,
        FcpError::MissingField { field } if field.contains("instance_id")
    ));
}

#[fcp_async_core::runtime::test]
async fn malformed_inputs_streaming_denials_and_platform_skip_are_mapped() {
    let instance_id = make_instance_id("errors");
    let (connector, signing_key) = configure_and_handshake(&instance_id).await;

    let unknown = connector
        .invoke(invoke_request(
            connector.id(),
            "apple_notes.unknown",
            &ZoneId::private(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_HEALTH,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect_err("unknown operation should be rejected");
    assert!(matches!(
        unknown,
        FcpError::InvalidRequest { code: 1004, .. }
    ));

    let missing_query = connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEARCH_NOTES,
            &ZoneId::private(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEARCH_NOTES,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect_err("missing query should be rejected before subprocess access");
    assert!(matches!(
        missing_query,
        FcpError::InvalidRequest { code: 1005, .. }
    ));

    let empty_query = connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEARCH_NOTES,
            &ZoneId::private(),
            json!({ "query": "   " }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEARCH_NOTES,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect_err("empty query should be rejected before subprocess access");
    assert!(matches!(
        empty_query,
        FcpError::InvalidRequest { code: 1003, .. }
    ));

    let missing_title = connector
        .invoke(invoke_request(
            connector.id(),
            OP_CREATE_NOTE,
            &ZoneId::private(),
            json!({ "body": NOTE_BODY }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_CREATE_NOTE,
                CAP_WRITE,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect_err("missing title should be rejected before subprocess access");
    assert!(matches!(
        missing_title,
        FcpError::InvalidRequest { code: 1005, .. }
    ));

    let subscribe_error = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("apple-notes-subscribe"),
            topics: vec!["apple_notes.changed".into()],
            since: None,
            max_events_per_sec: Some(10),
            batch_ms: Some(100),
            window_size: Some(16),
            capability_token: Some(valid_token(
                &signing_key,
                &instance_id,
                OP_LIST_NOTES,
                CAP_READ,
                &ZoneId::private(),
            )),
        })
        .await
        .expect_err("Apple Notes should not advertise streaming");
    assert!(matches!(subscribe_error, FcpError::StreamingNotSupported));

    let unsubscribe_error = connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("apple-notes-unsubscribe"),
            topics: vec!["apple_notes.changed".into()],
            capability_token: Some(valid_token(
                &signing_key,
                &instance_id,
                OP_LIST_NOTES,
                CAP_READ,
                &ZoneId::private(),
            )),
        })
        .await
        .expect_err("Apple Notes should not advertise streaming");
    assert!(matches!(unsubscribe_error, FcpError::StreamingNotSupported));

    let started_at = Instant::now();
    if std::env::consts::OS == "macos" {
        emit_proof_log(&ProofLog {
            event: "local_osascript_live_fixture",
            operation: OP_LIST_NOTES,
            capability: CAP_READ,
            zone: ZoneId::private().as_str(),
            instance_id: instance_id.as_str(),
            platform: std::env::consts::OS,
            fixture_id: "apple-notes-live-automation-required-v1",
            note_id_hash: None,
            folder_id_hash: None,
            lifecycle_phase: "structured-live-skip",
            latency_ms: elapsed_ms(started_at),
            result: "skip",
            error_code: None,
            audit_receipt_id: "not-issued:live-fixture-not-requested",
            cleanup_result: "no-live-state-created",
            skip_reason: Some(
                "live Notes permission/app-unavailable/timeout coverage requires explicit operator-gated fixture",
            ),
        });
    } else {
        let unsupported = connector
            .invoke(invoke_request(
                connector.id(),
                OP_LIST_NOTES,
                &ZoneId::private(),
                json!({}),
                valid_token(
                    &signing_key,
                    &instance_id,
                    OP_LIST_NOTES,
                    CAP_READ,
                    &ZoneId::private(),
                ),
            ))
            .await
            .expect_err("non-macOS should fail closed before osascript launch");
        assert!(matches!(
            unsupported,
            FcpError::ConnectorUnavailable { code: 5001, .. }
        ));
        emit_proof_log(&ProofLog {
            event: "local_osascript_platform_skip",
            operation: OP_LIST_NOTES,
            capability: CAP_READ,
            zone: ZoneId::private().as_str(),
            instance_id: instance_id.as_str(),
            platform: std::env::consts::OS,
            fixture_id: "apple-notes-non-macos-unsupported-v1",
            note_id_hash: None,
            folder_id_hash: None,
            lifecycle_phase: "invoke-list-notes",
            latency_ms: elapsed_ms(started_at),
            result: "skip",
            error_code: Some("FCP-5001"),
            audit_receipt_id: "not-issued:unsupported-platform",
            cleanup_result: "no-live-state-created",
            skip_reason: Some("unsupported platform"),
        });
    }
}

#[test]
fn local_bridge_invocation_shapes_keep_user_values_as_argv_and_logs_redacted_hashes() {
    let client = AppleNotesClient::from_config(&AppleNotesConfig {
        default_folder: Some(FOLDER_NAME.into()),
        osascript_path: "/usr/bin/osascript".into(),
        subprocess_timeout_secs: 30,
    })
    .expect("canonical Apple Notes config should build a client");

    let invocation = client.create_note_invocation(NOTE_TITLE, NOTE_BODY, None);
    assert_eq!(invocation.args, [NOTE_TITLE, NOTE_BODY, FOLDER_NAME]);
    assert!(
        !invocation.script.contains(NOTE_TITLE),
        "static AppleScript must not interpolate the title"
    );
    assert!(
        !invocation.script.contains(NOTE_BODY),
        "static AppleScript must not interpolate the body"
    );
    assert!(
        !invocation.script.contains(FOLDER_NAME),
        "static AppleScript must not interpolate the folder"
    );
    assert_eq!(client.list_notes_invocation(None).args, [FOLDER_NAME]);
    assert_eq!(client.get_note_invocation(NOTE_ID).args, [NOTE_ID]);

    emit_proof_log(&ProofLog {
        event: "local_bridge_argv_shape",
        operation: OP_CREATE_NOTE,
        capability: CAP_WRITE,
        zone: ZoneId::private().as_str(),
        instance_id: "not-handshaken:argv-shape",
        platform: std::env::consts::OS,
        fixture_id: "apple-notes-static-script-argv-v1",
        note_id_hash: Some(&hash_private_value(NOTE_ID)),
        folder_id_hash: Some(&hash_private_value(FOLDER_NAME)),
        lifecycle_phase: "construct-invocation-no-subprocess",
        latency_ms: 0,
        result: "ok",
        error_code: None,
        audit_receipt_id: "not-issued:argv-shape",
        cleanup_result: "no-live-state-created",
        skip_reason: None,
    });
}

async fn configure_and_handshake(
    instance_id: &InstanceId,
) -> (AppleNotesConnector, Ed25519SigningKey) {
    let mut connector = AppleNotesConnector::new();
    assert!(
        !matches!(connector.health().await.status, HealthState::Ready),
        "connector must not start ready before configure"
    );
    connector
        .configure(json!({ "subprocess_timeout_secs": 1 }))
        .await
        .expect("Apple Notes connector should accept deterministic local config");
    let signing_key = Ed25519SigningKey::generate();
    let response = connector
        .handshake(handshake_request(&signing_key, instance_id))
        .await
        .expect("handshake should accept deterministic requested instance id");
    assert_eq!(response.status, "accepted");
    assert!(
        response
            .capabilities_granted
            .iter()
            .any(|grant| grant.capability.as_str() == CAP_READ)
    );
    (connector, signing_key)
}

fn handshake_request(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::private(),
        zone_dir: None,
        host_public_key: signing_key.verifying_key().to_bytes(),
        nonce: [11; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn invoke_request(
    connector_id: &ConnectorId,
    operation: &'static str,
    zone_id: &ZoneId,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("req_{operation}")),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(operation),
        zone_id: zone_id.clone(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: Some(format!("idem_{operation}")),
        lease_seq: None,
        deadline_ms: Some(5_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &'static str,
    capability: &'static str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id.as_str())
        .principal("user:apple-notes-test")
        .operations(&[operation])
        .issuer("node:apple-notes-test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn token_without_instance(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id.as_str())
        .principal("user:apple-notes-test")
        .operations(&[operation])
        .issuer("node:apple-notes-test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn make_instance_id(suffix: &str) -> InstanceId {
    InstanceId::from_str(&format!("inst_apple_notes_{suffix}"))
        .expect("test instance id should be canonical")
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

fn hash_private_value(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::from("sha256:");
    for byte in digest.iter().take(8) {
        write!(&mut out, "{byte:02x}").expect("writing to string should not fail");
    }
    out
}

struct ProofLog<'a> {
    event: &'a str,
    operation: &'a str,
    capability: &'a str,
    zone: &'a str,
    instance_id: &'a str,
    platform: &'a str,
    fixture_id: &'a str,
    note_id_hash: Option<&'a str>,
    folder_id_hash: Option<&'a str>,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    audit_receipt_id: &'a str,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

fn emit_proof_log(proof: &ProofLog<'_>) {
    let line = serde_json::to_string(&json!({
        "command_line": "cargo test -p fcp-apple-notes --tests -- --nocapture",
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "event": proof.event,
        "op_id": proof.operation,
        "capability": proof.capability,
        "zone": proof.zone,
        "instance_id": proof.instance_id,
        "platform": proof.platform,
        "fixture_id": proof.fixture_id,
        "note_id_hash": proof.note_id_hash,
        "folder_id_hash": proof.folder_id_hash,
        "lifecycle_phase": proof.lifecycle_phase,
        "latency_ms": proof.latency_ms,
        "result": proof.result,
        "error_code": proof.error_code,
        "audit_receipt_id": proof.audit_receipt_id,
        "cleanup_result": proof.cleanup_result,
        "skip_reason": proof.skip_reason,
        "pii_redaction": {
            "note_titles": "omitted",
            "note_bodies": "omitted",
            "account_names": "omitted",
            "script_source_with_user_data": "not_generated",
            "local_paths": "omitted",
            "credentials": "omitted"
        }
    }))
    .expect("proof log should serialize");
    assert_redacted(&line);
    println!("APPLE_NOTES_E2E_JSONL {line}");
}

fn assert_redacted(line: &str) {
    for forbidden in [
        NOTE_ID,
        NOTE_TITLE,
        NOTE_BODY,
        FOLDER_NAME,
        "/Users/",
        "/tmp/",
        "osascript_path",
        "password",
        "secret",
        "token",
    ] {
        assert!(
            !line.contains(forbidden),
            "proof log leaked forbidden value: {forbidden}"
        );
    }
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |value| value.trim().to_string())
}
