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
    env,
    net::TcpListener,
    process::Command,
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityToken, ConnectorId, FcpError, InstanceId, OperationId,
    RequestId, SimulateRequest, ZoneId,
};
use fcp_whisper::connector::WhisperConnector;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const CONNECTOR_ID: &str = "whisper";
const CONNECTOR_MANIFEST_ID: &str = "fcp.whisper";
const BEAD_ID: &str = "flywheel_connectors-4kw5f.11.14";
const FIXTURE_API_KEY: &str = "sk-whisper-fixture-secret";
const FIXTURE_AUDIO_BASE64: &str = "UklGRgAAAAAA";
const FIXTURE_AUDIO_URL: &str = "https://audio-fixture.invalid/private/speech.wav";
const SECRET_TRANSCRIPT: &str = "secret transcript body";
const PROVIDER_BODY_SENTINEL: &str = "provider raw error body";
const TRANSCRIBE_OP: &str = "whisper.transcribe";
const TRANSLATE_OP: &str = "whisper.translate";
const DETECT_LANGUAGE_OP: &str = "whisper.detect_language";
const VERBOSE_OP: &str = "whisper.transcribe_verbose";
const LIST_MODELS_OP: &str = "whisper.list_models";
const HEALTH_OP: &str = "whisper.health";
const USAGE_OP: &str = "whisper.usage";
const FORMATS_OP: &str = "whisper.formats";
const TRANSCRIPTION_CAP: &str = "whisper.transcription";
const TRANSLATION_CAP: &str = "whisper.translation";
const INFO_CAP: &str = "whisper.info";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhisperEvidenceLog {
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
    audio_fixture_hash: String,
    model_id: String,
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
    audio_fixture: &str,
    model_id: &str,
    lifecycle_phase: &str,
    latency_ms: u64,
    result: &str,
    error_code: Option<String>,
    cleanup_result: &str,
    skip_reason: Option<&str>,
) -> WhisperEvidenceLog {
    WhisperEvidenceLog {
        schema_version: "whisper_connector_local_evidence.v1".to_string(),
        bead_id: BEAD_ID.to_string(),
        command_line: "cargo test -p fcp-whisper --test integration".to_string(),
        git_revision: git_revision(),
        connector_id: CONNECTOR_MANIFEST_ID.to_string(),
        operation_id: operation_id.to_string(),
        capability: capability.to_string(),
        zone: "z:work".to_string(),
        instance_id: stable_hash("whisper-loopback-instance"),
        fixture_id: "whisper-speech-loopback-fixture.v1".to_string(),
        audio_fixture_hash: stable_hash(audio_fixture),
        model_id: model_id.to_string(),
        lifecycle_phase: lifecycle_phase.to_string(),
        latency_ms,
        result: result.to_string(),
        error_code,
        audit_receipt_id: format!("audit:{BEAD_ID}:{operation_id}"),
        cleanup_result: cleanup_result.to_string(),
        skip_reason: skip_reason.map(str::to_string),
        redaction: "audio_bytes_transcripts_speakers_api_keys_provider_bodies_paths_not_logged"
            .to_string(),
    }
}

fn assert_log_shape_and_redaction(logs: &[WhisperEvidenceLog]) {
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
            "audio_fixture_hash",
            "model_id",
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
        FIXTURE_API_KEY,
        FIXTURE_AUDIO_BASE64,
        FIXTURE_AUDIO_URL,
        SECRET_TRANSCRIPT,
        PROVIDER_BODY_SENTINEL,
        "speaker-one",
        "alice@example.com",
        "/Users/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
}

fn config(base_url: &str, request_timeout_ms: Option<u64>) -> Value {
    let mut config = json!({
        "api_key": FIXTURE_API_KEY,
        "base_url": base_url,
    });
    if let Some(timeout) = request_timeout_ms {
        config["request_timeout_ms"] = json!(timeout);
    }
    config
}

async fn configure_and_handshake(
    connector: &mut WhisperConnector,
    signing_key: &Ed25519SigningKey,
    base_url: &str,
    request_timeout_ms: Option<u64>,
) {
    connector
        .handle_configure(config(base_url, request_timeout_ms))
        .await
        .expect("configure should accept loopback base URL");
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [TRANSCRIPTION_CAP, TRANSLATION_CAP, INFO_CAP],
        }))
        .await
        .expect("handshake should complete");
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    target_instance: Option<&str>,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor");
    if let Some(instance) = target_instance {
        builder = builder.target_instance(instance);
    }
    CapabilityToken::from_raw(builder.sign(signing_key).expect("sign token"))
}

fn simulate_request_json(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
    zone: &str,
    target_instance: Option<&str>,
) -> Value {
    serde_json::to_value(SimulateRequest {
        r#type: "simulate".into(),
        id: RequestId::new(format!("sim-{operation}")),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::new(operation).expect("valid operation id"),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: capability_token(
            signing_key,
            capability,
            operation,
            zone,
            target_instance,
        ),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    })
    .expect("serialize simulate request")
}

fn unused_loopback_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused loopback port");
    let addr = listener.local_addr().expect("unused loopback address");
    drop(listener);
    format!("http://{addr}/v1")
}

fn openai_api_error(message: &str) -> Value {
    json!({
        "error": {
            "message": message,
            "type": "provider_error",
            "code": "provider_error"
        }
    })
}

async fn configured_connector(base_url: &str, request_timeout_ms: Option<u64>) -> WhisperConnector {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = WhisperConnector::new();
    configure_and_handshake(&mut connector, &signing_key, base_url, request_timeout_ms).await;
    connector
}

fn assert_external_error(error: &FcpError, status: Option<u16>, retryable: bool) {
    match error {
        FcpError::External {
            service,
            status_code,
            retryable: actual_retryable,
            ..
        } => {
            assert_eq!(service, "whisper");
            assert_eq!(*status_code, status);
            assert_eq!(*actual_retryable, retryable);
        }
        other => {
            assert!(
                matches!(other, FcpError::External { .. }),
                "expected external error, got {other:?}"
            );
        }
    }
}

#[fcp_async_core::runtime::test]
async fn connector_lifecycle_uses_api_key_fixture_without_leaking_secret() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = WhisperConnector::new();

    let before = connector
        .handle_health()
        .await
        .expect("health before config");
    assert_eq!(before["status"], "unconfigured");

    configure_and_handshake(&mut connector, &signing_key, "http://127.0.0.1:1/v1", None).await;
    let health = connector
        .handle_health()
        .await
        .expect("health after config");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["requests"], 0);
    assert_eq!(health["errors"], 0);

    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor after config");
    assert_eq!(doctor["status"], "healthy");
    let self_check = connector
        .handle_self_check()
        .await
        .expect("self-check after config");
    assert_eq!(self_check["status"], "ok");

    let shutdown = connector
        .handle_shutdown(json!({ "reason": "connector-local integration test" }))
        .await
        .expect("shutdown should complete");
    assert_eq!(shutdown, json!({}));

    let wire =
        serde_json::to_string(&json!([health, doctor, self_check, shutdown])).expect("serialize");
    assert!(!wire.contains(FIXTURE_API_KEY));
}

#[fcp_async_core::runtime::test]
async fn capability_tokens_deny_wrong_zone_or_instance_before_execution() {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = WhisperConnector::new();
    configure_and_handshake(&mut connector, &signing_key, "http://127.0.0.1:1/v1", None).await;
    let connector_instance_id = connector.instance_id().to_string();

    let allowed = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            TRANSCRIPTION_CAP,
            TRANSCRIBE_OP,
            "z:work",
            Some(&connector_instance_id),
        ))
        .await
        .expect("valid simulate should return policy result");
    assert_eq!(allowed["would_succeed"], true);

    let wrong_instance = InstanceId::new();
    let instance_denied = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            TRANSCRIPTION_CAP,
            TRANSCRIBE_OP,
            "z:work",
            Some(wrong_instance.as_str()),
        ))
        .await
        .expect("simulate wrong instance should return policy result");
    assert_eq!(instance_denied["would_succeed"], false);
    assert!(
        instance_denied["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Token instance mismatch"))
    );

    let wrong_zone = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            TRANSCRIPTION_CAP,
            TRANSCRIBE_OP,
            "z:private",
            Some(&connector_instance_id),
        ))
        .await
        .expect("simulate wrong zone should return policy result");
    assert_eq!(wrong_zone["would_succeed"], false);
    assert_eq!(wrong_zone["denial_code"], "FCP-4001");
    assert!(
        wrong_zone["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Token audience mismatch"))
    );

    let missing_capability = connector
        .handle_simulate(simulate_request_json(
            &signing_key,
            INFO_CAP,
            TRANSCRIBE_OP,
            "z:work",
            Some(&connector_instance_id),
        ))
        .await
        .expect("simulate missing capability should return policy result");
    assert_eq!(missing_capability["would_succeed"], false);
    assert_eq!(missing_capability["denial_code"], "FCP-3003");
    assert!(
        missing_capability["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(TRANSCRIBE_OP))
    );
    assert_eq!(
        missing_capability["missing_capabilities"][0],
        TRANSCRIPTION_CAP
    );
}

#[fcp_async_core::runtime::test]
async fn loopback_speech_fixture_emits_redacted_jsonl() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(header("authorization", format!("Bearer {FIXTURE_API_KEY}")))
        .and(body_partial_json(json!({
            "audio_base64": FIXTURE_AUDIO_BASE64,
            "model": "whisper-large-v3"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": SECRET_TRANSCRIPT,
            "language": "en",
            "duration": 1.25,
            "segments": [{
                "id": 0,
                "start": 0.0,
                "end": 1.25,
                "text": SECRET_TRANSCRIPT
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(body_partial_json(json!({
            "audio_url": FIXTURE_AUDIO_URL,
            "model": "whisper-1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "url fixture transcript",
            "language": "en",
            "duration": 2.5
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/translations"))
        .and(body_partial_json(json!({
            "audio_base64": FIXTURE_AUDIO_BASE64,
            "model": "whisper-1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "translated secret transcript",
            "language": "es",
            "duration": 1.5
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(body_partial_json(json!({
            "audio_base64": FIXTURE_AUDIO_BASE64,
            "response_format": "verbose_json"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "language": "en",
            "confidence": 0.99,
            "text": "verbose transcript",
            "duration": 1.5,
            "segments": [],
            "words": [{"word": "speaker-one", "start": 0.0, "end": 0.5}]
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", format!("Bearer {FIXTURE_API_KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "whisper-1"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = configured_connector(&format!("{}/v1", server.uri()), None).await;
    let mut logs = Vec::new();

    let start = Instant::now();
    let transcribed = connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-large-v3",
                "language": "en"
            }
        }))
        .await
        .expect("transcribe base64 through loopback");
    assert_eq!(transcribed["text"], SECRET_TRANSCRIPT);
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-large-v3",
        "invoke",
        elapsed_millis(start),
        "success",
        None,
        "not_required",
        None,
    ));

    let start = Instant::now();
    let from_url = connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": {
                "audio_url": FIXTURE_AUDIO_URL,
                "model": "whisper-1"
            }
        }))
        .await
        .expect("transcribe URL through loopback");
    assert_eq!(from_url["language"], "en");
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_URL,
        "whisper-1",
        "invoke",
        elapsed_millis(start),
        "success",
        None,
        "not_required",
        None,
    ));

    let start = Instant::now();
    let translated = connector
        .handle_invoke(json!({
            "operation_id": TRANSLATE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-1"
            }
        }))
        .await
        .expect("translate through loopback");
    assert_eq!(translated["source_language"], "es");
    logs.push(evidence_log(
        TRANSLATE_OP,
        TRANSLATION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-1",
        "invoke",
        elapsed_millis(start),
        "success",
        None,
        "not_required",
        None,
    ));

    let start = Instant::now();
    let detected = connector
        .handle_invoke(json!({
            "operation_id": DETECT_LANGUAGE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-1"
            }
        }))
        .await
        .expect("detect language through loopback");
    assert_eq!(detected["language"], "en");
    logs.push(evidence_log(
        DETECT_LANGUAGE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-1",
        "invoke",
        elapsed_millis(start),
        "success",
        None,
        "not_required",
        None,
    ));

    let start = Instant::now();
    let verbose = connector
        .handle_invoke(json!({
            "operation_id": VERBOSE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-1"
            }
        }))
        .await
        .expect("verbose transcribe through loopback");
    assert_eq!(verbose["words"][0]["word"], "speaker-one");
    logs.push(evidence_log(
        VERBOSE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-1",
        "invoke",
        elapsed_millis(start),
        "success",
        None,
        "not_required",
        None,
    ));

    let start = Instant::now();
    let health = connector
        .handle_invoke(json!({
            "operation_id": HEALTH_OP,
            "input": {}
        }))
        .await
        .expect("health should query model endpoint");
    assert_eq!(health["status"], "ok");
    logs.push(evidence_log(
        HEALTH_OP,
        INFO_CAP,
        "no-audio",
        "whisper-1",
        "invoke",
        elapsed_millis(start),
        "success",
        None,
        "not_required",
        None,
    ));

    for operation in [LIST_MODELS_OP, USAGE_OP, FORMATS_OP] {
        let result = connector
            .handle_invoke(json!({
                "operation_id": operation,
                "input": {}
            }))
            .await
            .expect("local info operation should succeed");
        assert!(result.as_object().is_some());
    }

    connector
        .handle_shutdown(json!({ "reason": "loopback complete" }))
        .await
        .expect("shutdown should complete");
    assert_log_shape_and_redaction(&logs);
}

#[fcp_async_core::runtime::test]
async fn loopback_errors_cover_audio_auth_rate_provider_network_timeout_and_malformed_shapes() {
    let mut logs = Vec::new();
    let base_url = unused_loopback_base_url();
    let connector = configured_connector(&base_url, None).await;

    let missing = connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": {}
        }))
        .await
        .expect_err("missing audio should fail before provider dispatch");
    assert_external_error(&missing, Some(400), false);
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        "missing-audio",
        "whisper-1",
        "invoke",
        0,
        "error",
        Some(missing.error_code()),
        "not_required",
        None,
    ));

    let empty = connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": { "audio_base64": "" }
        }))
        .await
        .expect_err("empty audio should fail before provider dispatch");
    assert_external_error(&empty, Some(400), false);

    let oversized_audio = "A".repeat(36 * 1024 * 1024);
    let oversized = connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": { "audio_base64": oversized_audio }
        }))
        .await
        .expect_err("oversized audio should fail before provider dispatch");
    assert_external_error(&oversized, Some(413), false);

    let unauthorized_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(openai_api_error("invalid api key")))
        .expect(1)
        .mount(&unauthorized_server)
        .await;
    let unauthorized_connector =
        configured_connector(&format!("{}/v1", unauthorized_server.uri()), None).await;
    let unauthorized = unauthorized_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": { "audio_base64": FIXTURE_AUDIO_BASE64 }
        }))
        .await
        .expect_err("401 should map to auth external error");
    assert_external_error(&unauthorized, Some(401), false);
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-1",
        "invoke",
        0,
        "error",
        Some(unauthorized.error_code()),
        "not_required",
        None,
    ));

    let rate_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(openai_api_error("rate limited")),
        )
        .expect(1)
        .mount(&rate_server)
        .await;
    let rate_connector = configured_connector(&format!("{}/v1", rate_server.uri()), None).await;
    let rate_limited = rate_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": { "audio_base64": FIXTURE_AUDIO_BASE64 }
        }))
        .await
        .expect_err("429 should map to retryable external error");
    assert_external_error(&rate_limited, Some(429), true);
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-1",
        "invoke",
        0,
        "error",
        Some(rate_limited.error_code()),
        "not_required",
        None,
    ));

    let provider_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(body_partial_json(json!({ "model": "whisper-missing" })))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(openai_api_error("model not available")),
        )
        .expect(1)
        .mount(&provider_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(body_partial_json(json!({ "model": "whisper-down" })))
        .respond_with(ResponseTemplate::new(503).set_body_string(PROVIDER_BODY_SENTINEL))
        .expect(1)
        .mount(&provider_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(body_partial_json(json!({ "model": "whisper-malformed" })))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&provider_server)
        .await;
    let provider_connector =
        configured_connector(&format!("{}/v1", provider_server.uri()), None).await;
    let missing_model = provider_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-missing"
            }
        }))
        .await
        .expect_err("missing model should map to provider external error");
    assert_external_error(&missing_model, Some(404), false);

    let provider_unavailable = provider_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-down"
            }
        }))
        .await
        .expect_err("503 should map to retryable provider error");
    assert_external_error(&provider_unavailable, Some(503), true);
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-down",
        "invoke",
        0,
        "error",
        Some(provider_unavailable.error_code()),
        "not_required",
        None,
    ));

    let malformed = provider_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": {
                "audio_base64": FIXTURE_AUDIO_BASE64,
                "model": "whisper-malformed"
            }
        }))
        .await
        .expect_err("malformed provider JSON should fail");
    assert!(matches!(malformed, FcpError::Internal { .. }));

    let network_connector = configured_connector(&unused_loopback_base_url(), None).await;
    let network = network_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": { "audio_base64": FIXTURE_AUDIO_BASE64 }
        }))
        .await
        .expect_err("closed loopback port should map to network error");
    assert_external_error(&network, None, true);

    let timeout_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(StdDuration::from_millis(75))
                .set_body_json(json!({ "text": "late transcript" })),
        )
        .expect(1)
        .mount(&timeout_server)
        .await;
    let timeout_connector =
        configured_connector(&format!("{}/v1", timeout_server.uri()), Some(10)).await;
    let timed_out = timeout_connector
        .handle_invoke(json!({
            "operation_id": TRANSCRIBE_OP,
            "input": { "audio_base64": FIXTURE_AUDIO_BASE64 }
        }))
        .await
        .expect_err("short test timeout should fail deterministically");
    assert_external_error(&timed_out, None, true);
    logs.push(evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        FIXTURE_AUDIO_BASE64,
        "whisper-1",
        "invoke",
        75,
        "error",
        Some(timed_out.error_code()),
        "not_required",
        None,
    ));

    assert_log_shape_and_redaction(&logs);
}

#[test]
fn absent_live_whisper_credentials_emit_structured_skip_artifact() {
    let live_enabled = env::var("FCP_WHISPER_LIVE_ENABLE").ok().as_deref() == Some("1");
    let api_key_present = env::var("OPENAI_API_KEY")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());

    if !(live_enabled && api_key_present) {
        let log = evidence_log(
            TRANSCRIBE_OP,
            TRANSCRIPTION_CAP,
            "live-audio-fixture",
            "whisper-1",
            "live_verification",
            0,
            "skipped",
            None,
            "not_started",
            Some("FCP_WHISPER_LIVE_ENABLE=1 and OPENAI_API_KEY are required"),
        );
        assert_log_shape_and_redaction(&[log]);
        return;
    }

    let log = evidence_log(
        TRANSCRIBE_OP,
        TRANSCRIPTION_CAP,
        "live-audio-fixture",
        "whisper-1",
        "live_verification",
        0,
        "skipped",
        None,
        "not_started",
        Some("live verification is intentionally outside connector-local CI"),
    );
    assert_log_shape_and_redaction(&[log]);
}
