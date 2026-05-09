#![allow(clippy::too_many_lines)]

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_azure_speech::AzureSpeechConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, InstanceId, ZoneId,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_RESOURCE_ID: &str = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/speech";
const TEST_ENTRA_RESOURCE: &str = "https://cognitiveservices.azure.com/";
const TEST_MANAGED_IDENTITY_CLIENT_ID: &str = "11111111-2222-3333-4444-555555555555";
const CONNECTOR_ID: &str = "fcp.azure-speech";
const OP_VOICES: &str = "azure.speech.voices.list";
const OP_TTS: &str = "azure.speech.tts.synthesize";
const OP_STT_FAST: &str = "azure.speech.stt.transcribe_fast";
const OP_BATCH_SUBMIT: &str = "azure.speech.stt.batch.submit";
const OP_BATCH_GET: &str = "azure.speech.stt.batch.get";
const OP_BATCH_FILES: &str = "azure.speech.stt.batch.files";
const OP_CUSTOM_PROJECT_CREATE: &str = "azure.speech.stt.custom.projects.create";
const OP_CUSTOM_PROJECT_LIST: &str = "azure.speech.stt.custom.projects.list";
const OP_CUSTOM_PROJECT_GET: &str = "azure.speech.stt.custom.projects.get";
const OP_CUSTOM_PROJECT_DELETE: &str = "azure.speech.stt.custom.projects.delete";
const OP_CUSTOM_DATASET_CREATE: &str = "azure.speech.stt.custom.datasets.create";
const OP_CUSTOM_DATASET_GET: &str = "azure.speech.stt.custom.datasets.get";
const OP_CUSTOM_DATASET_DELETE: &str = "azure.speech.stt.custom.datasets.delete";
const OP_CUSTOM_MODEL_CREATE: &str = "azure.speech.stt.custom.models.create";
const OP_CUSTOM_MODEL_GET: &str = "azure.speech.stt.custom.models.get";
const OP_CUSTOM_MODEL_DELETE: &str = "azure.speech.stt.custom.models.delete";
const OP_CUSTOM_ENDPOINT_CREATE: &str = "azure.speech.stt.custom.endpoints.create";
const OP_CUSTOM_ENDPOINT_GET: &str = "azure.speech.stt.custom.endpoints.get";
const OP_CUSTOM_ENDPOINT_DELETE: &str = "azure.speech.stt.custom.endpoints.delete";
const CAP_VOICES: &str = "azure.speech.voices";
const CAP_TTS: &str = "azure.speech.tts";
const CAP_STT: &str = "azure.speech.stt";
const CUSTOM_PROJECT_ID: &str = "project-loopback-123";
const CUSTOM_DATASET_ID: &str = "dataset-loopback-123";
const CUSTOM_MODEL_ID: &str = "model-loopback-123";
const CUSTOM_ENDPOINT_ID: &str = "endpoint-loopback-123";

async fn configured_connector(server: &MockServer) -> (AzureSpeechConnector, Ed25519SigningKey) {
    configured_connector_with(server, json!({})).await
}

async fn configured_connector_with(
    server: &MockServer,
    extra_config: Value,
) -> (AzureSpeechConnector, Ed25519SigningKey) {
    let mut connector = AzureSpeechConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("subscription_key".into(), json!("loopback-secret"));
    config.insert("region".into(), json!("eastus"));
    config.insert(
        "token_url".into(),
        json!(format!("{}/sts/v1.0/issueToken", server.uri())),
    );
    config.insert("tts_base_url".into(), json!(server.uri()));
    config.insert("stt_base_url".into(), json!(server.uri()));
    config.insert("inline_audio_max_bytes".into(), json!(4));
    if let Some(extra) = extra_config.as_object() {
        for (key, value) in extra {
            config.insert(key.clone(), value.clone());
        }
    }
    connector
        .handle_configure(Value::Object(config))
        .await
        .expect("configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                vec![
                    CapabilityId::from_static(CAP_VOICES),
                    CapabilityId::from_static(CAP_TTS),
                    CapabilityId::from_static(CAP_STT),
                ],
                signing_key.verifying_key().to_bytes(),
            ))
            .expect("handshake request should serialize"),
        )
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn configured_entra_connector(
    server: &MockServer,
    token_format: &str,
) -> (AzureSpeechConnector, Ed25519SigningKey) {
    let mut connector = AzureSpeechConnector::new();
    let mut params = json!({
        "entra_access_token": "aad-secret",
        "entra_token_format": token_format,
        "entra_token_source": "managed_identity",
        "region": "eastus",
        "token_url": format!("{}/sts/v1.0/issueToken", server.uri()),
        "tts_base_url": server.uri(),
        "stt_base_url": server.uri(),
        "inline_audio_max_bytes": 4,
    });
    if token_format == "aad_resource_token" {
        params["entra_resource_id"] = json!(TEST_RESOURCE_ID);
    }
    let configured = connector
        .handle_configure(params)
        .await
        .expect("configure should succeed");
    assert_eq!(configured["auth_mode"], "entra_access_token");
    assert_eq!(configured["auth_token_source"], "managed_identity");
    assert!(
        !serde_json::to_string(&configured)
            .expect("configure result should serialize")
            .contains("aad-secret")
    );
    assert!(
        !serde_json::to_string(&configured)
            .expect("configure result should serialize")
            .contains(TEST_RESOURCE_ID)
    );
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                vec![
                    CapabilityId::from_static(CAP_VOICES),
                    CapabilityId::from_static(CAP_TTS),
                    CapabilityId::from_static(CAP_STT),
                ],
                signing_key.verifying_key().to_bytes(),
            ))
            .expect("handshake request should serialize"),
        )
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

fn handshake_request(
    capabilities_requested: Vec<CapabilityId>,
    host_public_key: [u8; 32],
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [42_u8; 32],
        capabilities_requested,
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    valid_token_with_zone_and_instance(
        signing_key,
        "z:work",
        instance_id.as_str(),
        capability,
        operation,
    )
}

fn valid_token_with_zone_and_instance(
    signing_key: &Ed25519SigningKey,
    zone_id: &str,
    instance_id: &str,
    capability: &str,
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
        .capability_id(capability)
        .zone_id(zone_id)
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &AzureSpeechConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    capability: &str,
    input: Value,
) -> fcp_prelude::FcpResult<Value> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input,
            "capability_token": valid_token(signing_key, connector.instance_id(), capability, operation),
        }))
        .await
}

fn e2e_log_path() -> Option<PathBuf> {
    std::env::var_os("AZURE_SPEECH_E2E_JSONL").map(PathBuf::from)
}

fn e2e_command_line() -> String {
    std::env::var("AZURE_SPEECH_E2E_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-azure-speech --test loopback azure_speech_loopback_e2e_jsonl_matrix -- --nocapture".into()
    })
}

fn e2e_git_revision() -> String {
    std::env::var("AZURE_SPEECH_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".into())
}

fn test_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn append_e2e_record(records: &mut Vec<Value>, record: Value) {
    if let Some(path) = e2e_log_path() {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).expect("e2e artifact directory should be created");
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("e2e JSONL should open");
        writeln!(file, "{record}").expect("e2e JSONL line should write");
    }
    println!("AZURE_SPEECH_E2E_JSONL {record}");
    records.push(record);
}

#[allow(clippy::too_many_arguments)]
fn e2e_record(
    scenario: &str,
    operation_id: &str,
    capability: &str,
    auth_mode: &str,
    fixture_or_live_mode: &str,
    http_status: u16,
    retry_backoff_decision: &str,
    fcp_error_mapping: &str,
    latency_ms: u128,
    result: &str,
    cleanup_result: &str,
    skip_reason: &str,
    voice_id: &str,
    language_id: &str,
    model_id: &str,
    content_type: &str,
    input_audio_byte_count: usize,
    output_audio_byte_count: usize,
    transcript_length: usize,
    stream_chunk_count: usize,
) -> Value {
    json!({
        "record_type": "azure_speech_connector_e2e",
        "command_line": e2e_command_line(),
        "git_revision": e2e_git_revision(),
        "connector_id": CONNECTOR_ID,
        "scenario": scenario,
        "operation_id": operation_id,
        "capability": capability,
        "zone": "z:work",
        "instance_id": "loopback-instance-redacted",
        "fixture_or_live_mode": fixture_or_live_mode,
        "region_class": "public",
        "endpoint_class": if fixture_or_live_mode == "live" { "microsoft_public" } else { "loopback" },
        "auth_mode": auth_mode,
        "token_source_class": "not_applicable",
        "api_version": "2025-10-15",
        "resource_id_hash": "n/a",
        "model_id_hash": "n/a",
        "project_id_hash": "n/a",
        "voice_id": voice_id,
        "language_id": language_id,
        "model_id": model_id,
        "content_type": content_type,
        "input_audio_byte_count": input_audio_byte_count,
        "output_audio_byte_count": output_audio_byte_count,
        "transcript_length": transcript_length,
        "stream_chunk_count": stream_chunk_count,
        "http_status": http_status,
        "websocket_close_code": Value::Null,
        "retry_backoff_decision": retry_backoff_decision,
        "fcp_error_mapping": fcp_error_mapping,
        "latency_ms": latency_ms,
        "result": result,
        "audit_receipt_id": format!("azure-speech-e2e-{scenario}"),
        "cleanup_result": cleanup_result,
        "skip_reason": skip_reason,
    })
}

fn with_identity_metadata(
    mut record: Value,
    token_source_class: &str,
    resource_id_hash: &str,
) -> Value {
    record["token_source_class"] = json!(token_source_class);
    record["resource_id_hash"] = json!(resource_id_hash);
    record
}

fn with_custom_speech_hashes(
    mut record: Value,
    resource_id: Option<&str>,
    model_id: Option<&str>,
    project_id: Option<&str>,
) -> Value {
    if let Some(resource_id) = resource_id {
        record["resource_id_hash"] = json!(test_sha256_hex(resource_id.as_bytes()));
    }
    if let Some(model_id) = model_id {
        record["model_id_hash"] = json!(test_sha256_hex(model_id.as_bytes()));
    }
    if let Some(project_id) = project_id {
        record["project_id_hash"] = json!(test_sha256_hex(project_id.as_bytes()));
    }
    record
}

fn connector_local_identity_skip_record(scenario: &str, fcp_error_mapping: &str) -> Value {
    with_identity_metadata(
        e2e_record(
            scenario,
            "azure.speech.auth.connector_local_identity",
            "azure.speech.auth",
            "connector_local_identity",
            "fixture",
            0,
            "not_started",
            fcp_error_mapping,
            0,
            "skipped",
            "not_started",
            "host_token_broker_required",
            "n/a",
            "n/a",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
        "connector_local_imds_policy_blocked",
        &test_sha256_hex(TEST_ENTRA_RESOURCE.as_bytes()),
    )
}

fn assert_jsonl_is_redacted(records: &[Value]) {
    let jsonl = records
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "loopback-secret",
        "aad-secret",
        "Bearer",
        TEST_RESOURCE_ID,
        "sig=SECRET",
        "Weather",
        "hello",
        "nightly support calls",
        "raw-audio",
        "transcript text",
        "should-not-leak",
        TEST_MANAGED_IDENTITY_CLIENT_ID,
        CUSTOM_PROJECT_ID,
        CUSTOM_DATASET_ID,
        CUSTOM_MODEL_ID,
        CUSTOM_ENDPOINT_ID,
    ] {
        assert!(
            !jsonl.contains(forbidden),
            "e2e JSONL must not leak forbidden fragment {forbidden:?}: {jsonl}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn voices_and_tts_use_issued_token_and_redact_large_audio() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sts/v1.0/issueToken"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("token-1"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header("authorization", "Bearer token-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-ChristopherNeural", "Locale": "en-US"}
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/cognitiveservices/v1"))
        .and(header("authorization", "Bearer token-1"))
        .and(header(
            "x-microsoft-outputformat",
            "riff-24khz-16bit-mono-pcm",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "audio/wav")
                .set_body_bytes(vec![1_u8, 2, 3, 4, 5, 6]),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server).await;
    let voices = invoke(&connector, &signing_key, OP_VOICES, CAP_VOICES, json!({}))
        .await
        .expect("voices list should succeed");
    assert_eq!(voices["voices"][0]["Name"], "en-US-ChristopherNeural");

    let tts = invoke(
        &connector,
        &signing_key,
        OP_TTS,
        CAP_TTS,
        json!({
                "text": "hello",
                "voice": "en-US-ChristopherNeural",
                "locale": "en-US"
        }),
    )
    .await
    .expect("tts should succeed");
    assert_eq!(tts["mode"], "artifact_reference");
    assert_eq!(tts["audio_base64"], Value::Null);
    assert_eq!(tts["artifact"]["byte_count"], 6);
}

#[fcp_async_core::runtime::test]
async fn entra_aad_resource_token_uses_authorization_without_issue_token() {
    let server = MockServer::start().await;
    let expected_authorization = format!("Bearer aad#{TEST_RESOURCE_ID}#aad-secret");
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header("authorization", expected_authorization.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-ChristopherNeural", "Locale": "en-US"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_entra_connector(&server, "aad_resource_token").await;
    let self_check = connector
        .handle_self_check()
        .await
        .expect("self-check should validate the configured Entra header");
    assert_eq!(self_check["status"], "ok");
    assert_eq!(self_check["auth_token_format"], "aad_resource_token");
    assert!(self_check["entra_resource_id_hash"].as_str().is_some());
    assert!(
        !serde_json::to_string(&self_check)
            .expect("self-check should serialize")
            .contains(TEST_RESOURCE_ID)
    );

    let voices = invoke(&connector, &signing_key, OP_VOICES, CAP_VOICES, json!({}))
        .await
        .expect("voices list should succeed with Entra auth");
    assert_eq!(voices["voices"][0]["Name"], "en-US-ChristopherNeural");
}

#[fcp_async_core::runtime::test]
async fn entra_bearer_token_authenticates_2025_10_15_fast_transcription() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("authorization", "Bearer aad-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "durationMilliseconds": 1000,
            "combinedPhrases": [{"text": "Hello"}],
            "phrases": [{"text": "Hello", "confidence": 0.9}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_entra_connector(&server, "bearer_token").await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
                "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
                "content_type": "audio/wav",
                "locale": "en-US"
        }),
    )
    .await
    .expect("fast transcription should succeed with raw Entra bearer auth");
    assert_eq!(result["text"], "Hello");
    assert_eq!(result["api_version"], "2025-10-15");
}

#[fcp_async_core::runtime::test]
async fn credential_id_mode_allows_host_injected_auth_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header(
            "x-fcp-credential-id",
            "11223344-5566-7788-99aa-bbccddeeff00",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-AvaNeural", "Locale": "en-US"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = AzureSpeechConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "region": "eastus",
            "token_url": format!("{}/sts/v1.0/issueToken", server.uri()),
            "tts_base_url": server.uri(),
            "stt_base_url": server.uri(),
        }))
        .await
        .expect("credential_id config should succeed");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(
            serde_json::to_value(handshake_request(
                vec![CapabilityId::from_static(CAP_VOICES)],
                signing_key.verifying_key().to_bytes(),
            ))
            .expect("handshake request should serialize"),
        )
        .await
        .expect("handshake should succeed");
    let health = connector
        .handle_health()
        .await
        .expect("health should serialize");
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["live_requests_supported"], true);
    assert_eq!(health["direct_live_auth_supported"], false);

    let voices = invoke(&connector, &signing_key, OP_VOICES, CAP_VOICES, json!({}))
        .await
        .expect("host-injected credential_id request should be allowed");
    assert_eq!(voices["voices"][0]["Name"], "en-US-AvaNeural");
}

#[fcp_async_core::runtime::test]
async fn fast_transcription_posts_2025_10_15_multipart_and_preserves_result_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "durationMilliseconds": 2000,
            "combinedPhrases": [{"channel": 0, "text": "Weather"}],
            "phrases": [{
                "channel": 0,
                "text": "Weather",
                "confidence": 0.789,
                "words": [{"text": "weather", "confidence": 0.8}]
            }]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
                "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
                "content_type": "audio/wav",
                "locales": ["en-US"],
                "phrase_list": {"phrases": ["Weather"], "biasingWeight": 1.4},
                "channels": [0]
        }),
    )
    .await
    .expect("transcription should succeed");
    assert_eq!(result["text"], "Weather");
    assert_eq!(result["api_version"], "2025-10-15");
    assert_eq!(
        result["provider_result"]["phrases"][0]["words"][0]["confidence"],
        0.8
    );
}

#[fcp_async_core::runtime::test]
async fn batch_transcription_submit_get_and_files_redact_provider_urls() {
    let server = MockServer::start().await;
    let transcription_id = "ba7ea6f5-3065-40b7-b49a-a90f48584683";
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:submit"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header(
                    "location",
                    format!(
                        "{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15",
                        server.uri()
                    ),
                )
                .set_body_json(json!({
                    "self": format!("{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15", server.uri()),
                    "displayName": "nightly support calls",
                    "locale": "en-US",
                    "links": {
                        "files": format!("{}/speechtotext/transcriptions/{transcription_id}/files?api-version=2025-10-15&sig=SECRET", server.uri())
                    },
                    "status": "Running"
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/speechtotext/transcriptions/{transcription_id}")))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": format!("{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15", server.uri()),
            "status": "Succeeded",
            "links": {
                "files": format!("{}/speechtotext/transcriptions/{transcription_id}/files?api-version=2025-10-15", server.uri())
            },
            "properties": {
                "durationMilliseconds": 42000
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/speechtotext/transcriptions/{transcription_id}/files"
        )))
        .and(query_param("api-version", "2025-10-15"))
        .and(query_param("sasValidityInSeconds", "300"))
        .and(query_param("top", "2"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [{
                "name": "audio.wav.json",
                "kind": "Transcription",
                "links": {
                    "contentUrl": "https://storage.example/transcript.json?sig=SECRET&se=2030-01-01"
                }
            }]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server).await;
    let submit = invoke(
        &connector,
        &signing_key,
        OP_BATCH_SUBMIT,
        CAP_STT,
        json!({
                "display_name": "nightly support calls",
                "locale": "en-US",
                "content_urls": ["https://storage.example/audio.wav?sig=SECRET"],
                "time_to_live_hours": 48,
                "profanity_filter_mode": "Masked"
        }),
    )
    .await
    .expect("batch submit should succeed");
    assert_eq!(submit["api_version"], "2025-10-15");
    assert_eq!(submit["content_source"]["mode"], "content_urls");
    assert!(submit["transcription_id_hash"].as_str().is_some());
    assert!(
        !serde_json::to_string(&submit)
            .expect("submit JSON should serialize")
            .contains("SECRET")
    );

    let status = invoke(
        &connector,
        &signing_key,
        OP_BATCH_GET,
        CAP_STT,
        json!({
                "transcription_id": transcription_id
        }),
    )
    .await
    .expect("batch status should succeed");
    assert_eq!(status["transcription"]["status"], "Succeeded");

    let files = invoke(
        &connector,
        &signing_key,
        OP_BATCH_FILES,
        CAP_STT,
        json!({
                "transcription_id": transcription_id,
                "sas_validity_seconds": 300,
                "top": 2
        }),
    )
    .await
    .expect("batch files should succeed");
    assert_eq!(files["files"]["values"][0]["name"], "audio.wav.json");
    assert_eq!(
        files["files"]["values"][0]["links"]["contentUrl"]["redacted"],
        true
    );
    assert!(
        !serde_json::to_string(&files)
            .expect("files JSON should serialize")
            .contains("SECRET")
    );
}

#[fcp_async_core::runtime::test]
async fn azure_speech_loopback_e2e_jsonl_matrix() {
    let mut records = Vec::new();

    let voices_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sts/v1.0/issueToken"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("token-e2e"))
        .mount(&voices_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header("authorization", "Bearer token-e2e"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-ChristopherNeural", "Locale": "en-US"}
        ])))
        .mount(&voices_server)
        .await;
    let (voices_connector, voices_key) = configured_connector(&voices_server).await;
    let started = Instant::now();
    let voices = invoke(
        &voices_connector,
        &voices_key,
        OP_VOICES,
        CAP_VOICES,
        json!({}),
    )
    .await
    .expect("voices loopback should succeed");
    assert_eq!(voices["voices"][0]["Locale"], "en-US");
    append_e2e_record(
        &mut records,
        e2e_record(
            "voices_list",
            OP_VOICES,
            CAP_VOICES,
            "subscription_key",
            "fixture",
            200,
            "not_retried",
            "none",
            started.elapsed().as_millis(),
            "passed",
            "not_started",
            "not_skipped",
            "en-US-ChristopherNeural",
            "en-US",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );

    let tts_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sts/v1.0/issueToken"))
        .respond_with(ResponseTemplate::new(200).set_body_string("token-tts"))
        .mount(&tts_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/cognitiveservices/v1"))
        .and(header("authorization", "Bearer token-tts"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "audio/wav")
                .set_body_bytes(vec![1_u8, 2, 3, 4, 5, 6]),
        )
        .mount(&tts_server)
        .await;
    let (tts_connector, tts_key) = configured_connector(&tts_server).await;
    let started = Instant::now();
    let tts = invoke(
        &tts_connector,
        &tts_key,
        OP_TTS,
        CAP_TTS,
        json!({
            "text": "redacted text",
            "voice": "en-US-ChristopherNeural",
            "locale": "en-US"
        }),
    )
    .await
    .expect("tts loopback should succeed");
    assert_eq!(tts["artifact"]["byte_count"], 6);
    append_e2e_record(
        &mut records,
        e2e_record(
            "tts_synthesize",
            OP_TTS,
            CAP_TTS,
            "subscription_key",
            "fixture",
            200,
            "not_retried",
            "none",
            started.elapsed().as_millis(),
            "passed",
            "not_started",
            "not_skipped",
            "en-US-ChristopherNeural",
            "en-US",
            "n/a",
            "audio/wav",
            0,
            6,
            0,
            0,
        ),
    );

    let stt_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "durationMilliseconds": 2000,
            "combinedPhrases": [{"channel": 0, "text": "Weather"}],
            "phrases": [{"channel": 0, "text": "Weather", "confidence": 0.789}]
        })))
        .mount(&stt_server)
        .await;
    let (stt_connector, stt_key) = configured_connector(&stt_server).await;
    let audio = [1_u8, 2, 3, 4];
    let started = Instant::now();
    let stt = invoke(
        &stt_connector,
        &stt_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
            "audio_base64": BASE64_STANDARD.encode(audio),
            "content_type": "audio/wav",
            "locale": "en-US"
        }),
    )
    .await
    .expect("fast STT loopback should succeed");
    let transcript_length = stt["text"].as_str().map_or(0, str::len);
    append_e2e_record(
        &mut records,
        e2e_record(
            "stt_fast_transcribe",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            200,
            "not_retried",
            "none",
            started.elapsed().as_millis(),
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            audio.len(),
            0,
            transcript_length,
            0,
        ),
    );

    let batch_server = MockServer::start().await;
    let transcription_id = "ba7ea6f5-3065-40b7-b49a-a90f48584683";
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:submit"))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header(
                    "location",
                    format!(
                        "{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15",
                        batch_server.uri()
                    ),
                )
                .set_body_json(json!({
                    "self": format!("{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15", batch_server.uri()),
                    "displayName": "redacted batch",
                    "locale": "en-US",
                    "links": {
                        "files": format!("{}/speechtotext/transcriptions/{transcription_id}/files?api-version=2025-10-15&sig=SECRET", batch_server.uri())
                    },
                    "status": "Running"
                })),
        )
        .mount(&batch_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/speechtotext/transcriptions/{transcription_id}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": format!("{}/speechtotext/transcriptions/{transcription_id}?api-version=2025-10-15", batch_server.uri()),
            "status": "Succeeded",
            "links": {
                "files": format!("{}/speechtotext/transcriptions/{transcription_id}/files?api-version=2025-10-15", batch_server.uri())
            }
        })))
        .mount(&batch_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/speechtotext/transcriptions/{transcription_id}/files"
        )))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [{
                "name": "redacted.json",
                "kind": "Transcription",
                "links": {
                    "contentUrl": "https://storage.example/transcript.json?sig=SECRET"
                }
            }]
        })))
        .mount(&batch_server)
        .await;
    let (batch_connector, batch_key) = configured_connector(&batch_server).await;
    let started = Instant::now();
    let batch_submit = invoke(
        &batch_connector,
        &batch_key,
        OP_BATCH_SUBMIT,
        CAP_STT,
        json!({
            "display_name": "redacted batch",
            "locale": "en-US",
            "content_urls": ["https://storage.example/audio.wav?sig=SECRET"]
        }),
    )
    .await
    .expect("batch submit loopback should succeed");
    assert!(batch_submit["transcription_id_hash"].as_str().is_some());
    append_e2e_record(
        &mut records,
        e2e_record(
            "batch_submit",
            OP_BATCH_SUBMIT,
            CAP_STT,
            "subscription_key",
            "fixture",
            201,
            "not_retried",
            "none",
            started.elapsed().as_millis(),
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );
    let batch_get = invoke(
        &batch_connector,
        &batch_key,
        OP_BATCH_GET,
        CAP_STT,
        json!({ "transcription_id": transcription_id }),
    )
    .await
    .expect("batch get loopback should succeed");
    assert_eq!(batch_get["transcription"]["status"], "Succeeded");
    append_e2e_record(
        &mut records,
        e2e_record(
            "batch_get",
            OP_BATCH_GET,
            CAP_STT,
            "subscription_key",
            "fixture",
            200,
            "not_retried",
            "none",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );
    let batch_files = invoke(
        &batch_connector,
        &batch_key,
        OP_BATCH_FILES,
        CAP_STT,
        json!({ "transcription_id": transcription_id }),
    )
    .await
    .expect("batch files loopback should succeed");
    assert_eq!(
        batch_files["files"]["values"][0]["links"]["contentUrl"]["redacted"],
        true
    );
    append_e2e_record(
        &mut records,
        e2e_record(
            "batch_files",
            OP_BATCH_FILES,
            CAP_STT,
            "subscription_key",
            "fixture",
            200,
            "not_retried",
            "none",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );

    let custom_server = MockServer::start().await;
    let project_url = format!(
        "{}/speechtotext/projects/{CUSTOM_PROJECT_ID}?api-version=2025-10-15",
        custom_server.uri()
    );
    let dataset_url = format!(
        "{}/speechtotext/datasets/{CUSTOM_DATASET_ID}?api-version=2025-10-15",
        custom_server.uri()
    );
    let model_url = format!(
        "{}/speechtotext/models/{CUSTOM_MODEL_ID}?api-version=2025-10-15",
        custom_server.uri()
    );
    let endpoint_url = format!(
        "{}/speechtotext/endpoints/{CUSTOM_ENDPOINT_ID}?api-version=2025-10-15",
        custom_server.uri()
    );
    Mock::given(method("POST"))
        .and(path("/speechtotext/projects"))
        .and(query_param("api-version", "2025-10-15"))
        .and(header("ocp-apim-subscription-key", "loopback-secret"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("location", project_url.as_str())
                .set_body_json(json!({
                    "self": project_url,
                    "displayName": "redacted project",
                    "locale": "en-US",
                    "links": {
                        "models": format!("{}/speechtotext/projects/{CUSTOM_PROJECT_ID}/models?api-version=2025-10-15", custom_server.uri())
                    }
                })),
        )
        .mount(&custom_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/speechtotext/projects"))
        .and(query_param("api-version", "2025-10-15"))
        .and(query_param("filter", "foundryProjectName eq 'redacted'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [{"self": project_url, "displayName": "redacted project"}]
        })))
        .mount(&custom_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/speechtotext/projects/{CUSTOM_PROJECT_ID}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": project_url,
            "displayName": "redacted project",
            "locale": "en-US"
        })))
        .mount(&custom_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/speechtotext/projects/{CUSTOM_PROJECT_ID}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&custom_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/datasets"))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("location", dataset_url.as_str())
                .set_body_json(json!({
                    "self": dataset_url,
                    "kind": "AudioFiles",
                    "contentUrl": "https://storage.example/dataset.zip?sig=SECRET",
                    "project": {"self": project_url}
                })),
        )
        .mount(&custom_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/speechtotext/datasets/{CUSTOM_DATASET_ID}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": dataset_url,
            "kind": "AudioFiles",
            "project": {"self": project_url}
        })))
        .mount(&custom_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/speechtotext/datasets/{CUSTOM_DATASET_ID}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&custom_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/models"))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("location", model_url.as_str())
                .set_body_json(json!({
                    "self": model_url,
                    "displayName": "redacted model",
                    "project": {"self": project_url},
                    "datasets": [{"self": dataset_url}]
                })),
        )
        .mount(&custom_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/speechtotext/models/{CUSTOM_MODEL_ID}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": model_url,
            "project": {"self": project_url}
        })))
        .mount(&custom_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("/speechtotext/models/{CUSTOM_MODEL_ID}")))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&custom_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/endpoints"))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("location", endpoint_url.as_str())
                .set_body_json(json!({
                    "self": endpoint_url,
                    "displayName": "redacted endpoint",
                    "project": {"self": project_url},
                    "model": {"self": model_url}
                })),
        )
        .mount(&custom_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/speechtotext/endpoints/{CUSTOM_ENDPOINT_ID}"
        )))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "self": endpoint_url,
            "project": {"self": project_url},
            "model": {"self": model_url}
        })))
        .mount(&custom_server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!(
            "/speechtotext/endpoints/{CUSTOM_ENDPOINT_ID}"
        )))
        .and(query_param("api-version", "2025-10-15"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&custom_server)
        .await;

    let (custom_connector, custom_key) = configured_connector(&custom_server).await;
    let project_create = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_PROJECT_CREATE,
        CAP_STT,
        json!({
            "display_name": "redacted project",
            "locale": "en-US",
            "foundry_project_name": "redacted"
        }),
    )
    .await
    .expect("custom project create should succeed");
    assert_eq!(project_create["resource"]["self"]["redacted"], true);
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_project_create",
                OP_CUSTOM_PROJECT_CREATE,
                CAP_STT,
                "subscription_key",
                "fixture",
                201,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "n/a",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_PROJECT_ID),
            None,
            Some(CUSTOM_PROJECT_ID),
        ),
    );
    let project_list = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_PROJECT_LIST,
        CAP_STT,
        json!({"filter": "foundryProjectName eq 'redacted'"}),
    )
    .await
    .expect("custom project list should succeed");
    assert_eq!(
        project_list["resource"]["values"][0]["self"]["redacted"],
        true
    );
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_project_list",
                OP_CUSTOM_PROJECT_LIST,
                CAP_STT,
                "subscription_key",
                "fixture",
                200,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "n/a",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            None,
            None,
            Some(CUSTOM_PROJECT_ID),
        ),
    );
    let _project_get = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_PROJECT_GET,
        CAP_STT,
        json!({"project_id": CUSTOM_PROJECT_ID}),
    )
    .await
    .expect("custom project get should succeed");
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_project_get",
                OP_CUSTOM_PROJECT_GET,
                CAP_STT,
                "subscription_key",
                "fixture",
                200,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "n/a",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_PROJECT_ID),
            None,
            Some(CUSTOM_PROJECT_ID),
        ),
    );

    let dataset_create = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_DATASET_CREATE,
        CAP_STT,
        json!({
            "display_name": "redacted dataset",
            "locale": "en-US",
            "kind": "AudioFiles",
            "content_url": "https://storage.example/dataset.zip?sig=SECRET",
            "project_id": CUSTOM_PROJECT_ID
        }),
    )
    .await
    .expect("custom dataset create should succeed");
    assert_eq!(dataset_create["resource"]["contentUrl"]["redacted"], true);
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_dataset_create",
                OP_CUSTOM_DATASET_CREATE,
                CAP_STT,
                "subscription_key",
                "fixture",
                201,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "n/a",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_DATASET_ID),
            None,
            Some(CUSTOM_PROJECT_ID),
        ),
    );
    let _dataset_get = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_DATASET_GET,
        CAP_STT,
        json!({"dataset_id": CUSTOM_DATASET_ID}),
    )
    .await
    .expect("custom dataset get should succeed");
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_dataset_get",
                OP_CUSTOM_DATASET_GET,
                CAP_STT,
                "subscription_key",
                "fixture",
                200,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "n/a",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_DATASET_ID),
            None,
            Some(CUSTOM_PROJECT_ID),
        ),
    );

    let model_create = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_MODEL_CREATE,
        CAP_STT,
        json!({
            "display_name": "redacted model",
            "locale": "en-US",
            "project_id": CUSTOM_PROJECT_ID,
            "datasets": [{"id": CUSTOM_DATASET_ID}]
        }),
    )
    .await
    .expect("custom model create should succeed");
    assert_eq!(
        model_create["model_id_hash"],
        test_sha256_hex(CUSTOM_MODEL_ID.as_bytes())
    );
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_model_create",
                OP_CUSTOM_MODEL_CREATE,
                CAP_STT,
                "subscription_key",
                "fixture",
                201,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "custom_model_hash_only",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_MODEL_ID),
            Some(CUSTOM_MODEL_ID),
            Some(CUSTOM_PROJECT_ID),
        ),
    );
    let _model_get = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_MODEL_GET,
        CAP_STT,
        json!({"model_id": CUSTOM_MODEL_ID}),
    )
    .await
    .expect("custom model get should succeed");
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_model_get",
                OP_CUSTOM_MODEL_GET,
                CAP_STT,
                "subscription_key",
                "fixture",
                200,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "custom_model_hash_only",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_MODEL_ID),
            Some(CUSTOM_MODEL_ID),
            Some(CUSTOM_PROJECT_ID),
        ),
    );

    let endpoint_create = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_ENDPOINT_CREATE,
        CAP_STT,
        json!({
            "display_name": "redacted endpoint",
            "locale": "en-US",
            "model_id": CUSTOM_MODEL_ID,
            "project_id": CUSTOM_PROJECT_ID
        }),
    )
    .await
    .expect("custom endpoint create should succeed");
    assert_eq!(
        endpoint_create["model_id_hash"],
        test_sha256_hex(CUSTOM_MODEL_ID.as_bytes())
    );
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_endpoint_create",
                OP_CUSTOM_ENDPOINT_CREATE,
                CAP_STT,
                "subscription_key",
                "fixture",
                201,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "custom_model_hash_only",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_ENDPOINT_ID),
            Some(CUSTOM_MODEL_ID),
            Some(CUSTOM_PROJECT_ID),
        ),
    );
    let _endpoint_get = invoke(
        &custom_connector,
        &custom_key,
        OP_CUSTOM_ENDPOINT_GET,
        CAP_STT,
        json!({"endpoint_id": CUSTOM_ENDPOINT_ID}),
    )
    .await
    .expect("custom endpoint get should succeed");
    append_e2e_record(
        &mut records,
        with_custom_speech_hashes(
            e2e_record(
                "custom_endpoint_get",
                OP_CUSTOM_ENDPOINT_GET,
                CAP_STT,
                "subscription_key",
                "fixture",
                200,
                "not_retried",
                "none",
                0,
                "passed",
                "not_started",
                "not_skipped",
                "n/a",
                "en-US",
                "custom_model_hash_only",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            Some(CUSTOM_ENDPOINT_ID),
            Some(CUSTOM_MODEL_ID),
            Some(CUSTOM_PROJECT_ID),
        ),
    );
    for (scenario, operation, id_field, id_value, resource_id, model_id) in [
        (
            "custom_endpoint_delete",
            OP_CUSTOM_ENDPOINT_DELETE,
            "endpoint_id",
            CUSTOM_ENDPOINT_ID,
            CUSTOM_ENDPOINT_ID,
            Some(CUSTOM_MODEL_ID),
        ),
        (
            "custom_model_delete",
            OP_CUSTOM_MODEL_DELETE,
            "model_id",
            CUSTOM_MODEL_ID,
            CUSTOM_MODEL_ID,
            Some(CUSTOM_MODEL_ID),
        ),
        (
            "custom_dataset_delete",
            OP_CUSTOM_DATASET_DELETE,
            "dataset_id",
            CUSTOM_DATASET_ID,
            CUSTOM_DATASET_ID,
            None,
        ),
        (
            "custom_project_delete",
            OP_CUSTOM_PROJECT_DELETE,
            "project_id",
            CUSTOM_PROJECT_ID,
            CUSTOM_PROJECT_ID,
            None,
        ),
    ] {
        invoke(
            &custom_connector,
            &custom_key,
            operation,
            CAP_STT,
            json!({id_field: id_value}),
        )
        .await
        .expect("custom delete should succeed");
        append_e2e_record(
            &mut records,
            with_custom_speech_hashes(
                e2e_record(
                    scenario,
                    operation,
                    CAP_STT,
                    "subscription_key",
                    "fixture",
                    204,
                    "not_retried",
                    "none",
                    0,
                    "passed",
                    "deleted_loopback_resource",
                    "not_skipped",
                    "n/a",
                    "en-US",
                    "custom_model_hash_only",
                    "application/json",
                    0,
                    0,
                    0,
                    0,
                ),
                Some(resource_id),
                model_id,
                Some(CUSTOM_PROJECT_ID),
            ),
        );
    }

    let identity_server = MockServer::start().await;
    let expected_authorization = format!("Bearer aad#{TEST_RESOURCE_ID}#aad-secret");
    Mock::given(method("GET"))
        .and(path("/cognitiveservices/voices/list"))
        .and(header("authorization", expected_authorization.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Name": "en-US-AvaNeural", "Locale": "en-US"}
        ])))
        .expect(1)
        .mount(&identity_server)
        .await;
    let (identity_connector, identity_key) =
        configured_entra_connector(&identity_server, "aad_resource_token").await;
    let started = Instant::now();
    let identity_voices = invoke(
        &identity_connector,
        &identity_key,
        OP_VOICES,
        CAP_VOICES,
        json!({}),
    )
    .await
    .expect("host-brokered managed identity handoff should authenticate");
    assert_eq!(identity_voices["voices"][0]["Name"], "en-US-AvaNeural");
    append_e2e_record(
        &mut records,
        with_identity_metadata(
            e2e_record(
                "managed_identity_host_token_handoff",
                OP_VOICES,
                CAP_VOICES,
                "entra_access_token",
                "fixture",
                200,
                "not_retried",
                "none",
                started.elapsed().as_millis(),
                "passed",
                "not_started",
                "not_skipped",
                "en-US-AvaNeural",
                "en-US",
                "n/a",
                "application/json",
                0,
                0,
                0,
                0,
            ),
            "managed_identity_host_broker",
            &test_sha256_hex(TEST_RESOURCE_ID.as_bytes()),
        ),
    );

    let mut connector_local_identity = AzureSpeechConnector::new();
    let connector_local_error = connector_local_identity
        .handle_configure(json!({
            "connector_local_identity": true,
            "managed_identity_client_id": TEST_MANAGED_IDENTITY_CLIENT_ID,
            "region": "eastus",
        }))
        .await
        .expect_err("connector-local IMDS must be blocked by host-policy guidance");
    let connector_local_message = connector_local_error.to_string();
    assert!(connector_local_message.contains("host-provided entra_access_token"));
    assert!(!connector_local_message.contains(TEST_MANAGED_IDENTITY_CLIENT_ID));
    for scenario in [
        "connector_local_imds_policy_skip",
        "imds_token_success_skip",
        "imds_expired_refresh_skip",
        "imds_missing_permission_skip",
        "imds_tenant_resource_mismatch_skip",
        "imds_timeout_skip",
        "imds_provider_auth_failure_skip",
    ] {
        append_e2e_record(
            &mut records,
            connector_local_identity_skip_record(scenario, "host_token_broker_required"),
        );
    }

    let retry_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after-ms", "0")
                .set_body_string("redacted provider rate limit"),
        )
        .up_to_n_times(1)
        .mount(&retry_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "durationMilliseconds": 100,
            "combinedPhrases": [{"text": "Recovered"}]
        })))
        .mount(&retry_server)
        .await;
    let (retry_connector, retry_key) = configured_connector(&retry_server).await;
    let retry_result = invoke(
        &retry_connector,
        &retry_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
            "audio_base64": BASE64_STANDARD.encode([9_u8, 8, 7, 6]),
            "content_type": "audio/wav",
            "locale": "en-US"
        }),
    )
    .await
    .expect("retry should recover");
    assert_eq!(retry_result["api_version"], "2025-10-15");
    append_e2e_record(
        &mut records,
        e2e_record(
            "rate_limit_retry",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            200,
            "429_retry_after_ms_then_success",
            "none",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            4,
            0,
            retry_result["text"].as_str().map_or(0, str::len),
            0,
        ),
    );

    let error_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "should-not-leak",
            "transcript": "transcript text"
        })))
        .mount(&error_server)
        .await;
    let (error_connector, error_key) = configured_connector(&error_server).await;
    let error = invoke(
        &error_connector,
        &error_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
            "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
            "content_type": "audio/wav",
            "locale": "en-US"
        }),
    )
    .await
    .expect_err("provider 401 should fail");
    let mapping = error.to_string();
    assert!(!mapping.contains("should-not-leak"));
    assert!(!mapping.contains("transcript text"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "provider_error_401",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            401,
            "not_retried",
            "External",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            4,
            0,
            0,
            0,
        ),
    );

    let timeout_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({"combinedPhrases": [{"text": "slow"}]})),
        )
        .mount(&timeout_server)
        .await;
    let (timeout_connector, timeout_key) =
        configured_connector_with(&timeout_server, json!({"request_timeout_ms": 100})).await;
    let timeout_error = invoke(
        &timeout_connector,
        &timeout_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
            "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
            "content_type": "audio/wav",
            "locale": "en-US"
        }),
    )
    .await
    .expect_err("slow provider should hit request timeout");
    assert!(timeout_error.to_string().contains("timeout"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "provider_timeout",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "UpstreamTimeout",
            100,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            4,
            0,
            0,
            0,
        ),
    );

    let malformed = invoke(
        &tts_connector,
        &tts_key,
        OP_TTS,
        CAP_TTS,
        json!({"ssml": "<voice>missing speak root</voice>"}),
    )
    .await
    .expect_err("malformed SSML should fail before provider call");
    assert!(malformed.to_string().contains("SSML"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "malformed_input",
            OP_TTS,
            CAP_TTS,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "InvalidRequest",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "en-US-ChristopherNeural",
            "en-US",
            "n/a",
            "application/ssml+xml",
            0,
            0,
            0,
            0,
        ),
    );

    let unsupported = invoke(
        &stt_connector,
        &stt_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
            "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
            "content_type": "application/octet-stream"
        }),
    )
    .await
    .expect_err("unsupported format should fail before provider call");
    assert!(unsupported.to_string().contains("unsupported"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "unsupported_format",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "InvalidRequest",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "application/octet-stream",
            4,
            0,
            0,
            0,
        ),
    );

    let oversized_server = MockServer::start().await;
    let (oversized_connector, oversized_key) =
        configured_connector_with(&oversized_server, json!({"stt_max_audio_bytes": 2})).await;
    let oversized = invoke(
        &oversized_connector,
        &oversized_key,
        OP_STT_FAST,
        CAP_STT,
        json!({
            "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
            "content_type": "audio/wav"
        }),
    )
    .await
    .expect_err("oversized audio should fail before provider call");
    assert!(oversized.to_string().contains("max_audio_bytes"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "oversized_audio",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "InvalidRequest",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            4,
            0,
            0,
            0,
        ),
    );

    let wrong_zone = valid_token_with_zone_and_instance(
        &voices_key,
        "z:private",
        voices_connector.instance_id().as_str(),
        CAP_VOICES,
        OP_VOICES,
    );
    let zone_denial = voices_connector
        .handle_invoke(json!({
            "operation_id": OP_VOICES,
            "input": {},
            "capability_token": wrong_zone
        }))
        .await
        .expect_err("wrong-zone capability token must be denied");
    assert!(!zone_denial.to_string().contains("loopback-secret"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "capability_zone_denial",
            OP_VOICES,
            CAP_VOICES,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "CapabilityDenied",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "n/a",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );

    let wrong_instance = InstanceId::new();
    let wrong_instance_grant = valid_token_with_zone_and_instance(
        &voices_key,
        "z:work",
        wrong_instance.as_str(),
        CAP_VOICES,
        OP_VOICES,
    );
    let instance_denial = voices_connector
        .handle_invoke(json!({
            "operation_id": OP_VOICES,
            "input": {},
            "capability_token": wrong_instance_grant
        }))
        .await
        .expect_err("wrong-instance capability token must be denied");
    assert!(!instance_denial.to_string().contains("loopback-secret"));
    append_e2e_record(
        &mut records,
        e2e_record(
            "capability_instance_denial",
            OP_VOICES,
            CAP_VOICES,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "CapabilityDenied",
            0,
            "passed",
            "not_started",
            "not_skipped",
            "n/a",
            "n/a",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );

    let cancellation_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/speechtotext/transcriptions:transcribe"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!({"combinedPhrases": [{"text": "cancelled"}]})),
        )
        .mount(&cancellation_server)
        .await;
    let (cancellation_connector, cancellation_key) =
        configured_connector(&cancellation_server).await;
    let cancellation = fcp_async_core::time::timeout(
        Duration::from_millis(1),
        invoke(
            &cancellation_connector,
            &cancellation_key,
            OP_STT_FAST,
            CAP_STT,
            json!({
                "audio_base64": BASE64_STANDARD.encode([1_u8, 2, 3, 4]),
                "content_type": "audio/wav",
                "locale": "en-US"
            }),
        ),
    )
    .await;
    assert!(cancellation.is_err());
    append_e2e_record(
        &mut records,
        e2e_record(
            "harness_cancellation",
            OP_STT_FAST,
            CAP_STT,
            "subscription_key",
            "fixture",
            0,
            "not_retried",
            "HarnessTimeoutCancellation",
            1,
            "passed",
            "future_dropped",
            "not_skipped",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            4,
            0,
            0,
            0,
        ),
    );

    append_e2e_record(
        &mut records,
        e2e_record(
            "streaming_blocker",
            "azure.speech.stt.realtime.websocket",
            CAP_STT,
            "subscription_key",
            "fixture",
            0,
            "not_started",
            "blocked_official_sdk_only_protocol",
            0,
            "blocked",
            "not_started",
            "Microsoft Learn documents SDK stream APIs but not the standalone wire protocol",
            "n/a",
            "en-US",
            "n/a",
            "audio/wav",
            0,
            0,
            0,
            0,
        ),
    );

    let mut shutdown_connector = voices_connector;
    let shutdown = shutdown_connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should clean connector state");
    assert_eq!(shutdown["status"], "shutdown");
    append_e2e_record(
        &mut records,
        e2e_record(
            "shutdown_cleanup",
            "azure.speech.shutdown",
            "connector.lifecycle",
            "subscription_key",
            "fixture",
            0,
            "not_started",
            "none",
            0,
            "passed",
            "shutdown",
            "not_skipped",
            "n/a",
            "n/a",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );

    let live_ready = std::env::var("AZURE_SPEECH_LIVE").ok().as_deref() == Some("1")
        && std::env::var("AZURE_SPEECH_KEY")
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
        && std::env::var("AZURE_SPEECH_REGION")
            .ok()
            .is_some_and(|value| !value.trim().is_empty());
    let live_result = if live_ready { "configured" } else { "skipped" };
    let live_skip_reason = if live_ready {
        "not_skipped"
    } else {
        "AZURE_SPEECH_LIVE=1 plus AZURE_SPEECH_KEY and AZURE_SPEECH_REGION are required for optional live smoke"
    };
    append_e2e_record(
        &mut records,
        e2e_record(
            "optional_live_smoke",
            OP_VOICES,
            CAP_VOICES,
            "subscription_key",
            "live",
            0,
            "not_started",
            "not_applicable",
            0,
            live_result,
            "not_started",
            live_skip_reason,
            "n/a",
            "n/a",
            "n/a",
            "application/json",
            0,
            0,
            0,
            0,
        ),
    );

    assert!(
        records
            .iter()
            .filter(|record| record["record_type"] == "azure_speech_connector_e2e")
            .count()
            >= 25
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "rate_limit_retry")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "provider_timeout")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "harness_cancellation")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "managed_identity_host_token_handoff")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "connector_local_imds_policy_skip")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "optional_live_smoke")
    );
    assert_jsonl_is_redacted(&records);
}
