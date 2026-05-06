//! Deepgram and ElevenLabs connector-boundary evidence.
//!
//! This deterministic lane covers the currently implemented prerecorded
//! Deepgram Listen and request-response ElevenLabs voices/TTS surfaces. It
//! deliberately records only counts, hashes, ids, and status mappings: no
//! transcripts, source URLs, audio bytes, generated text, or API keys.

#![cfg(all(feature = "deepgram", feature = "elevenlabs"))]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::time::{Duration, Instant};

use fcp_deepgram::DeepgramConnector;
use fcp_e2e::{HttpFixtureResponse, HttpFixtureRoute, HttpFixtureServer, RecordedHttpRequest};
use fcp_elevenlabs::ElevenlabsConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "target/fcp-speech-media/speech-media-e2e.jsonl";
const DEEPGRAM_TRANSCRIBE: &str = "deepgram.listen.transcribe";
const ELEVEN_VOICES: &str = "elevenlabs.voices.list";
const ELEVEN_TTS: &str = "elevenlabs.tts.generate";

#[fcp_async_core::runtime::test]
async fn speech_media_provider_loopback_emits_redacted_evidence() {
    let mut records = Vec::new();
    run_deepgram_fixture_script(&mut records).await;
    run_elevenlabs_fixture_script(&mut records).await;

    let jsonl = write_jsonl_artifact(&records);
    assert!(jsonl.contains("\"fixture_mode\":\"loopback_http_tcp\""));
    assert!(jsonl.contains("\"provider\":\"deepgram\""));
    assert!(jsonl.contains("\"provider\":\"elevenlabs\""));
    assert!(!jsonl.contains("deepgram-fixture-key"));
    assert!(!jsonl.contains("eleven-fixture-key"));
    assert!(!jsonl.contains("https://media.example.test"));
    assert!(!jsonl.contains("fixture transcript"));
    assert!(!jsonl.contains("hello from fixture"));
    assert!(!jsonl.contains("unsupported format fixture"));
    assert!(!jsonl.contains("AQIDBAU="));
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_deepgram_fixture_script(records: &mut Vec<Value>) {
    let server = HttpFixtureServer::start().expect("Deepgram loopback should bind");
    mount_deepgram_transcribe_success(&server);
    let mut connector = configured_deepgram(&server, 5_000).await;

    let started = Instant::now();
    let transcript = deepgram_invoke(
        &connector,
        json!({
            "audio_url": "https://media.example.test/path/customer-audio.wav",
            "language": "en",
            "smart_format": true
        }),
    )
    .await
    .expect("Deepgram fixture transcription should succeed");
    assert_single_deepgram_transcribe_request(&server, "customer-audio.wav");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_prerecorded_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "model_id": "nova-3",
            "media_reference_hash": hash_label("https://media.example.test/path/customer-audio.wav"),
            "media_byte_count": Value::Null,
            "transcript_char_count": transcript_char_count(&transcript),
            "stream_frame_count": 0_u64,
            "streaming_supported": false,
            "realtime_scope": "not_in_this_slice"
        }),
    }));

    let cleanup_result = connector
        .handle_shutdown(json!({ "reason": "speech media fixture complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: "deepgram.cleanup",
        scenario_id: "deepgram_cleanup",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({ "cleanup_result": cleanup_result }),
    }));

    let rate_server = HttpFixtureServer::start().expect("Deepgram rate limit loopback should bind");
    mount_deepgram_rate_limit(&rate_server);
    let rate_connector = configured_deepgram(&rate_server, 5_000).await;
    let started = Instant::now();
    let rate_limited = deepgram_invoke(
        &rate_connector,
        json!({"audio_url": "https://media.example.test/path/rate-limit.wav"}),
    )
    .await
    .expect_err("rate-limited fixture should fail");
    assert_single_deepgram_transcribe_request(&rate_server, "rate-limit.wav");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_rate_limit",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(429),
        retry_decision: "provider_returned_retry_after",
        fcp_error_mapping: classify_error(&rate_limited),
        skip_reason: None,
        details: json!({
            "model_id": "nova-3",
            "media_reference_hash": hash_label("https://media.example.test/path/rate-limit.wav"),
            "media_byte_count": Value::Null,
            "stream_frame_count": 0_u64
        }),
    }));

    let oversized = deepgram_invoke(
        &rate_connector,
        json!({
            "audio_url": "https://media.example.test/path/oversized.wav",
            "media_byte_count": 1_073_741_825_u64
        }),
    )
    .await
    .expect_err("oversized media fixture should fail before network I/O");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_oversized_media_denial",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_attempted",
        fcp_error_mapping: classify_error(&oversized),
        skip_reason: None,
        details: json!({
            "model_id": "nova-3",
            "media_reference_hash": hash_label("https://media.example.test/path/oversized.wav"),
            "media_byte_count": 1_073_741_825_u64,
            "stream_frame_count": 0_u64
        }),
    }));

    let mut credential_connector = DeepgramConnector::new();
    credential_connector
        .handle_configure(json!({ "credential_id": "deepgram-credential-ref" }))
        .await
        .expect("credential-id configure should succeed");
    credential_connector
        .handle_handshake(json!({}))
        .await
        .expect("credential-id handshake should succeed");
    let denied = credential_connector
        .handle_invoke(json!({
            "operation_id": DEEPGRAM_TRANSCRIBE,
            "input": { "audio_url": "https://media.example.test/path/denied.wav" }
        }))
        .await
        .expect_err("credential-id mode should be denied without host injection");
    records.push(evidence_record(EvidenceInput {
        provider: "deepgram",
        operation: DEEPGRAM_TRANSCRIBE,
        scenario_id: "deepgram_credential_injection_required",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_attempted",
        fcp_error_mapping: classify_error(&denied),
        skip_reason: Some("host_credential_injection_not_available_in_fixture"),
        details: json!({
            "media_reference_hash": hash_label("https://media.example.test/path/denied.wav"),
            "stream_frame_count": 0_u64
        }),
    }));
}

async fn run_elevenlabs_fixture_script(records: &mut Vec<Value>) {
    let server = HttpFixtureServer::start().expect("ElevenLabs loopback should bind");
    mount_elevenlabs_voices(&server);
    mount_elevenlabs_tts(&server);
    let mut connector = configured_elevenlabs(&server, 5_000).await;

    let started = Instant::now();
    let voices = elevenlabs_invoke(&connector, ELEVEN_VOICES, json!({}))
        .await
        .expect("ElevenLabs voices fixture should succeed");
    assert_elevenlabs_voices_request(&server);
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_VOICES,
        scenario_id: "elevenlabs_voices_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "voice_count": voices["voices"].as_array().map_or(0, Vec::len),
            "voice_id": "voice-fixture",
            "model_id": "eleven_multilingual_v2",
            "stream_frame_count": 0_u64,
            "streaming_supported": false,
            "realtime_scope": "not_in_this_slice"
        }),
    }));

    let started = Instant::now();
    let speech = elevenlabs_invoke(
        &connector,
        ELEVEN_TTS,
        json!({
            "voice_id": "voice-fixture",
            "text": "hello from fixture",
            "output_format": "mp3_44100_128",
            "seed": 7_u64
        }),
    )
    .await
    .expect("ElevenLabs TTS fixture should succeed");
    assert_elevenlabs_tts_request(&server);
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS,
        scenario_id: "elevenlabs_tts_success",
        latency_ms: started.elapsed().as_millis(),
        http_status: Some(200),
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({
            "voice_id": speech["voice_id"].clone(),
            "model_id": "eleven_multilingual_v2",
            "audio_content_type": speech["content_type"].clone(),
            "audio_byte_count": speech["audio_size_bytes"].clone(),
            "output_format": "mp3_44100_128",
            "generated_text_hash": hash_label("hello from fixture"),
            "stream_frame_count": 0_u64
        }),
    }));

    let unsupported_format = elevenlabs_invoke(
        &connector,
        ELEVEN_TTS,
        json!({
            "voice_id": "voice-fixture",
            "text": "unsupported format fixture",
            "output_format": "wav"
        }),
    )
    .await
    .expect_err("unsupported output format should fail before network I/O");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS,
        scenario_id: "elevenlabs_unsupported_output_format",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_attempted",
        fcp_error_mapping: classify_error(&unsupported_format),
        skip_reason: None,
        details: json!({
            "voice_id": "voice-fixture",
            "model_id": "eleven_multilingual_v2",
            "output_format": "wav",
            "generated_text_hash": hash_label("unsupported format fixture"),
            "stream_frame_count": 0_u64
        }),
    }));

    let cleanup_result = connector
        .handle_shutdown(json!({ "reason": "speech media fixture complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: "elevenlabs.cleanup",
        scenario_id: "elevenlabs_cleanup",
        latency_ms: 0,
        http_status: None,
        retry_decision: "not_needed",
        fcp_error_mapping: "ok",
        skip_reason: None,
        details: json!({ "cleanup_result": cleanup_result }),
    }));

    let timeout_server =
        HttpFixtureServer::start().expect("ElevenLabs timeout loopback should bind");
    mount_elevenlabs_slow_tts(&timeout_server);
    let timeout_connector = configured_elevenlabs(&timeout_server, 20).await;
    let started = Instant::now();
    let timeout = elevenlabs_invoke(
        &timeout_connector,
        ELEVEN_TTS,
        json!({"voice_id": "voice-timeout", "text": "timeout fixture"}),
    )
    .await
    .expect_err("timeout fixture should fail");
    records.push(evidence_record(EvidenceInput {
        provider: "elevenlabs",
        operation: ELEVEN_TTS,
        scenario_id: "elevenlabs_timeout",
        latency_ms: started.elapsed().as_millis(),
        http_status: None,
        retry_decision: "request_timed_out",
        fcp_error_mapping: classify_error(&timeout),
        skip_reason: None,
        details: json!({
            "voice_id": "voice-timeout",
            "generated_text_hash": hash_label("timeout fixture"),
            "stream_frame_count": 0_u64
        }),
    }));
}

async fn configured_deepgram(
    server: &HttpFixtureServer,
    request_timeout_ms: u64,
) -> DeepgramConnector {
    let mut connector = DeepgramConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "deepgram-fixture-key",
            "base_url": server.base_url(),
            "request_timeout_ms": request_timeout_ms
        }))
        .await
        .expect("Deepgram connector should configure");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("Deepgram connector should handshake");
    connector
}

async fn configured_elevenlabs(
    server: &HttpFixtureServer,
    request_timeout_ms: u64,
) -> ElevenlabsConnector {
    let mut connector = ElevenlabsConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "eleven-fixture-key",
            "base_url": server.base_url(),
            "request_timeout_ms": request_timeout_ms
        }))
        .await
        .expect("ElevenLabs connector should configure");
    connector
        .handle_handshake(json!({"session_id": "speech-media-fixture"}))
        .await
        .expect("ElevenLabs connector should handshake");
    connector
}

async fn deepgram_invoke(
    connector: &DeepgramConnector,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({"operation_id": DEEPGRAM_TRANSCRIBE, "input": input}))
        .await
}

async fn elevenlabs_invoke(
    connector: &ElevenlabsConnector,
    operation: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(json!({"operation_id": operation, "input": input}))
        .await
}

fn mount_deepgram_transcribe_success(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/v1/listen")
            .for_scenario("deepgram_prerecorded_success")
            .with_query("model", "nova-3")
            .require_header("authorization", "Token deepgram-fixture-key")
            .respond_with(HttpFixtureResponse::json(json!({
                "metadata": { "request_id": "deepgram-fixture" },
                "results": {
                    "channels": [{
                        "alternatives": [{
                            "transcript": "fixture transcript should stay out of evidence",
                            "confidence": 0.98
                        }]
                    }]
                }
            }))),
    );
}

fn mount_deepgram_rate_limit(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/v1/listen")
            .for_scenario("deepgram_rate_limit")
            .with_query("model", "nova-3")
            .require_header("authorization", "Token deepgram-fixture-key")
            .respond_with(HttpFixtureResponse::rate_limited(
                2,
                json!({"error": "rate limited"}),
            )),
    );
}

fn mount_elevenlabs_voices(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::get("/voices")
            .for_scenario("elevenlabs_voices_success")
            .require_header("xi-api-key", "eleven-fixture-key")
            .respond_with(HttpFixtureResponse::json(json!({
                "voices": [{
                    "voice_id": "voice-fixture",
                    "name": "Fixture Voice",
                    "category": "generated"
                }]
            }))),
    );
}

fn mount_elevenlabs_tts(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/text-to-speech/voice-fixture")
            .for_scenario("elevenlabs_tts_success")
            .with_query("output_format", "mp3_44100_128")
            .require_header("xi-api-key", "eleven-fixture-key")
            .respond_with(HttpFixtureResponse::binary(
                vec![1_u8, 2, 3, 4, 5],
                "audio/mpeg",
            )),
    );
}

fn mount_elevenlabs_slow_tts(server: &HttpFixtureServer) {
    server.mount(
        HttpFixtureRoute::post("/text-to-speech/voice-timeout")
            .for_scenario("elevenlabs_timeout")
            .require_header("xi-api-key", "eleven-fixture-key")
            .respond_with(
                HttpFixtureResponse::binary(vec![1_u8, 2, 3], "audio/mpeg")
                    .with_delay(Duration::from_millis(200)),
            ),
    );
}

fn assert_single_deepgram_transcribe_request(server: &HttpFixtureServer, media_name: &str) {
    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "expected one Deepgram HTTP request");
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/listen");
    assert_eq!(request.query_value("model"), Some("nova-3"));
    assert_eq!(
        request.header("authorization"),
        Some("Token deepgram-fixture-key")
    );
    assert_eq!(
        request
            .body_json()
            .expect("Deepgram request body should be JSON"),
        json!({ "url": format!("https://media.example.test/path/{media_name}") })
    );
}

fn assert_elevenlabs_voices_request(server: &HttpFixtureServer) {
    let request = recorded_request(server, "GET", "/voices");
    assert_eq!(request.header("xi-api-key"), Some("eleven-fixture-key"));
}

fn assert_elevenlabs_tts_request(server: &HttpFixtureServer) {
    let request = recorded_request(server, "POST", "/text-to-speech/voice-fixture");
    assert_eq!(request.header("xi-api-key"), Some("eleven-fixture-key"));
    assert_eq!(request.query_value("output_format"), Some("mp3_44100_128"));
    assert_eq!(
        request
            .body_json()
            .expect("ElevenLabs TTS request body should be JSON"),
        json!({
            "text": "hello from fixture",
            "model_id": "eleven_multilingual_v2",
            "seed": 7_u64
        })
    );
}

fn recorded_request(server: &HttpFixtureServer, method: &str, path: &str) -> RecordedHttpRequest {
    server
        .recorded_requests()
        .into_iter()
        .find(|request| request.method == method && request.path == path)
        .unwrap_or_else(|| panic!("expected {method} {path} request"))
}

struct EvidenceInput<'a> {
    provider: &'a str,
    operation: &'a str,
    scenario_id: &'a str,
    latency_ms: u128,
    http_status: Option<u16>,
    retry_decision: &'a str,
    fcp_error_mapping: &'a str,
    skip_reason: Option<&'a str>,
    details: Value,
}

fn evidence_record(input: EvidenceInput<'_>) -> Value {
    let EvidenceInput {
        provider,
        operation,
        scenario_id,
        latency_ms,
        http_status,
        retry_decision,
        fcp_error_mapping,
        skip_reason,
        details,
    } = input;
    json!({
        "schema": "fcp.speech_media.e2e.v1",
        "command_line": "cargo test -p fcp-e2e --no-default-features --features deepgram,elevenlabs --test speech_media_provider_e2e -- --nocapture",
        "git_revision": git_revision(),
        "fixture_mode": "loopback_http_tcp",
        "provider": provider,
        "operation": operation,
        "scenario_id": scenario_id,
        "model_id": details.get("model_id").cloned().unwrap_or(Value::Null),
        "voice_id": details.get("voice_id").cloned().unwrap_or(Value::Null),
        "media_reference_hash": details.get("media_reference_hash").cloned().unwrap_or(Value::Null),
        "media_byte_count": details.get("media_byte_count").cloned().unwrap_or(Value::Null),
        "audio_content_type": details.get("audio_content_type").cloned().unwrap_or(Value::Null),
        "audio_byte_count": details.get("audio_byte_count").cloned().unwrap_or(Value::Null),
        "output_format": details.get("output_format").cloned().unwrap_or(Value::Null),
        "transcript_char_count": details.get("transcript_char_count").cloned().unwrap_or(Value::Null),
        "voice_count": details.get("voice_count").cloned().unwrap_or(Value::Null),
        "generated_text_hash": details.get("generated_text_hash").cloned().unwrap_or(Value::Null),
        "stream_frame_count": details.get("stream_frame_count").cloned().unwrap_or(json!(0_u64)),
        "streaming_supported": details.get("streaming_supported").cloned().unwrap_or(json!(false)),
        "realtime_scope": details.get("realtime_scope").cloned().unwrap_or(json!("not_in_this_slice")),
        "http_status": http_status,
        "latency_ms": u64::try_from(latency_ms).unwrap_or(u64::MAX),
        "retry_decision": retry_decision,
        "fcp_error_mapping": fcp_error_mapping,
        "audit_receipt_id_hash": audit_receipt_id_hash(provider, operation, scenario_id),
        "cleanup_result": details.get("cleanup_result").cloned().unwrap_or(json!("pending")),
        "skip_reason": skip_reason
    })
}

fn transcript_char_count(payload: &Value) -> u64 {
    payload
        .get("results")
        .and_then(|results| results.get("channels"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|channel| {
            channel
                .get("alternatives")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|alternative| alternative.get("transcript").and_then(Value::as_str))
        .map(|transcript| u64::try_from(transcript.chars().count()).unwrap_or(u64::MAX))
        .sum()
}

fn classify_error(error: &FcpError) -> &'static str {
    match error {
        FcpError::External {
            status_code: Some(429),
            ..
        } => "external.rate_limited",
        FcpError::External { .. } => "external.provider_error",
        FcpError::UpstreamTimeout { .. } => "external.timeout",
        FcpError::InvalidRequest { .. } => "protocol.invalid_request",
        _ => "other",
    }
}

fn audit_receipt_id_hash(provider: &str, operation: &str, scenario_id: &str) -> String {
    let input = format!("{provider}:{operation}:{scenario_id}");
    format!("sha256:{}", hex_lower(&Sha256::digest(input.as_bytes())))
}

fn hash_label(value: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(value.as_bytes())))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    let jsonl = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("evidence record should serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::create_dir_all("target/fcp-speech-media")
        .expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    for line in jsonl.lines() {
        println!("SPEECH_MEDIA_FIXTURE_JSONL {line}");
    }
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}
