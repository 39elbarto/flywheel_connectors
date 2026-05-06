//! Groq connector e2e evidence.
//!
//! The default path is deterministic and uses a loopback OpenAI-compatible
//! fixture. Set live credentials to additionally exercise the first-party
//! Groq API and record redaction-safe JSONL evidence without prompts, completions,
//! tool arguments, or bearer tokens.

#![cfg(feature = "groq")]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_groq::GroqConnector;
use fcp_groq::connector::{test_handshake_request, test_invoke_request};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "groq.chat.completions";
const OP_CHAT_STREAM: &str = "groq.chat.completions_stream";
const OP_MODELS: &str = "groq.models.list";
const OP_HEALTH: &str = "groq.health";

const CAP_CHAT: &str = "groq.chat";
const CAP_MODELS: &str = "groq.models.read";
const CAP_HEALTH: &str = "groq.health.read";

const MODEL: &str = "llama-3.1-8b-instant";
const ARTIFACT_PATH: &str = "target/fcp-groq/groq-live-e2e.jsonl";

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:groq-e2e")
        .operations(&[operation])
        .issuer("node:groq-e2e")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

async fn configured_connector(config: Value, capabilities: &[&'static str]) -> ConfiguredGroq {
    let mut connector = GroqConnector::new();
    connector
        .handle_configure(config)
        .await
        .expect("Groq connector should configure");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(*capability))
        .collect();
    connector
        .handshake(test_handshake_request(requested, verifying_key.to_bytes()))
        .await
        .expect("Groq connector handshake should succeed");

    ConfiguredGroq {
        connector,
        signing_key,
    }
}

struct ConfiguredGroq {
    connector: GroqConnector,
    signing_key: Ed25519SigningKey,
}

async fn invoke(
    connector: &GroqConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    let response = connector
        .invoke(test_invoke_request(
            "groq-e2e",
            operation,
            input,
            capability_grant,
        ))
        .await?;
    if let Some(error) = response.error {
        Err(error)
    } else {
        response.result.ok_or_else(|| FcpError::Internal {
            message: "Groq invoke response had neither result nor error".into(),
        })
    }
}

#[fcp_async_core::runtime::test]
async fn groq_connector_emits_redacted_e2e_evidence() {
    let mut records = Vec::new();
    run_fixture_script(&mut records).await;
    run_live_script_or_record_skip(&mut records).await;

    let jsonl = write_jsonl_artifact(&records);
    assert!(jsonl.contains("\"provider_mode\":\"fixture\""));
    assert!(jsonl.contains("\"provider_mode\":\"live\"") || jsonl.contains("\"skip_reason\""));
    assert!(!jsonl.contains("groq-fixture-key"));
    assert!(!jsonl.contains("GROQ_API_KEY"));
    assert!(!jsonl.contains("Bearer "));
    assert!(!jsonl.contains("private prompt"));
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_fixture_script(records: &mut Vec<Value>) {
    let server = MockServer::start().await;
    mount_fixture_chat(&server).await;
    mount_fixture_stream(&server).await;
    mount_fixture_models(&server).await;
    mount_fixture_rate_limit(&server).await;

    let mut configured = configured_connector(
        json!({
            "api_key": "groq-fixture-key",
            "base_url": format!("{}/openai/v1", server.uri()),
            "default_model": MODEL,
            "wait_on_rate_limit_ms": 1
        }),
        &[CAP_CHAT, CAP_MODELS, CAP_HEALTH],
    )
    .await;

    let started = Instant::now();
    let chat = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "model": MODEL,
            "messages": [{"role": "user", "content": "private prompt"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect("fixture chat should succeed");
    records.push(evidence_record(
        "fixture",
        OP_CHAT,
        MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "prompt_tokens": chat["usage"]["prompt_tokens"].as_u64(),
            "completion_tokens": chat["usage"]["completion_tokens"].as_u64(),
            "stream_chunk_count": 0_u64
        }),
    ));

    let started = Instant::now();
    let stream = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({
            "model": MODEL,
            "messages": [{"role": "user", "content": "private prompt"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect("fixture stream should succeed");
    records.push(evidence_record(
        "fixture",
        OP_CHAT_STREAM,
        MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "prompt_tokens": Value::Null,
            "completion_tokens": Value::Null,
            "stream_chunk_count": stream["chunk_count"].as_u64()
        }),
    ));

    let started = Instant::now();
    let models = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MODELS,
        CAP_MODELS,
        json!({ "refresh": true }),
    )
    .await
    .expect("fixture models should succeed");
    records.push(evidence_record(
        "fixture",
        OP_MODELS,
        MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "model_count": models["data"].as_array().map(Vec::len),
            "prompt_tokens": Value::Null,
            "completion_tokens": Value::Null,
            "stream_chunk_count": 0_u64
        }),
    ));

    let started = Instant::now();
    let health = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_HEALTH,
        CAP_HEALTH,
        json!({}),
    )
    .await
    .expect("fixture health should succeed");
    records.push(evidence_record(
        "fixture",
        OP_HEALTH,
        MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "model_count": health["model_count"].as_u64(),
            "prompt_tokens": Value::Null,
            "completion_tokens": Value::Null,
            "stream_chunk_count": 0_u64
        }),
    ));

    let started = Instant::now();
    let rate_limited = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "model": "llama-3.1-70b-versatile",
            "messages": [{"role": "user", "content": "private prompt"}],
            "max_tokens": 8
        }),
    )
    .await
    .expect_err("fixture rate limit should map to FCP error");
    records.push(evidence_record(
        "fixture",
        OP_CHAT,
        "llama-3.1-70b-versatile",
        started.elapsed().as_millis(),
        Some(429),
        "waited_then_failed",
        classify_error(&rate_limited),
        None,
        json!({
            "prompt_tokens": Value::Null,
            "completion_tokens": Value::Null,
            "stream_chunk_count": 0_u64
        }),
    ));

    let cleanup_result = configured
        .connector
        .handle_shutdown(json!({ "reason": "e2e complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(
        "fixture",
        "groq.cleanup",
        MODEL,
        0,
        None,
        "not_needed",
        "ok",
        None,
        json!({
            "cleanup_result": cleanup_result,
            "prompt_tokens": Value::Null,
            "completion_tokens": Value::Null,
            "stream_chunk_count": 0_u64
        }),
    ));
}

async fn run_live_script_or_record_skip(records: &mut Vec<Value>) {
    let live_bearer = std::env::var("GROQ_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let Some(live_bearer) = live_bearer else {
        records.push(evidence_record(
            "live",
            OP_CHAT,
            MODEL,
            0,
            None,
            "not_attempted",
            "skip",
            Some("missing_live_credentials"),
            json!({
                "prompt_tokens": Value::Null,
                "completion_tokens": Value::Null,
                "stream_chunk_count": 0_u64
            }),
        ));
        return;
    };

    let mut configured = configured_connector(
        json!({
            "api_key": live_bearer,
            "default_model": MODEL,
            "request_timeout_ms": 30_000
        }),
        &[CAP_CHAT, CAP_MODELS],
    )
    .await;

    let started = Instant::now();
    let chat = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "model": MODEL,
            "messages": [{"role": "user", "content": "Return the word ok."}],
            "max_tokens": 4,
            "temperature": 0
        }),
    )
    .await;

    match chat {
        Ok(response) => records.push(evidence_record(
            "live",
            OP_CHAT,
            MODEL,
            started.elapsed().as_millis(),
            Some(200),
            "not_needed",
            "ok",
            None,
            json!({
                "prompt_tokens": response["usage"]["prompt_tokens"].as_u64(),
                "completion_tokens": response["usage"]["completion_tokens"].as_u64(),
                "stream_chunk_count": 0_u64
            }),
        )),
        Err(err) => {
            records.push(evidence_record(
                "live",
                OP_CHAT,
                MODEL,
                started.elapsed().as_millis(),
                None,
                "provider_returned_error",
                classify_error(&err),
                None,
                json!({
                    "prompt_tokens": Value::Null,
                    "completion_tokens": Value::Null,
                    "stream_chunk_count": 0_u64
                }),
            ));
            assert!(
                false,
                "live Groq invocation failed after live credentials were provided: {err}"
            );
        }
    }

    let cleanup_result = configured
        .connector
        .handle_shutdown(json!({ "reason": "live e2e complete" }))
        .await
        .map(|_| "shutdown_ok")
        .unwrap_or("shutdown_error");
    records.push(evidence_record(
        "live",
        "groq.cleanup",
        MODEL,
        0,
        None,
        "not_needed",
        "ok",
        None,
        json!({
            "cleanup_result": cleanup_result,
            "prompt_tokens": Value::Null,
            "completion_tokens": Value::Null,
            "stream_chunk_count": 0_u64
        }),
    ));
}

async fn mount_fixture_chat(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-fixture-key"))
        .and(body_partial_json(json!({
            "model": MODEL,
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-groq-e2e",
            "object": "chat.completion",
            "created": 1,
            "model": MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "fixture response"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 2,
                "total_tokens": 4
            }
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_fixture_stream(server: &MockServer) {
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"fi\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"xture\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-fixture-key"))
        .and(body_partial_json(json!({
            "model": MODEL,
            "stream": true
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_fixture_models(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/openai/v1/models"))
        .and(header("authorization", "Bearer groq-fixture-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": MODEL,
                "object": "model",
                "created": 1,
                "owned_by": "Meta",
                "active": true,
                "context_window": 131_072
            }]
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_fixture_rate_limit(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-fixture-key"))
        .and(body_partial_json(json!({
            "model": "llama-3.1-70b-versatile",
            "stream": false
        })))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_json(json!({
                    "error": {
                        "message": "Rate limit reached for fixture",
                        "type": "rate_limit_error",
                        "code": "rate_limit_exceeded"
                    }
                })),
        )
        .expect(1)
        .mount(server)
        .await;
}

#[allow(clippy::too_many_arguments)]
fn evidence_record(
    provider_mode: &str,
    operation: &str,
    model_id: &str,
    latency_ms: u128,
    http_status: Option<u16>,
    retry_decision: &str,
    fcp_error_mapping: &str,
    skip_reason: Option<&str>,
    details: Value,
) -> Value {
    json!({
        "schema": "fcp.groq.e2e.v1",
        "command_line": "cargo test -p fcp-e2e --no-default-features --features groq --test groq_live_e2e -- --nocapture",
        "git_revision": git_revision(),
        "provider_mode": provider_mode,
        "operation": operation,
        "model_id": model_id,
        "prompt_tokens": details.get("prompt_tokens").cloned().unwrap_or(Value::Null),
        "completion_tokens": details.get("completion_tokens").cloned().unwrap_or(Value::Null),
        "stream_chunk_count": details.get("stream_chunk_count").cloned().unwrap_or(json!(0_u64)),
        "http_status": http_status,
        "latency_ms": u64::try_from(latency_ms).unwrap_or(u64::MAX),
        "retry_decision": retry_decision,
        "fcp_error_mapping": fcp_error_mapping,
        "audit_receipt_id_hash": audit_receipt_id_hash(provider_mode, operation, model_id),
        "cleanup_result": details.get("cleanup_result").cloned().unwrap_or(json!("pending")),
        "skip_reason": skip_reason,
        "details": details
    })
}

fn classify_error(error: &FcpError) -> &'static str {
    match error {
        FcpError::RateLimited { .. } => "capability.rate_limited",
        FcpError::External {
            status_code: Some(429),
            ..
        } => "external.rate_limited",
        FcpError::External { .. } => "external.provider_error",
        FcpError::UpstreamTimeout { .. } => "external.timeout",
        FcpError::DependencyUnavailable { .. } => "external.dependency_unavailable",
        FcpError::ConnectorUnavailable { .. } => "connector.unavailable",
        FcpError::InvalidRequest { .. } => "protocol.invalid_request",
        _ => "other",
    }
}

fn audit_receipt_id_hash(provider_mode: &str, operation: &str, model_id: &str) -> String {
    let input = format!("{provider_mode}:{operation}:{model_id}");
    format!("blake3:{}", blake3::hash(input.as_bytes()).to_hex())
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
    std::fs::create_dir_all("target/fcp-groq").expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}
