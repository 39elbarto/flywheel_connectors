//! Voyage connector e2e evidence.
//!
//! The default path is deterministic and uses a loopback fixture. Set the
//! Voyage API-key environment variable to enable the live smoke path. Evidence
//! is JSONL and redacts input text, candidate documents, API keys, and vectors.

#![cfg(feature = "voyage")]
#![allow(clippy::too_many_lines)]

use std::io::Write as _;
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use fcp_voyage::VoyageConnector;
use fcp_voyage::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_RERANK_MODEL};
use fcp_voyage::connector::{test_handshake_request, test_invoke_request};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_EMBEDDINGS: &str = "voyage.embeddings.create";
const OP_RERANK: &str = "voyage.rerank";

const CAP_EMBEDDINGS: &str = "voyage.embeddings";
const CAP_RERANK: &str = "voyage.rerank";
const CAP_HEALTH: &str = "voyage.health.read";

const ARTIFACT_PATH: &str = "target/fcp-voyage/voyage-live-e2e.jsonl";

#[fcp_async_core::runtime::test]
async fn voyage_connector_emits_redacted_e2e_evidence() {
    let mut records = Vec::new();
    run_fixture_script(&mut records).await;
    run_live_script_or_record_skip(&mut records).await;

    let jsonl = write_jsonl_artifact(&records);
    assert!(jsonl.contains("\"provider_mode\":\"fixture\""));
    assert!(jsonl.contains("\"provider_mode\":\"live\"") || jsonl.contains("\"skip_reason\""));
    assert!(!jsonl.contains("fixture-bearer"));
    assert!(!jsonl.contains(&voyage_api_key_env()));
    assert!(!jsonl.contains("private query"));
    assert!(!jsonl.contains("private document"));
    assert!(!jsonl.contains("[0.1,0.2]"));
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

async fn run_fixture_script(records: &mut Vec<Value>) {
    let server = MockServer::start().await;
    mount_fixture_embeddings(&server, 2).await;
    mount_fixture_batch_embeddings(&server, 2).await;
    mount_fixture_rerank(&server).await;
    mount_fixture_rate_limit(&server).await;

    let mut configured = configured_connector(
        json!({
            "api_key": "fixture-bearer",
            "base_url": format!("{}/v1", server.uri()),
            "wait_on_rate_limit_ms": 1
        }),
        &[CAP_EMBEDDINGS, CAP_RERANK, CAP_HEALTH],
    )
    .await;

    let started = Instant::now();
    let embeddings = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": "private document",
            "input_type": "document",
            "output_dimension": 512
        }),
    )
    .await
    .expect("fixture embeddings should succeed");
    records.push(evidence_record(
        "fixture",
        OP_EMBEDDINGS,
        DEFAULT_EMBEDDING_MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "batch_size": 1_u64,
            "input_bytes": 16_u64,
            "vector_dimensions": embeddings["data"][0]["embedding"].as_array().map(Vec::len),
            "total_tokens": embeddings["usage"]["total_tokens"].as_u64()
        }),
    ));

    let started = Instant::now();
    let batch = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": ["private query", "private document"],
            "input_type": "query"
        }),
    )
    .await
    .expect("fixture batch embeddings should succeed");
    records.push(evidence_record(
        "fixture",
        OP_EMBEDDINGS,
        DEFAULT_EMBEDDING_MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "batch_size": 2_u64,
            "input_bytes": 30_u64,
            "vector_dimensions": batch["data"][0]["embedding"].as_array().map(Vec::len),
            "total_tokens": batch["usage"]["total_tokens"].as_u64()
        }),
    ));

    let started = Instant::now();
    let rerank = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({
            "query": "private query",
            "documents": ["private document", "private other"],
            "top_k": 1,
            "return_documents": false
        }),
    )
    .await
    .expect("fixture rerank should succeed");
    records.push(evidence_record(
        "fixture",
        OP_RERANK,
        DEFAULT_RERANK_MODEL,
        started.elapsed().as_millis(),
        Some(200),
        "not_needed",
        "ok",
        None,
        json!({
            "batch_size": 2_u64,
            "input_bytes": 42_u64,
            "result_count": rerank["result_count"].as_u64(),
            "top_relevance_bucket": "high"
        }),
    ));

    let started = Instant::now();
    let rate_limited = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "model": "voyage-rate-limit-fixture",
            "input": "private document"
        }),
    )
    .await
    .expect_err("fixture rate limit should map to FCP error");
    records.push(evidence_record(
        "fixture",
        OP_EMBEDDINGS,
        "voyage-rate-limit-fixture",
        started.elapsed().as_millis(),
        Some(429),
        "waited_then_failed",
        classify_error(&rate_limited),
        None,
        json!({
            "batch_size": 1_u64,
            "input_bytes": 16_u64,
            "vector_dimensions": Value::Null,
            "total_tokens": Value::Null
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
        "voyage.cleanup",
        DEFAULT_EMBEDDING_MODEL,
        0,
        None,
        "not_needed",
        "ok",
        None,
        json!({ "cleanup_result": cleanup_result }),
    ));
}

async fn run_live_script_or_record_skip(records: &mut Vec<Value>) {
    let bearer = std::env::var(voyage_api_key_env())
        .ok()
        .filter(|value| !value.trim().is_empty());
    let Some(api_key) = bearer else {
        records.push(evidence_record(
            "live",
            OP_EMBEDDINGS,
            DEFAULT_EMBEDDING_MODEL,
            0,
            None,
            "not_attempted",
            "skip",
            Some("missing_live_credentials"),
            json!({ "batch_size": 0_u64, "input_bytes": 0_u64 }),
        ));
        return;
    };

    let mut configured = configured_connector(
        json!({
            "api_key": api_key,
            "request_timeout_ms": 30_000
        }),
        &[CAP_EMBEDDINGS, CAP_RERANK, CAP_HEALTH],
    )
    .await;

    let started = Instant::now();
    let embeddings = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({
            "input": "The retrieval test sentence.",
            "input_type": "document",
            "output_dimension": 256
        }),
    )
    .await;
    match embeddings {
        Ok(response) => records.push(evidence_record(
            "live",
            OP_EMBEDDINGS,
            DEFAULT_EMBEDDING_MODEL,
            started.elapsed().as_millis(),
            Some(200),
            "not_needed",
            "ok",
            None,
            json!({
                "batch_size": 1_u64,
                "input_bytes": 28_u64,
                "vector_dimensions": response["data"][0]["embedding"].as_array().map(Vec::len),
                "total_tokens": response["usage"]["total_tokens"].as_u64()
            }),
        )),
        Err(err) => {
            records.push(evidence_record(
                "live",
                OP_EMBEDDINGS,
                DEFAULT_EMBEDDING_MODEL,
                started.elapsed().as_millis(),
                None,
                "provider_returned_error",
                classify_error(&err),
                None,
                json!({ "batch_size": 1_u64, "input_bytes": 28_u64 }),
            ));
            assert_eq!(
                classify_error(&err),
                "ok",
                "live Voyage embeddings failed after credentials were provided: {err}"
            );
        }
    }

    let started = Instant::now();
    let rerank = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({
            "query": "Ranking test sentence.",
            "documents": ["Ranking test sentence.", "Unrelated comparison sentence."],
            "top_k": 1,
            "return_documents": false
        }),
    )
    .await;
    match rerank {
        Ok(response) => records.push(evidence_record(
            "live",
            OP_RERANK,
            DEFAULT_RERANK_MODEL,
            started.elapsed().as_millis(),
            Some(200),
            "not_needed",
            "ok",
            None,
            json!({
                "batch_size": 2_u64,
                "input_bytes": 61_u64,
                "result_count": response["result_count"].as_u64(),
                "top_relevance_bucket": "recorded"
            }),
        )),
        Err(err) => {
            records.push(evidence_record(
                "live",
                OP_RERANK,
                DEFAULT_RERANK_MODEL,
                started.elapsed().as_millis(),
                None,
                "provider_returned_error",
                classify_error(&err),
                None,
                json!({ "batch_size": 2_u64, "input_bytes": 61_u64 }),
            ));
            assert_eq!(
                classify_error(&err),
                "ok",
                "live Voyage rerank failed after credentials were provided: {err}"
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
        "voyage.cleanup",
        DEFAULT_EMBEDDING_MODEL,
        0,
        None,
        "not_needed",
        "ok",
        None,
        json!({ "cleanup_result": cleanup_result }),
    ));
}

async fn mount_fixture_embeddings(server: &MockServer, total_tokens: u32) {
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("authorization", "Bearer fixture-bearer"))
        .and(body_partial_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input_type": "document"
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, total_tokens)),
        )
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_fixture_batch_embeddings(server: &MockServer, total_tokens: u32) {
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("authorization", "Bearer fixture-bearer"))
        .and(body_partial_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input_type": "query"
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, total_tokens)),
        )
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_fixture_rerank(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/rerank"))
        .and(header("authorization", "Bearer fixture-bearer"))
        .and(body_partial_json(json!({
            "model": DEFAULT_RERANK_MODEL,
            "top_k": 1
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": DEFAULT_RERANK_MODEL,
            "data": [{"index": 0, "relevance_score": 0.92}],
            "usage": {"total_tokens": 8}
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_fixture_rate_limit(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("authorization", "Bearer fixture-bearer"))
        .and(body_partial_json(json!({
            "model": "voyage-rate-limit-fixture"
        })))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_json(json!({"detail": "rate limited"})),
        )
        .expect(1)
        .mount(server)
        .await;
}

fn embedding_body(model: &str, total_tokens: u32) -> Value {
    json!({
        "object": "list",
        "model": model,
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
        "usage": {"prompt_tokens": total_tokens, "total_tokens": total_tokens}
    })
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
        "schema": "fcp.voyage.e2e.v1",
        "command_line": "cargo test -p fcp-e2e --no-default-features --features voyage --test voyage_live_e2e -- --nocapture",
        "git_revision": git_revision(),
        "provider_mode": provider_mode,
        "operation": operation,
        "model_id": model_id,
        "batch_size": details.get("batch_size").cloned().unwrap_or(Value::Null),
        "input_bytes": details.get("input_bytes").cloned().unwrap_or(Value::Null),
        "vector_dimensions": details.get("vector_dimensions").cloned().unwrap_or(Value::Null),
        "total_tokens": details.get("total_tokens").cloned().unwrap_or(Value::Null),
        "result_count": details.get("result_count").cloned().unwrap_or(Value::Null),
        "top_relevance_bucket": details.get("top_relevance_bucket").cloned().unwrap_or(Value::Null),
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
    std::fs::create_dir_all("target/fcp-voyage").expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}

fn voyage_api_key_env() -> String {
    ["VOYAGE", "API", "KEY"].join("_")
}

async fn configured_connector(config: Value, capabilities: &[&'static str]) -> ConfiguredVoyage {
    let mut connector = VoyageConnector::new();
    connector
        .handle_configure(config)
        .await
        .expect("Voyage connector should configure");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect();
    connector
        .handshake(test_handshake_request(requested, verifying_key.to_bytes()))
        .await
        .expect("Voyage connector handshake should succeed");
    ConfiguredVoyage {
        connector,
        signing_key,
    }
}

struct ConfiguredVoyage {
    connector: VoyageConnector,
    signing_key: Ed25519SigningKey,
}

async fn invoke(
    connector: &VoyageConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    let response = connector
        .invoke(test_invoke_request(
            "voyage-e2e",
            operation,
            input,
            capability_grant,
        ))
        .await?;
    if let Some(error) = response.error {
        Err(error)
    } else {
        response.result.ok_or_else(|| FcpError::Internal {
            message: "Voyage invoke response had neither result nor error".into(),
        })
    }
}

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
        .principal("user:voyage-e2e")
        .operations(&[operation])
        .issuer("node:voyage-e2e")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}
