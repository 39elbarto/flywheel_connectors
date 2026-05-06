#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_fireworks::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL};
use fcp_fireworks::connector::{CONNECTOR_ID, test_handshake_request};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, InstanceId};
use serde_json::{Value, json};

const OP_CHAT: &str = "fireworks.chat.completions";
const OP_CHAT_STREAM: &str = "fireworks.chat.completions_stream";
const OP_EMBEDDINGS: &str = "fireworks.embeddings.create";
const OP_MODELS: &str = "fireworks.models.list";

const CAP_CHAT: &str = "fireworks.chat";
const CAP_EMBEDDINGS: &str = "fireworks.embeddings";
const CAP_MODELS: &str = "fireworks.models.read";

#[fcp_async_core::runtime::test]
async fn fireworks_live_smoke_or_structured_skip_jsonl() {
    let git_revision =
        std::env::var("FIREWORKS_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let Ok(api_key) = std::env::var("FIREWORKS_API_KEY") else {
        emit_jsonl(
            &git_revision,
            "live_smoke",
            "live",
            "skipped",
            json!({
                "skip_reason": "FIREWORKS_API_KEY not set",
                "cleanup_result": "not_started"
            }),
        );
        return;
    };

    let chat_model =
        std::env::var("FIREWORKS_LIVE_CHAT_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
    let embedding_model = std::env::var("FIREWORKS_LIVE_EMBEDDING_MODEL")
        .unwrap_or_else(|_| DEFAULT_EMBEDDING_MODEL.to_string());
    let mut connector = fcp_fireworks::FireworksConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "default_model": chat_model,
            "default_embedding_model": embedding_model,
            "request_timeout_ms": 60_000,
            "wait_on_rate_limit_ms": 1000
        }))
        .await
        .expect("live configure should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(test_handshake_request(
            vec![
                CapabilityId::from_static(CAP_CHAT),
                CapabilityId::from_static(CAP_EMBEDDINGS),
                CapabilityId::from_static(CAP_MODELS),
            ],
            verifying_key.to_bytes(),
        ))
        .await
        .expect("live handshake should succeed");

    let models = invoke(
        &connector,
        &signing_key,
        OP_MODELS,
        CAP_MODELS,
        json!({"refresh": true}),
    )
    .await
    .expect("live models.list should succeed");
    emit_jsonl(
        &git_revision,
        "models.list",
        "live",
        "passed",
        json!({
            "model_count": models["data"].as_array().map(Vec::len).unwrap_or_default(),
            "http_status": 200
        }),
    );

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "Reply with one short word."}],
            "max_tokens": 4
        }),
    )
    .await
    .expect("live chat should succeed");
    emit_jsonl(
        &git_revision,
        "chat",
        "live",
        "passed",
        json!({
            "model_id_hash": blake3::hash(chat_model.as_bytes()).to_hex().to_string(),
            "completion_bytes": chat["content"].as_str().unwrap_or_default().len(),
            "token_count": chat["usage"]["total_tokens"],
            "http_status": 200
        }),
    );

    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "Reply with ok."}],
            "max_tokens": 4
        }),
    )
    .await
    .expect("live stream should succeed");
    emit_jsonl(
        &git_revision,
        "stream",
        "live",
        "passed",
        json!({
            "stream_chunk_count": stream["chunk_count"],
            "completion_bytes": stream["content"].as_str().unwrap_or_default().len(),
            "http_status": 200
        }),
    );

    let embeddings = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "short live embedding input"}),
    )
    .await
    .expect("live embeddings should succeed");
    emit_jsonl(
        &git_revision,
        "embeddings",
        "live",
        "passed",
        json!({
            "model_id_hash": blake3::hash(embedding_model.as_bytes()).to_hex().to_string(),
            "embedding_dimensions": embeddings["dimensions"],
            "data_count": embeddings["data_count"],
            "http_status": 200
        }),
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("live shutdown should succeed");
    emit_jsonl(
        &git_revision,
        "cleanup",
        "live",
        "passed",
        json!({
            "cleanup_result": "shutdown"
        }),
    );
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &fcp_fireworks::FireworksConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_grant,
        }))
        .await
}

fn emit_jsonl(
    git_revision: &str,
    operation: &str,
    fixture_mode: &str,
    status: &str,
    fields: Value,
) {
    let mut record = serde_json::Map::new();
    record.insert("event".into(), json!("fireworks_live_operation"));
    record.insert("connector_id".into(), json!(CONNECTOR_ID));
    record.insert("git_revision".into(), json!(git_revision));
    record.insert("fixture_mode".into(), json!(fixture_mode));
    record.insert("operation".into(), json!(operation));
    record.insert("status".into(), json!(status));
    record.insert(
        "command_line".into(),
        json!("cargo test -p fcp-fireworks --test live_verification fireworks_live_smoke_or_structured_skip_jsonl -- --nocapture"),
    );
    if let Value::Object(fields) = fields {
        for (key, value) in fields {
            record.insert(key, value);
        }
    }
    println!("FIREWORKS_E2E_JSONL {}", Value::Object(record));
}
