//! Live verification for the `DeepSeek` connector.
//!
//! These tests require `DEEPSEEK_API_KEY`. They skip gracefully when the key is
//! absent and emit JSONL records that contain only lengths and status metadata.

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_deepseek::DeepSeekConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, InstanceId};
use serde_json::{Value, json};

const OP_CHAT: &str = "deepseek.chat.completions";
const OP_CHAT_STREAM: &str = "deepseek.chat.completions_stream";
const OP_MODELS: &str = "deepseek.models.list";
const CAP_CHAT: &str = "deepseek.chat";
const CAP_MODELS: &str = "deepseek.models.read";

fn deepseek_api_key() -> Option<String> {
    std::env::var("DEEPSEEK_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
}

fn emit_live(event: &str, payload: &Value) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert("connector".into(), json!("fcp-deepseek"));
    object.insert("fixture_mode".into(), json!("live"));
    object.insert(
        "git_revision".into(),
        json!(option_env!("GIT_REVISION").unwrap_or("unknown")),
    );
    object.insert(
        "command_line".into(),
        json!(std::env::args().collect::<Vec<_>>().join(" ")),
    );
    if let Some(payload) = payload.as_object() {
        for (key, value) in payload {
            object.insert(key.clone(), value.clone());
        }
    }
    eprintln!("DEEPSEEK_E2E_JSONL {}", Value::Object(object));
}

fn generate_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    op: &str,
    cap: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:live-test")
        .operations(&[op])
        .issuer("node:live-test")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

async fn setup_live_connector(
    api_key: &str,
    capabilities: Vec<CapabilityId>,
) -> (DeepSeekConnector, Ed25519SigningKey) {
    let mut connector = DeepSeekConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "request_timeout_ms": 240_000,
            "default_model": "deepseek-v4-pro"
        }))
        .await
        .expect("configure with real API key should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(fcp_deepseek::connector::test_handshake_request(
            capabilities,
            verifying_key.to_bytes(),
        ))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn live_models_and_chat_shape() {
    let Some(api_key) = deepseek_api_key() else {
        emit_live(
            "deepseek_live_skipped",
            &json!({
                "status": "skipped",
                "skip_reason": "DEEPSEEK_API_KEY not set",
                "operation": "models+chat",
                "model_id": "deepseek-v4-flash,deepseek-v4-pro",
                "content_bytes": 0,
                "reasoning_content_bytes": 0,
                "stream_chunk_count": 0,
                "http_status": "not_dispatched",
                "retry_decision": "none",
                "error_mapping": "none",
                "cleanup_result": "skipped"
            }),
        );
        return;
    };

    let (connector, signing_key) = setup_live_connector(
        &api_key,
        vec![
            CapabilityId::from_static(CAP_MODELS),
            CapabilityId::from_static(CAP_CHAT),
        ],
    )
    .await;

    let models = connector
        .handle_invoke(json!({
            "operation": OP_MODELS,
            "input": {},
            "capability_token": generate_token(&signing_key, connector.instance_id(), OP_MODELS, CAP_MODELS)
        }))
        .await
        .expect("live models should succeed");
    assert!(
        models["data"]
            .as_array()
            .is_some_and(|models| !models.is_empty())
    );

    let non_reasoning = connector
        .handle_invoke(json!({
            "operation": OP_CHAT,
            "input": {
                "model": "deepseek-v4-flash",
                "messages": [{"role": "user", "content": "Reply with OK."}],
                "thinking": {"type": "disabled"},
                "max_tokens": 8
            },
            "capability_token": generate_token(&signing_key, connector.instance_id(), OP_CHAT, CAP_CHAT)
        }))
        .await
        .expect("live non-reasoning chat should succeed");
    assert!(non_reasoning["content_bytes"].as_u64().unwrap_or(0) > 0);

    let reasoning = connector
        .handle_invoke(json!({
            "operation": OP_CHAT,
            "input": {
                "model": "deepseek-v4-pro",
                "messages": [{"role": "user", "content": "What is 2+2? Answer briefly."}],
                "thinking": {"type": "enabled"},
                "reasoning_effort": "high",
                "max_tokens": 32
            },
            "capability_token": generate_token(&signing_key, connector.instance_id(), OP_CHAT, CAP_CHAT)
        }))
        .await
        .expect("live reasoning chat should succeed");
    assert!(reasoning["content_bytes"].as_u64().unwrap_or(0) > 0);

    emit_live(
        "deepseek_live_models_and_chat",
        &json!({
            "status": "passed",
            "operation": "models+chat",
            "model_id": "deepseek-v4-flash,deepseek-v4-pro",
            "content_bytes": non_reasoning["content_bytes"].as_u64().unwrap_or(0) + reasoning["content_bytes"].as_u64().unwrap_or(0),
            "reasoning_content_bytes": reasoning["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "connector-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn live_streaming_reasoning_shape() {
    let Some(api_key) = deepseek_api_key() else {
        emit_live(
            "deepseek_live_stream_skipped",
            &json!({
                "status": "skipped",
                "skip_reason": "DEEPSEEK_API_KEY not set",
                "operation": OP_CHAT_STREAM,
                "model_id": "deepseek-v4-pro",
                "content_bytes": 0,
                "reasoning_content_bytes": 0,
                "stream_chunk_count": 0,
                "http_status": "not_dispatched",
                "retry_decision": "none",
                "error_mapping": "none",
                "cleanup_result": "skipped"
            }),
        );
        return;
    };

    let (connector, signing_key) =
        setup_live_connector(&api_key, vec![CapabilityId::from_static(CAP_CHAT)]).await;
    let stream = connector
        .handle_invoke(json!({
            "operation": OP_CHAT_STREAM,
            "input": {
                "model": "deepseek-v4-pro",
                "messages": [{"role": "user", "content": "Count to three."}],
                "thinking": {"type": "enabled"},
                "reasoning_effort": "high",
                "max_tokens": 32
            },
            "capability_token": generate_token(&signing_key, connector.instance_id(), OP_CHAT_STREAM, CAP_CHAT)
        }))
        .await
        .expect("live streaming chat should succeed");

    assert!(stream["chunk_count"].as_u64().unwrap_or(0) > 0);
    assert!(stream["content_bytes"].as_u64().unwrap_or(0) > 0);
    emit_live(
        "deepseek_live_streaming_reasoning",
        &json!({
            "status": "passed",
            "operation": OP_CHAT_STREAM,
            "model_id": "deepseek-v4-pro",
            "content_bytes": stream["content_bytes"],
            "reasoning_content_bytes": stream["reasoning_content_bytes"],
            "stream_chunk_count": stream["chunk_count"],
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "connector-dropped"
        }),
    );
}
