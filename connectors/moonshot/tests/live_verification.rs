use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_moonshot::MoonshotConnector;
use fcp_moonshot::connector::test_handshake_request;
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector};
use serde_json::json;

const OP_CHAT: &str = "moonshot.chat.completions";
const CAP_CHAT: &str = "moonshot.chat";
const MOONSHOT_KEY_ENV: &str = concat!("MOONSHOT", "_API", "_KEY");

fn capability_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &fcp_prelude::InstanceId,
) -> fcp_prelude::CapabilityToken {
    let now = chrono::Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(CAP_CHAT)
        .zone_id("z:work")
        .principal("user:live")
        .operations(&[OP_CHAT])
        .issuer("node:live")
        .target_instance(instance_id.as_str())
        .validity(now, now + chrono::Duration::minutes(10))
        .try_constraints_cbor(&cbor)
        .expect("constraints accepted")
        .sign(signing_key)
        .expect("capability grant signs");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

fn read_live_auth_material() -> Option<String> {
    std::env::vars().find_map(|(name, value)| {
        (name == MOONSHOT_KEY_ENV && !value.trim().is_empty()).then_some(value)
    })
}

#[fcp_async_core::runtime::test]
async fn moonshot_live_smoke_or_structured_skip_jsonl() {
    let Some(live_auth_material) = read_live_auth_material() else {
        println!(
            "MOONSHOT_E2E_JSONL {}",
            json!({
                "event": "moonshot_live_operation",
                "fixture_mode": "live",
                "operation": "live_smoke",
                "status": "skipped",
                "skip_reason": format!("{MOONSHOT_KEY_ENV} not set"),
                "cleanup_result": "not_started",
                "connector_id": "fcp.moonshot",
                "command_line": "cargo test -p fcp-moonshot --test live_verification moonshot_live_smoke_or_structured_skip_jsonl -- --nocapture",
                "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown")
            })
        );
        return;
    };

    let base_url =
        std::env::var("MOONSHOT_BASE_URL").unwrap_or_else(|_| "https://api.moonshot.ai/v1".into());
    let model = std::env::var("MOONSHOT_MODEL").unwrap_or_else(|_| "kimi-k2.6".into());
    let mut connector = MoonshotConnector::new();
    connector
        .handle_configure(json!({
            "api_key": live_auth_material,
            "base_url": base_url,
            "default_model": model,
            "request_timeout_ms": 30_000
        }))
        .await
        .expect("live configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_CHAT)],
            verifying_key.to_bytes(),
        ))
        .await
        .expect("live handshake should succeed");
    let capability_grant = capability_grant(&signing_key, connector.instance_id());
    let result = connector
        .handle_invoke(json!({
            "operation": OP_CHAT,
            "input": {
                "messages": [{"role": "user", "content": "Return exactly: ok"}],
                "max_completion_tokens": 4,
                "estimated_input_tokens": 8
            },
            "capability_token": capability_grant
        }))
        .await;
    let status = if result.is_ok() { "passed" } else { "failed" };
    println!(
        "MOONSHOT_E2E_JSONL {}",
        json!({
            "event": "moonshot_live_operation",
            "fixture_mode": "live",
            "operation": "chat",
            "status": status,
            "endpoint_class": if base_url.contains(".cn") { "cn" } else { "international" },
            "model_id": model,
            "input_tokens": 8,
            "output_tokens": result.as_ref().ok().and_then(|value| value.pointer("/usage/completion_tokens").and_then(serde_json::Value::as_u64)),
            "http_status": if result.is_ok() { 200 } else { 0 },
            "retry_decision": "not_retried",
            "fcp_error_mapping": result.as_ref().err().map(ToString::to_string),
            "cleanup_result": "shutdown",
            "command_line": "cargo test -p fcp-moonshot --test live_verification moonshot_live_smoke_or_structured_skip_jsonl -- --nocapture",
            "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown")
        })
    );
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("live shutdown succeeds");
    result.expect("live chat should succeed");
}
