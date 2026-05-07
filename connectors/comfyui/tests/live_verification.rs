use chrono::{Duration as ChronoDuration, Utc};
use fcp_comfyui::connector::test_handshake_request;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, InstanceId};
use serde_json::{Value, json};

const OP_HEALTH: &str = "comfyui.health";
const CAP_HEALTH: &str = "comfyui.health.read";

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

#[fcp_async_core::runtime::test]
async fn comfyui_live_health_or_structured_skip_jsonl() {
    let git_revision =
        std::env::var("COMFYUI_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".into());
    let Some(base_url) = std::env::var("COMFYUI_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        emit_live_jsonl(&git_revision, "skipped", "COMFYUI_BASE_URL not set", None);
        return;
    };

    let mut connector = fcp_comfyui::ComfyUiConnector::new();
    let allowed_hosts = std::env::var("COMFYUI_ALLOWED_HOSTS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter(|host| !host.trim().is_empty())
                .map(|host| host.trim().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut config = serde_json::Map::new();
    config.insert("base_url".into(), json!(base_url));
    config.insert("allowed_hosts".into(), json!(allowed_hosts));
    config.insert("allow_private_ranges".into(), json!(true));
    config.insert("allow_tailnet_ranges".into(), json!(true));
    if let Ok(header) = std::env::var("COMFYUI_AUTHORIZATION_HEADER") {
        config.insert("authorization_header".into(), json!(header));
    }
    connector
        .handle_configure(Value::Object(config))
        .await
        .expect("configure live ComfyUI connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_HEALTH)],
            verifying_key.to_bytes(),
        ))
        .await
        .expect("handshake should succeed");
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_HEALTH, OP_HEALTH);
    let result = connector
        .handle_invoke(json!({
            "operation": OP_HEALTH,
            "input": {},
            "capability_token": capability_grant,
        }))
        .await;
    match result {
        Ok(value) => emit_live_jsonl(
            &git_revision,
            "passed",
            "",
            value.get("endpoint_class").and_then(Value::as_str),
        ),
        Err(error) => emit_live_jsonl(&git_revision, "failed", &error.to_string(), None),
    }
}

fn emit_live_jsonl(git_revision: &str, status: &str, reason: &str, endpoint_class: Option<&str>) {
    println!(
        "COMFYUI_E2E_JSONL {}",
        serde_json::json!({
            "event": "comfyui_live_health",
            "fixture_mode": "live",
            "git_revision": git_revision,
            "operation": OP_HEALTH,
            "status": status,
            "base_url_class": endpoint_class.unwrap_or("unknown"),
            "prompt_id_hash": null,
            "workflow_fixture_id": null,
            "output_count": 0,
            "http_status": if status == "passed" { Some(200) } else { None },
            "retry_decision": "not_needed",
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "cleanup_result": null,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
        })
    );
}
