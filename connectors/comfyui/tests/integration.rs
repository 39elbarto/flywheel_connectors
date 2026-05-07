#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_comfyui::client::{
    ComfyUiUrlPolicy, DEFAULT_BASE_URL, classify_comfyui_base_url, normalize_comfyui_base_url,
};
use fcp_comfyui::connector::test_handshake_request;
use fcp_comfyui::types::{
    ComfyImage, HistoryResponse, artifacts_from_history, status_from_history, validate_client_id,
    validate_prompt_id, validate_workflow_json, view_url,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_SUBMIT: &str = "comfyui.workflow.submit";
const OP_STATUS: &str = "comfyui.workflow.status";
const OP_RESULT: &str = "comfyui.workflow.result";
const OP_CANCEL: &str = "comfyui.workflow.cancel";
const OP_WAIT: &str = "comfyui.workflow.wait_until_complete";
const OP_HEALTH: &str = "comfyui.health";

const CAP_RUN: &str = "comfyui.workflow.run";
const CAP_READ: &str = "comfyui.workflow.read";
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

async fn configured_connector(
    server: &MockServer,
    capabilities: &[&'static str],
    extra_config: Value,
) -> (fcp_comfyui::ComfyUiConnector, Ed25519SigningKey) {
    let mut connector = fcp_comfyui::ComfyUiConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("base_url".into(), json!(server.uri()));
    config.insert("authorization_header".into(), json!("Bearer comfy-secret"));
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
    let verifying_key = signing_key.verifying_key();
    let caps = capabilities
        .iter()
        .map(|cap| CapabilityId::from_static(cap))
        .collect();
    connector
        .handshake(test_handshake_request(caps, verifying_key.to_bytes()))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn invoke(
    connector: &fcp_comfyui::ComfyUiConnector,
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

#[test]
fn url_auth_and_payload_validation_enforce_self_hosted_policy() {
    let default_policy = ComfyUiUrlPolicy::default();
    assert_eq!(
        normalize_comfyui_base_url(None, &default_policy).unwrap(),
        DEFAULT_BASE_URL
    );
    assert!(normalize_comfyui_base_url(Some("https://api.example.com"), &default_policy).is_err());
    assert!(
        normalize_comfyui_base_url(
            Some("http://10.0.0.5:8188"),
            &ComfyUiUrlPolicy::new(false, vec!["10.0.0.5".into()], false, false),
        )
        .is_err()
    );
    assert_eq!(
        normalize_comfyui_base_url(
            Some("http://10.0.0.5:8188"),
            &ComfyUiUrlPolicy::new(false, vec!["10.0.0.5".into()], true, false),
        )
        .unwrap(),
        "http://10.0.0.5:8188"
    );
    assert!(
        normalize_comfyui_base_url(
            Some("https://studio.tailnet.ts.net"),
            &ComfyUiUrlPolicy::new(true, vec!["studio.tailnet.ts.net".into()], false, false),
        )
        .is_err()
    );
    assert_eq!(
        normalize_comfyui_base_url(
            Some("https://studio.tailnet.ts.net"),
            &ComfyUiUrlPolicy::new(true, vec!["studio.tailnet.ts.net".into()], false, true),
        )
        .unwrap(),
        "https://studio.tailnet.ts.net"
    );
    assert_eq!(
        classify_comfyui_base_url("https://studio.tailnet.ts.net"),
        "tailnet_dns"
    );
    assert!(validate_prompt_id("prompt-123_ok").is_ok());
    assert!(validate_prompt_id("../prompt").is_err());
    assert!(validate_client_id("fcp-client").is_ok());
    assert!(validate_client_id("bad\nclient").is_err());
    assert!(validate_workflow_json(&json!({"3": {"class_type": "KSampler"}})).is_ok());
    assert!(validate_workflow_json(&json!(["not", "a", "workflow"])).is_err());
}

#[test]
fn history_parsing_and_view_url_builder_return_metadata_only() {
    let history: HistoryResponse = serde_json::from_value(json!({
        "prompt-123": {
            "status": {"status_str": "success"},
            "outputs": {
                "9": {
                    "images": [
                        {"filename": "image.png", "subfolder": "safe-folder", "type": "output"}
                    ]
                }
            }
        }
    }))
    .expect("history should parse");
    let status = status_from_history("prompt-123", &history);
    assert!(status.complete);
    assert_eq!(status.output_count, 1);
    let artifacts = artifacts_from_history("http://localhost:8188", "prompt-123", &history)
        .expect("view URL should build");
    assert_eq!(artifacts.len(), 1);
    assert!(artifacts[0].url.contains("/view?filename=image.png"));
    assert_eq!(artifacts[0].url_host_class, "loopback");
    assert!(
        view_url(
            "http://localhost:8188",
            &ComfyImage {
                filename: "bad\0.png".into(),
                subfolder: String::new(),
                kind: "output".into(),
            },
        )
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn submit_status_result_cancel_wait_health_and_redaction_work() {
    let server = MockServer::start().await;
    mount_comfyui_cycle(&server).await;
    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_RUN, CAP_READ, CAP_HEALTH],
        json!({ "poll_interval_ms": 1 }),
    )
    .await;

    let submit = invoke(
        &connector,
        &signing_key,
        OP_SUBMIT,
        CAP_RUN,
        json!({
            "workflow": {"3": {"class_type": "KSampler", "inputs": {"prompt": "private prompt"}}},
            "client_id": "fcp-test-client"
        }),
    )
    .await
    .expect("submit should succeed");
    let status = invoke(
        &connector,
        &signing_key,
        OP_STATUS,
        CAP_READ,
        json!({"prompt_id": "prompt-123"}),
    )
    .await
    .expect("status should succeed");
    let result = invoke(
        &connector,
        &signing_key,
        OP_RESULT,
        CAP_READ,
        json!({"prompt_id": "prompt-123"}),
    )
    .await
    .expect("result should succeed");
    let wait = invoke(
        &connector,
        &signing_key,
        OP_WAIT,
        CAP_READ,
        json!({"prompt_id": "prompt-123", "timeout_ms": 1000, "poll_interval_ms": 1}),
    )
    .await
    .expect("wait should succeed");
    let cancel = invoke(
        &connector,
        &signing_key,
        OP_CANCEL,
        CAP_RUN,
        json!({"prompt_id": "prompt-123", "interrupt_running": true}),
    )
    .await
    .expect("cancel should succeed");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should succeed");

    assert_eq!(submit["prompt_id"], "prompt-123");
    assert_eq!(status["complete"], true);
    assert_eq!(result["output_count"], 1);
    assert_eq!(wait["complete"], true);
    assert_eq!(cancel["cancel_requested"], true);
    assert_eq!(health["status"], "ok");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("comfy-secret"));
}

#[fcp_async_core::runtime::test]
async fn comfyui_loopback_e2e_jsonl_matrix() {
    let server = MockServer::start().await;
    mount_comfyui_cycle(&server).await;
    let git_revision =
        std::env::var("COMFYUI_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".into());
    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_RUN, CAP_READ, CAP_HEALTH],
        json!({ "poll_interval_ms": 1 }),
    )
    .await;
    let workflow_fixture =
        json!({"3": {"class_type": "SaveImage", "inputs": {"filename_prefix": "fcp"}}});
    let submit = invoke(
        &connector,
        &signing_key,
        OP_SUBMIT,
        CAP_RUN,
        json!({"workflow": workflow_fixture, "client_id": "jsonl-fixture"}),
    )
    .await
    .expect("submit should succeed");
    let result = invoke(
        &connector,
        &signing_key,
        OP_RESULT,
        CAP_READ,
        json!({"prompt_id": "prompt-123"}),
    )
    .await
    .expect("result should succeed");
    let cancel = invoke(
        &connector,
        &signing_key,
        OP_CANCEL,
        CAP_RUN,
        json!({"prompt_id": "prompt-123"}),
    )
    .await
    .expect("cancel should succeed");

    for (operation, status, output_count) in [
        (OP_SUBMIT, "submitted", 0_u64),
        (
            OP_RESULT,
            "succeeded",
            result["output_count"].as_u64().unwrap_or(0),
        ),
        (OP_CANCEL, "cleanup_requested", 0_u64),
    ] {
        println!(
            "COMFYUI_E2E_JSONL {}",
            serde_json::json!({
                "event": "comfyui_loopback_fixture",
                "fixture_mode": "wiremock",
                "git_revision": git_revision,
                "operation": operation,
                "status": status,
                "prompt_id_hash": blake3_hex("prompt-123"),
                "workflow_fixture_id": "minimal-save-image",
                "base_url_class": "loopback",
                "output_count": output_count,
                "http_status": 200,
                "retry_decision": "not_needed",
                "fcp_error_mapping": null,
                "cleanup_result": cancel["cancel_requested"],
                "skip_reason": null,
            })
        );
    }
    assert_eq!(submit["prompt_id"], "prompt-123");
}

async fn mount_comfyui_cycle(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/prompt"))
        .and(header("authorization", "Bearer comfy-secret"))
        .and(body_partial_json(json!({"client_id": "fcp-test-client"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompt_id": "prompt-123",
            "number": 1
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/prompt"))
        .and(body_partial_json(json!({"client_id": "jsonl-fixture"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompt_id": "prompt-123",
            "number": 1
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/history/prompt-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "prompt-123": {
                "status": {"status_str": "success", "completed": true},
                "outputs": {
                    "9": {
                        "images": [
                            {"filename": "output.png", "subfolder": "fcp", "type": "output"}
                        ]
                    }
                }
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/queue"))
        .and(body_partial_json(json!({"delete": ["prompt-123"]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"deleted": ["prompt-123"]})))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/interrupt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"interrupted": true})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/system_stats"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "system": {"python_version": "3.12"},
            "devices": []
        })))
        .mount(server)
        .await;
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}
