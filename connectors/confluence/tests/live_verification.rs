//! Environment-gated live verification for the `Confluence` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_confluence::connector::ConfluenceConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const BASE_URL_ENV: &str = "CONFLUENCE_SANDBOX_BASE_URL";
const EMAIL_ENV: &str = "CONFLUENCE_SANDBOX_EMAIL";
const TOKEN_ENV: &str = "CONFLUENCE_SANDBOX_API_TOKEN";
const SPACE_KEY_ENV: &str = "CONFLUENCE_SANDBOX_SPACE_KEY";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "fcp.confluence";
const CAP_SPACES_READ: &str = "confluence.spaces.read";
const CAP_PAGES_READ: &str = "confluence.pages.read";
const CAP_PAGES_WRITE: &str = "confluence.pages.write";
const OP_PAGES_LIST: &str = "confluence.pages.list";
const OP_SPACES_LIST: &str = "confluence.spaces.list";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.1";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("confluence", "Confluence sandbox")
        .with_env_secret(
            "api_token",
            TOKEN_ENV,
            "Confluence API token scoped to a dedicated sandbox space",
        )
        .with_env_var(BASE_URL_ENV, "Confluence sandbox site base URL")
        .with_env_var(EMAIL_ENV, "Confluence sandbox account email")
        .with_env_var(
            SPACE_KEY_ENV,
            "Confluence sandbox space key used for bounded page-list proof",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a dedicated Confluence sandbox site and space. This suite performs read-only space and page listings; page create/update/delete belongs in a separate namespaced mutation flow.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    space_count: usize,
    page_count: usize,
    evidence: &Value,
) {
    eprintln!(
        "CONFLUENCE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "confluence_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [BASE_URL_ENV, EMAIL_ENV, SPACE_KEY_ENV, NAMESPACE_ENV],
            "operation": [OP_SPACES_LIST, OP_PAGES_LIST],
            "bead_id": BEAD_ID,
            "status": status,
            "provider": "Confluence sandbox",
            "environment": "sandbox",
            "resource_class": "space_and_page_listing",
            "space_count": space_count,
            "page_count": page_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one space listing and one page listing against a sandbox space.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "email_logged": false,
            "space_key_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

#[fcp_async_core::runtime::test]
async fn confluence_live_sandbox_spaces_and_pages_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            0,
            &env.evidence_summary(),
        );
        return;
    }

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let spaces = match invoke(
        &connector,
        &signing_key,
        OP_SPACES_LIST,
        json!({"start": 0, "limit": 1}),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, 0, &env.evidence_summary());
            panic!("Confluence sandbox space listing failed: {error}");
        }
    };
    env.budget.record_api_call(OP_SPACES_LIST, 0.0);
    let space_count = spaces["results"].as_array().map_or(0, Vec::len);

    let pages = match invoke(
        &connector,
        &signing_key,
        OP_PAGES_LIST,
        json!({
            "space_key": env.env_vars.get(SPACE_KEY_ENV).expect("space key env is ready"),
            "start": 0,
            "limit": 1
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                space_count,
                0,
                &env.evidence_summary(),
            );
            panic!("Confluence sandbox page listing failed: {error}");
        }
    };
    env.budget.record_api_call(OP_PAGES_LIST, 0.0);
    let page_count = pages["results"].as_array().map_or(0, Vec::len);

    emit_live_jsonl(
        "passed",
        "",
        space_count,
        page_count,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "spaces.list and pages.list completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> ConfluenceConnector {
    let mut connector = ConfluenceConnector::new();
    connector
        .configure(json!({
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "email": env.env_vars.get(EMAIL_ENV).expect("email env is ready"),
            "api_token": env.secrets.require("api_token"),
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure live connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SPACES_READ),
                CapabilityId::from_static(CAP_PAGES_READ),
                CapabilityId::from_static(CAP_PAGES_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake live connector");
    connector
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_SPACES_LIST => CAP_SPACES_READ,
        OP_PAGES_LIST => CAP_PAGES_READ,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &ConfluenceConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:confluence-live")
        .operations(&[operation])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &ConfluenceConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("confluence-live-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_for(connector, signing_key, operation),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await?;
    assert_eq!(response.status, InvokeStatus::Ok);
    Ok(response.result.expect("successful response has result"))
}
