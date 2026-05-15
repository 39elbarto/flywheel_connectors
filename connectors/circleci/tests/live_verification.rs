//! Environment-gated live verification for the `CircleCI` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_circleci::connector::CircleCiConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "CIRCLECI_SANDBOX_TOKEN";
const PROJECT_SLUG_ENV: &str = "CIRCLECI_SANDBOX_PROJECT_SLUG";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "fcp.circleci";
const CAP_PIPELINES_READ: &str = "circleci.pipelines.read";
const CAP_PIPELINES_WRITE: &str = "circleci.pipelines.write";
const CAP_WORKFLOWS_READ: &str = "circleci.workflows.read";
const CAP_WORKFLOWS_WRITE: &str = "circleci.workflows.write";
const CAP_JOBS_READ: &str = "circleci.jobs.read";
const CAP_PROJECTS_READ: &str = "circleci.projects.read";
const OP_PIPELINES_LIST: &str = "circleci.pipelines.list";
const OP_PROJECTS_LIST: &str = "circleci.projects.list";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("circleci", "CircleCI sandbox")
        .with_env_secret(
            "token",
            TOKEN_ENV,
            "CircleCI personal API token scoped to a sandbox project",
        )
        .with_env_var(
            PROJECT_SLUG_ENV,
            "CircleCI sandbox project slug such as gh/org/repo",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for the sandbox run",
        )
        .with_account_setup(
            "Use a dedicated CircleCI sandbox project. This suite lists projects and pipelines only; it does not trigger pipelines.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::None)
        .with_rate_limits(0.5, true)
        .with_metadata("request_categories", json!(["projects.list", "pipelines.list"]))
        .with_metadata("pipeline_triggered", json!(false))
}

#[fcp_async_core::runtime::test]
async fn live_verification_lists_projects_when_enabled() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            &env.evidence_summary(),
        );
        return;
    }

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let projects = invoke(&connector, &signing_key, OP_PROJECTS_LIST, json!({}))
        .await
        .expect("list live CircleCI projects");
    let project_count = projects["items"].as_array().map_or(0, Vec::len);
    let project_slug = env
        .env_vars
        .get(PROJECT_SLUG_ENV)
        .expect("project slug env is ready");
    let pipelines = invoke(
        &connector,
        &signing_key,
        OP_PIPELINES_LIST,
        json!({
            "project_slug": project_slug,
            "page_token": null
        }),
    )
    .await
    .expect("list live CircleCI pipelines");
    let pipeline_count = pipelines["items"].as_array().map_or(0, Vec::len);

    emit_live_jsonl(
        "passed",
        "projects.list and pipelines.list completed",
        project_count + pipeline_count,
        &json!({
            "environment": env.evidence_summary(),
            "project_count": project_count,
            "pipeline_count": pipeline_count,
            "operation_result": "circleci.projects.list and circleci.pipelines.list completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> CircleCiConnector {
    let mut connector = CircleCiConnector::new();
    connector
        .configure(json!({
            "api_token": env.secrets.require("token"),
            "base_url": "https://circleci.com/api/v2",
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
                CapabilityId::from_static(CAP_PIPELINES_READ),
                CapabilityId::from_static(CAP_PIPELINES_WRITE),
                CapabilityId::from_static(CAP_WORKFLOWS_READ),
                CapabilityId::from_static(CAP_WORKFLOWS_WRITE),
                CapabilityId::from_static(CAP_JOBS_READ),
                CapabilityId::from_static(CAP_PROJECTS_READ),
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
        OP_PIPELINES_LIST => CAP_PIPELINES_READ,
        OP_PROJECTS_LIST => CAP_PROJECTS_READ,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &CircleCiConnector,
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
        .principal("user:circleci-live")
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
    connector: &CircleCiConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("circleci-live-{operation}")),
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

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "CIRCLECI_LIVE_SANDBOX_JSONL {}",
        json!({
            "connector": "circleci",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [TOKEN_ENV],
            "required_env": [PROJECT_SLUG_ENV, NAMESPACE_ENV],
            "operation": [OP_PROJECTS_LIST, OP_PIPELINES_LIST],
            "status": status,
            "provider": "CircleCI sandbox",
            "environment": "sandbox",
            "resource_class": "project_and_pipeline_inventory",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one project inventory call and one sandbox project pipeline list.",
            "mutation_expected": false,
            "cleanup_strategy": "noop_read_only",
            "cleanup_result": "not_required",
            "provider_project_class": "dedicated_sandbox",
            "request_category": ["projects.list", "pipelines.list"],
            "pipeline_triggered": false,
            "dropped_or_budgeted_count": 0,
            "credential_material_logged": false,
            "project_slug_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}
