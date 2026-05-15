#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_dockerhub::connector::DockerHubConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::SelfCheckStatus;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "DOCKERHUB_SANDBOX_TOKEN";
const USERNAME_ENV: &str = "DOCKERHUB_SANDBOX_USERNAME";
const BASE_URL_ENV: &str = "DOCKERHUB_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "DOCKERHUB_SANDBOX_NAMESPACE";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "fcp.dockerhub";
const CAP_REPOS_READ: &str = "dockerhub.repos.read";
const CAP_REPOS_WRITE: &str = "dockerhub.repos.write";
const OP_HEALTH: &str = "dockerhub.health";
const OP_REPOS_CREATE: &str = "dockerhub.repos.create";
const OP_REPOS_LIST: &str = "dockerhub.repos.list";
const OP_REPOS_GET: &str = "dockerhub.repos.get";
const OP_REPOS_DELETE: &str = "dockerhub.repos.delete";
const CALL_CEILING: usize = 6;

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("dockerhub", "Docker Hub sandbox")
        .with_env_secret(
            "token",
            TOKEN_ENV,
            "Docker Hub access token for a dedicated test account",
        )
        .with_env_var(USERNAME_ENV, "Docker Hub sandbox username for the test account")
        .with_env_var(
            NAMESPACE_ENV,
            "Disposable Docker Hub namespace or organization used for sandbox repositories",
        )
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic repository names for this run",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://hub.docker.com",
            "Docker Hub API endpoint",
        )
        .with_account_setup(
            "Use a dedicated Docker Hub test namespace. The token must create, list, get, and delete synthetic repositories.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
        .with_metadata(
            "request_categories",
            json!([
                "auth-denial",
                "health",
                "repos.create",
                "repos.list",
                "repos.delete",
                "cleanup.verify"
            ]),
        )
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "DOCKERHUB_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "dockerhub_live_sandbox_repository_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [TOKEN_ENV],
            "required_env": [USERNAME_ENV, NAMESPACE_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": [BASE_URL_ENV],
            "operation": [
                "auth-denial",
                OP_HEALTH,
                OP_REPOS_CREATE,
                OP_REPOS_LIST,
                OP_REPOS_DELETE,
                OP_REPOS_GET
            ],
            "status": status,
            "provider": "Docker Hub sandbox",
            "environment": "sandbox",
            "resource_class": "synthetic_repository",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token auth-denial probe, one health probe, one repository create, one repository list, one repository delete, and one cleanup verification lookup.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "health",
                "repos.create",
                "repos.list",
                "repos.delete",
                "cleanup.verify"
            ],
            "auth_denial_verified": auth_denial_verified,
            "namespace_logged": false,
            "username_logged": false,
            "repository_name_logged": false,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
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
async fn dockerhub_live_sandbox_repository_lifecycle_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let auth_denial_verified = invalid_token_is_denied(&env).await;
    assert!(
        auth_denial_verified,
        "Docker Hub invalid-token self-check must not report healthy"
    );

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("Docker Hub namespace env is ready");
    let run_namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("run namespace env is ready");
    let repo_name = sandbox_repo_name(run_namespace);
    let repo_hash = redacted_hash(&repo_name);

    if let Err(error) = invoke(&connector, &signing_key, OP_HEALTH, json!({})).await {
        emit_live_jsonl(
            "failed",
            &error.to_string(),
            0,
            "not_started",
            auth_denial_verified,
            &env.evidence_summary(),
        );
        panic!("Docker Hub sandbox health probe failed: {error}");
    }

    if let Err(error) = invoke(
        &connector,
        &signing_key,
        OP_REPOS_CREATE,
        json!({
            "namespace": namespace,
            "name": repo_name.as_str(),
            "description": "FCP Docker Hub live verification repository",
            "is_private": false
        }),
    )
    .await
    {
        emit_live_jsonl(
            "failed",
            &error.to_string(),
            0,
            "create_failed",
            auth_denial_verified,
            &json!({
                "environment": env.evidence_summary(),
                "repository_name_hash": repo_hash,
            }),
        );
        panic!("Docker Hub sandbox repository create failed: {error}");
    }

    let mut observed_count = 0;
    let mut created_visible = false;
    let mut proof_error = None;
    match invoke(
        &connector,
        &signing_key,
        OP_REPOS_LIST,
        json!({ "namespace": namespace }),
    )
    .await
    {
        Ok(repos) => {
            if let Some(items) = repos.as_array() {
                observed_count = items.len();
                created_visible = items.iter().any(|repo| {
                    repo.get("name").and_then(Value::as_str) == Some(repo_name.as_str())
                        && repo.get("namespace").and_then(Value::as_str) == Some(namespace)
                });
            }
            if !created_visible {
                proof_error = Some("created repository was not visible in repos.list".to_string());
            }
        }
        Err(error) => {
            proof_error = Some(error.to_string());
        }
    }

    let mut cleanup_result;
    match invoke(
        &connector,
        &signing_key,
        OP_REPOS_DELETE,
        json!({ "namespace": namespace, "name": repo_name.as_str() }),
    )
    .await
    {
        Ok(_deleted) => {
            cleanup_result = "delete_completed";
        }
        Err(error) => {
            cleanup_result = "delete_failed";
            if proof_error.is_none() {
                proof_error = Some(error.to_string());
            }
        }
    }

    if cleanup_result == "delete_completed" {
        match invoke(
            &connector,
            &signing_key,
            OP_REPOS_GET,
            json!({ "namespace": namespace, "name": repo_name.as_str() }),
        )
        .await
        {
            Err(FcpError::ResourceNotFound { .. }) => {
                cleanup_result = "delete_verified_not_found";
            }
            Err(error) => {
                cleanup_result = "delete_verification_failed";
                if proof_error.is_none() {
                    proof_error = Some(error.to_string());
                }
            }
            Ok(_repo) => {
                cleanup_result = "delete_not_verified";
                if proof_error.is_none() {
                    proof_error = Some("deleted repository remained fetchable".to_string());
                }
            }
        }
    }

    if let Some(error) = proof_error {
        emit_live_jsonl(
            "failed",
            &error,
            observed_count,
            cleanup_result,
            auth_denial_verified,
            &json!({
                "environment": env.evidence_summary(),
                "repository_name_hash": repo_hash,
                "created_visible": created_visible,
            }),
        );
        panic!("Docker Hub sandbox repository lifecycle failed: {error}");
    }

    emit_live_jsonl(
        "passed",
        "repository lifecycle completed",
        observed_count,
        cleanup_result,
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "repository_name_hash": repo_hash,
            "created_visible": created_visible,
            "operation_result": "auth denial, health, repos.create, repos.list, repos.delete, and cleanup verification completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> DockerHubConnector {
    let mut connector = DockerHubConnector::new();
    connector
        .configure(json!({
            "mode": "token",
            "access_token": env.secrets.require("token"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "namespace": env.env_vars.get(NAMESPACE_ENV).expect("Docker Hub namespace env is ready"),
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure Docker Hub live connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_REPOS_READ),
                CapabilityId::from_static(CAP_REPOS_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake Docker Hub live connector");
    connector
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let mut connector = DockerHubConnector::new();
    connector
        .configure(json!({
            "mode": "token",
            "access_token": "fcp-live-verification-invalid-token",
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure invalid-token Docker Hub connector");

    match connector.self_check().await {
        Ok(report) => report.status != SelfCheckStatus::Ok,
        Err(_error) => true,
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_HEALTH | OP_REPOS_GET | OP_REPOS_LIST => CAP_REPOS_READ,
        OP_REPOS_CREATE | OP_REPOS_DELETE => CAP_REPOS_WRITE,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &DockerHubConnector,
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
        .principal("user:dockerhub-live")
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
    connector: &DockerHubConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("dockerhub-live-{operation}")),
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

fn sandbox_repo_name(run_namespace: &str) -> String {
    let mut sanitized = String::with_capacity(run_namespace.len().min(32));
    let mut last_was_dash = false;
    for character in run_namespace.chars() {
        let next = if character.is_ascii_alphanumeric() {
            character.to_ascii_lowercase()
        } else {
            '-'
        };
        if next == '-' {
            if !last_was_dash && !sanitized.is_empty() {
                sanitized.push('-');
                last_was_dash = true;
            }
        } else {
            sanitized.push(next);
            last_was_dash = false;
        }
        if sanitized.len() >= 32 {
            break;
        }
    }
    while sanitized.ends_with('-') {
        sanitized.pop();
    }
    if sanitized.is_empty() {
        sanitized.push_str("run");
    }
    format!("fcp-{sanitized}-{}", Utc::now().timestamp_millis())
}

fn redacted_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let encoded = hex::encode(digest);
    let short_hash = encoded.chars().take(16).collect::<String>();
    format!("sha256:{short_hash}")
}
