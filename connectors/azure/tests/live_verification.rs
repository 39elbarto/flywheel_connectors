#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use std::time::Duration as StdDuration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{Duration as ChronoDuration, Utc};
use fcp_azure::connector::AzureConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpError, HandshakeRequest,
    InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::FcpConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TENANT_ID_ENV: &str = "AZURE_SANDBOX_TENANT_ID";
const CLIENT_ID_ENV: &str = "AZURE_SANDBOX_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "AZURE_SANDBOX_CLIENT_SECRET";
const SUBSCRIPTION_ID_ENV: &str = "AZURE_SANDBOX_SUBSCRIPTION_ID";
const RESOURCE_GROUP_ENV: &str = "AZURE_SANDBOX_RESOURCE_GROUP";
const STORAGE_ACCOUNT_ENV: &str = "AZURE_SANDBOX_STORAGE_ACCOUNT";
const CONTAINER_ENV: &str = "AZURE_SANDBOX_CONTAINER";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const AUTHORITY_HOST_ENV: &str = "AZURE_SANDBOX_AUTHORITY_HOST";
const CAP_STORAGE_READ: &str = "azure.storage.read";
const CAP_STORAGE_WRITE: &str = "azure.storage.write";
const OP_BLOB_LIST_BLOBS: &str = "azure.storage.blob_list_blobs";
const OP_BLOB_GET: &str = "azure.storage.blob_get";
const OP_BLOB_PUT: &str = "azure.storage.blob_put";
const OP_BLOB_DELETE: &str = "azure.storage.blob_delete";
const CALL_CEILING: usize = 6;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-azure --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("azure", "Microsoft Azure sandbox")
        .with_env_secret(
            "client_secret",
            CLIENT_SECRET_ENV,
            "Azure sandbox service-principal client secret",
        )
        .with_env_var(TENANT_ID_ENV, "Azure sandbox tenant id")
        .with_env_var(CLIENT_ID_ENV, "Azure sandbox service-principal client id")
        .with_env_var(SUBSCRIPTION_ID_ENV, "Azure sandbox subscription id")
        .with_env_var(RESOURCE_GROUP_ENV, "Azure sandbox resource group name")
        .with_env_var(STORAGE_ACCOUNT_ENV, "Azure sandbox Storage account name")
        .with_env_var(CONTAINER_ENV, "Azure sandbox Blob Storage container")
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic blob names for this run",
        )
        .with_env_var_default(
            AUTHORITY_HOST_ENV,
            "https://login.microsoftonline.com",
            "Azure OAuth authority host for client-credentials token exchange",
        )
        .with_account_setup(
            "Use a dedicated Azure tenant, subscription, resource group, Storage account, and container. The service principal must only list, read, write, and delete synthetic blobs in the sandbox container.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
        .with_metadata(
            "request_categories",
            json!([
                "token.exchange",
                "auth-denial",
                "blob.put",
                "blob.list",
                "blob.delete",
                "cleanup.verify"
            ]),
        )
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    token_acquired: bool,
    auth_denial_verified: bool,
    evidence: &Value,
) {
    eprintln!(
        "AZURE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "azure_live_sandbox_blob_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [CLIENT_SECRET_ENV],
            "required_env": [
                TENANT_ID_ENV,
                CLIENT_ID_ENV,
                SUBSCRIPTION_ID_ENV,
                RESOURCE_GROUP_ENV,
                STORAGE_ACCOUNT_ENV,
                CONTAINER_ENV,
                RUN_NAMESPACE_ENV
            ],
            "defaulted_env": AUTHORITY_HOST_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "token.exchange",
                "auth-denial",
                OP_BLOB_PUT,
                OP_BLOB_LIST_BLOBS,
                OP_BLOB_DELETE,
                OP_BLOB_GET
            ],
            "status": status,
            "provider": "Microsoft Azure sandbox",
            "environment": "sandbox",
            "resource_class": "synthetic_blob",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one client-credentials token exchange, one invalid-token denial probe, one blob put, one prefix list, one delete, and one post-delete get verification.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "token.exchange",
                "auth-denial",
                "blob.put",
                "blob.list",
                "blob.delete",
                "cleanup.verify"
            ],
            "token_acquired": token_acquired,
            "auth_denial_verified": auth_denial_verified,
            "tenant_id_logged": false,
            "client_id_logged": false,
            "subscription_id_logged": false,
            "resource_group_logged": false,
            "storage_account_logged": false,
            "container_logged": false,
            "blob_name_logged": false,
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

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[fcp_async_core::runtime::test]
async fn azure_live_sandbox_blob_lifecycle_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            false,
            false,
            &env.evidence_summary(),
        );
        return;
    }

    let tenant_id = env
        .env_vars
        .get(TENANT_ID_ENV)
        .expect("Azure tenant env is ready");
    let subscription_id = env
        .env_vars
        .get(SUBSCRIPTION_ID_ENV)
        .expect("Azure subscription env is ready");
    let resource_group = env
        .env_vars
        .get(RESOURCE_GROUP_ENV)
        .expect("Azure resource group env is ready");
    let storage_account = env
        .env_vars
        .get(STORAGE_ACCOUNT_ENV)
        .expect("Azure storage account env is ready");
    let container = env
        .env_vars
        .get(CONTAINER_ENV)
        .expect("Azure container env is ready");
    let run_namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("run namespace env is ready");
    let blob_name = sandbox_blob_name(run_namespace);
    let blob_prefix = blob_name
        .rsplit_once('/')
        .map(|(prefix, _name)| format!("{prefix}/"))
        .unwrap_or_default();
    let blob_name_hash = redacted_hash(&blob_name);
    let blob_body = BASE64.encode(format!(
        "FCP Azure live verification blob {blob_name_hash}\n"
    ));

    let auth_denial_verified =
        invalid_bearer_token_is_denied(storage_account, container, &blob_prefix).await;
    assert!(
        auth_denial_verified,
        "Azure invalid-token blob list must be denied"
    );

    let token = match acquire_storage_bearer_token(&env).await {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error,
                0,
                "not_started",
                false,
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "tenant_id_hash": redacted_hash(tenant_id),
                    "subscription_id_hash": redacted_hash(subscription_id),
                    "resource_group_hash": redacted_hash(resource_group),
                    "storage_account_hash": redacted_hash(storage_account),
                    "container_hash": redacted_hash(container),
                    "blob_name_hash": blob_name_hash,
                }),
            );
            panic!("Azure sandbox token exchange failed: {error}");
        }
    };

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let connector = configured_connector(&token, &signing_key, &instance_id).await;
    let mut proof_error = None;
    let mut observed_count = 0;
    let mut created = false;
    let mut created_visible = false;
    let mut cleanup_result = "not_started";

    if let Err(error) = invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_BLOB_PUT,
        json!({
            "storage_account": storage_account,
            "container": container,
            "blob_name": blob_name.as_str(),
            "content_base64": blob_body,
            "content_type": "text/plain"
        }),
    )
    .await
    {
        proof_error = Some(safe_error_reason(&error));
    } else {
        created = true;
    }

    if proof_error.is_none() {
        match invoke(
            &connector,
            &signing_key,
            &instance_id,
            OP_BLOB_LIST_BLOBS,
            json!({
                "storage_account": storage_account,
                "container": container,
                "prefix": blob_prefix.as_str()
            }),
        )
        .await
        {
            Ok(value) => {
                if let Some(blobs) = value.get("blobs").and_then(Value::as_array) {
                    observed_count = blobs.len();
                    created_visible = blobs.iter().any(|blob| {
                        blob.get("name").and_then(Value::as_str) == Some(blob_name.as_str())
                    });
                }
                if !created_visible {
                    proof_error = Some("created_blob_not_visible_in_list_blobs".to_string());
                }
            }
            Err(error) => {
                proof_error = Some(safe_error_reason(&error));
            }
        }
    }

    if created {
        match invoke(
            &connector,
            &signing_key,
            &instance_id,
            OP_BLOB_DELETE,
            json!({
                "storage_account": storage_account,
                "container": container,
                "blob_name": blob_name.as_str()
            }),
        )
        .await
        {
            Ok(_value) => {
                cleanup_result = "delete_completed";
            }
            Err(error) => {
                cleanup_result = "delete_failed";
                if proof_error.is_none() {
                    proof_error = Some(safe_error_reason(&error));
                }
            }
        }
    }

    if cleanup_result == "delete_completed" {
        match invoke(
            &connector,
            &signing_key,
            &instance_id,
            OP_BLOB_GET,
            json!({
                "storage_account": storage_account,
                "container": container,
                "blob_name": blob_name.as_str()
            }),
        )
        .await
        {
            Err(FcpError::ResourceNotFound { .. }) => {
                cleanup_result = "delete_verified_not_found";
            }
            Err(error) => {
                cleanup_result = "delete_verification_failed";
                if proof_error.is_none() {
                    proof_error = Some(safe_error_reason(&error));
                }
            }
            Ok(_value) => {
                cleanup_result = "delete_not_verified";
                if proof_error.is_none() {
                    proof_error = Some("deleted_blob_remained_fetchable".to_string());
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
            true,
            auth_denial_verified,
            &json!({
                "environment": env.evidence_summary(),
                "tenant_id_hash": redacted_hash(tenant_id),
                "client_id_hash": redacted_hash(env.env_vars.get(CLIENT_ID_ENV).expect("client id env is ready")),
                "subscription_id_hash": redacted_hash(subscription_id),
                "resource_group_hash": redacted_hash(resource_group),
                "storage_account_hash": redacted_hash(storage_account),
                "container_hash": redacted_hash(container),
                "blob_name_hash": blob_name_hash,
                "created_visible": created_visible,
            }),
        );
        panic!("Azure sandbox blob lifecycle failed: {error}");
    }

    emit_live_jsonl(
        "passed",
        "Blob lifecycle completed",
        observed_count,
        cleanup_result,
        true,
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "tenant_id_hash": redacted_hash(tenant_id),
            "client_id_hash": redacted_hash(env.env_vars.get(CLIENT_ID_ENV).expect("client id env is ready")),
            "subscription_id_hash": redacted_hash(subscription_id),
            "resource_group_hash": redacted_hash(resource_group),
            "storage_account_hash": redacted_hash(storage_account),
            "container_hash": redacted_hash(container),
            "blob_name_hash": blob_name_hash,
            "created_visible": created_visible,
            "operation_result": "token exchange, auth denial, blob put, blob list, blob delete, and cleanup verification completed",
        }),
    );
}

async fn acquire_storage_bearer_token(env: &LiveEnvironment) -> Result<String, String> {
    let authority_host = env
        .env_vars
        .get(AUTHORITY_HOST_ENV)
        .expect("Azure authority host env is ready")
        .trim_end_matches('/');
    let tenant_id = env
        .env_vars
        .get(TENANT_ID_ENV)
        .expect("Azure tenant env is ready");
    let client_id = env
        .env_vars
        .get(CLIENT_ID_ENV)
        .expect("Azure client id env is ready");
    let client_secret = env.secrets.require("client_secret");
    let token_url = format!("{authority_host}/{tenant_id}/oauth2/v2.0/token");
    let form = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://storage.azure.com/.default"),
        ("grant_type", "client_credentials"),
    ];
    let body =
        serde_urlencoded::to_string(form).map_err(|_| "token_request_form_failed".to_string())?;

    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(10))
        .build()
        .map_err(|_| "token_client_init_failed".to_string())?;
    let response = client
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "token_request_timeout".to_string()
            } else if error.is_connect() {
                "token_request_connect_failed".to_string()
            } else {
                "token_request_failed".to_string()
            }
        })?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|_| "token_response_read_failed".to_string())?;
    if !status.is_success() {
        return Err(format!("token_endpoint_status_{}", status.as_u16()));
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).map_err(|_| "token_response_parse_failed".to_string())?;
    if parsed.access_token.trim().is_empty() {
        return Err("token_response_missing_access_token".to_string());
    }
    Ok(parsed.access_token)
}

async fn configured_connector(
    bearer_token: &str,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> AzureConnector {
    let mut connector = AzureConnector::new();
    connector
        .configure(json!({
            "mode": "bearer_token",
            "bearer_token": bearer_token,
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure Azure sandbox credentials");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [47_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_STORAGE_READ),
                CapabilityId::from_static(CAP_STORAGE_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: Some(instance_id.clone()),
        })
        .await
        .expect("handshake Azure sandbox connector");
    connector
}

async fn invalid_bearer_token_is_denied(
    storage_account: &str,
    container: &str,
    prefix: &str,
) -> bool {
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let connector = configured_connector(
        "fcp-live-verification-invalid-bearer-token",
        &signing_key,
        &instance_id,
    )
    .await;
    invoke(
        &connector,
        &signing_key,
        &instance_id,
        OP_BLOB_LIST_BLOBS,
        json!({
            "storage_account": storage_account,
            "container": container,
            "prefix": prefix
        }),
    )
    .await
    .is_err_and(|error| matches!(error, FcpError::Unauthorized { .. }))
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_BLOB_LIST_BLOBS | OP_BLOB_GET => CAP_STORAGE_READ,
        OP_BLOB_PUT | OP_BLOB_DELETE => CAP_STORAGE_WRITE,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
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
        .principal("user:azure-live")
        .operations(&[operation])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(instance_id.as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &AzureConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("azure-live-{operation}")),
            connector_id: ConnectorId::from_static("fcp.azure"),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_for(signing_key, instance_id, operation),
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

fn sandbox_blob_name(run_namespace: &str) -> String {
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
    format!(
        "fcp-live-verification/{sanitized}/blob-{}.txt",
        Utc::now().timestamp_millis()
    )
}

fn safe_error_reason(error: &FcpError) -> String {
    match error {
        FcpError::Unauthorized { .. } => "unauthorized".to_string(),
        FcpError::ResourceNotFound { .. } => "resource_not_found".to_string(),
        FcpError::RateLimited { .. } => "rate_limited".to_string(),
        FcpError::InvalidRequest { code, .. } => format!("invalid_request_{code}"),
        FcpError::External {
            service,
            status_code,
            retryable,
            ..
        } => format!(
            "external_{service}_status_{}_retryable_{retryable}",
            status_code.map_or_else(|| "unknown".to_string(), |status| status.to_string())
        ),
        FcpError::Internal { .. } => "internal_error".to_string(),
        FcpError::NotConfigured => "not_configured".to_string(),
        FcpError::NotHandshaken => "not_handshaken".to_string(),
        FcpError::StreamingNotSupported => "streaming_not_supported".to_string(),
        _ => "fcp_error".to_string(),
    }
}

fn redacted_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let encoded = hex::encode(digest);
    let short_hash = encoded.chars().take(16).collect::<String>();
    format!("sha256:{short_hash}")
}
