#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_microsoft365::connector::M365Connector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TENANT_ID_ENV: &str = "MICROSOFT365_SANDBOX_TENANT_ID";
const CLIENT_ID_ENV: &str = "MICROSOFT365_SANDBOX_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "MICROSOFT365_SANDBOX_CLIENT_SECRET";
const USER_ID_ENV: &str = "MICROSOFT365_SANDBOX_USER_ID";
const API_URL_ENV: &str = "MICROSOFT365_SANDBOX_API_URL";
const AUTH_URL_ENV: &str = "MICROSOFT365_SANDBOX_AUTH_URL";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CAP_FILES_READ: &str = "m365.files.read";
const CAP_FILES_WRITE: &str = "m365.files.write";
const OP_LIST_ITEMS: &str = "m365.files.list_items";
const OP_GET_ITEM: &str = "m365.files.get_item";
const OP_UPLOAD_FILE: &str = "m365.files.upload_file";
const OP_DELETE_ITEM: &str = "m365.files.delete_item";
const REQUIRED_PERMISSION: &str = "Files.ReadWrite.All";
const CALL_CEILING: usize = 8;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-microsoft365 --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("microsoft365", "Microsoft 365 sandbox")
        .with_env_secret(
            "client_secret",
            CLIENT_SECRET_ENV,
            "Microsoft Entra application client secret for a dedicated test tenant",
        )
        .with_env_var(
            TENANT_ID_ENV,
            "Microsoft Entra tenant id dedicated to live sandbox verification",
        )
        .with_env_var(
            CLIENT_ID_ENV,
            "Microsoft Entra application client id with sandbox Microsoft Graph file permissions",
        )
        .with_env_var(
            USER_ID_ENV,
            "Sandbox user id or UPN whose OneDrive root is dedicated to verification objects",
        )
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic OneDrive file names for this run",
        )
        .with_env_var_default(
            API_URL_ENV,
            "https://graph.microsoft.com/v1.0",
            "Microsoft Graph API endpoint for the sandbox tenant",
        )
        .with_env_var_default(
            AUTH_URL_ENV,
            "https://login.microsoftonline.com",
            "Microsoft Entra OAuth endpoint for client-credentials exchange",
        )
        .with_account_setup(
            "Use a dedicated Microsoft 365 developer/test tenant, sandbox app registration, and disposable OneDrive-enabled user. Grant the app Files.ReadWrite.All application permission with admin consent.",
        )
        .with_budget(0.02)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
        .with_metadata(
            "request_categories",
            json!([
                "auth-denial",
                "health",
                "files.upload_file",
                "files.list_items",
                "files.delete_item",
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
        "MICROSOFT365_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "microsoft365_live_sandbox_file_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [CLIENT_SECRET_ENV],
            "required_env": [TENANT_ID_ENV, CLIENT_ID_ENV, USER_ID_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": [API_URL_ENV, AUTH_URL_ENV],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                "m365.self_check",
                OP_UPLOAD_FILE,
                OP_LIST_ITEMS,
                OP_DELETE_ITEM,
                OP_GET_ITEM
            ],
            "status": status,
            "provider": "Microsoft 365 sandbox",
            "environment": "sandbox",
            "resource_class": "synthetic_onedrive_file",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid client-secret auth-denial probe, one client-credentials configure, one self-check, one file upload, one root list, one delete, and one post-delete get verification.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "health",
                "files.upload_file",
                "files.list_items",
                "files.delete_item",
                "cleanup.verify"
            ],
            "auth_denial_verified": auth_denial_verified,
            "tenant_id_logged": false,
            "client_id_logged": false,
            "user_id_logged": false,
            "file_path_logged": false,
            "item_id_logged": false,
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
async fn microsoft365_live_sandbox_file_lifecycle_or_structured_skip_jsonl() {
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

    let auth_denial_verified = invalid_client_secret_is_denied(&env).await;
    assert!(
        auth_denial_verified,
        "Microsoft 365 invalid client-secret configure must be denied"
    );

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let user_id = env
        .env_vars
        .get(USER_ID_ENV)
        .expect("Microsoft 365 sandbox user id env is ready");
    let run_namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("run namespace env is ready");
    let file_path = sandbox_file_path(run_namespace);
    let file_name = file_path.trim_start_matches('/').to_string();
    let file_path_hash = redacted_hash(&file_path);
    let content = format!("FCP Microsoft 365 live verification file {file_path_hash}\n");
    let content_b64 = BASE64.encode(content.as_bytes());

    let mut proof_error = None;
    let mut observed_count = 0;
    let mut created_visible = false;
    let mut item_id = None;
    let mut item_id_hash = None;
    let mut cleanup_result = "not_started";

    match connector.handle_self_check().await {
        Ok(value) if value.get("status").and_then(Value::as_str) == Some("healthy") => {}
        Ok(value) => {
            proof_error = Some(format!(
                "self_check_status_{}",
                value
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
        Err(error) => {
            proof_error = Some(safe_error_reason(&error));
        }
    }

    if proof_error.is_none() {
        match invoke(
            &connector,
            &signing_key,
            OP_UPLOAD_FILE,
            json!({
                "user_id": user_id,
                "path": file_path.as_str(),
                "content": content_b64
            }),
        )
        .await
        {
            Ok(value) => {
                item_id = value
                    .get("item")
                    .and_then(|item| item.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                item_id_hash = item_id.as_deref().map(redacted_hash);
                if item_id.is_none() {
                    proof_error = Some("upload_missing_item_id".to_string());
                }
            }
            Err(error) => {
                proof_error = Some(safe_error_reason(&error));
            }
        }
    }

    if proof_error.is_none() {
        match invoke(
            &connector,
            &signing_key,
            OP_LIST_ITEMS,
            json!({ "user_id": user_id }),
        )
        .await
        {
            Ok(value) => {
                if let Some(items) = value.get("items").and_then(Value::as_array) {
                    observed_count = items.len();
                    created_visible = items.iter().any(|item| {
                        item.get("name").and_then(Value::as_str) == Some(file_name.as_str())
                            || item.get("id").and_then(Value::as_str) == item_id.as_deref()
                    });
                }
                if !created_visible {
                    proof_error = Some("created_file_not_visible_in_list_items".to_string());
                }
            }
            Err(error) => {
                proof_error = Some(safe_error_reason(&error));
            }
        }
    }

    if let Some(item_id) = item_id.as_deref() {
        match invoke(
            &connector,
            &signing_key,
            OP_DELETE_ITEM,
            json!({ "user_id": user_id, "item_id": item_id }),
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

        if cleanup_result == "delete_completed" {
            match invoke(
                &connector,
                &signing_key,
                OP_GET_ITEM,
                json!({ "user_id": user_id, "item_id": item_id }),
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
                        proof_error = Some("deleted_file_remained_fetchable".to_string());
                    }
                }
            }
        }
    } else if cleanup_result == "not_started" {
        cleanup_result = "no_item_id_to_delete";
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
                "tenant_class": "dedicated_sandbox_tenant",
                "user_id_hash": redacted_hash(user_id),
                "file_path_hash": file_path_hash,
                "item_id_hash": item_id_hash,
                "created_visible": created_visible,
            }),
        );
        panic!("Microsoft 365 sandbox file lifecycle failed: {error}");
    }

    emit_live_jsonl(
        "passed",
        "file lifecycle completed",
        observed_count,
        cleanup_result,
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "tenant_class": "dedicated_sandbox_tenant",
            "user_id_hash": redacted_hash(user_id),
            "file_path_hash": file_path_hash,
            "item_id_hash": item_id_hash,
            "created_visible": created_visible,
            "operation_result": "auth denial, self-check, files.upload_file, files.list_items, files.delete_item, and cleanup verification completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> M365Connector {
    let mut connector = M365Connector::new();
    connector
        .handle_configure(json!({
            "app_credentials": app_credentials(env, env.secrets.require("client_secret")),
            "api_url": env.env_vars.get(API_URL_ENV).expect("API URL env is ready"),
            "auth_url": env.env_vars.get(AUTH_URL_ENV).expect("auth URL env is ready"),
            "required_permissions": [REQUIRED_PERMISSION]
        }))
        .await
        .expect("configure Microsoft 365 live connector");
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![37_u8; 32],
            "capabilities_requested": [CAP_FILES_READ, CAP_FILES_WRITE]
        }))
        .await
        .expect("handshake Microsoft 365 live connector");
    connector
}

async fn invalid_client_secret_is_denied(env: &LiveEnvironment) -> bool {
    let mut connector = M365Connector::new();
    connector
        .handle_configure(json!({
            "app_credentials": app_credentials(env, "fcp-live-verification-invalid-client-secret"),
            "api_url": env.env_vars.get(API_URL_ENV).expect("API URL env is ready"),
            "auth_url": env.env_vars.get(AUTH_URL_ENV).expect("auth URL env is ready"),
            "required_permissions": [REQUIRED_PERMISSION]
        }))
        .await
        .is_err()
}

fn app_credentials(env: &LiveEnvironment, client_secret: &str) -> Value {
    json!({
        "tenant_id": env.env_vars.get(TENANT_ID_ENV).expect("tenant id env is ready"),
        "client_id": env.env_vars.get(CLIENT_ID_ENV).expect("client id env is ready"),
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    })
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_LIST_ITEMS | OP_GET_ITEM => CAP_FILES_READ,
        OP_UPLOAD_FILE | OP_DELETE_ITEM => CAP_FILES_WRITE,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &M365Connector,
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
        .principal("user:microsoft365-live")
        .operations(&[operation])
        .issuer("node:live-verification")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &M365Connector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_for(connector, signing_key, operation)
        }))
        .await
}

fn sandbox_file_path(run_namespace: &str) -> String {
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
    format!("fcp-{sanitized}-{}.txt", Utc::now().timestamp_millis())
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
