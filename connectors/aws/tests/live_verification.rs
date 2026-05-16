#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_aws::connector::AwsConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpError, HandshakeRequest,
    InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::FcpConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_KEY_ID_ENV: &str = "AWS_SANDBOX_ACCESS_KEY_ID";
const SECRET_ACCESS_KEY_ENV: &str = "AWS_SANDBOX_SECRET_ACCESS_KEY";
const SESSION_TOKEN_ENV: &str = "AWS_SANDBOX_SESSION_TOKEN";
const REGION_ENV: &str = "AWS_SANDBOX_REGION";
const ACCOUNT_ID_ENV: &str = "AWS_SANDBOX_ACCOUNT_ID";
const BUCKET_ENV: &str = "AWS_SANDBOX_BUCKET";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CAP_S3_READ: &str = "aws.s3.read";
const CAP_S3_WRITE: &str = "aws.s3.write";
const OP_S3_LIST_OBJECTS: &str = "aws.s3.list_objects";
const OP_S3_GET_OBJECT: &str = "aws.s3.get_object";
const OP_S3_PUT_OBJECT: &str = "aws.s3.put_object";
const OP_S3_DELETE_OBJECT: &str = "aws.s3.delete_object";
const CALL_CEILING: usize = 5;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-aws --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("aws", "Amazon Web Services sandbox")
        .with_env_secret(
            "access_key_id",
            ACCESS_KEY_ID_ENV,
            "Sandbox AWS access key id scoped to the verification account",
        )
        .with_env_secret(
            "secret_access_key",
            SECRET_ACCESS_KEY_ENV,
            "Sandbox AWS secret access key scoped to the verification account",
        )
        .with_env_var(
            REGION_ENV,
            "AWS region used for signing the S3 verification request",
        )
        .with_env_var(
            ACCOUNT_ID_ENV,
            "AWS sandbox account id for redaction-safe evidence correlation",
        )
        .with_env_var(
            BUCKET_ENV,
            "Dedicated sandbox S3 bucket for synthetic verification objects",
        )
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic S3 object keys for this run",
        )
        .with_account_setup(
            "Use a dedicated AWS sandbox account and bucket. Credentials must put, list, get, and delete only synthetic objects in that bucket.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
        .with_metadata(
            "request_categories",
            json!([
                "auth-denial",
                "s3.put_object",
                "s3.list_objects",
                "s3.delete_object",
                "cleanup.verify"
            ]),
        )
}

fn optional_env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
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
        "AWS_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "aws_live_sandbox_s3_object_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [ACCESS_KEY_ID_ENV, SECRET_ACCESS_KEY_ENV],
            "optional_secret_env": SESSION_TOKEN_ENV,
            "required_env": [REGION_ENV, ACCOUNT_ID_ENV, BUCKET_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": [],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_S3_PUT_OBJECT,
                OP_S3_LIST_OBJECTS,
                OP_S3_DELETE_OBJECT,
                OP_S3_GET_OBJECT
            ],
            "status": status,
            "provider": "Amazon Web Services sandbox",
            "environment": "sandbox",
            "resource_class": "synthetic_s3_object",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-signature auth-denial list probe, one S3 object put, one prefix list, one delete, and one post-delete get verification.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "s3.put_object",
                "s3.list_objects",
                "s3.delete_object",
                "cleanup.verify"
            ],
            "auth_denial_verified": auth_denial_verified,
            "account_id_logged": false,
            "bucket_logged": false,
            "object_key_logged": false,
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
async fn aws_live_sandbox_s3_object_lifecycle_or_structured_skip_jsonl() {
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

    let bucket = env
        .env_vars
        .get(BUCKET_ENV)
        .expect("AWS bucket env is ready");
    let run_namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("run namespace env is ready");
    let account_id = env
        .env_vars
        .get(ACCOUNT_ID_ENV)
        .expect("AWS account id env is ready");
    let object_key = sandbox_object_key(run_namespace);
    let object_prefix = object_key
        .rsplit_once('/')
        .map(|(prefix, _name)| format!("{prefix}/"))
        .unwrap_or_default();
    let object_key_hash = redacted_hash(&object_key);
    let bucket_hash = redacted_hash(bucket);
    let body = format!("FCP AWS live verification object {object_key_hash}\n");

    let auth_denial_verified = invalid_secret_is_denied(&env, bucket, &object_prefix).await;
    assert!(
        auth_denial_verified,
        "AWS invalid-signature S3 list must be denied"
    );

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let mut proof_error = None;
    let mut observed_count = 0;
    let mut created_visible = false;
    let mut cleanup_result;

    if let Err(error) = invoke(
        &connector,
        &signing_key,
        OP_S3_PUT_OBJECT,
        json!({
            "bucket": bucket,
            "key": object_key.as_str(),
            "body": body,
            "content_type": "text/plain"
        }),
    )
    .await
    {
        proof_error = Some(safe_error_reason(&error));
    }

    if proof_error.is_none() {
        match invoke(
            &connector,
            &signing_key,
            OP_S3_LIST_OBJECTS,
            json!({ "bucket": bucket, "prefix": object_prefix.as_str() }),
        )
        .await
        {
            Ok(value) => {
                if let Some(objects) = value.as_array() {
                    observed_count = objects.len();
                    created_visible = objects.iter().any(|object| {
                        object.get("key").and_then(Value::as_str) == Some(object_key.as_str())
                    });
                }
                if !created_visible {
                    proof_error = Some("created_object_not_visible_in_list_objects".to_string());
                }
            }
            Err(error) => {
                proof_error = Some(safe_error_reason(&error));
            }
        }
    }

    match invoke(
        &connector,
        &signing_key,
        OP_S3_DELETE_OBJECT,
        json!({ "bucket": bucket, "key": object_key.as_str() }),
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
            OP_S3_GET_OBJECT,
            json!({ "bucket": bucket, "key": object_key.as_str() }),
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
                    proof_error = Some("deleted_object_remained_fetchable".to_string());
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
                "account_id_hash": redacted_hash(account_id),
                "bucket_hash": bucket_hash,
                "object_key_hash": object_key_hash,
                "created_visible": created_visible,
            }),
        );
        panic!("AWS sandbox S3 object lifecycle failed: {error}");
    }

    emit_live_jsonl(
        "passed",
        "S3 object lifecycle completed",
        observed_count,
        cleanup_result,
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "account_id_hash": redacted_hash(account_id),
            "bucket_hash": bucket_hash,
            "object_key_hash": object_key_hash,
            "created_visible": created_visible,
            "operation_result": "auth denial, s3.put_object, s3.list_objects, s3.delete_object, and cleanup verification completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> AwsConnector {
    let mut config = json!({
        "access_key_id": env.secrets.require("access_key_id"),
        "secret_access_key": env.secrets.require("secret_access_key"),
        "region": env.env_vars.get(REGION_ENV).expect("region env is ready"),
        "request_timeout_ms": 10_000,
        "retry": {
            "max_retries": 1,
            "initial_delay_ms": 250,
            "max_delay_ms": 1_000,
            "jitter_enabled": false
        }
    });
    if let Some(session_token) = optional_env_value(SESSION_TOKEN_ENV) {
        config["session_token"] = json!(session_token);
    }

    let mut connector = AwsConnector::new();
    connector
        .configure(config)
        .await
        .expect("configure AWS sandbox credentials");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [41_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_S3_READ),
                CapabilityId::from_static(CAP_S3_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake AWS sandbox connector");
    connector
}

async fn invalid_secret_is_denied(env: &LiveEnvironment, bucket: &str, prefix: &str) -> bool {
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = AwsConnector::new();
    let mut config = json!({
        "access_key_id": env.secrets.require("access_key_id"),
        "secret_access_key": "fcp-live-verification-invalid-secret-access-key",
        "region": env.env_vars.get(REGION_ENV).expect("region env is ready"),
        "request_timeout_ms": 10_000,
        "retry": {
            "max_retries": 0,
            "initial_delay_ms": 1,
            "max_delay_ms": 1,
            "jitter_enabled": false
        }
    });
    if let Some(session_token) = optional_env_value(SESSION_TOKEN_ENV) {
        config["session_token"] = json!(session_token);
    }

    connector
        .configure(config)
        .await
        .expect("configure invalid-secret AWS connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [43_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_S3_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake invalid-secret AWS connector");

    invoke(
        &connector,
        &signing_key,
        OP_S3_LIST_OBJECTS,
        json!({ "bucket": bucket, "prefix": prefix }),
    )
    .await
    .is_err_and(|error| matches!(error, FcpError::Unauthorized { .. }))
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_S3_LIST_OBJECTS | OP_S3_GET_OBJECT => CAP_S3_READ,
        OP_S3_PUT_OBJECT | OP_S3_DELETE_OBJECT => CAP_S3_WRITE,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &AwsConnector,
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
        .principal("user:aws-live")
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
    connector: &AwsConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("aws-live-{operation}")),
            connector_id: ConnectorId::from_static("fcp.aws"),
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

fn sandbox_object_key(run_namespace: &str) -> String {
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
        "fcp-live-verification/{sanitized}/object-{}.txt",
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
