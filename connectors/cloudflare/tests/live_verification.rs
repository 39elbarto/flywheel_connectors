#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_cloudflare::connector::CloudflareConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use fcp_sdk::prelude::SelfCheckStatus;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const API_TOKEN_ENV: &str = "CLOUDFLARE_SANDBOX_API_TOKEN";
const ACCOUNT_ID_ENV: &str = "CLOUDFLARE_SANDBOX_ACCOUNT_ID";
const ZONE_ID_ENV: &str = "CLOUDFLARE_SANDBOX_ZONE_ID";
const BASE_URL_ENV: &str = "CLOUDFLARE_SANDBOX_BASE_URL";
const RUN_NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "fcp.cloudflare";
const CAP_ZONES_READ: &str = "cloudflare.zones.read";
const CAP_DNS_READ: &str = "cloudflare.dns.read";
const CAP_DNS_WRITE: &str = "cloudflare.dns.write";
const OP_HEALTH: &str = "cloudflare.health";
const OP_DNS_CREATE: &str = "cloudflare.dns.create_record";
const OP_DNS_LIST: &str = "cloudflare.dns.list_records";
const OP_DNS_DELETE: &str = "cloudflare.dns.delete_record";
const CALL_CEILING: usize = 6;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-cloudflare --test live_verification -- --nocapture";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("cloudflare", "Cloudflare sandbox")
        .with_env_secret(
            "api_token",
            API_TOKEN_ENV,
            "Cloudflare API token scoped to the sandbox account",
        )
        .with_env_var(
            ACCOUNT_ID_ENV,
            "Cloudflare sandbox account id bound to the token",
        )
        .with_env_var(
            ZONE_ID_ENV,
            "Cloudflare sandbox zone id dedicated to DNS live verification",
        )
        .with_env_var(
            RUN_NAMESPACE_ENV,
            "Shared namespace embedded in synthetic DNS record names for this run",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.cloudflare.com/client/v4",
            "Cloudflare API v4 endpoint",
        )
        .with_account_setup(
            "Use a dedicated Cloudflare test zone. The token must verify itself, create/list/delete TXT records in that zone, and avoid production zones.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
        .with_metadata(
            "request_categories",
            json!([
                "auth-denial",
                "health",
                "dns.create_record",
                "dns.list_records",
                "dns.delete_record",
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
        "CLOUDFLARE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "cloudflare_live_sandbox_dns_record_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [API_TOKEN_ENV],
            "required_env": [ACCOUNT_ID_ENV, ZONE_ID_ENV, RUN_NAMESPACE_ENV],
            "defaulted_env": [BASE_URL_ENV],
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_HEALTH,
                OP_DNS_CREATE,
                OP_DNS_LIST,
                OP_DNS_DELETE,
                OP_DNS_LIST
            ],
            "status": status,
            "provider": "Cloudflare sandbox",
            "environment": "sandbox",
            "resource_class": "synthetic_dns_txt_record",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token auth-denial probe, one token health probe, one TXT record create, one post-create DNS list, one delete, and one post-delete DNS list.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "health",
                "dns.create_record",
                "dns.list_records",
                "dns.delete_record",
                "cleanup.verify"
            ],
            "auth_denial_verified": auth_denial_verified,
            "account_id_logged": false,
            "zone_id_logged": false,
            "record_id_logged": false,
            "record_name_logged": false,
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
async fn cloudflare_live_sandbox_dns_record_lifecycle_or_structured_skip_jsonl() {
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
        "Cloudflare invalid-token self-check must not report healthy"
    );

    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(&env, &signing_key).await;
    let zone_id = env
        .env_vars
        .get(ZONE_ID_ENV)
        .expect("Cloudflare zone id env is ready");
    let run_namespace = env
        .env_vars
        .get(RUN_NAMESPACE_ENV)
        .expect("run namespace env is ready");
    let record_name = sandbox_record_name(run_namespace);
    let record_name_hash = redacted_hash(&record_name);
    let record_content = format!("fcp-live-verification={record_name_hash}");

    if let Err(error) = invoke(&connector, &signing_key, OP_HEALTH, json!({})).await {
        emit_live_jsonl(
            "failed",
            &error.to_string(),
            0,
            "not_started",
            auth_denial_verified,
            &env.evidence_summary(),
        );
        panic!("Cloudflare sandbox health probe failed: {error}");
    }

    let created = match invoke(
        &connector,
        &signing_key,
        OP_DNS_CREATE,
        json!({
            "zone_id": zone_id,
            "type": "TXT",
            "name": record_name.as_str(),
            "content": record_content.as_str(),
            "ttl": 120,
            "proxied": false,
            "comment": "FCP Cloudflare live verification record"
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                "create_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "record_name_hash": record_name_hash,
                }),
            );
            panic!("Cloudflare sandbox DNS create failed: {error}");
        }
    };
    let record_id = created
        .get("id")
        .and_then(Value::as_str)
        .expect("created Cloudflare DNS record includes id");
    let record_id_hash = redacted_hash(record_id);

    let mut observed_count = 0;
    let mut created_visible = false;
    let mut proof_error = None;
    match invoke(
        &connector,
        &signing_key,
        OP_DNS_LIST,
        json!({ "zone_id": zone_id }),
    )
    .await
    {
        Ok(records) => {
            if let Some(items) = records.as_array() {
                observed_count = items.len();
                created_visible = items
                    .iter()
                    .any(|record| record.get("id").and_then(Value::as_str) == Some(record_id));
            }
            if !created_visible {
                proof_error = Some("created DNS record was not visible in dns.list_records".into());
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
        OP_DNS_DELETE,
        json!({ "zone_id": zone_id, "record_id": record_id }),
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
            OP_DNS_LIST,
            json!({ "zone_id": zone_id }),
        )
        .await
        {
            Ok(records) => {
                let still_visible = records.as_array().is_some_and(|items| {
                    items
                        .iter()
                        .any(|record| record.get("id").and_then(Value::as_str) == Some(record_id))
                });
                if still_visible {
                    cleanup_result = "delete_not_verified";
                    if proof_error.is_none() {
                        proof_error = Some("deleted DNS record remained visible".into());
                    }
                } else {
                    cleanup_result = "delete_verified_absent";
                }
            }
            Err(FcpError::ResourceNotFound { .. }) => {
                cleanup_result = "delete_verified_zone_empty";
            }
            Err(error) => {
                cleanup_result = "delete_verification_failed";
                if proof_error.is_none() {
                    proof_error = Some(error.to_string());
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
                "record_id_hash": record_id_hash,
                "record_name_hash": record_name_hash,
                "created_visible": created_visible,
            }),
        );
        panic!("Cloudflare sandbox DNS record lifecycle failed: {error}");
    }

    emit_live_jsonl(
        "passed",
        "DNS record lifecycle completed",
        observed_count,
        cleanup_result,
        auth_denial_verified,
        &json!({
            "environment": env.evidence_summary(),
            "record_id_hash": record_id_hash,
            "record_name_hash": record_name_hash,
            "created_visible": created_visible,
            "operation_result": "auth denial, health, dns.create_record, dns.list_records, dns.delete_record, and cleanup verification completed",
        }),
    );
}

async fn configured_connector(
    env: &LiveEnvironment,
    signing_key: &Ed25519SigningKey,
) -> CloudflareConnector {
    let mut connector = CloudflareConnector::new();
    connector
        .configure(json!({
            "mode": "api_token",
            "api_token": env.secrets.require("api_token"),
            "account_id": env.env_vars.get(ACCOUNT_ID_ENV).expect("account id env is ready"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "request_timeout_ms": 10_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 250,
                "max_delay_ms": 1_000,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure Cloudflare live connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_ZONES_READ),
                CapabilityId::from_static(CAP_DNS_READ),
                CapabilityId::from_static(CAP_DNS_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake Cloudflare live connector");
    connector
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let mut connector = CloudflareConnector::new();
    connector
        .configure(json!({
            "mode": "api_token",
            "api_token": "fcp-live-verification-invalid-token",
            "account_id": env.env_vars.get(ACCOUNT_ID_ENV).expect("account id env is ready"),
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
        .expect("configure invalid-token Cloudflare connector");

    match connector.self_check().await {
        Ok(report) => report.status != SelfCheckStatus::Ok,
        Err(_error) => true,
    }
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
        OP_HEALTH => CAP_ZONES_READ,
        OP_DNS_LIST => CAP_DNS_READ,
        OP_DNS_CREATE | OP_DNS_DELETE => CAP_DNS_WRITE,
        _ => panic!("unsupported operation {operation}"),
    }
}

fn capability_for(
    connector: &CloudflareConnector,
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
        .principal("user:cloudflare-live")
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
    connector: &CloudflareConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("cloudflare-live-{operation}")),
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

fn sandbox_record_name(run_namespace: &str) -> String {
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
    format!("_fcp-{sanitized}-{}", Utc::now().timestamp_millis())
}

fn redacted_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let encoded = hex::encode(digest);
    let short_hash = encoded.chars().take(16).collect::<String>();
    format!("sha256:{short_hash}")
}
