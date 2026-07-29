//! Environment-gated sandbox verification for the `DocuSign` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use fcp_docusign::{
    client::{DocuSignAuth, DocuSignClient},
    connector::DocuSignConnector,
};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const BASE_URL_ENV: &str = "DOCUSIGN_SANDBOX_BASE_URL";
const ACCESS_TOKEN_ENV: &str = "DOCUSIGN_SANDBOX_ACCESS_TOKEN";
const ACCOUNT_ID_ENV: &str = "DOCUSIGN_SANDBOX_ACCOUNT_ID";
const INTEGRATION_KEY_ENV: &str = "DOCUSIGN_SANDBOX_INTEGRATION_KEY";
const USER_ID_ENV: &str = "DOCUSIGN_SANDBOX_USER_ID";
const PRIVATE_KEY_ENV: &str = "DOCUSIGN_SANDBOX_PRIVATE_KEY";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_ENVELOPES: &str = "docusign.list_envelopes";
const OP_CREATE_ENVELOPE: &str = "docusign.create_envelope";
const OP_GET_ENVELOPE: &str = "docusign.get_envelope";
const OP_RECYCLE_ENVELOPE: &str = "docusign.move_envelope_to_recyclebin";
const CALL_CEILING: usize = 5;
const LIVE_COMMAND: &str =
    "rch exec -- cargo test -p fcp-docusign --test live_verification -- --nocapture";
const TEXT_DOCUMENT_BASE64: &str = "RkNQIERvY3VTaWduIGxpdmUgdmVyaWZpY2F0aW9uIGRvY3VtZW50Cg==";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("docusign", "DocuSign demo sandbox")
        .with_env_secret(
            "access_token",
            ACCESS_TOKEN_ENV,
            "Pre-minted DocuSign demo OAuth access token for the current connector auth surface",
        )
        .with_env_secret(
            "integration_key",
            INTEGRATION_KEY_ENV,
            "DocuSign demo integration key retained in the evidence contract for JWT grant follow-up",
        )
        .with_env_secret(
            "private_key",
            PRIVATE_KEY_ENV,
            "DocuSign demo RSA private key retained in the evidence contract for JWT grant follow-up",
        )
        .with_env_var(USER_ID_ENV, "DocuSign demo user id paired with the integration key")
        .with_env_var(ACCOUNT_ID_ENV, "DocuSign demo account id used for read-only envelope listing")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://demo.docusign.net/restapi/v2.1/accounts",
            "DocuSign demo account-root REST API endpoint",
        )
        .with_account_setup(
            "Use a dedicated DocuSign demo account. This suite performs one invalid-token listing, one sandbox envelope listing, one draft envelope create, one readback, and one recycle-bin cleanup move.",
        )
        .with_budget(0.02)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
        .with_metadata(
            "auth_gap",
            json!("Current connector consumes DOCUSIGN_SANDBOX_ACCESS_TOKEN directly; JWT grant inputs are required in the manifest but not minted by this connector yet."),
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
        "DOCUSIGN_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "docusign_live_sandbox_envelope_lifecycle",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [
                ACCESS_TOKEN_ENV,
                INTEGRATION_KEY_ENV,
                PRIVATE_KEY_ENV
            ],
            "required_env": [USER_ID_ENV, ACCOUNT_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "command": LIVE_COMMAND,
            "git_revision": option_env!("FCP_LIVE_GIT_REVISION").unwrap_or("unknown"),
            "operation": [
                "auth-denial",
                OP_LIST_ENVELOPES,
                OP_CREATE_ENVELOPE,
                OP_GET_ENVELOPE,
                OP_RECYCLE_ENVELOPE
            ],
            "status": status,
            "provider": "DocuSign demo sandbox",
            "environment": "sandbox",
            "resource_class": "sandbox_draft_envelope",
            "observed_count": observed_count,
            "call_ceiling": CALL_CEILING,
            "rate_limit_guidance": "Performs one invalid-token envelope listing, one sandbox envelope listing, one draft envelope create, one readback, and one recycle-bin cleanup move.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_recyclebin_move",
            "cleanup_result": cleanup_result,
            "request_category": [
                "auth-denial",
                "envelope.list",
                "envelope.create_draft",
                "envelope.readback",
                "envelope.recyclebin"
            ],
            "auth_denial_verified": auth_denial_verified,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "account_id_logged": false,
            "envelope_id_logged": false,
            "recipient_email_logged": false,
            "document_body_logged": false,
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
async fn docusign_live_sandbox_envelope_listing_or_structured_skip_jsonl() {
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
        "DocuSign invalid-token envelope listing must be denied"
    );

    let mut connector = configured_connector(&env).await;
    let account_id = env
        .env_vars
        .get(ACCOUNT_ID_ENV)
        .expect("account id env is ready");
    let namespace = env
        .env_vars
        .get(NAMESPACE_ENV)
        .expect("namespace env is ready");
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .expect("base URL env is ready");
    let envelope_key = short_hash(&format!("{namespace}:{}", Uuid::new_v4()));
    let email_subject = format!("FCP DocuSign live verification {namespace} {envelope_key}");
    let recipient_email = format!("fcp-docusign-{envelope_key}@example.com");

    let list = match invoke(
        &connector,
        OP_LIST_ENVELOPES,
        json!({
            "account_id": account_id,
            "from_date": "2020-01-01T00:00:00Z",
            "count": 1
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
                "not_started",
                auth_denial_verified,
                &env.evidence_summary(),
            );
            panic!("DocuSign sandbox envelope listing failed: {error}");
        }
    };

    let create = match invoke(
        &connector,
        OP_CREATE_ENVELOPE,
        json!({
            "account_id": account_id,
            "envelope_definition": {
                "emailSubject": email_subject,
                "status": "created",
                "documents": [{
                    "documentBase64": TEXT_DOCUMENT_BASE64,
                    "name": "fcp-live-verification.txt",
                    "fileExtension": "txt",
                    "documentId": "1"
                }],
                "recipients": {
                    "signers": [{
                        "email": recipient_email,
                        "name": "FCP Live Verification",
                        "recipientId": "1",
                        "routingOrder": "1"
                    }]
                }
            }
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                1,
                "not_started",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "account_hash": redacted_hash(account_id),
                    "recipient_email_hash": redacted_hash(&recipient_email),
                    "subject_hash": redacted_hash(&email_subject),
                    "list_count": list["envelopes"].as_array().map_or(0, Vec::len),
                }),
            );
            panic!("DocuSign sandbox draft envelope create failed: {error}");
        }
    };

    let envelope_id = create["envelopeId"]
        .as_str()
        .or_else(|| create["envelope_id"].as_str())
        .expect("DocuSign create response includes envelope id");
    let readback = match invoke(
        &connector,
        OP_GET_ENVELOPE,
        json!({
            "account_id": account_id,
            "envelope_id": envelope_id
        }),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                2,
                "readback_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "account_hash": redacted_hash(account_id),
                    "envelope_hash": redacted_hash(envelope_id),
                    "subject_hash": redacted_hash(&email_subject),
                }),
            );
            panic!("DocuSign sandbox draft envelope readback failed: {error}");
        }
    };

    match cleanup_client(&env)
        .move_envelopes_to_recycle_bin(account_id, &[envelope_id])
        .await
    {
        Ok(cleanup) => {
            emit_live_jsonl(
                "passed",
                "",
                list["envelopes"]
                    .as_array()
                    .map_or(3, |items| items.len().saturating_add(3)),
                "recyclebin_completed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "account_hash": redacted_hash(account_id),
                    "envelope_hash": redacted_hash(envelope_id),
                    "recipient_email_hash": redacted_hash(&recipient_email),
                    "subject_hash": redacted_hash(&email_subject),
                    "list_count": list["envelopes"].as_array().map_or(0, Vec::len),
                    "readback_present": readback.get("envelope").is_some(),
                    "cleanup_result": cleanup,
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                3,
                "recyclebin_failed",
                auth_denial_verified,
                &json!({
                    "environment": env.evidence_summary(),
                    "base_url_hash": redacted_hash(base_url),
                    "account_hash": redacted_hash(account_id),
                    "envelope_hash": redacted_hash(envelope_id),
                    "subject_hash": redacted_hash(&email_subject),
                    "readback_present": readback.get("envelope").is_some(),
                }),
            );
            panic!("DocuSign sandbox draft envelope recycle-bin cleanup failed: {error}");
        }
    }

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> DocuSignConnector {
    configured_connector_with_token(env, env.secrets.require("access_token")).await
}

async fn configured_connector_with_token(
    env: &LiveEnvironment,
    access_token: &str,
) -> DocuSignConnector {
    let mut connector = DocuSignConnector::new();
    connector
        .handle_configure(json!({
            "access_token": access_token,
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready")
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({
            "session_id": format!("docusign-live-{}", env.tenant.run_prefix())
        }))
        .await
        .expect("handshake live connector");
    connector
}

async fn invalid_token_is_denied(env: &LiveEnvironment) -> bool {
    let connector = configured_connector_with_token(env, "fcp-invalid-docusign-live-token").await;
    let account_id = env
        .env_vars
        .get(ACCOUNT_ID_ENV)
        .expect("account id env is ready");
    invoke(
        &connector,
        OP_LIST_ENVELOPES,
        json!({
            "account_id": account_id,
            "from_date": "2020-01-01T00:00:00Z",
            "count": 1
        }),
    )
    .await
    .is_err()
}

async fn invoke(
    connector: &DocuSignConnector,
    operation: &'static str,
    input: Value,
) -> Result<Value, fcp_prelude::FcpError> {
    connector
        .handle_invoke(json!({
            "operation_id": operation,
            "input": input
        }))
        .await
}

fn cleanup_client(env: &LiveEnvironment) -> DocuSignClient {
    DocuSignClient::new(
        DocuSignAuth::BearerToken(env.secrets.require("access_token").to_string()),
        env.env_vars
            .get(BASE_URL_ENV)
            .expect("base URL env is ready"),
    )
    .expect("construct DocuSign cleanup client")
}

fn redacted_hash(value: &str) -> String {
    format!("sha256:{}", short_hash(value))
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest).chars().take(16).collect()
}
