//! Environment-gated sandbox verification for the `DocuSign` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use fcp_docusign::connector::DocuSignConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const BASE_URL_ENV: &str = "DOCUSIGN_SANDBOX_BASE_URL";
const ACCESS_TOKEN_ENV: &str = "DOCUSIGN_SANDBOX_ACCESS_TOKEN";
const ACCOUNT_ID_ENV: &str = "DOCUSIGN_SANDBOX_ACCOUNT_ID";
const INTEGRATION_KEY_ENV: &str = "DOCUSIGN_SANDBOX_INTEGRATION_KEY";
const USER_ID_ENV: &str = "DOCUSIGN_SANDBOX_USER_ID";
const PRIVATE_KEY_ENV: &str = "DOCUSIGN_SANDBOX_PRIVATE_KEY";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_ENVELOPES: &str = "docusign.list_envelopes";

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
            "Use a dedicated DocuSign demo account. This suite performs one read-only envelope listing by default; write-path proof belongs in a dedicated namespaced envelope flow.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::AutoExpire { ttl_hours: 168 })
        .with_rate_limits(0.5, true)
        .with_metadata(
            "auth_gap",
            json!("Current connector consumes DOCUSIGN_SANDBOX_ACCESS_TOKEN directly; JWT grant inputs are required in the manifest but not minted by this connector yet."),
        )
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "DOCUSIGN_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "docusign_live_sandbox_verification",
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
            "operation": OP_LIST_ENVELOPES,
            "status": status,
            "provider": "DocuSign demo sandbox",
            "environment": "sandbox",
            "resource_class": "envelope_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only envelope listing against the demo account.",
            "mutation_expected": false,
            "cleanup_strategy": "auto_expire",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "account_id_logged": false,
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
            &env.evidence_summary(),
        );
        return;
    }

    let mut connector = configured_connector(&env).await;
    let account_id = env
        .env_vars
        .get(ACCOUNT_ID_ENV)
        .expect("account id env is ready");
    match connector
        .handle_invoke(json!({
            "operation_id": OP_LIST_ENVELOPES,
            "input": {
                "account_id": account_id,
                "from_date": "2020-01-01T00:00:00Z",
                "count": 1
            }
        }))
        .await
    {
        Ok(value) => {
            let observed_count = value["envelopes"].as_array().map_or(0, Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "list_envelopes completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("DocuSign sandbox envelope listing failed: {error}");
        }
    }
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> DocuSignConnector {
    let mut connector = DocuSignConnector::new();
    connector
        .handle_configure(json!({
            "access_token": env.secrets.require("access_token"),
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
