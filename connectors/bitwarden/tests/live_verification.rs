//! Environment-gated live verification for the `Bitwarden` connector.

#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use fcp_bitwarden::connector::BitwardenConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const CLIENT_ID_ENV: &str = "BITWARDEN_SANDBOX_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "BITWARDEN_SANDBOX_CLIENT_SECRET";
const ORG_ID_ENV: &str = "BITWARDEN_SANDBOX_ORG_ID";
const BASE_URL_ENV: &str = "BITWARDEN_SANDBOX_BASE_URL";
const IDENTITY_URL_ENV: &str = "BITWARDEN_SANDBOX_IDENTITY_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const CONNECTOR_ID: &str = "bitwarden";
const OP_COLLECTIONS_LIST: &str = "bitwarden.collections.list";

#[fcp_async_core::runtime::test]
async fn live_verification_lists_collections_when_enabled() -> Result<(), Box<dyn std::error::Error>>
{
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            &env.evidence_summary(),
        );
        return Ok(());
    }

    let mut connector = configured_connector(&env).await;
    let collections = match connector
        .handle_invoke(json!({
            "operation_id": OP_COLLECTIONS_LIST,
            "input": {}
        }))
        .await
    {
        Ok(collections) => collections,
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            let error: Box<dyn std::error::Error> = Box::new(error);
            return Err(error);
        }
    };
    let collection_count = collections
        .get("data")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    emit_live_jsonl(
        "passed",
        "Bitwarden Public API collections.list completed",
        collection_count,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "collections.list completed",
        }),
    );

    connector.handle_shutdown(json!({})).await?;

    Ok(())
}

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox(CONNECTOR_ID, "Bitwarden Public API organization sandbox")
        .with_env_secret(
            "client_id",
            CLIENT_ID_ENV,
            "Bitwarden organization Public API client id for the sandbox organization",
        )
        .with_env_secret(
            "client_secret",
            CLIENT_SECRET_ENV,
            "Bitwarden organization Public API client secret for the sandbox organization",
        )
        .with_env_var(
            ORG_ID_ENV,
            "Bitwarden sandbox organization id recorded for evidence scoping",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.bitwarden.com",
            "Bitwarden Public API endpoint for the sandbox organization",
        )
        .with_env_var_default(
            IDENTITY_URL_ENV,
            "https://identity.bitwarden.com/connect/token",
            "Bitwarden identity endpoint for client-credentials token exchange",
        )
        .with_account_setup(
            "Use a disposable Bitwarden Teams or Enterprise organization API key; this suite performs one read-only Public API collection listing and does not access vault item contents.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::None)
        .with_rate_limits(1.0, true)
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

async fn configured_connector(env: &LiveEnvironment) -> BitwardenConnector {
    let mut connector = BitwardenConnector::new();
    connector
        .handle_configure(json!({
            "client_id": env.secrets.require("client_id"),
            "client_secret": env.secrets.require("client_secret"),
            "organization_id": env.env_vars.get(ORG_ID_ENV).expect("organization id env is ready"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "identity_url": env.env_vars.get(IDENTITY_URL_ENV).expect("identity URL env is ready"),
        }))
        .await
        .expect("configure Bitwarden live connector");
    connector
        .handle_handshake(json!({"session_id": "bitwarden-live-verification"}))
        .await
        .expect("handshake Bitwarden live connector");
    connector
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "BITWARDEN_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "bitwarden_live_sandbox_verification",
            "connector": CONNECTOR_ID,
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [CLIENT_ID_ENV, CLIENT_SECRET_ENV],
            "required_env": [ORG_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": [BASE_URL_ENV, IDENTITY_URL_ENV],
            "operation": OP_COLLECTIONS_LIST,
            "status": status,
            "provider": "Bitwarden Public API sandbox",
            "environment": "sandbox",
            "resource_class": "organization_collection_listing",
            "observed_count": observed_count,
            "call_ceiling": 2,
            "mutation_expected": false,
            "cleanup_strategy": "noop",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "organization_id_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}
