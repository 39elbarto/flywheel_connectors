//! Environment-gated sandbox verification for the `Intercom` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use fcp_intercom::connector::IntercomConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "INTERCOM_SANDBOX_TOKEN";
const WORKSPACE_ID_ENV: &str = "INTERCOM_SANDBOX_WORKSPACE_ID";
const BASE_URL_ENV: &str = "INTERCOM_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_CONTACTS_LIST: &str = "intercom.contacts.list";
const OP_CONTACTS_CREATE: &str = "intercom.contacts.create";
const OP_CONTACTS_DELETE: &str = "intercom.contacts.delete";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("intercom", "Intercom sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "Intercom OAuth token scoped to a dedicated sandbox workspace",
        )
        .with_env_var(
            WORKSPACE_ID_ENV,
            "Intercom sandbox workspace id used for evidence scoping",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://api.intercom.io", "Intercom API endpoint")
        .with_account_setup(
            "Use a dedicated Intercom sandbox or development workspace. This suite lists contacts, creates one namespaced synthetic contact, and deletes that contact before finishing.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    evidence: &Value,
) {
    eprintln!(
        "INTERCOM_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "intercom_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [WORKSPACE_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_CONTACTS_CREATE,
            "operations": [OP_CONTACTS_LIST, OP_CONTACTS_CREATE, OP_CONTACTS_DELETE],
            "status": status,
            "provider": "Intercom sandbox",
            "environment": "sandbox",
            "resource_class": "namespaced_synthetic_contact",
            "observed_count": observed_count,
            "call_ceiling": 3,
            "rate_limit_guidance": "Performs one contact listing plus one create/delete pair against the sandbox workspace.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "workspace_id_logged": false,
            "contact_email_logged": false,
            "contact_id_logged": false,
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
async fn intercom_live_sandbox_contact_flow_or_structured_skip_jsonl()
-> Result<(), Box<dyn std::error::Error>> {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            &env.evidence_summary(),
        );
        return Ok(());
    }

    let mut connector = configured_connector(&env).await?;
    let observed_count = match connector
        .handle_invoke(json!({
            "operation_id": OP_CONTACTS_LIST,
            "input": {
                "per_page": 1
            }
        }))
        .await
    {
        Ok(value) => value
            .get("data")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                "not_started",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            return Err(error);
        }
    };

    let contact = create_sandbox_contact(&connector, &env, observed_count).await?;
    delete_sandbox_contact(&connector, &env, observed_count, &contact).await?;

    emit_live_jsonl(
        "passed",
        "",
        observed_count,
        "deleted_created_contact",
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "contacts.list, contacts.create, and contacts.delete completed",
            "created_contact_id_recorded": false,
        }),
    );

    connector.handle_shutdown(json!({})).await?;
    Ok(())
}

async fn configured_connector(
    env: &LiveEnvironment,
) -> Result<IntercomConnector, Box<dyn std::error::Error>> {
    let auth_value = env
        .secrets
        .get("access_token")
        .ok_or("access token env is ready")?;
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .ok_or("base URL env is ready")?;
    let mut connector = IntercomConnector::new();
    connector
        .handle_configure(json!({
            "access_token": auth_value,
            "base_url": base_url
        }))
        .await?;
    connector
        .handle_handshake(json!({
            "session_id": format!("intercom-live-{}", env.tenant.run_prefix())
        }))
        .await?;
    Ok(connector)
}

async fn create_sandbox_contact(
    connector: &IntercomConnector,
    env: &LiveEnvironment,
    observed_count: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let run_prefix = env.tenant.run_prefix();
    let contact = connector
        .handle_invoke(json!({
            "operation_id": OP_CONTACTS_CREATE,
            "input": {
                "role": "user",
                "email": format!("fcp-sandbox-{run_prefix}@example.com"),
                "name": format!("FCP Sandbox {run_prefix}"),
            }
        }))
        .await;

    match contact {
        Ok(value) => value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| "Intercom contacts.create response did not include a contact id".into()),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                observed_count,
                "not_started",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            Err(error)
        }
    }
}

async fn delete_sandbox_contact(
    connector: &IntercomConnector,
    env: &LiveEnvironment,
    observed_count: usize,
    contact_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match connector
        .handle_invoke(json!({
            "operation_id": OP_CONTACTS_DELETE,
            "input": {
                "contact_id": contact_id,
            }
        }))
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                observed_count,
                "delete_failed_for_created_contact",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            Err(error)
        }
    }
}
