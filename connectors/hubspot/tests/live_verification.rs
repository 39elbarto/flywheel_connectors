//! Environment-gated sandbox verification for the `HubSpot` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use fcp_hubspot::connector::HubSpotConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "HUBSPOT_SANDBOX_TOKEN";
const PORTAL_ID_ENV: &str = "HUBSPOT_SANDBOX_PORTAL_ID";
const BASE_URL_ENV: &str = "HUBSPOT_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_CONTACTS_LIST: &str = "hubspot.contacts.list";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("hubspot", "HubSpot sandbox")
        .with_env_secret(
            "access_token",
            TOKEN_ENV,
            "HubSpot private app or OAuth token scoped to the sandbox portal",
        )
        .with_env_var(PORTAL_ID_ENV, "HubSpot sandbox portal id used for evidence scoping")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(BASE_URL_ENV, "https://api.hubapi.com", "HubSpot API endpoint")
        .with_account_setup(
            "Use a dedicated HubSpot sandbox or developer test portal. This suite performs one read-only contact listing by default; write-path proof belongs in a dedicated namespaced contact flow.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "HUBSPOT_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "hubspot_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [PORTAL_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_CONTACTS_LIST,
            "status": status,
            "provider": "HubSpot sandbox",
            "environment": "sandbox",
            "resource_class": "contact_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only contact listing against the sandbox portal.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "portal_id_logged": false,
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
async fn hubspot_live_sandbox_contact_listing_or_structured_skip_jsonl() {
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
    match connector
        .handle_invoke(json!({
            "operation_id": OP_CONTACTS_LIST,
            "input": {
                "limit": 1,
                "properties": ["email", "firstname", "lastname"]
            }
        }))
        .await
    {
        Ok(value) => {
            let observed_count = value["results"].as_array().map_or(0, Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "contacts.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("HubSpot sandbox contact listing failed: {error}");
        }
    }
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> HubSpotConnector {
    let mut connector = HubSpotConnector::new();
    connector
        .handle_configure(json!({
            "access_token": env.secrets.require("access_token"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready")
        }))
        .await
        .expect("configure live connector");
    connector
        .handle_handshake(json!({
            "session_id": format!("hubspot-live-{}", env.tenant.run_prefix())
        }))
        .await
        .expect("handshake live connector");
    connector
}
