use fcp_microsoft365::connector::M365Connector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "MICROSOFT365_SANDBOX_ACCESS_TOKEN";
const API_URL_ENV: &str = "MICROSOFT365_SANDBOX_API_URL";
const OPERATION: &str = "m365.self_check";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("microsoft365", "Microsoft 365 sandbox")
        .with_env_secret(
            "access_token",
            ACCESS_TOKEN_ENV,
            "Microsoft Graph access token for a dedicated test tenant",
        )
        .with_env_var_default(
            API_URL_ENV,
            "https://graph.microsoft.com/v1.0",
            "Microsoft Graph API endpoint for the test tenant",
        )
        .with_account_setup(
            "Use a dedicated Microsoft 365 developer/test tenant and a token with User.Read or equivalent read scope.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, evidence: &Value) {
    println!(
        "MICROSOFT365_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "microsoft365_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": ACCESS_TOKEN_ENV,
            "defaulted_env": API_URL_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Microsoft 365 sandbox",
            "environment": "sandbox",
            "resource_class": "graph_profile_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one Microsoft Graph /me or /organization health probe.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
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
async fn microsoft365_live_sandbox_self_check_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            "skipped",
            &env.evidence_summary(),
        );
        return;
    }

    let mut connector = M365Connector::new();
    connector
        .handle_configure(json!({
            "access_token": env.secrets.require("access_token"),
            "api_url": env.env_vars.get(API_URL_ENV).expect("API URL env is ready"),
            "required_permissions": []
        }))
        .await
        .expect("configure Microsoft 365 sandbox credentials");

    match connector.handle_self_check().await {
        Ok(value) => {
            let connector_status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            assert_eq!(
                connector_status, "healthy",
                "Microsoft 365 sandbox self-check should pass"
            );
            emit_live_jsonl(
                "passed",
                "",
                connector_status,
                &json!({
                    "environment": env.evidence_summary(),
                    "self_check": value,
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                "error",
                &env.evidence_summary(),
            );
            panic!("Microsoft 365 sandbox self-check failed: {error}");
        }
    }
}
