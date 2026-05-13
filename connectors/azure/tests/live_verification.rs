use fcp_azure::connector::AzureConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const BEARER_TOKEN_ENV: &str = "AZURE_SANDBOX_BEARER_TOKEN";
const MANAGEMENT_URL_ENV: &str = "AZURE_SANDBOX_MANAGEMENT_URL";
const OPERATION: &str = "azure.management.list_subscriptions";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("azure", "Microsoft Azure sandbox")
        .with_env_secret(
            "bearer_token",
            BEARER_TOKEN_ENV,
            "Azure sandbox or test-tenant bearer token with subscription read scope",
        )
        .with_env_var_default(
            MANAGEMENT_URL_ENV,
            "https://management.azure.com",
            "Azure Resource Manager endpoint for the sandbox tenant",
        )
        .with_account_setup(
            "Use a dedicated Azure test tenant/subscription with a least-privilege token for subscription discovery.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, evidence: &Value) {
    println!(
        "AZURE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "azure_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": BEARER_TOKEN_ENV,
            "defaulted_env": MANAGEMENT_URL_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Microsoft Azure sandbox",
            "environment": "sandbox",
            "resource_class": "subscription_read_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one Azure Resource Manager subscription-list probe.",
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
async fn azure_live_sandbox_self_check_or_structured_skip_jsonl() {
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

    let mut connector = AzureConnector::new();
    connector
        .configure(json!({
            "mode": "bearer_token",
            "bearer_token": env.secrets.require("bearer_token"),
            "management_url": env.env_vars.get(MANAGEMENT_URL_ENV).expect("management URL env is ready"),
            "request_timeout_ms": 10_000,
            "retry": { "max_retries": 1 }
        }))
        .await
        .expect("configure Azure sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            let details = report.details.unwrap_or_else(|| json!({}));
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "Azure sandbox self-check should pass"
            );
            emit_live_jsonl(
                "passed",
                "",
                &connector_status,
                &json!({
                    "environment": env.evidence_summary(),
                    "self_check_details": details,
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
            panic!("Azure sandbox self-check failed: {error}");
        }
    }
}
