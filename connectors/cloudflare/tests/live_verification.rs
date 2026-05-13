use fcp_cloudflare::connector::CloudflareConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const API_TOKEN_ENV: &str = "CLOUDFLARE_SANDBOX_API_TOKEN";
const ACCOUNT_ID_ENV: &str = "CLOUDFLARE_SANDBOX_ACCOUNT_ID";
const BASE_URL_ENV: &str = "CLOUDFLARE_SANDBOX_BASE_URL";
const OPERATION: &str = "cloudflare.health";

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
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.cloudflare.com/client/v4",
            "Cloudflare API v4 endpoint",
        )
        .with_account_setup(
            "Use a dedicated Cloudflare test account with token-verification and account-scoped read permissions.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, evidence: &Value) {
    println!(
        "CLOUDFLARE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "cloudflare_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_TOKEN_ENV,
            "required_env": ACCOUNT_ID_ENV,
            "defaulted_env": BASE_URL_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Cloudflare sandbox",
            "environment": "sandbox",
            "resource_class": "token_verify_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one Cloudflare token verification probe.",
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
async fn cloudflare_live_sandbox_self_check_or_structured_skip_jsonl() {
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

    let mut connector = CloudflareConnector::new();
    connector
        .configure(json!({
            "mode": "api_token",
            "api_token": env.secrets.require("api_token"),
            "account_id": env.env_vars.get(ACCOUNT_ID_ENV).expect("account id env is ready"),
            "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
            "request_timeout_ms": 10_000,
            "retry": { "max_retries": 1 }
        }))
        .await
        .expect("configure Cloudflare sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            let details = report.details.unwrap_or_else(|| json!({}));
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "Cloudflare sandbox self-check should pass"
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
            panic!("Cloudflare sandbox self-check failed: {error}");
        }
    }
}
