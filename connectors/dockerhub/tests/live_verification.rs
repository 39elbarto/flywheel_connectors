use fcp_dockerhub::connector::DockerHubConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "DOCKERHUB_SANDBOX_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "DOCKERHUB_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "DOCKERHUB_SANDBOX_NAMESPACE";
const OPERATION: &str = "dockerhub.health";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("dockerhub", "Docker Hub sandbox")
        .with_env_secret(
            "access_token",
            ACCESS_TOKEN_ENV,
            "Docker Hub access token for a dedicated test account",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://hub.docker.com",
            "Docker Hub API endpoint",
        )
        .with_env_var_default(
            NAMESPACE_ENV,
            "",
            "Optional Docker Hub namespace for sandbox repository probes",
        )
        .with_account_setup("Use a dedicated Docker Hub test account with a revocable token.")
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, evidence: &Value) {
    println!(
        "DOCKERHUB_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "dockerhub_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": ACCESS_TOKEN_ENV,
            "defaulted_env": [BASE_URL_ENV, NAMESPACE_ENV],
            "operation": OPERATION,
            "status": status,
            "provider": "Docker Hub sandbox",
            "environment": "sandbox",
            "resource_class": "authenticated_user_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one Docker Hub authenticated user probe.",
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
async fn dockerhub_live_sandbox_self_check_or_structured_skip_jsonl() {
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

    let namespace = env.env_vars.get(NAMESPACE_ENV).unwrap_or_default();
    let mut config = json!({
        "mode": "token",
        "access_token": env.secrets.require("access_token"),
        "base_url": env.env_vars.get(BASE_URL_ENV).expect("base URL env is ready"),
        "request_timeout_ms": 10_000,
        "retry": { "max_retries": 1 }
    });
    if !namespace.trim().is_empty() {
        config["namespace"] = json!(namespace);
    }

    let mut connector = DockerHubConnector::new();
    connector
        .configure(config)
        .await
        .expect("configure Docker Hub sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "Docker Hub sandbox self-check should pass"
            );
            emit_live_jsonl(
                "passed",
                "",
                &connector_status,
                &json!({
                    "environment": env.evidence_summary(),
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
            panic!("Docker Hub sandbox self-check failed: {error}");
        }
    }
}
