use fcp_aws::connector::AwsConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_KEY_ID_ENV: &str = "AWS_SANDBOX_ACCESS_KEY_ID";
const SECRET_ACCESS_KEY_ENV: &str = "AWS_SANDBOX_SECRET_ACCESS_KEY";
const SESSION_TOKEN_ENV: &str = "AWS_SANDBOX_SESSION_TOKEN";
const REGION_ENV: &str = "AWS_SANDBOX_REGION";
const STS_BASE_URL_ENV: &str = "AWS_SANDBOX_STS_BASE_URL";
const OPERATION: &str = "aws.sts.get_caller_identity";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("aws", "Amazon Web Services sandbox")
        .with_env_secret(
            "access_key_id",
            ACCESS_KEY_ID_ENV,
            "Sandbox AWS access key id scoped to the verification account",
        )
        .with_env_secret(
            "secret_access_key",
            SECRET_ACCESS_KEY_ENV,
            "Sandbox AWS secret access key scoped to the verification account",
        )
        .with_env_var_default(
            REGION_ENV,
            "us-east-1",
            "AWS region used for signing the STS verification request",
        )
        .with_env_var(
            STS_BASE_URL_ENV,
            "Dedicated sandbox, LocalStack, or signing-proxy STS endpoint",
        )
        .with_account_setup(
            "Use a dedicated AWS sandbox account or LocalStack/STSesque signing proxy with no production credentials.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn optional_env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, evidence: &Value) {
    println!(
        "AWS_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "aws_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [ACCESS_KEY_ID_ENV, SECRET_ACCESS_KEY_ENV],
            "optional_secret_env": SESSION_TOKEN_ENV,
            "required_env": STS_BASE_URL_ENV,
            "defaulted_env": REGION_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Amazon Web Services sandbox",
            "environment": "sandbox",
            "resource_class": "sts_caller_identity_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one signed STS GetCallerIdentity probe against the configured sandbox STS endpoint.",
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
async fn aws_live_sandbox_self_check_or_structured_skip_jsonl() {
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

    let mut config = json!({
        "access_key_id": env.secrets.require("access_key_id"),
        "secret_access_key": env.secrets.require("secret_access_key"),
        "region": env.env_vars.get(REGION_ENV).expect("region env is ready"),
        "sts_base_url": env.env_vars.get(STS_BASE_URL_ENV).expect("STS endpoint env is ready"),
        "request_timeout_ms": 10_000,
        "retry": { "max_retries": 1 }
    });
    if let Some(session_token) = optional_env_value(SESSION_TOKEN_ENV) {
        config["session_token"] = json!(session_token);
    }

    let mut connector = AwsConnector::new();
    connector
        .configure(config)
        .await
        .expect("configure AWS sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            let details = report.details.unwrap_or_else(|| json!({}));
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "AWS sandbox self-check should pass"
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
            panic!("AWS sandbox self-check failed: {error}");
        }
    }
}
