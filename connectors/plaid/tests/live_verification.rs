use fcp_plaid::connector::PlaidConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const CLIENT_ID_ENV: &str = "PLAID_SANDBOX_CLIENT_ID";
const SECRET_ENV: &str = "PLAID_SANDBOX_SECRET";
const OPERATION: &str = "plaid.doctor_link_token_create";

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str, failed_checks: usize) {
    println!(
        "PLAID_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "plaid_live_sandbox_doctor",
            "fixture_mode": "live",
            "suite_class": "live_sandbox",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [CLIENT_ID_ENV, SECRET_ENV],
            "operation": OPERATION,
            "status": status,
            "provider": "Plaid sandbox API",
            "environment": "sandbox",
            "resource_class": "ephemeral_link_token_probe",
            "connector_status": connector_status,
            "failed_check_count": failed_checks,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one /link/token/create sandbox credential-validation probe.",
            "mutation_expected": false,
            "ephemeral_resource_expected": true,
            "cleanup_strategy": "none",
            "cleanup_result": "ephemeral_link_token_expires_without_cleanup",
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

fn failed_check_count(value: &Value) -> usize {
    value
        .get("checks")
        .and_then(Value::as_array)
        .map_or(0, |checks| {
            checks
                .iter()
                .filter(|check| {
                    check
                        .get("passed")
                        .and_then(Value::as_bool)
                        .is_some_and(|passed| !passed)
                })
                .count()
        })
}

#[fcp_async_core::runtime::test]
async fn plaid_live_sandbox_doctor_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
            0,
        );
        return;
    }

    let Some(client_id) = env_value(CLIENT_ID_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{CLIENT_ID_ENV} is not set"),
            "skipped",
            0,
        );
        return;
    };
    let Some(secret) = env_value(SECRET_ENV) else {
        emit_live_jsonl("skipped", &format!("{SECRET_ENV} is not set"), "skipped", 0);
        return;
    };

    let mut connector = PlaidConnector::new();
    connector
        .handle_configure(json!({
            "client_id": client_id,
            "secret": secret,
            "environment": "sandbox",
            "base_url": "https://sandbox.plaid.com",
        }))
        .await
        .expect("configure Plaid sandbox credentials");

    match connector.handle_doctor().await {
        Ok(value) => {
            let connector_status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let failed_checks = failed_check_count(&value);
            assert_eq!(
                connector_status, "healthy",
                "Plaid sandbox doctor should pass"
            );
            emit_live_jsonl("passed", "", connector_status, failed_checks);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error", 0);
            panic!("Plaid sandbox doctor failed: {error}");
        }
    }
}
