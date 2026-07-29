use fcp_paypal::connector::PayPalConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use serde_json::{Map, Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const CLIENT_ID_ENV: &str = "PAYPAL_SANDBOX_CLIENT_ID";
const CLIENT_SECRET_ENV: &str = "PAYPAL_SANDBOX_CLIENT_SECRET";
const OPERATION: &str = "paypal.self_check_orders_probe";

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

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str) {
    println!(
        "PAYPAL_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "paypal_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "live_sandbox",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [CLIENT_ID_ENV, CLIENT_SECRET_ENV],
            "operation": OPERATION,
            "status": status,
            "provider": "PayPal sandbox API",
            "environment": "sandbox",
            "resource_class": "orders_read_probe",
            "connector_status": connector_status,
            "call_ceiling": 2,
            "rate_limit_guidance": "Performs one OAuth token request and one GET /v2/checkout/orders?limit=1 sandbox probe.",
            "mutation_expected": false,
            "cleanup_strategy": "none",
            "cleanup_result": "not_required",
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn paypal_live_sandbox_self_check_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
        );
        return;
    }

    let Some(client_id) = env_value(CLIENT_ID_ENV) else {
        emit_live_jsonl("skipped", &format!("{CLIENT_ID_ENV} is not set"), "skipped");
        return;
    };
    let Some(client_secret) = env_value(CLIENT_SECRET_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{CLIENT_SECRET_ENV} is not set"),
            "skipped",
        );
        return;
    };

    let mut config = Map::new();
    config.insert("client_id".to_owned(), json!(client_id));
    config.insert("client_secret".to_owned(), json!(client_secret));
    config.insert("sandbox".to_owned(), json!(true));
    config.insert("request_timeout_ms".to_owned(), json!(10_000));
    config.insert(
        "base_url".to_owned(),
        json!("https://api-m.sandbox.paypal.com"),
    );

    let mut connector = PayPalConnector::new();
    connector
        .configure(Value::Object(config))
        .await
        .expect("configure PayPal sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "PayPal sandbox self-check should pass"
            );
            emit_live_jsonl("passed", "", &connector_status);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error");
            panic!("PayPal sandbox self-check failed: {error}");
        }
    }
}
