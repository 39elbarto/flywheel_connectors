use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_square::SquareConnector;
use serde_json::{Map, Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const ACCESS_TOKEN_ENV: &str = "SQUARE_SANDBOX_ACCESS_TOKEN";
const BASE_URL_ENV: &str = "SQUARE_SANDBOX_BASE_URL";
const OPERATION: &str = "square.self_check_locations_probe";

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

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    connector_status: &str,
    location_count: Option<u64>,
) {
    println!(
        "SQUARE_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "square_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "live_sandbox",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": ACCESS_TOKEN_ENV,
            "optional_env": BASE_URL_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Square sandbox API",
            "environment": "sandbox",
            "resource_class": "locations_read_probe",
            "connector_status": connector_status,
            "location_count": location_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one GET /v2/locations sandbox probe.",
            "mutation_expected": false,
            "cleanup_strategy": "none",
            "cleanup_result": "not_required",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

fn location_count_from_report(details: Option<&Value>) -> Option<u64> {
    details
        .and_then(|details| details.get("live_probe"))
        .and_then(|probe| probe.get("location_count"))
        .and_then(Value::as_u64)
}

#[fcp_async_core::runtime::test]
async fn square_live_sandbox_self_check_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
            None,
        );
        return;
    }

    let Some(access_token) = env_value(ACCESS_TOKEN_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{ACCESS_TOKEN_ENV} is not set"),
            "skipped",
            None,
        );
        return;
    };
    let base_url =
        env_value(BASE_URL_ENV).unwrap_or_else(|| "https://connect.squareupsandbox.com/v2".into());

    let mut config = Map::new();
    config.insert("base_url".to_owned(), json!(base_url));
    config.insert("access_token".to_owned(), json!(access_token));
    config.insert("request_timeout_ms".to_owned(), json!(10_000));

    let mut connector = SquareConnector::new();
    connector
        .configure(Value::Object(config))
        .await
        .expect("configure Square sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            let location_count = location_count_from_report(report.details.as_ref());
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "Square sandbox self-check should pass"
            );
            emit_live_jsonl("passed", "", &connector_status, location_count);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error", None);
            panic!("Square sandbox self-check failed: {error}");
        }
    }
}
