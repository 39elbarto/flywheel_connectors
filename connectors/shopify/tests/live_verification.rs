use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use fcp_shopify::connector::ShopifyConnector;
use serde_json::{Map, Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const SHOP_DOMAIN_ENV: &str = "SHOPIFY_SANDBOX_SHOP_DOMAIN";
const ACCESS_TOKEN_ENV: &str = "SHOPIFY_SANDBOX_ACCESS_TOKEN";
const API_VERSION_ENV: &str = "SHOPIFY_SANDBOX_API_VERSION";
const OPERATION: &str = "shopify.self_check_shop_probe";

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
        "SHOPIFY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "shopify_live_sandbox_self_check",
            "fixture_mode": "live",
            "suite_class": "live_sandbox",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [SHOP_DOMAIN_ENV, ACCESS_TOKEN_ENV],
            "optional_env": API_VERSION_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Shopify Admin API development store",
            "environment": "sandbox",
            "resource_class": "shop_metadata_read_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one GET /admin/api/<version>/shop.json probe against a development or test shop.",
            "mutation_expected": false,
            "cleanup_strategy": "none",
            "cleanup_result": "not_required",
            "shop_identity_logged": false,
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn shopify_live_sandbox_self_check_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
        );
        return;
    }

    let Some(shop_domain) = env_value(SHOP_DOMAIN_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{SHOP_DOMAIN_ENV} is not set"),
            "skipped",
        );
        return;
    };
    let Some(access_token) = env_value(ACCESS_TOKEN_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{ACCESS_TOKEN_ENV} is not set"),
            "skipped",
        );
        return;
    };

    let mut config = Map::new();
    config.insert("shop_domain".to_owned(), json!(shop_domain));
    config.insert("access_token".to_owned(), json!(access_token));
    config.insert("request_timeout_ms".to_owned(), json!(10_000));
    if let Some(api_version) = env_value(API_VERSION_ENV) {
        config.insert("api_version".to_owned(), json!(api_version));
    }

    let mut connector = ShopifyConnector::new();
    connector
        .configure(Value::Object(config))
        .await
        .expect("configure Shopify sandbox credentials");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "Shopify sandbox self-check should pass"
            );
            emit_live_jsonl("passed", "", &connector_status);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error");
            panic!("Shopify sandbox self-check failed: {error}");
        }
    }
}
