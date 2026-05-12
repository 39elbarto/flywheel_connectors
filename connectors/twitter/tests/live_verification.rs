use fcp_twitter::TwitterConnector;
use serde_json::{Map, Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const CONSUMER_KEY_ENV: &str = "TWITTER_CONSUMER_KEY";
const CONSUMER_SECRET_ENV: &str = "TWITTER_CONSUMER_SECRET";
const ACCESS_TOKEN_ENV: &str = "TWITTER_ACCESS_TOKEN";
const ACCESS_TOKEN_SECRET_ENV: &str = "TWITTER_ACCESS_TOKEN_SECRET";
const BEARER_TOKEN_ENV: &str = "TWITTER_BEARER_TOKEN";
const OPERATION: &str = "twitter.self_check_users_me";

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
        "TWITTER_LIVE_JSONL {}",
        json!({
            "event": "twitter_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [
                CONSUMER_KEY_ENV,
                CONSUMER_SECRET_ENV,
                ACCESS_TOKEN_ENV,
                ACCESS_TOKEN_SECRET_ENV
            ],
            "optional_secret_env": BEARER_TOKEN_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Twitter API v2",
            "resource_class": "authenticated_user_read_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one authenticated GET /2/users/me probe through handle_self_check.",
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn twitter_live_read_self_check_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
        );
        return;
    }

    let Some(consumer_key) = env_value(CONSUMER_KEY_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{CONSUMER_KEY_ENV} is not set"),
            "skipped",
        );
        return;
    };
    let Some(consumer_secret) = env_value(CONSUMER_SECRET_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{CONSUMER_SECRET_ENV} is not set"),
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
    let Some(access_token_secret) = env_value(ACCESS_TOKEN_SECRET_ENV) else {
        emit_live_jsonl(
            "skipped",
            &format!("{ACCESS_TOKEN_SECRET_ENV} is not set"),
            "skipped",
        );
        return;
    };

    let mut config = Map::new();
    config.insert("consumer_key".to_owned(), json!(consumer_key));
    config.insert("consumer_secret".to_owned(), json!(consumer_secret));
    config.insert("access_token".to_owned(), json!(access_token));
    config.insert("access_token_secret".to_owned(), json!(access_token_secret));
    if let Some(bearer_token) = env_value(BEARER_TOKEN_ENV) {
        config.insert("bearer_token".to_owned(), json!(bearer_token));
    }

    let mut connector = TwitterConnector::new();
    connector
        .handle_configure(Value::Object(config))
        .await
        .expect("configure Twitter OAuth credentials");

    match connector.handle_self_check().await {
        Ok(value) => {
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            assert_eq!(status, "ok", "Twitter live self-check should pass");
            emit_live_jsonl("passed", "", status);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error");
            panic!("Twitter live read smoke failed: {error}");
        }
    }
}
