use fcp_brave_search::BraveSearchConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const API_KEY_ENV: &str = "BRAVE_SEARCH_API_KEY";
const OPERATION: &str = "brave-search.web.search";

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
        "BRAVE_SEARCH_LIVE_JSONL {}",
        json!({
            "event": "brave_search_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_KEY_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Brave Search API",
            "resource_class": "read_only_web_search",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one web-search probe with count=1 through handle_self_check.",
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn brave_search_live_read_self_check_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
        );
        return;
    }

    let Some(api_key) = env_value(API_KEY_ENV) else {
        emit_live_jsonl("skipped", &format!("{API_KEY_ENV} is not set"), "skipped");
        return;
    };

    let mut connector = BraveSearchConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "request_timeout_ms": 10_000,
        }))
        .await
        .expect("configure Brave Search API key");
    connector
        .handle_handshake(json!({ "session_id": "brave-search-live-read" }))
        .await
        .expect("handshake Brave Search live connector");

    match connector.handle_self_check().await {
        Ok(value) => {
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            assert_eq!(status, "ok", "Brave Search live self-check should pass");
            emit_live_jsonl("passed", "", status);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error");
            panic!("Brave Search live read smoke failed: {error}");
        }
    }
}
