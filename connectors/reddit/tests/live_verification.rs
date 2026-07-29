use fcp_reddit::connector::RedditConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const TOKEN_ENV: &str = "REDDIT_BEARER_TOKEN";
const OPERATION: &str = "reddit.search_posts";

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

fn emit_live_jsonl(status: &str, reason: &str, result_count: usize) {
    println!(
        "REDDIT_LIVE_JSONL {}",
        json!({
            "event": "reddit_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Reddit OAuth API",
            "resource_class": "read_only_search",
            "result_count": result_count,
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn reddit_live_read_search_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let Some(token) = env_value(TOKEN_ENV) else {
        emit_live_jsonl("skipped", &format!("{TOKEN_ENV} is not set"), 0);
        return;
    };

    let mut connector = RedditConnector::new();
    connector
        .handle_configure(json!({ "bearer_token": token }))
        .await
        .expect("configure Reddit bearer token");
    connector
        .handle_handshake(json!({ "session_id": "reddit-live-read" }))
        .await
        .expect("handshake Reddit live connector");

    match connector
        .handle_invoke(json!({
            "operation_id": OPERATION,
            "input": {
                "query": "rust",
                "subreddit": "rust",
                "limit": 1,
            }
        }))
        .await
    {
        Ok(value) => {
            let result_count = value
                .get("posts")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            assert!(result_count <= 1, "live smoke caps Reddit result count");
            emit_live_jsonl("passed", "", result_count);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0);
            panic!("Reddit live read smoke failed: {error}");
        }
    }
}
