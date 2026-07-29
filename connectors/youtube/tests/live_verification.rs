use fcp_youtube::connector::YouTubeConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const API_KEY_ENV: &str = "YOUTUBE_API_KEY";
const OPERATION: &str = "youtube.search";

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
        "YOUTUBE_LIVE_JSONL {}",
        json!({
            "event": "youtube_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_KEY_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "YouTube Data API v3",
            "resource_class": "read_only_search_probe",
            "connector_status": connector_status,
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn youtube_live_read_self_check_or_structured_skip_jsonl() {
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

    let mut connector = YouTubeConnector::new();
    connector
        .handle_configure(json!({ "api_key": api_key }))
        .await
        .expect("configure YouTube API key");

    match connector.handle_self_check().await {
        Ok(value) => {
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            assert_eq!(status, "ok", "YouTube live self-check should pass");
            emit_live_jsonl("passed", "", status);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error");
            panic!("YouTube live read smoke failed: {error}");
        }
    }
}
