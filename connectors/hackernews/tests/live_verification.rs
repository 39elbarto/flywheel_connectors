use fcp_hackernews::connector::HackerNewsConnector;
use fcp_prelude::FcpConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const OPERATION: &str = "hackernews.top_stories";

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn emit_live_jsonl(status: &str, reason: &str, ready: bool) {
    println!(
        "HACKERNEWS_LIVE_JSONL {}",
        json!({
            "event": "hackernews_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Hacker News Firebase API",
            "resource_class": "public_topstories_probe",
            "ready": ready,
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn hackernews_live_read_self_check_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            false,
        );
        return;
    }

    let mut connector = HackerNewsConnector::new();
    connector
        .configure(json!({
            "request_timeout_ms": 5_000,
            "retry": {
                "max_retries": 1,
                "initial_delay_ms": 100,
                "max_delay_ms": 250,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure Hacker News defaults");

    match connector.self_check().await {
        Ok(report) => {
            let value = serde_json::to_value(&report).expect("serialize self-check");
            let ready = value.get("ready").and_then(Value::as_bool).unwrap_or(false);
            assert!(ready, "Hacker News live self-check should be ready");
            emit_live_jsonl("passed", "", ready);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), false);
            panic!("Hacker News live read smoke failed: {error}");
        }
    }
}
