use fcp_wolfram::WolframConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const APP_ID_ENV: &str = "WOLFRAM_APP_ID";
const OPERATION: &str = "wolfram.short_answer";

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

fn emit_live_jsonl(status: &str, reason: &str, answer_present: bool) {
    println!(
        "WOLFRAM_LIVE_JSONL {}",
        json!({
            "event": "wolfram_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": APP_ID_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Wolfram Alpha API",
            "resource_class": "short_answer_read",
            "answer_present": answer_present,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one /v1/result short-answer query for 2+2.",
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn wolfram_live_read_short_answer_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            false,
        );
        return;
    }

    let Some(app_id) = env_value(APP_ID_ENV) else {
        emit_live_jsonl("skipped", &format!("{APP_ID_ENV} is not set"), false);
        return;
    };

    let mut connector = WolframConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "timeout_ms": 10_000,
        }))
        .await
        .expect("configure Wolfram connector");

    match connector
        .handle_invoke(json!({
            "operation": OPERATION,
            "input": {
                "input": "2+2",
                "app_id": app_id,
            }
        }))
        .await
    {
        Ok(value) => {
            let answer_present = value
                .get("answer")
                .and_then(Value::as_str)
                .is_some_and(|answer| !answer.trim().is_empty());
            assert!(answer_present, "Wolfram short answer should be present");
            emit_live_jsonl("passed", "", answer_present);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), false);
            panic!("Wolfram live read smoke failed: {error}");
        }
    }
}
