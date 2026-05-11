use fcp_semanticscholar::connector::SemanticScholarConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const OPERATION: &str = "semanticscholar.paper.search";

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn emit_live_jsonl(status: &str, reason: &str, result_count: usize) {
    println!(
        "SEMANTICSCHOLAR_LIVE_JSONL {}",
        json!({
            "event": "semanticscholar_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "operation": OPERATION,
            "status": status,
            "provider": "Semantic Scholar Graph API",
            "resource_class": "public_paper_search",
            "result_count": result_count,
            "mutation_expected": false,
            "cleanup_result": "not_required",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn semanticscholar_live_read_search_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl("skipped", &format!("{LIVE_GATE_ENV} is not set to 1"), 0);
        return;
    }

    let mut connector = SemanticScholarConnector::new();
    connector
        .handle_configure(json!({}))
        .await
        .expect("configure Semantic Scholar public defaults");
    connector
        .handle_handshake(json!({ "session_id": "semanticscholar-live-read" }))
        .await
        .expect("handshake Semantic Scholar live connector");

    match connector
        .handle_invoke(json!({
            "operation_id": OPERATION,
            "input": {
                "query": "transformers",
                "limit": 1,
                "fields": "paperId,title,year",
            }
        }))
        .await
    {
        Ok(value) => {
            let result_count = value
                .get("data")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            assert!(
                result_count <= 1,
                "live smoke caps Semantic Scholar result count"
            );
            emit_live_jsonl("passed", "", result_count);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0);
            panic!("Semantic Scholar live read smoke failed: {error}");
        }
    }
}
