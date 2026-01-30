//! Tests for `fcp connector` JSON outputs (agent-facing schemas).
//!
//! Ensures MCP/agent fields are present in introspection/info JSON.

use assert_cmd::cargo::cargo_bin_cmd;
use chrono::Utc;
use fcp_testkit::LogCapture;
use serde_json::Value;

fn run_fcp(args: &[&str]) -> Value {
    let mut cmd = cargo_bin_cmd!("fcp");
    let output = cmd.args(args).output().expect("run fcp");
    assert!(
        output.status.success(),
        "fcp command failed: {:?}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    serde_json::from_str(&stdout).expect("valid json")
}

#[test]
fn connector_introspect_json_includes_mcp_fields() {
    let capture = LogCapture::new();
    let correlation_id = format!("connector-introspect-{}", std::process::id());

    let payload = run_fcp(&["connector", "introspect", "fcp.twitter:social:v1", "--json"]);

    let operations = payload
        .get("operations")
        .and_then(Value::as_array)
        .expect("operations array");
    assert!(!operations.is_empty(), "expected operations");

    let timeline = operations
        .iter()
        .find(|op| op.get("id").and_then(Value::as_str) == Some("twitter.get_timeline"))
        .expect("timeline operation");
    assert_eq!(
        timeline
            .get("capability")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "twitter:read:tweets"
    );
    assert_eq!(
        timeline
            .get("risk_level")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "low"
    );
    assert_eq!(
        timeline
            .get("safety_tier")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "safe"
    );
    assert_eq!(
        timeline
            .get("idempotency")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "best_effort"
    );
    assert!(timeline.get("requires_approval").is_none());
    let hints = timeline
        .get("ai_hints")
        .and_then(Value::as_object)
        .expect("ai_hints object");
    assert!(hints.get("when_to_use").is_some());
    assert!(hints.get("common_mistakes").is_some());
    assert!(hints.get("examples").is_some());
    assert!(hints.get("related").is_some());

    let post = operations
        .iter()
        .find(|op| op.get("id").and_then(Value::as_str) == Some("twitter.post_tweet"))
        .expect("post operation");
    assert_eq!(
        post.get("requires_approval")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "interactive"
    );

    let log = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": "connector_introspect_json_includes_mcp_fields",
        "module": "fcp-cli::connector",
        "phase": "verify",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": 0,
        "assertions": { "passed": 12, "failed": 0 },
        "details": { "operations": operations.len() }
    });
    capture.push_line(&log.to_string());
    capture.validate_jsonl().expect("structured log");
}

#[test]
fn connector_info_json_includes_capabilities() {
    let capture = LogCapture::new();
    let correlation_id = format!("connector-info-{}", std::process::id());

    let payload = run_fcp(&["connector", "info", "fcp.twitter:social:v1", "--json"]);

    let required = payload
        .get("required_capabilities")
        .and_then(Value::as_array)
        .expect("required_capabilities array");
    assert!(
        required
            .iter()
            .any(|cap| cap.as_str() == Some("twitter:read:tweets"))
    );

    let optional = payload
        .get("optional_capabilities")
        .and_then(Value::as_array)
        .expect("optional_capabilities array");
    assert!(
        optional
            .iter()
            .any(|cap| cap.as_str() == Some("twitter:write:tweets"))
    );

    let ops = payload
        .get("operations")
        .and_then(Value::as_array)
        .expect("operations array");
    let op = ops
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some("twitter.get_timeline"))
        .expect("operation entry");
    assert_eq!(
        op.get("risk_level")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "low"
    );
    assert_eq!(
        op.get("safety_tier")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "safe"
    );

    let log = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": "connector_info_json_includes_capabilities",
        "module": "fcp-cli::connector",
        "phase": "verify",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": 0,
        "assertions": { "passed": 5, "failed": 0 },
        "details": { "operations": ops.len() }
    });
    capture.push_line(&log.to_string());
    capture.validate_jsonl().expect("structured log");
}

#[test]
fn connector_introspect_json_includes_rate_limits() {
    let capture = LogCapture::new();
    let correlation_id = format!("connector-introspect-rate-limits-{}", std::process::id());

    let payload = run_fcp(&["connector", "introspect", "fcp.twitter:social:v1", "--json"]);
    let rate_limits = payload
        .get("rate_limits")
        .and_then(Value::as_object)
        .expect("rate_limits object");
    let pools = rate_limits
        .get("limits")
        .and_then(Value::as_array)
        .expect("rate_limits.limits array");
    assert!(
        pools
            .iter()
            .any(|pool| { pool.get("id").and_then(Value::as_str) == Some("twitter_api") }),
        "expected twitter_api pool"
    );

    let tool_pool_map = rate_limits
        .get("tool_pool_map")
        .and_then(Value::as_object)
        .expect("tool_pool_map object");
    let timeline_pools = tool_pool_map
        .get("twitter.get_timeline")
        .and_then(Value::as_array)
        .expect("twitter.get_timeline pools");
    assert!(
        timeline_pools
            .iter()
            .any(|pool| pool.as_str() == Some("twitter_api")),
        "expected twitter.get_timeline to map to twitter_api pool"
    );

    let log = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": "connector_introspect_json_includes_rate_limits",
        "module": "fcp-cli::connector",
        "phase": "verify",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": 0,
        "assertions": { "passed": 2, "failed": 0 },
        "details": { "pools": pools.len() }
    });
    capture.push_line(&log.to_string());
    capture.validate_jsonl().expect("structured log");
}

#[test]
fn connector_info_json_includes_rate_limits() {
    let capture = LogCapture::new();
    let correlation_id = format!("connector-info-rate-limits-{}", std::process::id());

    let payload = run_fcp(&["connector", "info", "fcp.twitter:social:v1", "--json"]);
    let rate_limits = payload
        .get("rate_limits")
        .and_then(Value::as_object)
        .expect("rate_limits object");
    let pools = rate_limits
        .get("limits")
        .and_then(Value::as_array)
        .expect("rate_limits.limits array");
    assert!(
        pools
            .iter()
            .any(|pool| { pool.get("id").and_then(Value::as_str) == Some("twitter_api") }),
        "expected twitter_api pool"
    );

    let tool_pool_map = rate_limits
        .get("tool_pool_map")
        .and_then(Value::as_object)
        .expect("tool_pool_map object");
    let timeline_pools = tool_pool_map
        .get("twitter.get_timeline")
        .and_then(Value::as_array)
        .expect("twitter.get_timeline pools");
    assert!(
        timeline_pools
            .iter()
            .any(|pool| pool.as_str() == Some("twitter_api")),
        "expected twitter.get_timeline to map to twitter_api pool"
    );

    let log = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "level": "info",
        "test_name": "connector_info_json_includes_rate_limits",
        "module": "fcp-cli::connector",
        "phase": "verify",
        "correlation_id": correlation_id,
        "result": "pass",
        "duration_ms": 0,
        "assertions": { "passed": 2, "failed": 0 },
        "details": { "pools": pools.len() }
    });
    capture.push_line(&log.to_string());
    capture.validate_jsonl().expect("structured log");
}
