//! Zapier API types.

use serde::{Deserialize, Serialize};

/// A Zapier zap (automation workflow).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zap {
    /// Unique identifier for the zap.
    pub id: String,
    /// Human-readable title.
    pub title: Option<String>,
    /// Whether the zap is currently enabled.
    pub is_enabled: Option<bool>,
    /// Number of steps in the zap.
    pub steps: Option<u64>,
    /// URL to edit the zap.
    pub url: Option<String>,
    /// Last modified timestamp.
    pub modified_at: Option<String>,
}

/// A Zapier NLA action (exposed action for NLA API).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NlaAction {
    /// Unique action ID.
    pub id: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// The operation type (e.g., "Slack: Send Channel Message").
    pub operation_type: Option<String>,
    /// Action parameters schema.
    pub params: Option<serde_json::Value>,
}

/// Result of executing a Zapier NLA action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Status of the execution.
    pub status: Option<String>,
    /// Result data from the execution.
    pub result: Option<serde_json::Value>,
    /// Action ID that was executed.
    pub action_id: Option<String>,
    /// Error message if execution failed.
    pub error: Option<String>,
}

/// Zapier API error response body.
///
/// Zapier returns `{"error": "message"}` or `{"detail": "message"}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message.
    pub error: Option<String>,
    /// Alternative detail field used in some endpoints.
    pub detail: Option<String>,
    /// Error type descriptor.
    #[serde(rename = "type")]
    pub error_type: Option<String>,
}

/// A zap execution/run history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZapRun {
    /// Unique run identifier.
    pub id: String,
    /// Status of the run (e.g., "success", "error").
    pub status: Option<String>,
    /// Start time of the run.
    pub start_time: Option<String>,
    /// End time of the run.
    pub end_time: Option<String>,
    /// The zap ID this run belongs to.
    pub zap_id: Option<String>,
    /// Data produced by the run.
    pub data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn zap_roundtrip() {
        let z: Zap = serde_json::from_value(json!({
            "id": "zap_abc123",
            "title": "New Lead to Slack",
            "is_enabled": true,
            "steps": 3,
            "url": "https://zapier.com/app/zap/abc123",
            "modified_at": "2026-01-15T10:30:00Z",
        }))
        .unwrap();
        assert_eq!(z.id, "zap_abc123");
        assert_eq!(z.title, Some("New Lead to Slack".into()));
        assert_eq!(z.is_enabled, Some(true));
        assert_eq!(z.steps, Some(3));
        assert_eq!(z.url, Some("https://zapier.com/app/zap/abc123".into()));
        assert_eq!(z.modified_at, Some("2026-01-15T10:30:00Z".into()));
        let re = serde_json::to_value(&z).unwrap();
        assert_eq!(re["title"], "New Lead to Slack");
    }

    #[test]
    fn zap_minimal() {
        let z: Zap = serde_json::from_value(json!({"id": "z1"})).unwrap();
        assert_eq!(z.id, "z1");
        assert!(z.title.is_none());
        assert!(z.is_enabled.is_none());
        assert!(z.steps.is_none());
        assert!(z.url.is_none());
        assert!(z.modified_at.is_none());
    }

    #[test]
    fn zap_disabled() {
        let z: Zap = serde_json::from_value(json!({
            "id": "z2",
            "is_enabled": false,
        }))
        .unwrap();
        assert_eq!(z.is_enabled, Some(false));
    }

    #[test]
    fn zap_serialize_roundtrip() {
        let z = Zap {
            id: "z1".into(),
            title: Some("My Zap".into()),
            is_enabled: Some(true),
            steps: Some(5),
            url: None,
            modified_at: None,
        };
        let v = serde_json::to_value(&z).unwrap();
        assert_eq!(v["id"], "z1");
        assert_eq!(v["title"], "My Zap");
        assert_eq!(v["steps"], 5);
    }

    #[test]
    fn zap_extra_fields_ignored() {
        let z: Zap = serde_json::from_value(json!({
            "id": "z1",
            "title": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(z.id, "z1");
        assert_eq!(z.title, Some("Test".into()));
    }

    #[test]
    fn nla_action_roundtrip() {
        let a: NlaAction = serde_json::from_value(json!({
            "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "description": "Send a Slack message",
            "operation_type": "Slack: Send Channel Message",
            "params": {"channel": "string", "body": "string"},
        }))
        .unwrap();
        assert_eq!(a.id, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(a.description, Some("Send a Slack message".into()));
        assert_eq!(a.operation_type, Some("Slack: Send Channel Message".into()));
        assert!(a.params.is_some());
    }

    #[test]
    fn nla_action_minimal() {
        let a: NlaAction = serde_json::from_value(json!({"id": "a1"})).unwrap();
        assert_eq!(a.id, "a1");
        assert!(a.description.is_none());
        assert!(a.operation_type.is_none());
        assert!(a.params.is_none());
    }

    #[test]
    fn nla_action_serialize() {
        let a = NlaAction {
            id: "a1".into(),
            description: Some("Send email".into()),
            operation_type: None,
            params: Some(json!({"to": "string"})),
        };
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["id"], "a1");
        assert_eq!(v["description"], "Send email");
    }

    #[test]
    fn nla_action_extra_fields_ignored() {
        let a: NlaAction = serde_json::from_value(json!({
            "id": "a1",
            "description": "Do thing",
            "extra": 42,
        }))
        .unwrap();
        assert_eq!(a.id, "a1");
    }

    #[test]
    fn execution_result_roundtrip() {
        let r: ExecutionResult = serde_json::from_value(json!({
            "status": "success",
            "result": {"message_id": "msg_123"},
            "action_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        }))
        .unwrap();
        assert_eq!(r.status, Some("success".into()));
        assert!(r.result.is_some());
        assert_eq!(r.action_id, Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()));
        assert!(r.error.is_none());
    }

    #[test]
    fn execution_result_with_error() {
        let r: ExecutionResult = serde_json::from_value(json!({
            "status": "error",
            "error": "Action execution failed: invalid params",
        }))
        .unwrap();
        assert_eq!(r.status, Some("error".into()));
        assert_eq!(r.error, Some("Action execution failed: invalid params".into()));
        assert!(r.result.is_none());
    }

    #[test]
    fn execution_result_minimal() {
        let r: ExecutionResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.status.is_none());
        assert!(r.result.is_none());
        assert!(r.action_id.is_none());
        assert!(r.error.is_none());
    }

    #[test]
    fn execution_result_serialize() {
        let r = ExecutionResult {
            status: Some("success".into()),
            result: Some(json!({"ok": true})),
            action_id: Some("a1".into()),
            error: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["result"]["ok"], true);
    }

    #[test]
    fn api_error_response_with_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Authentication required",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Authentication required".into()));
        assert!(e.detail.is_none());
        assert!(e.error_type.is_none());
    }

    #[test]
    fn api_error_response_with_detail() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "Not found",
        }))
        .unwrap();
        assert!(e.error.is_none());
        assert_eq!(e.detail, Some("Not found".into()));
    }

    #[test]
    fn api_error_response_with_type() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Bad request",
            "type": "validation_error",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Bad request".into()));
        assert_eq!(e.error_type, Some("validation_error".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.detail.is_none());
        assert!(e.error_type.is_none());
    }

    #[test]
    fn zap_run_roundtrip() {
        let r: ZapRun = serde_json::from_value(json!({
            "id": "run_abc123",
            "status": "success",
            "start_time": "2026-01-15T10:30:00Z",
            "end_time": "2026-01-15T10:30:05Z",
            "zap_id": "zap_abc123",
            "data": {"rows_created": 3},
        }))
        .unwrap();
        assert_eq!(r.id, "run_abc123");
        assert_eq!(r.status, Some("success".into()));
        assert_eq!(r.start_time, Some("2026-01-15T10:30:00Z".into()));
        assert_eq!(r.end_time, Some("2026-01-15T10:30:05Z".into()));
        assert_eq!(r.zap_id, Some("zap_abc123".into()));
        assert!(r.data.is_some());
    }

    #[test]
    fn zap_run_minimal() {
        let r: ZapRun = serde_json::from_value(json!({"id": "r1"})).unwrap();
        assert_eq!(r.id, "r1");
        assert!(r.status.is_none());
        assert!(r.start_time.is_none());
        assert!(r.end_time.is_none());
        assert!(r.zap_id.is_none());
        assert!(r.data.is_none());
    }

    #[test]
    fn zap_run_error_status() {
        let r: ZapRun = serde_json::from_value(json!({
            "id": "r2",
            "status": "error",
        }))
        .unwrap();
        assert_eq!(r.status, Some("error".into()));
    }

    #[test]
    fn zap_run_serialize() {
        let r = ZapRun {
            id: "r1".into(),
            status: Some("success".into()),
            start_time: None,
            end_time: None,
            zap_id: Some("z1".into()),
            data: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["id"], "r1");
        assert_eq!(v["status"], "success");
        assert_eq!(v["zap_id"], "z1");
    }

    #[test]
    fn zap_run_extra_fields_ignored() {
        let r: ZapRun = serde_json::from_value(json!({
            "id": "r1",
            "unknown": true,
        }))
        .unwrap();
        assert_eq!(r.id, "r1");
    }

    #[test]
    fn zap_with_zero_steps() {
        let z: Zap = serde_json::from_value(json!({
            "id": "z1",
            "steps": 0,
        }))
        .unwrap();
        assert_eq!(z.steps, Some(0));
    }

    #[test]
    fn execution_result_extra_fields_ignored() {
        let r: ExecutionResult = serde_json::from_value(json!({
            "status": "success",
            "extra_field": 42,
        }))
        .unwrap();
        assert_eq!(r.status, Some("success".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn zap_clone() {
        let z = Zap {
            id: "z1".into(),
            title: Some("My Zap".into()),
            is_enabled: Some(true),
            steps: Some(3),
            url: None,
            modified_at: None,
        };
        let z2 = z.clone();
        assert_eq!(z2.id, "z1");
        assert_eq!(z2.title, Some("My Zap".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn nla_action_clone() {
        let a = NlaAction {
            id: "a1".into(),
            description: Some("Send".into()),
            operation_type: None,
            params: None,
        };
        let a2 = a.clone();
        assert_eq!(a2.id, "a1");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn execution_result_clone() {
        let r = ExecutionResult {
            status: Some("success".into()),
            result: Some(json!({"ok": true})),
            action_id: Some("a1".into()),
            error: None,
        };
        let r2 = r.clone();
        assert_eq!(r2.status, Some("success".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn zap_run_clone() {
        let r = ZapRun {
            id: "r1".into(),
            status: Some("success".into()),
            start_time: None,
            end_time: None,
            zap_id: Some("z1".into()),
            data: None,
        };
        let r2 = r.clone();
        assert_eq!(r2.id, "r1");
    }

    #[test]
    fn zap_debug_format() {
        let z = Zap {
            id: "z1".into(),
            title: Some("Test".into()),
            is_enabled: None,
            steps: None,
            url: None,
            modified_at: None,
        };
        let dbg = format!("{z:?}");
        assert!(dbg.contains("Zap"));
        assert!(dbg.contains("z1"));
    }

    #[test]
    fn nla_action_debug_format() {
        let a = NlaAction {
            id: "a1".into(),
            description: None,
            operation_type: None,
            params: None,
        };
        let dbg = format!("{a:?}");
        assert!(dbg.contains("NlaAction"));
    }

    #[test]
    fn api_error_response_both_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "bad",
            "detail": "also bad",
            "type": "err_type"
        }))
        .unwrap();
        assert_eq!(e.error, Some("bad".into()));
        assert_eq!(e.detail, Some("also bad".into()));
        assert_eq!(e.error_type, Some("err_type".into()));
    }

    #[test]
    fn zap_large_step_count() {
        let z: Zap = serde_json::from_value(json!({
            "id": "z1",
            "steps": 999
        }))
        .unwrap();
        assert_eq!(z.steps, Some(999));
    }

    #[test]
    fn execution_result_action_id_only() {
        let r: ExecutionResult = serde_json::from_value(json!({
            "action_id": "act_123"
        }))
        .unwrap();
        assert_eq!(r.action_id, Some("act_123".into()));
        assert!(r.status.is_none());
    }

    #[test]
    fn zap_run_with_data() {
        let r: ZapRun = serde_json::from_value(json!({
            "id": "r1",
            "data": {"count": 42}
        }))
        .unwrap();
        assert_eq!(r.data.unwrap()["count"], 42);
    }
}
