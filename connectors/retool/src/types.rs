//! `Retool` API types.

use serde::{Deserialize, Serialize};

/// A `Retool` workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Workflows list response from `Retool`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowsListResponse {
    pub data: Vec<serde_json::Value>,
    #[serde(rename = "totalCount")]
    pub total_count: Option<i64>,
    #[serde(rename = "nextToken")]
    pub next_token: Option<String>,
    #[serde(rename = "hasMore")]
    pub has_more: Option<bool>,
}

/// Workflow run response from `Retool`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRunResponse {
    pub data: Option<serde_json::Value>,
    #[serde(rename = "workflowId")]
    pub workflow_id: Option<String>,
    pub success: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// `Retool` API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub error: Option<String>,
    pub status: Option<i64>,
}

impl ApiErrorResponse {
    /// Extract the most useful error message from the response.
    pub fn detail(&self) -> Option<String> {
        self.message
            .clone()
            .or_else(|| self.error.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workflow_roundtrip() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "wf_abc123",
            "name": "Daily Report",
            "folderId": "folder1",
            "isEnabled": true,
            "createdAt": "2025-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(w.id, "wf_abc123");
        assert_eq!(w.name, Some("Daily Report".into()));
        assert_eq!(w.folder_id, Some("folder1".into()));
        assert_eq!(w.is_enabled, Some(true));
        let re = serde_json::to_value(&w).unwrap();
        assert_eq!(re["id"], "wf_abc123");
        assert_eq!(re["createdAt"], "2025-01-01T00:00:00Z");
    }

    #[test]
    fn workflow_minimal() {
        let w: Workflow = serde_json::from_value(json!({"id": "wf1"})).unwrap();
        assert_eq!(w.id, "wf1");
        assert!(w.name.is_none());
        assert!(w.folder_id.is_none());
        assert!(w.is_enabled.is_none());
    }

    #[test]
    fn workflow_serialize_deserialize() {
        let original = Workflow {
            id: "wf_test".into(),
            name: Some("Test Workflow".into()),
            folder_id: None,
            is_enabled: Some(false),
            extra: json!({}),
        };
        let json_val = serde_json::to_value(&original).unwrap();
        assert_eq!(json_val["id"], "wf_test");
        assert_eq!(json_val["name"], "Test Workflow");
        assert_eq!(json_val["isEnabled"], false);
        let back: Workflow = serde_json::from_value(json_val).unwrap();
        assert_eq!(back.id, "wf_test");
        assert_eq!(back.is_enabled, Some(false));
    }

    #[test]
    fn workflows_list_response_roundtrip() {
        let r: WorkflowsListResponse = serde_json::from_value(json!({
            "data": [
                {"id": "wf1", "name": "Workflow A"},
                {"id": "wf2", "name": "Workflow B"}
            ],
            "totalCount": 2,
            "nextToken": null,
            "hasMore": false
        }))
        .unwrap();
        assert_eq!(r.data.len(), 2);
        assert_eq!(r.total_count, Some(2));
        assert!(!r.has_more.unwrap());
    }

    #[test]
    fn workflows_list_response_empty() {
        let r: WorkflowsListResponse = serde_json::from_value(json!({
            "data": []
        }))
        .unwrap();
        assert!(r.data.is_empty());
        assert!(r.total_count.is_none());
        assert!(r.has_more.is_none());
    }

    #[test]
    fn workflows_list_response_with_pagination() {
        let r: WorkflowsListResponse = serde_json::from_value(json!({
            "data": [{"id": "wf1"}],
            "totalCount": 50,
            "nextToken": "token_abc",
            "hasMore": true
        }))
        .unwrap();
        assert_eq!(r.data.len(), 1);
        assert_eq!(r.total_count, Some(50));
        assert_eq!(r.next_token, Some("token_abc".into()));
        assert!(r.has_more.unwrap());
    }

    #[test]
    fn workflow_run_response_roundtrip() {
        let r: WorkflowRunResponse = serde_json::from_value(json!({
            "data": {"result": "ok", "rows": 42},
            "workflowId": "wf_abc123",
            "success": true
        }))
        .unwrap();
        assert!(r.data.is_some());
        assert_eq!(r.workflow_id, Some("wf_abc123".into()));
        assert_eq!(r.success, Some(true));
    }

    #[test]
    fn workflow_run_response_minimal() {
        let r: WorkflowRunResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.data.is_none());
        assert!(r.workflow_id.is_none());
        assert!(r.success.is_none());
    }

    #[test]
    fn workflow_run_response_with_null_data() {
        let r: WorkflowRunResponse = serde_json::from_value(json!({
            "data": null,
            "success": true
        }))
        .unwrap();
        assert!(r.data.is_none());
        assert_eq!(r.success, Some(true));
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Workflow not found",
            "status": 404
        }))
        .unwrap();
        assert_eq!(e.message, Some("Workflow not found".into()));
        assert_eq!(e.status, Some(404));
        assert_eq!(e.detail(), Some("Workflow not found".into()));
    }

    #[test]
    fn api_error_response_with_error_field() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Unauthorized access"
        }))
        .unwrap();
        assert!(e.message.is_none());
        assert_eq!(e.error, Some("Unauthorized access".into()));
        assert_eq!(e.detail(), Some("Unauthorized access".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.error.is_none());
        assert!(e.status.is_none());
        assert!(e.detail().is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": "Invalid token"})).unwrap();
        assert_eq!(e.message, Some("Invalid token".into()));
        assert!(e.status.is_none());
    }

    #[test]
    fn api_error_response_prefers_message_over_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Primary message",
            "error": "Fallback error"
        }))
        .unwrap();
        assert_eq!(e.detail(), Some("Primary message".into()));
    }

    #[test]
    fn workflows_list_many_items() {
        let items: Vec<serde_json::Value> = (0..100)
            .map(|i| json!({"id": format!("wf_{i}"), "name": format!("Workflow {i}")}))
            .collect();
        let r: WorkflowsListResponse = serde_json::from_value(json!({
            "data": items,
            "totalCount": 100
        }))
        .unwrap();
        assert_eq!(r.data.len(), 100);
        assert_eq!(r.total_count, Some(100));
    }

    #[test]
    fn workflow_with_extra_fields() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "wf_extra",
            "name": "Extra",
            "custom_field": "custom_value",
            "tags": ["a", "b"]
        }))
        .unwrap();
        assert_eq!(w.id, "wf_extra");
        let re = serde_json::to_value(&w).unwrap();
        assert_eq!(re["custom_field"], "custom_value");
        assert_eq!(re["tags"], json!(["a", "b"]));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn workflow_clone() {
        let w = Workflow {
            id: "wf1".into(),
            name: Some("Test".into()),
            folder_id: None,
            is_enabled: Some(true),
            extra: json!({}),
        };
        let c = w.clone();
        assert_eq!(c.id, "wf1");
        assert_eq!(c.name, Some("Test".into()));
    }

    #[test]
    fn workflow_debug() {
        let w = Workflow {
            id: "wf1".into(),
            name: None,
            folder_id: None,
            is_enabled: None,
            extra: json!({}),
        };
        let dbg = format!("{w:?}");
        assert!(dbg.contains("Workflow"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn workflows_list_response_clone() {
        let r = WorkflowsListResponse {
            data: vec![json!({"id": "wf1"})],
            total_count: Some(1),
            next_token: None,
            has_more: Some(false),
        };
        let c = r.clone();
        assert_eq!(c.data.len(), 1);
        assert_eq!(c.total_count, Some(1));
    }

    #[test]
    fn workflows_list_response_debug() {
        let r = WorkflowsListResponse {
            data: vec![],
            total_count: None,
            next_token: None,
            has_more: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("WorkflowsListResponse"));
    }

    #[test]
    fn workflows_list_response_serialize() {
        let r = WorkflowsListResponse {
            data: vec![json!({"id": "wf1"})],
            total_count: Some(1),
            next_token: Some("tok_next".into()),
            has_more: Some(true),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["data"].as_array().unwrap().len(), 1);
        assert_eq!(v["totalCount"], 1);
        assert_eq!(v["nextToken"], "tok_next");
        assert_eq!(v["hasMore"], true);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn workflow_run_response_clone() {
        let r = WorkflowRunResponse {
            data: Some(json!({"result": "ok"})),
            workflow_id: Some("wf1".into()),
            success: Some(true),
            extra: json!({}),
        };
        let c = r.clone();
        assert!(c.data.is_some());
        assert_eq!(c.success, Some(true));
    }

    #[test]
    fn workflow_run_response_debug() {
        let r = WorkflowRunResponse {
            data: None,
            workflow_id: None,
            success: None,
            extra: json!({}),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("WorkflowRunResponse"));
    }

    #[test]
    fn workflow_run_response_serialize() {
        let r = WorkflowRunResponse {
            data: Some(json!(42)),
            workflow_id: Some("wf_abc".into()),
            success: Some(true),
            extra: json!({}),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["data"], 42);
        assert_eq!(v["workflowId"], "wf_abc");
        assert_eq!(v["success"], true);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("err".into()),
            error: Some("ERR".into()),
            status: Some(500),
        };
        let c = e.clone();
        assert_eq!(c.message, Some("err".into()));
        assert_eq!(c.error, Some("ERR".into()));
        assert_eq!(c.status, Some(500));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            message: None,
            error: None,
            status: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_detail_none_when_all_none() {
        let e = ApiErrorResponse {
            message: None,
            error: None,
            status: None,
        };
        assert!(e.detail().is_none());
    }

    #[test]
    fn api_error_detail_prefers_message() {
        let e = ApiErrorResponse {
            message: Some("primary".into()),
            error: Some("fallback".into()),
            status: None,
        };
        assert_eq!(e.detail(), Some("primary".into()));
    }

    #[test]
    fn api_error_detail_falls_back_to_error() {
        let e = ApiErrorResponse {
            message: None,
            error: Some("fallback error".into()),
            status: None,
        };
        assert_eq!(e.detail(), Some("fallback error".into()));
    }

    #[test]
    fn workflow_is_enabled_false() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "wf1",
            "isEnabled": false,
        }))
        .unwrap();
        assert_eq!(w.is_enabled, Some(false));
    }

    #[test]
    fn workflow_run_response_with_extra_fields() {
        let r: WorkflowRunResponse = serde_json::from_value(json!({
            "data": {"count": 5},
            "success": true,
            "executionTime": 1234
        }))
        .unwrap();
        assert!(r.success.unwrap());
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["executionTime"], 1234);
    }
}
