//! n8n API types.

use serde::{Deserialize, Serialize};

/// An n8n workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<Tag>>,
}

/// An n8n workflow tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// An n8n execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub id: String,
    #[serde(default)]
    pub finished: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default, rename = "startedAt")]
    pub started_at: Option<String>,
    #[serde(default, rename = "stoppedAt")]
    pub stopped_at: Option<String>,
    #[serde(default, rename = "workflowId")]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, rename = "retryOf")]
    pub retry_of: Option<String>,
    #[serde(default, rename = "retrySuccessId")]
    pub retry_success_id: Option<String>,
}

/// n8n paginated list response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    #[serde(default, rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// n8n API error response body.
///
/// n8n returns `{"message": "error description"}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from n8n.
    pub message: Option<String>,
    /// Optional error code.
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workflow_full_roundtrip() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1001",
            "name": "Daily Report",
            "active": true,
            "createdAt": "2025-01-15T10:00:00.000Z",
            "updatedAt": "2025-02-20T14:30:00.000Z",
            "tags": [
                {"id": "t1", "name": "production"},
                {"id": "t2", "name": "reporting"},
            ]
        }))
        .unwrap();
        assert_eq!(w.id, "1001");
        assert_eq!(w.name, Some("Daily Report".into()));
        assert_eq!(w.active, Some(true));
        assert_eq!(w.created_at, Some("2025-01-15T10:00:00.000Z".into()));
        assert_eq!(w.updated_at, Some("2025-02-20T14:30:00.000Z".into()));
        let tags = w.tags.as_ref().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, Some("production".into()));
        let re = serde_json::to_value(&w).unwrap();
        assert_eq!(re["name"], "Daily Report");
    }

    #[test]
    fn workflow_minimal() {
        let w: Workflow = serde_json::from_value(json!({"id": "42"})).unwrap();
        assert_eq!(w.id, "42");
        assert!(w.name.is_none());
        assert!(w.active.is_none());
        assert!(w.created_at.is_none());
        assert!(w.updated_at.is_none());
        assert!(w.tags.is_none());
    }

    #[test]
    fn workflow_inactive() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "99",
            "name": "Disabled Workflow",
            "active": false,
        }))
        .unwrap();
        assert_eq!(w.active, Some(false));
    }

    #[test]
    fn workflow_extra_fields_ignored() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1",
            "name": "Test",
            "unknown_field": "should be ignored",
            "nodes": [{"type": "n8n-nodes-base.start"}],
        }))
        .unwrap();
        assert_eq!(w.id, "1");
        assert_eq!(w.name, Some("Test".into()));
    }

    #[test]
    fn workflow_serialize_roundtrip() {
        let w = Workflow {
            id: "w1".into(),
            name: Some("My Workflow".into()),
            active: Some(true),
            created_at: None,
            updated_at: None,
            tags: Some(vec![Tag { id: Some("t1".into()), name: Some("dev".into()) }]),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["id"], "w1");
        assert_eq!(v["name"], "My Workflow");
        assert_eq!(v["active"], true);
        assert_eq!(v["tags"][0]["name"], "dev");
    }

    #[test]
    fn tag_roundtrip() {
        let t: Tag = serde_json::from_value(json!({"id": "t1", "name": "production"})).unwrap();
        assert_eq!(t.id, Some("t1".into()));
        assert_eq!(t.name, Some("production".into()));
    }

    #[test]
    fn tag_minimal() {
        let t: Tag = serde_json::from_value(json!({})).unwrap();
        assert!(t.id.is_none());
        assert!(t.name.is_none());
    }

    #[test]
    fn execution_full_roundtrip() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50001",
            "finished": true,
            "mode": "trigger",
            "startedAt": "2025-03-01T08:00:00.000Z",
            "stoppedAt": "2025-03-01T08:00:05.000Z",
            "workflowId": "1001",
            "status": "success",
            "retryOf": null,
            "retrySuccessId": null,
        }))
        .unwrap();
        assert_eq!(e.id, "50001");
        assert_eq!(e.finished, Some(true));
        assert_eq!(e.mode, Some("trigger".into()));
        assert_eq!(e.started_at, Some("2025-03-01T08:00:00.000Z".into()));
        assert_eq!(e.stopped_at, Some("2025-03-01T08:00:05.000Z".into()));
        assert_eq!(e.workflow_id, Some("1001".into()));
        assert_eq!(e.status, Some("success".into()));
        assert!(e.retry_of.is_none());
        assert!(e.retry_success_id.is_none());
    }

    #[test]
    fn execution_minimal() {
        let e: Execution = serde_json::from_value(json!({"id": "1"})).unwrap();
        assert_eq!(e.id, "1");
        assert!(e.finished.is_none());
        assert!(e.mode.is_none());
        assert!(e.started_at.is_none());
        assert!(e.workflow_id.is_none());
        assert!(e.status.is_none());
    }

    #[test]
    fn execution_failed() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50002",
            "finished": true,
            "mode": "manual",
            "status": "error",
            "workflowId": "1002",
        }))
        .unwrap();
        assert_eq!(e.status, Some("error".into()));
        assert_eq!(e.finished, Some(true));
    }

    #[test]
    fn execution_running() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50003",
            "finished": false,
            "mode": "webhook",
            "status": "running",
        }))
        .unwrap();
        assert_eq!(e.finished, Some(false));
        assert_eq!(e.status, Some("running".into()));
    }

    #[test]
    fn execution_with_retry() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50004",
            "finished": true,
            "retryOf": "50003",
            "retrySuccessId": "50004",
            "status": "success",
        }))
        .unwrap();
        assert_eq!(e.retry_of, Some("50003".into()));
        assert_eq!(e.retry_success_id, Some("50004".into()));
    }

    #[test]
    fn execution_extra_fields_ignored() {
        let e: Execution = serde_json::from_value(json!({
            "id": "1",
            "finished": true,
            "data": {"resultData": {}},
            "unknown": 42,
        }))
        .unwrap();
        assert_eq!(e.id, "1");
        assert_eq!(e.finished, Some(true));
    }

    #[test]
    fn execution_serialize_roundtrip() {
        let e = Execution {
            id: "e1".into(),
            finished: Some(true),
            mode: Some("trigger".into()),
            started_at: Some("2025-01-01T00:00:00Z".into()),
            stopped_at: Some("2025-01-01T00:00:01Z".into()),
            workflow_id: Some("w1".into()),
            status: Some("success".into()),
            retry_of: None,
            retry_success_id: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["id"], "e1");
        assert_eq!(v["finished"], true);
        assert_eq!(v["mode"], "trigger");
        assert_eq!(v["workflowId"], "w1");
    }

    #[test]
    fn list_response_workflows() {
        let lr: ListResponse<Workflow> = serde_json::from_value(json!({
            "data": [
                {"id": "1", "name": "WF1"},
                {"id": "2", "name": "WF2"},
            ],
            "nextCursor": "abc123",
        }))
        .unwrap();
        assert_eq!(lr.data.len(), 2);
        assert_eq!(lr.next_cursor, Some("abc123".into()));
    }

    #[test]
    fn list_response_empty() {
        let lr: ListResponse<Workflow> = serde_json::from_value(json!({
            "data": [],
        }))
        .unwrap();
        assert!(lr.data.is_empty());
        assert!(lr.next_cursor.is_none());
    }

    #[test]
    fn list_response_executions() {
        let lr: ListResponse<Execution> = serde_json::from_value(json!({
            "data": [
                {"id": "100", "finished": true},
            ],
        }))
        .unwrap();
        assert_eq!(lr.data.len(), 1);
        assert_eq!(lr.data[0].id, "100");
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Workflow not found",
            "code": "NOT_FOUND",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Workflow not found".into()));
        assert_eq!(e.code, Some("NOT_FOUND".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.code.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Rate limit exceeded",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Rate limit exceeded".into()));
        assert!(e.code.is_none());
    }

    #[test]
    fn workflow_empty_tags() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1",
            "tags": [],
        }))
        .unwrap();
        assert!(w.tags.unwrap().is_empty());
    }

    #[test]
    fn tag_extra_fields_ignored() {
        let t: Tag = serde_json::from_value(json!({
            "id": "t1",
            "name": "test",
            "createdAt": "2025-01-01",
        }))
        .unwrap();
        assert_eq!(t.id, Some("t1".into()));
    }
}
