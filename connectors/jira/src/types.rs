//! Jira REST API types.

use serde::{Deserialize, Serialize};

// ── Issue ───────────────────────────────────────────────────────

/// Jira issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraIssue {
    pub id: String,
    pub key: String,
    #[serde(rename = "self")]
    pub self_url: Option<String>,
    pub fields: Option<serde_json::Value>,
    pub changelog: Option<serde_json::Value>,
}

/// Response from creating an issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIssueResponse {
    pub id: String,
    pub key: String,
    #[serde(rename = "self")]
    pub self_url: String,
}

// ── Project ─────────────────────────────────────────────────────

/// Jira project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraProject {
    pub id: Option<String>,
    pub key: String,
    pub name: Option<String>,
}

// ── Transition ──────────────────────────────────────────────────

/// Jira workflow transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraTransition {
    pub id: String,
    pub name: String,
    pub to: Option<TransitionStatus>,
}

/// Status that a transition leads to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionStatus {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "statusCategory")]
    pub status_category: Option<serde_json::Value>,
}

/// Response from listing transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionsResponse {
    pub transitions: Vec<JiraTransition>,
}

// ── Comment ─────────────────────────────────────────────────────

/// Jira comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraComment {
    pub id: Option<String>,
    pub body: Option<serde_json::Value>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub author: Option<serde_json::Value>,
    pub visibility: Option<serde_json::Value>,
}

/// Paginated comment list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentListResponse {
    pub comments: Vec<JiraComment>,
    pub total: u64,
    pub start_at: Option<u64>,
    pub max_results: Option<u64>,
}

// ── Sprint ──────────────────────────────────────────────────────

/// Jira sprint (from Agile API).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraSprint {
    pub id: u64,
    pub name: String,
    pub state: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub complete_date: Option<String>,
    pub origin_board_id: Option<u64>,
    pub goal: Option<String>,
}

/// Paginated sprint list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SprintListResponse {
    pub values: Vec<JiraSprint>,
    pub is_last: Option<bool>,
    pub max_results: Option<u64>,
    pub start_at: Option<u64>,
}

// ── Search ──────────────────────────────────────────────────────

/// JQL search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub issues: Vec<JiraIssue>,
    pub total: u64,
    pub max_results: u64,
    pub start_at: u64,
}

// ── Attachment ──────────────────────────────────────────────────

/// Jira attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraAttachment {
    pub id: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    pub mime_type: Option<String>,
    pub content: Option<String>,
    pub created: Option<String>,
    pub author: Option<serde_json::Value>,
}

// ── API Error ───────────────────────────────────────────────────

/// Jira REST API error response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error_messages: Option<Vec<String>>,
    pub errors: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jira_issue_serde() {
        let issue = JiraIssue {
            id: "10001".to_string(),
            key: "PROJ-1".to_string(),
            self_url: Some("https://jira.example.com/rest/api/2/issue/10001".to_string()),
            fields: Some(json!({"summary": "Bug fix", "status": {"name": "Open"}})),
            changelog: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("\"self\":"));
        let back: JiraIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "PROJ-1");
    }

    #[test]
    fn create_issue_response_serde() {
        let json = r#"{"id":"10002","key":"PROJ-2","self":"https://jira.example.com/rest/api/2/issue/10002"}"#;
        let resp: CreateIssueResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.key, "PROJ-2");
    }

    #[test]
    fn jira_project_serde() {
        let project = JiraProject {
            id: Some("100".to_string()),
            key: "PROJ".to_string(),
            name: Some("My Project".to_string()),
        };
        let json = serde_json::to_string(&project).unwrap();
        let back: JiraProject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "PROJ");
    }

    #[test]
    fn jira_transition_serde() {
        let json = json!({
            "id": "21",
            "name": "Done",
            "to": {"id": "3", "name": "Done", "statusCategory": {"name": "Done"}}
        });
        let tr: JiraTransition = serde_json::from_value(json).unwrap();
        assert_eq!(tr.name, "Done");
        assert!(tr.to.is_some());
    }

    #[test]
    fn transitions_response_serde() {
        let json = json!({"transitions": [{"id": "1", "name": "Start", "to": null}]});
        let resp: TransitionsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.transitions.len(), 1);
    }

    #[test]
    fn comment_list_response_camel_case() {
        let json = json!({
            "comments": [{"id": "1", "body": "test"}],
            "total": 1,
            "startAt": 0,
            "maxResults": 50
        });
        let resp: CommentListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total, 1);
        assert_eq!(resp.start_at, Some(0));
    }

    #[test]
    fn jira_sprint_camel_case() {
        let json = json!({
            "id": 1,
            "name": "Sprint 1",
            "state": "active",
            "startDate": "2026-03-01",
            "endDate": "2026-03-14",
            "originBoardId": 42
        });
        let sprint: JiraSprint = serde_json::from_value(json).unwrap();
        assert_eq!(sprint.name, "Sprint 1");
        assert_eq!(sprint.origin_board_id, Some(42));
    }

    #[test]
    fn sprint_list_response() {
        let json = json!({"values": [], "isLast": true, "maxResults": 50, "startAt": 0});
        let resp: SprintListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.values.is_empty());
        assert_eq!(resp.is_last, Some(true));
    }

    #[test]
    fn search_result_serde() {
        let json = json!({
            "issues": [{"id": "1", "key": "P-1", "self": null, "fields": null, "changelog": null}],
            "total": 1,
            "maxResults": 50,
            "startAt": 0
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.issues.len(), 1);
    }

    #[test]
    fn jira_attachment_serde() {
        let json = json!({
            "id": "a1",
            "filename": "doc.pdf",
            "size": 2048,
            "mimeType": "application/pdf"
        });
        let att: JiraAttachment = serde_json::from_value(json).unwrap();
        assert_eq!(att.filename.as_deref(), Some("doc.pdf"));
        assert_eq!(att.size, Some(2048));
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({"errorMessages": ["Issue not found"], "errors": {}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error_messages.as_ref().unwrap().len(), 1);
    }
}
