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

// ── Worklog ─────────────────────────────────────────────────────

/// Jira worklog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraWorklog {
    pub id: Option<String>,
    #[serde(rename = "self")]
    pub self_url: Option<String>,
    pub author: Option<serde_json::Value>,
    pub update_author: Option<serde_json::Value>,
    pub comment: Option<serde_json::Value>,
    pub started: Option<String>,
    pub time_spent: Option<String>,
    pub time_spent_seconds: Option<u64>,
    pub issue_id: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub visibility: Option<serde_json::Value>,
}

/// Paginated worklog list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorklogListResponse {
    pub worklogs: Vec<JiraWorklog>,
    pub total: u64,
    pub start_at: Option<u64>,
    pub max_results: Option<u64>,
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

    // ════════════════════════════════════════════════════════════════
    // JiraIssue
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_issue_serde_roundtrip() {
        let issue = JiraIssue {
            id: "10001".to_string(),
            key: "PROJ-1".to_string(),
            self_url: Some("https://jira.example.com/rest/api/2/issue/10001".to_string()),
            fields: Some(json!({"summary": "Bug fix", "status": {"name": "Open"}})),
            changelog: None,
        };
        let serialized = serde_json::to_string(&issue).unwrap();
        assert!(serialized.contains("\"self\":"));
        let back: JiraIssue = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.id, "10001");
        assert_eq!(back.key, "PROJ-1");
        assert_eq!(back.self_url, issue.self_url);
        assert!(back.changelog.is_none());
    }

    #[test]
    fn jira_issue_all_fields_null() {
        let json = json!({
            "id": "1",
            "key": "K-1",
            "self": null,
            "fields": null,
            "changelog": null
        });
        let issue: JiraIssue = serde_json::from_value(json).unwrap();
        assert!(issue.self_url.is_none());
        assert!(issue.fields.is_none());
        assert!(issue.changelog.is_none());
    }

    #[test]
    fn jira_issue_missing_optional_fields() {
        // self, fields, changelog are all Optional — should deserialize without them
        let json = json!({"id": "2", "key": "X-2"});
        let issue: JiraIssue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.id, "2");
        assert_eq!(issue.key, "X-2");
        assert!(issue.self_url.is_none());
        assert!(issue.fields.is_none());
        assert!(issue.changelog.is_none());
    }

    #[test]
    fn jira_issue_with_changelog() {
        let json = json!({
            "id": "3",
            "key": "Z-3",
            "fields": {"summary": "test"},
            "changelog": {"histories": []}
        });
        let issue: JiraIssue = serde_json::from_value(json).unwrap();
        assert!(issue.changelog.is_some());
        assert!(issue.changelog.unwrap().get("histories").is_some());
    }

    #[test]
    fn jira_issue_clone() {
        let issue = JiraIssue {
            id: "10".into(),
            key: "CL-10".into(),
            self_url: Some("url".into()),
            fields: Some(json!({"a": 1})),
            changelog: None,
        };
        let cloned = issue.clone();
        assert_eq!(cloned.id, issue.id);
        assert_eq!(cloned.key, issue.key);
        assert_eq!(cloned.self_url, issue.self_url);
        assert_eq!(cloned.fields, issue.fields);
    }

    #[test]
    fn jira_issue_debug() {
        let issue = JiraIssue {
            id: "1".into(),
            key: "D-1".into(),
            self_url: None,
            fields: None,
            changelog: None,
        };
        let dbg = format!("{issue:?}");
        assert!(dbg.contains("JiraIssue"), "got: {dbg}");
        assert!(dbg.contains("D-1"), "got: {dbg}");
    }

    #[test]
    fn jira_issue_self_url_rename() {
        // Verify the serde rename of self_url to "self" in JSON
        let issue = JiraIssue {
            id: "1".into(),
            key: "R-1".into(),
            self_url: Some("https://example.com".into()),
            fields: None,
            changelog: None,
        };
        let val = serde_json::to_value(&issue).unwrap();
        assert!(val.get("self").is_some());
        assert!(val.get("self_url").is_none());
    }

    #[test]
    fn jira_issue_serializes_null_optionals() {
        let issue = JiraIssue {
            id: "1".into(),
            key: "N-1".into(),
            self_url: None,
            fields: None,
            changelog: None,
        };
        let val = serde_json::to_value(&issue).unwrap();
        // Without skip_serializing_if, None fields should be serialized as null
        assert!(val.get("self").is_some());
        assert!(val["self"].is_null());
        assert!(val["fields"].is_null());
        assert!(val["changelog"].is_null());
    }

    // ════════════════════════════════════════════════════════════════
    // CreateIssueResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn create_issue_response_serde() {
        let json = r#"{"id":"10002","key":"PROJ-2","self":"https://jira.example.com/rest/api/2/issue/10002"}"#;
        let resp: CreateIssueResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "10002");
        assert_eq!(resp.key, "PROJ-2");
        assert!(resp.self_url.contains("10002"));
    }

    #[test]
    fn create_issue_response_roundtrip() {
        let resp = CreateIssueResponse {
            id: "999".into(),
            key: "RT-999".into(),
            self_url: "https://example.com/rest/api/3/issue/999".into(),
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let back: CreateIssueResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.id, resp.id);
        assert_eq!(back.key, resp.key);
        assert_eq!(back.self_url, resp.self_url);
    }

    #[test]
    fn create_issue_response_clone_debug() {
        let resp = CreateIssueResponse {
            id: "1".into(),
            key: "CD-1".into(),
            self_url: "u".into(),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.key, "CD-1");
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CreateIssueResponse"), "got: {dbg}");
    }

    #[test]
    fn create_issue_response_self_rename() {
        let resp = CreateIssueResponse {
            id: "1".into(),
            key: "SR-1".into(),
            self_url: "https://test.com".into(),
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert!(val.get("self").is_some());
        assert!(val.get("self_url").is_none());
    }

    // ════════════════════════════════════════════════════════════════
    // JiraProject
    // ════════════════════════════════════════════════════════════════

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
        assert_eq!(back.name.as_deref(), Some("My Project"));
    }

    #[test]
    fn jira_project_missing_optionals() {
        let json = json!({"key": "MIN"});
        let project: JiraProject = serde_json::from_value(json).unwrap();
        assert_eq!(project.key, "MIN");
        assert!(project.id.is_none());
        assert!(project.name.is_none());
    }

    #[test]
    fn jira_project_null_optionals() {
        let json = json!({"key": "NUL", "id": null, "name": null});
        let project: JiraProject = serde_json::from_value(json).unwrap();
        assert!(project.id.is_none());
        assert!(project.name.is_none());
    }

    #[test]
    fn jira_project_clone_debug() {
        let project = JiraProject {
            id: None,
            key: "P".into(),
            name: None,
        };
        let cloned = project.clone();
        assert_eq!(cloned.key, project.key);
        let dbg = format!("{project:?}");
        assert!(dbg.contains("JiraProject"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // JiraTransition / TransitionStatus
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_transition_serde() {
        let json = json!({
            "id": "21",
            "name": "Done",
            "to": {"id": "3", "name": "Done", "statusCategory": {"name": "Done"}}
        });
        let tr: JiraTransition = serde_json::from_value(json).unwrap();
        assert_eq!(tr.id, "21");
        assert_eq!(tr.name, "Done");
        assert!(tr.to.is_some());
        let to = tr.to.unwrap();
        assert_eq!(to.id.as_deref(), Some("3"));
        assert_eq!(to.name.as_deref(), Some("Done"));
        assert!(to.status_category.is_some());
    }

    #[test]
    fn jira_transition_null_to() {
        let json = json!({"id": "5", "name": "Start", "to": null});
        let tr: JiraTransition = serde_json::from_value(json).unwrap();
        assert!(tr.to.is_none());
    }

    #[test]
    fn jira_transition_missing_to() {
        let json = json!({"id": "6", "name": "Back"});
        let tr: JiraTransition = serde_json::from_value(json).unwrap();
        assert!(tr.to.is_none());
    }

    #[test]
    fn transition_status_all_optional_fields() {
        let json = json!({});
        let status: TransitionStatus = serde_json::from_value(json).unwrap();
        assert!(status.id.is_none());
        assert!(status.name.is_none());
        assert!(status.status_category.is_none());
    }

    #[test]
    fn transition_status_camel_case_status_category() {
        let json = json!({"statusCategory": {"key": "done", "name": "Done"}});
        let status: TransitionStatus = serde_json::from_value(json).unwrap();
        assert!(status.status_category.is_some());
        // Verify roundtrip serializes back to camelCase
        let val = serde_json::to_value(&status).unwrap();
        assert!(val.get("statusCategory").is_some());
        assert!(val.get("status_category").is_none());
    }

    #[test]
    fn transition_status_clone_debug() {
        let ts = TransitionStatus {
            id: Some("1".into()),
            name: Some("Open".into()),
            status_category: None,
        };
        let cloned = ts.clone();
        assert_eq!(cloned.id, ts.id);
        let dbg = format!("{ts:?}");
        assert!(dbg.contains("TransitionStatus"), "got: {dbg}");
    }

    #[test]
    fn jira_transition_roundtrip() {
        let tr = JiraTransition {
            id: "11".into(),
            name: "In Progress".into(),
            to: Some(TransitionStatus {
                id: Some("2".into()),
                name: Some("In Progress".into()),
                status_category: Some(json!({"name": "In Progress"})),
            }),
        };
        let serialized = serde_json::to_value(&tr).unwrap();
        let back: JiraTransition = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.id, "11");
        assert_eq!(back.name, "In Progress");
        assert!(back.to.is_some());
    }

    // ════════════════════════════════════════════════════════════════
    // TransitionsResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn transitions_response_serde() {
        let json = json!({"transitions": [{"id": "1", "name": "Start", "to": null}]});
        let resp: TransitionsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.transitions.len(), 1);
        assert_eq!(resp.transitions[0].name, "Start");
    }

    #[test]
    fn transitions_response_empty() {
        let json = json!({"transitions": []});
        let resp: TransitionsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.transitions.is_empty());
    }

    #[test]
    fn transitions_response_multiple() {
        let json = json!({
            "transitions": [
                {"id": "1", "name": "To Do"},
                {"id": "2", "name": "In Progress"},
                {"id": "3", "name": "Done"}
            ]
        });
        let resp: TransitionsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.transitions.len(), 3);
    }

    #[test]
    fn transitions_response_clone_debug() {
        let resp = TransitionsResponse {
            transitions: vec![JiraTransition {
                id: "1".into(),
                name: "T".into(),
                to: None,
            }],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.transitions.len(), 1);
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("TransitionsResponse"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // JiraComment
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_comment_all_fields() {
        let json = json!({
            "id": "100",
            "body": {"type": "doc", "content": [{"type": "paragraph"}]},
            "created": "2026-01-01T00:00:00.000+0000",
            "updated": "2026-01-02T00:00:00.000+0000",
            "author": {"displayName": "Test User"},
            "visibility": {"type": "role", "value": "Administrators"}
        });
        let comment: JiraComment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.id.as_deref(), Some("100"));
        assert!(comment.body.is_some());
        assert!(comment.created.is_some());
        assert!(comment.updated.is_some());
        assert!(comment.author.is_some());
        assert!(comment.visibility.is_some());
    }

    #[test]
    fn jira_comment_all_optional_none() {
        let json = json!({});
        let comment: JiraComment = serde_json::from_value(json).unwrap();
        assert!(comment.id.is_none());
        assert!(comment.body.is_none());
        assert!(comment.created.is_none());
        assert!(comment.updated.is_none());
        assert!(comment.author.is_none());
        assert!(comment.visibility.is_none());
    }

    #[test]
    fn jira_comment_roundtrip() {
        let comment = JiraComment {
            id: Some("50".into()),
            body: Some(json!("plain text")),
            created: Some("2026-03-01".into()),
            updated: None,
            author: None,
            visibility: None,
        };
        let val = serde_json::to_value(&comment).unwrap();
        let back: JiraComment = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, comment.id);
        assert_eq!(back.body, comment.body);
        assert_eq!(back.created, comment.created);
    }

    #[test]
    fn jira_comment_clone_debug() {
        let comment = JiraComment {
            id: Some("1".into()),
            body: None,
            created: None,
            updated: None,
            author: None,
            visibility: None,
        };
        let cloned = comment.clone();
        assert_eq!(cloned.id, comment.id);
        let dbg = format!("{comment:?}");
        assert!(dbg.contains("JiraComment"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // CommentListResponse
    // ════════════════════════════════════════════════════════════════

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
        assert_eq!(resp.max_results, Some(50));
    }

    #[test]
    fn comment_list_response_missing_pagination() {
        let json = json!({
            "comments": [],
            "total": 0
        });
        let resp: CommentListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total, 0);
        assert!(resp.start_at.is_none());
        assert!(resp.max_results.is_none());
    }

    #[test]
    fn comment_list_response_serializes_camel_case() {
        let resp = CommentListResponse {
            comments: vec![],
            total: 5,
            start_at: Some(10),
            max_results: Some(25),
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert!(val.get("startAt").is_some());
        assert!(val.get("maxResults").is_some());
        // snake_case should NOT appear
        assert!(val.get("start_at").is_none());
        assert!(val.get("max_results").is_none());
    }

    #[test]
    fn comment_list_response_clone_debug() {
        let resp = CommentListResponse {
            comments: vec![],
            total: 0,
            start_at: None,
            max_results: None,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.total, 0);
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CommentListResponse"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // JiraSprint
    // ════════════════════════════════════════════════════════════════

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
        assert_eq!(sprint.id, 1);
        assert_eq!(sprint.name, "Sprint 1");
        assert_eq!(sprint.state.as_deref(), Some("active"));
        assert_eq!(sprint.start_date.as_deref(), Some("2026-03-01"));
        assert_eq!(sprint.end_date.as_deref(), Some("2026-03-14"));
        assert_eq!(sprint.origin_board_id, Some(42));
    }

    #[test]
    fn jira_sprint_minimal() {
        let json = json!({"id": 99, "name": "Minimal Sprint"});
        let sprint: JiraSprint = serde_json::from_value(json).unwrap();
        assert_eq!(sprint.id, 99);
        assert_eq!(sprint.name, "Minimal Sprint");
        assert!(sprint.state.is_none());
        assert!(sprint.start_date.is_none());
        assert!(sprint.end_date.is_none());
        assert!(sprint.complete_date.is_none());
        assert!(sprint.origin_board_id.is_none());
        assert!(sprint.goal.is_none());
    }

    #[test]
    fn jira_sprint_all_fields() {
        let json = json!({
            "id": 10,
            "name": "Full Sprint",
            "state": "closed",
            "startDate": "2026-01-01",
            "endDate": "2026-01-14",
            "completeDate": "2026-01-13",
            "originBoardId": 5,
            "goal": "Deliver feature X"
        });
        let sprint: JiraSprint = serde_json::from_value(json).unwrap();
        assert_eq!(sprint.complete_date.as_deref(), Some("2026-01-13"));
        assert_eq!(sprint.goal.as_deref(), Some("Deliver feature X"));
    }

    #[test]
    fn jira_sprint_roundtrip() {
        let sprint = JiraSprint {
            id: 7,
            name: "RT Sprint".into(),
            state: Some("future".into()),
            start_date: None,
            end_date: None,
            complete_date: None,
            origin_board_id: Some(3),
            goal: Some("Goal".into()),
        };
        let val = serde_json::to_value(&sprint).unwrap();
        let back: JiraSprint = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, 7);
        assert_eq!(back.name, "RT Sprint");
        assert_eq!(back.state.as_deref(), Some("future"));
        assert_eq!(back.origin_board_id, Some(3));
        assert_eq!(back.goal.as_deref(), Some("Goal"));
    }

    #[test]
    fn jira_sprint_serializes_camel_case() {
        let sprint = JiraSprint {
            id: 1,
            name: "S".into(),
            state: None,
            start_date: Some("2026-01-01".into()),
            end_date: Some("2026-01-14".into()),
            complete_date: Some("2026-01-13".into()),
            origin_board_id: Some(5),
            goal: None,
        };
        let val = serde_json::to_value(&sprint).unwrap();
        assert!(val.get("startDate").is_some());
        assert!(val.get("endDate").is_some());
        assert!(val.get("completeDate").is_some());
        assert!(val.get("originBoardId").is_some());
        // snake_case should NOT appear
        assert!(val.get("start_date").is_none());
        assert!(val.get("end_date").is_none());
        assert!(val.get("complete_date").is_none());
        assert!(val.get("origin_board_id").is_none());
    }

    #[test]
    fn jira_sprint_clone_debug() {
        let sprint = JiraSprint {
            id: 1,
            name: "Clone".into(),
            state: None,
            start_date: None,
            end_date: None,
            complete_date: None,
            origin_board_id: None,
            goal: None,
        };
        let cloned = sprint.clone();
        assert_eq!(cloned.id, sprint.id);
        assert_eq!(cloned.name, sprint.name);
        let dbg = format!("{sprint:?}");
        assert!(dbg.contains("JiraSprint"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // SprintListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn sprint_list_response() {
        let json = json!({"values": [], "isLast": true, "maxResults": 50, "startAt": 0});
        let resp: SprintListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.values.is_empty());
        assert_eq!(resp.is_last, Some(true));
        assert_eq!(resp.max_results, Some(50));
        assert_eq!(resp.start_at, Some(0));
    }

    #[test]
    fn sprint_list_response_missing_pagination() {
        let json = json!({"values": [{"id": 1, "name": "S1"}]});
        let resp: SprintListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.values.len(), 1);
        assert!(resp.is_last.is_none());
        assert!(resp.max_results.is_none());
        assert!(resp.start_at.is_none());
    }

    #[test]
    fn sprint_list_response_is_last_false() {
        let json = json!({"values": [], "isLast": false});
        let resp: SprintListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.is_last, Some(false));
    }

    #[test]
    fn sprint_list_response_serializes_camel_case() {
        let resp = SprintListResponse {
            values: vec![],
            is_last: Some(true),
            max_results: Some(25),
            start_at: Some(0),
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert!(val.get("isLast").is_some());
        assert!(val.get("maxResults").is_some());
        assert!(val.get("startAt").is_some());
        assert!(val.get("is_last").is_none());
        assert!(val.get("max_results").is_none());
        assert!(val.get("start_at").is_none());
    }

    #[test]
    fn sprint_list_response_clone_debug() {
        let resp = SprintListResponse {
            values: vec![],
            is_last: None,
            max_results: None,
            start_at: None,
        };
        let cloned = resp.clone();
        assert!(cloned.values.is_empty());
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("SprintListResponse"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // SearchResult
    // ════════════════════════════════════════════════════════════════

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
        assert_eq!(result.max_results, 50);
        assert_eq!(result.start_at, 0);
        assert_eq!(result.issues.len(), 1);
    }

    #[test]
    fn search_result_empty_issues() {
        let json = json!({
            "issues": [],
            "total": 0,
            "maxResults": 50,
            "startAt": 0
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert!(result.issues.is_empty());
        assert_eq!(result.total, 0);
    }

    #[test]
    fn search_result_large_pagination() {
        let json = json!({
            "issues": [],
            "total": 10000,
            "maxResults": 100,
            "startAt": 9900
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.total, 10000);
        assert_eq!(result.start_at, 9900);
    }

    #[test]
    fn search_result_roundtrip() {
        let result = SearchResult {
            issues: vec![JiraIssue {
                id: "1".into(),
                key: "SR-1".into(),
                self_url: None,
                fields: Some(json!({"summary": "test"})),
                changelog: None,
            }],
            total: 1,
            max_results: 50,
            start_at: 0,
        };
        let val = serde_json::to_value(&result).unwrap();
        let back: SearchResult = serde_json::from_value(val).unwrap();
        assert_eq!(back.total, 1);
        assert_eq!(back.issues[0].key, "SR-1");
    }

    #[test]
    fn search_result_serializes_camel_case() {
        let result = SearchResult {
            issues: vec![],
            total: 0,
            max_results: 25,
            start_at: 10,
        };
        let val = serde_json::to_value(&result).unwrap();
        assert!(val.get("maxResults").is_some());
        assert!(val.get("startAt").is_some());
        assert!(val.get("max_results").is_none());
        assert!(val.get("start_at").is_none());
    }

    #[test]
    fn search_result_clone_debug() {
        let result = SearchResult {
            issues: vec![],
            total: 0,
            max_results: 50,
            start_at: 0,
        };
        let cloned = result.clone();
        assert_eq!(cloned.total, 0);
        let dbg = format!("{result:?}");
        assert!(dbg.contains("SearchResult"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // JiraAttachment
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_attachment_serde() {
        let json = json!({
            "id": "a1",
            "filename": "doc.pdf",
            "size": 2048,
            "mimeType": "application/pdf"
        });
        let att: JiraAttachment = serde_json::from_value(json).unwrap();
        assert_eq!(att.id.as_deref(), Some("a1"));
        assert_eq!(att.filename.as_deref(), Some("doc.pdf"));
        assert_eq!(att.size, Some(2048));
        assert_eq!(att.mime_type.as_deref(), Some("application/pdf"));
    }

    #[test]
    fn jira_attachment_all_fields() {
        let json = json!({
            "id": "att-1",
            "filename": "screenshot.png",
            "size": 1024000,
            "mimeType": "image/png",
            "content": "https://jira.example.com/secure/attachment/att-1/screenshot.png",
            "created": "2026-03-05T10:00:00.000+0000",
            "author": {"displayName": "Test User", "accountId": "abc123"}
        });
        let att: JiraAttachment = serde_json::from_value(json).unwrap();
        assert!(att.content.is_some());
        assert!(att.created.is_some());
        assert!(att.author.is_some());
    }

    #[test]
    fn jira_attachment_all_none() {
        let json = json!({});
        let att: JiraAttachment = serde_json::from_value(json).unwrap();
        assert!(att.id.is_none());
        assert!(att.filename.is_none());
        assert!(att.size.is_none());
        assert!(att.mime_type.is_none());
        assert!(att.content.is_none());
        assert!(att.created.is_none());
        assert!(att.author.is_none());
    }

    #[test]
    fn jira_attachment_serializes_camel_case() {
        let att = JiraAttachment {
            id: Some("1".into()),
            filename: Some("f.txt".into()),
            size: Some(100),
            mime_type: Some("text/plain".into()),
            content: None,
            created: None,
            author: None,
        };
        let val = serde_json::to_value(&att).unwrap();
        assert!(val.get("mimeType").is_some());
        assert!(val.get("mime_type").is_none());
    }

    #[test]
    fn jira_attachment_roundtrip() {
        let att = JiraAttachment {
            id: Some("42".into()),
            filename: Some("report.csv".into()),
            size: Some(512),
            mime_type: Some("text/csv".into()),
            content: Some("https://example.com/att/42".into()),
            created: Some("2026-01-01".into()),
            author: Some(json!({"name": "user"})),
        };
        let val = serde_json::to_value(&att).unwrap();
        let back: JiraAttachment = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, att.id);
        assert_eq!(back.filename, att.filename);
        assert_eq!(back.size, att.size);
        assert_eq!(back.mime_type, att.mime_type);
        assert_eq!(back.content, att.content);
    }

    #[test]
    fn jira_attachment_clone_debug() {
        let att = JiraAttachment {
            id: None,
            filename: None,
            size: None,
            mime_type: None,
            content: None,
            created: None,
            author: None,
        };
        let cloned = att.clone();
        assert!(cloned.id.is_none());
        let dbg = format!("{att:?}");
        assert!(dbg.contains("JiraAttachment"), "got: {dbg}");
    }

    #[test]
    fn jira_attachment_zero_size() {
        let json = json!({"size": 0});
        let att: JiraAttachment = serde_json::from_value(json).unwrap();
        assert_eq!(att.size, Some(0));
    }

    // ════════════════════════════════════════════════════════════════
    // ApiErrorResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn api_error_response_serde() {
        let json = json!({"errorMessages": ["Issue not found"], "errors": {}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error_messages.as_ref().unwrap().len(), 1);
        assert_eq!(err.error_messages.unwrap()[0], "Issue not found");
    }

    #[test]
    fn api_error_response_all_none() {
        let json = json!({});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error_messages.is_none());
        assert!(err.errors.is_none());
    }

    #[test]
    fn api_error_response_null_fields() {
        let json = json!({"errorMessages": null, "errors": null});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error_messages.is_none());
        assert!(err.errors.is_none());
    }

    #[test]
    fn api_error_response_multiple_messages() {
        let json = json!({
            "errorMessages": ["Error 1", "Error 2", "Error 3"],
            "errors": {"field1": "invalid", "field2": "required"}
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error_messages.as_ref().unwrap().len(), 3);
        assert!(err.errors.is_some());
        let errors_obj = err.errors.unwrap();
        assert!(errors_obj.get("field1").is_some());
        assert!(errors_obj.get("field2").is_some());
    }

    #[test]
    fn api_error_response_empty_messages() {
        let json = json!({"errorMessages": [], "errors": {}});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error_messages.as_ref().unwrap().is_empty());
    }

    #[test]
    fn api_error_response_roundtrip() {
        let resp = ApiErrorResponse {
            error_messages: Some(vec!["msg1".into(), "msg2".into()]),
            errors: Some(json!({"key": "value"})),
        };
        let val = serde_json::to_value(&resp).unwrap();
        let back: ApiErrorResponse = serde_json::from_value(val).unwrap();
        assert_eq!(back.error_messages.as_ref().unwrap().len(), 2);
        assert!(back.errors.is_some());
    }

    #[test]
    fn api_error_response_serializes_camel_case() {
        let resp = ApiErrorResponse {
            error_messages: Some(vec!["m".into()]),
            errors: None,
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert!(val.get("errorMessages").is_some());
        assert!(val.get("error_messages").is_none());
    }

    #[test]
    fn api_error_response_clone_debug() {
        let resp = ApiErrorResponse {
            error_messages: None,
            errors: None,
        };
        let cloned = resp.clone();
        assert!(cloned.error_messages.is_none());
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ApiErrorResponse"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // Cross-type integration
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn search_result_with_rich_issues() {
        let json = json!({
            "issues": [
                {
                    "id": "1001",
                    "key": "PROJ-1",
                    "self": "https://jira.example.com/rest/api/3/issue/1001",
                    "fields": {
                        "summary": "Complex issue",
                        "status": {"name": "In Progress"},
                        "assignee": {"displayName": "Dev"},
                        "priority": {"name": "High"}
                    },
                    "changelog": {"histories": [{"id": "h1"}]}
                },
                {
                    "id": "1002",
                    "key": "PROJ-2",
                    "fields": {"summary": "Simple"}
                }
            ],
            "total": 100,
            "maxResults": 2,
            "startAt": 0
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.issues.len(), 2);
        assert!(result.issues[0].changelog.is_some());
        assert!(result.issues[1].changelog.is_none());
        assert!(result.issues[0].self_url.is_some());
        assert!(result.issues[1].self_url.is_none());
    }

    #[test]
    fn comment_list_with_varied_comments() {
        let json = json!({
            "comments": [
                {"id": "1", "body": {"type": "doc"}, "author": {"name": "u1"}},
                {"id": "2"},
                {}
            ],
            "total": 3,
            "startAt": 0,
            "maxResults": 10
        });
        let resp: CommentListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.comments.len(), 3);
        assert!(resp.comments[0].body.is_some());
        assert!(resp.comments[1].body.is_none());
        assert!(resp.comments[2].id.is_none());
    }

    #[test]
    fn sprint_list_with_varied_sprints() {
        let json = json!({
            "values": [
                {"id": 1, "name": "Active", "state": "active", "startDate": "2026-01-01"},
                {"id": 2, "name": "Future", "state": "future"},
                {"id": 3, "name": "Closed", "state": "closed", "completeDate": "2026-02-28"}
            ],
            "isLast": false,
            "maxResults": 50,
            "startAt": 0
        });
        let resp: SprintListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.values.len(), 3);
        assert!(resp.values[0].start_date.is_some());
        assert!(resp.values[1].start_date.is_none());
        assert!(resp.values[2].complete_date.is_some());
        assert_eq!(resp.is_last, Some(false));
    }

    // ════════════════════════════════════════════════════════════════
    // JiraWorklog
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_worklog_all_fields() {
        let json = json!({
            "id": "100028",
            "self": "https://jira.example.com/rest/api/3/issue/10010/worklog/100028",
            "author": {"accountId": "abc123", "displayName": "Test User"},
            "updateAuthor": {"accountId": "abc123"},
            "comment": {"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "working on fix"}]}]},
            "started": "2026-03-01T09:00:00.000+0000",
            "timeSpent": "3h",
            "timeSpentSeconds": 10800,
            "issueId": "10010",
            "created": "2026-03-01T10:00:00.000+0000",
            "updated": "2026-03-01T10:00:00.000+0000",
            "visibility": {"type": "role", "value": "Developers"}
        });
        let wl: JiraWorklog = serde_json::from_value(json).unwrap();
        assert_eq!(wl.id.as_deref(), Some("100028"));
        assert!(wl.self_url.is_some());
        assert!(wl.author.is_some());
        assert!(wl.update_author.is_some());
        assert!(wl.comment.is_some());
        assert_eq!(wl.started.as_deref(), Some("2026-03-01T09:00:00.000+0000"));
        assert_eq!(wl.time_spent.as_deref(), Some("3h"));
        assert_eq!(wl.time_spent_seconds, Some(10800));
        assert_eq!(wl.issue_id.as_deref(), Some("10010"));
        assert!(wl.created.is_some());
        assert!(wl.updated.is_some());
        assert!(wl.visibility.is_some());
    }

    #[test]
    fn jira_worklog_minimal() {
        let json = json!({});
        let wl: JiraWorklog = serde_json::from_value(json).unwrap();
        assert!(wl.id.is_none());
        assert!(wl.self_url.is_none());
        assert!(wl.time_spent.is_none());
        assert!(wl.time_spent_seconds.is_none());
    }

    #[test]
    fn jira_worklog_roundtrip() {
        let wl = JiraWorklog {
            id: Some("500".into()),
            self_url: Some("https://example.com/worklog/500".into()),
            author: Some(json!({"displayName": "Dev"})),
            update_author: None,
            comment: None,
            started: Some("2026-03-01T08:00:00.000+0000".into()),
            time_spent: Some("2h 30m".into()),
            time_spent_seconds: Some(9000),
            issue_id: Some("10001".into()),
            created: Some("2026-03-01T09:00:00.000+0000".into()),
            updated: None,
            visibility: None,
        };
        let val = serde_json::to_value(&wl).unwrap();
        let back: JiraWorklog = serde_json::from_value(val).unwrap();
        assert_eq!(back.id, wl.id);
        assert_eq!(back.time_spent, wl.time_spent);
        assert_eq!(back.time_spent_seconds, wl.time_spent_seconds);
    }

    #[test]
    fn jira_worklog_camel_case_serialization() {
        let wl = JiraWorklog {
            id: Some("1".into()),
            self_url: None,
            author: None,
            update_author: Some(json!({"name": "u"})),
            comment: None,
            started: None,
            time_spent: Some("1h".into()),
            time_spent_seconds: Some(3600),
            issue_id: Some("10".into()),
            created: None,
            updated: None,
            visibility: None,
        };
        let val = serde_json::to_value(&wl).unwrap();
        assert!(val.get("timeSpent").is_some());
        assert!(val.get("timeSpentSeconds").is_some());
        assert!(val.get("updateAuthor").is_some());
        assert!(val.get("issueId").is_some());
        assert!(val.get("self").is_some());
        // snake_case must NOT appear
        assert!(val.get("time_spent").is_none());
        assert!(val.get("time_spent_seconds").is_none());
        assert!(val.get("update_author").is_none());
        assert!(val.get("issue_id").is_none());
        assert!(val.get("self_url").is_none());
    }

    #[test]
    fn jira_worklog_clone_debug() {
        let wl = JiraWorklog {
            id: Some("99".into()),
            self_url: None,
            author: None,
            update_author: None,
            comment: None,
            started: None,
            time_spent: None,
            time_spent_seconds: None,
            issue_id: None,
            created: None,
            updated: None,
            visibility: None,
        };
        let cloned = wl.clone();
        assert_eq!(cloned.id, wl.id);
        let dbg = format!("{wl:?}");
        assert!(dbg.contains("JiraWorklog"), "got: {dbg}");
    }

    #[test]
    fn jira_worklog_zero_seconds() {
        let json = json!({"timeSpentSeconds": 0, "timeSpent": "0m"});
        let wl: JiraWorklog = serde_json::from_value(json).unwrap();
        assert_eq!(wl.time_spent_seconds, Some(0));
    }

    // ════════════════════════════════════════════════════════════════
    // WorklogListResponse
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn worklog_list_response_camel_case() {
        let json = json!({
            "worklogs": [{"id": "1", "timeSpent": "2h", "timeSpentSeconds": 7200}],
            "total": 1,
            "startAt": 0,
            "maxResults": 50
        });
        let resp: WorklogListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.total, 1);
        assert_eq!(resp.start_at, Some(0));
        assert_eq!(resp.max_results, Some(50));
        assert_eq!(resp.worklogs.len(), 1);
    }

    #[test]
    fn worklog_list_response_empty() {
        let json = json!({"worklogs": [], "total": 0});
        let resp: WorklogListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.worklogs.is_empty());
        assert_eq!(resp.total, 0);
    }

    #[test]
    fn worklog_list_response_multiple() {
        let json = json!({
            "worklogs": [
                {"id": "1", "timeSpent": "1h", "timeSpentSeconds": 3600},
                {"id": "2", "timeSpent": "30m", "timeSpentSeconds": 1800},
                {"id": "3", "timeSpent": "2h", "timeSpentSeconds": 7200}
            ],
            "total": 3,
            "startAt": 0,
            "maxResults": 100
        });
        let resp: WorklogListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.worklogs.len(), 3);
        assert_eq!(resp.total, 3);
    }

    #[test]
    fn worklog_list_response_serializes_camel_case() {
        let resp = WorklogListResponse {
            worklogs: vec![],
            total: 5,
            start_at: Some(10),
            max_results: Some(25),
        };
        let val = serde_json::to_value(&resp).unwrap();
        assert!(val.get("startAt").is_some());
        assert!(val.get("maxResults").is_some());
        assert!(val.get("start_at").is_none());
        assert!(val.get("max_results").is_none());
    }

    #[test]
    fn worklog_list_response_clone_debug() {
        let resp = WorklogListResponse {
            worklogs: vec![],
            total: 0,
            start_at: None,
            max_results: None,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.total, 0);
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("WorklogListResponse"), "got: {dbg}");
    }
}
