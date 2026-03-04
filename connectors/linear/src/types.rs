//! Linear GraphQL API types.

use serde::{Deserialize, Serialize};

// ── GraphQL request/response ────────────────────────────────────

/// GraphQL request body.
#[derive(Debug, Serialize)]
pub struct GraphQLRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<serde_json::Value>,
}

/// GraphQL response wrapper.
#[derive(Debug, Deserialize)]
pub struct GraphQLResponse {
    pub data: Option<serde_json::Value>,
    pub errors: Option<Vec<GraphQLError>>,
}

/// GraphQL error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    pub path: Option<Vec<serde_json::Value>>,
    pub extensions: Option<serde_json::Value>,
}

// ── Issue ───────────────────────────────────────────────────────

/// Linear issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    pub identifier: String,
    pub title: String,
    pub description: Option<String>,
    pub priority: Option<f64>,
    pub priority_label: Option<String>,
    pub state: Option<IssueState>,
    pub assignee: Option<User>,
    pub team: Option<TeamRef>,
    pub labels: Option<LabelConnection>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub url: Option<String>,
}

/// Issue state (workflow state).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueState {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    #[serde(rename = "type")]
    pub state_type: Option<String>,
}

/// Label connection (paginated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelConnection {
    pub nodes: Vec<Label>,
}

/// Issue label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
}

// ── Team ────────────────────────────────────────────────────────

/// Linear team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub key: String,
    pub description: Option<String>,
}

/// Lightweight team reference in issue responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamRef {
    pub id: String,
    pub name: Option<String>,
    pub key: Option<String>,
}

// ── User ────────────────────────────────────────────────────────

/// Linear user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
}

// ── Cycle ───────────────────────────────────────────────────────

/// Linear cycle (sprint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cycle {
    pub id: String,
    pub number: u32,
    pub name: Option<String>,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
    pub completed_at: Option<String>,
}

// ── Project ─────────────────────────────────────────────────────

/// Linear project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub state: Option<String>,
    pub progress: Option<f64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub url: Option<String>,
}

// ── Comment ─────────────────────────────────────────────────────

/// Linear comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueComment {
    pub id: String,
    pub body: String,
    pub user: Option<User>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

// ── Mutation results ────────────────────────────────────────────

/// Result from creating an issue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCreatePayload {
    pub success: bool,
    pub issue: Option<Issue>,
}

/// Result from updating an issue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueUpdatePayload {
    pub success: bool,
    pub issue: Option<Issue>,
}

/// Result from creating a comment.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentCreatePayload {
    pub success: bool,
    pub comment: Option<IssueComment>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- GraphQL types ----

    #[test]
    fn graphql_request_serialize() {
        let req = GraphQLRequest {
            query: "{ viewer { id } }".to_string(),
            variables: Some(json!({"first": 10})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("viewer"));
        assert!(json.contains("\"first\":10"));
    }

    #[test]
    fn graphql_request_no_variables() {
        let req = GraphQLRequest {
            query: "{ viewer { id } }".to_string(),
            variables: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("variables"));
    }

    #[test]
    fn graphql_response_with_data() {
        let json = r#"{"data":{"viewer":{"id":"u1"}}}"#;
        let resp: GraphQLResponse = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_some());
        assert!(resp.errors.is_none());
    }

    #[test]
    fn graphql_response_with_errors() {
        let json = json!({
            "data": null,
            "errors": [{"message": "Not found", "path": ["issue"]}]
        });
        let resp: GraphQLResponse = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_none());
        let errors = resp.errors.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "Not found");
    }

    #[test]
    fn graphql_error_serde() {
        let err = GraphQLError {
            message: "Unauthorized".to_string(),
            path: Some(vec![json!("viewer")]),
            extensions: Some(json!({"code": "UNAUTHENTICATED"})),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphQLError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message, "Unauthorized");
    }

    // ---- Issue ----

    #[test]
    fn issue_camel_case_serde() {
        let json = json!({
            "id": "i1",
            "identifier": "PROJ-1",
            "title": "Fix bug",
            "description": "A bug",
            "priority": 2.0,
            "priorityLabel": "High",
            "state": {"id": "s1", "name": "In Progress", "color": "#ff0", "type": "started"},
            "assignee": {"id": "u1", "name": "Alice", "displayName": "alice", "email": "alice@example.com"},
            "team": {"id": "t1", "name": "Eng", "key": "ENG"},
            "labels": {"nodes": [{"id": "l1", "name": "bug", "color": "#f00"}]},
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-03-01T00:00:00Z",
            "url": "https://linear.app/project/PROJ-1"
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.identifier, "PROJ-1");
        assert_eq!(issue.priority_label.as_deref(), Some("High"));
        assert!(issue.state.is_some());
        assert!(issue.assignee.is_some());
        assert_eq!(issue.labels.as_ref().unwrap().nodes.len(), 1);
    }

    #[test]
    fn issue_minimal() {
        let json = json!({
            "id": "i2",
            "identifier": "PROJ-2",
            "title": "Task",
            "description": null,
            "priority": null,
            "priorityLabel": null,
            "state": null,
            "assignee": null,
            "team": null,
            "labels": null,
            "createdAt": null,
            "updatedAt": null,
            "url": null
        });
        let issue: Issue = serde_json::from_value(json).unwrap();
        assert_eq!(issue.title, "Task");
        assert!(issue.state.is_none());
    }

    // ---- Team ----

    #[test]
    fn team_serde() {
        let team = Team {
            id: "t1".to_string(),
            name: "Engineering".to_string(),
            key: "ENG".to_string(),
            description: Some("Core team".to_string()),
        };
        let json = serde_json::to_string(&team).unwrap();
        let back: Team = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, "ENG");
    }

    // ---- Cycle ----

    #[test]
    fn cycle_camel_case_serde() {
        let json = json!({
            "id": "c1",
            "number": 5,
            "name": "Sprint 5",
            "startsAt": "2026-03-01",
            "endsAt": "2026-03-14",
            "completedAt": null
        });
        let cycle: Cycle = serde_json::from_value(json).unwrap();
        assert_eq!(cycle.number, 5);
        assert!(cycle.completed_at.is_none());
    }

    // ---- Project ----

    #[test]
    fn project_serde() {
        let json = json!({
            "id": "p1",
            "name": "Q1 Goals",
            "description": "quarterly",
            "state": "started",
            "progress": 0.75,
            "createdAt": "2026-01-01",
            "updatedAt": "2026-03-01",
            "url": "https://linear.app/project/p1"
        });
        let project: Project = serde_json::from_value(json).unwrap();
        assert_eq!(project.name, "Q1 Goals");
        assert_eq!(project.progress, Some(0.75));
    }

    // ---- IssueComment ----

    #[test]
    fn issue_comment_serde() {
        let json = json!({
            "id": "cmt1",
            "body": "Looks good!",
            "user": {"id": "u1", "name": "Alice", "displayName": null, "email": null},
            "createdAt": "2026-03-03",
            "updatedAt": null
        });
        let comment: IssueComment = serde_json::from_value(json).unwrap();
        assert_eq!(comment.body, "Looks good!");
        assert!(comment.user.is_some());
    }

    // ---- Mutation payloads ----

    #[test]
    fn issue_create_payload() {
        let json = json!({"success": true, "issue": {"id":"i1","identifier":"P-1","title":"New","description":null,"priority":null,"priorityLabel":null,"state":null,"assignee":null,"team":null,"labels":null,"createdAt":null,"updatedAt":null,"url":null}});
        let payload: IssueCreatePayload = serde_json::from_value(json).unwrap();
        assert!(payload.success);
        assert!(payload.issue.is_some());
    }

    #[test]
    fn issue_update_payload_failed() {
        let json = json!({"success": false, "issue": null});
        let payload: IssueUpdatePayload = serde_json::from_value(json).unwrap();
        assert!(!payload.success);
        assert!(payload.issue.is_none());
    }

    #[test]
    fn comment_create_payload() {
        let json = json!({"success": true, "comment": {"id":"c1","body":"hi","user":null,"createdAt":null,"updatedAt":null}});
        let payload: CommentCreatePayload = serde_json::from_value(json).unwrap();
        assert!(payload.success);
    }
}
