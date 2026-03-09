//! Jira REST API types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ── Deployment ─────────────────────────────────────────────────

/// Jira deployment type — determines API version and auth semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JiraDeployment {
    /// Atlassian Cloud — uses REST API v3, Basic auth with email:api_token.
    Cloud,
    /// Jira Server or Data Center — uses REST API v2, Basic auth with username:password or PAT.
    ServerDc,
}

impl Default for JiraDeployment {
    fn default() -> Self {
        Self::Cloud
    }
}

impl fmt::Display for JiraDeployment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cloud => write!(f, "cloud"),
            Self::ServerDc => write!(f, "server_dc"),
        }
    }
}

impl FromStr for JiraDeployment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cloud" => Ok(Self::Cloud),
            "server_dc" | "server" | "dc" | "datacenter" | "data_center" => Ok(Self::ServerDc),
            other => Err(format!(
                "Unknown deployment type '{other}'; expected 'cloud' or 'server_dc'"
            )),
        }
    }
}

impl JiraDeployment {
    /// REST API version path component for this deployment type.
    #[must_use]
    pub const fn api_version(&self) -> &'static str {
        match self {
            Self::Cloud => "3",
            Self::ServerDc => "2",
        }
    }
}

/// Server information returned by `/rest/api/2/serverInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraServerInfo {
    pub base_url: Option<String>,
    pub version: Option<String>,
    pub version_numbers: Option<Vec<u64>>,
    pub deployment_type: Option<String>,
    pub build_number: Option<u64>,
    pub build_date: Option<String>,
    pub server_time: Option<String>,
    pub scm_info: Option<String>,
    pub server_title: Option<String>,
}

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

// ── Beads Sync ──────────────────────────────────────────────────

/// Direction/origin marker for Jira ↔ Beads synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JiraSyncOrigin {
    /// The Jira copy is authoritative for this sync step.
    Jira,
    /// The Beads copy is authoritative for this sync step.
    Beads,
}

/// Reconciliation action chosen by the sync engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JiraSyncAction {
    /// No mutation required; both sides already converge.
    Noop,
    /// Push the Beads projection into Jira.
    PushBead,
    /// Pull the Jira issue into a Beads projection.
    PullIssue,
    /// Abort because both sides changed concurrently.
    Conflict,
}

/// Conflict resolution policy for a sync run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JiraSyncConflictPolicy {
    /// Default: fail closed and surface an explicit conflict object.
    #[default]
    FailClosed,
    /// Deterministically prefer one side when both changed.
    LastWriteWins,
}

/// Canonical Beads-facing issue projection used by Jira sync operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraBeadRecord {
    /// Stable bead identifier.
    pub bead_id: String,
    /// Title / summary.
    pub title: String,
    /// Optional Markdown description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional workflow status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Optional priority label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Optional labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Optional assignee identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// Optional due date in `YYYY-MM-DD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    /// Optional estimate in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate_seconds: Option<u64>,
    /// Linked Jira issue key when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_key: Option<String>,
    /// Linked Jira issue ID when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_id: Option<String>,
    /// Revision fingerprint/timestamp for the Beads-side copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// Persistable synchronization state that callers can store via connector state plumbing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraSyncState {
    /// Stable bead identifier if the mapping is established.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    /// Jira issue key if the mapping is established.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_key: Option<String>,
    /// Jira issue ID if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_id: Option<String>,
    /// Deterministic projection fingerprint for the last synced Beads payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_fingerprint: Option<String>,
    /// Deterministic projection fingerprint for the last synced Jira payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jira_fingerprint: Option<String>,
    /// Last synced Beads revision marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_revision: Option<String>,
    /// Last synced Jira revision marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jira_revision: Option<String>,
    /// Which side authored the last successful sync.
    pub last_sync_origin: JiraSyncOrigin,
    /// Tombstone for archived/deleted mappings.
    #[serde(default)]
    pub tombstoned: bool,
}

/// Explicit conflict evidence returned by `jira.sync.reconcile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraSyncConflict {
    /// Stable reason code suitable for automation.
    pub reason_code: String,
    /// Current Beads-side fingerprint.
    pub bead_fingerprint: String,
    /// Current Jira-side fingerprint.
    pub jira_fingerprint: String,
    /// Beads revision marker, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_revision: Option<String>,
    /// Jira revision marker, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jira_revision: Option<String>,
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

// ── Automation Rule ─────────────────────────────────────────────

/// Jira automation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraAutomationRule {
    pub id: Option<u64>,
    pub name: Option<String>,
    pub state: Option<String>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    pub author_account_id: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub trigger: Option<JiraAutomationTrigger>,
    pub conditions: Option<Vec<JiraAutomationCondition>>,
    pub actions: Option<Vec<JiraAutomationAction>>,
    pub projects: Option<Vec<serde_json::Value>>,
    pub tags: Option<Vec<String>>,
    pub rule_scope: Option<serde_json::Value>,
}

/// Automation rule trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraAutomationTrigger {
    #[serde(rename = "type")]
    pub trigger_type: Option<String>,
    pub value: Option<serde_json::Value>,
}

/// Automation rule condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraAutomationCondition {
    #[serde(rename = "type")]
    pub condition_type: Option<String>,
    pub value: Option<serde_json::Value>,
}

/// Automation rule action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraAutomationAction {
    #[serde(rename = "type")]
    pub action_type: Option<String>,
    pub value: Option<serde_json::Value>,
}

/// Paginated automation rule list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationRuleListResponse {
    pub rules: Option<Vec<JiraAutomationRule>>,
    pub total: Option<u64>,
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
    // Jira Sync Types
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn jira_sync_origin_roundtrip() {
        let value = serde_json::to_value(JiraSyncOrigin::Beads).unwrap();
        assert_eq!(value, json!("beads"));
        let roundtrip: JiraSyncOrigin = serde_json::from_value(value).unwrap();
        assert_eq!(roundtrip, JiraSyncOrigin::Beads);
    }

    #[test]
    fn jira_sync_conflict_policy_default() {
        assert_eq!(
            JiraSyncConflictPolicy::default(),
            JiraSyncConflictPolicy::FailClosed
        );
    }

    #[test]
    fn jira_bead_record_roundtrip() {
        let bead = JiraBeadRecord {
            bead_id: "br-123".into(),
            title: "Fix Jira sync".into(),
            description: Some("Ship deterministic mapping.".into()),
            status: Some("in_progress".into()),
            priority: Some("1".into()),
            labels: vec!["backend".into(), "jira".into()],
            assignee: Some("acct-1".into()),
            due_date: Some("2026-03-31".into()),
            estimate_seconds: Some(3600),
            issue_key: Some("PROJ-12".into()),
            issue_id: Some("10012".into()),
            revision: Some("bead-rev-7".into()),
        };

        let value = serde_json::to_value(&bead).unwrap();
        let roundtrip: JiraBeadRecord = serde_json::from_value(value).unwrap();
        assert_eq!(roundtrip, bead);
    }

    #[test]
    fn jira_sync_state_roundtrip() {
        let state = JiraSyncState {
            bead_id: Some("br-123".into()),
            issue_key: Some("PROJ-12".into()),
            issue_id: Some("10012".into()),
            bead_fingerprint: Some("{\"title\":\"x\"}".into()),
            jira_fingerprint: Some("{\"title\":\"y\"}".into()),
            bead_revision: Some("bead-rev-7".into()),
            jira_revision: Some("2026-03-09T00:00:00Z".into()),
            last_sync_origin: JiraSyncOrigin::Jira,
            tombstoned: false,
        };

        let value = serde_json::to_value(&state).unwrap();
        let roundtrip: JiraSyncState = serde_json::from_value(value).unwrap();
        assert_eq!(roundtrip, state);
    }

    #[test]
    fn jira_sync_conflict_roundtrip() {
        let conflict = JiraSyncConflict {
            reason_code: "concurrent_changes_detected".into(),
            bead_fingerprint: "{\"title\":\"local\"}".into(),
            jira_fingerprint: "{\"title\":\"remote\"}".into(),
            bead_revision: Some("b-1".into()),
            jira_revision: Some("j-1".into()),
        };

        let value = serde_json::to_value(&conflict).unwrap();
        let roundtrip: JiraSyncConflict = serde_json::from_value(value).unwrap();
        assert_eq!(roundtrip, conflict);
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

    // ════════════════════════════════════════════════════════════════
    // JiraAutomationRule
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn automation_rule_serde_roundtrip() {
        let rule = JiraAutomationRule {
            id: Some(42),
            name: Some("Auto-close stale issues".into()),
            state: Some("ENABLED".into()),
            enabled: Some(true),
            description: Some("Closes issues after 30 days".into()),
            author_account_id: Some("5b109f2e9729b51b54dc274d".into()),
            created: Some("2026-01-15T10:00:00.000Z".into()),
            updated: Some("2026-02-01T15:30:00.000Z".into()),
            trigger: Some(JiraAutomationTrigger {
                trigger_type: Some("jira.scheduled".into()),
                value: Some(json!({"cron": "0 0 * * *"})),
            }),
            conditions: Some(vec![JiraAutomationCondition {
                condition_type: Some("jira.issue.condition".into()),
                value: Some(json!({"selectedField": "status", "compareValue": "Open"})),
            }]),
            actions: Some(vec![JiraAutomationAction {
                action_type: Some("jira.issue.transition".into()),
                value: Some(json!({"transitionId": "5"})),
            }]),
            projects: Some(vec![json!({"projectId": "10001"})]),
            tags: Some(vec!["maintenance".into()]),
            rule_scope: None,
        };
        let serialized = serde_json::to_string(&rule).unwrap();
        let back: JiraAutomationRule = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.id, Some(42));
        assert_eq!(back.name.as_deref(), Some("Auto-close stale issues"));
        assert_eq!(back.state.as_deref(), Some("ENABLED"));
        assert_eq!(back.enabled, Some(true));
    }

    #[test]
    fn automation_rule_minimal_deserialization() {
        let json = json!({
            "id": 1,
            "name": "Test Rule"
        });
        let rule: JiraAutomationRule = serde_json::from_value(json).unwrap();
        assert_eq!(rule.id, Some(1));
        assert_eq!(rule.name.as_deref(), Some("Test Rule"));
        assert!(rule.state.is_none());
        assert!(rule.enabled.is_none());
        assert!(rule.trigger.is_none());
        assert!(rule.conditions.is_none());
        assert!(rule.actions.is_none());
    }

    #[test]
    fn automation_rule_all_none() {
        let json = json!({});
        let rule: JiraAutomationRule = serde_json::from_value(json).unwrap();
        assert!(rule.id.is_none());
        assert!(rule.name.is_none());
    }

    #[test]
    fn automation_rule_clone_debug() {
        let rule = JiraAutomationRule {
            id: Some(99),
            name: Some("Cloned rule".into()),
            state: None,
            enabled: None,
            description: None,
            author_account_id: None,
            created: None,
            updated: None,
            trigger: None,
            conditions: None,
            actions: None,
            projects: None,
            tags: None,
            rule_scope: None,
        };
        let cloned = rule.clone();
        assert_eq!(cloned.id, Some(99));
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("JiraAutomationRule"), "got: {dbg}");
    }

    #[test]
    fn automation_trigger_serde() {
        let trigger = JiraAutomationTrigger {
            trigger_type: Some("jira.issue.created".into()),
            value: Some(json!({"projectId": "10001"})),
        };
        let serialized = serde_json::to_string(&trigger).unwrap();
        assert!(serialized.contains("\"type\":"));
        let back: JiraAutomationTrigger = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.trigger_type.as_deref(), Some("jira.issue.created"));
    }

    #[test]
    fn automation_condition_serde() {
        let cond = JiraAutomationCondition {
            condition_type: Some("jira.jql.condition".into()),
            value: Some(json!({"jql": "status = Open"})),
        };
        let serialized = serde_json::to_string(&cond).unwrap();
        let back: JiraAutomationCondition = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.condition_type.as_deref(), Some("jira.jql.condition"));
    }

    #[test]
    fn automation_action_serde() {
        let action = JiraAutomationAction {
            action_type: Some("jira.issue.assign".into()),
            value: Some(json!({"accountId": "abc123"})),
        };
        let serialized = serde_json::to_string(&action).unwrap();
        let back: JiraAutomationAction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.action_type.as_deref(), Some("jira.issue.assign"));
    }

    #[test]
    fn automation_rule_list_response_serde() {
        let resp_json = json!({
            "rules": [
                {"id": 1, "name": "Rule 1", "enabled": true},
                {"id": 2, "name": "Rule 2", "enabled": false}
            ],
            "total": 2
        });
        let resp: AutomationRuleListResponse = serde_json::from_value(resp_json).unwrap();
        assert_eq!(resp.total, Some(2));
        let rules = resp.rules.unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name.as_deref(), Some("Rule 1"));
        assert_eq!(rules[1].enabled, Some(false));
    }

    #[test]
    fn automation_rule_list_response_empty() {
        let resp_json = json!({"rules": [], "total": 0});
        let resp: AutomationRuleListResponse = serde_json::from_value(resp_json).unwrap();
        assert_eq!(resp.total, Some(0));
        assert!(resp.rules.unwrap().is_empty());
    }

    #[test]
    fn automation_rule_list_response_clone_debug() {
        let resp = AutomationRuleListResponse {
            rules: Some(vec![]),
            total: Some(0),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.total, Some(0));
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("AutomationRuleListResponse"), "got: {dbg}");
    }

    // ════════════════════════════════════════════════════════════════
    // JiraDeployment
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn deployment_default_is_cloud() {
        assert_eq!(JiraDeployment::default(), JiraDeployment::Cloud);
    }

    #[test]
    fn deployment_display_cloud() {
        assert_eq!(JiraDeployment::Cloud.to_string(), "cloud");
    }

    #[test]
    fn deployment_display_server_dc() {
        assert_eq!(JiraDeployment::ServerDc.to_string(), "server_dc");
    }

    #[test]
    fn deployment_from_str_cloud() {
        let d: JiraDeployment = "cloud".parse().unwrap();
        assert_eq!(d, JiraDeployment::Cloud);
    }

    #[test]
    fn deployment_from_str_cloud_uppercase() {
        let d: JiraDeployment = "Cloud".parse().unwrap();
        assert_eq!(d, JiraDeployment::Cloud);
    }

    #[test]
    fn deployment_from_str_server_dc() {
        let d: JiraDeployment = "server_dc".parse().unwrap();
        assert_eq!(d, JiraDeployment::ServerDc);
    }

    #[test]
    fn deployment_from_str_server() {
        let d: JiraDeployment = "server".parse().unwrap();
        assert_eq!(d, JiraDeployment::ServerDc);
    }

    #[test]
    fn deployment_from_str_dc() {
        let d: JiraDeployment = "dc".parse().unwrap();
        assert_eq!(d, JiraDeployment::ServerDc);
    }

    #[test]
    fn deployment_from_str_datacenter() {
        let d: JiraDeployment = "datacenter".parse().unwrap();
        assert_eq!(d, JiraDeployment::ServerDc);
    }

    #[test]
    fn deployment_from_str_data_center() {
        let d: JiraDeployment = "data_center".parse().unwrap();
        assert_eq!(d, JiraDeployment::ServerDc);
    }

    #[test]
    fn deployment_from_str_invalid() {
        let result: Result<JiraDeployment, _> = "invalid".parse();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Unknown deployment type"), "got: {msg}");
        assert!(msg.contains("invalid"), "got: {msg}");
    }

    #[test]
    fn deployment_api_version_cloud() {
        assert_eq!(JiraDeployment::Cloud.api_version(), "3");
    }

    #[test]
    fn deployment_api_version_server_dc() {
        assert_eq!(JiraDeployment::ServerDc.api_version(), "2");
    }

    #[test]
    fn deployment_serialize_cloud() {
        let json = serde_json::to_string(&JiraDeployment::Cloud).unwrap();
        assert_eq!(json, "\"cloud\"");
    }

    #[test]
    fn deployment_serialize_server_dc() {
        let json = serde_json::to_string(&JiraDeployment::ServerDc).unwrap();
        assert_eq!(json, "\"server_dc\"");
    }

    #[test]
    fn deployment_deserialize_cloud() {
        let d: JiraDeployment = serde_json::from_str("\"cloud\"").unwrap();
        assert_eq!(d, JiraDeployment::Cloud);
    }

    #[test]
    fn deployment_deserialize_server_dc() {
        let d: JiraDeployment = serde_json::from_str("\"server_dc\"").unwrap();
        assert_eq!(d, JiraDeployment::ServerDc);
    }

    #[test]
    fn deployment_serde_roundtrip_cloud() {
        let original = JiraDeployment::Cloud;
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: JiraDeployment = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn deployment_serde_roundtrip_server_dc() {
        let original = JiraDeployment::ServerDc;
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: JiraDeployment = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn deployment_clone() {
        let d = JiraDeployment::Cloud;
        let cloned = d;
        assert_eq!(d, cloned);
    }

    #[test]
    fn deployment_debug() {
        let dbg = format!("{:?}", JiraDeployment::Cloud);
        assert!(dbg.contains("Cloud"), "got: {dbg}");
        let dbg = format!("{:?}", JiraDeployment::ServerDc);
        assert!(dbg.contains("ServerDc"), "got: {dbg}");
    }

    #[test]
    fn deployment_eq() {
        assert_eq!(JiraDeployment::Cloud, JiraDeployment::Cloud);
        assert_eq!(JiraDeployment::ServerDc, JiraDeployment::ServerDc);
        assert_ne!(JiraDeployment::Cloud, JiraDeployment::ServerDc);
    }

    // ════════════════════════════════════════════════════════════════
    // JiraServerInfo
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn server_info_deserialize_cloud() {
        let json = json!({
            "baseUrl": "https://mysite.atlassian.net",
            "version": "1001.0.0-SNAPSHOT",
            "versionNumbers": [1001, 0, 0],
            "deploymentType": "Cloud",
            "buildNumber": 100227,
            "buildDate": "2026-03-01T00:00:00.000+0000",
            "serverTime": "2026-03-09T12:00:00.000+0000",
            "scmInfo": "abc123",
            "serverTitle": "My Jira"
        });
        let info: JiraServerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(
            info.base_url.as_deref(),
            Some("https://mysite.atlassian.net")
        );
        assert_eq!(info.version.as_deref(), Some("1001.0.0-SNAPSHOT"));
        assert_eq!(info.deployment_type.as_deref(), Some("Cloud"));
        assert_eq!(info.build_number, Some(100227));
        assert_eq!(info.server_title.as_deref(), Some("My Jira"));
    }

    #[test]
    fn server_info_deserialize_server() {
        let json = json!({
            "baseUrl": "https://jira.mycompany.com",
            "version": "9.4.7",
            "versionNumbers": [9, 4, 7],
            "deploymentType": "Server",
            "buildNumber": 90407
        });
        let info: JiraServerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.deployment_type.as_deref(), Some("Server"));
        assert_eq!(info.version.as_deref(), Some("9.4.7"));
    }

    #[test]
    fn server_info_all_optional() {
        let json = json!({});
        let info: JiraServerInfo = serde_json::from_value(json).unwrap();
        assert!(info.base_url.is_none());
        assert!(info.version.is_none());
        assert!(info.version_numbers.is_none());
        assert!(info.deployment_type.is_none());
        assert!(info.build_number.is_none());
        assert!(info.build_date.is_none());
        assert!(info.server_time.is_none());
        assert!(info.scm_info.is_none());
        assert!(info.server_title.is_none());
    }

    #[test]
    fn server_info_clone_debug() {
        let info = JiraServerInfo {
            base_url: Some("https://example.com".into()),
            version: Some("9.0.0".into()),
            version_numbers: Some(vec![9, 0, 0]),
            deployment_type: Some("Server".into()),
            build_number: Some(90000),
            build_date: None,
            server_time: None,
            scm_info: None,
            server_title: None,
        };
        let cloned = info.clone();
        assert_eq!(cloned.version, info.version);
        let dbg = format!("{info:?}");
        assert!(dbg.contains("JiraServerInfo"), "got: {dbg}");
    }

    #[test]
    fn server_info_serde_roundtrip() {
        let info = JiraServerInfo {
            base_url: Some("https://jira.example.com".into()),
            version: Some("8.20.1".into()),
            version_numbers: Some(vec![8, 20, 1]),
            deployment_type: Some("Server".into()),
            build_number: Some(82001),
            build_date: Some("2025-12-01T00:00:00.000+0000".into()),
            server_time: Some("2026-03-09T14:00:00.000+0000".into()),
            scm_info: Some("deadbeef".into()),
            server_title: Some("Company Jira".into()),
        };
        let json = serde_json::to_value(&info).unwrap();
        let deserialized: JiraServerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.base_url, info.base_url);
        assert_eq!(deserialized.version, info.version);
        assert_eq!(deserialized.build_number, info.build_number);
        assert_eq!(deserialized.deployment_type, info.deployment_type);
    }
}
