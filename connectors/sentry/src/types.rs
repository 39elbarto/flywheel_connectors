//! Sentry API types.

use serde::{Deserialize, Serialize};

/// A Sentry organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: String,
    pub slug: String,
    pub name: String,
}

/// A Sentry project.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub platform: Option<String>,
    #[serde(default)]
    pub is_bookmarked: bool,
    #[serde(default)]
    pub is_member: bool,
    #[serde(default)]
    pub has_access: bool,
    pub date_created: Option<String>,
    pub first_event: Option<String>,
}

/// A Sentry issue (group of events).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    pub id: String,
    pub short_id: Option<String>,
    pub title: String,
    pub culprit: Option<String>,
    pub level: Option<String>,
    pub status: Option<String>,
    pub substatus: Option<String>,
    #[serde(rename = "type")]
    pub issue_type: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub count: Option<String>,
    pub user_count: Option<u64>,
    pub permalink: Option<String>,
    pub project: Option<IssueProject>,
    pub assigned_to: Option<serde_json::Value>,
    pub is_bookmarked: Option<bool>,
    pub is_subscribed: Option<bool>,
    pub has_seen: Option<bool>,
    pub metadata: Option<serde_json::Value>,
    pub stats: Option<serde_json::Value>,
}

/// Minimal project info embedded in an issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueProject {
    pub id: String,
    pub slug: String,
    pub name: Option<String>,
}

/// A Sentry event (single error occurrence).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub event_id: Option<String>,
    #[serde(rename = "eventID")]
    pub event_id_upper: Option<String>,
    pub title: Option<String>,
    pub message: Option<String>,
    pub platform: Option<String>,
    pub date_created: Option<String>,
    pub date_received: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub tags: Option<Vec<EventTag>>,
    pub entries: Option<Vec<serde_json::Value>>,
    pub contexts: Option<serde_json::Value>,
    pub user: Option<serde_json::Value>,
    pub sdk: Option<serde_json::Value>,
    pub context: Option<serde_json::Value>,
    pub errors: Option<Vec<serde_json::Value>>,
    pub fingerprints: Option<Vec<String>>,
}

/// A tag attached to an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTag {
    pub key: String,
    pub value: String,
}

/// A Sentry release.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub version: String,
    #[serde(rename = "shortVersion")]
    pub short_version: Option<String>,
    pub date_released: Option<String>,
    pub date_created: Option<String>,
    pub new_groups: Option<u64>,
    pub first_event: Option<String>,
    pub last_event: Option<String>,
    pub last_deploy: Option<Deploy>,
    pub authors: Option<Vec<serde_json::Value>>,
    pub projects: Option<Vec<ReleaseProject>>,
    pub commit_count: Option<u64>,
    pub url: Option<String>,
}

/// Project info in a release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseProject {
    pub id: Option<u64>,
    pub slug: String,
    pub name: Option<String>,
}

/// A deploy record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deploy {
    pub id: Option<String>,
    pub environment: Option<String>,
    pub date_started: Option<String>,
    pub date_finished: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
}

/// An alert rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRule {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub conditions: Vec<serde_json::Value>,
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub filters: Vec<serde_json::Value>,
    pub action_match: Option<String>,
    pub filter_match: Option<String>,
    pub frequency: Option<u64>,
    pub date_created: Option<String>,
    pub status: Option<String>,
}

/// A Discover query result row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverResult {
    pub data: Vec<serde_json::Value>,
    pub meta: Option<serde_json::Value>,
}

/// A transaction event (performance monitoring).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub event_id: Option<String>,
    pub title: Option<String>,
    pub transaction: Option<String>,
    pub start_timestamp: Option<f64>,
    pub timestamp: Option<f64>,
    pub duration: Option<f64>,
    pub contexts: Option<serde_json::Value>,
    pub measurements: Option<serde_json::Value>,
    pub spans: Option<Vec<serde_json::Value>>,
    pub tags: Option<Vec<EventTag>>,
}

/// Sentry API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub detail: Option<String>,
    #[serde(rename = "extraData")]
    pub extra_data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn organization_roundtrip() {
        let org: Organization = serde_json::from_value(json!({
            "id": "1", "slug": "my-org", "name": "My Org"
        }))
        .unwrap();
        assert_eq!(org.slug, "my-org");
        let re = serde_json::to_value(&org).unwrap();
        assert_eq!(re["id"], "1");
    }

    #[test]
    fn project_roundtrip() {
        let p: Project = serde_json::from_value(json!({
            "id": "42", "slug": "backend", "name": "Backend",
            "platform": "python", "isBookmarked": true, "isMember": false,
            "hasAccess": true, "dateCreated": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(p.slug, "backend");
        assert!(p.is_bookmarked);
        assert!(!p.is_member);
        assert!(p.has_access);
        assert_eq!(p.platform, Some("python".into()));
    }

    #[test]
    fn project_defaults_booleans() {
        let p: Project = serde_json::from_value(json!({
            "id": "1", "slug": "s", "name": "n"
        }))
        .unwrap();
        assert!(!p.is_bookmarked);
        assert!(!p.is_member);
        assert!(!p.has_access);
    }

    #[test]
    fn issue_full_deserialization() {
        let i: Issue = serde_json::from_value(json!({
            "id": "100",
            "shortId": "PROJ-1A",
            "title": "NullPointerException",
            "culprit": "com.example.Main.handle",
            "level": "error",
            "status": "unresolved",
            "substatus": "new",
            "type": "error",
            "firstSeen": "2026-01-01T00:00:00Z",
            "lastSeen": "2026-03-01T00:00:00Z",
            "count": "42",
            "userCount": 15,
            "permalink": "https://sentry.io/issues/100/",
            "project": {"id": "1", "slug": "backend"},
            "isBookmarked": false,
            "isSubscribed": true,
            "hasSeen": true,
        }))
        .unwrap();
        assert_eq!(i.id, "100");
        assert_eq!(i.short_id, Some("PROJ-1A".into()));
        assert_eq!(i.issue_type, Some("error".into()));
        assert_eq!(i.user_count, Some(15));
        assert_eq!(i.project.unwrap().slug, "backend");
    }

    #[test]
    fn issue_minimal() {
        let i: Issue = serde_json::from_value(json!({
            "id": "1", "title": "err"
        }))
        .unwrap();
        assert_eq!(i.id, "1");
        assert!(i.culprit.is_none());
        assert!(i.project.is_none());
    }

    #[test]
    fn event_deserialization() {
        let e: Event = serde_json::from_value(json!({
            "eventID": "abc123",
            "title": "Error in handler",
            "platform": "python",
            "dateCreated": "2026-01-01T00:00:00Z",
            "type": "error",
            "tags": [{"key": "browser", "value": "Chrome"}],
            "fingerprints": ["{{ default }}"],
        }))
        .unwrap();
        assert_eq!(e.event_id_upper, Some("abc123".into()));
        assert_eq!(e.event_type, Some("error".into()));
        assert_eq!(e.tags.unwrap()[0].key, "browser");
        assert_eq!(e.fingerprints.unwrap(), vec!["{{ default }}"]);
    }

    #[test]
    fn event_tag_roundtrip() {
        let t: EventTag = serde_json::from_value(json!({"key": "env", "value": "prod"})).unwrap();
        assert_eq!(t.key, "env");
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["value"], "prod");
    }

    #[test]
    fn release_deserialization() {
        let r: Release = serde_json::from_value(json!({
            "version": "backend@1.2.3",
            "shortVersion": "1.2.3",
            "dateReleased": "2026-03-01T00:00:00Z",
            "newGroups": 5,
            "commitCount": 12,
            "projects": [{"slug": "backend", "name": "Backend"}],
            "lastDeploy": {
                "id": "1",
                "environment": "production",
                "dateFinished": "2026-03-01T00:00:00Z",
            },
        }))
        .unwrap();
        assert_eq!(r.version, "backend@1.2.3");
        assert_eq!(r.short_version, Some("1.2.3".into()));
        assert_eq!(r.new_groups, Some(5));
        assert_eq!(r.commit_count, Some(12));
        assert_eq!(r.projects.unwrap()[0].slug, "backend");
        let deploy = r.last_deploy.unwrap();
        assert_eq!(deploy.environment, Some("production".into()));
    }

    #[test]
    fn deploy_roundtrip() {
        let d: Deploy = serde_json::from_value(json!({
            "id": "42", "environment": "staging",
            "dateStarted": "2026-01-01T00:00:00Z",
            "dateFinished": "2026-01-01T01:00:00Z",
            "name": "v1-deploy", "url": "https://example.com"
        }))
        .unwrap();
        assert_eq!(d.environment, Some("staging".into()));
        assert_eq!(d.name, Some("v1-deploy".into()));
        let re = serde_json::to_value(&d).unwrap();
        assert_eq!(re["url"], "https://example.com");
    }

    #[test]
    fn alert_rule_deserialization() {
        let a: AlertRule = serde_json::from_value(json!({
            "id": "1",
            "name": "High error rate",
            "conditions": [{"id": "sentry.rules.conditions.event_frequency.EventFrequencyCondition"}],
            "actions": [{"id": "sentry.mail.actions.NotifyEmailAction"}],
            "actionMatch": "all",
            "filterMatch": "all",
            "frequency": 30,
            "status": "active",
        }))
        .unwrap();
        assert_eq!(a.name, "High error rate");
        assert_eq!(a.conditions.len(), 1);
        assert_eq!(a.actions.len(), 1);
        assert_eq!(a.frequency, Some(30));
        assert_eq!(a.action_match, Some("all".into()));
    }

    #[test]
    fn alert_rule_defaults_empty_vecs() {
        let a: AlertRule = serde_json::from_value(json!({"name": "empty"})).unwrap();
        assert!(a.conditions.is_empty());
        assert!(a.actions.is_empty());
        assert!(a.filters.is_empty());
    }

    #[test]
    fn discover_result_deserialization() {
        let d: DiscoverResult = serde_json::from_value(json!({
            "data": [
                {"transaction": "/api/users", "count()": 100},
                {"transaction": "/api/items", "count()": 50},
            ],
            "meta": {"fields": {"transaction": "string"}},
        }))
        .unwrap();
        assert_eq!(d.data.len(), 2);
        assert!(d.meta.is_some());
    }

    #[test]
    fn transaction_deserialization() {
        let t: Transaction = serde_json::from_value(json!({
            "eventId": "tx-1",
            "title": "GET /api/users",
            "transaction": "/api/users",
            "startTimestamp": 1709251200.0,
            "timestamp": 1709251200.5,
            "duration": 500.0,
            "tags": [{"key": "http.method", "value": "GET"}],
            "spans": [{"op": "db", "description": "SELECT *"}],
        }))
        .unwrap();
        assert_eq!(t.transaction, Some("/api/users".into()));
        assert_eq!(t.duration, Some(500.0));
        assert_eq!(t.spans.unwrap().len(), 1);
    }

    #[test]
    fn api_error_response_with_detail() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"detail": "Not found", "extraData": {"code": 404}}))
                .unwrap();
        assert_eq!(e.detail, Some("Not found".into()));
        assert!(e.extra_data.is_some());
    }

    #[test]
    fn api_error_response_minimal() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.detail.is_none());
        assert!(e.extra_data.is_none());
    }

    #[test]
    fn issue_project_roundtrip() {
        let p: IssueProject =
            serde_json::from_value(json!({"id": "1", "slug": "backend", "name": "Backend"}))
                .unwrap();
        assert_eq!(p.slug, "backend");
        assert_eq!(p.name, Some("Backend".into()));
    }

    #[test]
    fn release_project_roundtrip() {
        let p: ReleaseProject =
            serde_json::from_value(json!({"id": 42, "slug": "frontend", "name": "Frontend"}))
                .unwrap();
        assert_eq!(p.id, Some(42));
        assert_eq!(p.slug, "frontend");
    }
}
