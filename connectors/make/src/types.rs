//! `Make` API types.

use serde::{Deserialize, Serialize};

/// A `Make` scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub id: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: Option<bool>,
    #[serde(rename = "teamId")]
    pub team_id: Option<i64>,
}

/// A `Make` scenario execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub id: i64,
    #[serde(rename = "scenarioId")]
    pub scenario_id: Option<i64>,
    pub status: Option<String>,
    pub started: Option<String>,
    pub finished: Option<String>,
}

/// Result from triggering a scenario run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRunResult {
    #[serde(rename = "executionId")]
    pub execution_id: Option<String>,
}

/// `Make` API error response body.
///
/// `Make` returns `{"message": "..."}` or `{"detail": "..."}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from `Make`.
    pub message: Option<String>,
    /// Alternative error detail field.
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scenario_roundtrip() {
        let s: Scenario = serde_json::from_value(json!({
            "id": 12345,
            "name": "Daily Sync",
            "description": "Sync data daily from CRM",
            "isEnabled": true,
            "teamId": 99,
        }))
        .unwrap();
        assert_eq!(s.id, 12345);
        assert_eq!(s.name, Some("Daily Sync".into()));
        assert_eq!(s.description, Some("Sync data daily from CRM".into()));
        assert_eq!(s.is_enabled, Some(true));
        assert_eq!(s.team_id, Some(99));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "Daily Sync");
    }

    #[test]
    fn scenario_minimal() {
        let s: Scenario = serde_json::from_value(json!({"id": 1})).unwrap();
        assert_eq!(s.id, 1);
        assert!(s.name.is_none());
        assert!(s.description.is_none());
        assert!(s.is_enabled.is_none());
        assert!(s.team_id.is_none());
    }

    #[test]
    fn scenario_serialize_roundtrip() {
        let s = Scenario {
            id: 42,
            name: Some("Test Scenario".into()),
            description: None,
            is_enabled: Some(false),
            team_id: Some(7),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["id"], 42);
        assert_eq!(v["name"], "Test Scenario");
        assert_eq!(v["isEnabled"], false);
        assert_eq!(v["teamId"], 7);
    }

    #[test]
    fn scenario_extra_fields_ignored() {
        let s: Scenario = serde_json::from_value(json!({
            "id": 1,
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(s.id, 1);
        assert_eq!(s.name, Some("Test".into()));
    }

    #[test]
    fn execution_roundtrip() {
        let e: Execution = serde_json::from_value(json!({
            "id": 67890,
            "scenarioId": 12345,
            "status": "success",
            "started": "2026-01-15T10:00:00Z",
            "finished": "2026-01-15T10:01:30Z",
        }))
        .unwrap();
        assert_eq!(e.id, 67890);
        assert_eq!(e.scenario_id, Some(12345));
        assert_eq!(e.status, Some("success".into()));
        assert_eq!(e.started, Some("2026-01-15T10:00:00Z".into()));
        assert_eq!(e.finished, Some("2026-01-15T10:01:30Z".into()));
        let re = serde_json::to_value(&e).unwrap();
        assert_eq!(re["status"], "success");
    }

    #[test]
    fn execution_minimal() {
        let e: Execution = serde_json::from_value(json!({"id": 1})).unwrap();
        assert_eq!(e.id, 1);
        assert!(e.scenario_id.is_none());
        assert!(e.status.is_none());
        assert!(e.started.is_none());
        assert!(e.finished.is_none());
    }

    #[test]
    fn execution_serialize_roundtrip() {
        let e = Execution {
            id: 100,
            scenario_id: Some(42),
            status: Some("running".into()),
            started: Some("2026-03-01T12:00:00Z".into()),
            finished: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["id"], 100);
        assert_eq!(v["scenarioId"], 42);
        assert_eq!(v["status"], "running");
    }

    #[test]
    fn execution_extra_fields_ignored() {
        let e: Execution = serde_json::from_value(json!({
            "id": 1,
            "status": "done",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(e.id, 1);
        assert_eq!(e.status, Some("done".into()));
    }

    #[test]
    fn scenario_run_result_roundtrip() {
        let r: ScenarioRunResult = serde_json::from_value(json!({
            "executionId": "exec_abc123",
        }))
        .unwrap();
        assert_eq!(r.execution_id, Some("exec_abc123".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["executionId"], "exec_abc123");
    }

    #[test]
    fn scenario_run_result_empty() {
        let r: ScenarioRunResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.execution_id.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Scenario not found",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Scenario not found".into()));
        assert!(e.detail.is_none());
    }

    #[test]
    fn api_error_response_with_detail() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "Authentication required",
        }))
        .unwrap();
        assert!(e.message.is_none());
        assert_eq!(e.detail, Some("Authentication required".into()));
    }

    #[test]
    fn api_error_response_with_both() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Error occurred",
            "detail": "Some detail",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Error occurred".into()));
        assert_eq!(e.detail, Some("Some detail".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.detail.is_none());
    }
}
