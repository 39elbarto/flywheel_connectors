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

    #[test]
    fn scenario_clone() {
        let s = Scenario {
            id: 1,
            name: Some("Test".into()),
            description: None,
            is_enabled: Some(true),
            team_id: Some(5),
        };
        let c = s.clone();
        assert_eq!(c.id, s.id);
        assert_eq!(c.name, s.name);
        assert_eq!(c.is_enabled, s.is_enabled);
    }

    #[test]
    fn scenario_debug() {
        let s = Scenario {
            id: 42,
            name: Some("Debug Test".into()),
            description: None,
            is_enabled: None,
            team_id: None,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Scenario"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn execution_clone() {
        let e = Execution {
            id: 10,
            scenario_id: Some(5),
            status: Some("done".into()),
            started: None,
            finished: None,
        };
        let c = e.clone();
        assert_eq!(c.id, e.id);
        assert_eq!(c.status, e.status);
    }

    #[test]
    fn execution_debug() {
        let e = Execution {
            id: 99,
            scenario_id: None,
            status: Some("running".into()),
            started: None,
            finished: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Execution"));
        assert!(dbg.contains("running"));
    }

    #[test]
    fn scenario_run_result_clone() {
        let r = ScenarioRunResult {
            execution_id: Some("exec_1".into()),
        };
        let c = r.clone();
        assert_eq!(c.execution_id, r.execution_id);
    }

    #[test]
    fn scenario_run_result_debug() {
        let r = ScenarioRunResult {
            execution_id: Some("exec_abc".into()),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ScenarioRunResult"));
    }

    #[test]
    fn api_error_clone() {
        let e = ApiErrorResponse {
            message: Some("err".into()),
            detail: None,
        };
        let c = e.clone();
        assert_eq!(c.message, e.message);
    }

    #[test]
    fn api_error_debug() {
        let e = ApiErrorResponse {
            message: Some("test".into()),
            detail: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn scenario_from_json_string() {
        let s: Scenario =
            serde_json::from_str(r#"{"id":7,"name":"FromStr"}"#).unwrap();
        assert_eq!(s.id, 7);
        assert_eq!(s.name, Some("FromStr".into()));
    }

    #[test]
    fn execution_from_json_string() {
        let e: Execution =
            serde_json::from_str(r#"{"id":3,"status":"failed"}"#).unwrap();
        assert_eq!(e.id, 3);
        assert_eq!(e.status, Some("failed".into()));
    }

    #[test]
    fn scenario_missing_id_fails() {
        assert!(serde_json::from_value::<Scenario>(json!({"name": "x"})).is_err());
    }

    #[test]
    fn execution_missing_id_fails() {
        assert!(serde_json::from_value::<Execution>(json!({"status": "ok"})).is_err());
    }

    #[test]
    fn scenario_run_result_extra_fields_ignored() {
        let r: ScenarioRunResult =
            serde_json::from_value(json!({"executionId": "e1", "extra": true})).unwrap();
        assert_eq!(r.execution_id, Some("e1".into()));
    }

    #[test]
    fn scenario_unicode_name() {
        let s: Scenario = serde_json::from_value(json!({"id": 1, "name": "日本語テスト"})).unwrap();
        assert_eq!(s.name, Some("日本語テスト".into()));
    }

    #[test]
    fn execution_all_statuses() {
        for status in ["success", "failed", "running", "waiting", "cancelled"] {
            let e: Execution =
                serde_json::from_value(json!({"id": 1, "status": status})).unwrap();
            assert_eq!(e.status.as_deref(), Some(status));
        }
    }

    #[test]
    fn scenario_is_enabled_false() {
        let s: Scenario =
            serde_json::from_value(json!({"id": 1, "isEnabled": false})).unwrap();
        assert_eq!(s.is_enabled, Some(false));
    }

    #[test]
    fn scenario_negative_id() {
        let s: Scenario = serde_json::from_value(json!({"id": -1})).unwrap();
        assert_eq!(s.id, -1);
    }

    #[test]
    fn scenario_roundtrip_preserves_rename() {
        let s = Scenario {
            id: 1,
            name: None,
            description: None,
            is_enabled: Some(true),
            team_id: Some(42),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("isEnabled").is_some());
        assert!(v.get("is_enabled").is_none());
        assert!(v.get("teamId").is_some());
        assert!(v.get("team_id").is_none());
    }

    #[test]
    fn execution_roundtrip_preserves_rename() {
        let e = Execution {
            id: 1,
            scenario_id: Some(10),
            status: None,
            started: None,
            finished: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("scenarioId").is_some());
        assert!(v.get("scenario_id").is_none());
    }

    #[test]
    fn scenario_run_result_preserves_rename() {
        let r = ScenarioRunResult {
            execution_id: Some("e1".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("executionId").is_some());
        assert!(v.get("execution_id").is_none());
    }

    #[test]
    fn api_error_response_extra_fields() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": "m", "unknown": 42})).unwrap();
        assert_eq!(e.message, Some("m".into()));
    }

    #[test]
    fn api_error_response_null_fields() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": null, "detail": null})).unwrap();
        assert!(e.message.is_none());
        assert!(e.detail.is_none());
    }
}
