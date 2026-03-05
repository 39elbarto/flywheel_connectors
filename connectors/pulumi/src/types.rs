//! `Pulumi` API types.

use serde::{Deserialize, Serialize};

/// A `Pulumi` stack with full details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stack {
    pub org_name: String,
    pub project_name: String,
    pub stack_name: String,
    #[serde(default)]
    pub active_update: Option<String>,
    #[serde(default)]
    pub tags: Option<serde_json::Value>,
    #[serde(default)]
    pub version: Option<u64>,
}

/// A `Pulumi` stack summary (as returned from the list endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackSummary {
    pub org_name: String,
    pub project_name: String,
    pub stack_name: String,
    #[serde(default)]
    pub last_update: Option<u64>,
    #[serde(default)]
    pub resource_count: Option<u64>,
}

/// A `Pulumi` deployment update entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentUpdate {
    #[serde(default)]
    pub version: Option<u64>,
    #[serde(default)]
    pub start_time: Option<u64>,
    #[serde(default)]
    pub end_time: Option<u64>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub environment: Option<serde_json::Value>,
    #[serde(default)]
    pub resource_changes: Option<serde_json::Value>,
}

/// `Pulumi` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub code: Option<u16>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stack_roundtrip() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "myorg",
            "projectName": "myproject",
            "stackName": "production",
            "activeUpdate": "abc123",
            "version": 42,
        }))
        .unwrap();
        assert_eq!(s.org_name, "myorg");
        assert_eq!(s.project_name, "myproject");
        assert_eq!(s.stack_name, "production");
        assert_eq!(s.active_update, Some("abc123".into()));
        assert_eq!(s.version, Some(42));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["orgName"], "myorg");
        assert_eq!(re["projectName"], "myproject");
    }

    #[test]
    fn stack_minimal() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o",
            "projectName": "p",
            "stackName": "s",
        }))
        .unwrap();
        assert_eq!(s.org_name, "o");
        assert!(s.active_update.is_none());
        assert!(s.tags.is_none());
        assert!(s.version.is_none());
    }

    #[test]
    fn stack_with_tags() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o",
            "projectName": "p",
            "stackName": "s",
            "tags": {"env": "staging", "team": "platform"},
        }))
        .unwrap();
        let tags = s.tags.unwrap();
        assert_eq!(tags["env"], "staging");
    }

    #[test]
    fn stack_summary_roundtrip() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "myorg",
            "projectName": "myproject",
            "stackName": "dev",
            "lastUpdate": 1709_280_000,
            "resourceCount": 15,
        }))
        .unwrap();
        assert_eq!(ss.org_name, "myorg");
        assert_eq!(ss.stack_name, "dev");
        assert_eq!(ss.last_update, Some(1709_280_000));
        assert_eq!(ss.resource_count, Some(15));
        let re = serde_json::to_value(&ss).unwrap();
        assert_eq!(re["stackName"], "dev");
    }

    #[test]
    fn stack_summary_minimal() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "o",
            "projectName": "p",
            "stackName": "s",
        }))
        .unwrap();
        assert_eq!(ss.org_name, "o");
        assert!(ss.last_update.is_none());
        assert!(ss.resource_count.is_none());
    }

    #[test]
    fn deployment_update_roundtrip() {
        let du: DeploymentUpdate = serde_json::from_value(json!({
            "version": 3,
            "startTime": 1709_280_000,
            "endTime": 1709_280_120,
            "result": "succeeded",
            "kind": "update",
            "message": "Updating stack",
            "resourceChanges": {"create": 2, "update": 1},
        }))
        .unwrap();
        assert_eq!(du.version, Some(3));
        assert_eq!(du.result, Some("succeeded".into()));
        assert_eq!(du.kind, Some("update".into()));
        assert_eq!(du.message, Some("Updating stack".into()));
        let re = serde_json::to_value(&du).unwrap();
        assert_eq!(re["result"], "succeeded");
    }

    #[test]
    fn deployment_update_minimal() {
        let du: DeploymentUpdate = serde_json::from_value(json!({})).unwrap();
        assert!(du.version.is_none());
        assert!(du.start_time.is_none());
        assert!(du.end_time.is_none());
        assert!(du.result.is_none());
        assert!(du.kind.is_none());
        assert!(du.message.is_none());
    }

    #[test]
    fn deployment_update_with_environment() {
        let du: DeploymentUpdate = serde_json::from_value(json!({
            "environment": {"AWS_REGION": "us-west-2"},
        }))
        .unwrap();
        let env = du.environment.unwrap();
        assert_eq!(env["AWS_REGION"], "us-west-2");
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "code": 404,
            "message": "not found",
        }))
        .unwrap();
        assert_eq!(e.message, Some("not found".into()));
        assert_eq!(e.code, Some(404));
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
            "message": "internal server error",
        }))
        .unwrap();
        assert_eq!(e.message, Some("internal server error".into()));
        assert!(e.code.is_none());
    }

    #[test]
    fn stack_serializes_camel_case() {
        let s = Stack {
            org_name: "o".into(),
            project_name: "p".into(),
            stack_name: "s".into(),
            active_update: None,
            tags: None,
            version: Some(1),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("orgName").is_some());
        assert!(v.get("projectName").is_some());
        assert!(v.get("stackName").is_some());
        assert!(v.get("org_name").is_none());
    }

    #[test]
    fn stack_summary_serializes_camel_case() {
        let ss = StackSummary {
            org_name: "o".into(),
            project_name: "p".into(),
            stack_name: "s".into(),
            last_update: Some(123),
            resource_count: None,
        };
        let v = serde_json::to_value(&ss).unwrap();
        assert!(v.get("orgName").is_some());
        assert!(v.get("lastUpdate").is_some());
        assert!(v.get("org_name").is_none());
    }

    #[test]
    fn deployment_update_serializes_camel_case() {
        let du = DeploymentUpdate {
            version: Some(1),
            start_time: Some(100),
            end_time: None,
            result: None,
            kind: None,
            message: None,
            environment: None,
            resource_changes: None,
        };
        let v = serde_json::to_value(&du).unwrap();
        assert!(v.get("startTime").is_some());
        assert!(v.get("start_time").is_none());
    }
}
