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
            "lastUpdate": 1_709_280_000,
            "resourceCount": 15,
        }))
        .unwrap();
        assert_eq!(ss.org_name, "myorg");
        assert_eq!(ss.stack_name, "dev");
        assert_eq!(ss.last_update, Some(1_709_280_000));
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
            "startTime": 1_709_280_000,
            "endTime": 1_709_280_120,
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

    // ── Clone trait tests ───────────────────────────────────────

    #[test]
    fn stack_clone() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "version": 5
        }))
        .unwrap();
        let c = s.clone();
        assert_eq!(c.org_name, s.org_name);
        assert_eq!(c.version, s.version);
    }

    #[test]
    fn stack_summary_clone() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "resourceCount": 10
        }))
        .unwrap();
        let c = ss.clone();
        assert_eq!(c.resource_count, ss.resource_count);
    }

    #[test]
    fn deployment_update_clone() {
        let du: DeploymentUpdate = serde_json::from_value(json!({
            "version": 3, "result": "succeeded", "kind": "update"
        }))
        .unwrap();
        let c = du.clone();
        assert_eq!(c.version, du.version);
        assert_eq!(c.result, du.result);
    }

    // ── Debug trait tests ───────────────────────────────────────

    #[test]
    fn stack_debug() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s"
        }))
        .unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Stack"));
    }

    #[test]
    fn stack_summary_debug() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s"
        }))
        .unwrap();
        let dbg = format!("{ss:?}");
        assert!(dbg.contains("StackSummary"));
    }

    #[test]
    fn deployment_update_debug() {
        let du: DeploymentUpdate = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{du:?}");
        assert!(dbg.contains("DeploymentUpdate"));
    }

    // ── Serialize roundtrip tests ───────────────────────────────

    #[test]
    fn stack_serialize_roundtrip() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "myorg", "projectName": "proj1", "stackName": "prod",
            "activeUpdate": "up1", "tags": {"env": "prod"}, "version": 42
        }))
        .unwrap();
        let serialized = serde_json::to_value(&s).unwrap();
        let back: Stack = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.org_name, "myorg");
        assert_eq!(back.active_update, Some("up1".into()));
        assert_eq!(back.version, Some(42));
    }

    #[test]
    fn stack_summary_serialize_roundtrip() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "dev",
            "lastUpdate": 999, "resourceCount": 25
        }))
        .unwrap();
        let serialized = serde_json::to_value(&ss).unwrap();
        let back: StackSummary = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.last_update, Some(999));
        assert_eq!(back.resource_count, Some(25));
    }

    #[test]
    fn deployment_update_serialize_roundtrip() {
        let du: DeploymentUpdate = serde_json::from_value(json!({
            "version": 7, "startTime": 100, "endTime": 200,
            "result": "failed", "kind": "destroy",
            "message": "Destroying resources",
            "environment": {"PULUMI_CI": "true"},
            "resourceChanges": {"delete": 5}
        }))
        .unwrap();
        let serialized = serde_json::to_value(&du).unwrap();
        let back: DeploymentUpdate = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.version, Some(7));
        assert_eq!(back.result, Some("failed".into()));
        assert_eq!(back.kind, Some("destroy".into()));
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn stack_empty_strings() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "", "projectName": "", "stackName": ""
        }))
        .unwrap();
        assert_eq!(s.org_name, "");
        assert_eq!(s.project_name, "");
        assert_eq!(s.stack_name, "");
    }

    #[test]
    fn stack_version_zero() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "version": 0
        }))
        .unwrap();
        assert_eq!(s.version, Some(0));
    }

    #[test]
    fn stack_version_large() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "version": u64::MAX
        }))
        .unwrap();
        assert_eq!(s.version, Some(u64::MAX));
    }

    #[test]
    fn stack_tags_array() {
        // tags is serde_json::Value so it can be any shape
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "tags": ["a", "b"]
        }))
        .unwrap();
        assert!(s.tags.unwrap().is_array());
    }

    #[test]
    fn stack_summary_resource_count_zero() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "resourceCount": 0
        }))
        .unwrap();
        assert_eq!(ss.resource_count, Some(0));
    }

    #[test]
    fn deployment_update_all_none() {
        let du: DeploymentUpdate = serde_json::from_value(json!({})).unwrap();
        assert!(du.version.is_none());
        assert!(du.start_time.is_none());
        assert!(du.end_time.is_none());
        assert!(du.result.is_none());
        assert!(du.kind.is_none());
        assert!(du.message.is_none());
        assert!(du.environment.is_none());
        assert!(du.resource_changes.is_none());
    }

    #[test]
    fn deployment_update_result_values() {
        for result_val in &["succeeded", "failed", "in-progress"] {
            let du: DeploymentUpdate = serde_json::from_value(json!({
                "result": result_val
            }))
            .unwrap();
            assert_eq!(du.result.as_deref(), Some(*result_val));
        }
    }

    #[test]
    fn deployment_update_kind_values() {
        for kind_val in &["update", "preview", "destroy", "refresh", "import"] {
            let du: DeploymentUpdate = serde_json::from_value(json!({
                "kind": kind_val
            }))
            .unwrap();
            assert_eq!(du.kind.as_deref(), Some(*kind_val));
        }
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "code": 500, "message": "internal"
        }))
        .unwrap();
        let c = e.clone();
        assert_eq!(c.code, e.code);
        assert_eq!(c.message, e.message);
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "test"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn stack_active_update_default() {
        // active_update has #[serde(default)] so it defaults to None
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s"
        }))
        .unwrap();
        assert!(s.active_update.is_none());
    }

    #[test]
    fn stack_tags_default() {
        // tags has #[serde(default)] so it defaults to None
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s"
        }))
        .unwrap();
        assert!(s.tags.is_none());
    }

    // ── Additional type coverage tests ────────────────────────────

    #[test]
    fn stack_tags_null_value() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "tags": null
        }))
        .unwrap();
        assert!(s.tags.is_none());
    }

    #[test]
    fn stack_tags_nested_object() {
        let s: Stack = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "tags": {"env": {"sub": "value"}, "region": "us-west"}
        }))
        .unwrap();
        let tags = s.tags.unwrap();
        assert_eq!(tags["env"]["sub"], "value");
    }

    #[test]
    fn stack_summary_last_update_zero() {
        let ss: StackSummary = serde_json::from_value(json!({
            "orgName": "o", "projectName": "p", "stackName": "s",
            "lastUpdate": 0
        }))
        .unwrap();
        assert_eq!(ss.last_update, Some(0));
    }

    #[test]
    fn deployment_update_resource_changes_complex() {
        let du: DeploymentUpdate = serde_json::from_value(json!({
            "resourceChanges": {"create": 3, "update": 2, "delete": 1, "same": 10}
        }))
        .unwrap();
        let rc = du.resource_changes.unwrap();
        assert_eq!(rc["create"], 3);
        assert_eq!(rc["same"], 10);
    }

    #[test]
    fn deployment_update_start_end_times() {
        let du: DeploymentUpdate = serde_json::from_value(json!({
            "startTime": 1000, "endTime": 2000
        }))
        .unwrap();
        assert_eq!(du.start_time, Some(1000));
        assert_eq!(du.end_time, Some(2000));
    }

    #[test]
    fn api_error_response_code_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"code": 401})).unwrap();
        assert_eq!(e.code, Some(401));
        assert!(e.message.is_none());
    }
}
