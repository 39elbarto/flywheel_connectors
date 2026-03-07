//! Terraform Cloud API types.

use serde::{Deserialize, Serialize};

/// A Terraform Cloud workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub terraform_version: Option<String>,
    #[serde(rename = "auto-apply")]
    pub auto_apply: Option<bool>,
    #[serde(rename = "working-directory")]
    pub working_directory: Option<String>,
    #[serde(rename = "resource-count")]
    pub resource_count: Option<u64>,
    #[serde(rename = "updated-at")]
    pub updated_at: Option<String>,
}

/// A Terraform Cloud run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    pub status: Option<String>,
    pub message: Option<String>,
    #[serde(rename = "has-changes")]
    pub has_changes: Option<bool>,
    #[serde(rename = "is-destroy")]
    pub is_destroy: Option<bool>,
    #[serde(rename = "created-at")]
    pub created_at: Option<String>,
    #[serde(rename = "plan-only")]
    pub plan_only: Option<bool>,
    #[serde(rename = "auto-apply")]
    pub auto_apply: Option<bool>,
}

/// A Terraform Cloud plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub status: Option<String>,
    #[serde(rename = "has-changes")]
    pub has_changes: Option<bool>,
    #[serde(rename = "resource-additions")]
    pub resource_additions: Option<u64>,
    #[serde(rename = "resource-changes")]
    pub resource_changes: Option<u64>,
    #[serde(rename = "resource-destructions")]
    pub resource_destructions: Option<u64>,
    #[serde(rename = "log-read-url")]
    pub log_read_url: Option<String>,
}

/// A Terraform Cloud state version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateVersion {
    pub id: String,
    pub serial: Option<u64>,
    #[serde(rename = "terraform-version")]
    pub terraform_version: Option<String>,
    #[serde(rename = "created-at")]
    pub created_at: Option<String>,
    #[serde(rename = "resources-processed")]
    pub resources_processed: Option<bool>,
}

/// A Terraform state resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateResource {
    pub address: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub module: Option<String>,
    pub provider: Option<String>,
}

/// A Terraform Cloud configuration version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationVersion {
    pub id: String,
    pub status: Option<String>,
    pub source: Option<String>,
    #[serde(rename = "upload-url")]
    pub upload_url: Option<String>,
}

/// A Terraform module reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRef {
    pub source: Option<String>,
    pub version: Option<String>,
    pub key: Option<String>,
}

/// A Terraform output value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputValue {
    pub name: Option<String>,
    pub value: Option<serde_json::Value>,
    pub sensitive: Option<bool>,
    #[serde(rename = "type")]
    pub output_type: Option<String>,
}

/// A resource change descriptor from a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChange {
    pub address: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub actions: Option<Vec<String>>,
    pub name: Option<String>,
    pub module: Option<String>,
}

/// A validation diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Option<String>,
    pub summary: Option<String>,
    pub detail: Option<String>,
}

/// A drift resource descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftResource {
    pub address: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub change_type: Option<String>,
}

/// Terraform Cloud API error response body.
///
/// Terraform Cloud returns `{"errors": [{"status": "...", "title": "...", "detail": "..."}]}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub errors: Option<Vec<ApiError>>,
}

/// Individual error entry in a Terraform Cloud API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    pub status: Option<String>,
    pub title: Option<String>,
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workspace_roundtrip() {
        let w: Workspace = serde_json::from_value(json!({
            "id": "ws-abc123",
            "name": "my-workspace",
            "description": "Production infrastructure",
            "terraform_version": "1.7.0",
            "auto-apply": true,
            "working-directory": "/infra",
            "resource-count": 42,
            "updated-at": "2026-03-01T12:00:00Z",
        }))
        .unwrap();
        assert_eq!(w.id, "ws-abc123");
        assert_eq!(w.name, Some("my-workspace".into()));
        assert_eq!(w.description, Some("Production infrastructure".into()));
        assert_eq!(w.terraform_version, Some("1.7.0".into()));
        assert_eq!(w.auto_apply, Some(true));
        assert_eq!(w.working_directory, Some("/infra".into()));
        assert_eq!(w.resource_count, Some(42));
        let re = serde_json::to_value(&w).unwrap();
        assert_eq!(re["name"], "my-workspace");
    }

    #[test]
    fn workspace_minimal() {
        let w: Workspace = serde_json::from_value(json!({"id": "ws-x"})).unwrap();
        assert_eq!(w.id, "ws-x");
        assert!(w.name.is_none());
        assert!(w.description.is_none());
        assert!(w.terraform_version.is_none());
        assert!(w.auto_apply.is_none());
    }

    #[test]
    fn run_roundtrip() {
        let r: Run = serde_json::from_value(json!({
            "id": "run-abc123",
            "status": "planned",
            "message": "Queued manually",
            "has-changes": true,
            "is-destroy": false,
            "created-at": "2026-03-01T12:00:00Z",
            "plan-only": false,
            "auto-apply": false,
        }))
        .unwrap();
        assert_eq!(r.id, "run-abc123");
        assert_eq!(r.status, Some("planned".into()));
        assert_eq!(r.has_changes, Some(true));
        assert_eq!(r.is_destroy, Some(false));
        assert_eq!(r.plan_only, Some(false));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["status"], "planned");
    }

    #[test]
    fn run_minimal() {
        let r: Run = serde_json::from_value(json!({"id": "run-x"})).unwrap();
        assert_eq!(r.id, "run-x");
        assert!(r.status.is_none());
        assert!(r.has_changes.is_none());
    }

    #[test]
    fn plan_roundtrip() {
        let p: Plan = serde_json::from_value(json!({
            "id": "plan-abc123",
            "status": "finished",
            "has-changes": true,
            "resource-additions": 3,
            "resource-changes": 1,
            "resource-destructions": 0,
            "log-read-url": "https://archivist.terraform.io/v1/object/123",
        }))
        .unwrap();
        assert_eq!(p.id, "plan-abc123");
        assert_eq!(p.status, Some("finished".into()));
        assert_eq!(p.has_changes, Some(true));
        assert_eq!(p.resource_additions, Some(3));
        assert_eq!(p.resource_changes, Some(1));
        assert_eq!(p.resource_destructions, Some(0));
    }

    #[test]
    fn plan_minimal() {
        let p: Plan = serde_json::from_value(json!({"id": "plan-x"})).unwrap();
        assert_eq!(p.id, "plan-x");
        assert!(p.status.is_none());
        assert!(p.resource_additions.is_none());
    }

    #[test]
    fn state_version_roundtrip() {
        let sv: StateVersion = serde_json::from_value(json!({
            "id": "sv-abc123",
            "serial": 5,
            "terraform-version": "1.7.0",
            "created-at": "2026-03-01T12:00:00Z",
            "resources-processed": true,
        }))
        .unwrap();
        assert_eq!(sv.id, "sv-abc123");
        assert_eq!(sv.serial, Some(5));
        assert_eq!(sv.terraform_version, Some("1.7.0".into()));
        assert_eq!(sv.resources_processed, Some(true));
    }

    #[test]
    fn state_version_minimal() {
        let sv: StateVersion = serde_json::from_value(json!({"id": "sv-x"})).unwrap();
        assert_eq!(sv.id, "sv-x");
        assert!(sv.serial.is_none());
    }

    #[test]
    fn state_resource_roundtrip() {
        let sr: StateResource = serde_json::from_value(json!({
            "address": "aws_instance.web",
            "name": "web",
            "type": "aws_instance",
            "module": "module.vpc",
            "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
        }))
        .unwrap();
        assert_eq!(sr.address, Some("aws_instance.web".into()));
        assert_eq!(sr.name, Some("web".into()));
        assert_eq!(sr.resource_type, Some("aws_instance".into()));
        assert_eq!(sr.module, Some("module.vpc".into()));
    }

    #[test]
    fn state_resource_minimal() {
        let sr: StateResource = serde_json::from_value(json!({})).unwrap();
        assert!(sr.address.is_none());
        assert!(sr.name.is_none());
        assert!(sr.resource_type.is_none());
    }

    #[test]
    fn configuration_version_roundtrip() {
        let cv: ConfigurationVersion = serde_json::from_value(json!({
            "id": "cv-abc123",
            "status": "uploaded",
            "source": "tfe-api",
            "upload-url": "https://archivist.terraform.io/v1/upload/123",
        }))
        .unwrap();
        assert_eq!(cv.id, "cv-abc123");
        assert_eq!(cv.status, Some("uploaded".into()));
        assert_eq!(cv.source, Some("tfe-api".into()));
    }

    #[test]
    fn module_ref_roundtrip() {
        let m: ModuleRef = serde_json::from_value(json!({
            "source": "hashicorp/consul/aws",
            "version": "0.1.0",
            "key": "consul",
        }))
        .unwrap();
        assert_eq!(m.source, Some("hashicorp/consul/aws".into()));
        assert_eq!(m.version, Some("0.1.0".into()));
        assert_eq!(m.key, Some("consul".into()));
    }

    #[test]
    fn module_ref_minimal() {
        let m: ModuleRef = serde_json::from_value(json!({})).unwrap();
        assert!(m.source.is_none());
        assert!(m.version.is_none());
    }

    #[test]
    fn output_value_roundtrip() {
        let o: OutputValue = serde_json::from_value(json!({
            "name": "api_endpoint",
            "value": "https://api.example.com",
            "sensitive": false,
            "type": "string",
        }))
        .unwrap();
        assert_eq!(o.name, Some("api_endpoint".into()));
        assert_eq!(o.sensitive, Some(false));
        assert_eq!(o.output_type, Some("string".into()));
    }

    #[test]
    fn output_value_sensitive() {
        let o: OutputValue = serde_json::from_value(json!({
            "name": "db_password",
            "value": null,
            "sensitive": true,
            "type": "string",
        }))
        .unwrap();
        assert_eq!(o.sensitive, Some(true));
    }

    #[test]
    fn resource_change_roundtrip() {
        let rc: ResourceChange = serde_json::from_value(json!({
            "address": "aws_instance.web",
            "type": "aws_instance",
            "actions": ["create"],
            "name": "web",
            "module": null,
        }))
        .unwrap();
        assert_eq!(rc.address, Some("aws_instance.web".into()));
        assert_eq!(rc.resource_type, Some("aws_instance".into()));
        assert_eq!(rc.actions, Some(vec!["create".to_string()]));
    }

    #[test]
    fn resource_change_multiple_actions() {
        let rc: ResourceChange = serde_json::from_value(json!({
            "address": "aws_instance.web",
            "type": "aws_instance",
            "actions": ["delete", "create"],
            "name": "web",
        }))
        .unwrap();
        assert_eq!(rc.actions.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn diagnostic_roundtrip() {
        let d: Diagnostic = serde_json::from_value(json!({
            "severity": "error",
            "summary": "Missing required argument",
            "detail": "The argument \"region\" is required.",
        }))
        .unwrap();
        assert_eq!(d.severity, Some("error".into()));
        assert_eq!(d.summary, Some("Missing required argument".into()));
    }

    #[test]
    fn diagnostic_warning() {
        let d: Diagnostic = serde_json::from_value(json!({
            "severity": "warning",
            "summary": "Deprecated argument",
        }))
        .unwrap();
        assert_eq!(d.severity, Some("warning".into()));
        assert!(d.detail.is_none());
    }

    #[test]
    fn drift_resource_roundtrip() {
        let dr: DriftResource = serde_json::from_value(json!({
            "address": "aws_instance.web",
            "type": "aws_instance",
            "change_type": "update",
        }))
        .unwrap();
        assert_eq!(dr.address, Some("aws_instance.web".into()));
        assert_eq!(dr.resource_type, Some("aws_instance".into()));
        assert_eq!(dr.change_type, Some("update".into()));
    }

    #[test]
    fn api_error_response_with_errors() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [{
                "status": "404",
                "title": "not found",
                "detail": "Workspace not found",
            }]
        }))
        .unwrap();
        let errors = e.errors.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].status, Some("404".into()));
        assert_eq!(errors[0].title, Some("not found".into()));
        assert_eq!(errors[0].detail, Some("Workspace not found".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.errors.is_none());
    }

    #[test]
    fn api_error_response_multiple_errors() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [
                {"status": "422", "title": "invalid", "detail": "Name is required"},
                {"status": "422", "title": "invalid", "detail": "Version must be set"},
            ]
        }))
        .unwrap();
        assert_eq!(e.errors.unwrap().len(), 2);
    }

    #[test]
    fn workspace_extra_fields_ignored() {
        let w: Workspace = serde_json::from_value(json!({
            "id": "ws-1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(w.id, "ws-1");
        assert_eq!(w.name, Some("Test".into()));
    }

    #[test]
    fn run_extra_fields_ignored() {
        let r: Run = serde_json::from_value(json!({
            "id": "run-1",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(r.id, "run-1");
    }

    #[test]
    fn plan_extra_fields_ignored() {
        let p: Plan = serde_json::from_value(json!({
            "id": "plan-1",
            "extra": true,
        }))
        .unwrap();
        assert_eq!(p.id, "plan-1");
    }

    #[test]
    fn workspace_serialize_roundtrip() {
        let w = Workspace {
            id: "ws-1".into(),
            name: Some("prod".into()),
            description: None,
            terraform_version: Some("1.7.0".into()),
            auto_apply: Some(false),
            working_directory: None,
            resource_count: Some(10),
            updated_at: None,
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["id"], "ws-1");
        assert_eq!(v["name"], "prod");
        assert_eq!(v["auto-apply"], false);
        assert_eq!(v["resource-count"], 10);
    }

    #[test]
    fn run_serialize_roundtrip() {
        let r = Run {
            id: "run-1".into(),
            status: Some("applied".into()),
            message: Some("Apply complete".into()),
            has_changes: Some(true),
            is_destroy: Some(false),
            created_at: None,
            plan_only: Some(false),
            auto_apply: Some(true),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["id"], "run-1");
        assert_eq!(v["status"], "applied");
        assert_eq!(v["has-changes"], true);
    }

    #[test]
    fn plan_serialize_roundtrip() {
        let p = Plan {
            id: "plan-1".into(),
            status: Some("finished".into()),
            has_changes: Some(true),
            resource_additions: Some(2),
            resource_changes: Some(1),
            resource_destructions: Some(0),
            log_read_url: Some("https://example.com/log".into()),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["id"], "plan-1");
        assert_eq!(v["resource-additions"], 2);
    }

    // -- Clone trait tests --

    #[test]
    fn workspace_clone() {
        let w = Workspace {
            id: "ws-1".into(),
            name: Some("prod".into()),
            description: None,
            terraform_version: Some("1.7.0".into()),
            auto_apply: Some(false),
            working_directory: None,
            resource_count: Some(10),
            updated_at: None,
        };
        let cloned = w.clone();
        drop(w);
        assert_eq!(cloned.id, "ws-1");
        assert_eq!(cloned.name, Some("prod".into()));
    }

    #[test]
    fn run_clone() {
        let r = Run {
            id: "run-1".into(),
            status: Some("applied".into()),
            message: None,
            has_changes: Some(true),
            is_destroy: Some(false),
            created_at: None,
            plan_only: Some(false),
            auto_apply: None,
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.id, "run-1");
        assert_eq!(cloned.has_changes, Some(true));
    }

    #[test]
    fn plan_clone() {
        let p = Plan {
            id: "plan-1".into(),
            status: Some("finished".into()),
            has_changes: None,
            resource_additions: Some(3),
            resource_changes: None,
            resource_destructions: None,
            log_read_url: None,
        };
        let cloned = p.clone();
        drop(p);
        assert_eq!(cloned.id, "plan-1");
        assert_eq!(cloned.resource_additions, Some(3));
    }

    #[test]
    fn state_version_clone() {
        let sv = StateVersion {
            id: "sv-1".into(),
            serial: Some(1),
            terraform_version: None,
            created_at: None,
            resources_processed: Some(true),
        };
        let cloned = sv.clone();
        drop(sv);
        assert_eq!(cloned.id, "sv-1");
    }

    #[test]
    fn state_resource_clone() {
        let sr = StateResource {
            address: Some("aws_instance.web".into()),
            name: Some("web".into()),
            resource_type: Some("aws_instance".into()),
            module: None,
            provider: None,
        };
        let cloned = sr.clone();
        drop(sr);
        assert_eq!(cloned.address, Some("aws_instance.web".into()));
    }

    #[test]
    fn configuration_version_clone() {
        let cv = ConfigurationVersion {
            id: "cv-1".into(),
            status: Some("uploaded".into()),
            source: None,
            upload_url: None,
        };
        let cloned = cv.clone();
        drop(cv);
        assert_eq!(cloned.id, "cv-1");
    }

    #[test]
    fn module_ref_clone() {
        let m = ModuleRef {
            source: Some("hashicorp/consul/aws".into()),
            version: Some("0.1.0".into()),
            key: None,
        };
        let cloned = m.clone();
        drop(m);
        assert_eq!(cloned.source, Some("hashicorp/consul/aws".into()));
    }

    #[test]
    fn output_value_clone() {
        let o = OutputValue {
            name: Some("endpoint".into()),
            value: Some(json!("https://api.example.com")),
            sensitive: Some(false),
            output_type: Some("string".into()),
        };
        let cloned = o.clone();
        drop(o);
        assert_eq!(cloned.name, Some("endpoint".into()));
    }

    #[test]
    fn resource_change_clone() {
        let rc = ResourceChange {
            address: Some("aws_instance.web".into()),
            resource_type: Some("aws_instance".into()),
            actions: Some(vec!["create".into()]),
            name: None,
            module: None,
        };
        let cloned = rc.clone();
        drop(rc);
        assert_eq!(cloned.actions.unwrap().len(), 1);
    }

    #[test]
    fn diagnostic_clone() {
        let d = Diagnostic {
            severity: Some("error".into()),
            summary: Some("Missing".into()),
            detail: None,
        };
        let cloned = d.clone();
        drop(d);
        assert_eq!(cloned.severity, Some("error".into()));
    }

    #[test]
    fn drift_resource_clone() {
        let dr = DriftResource {
            address: Some("aws_instance.web".into()),
            resource_type: None,
            change_type: Some("update".into()),
        };
        let cloned = dr.clone();
        drop(dr);
        assert_eq!(cloned.change_type, Some("update".into()));
    }

    // -- Debug trait tests --

    #[test]
    fn workspace_debug() {
        let w: Workspace = serde_json::from_value(json!({"id": "ws-dbg"})).unwrap();
        let dbg = format!("{w:?}");
        assert!(dbg.contains("Workspace"));
        assert!(dbg.contains("ws-dbg"));
    }

    #[test]
    fn run_debug() {
        let r: Run = serde_json::from_value(json!({"id": "run-dbg"})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Run"));
    }

    #[test]
    fn plan_debug() {
        let p: Plan = serde_json::from_value(json!({"id": "plan-dbg"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Plan"));
    }

    #[test]
    fn state_version_debug() {
        let sv: StateVersion = serde_json::from_value(json!({"id": "sv-dbg"})).unwrap();
        let dbg = format!("{sv:?}");
        assert!(dbg.contains("StateVersion"));
    }

    #[test]
    fn configuration_version_minimal() {
        let cv: ConfigurationVersion = serde_json::from_value(json!({"id": "cv-x"})).unwrap();
        assert_eq!(cv.id, "cv-x");
        assert!(cv.status.is_none());
        assert!(cv.upload_url.is_none());
    }

    #[test]
    fn output_value_minimal() {
        let o: OutputValue = serde_json::from_value(json!({})).unwrap();
        assert!(o.name.is_none());
        assert!(o.value.is_none());
        assert!(o.sensitive.is_none());
    }

    #[test]
    fn resource_change_minimal() {
        let rc: ResourceChange = serde_json::from_value(json!({})).unwrap();
        assert!(rc.address.is_none());
        assert!(rc.actions.is_none());
    }

    #[test]
    fn diagnostic_minimal() {
        let d: Diagnostic = serde_json::from_value(json!({})).unwrap();
        assert!(d.severity.is_none());
        assert!(d.summary.is_none());
        assert!(d.detail.is_none());
    }

    #[test]
    fn drift_resource_minimal() {
        let dr: DriftResource = serde_json::from_value(json!({})).unwrap();
        assert!(dr.address.is_none());
        assert!(dr.resource_type.is_none());
        assert!(dr.change_type.is_none());
    }

    #[test]
    fn state_version_serialize_roundtrip() {
        let sv = StateVersion {
            id: "sv-1".into(),
            serial: Some(5),
            terraform_version: Some("1.7.0".into()),
            created_at: None,
            resources_processed: Some(true),
        };
        let v = serde_json::to_value(&sv).unwrap();
        assert_eq!(v["id"], "sv-1");
        assert_eq!(v["serial"], 5);
    }
}
