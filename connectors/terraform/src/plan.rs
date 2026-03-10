//! Terraform plan generation and review (read-only).
//!
//! Parses the JSON output of `terraform show -json planfile` into structured
//! types, computes plan summaries, detects destructive changes, and renders
//! plans as human-readable text or machine-readable JSON.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{DefaultHasher, Hash, Hasher};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Core enums
// ---------------------------------------------------------------------------

/// Action that Terraform will take on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    Create,
    Update,
    Delete,
    NoOp,
    Read,
    Replace,
}

impl std::fmt::Display for PlanAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => f.write_str("create"),
            Self::Update => f.write_str("update"),
            Self::Delete => f.write_str("delete"),
            Self::NoOp => f.write_str("no-op"),
            Self::Read => f.write_str("read"),
            Self::Replace => f.write_str("replace"),
        }
    }
}

/// Severity level for a plan diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
}

impl std::fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => f.write_str("error"),
            Self::Warning => f.write_str("warning"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single resource change within a Terraform plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceChange {
    /// The full address of the resource, e.g. `aws_instance.web`.
    pub address: String,
    /// The action Terraform will take.
    pub action: PlanAction,
    /// The Terraform resource type, e.g. `aws_instance`.
    pub resource_type: String,
    /// The state of the resource before the plan is applied.
    pub before: Option<Value>,
    /// The planned state of the resource after the plan is applied.
    pub after: Option<Value>,
    /// Keys in `after` whose values are not yet known.
    pub after_unknown: Option<Value>,
}

/// A change to a Terraform output value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputChange {
    /// The output name.
    pub name: String,
    /// The action Terraform will take.
    pub action: PlanAction,
    /// The value before the plan is applied.
    pub before: Option<Value>,
    /// The value after the plan is applied.
    pub after: Option<Value>,
    /// Whether the output is marked as sensitive.
    pub sensitive: bool,
}

/// A summary of the counts within a Terraform plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSummary {
    /// Number of resources to add.
    pub adds: usize,
    /// Number of resources to change (update).
    pub changes: usize,
    /// Number of resources to destroy (delete or replace).
    pub destroys: usize,
    /// Number of resources with no changes.
    pub no_ops: usize,
    /// Total number of resource changes in the plan.
    pub total: usize,
}

/// A parsed Terraform plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerraformPlan {
    /// SHA-256 style integrity hash of the plan JSON (using `DefaultHasher`).
    plan_hash: String,
    /// The format version of the plan output (e.g. `"1.2"`).
    pub format_version: String,
    /// The Terraform version that created the plan.
    pub terraform_version: String,
    /// Resource changes within the plan.
    pub resource_changes: Vec<ResourceChange>,
    /// Output changes within the plan.
    pub output_changes: Vec<OutputChange>,
    /// Provider versions used in the plan.
    pub provider_versions: HashMap<String, String>,
}

/// A diagnostic emitted during plan validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDiagnostic {
    /// The severity of the diagnostic.
    pub severity: DiagnosticSeverity,
    /// A brief summary of the diagnostic.
    pub summary: String,
    /// Optional detailed description.
    pub detail: Option<String>,
    /// Optional source range (as a string).
    pub range: Option<String>,
}

/// Result of `terraform validate` parsed into structured data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanValidation {
    /// Whether the configuration is valid.
    pub valid: bool,
    /// Number of error diagnostics.
    pub error_count: usize,
    /// Number of warning diagnostics.
    pub warning_count: usize,
    /// All diagnostics.
    pub diagnostics: Vec<PlanDiagnostic>,
}

/// Renders a `TerraformPlan` to text or JSON.
pub struct PlanRenderer;

// ---------------------------------------------------------------------------
// Helper: deterministic hash
// ---------------------------------------------------------------------------

/// Compute a deterministic hash of the plan JSON using `DefaultHasher`.
///
/// The JSON value is serialized to a canonical string (via `to_string`) and
/// then hashed. The result is returned as a hex-encoded string.
pub fn compute_plan_hash(plan_json: &Value) -> String {
    let mut hasher = DefaultHasher::new();
    plan_json.to_string().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// Helper: resolve action from actions array
// ---------------------------------------------------------------------------

fn resolve_action(actions: &[Value]) -> PlanAction {
    if actions.len() == 2 {
        let a = actions[0].as_str().unwrap_or_default();
        let b = actions[1].as_str().unwrap_or_default();
        if (a == "delete" && b == "create") || (a == "create" && b == "delete") {
            return PlanAction::Replace;
        }
    }
    if actions.len() == 1 {
        if let Some(s) = actions[0].as_str() {
            return match s {
                "create" => PlanAction::Create,
                "update" => PlanAction::Update,
                "delete" => PlanAction::Delete,
                "no-op" => PlanAction::NoOp,
                "read" => PlanAction::Read,
                _ => PlanAction::NoOp,
            };
        }
    }
    PlanAction::NoOp
}

// ---------------------------------------------------------------------------
// TerraformPlan
// ---------------------------------------------------------------------------

impl TerraformPlan {
    /// Parse a `TerraformPlan` from the JSON output of `terraform show -json`.
    pub fn from_json(plan_json: &Value) -> Result<Self, String> {
        let format_version = plan_json
            .get("format_version")
            .and_then(Value::as_str)
            .unwrap_or("0.0")
            .to_owned();

        let terraform_version = plan_json
            .get("terraform_version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();

        // Parse resource_changes
        let resource_changes = if let Some(arr) =
            plan_json.get("resource_changes").and_then(Value::as_array)
        {
            let mut changes = Vec::with_capacity(arr.len());
            for item in arr {
                let address = item
                    .get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "resource_changes[].address is required".to_owned())?
                    .to_owned();

                let resource_type = item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();

                let change = item.get("change").ok_or_else(|| {
                    format!("resource_changes[].change is required for {address}")
                })?;

                let actions = change
                    .get("actions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        format!("resource_changes[].change.actions is required for {address}")
                    })?;

                let action = resolve_action(actions);

                let before = change.get("before").cloned().filter(|v| !v.is_null());
                let after = change.get("after").cloned().filter(|v| !v.is_null());
                let after_unknown = change
                    .get("after_unknown")
                    .cloned()
                    .filter(|v| !v.is_null());

                changes.push(ResourceChange {
                    address,
                    action,
                    resource_type,
                    before,
                    after,
                    after_unknown,
                });
            }
            changes
        } else {
            Vec::new()
        };

        // Parse output_changes
        let output_changes =
            if let Some(obj) = plan_json.get("output_changes").and_then(Value::as_object) {
                let mut outputs = Vec::with_capacity(obj.len());
                for (name, val) in obj {
                    let actions = val
                        .get("actions")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let action = resolve_action(&actions);
                    let before = val.get("before").cloned().filter(|v| !v.is_null());
                    let after = val.get("after").cloned().filter(|v| !v.is_null());
                    let sensitive = val
                        .get("after_sensitive")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);

                    outputs.push(OutputChange {
                        name: name.clone(),
                        action,
                        before,
                        after,
                        sensitive,
                    });
                }
                // Sort by name for determinism
                outputs.sort_by(|a, b| a.name.cmp(&b.name));
                outputs
            } else {
                Vec::new()
            };

        // Parse provider_versions (optional; terraform plan JSON may include
        // configuration.provider_config with version constraints)
        let provider_versions = if let Some(obj) = plan_json
            .get("provider_versions")
            .and_then(Value::as_object)
        {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        } else {
            HashMap::new()
        };

        let plan_hash = compute_plan_hash(plan_json);

        Ok(Self {
            plan_hash,
            format_version,
            terraform_version,
            resource_changes,
            output_changes,
            provider_versions,
        })
    }

    /// Compute a summary of add/change/destroy counts.
    #[must_use]
    pub fn summary(&self) -> PlanSummary {
        let mut adds = 0usize;
        let mut changes = 0usize;
        let mut destroys = 0usize;
        let mut no_ops = 0usize;
        for rc in &self.resource_changes {
            match rc.action {
                PlanAction::Create => adds += 1,
                PlanAction::Update => changes += 1,
                PlanAction::Delete | PlanAction::Replace => destroys += 1,
                PlanAction::NoOp | PlanAction::Read => no_ops += 1,
            }
        }
        let total = self.resource_changes.len();
        PlanSummary {
            adds,
            changes,
            destroys,
            no_ops,
            total,
        }
    }

    /// Filter resource changes by Terraform resource type (e.g. `aws_instance`).
    #[must_use]
    pub fn changes_for_type(&self, resource_type: &str) -> Vec<&ResourceChange> {
        self.resource_changes
            .iter()
            .filter(|rc| rc.resource_type == resource_type)
            .collect()
    }

    /// Return `true` if the plan contains any delete or replace actions.
    #[must_use]
    pub fn has_destructive_changes(&self) -> bool {
        self.resource_changes
            .iter()
            .any(|rc| matches!(rc.action, PlanAction::Delete | PlanAction::Replace))
    }

    /// The integrity hash of the plan JSON.
    #[must_use]
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
}

// ---------------------------------------------------------------------------
// PlanValidation
// ---------------------------------------------------------------------------

impl PlanValidation {
    /// Parse a `PlanValidation` from the JSON output of `terraform validate -json`.
    pub fn from_json(validate_json: &Value) -> Result<Self, String> {
        let valid = validate_json
            .get("valid")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let error_count = validate_json
            .get("error_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;

        let warning_count = validate_json
            .get("warning_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;

        let diagnostics =
            if let Some(arr) = validate_json.get("diagnostics").and_then(Value::as_array) {
                let mut diags = Vec::with_capacity(arr.len());
                for item in arr {
                    let severity_str = item
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("error");
                    let severity = match severity_str {
                        "warning" => DiagnosticSeverity::Warning,
                        _ => DiagnosticSeverity::Error,
                    };
                    let summary = item
                        .get("summary")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let detail = item.get("detail").and_then(Value::as_str).map(String::from);
                    let range = item.get("range").map(|r| r.to_string());

                    diags.push(PlanDiagnostic {
                        severity,
                        summary,
                        detail,
                        range,
                    });
                }
                diags
            } else {
                Vec::new()
            };

        Ok(Self {
            valid,
            error_count,
            warning_count,
            diagnostics,
        })
    }
}

// ---------------------------------------------------------------------------
// PlanRenderer
// ---------------------------------------------------------------------------

impl PlanRenderer {
    /// Render a human-readable text summary of the plan.
    #[must_use]
    pub fn render_text(plan: &TerraformPlan) -> String {
        let summary = plan.summary();
        let mut out = String::new();

        let _ = writeln!(out, "Terraform v{} — Plan Summary", plan.terraform_version);
        let _ = writeln!(out, "Format version: {}", plan.format_version);
        let _ = writeln!(
            out,
            "{} to add, {} to change, {} to destroy ({} total)",
            summary.adds, summary.changes, summary.destroys, summary.total
        );

        if !plan.resource_changes.is_empty() {
            out.push_str("\nResource Changes:\n");
            for rc in &plan.resource_changes {
                let _ = writeln!(out, "  {} {} ({})", rc.action, rc.address, rc.resource_type);
            }
        }

        if !plan.output_changes.is_empty() {
            out.push_str("\nOutput Changes:\n");
            for oc in &plan.output_changes {
                let sens = if oc.sensitive { " (sensitive)" } else { "" };
                let _ = writeln!(out, "  {} {}{}", oc.action, oc.name, sens);
            }
        }

        let _ = writeln!(out, "\nPlan hash: {}", plan.plan_hash);
        out
    }

    /// Render a machine-readable JSON summary of the plan.
    #[must_use]
    pub fn render_json(plan: &TerraformPlan) -> Value {
        let summary = plan.summary();
        serde_json::json!({
            "terraform_version": plan.terraform_version,
            "format_version": plan.format_version,
            "plan_hash": plan.plan_hash,
            "summary": {
                "adds": summary.adds,
                "changes": summary.changes,
                "destroys": summary.destroys,
                "no_ops": summary.no_ops,
                "total": summary.total,
            },
            "resource_changes": plan.resource_changes.iter().map(|rc| {
                serde_json::json!({
                    "address": rc.address,
                    "action": rc.action,
                    "resource_type": rc.resource_type,
                })
            }).collect::<Vec<_>>(),
            "output_changes": plan.output_changes.iter().map(|oc| {
                serde_json::json!({
                    "name": oc.name,
                    "action": oc.action,
                    "sensitive": oc.sensitive,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Helper to build a minimal plan JSON --

    fn minimal_plan_json() -> Value {
        json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [],
            "output_changes": {}
        })
    }

    fn single_create_plan() -> Value {
        json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "actions": ["create"],
                    "before": null,
                    "after": {"ami": "ami-123", "instance_type": "t3.micro"},
                    "after_unknown": {"id": true, "arn": true}
                }
            }],
            "output_changes": {
                "ip": {
                    "actions": ["create"],
                    "before": null,
                    "after": "10.0.0.1",
                    "after_sensitive": false
                }
            }
        })
    }

    fn multi_change_plan() -> Value {
        json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [
                {
                    "address": "aws_instance.web",
                    "type": "aws_instance",
                    "change": {"actions": ["create"], "before": null, "after": {"ami": "ami-1"}, "after_unknown": {}}
                },
                {
                    "address": "aws_s3_bucket.logs",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["update"], "before": {"versioning": false}, "after": {"versioning": true}, "after_unknown": {}}
                },
                {
                    "address": "aws_security_group.old",
                    "type": "aws_security_group",
                    "change": {"actions": ["delete"], "before": {"id": "sg-123"}, "after": null, "after_unknown": {}}
                },
                {
                    "address": "aws_iam_role.app",
                    "type": "aws_iam_role",
                    "change": {"actions": ["no-op"], "before": {"name": "app"}, "after": {"name": "app"}, "after_unknown": {}}
                }
            ],
            "output_changes": {}
        })
    }

    // -----------------------------------------------------------------------
    // PlanAction serde + Display
    // -----------------------------------------------------------------------

    #[test]
    fn plan_action_serde_create() {
        let a: PlanAction = serde_json::from_str("\"create\"").unwrap();
        assert_eq!(a, PlanAction::Create);
    }

    #[test]
    fn plan_action_serde_update() {
        let a: PlanAction = serde_json::from_str("\"update\"").unwrap();
        assert_eq!(a, PlanAction::Update);
    }

    #[test]
    fn plan_action_serde_delete() {
        let a: PlanAction = serde_json::from_str("\"delete\"").unwrap();
        assert_eq!(a, PlanAction::Delete);
    }

    #[test]
    fn plan_action_serde_no_op() {
        let a: PlanAction = serde_json::from_str("\"no_op\"").unwrap();
        assert_eq!(a, PlanAction::NoOp);
    }

    #[test]
    fn plan_action_serde_read() {
        let a: PlanAction = serde_json::from_str("\"read\"").unwrap();
        assert_eq!(a, PlanAction::Read);
    }

    #[test]
    fn plan_action_serde_replace() {
        let a: PlanAction = serde_json::from_str("\"replace\"").unwrap();
        assert_eq!(a, PlanAction::Replace);
    }

    #[test]
    fn plan_action_serialize_roundtrip() {
        for &action in &[
            PlanAction::Create,
            PlanAction::Update,
            PlanAction::Delete,
            PlanAction::NoOp,
            PlanAction::Read,
            PlanAction::Replace,
        ] {
            let s = serde_json::to_string(&action).unwrap();
            let back: PlanAction = serde_json::from_str(&s).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn plan_action_display_create() {
        assert_eq!(PlanAction::Create.to_string(), "create");
    }

    #[test]
    fn plan_action_display_update() {
        assert_eq!(PlanAction::Update.to_string(), "update");
    }

    #[test]
    fn plan_action_display_delete() {
        assert_eq!(PlanAction::Delete.to_string(), "delete");
    }

    #[test]
    fn plan_action_display_no_op() {
        assert_eq!(PlanAction::NoOp.to_string(), "no-op");
    }

    #[test]
    fn plan_action_display_read() {
        assert_eq!(PlanAction::Read.to_string(), "read");
    }

    #[test]
    fn plan_action_display_replace() {
        assert_eq!(PlanAction::Replace.to_string(), "replace");
    }

    // -----------------------------------------------------------------------
    // DiagnosticSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn diagnostic_severity_serde_error() {
        let s: DiagnosticSeverity = serde_json::from_str("\"error\"").unwrap();
        assert_eq!(s, DiagnosticSeverity::Error);
    }

    #[test]
    fn diagnostic_severity_serde_warning() {
        let s: DiagnosticSeverity = serde_json::from_str("\"warning\"").unwrap();
        assert_eq!(s, DiagnosticSeverity::Warning);
    }

    #[test]
    fn diagnostic_severity_display() {
        assert_eq!(DiagnosticSeverity::Error.to_string(), "error");
        assert_eq!(DiagnosticSeverity::Warning.to_string(), "warning");
    }

    #[test]
    fn diagnostic_severity_roundtrip() {
        for &sev in &[DiagnosticSeverity::Error, DiagnosticSeverity::Warning] {
            let s = serde_json::to_string(&sev).unwrap();
            let back: DiagnosticSeverity = serde_json::from_str(&s).unwrap();
            assert_eq!(sev, back);
        }
    }

    // -----------------------------------------------------------------------
    // resolve_action helper
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_action_create() {
        assert_eq!(resolve_action(&[json!("create")]), PlanAction::Create);
    }

    #[test]
    fn resolve_action_update() {
        assert_eq!(resolve_action(&[json!("update")]), PlanAction::Update);
    }

    #[test]
    fn resolve_action_delete() {
        assert_eq!(resolve_action(&[json!("delete")]), PlanAction::Delete);
    }

    #[test]
    fn resolve_action_no_op() {
        assert_eq!(resolve_action(&[json!("no-op")]), PlanAction::NoOp);
    }

    #[test]
    fn resolve_action_read() {
        assert_eq!(resolve_action(&[json!("read")]), PlanAction::Read);
    }

    #[test]
    fn resolve_action_replace_delete_create() {
        assert_eq!(
            resolve_action(&[json!("delete"), json!("create")]),
            PlanAction::Replace
        );
    }

    #[test]
    fn resolve_action_replace_create_delete() {
        assert_eq!(
            resolve_action(&[json!("create"), json!("delete")]),
            PlanAction::Replace
        );
    }

    #[test]
    fn resolve_action_unknown_single() {
        assert_eq!(resolve_action(&[json!("migrate")]), PlanAction::NoOp);
    }

    #[test]
    fn resolve_action_empty() {
        assert_eq!(resolve_action(&[]), PlanAction::NoOp);
    }

    // -----------------------------------------------------------------------
    // compute_plan_hash
    // -----------------------------------------------------------------------

    #[test]
    fn compute_plan_hash_deterministic() {
        let j = single_create_plan();
        let h1 = compute_plan_hash(&j);
        let h2 = compute_plan_hash(&j);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_plan_hash_different_inputs() {
        let h1 = compute_plan_hash(&json!({"a": 1}));
        let h2 = compute_plan_hash(&json!({"a": 2}));
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_plan_hash_hex_length() {
        let h = compute_plan_hash(&json!({}));
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_plan_hash_null() {
        let h = compute_plan_hash(&json!(null));
        assert_eq!(h.len(), 16);
    }

    // -----------------------------------------------------------------------
    // TerraformPlan::from_json — parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_empty_plan() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        assert_eq!(plan.format_version, "1.2");
        assert_eq!(plan.terraform_version, "1.5.0");
        assert!(plan.resource_changes.is_empty());
        assert!(plan.output_changes.is_empty());
    }

    #[test]
    fn parse_single_create() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        assert_eq!(plan.resource_changes.len(), 1);
        let rc = &plan.resource_changes[0];
        assert_eq!(rc.address, "aws_instance.web");
        assert_eq!(rc.action, PlanAction::Create);
        assert_eq!(rc.resource_type, "aws_instance");
        assert!(rc.before.is_none());
        assert!(rc.after.is_some());
        assert!(rc.after_unknown.is_some());
    }

    #[test]
    fn parse_single_create_output() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        assert_eq!(plan.output_changes.len(), 1);
        let oc = &plan.output_changes[0];
        assert_eq!(oc.name, "ip");
        assert_eq!(oc.action, PlanAction::Create);
        assert!(!oc.sensitive);
        assert_eq!(oc.after, Some(json!("10.0.0.1")));
    }

    #[test]
    fn parse_multi_change_plan() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        assert_eq!(plan.resource_changes.len(), 4);
        assert_eq!(plan.resource_changes[0].action, PlanAction::Create);
        assert_eq!(plan.resource_changes[1].action, PlanAction::Update);
        assert_eq!(plan.resource_changes[2].action, PlanAction::Delete);
        assert_eq!(plan.resource_changes[3].action, PlanAction::NoOp);
    }

    #[test]
    fn parse_replace_action() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.forced",
                "type": "aws_instance",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"id": "i-old"},
                    "after": {"ami": "ami-new"},
                    "after_unknown": {"id": true}
                }
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.resource_changes[0].action, PlanAction::Replace);
    }

    #[test]
    fn parse_read_action() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "data.aws_ami.latest",
                "type": "aws_ami",
                "change": {
                    "actions": ["read"],
                    "before": null,
                    "after": null,
                    "after_unknown": {}
                }
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.resource_changes[0].action, PlanAction::Read);
    }

    #[test]
    fn parse_missing_format_version_defaults() {
        let j = json!({"terraform_version": "1.5.0"});
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.format_version, "0.0");
    }

    #[test]
    fn parse_missing_terraform_version_defaults() {
        let j = json!({"format_version": "1.2"});
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.terraform_version, "unknown");
    }

    #[test]
    fn parse_missing_resource_changes_is_empty() {
        let j = json!({"format_version": "1.2", "terraform_version": "1.5.0"});
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert!(plan.resource_changes.is_empty());
    }

    #[test]
    fn parse_resource_missing_address_errors() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "type": "aws_instance",
                "change": {"actions": ["create"], "before": null, "after": null}
            }]
        });
        let err = TerraformPlan::from_json(&j).unwrap_err();
        assert!(err.contains("address"));
    }

    #[test]
    fn parse_resource_missing_change_errors() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance"
            }]
        });
        let err = TerraformPlan::from_json(&j).unwrap_err();
        assert!(err.contains("change"));
    }

    #[test]
    fn parse_resource_missing_actions_errors() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {"before": null, "after": null}
            }]
        });
        let err = TerraformPlan::from_json(&j).unwrap_err();
        assert!(err.contains("actions"));
    }

    #[test]
    fn parse_provider_versions() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "provider_versions": {
                "registry.terraform.io/hashicorp/aws": "5.30.0",
                "registry.terraform.io/hashicorp/random": "3.6.0"
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.provider_versions.len(), 2);
        assert_eq!(
            plan.provider_versions["registry.terraform.io/hashicorp/aws"],
            "5.30.0"
        );
    }

    #[test]
    fn parse_null_before_after() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "actions": ["create"],
                    "before": null,
                    "after": null,
                    "after_unknown": null
                }
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let rc = &plan.resource_changes[0];
        assert!(rc.before.is_none());
        assert!(rc.after.is_none());
        assert!(rc.after_unknown.is_none());
    }

    #[test]
    fn parse_complex_after_value() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "actions": ["create"],
                    "before": null,
                    "after": {
                        "tags": {"env": "prod", "team": "infra"},
                        "count": 3,
                        "nested": {"a": {"b": [1, 2, 3]}}
                    },
                    "after_unknown": {}
                }
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let after = plan.resource_changes[0].after.as_ref().unwrap();
        assert_eq!(after["tags"]["env"], "prod");
        assert_eq!(after["count"], 3);
    }

    #[test]
    fn parse_sensitive_output() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "secret": {
                    "actions": ["create"],
                    "before": null,
                    "after": null,
                    "after_sensitive": true
                }
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert!(plan.output_changes[0].sensitive);
    }

    #[test]
    fn parse_multiple_outputs_sorted() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "zzz": {"actions": ["create"], "before": null, "after": "z", "after_sensitive": false},
                "aaa": {"actions": ["create"], "before": null, "after": "a", "after_sensitive": false}
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.output_changes[0].name, "aaa");
        assert_eq!(plan.output_changes[1].name, "zzz");
    }

    #[test]
    fn parse_output_update() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "endpoint": {
                    "actions": ["update"],
                    "before": "http://old.example.com",
                    "after": "https://new.example.com",
                    "after_sensitive": false
                }
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let oc = &plan.output_changes[0];
        assert_eq!(oc.action, PlanAction::Update);
        assert_eq!(oc.before, Some(json!("http://old.example.com")));
        assert_eq!(oc.after, Some(json!("https://new.example.com")));
    }

    #[test]
    fn parse_output_delete() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "old_out": {
                    "actions": ["delete"],
                    "before": "value",
                    "after": null,
                    "after_sensitive": false
                }
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.output_changes[0].action, PlanAction::Delete);
    }

    // -----------------------------------------------------------------------
    // TerraformPlan::summary
    // -----------------------------------------------------------------------

    #[test]
    fn summary_empty_plan() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let s = plan.summary();
        assert_eq!(s.adds, 0);
        assert_eq!(s.changes, 0);
        assert_eq!(s.destroys, 0);
        assert_eq!(s.no_ops, 0);
        assert_eq!(s.total, 0);
    }

    #[test]
    fn summary_single_create() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let s = plan.summary();
        assert_eq!(s.adds, 1);
        assert_eq!(s.changes, 0);
        assert_eq!(s.destroys, 0);
        assert_eq!(s.total, 1);
    }

    #[test]
    fn summary_multi_change() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        let s = plan.summary();
        assert_eq!(s.adds, 1);
        assert_eq!(s.changes, 1);
        assert_eq!(s.destroys, 1);
        assert_eq!(s.no_ops, 1);
        assert_eq!(s.total, 4);
    }

    #[test]
    fn summary_all_creates() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [
                {"address": "a.1", "type": "a", "change": {"actions": ["create"], "before": null, "after": {}}},
                {"address": "a.2", "type": "a", "change": {"actions": ["create"], "before": null, "after": {}}},
                {"address": "a.3", "type": "a", "change": {"actions": ["create"], "before": null, "after": {}}}
            ]
        });
        let s = TerraformPlan::from_json(&j).unwrap().summary();
        assert_eq!(s.adds, 3);
        assert_eq!(s.changes, 0);
        assert_eq!(s.destroys, 0);
        assert_eq!(s.total, 3);
    }

    #[test]
    fn summary_all_deletes() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [
                {"address": "a.1", "type": "a", "change": {"actions": ["delete"], "before": {}, "after": null}},
                {"address": "a.2", "type": "a", "change": {"actions": ["delete"], "before": {}, "after": null}}
            ]
        });
        let s = TerraformPlan::from_json(&j).unwrap().summary();
        assert_eq!(s.adds, 0);
        assert_eq!(s.destroys, 2);
        assert_eq!(s.total, 2);
    }

    #[test]
    fn summary_all_updates() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [
                {"address": "a.1", "type": "a", "change": {"actions": ["update"], "before": {}, "after": {}}},
                {"address": "a.2", "type": "a", "change": {"actions": ["update"], "before": {}, "after": {}}}
            ]
        });
        let s = TerraformPlan::from_json(&j).unwrap().summary();
        assert_eq!(s.changes, 2);
        assert_eq!(s.destroys, 0);
        assert_eq!(s.total, 2);
    }

    #[test]
    fn summary_replace_counts_as_destroy() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "a.1", "type": "a",
                "change": {"actions": ["delete", "create"], "before": {}, "after": {}}
            }]
        });
        let s = TerraformPlan::from_json(&j).unwrap().summary();
        assert_eq!(s.destroys, 1);
        assert_eq!(s.adds, 0);
    }

    #[test]
    fn summary_read_counts_as_noop() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "data.a.1", "type": "a",
                "change": {"actions": ["read"], "before": null, "after": null}
            }]
        });
        let s = TerraformPlan::from_json(&j).unwrap().summary();
        assert_eq!(s.no_ops, 1);
    }

    // -----------------------------------------------------------------------
    // TerraformPlan::changes_for_type
    // -----------------------------------------------------------------------

    #[test]
    fn changes_for_type_matching() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        let aws_instances = plan.changes_for_type("aws_instance");
        assert_eq!(aws_instances.len(), 1);
        assert_eq!(aws_instances[0].address, "aws_instance.web");
    }

    #[test]
    fn changes_for_type_no_match() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        let result = plan.changes_for_type("aws_lambda_function");
        assert!(result.is_empty());
    }

    #[test]
    fn changes_for_type_multiple_matches() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [
                {"address": "aws_instance.a", "type": "aws_instance", "change": {"actions": ["create"], "before": null, "after": {}}},
                {"address": "aws_instance.b", "type": "aws_instance", "change": {"actions": ["update"], "before": {}, "after": {}}},
                {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "change": {"actions": ["create"], "before": null, "after": {}}}
            ]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.changes_for_type("aws_instance").len(), 2);
        assert_eq!(plan.changes_for_type("aws_s3_bucket").len(), 1);
    }

    #[test]
    fn changes_for_type_empty_plan() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        assert!(plan.changes_for_type("anything").is_empty());
    }

    // -----------------------------------------------------------------------
    // TerraformPlan::has_destructive_changes
    // -----------------------------------------------------------------------

    #[test]
    fn has_destructive_with_delete() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        assert!(plan.has_destructive_changes());
    }

    #[test]
    fn has_destructive_with_replace() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "a.1", "type": "a",
                "change": {"actions": ["delete", "create"], "before": {}, "after": {}}
            }]
        });
        assert!(
            TerraformPlan::from_json(&j)
                .unwrap()
                .has_destructive_changes()
        );
    }

    #[test]
    fn no_destructive_create_only() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        assert!(!plan.has_destructive_changes());
    }

    #[test]
    fn no_destructive_empty_plan() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        assert!(!plan.has_destructive_changes());
    }

    #[test]
    fn no_destructive_update_only() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "a.1", "type": "a",
                "change": {"actions": ["update"], "before": {}, "after": {}}
            }]
        });
        assert!(
            !TerraformPlan::from_json(&j)
                .unwrap()
                .has_destructive_changes()
        );
    }

    // -----------------------------------------------------------------------
    // TerraformPlan::plan_hash
    // -----------------------------------------------------------------------

    #[test]
    fn plan_hash_matches_compute() {
        let j = single_create_plan();
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.plan_hash(), compute_plan_hash(&j));
    }

    #[test]
    fn plan_hash_is_hex() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        assert!(plan.plan_hash().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn plan_hash_length_is_16() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        assert_eq!(plan.plan_hash().len(), 16);
    }

    // -----------------------------------------------------------------------
    // TerraformPlan serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn terraform_plan_serde_roundtrip() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let serialized = serde_json::to_value(&plan).unwrap();
        let deserialized: TerraformPlan = serde_json::from_value(serialized).unwrap();
        assert_eq!(plan, deserialized);
    }

    #[test]
    fn terraform_plan_clone() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let cloned = plan.clone();
        drop(plan);
        assert_eq!(cloned.format_version, "1.2");
        assert_eq!(cloned.resource_changes.len(), 1);
    }

    #[test]
    fn terraform_plan_debug() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("TerraformPlan"));
        assert!(dbg.contains("1.2"));
    }

    // -----------------------------------------------------------------------
    // ResourceChange serde
    // -----------------------------------------------------------------------

    #[test]
    fn resource_change_serde_roundtrip() {
        let rc = ResourceChange {
            address: "aws_instance.web".into(),
            action: PlanAction::Create,
            resource_type: "aws_instance".into(),
            before: None,
            after: Some(json!({"ami": "ami-123"})),
            after_unknown: Some(json!({"id": true})),
        };
        let v = serde_json::to_value(&rc).unwrap();
        let back: ResourceChange = serde_json::from_value(v).unwrap();
        assert_eq!(rc, back);
    }

    #[test]
    fn resource_change_clone() {
        let rc = ResourceChange {
            address: "a.b".into(),
            action: PlanAction::Delete,
            resource_type: "a".into(),
            before: Some(json!({"id": "x"})),
            after: None,
            after_unknown: None,
        };
        let cloned = rc.clone();
        drop(rc);
        assert_eq!(cloned.address, "a.b");
        assert_eq!(cloned.action, PlanAction::Delete);
    }

    // -----------------------------------------------------------------------
    // OutputChange serde
    // -----------------------------------------------------------------------

    #[test]
    fn output_change_serde_roundtrip() {
        let oc = OutputChange {
            name: "endpoint".into(),
            action: PlanAction::Create,
            before: None,
            after: Some(json!("https://example.com")),
            sensitive: false,
        };
        let v = serde_json::to_value(&oc).unwrap();
        let back: OutputChange = serde_json::from_value(v).unwrap();
        assert_eq!(oc, back);
    }

    #[test]
    fn output_change_sensitive_roundtrip() {
        let oc = OutputChange {
            name: "secret".into(),
            action: PlanAction::Create,
            before: None,
            after: None,
            sensitive: true,
        };
        let v = serde_json::to_value(&oc).unwrap();
        assert_eq!(v["sensitive"], true);
        let back: OutputChange = serde_json::from_value(v).unwrap();
        assert!(back.sensitive);
    }

    // -----------------------------------------------------------------------
    // PlanSummary serde
    // -----------------------------------------------------------------------

    #[test]
    fn plan_summary_serde_roundtrip() {
        let s = PlanSummary {
            adds: 3,
            changes: 2,
            destroys: 1,
            no_ops: 5,
            total: 11,
        };
        let v = serde_json::to_value(s).unwrap();
        let back: PlanSummary = serde_json::from_value(v).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn plan_summary_copy() {
        let s = PlanSummary {
            adds: 1,
            changes: 0,
            destroys: 0,
            no_ops: 0,
            total: 1,
        };
        let copied = s;
        assert_eq!(s.adds, copied.adds);
    }

    // -----------------------------------------------------------------------
    // PlanValidation
    // -----------------------------------------------------------------------

    #[test]
    fn validation_valid() {
        let j = json!({
            "valid": true,
            "error_count": 0,
            "warning_count": 0,
            "diagnostics": []
        });
        let v = PlanValidation::from_json(&j).unwrap();
        assert!(v.valid);
        assert_eq!(v.error_count, 0);
        assert_eq!(v.warning_count, 0);
        assert!(v.diagnostics.is_empty());
    }

    #[test]
    fn validation_with_errors() {
        let j = json!({
            "valid": false,
            "error_count": 2,
            "warning_count": 0,
            "diagnostics": [
                {"severity": "error", "summary": "Missing argument", "detail": "region is required"},
                {"severity": "error", "summary": "Invalid value", "detail": "ami must start with ami-"}
            ]
        });
        let v = PlanValidation::from_json(&j).unwrap();
        assert!(!v.valid);
        assert_eq!(v.error_count, 2);
        assert_eq!(v.diagnostics.len(), 2);
        assert_eq!(v.diagnostics[0].severity, DiagnosticSeverity::Error);
        assert_eq!(v.diagnostics[0].summary, "Missing argument");
        assert_eq!(v.diagnostics[0].detail, Some("region is required".into()));
    }

    #[test]
    fn validation_with_warnings() {
        let j = json!({
            "valid": true,
            "error_count": 0,
            "warning_count": 2,
            "diagnostics": [
                {"severity": "warning", "summary": "Deprecated argument"},
                {"severity": "warning", "summary": "Version constraint"}
            ]
        });
        let v = PlanValidation::from_json(&j).unwrap();
        assert!(v.valid);
        assert_eq!(v.warning_count, 2);
        assert_eq!(v.diagnostics[0].severity, DiagnosticSeverity::Warning);
        assert!(v.diagnostics[0].detail.is_none());
    }

    #[test]
    fn validation_mixed_diagnostics() {
        let j = json!({
            "valid": false,
            "error_count": 1,
            "warning_count": 1,
            "diagnostics": [
                {"severity": "error", "summary": "Bad config"},
                {"severity": "warning", "summary": "Deprecation notice"}
            ]
        });
        let v = PlanValidation::from_json(&j).unwrap();
        assert!(!v.valid);
        assert_eq!(v.diagnostics.len(), 2);
        assert_eq!(v.diagnostics[0].severity, DiagnosticSeverity::Error);
        assert_eq!(v.diagnostics[1].severity, DiagnosticSeverity::Warning);
    }

    #[test]
    fn validation_with_range() {
        let j = json!({
            "valid": false,
            "error_count": 1,
            "warning_count": 0,
            "diagnostics": [{
                "severity": "error",
                "summary": "Syntax error",
                "detail": "Unexpected token",
                "range": {"filename": "main.tf", "start": {"line": 5, "column": 1}}
            }]
        });
        let v = PlanValidation::from_json(&j).unwrap();
        let diag = &v.diagnostics[0];
        assert!(diag.range.is_some());
        let range_str = diag.range.as_ref().unwrap();
        assert!(range_str.contains("main.tf"));
    }

    #[test]
    fn validation_missing_valid_defaults_false() {
        let j = json!({});
        let v = PlanValidation::from_json(&j).unwrap();
        assert!(!v.valid);
        assert_eq!(v.error_count, 0);
        assert_eq!(v.warning_count, 0);
    }

    #[test]
    fn validation_missing_diagnostics_is_empty() {
        let j = json!({"valid": true, "error_count": 0, "warning_count": 0});
        let v = PlanValidation::from_json(&j).unwrap();
        assert!(v.diagnostics.is_empty());
    }

    #[test]
    fn validation_serde_roundtrip() {
        let v = PlanValidation {
            valid: false,
            error_count: 1,
            warning_count: 2,
            diagnostics: vec![
                PlanDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    summary: "err".into(),
                    detail: Some("detail".into()),
                    range: None,
                },
                PlanDiagnostic {
                    severity: DiagnosticSeverity::Warning,
                    summary: "warn".into(),
                    detail: None,
                    range: Some("main.tf:5".into()),
                },
            ],
        };
        let json_val = serde_json::to_value(&v).unwrap();
        let back: PlanValidation = serde_json::from_value(json_val).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn validation_clone() {
        let v = PlanValidation {
            valid: true,
            error_count: 0,
            warning_count: 0,
            diagnostics: vec![],
        };
        let cloned = v.clone();
        drop(v);
        assert!(cloned.valid);
    }

    // -----------------------------------------------------------------------
    // PlanDiagnostic
    // -----------------------------------------------------------------------

    #[test]
    fn plan_diagnostic_serde_roundtrip() {
        let d = PlanDiagnostic {
            severity: DiagnosticSeverity::Error,
            summary: "test error".into(),
            detail: Some("detailed".into()),
            range: Some("file.tf:10".into()),
        };
        let v = serde_json::to_value(&d).unwrap();
        let back: PlanDiagnostic = serde_json::from_value(v).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn plan_diagnostic_debug() {
        let d = PlanDiagnostic {
            severity: DiagnosticSeverity::Warning,
            summary: "deprecated".into(),
            detail: None,
            range: None,
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("PlanDiagnostic"));
        assert!(dbg.contains("deprecated"));
    }

    // -----------------------------------------------------------------------
    // PlanRenderer::render_text
    // -----------------------------------------------------------------------

    #[test]
    fn render_text_empty_plan() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("Terraform v1.5.0"));
        assert!(text.contains("0 to add"));
        assert!(text.contains("0 to change"));
        assert!(text.contains("0 to destroy"));
    }

    #[test]
    fn render_text_with_changes() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("1 to add"));
        assert!(text.contains("1 to change"));
        assert!(text.contains("1 to destroy"));
        assert!(text.contains("4 total"));
    }

    #[test]
    fn render_text_contains_resource_changes() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("aws_instance.web"));
        assert!(text.contains("create"));
    }

    #[test]
    fn render_text_contains_output_changes() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("Output Changes"));
        assert!(text.contains("ip"));
    }

    #[test]
    fn render_text_contains_plan_hash() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("Plan hash:"));
        assert!(text.contains(plan.plan_hash()));
    }

    #[test]
    fn render_text_sensitive_output() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "secret": {
                    "actions": ["create"],
                    "before": null,
                    "after": null,
                    "after_sensitive": true
                }
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("(sensitive)"));
    }

    #[test]
    fn render_text_format_version() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("Format version: 1.2"));
    }

    // -----------------------------------------------------------------------
    // PlanRenderer::render_json
    // -----------------------------------------------------------------------

    #[test]
    fn render_json_empty_plan() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert_eq!(rendered["summary"]["adds"], 0);
        assert_eq!(rendered["summary"]["changes"], 0);
        assert_eq!(rendered["summary"]["destroys"], 0);
        assert_eq!(rendered["summary"]["total"], 0);
    }

    #[test]
    fn render_json_with_changes() {
        let plan = TerraformPlan::from_json(&multi_change_plan()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert_eq!(rendered["summary"]["adds"], 1);
        assert_eq!(rendered["summary"]["changes"], 1);
        assert_eq!(rendered["summary"]["destroys"], 1);
        assert_eq!(rendered["summary"]["no_ops"], 1);
        assert_eq!(rendered["summary"]["total"], 4);
    }

    #[test]
    fn render_json_contains_version() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert_eq!(rendered["terraform_version"], "1.5.0");
        assert_eq!(rendered["format_version"], "1.2");
    }

    #[test]
    fn render_json_contains_plan_hash() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert_eq!(rendered["plan_hash"].as_str().unwrap(), plan.plan_hash());
    }

    #[test]
    fn render_json_resource_changes_list() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        let rcs = rendered["resource_changes"].as_array().unwrap();
        assert_eq!(rcs.len(), 1);
        assert_eq!(rcs[0]["address"], "aws_instance.web");
        assert_eq!(rcs[0]["action"], "create");
        assert_eq!(rcs[0]["resource_type"], "aws_instance");
    }

    #[test]
    fn render_json_output_changes_list() {
        let plan = TerraformPlan::from_json(&single_create_plan()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        let ocs = rendered["output_changes"].as_array().unwrap();
        assert_eq!(ocs.len(), 1);
        assert_eq!(ocs[0]["name"], "ip");
        assert_eq!(ocs[0]["action"], "create");
        assert_eq!(ocs[0]["sensitive"], false);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn plan_with_unknown_resource_type() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "custom.thing",
                "change": {"actions": ["create"], "before": null, "after": {}}
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.resource_changes[0].resource_type, "unknown");
    }

    #[test]
    fn plan_many_resources() {
        let changes: Vec<Value> = (0..50)
            .map(|i| {
                json!({
                    "address": format!("aws_instance.node_{i}"),
                    "type": "aws_instance",
                    "change": {"actions": ["create"], "before": null, "after": {"id": i}}
                })
            })
            .collect();
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": changes
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.resource_changes.len(), 50);
        assert_eq!(plan.summary().adds, 50);
    }

    #[test]
    fn plan_complex_nested_after_unknown() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "actions": ["create"],
                    "before": null,
                    "after": {"ami": "ami-123"},
                    "after_unknown": {
                        "id": true,
                        "arn": true,
                        "tags_all": true,
                        "network_interface": [{"private_ip": true}]
                    }
                }
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let au = plan.resource_changes[0].after_unknown.as_ref().unwrap();
        assert_eq!(au["id"], true);
        assert!(au["network_interface"].is_array());
    }

    #[test]
    fn plan_with_before_and_after() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.web",
                "type": "aws_instance",
                "change": {
                    "actions": ["update"],
                    "before": {"instance_type": "t3.micro"},
                    "after": {"instance_type": "t3.small"}
                }
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let rc = &plan.resource_changes[0];
        assert_eq!(rc.before.as_ref().unwrap()["instance_type"], "t3.micro");
        assert_eq!(rc.after.as_ref().unwrap()["instance_type"], "t3.small");
    }

    #[test]
    fn plan_empty_json_object() {
        let plan = TerraformPlan::from_json(&json!({})).unwrap();
        assert_eq!(plan.format_version, "0.0");
        assert_eq!(plan.terraform_version, "unknown");
        assert!(plan.resource_changes.is_empty());
        assert!(plan.output_changes.is_empty());
    }

    #[test]
    fn plan_hash_stability_across_parses() {
        let j = single_create_plan();
        let p1 = TerraformPlan::from_json(&j).unwrap();
        let p2 = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(p1.plan_hash(), p2.plan_hash());
    }

    #[test]
    fn plan_mixed_resource_types() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [
                {"address": "aws_instance.a", "type": "aws_instance", "change": {"actions": ["create"], "before": null, "after": {}}},
                {"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"actions": ["create"], "before": null, "after": {}}},
                {"address": "aws_instance.c", "type": "aws_instance", "change": {"actions": ["delete"], "before": {}, "after": null}},
                {"address": "google_compute_instance.d", "type": "google_compute_instance", "change": {"actions": ["update"], "before": {}, "after": {}}}
            ]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.changes_for_type("aws_instance").len(), 2);
        assert_eq!(plan.changes_for_type("aws_s3_bucket").len(), 1);
        assert_eq!(plan.changes_for_type("google_compute_instance").len(), 1);
    }

    #[test]
    fn plan_output_no_sensitive_field_defaults_false() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "out1": {
                    "actions": ["create"],
                    "before": null,
                    "after": "val"
                }
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert!(!plan.output_changes[0].sensitive);
    }

    #[test]
    fn validation_unknown_severity_defaults_error() {
        let j = json!({
            "valid": false,
            "error_count": 1,
            "warning_count": 0,
            "diagnostics": [{
                "severity": "fatal",
                "summary": "Critical failure"
            }]
        });
        let v = PlanValidation::from_json(&j).unwrap();
        assert_eq!(v.diagnostics[0].severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn validation_many_diagnostics() {
        let diags: Vec<Value> = (0..20)
            .map(|i| {
                json!({
                    "severity": if i % 2 == 0 { "error" } else { "warning" },
                    "summary": format!("Diagnostic {i}")
                })
            })
            .collect();
        let j = json!({
            "valid": false,
            "error_count": 10,
            "warning_count": 10,
            "diagnostics": diags
        });
        let v = PlanValidation::from_json(&j).unwrap();
        assert_eq!(v.diagnostics.len(), 20);
    }

    #[test]
    fn render_text_no_resource_changes_section() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(!text.contains("Resource Changes"));
    }

    #[test]
    fn render_text_no_output_changes_section() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(!text.contains("Output Changes"));
    }

    #[test]
    fn render_json_empty_output_changes() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert!(rendered["output_changes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn render_json_empty_resource_changes() {
        let plan = TerraformPlan::from_json(&minimal_plan_json()).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert!(rendered["resource_changes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn plan_action_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PlanAction::Create);
        set.insert(PlanAction::Create);
        set.insert(PlanAction::Delete);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn diagnostic_severity_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DiagnosticSeverity::Error);
        set.insert(DiagnosticSeverity::Error);
        set.insert(DiagnosticSeverity::Warning);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn resource_change_debug() {
        let rc = ResourceChange {
            address: "a.b".into(),
            action: PlanAction::Create,
            resource_type: "a".into(),
            before: None,
            after: None,
            after_unknown: None,
        };
        let dbg = format!("{rc:?}");
        assert!(dbg.contains("ResourceChange"));
        assert!(dbg.contains("a.b"));
    }

    #[test]
    fn output_change_debug() {
        let oc = OutputChange {
            name: "out".into(),
            action: PlanAction::Create,
            before: None,
            after: Some(json!("val")),
            sensitive: false,
        };
        let dbg = format!("{oc:?}");
        assert!(dbg.contains("OutputChange"));
        assert!(dbg.contains("out"));
    }

    #[test]
    fn plan_summary_debug() {
        let s = PlanSummary {
            adds: 1,
            changes: 2,
            destroys: 3,
            no_ops: 4,
            total: 10,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("PlanSummary"));
    }

    #[test]
    fn plan_with_empty_provider_versions() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "provider_versions": {}
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert!(plan.provider_versions.is_empty());
    }

    #[test]
    fn compute_plan_hash_empty_object() {
        let h = compute_plan_hash(&json!({}));
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn compute_plan_hash_array() {
        let h = compute_plan_hash(&json!([1, 2, 3]));
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn compute_plan_hash_string() {
        let h = compute_plan_hash(&json!("hello"));
        assert_eq!(h.len(), 16);
    }

    #[test]
    fn plan_render_text_delete_action() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.old",
                "type": "aws_instance",
                "change": {"actions": ["delete"], "before": {}, "after": null}
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("delete"));
        assert!(text.contains("aws_instance.old"));
    }

    #[test]
    fn plan_render_text_replace_action() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.forced",
                "type": "aws_instance",
                "change": {"actions": ["delete", "create"], "before": {}, "after": {}}
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let text = PlanRenderer::render_text(&plan);
        assert!(text.contains("replace"));
    }

    #[test]
    fn render_json_replace_action() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "resource_changes": [{
                "address": "aws_instance.forced",
                "type": "aws_instance",
                "change": {"actions": ["delete", "create"], "before": {}, "after": {}}
            }]
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        let rendered = PlanRenderer::render_json(&plan);
        assert_eq!(rendered["resource_changes"][0]["action"], "replace");
    }

    #[test]
    fn plan_partial_output_changes_object() {
        let j = json!({
            "format_version": "1.2",
            "terraform_version": "1.5.0",
            "output_changes": {
                "out_a": {"actions": ["create"], "before": null, "after": "a", "after_sensitive": false},
                "out_b": {"actions": ["delete"], "before": "b", "after": null, "after_sensitive": false},
                "out_c": {"actions": ["update"], "before": "c_old", "after": "c_new", "after_sensitive": true}
            }
        });
        let plan = TerraformPlan::from_json(&j).unwrap();
        assert_eq!(plan.output_changes.len(), 3);
        // Sorted: out_a, out_b, out_c
        assert_eq!(plan.output_changes[0].name, "out_a");
        assert_eq!(plan.output_changes[0].action, PlanAction::Create);
        assert_eq!(plan.output_changes[1].name, "out_b");
        assert_eq!(plan.output_changes[1].action, PlanAction::Delete);
        assert_eq!(plan.output_changes[2].name, "out_c");
        assert!(plan.output_changes[2].sensitive);
    }
}
