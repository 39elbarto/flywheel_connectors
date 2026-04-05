//! Operation replay from history with input override capabilities.
//!
//! Provides a workflow for replaying previously-executed operations with optional
//! field-level input overrides.  Supports dry-run previews, risk assessment,
//! field-level diffs, and safety checks before replay execution.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Core types ──────────────────────────────────────────────────────────────

/// A request to replay a previously-executed operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayRequest {
    /// ID of the history entry to replay.
    pub history_entry_id: String,
    /// Field-level overrides to apply on top of the original inputs.
    #[serde(default)]
    pub overrides: HashMap<String, Value>,
    /// If true, show what would happen without executing.
    #[serde(default)]
    pub dry_run: bool,
    /// If true, skip preflight safety checks.
    #[serde(default)]
    pub skip_preflight: bool,
}

/// The type of change applied to a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    /// A new field was added.
    Added,
    /// An existing field was modified.
    Modified,
    /// A field was removed.
    Removed,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Added => f.write_str("added"),
            Self::Modified => f.write_str("modified"),
            Self::Removed => f.write_str("removed"),
        }
    }
}

/// A single field-level change between original and modified inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldChange {
    /// Dot-separated path to the field (e.g. "user.email").
    pub path: String,
    /// Old value (None for additions).
    pub old_value: Option<Value>,
    /// New value (None for removals).
    pub new_value: Option<Value>,
    /// Type of change.
    pub change_type: ChangeType,
}

/// A preview of what a replay operation would do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayPreview {
    /// The original command/operation that was executed.
    pub original_command: String,
    /// The modified command/operation after overrides.
    pub modified_command: String,
    /// List of field-level changes.
    pub changes: Vec<FieldChange>,
    /// Assessment of the risk level.
    pub risk_assessment: String,
    /// The connector that will be invoked.
    pub connector: String,
    /// The operation that will be invoked.
    pub operation: String,
    /// The original input values.
    pub original_inputs: Value,
    /// The modified input values after overrides.
    pub modified_inputs: Value,
}

/// The outcome of executing a replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayOutcome {
    /// Whether the replay completed successfully.
    pub success: bool,
    /// ID of the original history entry that was replayed.
    pub original_id: String,
    /// ID of the new history entry created by this replay.
    pub new_id: String,
    /// Wall-clock duration of the replay.
    pub duration: Duration,
    /// Output from the replayed operation.
    pub output: Value,
}

/// Policy governing how a replay is performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayPolicy {
    /// Replay with the exact same inputs.
    ExactReplay,
    /// Replay with field-level input overrides.
    OverrideInputs,
    /// Clone the operation context and modify it.
    CloneAndModify,
}

impl ReplayPolicy {
    /// Return the canonical string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactReplay => "exact_replay",
            Self::OverrideInputs => "override_inputs",
            Self::CloneAndModify => "clone_and_modify",
        }
    }

    /// Whether this policy allows input modifications.
    #[must_use]
    pub const fn allows_overrides(self) -> bool {
        matches!(self, Self::OverrideInputs | Self::CloneAndModify)
    }
}

impl std::fmt::Display for ReplayPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validation result for a replay request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayValidation {
    /// Whether the replay is valid and can proceed.
    pub valid: bool,
    /// Non-fatal warnings about the replay.
    pub warnings: Vec<String>,
    /// Fatal issues that block the replay.
    pub blockers: Vec<String>,
}

impl ReplayValidation {
    /// Create a valid result with no warnings or blockers.
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            valid: true,
            warnings: Vec::new(),
            blockers: Vec::new(),
        }
    }

    /// Create a blocked result.
    #[must_use]
    pub fn blocked(reason: &str) -> Self {
        Self {
            valid: false,
            warnings: Vec::new(),
            blockers: vec![reason.to_string()],
        }
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }

    /// Add a blocker and mark as invalid.
    pub fn add_blocker(&mut self, blocker: &str) {
        self.blockers.push(blocker.to_string());
        self.valid = false;
    }
}

// ── Operations classified by safety ─────────────────────────────────────────

/// Operations that are considered unsafe to replay (destructive/mutating).
const UNSAFE_OPERATIONS: &[&str] = &[
    "delete",
    "remove",
    "destroy",
    "drop",
    "purge",
    "truncate",
    "erase",
    "wipe",
    "terminate",
    "revoke",
];

/// Operations that are always safe to replay (read-only).
const SAFE_OPERATIONS: &[&str] = &[
    "get",
    "list",
    "search",
    "query",
    "describe",
    "inspect",
    "read",
    "fetch",
    "find",
    "count",
    "exists",
    "check",
    "verify",
    "validate",
    "status",
    "ping",
    "health",
    "version",
    "introspect",
];

/// Connectors that require extra caution for any mutating operation.
const HIGH_RISK_CONNECTORS: &[&str] = &[
    "terraform",
    "kubernetes",
    "aws",
    "gcp",
    "azure",
    "production",
];

// ── Core functions ──────────────────────────────────────────────────────────

/// Build a replay preview from a history entry and overrides.
#[must_use]
pub fn build_replay_preview(
    _entry_id: &str,
    connector: &str,
    operation: &str,
    original_inputs: &Value,
    overrides: &HashMap<String, Value>,
) -> ReplayPreview {
    let modified_inputs = apply_field_overrides(original_inputs, overrides)
        .unwrap_or_else(|_| original_inputs.clone());
    let changes = diff_inputs(original_inputs, &modified_inputs);
    let risk = assess_risk(connector, operation, &changes);
    let original_command = format!("{connector}/{operation}");
    let modified_command = if changes.is_empty() {
        original_command.clone()
    } else {
        format!("{connector}/{operation} (+{} overrides)", overrides.len())
    };

    ReplayPreview {
        original_command,
        modified_command,
        changes,
        risk_assessment: risk,
        connector: connector.to_string(),
        operation: operation.to_string(),
        original_inputs: original_inputs.clone(),
        modified_inputs,
    }
}

/// Validate whether a replay can proceed.
#[must_use]
pub fn validate_replay(preview: &ReplayPreview) -> ReplayValidation {
    let mut validation = ReplayValidation::ok();

    // Check if the operation is explicitly unsafe.
    if is_explicitly_unsafe(&preview.operation) {
        validation.add_blocker(&format!(
            "operation `{}` is destructive and cannot be replayed without explicit confirmation",
            preview.operation
        ));
    }

    // Warn about high-risk connectors.
    let connector_lower = preview.connector.to_lowercase();
    if HIGH_RISK_CONNECTORS
        .iter()
        .any(|c| connector_lower.contains(c))
    {
        validation.add_warning(&format!(
            "connector `{}` is high-risk; review changes carefully",
            preview.connector
        ));
    }

    // Warn about large number of overrides.
    if preview.changes.len() > 10 {
        validation.add_warning(
            format!(
                "{} field changes detected; consider reviewing each change",
                preview.changes.len()
            )
            .as_str(),
        );
    }

    // Warn if adding new fields.
    let additions = preview
        .changes
        .iter()
        .filter(|c| c.change_type == ChangeType::Added)
        .count();
    if additions > 0 {
        validation.add_warning(&format!(
            "{additions} new field(s) added that were not in the original input"
        ));
    }

    // Warn about field removals.
    let removals = preview
        .changes
        .iter()
        .filter(|c| c.change_type == ChangeType::Removed)
        .count();
    if removals > 0 {
        validation.add_warning(&format!(
            "{removals} field(s) removed from the original input"
        ));
    }

    validation
}

/// Apply field-level overrides to a JSON value.
///
/// Override keys use dot-notation for nested paths (e.g. "user.email").
/// Setting a value to `null` removes the field.
///
/// # Errors
///
/// Returns an error if the original value is not an object and overrides
/// are non-empty.
pub fn apply_field_overrides(
    original: &Value,
    overrides: &HashMap<String, Value>,
) -> Result<Value, String> {
    if overrides.is_empty() {
        return Ok(original.clone());
    }

    let mut result = original.clone();

    if !result.is_object() && !result.is_null() {
        return Err(format!(
            "cannot apply overrides to non-object value: {}",
            value_type_name(&result)
        ));
    }

    // If the original is null, start with an empty object.
    if result.is_null() {
        result = Value::Object(serde_json::Map::new());
    }

    for (path, value) in overrides {
        if value.is_null() {
            remove_at_path(&mut result, path);
        } else {
            set_at_path(&mut result, path, value.clone());
        }
    }

    Ok(result)
}

/// Compute the field-level diff between two JSON values.
#[must_use]
pub fn diff_inputs(original: &Value, modified: &Value) -> Vec<FieldChange> {
    let mut changes = Vec::new();
    diff_recursive(original, modified, String::new(), &mut changes);
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    changes
}

/// Check if an operation on a connector is safe to replay.
#[must_use]
pub fn is_replay_safe(connector: &str, operation: &str) -> bool {
    let op_lower = operation.to_lowercase();

    // If the operation name contains a known safe verb, it's safe.
    if SAFE_OPERATIONS.iter().any(|s| op_lower.contains(s)) {
        return true;
    }

    // If the operation name contains an unsafe verb, it's not safe.
    if UNSAFE_OPERATIONS.iter().any(|u| op_lower.contains(u)) {
        return false;
    }

    // For high-risk connectors, default to unsafe.
    let conn_lower = connector.to_lowercase();
    if HIGH_RISK_CONNECTORS.iter().any(|c| conn_lower.contains(c)) {
        return false;
    }

    // Default: consider safe (read operations are more common).
    true
}

/// Determine the appropriate replay policy based on the request.
#[must_use]
pub fn determine_policy(request: &ReplayRequest) -> ReplayPolicy {
    if request.overrides.is_empty() {
        ReplayPolicy::ExactReplay
    } else {
        ReplayPolicy::OverrideInputs
    }
}

// ── Formatting ──────────────────────────────────────────────────────────────

/// Format a replay preview for terminal display.
#[must_use]
pub fn format_preview(preview: &ReplayPreview) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Replay Preview ===");
    let _ = writeln!(out, "Connector: {}", preview.connector);
    let _ = writeln!(out, "Operation: {}", preview.operation);
    let _ = writeln!(out, "Risk: {}", preview.risk_assessment);
    let _ = writeln!(out);

    if preview.changes.is_empty() {
        let _ = writeln!(out, "No input changes (exact replay).");
    } else {
        let _ = writeln!(out, "Changes ({}):", preview.changes.len());
        for change in &preview.changes {
            let symbol = match change.change_type {
                ChangeType::Added => "+",
                ChangeType::Modified => "~",
                ChangeType::Removed => "-",
            };
            let _ = writeln!(out, "  {symbol} {}: {}", change.path, format_change(change));
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Original: {}", preview.original_command);
    let _ = writeln!(out, "Modified: {}", preview.modified_command);

    out
}

/// Format a replay outcome for terminal display.
#[must_use]
pub fn format_outcome(outcome: &ReplayOutcome) -> String {
    let mut out = String::new();
    let status = if outcome.success { "SUCCESS" } else { "FAILED" };
    let _ = writeln!(out, "=== Replay {status} ===");
    let _ = writeln!(out, "Original: {}", outcome.original_id);
    let _ = writeln!(out, "New:      {}", outcome.new_id);
    let _ = writeln!(out, "Duration: {}ms", outcome.duration.as_millis());

    if !outcome.success {
        if let Some(error) = outcome.output.get("error") {
            let _ = writeln!(out, "Error: {error}");
        }
    }

    out
}

/// Format a validation result for display.
#[must_use]
pub fn format_validation(validation: &ReplayValidation) -> String {
    let mut out = String::new();
    if validation.valid {
        let _ = writeln!(out, "Validation: PASS");
    } else {
        let _ = writeln!(out, "Validation: BLOCKED");
    }

    if !validation.blockers.is_empty() {
        let _ = writeln!(out, "Blockers:");
        for b in &validation.blockers {
            let _ = writeln!(out, "  - {b}");
        }
    }

    if !validation.warnings.is_empty() {
        let _ = writeln!(out, "Warnings:");
        for w in &validation.warnings {
            let _ = writeln!(out, "  - {w}");
        }
    }

    out
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn is_explicitly_unsafe(operation: &str) -> bool {
    let op_lower = operation.to_lowercase();
    UNSAFE_OPERATIONS.iter().any(|u| op_lower.contains(u))
}

fn assess_risk(connector: &str, operation: &str, changes: &[FieldChange]) -> String {
    let conn_lower = connector.to_lowercase();
    let op_lower = operation.to_lowercase();

    let is_high_risk_connector = HIGH_RISK_CONNECTORS.iter().any(|c| conn_lower.contains(c));

    if UNSAFE_OPERATIONS.iter().any(|u| op_lower.contains(u)) {
        return "HIGH — destructive operation".to_string();
    }

    if SAFE_OPERATIONS.iter().any(|s| op_lower.contains(s)) {
        if is_high_risk_connector {
            return "LOW — read-only on high-risk connector".to_string();
        }
        return "NONE — read-only operation".to_string();
    }

    if is_high_risk_connector && !changes.is_empty() {
        return "HIGH — mutating operation on infrastructure connector".to_string();
    }

    if is_high_risk_connector {
        return "MEDIUM — infrastructure connector".to_string();
    }

    if changes.is_empty() {
        "LOW — exact replay".to_string()
    } else {
        "MEDIUM — inputs modified".to_string()
    }
}

const fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn format_change(change: &FieldChange) -> String {
    match change.change_type {
        ChangeType::Added => format_value_compact(change.new_value.as_ref()),
        ChangeType::Removed => {
            format!("(was {})", format_value_compact(change.old_value.as_ref()))
        }
        ChangeType::Modified => {
            format!(
                "{} -> {}",
                format_value_compact(change.old_value.as_ref()),
                format_value_compact(change.new_value.as_ref())
            )
        }
    }
}

fn format_value_compact(v: Option<&Value>) -> String {
    match v {
        None => "(none)".to_string(),
        Some(Value::String(s)) => format!("\"{s}\""),
        Some(Value::Null) => "null".to_string(),
        Some(v) => {
            let s = v.to_string();
            if s.len() > 50 {
                format!("{}...", &s[..47])
            } else {
                s
            }
        }
    }
}

fn set_at_path(root: &mut Value, path: &str, value: Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last segment — set the value.
            if let Value::Object(map) = current {
                map.insert(part.to_string(), value);
            }
            return;
        }
        // Navigate or create intermediate objects.
        if !current.is_object() {
            return;
        }
        let map = current.as_object_mut().unwrap();
        if !map.contains_key(*part) {
            map.insert(part.to_string(), Value::Object(serde_json::Map::new()));
        }
        current = map.get_mut(*part).unwrap();
    }
}

fn remove_at_path(root: &mut Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            if let Value::Object(map) = current {
                map.remove(*part);
            }
            return;
        }
        if let Value::Object(map) = current {
            if let Some(next) = map.get_mut(*part) {
                current = next;
            } else {
                return;
            }
        } else {
            return;
        }
    }
}

fn diff_recursive(
    original: &Value,
    modified: &Value,
    prefix: String,
    changes: &mut Vec<FieldChange>,
) {
    match (original, modified) {
        (Value::Object(orig_map), Value::Object(mod_map)) => {
            // Check for modified and removed keys.
            for (key, orig_val) in orig_map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                match mod_map.get(key) {
                    Some(mod_val) => {
                        diff_recursive(orig_val, mod_val, path, changes);
                    }
                    None => {
                        changes.push(FieldChange {
                            path,
                            old_value: Some(orig_val.clone()),
                            new_value: None,
                            change_type: ChangeType::Removed,
                        });
                    }
                }
            }
            // Check for added keys.
            for (key, mod_val) in mod_map {
                if !orig_map.contains_key(key) {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    changes.push(FieldChange {
                        path,
                        old_value: None,
                        new_value: Some(mod_val.clone()),
                        change_type: ChangeType::Added,
                    });
                }
            }
        }
        (a, b) if a != b => {
            let path = if prefix.is_empty() {
                "(root)".to_string()
            } else {
                prefix
            };
            changes.push(FieldChange {
                path,
                old_value: Some(a.clone()),
                new_value: Some(b.clone()),
                change_type: ChangeType::Modified,
            });
        }
        _ => {
            // Values are equal — no change.
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helper factories ────────────────────────────────────────────────

    fn simple_request(entry_id: &str) -> ReplayRequest {
        ReplayRequest {
            history_entry_id: entry_id.to_string(),
            overrides: HashMap::new(),
            dry_run: false,
            skip_preflight: false,
        }
    }

    fn request_with_overrides(entry_id: &str, overrides: HashMap<String, Value>) -> ReplayRequest {
        ReplayRequest {
            history_entry_id: entry_id.to_string(),
            overrides,
            dry_run: false,
            skip_preflight: false,
        }
    }

    fn simple_preview(connector: &str, operation: &str) -> ReplayPreview {
        ReplayPreview {
            original_command: format!("{connector}/{operation}"),
            modified_command: format!("{connector}/{operation}"),
            changes: Vec::new(),
            risk_assessment: "NONE".to_string(),
            connector: connector.to_string(),
            operation: operation.to_string(),
            original_inputs: json!({}),
            modified_inputs: json!({}),
        }
    }

    fn simple_outcome(success: bool) -> ReplayOutcome {
        ReplayOutcome {
            success,
            original_id: "orig-123".to_string(),
            new_id: "new-456".to_string(),
            duration: Duration::from_millis(100),
            output: if success {
                json!({"result": "ok"})
            } else {
                json!({"error": "something failed"})
            },
        }
    }

    // ── apply_field_overrides tests ─────────────────────────────────────

    #[test]
    fn apply_overrides_empty() {
        let original = json!({"key": "value"});
        let overrides = HashMap::new();
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn apply_overrides_simple_field() {
        let original = json!({"name": "Alice"});
        let mut overrides = HashMap::new();
        overrides.insert("name".to_string(), json!("Bob"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["name"], "Bob");
    }

    #[test]
    fn apply_overrides_add_field() {
        let original = json!({"name": "Alice"});
        let mut overrides = HashMap::new();
        overrides.insert("email".to_string(), json!("alice@example.com"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["email"], "alice@example.com");
        assert_eq!(result["name"], "Alice");
    }

    #[test]
    fn apply_overrides_remove_field() {
        let original = json!({"name": "Alice", "age": 30});
        let mut overrides = HashMap::new();
        overrides.insert("age".to_string(), Value::Null);
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert!(result.get("age").is_none());
        assert_eq!(result["name"], "Alice");
    }

    #[test]
    fn apply_overrides_nested_field() {
        let original = json!({"user": {"name": "Alice", "email": "old@example.com"}});
        let mut overrides = HashMap::new();
        overrides.insert("user.email".to_string(), json!("new@example.com"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["user"]["email"], "new@example.com");
        assert_eq!(result["user"]["name"], "Alice");
    }

    #[test]
    fn apply_overrides_deeply_nested() {
        let original = json!({"a": {"b": {"c": "old"}}});
        let mut overrides = HashMap::new();
        overrides.insert("a.b.c".to_string(), json!("new"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["a"]["b"]["c"], "new");
    }

    #[test]
    fn apply_overrides_create_nested_path() {
        let original = json!({"name": "Alice"});
        let mut overrides = HashMap::new();
        overrides.insert("address.city".to_string(), json!("NYC"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["address"]["city"], "NYC");
    }

    #[test]
    fn apply_overrides_remove_nested() {
        let original = json!({"user": {"name": "Alice", "age": 30}});
        let mut overrides = HashMap::new();
        overrides.insert("user.age".to_string(), Value::Null);
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert!(result["user"].get("age").is_none());
        assert_eq!(result["user"]["name"], "Alice");
    }

    #[test]
    fn apply_overrides_to_null_creates_object() {
        let original = Value::Null;
        let mut overrides = HashMap::new();
        overrides.insert("key".to_string(), json!("value"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["key"], "value");
    }

    #[test]
    fn apply_overrides_non_object_error() {
        let original = json!("just a string");
        let mut overrides = HashMap::new();
        overrides.insert("key".to_string(), json!("value"));
        let err = apply_field_overrides(&original, &overrides).unwrap_err();
        assert!(err.contains("non-object"));
    }

    #[test]
    fn apply_overrides_array_error() {
        let original = json!([1, 2, 3]);
        let mut overrides = HashMap::new();
        overrides.insert("key".to_string(), json!("value"));
        let err = apply_field_overrides(&original, &overrides).unwrap_err();
        assert!(err.contains("non-object"));
    }

    #[test]
    fn apply_overrides_multiple_fields() {
        let original = json!({"a": 1, "b": 2, "c": 3});
        let mut overrides = HashMap::new();
        overrides.insert("a".to_string(), json!(10));
        overrides.insert("b".to_string(), json!(20));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["a"], 10);
        assert_eq!(result["b"], 20);
        assert_eq!(result["c"], 3);
    }

    #[test]
    fn apply_overrides_change_type() {
        let original = json!({"count": 42});
        let mut overrides = HashMap::new();
        overrides.insert("count".to_string(), json!("forty-two"));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["count"], "forty-two");
    }

    #[test]
    fn apply_overrides_set_to_object() {
        let original = json!({"data": "plain"});
        let mut overrides = HashMap::new();
        overrides.insert("data".to_string(), json!({"nested": true}));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["data"]["nested"], true);
    }

    #[test]
    fn apply_overrides_set_to_array() {
        let original = json!({"tags": []});
        let mut overrides = HashMap::new();
        overrides.insert("tags".to_string(), json!(["a", "b", "c"]));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["tags"], json!(["a", "b", "c"]));
    }

    // ── diff_inputs tests ───────────────────────────────────────────────

    #[test]
    fn diff_identical() {
        let a = json!({"name": "Alice", "age": 30});
        let changes = diff_inputs(&a, &a);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_modified_field() {
        let a = json!({"name": "Alice"});
        let b = json!({"name": "Bob"});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "name");
        assert_eq!(changes[0].change_type, ChangeType::Modified);
        assert_eq!(changes[0].old_value.as_ref().unwrap(), &json!("Alice"));
        assert_eq!(changes[0].new_value.as_ref().unwrap(), &json!("Bob"));
    }

    #[test]
    fn diff_added_field() {
        let a = json!({"name": "Alice"});
        let b = json!({"name": "Alice", "age": 30});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "age");
        assert_eq!(changes[0].change_type, ChangeType::Added);
    }

    #[test]
    fn diff_removed_field() {
        let a = json!({"name": "Alice", "age": 30});
        let b = json!({"name": "Alice"});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "age");
        assert_eq!(changes[0].change_type, ChangeType::Removed);
    }

    #[test]
    fn diff_nested_modification() {
        let a = json!({"user": {"name": "Alice"}});
        let b = json!({"user": {"name": "Bob"}});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "user.name");
    }

    #[test]
    fn diff_nested_addition() {
        let a = json!({"user": {"name": "Alice"}});
        let b = json!({"user": {"name": "Alice", "email": "alice@ex.com"}});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "user.email");
        assert_eq!(changes[0].change_type, ChangeType::Added);
    }

    #[test]
    fn diff_nested_removal() {
        let a = json!({"user": {"name": "Alice", "age": 30}});
        let b = json!({"user": {"name": "Alice"}});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "user.age");
        assert_eq!(changes[0].change_type, ChangeType::Removed);
    }

    #[test]
    fn diff_multiple_changes() {
        let a = json!({"a": 1, "b": 2, "c": 3});
        let b = json!({"a": 10, "c": 3, "d": 4});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 3); // a modified, b removed, d added
        let types: Vec<ChangeType> = changes.iter().map(|c| c.change_type).collect();
        assert!(types.contains(&ChangeType::Modified));
        assert!(types.contains(&ChangeType::Removed));
        assert!(types.contains(&ChangeType::Added));
    }

    #[test]
    fn diff_deep_nesting() {
        let a = json!({"a": {"b": {"c": {"d": "old"}}}});
        let b = json!({"a": {"b": {"c": {"d": "new"}}}});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "a.b.c.d");
    }

    #[test]
    fn diff_empty_objects() {
        let a = json!({});
        let b = json!({});
        let changes = diff_inputs(&a, &b);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_from_empty_to_populated() {
        let a = json!({});
        let b = json!({"key": "value"});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Added);
    }

    #[test]
    fn diff_from_populated_to_empty() {
        let a = json!({"key": "value"});
        let b = json!({});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Removed);
    }

    #[test]
    fn diff_type_change() {
        let a = json!({"val": 42});
        let b = json!({"val": "forty-two"});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Modified);
    }

    #[test]
    fn diff_sorted_by_path() {
        let a = json!({"z": 1, "a": 2, "m": 3});
        let b = json!({"z": 10, "a": 20, "m": 30});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].path, "a");
        assert_eq!(changes[1].path, "m");
        assert_eq!(changes[2].path, "z");
    }

    #[test]
    fn diff_array_treated_as_value() {
        let a = json!({"tags": ["a", "b"]});
        let b = json!({"tags": ["a", "b", "c"]});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "tags");
        assert_eq!(changes[0].change_type, ChangeType::Modified);
    }

    #[test]
    fn diff_scalar_root_values() {
        let a = json!(42);
        let b = json!(43);
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "(root)");
    }

    #[test]
    fn diff_scalar_equal() {
        let a = json!(42);
        let changes = diff_inputs(&a, &a);
        assert!(changes.is_empty());
    }

    // ── is_replay_safe tests ────────────────────────────────────────────

    #[test]
    fn safe_read_operations() {
        assert!(is_replay_safe("github", "list_repos"));
        assert!(is_replay_safe("github", "get_user"));
        assert!(is_replay_safe("slack", "search_messages"));
        assert!(is_replay_safe("jira", "query_issues"));
        assert!(is_replay_safe("any", "describe_instance"));
        assert!(is_replay_safe("api", "health_check"));
    }

    #[test]
    fn unsafe_destructive_operations() {
        assert!(!is_replay_safe("github", "delete_repo"));
        assert!(!is_replay_safe("slack", "remove_user"));
        assert!(!is_replay_safe("aws", "destroy_instance"));
        assert!(!is_replay_safe("db", "drop_table"));
        assert!(!is_replay_safe("cache", "purge_all"));
        assert!(!is_replay_safe("auth", "revoke_token"));
    }

    #[test]
    fn high_risk_connectors_default_unsafe() {
        // Unknown operation on high-risk connector defaults to unsafe.
        assert!(!is_replay_safe("terraform", "apply_plan"));
        assert!(!is_replay_safe("kubernetes", "scale_deployment"));
        assert!(!is_replay_safe("aws", "create_instance"));
    }

    #[test]
    fn high_risk_read_operations_are_safe() {
        assert!(is_replay_safe("terraform", "list_resources"));
        assert!(is_replay_safe("kubernetes", "get_pod"));
        assert!(is_replay_safe("aws", "describe_instances"));
    }

    #[test]
    fn normal_connector_unknown_op_is_safe() {
        assert!(is_replay_safe("github", "some_unknown_op"));
        assert!(is_replay_safe("slack", "custom_action"));
    }

    // ── validate_replay tests ───────────────────────────────────────────

    #[test]
    fn validate_safe_read_operation() {
        let preview = simple_preview("github", "list_repos");
        let v = validate_replay(&preview);
        assert!(v.valid);
        assert!(v.blockers.is_empty());
    }

    #[test]
    fn validate_destructive_operation_blocked() {
        let preview = simple_preview("github", "delete_repo");
        let v = validate_replay(&preview);
        assert!(!v.valid);
        assert!(!v.blockers.is_empty());
        assert!(v.blockers[0].contains("destructive"));
    }

    #[test]
    fn validate_high_risk_connector_warning() {
        let preview = simple_preview("terraform", "list_resources");
        let v = validate_replay(&preview);
        assert!(v.valid);
        assert!(v.warnings.iter().any(|w| w.contains("high-risk")));
    }

    #[test]
    fn validate_many_changes_warning() {
        let mut preview = simple_preview("github", "update_issue");
        preview.changes = (0..15)
            .map(|i| FieldChange {
                path: format!("field_{i}"),
                old_value: Some(json!(i)),
                new_value: Some(json!(i + 100)),
                change_type: ChangeType::Modified,
            })
            .collect();
        let v = validate_replay(&preview);
        assert!(v.warnings.iter().any(|w| w.contains("field changes")));
    }

    #[test]
    fn validate_additions_warning() {
        let mut preview = simple_preview("github", "update_issue");
        preview.changes = vec![FieldChange {
            path: "new_field".to_string(),
            old_value: None,
            new_value: Some(json!("new")),
            change_type: ChangeType::Added,
        }];
        let v = validate_replay(&preview);
        assert!(v.warnings.iter().any(|w| w.contains("new field")));
    }

    #[test]
    fn validate_removals_warning() {
        let mut preview = simple_preview("github", "update_issue");
        preview.changes = vec![FieldChange {
            path: "old_field".to_string(),
            old_value: Some(json!("old")),
            new_value: None,
            change_type: ChangeType::Removed,
        }];
        let v = validate_replay(&preview);
        assert!(v.warnings.iter().any(|w| w.contains("removed")));
    }

    #[test]
    fn validate_no_issues() {
        let preview = simple_preview("slack", "list_channels");
        let v = validate_replay(&preview);
        assert!(v.valid);
        assert!(v.warnings.is_empty());
        assert!(v.blockers.is_empty());
    }

    // ── build_replay_preview tests ──────────────────────────────────────

    #[test]
    fn build_preview_no_overrides() {
        let inputs = json!({"query": "test"});
        let overrides = HashMap::new();
        let p = build_replay_preview("entry-1", "github", "search_repos", &inputs, &overrides);
        assert_eq!(p.connector, "github");
        assert_eq!(p.operation, "search_repos");
        assert!(p.changes.is_empty());
        assert_eq!(p.original_inputs, inputs);
        assert_eq!(p.modified_inputs, inputs);
    }

    #[test]
    fn build_preview_with_overrides() {
        let inputs = json!({"query": "old"});
        let mut overrides = HashMap::new();
        overrides.insert("query".to_string(), json!("new"));
        let p = build_replay_preview("entry-1", "github", "search_repos", &inputs, &overrides);
        assert_eq!(p.changes.len(), 1);
        assert_eq!(p.modified_inputs["query"], "new");
    }

    #[test]
    fn build_preview_risk_assessment_safe() {
        let inputs = json!({});
        let overrides = HashMap::new();
        let p = build_replay_preview("e1", "github", "list_repos", &inputs, &overrides);
        assert!(p.risk_assessment.contains("NONE"));
    }

    #[test]
    fn build_preview_risk_assessment_destructive() {
        let inputs = json!({});
        let overrides = HashMap::new();
        let p = build_replay_preview("e1", "github", "delete_repo", &inputs, &overrides);
        assert!(p.risk_assessment.contains("HIGH"));
    }

    #[test]
    fn build_preview_modified_command_shows_overrides() {
        let inputs = json!({"a": 1});
        let mut overrides = HashMap::new();
        overrides.insert("a".to_string(), json!(2));
        let p = build_replay_preview("e1", "github", "update_issue", &inputs, &overrides);
        assert!(p.modified_command.contains("overrides"));
    }

    // ── ReplayPolicy tests ─────────────────────────────────────────────

    #[test]
    fn policy_exact_replay() {
        let r = simple_request("e1");
        assert_eq!(determine_policy(&r), ReplayPolicy::ExactReplay);
    }

    #[test]
    fn policy_override_inputs() {
        let mut overrides = HashMap::new();
        overrides.insert("key".to_string(), json!("val"));
        let r = request_with_overrides("e1", overrides);
        assert_eq!(determine_policy(&r), ReplayPolicy::OverrideInputs);
    }

    #[test]
    fn policy_as_str() {
        assert_eq!(ReplayPolicy::ExactReplay.as_str(), "exact_replay");
        assert_eq!(ReplayPolicy::OverrideInputs.as_str(), "override_inputs");
        assert_eq!(ReplayPolicy::CloneAndModify.as_str(), "clone_and_modify");
    }

    #[test]
    fn policy_allows_overrides() {
        assert!(!ReplayPolicy::ExactReplay.allows_overrides());
        assert!(ReplayPolicy::OverrideInputs.allows_overrides());
        assert!(ReplayPolicy::CloneAndModify.allows_overrides());
    }

    #[test]
    fn policy_display() {
        assert_eq!(ReplayPolicy::ExactReplay.to_string(), "exact_replay");
    }

    // ── ReplayValidation tests ──────────────────────────────────────────

    #[test]
    fn validation_ok() {
        let v = ReplayValidation::ok();
        assert!(v.valid);
        assert!(v.warnings.is_empty());
        assert!(v.blockers.is_empty());
    }

    #[test]
    fn validation_blocked() {
        let v = ReplayValidation::blocked("cannot proceed");
        assert!(!v.valid);
        assert_eq!(v.blockers.len(), 1);
    }

    #[test]
    fn validation_add_warning() {
        let mut v = ReplayValidation::ok();
        v.add_warning("be careful");
        assert!(v.valid);
        assert_eq!(v.warnings.len(), 1);
    }

    #[test]
    fn validation_add_blocker() {
        let mut v = ReplayValidation::ok();
        v.add_blocker("cannot do this");
        assert!(!v.valid);
        assert_eq!(v.blockers.len(), 1);
    }

    // ── Formatting tests ────────────────────────────────────────────────

    #[test]
    fn format_preview_no_changes() {
        let p = simple_preview("github", "list_repos");
        let formatted = format_preview(&p);
        assert!(formatted.contains("Replay Preview"));
        assert!(formatted.contains("github"));
        assert!(formatted.contains("list_repos"));
        assert!(formatted.contains("No input changes"));
    }

    #[test]
    fn format_preview_with_changes() {
        let mut p = simple_preview("github", "update_issue");
        p.changes = vec![FieldChange {
            path: "title".to_string(),
            old_value: Some(json!("old title")),
            new_value: Some(json!("new title")),
            change_type: ChangeType::Modified,
        }];
        let formatted = format_preview(&p);
        assert!(formatted.contains("Changes (1)"));
        assert!(formatted.contains("title"));
        assert!(formatted.contains('~'));
    }

    #[test]
    fn format_preview_added_field() {
        let mut p = simple_preview("github", "update_issue");
        p.changes = vec![FieldChange {
            path: "labels".to_string(),
            old_value: None,
            new_value: Some(json!(["bug"])),
            change_type: ChangeType::Added,
        }];
        let formatted = format_preview(&p);
        assert!(formatted.contains('+'));
    }

    #[test]
    fn format_preview_removed_field() {
        let mut p = simple_preview("github", "update_issue");
        p.changes = vec![FieldChange {
            path: "assignee".to_string(),
            old_value: Some(json!("alice")),
            new_value: None,
            change_type: ChangeType::Removed,
        }];
        let formatted = format_preview(&p);
        assert!(formatted.contains('-'));
        assert!(formatted.contains("was"));
    }

    #[test]
    fn format_outcome_success() {
        let o = simple_outcome(true);
        let formatted = format_outcome(&o);
        assert!(formatted.contains("SUCCESS"));
        assert!(formatted.contains("orig-123"));
        assert!(formatted.contains("new-456"));
    }

    #[test]
    fn format_outcome_failure() {
        let o = simple_outcome(false);
        let formatted = format_outcome(&o);
        assert!(formatted.contains("FAILED"));
        assert!(formatted.contains("something failed"));
    }

    #[test]
    fn format_outcome_duration() {
        let o = simple_outcome(true);
        let formatted = format_outcome(&o);
        assert!(formatted.contains("100ms"));
    }

    #[test]
    fn format_validation_pass() {
        let v = ReplayValidation::ok();
        let formatted = format_validation(&v);
        assert!(formatted.contains("PASS"));
    }

    #[test]
    fn format_validation_blocked() {
        let v = ReplayValidation::blocked("not allowed");
        let formatted = format_validation(&v);
        assert!(formatted.contains("BLOCKED"));
        assert!(formatted.contains("not allowed"));
    }

    #[test]
    fn format_validation_with_warnings() {
        let mut v = ReplayValidation::ok();
        v.add_warning("warning one");
        let formatted = format_validation(&v);
        assert!(formatted.contains("Warnings"));
        assert!(formatted.contains("warning one"));
    }

    // ── ChangeType tests ────────────────────────────────────────────────

    #[test]
    fn change_type_display() {
        assert_eq!(ChangeType::Added.to_string(), "added");
        assert_eq!(ChangeType::Modified.to_string(), "modified");
        assert_eq!(ChangeType::Removed.to_string(), "removed");
    }

    // ── Serialization roundtrip tests ───────────────────────────────────

    #[test]
    fn replay_request_serde() {
        let r = simple_request("entry-1");
        let json = serde_json::to_string(&r).unwrap();
        let deser: ReplayRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.history_entry_id, "entry-1");
        assert!(!deser.dry_run);
    }

    #[test]
    fn replay_preview_serde() {
        let p = simple_preview("github", "list_repos");
        let json = serde_json::to_string(&p).unwrap();
        let deser: ReplayPreview = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.connector, "github");
    }

    #[test]
    fn replay_outcome_serde() {
        let o = simple_outcome(true);
        let json = serde_json::to_string(&o).unwrap();
        let deser: ReplayOutcome = serde_json::from_str(&json).unwrap();
        assert!(deser.success);
    }

    #[test]
    fn replay_policy_serde() {
        let p = ReplayPolicy::OverrideInputs;
        let json = serde_json::to_string(&p).unwrap();
        let deser: ReplayPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, ReplayPolicy::OverrideInputs);
    }

    #[test]
    fn field_change_serde() {
        let c = FieldChange {
            path: "name".to_string(),
            old_value: Some(json!("old")),
            new_value: Some(json!("new")),
            change_type: ChangeType::Modified,
        };
        let json = serde_json::to_string(&c).unwrap();
        let deser: FieldChange = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.path, "name");
    }

    #[test]
    fn replay_validation_serde() {
        let mut v = ReplayValidation::ok();
        v.add_warning("caution");
        let json = serde_json::to_string(&v).unwrap();
        let deser: ReplayValidation = serde_json::from_str(&json).unwrap();
        assert!(deser.valid);
        assert_eq!(deser.warnings.len(), 1);
    }

    // ── Edge case tests ─────────────────────────────────────────────────

    #[test]
    fn apply_overrides_boolean_value() {
        let original = json!({"enabled": false});
        let mut overrides = HashMap::new();
        overrides.insert("enabled".to_string(), json!(true));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["enabled"], true);
    }

    #[test]
    fn apply_overrides_numeric_value() {
        let original = json!({"count": 0});
        let mut overrides = HashMap::new();
        overrides.insert("count".to_string(), json!(999));
        let result = apply_field_overrides(&original, &overrides).unwrap();
        assert_eq!(result["count"], 999);
    }

    #[test]
    fn diff_boolean_change() {
        let a = json!({"enabled": true});
        let b = json!({"enabled": false});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "enabled");
    }

    #[test]
    fn diff_null_to_value() {
        let a = json!({"field": null});
        let b = json!({"field": "now set"});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Modified);
    }

    #[test]
    fn diff_value_to_null() {
        let a = json!({"field": "was set"});
        let b = json!({"field": null});
        let changes = diff_inputs(&a, &b);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Modified);
    }

    #[test]
    fn is_replay_safe_case_insensitive() {
        assert!(is_replay_safe("GitHub", "List_Repos"));
        assert!(!is_replay_safe("GITHUB", "DELETE_REPO"));
    }

    #[test]
    fn is_replay_safe_partial_match() {
        // "get_all_users" contains "get"
        assert!(is_replay_safe("any", "get_all_users"));
        // "delete_old_data" contains "delete"
        assert!(!is_replay_safe("any", "delete_old_data"));
    }

    #[test]
    fn replay_request_dry_run() {
        let r = ReplayRequest {
            history_entry_id: "e1".to_string(),
            overrides: HashMap::new(),
            dry_run: true,
            skip_preflight: false,
        };
        assert!(r.dry_run);
    }

    #[test]
    fn replay_request_skip_preflight() {
        let r = ReplayRequest {
            history_entry_id: "e1".to_string(),
            overrides: HashMap::new(),
            dry_run: false,
            skip_preflight: true,
        };
        assert!(r.skip_preflight);
    }

    #[test]
    fn value_type_name_coverage() {
        assert_eq!(value_type_name(&Value::Null), "null");
        assert_eq!(value_type_name(&json!(true)), "boolean");
        assert_eq!(value_type_name(&json!(42)), "number");
        assert_eq!(value_type_name(&json!("str")), "string");
        assert_eq!(value_type_name(&json!([1])), "array");
        assert_eq!(value_type_name(&json!({})), "object");
    }

    #[test]
    fn format_change_added() {
        let c = FieldChange {
            path: "new".to_string(),
            old_value: None,
            new_value: Some(json!("value")),
            change_type: ChangeType::Added,
        };
        let formatted = format_change(&c);
        assert!(formatted.contains("value"));
    }

    #[test]
    fn format_change_removed() {
        let c = FieldChange {
            path: "old".to_string(),
            old_value: Some(json!("gone")),
            new_value: None,
            change_type: ChangeType::Removed,
        };
        let formatted = format_change(&c);
        assert!(formatted.contains("was"));
    }

    #[test]
    fn format_change_modified() {
        let c = FieldChange {
            path: "field".to_string(),
            old_value: Some(json!("old")),
            new_value: Some(json!("new")),
            change_type: ChangeType::Modified,
        };
        let formatted = format_change(&c);
        assert!(formatted.contains("->"));
    }

    #[test]
    fn format_value_compact_long_string() {
        let long_val = json!({"key": "a".repeat(100)});
        let formatted = format_value_compact(Some(&long_val));
        assert!(formatted.len() <= 53); // 50 + "..."
    }

    #[test]
    fn format_value_compact_none() {
        let formatted = format_value_compact(None);
        assert_eq!(formatted, "(none)");
    }

    #[test]
    fn format_value_compact_null() {
        let formatted = format_value_compact(Some(&Value::Null));
        assert_eq!(formatted, "null");
    }

    #[test]
    fn assess_risk_read_on_normal() {
        let risk = assess_risk("github", "list_repos", &[]);
        assert!(risk.contains("NONE"));
    }

    #[test]
    fn assess_risk_read_on_high_risk() {
        let risk = assess_risk("terraform", "list_resources", &[]);
        assert!(risk.contains("LOW"));
    }

    #[test]
    fn assess_risk_mutating_on_high_risk() {
        let changes = vec![FieldChange {
            path: "replicas".to_string(),
            old_value: Some(json!(1)),
            new_value: Some(json!(3)),
            change_type: ChangeType::Modified,
        }];
        let risk = assess_risk("kubernetes", "scale_deployment", &changes);
        assert!(risk.contains("HIGH"));
    }

    #[test]
    fn assess_risk_unknown_op_no_changes() {
        let risk = assess_risk("github", "custom_op", &[]);
        assert!(risk.contains("LOW"));
    }

    #[test]
    fn assess_risk_unknown_op_with_changes() {
        let changes = vec![FieldChange {
            path: "field".to_string(),
            old_value: Some(json!(1)),
            new_value: Some(json!(2)),
            change_type: ChangeType::Modified,
        }];
        let risk = assess_risk("github", "custom_op", &changes);
        assert!(risk.contains("MEDIUM"));
    }

    #[test]
    fn build_preview_preserves_original() {
        let inputs = json!({"key": "original"});
        let mut overrides = HashMap::new();
        overrides.insert("key".to_string(), json!("modified"));
        let p = build_replay_preview("e1", "github", "update", &inputs, &overrides);
        assert_eq!(p.original_inputs["key"], "original");
        assert_eq!(p.modified_inputs["key"], "modified");
    }

    #[test]
    fn validate_multiple_blockers() {
        let mut v = ReplayValidation::ok();
        v.add_blocker("issue one");
        v.add_blocker("issue two");
        assert!(!v.valid);
        assert_eq!(v.blockers.len(), 2);
    }

    #[test]
    fn validate_multiple_warnings() {
        let mut v = ReplayValidation::ok();
        v.add_warning("warn one");
        v.add_warning("warn two");
        v.add_warning("warn three");
        assert!(v.valid);
        assert_eq!(v.warnings.len(), 3);
    }
}
