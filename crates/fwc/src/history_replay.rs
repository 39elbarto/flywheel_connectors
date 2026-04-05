//! History replay, clone, and input-override flows.
//!
//! Builds on the low-level `replay` module to provide higher-level abstractions
//! for replaying operations with input overrides, comparing history entries, and
//! rendering TOON-formatted diffs and plans.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Risk level (self-contained) ─────────────────────────────────────────────

/// Operation risk level, mirroring `fcp_core::RiskLevel` but self-contained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Whether this risk level requires explicit approval before replay.
    #[must_use]
    pub const fn requires_approval(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    /// Canonical string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Core types ──────────────────────────────────────────────────────────────

/// Reference to a historical operation with full context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryRef {
    /// Unique identifier for the history entry.
    pub entry_id: String,
    /// Connector that was invoked.
    pub connector: String,
    /// Operation within the connector.
    pub operation: String,
    /// The original input payload.
    pub original_input: Value,
    /// The original output payload (if captured).
    pub original_output: Option<Value>,
    /// ISO-8601 timestamp of the invocation.
    pub timestamp: String,
}

/// A field-level input override.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputOverride {
    /// Dot-notation path to the field (e.g. `"config.timeout"`).
    pub field_path: String,
    /// The old value at that path.
    pub old_value: Value,
    /// The new value to set.
    pub new_value: Value,
}

/// A single line in a diff view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiffLine {
    /// A field/value was added.
    Added { path: String, value: Value },
    /// A field/value was removed.
    Removed { path: String, value: Value },
    /// A field/value was changed.
    Changed {
        path: String,
        old: Value,
        new: Value,
    },
    /// A field/value was unchanged.
    Unchanged { path: String, value: Value },
}

/// A replay plan describing what will happen when an operation is replayed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayPlan {
    /// Reference to the original operation.
    pub source: HistoryRef,
    /// Field-level input overrides to apply.
    pub overrides: Vec<InputOverride>,
    /// Preview of what changed between original and effective input.
    pub diff: Vec<DiffLine>,
    /// Whether the operation requires explicit approval (destructive ops).
    pub requires_approval: bool,
    /// Estimated risk level from the source operation.
    pub estimated_risk: RiskLevel,
}

/// Result of comparing two history entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompareResult {
    /// The entries being compared.
    pub entries: Vec<HistoryRef>,
    /// Diff between the input payloads.
    pub input_diff: Vec<DiffLine>,
    /// Diff between the output payloads.
    pub output_diff: Vec<DiffLine>,
    /// Metadata differences: `(field_name, left_value, right_value)`.
    pub metadata_diff: Vec<(String, String, String)>,
}

// ── Override parsing ────────────────────────────────────────────────────────

/// Parse an override string in `"field.path=newvalue"` format.
///
/// Values that parse as valid JSON are used as-is; otherwise they are treated
/// as plain strings.
///
/// # Errors
///
/// Returns an error if the string has no `=` separator or the key is empty.
pub fn parse_override(s: &str) -> Result<InputOverride, String> {
    let Some((key, raw_value)) = s.split_once('=') else {
        return Err(format!("missing `=` separator in override: {s}"));
    };

    let key = key.trim();
    if key.is_empty() {
        return Err(format!("empty key in override: {s}"));
    }

    let raw_value = raw_value.trim();
    let new_value: Value =
        serde_json::from_str(raw_value).unwrap_or(Value::String(raw_value.to_owned()));

    Ok(InputOverride {
        field_path: key.to_owned(),
        old_value: Value::Null, // Will be filled in when applying against a concrete input.
        new_value,
    })
}

// ── Override application ────────────────────────────────────────────────────

/// Apply a set of input overrides to a JSON value.
///
/// Supports dot-notation paths for nested fields and numeric segments for
/// array indices. Creates intermediate objects as needed.
///
/// # Errors
///
/// Returns an error if a path segment tries to traverse a non-object/non-array
/// value, or if an array index is out of bounds.
pub fn apply_overrides(input: &Value, overrides: &[InputOverride]) -> Result<Value, String> {
    let mut result = input.clone();

    for ov in overrides {
        set_at_path(&mut result, &ov.field_path, ov.new_value.clone())
            .map_err(|e| format!("failed to apply override at `{}`: {e}", ov.field_path))?;
    }

    Ok(result)
}

/// Get the value at a dot-notation path in a JSON value.
fn get_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut current = root;

    for segment in &segments {
        if let Ok(idx) = segment.parse::<usize>() {
            current = current.as_array()?.get(idx)?;
        } else {
            current = current.as_object()?.get(*segment)?;
        }
    }

    Some(current)
}

/// Set a value at a dot-notation path, creating intermediate objects/arrays.
fn set_at_path(root: &mut Value, path: &str, value: Value) -> Result<(), String> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return Err("empty path".to_owned());
    }

    let mut current = root;

    for (i, segment) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;

        if let Ok(idx) = segment.parse::<usize>() {
            // Array index access.
            if is_last {
                match current {
                    Value::Array(arr) => {
                        if idx < arr.len() {
                            arr[idx] = value;
                            return Ok(());
                        }
                        // Extend the array with nulls and set.
                        while arr.len() <= idx {
                            arr.push(Value::Null);
                        }
                        arr[idx] = value;
                        return Ok(());
                    }
                    Value::Null => {
                        let mut arr = vec![Value::Null; idx + 1];
                        arr[idx] = value;
                        *current = Value::Array(arr);
                        return Ok(());
                    }
                    _ => {
                        return Err(format!(
                            "cannot index into non-array at segment `{segment}`"
                        ));
                    }
                }
            }
            // Intermediate array access.
            match current {
                Value::Array(arr) => {
                    if idx >= arr.len() {
                        while arr.len() <= idx {
                            arr.push(Value::Null);
                        }
                    }
                    current = &mut arr[idx];
                }
                Value::Null => {
                    let arr = vec![Value::Null; idx + 1];
                    *current = Value::Array(arr);
                    if let Value::Array(arr) = current {
                        current = &mut arr[idx];
                    }
                }
                _ => {
                    return Err(format!(
                        "cannot traverse array index `{segment}` in non-array"
                    ));
                }
            }
        } else {
            // Object key access.
            if is_last {
                match current {
                    Value::Object(map) => {
                        map.insert((*segment).to_owned(), value);
                        return Ok(());
                    }
                    Value::Null => {
                        *current = serde_json::json!({});
                        if let Value::Object(map) = current {
                            map.insert((*segment).to_owned(), value);
                        }
                        return Ok(());
                    }
                    _ => return Err(format!("cannot set key `{segment}` on non-object value")),
                }
            }
            // Intermediate object key.
            match current {
                Value::Object(map) => {
                    current = map
                        .entry((*segment).to_owned())
                        .or_insert_with(|| serde_json::json!({}));
                }
                Value::Null => {
                    *current = serde_json::json!({});
                    if let Value::Object(map) = current {
                        current = map
                            .entry((*segment).to_owned())
                            .or_insert_with(|| serde_json::json!({}));
                    }
                }
                _ => {
                    return Err(format!(
                        "cannot traverse key `{segment}` in non-object value"
                    ));
                }
            }
        }
    }

    Ok(())
}

// ── Replay plan construction ────────────────────────────────────────────────

/// Build a replay plan from a history reference and overrides.
///
/// Populates each override's `old_value` from the original input, computes the
/// diff between the original and effective input, and determines whether
/// approval is required based on the risk level.
pub fn build_replay_plan(entry: &HistoryRef, overrides: &[InputOverride]) -> ReplayPlan {
    // Fill in old_value for each override from original input.
    let filled_overrides: Vec<InputOverride> = overrides
        .iter()
        .map(|ov| {
            let old = get_at_path(&entry.original_input, &ov.field_path)
                .cloned()
                .unwrap_or(Value::Null);
            InputOverride {
                field_path: ov.field_path.clone(),
                old_value: old,
                new_value: ov.new_value.clone(),
            }
        })
        .collect();

    // Compute effective input.
    let effective = apply_overrides(&entry.original_input, &filled_overrides)
        .unwrap_or_else(|_| entry.original_input.clone());

    // Build diff between original and effective.
    let diff = diff_values(&entry.original_input, &effective, "");

    // Determine risk — default to Low if unknown.
    let risk = infer_risk_level(&entry.connector, &entry.operation);

    ReplayPlan {
        source: entry.clone(),
        overrides: filled_overrides,
        diff,
        requires_approval: risk.requires_approval(),
        estimated_risk: risk,
    }
}

/// Infer risk level based on connector and operation names.
///
/// Operations containing destructive keywords get higher risk levels.
fn infer_risk_level(connector: &str, operation: &str) -> RiskLevel {
    let op_lower = operation.to_lowercase();
    let conn_lower = connector.to_lowercase();

    // Critical: destructive operations on production-grade connectors.
    if op_lower.contains("delete") || op_lower.contains("destroy") || op_lower.contains("drop") {
        if conn_lower.contains("prod") || conn_lower.contains("terraform") {
            return RiskLevel::Critical;
        }
        return RiskLevel::High;
    }

    // High: mutations.
    if op_lower.contains("update") || op_lower.contains("patch") || op_lower.contains("put") {
        return RiskLevel::Medium;
    }

    // Medium: creation.
    if op_lower.contains("create") || op_lower.contains("post") || op_lower.contains("send") {
        return RiskLevel::Medium;
    }

    // Default: read-only operations.
    RiskLevel::Low
}

// ── Entry comparison ────────────────────────────────────────────────────────

/// Compare two history entries, producing diffs of inputs, outputs, and metadata.
pub fn compare_entries(a: &HistoryRef, b: &HistoryRef) -> CompareResult {
    let input_diff = diff_values(&a.original_input, &b.original_input, "");

    let output_a = a.original_output.clone().unwrap_or(Value::Null);
    let output_b = b.original_output.clone().unwrap_or(Value::Null);
    let output_diff = diff_values(&output_a, &output_b, "");

    let mut metadata_diff = Vec::new();

    if a.connector != b.connector {
        metadata_diff.push((
            "connector".to_owned(),
            a.connector.clone(),
            b.connector.clone(),
        ));
    }
    if a.operation != b.operation {
        metadata_diff.push((
            "operation".to_owned(),
            a.operation.clone(),
            b.operation.clone(),
        ));
    }
    if a.timestamp != b.timestamp {
        metadata_diff.push((
            "timestamp".to_owned(),
            a.timestamp.clone(),
            b.timestamp.clone(),
        ));
    }
    if a.entry_id != b.entry_id {
        metadata_diff.push((
            "entry_id".to_owned(),
            a.entry_id.clone(),
            b.entry_id.clone(),
        ));
    }

    CompareResult {
        entries: vec![a.clone(), b.clone()],
        input_diff,
        output_diff,
        metadata_diff,
    }
}

// ── Diff engine ─────────────────────────────────────────────────────────────

/// Compute structural diff between two JSON values, producing `DiffLine` entries.
fn diff_values(old: &Value, new: &Value, prefix: &str) -> Vec<DiffLine> {
    let mut lines = Vec::new();
    diff_recursive(old, new, prefix, &mut lines);
    lines
}

fn diff_recursive(old: &Value, new: &Value, prefix: &str, lines: &mut Vec<DiffLine>) {
    if old == new {
        // Emit unchanged leaf nodes (not containers, to avoid noise).
        match old {
            Value::Object(_) | Value::Array(_) => {
                // Recurse into containers to list their leaves as unchanged.
                match old {
                    Value::Object(map) => {
                        for (key, val) in map {
                            let child_path = make_path(prefix, key);
                            diff_recursive(val, val, &child_path, lines);
                        }
                    }
                    Value::Array(arr) => {
                        for (i, val) in arr.iter().enumerate() {
                            let child_path = make_path(prefix, &i.to_string());
                            diff_recursive(val, val, &child_path, lines);
                        }
                    }
                    _ => {}
                }
            }
            _ => {
                lines.push(DiffLine::Unchanged {
                    path: if prefix.is_empty() {
                        "<root>".to_owned()
                    } else {
                        prefix.to_owned()
                    },
                    value: old.clone(),
                });
            }
        }
        return;
    }

    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            // Check removed and modified.
            for (key, old_val) in old_map {
                let child_path = make_path(prefix, key);
                match new_map.get(key) {
                    Some(new_val) => diff_recursive(old_val, new_val, &child_path, lines),
                    None => lines.push(DiffLine::Removed {
                        path: child_path,
                        value: old_val.clone(),
                    }),
                }
            }
            // Check added.
            for (key, new_val) in new_map {
                if !old_map.contains_key(key) {
                    let child_path = make_path(prefix, key);
                    lines.push(DiffLine::Added {
                        path: child_path,
                        value: new_val.clone(),
                    });
                }
            }
        }
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            let max_len = old_arr.len().max(new_arr.len());
            for i in 0..max_len {
                let child_path = make_path(prefix, &i.to_string());
                match (old_arr.get(i), new_arr.get(i)) {
                    (Some(ov), Some(nv)) => diff_recursive(ov, nv, &child_path, lines),
                    (Some(ov), None) => lines.push(DiffLine::Removed {
                        path: child_path,
                        value: ov.clone(),
                    }),
                    (None, Some(nv)) => lines.push(DiffLine::Added {
                        path: child_path,
                        value: nv.clone(),
                    }),
                    (None, None) => {}
                }
            }
        }
        _ => {
            // Leaf changed.
            let path = if prefix.is_empty() {
                "<root>".to_owned()
            } else {
                prefix.to_owned()
            };
            lines.push(DiffLine::Changed {
                path,
                old: old.clone(),
                new: new.clone(),
            });
        }
    }
}

fn make_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

// ── TOON formatting ─────────────────────────────────────────────────────────

/// Format a diff as a TOON-style string (token-efficient, agent-facing).
pub fn format_diff_toon(diff: &[DiffLine]) -> String {
    let mut out = String::new();
    if diff.is_empty() {
        out.push_str("(no changes)\n");
        return out;
    }

    let mut added = 0usize;
    let mut removed = 0usize;
    let mut changed = 0usize;
    let mut unchanged = 0usize;

    for line in diff {
        match line {
            DiffLine::Added { path, value } => {
                let _ = writeln!(out, "+ {path}: {}", compact_value(value));
                added += 1;
            }
            DiffLine::Removed { path, value } => {
                let _ = writeln!(out, "- {path}: {}", compact_value(value));
                removed += 1;
            }
            DiffLine::Changed { path, old, new } => {
                let _ = writeln!(
                    out,
                    "~ {path}: {} -> {}",
                    compact_value(old),
                    compact_value(new)
                );
                changed += 1;
            }
            DiffLine::Unchanged { .. } => {
                unchanged += 1;
            }
        }
    }

    let _ = writeln!(out, "--- +{added} -{removed} ~{changed} ={unchanged}");
    out
}

/// Format a replay plan as a TOON-style string.
pub fn format_replay_plan_toon(plan: &ReplayPlan) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "REPLAY PLAN");
    let _ = writeln!(
        out,
        "source: {} / {} @ {}",
        plan.source.connector, plan.source.operation, plan.source.entry_id
    );
    let _ = writeln!(out, "risk: {}", plan.estimated_risk);
    let _ = writeln!(out, "approval_required: {}", plan.requires_approval);

    if plan.overrides.is_empty() {
        let _ = writeln!(out, "overrides: (none)");
    } else {
        let _ = writeln!(out, "overrides:");
        for ov in &plan.overrides {
            let _ = writeln!(
                out,
                "  {}: {} -> {}",
                ov.field_path,
                compact_value(&ov.old_value),
                compact_value(&ov.new_value)
            );
        }
    }

    let _ = writeln!(out, "diff:");
    let diff_str = format_diff_toon(&plan.diff);
    for line in diff_str.lines() {
        let _ = writeln!(out, "  {line}");
    }

    out
}

/// Compact JSON value rendering for TOON output.
fn compact_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            if s.len() > 50 {
                format!("\"{}...\"", &s[..47])
            } else {
                format!("\"{s}\"")
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_owned()
            } else {
                format!("[...{}]", arr.len())
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                "{}".to_owned()
            } else {
                let keys: Vec<&str> = map.keys().map(String::as_str).take(3).collect();
                if keys.len() < map.len() {
                    format!("{{{}, ...}}", keys.join(", "))
                } else {
                    format!("{{{}}}", keys.join(", "))
                }
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn sample_ref() -> HistoryRef {
        HistoryRef {
            entry_id: "e001".to_owned(),
            connector: "github".to_owned(),
            operation: "issues.create".to_owned(),
            original_input: json!({
                "title": "Bug report",
                "body": "Something broke",
                "labels": ["bug", "p1"],
                "config": {
                    "timeout": 30,
                    "retry": true
                }
            }),
            original_output: Some(json!({
                "id": 42,
                "url": "https://github.com/repo/issues/42"
            })),
            timestamp: "2026-03-12T10:00:00Z".to_owned(),
        }
    }

    fn sample_ref_b() -> HistoryRef {
        HistoryRef {
            entry_id: "e002".to_owned(),
            connector: "github".to_owned(),
            operation: "issues.create".to_owned(),
            original_input: json!({
                "title": "Feature request",
                "body": "Add dark mode",
                "labels": ["enhancement"],
                "config": {
                    "timeout": 60,
                    "retry": false
                }
            }),
            original_output: Some(json!({
                "id": 43,
                "url": "https://github.com/repo/issues/43"
            })),
            timestamp: "2026-03-12T11:00:00Z".to_owned(),
        }
    }

    fn sample_ref_no_output() -> HistoryRef {
        HistoryRef {
            entry_id: "e003".to_owned(),
            connector: "slack".to_owned(),
            operation: "chat.post".to_owned(),
            original_input: json!({"channel": "#general", "text": "Hello"}),
            original_output: None,
            timestamp: "2026-03-12T12:00:00Z".to_owned(),
        }
    }

    fn sample_ref_delete() -> HistoryRef {
        HistoryRef {
            entry_id: "e004".to_owned(),
            connector: "terraform".to_owned(),
            operation: "resources.delete".to_owned(),
            original_input: json!({"resource_id": "vpc-123"}),
            original_output: Some(json!({"deleted": true})),
            timestamp: "2026-03-12T13:00:00Z".to_owned(),
        }
    }

    fn sample_ref_empty() -> HistoryRef {
        HistoryRef {
            entry_id: "e005".to_owned(),
            connector: "noop".to_owned(),
            operation: "ping".to_owned(),
            original_input: json!({}),
            original_output: Some(json!({})),
            timestamp: "2026-03-12T14:00:00Z".to_owned(),
        }
    }

    // ── parse_override tests ────────────────────────────────────────────

    #[test]
    fn parse_override_simple_string() {
        let ov = parse_override("title=New Title").unwrap();
        assert_eq!(ov.field_path, "title");
        assert_eq!(ov.new_value, json!("New Title"));
    }

    #[test]
    fn parse_override_json_number() {
        let ov = parse_override("config.timeout=60").unwrap();
        assert_eq!(ov.field_path, "config.timeout");
        assert_eq!(ov.new_value, json!(60));
    }

    #[test]
    fn parse_override_json_boolean() {
        let ov = parse_override("config.retry=false").unwrap();
        assert_eq!(ov.field_path, "config.retry");
        assert_eq!(ov.new_value, json!(false));
    }

    #[test]
    fn parse_override_json_null() {
        let ov = parse_override("body=null").unwrap();
        assert_eq!(ov.field_path, "body");
        assert_eq!(ov.new_value, Value::Null);
    }

    #[test]
    fn parse_override_json_array() {
        let ov = parse_override(r#"labels=["bug","p2"]"#).unwrap();
        assert_eq!(ov.field_path, "labels");
        assert_eq!(ov.new_value, json!(["bug", "p2"]));
    }

    #[test]
    fn parse_override_json_object() {
        let ov = parse_override(r#"config={"timeout":120}"#).unwrap();
        assert_eq!(ov.field_path, "config");
        assert_eq!(ov.new_value, json!({"timeout": 120}));
    }

    #[test]
    fn parse_override_nested_path() {
        let ov = parse_override("a.b.c.d=42").unwrap();
        assert_eq!(ov.field_path, "a.b.c.d");
        assert_eq!(ov.new_value, json!(42));
    }

    #[test]
    fn parse_override_whitespace_trimmed() {
        let ov = parse_override("  title  =  hello  ").unwrap();
        assert_eq!(ov.field_path, "title");
        assert_eq!(ov.new_value, json!("hello"));
    }

    #[test]
    fn parse_override_missing_equals() {
        let result = parse_override("no-equals-sign");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing `=` separator"));
    }

    #[test]
    fn parse_override_empty_key() {
        let result = parse_override("=value");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty key"));
    }

    #[test]
    fn parse_override_empty_value_is_string() {
        let ov = parse_override("title=").unwrap();
        assert_eq!(ov.field_path, "title");
        assert_eq!(ov.new_value, json!(""));
    }

    #[test]
    fn parse_override_value_with_equals_sign() {
        let ov = parse_override("query=a=b").unwrap();
        assert_eq!(ov.field_path, "query");
        assert_eq!(ov.new_value, json!("a=b"));
    }

    #[test]
    fn parse_override_old_value_is_null() {
        let ov = parse_override("field=val").unwrap();
        assert_eq!(ov.old_value, Value::Null);
    }

    #[test]
    fn parse_override_json_string_quoted() {
        let ov = parse_override(r#"name="hello world""#).unwrap();
        assert_eq!(ov.new_value, json!("hello world"));
    }

    // ── apply_overrides tests ───────────────────────────────────────────

    #[test]
    fn apply_simple_field() {
        let input = json!({"title": "old"});
        let ov = InputOverride {
            field_path: "title".to_owned(),
            old_value: json!("old"),
            new_value: json!("new"),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["title"], json!("new"));
    }

    #[test]
    fn apply_nested_field() {
        let input = json!({"config": {"timeout": 30}});
        let ov = InputOverride {
            field_path: "config.timeout".to_owned(),
            old_value: json!(30),
            new_value: json!(60),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["config"]["timeout"], json!(60));
    }

    #[test]
    fn apply_deeply_nested() {
        let input = json!({"a": {"b": {"c": {"d": 1}}}});
        let ov = InputOverride {
            field_path: "a.b.c.d".to_owned(),
            old_value: json!(1),
            new_value: json!(999),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["a"]["b"]["c"]["d"], json!(999));
    }

    #[test]
    fn apply_creates_intermediate_objects() {
        let input = json!({});
        let ov = InputOverride {
            field_path: "x.y.z".to_owned(),
            old_value: Value::Null,
            new_value: json!(42),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["x"]["y"]["z"], json!(42));
    }

    #[test]
    fn apply_array_index() {
        let input = json!({"items": [10, 20, 30]});
        let ov = InputOverride {
            field_path: "items.1".to_owned(),
            old_value: json!(20),
            new_value: json!(99),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["items"][1], json!(99));
    }

    #[test]
    fn apply_array_index_extends() {
        let input = json!({"items": [1]});
        let ov = InputOverride {
            field_path: "items.3".to_owned(),
            old_value: Value::Null,
            new_value: json!(42),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        let arr = result["items"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[3], json!(42));
    }

    #[test]
    fn apply_multiple_overrides() {
        let input = json!({"a": 1, "b": 2, "c": 3});
        let ovs = vec![
            InputOverride {
                field_path: "a".to_owned(),
                old_value: json!(1),
                new_value: json!(10),
            },
            InputOverride {
                field_path: "b".to_owned(),
                old_value: json!(2),
                new_value: json!(20),
            },
        ];
        let result = apply_overrides(&input, &ovs).unwrap();
        assert_eq!(result["a"], json!(10));
        assert_eq!(result["b"], json!(20));
        assert_eq!(result["c"], json!(3));
    }

    #[test]
    fn apply_override_adds_new_field() {
        let input = json!({"existing": true});
        let ov = InputOverride {
            field_path: "new_field".to_owned(),
            old_value: Value::Null,
            new_value: json!("added"),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["new_field"], json!("added"));
        assert_eq!(result["existing"], json!(true));
    }

    #[test]
    fn apply_override_to_null_root() {
        let input = Value::Null;
        let ov = InputOverride {
            field_path: "key".to_owned(),
            old_value: Value::Null,
            new_value: json!("value"),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["key"], json!("value"));
    }

    #[test]
    fn apply_override_error_on_scalar_traversal() {
        let input = json!({"a": "string_value"});
        let ov = InputOverride {
            field_path: "a.b".to_owned(),
            old_value: Value::Null,
            new_value: json!(42),
        };
        let result = apply_overrides(&input, &[ov]);
        assert!(result.is_err());
    }

    #[test]
    fn apply_override_empty_overrides() {
        let input = json!({"a": 1});
        let result = apply_overrides(&input, &[]).unwrap();
        assert_eq!(result, json!({"a": 1}));
    }

    #[test]
    fn apply_override_replaces_value_type() {
        let input = json!({"val": 42});
        let ov = InputOverride {
            field_path: "val".to_owned(),
            old_value: json!(42),
            new_value: json!("now a string"),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["val"], json!("now a string"));
    }

    #[test]
    fn apply_override_nested_array_in_object() {
        let input = json!({"data": {"items": [1, 2, 3]}});
        let ov = InputOverride {
            field_path: "data.items.0".to_owned(),
            old_value: json!(1),
            new_value: json!(100),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["data"]["items"][0], json!(100));
    }

    // ── get_at_path tests ───────────────────────────────────────────────

    #[test]
    fn get_at_path_simple() {
        let v = json!({"a": 1});
        assert_eq!(get_at_path(&v, "a"), Some(&json!(1)));
    }

    #[test]
    fn get_at_path_nested() {
        let v = json!({"a": {"b": {"c": 42}}});
        assert_eq!(get_at_path(&v, "a.b.c"), Some(&json!(42)));
    }

    #[test]
    fn get_at_path_array_index() {
        let v = json!({"items": [10, 20, 30]});
        assert_eq!(get_at_path(&v, "items.1"), Some(&json!(20)));
    }

    #[test]
    fn get_at_path_missing() {
        let v = json!({"a": 1});
        assert_eq!(get_at_path(&v, "b"), None);
    }

    #[test]
    fn get_at_path_deep_missing() {
        let v = json!({"a": {"b": 1}});
        assert_eq!(get_at_path(&v, "a.c"), None);
    }

    #[test]
    fn get_at_path_array_out_of_bounds() {
        let v = json!({"items": [1]});
        assert_eq!(get_at_path(&v, "items.5"), None);
    }

    // ── diff_values tests ───────────────────────────────────────────────

    #[test]
    fn diff_identical_values() {
        let v = json!({"a": 1, "b": 2});
        let diff = diff_values(&v, &v, "");
        assert!(diff.iter().all(|d| matches!(d, DiffLine::Unchanged { .. })));
    }

    #[test]
    fn diff_added_field() {
        let old = json!({"a": 1});
        let new = json!({"a": 1, "b": 2});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Added { path, .. } if path == "b"))
        );
    }

    #[test]
    fn diff_removed_field() {
        let old = json!({"a": 1, "b": 2});
        let new = json!({"a": 1});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Removed { path, .. } if path == "b"))
        );
    }

    #[test]
    fn diff_changed_field() {
        let old = json!({"a": 1});
        let new = json!({"a": 2});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Changed { path, .. } if path == "a"))
        );
    }

    #[test]
    fn diff_nested_change() {
        let old = json!({"config": {"timeout": 30}});
        let new = json!({"config": {"timeout": 60}});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Changed { path, .. } if path == "config.timeout"))
        );
    }

    #[test]
    fn diff_array_element_changed() {
        let old = json!({"items": [1, 2, 3]});
        let new = json!({"items": [1, 99, 3]});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Changed { path, .. } if path == "items.1"))
        );
    }

    #[test]
    fn diff_array_element_added() {
        let old = json!({"items": [1, 2]});
        let new = json!({"items": [1, 2, 3]});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Added { path, .. } if path == "items.2"))
        );
    }

    #[test]
    fn diff_array_element_removed() {
        let old = json!({"items": [1, 2, 3]});
        let new = json!({"items": [1, 2]});
        let diff = diff_values(&old, &new, "");
        assert!(
            diff.iter()
                .any(|d| matches!(d, DiffLine::Removed { path, .. } if path == "items.2"))
        );
    }

    #[test]
    fn diff_empty_objects() {
        let diff = diff_values(&json!({}), &json!({}), "");
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_null_to_value() {
        let diff = diff_values(&Value::Null, &json!(42), "");
        assert_eq!(diff.len(), 1);
        assert!(matches!(&diff[0], DiffLine::Changed { .. }));
    }

    #[test]
    fn diff_type_change() {
        let old = json!({"val": 42});
        let new = json!({"val": "forty-two"});
        let diff = diff_values(&old, &new, "");
        assert!(diff.iter().any(|d| matches!(d, DiffLine::Changed {
            path,
            old: o,
            new: n,
        } if path == "val" && *o == json!(42) && *n == json!("forty-two"))));
    }

    // ── build_replay_plan tests ─────────────────────────────────────────

    #[test]
    fn replay_plan_no_overrides() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        assert!(plan.overrides.is_empty());
        assert!(
            plan.diff
                .iter()
                .all(|d| matches!(d, DiffLine::Unchanged { .. }))
        );
        assert_eq!(plan.source.entry_id, "e001");
    }

    #[test]
    fn replay_plan_with_one_override() {
        let entry = sample_ref();
        let ov = parse_override("title=Updated Title").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        assert_eq!(plan.overrides.len(), 1);
        assert_eq!(plan.overrides[0].field_path, "title");
        assert_eq!(plan.overrides[0].old_value, json!("Bug report"));
        assert_eq!(plan.overrides[0].new_value, json!("Updated Title"));
    }

    #[test]
    fn replay_plan_with_multiple_overrides() {
        let entry = sample_ref();
        let ovs = vec![
            parse_override("title=New Title").unwrap(),
            parse_override("config.timeout=120").unwrap(),
        ];
        let plan = build_replay_plan(&entry, &ovs);
        assert_eq!(plan.overrides.len(), 2);
    }

    #[test]
    fn replay_plan_fills_old_values() {
        let entry = sample_ref();
        let ov = parse_override("config.timeout=60").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        assert_eq!(plan.overrides[0].old_value, json!(30));
    }

    #[test]
    fn replay_plan_missing_field_old_value_is_null() {
        let entry = sample_ref();
        let ov = parse_override("nonexistent=42").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        assert_eq!(plan.overrides[0].old_value, Value::Null);
    }

    #[test]
    fn replay_plan_diff_contains_changes() {
        let entry = sample_ref();
        let ov = parse_override("title=Changed").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        assert!(
            plan.diff
                .iter()
                .any(|d| matches!(d, DiffLine::Changed { path, .. } if path == "title"))
        );
    }

    #[test]
    fn replay_plan_risk_low_for_read_op() {
        let entry = HistoryRef {
            entry_id: "r001".to_owned(),
            connector: "github".to_owned(),
            operation: "issues.list".to_owned(),
            original_input: json!({}),
            original_output: None,
            timestamp: "2026-03-12T10:00:00Z".to_owned(),
        };
        let plan = build_replay_plan(&entry, &[]);
        assert_eq!(plan.estimated_risk, RiskLevel::Low);
        assert!(!plan.requires_approval);
    }

    #[test]
    fn replay_plan_risk_medium_for_create() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        assert_eq!(plan.estimated_risk, RiskLevel::Medium);
        assert!(!plan.requires_approval);
    }

    #[test]
    fn replay_plan_risk_high_for_delete() {
        let entry = HistoryRef {
            entry_id: "d001".to_owned(),
            connector: "github".to_owned(),
            operation: "repos.delete".to_owned(),
            original_input: json!({"repo": "test"}),
            original_output: None,
            timestamp: "2026-03-12T10:00:00Z".to_owned(),
        };
        let plan = build_replay_plan(&entry, &[]);
        assert_eq!(plan.estimated_risk, RiskLevel::High);
        assert!(plan.requires_approval);
    }

    #[test]
    fn replay_plan_risk_critical_for_terraform_delete() {
        let entry = sample_ref_delete();
        let plan = build_replay_plan(&entry, &[]);
        assert_eq!(plan.estimated_risk, RiskLevel::Critical);
        assert!(plan.requires_approval);
    }

    #[test]
    fn replay_plan_risk_medium_for_update() {
        let entry = HistoryRef {
            entry_id: "u001".to_owned(),
            connector: "github".to_owned(),
            operation: "issues.update".to_owned(),
            original_input: json!({"id": 1}),
            original_output: None,
            timestamp: "2026-03-12T10:00:00Z".to_owned(),
        };
        let plan = build_replay_plan(&entry, &[]);
        assert_eq!(plan.estimated_risk, RiskLevel::Medium);
    }

    #[test]
    fn replay_plan_preserves_source() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        assert_eq!(plan.source.connector, "github");
        assert_eq!(plan.source.operation, "issues.create");
        assert_eq!(plan.source.timestamp, "2026-03-12T10:00:00Z");
    }

    // ── compare_entries tests ───────────────────────────────────────────

    #[test]
    fn compare_same_entry() {
        let entry = sample_ref();
        let result = compare_entries(&entry, &entry);
        assert!(
            result
                .input_diff
                .iter()
                .all(|d| matches!(d, DiffLine::Unchanged { .. }))
        );
        assert!(
            result
                .output_diff
                .iter()
                .all(|d| matches!(d, DiffLine::Unchanged { .. }))
        );
        assert!(result.metadata_diff.is_empty());
    }

    #[test]
    fn compare_different_entries() {
        let a = sample_ref();
        let b = sample_ref_b();
        let result = compare_entries(&a, &b);
        assert!(!result.input_diff.is_empty());
        assert!(!result.output_diff.is_empty());
    }

    #[test]
    fn compare_entries_metadata_diff() {
        let a = sample_ref();
        let b = sample_ref_b();
        let result = compare_entries(&a, &b);
        assert!(
            result
                .metadata_diff
                .iter()
                .any(|(field, _, _)| field == "timestamp")
        );
        assert!(
            result
                .metadata_diff
                .iter()
                .any(|(field, _, _)| field == "entry_id")
        );
    }

    #[test]
    fn compare_different_connectors() {
        let a = sample_ref();
        let b = sample_ref_no_output();
        let result = compare_entries(&a, &b);
        assert!(
            result
                .metadata_diff
                .iter()
                .any(|(field, _, _)| field == "connector")
        );
        assert!(
            result
                .metadata_diff
                .iter()
                .any(|(field, _, _)| field == "operation")
        );
    }

    #[test]
    fn compare_with_missing_output() {
        let a = sample_ref();
        let b = sample_ref_no_output();
        let result = compare_entries(&a, &b);
        // Output diff should show changes (a has output, b has null).
        assert!(!result.output_diff.is_empty());
    }

    #[test]
    fn compare_both_missing_output() {
        let mut a = sample_ref_no_output();
        let mut b = sample_ref_no_output();
        b.entry_id = "e006".to_owned();
        a.original_input = json!({"x": 1});
        b.original_input = json!({"x": 1});
        let result = compare_entries(&a, &b);
        // Both outputs are null, so output diff should be all unchanged or empty.
        assert!(
            result
                .output_diff
                .iter()
                .all(|d| matches!(d, DiffLine::Unchanged { .. }))
        );
    }

    #[test]
    fn compare_entries_count() {
        let a = sample_ref();
        let b = sample_ref_b();
        let result = compare_entries(&a, &b);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].entry_id, "e001");
        assert_eq!(result.entries[1].entry_id, "e002");
    }

    #[test]
    fn compare_empty_inputs() {
        let a = sample_ref_empty();
        let b = sample_ref_empty();
        let result = compare_entries(&a, &b);
        assert!(result.input_diff.is_empty());
    }

    // ── format_diff_toon tests ──────────────────────────────────────────

    #[test]
    fn format_diff_empty() {
        let output = format_diff_toon(&[]);
        assert!(output.contains("(no changes)"));
    }

    #[test]
    fn format_diff_added() {
        let diff = vec![DiffLine::Added {
            path: "new_field".to_owned(),
            value: json!(42),
        }];
        let output = format_diff_toon(&diff);
        assert!(output.contains("+ new_field: 42"));
        assert!(output.contains("+1"));
    }

    #[test]
    fn format_diff_removed() {
        let diff = vec![DiffLine::Removed {
            path: "old_field".to_owned(),
            value: json!("gone"),
        }];
        let output = format_diff_toon(&diff);
        assert!(output.contains("- old_field: \"gone\""));
        assert!(output.contains("-1"));
    }

    #[test]
    fn format_diff_changed() {
        let diff = vec![DiffLine::Changed {
            path: "title".to_owned(),
            old: json!("old"),
            new: json!("new"),
        }];
        let output = format_diff_toon(&diff);
        assert!(output.contains("~ title: \"old\" -> \"new\""));
        assert!(output.contains("~1"));
    }

    #[test]
    fn format_diff_unchanged_not_printed() {
        let diff = vec![DiffLine::Unchanged {
            path: "hidden".to_owned(),
            value: json!(1),
        }];
        let output = format_diff_toon(&diff);
        assert!(!output.contains("hidden"));
        assert!(output.contains("=1"));
    }

    #[test]
    fn format_diff_mixed() {
        let diff = vec![
            DiffLine::Added {
                path: "a".to_owned(),
                value: json!(1),
            },
            DiffLine::Removed {
                path: "b".to_owned(),
                value: json!(2),
            },
            DiffLine::Changed {
                path: "c".to_owned(),
                old: json!(3),
                new: json!(4),
            },
            DiffLine::Unchanged {
                path: "d".to_owned(),
                value: json!(5),
            },
        ];
        let output = format_diff_toon(&diff);
        assert!(output.contains("+1 -1 ~1 =1"));
    }

    // ── format_replay_plan_toon tests ───────────────────────────────────

    #[test]
    fn format_plan_contains_header() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("REPLAY PLAN"));
    }

    #[test]
    fn format_plan_contains_source() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("github / issues.create @ e001"));
    }

    #[test]
    fn format_plan_contains_risk() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("risk: medium"));
    }

    #[test]
    fn format_plan_no_overrides() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("overrides: (none)"));
    }

    #[test]
    fn format_plan_with_overrides() {
        let entry = sample_ref();
        let ov = parse_override("title=New").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("title:"));
        assert!(output.contains("\"New\""));
    }

    #[test]
    fn format_plan_approval_required() {
        let entry = sample_ref_delete();
        let plan = build_replay_plan(&entry, &[]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("approval_required: true"));
    }

    #[test]
    fn format_plan_diff_section() {
        let entry = sample_ref();
        let ov = parse_override("title=Changed").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        let output = format_replay_plan_toon(&plan);
        assert!(output.contains("diff:"));
    }

    // ── compact_value tests ─────────────────────────────────────────────

    #[test]
    fn compact_null() {
        assert_eq!(compact_value(&Value::Null), "null");
    }

    #[test]
    fn compact_bool() {
        assert_eq!(compact_value(&json!(true)), "true");
        assert_eq!(compact_value(&json!(false)), "false");
    }

    #[test]
    fn compact_number() {
        assert_eq!(compact_value(&json!(42)), "42");
        assert_eq!(compact_value(&json!(2.5)), "2.5");
    }

    #[test]
    fn compact_short_string() {
        assert_eq!(compact_value(&json!("hello")), "\"hello\"");
    }

    #[test]
    fn compact_long_string_truncated() {
        let long = "a".repeat(100);
        let result = compact_value(&json!(long));
        assert!(result.len() < 60);
        assert!(result.ends_with("...\""));
    }

    #[test]
    fn compact_empty_array() {
        assert_eq!(compact_value(&json!([])), "[]");
    }

    #[test]
    fn compact_nonempty_array() {
        assert_eq!(compact_value(&json!([1, 2, 3])), "[...3]");
    }

    #[test]
    fn compact_empty_object() {
        assert_eq!(compact_value(&json!({})), "{}");
    }

    #[test]
    fn compact_small_object() {
        let v = json!({"a": 1, "b": 2});
        let result = compact_value(&v);
        assert!(result.contains('a'));
        assert!(result.contains('b'));
    }

    #[test]
    fn compact_large_object_truncated() {
        let v = json!({"a": 1, "b": 2, "c": 3, "d": 4});
        let result = compact_value(&v);
        assert!(result.contains("..."));
    }

    // ── RiskLevel tests ─────────────────────────────────────────────────

    #[test]
    fn risk_low_no_approval() {
        assert!(!RiskLevel::Low.requires_approval());
    }

    #[test]
    fn risk_medium_no_approval() {
        assert!(!RiskLevel::Medium.requires_approval());
    }

    #[test]
    fn risk_high_needs_approval() {
        assert!(RiskLevel::High.requires_approval());
    }

    #[test]
    fn risk_critical_needs_approval() {
        assert!(RiskLevel::Critical.requires_approval());
    }

    #[test]
    fn risk_as_str() {
        assert_eq!(RiskLevel::Low.as_str(), "low");
        assert_eq!(RiskLevel::Medium.as_str(), "medium");
        assert_eq!(RiskLevel::High.as_str(), "high");
        assert_eq!(RiskLevel::Critical.as_str(), "critical");
    }

    #[test]
    fn risk_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "low");
        assert_eq!(format!("{}", RiskLevel::Critical), "critical");
    }

    #[test]
    fn risk_serialization_roundtrip() {
        let risk = RiskLevel::High;
        let json = serde_json::to_string(&risk).unwrap();
        let back: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(risk, back);
    }

    // ── infer_risk_level tests ──────────────────────────────────────────

    #[test]
    fn infer_risk_delete_generic() {
        assert_eq!(infer_risk_level("github", "repos.delete"), RiskLevel::High);
    }

    #[test]
    fn infer_risk_delete_terraform() {
        assert_eq!(
            infer_risk_level("terraform", "resources.delete"),
            RiskLevel::Critical
        );
    }

    #[test]
    fn infer_risk_destroy() {
        assert_eq!(
            infer_risk_level("aws", "instances.destroy"),
            RiskLevel::High
        );
    }

    #[test]
    fn infer_risk_drop() {
        assert_eq!(infer_risk_level("db", "tables.drop"), RiskLevel::High);
    }

    #[test]
    fn infer_risk_create() {
        assert_eq!(
            infer_risk_level("github", "issues.create"),
            RiskLevel::Medium
        );
    }

    #[test]
    fn infer_risk_update() {
        assert_eq!(
            infer_risk_level("github", "issues.update"),
            RiskLevel::Medium
        );
    }

    #[test]
    fn infer_risk_list() {
        assert_eq!(infer_risk_level("github", "issues.list"), RiskLevel::Low);
    }

    #[test]
    fn infer_risk_get() {
        assert_eq!(infer_risk_level("github", "issues.get"), RiskLevel::Low);
    }

    #[test]
    fn infer_risk_send() {
        assert_eq!(
            infer_risk_level("slack", "chat.post_message"),
            RiskLevel::Medium
        );
    }

    #[test]
    fn infer_risk_prod_delete() {
        assert_eq!(
            infer_risk_level("prod-db", "records.delete"),
            RiskLevel::Critical
        );
    }

    // ── HistoryRef serialization tests ──────────────────────────────────

    #[test]
    fn history_ref_serialize_roundtrip() {
        let entry = sample_ref();
        let json = serde_json::to_string(&entry).unwrap();
        let back: HistoryRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entry_id, entry.entry_id);
        assert_eq!(back.connector, entry.connector);
        assert_eq!(back.operation, entry.operation);
    }

    #[test]
    fn history_ref_with_null_output() {
        let entry = sample_ref_no_output();
        let json = serde_json::to_string(&entry).unwrap();
        let back: HistoryRef = serde_json::from_str(&json).unwrap();
        assert!(back.original_output.is_none());
    }

    // ── InputOverride serialization tests ───────────────────────────────

    #[test]
    fn input_override_serialize_roundtrip() {
        let ov = InputOverride {
            field_path: "config.timeout".to_owned(),
            old_value: json!(30),
            new_value: json!(60),
        };
        let json = serde_json::to_string(&ov).unwrap();
        let back: InputOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(ov, back);
    }

    // ── DiffLine serialization tests ────────────────────────────────────

    #[test]
    fn diffline_added_serialize() {
        let line = DiffLine::Added {
            path: "x".to_owned(),
            value: json!(1),
        };
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.contains("added"));
        let back: DiffLine = serde_json::from_str(&json).unwrap();
        assert_eq!(line, back);
    }

    #[test]
    fn diffline_removed_serialize() {
        let line = DiffLine::Removed {
            path: "x".to_owned(),
            value: json!(1),
        };
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.contains("removed"));
    }

    #[test]
    fn diffline_changed_serialize() {
        let line = DiffLine::Changed {
            path: "x".to_owned(),
            old: json!(1),
            new: json!(2),
        };
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.contains("changed"));
    }

    #[test]
    fn diffline_unchanged_serialize() {
        let line = DiffLine::Unchanged {
            path: "x".to_owned(),
            value: json!(1),
        };
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.contains("unchanged"));
    }

    // ── ReplayPlan serialization tests ──────────────────────────────────

    #[test]
    fn replay_plan_serialize_roundtrip() {
        let entry = sample_ref();
        let plan = build_replay_plan(&entry, &[]);
        let json = serde_json::to_string(&plan).unwrap();
        let back: ReplayPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.source.entry_id, plan.source.entry_id);
        assert_eq!(back.estimated_risk, plan.estimated_risk);
    }

    // ── CompareResult serialization tests ───────────────────────────────

    #[test]
    fn compare_result_serialize_roundtrip() {
        let a = sample_ref();
        let b = sample_ref_b();
        let result = compare_entries(&a, &b);
        let json = serde_json::to_string(&result).unwrap();
        let back: CompareResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries.len(), 2);
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn replay_plan_with_empty_input() {
        let entry = sample_ref_empty();
        let ov = parse_override("new_key=value").unwrap();
        let plan = build_replay_plan(&entry, &[ov]);
        assert_eq!(plan.overrides[0].old_value, Value::Null);
        assert!(
            plan.diff
                .iter()
                .any(|d| matches!(d, DiffLine::Added { path, .. } if path == "new_key"))
        );
    }

    #[test]
    fn replay_plan_override_conflict_last_wins() {
        let entry = sample_ref();
        let ovs = vec![
            parse_override("title=First").unwrap(),
            parse_override("title=Second").unwrap(),
        ];
        let plan = build_replay_plan(&entry, &ovs);
        // Both overrides are recorded.
        assert_eq!(plan.overrides.len(), 2);
        // The diff should reflect the final value.
        let title_changes: Vec<_> = plan
            .diff
            .iter()
            .filter(|d| matches!(d, DiffLine::Changed { path, .. } if path == "title"))
            .collect();
        assert!(!title_changes.is_empty());
    }

    #[test]
    fn compare_entries_same_connector_different_ops() {
        let a = sample_ref();
        let mut b = sample_ref();
        b.entry_id = "e999".to_owned();
        b.operation = "issues.update".to_owned();
        let result = compare_entries(&a, &b);
        assert!(
            result
                .metadata_diff
                .iter()
                .any(|(field, _, _)| field == "operation")
        );
    }

    #[test]
    fn diff_large_array() {
        let old: Vec<i32> = (0..50).collect();
        let mut new_arr = old.clone();
        new_arr[25] = 999;
        let old_val = json!(old);
        let new_val = json!(new_arr);
        let diff = diff_values(&old_val, &new_val, "");
        let changed: Vec<_> = diff
            .iter()
            .filter(|d| matches!(d, DiffLine::Changed { .. }))
            .collect();
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn diff_deeply_nested_identical() {
        let v = json!({"a": {"b": {"c": {"d": {"e": 1}}}}});
        let diff = diff_values(&v, &v, "");
        assert!(diff.iter().all(|d| matches!(d, DiffLine::Unchanged { .. })));
    }

    #[test]
    fn diff_root_level_scalar() {
        let diff = diff_values(&json!(1), &json!(2), "");
        assert_eq!(diff.len(), 1);
        match &diff[0] {
            DiffLine::Changed { path, old, new } => {
                assert_eq!(path, "<root>");
                assert_eq!(*old, json!(1));
                assert_eq!(*new, json!(2));
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn apply_overrides_preserves_unrelated_fields() {
        let input = json!({"a": 1, "b": 2, "c": {"x": 10, "y": 20}});
        let ov = InputOverride {
            field_path: "c.x".to_owned(),
            old_value: json!(10),
            new_value: json!(99),
        };
        let result = apply_overrides(&input, &[ov]).unwrap();
        assert_eq!(result["a"], json!(1));
        assert_eq!(result["b"], json!(2));
        assert_eq!(result["c"]["x"], json!(99));
        assert_eq!(result["c"]["y"], json!(20));
    }

    #[test]
    fn make_path_helper_empty_prefix() {
        assert_eq!(make_path("", "key"), "key");
    }

    #[test]
    fn make_path_helper_with_prefix() {
        assert_eq!(make_path("a.b", "c"), "a.b.c");
    }

    #[test]
    fn format_diff_toon_summary_line() {
        let diff = vec![
            DiffLine::Added {
                path: "a".to_owned(),
                value: json!(1),
            },
            DiffLine::Added {
                path: "b".to_owned(),
                value: json!(2),
            },
        ];
        let output = format_diff_toon(&diff);
        assert!(output.contains("+2"));
    }
}
