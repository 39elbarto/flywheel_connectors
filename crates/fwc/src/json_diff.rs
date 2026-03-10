//! Structural JSON diff engine.
//!
//! Produces human-readable diffs showing what changed between two JSON values,
//! with path-aware change tracking for additions, removals, and modifications.

use serde::Serialize;
use serde_json::Value;

/// A single change detected between two JSON values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Change {
    /// JSON path to the changed value (e.g. `"issues[3]"`, `"user.login"`).
    pub path: String,
    /// Type of change.
    pub kind: ChangeKind,
    /// The old value (for modified/removed).
    pub old: Option<Value>,
    /// The new value (for modified/added).
    pub new: Option<Value>,
}

/// Kind of change detected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

/// Result of diffing two JSON values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiffResult {
    pub changes: Vec<Change>,
}

impl DiffResult {
    /// Whether the two values are identical.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Count changes by kind.
    pub fn count_by_kind(&self, kind: ChangeKind) -> usize {
        self.changes.iter().filter(|c| c.kind == kind).count()
    }

    /// Render as a human-readable summary.
    pub fn summary(&self) -> String {
        if self.changes.is_empty() {
            return "(no changes)".to_string();
        }
        let added = self.count_by_kind(ChangeKind::Added);
        let removed = self.count_by_kind(ChangeKind::Removed);
        let modified = self.count_by_kind(ChangeKind::Modified);
        let mut parts = Vec::new();
        if added > 0 {
            parts.push(format!("+{added} added"));
        }
        if removed > 0 {
            parts.push(format!("-{removed} removed"));
        }
        if modified > 0 {
            parts.push(format!("~{modified} modified"));
        }
        parts.join(", ")
    }

    /// Render as human-readable diff lines.
    pub fn render_lines(&self) -> String {
        let mut out = String::new();
        for change in &self.changes {
            let line = match change.kind {
                ChangeKind::Added => {
                    format!(
                        "+ {}: {}",
                        change.path,
                        format_value_compact(change.new.as_ref())
                    )
                }
                ChangeKind::Removed => {
                    format!(
                        "- {}: {}",
                        change.path,
                        format_value_compact(change.old.as_ref())
                    )
                }
                ChangeKind::Modified => {
                    format!(
                        "~ {}: {} -> {}",
                        change.path,
                        format_value_compact(change.old.as_ref()),
                        format_value_compact(change.new.as_ref()),
                    )
                }
            };
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

/// Compute structural diff between two JSON values.
pub fn diff(old: &Value, new: &Value) -> DiffResult {
    let mut changes = Vec::new();
    diff_values(old, new, &[], &mut changes);
    DiffResult { changes }
}

fn diff_values(old: &Value, new: &Value, path: &[String], changes: &mut Vec<Change>) {
    if old == new {
        return;
    }

    match (old, new) {
        (Value::Object(old_map), Value::Object(new_map)) => {
            // Check for removed and modified keys.
            for (key, old_val) in old_map {
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                match new_map.get(key) {
                    Some(new_val) => diff_values(old_val, new_val, &child_path, changes),
                    None => changes.push(Change {
                        path: format_path(&child_path),
                        kind: ChangeKind::Removed,
                        old: Some(old_val.clone()),
                        new: None,
                    }),
                }
            }
            // Check for added keys.
            for (key, new_val) in new_map {
                if !old_map.contains_key(key) {
                    let mut child_path = path.to_vec();
                    child_path.push(key.clone());
                    changes.push(Change {
                        path: format_path(&child_path),
                        kind: ChangeKind::Added,
                        old: None,
                        new: Some(new_val.clone()),
                    });
                }
            }
        }
        (Value::Array(old_arr), Value::Array(new_arr)) => {
            let max_len = old_arr.len().max(new_arr.len());
            for i in 0..max_len {
                let mut child_path = path.to_vec();
                child_path.push(format!("[{i}]"));
                match (old_arr.get(i), new_arr.get(i)) {
                    (Some(old_val), Some(new_val)) => {
                        diff_values(old_val, new_val, &child_path, changes);
                    }
                    (Some(old_val), None) => {
                        changes.push(Change {
                            path: format_path(&child_path),
                            kind: ChangeKind::Removed,
                            old: Some(old_val.clone()),
                            new: None,
                        });
                    }
                    (None, Some(new_val)) => {
                        changes.push(Change {
                            path: format_path(&child_path),
                            kind: ChangeKind::Added,
                            old: None,
                            new: Some(new_val.clone()),
                        });
                    }
                    (None, None) => {}
                }
            }
        }
        _ => {
            // Leaf value changed.
            changes.push(Change {
                path: format_path(path),
                kind: ChangeKind::Modified,
                old: Some(old.clone()),
                new: Some(new.clone()),
            });
        }
    }
}

fn format_path(segments: &[String]) -> String {
    if segments.is_empty() {
        return "<root>".to_string();
    }
    let mut result = String::new();
    for segment in segments {
        if !segment.starts_with('[') && !result.is_empty() {
            result.push('.');
        }
        result.push_str(segment);
    }
    result
}

fn format_value_compact(value: Option<&Value>) -> String {
    match value {
        None => "(absent)".to_string(),
        Some(Value::Null) => "null".to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => {
            if s.len() > 60 {
                format!("\"{}...\"", &s[..57])
            } else {
                format!("\"{s}\"")
            }
        }
        Some(Value::Array(arr)) => format!("[{} items]", arr.len()),
        Some(Value::Object(map)) => format!("{{{} keys}}", map.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Identical values ────────────────────────────────────────────

    #[test]
    fn identical_values_produce_empty_diff() {
        let a = json!({"name": "alice", "age": 30});
        let result = diff(&a, &a);
        assert!(result.is_empty());
        assert_eq!(result.summary(), "(no changes)");
    }

    // ── Scalar changes ──────────────────────────────────────────────

    #[test]
    fn scalar_modification() {
        let old = json!({"name": "alice"});
        let new = json!({"name": "bob"});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "name");
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
        assert_eq!(result.changes[0].old, Some(json!("alice")));
        assert_eq!(result.changes[0].new, Some(json!("bob")));
    }

    #[test]
    fn type_change_detected_as_modification() {
        let old = json!({"value": 42});
        let new = json!({"value": "forty-two"});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    // ── Object field changes ────────────────────────────────────────

    #[test]
    fn field_added() {
        let old = json!({"name": "alice"});
        let new = json!({"name": "alice", "email": "alice@example.com"});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "email");
        assert_eq!(result.changes[0].kind, ChangeKind::Added);
    }

    #[test]
    fn field_removed() {
        let old = json!({"name": "alice", "email": "alice@example.com"});
        let new = json!({"name": "alice"});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "email");
        assert_eq!(result.changes[0].kind, ChangeKind::Removed);
    }

    #[test]
    fn multiple_changes() {
        let old = json!({"a": 1, "b": 2, "c": 3});
        let new = json!({"a": 1, "b": 99, "d": 4});
        let result = diff(&old, &new);
        assert_eq!(result.count_by_kind(ChangeKind::Modified), 1); // b: 2 -> 99
        assert_eq!(result.count_by_kind(ChangeKind::Removed), 1); // c removed
        assert_eq!(result.count_by_kind(ChangeKind::Added), 1); // d added
    }

    // ── Nested object changes ───────────────────────────────────────

    #[test]
    fn nested_field_change() {
        let old = json!({"user": {"name": "alice", "age": 30}});
        let new = json!({"user": {"name": "alice", "age": 31}});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "user.age");
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn nested_field_added() {
        let old = json!({"config": {"debug": false}});
        let new = json!({"config": {"debug": false, "verbose": true}});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].path, "config.verbose");
        assert_eq!(result.changes[0].kind, ChangeKind::Added);
    }

    // ── Array changes ───────────────────────────────────────────────

    #[test]
    fn array_item_added() {
        let old = json!({"tags": ["a", "b"]});
        let new = json!({"tags": ["a", "b", "c"]});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "tags[2]");
        assert_eq!(result.changes[0].kind, ChangeKind::Added);
    }

    #[test]
    fn array_item_removed() {
        let old = json!({"tags": ["a", "b", "c"]});
        let new = json!({"tags": ["a", "b"]});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "tags[2]");
        assert_eq!(result.changes[0].kind, ChangeKind::Removed);
    }

    #[test]
    fn array_item_modified() {
        let old = json!({"items": [1, 2, 3]});
        let new = json!({"items": [1, 99, 3]});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "items[1]");
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn array_of_objects_changes() {
        let old = json!({"issues": [
            {"number": 1, "title": "Bug"},
            {"number": 2, "title": "Feature"},
        ]});
        let new = json!({"issues": [
            {"number": 1, "title": "Bug fix"},
            {"number": 2, "title": "Feature"},
            {"number": 3, "title": "New issue"},
        ]});
        let result = diff(&old, &new);
        // issues[0].title changed, issues[2] added
        assert!(result.changes.iter().any(|c| c.path == "issues[0].title"));
        assert!(
            result
                .changes
                .iter()
                .any(|c| c.path == "issues[2]" && c.kind == ChangeKind::Added)
        );
    }

    // ── Root-level changes ──────────────────────────────────────────

    #[test]
    fn root_type_change() {
        let old = json!(42);
        let new = json!("forty-two");
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "<root>");
    }

    #[test]
    fn root_null_to_object() {
        let result = diff(&json!(null), &json!({"key": "value"}));
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    // ── Summary and rendering ───────────────────────────────────────

    #[test]
    fn summary_format() {
        let old = json!({"a": 1, "b": 2});
        let new = json!({"a": 99, "c": 3});
        let result = diff(&old, &new);
        let summary = result.summary();
        assert!(summary.contains("added"));
        assert!(summary.contains("removed"));
        assert!(summary.contains("modified"));
    }

    #[test]
    fn render_lines_format() {
        let old = json!({"name": "alice"});
        let new = json!({"name": "bob", "email": "bob@test.com"});
        let result = diff(&old, &new);
        let lines = result.render_lines();
        assert!(lines.contains("~ name:"));
        assert!(lines.contains("+ email:"));
    }

    #[test]
    fn empty_diff_render() {
        let a = json!({"x": 1});
        let result = diff(&a, &a);
        assert_eq!(result.render_lines(), "");
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn both_empty_objects() {
        let result = diff(&json!({}), &json!({}));
        assert!(result.is_empty());
    }

    #[test]
    fn both_empty_arrays() {
        let result = diff(&json!([]), &json!([]));
        assert!(result.is_empty());
    }

    #[test]
    fn deeply_nested_change() {
        let old = json!({"a": {"b": {"c": {"d": 1}}}});
        let new = json!({"a": {"b": {"c": {"d": 2}}}});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].path, "a.b.c.d");
    }

    #[test]
    fn null_value_changes() {
        let old = json!({"x": null});
        let new = json!({"x": 42});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
        assert_eq!(result.changes[0].old, Some(Value::Null));
    }

    #[test]
    fn boolean_changes() {
        let old = json!({"active": true});
        let new = json!({"active": false});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn compact_string_truncation() {
        let long = "a".repeat(100);
        let formatted = format_value_compact(Some(&json!(long)));
        assert!(formatted.len() < 70);
        assert!(formatted.ends_with("...\""));
    }

    #[test]
    fn count_by_kind_correct() {
        let old = json!({"a": 1, "b": 2, "c": 3});
        let new = json!({"a": 99, "d": 4});
        let result = diff(&old, &new);
        assert_eq!(result.count_by_kind(ChangeKind::Modified), 1);
        assert_eq!(result.count_by_kind(ChangeKind::Removed), 2);
        assert_eq!(result.count_by_kind(ChangeKind::Added), 1);
    }

    #[test]
    fn deterministic_output() {
        let old = json!({"a": 1, "b": 2});
        let new = json!({"a": 99, "c": 3});
        let a = serde_json::to_string(&diff(&old, &new)).unwrap();
        let b = serde_json::to_string(&diff(&old, &new)).unwrap();
        assert_eq!(a, b);
    }

    // ── DiffResult API tests ────────────────────────────────────────

    #[test]
    fn diff_result_is_empty_when_no_changes() {
        let result = DiffResult {
            changes: Vec::new(),
        };
        assert!(result.is_empty());
    }

    #[test]
    fn diff_result_not_empty_with_changes() {
        let result = DiffResult {
            changes: vec![Change {
                path: "x".to_string(),
                kind: ChangeKind::Added,
                old: None,
                new: Some(json!(1)),
            }],
        };
        assert!(!result.is_empty());
    }

    #[test]
    fn diff_result_summary_only_added() {
        let result = DiffResult {
            changes: vec![
                Change {
                    path: "a".to_string(),
                    kind: ChangeKind::Added,
                    old: None,
                    new: Some(json!(1)),
                },
                Change {
                    path: "b".to_string(),
                    kind: ChangeKind::Added,
                    old: None,
                    new: Some(json!(2)),
                },
            ],
        };
        let summary = result.summary();
        assert!(summary.contains("+2 added"));
        assert!(!summary.contains("removed"));
        assert!(!summary.contains("modified"));
    }

    #[test]
    fn diff_result_summary_only_removed() {
        let result = DiffResult {
            changes: vec![Change {
                path: "x".to_string(),
                kind: ChangeKind::Removed,
                old: Some(json!(1)),
                new: None,
            }],
        };
        let summary = result.summary();
        assert!(summary.contains("-1 removed"));
        assert!(!summary.contains("added"));
    }

    #[test]
    fn diff_result_summary_only_modified() {
        let result = DiffResult {
            changes: vec![Change {
                path: "x".to_string(),
                kind: ChangeKind::Modified,
                old: Some(json!(1)),
                new: Some(json!(2)),
            }],
        };
        let summary = result.summary();
        assert!(summary.contains("~1 modified"));
        assert!(!summary.contains("added"));
    }

    #[test]
    fn diff_result_count_by_kind_zero() {
        let result = DiffResult {
            changes: Vec::new(),
        };
        assert_eq!(result.count_by_kind(ChangeKind::Added), 0);
        assert_eq!(result.count_by_kind(ChangeKind::Removed), 0);
        assert_eq!(result.count_by_kind(ChangeKind::Modified), 0);
    }

    #[test]
    fn diff_result_clone() {
        let result = diff(&json!({"a": 1}), &json!({"a": 2}));
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn diff_result_serializes() {
        let result = diff(&json!({"x": 1}), &json!({"x": 2}));
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("changes"));
        assert!(json_str.contains("modified"));
    }

    // ── ChangeKind tests ────────────────────────────────────────────

    #[test]
    fn change_kind_eq() {
        assert_eq!(ChangeKind::Added, ChangeKind::Added);
        assert_eq!(ChangeKind::Removed, ChangeKind::Removed);
        assert_eq!(ChangeKind::Modified, ChangeKind::Modified);
    }

    #[test]
    fn change_kind_ne() {
        assert_ne!(ChangeKind::Added, ChangeKind::Removed);
        assert_ne!(ChangeKind::Removed, ChangeKind::Modified);
    }

    #[test]
    fn change_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ChangeKind::Added).unwrap(),
            "\"added\""
        );
        assert_eq!(
            serde_json::to_string(&ChangeKind::Removed).unwrap(),
            "\"removed\""
        );
        assert_eq!(
            serde_json::to_string(&ChangeKind::Modified).unwrap(),
            "\"modified\""
        );
    }

    #[test]
    fn change_kind_copy() {
        let k = ChangeKind::Added;
        let k2 = k;
        assert_eq!(k, k2);
    }

    // ── Additional scalar change tests ──────────────────────────────

    #[test]
    fn number_to_string_change() {
        let result = diff(&json!({"v": 42}), &json!({"v": "42"}));
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
        assert_eq!(result.changes[0].old, Some(json!(42)));
        assert_eq!(result.changes[0].new, Some(json!("42")));
    }

    #[test]
    fn boolean_to_number() {
        let result = diff(&json!({"v": true}), &json!({"v": 1}));
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn null_to_string() {
        let result = diff(&json!({"v": null}), &json!({"v": "hello"}));
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn string_to_null() {
        let result = diff(&json!({"v": "hello"}), &json!({"v": null}));
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn integer_change() {
        let result = diff(&json!({"n": 1}), &json!({"n": 2}));
        assert_eq!(result.changes[0].old, Some(json!(1)));
        assert_eq!(result.changes[0].new, Some(json!(2)));
    }

    // ── Multiple field changes ──────────────────────────────────────

    #[test]
    fn all_fields_changed() {
        let old = json!({"a": 1, "b": 2, "c": 3});
        let new = json!({"a": 10, "b": 20, "c": 30});
        let result = diff(&old, &new);
        assert_eq!(result.count_by_kind(ChangeKind::Modified), 3);
    }

    #[test]
    fn all_fields_added() {
        let result = diff(&json!({}), &json!({"a": 1, "b": 2, "c": 3}));
        assert_eq!(result.count_by_kind(ChangeKind::Added), 3);
    }

    #[test]
    fn all_fields_removed() {
        let result = diff(&json!({"a": 1, "b": 2, "c": 3}), &json!({}));
        assert_eq!(result.count_by_kind(ChangeKind::Removed), 3);
    }

    // ── Array edge cases ────────────────────────────────────────────

    #[test]
    fn array_completely_replaced() {
        let old = json!({"arr": [1, 2, 3]});
        let new = json!({"arr": [4, 5, 6]});
        let result = diff(&old, &new);
        assert_eq!(result.count_by_kind(ChangeKind::Modified), 3);
    }

    #[test]
    fn array_shrink_to_empty() {
        let old = json!({"arr": [1, 2, 3]});
        let new = json!({"arr": []});
        let result = diff(&old, &new);
        assert_eq!(result.count_by_kind(ChangeKind::Removed), 3);
    }

    #[test]
    fn array_grow_from_empty() {
        let old = json!({"arr": []});
        let new = json!({"arr": [1, 2]});
        let result = diff(&old, &new);
        assert_eq!(result.count_by_kind(ChangeKind::Added), 2);
    }

    #[test]
    fn nested_array_item_change() {
        let old = json!({"arr": [{"x": 1}, {"x": 2}]});
        let new = json!({"arr": [{"x": 1}, {"x": 99}]});
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "arr[1].x");
    }

    #[test]
    fn root_arrays_differ() {
        let old = json!([1, 2]);
        let new = json!([1, 3]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].path, "[1]");
    }

    #[test]
    fn root_arrays_different_lengths() {
        let old = json!([1, 2]);
        let new = json!([1, 2, 3]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::Added);
        assert_eq!(result.changes[0].path, "[2]");
    }

    // ── Deeply nested changes ───────────────────────────────────────

    #[test]
    fn five_level_nested_change() {
        let old = json!({"a": {"b": {"c": {"d": {"e": 1}}}}});
        let new = json!({"a": {"b": {"c": {"d": {"e": 2}}}}});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].path, "a.b.c.d.e");
    }

    #[test]
    fn nested_array_in_object_change() {
        let old = json!({"data": {"items": [1, 2]}});
        let new = json!({"data": {"items": [1, 3]}});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].path, "data.items[1]");
    }

    // ── format_path tests ───────────────────────────────────────────

    #[test]
    fn format_path_empty_is_root() {
        assert_eq!(format_path(&[]), "<root>");
    }

    #[test]
    fn format_path_single_segment() {
        assert_eq!(format_path(&["name".to_string()]), "name");
    }

    #[test]
    fn format_path_dotted() {
        assert_eq!(
            format_path(&["user".to_string(), "name".to_string()]),
            "user.name"
        );
    }

    #[test]
    fn format_path_with_array_index() {
        assert_eq!(
            format_path(&["items".to_string(), "[0]".to_string()]),
            "items[0]"
        );
    }

    #[test]
    fn format_path_mixed() {
        assert_eq!(
            format_path(&["data".to_string(), "[0]".to_string(), "name".to_string()]),
            "data[0].name"
        );
    }

    // ── format_value_compact tests ──────────────────────────────────

    #[test]
    fn compact_none_is_absent() {
        assert_eq!(format_value_compact(None), "(absent)");
    }

    #[test]
    fn compact_null() {
        assert_eq!(format_value_compact(Some(&Value::Null)), "null");
    }

    #[test]
    fn compact_bool_true() {
        assert_eq!(format_value_compact(Some(&json!(true))), "true");
    }

    #[test]
    fn compact_bool_false() {
        assert_eq!(format_value_compact(Some(&json!(false))), "false");
    }

    #[test]
    fn compact_number() {
        assert_eq!(format_value_compact(Some(&json!(42))), "42");
    }

    #[test]
    fn compact_short_string() {
        assert_eq!(format_value_compact(Some(&json!("hi"))), "\"hi\"");
    }

    #[test]
    fn compact_array_shows_count() {
        assert_eq!(format_value_compact(Some(&json!([1, 2, 3]))), "[3 items]");
    }

    #[test]
    fn compact_empty_array() {
        assert_eq!(format_value_compact(Some(&json!([]))), "[0 items]");
    }

    #[test]
    fn compact_object_shows_key_count() {
        assert_eq!(
            format_value_compact(Some(&json!({"a": 1, "b": 2}))),
            "{2 keys}"
        );
    }

    #[test]
    fn compact_empty_object() {
        assert_eq!(format_value_compact(Some(&json!({}))), "{0 keys}");
    }

    // ── Render lines edge cases ─────────────────────────────────────

    #[test]
    fn render_lines_added() {
        let result = DiffResult {
            changes: vec![Change {
                path: "x".to_string(),
                kind: ChangeKind::Added,
                old: None,
                new: Some(json!(42)),
            }],
        };
        let lines = result.render_lines();
        assert!(lines.starts_with("+ x:"));
        assert!(lines.contains("42"));
    }

    #[test]
    fn render_lines_removed() {
        let result = DiffResult {
            changes: vec![Change {
                path: "y".to_string(),
                kind: ChangeKind::Removed,
                old: Some(json!("gone")),
                new: None,
            }],
        };
        let lines = result.render_lines();
        assert!(lines.starts_with("- y:"));
        assert!(lines.contains("gone"));
    }

    #[test]
    fn render_lines_modified() {
        let result = DiffResult {
            changes: vec![Change {
                path: "z".to_string(),
                kind: ChangeKind::Modified,
                old: Some(json!(1)),
                new: Some(json!(2)),
            }],
        };
        let lines = result.render_lines();
        assert!(lines.starts_with("~ z:"));
        assert!(lines.contains("1 -> 2"));
    }

    #[test]
    fn render_lines_multiple_changes() {
        let old = json!({"a": 1, "b": 2});
        let new = json!({"a": 99, "c": 3});
        let result = diff(&old, &new);
        let lines = result.render_lines();
        let line_count = lines.lines().count();
        assert_eq!(line_count, 3); // modified a, removed b, added c
    }

    // ── Object to array type change ─────────────────────────────────

    #[test]
    fn object_to_array_is_modification() {
        let old = json!({"v": {"key": 1}});
        let new = json!({"v": [1, 2, 3]});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
        assert_eq!(result.changes[0].path, "v");
    }

    #[test]
    fn array_to_object_is_modification() {
        let old = json!({"v": [1, 2]});
        let new = json!({"v": {"key": "val"}});
        let result = diff(&old, &new);
        assert_eq!(result.changes[0].kind, ChangeKind::Modified);
    }

    // ── Identical nested structures ─────────────────────────────────

    #[test]
    fn identical_nested_objects() {
        let v = json!({"a": {"b": {"c": [1, 2, 3]}}});
        let result = diff(&v, &v);
        assert!(result.is_empty());
    }

    #[test]
    fn identical_arrays_of_objects() {
        let v = json!([{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]);
        let result = diff(&v, &v);
        assert!(result.is_empty());
    }

    #[test]
    fn identical_scalars() {
        assert!(diff(&json!(42), &json!(42)).is_empty());
        assert!(diff(&json!("hello"), &json!("hello")).is_empty());
        assert!(diff(&json!(true), &json!(true)).is_empty());
        assert!(diff(&json!(null), &json!(null)).is_empty());
    }
}
