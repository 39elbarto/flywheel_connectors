//! Two-operation pipe: output of A feeds input of B via field mapping.
//!
//! The pipe module provides a mapping engine that transforms JSON output
//! from one operation into valid input for another, with support for
//! path expressions, literal values, and template strings.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ── Map expression types ────────────────────────────────────────────────

/// A single field mapping rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapRule {
    /// Source expression (JSON path like `"issues[0].title"` or literal `"\"#general\""`).
    pub source: String,
    /// Target field name in the destination input.
    pub target: String,
}

/// A complete mapping specification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MappingSpec {
    pub rules: Vec<MapRule>,
}

/// Error from mapping evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct MappingError {
    pub source: String,
    pub target: String,
    pub message: String,
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}: {}", self.source, self.target, self.message)
    }
}

/// Result of applying a mapping specification.
#[derive(Debug)]
pub struct MappingResult {
    /// The produced output object.
    pub output: Value,
    /// Any mapping errors encountered.
    pub errors: Vec<MappingError>,
}

// ── Parsing ─────────────────────────────────────────────────────────────

/// Parse a `--map` expression string into a `MappingSpec`.
///
/// Format: `"source.path -> target, source2 -> target2"`
pub fn parse_map_expression(expr: &str) -> Result<MappingSpec, String> {
    let mut rules = Vec::new();
    for segment in expr.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some((source, target)) = segment.split_once("->") else {
            return Err(format!("invalid mapping rule (missing ->): '{segment}'"));
        };
        let source = source.trim().to_owned();
        let target = target.trim().to_owned();
        if source.is_empty() {
            return Err(format!("empty source in mapping rule: '{segment}'"));
        }
        if target.is_empty() {
            return Err(format!("empty target in mapping rule: '{segment}'"));
        }
        rules.push(MapRule { source, target });
    }
    if rules.is_empty() {
        return Err("no mapping rules found".to_owned());
    }
    Ok(MappingSpec { rules })
}

/// Parse a JSON mapping file into a `MappingSpec`.
///
/// File format: `[{"source": "a.x", "target": "b.x"}, ...]`
pub fn parse_map_file(content: &str) -> Result<MappingSpec, String> {
    let rules: Vec<MapRule> =
        serde_json::from_str(content).map_err(|e| format!("invalid map file JSON: {e}"))?;
    if rules.is_empty() {
        return Err("map file contains no rules".to_owned());
    }
    Ok(MappingSpec { rules })
}

// ── Evaluation ──────────────────────────────────────────────────────────

/// Apply a mapping specification to transform source output into target input.
pub fn apply_mapping(source_output: &Value, spec: &MappingSpec) -> MappingResult {
    let mut output = Map::new();
    let mut errors = Vec::new();

    for rule in &spec.rules {
        match resolve_source(&rule.source, source_output) {
            Some(value) => {
                set_target(&mut output, &rule.target, value);
            }
            None => {
                errors.push(MappingError {
                    source: rule.source.clone(),
                    target: rule.target.clone(),
                    message: format!(
                        "source path '{}' not found in operation output",
                        rule.source
                    ),
                });
            }
        }
    }

    MappingResult {
        output: Value::Object(output),
        errors,
    }
}

/// Resolve a source expression against the source output.
fn resolve_source(source: &str, output: &Value) -> Option<Value> {
    // Check for literal string (quoted).
    if source.starts_with('"') && source.ends_with('"') && source.len() >= 2 {
        let literal = &source[1..source.len() - 1];
        return Some(Value::String(literal.to_owned()));
    }

    // Check for literal number.
    if let Ok(n) = source.parse::<i64>() {
        return Some(Value::Number(n.into()));
    }

    // Check for literal boolean.
    match source {
        "true" => return Some(Value::Bool(true)),
        "false" => return Some(Value::Bool(false)),
        "null" => return Some(Value::Null),
        _ => {}
    }

    // Path resolution.
    resolve_json_path(output, source)
}

/// Resolve a dotted JSON path with array index support.
///
/// Examples: `"title"`, `"user.login"`, `"items[0].name"`, `"labels[0]"`
fn resolve_json_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        // Handle array index notation.
        if let Some((key, rest)) = segment.split_once('[') {
            // Navigate to the key first.
            if !key.is_empty() {
                current = current.get(key)?;
            }
            // Parse the index.
            let idx_str = rest.strip_suffix(']')?;
            let idx: usize = idx_str.parse().ok()?;
            current = current.as_array()?.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current.clone())
}

/// Set a value in the output map, supporting nested targets via dot notation.
fn set_target(output: &mut Map<String, Value>, target: &str, value: Value) {
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() == 1 {
        output.insert(target.to_owned(), value);
        return;
    }

    // Navigate/create nested objects.
    let mut current = output;
    for part in &parts[..parts.len() - 1] {
        let entry = current
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        current = match entry {
            Value::Object(map) => map,
            _ => return, // Can't nest into non-object.
        };
    }
    if let Some(last) = parts.last() {
        current.insert((*last).to_owned(), value);
    }
}

// ── Pipe plan (for dry-run) ─────────────────────────────────────────────

/// A pipe execution plan for preview/dry-run.
#[derive(Debug, Clone, Serialize)]
pub struct PipePlan {
    /// Source operation ID.
    pub source_operation: String,
    /// Target operation ID.
    pub target_operation: String,
    /// Mapping rules applied.
    pub mapping: MappingSpec,
    /// Whether the target operation is risky and requires approval.
    pub requires_approval: bool,
    /// Estimated output for the target (if dry-run with source output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_input: Option<Value>,
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── parse_map_expression ────────────────────────────────────────

    #[test]
    fn parse_simple_rule() {
        let spec = parse_map_expression("title -> text").unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "title");
        assert_eq!(spec.rules[0].target, "text");
    }

    #[test]
    fn parse_multiple_rules() {
        let spec = parse_map_expression("title -> text, body -> description").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].target, "text");
        assert_eq!(spec.rules[1].target, "description");
    }

    #[test]
    fn parse_with_path_expressions() {
        let spec =
            parse_map_expression("issues[0].title -> text, \"#general\" -> channel").unwrap();
        assert_eq!(spec.rules.len(), 2);
        assert_eq!(spec.rules[0].source, "issues[0].title");
        assert_eq!(spec.rules[1].source, "\"#general\"");
    }

    #[test]
    fn parse_trims_whitespace() {
        let spec = parse_map_expression("  title  ->  text  ").unwrap();
        assert_eq!(spec.rules[0].source, "title");
        assert_eq!(spec.rules[0].target, "text");
    }

    #[test]
    fn parse_skips_empty_segments() {
        let spec = parse_map_expression("title -> text, , body -> desc").unwrap();
        assert_eq!(spec.rules.len(), 2);
    }

    #[test]
    fn parse_error_missing_arrow() {
        let err = parse_map_expression("title text").unwrap_err();
        assert!(err.contains("missing ->"));
    }

    #[test]
    fn parse_error_empty_source() {
        let err = parse_map_expression(" -> text").unwrap_err();
        assert!(err.contains("empty source"));
    }

    #[test]
    fn parse_error_empty_target() {
        let err = parse_map_expression("title -> ").unwrap_err();
        assert!(err.contains("empty target"));
    }

    #[test]
    fn parse_error_empty_expression() {
        let err = parse_map_expression("").unwrap_err();
        assert!(err.contains("no mapping rules"));
    }

    // ── parse_map_file ──────────────────────────────────────────────

    #[test]
    fn parse_file_format() {
        let content = r#"[{"source": "title", "target": "text"}]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 1);
        assert_eq!(spec.rules[0].source, "title");
    }

    #[test]
    fn parse_file_multiple_rules() {
        let content = r#"[
            {"source": "title", "target": "text"},
            {"source": "body", "target": "description"}
        ]"#;
        let spec = parse_map_file(content).unwrap();
        assert_eq!(spec.rules.len(), 2);
    }

    #[test]
    fn parse_file_invalid_json() {
        let err = parse_map_file("not json").unwrap_err();
        assert!(err.contains("invalid map file"));
    }

    #[test]
    fn parse_file_empty_rules() {
        let err = parse_map_file("[]").unwrap_err();
        assert!(err.contains("no rules"));
    }

    // ── resolve_source ──────────────────────────────────────────────

    #[test]
    fn resolve_literal_string() {
        let val = resolve_source("\"#general\"", &json!({}));
        assert_eq!(val, Some(json!("#general")));
    }

    #[test]
    fn resolve_literal_number() {
        let val = resolve_source("42", &json!({}));
        assert_eq!(val, Some(json!(42)));
    }

    #[test]
    fn resolve_literal_true() {
        let val = resolve_source("true", &json!({}));
        assert_eq!(val, Some(json!(true)));
    }

    #[test]
    fn resolve_literal_false() {
        let val = resolve_source("false", &json!({}));
        assert_eq!(val, Some(json!(false)));
    }

    #[test]
    fn resolve_literal_null() {
        let val = resolve_source("null", &json!({}));
        assert_eq!(val, Some(Value::Null));
    }

    #[test]
    fn resolve_simple_path() {
        let output = json!({"title": "Bug report"});
        let val = resolve_source("title", &output);
        assert_eq!(val, Some(json!("Bug report")));
    }

    #[test]
    fn resolve_nested_path() {
        let output = json!({"user": {"login": "octocat"}});
        let val = resolve_source("user.login", &output);
        assert_eq!(val, Some(json!("octocat")));
    }

    #[test]
    fn resolve_array_index() {
        let output = json!({"items": [{"name": "first"}, {"name": "second"}]});
        let val = resolve_source("items[0].name", &output);
        assert_eq!(val, Some(json!("first")));
    }

    #[test]
    fn resolve_array_second_element() {
        let output = json!({"items": [{"name": "first"}, {"name": "second"}]});
        let val = resolve_source("items[1].name", &output);
        assert_eq!(val, Some(json!("second")));
    }

    #[test]
    fn resolve_missing_path() {
        let output = json!({"title": "Bug"});
        let val = resolve_source("nonexistent", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_deep_nested_path() {
        let output = json!({"a": {"b": {"c": {"d": "deep"}}}});
        let val = resolve_source("a.b.c.d", &output);
        assert_eq!(val, Some(json!("deep")));
    }

    #[test]
    fn resolve_array_out_of_bounds() {
        let output = json!({"items": [{"name": "only"}]});
        let val = resolve_source("items[5].name", &output);
        assert_eq!(val, None);
    }

    #[test]
    fn resolve_bare_array_index() {
        let output = json!(["a", "b", "c"]);
        let val = resolve_source("[1]", &output);
        assert_eq!(val, Some(json!("b")));
    }

    // ── set_target ──────────────────────────────────────────────────

    #[test]
    fn set_simple_target() {
        let mut output = Map::new();
        set_target(&mut output, "text", json!("hello"));
        assert_eq!(output["text"], json!("hello"));
    }

    #[test]
    fn set_nested_target() {
        let mut output = Map::new();
        set_target(&mut output, "metadata.name", json!("test"));
        assert_eq!(output["metadata"]["name"], json!("test"));
    }

    #[test]
    fn set_deep_nested_target() {
        let mut output = Map::new();
        set_target(&mut output, "a.b.c", json!(42));
        assert_eq!(output["a"]["b"]["c"], json!(42));
    }

    #[test]
    fn set_multiple_nested_targets() {
        let mut output = Map::new();
        set_target(&mut output, "user.name", json!("Alice"));
        set_target(&mut output, "user.email", json!("alice@example.com"));
        assert_eq!(output["user"]["name"], json!("Alice"));
        assert_eq!(output["user"]["email"], json!("alice@example.com"));
    }

    // ── apply_mapping ───────────────────────────────────────────────

    #[test]
    fn apply_simple_mapping() {
        let output = json!({"title": "Bug", "body": "Details"});
        let spec = parse_map_expression("title -> text, body -> description").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["description"], "Details");
    }

    #[test]
    fn apply_mapping_with_literal() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, \"#general\" -> channel").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["channel"], "#general");
    }

    #[test]
    fn apply_mapping_with_path() {
        let output = json!({"issues": [{"title": "Bug", "number": 42}]});
        let spec =
            parse_map_expression("issues[0].title -> text, issues[0].number -> issue_number")
                .unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["text"], "Bug");
        assert_eq!(result.output["issue_number"], 42);
    }

    #[test]
    fn apply_mapping_missing_source() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("missing -> text").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].message.contains("not found"));
    }

    #[test]
    fn apply_mapping_partial_success() {
        let output = json!({"title": "Bug"});
        let spec = parse_map_expression("title -> text, missing -> desc").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.output["text"], "Bug");
    }

    #[test]
    fn apply_mapping_nested_target() {
        let output = json!({"name": "test"});
        let spec = parse_map_expression("name -> metadata.name").unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["metadata"]["name"], "test");
    }

    #[test]
    fn apply_mapping_empty_output() {
        let output = json!({});
        let spec = parse_map_expression("title -> text").unwrap();
        let result = apply_mapping(&output, &spec);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn apply_mapping_preserves_types() {
        let output = json!({
            "count": 42,
            "active": true,
            "tags": ["a", "b"],
            "meta": {"key": "val"}
        });
        let spec =
            parse_map_expression("count -> num, active -> flag, tags -> labels, meta -> extra")
                .unwrap();
        let result = apply_mapping(&output, &spec);
        assert!(result.errors.is_empty());
        assert_eq!(result.output["num"], 42);
        assert_eq!(result.output["flag"], true);
        assert_eq!(result.output["labels"], json!(["a", "b"]));
        assert_eq!(result.output["extra"], json!({"key": "val"}));
    }

    // ── MappingSpec serde ───────────────────────────────────────────

    #[test]
    fn mapping_spec_roundtrip() {
        let spec = parse_map_expression("title -> text, body -> desc").unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        let back: MappingSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back.rules[0].source, "title");
    }

    // ── MappingError display ────────────────────────────────────────

    #[test]
    fn mapping_error_display() {
        let err = MappingError {
            source: "a.b".to_owned(),
            target: "c".to_owned(),
            message: "not found".to_owned(),
        };
        assert_eq!(err.to_string(), "a.b -> c: not found");
    }

    // ── PipePlan serialization ──────────────────────────────────────

    #[test]
    fn pipe_plan_serializes() {
        let plan = PipePlan {
            source_operation: "github.list_issues".to_owned(),
            target_operation: "slack.send_message".to_owned(),
            mapping: parse_map_expression("title -> text").unwrap(),
            requires_approval: false,
            preview_input: Some(json!({"text": "Bug report"})),
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["source_operation"], "github.list_issues");
        assert!(json.get("preview_input").is_some());
    }

    #[test]
    fn pipe_plan_skips_none_preview() {
        let plan = PipePlan {
            source_operation: "a".to_owned(),
            target_operation: "b".to_owned(),
            mapping: MappingSpec::default(),
            requires_approval: true,
            preview_input: None,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("preview_input").is_none());
        assert_eq!(json["requires_approval"], true);
    }

    // ── resolve_json_path edge cases ────────────────────────────────

    #[test]
    fn resolve_path_top_level_array() {
        let val = json!([1, 2, 3]);
        assert_eq!(resolve_json_path(&val, "[2]"), Some(json!(3)));
    }

    #[test]
    fn resolve_path_nested_array() {
        let val = json!({"data": {"items": [10, 20, 30]}});
        assert_eq!(resolve_json_path(&val, "data.items[1]"), Some(json!(20)));
    }

    #[test]
    fn resolve_path_empty_string() {
        let val = json!({"key": "value"});
        // Empty path returns the value itself.
        assert_eq!(resolve_json_path(&val, ""), Some(json!({"key": "value"})));
    }

    #[test]
    fn resolve_path_number_value() {
        let val = json!({"count": 42});
        assert_eq!(resolve_json_path(&val, "count"), Some(json!(42)));
    }

    #[test]
    fn resolve_path_boolean_value() {
        let val = json!({"active": true});
        assert_eq!(resolve_json_path(&val, "active"), Some(json!(true)));
    }

    #[test]
    fn resolve_path_null_value() {
        let val = json!({"field": null});
        assert_eq!(resolve_json_path(&val, "field"), Some(Value::Null));
    }

    // ── MapRule equality ────────────────────────────────────────────

    #[test]
    fn map_rule_equality() {
        let a = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        let b = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn map_rule_inequality() {
        let a = MapRule {
            source: "title".to_owned(),
            target: "text".to_owned(),
        };
        let b = MapRule {
            source: "body".to_owned(),
            target: "text".to_owned(),
        };
        assert_ne!(a, b);
    }

    // ── Default mapping spec ────────────────────────────────────────

    #[test]
    fn default_mapping_spec_empty() {
        let spec = MappingSpec::default();
        assert!(spec.rules.is_empty());
    }
}
