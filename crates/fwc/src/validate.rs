//! Pre-invoke input validation with human-readable error messages.
//!
//! Validates operation inputs against JSON Schema BEFORE sending to the
//! connector, catching errors locally and producing actionable fix suggestions.

use serde::Serialize;
use serde_json::Value;

/// A single validation error with fix suggestion.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    /// JSON path to the error (e.g. "owner", "metadata.name").
    pub path: String,
    /// What went wrong.
    pub message: String,
    /// How to fix it.
    pub suggestion: String,
}

/// Result of validating input against schema.
#[derive(Debug)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate an input value against a JSON Schema.
pub fn validate(input: &Value, schema: &Value) -> ValidationResult {
    let mut errors = Vec::new();
    validate_value(input, schema, &[], &mut errors);
    ValidationResult { errors }
}

fn validate_value(
    input: &Value,
    schema: &Value,
    path: &[String],
    errors: &mut Vec<ValidationError>,
) {
    let path_str = if path.is_empty() {
        "<root>".to_string()
    } else {
        path.join(".")
    };

    // Check type constraint.
    if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
        if !type_matches(input, expected_type) {
            let actual = json_type_name(input);
            errors.push(ValidationError {
                path: path_str.clone(),
                message: format!("expected {expected_type}, got {actual}"),
                suggestion: type_fix_suggestion(expected_type, input),
            });
            return; // Don't recurse into wrong type.
        }
    }

    // Check enum constraint.
    if let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
        if !enum_values.contains(input) {
            let allowed = enum_values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            errors.push(ValidationError {
                path: path_str.clone(),
                message: "value not in allowed set".to_string(),
                suggestion: format!("use one of: {allowed}"),
            });
        }
    }

    // For objects: check required fields and recurse into properties.
    if input.is_object() {
        validate_object(input, schema, path, errors);
    }

    // For arrays: validate items against items schema.
    if input.is_array() {
        validate_array(input, schema, path, errors);
    }

    // Check string constraints.
    if let Some(s) = input.as_str() {
        validate_string(s, schema, &path_str, errors);
    }

    // Check numeric constraints.
    if let Some(n) = input.as_f64() {
        validate_number(n, schema, &path_str, errors);
    }
}

fn validate_object(
    input: &Value,
    schema: &Value,
    path: &[String],
    errors: &mut Vec<ValidationError>,
) {
    let Some(input_obj) = input.as_object() else {
        return;
    };

    // Check required fields.
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for req in required.iter().filter_map(Value::as_str) {
            if !input_obj.contains_key(req) {
                let mut field_path = path.to_vec();
                field_path.push(req.to_string());
                let type_hint = schema
                    .get("properties")
                    .and_then(|p| p.get(req))
                    .and_then(|p| p.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("value");
                errors.push(ValidationError {
                    path: field_path.join("."),
                    message: "required field missing".to_string(),
                    suggestion: format!("add '{req}' with a {type_hint} value"),
                });
            }
        }
    }

    // Recurse into properties.
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (key, prop_schema) in properties {
            if let Some(value) = input_obj.get(key) {
                let mut child_path = path.to_vec();
                child_path.push(key.clone());
                validate_value(value, prop_schema, &child_path, errors);
            }
        }
    }
}

fn validate_array(
    input: &Value,
    schema: &Value,
    path: &[String],
    errors: &mut Vec<ValidationError>,
) {
    let Some(arr) = input.as_array() else {
        return;
    };

    // Check minItems / maxItems.
    if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
        if (arr.len() as u64) < min {
            let path_str = if path.is_empty() {
                "<root>".to_string()
            } else {
                path.join(".")
            };
            errors.push(ValidationError {
                path: path_str,
                message: format!("array too short: {} items, minimum {min}", arr.len()),
                suggestion: format!(
                    "add at least {} more item(s)",
                    usize::try_from(min).unwrap_or(usize::MAX) - arr.len()
                ),
            });
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
        if (arr.len() as u64) > max {
            let path_str = if path.is_empty() {
                "<root>".to_string()
            } else {
                path.join(".")
            };
            errors.push(ValidationError {
                path: path_str,
                message: format!("array too long: {} items, maximum {max}", arr.len()),
                suggestion: format!(
                    "remove {} item(s)",
                    arr.len() - usize::try_from(max).unwrap_or(0)
                ),
            });
        }
    }

    // Validate each item against items schema.
    if let Some(item_schema) = schema.get("items") {
        for (i, item) in arr.iter().enumerate() {
            let mut item_path = path.to_vec();
            item_path.push(format!("[{i}]"));
            validate_value(item, item_schema, &item_path, errors);
        }
    }
}

fn validate_string(s: &str, schema: &Value, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(min_len) = schema.get("minLength").and_then(Value::as_u64) {
        if (s.len() as u64) < min_len {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("string too short: {} chars, minimum {min_len}", s.len()),
                suggestion: format!("provide at least {min_len} characters"),
            });
        }
    }
    if let Some(max_len) = schema.get("maxLength").and_then(Value::as_u64) {
        if (s.len() as u64) > max_len {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("string too long: {} chars, maximum {max_len}", s.len()),
                suggestion: format!("shorten to at most {max_len} characters"),
            });
        }
    }
}

fn validate_number(n: f64, schema: &Value, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
        if n < min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value {n} is below minimum {min}"),
                suggestion: format!("use a value >= {min}"),
            });
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
        if n > max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value {n} exceeds maximum {max}"),
                suggestion: format!("use a value <= {max}"),
            });
        }
    }
}

fn type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_fix_suggestion(expected: &str, actual: &Value) -> String {
    match (expected, actual) {
        ("array", Value::String(s)) => format!("wrap in array: [\"{s}\"]"),
        ("array", _) => "wrap the value in an array: [value]".to_string(),
        ("string", Value::Number(n)) => format!("use string: \"{n}\""),
        ("integer" | "number", Value::String(s)) => format!("use number: {s}"),
        ("boolean", Value::String(s)) if s == "true" || s == "false" => {
            format!("use boolean: {s} (without quotes)")
        }
        _ => format!("provide a {expected} value"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issue_schema() -> Value {
        json!({
            "type": "object",
            "required": ["owner", "repo", "title"],
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" },
                "body": { "type": "string" },
                "labels": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "milestone": { "type": "integer" }
            }
        })
    }

    // ── Valid input tests ─────────────────────────────────────────────

    #[test]
    fn valid_input_passes() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug report"
        });
        let result = validate(&input, &issue_schema());
        assert!(result.is_valid(), "errors: {:?}", result.errors);
    }

    #[test]
    fn valid_input_with_optional_fields() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug report",
            "body": "Description",
            "labels": ["bug"],
            "milestone": 3
        });
        let result = validate(&input, &issue_schema());
        assert!(result.is_valid());
    }

    // ── Missing required fields ──────────────────────────────────────

    #[test]
    fn missing_required_field() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world"
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, "title");
        assert!(result.errors[0].message.contains("required"));
        assert!(result.errors[0].suggestion.contains("title"));
    }

    #[test]
    fn multiple_missing_required() {
        let input = json!({});
        let result = validate(&input, &issue_schema());
        assert_eq!(result.errors.len(), 3);
    }

    // ── Type mismatch tests ─────────────────────────────────────────

    #[test]
    fn wrong_type_string_for_integer() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "milestone": "3"
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "milestone");
        assert!(result.errors[0].message.contains("integer"));
        assert!(result.errors[0].suggestion.contains('3'));
    }

    #[test]
    fn wrong_type_string_for_array() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "labels": "bug"
        });
        let result = validate(&input, &issue_schema());
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("array"));
        assert!(result.errors[0].suggestion.contains("[\"bug\"]"));
    }

    // ── Enum validation ─────────────────────────────────────────────

    #[test]
    fn enum_invalid_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed", "all"] }
            }
        });
        let input = json!({"state": "invalid"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("open"));
        assert!(result.errors[0].suggestion.contains("closed"));
    }

    #[test]
    fn enum_valid_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let input = json!({"state": "open"});
        assert!(validate(&input, &schema).is_valid());
    }

    // ── Nested object validation ────────────────────────────────────

    #[test]
    fn nested_required_field_missing() {
        let schema = json!({
            "type": "object",
            "required": ["metadata"],
            "properties": {
                "metadata": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            }
        });
        let input = json!({"metadata": {}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "metadata.name");
    }

    #[test]
    fn nested_type_mismatch() {
        let schema = json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "port": { "type": "integer" }
                    }
                }
            }
        });
        let input = json!({"config": {"port": "8080"}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "config.port");
    }

    // ── Array validation ────────────────────────────────────────────

    #[test]
    fn array_item_type_mismatch() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        let input = json!({"tags": ["valid", 42]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("[1]"));
    }

    #[test]
    fn array_min_items() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "minItems": 2, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": ["one"]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    // ── String constraints ──────────────────────────────────────────

    #[test]
    fn string_min_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 3 }
            }
        });
        let input = json!({"name": "ab"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    // ── Number constraints ──────────────────────────────────────────

    #[test]
    fn number_minimum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "minimum": 1 }
            }
        });
        let input = json!({"page": 0});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("below minimum"));
    }

    #[test]
    fn number_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 }
            }
        });
        let input = json!({"limit": 200});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("exceeds maximum"));
    }

    // ── Empty/edge cases ────────────────────────────────────────────

    #[test]
    fn empty_schema_accepts_anything() {
        let schema = json!({});
        let input = json!({"anything": "goes"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn empty_input_with_no_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "optional": { "type": "string" }
            }
        });
        assert!(validate(&json!({}), &schema).is_valid());
    }

    // ── Error has actionable suggestion ──────────────────────────────

    #[test]
    fn suggestion_is_not_empty() {
        let input = json!({});
        let result = validate(&input, &issue_schema());
        for error in &result.errors {
            assert!(
                !error.suggestion.is_empty(),
                "suggestion should not be empty for: {}",
                error.path
            );
        }
    }

    #[test]
    fn boolean_string_fix_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "verbose": { "type": "boolean" }
            }
        });
        let input = json!({"verbose": "true"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("true"));
        assert!(result.errors[0].suggestion.contains("without quotes"));
    }

    // ── Additional type mismatch tests ───────────────────────────────

    #[test]
    fn wrong_type_number_for_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!({"name": 42});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "name");
        assert!(result.errors[0].message.contains("string"));
        assert!(result.errors[0].suggestion.contains("42"));
    }

    #[test]
    fn wrong_type_integer_for_boolean() {
        let schema = json!({
            "type": "object",
            "properties": {
                "flag": { "type": "boolean" }
            }
        });
        let input = json!({"flag": 1});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("boolean"));
        assert!(result.errors[0].suggestion.contains("boolean"));
    }

    #[test]
    fn wrong_type_object_for_array() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array" }
            }
        });
        let input = json!({"items": {"key": "val"}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("array"));
        assert!(result.errors[0].suggestion.contains("[value]"));
    }

    #[test]
    fn wrong_type_array_for_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "config": { "type": "object" }
            }
        });
        let input = json!({"config": [1, 2, 3]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("object"));
    }

    #[test]
    fn wrong_type_boolean_for_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!({"name": true});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("string"));
    }

    #[test]
    fn wrong_type_null_for_integer() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            }
        });
        let input = json!({"count": null});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("integer"));
        assert!(result.errors[0].message.contains("null"));
    }

    #[test]
    fn boolean_string_false_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "verbose": { "type": "boolean" }
            }
        });
        let input = json!({"verbose": "false"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("false"));
        assert!(result.errors[0].suggestion.contains("without quotes"));
    }

    #[test]
    fn number_string_suggestion_for_number_type() {
        let schema = json!({
            "type": "object",
            "properties": {
                "amount": { "type": "number" }
            }
        });
        let input = json!({"amount": "3.14"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("3.14"));
    }

    // ── Additional string constraint tests ──────────────────────────

    #[test]
    fn string_max_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "maxLength": 5 }
            }
        });
        let input = json!({"code": "toolong"});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too long"));
        assert!(result.errors[0].suggestion.contains('5'));
    }

    #[test]
    fn string_exact_min_length_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "code": { "type": "string", "minLength": 3 }
            }
        });
        let input = json!({"code": "abc"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn string_both_min_and_max_length_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "token": { "type": "string", "minLength": 3, "maxLength": 10 }
            }
        });
        let input = json!({"token": "hello"});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn string_empty_below_min_length() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 1 }
            }
        });
        let input = json!({"name": ""});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    // ── Additional number constraint tests ──────────────────────────

    #[test]
    fn number_exact_minimum_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "minimum": 1 }
            }
        });
        let input = json!({"page": 1});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn number_exact_maximum_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 }
            }
        });
        let input = json!({"limit": 100});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn number_both_minimum_and_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer", "minimum": 1, "maximum": 50 }
            }
        });
        let input = json!({"count": 25});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn number_below_minimum_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "minimum": 1 }
            }
        });
        let input = json!({"page": -5});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains(">= 1"));
    }

    #[test]
    fn number_above_maximum_suggestion() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "maximum": 100 }
            }
        });
        let input = json!({"limit": 500});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].suggestion.contains("<= 100"));
    }

    #[test]
    fn float_number_minimum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "threshold": { "type": "number", "minimum": 0.0 }
            }
        });
        let input = json!({"threshold": -0.5});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("below minimum"));
    }

    #[test]
    fn float_number_maximum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "score": { "type": "number", "maximum": 1.0 }
            }
        });
        let input = json!({"score": 1.5});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("exceeds maximum"));
    }

    // ── Array constraint tests ──────────────────────────────────────

    #[test]
    fn array_max_items() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": { "type": "array", "maxItems": 3, "items": {"type": "string"} }
            }
        });
        let input = json!({"tags": ["a", "b", "c", "d"]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too long"));
        assert!(result.errors[0].suggestion.contains("remove"));
    }

    #[test]
    fn array_exact_min_items_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "minItems": 2, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": ["one", "two"]});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn array_exact_max_items_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "maxItems": 2, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": ["one", "two"]});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn array_empty_below_min() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "minItems": 1, "items": {"type": "string"} }
            }
        });
        let input = json!({"items": []});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("too short"));
    }

    #[test]
    fn array_multiple_item_type_mismatches() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ids": { "type": "array", "items": { "type": "integer" } }
            }
        });
        let input = json!({"ids": ["a", "b", 3]});
        let result = validate(&input, &schema);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].path.contains("[0]"));
        assert!(result.errors[1].path.contains("[1]"));
    }

    // ── Deeply nested validation tests ──────────────────────────────

    #[test]
    fn three_level_nested_required() {
        let schema = json!({
            "type": "object",
            "required": ["a"],
            "properties": {
                "a": {
                    "type": "object",
                    "required": ["b"],
                    "properties": {
                        "b": {
                            "type": "object",
                            "required": ["c"],
                            "properties": {
                                "c": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let input = json!({"a": {"b": {}}});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "a.b.c");
    }

    #[test]
    fn nested_type_mismatch_in_array_of_objects() {
        let schema = json!({
            "type": "object",
            "properties": {
                "users": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "age": { "type": "integer" }
                        }
                    }
                }
            }
        });
        let input = json!({"users": [{"age": "thirty"}]});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("users"));
        assert!(result.errors[0].path.contains("[0]"));
        assert!(result.errors[0].path.contains("age"));
    }

    // ── Enum edge cases ─────────────────────────────────────────────

    #[test]
    fn enum_with_integer_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "priority": { "type": "integer", "enum": [1, 2, 3] }
            }
        });
        let input = json!({"priority": 4});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].message.contains("not in allowed set"));
    }

    #[test]
    fn enum_with_valid_integer() {
        let schema = json!({
            "type": "object",
            "properties": {
                "priority": { "type": "integer", "enum": [1, 2, 3] }
            }
        });
        let input = json!({"priority": 2});
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn enum_empty_string_invalid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let input = json!({"state": ""});
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
    }

    // ── Validation result API tests ─────────────────────────────────

    #[test]
    fn validation_result_is_valid_when_no_errors() {
        let result = ValidationResult { errors: Vec::new() };
        assert!(result.is_valid());
    }

    #[test]
    fn validation_result_not_valid_with_errors() {
        let result = ValidationResult {
            errors: vec![ValidationError {
                path: "field".to_string(),
                message: "bad".to_string(),
                suggestion: "fix it".to_string(),
            }],
        };
        assert!(!result.is_valid());
    }

    #[test]
    fn validation_error_debug_format() {
        let err = ValidationError {
            path: "name".to_string(),
            message: "required".to_string(),
            suggestion: "add it".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("name"));
        assert!(debug.contains("required"));
    }

    #[test]
    fn validation_error_clone() {
        let err = ValidationError {
            path: "f".to_string(),
            message: "m".to_string(),
            suggestion: "s".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err.path, cloned.path);
        assert_eq!(err.message, cloned.message);
        assert_eq!(err.suggestion, cloned.suggestion);
    }

    #[test]
    fn validation_error_serializes() {
        let err = ValidationError {
            path: "x".to_string(),
            message: "bad".to_string(),
            suggestion: "fix".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["path"], "x");
        assert_eq!(json["message"], "bad");
        assert_eq!(json["suggestion"], "fix");
    }

    // ── Type matching helper tests ──────────────────────────────────

    #[test]
    fn type_matches_null() {
        assert!(type_matches(&Value::Null, "null"));
        assert!(!type_matches(&Value::Null, "string"));
    }

    #[test]
    fn type_matches_unknown_type_accepted() {
        assert!(type_matches(&json!(42), "unknown_type"));
    }

    #[test]
    fn type_matches_number_includes_integers() {
        assert!(type_matches(&json!(42), "number"));
        assert!(type_matches(&json!(1.5), "number"));
    }

    #[test]
    fn type_matches_integer_rejects_float() {
        assert!(!type_matches(&json!(1.5), "integer"));
    }

    // ── json_type_name helper tests ─────────────────────────────────

    #[test]
    fn json_type_name_all_types() {
        assert_eq!(json_type_name(&Value::Null), "null");
        assert_eq!(json_type_name(&json!(true)), "boolean");
        assert_eq!(json_type_name(&json!(42)), "integer");
        assert_eq!(json_type_name(&json!(1.5)), "number");
        assert_eq!(json_type_name(&json!("hello")), "string");
        assert_eq!(json_type_name(&json!([1, 2])), "array");
        assert_eq!(json_type_name(&json!({"a": 1})), "object");
    }

    // ── Root-level type mismatch ────────────────────────────────────

    #[test]
    fn root_type_mismatch_string_for_object() {
        let schema = json!({"type": "object"});
        let input = json!("hello");
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
        assert!(result.errors[0].message.contains("object"));
    }

    #[test]
    fn root_type_mismatch_array_for_object() {
        let schema = json!({"type": "object"});
        let input = json!([1, 2, 3]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
    }

    #[test]
    fn root_valid_array() {
        let schema = json!({
            "type": "array",
            "items": { "type": "string" }
        });
        let input = json!(["a", "b", "c"]);
        assert!(validate(&input, &schema).is_valid());
    }

    #[test]
    fn root_array_with_invalid_items() {
        let schema = json!({
            "type": "array",
            "items": { "type": "string" }
        });
        let input = json!(["a", 42, "c"]);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert!(result.errors[0].path.contains("[1]"));
    }

    // ── Extra properties (no additionalProperties enforcement) ─────

    #[test]
    fn extra_properties_accepted() {
        let input = json!({
            "owner": "octocat",
            "repo": "hello-world",
            "title": "Bug",
            "extra_field": "ignored"
        });
        let result = validate(&input, &issue_schema());
        assert!(result.is_valid());
    }

    #[test]
    fn null_input_with_object_schema() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!(null);
        let result = validate(&input, &schema);
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].path, "<root>");
    }
}
