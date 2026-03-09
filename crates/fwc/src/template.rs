//! Input payload template generator from JSON Schema.
//!
//! Generates fill-in-the-blanks JSON templates for operations, with placeholder
//! values and type/required annotations so agents can quickly scaffold payloads.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Generate a template from a JSON Schema, with placeholder values.
pub fn generate_template(
    schema: &Value,
    required_only: bool,
    fill: &BTreeMap<String, String>,
) -> Value {
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => generate_object(schema, required_only, fill, &[]),
        Some("array") => generate_array(schema, required_only, fill, &[]),
        Some(type_name) => placeholder_for_type(type_name, false),
        None => json!("<unknown>"),
    }
}

fn generate_object(
    schema: &Value,
    required_only: bool,
    fill: &BTreeMap<String, String>,
    path: &[String],
) -> Value {
    let Some(Value::Object(properties)) = schema.get("properties") else {
        return json!({});
    };

    let required_fields: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut result = serde_json::Map::new();

    for (key, prop_schema) in properties {
        let is_required = required_fields.contains(&key.as_str());

        if required_only && !is_required {
            continue;
        }

        // Check if this field has a pre-filled value.
        let fill_key = if path.is_empty() {
            key.clone()
        } else {
            format!("{}.{key}", path.join("."))
        };

        if let Some(value) = fill.get(&fill_key) {
            // Parse the fill value as JSON, fallback to string.
            let parsed = serde_json::from_str(value).unwrap_or(Value::String(value.clone()));
            result.insert(key.clone(), parsed);
            continue;
        }
        // Also check just the key name (flat fill).
        if let Some(value) = fill.get(key) {
            let parsed = serde_json::from_str(value).unwrap_or(Value::String(value.clone()));
            result.insert(key.clone(), parsed);
            continue;
        }

        let mut child_path = path.to_vec();
        child_path.push(key.clone());

        let prop_value =
            generate_property(prop_schema, is_required, required_only, fill, &child_path);
        result.insert(key.clone(), prop_value);
    }

    Value::Object(result)
}

fn generate_property(
    schema: &Value,
    is_required: bool,
    required_only: bool,
    fill: &BTreeMap<String, String>,
    path: &[String],
) -> Value {
    // If there's a default value, use it.
    if let Some(default) = schema.get("default") {
        return default.clone();
    }

    // If there's an example value, use it.
    if let Some(example) = schema.get("example") {
        return example.clone();
    }

    // If there's an enum, show the first value.
    if let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
        if let Some(first) = enum_values.first() {
            let suffix = if enum_values.len() > 1 {
                format!(
                    "|{}",
                    enum_values
                        .iter()
                        .skip(1)
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("|")
                )
            } else {
                String::new()
            };
            if let Some(s) = first.as_str() {
                return Value::String(format!("{s}{suffix}"));
            }
            return first.clone();
        }
    }

    let type_name = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string");

    match type_name {
        "object" => generate_object(schema, required_only, fill, path),
        "array" => generate_array(schema, required_only, fill, path),
        _ => placeholder_for_type(type_name, is_required),
    }
}

fn generate_array(
    schema: &Value,
    required_only: bool,
    fill: &BTreeMap<String, String>,
    path: &[String],
) -> Value {
    let item_schema = schema
        .get("items")
        .cloned()
        .unwrap_or(json!({"type": "string"}));
    let item = generate_property(&item_schema, false, required_only, fill, path);
    json!([item])
}

fn placeholder_for_type(type_name: &str, is_required: bool) -> Value {
    let req = if is_required { "required" } else { "optional" };
    match type_name {
        "string" => Value::String(format!("<string:{req}>")),
        "integer" => Value::String(format!("<integer:{req}>")),
        "number" => Value::String(format!("<number:{req}>")),
        "boolean" => Value::String(format!("<boolean:{req}>")),
        "null" => Value::Null,
        _ => Value::String(format!("<{type_name}:{req}>")),
    }
}

/// Parse a `--fill` argument like `"owner=octocat,repo=hello-world"` into a map.
pub fn parse_fill_args(fill_str: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if fill_str.is_empty() {
        return map;
    }
    for pair in fill_str.split(',') {
        if let Some((key, value)) = pair.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_object_template() {
        let schema = json!({
            "type": "object",
            "required": ["owner", "repo"],
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "page": { "type": "integer" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["owner"], "<string:required>");
        assert_eq!(result["repo"], "<string:required>");
        assert_eq!(result["page"], "<integer:optional>");
    }

    #[test]
    fn required_only_template() {
        let schema = json!({
            "type": "object",
            "required": ["owner"],
            "properties": {
                "owner": { "type": "string" },
                "body": { "type": "string" }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert_eq!(result["owner"], "<string:required>");
        assert!(result.get("body").is_none());
    }

    #[test]
    fn fill_replaces_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["owner", "repo"],
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("owner".to_string(), "octocat".to_string());
        fill.insert("repo".to_string(), "hello-world".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["owner"], "octocat");
        assert_eq!(result["repo"], "hello-world");
        assert_eq!(result["title"], "<string:optional>");
    }

    #[test]
    fn enum_shows_options() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["open", "closed", "all"]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        let state = result["state"].as_str().unwrap();
        assert!(state.contains("open"));
        assert!(state.contains("closed"));
    }

    #[test]
    fn default_value_used() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "default": 1 }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["page"], 1);
    }

    #[test]
    fn example_value_used() {
        let schema = json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "example": "user@example.com" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["email"], "user@example.com");
    }

    #[test]
    fn array_field_generates_single_item() {
        let schema = json!({
            "type": "object",
            "properties": {
                "labels": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["labels"].is_array());
        assert_eq!(result["labels"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn nested_object_template() {
        let schema = json!({
            "type": "object",
            "required": ["metadata"],
            "properties": {
                "metadata": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" },
                        "namespace": { "type": "string" }
                    }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["metadata"].is_object());
        assert_eq!(result["metadata"]["name"], "<string:required>");
        assert_eq!(result["metadata"]["namespace"], "<string:optional>");
    }

    #[test]
    fn nested_required_only_propagates() {
        let schema = json!({
            "type": "object",
            "required": ["metadata"],
            "properties": {
                "metadata": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" },
                        "namespace": { "type": "string" }
                    }
                },
                "optional_field": { "type": "string" }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert!(result.get("optional_field").is_none());
        assert!(result["metadata"].is_object());
        assert_eq!(result["metadata"]["name"], "<string:required>");
        // nested non-required should also be filtered
        assert!(result["metadata"].get("namespace").is_none());
    }

    #[test]
    fn parse_fill_args_basic() {
        let fill = parse_fill_args("owner=octocat,repo=hello-world");
        assert_eq!(fill.get("owner").unwrap(), "octocat");
        assert_eq!(fill.get("repo").unwrap(), "hello-world");
    }

    #[test]
    fn parse_fill_args_empty() {
        let fill = parse_fill_args("");
        assert!(fill.is_empty());
    }

    #[test]
    fn parse_fill_args_with_spaces() {
        let fill = parse_fill_args("key = value , other = data");
        assert_eq!(fill.get("key").unwrap(), "value");
        assert_eq!(fill.get("other").unwrap(), "data");
    }

    #[test]
    fn boolean_placeholder() {
        let schema = json!({
            "type": "object",
            "properties": {
                "verbose": { "type": "boolean" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["verbose"], "<boolean:optional>");
    }

    #[test]
    fn empty_schema_returns_empty_object() {
        let schema = json!({"type": "object"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, json!({}));
    }

    #[test]
    fn fill_json_value_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("count".to_string(), "42".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["count"], 42);
    }

    #[test]
    fn deterministic_output() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" },
                "c": { "type": "boolean" }
            }
        });
        let a =
            serde_json::to_string(&generate_template(&schema, false, &BTreeMap::new())).unwrap();
        let b =
            serde_json::to_string(&generate_template(&schema, false, &BTreeMap::new())).unwrap();
        assert_eq!(a, b);
    }
}
