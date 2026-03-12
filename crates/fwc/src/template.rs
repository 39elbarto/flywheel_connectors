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

    // ── Additional template tests ─────────────────────────────────

    #[test]
    fn number_placeholder() {
        let schema = json!({
            "type": "object",
            "properties": {
                "price": { "type": "number" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["price"], "<number:optional>");
    }

    #[test]
    fn null_type_returns_null() {
        let schema = json!({
            "type": "object",
            "properties": {
                "nothing": { "type": "null" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["nothing"].is_null());
    }

    #[test]
    fn unknown_type_placeholder() {
        let schema = json!({
            "type": "object",
            "properties": {
                "weird": { "type": "custom_type" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["weird"], "<custom_type:optional>");
    }

    #[test]
    fn required_string_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["name"], "<string:required>");
    }

    #[test]
    fn required_integer_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["count"],
            "properties": {
                "count": { "type": "integer" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["count"], "<integer:required>");
    }

    #[test]
    fn required_number_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["amount"],
            "properties": {
                "amount": { "type": "number" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["amount"], "<number:required>");
    }

    #[test]
    fn required_boolean_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["active"],
            "properties": {
                "active": { "type": "boolean" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["active"], "<boolean:required>");
    }

    #[test]
    fn top_level_array_generates_single_item() {
        let schema = json!({
            "type": "array",
            "items": { "type": "integer" }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 1);
        assert_eq!(result[0], "<integer:optional>");
    }

    #[test]
    fn top_level_string_type_returns_placeholder() {
        let schema = json!({"type": "string"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, "<string:optional>");
    }

    #[test]
    fn top_level_integer_type_returns_placeholder() {
        let schema = json!({"type": "integer"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, "<integer:optional>");
    }

    #[test]
    fn top_level_boolean_type_returns_placeholder() {
        let schema = json!({"type": "boolean"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, "<boolean:optional>");
    }

    #[test]
    fn no_type_returns_unknown() {
        let schema = json!({});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, "<unknown>");
    }

    #[test]
    fn enum_single_value_no_pipe() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "enum": ["only"]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["state"], "only");
    }

    #[test]
    fn enum_numeric_first_value_returned_directly() {
        let schema = json!({
            "type": "object",
            "properties": {
                "level": {
                    "type": "integer",
                    "enum": [1, 2, 3]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["level"], 1);
    }

    #[test]
    fn default_takes_precedence_over_example() {
        let schema = json!({
            "type": "object",
            "properties": {
                "port": { "type": "integer", "default": 8080, "example": 9090 }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["port"], 8080);
    }

    #[test]
    fn example_takes_precedence_over_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "color": { "type": "string", "example": "red", "enum": ["blue", "green"] }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["color"], "red");
    }

    #[test]
    fn fill_nested_path_replaces_correctly() {
        let schema = json!({
            "type": "object",
            "properties": {
                "metadata": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("metadata.name".to_string(), "my-app".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["metadata"]["name"], "my-app");
    }

    #[test]
    fn fill_json_boolean_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "active": { "type": "boolean" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("active".to_string(), "true".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["active"], true);
    }

    #[test]
    fn fill_json_null_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "field": { "type": "null" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("field".to_string(), "null".to_string());
        let result = generate_template(&schema, false, &fill);
        assert!(result["field"].is_null());
    }

    #[test]
    fn fill_non_json_string_kept_as_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tag": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("tag".to_string(), "hello world".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["tag"], "hello world");
    }

    #[test]
    fn fill_overrides_default() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page": { "type": "integer", "default": 1 }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("page".to_string(), "5".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["page"], 5);
    }

    #[test]
    fn fill_overrides_example() {
        let schema = json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "example": "test@example.com" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("email".to_string(), "me@example.com".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["email"], "me@example.com");
    }

    #[test]
    fn array_of_objects_generates_single_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": { "type": "integer" },
                            "name": { "type": "string" }
                        }
                    }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["items"].is_array());
        let items = result["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].is_object());
        assert_eq!(items[0]["id"], "<integer:required>");
    }

    #[test]
    fn array_without_items_uses_string_default() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": { "type": "array" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["tags"].is_array());
        assert_eq!(result["tags"][0], "<string:optional>");
    }

    #[test]
    fn deeply_nested_object_template() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {
                    "type": "object",
                    "properties": {
                        "b": {
                            "type": "object",
                            "properties": {
                                "c": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["a"]["b"]["c"], "<string:optional>");
    }

    #[test]
    fn parse_fill_args_single_pair() {
        let fill = parse_fill_args("name=test");
        assert_eq!(fill.len(), 1);
        assert_eq!(fill.get("name").unwrap(), "test");
    }

    #[test]
    fn parse_fill_args_value_with_equals() {
        // split_once means only the first = matters
        let fill = parse_fill_args("query=a=b");
        assert_eq!(fill.get("query").unwrap(), "a=b");
    }

    #[test]
    fn parse_fill_args_no_equals_skipped() {
        let fill = parse_fill_args("noequals,key=val");
        assert_eq!(fill.len(), 1);
        assert_eq!(fill.get("key").unwrap(), "val");
    }

    #[test]
    fn parse_fill_args_three_pairs() {
        let fill = parse_fill_args("a=1,b=2,c=3");
        assert_eq!(fill.len(), 3);
        assert_eq!(fill.get("a").unwrap(), "1");
        assert_eq!(fill.get("b").unwrap(), "2");
        assert_eq!(fill.get("c").unwrap(), "3");
    }

    #[test]
    fn required_only_with_nested_array() {
        let schema = json!({
            "type": "object",
            "required": ["ids"],
            "properties": {
                "ids": {
                    "type": "array",
                    "items": { "type": "integer" }
                },
                "labels": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert!(result["ids"].is_array());
        assert!(result.get("labels").is_none());
    }

    #[test]
    fn multiple_properties_all_required() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b", "c"],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" },
                "c": { "type": "boolean" }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert_eq!(result["a"], "<string:required>");
        assert_eq!(result["b"], "<integer:required>");
        assert_eq!(result["c"], "<boolean:required>");
    }

    #[test]
    fn multiple_properties_none_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "x": { "type": "string" },
                "y": { "type": "integer" }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        // No required fields, all filtered
        assert_eq!(result, json!({}));
    }

    #[test]
    fn object_without_properties_returns_empty() {
        let schema = json!({
            "type": "object",
            "required": ["name"]
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, json!({}));
    }

    #[test]
    fn fill_json_array_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ids": { "type": "array" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("ids".to_string(), "[1,2,3]".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["ids"], json!([1, 2, 3]));
    }

    #[test]
    fn fill_json_object_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "meta": { "type": "object" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("meta".to_string(), r#"{"key":"val"}"#.to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["meta"], json!({"key": "val"}));
    }

    #[test]
    fn enum_empty_array_falls_through_to_type() {
        let schema = json!({
            "type": "object",
            "properties": {
                "field": {
                    "type": "string",
                    "enum": []
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["field"], "<string:optional>");
    }

    #[test]
    fn top_level_number_type() {
        let schema = json!({"type": "number"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, "<number:optional>");
    }

    #[test]
    fn top_level_null_type() {
        let schema = json!({"type": "null"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result.is_null());
    }

    #[test]
    fn top_level_array_of_objects() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "integer" }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result.is_array());
        assert_eq!(result[0]["id"], "<integer:required>");
    }

    // ── Extended template tests (target 90+) ─────────────────────

    #[test]
    fn top_level_custom_type_returns_placeholder() {
        let schema = json!({"type": "binary"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result, "<binary:optional>");
    }

    #[test]
    fn top_level_array_without_items_uses_string_default() {
        let schema = json!({"type": "array"});
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 1);
        assert_eq!(result[0], "<string:optional>");
    }

    #[test]
    fn required_custom_type_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["blob"],
            "properties": {
                "blob": { "type": "binary" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["blob"], "<binary:required>");
    }

    #[test]
    fn null_type_required_still_null() {
        let schema = json!({
            "type": "object",
            "required": ["nothing"],
            "properties": {
                "nothing": { "type": "null" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // null type always returns null regardless of required status
        assert!(result["nothing"].is_null());
    }

    #[test]
    fn enum_two_string_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "dir": {
                    "type": "string",
                    "enum": ["asc", "desc"]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["dir"], "asc|desc");
    }

    #[test]
    fn enum_three_values_shows_all() {
        let schema = json!({
            "type": "object",
            "properties": {
                "priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high"]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        let val = result["priority"].as_str().unwrap();
        assert_eq!(val, "low|medium|high");
    }

    #[test]
    fn enum_with_boolean_first_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "flag": {
                    "type": "boolean",
                    "enum": [true, false]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // true is not a string, so first.as_str() returns None, falls through to first.clone()
        assert_eq!(result["flag"], true);
    }

    #[test]
    fn enum_with_null_first_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "val": {
                    "enum": [null, "something"]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["val"].is_null());
    }

    #[test]
    fn default_value_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "region": { "type": "string", "default": "us-east-1" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["region"], "us-east-1");
    }

    #[test]
    fn default_value_boolean() {
        let schema = json!({
            "type": "object",
            "properties": {
                "debug": { "type": "boolean", "default": false }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["debug"], false);
    }

    #[test]
    fn default_value_null() {
        let schema = json!({
            "type": "object",
            "properties": {
                "opt": { "default": null }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["opt"].is_null());
    }

    #[test]
    fn default_value_array() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": { "type": "array", "default": ["a", "b"] }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["tags"], json!(["a", "b"]));
    }

    #[test]
    fn default_value_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "config": { "type": "object", "default": {"key": "val"} }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["config"], json!({"key": "val"}));
    }

    #[test]
    fn example_value_integer() {
        let schema = json!({
            "type": "object",
            "properties": {
                "retries": { "type": "integer", "example": 3 }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["retries"], 3);
    }

    #[test]
    fn example_value_boolean() {
        let schema = json!({
            "type": "object",
            "properties": {
                "enabled": { "type": "boolean", "example": true }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["enabled"], true);
    }

    #[test]
    fn example_takes_precedence_over_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "example": "https://api.example.com" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["url"], "https://api.example.com");
    }

    #[test]
    fn default_takes_precedence_over_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "sort": { "type": "string", "default": "name", "enum": ["date", "name", "size"] }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["sort"], "name");
    }

    #[test]
    fn fill_overrides_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "state": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("state".to_string(), "all".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["state"], "all");
    }

    #[test]
    fn fill_with_required_only_includes_required_with_fill() {
        let schema = json!({
            "type": "object",
            "required": ["owner"],
            "properties": {
                "owner": { "type": "string" },
                "title": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("owner".to_string(), "me".to_string());
        fill.insert("title".to_string(), "hello".to_string());
        let result = generate_template(&schema, true, &fill);
        assert_eq!(result["owner"], "me");
        // title is not required, so it's excluded even if fill is present
        assert!(result.get("title").is_none());
    }

    #[test]
    fn fill_float_value_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "price": { "type": "number" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("price".to_string(), "9.99".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["price"], 9.99);
    }

    #[test]
    fn fill_negative_number_parsed() {
        let schema = json!({
            "type": "object",
            "properties": {
                "offset": { "type": "integer" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("offset".to_string(), "-10".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["offset"], -10);
    }

    #[test]
    fn fill_empty_string_remains_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "note": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("note".to_string(), String::new());
        let result = generate_template(&schema, false, &fill);
        // empty string isn't valid JSON, so serde_json::from_str fails, kept as string
        assert_eq!(result["note"], "");
    }

    #[test]
    fn fill_deeply_nested_path() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {
                    "type": "object",
                    "properties": {
                        "b": {
                            "type": "object",
                            "properties": {
                                "c": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("a.b.c".to_string(), "deep-value".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["a"]["b"]["c"], "deep-value");
    }

    #[test]
    fn fill_flat_key_matches_nested_property() {
        // When path-based fill doesn't match, the flat key fallback is used
        let schema = json!({
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("name".to_string(), "flat-fill".to_string());
        let result = generate_template(&schema, false, &fill);
        // The flat key "name" matches the nested property's key
        assert_eq!(result["nested"]["name"], "flat-fill");
    }

    #[test]
    fn nested_array_of_arrays() {
        let schema = json!({
            "type": "object",
            "properties": {
                "matrix": {
                    "type": "array",
                    "items": {
                        "type": "array",
                        "items": { "type": "integer" }
                    }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result["matrix"].is_array());
        assert!(result["matrix"][0].is_array());
        assert_eq!(result["matrix"][0][0], "<integer:optional>");
    }

    #[test]
    fn array_items_with_default() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ports": {
                    "type": "array",
                    "items": { "type": "integer", "default": 8080 }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["ports"][0], 8080);
    }

    #[test]
    fn array_items_with_example() {
        let schema = json!({
            "type": "object",
            "properties": {
                "emails": {
                    "type": "array",
                    "items": { "type": "string", "example": "user@test.com" }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["emails"][0], "user@test.com");
    }

    #[test]
    fn array_items_with_enum() {
        let schema = json!({
            "type": "object",
            "properties": {
                "roles": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["admin", "user", "viewer"]
                    }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        let role = result["roles"][0].as_str().unwrap();
        assert!(role.contains("admin"));
        assert!(role.contains("user"));
    }

    #[test]
    fn top_level_array_required_only_propagates() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "integer" },
                    "label": { "type": "string" }
                }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert!(result.is_array());
        let item = &result[0];
        assert_eq!(item["id"], "<integer:required>");
        assert!(item.get("label").is_none());
    }

    #[test]
    fn property_without_type_defaults_to_string() {
        let schema = json!({
            "type": "object",
            "properties": {
                "unknown": {}
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["unknown"], "<string:optional>");
    }

    #[test]
    fn required_property_without_type_defaults_to_string() {
        let schema = json!({
            "type": "object",
            "required": ["unknown"],
            "properties": {
                "unknown": {}
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["unknown"], "<string:required>");
    }

    #[test]
    fn parse_fill_args_duplicate_key_last_wins() {
        let fill = parse_fill_args("key=first,key=second");
        assert_eq!(fill.len(), 1);
        assert_eq!(fill.get("key").unwrap(), "second");
    }

    #[test]
    fn parse_fill_args_empty_value() {
        let fill = parse_fill_args("key=");
        assert_eq!(fill.get("key").unwrap(), "");
    }

    #[test]
    fn parse_fill_args_empty_key() {
        let fill = parse_fill_args("=value");
        assert_eq!(fill.get("").unwrap(), "value");
    }

    #[test]
    fn parse_fill_args_value_with_comma_not_split() {
        // Commas are always delimiters, so values cannot contain commas
        let fill = parse_fill_args("q=a,b=2");
        assert_eq!(fill.get("q").unwrap(), "a");
        assert_eq!(fill.get("b").unwrap(), "2");
    }

    #[test]
    fn parse_fill_args_special_characters_in_value() {
        let fill = parse_fill_args("url=https://example.com/path?q=1&r=2");
        assert_eq!(
            fill.get("url").unwrap(),
            "https://example.com/path?q=1&r=2"
        );
    }

    #[test]
    fn parse_fill_args_unicode_values() {
        let fill = parse_fill_args("name=hello world");
        assert_eq!(fill.get("name").unwrap(), "hello world");
    }

    #[test]
    fn parse_fill_args_many_pairs() {
        let fill = parse_fill_args("a=1,b=2,c=3,d=4,e=5");
        assert_eq!(fill.len(), 5);
        for (key, val) in [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")] {
            assert_eq!(fill.get(key).unwrap(), val);
        }
    }

    #[test]
    fn required_only_empty_required_array() {
        let schema = json!({
            "type": "object",
            "required": [],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert_eq!(result, json!({}));
    }

    #[test]
    fn required_field_not_in_properties_ignored() {
        let schema = json!({
            "type": "object",
            "required": ["phantom"],
            "properties": {
                "real": { "type": "string" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // "phantom" is required but not in properties, so it doesn't appear
        assert!(result.get("phantom").is_none());
        assert_eq!(result["real"], "<string:optional>");
    }

    #[test]
    fn required_only_field_not_in_properties_ignored() {
        let schema = json!({
            "type": "object",
            "required": ["phantom"],
            "properties": {
                "real": { "type": "string" }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert!(result.get("phantom").is_none());
        // "real" is not required, filtered out
        assert!(result.get("real").is_none());
    }

    #[test]
    fn schema_with_non_array_required_field() {
        // If "required" is not an array, it should be treated as no required fields
        let schema = json!({
            "type": "object",
            "required": "name",
            "properties": {
                "name": { "type": "string" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // "required" is a string not an array, so as_array returns None
        assert_eq!(result["name"], "<string:optional>");
    }

    #[test]
    fn many_fill_values_applied() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "string" },
                "c": { "type": "string" },
                "d": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("a".to_string(), "alpha".to_string());
        fill.insert("b".to_string(), "beta".to_string());
        fill.insert("c".to_string(), "gamma".to_string());
        fill.insert("d".to_string(), "delta".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["a"], "alpha");
        assert_eq!(result["b"], "beta");
        assert_eq!(result["c"], "gamma");
        assert_eq!(result["d"], "delta");
    }

    #[test]
    fn fill_unused_key_ignored() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("name".to_string(), "test".to_string());
        fill.insert("nonexistent".to_string(), "ignored".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["name"], "test");
        assert!(result.get("nonexistent").is_none());
    }

    #[test]
    fn mixed_required_and_optional_with_defaults() {
        let schema = json!({
            "type": "object",
            "required": ["host"],
            "properties": {
                "host": { "type": "string" },
                "port": { "type": "integer", "default": 443 },
                "tls": { "type": "boolean", "default": true }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert_eq!(result["host"], "<string:required>");
        assert_eq!(result["port"], 443);
        assert_eq!(result["tls"], true);
    }

    #[test]
    fn mixed_required_only_with_defaults() {
        let schema = json!({
            "type": "object",
            "required": ["host"],
            "properties": {
                "host": { "type": "string" },
                "port": { "type": "integer", "default": 443 }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        assert_eq!(result["host"], "<string:required>");
        // port is optional, filtered even though it has a default
        assert!(result.get("port").is_none());
    }

    #[test]
    fn object_property_with_no_nested_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "extra": { "type": "object" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // object without properties returns empty object
        assert_eq!(result["extra"], json!({}));
    }

    #[test]
    fn top_level_array_with_boolean_items() {
        let schema = json!({
            "type": "array",
            "items": { "type": "boolean" }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        assert!(result.is_array());
        assert_eq!(result[0], "<boolean:optional>");
    }

    #[test]
    fn serialization_roundtrip() {
        let schema = json!({
            "type": "object",
            "required": ["name", "count"],
            "properties": {
                "name": { "type": "string" },
                "count": { "type": "integer" },
                "active": { "type": "boolean" }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn template_result_is_valid_json() {
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "integer" },
                "tags": { "type": "array", "items": { "type": "string" } },
                "meta": {
                    "type": "object",
                    "properties": {
                        "created": { "type": "string" }
                    }
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // Must serialize without error
        let json_str = serde_json::to_string_pretty(&result).unwrap();
        assert!(!json_str.is_empty());
        // Must parse back
        let _: Value = serde_json::from_str(&json_str).unwrap();
    }

    #[test]
    fn enum_with_mixed_string_and_null() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": {
                    "enum": ["active", null]
                }
            }
        });
        let result = generate_template(&schema, false, &BTreeMap::new());
        // first is "active" (a string), second is null (not a string, filtered from suffix)
        let val = result["status"].as_str().unwrap();
        assert!(val.starts_with("active"));
    }

    #[test]
    fn parse_fill_args_dotted_keys() {
        let fill = parse_fill_args("a.b.c=deep,x.y=shallow");
        assert_eq!(fill.get("a.b.c").unwrap(), "deep");
        assert_eq!(fill.get("x.y").unwrap(), "shallow");
    }

    #[test]
    fn fill_with_json_string_literal() {
        // A JSON string value like "\"quoted\"" should parse as a JSON string
        let schema = json!({
            "type": "object",
            "properties": {
                "msg": { "type": "string" }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("msg".to_string(), "\"hello\"".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["msg"], "hello");
    }

    #[test]
    fn nested_object_required_only_all_optional() {
        let schema = json!({
            "type": "object",
            "required": ["config"],
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "a": { "type": "string" },
                        "b": { "type": "string" }
                    }
                }
            }
        });
        let result = generate_template(&schema, true, &BTreeMap::new());
        // config is required so it's included, but has no required children
        assert!(result["config"].is_object());
        assert_eq!(result["config"], json!({}));
    }

    #[test]
    fn complex_schema_with_all_features() {
        let schema = json!({
            "type": "object",
            "required": ["name", "type", "tags"],
            "properties": {
                "name": { "type": "string" },
                "type": { "type": "string", "enum": ["a", "b", "c"] },
                "count": { "type": "integer", "default": 10 },
                "description": { "type": "string", "example": "A widget" },
                "tags": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "metadata": {
                    "type": "object",
                    "required": ["version"],
                    "properties": {
                        "version": { "type": "integer" },
                        "label": { "type": "string" }
                    }
                }
            }
        });
        let mut fill = BTreeMap::new();
        fill.insert("name".to_string(), "widget-1".to_string());
        let result = generate_template(&schema, false, &fill);
        assert_eq!(result["name"], "widget-1");
        assert_eq!(result["type"], "a|b|c");
        assert_eq!(result["count"], 10);
        assert_eq!(result["description"], "A widget");
        assert!(result["tags"].is_array());
        assert_eq!(result["metadata"]["version"], "<integer:required>");
        assert_eq!(result["metadata"]["label"], "<string:optional>");
    }

    #[test]
    fn parse_fill_args_only_commas_no_equals() {
        let fill = parse_fill_args("abc,def,ghi");
        assert!(fill.is_empty());
    }

    #[test]
    fn parse_fill_args_trailing_comma() {
        let fill = parse_fill_args("a=1,");
        // trailing comma creates empty string pair, no = means skipped
        assert_eq!(fill.len(), 1);
        assert_eq!(fill.get("a").unwrap(), "1");
    }

    #[test]
    fn parse_fill_args_leading_comma() {
        let fill = parse_fill_args(",a=1");
        assert_eq!(fill.len(), 1);
        assert_eq!(fill.get("a").unwrap(), "1");
    }
}
