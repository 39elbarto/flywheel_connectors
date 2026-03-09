//! Deep schema navigator for JSON Schema exploration.
//!
//! Walks JSON Schemas and produces flat, annotated field listings with
//! required/optional markers, types, constraints, and example values.

use serde::Serialize;
use serde_json::Value;

// ── Schema field annotation ─────────────────────────────────────────────

/// A flattened schema field with annotations.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaField {
    /// Dot-separated path (e.g. `"labels"`, `"spec.containers[].image"`).
    pub path: String,
    /// JSON Schema type (e.g. `"string"`, `"integer"`, `"[string]"`, `"object"`).
    pub field_type: String,
    /// Whether this field is required.
    pub required: bool,
    /// Description from the schema.
    pub description: Option<String>,
    /// Example value (if provided in schema or extracted from examples).
    pub example: Option<Value>,
    /// Enum constraints (if any).
    pub enum_values: Option<Vec<Value>>,
    /// Minimum value constraint.
    pub minimum: Option<Value>,
    /// Maximum value constraint.
    pub maximum: Option<Value>,
    /// Default value.
    pub default: Option<Value>,
    /// Nesting depth (0 = top-level).
    pub depth: usize,
}

/// Walk a JSON Schema and produce a flat list of annotated fields.
pub fn walk_schema(schema: &Value, examples: &[String]) -> Vec<SchemaField> {
    let mut fields = Vec::new();
    let required_set = extract_required(schema);
    let example_values = extract_example_values(examples);

    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (name, prop_schema) in props {
            walk_property(
                name,
                prop_schema,
                required_set.contains(&name.as_str()),
                &example_values,
                &mut fields,
                0,
            );
        }
    }

    // Sort: required first, then alphabetical.
    fields.sort_by(|a, b| {
        b.required
            .cmp(&a.required)
            .then_with(|| a.path.cmp(&b.path))
    });

    fields
}

/// Generate a scaffold JSON template with placeholders for required fields.
pub fn scaffold_template(schema: &Value) -> Value {
    let required_set = extract_required(schema);
    let mut template = serde_json::Map::new();

    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (name, prop_schema) in props {
            if required_set.contains(&name.as_str()) {
                template.insert(name.clone(), scaffold_value(prop_schema));
            }
        }
    }

    Value::Object(template)
}

/// Filter fields to show only those matching a specific path prefix.
pub fn filter_by_field(fields: &[SchemaField], field_name: &str) -> Vec<SchemaField> {
    let prefix = format!("{field_name}.");
    fields
        .iter()
        .filter(|f| f.path == field_name || f.path.starts_with(&prefix))
        .cloned()
        .collect()
}

// ── Internal helpers ────────────────────────────────────────────────────

fn extract_required(schema: &Value) -> Vec<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .collect()
        })
        .unwrap_or_default()
}

fn walk_property(
    path: &str,
    schema: &Value,
    required: bool,
    examples: &Value,
    fields: &mut Vec<SchemaField>,
    depth: usize,
) {
    let field_type = infer_type(schema);
    let description = schema
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let example = examples.get(path).cloned().or_else(|| {
        schema.get("example").cloned().or_else(|| {
            schema.get("examples").and_then(|e| e.as_array().and_then(|a| a.first().cloned()))
        })
    });
    let enum_values = schema
        .get("enum")
        .and_then(Value::as_array)
        .cloned();
    let minimum = schema.get("minimum").cloned();
    let maximum = schema.get("maximum").cloned();
    let default = schema.get("default").cloned();

    fields.push(SchemaField {
        path: path.to_owned(),
        field_type,
        required,
        description,
        example,
        enum_values,
        minimum,
        maximum,
        default,
        depth,
    });

    // Recurse into nested object properties.
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        let nested_required = extract_required(schema);
        for (name, prop_schema) in props {
            let nested_path = format!("{path}.{name}");
            walk_property(
                &nested_path,
                prop_schema,
                nested_required.contains(&name.as_str()),
                examples,
                fields,
                depth + 1,
            );
        }
    }

    // Recurse into array items.
    if let Some(items) = schema.get("items") {
        if items.get("properties").is_some() {
            let item_path = format!("{path}[]");
            let nested_required = extract_required(items);
            if let Some(props) = items.get("properties").and_then(Value::as_object) {
                for (name, prop_schema) in props {
                    let nested_path = format!("{item_path}.{name}");
                    walk_property(
                        &nested_path,
                        prop_schema,
                        nested_required.contains(&name.as_str()),
                        examples,
                        fields,
                        depth + 1,
                    );
                }
            }
        }
    }
}

fn infer_type(schema: &Value) -> String {
    if let Some(type_str) = schema.get("type").and_then(Value::as_str) {
        if type_str == "array" {
            if let Some(items) = schema.get("items") {
                let item_type = items
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("any");
                return format!("[{item_type}]");
            }
            return "[any]".to_owned();
        }
        return type_str.to_owned();
    }
    if schema.get("oneOf").is_some() || schema.get("anyOf").is_some() {
        return "union".to_owned();
    }
    "any".to_owned()
}

fn scaffold_value(schema: &Value) -> Value {
    let type_str = schema.get("type").and_then(Value::as_str).unwrap_or("any");
    match type_str {
        "string" => {
            if let Some(enum_vals) = schema.get("enum").and_then(Value::as_array) {
                return enum_vals
                    .first()
                    .cloned()
                    .unwrap_or(Value::String("<string>".to_owned()));
            }
            Value::String("<string>".to_owned())
        }
        "integer" | "number" => Value::Number(serde_json::Number::from(0)),
        "boolean" => Value::Bool(false),
        "array" => Value::Array(vec![]),
        "object" => {
            let mut obj = serde_json::Map::new();
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                let required_set = extract_required(schema);
                for (name, prop_schema) in props {
                    if required_set.contains(&name.as_str()) {
                        obj.insert(name.clone(), scaffold_value(prop_schema));
                    }
                }
            }
            Value::Object(obj)
        }
        _ => Value::Null,
    }
}

fn extract_example_values(examples: &[String]) -> Value {
    let mut map = serde_json::Map::new();
    for example in examples {
        if let Ok(parsed) = serde_json::from_str::<Value>(example) {
            if let Some(obj) = parsed.as_object() {
                for (key, value) in obj {
                    map.insert(key.clone(), value.clone());
                }
            }
        }
    }
    Value::Object(map)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn simple_schema() -> Value {
        json!({
            "type": "object",
            "required": ["owner", "repo", "title"],
            "properties": {
                "owner": { "type": "string", "description": "Repository owner" },
                "repo": { "type": "string", "description": "Repository name" },
                "title": { "type": "string", "description": "Issue title" },
                "body": { "type": "string", "description": "Issue body in markdown" },
                "assignees": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "GitHub usernames to assign"
                },
                "labels": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Label names"
                },
                "milestone": { "type": "integer", "description": "Milestone number" }
            }
        })
    }

    // ── walk_schema tests ───────────────────────────────────────────

    #[test]
    fn walk_schema_extracts_all_fields() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        assert_eq!(fields.len(), 7);
    }

    #[test]
    fn walk_schema_marks_required_fields() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let required: Vec<&str> = fields
            .iter()
            .filter(|f| f.required)
            .map(|f| f.path.as_str())
            .collect();
        assert!(required.contains(&"owner"));
        assert!(required.contains(&"repo"));
        assert!(required.contains(&"title"));
        assert_eq!(required.len(), 3);
    }

    #[test]
    fn walk_schema_marks_optional_fields() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let optional: Vec<&str> = fields
            .iter()
            .filter(|f| !f.required)
            .map(|f| f.path.as_str())
            .collect();
        assert!(optional.contains(&"body"));
        assert!(optional.contains(&"assignees"));
        assert!(optional.contains(&"labels"));
        assert!(optional.contains(&"milestone"));
    }

    #[test]
    fn walk_schema_infers_types() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let owner = fields.iter().find(|f| f.path == "owner").unwrap();
        assert_eq!(owner.field_type, "string");
        let labels = fields.iter().find(|f| f.path == "labels").unwrap();
        assert_eq!(labels.field_type, "[string]");
        let milestone = fields.iter().find(|f| f.path == "milestone").unwrap();
        assert_eq!(milestone.field_type, "integer");
    }

    #[test]
    fn walk_schema_extracts_descriptions() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let owner = fields.iter().find(|f| f.path == "owner").unwrap();
        assert_eq!(owner.description.as_deref(), Some("Repository owner"));
    }

    #[test]
    fn walk_schema_required_first_sort() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let first_optional = fields.iter().position(|f| !f.required).unwrap();
        let last_required = fields
            .iter()
            .rposition(|f| f.required)
            .unwrap_or(0);
        assert!(last_required < first_optional);
    }

    #[test]
    fn walk_schema_with_examples() {
        let schema = simple_schema();
        let examples =
            vec![r#"{"owner": "octocat", "repo": "hello-world", "title": "Bug report"}"#.to_owned()];
        let fields = walk_schema(&schema, &examples);
        let owner = fields.iter().find(|f| f.path == "owner").unwrap();
        assert_eq!(owner.example, Some(json!("octocat")));
    }

    #[test]
    fn walk_schema_empty_properties() {
        let schema = json!({"type": "object"});
        let fields = walk_schema(&schema, &[]);
        assert!(fields.is_empty());
    }

    #[test]
    fn walk_schema_no_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "foo": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        assert_eq!(fields.len(), 1);
        assert!(!fields[0].required);
    }

    // ── Nested schema tests ─────────────────────────────────────────

    #[test]
    fn walk_schema_nested_object() {
        let schema = json!({
            "type": "object",
            "required": ["namespace", "spec"],
            "properties": {
                "namespace": { "type": "string" },
                "spec": {
                    "type": "object",
                    "required": ["replicas"],
                    "properties": {
                        "replicas": { "type": "integer" },
                        "selector": { "type": "object" }
                    }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        assert!(fields.iter().any(|f| f.path == "spec.replicas" && f.required));
        assert!(fields.iter().any(|f| f.path == "spec.selector" && !f.required));
    }

    #[test]
    fn walk_schema_array_with_object_items() {
        let schema = json!({
            "type": "object",
            "properties": {
                "containers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "image"],
                        "properties": {
                            "name": { "type": "string" },
                            "image": { "type": "string" },
                            "ports": { "type": "array", "items": { "type": "integer" } }
                        }
                    }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        assert!(fields.iter().any(|f| f.path == "containers[].name" && f.required));
        assert!(fields.iter().any(|f| f.path == "containers[].image" && f.required));
        assert!(fields.iter().any(|f| f.path == "containers[].ports" && !f.required));
    }

    #[test]
    fn walk_schema_depth_tracking() {
        let schema = json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "nested": { "type": "string" }
                    }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let spec = fields.iter().find(|f| f.path == "spec").unwrap();
        assert_eq!(spec.depth, 0);
        let nested = fields.iter().find(|f| f.path == "spec.nested").unwrap();
        assert_eq!(nested.depth, 1);
    }

    // ── Enum / constraint tests ─────────────────────────────────────

    #[test]
    fn walk_schema_enum_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["open", "closed", "all"]
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let status = fields.iter().find(|f| f.path == "status").unwrap();
        assert_eq!(
            status.enum_values,
            Some(vec![json!("open"), json!("closed"), json!("all")])
        );
    }

    #[test]
    fn walk_schema_min_max() {
        let schema = json!({
            "type": "object",
            "properties": {
                "page_size": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let ps = fields.iter().find(|f| f.path == "page_size").unwrap();
        assert_eq!(ps.minimum, Some(json!(1)));
        assert_eq!(ps.maximum, Some(json!(100)));
    }

    #[test]
    fn walk_schema_default_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "default": 20
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let limit = fields.iter().find(|f| f.path == "limit").unwrap();
        assert_eq!(limit.default, Some(json!(20)));
    }

    // ── scaffold_template tests ─────────────────────────────────────

    #[test]
    fn scaffold_template_required_only() {
        let schema = simple_schema();
        let template = scaffold_template(&schema);
        assert!(template.get("owner").is_some());
        assert!(template.get("repo").is_some());
        assert!(template.get("title").is_some());
        assert!(template.get("body").is_none());
        assert!(template.get("labels").is_none());
    }

    #[test]
    fn scaffold_template_string_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["name"], "<string>");
    }

    #[test]
    fn scaffold_template_integer_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["count"],
            "properties": {
                "count": { "type": "integer" }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["count"], 0);
    }

    #[test]
    fn scaffold_template_boolean_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["active"],
            "properties": {
                "active": { "type": "boolean" }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["active"], false);
    }

    #[test]
    fn scaffold_template_enum_uses_first_value() {
        let schema = json!({
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["status"], "open");
    }

    #[test]
    fn scaffold_template_nested_object() {
        let schema = json!({
            "type": "object",
            "required": ["spec"],
            "properties": {
                "spec": {
                    "type": "object",
                    "required": ["replicas"],
                    "properties": {
                        "replicas": { "type": "integer" },
                        "selector": { "type": "object" }
                    }
                }
            }
        });
        let template = scaffold_template(&schema);
        assert!(template.get("spec").is_some());
        assert_eq!(template["spec"]["replicas"], 0);
        assert!(template["spec"].get("selector").is_none());
    }

    #[test]
    fn scaffold_template_empty_schema() {
        let schema = json!({"type": "object"});
        let template = scaffold_template(&schema);
        assert_eq!(template, json!({}));
    }

    // ── filter_by_field tests ───────────────────────────────────────

    #[test]
    fn filter_by_field_exact_match() {
        let schema = json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "replicas": { "type": "integer" },
                        "selector": { "type": "object" }
                    }
                },
                "name": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let filtered = filter_by_field(&fields, "spec");
        assert!(filtered.iter().any(|f| f.path == "spec"));
        assert!(filtered.iter().any(|f| f.path == "spec.replicas"));
        assert!(!filtered.iter().any(|f| f.path == "name"));
    }

    #[test]
    fn filter_by_field_no_match() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let filtered = filter_by_field(&fields, "nonexistent");
        assert!(filtered.is_empty());
    }

    // ── Type inference tests ────────────────────────────────────────

    #[test]
    fn infer_type_string() {
        assert_eq!(infer_type(&json!({"type": "string"})), "string");
    }

    #[test]
    fn infer_type_integer() {
        assert_eq!(infer_type(&json!({"type": "integer"})), "integer");
    }

    #[test]
    fn infer_type_boolean() {
        assert_eq!(infer_type(&json!({"type": "boolean"})), "boolean");
    }

    #[test]
    fn infer_type_array_of_strings() {
        assert_eq!(
            infer_type(&json!({"type": "array", "items": {"type": "string"}})),
            "[string]"
        );
    }

    #[test]
    fn infer_type_array_without_items() {
        assert_eq!(infer_type(&json!({"type": "array"})), "[any]");
    }

    #[test]
    fn infer_type_object() {
        assert_eq!(infer_type(&json!({"type": "object"})), "object");
    }

    #[test]
    fn infer_type_union() {
        assert_eq!(infer_type(&json!({"oneOf": []})), "union");
    }

    #[test]
    fn infer_type_any_of() {
        assert_eq!(infer_type(&json!({"anyOf": []})), "union");
    }

    #[test]
    fn infer_type_unknown() {
        assert_eq!(infer_type(&json!({})), "any");
    }

    // ── Example extraction tests ────────────────────────────────────

    #[test]
    fn extract_example_values_from_json() {
        let examples = vec![r#"{"owner": "octocat", "repo": "hello-world"}"#.to_owned()];
        let values = extract_example_values(&examples);
        assert_eq!(values["owner"], "octocat");
        assert_eq!(values["repo"], "hello-world");
    }

    #[test]
    fn extract_example_values_invalid_json_skipped() {
        let examples = vec!["not json".to_owned()];
        let values = extract_example_values(&examples);
        assert!(values.as_object().unwrap().is_empty());
    }

    #[test]
    fn extract_example_values_multiple_examples_merged() {
        let examples = vec![
            r#"{"owner": "octocat"}"#.to_owned(),
            r#"{"repo": "hello-world"}"#.to_owned(),
        ];
        let values = extract_example_values(&examples);
        assert_eq!(values["owner"], "octocat");
        assert_eq!(values["repo"], "hello-world");
    }

    #[test]
    fn extract_example_values_empty() {
        let values = extract_example_values(&[]);
        assert!(values.as_object().unwrap().is_empty());
    }

    // ── Schema example in schema ────────────────────────────────────

    #[test]
    fn walk_schema_example_from_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "example": "my-app"
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let name = fields.iter().find(|f| f.path == "name").unwrap();
        assert_eq!(name.example, Some(json!("my-app")));
    }

    #[test]
    fn walk_schema_examples_array_from_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "examples": ["active", "inactive"]
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let status = fields.iter().find(|f| f.path == "status").unwrap();
        assert_eq!(status.example, Some(json!("active")));
    }

    // ── Serialization tests ─────────────────────────────────────────

    #[test]
    fn schema_field_serializes_to_json() {
        let field = SchemaField {
            path: "name".to_owned(),
            field_type: "string".to_owned(),
            required: true,
            description: Some("The name".to_owned()),
            example: Some(json!("example-name")),
            enum_values: None,
            minimum: None,
            maximum: None,
            default: None,
            depth: 0,
        };
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["path"], "name");
        assert_eq!(json["field_type"], "string");
        assert_eq!(json["required"], true);
    }

    #[test]
    fn scaffold_template_array_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["tags"],
            "properties": {
                "tags": { "type": "array", "items": { "type": "string" } }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["tags"], json!([]));
    }
}
