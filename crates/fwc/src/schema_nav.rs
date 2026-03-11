//! Deep schema navigator for JSON Schema exploration.
//!
//! Walks JSON Schemas and produces flat, annotated field listings with
//! required/optional markers, types, constraints, and example values.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Map, Value};

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
    /// Variant summaries for `oneOf` / `anyOf` composed fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variants: Option<Vec<String>>,
    /// Additional constraints and conditional availability notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Vec<String>>,
    /// Nesting depth (0 = top-level).
    pub depth: usize,
}

/// Walk a JSON Schema and produce a flat list of annotated fields.
pub fn walk_schema(schema: &Value, examples: &[String]) -> Vec<SchemaField> {
    let normalized = normalize_schema(schema);
    let mut fields = Vec::new();
    let example_values = extract_example_values(examples);

    for property in collect_child_properties(&normalized) {
        walk_property(
            &property.name,
            &property.schema,
            property.required,
            &property.notes.into_iter().collect::<Vec<_>>(),
            &example_values,
            &mut fields,
            0,
        );
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
    let normalized = normalize_schema(schema);
    if normalized.get("properties").is_some() {
        return scaffold_object(&normalized);
    }
    scaffold_value(&normalized)
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

/// Filter fields to show only required fields.
pub fn required_only_fields(fields: &[SchemaField]) -> Vec<SchemaField> {
    fields.iter().filter(|f| f.required).cloned().collect()
}

/// Produce a summary of schema fields as a JSON value suitable for display.
///
/// Each field is rendered as an object with path, type, required, description,
/// and any constraints. This is the structured backing for `fwc schema`.
pub fn schema_summary(fields: &[SchemaField]) -> Value {
    let items: Vec<Value> = fields
        .iter()
        .map(|f| {
            let mut obj = serde_json::json!({
                "path": f.path,
                "type": f.field_type,
                "required": f.required,
            });
            if let Some(desc) = &f.description {
                obj["description"] = Value::String(desc.clone());
            }
            if let Some(ex) = &f.example {
                obj["example"] = ex.clone();
            }
            if let Some(enums) = &f.enum_values {
                obj["enum"] = Value::Array(enums.clone());
            }
            if let Some(min) = &f.minimum {
                obj["minimum"] = min.clone();
            }
            if let Some(max) = &f.maximum {
                obj["maximum"] = max.clone();
            }
            if let Some(def) = &f.default {
                obj["default"] = def.clone();
            }
            if let Some(variants) = &f.variants {
                obj["variants"] = serde_json::json!(variants);
            }
            if let Some(constraints) = &f.constraints {
                obj["constraints"] = serde_json::json!(constraints);
            }
            obj
        })
        .collect();
    Value::Array(items)
}

/// Fill known values into a scaffolded template.
///
/// Takes a scaffold template (from `scaffold_template`) and a map of
/// path → value bindings, and replaces placeholder values with the provided
/// values. Paths use dot notation for nested fields.
pub fn fill_template(template: &Value, bindings: &Map<String, Value>) -> Value {
    match template {
        Value::Object(obj) => {
            let mut result = Map::new();
            for (key, val) in obj {
                if let Some(bound) = bindings.get(key) {
                    result.insert(key.clone(), bound.clone());
                } else {
                    result.insert(key.clone(), fill_template(val, bindings));
                }
            }
            Value::Object(result)
        }
        other => other.clone(),
    }
}

// ── Pre-invoke input validation ─────────────────────────────────────────

/// A single validation error with structured context for agent consumption.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    /// Dot-separated path to the problematic field.
    pub path: String,
    /// What was expected (type, constraint, etc.).
    pub expected: String,
    /// What was actually provided (summary).
    pub actual: String,
    /// Human-readable fix suggestion.
    pub fix: String,
}

/// Validate an input payload against a JSON Schema.
///
/// Returns a list of validation errors. An empty list means the input is valid.
/// This is a structural pre-check, not a full JSON Schema validator — it catches
/// the most common agent mistakes: missing required fields, wrong types, and
/// enum constraint violations.
pub fn validate_input(schema: &Value, input: &Value) -> Vec<ValidationError> {
    let normalized = normalize_schema(schema);
    let mut errors = Vec::new();
    validate_object(&normalized, input, "", &mut errors);
    errors
}

fn validate_object(
    schema: &Value,
    input: &Value,
    prefix: &str,
    errors: &mut Vec<ValidationError>,
) {
    // Check required fields
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let input_obj = input.as_object();

    for req in &required {
        let path = if prefix.is_empty() {
            (*req).to_owned()
        } else {
            format!("{prefix}.{req}")
        };

        let present = input_obj.is_some_and(|obj| {
            obj.get(*req)
                .is_some_and(|v| !v.is_null())
        });

        if !present {
            errors.push(ValidationError {
                path: path.clone(),
                expected: "required field".to_owned(),
                actual: "missing".to_owned(),
                fix: format!("Add the required field '{path}' to your input"),
            });
        }
    }

    // Check property types
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        if let Some(obj) = input_obj {
            for (key, val) in obj {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };

                if let Some(prop_schema) = properties.get(key) {
                    let prop_normalized = normalize_schema(prop_schema);
                    validate_type(&prop_normalized, val, &path, errors);

                    // Recurse into nested objects
                    if val.is_object() && prop_normalized.get("properties").is_some() {
                        validate_object(&prop_normalized, val, &path, errors);
                    }
                }
            }
        }
    }
}

fn validate_type(
    schema: &Value,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    // Check enum constraints
    if let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
        if !enum_values.contains(value) {
            let allowed: Vec<String> = enum_values.iter().map(|v| v.to_string()).collect();
            errors.push(ValidationError {
                path: path.to_owned(),
                expected: format!("one of: {}", allowed.join(", ")),
                actual: value.to_string(),
                fix: format!(
                    "Change '{path}' to one of the allowed values: {}",
                    allowed.join(", ")
                ),
            });
        }
        return;
    }

    // Check type constraint
    let expected_type = schema.get("type").and_then(Value::as_str);
    if let Some(expected) = expected_type {
        let type_matches = match expected {
            "string" => value.is_string(),
            "number" | "integer" => value.is_number(),
            "boolean" => value.is_boolean(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            "null" => value.is_null(),
            _ => true,
        };

        if !type_matches {
            let actual_type = match value {
                Value::Null => "null",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            errors.push(ValidationError {
                path: path.to_owned(),
                expected: format!("type '{expected}'"),
                actual: format!("type '{actual_type}'"),
                fix: format!("Change '{path}' to a value of type '{expected}'"),
            });
        }
    }

    // Check minimum/maximum for numbers
    if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
        if let Some(val) = value.as_f64() {
            if val < min {
                errors.push(ValidationError {
                    path: path.to_owned(),
                    expected: format!("value >= {min}"),
                    actual: format!("{val}"),
                    fix: format!("Change '{path}' to a value >= {min}"),
                });
            }
        }
    }
    if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
        if let Some(val) = value.as_f64() {
            if val > max {
                errors.push(ValidationError {
                    path: path.to_owned(),
                    expected: format!("value <= {max}"),
                    actual: format!("{val}"),
                    fix: format!("Change '{path}' to a value <= {max}"),
                });
            }
        }
    }
}

// ── Internal helpers ────────────────────────────────────────────────────

fn extract_required(schema: &Value) -> Vec<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn walk_property(
    path: &str,
    schema: &Value,
    required: bool,
    inherited_constraints: &[String],
    examples: &Value,
    fields: &mut Vec<SchemaField>,
    depth: usize,
) {
    let normalized = normalize_schema(schema);
    let field_type = infer_type(&normalized);
    let description = normalized
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let example = examples.get(path).cloned().or_else(|| {
        normalized.get("example").cloned().or_else(|| {
            normalized
                .get("examples")
                .and_then(|e| e.as_array().and_then(|a| a.first().cloned()))
        })
    });
    let enum_values = normalized.get("enum").and_then(Value::as_array).cloned();
    let minimum = normalized.get("minimum").cloned();
    let maximum = normalized.get("maximum").cloned();
    let default = normalized.get("default").cloned();
    let variants = summarize_variants(&normalized);
    let constraints = merged_constraints(inherited_constraints, constraint_notes(&normalized));

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
        variants,
        constraints,
        depth,
    });

    for property in collect_child_properties(&normalized) {
        let nested_path = format!("{path}.{}", property.name);
        let nested_constraints = property.notes.into_iter().collect::<Vec<_>>();
        walk_property(
            &nested_path,
            &property.schema,
            property.required,
            &nested_constraints,
            examples,
            fields,
            depth + 1,
        );
    }

    if let Some(items) = normalized.get("items") {
        let item_path = format!("{path}[]");
        for property in collect_child_properties(items) {
            let nested_path = format!("{item_path}.{}", property.name);
            let nested_constraints = property.notes.into_iter().collect::<Vec<_>>();
            walk_property(
                &nested_path,
                &property.schema,
                property.required,
                &nested_constraints,
                examples,
                fields,
                depth + 1,
            );
        }
    }
}

fn infer_type(schema: &Value) -> String {
    let normalized = normalize_schema(schema);
    if let Some(type_values) = normalized.get("type").and_then(Value::as_array) {
        let variants = type_values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !variants.is_empty() {
            return variants.join(" | ");
        }
    }
    if let Some(type_str) = normalized.get("type").and_then(Value::as_str) {
        if type_str == "array" {
            if let Some(items) = normalized.get("items") {
                return format!("[{}]", describe_schema_inline(items));
            }
            return "[any]".to_owned();
        }
        return type_str.to_owned();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(variants) = normalized.get(key).and_then(Value::as_array) {
            if variants.is_empty() {
                return format!("{key}<any>");
            }
            let summaries = variants
                .iter()
                .map(describe_schema_inline)
                .collect::<Vec<_>>()
                .join(", ");
            return format!("{key}<{summaries}>");
        }
    }
    if normalized.get("properties").is_some() {
        return "object".to_owned();
    }
    "any".to_owned()
}

fn scaffold_value(schema: &Value) -> Value {
    let normalized = normalize_schema(schema);
    if let Some(default) = normalized.get("default") {
        return default.clone();
    }
    if let Some(example) = normalized.get("example") {
        return example.clone();
    }
    if let Some(first_example) = normalized
        .get("examples")
        .and_then(Value::as_array)
        .and_then(|examples| examples.first())
    {
        return first_example.clone();
    }
    if let Some(constraint) = normalized.get("const") {
        return constraint.clone();
    }
    if let Some(variant) = select_preferred_variant(&normalized) {
        return scaffold_value(variant);
    }
    let type_str = normalized
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if normalized.get("properties").is_some() {
                "object"
            } else {
                "any"
            }
        });
    match type_str {
        "string" => {
            if let Some(enum_vals) = normalized.get("enum").and_then(Value::as_array) {
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
        "object" => scaffold_object(&normalized),
        _ => Value::Null,
    }
}

fn scaffold_object(schema: &Value) -> Value {
    let mut template = Map::new();
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        let required_set = extract_required(schema);
        for (name, prop_schema) in props {
            if required_set.contains(&name.as_str()) {
                template.insert(name.clone(), scaffold_value(prop_schema));
            }
        }
    }
    Value::Object(template)
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

#[derive(Debug)]
struct ChildProperty {
    name: String,
    schema: Value,
    required: bool,
    notes: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct ChildPropertyAccumulator {
    schema: Option<Value>,
    required: bool,
    notes: BTreeSet<String>,
}

fn collect_child_properties(schema: &Value) -> Vec<ChildProperty> {
    let mut collected = BTreeMap::<String, ChildPropertyAccumulator>::new();

    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        let required_set = extract_required(schema);
        for (name, prop_schema) in props {
            let entry = collected.entry(name.clone()).or_default();
            merge_into_schema(&mut entry.schema, prop_schema.clone());
            entry.required = entry.required || required_set.contains(&name.as_str());
        }
    }

    for key in ["oneOf", "anyOf"] {
        let Some(variants) = schema.get(key).and_then(Value::as_array) else {
            continue;
        };
        let discriminator = schema
            .get("discriminator")
            .and_then(|value| value.get("propertyName"))
            .and_then(Value::as_str);
        let mut stats = BTreeMap::<String, (BTreeSet<String>, BTreeSet<String>)>::new();

        for (index, variant) in variants.iter().enumerate() {
            let label = variant_condition_label(variant, index, discriminator);
            let required_set = extract_required(variant);
            let Some(props) = variant.get("properties").and_then(Value::as_object) else {
                continue;
            };
            for (name, prop_schema) in props {
                let entry = collected.entry(name.clone()).or_default();
                merge_into_schema(&mut entry.schema, prop_schema.clone());
                let stat_entry = stats
                    .entry(name.clone())
                    .or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
                stat_entry.0.insert(label.clone());
                if required_set.contains(&name.as_str()) {
                    stat_entry.1.insert(label.clone());
                }
            }
        }

        for (name, (present_labels, required_labels)) in stats {
            let Some(entry) = collected.get_mut(&name) else {
                continue;
            };
            if present_labels.len() == variants.len() {
                if required_labels.len() == variants.len() {
                    entry.required = true;
                } else if !required_labels.is_empty() {
                    entry
                        .notes
                        .insert(format!("required when {}", join_labels(&required_labels)));
                }
            } else {
                entry
                    .notes
                    .insert(format!("available when {}", join_labels(&present_labels)));
                if !required_labels.is_empty() {
                    entry
                        .notes
                        .insert(format!("required when {}", join_labels(&required_labels)));
                }
            }
        }
    }

    collected
        .into_iter()
        .filter_map(|(name, accumulator)| {
            accumulator.schema.map(|schema| ChildProperty {
                name,
                schema,
                required: accumulator.required,
                notes: accumulator.notes,
            })
        })
        .collect()
}

fn merged_constraints(
    inherited_constraints: &[String],
    own_constraints: Vec<String>,
) -> Option<Vec<String>> {
    let mut merged = BTreeSet::new();
    merged.extend(inherited_constraints.iter().cloned());
    merged.extend(own_constraints);
    if merged.is_empty() {
        None
    } else {
        Some(merged.into_iter().collect())
    }
}

fn summarize_variants(schema: &Value) -> Option<Vec<String>> {
    for key in ["oneOf", "anyOf"] {
        let Some(variants) = schema.get(key).and_then(Value::as_array) else {
            continue;
        };
        let discriminator = schema
            .get("discriminator")
            .and_then(|value| value.get("propertyName"))
            .and_then(Value::as_str);
        let summaries = variants
            .iter()
            .enumerate()
            .map(|(index, variant)| {
                let label = variant_condition_label(variant, index, discriminator);
                let shape = describe_schema_inline(variant);
                format!("{label}: {shape}")
            })
            .collect::<Vec<_>>();
        return Some(summaries);
    }
    None
}

fn constraint_notes(schema: &Value) -> Vec<String> {
    let mut notes = BTreeSet::new();
    if let Some(discriminator) = schema
        .get("discriminator")
        .and_then(|value| value.get("propertyName"))
        .and_then(Value::as_str)
    {
        notes.insert(format!("discriminator: {discriminator}"));
    }
    if let Some(not_schema) = schema.get("not") {
        notes.insert(format!("not {}", describe_schema_inline(not_schema)));
    }
    notes.into_iter().collect()
}

fn describe_schema_inline(schema: &Value) -> String {
    let normalized = normalize_schema(schema);
    if let Some(constraint) = normalized.get("const") {
        return format!("const {}", short_value(constraint));
    }
    if let Some(enum_values) = normalized.get("enum").and_then(Value::as_array) {
        if !enum_values.is_empty() {
            return format!("enum {{{}}}", summarize_enum_values(enum_values));
        }
    }
    if let Some(type_values) = normalized.get("type").and_then(Value::as_array) {
        let variants = type_values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !variants.is_empty() {
            return variants.join(" | ");
        }
    }
    if let Some(type_str) = normalized.get("type").and_then(Value::as_str) {
        return match type_str {
            "array" => normalized
                .get("items")
                .map(|items| format!("[{}]", describe_schema_inline(items)))
                .unwrap_or_else(|| "[any]".to_owned()),
            "object" => describe_object_shape(&normalized),
            _ => type_str.to_owned(),
        };
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(variants) = normalized.get(key).and_then(Value::as_array) {
            if variants.is_empty() {
                return format!("{key}<any>");
            }
            return format!(
                "{key}<{}>",
                variants
                    .iter()
                    .map(describe_schema_inline)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if normalized.get("properties").is_some() {
        return describe_object_shape(&normalized);
    }
    "any".to_owned()
}

fn describe_object_shape(schema: &Value) -> String {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return "object".to_owned();
    };
    if props.is_empty() {
        return "object".to_owned();
    }

    let mut names = props.keys().cloned().collect::<Vec<_>>();
    names.sort();
    let mut parts = Vec::new();
    for (index, name) in names.iter().enumerate() {
        if index == 3 {
            parts.push("...".to_owned());
            break;
        }
        if let Some(prop_schema) = props.get(name) {
            parts.push(format!("{name}: {}", summarize_object_member(prop_schema)));
        }
    }
    format!("object {{{}}}", parts.join(", "))
}

fn summarize_object_member(schema: &Value) -> String {
    let normalized = normalize_schema(schema);
    if let Some(constraint) = normalized.get("const") {
        return format!("const {}", short_value(constraint));
    }
    if let Some(enum_values) = normalized.get("enum").and_then(Value::as_array) {
        if !enum_values.is_empty() {
            return format!("enum {{{}}}", summarize_enum_values(enum_values));
        }
    }
    if let Some(type_str) = normalized.get("type").and_then(Value::as_str) {
        return match type_str {
            "array" => normalized
                .get("items")
                .map(|items| format!("[{}]", summarize_object_member(items)))
                .unwrap_or_else(|| "[any]".to_owned()),
            "object" => "object".to_owned(),
            _ => type_str.to_owned(),
        };
    }
    for key in ["oneOf", "anyOf"] {
        if normalized.get(key).is_some() {
            return key.to_owned();
        }
    }
    if normalized.get("properties").is_some() {
        return "object".to_owned();
    }
    "any".to_owned()
}

fn variant_condition_label(variant: &Value, index: usize, discriminator: Option<&str>) -> String {
    if let Some(property_name) = discriminator {
        if let Some(value) = discriminator_value(variant, property_name) {
            return format!("{property_name}={}", short_value(value));
        }
    }
    if let Some(title) = variant.get("title").and_then(Value::as_str) {
        return title.to_owned();
    }
    if let Some(description) = variant
        .get("description")
        .and_then(Value::as_str)
        .filter(|description| description.len() <= 48)
    {
        return description.to_owned();
    }
    format!("variant-{}", index + 1)
}

fn discriminator_value<'a>(variant: &'a Value, property_name: &str) -> Option<&'a Value> {
    let property = variant
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property_name))?;
    property.get("const").or_else(|| {
        property
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
    })
}

fn join_labels(labels: &BTreeSet<String>) -> String {
    labels.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn short_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn summarize_enum_values(values: &[Value]) -> String {
    let mut parts = values.iter().take(3).map(short_value).collect::<Vec<_>>();
    if values.len() > 3 {
        parts.push("...".to_owned());
    }
    parts.join(", ")
}

fn select_preferred_variant(schema: &Value) -> Option<&Value> {
    ["oneOf", "anyOf"]
        .into_iter()
        .find_map(|key| schema.get(key).and_then(Value::as_array))
        .and_then(|variants| variants.first())
}

fn normalize_schema(schema: &Value) -> Value {
    let mut normalized = if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        let mut base = schema.clone();
        if let Some(map) = base.as_object_mut() {
            map.remove("allOf");
        }
        all_of.iter().fold(base, |acc, variant| {
            merge_schema_values(&acc, &normalize_schema(variant))
        })
    } else {
        schema.clone()
    };
    normalize_nested_schema(&mut normalized);
    normalized
}

fn normalize_nested_schema(schema: &mut Value) {
    let Some(map) = schema.as_object_mut() else {
        return;
    };

    if let Some(props) = map.get_mut("properties").and_then(Value::as_object_mut) {
        for property in props.values_mut() {
            *property = normalize_schema(property);
        }
    }
    if let Some(items) = map.get_mut("items") {
        *items = normalize_schema(items);
    }
    if let Some(not_schema) = map.get_mut("not") {
        *not_schema = normalize_schema(not_schema);
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(variants) = map.get_mut(key).and_then(Value::as_array_mut) {
            for variant in variants {
                *variant = normalize_schema(variant);
            }
        }
    }
}

fn merge_schema_values(base: &Value, overlay: &Value) -> Value {
    let (Some(base_map), Some(overlay_map)) = (base.as_object(), overlay.as_object()) else {
        return if base.is_null() {
            overlay.clone()
        } else {
            base.clone()
        };
    };

    let mut merged = base_map.clone();
    for (key, overlay_value) in overlay_map {
        match key.as_str() {
            "allOf" => {}
            "properties" => {
                let combined = match (
                    merged.get("properties").and_then(Value::as_object),
                    overlay_value.as_object(),
                ) {
                    (Some(existing), Some(additional)) => {
                        let mut props = existing.clone();
                        for (name, prop_schema) in additional {
                            let merged_prop = props
                                .get(name)
                                .map(|existing_prop| {
                                    merge_schema_values(existing_prop, prop_schema)
                                })
                                .unwrap_or_else(|| prop_schema.clone());
                            props.insert(name.clone(), merged_prop);
                        }
                        Value::Object(props)
                    }
                    (None, Some(additional)) => Value::Object(additional.clone()),
                    _ => overlay_value.clone(),
                };
                merged.insert(key.clone(), combined);
            }
            "required" => {
                let mut required = BTreeSet::new();
                if let Some(existing) = merged.get("required").and_then(Value::as_array) {
                    required.extend(existing.iter().filter_map(Value::as_str).map(str::to_owned));
                }
                if let Some(additional) = overlay_value.as_array() {
                    required.extend(
                        additional
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned),
                    );
                }
                merged.insert(
                    key.clone(),
                    Value::Array(required.into_iter().map(Value::String).collect()),
                );
            }
            "items" => {
                let combined = merged
                    .get("items")
                    .map(|existing| merge_schema_values(existing, overlay_value))
                    .unwrap_or_else(|| overlay_value.clone());
                merged.insert(key.clone(), combined);
            }
            _ => {
                merged
                    .entry(key.clone())
                    .or_insert_with(|| overlay_value.clone());
            }
        }
    }

    Value::Object(merged)
}

fn merge_into_schema(target: &mut Option<Value>, addition: Value) {
    match target.take() {
        Some(existing) => *target = Some(merge_schema_values(&existing, &addition)),
        None => *target = Some(addition),
    }
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
        let last_required = fields.iter().rposition(|f| f.required).unwrap_or(0);
        assert!(last_required < first_optional);
    }

    #[test]
    fn walk_schema_with_examples() {
        let schema = simple_schema();
        let examples = vec![
            r#"{"owner": "octocat", "repo": "hello-world", "title": "Bug report"}"#.to_owned(),
        ];
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
        assert!(fields
            .iter()
            .any(|f| f.path == "spec.replicas" && f.required));
        assert!(fields
            .iter()
            .any(|f| f.path == "spec.selector" && !f.required));
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
        assert!(fields
            .iter()
            .any(|f| f.path == "containers[].name" && f.required));
        assert!(fields
            .iter()
            .any(|f| f.path == "containers[].image" && f.required));
        assert!(fields
            .iter()
            .any(|f| f.path == "containers[].ports" && !f.required));
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

    #[test]
    fn walk_schema_all_of_merges_properties_and_required_fields() {
        let schema = json!({
            "allOf": [
                {
                    "type": "object",
                    "required": ["owner"],
                    "properties": {
                        "owner": { "type": "string" }
                    }
                },
                {
                    "type": "object",
                    "required": ["repo"],
                    "properties": {
                        "repo": { "type": "string" }
                    }
                }
            ]
        });
        let fields = walk_schema(&schema, &[]);
        assert!(fields.iter().any(|f| f.path == "owner" && f.required));
        assert!(fields.iter().any(|f| f.path == "repo" && f.required));
    }

    #[test]
    fn walk_schema_discriminated_union_exposes_variants_and_conditional_children() {
        let schema = json!({
            "type": "object",
            "properties": {
                "assignee": {
                    "oneOf": [
                        {
                            "type": "string",
                            "description": "username"
                        },
                        {
                            "type": "object",
                            "required": ["kind", "id"],
                            "properties": {
                                "kind": { "const": "user" },
                                "id": { "type": "integer" },
                                "name": { "type": "string" }
                            }
                        }
                    ],
                    "discriminator": { "propertyName": "kind" }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let assignee = fields.iter().find(|f| f.path == "assignee").unwrap();
        assert!(assignee.field_type.starts_with("oneOf<"));
        assert!(assignee
            .variants
            .as_ref()
            .unwrap()
            .iter()
            .any(|variant| variant
                == "kind=user: object {id: integer, kind: const user, name: string}"));
        assert!(assignee
            .constraints
            .as_ref()
            .unwrap()
            .contains(&"discriminator: kind".to_owned()));

        let assignee_id = fields.iter().find(|f| f.path == "assignee.id").unwrap();
        assert!(!assignee_id.required);
        let child_constraints = assignee_id.constraints.as_ref().unwrap();
        assert!(child_constraints
            .iter()
            .any(|constraint| constraint == "available when kind=user"));
        assert!(child_constraints
            .iter()
            .any(|constraint| constraint == "required when kind=user"));
    }

    #[test]
    fn walk_schema_root_union_collects_variant_properties() {
        let schema = json!({
            "oneOf": [
                {
                    "type": "object",
                    "required": ["owner"],
                    "properties": {
                        "owner": { "type": "string" }
                    }
                },
                {
                    "type": "object",
                    "required": ["repo"],
                    "properties": {
                        "repo": { "type": "string" }
                    }
                }
            ]
        });
        let fields = walk_schema(&schema, &[]);
        assert!(fields.iter().any(|f| f.path == "owner"));
        assert!(fields.iter().any(|f| f.path == "repo"));
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

    #[test]
    fn walk_schema_surfaces_not_as_constraint() {
        let schema = json!({
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "not": { "enum": ["legacy"] }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let mode = fields.iter().find(|f| f.path == "mode").unwrap();
        assert!(mode
            .constraints
            .as_ref()
            .unwrap()
            .contains(&"not enum {legacy}".to_owned()));
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
    fn scaffold_template_merges_all_of_required_fields() {
        let schema = json!({
            "allOf": [
                {
                    "type": "object",
                    "required": ["owner"],
                    "properties": {
                        "owner": { "type": "string" }
                    }
                },
                {
                    "type": "object",
                    "required": ["repo"],
                    "properties": {
                        "repo": { "type": "string" }
                    }
                }
            ]
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["owner"], "<string>");
        assert_eq!(template["repo"], "<string>");
    }

    #[test]
    fn scaffold_template_uses_first_union_variant_and_const_discriminator() {
        let schema = json!({
            "oneOf": [
                {
                    "type": "object",
                    "required": ["kind", "id"],
                    "properties": {
                        "kind": { "const": "user" },
                        "id": { "type": "integer" }
                    }
                },
                {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            ]
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["kind"], "user");
        assert_eq!(template["id"], 0);
        assert!(template.get("name").is_none());
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
        assert_eq!(infer_type(&json!({"oneOf": []})), "oneOf<any>");
    }

    #[test]
    fn infer_type_any_of() {
        assert_eq!(infer_type(&json!({"anyOf": []})), "anyOf<any>");
    }

    #[test]
    fn infer_type_all_of_merged_object() {
        assert_eq!(
            infer_type(&json!({
                "allOf": [
                    { "type": "object", "properties": { "owner": { "type": "string" } } },
                    { "type": "object", "properties": { "repo": { "type": "string" } } }
                ]
            })),
            "object"
        );
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
            variants: None,
            constraints: None,
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

    // ── Additional walk_schema tests ───────────────────────────────

    #[test]
    fn walk_schema_number_type() {
        let schema = json!({
            "type": "object",
            "properties": {
                "price": { "type": "number" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let price = fields.iter().find(|f| f.path == "price").unwrap();
        assert_eq!(price.field_type, "number");
    }

    #[test]
    fn walk_schema_boolean_type() {
        let schema = json!({
            "type": "object",
            "properties": {
                "enabled": { "type": "boolean", "description": "Feature flag" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let f = fields.iter().find(|f| f.path == "enabled").unwrap();
        assert_eq!(f.field_type, "boolean");
        assert_eq!(f.description.as_deref(), Some("Feature flag"));
    }

    #[test]
    fn walk_schema_array_of_integers() {
        let schema = json!({
            "type": "object",
            "properties": {
                "ports": { "type": "array", "items": { "type": "integer" } }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let ports = fields.iter().find(|f| f.path == "ports").unwrap();
        assert_eq!(ports.field_type, "[integer]");
    }

    #[test]
    fn walk_schema_array_of_objects_without_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": { "type": "array", "items": { "type": "object" } }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let items = fields.iter().find(|f| f.path == "items").unwrap();
        assert_eq!(items.field_type, "[object]");
        // No child fields since items has no properties
        assert!(!fields.iter().any(|f| f.path.starts_with("items[]")));
    }

    #[test]
    fn walk_schema_deeply_nested() {
        let schema = json!({
            "type": "object",
            "properties": {
                "level1": {
                    "type": "object",
                    "properties": {
                        "level2": {
                            "type": "object",
                            "properties": {
                                "level3": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let l3 = fields
            .iter()
            .find(|f| f.path == "level1.level2.level3")
            .unwrap();
        assert_eq!(l3.depth, 2);
        assert_eq!(l3.field_type, "string");
    }

    #[test]
    fn walk_schema_multiple_required_and_optional() {
        let schema = json!({
            "type": "object",
            "required": ["a", "c"],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "string" },
                "c": { "type": "string" },
                "d": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        assert_eq!(fields.len(), 4);
        let required: Vec<&str> = fields
            .iter()
            .filter(|f| f.required)
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(required.len(), 2);
        assert!(required.contains(&"a"));
        assert!(required.contains(&"c"));
    }

    #[test]
    fn walk_schema_alphabetical_within_required_group() {
        let schema = json!({
            "type": "object",
            "required": ["zulu", "alpha"],
            "properties": {
                "zulu": { "type": "string" },
                "alpha": { "type": "string" },
                "mike": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        // Required fields come first, sorted alphabetically among themselves
        assert!(fields[0].required);
        assert!(fields[1].required);
        assert!(!fields[2].required);
        assert!(fields[0].path < fields[1].path);
    }

    #[test]
    fn walk_schema_no_description() {
        let schema = json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let id = fields.iter().find(|f| f.path == "id").unwrap();
        assert!(id.description.is_none());
    }

    #[test]
    fn walk_schema_all_constraint_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1000,
                    "default": 10,
                    "description": "Item count"
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let count = fields.iter().find(|f| f.path == "count").unwrap();
        assert_eq!(count.minimum, Some(json!(0)));
        assert_eq!(count.maximum, Some(json!(1000)));
        assert_eq!(count.default, Some(json!(10)));
    }

    #[test]
    fn walk_schema_external_example_overrides_schema_example() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "example": "default-name" }
            }
        });
        let examples = vec![r#"{"name": "external-name"}"#.to_owned()];
        let fields = walk_schema(&schema, &examples);
        let name = fields.iter().find(|f| f.path == "name").unwrap();
        // External examples take priority over schema examples
        assert_eq!(name.example, Some(json!("external-name")));
    }

    #[test]
    fn walk_schema_empty_examples_array() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "examples": [] }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let status = fields.iter().find(|f| f.path == "status").unwrap();
        assert!(status.example.is_none());
    }

    // ── Additional infer_type tests ────────────────────────────────

    #[test]
    fn infer_type_number() {
        assert_eq!(infer_type(&json!({"type": "number"})), "number");
    }

    #[test]
    fn infer_type_array_of_objects() {
        assert_eq!(
            infer_type(&json!({"type": "array", "items": {"type": "object"}})),
            "[object]"
        );
    }

    #[test]
    fn infer_type_array_of_boolean() {
        assert_eq!(
            infer_type(&json!({"type": "array", "items": {"type": "boolean"}})),
            "[boolean]"
        );
    }

    #[test]
    fn infer_type_array_items_no_type() {
        assert_eq!(infer_type(&json!({"type": "array", "items": {}})), "[any]");
    }

    // ── Additional scaffold_template tests ─────────────────────────

    #[test]
    fn scaffold_template_number_placeholder() {
        let schema = json!({
            "type": "object",
            "required": ["amount"],
            "properties": {
                "amount": { "type": "number" }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["amount"], 0);
    }

    #[test]
    fn scaffold_template_null_for_unknown_type() {
        let schema = json!({
            "type": "object",
            "required": ["data"],
            "properties": {
                "data": { "type": "custom" }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["data"], json!(null));
    }

    #[test]
    fn scaffold_template_no_type_field() {
        let schema = json!({
            "type": "object",
            "required": ["value"],
            "properties": {
                "value": {}
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["value"], json!(null));
    }

    #[test]
    fn scaffold_template_deeply_nested_required() {
        let schema = json!({
            "type": "object",
            "required": ["outer"],
            "properties": {
                "outer": {
                    "type": "object",
                    "required": ["inner"],
                    "properties": {
                        "inner": { "type": "string" },
                        "optional_field": { "type": "integer" }
                    }
                }
            }
        });
        let template = scaffold_template(&schema);
        assert!(template.get("outer").is_some());
        assert_eq!(template["outer"]["inner"], "<string>");
        assert!(template["outer"].get("optional_field").is_none());
    }

    #[test]
    fn scaffold_template_enum_with_integers() {
        let schema = json!({
            "type": "object",
            "required": ["priority"],
            "properties": {
                "priority": { "type": "string", "enum": ["high", "medium", "low"] }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["priority"], "high");
    }

    #[test]
    fn scaffold_template_empty_enum_fallback() {
        let schema = json!({
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": { "type": "string", "enum": [] }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["status"], "<string>");
    }

    // ── Additional filter_by_field tests ───────────────────────────

    #[test]
    fn filter_by_field_leaf_node() {
        let schema = simple_schema();
        let fields = walk_schema(&schema, &[]);
        let filtered = filter_by_field(&fields, "owner");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "owner");
    }

    #[test]
    fn filter_by_field_nested_children() {
        let schema = json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "timeout": { "type": "integer" },
                        "retries": { "type": "integer" }
                    }
                },
                "name": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let filtered = filter_by_field(&fields, "config");
        assert_eq!(filtered.len(), 3); // config + config.timeout + config.retries
        assert!(filtered
            .iter()
            .all(|f| f.path == "config" || f.path.starts_with("config.")));
    }

    #[test]
    fn filter_by_field_does_not_match_partial_prefix() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "namespace": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let filtered = filter_by_field(&fields, "name");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "name");
    }

    // ── Additional extract_example_values tests ────────────────────

    #[test]
    fn extract_example_values_non_object_skipped() {
        let examples = vec!["42".to_owned(), "[1,2,3]".to_owned()];
        let values = extract_example_values(&examples);
        assert!(values.as_object().unwrap().is_empty());
    }

    #[test]
    fn extract_example_values_later_overwrites_earlier() {
        let examples = vec![
            r#"{"key": "first"}"#.to_owned(),
            r#"{"key": "second"}"#.to_owned(),
        ];
        let values = extract_example_values(&examples);
        assert_eq!(values["key"], "second");
    }

    // ── SchemaField serialization tests ────────────────────────────

    #[test]
    fn schema_field_serializes_enum_values() {
        let field = SchemaField {
            path: "status".to_owned(),
            field_type: "string".to_owned(),
            required: false,
            description: None,
            example: None,
            enum_values: Some(vec![json!("a"), json!("b")]),
            minimum: None,
            maximum: None,
            default: Some(json!("a")),
            variants: Some(vec!["choice-a: string".to_owned()]),
            constraints: Some(vec!["discriminator: mode".to_owned()]),
            depth: 0,
        };
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["enum_values"], json!(["a", "b"]));
        assert_eq!(json["default"], "a");
        assert_eq!(json["variants"], json!(["choice-a: string"]));
        assert_eq!(json["constraints"], json!(["discriminator: mode"]));
    }

    #[test]
    fn schema_field_serializes_constraints() {
        let field = SchemaField {
            path: "count".to_owned(),
            field_type: "integer".to_owned(),
            required: true,
            description: Some("Item count".to_owned()),
            example: Some(json!(42)),
            enum_values: None,
            minimum: Some(json!(1)),
            maximum: Some(json!(100)),
            default: None,
            variants: None,
            constraints: Some(vec!["not enum {legacy}".to_owned()]),
            depth: 1,
        };
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["minimum"], 1);
        assert_eq!(json["maximum"], 100);
        assert_eq!(json["depth"], 1);
        assert_eq!(json["example"], 42);
        assert_eq!(json["constraints"], json!(["not enum {legacy}"]));
    }

    #[test]
    fn schema_field_clone() {
        let field = SchemaField {
            path: "test".to_owned(),
            field_type: "string".to_owned(),
            required: true,
            description: Some("desc".to_owned()),
            example: None,
            enum_values: None,
            minimum: None,
            maximum: None,
            default: None,
            variants: None,
            constraints: None,
            depth: 0,
        };
        let cloned = field.clone();
        assert_eq!(field.path, cloned.path);
        assert_eq!(field.required, cloned.required);
    }

    // ── Array items recursion tests ────────────────────────────────

    #[test]
    fn walk_schema_array_items_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "users": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["email"],
                        "properties": {
                            "email": { "type": "string" },
                            "name": { "type": "string" }
                        }
                    }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let email = fields.iter().find(|f| f.path == "users[].email").unwrap();
        assert!(email.required);
        let name = fields.iter().find(|f| f.path == "users[].name").unwrap();
        assert!(!name.required);
    }

    #[test]
    fn walk_schema_array_items_depth() {
        let schema = json!({
            "type": "object",
            "properties": {
                "records": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" }
                        }
                    }
                }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let id = fields.iter().find(|f| f.path == "records[].id").unwrap();
        assert_eq!(id.depth, 1);
    }

    // ── Additional edge case tests ─────────────────────────────────

    #[test]
    fn walk_schema_single_field() {
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        assert_eq!(fields.len(), 1);
        assert!(fields[0].required);
        assert_eq!(fields[0].depth, 0);
    }

    #[test]
    fn walk_schema_null_type_field() {
        let schema = json!({
            "type": "object",
            "properties": {
                "data": { "type": "null" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let data = fields.iter().find(|f| f.path == "data").unwrap();
        assert_eq!(data.field_type, "null");
    }

    #[test]
    fn scaffold_template_multiple_required_string_fields() {
        let schema = json!({
            "type": "object",
            "required": ["first_name", "last_name", "email"],
            "properties": {
                "first_name": { "type": "string" },
                "last_name": { "type": "string" },
                "email": { "type": "string" },
                "age": { "type": "integer" }
            }
        });
        let template = scaffold_template(&schema);
        assert_eq!(template["first_name"], "<string>");
        assert_eq!(template["last_name"], "<string>");
        assert_eq!(template["email"], "<string>");
        assert!(template.get("age").is_none());
    }

    #[test]
    fn filter_by_field_empty_fields_list() {
        let filtered = filter_by_field(&[], "anything");
        assert!(filtered.is_empty());
    }

    // ── required_only_fields tests ──────────────────────────────────────

    #[test]
    fn required_only_filters_to_required() {
        let schema = json!({
            "type": "object",
            "required": ["name", "email"],
            "properties": {
                "name": { "type": "string" },
                "email": { "type": "string" },
                "age": { "type": "integer" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let required = required_only_fields(&fields);
        assert!(required.iter().all(|f| f.required));
        assert!(required.iter().any(|f| f.path == "name"));
        assert!(required.iter().any(|f| f.path == "email"));
        assert!(!required.iter().any(|f| f.path == "age"));
    }

    #[test]
    fn required_only_empty_when_no_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "x": { "type": "string" },
                "y": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let required = required_only_fields(&fields);
        assert!(required.is_empty());
    }

    #[test]
    fn required_only_all_when_all_required() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let required = required_only_fields(&fields);
        assert_eq!(required.len(), 2);
    }

    #[test]
    fn required_only_empty_input() {
        assert!(required_only_fields(&[]).is_empty());
    }

    // ── schema_summary tests ────────────────────────────────────────────

    #[test]
    fn schema_summary_produces_array() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "description": "User name" },
                "age": { "type": "integer" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let summary = schema_summary(&fields);
        assert!(summary.is_array());
        let arr = summary.as_array().unwrap();
        assert_eq!(arr.len(), fields.len());
    }

    #[test]
    fn schema_summary_includes_required_flag() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "opt": { "type": "string" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let summary = schema_summary(&fields);
        let arr = summary.as_array().unwrap();
        let name_entry = arr.iter().find(|e| e["path"] == "name").unwrap();
        assert_eq!(name_entry["required"], true);
        let opt_entry = arr.iter().find(|e| e["path"] == "opt").unwrap();
        assert_eq!(opt_entry["required"], false);
    }

    #[test]
    fn schema_summary_includes_description() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Full name" }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let summary = schema_summary(&fields);
        let arr = summary.as_array().unwrap();
        assert_eq!(arr[0]["description"], "Full name");
    }

    #[test]
    fn schema_summary_includes_enum_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let fields = walk_schema(&schema, &[]);
        let summary = schema_summary(&fields);
        let arr = summary.as_array().unwrap();
        assert!(arr[0]["enum"].is_array());
    }

    #[test]
    fn schema_summary_empty_fields() {
        let summary = schema_summary(&[]);
        assert!(summary.is_array());
        assert!(summary.as_array().unwrap().is_empty());
    }

    // ── fill_template tests ─────────────────────────────────────────────

    #[test]
    fn fill_template_replaces_known_values() {
        let schema = json!({
            "type": "object",
            "required": ["owner", "repo", "title"],
            "properties": {
                "owner": { "type": "string" },
                "repo": { "type": "string" },
                "title": { "type": "string" }
            }
        });
        let template = scaffold_template(&schema);
        let mut bindings = Map::new();
        bindings.insert("owner".into(), json!("octocat"));
        bindings.insert("repo".into(), json!("hello-world"));
        let filled = fill_template(&template, &bindings);
        assert_eq!(filled["owner"], "octocat");
        assert_eq!(filled["repo"], "hello-world");
        // title should retain its placeholder
        assert_eq!(filled["title"], "<string>");
    }

    #[test]
    fn fill_template_preserves_unfilled_placeholders() {
        let template = json!({
            "name": "<string>",
            "count": "<integer>"
        });
        let filled = fill_template(&template, &Map::new());
        assert_eq!(filled["name"], "<string>");
        assert_eq!(filled["count"], "<integer>");
    }

    #[test]
    fn fill_template_works_on_empty_template() {
        let template = json!({});
        let filled = fill_template(&template, &Map::new());
        assert!(filled.as_object().unwrap().is_empty());
    }

    #[test]
    fn fill_template_handles_non_object() {
        let template = json!("hello");
        let filled = fill_template(&template, &Map::new());
        assert_eq!(filled, "hello");
    }

    // ── validate_input tests ────────────────────────────────────────────

    #[test]
    fn validate_input_valid_payload_returns_empty() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "age": { "type": "integer" }
            }
        });
        let input = json!({ "name": "Alice", "age": 30 });
        let errors = validate_input(&schema, &input);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_input_missing_required_field() {
        let schema = json!({
            "type": "object",
            "required": ["name", "email"],
            "properties": {
                "name": { "type": "string" },
                "email": { "type": "string" }
            }
        });
        let input = json!({ "name": "Alice" });
        let errors = validate_input(&schema, &input);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "email");
        assert_eq!(errors[0].actual, "missing");
        assert!(errors[0].fix.contains("email"));
    }

    #[test]
    fn validate_input_wrong_type() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            }
        });
        let input = json!({ "count": "not-a-number" });
        let errors = validate_input(&schema, &input);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "count");
        assert!(errors[0].expected.contains("integer"));
        assert!(errors[0].actual.contains("string"));
    }

    #[test]
    fn validate_input_enum_violation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let input = json!({ "status": "invalid" });
        let errors = validate_input(&schema, &input);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].expected.contains("open"));
        assert!(errors[0].expected.contains("closed"));
    }

    #[test]
    fn validate_input_minimum_violation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "age": { "type": "integer", "minimum": 0 }
            }
        });
        let input = json!({ "age": -5 });
        let errors = validate_input(&schema, &input);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].expected.contains(">= 0"));
    }

    #[test]
    fn validate_input_maximum_violation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "score": { "type": "number", "maximum": 100.0 }
            }
        });
        let input = json!({ "score": 150.0 });
        let errors = validate_input(&schema, &input);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].expected.contains("<= 100"));
    }

    #[test]
    fn validate_input_multiple_errors() {
        let schema = json!({
            "type": "object",
            "required": ["name", "email"],
            "properties": {
                "name": { "type": "string" },
                "email": { "type": "string" },
                "age": { "type": "integer" }
            }
        });
        let input = json!({ "age": "not-a-number" });
        let errors = validate_input(&schema, &input);
        // Missing name, missing email, wrong type for age
        assert_eq!(errors.len(), 3);
    }

    #[test]
    fn validate_input_null_required_field() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        });
        let input = json!({ "name": null });
        let errors = validate_input(&schema, &input);
        // Missing required (null treated as absent) + wrong type
        assert!(errors.len() >= 1);
        assert!(errors.iter().any(|e| e.path == "name"));
    }

    #[test]
    fn validate_input_nested_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "required": ["city"],
                    "properties": {
                        "city": { "type": "string" },
                        "zip": { "type": "string" }
                    }
                }
            }
        });
        let input = json!({ "address": { "zip": "12345" } });
        let errors = validate_input(&schema, &input);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "address.city");
    }

    #[test]
    fn validate_input_empty_object_against_schema_with_no_required() {
        let schema = json!({
            "type": "object",
            "properties": {
                "opt1": { "type": "string" },
                "opt2": { "type": "integer" }
            }
        });
        let input = json!({});
        let errors = validate_input(&schema, &input);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_input_correct_enum_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["open", "closed"] }
            }
        });
        let input = json!({ "status": "open" });
        let errors = validate_input(&schema, &input);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_input_all_errors_have_fix() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": { "type": "string" },
                "b": { "type": "integer" },
                "c": { "type": "string", "enum": ["x", "y"] }
            }
        });
        let input = json!({ "b": "wrong", "c": "z" });
        let errors = validate_input(&schema, &input);
        for err in &errors {
            assert!(!err.fix.is_empty(), "Error at '{}' has no fix", err.path);
        }
    }

    #[test]
    fn validation_error_debug_and_clone() {
        let err = ValidationError {
            path: "name".to_owned(),
            expected: "required".to_owned(),
            actual: "missing".to_owned(),
            fix: "Add name".to_owned(),
        };
        let cloned = err.clone();
        assert_eq!(cloned.path, err.path);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ValidationError"));
    }
}
