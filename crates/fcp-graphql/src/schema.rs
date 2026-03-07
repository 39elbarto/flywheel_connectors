//! JSON Schema validation helpers.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use jsonschema::Validator;
use serde_json::Value;

use crate::error::GraphqlClientError;

#[derive(Debug, Default)]
pub struct SchemaCache {
    inner: Mutex<std::collections::HashMap<u64, Arc<Validator>>>,
}

impl SchemaCache {
    /// Fetch or compile a schema validator.
    pub fn get_or_compile(&self, schema: &str) -> Result<Arc<Validator>, GraphqlClientError> {
        let mut hasher = DefaultHasher::new();
        schema.hash(&mut hasher);
        let key = hasher.finish();

        let guard = self
            .inner
            .lock()
            .map_err(|_| GraphqlClientError::Protocol {
                message: "schema cache lock poisoned".to_string(),
            })?;
        if let Some(existing) = guard.get(&key) {
            return Ok(Arc::clone(existing));
        }
        drop(guard);

        let value: Value = serde_json::from_str(schema)?;
        let validator =
            Validator::new(&value).map_err(|err| GraphqlClientError::SchemaValidation {
                message: "invalid JSON Schema".to_string(),
                errors: vec![err.to_string()],
            })?;

        let validator = Arc::new(validator);
        self.inner
            .lock()
            .map_err(|_| GraphqlClientError::Protocol {
                message: "schema cache lock poisoned".to_string(),
            })?
            .insert(key, Arc::clone(&validator));

        Ok(validator)
    }

    /// Validate a JSON value against a schema.
    pub fn validate(&self, schema: &str, value: &Value) -> Result<(), GraphqlClientError> {
        let validator = self.get_or_compile(schema)?;
        let mut errors = Vec::new();
        for error in validator.iter_errors(value) {
            errors.push(error.to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(GraphqlClientError::SchemaValidation {
                message: "schema validation failed".to_string(),
                errors,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SIMPLE_SCHEMA: &str = r#"{
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        }
    }"#;

    // ---- get_or_compile ----

    #[test]
    fn compile_valid_schema() {
        let cache = SchemaCache::default();
        let result = cache.get_or_compile(SIMPLE_SCHEMA);
        assert!(result.is_ok());
    }

    #[test]
    fn compile_caches_validator() {
        let cache = SchemaCache::default();
        let v1 = cache.get_or_compile(SIMPLE_SCHEMA).unwrap();
        let v2 = cache.get_or_compile(SIMPLE_SCHEMA).unwrap();
        // Same Arc pointer (cached)
        assert!(Arc::ptr_eq(&v1, &v2));
    }

    #[test]
    fn compile_invalid_json_returns_json_error() {
        let cache = SchemaCache::default();
        let result = cache.get_or_compile("{not valid json");
        match result {
            Err(GraphqlClientError::Json(_)) => {}
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    // ---- validate ----

    #[test]
    fn validate_valid_value_passes() {
        let cache = SchemaCache::default();
        let value = json!({"name": "Alice", "age": 30});
        assert!(cache.validate(SIMPLE_SCHEMA, &value).is_ok());
    }

    #[test]
    fn validate_missing_required_field_fails() {
        let cache = SchemaCache::default();
        let value = json!({"age": 30});
        match cache.validate(SIMPLE_SCHEMA, &value) {
            Err(GraphqlClientError::SchemaValidation { errors, .. }) => {
                assert!(!errors.is_empty());
            }
            other => panic!("expected SchemaValidation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_wrong_type_fails() {
        let cache = SchemaCache::default();
        let value = json!({"name": 123});
        match cache.validate(SIMPLE_SCHEMA, &value) {
            Err(GraphqlClientError::SchemaValidation { errors, .. }) => {
                assert!(!errors.is_empty());
            }
            other => panic!("expected SchemaValidation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_collects_multiple_errors() {
        let schema = r#"{
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "integer"}
            }
        }"#;
        let cache = SchemaCache::default();
        // Missing both required fields
        let value = json!({});
        match cache.validate(schema, &value) {
            Err(GraphqlClientError::SchemaValidation { errors, .. }) => {
                assert!(
                    errors.len() >= 2,
                    "expected at least 2 errors, got {}",
                    errors.len()
                );
            }
            other => panic!("expected SchemaValidation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_different_schemas_cached_separately() {
        let cache = SchemaCache::default();
        let schema_a = r#"{"type": "string"}"#;
        let schema_b = r#"{"type": "integer"}"#;

        assert!(cache.validate(schema_a, &json!("hello")).is_ok());
        assert!(cache.validate(schema_b, &json!(42)).is_ok());
        assert!(cache.validate(schema_a, &json!(42)).is_err());
        assert!(cache.validate(schema_b, &json!("hello")).is_err());
    }

    #[test]
    fn validate_empty_object_against_no_required_passes() {
        let schema = r#"{"type": "object"}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({})).is_ok());
    }

    // ---- additional schema edge cases ----

    #[test]
    fn schema_cache_debug_contains_type_name() {
        let cache = SchemaCache::default();
        let dbg = format!("{cache:?}");
        assert!(dbg.contains("SchemaCache"));
    }

    #[test]
    fn validate_null_against_null_type() {
        let schema = r#"{"type": "null"}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(null)).is_ok());
    }

    #[test]
    fn validate_string_against_string_type() {
        let schema = r#"{"type": "string", "minLength": 1}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("hello")).is_ok());
        assert!(cache.validate(schema, &json!("")).is_err());
    }

    #[test]
    fn validate_array_against_array_schema() {
        let schema = r#"{"type": "array", "items": {"type": "integer"}, "minItems": 1}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!([1, 2, 3])).is_ok());
        assert!(cache.validate(schema, &json!([])).is_err());
        assert!(cache.validate(schema, &json!(["not int"])).is_err());
    }

    #[test]
    fn validate_number_against_number_schema() {
        let schema = r#"{"type": "number", "minimum": 0, "maximum": 100}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(50)).is_ok());
        assert!(cache.validate(schema, &json!(0)).is_ok());
        assert!(cache.validate(schema, &json!(100)).is_ok());
        assert!(cache.validate(schema, &json!(-1)).is_err());
        assert!(cache.validate(schema, &json!(101)).is_err());
    }

    #[test]
    fn validate_additional_properties_false_rejects_extra() {
        let schema = r#"{
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": false
        }"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({"name": "Alice"})).is_ok());
        assert!(
            cache
                .validate(schema, &json!({"name": "Alice", "extra": true}))
                .is_err()
        );
    }

    #[test]
    fn validate_any_of_schema() {
        let schema = r#"{"anyOf": [{"type": "string"}, {"type": "integer"}]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("hello")).is_ok());
        assert!(cache.validate(schema, &json!(42)).is_ok());
        assert!(cache.validate(schema, &json!(true)).is_err());
    }

    #[test]
    fn validate_boolean_schema_true_accepts_anything() {
        let schema = r"true";
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(null)).is_ok());
        assert!(cache.validate(schema, &json!("anything")).is_ok());
        assert!(cache.validate(schema, &json!(42)).is_ok());
    }

    #[test]
    fn validate_boolean_schema_false_rejects_everything() {
        let schema = r"false";
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(null)).is_err());
        assert!(cache.validate(schema, &json!("anything")).is_err());
    }

    #[test]
    fn compile_empty_object_schema() {
        let cache = SchemaCache::default();
        // Empty object is a valid schema that accepts anything
        let result = cache.get_or_compile(r"{}");
        assert!(result.is_ok());
        assert!(cache.validate(r"{}", &json!("anything")).is_ok());
    }

    #[test]
    fn validate_nested_object_schema() {
        let schema = r#"{
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "required": ["city"],
                    "properties": {
                        "city": {"type": "string"},
                        "zip": {"type": "string"}
                    }
                }
            },
            "required": ["address"]
        }"#;
        let cache = SchemaCache::default();
        assert!(
            cache
                .validate(schema, &json!({"address": {"city": "NYC"}}))
                .is_ok()
        );
        assert!(cache.validate(schema, &json!({"address": {}})).is_err());
        assert!(cache.validate(schema, &json!({})).is_err());
    }

    #[test]
    fn validate_schema_validation_error_contains_message() {
        let cache = SchemaCache::default();
        let result = cache.validate(SIMPLE_SCHEMA, &json!({}));
        match result {
            Err(GraphqlClientError::SchemaValidation { message, errors }) => {
                assert_eq!(message, "schema validation failed");
                assert!(!errors.is_empty());
            }
            other => panic!("expected SchemaValidation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_pattern_property() {
        let schema = r#"{"type": "string", "pattern": "^[a-z]+$"}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("hello")).is_ok());
        assert!(cache.validate(schema, &json!("Hello123")).is_err());
    }
}
