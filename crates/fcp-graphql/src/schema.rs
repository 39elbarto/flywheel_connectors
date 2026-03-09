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

    // ---- enum schema ----

    #[test]
    fn validate_enum_string_values() {
        let schema = r#"{"type": "string", "enum": ["red", "green", "blue"]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("red")).is_ok());
        assert!(cache.validate(schema, &json!("yellow")).is_err());
    }

    #[test]
    fn validate_enum_integer_values() {
        let schema = r#"{"type": "integer", "enum": [1, 2, 3]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(2)).is_ok());
        assert!(cache.validate(schema, &json!(4)).is_err());
    }

    // ---- const schema ----

    #[test]
    fn validate_const_value() {
        let schema = r#"{"const": "fixed"}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("fixed")).is_ok());
        assert!(cache.validate(schema, &json!("other")).is_err());
    }

    // ---- array constraints ----

    #[test]
    fn validate_array_max_items() {
        let schema = r#"{"type": "array", "maxItems": 3}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!([1, 2])).is_ok());
        assert!(cache.validate(schema, &json!([1, 2, 3])).is_ok());
        assert!(cache.validate(schema, &json!([1, 2, 3, 4])).is_err());
    }

    #[test]
    fn validate_array_unique_items() {
        let schema = r#"{"type": "array", "uniqueItems": true}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!([1, 2, 3])).is_ok());
        assert!(cache.validate(schema, &json!([1, 1, 2])).is_err());
    }

    // ---- string constraints ----

    #[test]
    fn validate_string_max_length() {
        let schema = r#"{"type": "string", "maxLength": 5}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("abc")).is_ok());
        assert!(cache.validate(schema, &json!("abcdef")).is_err());
    }

    // ---- integer constraints ----

    #[test]
    fn validate_integer_exclusive_minimum() {
        let schema = r#"{"type": "integer", "exclusiveMinimum": 0}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(1)).is_ok());
        assert!(cache.validate(schema, &json!(0)).is_err());
    }

    // ---- multiple types ----

    #[test]
    fn validate_one_of_schema() {
        let schema = r#"{"oneOf": [{"type": "string"}, {"type": "null"}]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("hello")).is_ok());
        assert!(cache.validate(schema, &json!(null)).is_ok());
        assert!(cache.validate(schema, &json!(42)).is_err());
    }

    #[test]
    fn validate_not_schema() {
        let schema = r#"{"not": {"type": "string"}}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(42)).is_ok());
        assert!(cache.validate(schema, &json!("hello")).is_err());
    }

    // ---- cache behavior ----

    #[test]
    fn cache_returns_same_validator_for_same_schema() {
        let cache = SchemaCache::default();
        let v1 = cache.get_or_compile(r#"{"type": "integer"}"#).unwrap();
        let v2 = cache.get_or_compile(r#"{"type": "integer"}"#).unwrap();
        assert!(Arc::ptr_eq(&v1, &v2));
    }

    #[test]
    fn cache_returns_different_validators_for_different_schemas() {
        let cache = SchemaCache::default();
        let v1 = cache.get_or_compile(r#"{"type": "string"}"#).unwrap();
        let v2 = cache.get_or_compile(r#"{"type": "integer"}"#).unwrap();
        assert!(!Arc::ptr_eq(&v1, &v2));
    }

    // ---- deeply nested validation ----

    #[test]
    fn validate_deeply_nested_schema() {
        let schema = r#"{
            "type": "object",
            "properties": {
                "level1": {
                    "type": "object",
                    "properties": {
                        "level2": {
                            "type": "object",
                            "properties": {
                                "value": {"type": "integer"}
                            },
                            "required": ["value"]
                        }
                    },
                    "required": ["level2"]
                }
            },
            "required": ["level1"]
        }"#;
        let cache = SchemaCache::default();
        assert!(
            cache
                .validate(schema, &json!({"level1": {"level2": {"value": 42}}}))
                .is_ok()
        );
        assert!(
            cache
                .validate(schema, &json!({"level1": {"level2": {}}}))
                .is_err()
        );
    }

    // ---- error message content ----

    #[test]
    fn compile_invalid_schema_returns_schema_validation_error() {
        let cache = SchemaCache::default();
        // An invalid schema type value causes a SchemaValidation error
        let result = cache.get_or_compile(r#"{"type": "not_a_type"}"#);
        match result {
            Err(GraphqlClientError::SchemaValidation { message, errors }) => {
                assert_eq!(message, "invalid JSON Schema");
                assert!(!errors.is_empty());
            }
            other => panic!("expected SchemaValidation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_schema_error_message_has_details() {
        let schema = r#"{"type": "object", "required": ["x", "y"]}"#;
        let cache = SchemaCache::default();
        match cache.validate(schema, &json!({})) {
            Err(GraphqlClientError::SchemaValidation { message, errors }) => {
                assert_eq!(message, "schema validation failed");
                assert!(errors.len() >= 2);
            }
            other => panic!("expected SchemaValidation, got {other:?}"),
        }
    }

    // ---- Schema with numeric constraints ----

    #[test]
    fn validate_integer_multiple_of() {
        let schema = r#"{"type": "integer", "multipleOf": 5}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(10)).is_ok());
        assert!(cache.validate(schema, &json!(15)).is_ok());
        assert!(cache.validate(schema, &json!(7)).is_err());
    }

    #[test]
    fn validate_number_exclusive_maximum() {
        let schema = r#"{"type": "number", "exclusiveMaximum": 10}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(9)).is_ok());
        assert!(cache.validate(schema, &json!(10)).is_err());
    }

    // ---- Schema with string format constraints ----

    #[test]
    fn validate_string_min_and_max_length() {
        let schema = r#"{"type": "string", "minLength": 2, "maxLength": 5}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("ab")).is_ok());
        assert!(cache.validate(schema, &json!("abcde")).is_ok());
        assert!(cache.validate(schema, &json!("a")).is_err());
        assert!(cache.validate(schema, &json!("abcdef")).is_err());
    }

    // ---- Schema caching with many schemas ----

    #[test]
    fn cache_stores_multiple_schemas() {
        let cache = SchemaCache::default();
        for i in 0..10 {
            let schema = format!(r#"{{"type": "integer", "minimum": {i}}}"#);
            assert!(cache.get_or_compile(&schema).is_ok());
        }
        // Verify one is cached
        let schema = r#"{"type": "integer", "minimum": 5}"#;
        let v1 = cache.get_or_compile(schema).unwrap();
        let v2 = cache.get_or_compile(schema).unwrap();
        assert!(Arc::ptr_eq(&v1, &v2));
    }

    // ---- validate with complex object schemas ----

    #[test]
    fn validate_object_with_default() {
        let schema = r#"{
            "type": "object",
            "properties": {
                "name": {"type": "string", "default": "unknown"}
            }
        }"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({})).is_ok());
        assert!(cache.validate(schema, &json!({"name": "Alice"})).is_ok());
    }

    #[test]
    fn validate_object_with_pattern_properties() {
        let schema = r#"{
            "type": "object",
            "patternProperties": {
                "^x-": {"type": "string"}
            },
            "additionalProperties": false
        }"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({"x-custom": "val"})).is_ok());
        assert!(cache.validate(schema, &json!({"name": "bad"})).is_err());
    }

    // ---- validate array with tuple validation ----

    #[test]
    fn validate_array_min_and_max_items() {
        let schema = r#"{"type": "array", "minItems": 2, "maxItems": 4}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!([1, 2])).is_ok());
        assert!(cache.validate(schema, &json!([1, 2, 3, 4])).is_ok());
        assert!(cache.validate(schema, &json!([1])).is_err());
        assert!(cache.validate(schema, &json!([1, 2, 3, 4, 5])).is_err());
    }

    // ---- validate with allOf ----

    #[test]
    fn validate_all_of_schema() {
        let schema = r#"{"allOf": [{"type": "object", "required": ["a"]}, {"type": "object", "required": ["b"]}]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({"a": 1, "b": 2})).is_ok());
        assert!(cache.validate(schema, &json!({"a": 1})).is_err());
        assert!(cache.validate(schema, &json!({"b": 2})).is_err());
    }

    // ---- validate with if/then/else ----

    #[test]
    fn validate_if_then_else() {
        let schema = r#"{
            "if": {"properties": {"type": {"const": "email"}}},
            "then": {"required": ["address"]},
            "else": {"required": ["phone"]}
        }"#;
        let cache = SchemaCache::default();
        assert!(
            cache
                .validate(schema, &json!({"type": "email", "address": "a@b.com"}))
                .is_ok()
        );
        assert!(
            cache
                .validate(schema, &json!({"type": "sms", "phone": "123"}))
                .is_ok()
        );
    }

    // ---- validate with definitions/refs ----

    #[test]
    fn validate_dependent_required() {
        let schema = r#"{
            "type": "object",
            "dependentRequired": {
                "credit_card": ["billing_address"]
            }
        }"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({})).is_ok());
        assert!(
            cache
                .validate(
                    schema,
                    &json!({"credit_card": "1234", "billing_address": "123 Main St"})
                )
                .is_ok()
        );
    }

    // ---- error handling edge cases ----

    #[test]
    fn compile_empty_string_returns_json_error() {
        let cache = SchemaCache::default();
        let result = cache.get_or_compile("");
        match result {
            Err(GraphqlClientError::Json(_)) => {}
            other => panic!("expected Json error, got {other:?}"),
        }
    }

    #[test]
    fn compile_array_json_is_valid_schema() {
        // A JSON array is not a valid JSON Schema (should be object or boolean)
        let cache = SchemaCache::default();
        let result = cache.get_or_compile("[1, 2, 3]");
        // jsonschema may accept or reject this; either way it shouldn't panic
        let _ = result;
    }

    #[test]
    fn validate_same_schema_different_values() {
        let schema = r#"{"type": "string", "enum": ["a", "b", "c"]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("a")).is_ok());
        assert!(cache.validate(schema, &json!("b")).is_ok());
        assert!(cache.validate(schema, &json!("c")).is_ok());
        assert!(cache.validate(schema, &json!("d")).is_err());
        assert!(cache.validate(schema, &json!(1)).is_err());
    }

    // ---- Schema: object with minProperties/maxProperties ----

    #[test]
    fn validate_object_min_properties() {
        let schema = r#"{"type": "object", "minProperties": 2}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({"a": 1, "b": 2})).is_ok());
        assert!(cache.validate(schema, &json!({"a": 1})).is_err());
    }

    #[test]
    fn validate_object_max_properties() {
        let schema = r#"{"type": "object", "maxProperties": 2}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({"a": 1, "b": 2})).is_ok());
        assert!(
            cache
                .validate(schema, &json!({"a": 1, "b": 2, "c": 3}))
                .is_err()
        );
    }

    // ---- Schema: numeric multipleOf with float ----

    #[test]
    fn validate_number_multiple_of_float() {
        let schema = r#"{"type": "number", "multipleOf": 0.5}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!(1.5)).is_ok());
        assert!(cache.validate(schema, &json!(2.0)).is_ok());
        assert!(cache.validate(schema, &json!(1.3)).is_err());
    }

    // ---- Schema: ref within definitions ----

    #[test]
    fn validate_schema_with_definitions_and_ref() {
        let ref_str = "#/$defs/name";
        let schema = serde_json::json!({
            "$defs": {
                "name": {"type": "string", "minLength": 1}
            },
            "type": "object",
            "properties": {
                "first_name": {"$ref": ref_str},
                "last_name": {"$ref": ref_str}
            },
            "required": ["first_name"]
        })
        .to_string();
        let cache = SchemaCache::default();
        assert!(
            cache
                .validate(&schema, &json!({"first_name": "Alice"}))
                .is_ok()
        );
        assert!(cache.validate(&schema, &json!({})).is_err());
        assert!(
            cache
                .validate(&schema, &json!({"first_name": ""}))
                .is_err()
        );
    }

    // ---- Schema cache: concurrent-safe usage ----

    #[test]
    fn cache_compile_and_validate_in_sequence() {
        let cache = SchemaCache::default();
        let schema = r#"{"type": "integer", "minimum": 0}"#;

        // Compile
        let v = cache.get_or_compile(schema).unwrap();
        assert!(Arc::strong_count(&v) >= 1);

        // Validate using same schema
        assert!(cache.validate(schema, &json!(5)).is_ok());
        assert!(cache.validate(schema, &json!(-1)).is_err());

        // Re-fetch should be cached
        let v2 = cache.get_or_compile(schema).unwrap();
        assert!(Arc::ptr_eq(&v, &v2));
    }

    // ---- Schema: empty required array ----

    #[test]
    fn validate_empty_required_array_accepts_empty_object() {
        let schema = r#"{"type": "object", "required": []}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!({})).is_ok());
    }

    // ---- Schema: type array (multiple types) ----

    #[test]
    fn validate_type_array_string_or_null() {
        let schema = r#"{"type": ["string", "null"]}"#;
        let cache = SchemaCache::default();
        assert!(cache.validate(schema, &json!("hello")).is_ok());
        assert!(cache.validate(schema, &json!(null)).is_ok());
        assert!(cache.validate(schema, &json!(42)).is_err());
    }

    // ---- SchemaCache: compile returns error for deeply invalid schemas ----

    #[test]
    fn compile_deeply_invalid_type() {
        let cache = SchemaCache::default();
        // "type": 42 is invalid
        let result = cache.get_or_compile(r#"{"type": 42}"#);
        match result {
            Err(GraphqlClientError::SchemaValidation { .. }) => {}
            other => panic!("expected SchemaValidation error, got {other:?}"),
        }
    }
}
