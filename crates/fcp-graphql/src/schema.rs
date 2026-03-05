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
}
