#![allow(dead_code)]

use std::fmt;
use std::sync::{Arc, Mutex};

use jsonschema::Validator;
use serde_json::Value;

const E2E_LOG_V1_SCHEMA: &str =
    include_str!("../../fcp-conformance/src/schemas/E2E_Log_v1.schema.json");
const E2E_LOG_V2_SCHEMA: &str =
    include_str!("../../fcp-conformance/src/schemas/E2E_Log_v2.schema.json");

#[derive(Debug, Clone)]
pub struct SchemaValidationError {
    message: String,
}

impl SchemaValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SchemaValidationError {}

fn compile_schema(schema_str: &str) -> Result<Validator, SchemaValidationError> {
    let schema: Value = serde_json::from_str(schema_str)
        .map_err(|err| SchemaValidationError::new(err.to_string()))?;
    Validator::new(&schema)
        .map_err(|err| SchemaValidationError::new(format!("schema compile failed: {err}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E2eLogVersion {
    V1,
    V2,
}

fn detect_log_version(value: &Value) -> Result<E2eLogVersion, SchemaValidationError> {
    match value.get("log_version") {
        None => Ok(E2eLogVersion::V1),
        Some(Value::String(version)) => match version.as_str() {
            "v1" => Ok(E2eLogVersion::V1),
            "v2" => Ok(E2eLogVersion::V2),
            other => Err(SchemaValidationError::new(format!(
                "unknown log_version `{other}`"
            ))),
        },
        Some(other) => Err(SchemaValidationError::new(format!(
            "log_version must be a string, got {other}"
        ))),
    }
}

fn validate_e2e_log_jsonl(input: &str) -> Result<(), SchemaValidationError> {
    let validator_v1 = compile_schema(E2E_LOG_V1_SCHEMA)?;
    let validator_v2 = compile_schema(E2E_LOG_V2_SCHEMA)?;
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|err| {
            SchemaValidationError::new(format!("line {}: invalid JSON: {err}", idx + 1))
        })?;
        let version = detect_log_version(&value)?;
        let validator = match version {
            E2eLogVersion::V1 => &validator_v1,
            E2eLogVersion::V2 => &validator_v2,
        };
        if let Err(err) = validator.validate(&value) {
            return Err(SchemaValidationError::new(format!(
                "line {}: {}",
                idx + 1,
                err
            )));
        }
    }
    Ok(())
}

/// Minimal JSONL capture for `fcp-core` integration tests.
#[derive(Clone, Default)]
pub struct LogCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn jsonl(&self) -> String {
        let guard = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&guard).into_owned()
    }

    pub fn push_line(&self, line: &str) {
        let mut guard = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.extend_from_slice(line.as_bytes());
        guard.push(b'\n');
    }

    /// Serialize and append a JSON value as a JSONL line.
    ///
    /// # Errors
    ///
    /// Returns any serialization error produced by `serde_json::to_string`.
    pub fn push_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error> {
        let line = serde_json::to_string(value)?;
        self.push_line(&line);
        Ok(())
    }

    /// Validate the collected JSONL log against the E2E schema.
    ///
    /// # Errors
    ///
    /// Returns any schema validation error from `validate_e2e_log_jsonl`.
    pub fn validate_jsonl(&self) -> Result<(), SchemaValidationError> {
        validate_e2e_log_jsonl(&self.jsonl())
    }

    /// Assert that the collected JSONL log matches the E2E schema.
    ///
    /// # Panics
    ///
    /// Panics if schema validation fails.
    pub fn assert_valid(&self) {
        self.validate_jsonl()
            .expect("expected JSONL logs to match the E2E schema");
    }
}
