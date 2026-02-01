//! FZPF (Flywheel Zone Policy Format) schema validation.
//!
//! This module provides schema validation for FCP2 zone policy documents.
//! It includes the FZPF v0.1 JSON Schema and validation utilities.
//!
//! # Schema Validation
//!
//! The FZPF schema enforces:
//! - Zone definition structure with integrity/confidentiality levels
//! - Zone policy access control rules
//! - Role definitions and assignments
//! - Cross-zone data flow rules
//! - Taint-based policy rules
//! - Approval constraints for elevation/declassification/execution
//!
//! # Normative Requirements
//!
//! - **Patterns**: Only anchored glob patterns (*, ?) are allowed. Regex and `JSONPath` are forbidden.
//! - **JSON Pointers**: RFC 6901 only for input constraints.
//! - **Zone IDs**: Must match `^z:[a-z][a-z0-9_-]*$`
//! - **Integrity/Confidentiality**: 0-100 range, child zones must not exceed parent levels
//!
//! # Example
//!
//! ```ignore
//! use fcp_conformance::schemas::validate_fzpf_policy;
//!
//! let policy_json = r#"{ "policy": { ... }, "zones": [...] }"#;
//! let result = validate_fzpf_policy(policy_json);
//! assert!(result.is_ok());
//! ```

use jsonschema::Validator;
use serde_json::Value;

/// The FZPF v0.1 JSON Schema as a string constant.
pub const FZPF_V01_SCHEMA: &str = include_str!("FZPF_v0.1.schema.json");

/// The E2E harness JSONL log schema (v1).
pub const E2E_LOG_V1_SCHEMA: &str = include_str!("E2E_Log_v1.schema.json");
/// The E2E harness JSONL log schema (v2).
pub const E2E_LOG_V2_SCHEMA: &str = include_str!("E2E_Log_v2.schema.json");
/// The `PolicyBundle` JSON schema (v1).
pub const POLICY_BUNDLE_V1_SCHEMA: &str = include_str!("PolicyBundle_v1.schema.json");
/// The `ReleaseManifest` JSON schema (v1).
pub const RELEASE_MANIFEST_V1_SCHEMA: &str = include_str!("ReleaseManifest_v1.schema.json");
/// The `RolloutPolicy` JSON schema (v1).
pub const ROLLOUT_POLICY_V1_SCHEMA: &str = include_str!("RolloutPolicy_v1.schema.json");
/// The `Trace` JSON schema (v1).
pub const TRACE_V1_SCHEMA: &str = include_str!("Trace_v1.schema.json");
/// The `CapabilityUsage` JSON schema (v1).
pub const CAPABILITY_USAGE_V1_SCHEMA: &str = include_str!("CapabilityUsage_v1.schema.json");

/// Schema validation error for conformance helpers.
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

impl std::fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// Validate a single E2E log entry (JSON object) against the versioned schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_e2e_log_entry(value: &Value) -> Result<(), SchemaValidationError> {
    let version = detect_log_version(value)?;
    let validator = match version {
        E2eLogVersion::V1 => compile_schema(E2E_LOG_V1_SCHEMA)?,
        E2eLogVersion::V2 => compile_schema(E2E_LOG_V2_SCHEMA)?,
    };
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

/// Validate a JSONL payload of E2E log entries.
///
/// # Errors
///
/// Returns `SchemaValidationError` if any line is invalid JSON or fails schema validation.
pub fn validate_e2e_log_jsonl(input: &str) -> Result<(), SchemaValidationError> {
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

/// Validate a `PolicyBundle` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_policy_bundle(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(POLICY_BUNDLE_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

/// Validate a `ReleaseManifest` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_release_manifest(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(RELEASE_MANIFEST_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

/// Validate a `RolloutPolicy` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_rollout_policy(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(ROLLOUT_POLICY_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

/// Validate a `Trace` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_trace(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(TRACE_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

/// Validate a `CapabilityUsage` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_capability_usage(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(CAPABILITY_USAGE_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

#[cfg(test)]
mod tests;
