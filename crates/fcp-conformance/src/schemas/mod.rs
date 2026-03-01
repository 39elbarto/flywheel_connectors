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
/// The `SupplyChainAttestation` JSON schema (v1).
pub const SUPPLY_CHAIN_ATTESTATION_V1_SCHEMA: &str =
    include_str!("SupplyChainAttestation_v1.schema.json");
/// The `SBOM` JSON schema (v1).
pub const SBOM_V1_SCHEMA: &str = include_str!("Sbom_v1.schema.json");
/// The ASUPERSYNC step-level forensics JSON schema (v1).
pub const ASUPERSYNC_FORENSICS_V1_SCHEMA: &str =
    include_str!("Asupersync_Forensics_v1.schema.json");
/// Canonical ASUPERSYNC forensics schema version marker.
pub const ASUPERSYNC_FORENSICS_V1: &str = "asupersync-forensics/v1";

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

/// Deterministic, rule-keyed diagnostic for ASUPERSYNC forensics validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicsRuleDiagnostic {
    /// Stable rule identifier.
    pub rule_id: &'static str,
    /// Field name tied to the rule.
    pub field: &'static str,
    /// Human-readable deterministic message.
    pub message: String,
}

impl ForensicsRuleDiagnostic {
    fn new(rule_id: &'static str, field: &'static str, message: impl Into<String>) -> Self {
        Self {
            rule_id,
            field,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ForensicsRuleDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.rule_id, self.field, self.message)
    }
}

/// Validation errors for ASUPERSYNC step-level forensics records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForensicsValidationError {
    /// JSON line could not be parsed.
    InvalidJsonLine {
        /// 1-based line number.
        line: usize,
        /// Parse error message.
        message: String,
    },
    /// Rule-level violation with deterministic diagnostic metadata.
    RuleViolation {
        /// Optional 1-based line number.
        line: Option<usize>,
        /// Rule diagnostic payload.
        diagnostic: ForensicsRuleDiagnostic,
    },
}

impl ForensicsValidationError {
    fn with_line(self, line: usize) -> Self {
        match self {
            Self::RuleViolation {
                line: Some(existing_line),
                diagnostic,
            } => Self::RuleViolation {
                line: Some(existing_line),
                diagnostic,
            },
            Self::RuleViolation {
                line: None,
                diagnostic,
            } => Self::RuleViolation {
                line: Some(line),
                diagnostic,
            },
            other => other,
        }
    }

    /// Stable rule identifier, when present.
    #[must_use]
    pub const fn rule_id(&self) -> Option<&'static str> {
        match self {
            Self::InvalidJsonLine { .. } => None,
            Self::RuleViolation { diagnostic, .. } => Some(diagnostic.rule_id),
        }
    }

    /// 1-based line number, when available.
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        match self {
            Self::InvalidJsonLine { line, .. } => Some(*line),
            Self::RuleViolation { line, .. } => *line,
        }
    }
}

impl std::fmt::Display for ForensicsValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJsonLine { line, message } => {
                write!(f, "line {line}: invalid JSON: {message}")
            }
            Self::RuleViolation {
                line: Some(line),
                diagnostic,
            } => write!(f, "line {line}: {diagnostic}"),
            Self::RuleViolation {
                line: None,
                diagnostic,
            } => write!(f, "{diagnostic}"),
        }
    }
}

impl std::error::Error for ForensicsValidationError {}

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

const RULE_RECORD_OBJECT: &str = "asupersync.forensics.v1.record.object";
const RULE_SCHEMA_VERSION: &str = "asupersync.forensics.v1.schema_version";
const RULE_RUN_ID: &str = "asupersync.forensics.v1.run_id";
const RULE_RUN_ID_MATCH: &str = "asupersync.forensics.v1.run_id.match";
const RULE_SCENARIO_ID: &str = "asupersync.forensics.v1.scenario_id";
const RULE_TRACE_ID: &str = "asupersync.forensics.v1.trace_id";
const RULE_CORRELATION_ID: &str = "asupersync.forensics.v1.correlation_id";
const RULE_CONNECTOR: &str = "asupersync.forensics.v1.connector";
const RULE_ZONE: &str = "asupersync.forensics.v1.zone";
const RULE_OPERATION: &str = "asupersync.forensics.v1.operation";
const RULE_ATTEMPT: &str = "asupersync.forensics.v1.attempt";
const RULE_TIMEOUT_BUDGET_MS: &str = "asupersync.forensics.v1.timeout_budget_ms";
const RULE_CANCELLATION_REASON: &str = "asupersync.forensics.v1.cancellation_reason";
const RULE_QUEUE_DEPTH: &str = "asupersync.forensics.v1.queue_depth";
const RULE_DECODE_BUDGET: &str = "asupersync.forensics.v1.decode_budget";
const RULE_OUTCOME: &str = "asupersync.forensics.v1.outcome";
const RULE_ELAPSED_MS: &str = "asupersync.forensics.v1.elapsed_ms";
const RULE_SPAN_ID: &str = "asupersync.forensics.v1.span_id";
const RULE_RESULT_CODE: &str = "asupersync.forensics.v1.result_code";

fn rule_violation(
    line: Option<usize>,
    rule_id: &'static str,
    field: &'static str,
    message: impl Into<String>,
) -> ForensicsValidationError {
    ForensicsValidationError::RuleViolation {
        line,
        diagnostic: ForensicsRuleDiagnostic::new(rule_id, field, message),
    }
}

fn require_non_empty_string<'a>(
    value: &'a Value,
    field: &'static str,
    rule_id: &'static str,
) -> Result<&'a str, ForensicsValidationError> {
    match value.get(field) {
        Some(Value::String(raw)) if raw.trim().is_empty() => Err(rule_violation(
            None,
            rule_id,
            field,
            "must be a non-empty string",
        )),
        Some(Value::String(raw)) => Ok(raw.as_str()),
        Some(other) => Err(rule_violation(
            None,
            rule_id,
            field,
            format!("must be a string, got {other}"),
        )),
        None => Err(rule_violation(
            None,
            rule_id,
            field,
            "missing required field",
        )),
    }
}

fn require_non_negative_u64(
    value: &Value,
    field: &'static str,
    rule_id: &'static str,
) -> Result<u64, ForensicsValidationError> {
    let Some(raw) = value.get(field) else {
        return Err(rule_violation(
            None,
            rule_id,
            field,
            "missing required field",
        ));
    };

    raw.as_u64().ok_or_else(|| {
        rule_violation(
            None,
            rule_id,
            field,
            format!("must be a non-negative integer, got {raw}"),
        )
    })
}

fn require_nullable_non_empty_string(
    value: &Value,
    field: &'static str,
    rule_id: &'static str,
) -> Result<Option<String>, ForensicsValidationError> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if raw.trim().is_empty() => Err(rule_violation(
            None,
            rule_id,
            field,
            "must be null or a non-empty string",
        )),
        Some(Value::String(raw)) => Ok(Some(raw.clone())),
        Some(other) => Err(rule_violation(
            None,
            rule_id,
            field,
            format!("must be null or a string, got {other}"),
        )),
        None => Err(rule_violation(
            None,
            rule_id,
            field,
            "missing required field",
        )),
    }
}

fn require_nullable_non_negative_number(
    value: &Value,
    field: &'static str,
    rule_id: &'static str,
) -> Result<Option<f64>, ForensicsValidationError> {
    match value.get(field) {
        Some(Value::Null) => Ok(None),
        Some(raw) => {
            let number = raw.as_f64().ok_or_else(|| {
                rule_violation(
                    None,
                    rule_id,
                    field,
                    format!("must be null or a non-negative number, got {raw}"),
                )
            })?;
            if !number.is_finite() || number < 0.0 {
                return Err(rule_violation(
                    None,
                    rule_id,
                    field,
                    format!("must be null or a non-negative number, got {raw}"),
                ));
            }
            Ok(Some(number))
        }
        None => Err(rule_violation(
            None,
            rule_id,
            field,
            "missing required field",
        )),
    }
}

fn validate_run_id(
    value: &Value,
    expected_run_id: Option<&str>,
) -> Result<(), ForensicsValidationError> {
    let run_id = require_non_empty_string(value, "run_id", RULE_RUN_ID)?;
    if let Some(expected) = expected_run_id
        && run_id != expected
    {
        return Err(rule_violation(
            None,
            RULE_RUN_ID_MATCH,
            "run_id",
            format!("must match expected run_id `{expected}`, got `{run_id}`"),
        ));
    }
    Ok(())
}

fn validate_identity_fields(value: &Value) -> Result<(), ForensicsValidationError> {
    require_non_empty_string(value, "scenario_id", RULE_SCENARIO_ID)?;
    require_non_empty_string(value, "trace_id", RULE_TRACE_ID)?;
    require_non_empty_string(value, "correlation_id", RULE_CORRELATION_ID)?;
    require_non_empty_string(value, "connector", RULE_CONNECTOR)?;
    require_non_empty_string(value, "zone", RULE_ZONE)?;
    require_non_empty_string(value, "operation", RULE_OPERATION)?;
    Ok(())
}

fn validate_attempt(value: &Value) -> Result<(), ForensicsValidationError> {
    let attempt = require_non_negative_u64(value, "attempt", RULE_ATTEMPT)?;
    if attempt == 0 {
        return Err(rule_violation(
            None,
            RULE_ATTEMPT,
            "attempt",
            "must be greater than or equal to 1",
        ));
    }
    Ok(())
}

fn validate_outcome(value: &Value) -> Result<(), ForensicsValidationError> {
    let outcome = require_non_empty_string(value, "outcome", RULE_OUTCOME)?;
    if !matches!(outcome, "pass" | "fail" | "planned") {
        return Err(rule_violation(
            None,
            RULE_OUTCOME,
            "outcome",
            format!("must be one of [pass, fail, planned], got `{outcome}`"),
        ));
    }
    Ok(())
}

fn validate_optional_span_id(value: &Value) -> Result<(), ForensicsValidationError> {
    if let Some(span_id_value) = value.get("span_id") {
        match span_id_value {
            Value::String(span_id)
                if span_id.len() == 16 && span_id.chars().all(|ch| ch.is_ascii_hexdigit()) => {}
            Value::String(span_id) => {
                return Err(rule_violation(
                    None,
                    RULE_SPAN_ID,
                    "span_id",
                    format!("must be 16 hexadecimal characters, got `{span_id}`"),
                ));
            }
            other => {
                return Err(rule_violation(
                    None,
                    RULE_SPAN_ID,
                    "span_id",
                    format!("must be a hex string, got {other}"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_optional_result_code(value: &Value) -> Result<(), ForensicsValidationError> {
    if let Some(result_code_value) = value.get("result_code") {
        match result_code_value {
            Value::String(result_code) if !result_code.trim().is_empty() => {}
            Value::String(_) => {
                return Err(rule_violation(
                    None,
                    RULE_RESULT_CODE,
                    "result_code",
                    "must be a non-empty string when present",
                ));
            }
            other => {
                return Err(rule_violation(
                    None,
                    RULE_RESULT_CODE,
                    "result_code",
                    format!("must be a string when present, got {other}"),
                ));
            }
        }
    }
    Ok(())
}

/// Validate a single ASUPERSYNC step-level forensics record.
///
/// The validation emits deterministic, rule-keyed diagnostics for missing fields,
/// type mismatches, and semantic invariant violations.
///
/// # Errors
///
/// Returns `ForensicsValidationError` when the record is malformed.
pub fn validate_asupersync_forensics_entry(
    value: &Value,
    expected_run_id: Option<&str>,
) -> Result<(), ForensicsValidationError> {
    if !value.is_object() {
        return Err(rule_violation(
            None,
            RULE_RECORD_OBJECT,
            "$",
            "record must be a JSON object",
        ));
    }

    let schema_version = require_non_empty_string(value, "schema_version", RULE_SCHEMA_VERSION)?;
    if schema_version != ASUPERSYNC_FORENSICS_V1 {
        return Err(rule_violation(
            None,
            RULE_SCHEMA_VERSION,
            "schema_version",
            format!("must equal `{ASUPERSYNC_FORENSICS_V1}`, got `{schema_version}`"),
        ));
    }

    validate_run_id(value, expected_run_id)?;
    validate_identity_fields(value)?;
    validate_attempt(value)?;

    require_non_negative_u64(value, "timeout_budget_ms", RULE_TIMEOUT_BUDGET_MS)?;
    require_nullable_non_empty_string(value, "cancellation_reason", RULE_CANCELLATION_REASON)?;
    require_nullable_non_negative_number(value, "queue_depth", RULE_QUEUE_DEPTH)?;
    require_nullable_non_negative_number(value, "decode_budget", RULE_DECODE_BUDGET)?;

    validate_outcome(value)?;
    require_non_negative_u64(value, "elapsed_ms", RULE_ELAPSED_MS)?;
    validate_optional_span_id(value)?;
    validate_optional_result_code(value)?;

    Ok(())
}

/// Validate a JSONL payload of ASUPERSYNC step-level forensics records.
///
/// # Errors
///
/// Returns `ForensicsValidationError` with line-aware diagnostics when
/// any record is invalid.
pub fn validate_asupersync_forensics_jsonl(
    input: &str,
    expected_run_id: Option<&str>,
) -> Result<(), ForensicsValidationError> {
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let value: Value = serde_json::from_str(trimmed).map_err(|err| {
            ForensicsValidationError::InvalidJsonLine {
                line: idx + 1,
                message: err.to_string(),
            }
        })?;

        validate_asupersync_forensics_entry(&value, expected_run_id)
            .map_err(|err| err.with_line(idx + 1))?;
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

/// Validate a `SupplyChainAttestation` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_supply_chain_attestation(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(SUPPLY_CHAIN_ATTESTATION_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

/// Validate an `SBOM` JSON document against the v1 schema.
///
/// # Errors
///
/// Returns `SchemaValidationError` if validation fails.
pub fn validate_sbom(value: &Value) -> Result<(), SchemaValidationError> {
    let validator = compile_schema(SBOM_V1_SCHEMA)?;
    validator
        .validate(value)
        .map_err(|err| SchemaValidationError::new(err.to_string()))
}

#[cfg(test)]
mod tests;
