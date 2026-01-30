//! Structured logging utilities for E2E connector verification.

use std::io::{self, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use fcp_conformance::schemas::validate_e2e_log_entry;
use serde::{Deserialize, Serialize};

/// Summary of assertions for a test phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AssertionsSummary {
    /// Number of passed assertions.
    pub passed: u32,
    /// Number of failed assertions.
    pub failed: u32,
}

impl AssertionsSummary {
    /// Create a new summary from counts.
    #[must_use]
    pub const fn new(passed: u32, failed: u32) -> Self {
        Self { passed, failed }
    }
}

/// Structured log entry for E2E tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eLogEntry {
    /// RFC3339 timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Log level (info, warn, error).
    pub level: String,
    /// Test name.
    pub test_name: String,
    /// Module name (e.g., fcp-e2e).
    pub module: String,
    /// Phase (setup|execute|verify|teardown).
    pub phase: String,
    /// Correlation ID.
    pub correlation_id: String,
    /// Result (pass|fail).
    pub result: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Assertion counts.
    pub assertions: AssertionsSummary,
    /// Context-specific fields (`zone_id`, `connector_id`, etc.).
    #[serde(default)]
    pub context: serde_json::Value,
}

impl E2eLogEntry {
    /// Create a new log entry.
    #[must_use]
    pub fn new(
        level: impl Into<String>,
        test_name: impl Into<String>,
        module: impl Into<String>,
        phase: impl Into<String>,
        correlation_id: impl Into<String>,
        result: impl Into<String>,
        duration_ms: u64,
        assertions: AssertionsSummary,
        context: serde_json::Value,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            level: level.into(),
            test_name: test_name.into(),
            module: module.into(),
            phase: phase.into(),
            correlation_id: correlation_id.into(),
            result: result.into(),
            duration_ms,
            assertions,
            context: redact_secrets(&context),
        }
    }

    /// Validate this log entry against the shared E2E schema.
    ///
    /// # Errors
    /// Returns [`LogSchemaError`] if required fields are missing or malformed.
    pub fn validate(&self) -> Result<(), LogSchemaError> {
        let value = serde_json::to_value(self).map_err(|err| LogSchemaError::InvalidJson {
            message: err.to_string(),
        })?;
        validate_log_entry_value(&value)
    }
}

/// Logger that collects E2E log entries in memory.
#[derive(Debug, Default)]
pub struct E2eLogger {
    entries: Vec<E2eLogEntry>,
}

impl E2eLogger {
    /// Create a new logger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a log entry.
    pub fn push(&mut self, entry: E2eLogEntry) {
        self.entries.push(entry);
    }

    /// Return all collected entries.
    #[must_use]
    pub fn entries(&self) -> &[E2eLogEntry] {
        &self.entries
    }

    /// Drain all collected entries.
    pub fn drain(&mut self) -> Vec<E2eLogEntry> {
        std::mem::take(&mut self.entries)
    }

    /// Serialize all entries to JSON lines.
    #[must_use]
    pub fn to_json_lines(&self) -> String {
        self.entries
            .iter()
            .filter_map(|entry| serde_json::to_string(entry).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write all entries as JSON lines to a file.
    ///
    /// # Errors
    /// Returns an IO error if the file cannot be created or written to.
    pub fn write_json_lines<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut file = std::fs::File::create(path)?;
        for entry in &self.entries {
            let line = serde_json::to_string(entry)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

/// Errors for log schema validation.
#[derive(Debug, thiserror::Error)]
pub enum LogSchemaError {
    /// JSON serialization failure.
    #[error("invalid json: {message}")]
    InvalidJson { message: String },
    /// Missing required field.
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },
    /// Invalid field type or value.
    #[error("invalid field {field}: {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
}

/// Validate an arbitrary JSON value against the shared E2E log schema.
///
/// This accepts both harness logs (`test_name`, `phase`) and script logs
/// (`script`, `step`) as long as the required base fields are present.
///
/// # Errors
///
/// Returns `LogSchemaError` if schema validation fails.
pub fn validate_log_entry_value(value: &serde_json::Value) -> Result<(), LogSchemaError> {
    validate_e2e_log_entry(value).map_err(|err| LogSchemaError::InvalidField {
        field: "schema",
        message: err.to_string(),
    })
}

fn should_redact_key(key: &str) -> bool {
    let needle = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "client_secret",
    ]
    .iter()
    .any(|s| needle.contains(s))
}

fn redact_secrets(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, val) in map {
                if should_redact_key(key) {
                    redacted.insert(
                        key.clone(),
                        serde_json::Value::String("redacted".to_string()),
                    );
                } else {
                    redacted.insert(key.clone(), redact_secrets(val));
                }
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(redact_secrets).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{AssertionsSummary, E2eLogEntry, validate_log_entry_value};
    use serde_json::json;

    #[test]
    fn validate_harness_log_entry() {
        let entry = E2eLogEntry::new(
            "info",
            "test_harness",
            "fcp-e2e",
            "execute",
            "00000000-0000-4000-8000-000000000000",
            "pass",
            12,
            AssertionsSummary::new(3, 0),
            json!({"zone_id": "z:work"}),
        );
        entry.validate().expect("entry should validate");
    }

    #[test]
    fn validate_script_log_entry() {
        let entry = json!({
            "timestamp": "2026-01-27T00:00:00Z",
            "script": "e2e_happy_path",
            "step": "invoke",
            "step_number": 4,
            "correlation_id": "00000000-0000-4000-8000-000000000000",
            "duration_ms": 25,
            "result": "pass",
            "artifacts": ["receipt.cbor"]
        });
        validate_log_entry_value(&entry).expect("script entry should validate");
    }

    #[test]
    fn reject_missing_core_fields() {
        let entry = json!({
            "script": "e2e_happy_path",
            "step": "invoke"
        });
        assert!(validate_log_entry_value(&entry).is_err());
    }
}
