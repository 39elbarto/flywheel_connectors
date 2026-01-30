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
    /// Log schema version.
    #[serde(default = "default_log_version")]
    pub log_version: String,
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
            log_version: default_log_version(),
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

fn default_log_version() -> String {
    "v1".to_string()
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

    #[test]
    fn should_redact_key_matches_sensitive() {
        assert!(super::should_redact_key("access_token"));
        assert!(super::should_redact_key("refresh_token"));
        assert!(super::should_redact_key("api_key"));
        assert!(super::should_redact_key("apikey"));
        assert!(super::should_redact_key("client_secret"));
        assert!(super::should_redact_key("password"));
        assert!(super::should_redact_key("secret"));
        assert!(super::should_redact_key("token"));
    }

    #[test]
    fn should_redact_key_case_insensitive() {
        assert!(super::should_redact_key("API_KEY"));
        assert!(super::should_redact_key("AccessToken"));
        assert!(super::should_redact_key("CLIENT_SECRET"));
        assert!(super::should_redact_key("Password"));
    }

    #[test]
    fn should_redact_key_normal_keys_not_matched() {
        assert!(!super::should_redact_key("name"));
        assert!(!super::should_redact_key("status"));
        assert!(!super::should_redact_key("zone_id"));
        assert!(!super::should_redact_key("module"));
        assert!(!super::should_redact_key("correlation_id"));
    }

    #[test]
    fn redact_secrets_redacts_sensitive_keys() {
        let input = json!({
            "access_token": "bearer-xyz",
            "name": "test"
        });
        let redacted = super::redact_secrets(&input);
        assert_eq!(
            redacted.get("access_token").and_then(|v| v.as_str()),
            Some("redacted")
        );
        assert_eq!(redacted.get("name").and_then(|v| v.as_str()), Some("test"));
    }

    #[test]
    fn redact_secrets_handles_nested_objects() {
        let input = json!({
            "auth": {
                "client_secret": "s3cr3t",
                "client_id": "my-app"
            }
        });
        let redacted = super::redact_secrets(&input);
        let auth = redacted.get("auth").expect("auth key");
        assert_eq!(
            auth.get("client_secret").and_then(|v| v.as_str()),
            Some("redacted")
        );
        assert_eq!(
            auth.get("client_id").and_then(|v| v.as_str()),
            Some("my-app")
        );
    }

    #[test]
    fn redact_secrets_handles_arrays() {
        let input = json!([
            {"password": "pass1", "user": "alice"},
            {"password": "pass2", "user": "bob"}
        ]);
        let redacted = super::redact_secrets(&input);
        let arr = redacted.as_array().expect("array");
        assert_eq!(
            arr[0].get("password").and_then(|v| v.as_str()),
            Some("redacted")
        );
        assert_eq!(arr[0].get("user").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(
            arr[1].get("password").and_then(|v| v.as_str()),
            Some("redacted")
        );
    }

    #[test]
    fn redact_secrets_scalar_passthrough() {
        assert_eq!(super::redact_secrets(&json!("hello")), json!("hello"));
        assert_eq!(super::redact_secrets(&json!(42)), json!(42));
        assert_eq!(super::redact_secrets(&json!(true)), json!(true));
        assert_eq!(super::redact_secrets(&json!(null)), json!(null));
    }

    #[test]
    fn logger_new_is_empty() {
        let logger = super::E2eLogger::new();
        assert!(logger.entries().is_empty());
    }

    #[test]
    fn logger_push_and_entries() {
        let mut logger = super::E2eLogger::new();
        let entry = E2eLogEntry::new(
            "info",
            "test",
            "mod",
            "setup",
            "corr-1",
            "pass",
            5,
            AssertionsSummary::new(1, 0),
            json!({}),
        );
        logger.push(entry);
        assert_eq!(logger.entries().len(), 1);
        assert_eq!(logger.entries()[0].test_name, "test");
    }

    #[test]
    fn logger_drain_clears_entries() {
        let mut logger = super::E2eLogger::new();
        logger.push(E2eLogEntry::new(
            "info",
            "t1",
            "m",
            "setup",
            "c1",
            "pass",
            1,
            AssertionsSummary::new(1, 0),
            json!({}),
        ));
        logger.push(E2eLogEntry::new(
            "error",
            "t2",
            "m",
            "verify",
            "c2",
            "fail",
            2,
            AssertionsSummary::new(0, 1),
            json!({}),
        ));
        let drained = logger.drain();
        assert_eq!(drained.len(), 2);
        assert!(logger.entries().is_empty());
    }

    #[test]
    fn logger_to_json_lines() {
        let mut logger = super::E2eLogger::new();
        logger.push(E2eLogEntry::new(
            "info",
            "test1",
            "mod1",
            "setup",
            "corr-1",
            "pass",
            10,
            AssertionsSummary::new(1, 0),
            json!({}),
        ));
        logger.push(E2eLogEntry::new(
            "warn",
            "test2",
            "mod2",
            "verify",
            "corr-2",
            "fail",
            20,
            AssertionsSummary::new(0, 1),
            json!({}),
        ));
        let lines = logger.to_json_lines();
        let parts: Vec<&str> = lines.split('\n').collect();
        assert_eq!(parts.len(), 2);
        let first: serde_json::Value = serde_json::from_str(parts[0]).expect("valid JSON");
        assert_eq!(
            first.get("test_name").and_then(|v| v.as_str()),
            Some("test1")
        );
    }

    #[test]
    fn assertions_summary_serde_roundtrip() {
        let summary = AssertionsSummary::new(5, 2);
        let json_str = serde_json::to_string(&summary).expect("serialize");
        let back: AssertionsSummary = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.passed, 5);
        assert_eq!(back.failed, 2);
    }

    #[test]
    fn log_entry_serde_roundtrip() {
        let entry = E2eLogEntry::new(
            "info",
            "serde_test",
            "fcp-e2e",
            "execute",
            "00000000-0000-4000-8000-000000000000",
            "pass",
            42,
            AssertionsSummary::new(3, 1),
            json!({"zone_id": "z:work"}),
        );
        let json_str = serde_json::to_string(&entry).expect("serialize");
        let back: E2eLogEntry = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.test_name, "serde_test");
        assert_eq!(back.level, "info");
        assert_eq!(back.phase, "execute");
        assert_eq!(back.result, "pass");
        assert_eq!(back.duration_ms, 42);
        assert_eq!(back.assertions.passed, 3);
        assert_eq!(back.assertions.failed, 1);
    }

    #[test]
    fn log_schema_error_display_variants() {
        let e1 = super::LogSchemaError::InvalidJson {
            message: "bad json".to_string(),
        };
        assert_eq!(e1.to_string(), "invalid json: bad json");

        let e2 = super::LogSchemaError::MissingField { field: "timestamp" };
        assert_eq!(e2.to_string(), "missing required field: timestamp");

        let e3 = super::LogSchemaError::InvalidField {
            field: "level",
            message: "must be info|warn|error".to_string(),
        };
        assert_eq!(
            e3.to_string(),
            "invalid field level: must be info|warn|error"
        );
    }

    #[test]
    fn log_entry_redacts_context_secrets() {
        let entry = E2eLogEntry::new(
            "info",
            "redact_test",
            "fcp-e2e",
            "setup",
            "corr-redact",
            "pass",
            0,
            AssertionsSummary::new(1, 0),
            json!({"access_token": "secret-value", "zone_id": "z:work"}),
        );
        assert_eq!(
            entry.context.get("access_token").and_then(|v| v.as_str()),
            Some("redacted")
        );
        assert_eq!(
            entry.context.get("zone_id").and_then(|v| v.as_str()),
            Some("z:work")
        );
    }

    #[test]
    fn logger_default_matches_new() {
        let default_logger = super::E2eLogger::default();
        let new_logger = super::E2eLogger::new();
        assert_eq!(default_logger.entries().len(), new_logger.entries().len());
    }

    #[test]
    fn assertions_summary_zero_counts() {
        let summary = AssertionsSummary::new(0, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
    }
}
