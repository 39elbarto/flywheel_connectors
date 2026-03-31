use std::sync::{Arc, Mutex};

use crate::schemas::{SchemaValidationError, validate_e2e_log_jsonl};

/// Minimal JSONL capture for conformance-owned schema validation tests.
#[derive(Clone, Default)]
pub struct LogCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    /// Create a new log capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return captured logs as JSONL.
    #[must_use]
    pub fn jsonl(&self) -> String {
        let guard = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&guard).into_owned()
    }

    /// Append a JSONL line directly into the capture.
    pub fn push_line(&self, line: &str) {
        let mut guard = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.extend_from_slice(line.as_bytes());
        guard.push(b'\n');
    }

    /// Append a JSON value as a JSONL line.
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the value cannot be encoded.
    pub fn push_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error> {
        let line = serde_json::to_string(value)?;
        self.push_line(&line);
        Ok(())
    }

    /// Clear captured logs.
    pub fn clear(&self) {
        let mut guard = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.clear();
    }

    /// Validate the captured JSONL logs against the E2E schema.
    ///
    /// # Errors
    ///
    /// Returns a schema validation error if any entry is invalid.
    pub fn validate_jsonl(&self) -> Result<(), SchemaValidationError> {
        validate_e2e_log_jsonl(&self.jsonl())
    }

    /// Assert that captured JSONL logs validate against the schema.
    ///
    /// # Panics
    ///
    /// Panics if validation fails.
    pub fn assert_valid(&self) {
        self.validate_jsonl()
            .expect("expected JSONL logs to match the E2E schema");
    }
}
