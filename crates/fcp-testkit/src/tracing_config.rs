//! Tracing configuration for test output.
//!
//! Provides utilities for configuring tracing in tests with appropriate
//! output formatting and filtering.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, Once};

use fcp_conformance::schemas::{SchemaValidationError, validate_e2e_log_jsonl};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

static INIT: Once = Once::new();

/// Initialize tracing for tests.
///
/// This should be called at the start of each test or in a test setup function.
/// It's safe to call multiple times; only the first call will initialize tracing.
///
/// Uses the `RUST_LOG` environment variable if set, otherwise defaults to `info`.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::init_test_tracing;
///
/// #[fcp_async_core::runtime::test]
/// async fn my_test() {
///     init_test_tracing();
///     // ... test code
/// }
/// ```
pub fn init_test_tracing() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,fcp_testkit=debug"));

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_ansi(true)
                    .compact(),
            )
            .init();
    });
}

/// Initialize tracing with a specific filter.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::init_test_tracing_with_filter;
///
/// #[fcp_async_core::runtime::test]
/// async fn my_verbose_test() {
///     init_test_tracing_with_filter("debug");
///     // ... test code
/// }
/// ```
pub fn init_test_tracing_with_filter(filter: &str) {
    INIT.call_once(|| {
        let filter = EnvFilter::new(filter);

        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_test_writer()
                    .with_ansi(true)
                    .compact(),
            )
            .init();
    });
}

/// Initialize tracing with JSON output (useful for structured log analysis).
///
/// # Example
///
/// ```rust
/// use fcp_testkit::init_test_tracing_json;
///
/// #[fcp_async_core::runtime::test]
/// async fn my_test() {
///     init_test_tracing_json();
///     // ... test code
/// }
/// ```
pub fn init_test_tracing_json() {
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,fcp_testkit=debug"));

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_test_writer().json())
            .init();
    });
}

/// Initialize silent tracing (suppresses all output).
///
/// Useful for tests that intentionally trigger errors and don't want log noise.
pub fn init_test_tracing_silent() {
    INIT.call_once(|| {
        let filter = EnvFilter::new("off");

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_test_writer())
            .init();
    });
}

/// Guard that captures tracing events for assertion.
///
/// Note: This is a simplified implementation. For production use,
/// consider using `tracing-test` crate.
#[derive(Debug, Default)]
pub struct TracingCapture {
    events: std::sync::Arc<std::sync::Mutex<Vec<CapturedEvent>>>,
}

/// A captured tracing event.
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    /// Event level (trace, debug, info, warn, error)
    pub level: String,
    /// Event message
    pub message: String,
    /// Event target (module path)
    pub target: String,
}

impl TracingCapture {
    /// Create a new tracing capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all captured events.
    ///
    /// # Panics
    ///
    /// Panics if the capture mutex is poisoned.
    #[must_use]
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Check if any event contains the given message.
    ///
    /// # Panics
    ///
    /// Panics if the capture mutex is poisoned.
    #[must_use]
    pub fn contains(&self, message: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.message.contains(message))
    }

    /// Check if any error event was logged.
    ///
    /// # Panics
    ///
    /// Panics if the capture mutex is poisoned.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.level == "ERROR")
    }

    /// Check if any warning event was logged.
    ///
    /// # Panics
    ///
    /// Panics if the capture mutex is poisoned.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.level == "WARN")
    }

    /// Assert no errors were logged.
    ///
    /// # Panics
    ///
    /// Panics if any error events were captured.
    pub fn assert_no_errors(&self) {
        let errors: Vec<_> = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level == "ERROR")
            .cloned()
            .collect();

        assert!(
            errors.is_empty(),
            "Expected no errors but found: {errors:?}"
        );
    }

    /// Assert no warnings were logged.
    ///
    /// # Panics
    ///
    /// Panics if any warning events were captured.
    pub fn assert_no_warnings(&self) {
        let warnings: Vec<_> = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.level == "WARN")
            .cloned()
            .collect();

        assert!(
            warnings.is_empty(),
            "Expected no warnings but found: {warnings:?}"
        );
    }

    /// Clear all captured events.
    ///
    /// # Panics
    ///
    /// Panics if the capture mutex is poisoned.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

#[derive(Debug, Clone, Default)]
struct LogCaptureBuffer {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl LogCaptureBuffer {
    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn clear(&self) {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

struct LogCaptureWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for LogCaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCaptureBuffer {
    type Writer = LogCaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        Self::Writer {
            bytes: Arc::clone(&self.bytes),
        }
    }
}

/// Capture structured JSON logs and validate against the E2E schema.
#[derive(Debug, Clone, Default)]
pub struct LogCapture {
    buffer: LogCaptureBuffer,
}

impl LogCapture {
    /// Create a new log capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a JSON tracing subscriber that writes into this capture.
    ///
    /// Keep the returned guard alive for the duration of the capture.
    #[must_use]
    pub fn install_json(&self) -> tracing::subscriber::DefaultGuard {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        self.install_json_with_filter(filter)
    }

    /// Install a JSON tracing subscriber with a specific filter.
    ///
    /// Keep the returned guard alive for the duration of the capture.
    #[must_use]
    pub fn install_json_with_filter(
        &self,
        filter: impl Into<EnvFilter>,
    ) -> tracing::subscriber::DefaultGuard {
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(self.buffer.clone())
            .json()
            .with_ansi(false)
            .with_level(false)
            .with_target(false)
            .with_file(false)
            .with_line_number(false)
            .with_current_span(false)
            .flatten_event(true);

        let subscriber = tracing_subscriber::registry()
            .with(filter.into())
            .with(layer);
        tracing::subscriber::set_default(subscriber)
    }

    /// Return captured logs as JSONL.
    #[must_use]
    pub fn jsonl(&self) -> String {
        let bytes = self.buffer.snapshot();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Append a JSONL line directly into the capture.
    pub fn push_line(&self, line: &str) {
        let mut guard = self
            .buffer
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
        self.buffer.clear();
    }

    /// Validate the captured JSONL logs against the E2E schema.
    ///
    /// # Errors
    /// Returns a schema validation error if any entry is invalid.
    pub fn validate_jsonl(&self) -> Result<(), SchemaValidationError> {
        validate_e2e_log_jsonl(&self.jsonl())
    }

    /// Assert that captured JSONL logs validate against the schema.
    ///
    /// # Panics
    /// Panics if validation fails.
    pub fn assert_valid(&self) {
        self.validate_jsonl()
            .expect("expected JSONL logs to match the E2E schema");
    }
}

#[cfg(test)]
mod tests {
    use super::LogCapture;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn log_capture_validates_tracing_jsonl() {
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("info");

        tracing::info!(
            script = "e2e_test",
            step = "init",
            correlation_id = "00000000-0000-4000-8000-000000000000",
            duration_ms = 5_u64,
            result = "pass"
        );

        assert!(!capture.jsonl().trim().is_empty());
        capture.assert_valid();
    }

    #[test]
    fn log_capture_accepts_valid_entry() {
        let capture = LogCapture::new();
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": "log_capture_valid",
            "module": "fcp-testkit",
            "phase": "execute",
            "correlation_id": "00000000-0000-4000-8000-000000000000",
            "result": "pass",
            "duration_ms": 12,
            "assertions": { "passed": 1, "failed": 0 }
        });
        capture.push_value(&entry).expect("serialize log entry");
        capture.assert_valid();
    }

    #[test]
    fn log_capture_rejects_invalid_json() {
        let capture = LogCapture::new();
        capture.push_line("{invalid-json");
        let err = capture
            .validate_jsonl()
            .expect_err("invalid JSON should fail validation");
        let message = err.to_string();
        assert!(
            message.contains("line 1: invalid JSON"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn log_capture_rejects_missing_fields() {
        let capture = LogCapture::new();
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "result": "pass"
        });
        capture.push_value(&entry).expect("serialize log entry");
        let err = capture
            .validate_jsonl()
            .expect_err("missing fields should fail validation");
        let message = err.to_string();
        assert!(
            message.starts_with("line 1:"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn log_capture_reports_line_numbers_for_multiple_entries() {
        let capture = LogCapture::new();
        let valid = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": "log_capture_multi",
            "module": "fcp-testkit",
            "phase": "execute",
            "correlation_id": "00000000-0000-4000-8000-000000000000",
            "result": "pass",
            "duration_ms": 12,
            "assertions": { "passed": 1, "failed": 0 }
        });
        capture.push_value(&valid).expect("serialize log entry");
        capture.push_line("{invalid-json");

        let err = capture
            .validate_jsonl()
            .expect_err("invalid second line should fail validation");
        let message = err.to_string();
        assert!(
            message.contains("line 2: invalid JSON"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn log_capture_clear_resets_buffer() {
        let capture = LogCapture::new();
        capture.push_line("{invalid-json");
        capture.clear();
        capture
            .validate_jsonl()
            .expect("cleared buffer should validate");
    }

    #[test]
    fn tracing_capture_initially_empty() {
        let capture = super::TracingCapture::new();
        assert!(capture.events().is_empty());
        assert!(!capture.has_errors());
        assert!(!capture.has_warnings());
        assert!(!capture.contains("anything"));
    }

    #[test]
    fn tracing_capture_assert_no_errors_empty() {
        let capture = super::TracingCapture::new();
        capture.assert_no_errors(); // should not panic
    }

    #[test]
    fn tracing_capture_assert_no_warnings_empty() {
        let capture = super::TracingCapture::new();
        capture.assert_no_warnings(); // should not panic
    }

    #[test]
    fn tracing_capture_clear() {
        let capture = super::TracingCapture::new();
        capture.clear(); // should not panic on empty
        assert!(capture.events().is_empty());
    }

    #[test]
    fn tracing_capture_debug() {
        let capture = super::TracingCapture::new();
        let debug = format!("{capture:?}");
        assert!(debug.contains("TracingCapture"));
    }

    #[test]
    fn captured_event_clone() {
        let event = super::CapturedEvent {
            level: "INFO".to_string(),
            message: "test".to_string(),
            target: "module".to_string(),
        };
        let moved = event;
        assert_eq!(moved.level, "INFO");
        assert_eq!(moved.message, "test");
        assert_eq!(moved.target, "module");
    }

    #[test]
    fn captured_event_debug() {
        let event = super::CapturedEvent {
            level: "ERROR".to_string(),
            message: "bad thing".to_string(),
            target: "my_module".to_string(),
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("CapturedEvent"));
        assert!(debug.contains("ERROR"));
        assert!(debug.contains("bad thing"));
    }

    #[test]
    fn log_capture_jsonl_initially_empty() {
        let capture = LogCapture::new();
        assert!(capture.jsonl().is_empty());
    }

    #[test]
    fn log_capture_push_line_appends_newline() {
        let capture = LogCapture::new();
        capture.push_line(r#"{"a":1}"#);
        let jsonl = capture.jsonl();
        assert!(jsonl.ends_with('\n'));
        assert_eq!(jsonl.lines().count(), 1);
    }

    #[test]
    fn log_capture_push_multiple_lines() {
        let capture = LogCapture::new();
        capture.push_line(r#"{"a":1}"#);
        capture.push_line(r#"{"b":2}"#);
        let jsonl = capture.jsonl();
        assert_eq!(jsonl.lines().count(), 2);
    }

    #[test]
    fn log_capture_default_same_as_new() {
        let a = LogCapture::new();
        let b = LogCapture::default();
        assert!(a.jsonl().is_empty());
        assert!(b.jsonl().is_empty());
    }

    #[test]
    fn log_capture_clone() {
        let capture = LogCapture::new();
        capture.push_line(r#"{"test":true}"#);
        let cloned = capture.clone();
        // Clone shares the same Arc buffer
        assert_eq!(capture.jsonl(), cloned.jsonl());
    }

    // ---- Additional TracingCapture tests ----

    #[test]
    fn tracing_capture_default_is_empty() {
        let capture = super::TracingCapture::default();
        assert!(capture.events().is_empty());
        assert!(!capture.has_errors());
        assert!(!capture.has_warnings());
    }

    #[test]
    fn tracing_capture_contains_false_on_empty() {
        let capture = super::TracingCapture::new();
        assert!(!capture.contains("missing"));
        assert!(!capture.contains(""));
    }

    #[test]
    fn tracing_capture_clear_is_idempotent() {
        let capture = super::TracingCapture::new();
        capture.clear();
        capture.clear();
        assert!(capture.events().is_empty());
    }

    // ---- Additional CapturedEvent tests ----

    #[test]
    fn captured_event_clone_preserves_all_fields() {
        let event = super::CapturedEvent {
            level: "WARN".to_string(),
            message: "warning msg".to_string(),
            target: "my_target".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event.level, cloned.level);
        assert_eq!(event.message, cloned.message);
        assert_eq!(event.target, cloned.target);
    }

    #[test]
    fn captured_event_debug_contains_all_fields() {
        let event = super::CapturedEvent {
            level: "DEBUG".to_string(),
            message: "a debug message".to_string(),
            target: "some::target".to_string(),
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("DEBUG"));
        assert!(dbg.contains("a debug message"));
        assert!(dbg.contains("some::target"));
    }

    // ---- Additional LogCapture tests ----

    #[test]
    fn log_capture_push_value_produces_valid_json_line() {
        let capture = LogCapture::new();
        let val = json!({"key": "value", "num": 42});
        capture.push_value(&val).unwrap();
        let jsonl = capture.jsonl();
        let parsed: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        assert_eq!(parsed["key"], "value");
        assert_eq!(parsed["num"], 42);
    }

    #[test]
    fn log_capture_multiple_push_values() {
        let capture = LogCapture::new();
        for i in 0..5 {
            let val = json!({"index": i});
            capture.push_value(&val).unwrap();
        }
        let jsonl = capture.jsonl();
        assert_eq!(jsonl.lines().count(), 5);
    }

    #[test]
    fn log_capture_clear_then_push() {
        let capture = LogCapture::new();
        capture.push_line("first");
        capture.clear();
        assert!(capture.jsonl().is_empty());
        capture.push_line("second");
        assert_eq!(capture.jsonl().lines().count(), 1);
        assert!(capture.jsonl().contains("second"));
    }

    #[test]
    fn log_capture_debug_format() {
        let capture = LogCapture::new();
        let dbg = format!("{capture:?}");
        assert!(dbg.contains("LogCapture"));
    }

    #[test]
    fn log_capture_validate_empty_is_ok() {
        let capture = LogCapture::new();
        assert!(capture.validate_jsonl().is_ok());
    }

    #[test]
    fn log_capture_push_line_does_not_double_newline() {
        let capture = LogCapture::new();
        capture.push_line("line1");
        capture.push_line("line2");
        let raw = capture.jsonl();
        // Should not have double newlines
        assert!(!raw.contains("\n\n"));
    }

    // ---- Additional LogCapture validation tests ----

    #[test]
    fn log_capture_validate_multiple_valid_entries() {
        let capture = LogCapture::new();
        for i in 0..3 {
            let entry = json!({
                "timestamp": Utc::now().to_rfc3339(),
                "test_name": format!("test_{i}"),
                "module": "fcp-testkit",
                "phase": "execute",
                "correlation_id": "00000000-0000-4000-8000-000000000000",
                "result": "pass",
                "duration_ms": i,
                "assertions": { "passed": 1, "failed": 0 }
            });
            capture.push_value(&entry).unwrap();
        }
        capture.assert_valid();
    }

    #[test]
    fn log_capture_push_value_with_nested_objects() {
        let capture = LogCapture::new();
        let val = json!({
            "outer": {
                "inner": {
                    "deep": [1, 2, 3]
                }
            }
        });
        capture.push_value(&val).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(capture.jsonl().trim()).unwrap();
        assert_eq!(parsed["outer"]["inner"]["deep"][1], 2);
    }

    #[test]
    fn log_capture_push_value_null() {
        let capture = LogCapture::new();
        capture.push_value(&json!(null)).unwrap();
        let jsonl = capture.jsonl();
        assert_eq!(jsonl.trim(), "null");
    }

    #[test]
    fn log_capture_push_value_array() {
        let capture = LogCapture::new();
        capture.push_value(&json!([1, 2, 3])).unwrap();
        let jsonl = capture.jsonl();
        assert!(jsonl.contains("[1,2,3]"));
    }

    #[test]
    fn log_capture_clear_multiple_times() {
        let capture = LogCapture::new();
        capture.push_line("a");
        capture.clear();
        assert!(capture.jsonl().is_empty());
        capture.push_line("b");
        capture.clear();
        assert!(capture.jsonl().is_empty());
    }

    // ---- Additional TracingCapture tests ----

    #[test]
    fn tracing_capture_new_no_errors_no_warnings() {
        let capture = super::TracingCapture::new();
        capture.assert_no_errors();
        capture.assert_no_warnings();
    }

    #[test]
    fn tracing_capture_events_returns_empty_vec_initially() {
        let capture = super::TracingCapture::new();
        let events = capture.events();
        assert!(events.is_empty());
        assert_eq!(events.len(), 0);
    }

    // ---- CapturedEvent additional tests ----

    #[test]
    fn captured_event_various_levels() {
        for level in &["TRACE", "DEBUG", "INFO", "WARN", "ERROR"] {
            let event = super::CapturedEvent {
                level: level.to_string(),
                message: "test msg".to_string(),
                target: "test_target".to_string(),
            };
            assert_eq!(event.level, *level);
        }
    }

    #[test]
    fn captured_event_empty_message() {
        let event = super::CapturedEvent {
            level: "INFO".to_string(),
            message: String::new(),
            target: "t".to_string(),
        };
        assert!(event.message.is_empty());
    }

    #[test]
    fn captured_event_clone_independence() {
        let original = super::CapturedEvent {
            level: "WARN".to_string(),
            message: "original msg".to_string(),
            target: "orig".to_string(),
        };
        let cloned = original.clone();
        // Verify they are equal
        assert_eq!(original.level, cloned.level);
        assert_eq!(original.message, cloned.message);
        assert_eq!(original.target, cloned.target);
    }
}
