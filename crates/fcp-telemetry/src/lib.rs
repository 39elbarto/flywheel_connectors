//! FCP Telemetry - Unified Metrics, Logging, and Tracing for FCP Connectors
//!
//! This crate provides comprehensive observability infrastructure for FCP connectors:
//!
//! - **Structured Logging**: JSON-formatted logs with automatic field injection
//! - **Metrics Collection**: Counters, gauges, histograms with Prometheus export
//! - **Distributed Tracing**: Span creation with W3C Trace Context propagation
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fcp_telemetry::{TelemetryConfig, init_telemetry};
//!
//! // Initialize with defaults
//! init_telemetry(TelemetryConfig::default())?;
//!
//! // Use tracing macros as normal
//! tracing::info!(connector_id = "my-connector", "Starting up");
//!
//! // Record metrics
//! fcp_telemetry::metrics::increment_counter("requests_total", &[("connector", "my-connector")]);
//! ```

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

mod context;
mod export;
mod logging;
pub mod metrics;
pub mod trace_capture;
mod tracing_layer;
mod usage;

pub use context::*;
pub use export::*;
pub use logging::*;
pub use usage::*;
// Re-export tracing_layer items explicitly to avoid TraceContext collision
// (we prefer context::TraceContext which is the proper W3C binary implementation)
pub use tracing_layer::{
    FcpSpan, SpanGuard, TRACEPARENT_HEADER, TRACESTATE_HEADER, extract_trace_context,
    inject_trace_context,
};
// Export the legacy string-based TraceContext under a distinct name
pub use tracing_layer::TraceContext as LegacyTraceContext;

use std::sync::OnceLock;

/// Global telemetry state.
static TELEMETRY: OnceLock<TelemetryState> = OnceLock::new();

/// Internal telemetry state.
struct TelemetryState {
    #[allow(dead_code)]
    config: TelemetryConfig,
}

/// Configuration for telemetry initialization.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service/connector name for identifying logs and metrics.
    pub service_name: String,

    /// Log level filter (e.g., "info", "debug", "trace").
    pub log_level: String,

    /// Enable JSON log output.
    pub json_logs: bool,

    /// Enable Prometheus metrics endpoint.
    pub prometheus_enabled: bool,

    /// Prometheus metrics endpoint port.
    pub prometheus_port: u16,

    /// Enable OTLP trace export.
    pub otlp_enabled: bool,

    /// OTLP endpoint URL.
    pub otlp_endpoint: Option<String>,

    /// Sample rate for tracing (0.0 to 1.0).
    pub trace_sample_rate: f64,

    /// Fields to redact from logs (sensitive data).
    pub redact_fields: Vec<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "fcp-connector".to_string(),
            log_level: "info".to_string(),
            json_logs: true,
            prometheus_enabled: false,
            prometheus_port: 9090,
            otlp_enabled: false,
            otlp_endpoint: None,
            trace_sample_rate: 1.0,
            redact_fields: vec![
                "password".to_string(),
                "api_key".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        }
    }
}

impl TelemetryConfig {
    /// Create a new configuration with the given service name.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Set the log level.
    #[must_use]
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Enable or disable JSON logs.
    #[must_use]
    pub const fn with_json_logs(mut self, enabled: bool) -> Self {
        self.json_logs = enabled;
        self
    }

    /// Enable Prometheus metrics on the given port.
    #[must_use]
    pub const fn with_prometheus(mut self, port: u16) -> Self {
        self.prometheus_enabled = true;
        self.prometheus_port = port;
        self
    }

    /// Enable OTLP trace export to the given endpoint.
    #[must_use]
    pub fn with_otlp(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_enabled = true;
        self.otlp_endpoint = Some(endpoint.into());
        self
    }

    /// Set the trace sampling rate (0.0 to 1.0).
    #[must_use]
    pub const fn with_sample_rate(mut self, rate: f64) -> Self {
        self.trace_sample_rate = rate;
        self
    }

    /// Add fields to redact from logs.
    #[must_use]
    pub fn with_redact_fields(mut self, fields: Vec<String>) -> Self {
        self.redact_fields.extend(fields);
        self
    }
}

/// Initialize the telemetry system.
///
/// This should be called once at application startup. Subsequent calls are no-ops.
///
/// # Errors
///
/// Returns an error if telemetry initialization fails.
pub fn init_telemetry(config: TelemetryConfig) -> Result<(), TelemetryError> {
    // Initialize logging
    init_logging(&config)?;

    // Initialize metrics if Prometheus enabled
    if config.prometheus_enabled {
        init_prometheus_exporter(config.prometheus_port)?;
    }

    // Initialize OTLP tracing if enabled
    if config.otlp_enabled {
        if let Some(ref endpoint) = config.otlp_endpoint {
            init_otlp_tracer(&config.service_name, endpoint)?;
        }
    }

    // Store config
    let _ = TELEMETRY.set(TelemetryState { config });

    Ok(())
}

/// Initialize telemetry synchronously (for simple use cases without OTLP).
///
/// # Errors
///
/// Returns an error if initialization fails.
pub fn init_telemetry_sync(config: TelemetryConfig) -> Result<(), TelemetryError> {
    if TELEMETRY.get().is_some() {
        return Ok(());
    }

    // Initialize logging
    init_logging(&config)?;

    // Initialize metrics if Prometheus enabled
    if config.prometheus_enabled {
        init_prometheus_exporter(config.prometheus_port)?;
    }

    // Store config
    let _ = TELEMETRY.set(TelemetryState { config });

    Ok(())
}

/// Telemetry error type.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// Failed to initialize logging.
    #[error("Failed to initialize logging: {0}")]
    LoggingInit(String),

    /// Failed to initialize metrics.
    #[error("Failed to initialize metrics: {0}")]
    MetricsInit(String),

    /// Failed to initialize tracing.
    #[error("Failed to initialize tracing: {0}")]
    TracingInit(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Shutdown telemetry gracefully.
///
/// This flushes any pending metrics and traces.
pub fn shutdown_telemetry() {
    // Shutdown OpenTelemetry if initialized
    opentelemetry::global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();

        assert_eq!(config.service_name, "fcp-connector");
        assert_eq!(config.log_level, "info");
        assert!(config.json_logs);
        assert!(!config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 9090);
        assert!(!config.otlp_enabled);
        assert!(config.otlp_endpoint.is_none());
        assert_eq!(config.trace_sample_rate, 1.0);
        assert!(!config.redact_fields.is_empty());
    }

    #[test]
    fn test_telemetry_config_new() {
        let config = TelemetryConfig::new("my-service");

        assert_eq!(config.service_name, "my-service");
        // Other fields should be defaults
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_telemetry_config_with_log_level() {
        let config = TelemetryConfig::new("test").with_log_level("debug");

        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_telemetry_config_with_json_logs_enabled() {
        let config = TelemetryConfig::new("test").with_json_logs(true);

        assert!(config.json_logs);
    }

    #[test]
    fn test_telemetry_config_with_json_logs_disabled() {
        let config = TelemetryConfig::new("test").with_json_logs(false);

        assert!(!config.json_logs);
    }

    #[test]
    fn test_telemetry_config_with_prometheus() {
        let config = TelemetryConfig::new("test").with_prometheus(8080);

        assert!(config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 8080);
    }

    #[test]
    fn test_telemetry_config_with_otlp() {
        let config = TelemetryConfig::new("test").with_otlp("http://localhost:4317");

        assert!(config.otlp_enabled);
        assert_eq!(
            config.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_with_sample_rate() {
        let config = TelemetryConfig::new("test").with_sample_rate(0.5);

        assert_eq!(config.trace_sample_rate, 0.5);
    }

    #[test]
    fn test_telemetry_config_with_redact_fields() {
        let config =
            TelemetryConfig::new("test").with_redact_fields(vec!["custom_secret".to_string()]);

        assert!(config.redact_fields.contains(&"custom_secret".to_string()));
        // Should also still have the default fields
        assert!(config.redact_fields.contains(&"password".to_string()));
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_builder_chain() {
        let config = TelemetryConfig::new("my-connector")
            .with_log_level("trace")
            .with_json_logs(true)
            .with_prometheus(9091)
            .with_otlp("http://collector:4317")
            .with_sample_rate(0.1)
            .with_redact_fields(vec!["api_secret".to_string()]);

        assert_eq!(config.service_name, "my-connector");
        assert_eq!(config.log_level, "trace");
        assert!(config.json_logs);
        assert!(config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 9091);
        assert!(config.otlp_enabled);
        assert_eq!(
            config.otlp_endpoint,
            Some("http://collector:4317".to_string())
        );
        assert_eq!(config.trace_sample_rate, 0.1);
        assert!(config.redact_fields.contains(&"api_secret".to_string()));
    }

    #[test]
    fn test_telemetry_config_debug() {
        let config = TelemetryConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("TelemetryConfig"));
        assert!(debug_str.contains("service_name"));
    }

    #[test]
    fn test_telemetry_config_clone() {
        let config = TelemetryConfig::new("test")
            .with_prometheus(8080)
            .with_log_level("debug");

        let cloned = config.clone();

        assert_eq!(config.service_name, cloned.service_name);
        assert_eq!(config.prometheus_port, cloned.prometheus_port);
        assert_eq!(config.log_level, cloned.log_level);
    }

    #[test]
    fn test_telemetry_error_logging_init() {
        let error = TelemetryError::LoggingInit("test error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Failed to initialize logging"));
        assert!(error_str.contains("test error"));
    }

    #[test]
    fn test_telemetry_error_metrics_init() {
        let error = TelemetryError::MetricsInit("metrics error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Failed to initialize metrics"));
        assert!(error_str.contains("metrics error"));
    }

    #[test]
    fn test_telemetry_error_tracing_init() {
        let error = TelemetryError::TracingInit("tracing error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Failed to initialize tracing"));
        assert!(error_str.contains("tracing error"));
    }

    #[test]
    fn test_telemetry_error_config() {
        let error = TelemetryError::Config("config error".to_string());
        let error_str = format!("{error}");

        assert!(error_str.contains("Configuration error"));
        assert!(error_str.contains("config error"));
    }

    #[test]
    fn test_telemetry_error_debug() {
        let error = TelemetryError::LoggingInit("debug test".to_string());
        let debug_str = format!("{error:?}");

        assert!(debug_str.contains("LoggingInit"));
    }

    #[test]
    fn test_default_redact_fields() {
        let config = TelemetryConfig::default();

        assert!(config.redact_fields.contains(&"password".to_string()));
        assert!(config.redact_fields.contains(&"api_key".to_string()));
        assert!(config.redact_fields.contains(&"secret".to_string()));
        assert!(config.redact_fields.contains(&"token".to_string()));
        assert!(config.redact_fields.contains(&"authorization".to_string()));
    }

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate bounds
    fn test_telemetry_config_sample_rate_bounds() {
        // Test edge cases for sample rate
        let config_zero = TelemetryConfig::new("test").with_sample_rate(0.0);
        assert_eq!(config_zero.trace_sample_rate, 0.0);

        let config_one = TelemetryConfig::new("test").with_sample_rate(1.0);
        assert_eq!(config_one.trace_sample_rate, 1.0);
    }
}
