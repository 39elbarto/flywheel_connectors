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

use std::sync::{Mutex, OnceLock};

/// Global telemetry state.
static TELEMETRY: OnceLock<TelemetryState> = OnceLock::new();
static TELEMETRY_INIT_LOCK: Mutex<()> = Mutex::new(());

/// Internal telemetry state.
struct TelemetryState {
    #[allow(dead_code)]
    config: TelemetryConfig,
}

/// Compiled-in fallback for the Prometheus metrics endpoint port.
pub const DEFAULT_PROMETHEUS_PORT: u16 = 9090;

/// Environment variables checked for the Prometheus metrics endpoint port, in precedence order.
pub const PROMETHEUS_PORT_ENV_VARS: [&str; 4] = [
    "FCP_TELEMETRY_PROMETHEUS_PORT",
    "FCP_TELEMETRY_PORT",
    "FCP_PROMETHEUS_PORT",
    "PROMETHEUS_PORT",
];

fn resolve_prometheus_port() -> u16 {
    resolve_prometheus_port_with(|key| std::env::var(key).ok())
}

fn resolve_prometheus_port_with<F>(mut get_env: F) -> u16
where
    F: FnMut(&str) -> Option<String>,
{
    for key in PROMETHEUS_PORT_ENV_VARS {
        let Some(value) = get_env(key) else {
            continue;
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(port) = trimmed.parse::<u16>() {
            return port;
        }
    }
    DEFAULT_PROMETHEUS_PORT
}

/// Configuration for telemetry initialization.
///
/// The Prometheus metrics port can be overridden at startup via, in precedence order:
/// `FCP_TELEMETRY_PROMETHEUS_PORT`, `FCP_TELEMETRY_PORT`, `FCP_PROMETHEUS_PORT`,
/// or `PROMETHEUS_PORT`.
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
            prometheus_port: resolve_prometheus_port(),
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

/// Return the currently initialized telemetry configuration, if telemetry has already started.
#[must_use]
pub fn current_telemetry_config() -> Option<&'static TelemetryConfig> {
    TELEMETRY.get().map(|state| &state.config)
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

fn init_telemetry_with<L, P, O>(
    state: &OnceLock<TelemetryState>,
    config: TelemetryConfig,
    otlp_enabled: bool,
    init_logging_fn: L,
    init_prometheus_fn: P,
    init_otlp_fn: O,
) -> Result<(), TelemetryError>
where
    L: Fn(&TelemetryConfig) -> Result<(), TelemetryError>,
    P: Fn(u16) -> Result<(), TelemetryError>,
    O: Fn(&str, &str, f64) -> Result<(), TelemetryError>,
{
    if state.get().is_some() {
        return Ok(());
    }

    let _guard = TELEMETRY_INIT_LOCK
        .lock()
        .map_err(|_| TelemetryError::Config("telemetry init lock poisoned".to_string()))?;

    if state.get().is_some() {
        return Ok(());
    }

    init_logging_fn(&config)?;

    if config.prometheus_enabled {
        init_prometheus_fn(config.prometheus_port)?;
    }

    if otlp_enabled && config.otlp_enabled {
        if let Some(ref endpoint) = config.otlp_endpoint {
            // Thread the operator-configured sample rate through to the
            // SDK so `with_sample_rate(0.01)` actually results in a 1%
            // sampling rate rather than silently exporting 100% of
            // spans. Prior behavior silently dropped the rate on the
            // floor and used Sampler::AlwaysOn unconditionally.
            init_otlp_fn(
                &config.service_name,
                endpoint,
                config.trace_sample_rate,
            )?;
        }
    }

    let _ = state.set(TelemetryState { config });

    Ok(())
}

/// Initialize the telemetry system.
///
/// This should be called once at application startup. Subsequent calls are no-ops.
///
/// # Errors
///
/// Returns an error if telemetry initialization fails.
pub fn init_telemetry(config: TelemetryConfig) -> Result<(), TelemetryError> {
    init_telemetry_with(
        &TELEMETRY,
        config,
        true,
        init_logging,
        init_prometheus_exporter,
        init_otlp_tracer_with_sample_rate,
    )
}

/// Initialize telemetry synchronously (for simple use cases without OTLP).
///
/// # Errors
///
/// Returns an error if initialization fails.
pub fn init_telemetry_sync(config: TelemetryConfig) -> Result<(), TelemetryError> {
    init_telemetry_with(
        &TELEMETRY,
        config,
        false,
        init_logging,
        init_prometheus_exporter,
        init_otlp_tracer_with_sample_rate,
    )
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
/// Note: In opentelemetry 0.31+, shutdown is handled by the `SdkTracerProvider`
/// directly. Call `.shutdown()` on the provider instance returned by `init_otlp_tracer`
/// if you need explicit flush behavior.
pub fn shutdown_telemetry() {
    tracing::info!("Telemetry shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    #[allow(clippy::float_cmp)] // exact float comparison is safe for sample rate
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();

        assert_eq!(config.service_name, "fcp-connector");
        assert_eq!(config.log_level, "info");
        assert!(config.json_logs);
        assert!(!config.prometheus_enabled);
        assert_eq!(config.prometheus_port, DEFAULT_PROMETHEUS_PORT);
        assert!(!config.otlp_enabled);
        assert!(config.otlp_endpoint.is_none());
        assert_eq!(config.trace_sample_rate, 1.0);
        assert!(!config.redact_fields.is_empty());
    }

    #[test]
    fn test_resolve_prometheus_port_uses_first_valid_env_var() {
        let resolved = resolve_prometheus_port_with(|key| match key {
            "FCP_TELEMETRY_PROMETHEUS_PORT" => Some("9200".to_string()),
            "FCP_TELEMETRY_PORT" => Some("9300".to_string()),
            _ => None,
        });

        assert_eq!(resolved, 9200);
    }

    #[test]
    fn test_resolve_prometheus_port_falls_back_to_lower_priority_env_var() {
        let resolved = resolve_prometheus_port_with(|key| match key {
            "FCP_TELEMETRY_PROMETHEUS_PORT" => Some("not-a-port".to_string()),
            "FCP_TELEMETRY_PORT" => Some("   ".to_string()),
            "FCP_PROMETHEUS_PORT" => Some("9400".to_string()),
            _ => None,
        });

        assert_eq!(resolved, 9400);
    }

    #[test]
    fn test_resolve_prometheus_port_uses_compiled_default_when_no_env_is_valid() {
        let resolved = resolve_prometheus_port_with(|key| match key {
            "FCP_TELEMETRY_PROMETHEUS_PORT" => Some("70000".to_string()),
            "PROMETHEUS_PORT" => Some("invalid".to_string()),
            _ => None,
        });

        assert_eq!(resolved, DEFAULT_PROMETHEUS_PORT);
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

    #[test]
    fn test_telemetry_config_new_from_string() {
        let name = String::from("dynamic-service");
        let config = TelemetryConfig::new(name);
        assert_eq!(config.service_name, "dynamic-service");
    }

    #[test]
    fn test_telemetry_config_with_log_level_from_string() {
        let level = String::from("warn");
        let config = TelemetryConfig::new("test").with_log_level(level);
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn test_telemetry_config_with_otlp_from_string() {
        let endpoint = String::from("http://otel:4317");
        let config = TelemetryConfig::new("test").with_otlp(endpoint);
        assert!(config.otlp_enabled);
        assert_eq!(config.otlp_endpoint, Some("http://otel:4317".to_string()));
    }

    #[test]
    fn test_telemetry_config_default_otlp_disabled() {
        let config = TelemetryConfig::default();
        assert!(!config.otlp_enabled);
        assert!(config.otlp_endpoint.is_none());
    }

    #[test]
    fn test_telemetry_config_redact_fields_extend() {
        let config = TelemetryConfig::new("test")
            .with_redact_fields(vec!["field_a".to_string()])
            .with_redact_fields(vec!["field_b".to_string()]);
        assert!(config.redact_fields.contains(&"field_a".to_string()));
        assert!(config.redact_fields.contains(&"field_b".to_string()));
        // Original defaults should still be present
        assert!(config.redact_fields.contains(&"password".to_string()));
    }

    #[test]
    fn test_telemetry_config_default_redact_count() {
        let config = TelemetryConfig::default();
        assert_eq!(config.redact_fields.len(), 5);
    }

    #[test]
    fn test_telemetry_config_clone_independence() {
        let config = TelemetryConfig::new("original").with_prometheus(8080);
        let mut cloned = config.clone();
        cloned.service_name = "modified".to_string();
        // Original should not be affected
        assert_eq!(config.service_name, "original");
    }

    #[test]
    fn test_telemetry_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TelemetryError::Config("test".to_string()));
        assert!(err.to_string().contains("Configuration error"));
    }

    #[test]
    fn test_telemetry_error_debug_all_variants() {
        let variants: Vec<TelemetryError> = vec![
            TelemetryError::LoggingInit("a".to_string()),
            TelemetryError::MetricsInit("b".to_string()),
            TelemetryError::TracingInit("c".to_string()),
            TelemetryError::Config("d".to_string()),
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn test_telemetry_config_empty_service_name() {
        let config = TelemetryConfig::new("");
        assert_eq!(config.service_name, "");
    }

    #[test]
    fn test_telemetry_config_unicode_service_name() {
        let config = TelemetryConfig::new("service-日本語");
        assert_eq!(config.service_name, "service-日本語");
    }

    #[test]
    fn test_shutdown_telemetry_no_panic() {
        // Shutdown should never panic even without init
        shutdown_telemetry();
    }

    #[test]
    fn test_init_telemetry_with_is_idempotent() {
        let state = OnceLock::new();
        let logging_calls = AtomicUsize::new(0);
        let prometheus_calls = AtomicUsize::new(0);
        let otlp_calls = AtomicUsize::new(0);

        let config = TelemetryConfig::new("test-service")
            .with_prometheus(9091)
            .with_otlp("http://collector:4317");

        init_telemetry_with(
            &state,
            config.clone(),
            true,
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| {
                prometheus_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _| {
                otlp_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        init_telemetry_with(
            &state,
            config,
            true,
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| {
                prometheus_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_, _, _| {
                otlp_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(logging_calls.load(Ordering::SeqCst), 1);
        assert_eq!(prometheus_calls.load(Ordering::SeqCst), 1);
        assert_eq!(otlp_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.get().unwrap().config.service_name,
            "test-service".to_string()
        );
    }

    #[test]
    fn test_init_telemetry_with_failed_attempt_can_retry() {
        let state = OnceLock::new();
        let logging_calls = AtomicUsize::new(0);

        let first = init_telemetry_with(
            &state,
            TelemetryConfig::new("first-attempt"),
            true,
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Err(TelemetryError::LoggingInit("boom".to_string()))
            },
            |_| Ok(()),
            |_, _, _| Ok(()),
        );

        assert!(matches!(first, Err(TelemetryError::LoggingInit(_))));
        assert!(state.get().is_none());

        init_telemetry_with(
            &state,
            TelemetryConfig::new("second-attempt"),
            true,
            |_| {
                logging_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            |_| Ok(()),
            |_, _, _| Ok(()),
        )
        .unwrap();

        assert_eq!(logging_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            state.get().unwrap().config.service_name,
            "second-attempt".to_string()
        );
    }

    /// Regression for the silently-ignored sample rate: whatever the
    /// operator configures via `with_sample_rate` MUST reach the OTLP
    /// init function, not get dropped by `init_telemetry_with`. Prior
    /// behavior threaded only (service_name, endpoint) through, so the
    /// SDK sampler was `AlwaysOn` regardless of config.
    #[test]
    #[allow(clippy::float_cmp)]
    fn test_init_telemetry_threads_sample_rate_to_otlp() {
        let state = OnceLock::new();
        let captured_rate: std::sync::Mutex<Option<f64>> = std::sync::Mutex::new(None);

        init_telemetry_with(
            &state,
            TelemetryConfig::new("sample-rate-test")
                .with_otlp("http://collector:4317")
                .with_sample_rate(0.05),
            true,
            |_| Ok(()),
            |_| Ok(()),
            |_, _, rate| {
                *captured_rate.lock().expect("lock") = Some(rate);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            *captured_rate.lock().expect("lock"),
            Some(0.05),
            "configured sample rate must reach the OTLP initializer",
        );
    }

    #[test]
    fn test_init_telemetry_sync_skips_otlp_side_effects() {
        let state = OnceLock::new();
        let otlp_calls = AtomicUsize::new(0);

        init_telemetry_with(
            &state,
            TelemetryConfig::new("sync").with_otlp("http://collector:4317"),
            false,
            |_| Ok(()),
            |_| Ok(()),
            |_, _, _| {
                otlp_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(otlp_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_telemetry_config_with_prometheus_default_port() {
        let config = TelemetryConfig::new("test").with_prometheus(0);
        assert!(config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 0);
    }

    #[test]
    fn test_telemetry_config_with_prometheus_max_port() {
        let config = TelemetryConfig::new("test").with_prometheus(u16::MAX);
        assert_eq!(config.prometheus_port, u16::MAX);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_telemetry_config_sample_rate_negative() {
        // Negative sample rate should be stored as-is (validation is caller's responsibility)
        let config = TelemetryConfig::new("test").with_sample_rate(-1.0);
        assert_eq!(config.trace_sample_rate, -1.0);
    }

    #[test]
    fn test_telemetry_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TelemetryError>();
    }

    #[test]
    fn test_telemetry_config_long_service_name() {
        let long_name = "a".repeat(1000);
        let config = TelemetryConfig::new(&long_name);
        assert_eq!(config.service_name.len(), 1000);
    }

    #[test]
    fn test_telemetry_config_with_empty_redact_fields() {
        let config = TelemetryConfig::new("test").with_redact_fields(vec![]);
        // Original defaults should still be present
        assert_eq!(config.redact_fields.len(), 5);
    }

    #[test]
    fn test_telemetry_config_with_otlp_empty_endpoint() {
        let config = TelemetryConfig::new("test").with_otlp("");
        assert!(config.otlp_enabled);
        assert_eq!(config.otlp_endpoint, Some(String::new()));
    }

    #[test]
    fn test_telemetry_error_display_long_message() {
        let long_msg = "x".repeat(500);
        let error = TelemetryError::Config(long_msg.clone());
        let display = format!("{error}");
        assert!(display.contains(&long_msg));
    }

    #[test]
    fn test_telemetry_error_source_is_none() {
        let error = TelemetryError::LoggingInit("test".to_string());
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn test_telemetry_config_debug_contains_all_fields() {
        let config = TelemetryConfig::new("svc")
            .with_log_level("debug")
            .with_prometheus(DEFAULT_PROMETHEUS_PORT)
            .with_otlp("http://otel:4317")
            .with_sample_rate(0.5);
        let debug = format!("{config:?}");
        assert!(debug.contains("svc"));
        assert!(debug.contains("debug"));
        assert!(debug.contains(&DEFAULT_PROMETHEUS_PORT.to_string()));
        assert!(debug.contains("otel"));
    }
}
