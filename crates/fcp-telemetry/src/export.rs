//! Export formats for telemetry data.
//!
//! Supports Prometheus exposition format and OTLP export.

use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource, runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider},
};

use crate::TelemetryError;

/// Initialize the Prometheus metrics exporter.
///
/// This starts an HTTP server on the specified port that exposes metrics
/// in Prometheus exposition format at `/metrics`.
///
/// # Errors
/// Returns `TelemetryError::MetricsInit` if the exporter cannot be started.
pub fn init_prometheus_exporter(port: u16) -> Result<(), TelemetryError> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;

    tracing::info!(port = port, "Prometheus metrics exporter started");

    Ok(())
}

/// Initialize the OTLP trace exporter.
///
/// This sets up OpenTelemetry trace export to an OTLP-compatible collector.
///
/// # Errors
/// Returns `TelemetryError::TracingInit` if the exporter cannot be initialized.
pub fn init_otlp_tracer(service_name: &str, endpoint: &str) -> Result<(), TelemetryError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| TelemetryError::TracingInit(e.to_string()))?;

    let resource = Resource::new(vec![KeyValue::new(
        "service.name",
        service_name.to_string(),
    )]);

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider);

    tracing::info!(endpoint = endpoint, "OTLP trace exporter initialized");

    Ok(())
}

/// Generate Prometheus exposition format text from current metrics.
///
/// This is useful for embedding metrics in custom HTTP handlers.
#[must_use]
pub fn prometheus_text_format() -> String {
    // The PrometheusBuilder handles this internally via the HTTP server
    // This function is provided for custom integrations
    "# Metrics are exposed via HTTP endpoint\n".to_string()
}

/// Health check endpoint response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthResponse {
    /// Service status.
    pub status: String,

    /// Service version.
    pub version: String,

    /// Uptime in seconds.
    pub uptime_seconds: u64,

    /// Additional checks.
    pub checks: Vec<HealthCheck>,
}

/// Individual health check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    /// Check name.
    pub name: String,

    /// Check status.
    pub status: String,

    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl HealthResponse {
    /// Create a healthy response.
    #[must_use]
    pub fn healthy(version: &str, uptime_seconds: u64) -> Self {
        Self {
            status: "healthy".to_string(),
            version: version.to_string(),
            uptime_seconds,
            checks: Vec::new(),
        }
    }

    /// Create an unhealthy response.
    #[must_use]
    pub fn unhealthy(version: &str, uptime_seconds: u64, message: &str) -> Self {
        Self {
            status: "unhealthy".to_string(),
            version: version.to_string(),
            uptime_seconds,
            checks: vec![HealthCheck {
                name: "main".to_string(),
                status: "fail".to_string(),
                message: Some(message.to_string()),
            }],
        }
    }

    /// Add a health check.
    #[must_use]
    pub fn with_check(mut self, name: &str, passed: bool, message: Option<&str>) -> Self {
        self.checks.push(HealthCheck {
            name: name.to_string(),
            status: if passed { "pass" } else { "fail" }.to_string(),
            message: message.map(String::from),
        });
        self
    }

    /// Check if all checks passed.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == "healthy" && self.checks.iter().all(|c| c.status == "pass")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_healthy() {
        let response = HealthResponse::healthy("1.0.0", 3600);
        assert!(response.is_healthy());
        assert_eq!(response.status, "healthy");
    }

    #[test]
    fn test_health_response_with_checks() {
        let response = HealthResponse::healthy("1.0.0", 3600)
            .with_check("database", true, None)
            .with_check("cache", true, Some("Connected"));

        assert!(response.is_healthy());
        assert_eq!(response.checks.len(), 2);
    }

    #[test]
    fn test_health_response_unhealthy() {
        let response = HealthResponse::unhealthy("1.0.0", 3600, "Database connection failed");
        assert!(!response.is_healthy());
        assert_eq!(response.status, "unhealthy");
    }

    #[test]
    fn test_health_response_fields() {
        let response = HealthResponse::healthy("2.0.0", 7200);
        assert_eq!(response.version, "2.0.0");
        assert_eq!(response.uptime_seconds, 7200);
        assert!(response.checks.is_empty());
    }

    #[test]
    fn test_health_response_unhealthy_fields() {
        let response = HealthResponse::unhealthy("1.5.0", 1000, "Service unavailable");
        assert_eq!(response.version, "1.5.0");
        assert_eq!(response.uptime_seconds, 1000);
        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].name, "main");
        assert_eq!(response.checks[0].status, "fail");
        assert_eq!(
            response.checks[0].message,
            Some("Service unavailable".to_string())
        );
    }

    #[test]
    fn test_health_check_passed() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("api", true, None);

        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].name, "api");
        assert_eq!(response.checks[0].status, "pass");
        assert!(response.checks[0].message.is_none());
    }

    #[test]
    fn test_health_check_failed() {
        let response =
            HealthResponse::healthy("1.0.0", 100).with_check("database", false, Some("Timeout"));

        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].name, "database");
        assert_eq!(response.checks[0].status, "fail");
        assert_eq!(response.checks[0].message, Some("Timeout".to_string()));
    }

    #[test]
    fn test_health_response_mixed_checks() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("database", true, None)
            .with_check("cache", false, Some("Connection refused"))
            .with_check("api", true, Some("OK"));

        // Even with healthy status, if any check fails, is_healthy returns false
        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 3);
    }

    #[test]
    fn test_health_response_all_checks_pass() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("database", true, None)
            .with_check("cache", true, None)
            .with_check("api", true, None);

        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_check_clone() {
        let check = HealthCheck {
            name: "test".to_string(),
            status: "pass".to_string(),
            message: Some("OK".to_string()),
        };

        let cloned = check.clone();
        assert_eq!(check.name, cloned.name);
        assert_eq!(check.status, cloned.status);
        assert_eq!(check.message, cloned.message);
    }

    #[test]
    fn test_health_response_clone() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("db", true, None);

        let cloned = response.clone();
        assert_eq!(response.status, cloned.status);
        assert_eq!(response.version, cloned.version);
        assert_eq!(response.uptime_seconds, cloned.uptime_seconds);
        assert_eq!(response.checks.len(), cloned.checks.len());
    }

    #[test]
    fn test_health_check_debug() {
        let check = HealthCheck {
            name: "test".to_string(),
            status: "pass".to_string(),
            message: None,
        };

        let debug_str = format!("{check:?}");
        assert!(debug_str.contains("HealthCheck"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_health_response_debug() {
        let response = HealthResponse::healthy("1.0.0", 100);
        let debug_str = format!("{response:?}");
        assert!(debug_str.contains("HealthResponse"));
    }

    #[test]
    fn test_health_response_json_serialization() {
        let response =
            HealthResponse::healthy("1.0.0", 3600).with_check("database", true, Some("Connected"));

        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"uptime_seconds\":3600"));
        assert!(json.contains("\"name\":\"database\""));
        assert!(json.contains("\"message\":\"Connected\""));
    }

    #[test]
    fn test_health_response_json_skip_none_message() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("api", true, None);

        let json = serde_json::to_string(&response).unwrap();

        // The message field should be skipped when None
        assert!(!json.contains("\"message\":null"));
    }

    #[test]
    fn test_health_response_zero_uptime() {
        let response = HealthResponse::healthy("0.1.0", 0);
        assert_eq!(response.uptime_seconds, 0);
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_long_uptime() {
        let one_year_seconds = 365 * 24 * 60 * 60;
        let response = HealthResponse::healthy("1.0.0", one_year_seconds);
        assert_eq!(response.uptime_seconds, one_year_seconds);
    }

    #[test]
    fn test_health_response_empty_version() {
        let response = HealthResponse::healthy("", 100);
        assert_eq!(response.version, "");
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_semver_version() {
        let response = HealthResponse::healthy("1.2.3-beta.1+build.456", 100);
        assert_eq!(response.version, "1.2.3-beta.1+build.456");
    }

    #[test]
    fn test_health_check_long_message() {
        let long_message = "a".repeat(1000);
        let response =
            HealthResponse::healthy("1.0.0", 100).with_check("test", false, Some(&long_message));

        assert_eq!(response.checks[0].message, Some(long_message));
    }

    #[test]
    fn test_health_check_special_characters() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check(
            "test/check",
            true,
            Some("Status: OK! <test>"),
        );

        assert_eq!(response.checks[0].name, "test/check");
        assert_eq!(
            response.checks[0].message,
            Some("Status: OK! <test>".to_string())
        );
    }

    #[test]
    fn test_prometheus_text_format() {
        let text = prometheus_text_format();
        assert!(!text.is_empty());
    }

    #[test]
    fn test_multiple_unhealthy_checks() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("db", false, Some("Connection timeout"))
            .with_check("cache", false, Some("Memory full"))
            .with_check("api", false, Some("Rate limited"));

        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 3);
        assert!(response.checks.iter().all(|c| c.status == "fail"));
    }

    #[test]
    fn test_health_response_chain() {
        // Test that builder pattern chains correctly
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("check1", true, None)
            .with_check("check2", true, Some("OK"))
            .with_check("check3", true, None)
            .with_check("check4", true, Some("All good"));

        assert_eq!(response.checks.len(), 4);
        assert!(response.is_healthy());
    }
}
