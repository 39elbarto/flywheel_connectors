//! Export formats for telemetry data.
//!
//! Supports Prometheus exposition format and OTLP export.

use std::{
    io::{self, BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::OnceLock,
    thread,
};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};

use crate::TelemetryError;

static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the Prometheus metrics exporter.
///
/// This starts an HTTP server on the specified port that exposes metrics
/// in Prometheus exposition format at `/metrics`.
///
/// # Errors
/// Returns `TelemetryError::MetricsInit` if the exporter cannot be started.
pub fn init_prometheus_exporter(port: u16) -> Result<(), TelemetryError> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener =
        TcpListener::bind(addr).map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;
    let server_handle = handle.clone();
    thread::Builder::new()
        .name(format!("fcp-telemetry-prometheus-{port}"))
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if let Err(error) = serve_prometheus_connection(stream, &server_handle) {
                            tracing::warn!(?error, "Prometheus scrape failed");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(?error, "Prometheus listener accept failed");
                    }
                }
            }
        })
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;

    let _ = PROMETHEUS_HANDLE.set(handle);

    tracing::info!(port = port, "Prometheus metrics exporter started");

    Ok(())
}

/// Initialize the OTLP trace exporter with a fixed `AlwaysOn` sampler.
///
/// Kept for backward compatibility. New callers should use
/// [`init_otlp_tracer_with_sample_rate`] so the
/// [`TelemetryConfig::trace_sample_rate`](crate::TelemetryConfig::trace_sample_rate)
/// actually reaches the SDK. Historically this function ignored the
/// configured sample rate entirely, so a service configured with
/// `with_sample_rate(0.01)` still exported 100% of spans — the opposite
/// of what the operator asked for, and a material cost/PII-volume
/// regression on hot paths.
///
/// # Errors
/// Returns `TelemetryError::TracingInit` if the exporter cannot be initialized.
pub fn init_otlp_tracer(service_name: &str, endpoint: &str) -> Result<(), TelemetryError> {
    init_otlp_tracer_with_sample_rate(service_name, endpoint, 1.0)
}

/// Initialize the OTLP trace exporter with a configurable head-sampling rate.
///
/// `sample_rate` is clamped to `[0.0, 1.0]`. The sampler honors upstream
/// sampling decisions carried in `traceparent` (parent-based wrapper),
/// so a service behaving as a downstream node follows whatever the
/// edge decided rather than re-rolling the dice per hop.
///
/// Special-cases:
/// * rate >= 1.0 → `Sampler::AlwaysOn` (no per-span RNG, matches the
///   historical default).
/// * rate <= 0.0 → `Sampler::AlwaysOff` (exports nothing; local spans
///   still run but no OTLP traffic is generated).
/// * otherwise → `ParentBased(TraceIdRatioBased(rate))`.
///
/// # Errors
/// Returns `TelemetryError::TracingInit` if the exporter cannot be initialized.
pub fn init_otlp_tracer_with_sample_rate(
    service_name: &str,
    endpoint: &str,
    sample_rate: f64,
) -> Result<(), TelemetryError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| TelemetryError::TracingInit(e.to_string()))?;

    let resource = Resource::builder_empty()
        .with_attributes([KeyValue::new("service.name", service_name.to_string())])
        .build();

    // NaN maps to AlwaysOff (clamp + compare: NaN != NaN so both
    // `>= 1.0` and `<= 0.0` are false, but we want fail-safe behavior
    // — an insane input must not silently default to AlwaysOn).
    let clamped = if sample_rate.is_nan() {
        0.0
    } else {
        sample_rate.clamp(0.0, 1.0)
    };
    let sampler = if clamped >= 1.0 {
        Sampler::AlwaysOn
    } else if clamped <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(clamped)))
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider);

    tracing::info!(
        endpoint = endpoint,
        sample_rate = clamped,
        "OTLP trace exporter initialized"
    );

    Ok(())
}

fn render_prometheus_handle(handle: &PrometheusHandle) -> String {
    handle.run_upkeep();
    handle.render()
}

fn serve_prometheus_connection(mut stream: TcpStream, handle: &PrometheusHandle) -> io::Result<()> {
    let request_line = {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line
    };

    let (status_line, content_type, body) = if request_line.starts_with("GET /metrics ") {
        (
            "HTTP/1.1 200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_prometheus_handle(handle),
        )
    } else {
        (
            "HTTP/1.1 404 Not Found",
            "text/plain; charset=utf-8",
            "Not Found\n".to_string(),
        )
    };

    write!(
        stream,
        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

/// Generate Prometheus exposition format text from current metrics.
///
/// This is useful for embedding metrics in custom HTTP handlers after
/// [`init_prometheus_exporter`] has installed a recorder.
#[must_use]
pub fn prometheus_text_format() -> String {
    PROMETHEUS_HANDLE.get().map_or_else(
        || {
            "# Prometheus exporter not initialized; call init_prometheus_exporter first\n"
                .to_string()
        },
        render_prometheus_handle,
    )
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
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use metrics::{Key, Recorder};

    static METADATA: metrics::Metadata =
        metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!()));

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
    fn test_render_prometheus_handle_smoke() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let counter = recorder.register_counter(&Key::from_name("fcp_test_counter"), &METADATA);
        counter.increment(3);

        let rendered = render_prometheus_handle(&recorder.handle());
        assert!(rendered.contains("# TYPE fcp_test_counter counter"));
        assert!(rendered.contains("fcp_test_counter 3"));
    }

    #[test]
    fn test_prometheus_http_scrape_smoke() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let counter = recorder.register_counter(&Key::from_name("fcp_http_counter"), &METADATA);
        counter.increment(7);

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_prometheus_connection(stream, &handle).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.contains("# TYPE fcp_http_counter counter"));
        assert!(response.contains("fcp_http_counter 7"));
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

    #[test]
    fn test_health_response_json_value() {
        let response =
            HealthResponse::healthy("2.0.0", 500).with_check("db", true, Some("connected"));
        let val: serde_json::Value = serde_json::to_value(&response).unwrap();
        assert_eq!(val["status"], "healthy");
        assert_eq!(val["version"], "2.0.0");
        assert_eq!(val["uptime_seconds"], 500);
        assert_eq!(val["checks"][0]["name"], "db");
        assert_eq!(val["checks"][0]["status"], "pass");
        assert_eq!(val["checks"][0]["message"], "connected");
    }

    #[test]
    fn test_health_response_unhealthy_check_message() {
        let response = HealthResponse::unhealthy("1.0.0", 0, "boot failure");
        assert_eq!(response.checks.len(), 1);
        assert_eq!(response.checks[0].message, Some("boot failure".to_string()));
        assert_eq!(response.checks[0].name, "main");
    }

    #[test]
    fn test_health_response_unhealthy_is_not_healthy() {
        let response =
            HealthResponse::unhealthy("1.0.0", 100, "down").with_check("api", true, None);
        // status is unhealthy so overall is_healthy is false
        assert!(!response.is_healthy());
    }

    #[test]
    fn test_health_check_no_message_debug() {
        let check = HealthCheck {
            name: "api".to_string(),
            status: "pass".to_string(),
            message: None,
        };
        let debug = format!("{check:?}");
        assert!(debug.contains("None"));
    }

    #[test]
    fn test_health_response_many_checks() {
        let mut response = HealthResponse::healthy("1.0.0", 100);
        for i in 0..50 {
            response = response.with_check(&format!("check_{i}"), true, None);
        }
        assert_eq!(response.checks.len(), 50);
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_max_uptime() {
        let response = HealthResponse::healthy("1.0.0", u64::MAX);
        assert_eq!(response.uptime_seconds, u64::MAX);
    }

    #[test]
    fn test_health_check_clone_independence() {
        let check = HealthCheck {
            name: "original".to_string(),
            status: "pass".to_string(),
            message: Some("ok".to_string()),
        };
        let mut cloned = check.clone();
        cloned.name = "modified".to_string();
        assert_eq!(check.name, "original");
    }

    #[test]
    fn test_health_response_clone_independence() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("db", true, None);
        let cloned = response.clone();
        assert_eq!(response.checks.len(), cloned.checks.len());
        assert_eq!(response.status, cloned.status);
    }

    #[test]
    fn test_health_response_json_array_checks() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("a", true, None)
            .with_check("b", false, Some("err"));
        let json = serde_json::to_string(&response).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val["checks"].is_array());
        assert_eq!(val["checks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_prometheus_text_format_is_not_empty() {
        let text = prometheus_text_format();
        assert!(text.len() > 5);
    }

    #[test]
    fn test_health_response_unicode_version() {
        let response = HealthResponse::healthy("v1.0-日本語", 100);
        assert_eq!(response.version, "v1.0-日本語");
    }

    #[test]
    fn test_health_check_with_empty_name() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check("", true, None);
        assert_eq!(response.checks[0].name, "");
        assert!(response.is_healthy());
    }

    #[test]
    fn test_health_response_unhealthy_with_additional_passing_checks() {
        let response = HealthResponse::unhealthy("1.0.0", 100, "main failure")
            .with_check("db", true, None)
            .with_check("cache", true, None);
        // Main status is unhealthy, so is_healthy returns false even with passing checks
        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 3); // main + db + cache
    }

    #[test]
    fn test_health_response_json_roundtrip() {
        let response = HealthResponse::healthy("2.1.0", 12345)
            .with_check("api", true, Some("OK"))
            .with_check("db", false, Some("Timeout"));
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "healthy");
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["uptime_seconds"], 12345);
    }

    #[test]
    fn test_health_check_message_with_newlines() {
        let response = HealthResponse::healthy("1.0.0", 100).with_check(
            "test",
            false,
            Some("Line 1\nLine 2\nLine 3"),
        );
        assert_eq!(
            response.checks[0].message,
            Some("Line 1\nLine 2\nLine 3".to_string())
        );
    }

    #[test]
    fn test_health_response_healthy_no_checks_is_healthy() {
        let response = HealthResponse::healthy("1.0.0", 100);
        assert!(response.is_healthy());
        assert!(response.checks.is_empty());
    }

    #[test]
    fn test_health_response_unhealthy_zero_uptime() {
        let response = HealthResponse::unhealthy("1.0.0", 0, "not started");
        assert!(!response.is_healthy());
        assert_eq!(response.uptime_seconds, 0);
    }

    #[test]
    fn test_health_check_json_serialization_with_message() {
        let check = HealthCheck {
            name: "test_check".to_string(),
            status: "pass".to_string(),
            message: Some("all good".to_string()),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"message\":\"all good\""));
    }

    #[test]
    fn test_health_check_json_serialization_without_message() {
        let check = HealthCheck {
            name: "test_check".to_string(),
            status: "pass".to_string(),
            message: None,
        };
        let json = serde_json::to_string(&check).unwrap();
        // message should be skipped when None
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_health_response_single_failing_check() {
        let response =
            HealthResponse::healthy("1.0.0", 100).with_check("critical", false, Some("Down"));
        assert!(!response.is_healthy());
        assert_eq!(response.checks.len(), 1);
    }

    #[test]
    fn test_health_response_clone_deep_independence() {
        let response = HealthResponse::healthy("1.0.0", 100)
            .with_check("a", true, Some("ok"))
            .with_check("b", false, Some("err"));
        let mut cloned = response.clone();
        cloned.status = "degraded".to_string();
        cloned.checks.clear();
        // Original should be unaffected
        assert_eq!(response.status, "healthy");
        assert_eq!(response.checks.len(), 2);
    }

    // --- Acceptance: prometheus_text_format ---

    #[test]
    fn prometheus_text_format_returns_non_empty() {
        let text = prometheus_text_format();
        assert!(
            !text.is_empty(),
            "prometheus text format should return content"
        );
        assert!(text.starts_with('#'), "should start with comment line");
    }

    // --- Acceptance: health response JSON contract ---

    #[test]
    fn health_response_json_has_required_fields() {
        let response = HealthResponse::healthy("2.0.0", 7200)
            .with_check("store", true, None)
            .with_check("mesh", true, Some("all nodes reachable"));
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["status"], "healthy");
        assert_eq!(parsed["version"], "2.0.0");
        assert_eq!(parsed["uptime_seconds"], 7200);
        assert!(parsed["checks"].is_array());
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn health_response_json_omits_null_messages() {
        let response = HealthResponse::healthy("1.0.0", 0).with_check("db", true, None);
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["checks"][0].get("message").is_none(),
            "None message should be omitted from JSON"
        );
    }

    #[test]
    fn unhealthy_response_includes_failure_check() {
        let response = HealthResponse::unhealthy("1.0.0", 100, "connection refused");
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["status"], "unhealthy");
        assert_eq!(parsed["checks"][0]["name"], "main");
        assert_eq!(parsed["checks"][0]["status"], "fail");
        assert_eq!(parsed["checks"][0]["message"], "connection refused");
    }

    // --- Acceptance: mixed health check scenarios ---

    #[test]
    fn health_with_all_passing_checks_is_healthy() {
        let response = HealthResponse::healthy("1.0.0", 500)
            .with_check("store", true, None)
            .with_check("mesh", true, None)
            .with_check("audit", true, None);
        assert!(response.is_healthy());
        assert_eq!(response.checks.len(), 3);
    }

    #[test]
    fn health_with_one_failing_check_is_unhealthy() {
        let response = HealthResponse::healthy("1.0.0", 500)
            .with_check("store", true, None)
            .with_check("mesh", false, Some("2 nodes unreachable"))
            .with_check("audit", true, None);
        assert!(!response.is_healthy());
    }

    #[test]
    fn health_with_many_checks_serializes_all() {
        let mut response = HealthResponse::healthy("1.0.0", 0);
        for i in 0..20 {
            response = response.with_check(
                &format!("check_{i}"),
                i % 3 != 0,
                Some(&format!("detail {i}")),
            );
        }
        let json = serde_json::to_string(&response).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["checks"].as_array().unwrap().len(), 20);
    }

    #[test]
    fn health_response_version_preserved_exactly() {
        let response = HealthResponse::healthy("0.1.0-alpha.3+build.456", 1);
        assert_eq!(response.version, "0.1.0-alpha.3+build.456");
    }
}
