#![cfg(feature = "otlp")]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io,
    io::Write,
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fcp_telemetry::{
    FcpSpan, OtlpHeader, OtlpResourceAttribute, TelemetryConfig, TelemetryError, flush_otlp_logs,
    flush_otlp_metrics, flush_otlp_tracer, init_logging, init_otlp_logs_with_options_and_timeout,
    init_otlp_metrics_with_options_and_timeout,
    init_otlp_tracer_with_sample_rate_options_and_timeout, shutdown_otlp_logs,
    shutdown_otlp_metrics, shutdown_otlp_tracer,
};
use opentelemetry::{KeyValue, global};
use serde_json::json;
use tokio::net::TcpListener;

fn evidence_path() -> Option<String> {
    std::env::var("FCP_TELEMETRY_OTLP_EVIDENCE")
        .ok()
        .filter(|path| !path.trim().is_empty())
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-telemetry --test otlp_unavailable_fixture --features otlp".to_string()
    })
}

fn git_revision() -> String {
    std::env::var("FCP_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string())
}

fn append_evidence(value: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    println!("{value}");
    let Some(path) = evidence_path() else {
        return Ok(());
    };
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{value}")?;
    Ok(())
}

async fn unused_loopback_endpoint() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn classify_error(error: &TelemetryError) -> &'static str {
    let rendered = error.to_string().to_ascii_lowercase();
    if rendered.contains("connection refused") || rendered.contains("transport error") {
        "collector_unavailable"
    } else if rendered.contains("timeout") {
        "collector_timeout"
    } else {
        "collector_export_error"
    }
}

fn expect_flush_error(
    result: Result<(), TelemetryError>,
    signal_type: &str,
) -> Result<TelemetryError, Box<dyn Error>> {
    match result {
        Ok(()) => Err(io::Error::other(format!(
            "unavailable collector should fail {signal_type} OTLP flush",
        ))
        .into()),
        Err(error) => Ok(error),
    }
}

const fn cleanup_result(shutdown_result: &Result<(), TelemetryError>) -> &'static str {
    if shutdown_result.is_ok() {
        "shutdown_after_flush_failure"
    } else {
        "shutdown_reported_error_after_flush_failure"
    }
}

fn append_start_evidence(signal_type: &str) -> Result<(), Box<dyn Error>> {
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_unavailable_grpc",
        "signal_type": signal_type
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_trace_exporter_maps_unavailable_collector_to_flush_error()
-> Result<(), Box<dyn Error>> {
    let addr = unused_loopback_endpoint().await?;
    let endpoint = format!("http://{addr}");

    append_start_evidence("trace")?;

    init_otlp_tracer_with_sample_rate_options_and_timeout(
        "fcp-telemetry-unavailable-e2e",
        &endpoint,
        1.0,
        &[OtlpHeader::new("x-fcp-e2e", "otlp-unavailable-fixture")?],
        &[OtlpResourceAttribute::new(
            "fcp.zone",
            "z:otlp-unavailable",
        )?],
        Some(Duration::from_millis(250)),
    )?;

    {
        let mut span = FcpSpan::new("telemetry.otlp.unavailable")
            .server()
            .connector_id("fcp.telemetry")
            .operation("otlp.export")
            .attribute("fcp.signal_type", "trace")
            .start();
        span.record_error("collector unavailable");
    }

    let flush_error = expect_flush_error(flush_otlp_tracer(), "trace")?;
    let error_mapping = classify_error(&flush_error);
    let shutdown_result = shutdown_otlp_tracer();

    assert!(
        matches!(flush_error, TelemetryError::TracingInit(_)),
        "flush error should map through TelemetryError::TracingInit: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "trace",
        "batch_count": 0,
        "span_count": 1,
        "first_span_name": "telemetry.otlp.unavailable",
        "collector_endpoint_class": "local_loopback_unavailable_grpc",
        "retry_decision": "sdk_default_flush_failure",
        "dropped_count": 1,
        "grpc_status": "unavailable",
        "runtime_error_mapping": error_mapping,
        "cleanup_result": cleanup_result(&shutdown_result),
        "skip_reason": null
    }))?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_metric_exporter_maps_unavailable_collector_to_flush_error()
-> Result<(), Box<dyn Error>> {
    let addr = unused_loopback_endpoint().await?;
    let endpoint = format!("http://{addr}");

    append_start_evidence("metric")?;

    init_otlp_metrics_with_options_and_timeout(
        "fcp-telemetry-unavailable-metrics-e2e",
        &endpoint,
        &[OtlpHeader::new(
            "x-fcp-e2e",
            "otlp-unavailable-metrics-fixture",
        )?],
        &[OtlpResourceAttribute::new(
            "fcp.zone",
            "z:otlp-unavailable",
        )?],
        Some(Duration::from_millis(250)),
    )?;

    let meter = global::meter("fcp.telemetry.unavailable");
    let counter = meter
        .u64_counter("fcp.telemetry.otlp.metric_unavailable")
        .with_description("OTLP unavailable collector metrics fixture counter")
        .build();
    counter.add(
        1,
        &[
            KeyValue::new("fcp.signal_type", "metric"),
            KeyValue::new("fcp.test", "otlp-unavailable-fixture"),
        ],
    );

    let flush_error = expect_flush_error(flush_otlp_metrics(), "metric")?;
    let error_mapping = classify_error(&flush_error);
    let shutdown_result = shutdown_otlp_metrics();

    assert!(
        matches!(flush_error, TelemetryError::MetricsInit(_)),
        "flush error should map through TelemetryError::MetricsInit: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "metric",
        "batch_count": 0,
        "metric_count": 1,
        "data_point_count": 1,
        "first_metric_name": "fcp.telemetry.otlp.metric_unavailable",
        "collector_endpoint_class": "local_loopback_unavailable_grpc",
        "retry_decision": "sdk_default_flush_failure",
        "dropped_count": 1,
        "grpc_status": "unavailable",
        "runtime_error_mapping": error_mapping,
        "cleanup_result": cleanup_result(&shutdown_result),
        "skip_reason": null
    }))?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_log_exporter_maps_unavailable_collector_to_flush_error() -> Result<(), Box<dyn Error>>
{
    let addr = unused_loopback_endpoint().await?;
    let endpoint = format!("http://{addr}");

    append_start_evidence("log")?;

    init_otlp_logs_with_options_and_timeout(
        "fcp-telemetry-unavailable-logs-e2e",
        &endpoint,
        &[OtlpHeader::new(
            "x-fcp-e2e",
            "otlp-unavailable-logs-fixture",
        )?],
        &[OtlpResourceAttribute::new(
            "fcp.zone",
            "z:otlp-unavailable",
        )?],
        Some(Duration::from_millis(250)),
    )?;
    init_logging(
        &TelemetryConfig::new("fcp-telemetry-unavailable-logs-e2e")
            .with_log_level("info")
            .with_json_logs(false),
    )?;

    tracing::info!(
        target: "fcp.telemetry.otlp.fixture",
        fcp_signal_type = "log",
        fcp_test = "otlp-unavailable-fixture",
        "telemetry.otlp.log_unavailable"
    );

    let flush_error = expect_flush_error(flush_otlp_logs(), "log")?;
    let error_mapping = classify_error(&flush_error);
    let shutdown_result = shutdown_otlp_logs();

    assert!(
        matches!(flush_error, TelemetryError::LoggingInit(_)),
        "flush error should map through TelemetryError::LoggingInit: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "log",
        "batch_count": 0,
        "log_record_count": 1,
        "first_log_severity": "INFO",
        "collector_endpoint_class": "local_loopback_unavailable_grpc",
        "retry_decision": "sdk_default_flush_failure",
        "dropped_count": 1,
        "grpc_status": "unavailable",
        "runtime_error_mapping": error_mapping,
        "cleanup_result": cleanup_result(&shutdown_result),
        "skip_reason": null
    }))?;

    Ok(())
}
