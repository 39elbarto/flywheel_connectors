#![cfg(feature = "otlp")]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fcp_telemetry::{
    FcpSpan, OtlpHeader, OtlpResourceAttribute, TelemetryError, flush_otlp_tracer,
    init_otlp_tracer_with_sample_rate_options_and_timeout, shutdown_otlp_tracer,
};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_trace_exporter_maps_unavailable_collector_to_flush_error()
-> Result<(), Box<dyn Error>> {
    let command_line = std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-telemetry --test otlp_unavailable_fixture --features otlp".to_string()
    });
    let git_revision = std::env::var("FCP_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let addr = unused_loopback_endpoint().await?;
    let endpoint = format!("http://{addr}");

    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line,
        "git_revision": git_revision,
        "collector_endpoint_class": "local_loopback_unavailable_grpc",
        "signal_type": "trace"
    }))?;

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

    let flush_error = flush_otlp_tracer()
        .expect_err("unavailable collector should surface as an OTLP flush error");
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
        "cleanup_result": if shutdown_result.is_ok() {
            "shutdown_after_flush_failure"
        } else {
            "shutdown_reported_error_after_flush_failure"
        },
        "skip_reason": null
    }))?;

    Ok(())
}
