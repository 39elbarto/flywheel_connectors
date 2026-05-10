#![cfg(feature = "otlp")]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io,
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fcp_telemetry::{
    FcpSpan, OtlpHeader, OtlpResourceAttribute, TelemetryError, flush_otlp_tracer,
    init_otlp_tracer_with_sample_rate_options_and_timeout, shutdown_otlp_tracer,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use serde_json::json;
use tokio::{net::TcpListener, time};
use tokio_stream::wrappers::TcpListenerStream;

struct BackpressureTraceCollector {
    seen_requests: Mutex<u64>,
}

impl BackpressureTraceCollector {
    const fn new() -> Self {
        Self {
            seen_requests: Mutex::new(0),
        }
    }
}

#[tonic::async_trait]
impl TraceService for BackpressureTraceCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-backpressure-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e backpressure marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        *self
            .seen_requests
            .lock()
            .map_err(|_| tonic::Status::internal("collector counter lock poisoned"))? += 1;

        Err(tonic::Status::resource_exhausted(
            "collector backpressure: request queue full",
        ))
    }
}

async fn start_backpressure_collector()
-> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let service = TraceServiceServer::new(BackpressureTraceCollector::new());

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, handle))
}

async fn abort_server(server: tokio::task::JoinHandle<()>) -> Result<(), Box<dyn Error>> {
    server.abort();
    match server.await {
        Ok(()) => Ok(()),
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(Box::new(error)),
    }
}

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
        "cargo test -p fcp-telemetry --test otlp_backpressure_fixture --features otlp".to_string()
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

fn expect_flush_error(
    result: Result<(), TelemetryError>,
) -> Result<TelemetryError, Box<dyn Error>> {
    match result {
        Ok(()) => {
            Err(io::Error::other("backpressured collector should fail OTLP trace flush").into())
        }
        Err(error) => Ok(error),
    }
}

fn classify_error(error: &TelemetryError) -> &'static str {
    let rendered = error.to_string().to_ascii_lowercase();
    if rendered.contains("resource exhausted")
        || rendered.contains("resource_exhausted")
        || rendered.contains("resource has been exhausted")
    {
        "collector_backpressure"
    } else if rendered.contains("timeout") {
        "collector_timeout"
    } else {
        "collector_export_error"
    }
}

const fn cleanup_result(shutdown_result: &Result<(), TelemetryError>) -> &'static str {
    if shutdown_result.is_ok() {
        "shutdown_after_backpressure"
    } else {
        "shutdown_reported_error_after_backpressure"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_trace_exporter_maps_collector_backpressure_to_flush_error()
-> Result<(), Box<dyn Error>> {
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_backpressure_grpc",
        "signal_type": "trace"
    }))?;

    let (addr, server) = start_backpressure_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_tracer_with_sample_rate_options_and_timeout(
        "fcp-telemetry-backpressure-e2e",
        &endpoint,
        1.0,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-backpressure-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new(
            "fcp.zone",
            "z:otlp-backpressure",
        )?],
        Some(Duration::from_secs(1)),
    )?;

    {
        let mut span = FcpSpan::new("telemetry.otlp.backpressure")
            .server()
            .connector_id("fcp.telemetry")
            .operation("otlp.export")
            .attribute("fcp.signal_type", "trace")
            .start();
        span.record_error("collector backpressure");
    }

    let flush_error = expect_flush_error(flush_otlp_tracer())?;
    let error_mapping = classify_error(&flush_error);
    let shutdown_result = shutdown_otlp_tracer();
    abort_server(server).await?;

    assert!(
        matches!(flush_error, TelemetryError::TracingInit(_)),
        "flush error should map through TelemetryError::TracingInit: {flush_error:?}",
    );
    assert_eq!(
        error_mapping, "collector_backpressure",
        "flush error should preserve resource-exhausted/backpressure classification: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "trace",
        "batch_count": 0,
        "span_count": 1,
        "first_span_name": "telemetry.otlp.backpressure",
        "collector_endpoint_class": "local_loopback_backpressure_grpc",
        "retry_decision": "collector_backpressure_rejected",
        "dropped_count": 1,
        "grpc_status": "resource_exhausted",
        "runtime_error_mapping": error_mapping,
        "cleanup_result": cleanup_result(&shutdown_result),
        "skip_reason": null
    }))?;

    time::sleep(Duration::from_millis(10)).await;
    Ok(())
}
