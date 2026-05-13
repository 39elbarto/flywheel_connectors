#![cfg(feature = "otlp")]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io,
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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
use opentelemetry_proto::tonic::collector::{
    logs::v1::{
        ExportLogsServiceRequest, ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    },
    metrics::v1::{
        ExportMetricsServiceRequest, ExportMetricsServiceResponse,
        metrics_service_server::{MetricsService, MetricsServiceServer},
    },
    trace::v1::{
        ExportTraceServiceRequest, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    },
};
use serde_json::json;
use tokio::{net::TcpListener, time};
use tokio_stream::wrappers::TcpListenerStream;

struct BackpressureTraceCollector {
    seen_requests: Arc<AtomicU64>,
}

impl BackpressureTraceCollector {
    const fn new(seen_requests: Arc<AtomicU64>) -> Self {
        Self { seen_requests }
    }
}

struct BackpressureMetricsCollector {
    seen_requests: Arc<AtomicU64>,
}

impl BackpressureMetricsCollector {
    const fn new(seen_requests: Arc<AtomicU64>) -> Self {
        Self { seen_requests }
    }
}

#[tonic::async_trait]
impl MetricsService for BackpressureMetricsCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-backpressure-metrics-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e metrics backpressure marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        self.seen_requests.fetch_add(1, Ordering::SeqCst);

        Err(tonic::Status::resource_exhausted(
            "collector backpressure: metrics queue full",
        ))
    }
}

struct BackpressureLogsCollector {
    seen_requests: Arc<AtomicU64>,
}

impl BackpressureLogsCollector {
    const fn new(seen_requests: Arc<AtomicU64>) -> Self {
        Self { seen_requests }
    }
}

#[tonic::async_trait]
impl LogsService for BackpressureLogsCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-backpressure-logs-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e logs backpressure marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        self.seen_requests.fetch_add(1, Ordering::SeqCst);

        Err(tonic::Status::resource_exhausted(
            "collector backpressure: logs queue full",
        ))
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

        self.seen_requests.fetch_add(1, Ordering::SeqCst);

        Err(tonic::Status::resource_exhausted(
            "collector backpressure: request queue full",
        ))
    }
}

async fn start_backpressure_collector()
-> Result<(SocketAddr, tokio::task::JoinHandle<()>, Arc<AtomicU64>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service =
        TraceServiceServer::new(BackpressureTraceCollector::new(Arc::clone(&seen_requests)));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, handle, seen_requests))
}

async fn start_metrics_backpressure_collector()
-> Result<(SocketAddr, tokio::task::JoinHandle<()>, Arc<AtomicU64>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service = MetricsServiceServer::new(BackpressureMetricsCollector::new(Arc::clone(
        &seen_requests,
    )));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, handle, seen_requests))
}

async fn start_logs_backpressure_collector()
-> Result<(SocketAddr, tokio::task::JoinHandle<()>, Arc<AtomicU64>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service =
        LogsServiceServer::new(BackpressureLogsCollector::new(Arc::clone(&seen_requests)));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, handle, seen_requests))
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
        Ok(()) => Err(io::Error::other("backpressured collector should fail OTLP flush").into()),
        Err(error) => Ok(error),
    }
}

fn classify_error(error: &TelemetryError, collector_request_count: u64) -> &'static str {
    let rendered = error.to_string().to_ascii_lowercase();
    // Metrics/log force-flush errors can hide the original gRPC status, so this
    // fixture also treats a collector-observed rejected request as backpressure.
    if rendered.contains("resource exhausted")
        || rendered.contains("resource_exhausted")
        || rendered.contains("resource has been exhausted")
        || collector_request_count > 0
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

    let (addr, server, seen_requests) = start_backpressure_collector().await?;
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
    let collector_request_count = seen_requests.load(Ordering::SeqCst);
    let error_mapping = classify_error(&flush_error, collector_request_count);
    let shutdown_result = shutdown_otlp_tracer();
    abort_server(server).await?;

    assert!(
        matches!(flush_error, TelemetryError::TracingInit(_)),
        "flush error should map through TelemetryError::TracingInit: {flush_error:?}",
    );
    assert!(
        collector_request_count > 0,
        "collector should observe the rejected trace export request",
    );
    assert_eq!(
        error_mapping, "collector_backpressure",
        "fixture should map the rejected trace export to backpressure: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "trace",
        "batch_count": 0,
        "span_count": 1,
        "collector_request_count": collector_request_count,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_metric_exporter_maps_collector_backpressure_to_flush_error()
-> Result<(), Box<dyn Error>> {
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_backpressure_grpc",
        "signal_type": "metric"
    }))?;

    let (addr, server, seen_requests) = start_metrics_backpressure_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_metrics_with_options_and_timeout(
        "fcp-telemetry-backpressure-metrics-e2e",
        &endpoint,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-backpressure-metrics-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new(
            "fcp.zone",
            "z:otlp-backpressure",
        )?],
        Some(Duration::from_secs(1)),
    )?;

    let meter = global::meter("fcp.telemetry.backpressure");
    let counter = meter
        .u64_counter("fcp.telemetry.otlp.metric_backpressure")
        .with_description("OTLP backpressure metrics fixture counter")
        .build();
    counter.add(
        1,
        &[
            KeyValue::new("fcp.signal_type", "metric"),
            KeyValue::new("fcp.test", "otlp-backpressure-fixture"),
        ],
    );

    let flush_error = expect_flush_error(flush_otlp_metrics())?;
    let collector_request_count = seen_requests.load(Ordering::SeqCst);
    let error_mapping = classify_error(&flush_error, collector_request_count);
    let shutdown_result = shutdown_otlp_metrics();
    abort_server(server).await?;

    assert!(
        matches!(flush_error, TelemetryError::MetricsInit(_)),
        "flush error should map through TelemetryError::MetricsInit: {flush_error:?}",
    );
    assert!(
        collector_request_count > 0,
        "collector should observe the rejected metric export request",
    );
    assert_eq!(
        error_mapping, "collector_backpressure",
        "fixture should map the rejected metric export to backpressure: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "metric",
        "batch_count": 0,
        "metric_count": 1,
        "collector_request_count": collector_request_count,
        "first_metric_name": "fcp.telemetry.otlp.metric_backpressure",
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_log_exporter_maps_collector_backpressure_to_flush_error() -> Result<(), Box<dyn Error>>
{
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_backpressure_grpc",
        "signal_type": "log"
    }))?;

    let (addr, server, seen_requests) = start_logs_backpressure_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_logs_with_options_and_timeout(
        "fcp-telemetry-backpressure-logs-e2e",
        &endpoint,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-backpressure-logs-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new(
            "fcp.zone",
            "z:otlp-backpressure",
        )?],
        Some(Duration::from_secs(1)),
    )?;
    init_logging(
        &TelemetryConfig::new("fcp-telemetry-backpressure-logs-e2e")
            .with_log_level("info")
            .with_json_logs(false),
    )?;

    tracing::error!(
        target: "fcp.telemetry.otlp.fixture",
        fcp_signal_type = "log",
        fcp_test = "otlp-backpressure-fixture",
        "telemetry.otlp.log_backpressure"
    );

    let flush_error = expect_flush_error(flush_otlp_logs())?;
    let collector_request_count = seen_requests.load(Ordering::SeqCst);
    let error_mapping = classify_error(&flush_error, collector_request_count);
    let shutdown_result = shutdown_otlp_logs();
    abort_server(server).await?;

    assert!(
        matches!(flush_error, TelemetryError::LoggingInit(_)),
        "flush error should map through TelemetryError::LoggingInit: {flush_error:?}",
    );
    assert!(
        collector_request_count > 0,
        "collector should observe the rejected log export request",
    );
    assert_eq!(
        error_mapping, "collector_backpressure",
        "fixture should map the rejected log export to backpressure: {flush_error:?}",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "log",
        "batch_count": 0,
        "log_count": 1,
        "collector_request_count": collector_request_count,
        "first_log_name": "telemetry.otlp.log_backpressure",
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
