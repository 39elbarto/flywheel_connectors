#![cfg(feature = "otlp")]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fcp_telemetry::{
    FcpSpan, OtlpHeader, OtlpResourceAttribute, OtlpRetryPolicy, TelemetryConfig, flush_otlp_logs,
    flush_otlp_metrics, flush_otlp_tracer, init_logging,
    init_otlp_logs_with_options_timeout_and_retry,
    init_otlp_metrics_with_options_timeout_and_retry,
    init_otlp_tracer_with_sample_rate_options_timeout_and_retry, shutdown_otlp_logs,
    shutdown_otlp_metrics, shutdown_otlp_tracer,
};
use opentelemetry::{KeyValue, global};
use opentelemetry_proto::tonic::{
    collector::{
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
    },
    common::v1::any_value,
    logs::v1::LogRecord,
    metrics::v1::metric,
};
use serde_json::json;
use tokio::{net::TcpListener, sync::mpsc, time};
use tokio_stream::wrappers::TcpListenerStream;

struct TransientTraceCollector {
    tx: Mutex<mpsc::Sender<ExportTraceServiceRequest>>,
    seen_requests: Arc<AtomicU64>,
}

impl TransientTraceCollector {
    const fn new(
        tx: mpsc::Sender<ExportTraceServiceRequest>,
        seen_requests: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx: Mutex::new(tx),
            seen_requests,
        }
    }
}

#[tonic::async_trait]
impl TraceService for TransientTraceCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-retry-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e retry marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        let attempt = self.seen_requests.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt == 1 {
            return Err(tonic::Status::unavailable(
                "collector temporarily unavailable",
            ));
        }

        self.tx
            .lock()
            .map_err(|_| tonic::Status::internal("collector channel lock poisoned"))?
            .try_send(request.into_inner())
            .map_err(|_| tonic::Status::resource_exhausted("collector channel full"))?;

        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

struct TransientMetricsCollector {
    tx: Mutex<mpsc::Sender<ExportMetricsServiceRequest>>,
    seen_requests: Arc<AtomicU64>,
}

impl TransientMetricsCollector {
    const fn new(
        tx: mpsc::Sender<ExportMetricsServiceRequest>,
        seen_requests: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx: Mutex::new(tx),
            seen_requests,
        }
    }
}

#[tonic::async_trait]
impl MetricsService for TransientMetricsCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-retry-metrics-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e metrics retry marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        let attempt = self.seen_requests.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt == 1 {
            return Err(tonic::Status::unavailable(
                "collector temporarily unavailable",
            ));
        }

        self.tx
            .lock()
            .map_err(|_| tonic::Status::internal("collector channel lock poisoned"))?
            .try_send(request.into_inner())
            .map_err(|_| tonic::Status::resource_exhausted("collector channel full"))?;

        Ok(tonic::Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

struct TransientLogsCollector {
    tx: Mutex<mpsc::Sender<ExportLogsServiceRequest>>,
    seen_requests: Arc<AtomicU64>,
}

impl TransientLogsCollector {
    const fn new(
        tx: mpsc::Sender<ExportLogsServiceRequest>,
        seen_requests: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx: Mutex::new(tx),
            seen_requests,
        }
    }
}

#[tonic::async_trait]
impl LogsService for TransientLogsCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportLogsServiceRequest>,
    ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-retry-logs-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e logs retry marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        let attempt = self.seen_requests.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt == 1 {
            return Err(tonic::Status::unavailable(
                "collector temporarily unavailable",
            ));
        }

        self.tx
            .lock()
            .map_err(|_| tonic::Status::internal("collector channel lock poisoned"))?
            .try_send(request.into_inner())
            .map_err(|_| tonic::Status::resource_exhausted("collector channel full"))?;

        Ok(tonic::Response::new(ExportLogsServiceResponse {
            partial_success: None,
        }))
    }
}

async fn start_trace_collector() -> Result<
    (
        SocketAddr,
        mpsc::Receiver<ExportTraceServiceRequest>,
        tokio::task::JoinHandle<()>,
        Arc<AtomicU64>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = mpsc::channel(4);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service =
        TraceServiceServer::new(TransientTraceCollector::new(tx, Arc::clone(&seen_requests)));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, rx, handle, seen_requests))
}

async fn start_metrics_collector() -> Result<
    (
        SocketAddr,
        mpsc::Receiver<ExportMetricsServiceRequest>,
        tokio::task::JoinHandle<()>,
        Arc<AtomicU64>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = mpsc::channel(4);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service = MetricsServiceServer::new(TransientMetricsCollector::new(
        tx,
        Arc::clone(&seen_requests),
    ));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, rx, handle, seen_requests))
}

async fn start_logs_collector() -> Result<
    (
        SocketAddr,
        mpsc::Receiver<ExportLogsServiceRequest>,
        tokio::task::JoinHandle<()>,
        Arc<AtomicU64>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = mpsc::channel(4);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service =
        LogsServiceServer::new(TransientLogsCollector::new(tx, Arc::clone(&seen_requests)));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, rx, handle, seen_requests))
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
        "cargo test -p fcp-telemetry --test otlp_retry_fixture --features otlp".to_string()
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

const fn retry_policy() -> OtlpRetryPolicy {
    OtlpRetryPolicy::new(2, Duration::from_millis(10), Duration::from_millis(10))
}

fn string_value(value: Option<&opentelemetry_proto::tonic::common::v1::AnyValue>) -> Option<&str> {
    match value?.value.as_ref()? {
        any_value::Value::StringValue(value) => Some(value.as_str()),
        _ => None,
    }
}

fn resource_attribute<'a>(request: &'a ExportTraceServiceRequest, key: &str) -> Option<&'a str> {
    request
        .resource_spans
        .first()?
        .resource
        .as_ref()?
        .attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .and_then(|attribute| string_value(attribute.value.as_ref()))
}

fn metrics_resource_attribute<'a>(
    request: &'a ExportMetricsServiceRequest,
    key: &str,
) -> Option<&'a str> {
    request
        .resource_metrics
        .first()?
        .resource
        .as_ref()?
        .attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .and_then(|attribute| string_value(attribute.value.as_ref()))
}

fn logs_resource_attribute<'a>(
    request: &'a ExportLogsServiceRequest,
    key: &str,
) -> Option<&'a str> {
    request
        .resource_logs
        .first()?
        .resource
        .as_ref()?
        .attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .and_then(|attribute| string_value(attribute.value.as_ref()))
}

fn metric_data_point_count(metric: &opentelemetry_proto::tonic::metrics::v1::Metric) -> usize {
    match metric.data.as_ref() {
        Some(metric::Data::Gauge(gauge)) => gauge.data_points.len(),
        Some(metric::Data::Sum(sum)) => sum.data_points.len(),
        Some(metric::Data::Histogram(histogram)) => histogram.data_points.len(),
        Some(metric::Data::ExponentialHistogram(histogram)) => histogram.data_points.len(),
        Some(metric::Data::Summary(summary)) => summary.data_points.len(),
        None => 0,
    }
}

fn log_record_count(request: &ExportLogsServiceRequest) -> usize {
    request
        .resource_logs
        .iter()
        .flat_map(|resource| &resource.scope_logs)
        .map(|scope| scope.log_records.len())
        .sum()
}

fn first_log_record(request: &ExportLogsServiceRequest) -> Option<&LogRecord> {
    request
        .resource_logs
        .first()?
        .scope_logs
        .first()?
        .log_records
        .first()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_trace_exporter_retries_transient_unavailable_and_flushes()
-> Result<(), Box<dyn Error>> {
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_transient_unavailable_grpc",
        "signal_type": "trace"
    }))?;

    let (addr, mut rx, server, seen_requests) = start_trace_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_tracer_with_sample_rate_options_timeout_and_retry(
        "fcp-telemetry-retry-e2e",
        &endpoint,
        1.0,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-retry-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new("fcp.zone", "z:otlp-retry")?],
        Some(Duration::from_secs(1)),
        retry_policy(),
    )?;

    {
        let mut span = FcpSpan::new("telemetry.otlp.retry")
            .server()
            .connector_id("fcp.telemetry")
            .operation("otlp.export")
            .attribute("fcp.signal_type", "trace")
            .start();
        span.set_ok();
    }

    flush_otlp_tracer()?;
    let request = time::timeout(time::Duration::from_secs(10), rx.recv())
        .await?
        .ok_or("collector did not receive retried OTLP trace export")?;
    let collector_request_count = seen_requests.load(Ordering::SeqCst);
    let shutdown_result = shutdown_otlp_tracer();
    abort_server(server).await?;

    let span_count: usize = request
        .resource_spans
        .iter()
        .flat_map(|resource| &resource.scope_spans)
        .map(|scope| scope.spans.len())
        .sum();
    let first_span = request
        .resource_spans
        .first()
        .and_then(|resource| resource.scope_spans.first())
        .and_then(|scope| scope.spans.first())
        .ok_or("retried trace export did not contain spans")?;

    assert_eq!(collector_request_count, 2);
    assert_eq!(first_span.name, "telemetry.otlp.retry");
    assert_eq!(
        resource_attribute(&request, "service.name"),
        Some("fcp-telemetry-retry-e2e")
    );
    assert_eq!(
        resource_attribute(&request, "fcp.zone"),
        Some("z:otlp-retry")
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_received",
        "ts_ms": now_millis(),
        "signal_type": "trace",
        "batch_count": request.resource_spans.len(),
        "span_count": span_count,
        "collector_request_count": collector_request_count,
        "first_span_name": first_span.name,
        "collector_endpoint_class": "local_loopback_transient_unavailable_grpc",
        "retry_decision": "retry_after_unavailable_then_success",
        "retry_max_attempts": retry_policy().max_attempts,
        "dropped_count": 0,
        "first_grpc_status": "unavailable",
        "grpc_status": "ok",
        "runtime_error_mapping": "transient_unavailable_recovered",
        "cleanup_result": if shutdown_result.is_ok() { "shutdown_after_retry_success" } else { "shutdown_reported_error_after_retry_success" },
        "skip_reason": null
    }))?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_metric_exporter_retries_transient_unavailable_and_flushes()
-> Result<(), Box<dyn Error>> {
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_transient_unavailable_grpc",
        "signal_type": "metric"
    }))?;

    let (addr, mut rx, server, seen_requests) = start_metrics_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_metrics_with_options_timeout_and_retry(
        "fcp-telemetry-retry-metrics-e2e",
        &endpoint,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-retry-metrics-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new("fcp.zone", "z:otlp-retry")?],
        Some(Duration::from_secs(1)),
        retry_policy(),
    )?;

    let meter = global::meter("fcp.telemetry.retry");
    let counter = meter
        .u64_counter("fcp.telemetry.otlp.metric_retry")
        .with_description("OTLP retry metrics fixture counter")
        .build();
    counter.add(
        1,
        &[
            KeyValue::new("fcp.signal_type", "metric"),
            KeyValue::new("fcp.test", "otlp-retry-fixture"),
        ],
    );

    flush_otlp_metrics()?;
    let request = time::timeout(time::Duration::from_secs(10), rx.recv())
        .await?
        .ok_or("collector did not receive retried OTLP metrics export")?;
    let collector_request_count = seen_requests.load(Ordering::SeqCst);
    let shutdown_result = shutdown_otlp_metrics();
    abort_server(server).await?;

    let metric_count = request
        .resource_metrics
        .iter()
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
        .count();
    let exported_metric = request
        .resource_metrics
        .iter()
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
        .find(|metric| metric.name == "fcp.telemetry.otlp.metric_retry")
        .ok_or("retried metrics export did not contain fixture metric")?;
    let data_point_count = metric_data_point_count(exported_metric);

    assert_eq!(collector_request_count, 2);
    assert!(data_point_count > 0);
    assert_eq!(
        metrics_resource_attribute(&request, "service.name"),
        Some("fcp-telemetry-retry-metrics-e2e")
    );
    assert_eq!(
        metrics_resource_attribute(&request, "fcp.zone"),
        Some("z:otlp-retry")
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_received",
        "ts_ms": now_millis(),
        "signal_type": "metric",
        "batch_count": request.resource_metrics.len(),
        "metric_count": metric_count,
        "data_point_count": data_point_count,
        "collector_request_count": collector_request_count,
        "first_metric_name": exported_metric.name,
        "collector_endpoint_class": "local_loopback_transient_unavailable_grpc",
        "retry_decision": "retry_after_unavailable_then_success",
        "retry_max_attempts": retry_policy().max_attempts,
        "dropped_count": 0,
        "first_grpc_status": "unavailable",
        "grpc_status": "ok",
        "runtime_error_mapping": "transient_unavailable_recovered",
        "cleanup_result": if shutdown_result.is_ok() { "shutdown_after_retry_success" } else { "shutdown_reported_error_after_retry_success" },
        "skip_reason": null
    }))?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_log_exporter_retries_transient_unavailable_and_flushes() -> Result<(), Box<dyn Error>>
{
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_transient_unavailable_grpc",
        "signal_type": "log"
    }))?;

    let (addr, mut rx, server, seen_requests) = start_logs_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_logs_with_options_timeout_and_retry(
        "fcp-telemetry-retry-logs-e2e",
        &endpoint,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-retry-logs-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new("fcp.zone", "z:otlp-retry")?],
        Some(Duration::from_secs(1)),
        retry_policy(),
    )?;
    init_logging(
        &TelemetryConfig::new("fcp-telemetry-retry-logs-e2e")
            .with_log_level("info")
            .with_json_logs(false),
    )?;

    tracing::info!(
        target: "fcp.telemetry.otlp.fixture",
        fcp_signal_type = "log",
        fcp_test = "otlp-retry-fixture",
        "telemetry.otlp.log_retry"
    );

    flush_otlp_logs()?;
    let request = time::timeout(time::Duration::from_secs(10), rx.recv())
        .await?
        .ok_or("collector did not receive retried OTLP logs export")?;
    let collector_request_count = seen_requests.load(Ordering::SeqCst);
    let shutdown_result = shutdown_otlp_logs();
    abort_server(server).await?;

    let record_count = log_record_count(&request);
    let first_record =
        first_log_record(&request).ok_or("retried logs export did not contain log records")?;

    assert_eq!(collector_request_count, 2);
    assert!(record_count > 0);
    assert_eq!(
        logs_resource_attribute(&request, "service.name"),
        Some("fcp-telemetry-retry-logs-e2e")
    );
    assert_eq!(
        logs_resource_attribute(&request, "fcp.zone"),
        Some("z:otlp-retry")
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_received",
        "ts_ms": now_millis(),
        "signal_type": "log",
        "batch_count": request.resource_logs.len(),
        "log_record_count": record_count,
        "first_log_severity": format!("{:?}", first_record.severity_number()),
        "collector_request_count": collector_request_count,
        "collector_endpoint_class": "local_loopback_transient_unavailable_grpc",
        "retry_decision": "retry_after_unavailable_then_success",
        "retry_max_attempts": retry_policy().max_attempts,
        "dropped_count": 0,
        "first_grpc_status": "unavailable",
        "grpc_status": "ok",
        "runtime_error_mapping": "transient_unavailable_recovered",
        "cleanup_result": if shutdown_result.is_ok() { "shutdown_after_retry_success" } else { "shutdown_reported_error_after_retry_success" },
        "skip_reason": null
    }))?;

    Ok(())
}
