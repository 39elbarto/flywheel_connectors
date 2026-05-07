#![cfg(feature = "otlp")]

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fcp_telemetry::{
    FcpSpan, OtlpHeader, OtlpResourceAttribute, flush_otlp_metrics, flush_otlp_tracer,
    init_otlp_metrics_with_options_and_timeout, init_otlp_tracer_with_sample_rate_and_options,
    shutdown_otlp_metrics, shutdown_otlp_tracer,
};
use opentelemetry::{KeyValue, global};
use opentelemetry_proto::tonic::{
    collector::{
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
    metrics::v1::metric,
};
use serde_json::json;
use tokio::{net::TcpListener, sync::mpsc, time};
use tokio_stream::wrappers::TcpListenerStream;

struct RecordingTraceCollector {
    tx: Mutex<mpsc::Sender<ExportTraceServiceRequest>>,
}

impl RecordingTraceCollector {
    const fn new(tx: mpsc::Sender<ExportTraceServiceRequest>) -> Self {
        Self { tx: Mutex::new(tx) }
    }
}

#[tonic::async_trait]
impl TraceService for RecordingTraceCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e collector marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
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

struct RecordingMetricsCollector {
    tx: Mutex<mpsc::Sender<ExportMetricsServiceRequest>>,
}

impl RecordingMetricsCollector {
    const fn new(tx: mpsc::Sender<ExportMetricsServiceRequest>) -> Self {
        Self { tx: Mutex::new(tx) }
    }
}

#[tonic::async_trait]
impl MetricsService for RecordingMetricsCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportMetricsServiceRequest>,
    ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-metrics-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e metrics collector marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
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

async fn start_collector() -> Result<
    (
        SocketAddr,
        mpsc::Receiver<ExportTraceServiceRequest>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = mpsc::channel(8);
    let service = TraceServiceServer::new(RecordingTraceCollector::new(tx));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, rx, handle))
}

async fn start_metrics_collector() -> Result<
    (
        SocketAddr,
        mpsc::Receiver<ExportMetricsServiceRequest>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn Error>,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = mpsc::channel(8);
    let service = MetricsServiceServer::new(RecordingMetricsCollector::new(tx));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, rx, handle))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_trace_exporter_reaches_local_collector_and_flushes() -> Result<(), Box<dyn Error>> {
    let command_line = std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-telemetry --test otlp_collector_fixture --features otlp".to_string()
    });
    let git_revision = std::env::var("FCP_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line,
        "git_revision": git_revision,
        "collector_endpoint_class": "local_loopback_grpc",
        "signal_type": "trace"
    }))?;

    let (addr, mut rx, server) = start_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_tracer_with_sample_rate_and_options(
        "fcp-telemetry-e2e",
        &endpoint,
        1.0,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[
            OtlpResourceAttribute::new("deployment.environment", "test")?,
            OtlpResourceAttribute::new("fcp.zone", "z:otlp-e2e")?,
        ],
    )?;

    {
        let mut span = FcpSpan::new("telemetry.otlp.e2e")
            .server()
            .connector_id("fcp.telemetry")
            .operation("otlp.export")
            .attribute("fcp.signal_type", "trace")
            .start();
        span.set_attribute("fcp.batch_hint", "single-span");
        span.set_ok();
    }

    flush_otlp_tracer()?;
    let request = time::timeout(time::Duration::from_secs(10), rx.recv())
        .await?
        .ok_or("collector did not receive an OTLP export request")?;
    shutdown_otlp_tracer()?;
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
        .ok_or("collector request did not contain any spans")?;

    assert_eq!(first_span.name, "telemetry.otlp.e2e");
    assert_eq!(
        resource_attribute(&request, "service.name"),
        Some("fcp-telemetry-e2e")
    );
    assert_eq!(
        resource_attribute(&request, "deployment.environment"),
        Some("test")
    );
    assert_eq!(resource_attribute(&request, "fcp.zone"), Some("z:otlp-e2e"));

    let evidence = json!({
        "event": "otlp_e2e_export_received",
        "ts_ms": now_millis(),
        "signal_type": "trace",
        "batch_count": request.resource_spans.len(),
        "span_count": span_count,
        "first_span_name": first_span.name,
        "collector_endpoint_class": "local_loopback_grpc",
        "retry_decision": "not_needed",
        "dropped_count": 0,
        "grpc_status": "ok",
        "runtime_error_mapping": "none",
        "cleanup_result": "shutdown_and_abort_server",
        "skip_reason": null
    });
    append_evidence(&evidence)?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_metric_exporter_reaches_local_collector_and_flushes() -> Result<(), Box<dyn Error>> {
    let command_line = std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-telemetry --test otlp_collector_fixture --features otlp".to_string()
    });
    let git_revision = std::env::var("FCP_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line,
        "git_revision": git_revision,
        "collector_endpoint_class": "local_loopback_grpc",
        "signal_type": "metric"
    }))?;

    let (addr, mut rx, server) = start_metrics_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_metrics_with_options_and_timeout(
        "fcp-telemetry-metrics-e2e",
        &endpoint,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-metrics-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[
            OtlpResourceAttribute::new("deployment.environment", "test")?,
            OtlpResourceAttribute::new("fcp.zone", "z:otlp-e2e")?,
        ],
        Some(Duration::from_secs(3)),
    )?;

    let meter = global::meter("fcp.telemetry.e2e");
    let counter = meter
        .u64_counter("fcp.telemetry.otlp.metric_exported")
        .with_description("OTLP metrics fixture counter")
        .build();
    counter.add(
        7,
        &[
            KeyValue::new("fcp.signal_type", "metric"),
            KeyValue::new("fcp.test", "otlp-metrics-fixture"),
        ],
    );

    flush_otlp_metrics()?;
    let request = time::timeout(time::Duration::from_secs(10), rx.recv())
        .await?
        .ok_or("collector did not receive an OTLP metrics export request")?;
    shutdown_otlp_metrics()?;
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
        .find(|metric| metric.name == "fcp.telemetry.otlp.metric_exported")
        .ok_or("collector request did not contain the fixture metric")?;
    let data_point_count = metric_data_point_count(exported_metric);

    assert!(data_point_count > 0);
    assert_eq!(
        metrics_resource_attribute(&request, "service.name"),
        Some("fcp-telemetry-metrics-e2e")
    );
    assert_eq!(
        metrics_resource_attribute(&request, "deployment.environment"),
        Some("test")
    );
    assert_eq!(
        metrics_resource_attribute(&request, "fcp.zone"),
        Some("z:otlp-e2e")
    );

    let evidence = json!({
        "event": "otlp_e2e_export_received",
        "ts_ms": now_millis(),
        "signal_type": "metric",
        "batch_count": request.resource_metrics.len(),
        "metric_count": metric_count,
        "data_point_count": data_point_count,
        "first_metric_name": exported_metric.name,
        "collector_endpoint_class": "local_loopback_grpc",
        "retry_decision": "not_needed",
        "dropped_count": 0,
        "grpc_status": "ok",
        "runtime_error_mapping": "none",
        "cleanup_result": "shutdown_and_abort_server",
        "skip_reason": null
    });
    append_evidence(&evidence)?;

    Ok(())
}
