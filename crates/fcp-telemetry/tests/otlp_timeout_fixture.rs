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

struct SlowTraceCollector {
    seen_requests: Arc<AtomicU64>,
}

impl SlowTraceCollector {
    const fn new(seen_requests: Arc<AtomicU64>) -> Self {
        Self { seen_requests }
    }
}

#[tonic::async_trait]
impl TraceService for SlowTraceCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let metadata = request.metadata();
        let marker = metadata
            .get("x-fcp-e2e")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if marker != "otlp-timeout-fixture" {
            return Err(tonic::Status::invalid_argument(
                "missing x-fcp-e2e timeout marker",
            ));
        }
        if metadata.get("authorization").is_none() {
            return Err(tonic::Status::invalid_argument(
                "missing authorization metadata",
            ));
        }

        self.seen_requests.fetch_add(1, Ordering::SeqCst);
        time::sleep(Duration::from_secs(5)).await;

        Ok(tonic::Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

async fn start_slow_collector()
-> Result<(SocketAddr, Arc<AtomicU64>, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let seen_requests = Arc::new(AtomicU64::new(0));
    let service = TraceServiceServer::new(SlowTraceCollector::new(Arc::clone(&seen_requests)));

    let handle = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await;
    });

    Ok((addr, seen_requests, handle))
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
        "cargo test -p fcp-telemetry --test otlp_timeout_fixture --features otlp".to_string()
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
        Ok(()) => Err(io::Error::other("slow collector should time out OTLP trace flush").into()),
        Err(error) => Ok(error),
    }
}

fn classify_error(error: &TelemetryError) -> &'static str {
    let rendered = error.to_string().to_ascii_lowercase();
    if rendered.contains("cancel") {
        "collector_request_cancelled"
    } else if rendered.contains("timeout")
        || rendered.contains("timed out")
        || rendered.contains("deadline")
        || rendered.contains("elapsed")
    {
        "collector_timeout"
    } else {
        "collector_export_error"
    }
}

const fn cleanup_result(shutdown_result: &Result<(), TelemetryError>) -> &'static str {
    if shutdown_result.is_ok() {
        "shutdown_after_timeout"
    } else {
        "shutdown_reported_error_after_timeout"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_trace_exporter_times_out_slow_collector_and_cleans_up() -> Result<(), Box<dyn Error>>
{
    append_evidence(&json!({
        "event": "otlp_e2e_start",
        "ts_ms": now_millis(),
        "command_line": command_line(),
        "git_revision": git_revision(),
        "collector_endpoint_class": "local_loopback_slow_grpc",
        "signal_type": "trace"
    }))?;

    let (addr, seen_requests, server) = start_slow_collector().await?;
    let endpoint = format!("http://{addr}");
    init_otlp_tracer_with_sample_rate_options_and_timeout(
        "fcp-telemetry-timeout-e2e",
        &endpoint,
        1.0,
        &[
            OtlpHeader::new("x-fcp-e2e", "otlp-timeout-fixture")?,
            OtlpHeader::new("authorization", "Bearer redacted-test-token")?,
        ],
        &[OtlpResourceAttribute::new("fcp.zone", "z:otlp-timeout")?],
        Some(Duration::from_millis(150)),
    )?;

    {
        let mut span = FcpSpan::new("telemetry.otlp.timeout")
            .server()
            .connector_id("fcp.telemetry")
            .operation("otlp.export")
            .attribute("fcp.signal_type", "trace")
            .start();
        span.record_error("collector timed out before export completed");
    }

    let flush_error = expect_flush_error(flush_otlp_tracer())?;
    let error_mapping = classify_error(&flush_error);
    let request_count = seen_requests.load(Ordering::SeqCst);
    let shutdown_result = shutdown_otlp_tracer();
    abort_server(server).await?;

    assert!(
        matches!(flush_error, TelemetryError::TracingInit(_)),
        "flush error should map through TelemetryError::TracingInit: {flush_error:?}",
    );
    assert!(
        matches!(
            error_mapping,
            "collector_timeout" | "collector_request_cancelled"
        ),
        "flush error should preserve timeout/cancellation classification: {flush_error:?}",
    );
    assert!(
        request_count > 0,
        "slow collector should receive at least one export request before timeout",
    );

    append_evidence(&json!({
        "event": "otlp_e2e_export_failed",
        "ts_ms": now_millis(),
        "signal_type": "trace",
        "batch_count": 0,
        "span_count": 1,
        "first_span_name": "telemetry.otlp.timeout",
        "collector_endpoint_class": "local_loopback_slow_grpc",
        "collector_request_count": request_count,
        "retry_decision": "collector_timeout_cancelled",
        "dropped_count": 1,
        "grpc_status": "deadline_exceeded",
        "runtime_error_mapping": error_mapping,
        "timeout_ms": 150,
        "cancellation_checkpoint": "client_export_timeout_before_collector_response",
        "cleanup_result": cleanup_result(&shutdown_result),
        "skip_reason": null
    }))?;

    Ok(())
}
