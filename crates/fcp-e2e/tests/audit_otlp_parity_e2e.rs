use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use fcp_audit::otlp_export::{
    AuditOtlpExportError, AuditOtlpResource, AuditOtlpSpan, AuditOtlpSpanSink,
    FireAndForgetExporter,
};
use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};

const ZONE: &str = "z:work";
const SECRET: &str = "sk-live-never-export-to-otlp";

#[derive(Debug, Default)]
struct RecordingCollector {
    spans: Arc<Mutex<Vec<AuditOtlpSpan>>>,
}

impl RecordingCollector {
    fn spans(&self) -> Arc<Mutex<Vec<AuditOtlpSpan>>> {
        Arc::clone(&self.spans)
    }
}

impl AuditOtlpSpanSink for RecordingCollector {
    fn export(&self, span: &AuditOtlpSpan) -> Result<(), AuditOtlpExportError> {
        self.spans
            .lock()
            .expect("recording collector lock poisoned")
            .push(span.clone());
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecoveringCollector {
    fail: AtomicBool,
    spans: Arc<Mutex<Vec<AuditOtlpSpan>>>,
}

#[derive(Debug, Clone)]
struct RecoveringCollectorSink(Arc<RecoveringCollector>);

impl RecoveringCollector {
    fn failing() -> Self {
        Self {
            fail: AtomicBool::new(true),
            spans: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_recovered(&self) {
        self.fail.store(false, Ordering::SeqCst);
    }

    fn spans(&self) -> Arc<Mutex<Vec<AuditOtlpSpan>>> {
        Arc::clone(&self.spans)
    }
}

impl AuditOtlpSpanSink for RecoveringCollectorSink {
    fn export(&self, span: &AuditOtlpSpan) -> Result<(), AuditOtlpExportError> {
        if self.0.fail.load(Ordering::SeqCst) {
            return Err(AuditOtlpExportError::new("collector_unreachable"));
        }
        self.0
            .spans
            .lock()
            .expect("recovering collector lock poisoned")
            .push(span.clone());
        Ok(())
    }
}

fn ctx(seq: usize) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: ZONE.to_string(),
        actor: "agent:otlp-e2e".to_string(),
        connector_id: "fcp.audit-fixture".to_string(),
        operation: "audit.append".to_string(),
        operation_id: format!("op-{seq}"),
        correlation_id: Some(format!("corr-{seq}")),
        occurred_at: 1_715_630_400,
    }
}

fn chain_with_recording_collector(
    capacity: usize,
) -> (InvokeAuditChain, Arc<Mutex<Vec<AuditOtlpSpan>>>) {
    let collector = RecordingCollector::default();
    let spans = collector.spans();
    let exporter = FireAndForgetExporter::with_sink(
        capacity,
        AuditOtlpResource::fcp_host("0.1.0", "host-otlp-e2e"),
        collector,
    );
    (
        InvokeAuditChain::new_with_otlp_exporter(Arc::new(exporter)),
        spans,
    )
}

fn wait_for_spans(spans: &Arc<Mutex<Vec<AuditOtlpSpan>>>, expected: usize) -> Vec<AuditOtlpSpan> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = spans.lock().expect("span collector lock poisoned").clone();
        if snapshot.len() >= expected {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected} audit OTLP spans; saw {}",
            snapshot.len()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_drops(chain: &InvokeAuditChain, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let dropped = chain
            .otlp_status()
            .expect("OTLP exporter status")
            .dropped_total;
        if dropped >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected} dropped audit OTLP spans; saw {dropped}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn test_1000_appends_emit_1000_spans() {
    let (chain, spans) = chain_with_recording_collector(1_024);

    for index in 0..1_000 {
        chain
            .append(&ctx(index), InvokePhase::PreflightAllow)
            .expect("audit append must succeed");
    }

    let spans = wait_for_spans(&spans, 1_000);
    assert_eq!(spans.len(), 1_000);
    assert_eq!(chain.otlp_status().expect("OTLP status").dropped_total, 0);
}

#[test]
fn test_span_fields_byte_equivalent_to_audit() {
    let (chain, spans) = chain_with_recording_collector(8);
    let entry = chain
        .append(&ctx(1), InvokePhase::PreflightAllow)
        .expect("audit append must succeed");

    let spans = wait_for_spans(&spans, 1);
    let span = &spans[0];
    assert_eq!(
        span.attributes["fcp.audit.entry.entry_id"],
        serde_json::json!(&entry.id[..32])
    );
    assert_eq!(
        span.attributes["fcp.audit.entry.hlc"],
        serde_json::json!("1715630400000000000.0")
    );
    assert_eq!(
        span.attributes["fcp.audit.entry.zone"],
        serde_json::json!(entry.zone_id)
    );
    assert_eq!(
        span.attributes["fcp.audit.entry.decision"],
        serde_json::json!("accepted")
    );
    assert_eq!(
        span.attributes["fcp.audit.entry.reason_code"],
        serde_json::json!("Ok")
    );
    assert_eq!(
        span.attributes["fcp.audit.entry.seq"],
        serde_json::json!(entry.seq)
    );
}

#[test]
fn test_no_secret_leak_in_spans() {
    let (chain, spans) = chain_with_recording_collector(8);
    chain
        .append(
            &ctx(1),
            InvokePhase::DispatchError {
                error: format!("upstream returned credential {SECRET}"),
                duration_ms: 7,
            },
        )
        .expect("audit append must succeed even for dispatch error");

    let serialized = serde_json::to_string(&wait_for_spans(&spans, 1)).expect("serialize spans");
    assert!(
        !serialized.contains(SECRET),
        "OTLP span leaked secret material: {serialized}"
    );
    assert!(serialized.contains("DispatchError"));
}

#[test]
fn test_otlp_collector_down_does_not_block_append() {
    let collector = Arc::new(RecoveringCollector::failing());
    let exporter = FireAndForgetExporter::with_sink(
        8,
        AuditOtlpResource::fcp_host("0.1.0", "host-otlp-e2e"),
        RecoveringCollectorSink(Arc::clone(&collector)),
    );
    let chain = InvokeAuditChain::new_with_otlp_exporter(Arc::new(exporter));

    let started = Instant::now();
    for index in 0..100 {
        chain
            .append(&ctx(index), InvokePhase::PreflightAllow)
            .expect("audit append must not depend on collector availability");
    }

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "audit appends blocked on unavailable OTLP collector"
    );
    wait_for_drops(&chain, 100);
}

#[test]
fn test_collector_drop_recovers_when_restored() {
    let collector = Arc::new(RecoveringCollector::failing());
    let spans = collector.spans();
    let exporter = FireAndForgetExporter::with_sink(
        8,
        AuditOtlpResource::fcp_host("0.1.0", "host-otlp-e2e"),
        RecoveringCollectorSink(Arc::clone(&collector)),
    );
    let chain = InvokeAuditChain::new_with_otlp_exporter(Arc::new(exporter));

    chain
        .append(&ctx(1), InvokePhase::PreflightAllow)
        .expect("first append succeeds while collector is down");
    wait_for_drops(&chain, 1);

    collector.set_recovered();
    chain
        .append(&ctx(2), InvokePhase::PreflightAllow)
        .expect("append succeeds after collector recovers");

    let spans = wait_for_spans(&spans, 1);
    assert_eq!(spans.len(), 1);
    assert!(spans[0].status.message.is_empty());
    assert!(
        chain
            .otlp_status()
            .expect("OTLP status")
            .last_export_unix_nano
            .is_some()
    );
}
