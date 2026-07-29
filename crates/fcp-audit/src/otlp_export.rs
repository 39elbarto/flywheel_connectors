//! Fire-and-forget OTLP span export for audit-chain appends.
//!
//! The audit chain is the canonical record. This module builds the narrow span
//! payload promised by `docs/operator/audit_otlp_parity.md` and sends it through
//! a bounded, non-blocking queue so collector failures cannot block appends.

#![allow(clippy::module_name_repetitions)]

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{AuditEntry, Severity};

/// Constant OTLP span name for audit entries.
pub const AUDIT_OTLP_SPAN_NAME: &str = "fcp.audit.entry";
const AUDIT_OTLP_SPAN_KIND: &str = "INTERNAL";
const SYNTHETIC_DURATION_NANOS: u64 = 1_000;
const DEFAULT_PREV_HASH_PREFIX: &str = "0000000000000000";
const DEFAULT_SIG_KIND: &str = "ed25519";
const ERROR_FULL_ESCALATION_AFTER: Duration = Duration::from_secs(5);

/// Resource fields attached to audit OTLP spans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOtlpResource {
    /// OpenTelemetry service name.
    #[serde(rename = "service.name")]
    pub service_name: String,
    /// Build or crate version.
    #[serde(rename = "service.version", skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,
    /// Host/runtime instance id.
    #[serde(
        rename = "service.instance.id",
        skip_serializing_if = "Option::is_none"
    )]
    pub service_instance_id: Option<String>,
}

impl AuditOtlpResource {
    /// Build a resource descriptor for the FCP host runtime.
    #[must_use]
    pub fn fcp_host(version: impl Into<String>, instance_id: impl Into<String>) -> Self {
        Self {
            service_name: "fcp-host".to_string(),
            service_version: Some(version.into()),
            service_instance_id: Some(instance_id.into()),
        }
    }
}

impl Default for AuditOtlpResource {
    fn default() -> Self {
        Self {
            service_name: "fcp-host".to_string(),
            service_version: None,
            service_instance_id: None,
        }
    }
}

/// OTLP span status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOtlpStatus {
    /// `OK` for accepted decisions, `ERROR` for rejected decisions.
    pub code: String,
    /// Empty for OK spans; reason code for ERROR spans.
    pub message: String,
}

/// JSON-serializable audit OTLP span body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOtlpSpan {
    /// Constant span name, `fcp.audit.entry`.
    pub name: String,
    /// Constant span kind, `INTERNAL`.
    pub kind: String,
    /// Status mapped from the audit decision.
    pub status: AuditOtlpStatus,
    /// Start timestamp in Unix nanoseconds.
    pub start_time_unix_nano: u64,
    /// End timestamp in Unix nanoseconds.
    pub end_time_unix_nano: u64,
    /// Narrow audit attributes. No full entry body is copied.
    pub attributes: BTreeMap<String, Value>,
    /// Runtime resource attributes.
    pub resource: AuditOtlpResource,
}

impl AuditOtlpSpan {
    /// Build the parity span body for an audit entry.
    #[must_use]
    pub fn from_entry(entry: &AuditEntry, resource: AuditOtlpResource) -> Self {
        let physical_ns = entry.hlc.physical_ms.saturating_mul(1_000_000);
        let counter = entry.hlc.logical;
        let decision = decision_for_entry(entry);
        let reason_code = reason_code_for_entry(entry, decision);
        let status = if decision == "accepted" {
            AuditOtlpStatus {
                code: "OK".to_string(),
                message: String::new(),
            }
        } else {
            AuditOtlpStatus {
                code: "ERROR".to_string(),
                message: reason_code.clone(),
            }
        };

        let mut attributes = BTreeMap::new();
        attributes.insert(
            "fcp.audit.entry.entry_id".to_string(),
            json!(entry_id_prefix(entry)),
        );
        attributes.insert(
            "fcp.audit.entry.hlc".to_string(),
            json!(format!("{physical_ns}.{counter}")),
        );
        attributes.insert("fcp.audit.entry.hlc.l".to_string(), json!(physical_ns));
        attributes.insert("fcp.audit.entry.hlc.c".to_string(), json!(counter));
        attributes.insert(
            "fcp.audit.entry.hlc.node_id".to_string(),
            json!(&entry.hlc.node_id),
        );
        attributes.insert("fcp.audit.entry.zone".to_string(), json!(&entry.zone_id));
        attributes.insert("fcp.audit.entry.decision".to_string(), json!(decision));
        attributes.insert(
            "fcp.audit.entry.reason_code".to_string(),
            json!(reason_code),
        );
        attributes.insert(
            "fcp.audit.entry.quorum_height".to_string(),
            json!(quorum_height(entry)),
        );
        attributes.insert(
            "fcp.audit.entry.sig_kinds_present".to_string(),
            json!(sig_kinds_present(entry)),
        );
        attributes.insert("fcp.audit.entry.seq".to_string(), json!(entry.seq));
        attributes.insert(
            "fcp.audit.entry.prev_hash_prefix".to_string(),
            json!(prev_hash_prefix(entry)),
        );

        Self {
            name: AUDIT_OTLP_SPAN_NAME.to_string(),
            kind: AUDIT_OTLP_SPAN_KIND.to_string(),
            status,
            start_time_unix_nano: physical_ns,
            end_time_unix_nano: physical_ns.saturating_add(SYNTHETIC_DURATION_NANOS),
            attributes,
            resource,
        }
    }
}

/// Stable exporter status for admin surfaces and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditOtlpExporterStatus {
    /// Current approximate queue depth.
    pub queue_depth: usize,
    /// Configured queue capacity.
    pub queue_capacity: usize,
    /// Total spans dropped due to queue pressure, worker disconnect, or sink failure.
    pub dropped_total: u64,
    /// Last successful export timestamp in Unix nanoseconds.
    pub last_export_unix_nano: Option<u64>,
}

/// Export outcome for the non-blocking enqueue path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOtlpEnqueueOutcome {
    /// Span was accepted by the background worker queue.
    Enqueued,
    /// Span was dropped synchronously before enqueue.
    Dropped(AuditOtlpDropReason),
}

/// Drop reason emitted by the fire-and-forget path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOtlpDropReason {
    /// The bounded queue is full.
    QueueFull,
    /// The background worker is no longer receiving spans.
    WorkerDisconnected,
}

/// Sink-side export error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOtlpExportError {
    message: String,
}

impl AuditOtlpExportError {
    /// Create a redaction-safe sink error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Redaction-safe error text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for AuditOtlpExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AuditOtlpExportError {}

/// Export target used by the background worker.
pub trait AuditOtlpSpanSink: Send + Sync + 'static {
    /// Export one already-redacted audit span.
    ///
    /// Implementations must not block indefinitely. Return an error instead
    /// when a collector is unavailable or applying backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`AuditOtlpExportError`] when the sink cannot accept the span.
    fn export(&self, span: &AuditOtlpSpan) -> Result<(), AuditOtlpExportError>;
}

/// Sink that drops spans after they leave the exporter queue.
#[derive(Debug, Default)]
pub struct NoopAuditOtlpSpanSink;

impl AuditOtlpSpanSink for NoopAuditOtlpSpanSink {
    fn export(&self, _span: &AuditOtlpSpan) -> Result<(), AuditOtlpExportError> {
        Ok(())
    }
}

/// Bounded, non-blocking audit OTLP exporter.
#[derive(Debug)]
pub struct FireAndForgetExporter {
    sender: SyncSender<AuditOtlpSpan>,
    stats: Arc<ExporterStats>,
    resource: AuditOtlpResource,
}

#[derive(Debug)]
struct ExporterStats {
    queue_depth: AtomicUsize,
    queue_capacity: usize,
    dropped_total: AtomicU64,
    last_export_unix_nano: AtomicU64,
    outage_started_millis: AtomicU64,
    outage_drop_count: AtomicU64,
    first_full_millis: Mutex<Option<u128>>,
}

impl ExporterStats {
    const fn new(queue_capacity: usize) -> Self {
        Self {
            queue_depth: AtomicUsize::new(0),
            queue_capacity,
            dropped_total: AtomicU64::new(0),
            last_export_unix_nano: AtomicU64::new(0),
            outage_started_millis: AtomicU64::new(0),
            outage_drop_count: AtomicU64::new(0),
            first_full_millis: Mutex::new(None),
        }
    }
}

impl FireAndForgetExporter {
    /// Create an exporter with a no-op sink.
    #[must_use]
    pub fn noop(queue_capacity: usize, resource: AuditOtlpResource) -> Self {
        Self::with_sink(queue_capacity, resource, NoopAuditOtlpSpanSink)
    }

    /// Create an exporter backed by `sink`.
    ///
    /// # Panics
    ///
    /// Panics if the background exporter thread cannot be spawned.
    #[must_use]
    pub fn with_sink<S>(queue_capacity: usize, resource: AuditOtlpResource, sink: S) -> Self
    where
        S: AuditOtlpSpanSink,
    {
        let queue_capacity = queue_capacity.max(1);
        let (sender, receiver) = sync_channel(queue_capacity);
        let stats = Arc::new(ExporterStats::new(queue_capacity));
        let worker_stats = Arc::clone(&stats);
        let sink = Arc::new(sink);

        thread::Builder::new()
            .name("fcp-audit-otlp-export".to_string())
            .spawn(move || {
                while let Ok(span) = receiver.recv() {
                    worker_stats.queue_depth.fetch_sub(1, Ordering::SeqCst);
                    if let Err(error) = sink.export(&span) {
                        record_sink_drop(&worker_stats, &span, &error);
                    } else {
                        record_sink_success(&worker_stats);
                    }
                }
            })
            .expect("failed to spawn audit OTLP exporter thread");

        Self {
            sender,
            stats,
            resource,
        }
    }

    /// Convert and enqueue an audit entry without blocking on export.
    #[must_use]
    pub fn try_export_entry(&self, entry: &AuditEntry) -> AuditOtlpEnqueueOutcome {
        self.try_export_span(AuditOtlpSpan::from_entry(entry, self.resource.clone()))
    }

    /// Enqueue an already-built span without blocking on export.
    #[must_use]
    pub fn try_export_span(&self, span: AuditOtlpSpan) -> AuditOtlpEnqueueOutcome {
        let depth_after = self.stats.queue_depth.fetch_add(1, Ordering::SeqCst) + 1;
        match self.sender.try_send(span) {
            Ok(()) => {
                self.record_queue_depth(depth_after);
                AuditOtlpEnqueueOutcome::Enqueued
            }
            Err(TrySendError::Full(span)) => {
                self.stats.queue_depth.fetch_sub(1, Ordering::SeqCst);
                self.record_enqueue_drop(&span, AuditOtlpDropReason::QueueFull);
                AuditOtlpEnqueueOutcome::Dropped(AuditOtlpDropReason::QueueFull)
            }
            Err(TrySendError::Disconnected(span)) => {
                self.stats.queue_depth.fetch_sub(1, Ordering::SeqCst);
                self.record_enqueue_drop(&span, AuditOtlpDropReason::WorkerDisconnected);
                AuditOtlpEnqueueOutcome::Dropped(AuditOtlpDropReason::WorkerDisconnected)
            }
        }
    }

    /// Snapshot exporter counters.
    #[must_use]
    pub fn status(&self) -> AuditOtlpExporterStatus {
        let last_export = self.stats.last_export_unix_nano.load(Ordering::SeqCst);
        AuditOtlpExporterStatus {
            queue_depth: self.stats.queue_depth.load(Ordering::SeqCst),
            queue_capacity: self.stats.queue_capacity,
            dropped_total: self.stats.dropped_total.load(Ordering::SeqCst),
            last_export_unix_nano: (last_export != 0).then_some(last_export),
        }
    }

    fn record_queue_depth(&self, depth_after: usize) {
        let capacity = self.stats.queue_capacity.max(1);
        if depth_after.saturating_mul(100) >= capacity.saturating_mul(80) {
            tracing::warn!(
                event = "otlp_queue_high_water",
                queue_depth = depth_after,
                queue_capacity = capacity,
                "audit OTLP queue reached high-water mark"
            );
        }

        if depth_after < capacity {
            if let Ok(mut first_full) = self.stats.first_full_millis.lock() {
                *first_full = None;
            }
        }
    }

    fn record_enqueue_drop(&self, span: &AuditOtlpSpan, reason: AuditOtlpDropReason) {
        let dropped_count_total = self.stats.dropped_total.fetch_add(1, Ordering::SeqCst) + 1;
        let reason_str = match reason {
            AuditOtlpDropReason::QueueFull => "queue_full",
            AuditOtlpDropReason::WorkerDisconnected => "worker_disconnected",
        };
        tracing::warn!(
            event = "otlp_drop",
            entry_id = %entry_id_attr(span),
            reason = reason_str,
            dropped_count_total,
            last_attempt_ms = 0u64,
            "audit OTLP span dropped before enqueue"
        );

        if reason == AuditOtlpDropReason::QueueFull {
            self.record_queue_full_escalation();
        }
    }

    fn record_queue_full_escalation(&self) {
        let now = now_millis();
        let Ok(mut first_full) = self.stats.first_full_millis.lock() else {
            return;
        };
        let first = first_full.get_or_insert(now);
        if now.saturating_sub(*first) >= ERROR_FULL_ESCALATION_AFTER.as_millis() {
            tracing::error!(
                event = "otlp_queue_full_escalated",
                queue_capacity = self.stats.queue_capacity,
                dropped_total = self.stats.dropped_total.load(Ordering::SeqCst),
                "audit OTLP queue stayed full past escalation budget"
            );
        }
    }
}

fn record_sink_drop(stats: &ExporterStats, span: &AuditOtlpSpan, error: &AuditOtlpExportError) {
    let dropped_count_total = stats.dropped_total.fetch_add(1, Ordering::SeqCst) + 1;
    let now = now_millis_u64();
    stats
        .outage_started_millis
        .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst)
        .ok();
    stats.outage_drop_count.fetch_add(1, Ordering::SeqCst);
    tracing::warn!(
        event = "otlp_drop",
        entry_id = %entry_id_attr(span),
        reason = "collector_unreachable",
        dropped_count_total,
        last_attempt_ms = 0u64,
        error = %error,
        "audit OTLP sink rejected span"
    );
}

fn record_sink_success(stats: &ExporterStats) {
    stats
        .last_export_unix_nano
        .store(now_unix_nanos(), Ordering::SeqCst);
    let outage_started = stats.outage_started_millis.swap(0, Ordering::SeqCst);
    let dropped_during_outage = stats.outage_drop_count.swap(0, Ordering::SeqCst);
    if outage_started != 0 || dropped_during_outage != 0 {
        let outage_secs = now_millis_u64()
            .saturating_sub(outage_started)
            .saturating_div(1_000);
        tracing::info!(
            event = "otlp_resume",
            dropped_during_outage,
            outage_secs,
            "audit OTLP sink resumed"
        );
    }
}

fn entry_id_attr(span: &AuditOtlpSpan) -> String {
    span.attributes
        .get("fcp.audit.entry.entry_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn entry_id_prefix(entry: &AuditEntry) -> String {
    let id = if entry.id.len() >= 32 {
        entry.id.as_str()
    } else {
        ""
    };
    if id.len() >= 32 && id.bytes().take(32).all(|byte| byte.is_ascii_hexdigit()) {
        id[..32].to_ascii_lowercase()
    } else {
        "0".repeat(32)
    }
}

fn decision_for_entry(entry: &AuditEntry) -> &'static str {
    if let Some(decision) = metadata_string(entry, "decision") {
        return match decision {
            "accepted" => "accepted",
            "rejected_predicate" => "rejected_predicate",
            "rejected_revocation" => "rejected_revocation",
            "rejected_expired" => "rejected_expired",
            _ => severity_decision(entry.severity),
        };
    }

    let event_type = entry.event_type.as_str();
    if event_type.contains("revocation") {
        "rejected_revocation"
    } else if event_type.contains("expired") {
        "rejected_expired"
    } else if event_type.contains("deny") || event_type.contains("error") {
        "rejected_predicate"
    } else {
        severity_decision(entry.severity)
    }
}

const fn severity_decision(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "accepted",
        Severity::Warning | Severity::Error | Severity::Critical => "rejected_predicate",
    }
}

fn reason_code_for_entry(entry: &AuditEntry, decision: &str) -> String {
    if let Some(reason_code) = metadata_string(entry, "reason_code") {
        return reason_code.to_string();
    }
    if decision == "accepted" {
        "Ok".to_string()
    } else if entry.event_type.contains("revocation") {
        "RevokedBeforeUse".to_string()
    } else if entry.event_type.contains("expired") {
        "Expired".to_string()
    } else if entry.event_type.contains("deny") {
        "RejectedPredicate".to_string()
    } else if entry.event_type.contains("error") {
        "DispatchError".to_string()
    } else {
        "RejectedPredicate".to_string()
    }
}

fn quorum_height(entry: &AuditEntry) -> u64 {
    metadata_u64(entry, "quorum_height").unwrap_or(0)
}

fn sig_kinds_present(entry: &AuditEntry) -> Vec<String> {
    if let Some(Value::Array(values)) = entry.metadata.get("sig_kinds_present") {
        let mut kinds = values
            .iter()
            .filter_map(Value::as_str)
            .filter(|kind| matches!(*kind, "ed25519" | "ml_dsa_65" | "bls_aggregate" | "stark"))
            .map(str::to_string)
            .collect::<Vec<_>>();
        kinds.sort();
        kinds.dedup();
        if !kinds.is_empty() {
            return kinds;
        }
    }

    vec![DEFAULT_SIG_KIND.to_string()]
}

fn prev_hash_prefix(entry: &AuditEntry) -> String {
    entry
        .prev
        .as_deref()
        .filter(|prev| prev.len() >= 16 && prev.bytes().take(16).all(|b| b.is_ascii_hexdigit()))
        .map_or_else(
            || DEFAULT_PREV_HASH_PREFIX.to_string(),
            |prev| prev[..16].to_ascii_lowercase(),
        )
}

fn metadata_string<'a>(entry: &'a AuditEntry, key: &str) -> Option<&'a str> {
    entry.metadata.get(key).and_then(Value::as_str)
}

fn metadata_u64(entry: &AuditEntry, key: &str) -> Option<u64> {
    entry.metadata.get(key).and_then(Value::as_u64)
}

fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn now_millis_u64() -> u64 {
    u64::try_from(now_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditEntryBuilder, event_types};

    #[derive(Debug)]
    struct RecordingSink {
        spans: Arc<Mutex<Vec<AuditOtlpSpan>>>,
    }

    impl AuditOtlpSpanSink for RecordingSink {
        fn export(&self, span: &AuditOtlpSpan) -> Result<(), AuditOtlpExportError> {
            self.spans.lock().expect("spans lock").push(span.clone());
            Ok(())
        }
    }

    fn entry() -> AuditEntry {
        AuditEntryBuilder::new()
            .event_type(event_types::CAPABILITY_INVOKE)
            .severity(Severity::Info)
            .actor("agent:test")
            .zone_id("z:work")
            .seq(7)
            .occurred_at(1_715_630_400)
            .prev("9a2b3c4d5e6f7081123456789abcdef0")
            .meta("decision", json!("accepted"))
            .meta("reason_code", json!("Ok"))
            .meta("hlc", json!("1715630400000000000.0"))
            .meta("sig_kinds_present", json!(["ed25519", "ml_dsa_65"]))
            .build_with_computed_id()
            .expect("entry")
    }

    #[test]
    fn span_from_entry_matches_contract_fields() {
        let span = AuditOtlpSpan::from_entry(
            &entry(),
            AuditOtlpResource::fcp_host("0.1.0", "host-alpha-01"),
        );

        assert_eq!(span.name, AUDIT_OTLP_SPAN_NAME);
        assert_eq!(span.kind, AUDIT_OTLP_SPAN_KIND);
        assert_eq!(span.status.code, "OK");
        assert_eq!(span.status.message, "");
        assert_eq!(span.start_time_unix_nano, 1_715_630_400_000_000_000);
        assert_eq!(span.end_time_unix_nano, 1_715_630_400_000_001_000);
        assert_eq!(
            span.attributes["fcp.audit.entry.hlc"],
            json!("1715630400000000000.0")
        );
        assert_eq!(
            span.attributes["fcp.audit.entry.hlc.l"],
            json!(1_715_630_400_000_000_000u64)
        );
        assert_eq!(span.attributes["fcp.audit.entry.hlc.c"], json!(0));
        assert_eq!(
            span.attributes["fcp.audit.entry.hlc.node_id"],
            json!("agent:test")
        );
        assert_eq!(span.attributes["fcp.audit.entry.zone"], json!("z:work"));
        assert_eq!(
            span.attributes["fcp.audit.entry.decision"],
            json!("accepted")
        );
        assert_eq!(span.attributes["fcp.audit.entry.reason_code"], json!("Ok"));
        assert_eq!(span.attributes["fcp.audit.entry.seq"], json!(7));
        assert_eq!(
            span.attributes["fcp.audit.entry.prev_hash_prefix"],
            json!("9a2b3c4d5e6f7081")
        );
    }

    #[test]
    fn exporter_enqueues_without_blocking() {
        let spans = Arc::new(Mutex::new(Vec::new()));
        let exporter = FireAndForgetExporter::with_sink(
            4,
            AuditOtlpResource::default(),
            RecordingSink {
                spans: Arc::clone(&spans),
            },
        );

        assert_eq!(
            exporter.try_export_entry(&entry()),
            AuditOtlpEnqueueOutcome::Enqueued
        );

        for _ in 0..20 {
            if spans.lock().expect("spans lock").len() == 1 {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("export worker did not record span");
    }
}
