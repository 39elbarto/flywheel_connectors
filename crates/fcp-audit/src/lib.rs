//! FCP2 audit chain and receipt primitives.
//!
//! This crate provides protocol-level types for audit chains, decision receipts,
//! event filtering, and chain verification. These are the building blocks used
//! by higher-level crates (`fcp-core`, `fcp-cli`) to implement audit functionality.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ============================================================================
// Event type constants
// ============================================================================

/// Required audit event types (NORMATIVE).
pub mod event_types {
    /// Secret was accessed by an actor.
    pub const SECRET_ACCESS: &str = "secret.access";
    /// Capability was invoked.
    pub const CAPABILITY_INVOKE: &str = "capability.invoke";
    /// Privilege elevation was granted.
    pub const ELEVATION_GRANTED: &str = "elevation.granted";
    /// Declassification was granted.
    pub const DECLASSIFICATION_GRANTED: &str = "declassification.granted";
    /// Object transitioned between zones.
    pub const ZONE_TRANSITION: &str = "zone.transition";
    /// Revocation was issued.
    pub const REVOCATION_ISSUED: &str = "revocation.issued";
    /// Security violation detected.
    pub const SECURITY_VIOLATION: &str = "security.violation";
    /// Audit chain fork detected (critical).
    pub const AUDIT_FORK_DETECTED: &str = "audit.fork_detected";
}

// ============================================================================
// Severity
// ============================================================================

/// Severity level for audit events.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational event, no action required.
    #[default]
    Info,
    /// Warning event, may require attention.
    Warning,
    /// Error event, requires investigation.
    Error,
    /// Critical event, requires immediate action.
    Critical,
}

impl Severity {
    /// Returns the severity for a given event type string.
    #[must_use]
    pub fn for_event_type(event_type: &str) -> Self {
        match event_type {
            event_types::SECRET_ACCESS
            | event_types::ELEVATION_GRANTED
            | event_types::DECLASSIFICATION_GRANTED => Self::Warning,
            event_types::REVOCATION_ISSUED | event_types::SECURITY_VIOLATION => Self::Error,
            event_types::AUDIT_FORK_DETECTED => Self::Critical,
            _ => Self::Info,
        }
    }

    /// Returns true if this severity is at least as severe as `other`.
    #[must_use]
    pub const fn is_at_least(&self, other: Self) -> bool {
        *self as u8 >= other as u8
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================================
// TraceContext
// ============================================================================

/// W3C Trace Context compatible distributed trace context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    /// 16-byte trace ID encoded as hex string.
    pub trace_id: String,
    /// 8-byte span ID encoded as hex string.
    pub span_id: String,
    /// Trace flags (W3C trace-flags).
    #[serde(default)]
    pub flags: u8,
}

impl TraceContext {
    /// Create a new trace context.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            flags: 0,
        }
    }

    /// Create a trace context with flags.
    #[must_use]
    pub const fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Returns true if the sampled flag is set.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.flags
        )
    }
}

// ============================================================================
// AuditEntry
// ============================================================================

/// A single entry in the audit chain.
///
/// Represents an append-only, hash-linked audit event. Each entry links to its
/// predecessor via `prev` and carries a monotonic `seq` for O(1) freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry.
    pub id: String,
    /// Event type (e.g., "secret.access", "capability.invoke").
    pub event_type: String,
    /// Severity level.
    pub severity: Severity,
    /// Actor who triggered the event.
    pub actor: String,
    /// Zone where event occurred.
    pub zone_id: String,
    /// Monotonic chain sequence number.
    pub seq: u64,
    /// When event occurred (Unix timestamp seconds).
    pub occurred_at: u64,
    /// Previous entry ID in chain (hash link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// Correlation ID for request tracing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub correlation_id: String,
    /// Optional trace context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
    /// Connector ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Operation ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Additional metadata as key-value pairs.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metadata: std::collections::BTreeMap<String, serde_json::Value>,
}

impl AuditEntry {
    /// Check if this is a genesis entry (seq 0, no prev).
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.seq == 0 && self.prev.is_none()
    }

    /// Check if this entry follows another entry in the chain.
    #[must_use]
    pub fn follows(&self, other: &Self) -> bool {
        other
            .seq
            .checked_add(1)
            .is_some_and(|next_seq| self.seq == next_seq)
            && self.prev.as_deref() == Some(other.id.as_str())
    }

    /// Get the severity for this entry's event type.
    #[must_use]
    pub fn computed_severity(&self) -> Severity {
        Severity::for_event_type(&self.event_type)
    }
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[seq={}] {} by {} in {} at {}",
            self.seq, self.event_type, self.actor, self.zone_id, self.occurred_at
        )
    }
}

// ============================================================================
// AuditEntryBuilder
// ============================================================================

/// Builder for constructing `AuditEntry` instances.
#[derive(Debug, Clone, Default)]
pub struct AuditEntryBuilder {
    id: Option<String>,
    event_type: Option<String>,
    severity: Option<Severity>,
    actor: Option<String>,
    zone_id: Option<String>,
    seq: Option<u64>,
    occurred_at: Option<u64>,
    prev: Option<String>,
    correlation_id: Option<String>,
    trace_context: Option<TraceContext>,
    connector_id: Option<String>,
    operation_id: Option<String>,
    metadata: std::collections::BTreeMap<String, serde_json::Value>,
}

impl AuditEntryBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the entry ID.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the event type.
    #[must_use]
    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Set the severity.
    #[must_use]
    pub const fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the actor.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, zone_id: impl Into<String>) -> Self {
        self.zone_id = Some(zone_id.into());
        self
    }

    /// Set the sequence number.
    #[must_use]
    pub const fn seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set the occurred-at timestamp.
    #[must_use]
    pub const fn occurred_at(mut self, ts: u64) -> Self {
        self.occurred_at = Some(ts);
        self
    }

    /// Set the previous entry ID.
    #[must_use]
    pub fn prev(mut self, prev: impl Into<String>) -> Self {
        self.prev = Some(prev.into());
        self
    }

    /// Set the correlation ID.
    #[must_use]
    pub fn correlation_id(mut self, cid: impl Into<String>) -> Self {
        self.correlation_id = Some(cid.into());
        self
    }

    /// Set the trace context.
    #[must_use]
    pub fn trace_context(mut self, tc: TraceContext) -> Self {
        self.trace_context = Some(tc);
        self
    }

    /// Set the connector ID.
    #[must_use]
    pub fn connector_id(mut self, cid: impl Into<String>) -> Self {
        self.connector_id = Some(cid.into());
        self
    }

    /// Set the operation ID.
    #[must_use]
    pub fn operation_id(mut self, oid: impl Into<String>) -> Self {
        self.operation_id = Some(oid.into());
        self
    }

    /// Add a metadata key-value pair.
    #[must_use]
    pub fn meta(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Build the `AuditEntry`.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::BuilderMissingField` if required fields are not set.
    pub fn build(self) -> Result<AuditEntry, AuditError> {
        let id = self
            .id
            .ok_or_else(|| AuditError::BuilderMissingField("id".to_string()))?;
        let event_type = self
            .event_type
            .ok_or_else(|| AuditError::BuilderMissingField("event_type".to_string()))?;
        let actor = self
            .actor
            .ok_or_else(|| AuditError::BuilderMissingField("actor".to_string()))?;
        let zone_id = self
            .zone_id
            .ok_or_else(|| AuditError::BuilderMissingField("zone_id".to_string()))?;
        let seq = self
            .seq
            .ok_or_else(|| AuditError::BuilderMissingField("seq".to_string()))?;
        let occurred_at = self
            .occurred_at
            .ok_or_else(|| AuditError::BuilderMissingField("occurred_at".to_string()))?;

        let severity = self
            .severity
            .unwrap_or_else(|| Severity::for_event_type(&event_type));

        Ok(AuditEntry {
            id,
            event_type,
            severity,
            actor,
            zone_id,
            seq,
            occurred_at,
            prev: self.prev,
            correlation_id: self.correlation_id.unwrap_or_default(),
            trace_context: self.trace_context,
            connector_id: self.connector_id,
            operation_id: self.operation_id,
            metadata: self.metadata,
        })
    }
}

// ============================================================================
// ChainHead
// ============================================================================

/// Checkpoint of the audit chain head.
///
/// Enables fast sync without full chain traversal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainHead {
    /// Zone this head covers.
    pub zone_id: String,
    /// Head entry ID (tip of the chain).
    pub head_entry: String,
    /// Sequence number of the head entry.
    pub head_seq: u64,
    /// Coverage fraction (0.0-1.0) of expected nodes contributing.
    pub coverage: f64,
    /// Epoch identifier.
    pub epoch_id: String,
    /// Number of quorum signatures.
    pub signature_count: u32,
}

impl ChainHead {
    /// Returns true if coverage meets the given threshold.
    #[must_use]
    pub const fn meets_coverage(&self, threshold: f64) -> bool {
        self.coverage >= threshold
    }

    /// Returns true if this head has quorum signatures.
    #[must_use]
    pub const fn has_quorum(&self) -> bool {
        self.signature_count > 0
    }
}

impl fmt::Display for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChainHead(zone={}, seq={}, coverage={:.1}%)",
            self.zone_id,
            self.head_seq,
            self.coverage * 100.0
        )
    }
}

// ============================================================================
// Decision + DecisionReceipt
// ============================================================================

/// Decision outcome for capability/access evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Access/capability was allowed.
    Allow,
    /// Access/capability was denied.
    Deny,
}

impl Decision {
    /// Returns true if this is an Allow decision.
    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns true if this is a Deny decision.
    #[must_use]
    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// Decision receipt for explainable allow/deny.
///
/// Content-addressed "why allowed/denied" record with stable reason codes
/// and evidence references. This powers `fcp explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Unique receipt ID.
    pub id: String,
    /// The request that was evaluated.
    pub request_id: String,
    /// The decision outcome.
    pub decision: Decision,
    /// Stable reason code for programmatic handling.
    pub reason_code: String,
    /// Evidence references that support this decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Optional human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// When the decision was made (Unix timestamp seconds).
    pub decided_at: u64,
    /// Zone context.
    pub zone_id: String,
}

impl DecisionReceipt {
    /// Returns true if this receipt is an allow decision.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }

    /// Returns true if this receipt is a deny decision.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        self.decision.is_deny()
    }

    /// Returns true if this receipt has an explanation.
    #[must_use]
    pub const fn has_explanation(&self) -> bool {
        self.explanation.is_some()
    }

    /// Returns the number of evidence references.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecisionReceipt({}: {} for {} reason={})",
            self.id, self.decision, self.request_id, self.reason_code
        )
    }
}

// ============================================================================
// AuditFilter
// ============================================================================

/// Filter options for querying audit entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by connector ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Filter by operation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Filter by correlation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Filter by trace ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Filter by event type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Filter by actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Filter by minimum severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// Filter by zone ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
}

impl AuditFilter {
    /// Check if this filter matches the given entry.
    #[must_use]
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(ref cid) = self.connector_id {
            if entry.connector_id.as_ref() != Some(cid) {
                return false;
            }
        }
        if let Some(ref oid) = self.operation_id {
            if entry.operation_id.as_ref() != Some(oid) {
                return false;
            }
        }
        if let Some(ref corr) = self.correlation_id {
            if entry.correlation_id != *corr {
                return false;
            }
        }
        if let Some(ref tid) = self.trace_id {
            match &entry.trace_context {
                Some(tc) if tc.trace_id == *tid => {}
                _ => return false,
            }
        }
        if let Some(ref et) = self.event_type {
            if entry.event_type != *et {
                return false;
            }
        }
        if let Some(ref actor) = self.actor {
            if entry.actor != *actor {
                return false;
            }
        }
        if let Some(min_sev) = self.min_severity {
            if !entry.severity.is_at_least(min_sev) {
                return false;
            }
        }
        if let Some(ref zone) = self.zone_id {
            if entry.zone_id != *zone {
                return false;
            }
        }
        true
    }

    /// Check if any filter field is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.connector_id.is_none()
            && self.operation_id.is_none()
            && self.correlation_id.is_none()
            && self.trace_id.is_none()
            && self.event_type.is_none()
            && self.actor.is_none()
            && self.min_severity.is_none()
            && self.zone_id.is_none()
    }

    /// Count the number of active filter fields.
    #[must_use]
    pub const fn active_count(&self) -> usize {
        let mut count = 0;
        if self.connector_id.is_some() {
            count += 1;
        }
        if self.operation_id.is_some() {
            count += 1;
        }
        if self.correlation_id.is_some() {
            count += 1;
        }
        if self.trace_id.is_some() {
            count += 1;
        }
        if self.event_type.is_some() {
            count += 1;
        }
        if self.actor.is_some() {
            count += 1;
        }
        if self.min_severity.is_some() {
            count += 1;
        }
        if self.zone_id.is_some() {
            count += 1;
        }
        count
    }
}

impl fmt::Display for AuditFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "AuditFilter(none)");
        }
        write!(f, "AuditFilter({} active)", self.active_count())
    }
}

// ============================================================================
// VerifyStatus + VerifyIssue + VerifyReport
// ============================================================================

/// Status of audit chain verification.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyStatus {
    /// Chain is valid.
    #[default]
    Ok,
    /// Chain has warnings but is usable.
    Warn,
    /// Chain has critical issues.
    Fail,
}

impl VerifyStatus {
    /// Returns true if the status indicates success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns true if the status indicates failure.
    #[must_use]
    pub const fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for VerifyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Warn => write!(f, "warn"),
            Self::Fail => write!(f, "fail"),
        }
    }
}

/// An issue found during chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyIssue {
    /// Issue code (e.g., `audit.seq_gap`).
    pub code: String,
    /// Human-readable description.
    pub message: String,
    /// Sequence number where issue was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Entry ID where issue was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
}

impl VerifyIssue {
    /// Create a new verify issue.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            seq: None,
            entry_id: None,
        }
    }

    /// Set the sequence number context.
    #[must_use]
    pub const fn with_seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set the entry ID context.
    #[must_use]
    pub fn with_entry_id(mut self, entry_id: impl Into<String>) -> Self {
        self.entry_id = Some(entry_id.into());
        self
    }

    /// Returns true if this is a critical issue that causes verification failure.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        matches!(
            self.code.as_str(),
            "audit.fork_detected"
                | "audit.prev_mismatch"
                | "audit.seq_gap"
                | "audit.genesis_invalid"
                | "audit.head_mismatch"
                | "audit.head_seq_mismatch"
        )
    }
}

impl fmt::Display for VerifyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Report from audit chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Overall status.
    pub status: VerifyStatus,
    /// Zone ID (if scoped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    /// Number of entries in the chain.
    pub chain_len: usize,
    /// Head sequence (if head was provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    /// Head entry ID (if head was provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_entry: Option<String>,
    /// Issues found.
    #[serde(default)]
    pub issues: Vec<VerifyIssue>,
}

impl VerifyReport {
    /// Create an empty OK report.
    #[must_use]
    pub const fn ok(chain_len: usize) -> Self {
        Self {
            status: VerifyStatus::Ok,
            zone_id: None,
            chain_len,
            head_seq: None,
            head_entry: None,
            issues: Vec::new(),
        }
    }

    /// Returns true if no issues were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }

    /// Returns the number of critical issues.
    #[must_use]
    pub fn critical_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_critical()).count()
    }
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifyReport(status={}, chain_len={}, issues={})",
            self.status,
            self.chain_len,
            self.issues.len()
        )
    }
}

// ============================================================================
// Chain verification
// ============================================================================

/// Verify an audit chain for consistency.
///
/// Checks:
/// - Genesis entry has seq 0 and no prev
/// - Sequence numbers are monotonically increasing without gaps
/// - Each entry's `prev` points to the preceding entry's `id`
/// - If a head is provided, it matches the chain tip
///
/// # Arguments
///
/// * `entries` - Sorted audit entries (by seq, ascending)
/// * `head` - Optional chain head to verify against
/// * `zone_id` - Optional zone ID to scope verification
///
/// # Returns
///
/// A `VerifyReport` describing the chain's integrity.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn verify_chain(
    entries: &[AuditEntry],
    head: Option<&ChainHead>,
    zone_id: Option<&str>,
) -> VerifyReport {
    let mut issues = Vec::new();

    if entries.is_empty() {
        let mut report = VerifyReport::ok(0);
        report.zone_id = zone_id.map(ToString::to_string);
        if head.is_some() {
            issues.push(VerifyIssue::new(
                "audit.chain.empty",
                "head provided but chain is empty",
            ));
            report.issues = issues;
            report.status = VerifyStatus::Warn;
        }
        return report;
    }

    // Check zone filter
    if let Some(zone) = zone_id {
        for entry in entries {
            if entry.zone_id != zone {
                issues.push(
                    VerifyIssue::new(
                        "audit.zone_mismatch",
                        format!(
                            "entry zone {} does not match expected zone {}",
                            entry.zone_id, zone
                        ),
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }
        }
    }

    // Check duplicate seqs
    let mut seen_seq: std::collections::HashMap<u64, &str> = std::collections::HashMap::new();
    for entry in entries {
        if let Some(prev_id) = seen_seq.insert(entry.seq, &entry.id) {
            if prev_id != entry.id {
                issues.push(
                    VerifyIssue::new(
                        "audit.fork_detected",
                        "multiple entries share the same seq with different ids",
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }
        }
    }

    // Check genesis and chain linking
    let mut iter = entries.iter();
    if let Some(first) = iter.next() {
        if first.seq != 0 || first.prev.is_some() {
            issues.push(
                VerifyIssue::new(
                    "audit.genesis_invalid",
                    "genesis entry must have seq 0 and no prev",
                )
                .with_seq(first.seq)
                .with_entry_id(&first.id),
            );
        }

        let mut prev = first;
        for entry in iter {
            let expected_seq = prev.seq.saturating_add(1);
            if entry.seq != expected_seq {
                issues.push(
                    VerifyIssue::new(
                        "audit.seq_gap",
                        format!("expected seq {expected_seq}, found {}", entry.seq),
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }

            if entry.prev.as_deref() != Some(prev.id.as_str()) {
                issues.push(
                    VerifyIssue::new(
                        "audit.prev_mismatch",
                        "prev pointer does not match previous entry id",
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }

            prev = entry;
        }
    }

    // Verify head
    if let Some(head) = head {
        if let Some(last) = entries.last() {
            if head.head_entry != last.id {
                issues.push(
                    VerifyIssue::new(
                        "audit.head_mismatch",
                        "chain head does not reference chain tip",
                    )
                    .with_seq(last.seq)
                    .with_entry_id(&last.id),
                );
            }
            if head.head_seq != last.seq {
                issues.push(
                    VerifyIssue::new(
                        "audit.head_seq_mismatch",
                        "head seq does not match chain tip seq",
                    )
                    .with_seq(last.seq)
                    .with_entry_id(&last.id),
                );
            }
        }

        if let Some(zone) = zone_id {
            if head.zone_id != zone {
                issues.push(VerifyIssue::new(
                    "audit.head_zone_mismatch",
                    format!("head zone {} does not match {}", head.zone_id, zone),
                ));
            }
        }
    }

    let is_fail = issues.iter().any(VerifyIssue::is_critical);

    let status = if issues.is_empty() {
        VerifyStatus::Ok
    } else if is_fail {
        VerifyStatus::Fail
    } else {
        VerifyStatus::Warn
    };

    VerifyReport {
        status,
        zone_id: zone_id.map(ToString::to_string),
        chain_len: entries.len(),
        head_seq: head.map(|h| h.head_seq),
        head_entry: head.map(|h| h.head_entry.clone()),
        issues,
    }
}

// ============================================================================
// AuditError
// ============================================================================

/// Errors that can occur in audit operations.
#[derive(Debug, Clone, Error)]
pub enum AuditError {
    /// A required field was missing from the builder.
    #[error("builder missing required field: {0}")]
    BuilderMissingField(String),

    /// Chain verification failed.
    #[error("chain verification failed: {0}")]
    VerificationFailed(String),

    /// Zone was not found.
    #[error("zone '{0}' not found or not accessible")]
    ZoneNotFound(String),

    /// Audit chain is unavailable.
    #[error("audit chain for zone '{0}' is unavailable")]
    ChainUnavailable(String),

    /// Sequence number overflow.
    #[error("sequence number overflow at seq {0}")]
    SeqOverflow(u64),

    /// Invalid entry: describes what's wrong.
    #[error("invalid entry: {0}")]
    InvalidEntry(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Fork detected in the chain.
    #[error("fork detected at seq {0}")]
    ForkDetected(u64),
}

impl AuditError {
    /// Returns the FCP error code for this error variant.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::BuilderMissingField(_) => "FCP-4000",
            Self::VerificationFailed(_) => "FCP-5010",
            Self::ZoneNotFound(_) => "FCP-4001",
            Self::ChainUnavailable(_) => "FCP-5011",
            Self::SeqOverflow(_) => "FCP-5012",
            Self::InvalidEntry(_) => "FCP-4002",
            Self::SerializationError(_) => "FCP-5013",
            Self::ForkDetected(_) => "FCP-5014",
        }
    }
}

// ============================================================================
// FreshnessLevel
// ============================================================================

/// Freshness level for audit chain status reporting.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum FreshnessLevel {
    /// Chain is up to date.
    Fresh,
    /// Chain is slightly behind.
    Stale,
    /// Chain is significantly behind.
    Degraded,
    /// Chain data is missing or unavailable.
    #[default]
    Missing,
}

impl FreshnessLevel {
    /// Returns true if the chain is considered healthy.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

impl fmt::Display for FreshnessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh => write!(f, "fresh"),
            Self::Stale => write!(f, "stale"),
            Self::Degraded => write!(f, "degraded"),
            Self::Missing => write!(f, "missing"),
        }
    }
}

// ============================================================================
// AuditStatus
// ============================================================================

/// Status of the audit subsystem for a zone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditStatus {
    /// Freshness of the audit chain.
    pub freshness: FreshnessLevel,
    /// Current head sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    /// Coverage fraction (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<f64>,
    /// Optional reason/explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditStatus {
    /// Create a fresh status.
    #[must_use]
    pub const fn fresh(head_seq: u64, coverage: f64) -> Self {
        Self {
            freshness: FreshnessLevel::Fresh,
            head_seq: Some(head_seq),
            coverage: Some(coverage),
            reason: None,
        }
    }

    /// Create a missing status.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            freshness: FreshnessLevel::Missing,
            head_seq: None,
            coverage: None,
            reason: None,
        }
    }

    /// Add a reason to this status.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

impl Default for AuditStatus {
    fn default() -> Self {
        Self::missing()
    }
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuditStatus({})", self.freshness)?;
        if let Some(seq) = self.head_seq {
            write!(f, " seq={seq}")?;
        }
        if let Some(cov) = self.coverage {
            write!(f, " coverage={:.1}%", cov * 100.0)?;
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn genesis_entry() -> AuditEntry {
        AuditEntry {
            id: "entry-0".to_string(),
            event_type: event_types::CAPABILITY_INVOKE.to_string(),
            severity: Severity::Info,
            actor: "user:alice".to_string(),
            zone_id: "z:work".to_string(),
            seq: 0,
            occurred_at: 1_700_000_000,
            prev: None,
            correlation_id: "corr-0".to_string(),
            trace_context: None,
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            metadata: BTreeMap::new(),
        }
    }

    fn chain_entry(seq: u64, prev_id: &str) -> AuditEntry {
        AuditEntry {
            id: format!("entry-{seq}"),
            event_type: event_types::SECRET_ACCESS.to_string(),
            severity: Severity::Warning,
            actor: "user:bob".to_string(),
            zone_id: "z:work".to_string(),
            seq,
            occurred_at: 1_700_000_000 + seq * 60,
            prev: Some(prev_id.to_string()),
            correlation_id: format!("corr-{seq}"),
            trace_context: None,
            connector_id: None,
            operation_id: None,
            metadata: BTreeMap::new(),
        }
    }

    fn sample_head(entry_id: &str, seq: u64) -> ChainHead {
        ChainHead {
            zone_id: "z:work".to_string(),
            head_entry: entry_id.to_string(),
            head_seq: seq,
            coverage: 0.85,
            epoch_id: "epoch-1".to_string(),
            signature_count: 3,
        }
    }

    fn sample_receipt() -> DecisionReceipt {
        DecisionReceipt {
            id: "receipt-1".to_string(),
            request_id: "req-1".to_string(),
            decision: Decision::Allow,
            reason_code: "policy.match".to_string(),
            evidence: vec!["evidence-1".to_string(), "evidence-2".to_string()],
            explanation: Some("Policy matched capability grant".to_string()),
            decided_at: 1_700_000_000,
            zone_id: "z:work".to_string(),
        }
    }

    // ── event_types constants ────────────────────────────────────────────

    #[test]
    fn event_type_constants_are_valid() {
        assert_eq!(event_types::SECRET_ACCESS, "secret.access");
        assert_eq!(event_types::CAPABILITY_INVOKE, "capability.invoke");
        assert_eq!(event_types::ELEVATION_GRANTED, "elevation.granted");
        assert_eq!(
            event_types::DECLASSIFICATION_GRANTED,
            "declassification.granted"
        );
        assert_eq!(event_types::ZONE_TRANSITION, "zone.transition");
        assert_eq!(event_types::REVOCATION_ISSUED, "revocation.issued");
        assert_eq!(event_types::SECURITY_VIOLATION, "security.violation");
        assert_eq!(event_types::AUDIT_FORK_DETECTED, "audit.fork_detected");
    }

    #[test]
    fn event_type_constants_contain_dot() {
        let types = [
            event_types::SECRET_ACCESS,
            event_types::CAPABILITY_INVOKE,
            event_types::ELEVATION_GRANTED,
            event_types::DECLASSIFICATION_GRANTED,
            event_types::ZONE_TRANSITION,
            event_types::REVOCATION_ISSUED,
            event_types::SECURITY_VIOLATION,
            event_types::AUDIT_FORK_DETECTED,
        ];
        for t in types {
            assert!(t.contains('.'), "event type {t} should contain a dot");
        }
    }

    // ── Severity ─────────────────────────────────────────────────────────

    #[test]
    fn severity_default_is_info() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn severity_is_at_least() {
        assert!(Severity::Critical.is_at_least(Severity::Info));
        assert!(Severity::Warning.is_at_least(Severity::Warning));
        assert!(!Severity::Info.is_at_least(Severity::Warning));
    }

    #[test]
    fn severity_for_event_type_mapping() {
        assert_eq!(
            Severity::for_event_type(event_types::CAPABILITY_INVOKE),
            Severity::Info
        );
        assert_eq!(
            Severity::for_event_type(event_types::ZONE_TRANSITION),
            Severity::Info
        );
        assert_eq!(
            Severity::for_event_type(event_types::SECRET_ACCESS),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::ELEVATION_GRANTED),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::DECLASSIFICATION_GRANTED),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::REVOCATION_ISSUED),
            Severity::Error
        );
        assert_eq!(
            Severity::for_event_type(event_types::SECURITY_VIOLATION),
            Severity::Error
        );
        assert_eq!(
            Severity::for_event_type(event_types::AUDIT_FORK_DETECTED),
            Severity::Critical
        );
    }

    #[test]
    fn severity_for_unknown_event_type() {
        assert_eq!(Severity::for_event_type("custom.event"), Severity::Info);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let parsed: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, parsed);
        }
    }

    #[test]
    fn severity_serde_values() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn severity_debug() {
        let debug = format!("{:?}", Severity::Critical);
        assert_eq!(debug, "Critical");
    }

    #[test]
    fn severity_clone() {
        let sev = Severity::Warning;
        let copied = sev;
        assert_eq!(sev, copied);
    }

    #[test]
    fn severity_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Severity::Info);
        set.insert(Severity::Warning);
        set.insert(Severity::Info); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn severity_copy() {
        let sev = Severity::Error;
        let copied = sev;
        assert_eq!(sev, copied); // both still usable, Copy trait
    }

    // ── TraceContext ─────────────────────────────────────────────────────

    #[test]
    fn trace_context_new() {
        let tc = TraceContext::new("trace-id-123", "span-id-456");
        assert_eq!(tc.trace_id, "trace-id-123");
        assert_eq!(tc.span_id, "span-id-456");
        assert_eq!(tc.flags, 0);
    }

    #[test]
    fn trace_context_with_flags() {
        let tc = TraceContext::new("tid", "sid").with_flags(0x01);
        assert_eq!(tc.flags, 0x01);
        assert!(tc.is_sampled());
    }

    #[test]
    fn trace_context_not_sampled() {
        let tc = TraceContext::new("tid", "sid");
        assert!(!tc.is_sampled());
    }

    #[test]
    fn trace_context_sampled_flag() {
        let tc = TraceContext::new("tid", "sid").with_flags(0x03);
        assert!(tc.is_sampled()); // bit 0 is set
    }

    #[test]
    fn trace_context_display() {
        let tc = TraceContext::new("aabb", "ccdd").with_flags(1);
        assert_eq!(tc.to_string(), "00-aabb-ccdd-01");
    }

    #[test]
    fn trace_context_display_zero_flags() {
        let tc = TraceContext::new("aabb", "ccdd");
        assert_eq!(tc.to_string(), "00-aabb-ccdd-00");
    }

    #[test]
    fn trace_context_serde_roundtrip() {
        let tc = TraceContext::new("trace123", "span456").with_flags(1);
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    #[test]
    fn trace_context_serde_default_flags() {
        // flags has #[serde(default)] so should deserialize to 0 if missing
        let json = r#"{"trace_id":"t","span_id":"s"}"#;
        let tc: TraceContext = serde_json::from_str(json).unwrap();
        assert_eq!(tc.flags, 0);
    }

    #[test]
    fn trace_context_clone() {
        let tc = TraceContext::new("tid", "sid").with_flags(5);
        let cloned = tc.clone();
        assert_eq!(tc, cloned);
    }

    #[test]
    fn trace_context_debug() {
        let tc = TraceContext::new("tid", "sid");
        let debug = format!("{tc:?}");
        assert!(debug.contains("TraceContext"));
        assert!(debug.contains("tid"));
    }

    #[test]
    fn trace_context_eq() {
        let a = TraceContext::new("tid", "sid");
        let b = TraceContext::new("tid", "sid");
        let c = TraceContext::new("other", "sid");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn trace_context_empty_ids() {
        let tc = TraceContext::new("", "");
        assert_eq!(tc.trace_id, "");
        assert_eq!(tc.span_id, "");
        assert_eq!(tc.to_string(), "00---00");
    }

    #[test]
    fn trace_context_unicode_ids() {
        let tc = TraceContext::new("trace-\u{1F600}", "span-\u{1F680}");
        assert!(tc.trace_id.contains('\u{1F600}'));
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    // ── AuditEntry ───────────────────────────────────────────────────────

    #[test]
    fn audit_entry_is_genesis() {
        let entry = genesis_entry();
        assert!(entry.is_genesis());
    }

    #[test]
    fn audit_entry_not_genesis_with_prev() {
        let mut entry = genesis_entry();
        entry.prev = Some("prev-id".to_string());
        assert!(!entry.is_genesis());
    }

    #[test]
    fn audit_entry_not_genesis_nonzero_seq() {
        let mut entry = genesis_entry();
        entry.seq = 1;
        assert!(!entry.is_genesis());
    }

    #[test]
    fn audit_entry_follows() {
        let first = genesis_entry();
        let second = chain_entry(1, "entry-0");
        assert!(second.follows(&first));
    }

    #[test]
    fn audit_entry_follows_wrong_prev() {
        let first = genesis_entry();
        let second = chain_entry(1, "wrong-id");
        assert!(!second.follows(&first));
    }

    #[test]
    fn audit_entry_follows_wrong_seq() {
        let first = genesis_entry();
        let mut second = chain_entry(2, "entry-0"); // gap
        second.prev = Some("entry-0".to_string());
        assert!(!second.follows(&first));
    }

    #[test]
    fn audit_entry_follows_seq_overflow() {
        let mut first = genesis_entry();
        first.seq = u64::MAX;
        let second = chain_entry(0, "entry-0");
        assert!(!second.follows(&first)); // would overflow
    }

    #[test]
    fn audit_entry_computed_severity() {
        let entry = genesis_entry();
        assert_eq!(entry.computed_severity(), Severity::Info);

        let mut entry2 = genesis_entry();
        entry2.event_type = event_types::SECURITY_VIOLATION.to_string();
        assert_eq!(entry2.computed_severity(), Severity::Error);
    }

    #[test]
    fn audit_entry_display() {
        let entry = genesis_entry();
        let display = entry.to_string();
        assert!(display.contains("seq=0"));
        assert!(display.contains("capability.invoke"));
        assert!(display.contains("user:alice"));
        assert!(display.contains("z:work"));
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = genesis_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn audit_entry_serde_skips_none_fields() {
        let entry = genesis_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"prev\""));
        assert!(!json.contains("\"trace_context\""));
    }

    #[test]
    fn audit_entry_serde_skips_empty_metadata() {
        let entry = genesis_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"metadata\""));
    }

    #[test]
    fn audit_entry_serde_skips_empty_correlation_id() {
        let mut entry = genesis_entry();
        entry.correlation_id = String::new();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"correlation_id\""));
    }

    #[test]
    fn audit_entry_serde_with_metadata() {
        let mut entry = genesis_entry();
        entry
            .metadata
            .insert("key".to_string(), serde_json::json!("value"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"metadata\""));
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.metadata.get("key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn audit_entry_clone() {
        let entry = genesis_entry();
        let cloned = entry.clone();
        assert_eq!(entry.id, cloned.id);
        assert_eq!(entry.seq, cloned.seq);
    }

    #[test]
    fn audit_entry_debug() {
        let entry = genesis_entry();
        let debug = format!("{entry:?}");
        assert!(debug.contains("AuditEntry"));
        assert!(debug.contains("entry-0"));
    }

    #[test]
    fn audit_entry_eq() {
        let a = genesis_entry();
        let b = genesis_entry();
        assert_eq!(a, b);

        let mut c = genesis_entry();
        c.id = "different".to_string();
        assert_ne!(a, c);
    }

    #[test]
    fn audit_entry_with_trace_context() {
        let mut entry = genesis_entry();
        entry.trace_context = Some(TraceContext::new("trace-abc", "span-def"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("trace_context"));
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert!(parsed.trace_context.is_some());
        assert_eq!(parsed.trace_context.as_ref().unwrap().trace_id, "trace-abc");
    }

    #[test]
    fn audit_entry_unicode_actor() {
        let mut entry = genesis_entry();
        entry.actor = "user:\u{1F600}\u{1F680}".to_string();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.actor, "user:\u{1F600}\u{1F680}");
    }

    #[test]
    fn audit_entry_large_seq() {
        let mut entry = genesis_entry();
        entry.seq = u64::MAX;
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, u64::MAX);
    }

    #[test]
    fn audit_entry_empty_strings() {
        let entry = AuditEntry {
            id: String::new(),
            event_type: String::new(),
            severity: Severity::Info,
            actor: String::new(),
            zone_id: String::new(),
            seq: 0,
            occurred_at: 0,
            prev: None,
            correlation_id: String::new(),
            trace_context: None,
            connector_id: None,
            operation_id: None,
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    // ── AuditEntryBuilder ────────────────────────────────────────────────

    #[test]
    fn builder_basic() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::CAPABILITY_INVOKE)
            .actor("user:alice")
            .zone_id("z:work")
            .seq(0)
            .occurred_at(1_700_000_000)
            .build()
            .unwrap();

        assert_eq!(entry.id, "e-1");
        assert_eq!(entry.event_type, event_types::CAPABILITY_INVOKE);
        assert!(entry.is_genesis());
        // Severity auto-computed
        assert_eq!(entry.severity, Severity::Info);
    }

    #[test]
    fn builder_with_all_fields() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::SECRET_ACCESS)
            .severity(Severity::Critical)
            .actor("user:bob")
            .zone_id("z:prod")
            .seq(5)
            .occurred_at(1_700_000_300)
            .prev("e-0")
            .correlation_id("corr-5")
            .trace_context(TraceContext::new("tid", "sid"))
            .connector_id("fcp.slack:base:v1")
            .operation_id("send")
            .meta("key1", serde_json::json!(42))
            .build()
            .unwrap();

        assert_eq!(entry.severity, Severity::Critical); // explicit override
        assert_eq!(entry.prev, Some("e-0".to_string()));
        assert!(entry.trace_context.is_some());
        assert_eq!(entry.connector_id, Some("fcp.slack:base:v1".to_string()));
        assert_eq!(entry.operation_id, Some("send".to_string()));
        assert_eq!(entry.metadata.get("key1"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn builder_missing_id() {
        let result = AuditEntryBuilder::new()
            .event_type("test")
            .actor("alice")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn builder_missing_event_type() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .actor("alice")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("event_type"));
    }

    #[test]
    fn builder_missing_actor() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("actor"));
    }

    #[test]
    fn builder_missing_zone_id() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("alice")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zone_id"));
    }

    #[test]
    fn builder_missing_seq() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("alice")
            .zone_id("z:w")
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("seq"));
    }

    #[test]
    fn builder_missing_occurred_at() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("alice")
            .zone_id("z:w")
            .seq(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("occurred_at"));
    }

    #[test]
    fn builder_auto_severity() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::AUDIT_FORK_DETECTED)
            .actor("system")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.severity, Severity::Critical);
    }

    #[test]
    fn builder_default() {
        let builder = AuditEntryBuilder::default();
        let debug = format!("{builder:?}");
        assert!(debug.contains("AuditEntryBuilder"));
    }

    #[test]
    fn builder_clone() {
        let builder = AuditEntryBuilder::new().id("e-1").event_type("test");
        let cloned = builder.clone();
        let debug_orig = format!("{builder:?}");
        let debug_clone = format!("{cloned:?}");
        assert_eq!(debug_orig, debug_clone);
    }

    // ── ChainHead ────────────────────────────────────────────────────────

    #[test]
    fn chain_head_meets_coverage() {
        let head = sample_head("entry-5", 5);
        assert!(head.meets_coverage(0.80));
        assert!(head.meets_coverage(0.85));
        assert!(!head.meets_coverage(0.90));
    }

    #[test]
    fn chain_head_has_quorum() {
        let head = sample_head("entry-5", 5);
        assert!(head.has_quorum());

        let mut no_quorum = sample_head("entry-5", 5);
        no_quorum.signature_count = 0;
        assert!(!no_quorum.has_quorum());
    }

    #[test]
    fn chain_head_display() {
        let head = sample_head("entry-5", 5);
        let display = head.to_string();
        assert!(display.contains("z:work"));
        assert!(display.contains("seq=5"));
        assert!(display.contains("85.0%"));
    }

    #[test]
    fn chain_head_serde_roundtrip() {
        let head = sample_head("entry-5", 5);
        let json = serde_json::to_string(&head).unwrap();
        let parsed: ChainHead = serde_json::from_str(&json).unwrap();
        assert_eq!(head, parsed);
    }

    #[test]
    fn chain_head_clone() {
        let head = sample_head("entry-5", 5);
        let cloned = head.clone();
        assert_eq!(head.head_seq, cloned.head_seq);
        assert_eq!(head.zone_id, cloned.zone_id);
    }

    #[test]
    fn chain_head_debug() {
        let head = sample_head("entry-5", 5);
        let debug = format!("{head:?}");
        assert!(debug.contains("ChainHead"));
    }

    #[test]
    fn chain_head_zero_coverage() {
        let mut head = sample_head("entry-5", 5);
        head.coverage = 0.0;
        assert!(!head.meets_coverage(0.1));
        assert!(head.meets_coverage(0.0));
    }

    #[test]
    fn chain_head_full_coverage() {
        let mut head = sample_head("entry-5", 5);
        head.coverage = 1.0;
        assert!(head.meets_coverage(1.0));
    }

    // ── Decision ─────────────────────────────────────────────────────────

    #[test]
    fn decision_is_allow() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Allow.is_deny());
    }

    #[test]
    fn decision_is_deny() {
        assert!(Decision::Deny.is_deny());
        assert!(!Decision::Deny.is_allow());
    }

    #[test]
    fn decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn decision_serde_roundtrip() {
        for d in [Decision::Allow, Decision::Deny] {
            let json = serde_json::to_string(&d).unwrap();
            let parsed: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, parsed);
        }
    }

    #[test]
    fn decision_serde_values() {
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");
    }

    #[test]
    fn decision_clone() {
        let d = Decision::Allow;
        let copied = d;
        assert_eq!(d, copied);
    }

    #[test]
    fn decision_copy() {
        let d = Decision::Deny;
        let copied = d;
        assert_eq!(d, copied);
    }

    #[test]
    fn decision_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Decision::Allow);
        set.insert(Decision::Deny);
        set.insert(Decision::Allow);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn decision_debug() {
        assert_eq!(format!("{:?}", Decision::Allow), "Allow");
        assert_eq!(format!("{:?}", Decision::Deny), "Deny");
    }

    // ── DecisionReceipt ──────────────────────────────────────────────────

    #[test]
    fn receipt_is_allow() {
        let receipt = sample_receipt();
        assert!(receipt.is_allow());
        assert!(!receipt.is_deny());
    }

    #[test]
    fn receipt_is_deny() {
        let mut receipt = sample_receipt();
        receipt.decision = Decision::Deny;
        assert!(receipt.is_deny());
        assert!(!receipt.is_allow());
    }

    #[test]
    fn receipt_has_explanation() {
        let receipt = sample_receipt();
        assert!(receipt.has_explanation());

        let mut no_exp = sample_receipt();
        no_exp.explanation = None;
        assert!(!no_exp.has_explanation());
    }

    #[test]
    fn receipt_evidence_count() {
        let receipt = sample_receipt();
        assert_eq!(receipt.evidence_count(), 2);

        let mut no_ev = sample_receipt();
        no_ev.evidence.clear();
        assert_eq!(no_ev.evidence_count(), 0);
    }

    #[test]
    fn receipt_display() {
        let receipt = sample_receipt();
        let display = receipt.to_string();
        assert!(display.contains("receipt-1"));
        assert!(display.contains("allow"));
        assert!(display.contains("req-1"));
        assert!(display.contains("policy.match"));
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn receipt_serde_skips_none_explanation() {
        let mut receipt = sample_receipt();
        receipt.explanation = None;
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("explanation"));
    }

    #[test]
    fn receipt_serde_skips_empty_evidence() {
        let mut receipt = sample_receipt();
        receipt.evidence.clear();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("evidence"));
    }

    #[test]
    fn receipt_clone() {
        let receipt = sample_receipt();
        let cloned = receipt.clone();
        assert_eq!(receipt.id, cloned.id);
        assert_eq!(receipt.decision, cloned.decision);
    }

    #[test]
    fn receipt_debug() {
        let receipt = sample_receipt();
        let debug = format!("{receipt:?}");
        assert!(debug.contains("DecisionReceipt"));
    }

    // ── AuditFilter ──────────────────────────────────────────────────────

    #[test]
    fn filter_default_is_empty() {
        let filter = AuditFilter::default();
        assert!(filter.is_empty());
        assert_eq!(filter.active_count(), 0);
    }

    #[test]
    fn filter_matches_all_when_empty() {
        let filter = AuditFilter::default();
        let entry = genesis_entry();
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_connector_id() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            ..Default::default()
        };
        let entry = genesis_entry();
        assert!(filter.matches(&entry));

        let filter_wrong = AuditFilter {
            connector_id: Some("fcp.slack:base:v1".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&entry));
    }

    #[test]
    fn filter_connector_id_none_entry() {
        let filter = AuditFilter {
            connector_id: Some("any".to_string()),
            ..Default::default()
        };
        let mut entry = genesis_entry();
        entry.connector_id = None;
        assert!(!filter.matches(&entry));
    }

    #[test]
    fn filter_operation_id() {
        let filter = AuditFilter {
            operation_id: Some("send_message".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            operation_id: Some("other_op".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_correlation_id() {
        let filter = AuditFilter {
            correlation_id: Some("corr-0".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            correlation_id: Some("corr-999".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_trace_id() {
        let filter = AuditFilter {
            trace_id: Some("trace-abc".to_string()),
            ..Default::default()
        };
        // No trace context on genesis => no match
        assert!(!filter.matches(&genesis_entry()));

        let mut entry = genesis_entry();
        entry.trace_context = Some(TraceContext::new("trace-abc", "span-def"));
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_event_type() {
        let filter = AuditFilter {
            event_type: Some(event_types::CAPABILITY_INVOKE.to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            event_type: Some(event_types::SECRET_ACCESS.to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_actor() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            actor: Some("user:bob".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_min_severity() {
        let filter = AuditFilter {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };
        // Genesis entry is Info severity
        assert!(!filter.matches(&genesis_entry()));

        let mut entry = genesis_entry();
        entry.severity = Severity::Error;
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_zone_id() {
        let filter = AuditFilter {
            zone_id: Some("z:work".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            zone_id: Some("z:prod".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_multiple_fields() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            event_type: Some(event_types::CAPABILITY_INVOKE.to_string()),
            zone_id: Some("z:work".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));
        assert_eq!(filter.active_count(), 3);
        assert!(!filter.is_empty());
    }

    #[test]
    fn filter_active_count_all() {
        let filter = AuditFilter {
            connector_id: Some("c".to_string()),
            operation_id: Some("o".to_string()),
            correlation_id: Some("corr".to_string()),
            trace_id: Some("t".to_string()),
            event_type: Some("e".to_string()),
            actor: Some("a".to_string()),
            min_severity: Some(Severity::Info),
            zone_id: Some("z".to_string()),
        };
        assert_eq!(filter.active_count(), 8);
    }

    #[test]
    fn filter_display_empty() {
        let filter = AuditFilter::default();
        assert_eq!(filter.to_string(), "AuditFilter(none)");
    }

    #[test]
    fn filter_display_active() {
        let filter = AuditFilter {
            actor: Some("alice".to_string()),
            ..Default::default()
        };
        assert_eq!(filter.to_string(), "AuditFilter(1 active)");
    }

    #[test]
    fn filter_serde_roundtrip() {
        let filter = AuditFilter {
            connector_id: Some("c".to_string()),
            actor: Some("a".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&filter).unwrap();
        let parsed: AuditFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter, parsed);
    }

    #[test]
    fn filter_serde_skips_none() {
        let filter = AuditFilter::default();
        let json = serde_json::to_string(&filter).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn filter_clone() {
        let filter = AuditFilter {
            actor: Some("alice".to_string()),
            ..Default::default()
        };
        let cloned = filter.clone();
        assert_eq!(filter, cloned);
    }

    #[test]
    fn filter_debug() {
        let filter = AuditFilter::default();
        let debug = format!("{filter:?}");
        assert!(debug.contains("AuditFilter"));
    }

    // ── VerifyStatus ─────────────────────────────────────────────────────

    #[test]
    fn verify_status_is_ok() {
        assert!(VerifyStatus::Ok.is_ok());
        assert!(!VerifyStatus::Warn.is_ok());
        assert!(!VerifyStatus::Fail.is_ok());
    }

    #[test]
    fn verify_status_is_fail() {
        assert!(VerifyStatus::Fail.is_fail());
        assert!(!VerifyStatus::Ok.is_fail());
        assert!(!VerifyStatus::Warn.is_fail());
    }

    #[test]
    fn verify_status_default() {
        assert_eq!(VerifyStatus::default(), VerifyStatus::Ok);
    }

    #[test]
    fn verify_status_display() {
        assert_eq!(VerifyStatus::Ok.to_string(), "ok");
        assert_eq!(VerifyStatus::Warn.to_string(), "warn");
        assert_eq!(VerifyStatus::Fail.to_string(), "fail");
    }

    #[test]
    fn verify_status_serde_roundtrip() {
        for s in [VerifyStatus::Ok, VerifyStatus::Warn, VerifyStatus::Fail] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: VerifyStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }
    }

    #[test]
    fn verify_status_serde_values() {
        assert_eq!(serde_json::to_string(&VerifyStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&VerifyStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyStatus::Fail).unwrap(),
            "\"fail\""
        );
    }

    #[test]
    fn verify_status_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VerifyStatus::Ok);
        set.insert(VerifyStatus::Warn);
        set.insert(VerifyStatus::Ok);
        assert_eq!(set.len(), 2);
    }

    // ── VerifyIssue ──────────────────────────────────────────────────────

    #[test]
    fn verify_issue_new() {
        let issue = VerifyIssue::new("audit.test", "test message");
        assert_eq!(issue.code, "audit.test");
        assert_eq!(issue.message, "test message");
        assert!(issue.seq.is_none());
        assert!(issue.entry_id.is_none());
    }

    #[test]
    fn verify_issue_with_seq() {
        let issue = VerifyIssue::new("audit.test", "msg").with_seq(42);
        assert_eq!(issue.seq, Some(42));
    }

    #[test]
    fn verify_issue_with_entry_id() {
        let issue = VerifyIssue::new("audit.test", "msg").with_entry_id("entry-5");
        assert_eq!(issue.entry_id, Some("entry-5".to_string()));
    }

    #[test]
    fn verify_issue_chained_builders() {
        let issue = VerifyIssue::new("audit.test", "msg")
            .with_seq(10)
            .with_entry_id("e-10");
        assert_eq!(issue.seq, Some(10));
        assert_eq!(issue.entry_id, Some("e-10".to_string()));
    }

    #[test]
    fn verify_issue_is_critical_true() {
        let critical_codes = [
            "audit.fork_detected",
            "audit.prev_mismatch",
            "audit.seq_gap",
            "audit.genesis_invalid",
            "audit.head_mismatch",
            "audit.head_seq_mismatch",
        ];
        for code in critical_codes {
            let issue = VerifyIssue::new(code, "msg");
            assert!(issue.is_critical(), "{code} should be critical");
        }
    }

    #[test]
    fn verify_issue_is_critical_false() {
        let non_critical = ["audit.zone_mismatch", "audit.chain.empty", "custom.issue"];
        for code in non_critical {
            let issue = VerifyIssue::new(code, "msg");
            assert!(!issue.is_critical(), "{code} should not be critical");
        }
    }

    #[test]
    fn verify_issue_display() {
        let issue = VerifyIssue::new("audit.test", "something went wrong");
        assert_eq!(issue.to_string(), "audit.test: something went wrong");
    }

    #[test]
    fn verify_issue_serde_roundtrip() {
        let issue = VerifyIssue::new("audit.test", "msg")
            .with_seq(5)
            .with_entry_id("e-5");
        let json = serde_json::to_string(&issue).unwrap();
        let parsed: VerifyIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, parsed);
    }

    #[test]
    fn verify_issue_serde_skips_none() {
        let issue = VerifyIssue::new("audit.test", "msg");
        let json = serde_json::to_string(&issue).unwrap();
        assert!(!json.contains("seq"));
        assert!(!json.contains("entry_id"));
    }

    #[test]
    fn verify_issue_clone() {
        let issue = VerifyIssue::new("code", "msg").with_seq(1);
        let cloned = issue.clone();
        assert_eq!(issue, cloned);
    }

    // ── VerifyReport ─────────────────────────────────────────────────────

    #[test]
    fn verify_report_ok() {
        let report = VerifyReport::ok(10);
        assert!(report.is_clean());
        assert_eq!(report.chain_len, 10);
        assert_eq!(report.status, VerifyStatus::Ok);
        assert_eq!(report.critical_count(), 0);
    }

    #[test]
    fn verify_report_critical_count() {
        let mut report = VerifyReport::ok(5);
        report.issues.push(VerifyIssue::new("audit.seq_gap", "gap"));
        report
            .issues
            .push(VerifyIssue::new("audit.zone_mismatch", "zone"));
        report
            .issues
            .push(VerifyIssue::new("audit.fork_detected", "fork"));
        assert_eq!(report.critical_count(), 2);
    }

    #[test]
    fn verify_report_display() {
        let report = VerifyReport::ok(5);
        let display = report.to_string();
        assert!(display.contains("ok"));
        assert!(display.contains("chain_len=5"));
        assert!(display.contains("issues=0"));
    }

    #[test]
    fn verify_report_serde_roundtrip() {
        let mut report = VerifyReport::ok(3);
        report.zone_id = Some("z:work".to_string());
        report.head_seq = Some(2);
        report.head_entry = Some("entry-2".to_string());
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn verify_report_serde_skips_none() {
        let report = VerifyReport::ok(0);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("zone_id"));
        assert!(!json.contains("head_seq"));
        assert!(!json.contains("head_entry"));
    }

    #[test]
    fn verify_report_clone() {
        let report = VerifyReport::ok(5);
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    // ── verify_chain function ────────────────────────────────────────────

    #[test]
    fn verify_chain_empty() {
        let report = verify_chain(&[], None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 0);
        assert!(report.is_clean());
    }

    #[test]
    fn verify_chain_empty_with_head() {
        let head = sample_head("entry-0", 0);
        let report = verify_chain(&[], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Warn);
        assert!(!report.is_clean());
    }

    #[test]
    fn verify_chain_valid_single() {
        let entries = [genesis_entry()];
        let report = verify_chain(&entries, None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 1);
    }

    #[test]
    fn verify_chain_valid_three_entries() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let e2 = chain_entry(2, "entry-1");
        let entries = [e0, e1, e2];
        let report = verify_chain(&entries, None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 3);
    }

    #[test]
    fn verify_chain_invalid_genesis_nonzero_seq() {
        let mut entry = genesis_entry();
        entry.seq = 1;
        let report = verify_chain(&[entry], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.genesis_invalid")
        );
    }

    #[test]
    fn verify_chain_invalid_genesis_with_prev() {
        let mut entry = genesis_entry();
        entry.prev = Some("some-prev".to_string());
        let report = verify_chain(&[entry], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
    }

    #[test]
    fn verify_chain_seq_gap() {
        let e0 = genesis_entry();
        let e2 = chain_entry(2, "entry-0"); // seq gap: 0 -> 2
        let report = verify_chain(&[e0, e2], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(report.issues.iter().any(|i| i.code == "audit.seq_gap"));
    }

    #[test]
    fn verify_chain_prev_mismatch() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "wrong-prev");
        let report = verify_chain(&[e0, e1], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.prev_mismatch")
        );
    }

    #[test]
    fn verify_chain_zone_mismatch() {
        let mut entry = genesis_entry();
        entry.zone_id = "z:other".to_string();
        let report = verify_chain(&[entry], None, Some("z:work"));
        assert!(!report.is_clean());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.zone_mismatch")
        );
    }

    #[test]
    fn verify_chain_duplicate_seq_fork() {
        let e0 = genesis_entry();
        let mut e0_fork = genesis_entry();
        e0_fork.id = "entry-0-fork".to_string();
        let report = verify_chain(&[e0, e0_fork], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.fork_detected")
        );
    }

    #[test]
    fn verify_chain_head_match() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("entry-1", 1);
        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert!(report.status.is_ok());
    }

    #[test]
    fn verify_chain_head_mismatch_entry() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("wrong-entry", 1);
        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_mismatch")
        );
    }

    #[test]
    fn verify_chain_head_mismatch_seq() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("entry-1", 99);
        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_seq_mismatch")
        );
    }

    #[test]
    fn verify_chain_head_zone_mismatch() {
        let e0 = genesis_entry();
        let mut head = sample_head("entry-0", 0);
        head.zone_id = "z:other".to_string();
        let report = verify_chain(&[e0], Some(&head), Some("z:work"));
        assert!(!report.is_clean());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_zone_mismatch")
        );
    }

    #[test]
    fn verify_chain_with_zone_filter_ok() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let report = verify_chain(&[e0, e1], None, Some("z:work"));
        assert!(report.status.is_ok());
        assert_eq!(report.zone_id, Some("z:work".to_string()));
    }

    // ── AuditError ───────────────────────────────────────────────────────

    #[test]
    fn audit_error_display_builder_missing() {
        let err = AuditError::BuilderMissingField("id".to_string());
        assert_eq!(err.to_string(), "builder missing required field: id");
    }

    #[test]
    fn audit_error_display_verification_failed() {
        let err = AuditError::VerificationFailed("chain broken".to_string());
        assert!(err.to_string().contains("chain broken"));
    }

    #[test]
    fn audit_error_display_zone_not_found() {
        let err = AuditError::ZoneNotFound("z:test".to_string());
        assert!(err.to_string().contains("z:test"));
    }

    #[test]
    fn audit_error_display_chain_unavailable() {
        let err = AuditError::ChainUnavailable("z:prod".to_string());
        assert!(err.to_string().contains("z:prod"));
    }

    #[test]
    fn audit_error_display_seq_overflow() {
        let err = AuditError::SeqOverflow(u64::MAX);
        assert!(err.to_string().contains("overflow"));
    }

    #[test]
    fn audit_error_display_invalid_entry() {
        let err = AuditError::InvalidEntry("bad data".to_string());
        assert!(err.to_string().contains("bad data"));
    }

    #[test]
    fn audit_error_display_serialization() {
        let err = AuditError::SerializationError("parse fail".to_string());
        assert!(err.to_string().contains("parse fail"));
    }

    #[test]
    fn audit_error_display_fork() {
        let err = AuditError::ForkDetected(42);
        assert!(err.to_string().contains("42"));
    }

    #[test]
    fn audit_error_codes() {
        assert_eq!(
            AuditError::BuilderMissingField(String::new()).error_code(),
            "FCP-4000"
        );
        assert_eq!(
            AuditError::VerificationFailed(String::new()).error_code(),
            "FCP-5010"
        );
        assert_eq!(
            AuditError::ZoneNotFound(String::new()).error_code(),
            "FCP-4001"
        );
        assert_eq!(
            AuditError::ChainUnavailable(String::new()).error_code(),
            "FCP-5011"
        );
        assert_eq!(AuditError::SeqOverflow(0).error_code(), "FCP-5012");
        assert_eq!(
            AuditError::InvalidEntry(String::new()).error_code(),
            "FCP-4002"
        );
        assert_eq!(
            AuditError::SerializationError(String::new()).error_code(),
            "FCP-5013"
        );
        assert_eq!(AuditError::ForkDetected(0).error_code(), "FCP-5014");
    }

    #[test]
    fn audit_error_debug() {
        let err = AuditError::ForkDetected(10);
        let debug = format!("{err:?}");
        assert!(debug.contains("ForkDetected"));
        assert!(debug.contains("10"));
    }

    #[test]
    fn audit_error_clone() {
        let err = AuditError::ZoneNotFound("z:test".to_string());
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn audit_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AuditError::ForkDetected(1));
        assert!(err.to_string().contains("fork"));
    }

    // ── FreshnessLevel ───────────────────────────────────────────────────

    #[test]
    fn freshness_default_is_missing() {
        assert_eq!(FreshnessLevel::default(), FreshnessLevel::Missing);
    }

    #[test]
    fn freshness_is_healthy() {
        assert!(FreshnessLevel::Fresh.is_healthy());
        assert!(!FreshnessLevel::Stale.is_healthy());
        assert!(!FreshnessLevel::Degraded.is_healthy());
        assert!(!FreshnessLevel::Missing.is_healthy());
    }

    #[test]
    fn freshness_ordering() {
        assert!(FreshnessLevel::Fresh < FreshnessLevel::Stale);
        assert!(FreshnessLevel::Stale < FreshnessLevel::Degraded);
        assert!(FreshnessLevel::Degraded < FreshnessLevel::Missing);
    }

    #[test]
    fn freshness_display() {
        assert_eq!(FreshnessLevel::Fresh.to_string(), "fresh");
        assert_eq!(FreshnessLevel::Stale.to_string(), "stale");
        assert_eq!(FreshnessLevel::Degraded.to_string(), "degraded");
        assert_eq!(FreshnessLevel::Missing.to_string(), "missing");
    }

    #[test]
    fn freshness_serde_roundtrip() {
        for lvl in [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::Degraded,
            FreshnessLevel::Missing,
        ] {
            let json = serde_json::to_string(&lvl).unwrap();
            let parsed: FreshnessLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(lvl, parsed);
        }
    }

    #[test]
    fn freshness_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessLevel::Fresh);
        set.insert(FreshnessLevel::Missing);
        set.insert(FreshnessLevel::Fresh);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn freshness_clone() {
        let lvl = FreshnessLevel::Degraded;
        let copied = lvl;
        assert_eq!(lvl, copied);
    }

    #[test]
    fn freshness_copy() {
        let lvl = FreshnessLevel::Stale;
        let copied = lvl;
        assert_eq!(lvl, copied);
    }

    // ── AuditStatus ──────────────────────────────────────────────────────

    #[test]
    fn audit_status_fresh() {
        let status = AuditStatus::fresh(100, 0.95);
        assert_eq!(status.freshness, FreshnessLevel::Fresh);
        assert_eq!(status.head_seq, Some(100));
        assert_eq!(status.coverage, Some(0.95));
        assert!(status.reason.is_none());
    }

    #[test]
    fn audit_status_missing() {
        let status = AuditStatus::missing();
        assert_eq!(status.freshness, FreshnessLevel::Missing);
        assert!(status.head_seq.is_none());
        assert!(status.coverage.is_none());
    }

    #[test]
    fn audit_status_default_is_missing() {
        let status = AuditStatus::default();
        assert_eq!(status.freshness, FreshnessLevel::Missing);
    }

    #[test]
    fn audit_status_with_reason() {
        let status = AuditStatus::fresh(50, 0.5).with_reason("partial coverage");
        assert_eq!(status.reason, Some("partial coverage".to_string()));
    }

    #[test]
    fn audit_status_display_fresh() {
        let status = AuditStatus::fresh(100, 0.95);
        let display = status.to_string();
        assert!(display.contains("fresh"));
        assert!(display.contains("seq=100"));
        assert!(display.contains("95.0%"));
    }

    #[test]
    fn audit_status_display_missing() {
        let status = AuditStatus::missing();
        let display = status.to_string();
        assert!(display.contains("missing"));
        assert!(!display.contains("seq="));
    }

    #[test]
    fn audit_status_serde_roundtrip() {
        let status = AuditStatus::fresh(200, 0.75).with_reason("test");
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AuditStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn audit_status_serde_skips_none() {
        let status = AuditStatus::missing();
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("head_seq"));
        assert!(!json.contains("coverage"));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn audit_status_clone() {
        let status = AuditStatus::fresh(10, 0.5);
        let cloned = status.clone();
        assert_eq!(status.freshness, cloned.freshness);
        assert_eq!(status.head_seq, cloned.head_seq);
    }

    #[test]
    fn audit_status_debug() {
        let status = AuditStatus::fresh(10, 0.5);
        let debug = format!("{status:?}");
        assert!(debug.contains("AuditStatus"));
    }
}
