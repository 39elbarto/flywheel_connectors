//! Mesh Trace Capture - Types and infrastructure for deterministic trace replay.
//!
//! This module provides the foundation for capturing mesh events (routing decisions,
//! admission control outcomes, gossip state, lease operations) for debugging and
//! incident analysis.
//!
//! # Architecture
//!
//! - [`TraceEvent`]: Enum of all capturable mesh events
//! - [`RedactionPolicy`]: Controls sensitive field redaction
//! - [`CapturedTrace`]: Sequence of events for replay
//! - [`TraceCapture`]: Capture configuration and buffer management
//!
//! # Example
//!
//! ```rust
//! use fcp_telemetry::trace_capture::{
//!     TraceEvent, RedactionPolicy, CapturedTrace, RoutingDecision,
//! };
//!
//! // Create a captured trace
//! let mut trace = CapturedTrace::new("mesh-debug-001");
//!
//! // Add routing decision event
//! trace.push(TraceEvent::Routing(RoutingDecision {
//!     timestamp: 1706832000000,
//!     trace_id: "abc123".to_string(),
//!     source_node: "node-1".to_string(),
//!     target_node: Some("node-2".to_string()),
//!     object_id: "obj-xyz".to_string(),
//!     path_type: "direct".to_string(),
//!     decision: "routed".to_string(),
//!     reason: None,
//! }));
//!
//! // Apply redaction before export
//! let policy = RedactionPolicy::default();
//! let redacted = trace.with_redaction(&policy);
//! ```

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

// ============================================================================
// Redaction Policy
// ============================================================================

/// Policy for redacting sensitive fields from trace events.
///
/// Ensures traces can be exported without leaking secrets, PII, or tokens.
#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    /// Field names to redact (exact match).
    pub redact_fields: HashSet<String>,
    /// Field name patterns to redact (prefix match).
    pub redact_prefixes: Vec<String>,
    /// Whether to hash redacted values (allows correlation without exposure).
    pub hash_redacted: bool,
    /// Redaction marker for replaced values.
    pub redaction_marker: String,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            redact_fields: [
                "password",
                "api_key",
                "secret",
                "token",
                "authorization",
                "credential",
                "private_key",
                "session_key",
                "bearer",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            redact_prefixes: vec![
                "x-api-".to_string(),
                "x-auth-".to_string(),
                "secret_".to_string(),
            ],
            hash_redacted: false,
            redaction_marker: "[REDACTED]".to_string(),
        }
    }
}

impl RedactionPolicy {
    /// Create a new empty redaction policy.
    #[must_use]
    pub fn none() -> Self {
        Self {
            redact_fields: HashSet::new(),
            redact_prefixes: Vec::new(),
            hash_redacted: false,
            redaction_marker: "[REDACTED]".to_string(),
        }
    }

    /// Add a field to redact.
    #[must_use]
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.redact_fields.insert(field.into());
        self
    }

    /// Add a prefix pattern to redact.
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.redact_prefixes.push(prefix.into());
        self
    }

    /// Enable hashing of redacted values for correlation.
    #[must_use]
    pub const fn with_hash_redacted(mut self, enabled: bool) -> Self {
        self.hash_redacted = enabled;
        self
    }

    /// Set custom redaction marker.
    #[must_use]
    pub fn with_marker(mut self, marker: impl Into<String>) -> Self {
        self.redaction_marker = marker.into();
        self
    }

    /// Check if a field name should be redacted.
    #[must_use]
    pub fn should_redact(&self, field_name: &str) -> bool {
        let lower = field_name.to_lowercase();

        // Exact match
        if self.redact_fields.contains(&lower) {
            return true;
        }

        // Prefix match
        for prefix in &self.redact_prefixes {
            if lower.starts_with(&prefix.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Redact a value, optionally hashing it.
    #[must_use]
    pub fn redact_value(&self, original: &str) -> String {
        if self.hash_redacted {
            // Use first 8 chars of SHA-256 for correlation
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(original.as_bytes());
            format!("[REDACTED:{}]", hex::encode(&hash[..4]))
        } else {
            self.redaction_marker.clone()
        }
    }
}

// ============================================================================
// Trace Events
// ============================================================================

/// A mesh trace event for capture and replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum TraceEvent {
    /// Routing decision for symbol or control-plane message.
    Routing(RoutingDecision),
    /// Admission control outcome.
    Admission(AdmissionOutcome),
    /// Gossip state change.
    Gossip(GossipEvent),
    /// Lease operation.
    Lease(LeaseEvent),
    /// Session establishment.
    Session(SessionEvent),
    /// Policy enforcement decision.
    Policy(PolicyDecision),
}

impl TraceEvent {
    /// Get the timestamp of this event.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        match self {
            Self::Routing(e) => e.timestamp,
            Self::Admission(e) => e.timestamp,
            Self::Gossip(e) => e.timestamp,
            Self::Lease(e) => e.timestamp,
            Self::Session(e) => e.timestamp,
            Self::Policy(e) => e.timestamp,
        }
    }

    /// Get the trace ID of this event.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        match self {
            Self::Routing(e) => &e.trace_id,
            Self::Admission(e) => &e.trace_id,
            Self::Gossip(e) => &e.trace_id,
            Self::Lease(e) => &e.trace_id,
            Self::Session(e) => &e.trace_id,
            Self::Policy(e) => &e.trace_id,
        }
    }

    /// Apply redaction policy to this event.
    #[must_use]
    pub fn with_redaction(&self, policy: &RedactionPolicy) -> Self {
        match self {
            Self::Routing(e) => Self::Routing(e.with_redaction(policy)),
            Self::Admission(e) => Self::Admission(e.with_redaction(policy)),
            Self::Gossip(e) => Self::Gossip(e.with_redaction(policy)),
            Self::Lease(e) => Self::Lease(e.with_redaction(policy)),
            Self::Session(e) => Self::Session(e.with_redaction(policy)),
            Self::Policy(e) => Self::Policy(e.with_redaction(policy)),
        }
    }
}

/// Routing decision for symbol or control-plane message delivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingDecision {
    /// Timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// W3C trace ID.
    pub trace_id: String,
    /// Source node ID.
    pub source_node: String,
    /// Target node ID (if routed).
    pub target_node: Option<String>,
    /// Object ID being routed.
    pub object_id: String,
    /// Path type selected (direct, mesh, derp, funnel).
    pub path_type: String,
    /// Decision outcome (routed, dropped, deferred).
    pub decision: String,
    /// Reason for decision (if not routed).
    pub reason: Option<String>,
}

impl RoutingDecision {
    fn with_redaction(&self, _policy: &RedactionPolicy) -> Self {
        // Routing decisions don't typically contain sensitive fields
        self.clone()
    }
}

/// Admission control outcome for incoming request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionOutcome {
    /// Timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// W3C trace ID.
    pub trace_id: String,
    /// Peer node ID.
    pub peer_node: String,
    /// Request type (`symbol_request`, `invoke`, `gossip`).
    pub request_type: String,
    /// Decision outcome (admit, reject, throttle, quarantine).
    pub decision: String,
    /// Reason code (e.g., FCP-5001).
    pub reason_code: Option<String>,
    /// Budget remaining after this request.
    pub budget_remaining: Option<u64>,
    /// Whether peer was authenticated.
    pub authenticated: bool,
}

impl AdmissionOutcome {
    fn with_redaction(&self, _policy: &RedactionPolicy) -> Self {
        // Admission outcomes don't typically contain sensitive fields
        self.clone()
    }
}

/// Gossip state change event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipEvent {
    /// Timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// W3C trace ID.
    pub trace_id: String,
    /// Event type (announce, reconcile, merge).
    pub gossip_type: String,
    /// Number of objects affected.
    pub object_count: u32,
    /// Peer node ID (if applicable).
    pub peer_node: Option<String>,
    /// Whether event was successful.
    pub success: bool,
}

impl GossipEvent {
    fn with_redaction(&self, _policy: &RedactionPolicy) -> Self {
        self.clone()
    }
}

/// Lease operation event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseEvent {
    /// Timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// W3C trace ID.
    pub trace_id: String,
    /// Operation type (acquire, renew, release, conflict).
    pub operation: String,
    /// Subject object ID.
    pub subject_id: String,
    /// Lease purpose (`singleton_writer`, `operation`, `coordinator`).
    pub purpose: String,
    /// Node holding/requesting the lease.
    pub node_id: String,
    /// Whether operation succeeded.
    pub success: bool,
    /// Conflict holder (if conflict).
    pub conflict_holder: Option<String>,
}

impl LeaseEvent {
    fn with_redaction(&self, _policy: &RedactionPolicy) -> Self {
        self.clone()
    }
}

/// Session establishment event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEvent {
    /// Timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// W3C trace ID.
    pub trace_id: String,
    /// Session ID (hex).
    pub session_id: String,
    /// Session event kind (hello, ack, established, failed).
    pub kind: String,
    /// Peer node ID.
    pub peer_node: String,
    /// Suite negotiated (if established).
    pub suite: Option<String>,
    /// Failure reason (if failed).
    pub failure_reason: Option<String>,
}

impl SessionEvent {
    fn with_redaction(&self, policy: &RedactionPolicy) -> Self {
        let mut redacted = self.clone();
        // Session IDs might be sensitive in some contexts
        if policy.should_redact("session_id") {
            redacted.session_id = policy.redact_value(&self.session_id);
        }
        redacted
    }
}

/// Policy enforcement decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// W3C trace ID.
    pub trace_id: String,
    /// Zone ID.
    pub zone_id: String,
    /// Operation being evaluated.
    pub operation: String,
    /// Connector ID.
    pub connector_id: String,
    /// Decision outcome (allow, deny).
    pub decision: String,
    /// Reason code.
    pub reason_code: String,
    /// Evidence object IDs.
    pub evidence: Vec<String>,
}

impl PolicyDecision {
    fn with_redaction(&self, _policy: &RedactionPolicy) -> Self {
        self.clone()
    }
}

// ============================================================================
// Captured Trace
// ============================================================================

/// A captured sequence of trace events for replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedTrace {
    /// Unique trace capture ID.
    pub id: String,
    /// Trace version for compatibility.
    pub version: u32,
    /// Capture start timestamp (ms since epoch).
    pub started_at: u64,
    /// Capture end timestamp (ms since epoch).
    pub ended_at: Option<u64>,
    /// Node ID that captured this trace.
    pub capturing_node: Option<String>,
    /// Sequence of events in timestamp order.
    pub events: Vec<TraceEvent>,
    /// Whether redaction has been applied.
    pub redacted: bool,
}

/// Current trace format version.
pub const TRACE_VERSION: u32 = 1;

impl CapturedTrace {
    /// Create a new empty trace capture.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: TRACE_VERSION,
            started_at: current_time_ms(),
            ended_at: None,
            capturing_node: None,
            events: Vec::new(),
            redacted: false,
        }
    }

    /// Set the capturing node ID.
    #[must_use]
    pub fn with_node(mut self, node_id: impl Into<String>) -> Self {
        self.capturing_node = Some(node_id.into());
        self
    }

    /// Add an event to the trace.
    pub fn push(&mut self, event: TraceEvent) {
        self.events.push(event);
    }

    /// Mark the trace as complete.
    pub fn finish(&mut self) {
        self.ended_at = Some(current_time_ms());
    }

    /// Get the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if trace is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get trace duration in milliseconds.
    #[must_use]
    pub fn duration_ms(&self) -> Option<u64> {
        self.ended_at.map(|end| end.saturating_sub(self.started_at))
    }

    /// Apply redaction policy to all events.
    #[must_use]
    pub fn with_redaction(&self, policy: &RedactionPolicy) -> Self {
        Self {
            id: self.id.clone(),
            version: self.version,
            started_at: self.started_at,
            ended_at: self.ended_at,
            capturing_node: self.capturing_node.clone(),
            events: self
                .events
                .iter()
                .map(|e| e.with_redaction(policy))
                .collect(),
            redacted: true,
        }
    }

    /// Serialize to canonical CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TraceError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| TraceError::Serialization(e.to_string()))?;
        Ok(bytes)
    }

    /// Deserialize from CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TraceError> {
        ciborium::from_reader(bytes).map_err(|e| TraceError::Deserialization(e.to_string()))
    }

    /// Serialize to JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, TraceError> {
        serde_json::to_string_pretty(self).map_err(|e| TraceError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_json(json: &str) -> Result<Self, TraceError> {
        serde_json::from_str(json).map_err(|e| TraceError::Deserialization(e.to_string()))
    }

    /// Write JSON trace output to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or IO fails.
    pub fn write_json<P: AsRef<Path>>(&self, path: P) -> Result<(), TraceError> {
        let json = self.to_json()?;
        std::fs::write(path, json.as_bytes()).map_err(|e| TraceError::Io(e.to_string()))
    }

    /// Write CBOR trace output to a file.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or IO fails.
    pub fn write_cbor<P: AsRef<Path>>(&self, path: P) -> Result<(), TraceError> {
        let bytes = self.to_cbor()?;
        std::fs::write(path, bytes).map_err(|e| TraceError::Io(e.to_string()))
    }
}

// ============================================================================
// Trace Capture Configuration
// ============================================================================

/// Configuration for trace capture.
#[derive(Debug, Clone)]
pub struct TraceCaptureConfig {
    /// Whether capture is enabled.
    pub enabled: bool,
    /// Maximum events to buffer.
    pub max_events: usize,
    /// Maximum trace size in bytes.
    pub max_size_bytes: usize,
    /// Sampling rate (0.0 to 1.0).
    pub sample_rate: f64,
    /// Redaction policy to apply.
    pub redaction_policy: RedactionPolicy,
}

impl Default for TraceCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_events: 10_000,
            max_size_bytes: 10 * 1024 * 1024, // 10 MB
            sample_rate: 1.0,
            redaction_policy: RedactionPolicy::default(),
        }
    }
}

impl TraceCaptureConfig {
    /// Create a new capture config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable capture.
    #[must_use]
    pub const fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Set maximum events to buffer.
    #[must_use]
    pub const fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Set maximum trace size in bytes.
    #[must_use]
    pub const fn with_max_size_bytes(mut self, max_bytes: usize) -> Self {
        self.max_size_bytes = max_bytes;
        self
    }

    /// Set sampling rate.
    #[must_use]
    pub const fn with_sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = rate;
        self
    }

    /// Set redaction policy.
    #[must_use]
    pub fn with_redaction(mut self, policy: RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Error type for trace operations.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    /// Serialization error.
    #[error("Trace serialization error: {0}")]
    Serialization(String),

    /// Deserialization error.
    #[error("Trace deserialization error: {0}")]
    Deserialization(String),

    /// Capture buffer full.
    #[error("Trace capture buffer full")]
    BufferFull,

    /// Invalid trace version.
    #[error("Unsupported trace version: {0}")]
    UnsupportedVersion(u32),

    /// IO error while writing trace output.
    #[error("Trace IO error: {0}")]
    Io(String),
}

// ============================================================================
// Trace Capture
// ============================================================================

/// Trace export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceExportFormat {
    /// Pretty JSON format.
    Json,
    /// Canonical CBOR format.
    Cbor,
}

/// Trace capture buffer with sampling and size caps.
#[derive(Debug, Clone)]
pub struct TraceCapture {
    config: TraceCaptureConfig,
    trace: CapturedTrace,
    trace_id: String,
    event_bytes: usize,
}

impl TraceCapture {
    /// Create a new trace capture buffer with the given ID and config.
    #[must_use]
    pub fn new(id: impl Into<String>, config: TraceCaptureConfig) -> Self {
        let id = id.into();
        Self {
            config,
            trace: CapturedTrace::new(id.clone()),
            trace_id: id,
            event_bytes: 0,
        }
    }

    /// Set the capturing node ID.
    #[must_use]
    pub fn with_node(mut self, node_id: impl Into<String>) -> Self {
        self.trace.capturing_node = Some(node_id.into());
        self
    }

    /// Trace ID used for events in this capture.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Capture ID for this trace buffer.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        &self.trace.id
    }

    /// Access the capture configuration.
    #[must_use]
    pub const fn config(&self) -> &TraceCaptureConfig {
        &self.config
    }

    /// Record a trace event if sampling and buffer limits allow.
    ///
    /// # Errors
    ///
    /// Returns `TraceError::BufferFull` if the buffer is full.
    pub fn record(&mut self, event: TraceEvent) -> Result<(), TraceError> {
        if !self.config.enabled {
            return Ok(());
        }

        if !self.should_sample() {
            return Ok(());
        }

        if self.trace.events.len() >= self.config.max_events {
            return Err(TraceError::BufferFull);
        }

        let event_bytes = serde_json::to_vec(&event)
            .map_err(|e| TraceError::Serialization(e.to_string()))?
            .len();

        if self.event_bytes.saturating_add(event_bytes) > self.config.max_size_bytes {
            return Err(TraceError::BufferFull);
        }

        self.event_bytes = self.event_bytes.saturating_add(event_bytes);
        self.trace.events.push(event);
        Ok(())
    }

    /// Mark the capture as complete.
    pub fn finish(&mut self) {
        self.trace.finish();
    }

    /// Snapshot the current trace (unredacted).
    #[must_use]
    pub fn snapshot(&self) -> CapturedTrace {
        self.trace.clone()
    }

    /// Snapshot the current trace with redaction applied.
    #[must_use]
    pub fn redacted_snapshot(&self) -> CapturedTrace {
        self.trace.with_redaction(&self.config.redaction_policy)
    }

    /// Export the trace to a file in the chosen format.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or IO fails.
    pub fn export_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        redacted: bool,
        format: TraceExportFormat,
    ) -> Result<(), TraceError> {
        let trace = if redacted {
            self.redacted_snapshot()
        } else {
            self.snapshot()
        };

        match format {
            TraceExportFormat::Json => trace.write_json(path),
            TraceExportFormat::Cbor => trace.write_cbor(path),
        }
    }

    fn should_sample(&self) -> bool {
        let rate = self.config.sample_rate.clamp(0.0, 1.0);
        if rate <= 0.0 {
            return false;
        }
        if rate >= 1.0 {
            return true;
        }
        rand::random::<f64>() <= rate
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Get current time in milliseconds since epoch.
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redaction_policy_default() {
        let policy = RedactionPolicy::default();

        assert!(policy.should_redact("password"));
        assert!(policy.should_redact("api_key"));
        assert!(policy.should_redact("secret"));
        assert!(policy.should_redact("token"));
        assert!(!policy.should_redact("username"));
        assert!(!policy.should_redact("zone_id"));
    }

    #[test]
    fn test_redaction_policy_case_insensitive() {
        let policy = RedactionPolicy::default();

        assert!(policy.should_redact("PASSWORD"));
        assert!(policy.should_redact("Api_Key"));
        assert!(policy.should_redact("SECRET"));
    }

    #[test]
    fn test_redaction_policy_prefix_match() {
        let policy = RedactionPolicy::default();

        assert!(policy.should_redact("x-api-key"));
        assert!(policy.should_redact("x-auth-token"));
        assert!(policy.should_redact("secret_value"));
        assert!(!policy.should_redact("x-request-id"));
    }

    #[test]
    fn test_redaction_policy_custom() {
        let policy = RedactionPolicy::none()
            .with_field("custom_secret")
            .with_prefix("my-auth-");

        assert!(policy.should_redact("custom_secret"));
        assert!(policy.should_redact("my-auth-header"));
        assert!(!policy.should_redact("password")); // Not in policy
    }

    #[test]
    fn test_redaction_policy_hash() {
        let policy = RedactionPolicy::default().with_hash_redacted(true);

        let redacted = policy.redact_value("my-secret-value");
        assert!(redacted.starts_with("[REDACTED:"));
        assert!(redacted.ends_with(']'));

        // Same input should produce same hash
        let redacted2 = policy.redact_value("my-secret-value");
        assert_eq!(redacted, redacted2);

        // Different input should produce different hash
        let redacted3 = policy.redact_value("different-value");
        assert_ne!(redacted, redacted3);
    }

    #[test]
    fn test_routing_decision() {
        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 1_706_832_000_000,
            trace_id: "abc123".to_string(),
            source_node: "node-1".to_string(),
            target_node: Some("node-2".to_string()),
            object_id: "obj-xyz".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        });

        assert_eq!(event.timestamp(), 1_706_832_000_000);
        assert_eq!(event.trace_id(), "abc123");
    }

    #[test]
    fn test_admission_outcome() {
        let event = TraceEvent::Admission(AdmissionOutcome {
            timestamp: 1_706_832_001_000,
            trace_id: "def456".to_string(),
            peer_node: "node-3".to_string(),
            request_type: "symbol_request".to_string(),
            decision: "admit".to_string(),
            reason_code: None,
            budget_remaining: Some(1000),
            authenticated: true,
        });

        assert_eq!(event.timestamp(), 1_706_832_001_000);
        assert_eq!(event.trace_id(), "def456");
    }

    #[test]
    fn test_captured_trace_basic() {
        let mut trace = CapturedTrace::new("test-trace-001");

        assert_eq!(trace.id, "test-trace-001");
        assert_eq!(trace.version, TRACE_VERSION);
        assert!(trace.is_empty());

        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1000,
            trace_id: "t1".to_string(),
            source_node: "n1".to_string(),
            target_node: Some("n2".to_string()),
            object_id: "o1".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        }));

        assert_eq!(trace.len(), 1);
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_captured_trace_finish() {
        let mut trace = CapturedTrace::new("test-trace-002");
        trace.finish();

        assert!(trace.ended_at.is_some());
        assert!(trace.duration_ms().is_some());
    }

    #[test]
    fn test_captured_trace_with_node() {
        let trace = CapturedTrace::new("test").with_node("node-123");
        assert_eq!(trace.capturing_node, Some("node-123".to_string()));
    }

    #[test]
    fn test_captured_trace_redaction() {
        let mut trace = CapturedTrace::new("test-redact");

        trace.push(TraceEvent::Session(SessionEvent {
            timestamp: 1000,
            trace_id: "t1".to_string(),
            session_id: "secret-session-id".to_string(),
            kind: "established".to_string(),
            peer_node: "n1".to_string(),
            suite: Some("aes256-gcm".to_string()),
            failure_reason: None,
        }));

        let policy = RedactionPolicy::default().with_field("session_id");
        let redacted = trace.with_redaction(&policy);

        assert!(redacted.redacted);

        if let TraceEvent::Session(session) = &redacted.events[0] {
            assert_eq!(session.session_id, "[REDACTED]");
        } else {
            panic!("Expected Session event");
        }
    }

    #[test]
    fn test_captured_trace_json_roundtrip() {
        let mut trace = CapturedTrace::new("json-test");
        trace.push(TraceEvent::Gossip(GossipEvent {
            timestamp: 2000,
            trace_id: "g1".to_string(),
            gossip_type: "announce".to_string(),
            object_count: 5,
            peer_node: Some("p1".to_string()),
            success: true,
        }));

        let json = trace.to_json().unwrap();
        let parsed = CapturedTrace::from_json(&json).unwrap();

        assert_eq!(parsed.id, trace.id);
        assert_eq!(parsed.events.len(), 1);
    }

    #[test]
    fn test_captured_trace_cbor_roundtrip() {
        let mut trace = CapturedTrace::new("cbor-test");
        trace.push(TraceEvent::Lease(LeaseEvent {
            timestamp: 3000,
            trace_id: "l1".to_string(),
            operation: "acquire".to_string(),
            subject_id: "sub-1".to_string(),
            purpose: "singleton_writer".to_string(),
            node_id: "node-1".to_string(),
            success: true,
            conflict_holder: None,
        }));

        let cbor = trace.to_cbor().unwrap();
        let parsed = CapturedTrace::from_cbor(&cbor).unwrap();

        assert_eq!(parsed.id, trace.id);
        assert_eq!(parsed.events.len(), 1);
    }

    #[test]
    fn test_trace_event_serde() {
        let event = TraceEvent::Policy(PolicyDecision {
            timestamp: 4000,
            trace_id: "p1".to_string(),
            zone_id: "z:work".to_string(),
            operation: "invoke".to_string(),
            connector_id: "fcp.test".to_string(),
            decision: "allow".to_string(),
            reason_code: "CAPABILITY_VALID".to_string(),
            evidence: vec!["e1".to_string(), "e2".to_string()],
        });

        let json = serde_json::to_string(&event).unwrap();
        let parsed: TraceEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, parsed);
    }

    #[test]
    fn test_trace_capture_config_default() {
        let config = TraceCaptureConfig::default();

        assert!(!config.enabled);
        assert_eq!(config.max_events, 10_000);
        assert!(config.sample_rate >= 0.0);
        assert!(config.sample_rate <= 1.0);
    }

    #[test]
    fn test_trace_capture_config_builder() {
        let config = TraceCaptureConfig::new()
            .enabled()
            .with_max_events(5000)
            .with_sample_rate(0.5);

        assert!(config.enabled);
        assert_eq!(config.max_events, 5000);
    }

    #[test]
    fn test_trace_capture_records_event() {
        let config = TraceCaptureConfig::new().enabled();
        let mut capture = TraceCapture::new("trace-1", config);

        let event = TraceEvent::Admission(AdmissionOutcome {
            timestamp: 1,
            trace_id: "trace-1".to_string(),
            peer_node: "peer-1".to_string(),
            request_type: "symbol_request".to_string(),
            decision: "admit".to_string(),
            reason_code: None,
            budget_remaining: None,
            authenticated: true,
        });

        capture.record(event).expect("record event");
        let snapshot = capture.snapshot();
        assert_eq!(snapshot.events.len(), 1);
    }

    #[test]
    fn test_trace_capture_respects_max_events() {
        let config = TraceCaptureConfig::new().enabled().with_max_events(1);
        let mut capture = TraceCapture::new("trace-2", config);

        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 2,
            trace_id: "trace-2".to_string(),
            gossip_type: "announce".to_string(),
            object_count: 1,
            peer_node: None,
            success: true,
        });

        capture.record(event.clone()).expect("first event");
        let err = capture.record(event).expect_err("buffer should be full");
        assert!(matches!(err, TraceError::BufferFull));
    }

    #[test]
    fn test_trace_capture_sampling_zero_drops() {
        let config = TraceCaptureConfig::new().enabled().with_sample_rate(0.0);
        let mut capture = TraceCapture::new("trace-3", config);

        let event = TraceEvent::Session(SessionEvent {
            timestamp: 3,
            trace_id: "trace-3".to_string(),
            session_id: "sess".to_string(),
            kind: "hello".to_string(),
            peer_node: "peer-1".to_string(),
            suite: None,
            failure_reason: None,
        });

        capture.record(event).expect("record ok");
        assert!(capture.snapshot().events.is_empty());
    }

    #[test]
    fn test_trace_error_display() {
        let err = TraceError::Serialization("test".to_string());
        assert!(format!("{err}").contains("serialization"));

        let err = TraceError::BufferFull;
        assert!(format!("{err}").contains("buffer full"));

        let err = TraceError::UnsupportedVersion(99);
        assert!(format!("{err}").contains("99"));

        let err = TraceError::Io("io".to_string());
        assert!(format!("{err}").contains("IO"));
    }

    #[test]
    fn test_all_event_types() {
        // Ensure all event types can be serialized/deserialized
        let events = vec![
            TraceEvent::Routing(RoutingDecision {
                timestamp: 1,
                trace_id: "1".to_string(),
                source_node: "s".to_string(),
                target_node: None,
                object_id: "o".to_string(),
                path_type: "direct".to_string(),
                decision: "routed".to_string(),
                reason: None,
            }),
            TraceEvent::Admission(AdmissionOutcome {
                timestamp: 2,
                trace_id: "2".to_string(),
                peer_node: "p".to_string(),
                request_type: "invoke".to_string(),
                decision: "admit".to_string(),
                reason_code: None,
                budget_remaining: None,
                authenticated: false,
            }),
            TraceEvent::Gossip(GossipEvent {
                timestamp: 3,
                trace_id: "3".to_string(),
                gossip_type: "merge".to_string(),
                object_count: 10,
                peer_node: None,
                success: true,
            }),
            TraceEvent::Lease(LeaseEvent {
                timestamp: 4,
                trace_id: "4".to_string(),
                operation: "release".to_string(),
                subject_id: "s".to_string(),
                purpose: "operation".to_string(),
                node_id: "n".to_string(),
                success: true,
                conflict_holder: None,
            }),
            TraceEvent::Session(SessionEvent {
                timestamp: 5,
                trace_id: "5".to_string(),
                session_id: "sess".to_string(),
                kind: "hello".to_string(),
                peer_node: "p".to_string(),
                suite: None,
                failure_reason: None,
            }),
            TraceEvent::Policy(PolicyDecision {
                timestamp: 6,
                trace_id: "6".to_string(),
                zone_id: "z".to_string(),
                operation: "op".to_string(),
                connector_id: "c".to_string(),
                decision: "deny".to_string(),
                reason_code: "FCP-1001".to_string(),
                evidence: vec![],
            }),
        ];

        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            let parsed: TraceEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event.timestamp(), parsed.timestamp());
        }
    }

    // ====================================================================
    // New tests: RedactionPolicy
    // ====================================================================

    #[test]
    fn test_redaction_policy_none_redacts_nothing() {
        let policy = RedactionPolicy::none();
        assert!(!policy.should_redact("password"));
        assert!(!policy.should_redact("api_key"));
        assert!(!policy.should_redact("secret"));
        assert!(!policy.should_redact("token"));
        assert!(policy.redact_fields.is_empty());
        assert!(policy.redact_prefixes.is_empty());
    }

    #[test]
    fn test_redaction_policy_marker_without_hash() {
        let policy = RedactionPolicy::default();
        assert!(!policy.hash_redacted);
        let redacted = policy.redact_value("sensitive-data");
        assert_eq!(redacted, "[REDACTED]");
    }

    #[test]
    fn test_redaction_policy_custom_marker() {
        let policy = RedactionPolicy::none().with_marker("***REMOVED***");
        let redacted = policy.redact_value("anything");
        assert_eq!(redacted, "***REMOVED***");
    }

    #[test]
    fn test_redaction_policy_hash_deterministic() {
        let policy = RedactionPolicy::none().with_hash_redacted(true);
        let a = policy.redact_value("same-input");
        let b = policy.redact_value("same-input");
        assert_eq!(a, b);
        assert!(a.starts_with("[REDACTED:"));
        assert!(a.ends_with(']'));
        // Hash portion is 8 hex chars
        let inner = a
            .strip_prefix("[REDACTED:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();
        assert_eq!(inner.len(), 8);
    }

    #[test]
    fn test_redaction_policy_builder_chaining() {
        let policy = RedactionPolicy::none()
            .with_field("field_a")
            .with_field("field_b")
            .with_prefix("custom-")
            .with_hash_redacted(true)
            .with_marker("[GONE]");

        assert!(policy.should_redact("field_a"));
        assert!(policy.should_redact("field_b"));
        assert!(policy.should_redact("custom-header"));
        assert!(!policy.should_redact("other"));
        assert!(policy.hash_redacted);
        // hash_redacted overrides marker
        let val = policy.redact_value("x");
        assert!(val.starts_with("[REDACTED:"));
    }

    #[test]
    fn test_redaction_policy_default_all_fields() {
        let policy = RedactionPolicy::default();
        let expected = [
            "password",
            "api_key",
            "secret",
            "token",
            "authorization",
            "credential",
            "private_key",
            "session_key",
            "bearer",
        ];
        for field in &expected {
            assert!(
                policy.should_redact(field),
                "Expected '{field}' to be redacted"
            );
        }
    }

    #[test]
    fn test_redaction_policy_default_all_prefixes() {
        let policy = RedactionPolicy::default();
        assert!(policy.should_redact("x-api-foo"));
        assert!(policy.should_redact("x-auth-bar"));
        assert!(policy.should_redact("secret_something"));
    }

    #[test]
    fn test_redaction_policy_prefix_case_insensitive() {
        let policy = RedactionPolicy::none().with_prefix("X-My-Secret-");
        assert!(policy.should_redact("x-my-secret-value"));
        assert!(policy.should_redact("X-MY-SECRET-VALUE"));
    }

    // ====================================================================
    // New tests: TraceEvent variants
    // ====================================================================

    #[test]
    fn test_gossip_event_timestamp_and_trace_id() {
        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 9999,
            trace_id: "gossip-trace".to_string(),
            gossip_type: "reconcile".to_string(),
            object_count: 42,
            peer_node: Some("peer-x".to_string()),
            success: false,
        });
        assert_eq!(event.timestamp(), 9999);
        assert_eq!(event.trace_id(), "gossip-trace");
    }

    #[test]
    fn test_lease_event_timestamp_and_trace_id() {
        let event = TraceEvent::Lease(LeaseEvent {
            timestamp: 7777,
            trace_id: "lease-trace".to_string(),
            operation: "renew".to_string(),
            subject_id: "sub-99".to_string(),
            purpose: "coordinator".to_string(),
            node_id: "node-a".to_string(),
            success: false,
            conflict_holder: Some("node-b".to_string()),
        });
        assert_eq!(event.timestamp(), 7777);
        assert_eq!(event.trace_id(), "lease-trace");
    }

    #[test]
    fn test_session_event_timestamp_and_trace_id() {
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 5555,
            trace_id: "sess-trace".to_string(),
            session_id: "sid-123".to_string(),
            kind: "failed".to_string(),
            peer_node: "peer-z".to_string(),
            suite: None,
            failure_reason: Some("timeout".to_string()),
        });
        assert_eq!(event.timestamp(), 5555);
        assert_eq!(event.trace_id(), "sess-trace");
    }

    #[test]
    fn test_policy_event_timestamp_and_trace_id() {
        let event = TraceEvent::Policy(PolicyDecision {
            timestamp: 3333,
            trace_id: "pol-trace".to_string(),
            zone_id: "z:test".to_string(),
            operation: "read".to_string(),
            connector_id: "fcp.example".to_string(),
            decision: "deny".to_string(),
            reason_code: "FCP-5001".to_string(),
            evidence: vec!["ev1".to_string()],
        });
        assert_eq!(event.timestamp(), 3333);
        assert_eq!(event.trace_id(), "pol-trace");
    }

    #[test]
    fn test_routing_decision_with_reason() {
        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 100,
            trace_id: "rt-1".to_string(),
            source_node: "src".to_string(),
            target_node: None,
            object_id: "obj".to_string(),
            path_type: "mesh".to_string(),
            decision: "dropped".to_string(),
            reason: Some("no route".to_string()),
        });
        assert_eq!(event.timestamp(), 100);
        assert_eq!(event.trace_id(), "rt-1");
    }

    // ====================================================================
    // New tests: TraceEvent redaction per variant
    // ====================================================================

    #[test]
    fn test_routing_redaction_preserves_fields() {
        let rd = RoutingDecision {
            timestamp: 10,
            trace_id: "r1".to_string(),
            source_node: "s1".to_string(),
            target_node: Some("t1".to_string()),
            object_id: "o1".to_string(),
            path_type: "funnel".to_string(),
            decision: "deferred".to_string(),
            reason: Some("capacity".to_string()),
        };
        let event = TraceEvent::Routing(rd);
        let policy = RedactionPolicy::default().with_field("session_id");
        let redacted = event.with_redaction(&policy);
        // Routing doesn't redact anything — should be identical
        assert_eq!(event, redacted);
    }

    #[test]
    fn test_admission_redaction_preserves_fields() {
        let event = TraceEvent::Admission(AdmissionOutcome {
            timestamp: 20,
            trace_id: "a1".to_string(),
            peer_node: "p1".to_string(),
            request_type: "gossip".to_string(),
            decision: "reject".to_string(),
            reason_code: Some("FCP-4001".to_string()),
            budget_remaining: Some(0),
            authenticated: false,
        });
        let policy = RedactionPolicy::default();
        let redacted = event.with_redaction(&policy);
        assert_eq!(event, redacted);
    }

    #[test]
    fn test_gossip_redaction_preserves_fields() {
        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 30,
            trace_id: "g1".to_string(),
            gossip_type: "announce".to_string(),
            object_count: 7,
            peer_node: None,
            success: true,
        });
        let policy = RedactionPolicy::default();
        let redacted = event.with_redaction(&policy);
        assert_eq!(event, redacted);
    }

    #[test]
    fn test_lease_redaction_preserves_fields() {
        let event = TraceEvent::Lease(LeaseEvent {
            timestamp: 40,
            trace_id: "l1".to_string(),
            operation: "conflict".to_string(),
            subject_id: "s1".to_string(),
            purpose: "singleton_writer".to_string(),
            node_id: "n1".to_string(),
            success: false,
            conflict_holder: Some("n2".to_string()),
        });
        let policy = RedactionPolicy::default();
        let redacted = event.with_redaction(&policy);
        assert_eq!(event, redacted);
    }

    #[test]
    fn test_policy_redaction_preserves_fields() {
        let event = TraceEvent::Policy(PolicyDecision {
            timestamp: 50,
            trace_id: "p1".to_string(),
            zone_id: "z1".to_string(),
            operation: "invoke".to_string(),
            connector_id: "c1".to_string(),
            decision: "allow".to_string(),
            reason_code: "OK".to_string(),
            evidence: vec!["e1".to_string(), "e2".to_string()],
        });
        let policy = RedactionPolicy::default();
        let redacted = event.with_redaction(&policy);
        assert_eq!(event, redacted);
    }

    #[test]
    fn test_session_redaction_with_hash() {
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 60,
            trace_id: "s1".to_string(),
            session_id: "my-secret-session".to_string(),
            kind: "ack".to_string(),
            peer_node: "peer-1".to_string(),
            suite: Some("chacha20poly1305".to_string()),
            failure_reason: None,
        });
        let policy = RedactionPolicy::default()
            .with_field("session_id")
            .with_hash_redacted(true);
        let redacted = event.with_redaction(&policy);
        if let TraceEvent::Session(sess) = &redacted {
            assert!(sess.session_id.starts_with("[REDACTED:"));
            // Other fields preserved
            assert_eq!(sess.kind, "ack");
            assert_eq!(sess.peer_node, "peer-1");
            assert_eq!(sess.suite, Some("chacha20poly1305".to_string()));
        } else {
            panic!("Expected Session event");
        }
    }

    // ====================================================================
    // New tests: CapturedTrace
    // ====================================================================

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_captured_trace_multiple_events() {
        let mut trace = CapturedTrace::new("multi-event");
        for i in 0..10 {
            trace.push(TraceEvent::Gossip(GossipEvent {
                timestamp: i * 100,
                trace_id: format!("t-{i}"),
                gossip_type: "announce".to_string(),
                object_count: i as u32,
                peer_node: None,
                success: true,
            }));
        }
        assert_eq!(trace.len(), 10);
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_captured_trace_duration_before_finish_is_none() {
        let trace = CapturedTrace::new("no-finish");
        assert!(trace.duration_ms().is_none());
        assert!(trace.ended_at.is_none());
    }

    #[test]
    fn test_captured_trace_version() {
        let trace = CapturedTrace::new("version-check");
        assert_eq!(trace.version, TRACE_VERSION);
        assert_eq!(trace.version, 1);
    }

    #[test]
    fn test_captured_trace_started_at_nonzero() {
        let trace = CapturedTrace::new("ts-check");
        // started_at should be a reasonable timestamp (post-2020)
        assert!(trace.started_at > 1_577_836_800_000); // 2020-01-01
    }

    #[test]
    fn test_captured_trace_redaction_sets_flag() {
        let trace = CapturedTrace::new("flag-check");
        assert!(!trace.redacted);
        let redacted = trace.with_redaction(&RedactionPolicy::none());
        assert!(redacted.redacted);
    }

    #[test]
    fn test_captured_trace_json_roundtrip_preserves_all_fields() {
        let mut trace = CapturedTrace::new("full-roundtrip");
        trace.capturing_node = Some("node-42".to_string());
        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1000,
            trace_id: "rt".to_string(),
            source_node: "src".to_string(),
            target_node: Some("tgt".to_string()),
            object_id: "obj".to_string(),
            path_type: "derp".to_string(),
            decision: "routed".to_string(),
            reason: None,
        }));
        trace.push(TraceEvent::Admission(AdmissionOutcome {
            timestamp: 2000,
            trace_id: "ad".to_string(),
            peer_node: "peer".to_string(),
            request_type: "invoke".to_string(),
            decision: "throttle".to_string(),
            reason_code: Some("RATE_LIMIT".to_string()),
            budget_remaining: Some(500),
            authenticated: true,
        }));
        trace.finish();

        let json = trace.to_json().unwrap();
        let parsed = CapturedTrace::from_json(&json).unwrap();

        assert_eq!(parsed.id, "full-roundtrip");
        assert_eq!(parsed.version, TRACE_VERSION);
        assert_eq!(parsed.capturing_node, Some("node-42".to_string()));
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].timestamp(), 1000);
        assert_eq!(parsed.events[1].timestamp(), 2000);
        assert!(parsed.ended_at.is_some());
    }

    #[test]
    fn test_captured_trace_cbor_roundtrip_preserves_all_fields() {
        let mut trace = CapturedTrace::new("cbor-full");
        trace.push(TraceEvent::Policy(PolicyDecision {
            timestamp: 999,
            trace_id: "p99".to_string(),
            zone_id: "z:prod".to_string(),
            operation: "write".to_string(),
            connector_id: "fcp.db".to_string(),
            decision: "deny".to_string(),
            reason_code: "FCP-6000".to_string(),
            evidence: vec!["e-a".to_string(), "e-b".to_string(), "e-c".to_string()],
        }));

        let cbor = trace.to_cbor().unwrap();
        let parsed = CapturedTrace::from_cbor(&cbor).unwrap();

        assert_eq!(parsed.id, "cbor-full");
        assert_eq!(parsed.events.len(), 1);
        if let TraceEvent::Policy(p) = &parsed.events[0] {
            assert_eq!(p.evidence.len(), 3);
            assert_eq!(p.zone_id, "z:prod");
        } else {
            panic!("Expected Policy event");
        }
    }

    #[test]
    fn test_captured_trace_clone() {
        let mut trace = CapturedTrace::new("clone-test");
        trace.push(TraceEvent::Gossip(GossipEvent {
            timestamp: 500,
            trace_id: "cl".to_string(),
            gossip_type: "merge".to_string(),
            object_count: 3,
            peer_node: Some("peer-c".to_string()),
            success: true,
        }));
        let cloned = trace.clone();
        drop(trace);

        assert_eq!(cloned.id, "clone-test");
        assert_eq!(cloned.len(), 1);
    }

    #[test]
    fn test_captured_trace_debug_format() {
        let trace = CapturedTrace::new("debug-fmt");
        let dbg = format!("{trace:?}");
        assert!(dbg.contains("debug-fmt"));
        assert!(dbg.contains("CapturedTrace"));
    }

    // ====================================================================
    // New tests: TraceCapture
    // ====================================================================

    #[test]
    fn test_trace_capture_disabled_ignores_events() {
        let config = TraceCaptureConfig::new(); // enabled = false by default
        let mut capture = TraceCapture::new("disabled-trace", config);

        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: "d1".to_string(),
            source_node: "s".to_string(),
            target_node: None,
            object_id: "o".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        });

        // Should succeed even when disabled (silently drops)
        capture
            .record(event)
            .expect("disabled capture should succeed");
        assert!(capture.snapshot().is_empty());
    }

    #[test]
    fn test_trace_capture_ids() {
        let config = TraceCaptureConfig::new().enabled();
        let capture = TraceCapture::new("cap-id-test", config);
        assert_eq!(capture.trace_id(), "cap-id-test");
        assert_eq!(capture.capture_id(), "cap-id-test");
    }

    #[test]
    fn test_trace_capture_with_node() {
        let config = TraceCaptureConfig::new().enabled();
        let capture = TraceCapture::new("node-test", config).with_node("my-node");
        let snap = capture.snapshot();
        assert_eq!(snap.capturing_node, Some("my-node".to_string()));
    }

    #[test]
    fn test_trace_capture_config_accessor() {
        let config = TraceCaptureConfig::new()
            .enabled()
            .with_max_events(42)
            .with_max_size_bytes(1024)
            .with_sample_rate(0.75);
        let capture = TraceCapture::new("cfg-test", config);
        let cfg = capture.config();
        assert!(cfg.enabled);
        assert_eq!(cfg.max_events, 42);
        assert_eq!(cfg.max_size_bytes, 1024);
        assert!((cfg.sample_rate - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_trace_capture_finish_sets_ended_at() {
        let config = TraceCaptureConfig::new().enabled();
        let mut capture = TraceCapture::new("finish-test", config);
        capture.finish();
        let snap = capture.snapshot();
        assert!(snap.ended_at.is_some());
        assert!(snap.duration_ms().is_some());
    }

    #[test]
    fn test_trace_capture_redacted_snapshot() {
        let policy = RedactionPolicy::default().with_field("session_id");
        let config = TraceCaptureConfig::new().enabled().with_redaction(policy);
        let mut capture = TraceCapture::new("redact-snap", config);

        capture
            .record(TraceEvent::Session(SessionEvent {
                timestamp: 100,
                trace_id: "rs1".to_string(),
                session_id: "secret-sid".to_string(),
                kind: "established".to_string(),
                peer_node: "peer".to_string(),
                suite: Some("aes256".to_string()),
                failure_reason: None,
            }))
            .unwrap();

        let snap = capture.redacted_snapshot();
        assert!(snap.redacted);
        if let TraceEvent::Session(sess) = &snap.events[0] {
            assert_eq!(sess.session_id, "[REDACTED]");
        } else {
            panic!("Expected Session event");
        }

        // Unredacted snapshot should preserve original
        let raw = capture.snapshot();
        assert!(!raw.redacted);
        if let TraceEvent::Session(sess) = &raw.events[0] {
            assert_eq!(sess.session_id, "secret-sid");
        } else {
            panic!("Expected Session event");
        }
    }

    #[test]
    fn test_trace_capture_max_size_bytes_limit() {
        let config = TraceCaptureConfig::new()
            .enabled()
            .with_max_events(10_000)
            .with_max_size_bytes(200); // very small byte limit
        let mut capture = TraceCapture::new("size-limit", config);

        let mut hit_buffer_full = false;
        for i in 0..100 {
            let event = TraceEvent::Policy(PolicyDecision {
                timestamp: i,
                trace_id: format!("t-{i}"),
                zone_id: "z".to_string(),
                operation: "op".to_string(),
                connector_id: "c".to_string(),
                decision: "allow".to_string(),
                reason_code: "OK".to_string(),
                evidence: vec!["evidence-data-padding".to_string()],
            });
            if matches!(capture.record(event), Err(TraceError::BufferFull)) {
                hit_buffer_full = true;
                break;
            }
        }
        assert!(hit_buffer_full, "Expected BufferFull due to byte limit");
    }

    #[test]
    fn test_trace_capture_sampling_full_rate() {
        let config = TraceCaptureConfig::new().enabled().with_sample_rate(1.0);
        let mut capture = TraceCapture::new("full-rate", config);

        for i in 0..20 {
            let event = TraceEvent::Gossip(GossipEvent {
                timestamp: i,
                trace_id: format!("fr-{i}"),
                gossip_type: "announce".to_string(),
                object_count: 1,
                peer_node: None,
                success: true,
            });
            capture.record(event).unwrap();
        }
        // All 20 should be captured at 100% sample rate
        assert_eq!(capture.snapshot().events.len(), 20);
    }

    // ====================================================================
    // New tests: TraceCaptureConfig
    // ====================================================================

    #[test]
    fn test_trace_capture_config_max_size_bytes_default() {
        let config = TraceCaptureConfig::default();
        assert_eq!(config.max_size_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn test_trace_capture_config_with_redaction() {
        let policy = RedactionPolicy::none().with_field("custom_field");
        let config = TraceCaptureConfig::new().with_redaction(policy);
        assert!(config.redaction_policy.should_redact("custom_field"));
        assert!(!config.redaction_policy.should_redact("password"));
    }

    // ====================================================================
    // New tests: TraceError
    // ====================================================================

    #[test]
    fn test_trace_error_deserialization_display() {
        let err = TraceError::Deserialization("bad input".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("deserialization"));
        assert!(msg.contains("bad input"));
    }

    #[test]
    fn test_trace_error_debug() {
        let err = TraceError::BufferFull;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("BufferFull"));
    }

    // ====================================================================
    // New tests: TraceExportFormat
    // ====================================================================

    #[test]
    fn test_trace_export_format_eq() {
        assert_eq!(TraceExportFormat::Json, TraceExportFormat::Json);
        assert_eq!(TraceExportFormat::Cbor, TraceExportFormat::Cbor);
        assert_ne!(TraceExportFormat::Json, TraceExportFormat::Cbor);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_trace_export_format_clone_and_copy() {
        let fmt = TraceExportFormat::Json;
        let copied = fmt;
        let cloned = fmt.clone();
        assert_eq!(fmt, copied);
        assert_eq!(fmt, cloned);
    }

    #[test]
    fn test_trace_export_format_debug() {
        let dbg = format!("{:?}", TraceExportFormat::Cbor);
        assert!(dbg.contains("Cbor"));
    }

    // ====================================================================
    // New tests: TraceEvent serde (all event types via CBOR)
    // ====================================================================

    #[test]
    fn test_all_event_types_cbor_roundtrip() {
        let events = vec![
            TraceEvent::Routing(RoutingDecision {
                timestamp: 10,
                trace_id: "r10".to_string(),
                source_node: "s".to_string(),
                target_node: Some("t".to_string()),
                object_id: "o".to_string(),
                path_type: "direct".to_string(),
                decision: "routed".to_string(),
                reason: None,
            }),
            TraceEvent::Admission(AdmissionOutcome {
                timestamp: 20,
                trace_id: "a20".to_string(),
                peer_node: "p".to_string(),
                request_type: "invoke".to_string(),
                decision: "quarantine".to_string(),
                reason_code: Some("QUARANTINE".to_string()),
                budget_remaining: None,
                authenticated: false,
            }),
            TraceEvent::Gossip(GossipEvent {
                timestamp: 30,
                trace_id: "g30".to_string(),
                gossip_type: "reconcile".to_string(),
                object_count: 99,
                peer_node: Some("gp".to_string()),
                success: false,
            }),
            TraceEvent::Lease(LeaseEvent {
                timestamp: 40,
                trace_id: "l40".to_string(),
                operation: "acquire".to_string(),
                subject_id: "sub".to_string(),
                purpose: "operation".to_string(),
                node_id: "nd".to_string(),
                success: true,
                conflict_holder: None,
            }),
            TraceEvent::Session(SessionEvent {
                timestamp: 50,
                trace_id: "s50".to_string(),
                session_id: "sid".to_string(),
                kind: "established".to_string(),
                peer_node: "sp".to_string(),
                suite: Some("aes128".to_string()),
                failure_reason: None,
            }),
            TraceEvent::Policy(PolicyDecision {
                timestamp: 60,
                trace_id: "p60".to_string(),
                zone_id: "z".to_string(),
                operation: "op".to_string(),
                connector_id: "c".to_string(),
                decision: "allow".to_string(),
                reason_code: "OK".to_string(),
                evidence: vec!["ev".to_string()],
            }),
        ];

        let mut trace = CapturedTrace::new("cbor-all-types");
        for event in &events {
            trace.push(event.clone());
        }
        let cbor = trace.to_cbor().unwrap();
        let parsed = CapturedTrace::from_cbor(&cbor).unwrap();

        assert_eq!(parsed.events.len(), events.len());
        for (original, roundtripped) in events.iter().zip(parsed.events.iter()) {
            assert_eq!(original, roundtripped);
        }
    }

    #[test]
    fn test_trace_event_json_tag_names() {
        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: "t".to_string(),
            source_node: "s".to_string(),
            target_node: None,
            object_id: "o".to_string(),
            path_type: "d".to_string(),
            decision: "r".to_string(),
            reason: None,
        });
        let json = serde_json::to_string(&event).unwrap();
        // Verify serde tag "event_type" with snake_case rename
        assert!(json.contains("\"event_type\":\"routing\""));

        let admission = TraceEvent::Admission(AdmissionOutcome {
            timestamp: 2,
            trace_id: "t2".to_string(),
            peer_node: "p".to_string(),
            request_type: "invoke".to_string(),
            decision: "admit".to_string(),
            reason_code: None,
            budget_remaining: None,
            authenticated: true,
        });
        let json2 = serde_json::to_string(&admission).unwrap();
        assert!(json2.contains("\"event_type\":\"admission\""));
    }

    // ====================================================================
    // New tests: File I/O (write + read back)
    // ====================================================================

    #[test]
    fn test_write_and_read_json_file() {
        let dir = std::env::temp_dir().join("fcp-telemetry-test-json");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("trace.json");

        let mut trace = CapturedTrace::new("file-json-test");
        trace.push(TraceEvent::Lease(LeaseEvent {
            timestamp: 777,
            trace_id: "fj1".to_string(),
            operation: "acquire".to_string(),
            subject_id: "s".to_string(),
            purpose: "op".to_string(),
            node_id: "n".to_string(),
            success: true,
            conflict_holder: None,
        }));
        trace.write_json(&path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed = CapturedTrace::from_json(&contents).unwrap();
        assert_eq!(parsed.id, "file-json-test");
        assert_eq!(parsed.events.len(), 1);

        // Cleanup
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_write_and_read_cbor_file() {
        let dir = std::env::temp_dir().join("fcp-telemetry-test-cbor");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("trace.cbor");

        let mut trace = CapturedTrace::new("file-cbor-test");
        trace.push(TraceEvent::Gossip(GossipEvent {
            timestamp: 888,
            trace_id: "fc1".to_string(),
            gossip_type: "merge".to_string(),
            object_count: 5,
            peer_node: None,
            success: true,
        }));
        trace.write_cbor(&path).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let parsed = CapturedTrace::from_cbor(&bytes).unwrap();
        assert_eq!(parsed.id, "file-cbor-test");
        assert_eq!(parsed.events.len(), 1);

        // Cleanup
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_from_json_invalid_returns_error() {
        let result = CapturedTrace::from_json("not valid json {{{");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TraceError::Deserialization(_)));
    }

    #[test]
    fn test_from_cbor_invalid_returns_error() {
        let result = CapturedTrace::from_cbor(&[0xFF, 0xFE, 0x00]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TraceError::Deserialization(_)));
    }
}
