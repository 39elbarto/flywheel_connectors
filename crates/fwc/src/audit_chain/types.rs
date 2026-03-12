//! Audit tail types for machine-readable JSON output.
//!
//! These types define the stable JSON schema for audit event streaming,
//! enabling automation and incident response tooling integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Audit event output record for streaming display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventOutput {
    /// Sequence number in the audit chain (monotonic).
    pub seq: u64,

    /// When the event occurred (Unix timestamp seconds).
    pub occurred_at: u64,

    /// ISO-8601 formatted timestamp for human readability.
    pub occurred_at_iso: String,

    /// Event type (e.g., "capability.invoke", "secret.access").
    pub event_type: String,

    /// Actor who triggered the event.
    pub actor: String,

    /// Zone where event occurred.
    pub zone_id: String,

    /// Correlation ID for request tracing (hex-encoded 16 bytes).
    pub correlation_id: String,

    /// Trace ID if W3C trace context present (hex-encoded 16 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Span ID if W3C trace context present (hex-encoded 8 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,

    /// Connector ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,

    /// Operation ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,

    /// Previous event object ID in chain (hex-encoded, for integrity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

impl AuditEventOutput {
    /// Get ANSI color code for this event type.
    #[must_use]
    pub fn event_type_color(&self) -> &'static str {
        match self.event_type.as_str() {
            "secret.access" => "\x1b[33m",     // Yellow - sensitive
            "capability.invoke" => "\x1b[32m", // Green - normal operation
            "elevation.granted" | "declassification.granted" => "\x1b[36m", // Cyan - elevated/data flow
            "zone.transition" => "\x1b[35m", // Magenta - zone movement
            "revocation.issued" | "security.violation" => "\x1b[31m", // Red - revocation/violation
            "audit.fork_detected" => "\x1b[31;1m", // Bold red - critical
            _ => "\x1b[0m",                  // Default
        }
    }

    /// Get event type symbol for terminal output.
    #[must_use]
    pub fn event_type_symbol(&self) -> &'static str {
        match self.event_type.as_str() {
            "secret.access" => "🔑",
            "capability.invoke" => "⚡",
            "elevation.granted" => "⬆",
            "declassification.granted" => "🔓",
            "zone.transition" => "→",
            "revocation.issued" => "⊘",
            "security.violation" | "audit.fork_detected" => "⚠",
            _ => "•",
        }
    }

    /// Reset ANSI color.
    #[must_use]
    pub const fn ansi_reset() -> &'static str {
        "\x1b[0m"
    }
}

/// Filter options for audit event streaming.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
}

impl AuditFilter {
    /// Check if this filter matches the given event.
    #[must_use]
    pub fn matches(&self, event: &AuditEventOutput) -> bool {
        if let Some(ref cid) = self.connector_id {
            if event.connector_id.as_ref() != Some(cid) {
                return false;
            }
        }
        if let Some(ref oid) = self.operation_id {
            if event.operation_id.as_ref() != Some(oid) {
                return false;
            }
        }
        if let Some(ref corr) = self.correlation_id {
            if &event.correlation_id != corr {
                return false;
            }
        }
        if let Some(ref tid) = self.trace_id {
            if event.trace_id.as_ref() != Some(tid) {
                return false;
            }
        }
        if let Some(ref et) = self.event_type {
            if &event.event_type != et {
                return false;
            }
        }
        if let Some(ref actor) = self.actor {
            if &event.actor != actor {
                return false;
            }
        }
        true
    }

    /// Check if any filter is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.connector_id.is_none()
            && self.operation_id.is_none()
            && self.correlation_id.is_none()
            && self.trace_id.is_none()
            && self.event_type.is_none()
            && self.actor.is_none()
    }
}

/// Audit tail stream summary (shown when streaming ends).
#[allow(dead_code)] // Planned for streaming mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStreamSummary {
    /// Total events streamed.
    pub total_events: u64,

    /// Events filtered out.
    pub filtered_events: u64,

    /// Starting sequence number.
    pub start_seq: u64,

    /// Ending sequence number.
    pub end_seq: u64,

    /// Time range start.
    pub start_time: DateTime<Utc>,

    /// Time range end.
    pub end_time: DateTime<Utc>,

    /// Zone being tailed.
    pub zone_id: String,
}

/// Error when tailing audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTailError {
    /// Error code (FCP-XXXX).
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Recovery hints for operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

impl std::fmt::Display for AuditTailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuditTailError {}

impl AuditTailError {
    /// Create a "zone not found" error.
    #[must_use]
    pub fn zone_not_found(zone_id: &str) -> Self {
        Self {
            code: "FCP-4001".to_string(),
            message: format!("Zone '{zone_id}' not found or not accessible"),
            hints: vec![
                "Verify the zone ID is correct".to_string(),
                "Check if you have access to this zone".to_string(),
                "Run 'fcp doctor --zone <zone>' to diagnose".to_string(),
            ],
        }
    }

    /// Create an "audit chain unavailable" error.
    #[must_use]
    pub fn chain_unavailable(zone_id: &str) -> Self {
        Self {
            code: "FCP-5011".to_string(),
            message: format!("Audit chain for zone '{zone_id}' is unavailable"),
            hints: vec![
                "The zone may not have any audit events yet".to_string(),
                "Check if the zone's audit head is synchronized".to_string(),
                "Run 'fcp doctor --zone <zone>' to check freshness".to_string(),
            ],
        }
    }

    /// Create an "interrupted" error.
    #[allow(dead_code)] // Planned for streaming mode
    #[must_use]
    pub fn interrupted() -> Self {
        Self {
            code: "FCP-9001".to_string(),
            message: "Audit tail interrupted".to_string(),
            hints: vec!["Stream was interrupted by user or system signal".to_string()],
        }
    }
}

/// Event type constants for filtering.
#[allow(dead_code)] // Planned for filter parsing
pub mod event_types {
    pub const SECRET_ACCESS: &str = "secret.access";
    pub const CAPABILITY_INVOKE: &str = "capability.invoke";
    pub const ELEVATION_GRANTED: &str = "elevation.granted";
    pub const DECLASSIFICATION_GRANTED: &str = "declassification.granted";
    pub const ZONE_TRANSITION: &str = "zone.transition";
    pub const REVOCATION_ISSUED: &str = "revocation.issued";
    pub const SECURITY_VIOLATION: &str = "security.violation";
    pub const AUDIT_FORK_DETECTED: &str = "audit.fork_detected";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> AuditEventOutput {
        AuditEventOutput {
            seq: 42,
            occurred_at: 1_700_000_000,
            occurred_at_iso: "2023-11-14T22:13:20Z".to_string(),
            event_type: "capability.invoke".to_string(),
            actor: "user:alice".to_string(),
            zone_id: "z:work".to_string(),
            correlation_id: "aabbccdd11223344aabbccdd11223344".to_string(),
            trace_id: Some("deadbeef00112233deadbeef00112233".to_string()),
            span_id: Some("1122334455667788".to_string()),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: Some("prev-object-id".to_string()),
        }
    }

    #[test]
    fn event_type_colors() {
        let event = sample_event();
        assert_eq!(event.event_type_color(), "\x1b[32m"); // Green for capability.invoke
    }

    #[test]
    fn event_type_symbols() {
        let event = sample_event();
        assert_eq!(event.event_type_symbol(), "⚡"); // Lightning for capability.invoke
    }

    #[test]
    fn filter_matches_all_when_empty() {
        let filter = AuditFilter::default();
        let event = sample_event();
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_matches_connector_id() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            ..Default::default()
        };
        let event = sample_event();
        assert!(filter.matches(&event));

        let filter_wrong = AuditFilter {
            connector_id: Some("fcp.discord:base:v1".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&event));
    }

    #[test]
    fn filter_matches_operation_id() {
        let filter = AuditFilter {
            operation_id: Some("send_message".to_string()),
            ..Default::default()
        };
        let event = sample_event();
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_matches_correlation_id() {
        let filter = AuditFilter {
            correlation_id: Some("aabbccdd11223344aabbccdd11223344".to_string()),
            ..Default::default()
        };
        let event = sample_event();
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_matches_trace_id() {
        let filter = AuditFilter {
            trace_id: Some("deadbeef00112233deadbeef00112233".to_string()),
            ..Default::default()
        };
        let event = sample_event();
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_matches_event_type() {
        let filter = AuditFilter {
            event_type: Some("capability.invoke".to_string()),
            ..Default::default()
        };
        let event = sample_event();
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_matches_actor() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            ..Default::default()
        };
        let event = sample_event();
        assert!(filter.matches(&event));
    }

    #[test]
    fn filter_is_empty_when_default() {
        let filter = AuditFilter::default();
        assert!(filter.is_empty());
    }

    #[test]
    fn filter_not_empty_with_any_field() {
        let filter = AuditFilter {
            connector_id: Some("test".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    #[test]
    fn audit_event_json_snapshot() {
        let event = sample_event();
        let json = serde_json::to_string_pretty(&event).unwrap();

        assert!(json.contains("\"seq\": 42"));
        assert!(json.contains("\"event_type\": \"capability.invoke\""));
        assert!(json.contains("\"actor\": \"user:alice\""));
        assert!(json.contains("\"zone_id\": \"z:work\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"span_id\""));

        // Verify roundtrip
        let parsed: AuditEventOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.event_type, "capability.invoke");
    }

    #[test]
    fn audit_error_zone_not_found() {
        let err = AuditTailError::zone_not_found("z:secret");
        assert_eq!(err.code, "FCP-4001");
        assert!(err.message.contains("z:secret"));
        assert!(!err.hints.is_empty());
    }

    #[test]
    fn audit_error_chain_unavailable() {
        let err = AuditTailError::chain_unavailable("z:work");
        assert_eq!(err.code, "FCP-5011");
        assert!(err.message.contains("z:work"));
    }

    // ================================================================
    // AuditEventOutput — event_type_color exhaustive coverage
    // ================================================================

    #[test]
    fn event_type_color_secret_access() {
        let mut e = sample_event();
        e.event_type = "secret.access".to_string();
        assert_eq!(e.event_type_color(), "\x1b[33m"); // Yellow
    }

    #[test]
    fn event_type_color_elevation_granted() {
        let mut e = sample_event();
        e.event_type = "elevation.granted".to_string();
        assert_eq!(e.event_type_color(), "\x1b[36m"); // Cyan
    }

    #[test]
    fn event_type_color_declassification_granted() {
        let mut e = sample_event();
        e.event_type = "declassification.granted".to_string();
        assert_eq!(e.event_type_color(), "\x1b[36m"); // Cyan
    }

    #[test]
    fn event_type_color_zone_transition() {
        let mut e = sample_event();
        e.event_type = "zone.transition".to_string();
        assert_eq!(e.event_type_color(), "\x1b[35m"); // Magenta
    }

    #[test]
    fn event_type_color_revocation_issued() {
        let mut e = sample_event();
        e.event_type = "revocation.issued".to_string();
        assert_eq!(e.event_type_color(), "\x1b[31m"); // Red
    }

    #[test]
    fn event_type_color_security_violation() {
        let mut e = sample_event();
        e.event_type = "security.violation".to_string();
        assert_eq!(e.event_type_color(), "\x1b[31m"); // Red
    }

    #[test]
    fn event_type_color_audit_fork_detected() {
        let mut e = sample_event();
        e.event_type = "audit.fork_detected".to_string();
        assert_eq!(e.event_type_color(), "\x1b[31;1m"); // Bold red
    }

    #[test]
    fn event_type_color_unknown_defaults() {
        let mut e = sample_event();
        e.event_type = "some.unknown.event".to_string();
        assert_eq!(e.event_type_color(), "\x1b[0m"); // Default/reset
    }

    // ================================================================
    // AuditEventOutput — event_type_symbol exhaustive coverage
    // ================================================================

    #[test]
    fn event_type_symbol_secret_access() {
        let mut e = sample_event();
        e.event_type = "secret.access".to_string();
        assert_eq!(e.event_type_symbol(), "\u{1f511}");
    }

    #[test]
    fn event_type_symbol_elevation_granted() {
        let mut e = sample_event();
        e.event_type = "elevation.granted".to_string();
        assert_eq!(e.event_type_symbol(), "\u{2b06}");
    }

    #[test]
    fn event_type_symbol_declassification_granted() {
        let mut e = sample_event();
        e.event_type = "declassification.granted".to_string();
        assert_eq!(e.event_type_symbol(), "\u{1f513}");
    }

    #[test]
    fn event_type_symbol_zone_transition() {
        let mut e = sample_event();
        e.event_type = "zone.transition".to_string();
        assert_eq!(e.event_type_symbol(), "\u{2192}");
    }

    #[test]
    fn event_type_symbol_revocation_issued() {
        let mut e = sample_event();
        e.event_type = "revocation.issued".to_string();
        assert_eq!(e.event_type_symbol(), "\u{2298}");
    }

    #[test]
    fn event_type_symbol_security_violation() {
        let mut e = sample_event();
        e.event_type = "security.violation".to_string();
        assert_eq!(e.event_type_symbol(), "\u{26a0}");
    }

    #[test]
    fn event_type_symbol_audit_fork_detected() {
        let mut e = sample_event();
        e.event_type = "audit.fork_detected".to_string();
        assert_eq!(e.event_type_symbol(), "\u{26a0}");
    }

    #[test]
    fn event_type_symbol_unknown_defaults_to_bullet() {
        let mut e = sample_event();
        e.event_type = "totally.custom".to_string();
        assert_eq!(e.event_type_symbol(), "\u{2022}");
    }

    // ================================================================
    // AuditEventOutput — ansi_reset
    // ================================================================

    #[test]
    fn ansi_reset_is_escape_sequence() {
        assert_eq!(AuditEventOutput::ansi_reset(), "\x1b[0m");
    }

    // ================================================================
    // AuditEventOutput — serde with optional None fields
    // ================================================================

    fn minimal_event() -> AuditEventOutput {
        AuditEventOutput {
            seq: 0,
            occurred_at: 0,
            occurred_at_iso: "1970-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            actor: "user:test".to_string(),
            zone_id: "z:default".to_string(),
            correlation_id: "0".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: None,
            operation_id: None,
            prev: None,
        }
    }

    #[test]
    fn serde_omits_none_trace_id() {
        let e = minimal_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("trace_id"));
    }

    #[test]
    fn serde_omits_none_span_id() {
        let e = minimal_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("span_id"));
    }

    #[test]
    fn serde_omits_none_connector_id() {
        let e = minimal_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("connector_id"));
    }

    #[test]
    fn serde_omits_none_operation_id() {
        let e = minimal_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("operation_id"));
    }

    #[test]
    fn serde_omits_none_prev() {
        let e = minimal_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains("prev"));
    }

    #[test]
    fn serde_includes_some_trace_id() {
        let e = sample_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("trace_id"));
        assert!(json.contains("deadbeef"));
    }

    #[test]
    fn serde_includes_some_span_id() {
        let e = sample_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("span_id"));
        assert!(json.contains("1122334455667788"));
    }

    #[test]
    fn serde_includes_some_connector_id() {
        let e = sample_event();
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("connector_id"));
        assert!(json.contains("fcp.telegram"));
    }

    #[test]
    fn serde_roundtrip_minimal_event() {
        let e = minimal_event();
        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEventOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, 0);
        assert_eq!(parsed.occurred_at, 0);
        assert_eq!(parsed.event_type, "test");
        assert!(parsed.trace_id.is_none());
        assert!(parsed.span_id.is_none());
        assert!(parsed.connector_id.is_none());
        assert!(parsed.operation_id.is_none());
        assert!(parsed.prev.is_none());
    }

    #[test]
    fn serde_roundtrip_full_event() {
        let e = sample_event();
        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEventOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, e.seq);
        assert_eq!(parsed.occurred_at, e.occurred_at);
        assert_eq!(parsed.occurred_at_iso, e.occurred_at_iso);
        assert_eq!(parsed.event_type, e.event_type);
        assert_eq!(parsed.actor, e.actor);
        assert_eq!(parsed.zone_id, e.zone_id);
        assert_eq!(parsed.correlation_id, e.correlation_id);
        assert_eq!(parsed.trace_id, e.trace_id);
        assert_eq!(parsed.span_id, e.span_id);
        assert_eq!(parsed.connector_id, e.connector_id);
        assert_eq!(parsed.operation_id, e.operation_id);
        assert_eq!(parsed.prev, e.prev);
    }

    #[test]
    fn serde_json_shape_has_all_mandatory_keys() {
        let e = minimal_event();
        let val: serde_json::Value = serde_json::to_value(&e).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("seq"));
        assert!(obj.contains_key("occurred_at"));
        assert!(obj.contains_key("occurred_at_iso"));
        assert!(obj.contains_key("event_type"));
        assert!(obj.contains_key("actor"));
        assert!(obj.contains_key("zone_id"));
        assert!(obj.contains_key("correlation_id"));
    }

    #[test]
    fn serde_json_shape_optional_keys_absent_when_none() {
        let e = minimal_event();
        let val: serde_json::Value = serde_json::to_value(&e).unwrap();
        let obj = val.as_object().unwrap();
        assert!(!obj.contains_key("trace_id"));
        assert!(!obj.contains_key("span_id"));
        assert!(!obj.contains_key("connector_id"));
        assert!(!obj.contains_key("operation_id"));
        assert!(!obj.contains_key("prev"));
    }

    #[test]
    fn serde_json_shape_optional_keys_present_when_some() {
        let e = sample_event();
        let val: serde_json::Value = serde_json::to_value(&e).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("span_id"));
        assert!(obj.contains_key("connector_id"));
        assert!(obj.contains_key("operation_id"));
        assert!(obj.contains_key("prev"));
    }

    #[test]
    fn serde_seq_is_number() {
        let e = sample_event();
        let val: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert!(val["seq"].is_u64());
        assert_eq!(val["seq"].as_u64().unwrap(), 42);
    }

    #[test]
    fn serde_occurred_at_is_number() {
        let e = sample_event();
        let val: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert!(val["occurred_at"].is_u64());
    }

    // ================================================================
    // AuditEventOutput — clone behavior
    // ================================================================

    #[test]
    fn clone_preserves_all_fields() {
        let e = sample_event();
        let cloned = e.clone();
        assert_eq!(e.seq, cloned.seq);
        assert_eq!(e.occurred_at, cloned.occurred_at);
        assert_eq!(e.occurred_at_iso, cloned.occurred_at_iso);
        assert_eq!(e.event_type, cloned.event_type);
        assert_eq!(e.actor, cloned.actor);
        assert_eq!(e.zone_id, cloned.zone_id);
        assert_eq!(e.correlation_id, cloned.correlation_id);
        assert_eq!(e.trace_id, cloned.trace_id);
        assert_eq!(e.span_id, cloned.span_id);
        assert_eq!(e.connector_id, cloned.connector_id);
        assert_eq!(e.operation_id, cloned.operation_id);
        assert_eq!(e.prev, cloned.prev);
    }

    #[test]
    fn clone_minimal_event_preserves_nones() {
        let e = minimal_event();
        let cloned = e.clone();
        assert!(cloned.trace_id.is_none());
        assert!(cloned.span_id.is_none());
        assert!(cloned.connector_id.is_none());
        assert!(cloned.operation_id.is_none());
        assert!(cloned.prev.is_none());
    }

    // ================================================================
    // AuditEventOutput — boundary values
    // ================================================================

    #[test]
    fn event_with_max_seq() {
        let mut e = minimal_event();
        e.seq = u64::MAX;
        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEventOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, u64::MAX);
    }

    #[test]
    fn event_with_max_occurred_at() {
        let mut e = minimal_event();
        e.occurred_at = u64::MAX;
        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEventOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.occurred_at, u64::MAX);
    }

    #[test]
    fn event_with_empty_strings() {
        let e = AuditEventOutput {
            seq: 0,
            occurred_at: 0,
            occurred_at_iso: String::new(),
            event_type: String::new(),
            actor: String::new(),
            zone_id: String::new(),
            correlation_id: String::new(),
            trace_id: None,
            span_id: None,
            connector_id: None,
            operation_id: None,
            prev: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: AuditEventOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type, "");
        assert_eq!(parsed.actor, "");
        assert_eq!(parsed.zone_id, "");
    }

    #[test]
    fn event_with_empty_event_type_gets_default_color() {
        let mut e = minimal_event();
        e.event_type = String::new();
        assert_eq!(e.event_type_color(), "\x1b[0m");
    }

    #[test]
    fn event_with_empty_event_type_gets_bullet_symbol() {
        let mut e = minimal_event();
        e.event_type = String::new();
        assert_eq!(e.event_type_symbol(), "\u{2022}");
    }

    // ================================================================
    // AuditFilter — per-field rejection
    // ================================================================

    #[test]
    fn filter_rejects_wrong_connector_id() {
        let filter = AuditFilter {
            connector_id: Some("wrong".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&sample_event()));
    }

    #[test]
    fn filter_rejects_wrong_operation_id() {
        let filter = AuditFilter {
            operation_id: Some("wrong_op".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&sample_event()));
    }

    #[test]
    fn filter_rejects_wrong_correlation_id() {
        let filter = AuditFilter {
            correlation_id: Some("wrong".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&sample_event()));
    }

    #[test]
    fn filter_rejects_wrong_trace_id() {
        let filter = AuditFilter {
            trace_id: Some("wrong".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&sample_event()));
    }

    #[test]
    fn filter_rejects_wrong_event_type() {
        let filter = AuditFilter {
            event_type: Some("wrong.type".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&sample_event()));
    }

    #[test]
    fn filter_rejects_wrong_actor() {
        let filter = AuditFilter {
            actor: Some("user:wrong".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&sample_event()));
    }

    #[test]
    fn filter_matches_event_with_none_connector() {
        // Event has no connector_id, filter also has no connector requirement → match
        let mut e = sample_event();
        e.connector_id = None;
        let filter = AuditFilter::default();
        assert!(filter.matches(&e));
    }

    #[test]
    fn filter_connector_rejects_when_event_has_none() {
        let mut e = sample_event();
        e.connector_id = None;
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&e));
    }

    #[test]
    fn filter_operation_rejects_when_event_has_none() {
        let mut e = sample_event();
        e.operation_id = None;
        let filter = AuditFilter {
            operation_id: Some("send_message".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&e));
    }

    #[test]
    fn filter_trace_rejects_when_event_has_none() {
        let mut e = sample_event();
        e.trace_id = None;
        let filter = AuditFilter {
            trace_id: Some("deadbeef".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&e));
    }

    // ================================================================
    // AuditFilter — combined filters
    // ================================================================

    #[test]
    fn filter_combined_all_matching() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            correlation_id: Some("aabbccdd11223344aabbccdd11223344".to_string()),
            trace_id: Some("deadbeef00112233deadbeef00112233".to_string()),
            event_type: Some("capability.invoke".to_string()),
            actor: Some("user:alice".to_string()),
        };
        assert!(filter.matches(&sample_event()));
    }

    #[test]
    fn filter_combined_one_mismatch() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            correlation_id: Some("aabbccdd11223344aabbccdd11223344".to_string()),
            trace_id: Some("deadbeef00112233deadbeef00112233".to_string()),
            event_type: Some("capability.invoke".to_string()),
            actor: Some("user:bob".to_string()), // mismatch
        };
        assert!(!filter.matches(&sample_event()));
    }

    // ================================================================
    // AuditFilter — is_empty per field
    // ================================================================

    #[test]
    fn filter_not_empty_with_operation_id() {
        let filter = AuditFilter {
            operation_id: Some("x".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    #[test]
    fn filter_not_empty_with_correlation_id() {
        let filter = AuditFilter {
            correlation_id: Some("x".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    #[test]
    fn filter_not_empty_with_trace_id() {
        let filter = AuditFilter {
            trace_id: Some("x".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    #[test]
    fn filter_not_empty_with_event_type() {
        let filter = AuditFilter {
            event_type: Some("x".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    #[test]
    fn filter_not_empty_with_actor() {
        let filter = AuditFilter {
            actor: Some("x".to_string()),
            ..Default::default()
        };
        assert!(!filter.is_empty());
    }

    // ================================================================
    // AuditFilter — serde roundtrip
    // ================================================================

    #[test]
    fn filter_serde_roundtrip_default() {
        let f = AuditFilter::default();
        let json = serde_json::to_string(&f).unwrap();
        let parsed: AuditFilter = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn filter_serde_roundtrip_populated() {
        let f = AuditFilter {
            connector_id: Some("c".to_string()),
            operation_id: Some("o".to_string()),
            correlation_id: Some("corr".to_string()),
            trace_id: Some("t".to_string()),
            event_type: Some("e".to_string()),
            actor: Some("a".to_string()),
        };
        let json = serde_json::to_string(&f).unwrap();
        let parsed: AuditFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id.as_deref(), Some("c"));
        assert_eq!(parsed.operation_id.as_deref(), Some("o"));
        assert_eq!(parsed.correlation_id.as_deref(), Some("corr"));
        assert_eq!(parsed.trace_id.as_deref(), Some("t"));
        assert_eq!(parsed.event_type.as_deref(), Some("e"));
        assert_eq!(parsed.actor.as_deref(), Some("a"));
    }

    #[test]
    fn filter_serde_omits_none_fields() {
        let f = AuditFilter::default();
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("connector_id"));
        assert!(!json.contains("operation_id"));
        assert!(!json.contains("correlation_id"));
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("event_type"));
        assert!(!json.contains("actor"));
    }

    #[test]
    fn filter_serde_includes_some_fields() {
        let f = AuditFilter {
            connector_id: Some("fcp.test".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("connector_id"));
        assert!(json.contains("fcp.test"));
    }

    // ================================================================
    // AuditFilter — clone
    // ================================================================

    #[test]
    fn filter_clone_preserves_all_fields() {
        let f = AuditFilter {
            connector_id: Some("c".to_string()),
            operation_id: Some("o".to_string()),
            correlation_id: Some("corr".to_string()),
            trace_id: Some("t".to_string()),
            event_type: Some("e".to_string()),
            actor: Some("a".to_string()),
        };
        let cloned = f.clone();
        assert_eq!(f.connector_id, cloned.connector_id);
        assert_eq!(f.operation_id, cloned.operation_id);
        assert_eq!(f.correlation_id, cloned.correlation_id);
        assert_eq!(f.trace_id, cloned.trace_id);
        assert_eq!(f.event_type, cloned.event_type);
        assert_eq!(f.actor, cloned.actor);
    }

    // ================================================================
    // AuditStreamSummary — serde roundtrip
    // ================================================================

    #[test]
    fn stream_summary_serde_roundtrip() {
        let summary = AuditStreamSummary {
            total_events: 100,
            filtered_events: 20,
            start_seq: 0,
            end_seq: 99,
            start_time: chrono::Utc::now(),
            end_time: chrono::Utc::now(),
            zone_id: "z:work".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: AuditStreamSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_events, 100);
        assert_eq!(parsed.filtered_events, 20);
        assert_eq!(parsed.start_seq, 0);
        assert_eq!(parsed.end_seq, 99);
        assert_eq!(parsed.zone_id, "z:work");
    }

    #[test]
    fn stream_summary_clone() {
        let summary = AuditStreamSummary {
            total_events: 50,
            filtered_events: 10,
            start_seq: 5,
            end_seq: 54,
            start_time: chrono::Utc::now(),
            end_time: chrono::Utc::now(),
            zone_id: "z:test".to_string(),
        };
        let cloned = summary.clone();
        assert_eq!(summary.total_events, cloned.total_events);
        assert_eq!(summary.filtered_events, cloned.filtered_events);
        assert_eq!(summary.zone_id, cloned.zone_id);
    }

    #[test]
    fn stream_summary_json_shape() {
        let summary = AuditStreamSummary {
            total_events: 1,
            filtered_events: 0,
            start_seq: 0,
            end_seq: 0,
            start_time: chrono::Utc::now(),
            end_time: chrono::Utc::now(),
            zone_id: "z:x".to_string(),
        };
        let val: serde_json::Value = serde_json::to_value(&summary).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("total_events"));
        assert!(obj.contains_key("filtered_events"));
        assert!(obj.contains_key("start_seq"));
        assert!(obj.contains_key("end_seq"));
        assert!(obj.contains_key("start_time"));
        assert!(obj.contains_key("end_time"));
        assert!(obj.contains_key("zone_id"));
    }

    #[test]
    fn stream_summary_boundary_zero_events() {
        let summary = AuditStreamSummary {
            total_events: 0,
            filtered_events: 0,
            start_seq: 0,
            end_seq: 0,
            start_time: chrono::Utc::now(),
            end_time: chrono::Utc::now(),
            zone_id: "z:empty".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: AuditStreamSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_events, 0);
    }

    // ================================================================
    // AuditTailError — serde roundtrip
    // ================================================================

    #[test]
    fn tail_error_serde_roundtrip() {
        let err = AuditTailError::zone_not_found("z:test");
        let json = serde_json::to_string(&err).unwrap();
        let parsed: AuditTailError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "FCP-4001");
        assert!(parsed.message.contains("z:test"));
        assert!(!parsed.hints.is_empty());
    }

    #[test]
    fn tail_error_serde_roundtrip_interrupted() {
        let err = AuditTailError::interrupted();
        let json = serde_json::to_string(&err).unwrap();
        let parsed: AuditTailError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "FCP-9001");
        assert_eq!(parsed.hints.len(), 1);
    }

    #[test]
    fn tail_error_serde_empty_hints_omitted() {
        let err = AuditTailError {
            code: "TEST".to_string(),
            message: "test".to_string(),
            hints: vec![],
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("hints"));
    }

    #[test]
    fn tail_error_serde_hints_present_when_nonempty() {
        let err = AuditTailError::zone_not_found("z:x");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("hints"));
    }

    // ================================================================
    // AuditTailError — Display + Error
    // ================================================================

    #[test]
    fn tail_error_display_format() {
        let err = AuditTailError {
            code: "E-1234".to_string(),
            message: "something went wrong".to_string(),
            hints: vec![],
        };
        let s = format!("{err}");
        assert_eq!(s, "E-1234: something went wrong");
    }

    #[test]
    fn tail_error_is_std_error() {
        let err = AuditTailError::zone_not_found("z:x");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn tail_error_chain_unavailable_hints_count() {
        let err = AuditTailError::chain_unavailable("z:test");
        assert_eq!(err.hints.len(), 3);
    }

    #[test]
    fn tail_error_zone_not_found_hints_count() {
        let err = AuditTailError::zone_not_found("z:test");
        assert_eq!(err.hints.len(), 3);
    }

    #[test]
    fn tail_error_interrupted_hints_count() {
        let err = AuditTailError::interrupted();
        assert_eq!(err.hints.len(), 1);
    }

    #[test]
    fn tail_error_clone() {
        let err = AuditTailError::zone_not_found("z:x");
        let cloned = err.clone();
        assert_eq!(err.code, cloned.code);
        assert_eq!(err.message, cloned.message);
        assert_eq!(err.hints.len(), cloned.hints.len());
    }

    // ================================================================
    // event_types constants
    // ================================================================

    #[test]
    fn event_type_constants_values() {
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
    fn event_type_constants_match_color_branches() {
        let mut e = minimal_event();

        e.event_type = event_types::SECRET_ACCESS.to_string();
        assert_eq!(e.event_type_color(), "\x1b[33m");

        e.event_type = event_types::CAPABILITY_INVOKE.to_string();
        assert_eq!(e.event_type_color(), "\x1b[32m");

        e.event_type = event_types::ELEVATION_GRANTED.to_string();
        assert_eq!(e.event_type_color(), "\x1b[36m");

        e.event_type = event_types::DECLASSIFICATION_GRANTED.to_string();
        assert_eq!(e.event_type_color(), "\x1b[36m");

        e.event_type = event_types::ZONE_TRANSITION.to_string();
        assert_eq!(e.event_type_color(), "\x1b[35m");

        e.event_type = event_types::REVOCATION_ISSUED.to_string();
        assert_eq!(e.event_type_color(), "\x1b[31m");

        e.event_type = event_types::SECURITY_VIOLATION.to_string();
        assert_eq!(e.event_type_color(), "\x1b[31m");

        e.event_type = event_types::AUDIT_FORK_DETECTED.to_string();
        assert_eq!(e.event_type_color(), "\x1b[31;1m");
    }

    #[test]
    fn event_type_constants_match_symbol_branches() {
        let mut e = minimal_event();

        e.event_type = event_types::SECRET_ACCESS.to_string();
        assert_eq!(e.event_type_symbol(), "\u{1f511}");

        e.event_type = event_types::CAPABILITY_INVOKE.to_string();
        assert_eq!(e.event_type_symbol(), "\u{26a1}");

        e.event_type = event_types::ELEVATION_GRANTED.to_string();
        assert_eq!(e.event_type_symbol(), "\u{2b06}");

        e.event_type = event_types::DECLASSIFICATION_GRANTED.to_string();
        assert_eq!(e.event_type_symbol(), "\u{1f513}");

        e.event_type = event_types::ZONE_TRANSITION.to_string();
        assert_eq!(e.event_type_symbol(), "\u{2192}");

        e.event_type = event_types::REVOCATION_ISSUED.to_string();
        assert_eq!(e.event_type_symbol(), "\u{2298}");

        e.event_type = event_types::SECURITY_VIOLATION.to_string();
        assert_eq!(e.event_type_symbol(), "\u{26a0}");

        e.event_type = event_types::AUDIT_FORK_DETECTED.to_string();
        assert_eq!(e.event_type_symbol(), "\u{26a0}");
    }

    // ================================================================
    // AuditFilter — deserialize from JSON with missing optional fields
    // ================================================================

    #[test]
    fn filter_deserialize_empty_object() {
        let f: AuditFilter = serde_json::from_str("{}").unwrap();
        assert!(f.is_empty());
        assert!(f.connector_id.is_none());
    }

    #[test]
    fn filter_deserialize_partial_fields() {
        let f: AuditFilter = serde_json::from_str(r#"{"actor":"user:x"}"#).unwrap();
        assert!(!f.is_empty());
        assert_eq!(f.actor.as_deref(), Some("user:x"));
        assert!(f.connector_id.is_none());
        assert!(f.event_type.is_none());
    }

    // ================================================================
    // AuditEventOutput — deserialize with missing optional fields
    // ================================================================

    #[test]
    fn event_deserialize_missing_optionals() {
        let json = r#"{
            "seq": 1,
            "occurred_at": 100,
            "occurred_at_iso": "ts",
            "event_type": "test",
            "actor": "user:x",
            "zone_id": "z:a",
            "correlation_id": "c"
        }"#;
        let e: AuditEventOutput = serde_json::from_str(json).unwrap();
        assert_eq!(e.seq, 1);
        assert!(e.trace_id.is_none());
        assert!(e.span_id.is_none());
        assert!(e.connector_id.is_none());
        assert!(e.operation_id.is_none());
        assert!(e.prev.is_none());
    }

    // ================================================================
    // AuditTailError — json shape
    // ================================================================

    #[test]
    fn tail_error_json_shape() {
        let err = AuditTailError::zone_not_found("z:x");
        let val: serde_json::Value = serde_json::to_value(&err).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("code"));
        assert!(obj.contains_key("message"));
        assert!(obj.contains_key("hints"));
    }

    #[test]
    fn tail_error_json_shape_no_hints() {
        let err = AuditTailError {
            code: "X".to_string(),
            message: "y".to_string(),
            hints: vec![],
        };
        let val: serde_json::Value = serde_json::to_value(&err).unwrap();
        let obj = val.as_object().unwrap();
        // hints is empty vec so skip_serializing_if Vec::is_empty kicks in
        assert!(!obj.contains_key("hints"));
    }
}
