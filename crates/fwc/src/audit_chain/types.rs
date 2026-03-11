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
}
