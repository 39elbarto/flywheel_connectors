//! Event types for FCP - streaming events and envelopes.
//!
//! Based on FCP Specification Section 9 (Wire Protocol) - Event Messages.

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{ConnectorId, CorrelationId, InstanceId, Principal, ZoneId};

/// Event envelope wrapper for streaming events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Event topic
    pub topic: String,

    /// Timestamp when event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Sequence number for ordering
    pub seq: u64,

    /// Cursor for replay
    pub cursor: String,

    /// Whether acknowledgment is required
    pub requires_ack: bool,

    /// Event data
    pub data: EventData,
}

impl EventEnvelope {
    /// Create a new event envelope.
    #[must_use]
    pub fn new(topic: impl Into<String>, data: EventData) -> Self {
        Self {
            topic: topic.into(),
            timestamp: chrono::Utc::now(),
            seq: 0,
            cursor: String::new(),
            requires_ack: false,
            data,
        }
    }

    /// Set the sequence number.
    #[must_use]
    pub const fn with_seq(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// Set the cursor.
    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = cursor.into();
        self
    }

    /// Require acknowledgment.
    #[must_use]
    pub const fn requiring_ack(mut self) -> Self {
        self.requires_ack = true;
        self
    }

    /// Schema identifier for canonical encoding.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.stream", "EventEnvelope", Version::new(1, 1, 0))
    }

    /// Canonical bytes (schema hash + deterministic CBOR).
    ///
    /// # Errors
    /// Returns `SerializationError` if encoding fails or payload is oversized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        CanonicalSerializer::serialize(self, &Self::schema())
    }

    /// Convenience: set cursor to the decimal `seq` string.
    #[must_use]
    pub fn with_cursor_seq(mut self, seq: u64) -> Self {
        self.cursor = seq.to_string();
        self
    }
}

/// Thread context for event metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreadKind {
    /// Standard thread under a parent message.
    Thread,
    /// Forum topic (e.g., Telegram forum topics).
    ForumTopic,
    /// Channel-scoped thread (platform-native thread or topic channel).
    Channel,
    /// Reply thread (reply-chain semantics).
    Reply,
}

/// Normalized thread metadata for events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreadInfo {
    /// Thread identifier in the source system.
    pub thread_id: String,
    /// Optional parent identifier (message/channel/topic).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Thread kind.
    pub kind: ThreadKind,
}

impl ThreadInfo {
    /// Create thread metadata with required fields.
    #[must_use]
    pub fn new(thread_id: impl Into<String>, kind: ThreadKind) -> Self {
        Self {
            thread_id: thread_id.into(),
            parent_id: None,
            kind,
        }
    }

    /// Attach a parent identifier (message/channel/topic).
    #[must_use]
    pub fn with_parent_id(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }
}

/// Event data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    /// Source connector
    pub connector_id: ConnectorId,

    /// Source instance
    pub instance_id: InstanceId,

    /// Zone the event originated from
    pub zone_id: ZoneId,

    /// Principal that caused the event
    pub principal: Principal,

    /// Event payload (JSON)
    pub payload: serde_json::Value,

    /// Correlation ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,

    /// Resource URIs affected by this event
    #[serde(default)]
    pub resource_uris: Vec<String>,

    /// Optional thread metadata for threading/ordering semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_info: Option<ThreadInfo>,
}

impl EventData {
    /// Create new event data.
    #[must_use]
    pub const fn new(
        connector_id: ConnectorId,
        instance_id: InstanceId,
        zone_id: ZoneId,
        principal: Principal,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            connector_id,
            instance_id,
            zone_id,
            principal,
            payload,
            correlation_id: None,
            resource_uris: Vec::new(),
            thread_info: None,
        }
    }

    /// Add a correlation ID.
    #[must_use]
    pub const fn with_correlation_id(mut self, id: CorrelationId) -> Self {
        self.correlation_id = Some(id);
        self
    }

    /// Add resource URIs.
    #[must_use]
    pub fn with_resource_uris(mut self, uris: Vec<String>) -> Self {
        self.resource_uris = uris;
        self
    }

    /// Attach thread metadata.
    #[must_use]
    pub fn with_thread_info(mut self, info: ThreadInfo) -> Self {
        self.thread_info = Some(info);
        self
    }
}

/// Event acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAck {
    /// Message type ("ack")
    pub r#type: String,

    /// Topic of the event being acknowledged
    pub topic: String,

    /// Sequence numbers being acknowledged
    pub seqs: Vec<u64>,

    /// Cursors being acknowledged
    #[serde(default)]
    pub cursors: Vec<String>,
}

impl EventAck {
    /// Create a new acknowledgment.
    #[must_use]
    pub fn new(topic: impl Into<String>, seqs: Vec<u64>) -> Self {
        Self {
            r#type: "ack".into(),
            topic: topic.into(),
            seqs,
            cursors: Vec::new(),
        }
    }

    /// Add cursors.
    #[must_use]
    pub fn with_cursors(mut self, cursors: Vec<String>) -> Self {
        self.cursors = cursors;
        self
    }

    /// Schema identifier for canonical encoding.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.stream", "EventAck", Version::new(1, 0, 0))
    }

    /// Canonical bytes (schema hash + deterministic CBOR).
    ///
    /// # Errors
    /// Returns `SerializationError` if encoding fails or payload is oversized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        CanonicalSerializer::serialize(self, &Self::schema())
    }
}

/// Negative acknowledgment (for redelivery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNack {
    /// Message type ("nack")
    pub r#type: String,

    /// Topic of the event
    pub topic: String,

    /// Sequence numbers to redeliver
    pub seqs: Vec<u64>,

    /// Reason for nack
    pub reason: String,

    /// Delay before redelivery in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

impl EventNack {
    /// Create a new negative acknowledgment.
    #[must_use]
    pub fn new(topic: impl Into<String>, seqs: Vec<u64>, reason: impl Into<String>) -> Self {
        Self {
            r#type: "nack".into(),
            topic: topic.into(),
            seqs,
            reason: reason.into(),
            delay_ms: None,
        }
    }

    /// Set the redelivery delay.
    #[must_use]
    pub const fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = Some(delay_ms);
        self
    }

    /// Schema identifier for canonical encoding.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.stream", "EventNack", Version::new(1, 0, 0))
    }

    /// Canonical bytes (schema hash + deterministic CBOR).
    ///
    /// # Errors
    /// Returns `SerializationError` if encoding fails or payload is oversized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        CanonicalSerializer::serialize(self, &Self::schema())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::TrustLevel;

    fn sample_connector_id() -> ConnectorId {
        ConnectorId::from_static("test:streaming:v1")
    }

    fn sample_principal() -> Principal {
        Principal {
            kind: "user".to_string(),
            id: "alice".to_string(),
            trust: TrustLevel::Paired,
            display: Some("Alice".to_string()),
        }
    }

    fn sample_event_data() -> EventData {
        EventData::new(
            sample_connector_id(),
            InstanceId::new(),
            ZoneId::work(),
            sample_principal(),
            json!({"action": "created", "resource": "document"}),
        )
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventEnvelope tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_envelope_new_sets_defaults() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.test", data);

        assert_eq!(envelope.topic, "events.test");
        assert_eq!(envelope.seq, 0);
        assert!(envelope.cursor.is_empty());
        assert!(!envelope.requires_ack);
    }

    #[test]
    fn event_envelope_with_seq() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.test", data).with_seq(42);

        assert_eq!(envelope.seq, 42);
    }

    #[test]
    fn event_envelope_with_cursor() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.test", data).with_cursor("cursor-abc123");

        assert_eq!(envelope.cursor, "cursor-abc123");
    }

    #[test]
    fn event_envelope_requiring_ack() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.test", data).requiring_ack();

        assert!(envelope.requires_ack);
    }

    #[test]
    fn event_envelope_builder_chain() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.chain", data)
            .with_seq(100)
            .with_cursor("cursor-xyz")
            .requiring_ack();

        assert_eq!(envelope.topic, "events.chain");
        assert_eq!(envelope.seq, 100);
        assert_eq!(envelope.cursor, "cursor-xyz");
        assert!(envelope.requires_ack);
    }

    #[test]
    fn event_envelope_serialization_roundtrip() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.roundtrip", data)
            .with_seq(5)
            .with_cursor("cur-001");

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: EventEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.topic, "events.roundtrip");
        assert_eq!(parsed.seq, 5);
        assert_eq!(parsed.cursor, "cur-001");
    }

    #[test]
    fn event_envelope_serialization_includes_cursor() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.minimal", data);

        let json = serde_json::to_string(&envelope).unwrap();

        // Cursor is always present for replay semantics
        assert!(json.contains("\"cursor\":\"\""));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventData tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_data_new_sets_fields() {
        let principal = Principal {
            kind: "service".to_string(),
            id: "backend".to_string(),
            trust: TrustLevel::Paired,
            display: None,
        };
        let data = EventData::new(
            ConnectorId::from_static("my:connector:v1"),
            InstanceId::new(),
            ZoneId::private(),
            principal,
            json!({"key": "value"}),
        );

        assert_eq!(data.connector_id.as_str(), "my:connector:v1");
        assert!(data.instance_id.as_str().starts_with("inst_"));
        assert_eq!(data.zone_id.as_str(), "z:private");
        assert_eq!(data.principal.kind, "service");
        assert_eq!(data.principal.id, "backend");
        assert_eq!(data.payload, json!({"key": "value"}));
        assert!(data.correlation_id.is_none());
        assert!(data.resource_uris.is_empty());
        assert!(data.thread_info.is_none());
    }

    #[test]
    fn event_data_with_correlation_id() {
        let corr_id = CorrelationId::new();
        let data = sample_event_data().with_correlation_id(corr_id.clone());

        assert_eq!(data.correlation_id.unwrap(), corr_id);
    }

    #[test]
    fn event_data_with_resource_uris() {
        let uris = vec![
            "fcp://connector/resource/1".to_string(),
            "fcp://connector/resource/2".to_string(),
        ];
        let data = sample_event_data().with_resource_uris(uris.clone());

        assert_eq!(data.resource_uris, uris);
    }

    #[test]
    fn event_data_with_thread_info() {
        let thread =
            ThreadInfo::new("thread-123", ThreadKind::ForumTopic).with_parent_id("channel-1");
        let data = sample_event_data().with_thread_info(thread.clone());

        assert_eq!(data.thread_info, Some(thread));
    }

    #[test]
    fn event_data_builder_chain() {
        let corr_id = CorrelationId::new();
        let data = sample_event_data()
            .with_correlation_id(corr_id.clone())
            .with_resource_uris(vec!["fcp://res/1".to_string()]);

        assert_eq!(data.correlation_id.unwrap(), corr_id);
        assert_eq!(data.resource_uris.len(), 1);
    }

    #[test]
    fn event_data_serialization_roundtrip() {
        let corr_id = CorrelationId::new();
        let data = sample_event_data()
            .with_correlation_id(corr_id.clone())
            .with_resource_uris(vec!["uri:1".to_string(), "uri:2".to_string()]);

        let json = serde_json::to_string(&data).unwrap();
        let parsed: EventData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.connector_id.as_str(), "test:streaming:v1");
        assert_eq!(parsed.correlation_id.unwrap(), corr_id);
        assert_eq!(parsed.resource_uris.len(), 2);
    }

    #[test]
    fn event_data_serialization_includes_thread_info() {
        let thread = ThreadInfo::new("thread-9", ThreadKind::Thread);
        let data = sample_event_data().with_thread_info(thread.clone());

        let json = serde_json::to_string(&data).unwrap();
        let parsed: EventData = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.thread_info, Some(thread));
    }

    #[test]
    fn event_data_empty_resource_uris_deserializes() {
        // Verify default for resource_uris works during deserialization
        let json = r#"{
            "connector_id": "c1:test:v1",
            "instance_id": "inst_test",
            "zone_id": "z:work",
            "principal": {"kind": "user", "id": "bob", "trust": "paired"},
            "payload": {}
        }"#;

        let data: EventData = serde_json::from_str(json).unwrap();
        assert!(data.resource_uris.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventAck tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_ack_new_sets_defaults() {
        let ack = EventAck::new("events.acked", vec![1, 2, 3]);

        assert_eq!(ack.r#type, "ack");
        assert_eq!(ack.topic, "events.acked");
        assert_eq!(ack.seqs, vec![1, 2, 3]);
        assert!(ack.cursors.is_empty());
    }

    #[test]
    fn event_ack_with_cursors() {
        let ack = EventAck::new("events.cursor", vec![5])
            .with_cursors(vec!["cur-a".to_string(), "cur-b".to_string()]);

        assert_eq!(ack.cursors, vec!["cur-a", "cur-b"]);
    }

    #[test]
    fn event_ack_empty_seqs() {
        let ack = EventAck::new("events.empty", vec![]);

        assert!(ack.seqs.is_empty());
    }

    #[test]
    fn event_ack_serialization_roundtrip() {
        let ack = EventAck::new("events.roundtrip", vec![10, 20, 30])
            .with_cursors(vec!["cursor-1".to_string()]);

        let json = serde_json::to_string(&ack).unwrap();
        let parsed: EventAck = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.r#type, "ack");
        assert_eq!(parsed.topic, "events.roundtrip");
        assert_eq!(parsed.seqs, vec![10, 20, 30]);
        assert_eq!(parsed.cursors, vec!["cursor-1"]);
    }

    #[test]
    fn event_ack_cursors_default_empty() {
        // Verify default works during deserialization
        let json = r#"{
            "type": "ack",
            "topic": "test",
            "seqs": [1]
        }"#;

        let ack: EventAck = serde_json::from_str(json).unwrap();
        assert!(ack.cursors.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventNack tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_nack_new_sets_defaults() {
        let nack = EventNack::new("events.failed", vec![7, 8], "processing error");

        assert_eq!(nack.r#type, "nack");
        assert_eq!(nack.topic, "events.failed");
        assert_eq!(nack.seqs, vec![7, 8]);
        assert_eq!(nack.reason, "processing error");
        assert!(nack.delay_ms.is_none());
    }

    #[test]
    fn event_nack_with_delay() {
        let nack = EventNack::new("events.retry", vec![1], "temporary failure").with_delay(5000);

        assert_eq!(nack.delay_ms, Some(5000));
    }

    #[test]
    fn event_nack_serialization_roundtrip() {
        let nack = EventNack::new("events.nack.rt", vec![100], "timeout").with_delay(10000);

        let json = serde_json::to_string(&nack).unwrap();
        let parsed: EventNack = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.r#type, "nack");
        assert_eq!(parsed.topic, "events.nack.rt");
        assert_eq!(parsed.seqs, vec![100]);
        assert_eq!(parsed.reason, "timeout");
        assert_eq!(parsed.delay_ms, Some(10000));
    }

    #[test]
    fn event_nack_optional_delay_omitted() {
        let nack = EventNack::new("events.no-delay", vec![1], "error");

        let json = serde_json::to_string(&nack).unwrap();

        assert!(!json.contains("delay_ms"));
    }

    #[test]
    fn event_nack_multiple_seqs() {
        let nack = EventNack::new("events.batch", vec![1, 2, 3, 4, 5], "batch failure");

        assert_eq!(nack.seqs.len(), 5);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Integration tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_flow_envelope_to_ack() {
        // Simulate a typical event flow: envelope received, then acked
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.flow", data)
            .with_seq(42)
            .with_cursor("cur-flow-42")
            .requiring_ack();

        // Client receives envelope and sends ack
        let ack =
            EventAck::new(&envelope.topic, vec![envelope.seq]).with_cursors(vec![envelope.cursor]);

        assert_eq!(ack.topic, "events.flow");
        assert_eq!(ack.seqs, vec![42]);
        assert_eq!(ack.cursors, vec!["cur-flow-42"]);
    }

    #[test]
    fn event_flow_envelope_to_nack() {
        // Simulate a failed event processing: envelope received, then nacked
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.failure", data)
            .with_seq(99)
            .requiring_ack();

        // Client fails processing and sends nack
        let nack = EventNack::new(&envelope.topic, vec![envelope.seq], "database unavailable")
            .with_delay(10000);

        assert_eq!(nack.topic, "events.failure");
        assert_eq!(nack.seqs, vec![99]);
        assert_eq!(nack.delay_ms, Some(10000));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Canonical encoding tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_envelope_canonical_bytes_prefix_schema_hash() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.canonical", data)
            .with_seq(7)
            .with_cursor_seq(7);

        let bytes = envelope.canonical_bytes().unwrap();
        let schema_hash = EventEnvelope::schema().hash();

        assert_eq!(&bytes[..fcp_cbor::SCHEMA_HASH_LEN], schema_hash.as_bytes());
    }

    #[test]
    fn event_ack_canonical_bytes_prefix_schema_hash() {
        let ack = EventAck::new("events.ack", vec![1, 2]).with_cursors(vec!["c1".into()]);
        let bytes = ack.canonical_bytes().unwrap();
        let schema_hash = EventAck::schema().hash();

        assert_eq!(&bytes[..fcp_cbor::SCHEMA_HASH_LEN], schema_hash.as_bytes());
    }

    #[test]
    fn event_nack_canonical_bytes_prefix_schema_hash() {
        let nack = EventNack::new("events.nack", vec![3], "retry").with_delay(250);
        let bytes = nack.canonical_bytes().unwrap();
        let schema_hash = EventNack::schema().hash();

        assert_eq!(&bytes[..fcp_cbor::SCHEMA_HASH_LEN], schema_hash.as_bytes());
    }
}
