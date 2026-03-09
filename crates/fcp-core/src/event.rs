//! Event types for FCP - streaming events and envelopes.
//!
//! Based on FCP Specification Section 9 (Wire Protocol) - Event Messages.

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{ConnectorId, CorrelationId, InstanceId, Principal, ZoneId};

/// Policy governing how sequence numbers on an event stream are interpreted.
///
/// Connectors that emit ordering metadata should set this to indicate whether
/// ordering is global (gateway-scoped), per-key, or unordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingPolicy {
    /// The gateway (host) assigns sequence numbers globally.
    /// Events are totally ordered across all keys.
    Gateway,
    /// Sequence numbers are scoped per `stream_key`.
    /// Events with the same key are ordered; cross-key order is undefined.
    PerKey,
    /// No ordering guarantee. Sequence numbers may be used for deduplication
    /// but do not imply delivery order.
    Unordered,
}

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

    /// Optional stream key for per-key ordering.
    ///
    /// When set, events with the same `stream_key` are delivered in `seq` order.
    /// Connectors should populate this with a stable identifier (e.g., channel ID,
    /// user ID, or resource ID) when the source system provides key-scoped ordering.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stream_key: Option<String>,

    /// Ordering policy that governs how sequence numbers should be interpreted.
    ///
    /// Defaults to `None` (unspecified) for backward compatibility. Connectors
    /// that emit ordering metadata should set this explicitly.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ordering: Option<OrderingPolicy>,
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
            stream_key: None,
            ordering: None,
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

    /// Set the stream key for per-key ordering.
    #[must_use]
    pub fn with_stream_key(mut self, key: impl Into<String>) -> Self {
        self.stream_key = Some(key.into());
        self
    }

    /// Set the ordering policy.
    #[must_use]
    pub const fn with_ordering(mut self, policy: OrderingPolicy) -> Self {
        self.ordering = Some(policy);
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

    /// Normalize a Telegram forum topic identifier.
    #[must_use]
    pub fn from_telegram_message_thread(
        message_thread_id: i64,
        chat_id: impl Into<String>,
    ) -> Self {
        Self::new(message_thread_id.to_string(), ThreadKind::ForumTopic).with_parent_id(chat_id)
    }

    /// Normalize a Slack thread rooted at `thread_ts`.
    ///
    /// Slack commonly exposes only the root message timestamp (`thread_ts`).
    /// When no distinct parent message identifier is available, reuse
    /// `thread_ts` as the parent marker.
    #[must_use]
    pub fn from_slack_thread(
        thread_ts: impl Into<String>,
        parent_message_ts: Option<String>,
    ) -> Self {
        let thread_id = thread_ts.into();
        let parent_id = parent_message_ts.unwrap_or_else(|| thread_id.clone());
        Self::new(thread_id, ThreadKind::Reply).with_parent_id(parent_id)
    }

    /// Normalize a Discord thread channel identifier.
    #[must_use]
    pub fn from_discord_thread(
        channel_id: impl Into<String>,
        parent_channel_id: Option<String>,
    ) -> Self {
        let info = Self::new(channel_id, ThreadKind::Channel);
        match parent_channel_id {
            Some(parent_channel_id) => info.with_parent_id(parent_channel_id),
            None => info,
        }
    }

    /// Normalize a Discord channel payload when it represents a thread channel.
    #[must_use]
    pub fn from_discord_channel(
        channel_id: impl Into<String>,
        channel_type: i32,
        parent_channel_id: Option<String>,
    ) -> Option<Self> {
        match channel_type {
            10..=12 => Some(Self::from_discord_thread(channel_id, parent_channel_id)),
            _ => None,
        }
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
    // OrderingPolicy tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ordering_policy_serde_all_variants() {
        for (policy, expected) in [
            (OrderingPolicy::Gateway, "\"gateway\""),
            (OrderingPolicy::PerKey, "\"per_key\""),
            (OrderingPolicy::Unordered, "\"unordered\""),
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            assert_eq!(json, expected);
            let back: OrderingPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, back);
        }
    }

    #[test]
    fn ordering_policy_clone_and_copy() {
        let policy = OrderingPolicy::PerKey;
        let cloned = policy;
        assert_eq!(policy, cloned);
    }

    #[test]
    fn ordering_policy_debug_format() {
        let dbg = format!("{:?}", OrderingPolicy::Gateway);
        assert!(dbg.contains("Gateway"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventEnvelope stream_key / ordering tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_envelope_new_defaults_stream_key_none() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.test", data);
        assert!(envelope.stream_key.is_none());
        assert!(envelope.ordering.is_none());
    }

    #[test]
    fn event_envelope_with_stream_key() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.test", data).with_stream_key("channel-123");
        assert_eq!(envelope.stream_key, Some("channel-123".to_string()));
    }

    #[test]
    fn event_envelope_with_ordering() {
        let data = sample_event_data();
        let envelope =
            EventEnvelope::new("events.test", data).with_ordering(OrderingPolicy::PerKey);
        assert_eq!(envelope.ordering, Some(OrderingPolicy::PerKey));
    }

    #[test]
    fn event_envelope_stream_key_and_ordering_builder_chain() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.keyed", data)
            .with_seq(10)
            .with_stream_key("user-42")
            .with_ordering(OrderingPolicy::PerKey)
            .requiring_ack();

        assert_eq!(envelope.seq, 10);
        assert_eq!(envelope.stream_key, Some("user-42".to_string()));
        assert_eq!(envelope.ordering, Some(OrderingPolicy::PerKey));
        assert!(envelope.requires_ack);
    }

    #[test]
    fn event_envelope_stream_key_omitted_when_none() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.minimal", data);
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("stream_key"));
        assert!(!json.contains("ordering"));
    }

    #[test]
    fn event_envelope_stream_key_present_when_set() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.keyed", data)
            .with_stream_key("key-abc")
            .with_ordering(OrderingPolicy::Gateway);
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"stream_key\":\"key-abc\""));
        assert!(json.contains("\"ordering\":\"gateway\""));
    }

    #[test]
    fn event_envelope_ordering_roundtrip() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.rt", data)
            .with_stream_key("resource-99")
            .with_ordering(OrderingPolicy::Unordered)
            .with_seq(7);

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: EventEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.stream_key, Some("resource-99".to_string()));
        assert_eq!(parsed.ordering, Some(OrderingPolicy::Unordered));
        assert_eq!(parsed.seq, 7);
    }

    #[test]
    fn event_envelope_backward_compat_missing_stream_key() {
        // Old JSON without stream_key/ordering should deserialize with None defaults
        let json = r#"{
            "topic": "events.old",
            "timestamp": "2025-01-01T00:00:00Z",
            "seq": 1,
            "cursor": "c1",
            "requires_ack": false,
            "data": {
                "connector_id": "test:streaming:v1",
                "instance_id": "inst_old",
                "zone_id": "z:work",
                "principal": {"kind": "user", "id": "alice", "trust": "paired"},
                "payload": {}
            }
        }"#;

        let envelope: EventEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.topic, "events.old");
        assert!(envelope.stream_key.is_none());
        assert!(envelope.ordering.is_none());
    }

    #[test]
    fn event_envelope_gateway_ordering_no_stream_key() {
        // Gateway ordering doesn't require a stream_key (global ordering)
        let data = sample_event_data();
        let envelope =
            EventEnvelope::new("events.global", data).with_ordering(OrderingPolicy::Gateway);

        assert!(envelope.stream_key.is_none());
        assert_eq!(envelope.ordering, Some(OrderingPolicy::Gateway));

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("stream_key"));
        assert!(json.contains("\"ordering\":\"gateway\""));
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

    // ─────────────────────────────────────────────────────────────────────────────
    // ThreadKind serde tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn thread_kind_serde_all_variants() {
        for (kind, expected) in [
            (ThreadKind::Thread, "\"thread\""),
            (ThreadKind::ForumTopic, "\"forum_topic\""),
            (ThreadKind::Channel, "\"channel\""),
            (ThreadKind::Reply, "\"reply\""),
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, expected);
            let back: ThreadKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ThreadInfo tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn thread_info_new_no_parent() {
        let info = ThreadInfo::new("tid-1", ThreadKind::Thread);
        assert_eq!(info.thread_id, "tid-1");
        assert!(info.parent_id.is_none());
        assert_eq!(info.kind, ThreadKind::Thread);
    }

    #[test]
    fn thread_info_with_parent_id() {
        let info = ThreadInfo::new("tid-2", ThreadKind::ForumTopic).with_parent_id("parent-99");
        assert_eq!(info.parent_id, Some("parent-99".to_string()));
    }

    #[test]
    fn thread_info_from_telegram_message_thread() {
        let info = ThreadInfo::from_telegram_message_thread(42, "chat-9");
        assert_eq!(info.thread_id, "42");
        assert_eq!(info.parent_id, Some("chat-9".to_string()));
        assert_eq!(info.kind, ThreadKind::ForumTopic);
    }

    #[test]
    fn thread_info_from_slack_thread_uses_thread_ts_as_parent_by_default() {
        let info = ThreadInfo::from_slack_thread("1700000000.000100", None);
        assert_eq!(info.thread_id, "1700000000.000100");
        assert_eq!(info.parent_id, Some("1700000000.000100".to_string()));
        assert_eq!(info.kind, ThreadKind::Reply);
    }

    #[test]
    fn thread_info_from_slack_thread_respects_explicit_parent() {
        let info =
            ThreadInfo::from_slack_thread("1700000000.000100", Some("1700000000.000001".into()));
        assert_eq!(info.thread_id, "1700000000.000100");
        assert_eq!(info.parent_id, Some("1700000000.000001".to_string()));
        assert_eq!(info.kind, ThreadKind::Reply);
    }

    #[test]
    fn thread_info_from_discord_thread() {
        let info = ThreadInfo::from_discord_thread("thread-1", Some("channel-1".into()));
        assert_eq!(info.thread_id, "thread-1");
        assert_eq!(info.parent_id, Some("channel-1".to_string()));
        assert_eq!(info.kind, ThreadKind::Channel);
    }

    #[test]
    fn thread_info_from_discord_channel_filters_non_thread_channels() {
        assert!(ThreadInfo::from_discord_channel("channel-1", 0, Some("parent".into())).is_none());
        assert_eq!(
            ThreadInfo::from_discord_channel("thread-1", 11, Some("parent".into())),
            Some(ThreadInfo::from_discord_thread(
                "thread-1",
                Some("parent".into())
            ))
        );
    }

    #[test]
    fn thread_info_serde_roundtrip_with_parent() {
        let info =
            ThreadInfo::new("thread-abc", ThreadKind::Channel).with_parent_id("channel-main");
        let json = serde_json::to_string(&info).unwrap();
        let back: ThreadInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn thread_info_serde_roundtrip_without_parent() {
        let info = ThreadInfo::new("thread-solo", ThreadKind::Reply);
        let json = serde_json::to_string(&info).unwrap();
        // parent_id should be omitted
        assert!(!json.contains("parent_id"));
        let back: ThreadInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn thread_info_equality() {
        let a = ThreadInfo::new("t1", ThreadKind::Thread);
        let b = ThreadInfo::new("t1", ThreadKind::Thread);
        let c = ThreadInfo::new("t2", ThreadKind::Thread);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn thread_info_equality_kind_differs() {
        let a = ThreadInfo::new("t1", ThreadKind::Thread);
        let b = ThreadInfo::new("t1", ThreadKind::Reply);
        assert_ne!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventEnvelope additional tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_envelope_with_cursor_seq_sets_string() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.cursor-seq", data).with_cursor_seq(123);
        assert_eq!(envelope.cursor, "123");
    }

    #[test]
    fn event_envelope_with_cursor_seq_zero() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.zero", data).with_cursor_seq(0);
        assert_eq!(envelope.cursor, "0");
    }

    #[test]
    fn event_envelope_schema_is_stable() {
        let schema1 = EventEnvelope::schema();
        let schema2 = EventEnvelope::schema();
        assert_eq!(schema1.hash(), schema2.hash());
    }

    #[test]
    fn event_envelope_canonical_bytes_same_envelope_is_deterministic() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.det", data)
            .with_seq(1)
            .with_cursor("c");

        // Same envelope produces same canonical bytes on repeated calls
        let bytes1 = envelope.canonical_bytes().unwrap();
        let bytes2 = envelope.canonical_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventAck additional tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_ack_schema_is_stable() {
        let schema1 = EventAck::schema();
        let schema2 = EventAck::schema();
        assert_eq!(schema1.hash(), schema2.hash());
    }

    #[test]
    fn event_ack_canonical_bytes_deterministic() {
        let ack1 = EventAck::new("events.ack-det", vec![10, 20]);
        let ack2 = EventAck::new("events.ack-det", vec![10, 20]);
        let bytes1 = ack1.canonical_bytes().unwrap();
        let bytes2 = ack2.canonical_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn event_ack_type_field_is_ack() {
        let ack = EventAck::new("t", vec![]);
        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("\"type\":\"ack\""));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventNack additional tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_nack_schema_is_stable() {
        let schema1 = EventNack::schema();
        let schema2 = EventNack::schema();
        assert_eq!(schema1.hash(), schema2.hash());
    }

    #[test]
    fn event_nack_canonical_bytes_deterministic() {
        let nack1 = EventNack::new("events.nack-det", vec![5], "err").with_delay(100);
        let nack2 = EventNack::new("events.nack-det", vec![5], "err").with_delay(100);
        let bytes1 = nack1.canonical_bytes().unwrap();
        let bytes2 = nack2.canonical_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn event_nack_type_field_is_nack() {
        let nack = EventNack::new("t", vec![], "reason");
        let json = serde_json::to_string(&nack).unwrap();
        assert!(json.contains("\"type\":\"nack\""));
    }

    #[test]
    fn event_nack_delay_zero_is_valid() {
        let nack = EventNack::new("t", vec![1], "fast retry").with_delay(0);
        assert_eq!(nack.delay_ms, Some(0));
        let json = serde_json::to_string(&nack).unwrap();
        assert!(json.contains("\"delay_ms\":0"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // EventData additional tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_data_optional_fields_omitted_in_json() {
        let data = sample_event_data();
        let json = serde_json::to_string(&data).unwrap();
        // correlation_id and thread_info should be omitted when None
        assert!(!json.contains("correlation_id"));
        assert!(!json.contains("thread_info"));
    }

    #[test]
    fn event_data_all_fields_populated_roundtrip() {
        let corr_id = CorrelationId::new();
        let thread = ThreadInfo::new("tid-full", ThreadKind::ForumTopic).with_parent_id("parent");
        let data = sample_event_data()
            .with_correlation_id(corr_id.clone())
            .with_resource_uris(vec!["uri:a".into(), "uri:b".into()])
            .with_thread_info(thread.clone());

        let json = serde_json::to_string(&data).unwrap();
        let back: EventData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.correlation_id.unwrap(), corr_id);
        assert_eq!(back.resource_uris, vec!["uri:a", "uri:b"]);
        assert_eq!(back.thread_info, Some(thread));
    }

    #[test]
    fn event_data_complex_payload() {
        let data = EventData::new(
            sample_connector_id(),
            InstanceId::new(),
            ZoneId::work(),
            sample_principal(),
            json!({
                "nested": {"key": "value"},
                "array": [1, 2, 3],
                "null_val": null,
                "bool_val": true
            }),
        );
        let json = serde_json::to_string(&data).unwrap();
        let back: EventData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload["nested"]["key"], "value");
        assert_eq!(back.payload["array"][1], 2);
        assert!(back.payload["null_val"].is_null());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Schema hash distinctness
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_schemas_are_distinct() {
        let envelope_hash = EventEnvelope::schema().hash();
        let ack_hash = EventAck::schema().hash();
        let nack_hash = EventNack::schema().hash();
        assert_ne!(envelope_hash, ack_hash);
        assert_ne!(envelope_hash, nack_hash);
        assert_ne!(ack_hash, nack_hash);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: EventEnvelope
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_envelope_clone_preserves_all_fields() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.clone", data)
            .with_seq(55)
            .with_cursor("clone-cur")
            .with_stream_key("sk-1")
            .with_ordering(OrderingPolicy::Gateway)
            .requiring_ack();
        let cloned = envelope.clone();
        assert_eq!(cloned.topic, envelope.topic);
        assert_eq!(cloned.seq, envelope.seq);
        assert_eq!(cloned.cursor, envelope.cursor);
        assert_eq!(cloned.requires_ack, envelope.requires_ack);
        assert_eq!(cloned.stream_key, envelope.stream_key);
        assert_eq!(cloned.ordering, envelope.ordering);
    }

    #[test]
    fn event_envelope_debug_format() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.dbg", data);
        let dbg = format!("{envelope:?}");
        assert!(dbg.contains("events.dbg"));
        assert!(dbg.contains("EventEnvelope"));
    }

    #[test]
    fn event_envelope_with_cursor_seq_max() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.max", data).with_cursor_seq(u64::MAX);
        assert_eq!(envelope.cursor, u64::MAX.to_string());
    }

    #[test]
    fn event_envelope_with_seq_zero() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.z", data).with_seq(0);
        assert_eq!(envelope.seq, 0);
    }

    #[test]
    fn event_envelope_with_seq_max() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.max", data).with_seq(u64::MAX);
        assert_eq!(envelope.seq, u64::MAX);
    }

    #[test]
    fn event_envelope_empty_topic() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("", data);
        assert!(envelope.topic.is_empty());
    }

    #[test]
    fn event_envelope_unicode_topic() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.unicode.\u{1F600}", data);
        assert!(envelope.topic.contains('\u{1F600}'));
    }

    #[test]
    fn event_envelope_long_cursor() {
        let data = sample_event_data();
        let long_cursor = "x".repeat(10_000);
        let envelope = EventEnvelope::new("t", data).with_cursor(long_cursor);
        assert_eq!(envelope.cursor.len(), 10_000);
    }

    #[test]
    fn event_envelope_canonical_bytes_nonempty() {
        let data = sample_event_data();
        let envelope = EventEnvelope::new("events.bytes", data).with_seq(1);
        let bytes = envelope.canonical_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn event_envelope_canonical_bytes_differ_by_seq() {
        let data1 = sample_event_data();
        let data2 = sample_event_data();
        let e1 = EventEnvelope::new("t", data1).with_seq(1).with_cursor("c");
        let e2 = EventEnvelope::new("t", data2).with_seq(2).with_cursor("c");
        let b1 = e1.canonical_bytes().unwrap();
        let b2 = e2.canonical_bytes().unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn event_envelope_schema_version() {
        let schema = EventEnvelope::schema();
        // Version should be 1.1.0 per code
        let hash = schema.hash();
        assert!(!hash.as_bytes().is_empty());
    }

    #[test]
    fn event_envelope_all_ordering_policies_roundtrip() {
        for policy in [
            OrderingPolicy::Gateway,
            OrderingPolicy::PerKey,
            OrderingPolicy::Unordered,
        ] {
            let data = sample_event_data();
            let envelope = EventEnvelope::new("t", data).with_ordering(policy);
            let json = serde_json::to_string(&envelope).unwrap();
            let back: EventEnvelope = serde_json::from_str(&json).unwrap();
            assert_eq!(back.ordering, Some(policy));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: OrderingPolicy
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn ordering_policy_eq() {
        assert_eq!(OrderingPolicy::Gateway, OrderingPolicy::Gateway);
        assert_ne!(OrderingPolicy::Gateway, OrderingPolicy::PerKey);
        assert_ne!(OrderingPolicy::PerKey, OrderingPolicy::Unordered);
    }

    #[test]
    fn ordering_policy_debug_all_variants() {
        assert!(format!("{:?}", OrderingPolicy::PerKey).contains("PerKey"));
        assert!(format!("{:?}", OrderingPolicy::Unordered).contains("Unordered"));
    }

    #[test]
    fn ordering_policy_deserialize_unknown_fails() {
        let result = serde_json::from_str::<OrderingPolicy>("\"unknown_policy\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: EventData
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_data_clone_preserves_fields() {
        let data = sample_event_data()
            .with_resource_uris(vec!["uri:1".to_string()])
            .with_thread_info(ThreadInfo::new("t1", ThreadKind::Thread));
        let cloned = data.clone();
        assert_eq!(cloned.connector_id.as_str(), data.connector_id.as_str());
        assert_eq!(cloned.resource_uris, data.resource_uris);
        assert_eq!(cloned.thread_info, data.thread_info);
    }

    #[test]
    fn event_data_debug_format() {
        let data = sample_event_data();
        let dbg = format!("{data:?}");
        assert!(dbg.contains("EventData"));
    }

    #[test]
    fn event_data_null_payload() {
        let data = EventData::new(
            sample_connector_id(),
            InstanceId::new(),
            ZoneId::work(),
            sample_principal(),
            json!(null),
        );
        assert!(data.payload.is_null());
    }

    #[test]
    fn event_data_array_payload() {
        let data = EventData::new(
            sample_connector_id(),
            InstanceId::new(),
            ZoneId::work(),
            sample_principal(),
            json!([1, 2, 3]),
        );
        assert!(data.payload.is_array());
        assert_eq!(data.payload.as_array().unwrap().len(), 3);
    }

    #[test]
    fn event_data_empty_resource_uris_roundtrip() {
        let data = sample_event_data().with_resource_uris(vec![]);
        let json = serde_json::to_string(&data).unwrap();
        let back: EventData = serde_json::from_str(&json).unwrap();
        assert!(back.resource_uris.is_empty());
    }

    #[test]
    fn event_data_many_resource_uris() {
        let uris: Vec<String> = (0..100).map(|i| format!("fcp://res/{i}")).collect();
        let data = sample_event_data().with_resource_uris(uris);
        assert_eq!(data.resource_uris.len(), 100);
        let json = serde_json::to_string(&data).unwrap();
        let back: EventData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resource_uris.len(), 100);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: EventAck
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_ack_clone_preserves_all_fields() {
        let ack = EventAck::new("t.clone", vec![1, 2, 3])
            .with_cursors(vec!["c1".to_string(), "c2".to_string()]);
        let cloned = ack.clone();
        assert_eq!(cloned.r#type, ack.r#type);
        assert_eq!(cloned.topic, ack.topic);
        assert_eq!(cloned.seqs, ack.seqs);
        assert_eq!(cloned.cursors, ack.cursors);
    }

    #[test]
    fn event_ack_large_seqs() {
        let seqs: Vec<u64> = (0..1000).collect();
        let ack = EventAck::new("t.large", seqs);
        assert_eq!(ack.seqs.len(), 1000);
    }

    #[test]
    fn event_ack_debug_format() {
        let ack = EventAck::new("t", vec![1]);
        let dbg = format!("{ack:?}");
        assert!(dbg.contains("EventAck"));
    }

    #[test]
    fn event_ack_canonical_bytes_nonempty() {
        let ack = EventAck::new("t.cb", vec![1, 2]);
        let bytes = ack.canonical_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: EventNack
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_nack_clone_preserves_all_fields() {
        let nack = EventNack::new("t.clone", vec![7], "err").with_delay(500);
        let cloned = nack.clone();
        assert_eq!(cloned.r#type, nack.r#type);
        assert_eq!(cloned.topic, nack.topic);
        assert_eq!(cloned.seqs, nack.seqs);
        assert_eq!(cloned.reason, nack.reason);
        assert_eq!(cloned.delay_ms, nack.delay_ms);
    }

    #[test]
    fn event_nack_debug_format() {
        let nack = EventNack::new("t", vec![1], "r");
        let dbg = format!("{nack:?}");
        assert!(dbg.contains("EventNack"));
    }

    #[test]
    fn event_nack_empty_reason() {
        let nack = EventNack::new("t", vec![1], "");
        assert!(nack.reason.is_empty());
    }

    #[test]
    fn event_nack_empty_seqs() {
        let nack = EventNack::new("t", vec![], "r");
        assert!(nack.seqs.is_empty());
    }

    #[test]
    fn event_nack_max_delay() {
        let nack = EventNack::new("t", vec![1], "r").with_delay(u64::MAX);
        assert_eq!(nack.delay_ms, Some(u64::MAX));
    }

    #[test]
    fn event_nack_canonical_bytes_nonempty() {
        let nack = EventNack::new("t", vec![1], "r");
        let bytes = nack.canonical_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn event_nack_delay_omitted_in_json_when_none() {
        let nack = EventNack::new("t", vec![1], "r");
        let json = serde_json::to_string(&nack).unwrap();
        assert!(!json.contains("delay_ms"));
    }

    #[test]
    fn event_nack_delay_present_in_json_when_set() {
        let nack = EventNack::new("t", vec![1], "r").with_delay(250);
        let json = serde_json::to_string(&nack).unwrap();
        assert!(json.contains("\"delay_ms\":250"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: ThreadInfo
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn thread_info_clone() {
        let info = ThreadInfo::new("t1", ThreadKind::Thread).with_parent_id("p1");
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn thread_info_debug_format() {
        let info = ThreadInfo::new("tid", ThreadKind::ForumTopic);
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ThreadInfo"));
        assert!(dbg.contains("ForumTopic"));
    }

    #[test]
    fn thread_info_from_discord_thread_no_parent() {
        let info = ThreadInfo::from_discord_thread("thread-1", None);
        assert_eq!(info.thread_id, "thread-1");
        assert!(info.parent_id.is_none());
        assert_eq!(info.kind, ThreadKind::Channel);
    }

    #[test]
    fn thread_info_from_discord_channel_all_thread_types() {
        for channel_type in [10, 11, 12] {
            let result =
                ThreadInfo::from_discord_channel("ch", channel_type, Some("parent".into()));
            assert!(result.is_some(), "channel_type {channel_type} should be a thread");
        }
    }

    #[test]
    fn thread_info_from_discord_channel_non_thread_types() {
        for channel_type in [0, 1, 2, 5, 9, 13, 100] {
            let result = ThreadInfo::from_discord_channel("ch", channel_type, None);
            assert!(
                result.is_none(),
                "channel_type {channel_type} should not be a thread"
            );
        }
    }

    #[test]
    fn thread_info_from_telegram_negative_thread_id() {
        let info = ThreadInfo::from_telegram_message_thread(-1, "chat");
        assert_eq!(info.thread_id, "-1");
    }

    #[test]
    fn thread_info_parent_id_omitted_in_json_when_none() {
        let info = ThreadInfo::new("t1", ThreadKind::Thread);
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("parent_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Expanded coverage: ThreadKind
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn thread_kind_clone_and_eq() {
        let a = ThreadKind::Thread;
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn thread_kind_debug() {
        assert!(format!("{:?}", ThreadKind::Reply).contains("Reply"));
        assert!(format!("{:?}", ThreadKind::Channel).contains("Channel"));
    }

    #[test]
    fn thread_kind_deserialize_unknown_fails() {
        let result = serde_json::from_str::<ThreadKind>("\"unknown_kind\"");
        assert!(result.is_err());
    }

    #[test]
    fn thread_kind_inequality() {
        assert_ne!(ThreadKind::Thread, ThreadKind::ForumTopic);
        assert_ne!(ThreadKind::Channel, ThreadKind::Reply);
    }
}
