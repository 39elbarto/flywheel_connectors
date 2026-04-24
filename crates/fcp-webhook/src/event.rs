//! Webhook event types and processing.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use fcp_core::{TaintFlag, TaintFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Webhook event.
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Unique event ID (for deduplication).
    pub id: String,

    /// Event type (e.g., "push", "issue.opened").
    pub event_type: String,

    /// Event timestamp.
    pub timestamp: DateTime<Utc>,

    /// Provider name.
    pub provider: String,

    /// Raw payload.
    pub payload: Value,

    /// Parsed headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Delivery metadata.
    #[serde(default)]
    pub metadata: EventMetadata,
}

impl fmt::Debug for WebhookEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_headers: HashMap<&str, &str> = self
            .headers
            .keys()
            .map(|key| (key.as_str(), "[REDACTED]"))
            .collect();

        f.debug_struct("WebhookEvent")
            .field("id", &self.id)
            .field("event_type", &self.event_type)
            .field("timestamp", &self.timestamp)
            .field("provider", &self.provider)
            .field("payload", &self.payload)
            .field("headers", &redacted_headers)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl WebhookEvent {
    /// Create a new webhook event.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        event_type: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            event_type: event_type.into(),
            timestamp: Utc::now(),
            provider: provider.into(),
            payload: Value::Null,
            headers: HashMap::new(),
            metadata: EventMetadata::default(),
        }
    }

    /// Set the payload.
    #[must_use]
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    /// Set headers.
    #[must_use]
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Add a taint flag to this event.
    #[must_use]
    pub fn with_taint_flag(mut self, flag: TaintFlag) -> Self {
        self.metadata.taint_flags.insert(flag);
        self
    }

    /// Apply default taint labels for externally injected webhook payloads.
    #[must_use]
    pub fn with_default_webhook_taint(self) -> Self {
        self.with_taint_flag(TaintFlag::WebhookInjected)
            .with_taint_flag(TaintFlag::PublicInput)
    }

    /// Get a header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        // Case-insensitive header lookup
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get a value from the payload.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Value> {
        let mut current = &self.payload;
        for part in path.split('.') {
            current = current.get(part)?;
        }
        Some(current)
    }

    /// Get a string value from the payload.
    #[must_use]
    pub fn get_str(&self, path: &str) -> Option<&str> {
        self.get(path)?.as_str()
    }

    /// Get an i64 value from the payload.
    #[must_use]
    pub fn get_i64(&self, path: &str) -> Option<i64> {
        self.get(path)?.as_i64()
    }

    /// Check if this event matches a type pattern.
    #[must_use]
    pub fn matches_type(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        pattern.strip_suffix('*').map_or_else(
            || self.event_type == pattern,
            |prefix| self.event_type.starts_with(prefix),
        )
    }
}

/// Event delivery metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Delivery attempt number.
    #[serde(default)]
    pub attempt: u32,

    /// First delivery attempt time.
    pub first_attempt_at: Option<DateTime<Utc>>,

    /// Last delivery attempt time.
    pub last_attempt_at: Option<DateTime<Utc>>,

    /// Next scheduled retry time.
    pub next_retry_at: Option<DateTime<Utc>>,

    /// Delivery status.
    #[serde(default)]
    pub status: DeliveryStatus,

    /// Error message from last attempt.
    pub last_error: Option<String>,

    /// Source IP address.
    pub source_ip: Option<String>,

    /// Accumulated taint flags for this event payload.
    #[serde(default)]
    pub taint_flags: TaintFlags,

    /// Custom metadata.
    #[serde(default)]
    pub custom: HashMap<String, Value>,
}

/// Event delivery status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Pending delivery.
    #[default]
    Pending,
    /// Successfully delivered.
    Delivered,
    /// Delivery failed.
    Failed,
    /// In dead letter queue.
    DeadLettered,
}

/// Event subscription for filtering.
#[derive(Debug, Clone)]
pub struct EventSubscription {
    /// Event type patterns to match.
    pub event_types: Vec<String>,

    /// Provider filter (None = all providers).
    pub provider: Option<String>,
}

impl EventSubscription {
    /// Create a new subscription for all events.
    #[must_use]
    pub fn all() -> Self {
        Self {
            event_types: vec!["*".to_string()],
            provider: None,
        }
    }

    /// Create a subscription for specific event types.
    #[must_use]
    pub const fn for_types(types: Vec<String>) -> Self {
        Self {
            event_types: types,
            provider: None,
        }
    }

    /// Filter by provider.
    #[must_use]
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Check if an event matches this subscription.
    #[must_use]
    pub fn matches(&self, event: &WebhookEvent) -> bool {
        // Check provider filter
        if let Some(ref provider) = self.provider {
            if &event.provider != provider {
                return false;
            }
        }

        // Check event type patterns
        for pattern in &self.event_types {
            if event.matches_type(pattern) {
                return true;
            }
        }

        false
    }
}

impl Default for EventSubscription {
    fn default() -> Self {
        Self::all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use fcp_core::TaintFlag;

    fn test_event() -> WebhookEvent {
        WebhookEvent::new("evt_123", "push", "github").with_payload(serde_json::json!({
            "ref": "refs/heads/main",
            "repository": {
                "name": "test-repo",
                "owner": {
                    "login": "user"
                }
            }
        }))
    }

    fn canonicalize_json(value: Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(canonicalize_json)
                    .collect::<Vec<_>>(),
            ),
            Value::Object(map) => {
                let mut entries = map.into_iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                let mut canonical = serde_json::Map::new();
                for (key, value) in entries {
                    canonical.insert(key, canonicalize_json(value));
                }
                Value::Object(canonical)
            }
            other => other,
        }
    }

    fn scrub_json_pointer(snapshot: &mut Value, pointer: &str, replacement: &str) {
        *snapshot.pointer_mut(pointer).expect("pointer exists") = Value::String(replacement.into());
    }

    #[test]
    fn test_event_get() {
        let event = test_event();

        assert_eq!(event.get_str("ref"), Some("refs/heads/main"));
        assert_eq!(event.get_str("repository.name"), Some("test-repo"));
        assert_eq!(event.get_str("repository.owner.login"), Some("user"));
        assert!(event.get("nonexistent").is_none());
    }

    #[test]
    fn test_event_matches_type() {
        let event = test_event();

        assert!(event.matches_type("push"));
        assert!(event.matches_type("*"));
        assert!(event.matches_type("pus*"));
        assert!(!event.matches_type("pull_request"));
    }

    #[test]
    fn test_subscription_matches() {
        let event = test_event();

        let sub = EventSubscription::all();
        assert!(sub.matches(&event));

        let sub = EventSubscription::for_types(vec!["push".to_string()]);
        assert!(sub.matches(&event));

        let sub = EventSubscription::for_types(vec!["pull_request".to_string()]);
        assert!(!sub.matches(&event));

        let sub = EventSubscription::all().with_provider("github");
        assert!(sub.matches(&event));

        let sub = EventSubscription::all().with_provider("gitlab");
        assert!(!sub.matches(&event));
    }

    // ── New tests ──

    #[test]
    fn test_event_new_defaults() {
        let event = WebhookEvent::new("e1", "push", "github");
        assert_eq!(event.id, "e1");
        assert_eq!(event.event_type, "push");
        assert_eq!(event.provider, "github");
        assert_eq!(event.payload, Value::Null);
        assert!(event.headers.is_empty());
        assert_eq!(event.metadata.attempt, 0);
    }

    #[test]
    fn test_event_header_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("X-GitHub-Event".to_string(), "push".to_string());

        let event = WebhookEvent::new("e1", "push", "github").with_headers(headers);

        assert_eq!(event.header("x-github-event"), Some("push"));
        assert_eq!(event.header("X-GITHUB-EVENT"), Some("push"));
        assert_eq!(event.header("X-GitHub-Event"), Some("push"));
        assert_eq!(event.header("nonexistent"), None);
    }

    #[test]
    fn test_event_get_i64() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"count": 42}));
        assert_eq!(event.get_i64("count"), Some(42));
        assert_eq!(event.get_i64("missing"), None);
    }

    #[test]
    fn test_event_get_str_missing() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"count": 42}));
        // count is numeric, not a string
        assert_eq!(event.get_str("count"), None);
        assert_eq!(event.get_str("missing"), None);
    }

    #[test]
    fn test_event_matches_type_exact_no_wildcard() {
        let event = WebhookEvent::new("e1", "push", "github");
        assert!(event.matches_type("push"));
        assert!(!event.matches_type("pusher"));
    }

    #[test]
    fn test_event_metadata_default() {
        let meta = EventMetadata::default();
        assert_eq!(meta.attempt, 0);
        assert!(meta.first_attempt_at.is_none());
        assert!(meta.last_attempt_at.is_none());
        assert!(meta.next_retry_at.is_none());
        assert_eq!(meta.status, DeliveryStatus::Pending);
        assert!(meta.last_error.is_none());
        assert!(meta.source_ip.is_none());
        assert!(meta.taint_flags.is_empty());
        assert!(meta.custom.is_empty());
    }

    #[test]
    fn test_event_default_webhook_taint() {
        let event = WebhookEvent::new("e1", "push", "github").with_default_webhook_taint();
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_delivery_status_serde() {
        let statuses = vec![
            (DeliveryStatus::Pending, "\"pending\""),
            (DeliveryStatus::Delivered, "\"delivered\""),
            (DeliveryStatus::Failed, "\"failed\""),
            (DeliveryStatus::DeadLettered, "\"dead_lettered\""),
        ];

        for (status, expected) in statuses {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, expected);
            let roundtrip: DeliveryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, status);
        }
    }

    #[test]
    fn test_subscription_default_is_all() {
        let sub = EventSubscription::default();
        let event = test_event();
        assert!(sub.matches(&event));
    }

    #[test]
    fn test_subscription_prefix_pattern() {
        let sub = EventSubscription::for_types(vec!["issue.*".to_string()]);
        let event = WebhookEvent::new("e1", "issue.opened", "github");
        assert!(sub.matches(&event));
    }

    #[test]
    fn test_event_serde_roundtrip() {
        let event = test_event();
        let json = serde_json::to_string(&event).unwrap();
        let roundtrip: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.id, event.id);
        assert_eq!(roundtrip.event_type, event.event_type);
        assert_eq!(roundtrip.provider, event.provider);
        assert_eq!(roundtrip.payload, event.payload);
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn test_event_with_single_taint_flag() {
        let event =
            WebhookEvent::new("e1", "push", "github").with_taint_flag(TaintFlag::WebhookInjected);
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(!event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_event_with_multiple_taint_flags_additive() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_taint_flag(TaintFlag::WebhookInjected)
            .with_taint_flag(TaintFlag::PublicInput)
            .with_taint_flag(TaintFlag::WebhookInjected); // duplicate
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_event_get_empty_path() {
        let event = test_event();
        // Empty path splits to [""], which tries to get key "" from root
        assert!(event.get("").is_none());
    }

    #[test]
    fn test_event_get_deeply_nested() {
        let event = WebhookEvent::new("e1", "push", "github").with_payload(serde_json::json!({
            "a": {"b": {"c": {"d": {"e": "deep"}}}}
        }));
        assert_eq!(event.get_str("a.b.c.d.e"), Some("deep"));
        assert!(event.get("a.b.c.d.e.f").is_none());
    }

    #[test]
    fn test_event_get_null_value() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"key": null}));
        let val = event.get("key");
        assert!(val.is_some());
        assert!(val.unwrap().is_null());
        assert_eq!(event.get_str("key"), None);
        assert_eq!(event.get_i64("key"), None);
    }

    #[test]
    fn test_event_get_array_value() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"items": [1, 2, 3]}));
        let val = event.get("items");
        assert!(val.is_some());
        assert!(val.unwrap().is_array());
        // Array index access via path doesn't work (uses string key, not numeric)
        assert!(event.get("items.0").is_none());
    }

    #[test]
    fn test_event_get_i64_float_truncation() {
        let event =
            WebhookEvent::new("e1", "push", "github").with_payload(serde_json::json!({"f": 3.5}));
        // serde_json as_i64 returns None for floats
        assert_eq!(event.get_i64("f"), None);
    }

    #[test]
    fn test_event_matches_type_empty_string() {
        let event = WebhookEvent::new("e1", "", "github");
        assert!(event.matches_type(""));
        assert!(event.matches_type("*"));
        assert!(!event.matches_type("push"));
    }

    #[test]
    fn test_event_matches_type_wildcard_only() {
        let event = WebhookEvent::new("e1", "issue.opened", "github");
        assert!(event.matches_type("*"));
        assert!(event.matches_type("issue.*"));
        assert!(event.matches_type("issue.opened"));
        assert!(!event.matches_type("issue.closed"));
        assert!(event.matches_type("issue.o*"));
        assert!(!event.matches_type("pull*"));
    }

    #[test]
    fn test_subscription_with_empty_event_types() {
        let sub = EventSubscription::for_types(vec![]);
        let event = test_event();
        // No patterns to match → false
        assert!(!sub.matches(&event));
    }

    #[test]
    fn test_subscription_multiple_patterns() {
        let sub = EventSubscription::for_types(vec![
            "push".to_string(),
            "pull_request".to_string(),
            "issue.*".to_string(),
        ]);
        assert!(sub.matches(&WebhookEvent::new("e1", "push", "github")));
        assert!(sub.matches(&WebhookEvent::new("e2", "pull_request", "github")));
        assert!(sub.matches(&WebhookEvent::new("e3", "issue.opened", "github")));
        assert!(!sub.matches(&WebhookEvent::new("e4", "release", "github")));
    }

    #[test]
    fn test_subscription_provider_filter_mismatch() {
        let sub = EventSubscription::for_types(vec!["push".to_string()]).with_provider("gitlab");
        let event = WebhookEvent::new("e1", "push", "github");
        assert!(!sub.matches(&event));
    }

    #[test]
    fn test_event_metadata_serde_roundtrip() {
        let meta = EventMetadata {
            attempt: 3,
            status: DeliveryStatus::Failed,
            last_error: Some("connection refused".to_string()),
            source_ip: Some("1.2.3.4".to_string()),
            custom: {
                let mut m = HashMap::new();
                m.insert("key".to_string(), serde_json::json!("val"));
                m
            },
            ..EventMetadata::default()
        };

        let json = serde_json::to_string(&meta).unwrap();
        let roundtrip: EventMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.attempt, 3);
        assert_eq!(roundtrip.status, DeliveryStatus::Failed);
        assert_eq!(roundtrip.last_error.as_deref(), Some("connection refused"));
        assert_eq!(roundtrip.source_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(roundtrip.custom.get("key").unwrap(), "val");
    }

    #[test]
    fn test_event_with_payload_overwrites() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"a": 1}))
            .with_payload(serde_json::json!({"b": 2}));
        assert!(event.get("a").is_none());
        assert_eq!(event.get_i64("b"), Some(2));
    }

    #[test]
    fn test_event_with_headers_overwrites() {
        let mut h1 = HashMap::new();
        h1.insert("key1".to_string(), "val1".to_string());
        let mut h2 = HashMap::new();
        h2.insert("key2".to_string(), "val2".to_string());

        let event = WebhookEvent::new("e1", "push", "github")
            .with_headers(h1)
            .with_headers(h2);
        assert!(event.header("key1").is_none());
        assert_eq!(event.header("key2"), Some("val2"));
    }

    #[test]
    fn test_event_debug_redacts_header_values() {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Bearer webhook-secret".to_string(),
        );
        headers.insert(
            "x-hub-signature-256".to_string(),
            "sha256=super-secret-signature".to_string(),
        );

        let event = WebhookEvent::new("e1", "push", "github").with_headers(headers);
        let debug = format!("{event:?}");

        assert!(debug.contains("authorization"));
        assert!(debug.contains("x-hub-signature-256"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("Bearer webhook-secret"));
        assert!(!debug.contains("super-secret-signature"));
    }

    #[test]
    fn test_delivery_status_default_is_pending() {
        assert_eq!(DeliveryStatus::default(), DeliveryStatus::Pending);
    }

    #[test]
    fn test_delivery_status_equality() {
        assert_eq!(DeliveryStatus::Delivered, DeliveryStatus::Delivered);
        assert_ne!(DeliveryStatus::Pending, DeliveryStatus::Failed);
    }

    #[test]
    fn test_event_serde_with_taint_flags() {
        let event = WebhookEvent::new("e1", "push", "github").with_default_webhook_taint();
        let json = serde_json::to_string(&event).unwrap();
        let roundtrip: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert!(
            roundtrip
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(
            roundtrip
                .metadata
                .taint_flags
                .contains(TaintFlag::PublicInput)
        );
    }

    #[test]
    fn test_subscription_wildcard_star_matches_all_types() {
        let sub = EventSubscription::for_types(vec!["*".to_string()]);
        assert!(sub.matches(&WebhookEvent::new("e1", "push", "github")));
        assert!(sub.matches(&WebhookEvent::new("e2", "anything", "stripe")));
        assert!(sub.matches(&WebhookEvent::new("e3", "", "slack")));
    }

    #[test]
    fn test_event_get_boolean() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"active": true, "count": 5}));
        // get_str returns None for non-string types
        assert_eq!(event.get_str("active"), None);
        // get_i64 returns None for booleans
        assert_eq!(event.get_i64("active"), None);
        // but get returns the Value
        assert_eq!(event.get("active").unwrap(), &serde_json::json!(true));
    }

    // ── Path traversal edge cases ────────────────────────────────────

    #[test]
    fn test_event_get_double_dot_path() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"a": {"": {"b": 42}}}));
        // "a..b" splits into ["a", "", "b"] — the empty segment tries to index with ""
        let result = event.get("a..b");
        assert_eq!(result.and_then(serde_json::Value::as_i64), Some(42));
    }

    #[test]
    fn test_event_get_null_intermediate() {
        let event =
            WebhookEvent::new("e1", "push", "github").with_payload(serde_json::json!({"a": null}));
        // Traversing through null returns None
        assert!(event.get("a.b").is_none());
    }

    // ── Header case-insensitivity ────────────────────────────────────

    #[test]
    fn test_header_case_insensitive_mixed() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("X-Custom-HEADER".into(), "custom-value".into());
        let event = WebhookEvent::new("e1", "push", "github").with_headers(headers);

        assert_eq!(event.header("content-type"), Some("application/json"));
        assert_eq!(event.header("CONTENT-TYPE"), Some("application/json"));
        assert_eq!(event.header("x-custom-header"), Some("custom-value"));
        assert_eq!(event.header("X-CUSTOM-HEADER"), Some("custom-value"));
        assert!(event.header("nonexistent").is_none());
    }

    // ── get_i64 edge cases ───────────────────────────────────────────

    #[test]
    fn test_event_get_i64_large_values() {
        let event = WebhookEvent::new("e1", "push", "github").with_payload(serde_json::json!({
            "max": i64::MAX,
            "min": i64::MIN,
            "zero": 0
        }));
        assert_eq!(event.get_i64("max"), Some(i64::MAX));
        assert_eq!(event.get_i64("min"), Some(i64::MIN));
        assert_eq!(event.get_i64("zero"), Some(0));
    }

    // ── matches_type edge cases ──────────────────────────────────────

    #[test]
    fn test_matches_type_prefix_wildcard() {
        let event = WebhookEvent::new("e1", "issue.opened", "github");
        assert!(event.matches_type("issue.*"));
        assert!(event.matches_type("issue.opened"));
        assert!(!event.matches_type("pull_request.*"));
    }

    #[test]
    fn test_matches_type_empty_prefix_wildcard() {
        let event = WebhookEvent::new("e1", "push", "github");
        // "*" at end with empty prefix matches everything
        assert!(event.matches_type("*"));
    }

    #[test]
    fn test_matches_type_no_wildcard_exact() {
        let event = WebhookEvent::new("e1", "push", "github");
        assert!(event.matches_type("push"));
        assert!(!event.matches_type("push."));
        assert!(!event.matches_type("pus"));
    }

    // ── Serde roundtrip edge cases ───────────────────────────────────

    #[test]
    fn test_event_serde_null_payload() {
        let event = WebhookEvent::new("e1", "test", "provider");
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.payload, serde_json::Value::Null);
    }

    #[test]
    fn test_event_serde_complex_payload() {
        let payload = serde_json::json!({
            "array": [1, "two", null, {"nested": true}],
            "object": {"deep": {"deeper": []}},
            "null_val": null
        });
        let event = WebhookEvent::new("e1", "test", "provider").with_payload(payload.clone());
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.payload, payload);
    }

    #[test]
    fn webhook_event_payload_shape_snapshot() {
        let fixed_at = Utc.with_ymd_and_hms(2026, 4, 20, 1, 14, 0).unwrap();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("X-GitHub-Delivery".into(), "[delivery-id]".into());
        headers.insert("X-Hub-Signature-256".into(), "[signature]".into());

        let mut custom = HashMap::new();
        custom.insert("region".into(), serde_json::json!("us-east-1"));
        custom.insert("request_id".into(), serde_json::json!("[request-id]"));

        let mut taint_flags = TaintFlags::default();
        taint_flags.insert(TaintFlag::WebhookInjected);
        taint_flags.insert(TaintFlag::PublicInput);

        let mut event = WebhookEvent::new("[event-id]", "issue_comment.created", "github")
            .with_payload(serde_json::json!({
                "action": "created",
                "comment": {
                    "body": "Snapshot drift detected",
                    "id": "[comment-id]",
                },
                "issue": {
                    "number": 42,
                    "title": "Golden review follow-up",
                },
                "repository": {
                    "full_name": "flywheel-ai/flywheel_connectors",
                    "private": true,
                },
                "sender": {
                    "id": "[sender-id]",
                    "login": "cod-p9",
                }
            }))
            .with_headers(headers);
        event.timestamp = fixed_at;
        event.metadata = EventMetadata {
            attempt: 2,
            first_attempt_at: Some(fixed_at),
            last_attempt_at: Some(fixed_at + Duration::seconds(5)),
            next_retry_at: Some(fixed_at + Duration::seconds(30)),
            status: DeliveryStatus::Failed,
            last_error: Some("upstream timeout".into()),
            source_ip: Some("[source-ip]".into()),
            taint_flags,
            custom,
        };

        let mut snapshot = serde_json::to_value(&event).expect("serialize event");
        for pointer in [
            "/timestamp",
            "/metadata/first_attempt_at",
            "/metadata/last_attempt_at",
            "/metadata/next_retry_at",
        ] {
            scrub_json_pointer(&mut snapshot, pointer, "[timestamp]");
        }

        insta::assert_json_snapshot!(
            "webhook_event_payload_shape_snapshot",
            canonicalize_json(snapshot)
        );
    }

    // ── DeliveryStatus serde ─────────────────────────────────────────

    #[test]
    fn test_delivery_status_all_variants_serde() {
        for status in [
            DeliveryStatus::Pending,
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::DeadLettered,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: DeliveryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_delivery_status_default() {
        assert_eq!(DeliveryStatus::default(), DeliveryStatus::Pending);
    }

    // ── with_taint_flag accumulation ─────────────────────────────────

    #[test]
    fn test_taint_flags_accumulate() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_taint_flag(TaintFlag::WebhookInjected)
            .with_taint_flag(TaintFlag::PublicInput);
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_taint_flag_idempotent() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_taint_flag(TaintFlag::WebhookInjected)
            .with_taint_flag(TaintFlag::WebhookInjected);
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
    }

    // ── EventSubscription edge cases ─────────────────────────────────

    #[test]
    fn test_subscription_empty_types() {
        let sub = EventSubscription {
            event_types: vec![],
            provider: None,
        };
        // Empty event_types matches nothing
        assert!(!sub.matches(&WebhookEvent::new("e1", "push", "github")));
    }

    #[test]
    fn test_subscription_provider_filter() {
        let sub = EventSubscription {
            event_types: vec!["*".into()],
            provider: Some("github".into()),
        };
        assert!(sub.matches(&WebhookEvent::new("e1", "push", "github")));
        assert!(!sub.matches(&WebhookEvent::new("e1", "push", "stripe")));
    }

    #[test]
    fn test_subscription_no_provider_filter() {
        let sub = EventSubscription {
            event_types: vec!["push".into()],
            provider: None,
        };
        // No provider filter → matches any provider
        assert!(sub.matches(&WebhookEvent::new("e1", "push", "github")));
        assert!(sub.matches(&WebhookEvent::new("e1", "push", "stripe")));
    }

    // ── Batch 3: SunnyMoose deep test expansion ──

    #[test]
    fn test_event_clone() {
        let original = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"key": "value"}))
            .with_default_webhook_taint();
        let cloned = original.clone();
        assert_eq!(original.id, cloned.id);
        assert_eq!(original.event_type, cloned.event_type);
        assert_eq!(original.provider, cloned.provider);
        assert_eq!(original.payload, cloned.payload);
    }

    #[test]
    fn test_event_debug() {
        let event = WebhookEvent::new("evt_dbg", "push", "github");
        let debug = format!("{event:?}");
        assert!(debug.contains("WebhookEvent"));
        assert!(debug.contains("evt_dbg"));
        assert!(debug.contains("push"));
        assert!(debug.contains("github"));
    }

    #[test]
    fn test_event_metadata_debug() {
        let meta = EventMetadata::default();
        let debug = format!("{meta:?}");
        assert!(debug.contains("EventMetadata"));
    }

    #[test]
    fn test_event_metadata_clone() {
        let original = EventMetadata {
            attempt: 5,
            status: DeliveryStatus::Failed,
            last_error: Some("timeout".into()),
            source_ip: Some("10.0.0.1".into()),
            ..EventMetadata::default()
        };
        let cloned = original.clone();
        assert_eq!(original.attempt, cloned.attempt);
        assert_eq!(original.status, cloned.status);
        assert_eq!(original.last_error, cloned.last_error);
        assert_eq!(original.source_ip, cloned.source_ip);
    }

    #[test]
    fn test_delivery_status_debug() {
        let debug = format!("{:?}", DeliveryStatus::Pending);
        assert!(debug.contains("Pending"));
        let debug = format!("{:?}", DeliveryStatus::DeadLettered);
        assert!(debug.contains("DeadLettered"));
    }

    #[test]
    fn test_delivery_status_copy() {
        let status = DeliveryStatus::Delivered;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn test_event_subscription_debug() {
        let sub = EventSubscription::for_types(vec!["push".into()]).with_provider("github");
        let debug = format!("{sub:?}");
        assert!(debug.contains("EventSubscription"));
        assert!(debug.contains("push"));
        assert!(debug.contains("github"));
    }

    #[test]
    fn test_event_subscription_clone() {
        let original = EventSubscription::for_types(vec!["push".into()]).with_provider("github");
        let cloned = original.clone();
        assert_eq!(original.event_types, cloned.event_types);
        assert_eq!(original.provider, cloned.provider);
    }

    #[test]
    fn test_event_unicode_fields() {
        let event = WebhookEvent::new("evt_\u{00E9}", "push_\u{00F1}", "provider_\u{00FC}");
        assert_eq!(event.id, "evt_\u{00E9}");
        assert_eq!(event.event_type, "push_\u{00F1}");
        assert_eq!(event.provider, "provider_\u{00FC}");
    }

    #[test]
    fn test_event_empty_strings() {
        let event = WebhookEvent::new("", "", "");
        assert_eq!(event.id, "");
        assert_eq!(event.event_type, "");
        assert_eq!(event.provider, "");
    }

    #[test]
    fn test_event_with_payload_null_explicitly() {
        let event = WebhookEvent::new("e1", "push", "github").with_payload(serde_json::Value::Null);
        assert!(event.payload.is_null());
    }

    #[test]
    fn test_event_serde_with_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("X-Custom".into(), "value".into());
        let event = WebhookEvent::new("e1", "push", "github").with_headers(headers);
        let json = serde_json::to_string(&event).unwrap();
        let roundtrip: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.headers.len(), 2);
        assert_eq!(roundtrip.header("content-type"), Some("application/json"));
    }

    #[test]
    fn test_event_serde_with_metadata_custom() {
        let mut custom = HashMap::new();
        custom.insert("retry_count".into(), serde_json::json!(3));
        custom.insert("origin".into(), serde_json::json!("us-east-1"));
        let event = WebhookEvent {
            metadata: EventMetadata {
                custom,
                ..EventMetadata::default()
            },
            ..WebhookEvent::new("e1", "push", "github")
        };
        let json = serde_json::to_string(&event).unwrap();
        let roundtrip: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(
            roundtrip.metadata.custom.get("retry_count"),
            Some(&serde_json::json!(3))
        );
        assert_eq!(
            roundtrip.metadata.custom.get("origin"),
            Some(&serde_json::json!("us-east-1"))
        );
    }

    #[test]
    fn test_event_matches_type_star_at_start() {
        // "*foo" is not a valid glob-like pattern in this impl — it's treated as exact match
        let event = WebhookEvent::new("e1", "*foo", "github");
        assert!(event.matches_type("*foo"));
        assert!(event.matches_type("*")); // global wildcard always matches
    }

    #[test]
    fn test_event_get_with_numeric_string_key() {
        let event = WebhookEvent::new("e1", "push", "github")
            .with_payload(serde_json::json!({"0": "zero", "1": "one"}));
        assert_eq!(event.get_str("0"), Some("zero"));
        assert_eq!(event.get_str("1"), Some("one"));
    }

    #[test]
    fn test_subscription_matches_first_of_many_types() {
        let sub = EventSubscription::for_types(vec!["push".into(), "release".into()]);
        let event = WebhookEvent::new("e1", "push", "github");
        assert!(sub.matches(&event));
    }

    #[test]
    fn test_subscription_matches_last_of_many_types() {
        let sub =
            EventSubscription::for_types(vec!["issue".into(), "release".into(), "push".into()]);
        let event = WebhookEvent::new("e1", "push", "github");
        assert!(sub.matches(&event));
    }

    #[test]
    fn test_event_header_empty_value() {
        let mut headers = HashMap::new();
        headers.insert("X-Empty".into(), String::new());
        let event = WebhookEvent::new("e1", "push", "github").with_headers(headers);
        assert_eq!(event.header("x-empty"), Some(""));
    }

    #[test]
    fn test_event_metadata_all_fields_set() {
        let now = Utc::now();
        let meta = EventMetadata {
            attempt: 10,
            first_attempt_at: Some(now),
            last_attempt_at: Some(now),
            next_retry_at: Some(now),
            status: DeliveryStatus::Delivered,
            last_error: None,
            source_ip: Some("192.168.1.1".into()),
            taint_flags: TaintFlags::default(),
            custom: HashMap::new(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let rt: EventMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.attempt, 10);
        assert_eq!(rt.status, DeliveryStatus::Delivered);
        assert!(rt.first_attempt_at.is_some());
        assert!(rt.last_attempt_at.is_some());
        assert!(rt.next_retry_at.is_some());
    }

    // ── Batch 4: SunnyMoose additional test expansion ──

    #[test]
    fn test_event_get_root_primitive() {
        let event =
            WebhookEvent::new("e1", "test", "p").with_payload(serde_json::json!("a plain string"));
        // Root is a string, so get("") tries key "" which won't work on a string
        assert!(event.get("anything").is_none());
        // But the raw payload is accessible
        assert_eq!(event.payload.as_str(), Some("a plain string"));
    }

    #[test]
    fn test_event_get_with_dots_in_key_name() {
        // If a key literally contains a dot, the path traversal will split on it
        let event =
            WebhookEvent::new("e1", "test", "p").with_payload(serde_json::json!({"a.b": "value"}));
        // "a.b" splits to ["a", "b"] so this won't find the literal key "a.b"
        assert!(event.get("a.b").is_none());
    }

    #[test]
    fn test_event_matches_type_partial_wildcard() {
        let event = WebhookEvent::new("e1", "issue.opened.draft", "gh");
        assert!(event.matches_type("issue.*"));
        assert!(event.matches_type("issue.opened.*"));
        assert!(!event.matches_type("issue.closed.*"));
    }

    #[test]
    fn test_event_matches_type_single_star_literal() {
        // Pattern "*" (just the star) always matches
        let event = WebhookEvent::new("e1", "anything", "p");
        assert!(event.matches_type("*"));
    }

    #[test]
    fn test_event_matches_type_trailing_dot_pattern() {
        let event = WebhookEvent::new("e1", "push", "gh");
        // "push." does not match "push" (exact match fails, no wildcard)
        assert!(!event.matches_type("push."));
    }

    #[test]
    fn test_event_serde_empty_headers_and_metadata() {
        let json_str = r#"{"id":"e1","event_type":"test","timestamp":"2026-01-01T00:00:00Z","provider":"p","payload":null}"#;
        let event: WebhookEvent = serde_json::from_str(json_str).unwrap();
        assert_eq!(event.id, "e1");
        assert!(event.headers.is_empty());
        assert_eq!(event.metadata.attempt, 0);
        assert_eq!(event.metadata.status, DeliveryStatus::Pending);
    }

    #[test]
    fn test_event_serde_preserves_timestamp() {
        let event = WebhookEvent::new("e1", "push", "gh");
        let ts = event.timestamp;
        let json = serde_json::to_string(&event).unwrap();
        let rt: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.timestamp, ts);
    }

    #[test]
    fn test_delivery_status_serde_unknown_variant_fails() {
        let result: Result<DeliveryStatus, _> = serde_json::from_str(r#""unknown_status""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_event_subscription_for_types_preserves_order() {
        let types = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        let sub = EventSubscription::for_types(types.clone());
        assert_eq!(sub.event_types, types);
    }

    #[test]
    fn test_event_subscription_with_provider_replaces() {
        let sub = EventSubscription::all()
            .with_provider("github")
            .with_provider("stripe");
        assert_eq!(sub.provider, Some("stripe".to_string()));
    }

    #[test]
    fn test_event_get_i64_string_value() {
        let event =
            WebhookEvent::new("e1", "test", "p").with_payload(serde_json::json!({"num_str": "42"}));
        // String "42" is not an i64
        assert_eq!(event.get_i64("num_str"), None);
    }

    #[test]
    fn test_event_get_str_number_value() {
        let event =
            WebhookEvent::new("e1", "test", "p").with_payload(serde_json::json!({"count": 42}));
        // Number 42 is not a string
        assert_eq!(event.get_str("count"), None);
    }

    #[test]
    fn test_event_header_returns_first_case_match() {
        // If headers have multiple entries differing only in case, find returns the first one
        let mut headers = HashMap::new();
        headers.insert("x-key".to_string(), "lower".to_string());
        // HashMap doesn't preserve insertion order, but we can test that lookup works
        let event = WebhookEvent::new("e1", "test", "p").with_headers(headers);
        assert_eq!(event.header("X-KEY"), Some("lower"));
    }

    #[test]
    fn test_event_metadata_custom_nested_json() {
        let mut custom = HashMap::new();
        custom.insert("nested".into(), serde_json::json!({"a": {"b": [1, 2, 3]}}));
        let meta = EventMetadata {
            custom,
            ..EventMetadata::default()
        };
        let json = serde_json::to_string(&meta).unwrap();
        let rt: EventMetadata = serde_json::from_str(&json).unwrap();
        let nested = rt.custom.get("nested").unwrap();
        assert!(nested.get("a").unwrap().get("b").unwrap().is_array());
    }

    #[test]
    fn test_event_subscription_matches_wildcard_prefix_empty_provider() {
        let sub = EventSubscription::for_types(vec!["*".to_string()]);
        // With no provider filter, should match any provider
        assert!(sub.matches(&WebhookEvent::new("e1", "any", "")));
        assert!(sub.matches(&WebhookEvent::new("e2", "any", "github")));
    }

    #[test]
    fn test_event_with_taint_then_default_taint() {
        let event = WebhookEvent::new("e1", "push", "gh")
            .with_taint_flag(TaintFlag::WebhookInjected)
            .with_default_webhook_taint();
        // Should have both flags (additive)
        assert!(
            event
                .metadata
                .taint_flags
                .contains(TaintFlag::WebhookInjected)
        );
        assert!(event.metadata.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_event_get_i64_negative() {
        let event =
            WebhookEvent::new("e1", "test", "p").with_payload(serde_json::json!({"val": -999}));
        assert_eq!(event.get_i64("val"), Some(-999));
    }

    #[test]
    fn test_event_get_i64_zero() {
        let event =
            WebhookEvent::new("e1", "test", "p").with_payload(serde_json::json!({"val": 0}));
        assert_eq!(event.get_i64("val"), Some(0));
    }

    #[test]
    fn test_event_payload_object_in_array() {
        let event = WebhookEvent::new("e1", "test", "p")
            .with_payload(serde_json::json!({"items": [{"id": 1}, {"id": 2}]}));
        let items = event.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].get("id").unwrap().as_i64(), Some(1));
    }

    #[test]
    fn test_event_metadata_serde_with_taint_flags() {
        let mut meta = EventMetadata::default();
        meta.taint_flags.insert(TaintFlag::WebhookInjected);
        meta.taint_flags.insert(TaintFlag::PublicInput);
        let json = serde_json::to_string(&meta).unwrap();
        let rt: EventMetadata = serde_json::from_str(&json).unwrap();
        assert!(rt.taint_flags.contains(TaintFlag::WebhookInjected));
        assert!(rt.taint_flags.contains(TaintFlag::PublicInput));
    }

    #[test]
    fn test_event_subscription_empty_provider_string() {
        let sub = EventSubscription::all().with_provider("");
        let event = WebhookEvent::new("e1", "push", "");
        assert!(sub.matches(&event));
        // Non-empty provider should not match
        let event2 = WebhookEvent::new("e2", "push", "github");
        assert!(!sub.matches(&event2));
    }

    #[test]
    fn test_delivery_status_clone() {
        let status = DeliveryStatus::Failed;
        let cloned = status;
        assert_eq!(status, cloned);
    }

    // ── Batch 5: SunnyMoose test expansion ──

    #[test]
    fn test_event_matches_type_literal_star_in_event_type() {
        let event = WebhookEvent::new("e1", "push*", "gh");
        // "push*" should match itself exactly
        assert!(event.matches_type("push*"));
        // But "push*" as pattern means prefix "push" which also matches "push*"
        assert!(event.matches_type("push*"));
        // "push" alone doesn't match "push*"
        assert!(!event.matches_type("push"));
    }

    #[test]
    fn test_event_serde_deserialize_missing_optional_metadata_fields() {
        let json_str = r#"{
            "id": "e1",
            "event_type": "test",
            "timestamp": "2026-01-15T10:30:00Z",
            "provider": "p",
            "payload": {"key": "value"}
        }"#;
        let event: WebhookEvent = serde_json::from_str(json_str).unwrap();
        assert_eq!(event.id, "e1");
        assert_eq!(event.event_type, "test");
        assert_eq!(event.provider, "p");
        assert!(event.headers.is_empty());
        assert_eq!(event.metadata.attempt, 0);
        assert!(event.metadata.last_error.is_none());
        assert!(event.metadata.source_ip.is_none());
    }

    #[test]
    fn test_event_serde_full_metadata_roundtrip() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 8, 12, 0, 0).unwrap();
        let mut custom = HashMap::new();
        custom.insert("region".into(), serde_json::json!("us-east-1"));
        custom.insert("weight".into(), serde_json::json!(1.23));
        let meta = EventMetadata {
            attempt: 7,
            first_attempt_at: Some(ts),
            last_attempt_at: Some(ts),
            next_retry_at: Some(ts),
            status: DeliveryStatus::DeadLettered,
            last_error: Some("connection reset".into()),
            source_ip: Some("10.0.0.1".into()),
            taint_flags: TaintFlags::default(),
            custom,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let rt: EventMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.attempt, 7);
        assert_eq!(rt.status, DeliveryStatus::DeadLettered);
        assert_eq!(rt.last_error.as_deref(), Some("connection reset"));
        assert_eq!(rt.source_ip.as_deref(), Some("10.0.0.1"));
        assert!(rt.first_attempt_at.is_some());
        assert!(rt.last_attempt_at.is_some());
        assert!(rt.next_retry_at.is_some());
        assert_eq!(
            rt.custom.get("region"),
            Some(&serde_json::json!("us-east-1"))
        );
    }

    #[test]
    fn test_event_get_str_on_nested_object_returns_none() {
        let event = WebhookEvent::new("e1", "push", "gh")
            .with_payload(serde_json::json!({"nested": {"key": "val"}}));
        // "nested" is an object, not a string
        assert_eq!(event.get_str("nested"), None);
    }

    #[test]
    fn test_event_get_i64_on_nested_object_returns_none() {
        let event = WebhookEvent::new("e1", "push", "gh")
            .with_payload(serde_json::json!({"nested": {"key": 42}}));
        assert_eq!(event.get_i64("nested"), None);
    }

    #[test]
    fn test_event_header_with_unicode_value() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom".into(), "\u{1F600} emoji header".into());
        let event = WebhookEvent::new("e1", "push", "gh").with_headers(headers);
        assert_eq!(event.header("x-custom"), Some("\u{1F600} emoji header"));
    }

    #[test]
    fn test_subscription_for_types_single_type() {
        let sub = EventSubscription::for_types(vec!["push".into()]);
        assert_eq!(sub.event_types.len(), 1);
        assert!(sub.provider.is_none());
    }

    #[test]
    fn test_subscription_matches_empty_event_type_with_wildcard() {
        let sub = EventSubscription::for_types(vec!["*".into()]);
        let event = WebhookEvent::new("e1", "", "gh");
        assert!(sub.matches(&event));
    }

    #[test]
    fn test_subscription_matches_unicode_event_type() {
        let sub = EventSubscription::for_types(vec!["\u{00E9}vent.*".into()]);
        let event = WebhookEvent::new("e1", "\u{00E9}vent.created", "gh");
        assert!(sub.matches(&event));
    }

    #[test]
    fn test_event_metadata_attempt_boundary() {
        let meta = EventMetadata {
            attempt: u32::MAX,
            ..EventMetadata::default()
        };
        assert_eq!(meta.attempt, u32::MAX);
        let json = serde_json::to_string(&meta).unwrap();
        let rt: EventMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.attempt, u32::MAX);
    }

    #[test]
    fn test_delivery_status_serde_pending_is_default() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            #[serde(default)]
            status: DeliveryStatus,
        }
        let json_str = "{}";
        let w: Wrapper = serde_json::from_str(json_str).unwrap();
        assert_eq!(w.status, DeliveryStatus::Pending);
    }

    #[test]
    fn test_event_with_headers_empty_map() {
        let event = WebhookEvent::new("e1", "push", "gh").with_headers(HashMap::new());
        assert!(event.headers.is_empty());
        assert!(event.header("anything").is_none());
    }

    #[test]
    fn test_event_get_on_array_root() {
        let event =
            WebhookEvent::new("e1", "push", "gh").with_payload(serde_json::json!([1, 2, 3]));
        // Path-based get on an array root won't find string keys
        assert!(event.get("0").is_none());
        assert!(event.payload.is_array());
    }

    #[test]
    fn test_subscription_all_no_provider() {
        let sub = EventSubscription::all();
        assert!(sub.provider.is_none());
        assert_eq!(sub.event_types, vec!["*"]);
    }

    #[test]
    fn test_event_clone_independence() {
        let original =
            WebhookEvent::new("e1", "push", "gh").with_payload(serde_json::json!({"key": "val"}));
        let mut cloned = original.clone();
        cloned.id = "e2".into();
        cloned.event_type = "release".into();
        // Original should be unchanged
        assert_eq!(original.id, "e1");
        assert_eq!(original.event_type, "push");
    }

    #[test]
    fn test_event_metadata_clone_independence() {
        let original = EventMetadata {
            attempt: 3,
            last_error: Some("err".into()),
            ..EventMetadata::default()
        };
        let mut cloned = original.clone();
        cloned.attempt = 99;
        cloned.last_error = Some("different".into());
        assert_eq!(original.attempt, 3);
        assert_eq!(original.last_error.as_deref(), Some("err"));
    }
}
