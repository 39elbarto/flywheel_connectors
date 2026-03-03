//! Webhook event types and processing.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use fcp_core::{TaintFlag, TaintFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Webhook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
