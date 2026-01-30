//! Webhook event types and processing.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
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
}
