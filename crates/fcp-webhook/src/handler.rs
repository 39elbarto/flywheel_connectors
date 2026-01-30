//! Generic webhook handler.
//!
//! Provides a unified interface for handling webhooks from any provider.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

use crate::{
    DEFAULT_MAX_PAYLOAD_SIZE, DeliveryStatus, EventSubscription, SignatureVerifier, WebhookError,
    WebhookEvent, WebhookResult,
};

/// Webhook handler configuration.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Maximum payload size.
    pub max_payload_size: usize,

    /// Enable idempotency checking.
    pub idempotency_enabled: bool,

    /// How long to remember event IDs for idempotency.
    pub idempotency_ttl: Duration,

    /// IP allowlist (empty = allow all).
    pub ip_allowlist: Vec<String>,

    /// Maximum retry attempts.
    pub max_retries: u32,

    /// Retry delay.
    pub retry_delay: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
            idempotency_enabled: true,
            idempotency_ttl: Duration::from_secs(86400), // 24 hours
            ip_allowlist: Vec::new(),
            max_retries: 3,
            retry_delay: Duration::from_secs(60),
        }
    }
}

impl WebhookConfig {
    /// Create a new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum payload size.
    #[must_use]
    pub const fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Enable or disable idempotency.
    #[must_use]
    pub const fn with_idempotency(mut self, enabled: bool) -> Self {
        self.idempotency_enabled = enabled;
        self
    }

    /// Set idempotency TTL.
    #[must_use]
    pub const fn with_idempotency_ttl(mut self, ttl: Duration) -> Self {
        self.idempotency_ttl = ttl;
        self
    }

    /// Set IP allowlist.
    #[must_use]
    pub fn with_ip_allowlist(mut self, ips: Vec<String>) -> Self {
        self.ip_allowlist = ips;
        self
    }

    /// Set maximum retries.
    #[must_use]
    pub const fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }
}

/// Generic webhook handler.
pub struct WebhookHandler<V: SignatureVerifier> {
    verifier: V,
    provider: String,
    config: WebhookConfig,
    seen_events: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

impl<V: SignatureVerifier> WebhookHandler<V> {
    /// Create a new webhook handler.
    #[must_use]
    pub fn new(verifier: V, provider: impl Into<String>) -> Self {
        Self {
            verifier,
            provider: provider.into(),
            config: WebhookConfig::default(),
            seen_events: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with configuration.
    #[must_use]
    pub fn with_config(verifier: V, provider: impl Into<String>, config: WebhookConfig) -> Self {
        Self {
            verifier,
            provider: provider.into(),
            config,
            seen_events: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Verify a webhook signature.
    pub fn verify(&self, body: &[u8], signature: &str) -> WebhookResult<()> {
        // Check payload size
        if body.len() > self.config.max_payload_size {
            return Err(WebhookError::PayloadTooLarge {
                size: body.len(),
                limit: self.config.max_payload_size,
            });
        }

        self.verifier.verify(body, signature)
    }

    /// Check IP against allowlist.
    pub fn check_ip(&self, ip: &str) -> WebhookResult<()> {
        if self.config.ip_allowlist.is_empty() {
            return Ok(());
        }

        if self.config.ip_allowlist.contains(&ip.to_string()) {
            Ok(())
        } else {
            Err(WebhookError::IpNotAllowed(ip.to_string()))
        }
    }

    /// Check for replay (duplicate event).
    pub fn check_replay(&self, event_id: &str) -> WebhookResult<()> {
        if !self.config.idempotency_enabled {
            return Ok(());
        }

        // Clean up old entries
        self.cleanup_seen_events();

        let is_replay = self.seen_events.read().contains_key(event_id);
        if is_replay {
            return Err(WebhookError::ReplayDetected {
                event_id: event_id.to_string(),
            });
        }

        Ok(())
    }

    /// Record an event as seen.
    pub fn record_event(&self, event_id: &str) {
        if self.config.idempotency_enabled {
            let mut seen = self.seen_events.write();
            seen.insert(event_id.to_string(), Utc::now());
        }
    }

    /// Check for replay and record the event in one atomic operation.
    /// Returns `Err(ReplayDetected)` if already seen.
    pub fn claim_event(&self, event_id: &str) -> WebhookResult<()> {
        if !self.config.idempotency_enabled {
            return Ok(());
        }

        // Clean up old entries
        self.cleanup_seen_events();

        {
            let mut seen = self.seen_events.write();
            if seen.contains_key(event_id) {
                return Err(WebhookError::ReplayDetected {
                    event_id: event_id.to_string(),
                });
            }

            seen.insert(event_id.to_string(), Utc::now());
        }
        Ok(())
    }

    /// Clean up old seen events.
    fn cleanup_seen_events(&self) {
        let now = Utc::now();
        // Use saturating conversion to avoid panic on extreme durations
        let ttl = chrono::Duration::from_std(self.config.idempotency_ttl)
            .unwrap_or(chrono::TimeDelta::MAX);
        let mut seen = self.seen_events.write();
        seen.retain(|_, time| now - *time < ttl);
    }

    /// Get the provider name.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &WebhookConfig {
        &self.config
    }
}

impl<V: SignatureVerifier + std::fmt::Debug> std::fmt::Debug for WebhookHandler<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookHandler")
            .field("verifier", &self.verifier)
            .field("provider", &self.provider)
            .field("config", &self.config)
            .finish()
    }
}

/// Event router for dispatching webhooks.
#[derive(Debug, Default)]
pub struct EventRouter {
    subscriptions: Vec<(EventSubscription, String)>,
}

impl EventRouter {
    /// Create a new event router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a subscription.
    pub fn subscribe(&mut self, subscription: EventSubscription, handler_id: impl Into<String>) {
        self.subscriptions.push((subscription, handler_id.into()));
    }

    /// Get handlers that should receive an event.
    #[must_use]
    pub fn route(&self, event: &WebhookEvent) -> Vec<&str> {
        self.subscriptions
            .iter()
            .filter(|(sub, _)| sub.matches(event))
            .map(|(_, handler)| handler.as_str())
            .collect()
    }
}

/// Dead letter queue for failed webhooks.
#[derive(Debug, Default)]
pub struct DeadLetterQueue {
    events: RwLock<Vec<WebhookEvent>>,
    max_size: usize,
}

impl DeadLetterQueue {
    /// Create a new dead letter queue.
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            max_size,
        }
    }

    /// Add an event to the dead letter queue.
    pub fn push(&self, mut event: WebhookEvent) {
        event.metadata.status = DeliveryStatus::DeadLettered;
        let mut events = self.events.write();
        if events.len() >= self.max_size {
            events.remove(0); // Remove oldest
        }
        events.push(event);
    }

    /// Get all events in the queue.
    #[must_use]
    pub fn all(&self) -> Vec<WebhookEvent> {
        self.events.read().clone()
    }

    /// Get the queue size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.read().len()
    }

    /// Check if queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.read().is_empty()
    }

    /// Remove and return an event by ID.
    pub fn remove(&self, event_id: &str) -> Option<WebhookEvent> {
        let mut events = self.events.write();
        let pos = events.iter().position(|e| e.id == event_id)?;
        Some(events.remove(pos))
    }

    /// Clear the queue.
    pub fn clear(&self) {
        self.events.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HmacSha256Verifier;

    #[test]
    fn test_webhook_handler_verify() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier.clone(), "test");

        let body = b"test payload";
        let signature = verifier.compute(body);

        assert!(handler.verify(body, &signature).is_ok());
        assert!(handler.verify(body, "invalid").is_err());
    }

    #[test]
    fn test_payload_size_limit() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_max_payload_size(10);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        let large_body = vec![0u8; 100];
        let result = handler.verify(&large_body, "sig");

        assert!(matches!(result, Err(WebhookError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_ip_allowlist() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_ip_allowlist(vec!["192.168.1.1".to_string()]);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        assert!(handler.check_ip("192.168.1.1").is_ok());
        assert!(handler.check_ip("10.0.0.1").is_err());
    }

    #[test]
    fn test_replay_detection() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");

        // First check should pass
        assert!(handler.check_replay("event_1").is_ok());

        // Record the event
        handler.record_event("event_1");

        // Second check should fail
        assert!(matches!(
            handler.check_replay("event_1"),
            Err(WebhookError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn test_event_router() {
        let mut router = EventRouter::new();

        router.subscribe(
            EventSubscription::for_types(vec!["push".to_string()]),
            "push_handler",
        );
        router.subscribe(
            EventSubscription::all().with_provider("github"),
            "github_handler",
        );

        let event = WebhookEvent::new("1", "push", "github");
        let handlers = router.route(&event);

        assert!(handlers.contains(&"push_handler"));
        assert!(handlers.contains(&"github_handler"));

        let event = WebhookEvent::new("2", "issue", "gitlab");
        let handlers = router.route(&event);

        assert!(!handlers.contains(&"push_handler"));
        assert!(!handlers.contains(&"github_handler"));
    }

    #[test]
    fn test_dead_letter_queue() {
        let dlq = DeadLetterQueue::new(10);

        let event = WebhookEvent::new("1", "test", "provider");
        dlq.push(event);

        assert_eq!(dlq.len(), 1);
        assert!(!dlq.is_empty());

        let removed = dlq.remove("1");
        assert!(removed.is_some());
        assert!(dlq.is_empty());
    }

    #[test]
    fn test_idempotency_race_condition() {
        use crate::HmacSha256Verifier;
        use std::sync::Arc;
        use std::thread;

        let verifier = HmacSha256Verifier::new("secret");
        let handler = Arc::new(WebhookHandler::new(verifier, "test"));
        let event_id = "race_event";

        // Simulate two concurrent requests
        let h1 = handler.clone();
        let t1 = thread::spawn(move || {
            if h1.claim_event(event_id).is_ok() {
                // Simulate processing time
                thread::sleep(std::time::Duration::from_millis(50));
                true
            } else {
                false
            }
        });

        let h2 = handler.clone();
        let t2 = thread::spawn(move || {
            if h2.claim_event(event_id).is_ok() {
                // Simulate processing time
                thread::sleep(std::time::Duration::from_millis(50));
                true
            } else {
                false
            }
        });

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // If both return true, idempotency failed
        assert!(
            !(r1 && r2),
            "Race condition detected: both threads processed the same event"
        );
    }

    // ── New tests ──

    #[test]
    fn test_webhook_config_default() {
        let config = WebhookConfig::default();
        assert_eq!(config.max_payload_size, DEFAULT_MAX_PAYLOAD_SIZE);
        assert!(config.idempotency_enabled);
        assert_eq!(config.idempotency_ttl, Duration::from_secs(86400));
        assert!(config.ip_allowlist.is_empty());
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(60));
    }

    #[test]
    fn test_webhook_config_builder() {
        let config = WebhookConfig::new()
            .with_max_payload_size(1024)
            .with_idempotency(false)
            .with_idempotency_ttl(Duration::from_secs(3600))
            .with_ip_allowlist(vec!["1.2.3.4".into()])
            .with_max_retries(5);

        assert_eq!(config.max_payload_size, 1024);
        assert!(!config.idempotency_enabled);
        assert_eq!(config.idempotency_ttl, Duration::from_secs(3600));
        assert_eq!(config.ip_allowlist, vec!["1.2.3.4"]);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_webhook_handler_accessors() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "github");

        assert_eq!(handler.provider(), "github");
        assert_eq!(handler.config().max_payload_size, DEFAULT_MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_empty_allowlist_allows_all() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");

        // Empty allowlist should allow any IP
        assert!(handler.check_ip("1.2.3.4").is_ok());
        assert!(handler.check_ip("10.0.0.1").is_ok());
    }

    #[test]
    fn test_claim_event_first_and_replay() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");

        assert!(handler.claim_event("evt_1").is_ok());
        assert!(matches!(
            handler.claim_event("evt_1"),
            Err(WebhookError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn test_idempotency_disabled_allows_replay() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_idempotency(false);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        handler.record_event("evt_1");
        assert!(handler.check_replay("evt_1").is_ok());
        assert!(handler.claim_event("evt_1").is_ok());
    }

    #[test]
    fn test_event_router_empty() {
        let router = EventRouter::new();
        let event = crate::WebhookEvent::new("1", "push", "github");
        assert!(router.route(&event).is_empty());
    }

    #[test]
    fn test_dead_letter_queue_max_size_eviction() {
        let dlq = DeadLetterQueue::new(2);

        dlq.push(crate::WebhookEvent::new("1", "test", "p"));
        dlq.push(crate::WebhookEvent::new("2", "test", "p"));
        dlq.push(crate::WebhookEvent::new("3", "test", "p"));

        assert_eq!(dlq.len(), 2);
        // Oldest (id "1") should have been evicted
        let all = dlq.all();
        assert_eq!(all[0].id, "2");
        assert_eq!(all[1].id, "3");
    }

    #[test]
    fn test_dead_letter_queue_sets_dead_lettered_status() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("1", "test", "p"));

        let all = dlq.all();
        assert_eq!(all[0].metadata.status, DeliveryStatus::DeadLettered);
    }

    #[test]
    fn test_dead_letter_queue_clear() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("1", "test", "p"));
        dlq.push(crate::WebhookEvent::new("2", "test", "p"));
        assert_eq!(dlq.len(), 2);

        dlq.clear();
        assert!(dlq.is_empty());
    }

    #[test]
    fn test_dead_letter_queue_remove_nonexistent() {
        let dlq = DeadLetterQueue::new(10);
        assert!(dlq.remove("nonexistent").is_none());
    }

    #[test]
    fn test_webhook_handler_debug() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "github");
        let debug = format!("{handler:?}");
        assert!(debug.contains("WebhookHandler"));
        assert!(debug.contains("github"));
        assert!(debug.contains("[REDACTED]"));
    }
}
