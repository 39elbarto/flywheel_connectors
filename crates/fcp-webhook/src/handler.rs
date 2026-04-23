//! Generic webhook handler.
//!
//! Provides a unified interface for handling webhooks from any provider.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

use crate::{
    DeliveryStatus, EventSubscription, SignatureVerifier, WebhookError, WebhookEvent,
    WebhookResult, default_max_payload_size,
};

/// Maximum number of entries allowed in the replay event cache.
/// When this limit is reached, new events are rejected to prevent unbounded memory growth.
const MAX_SEEN_EVENTS: usize = 100_000;

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
            max_payload_size: default_max_payload_size(),
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
    seen_events: Arc<RwLock<SeenEventsState>>,
}

struct SeenEventsState {
    events: HashMap<String, DateTime<Utc>>,
    last_cleanup: DateTime<Utc>,
}

impl<V: SignatureVerifier> WebhookHandler<V> {
    /// Create a new webhook handler.
    #[must_use]
    pub fn new(verifier: V, provider: impl Into<String>) -> Self {
        Self {
            verifier,
            provider: provider.into(),
            config: WebhookConfig::default(),
            seen_events: Arc::new(RwLock::new(SeenEventsState {
                events: HashMap::new(),
                last_cleanup: Utc::now(),
            })),
        }
    }

    /// Create with configuration.
    #[must_use]
    pub fn with_config(verifier: V, provider: impl Into<String>, config: WebhookConfig) -> Self {
        Self {
            verifier,
            provider: provider.into(),
            config,
            seen_events: Arc::new(RwLock::new(SeenEventsState {
                events: HashMap::new(),
                last_cleanup: Utc::now(),
            })),
        }
    }

    /// Verify a webhook signature.
    ///
    /// # Errors
    /// Returns [`WebhookError::PayloadTooLarge`] when `body` exceeds configured limits,
    /// or verifier-specific signature errors when signature verification fails.
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
    ///
    /// # Errors
    /// Returns [`WebhookError::IpNotAllowed`] when `ip` is not present in a non-empty allowlist.
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
    ///
    /// # Errors
    /// Returns [`WebhookError::ReplayDetected`] when `event_id` was already seen.
    ///
    /// # Deprecated
    /// This split pair (`check_replay` + [`record_event`]) is TOCTOU-racy:
    /// two concurrent deliveries of the same untrusted `event_id` can both
    /// pass `check_replay` before either records, so both are processed —
    /// defeating the exactly-once guarantee on webhook input. Use
    /// [`claim_event`] instead, which performs the duplicate check and
    /// the insert under a single write lock (br-v3wrz).
    ///
    /// [`record_event`]: Self::record_event
    /// [`claim_event`]: Self::claim_event
    #[deprecated(
        since = "0.1.0",
        note = "use claim_event — split check/record is TOCTOU-racy (br-v3wrz)"
    )]
    pub fn check_replay(&self, event_id: &str) -> WebhookResult<()> {
        if !self.config.idempotency_enabled {
            return Ok(());
        }

        // Clean up old entries periodically
        self.cleanup_seen_events();

        let is_replay = {
            let state = self.seen_events.read();
            if let Some(&time) = state.events.get(event_id) {
                let now = Utc::now();
                let ttl = chrono::Duration::from_std(self.config.idempotency_ttl)
                    .unwrap_or(chrono::TimeDelta::MAX);
                now - time < ttl
            } else {
                false
            }
        };

        if is_replay {
            return Err(WebhookError::ReplayDetected {
                event_id: event_id.to_string(),
            });
        }

        Ok(())
    }

    /// Record an event as seen.
    ///
    /// # Errors
    /// Returns [`WebhookError::ReplayCacheFull`] when the cache has reached its maximum size.
    ///
    /// # Deprecated
    /// The write half of the racy [`check_replay`] + `record_event` pair.
    /// Use [`claim_event`] instead — it performs the duplicate check and
    /// the insert atomically under a single write lock (br-v3wrz).
    ///
    /// [`check_replay`]: Self::check_replay
    /// [`claim_event`]: Self::claim_event
    #[deprecated(
        since = "0.1.0",
        note = "use claim_event — split check/record is TOCTOU-racy (br-v3wrz)"
    )]
    pub fn record_event(&self, event_id: &str) -> WebhookResult<()> {
        if self.config.idempotency_enabled {
            let mut state = self.seen_events.write();
            if state.events.len() >= MAX_SEEN_EVENTS && !state.events.contains_key(event_id) {
                return Err(WebhookError::ReplayCacheFull {
                    size: state.events.len(),
                    limit: MAX_SEEN_EVENTS,
                });
            }
            state.events.insert(event_id.to_string(), Utc::now());
        }
        Ok(())
    }

    /// Check for replay and record the event in one atomic operation.
    ///
    /// This is the ONLY correct way to enforce exactly-once processing on
    /// untrusted webhook input. Duplicate-detection and the insert are
    /// performed under a single `seen_events.write()` acquisition, so two
    /// concurrent deliveries of the same `event_id` cannot both see "not
    /// seen yet". Prefer this over the deprecated [`check_replay`] /
    /// [`record_event`] pair (br-v3wrz).
    ///
    /// Returns `Err(ReplayDetected)` if already seen.
    ///
    /// # Errors
    /// Returns [`WebhookError::ReplayDetected`] when `event_id` was already claimed.
    ///
    /// [`check_replay`]: Self::check_replay
    /// [`record_event`]: Self::record_event
    pub fn claim_event(&self, event_id: &str) -> WebhookResult<()> {
        if !self.config.idempotency_enabled {
            return Ok(());
        }

        // Clean up old entries periodically
        self.cleanup_seen_events();

        {
            let mut state = self.seen_events.write();
            let now = Utc::now();

            if let Some(&time) = state.events.get(event_id) {
                let ttl = chrono::Duration::from_std(self.config.idempotency_ttl)
                    .unwrap_or(chrono::TimeDelta::MAX);
                if now - time < ttl {
                    return Err(WebhookError::ReplayDetected {
                        event_id: event_id.to_string(),
                    });
                }
            }

            if state.events.len() >= MAX_SEEN_EVENTS && !state.events.contains_key(event_id) {
                return Err(WebhookError::ReplayCacheFull {
                    size: state.events.len(),
                    limit: MAX_SEEN_EVENTS,
                });
            }

            state.events.insert(event_id.to_string(), now);
        }
        Ok(())
    }

    /// Clean up old seen events periodically to avoid O(N) traversal on every request.
    fn cleanup_seen_events(&self) {
        let now = Utc::now();

        let mut state = self.seen_events.write();

        // Only run cleanup if at least 1 minute has passed since last cleanup
        if now - state.last_cleanup < chrono::Duration::minutes(1) {
            return;
        }

        // Use saturating conversion to avoid panic on extreme durations
        let ttl = chrono::Duration::from_std(self.config.idempotency_ttl)
            .unwrap_or(chrono::TimeDelta::MAX);

        state.events.retain(|_, time| now - *time < ttl);
        state.last_cleanup = now;
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
            .finish_non_exhaustive()
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
        let mut handlers = Vec::new();
        for (subscription, handler) in &self.subscriptions {
            let handler = handler.as_str();
            if subscription.matches(event) && !handlers.contains(&handler) {
                handlers.push(handler);
            }
        }
        handlers
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
        if self.max_size == 0 {
            return;
        }

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
// Inline tests historically documented the split check_replay + record_event
// pair (now deprecated; see br-v3wrz). Keeping them running under
// allow(deprecated) preserves the regression surface while the pair exists.
// New code MUST use claim_event; see claim_event_is_atomic below.
#[allow(deprecated)]
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
        handler.record_event("event_1").unwrap();

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
        let h1 = Arc::clone(&handler);
        let t1 = thread::spawn(move || {
            if h1.claim_event(event_id).is_ok() {
                // Simulate processing time
                thread::sleep(std::time::Duration::from_millis(50));
                true
            } else {
                false
            }
        });

        let t2 = thread::spawn(move || {
            if handler.claim_event(event_id).is_ok() {
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
        assert_eq!(config.max_payload_size, default_max_payload_size());
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
        assert_eq!(
            handler.config().max_payload_size,
            default_max_payload_size()
        );
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

    /// Regression for br-v3wrz: `claim_event` MUST behave atomically
    /// under the concurrent delivery pattern that made the deprecated
    /// `check_replay` + `record_event` split pair unsafe.
    ///
    /// Simulates N concurrent deliveries of the same untrusted
    /// `event_id` across OS threads. Exactly one thread must observe
    /// `Ok(())`; every other thread must observe `ReplayDetected`.
    /// `AtomicUsize` success counter pins the property.
    #[test]
    fn claim_event_is_atomic_under_concurrent_deliveries() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const THREADS: usize = 16;
        const EVENT_ID: &str = "v3wrz-atomicity-regression";

        let verifier = HmacSha256Verifier::new("secret");
        let handler = Arc::new(WebhookHandler::new(verifier, "test"));
        let claim_ok = Arc::new(AtomicUsize::new(0));
        let claim_dup = Arc::new(AtomicUsize::new(0));

        let mut joins = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let h = Arc::clone(&handler);
            let ok = Arc::clone(&claim_ok);
            let dup = Arc::clone(&claim_dup);
            joins.push(std::thread::spawn(move || match h.claim_event(EVENT_ID) {
                Ok(()) => {
                    ok.fetch_add(1, Ordering::SeqCst);
                }
                Err(WebhookError::ReplayDetected { .. }) => {
                    dup.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => panic!("unexpected error under concurrent claim: {other:?}"),
            }));
        }
        for j in joins {
            j.join().expect("worker panic");
        }

        assert_eq!(
            claim_ok.load(Ordering::SeqCst),
            1,
            "claim_event must grant exactly one Ok under {THREADS} concurrent deliveries"
        );
        assert_eq!(
            claim_dup.load(Ordering::SeqCst),
            THREADS - 1,
            "remaining {} claims must all see ReplayDetected",
            THREADS - 1
        );
    }

    #[test]
    fn test_idempotency_disabled_allows_replay() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_idempotency(false);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        handler.record_event("evt_1").unwrap();
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

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn test_verify_exact_payload_size_limit() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_max_payload_size(10);
        let handler = WebhookHandler::with_config(verifier.clone(), "test", config);

        // Exactly at limit should pass (signature check)
        let body = vec![b'a'; 10];
        let sig = verifier.compute(&body);
        assert!(handler.verify(&body, &sig).is_ok());

        // One over limit should fail
        let body = vec![b'a'; 11];
        assert!(matches!(
            handler.verify(&body, "sig"),
            Err(WebhookError::PayloadTooLarge {
                size: 11,
                limit: 10
            })
        ));
    }

    #[test]
    fn test_verify_zero_max_payload_size() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_max_payload_size(0);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        // Any non-empty body should fail
        assert!(matches!(
            handler.verify(b"a", "sig"),
            Err(WebhookError::PayloadTooLarge { size: 1, limit: 0 })
        ));

        // Empty body should pass size check (fails on sig)
        assert!(handler.verify(b"", "sig").is_err()); // sig error, not size error
    }

    #[test]
    fn test_ip_allowlist_multiple_entries() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_ip_allowlist(vec![
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
            "172.16.0.1".to_string(),
        ]);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        assert!(handler.check_ip("192.168.1.1").is_ok());
        assert!(handler.check_ip("10.0.0.1").is_ok());
        assert!(handler.check_ip("172.16.0.1").is_ok());
        assert!(matches!(
            handler.check_ip("8.8.8.8"),
            Err(WebhookError::IpNotAllowed(_))
        ));
    }

    #[test]
    fn test_replay_detection_different_events() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");

        handler.record_event("evt_1").unwrap();
        handler.record_event("evt_2").unwrap();

        assert!(matches!(
            handler.check_replay("evt_1"),
            Err(WebhookError::ReplayDetected { .. })
        ));
        assert!(matches!(
            handler.check_replay("evt_2"),
            Err(WebhookError::ReplayDetected { .. })
        ));
        assert!(handler.check_replay("evt_3").is_ok());
    }

    #[test]
    fn test_replay_cleanup_ttl() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_idempotency_ttl(Duration::from_millis(1));
        let handler = WebhookHandler::with_config(verifier, "test", config);

        handler.record_event("evt_ttl").unwrap();
        assert!(matches!(
            handler.check_replay("evt_ttl"),
            Err(WebhookError::ReplayDetected { .. })
        ));

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(10));

        // After TTL, should be cleaned up
        assert!(handler.check_replay("evt_ttl").is_ok());
    }

    #[test]
    fn test_record_event_noop_when_idempotency_disabled() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_idempotency(false);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        handler.record_event("evt_1").unwrap();
        // Should not be recorded since idempotency is disabled
        assert!(handler.check_replay("evt_1").is_ok());
    }

    #[test]
    fn test_claim_event_when_idempotency_disabled() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_idempotency(false);
        let handler = WebhookHandler::with_config(verifier, "test", config);

        // Multiple claims should all succeed when idempotency is off
        assert!(handler.claim_event("evt_1").is_ok());
        assert!(handler.claim_event("evt_1").is_ok());
        assert!(handler.claim_event("evt_1").is_ok());
    }

    #[test]
    fn test_dead_letter_queue_single_capacity() {
        let dlq = DeadLetterQueue::new(1);

        dlq.push(crate::WebhookEvent::new("1", "test", "p"));
        assert_eq!(dlq.len(), 1);

        dlq.push(crate::WebhookEvent::new("2", "test", "p"));
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq.all()[0].id, "2");
    }

    #[test]
    fn test_dead_letter_queue_preserves_insertion_order() {
        let dlq = DeadLetterQueue::new(10);
        for i in 0..5 {
            dlq.push(crate::WebhookEvent::new(
                format!("evt_{i}"),
                "test",
                "provider",
            ));
        }

        let all = dlq.all();
        assert_eq!(all.len(), 5);
        for (i, event) in all.iter().enumerate() {
            assert_eq!(event.id, format!("evt_{i}"));
        }
    }

    #[test]
    fn test_dead_letter_queue_remove_returns_correct_event() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("a", "type_a", "p"));
        dlq.push(crate::WebhookEvent::new("b", "type_b", "p"));
        dlq.push(crate::WebhookEvent::new("c", "type_c", "p"));

        let removed = dlq.remove("b").unwrap();
        assert_eq!(removed.id, "b");
        assert_eq!(removed.event_type, "type_b");
        assert_eq!(dlq.len(), 2);

        // Remaining should be a and c
        let all = dlq.all();
        assert_eq!(all[0].id, "a");
        assert_eq!(all[1].id, "c");
    }

    #[test]
    fn test_event_router_wildcard_pattern() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::for_types(vec!["issue.*".to_string()]),
            "issue_handler",
        );

        assert_eq!(
            router
                .route(&crate::WebhookEvent::new("1", "issue.opened", "gh"))
                .len(),
            1
        );
        assert_eq!(
            router
                .route(&crate::WebhookEvent::new("2", "issue.closed", "gh"))
                .len(),
            1
        );
        assert!(
            router
                .route(&crate::WebhookEvent::new("3", "push", "gh"))
                .is_empty()
        );
    }

    #[test]
    fn test_event_router_overlapping_subscriptions() {
        let mut router = EventRouter::new();
        router.subscribe(EventSubscription::all(), "catch_all");
        router.subscribe(
            EventSubscription::for_types(vec!["push".to_string()]),
            "push_specific",
        );
        router.subscribe(
            EventSubscription::all().with_provider("github"),
            "github_all",
        );

        let event = crate::WebhookEvent::new("1", "push", "github");
        let handlers = router.route(&event);
        assert_eq!(handlers.len(), 3);
        assert!(handlers.contains(&"catch_all"));
        assert!(handlers.contains(&"push_specific"));
        assert!(handlers.contains(&"github_all"));
    }

    #[test]
    fn test_webhook_config_debug() {
        let config = WebhookConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("WebhookConfig"));
        assert!(debug.contains("max_payload_size"));
    }

    #[test]
    fn test_webhook_config_clone() {
        let original = WebhookConfig::new()
            .with_max_payload_size(1024)
            .with_max_retries(5);
        let copy = original;
        assert_eq!(copy.max_payload_size, 1024);
        assert_eq!(copy.max_retries, 5);
    }

    #[test]
    fn test_handler_shared_across_threads() {
        let verifier = HmacSha256Verifier::new("secret");
        let shared = Arc::new(WebhookHandler::new(verifier, "test"));

        let mut success_count = 0_u32;
        for i in 0..4 {
            let h = Arc::clone(&shared);
            let handle = std::thread::spawn(move || {
                let event_id = format!("evt_{i}");
                h.claim_event(&event_id).is_ok()
            });
            if handle.join().unwrap() {
                success_count += 1;
            }
        }
        // All 4 should succeed since they use different event IDs
        assert_eq!(success_count, 4);
    }

    // ── Batch 3: SunnyMoose deep test expansion ──

    #[test]
    fn test_webhook_config_new_equals_default() {
        let new_config = WebhookConfig::new();
        let default_config = WebhookConfig::default();
        assert_eq!(new_config.max_payload_size, default_config.max_payload_size);
        assert_eq!(
            new_config.idempotency_enabled,
            default_config.idempotency_enabled
        );
        assert_eq!(new_config.idempotency_ttl, default_config.idempotency_ttl);
        assert_eq!(new_config.max_retries, default_config.max_retries);
        assert_eq!(new_config.retry_delay, default_config.retry_delay);
    }

    #[test]
    fn test_webhook_config_max_retries_zero() {
        let config = WebhookConfig::new().with_max_retries(0);
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_verify_empty_body_empty_sig() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        // Empty signature will fail hex decode
        assert!(handler.verify(b"", "").is_err());
    }

    #[test]
    fn test_check_ip_ipv6() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_ip_allowlist(vec!["::1".to_string()]);
        let handler = WebhookHandler::with_config(verifier, "test", config);
        assert!(handler.check_ip("::1").is_ok());
        assert!(handler.check_ip("::2").is_err());
    }

    #[test]
    fn test_handler_provider_unicode() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "provid\u{00E9}r");
        assert_eq!(handler.provider(), "provid\u{00E9}r");
    }

    #[test]
    fn test_handler_provider_empty_string() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "");
        assert_eq!(handler.provider(), "");
    }

    #[test]
    fn test_claim_event_many_unique_events() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");

        for i in 0..100 {
            let event_id = format!("evt_{i}");
            assert!(handler.claim_event(&event_id).is_ok());
        }

        // All should be replays now
        for i in 0..100 {
            let event_id = format!("evt_{i}");
            assert!(matches!(
                handler.claim_event(&event_id),
                Err(WebhookError::ReplayDetected { .. })
            ));
        }
    }

    #[test]
    fn test_dead_letter_queue_zero_capacity() {
        let dlq = DeadLetterQueue::new(0);

        dlq.push(crate::WebhookEvent::new("1", "test", "p"));

        assert!(dlq.is_empty());
        assert_eq!(dlq.len(), 0);
        assert!(dlq.all().is_empty());
    }

    #[test]
    fn test_dead_letter_queue_all_returns_clone() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("1", "test", "p"));

        let all1 = dlq.all();
        let all2 = dlq.all();

        // Both should be independent clones
        assert_eq!(all1.len(), 1);
        assert_eq!(all2.len(), 1);
        assert_eq!(all1[0].id, all2[0].id);
    }

    #[test]
    fn test_dead_letter_queue_debug() {
        let dlq = DeadLetterQueue::new(5);
        let debug = format!("{dlq:?}");
        assert!(debug.contains("DeadLetterQueue"));
    }

    #[test]
    fn test_event_router_debug() {
        let router = EventRouter::new();
        let debug = format!("{router:?}");
        assert!(debug.contains("EventRouter"));
    }

    #[test]
    fn test_event_router_multiple_subscriptions_same_handler() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::for_types(vec!["push".to_string()]),
            "handler_a",
        );
        router.subscribe(
            EventSubscription::for_types(vec!["issue.*".to_string()]),
            "handler_a",
        );

        let push_event = crate::WebhookEvent::new("1", "push", "github");
        let handlers = router.route(&push_event);
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0], "handler_a");

        let issue_event = crate::WebhookEvent::new("2", "issue.opened", "github");
        let handlers = router.route(&issue_event);
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0], "handler_a");
    }

    #[test]
    fn test_event_router_no_match() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::for_types(vec!["push".to_string()]).with_provider("github"),
            "gh_push",
        );

        let event = crate::WebhookEvent::new("1", "pull_request", "gitlab");
        assert!(router.route(&event).is_empty());
    }

    #[test]
    fn test_dead_letter_queue_remove_middle_element() {
        let dlq = DeadLetterQueue::new(10);
        for i in 0..5 {
            dlq.push(crate::WebhookEvent::new(format!("evt_{i}"), "test", "p"));
        }

        let removed = dlq.remove("evt_2").unwrap();
        assert_eq!(removed.id, "evt_2");
        assert_eq!(dlq.len(), 4);

        let all = dlq.all();
        let ids: Vec<&str> = all.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["evt_0", "evt_1", "evt_3", "evt_4"]);
    }

    #[test]
    fn test_dead_letter_queue_multiple_removes() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("a", "test", "p"));
        dlq.push(crate::WebhookEvent::new("b", "test", "p"));
        dlq.push(crate::WebhookEvent::new("c", "test", "p"));

        assert!(dlq.remove("b").is_some());
        assert!(dlq.remove("b").is_none()); // already removed
        assert!(dlq.remove("a").is_some());
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq.all()[0].id, "c");
    }

    #[test]
    fn test_webhook_config_ip_allowlist_replace() {
        let config = WebhookConfig::new()
            .with_ip_allowlist(vec!["1.1.1.1".into()])
            .with_ip_allowlist(vec!["2.2.2.2".into(), "3.3.3.3".into()]);
        assert_eq!(config.ip_allowlist.len(), 2);
        assert!(!config.ip_allowlist.contains(&"1.1.1.1".to_string()));
        assert!(config.ip_allowlist.contains(&"2.2.2.2".to_string()));
    }

    // ── Batch 4: SunnyMoose additional test expansion ──

    #[test]
    fn test_webhook_config_large_max_payload_size() {
        let config = WebhookConfig::new().with_max_payload_size(usize::MAX);
        assert_eq!(config.max_payload_size, usize::MAX);
    }

    #[test]
    fn test_webhook_config_retry_delay_default() {
        let config = WebhookConfig::default();
        assert_eq!(config.retry_delay, Duration::from_secs(60));
    }

    #[test]
    fn test_webhook_config_chained_builder_all_fields() {
        let config = WebhookConfig::new()
            .with_max_payload_size(2048)
            .with_idempotency(true)
            .with_idempotency_ttl(Duration::from_secs(7200))
            .with_ip_allowlist(vec!["10.0.0.1".into(), "10.0.0.2".into()])
            .with_max_retries(10);
        assert_eq!(config.max_payload_size, 2048);
        assert!(config.idempotency_enabled);
        assert_eq!(config.idempotency_ttl, Duration::from_secs(7200));
        assert_eq!(config.ip_allowlist.len(), 2);
        assert_eq!(config.max_retries, 10);
    }

    #[test]
    fn test_handler_verify_empty_body_passes_size_check() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier.clone(), "test");
        let sig = verifier.compute(b"");
        // Empty body should pass size check and signature check
        assert!(handler.verify(b"", &sig).is_ok());
    }

    #[test]
    fn test_handler_check_ip_empty_string() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_ip_allowlist(vec![String::new()]);
        let handler = WebhookHandler::with_config(verifier, "test", config);
        // Empty string in allowlist matches empty string IP
        assert!(handler.check_ip("").is_ok());
        assert!(handler.check_ip("1.2.3.4").is_err());
    }

    #[test]
    fn test_handler_record_event_then_check() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        handler.record_event("unique_id_abc").unwrap();
        assert!(matches!(
            handler.check_replay("unique_id_abc"),
            Err(WebhookError::ReplayDetected { .. })
        ));
    }

    #[test]
    fn test_handler_claim_multiple_different_events() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        assert!(handler.claim_event("a").is_ok());
        assert!(handler.claim_event("b").is_ok());
        assert!(handler.claim_event("c").is_ok());
        // Replays should fail
        assert!(handler.claim_event("a").is_err());
        assert!(handler.claim_event("b").is_err());
        assert!(handler.claim_event("c").is_err());
    }

    #[test]
    fn test_dead_letter_queue_push_sets_dead_lettered_on_all() {
        let dlq = DeadLetterQueue::new(10);
        for i in 0..5 {
            let event = crate::WebhookEvent::new(format!("evt_{i}"), "test", "p");
            dlq.push(event);
        }
        let all = dlq.all();
        for event in &all {
            assert_eq!(event.metadata.status, DeliveryStatus::DeadLettered);
        }
    }

    #[test]
    fn test_dead_letter_queue_remove_first_element() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("first", "test", "p"));
        dlq.push(crate::WebhookEvent::new("second", "test", "p"));
        let removed = dlq.remove("first").unwrap();
        assert_eq!(removed.id, "first");
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq.all()[0].id, "second");
    }

    #[test]
    fn test_dead_letter_queue_remove_last_element() {
        let dlq = DeadLetterQueue::new(10);
        dlq.push(crate::WebhookEvent::new("first", "test", "p"));
        dlq.push(crate::WebhookEvent::new("last", "test", "p"));
        let removed = dlq.remove("last").unwrap();
        assert_eq!(removed.id, "last");
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq.all()[0].id, "first");
    }

    #[test]
    fn test_dead_letter_queue_eviction_order() {
        let dlq = DeadLetterQueue::new(3);
        dlq.push(crate::WebhookEvent::new("1", "test", "p"));
        dlq.push(crate::WebhookEvent::new("2", "test", "p"));
        dlq.push(crate::WebhookEvent::new("3", "test", "p"));
        // Should evict "1"
        dlq.push(crate::WebhookEvent::new("4", "test", "p"));
        let all = dlq.all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, "2");
        assert_eq!(all[1].id, "3");
        assert_eq!(all[2].id, "4");
        // Evict "2"
        dlq.push(crate::WebhookEvent::new("5", "test", "p"));
        let all = dlq.all();
        assert_eq!(all[0].id, "3");
        assert_eq!(all[1].id, "4");
        assert_eq!(all[2].id, "5");
    }

    #[test]
    fn test_event_router_subscribe_returns_in_order() {
        let mut router = EventRouter::new();
        router.subscribe(EventSubscription::all(), "first");
        router.subscribe(EventSubscription::all(), "second");
        router.subscribe(EventSubscription::all(), "third");
        let event = crate::WebhookEvent::new("e1", "push", "gh");
        let handlers = router.route(&event);
        assert_eq!(handlers, vec!["first", "second", "third"]);
    }

    #[test]
    fn test_event_router_provider_only_filter() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::all().with_provider("stripe"),
            "stripe_handler",
        );
        let gh_event = crate::WebhookEvent::new("e1", "push", "github");
        assert!(router.route(&gh_event).is_empty());
        let stripe_event = crate::WebhookEvent::new("e2", "charge.created", "stripe");
        assert_eq!(router.route(&stripe_event), vec!["stripe_handler"]);
    }

    #[test]
    fn test_event_router_type_and_provider_filter() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::for_types(vec!["push".into()]).with_provider("github"),
            "gh_push",
        );
        // Correct type, wrong provider
        assert!(
            router
                .route(&crate::WebhookEvent::new("e1", "push", "gitlab"))
                .is_empty()
        );
        // Wrong type, correct provider
        assert!(
            router
                .route(&crate::WebhookEvent::new("e2", "release", "github"))
                .is_empty()
        );
        // Both match
        assert_eq!(
            router.route(&crate::WebhookEvent::new("e3", "push", "github")),
            vec!["gh_push"]
        );
    }

    #[test]
    fn test_dead_letter_queue_clear_then_push() {
        let dlq = DeadLetterQueue::new(5);
        dlq.push(crate::WebhookEvent::new("1", "test", "p"));
        dlq.push(crate::WebhookEvent::new("2", "test", "p"));
        dlq.clear();
        assert!(dlq.is_empty());
        dlq.push(crate::WebhookEvent::new("3", "test", "p"));
        assert_eq!(dlq.len(), 1);
        assert_eq!(dlq.all()[0].id, "3");
    }

    #[test]
    fn test_handler_with_config_uses_custom_config() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new()
            .with_max_payload_size(512)
            .with_max_retries(7);
        let handler = WebhookHandler::with_config(verifier, "custom_provider", config);
        assert_eq!(handler.provider(), "custom_provider");
        assert_eq!(handler.config().max_payload_size, 512);
        assert_eq!(handler.config().max_retries, 7);
    }

    #[test]
    fn test_handler_verify_signature_error_not_size_error() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_max_payload_size(1000);
        let handler = WebhookHandler::with_config(verifier, "test", config);
        // Body within size limit but bad sig
        let result = handler.verify(b"small body", "bad_sig");
        assert!(result.is_err());
        assert!(!matches!(result, Err(WebhookError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_event_router_default() {
        let router = EventRouter::default();
        let event = crate::WebhookEvent::new("e1", "push", "gh");
        assert!(router.route(&event).is_empty());
    }

    #[test]
    fn test_dead_letter_queue_default() {
        let dlq = DeadLetterQueue::default();
        assert!(dlq.is_empty());
        assert_eq!(dlq.len(), 0);
    }

    #[test]
    fn test_replay_cleanup_preserves_recent_events() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new()
            .with_idempotency(true)
            .with_idempotency_ttl(Duration::from_secs(3600));
        let handler = WebhookHandler::with_config(verifier, "test", config);
        handler.record_event("recent_event").unwrap();
        // Event was just recorded, should not be cleaned up
        assert!(matches!(
            handler.check_replay("recent_event"),
            Err(WebhookError::ReplayDetected { .. })
        ));
    }

    // ── Batch 5: SunnyMoose test expansion ──

    #[test]
    fn test_verify_payload_size_exactly_max_minus_one() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_max_payload_size(10);
        let handler = WebhookHandler::with_config(verifier.clone(), "test", config);
        let body = vec![b'a'; 9];
        let sig = verifier.compute(&body);
        assert!(handler.verify(&body, &sig).is_ok());
    }

    #[test]
    fn test_handler_claim_event_unicode_id() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        assert!(handler.claim_event("evt_\u{00E9}\u{00F1}").is_ok());
        assert!(handler.claim_event("evt_\u{00E9}\u{00F1}").is_err());
    }

    #[test]
    fn test_handler_claim_event_empty_id() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        assert!(handler.claim_event("").is_ok());
        assert!(handler.claim_event("").is_err());
    }

    #[test]
    fn test_check_ip_unicode_ip() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_ip_allowlist(vec!["h\u{00F6}st".to_string()]);
        let handler = WebhookHandler::with_config(verifier, "test", config);
        assert!(handler.check_ip("h\u{00F6}st").is_ok());
        assert!(handler.check_ip("other").is_err());
    }

    #[test]
    fn test_dead_letter_queue_remove_from_empty() {
        let dlq = DeadLetterQueue::new(10);
        assert!(dlq.remove("any").is_none());
        assert!(dlq.is_empty());
    }

    #[test]
    fn test_dead_letter_queue_push_and_remove_all() {
        let dlq = DeadLetterQueue::new(5);
        for i in 0..5 {
            dlq.push(crate::WebhookEvent::new(format!("e{i}"), "t", "p"));
        }
        assert_eq!(dlq.len(), 5);
        for i in 0..5 {
            assert!(dlq.remove(&format!("e{i}")).is_some());
        }
        assert!(dlq.is_empty());
    }

    #[test]
    fn test_event_router_subscribe_duplicate_handler_ids() {
        let mut router = EventRouter::new();
        router.subscribe(
            EventSubscription::for_types(vec!["push".into()]),
            "same_handler",
        );
        router.subscribe(
            EventSubscription::for_types(vec!["push".into()]),
            "same_handler",
        );
        let event = crate::WebhookEvent::new("e1", "push", "gh");
        let handlers = router.route(&event);
        assert_eq!(handlers, vec!["same_handler"]);
    }

    #[test]
    fn test_dead_letter_queue_all_returns_dead_lettered_status() {
        let dlq = DeadLetterQueue::new(10);
        let mut event = crate::WebhookEvent::new("1", "test", "p");
        event.metadata.status = crate::DeliveryStatus::Failed;
        dlq.push(event);
        let all = dlq.all();
        assert_eq!(all[0].metadata.status, DeliveryStatus::DeadLettered);
    }

    #[test]
    fn test_handler_config_idempotency_ttl_zero() {
        let verifier = HmacSha256Verifier::new("secret");
        let config = WebhookConfig::new().with_idempotency_ttl(Duration::from_secs(0));
        let handler = WebhookHandler::with_config(verifier, "test", config);
        handler.record_event("evt_zero_ttl").unwrap();
        // With zero TTL, cleanup should remove it immediately
        // (depends on timing, but cleanup runs on check)
        // Wait a tiny moment to ensure it's past
        std::thread::sleep(Duration::from_millis(2));
        assert!(handler.check_replay("evt_zero_ttl").is_ok());
    }

    #[test]
    fn test_webhook_config_with_max_retries_u32_max() {
        let config = WebhookConfig::new().with_max_retries(u32::MAX);
        assert_eq!(config.max_retries, u32::MAX);
    }

    #[test]
    fn test_event_router_many_subscriptions() {
        let mut router = EventRouter::new();
        for i in 0..50 {
            router.subscribe(EventSubscription::all(), format!("handler_{i}"));
        }
        let event = crate::WebhookEvent::new("e1", "push", "gh");
        let handlers = router.route(&event);
        assert_eq!(handlers.len(), 50);
    }

    #[test]
    fn test_dead_letter_queue_preserves_event_fields() {
        let dlq = DeadLetterQueue::new(10);
        let event = crate::WebhookEvent::new("my_id", "my_type", "my_provider")
            .with_payload(serde_json::json!({"key": "value"}));
        dlq.push(event);
        let all = dlq.all();
        assert_eq!(all[0].id, "my_id");
        assert_eq!(all[0].event_type, "my_type");
        assert_eq!(all[0].provider, "my_provider");
        assert_eq!(all[0].payload, serde_json::json!({"key": "value"}));
    }

    #[test]
    fn test_handler_record_and_claim_interaction() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        // Record an event first
        handler.record_event("evt_rc").unwrap();
        // Claim should fail because it was already recorded
        assert!(handler.claim_event("evt_rc").is_err());
    }

    #[test]
    fn test_handler_claim_then_check_replay() {
        let verifier = HmacSha256Verifier::new("secret");
        let handler = WebhookHandler::new(verifier, "test");
        assert!(handler.claim_event("evt_cc").is_ok());
        assert!(handler.check_replay("evt_cc").is_err());
    }
}
