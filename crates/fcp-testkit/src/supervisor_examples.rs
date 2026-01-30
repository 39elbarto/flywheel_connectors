//! Reference examples for SDK runtime supervisors.
//!
//! This module provides copy-paste templates for connector authors implementing
//! polling and streaming connectors using the SDK's supervision infrastructure.
//!
//! # Polling Example
//!
//! ```rust,ignore
//! use fcp_testkit::supervisor_examples::FakePollingConnector;
//!
//! let connector = FakePollingConnector::new();
//! let outcome = connector.run_supervised().await;
//! ```
//!
//! # Streaming Example
//!
//! ```rust,ignore
//! use fcp_testkit::supervisor_examples::FakeStreamingConnector;
//!
//! let connector = FakeStreamingConnector::new();
//! // Use with StreamingSession trait
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use fcp_cbor::SchemaId;
use fcp_core::{
    ConnectorId, ConnectorStateSnapshot, CursorState, ObjectHeader, ObjectId, Provenance,
    Signature, TaintLevel, ZoneId,
};
#[cfg(feature = "cursor-store-object-store")]
use fcp_sdk::runtime::ObjectStoreCursorBackend;
use fcp_sdk::runtime::{
    CursorLease, CursorStore, CursorStoreError, InMemoryCursorStoreBackend, InMemoryPollingCursor,
    InMemoryStreamingSession, PollResult, PollingCursor, PollingSupervisor, PollingSupervisorStats,
    StreamingSession, SupervisorConfig, SupervisorOutcome,
};
use semver::Version;
use tokio::sync::watch;

#[cfg(feature = "cursor-store-object-store")]
use fcp_core::ObjectIdKey;
#[cfg(feature = "cursor-store-object-store")]
use fcp_store::MemoryObjectStore;
// ─────────────────────────────────────────────────────────────────────────────
// Fake Polling API
// ─────────────────────────────────────────────────────────────────────────────

/// A fake update from a polling API.
#[derive(Debug, Clone)]
pub struct FakeUpdate {
    /// Update ID (used for cursor advancement).
    pub id: i64,
    /// Update payload.
    pub payload: String,
}

/// Configuration for the fake polling API behavior.
#[derive(Debug, Clone)]
pub struct FakePollingApiConfig {
    /// Number of updates to return per poll (0 = empty).
    pub updates_per_poll: usize,
    /// Number of successful polls before injecting an error.
    pub success_count_before_error: Option<u32>,
    /// Error to inject (if any).
    pub inject_error: Option<FakePollingError>,
    /// Retry-After value for rate limit errors (ms).
    pub rate_limit_retry_after_ms: Option<u64>,
}

impl Default for FakePollingApiConfig {
    fn default() -> Self {
        Self {
            updates_per_poll: 2,
            success_count_before_error: None,
            inject_error: None,
            rate_limit_retry_after_ms: None,
        }
    }
}

/// Errors that can be injected into the fake polling API.
#[derive(Debug, Clone)]
pub enum FakePollingError {
    /// Timeout error (recoverable).
    Timeout,
    /// Rate limit error (recoverable with Retry-After).
    RateLimited,
    /// Authentication error (fatal).
    AuthFailed,
    /// Network error (recoverable).
    NetworkError,
}

/// A fake polling API that simulates a getUpdates-style endpoint.
///
/// Use this to test polling supervisor behavior with controllable failures.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::supervisor_examples::{FakePollingApi, FakePollingApiConfig, FakePollingError};
///
/// // Create API that fails after 3 successful polls
/// let config = FakePollingApiConfig {
///     updates_per_poll: 2,
///     success_count_before_error: Some(3),
///     inject_error: Some(FakePollingError::Timeout),
///     ..Default::default()
/// };
/// let api = FakePollingApi::new(config);
/// ```
#[derive(Debug)]
pub struct FakePollingApi {
    config: FakePollingApiConfig,
    poll_count: AtomicU32,
    next_update_id: AtomicU64,
}

impl FakePollingApi {
    /// Create a new fake polling API with the given configuration.
    #[must_use]
    pub const fn new(config: FakePollingApiConfig) -> Self {
        Self {
            config,
            poll_count: AtomicU32::new(0),
            next_update_id: AtomicU64::new(1),
        }
    }

    /// Create a fake API that always succeeds.
    #[must_use]
    pub fn always_success(updates_per_poll: usize) -> Self {
        Self::new(FakePollingApiConfig {
            updates_per_poll,
            ..Default::default()
        })
    }

    /// Create a fake API that fails after N polls.
    #[must_use]
    pub fn fail_after(n: u32, error: FakePollingError) -> Self {
        Self::new(FakePollingApiConfig {
            success_count_before_error: Some(n),
            inject_error: Some(error),
            ..Default::default()
        })
    }

    /// Create a fake API that simulates rate limiting.
    #[must_use]
    pub fn rate_limited(retry_after_ms: u64) -> Self {
        Self::new(FakePollingApiConfig {
            success_count_before_error: Some(1),
            inject_error: Some(FakePollingError::RateLimited),
            rate_limit_retry_after_ms: Some(retry_after_ms),
            ..Default::default()
        })
    }

    /// Get the current poll count.
    #[must_use]
    pub fn poll_count(&self) -> u32 {
        self.poll_count.load(Ordering::SeqCst)
    }

    /// Simulate a poll operation.
    ///
    /// Returns updates starting from the given offset, or an error based on config.
    pub fn poll(&self, _offset: Option<i64>) -> PollResult<FakeUpdate> {
        let count = self.poll_count.fetch_add(1, Ordering::SeqCst);

        // Check if we should inject an error
        if let Some(threshold) = self.config.success_count_before_error {
            if count >= threshold {
                return match &self.config.inject_error {
                    Some(FakePollingError::Timeout) => {
                        PollResult::recoverable("connection timeout")
                    }
                    Some(FakePollingError::RateLimited) => {
                        let retry_after = self.config.rate_limit_retry_after_ms.unwrap_or(1000);
                        PollResult::rate_limited("rate limited", retry_after)
                    }
                    Some(FakePollingError::AuthFailed) => {
                        PollResult::fatal("authentication failed")
                    }
                    Some(FakePollingError::NetworkError) => {
                        PollResult::recoverable("network error")
                    }
                    None => PollResult::empty(),
                };
            }
        }

        // Generate updates
        let updates: Vec<FakeUpdate> = (0..self.config.updates_per_poll)
            .map(|_| {
                let raw_id = self.next_update_id.fetch_add(1, Ordering::SeqCst);
                // Safe: update IDs won't exceed i64::MAX in tests
                #[allow(clippy::cast_possible_wrap)]
                let id = raw_id as i64;
                FakeUpdate {
                    id,
                    payload: format!("update-{id}"),
                }
            })
            .collect();

        PollResult::success(updates)
    }

    /// Reset the poll count and update ID counter.
    pub fn reset(&self) {
        self.poll_count.store(0, Ordering::SeqCst);
        self.next_update_id.store(1, Ordering::SeqCst);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake Polling Connector
// ─────────────────────────────────────────────────────────────────────────────

/// A reference polling connector using the `PollingSupervisor`.
///
/// This demonstrates the recommended pattern for building polling connectors
/// with the SDK's supervision infrastructure.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::supervisor_examples::{FakePollingConnector, FakePollingApi};
/// use tokio::sync::watch;
///
/// # async fn example() {
/// let api = FakePollingApi::always_success(2);
/// let connector = FakePollingConnector::new(api);
///
/// let (shutdown_tx, shutdown_rx) = watch::channel(false);
///
/// // Run supervisor in background
/// let handle = tokio::spawn(async move {
///     connector.run(shutdown_rx).await
/// });
///
/// // Let it run a bit, then shutdown
/// tokio::time::sleep(std::time::Duration::from_millis(100)).await;
/// shutdown_tx.send(true).unwrap();
///
/// let outcome = handle.await.unwrap();
/// # }
/// ```
pub struct FakePollingConnector {
    api: Arc<FakePollingApi>,
    config: SupervisorConfig,
    poll_interval_ms: u64,
    processed_updates: Arc<AtomicU64>,
}

impl FakePollingConnector {
    /// Create a new fake polling connector with the given API.
    #[must_use]
    pub fn new(api: FakePollingApi) -> Self {
        Self {
            api: Arc::new(api),
            config: SupervisorConfig::default()
                .with_base_backoff_ms(10) // Fast for testing
                .with_max_backoff_ms(100)
                .with_max_consecutive_failures(3),
            poll_interval_ms: 10, // Fast for testing
            processed_updates: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Set custom supervisor configuration.
    #[must_use]
    pub const fn with_config(mut self, config: SupervisorConfig) -> Self {
        self.config = config;
        self
    }

    /// Set custom poll interval.
    #[must_use]
    pub const fn with_poll_interval_ms(mut self, ms: u64) -> Self {
        self.poll_interval_ms = ms;
        self
    }

    /// Get the number of processed updates.
    #[must_use]
    pub fn processed_count(&self) -> u64 {
        self.processed_updates.load(Ordering::SeqCst)
    }

    /// Get the underlying API (for inspection).
    #[must_use]
    pub fn api(&self) -> &FakePollingApi {
        &self.api
    }

    /// Run the connector with supervision.
    ///
    /// Returns the supervisor outcome and statistics.
    pub async fn run(
        &self,
        shutdown: watch::Receiver<bool>,
    ) -> (SupervisorOutcome, PollingSupervisorStats) {
        let cursor = InMemoryPollingCursor::new();
        let mut supervisor = PollingSupervisor::new(self.config.clone(), cursor);

        let api = Arc::clone(&self.api);
        let processed = Arc::clone(&self.processed_updates);

        let outcome = supervisor
            .run(
                shutdown,
                self.poll_interval_ms,
                move |offset| {
                    let api = Arc::clone(&api);
                    async move { api.poll(offset) }
                },
                move |updates, cursor| {
                    for update in updates {
                        cursor.advance_if_newer(update.id);
                        processed.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                },
            )
            .await;

        (outcome, supervisor.stats().clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CursorStore Polling Example
// ─────────────────────────────────────────────────────────────────────────────

/// A polling connector example that persists cursor state via `CursorStore`.
///
/// Demonstrates lease acquisition (`CursorLease`), cursor load, commit, and snapshot creation.
pub struct FakeCursorStoreConnector {
    api: Arc<FakePollingApi>,
    backend: Arc<InMemoryCursorStoreBackend>,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    processed_updates: Arc<AtomicU64>,
}

impl FakeCursorStoreConnector {
    /// Create a new connector using an in-memory cursor store backend.
    #[must_use]
    pub fn new(api: FakePollingApi) -> Self {
        Self {
            api: Arc::new(api),
            backend: Arc::new(InMemoryCursorStoreBackend::new()),
            connector_id: ConnectorId::from_static("fake:operational:1.0"),
            zone_id: ZoneId::work(),
            processed_updates: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Return a handle to the backend (for reuse across restarts).
    #[must_use]
    pub fn backend(&self) -> Arc<InMemoryCursorStoreBackend> {
        Arc::clone(&self.backend)
    }

    /// Execute a single poll + commit cycle using `CursorStore`.
    ///
    /// # Errors
    ///
    /// Returns an error if the cursor store cannot load or commit the cursor state.
    ///
    /// Returns the committed cursor state.
    pub fn run_once(
        &self,
        backend: Arc<InMemoryCursorStoreBackend>,
        lease: CursorLease,
        created_at: u64,
    ) -> Result<CursorState, CursorStoreError> {
        let mut store = CursorStore::new(backend, self.connector_id.clone(), self.zone_id.clone());
        let previous = store.load_cursor()?;
        let offset = previous.as_ref().and_then(|cursor| cursor.offset);

        let result = self.api.poll(offset);
        let updates = match result {
            PollResult::Success(items) => items,
            _ => Vec::new(),
        };

        let mut cursor = offset.map_or_else(InMemoryPollingCursor::new, |offset| {
            InMemoryPollingCursor::with_offset(offset)
        });

        let mut last_seen = None;
        for update in updates {
            cursor.advance_if_newer(update.id);
            last_seen = Some(update.id.to_string());
            self.processed_updates.fetch_add(1, Ordering::SeqCst);
        }

        let cursor_state = CursorState {
            offset: cursor.offset(),
            last_seen_id: last_seen,
            watermark: Some(created_at),
        };

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "ConnectorStateObject", Version::new(1, 0, 0)),
            zone_id: self.zone_id.clone(),
            created_at,
            provenance: Provenance {
                origin_zone: self.zone_id.clone(),
                chain: Vec::new(),
                taint: TaintLevel::Untainted,
                elevated: false,
                elevation_token: None,
            },
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let head = store.commit_cursor(cursor_state.clone(), header, lease, Signature::zero())?;
        let _snapshot = Self::build_snapshot(
            head,
            &cursor_state,
            self.connector_id.clone(),
            self.zone_id.clone(),
            created_at,
        );

        Ok(cursor_state)
    }

    /// Execute a single poll + commit cycle using an `ObjectStoreCursorBackend`.
    ///
    /// Demonstrates mesh-persistent cursor storage via `ObjectStore`.
    ///
    /// # Errors
    ///
    /// Returns an error if the cursor store cannot load or commit the cursor state.
    #[cfg(feature = "cursor-store-object-store")]
    pub fn run_once_object_store(
        &self,
        object_store: Arc<MemoryObjectStore>,
        object_id_key: ObjectIdKey,
        lease: CursorLease,
        created_at: u64,
    ) -> Result<CursorState, CursorStoreError> {
        let backend = ObjectStoreCursorBackend::new(
            object_store,
            object_id_key,
            self.connector_id.clone(),
            self.zone_id.clone(),
        );
        let mut store = CursorStore::new(backend, self.connector_id.clone(), self.zone_id.clone());
        let previous = store.load_cursor()?;
        let offset = previous.as_ref().and_then(|cursor| cursor.offset);

        let result = self.api.poll(offset);
        let updates = match result {
            PollResult::Success(items) => items,
            _ => Vec::new(),
        };

        let mut cursor = offset.map_or_else(InMemoryPollingCursor::new, |offset| {
            InMemoryPollingCursor::with_offset(offset)
        });

        let mut last_seen = None;
        for update in updates {
            cursor.advance_if_newer(update.id);
            last_seen = Some(update.id.to_string());
            self.processed_updates.fetch_add(1, Ordering::SeqCst);
        }

        let cursor_state = CursorState {
            offset: cursor.offset(),
            last_seen_id: last_seen,
            watermark: Some(created_at),
        };

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0)),
            zone_id: self.zone_id.clone(),
            created_at,
            provenance: Provenance {
                origin_zone: self.zone_id.clone(),
                chain: Vec::new(),
                taint: TaintLevel::Untainted,
                elevated: false,
                elevation_token: None,
            },
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        let head = store.commit_cursor(cursor_state.clone(), header, lease, Signature::zero())?;
        let _snapshot = Self::build_snapshot(
            head,
            &cursor_state,
            self.connector_id.clone(),
            self.zone_id.clone(),
            created_at,
        );

        Ok(cursor_state)
    }

    /// Build a snapshot object from cursor state (example only).
    ///
    /// # Panics
    ///
    /// Panics if the cursor state cannot be encoded to canonical CBOR.
    #[must_use]
    pub fn build_snapshot(
        covers_head: ObjectId,
        cursor_state: &CursorState,
        connector_id: ConnectorId,
        zone_id: ZoneId,
        snapshotted_at: u64,
    ) -> ConnectorStateSnapshot {
        let state_cbor = cursor_state.to_cbor().expect("cursor state should encode");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "ConnectorStateSnapshot", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: snapshotted_at,
            provenance: Provenance {
                origin_zone: zone_id.clone(),
                chain: Vec::new(),
                taint: TaintLevel::Untainted,
                elevated: false,
                elevation_token: None,
            },
            refs: vec![covers_head],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };

        ConnectorStateSnapshot {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            covers_head,
            covers_seq: 0,
            state_cbor,
            snapshotted_at,
            signature: Signature::zero(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake Streaming Session
// ─────────────────────────────────────────────────────────────────────────────

/// A fake streaming event.
#[derive(Debug, Clone)]
pub struct FakeStreamEvent {
    /// Event sequence number.
    pub seq: u64,
    /// Event type.
    pub event_type: String,
    /// Event payload.
    pub payload: serde_json::Value,
}

/// A reference streaming session using the SDK's `StreamingSession` trait.
///
/// This demonstrates the recommended pattern for managing streaming state
/// with the SDK's session infrastructure.
///
/// # Example
///
/// ```rust
/// use fcp_testkit::supervisor_examples::FakeStreamingSession;
/// use fcp_sdk::runtime::StreamingSession;
///
/// let mut session = FakeStreamingSession::new();
///
/// // Set resume token after connection
/// session.set_resume_token("token-123".to_string());
///
/// // Track sequence numbers
/// let seq = session.next_sequence();
/// assert_eq!(seq, 0);
/// assert_eq!(session.sequence(), 1);
///
/// // Persist and restore
/// session.persist().unwrap();
/// ```
#[derive(Debug)]
pub struct FakeStreamingSession {
    inner: InMemoryStreamingSession,
    /// Events received in this session.
    pub events: Vec<FakeStreamEvent>,
    /// Whether persist was called (uses interior mutability for `&self`).
    persist_called: AtomicBool,
    /// Whether restore was called.
    restore_called: bool,
}

impl FakeStreamingSession {
    /// Create a new fake streaming session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: InMemoryStreamingSession::new(),
            events: Vec::new(),
            persist_called: AtomicBool::new(false),
            restore_called: false,
        }
    }

    /// Add a received event.
    pub fn add_event(&mut self, event: FakeStreamEvent) {
        self.set_sequence(event.seq + 1);
        self.events.push(event);
    }

    /// Get received event count.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Check if persist was called.
    #[must_use]
    pub fn persist_called(&self) -> bool {
        self.persist_called.load(Ordering::Relaxed)
    }

    /// Check if restore was called.
    #[must_use]
    pub const fn restore_called(&self) -> bool {
        self.restore_called
    }
}

impl Default for FakeStreamingSession {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingSession for FakeStreamingSession {
    fn resume_token(&self) -> Option<String> {
        self.inner.resume_token()
    }

    fn set_resume_token(&mut self, token: String) {
        self.inner.set_resume_token(token);
    }

    fn clear_resume_token(&mut self) {
        self.inner.clear_resume_token();
    }

    fn sequence(&self) -> u64 {
        self.inner.sequence()
    }

    fn set_sequence(&mut self, seq: u64) {
        self.inner.set_sequence(seq);
    }

    fn record_heartbeat_sent(&mut self, at: std::time::Instant) {
        self.inner.record_heartbeat_sent(at);
    }

    fn record_heartbeat_ack(&mut self, at: std::time::Instant) {
        self.inner.record_heartbeat_ack(at);
    }

    fn last_heartbeat_sent(&self) -> Option<std::time::Instant> {
        self.inner.last_heartbeat_sent()
    }

    fn last_heartbeat_ack(&self) -> Option<std::time::Instant> {
        self.inner.last_heartbeat_ack()
    }

    fn heartbeat_seq(&self) -> u64 {
        self.inner.heartbeat_seq()
    }

    fn ack_seq(&self) -> u64 {
        self.inner.ack_seq()
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.persist_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.restore_called = true;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_polling_api_success() {
        let api = FakePollingApi::always_success(3);

        let result = api.poll(None);
        assert!(matches!(result, PollResult::Success(updates) if updates.len() == 3));
        assert_eq!(api.poll_count(), 1);

        let result = api.poll(Some(3));
        assert!(matches!(result, PollResult::Success(updates) if updates.len() == 3));
        assert_eq!(api.poll_count(), 2);
    }

    #[test]
    fn fake_polling_api_fail_after() {
        let api = FakePollingApi::fail_after(2, FakePollingError::Timeout);

        // First two succeed
        assert!(matches!(api.poll(None), PollResult::Success(_)));
        assert!(matches!(api.poll(None), PollResult::Success(_)));

        // Third fails
        assert!(matches!(
            api.poll(None),
            PollResult::RecoverableError { .. }
        ));
    }

    #[test]
    fn fake_polling_api_rate_limited() {
        let api = FakePollingApi::rate_limited(5000);

        // First succeeds
        assert!(matches!(api.poll(None), PollResult::Success(_)));

        // Second is rate limited with retry-after
        let result = api.poll(None);
        assert!(matches!(
            result,
            PollResult::RecoverableError {
                retry_after_ms: Some(5000),
                ..
            }
        ));
    }

    #[test]
    fn fake_polling_api_fatal_error() {
        let api = FakePollingApi::fail_after(1, FakePollingError::AuthFailed);

        // First succeeds
        assert!(matches!(api.poll(None), PollResult::Success(_)));

        // Second is fatal
        assert!(matches!(api.poll(None), PollResult::FatalError { .. }));
    }

    #[tokio::test]
    async fn fake_polling_connector_shutdown() {
        let api = FakePollingApi::always_success(2);
        let connector = FakePollingConnector::new(api);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Run briefly then shutdown
        let handle = tokio::spawn(async move { connector.run(shutdown_rx).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();

        let (outcome, stats) = handle.await.unwrap();
        assert!(matches!(outcome, SupervisorOutcome::Shutdown));
        assert!(stats.total_polls > 0);
        assert!(stats.successful_polls > 0);
    }

    #[tokio::test]
    async fn fake_polling_connector_fatal_error() {
        let api = FakePollingApi::fail_after(1, FakePollingError::AuthFailed);
        let connector = FakePollingConnector::new(api);

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let (outcome, _stats) = connector.run(shutdown_rx).await;
        assert!(matches!(outcome, SupervisorOutcome::FatalError { .. }));
    }

    #[tokio::test]
    async fn fake_polling_connector_max_failures() {
        let api = FakePollingApi::fail_after(0, FakePollingError::NetworkError);
        let connector = FakePollingConnector::new(api)
            .with_config(SupervisorConfig::default().with_max_consecutive_failures(2));

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let (outcome, stats) = connector.run(shutdown_rx).await;
        assert!(matches!(
            outcome,
            SupervisorOutcome::MaxFailuresReached { failures: 2 }
        ));
        assert_eq!(stats.failed_polls, 2);
    }

    #[test]
    fn fake_cursor_store_connector_restart() {
        let api = FakePollingApi::always_success(2);
        let connector = FakeCursorStoreConnector::new(api);
        let backend = connector.backend();

        let first = connector
            .run_once(
                Arc::clone(&backend),
                CursorLease {
                    lease_seq: 1,
                    lease_object_id: ObjectId::from_bytes([0x11; 32]),
                },
                1_700_000_000,
            )
            .expect("first run should succeed");

        assert_eq!(first.offset, Some(3));

        let second = connector
            .run_once(
                Arc::clone(&backend),
                CursorLease {
                    lease_seq: 2,
                    lease_object_id: ObjectId::from_bytes([0x12; 32]),
                },
                1_700_000_010,
            )
            .expect("second run should succeed");

        assert!(second.offset.unwrap_or(0) > first.offset.unwrap_or(0));
    }

    #[test]
    fn fake_streaming_session_basics() {
        let mut session = FakeStreamingSession::new();

        assert!(session.resume_token().is_none());
        assert_eq!(session.sequence(), 0);

        session.set_resume_token("token-abc".to_string());
        assert_eq!(session.resume_token(), Some("token-abc".to_string()));

        session.add_event(FakeStreamEvent {
            seq: 0,
            event_type: "message".to_string(),
            payload: serde_json::json!({"text": "hello"}),
        });
        assert_eq!(session.sequence(), 1);
        assert_eq!(session.event_count(), 1);

        session.clear_resume_token();
        assert!(session.resume_token().is_none());
    }

    #[test]
    fn fake_streaming_session_persist_restore_tracking() {
        let mut session = FakeStreamingSession::new();

        // Initially both flags are false
        assert!(!session.persist_called());
        assert!(!session.restore_called());

        // Call persist() and verify flag is set
        session.persist().unwrap();
        assert!(session.persist_called());

        // Call restore() and verify flag is set
        session.restore().unwrap();
        assert!(session.restore_called());
    }
}
