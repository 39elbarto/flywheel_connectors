//! Runtime supervision utilities for streaming and polling connectors.
//!
//! This module provides:
//! - [`SupervisorConfig`]: Configuration for backoff, retry budgets, and lifecycle management
//! - [`StreamingSession`]: Trait for streaming connectors to manage session state
//! - [`PollingCursor`]: Trait for polling connectors to manage cursor/offset state
//! - [`CursorStore`]: Mesh-backed cursor state helper for polling connectors
//! - [`HealthTracker`]: Health state machine with transition rules
//!
//! # Design Principles
//!
//! 1. **Config defaults align with study docs** (1s base backoff, 60s cap, jitter on)
//! 2. **Traits are minimal** - connectors provide persistence, SDK provides supervision logic
//! 3. **Health transitions are explicit** - state changes require evidence
//!
//! # Example
//!
//! ```ignore
//! use fcp_sdk::runtime::{SupervisorConfig, HealthTracker, HealthTransition};
//!
//! let config = SupervisorConfig::default();
//! let mut health = HealthTracker::new();
//!
//! // Report failures
//! health.record_failure("connection timeout");
//!
//! // Health degrades after threshold
//! if health.consecutive_failures() >= config.max_consecutive_failures {
//!     health.transition(HealthTransition::ToUnhealthy { reason: "too many failures".into() });
//! }
//! ```

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[cfg(feature = "cursor-store-object-store")]
use fcp_cbor::CanonicalSerializer;
use fcp_core::{
    ConnectorId, ConnectorStateObject, CursorState, HealthSnapshot, HealthState, InstanceId,
    ObjectHeader, ObjectId, Signature, ZoneId,
};
use fcp_core::{ObjectIdKey, RetentionClass, StorageMeta, StoredObject};

// ─────────────────────────────────────────────────────────────────────────────
// SupervisorConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for connector supervisors (streaming or polling).
///
/// These settings control backoff behavior, retry budgets, and lifecycle
/// management. Defaults align with FCP2 study recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupervisorConfig {
    /// Base delay for exponential backoff (milliseconds).
    ///
    /// After a failure, wait `base_backoff_ms * 2^attempt` before retrying.
    /// Default: 1000ms (1 second).
    pub base_backoff_ms: u64,

    /// Maximum backoff delay (milliseconds).
    ///
    /// Backoff will not exceed this value regardless of attempt count.
    /// Default: 60000ms (60 seconds).
    pub max_backoff_ms: u64,

    /// Whether to add random jitter to backoff delays.
    ///
    /// When enabled, actual delay is `delay * (0.5 + random(0..0.5))`.
    /// Default: true.
    pub jitter_enabled: bool,

    /// Maximum consecutive failures before declaring unhealthy.
    ///
    /// After this many failures in a row without success, the supervisor
    /// should transition to `HealthState::Error`.
    /// Default: 5.
    pub max_consecutive_failures: u32,

    /// Cooldown period after max failures (milliseconds).
    ///
    /// After hitting `max_consecutive_failures`, wait this long before
    /// attempting recovery. This prevents rapid retry storms.
    /// Default: 300000ms (5 minutes).
    pub cooldown_after_failure_ms: u64,

    /// Graceful shutdown timeout (milliseconds).
    ///
    /// Maximum time to wait for in-flight operations during shutdown.
    /// Default: 30000ms (30 seconds).
    pub shutdown_timeout_ms: u64,

    /// Heartbeat interval for streaming sessions (milliseconds).
    ///
    /// How often to send/expect heartbeats. Zero disables heartbeats.
    /// Default: 30000ms (30 seconds).
    pub heartbeat_interval_ms: u64,

    /// Heartbeat timeout multiplier.
    ///
    /// If no heartbeat received within `heartbeat_interval_ms * heartbeat_timeout_multiplier`,
    /// consider the connection dead.
    /// Default: 2.5.
    pub heartbeat_timeout_multiplier: f64,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 1000,
            max_backoff_ms: 60_000,
            jitter_enabled: true,
            max_consecutive_failures: 5,
            cooldown_after_failure_ms: 300_000,
            shutdown_timeout_ms: 30_000,
            heartbeat_interval_ms: 30_000,
            heartbeat_timeout_multiplier: 2.5,
        }
    }
}

impl SupervisorConfig {
    /// Create a new config with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set base backoff.
    #[must_use]
    pub const fn with_base_backoff_ms(mut self, ms: u64) -> Self {
        self.base_backoff_ms = ms;
        self
    }

    /// Builder: set max backoff.
    #[must_use]
    pub const fn with_max_backoff_ms(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Builder: enable/disable jitter.
    #[must_use]
    pub const fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter_enabled = enabled;
        self
    }

    /// Builder: set max consecutive failures.
    #[must_use]
    pub const fn with_max_consecutive_failures(mut self, count: u32) -> Self {
        self.max_consecutive_failures = count;
        self
    }

    /// Compute backoff delay for a given attempt number (0-indexed).
    ///
    /// Returns the delay in milliseconds, capped at `max_backoff_ms`.
    #[must_use]
    pub fn compute_backoff(&self, attempt: u32) -> u64 {
        let exp = attempt.min(30); // Prevent overflow
        let delay = self.base_backoff_ms.saturating_mul(1u64 << exp);
        delay.min(self.max_backoff_ms)
    }

    /// Compute backoff delay with optional jitter.
    ///
    /// If jitter is enabled, returns delay * (0.5 + random factor).
    /// The `jitter_factor` should be in range [0.0, 1.0].
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compute_backoff_with_jitter(&self, attempt: u32, jitter_factor: f64) -> u64 {
        let base = self.compute_backoff(attempt);
        if self.jitter_enabled {
            let factor = jitter_factor.clamp(0.0, 1.0).mul_add(0.5, 0.5);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let jittered = (base as f64 * factor) as u64;
            jittered
        } else {
            base
        }
    }

    /// Get shutdown timeout as a Duration.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.shutdown_timeout_ms)
    }

    /// Get cooldown period as a Duration.
    #[must_use]
    pub const fn cooldown_duration(&self) -> Duration {
        Duration::from_millis(self.cooldown_after_failure_ms)
    }

    /// Get heartbeat interval as a Duration (or None if disabled).
    #[must_use]
    pub const fn heartbeat_interval(&self) -> Option<Duration> {
        if self.heartbeat_interval_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.heartbeat_interval_ms))
        }
    }

    /// Get heartbeat timeout as a Duration (or None if disabled).
    #[must_use]
    pub fn heartbeat_timeout(&self) -> Option<Duration> {
        self.heartbeat_interval().map(|interval| {
            Duration::from_secs_f64(interval.as_secs_f64() * self.heartbeat_timeout_multiplier)
        })
    }

    /// Validate configuration, returning errors for invalid values.
    ///
    /// # Errors
    ///
    /// Returns error strings for any invalid configuration values.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.base_backoff_ms == 0 {
            errors.push("base_backoff_ms must be > 0".to_string());
        }
        if self.max_backoff_ms < self.base_backoff_ms {
            errors.push("max_backoff_ms must be >= base_backoff_ms".to_string());
        }
        if self.max_consecutive_failures == 0 {
            errors.push("max_consecutive_failures must be > 0".to_string());
        }
        if self.heartbeat_timeout_multiplier <= 1.0 {
            errors.push("heartbeat_timeout_multiplier must be > 1.0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamingSession trait
// ─────────────────────────────────────────────────────────────────────────────

/// Session state for streaming connectors (e.g., WebSocket-based).
///
/// Connectors implement this trait to enable session resumption, sequence
/// tracking, and heartbeat management. The supervisor uses these hooks
/// to maintain connection health.
pub trait StreamingSession: Send + Sync {
    /// Get the current resume token (opaque string for session resumption).
    ///
    /// Returns `None` if no session has been established yet.
    fn resume_token(&self) -> Option<String>;

    /// Set the resume token after successful connection.
    fn set_resume_token(&mut self, token: String);

    /// Clear the resume token (e.g., when session is invalidated).
    fn clear_resume_token(&mut self);

    /// Get the current sequence number for ordered message delivery.
    fn sequence(&self) -> u64;

    /// Update the sequence number after processing a message.
    fn set_sequence(&mut self, seq: u64);

    /// Increment and return the next sequence number.
    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence();
        self.set_sequence(seq.saturating_add(1));
        seq
    }

    /// Record that a heartbeat was sent.
    fn record_heartbeat_sent(&mut self, at: Instant);

    /// Record that a heartbeat acknowledgment was received.
    fn record_heartbeat_ack(&mut self, at: Instant);

    /// Get the timestamp of the last sent heartbeat.
    fn last_heartbeat_sent(&self) -> Option<Instant>;

    /// Get the timestamp of the last received heartbeat acknowledgment.
    fn last_heartbeat_ack(&self) -> Option<Instant>;

    /// Check if heartbeats have timed out.
    ///
    /// Returns `true` if the last ack is older than the configured timeout.
    fn is_heartbeat_timeout(&self, timeout: Duration) -> bool {
        match (self.last_heartbeat_sent(), self.last_heartbeat_ack()) {
            (Some(sent), Some(ack)) => ack < sent && sent.elapsed() > timeout,
            (Some(sent), None) => sent.elapsed() > timeout,
            _ => false,
        }
    }

    /// Persist session state to storage (connector-specific).
    ///
    /// Called periodically and before shutdown to preserve state.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Restore session state from storage (connector-specific).
    ///
    /// Called during startup to resume from previous session.
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails.
    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of [`StreamingSession`] for testing.
#[derive(Debug, Default)]
pub struct InMemoryStreamingSession {
    resume_token: Option<String>,
    sequence: u64,
    last_heartbeat_sent: Option<Instant>,
    last_heartbeat_ack: Option<Instant>,
}

impl InMemoryStreamingSession {
    /// Create a new in-memory session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StreamingSession for InMemoryStreamingSession {
    fn resume_token(&self) -> Option<String> {
        self.resume_token.clone()
    }

    fn set_resume_token(&mut self, token: String) {
        self.resume_token = Some(token);
    }

    fn clear_resume_token(&mut self) {
        self.resume_token = None;
    }

    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn set_sequence(&mut self, seq: u64) {
        self.sequence = seq;
    }

    fn record_heartbeat_sent(&mut self, at: Instant) {
        self.last_heartbeat_sent = Some(at);
    }

    fn record_heartbeat_ack(&mut self, at: Instant) {
        self.last_heartbeat_ack = Some(at);
    }

    fn last_heartbeat_sent(&self) -> Option<Instant> {
        self.last_heartbeat_sent
    }

    fn last_heartbeat_ack(&self) -> Option<Instant> {
        self.last_heartbeat_ack
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: no persistence
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: nothing to restore
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PollingCursor trait
// ─────────────────────────────────────────────────────────────────────────────

/// Cursor state for polling connectors (e.g., getUpdates-style APIs).
///
/// Connectors implement this trait to track the current offset/sequence
/// and persist it across restarts. This enables exactly-once processing
/// of updates via offset deduplication.
pub trait PollingCursor: Send + Sync {
    /// Get the current cursor offset (e.g., Telegram `update_id`).
    ///
    /// Returns `None` if no updates have been processed yet.
    fn offset(&self) -> Option<i64>;

    /// Set the cursor offset after processing updates.
    ///
    /// Typically set to `last_update_id + 1` to acknowledge processed updates.
    fn set_offset(&mut self, offset: i64);

    /// Get the last processing timestamp.
    fn last_poll_at(&self) -> Option<Instant>;

    /// Record that a poll was executed.
    fn record_poll(&mut self, at: Instant, updates_received: usize);

    /// Get the count of updates received in the last poll.
    fn last_poll_count(&self) -> usize;

    /// Advance offset by processing an update with the given ID.
    ///
    /// Sets offset to `update_id + 1` if it's newer than current offset.
    fn advance_if_newer(&mut self, update_id: i64) {
        let new_offset = update_id.saturating_add(1);
        if self.offset().is_none_or(|current| new_offset > current) {
            self.set_offset(new_offset);
        }
    }

    /// Persist cursor state to storage (connector-specific).
    ///
    /// Called after processing updates and before shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Restore cursor state from storage (connector-specific).
    ///
    /// Called during startup to resume from previous cursor position.
    ///
    /// # Errors
    ///
    /// Returns an error if restoration fails.
    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// In-memory implementation of [`PollingCursor`] for testing.
#[derive(Debug, Default)]
pub struct InMemoryPollingCursor {
    offset: Option<i64>,
    last_poll_at: Option<Instant>,
    last_poll_count: usize,
}

impl InMemoryPollingCursor {
    /// Create a new in-memory cursor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cursor with an initial offset.
    #[must_use]
    pub const fn with_offset(offset: i64) -> Self {
        Self {
            offset: Some(offset),
            last_poll_at: None,
            last_poll_count: 0,
        }
    }
}

impl PollingCursor for InMemoryPollingCursor {
    fn offset(&self) -> Option<i64> {
        self.offset
    }

    fn set_offset(&mut self, offset: i64) {
        self.offset = Some(offset);
    }

    fn last_poll_at(&self) -> Option<Instant> {
        self.last_poll_at
    }

    fn record_poll(&mut self, at: Instant, updates_received: usize) {
        self.last_poll_at = Some(at);
        self.last_poll_count = updates_received;
    }

    fn last_poll_count(&self) -> usize {
        self.last_poll_count
    }

    fn persist(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: no persistence
        Ok(())
    }

    fn restore(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In-memory: nothing to restore
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CursorStore (mesh-backed cursor state helper)
// ─────────────────────────────────────────────────────────────────────────────

/// Lease metadata required for cursor state writes.
#[derive(Debug, Clone, Copy)]
pub struct CursorLease {
    /// Fencing token from the authorizing lease.
    pub lease_seq: u64,
    /// Lease object ID granting write authority.
    pub lease_object_id: ObjectId,
}

/// Errors returned by cursor store operations.
#[derive(Debug, thiserror::Error)]
pub enum CursorStoreError {
    /// Underlying storage failed.
    #[error("cursor store backend error: {0}")]
    Storage(String),

    /// Lease fencing token regressed.
    #[error("stale lease_seq (current {current}, incoming {incoming})")]
    StaleLeaseSeq {
        /// Current lease sequence.
        current: u64,
        /// Incoming lease sequence.
        incoming: u64,
    },

    /// Offset moved backwards.
    #[error("offset regression (current {current}, incoming {incoming})")]
    OffsetRegression {
        /// Current offset value.
        current: i64,
        /// Incoming offset value.
        incoming: i64,
    },

    /// Watermark moved backwards.
    #[error("watermark regression (current {current}, incoming {incoming})")]
    WatermarkRegression {
        /// Current watermark.
        current: u64,
        /// Incoming watermark.
        incoming: u64,
    },

    /// Cursor encoding failed.
    #[error("cursor encoding failed: {0}")]
    CursorEncoding(String),

    /// Cursor decoding failed.
    #[error("cursor decoding failed: {0}")]
    CursorDecoding(String),
}

/// Backend for storing and retrieving connector state objects.
pub trait CursorStoreBackend: Send + Sync {
    /// Load the latest state object (head) and its object id.
    ///
    /// # Errors
    /// Returns [`CursorStoreError::Storage`] if the backend cannot load state.
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError>;

    /// Persist a new state object and return its object id.
    ///
    /// # Errors
    /// Returns [`CursorStoreError::Storage`] if the backend cannot persist state.
    fn store_state_object(&self, state: ConnectorStateObject)
    -> Result<ObjectId, CursorStoreError>;
}

/// Cursor store helper that builds lease-fenced state objects.
#[derive(Debug)]
pub struct CursorStore<B: CursorStoreBackend> {
    backend: B,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: Option<InstanceId>,
    head: Option<ObjectId>,
    seq: u64,
    last_cursor: Option<CursorState>,
    last_lease_seq: u64,
}

impl<B: CursorStoreBackend> CursorStore<B> {
    /// Create a new cursor store helper.
    pub const fn new(backend: B, connector_id: ConnectorId, zone_id: ZoneId) -> Self {
        Self {
            backend,
            connector_id,
            zone_id,
            instance_id: None,
            head: None,
            seq: 0,
            last_cursor: None,
            last_lease_seq: 0,
        }
    }

    /// Attach an instance id to state objects produced by this store.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Load the latest cursor state from the backend.
    ///
    /// # Errors
    /// Returns [`CursorStoreError`] if the backend fails or the cursor payload is invalid.
    pub fn load_cursor(&mut self) -> Result<Option<CursorState>, CursorStoreError> {
        let Some((head_id, head)) = self.backend.load_head()? else {
            return Ok(None);
        };

        let cursor = CursorState::from_cbor(&head.state_cbor)
            .map_err(|err| CursorStoreError::CursorDecoding(err.to_string()))?;

        self.head = Some(head_id);
        self.seq = head.seq;
        self.last_cursor = Some(cursor.clone());
        self.last_lease_seq = head.lease_seq;

        Ok(Some(cursor))
    }

    /// Commit a new cursor state, enforcing lease fencing and monotonic rules.
    ///
    /// # Errors
    /// Returns [`CursorStoreError`] if monotonicity checks fail, the cursor cannot be
    /// encoded, or the backend cannot persist the state object.
    pub fn commit_cursor(
        &mut self,
        cursor: CursorState,
        mut header: ObjectHeader,
        lease: CursorLease,
        signature: Signature,
    ) -> Result<ObjectId, CursorStoreError> {
        self.validate_commit(&cursor, lease.lease_seq)?;

        if !header.refs.contains(&lease.lease_object_id) {
            header.refs.push(lease.lease_object_id);
        }

        let state_cbor = cursor
            .to_cbor()
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;

        let next_seq = if self.head.is_some() { self.seq + 1 } else { 0 };
        let prev = self.head;

        let updated_at = header.created_at;
        let state_obj = ConnectorStateObject {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            prev,
            seq: next_seq,
            state_cbor,
            updated_at,
            lease_seq: lease.lease_seq,
            lease_object_id: lease.lease_object_id,
            signature,
        };

        let object_id = self.backend.store_state_object(state_obj)?;
        self.head = Some(object_id);
        self.seq = next_seq;
        self.last_cursor = Some(cursor);
        self.last_lease_seq = lease.lease_seq;

        Ok(object_id)
    }

    /// Return the current head object id, if any.
    #[must_use]
    pub const fn head(&self) -> Option<ObjectId> {
        self.head
    }

    #[allow(clippy::missing_const_for_fn)]
    fn validate_commit(
        &self,
        cursor: &CursorState,
        lease_seq: u64,
    ) -> Result<(), CursorStoreError> {
        if lease_seq < self.last_lease_seq {
            return Err(CursorStoreError::StaleLeaseSeq {
                current: self.last_lease_seq,
                incoming: lease_seq,
            });
        }

        if let Some(previous) = &self.last_cursor {
            if let (Some(current), Some(incoming)) = (previous.offset, cursor.offset)
                && incoming < current
            {
                return Err(CursorStoreError::OffsetRegression { current, incoming });
            }

            if let (Some(current), Some(incoming)) = (previous.watermark, cursor.watermark)
                && incoming < current
            {
                return Err(CursorStoreError::WatermarkRegression { current, incoming });
            }
        }

        Ok(())
    }
}

/// In-memory cursor store backend for tests and local development.
#[derive(Debug, Default)]
pub struct InMemoryCursorStoreBackend {
    state: Mutex<InMemoryCursorStoreState>,
}

#[derive(Debug, Default)]
struct InMemoryCursorStoreState {
    next_id: u64,
    objects: Vec<(ObjectId, ConnectorStateObject)>,
}

impl InMemoryCursorStoreBackend {
    /// Create a new in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl CursorStoreBackend for InMemoryCursorStoreBackend {
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CursorStoreError::Storage("cursor store mutex poisoned".into()))?;
        Ok(state.objects.last().cloned())
    }

    fn store_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CursorStoreError::Storage("cursor store mutex poisoned".into()))?;
        let byte = u8::try_from(state.next_id % 256).unwrap_or(0);
        let object_id = ObjectId::from_bytes([byte; 32]);
        state.next_id = state.next_id.wrapping_add(1);
        state.objects.push((object_id, state_obj));
        drop(state);
        Ok(object_id)
    }
}

impl CursorStoreBackend for Arc<InMemoryCursorStoreBackend> {
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        self.as_ref().load_head()
    }

    fn store_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        self.as_ref().store_state_object(state_obj)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ObjectStore-backed cursor store
// ─────────────────────────────────────────────────────────────────────────────

/// Cursor store backend backed by an `ObjectStore` (mesh persistence).
#[cfg(feature = "cursor-store-object-store")]
#[derive(Clone)]
pub struct ObjectStoreCursorBackend {
    object_store: Arc<dyn fcp_store::ObjectStore>,
    object_id_key: ObjectIdKey,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    retention: RetentionClass,
}

#[cfg(feature = "cursor-store-object-store")]
impl ObjectStoreCursorBackend {
    /// Create a new backend that stores connector state objects in an `ObjectStore`.
    #[must_use]
    pub fn new(
        object_store: Arc<dyn fcp_store::ObjectStore>,
        object_id_key: ObjectIdKey,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            object_store,
            object_id_key,
            connector_id,
            zone_id,
            retention: RetentionClass::Pinned,
        }
    }

    /// Override retention class for stored state objects.
    #[must_use]
    pub const fn with_retention(mut self, retention: RetentionClass) -> Self {
        self.retention = retention;
        self
    }

    #[allow(clippy::missing_const_for_fn)]
    fn schema_id() -> fcp_cbor::SchemaId {
        fcp_cbor::SchemaId::new(
            "fcp.connector_state",
            "state_object",
            semver::Version::new(1, 0, 0),
        )
    }

    fn block_on_store<T>(
        fut: impl std::future::Future<Output = Result<T, fcp_store::ObjectStoreError>>,
    ) -> Result<T, CursorStoreError> {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| handle.block_on(fut))
                    .map_err(|err| CursorStoreError::Storage(err.to_string()));
            }
        } else {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| CursorStoreError::Storage(err.to_string()))?;
            return runtime
                .block_on(fut)
                .map_err(|err| CursorStoreError::Storage(err.to_string()));
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| CursorStoreError::Storage(err.to_string()))?;
        runtime
            .block_on(fut)
            .map_err(|err| CursorStoreError::Storage(err.to_string()))
    }

    fn decode_state_object(
        stored: &StoredObject,
    ) -> Result<ConnectorStateObject, CursorStoreError> {
        CanonicalSerializer::deserialize(&stored.body, &stored.header.schema)
            .map_err(|err| CursorStoreError::CursorDecoding(err.to_string()))
    }
}

#[cfg(feature = "cursor-store-object-store")]
impl CursorStoreBackend for ObjectStoreCursorBackend {
    fn load_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>, CursorStoreError> {
        let object_ids =
            Self::block_on_store(async { Ok(self.object_store.list_zone(&self.zone_id).await) })?;

        let mut best: Option<(ObjectId, ConnectorStateObject)> = None;

        for object_id in object_ids {
            let stored = match Self::block_on_store(self.object_store.get(&object_id)) {
                Ok(obj) => obj,
                Err(err) => {
                    tracing::warn!(error = %err, object_id = %object_id, "Failed to load state object");
                    continue;
                }
            };

            if stored.header.schema != Self::schema_id() {
                continue;
            }

            let state = match Self::decode_state_object(&stored) {
                Ok(state) => state,
                Err(err) => {
                    tracing::warn!(error = %err, object_id = %object_id, "Failed to decode state object");
                    continue;
                }
            };

            if state.connector_id != self.connector_id || state.zone_id != self.zone_id {
                continue;
            }

            let replace = match &best {
                None => true,
                Some((_id, current)) => {
                    state.seq > current.seq
                        || (state.seq == current.seq && state.lease_seq > current.lease_seq)
                }
            };

            if replace {
                best = Some((object_id, state));
            }
        }

        Ok(best)
    }

    fn store_state_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId, CursorStoreError> {
        if state_obj.connector_id != self.connector_id || state_obj.zone_id != self.zone_id {
            return Err(CursorStoreError::Storage(
                "connector_id/zone_id mismatch in state object".into(),
            ));
        }

        if state_obj.header.schema != Self::schema_id() {
            return Err(CursorStoreError::Storage(
                "unexpected schema for connector state object".into(),
            ));
        }

        let body = CanonicalSerializer::serialize(&state_obj, &state_obj.header.schema)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;
        let object_id = StoredObject::derive_id(&state_obj.header, &body, &self.object_id_key)
            .map_err(|err| CursorStoreError::CursorEncoding(err.to_string()))?;

        let header = state_obj.header;
        let stored = StoredObject {
            object_id,
            header,
            body,
            storage: StorageMeta {
                retention: self.retention,
            },
        };

        Self::block_on_store(self.object_store.put(stored))?;
        Ok(object_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Health State Machine
// ─────────────────────────────────────────────────────────────────────────────

/// Valid health state transitions.
///
/// The health state machine enforces these transition rules:
/// - `Starting` → `Healthy` (on successful initialization)
/// - `Starting` → `Unhealthy` (on initialization failure)
/// - `Healthy` → `Degraded` (on recoverable failures)
/// - `Healthy` → `Unhealthy` (on unrecoverable failures)
/// - `Degraded` → `Healthy` (on recovery)
/// - `Degraded` → `Unhealthy` (on continued failures)
/// - `Unhealthy` → `Healthy` (on recovery after cooldown)
/// - `Unhealthy` → `Degraded` (on partial recovery)
#[derive(Debug, Clone)]
pub enum HealthTransition {
    /// Transition to healthy state (successful operation).
    ToHealthy,
    /// Transition to degraded state (recoverable issue).
    ToDegraded {
        /// Reason for degradation.
        reason: String,
    },
    /// Transition to unhealthy/error state (unrecoverable issue).
    ToUnhealthy {
        /// Reason for error.
        reason: String,
    },
    /// Transition to starting state (reset).
    ToStarting,
}

/// Tracks connector health with explicit transition rules.
///
/// The tracker maintains:
/// - Current health state
/// - Consecutive failure count
/// - Timestamps for state changes
/// - Snapshot generation
#[derive(Debug)]
pub struct HealthTracker {
    state: HealthState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure_reason: Option<String>,
    started_at: Instant,
    last_state_change: Instant,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

impl HealthTracker {
    /// Create a new health tracker in the `Starting` state.
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: HealthState::Starting,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure_reason: None,
            started_at: now,
            last_state_change: now,
            last_success: None,
            last_failure: None,
        }
    }

    /// Get the current health state.
    #[must_use]
    pub const fn state(&self) -> &HealthState {
        &self.state
    }

    /// Check if currently healthy (Ready state).
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self.state, HealthState::Ready)
    }

    /// Check if currently degraded.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self.state, HealthState::Degraded { .. })
    }

    /// Check if currently unhealthy (Error state).
    #[must_use]
    pub const fn is_unhealthy(&self) -> bool {
        matches!(self.state, HealthState::Error { .. })
    }

    /// Get consecutive failure count.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Get consecutive success count.
    #[must_use]
    pub const fn consecutive_successes(&self) -> u32 {
        self.consecutive_successes
    }

    /// Record a successful operation.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        self.last_success = Some(Instant::now());
    }

    /// Record a failed operation.
    pub fn record_failure(&mut self, reason: &str) {
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure = Some(Instant::now());
        self.last_failure_reason = Some(reason.to_string());
    }

    /// Apply a health state transition.
    ///
    /// Returns `true` if the transition was valid and applied.
    pub fn transition(&mut self, transition: HealthTransition) -> bool {
        let valid = self.is_valid_transition(&transition);
        if valid {
            self.apply_transition(transition);
        }
        valid
    }

    /// Check if a transition is valid from the current state.
    ///
    /// Valid transitions:
    /// - `Starting` can transition to any state
    /// - Any state can transition to `Starting` (reset), except `Stopping`
    /// - `Ready` can transition to `Degraded` or `Error`
    /// - `Degraded` can transition to `Ready` or `Error`
    /// - `Error` can transition to `Ready` or `Degraded`
    /// - `Stopping` is terminal (no transitions allowed)
    #[must_use]
    #[allow(clippy::match_same_arms)] // Keep separate arms for documentation clarity
    pub const fn is_valid_transition(&self, transition: &HealthTransition) -> bool {
        match (&self.state, transition) {
            // Stopping is terminal - no transitions allowed
            (HealthState::Stopping, _) => false,
            // Starting can go anywhere
            (HealthState::Starting, _) => true,
            // Restart is always valid (except from Stopping, handled above)
            (_, HealthTransition::ToStarting) => true,
            // Ready can degrade or fail
            (
                HealthState::Ready,
                HealthTransition::ToDegraded { .. } | HealthTransition::ToUnhealthy { .. },
            ) => true,
            // Degraded can recover or fail
            (
                HealthState::Degraded { .. },
                HealthTransition::ToHealthy | HealthTransition::ToUnhealthy { .. },
            ) => true,
            // Error can recover (partially or fully)
            (
                HealthState::Error { .. },
                HealthTransition::ToHealthy | HealthTransition::ToDegraded { .. },
            ) => true,
            _ => false,
        }
    }

    fn apply_transition(&mut self, transition: HealthTransition) {
        self.last_state_change = Instant::now();
        match transition {
            HealthTransition::ToHealthy => {
                self.state = HealthState::Ready;
                self.consecutive_failures = 0;
            }
            HealthTransition::ToDegraded { reason } => {
                self.state = HealthState::Degraded { reason };
            }
            HealthTransition::ToUnhealthy { reason } => {
                self.state = HealthState::Error { reason };
            }
            HealthTransition::ToStarting => {
                self.state = HealthState::Starting;
                self.consecutive_failures = 0;
                self.consecutive_successes = 0;
            }
        }
    }

    /// Generate a health snapshot for the current state.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn snapshot(&self) -> HealthSnapshot {
        let uptime_ms = self.started_at.elapsed().as_millis() as u64;

        // Compute load as a proxy from failure rate (max 10 failures = 1.0 load)
        let load = if self.consecutive_failures > 0 {
            #[allow(clippy::cast_precision_loss)]
            let failure_ratio = self.consecutive_failures.min(10) as f32 / 10.0;
            Some(failure_ratio.min(1.0))
        } else {
            Some(0.0)
        };

        // Include failure reason in details if present
        let details = self.last_failure_reason.as_ref().map(|reason| {
            serde_json::json!({
                "last_error": reason,
                "consecutive_failures": self.consecutive_failures,
            })
        });

        HealthSnapshot {
            status: self.state.clone(),
            uptime_ms,
            load,
            details,
            rate_limit: None,
        }
    }

    /// Check if enough time has passed in unhealthy state for cooldown.
    #[must_use]
    pub fn cooldown_elapsed(&self, cooldown: Duration) -> bool {
        if !self.is_unhealthy() {
            return true;
        }
        self.last_state_change.elapsed() >= cooldown
    }

    /// Evaluate health based on config thresholds and auto-transition.
    ///
    /// Call this after `record_success` or `record_failure` to automatically
    /// transition between states based on configured thresholds.
    pub fn evaluate(&mut self, config: &SupervisorConfig) {
        match &self.state {
            HealthState::Starting => {
                // Auto-transition to Ready after first success
                if self.consecutive_successes > 0 {
                    self.transition(HealthTransition::ToHealthy);
                } else if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "initialization failed".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                }
            }
            HealthState::Ready => {
                // Degrade after some failures, fail after max
                if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "too many failures".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                } else if self.consecutive_failures > 0 {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "recoverable error".to_string());
                    self.transition(HealthTransition::ToDegraded { reason });
                }
            }
            HealthState::Degraded { .. } => {
                // Recover after some successes, fail after max failures
                if self.consecutive_failures >= config.max_consecutive_failures {
                    let reason = self
                        .last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "too many failures".to_string());
                    self.transition(HealthTransition::ToUnhealthy { reason });
                } else if self.consecutive_successes >= 3 {
                    // Require 3 consecutive successes to recover
                    self.transition(HealthTransition::ToHealthy);
                }
            }
            HealthState::Error { .. } => {
                // Recover only after cooldown and successes
                if self.cooldown_elapsed(config.cooldown_duration())
                    && self.consecutive_successes > 0
                {
                    self.transition(HealthTransition::ToHealthy);
                }
            }
            HealthState::Stopping => {
                // No auto-transitions from Stopping - it's terminal
            }
        }
    }
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PollingSupervisor
// ─────────────────────────────────────────────────────────────────────────────

/// Result from a single poll operation.
#[derive(Debug)]
pub enum PollResult<T> {
    /// Poll succeeded with optional data (empty if no updates).
    Success(Vec<T>),
    /// Poll failed with a recoverable error (will retry with backoff).
    RecoverableError {
        /// Error message.
        message: String,
        /// Optional retry-after hint from rate limiting (milliseconds).
        retry_after_ms: Option<u64>,
    },
    /// Poll failed with an unrecoverable error (will stop supervisor).
    FatalError {
        /// Error message.
        message: String,
    },
}

impl<T> PollResult<T> {
    /// Create a success result with items.
    #[must_use]
    pub const fn success(items: Vec<T>) -> Self {
        Self::Success(items)
    }

    /// Create an empty success result.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Success(Vec::new())
    }

    /// Create a recoverable error.
    pub fn recoverable(message: impl Into<String>) -> Self {
        Self::RecoverableError {
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Create a recoverable error with retry-after hint.
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self::RecoverableError {
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    /// Create a fatal error.
    pub fn fatal(message: impl Into<String>) -> Self {
        Self::FatalError {
            message: message.into(),
        }
    }
}

/// Outcome from running the polling supervisor.
#[derive(Debug, Clone)]
pub enum SupervisorOutcome {
    /// Supervisor stopped gracefully via shutdown signal.
    Shutdown,
    /// Supervisor stopped due to fatal error.
    FatalError {
        /// Error message.
        message: String,
    },
    /// Supervisor stopped due to too many consecutive failures.
    MaxFailuresReached {
        /// Number of consecutive failures.
        failures: u32,
    },
}

/// Statistics from a polling supervisor run.
#[derive(Debug, Clone, Default)]
pub struct PollingSupervisorStats {
    /// Total number of poll attempts.
    pub total_polls: u64,
    /// Number of successful polls.
    pub successful_polls: u64,
    /// Number of failed polls (recoverable).
    pub failed_polls: u64,
    /// Total items processed.
    pub items_processed: u64,
    /// Total time spent in backoff (milliseconds).
    pub backoff_time_ms: u64,
}

/// Supervised polling loop with backoff, health tracking, and cursor management.
///
/// The supervisor provides:
/// - Configurable poll interval with long-poll support
/// - Exponential backoff on recoverable errors
/// - Rate-limit aware backoff (respects Retry-After hints)
/// - Health state transitions based on success/failure patterns
/// - Cursor persistence hooks for exactly-once semantics
///
/// # Example
///
/// ```ignore
/// use fcp_sdk::runtime::{PollingSupervisor, PollResult, SupervisorConfig, InMemoryPollingCursor};
/// use tokio::sync::watch;
///
/// let config = SupervisorConfig::default();
/// let cursor = InMemoryPollingCursor::new();
/// let (shutdown_tx, shutdown_rx) = watch::channel(false);
///
/// let supervisor = PollingSupervisor::new(config, cursor);
/// let outcome = supervisor.run(
///     shutdown_rx,
///     1000, // poll interval ms
///     |offset| async move {
///         // Your poll logic here
///         PollResult::success(vec![item1, item2])
///     },
///     |items, cursor| {
///         // Process items, update cursor
///         for item in items {
///             cursor.advance_if_newer(item.id);
///         }
///         Ok(())
///     },
/// ).await;
/// ```
#[derive(Debug)]
pub struct PollingSupervisor<C: PollingCursor> {
    config: SupervisorConfig,
    cursor: C,
    health: HealthTracker,
    stats: PollingSupervisorStats,
}

impl<C: PollingCursor> PollingSupervisor<C> {
    /// Create a new polling supervisor.
    pub fn new(config: SupervisorConfig, cursor: C) -> Self {
        Self {
            config,
            cursor,
            health: HealthTracker::new(),
            stats: PollingSupervisorStats::default(),
        }
    }

    /// Get the current cursor.
    pub const fn cursor(&self) -> &C {
        &self.cursor
    }

    /// Get mutable access to the cursor.
    pub const fn cursor_mut(&mut self) -> &mut C {
        &mut self.cursor
    }

    /// Get the current health tracker.
    pub const fn health(&self) -> &HealthTracker {
        &self.health
    }

    /// Get the current statistics.
    pub const fn stats(&self) -> &PollingSupervisorStats {
        &self.stats
    }

    /// Get the supervisor configuration.
    pub const fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    /// Compute the next backoff delay, respecting rate-limit hints.
    ///
    /// If `retry_after_ms` is provided and greater than the computed backoff,
    /// it takes precedence.
    fn compute_delay(&self, attempt: u32, retry_after_ms: Option<u64>) -> Duration {
        // Generate a simple jitter factor based on attempt count
        // In production, you'd want to use a proper RNG
        let jitter = (f64::from(attempt) * 0.1).fract();
        let backoff = self.config.compute_backoff_with_jitter(attempt, jitter);

        // Respect rate-limit Retry-After if present and larger
        let delay_ms = match retry_after_ms {
            Some(retry_after) if retry_after > backoff => retry_after,
            _ => backoff,
        };

        Duration::from_millis(delay_ms)
    }

    /// Run the polling supervisor loop.
    ///
    /// # Arguments
    ///
    /// * `shutdown` - Watch channel receiver that signals shutdown when `true`
    /// * `poll_interval_ms` - Interval between polls when no backoff is active
    /// * `poll_fn` - Async function that performs the actual poll
    /// * `process_fn` - Function that processes poll results and updates cursor
    ///
    /// # Type Parameters
    ///
    /// * `T` - Type of items returned by the poll
    /// * `F` - Poll function type
    /// * `Fut` - Future type returned by poll function
    /// * `P` - Process function type
    ///
    /// # Returns
    ///
    /// Returns the outcome of the supervisor run.
    #[allow(clippy::too_many_lines)]
    pub async fn run<T, F, Fut, P>(
        &mut self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
        poll_interval_ms: u64,
        poll_fn: F,
        mut process_fn: P,
    ) -> SupervisorOutcome
    where
        F: Fn(Option<i64>) -> Fut,
        Fut: std::future::Future<Output = PollResult<T>>,
        P: FnMut(Vec<T>, &mut C) -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    {
        let poll_interval = Duration::from_millis(poll_interval_ms);
        let mut consecutive_failures: u32 = 0;

        // Restore cursor state if available
        if let Err(e) = self.cursor.restore() {
            tracing::warn!(error = %e, "Failed to restore cursor state, starting fresh");
        }

        // Transition to healthy on start
        self.health.record_success();
        self.health.evaluate(&self.config);

        loop {
            // Check for shutdown signal
            if *shutdown.borrow() {
                tracing::info!("Polling supervisor received shutdown signal");
                // Persist cursor before shutdown
                if let Err(e) = self.cursor.persist() {
                    tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                }
                return SupervisorOutcome::Shutdown;
            }

            // Execute poll
            self.stats.total_polls += 1;
            let offset = self.cursor.offset();
            let poll_start = Instant::now();

            tracing::debug!(offset = ?offset, "Starting poll");

            let result = poll_fn(offset).await;
            self.cursor.record_poll(Instant::now(), 0);

            match result {
                PollResult::Success(items) => {
                    let item_count = items.len();
                    self.stats.successful_polls += 1;
                    self.stats.items_processed += item_count as u64;
                    consecutive_failures = 0;

                    // Record success for health tracking
                    self.health.record_success();
                    self.health.evaluate(&self.config);

                    // Process items
                    if !items.is_empty() {
                        if let Err(e) = process_fn(items, &mut self.cursor) {
                            tracing::error!(error = %e, "Failed to process poll results");
                            // Don't fail the supervisor for processing errors
                        }

                        // Persist cursor after successful processing
                        if let Err(e) = self.cursor.persist() {
                            tracing::warn!(error = %e, "Failed to persist cursor");
                        }
                    }

                    tracing::debug!(
                        items = item_count,
                        elapsed_ms = poll_start.elapsed().as_millis(),
                        "Poll completed successfully"
                    );

                    // Wait for poll interval, checking for shutdown
                    tokio::select! {
                        () = tokio::time::sleep(poll_interval) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                if let Err(e) = self.cursor.persist() {
                                    tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                                }
                                return SupervisorOutcome::Shutdown;
                            }
                        }
                    }
                }

                PollResult::RecoverableError {
                    message,
                    retry_after_ms,
                } => {
                    self.stats.failed_polls += 1;
                    consecutive_failures = consecutive_failures.saturating_add(1);

                    // Record failure for health tracking
                    self.health.record_failure(&message);
                    self.health.evaluate(&self.config);

                    tracing::warn!(
                        error = %message,
                        consecutive_failures,
                        retry_after_ms = ?retry_after_ms,
                        "Poll failed with recoverable error"
                    );

                    // Check if we've exceeded max failures
                    if consecutive_failures >= self.config.max_consecutive_failures {
                        tracing::error!(
                            failures = consecutive_failures,
                            max = self.config.max_consecutive_failures,
                            "Maximum consecutive failures reached"
                        );
                        if let Err(e) = self.cursor.persist() {
                            tracing::error!(error = %e, "Failed to persist cursor");
                        }
                        return SupervisorOutcome::MaxFailuresReached {
                            failures: consecutive_failures,
                        };
                    }

                    // Compute backoff delay
                    let delay = self.compute_delay(consecutive_failures - 1, retry_after_ms);
                    self.stats.backoff_time_ms +=
                        u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);

                    tracing::info!(
                        delay_ms = delay.as_millis(),
                        attempt = consecutive_failures,
                        "Backing off before retry"
                    );

                    // Wait for backoff, checking for shutdown
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                if let Err(e) = self.cursor.persist() {
                                    tracing::error!(error = %e, "Failed to persist cursor on shutdown");
                                }
                                return SupervisorOutcome::Shutdown;
                            }
                        }
                    }
                }

                PollResult::FatalError { message } => {
                    tracing::error!(error = %message, "Poll failed with fatal error");
                    self.health.transition(HealthTransition::ToUnhealthy {
                        reason: message.clone(),
                    });
                    if let Err(e) = self.cursor.persist() {
                        tracing::error!(error = %e, "Failed to persist cursor");
                    }
                    return SupervisorOutcome::FatalError { message };
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_config_defaults() {
        let config = SupervisorConfig::default();
        assert_eq!(config.base_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 60_000);
        assert!(config.jitter_enabled);
        assert_eq!(config.max_consecutive_failures, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn supervisor_config_validation() {
        let config = SupervisorConfig {
            base_backoff_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = SupervisorConfig {
            max_backoff_ms: 500, // Less than base
            base_backoff_ms: 1000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn backoff_exponential() {
        let config = SupervisorConfig::default().with_jitter(false);
        assert_eq!(config.compute_backoff(0), 1000);
        assert_eq!(config.compute_backoff(1), 2000);
        assert_eq!(config.compute_backoff(2), 4000);
        assert_eq!(config.compute_backoff(3), 8000);
        // Should cap at max
        assert_eq!(config.compute_backoff(10), 60_000);
    }

    #[test]
    fn backoff_with_jitter() {
        let config = SupervisorConfig::default();
        let delay0 = config.compute_backoff_with_jitter(0, 0.0); // Min jitter
        let delay1 = config.compute_backoff_with_jitter(0, 1.0); // Max jitter
        assert!((500..=1000).contains(&delay0));
        assert!((500..=1000).contains(&delay1));
    }

    #[test]
    fn streaming_session_in_memory() {
        let mut session = InMemoryStreamingSession::new();
        assert!(session.resume_token().is_none());
        assert_eq!(session.sequence(), 0);

        session.set_resume_token("token123".to_string());
        assert_eq!(session.resume_token(), Some("token123".to_string()));

        let seq = session.next_sequence();
        assert_eq!(seq, 0);
        assert_eq!(session.sequence(), 1);

        session.clear_resume_token();
        assert!(session.resume_token().is_none());
    }

    #[test]
    fn polling_cursor_advance() {
        let mut cursor = InMemoryPollingCursor::new();
        assert!(cursor.offset().is_none());

        cursor.advance_if_newer(100);
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(50); // Older, should not change
        assert_eq!(cursor.offset(), Some(101));

        cursor.advance_if_newer(200);
        assert_eq!(cursor.offset(), Some(201));
    }

    #[test]
    fn health_tracker_transitions() {
        let mut tracker = HealthTracker::new();
        assert!(matches!(tracker.state(), HealthState::Starting));

        // Starting -> Ready
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Degraded
        tracker.record_failure("timeout");
        tracker.transition(HealthTransition::ToDegraded {
            reason: "timeout".to_string(),
        });
        assert!(tracker.is_degraded());

        // Degraded -> Healthy
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Unhealthy
        tracker.transition(HealthTransition::ToUnhealthy {
            reason: "fatal".to_string(),
        });
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_tracker_auto_evaluate() {
        let config = SupervisorConfig::default().with_max_consecutive_failures(3);
        let mut tracker = HealthTracker::new();

        // Starting -> Ready after first success
        tracker.record_success();
        tracker.evaluate(&config);
        assert!(tracker.is_healthy());

        // Ready -> Degraded after 1 failure
        tracker.record_failure("err1");
        tracker.evaluate(&config);
        assert!(tracker.is_degraded());

        // Degraded -> Unhealthy after 3 failures
        tracker.record_failure("err2");
        tracker.record_failure("err3");
        tracker.evaluate(&config);
        assert!(tracker.is_unhealthy());
    }

    #[test]
    fn health_snapshot_generation() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);

        let snapshot = tracker.snapshot();
        assert!(matches!(snapshot.status, HealthState::Ready));
        // uptime_ms is always >= 0 for u64, so just verify it exists
        let _ = snapshot.uptime_ms;
        assert_eq!(snapshot.load, Some(0.0));
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut tracker = HealthTracker::new();
        tracker.record_success();
        tracker.transition(HealthTransition::ToHealthy);
        assert!(tracker.is_healthy());

        // Ready -> Healthy is invalid (already healthy)
        assert!(!tracker.transition(HealthTransition::ToHealthy));

        // Ready -> Starting is always valid (reset)
        assert!(tracker.transition(HealthTransition::ToStarting));
        assert!(matches!(tracker.state(), HealthState::Starting));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PollingSupervisor tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn poll_result_constructors() {
        let success: PollResult<i32> = PollResult::success(vec![1, 2, 3]);
        assert!(matches!(success, PollResult::Success(items) if items.len() == 3));

        let empty: PollResult<i32> = PollResult::empty();
        assert!(matches!(empty, PollResult::Success(items) if items.is_empty()));

        let recoverable: PollResult<i32> = PollResult::recoverable("timeout");
        assert!(matches!(
            recoverable,
            PollResult::RecoverableError {
                retry_after_ms: None,
                ..
            }
        ));

        let rate_limited: PollResult<i32> = PollResult::rate_limited("too fast", 5000);
        assert!(matches!(
            rate_limited,
            PollResult::RecoverableError {
                retry_after_ms: Some(5000),
                ..
            }
        ));

        let fatal: PollResult<i32> = PollResult::fatal("auth failed");
        assert!(matches!(fatal, PollResult::FatalError { .. }));
    }

    #[test]
    fn polling_supervisor_creation() {
        let config = SupervisorConfig::default();
        let cursor = InMemoryPollingCursor::new();
        let supervisor = PollingSupervisor::new(config.clone(), cursor);

        assert!(supervisor.cursor().offset().is_none());
        assert!(matches!(supervisor.health().state(), HealthState::Starting));
        assert_eq!(supervisor.stats().total_polls, 0);
        assert_eq!(supervisor.config().base_backoff_ms, config.base_backoff_ms);
    }

    #[test]
    fn polling_supervisor_compute_delay_respects_retry_after() {
        let config = SupervisorConfig::default().with_jitter(false);
        let cursor = InMemoryPollingCursor::new();
        let supervisor = PollingSupervisor::new(config, cursor);

        // Without retry-after, uses exponential backoff
        let delay = supervisor.compute_delay(0, None);
        assert_eq!(delay.as_millis(), 1000);

        // With smaller retry-after, uses backoff
        let delay = supervisor.compute_delay(0, Some(500));
        assert_eq!(delay.as_millis(), 1000);

        // With larger retry-after, uses retry-after
        let delay = supervisor.compute_delay(0, Some(10_000));
        assert_eq!(delay.as_millis(), 10_000);
    }

    #[test]
    fn polling_supervisor_stats_default() {
        let stats = PollingSupervisorStats::default();
        assert_eq!(stats.total_polls, 0);
        assert_eq!(stats.successful_polls, 0);
        assert_eq!(stats.failed_polls, 0);
        assert_eq!(stats.items_processed, 0);
        assert_eq!(stats.backoff_time_ms, 0);
    }

    #[tokio::test]
    async fn polling_supervisor_shutdown_signal() {
        let config = SupervisorConfig::default();
        let cursor = InMemoryPollingCursor::new();
        let mut supervisor = PollingSupervisor::new(config, cursor);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(true); // Start with shutdown
        let _ = shutdown_tx; // Keep sender alive

        let outcome = supervisor
            .run(
                shutdown_rx,
                1000,
                |_offset| async { PollResult::<i32>::empty() },
                |_items, _cursor| Ok(()),
            )
            .await;

        assert!(matches!(outcome, SupervisorOutcome::Shutdown));
    }

    #[tokio::test]
    async fn polling_supervisor_fatal_error_stops() {
        let config = SupervisorConfig::default();
        let cursor = InMemoryPollingCursor::new();
        let mut supervisor = PollingSupervisor::new(config, cursor);

        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let outcome = supervisor
            .run(
                shutdown_rx,
                1000,
                |_offset| async { PollResult::<i32>::fatal("auth failed") },
                |_items, _cursor| Ok(()),
            )
            .await;

        assert!(matches!(
            outcome,
            SupervisorOutcome::FatalError { message } if message == "auth failed"
        ));
        assert_eq!(supervisor.stats().total_polls, 1);
        assert_eq!(supervisor.stats().failed_polls, 0); // Fatal errors don't increment failed_polls
    }

    #[tokio::test]
    async fn polling_supervisor_max_failures() {
        let config = SupervisorConfig::default()
            .with_max_consecutive_failures(2)
            .with_base_backoff_ms(1); // Fast backoff for testing
        let cursor = InMemoryPollingCursor::new();
        let mut supervisor = PollingSupervisor::new(config, cursor);

        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let outcome = supervisor
            .run(
                shutdown_rx,
                1,
                |_offset| async { PollResult::<i32>::recoverable("timeout") },
                |_items, _cursor| Ok(()),
            )
            .await;

        assert!(matches!(
            outcome,
            SupervisorOutcome::MaxFailuresReached { failures: 2 }
        ));
        assert_eq!(supervisor.stats().failed_polls, 2);
    }
}
