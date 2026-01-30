//! Connector state management for mesh-persisted state objects (NORMATIVE).
//!
//! Based on FCP Specification V2 §10 and docs §2.2.
//!
//! # Overview
//!
//! Implements the connector state model so polling/cursors/dedup are safe under
//! failover and migration. Authoritative state lives in mesh objects; local
//! `$CONNECTOR_STATE` is a cache only.
//!
//! # State Models
//!
//! - **Stateless**: No mesh-persisted state required
//! - **`SingletonWriter`**: Exactly one writer enforced via Lease
//! - **Crdt**: Multi-writer state using CRDT deltas + periodic snapshots
//!
//! # Key Invariants
//!
//! - State writes for `SingletonWriter` MUST be fenced by a Lease with
//!   `LeasePurpose::ConnectorStateWrite`
//! - Fork detection MUST pause connector execution and require resolution
//! - Snapshots enable compaction of older state objects

use fcp_cbor::{SerializationError, to_canonical_cbor};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{ConnectorId, InstanceId, ObjectHeader, ObjectId, TailscaleNodeId, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// Signature Type
// ─────────────────────────────────────────────────────────────────────────────

/// Ed25519 signature (64 bytes) (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 64]);

impl Signature {
    /// Create a signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Create a zero signature (for testing).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature")
            .field(&format!("{}...", &hex::encode(&self.0[..8])))
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}...", &hex::encode(&self.0[..8]))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::zero()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Types (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// CRDT type discriminant (NORMATIVE).
///
/// Defines the merge semantics for multi-writer connector state.
/// The actual CRDT implementations are in the `crate::crdt` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrdtType {
    /// Last-write-wins map (key-value with timestamps).
    ///
    /// Merge: Take entry with latest timestamp per key.
    /// Implementation: `crate::LwwMap`
    LwwMap,

    /// Observed-remove set (add/remove operations).
    ///
    /// Merge: Via observed-remove set algebra.
    /// Implementation: `crate::OrSet`
    OrSet,

    /// Grow-only counter (only increments).
    ///
    /// Merge: Take max per actor.
    /// Implementation: `crate::GCounter`
    GCounter,

    /// Positive-negative counter (increments and decrements).
    ///
    /// Merge: Merge positive and negative counters separately.
    /// Implementation: `crate::PnCounter`
    PnCounter,
}

impl CrdtType {
    /// Get the human-readable name for this CRDT type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LwwMap => "lww_map",
            Self::OrSet => "or_set",
            Self::GCounter => "g_counter",
            Self::PnCounter => "pn_counter",
        }
    }
}

impl fmt::Display for CrdtType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Model (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Connector state model discriminant (NORMATIVE).
///
/// Defines how connector state is persisted and synchronized in the mesh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectorStateModel {
    /// No mesh-persisted state required.
    ///
    /// The connector maintains no durable state across restarts.
    #[default]
    Stateless,

    /// Exactly one writer enforced via Lease (`ConnectorStateWrite` purpose).
    ///
    /// - State writes MUST be fenced by a Lease
    /// - Higher `lease_seq` wins deterministically
    /// - Fork detection triggers safety incident
    SingletonWriter,

    /// Multi-writer state using CRDT deltas + periodic snapshots.
    ///
    /// - Multiple nodes can write concurrently
    /// - Deltas are merged according to `crdt_type` semantics
    /// - Snapshots compact the delta chain
    Crdt {
        /// The CRDT type determining merge semantics.
        crdt_type: CrdtType,
    },
}

impl ConnectorStateModel {
    /// Check if this model is stateless.
    #[must_use]
    pub const fn is_stateless(&self) -> bool {
        matches!(self, Self::Stateless)
    }

    /// Check if this model requires singleton writer semantics.
    #[must_use]
    pub const fn is_singleton_writer(&self) -> bool {
        matches!(self, Self::SingletonWriter)
    }

    /// Check if this model uses CRDT semantics.
    #[must_use]
    pub const fn is_crdt(&self) -> bool {
        matches!(self, Self::Crdt { .. })
    }

    /// Get the CRDT type if this is a CRDT model.
    #[must_use]
    pub const fn crdt_type(&self) -> Option<CrdtType> {
        match self {
            Self::Crdt { crdt_type } => Some(*crdt_type),
            _ => None,
        }
    }
}

impl fmt::Display for ConnectorStateModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stateless => write!(f, "stateless"),
            Self::SingletonWriter => write!(f, "singleton_writer"),
            Self::Crdt { crdt_type } => write!(f, "crdt({crdt_type})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Root (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Root object for connector state (NORMATIVE).
///
/// This object defines the state model and points to the current head of the
/// state chain. It is the entry point for state resolution during failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateRoot {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier (for multi-instance connectors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// State model governing this connector's state.
    pub model: ConnectorStateModel,

    /// Latest `ConnectorStateObject` (or `None` if no state yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<ObjectId>,

    /// Schema version for safe upgrades (NORMATIVE).
    #[serde(default = "default_schema_version")]
    pub state_schema_version: u32,
}

const fn default_schema_version() -> u32 {
    1
}

impl ConnectorStateRoot {
    /// Create a new state root for a stateless connector.
    #[must_use]
    pub const fn stateless(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::Stateless,
            head: None,
            state_schema_version: 1,
        }
    }

    /// Create a new state root for a singleton-writer connector.
    #[must_use]
    pub const fn singleton_writer(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::SingletonWriter,
            head: None,
            state_schema_version: 1,
        }
    }

    /// Create a new state root for a CRDT connector.
    #[must_use]
    pub const fn crdt(
        header: ObjectHeader,
        connector_id: ConnectorId,
        zone_id: ZoneId,
        crdt_type: CrdtType,
    ) -> Self {
        Self {
            header,
            connector_id,
            instance_id: None,
            zone_id,
            model: ConnectorStateModel::Crdt { crdt_type },
            head: None,
            state_schema_version: 1,
        }
    }

    /// Set the instance ID.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Set the head object ID.
    #[must_use]
    pub const fn with_head(mut self, head: ObjectId) -> Self {
        self.head = Some(head);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Object (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// State object in the state chain (NORMATIVE).
///
/// For `SingletonWriter` connectors, each state object represents an atomic
/// state transition. The chain is linked via `prev` references.
///
/// # Singleton Writer Fencing
///
/// For `SingletonWriter` model:
/// - `lease_seq` MUST be included (fencing token)
/// - `lease_object_id` MUST reference the authorizing Lease
/// - Verifiers MUST reject updates with stale `lease_seq`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateObject {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// Previous state object in the chain (`None` for genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,

    /// Monotonic sequence number.
    ///
    /// MUST increase for each state object. Used for ordering and fork detection.
    pub seq: u64,

    /// Canonical state blob (CBOR-encoded).
    ///
    /// The structure depends on the connector's state schema.
    pub state_cbor: Vec<u8>,

    /// Timestamp when this state was created (UNIX seconds).
    pub updated_at: u64,

    /// Fencing token (NORMATIVE for `SingletonWriter`).
    ///
    /// The `lease_seq` from the authorizing Lease. Verifiers MUST reject
    /// updates with stale fencing tokens.
    pub lease_seq: u64,

    /// The Lease object granting write authority (NORMATIVE for `SingletonWriter`).
    ///
    /// This MUST be included in `header.refs` for reference tracking.
    pub lease_object_id: ObjectId,

    /// Ed25519 signature over the canonical state object.
    pub signature: Signature,
}

impl ConnectorStateObject {
    /// Check if this is a genesis state object.
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.prev.is_none()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Delta (NORMATIVE for CRDT models)
// ─────────────────────────────────────────────────────────────────────────────

/// Delta object for CRDT state models (NORMATIVE).
///
/// For `Crdt` connectors, deltas represent incremental changes that can be
/// merged according to CRDT semantics. Periodic snapshots compact the delta chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateDelta {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// CRDT type for this delta.
    pub crdt_type: CrdtType,

    /// Delta payload (CBOR-encoded).
    ///
    /// The structure depends on `crdt_type`:
    /// - `LwwMap`: `[(key, value, timestamp, actor)]`
    /// - `OrSet`: `[(element, add/remove, unique_tag)]`
    /// - `GCounter`: `[(actor_id, count)]`
    /// - `PnCounter`: `[(actor_id, pos_count, neg_count)]`
    pub delta_cbor: Vec<u8>,

    /// Timestamp when this delta was applied (UNIX seconds).
    pub applied_at: u64,

    /// Node that produced this delta.
    pub applied_by: TailscaleNodeId,

    /// Ed25519 signature over the canonical delta.
    pub signature: Signature,
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector State Snapshot (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot for state compaction (NORMATIVE).
///
/// Snapshots capture the full state at a point in time, enabling:
/// - Efficient state recovery without replaying entire chain
/// - Garbage collection of older state objects/deltas
/// - Bounded storage consumption
///
/// # Compaction Rules
///
/// - `MeshNode` SHOULD create a snapshot every N updates or M bytes
/// - After snapshot is replicated, older objects MAY be GC'd
/// - Audit/policy pins may preserve older objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStateSnapshot {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Optional instance identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,

    /// Zone in which this state resides.
    pub zone_id: ZoneId,

    /// Latest state object included in this snapshot.
    pub covers_head: ObjectId,

    /// Sequence number of the covered head.
    pub covers_seq: u64,

    /// Full canonical state at `covers_head` (CBOR-encoded).
    pub state_cbor: Vec<u8>,

    /// Timestamp when this snapshot was created (UNIX seconds).
    pub snapshotted_at: u64,

    /// Ed25519 signature over the canonical snapshot.
    pub signature: Signature,
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor State Schema (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical cursor state payload for polling connectors (NORMATIVE).
///
/// This struct defines the canonical schema stored inside
/// [`ConnectorStateObject::state_cbor`] for cursor/offset-based polling.
///
/// # Monotonicity Rules
/// - `offset` MUST be monotonic (non-decreasing).
/// - `watermark` MUST be monotonic if used (typically a Unix timestamp).
/// - `last_seen_id` SHOULD only advance forward (connector-specific ordering).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorState {
    /// Numeric offset (e.g., `update_id` + 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,

    /// Last seen identifier (e.g., message id, history id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_id: Option<String>,

    /// Watermark timestamp (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<u64>,
}

impl CursorState {
    /// Encode this cursor state as canonical CBOR (no schema hash prefix).
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if canonical CBOR encoding fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, SerializationError> {
        to_canonical_cbor(self)
    }

    /// Decode cursor state from canonical CBOR.
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if decoding fails, if trailing bytes are
    /// present, or if the encoding is not canonical.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, SerializationError> {
        let mut reader = bytes;
        let decoded: Self = ciborium::de::from_reader(&mut reader)?;
        if !reader.is_empty() {
            return Err(SerializationError::TrailingBytes);
        }

        let canonical = to_canonical_cbor(&decoded)?;
        if canonical != bytes {
            return Err(SerializationError::NonCanonicalEncoding);
        }

        Ok(decoded)
    }
}

/// Decode a cursor state from a connector state object.
///
/// # Errors
/// Returns a [`SerializationError`] if the embedded `state_cbor` is invalid.
pub fn cursor_state_from_object(
    state_obj: &ConnectorStateObject,
) -> Result<CursorState, SerializationError> {
    CursorState::from_cbor(&state_obj.state_cbor)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection (NORMATIVE for SingletonWriter)
// ─────────────────────────────────────────────────────────────────────────────

/// Fork event indicating competing writes (NORMATIVE).
///
/// A fork occurs when two different `ConnectorStateObject` share the same `prev`
/// (competing sequence numbers). This indicates a lease violation or bug.
///
/// # Recovery Protocol
///
/// 1. Pause connector execution immediately
/// 2. Log the fork event for audit
/// 3. Require manual resolution OR automated "choose-by-lease" recovery
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkEvent {
    /// The common predecessor.
    pub common_prev: ObjectId,

    /// First competing state object.
    pub branch_a: ObjectId,

    /// Second competing state object.
    pub branch_b: ObjectId,

    /// Sequence number at which the fork occurred.
    pub fork_seq: u64,

    /// Timestamp when the fork was detected (UNIX seconds).
    pub detected_at: u64,

    /// Zone in which the fork occurred.
    pub zone_id: ZoneId,

    /// Connector that experienced the fork.
    pub connector_id: ConnectorId,
}

/// Fork resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkResolution {
    /// Choose the branch with the higher `lease_seq`.
    ChooseByLease,

    /// Require manual intervention.
    ManualResolution,

    /// Merge both branches (only valid for CRDT state).
    CrdtMerge,
}

impl ForkResolution {
    /// Check if this resolution strategy is valid for the given state model.
    #[must_use]
    pub const fn is_valid_for(&self, model: &ConnectorStateModel) -> bool {
        match self {
            Self::ChooseByLease => model.is_singleton_writer(),
            Self::ManualResolution => true, // Always valid
            Self::CrdtMerge => model.is_crdt(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection and Resolution (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Result of fork detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateForkDetectionResult {
    /// No fork detected; single consistent head.
    NoFork {
        /// Current head object ID.
        head: ObjectId,
        /// Current sequence number.
        seq: u64,
    },
    /// Fork detected with competing heads.
    ForkDetected(ForkEvent),
}

impl StateForkDetectionResult {
    /// Returns true if a fork was detected.
    #[must_use]
    pub const fn is_fork(&self) -> bool {
        matches!(self, Self::ForkDetected(_))
    }

    /// Get fork event if one was detected.
    #[must_use]
    pub const fn fork_event(&self) -> Option<&ForkEvent> {
        match self {
            Self::ForkDetected(event) => Some(event),
            Self::NoFork { .. } => None,
        }
    }
}

impl ForkEvent {
    /// Create a new fork event.
    #[must_use]
    pub const fn new(
        common_prev: ObjectId,
        branch_a: ObjectId,
        branch_b: ObjectId,
        fork_seq: u64,
        detected_at: u64,
        zone_id: ZoneId,
        connector_id: ConnectorId,
    ) -> Self {
        Self {
            common_prev,
            branch_a,
            branch_b,
            fork_seq,
            detected_at,
            zone_id,
            connector_id,
        }
    }

    /// Determine the winning branch using lease-based resolution.
    ///
    /// Returns the object ID of the branch with the higher `lease_seq`.
    /// If `lease_seq` values are equal, returns `None` (requires manual resolution).
    #[must_use]
    pub fn resolve_by_lease(&self, lease_seq_a: u64, lease_seq_b: u64) -> Option<ObjectId> {
        use std::cmp::Ordering;
        match lease_seq_a.cmp(&lease_seq_b) {
            Ordering::Greater => Some(self.branch_a),
            Ordering::Less => Some(self.branch_b),
            Ordering::Equal => None, // Tie - requires manual resolution
        }
    }
}

/// Fork resolution outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkResolutionOutcome {
    /// The fork that was resolved.
    pub fork_event: ForkEvent,
    /// Resolution strategy used.
    pub strategy: ForkResolution,
    /// Winning branch object ID (if resolved).
    pub winning_head: Option<ObjectId>,
    /// Timestamp when resolution occurred.
    pub resolved_at: u64,
    /// Whether resolution succeeded.
    pub resolved: bool,
    /// Reason if resolution failed.
    pub failure_reason: Option<String>,
}

impl ForkResolutionOutcome {
    /// Create a successful resolution outcome.
    #[must_use]
    pub const fn success(
        fork_event: ForkEvent,
        strategy: ForkResolution,
        winning_head: ObjectId,
        resolved_at: u64,
    ) -> Self {
        Self {
            fork_event,
            strategy,
            winning_head: Some(winning_head),
            resolved_at,
            resolved: true,
            failure_reason: None,
        }
    }

    /// Create a failed resolution outcome.
    #[must_use]
    pub fn failure(
        fork_event: ForkEvent,
        strategy: ForkResolution,
        resolved_at: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            fork_event,
            strategy,
            winning_head: None,
            resolved_at,
            resolved: false,
            failure_reason: Some(reason.into()),
        }
    }
}

/// Fork detector for connector state objects.
///
/// Tracks state objects indexed by their `prev` pointer to detect forks
/// (multiple objects with the same `prev`).
#[derive(Debug, Default)]
pub struct StateForkDetector {
    /// Map from `prev` object ID to list of state objects pointing to it.
    /// A fork exists when any `prev` has more than one child.
    children_by_prev: std::collections::HashMap<ObjectId, Vec<ObjectId>>,
    /// Map from object ID to its sequence number.
    seq_by_id: std::collections::HashMap<ObjectId, u64>,
    /// Map from object ID to its `lease_seq` (for resolution).
    lease_seq_by_id: std::collections::HashMap<ObjectId, u64>,
}

impl StateForkDetector {
    /// Create a new fork detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a state object for fork detection.
    ///
    /// Call this for each state object received. The detector will track
    /// parent-child relationships to detect forks.
    pub fn register(
        &mut self,
        object_id: ObjectId,
        prev: Option<ObjectId>,
        seq: u64,
        lease_seq: u64,
    ) {
        self.seq_by_id.insert(object_id, seq);
        self.lease_seq_by_id.insert(object_id, lease_seq);

        if let Some(prev_id) = prev {
            self.children_by_prev
                .entry(prev_id)
                .or_default()
                .push(object_id);
        }
    }

    /// Check for forks in the registered state objects.
    ///
    /// Returns the first detected fork, if any.
    #[must_use]
    pub fn detect_fork(
        &self,
        zone_id: ZoneId,
        connector_id: ConnectorId,
        now: u64,
    ) -> StateForkDetectionResult {
        // Find any prev with multiple children (fork point)
        for (prev_id, children) in &self.children_by_prev {
            if children.len() > 1 {
                // Fork detected: multiple objects share the same prev
                let branch_a = children[0];
                let branch_b = children[1];
                let fork_seq = self.seq_by_id.get(&branch_a).copied().unwrap_or(0);

                return StateForkDetectionResult::ForkDetected(ForkEvent::new(
                    *prev_id,
                    branch_a,
                    branch_b,
                    fork_seq,
                    now,
                    zone_id,
                    connector_id,
                ));
            }
        }

        // No fork - find the latest head
        let (head, seq) = self
            .seq_by_id
            .iter()
            .max_by_key(|(_, seq)| *seq)
            .map_or((ObjectId::from_bytes([0u8; 32]), 0), |(id, seq)| {
                (*id, *seq)
            });

        StateForkDetectionResult::NoFork { head, seq }
    }

    /// Get the `lease_seq` for a given object ID.
    #[must_use]
    pub fn lease_seq(&self, object_id: &ObjectId) -> Option<u64> {
        self.lease_seq_by_id.get(object_id).copied()
    }

    /// Resolve a fork using the specified strategy.
    ///
    /// # Arguments
    ///
    /// * `fork` - The fork event to resolve
    /// * `strategy` - Resolution strategy to use
    /// * `model` - State model (for validation)
    /// * `now` - Current timestamp
    ///
    /// # Errors
    ///
    /// Returns a failure outcome if the strategy is invalid for the model
    /// or if lease-based resolution results in a tie.
    #[must_use]
    pub fn resolve(
        &self,
        fork: &ForkEvent,
        strategy: ForkResolution,
        model: &ConnectorStateModel,
        now: u64,
    ) -> ForkResolutionOutcome {
        if !strategy.is_valid_for(model) {
            return ForkResolutionOutcome::failure(
                fork.clone(),
                strategy,
                now,
                format!("strategy {strategy:?} is not valid for state model {model}"),
            );
        }

        match strategy {
            ForkResolution::ChooseByLease => {
                let lease_seq_a = self.lease_seq(&fork.branch_a).unwrap_or(0);
                let lease_seq_b = self.lease_seq(&fork.branch_b).unwrap_or(0);

                fork.resolve_by_lease(lease_seq_a, lease_seq_b).map_or_else(
                    || {
                        ForkResolutionOutcome::failure(
                            fork.clone(),
                            strategy,
                            now,
                            format!("lease_seq tie ({lease_seq_a} == {lease_seq_b}); manual resolution required"),
                        )
                    },
                    |winner| ForkResolutionOutcome::success(fork.clone(), strategy, winner, now),
                )
            }
            ForkResolution::ManualResolution => ForkResolutionOutcome::failure(
                fork.clone(),
                strategy,
                now,
                "manual resolution requires explicit head selection",
            ),
            ForkResolution::CrdtMerge => {
                // CRDT merge would happen at the delta level, not here
                // This just signals that merge is the strategy
                ForkResolutionOutcome::failure(
                    fork.clone(),
                    strategy,
                    now,
                    "CRDT merge requires delta-level merging (not implemented in detector)",
                )
            }
        }
    }

    /// Resolve a fork by explicitly selecting a head.
    ///
    /// Used for manual resolution when an operator chooses the winning branch.
    #[must_use]
    pub fn resolve_manual(
        &self,
        fork: &ForkEvent,
        selected_head: ObjectId,
        now: u64,
    ) -> ForkResolutionOutcome {
        // Validate the selected head is one of the fork branches
        if selected_head != fork.branch_a && selected_head != fork.branch_b {
            return ForkResolutionOutcome::failure(
                fork.clone(),
                ForkResolution::ManualResolution,
                now,
                format!(
                    "selected head {} is not one of the fork branches ({} or {})",
                    selected_head, fork.branch_a, fork.branch_b
                ),
            );
        }

        ForkResolutionOutcome::success(
            fork.clone(),
            ForkResolution::ManualResolution,
            selected_head,
            now,
        )
    }

    /// Clear all tracked state (for testing or reset).
    pub fn clear(&mut self) {
        self.children_by_prev.clear();
        self.seq_by_id.clear();
        self.lease_seq_by_id.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton Writer Fencing Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when fencing validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencingError {
    /// The lease has expired.
    LeaseExpired { expired_at: u64, now: u64 },

    /// The `lease_seq` is stale (superseded by a newer lease).
    StaleLeaseSeq { held_seq: u64, current_seq: u64 },

    /// The lease is for the wrong subject.
    SubjectMismatch { expected: ObjectId, got: ObjectId },

    /// The lease purpose is not `ConnectorStateWrite`.
    WrongPurpose,

    /// The state object references a non-existent lease.
    LeaseNotFound { lease_id: ObjectId },
}

impl fmt::Display for FencingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseExpired { expired_at, now } => {
                write!(f, "lease expired at {expired_at}, current time is {now}")
            }
            Self::StaleLeaseSeq {
                held_seq,
                current_seq,
            } => {
                write!(
                    f,
                    "stale lease_seq: held {held_seq}, current is {current_seq}"
                )
            }
            Self::SubjectMismatch { expected, got } => {
                write!(f, "lease subject mismatch: expected {expected}, got {got}")
            }
            Self::WrongPurpose => {
                write!(f, "lease purpose is not ConnectorStateWrite")
            }
            Self::LeaseNotFound { lease_id } => {
                write!(f, "lease not found: {lease_id}")
            }
        }
    }
}

impl std::error::Error for FencingError {}

/// Validate that a state object has valid fencing for singleton-writer semantics.
///
/// # Arguments
///
/// * `state_obj` - The state object to validate
/// * `current_known_seq` - The highest known `lease_seq` for this subject
/// * `now` - Current timestamp for expiry checking
/// * `lease_exp` - Expiration time of the referenced lease
///
/// # Errors
///
/// Returns an error if fencing validation fails.
pub fn validate_singleton_writer_fencing(
    state_obj: &ConnectorStateObject,
    current_known_seq: u64,
    now: u64,
    lease_exp: u64,
) -> Result<(), FencingError> {
    // Check lease expiry
    if now >= lease_exp {
        return Err(FencingError::LeaseExpired {
            expired_at: lease_exp,
            now,
        });
    }

    // Check fencing token is not stale
    if state_obj.lease_seq < current_known_seq {
        return Err(FencingError::StaleLeaseSeq {
            held_seq: state_obj.lease_seq,
            current_seq: current_known_seq,
        });
    }

    // Verify lease is in header refs
    if !state_obj.header.refs.contains(&state_obj.lease_object_id) {
        return Err(FencingError::LeaseNotFound {
            lease_id: state_obj.lease_object_id,
        });
    }

    // Note: Subject and purpose validation require the actual Lease object,
    // which should be done by the caller with access to the object store.

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for snapshot creation (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Create snapshot every N updates.
    #[serde(default = "default_snapshot_every_updates")]
    pub snapshot_every_updates: u32,

    /// Create snapshot every N bytes of state.
    #[serde(default = "default_snapshot_every_bytes")]
    pub snapshot_every_bytes: u64,
}

const fn default_snapshot_every_updates() -> u32 {
    5000
}

const fn default_snapshot_every_bytes() -> u64 {
    1_048_576 // 1 MiB
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_every_updates: default_snapshot_every_updates(),
            snapshot_every_bytes: default_snapshot_every_bytes(),
        }
    }
}

impl SnapshotConfig {
    /// Check if a snapshot should be created.
    #[must_use]
    pub const fn should_snapshot(&self, updates_since_last: u32, bytes_since_last: u64) -> bool {
        updates_since_last >= self.snapshot_every_updates
            || bytes_since_last >= self.snapshot_every_bytes
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provenance, TaintLevel};
    use fcp_cbor::SchemaId;
    use semver::Version;

    // ─────────────────────────────────────────────────────────────────────────
    // CrdtType Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn crdt_type_display() {
        assert_eq!(CrdtType::LwwMap.to_string(), "lww_map");
        assert_eq!(CrdtType::OrSet.to_string(), "or_set");
        assert_eq!(CrdtType::GCounter.to_string(), "g_counter");
        assert_eq!(CrdtType::PnCounter.to_string(), "pn_counter");
    }

    #[test]
    fn crdt_type_serde_roundtrip() {
        for crdt_type in [
            CrdtType::LwwMap,
            CrdtType::OrSet,
            CrdtType::GCounter,
            CrdtType::PnCounter,
        ] {
            let json = serde_json::to_string(&crdt_type).unwrap();
            let deserialized: CrdtType = serde_json::from_str(&json).unwrap();
            assert_eq!(crdt_type, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateModel Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_model_stateless() {
        let model = ConnectorStateModel::Stateless;
        assert!(model.is_stateless());
        assert!(!model.is_singleton_writer());
        assert!(!model.is_crdt());
        assert!(model.crdt_type().is_none());
        assert_eq!(model.to_string(), "stateless");
    }

    #[test]
    fn connector_state_model_singleton_writer() {
        let model = ConnectorStateModel::SingletonWriter;
        assert!(!model.is_stateless());
        assert!(model.is_singleton_writer());
        assert!(!model.is_crdt());
        assert!(model.crdt_type().is_none());
        assert_eq!(model.to_string(), "singleton_writer");
    }

    #[test]
    fn connector_state_model_crdt() {
        let model = ConnectorStateModel::Crdt {
            crdt_type: CrdtType::LwwMap,
        };
        assert!(!model.is_stateless());
        assert!(!model.is_singleton_writer());
        assert!(model.is_crdt());
        assert_eq!(model.crdt_type(), Some(CrdtType::LwwMap));
        assert_eq!(model.to_string(), "crdt(lww_map)");
    }

    #[test]
    fn connector_state_model_default_is_stateless() {
        let model = ConnectorStateModel::default();
        assert!(model.is_stateless());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CursorState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cursor_state_cbor_roundtrip() {
        let state = CursorState {
            offset: Some(42),
            last_seen_id: Some("msg_123".to_string()),
            watermark: Some(1_700_000_000),
        };

        let encoded = state.to_cbor().unwrap();
        let decoded = CursorState::from_cbor(&encoded).unwrap();

        assert_eq!(state, decoded);
    }

    #[test]
    fn cursor_state_cbor_deterministic() {
        let state = CursorState {
            offset: Some(7),
            last_seen_id: Some("cursor_abc".to_string()),
            watermark: Some(1_700_000_111),
        };

        let encoded1 = state.to_cbor().unwrap();
        let encoded2 = state.to_cbor().unwrap();

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn cursor_state_cbor_golden_vector() {
        let state = CursorState {
            offset: Some(1),
            last_seen_id: Some("a".to_string()),
            watermark: Some(2),
        };

        let encoded = state.to_cbor().unwrap();
        let expected =
            hex::decode("a3666f6666736574016977617465726d61726b026c6c6173745f7365656e5f69646161")
                .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn cursor_state_from_cbor_rejects_trailing_bytes() {
        let state = CursorState {
            offset: Some(9),
            last_seen_id: Some("trail".to_string()),
            watermark: Some(3),
        };

        let mut encoded = state.to_cbor().unwrap();
        encoded.push(0x00);

        let err = CursorState::from_cbor(&encoded).unwrap_err();
        assert!(matches!(err, SerializationError::TrailingBytes));
    }

    #[test]
    fn cursor_state_from_object_uses_state_cbor() {
        let state = CursorState {
            offset: Some(100),
            last_seen_id: Some("last_id".to_string()),
            watermark: Some(1_700_000_222),
        };
        let state_cbor = state.to_cbor().unwrap();

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "CursorState", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance {
                origin_zone: ZoneId::work(),
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

        let state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 1,
            state_cbor,
            updated_at: 1_700_000_000,
            lease_seq: 1,
            lease_object_id: test_object_id("lease"),
            signature: Signature::zero(),
        };

        let decoded = cursor_state_from_object(&state_obj).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn connector_state_model_serde_roundtrip() {
        let models = [
            ConnectorStateModel::Stateless,
            ConnectorStateModel::SingletonWriter,
            ConnectorStateModel::Crdt {
                crdt_type: CrdtType::OrSet,
            },
        ];

        for model in models {
            let json = serde_json::to_string(&model).unwrap();
            let deserialized: ConnectorStateModel = serde_json::from_str(&json).unwrap();
            assert_eq!(model, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SnapshotConfig Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_config_default() {
        let config = SnapshotConfig::default();
        assert_eq!(config.snapshot_every_updates, 5000);
        assert_eq!(config.snapshot_every_bytes, 1_048_576);
    }

    #[test]
    fn snapshot_config_should_snapshot() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 1000,
        };

        assert!(!config.should_snapshot(50, 500));
        assert!(config.should_snapshot(100, 500)); // Updates threshold
        assert!(config.should_snapshot(50, 1000)); // Bytes threshold
        assert!(config.should_snapshot(100, 1000)); // Both thresholds
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signature Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn signature_zero() {
        let sig = Signature::zero();
        assert_eq!(sig.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn signature_from_bytes() {
        let bytes = [42u8; 64];
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn signature_display() {
        let sig = Signature::from_bytes([0xab; 64]);
        let display = sig.to_string();
        assert!(display.contains("abababab"));
        assert!(display.ends_with("..."));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FencingError Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fencing_error_display() {
        let err = FencingError::LeaseExpired {
            expired_at: 1000,
            now: 2000,
        };
        assert!(err.to_string().contains("expired"));

        let err = FencingError::StaleLeaseSeq {
            held_seq: 5,
            current_seq: 10,
        };
        assert!(err.to_string().contains("stale"));

        let err = FencingError::WrongPurpose;
        assert!(err.to_string().contains("ConnectorStateWrite"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkResolution Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_resolution_serde() {
        let resolutions = [
            ForkResolution::ChooseByLease,
            ForkResolution::ManualResolution,
            ForkResolution::CrdtMerge,
        ];

        for resolution in resolutions {
            let json = serde_json::to_string(&resolution).unwrap();
            let deserialized: ForkResolution = serde_json::from_str(&json).unwrap();
            assert_eq!(resolution, deserialized);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fork Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::test_id(label)
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test:fork:v1")
    }

    #[test]
    fn fork_detector_no_fork_single_chain() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let obj1 = test_object_id("obj1");
        let obj2 = test_object_id("obj2");

        // Linear chain: genesis -> obj1 -> obj2
        detector.register(genesis, None, 0, 100);
        detector.register(obj1, Some(genesis), 1, 100);
        detector.register(obj2, Some(obj1), 2, 100);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);

        assert!(!result.is_fork());
        if let StateForkDetectionResult::NoFork { head, seq } = result {
            assert_eq!(head, obj2);
            assert_eq!(seq, 2);
        }
    }

    #[test]
    fn fork_detector_detects_fork() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        // Fork: genesis -> branch_a AND genesis -> branch_b
        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 101);
        detector.register(branch_b, Some(genesis), 1, 102);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);

        assert!(result.is_fork());
        let fork = result.fork_event().unwrap();
        assert_eq!(fork.common_prev, genesis);
        assert_eq!(fork.fork_seq, 1);
        // branch_a and branch_b should be the two competing heads (order may vary)
        assert!(
            (fork.branch_a == branch_a && fork.branch_b == branch_b)
                || (fork.branch_a == branch_b && fork.branch_b == branch_a)
        );
    }

    #[test]
    fn fork_resolve_by_lease_higher_wins() {
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        let fork = ForkEvent::new(
            genesis,
            branch_a,
            branch_b,
            1,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        );

        // branch_a has higher lease_seq
        let winner = fork.resolve_by_lease(200, 100);
        assert_eq!(winner, Some(branch_a));

        // branch_b has higher lease_seq
        let winner = fork.resolve_by_lease(100, 200);
        assert_eq!(winner, Some(branch_b));

        // Tie - no winner
        let winner = fork.resolve_by_lease(100, 100);
        assert!(winner.is_none());
    }

    #[test]
    fn fork_detector_resolve_by_lease_success() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 200); // Higher lease_seq
        detector.register(branch_b, Some(genesis), 1, 150);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        let outcome = detector.resolve(
            fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_001,
        );

        assert!(outcome.resolved);
        assert_eq!(outcome.winning_head, Some(branch_a));
    }

    #[test]
    fn fork_detector_resolve_invalid_strategy() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 200);
        detector.register(branch_b, Some(genesis), 1, 150);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        // ChooseByLease is not valid for CRDT model
        let outcome = detector.resolve(
            fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            },
            1_700_000_001,
        );

        assert!(!outcome.resolved);
        assert!(outcome.failure_reason.unwrap().contains("not valid"));
    }

    #[test]
    fn fork_detector_manual_resolution() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 100);
        detector.register(branch_b, Some(genesis), 1, 100);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        // Manually select branch_b as winner
        let outcome = detector.resolve_manual(fork, branch_b, 1_700_000_001);

        assert!(outcome.resolved);
        assert_eq!(outcome.winning_head, Some(branch_b));
        assert_eq!(outcome.strategy, ForkResolution::ManualResolution);
    }

    #[test]
    fn fork_detector_manual_resolution_invalid_head() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");
        let invalid_head = test_object_id("invalid");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 100);
        detector.register(branch_b, Some(genesis), 1, 100);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        // Try to select an invalid head
        let outcome = detector.resolve_manual(fork, invalid_head, 1_700_000_001);

        assert!(!outcome.resolved);
        assert!(
            outcome
                .failure_reason
                .unwrap()
                .contains("not one of the fork branches")
        );
    }

    #[test]
    fn fork_resolution_is_valid_for_model() {
        assert!(ForkResolution::ChooseByLease.is_valid_for(&ConnectorStateModel::SingletonWriter));
        assert!(!ForkResolution::ChooseByLease.is_valid_for(&ConnectorStateModel::Stateless));
        assert!(
            !ForkResolution::ChooseByLease.is_valid_for(&ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            })
        );

        assert!(
            ForkResolution::ManualResolution.is_valid_for(&ConnectorStateModel::SingletonWriter)
        );
        assert!(ForkResolution::ManualResolution.is_valid_for(&ConnectorStateModel::Stateless));
        assert!(
            ForkResolution::ManualResolution.is_valid_for(&ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            })
        );

        assert!(!ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::SingletonWriter));
        assert!(
            ForkResolution::CrdtMerge.is_valid_for(&ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            })
        );
    }

    #[test]
    fn fork_detector_clear() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let obj1 = test_object_id("obj1");

        detector.register(genesis, None, 0, 100);
        detector.register(obj1, Some(genesis), 1, 100);

        assert!(detector.lease_seq(&genesis).is_some());

        detector.clear();

        assert!(detector.lease_seq(&genesis).is_none());
    }

    // ── Additional coverage ──

    #[test]
    fn crdt_type_as_str() {
        assert_eq!(CrdtType::LwwMap.as_str(), "lww_map");
        assert_eq!(CrdtType::OrSet.as_str(), "or_set");
        assert_eq!(CrdtType::GCounter.as_str(), "g_counter");
        assert_eq!(CrdtType::PnCounter.as_str(), "pn_counter");
    }

    #[test]
    fn signature_serde_roundtrip() {
        let sig = Signature::from_bytes([0xAB; 64]);
        let json = serde_json::to_string(&sig).unwrap();
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn signature_debug_is_truncated() {
        let sig = Signature::from_bytes([0xCD; 64]);
        let debug = format!("{sig:?}");
        assert!(debug.contains("Signature"));
        assert!(debug.contains("..."));
    }

    #[test]
    fn signature_default_is_zero() {
        let sig = Signature::default();
        assert_eq!(sig, Signature::zero());
    }

    #[test]
    fn connector_state_model_tagged_serde() {
        // Verify the internally tagged representation
        let json = serde_json::to_string(&ConnectorStateModel::Stateless).unwrap();
        assert!(json.contains("\"type\":\"stateless\""));

        let json = serde_json::to_string(&ConnectorStateModel::SingletonWriter).unwrap();
        assert!(json.contains("\"type\":\"singleton_writer\""));

        let json = serde_json::to_string(&ConnectorStateModel::Crdt {
            crdt_type: CrdtType::OrSet,
        })
        .unwrap();
        assert!(json.contains("\"type\":\"crdt\""));
        assert!(json.contains("\"crdt_type\":\"or_set\""));
    }

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    #[test]
    fn connector_state_root_stateless_constructor() {
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work());
        assert!(root.model.is_stateless());
        assert!(root.head.is_none());
        assert!(root.instance_id.is_none());
        assert_eq!(root.state_schema_version, 1);
    }

    #[test]
    fn connector_state_root_singleton_writer_constructor() {
        let root = ConnectorStateRoot::singleton_writer(
            test_header(),
            test_connector_id(),
            ZoneId::work(),
        );
        assert!(root.model.is_singleton_writer());
    }

    #[test]
    fn connector_state_root_crdt_constructor() {
        let root = ConnectorStateRoot::crdt(
            test_header(),
            test_connector_id(),
            ZoneId::work(),
            CrdtType::GCounter,
        );
        assert!(root.model.is_crdt());
        assert_eq!(root.model.crdt_type(), Some(CrdtType::GCounter));
    }

    #[test]
    fn connector_state_root_with_instance_id() {
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work())
                .with_instance_id(InstanceId::new());
        assert!(root.instance_id.is_some());
    }

    #[test]
    fn connector_state_root_with_head() {
        let head = test_object_id("head");
        let root =
            ConnectorStateRoot::stateless(test_header(), test_connector_id(), ZoneId::work())
                .with_head(head);
        assert_eq!(root.head, Some(head));
    }

    #[test]
    fn connector_state_object_is_genesis() {
        let mut header = test_header();
        let lease_id = test_object_id("lease");
        header.refs.push(lease_id);

        let genesis = ConnectorStateObject {
            header: header.clone(),
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 0,
            state_cbor: vec![],
            updated_at: 1_700_000_000,
            lease_seq: 1,
            lease_object_id: lease_id,
            signature: Signature::zero(),
        };
        assert!(genesis.is_genesis());

        let non_genesis = ConnectorStateObject {
            prev: Some(test_object_id("prev")),
            seq: 1,
            ..genesis
        };
        assert!(!non_genesis.is_genesis());
    }

    #[test]
    fn validate_fencing_success() {
        let lease_id = test_object_id("lease");
        let mut header = test_header();
        header.refs.push(lease_id);

        let state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 1,
            state_cbor: vec![],
            updated_at: 1_700_000_000,
            lease_seq: 5,
            lease_object_id: lease_id,
            signature: Signature::zero(),
        };

        // Valid: now < lease_exp, lease_seq >= current_known_seq, lease in refs
        let result = validate_singleton_writer_fencing(&state_obj, 5, 1_700_000_100, 1_700_001_000);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_fencing_lease_expired() {
        let lease_id = test_object_id("lease");
        let mut header = test_header();
        header.refs.push(lease_id);

        let state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 1,
            state_cbor: vec![],
            updated_at: 1_700_000_000,
            lease_seq: 5,
            lease_object_id: lease_id,
            signature: Signature::zero(),
        };

        let result = validate_singleton_writer_fencing(&state_obj, 5, 1_700_002_000, 1_700_001_000);
        assert!(matches!(result, Err(FencingError::LeaseExpired { .. })));
    }

    #[test]
    fn validate_fencing_stale_seq() {
        let lease_id = test_object_id("lease");
        let mut header = test_header();
        header.refs.push(lease_id);

        let state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 1,
            state_cbor: vec![],
            updated_at: 1_700_000_000,
            lease_seq: 3, // Less than current known seq
            lease_object_id: lease_id,
            signature: Signature::zero(),
        };

        let result =
            validate_singleton_writer_fencing(&state_obj, 10, 1_700_000_100, 1_700_001_000);
        assert!(matches!(result, Err(FencingError::StaleLeaseSeq { .. })));
    }

    #[test]
    fn validate_fencing_lease_not_in_refs() {
        let lease_id = test_object_id("lease");
        let header = test_header(); // No refs

        let state_obj = ConnectorStateObject {
            header,
            connector_id: test_connector_id(),
            instance_id: None,
            zone_id: ZoneId::work(),
            prev: None,
            seq: 1,
            state_cbor: vec![],
            updated_at: 1_700_000_000,
            lease_seq: 5,
            lease_object_id: lease_id,
            signature: Signature::zero(),
        };

        let result = validate_singleton_writer_fencing(&state_obj, 5, 1_700_000_100, 1_700_001_000);
        assert!(matches!(result, Err(FencingError::LeaseNotFound { .. })));
    }

    #[test]
    fn cursor_state_empty_fields() {
        let state = CursorState {
            offset: None,
            last_seen_id: None,
            watermark: None,
        };
        let encoded = state.to_cbor().unwrap();
        let decoded = CursorState::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn fork_resolution_outcome_success() {
        let fork = ForkEvent::new(
            test_object_id("prev"),
            test_object_id("a"),
            test_object_id("b"),
            1,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        );
        let outcome = ForkResolutionOutcome::success(
            fork,
            ForkResolution::ChooseByLease,
            test_object_id("a"),
            1_700_000_001,
        );
        assert!(outcome.resolved);
        assert_eq!(outcome.winning_head, Some(test_object_id("a")));
        assert!(outcome.failure_reason.is_none());
    }

    #[test]
    fn fork_resolution_outcome_failure() {
        let fork = ForkEvent::new(
            test_object_id("prev"),
            test_object_id("a"),
            test_object_id("b"),
            1,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        );
        let outcome = ForkResolutionOutcome::failure(
            fork,
            ForkResolution::ManualResolution,
            1_700_000_001,
            "operator not available",
        );
        assert!(!outcome.resolved);
        assert!(outcome.winning_head.is_none());
        assert!(outcome.failure_reason.unwrap().contains("operator"));
    }

    #[test]
    fn snapshot_config_serde_roundtrip() {
        let config = SnapshotConfig {
            snapshot_every_updates: 100,
            snapshot_every_bytes: 2048,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: SnapshotConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snapshot_every_updates, 100);
        assert_eq!(back.snapshot_every_bytes, 2048);
    }

    #[test]
    fn fork_event_serde_roundtrip() {
        let fork = ForkEvent::new(
            test_object_id("prev"),
            test_object_id("a"),
            test_object_id("b"),
            5,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        );
        let json = serde_json::to_string(&fork).unwrap();
        let back: ForkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(fork, back);
    }

    #[test]
    fn fork_detector_lease_seq_lookup() {
        let mut detector = StateForkDetector::new();
        let obj = test_object_id("obj");
        detector.register(obj, None, 0, 42);
        assert_eq!(detector.lease_seq(&obj), Some(42));

        let unknown = test_object_id("unknown");
        assert!(detector.lease_seq(&unknown).is_none());
    }

    #[test]
    fn fork_resolve_crdt_merge_returns_failure() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 100);
        detector.register(branch_b, Some(genesis), 1, 100);

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        let outcome = detector.resolve(
            fork,
            ForkResolution::CrdtMerge,
            &ConnectorStateModel::Crdt {
                crdt_type: CrdtType::LwwMap,
            },
            1_700_000_001,
        );
        assert!(!outcome.resolved);
        assert!(outcome.failure_reason.unwrap().contains("delta-level"));
    }

    #[test]
    fn fork_resolve_lease_tie() {
        let mut detector = StateForkDetector::new();
        let genesis = test_object_id("genesis");
        let branch_a = test_object_id("branch_a");
        let branch_b = test_object_id("branch_b");

        detector.register(genesis, None, 0, 100);
        detector.register(branch_a, Some(genesis), 1, 100); // Same lease_seq
        detector.register(branch_b, Some(genesis), 1, 100); // Same lease_seq

        let result = detector.detect_fork(ZoneId::work(), test_connector_id(), 1_700_000_000);
        let fork = result.fork_event().unwrap();

        let outcome = detector.resolve(
            fork,
            ForkResolution::ChooseByLease,
            &ConnectorStateModel::SingletonWriter,
            1_700_000_001,
        );
        assert!(!outcome.resolved);
        assert!(outcome.failure_reason.unwrap().contains("tie"));
    }

    #[test]
    fn state_fork_detection_result_serde() {
        let no_fork = StateForkDetectionResult::NoFork {
            head: test_object_id("head"),
            seq: 42,
        };
        let json = serde_json::to_string(&no_fork).unwrap();
        let decoded: StateForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.is_fork());

        let fork = StateForkDetectionResult::ForkDetected(ForkEvent::new(
            test_object_id("prev"),
            test_object_id("a"),
            test_object_id("b"),
            10,
            1_700_000_000,
            ZoneId::work(),
            test_connector_id(),
        ));
        let json = serde_json::to_string(&fork).unwrap();
        let decoded: StateForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_fork());
    }
}
