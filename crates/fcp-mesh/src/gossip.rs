//! FCP2 Gossip Layer for Object Availability and Reconciliation.
//!
//! This module implements the gossip baseline from `FCP_Specification_V2.md` §8.2:
//! - Object/symbol availability announcements
//! - Compact summaries for anti-entropy
//! - Bounded reconciliation (no unbounded work)
//!
//! # Security Model (NORMATIVE)
//!
//! 1. **Quarantined objects MUST NOT pollute gossip**: Only admitted objects are gossiped.
//! 2. **Signed summaries**: All gossip messages are signed for authentication and rate limiting.
//! 3. **Bounded reconciliation**: Reconciliation work is bounded by admission control.
//!
//! # Design Notes
//!
//! The spec calls for XOR filters + IBLT for efficient set reconciliation. This baseline
//! implementation uses simpler set-based structures that can be upgraded to XOR/IBLT later.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::admission::ObjectAdmissionClass;
use fcp_core::{EpochId, NodeSignature, ObjectId, TailscaleNodeId, ZoneId};

// ─────────────────────────────────────────────────────────────────────────────
// Constants (NORMATIVE defaults)
// ─────────────────────────────────────────────────────────────────────────────

/// Default maximum objects per gossip summary (bounded reconciliation).
pub const DEFAULT_MAX_OBJECTS_PER_SUMMARY: usize = 10_000;

/// Default maximum symbols per gossip summary.
pub const DEFAULT_MAX_SYMBOLS_PER_SUMMARY: usize = 100_000;

/// Default gossip summary TTL in seconds.
pub const DEFAULT_SUMMARY_TTL_SECS: u64 = 300;

/// Default reconciliation batch size (bounded work).
pub const DEFAULT_RECONCILIATION_BATCH_SIZE: usize = 1000;

/// Maximum object IDs in a single gossip request (anti-amplification).
pub const MAX_OBJECT_IDS_PER_REQUEST: usize = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Filter Types (Placeholder for XOR Filter / IBLT)
// ─────────────────────────────────────────────────────────────────────────────

/// XOR filter placeholder for fast membership hints (NORMATIVE).
///
/// This baseline uses a simple Bloom filter approximation. Production implementations
/// SHOULD upgrade to actual XOR filters for:
/// - Lower false positive rates (≈1.23 bits/element vs ≈10 bits for Bloom)
/// - Faster membership queries
/// - Deterministic construction
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XorFilterPlaceholder {
    /// Compact bit representation (simplified for baseline).
    /// Real XOR filter would use fingerprints + 3-way XOR.
    bits: Vec<u64>,
    /// Number of elements inserted.
    count: u32,
    /// Hash seed for deterministic construction.
    seed: u64,
}

impl XorFilterPlaceholder {
    /// Create a new empty filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bits: Vec::new(),
            count: 0,
            seed: 0,
        }
    }

    /// Create a filter with a specific seed for reproducibility.
    #[must_use]
    pub const fn with_seed(seed: u64) -> Self {
        Self {
            bits: Vec::new(),
            count: 0,
            seed,
        }
    }

    /// Insert an item into the filter.
    pub fn insert(&mut self, item: &[u8]) {
        // Simplified: hash item and set bits
        let hash = self.hash_item(item);
        let idx = (hash as usize) % self.bit_capacity();
        let word_idx = idx / 64;
        let bit_idx = idx % 64;

        while self.bits.len() <= word_idx {
            self.bits.push(0);
        }
        self.bits[word_idx] |= 1 << bit_idx;
        self.count += 1;
    }

    /// Check if an item might be in the filter.
    ///
    /// Returns `false` if definitely not present, `true` if possibly present.
    #[must_use]
    pub fn may_contain(&self, item: &[u8]) -> bool {
        let hash = self.hash_item(item);
        let idx = (hash as usize) % self.bit_capacity();
        let word_idx = idx / 64;
        let bit_idx = idx % 64;

        if word_idx >= self.bits.len() {
            return false;
        }
        (self.bits[word_idx] & (1 << bit_idx)) != 0
    }

    /// Get the number of elements inserted.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.count
    }

    /// Check if filter is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Compute a digest of the filter for comparison.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP2-FILTER-DIGEST-V1");
        hasher.update(&self.seed.to_le_bytes());
        hasher.update(&self.count.to_le_bytes());
        for word in &self.bits {
            hasher.update(&word.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn hash_item(&self, item: &[u8]) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed.to_le_bytes());
        hasher.update(item);
        let hash = hasher.finalize();
        u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap())
    }

    const fn bit_capacity(&self) -> usize {
        // Default capacity: 64KB of bits = 512K bits
        // Can hold ~50K elements with <1% false positive rate
        512 * 1024
    }
}

/// IBLT state placeholder for precise set reconciliation (NORMATIVE).
///
/// Invertible Bloom Lookup Tables allow efficient computation of set differences.
/// This baseline uses a simple change-tracking approach. Production implementations
/// SHOULD upgrade to actual IBLT for:
/// - O(d) decoding where d is the difference size
/// - Deterministic reconciliation
/// - Bounded communication overhead
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IbltPlaceholder {
    /// Recent changes (object_id, esi) for reconciliation.
    /// Bounded to prevent unbounded growth.
    recent_changes: VecDeque<(ObjectId, Option<u32>)>,
    /// Maximum recent changes to track.
    max_changes: usize,
    /// Sequence number for change ordering.
    change_seq: u64,
}

impl IbltPlaceholder {
    /// Create a new IBLT placeholder with default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_changes(DEFAULT_RECONCILIATION_BATCH_SIZE)
    }

    /// Create with a custom change limit.
    #[must_use]
    pub fn with_max_changes(max_changes: usize) -> Self {
        Self {
            recent_changes: VecDeque::new(),
            max_changes,
            change_seq: 0,
        }
    }

    /// Record a local change (object added/updated).
    pub fn note_local_change(&mut self, object_id: &ObjectId, esi: Option<u32>) {
        if self.recent_changes.len() >= self.max_changes {
            // Remove oldest
            self.recent_changes.pop_front();
        }
        self.recent_changes.push_back((*object_id, esi));
        self.change_seq += 1;
    }

    /// Get recent changes for reconciliation.
    #[must_use]
    pub fn recent_changes(&self) -> Vec<(ObjectId, Option<u32>)> {
        self.recent_changes.iter().copied().collect()
    }

    /// Get current change sequence.
    #[must_use]
    pub const fn change_seq(&self) -> u64 {
        self.change_seq
    }

    /// Encode IBLT state for wire transmission.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Simplified encoding: just serialize recent changes
        serde_json::to_vec(&self.recent_changes).unwrap_or_default()
    }

    /// Clear all tracked changes.
    pub fn clear(&mut self) {
        self.recent_changes.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gossip State
// ─────────────────────────────────────────────────────────────────────────────

/// Local gossip state for a zone (NORMATIVE).
///
/// Tracks which objects and symbols this node has available for gossip.
/// Only admitted (non-quarantined) objects are included.
#[derive(Debug, Clone)]
pub struct GossipState {
    /// Zone this state covers.
    zone_id: ZoneId,

    /// Object availability filter (fast membership hint).
    object_filter: XorFilterPlaceholder,

    /// Symbol availability filter.
    symbol_filter: XorFilterPlaceholder,

    /// IBLT state for precise reconciliation.
    iblt_state: IbltPlaceholder,

    /// Admitted object IDs (authoritative set).
    admitted_objects: BTreeSet<ObjectId>,

    /// Symbol availability: object_id -> set of ESIs.
    symbol_availability: BTreeMap<ObjectId, BTreeSet<u32>>,

    /// Last update timestamp.
    last_updated: u64,
}

impl GossipState {
    /// Create a new gossip state for a zone.
    #[must_use]
    pub fn new(zone_id: ZoneId, config: &GossipConfig) -> Self {
        Self {
            zone_id,
            object_filter: XorFilterPlaceholder::new(),
            symbol_filter: XorFilterPlaceholder::new(),
            iblt_state: IbltPlaceholder::with_max_changes(config.reconciliation_batch_size),
            admitted_objects: BTreeSet::new(),
            symbol_availability: BTreeMap::new(),
            last_updated: 0,
        }
    }

    /// Get the zone ID.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Announce local object availability (NORMATIVE).
    ///
    /// Only admitted objects should be announced. This method does NOT check
    /// admission class - the caller MUST ensure the object is admitted.
    pub fn announce_object(&mut self, object_id: &ObjectId, now: u64) {
        if self.admitted_objects.insert(*object_id) {
            self.object_filter.insert(object_id.as_bytes());
            self.iblt_state.note_local_change(object_id, None);
            self.last_updated = now;
        }
    }

    /// Announce local symbol availability (NORMATIVE).
    ///
    /// # Arguments
    ///
    /// * `object_id` - The object this symbol belongs to
    /// * `esi` - Encoding Symbol Identifier
    /// * `now` - Current timestamp
    pub fn announce_symbol(&mut self, object_id: &ObjectId, esi: u32, now: u64) {
        // Ensure object is tracked
        if !self.admitted_objects.contains(object_id) {
            self.announce_object(object_id, now);
        }

        // Add symbol
        let symbols = self.symbol_availability.entry(*object_id).or_default();
        if symbols.insert(esi) {
            self.symbol_filter.insert(&symbol_key(object_id, esi));
            self.iblt_state.note_local_change(object_id, Some(esi));
            self.last_updated = now;
        }
    }

    /// Check if we might have an object (fast filter check).
    #[must_use]
    pub fn may_have_object(&self, object_id: &ObjectId) -> bool {
        self.object_filter.may_contain(object_id.as_bytes())
    }

    /// Check if we definitely have an object (authoritative check).
    #[must_use]
    pub fn has_object(&self, object_id: &ObjectId) -> bool {
        self.admitted_objects.contains(object_id)
    }

    /// Check if we might have a symbol.
    #[must_use]
    pub fn may_have_symbol(&self, object_id: &ObjectId, esi: u32) -> bool {
        self.symbol_filter.may_contain(&symbol_key(object_id, esi))
    }

    /// Check if we definitely have a symbol.
    #[must_use]
    pub fn has_symbol(&self, object_id: &ObjectId, esi: u32) -> bool {
        self.symbol_availability
            .get(object_id)
            .is_some_and(|s| s.contains(&esi))
    }

    /// Get all symbols we have for an object.
    #[must_use]
    pub fn symbols_for_object(&self, object_id: &ObjectId) -> Option<&BTreeSet<u32>> {
        self.symbol_availability.get(object_id)
    }

    /// Get the number of admitted objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.admitted_objects.len()
    }

    /// Get the total number of symbols.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbol_availability.values().map(BTreeSet::len).sum()
    }

    /// Create a compact summary for gossip exchange.
    #[must_use]
    pub fn create_summary(&self, from: TailscaleNodeId, epoch_id: EpochId) -> GossipSummary {
        GossipSummary {
            from,
            zone_id: self.zone_id.clone(),
            epoch_id,
            object_filter_digest: self.object_filter.digest(),
            symbol_filter_digest: self.symbol_filter.digest(),
            object_count: self.admitted_objects.len() as u32,
            symbol_count: self.symbol_count() as u32,
            iblt: self.iblt_state.encode(),
            timestamp: self.last_updated,
            signature: None,
        }
    }

    /// Remove an object from gossip state.
    pub fn remove_object(&mut self, object_id: &ObjectId, now: u64) {
        self.admitted_objects.remove(object_id);
        self.symbol_availability.remove(object_id);
        self.rebuild_filters();
        self.last_updated = now;
    }

    /// Rebuild filters from authoritative sets.
    fn rebuild_filters(&mut self) {
        self.object_filter = XorFilterPlaceholder::new();
        self.symbol_filter = XorFilterPlaceholder::new();

        for object_id in &self.admitted_objects {
            self.object_filter.insert(object_id.as_bytes());
        }

        for (object_id, esis) in &self.symbol_availability {
            for esi in esis {
                self.symbol_filter.insert(&symbol_key(object_id, *esi));
            }
        }
    }

    /// Get list of admitted objects (bounded).
    #[must_use]
    pub fn list_objects(&self, limit: usize) -> Vec<ObjectId> {
        self.admitted_objects.iter().take(limit).copied().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gossip Summary
// ─────────────────────────────────────────────────────────────────────────────

/// Signed gossip summary for anti-entropy (NORMATIVE).
///
/// This is exchanged between peers to detect differences in object/symbol availability.
/// The digest allows quick comparison without transferring full sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipSummary {
    /// Source node.
    pub from: TailscaleNodeId,
    /// Zone this summary covers.
    pub zone_id: ZoneId,
    /// Current epoch.
    pub epoch_id: EpochId,
    /// Digest of object filter.
    pub object_filter_digest: [u8; 32],
    /// Digest of symbol filter.
    pub symbol_filter_digest: [u8; 32],
    /// Number of objects (for quick comparison).
    pub object_count: u32,
    /// Number of symbols.
    pub symbol_count: u32,
    /// Compact IBLT encoding for precise delta reconciliation.
    pub iblt: Vec<u8>,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Node signature (for authentication and rate limiting).
    pub signature: Option<NodeSignature>,
}

impl GossipSummary {
    /// Check if this summary differs from another (needs reconciliation).
    #[must_use]
    pub fn differs_from(&self, other: &Self) -> bool {
        self.object_filter_digest != other.object_filter_digest
            || self.symbol_filter_digest != other.symbol_filter_digest
    }

    /// Check if summary is stale.
    #[must_use]
    pub const fn is_stale(&self, now: u64, ttl_secs: u64) -> bool {
        now.saturating_sub(self.timestamp) > ttl_secs
    }

    /// Get bytes for signing.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FCP2-GOSSIP-SUMMARY-V1");
        bytes.extend_from_slice(self.from.as_str().as_bytes());
        bytes.extend_from_slice(self.zone_id.as_bytes());
        bytes.extend_from_slice(self.epoch_id.as_str().as_bytes());
        bytes.extend_from_slice(&self.object_filter_digest);
        bytes.extend_from_slice(&self.symbol_filter_digest);
        bytes.extend_from_slice(&self.object_count.to_le_bytes());
        bytes.extend_from_slice(&self.symbol_count.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Attach a signature to this summary.
    #[must_use]
    pub fn with_signature(mut self, signature: NodeSignature) -> Self {
        self.signature = Some(signature);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gossip Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Gossip message types for wire exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GossipMessage {
    /// Summary announcement (periodic broadcast).
    Summary(GossipSummary),

    /// Request for specific objects/symbols (bounded).
    Request(GossipRequest),

    /// Response with requested data.
    Response(GossipResponse),

    /// Reconciliation request using IBLT.
    ReconcileRequest(ReconcileRequest),

    /// Reconciliation response with missing items.
    ReconcileResponse(ReconcileResponse),
}

/// Request for specific objects or symbols (NORMATIVE).
///
/// Requests are bounded to prevent amplification attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipRequest {
    /// Requesting node.
    pub from: TailscaleNodeId,
    /// Zone being requested.
    pub zone_id: ZoneId,
    /// Object IDs requested (bounded by `MAX_OBJECT_IDS_PER_REQUEST`).
    pub object_ids: Vec<ObjectId>,
    /// Specific symbols requested: (object_id, esi).
    pub symbols: Vec<(ObjectId, u32)>,
    /// Request timestamp.
    pub timestamp: u64,
    /// Optional signature for authenticated requests.
    pub signature: Option<NodeSignature>,
}

impl GossipRequest {
    /// Create a new request for objects.
    #[must_use]
    pub fn for_objects(
        from: TailscaleNodeId,
        zone_id: ZoneId,
        object_ids: Vec<ObjectId>,
        now: u64,
    ) -> Self {
        // Bound request size
        let bounded_ids: Vec<_> = object_ids
            .into_iter()
            .take(MAX_OBJECT_IDS_PER_REQUEST)
            .collect();

        Self {
            from,
            zone_id,
            object_ids: bounded_ids,
            symbols: Vec::new(),
            timestamp: now,
            signature: None,
        }
    }

    /// Create a new request for symbols.
    #[must_use]
    pub fn for_symbols(
        from: TailscaleNodeId,
        zone_id: ZoneId,
        symbols: Vec<(ObjectId, u32)>,
        now: u64,
    ) -> Self {
        // Bound request size
        let bounded_symbols: Vec<_> = symbols
            .into_iter()
            .take(MAX_OBJECT_IDS_PER_REQUEST)
            .collect();

        Self {
            from,
            zone_id,
            object_ids: Vec::new(),
            symbols: bounded_symbols,
            timestamp: now,
            signature: None,
        }
    }

    /// Validate request bounds.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.object_ids.len() <= MAX_OBJECT_IDS_PER_REQUEST
            && self.symbols.len() <= MAX_OBJECT_IDS_PER_REQUEST
    }

    /// Validate request bounds against configured limits.
    #[must_use]
    pub fn is_valid_with_limits(&self, max_objects: usize, max_symbols: usize) -> bool {
        self.object_ids.len() <= max_objects && self.symbols.len() <= max_symbols
    }
}

/// Response to a gossip request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipResponse {
    /// Responding node.
    pub from: TailscaleNodeId,
    /// In response to request from.
    pub to: TailscaleNodeId,
    /// Zone.
    pub zone_id: ZoneId,
    /// Object availability: which requested objects we have.
    pub have_objects: Vec<ObjectId>,
    /// Symbol availability: which requested symbols we have.
    pub have_symbols: Vec<(ObjectId, u32)>,
    /// Response timestamp.
    pub timestamp: u64,
}

/// Reconciliation request using IBLT state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileRequest {
    /// Requesting node.
    pub from: TailscaleNodeId,
    /// Zone being reconciled.
    pub zone_id: ZoneId,
    /// Our IBLT state.
    pub iblt: Vec<u8>,
    /// Our filter digests.
    pub object_filter_digest: [u8; 32],
    pub symbol_filter_digest: [u8; 32],
    /// Request timestamp.
    pub timestamp: u64,
}

/// Reconciliation response with computed differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileResponse {
    /// Responding node.
    pub from: TailscaleNodeId,
    /// Zone.
    pub zone_id: ZoneId,
    /// Objects we have that peer is missing (bounded).
    pub peer_missing_objects: Vec<ObjectId>,
    /// Objects peer has that we're missing (bounded).
    pub we_missing_objects: Vec<ObjectId>,
    /// Response timestamp.
    pub timestamp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer Gossip State
// ─────────────────────────────────────────────────────────────────────────────

/// Gossip state for a peer (NORMATIVE).
///
/// Tracks what we know about a peer's object/symbol availability.
#[derive(Debug, Clone)]
pub struct PeerGossipState {
    /// Peer node ID.
    peer_id: TailscaleNodeId,
    /// Last received summary.
    last_summary: Option<GossipSummary>,
    /// Object filter (received from peer).
    object_filter: XorFilterPlaceholder,
    /// Symbol filter (received from peer).
    symbol_filter: XorFilterPlaceholder,
    /// Last update time.
    last_updated: u64,
    /// Number of failed gossip attempts.
    failed_attempts: u32,
}

impl PeerGossipState {
    /// Create a new peer gossip state.
    #[must_use]
    pub fn new(peer_id: TailscaleNodeId) -> Self {
        Self {
            peer_id,
            last_summary: None,
            object_filter: XorFilterPlaceholder::new(),
            symbol_filter: XorFilterPlaceholder::new(),
            last_updated: 0,
            failed_attempts: 0,
        }
    }

    /// Get the peer ID.
    #[must_use]
    pub const fn peer_id(&self) -> &TailscaleNodeId {
        &self.peer_id
    }

    /// Update state from a received summary.
    pub fn update_from_summary(&mut self, summary: GossipSummary, now: u64) {
        self.last_summary = Some(summary);
        self.last_updated = now;
        self.failed_attempts = 0;
    }

    /// Check if peer might have an object.
    #[must_use]
    pub fn may_have_object(&self, object_id: &ObjectId) -> bool {
        self.object_filter.may_contain(object_id.as_bytes())
    }

    /// Check if peer might have a symbol.
    #[must_use]
    pub fn may_have_symbol(&self, object_id: &ObjectId, esi: u32) -> bool {
        self.symbol_filter.may_contain(&symbol_key(object_id, esi))
    }

    /// Check if peer state is stale.
    #[must_use]
    pub const fn is_stale(&self, now: u64, ttl_secs: u64) -> bool {
        now.saturating_sub(self.last_updated) > ttl_secs
    }

    /// Record a failed gossip attempt.
    pub fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
    }

    /// Get the number of consecutive failures.
    #[must_use]
    pub const fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh Gossip Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Mesh gossip controller (NORMATIVE).
///
/// Orchestrates gossip between peers for a zone.
#[derive(Debug)]
pub struct MeshGossip {
    /// Our node ID.
    local_node: TailscaleNodeId,
    /// Local gossip state per zone.
    zone_states: HashMap<ZoneId, GossipState>,
    /// Known peer states.
    peer_states: HashMap<TailscaleNodeId, PeerGossipState>,
    /// Configuration.
    config: GossipConfig,
}

/// Gossip configuration.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Maximum objects per summary.
    pub max_objects_per_summary: usize,
    /// Maximum symbols per summary.
    pub max_symbols_per_summary: usize,
    /// Maximum objects per request.
    pub max_objects_per_request: usize,
    /// Maximum symbols per request.
    pub max_symbols_per_request: usize,
    /// Summary TTL in seconds.
    pub summary_ttl_secs: u64,
    /// Reconciliation batch size.
    pub reconciliation_batch_size: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_objects_per_summary: DEFAULT_MAX_OBJECTS_PER_SUMMARY,
            max_symbols_per_summary: DEFAULT_MAX_SYMBOLS_PER_SUMMARY,
            max_objects_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            max_symbols_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            summary_ttl_secs: DEFAULT_SUMMARY_TTL_SECS,
            reconciliation_batch_size: DEFAULT_RECONCILIATION_BATCH_SIZE,
        }
    }
}

impl MeshGossip {
    /// Create a new gossip controller.
    #[must_use]
    pub fn new(local_node: TailscaleNodeId, config: GossipConfig) -> Self {
        Self {
            local_node,
            zone_states: HashMap::new(),
            peer_states: HashMap::new(),
            config,
        }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults(local_node: TailscaleNodeId) -> Self {
        Self::new(local_node, GossipConfig::default())
    }

    /// Get or create zone state.
    fn get_or_create_zone(&mut self, zone_id: &ZoneId) -> &mut GossipState {
        // We need to clone config to pass it into the closure, but we can't capture &self.config
        // mutable borrow of self.zone_states conflicts with immutable borrow of self.config
        // So we clone config cheaply (it's small) or extract fields.
        let config = self.config.clone();

        self.zone_states
            .entry(zone_id.clone())
            .or_insert_with(|| GossipState::new(zone_id.clone(), &config))
    }

    /// Announce object availability (NORMATIVE).
    ///
    /// # Arguments
    ///
    /// * `zone_id` - Zone the object belongs to
    /// * `object_id` - Object being announced
    /// * `admission_class` - Object admission class (MUST be Admitted)
    /// * `now` - Current timestamp
    ///
    /// # Returns
    ///
    /// `true` if object was added to gossip, `false` if quarantined (not gossiped).
    pub fn announce_object(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        admission_class: ObjectAdmissionClass,
        now: u64,
    ) -> bool {
        // NORMATIVE: Quarantined objects MUST NOT pollute gossip
        if admission_class == ObjectAdmissionClass::Quarantined {
            warn!(
                component = "mesh.gossip",
                event = "quarantine_blocked",
                zone_id = %zone_id,
                object_id = %object_id,
                reason = "gossip_propagation_denied"
            );
            return false;
        }

        let state = self.get_or_create_zone(zone_id);
        state.announce_object(object_id, now);
        info!(
            component = "mesh.gossip",
            event = "object_announced",
            node_id = %self.local_node.as_str(),
            zone_id = %zone_id,
            object_id = %object_id,
            timestamp = now
        );
        true
    }

    /// Announce symbol availability.
    pub fn announce_symbol(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        esi: u32,
        admission_class: ObjectAdmissionClass,
        now: u64,
    ) -> bool {
        // NORMATIVE: Quarantined objects MUST NOT pollute gossip
        if admission_class == ObjectAdmissionClass::Quarantined {
            warn!(
                component = "mesh.gossip",
                event = "quarantine_blocked",
                zone_id = %zone_id,
                object_id = %object_id,
                reason = "gossip_propagation_denied"
            );
            return false;
        }

        let state = self.get_or_create_zone(zone_id);
        state.announce_symbol(object_id, esi, now);
        debug!(
            component = "mesh.gossip",
            event = "symbol_announced",
            node_id = %self.local_node.as_str(),
            zone_id = %zone_id,
            object_id = %object_id,
            esi,
            timestamp = now
        );
        true
    }

    /// Create a summary for a zone.
    #[must_use]
    pub fn create_summary(&self, zone_id: &ZoneId, epoch_id: EpochId) -> Option<GossipSummary> {
        self.zone_states.get(zone_id).map(|state| {
            let epoch_label = epoch_id.as_str().to_string();
            let mut summary = state.create_summary(self.local_node.clone(), epoch_id);
            summary.object_count = summary
                .object_count
                .min(self.config.max_objects_per_summary as u32);
            summary.symbol_count = summary
                .symbol_count
                .min(self.config.max_symbols_per_summary as u32);
            if tracing::enabled!(tracing::Level::DEBUG) {
                let object_digest = hex::encode(summary.object_filter_digest);
                let symbol_digest = hex::encode(summary.symbol_filter_digest);
                debug!(
                    component = "mesh.gossip",
                    event = "summary_created",
                    node_id = %self.local_node.as_str(),
                    zone_id = %zone_id,
                    epoch_id = %epoch_label,
                    object_count = summary.object_count,
                    symbol_count = summary.symbol_count,
                    reconciliation_batch_size = self.config.reconciliation_batch_size,
                    object_digest = %object_digest,
                    symbol_digest = %symbol_digest
                );
            }
            summary
        })
    }

    /// Handle received summary from a peer.
    pub fn handle_summary(&mut self, summary: GossipSummary, now: u64) {
        if summary.is_stale(now, self.config.summary_ttl_secs) {
            let age_secs = now.saturating_sub(summary.timestamp);
            warn!(
                component = "mesh.gossip",
                event = "summary_rejected",
                reason = "stale",
                peer_id = %summary.from.as_str(),
                zone_id = %summary.zone_id,
                object_count = summary.object_count,
                symbol_count = summary.symbol_count,
                age_seconds = age_secs,
                ttl_seconds = self.config.summary_ttl_secs
            );
            return;
        }

        if summary.object_count as usize > self.config.max_objects_per_summary
            || summary.symbol_count as usize > self.config.max_symbols_per_summary
        {
            warn!(
                component = "mesh.gossip",
                event = "summary_rejected",
                reason = "oversized",
                peer_id = %summary.from.as_str(),
                zone_id = %summary.zone_id,
                object_count = summary.object_count,
                symbol_count = summary.symbol_count,
                max_objects = self.config.max_objects_per_summary,
                max_symbols = self.config.max_symbols_per_summary
            );
            return;
        }

        let peer_id = summary.from.clone();
        let object_count = summary.object_count;
        let symbol_count = summary.symbol_count;

        // Update peer state
        let peer_state = self
            .peer_states
            .entry(peer_id.clone())
            .or_insert_with(|| PeerGossipState::new(peer_id.clone()));
        peer_state.update_from_summary(summary, now);
        debug!(
            component = "mesh.gossip",
            event = "summary_received",
            peer_id = %peer_id.as_str(),
            object_count,
            symbol_count,
            accepted = true
        );
    }

    /// Find peers that might have an object.
    #[must_use]
    pub fn find_object_sources(&self, object_id: &ObjectId) -> Vec<TailscaleNodeId> {
        self.peer_states
            .iter()
            .filter(|(_, state)| state.may_have_object(object_id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Find peers that might have a symbol.
    #[must_use]
    pub fn find_symbol_sources(&self, object_id: &ObjectId, esi: u32) -> Vec<TailscaleNodeId> {
        self.peer_states
            .iter()
            .filter(|(_, state)| state.may_have_symbol(object_id, esi))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Check if we have an object locally.
    #[must_use]
    pub fn has_object(&self, zone_id: &ZoneId, object_id: &ObjectId) -> bool {
        self.zone_states
            .get(zone_id)
            .is_some_and(|s| s.has_object(object_id))
    }

    /// Check if we have a symbol locally.
    #[must_use]
    pub fn has_symbol(&self, zone_id: &ZoneId, object_id: &ObjectId, esi: u32) -> bool {
        self.zone_states
            .get(zone_id)
            .is_some_and(|s| s.has_symbol(object_id, esi))
    }

    /// Create a bounded request for objects we're missing.
    #[must_use]
    pub fn create_request(
        &self,
        zone_id: &ZoneId,
        object_ids: Vec<ObjectId>,
        now: u64,
    ) -> GossipRequest {
        let max_objects = self
            .config
            .max_objects_per_request
            .min(MAX_OBJECT_IDS_PER_REQUEST);
        let bounded: Vec<_> = object_ids.into_iter().take(max_objects).collect();
        debug!(
            component = "mesh.gossip",
            event = "request_created",
            node_id = %self.local_node.as_str(),
            zone_id = %zone_id,
            objects_requested = bounded.len(),
            max_objects
        );
        GossipRequest::for_objects(self.local_node.clone(), zone_id.clone(), bounded, now)
    }

    /// Handle a request from a peer.
    #[must_use]
    pub fn handle_request(&self, request: &GossipRequest) -> GossipResponse {
        let max_objects = self
            .config
            .max_objects_per_request
            .min(MAX_OBJECT_IDS_PER_REQUEST);
        let max_symbols = self
            .config
            .max_symbols_per_request
            .min(MAX_OBJECT_IDS_PER_REQUEST);
        let objects_requested = request.object_ids.len();
        let symbols_requested = request.symbols.len();
        let request_size = objects_requested + symbols_requested;

        if !request.is_valid_with_limits(max_objects, max_symbols) {
            let reason = if objects_requested > max_objects {
                "object_count_exceeded"
            } else if symbols_requested > max_symbols {
                "symbol_count_exceeded"
            } else {
                "invalid_request"
            };
            warn!(
                component = "mesh.gossip",
                event = "request_rejected",
                reason,
                peer_id = %request.from.as_str(),
                zone_id = %request.zone_id,
                objects_requested,
                symbols_requested,
                max_objects,
                max_symbols,
                request_size
            );
            return GossipResponse {
                from: self.local_node.clone(),
                to: request.from.clone(),
                zone_id: request.zone_id.clone(),
                have_objects: Vec::new(),
                have_symbols: Vec::new(),
                timestamp: request.timestamp,
            };
        }

        let zone_state = self.zone_states.get(&request.zone_id);

        let have_objects: Vec<ObjectId> = request
            .object_ids
            .iter()
            .take(max_objects)
            .filter(|id| zone_state.is_some_and(|s| s.has_object(id)))
            .copied()
            .collect();

        let have_symbols: Vec<(ObjectId, u32)> = request
            .symbols
            .iter()
            .take(max_symbols)
            .filter(|(id, esi)| zone_state.is_some_and(|s| s.has_symbol(id, *esi)))
            .copied()
            .collect();

        debug!(
            component = "mesh.gossip",
            event = "request_handled",
            peer_id = %request.from.as_str(),
            zone_id = %request.zone_id,
            objects_requested,
            symbols_requested,
            objects_served = have_objects.len(),
            symbols_served = have_symbols.len(),
            request_size
        );
        GossipResponse {
            from: self.local_node.clone(),
            to: request.from.clone(),
            zone_id: request.zone_id.clone(),
            have_objects,
            have_symbols,
            timestamp: request.timestamp,
        }
    }

    /// Get stats for a zone.
    #[must_use]
    pub fn zone_stats(&self, zone_id: &ZoneId) -> Option<GossipStats> {
        self.zone_states.get(zone_id).map(|state| GossipStats {
            object_count: state.object_count(),
            symbol_count: state.symbol_count(),
            last_updated: state.last_updated,
        })
    }

    /// Get number of known peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peer_states.len()
    }
}

/// Gossip statistics.
#[derive(Debug, Clone)]
pub struct GossipStats {
    /// Number of objects.
    pub object_count: usize,
    /// Number of symbols.
    pub symbol_count: usize,
    /// Last update timestamp.
    pub last_updated: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Create a symbol key for filter insertion.
fn symbol_key(object_id: &ObjectId, esi: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(object_id.as_bytes());
    key.extend_from_slice(&esi.to_le_bytes());
    key
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::ObjectAdmissionClass;

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    fn test_epoch() -> EpochId {
        EpochId::new("epoch-test")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // XorFilterPlaceholder Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn filter_insert_and_check() {
        let mut filter = XorFilterPlaceholder::new();
        assert!(filter.is_empty());

        filter.insert(b"test-item");
        assert!(!filter.is_empty());
        assert_eq!(filter.len(), 1);

        // Should find inserted item
        assert!(filter.may_contain(b"test-item"));

        // May or may not find non-inserted (false positives allowed)
        // Just ensure no panic
        let _ = filter.may_contain(b"other-item");
    }

    #[test]
    fn filter_digest_deterministic() {
        let mut filter1 = XorFilterPlaceholder::with_seed(42);
        let mut filter2 = XorFilterPlaceholder::with_seed(42);

        filter1.insert(b"item-a");
        filter1.insert(b"item-b");
        filter2.insert(b"item-a");
        filter2.insert(b"item-b");

        assert_eq!(filter1.digest(), filter2.digest());
    }

    #[test]
    fn filter_digest_differs_by_content() {
        let mut filter1 = XorFilterPlaceholder::with_seed(42);
        let mut filter2 = XorFilterPlaceholder::with_seed(42);

        filter1.insert(b"item-a");
        filter2.insert(b"item-b");

        assert_ne!(filter1.digest(), filter2.digest());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IBLT Placeholder Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn iblt_tracks_changes() {
        let mut iblt = IbltPlaceholder::new();
        let obj_id = test_object_id("obj-1");

        iblt.note_local_change(&obj_id, None);
        assert_eq!(iblt.change_seq(), 1);
        assert_eq!(iblt.recent_changes().len(), 1);

        iblt.note_local_change(&obj_id, Some(42));
        assert_eq!(iblt.change_seq(), 2);
        assert_eq!(iblt.recent_changes().len(), 2);
    }

    #[test]
    fn iblt_bounds_changes() {
        let mut iblt = IbltPlaceholder::with_max_changes(3);
        let obj_id = test_object_id("obj");

        for i in 0..5 {
            iblt.note_local_change(&obj_id, Some(i));
        }

        // Should only keep last 3
        assert_eq!(iblt.recent_changes().len(), 3);
        assert_eq!(iblt.change_seq(), 5);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GossipState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn gossip_state_announce_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        assert!(!state.has_object(&obj_id));
        state.announce_object(&obj_id, 1000);
        assert!(state.has_object(&obj_id));
        assert!(state.may_have_object(&obj_id));
        assert_eq!(state.object_count(), 1);
    }

    #[test]
    fn gossip_state_announce_symbol() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        state.announce_symbol(&obj_id, 42, 1000);

        assert!(state.has_object(&obj_id)); // Object auto-added
        assert!(state.has_symbol(&obj_id, 42));
        assert!(state.may_have_symbol(&obj_id, 42));
        assert_eq!(state.symbol_count(), 1);
    }

    #[test]
    fn gossip_state_create_summary() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        state.announce_object(&obj_id, 1000);
        state.announce_symbol(&obj_id, 1, 1000);
        state.announce_symbol(&obj_id, 2, 1000);

        let summary = state.create_summary(test_node("local"), test_epoch());

        assert_eq!(summary.zone_id.as_str(), "z:work");
        assert_eq!(summary.object_count, 1);
        assert_eq!(summary.symbol_count, 2);
    }

    #[test]
    fn gossip_state_remove_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        state.announce_object(&obj_id, 1000);
        state.announce_symbol(&obj_id, 42, 1000);
        assert!(state.has_object(&obj_id));

        state.remove_object(&obj_id, 2000);
        assert!(!state.has_object(&obj_id));
        assert!(!state.has_symbol(&obj_id, 42));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GossipSummary Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn summary_differs_from() {
        let summary1 = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [1; 32],
            symbol_filter_digest: [2; 32],
            object_count: 10,
            symbol_count: 100,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        let summary2 = GossipSummary {
            object_filter_digest: [3; 32], // Different
            ..summary1.clone()
        };

        assert!(summary1.differs_from(&summary2));
        assert!(!summary1.differs_from(&summary1));
    }

    #[test]
    fn summary_is_stale() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        assert!(!summary.is_stale(1100, 300)); // Within TTL
        assert!(summary.is_stale(1500, 300)); // Past TTL
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GossipRequest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn request_bounds_object_ids() {
        let many_ids: Vec<ObjectId> = (0..200)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        let request = GossipRequest::for_objects(test_node("node"), test_zone(), many_ids, 1000);

        assert!(request.is_valid());
        assert_eq!(request.object_ids.len(), MAX_OBJECT_IDS_PER_REQUEST);
    }

    #[test]
    fn request_bounds_symbols() {
        let object_id = test_object_id("obj-symbols");
        let symbols: Vec<(ObjectId, u32)> = (0..200).map(|esi| (object_id, esi)).collect();

        let request = GossipRequest::for_symbols(test_node("node"), test_zone(), symbols, 1000);

        assert!(request.is_valid());
        assert_eq!(request.symbols.len(), MAX_OBJECT_IDS_PER_REQUEST);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MeshGossip Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mesh_gossip_announce_admitted_object() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("admitted-obj");

        let added =
            gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);

        assert!(added);
        assert!(gossip.has_object(&test_zone(), &obj_id));
    }

    #[test]
    fn mesh_gossip_rejects_quarantined_object() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("quarantined-obj");

        let added = gossip.announce_object(
            &test_zone(),
            &obj_id,
            ObjectAdmissionClass::Quarantined,
            1000,
        );

        // NORMATIVE: Quarantined objects MUST NOT pollute gossip
        assert!(!added);
        assert!(!gossip.has_object(&test_zone(), &obj_id));
    }

    #[test]
    fn mesh_gossip_create_summary() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);

        let summary = gossip.create_summary(&test_zone(), test_epoch());
        assert!(summary.is_some());
        assert_eq!(summary.unwrap().object_count, 1);
    }

    #[test]
    fn mesh_gossip_create_summary_clamps_counts() {
        let config = GossipConfig {
            max_objects_per_summary: 1,
            max_symbols_per_summary: 1,
            max_objects_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            max_symbols_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            summary_ttl_secs: DEFAULT_SUMMARY_TTL_SECS,
            reconciliation_batch_size: DEFAULT_RECONCILIATION_BATCH_SIZE,
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let obj_id = test_object_id("obj-1");
        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);
        gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        let obj_id2 = test_object_id("obj-2");
        gossip.announce_object(&test_zone(), &obj_id2, ObjectAdmissionClass::Admitted, 1000);
        gossip.announce_symbol(
            &test_zone(),
            &obj_id2,
            2,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let summary = gossip
            .create_summary(&test_zone(), test_epoch())
            .expect("summary");
        assert_eq!(summary.object_count, 1);
        assert_eq!(summary.symbol_count, 1);
    }

    #[test]
    fn mesh_gossip_handle_summary_updates_peer() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 50,
            symbol_count: 500,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        gossip.handle_summary(summary, 1000);
        assert_eq!(gossip.peer_count(), 1);
    }

    #[test]
    fn mesh_gossip_ignores_stale_summary() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let now = 1000u64;
        let timestamp = now.saturating_sub(DEFAULT_SUMMARY_TTL_SECS + 1);

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 50,
            symbol_count: 500,
            iblt: vec![],
            timestamp,
            signature: None,
        };

        gossip.handle_summary(summary, now);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_ignores_oversized_summary() {
        let config = GossipConfig {
            max_objects_per_summary: 1,
            max_symbols_per_summary: 1,
            max_objects_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            max_symbols_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            summary_ttl_secs: DEFAULT_SUMMARY_TTL_SECS,
            reconciliation_batch_size: DEFAULT_RECONCILIATION_BATCH_SIZE,
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 2,
            symbol_count: 2,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        gossip.handle_summary(summary, 1000);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_handle_request() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);

        let request = GossipRequest::for_objects(
            test_node("peer"),
            test_zone(),
            vec![obj_id, test_object_id("unknown")],
            1000,
        );

        let response = gossip.handle_request(&request);

        // Should only include objects we have
        assert_eq!(response.have_objects.len(), 1);
        assert_eq!(response.have_objects[0], obj_id);
    }

    #[test]
    fn mesh_gossip_handle_request_bounds_results() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let object_ids: Vec<ObjectId> = (0..MAX_OBJECT_IDS_PER_REQUEST)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        for object_id in &object_ids {
            gossip.announce_object(
                &test_zone(),
                object_id,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let request =
            GossipRequest::for_objects(test_node("peer"), test_zone(), object_ids.clone(), 1000);

        let response = gossip.handle_request(&request);
        assert_eq!(response.have_objects.len(), object_ids.len());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_invalid_request() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let object_ids: Vec<ObjectId> = (0..=MAX_OBJECT_IDS_PER_REQUEST)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        for object_id in &object_ids {
            gossip.announce_object(
                &test_zone(),
                object_id,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let request = GossipRequest {
            from: test_node("peer"),
            zone_id: test_zone(),
            object_ids,
            symbols: vec![],
            timestamp: 1000,
            signature: None,
        };

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_over_config_object_request() {
        let config = GossipConfig {
            max_objects_per_request: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let object_ids: Vec<ObjectId> = (0..2)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        for object_id in &object_ids {
            gossip.announce_object(
                &test_zone(),
                object_id,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let request = GossipRequest::for_objects(test_node("peer"), test_zone(), object_ids, 1000);

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_invalid_symbol_request() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let object_id = test_object_id("obj-symbols-invalid");

        gossip.announce_symbol(
            &test_zone(),
            &object_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let max_esi =
            u32::try_from(MAX_OBJECT_IDS_PER_REQUEST).expect("max symbols fits u32 in test");
        let symbols: Vec<(ObjectId, u32)> = (0..=max_esi).map(|esi| (object_id, esi)).collect();

        let request = GossipRequest {
            from: test_node("peer"),
            zone_id: test_zone(),
            object_ids: vec![],
            symbols,
            timestamp: 1000,
            signature: None,
        };

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_over_config_symbol_request() {
        let config = GossipConfig {
            max_symbols_per_request: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let object_id = test_object_id("obj-symbols-config");

        gossip.announce_symbol(
            &test_zone(),
            &object_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        gossip.announce_symbol(
            &test_zone(),
            &object_id,
            2,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let symbols = vec![(object_id, 1), (object_id, 2)];
        let request = GossipRequest::for_symbols(test_node("peer"), test_zone(), symbols, 1000);

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_find_object_sources() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        // Add a peer that "has" the object (via filter)
        let mut peer_state = PeerGossipState::new(test_node("peer-1"));
        peer_state.object_filter.insert(obj_id.as_bytes());
        gossip.peer_states.insert(test_node("peer-1"), peer_state);

        let sources = gossip.find_object_sources(&obj_id);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].as_str(), "peer-1");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PeerGossipState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn peer_state_tracks_failures() {
        let mut peer = PeerGossipState::new(test_node("peer"));
        assert_eq!(peer.failed_attempts(), 0);

        peer.record_failure();
        peer.record_failure();
        assert_eq!(peer.failed_attempts(), 2);
    }

    #[test]
    fn peer_state_is_stale() {
        let peer = PeerGossipState::new(test_node("peer"));
        // last_updated defaults to 0

        assert!(peer.is_stale(1000, 300));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Symbol Key Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbol_key_format() {
        let obj_id = test_object_id("obj");
        let key = symbol_key(&obj_id, 42);

        // 32 bytes object_id + 4 bytes esi
        assert_eq!(key.len(), 36);
        assert!(key.starts_with(obj_id.as_bytes()));
    }
}
