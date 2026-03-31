//! FCP Gossip Layer for Object Availability and Reconciliation.
//!
//! This module implements the gossip baseline from `FCP_Specification_V3.md`
//! §11.6.8 (Gossip and Anti-Entropy Mechanics):
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
use std::time::Instant;

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

/// Minimum byte budget for encoded IBLT placeholders.
pub const MIN_IBLT_BYTES_BUDGET: usize = 512;

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

        let max_words = self.bit_capacity() / 64;
        if word_idx >= max_words {
            return; // index exceeds declared capacity — ignore silently
        }

        while self.bits.len() <= word_idx {
            self.bits.push(0);
        }
        self.bits[word_idx] |= 1u64 << bit_idx;
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
        (self.bits[word_idx] & (1u64 << bit_idx)) != 0
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
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&hash.as_bytes()[0..8]);
        u64::from_le_bytes(buf)
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

/// Errors when decoding a placeholder IBLT sketch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbltDecodeError {
    /// Encoded sketch exceeded the configured byte budget.
    TooLarge { len: usize, max: usize },
    /// Encoded sketch could not be parsed.
    InvalidEncoding,
    /// Encoded sketch decoded more changes than allowed.
    TooManyChanges { decoded: usize, max: usize },
}

impl IbltDecodeError {
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "iblt_bytes_exceeded",
            Self::InvalidEncoding => "iblt_invalid_encoding",
            Self::TooManyChanges { .. } => "iblt_change_limit_exceeded",
        }
    }
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
        if self.max_changes == 0 {
            self.change_seq += 1;
            return;
        }
        while self.recent_changes.len() >= self.max_changes {
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

    /// Get the number of change cells encoded in this placeholder sketch.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.recent_changes.len()
    }

    /// Encode IBLT state for wire transmission.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        // Simplified encoding: just serialize recent changes
        serde_json::to_vec(&self.recent_changes).unwrap_or_else(|_| b"[]".to_vec())
    }

    /// Decode IBLT state from a wire payload using explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload exceeds byte/change budgets or is malformed.
    pub fn decode_with_limits(
        bytes: &[u8],
        max_changes: usize,
        max_bytes: usize,
    ) -> Result<Self, IbltDecodeError> {
        if bytes.len() > max_bytes {
            return Err(IbltDecodeError::TooLarge {
                len: bytes.len(),
                max: max_bytes,
            });
        }

        if bytes.is_empty() {
            return Ok(Self::with_max_changes(max_changes));
        }

        let recent_changes: VecDeque<(ObjectId, Option<u32>)> =
            serde_json::from_slice(bytes).map_err(|_| IbltDecodeError::InvalidEncoding)?;
        if recent_changes.len() > max_changes {
            return Err(IbltDecodeError::TooManyChanges {
                decoded: recent_changes.len(),
                max: max_changes,
            });
        }

        Ok(Self {
            change_seq: u64::try_from(recent_changes.len()).unwrap_or(u64::MAX),
            recent_changes,
            max_changes,
        })
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
            object_count: u32::try_from(self.admitted_objects.len()).unwrap_or(u32::MAX),
            symbol_count: u32::try_from(self.symbol_count()).unwrap_or(u32::MAX),
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
    ///
    /// # Panics
    ///
    /// Panics if any field byte length exceeds `u32::MAX`.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Pre-allocate: 22 (prefix) + ~50 (from+zone+epoch with lengths)
        // + 64 (digests) + 8 (counts) + iblt.len() + 8 (timestamp)
        let estimated = 152 + self.iblt.len();
        let mut bytes = Vec::with_capacity(estimated);
        bytes.extend_from_slice(b"FCP2-GOSSIP-SUMMARY-V1");

        let from_bytes = self.from.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(from_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(from_bytes);

        let zone_bytes = self.zone_id.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);

        let epoch_bytes = self.epoch_id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(epoch_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(epoch_bytes);

        bytes.extend_from_slice(&self.object_filter_digest);
        bytes.extend_from_slice(&self.symbol_filter_digest);
        bytes.extend_from_slice(&self.object_count.to_le_bytes());
        bytes.extend_from_slice(&self.symbol_count.to_le_bytes());

        bytes.extend_from_slice(
            &u32::try_from(self.iblt.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.iblt);

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

impl GossipConfig {
    /// Derived byte budget for encoded IBLT payloads.
    ///
    /// This keeps placeholder sketches explicitly bounded without needing a
    /// second independently tuned knob while the implementation is still in a
    /// baseline/upgradeable state.
    #[must_use]
    pub const fn max_iblt_bytes(&self) -> usize {
        // 16 MB hard cap to prevent saturating_mul from returning usize::MAX.
        const MAX_IBLT_BYTES_CAP: usize = 16 * 1024 * 1024;

        let derived = self.reconciliation_batch_size.saturating_mul(48);
        if derived < MIN_IBLT_BYTES_BUDGET {
            MIN_IBLT_BYTES_BUDGET
        } else if derived > MAX_IBLT_BYTES_CAP {
            MAX_IBLT_BYTES_CAP
        } else {
            derived
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
    ///
    /// Borrows `config` and `zone_states` as disjoint fields to avoid
    /// cloning `GossipConfig` on every call.
    fn get_or_create_zone(&mut self, zone_id: &ZoneId) -> &mut GossipState {
        let config = &self.config;
        self.zone_states
            .entry(zone_id.clone())
            .or_insert_with(|| GossipState::new(zone_id.clone(), config))
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
            let iblt_cells = state.iblt_state.entry_count();
            let mut summary = state.create_summary(self.local_node.clone(), epoch_id);
            let max_iblt_bytes = self.config.max_iblt_bytes();
            let mut fallback_reason = "none";
            summary.object_count = summary
                .object_count
                .min(u32::try_from(self.config.max_objects_per_summary).unwrap_or(u32::MAX));
            summary.symbol_count = summary
                .symbol_count
                .min(u32::try_from(self.config.max_symbols_per_summary).unwrap_or(u32::MAX));
            if summary.iblt.len() > max_iblt_bytes {
                summary.iblt = b"[]".to_vec();
                fallback_reason = "iblt_bytes_exceeded";
            }
            if tracing::enabled!(tracing::Level::DEBUG) || fallback_reason != "none" {
                let object_digest = hex::encode(summary.object_filter_digest);
                let symbol_digest = hex::encode(summary.symbol_filter_digest);
                let summary_bytes =
                    serde_json::to_vec(&summary).map_or(0usize, |bytes| bytes.len());
                let summary_bytes = u64::try_from(summary_bytes).unwrap_or(u64::MAX);
                let iblt_bytes = u64::try_from(summary.iblt.len()).unwrap_or(u64::MAX);
                let iblt_cells = u64::try_from(iblt_cells).unwrap_or(u64::MAX);
                if fallback_reason == "none" {
                    debug!(
                        component = "mesh.gossip",
                        event = "summary_created",
                        node_id = %self.local_node.as_str(),
                        zone_id = %zone_id,
                        epoch_id = %epoch_label,
                        object_count = summary.object_count,
                        symbol_count = summary.symbol_count,
                        reconciliation_batch_size = self.config.reconciliation_batch_size,
                        summary_bytes,
                        iblt_bytes,
                        iblt_cells,
                        fallback_reason,
                        object_digest = %object_digest,
                        symbol_digest = %symbol_digest
                    );
                } else {
                    info!(
                        component = "mesh.gossip",
                        event = "summary_created",
                        node_id = %self.local_node.as_str(),
                        zone_id = %zone_id,
                        epoch_id = %epoch_label,
                        object_count = summary.object_count,
                        symbol_count = summary.symbol_count,
                        reconciliation_batch_size = self.config.reconciliation_batch_size,
                        summary_bytes,
                        iblt_bytes,
                        iblt_cells,
                        fallback_reason,
                        object_digest = %object_digest,
                        symbol_digest = %symbol_digest
                    );
                }
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
                peer_node_id = %summary.from.as_str(),
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
                peer_node_id = %summary.from.as_str(),
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
        let iblt_bytes = summary.iblt.len();
        let max_iblt_bytes = self.config.max_iblt_bytes();
        let decode_start = Instant::now();
        let iblt_cells = match IbltPlaceholder::decode_with_limits(
            &summary.iblt,
            self.config.reconciliation_batch_size,
            max_iblt_bytes,
        ) {
            Ok(decoded) => decoded.entry_count(),
            Err(error) => {
                let decode_ms =
                    u64::try_from(decode_start.elapsed().as_millis()).unwrap_or(u64::MAX);
                warn!(
                    component = "mesh.gossip",
                    event = "summary_rejected",
                    reason = error.reason_code(),
                    peer_node_id = %summary.from.as_str(),
                    zone_id = %summary.zone_id,
                    object_count,
                    symbol_count,
                    iblt_bytes,
                    max_iblt_bytes,
                    decode_ms
                );
                return;
            }
        };
        let decode_ms = u64::try_from(decode_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let summary_bytes = serde_json::to_vec(&summary).map_or(0usize, |bytes| bytes.len());
        let summary_bytes = u64::try_from(summary_bytes).unwrap_or(u64::MAX);
        let iblt_cells = u64::try_from(iblt_cells).unwrap_or(u64::MAX);

        // Update peer state
        let peer_state = self
            .peer_states
            .entry(peer_id.clone())
            .or_insert_with(|| PeerGossipState::new(peer_id.clone()));

        peer_state.update_from_summary(summary, now);
        debug!(
            component = "mesh.gossip",
            event = "summary_received",
            peer_node_id = %peer_id.as_str(),
            object_count,
            symbol_count,
            summary_bytes,
            iblt_bytes,
            iblt_cells,
            decode_ms,
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

    /// List admitted objects for a zone (up to `limit`).
    ///
    /// Returns object IDs known locally in the given zone. Used by
    /// test harnesses to drive simulated gossip replication.
    #[must_use]
    pub fn list_objects_in_zone(&self, zone_id: &ZoneId, limit: usize) -> Vec<ObjectId> {
        self.zone_states
            .get(zone_id)
            .map(|s| s.list_objects(limit))
            .unwrap_or_default()
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

    /// Remove peer states that have gone stale.
    ///
    /// This is used by integration/e2e flows to model peer leave/partition
    /// recovery with bounded gossip state.
    ///
    /// Returns the number of peer entries removed.
    pub fn prune_stale_peers(&mut self, now: u64) -> usize {
        let ttl_secs = self.config.summary_ttl_secs;
        let mut removed = 0usize;

        self.peer_states.retain(|peer_id, state| {
            let stale = state.is_stale(now, ttl_secs);
            if stale {
                removed += 1;
                warn!(
                    component = "mesh.gossip",
                    event = "peer_pruned",
                    peer_id = %peer_id.as_str(),
                    ttl_seconds = ttl_secs,
                    age_seconds = now.saturating_sub(state.last_updated),
                    failed_attempts = state.failed_attempts()
                );
            }
            !stale
        });

        removed
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
    use serde::Serialize;

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

    #[test]
    fn iblt_encode_empty_is_json_array() {
        let iblt = IbltPlaceholder::new();
        assert_eq!(iblt.encode(), b"[]".to_vec());
    }

    #[test]
    fn iblt_decode_rejects_oversized_payload() {
        let err = IbltPlaceholder::decode_with_limits(
            &vec![b'x'; MIN_IBLT_BYTES_BUDGET + 1],
            8,
            MIN_IBLT_BYTES_BUDGET,
        )
        .expect_err("oversized payload should fail");
        assert_eq!(
            err,
            IbltDecodeError::TooLarge {
                len: MIN_IBLT_BYTES_BUDGET + 1,
                max: MIN_IBLT_BYTES_BUDGET,
            }
        );
    }

    #[test]
    fn iblt_decode_rejects_invalid_encoding() {
        let err = IbltPlaceholder::decode_with_limits(b"not-json", 8, MIN_IBLT_BYTES_BUDGET)
            .expect_err("malformed payload should fail");
        assert_eq!(err, IbltDecodeError::InvalidEncoding);
    }

    #[test]
    fn iblt_decode_rejects_change_limit_exceeded() {
        let mut iblt = IbltPlaceholder::with_max_changes(4);
        let obj_id = test_object_id("obj-many");
        for esi in 0..3 {
            iblt.note_local_change(&obj_id, Some(esi));
        }

        let err = IbltPlaceholder::decode_with_limits(&iblt.encode(), 2, MIN_IBLT_BYTES_BUDGET)
            .expect_err("decoded changes should respect configured limit");
        assert_eq!(err, IbltDecodeError::TooManyChanges { decoded: 3, max: 2 });
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
    fn mesh_gossip_create_summary_falls_back_when_iblt_exceeds_budget() {
        let config = GossipConfig {
            reconciliation_batch_size: 64,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let obj_id = test_object_id("obj-summary-budget");

        for esi in 0..512 {
            gossip.announce_symbol(
                &test_zone(),
                &obj_id,
                esi,
                ObjectAdmissionClass::Admitted,
                1_000,
            );
        }

        let summary = gossip
            .create_summary(&test_zone(), test_epoch())
            .expect("summary should exist");
        assert_eq!(summary.iblt, b"[]".to_vec());
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
    fn mesh_gossip_prunes_stale_peers() {
        let config = GossipConfig {
            summary_ttl_secs: 10,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let initial_summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: vec![],
            timestamp: 100,
            signature: None,
        };

        gossip.handle_summary(initial_summary, 100);
        assert_eq!(gossip.peer_count(), 1);

        let removed = gossip.prune_stale_peers(111);
        assert_eq!(removed, 1);
        assert_eq!(gossip.peer_count(), 0);

        let fresh_summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [1; 32],
            symbol_filter_digest: [2; 32],
            object_count: 2,
            symbol_count: 2,
            iblt: vec![],
            timestamp: 112,
            signature: None,
        };

        gossip.handle_summary(fresh_summary, 112);
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
    fn mesh_gossip_rejects_summary_with_oversized_iblt() {
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config.clone());

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: vec![0u8; config.max_iblt_bytes() + 1],
            timestamp: 1_000,
            signature: None,
        };

        gossip.handle_summary(summary, 1_000);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_rejects_summary_with_invalid_iblt() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: b"not-json".to_vec(),
            timestamp: 1_000,
            signature: None,
        };

        gossip.handle_summary(summary, 1_000);
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

    // --- New tests below ---

    #[test]
    fn iblt_clear_and_encode() {
        let mut iblt = IbltPlaceholder::new();
        let obj_id = test_object_id("obj-1");

        iblt.note_local_change(&obj_id, None);
        iblt.note_local_change(&obj_id, Some(1));
        assert_eq!(iblt.recent_changes().len(), 2);

        let encoded = iblt.encode();
        assert!(!encoded.is_empty());

        iblt.clear();
        assert_eq!(iblt.recent_changes().len(), 0);
        // change_seq is preserved
        assert_eq!(iblt.change_seq(), 2);
    }

    #[test]
    fn gossip_state_list_objects() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);

        for i in 0..5 {
            state.announce_object(&test_object_id(&format!("obj-{i}")), 1000);
        }
        assert_eq!(state.object_count(), 5);

        let limited = state.list_objects(3);
        assert_eq!(limited.len(), 3);

        let all = state.list_objects(100);
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn gossip_state_symbols_for_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("obj-1");

        assert!(state.symbols_for_object(&obj_id).is_none());

        state.announce_symbol(&obj_id, 10, 1000);
        state.announce_symbol(&obj_id, 20, 1000);

        let syms = state.symbols_for_object(&obj_id).unwrap();
        assert_eq!(syms.len(), 2);
        assert!(syms.contains(&10));
        assert!(syms.contains(&20));
    }

    #[test]
    fn gossip_state_zone_id() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        assert_eq!(state.zone_id(), &test_zone());
    }

    #[test]
    fn gossip_summary_signing_bytes_deterministic() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0xAA; 32],
            symbol_filter_digest: [0xBB; 32],
            object_count: 42,
            symbol_count: 100,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        let bytes1 = summary.signing_bytes();
        let bytes2 = summary.signing_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(bytes1.starts_with(b"FCP2-GOSSIP-SUMMARY-V1"));
    }

    #[test]
    fn gossip_summary_with_signature() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: vec![],
            timestamp: 0,
            signature: None,
        };

        assert!(summary.signature.is_none());
        let node_id = fcp_core::NodeId::new("node-1");
        let sig = NodeSignature::new(node_id, [0xAB; 64], 1000);
        let signed = summary.with_signature(sig);
        assert!(signed.signature.is_some());
    }

    #[test]
    fn gossip_request_is_valid_with_limits() {
        let request = GossipRequest::for_objects(
            test_node("n"),
            test_zone(),
            vec![test_object_id("a"), test_object_id("b")],
            0,
        );

        assert!(request.is_valid_with_limits(5, 5));
        assert!(request.is_valid_with_limits(2, 5));
        assert!(!request.is_valid_with_limits(1, 5)); // 2 objects > limit 1
    }

    #[test]
    fn gossip_message_serde_roundtrip() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 2,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };
        let msg = GossipMessage::Summary(summary);
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: GossipMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            GossipMessage::Summary(s) => {
                assert_eq!(s.object_count, 1);
                assert_eq!(s.symbol_count, 2);
            }
            _ => panic!("expected Summary variant"),
        }
    }

    #[test]
    fn gossip_stats_debug_clone() {
        let stats = GossipStats {
            object_count: 10,
            symbol_count: 50,
            last_updated: 1234,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.object_count, 10);
        let s = format!("{stats:?}");
        assert!(s.contains("GossipStats"));
    }

    #[test]
    fn gossip_config_defaults() {
        let config = GossipConfig::default();
        assert_eq!(
            config.max_objects_per_summary,
            DEFAULT_MAX_OBJECTS_PER_SUMMARY
        );
        assert_eq!(
            config.max_symbols_per_summary,
            DEFAULT_MAX_SYMBOLS_PER_SUMMARY
        );
        assert_eq!(config.summary_ttl_secs, DEFAULT_SUMMARY_TTL_SECS);
        assert_eq!(
            config.reconciliation_batch_size,
            DEFAULT_RECONCILIATION_BATCH_SIZE
        );
        assert!(
            config.max_iblt_bytes() >= MIN_IBLT_BYTES_BUDGET,
            "IBLT byte budget should be explicitly bounded"
        );
    }

    #[derive(Serialize)]
    struct NaiveAvailabilitySummary {
        objects: Vec<ObjectId>,
        symbols: Vec<(ObjectId, u32)>,
    }

    #[test]
    fn optimized_summary_is_smaller_than_naive_baseline() {
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let mut objects = Vec::new();
        let mut symbols = Vec::new();

        for object_index in 0..96 {
            let object_id = test_object_id(&format!("naive-{object_index}"));
            objects.push(object_id);
            gossip.announce_object(
                &test_zone(),
                &object_id,
                ObjectAdmissionClass::Admitted,
                1_000,
            );
            for esi in 0..4 {
                symbols.push((object_id, esi));
                gossip.announce_symbol(
                    &test_zone(),
                    &object_id,
                    esi,
                    ObjectAdmissionClass::Admitted,
                    1_000,
                );
            }
        }

        let summary = gossip
            .create_summary(&test_zone(), test_epoch())
            .expect("summary should exist");
        let optimized_bytes = serde_json::to_vec(&summary).expect("summary should serialize");
        let baseline_bytes = serde_json::to_vec(&NaiveAvailabilitySummary { objects, symbols })
            .expect("baseline should serialize");

        assert!(
            optimized_bytes.len() < baseline_bytes.len(),
            "optimized summary should be smaller than explicit baseline"
        );
    }

    #[test]
    fn peer_gossip_state_update_from_summary() {
        let mut peer = PeerGossipState::new(test_node("peer-1"));
        peer.record_failure();
        peer.record_failure();
        assert_eq!(peer.failed_attempts(), 2);

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 5,
            symbol_count: 10,
            iblt: vec![],
            timestamp: 2000,
            signature: None,
        };

        peer.update_from_summary(summary, 2000);
        assert_eq!(peer.failed_attempts(), 0); // reset on update
        assert!(!peer.is_stale(2100, 300));
    }

    #[test]
    fn peer_gossip_state_peer_id() {
        let peer = PeerGossipState::new(test_node("my-peer"));
        assert_eq!(peer.peer_id().as_str(), "my-peer");
    }

    #[test]
    fn peer_gossip_state_may_have_symbol() {
        let mut peer = PeerGossipState::new(test_node("peer-1"));
        let obj_id = test_object_id("obj-sym");

        assert!(!peer.may_have_symbol(&obj_id, 42));

        peer.symbol_filter.insert(&symbol_key(&obj_id, 42));
        assert!(peer.may_have_symbol(&obj_id, 42));
    }

    #[test]
    fn mesh_gossip_announce_symbol_admitted() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        let added = gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            5,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        assert!(added);
        assert!(gossip.has_symbol(&test_zone(), &obj_id, 5));
    }

    #[test]
    fn mesh_gossip_announce_symbol_quarantined_rejected() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        let added = gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            5,
            ObjectAdmissionClass::Quarantined,
            1000,
        );
        assert!(!added);
        assert!(!gossip.has_symbol(&test_zone(), &obj_id, 5));
    }

    #[test]
    fn mesh_gossip_has_symbol_unknown_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");
        assert!(!gossip.has_symbol(&test_zone(), &obj_id, 0));
    }

    #[test]
    fn mesh_gossip_list_objects_in_zone() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        // No zone yet
        assert!(gossip.list_objects_in_zone(&test_zone(), 10).is_empty());

        for i in 0..5 {
            gossip.announce_object(
                &test_zone(),
                &test_object_id(&format!("obj-{i}")),
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let objs = gossip.list_objects_in_zone(&test_zone(), 3);
        assert_eq!(objs.len(), 3);

        let all = gossip.list_objects_in_zone(&test_zone(), 100);
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn mesh_gossip_zone_stats() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        assert!(gossip.zone_stats(&test_zone()).is_none());

        let obj_id = test_object_id("obj-1");
        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);
        gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            2,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let stats = gossip.zone_stats(&test_zone()).unwrap();
        assert_eq!(stats.object_count, 1);
        assert_eq!(stats.symbol_count, 2);
        assert_eq!(stats.last_updated, 1000);
    }

    #[test]
    fn mesh_gossip_create_request() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let ids = vec![test_object_id("a"), test_object_id("b")];

        let request = gossip.create_request(&test_zone(), ids, 1000);
        assert_eq!(request.object_ids.len(), 2);
        assert_eq!(request.from.as_str(), "local");
        assert!(request.is_valid());
    }

    #[test]
    fn mesh_gossip_find_symbol_sources() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        let mut peer = PeerGossipState::new(test_node("peer-1"));
        peer.symbol_filter.insert(&symbol_key(&obj_id, 7));
        gossip.peer_states.insert(test_node("peer-1"), peer);

        let sources = gossip.find_symbol_sources(&obj_id, 7);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].as_str(), "peer-1");

        let no_sources = gossip.find_symbol_sources(&obj_id, 999);
        assert!(no_sources.is_empty());
    }

    #[test]
    fn mesh_gossip_create_summary_none_for_unknown_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        assert!(gossip.create_summary(&test_zone(), test_epoch()).is_none());
    }

    #[test]
    fn xor_filter_with_seed() {
        let mut f1 = XorFilterPlaceholder::with_seed(100);
        let mut f2 = XorFilterPlaceholder::with_seed(200);

        f1.insert(b"same-item");
        f2.insert(b"same-item");

        // Different seeds produce different digests
        assert_ne!(f1.digest(), f2.digest());
    }

    #[test]
    fn xor_filter_default() {
        let filter = XorFilterPlaceholder::default();
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);
    }

    #[test]
    fn xor_filter_may_contain_not_inserted() {
        let filter = XorFilterPlaceholder::new();
        // Empty filter should not contain anything
        assert!(!filter.may_contain(b"anything"));
    }

    #[test]
    fn iblt_default() {
        let iblt = IbltPlaceholder::default();
        assert_eq!(iblt.change_seq(), 0);
        assert!(iblt.recent_changes().is_empty());
    }

    // ── XorFilterPlaceholder additional tests ──────────────────

    #[test]
    fn xor_filter_multiple_inserts() {
        let mut filter = XorFilterPlaceholder::new();
        filter.insert(b"item-1");
        filter.insert(b"item-2");
        filter.insert(b"item-3");
        assert_eq!(filter.len(), 3);
        assert!(filter.may_contain(b"item-1"));
        assert!(filter.may_contain(b"item-2"));
        assert!(filter.may_contain(b"item-3"));
    }

    #[test]
    fn xor_filter_digest_differs_by_seed() {
        let mut f1 = XorFilterPlaceholder::with_seed(1);
        let mut f2 = XorFilterPlaceholder::with_seed(2);
        f1.insert(b"same-item");
        f2.insert(b"same-item");
        assert_ne!(f1.digest(), f2.digest());
    }

    #[test]
    fn xor_filter_empty_digest_deterministic() {
        let d1 = XorFilterPlaceholder::new().digest();
        let d2 = XorFilterPlaceholder::new().digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn xor_filter_serde_roundtrip() {
        let mut filter = XorFilterPlaceholder::with_seed(99);
        filter.insert(b"serde-test");
        let json = serde_json::to_string(&filter).unwrap();
        let deserialized: XorFilterPlaceholder = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 1);
        assert!(deserialized.may_contain(b"serde-test"));
    }

    // ── IbltPlaceholder additional tests ───────────────────────

    #[test]
    fn iblt_zero_max_changes_still_increments_seq() {
        let mut iblt = IbltPlaceholder::with_max_changes(0);
        let obj = test_object_id("o");
        iblt.note_local_change(&obj, None);
        iblt.note_local_change(&obj, Some(1));
        assert_eq!(iblt.change_seq(), 2);
        assert!(iblt.recent_changes().is_empty());
    }

    #[test]
    fn iblt_encode_decode_roundtrip() {
        let mut iblt = IbltPlaceholder::with_max_changes(10);
        let obj = test_object_id("rt");
        iblt.note_local_change(&obj, None);
        iblt.note_local_change(&obj, Some(42));
        let encoded = iblt.encode();
        let decoded = IbltPlaceholder::decode_with_limits(&encoded, 10, 4096).unwrap();
        assert_eq!(decoded.recent_changes().len(), 2);
    }

    #[test]
    fn iblt_decode_empty_bytes_returns_empty() {
        let decoded = IbltPlaceholder::decode_with_limits(&[], 10, 4096).unwrap();
        assert!(decoded.recent_changes().is_empty());
    }

    #[test]
    fn iblt_decode_too_many_changes() {
        let mut iblt = IbltPlaceholder::with_max_changes(100);
        for i in 0..5 {
            iblt.note_local_change(&test_object_id(&format!("o{i}")), None);
        }
        let encoded = iblt.encode();
        // Decode with limit of 3 should fail
        let err = IbltPlaceholder::decode_with_limits(&encoded, 3, 4096).unwrap_err();
        assert!(matches!(
            err,
            IbltDecodeError::TooManyChanges { decoded: 5, max: 3 }
        ));
    }

    #[test]
    fn iblt_decode_error_reason_codes() {
        assert_eq!(
            IbltDecodeError::TooLarge { len: 10, max: 5 }.reason_code(),
            "iblt_bytes_exceeded"
        );
        assert_eq!(
            IbltDecodeError::InvalidEncoding.reason_code(),
            "iblt_invalid_encoding"
        );
        assert_eq!(
            IbltDecodeError::TooManyChanges {
                decoded: 10,
                max: 5
            }
            .reason_code(),
            "iblt_change_limit_exceeded"
        );
    }

    #[test]
    fn iblt_clear() {
        let mut iblt = IbltPlaceholder::new();
        iblt.note_local_change(&test_object_id("c"), None);
        assert!(!iblt.recent_changes().is_empty());
        iblt.clear();
        assert!(iblt.recent_changes().is_empty());
    }

    #[test]
    fn iblt_entry_count() {
        let mut iblt = IbltPlaceholder::with_max_changes(5);
        assert_eq!(iblt.entry_count(), 0);
        iblt.note_local_change(&test_object_id("e"), Some(1));
        assert_eq!(iblt.entry_count(), 1);
    }

    // ── GossipState additional tests ───────────────────────────

    #[test]
    fn gossip_state_announce_object_idempotent() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("idem");
        state.announce_object(&obj, 100);
        state.announce_object(&obj, 200);
        // Object counted once despite double announce
        assert_eq!(state.object_count(), 1);
    }

    #[test]
    fn gossip_state_announce_symbol_auto_announces_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("auto");
        state.announce_symbol(&obj, 0, 100);
        assert!(state.has_object(&obj));
        assert!(state.has_symbol(&obj, 0));
    }

    #[test]
    fn gossip_state_announce_symbol_idempotent() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("si");
        state.announce_symbol(&obj, 5, 100);
        state.announce_symbol(&obj, 5, 200);
        assert_eq!(state.symbol_count(), 1);
    }

    #[test]
    fn gossip_state_remove_object_clears_symbols() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("rm");
        state.announce_object(&obj, 100);
        state.announce_symbol(&obj, 0, 100);
        assert_eq!(state.object_count(), 1);
        assert_eq!(state.symbol_count(), 1);

        state.remove_object(&obj, 200);
        assert_eq!(state.object_count(), 0);
        assert_eq!(state.symbol_count(), 0);
        assert!(!state.has_object(&obj));
    }

    #[test]
    fn gossip_state_may_have_vs_has() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("mh");
        state.announce_object(&obj, 100);

        // Both should agree for inserted items
        assert!(state.has_object(&obj));
        assert!(state.may_have_object(&obj));

        // For non-inserted: has is definitive, may_have can false-positive
        let other = test_object_id("other");
        assert!(!state.has_object(&other));
    }

    #[test]
    fn gossip_state_multiple_symbols_per_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("multi");
        state.announce_symbol(&obj, 0, 100);
        state.announce_symbol(&obj, 1, 100);
        state.announce_symbol(&obj, 2, 100);
        assert_eq!(state.symbol_count(), 3);
        let syms = state.symbols_for_object(&obj).unwrap();
        assert_eq!(syms.len(), 3);
        assert!(syms.contains(&0));
        assert!(syms.contains(&1));
        assert!(syms.contains(&2));
    }

    #[test]
    fn gossip_state_create_summary_fields() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        state.announce_object(&test_object_id("s1"), 100);
        state.announce_symbol(&test_object_id("s1"), 0, 100);

        let summary = state.create_summary(test_node("me"), test_epoch());
        assert_eq!(summary.zone_id, test_zone());
        assert_eq!(summary.object_count, 1);
        assert_eq!(summary.symbol_count, 1);
        assert_eq!(summary.timestamp, 100);
        assert!(summary.signature.is_none());
    }

    // ── GossipSummary additional tests ─────────────────────────

    #[test]
    fn gossip_summary_differs_from_same() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        state.announce_object(&test_object_id("d1"), 100);
        let s1 = state.create_summary(test_node("n1"), test_epoch());
        let s2 = state.create_summary(test_node("n1"), test_epoch());
        assert!(!s1.differs_from(&s2));
    }

    #[test]
    fn gossip_summary_differs_from_different() {
        let config = GossipConfig::default();
        let mut s1_state = GossipState::new(test_zone(), &config);
        s1_state.announce_object(&test_object_id("a"), 100);
        let s1 = s1_state.create_summary(test_node("n1"), test_epoch());

        let mut s2_state = GossipState::new(test_zone(), &config);
        s2_state.announce_object(&test_object_id("b"), 100);
        let s2 = s2_state.create_summary(test_node("n2"), test_epoch());

        assert!(s1.differs_from(&s2));
    }

    #[test]
    fn gossip_summary_is_stale() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        let summary = state.create_summary(test_node("n"), test_epoch());
        // timestamp=0, now=0, ttl=300 → not stale
        assert!(!summary.is_stale(0, 300));
        // now=301 → stale
        assert!(summary.is_stale(301, 300));
    }

    #[test]
    fn gossip_summary_signing_bytes_includes_domain_separator() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        let summary = state.create_summary(test_node("sig"), test_epoch());
        let bytes = summary.signing_bytes();
        assert!(bytes.starts_with(b"FCP2-GOSSIP-SUMMARY-V1"));
    }

    #[test]
    fn gossip_summary_signing_bytes_differ_by_zone() {
        let config = GossipConfig::default();
        let s1 = GossipState::new(ZoneId::work(), &config);
        let s2 = GossipState::new(ZoneId::private(), &config);
        let b1 = s1
            .create_summary(test_node("n"), test_epoch())
            .signing_bytes();
        let b2 = s2
            .create_summary(test_node("n"), test_epoch())
            .signing_bytes();
        assert_ne!(b1, b2);
    }

    // ── GossipConfig tests ─────────────────────────────────────

    #[test]
    fn gossip_config_max_iblt_bytes_derived() {
        let config = GossipConfig::default();
        let expected = DEFAULT_RECONCILIATION_BATCH_SIZE * 48;
        assert_eq!(config.max_iblt_bytes(), expected);
    }

    #[test]
    fn gossip_config_max_iblt_bytes_min_budget() {
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        // 1 * 48 = 48 < MIN_IBLT_BYTES_BUDGET(512), so uses min
        assert_eq!(config.max_iblt_bytes(), MIN_IBLT_BYTES_BUDGET);
    }

    // ── GossipRequest additional tests ─────────────────────────

    #[test]
    fn gossip_request_for_objects_bounds_at_max() {
        let many_ids: Vec<ObjectId> = (0..200)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();
        let req = GossipRequest::for_objects(test_node("n"), test_zone(), many_ids, 0);
        assert_eq!(req.object_ids.len(), MAX_OBJECT_IDS_PER_REQUEST);
        assert!(req.symbols.is_empty());
        assert!(req.is_valid());
    }

    #[test]
    fn gossip_request_for_symbols_bounds_at_max() {
        let many_syms: Vec<(ObjectId, u32)> = (0..200)
            .map(|i| (test_object_id(&format!("s-{i}")), i))
            .collect();
        let req = GossipRequest::for_symbols(test_node("n"), test_zone(), many_syms, 0);
        assert_eq!(req.symbols.len(), MAX_OBJECT_IDS_PER_REQUEST);
        assert!(req.object_ids.is_empty());
        assert!(req.is_valid());
    }

    #[test]
    fn gossip_request_is_valid_rejects_oversized() {
        let req = GossipRequest {
            from: test_node("n"),
            zone_id: test_zone(),
            object_ids: (0..101).map(|i| test_object_id(&format!("o{i}"))).collect(),
            symbols: Vec::new(),
            timestamp: 0,
            signature: None,
        };
        assert!(!req.is_valid());
    }

    // ── MeshGossip additional tests ────────────────────────────

    #[test]
    fn mesh_gossip_prune_stale_peers() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();
        let epoch = test_epoch();

        // Add objects and create a summary from a "peer"
        gossip.announce_object(
            &zone,
            &test_object_id("o1"),
            ObjectAdmissionClass::Admitted,
            100,
        );
        let summary = gossip.create_summary(&zone, epoch).unwrap();

        // Simulate receiving it as if from a peer
        let mut peer_summary = summary;
        peer_summary.from = test_node("peer-1");
        peer_summary.timestamp = 100;
        gossip.handle_summary(peer_summary, 100);
        assert_eq!(gossip.peer_count(), 1);

        // Not stale yet (ttl=300)
        assert_eq!(gossip.prune_stale_peers(399), 0);
        assert_eq!(gossip.peer_count(), 1);

        // Now stale
        assert_eq!(gossip.prune_stale_peers(401), 1);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_has_object_unknown_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        assert!(!gossip.has_object(&test_zone(), &test_object_id("x")));
    }

    #[test]
    fn mesh_gossip_has_symbol_checks_zone() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();
        let obj = test_object_id("sym-zone");
        gossip.announce_symbol(&zone, &obj, 7, ObjectAdmissionClass::Admitted, 100);
        assert!(gossip.has_symbol(&zone, &obj, 7));
        assert!(!gossip.has_symbol(&zone, &obj, 8));
    }

    #[test]
    fn mesh_gossip_quarantined_symbol_not_announced() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();
        let obj = test_object_id("q-sym");
        let result = gossip.announce_symbol(&zone, &obj, 0, ObjectAdmissionClass::Quarantined, 100);
        assert!(!result);
        assert!(!gossip.has_symbol(&zone, &obj, 0));
    }

    #[test]
    fn mesh_gossip_create_summary_returns_none_for_missing_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        assert!(gossip.create_summary(&test_zone(), test_epoch()).is_none());
    }

    #[test]
    fn mesh_gossip_debug() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let s = format!("{gossip:?}");
        assert!(s.contains("MeshGossip"));
    }

    // ── PeerGossipState additional tests ───────────────────────

    #[test]
    fn peer_gossip_state_record_failure_saturates() {
        let mut state = PeerGossipState::new(test_node("sat"));
        for _ in 0..10 {
            state.record_failure();
        }
        assert_eq!(state.failed_attempts(), 10);
    }

    #[test]
    fn peer_gossip_state_update_resets_failures() {
        let mut state = PeerGossipState::new(test_node("reset"));
        state.record_failure();
        state.record_failure();
        assert_eq!(state.failed_attempts(), 2);

        let config = GossipConfig::default();
        let gs = GossipState::new(test_zone(), &config);
        let summary = gs.create_summary(test_node("p"), test_epoch());
        state.update_from_summary(summary, 100);
        assert_eq!(state.failed_attempts(), 0);
    }

    #[test]
    fn peer_gossip_state_debug_clone() {
        let state = PeerGossipState::new(test_node("dc"));
        let cloned = state.clone();
        assert_eq!(cloned.peer_id(), state.peer_id());
        let s = format!("{state:?}");
        assert!(s.contains("PeerGossipState"));
    }

    // ── GossipResponse / ReconcileRequest / ReconcileResponse ──

    #[test]
    fn gossip_response_serde_roundtrip() {
        let resp = GossipResponse {
            from: test_node("a"),
            to: test_node("b"),
            zone_id: test_zone(),
            have_objects: vec![test_object_id("o1")],
            have_symbols: vec![(test_object_id("o1"), 42)],
            timestamp: 999,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: GossipResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.timestamp, 999);
        assert_eq!(deserialized.have_objects.len(), 1);
    }

    #[test]
    fn reconcile_request_serde_roundtrip() {
        let req = ReconcileRequest {
            from: test_node("r"),
            zone_id: test_zone(),
            iblt: vec![],
            object_filter_digest: [0xAA; 32],
            symbol_filter_digest: [0xBB; 32],
            timestamp: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ReconcileRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.timestamp, 0);
    }

    #[test]
    fn reconcile_response_serde_roundtrip() {
        let resp = ReconcileResponse {
            from: test_node("rr"),
            zone_id: test_zone(),
            peer_missing_objects: vec![test_object_id("m1")],
            we_missing_objects: vec![test_object_id("m2")],
            timestamp: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: ReconcileResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.peer_missing_objects.len(), 1);
        assert_eq!(deserialized.we_missing_objects.len(), 1);
    }

    // ── GossipMessage all variants ─────────────────────────────

    #[test]
    fn gossip_message_summary_variant_serde() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        let summary = state.create_summary(test_node("sv"), test_epoch());
        let msg = GossipMessage::Summary(summary);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"summary\""));
        let _: GossipMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn gossip_message_request_variant_serde() {
        let req = GossipRequest::for_objects(test_node("rq"), test_zone(), vec![], 0);
        let msg = GossipMessage::Request(req);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"request\""));
    }

    #[test]
    fn gossip_message_reconcile_variants_serde() {
        let req_msg = GossipMessage::ReconcileRequest(ReconcileRequest {
            from: test_node("rc"),
            zone_id: test_zone(),
            iblt: vec![],
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            timestamp: 0,
        });
        let json = serde_json::to_string(&req_msg).unwrap();
        assert!(json.contains("\"type\":\"reconcile_request\""));

        let resp_msg = GossipMessage::ReconcileResponse(ReconcileResponse {
            from: test_node("rc"),
            zone_id: test_zone(),
            peer_missing_objects: vec![],
            we_missing_objects: vec![],
            timestamp: 0,
        });
        let json = serde_json::to_string(&resp_msg).unwrap();
        assert!(json.contains("\"type\":\"reconcile_response\""));
    }

    // ── GossipStats ────────────────────────────────────────────

    #[test]
    fn gossip_stats_fields() {
        let stats = GossipStats {
            object_count: 10,
            symbol_count: 50,
            last_updated: 1234,
        };
        let cloned = stats.clone();
        assert_eq!(stats.object_count, 10);
        assert_eq!(stats.symbol_count, 50);
        assert_eq!(cloned.last_updated, 1234);
    }
}
