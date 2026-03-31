//! Revocation types for FCP (NORMATIVE).
//!
//! This module implements the revocation system from `FCP_Specification_V3.md` §6.4.
//! Revocations make compromised devices/keys/tokens recoverable. Without revocation,
//! "compromised device" recovery is mostly imaginary.
//!
//! # Core Concepts
//!
//! - `RevocationObject`: Owner-signed object revoking one or more `ObjectId`s
//! - `RevocationEvent`: Chain node linking revocations with monotonic sequence
//! - `RevocationHead`: Quorum-signed checkpoint for O(1) freshness comparison
//! - `RevocationRegistry`: Fast lookup with bloom filter for negative lookups
//!
//! # Freshness Policies
//!
//! | Policy | Behavior |
//! |--------|----------|
//! | Strict | Require fresh revocation frontier or abort |
//! | Warn | Allow cached if within `max_age`, record degraded |
//! | `BestEffort` | Proceed with stale cache, record degraded state |
//!
//! # Enforcement
//!
//! Revocations MUST be checked before any capability use:
//! ```text
//! if registry.is_revoked(&capability_token_id) {
//!     return Err(FcpError::CapabilityRevoked);
//! }
//! ```

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ObjectHeader, ObjectId, QuorumPolicy, RiskTier, SignatureSet, ZoneId};

/// Scope of a revocation (NORMATIVE).
///
/// Determines what type of object is being revoked and how the revocation
/// should be enforced across the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationScope {
    /// Revoke capability tokens.
    /// Affected tokens MUST be rejected at all verification points.
    Capability,

    /// Revoke an issuer key.
    /// The node can no longer mint tokens; existing tokens remain valid until expiry.
    IssuerKey,

    /// Revoke a node attestation.
    /// Removes the device from the mesh entirely.
    NodeAttestation,

    /// Revoke a zone key.
    /// Forces zone key rotation; all zone members must re-enroll.
    ZoneKey,

    /// Revoke a connector binary.
    /// Supply chain response: connector MUST be stopped and replaced.
    ConnectorBinary,
}

impl RevocationScope {
    /// Get the human-readable name for this scope.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::IssuerKey => "issuer_key",
            Self::NodeAttestation => "node_attestation",
            Self::ZoneKey => "zone_key",
            Self::ConnectorBinary => "connector_binary",
        }
    }

    /// Check if this revocation scope is critical (requires immediate action).
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::NodeAttestation | Self::ZoneKey | Self::ConnectorBinary
        )
    }
}

impl fmt::Display for RevocationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Revocation object (NORMATIVE).
///
/// An owner-signed object that revokes one or more `ObjectId`s. The revocation
/// becomes effective at `effective_at` and may optionally expire.
///
/// # Signature Requirements
///
/// The `signature` field MUST be an Ed25519 signature from the zone owner.
/// Non-owner signatures are invalid and MUST be rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationObject {
    /// Object header with zone, schema, and provenance.
    pub header: ObjectHeader,

    /// `ObjectIds` being revoked.
    pub revoked: Vec<ObjectId>,

    /// Type of revocation.
    pub scope: RevocationScope,

    /// Human-readable reason for revocation.
    pub reason: String,

    /// When revocation becomes effective (UNIX timestamp).
    pub effective_at: u64,

    /// When revocation expires (None = permanent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Owner signature (Ed25519, REQUIRED).
    #[serde(with = "crate::util::hex_or_bytes")]
    pub signature: [u8; 64],
}

impl RevocationObject {
    /// Check if the revocation is currently active.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        if now < self.effective_at {
            return false;
        }
        self.expires_at.is_none_or(|exp| now < exp)
    }

    /// Check if a specific object ID is revoked by this revocation.
    #[must_use]
    pub fn revokes(&self, object_id: &ObjectId) -> bool {
        self.revoked.contains(object_id)
    }

    /// Get the zone this revocation applies to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

/// Revocation event chain node (NORMATIVE).
///
/// Links revocation objects into a hash-chain with monotonic sequence numbers.
/// This enables O(1) freshness comparison: if your local `head_seq` is less than
/// the remote `head_seq`, you're stale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvent {
    /// Object header.
    pub header: ObjectHeader,

    /// The revocation object this event references.
    pub revocation_object_id: ObjectId,

    /// Previous event in the chain (None for genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,

    /// Monotonic sequence number for O(1) freshness comparison.
    pub seq: u64,

    /// When the revocation occurred (UNIX timestamp).
    pub occurred_at: u64,

    /// Signature over the event (from the issuing node).
    #[serde(with = "crate::util::hex_or_bytes")]
    pub signature: [u8; 64],
}

impl RevocationEvent {
    /// Check if this event follows another event in the chain.
    ///
    /// # Arguments
    ///
    /// * `other` - The event that should precede this one
    /// * `other_id` - The `ObjectId` of `other` (computed from its content/header)
    ///
    /// # Returns
    ///
    /// `true` if this event's `prev` points to `other_id` and this event's
    /// sequence number is exactly one greater than `other`'s.
    #[must_use]
    pub fn follows(&self, other: &Self, other_id: &ObjectId) -> bool {
        // Use checked_add to prevent overflow when other.seq is u64::MAX
        other
            .seq
            .checked_add(1)
            .is_some_and(|next_seq| self.seq == next_seq)
            && self.prev.as_ref() == Some(other_id)
    }

    /// Get the zone this event belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

/// Epoch identifier for revocation head checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochId(String);

impl EpochId {
    /// Create a new epoch ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the epoch ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Revocation head checkpoint (NORMATIVE).
///
/// A quorum-signed checkpoint that represents the current state of the
/// revocation chain for a zone. Nodes can compare `head_seq` values for
/// O(1) freshness determination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationHead {
    /// Object header.
    pub header: ObjectHeader,

    /// Zone this head applies to.
    pub zone_id: ZoneId,

    /// `ObjectId` of the head event.
    pub head_event: ObjectId,

    /// Sequence number of the head event (for O(1) freshness).
    pub head_seq: u64,

    /// Epoch identifier for this checkpoint.
    pub epoch_id: EpochId,

    /// Quorum signatures from zone nodes (NORMATIVE).
    pub quorum_signatures: SignatureSet,
}

impl RevocationHead {
    /// Check if this head is fresher than another.
    #[must_use]
    pub const fn is_fresher_than(&self, other: &Self) -> bool {
        self.head_seq > other.head_seq
    }

    /// Check if this head satisfies the quorum policy.
    #[must_use]
    pub fn satisfies_quorum(&self, policy: &QuorumPolicy) -> bool {
        self.quorum_signatures
            .satisfies_quorum(policy, RiskTier::CriticalWrite)
    }

    /// Get the age of this head relative to a timestamp.
    #[must_use]
    pub const fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.header.created_at)
    }
}

/// Freshness policy for revocation checks (NORMATIVE).
///
/// Determines how strictly revocation freshness is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FreshnessPolicy {
    /// Require fresh revocation frontier or abort.
    /// Use for high-risk operations where stale revocation data is unacceptable.
    #[default]
    Strict,

    /// Allow cached revocations if within `max_age`.
    /// Records degraded state but allows operation to proceed.
    Warn,

    /// Proceed with stale cache, record degraded state.
    /// Use only when availability trumps security.
    BestEffort,
}

impl FreshnessPolicy {
    /// Get the human-readable name for this policy.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Warn => "warn",
            Self::BestEffort => "best_effort",
        }
    }

    /// Check if this policy allows stale data.
    #[must_use]
    pub const fn allows_stale(&self) -> bool {
        !matches!(self, Self::Strict)
    }

    /// Get the default freshness policy for a risk tier.
    #[must_use]
    pub const fn for_risk_tier(tier: RiskTier) -> Self {
        match tier {
            RiskTier::CriticalWrite | RiskTier::Dangerous => Self::Strict,
            RiskTier::Risky => Self::Warn,
            RiskTier::Safe => Self::BestEffort,
        }
    }
}

impl fmt::Display for FreshnessPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Revocation check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCheckResult {
    /// Whether the object is revoked.
    pub is_revoked: bool,

    /// The revocation object if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<ObjectId>,

    /// Scope of the revocation if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RevocationScope>,

    /// Whether the check used stale data.
    pub stale_data: bool,

    /// Age of the revocation head in seconds.
    pub head_age_secs: u64,
}

/// Simple bloom filter for fast negative lookups.
///
/// This is a basic implementation; production systems should use a more
/// sophisticated bloom filter library with configurable false positive rates.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    /// Bit vector for the bloom filter.
    bits: Vec<u64>,
    /// Number of hash functions (k).
    num_hashes: u8,
    /// Number of bits (m).
    num_bits: usize,
}

impl BloomFilter {
    /// Create a new bloom filter sized for expected elements.
    ///
    /// Uses optimal sizing: m = -n*ln(p) / (ln(2)^2), k = (m/n) * ln(2)
    /// where n = expected elements, p = false positive rate (0.01 = 1%).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(expected_elements: usize, false_positive_rate: f64) -> Self {
        let ln2 = std::f64::consts::LN_2;
        let n = expected_elements.max(1) as f64;
        let p = false_positive_rate.clamp(0.0001, 0.5);

        // m = -n * ln(p) / (ln(2)^2)
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let m = (-n * p.ln() / (ln2 * ln2)).ceil() as usize;
        let m = m.max(64); // Minimum 64 bits

        // k = (m/n) * ln(2)
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let k = ((m as f64 / n) * ln2).ceil() as u8;
        let k = k.clamp(1, 16); // Reasonable bounds

        // Round up to multiple of 64 for u64 storage
        let num_bits = m.div_ceil(64) * 64;
        let bits = vec![0u64; num_bits / 64];

        Self {
            bits,
            num_hashes: k,
            num_bits,
        }
    }

    /// Insert an item into the bloom filter.
    #[allow(clippy::cast_possible_truncation)]
    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = Self::hash_item(item);
        let m = self.num_bits as u64;
        for i in 0..self.num_hashes {
            // Double hashing: h_i = (h1 + i * h2) % m
            let hash = h1.wrapping_add(u64::from(i).wrapping_mul(h2));
            // Truncation is safe: hash % m < m, and m fits in usize (it came from usize)
            let index = (hash % m) as usize;
            self.bits[index / 64] |= 1u64 << (index % 64);
        }
    }

    /// Check if an item might be in the bloom filter.
    ///
    /// Returns `false` if definitely not present, `true` if possibly present.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn might_contain(&self, item: &[u8]) -> bool {
        let (h1, h2) = Self::hash_item(item);
        let m = self.num_bits as u64;
        for i in 0..self.num_hashes {
            let hash = h1.wrapping_add(u64::from(i).wrapping_mul(h2));
            let index = (hash % m) as usize;
            if self.bits[index / 64] & (1u64 << (index % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// Hash function using BLAKE3 to generate two 64-bit hashes for Double Hashing.
    fn hash_item(item: &[u8]) -> (u64, u64) {
        let hash = blake3::hash(item);
        let bytes = hash.as_bytes();
        let mut buf1 = [0u8; 8];
        let mut buf2 = [0u8; 8];
        buf1.copy_from_slice(&bytes[0..8]);
        buf2.copy_from_slice(&bytes[8..16]);
        let h1 = u64::from_le_bytes(buf1);
        let h2 = u64::from_le_bytes(buf2);

        (h1, h2)
    }

    /// Clear the bloom filter.
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        // Default: 10000 elements, 1% false positive rate
        Self::new(10000, 0.01)
    }
}

/// Revocation registry (NORMATIVE).
///
/// Provides fast revocation lookups using a bloom filter for negative lookups
/// and a hash map for confirmed revocations.
///
/// # Usage
///
/// ```ignore
/// let registry = RevocationRegistry::new();
///
/// // Fast path: definitely not revoked
/// if !registry.is_revoked(&object_id) {
///     // Safe to proceed
/// }
///
/// // Get full revocation details
/// if let Some(revocation) = registry.get_revocation(&object_id) {
///     // Handle revocation
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct RevocationRegistry {
    /// Active revocations indexed by revoked `ObjectId`.
    revocations: HashMap<ObjectId, RevocationObject>,

    /// Bloom filter for fast negative lookups.
    bloom_filter: BloomFilter,

    /// Latest known revocation head.
    pub head: Option<ObjectId>,

    /// Head sequence number for freshness comparison.
    pub head_seq: u64,

    /// When the registry was last updated (UNIX timestamp).
    pub last_updated: u64,
}

impl RevocationRegistry {
    /// Create a new empty revocation registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with custom bloom filter sizing.
    #[must_use]
    pub fn with_capacity(expected_revocations: usize) -> Self {
        Self {
            revocations: HashMap::with_capacity(expected_revocations),
            bloom_filter: BloomFilter::new(expected_revocations, 0.01),
            head: None,
            head_seq: 0,
            last_updated: 0,
        }
    }

    /// Check if an object ID is revoked (MUST be called before any capability use).
    ///
    /// Uses bloom filter for fast negative lookup, then checks the revocation map.
    #[must_use]
    pub fn is_revoked(&self, object_id: &ObjectId) -> bool {
        // Fast path: bloom filter says definitely not present
        if !self.bloom_filter.might_contain(object_id.as_bytes()) {
            return false;
        }
        // Slow path: check the actual map
        self.revocations.contains_key(object_id)
    }

    /// Check if an object ID is revoked at a specific time.
    #[must_use]
    pub fn is_revoked_at(&self, object_id: &ObjectId, at: u64) -> bool {
        if !self.bloom_filter.might_contain(object_id.as_bytes()) {
            return false;
        }
        self.revocations
            .get(object_id)
            .is_some_and(|r| r.is_active(at))
    }

    /// Get the revocation object for an object ID.
    #[must_use]
    pub fn get_revocation(&self, object_id: &ObjectId) -> Option<&RevocationObject> {
        self.revocations.get(object_id)
    }

    /// Add a revocation to the registry.
    pub fn add_revocation(&mut self, revocation: &RevocationObject) {
        for object_id in &revocation.revoked {
            self.bloom_filter.insert(object_id.as_bytes());
            self.revocations.insert(*object_id, revocation.clone());
        }
    }

    /// Update the head pointer and sequence.
    pub const fn update_head(&mut self, head: ObjectId, seq: u64, updated_at: u64) {
        self.head = Some(head);
        self.head_seq = seq;
        self.last_updated = updated_at;
    }

    /// Check freshness against a remote head.
    ///
    /// Returns `true` if this registry is fresh (not behind the remote).
    #[must_use]
    pub const fn is_fresh(&self, remote_seq: u64) -> bool {
        self.head_seq >= remote_seq
    }

    /// Check freshness with a policy and max age.
    ///
    /// # Arguments
    ///
    /// * `remote_seq` - Remote head sequence number
    /// * `policy` - Freshness enforcement policy
    /// * `max_age_secs` - Maximum acceptable age for cached data
    /// * `now` - Current timestamp
    ///
    /// # Returns
    ///
    /// A result indicating freshness status.
    #[must_use]
    pub const fn check_freshness(
        &self,
        remote_seq: u64,
        policy: FreshnessPolicy,
        max_age_secs: u64,
        now: u64,
    ) -> FreshnessCheckResult {
        let is_fresh = self.head_seq >= remote_seq;
        let age = now.saturating_sub(self.last_updated);
        let within_max_age = age <= max_age_secs;

        match policy {
            FreshnessPolicy::Strict => FreshnessCheckResult {
                allowed: is_fresh,
                stale: !is_fresh,
                age_secs: age,
                reason: if is_fresh {
                    None
                } else {
                    Some(FreshnessFailureReason::StaleData)
                },
            },
            FreshnessPolicy::Warn => FreshnessCheckResult {
                allowed: is_fresh || within_max_age,
                stale: !is_fresh,
                age_secs: age,
                reason: if is_fresh {
                    None
                } else if within_max_age {
                    Some(FreshnessFailureReason::StaleButWithinMaxAge)
                } else {
                    Some(FreshnessFailureReason::StaleData)
                },
            },
            FreshnessPolicy::BestEffort => FreshnessCheckResult {
                allowed: true,
                stale: !is_fresh,
                age_secs: age,
                reason: if is_fresh {
                    None
                } else {
                    Some(FreshnessFailureReason::StaleButAllowed)
                },
            },
        }
    }

    /// Get the number of revocations in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revocations.len()
    }

    /// Check if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revocations.is_empty()
    }

    /// Clear all revocations.
    pub fn clear(&mut self) {
        self.revocations.clear();
        self.bloom_filter.clear();
        self.head = None;
        self.head_seq = 0;
        self.last_updated = 0;
    }

    /// Get all revocations of a specific scope.
    #[must_use]
    pub fn revocations_by_scope(&self, scope: RevocationScope) -> Vec<&RevocationObject> {
        self.revocations
            .values()
            .filter(|r| r.scope == scope)
            .collect()
    }
}

/// Result of a freshness check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessCheckResult {
    /// Whether the operation is allowed to proceed.
    pub allowed: bool,

    /// Whether the data is stale.
    pub stale: bool,

    /// Age of the cached data in seconds.
    pub age_secs: u64,

    /// Reason for failure or degraded operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<FreshnessFailureReason>,
}

/// Reasons for freshness check results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FreshnessFailureReason {
    /// Data is stale and operation was blocked.
    StaleData,
    /// Data is stale but within max age (Warn policy).
    StaleButWithinMaxAge,
    /// Data is stale but operation allowed (`BestEffort` policy).
    StaleButAllowed,
}

impl FreshnessFailureReason {
    /// Get the human-readable description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StaleData => "stale_data",
            Self::StaleButWithinMaxAge => "stale_but_within_max_age",
            Self::StaleButAllowed => "stale_but_allowed",
        }
    }
}

impl fmt::Display for FreshnessFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_revocation() -> RevocationObject {
        RevocationObject {
            header: test_header(),
            revoked: vec![ObjectId::from_bytes([1u8; 32])],
            scope: RevocationScope::Capability,
            reason: "Compromised device".into(),
            effective_at: 1_700_000_000,
            expires_at: None,
            signature: [0u8; 64],
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationScope Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_scope_display() {
        assert_eq!(RevocationScope::Capability.to_string(), "capability");
        assert_eq!(RevocationScope::IssuerKey.to_string(), "issuer_key");
        assert_eq!(
            RevocationScope::NodeAttestation.to_string(),
            "node_attestation"
        );
        assert_eq!(RevocationScope::ZoneKey.to_string(), "zone_key");
        assert_eq!(
            RevocationScope::ConnectorBinary.to_string(),
            "connector_binary"
        );
    }

    #[test]
    fn revocation_scope_is_critical() {
        assert!(!RevocationScope::Capability.is_critical());
        assert!(!RevocationScope::IssuerKey.is_critical());
        assert!(RevocationScope::NodeAttestation.is_critical());
        assert!(RevocationScope::ZoneKey.is_critical());
        assert!(RevocationScope::ConnectorBinary.is_critical());
    }

    #[test]
    fn revocation_scope_serialization() {
        let scope = RevocationScope::Capability;
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("Capability"));

        let deserialized: RevocationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, scope);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_object_is_active() {
        let revocation = test_revocation();

        // Before effective_at: not active
        assert!(!revocation.is_active(1_699_999_999));

        // At effective_at: active
        assert!(revocation.is_active(1_700_000_000));

        // After effective_at: active (permanent)
        assert!(revocation.is_active(2_000_000_000));
    }

    #[test]
    fn revocation_object_is_active_with_expiry() {
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_800_000_000);

        // Before effective_at: not active
        assert!(!revocation.is_active(1_699_999_999));

        // Between effective and expiry: active
        assert!(revocation.is_active(1_750_000_000));

        // After expiry: not active
        assert!(!revocation.is_active(1_800_000_001));
    }

    #[test]
    fn revocation_object_revokes() {
        let revocation = test_revocation();
        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        let other_id = ObjectId::from_bytes([2u8; 32]);

        assert!(revocation.revokes(&revoked_id));
        assert!(!revocation.revokes(&other_id));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_policy_display() {
        assert_eq!(FreshnessPolicy::Strict.to_string(), "strict");
        assert_eq!(FreshnessPolicy::Warn.to_string(), "warn");
        assert_eq!(FreshnessPolicy::BestEffort.to_string(), "best_effort");
    }

    #[test]
    fn freshness_policy_allows_stale() {
        assert!(!FreshnessPolicy::Strict.allows_stale());
        assert!(FreshnessPolicy::Warn.allows_stale());
        assert!(FreshnessPolicy::BestEffort.allows_stale());
    }

    #[test]
    fn freshness_policy_for_risk_tier() {
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::CriticalWrite),
            FreshnessPolicy::Strict
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Dangerous),
            FreshnessPolicy::Strict
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Risky),
            FreshnessPolicy::Warn
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Safe),
            FreshnessPolicy::BestEffort
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BloomFilter Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn bloom_filter_basic() {
        let mut bf = BloomFilter::new(100, 0.01);

        let item = b"test item";
        assert!(!bf.might_contain(item));

        bf.insert(item);
        assert!(bf.might_contain(item));
    }

    #[test]
    fn bloom_filter_no_false_negatives() {
        let mut bf = BloomFilter::new(1000, 0.01);

        // Insert many items
        for i in 0..100u32 {
            bf.insert(&i.to_le_bytes());
        }

        // All inserted items must be found
        for i in 0..100u32 {
            assert!(
                bf.might_contain(&i.to_le_bytes()),
                "Bloom filter false negative for {i}"
            );
        }
    }

    #[test]
    fn bloom_filter_clear() {
        let mut bf = BloomFilter::new(100, 0.01);

        bf.insert(b"test");
        assert!(bf.might_contain(b"test"));

        bf.clear();
        assert!(!bf.might_contain(b"test"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationRegistry Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn registry_empty() {
        let registry = RevocationRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.head.is_none());
    }

    #[test]
    fn registry_is_revoked_fast_path() {
        let registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([99u8; 32]);

        // Fast path: bloom filter says not present
        assert!(!registry.is_revoked(&id));
    }

    #[test]
    fn registry_add_and_check_revocation() {
        let mut registry = RevocationRegistry::new();
        let revocation = test_revocation();
        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        let other_id = ObjectId::from_bytes([2u8; 32]);

        registry.add_revocation(&revocation);

        assert!(registry.is_revoked(&revoked_id));
        assert!(!registry.is_revoked(&other_id));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_is_revoked_at() {
        let mut registry = RevocationRegistry::new();
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_800_000_000);

        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        registry.add_revocation(&revocation);

        // Before effective: not revoked
        assert!(!registry.is_revoked_at(&revoked_id, 1_699_999_999));

        // During active period: revoked
        assert!(registry.is_revoked_at(&revoked_id, 1_750_000_000));

        // After expiry: not revoked
        assert!(!registry.is_revoked_at(&revoked_id, 1_800_000_001));
    }

    #[test]
    fn registry_get_revocation() {
        let mut registry = RevocationRegistry::new();
        let revocation = test_revocation();
        let revoked_id = ObjectId::from_bytes([1u8; 32]);

        registry.add_revocation(&revocation);

        let retrieved = registry.get_revocation(&revoked_id).unwrap();
        assert_eq!(retrieved.reason, "Compromised device");
        assert_eq!(retrieved.scope, RevocationScope::Capability);
    }

    #[test]
    fn registry_update_head() {
        let mut registry = RevocationRegistry::new();
        let head = ObjectId::from_bytes([42u8; 32]);

        registry.update_head(head, 100, 1_700_000_000);

        assert_eq!(registry.head, Some(head));
        assert_eq!(registry.head_seq, 100);
        assert_eq!(registry.last_updated, 1_700_000_000);
    }

    #[test]
    fn registry_is_fresh() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;

        assert!(registry.is_fresh(50)); // Equal
        assert!(registry.is_fresh(25)); // Ahead
        assert!(!registry.is_fresh(100)); // Behind
    }

    #[test]
    fn registry_check_freshness_strict() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_000_100;

        // Fresh: allowed
        let result = registry.check_freshness(50, FreshnessPolicy::Strict, 300, now);
        assert!(result.allowed);
        assert!(!result.stale);

        // Stale: blocked
        let result = registry.check_freshness(100, FreshnessPolicy::Strict, 300, now);
        assert!(!result.allowed);
        assert!(result.stale);
    }

    #[test]
    fn registry_check_freshness_warn() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_000_100;
        let max_age = 200;

        // Stale but within max_age: allowed with warning
        let result = registry.check_freshness(100, FreshnessPolicy::Warn, max_age, now);
        assert!(result.allowed);
        assert!(result.stale);
        assert_eq!(
            result.reason,
            Some(FreshnessFailureReason::StaleButWithinMaxAge)
        );

        // Stale and beyond max_age: blocked
        let result = registry.check_freshness(100, FreshnessPolicy::Warn, 50, now);
        assert!(!result.allowed);
        assert!(result.stale);
    }

    #[test]
    fn registry_check_freshness_best_effort() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_001_000; // Very stale

        // Always allowed
        let result = registry.check_freshness(100, FreshnessPolicy::BestEffort, 0, now);
        assert!(result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleButAllowed));
    }

    #[test]
    fn registry_clear() {
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&test_revocation());
        registry.update_head(ObjectId::from_bytes([1u8; 32]), 10, 1_700_000_000);

        assert!(!registry.is_empty());

        registry.clear();

        assert!(registry.is_empty());
        assert!(registry.head.is_none());
        assert_eq!(registry.head_seq, 0);
    }

    #[test]
    fn registry_revocations_by_scope() {
        let mut registry = RevocationRegistry::new();

        let mut cap_revocation = test_revocation();
        cap_revocation.scope = RevocationScope::Capability;
        cap_revocation.revoked = vec![ObjectId::from_bytes([1u8; 32])];

        let mut key_revocation = test_revocation();
        key_revocation.scope = RevocationScope::IssuerKey;
        key_revocation.revoked = vec![ObjectId::from_bytes([2u8; 32])];

        registry.add_revocation(&cap_revocation);
        registry.add_revocation(&key_revocation);

        let cap_revocations = registry.revocations_by_scope(RevocationScope::Capability);
        assert_eq!(cap_revocations.len(), 1);

        let key_revocations = registry.revocations_by_scope(RevocationScope::IssuerKey);
        assert_eq!(key_revocations.len(), 1);

        let node_revocations = registry.revocations_by_scope(RevocationScope::NodeAttestation);
        assert!(node_revocations.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationEvent Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_event_follows() {
        // The ObjectId of event1 (in a real system, this would be computed from event1's content)
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event2_id = ObjectId::from_bytes([20u8; 32]);

        let event1 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([1u8; 32]),
            prev: None,
            seq: 1,
            occurred_at: 1_700_000_000,
            signature: [0u8; 64],
        };

        let event2 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([2u8; 32]),
            prev: Some(event1_id), // Points to event1's ObjectId, NOT its revocation_object_id
            seq: 2,
            occurred_at: 1_700_000_001,
            signature: [0u8; 64],
        };

        // event2 follows event1 (event2.prev points to event1_id, and seq is correct)
        assert!(event2.follows(&event1, &event1_id));
        // event1 does not follow event2 (wrong order)
        assert!(!event1.follows(&event2, &event2_id));
        // event2 does not follow event1 with wrong ID
        let wrong_id = ObjectId::from_bytes([99u8; 32]);
        assert!(!event2.follows(&event1, &wrong_id));
    }

    #[test]
    fn revocation_event_follows_overflow_protection() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);

        let event1 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([1u8; 32]),
            prev: None,
            seq: u64::MAX, // Maximum sequence number
            occurred_at: 1_700_000_000,
            signature: [0u8; 64],
        };

        let event2 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([2u8; 32]),
            prev: Some(event1_id),
            seq: 0, // Would be u64::MAX + 1 if it wrapped
            occurred_at: 1_700_000_001,
            signature: [0u8; 64],
        };

        // Should return false because u64::MAX + 1 overflows (no valid successor)
        assert!(!event2.follows(&event1, &event1_id));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationHead Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_head_is_fresher_than() {
        let head1 = RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: 10,
            epoch_id: EpochId::new("epoch-1"),
            quorum_signatures: SignatureSet::new(),
        };

        let head2 = RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([2u8; 32]),
            head_seq: 20,
            epoch_id: EpochId::new("epoch-2"),
            quorum_signatures: SignatureSet::new(),
        };

        assert!(head2.is_fresher_than(&head1));
        assert!(!head1.is_fresher_than(&head2));
        assert!(!head1.is_fresher_than(&head1)); // Same seq
    }

    #[test]
    fn revocation_head_age() {
        let mut head = RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: 10,
            epoch_id: EpochId::new("epoch-1"),
            quorum_signatures: SignatureSet::new(),
        };
        head.header.created_at = 1_700_000_000;

        let now = 1_700_000_100;
        assert_eq!(head.age_secs(now), 100);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EpochId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn epoch_id_display() {
        let epoch = EpochId::new("epoch-2024-01");
        assert_eq!(epoch.to_string(), "epoch-2024-01");
        assert_eq!(epoch.as_str(), "epoch-2024-01");
    }

    #[test]
    fn epoch_id_serialization() {
        let epoch = EpochId::new("epoch-123");
        let json = serde_json::to_string(&epoch).unwrap();
        let deserialized: EpochId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.as_str(), "epoch-123");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationScope – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_scope_serde_roundtrip_all_variants() {
        let variants = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for scope in &variants {
            let json = serde_json::to_string(scope).unwrap();
            let decoded: RevocationScope = serde_json::from_str(&json).unwrap();
            assert_eq!(*scope, decoded, "roundtrip mismatch for {scope:?}");
        }
    }

    #[test]
    fn revocation_scope_as_str_all_variants() {
        assert_eq!(RevocationScope::Capability.as_str(), "capability");
        assert_eq!(RevocationScope::IssuerKey.as_str(), "issuer_key");
        assert_eq!(
            RevocationScope::NodeAttestation.as_str(),
            "node_attestation"
        );
        assert_eq!(RevocationScope::ZoneKey.as_str(), "zone_key");
        assert_eq!(
            RevocationScope::ConnectorBinary.as_str(),
            "connector_binary"
        );
    }

    #[test]
    fn revocation_scope_copy() {
        let a = RevocationScope::ZoneKey;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn revocation_scope_clone() {
        let a = RevocationScope::ConnectorBinary;
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn revocation_scope_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RevocationScope::Capability);
        set.insert(RevocationScope::Capability);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn revocation_scope_hash_different_variants() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RevocationScope::Capability);
        set.insert(RevocationScope::IssuerKey);
        set.insert(RevocationScope::NodeAttestation);
        set.insert(RevocationScope::ZoneKey);
        set.insert(RevocationScope::ConnectorBinary);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn revocation_scope_inequality() {
        assert_ne!(RevocationScope::Capability, RevocationScope::IssuerKey);
        assert_ne!(RevocationScope::ZoneKey, RevocationScope::ConnectorBinary);
    }

    #[test]
    fn revocation_scope_critical_vs_non_critical_partition() {
        let non_critical = [RevocationScope::Capability, RevocationScope::IssuerKey];
        let critical = [
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for scope in &non_critical {
            assert!(!scope.is_critical(), "{scope:?} should not be critical");
        }
        for scope in &critical {
            assert!(scope.is_critical(), "{scope:?} should be critical");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationObject – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_object_zone_id() {
        let revocation = test_revocation();
        assert_eq!(*revocation.zone_id(), ZoneId::work());
    }

    #[test]
    fn revocation_object_revokes_multiple_ids() {
        let mut revocation = test_revocation();
        let id1 = ObjectId::from_bytes([1u8; 32]);
        let id2 = ObjectId::from_bytes([2u8; 32]);
        let id3 = ObjectId::from_bytes([3u8; 32]);
        revocation.revoked = vec![id1, id2];

        assert!(revocation.revokes(&id1));
        assert!(revocation.revokes(&id2));
        assert!(!revocation.revokes(&id3));
    }

    #[test]
    fn revocation_object_revokes_empty_list() {
        let mut revocation = test_revocation();
        revocation.revoked = vec![];
        let id = ObjectId::from_bytes([1u8; 32]);
        assert!(!revocation.revokes(&id));
    }

    #[test]
    fn revocation_object_is_active_exact_effective_at() {
        let revocation = test_revocation();
        // At exactly effective_at: should be active
        assert!(revocation.is_active(revocation.effective_at));
        // One tick before: not active
        assert!(!revocation.is_active(revocation.effective_at - 1));
    }

    #[test]
    fn revocation_object_is_active_exact_expires_at() {
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_800_000_000);
        // At exactly expires_at: NOT active (now < exp is false when now == exp)
        assert!(!revocation.is_active(1_800_000_000));
        // One tick before expiry: active
        assert!(revocation.is_active(1_799_999_999));
    }

    #[test]
    fn revocation_object_clone() {
        let revocation = test_revocation();
        let cloned = revocation.clone();
        assert_eq!(cloned.scope, revocation.scope);
        assert_eq!(cloned.reason, revocation.reason);
        assert_eq!(cloned.effective_at, revocation.effective_at);
        assert_eq!(cloned.expires_at, revocation.expires_at);
        assert_eq!(cloned.revoked.len(), revocation.revoked.len());
    }

    #[test]
    fn revocation_object_serde_roundtrip() {
        let revocation = test_revocation();
        let json = serde_json::to_string(&revocation).unwrap();
        let decoded: RevocationObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.scope, revocation.scope);
        assert_eq!(decoded.reason, revocation.reason);
        assert_eq!(decoded.effective_at, revocation.effective_at);
        assert_eq!(decoded.expires_at, revocation.expires_at);
        assert_eq!(decoded.revoked, revocation.revoked);
    }

    #[test]
    fn revocation_object_serde_with_expiry() {
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_900_000_000);
        let json = serde_json::to_string(&revocation).unwrap();
        assert!(json.contains("expires_at"));
        let decoded: RevocationObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.expires_at, Some(1_900_000_000));
    }

    #[test]
    fn revocation_object_serde_without_expiry_omits_field() {
        let revocation = test_revocation();
        assert!(revocation.expires_at.is_none());
        let json = serde_json::to_string(&revocation).unwrap();
        assert!(!json.contains("expires_at"));
    }

    #[test]
    fn revocation_object_all_scopes() {
        let scopes = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for scope in scopes {
            let mut rev = test_revocation();
            rev.scope = scope;
            let json = serde_json::to_string(&rev).unwrap();
            let decoded: RevocationObject = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.scope, scope);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationEvent – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_event(seq: u64, prev: Option<ObjectId>) -> RevocationEvent {
        RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([1u8; 32]),
            prev,
            seq,
            occurred_at: 1_700_000_000 + seq,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn revocation_event_zone_id() {
        let event = test_event(1, None);
        assert_eq!(*event.zone_id(), ZoneId::work());
    }

    #[test]
    fn revocation_event_genesis_has_no_prev() {
        let genesis = test_event(0, None);
        assert!(genesis.prev.is_none());
        assert_eq!(genesis.seq, 0);
    }

    #[test]
    fn revocation_event_follows_requires_exact_seq_increment() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event1 = test_event(5, None);
        // Gap: seq 5 → seq 7 (should fail, needs seq 6)
        let event_gap = RevocationEvent {
            prev: Some(event1_id),
            seq: 7,
            ..test_event(7, Some(event1_id))
        };
        assert!(!event_gap.follows(&event1, &event1_id));
    }

    #[test]
    fn revocation_event_follows_correct_seq() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event1 = test_event(5, None);
        let event2 = test_event(6, Some(event1_id));
        assert!(event2.follows(&event1, &event1_id));
    }

    #[test]
    fn revocation_event_clone() {
        let event = test_event(42, None);
        let cloned = event.clone();
        assert_eq!(cloned.seq, event.seq);
        assert_eq!(cloned.occurred_at, event.occurred_at);
        assert_eq!(cloned.prev, event.prev);
        assert_eq!(cloned.revocation_object_id, event.revocation_object_id);
    }

    #[test]
    fn revocation_event_serde_roundtrip() {
        let event = test_event(10, Some(ObjectId::from_bytes([5u8; 32])));
        let json = serde_json::to_string(&event).unwrap();
        let decoded: RevocationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.seq, 10);
        assert_eq!(decoded.prev, Some(ObjectId::from_bytes([5u8; 32])));
    }

    #[test]
    fn revocation_event_serde_genesis_omits_prev() {
        let genesis = test_event(0, None);
        let json = serde_json::to_string(&genesis).unwrap();
        assert!(!json.contains("\"prev\""));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EpochId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn epoch_id_equality() {
        let a = EpochId::new("epoch-1");
        let b = EpochId::new("epoch-1");
        assert_eq!(a, b);
    }

    #[test]
    fn epoch_id_inequality() {
        let a = EpochId::new("epoch-1");
        let b = EpochId::new("epoch-2");
        assert_ne!(a, b);
    }

    #[test]
    fn epoch_id_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EpochId::new("epoch-1"));
        set.insert(EpochId::new("epoch-1"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn epoch_id_hash_different() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EpochId::new("epoch-1"));
        set.insert(EpochId::new("epoch-2"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn epoch_id_clone() {
        let a = EpochId::new("epoch-1");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn epoch_id_from_string() {
        let s = String::from("epoch-owned");
        let epoch = EpochId::new(s);
        assert_eq!(epoch.as_str(), "epoch-owned");
    }

    #[test]
    fn epoch_id_empty() {
        let epoch = EpochId::new("");
        assert_eq!(epoch.as_str(), "");
        assert_eq!(epoch.to_string(), "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationHead – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_head(seq: u64) -> RevocationHead {
        RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: seq,
            epoch_id: EpochId::new(format!("epoch-{seq}")),
            quorum_signatures: SignatureSet::new(),
        }
    }

    #[test]
    fn revocation_head_age_saturating() {
        let mut head = test_head(1);
        head.header.created_at = 1_700_000_000;
        // now < created_at → saturating_sub returns 0
        assert_eq!(head.age_secs(1_699_999_000), 0);
    }

    #[test]
    fn revocation_head_age_zero() {
        let mut head = test_head(1);
        head.header.created_at = 1_700_000_000;
        assert_eq!(head.age_secs(1_700_000_000), 0);
    }

    #[test]
    fn revocation_head_is_fresher_equal_seqs() {
        let h1 = test_head(10);
        let h2 = test_head(10);
        // Equal seqs: neither is fresher
        assert!(!h1.is_fresher_than(&h2));
        assert!(!h2.is_fresher_than(&h1));
    }

    #[test]
    fn revocation_head_clone() {
        let head = test_head(42);
        let cloned = head.clone();
        assert_eq!(head.head_seq, 42);
        assert_eq!(head.zone_id, ZoneId::work());
        assert_eq!(head.epoch_id.as_str(), "epoch-42");
        assert_eq!(cloned.head_seq, 42);
        assert_eq!(cloned.zone_id, ZoneId::work());
        assert_eq!(cloned.epoch_id.as_str(), "epoch-42");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessPolicy – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_policy_default_is_strict() {
        let policy = FreshnessPolicy::default();
        assert_eq!(policy, FreshnessPolicy::Strict);
    }

    #[test]
    fn freshness_policy_serde_roundtrip_all_variants() {
        let variants = [
            FreshnessPolicy::Strict,
            FreshnessPolicy::Warn,
            FreshnessPolicy::BestEffort,
        ];
        for policy in &variants {
            let json = serde_json::to_string(policy).unwrap();
            let decoded: FreshnessPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(*policy, decoded, "roundtrip mismatch for {policy:?}");
        }
    }

    #[test]
    fn freshness_policy_as_str_all_variants() {
        assert_eq!(FreshnessPolicy::Strict.as_str(), "strict");
        assert_eq!(FreshnessPolicy::Warn.as_str(), "warn");
        assert_eq!(FreshnessPolicy::BestEffort.as_str(), "best_effort");
    }

    #[test]
    fn freshness_policy_copy() {
        let a = FreshnessPolicy::Warn;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_policy_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessPolicy::Strict);
        set.insert(FreshnessPolicy::Strict);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn freshness_policy_hash_all_variants_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessPolicy::Strict);
        set.insert(FreshnessPolicy::Warn);
        set.insert(FreshnessPolicy::BestEffort);
        assert_eq!(set.len(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessFailureReason – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_failure_reason_as_str_all() {
        assert_eq!(FreshnessFailureReason::StaleData.as_str(), "stale_data");
        assert_eq!(
            FreshnessFailureReason::StaleButWithinMaxAge.as_str(),
            "stale_but_within_max_age"
        );
        assert_eq!(
            FreshnessFailureReason::StaleButAllowed.as_str(),
            "stale_but_allowed"
        );
    }

    #[test]
    fn freshness_failure_reason_display_all() {
        assert_eq!(FreshnessFailureReason::StaleData.to_string(), "stale_data");
        assert_eq!(
            FreshnessFailureReason::StaleButWithinMaxAge.to_string(),
            "stale_but_within_max_age"
        );
        assert_eq!(
            FreshnessFailureReason::StaleButAllowed.to_string(),
            "stale_but_allowed"
        );
    }

    #[test]
    fn freshness_failure_reason_serde_roundtrip_all() {
        let variants = [
            FreshnessFailureReason::StaleData,
            FreshnessFailureReason::StaleButWithinMaxAge,
            FreshnessFailureReason::StaleButAllowed,
        ];
        for reason in &variants {
            let json = serde_json::to_string(reason).unwrap();
            let decoded: FreshnessFailureReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, decoded, "roundtrip mismatch for {reason:?}");
        }
    }

    #[test]
    fn freshness_failure_reason_equality() {
        assert_eq!(
            FreshnessFailureReason::StaleData,
            FreshnessFailureReason::StaleData
        );
        assert_ne!(
            FreshnessFailureReason::StaleData,
            FreshnessFailureReason::StaleButAllowed
        );
    }

    #[test]
    fn freshness_failure_reason_copy() {
        let a = FreshnessFailureReason::StaleButWithinMaxAge;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_failure_reason_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessFailureReason::StaleData);
        set.insert(FreshnessFailureReason::StaleData);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn freshness_failure_reason_hash_all_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessFailureReason::StaleData);
        set.insert(FreshnessFailureReason::StaleButWithinMaxAge);
        set.insert(FreshnessFailureReason::StaleButAllowed);
        assert_eq!(set.len(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessCheckResult – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_check_result_serde_with_reason() {
        let result = FreshnessCheckResult {
            allowed: false,
            stale: true,
            age_secs: 300,
            reason: Some(FreshnessFailureReason::StaleData),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: FreshnessCheckResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.allowed);
        assert!(decoded.stale);
        assert_eq!(decoded.age_secs, 300);
        assert_eq!(decoded.reason, Some(FreshnessFailureReason::StaleData));
    }

    #[test]
    fn freshness_check_result_serde_without_reason() {
        let result = FreshnessCheckResult {
            allowed: true,
            stale: false,
            age_secs: 0,
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("reason"));
        let decoded: FreshnessCheckResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.allowed);
        assert!(!decoded.stale);
        assert!(decoded.reason.is_none());
    }

    #[test]
    fn freshness_check_result_clone() {
        let result = FreshnessCheckResult {
            allowed: true,
            stale: true,
            age_secs: 42,
            reason: Some(FreshnessFailureReason::StaleButAllowed),
        };
        let cloned = result.clone();
        assert_eq!(cloned.allowed, result.allowed);
        assert_eq!(cloned.stale, result.stale);
        assert_eq!(cloned.age_secs, result.age_secs);
        assert_eq!(cloned.reason, result.reason);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationCheckResult – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_check_result_serde_revoked() {
        let result = RevocationCheckResult {
            is_revoked: true,
            revocation: Some(ObjectId::from_bytes([1u8; 32])),
            scope: Some(RevocationScope::Capability),
            stale_data: false,
            head_age_secs: 10,
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: RevocationCheckResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_revoked);
        assert!(decoded.revocation.is_some());
        assert_eq!(decoded.scope, Some(RevocationScope::Capability));
        assert_eq!(decoded.head_age_secs, 10);
    }

    #[test]
    fn revocation_check_result_serde_not_revoked() {
        let result = RevocationCheckResult {
            is_revoked: false,
            revocation: None,
            scope: None,
            stale_data: false,
            head_age_secs: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("revocation"));
        assert!(!json.contains("scope"));
        let decoded: RevocationCheckResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.is_revoked);
        assert!(decoded.revocation.is_none());
        assert!(decoded.scope.is_none());
    }

    #[test]
    fn revocation_check_result_clone() {
        let result = RevocationCheckResult {
            is_revoked: true,
            revocation: Some(ObjectId::from_bytes([3u8; 32])),
            scope: Some(RevocationScope::ZoneKey),
            stale_data: true,
            head_age_secs: 999,
        };
        let cloned = result.clone();
        assert_eq!(cloned.is_revoked, result.is_revoked);
        assert_eq!(cloned.revocation, result.revocation);
        assert_eq!(cloned.scope, result.scope);
        assert_eq!(cloned.stale_data, result.stale_data);
        assert_eq!(cloned.head_age_secs, result.head_age_secs);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BloomFilter – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn bloom_filter_default() {
        let bf = BloomFilter::default();
        assert!(!bf.might_contain(b"anything"));
    }

    #[test]
    fn bloom_filter_insert_same_item_twice() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(b"hello");
        bf.insert(b"hello");
        assert!(bf.might_contain(b"hello"));
    }

    #[test]
    fn bloom_filter_many_items_no_false_negatives() {
        let mut bf = BloomFilter::new(10_000, 0.01);
        for i in 0..1000u32 {
            bf.insert(&i.to_le_bytes());
        }
        for i in 0..1000u32 {
            assert!(
                bf.might_contain(&i.to_le_bytes()),
                "false negative for item {i}"
            );
        }
    }

    #[test]
    fn bloom_filter_different_sizes() {
        // Very small
        let mut bf_small = BloomFilter::new(1, 0.5);
        bf_small.insert(b"x");
        assert!(bf_small.might_contain(b"x"));

        // Medium
        let mut bf_medium = BloomFilter::new(1000, 0.001);
        bf_medium.insert(b"y");
        assert!(bf_medium.might_contain(b"y"));
    }

    #[test]
    fn bloom_filter_empty_item() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(b"");
        assert!(bf.might_contain(b""));
    }

    #[test]
    fn bloom_filter_clear_then_reuse() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(b"first");
        bf.clear();
        assert!(!bf.might_contain(b"first"));
        bf.insert(b"second");
        assert!(bf.might_contain(b"second"));
        assert!(!bf.might_contain(b"first"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationRegistry – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn registry_with_capacity() {
        let registry = RevocationRegistry::with_capacity(1000);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.head.is_none());
        assert_eq!(registry.head_seq, 0);
        assert_eq!(registry.last_updated, 0);
    }

    #[test]
    fn registry_add_multiple_revocations() {
        let mut registry = RevocationRegistry::new();

        let mut rev1 = test_revocation();
        rev1.revoked = vec![ObjectId::from_bytes([1u8; 32])];
        rev1.scope = RevocationScope::Capability;

        let mut rev2 = test_revocation();
        rev2.revoked = vec![ObjectId::from_bytes([2u8; 32])];
        rev2.scope = RevocationScope::IssuerKey;

        let mut rev3 = test_revocation();
        rev3.revoked = vec![ObjectId::from_bytes([3u8; 32])];
        rev3.scope = RevocationScope::ZoneKey;

        registry.add_revocation(&rev1);
        registry.add_revocation(&rev2);
        registry.add_revocation(&rev3);

        assert_eq!(registry.len(), 3);
        assert!(registry.is_revoked(&ObjectId::from_bytes([1u8; 32])));
        assert!(registry.is_revoked(&ObjectId::from_bytes([2u8; 32])));
        assert!(registry.is_revoked(&ObjectId::from_bytes([3u8; 32])));
        assert!(!registry.is_revoked(&ObjectId::from_bytes([4u8; 32])));
    }

    #[test]
    fn registry_add_revocation_with_multiple_ids() {
        let mut registry = RevocationRegistry::new();
        let mut revocation = test_revocation();
        let id1 = ObjectId::from_bytes([10u8; 32]);
        let id2 = ObjectId::from_bytes([20u8; 32]);
        let id3 = ObjectId::from_bytes([30u8; 32]);
        revocation.revoked = vec![id1, id2, id3];

        registry.add_revocation(&revocation);
        // Each revoked ID gets its own entry in the map
        assert_eq!(registry.len(), 3);
        assert!(registry.is_revoked(&id1));
        assert!(registry.is_revoked(&id2));
        assert!(registry.is_revoked(&id3));
    }

    #[test]
    fn registry_len_tracking() {
        let mut registry = RevocationRegistry::new();
        assert_eq!(registry.len(), 0);

        let mut rev = test_revocation();
        rev.revoked = vec![ObjectId::from_bytes([1u8; 32])];
        registry.add_revocation(&rev);
        assert_eq!(registry.len(), 1);

        let mut rev2 = test_revocation();
        rev2.revoked = vec![ObjectId::from_bytes([2u8; 32])];
        registry.add_revocation(&rev2);
        assert_eq!(registry.len(), 2);

        registry.clear();
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_is_empty_transitions() {
        let mut registry = RevocationRegistry::new();
        assert!(registry.is_empty());

        registry.add_revocation(&test_revocation());
        assert!(!registry.is_empty());

        registry.clear();
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_is_fresh_zero_seq() {
        let registry = RevocationRegistry::new();
        assert!(registry.is_fresh(0)); // 0 >= 0
        assert!(!registry.is_fresh(1)); // 0 < 1
    }

    #[test]
    fn registry_check_freshness_all_policies_when_fresh() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 100;
        registry.last_updated = 1_700_000_000;
        let now = 1_700_000_050;

        // When fresh, all policies should allow and not be stale
        for policy in [
            FreshnessPolicy::Strict,
            FreshnessPolicy::Warn,
            FreshnessPolicy::BestEffort,
        ] {
            let result = registry.check_freshness(100, policy, 300, now);
            assert!(result.allowed, "policy {policy:?} should allow when fresh");
            assert!(
                !result.stale,
                "policy {policy:?} should not be stale when fresh"
            );
            assert!(
                result.reason.is_none(),
                "policy {policy:?} should have no reason when fresh"
            );
            assert_eq!(result.age_secs, 50);
        }
    }

    #[test]
    fn registry_check_freshness_warn_fresh_data() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 100;
        registry.last_updated = 1_700_000_000;
        let now = 1_700_000_050;

        let result = registry.check_freshness(100, FreshnessPolicy::Warn, 300, now);
        assert!(result.allowed);
        assert!(!result.stale);
        assert!(result.reason.is_none());
    }

    #[test]
    fn registry_check_freshness_strict_stale_reason() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let result = registry.check_freshness(100, FreshnessPolicy::Strict, 300, 1_700_000_100);
        assert!(!result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleData));
    }

    #[test]
    fn registry_check_freshness_warn_stale_beyond_max_age_reason() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        // now - last_updated = 500, max_age = 100 → beyond max age
        let result = registry.check_freshness(100, FreshnessPolicy::Warn, 100, 1_700_000_500);
        assert!(!result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleData));
    }

    #[test]
    fn registry_check_freshness_best_effort_always_allowed() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 0;
        registry.last_updated = 0;

        // Extremely stale, max_age 0, but BestEffort always allows
        let result = registry.check_freshness(u64::MAX, FreshnessPolicy::BestEffort, 0, u64::MAX);
        assert!(result.allowed);
        assert!(result.stale);
    }

    #[test]
    fn registry_revocations_by_scope_all_scopes() {
        let mut registry = RevocationRegistry::new();
        let scopes = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for (i, scope) in scopes.iter().enumerate() {
            let mut rev = test_revocation();
            rev.scope = *scope;
            let revoked_byte = u8::try_from(i).expect("scope index fits u8") + 10;
            rev.revoked = vec![ObjectId::from_bytes([revoked_byte; 32])];
            registry.add_revocation(&rev);
        }

        for scope in scopes {
            let found = registry.revocations_by_scope(scope);
            assert_eq!(found.len(), 1, "expected 1 revocation for scope {scope:?}");
            assert_eq!(found[0].scope, scope);
        }
    }

    #[test]
    fn registry_get_revocation_absent() {
        let registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([99u8; 32]);
        assert!(registry.get_revocation(&id).is_none());
    }

    #[test]
    fn registry_update_head_overwrites() {
        let mut registry = RevocationRegistry::new();
        let head1 = ObjectId::from_bytes([1u8; 32]);
        let head2 = ObjectId::from_bytes([2u8; 32]);

        registry.update_head(head1, 10, 100);
        assert_eq!(registry.head_seq, 10);

        registry.update_head(head2, 20, 200);
        assert_eq!(registry.head, Some(head2));
        assert_eq!(registry.head_seq, 20);
        assert_eq!(registry.last_updated, 200);
    }

    #[test]
    fn registry_clone() {
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&test_revocation());
        registry.update_head(ObjectId::from_bytes([42u8; 32]), 5, 999);

        let cloned = registry.clone();
        assert_eq!(cloned.len(), registry.len());
        assert_eq!(cloned.head_seq, registry.head_seq);
        assert_eq!(cloned.last_updated, registry.last_updated);
        assert_eq!(cloned.head, registry.head);
    }

    #[test]
    fn registry_default_matches_new() {
        let from_new = RevocationRegistry::new();
        let from_default = RevocationRegistry::default();
        assert!(from_new.is_empty());
        assert!(from_default.is_empty());
        assert_eq!(from_new.head_seq, from_default.head_seq);
        assert_eq!(from_new.last_updated, from_default.last_updated);
    }
}
