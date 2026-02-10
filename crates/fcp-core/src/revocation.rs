//! Revocation types for FCP2 (NORMATIVE).
//!
//! This module implements the revocation system from `FCP_Specification_V2.md` §14.3.
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
    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = Self::hash_item(item);
        for i in 0..self.num_hashes {
            // Double hashing: h_i = (h1 + i * h2) % m
            let hash = h1.wrapping_add(u64::from(i).wrapping_mul(h2));
            let index = (hash as usize) % self.num_bits;
            self.bits[index / 64] |= 1u64 << (index % 64);
        }
    }

    /// Check if an item might be in the bloom filter.
    ///
    /// Returns `false` if definitely not present, `true` if possibly present.
    #[must_use]
    pub fn might_contain(&self, item: &[u8]) -> bool {
        let (h1, h2) = Self::hash_item(item);
        for i in 0..self.num_hashes {
            let hash = h1.wrapping_add(u64::from(i).wrapping_mul(h2));
            let index = (hash as usize) % self.num_bits;
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
        let h1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

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
}
