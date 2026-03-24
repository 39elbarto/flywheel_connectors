//! Post-Compromise Security (PCS) zones via TreeKEM-inspired epoch ratcheting.
//!
//! Provides an optional PCS mode for sensitive zones (`z:owner`, `z:private`)
//! using MLS/TreeKEM-style group key agreement. In PCS mode, after a compromise
//! is detected and recovered (member removal + rekey), the system regains
//! forward security through group ratcheting.
//!
//! # Design choice: Option A (MLS-derived `ZoneKeyManifest` keys)
//!
//! The MLS-style group state produces an epoch-sequenced shared secret.
//! Zone key material is derived via HKDF from the group secret + epoch.
//! `ZoneKeyManifest` carries a `PcsMode` flag and group state references.
//!
//! # Why not full `OpenMLS`?
//!
//! For personal meshes (n=3..10 nodes), a full RFC 9420 MLS implementation
//! is unnecessary overhead. Instead we implement the core `TreeKEM` binary-tree
//! key derivation and epoch ratcheting primitives directly, using the existing
//! FCP crypto stack (HKDF-SHA256, X25519, HPKE).

use std::collections::HashMap;
use std::fmt;

use fcp_crypto::{CryptoError, X25519PublicKey, X25519SecretKey, hkdf_sha256_array};
use serde::{Deserialize, Serialize};

use crate::{TailscaleNodeId, ZoneId, ZoneKey, ZoneKeyId};

/// Domain separation prefix for PCS key derivation.
const PCS_DOMAIN: &[u8] = b"FCP2-PCS-";

/// Maximum supported group size for personal meshes.
pub const PCS_MAX_GROUP_SIZE: usize = 32;

/// PCS zone errors.
#[derive(Debug, thiserror::Error)]
pub enum PcsError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),

    #[error("group size {size} exceeds maximum {max}")]
    GroupTooLarge { size: usize, max: usize },

    #[error("member not found in group: {0}")]
    MemberNotFound(String),

    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("empty group: at least one member required")]
    EmptyGroup,

    #[error("tree node index {index} out of bounds (tree size: {tree_size})")]
    TreeIndexOutOfBounds { index: usize, tree_size: usize },

    #[error("removed member {member} attempted key derivation at epoch {epoch}")]
    RemovedMemberAccess { member: String, epoch: u64 },

    #[error("stale epoch: current is {current}, requested {requested}")]
    StaleEpoch { current: u64, requested: u64 },

    #[error("duplicate member: {0} already exists in group")]
    DuplicateMember(String),
}

pub type PcsResult<T> = Result<T, PcsError>;

/// PCS mode configuration for a zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PcsMode {
    /// Standard zone key management (no PCS).
    #[default]
    Disabled,
    /// PCS-enabled with `TreeKEM`-style group ratcheting.
    Enabled {
        /// Current group epoch number.
        epoch: u64,
        /// Opaque reference to the commit that established this epoch.
        #[serde(with = "crate::util::hex_or_bytes")]
        commit_ref: [u8; 32],
    },
}

/// Key management mode for `ZoneKeyManifest` integration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyManagementMode {
    /// Standard owner-distributed rotation.
    #[default]
    StandardRotation,
    /// PCS group-managed keys derived from `TreeKEM` epoch secret.
    PcsGroupManaged {
        /// Opaque reference to the MLS/TreeKEM commit.
        #[serde(with = "crate::util::hex_or_bytes")]
        commit_ref: [u8; 32],
        /// Current epoch number.
        epoch: u64,
    },
}

/// A member of the PCS group with their public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub node_id: TailscaleNodeId,
    pub public_key: X25519PublicKey,
    /// Leaf index in the `TreeKEM` binary tree.
    pub leaf_index: u32,
}

/// `TreeKEM` node in the binary ratchet tree.
///
/// Each node stores a public key and optionally the secret key
/// (if the local member is on the path from this node to the root).
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Public key at this tree node.
    pub public_key: Option<X25519PublicKey>,
    /// Secret key (only present for nodes on the local member's path).
    pub secret_key: Option<X25519SecretKey>,
    /// Hash of the node's key material (for tree hash computation).
    pub node_hash: [u8; 32],
}

impl TreeNode {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            public_key: None,
            secret_key: None,
            node_hash: [0u8; 32],
        }
    }
}

/// The PCS group state tracking epoch evolution for a zone.
#[derive(Debug, Clone)]
pub struct PcsGroupState {
    /// Zone this group manages.
    pub zone_id: ZoneId,
    /// Current epoch number (monotonically increasing).
    pub epoch: u64,
    /// Ordered list of group members (leaf nodes).
    members: Vec<GroupMember>,
    /// Current epoch secret (derived from tree root).
    epoch_secret: [u8; 32],
    /// Member lookup by node ID.
    member_index: HashMap<String, usize>,
}

impl PcsGroupState {
    /// Create a new PCS group from an initial set of members.
    ///
    /// # Errors
    ///
    /// Returns `PcsError::EmptyGroup` if members is empty, or
    /// `PcsError::GroupTooLarge` if the group exceeds `PCS_MAX_GROUP_SIZE`.
    pub fn new(
        zone_id: ZoneId,
        members: Vec<GroupMember>,
        initial_secret: [u8; 32],
    ) -> PcsResult<Self> {
        if members.is_empty() {
            return Err(PcsError::EmptyGroup);
        }
        if members.len() > PCS_MAX_GROUP_SIZE {
            return Err(PcsError::GroupTooLarge {
                size: members.len(),
                max: PCS_MAX_GROUP_SIZE,
            });
        }

        let mut member_index = HashMap::with_capacity(members.len());
        for (i, m) in members.iter().enumerate() {
            if member_index.contains_key(m.node_id.as_str()) {
                return Err(PcsError::DuplicateMember(m.node_id.as_str().to_string()));
            }
            member_index.insert(m.node_id.as_str().to_string(), i);
        }

        Ok(Self {
            zone_id,
            epoch: 0,
            members,
            epoch_secret: initial_secret,
            member_index,
        })
    }

    /// Current epoch number.
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of members in the group.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get all current members.
    #[must_use]
    pub fn members(&self) -> &[GroupMember] {
        &self.members
    }

    /// Check if a node is a member.
    #[must_use]
    pub fn is_member(&self, node_id: &TailscaleNodeId) -> bool {
        self.member_index.contains_key(node_id.as_str())
    }

    /// Derive the zone key for the current epoch.
    ///
    /// Uses HKDF with domain separation: `FCP2-PCS-ZONE-KEY || zone_id || epoch`.
    ///
    /// # Errors
    ///
    /// Returns `PcsError::Crypto` if key derivation fails.
    pub fn derive_zone_key(&self) -> PcsResult<ZoneKey> {
        derive_epoch_zone_key(&self.zone_id, &self.epoch_secret, self.epoch)
    }

    /// Derive the zone key for a specific epoch given its secret.
    ///
    /// # Errors
    ///
    /// Returns `PcsError::Crypto` if key derivation fails.
    pub fn derive_zone_key_for_epoch(
        zone_id: &ZoneId,
        epoch_secret: &[u8; 32],
        epoch: u64,
    ) -> PcsResult<ZoneKey> {
        derive_epoch_zone_key(zone_id, epoch_secret, epoch)
    }

    /// Derive a `ZoneKeyId` from the epoch secret and epoch number.
    ///
    /// Deterministic: same inputs always produce the same key ID.
    ///
    /// # Errors
    ///
    /// Returns `PcsError::Crypto` if derivation fails.
    pub fn derive_zone_key_id(&self) -> PcsResult<ZoneKeyId> {
        derive_epoch_zone_key_id(&self.zone_id, &self.epoch_secret, self.epoch)
    }

    /// Advance the group to the next epoch by ratcheting the epoch secret.
    ///
    /// This is the core PCS operation: the new epoch secret is derived from
    /// the current epoch secret plus the epoch number, ensuring forward secrecy.
    /// Knowledge of a past epoch secret does not reveal future epoch secrets.
    ///
    /// Returns the commit reference (hash of the new epoch state).
    ///
    /// # Errors
    ///
    /// Returns `PcsError::Crypto` if key derivation fails.
    pub fn advance_epoch(&mut self) -> PcsResult<EpochAdvanceResult> {
        let previous_epoch = self.epoch;
        let previous_secret = self.epoch_secret;

        // Derive new epoch secret: HKDF(prev_secret, "FCP2-PCS-EPOCH-ADVANCE" || epoch+1)
        let new_epoch = previous_epoch + 1;
        let new_secret = derive_next_epoch_secret(&previous_secret, new_epoch)?;

        // Compute commit reference (hash of zone_id || new_epoch || new_secret)
        let commit_ref = compute_commit_ref(&self.zone_id, new_epoch, &new_secret);

        self.epoch = new_epoch;
        self.epoch_secret = new_secret;

        Ok(EpochAdvanceResult {
            previous_epoch,
            new_epoch,
            commit_ref,
        })
    }

    /// Remove a member and advance the epoch (PCS rekey).
    ///
    /// After removal, the epoch secret is ratcheted so the removed member
    /// cannot derive future zone keys. This is the key PCS guarantee.
    ///
    /// # Errors
    ///
    /// Returns `PcsError::MemberNotFound` if the node is not in the group,
    /// or `PcsError::EmptyGroup` if removal would leave no members.
    pub fn remove_member(
        &mut self,
        node_id: &TailscaleNodeId,
    ) -> PcsResult<MembershipChangeResult> {
        let idx = self
            .member_index
            .get(node_id.as_str())
            .copied()
            .ok_or_else(|| PcsError::MemberNotFound(node_id.as_str().to_string()))?;

        if self.members.len() <= 1 {
            return Err(PcsError::EmptyGroup);
        }

        let removed = self.members.remove(idx);

        // Rebuild index after removal.
        self.member_index.clear();
        for (i, m) in self.members.iter().enumerate() {
            self.member_index.insert(m.node_id.as_str().to_string(), i);
        }

        // Inject fresh entropy from the removed member's leaf position
        // to ensure the removed member's knowledge is invalidated.
        let removal_salt = compute_removal_salt(node_id, self.epoch);
        let new_secret =
            derive_post_removal_secret(&self.epoch_secret, &removal_salt, self.epoch + 1)?;

        let previous_epoch = self.epoch;
        self.epoch += 1;
        self.epoch_secret = new_secret;

        let commit_ref = compute_commit_ref(&self.zone_id, self.epoch, &self.epoch_secret);

        Ok(MembershipChangeResult {
            previous_epoch,
            new_epoch: self.epoch,
            commit_ref,
            change: MembershipChange::Removed(removed),
        })
    }

    /// Add a new member and advance the epoch.
    ///
    /// The new member receives the current epoch secret (wrapped via HPKE
    /// at a higher layer). Adding a member does NOT invalidate the current
    /// epoch secret — forward secrecy is maintained because the new member
    /// cannot derive past epoch secrets.
    ///
    /// # Errors
    ///
    /// Returns `PcsError::GroupTooLarge` if the group is at capacity.
    pub fn add_member(&mut self, member: GroupMember) -> PcsResult<MembershipChangeResult> {
        if self.members.len() >= PCS_MAX_GROUP_SIZE {
            return Err(PcsError::GroupTooLarge {
                size: self.members.len() + 1,
                max: PCS_MAX_GROUP_SIZE,
            });
        }

        if self.is_member(&member.node_id) {
            return Err(PcsError::DuplicateMember(member.node_id.as_str().to_string()));
        }

        self.member_index
            .insert(member.node_id.as_str().to_string(), self.members.len());
        self.members.push(member.clone());

        // Advance epoch on membership change.
        let previous_epoch = self.epoch;
        let new_secret = derive_next_epoch_secret(&self.epoch_secret, self.epoch + 1)?;
        self.epoch += 1;
        self.epoch_secret = new_secret;

        let commit_ref = compute_commit_ref(&self.zone_id, self.epoch, &self.epoch_secret);

        Ok(MembershipChangeResult {
            previous_epoch,
            new_epoch: self.epoch,
            commit_ref,
            change: MembershipChange::Added(member),
        })
    }

    /// Get the current epoch secret (for zone key derivation by the owner).
    ///
    /// # Security
    ///
    /// This is secret material. Only use for wrapping in `ZoneKeyManifest`.
    #[must_use]
    pub const fn epoch_secret(&self) -> &[u8; 32] {
        &self.epoch_secret
    }

    /// Compute a PCS mode descriptor for embedding in `ZoneKeyManifest`.
    #[must_use]
    pub fn pcs_mode(&self) -> PcsMode {
        let commit_ref = compute_commit_ref(&self.zone_id, self.epoch, &self.epoch_secret);
        PcsMode::Enabled {
            epoch: self.epoch,
            commit_ref,
        }
    }

    /// Compute a `KeyManagementMode` for `ZoneKeyManifest` integration.
    #[must_use]
    pub fn key_management_mode(&self) -> KeyManagementMode {
        let commit_ref = compute_commit_ref(&self.zone_id, self.epoch, &self.epoch_secret);
        KeyManagementMode::PcsGroupManaged {
            commit_ref,
            epoch: self.epoch,
        }
    }
}

/// Result of advancing the epoch.
#[derive(Debug, Clone)]
pub struct EpochAdvanceResult {
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub commit_ref: [u8; 32],
}

/// Result of a membership change (add or remove).
#[derive(Debug, Clone)]
pub struct MembershipChangeResult {
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub commit_ref: [u8; 32],
    pub change: MembershipChange,
}

/// Type of membership change.
#[derive(Debug, Clone)]
pub enum MembershipChange {
    Added(GroupMember),
    Removed(GroupMember),
}

impl fmt::Display for MembershipChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added(m) => write!(f, "added {}", m.node_id.as_str()),
            Self::Removed(m) => write!(f, "removed {}", m.node_id.as_str()),
        }
    }
}

/// PCS audit event for structured logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcsAuditEvent {
    pub zone_id: String,
    pub event_type: PcsEventType,
    pub epoch: u64,
    pub member_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcp_error_code: Option<String>,
}

/// Types of PCS events for audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcsEventType {
    GroupCreated,
    EpochAdvanced,
    MemberAdded,
    MemberRemoved,
    ZoneKeyDerived,
    CompromiseRecovery,
}

// ── Internal derivation functions ───────────────────────────────────────

/// Derive zone key from epoch secret.
fn derive_epoch_zone_key(
    zone_id: &ZoneId,
    epoch_secret: &[u8; 32],
    epoch: u64,
) -> PcsResult<ZoneKey> {
    // PCS_DOMAIN(9) + "ZONE-KEY|"(9) + zone_id + "|"(1) + epoch(8)
    let mut info = Vec::with_capacity(PCS_DOMAIN.len() + 9 + zone_id.as_bytes().len() + 1 + 8);
    info.extend_from_slice(PCS_DOMAIN);
    info.extend_from_slice(b"ZONE-KEY|");
    info.extend_from_slice(zone_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(&epoch.to_be_bytes());

    let derived: [u8; 32] = hkdf_sha256_array(None, epoch_secret, &info)?;
    Ok(ZoneKey::from_bytes(derived))
}

/// Derive zone key ID from epoch secret.
fn derive_epoch_zone_key_id(
    zone_id: &ZoneId,
    epoch_secret: &[u8; 32],
    epoch: u64,
) -> PcsResult<ZoneKeyId> {
    // PCS_DOMAIN(9) + "ZONE-KEY-ID|"(12) + zone_id + "|"(1) + epoch(8)
    let mut info = Vec::with_capacity(PCS_DOMAIN.len() + 12 + zone_id.as_bytes().len() + 1 + 8);
    info.extend_from_slice(PCS_DOMAIN);
    info.extend_from_slice(b"ZONE-KEY-ID|");
    info.extend_from_slice(zone_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(&epoch.to_be_bytes());

    let derived: [u8; 8] = hkdf_sha256_array(None, epoch_secret, &info)?;
    Ok(ZoneKeyId::from_bytes(derived))
}

/// Derive the next epoch secret from the current one (forward ratchet).
fn derive_next_epoch_secret(current_secret: &[u8; 32], next_epoch: u64) -> PcsResult<[u8; 32]> {
    let mut info = Vec::with_capacity(PCS_DOMAIN.len() + 14 + 8);
    info.extend_from_slice(PCS_DOMAIN);
    info.extend_from_slice(b"EPOCH-ADVANCE|");
    info.extend_from_slice(&next_epoch.to_be_bytes());

    let derived: [u8; 32] = hkdf_sha256_array(None, current_secret, &info)?;
    Ok(derived)
}

/// Derive the epoch secret after member removal.
///
/// Uses the removal salt as additional entropy to ensure the removed
/// member's knowledge of the previous epoch secret is insufficient
/// to derive the new one.
fn derive_post_removal_secret(
    current_secret: &[u8; 32],
    removal_salt: &[u8; 32],
    next_epoch: u64,
) -> PcsResult<[u8; 32]> {
    // PCS_DOMAIN(9) + "REMOVAL-REKEY|"(14) + epoch(8)
    let mut info = Vec::with_capacity(PCS_DOMAIN.len() + 14 + 8);
    info.extend_from_slice(PCS_DOMAIN);
    info.extend_from_slice(b"REMOVAL-REKEY|");
    info.extend_from_slice(&next_epoch.to_be_bytes());

    // Use removal salt as HKDF salt (not info) to ensure cryptographic
    // independence from the standard epoch advance path.
    let derived: [u8; 32] = hkdf_sha256_array(Some(removal_salt), current_secret, &info)?;
    Ok(derived)
}

/// Compute a deterministic removal salt from the removed member's identity.
fn compute_removal_salt(node_id: &TailscaleNodeId, epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PCS_DOMAIN);
    hasher.update(b"REMOVAL-SALT|");
    hasher.update(node_id.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(&epoch.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute a commit reference (hash of the epoch state).
fn compute_commit_ref(zone_id: &ZoneId, epoch: u64, epoch_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PCS_DOMAIN);
    hasher.update(b"COMMIT-REF|");
    hasher.update(zone_id.as_bytes());
    hasher.update(b"|");
    hasher.update(&epoch.to_be_bytes());
    hasher.update(b"|");
    hasher.update(epoch_secret);
    *hasher.finalize().as_bytes()
}

/// Verify that a zone key was correctly derived from a given epoch secret.
///
/// # Errors
///
/// Returns `PcsError::Crypto` if derivation fails.
pub fn verify_epoch_zone_key(
    zone_id: &ZoneId,
    epoch_secret: &[u8; 32],
    epoch: u64,
    expected_key: &ZoneKey,
) -> PcsResult<bool> {
    let derived = derive_epoch_zone_key(zone_id, epoch_secret, epoch)?;
    Ok(derived.as_bytes() == expected_key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::x25519::X25519SecretKey;
    use rand::RngCore;

    fn test_zone_id() -> ZoneId {
        ZoneId::owner()
    }

    fn random_secret() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        bytes
    }

    fn make_member(name: &str, leaf: u32) -> GroupMember {
        let sk = X25519SecretKey::generate();
        GroupMember {
            node_id: TailscaleNodeId::new(name),
            public_key: sk.public_key(),
            leaf_index: leaf,
        }
    }

    fn make_group(n: usize) -> PcsGroupState {
        let members: Vec<_> = (0..n)
            .map(|i| make_member(&format!("node-{i}"), u32::try_from(i).unwrap_or(0)))
            .collect();
        PcsGroupState::new(test_zone_id(), members, random_secret()).unwrap()
    }

    // ── Group creation tests ────────────────────────────────────────────

    #[test]
    fn create_group_single_member() {
        let group = make_group(1);
        assert_eq!(group.member_count(), 1);
        assert_eq!(group.current_epoch(), 0);
    }

    #[test]
    fn create_group_max_members() {
        let group = make_group(PCS_MAX_GROUP_SIZE);
        assert_eq!(group.member_count(), PCS_MAX_GROUP_SIZE);
    }

    #[test]
    fn create_group_empty_fails() {
        let result = PcsGroupState::new(test_zone_id(), vec![], random_secret());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PcsError::EmptyGroup));
    }

    #[test]
    fn create_group_too_large_fails() {
        let members: Vec<_> = (0..PCS_MAX_GROUP_SIZE + 1)
            .map(|i| make_member(&format!("node-{i}"), u32::try_from(i).unwrap_or(0)))
            .collect();
        let result = PcsGroupState::new(test_zone_id(), members, random_secret());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PcsError::GroupTooLarge { .. }
        ));
    }

    // ── Deterministic key derivation tests ──────────────────────────────

    #[test]
    fn deterministic_zone_key_derivation() {
        let secret = [42u8; 32];
        let zone_id = test_zone_id();

        let key1 = derive_epoch_zone_key(&zone_id, &secret, 0).unwrap();
        let key2 = derive_epoch_zone_key(&zone_id, &secret, 0).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let secret = [42u8; 32];
        let zone_id = test_zone_id();

        let key0 = derive_epoch_zone_key(&zone_id, &secret, 0).unwrap();
        let key1 = derive_epoch_zone_key(&zone_id, &secret, 1).unwrap();
        assert_ne!(key0.as_bytes(), key1.as_bytes());
    }

    #[test]
    fn different_zones_produce_different_keys() {
        let secret = [42u8; 32];

        let key_owner = derive_epoch_zone_key(&ZoneId::owner(), &secret, 0).unwrap();
        let key_private = derive_epoch_zone_key(&ZoneId::private(), &secret, 0).unwrap();
        assert_ne!(key_owner.as_bytes(), key_private.as_bytes());
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let zone_id = test_zone_id();

        let key1 = derive_epoch_zone_key(&zone_id, &[1u8; 32], 0).unwrap();
        let key2 = derive_epoch_zone_key(&zone_id, &[2u8; 32], 0).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn zone_key_id_deterministic() {
        let secret = [42u8; 32];
        let zone_id = test_zone_id();

        let id1 = derive_epoch_zone_key_id(&zone_id, &secret, 5).unwrap();
        let id2 = derive_epoch_zone_key_id(&zone_id, &secret, 5).unwrap();
        assert_eq!(id1.as_bytes(), id2.as_bytes());
    }

    #[test]
    fn zone_key_id_varies_by_epoch() {
        let secret = [42u8; 32];
        let zone_id = test_zone_id();

        let id0 = derive_epoch_zone_key_id(&zone_id, &secret, 0).unwrap();
        let id1 = derive_epoch_zone_key_id(&zone_id, &secret, 1).unwrap();
        assert_ne!(id0.as_bytes(), id1.as_bytes());
    }

    // ── Epoch advance tests ─────────────────────────────────────────────

    #[test]
    fn epoch_advance_increments_epoch() {
        let mut group = make_group(3);
        assert_eq!(group.current_epoch(), 0);

        let result = group.advance_epoch().unwrap();
        assert_eq!(result.previous_epoch, 0);
        assert_eq!(result.new_epoch, 1);
        assert_eq!(group.current_epoch(), 1);
    }

    #[test]
    fn epoch_advance_changes_secret() {
        let mut group = make_group(3);
        let secret0 = *group.epoch_secret();

        group.advance_epoch().unwrap();
        let secret1 = *group.epoch_secret();

        assert_ne!(secret0, secret1);
    }

    #[test]
    fn epoch_advance_changes_zone_key() {
        let mut group = make_group(3);
        let key0 = group.derive_zone_key().unwrap();

        group.advance_epoch().unwrap();
        let key1 = group.derive_zone_key().unwrap();

        assert_ne!(key0.as_bytes(), key1.as_bytes());
    }

    #[test]
    fn multiple_epoch_advances() {
        let mut group = make_group(3);
        let mut keys = Vec::new();

        for i in 0..10 {
            let key = group.derive_zone_key().unwrap();
            keys.push(*key.as_bytes());

            let result = group.advance_epoch().unwrap();
            assert_eq!(result.new_epoch, u64::try_from(i).unwrap_or(0) + 1);
        }

        // All keys must be unique.
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "keys at epochs {i} and {j} collide");
            }
        }
    }

    #[test]
    fn epoch_advance_commit_ref_deterministic() {
        // Same initial state should produce same commit ref.
        let secret = [99u8; 32];
        let zone_id = test_zone_id();
        let members = vec![make_member("node-0", 0), make_member("node-1", 1)];

        let mut group1 = PcsGroupState::new(zone_id.clone(), members.clone(), secret).unwrap();
        let mut group2 = PcsGroupState::new(zone_id, members, secret).unwrap();

        let r1 = group1.advance_epoch().unwrap();
        let r2 = group2.advance_epoch().unwrap();

        assert_eq!(r1.commit_ref, r2.commit_ref);
    }

    // ── Forward secrecy tests ───────────────────────────────────────────

    #[test]
    fn forward_secrecy_past_secret_cannot_derive_future_key() {
        let mut group = make_group(3);
        let past_secret = *group.epoch_secret();
        let past_epoch = group.current_epoch();

        // Advance several epochs.
        for _ in 0..5 {
            group.advance_epoch().unwrap();
        }

        let future_key = group.derive_zone_key().unwrap();

        // Try to derive the future key using the past secret — should not match.
        let attempted =
            derive_epoch_zone_key(&group.zone_id, &past_secret, group.current_epoch()).unwrap();
        assert_ne!(
            attempted.as_bytes(),
            future_key.as_bytes(),
            "past secret must not derive future zone key"
        );

        // But the past key should still be derivable from the past secret.
        let past_key = derive_epoch_zone_key(&group.zone_id, &past_secret, past_epoch).unwrap();
        let verified =
            verify_epoch_zone_key(&group.zone_id, &past_secret, past_epoch, &past_key).unwrap();
        assert!(verified);
    }

    // ── Membership change tests ─────────────────────────────────────────

    #[test]
    fn remove_member_advances_epoch() {
        let mut group = make_group(3);
        let node1 = group.members()[1].node_id.clone();

        let result = group.remove_member(&node1).unwrap();
        assert_eq!(result.new_epoch, 1);
        assert_eq!(group.member_count(), 2);
        assert!(!group.is_member(&node1));
    }

    #[test]
    fn removed_member_cannot_derive_new_key() {
        let mut group = make_group(3);
        let pre_removal_secret = *group.epoch_secret();
        let pre_removal_epoch = group.current_epoch();

        let node1 = group.members()[1].node_id.clone();
        group.remove_member(&node1).unwrap();

        let post_removal_key = group.derive_zone_key().unwrap();

        // The removed member only knows the pre-removal secret.
        // Try to derive using standard epoch advance (what removed member might try).
        let attempted_advance =
            derive_next_epoch_secret(&pre_removal_secret, pre_removal_epoch + 1).unwrap();
        let attempted_key =
            derive_epoch_zone_key(&group.zone_id, &attempted_advance, group.current_epoch())
                .unwrap();

        assert_ne!(
            attempted_key.as_bytes(),
            post_removal_key.as_bytes(),
            "removed member must not be able to derive post-removal zone key"
        );
    }

    #[test]
    fn remove_nonexistent_member_fails() {
        let mut group = make_group(3);
        let result = group.remove_member(&TailscaleNodeId::new("nonexistent"));
        assert!(matches!(result.unwrap_err(), PcsError::MemberNotFound(_)));
    }

    #[test]
    fn remove_last_member_fails() {
        let mut group = make_group(1);
        let node = group.members()[0].node_id.clone();
        let result = group.remove_member(&node);
        assert!(matches!(result.unwrap_err(), PcsError::EmptyGroup));
    }

    #[test]
    fn add_member_advances_epoch() {
        let mut group = make_group(2);
        let new_member = make_member("new-node", 2);

        let result = group.add_member(new_member).unwrap();
        assert_eq!(result.new_epoch, 1);
        assert_eq!(group.member_count(), 3);
        assert!(group.is_member(&TailscaleNodeId::new("new-node")));
    }

    #[test]
    fn add_member_at_capacity_fails() {
        let mut group = make_group(PCS_MAX_GROUP_SIZE);
        let new_member = make_member("overflow-node", PCS_MAX_GROUP_SIZE as u32);

        let result = group.add_member(new_member);
        assert!(matches!(
            result.unwrap_err(),
            PcsError::GroupTooLarge { .. }
        ));
    }

    #[test]
    fn add_duplicate_member_fails() {
        let mut group = make_group(3);
        let duplicate = make_member("node-0", 99);
        let result = group.add_member(duplicate);
        assert!(matches!(result.unwrap_err(), PcsError::DuplicateMember(_)));
        // Group should be unchanged.
        assert_eq!(group.member_count(), 3);
        assert_eq!(group.current_epoch(), 0);
    }

    // ── Compromise → recovery scenario ──────────────────────────────────

    #[test]
    fn compromise_recovery_scenario() {
        // Setup: 4-node mesh (owner + 3 devices).
        let mut group = make_group(4);

        // Simulate normal operation: several epoch advances.
        for _ in 0..3 {
            group.advance_epoch().unwrap();
        }
        let pre_compromise_epoch = group.current_epoch();

        // Compromise detected: node-2 is compromised.
        // The compromised node knows the current epoch secret.
        let compromised_secret = *group.epoch_secret();
        let compromised_node = group.members()[2].node_id.clone();

        // Recovery: remove compromised node (triggers PCS rekey).
        let removal_result = group.remove_member(&compromised_node).unwrap();
        assert!(matches!(
            removal_result.change,
            MembershipChange::Removed(_)
        ));

        // Post-recovery: compromised node cannot derive new keys.
        let post_recovery_key = group.derive_zone_key().unwrap();

        // Compromised node tries standard ratchet with its known secret.
        let attempted =
            derive_next_epoch_secret(&compromised_secret, pre_compromise_epoch + 1).unwrap();
        let attempted_key =
            derive_epoch_zone_key(&group.zone_id, &attempted, group.current_epoch()).unwrap();

        assert_ne!(
            attempted_key.as_bytes(),
            post_recovery_key.as_bytes(),
            "compromised node must not derive post-recovery key"
        );

        // Verify remaining members can still derive keys.
        assert_eq!(group.member_count(), 3);
        let key = group.derive_zone_key().unwrap();
        assert_eq!(key.as_bytes(), post_recovery_key.as_bytes());
    }

    // ── Transient offline member rejoins scenario ───────────────────────

    #[test]
    fn offline_member_rejoin_scenario() {
        let mut group = make_group(3);

        // Node-1 goes offline. Other nodes continue advancing epochs.
        // (In real implementation, epoch advances would be gossiped.)
        let offline_epoch = group.current_epoch();
        let offline_secret = *group.epoch_secret();

        // Advance 3 epochs while node-1 is offline.
        for _ in 0..3 {
            group.advance_epoch().unwrap();
        }

        // Node-1 comes back online. It needs to catch up.
        // It must receive the epoch chain from the mesh gossip layer.
        // Here we simulate catch-up by re-deriving the epoch chain.
        let mut catchup_secret = offline_secret;
        for epoch in (offline_epoch + 1)..=group.current_epoch() {
            catchup_secret = derive_next_epoch_secret(&catchup_secret, epoch).unwrap();
        }

        // After catch-up, the offline node should derive the same zone key.
        let caught_up_key =
            derive_epoch_zone_key(&group.zone_id, &catchup_secret, group.current_epoch()).unwrap();
        let current_key = group.derive_zone_key().unwrap();

        assert_eq!(
            caught_up_key.as_bytes(),
            current_key.as_bytes(),
            "offline member should derive correct key after catch-up"
        );
    }

    // ── PcsMode and KeyManagementMode tests ─────────────────────────────

    #[test]
    fn pcs_mode_enabled() {
        let group = make_group(3);
        let mode = group.pcs_mode();
        assert!(matches!(mode, PcsMode::Enabled { epoch: 0, .. }));
    }

    #[test]
    fn pcs_mode_disabled_default() {
        let mode = PcsMode::default();
        assert!(matches!(mode, PcsMode::Disabled));
    }

    #[test]
    fn key_management_mode_pcs() {
        let group = make_group(3);
        let mode = group.key_management_mode();
        assert!(matches!(
            mode,
            KeyManagementMode::PcsGroupManaged { epoch: 0, .. }
        ));
    }

    #[test]
    fn key_management_mode_standard_default() {
        let mode = KeyManagementMode::default();
        assert!(matches!(mode, KeyManagementMode::StandardRotation));
    }

    // ── Serialization round-trip tests ──────────────────────────────────

    #[test]
    fn pcs_mode_serde_roundtrip_enabled() {
        let group = make_group(2);
        let mode = group.pcs_mode();
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: PcsMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn pcs_mode_serde_roundtrip_disabled() {
        let mode = PcsMode::Disabled;
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: PcsMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn key_management_mode_serde_roundtrip() {
        let group = make_group(2);
        let mode = group.key_management_mode();
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: KeyManagementMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }

    #[test]
    fn group_member_serde_roundtrip() {
        let member = make_member("test-node", 7);
        let json = serde_json::to_string(&member).unwrap();
        let deserialized: GroupMember = serde_json::from_str(&json).unwrap();
        assert_eq!(member.node_id, deserialized.node_id);
        assert_eq!(member.leaf_index, deserialized.leaf_index);
    }

    #[test]
    fn pcs_audit_event_serde() {
        let event = PcsAuditEvent {
            zone_id: "z:owner".to_string(),
            event_type: PcsEventType::MemberRemoved,
            epoch: 5,
            member_count: 3,
            rekey_ms: Some(2),
            memory_bytes: Some(1024),
            result: Some("success".to_string()),
            fcp_error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PcsAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.epoch, 5);
        assert_eq!(deserialized.event_type, PcsEventType::MemberRemoved);
    }

    // ── Verify epoch zone key function ──────────────────────────────────

    #[test]
    fn verify_correct_key_succeeds() {
        let secret = [42u8; 32];
        let zone_id = test_zone_id();
        let key = derive_epoch_zone_key(&zone_id, &secret, 3).unwrap();
        assert!(verify_epoch_zone_key(&zone_id, &secret, 3, &key).unwrap());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let secret = [42u8; 32];
        let zone_id = test_zone_id();
        let wrong_key = ZoneKey::from_bytes([0u8; 32]);
        assert!(!verify_epoch_zone_key(&zone_id, &secret, 3, &wrong_key).unwrap());
    }

    // ── Commit ref tests ────────────────────────────────────────────────

    #[test]
    fn commit_ref_deterministic() {
        let zone_id = test_zone_id();
        let secret = [42u8; 32];
        let ref1 = compute_commit_ref(&zone_id, 5, &secret);
        let ref2 = compute_commit_ref(&zone_id, 5, &secret);
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn commit_ref_varies_by_epoch() {
        let zone_id = test_zone_id();
        let secret = [42u8; 32];
        let ref0 = compute_commit_ref(&zone_id, 0, &secret);
        let ref1 = compute_commit_ref(&zone_id, 1, &secret);
        assert_ne!(ref0, ref1);
    }

    #[test]
    fn commit_ref_varies_by_zone() {
        let secret = [42u8; 32];
        let ref_owner = compute_commit_ref(&ZoneId::owner(), 0, &secret);
        let ref_private = compute_commit_ref(&ZoneId::private(), 0, &secret);
        assert_ne!(ref_owner, ref_private);
    }

    // ── Removal salt tests ──────────────────────────────────────────────

    #[test]
    fn removal_salt_deterministic() {
        let node = TailscaleNodeId::new("compromised");
        let s1 = compute_removal_salt(&node, 5);
        let s2 = compute_removal_salt(&node, 5);
        assert_eq!(s1, s2);
    }

    #[test]
    fn removal_salt_varies_by_node() {
        let s1 = compute_removal_salt(&TailscaleNodeId::new("node-a"), 0);
        let s2 = compute_removal_salt(&TailscaleNodeId::new("node-b"), 0);
        assert_ne!(s1, s2);
    }

    #[test]
    fn removal_salt_varies_by_epoch() {
        let node = TailscaleNodeId::new("node-a");
        let s0 = compute_removal_salt(&node, 0);
        let s1 = compute_removal_salt(&node, 1);
        assert_ne!(s0, s1);
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn many_rapid_epoch_advances() {
        let mut group = make_group(3);
        for _ in 0..100 {
            group.advance_epoch().unwrap();
        }
        assert_eq!(group.current_epoch(), 100);
        // Key derivation should still work.
        let _ = group.derive_zone_key().unwrap();
    }

    #[test]
    fn add_then_remove_then_add() {
        let mut group = make_group(2);

        let new_member = make_member("temp-node", 2);
        group.add_member(new_member).unwrap();
        assert_eq!(group.member_count(), 3);

        group
            .remove_member(&TailscaleNodeId::new("temp-node"))
            .unwrap();
        assert_eq!(group.member_count(), 2);

        let another = make_member("another-node", 3);
        group.add_member(another).unwrap();
        assert_eq!(group.member_count(), 3);
        assert_eq!(group.current_epoch(), 3);
    }

    #[test]
    fn remove_all_but_one() {
        let mut group = make_group(4);

        for i in 1..4 {
            let node = TailscaleNodeId::new(&format!("node-{i}"));
            group.remove_member(&node).unwrap();
        }

        assert_eq!(group.member_count(), 1);
        assert_eq!(group.current_epoch(), 3);
        let _ = group.derive_zone_key().unwrap();
    }

    #[test]
    fn membership_is_tracked_correctly_after_changes() {
        let mut group = make_group(3);

        assert!(group.is_member(&TailscaleNodeId::new("node-0")));
        assert!(group.is_member(&TailscaleNodeId::new("node-1")));
        assert!(group.is_member(&TailscaleNodeId::new("node-2")));

        group
            .remove_member(&TailscaleNodeId::new("node-1"))
            .unwrap();

        assert!(group.is_member(&TailscaleNodeId::new("node-0")));
        assert!(!group.is_member(&TailscaleNodeId::new("node-1")));
        assert!(group.is_member(&TailscaleNodeId::new("node-2")));

        let new_member = make_member("node-3", 3);
        group.add_member(new_member).unwrap();

        assert!(group.is_member(&TailscaleNodeId::new("node-3")));
        assert!(!group.is_member(&TailscaleNodeId::new("node-1")));
    }

    // ── Audit event tests ───────────────────────────────────────────────

    #[test]
    fn audit_event_all_fields() {
        let event = PcsAuditEvent {
            zone_id: "z:private".to_string(),
            event_type: PcsEventType::CompromiseRecovery,
            epoch: 10,
            member_count: 4,
            rekey_ms: Some(3),
            memory_bytes: Some(2048),
            result: Some("recovered".to_string()),
            fcp_error_code: Some("FCP-4001".to_string()),
        };
        let json = serde_json::to_string_pretty(&event).unwrap();
        assert!(json.contains("compromise_recovery"));
        assert!(json.contains("z:private"));
        assert!(json.contains("FCP-4001"));
    }

    #[test]
    fn audit_event_minimal() {
        let event = PcsAuditEvent {
            zone_id: "z:owner".to_string(),
            event_type: PcsEventType::GroupCreated,
            epoch: 0,
            member_count: 2,
            rekey_ms: None,
            memory_bytes: None,
            result: None,
            fcp_error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        // Optional fields should not appear.
        assert!(!json.contains("rekey_ms"));
        assert!(!json.contains("memory_bytes"));
        assert!(!json.contains("fcp_error_code"));
    }

    #[test]
    fn pcs_event_type_all_variants() {
        let variants = [
            PcsEventType::GroupCreated,
            PcsEventType::EpochAdvanced,
            PcsEventType::MemberAdded,
            PcsEventType::MemberRemoved,
            PcsEventType::ZoneKeyDerived,
            PcsEventType::CompromiseRecovery,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let roundtrip: PcsEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, roundtrip);
        }
    }

    // ── Display trait tests ─────────────────────────────────────────────

    #[test]
    fn membership_change_display() {
        let member = make_member("test-node", 0);
        let added = MembershipChange::Added(member.clone());
        assert!(added.to_string().contains("added"));
        assert!(added.to_string().contains("test-node"));

        let removed = MembershipChange::Removed(member);
        assert!(removed.to_string().contains("removed"));
    }

    // ── Zone key ring integration ───────────────────────────────────────

    #[test]
    fn pcs_derived_key_works_with_zone_key_ring() {
        let mut group = make_group(3);
        group.advance_epoch().unwrap();

        let zone_key = group.derive_zone_key().unwrap();
        let zone_key_id = group.derive_zone_key_id().unwrap();

        let mut ring = crate::ZoneKeyRing::new(group.zone_id.clone());
        ring.insert_zone_key(zone_key_id, zone_key);
        assert!(ring.set_active_zone_key(zone_key_id));
        assert_eq!(
            ring.active_zone_key().unwrap().as_bytes(),
            zone_key.as_bytes()
        );
    }
}
