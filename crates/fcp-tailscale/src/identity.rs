//! Mesh identity types for FCP2 Tailscale integration.
#![allow(clippy::doc_markdown)] // Many struct/type names in docs
//!
//! This module provides:
//! - [`MeshIdentity`] - Node identity with Tailscale `node_id`, keys, and ACL tags
//! - [`NodeKeys`] - Collection of node signing, encryption, and issuance keys
//! - [`NodeKeyAttestation`] - Owner-signed binding of `node_id` ↔ keys ↔ tags

use chrono::{DateTime, Utc};
use fcp_crypto::canonicalize::to_deterministic_cbor;
use fcp_crypto::{
    Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, KeyId, X25519PublicKey,
    canonical_signing_bytes,
};
use fcp_prelude::{TailscaleNodeId, validate_canonical_id};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::{TailscaleError, TailscaleResult};
use crate::tag::TailscaleTag;

/// Tailscale node ID (opaque string identifier).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeId(TailscaleNodeId);

impl NodeId {
    /// Create a new `NodeId` from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(TailscaleNodeId::new(id))
    }

    /// Validate a borrowed node ID without allocating a [`NodeId`].
    ///
    /// # Errors
    ///
    /// Returns an error if the borrowed string is not a canonical
    /// `TailscaleNodeId`.
    pub fn validate_str(id: &str) -> TailscaleResult<&str> {
        validate_canonical_id(id)
            .map(|()| id)
            .map_err(|err| TailscaleError::InvalidNodeId(err.to_string()))
    }

    /// Create a validated `NodeId` from untrusted input.
    ///
    /// # Errors
    ///
    /// Returns an error if the node ID is not a canonical `TailscaleNodeId`.
    pub fn try_new(id: impl Into<String>) -> TailscaleResult<Self> {
        let id = id.into();
        Self::validate_str(&id)?;
        Ok(Self(TailscaleNodeId::new(id)))
    }

    /// Get the node ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<String> for NodeId {
    type Error = TailscaleError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<NodeId> for String {
    fn from(value: NodeId) -> Self {
        value.as_str().to_string()
    }
}

impl From<NodeId> for TailscaleNodeId {
    fn from(value: NodeId) -> Self {
        value.0
    }
}

impl From<TailscaleNodeId> for NodeId {
    fn from(value: TailscaleNodeId) -> Self {
        Self(value)
    }
}

impl FromStr for NodeId {
    type Err = TailscaleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s.to_owned())
    }
}

/// Collection of node cryptographic keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeKeys {
    /// Node signing key (Ed25519) for authenticating messages.
    pub signing_key: Ed25519VerifyingKey,

    /// Node encryption key (X25519) for receiving encrypted data.
    pub encryption_key: X25519PublicKey,

    /// Node issuance key (Ed25519) for minting capability tokens.
    pub issuance_key: Ed25519VerifyingKey,
}

impl NodeKeys {
    /// Create a new NodeKeys instance.
    #[must_use]
    pub const fn new(
        signing_key: Ed25519VerifyingKey,
        encryption_key: X25519PublicKey,
        issuance_key: Ed25519VerifyingKey,
    ) -> Self {
        Self {
            signing_key,
            encryption_key,
            issuance_key,
        }
    }

    /// Get the key ID for the signing key.
    #[must_use]
    pub fn signing_kid(&self) -> KeyId {
        self.signing_key.key_id()
    }

    /// Get the key ID for the encryption key.
    #[must_use]
    pub fn encryption_kid(&self) -> KeyId {
        self.encryption_key.key_id()
    }

    /// Get the key ID for the issuance key.
    #[must_use]
    pub fn issuance_kid(&self) -> KeyId {
        self.issuance_key.key_id()
    }
}

/// Mesh identity for an FCP node.
///
/// This represents a node's identity in the FCP mesh, including its Tailscale
/// identity, cryptographic keys, and ACL tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshIdentity {
    /// Tailscale node ID.
    pub node_id: NodeId,

    /// Hostname of the node.
    pub hostname: String,

    /// IP addresses assigned to this node.
    pub ips: Vec<IpAddr>,

    /// ACL tags assigned to this node.
    pub tags: Vec<TailscaleTag>,

    /// Owner's public key anchor (Ed25519).
    pub owner_pubkey: Ed25519VerifyingKey,

    /// Node's cryptographic keys.
    pub node_keys: NodeKeys,

    /// Owner-signed attestation binding node_id ↔ keys ↔ tags.
    pub attestation: Option<NodeKeyAttestation>,
}

impl MeshIdentity {
    /// Create a new `MeshIdentity`.
    #[must_use]
    pub const fn new(
        node_id: NodeId,
        hostname: String,
        ips: Vec<IpAddr>,
        tags: Vec<TailscaleTag>,
        owner_pubkey: Ed25519VerifyingKey,
        node_keys: NodeKeys,
    ) -> Self {
        Self {
            node_id,
            hostname,
            ips,
            tags,
            owner_pubkey,
            node_keys,
            attestation: None,
        }
    }

    /// Attach an attestation to this identity.
    #[must_use]
    pub fn with_attestation(mut self, attestation: NodeKeyAttestation) -> Self {
        self.attestation = Some(attestation);
        self
    }

    /// Check if this identity has a valid attestation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No attestation is attached (`InvalidAttestation`)
    /// - The attestation has expired (`AttestationExpired`)
    /// - The attestation signature is invalid (`InvalidAttestation`)
    pub fn verify_attestation(&self) -> TailscaleResult<()> {
        let attestation = self
            .attestation
            .as_ref()
            .ok_or(TailscaleError::InvalidAttestation)?;

        attestation.verify(
            &self.owner_pubkey,
            &self.node_id,
            &self.node_keys,
            &self.tags,
        )
    }

    /// Check if the attestation is still valid (not expired).
    #[must_use]
    pub fn is_attestation_valid(&self) -> bool {
        self.attestation
            .as_ref()
            .is_some_and(|a| a.expires_at > Utc::now())
    }

    /// Get the FCP tags (zone memberships) for this node.
    ///
    /// This method only returns tags if the attestation is present and fully
    /// verifies. Unverified tags are ignored to prevent spoofing.
    #[must_use]
    pub fn fcp_tags(&self) -> Vec<&TailscaleTag> {
        if self.verify_attestation().is_err() {
            return Vec::new();
        }
        self.tags.iter().filter(|t| t.is_fcp_tag()).collect()
    }

    /// Get verified FCP tags, returning an error if verification fails.
    ///
    /// # Errors
    /// Returns `TailscaleError` if the attestation is missing, invalid, or expired.
    pub fn verified_fcp_tags(&self) -> TailscaleResult<Vec<&TailscaleTag>> {
        self.verify_attestation()?;
        Ok(self.tags.iter().filter(|t| t.is_fcp_tag()).collect())
    }
}

/// Attestation payload that gets signed.
#[derive(Debug, Clone, Serialize)]
struct AttestationPayload<'a> {
    schema: &'static str,
    node_id: &'a str,
    signing_kid: String,
    encryption_kid: String,
    issuance_kid: String,
    tags: Vec<&'a str>,
    issued_at: i64,
    expires_at: i64,
}

impl AttestationPayload<'_> {
    const SCHEMA: &'static str = "fcp.attestation.v1";
}

fn canonical_tag_strings(tags: &[TailscaleTag]) -> Vec<&str> {
    let mut tags = tags.iter().map(TailscaleTag::as_str).collect::<Vec<_>>();
    tags.sort_unstable();
    tags.dedup();
    tags
}

/// Owner-signed attestation binding node_id ↔ keys ↔ tags.
///
/// This proves that the owner of the mesh has authorized this node with the
/// specified keys and tags. The attestation has a validity period and must
/// be renewed periodically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeKeyAttestation {
    /// When this attestation was issued.
    pub issued_at: DateTime<Utc>,

    /// When this attestation expires.
    pub expires_at: DateTime<Utc>,

    /// Signature over the attestation payload.
    pub signature: Ed25519Signature,

    /// Key ID of the owner key that signed this attestation.
    pub signer_kid: KeyId,
}

impl NodeKeyAttestation {
    /// Create and sign a new attestation.
    ///
    /// The attestation binds the `node_id`, keys, and tags together with the
    /// owner's signature.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization of the attestation payload fails.
    pub fn sign(
        owner_key: &Ed25519SigningKey,
        node_id: &NodeId,
        node_keys: &NodeKeys,
        tags: &[TailscaleTag],
        validity_hours: u32,
    ) -> TailscaleResult<Self> {
        let now = Utc::now();
        let safe_hours = validity_hours.min(24 * 365 * 100); // 100 years max
        let expires_at = now + chrono::Duration::hours(i64::from(safe_hours));

        let payload = AttestationPayload {
            schema: AttestationPayload::SCHEMA,
            node_id: node_id.as_str(),
            signing_kid: node_keys.signing_kid().to_hex(),
            encryption_kid: node_keys.encryption_kid().to_hex(),
            issuance_kid: node_keys.issuance_kid().to_hex(),
            tags: canonical_tag_strings(tags),
            issued_at: now.timestamp(),
            expires_at: expires_at.timestamp(),
        };

        let signing_bytes = canonical_signing_bytes(
            AttestationPayload::SCHEMA,
            &to_deterministic_cbor(&payload)?,
        );

        let signature = owner_key.sign(&signing_bytes);

        Ok(Self {
            issued_at: now,
            expires_at,
            signature,
            signer_kid: owner_key.key_id(),
        })
    }

    /// Verify this attestation against the expected values.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The attestation has expired (`AttestationExpired`)
    /// - The signer key ID doesn't match the owner's key (`InvalidAttestation`)
    /// - The signature verification fails (`InvalidAttestation`)
    /// - JSON serialization of the payload fails
    pub fn verify(
        &self,
        owner_pubkey: &Ed25519VerifyingKey,
        node_id: &NodeId,
        node_keys: &NodeKeys,
        tags: &[TailscaleTag],
    ) -> TailscaleResult<()> {
        // Check expiration
        if self.expires_at <= Utc::now() {
            return Err(TailscaleError::AttestationExpired);
        }

        // Verify signer matches
        if self.signer_kid != owner_pubkey.key_id() {
            return Err(TailscaleError::InvalidAttestation);
        }

        // Reconstruct payload and verify signature
        let payload = AttestationPayload {
            schema: AttestationPayload::SCHEMA,
            node_id: node_id.as_str(),
            signing_kid: node_keys.signing_kid().to_hex(),
            encryption_kid: node_keys.encryption_kid().to_hex(),
            issuance_kid: node_keys.issuance_kid().to_hex(),
            tags: canonical_tag_strings(tags),
            issued_at: self.issued_at.timestamp(),
            expires_at: self.expires_at.timestamp(),
        };

        let signing_bytes = canonical_signing_bytes(
            AttestationPayload::SCHEMA,
            &to_deterministic_cbor(&payload)?,
        );

        owner_pubkey
            .verify(&signing_bytes, &self.signature)
            .map_err(|_| TailscaleError::InvalidAttestation)?;

        Ok(())
    }

    /// Check if this attestation has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Get the remaining validity duration.
    #[must_use]
    pub fn remaining_validity(&self) -> chrono::Duration {
        self.expires_at - Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::X25519SecretKey;

    fn create_test_keys() -> (Ed25519SigningKey, NodeKeys) {
        let owner_key = Ed25519SigningKey::generate();
        let signing_key = Ed25519SigningKey::generate();
        let encryption_key = X25519SecretKey::generate();
        let issuance_key = Ed25519SigningKey::generate();

        let node_keys = NodeKeys::new(
            signing_key.verifying_key(),
            encryption_key.public_key(),
            issuance_key.verifying_key(),
        );

        (owner_key, node_keys)
    }

    #[test]
    fn test_node_id_display() {
        let id = NodeId::new("node-12345");
        assert_eq!(id.to_string(), "node-12345");
        assert_eq!(id.as_str(), "node-12345");
    }

    #[test]
    fn test_node_keys_kids() {
        let (_, node_keys) = create_test_keys();

        // Key IDs should be deterministic
        let kid1 = node_keys.signing_kid();
        let kid2 = node_keys.signing_kid();
        assert_eq!(kid1, kid2);

        // Different keys should have different KIDs
        assert_ne!(node_keys.signing_kid(), node_keys.issuance_kid());
    }

    #[test]
    fn test_mesh_identity_creation() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");

        let identity = MeshIdentity::new(
            node_id.clone(),
            "test-host".to_string(),
            vec!["100.64.0.1".parse().unwrap()],
            vec![TailscaleTag::new("tag:fcp-work").unwrap()],
            owner_key.verifying_key(),
            node_keys,
        );

        assert_eq!(identity.node_id, node_id);
        assert_eq!(identity.hostname, "test-host");
        assert_eq!(identity.ips.len(), 1);
        assert_eq!(identity.tags.len(), 1);
        assert!(identity.attestation.is_none());
    }

    #[test]
    fn test_attestation_sign_and_verify() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let tags = vec![
            TailscaleTag::new("tag:fcp-work").unwrap(),
            TailscaleTag::new("tag:fcp-private").unwrap(),
        ];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify should succeed
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();

        // Should not be expired
        assert!(!attestation.is_expired());
    }

    #[test]
    fn test_attestation_wrong_node_id() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let wrong_node_id = NodeId::new("wrong-node");
        let tags = vec![TailscaleTag::new("tag:fcp-work").unwrap()];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify with wrong node_id should fail
        let result = attestation.verify(
            &owner_key.verifying_key(),
            &wrong_node_id,
            &node_keys,
            &tags,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_wrong_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let tags = vec![TailscaleTag::new("tag:fcp-work").unwrap()];
        let wrong_tags = vec![TailscaleTag::new("tag:fcp-private").unwrap()];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify with wrong tags should fail
        let result = attestation.verify(
            &owner_key.verifying_key(),
            &node_id,
            &node_keys,
            &wrong_tags,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_wrong_owner() {
        let (owner_key, node_keys) = create_test_keys();
        let wrong_owner_key = Ed25519SigningKey::generate();
        let node_id = NodeId::new("test-node");
        let tags = vec![TailscaleTag::new("tag:fcp-work").unwrap()];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify with wrong owner should fail
        let result = attestation.verify(
            &wrong_owner_key.verifying_key(),
            &node_id,
            &node_keys,
            &tags,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mesh_identity_with_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let tags = vec![TailscaleTag::new("tag:fcp-work").unwrap()];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let identity = MeshIdentity::new(
            node_id,
            "test-host".to_string(),
            vec!["100.64.0.1".parse().unwrap()],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        // Verify attestation should succeed
        identity.verify_attestation().unwrap();
        assert!(identity.is_attestation_valid());
    }

    #[test]
    fn test_fcp_tags_filter() {
        // `fcp_tags()` requires a valid attestation post-8a0d49596;
        // build one over the exact (node_id, tags, node_keys) we'll
        // hand to `MeshIdentity::new` so the surfaced filter sees the
        // expected 2 FCP tags.
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");

        // Mix of FCP and non-FCP tags
        let tags = vec![
            TailscaleTag::new("tag:fcp-work").unwrap(),
            TailscaleTag::new("tag:server").unwrap(),
            TailscaleTag::new("tag:fcp-private").unwrap(),
        ];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "test-host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let fcp_tags = identity.fcp_tags();
        assert_eq!(fcp_tags.len(), 2);
        assert!(fcp_tags.iter().any(|t| t.as_str() == "tag:fcp-work"));
        assert!(fcp_tags.iter().any(|t| t.as_str() == "tag:fcp-private"));
    }

    #[test]
    fn test_node_id_clone_and_eq() {
        let id = NodeId::new("node-abc");
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn test_node_id_hash_consistent() {
        use std::collections::HashSet;
        let id1 = NodeId::new("node-abc");
        let id2 = NodeId::new("node-abc");
        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_attestation_with_empty_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let tags: Vec<TailscaleTag> = vec![];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    #[test]
    fn test_attestation_remaining_validity_positive() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let tags = vec![TailscaleTag::new("tag:fcp-work").unwrap()];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let remaining = attestation.remaining_validity();
        assert!(remaining.num_hours() >= 23);
    }

    #[test]
    fn test_mesh_identity_no_attestation_verify_fails() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");

        let identity = MeshIdentity::new(
            node_id,
            "test-host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );

        // No attestation attached → verify should fail
        let result = identity.verify_attestation();
        assert!(result.is_err());
        assert!(!identity.is_attestation_valid());
    }

    #[test]
    fn test_mesh_identity_fcp_tags_with_no_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );

        assert!(identity.fcp_tags().is_empty());
    }

    #[test]
    fn test_mesh_identity_fcp_tags_with_only_non_fcp_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            vec![
                TailscaleTag::new("tag:server").unwrap(),
                TailscaleTag::new("tag:web").unwrap(),
            ],
            owner_key.verifying_key(),
            node_keys,
        );

        assert!(identity.fcp_tags().is_empty());
    }

    #[test]
    fn test_attestation_wrong_keys() {
        let (owner_key, node_keys) = create_test_keys();
        let (_, wrong_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");
        let tags = vec![TailscaleTag::new("tag:fcp-work").unwrap()];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify with wrong keys should fail (different key IDs in payload)
        let result = attestation.verify(&owner_key.verifying_key(), &node_id, &wrong_keys, &tags);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_keys_all_kids_different() {
        let (_, node_keys) = create_test_keys();
        let signing = node_keys.signing_kid();
        let encryption = node_keys.encryption_kid();
        let issuance = node_keys.issuance_kid();

        // All three key IDs should be distinct
        assert_ne!(signing, encryption);
        assert_ne!(signing, issuance);
        assert_ne!(encryption, issuance);
    }

    // --- NodeId: Debug, serde roundtrip, Display matches as_str, Clone ---

    #[test]
    fn test_node_id_debug() {
        let id = NodeId::new("n-42");
        let dbg = format!("{id:?}");
        assert!(dbg.contains("NodeId"));
        assert!(dbg.contains("n-42"));
    }

    #[test]
    fn test_node_id_serde_roundtrip() {
        let id = NodeId::new("stable-id-xyz");
        let json = serde_json::to_string(&id).unwrap();
        let decoded: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
        assert_eq!(decoded.as_str(), "stable-id-xyz");
    }

    #[test]
    fn test_node_id_display_matches_as_str() {
        let id = NodeId::new("node-display-test");
        assert_eq!(id.to_string(), id.as_str());
    }

    #[test]
    fn test_node_id_clone() {
        let id = NodeId::new("clone-me");
        let cloned = id.clone();
        assert_eq!(id, cloned);
        // Mutating the clone doesn't affect original (they're independent Strings)
        drop(cloned);
        assert_eq!(id.as_str(), "clone-me");
    }

    // --- NodeKeys: Clone, Debug ---

    #[test]
    fn test_node_keys_clone() {
        let (_, keys) = create_test_keys();
        let cloned = keys.clone();
        assert_eq!(keys.signing_kid(), cloned.signing_kid());
        assert_eq!(keys.encryption_kid(), cloned.encryption_kid());
        assert_eq!(keys.issuance_kid(), cloned.issuance_kid());
    }

    #[test]
    fn test_node_keys_debug() {
        let (_, keys) = create_test_keys();
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("NodeKeys"));
        assert!(dbg.contains("signing_key"));
        assert!(dbg.contains("encryption_key"));
        assert!(dbg.contains("issuance_key"));
    }

    // --- MeshIdentity: Clone, Debug, multiple IPs, hostname preserved ---

    #[test]
    fn test_mesh_identity_clone() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("clone-node"),
            "host-clone".to_string(),
            vec!["100.64.0.5".parse().unwrap()],
            vec![TailscaleTag::fcp_tag("work")],
            owner_key.verifying_key(),
            node_keys,
        );
        let cloned = identity.clone();
        assert_eq!(cloned.node_id, identity.node_id);
        assert_eq!(cloned.hostname, identity.hostname);
        assert_eq!(cloned.ips, identity.ips);
    }

    #[test]
    fn test_mesh_identity_debug() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("debug-node"),
            "host-debug".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let dbg = format!("{identity:?}");
        assert!(dbg.contains("MeshIdentity"));
        assert!(dbg.contains("debug-node"));
        assert!(dbg.contains("host-debug"));
    }

    #[test]
    fn test_mesh_identity_multiple_ips() {
        let (owner_key, node_keys) = create_test_keys();
        let ips: Vec<IpAddr> = vec![
            "100.64.0.1".parse().unwrap(),
            "fd7a:115c:a1e0::1".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
        ];
        let identity = MeshIdentity::new(
            NodeId::new("multi-ip"),
            "multi".to_string(),
            ips.clone(),
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.ips.len(), 3);
        assert_eq!(identity.ips, ips);
    }

    #[test]
    fn test_mesh_identity_hostname_preserved() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("n"),
            "my-special-hostname.local".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.hostname, "my-special-hostname.local");
    }

    // --- NodeKeyAttestation: Debug, Clone, signer_kid matches owner key ---

    #[test]
    fn test_attestation_debug() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("debug-attest");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 1).unwrap();
        let dbg = format!("{attestation:?}");
        assert!(dbg.contains("NodeKeyAttestation"));
        assert!(dbg.contains("issued_at"));
        assert!(dbg.contains("expires_at"));
        assert!(dbg.contains("signer_kid"));
    }

    #[test]
    fn test_attestation_clone() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("clone-attest");
        let tags = vec![TailscaleTag::fcp_tag("owner")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let cloned = attestation.clone();
        assert_eq!(cloned.issued_at, attestation.issued_at);
        assert_eq!(cloned.expires_at, attestation.expires_at);
        assert_eq!(cloned.signer_kid, attestation.signer_kid);
    }

    #[test]
    fn test_attestation_signer_kid_matches_owner() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("kid-match");
        let tags = vec![];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        assert_eq!(attestation.signer_kid, owner_key.key_id());
    }

    // --- Attestation with 0 validity_hours (expires immediately) ---

    #[test]
    fn test_attestation_zero_validity_expires_immediately() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("zero-validity");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 0).unwrap();

        // With 0 hours, expires_at == issued_at, so it is already expired
        assert!(attestation.is_expired());
        let result = attestation.verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags);
        assert!(result.is_err());
    }

    // --- Attestation with very large validity_hours ---

    #[test]
    fn test_attestation_large_validity() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("long-lived");
        let tags = vec![TailscaleTag::fcp_tag("community")];
        // 10 years in hours
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 87_600).unwrap();

        assert!(!attestation.is_expired());
        let remaining = attestation.remaining_validity();
        // Should be at least 87_000 hours remaining (allowing for test execution time)
        assert!(remaining.num_hours() >= 87_000);
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- MeshIdentity serde roundtrip ---

    #[test]
    fn test_mesh_identity_serde_roundtrip() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("serde-node"),
            "serde-host".to_string(),
            vec![
                "100.64.0.10".parse().unwrap(),
                "fd7a:115c:a1e0::42".parse().unwrap(),
            ],
            vec![
                TailscaleTag::fcp_tag("work"),
                TailscaleTag::fcp_tag("private"),
            ],
            owner_key.verifying_key(),
            node_keys,
        );

        let json = serde_json::to_string(&identity).unwrap();
        let decoded: MeshIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.node_id, identity.node_id);
        assert_eq!(decoded.hostname, identity.hostname);
        assert_eq!(decoded.ips, identity.ips);
        assert_eq!(decoded.tags, identity.tags);
        assert!(decoded.attestation.is_none());
    }

    // --- fcp_tags with all FCP tags ---

    #[test]
    fn test_fcp_tags_all_fcp() {
        // `fcp_tags()` requires a valid attestation post-8a0d49596.
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("all-fcp");
        let tags = vec![
            TailscaleTag::fcp_tag("owner"),
            TailscaleTag::fcp_tag("private"),
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::fcp_tag("community"),
            TailscaleTag::fcp_tag("public"),
        ];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        let fcp_tags = identity.fcp_tags();
        assert_eq!(fcp_tags.len(), 5);
        // All should be FCP tags
        for t in &fcp_tags {
            assert!(t.is_fcp_tag());
        }
    }

    // --- NodeId edge cases and trait coverage ---

    #[test]
    fn test_node_id_empty_string() {
        let id = NodeId::new("");
        assert_eq!(id.as_str(), "");
        assert_eq!(id.to_string(), "");
    }

    #[test]
    fn test_node_id_unicode() {
        let id = NodeId::new("nöde-日本語-🚀");
        assert_eq!(id.as_str(), "nöde-日本語-🚀");
        assert_eq!(id.to_string(), "nöde-日本語-🚀");
    }

    #[test]
    fn test_node_id_long_string() {
        let long_id = "a".repeat(1024);
        let id = NodeId::new(long_id.clone());
        assert_eq!(id.as_str(), long_id);
    }

    #[test]
    fn test_node_id_equality_different_ids() {
        let id1 = NodeId::new("node-1");
        let id2 = NodeId::new("node-2");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_id_hash_different_ids() {
        use std::collections::HashSet;
        let id1 = NodeId::new("node-alpha");
        let id2 = NodeId::new("node-beta");
        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_node_id_from_string_owned() {
        let owned = String::from("owned-id");
        let id = NodeId::new(owned);
        assert_eq!(id.as_str(), "owned-id");
    }

    #[test]
    fn test_node_id_serde_rejects_empty() {
        let err = serde_json::from_str::<NodeId>(r#""""#).unwrap_err();
        assert!(err.to_string().contains("invalid node ID"));
    }

    #[test]
    fn test_node_id_try_new_accepts_canonical_id() {
        let id = NodeId::try_new("node-validated").unwrap();
        assert_eq!(id.as_str(), "node-validated");
    }

    #[test]
    fn test_node_id_try_new_rejects_unicode() {
        assert!(matches!(
            NodeId::try_new("nöde-日本語"),
            Err(TailscaleError::InvalidNodeId(_))
        ));
    }

    // --- NodeKeys serde roundtrip ---

    #[test]
    fn test_node_keys_serde_roundtrip() {
        let (_, node_keys) = create_test_keys();
        let json = serde_json::to_string(&node_keys).unwrap();
        let decoded: NodeKeys = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.signing_kid(), node_keys.signing_kid());
        assert_eq!(decoded.encryption_kid(), node_keys.encryption_kid());
        assert_eq!(decoded.issuance_kid(), node_keys.issuance_kid());
    }

    // --- NodeKeys: KIDs are deterministic across clones ---

    #[test]
    fn test_node_keys_kids_stable_across_clone() {
        let (_, keys) = create_test_keys();
        let cloned = keys.clone();
        assert_eq!(keys.signing_kid(), cloned.signing_kid());
        assert_eq!(keys.encryption_kid(), cloned.encryption_kid());
        assert_eq!(keys.issuance_kid(), cloned.issuance_kid());
        // Drop original, cloned remains valid
        drop(keys);
        let _ = cloned.signing_kid();
    }

    // --- MeshIdentity with_attestation replaces previous attestation ---

    #[test]
    fn test_mesh_identity_with_attestation_replaces() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("replace-attest");
        let tags = vec![TailscaleTag::fcp_tag("work")];

        let attest1 =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let attest2 =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 48).unwrap();

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attest1)
        .with_attestation(attest2.clone());

        // The second attestation should be the one attached
        let attached = identity.attestation.as_ref().unwrap();
        assert_eq!(attached.expires_at, attest2.expires_at);
    }

    // --- MeshIdentity: empty IPs ---

    #[test]
    fn test_mesh_identity_empty_ips() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("no-ips"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert!(identity.ips.is_empty());
    }

    // --- MeshIdentity: IPv6-only ---

    #[test]
    fn test_mesh_identity_ipv6_only() {
        let (owner_key, node_keys) = create_test_keys();
        let ips: Vec<IpAddr> = vec![
            "fd7a:115c:a1e0::1".parse().unwrap(),
            "fd7a:115c:a1e0::2".parse().unwrap(),
        ];
        let identity = MeshIdentity::new(
            NodeId::new("ipv6-node"),
            "v6host".to_string(),
            ips,
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.ips.len(), 2);
        assert!(identity.ips.iter().all(std::net::IpAddr::is_ipv6));
    }

    // --- MeshIdentity serde roundtrip with attestation ---

    #[test]
    fn test_mesh_identity_serde_roundtrip_with_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("serde-attest-node");
        let tags = vec![TailscaleTag::fcp_tag("work")];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let identity = MeshIdentity::new(
            node_id.clone(),
            "serde-attest-host".to_string(),
            vec!["100.64.0.99".parse().unwrap()],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let json = serde_json::to_string(&identity).unwrap();
        let decoded: MeshIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.hostname, "serde-attest-host");
        assert!(decoded.attestation.is_some());
        let decoded_attest = decoded.attestation.as_ref().unwrap();
        assert_eq!(
            decoded_attest.signer_kid,
            identity.attestation.as_ref().unwrap().signer_kid
        );
    }

    // --- NodeKeyAttestation: verify fails with tampered tags (extra tag) ---

    #[test]
    fn test_attestation_extra_tag_fails_verify() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("extra-tag");
        let tags = vec![TailscaleTag::fcp_tag("work")];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify with an extra tag
        let mut extra_tags = tags;
        extra_tags.push(TailscaleTag::fcp_tag("private"));
        let result = attestation.verify(
            &owner_key.verifying_key(),
            &node_id,
            &node_keys,
            &extra_tags,
        );
        assert!(result.is_err());
    }

    // --- NodeKeyAttestation: verify fails with fewer tags ---

    #[test]
    fn test_attestation_fewer_tags_fails_verify() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("fewer-tags");
        let tags = vec![
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::fcp_tag("private"),
        ];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Verify with fewer tags
        let fewer = vec![TailscaleTag::fcp_tag("work")];
        let result = attestation.verify(&owner_key.verifying_key(), &node_id, &node_keys, &fewer);
        assert!(result.is_err());
    }

    // --- NodeKeyAttestation: 1-hour validity ---

    #[test]
    fn test_attestation_one_hour_validity() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("one-hour");
        let tags = vec![];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 1).unwrap();

        assert!(!attestation.is_expired());
        let remaining = attestation.remaining_validity();
        // Should be between 0 and 1 hour (allowing for test execution time)
        assert!(remaining.num_minutes() >= 59);
        assert!(remaining.num_minutes() <= 60);
    }

    // --- NodeKeyAttestation serde roundtrip ---

    #[test]
    fn test_attestation_serde_roundtrip() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("serde-attest");
        let tags = vec![TailscaleTag::fcp_tag("community")];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let json = serde_json::to_string(&attestation).unwrap();
        let decoded: NodeKeyAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.issued_at, attestation.issued_at);
        assert_eq!(decoded.expires_at, attestation.expires_at);
        assert_eq!(decoded.signer_kid, attestation.signer_kid);
    }

    // --- MeshIdentity: verify_attestation error type for missing attestation ---

    #[test]
    fn test_verify_attestation_missing_returns_invalid_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("no-attest"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let err = identity.verify_attestation().unwrap_err();
        assert!(matches!(err, TailscaleError::InvalidAttestation));
    }

    // --- MeshIdentity: fcp_tags preserves order ---

    #[test]
    fn test_fcp_tags_preserves_insertion_order() {
        // `fcp_tags()` requires a valid attestation post-8a0d49596.
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("order-test");
        let tags = vec![
            TailscaleTag::fcp_tag("public"),
            TailscaleTag::new("tag:server").unwrap(),
            TailscaleTag::fcp_tag("owner"),
            TailscaleTag::new("tag:web").unwrap(),
            TailscaleTag::fcp_tag("work"),
        ];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        let fcp_tags = identity.fcp_tags();
        assert_eq!(fcp_tags.len(), 3);
        assert_eq!(fcp_tags[0].as_str(), "tag:fcp-public");
        assert_eq!(fcp_tags[1].as_str(), "tag:fcp-owner");
        assert_eq!(fcp_tags[2].as_str(), "tag:fcp-work");
    }

    // --- NodeId: special characters ---

    #[test]
    fn test_node_id_with_special_chars() {
        let id = NodeId::new("node/path:special@chars");
        assert_eq!(id.as_str(), "node/path:special@chars");
        assert_eq!(id.to_string(), "node/path:special@chars");
    }

    #[test]
    fn test_node_id_with_whitespace() {
        let id = NodeId::new("node with spaces");
        assert_eq!(id.as_str(), "node with spaces");
    }

    #[test]
    fn test_node_id_with_newline() {
        let id = NodeId::new("node\nnewline");
        assert!(id.as_str().contains('\n'));
    }

    // --- NodeId: serde with special chars ---

    #[test]
    fn test_node_id_serde_roundtrip_unicode() {
        // The constructor `NodeId::new` is permissive (it wraps any
        // string), but the serde deserialize path goes through
        // `TryFrom<String>` → `TailscaleNodeId::try_new`, which rejects
        // any non-ASCII codepoint. That means a NodeId containing
        // Unicode is *not* round-trippable — the deserialize side fails
        // closed with `InvalidNodeId("identifier must be ASCII")`.
        //
        // The original test asserted the round-trip succeeded; that
        // hasn't been true since the NodeId validation was tightened
        // in fcp-core (commit 19745bc08). The test was born broken.
        // Repurpose it to pin the actual contract: serialization of a
        // permissively-constructed Unicode NodeId emits its bytes (so
        // log/audit pipelines can still record the offending value),
        // but deserialization rejects it. That's the security-relevant
        // invariant — it prevents an untrusted CBOR/JSON wire payload
        // from smuggling in a non-canonical node identity.
        let id = NodeId::new("nöde-日本語");
        let json = serde_json::to_string(&id).unwrap();
        let err = serde_json::from_str::<NodeId>(&json)
            .expect_err("non-ASCII node ID must be rejected on deserialize");
        assert!(
            err.to_string().contains("must be ASCII"),
            "expected ASCII-rejection message, got {err}"
        );
    }

    #[test]
    fn test_node_id_serde_json_contains_string() {
        let id = NodeId::new("test-id");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
    }

    // --- NodeId: inequality ---

    #[test]
    fn test_node_id_case_sensitive() {
        let id1 = NodeId::new("Node");
        let id2 = NodeId::new("node");
        assert_ne!(id1, id2);
    }

    // --- NodeKeys: serde stability ---

    #[test]
    fn test_node_keys_serde_json_has_expected_fields() {
        let (_, keys) = create_test_keys();
        let json = serde_json::to_string(&keys).unwrap();
        assert!(json.contains("signing_key"));
        assert!(json.contains("encryption_key"));
        assert!(json.contains("issuance_key"));
    }

    // --- MeshIdentity: hostname edge cases ---

    #[test]
    fn test_mesh_identity_empty_hostname() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("n"),
            String::new(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.hostname, "");
    }

    #[test]
    fn test_mesh_identity_long_hostname() {
        let (owner_key, node_keys) = create_test_keys();
        let long_hostname = "h".repeat(512);
        let identity = MeshIdentity::new(
            NodeId::new("n"),
            long_hostname.clone(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.hostname, long_hostname);
    }

    // --- MeshIdentity: many IPs ---

    #[test]
    fn test_mesh_identity_many_ips() {
        let (owner_key, node_keys) = create_test_keys();
        let ips: Vec<IpAddr> = (1..=20)
            .map(|i| format!("100.64.0.{i}").parse().unwrap())
            .collect();
        let identity = MeshIdentity::new(
            NodeId::new("many-ips"),
            "host".to_string(),
            ips.clone(),
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.ips.len(), 20);
        assert_eq!(identity.ips, ips);
    }

    // --- MeshIdentity: many tags ---

    #[test]
    fn test_mesh_identity_many_tags() {
        // `fcp_tags()` was tightened in commit 8a0d49596 to surface
        // tags ONLY when `is_attestation_valid()` holds — without an
        // attestation it returns the empty Vec. The legacy form of
        // this test built `MeshIdentity::new(...)` without an
        // attestation and asserted `fcp_tags().len() == 10`, which
        // post-tightening is unconditionally 0. Real production
        // identities always carry a verified attestation; the test
        // now mirrors that by signing with the owner key before
        // asserting the surface count.
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("many-tags");
        let tags: Vec<TailscaleTag> = (0..10)
            .map(|i| TailscaleTag::fcp_tag(&format!("zone{i}")))
            .collect();
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        assert_eq!(identity.tags.len(), 10);
        assert_eq!(identity.fcp_tags().len(), 10);
    }

    // --- MeshIdentity: serde with no IPs or tags ---

    #[test]
    fn test_mesh_identity_serde_roundtrip_empty_collections() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("empty-collections"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let json = serde_json::to_string(&identity).unwrap();
        let decoded: MeshIdentity = serde_json::from_str(&json).unwrap();
        assert!(decoded.ips.is_empty());
        assert!(decoded.tags.is_empty());
        assert!(decoded.attestation.is_none());
    }

    // --- Attestation: many tags ---

    #[test]
    fn test_attestation_many_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("many-tags-attest");
        let tags: Vec<TailscaleTag> = (0..20)
            .map(|i| TailscaleTag::fcp_tag(&format!("zone{i}")))
            .collect();
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- Attestation: serde preserves issued_at and expires_at ---

    #[test]
    fn test_attestation_serde_preserves_timestamps() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("ts-attest");
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &[], 48).unwrap();
        let json = serde_json::to_string(&attestation).unwrap();
        let decoded: NodeKeyAttestation = serde_json::from_str(&json).unwrap();

        // Timestamps should survive roundtrip
        assert_eq!(decoded.issued_at, attestation.issued_at);
        assert_eq!(decoded.expires_at, attestation.expires_at);
        assert_eq!(decoded.signer_kid, attestation.signer_kid);
    }

    // --- Attestation: different validity hours produce different expiry ---

    #[test]
    fn test_attestation_different_validity_hours() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("diff-validity");
        let a1 = NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &[], 1).unwrap();
        let a2 = NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &[], 100).unwrap();

        let r1 = a1.remaining_validity();
        let r2 = a2.remaining_validity();
        assert!(r2.num_hours() > r1.num_hours());
    }

    // --- Attestation: is_expired matches remaining_validity sign ---

    #[test]
    fn test_attestation_is_expired_consistent_with_remaining() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("consistency");
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &[], 24).unwrap();

        // Not expired → remaining validity should be positive
        assert!(!attestation.is_expired());
        assert!(attestation.remaining_validity().num_seconds() > 0);
    }

    // --- MeshIdentity: is_attestation_valid false when no attestation ---

    #[test]
    fn test_mesh_identity_is_attestation_valid_without_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("no-attest"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert!(!identity.is_attestation_valid());
    }

    // --- MeshIdentity: JSON roundtrip preserves tag order ---

    #[test]
    fn test_mesh_identity_serde_preserves_tag_order() {
        let (owner_key, node_keys) = create_test_keys();
        let tags = vec![
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::fcp_tag("private"),
            TailscaleTag::fcp_tag("owner"),
        ];
        let identity = MeshIdentity::new(
            NodeId::new("order"),
            "host".to_string(),
            vec![],
            tags.clone(),
            owner_key.verifying_key(),
            node_keys,
        );
        let json = serde_json::to_string(&identity).unwrap();
        let decoded: MeshIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tags, tags);
    }

    // --- MeshIdentity serde JSON field names ---

    #[test]
    fn test_mesh_identity_serde_field_names() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("fields"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let json = serde_json::to_string(&identity).unwrap();
        assert!(json.contains("node_id"));
        assert!(json.contains("hostname"));
        assert!(json.contains("ips"));
        assert!(json.contains("tags"));
        assert!(json.contains("owner_pubkey"));
        assert!(json.contains("node_keys"));
    }

    // --- NodeId: Hash consistency across clone ---

    #[test]
    fn test_node_id_hash_consistent_across_clone() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let id = NodeId::new("hash-test");
        let cloned = id.clone();

        let mut h1 = DefaultHasher::new();
        id.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        cloned.hash(&mut h2);
        let hash2 = h2.finish();

        assert_eq!(hash1, hash2);
    }

    // --- MeshIdentity: mixed IPv4 and IPv6 ---

    #[test]
    fn test_mesh_identity_mixed_ipv4_ipv6() {
        let (owner_key, node_keys) = create_test_keys();
        let ips: Vec<IpAddr> = vec![
            "100.64.0.1".parse().unwrap(),
            "fd7a:115c:a1e0::1".parse().unwrap(),
        ];
        let identity = MeshIdentity::new(
            NodeId::new("mixed-ip"),
            "host".to_string(),
            ips,
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert!(identity.ips[0].is_ipv4());
        assert!(identity.ips[1].is_ipv6());
    }

    // --- Attestation: verify with reordered tags succeeds for same logical set ---

    #[test]
    fn test_attestation_reordered_tags_succeeds() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("reorder");
        let tags = vec![
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::fcp_tag("private"),
        ];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        // Reversed order
        let reversed_tags = vec![
            TailscaleTag::fcp_tag("private"),
            TailscaleTag::fcp_tag("work"),
        ];
        let result = attestation.verify(
            &owner_key.verifying_key(),
            &node_id,
            &node_keys,
            &reversed_tags,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_attestation_duplicate_tags_verify_as_set() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("dedup");
        let duplicated_tags = vec![
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::fcp_tag("private"),
            TailscaleTag::fcp_tag("work"),
        ];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &duplicated_tags, 24)
                .unwrap();

        let deduped_tags = vec![
            TailscaleTag::fcp_tag("private"),
            TailscaleTag::fcp_tag("work"),
        ];
        assert!(
            attestation
                .verify(
                    &owner_key.verifying_key(),
                    &node_id,
                    &node_keys,
                    &deduped_tags,
                )
                .is_ok()
        );
    }

    // --- Attestation: single tag works ---

    #[test]
    fn test_attestation_single_tag() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("single-tag");
        let tags = vec![TailscaleTag::fcp_tag("owner")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- NodeId: serde as JSON value ---

    #[test]
    fn test_node_id_serde_value_is_string() {
        let id = NodeId::new("value-test");
        let val: serde_json::Value = serde_json::to_value(&id).unwrap();
        assert!(val.is_string());
        assert_eq!(val.as_str().unwrap(), "value-test");
    }

    #[test]
    fn test_node_id_deserialize_from_value() {
        let val = serde_json::Value::String("from-value".to_string());
        let id: NodeId = serde_json::from_value(val).unwrap();
        assert_eq!(id.as_str(), "from-value");
    }

    // --- NodeId: Hash with many entries ---

    #[test]
    fn test_node_id_hash_many_entries() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        for i in 0..50 {
            set.insert(NodeId::new(format!("node-{i}")));
        }
        assert_eq!(set.len(), 50);
        // Re-inserting same IDs doesn't grow set
        for i in 0..50 {
            set.insert(NodeId::new(format!("node-{i}")));
        }
        assert_eq!(set.len(), 50);
    }

    // --- NodeKeys: deterministic kid across serde roundtrip ---

    #[test]
    fn test_node_keys_kid_stable_across_serde() {
        let (_, keys) = create_test_keys();
        let signing_kid = keys.signing_kid();
        let encryption_kid = keys.encryption_kid();
        let issuance_kid = keys.issuance_kid();

        let json = serde_json::to_string(&keys).unwrap();
        let decoded: NodeKeys = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.signing_kid(), signing_kid);
        assert_eq!(decoded.encryption_kid(), encryption_kid);
        assert_eq!(decoded.issuance_kid(), issuance_kid);
    }

    // --- NodeKeys: JSON value shape ---

    #[test]
    fn test_node_keys_serde_value_is_object() {
        let (_, keys) = create_test_keys();
        let val: serde_json::Value = serde_json::to_value(&keys).unwrap();
        assert!(val.is_object());
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("signing_key"));
        assert!(obj.contains_key("encryption_key"));
        assert!(obj.contains_key("issuance_key"));
    }

    // --- MeshIdentity: serde value shape ---

    #[test]
    fn test_mesh_identity_serde_value_is_object() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("val-obj"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let val: serde_json::Value = serde_json::to_value(&identity).unwrap();
        assert!(val.is_object());
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("node_id"));
        assert!(obj.contains_key("hostname"));
        assert!(obj.contains_key("ips"));
        assert!(obj.contains_key("tags"));
    }

    // --- MeshIdentity: attestation field null in JSON when absent ---

    #[test]
    fn test_mesh_identity_attestation_null_in_json() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("null-attest"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let val: serde_json::Value = serde_json::to_value(&identity).unwrap();
        assert!(val.get("attestation").unwrap().is_null());
    }

    // --- MeshIdentity: attestation field present in JSON when set ---

    #[test]
    fn test_mesh_identity_attestation_present_in_json() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("with-attest");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        let val: serde_json::Value = serde_json::to_value(&identity).unwrap();
        assert!(val.get("attestation").unwrap().is_object());
    }

    // --- NodeKeyAttestation: JSON field names ---

    #[test]
    fn test_attestation_json_field_names() {
        let (owner_key, node_keys) = create_test_keys();
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &NodeId::new("fields"), &node_keys, &[], 24)
                .unwrap();
        let json = serde_json::to_string(&attestation).unwrap();
        assert!(json.contains("issued_at"));
        assert!(json.contains("expires_at"));
        assert!(json.contains("signature"));
        assert!(json.contains("signer_kid"));
    }

    // --- Attestation: verify with empty node_id ---

    #[test]
    fn test_attestation_sign_verify_empty_node_id() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("");
        let tags = vec![];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- Attestation: verify with non-fcp tags ---

    #[test]
    fn test_attestation_sign_verify_non_fcp_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("non-fcp");
        let tags = vec![
            TailscaleTag::new("tag:server").unwrap(),
            TailscaleTag::new("tag:web").unwrap(),
        ];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- Attestation: different owner keys produce different signer_kid ---

    #[test]
    fn test_attestation_different_owners_different_kid() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let (_, node_keys) = create_test_keys();
        let node_id = NodeId::new("kid-diff");

        let a1 = NodeKeyAttestation::sign(&key1, &node_id, &node_keys, &[], 24).unwrap();
        let a2 = NodeKeyAttestation::sign(&key2, &node_id, &node_keys, &[], 24).unwrap();

        assert_ne!(a1.signer_kid, a2.signer_kid);
    }

    // --- MeshIdentity: fcp_tags returns references to the identity's tags ---

    #[test]
    fn test_fcp_tags_returns_references() {
        // `fcp_tags()` requires a valid attestation post-8a0d49596.
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("ref-test");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        let fcp_tags = identity.fcp_tags();
        assert_eq!(fcp_tags.len(), 1);
        // The reference should point into identity.tags
        assert!(std::ptr::eq(fcp_tags[0], &raw const identity.tags[0]));
    }

    // --- MeshIdentity: with_attestation is chainable ---

    #[test]
    fn test_with_attestation_chainable() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("chain");
        let tags = vec![];
        let a = NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(a);
        assert!(identity.attestation.is_some());
    }

    // --- NodeId: Display vs Debug are different ---

    #[test]
    fn test_node_id_display_vs_debug() {
        let id = NodeId::new("compare");
        let display = format!("{id}");
        let debug = format!("{id:?}");
        assert_eq!(display, "compare");
        assert!(debug.contains("NodeId"));
        assert_ne!(display, debug);
    }

    // --- MeshIdentity: verify attestation with expired zero-validity attestation ---

    #[test]
    fn test_mesh_identity_verify_expired_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("expired");
        let tags = vec![];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 0).unwrap();

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        assert!(!identity.is_attestation_valid());
        let err = identity.verify_attestation().unwrap_err();
        assert!(matches!(err, TailscaleError::AttestationExpired));
    }

    // --- Attestation: remaining_validity for zero-validity is negative ---

    #[test]
    fn test_attestation_zero_validity_remaining_negative() {
        let (owner_key, node_keys) = create_test_keys();
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &NodeId::new("neg"), &node_keys, &[], 0).unwrap();
        let remaining = attestation.remaining_validity();
        assert!(remaining.num_seconds() <= 0);
    }

    // --- Attestation: serde roundtrip preserves signature ---

    #[test]
    fn test_attestation_serde_preserves_signature() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("sig-preserve");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let json = serde_json::to_string(&attestation).unwrap();
        let decoded: NodeKeyAttestation = serde_json::from_str(&json).unwrap();

        // The decoded attestation should still verify
        decoded
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- MeshIdentity: serde roundtrip with attestation still verifies ---

    #[test]
    fn test_mesh_identity_serde_roundtrip_attestation_verifies() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("serde-verify");
        let tags = vec![TailscaleTag::fcp_tag("owner")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec!["100.64.0.1".parse().unwrap()],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let json = serde_json::to_string(&identity).unwrap();
        let decoded: MeshIdentity = serde_json::from_str(&json).unwrap();

        // Decoded identity should still verify
        decoded.verify_attestation().unwrap();
        assert!(decoded.is_attestation_valid());
    }

    // --- NodeId: from different Into<String> types ---

    #[test]
    fn test_node_id_from_static_str() {
        let id = NodeId::new("static");
        assert_eq!(id.as_str(), "static");
    }

    #[test]
    fn test_node_id_from_cow_string() {
        let s = std::borrow::Cow::from("cow-id");
        let id = NodeId::new(s);
        assert_eq!(id.as_str(), "cow-id");
    }

    // --- MeshIdentity: single IPv4 address ---

    #[test]
    fn test_mesh_identity_single_ipv4() {
        let (owner_key, node_keys) = create_test_keys();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let identity = MeshIdentity::new(
            NodeId::new("v4-only"),
            "host".to_string(),
            vec![ip],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        assert_eq!(identity.ips.len(), 1);
        assert!(identity.ips[0].is_ipv4());
    }

    // --- NodeId: serde deserialization from invalid JSON ---

    #[test]
    fn test_node_id_deserialize_from_number_fails() {
        let result: Result<NodeId, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn test_node_id_deserialize_from_null_fails() {
        let result: Result<NodeId, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    #[test]
    fn test_node_id_deserialize_from_array_fails() {
        let result: Result<NodeId, _> = serde_json::from_str("[1,2]");
        assert!(result.is_err());
    }

    // --- NodeId: Display with empty string produces empty output ---

    #[test]
    fn test_node_id_display_empty_is_empty() {
        let id = NodeId::new("");
        assert_eq!(format!("{id}"), "");
    }

    // --- NodeKeys: const constructor produces consistent results ---

    #[test]
    fn test_node_keys_const_new() {
        let signing = Ed25519SigningKey::generate();
        let encryption = X25519SecretKey::generate();
        let issuance = Ed25519SigningKey::generate();

        let keys = NodeKeys::new(
            signing.verifying_key(),
            encryption.public_key(),
            issuance.verifying_key(),
        );
        // Key IDs should be non-zero length hex strings
        assert!(!keys.signing_kid().to_hex().is_empty());
        assert!(!keys.encryption_kid().to_hex().is_empty());
        assert!(!keys.issuance_kid().to_hex().is_empty());
    }

    // --- MeshIdentity: fcp_tags with only fcp- prefix tag ---

    #[test]
    fn test_mesh_identity_fcp_tags_with_bare_fcp_prefix() {
        // `fcp_tags()` requires a valid attestation post-8a0d49596.
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("bare-fcp");
        let tags = vec![TailscaleTag::new("tag:fcp-").unwrap()];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        // "tag:fcp-" is technically an FCP tag (starts with tag:fcp-)
        assert_eq!(identity.fcp_tags().len(), 1);
    }

    // --- Attestation: sign with unicode node_id ---

    #[test]
    fn test_attestation_sign_verify_unicode_node_id() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("n\u{00f6}de-\u{1F600}");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- Attestation: sign with non-fcp and fcp tags mixed ---

    #[test]
    fn test_attestation_sign_verify_mixed_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("mixed");
        let tags = vec![
            TailscaleTag::fcp_tag("work"),
            TailscaleTag::new("tag:server").unwrap(),
            TailscaleTag::fcp_tag("private"),
            TailscaleTag::new("tag:web").unwrap(),
        ];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap();
    }

    // --- MeshIdentity: Clone preserves attestation ---

    #[test]
    fn test_mesh_identity_clone_preserves_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("clone-attest");
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let cloned = identity.clone();
        assert!(cloned.attestation.is_some());
        assert!(cloned.is_attestation_valid());
        cloned.verify_attestation().unwrap();
        // Use original after clone to avoid redundant_clone
        assert!(identity.is_attestation_valid());
    }

    // --- MeshIdentity: serde JSON includes all expected top-level keys ---

    #[test]
    fn test_mesh_identity_json_has_attestation_key() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("json-keys"),
            "host".to_string(),
            vec![],
            vec![],
            owner_key.verifying_key(),
            node_keys,
        );
        let json = serde_json::to_string(&identity).unwrap();
        assert!(json.contains("\"attestation\""));
    }

    // --- NodeId: HashSet operations ---

    #[test]
    fn test_node_id_hashset_contains() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(NodeId::new("alpha"));
        set.insert(NodeId::new("beta"));
        assert!(set.contains(&NodeId::new("alpha")));
        assert!(set.contains(&NodeId::new("beta")));
        assert!(!set.contains(&NodeId::new("gamma")));
    }

    // --- Attestation: schema constant ---

    #[test]
    fn test_attestation_payload_schema() {
        assert_eq!(AttestationPayload::SCHEMA, "fcp.attestation.v1");
    }

    // --- MeshIdentity: verify_attestation with wrong tags in identity ---

    #[test]
    fn test_mesh_identity_verify_attestation_mismatched_tags() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("mismatch-tags");
        let original_tags = vec![TailscaleTag::fcp_tag("work")];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &original_tags, 24).unwrap();

        // Create identity with DIFFERENT tags than what was signed
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            vec![TailscaleTag::fcp_tag("private")], // different!
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        // verify_attestation should fail because tags don't match
        assert!(identity.verify_attestation().is_err());
        assert!(
            identity.fcp_tags().is_empty(),
            "convenience tag accessor must fail closed when attestation tag binding is invalid"
        );
    }

    #[test]
    fn test_mesh_identity_fcp_tags_rejects_wrong_owner_attestation() {
        let (owner_key, node_keys) = create_test_keys();
        let wrong_owner_key = Ed25519SigningKey::generate();
        let node_id = NodeId::new("wrong-owner-tags");
        let tags = vec![TailscaleTag::fcp_tag("owner")];

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            vec![],
            tags,
            wrong_owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        assert!(identity.is_attestation_valid());
        assert!(identity.verify_attestation().is_err());
        assert!(
            identity.fcp_tags().is_empty(),
            "fresh but unverified attestation must not surface FCP zone tags"
        );
        assert!(identity.verified_fcp_tags().is_err());
    }

    // --- NodeKeys: serde roundtrip with clone ---

    #[test]
    fn test_node_keys_serde_roundtrip_clone() {
        let (_, keys) = create_test_keys();
        let cloned = keys.clone();
        let json1 = serde_json::to_string(&keys).unwrap();
        let json2 = serde_json::to_string(&cloned).unwrap();
        assert_eq!(json1, json2);
    }

    // --- MeshIdentity: Debug output contains all field names ---

    #[test]
    fn test_mesh_identity_debug_all_fields() {
        let (owner_key, node_keys) = create_test_keys();
        let identity = MeshIdentity::new(
            NodeId::new("dbg-all"),
            "test-host".to_string(),
            vec!["100.64.0.1".parse().unwrap()],
            vec![TailscaleTag::fcp_tag("work")],
            owner_key.verifying_key(),
            node_keys,
        );
        let dbg = format!("{identity:?}");
        assert!(dbg.contains("node_id"));
        assert!(dbg.contains("hostname"));
        assert!(dbg.contains("ips"));
        assert!(dbg.contains("tags"));
        assert!(dbg.contains("owner_pubkey"));
        assert!(dbg.contains("node_keys"));
        assert!(dbg.contains("attestation"));
    }

    // --- Attestation: issued_at is before expires_at ---

    #[test]
    fn test_attestation_issued_before_expires() {
        let (owner_key, node_keys) = create_test_keys();
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &NodeId::new("time"), &node_keys, &[], 24)
                .unwrap();
        assert!(attestation.issued_at < attestation.expires_at);
    }

    // --- Attestation: signer_kid is deterministic for same key ---

    #[test]
    fn test_attestation_signer_kid_deterministic() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("det");
        let a1 = NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &[], 1).unwrap();
        let a2 = NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &[], 48).unwrap();
        assert_eq!(a1.signer_kid, a2.signer_kid);
    }

    // --- MeshIdentity: many tags serde roundtrip ---

    #[test]
    fn test_mesh_identity_many_tags_serde_roundtrip() {
        let (owner_key, node_keys) = create_test_keys();
        let tags: Vec<TailscaleTag> = (0..15)
            .map(|i| TailscaleTag::fcp_tag(&format!("z{i}")))
            .collect();
        let identity = MeshIdentity::new(
            NodeId::new("many-tags-serde"),
            "host".to_string(),
            vec![],
            tags.clone(),
            owner_key.verifying_key(),
            node_keys,
        );
        let json = serde_json::to_string(&identity).unwrap();
        let decoded: MeshIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tags.len(), 15);
        assert_eq!(decoded.tags, tags);
    }

    // --- Attestation: verify returns AttestationExpired for zero-validity ---

    #[test]
    fn test_attestation_verify_zero_returns_expired() {
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("zero-exp");
        let tags = vec![];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 0).unwrap();
        let err = attestation
            .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap_err();
        assert!(matches!(err, TailscaleError::AttestationExpired));
    }

    // --- Attestation: verify returns InvalidAttestation for wrong signer_kid ---

    #[test]
    fn test_attestation_verify_wrong_owner_returns_invalid() {
        let (owner_key, node_keys) = create_test_keys();
        let wrong_owner = Ed25519SigningKey::generate();
        let node_id = NodeId::new("wrong-owner");
        let tags = vec![];
        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).unwrap();
        let err = attestation
            .verify(&wrong_owner.verifying_key(), &node_id, &node_keys, &tags)
            .unwrap_err();
        assert!(matches!(err, TailscaleError::InvalidAttestation));
    }
}
