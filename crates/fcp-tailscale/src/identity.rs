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
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::error::{TailscaleError, TailscaleResult};
use crate::tag::TailscaleTag;

/// Tailscale node ID (opaque string identifier).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Create a new `NodeId` from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the node ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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
            .ok_or_else(|| TailscaleError::InvalidAttestation)?;

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
    #[must_use]
    pub fn fcp_tags(&self) -> Vec<&TailscaleTag> {
        self.tags.iter().filter(|t| t.is_fcp_tag()).collect()
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
        let expires_at = now + chrono::Duration::hours(i64::from(validity_hours));

        let payload = AttestationPayload {
            schema: AttestationPayload::SCHEMA,
            node_id: node_id.as_str(),
            signing_kid: node_keys.signing_kid().to_hex(),
            encryption_kid: node_keys.encryption_kid().to_hex(),
            issuance_kid: node_keys.issuance_kid().to_hex(),
            tags: tags.iter().map(TailscaleTag::as_str).collect(),
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
            tags: tags.iter().map(TailscaleTag::as_str).collect(),
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
        let (owner_key, node_keys) = create_test_keys();
        let node_id = NodeId::new("test-node");

        // Mix of FCP and non-FCP tags
        let tags = vec![
            TailscaleTag::new("tag:fcp-work").unwrap(),
            TailscaleTag::new("tag:server").unwrap(),
            TailscaleTag::new("tag:fcp-private").unwrap(),
        ];

        let identity = MeshIdentity::new(
            node_id,
            "test-host".to_string(),
            vec![],
            tags,
            owner_key.verifying_key(),
            node_keys,
        );

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
}
