//! Zone key distribution and rotation primitives.
//!
//! Implements `ZoneKeyManifest` objects and HPKE-wrapped zone keys.

use std::collections::HashMap;
use std::fmt;

use fcp_crypto::{
    CryptoError, Fcp2Aad, HpkeSealedBox, X25519PublicKey, X25519SecretKey, hpke_open, hpke_seal,
};
use serde::{Deserialize, Serialize};

use crate::{NodeSignature, ObjectHeader, ObjectIdKey, TailscaleNodeId, ZoneId};

/// Zone key length in bytes (ChaCha20-Poly1305 / XChaCha20-Poly1305).
pub const ZONE_KEY_LEN: usize = 32;

/// Zone key identifier (8 bytes as carried in FCPS frames).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ZoneKeyId(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 8]);

impl ZoneKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ZoneKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneKeyId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ZoneKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// `ObjectId` key identifier (8 bytes as carried in FCPS frames).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectIdKeyId(#[serde(with = "crate::util::hex_or_bytes")] pub [u8; 8]);

impl ObjectIdKeyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Debug for ObjectIdKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjectIdKeyId")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ObjectIdKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Symmetric zone encryption key (secret).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneKey([u8; ZONE_KEY_LEN]);

impl ZoneKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ZONE_KEY_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ZONE_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneKey")
            .field(&"[redacted; 32 bytes]")
            .finish()
    }
}

/// Supported zone key algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKeyAlgorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

/// Wrapped zone key entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedZoneKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

/// Wrapped `ObjectIdKey` entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedObjectIdKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

/// Rekey policy hints for zone membership changes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RekeyPolicy {
    #[serde(default)]
    pub epoch_ratchet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retain_epochs: Option<u32>,
    #[serde(default)]
    pub rewrap_on_membership_change: bool,
    #[serde(default)]
    pub rotate_object_id_key_on_membership_change: bool,
}

/// Zone key manifest object (owner-signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneKeyManifest {
    pub header: ObjectHeader,
    pub zone_id: ZoneId,
    pub zone_key_id: ZoneKeyId,
    pub object_id_key_id: ObjectIdKeyId,
    pub algorithm: ZoneKeyAlgorithm,
    pub valid_from: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_zone_key_id: Option<ZoneKeyId>,
    #[serde(default)]
    pub wrapped_keys: Vec<WrappedZoneKey>,
    #[serde(default)]
    pub wrapped_object_id_keys: Vec<WrappedObjectIdKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_policy: Option<RekeyPolicy>,
    pub signature: NodeSignature,
}

impl ZoneKeyManifest {
    /// Find the wrapped zone key for a recipient node.
    #[must_use]
    pub fn wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKey> {
        self.wrapped_keys
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Find the wrapped `ObjectIdKey` for a recipient node.
    #[must_use]
    pub fn wrapped_object_id_key_for(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Option<&WrappedObjectIdKey> {
        self.wrapped_object_id_keys
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Create a new empty manifest (for testing).
    ///
    /// # Errors
    ///
    /// This function is infallible but returns `Result` for API consistency.
    #[cfg(test)]
    pub fn new_empty(
        zone_id: ZoneId,
        valid_from: u64,
        _owner_key: &fcp_crypto::Ed25519SigningKey,
    ) -> Result<Self, crate::error::FcpError> {
        use rand::RngCore;

        let mut zone_key_id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut zone_key_id);

        let mut object_id_key_id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut object_id_key_id);

        // We need to sign a dummy payload or just return a valid signed structure?
        // The structure needs to be signed.
        // We can't easily sign `Self` because `signature` is a field.
        // We need a canonical representation without signature.
        // Ideally we follow `ZoneKeyManifest::sign` pattern if it existed.
        // But for testing we can just sign an empty byte slice if verify isn't strict about payload match
        // OR we duplicate the signing logic here.
        // But `ZoneKeyManifest` doesn't seem to have a canonical serialization method exposed?
        // Wait, `apply_manifest` doesn't verify signature. `NodeKeyAttestation` does.
        // `ZoneKeyManifest` struct definition doesn't have a `verify` method shown in my previous `read_file`.
        // Let's verify `ZoneKeyManifest` struct again.

        // It has `signature: NodeSignature`.
        // So we can just create a dummy signature.

        let signature =
            crate::NodeSignature::new(crate::NodeId::new("owner"), [0u8; 64], valid_from);

        Ok(Self {
            header: ObjectHeader {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.zone",
                    "ZoneKeyManifest",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: zone_id.clone(),
                created_at: valid_from,
                provenance: crate::Provenance::new(zone_id.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            zone_id,
            zone_key_id: ZoneKeyId(zone_key_id),
            object_id_key_id: ObjectIdKeyId(object_id_key_id),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature,
        })
    }
}

/// Zone key ring storing active/known keys by id.
#[derive(Debug, Clone)]
pub struct ZoneKeyRing {
    pub zone_id: ZoneId,
    zone_keys: HashMap<ZoneKeyId, ZoneKey>,
    object_id_keys: HashMap<ObjectIdKeyId, ObjectIdKey>,
    pub active_zone_key_id: Option<ZoneKeyId>,
    pub active_object_id_key_id: Option<ObjectIdKeyId>,
}

impl ZoneKeyRing {
    #[must_use]
    pub fn new(zone_id: ZoneId) -> Self {
        Self {
            zone_id,
            zone_keys: HashMap::new(),
            object_id_keys: HashMap::new(),
            active_zone_key_id: None,
            active_object_id_key_id: None,
        }
    }

    pub fn insert_zone_key(&mut self, key_id: ZoneKeyId, key: ZoneKey) {
        self.zone_keys.insert(key_id, key);
    }

    pub fn insert_object_id_key(&mut self, key_id: ObjectIdKeyId, key: ObjectIdKey) {
        self.object_id_keys.insert(key_id, key);
    }

    #[must_use]
    pub fn zone_key(&self, key_id: &ZoneKeyId) -> Option<&ZoneKey> {
        self.zone_keys.get(key_id)
    }

    #[must_use]
    pub fn object_id_key(&self, key_id: &ObjectIdKeyId) -> Option<&ObjectIdKey> {
        self.object_id_keys.get(key_id)
    }

    #[must_use]
    pub fn active_zone_key(&self) -> Option<&ZoneKey> {
        self.active_zone_key_id
            .as_ref()
            .and_then(|key_id| self.zone_keys.get(key_id))
    }

    #[must_use]
    pub fn active_object_id_key(&self) -> Option<&ObjectIdKey> {
        self.active_object_id_key_id
            .as_ref()
            .and_then(|key_id| self.object_id_keys.get(key_id))
    }

    #[must_use]
    pub fn set_active_zone_key(&mut self, key_id: ZoneKeyId) -> bool {
        if self.zone_keys.contains_key(&key_id) {
            self.active_zone_key_id = Some(key_id);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn set_active_object_id_key(&mut self, key_id: ObjectIdKeyId) -> bool {
        if self.object_id_keys.contains_key(&key_id) {
            self.active_object_id_key_id = Some(key_id);
            true
        } else {
            false
        }
    }

    /// Apply a zone key manifest for the local node and update active keys.
    ///
    /// # Errors
    /// Returns `ZoneKeyError` if the manifest is for a different zone or
    /// required wrapped keys are missing/invalid.
    pub fn apply_manifest(
        &mut self,
        manifest: &ZoneKeyManifest,
        node_id: &TailscaleNodeId,
        node_secret: &X25519SecretKey,
    ) -> ZoneKeyResult<()> {
        if manifest.zone_id != self.zone_id {
            return Err(ZoneKeyError::ZoneIdMismatch {
                expected: self.zone_id.as_str().to_string(),
                found: manifest.zone_id.as_str().to_string(),
            });
        }

        let wrapped_zone = manifest.wrapped_key_for(node_id).ok_or_else(|| {
            ZoneKeyError::MissingWrappedZoneKey {
                node_id: node_id.as_str().to_string(),
            }
        })?;
        let zone_key = unwrap_zone_key(node_secret, &manifest.zone_id, wrapped_zone)?;
        self.insert_zone_key(manifest.zone_key_id, zone_key);
        self.active_zone_key_id = Some(manifest.zone_key_id);

        let wrapped_object_id = manifest.wrapped_object_id_key_for(node_id).ok_or_else(|| {
            ZoneKeyError::MissingWrappedObjectIdKey {
                node_id: node_id.as_str().to_string(),
            }
        })?;
        let object_id_key =
            unwrap_object_id_key(node_secret, &manifest.zone_id, wrapped_object_id)?;
        self.insert_object_id_key(manifest.object_id_key_id, object_id_key);
        self.active_object_id_key_id = Some(manifest.object_id_key_id);

        Ok(())
    }
}

/// Zone key distribution errors.
#[derive(Debug, thiserror::Error)]
pub enum ZoneKeyError {
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid key length (expected {expected}, got {found})")]
    InvalidKeyLength { expected: usize, found: usize },
    #[error("zone id mismatch (expected {expected}, found {found})")]
    ZoneIdMismatch { expected: String, found: String },
    #[error("missing wrapped zone key for node `{node_id}`")]
    MissingWrappedZoneKey { node_id: String },
    #[error("missing wrapped ObjectIdKey for node `{node_id}`")]
    MissingWrappedObjectIdKey { node_id: String },
}

pub type ZoneKeyResult<T> = Result<T, ZoneKeyError>;

/// Wrap a zone key for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE sealing fails.
pub fn wrap_zone_key(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    zone_key: &ZoneKey,
) -> ZoneKeyResult<WrappedZoneKey> {
    let aad = Fcp2Aad::for_zone_key(
        zone_id.as_bytes(),
        recipient_node_id.as_str().as_bytes(),
        issued_at,
    );
    let sealed = hpke_seal(recipient_pk, zone_key.as_bytes(), &aad)?;
    Ok(WrappedZoneKey {
        recipient: recipient_node_id.clone(),
        issued_at,
        sealed,
    })
}

/// Unwrap a zone key for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE opening fails or key length is invalid.
pub fn unwrap_zone_key(
    recipient_sk: &X25519SecretKey,
    zone_id: &ZoneId,
    wrapped: &WrappedZoneKey,
) -> ZoneKeyResult<ZoneKey> {
    let aad = Fcp2Aad::for_zone_key(
        zone_id.as_bytes(),
        wrapped.recipient.as_str().as_bytes(),
        wrapped.issued_at,
    );
    let opened = hpke_open(recipient_sk, &wrapped.sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ZoneKey::from_bytes(bytes))
}

/// Wrap an `ObjectIdKey` for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE sealing fails.
pub fn wrap_object_id_key(
    recipient_pk: &X25519PublicKey,
    zone_id: &ZoneId,
    recipient_node_id: &TailscaleNodeId,
    issued_at: u64,
    object_id_key: &ObjectIdKey,
) -> ZoneKeyResult<WrappedObjectIdKey> {
    let aad = Fcp2Aad::for_objectid_key(
        zone_id.as_bytes(),
        recipient_node_id.as_str().as_bytes(),
        issued_at,
    );
    let sealed = hpke_seal(recipient_pk, object_id_key.as_bytes(), &aad)?;
    Ok(WrappedObjectIdKey {
        recipient: recipient_node_id.clone(),
        issued_at,
        sealed,
    })
}

/// Unwrap an `ObjectIdKey` for a recipient using HPKE.
///
/// # Errors
/// Returns `ZoneKeyError` if HPKE opening fails or key length is invalid.
pub fn unwrap_object_id_key(
    recipient_sk: &X25519SecretKey,
    zone_id: &ZoneId,
    wrapped: &WrappedObjectIdKey,
) -> ZoneKeyResult<ObjectIdKey> {
    let aad = Fcp2Aad::for_objectid_key(
        zone_id.as_bytes(),
        wrapped.recipient.as_str().as_bytes(),
        wrapped.issued_at,
    );
    let opened = hpke_open(recipient_sk, &wrapped.sealed, &aad)?;
    if opened.len() != ZONE_KEY_LEN {
        return Err(ZoneKeyError::InvalidKeyLength {
            expected: ZONE_KEY_LEN,
            found: opened.len(),
        });
    }
    let mut bytes = [0u8; ZONE_KEY_LEN];
    bytes.copy_from_slice(&opened);
    Ok(ObjectIdKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, NodeSignature, ObjectHeader, Provenance};
    use fcp_cbor::SchemaId;
    use fcp_crypto::x25519::X25519SecretKey;
    use rand::RngCore;
    use semver::Version;

    fn random_zone_key() -> ZoneKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        ZoneKey::from_bytes(bytes)
    }

    fn random_object_id_key() -> ObjectIdKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        ObjectIdKey::from_bytes(bytes)
    }

    fn test_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.zone", "ZoneKeyManifest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_signature() -> NodeSignature {
        NodeSignature::new(NodeId::new("owner-node"), [0u8; 64], 1_700_000_000)
    }

    #[test]
    fn zone_key_wrap_roundtrip() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-1");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let opened = unwrap_zone_key(&sk, &zone_id, &wrapped).unwrap();

        assert_eq!(opened, zone_key);
    }

    #[test]
    fn object_id_key_wrap_roundtrip() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-2");
        let issued_at = 1_700_000_123;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let opened = unwrap_object_id_key(&sk, &zone_id, &wrapped).unwrap();

        assert_eq!(opened, key);
    }

    #[test]
    fn unwrap_zone_key_fails_with_wrong_node_id() {
        let zone_id = ZoneId::community();
        let node_id = TailscaleNodeId::new("node-3");
        let issued_at = 1_700_000_456;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let mut wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        wrapped.recipient = TailscaleNodeId::new("node-4");

        let result = unwrap_zone_key(&sk, &zone_id, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn zone_key_ring_selects_by_id() {
        let zone_id = ZoneId::public();
        let mut ring = ZoneKeyRing::new(zone_id);

        let key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let key = ZoneKey::from_bytes([2u8; ZONE_KEY_LEN]);
        ring.insert_zone_key(key_id, key);

        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    #[test]
    fn apply_manifest_unwraps_and_sets_active() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-apply");
        let issued_at = 1_700_000_777;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([9u8; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([7u8; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key_id, Some(manifest.zone_key_id));
        assert_eq!(
            ring.active_object_id_key_id,
            Some(manifest.object_id_key_id)
        );
        assert_eq!(ring.active_zone_key(), Some(&zone_key));
        assert_eq!(ring.active_object_id_key(), Some(&object_id_key));
    }

    #[test]
    fn apply_manifest_rejects_mismatched_zone() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-apply");
        let issued_at = 1_700_000_888;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([3u8; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([4u8; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(ZoneId::private());
        let err = ring
            .apply_manifest(&manifest, &node_id, &sk)
            .expect_err("zone mismatch");
        assert!(matches!(err, ZoneKeyError::ZoneIdMismatch { .. }));
    }

    /// Test key rotation: applying a new manifest rotates the active key while
    /// keeping the old key accessible by its ID (deterministic selection).
    #[test]
    fn rotation_deterministic_key_selection_by_zone_key_id() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-rotation");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === First manifest (epoch 1) ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let object_id_key_id_1 =
            ObjectIdKeyId::from_bytes([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();

        // Verify initial state
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));

        // === Second manifest (epoch 2) - rotation ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]);
        let object_id_key_id_2 =
            ObjectIdKeyId::from_bytes([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]);

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1), // Links to previous key
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: Some(RekeyPolicy {
                overlap_window_secs: Some(600),
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();

        // Verify rotation occurred
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_2));

        // CRITICAL: Both keys must be accessible by their IDs (deterministic selection)
        // This enables decryption of symbols encrypted under either epoch without trial decrypt.
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );

        // Verify we can switch active key back to epoch 1 (for decryption overlap window)
        assert!(ring.set_active_zone_key(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));
    }

    /// Test membership change: a removed node cannot decrypt newly wrapped keys
    /// because they are not included in the `wrapped_keys` list.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn membership_change_removed_node_cannot_decrypt() {
        let zone_id = ZoneId::work();

        // Three nodes initially in the zone
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        let node_3_id = TailscaleNodeId::new("node-3"); // Will be removed

        let sk_1 = X25519SecretKey::generate();
        let pk_1 = sk_1.public_key();
        let sk_2 = X25519SecretKey::generate();
        let pk_2 = sk_2.public_key();
        let sk_3 = X25519SecretKey::generate();
        let pk_3 = sk_3.public_key();

        // === Initial manifest with all 3 nodes ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_3 =
            wrap_zone_key(&pk_3, &zone_id, &node_3_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_obj_1_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_3 =
            wrap_object_id_key(&pk_3, &zone_id, &node_3_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![
                wrapped_zone_1_for_1,
                wrapped_zone_1_for_2,
                wrapped_zone_1_for_3,
            ],
            wrapped_object_id_keys: vec![
                wrapped_obj_1_for_1,
                wrapped_obj_1_for_2,
                wrapped_obj_1_for_3,
            ],
            rekey_policy: None,
            signature: test_signature(),
        };

        // All 3 nodes can apply the initial manifest
        let mut ring_1 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_2 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_3 = ZoneKeyRing::new(zone_id.clone());

        ring_1
            .apply_manifest(&manifest_1, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_1, &node_2_id, &sk_2)
            .unwrap();
        ring_3
            .apply_manifest(&manifest_1, &node_3_id, &sk_3)
            .unwrap();

        // === Second manifest: node-3 is removed from membership ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x31; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x41; 8]);

        // Only wrap keys for nodes 1 and 2 (node 3 is excluded)
        let wrapped_zone_2_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_obj_2_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![wrapped_zone_2_for_1, wrapped_zone_2_for_2],
            wrapped_object_id_keys: vec![wrapped_obj_2_for_1, wrapped_obj_2_for_2],
            rekey_policy: Some(RekeyPolicy {
                rewrap_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        // Nodes 1 and 2 can apply the new manifest
        ring_1
            .apply_manifest(&manifest_2, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_2, &node_2_id, &sk_2)
            .unwrap();

        // CRITICAL: Node 3 CANNOT apply the new manifest (no wrapped key for them)
        let err = ring_3
            .apply_manifest(&manifest_2, &node_3_id, &sk_3)
            .expect_err("removed node should fail");
        assert!(
            matches!(err, ZoneKeyError::MissingWrappedZoneKey { .. }),
            "expected MissingWrappedZoneKey error, got {err:?}"
        );

        // Verify nodes 1 and 2 have the new key
        assert_eq!(ring_1.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_2.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_1.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_2.active_zone_key(), Some(&zone_key_2));

        // Node 3 still has only the old key
        assert_eq!(ring_3.active_zone_key_id, Some(zone_key_id_1));
        assert_eq!(ring_3.active_zone_key(), Some(&zone_key_1));
        assert!(ring_3.zone_key(&zone_key_id_2).is_none());
    }

    /// Test that `ObjectIdKey` rotation can happen independently or alongside `ZoneKey` rotation.
    #[test]
    fn rotation_with_object_id_key_change() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-objid-rotation");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === First manifest ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();

        // === Second manifest with BOTH ZoneKey AND ObjectIdKey rotation ===
        // (Used when rotate_object_id_key_on_membership_change policy is set)
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x41; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x51; 8]); // Also rotated!

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: Some(RekeyPolicy {
                rotate_object_id_key_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();

        // Verify both keys rotated
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring.active_object_id_key_id, Some(object_id_key_id_2));

        // Both old and new keys accessible (no trial decrypt needed)
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );
    }

    /// Test chain of three rotations (key1 → key2 → key3) verifying `prev_zone_key_id` linkage.
    /// This ensures the full rotation history is preserved and all keys remain accessible.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn rotation_chain_three_epochs() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-chain");

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        // === Epoch 1: Initial key ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_object_1 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None, // No previous key
            wrapped_keys: vec![wrapped_zone_1],
            wrapped_object_id_keys: vec![wrapped_object_1],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id.clone());
        ring.apply_manifest(&manifest_1, &node_id, &sk).unwrap();
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_1));

        // === Epoch 2: First rotation (links to epoch 1) ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x02; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x12; 8]);

        let wrapped_zone_2 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_object_2 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1), // Links to epoch 1
            wrapped_keys: vec![wrapped_zone_2],
            wrapped_object_id_keys: vec![wrapped_object_2],
            rekey_policy: None,
            signature: test_signature(),
        };

        ring.apply_manifest(&manifest_2, &node_id, &sk).unwrap();
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_2));

        // === Epoch 3: Second rotation (links to epoch 2) ===
        let issued_at_3 = 1_700_200_000;
        let zone_key_3 = random_zone_key();
        let object_id_key_3 = random_object_id_key();
        let zone_key_id_3 = ZoneKeyId::from_bytes([0x03; 8]);
        let object_id_key_id_3 = ObjectIdKeyId::from_bytes([0x13; 8]);

        let wrapped_zone_3 =
            wrap_zone_key(&pk, &zone_id, &node_id, issued_at_3, &zone_key_3).unwrap();
        let wrapped_object_3 =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at_3, &object_id_key_3).unwrap();

        let manifest_3 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_3,
            object_id_key_id: object_id_key_id_3,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_3,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_2), // Links to epoch 2
            wrapped_keys: vec![wrapped_zone_3],
            wrapped_object_id_keys: vec![wrapped_object_3],
            rekey_policy: Some(RekeyPolicy {
                epoch_ratchet: true,
                retain_epochs: Some(3), // Keep all 3 epochs
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        ring.apply_manifest(&manifest_3, &node_id, &sk).unwrap();

        // Verify final state
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id_3));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_3));

        // CRITICAL: All three keys must be accessible (deterministic key selection)
        assert_eq!(ring.zone_key(&zone_key_id_1), Some(&zone_key_1));
        assert_eq!(ring.zone_key(&zone_key_id_2), Some(&zone_key_2));
        assert_eq!(ring.zone_key(&zone_key_id_3), Some(&zone_key_3));

        // All ObjectId keys also accessible
        assert_eq!(
            ring.object_id_key(&object_id_key_id_1),
            Some(&object_id_key_1)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_2),
            Some(&object_id_key_2)
        );
        assert_eq!(
            ring.object_id_key(&object_id_key_id_3),
            Some(&object_id_key_3)
        );

        // Verify we can decrypt data from any epoch by switching active key
        assert!(ring.set_active_zone_key(zone_key_id_1));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_1));
        assert!(ring.set_active_zone_key(zone_key_id_2));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_2));
        assert!(ring.set_active_zone_key(zone_key_id_3));
        assert_eq!(ring.active_zone_key(), Some(&zone_key_3));
    }

    /// Test that applying the same manifest twice is idempotent.
    /// This verifies manifest replay doesn't corrupt state.
    #[test]
    fn manifest_replay_is_idempotent() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-replay");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();
        let zone_key_id = ZoneKeyId::from_bytes([0xAA; 8]);
        let object_id_key_id = ObjectIdKeyId::from_bytes([0xBB; 8]);

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id,
            object_id_key_id,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id);

        // Apply manifest first time
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();
        let state_after_first = (
            ring.active_zone_key_id,
            ring.active_zone_key().copied(),
            ring.active_object_id_key_id,
        );

        // Apply manifest second time (replay)
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();
        let state_after_second = (
            ring.active_zone_key_id,
            ring.active_zone_key().copied(),
            ring.active_object_id_key_id,
        );

        // State should be identical after replay
        assert_eq!(state_after_first, state_after_second);
        assert_eq!(ring.zone_key(&zone_key_id), Some(&zone_key));
    }

    /// Test node addition to zone membership (new node can receive keys).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn membership_change_node_addition() {
        let zone_id = ZoneId::work();

        // Two nodes initially in the zone
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        // New node to be added
        let node_3_id = TailscaleNodeId::new("node-3-new");

        let sk_1 = X25519SecretKey::generate();
        let pk_1 = sk_1.public_key();
        let sk_2 = X25519SecretKey::generate();
        let pk_2 = sk_2.public_key();
        let sk_3 = X25519SecretKey::generate();
        let pk_3 = sk_3.public_key();

        // === Initial manifest with 2 nodes ===
        let issued_at_1 = 1_700_000_000;
        let zone_key_1 = random_zone_key();
        let object_id_key_1 = random_object_id_key();
        let zone_key_id_1 = ZoneKeyId::from_bytes([0x01; 8]);
        let object_id_key_id_1 = ObjectIdKeyId::from_bytes([0x11; 8]);

        let wrapped_zone_1_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_zone_1_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &zone_key_1).unwrap();
        let wrapped_obj_1_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_1, &object_id_key_1).unwrap();
        let wrapped_obj_1_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_1, &object_id_key_1).unwrap();

        let manifest_1 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_1,
            object_id_key_id: object_id_key_id_1,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_1,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone_1_for_1, wrapped_zone_1_for_2],
            wrapped_object_id_keys: vec![wrapped_obj_1_for_1, wrapped_obj_1_for_2],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring_1 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_2 = ZoneKeyRing::new(zone_id.clone());
        let mut ring_3 = ZoneKeyRing::new(zone_id.clone());

        ring_1
            .apply_manifest(&manifest_1, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_1, &node_2_id, &sk_2)
            .unwrap();

        // Node 3 cannot apply initial manifest (not a member yet)
        let err = ring_3
            .apply_manifest(&manifest_1, &node_3_id, &sk_3)
            .expect_err("new node should not be in initial manifest");
        assert!(matches!(err, ZoneKeyError::MissingWrappedZoneKey { .. }));

        // === Second manifest: node-3 is added ===
        let issued_at_2 = 1_700_100_000;
        let zone_key_2 = random_zone_key();
        let object_id_key_2 = random_object_id_key();
        let zone_key_id_2 = ZoneKeyId::from_bytes([0x02; 8]);
        let object_id_key_id_2 = ObjectIdKeyId::from_bytes([0x12; 8]);

        // Wrap keys for all 3 nodes
        let wrapped_zone_2_for_1 =
            wrap_zone_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_2 =
            wrap_zone_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_zone_2_for_3 =
            wrap_zone_key(&pk_3, &zone_id, &node_3_id, issued_at_2, &zone_key_2).unwrap();
        let wrapped_obj_2_for_1 =
            wrap_object_id_key(&pk_1, &zone_id, &node_1_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_2 =
            wrap_object_id_key(&pk_2, &zone_id, &node_2_id, issued_at_2, &object_id_key_2).unwrap();
        let wrapped_obj_2_for_3 =
            wrap_object_id_key(&pk_3, &zone_id, &node_3_id, issued_at_2, &object_id_key_2).unwrap();

        let manifest_2 = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: zone_key_id_2,
            object_id_key_id: object_id_key_id_2,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_2,
            valid_until: None,
            prev_zone_key_id: Some(zone_key_id_1),
            wrapped_keys: vec![
                wrapped_zone_2_for_1,
                wrapped_zone_2_for_2,
                wrapped_zone_2_for_3,
            ],
            wrapped_object_id_keys: vec![
                wrapped_obj_2_for_1,
                wrapped_obj_2_for_2,
                wrapped_obj_2_for_3,
            ],
            rekey_policy: Some(RekeyPolicy {
                rewrap_on_membership_change: true,
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        // All 3 nodes can apply the new manifest
        ring_1
            .apply_manifest(&manifest_2, &node_1_id, &sk_1)
            .unwrap();
        ring_2
            .apply_manifest(&manifest_2, &node_2_id, &sk_2)
            .unwrap();
        ring_3
            .apply_manifest(&manifest_2, &node_3_id, &sk_3)
            .unwrap();

        // Verify all nodes have the new key
        assert_eq!(ring_1.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_2.active_zone_key_id, Some(zone_key_id_2));
        assert_eq!(ring_3.active_zone_key_id, Some(zone_key_id_2));

        // All nodes have the same key value
        assert_eq!(ring_1.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_2.active_zone_key(), Some(&zone_key_2));
        assert_eq!(ring_3.active_zone_key(), Some(&zone_key_2));

        // Original nodes have both old and new keys
        assert!(ring_1.zone_key(&zone_key_id_1).is_some());
        assert!(ring_2.zone_key(&zone_key_id_1).is_some());

        // New node only has the new key (didn't receive the old key)
        assert!(ring_3.zone_key(&zone_key_id_1).is_none());
        assert!(ring_3.zone_key(&zone_key_id_2).is_some());
    }

    /// Test that `valid_until` expiration field is correctly stored.
    #[test]
    fn manifest_with_valid_until() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-expiry");
        let issued_at = 1_700_000_000;
        let expires_at = 1_700_100_000; // 100,000 seconds later

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();
        let zone_key_id = ZoneKeyId::from_bytes([0xEE; 8]);
        let object_id_key_id = ObjectIdKeyId::from_bytes([0xFF; 8]);

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id,
            object_id_key_id,
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: Some(expires_at), // Expiration set
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: Some(RekeyPolicy {
                overlap_window_secs: Some(3600), // 1 hour overlap
                ..RekeyPolicy::default()
            }),
            signature: test_signature(),
        };

        // Manifest should apply successfully (expiration is metadata, not enforced in apply)
        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key_id, Some(zone_key_id));
        assert_eq!(manifest.valid_until, Some(expires_at));
        assert_eq!(
            manifest.rekey_policy.as_ref().unwrap().overlap_window_secs,
            Some(3600)
        );
    }

    /// Test XChaCha20-Poly1305 algorithm selection.
    #[test]
    fn manifest_with_xchacha20_poly1305() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-xchacha");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xCC; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xDD; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305, // Extended nonce variant
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        ring.apply_manifest(&manifest, &node_id, &sk).unwrap();

        assert_eq!(ring.active_zone_key(), Some(&zone_key));
        assert_eq!(manifest.algorithm, ZoneKeyAlgorithm::XChaCha20Poly1305);
    }

    /// Test `ZoneKeyId` and `ObjectIdKeyId` formatting.
    #[test]
    fn key_id_formatting() {
        let zone_key_id = ZoneKeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let object_id_key_id =
            ObjectIdKeyId::from_bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);

        // Display format should be lowercase hex
        assert_eq!(format!("{zone_key_id}"), "0123456789abcdef");
        assert_eq!(format!("{object_id_key_id}"), "fedcba9876543210");

        // Debug format includes type name
        assert!(format!("{zone_key_id:?}").contains("ZoneKeyId"));
        assert!(format!("{object_id_key_id:?}").contains("ObjectIdKeyId"));
    }

    /// Test `ZoneKey` redacted debug output for security.
    #[test]
    fn zone_key_debug_is_redacted() {
        let zone_key = ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]);
        let debug_output = format!("{zone_key:?}");

        // Should NOT contain the actual key bytes
        assert!(!debug_output.contains("42"));
        // Should contain redaction marker
        assert!(debug_output.contains("redacted"));
    }

    /// Test `set_active_zone_key` returns false for unknown key.
    #[test]
    fn set_active_key_unknown_returns_false() {
        let zone_id = ZoneId::work();
        let mut ring = ZoneKeyRing::new(zone_id);

        let unknown_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
        let unknown_obj_key_id = ObjectIdKeyId::from_bytes([0xEE; 8]);

        // Setting unknown key should return false
        assert!(!ring.set_active_zone_key(unknown_key_id));
        assert!(!ring.set_active_object_id_key(unknown_obj_key_id));

        // Active key should remain None
        assert!(ring.active_zone_key_id.is_none());
        assert!(ring.active_object_id_key_id.is_none());
    }

    // ── Serde and structural coverage ──

    #[test]
    fn zone_key_id_serde_roundtrip() {
        let id = ZoneKeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ZoneKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn object_id_key_id_serde_roundtrip() {
        let id = ObjectIdKeyId::from_bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectIdKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn zone_key_algorithm_serde_roundtrip() {
        for alg in [
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyAlgorithm::XChaCha20Poly1305,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let back: ZoneKeyAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, back);
        }
        // Verify snake_case
        let json = serde_json::to_string(&ZoneKeyAlgorithm::ChaCha20Poly1305).unwrap();
        assert!(json.contains("cha_cha20"));
    }

    #[test]
    fn rekey_policy_default() {
        let rp = RekeyPolicy::default();
        assert!(!rp.epoch_ratchet);
        assert!(rp.overlap_window_secs.is_none());
        assert!(rp.retain_epochs.is_none());
        assert!(!rp.rewrap_on_membership_change);
        assert!(!rp.rotate_object_id_key_on_membership_change);
    }

    #[test]
    fn rekey_policy_serde_roundtrip() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(600),
            retain_epochs: Some(5),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: false,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let back: RekeyPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.epoch_ratchet);
        assert_eq!(back.overlap_window_secs, Some(600));
        assert_eq!(back.retain_epochs, Some(5));
        assert!(back.rewrap_on_membership_change);
        assert!(!back.rotate_object_id_key_on_membership_change);
    }

    #[test]
    fn rekey_policy_serde_omits_none_fields() {
        let rp = RekeyPolicy::default();
        let json = serde_json::to_string(&rp).unwrap();
        assert!(!json.contains("overlap_window_secs"));
        assert!(!json.contains("retain_epochs"));
    }

    #[test]
    fn zone_key_from_bytes_as_bytes() {
        let bytes = [0x42u8; ZONE_KEY_LEN];
        let key = ZoneKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    #[test]
    fn zone_key_ring_new_empty() {
        let zone_id = ZoneId::work();
        let ring = ZoneKeyRing::new(zone_id.clone());
        assert_eq!(ring.zone_id, zone_id);
        assert!(ring.active_zone_key_id.is_none());
        assert!(ring.active_object_id_key_id.is_none());
        assert!(ring.active_zone_key().is_none());
        assert!(ring.active_object_id_key().is_none());
    }

    #[test]
    fn zone_key_ring_lookup_returns_none_for_unknown() {
        let ring = ZoneKeyRing::new(ZoneId::work());
        let unknown = ZoneKeyId::from_bytes([0xFF; 8]);
        let unknown_obj = ObjectIdKeyId::from_bytes([0xEE; 8]);
        assert!(ring.zone_key(&unknown).is_none());
        assert!(ring.object_id_key(&unknown_obj).is_none());
    }

    #[test]
    fn zone_key_error_display() {
        let err = ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        };
        let msg = err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));

        let err = ZoneKeyError::ZoneIdMismatch {
            expected: "z:work".into(),
            found: "z:private".into(),
        };
        assert!(err.to_string().contains("z:work"));

        let err = ZoneKeyError::MissingWrappedZoneKey {
            node_id: "node-42".into(),
        };
        assert!(err.to_string().contains("node-42"));

        let err = ZoneKeyError::MissingWrappedObjectIdKey {
            node_id: "node-99".into(),
        };
        assert!(err.to_string().contains("node-99"));
    }

    #[test]
    fn object_id_key_unwrap_fails_with_wrong_node_id() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-5");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let mut wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        wrapped.recipient = TailscaleNodeId::new("node-6");

        let result = unwrap_object_id_key(&sk, &zone_id, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn apply_manifest_missing_object_id_key() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-no-obj");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        // Create manifest with zone key but NO object id key for this node
        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![], // Empty!
            rekey_policy: None,
            signature: test_signature(),
        };

        let mut ring = ZoneKeyRing::new(zone_id);
        let err = ring
            .apply_manifest(&manifest, &node_id, &sk)
            .expect_err("should fail without object id key");
        assert!(matches!(
            err,
            ZoneKeyError::MissingWrappedObjectIdKey { .. }
        ));
    }

    #[test]
    fn zone_key_manifest_new_empty() {
        let zone_id = ZoneId::work();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let manifest =
            ZoneKeyManifest::new_empty(zone_id.clone(), 1_700_000_000, &signing_key).unwrap();
        assert_eq!(manifest.zone_id, zone_id);
        assert_eq!(manifest.valid_from, 1_700_000_000);
        assert!(manifest.valid_until.is_none());
        assert!(manifest.prev_zone_key_id.is_none());
        assert!(manifest.wrapped_keys.is_empty());
        assert!(manifest.wrapped_object_id_keys.is_empty());
        assert!(manifest.rekey_policy.is_none());
        assert_eq!(manifest.algorithm, ZoneKeyAlgorithm::ChaCha20Poly1305);
    }

    /// Test `wrapped_key_for` returns `None` when recipient not found.
    #[test]
    fn wrapped_key_for_missing_recipient() {
        let zone_id = ZoneId::work();
        let node_1_id = TailscaleNodeId::new("node-1");
        let node_2_id = TailscaleNodeId::new("node-2");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let zone_key = random_zone_key();
        let object_id_key = random_object_id_key();

        // Only wrap for node-1
        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_1_id, issued_at, &zone_key).unwrap();
        let wrapped_object =
            wrap_object_id_key(&pk, &zone_id, &node_1_id, issued_at, &object_id_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_object],
            rekey_policy: None,
            signature: test_signature(),
        };

        // node-1 found, node-2 not found
        assert!(manifest.wrapped_key_for(&node_1_id).is_some());
        assert!(manifest.wrapped_key_for(&node_2_id).is_none());
        assert!(manifest.wrapped_object_id_key_for(&node_1_id).is_some());
        assert!(manifest.wrapped_object_id_key_for(&node_2_id).is_none());
    }
}
