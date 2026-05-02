//! Zone key distribution and rotation primitives.
//!
//! Implements `ZoneKeyManifest` objects and HPKE-wrapped zone keys.

use std::collections::HashMap;
use std::fmt;

use fcp_crypto::{
    CryptoError, Fcp2Aad, HpkeSealedBox, X25519PublicKey, X25519SecretKey, XWingSealedBox,
    hpke_open, hpke_seal,
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

/// KEM used to wrap a zone key for a recipient.
///
/// Carried both at manifest level (default for the manifest) and on each
/// [`WrappedZoneKeyV4`] entry so a single V4 manifest can mix V3
/// (`HpkeX25519`) and V4 (`XWing`) recipients during the migration
/// window. See `docs/post-quantum/x_wing_kem_design.md` §3.2 + §6.
///
/// Introduced under sub-bead `kyopb.1.2.3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKemAlgorithm {
    /// V3 baseline: HPKE(DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305).
    HpkeX25519,
    /// V4 hybrid: X-Wing (X25519 + ML-KEM-768) + ChaCha20-Poly1305.
    XWing,
}

impl Default for ZoneKemAlgorithm {
    fn default() -> Self {
        // Backward compatibility: V3 manifests have no `kem` field;
        // serde substitutes the default, which MUST be `HpkeX25519`
        // so the inferred KEM matches the V3 wire format.
        Self::HpkeX25519
    }
}

/// Per-recipient sealed-box variant: discriminates V3 HPKE wrap vs V4
/// X-Wing wrap.
///
/// Carries the actual ciphertext for whichever KEM the sender chose for
/// this recipient. The serde tag `"kem"` puts the discriminator in the
/// JSON/CBOR map directly so a forensic reader can pick out the wrap
/// type without decoding the inner sealed box.
///
/// Introduced under sub-bead `kyopb.1.2.3`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kem", rename_all = "snake_case")]
pub enum WrappedKey {
    /// V3 HPKE-X25519 sealed box (existing wire form).
    HpkeX25519 {
        /// HPKE sealed box: `enc || ciphertext`.
        sealed: HpkeSealedBox,
    },
    /// V4 X-Wing hybrid sealed box.
    XWing {
        /// X-Wing sealed box: `enc || ciphertext` (per kyopb.1.2.2).
        sealed: XWingSealedBox,
    },
}

impl WrappedKey {
    /// Lift a V3 HPKE sealed box into the V4 enum form.
    #[must_use]
    pub const fn from_hpke(sealed: HpkeSealedBox) -> Self {
        Self::HpkeX25519 { sealed }
    }

    /// Lift a V4 X-Wing sealed box into the V4 enum form.
    #[must_use]
    pub const fn from_xwing(sealed: XWingSealedBox) -> Self {
        Self::XWing { sealed }
    }

    /// Report which KEM produced this wrap.
    #[must_use]
    pub const fn kem(&self) -> ZoneKemAlgorithm {
        match self {
            Self::HpkeX25519 { .. } => ZoneKemAlgorithm::HpkeX25519,
            Self::XWing { .. } => ZoneKemAlgorithm::XWing,
        }
    }

    /// Borrow the V3 HPKE sealed box if this is the HPKE-X25519 variant.
    #[must_use]
    pub const fn hpke_sealed(&self) -> Option<&HpkeSealedBox> {
        match self {
            Self::HpkeX25519 { sealed } => Some(sealed),
            Self::XWing { .. } => None,
        }
    }

    /// Borrow the V4 X-Wing sealed box if this is the X-Wing variant.
    #[must_use]
    pub const fn xwing_sealed(&self) -> Option<&XWingSealedBox> {
        match self {
            Self::XWing { sealed } => Some(sealed),
            Self::HpkeX25519 { .. } => None,
        }
    }
}

/// V4 wrapped zone-key entry — uses the [`WrappedKey`] enum so a single
/// manifest can carry mixed V3+V4 wraps.
///
/// Lives alongside the legacy [`WrappedZoneKey`] (which still carries
/// `HpkeSealedBox` directly) so V3 deserialisers continue to work
/// unchanged. Senders that emit V4 manifests SHOULD use this list and
/// can choose per recipient which KEM to wrap under.
///
/// Introduced under sub-bead `kyopb.1.2.3`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedZoneKeyV4 {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: WrappedKey,
}

/// Wrapped zone key entry (HPKE sealed box).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedZoneKey {
    pub recipient: TailscaleNodeId,
    pub issued_at: u64,
    pub sealed: HpkeSealedBox,
}

impl WrappedZoneKey {
    /// Lift a V3 wrap into the V4 [`WrappedZoneKeyV4`] form by tagging
    /// it as `HpkeX25519`. Used by the V3→V4 schema migration helper
    /// (see [`ZoneKeyManifest::migrated_to_v4`]).
    #[must_use]
    pub fn to_v4(&self) -> WrappedZoneKeyV4 {
        WrappedZoneKeyV4 {
            recipient: self.recipient.clone(),
            issued_at: self.issued_at,
            sealed: WrappedKey::from_hpke(self.sealed.clone()),
        }
    }
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
///
/// The `kem` field and `wrapped_keys_v4` list are V4 additions
/// (sub-bead `kyopb.1.2.3`). They are placed at the end of the field
/// list so the canonical CBOR encoding produced by serde derive places
/// them last in the map; V3 deserialisers tolerate them as
/// unknown-skipped fields, and V4 deserialisers find them via the
/// declared field names. Both are `#[serde(default)]` so a V3 manifest
/// (which omits both) deserialises with `kem = HpkeX25519` and an empty
/// `wrapped_keys_v4` list, matching the V3 wire form's implicit
/// semantics.
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
    /// Default KEM advertised by this manifest (V4 addition; defaults to
    /// `HpkeX25519` for backward compatibility with V3 manifests that
    /// omit the field).
    #[serde(default)]
    pub kem: ZoneKemAlgorithm,
    /// V4 wrapped-key entries. Empty in V3-only manifests; populated by
    /// V4 senders alongside (or instead of) `wrapped_keys` so a single
    /// manifest can carry mixed V3 + V4 wraps during the V3↔V4
    /// migration window. See `WrappedKey` for per-recipient KEM
    /// discrimination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrapped_keys_v4: Vec<WrappedZoneKeyV4>,
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
        rand::rng().fill_bytes(&mut zone_key_id);

        let mut object_id_key_id = [0u8; 8];
        rand::rng().fill_bytes(&mut object_id_key_id);

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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        })
    }

    /// Find the V4 wrapped zone-key entry for a recipient. Looks only in
    /// `wrapped_keys_v4`; callers that want V3 fallback should also
    /// consult [`Self::wrapped_key_for`].
    #[must_use]
    pub fn wrapped_key_v4_for(&self, node_id: &TailscaleNodeId) -> Option<&WrappedZoneKeyV4> {
        self.wrapped_keys_v4
            .iter()
            .find(|entry| entry.recipient == *node_id)
    }

    /// Resolve a recipient's wrap by trying V4 first, falling back to V3.
    ///
    /// Returns the [`WrappedKey`] enum directly so callers do not need to
    /// know which list a recipient was published into. V4 senders that
    /// also published a V3 wrap for this recipient (interop manifests)
    /// will see the V4 form returned.
    #[must_use]
    pub fn resolved_wrapped_key_for(&self, node_id: &TailscaleNodeId) -> Option<WrappedKey> {
        if let Some(v4) = self.wrapped_key_v4_for(node_id) {
            return Some(v4.sealed.clone());
        }
        self.wrapped_key_for(node_id)
            .map(|v3| WrappedKey::from_hpke(v3.sealed.clone()))
    }

    /// Produce a V4 view of this manifest by promoting every entry in
    /// `wrapped_keys` to a `WrappedZoneKeyV4` tagged as `HpkeX25519`,
    /// and setting the manifest-level `kem` field if requested.
    ///
    /// **Does NOT re-sign.** The caller is responsible for re-issuing the
    /// owner signature against the migrated payload — the migration
    /// helper is intentionally non-cryptographic and exists so callers
    /// can shape a V4 manifest before handing it to the owner-key
    /// signing flow.
    ///
    /// Originally V3 wraps are NOT removed; the V4 manifest carries
    /// both lists so V3-only recipients keep working.
    #[must_use]
    pub fn migrated_to_v4(&self, manifest_kem: ZoneKemAlgorithm) -> Self {
        let mut migrated = self.clone();
        migrated.kem = manifest_kem;
        // Promote any V3 wraps the migrated manifest doesn't already
        // cover under wrapped_keys_v4 (under HpkeX25519 tag) so a single
        // lookup against wrapped_keys_v4 suffices for any recipient.
        for v3 in &self.wrapped_keys {
            if migrated.wrapped_key_v4_for(&v3.recipient).is_none() {
                migrated.wrapped_keys_v4.push(v3.to_v4());
            }
        }
        migrated
    }

    /// Add a V4 X-Wing wrap for a recipient. If the recipient already
    /// has a V4 entry, it is replaced; the V3 `wrapped_keys` list is
    /// untouched (so a V4 sender can still publish HPKE wraps for V3
    /// recipients in the same manifest).
    pub fn add_xwing_wrap(
        &mut self,
        recipient: TailscaleNodeId,
        issued_at: u64,
        sealed: XWingSealedBox,
    ) {
        let entry = WrappedZoneKeyV4 {
            recipient: recipient.clone(),
            issued_at,
            sealed: WrappedKey::from_xwing(sealed),
        };
        if let Some(slot) = self
            .wrapped_keys_v4
            .iter_mut()
            .find(|e| e.recipient == recipient)
        {
            *slot = entry;
        } else {
            self.wrapped_keys_v4.push(entry);
        }
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
        rand::rng().fill_bytes(&mut bytes);
        ZoneKey::from_bytes(bytes)
    }

    fn random_object_id_key() -> ObjectIdKey {
        let mut bytes = [0u8; ZONE_KEY_LEN];
        rand::rng().fill_bytes(&mut bytes);
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
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
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // node-1 found, node-2 not found
        assert!(manifest.wrapped_key_for(&node_1_id).is_some());
        assert!(manifest.wrapped_key_for(&node_2_id).is_none());
        assert!(manifest.wrapped_object_id_key_for(&node_1_id).is_some());
        assert!(manifest.wrapped_object_id_key_for(&node_2_id).is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_id_hash_consistency() {
        use std::collections::HashSet;
        let id = ZoneKeyId::from_bytes([0x42; 8]);
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn zone_key_id_equality() {
        let a = ZoneKeyId::from_bytes([1; 8]);
        let b = ZoneKeyId::from_bytes([1; 8]);
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_id_inequality() {
        let a = ZoneKeyId::from_bytes([1; 8]);
        let b = ZoneKeyId::from_bytes([2; 8]);
        assert_ne!(a, b);
    }

    #[test]
    fn zone_key_id_clone() {
        let a = ZoneKeyId::from_bytes([0xAB; 8]);
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_id_copy() {
        let a = ZoneKeyId::from_bytes([0xCD; 8]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_id_as_bytes() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let id = ZoneKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ObjectIdKeyId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn object_id_key_id_hash_consistency() {
        use std::collections::HashSet;
        let id = ObjectIdKeyId::from_bytes([0x42; 8]);
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn object_id_key_id_equality() {
        let a = ObjectIdKeyId::from_bytes([3; 8]);
        let b = ObjectIdKeyId::from_bytes([3; 8]);
        assert_eq!(a, b);
    }

    #[test]
    fn object_id_key_id_inequality() {
        let a = ObjectIdKeyId::from_bytes([3; 8]);
        let b = ObjectIdKeyId::from_bytes([4; 8]);
        assert_ne!(a, b);
    }

    #[test]
    fn object_id_key_id_clone() {
        let a = ObjectIdKeyId::from_bytes([0xDE; 8]);
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn object_id_key_id_as_bytes() {
        let bytes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let id = ObjectIdKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKey – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_equality() {
        let a = ZoneKey::from_bytes([0x01; ZONE_KEY_LEN]);
        let b = ZoneKey::from_bytes([0x01; ZONE_KEY_LEN]);
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_inequality() {
        let a = ZoneKey::from_bytes([0x01; ZONE_KEY_LEN]);
        let b = ZoneKey::from_bytes([0x02; ZONE_KEY_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn zone_key_hash_consistency() {
        use std::collections::HashSet;
        let key = ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]);
        let mut set = HashSet::new();
        set.insert(key);
        set.insert(key);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn zone_key_copy() {
        let a = ZoneKey::from_bytes([0x99; ZONE_KEY_LEN]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn zone_key_clone() {
        let a = ZoneKey::from_bytes([0xAA; ZONE_KEY_LEN]);
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyAlgorithm – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_algorithm_equality() {
        assert_eq!(
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyAlgorithm::ChaCha20Poly1305
        );
        assert_ne!(
            ZoneKeyAlgorithm::ChaCha20Poly1305,
            ZoneKeyAlgorithm::XChaCha20Poly1305
        );
    }

    #[test]
    fn zone_key_algorithm_copy() {
        let a = ZoneKeyAlgorithm::XChaCha20Poly1305;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyError – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        });
        assert!(err.to_string().contains("32"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZoneKeyRing – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_ring_insert_and_retrieve_object_id_key() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ObjectIdKeyId::from_bytes([0x42; 8]);
        let key = random_object_id_key();
        ring.insert_object_id_key(key_id, key);
        assert_eq!(ring.object_id_key(&key_id), Some(&key));
        assert!(ring.set_active_object_id_key(key_id));
        assert_eq!(ring.active_object_id_key(), Some(&key));
    }

    #[test]
    fn zone_key_ring_clone() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key = random_zone_key();
        ring.insert_zone_key(key_id, key);
        let _ = ring.set_active_zone_key(key_id);

        let cloned = ring.clone();
        assert_eq!(cloned.zone_id, ring.zone_id);
        assert_eq!(cloned.active_zone_key_id, ring.active_zone_key_id);
        assert_eq!(cloned.zone_key(&key_id), Some(&key));
    }

    #[test]
    fn zone_key_ring_multiple_keys() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let id1 = ZoneKeyId::from_bytes([1; 8]);
        let id2 = ZoneKeyId::from_bytes([2; 8]);
        let key1 = ZoneKey::from_bytes([0x11; ZONE_KEY_LEN]);
        let key2 = ZoneKey::from_bytes([0x22; ZONE_KEY_LEN]);

        ring.insert_zone_key(id1, key1);
        ring.insert_zone_key(id2, key2);

        assert_eq!(ring.zone_key(&id1), Some(&key1));
        assert_eq!(ring.zone_key(&id2), Some(&key2));

        // Switch active between them
        assert!(ring.set_active_zone_key(id1));
        assert_eq!(ring.active_zone_key(), Some(&key1));
        assert!(ring.set_active_zone_key(id2));
        assert_eq!(ring.active_zone_key(), Some(&key2));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RekeyPolicy – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rekey_policy_clone() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(300),
            retain_epochs: Some(3),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: true,
        };
        let cloned = rp.clone();
        assert_eq!(cloned.epoch_ratchet, rp.epoch_ratchet);
        assert_eq!(cloned.overlap_window_secs, rp.overlap_window_secs);
        assert_eq!(cloned.retain_epochs, rp.retain_epochs);
        assert_eq!(
            cloned.rewrap_on_membership_change,
            rp.rewrap_on_membership_change
        );
        assert_eq!(
            cloned.rotate_object_id_key_on_membership_change,
            rp.rotate_object_id_key_on_membership_change
        );
    }

    #[test]
    fn rekey_policy_all_fields_set() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(600),
            retain_epochs: Some(10),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: true,
        };
        let json = serde_json::to_string(&rp).unwrap();
        assert!(json.contains("epoch_ratchet"));
        assert!(json.contains("overlap_window_secs"));
        assert!(json.contains("retain_epochs"));
        assert!(json.contains("rewrap_on_membership_change"));
        assert!(json.contains("rotate_object_id_key_on_membership_change"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ZONE_KEY_LEN constant
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_key_len_is_32() {
        assert_eq!(ZONE_KEY_LEN, 32);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New coverage tests
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify `ZoneKeyId` Display for all-zero bytes.
    #[test]
    fn zone_key_id_display_all_zeros() {
        let id = ZoneKeyId::from_bytes([0x00; 8]);
        assert_eq!(format!("{id}"), "0000000000000000");
    }

    /// Verify `ObjectIdKeyId` Display for all-zero bytes.
    #[test]
    fn object_id_key_id_display_all_zeros() {
        let id = ObjectIdKeyId::from_bytes([0x00; 8]);
        assert_eq!(format!("{id}"), "0000000000000000");
    }

    /// Verify the exact structure of the `ZoneKey` Debug output.
    #[test]
    fn zone_key_debug_exact_format() {
        let key = ZoneKey::from_bytes([0xFF; ZONE_KEY_LEN]);
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "ZoneKey(\"[redacted; 32 bytes]\")");
    }

    /// Verify `ZoneKeyId` Debug includes the hex encoding.
    #[test]
    fn zone_key_id_debug_includes_hex() {
        let id = ZoneKeyId::from_bytes([0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("ZoneKeyId("));
        assert!(dbg.contains("abcd000000000001"));
    }

    /// Verify `ObjectIdKeyId` Debug includes the hex encoding.
    #[test]
    fn object_id_key_id_debug_includes_hex() {
        let id = ObjectIdKeyId::from_bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("ObjectIdKeyId("));
        assert!(dbg.contains("1020304050607080"));
    }

    /// Verify `ZoneKeyAlgorithm` `XChaCha20Poly1305` serde `snake_case`.
    #[test]
    fn zone_key_algorithm_xchacha20_serde_snake_case() {
        let json = serde_json::to_string(&ZoneKeyAlgorithm::XChaCha20Poly1305).unwrap();
        assert!(json.contains("x_cha_cha20"));
    }

    /// Verify `ZoneKeyAlgorithm` debug output.
    #[test]
    fn zone_key_algorithm_debug_output() {
        let dbg_c = format!("{:?}", ZoneKeyAlgorithm::ChaCha20Poly1305);
        assert_eq!(dbg_c, "ChaCha20Poly1305");
        let dbg_x = format!("{:?}", ZoneKeyAlgorithm::XChaCha20Poly1305);
        assert_eq!(dbg_x, "XChaCha20Poly1305");
    }

    /// Verify `ZoneKeyAlgorithm` clone.
    #[test]
    fn zone_key_algorithm_clone() {
        let a = ZoneKeyAlgorithm::ChaCha20Poly1305;
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// Verify that `wrap_zone_key` produces different ciphertext on each call (HPKE non-determinism).
    #[test]
    fn wrap_zone_key_nondeterministic() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-nd");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = ZoneKey::from_bytes([0x42; ZONE_KEY_LEN]);

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        // Both must decrypt to the same key, but sealed boxes should differ
        let k1 = unwrap_zone_key(&sk, &zone_id, &w1).unwrap();
        let k2 = unwrap_zone_key(&sk, &zone_id, &w2).unwrap();
        assert_eq!(k1, zone_key);
        assert_eq!(k2, zone_key);
        // The encrypted payloads should differ (HPKE uses fresh randomness)
        assert_ne!(w1.sealed.ciphertext, w2.sealed.ciphertext);
    }

    /// Verify `unwrap_zone_key` fails when using a different secret key.
    #[test]
    fn unwrap_zone_key_wrong_secret_key() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-wsk");
        let issued_at = 1_700_000_000;

        let sk_correct = X25519SecretKey::generate();
        let pk = sk_correct.public_key();
        let sk_wrong = X25519SecretKey::generate();

        let zone_key = random_zone_key();
        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        let result = unwrap_zone_key(&sk_wrong, &zone_id, &wrapped);
        assert!(result.is_err(), "unwrap with wrong SK should fail");
    }

    /// Verify `unwrap_object_id_key` fails when using a different secret key.
    #[test]
    fn unwrap_object_id_key_wrong_secret_key() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-wsk2");
        let issued_at = 1_700_000_000;

        let real_sk = X25519SecretKey::generate();
        let pk = real_sk.public_key();
        let bad_sk = X25519SecretKey::generate();

        let key = random_object_id_key();
        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();

        let result = unwrap_object_id_key(&bad_sk, &zone_id, &wrapped);
        assert!(result.is_err(), "unwrap with wrong SK should fail");
    }

    /// Verify `unwrap_zone_key` fails when `zone_id` differs from the one used for wrapping.
    #[test]
    fn unwrap_zone_key_wrong_zone_id() {
        let wrap_zone = ZoneId::work();
        let open_zone = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-wzi");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &wrap_zone, &node_id, issued_at, &zone_key).unwrap();
        let result = unwrap_zone_key(&sk, &open_zone, &wrapped);
        assert!(result.is_err(), "unwrap with wrong zone_id should fail");
    }

    /// Verify `unwrap_object_id_key` fails when `zone_id` differs.
    #[test]
    fn unwrap_object_id_key_wrong_zone_id() {
        let wrap_zone = ZoneId::community();
        let open_zone = ZoneId::public();
        let node_id = TailscaleNodeId::new("node-wzi2");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &wrap_zone, &node_id, issued_at, &key).unwrap();
        let result = unwrap_object_id_key(&sk, &open_zone, &wrapped);
        assert!(result.is_err(), "unwrap with wrong zone_id should fail");
    }

    /// Verify `ZoneKeyRing::insert_zone_key` overwrites an existing key with the same id.
    #[test]
    fn zone_key_ring_insert_overwrites_existing() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key_a = ZoneKey::from_bytes([0xAA; ZONE_KEY_LEN]);
        let key_b = ZoneKey::from_bytes([0xBB; ZONE_KEY_LEN]);

        ring.insert_zone_key(key_id, key_a);
        assert_eq!(ring.zone_key(&key_id), Some(&key_a));

        ring.insert_zone_key(key_id, key_b);
        assert_eq!(ring.zone_key(&key_id), Some(&key_b));
    }

    /// Verify `ZoneKeyRing::insert_object_id_key` overwrites an existing key.
    #[test]
    fn zone_key_ring_insert_object_id_key_overwrites() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ObjectIdKeyId::from_bytes([0x02; 8]);
        let key_a = ObjectIdKey::from_bytes([0xCC; ZONE_KEY_LEN]);
        let key_b = ObjectIdKey::from_bytes([0xDD; ZONE_KEY_LEN]);

        ring.insert_object_id_key(key_id, key_a);
        assert_eq!(ring.object_id_key(&key_id), Some(&key_a));

        ring.insert_object_id_key(key_id, key_b);
        assert_eq!(ring.object_id_key(&key_id), Some(&key_b));
    }

    /// Verify `ZoneKeyRing` debug output includes the type name.
    #[test]
    fn zone_key_ring_debug_output() {
        let ring = ZoneKeyRing::new(ZoneId::work());
        let dbg = format!("{ring:?}");
        assert!(dbg.contains("ZoneKeyRing"));
    }

    /// Verify `RekeyPolicy` debug output.
    #[test]
    fn rekey_policy_debug_output() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(600),
            retain_epochs: Some(5),
            rewrap_on_membership_change: false,
            rotate_object_id_key_on_membership_change: false,
        };
        let dbg = format!("{rp:?}");
        assert!(dbg.contains("RekeyPolicy"));
        assert!(dbg.contains("epoch_ratchet: true"));
        assert!(dbg.contains("600"));
    }

    /// Verify `RekeyPolicy` deserialization from minimal JSON (only required fields).
    #[test]
    fn rekey_policy_deserialize_minimal_json() {
        let json = r"{}";
        let rp: RekeyPolicy = serde_json::from_str(json).unwrap();
        assert!(!rp.epoch_ratchet);
        assert!(rp.overlap_window_secs.is_none());
        assert!(rp.retain_epochs.is_none());
        assert!(!rp.rewrap_on_membership_change);
        assert!(!rp.rotate_object_id_key_on_membership_change);
    }

    /// Verify `ZoneKeyManifest::new_empty` produces unique random key IDs across invocations.
    #[test]
    fn zone_key_manifest_new_empty_unique_ids() {
        let zone_id = ZoneId::work();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let m1 = ZoneKeyManifest::new_empty(zone_id.clone(), 1_700_000_000, &signing_key).unwrap();
        let m2 = ZoneKeyManifest::new_empty(zone_id, 1_700_000_000, &signing_key).unwrap();
        // Random IDs should (almost certainly) differ
        assert_ne!(m1.zone_key_id, m2.zone_key_id);
        assert_ne!(m1.object_id_key_id, m2.object_id_key_id);
    }

    /// Verify `ZoneKeyManifest::new_empty` header fields.
    #[test]
    fn zone_key_manifest_new_empty_header_fields() {
        let zone_id = ZoneId::private();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let m = ZoneKeyManifest::new_empty(zone_id.clone(), 1_700_000_000, &signing_key).unwrap();
        assert_eq!(m.header.zone_id, zone_id);
        assert_eq!(m.header.created_at, 1_700_000_000);
        assert!(m.header.refs.is_empty());
        assert!(m.header.foreign_refs.is_empty());
        assert!(m.header.ttl_secs.is_none());
        assert!(m.header.placement.is_none());
    }

    /// Verify `wrapped_key_for` selects the correct entry among multiple recipients.
    #[test]
    #[allow(clippy::similar_names)]
    fn wrapped_key_for_selects_correct_among_multiple() {
        let zone_id = ZoneId::work();
        let node_1 = TailscaleNodeId::new("node-sel-1");
        let node_2 = TailscaleNodeId::new("node-sel-2");
        let node_3 = TailscaleNodeId::new("node-sel-3");
        let issued_at = 1_700_000_000;

        let sk1 = X25519SecretKey::generate();
        let sk2 = X25519SecretKey::generate();
        let sk3 = X25519SecretKey::generate();
        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();

        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let w1 = wrap_zone_key(&pk1, &zone_id, &node_1, issued_at, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk2, &zone_id, &node_2, issued_at, &zone_key).unwrap();
        let w3 = wrap_zone_key(&pk3, &zone_id, &node_3, issued_at, &zone_key).unwrap();
        let o1 = wrap_object_id_key(&pk1, &zone_id, &node_1, issued_at, &obj_key).unwrap();
        let o2 = wrap_object_id_key(&pk2, &zone_id, &node_2, issued_at, &obj_key).unwrap();
        let o3 = wrap_object_id_key(&pk3, &zone_id, &node_3, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![w1, w2, w3],
            wrapped_object_id_keys: vec![o1, o2, o3],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Each node selects its own wrapped key
        let got_1 = manifest.wrapped_key_for(&node_1).unwrap();
        assert_eq!(got_1.recipient, node_1);
        let got_2 = manifest.wrapped_key_for(&node_2).unwrap();
        assert_eq!(got_2.recipient, node_2);
        let got_3 = manifest.wrapped_key_for(&node_3).unwrap();
        assert_eq!(got_3.recipient, node_3);

        // Same for object id keys
        let obj_got = manifest.wrapped_object_id_key_for(&node_2).unwrap();
        assert_eq!(obj_got.recipient, node_2);
    }

    /// Verify `WrappedZoneKey` clone preserves all fields.
    #[test]
    fn wrapped_zone_key_clone() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-wclone");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let cloned = wrapped.clone();
        assert_eq!(cloned.recipient, wrapped.recipient);
        assert_eq!(cloned.issued_at, wrapped.issued_at);
        assert_eq!(cloned.sealed.ciphertext, wrapped.sealed.ciphertext);
    }

    /// Verify `WrappedObjectIdKey` clone preserves all fields.
    #[test]
    fn wrapped_object_id_key_clone() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-oclone");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let cloned = wrapped.clone();
        assert_eq!(cloned.recipient, wrapped.recipient);
        assert_eq!(cloned.issued_at, wrapped.issued_at);
        assert_eq!(cloned.sealed.ciphertext, wrapped.sealed.ciphertext);
    }

    /// Verify `WrappedZoneKey` debug output includes relevant information.
    #[test]
    fn wrapped_zone_key_debug() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-dbg");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let dbg = format!("{wrapped:?}");
        assert!(dbg.contains("WrappedZoneKey"));
        assert!(dbg.contains("node-dbg"));
    }

    /// Verify `ZoneKeyId` and `ObjectIdKeyId` work correctly as `HashMap` keys with distinct values.
    #[test]
    fn key_ids_as_hashmap_keys() {
        let mut map = HashMap::new();
        let id_a = ZoneKeyId::from_bytes([0x01; 8]);
        let id_b = ZoneKeyId::from_bytes([0x02; 8]);
        let id_c = ZoneKeyId::from_bytes([0x01; 8]); // same as id_a

        map.insert(id_a, "first");
        map.insert(id_b, "second");
        map.insert(id_c, "overwritten"); // should overwrite id_a's entry

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&id_a), Some(&"overwritten"));
        assert_eq!(map.get(&id_b), Some(&"second"));
    }

    /// Verify `ZoneKeyError::Crypto` variant Display.
    #[test]
    fn zone_key_error_crypto_display() {
        let crypto_err = CryptoError::HpkeFailed("test hpke error".to_string());
        let err = ZoneKeyError::from(crypto_err);
        let msg = err.to_string();
        assert!(msg.contains("crypto failure"));
    }

    /// Verify `ZoneKeyManifest` serde roundtrip (JSON).
    #[test]
    fn zone_key_manifest_serde_roundtrip() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-serde");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_obj = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0xAA; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0xBB; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: Some(1_700_100_000),
            prev_zone_key_id: Some(ZoneKeyId::from_bytes([0x99; 8])),
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_obj],
            rekey_policy: Some(RekeyPolicy {
                epoch_ratchet: true,
                overlap_window_secs: Some(600),
                retain_epochs: Some(3),
                rewrap_on_membership_change: true,
                rotate_object_id_key_on_membership_change: false,
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let back: ZoneKeyManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(back.zone_id, manifest.zone_id);
        assert_eq!(back.zone_key_id, manifest.zone_key_id);
        assert_eq!(back.object_id_key_id, manifest.object_id_key_id);
        assert_eq!(back.algorithm, manifest.algorithm);
        assert_eq!(back.valid_from, manifest.valid_from);
        assert_eq!(back.valid_until, manifest.valid_until);
        assert_eq!(back.prev_zone_key_id, manifest.prev_zone_key_id);
        assert_eq!(back.wrapped_keys.len(), 1);
        assert_eq!(back.wrapped_object_id_keys.len(), 1);
        assert!(back.rekey_policy.is_some());

        // The unwrapped key should still work after serde roundtrip
        let unwrapped = unwrap_zone_key(&sk, &zone_id, &back.wrapped_keys[0]).unwrap();
        assert_eq!(unwrapped, zone_key);
    }

    /// Verify that `unwrap_zone_key` with tampered `issued_at` fails (AAD mismatch).
    #[test]
    fn unwrap_zone_key_tampered_issued_at() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-tamper");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let mut wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        wrapped.issued_at = 1_700_000_001;

        let result = unwrap_zone_key(&sk, &zone_id, &wrapped);
        assert!(
            result.is_err(),
            "tampered issued_at should cause AAD mismatch"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge-case and boundary-condition tests (batch 2)
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify `ZoneKeyId` Display for all-FF bytes.
    #[test]
    fn zone_key_id_display_all_ff() {
        let id = ZoneKeyId::from_bytes([0xFF; 8]);
        assert_eq!(format!("{id}"), "ffffffffffffffff");
    }

    /// Verify `ObjectIdKeyId` Display for all-FF bytes.
    #[test]
    fn object_id_key_id_display_all_ff() {
        let id = ObjectIdKeyId::from_bytes([0xFF; 8]);
        assert_eq!(format!("{id}"), "ffffffffffffffff");
    }

    /// Verify `ZoneKey` single-byte difference causes inequality.
    #[test]
    fn zone_key_single_byte_difference() {
        let mut bytes_a = [0u8; ZONE_KEY_LEN];
        let mut bytes_b = [0u8; ZONE_KEY_LEN];
        bytes_b[ZONE_KEY_LEN - 1] = 1;
        let a = ZoneKey::from_bytes(bytes_a);
        let b = ZoneKey::from_bytes(bytes_b);
        assert_ne!(a, b);

        // First byte differs
        bytes_a[0] = 0xFF;
        let c = ZoneKey::from_bytes(bytes_a);
        assert_ne!(a, c);
    }

    /// Verify that `ObjectIdKey` debug output is redacted.
    #[test]
    fn object_id_key_debug_is_redacted() {
        let key = ObjectIdKey::from_bytes([0x42; 32]);
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("42"));
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("ObjectIdKey"));
    }

    /// Verify `ObjectIdKey` equality and inequality.
    #[test]
    fn object_id_key_equality_and_inequality() {
        let a = ObjectIdKey::from_bytes([0x01; 32]);
        let b = ObjectIdKey::from_bytes([0x01; 32]);
        let c = ObjectIdKey::from_bytes([0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Verify `ObjectIdKey` copy semantics.
    #[test]
    fn object_id_key_copy() {
        let a = ObjectIdKey::from_bytes([0xAB; 32]);
        let b = a;
        assert_eq!(a, b);
    }

    /// Verify `ObjectIdKey` `from_bytes`/`as_bytes` roundtrip.
    #[test]
    fn object_id_key_from_bytes_as_bytes_roundtrip() {
        let bytes = [0x13; 32];
        let key = ObjectIdKey::from_bytes(bytes);
        assert_eq!(*key.as_bytes(), bytes);
    }

    /// Verify `ObjectIdKey` hash consistency.
    #[test]
    fn object_id_key_hash_consistency() {
        use std::collections::HashSet;
        let key = ObjectIdKey::from_bytes([0x77; 32]);
        let mut set = HashSet::new();
        set.insert(key);
        set.insert(key);
        assert_eq!(set.len(), 1);
    }

    /// Verify `ObjectIdKeyId` copy semantics.
    #[test]
    fn object_id_key_id_copy() {
        let a = ObjectIdKeyId::from_bytes([0xFE; 8]);
        let b = a;
        assert_eq!(a, b);
    }

    /// Verify `ZoneKeyRing` `active_zone_key` returns `None` when `active_zone_key_id`
    /// is set to a key ID that was overwritten.
    #[test]
    fn zone_key_ring_active_after_overwrite_still_works() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key_a = ZoneKey::from_bytes([0xAA; ZONE_KEY_LEN]);
        let key_b = ZoneKey::from_bytes([0xBB; ZONE_KEY_LEN]);

        ring.insert_zone_key(key_id, key_a);
        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key_a));

        // Overwrite key value: active key ID stays but value changes
        ring.insert_zone_key(key_id, key_b);
        assert_eq!(ring.active_zone_key(), Some(&key_b));
    }

    /// Verify `ZoneKeyRing` with multiple object id keys and switching.
    #[test]
    fn zone_key_ring_multiple_object_id_keys_switching() {
        let mut ring = ZoneKeyRing::new(ZoneId::private());
        let id1 = ObjectIdKeyId::from_bytes([0x01; 8]);
        let id2 = ObjectIdKeyId::from_bytes([0x02; 8]);
        let id3 = ObjectIdKeyId::from_bytes([0x03; 8]);
        let key1 = ObjectIdKey::from_bytes([0x11; 32]);
        let key2 = ObjectIdKey::from_bytes([0x22; 32]);
        let key3 = ObjectIdKey::from_bytes([0x33; 32]);

        ring.insert_object_id_key(id1, key1);
        ring.insert_object_id_key(id2, key2);
        ring.insert_object_id_key(id3, key3);

        assert!(ring.set_active_object_id_key(id1));
        assert_eq!(ring.active_object_id_key(), Some(&key1));
        assert!(ring.set_active_object_id_key(id3));
        assert_eq!(ring.active_object_id_key(), Some(&key3));
        assert!(ring.set_active_object_id_key(id2));
        assert_eq!(ring.active_object_id_key(), Some(&key2));
    }

    /// Verify manifest serde roundtrip with all optional fields set to None.
    #[test]
    fn zone_key_manifest_serde_no_optional_fields() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-minimal");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_obj = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x02; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_obj],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let json = serde_json::to_string(&manifest).unwrap();
        // Optional None fields should be omitted
        assert!(!json.contains("valid_until"));
        assert!(!json.contains("prev_zone_key_id"));
        assert!(!json.contains("rekey_policy"));

        let back: ZoneKeyManifest = serde_json::from_str(&json).unwrap();
        assert!(back.valid_until.is_none());
        assert!(back.prev_zone_key_id.is_none());
        assert!(back.rekey_policy.is_none());

        // Key still unwraps correctly
        let unwrapped = unwrap_zone_key(&sk, &zone_id, &back.wrapped_keys[0]).unwrap();
        assert_eq!(unwrapped, zone_key);
    }

    /// Verify `wrap_object_id_key` produces different ciphertext on each call.
    #[test]
    fn wrap_object_id_key_nondeterministic() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-obj-nd");
        let issued_at = 1_700_000_000;
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = ObjectIdKey::from_bytes([0x42; 32]);

        let w1 = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let w2 = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();

        // Both decrypt to the same key
        let k1 = unwrap_object_id_key(&sk, &zone_id, &w1).unwrap();
        let k2 = unwrap_object_id_key(&sk, &zone_id, &w2).unwrap();
        assert_eq!(k1, key);
        assert_eq!(k2, key);

        // Ciphertexts differ due to HPKE randomness
        assert_ne!(w1.sealed.ciphertext, w2.sealed.ciphertext);
    }

    /// Verify `unwrap_object_id_key` fails when `issued_at` is tampered.
    #[test]
    fn unwrap_object_id_key_tampered_issued_at() {
        let zone_id = ZoneId::community();
        let node_id = TailscaleNodeId::new("node-obj-tamper");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let mut wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        wrapped.issued_at = 1_700_000_001; // tamper

        let result = unwrap_object_id_key(&sk, &zone_id, &wrapped);
        assert!(
            result.is_err(),
            "tampered issued_at should cause AAD mismatch"
        );
    }

    /// Verify `RekeyPolicy` serde with zero overlap window.
    #[test]
    fn rekey_policy_serde_zero_overlap_window() {
        let rp = RekeyPolicy {
            epoch_ratchet: false,
            overlap_window_secs: Some(0),
            retain_epochs: Some(0),
            rewrap_on_membership_change: false,
            rotate_object_id_key_on_membership_change: false,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let back: RekeyPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.overlap_window_secs, Some(0));
        assert_eq!(back.retain_epochs, Some(0));
    }

    /// Verify `RekeyPolicy` serde with partial fields (only some set).
    #[test]
    fn rekey_policy_serde_partial_fields() {
        let json = r#"{"epoch_ratchet": true, "overlap_window_secs": 1200}"#;
        let rp: RekeyPolicy = serde_json::from_str(json).unwrap();
        assert!(rp.epoch_ratchet);
        assert_eq!(rp.overlap_window_secs, Some(1200));
        assert!(rp.retain_epochs.is_none());
        assert!(!rp.rewrap_on_membership_change);
        assert!(!rp.rotate_object_id_key_on_membership_change);
    }

    /// Verify `RekeyPolicy` serde with large overlap window.
    #[test]
    fn rekey_policy_large_values() {
        let rp = RekeyPolicy {
            epoch_ratchet: true,
            overlap_window_secs: Some(u64::MAX),
            retain_epochs: Some(u32::MAX),
            rewrap_on_membership_change: true,
            rotate_object_id_key_on_membership_change: true,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let back: RekeyPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.overlap_window_secs, Some(u64::MAX));
        assert_eq!(back.retain_epochs, Some(u32::MAX));
    }

    /// Verify `ZoneKeyAlgorithm` serde rejects invalid string.
    #[test]
    fn zone_key_algorithm_serde_rejects_invalid() {
        let result: Result<ZoneKeyAlgorithm, _> = serde_json::from_str(r#""invalid_algo""#);
        assert!(result.is_err());
    }

    /// Verify `ZoneKeyManifest` clone preserves all fields.
    #[test]
    fn zone_key_manifest_clone_preserves_fields() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-clone");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();
        let obj_key = random_object_id_key();

        let wrapped_zone = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();
        let wrapped_obj = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &obj_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x02; 8]),
            algorithm: ZoneKeyAlgorithm::XChaCha20Poly1305,
            valid_from: issued_at,
            valid_until: Some(1_700_100_000),
            prev_zone_key_id: Some(ZoneKeyId::from_bytes([0x99; 8])),
            wrapped_keys: vec![wrapped_zone],
            wrapped_object_id_keys: vec![wrapped_obj],
            rekey_policy: Some(RekeyPolicy {
                epoch_ratchet: true,
                overlap_window_secs: Some(300),
                retain_epochs: Some(2),
                rewrap_on_membership_change: true,
                rotate_object_id_key_on_membership_change: false,
            }),
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        let cloned = manifest.clone();
        assert_eq!(cloned.zone_id, manifest.zone_id);
        assert_eq!(cloned.zone_key_id, manifest.zone_key_id);
        assert_eq!(cloned.object_id_key_id, manifest.object_id_key_id);
        assert_eq!(cloned.algorithm, manifest.algorithm);
        assert_eq!(cloned.valid_from, manifest.valid_from);
        assert_eq!(cloned.valid_until, manifest.valid_until);
        assert_eq!(cloned.prev_zone_key_id, manifest.prev_zone_key_id);
        assert_eq!(cloned.wrapped_keys.len(), manifest.wrapped_keys.len());
        assert_eq!(
            cloned.wrapped_object_id_keys.len(),
            manifest.wrapped_object_id_keys.len()
        );
        assert!(cloned.rekey_policy.is_some());
    }

    /// Verify `ZoneKeyManifest` debug output contains type name.
    #[test]
    fn zone_key_manifest_debug_output() {
        let zone_id = ZoneId::work();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let manifest = ZoneKeyManifest::new_empty(zone_id, 1_700_000_000, &signing_key).unwrap();
        let dbg = format!("{manifest:?}");
        assert!(dbg.contains("ZoneKeyManifest"));
        assert!(dbg.contains("zone_key_id"));
    }

    /// Verify `ZoneKeyError` Debug format for each variant.
    #[test]
    fn zone_key_error_debug_format_all_variants() {
        let err1 = ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        };
        let dbg1 = format!("{err1:?}");
        assert!(dbg1.contains("InvalidKeyLength"));

        let err2 = ZoneKeyError::ZoneIdMismatch {
            expected: "z:work".into(),
            found: "z:private".into(),
        };
        let dbg2 = format!("{err2:?}");
        assert!(dbg2.contains("ZoneIdMismatch"));

        let err3 = ZoneKeyError::MissingWrappedZoneKey {
            node_id: "n1".into(),
        };
        let dbg3 = format!("{err3:?}");
        assert!(dbg3.contains("MissingWrappedZoneKey"));

        let err4 = ZoneKeyError::MissingWrappedObjectIdKey {
            node_id: "n2".into(),
        };
        let dbg4 = format!("{err4:?}");
        assert!(dbg4.contains("MissingWrappedObjectIdKey"));
    }

    /// Verify `WrappedObjectIdKey` debug output includes relevant information.
    #[test]
    fn wrapped_object_id_key_debug() {
        let zone_id = ZoneId::private();
        let node_id = TailscaleNodeId::new("node-obj-dbg");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let key = random_object_id_key();

        let wrapped = wrap_object_id_key(&pk, &zone_id, &node_id, issued_at, &key).unwrap();
        let dbg = format!("{wrapped:?}");
        assert!(dbg.contains("WrappedObjectIdKey"));
        assert!(dbg.contains("node-obj-dbg"));
    }

    /// Verify wrap/unwrap with different `issued_at` values produce different AADs.
    #[test]
    fn wrap_unwrap_different_issued_at() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-ts");
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let issued_at_1 = 1_700_000_000;
        let issued_at_2 = 1_700_000_001;

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_1, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_2, &zone_key).unwrap();

        // Each can be unwrapped only with matching issued_at (embedded in AAD)
        let k1 = unwrap_zone_key(&sk, &zone_id, &w1).unwrap();
        let k2 = unwrap_zone_key(&sk, &zone_id, &w2).unwrap();
        assert_eq!(k1, zone_key);
        assert_eq!(k2, zone_key);
    }

    /// Verify `ZoneKeyRing` with community zone type.
    #[test]
    fn zone_key_ring_community_zone() {
        let ring = ZoneKeyRing::new(ZoneId::community());
        assert_eq!(ring.zone_id, ZoneId::community());
        assert!(ring.active_zone_key().is_none());
    }

    /// Verify `ZoneKeyRing` with public zone type.
    #[test]
    fn zone_key_ring_public_zone() {
        let ring = ZoneKeyRing::new(ZoneId::public());
        assert_eq!(ring.zone_id, ZoneId::public());
        assert!(ring.active_object_id_key().is_none());
    }

    /// Verify `ZoneKeyRing` with owner zone type.
    #[test]
    fn zone_key_ring_owner_zone() {
        let mut ring = ZoneKeyRing::new(ZoneId::owner());
        assert_eq!(ring.zone_id, ZoneId::owner());
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key = random_zone_key();
        ring.insert_zone_key(key_id, key);
        assert!(ring.set_active_zone_key(key_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    /// Verify manifest with all five zone types can be created via `new_empty`.
    #[test]
    fn zone_key_manifest_new_empty_all_zone_types() {
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        for zone_id in [
            ZoneId::owner(),
            ZoneId::private(),
            ZoneId::work(),
            ZoneId::community(),
            ZoneId::public(),
        ] {
            let manifest = ZoneKeyManifest::new_empty(zone_id.clone(), 100, &signing_key).unwrap();
            assert_eq!(manifest.zone_id, zone_id);
        }
    }

    /// Verify `ZoneKeyId` `from_bytes`/`as_bytes` roundtrip with alternating bytes.
    #[test]
    fn zone_key_id_from_bytes_as_bytes_alternating() {
        let bytes = [0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55];
        let id = ZoneKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
        assert_eq!(format!("{id}"), "aa55aa55aa55aa55");
    }

    /// Verify `ObjectIdKeyId` `from_bytes`/`as_bytes` roundtrip with sequential bytes.
    #[test]
    fn object_id_key_id_from_bytes_as_bytes_sequential() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let id = ObjectIdKeyId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
        assert_eq!(format!("{id}"), "0102030405060708");
    }

    /// Verify `ZoneKeyRing` debug output includes `zone_id` when keys are present.
    #[test]
    fn zone_key_ring_debug_with_keys() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let key_id = ZoneKeyId::from_bytes([0x42; 8]);
        ring.insert_zone_key(key_id, random_zone_key());
        let dbg = format!("{ring:?}");
        assert!(dbg.contains("ZoneKeyRing"));
        assert!(dbg.contains("z:work"));
    }

    /// Verify that `set_active_zone_key` preserves pre-existing `active_object_id_key_id`.
    #[test]
    fn set_active_zone_key_preserves_object_id_key_state() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let zone_key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let obj_key_id = ObjectIdKeyId::from_bytes([0x02; 8]);

        ring.insert_zone_key(zone_key_id, random_zone_key());
        ring.insert_object_id_key(obj_key_id, random_object_id_key());

        assert!(ring.set_active_object_id_key(obj_key_id));
        assert!(ring.set_active_zone_key(zone_key_id));

        // Both actives should be set
        assert_eq!(ring.active_zone_key_id, Some(zone_key_id));
        assert_eq!(ring.active_object_id_key_id, Some(obj_key_id));
    }

    /// Verify that unwrap with wrong key returns Crypto variant error.
    #[test]
    fn unwrap_zone_key_wrong_sk_returns_crypto_error() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-ce");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let bad_sk = X25519SecretKey::generate();

        let zone_key = random_zone_key();
        let wrapped = wrap_zone_key(&pk, &zone_id, &node_id, issued_at, &zone_key).unwrap();

        let err = unwrap_zone_key(&bad_sk, &zone_id, &wrapped).expect_err("should fail");
        assert!(matches!(err, ZoneKeyError::Crypto(_)));
    }

    /// Verify `ZoneKeyId` serde roundtrip preserves exact bytes for boundary values.
    #[test]
    fn zone_key_id_serde_boundary_bytes() {
        for bytes in [
            [0x00; 8],
            [0xFF; 8],
            [0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF],
        ] {
            let id = ZoneKeyId::from_bytes(bytes);
            let json = serde_json::to_string(&id).unwrap();
            let back: ZoneKeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
            assert_eq!(*back.as_bytes(), bytes);
        }
    }

    /// Verify `ObjectIdKeyId` serde roundtrip preserves exact bytes for boundary values.
    #[test]
    fn object_id_key_id_serde_boundary_bytes() {
        for bytes in [
            [0x00; 8],
            [0xFF; 8],
            [0x80, 0x7F, 0x01, 0xFE, 0x00, 0xFF, 0x55, 0xAA],
        ] {
            let id = ObjectIdKeyId::from_bytes(bytes);
            let json = serde_json::to_string(&id).unwrap();
            let back: ObjectIdKeyId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
            assert_eq!(*back.as_bytes(), bytes);
        }
    }

    /// Verify `ZONE_KEY_LEN` matches the expected 32-byte `ChaCha20` key size.
    #[test]
    fn zone_key_len_matches_key_construction() {
        let key = ZoneKey::from_bytes([0u8; ZONE_KEY_LEN]);
        assert_eq!(key.as_bytes().len(), ZONE_KEY_LEN);
        assert_eq!(key.as_bytes().len(), 32);
    }

    /// Verify that `wrapped_key_for` returns the first matching entry when duplicates exist.
    #[test]
    fn wrapped_key_for_returns_first_match() {
        let zone_id = ZoneId::work();
        let node_id = TailscaleNodeId::new("node-dup");
        let issued_at_a = 1_700_000_000;
        let issued_at_b = 1_700_000_001;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let w1 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_a, &zone_key).unwrap();
        let w2 = wrap_zone_key(&pk, &zone_id, &node_id, issued_at_b, &zone_key).unwrap();

        let manifest = ZoneKeyManifest {
            header: test_header(&zone_id),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x01; 8]),
            object_id_key_id: ObjectIdKeyId::from_bytes([0x11; 8]),
            algorithm: ZoneKeyAlgorithm::ChaCha20Poly1305,
            valid_from: issued_at_a,
            valid_until: None,
            prev_zone_key_id: None,
            wrapped_keys: vec![w1, w2],
            wrapped_object_id_keys: vec![],
            rekey_policy: None,
            signature: test_signature(),
            kem: ZoneKemAlgorithm::HpkeX25519,
            wrapped_keys_v4: vec![],
        };

        // Should return the first match (issued_at_a)
        let found = manifest.wrapped_key_for(&node_id).unwrap();
        assert_eq!(found.issued_at, issued_at_a);
    }

    /// Verify `ZoneKeyRing` does not change state on failed `set_active_zone_key`.
    #[test]
    fn zone_key_ring_set_active_failure_preserves_state() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let good_id = ZoneKeyId::from_bytes([0x01; 8]);
        let bad_id = ZoneKeyId::from_bytes([0x02; 8]);
        let key = random_zone_key();

        ring.insert_zone_key(good_id, key);
        assert!(ring.set_active_zone_key(good_id));

        // Attempt to set to unknown key
        assert!(!ring.set_active_zone_key(bad_id));

        // Active should still be good_id
        assert_eq!(ring.active_zone_key_id, Some(good_id));
        assert_eq!(ring.active_zone_key(), Some(&key));
    }

    /// Verify `ZoneKeyRing` does not change state on failed `set_active_object_id_key`.
    #[test]
    fn zone_key_ring_set_active_object_id_key_failure_preserves_state() {
        let mut ring = ZoneKeyRing::new(ZoneId::work());
        let good_id = ObjectIdKeyId::from_bytes([0x01; 8]);
        let bad_id = ObjectIdKeyId::from_bytes([0x02; 8]);
        let key = random_object_id_key();

        ring.insert_object_id_key(good_id, key);
        assert!(ring.set_active_object_id_key(good_id));

        // Attempt to set to unknown key
        assert!(!ring.set_active_object_id_key(bad_id));

        // Active should still be good_id
        assert_eq!(ring.active_object_id_key_id, Some(good_id));
        assert_eq!(ring.active_object_id_key(), Some(&key));
    }

    /// Verify that multiple different zone key rings are independent.
    #[test]
    fn zone_key_rings_are_independent() {
        let key_id = ZoneKeyId::from_bytes([0x01; 8]);
        let key = random_zone_key();

        let mut ring1 = ZoneKeyRing::new(ZoneId::work());
        let mut ring2 = ZoneKeyRing::new(ZoneId::private());

        ring1.insert_zone_key(key_id, key);
        assert!(ring1.set_active_zone_key(key_id));

        // ring2 should be unaffected
        assert!(ring2.active_zone_key().is_none());
        assert!(ring2.zone_key(&key_id).is_none());
        assert!(!ring2.set_active_zone_key(key_id));
    }

    /// Verify that different zone types produce distinct zone IDs that affect wrapping.
    #[test]
    fn different_zone_types_produce_distinct_aad() {
        let node_id = TailscaleNodeId::new("node-zones");
        let issued_at = 1_700_000_000;

        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let zone_key = random_zone_key();

        let wrapped_work =
            wrap_zone_key(&pk, &ZoneId::work(), &node_id, issued_at, &zone_key).unwrap();
        let wrapped_private =
            wrap_zone_key(&pk, &ZoneId::private(), &node_id, issued_at, &zone_key).unwrap();

        // Both should unwrap correctly under their own zone_id
        let k_work = unwrap_zone_key(&sk, &ZoneId::work(), &wrapped_work).unwrap();
        let k_priv = unwrap_zone_key(&sk, &ZoneId::private(), &wrapped_private).unwrap();
        assert_eq!(k_work, zone_key);
        assert_eq!(k_priv, zone_key);

        // Cross-zone unwrap should fail
        let result = unwrap_zone_key(&sk, &ZoneId::private(), &wrapped_work);
        assert!(result.is_err());
    }
}
