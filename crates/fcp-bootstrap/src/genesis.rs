//! Genesis state for FCP2 meshes.
//!
//! The genesis state is the initial state of an FCP2 mesh, created during the
//! bootstrap process. It contains the owner's public key, initial zones, and
//! the cryptographic fingerprint that identifies this mesh.

use chrono::{DateTime, Utc};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// A genesis state representing the initial state of an FCP2 mesh.
///
/// The genesis state is deterministically derived from the owner's public key,
/// ensuring that the same owner key will always produce the same genesis
/// fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisState {
    /// Schema version for the genesis format.
    pub schema_version: u32,

    /// The owner's public key (Ed25519).
    #[serde(with = "hex::serde")]
    pub owner_public_key: [u8; 32],

    /// The time this genesis was created.
    pub created_at: DateTime<Utc>,

    /// Initial zone definitions (typically z:owner, z:private, z:work, z:community, z:public).
    pub initial_zones: Vec<InitialZone>,

    /// The genesis fingerprint (computed, not stored).
    #[serde(skip)]
    #[allow(dead_code)]
    fingerprint_cache: Option<String>,
}

/// An initial zone definition in the genesis state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialZone {
    /// Zone ID (e.g., "z:owner", "z:private").
    pub zone_id: String,

    /// Human-readable name for the zone.
    pub name: String,

    /// Integrity level (higher = more sensitive).
    pub integrity_level: u8,

    /// Confidentiality level (higher = more restricted).
    pub confidentiality_level: u8,
}

/// Errors during genesis validation.
#[derive(Debug, Error)]
pub enum GenesisValidationError {
    /// Invalid owner public key.
    #[error("invalid owner public key")]
    InvalidOwnerKey,

    /// Missing required zone.
    #[error("missing required zone: {0}")]
    MissingRequiredZone(String),

    /// Invalid zone ID format.
    #[error("invalid zone ID format: {0}")]
    InvalidZoneId(String),

    /// Genesis timestamp is in the future.
    #[error("genesis timestamp is in the future")]
    FutureTimestamp,

    /// Invalid schema version.
    #[error("unsupported schema version: {0}")]
    UnsupportedSchemaVersion(u32),
}

/// Current schema version for genesis states.
pub const GENESIS_SCHEMA_VERSION: u32 = 1;

/// Required zones that must be present in genesis.
pub const REQUIRED_ZONES: &[&str] = &["z:owner", "z:private", "z:work", "z:community", "z:public"];

impl GenesisState {
    /// Create a new genesis state from an owner's public key.
    ///
    /// This creates the standard FCP2 zone hierarchy with default integrity
    /// and confidentiality levels.
    #[must_use]
    pub fn create(owner_public_key: &Ed25519VerifyingKey) -> Self {
        let initial_zones = vec![
            InitialZone {
                zone_id: "z:owner".to_string(),
                name: "Owner Zone".to_string(),
                integrity_level: 255,
                confidentiality_level: 255,
            },
            InitialZone {
                zone_id: "z:private".to_string(),
                name: "Private Zone".to_string(),
                integrity_level: 200,
                confidentiality_level: 200,
            },
            InitialZone {
                zone_id: "z:work".to_string(),
                name: "Work Zone".to_string(),
                integrity_level: 150,
                confidentiality_level: 150,
            },
            InitialZone {
                zone_id: "z:community".to_string(),
                name: "Community Zone".to_string(),
                integrity_level: 100,
                confidentiality_level: 100,
            },
            InitialZone {
                zone_id: "z:public".to_string(),
                name: "Public Zone".to_string(),
                integrity_level: 50,
                confidentiality_level: 0,
            },
        ];

        Self {
            schema_version: GENESIS_SCHEMA_VERSION,
            owner_public_key: owner_public_key.to_bytes(),
            created_at: Utc::now(),
            initial_zones,
            fingerprint_cache: None,
        }
    }

    /// Create a genesis state for cold recovery (deterministic creation time).
    ///
    /// Used during cold recovery when we need to recreate a genesis with
    /// a predictable fingerprint.
    ///
    /// # Panics
    ///
    /// Panics if the Unix epoch timestamp cannot be constructed (should never happen).
    #[must_use]
    pub fn create_deterministic(owner_public_key: &Ed25519VerifyingKey) -> Self {
        // For deterministic recreation, use epoch as the timestamp.
        // The fingerprint is based on the owner key, so this ensures
        // the same owner key always produces the same fingerprint.
        let mut genesis = Self::create(owner_public_key);
        genesis.created_at = DateTime::from_timestamp(0, 0).expect("epoch is valid");
        genesis
    }

    /// Compute the fingerprint of this genesis state.
    ///
    /// The fingerprint is a stable identifier for the mesh, computed as:
    /// `SHA256:base64(blake3(owner_public_key || schema_version))`
    #[must_use]
    pub fn fingerprint(&self) -> String {
        // Compute fingerprint from owner key and schema version
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.owner_public_key);
        hasher.update(&self.schema_version.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Use first 12 bytes for a shorter fingerprint
        let short_hash = &hash_bytes[..12];
        let b64 = base64_encode(short_hash);

        format!("SHA256:{b64}")
    }

    /// Validate this genesis state.
    ///
    /// # Errors
    ///
    /// Returns a validation error if any required field is invalid or missing.
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check schema version
        if self.schema_version != GENESIS_SCHEMA_VERSION {
            return Err(GenesisValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }

        // Check owner key is valid
        if Ed25519VerifyingKey::from_bytes(&self.owner_public_key).is_err() {
            return Err(GenesisValidationError::InvalidOwnerKey);
        }

        // Check timestamp is not in the future (allow 5 minute tolerance)
        let now = Utc::now();
        let tolerance = chrono::Duration::minutes(5);
        if self.created_at > now + tolerance {
            return Err(GenesisValidationError::FutureTimestamp);
        }

        // Check all required zones are present
        for required_zone in REQUIRED_ZONES {
            if !self
                .initial_zones
                .iter()
                .any(|z| z.zone_id == *required_zone)
            {
                return Err(GenesisValidationError::MissingRequiredZone(
                    (*required_zone).to_string(),
                ));
            }
        }

        // Validate zone ID formats
        for zone in &self.initial_zones {
            if !zone.zone_id.starts_with("z:") {
                return Err(GenesisValidationError::InvalidZoneId(zone.zone_id.clone()));
            }
        }

        Ok(())
    }

    /// Get the owner's public key as a verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored public key is invalid.
    pub fn owner_verifying_key(&self) -> Result<Ed25519VerifyingKey, GenesisValidationError> {
        Ed25519VerifyingKey::from_bytes(&self.owner_public_key)
            .map_err(|_| GenesisValidationError::InvalidOwnerKey)
    }

    /// Serialize the genesis state to canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if CBOR serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, crate::error::BootstrapError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserialize a genesis state from CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if CBOR deserialization fails.
    pub fn from_cbor(data: &[u8]) -> Result<Self, crate::error::BootstrapError> {
        let genesis: Self = ciborium::from_reader(data)?;
        Ok(genesis)
    }
}

/// Owner keypair with zeroization on drop.
#[derive(ZeroizeOnDrop)]
pub struct OwnerKeypair {
    /// The signing key (private).
    signing_key: Ed25519SigningKey,
}

impl OwnerKeypair {
    /// Create a new owner keypair from a signing key.
    #[must_use]
    pub const fn new(signing_key: Ed25519SigningKey) -> Self {
        Self { signing_key }
    }

    /// Get the verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign data with the owner key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> fcp_crypto::Ed25519Signature {
        self.signing_key.sign(message)
    }
}

impl std::fmt::Debug for OwnerKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerKeypair")
            .field("public_key", &hex::encode(self.verifying_key().to_bytes()))
            .finish_non_exhaustive()
    }
}

/// Base64 URL-safe encoding without padding.
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_creation() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let genesis = GenesisState::create(&verifying_key);

        assert_eq!(genesis.schema_version, GENESIS_SCHEMA_VERSION);
        assert_eq!(genesis.owner_public_key, verifying_key.to_bytes());
        assert_eq!(genesis.initial_zones.len(), 5);
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn test_genesis_fingerprint_deterministic() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let genesis1 = GenesisState::create_deterministic(&verifying_key);
        let genesis2 = GenesisState::create_deterministic(&verifying_key);

        assert_eq!(genesis1.fingerprint(), genesis2.fingerprint());
    }

    #[test]
    fn test_genesis_cbor_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let genesis = GenesisState::create(&verifying_key);
        let cbor = genesis.to_cbor().unwrap();
        let restored = GenesisState::from_cbor(&cbor).unwrap();

        assert_eq!(genesis.fingerprint(), restored.fingerprint());
        assert_eq!(genesis.owner_public_key, restored.owner_public_key);
    }

    #[test]
    fn test_genesis_validation_missing_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut genesis = GenesisState::create(&verifying_key);
        genesis.initial_zones.retain(|z| z.zone_id != "z:owner");

        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(_))
        ));
    }

    // ---- Validation edge cases ----

    #[test]
    fn genesis_validation_rejects_wrong_schema_version() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.schema_version = 99;
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::UnsupportedSchemaVersion(99))
        ));
    }

    #[test]
    fn genesis_validation_rejects_invalid_owner_key() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.owner_public_key = [0xFF; 32]; // not a valid Ed25519 compressed point
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::InvalidOwnerKey)
        ));
    }

    #[test]
    fn genesis_validation_rejects_future_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.created_at = Utc::now() + chrono::Duration::hours(1);
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::FutureTimestamp)
        ));
    }

    #[test]
    fn genesis_validation_rejects_invalid_zone_id_format() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.initial_zones.push(InitialZone {
            zone_id: "bad_zone".to_string(),
            name: "Bad Zone".to_string(),
            integrity_level: 0,
            confidentiality_level: 0,
        });
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::InvalidZoneId(_))
        ));
    }

    // ---- Each required zone triggers MissingRequiredZone ----

    #[test]
    fn genesis_validation_missing_each_required_zone() {
        for required in REQUIRED_ZONES {
            let signing_key = Ed25519SigningKey::generate();
            let verifying_key = signing_key.verifying_key();
            let mut genesis = GenesisState::create(&verifying_key);
            genesis.initial_zones.retain(|z| z.zone_id != *required);
            let result = genesis.validate();
            assert!(
                matches!(result, Err(GenesisValidationError::MissingRequiredZone(ref z)) if z == required),
                "Expected MissingRequiredZone for {required}"
            );
        }
    }

    // ---- Fingerprint properties ----

    #[test]
    fn genesis_fingerprint_starts_with_sha256() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let genesis = GenesisState::create(&verifying_key);
        assert!(genesis.fingerprint().starts_with("SHA256:"));
    }

    #[test]
    fn genesis_different_keys_different_fingerprints() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let g1 = GenesisState::create(&key1.verifying_key());
        let g2 = GenesisState::create(&key2.verifying_key());
        assert_ne!(g1.fingerprint(), g2.fingerprint());
    }

    // ---- Zone hierarchy ----

    #[test]
    fn genesis_zone_integrity_levels_are_descending() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let levels: Vec<u8> = genesis.initial_zones.iter().map(|z| z.integrity_level).collect();
        // z:owner=255, z:private=200, z:work=150, z:community=100, z:public=50
        for w in levels.windows(2) {
            assert!(w[0] > w[1], "integrity levels should be strictly descending");
        }
    }

    #[test]
    fn genesis_has_5_initial_zones() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        assert_eq!(genesis.initial_zones.len(), 5);
    }

    // ---- Deterministic genesis ----

    #[test]
    fn genesis_deterministic_has_epoch_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create_deterministic(&signing_key.verifying_key());
        assert_eq!(
            genesis.created_at,
            DateTime::from_timestamp(0, 0).unwrap()
        );
    }

    // ---- owner_verifying_key ----

    #[test]
    fn genesis_owner_verifying_key_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let genesis = GenesisState::create(&verifying_key);
        let recovered = genesis.owner_verifying_key().unwrap();
        assert_eq!(recovered.to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn genesis_owner_verifying_key_invalid() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.owner_public_key = [0xFF; 32]; // not a valid Ed25519 compressed point
        assert!(matches!(
            genesis.owner_verifying_key(),
            Err(GenesisValidationError::InvalidOwnerKey)
        ));
    }

    // ---- OwnerKeypair ----

    #[test]
    fn owner_keypair_debug_does_not_leak_private_key() {
        let signing_key = Ed25519SigningKey::generate();
        let keypair = super::OwnerKeypair::new(signing_key);
        let debug = format!("{keypair:?}");
        assert!(debug.contains("OwnerKeypair"));
        assert!(debug.contains("public_key"));
        // Should not contain "signing_key" or raw bytes
        assert!(!debug.contains("signing_key"));
    }

    #[test]
    fn owner_keypair_sign_produces_valid_signature() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let keypair = super::OwnerKeypair::new(signing_key);
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }
}
