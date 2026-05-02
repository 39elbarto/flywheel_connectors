//! Backing stores for V3/V4 compatibility ledgers.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fcp_cbor::to_canonical_cbor;
use fcp_evidence::{
    CompatibilityLedgerError, CompatibilityLedgerRoot, CompatibilityLedgerTrustAnchors,
    MeshCompatibilityLedger, MlDsa65LedgerVerifier,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Persistence API for signed compatibility ledgers.
pub trait CompatibilityLedgerStore: Send + Sync {
    /// Persist a ledger and return its root.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerStoreError`] if the ledger is malformed,
    /// rolls back the latest accepted epoch, or does not chain to the current root.
    fn put_ledger(
        &self,
        ledger: MeshCompatibilityLedger,
    ) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerStoreError>;

    /// Verify both signature halves, then persist the ledger.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerStoreError`] if signature verification or
    /// storage validation fails.
    fn put_verified_ledger(
        &self,
        ledger: MeshCompatibilityLedger,
        trust_anchors: &CompatibilityLedgerTrustAnchors,
        ml_dsa_verifier: &impl MlDsa65LedgerVerifier,
    ) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerStoreError> {
        ledger
            .verify_hybrid_signatures(trust_anchors, ml_dsa_verifier)
            .map_err(CompatibilityLedgerStoreError::Verification)?;
        self.put_ledger(ledger)
    }

    /// Fetch a ledger by root.
    fn get_ledger(&self, root: &CompatibilityLedgerRoot) -> Option<MeshCompatibilityLedger>;

    /// Fetch the latest ledger accepted for a mesh.
    fn latest_ledger(&self, mesh_id: &str) -> Option<MeshCompatibilityLedger>;
}

/// In-memory compatibility-ledger backing store.
#[derive(Debug, Default)]
pub struct MemoryCompatibilityLedgerStore {
    state: RwLock<CompatibilityLedgerState>,
}

#[derive(Debug, Default)]
struct CompatibilityLedgerState {
    ledgers: BTreeMap<CompatibilityLedgerRoot, MeshCompatibilityLedger>,
    latest_by_mesh: BTreeMap<String, CompatibilityLedgerRoot>,
}

impl MemoryCompatibilityLedgerStore {
    /// Construct an empty memory-backed ledger store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl CompatibilityLedgerStore for MemoryCompatibilityLedgerStore {
    fn put_ledger(
        &self,
        ledger: MeshCompatibilityLedger,
    ) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerStoreError> {
        let root = ledger
            .ledger_root()
            .map_err(CompatibilityLedgerStoreError::Ledger)?;
        let mesh_id = ledger.mesh_id().to_owned();

        let mut state = self.state.write();
        if state.ledgers.contains_key(&root) {
            state.latest_by_mesh.entry(mesh_id).or_insert(root);
            return Ok(root);
        }

        state.validate_next(&ledger, root, &mesh_id)?;
        state.insert_accepted(root, mesh_id, ledger);
        Ok(root)
    }

    fn get_ledger(&self, root: &CompatibilityLedgerRoot) -> Option<MeshCompatibilityLedger> {
        self.state.read().ledgers.get(root).cloned()
    }

    fn latest_ledger(&self, mesh_id: &str) -> Option<MeshCompatibilityLedger> {
        let state = self.state.read();
        let root = state.latest_by_mesh.get(mesh_id)?;
        state.ledgers.get(root).cloned()
    }
}

/// Filesystem-backed compatibility-ledger store.
///
/// Signed ledgers are stored as canonical CBOR under their ledger root, while a
/// separate canonical pointer records the latest accepted root for each mesh.
#[derive(Debug)]
pub struct DurableCompatibilityLedgerStore {
    ledger_dir: PathBuf,
    latest_dir: PathBuf,
    state: RwLock<CompatibilityLedgerState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LatestLedgerPointer {
    mesh_id: String,
    root: CompatibilityLedgerRoot,
}

impl DurableCompatibilityLedgerStore {
    /// Open or create a filesystem-backed compatibility-ledger store.
    ///
    /// # Errors
    /// Returns [`CompatibilityLedgerStoreError`] if the directory cannot be
    /// initialized or an existing ledger/pointer file cannot be decoded.
    pub fn open(root_dir: impl AsRef<Path>) -> Result<Self, CompatibilityLedgerStoreError> {
        let root_dir = root_dir.as_ref().to_path_buf();
        let ledger_dir = root_dir.join("ledgers");
        let latest_dir = root_dir.join("latest");
        fs::create_dir_all(&ledger_dir).map_err(|source| {
            CompatibilityLedgerStoreError::StorageIo {
                path: ledger_dir.clone(),
                message: source.to_string(),
            }
        })?;
        fs::create_dir_all(&latest_dir).map_err(|source| {
            CompatibilityLedgerStoreError::StorageIo {
                path: latest_dir.clone(),
                message: source.to_string(),
            }
        })?;

        let mut state = CompatibilityLedgerState::default();
        load_ledger_files(&ledger_dir, &mut state)?;
        load_latest_pointers(&latest_dir, &mut state)?;

        Ok(Self {
            ledger_dir,
            latest_dir,
            state: RwLock::new(state),
        })
    }

    fn ledger_path(&self, root: CompatibilityLedgerRoot) -> PathBuf {
        self.ledger_dir.join(format!("{root}.cbor"))
    }

    fn latest_path(mesh_id: &str, latest_dir: &Path) -> PathBuf {
        let digest = blake3::hash(mesh_id.as_bytes());
        latest_dir.join(format!("{}.latest.cbor", digest.to_hex()))
    }

    fn persist_ledger(
        &self,
        root: CompatibilityLedgerRoot,
        ledger: &MeshCompatibilityLedger,
    ) -> Result<(), CompatibilityLedgerStoreError> {
        let path = self.ledger_path(root);
        if path.exists() {
            return Ok(());
        }
        let bytes = ledger
            .to_canonical_cbor()
            .map_err(CompatibilityLedgerStoreError::Ledger)?;
        write_new_file(&path, &bytes)
    }

    fn persist_latest_pointer(
        &self,
        mesh_id: &str,
        root: CompatibilityLedgerRoot,
    ) -> Result<(), CompatibilityLedgerStoreError> {
        let pointer = LatestLedgerPointer {
            mesh_id: mesh_id.to_owned(),
            root,
        };
        let bytes = to_canonical_cbor(&pointer)
            .map_err(|err| CompatibilityLedgerStoreError::Ledger(err.into()))?;
        let path = Self::latest_path(mesh_id, &self.latest_dir);
        fs::write(&path, bytes).map_err(|source| CompatibilityLedgerStoreError::StorageIo {
            path,
            message: source.to_string(),
        })
    }
}

impl CompatibilityLedgerStore for DurableCompatibilityLedgerStore {
    fn put_ledger(
        &self,
        ledger: MeshCompatibilityLedger,
    ) -> Result<CompatibilityLedgerRoot, CompatibilityLedgerStoreError> {
        let root = ledger
            .ledger_root()
            .map_err(CompatibilityLedgerStoreError::Ledger)?;
        let mesh_id = ledger.mesh_id().to_owned();

        {
            let state = self.state.read();
            if state.ledgers.contains_key(&root) {
                drop(state);
                self.persist_latest_pointer(&mesh_id, root)?;
                self.state.write().latest_by_mesh.insert(mesh_id, root);
                return Ok(root);
            }
            state.validate_next(&ledger, root, &mesh_id)?;
        }

        self.persist_ledger(root, &ledger)?;
        self.persist_latest_pointer(&mesh_id, root)?;

        self.state.write().insert_accepted(root, mesh_id, ledger);
        Ok(root)
    }

    fn get_ledger(&self, root: &CompatibilityLedgerRoot) -> Option<MeshCompatibilityLedger> {
        self.state.read().ledgers.get(root).cloned()
    }

    fn latest_ledger(&self, mesh_id: &str) -> Option<MeshCompatibilityLedger> {
        let state = self.state.read();
        let root = state.latest_by_mesh.get(mesh_id)?;
        state.ledgers.get(root).cloned()
    }
}

impl CompatibilityLedgerState {
    fn validate_next(
        &self,
        ledger: &MeshCompatibilityLedger,
        root: CompatibilityLedgerRoot,
        mesh_id: &str,
    ) -> Result<(), CompatibilityLedgerStoreError> {
        if let Some(existing) = self.ledgers.get(&root) {
            if existing == ledger {
                return Ok(());
            }
            return Err(CompatibilityLedgerStoreError::RootCollision {
                root: root.to_string(),
            });
        }

        if let Some(latest_root) = self.latest_by_mesh.get(mesh_id).copied() {
            let latest = self.ledgers.get(&latest_root).ok_or(
                CompatibilityLedgerStoreError::MissingLatestLedger {
                    mesh_id: mesh_id.to_owned(),
                    latest_root: latest_root.to_string(),
                },
            )?;
            if ledger.epoch() <= latest.epoch() {
                return Err(CompatibilityLedgerStoreError::EpochRollback {
                    mesh_id: mesh_id.to_owned(),
                    latest_epoch: latest.epoch(),
                    attempted_epoch: ledger.epoch(),
                });
            }
            if ledger.previous_root() != Some(latest_root) {
                return Err(CompatibilityLedgerStoreError::PreviousRootMismatch {
                    mesh_id: mesh_id.to_owned(),
                    expected: Some(latest_root.to_string()),
                    observed: ledger.previous_root().map(|root| root.to_string()),
                });
            }
        } else if ledger.previous_root().is_some() {
            return Err(CompatibilityLedgerStoreError::PreviousRootMismatch {
                mesh_id: mesh_id.to_owned(),
                expected: None,
                observed: ledger.previous_root().map(|root| root.to_string()),
            });
        }

        Ok(())
    }

    fn insert_accepted(
        &mut self,
        root: CompatibilityLedgerRoot,
        mesh_id: String,
        ledger: MeshCompatibilityLedger,
    ) {
        self.ledgers.insert(root, ledger);
        self.latest_by_mesh.insert(mesh_id, root);
    }
}

fn load_ledger_files(
    ledger_dir: &Path,
    state: &mut CompatibilityLedgerState,
) -> Result<(), CompatibilityLedgerStoreError> {
    for entry in read_dir(ledger_dir)? {
        let entry = entry.map_err(|source| CompatibilityLedgerStoreError::StorageIo {
            path: ledger_dir.to_path_buf(),
            message: source.to_string(),
        })?;
        let path = entry.path();
        if !has_extension(&path, "cbor") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|source| CompatibilityLedgerStoreError::StorageIo {
            path: path.clone(),
            message: source.to_string(),
        })?;
        let ledger = MeshCompatibilityLedger::from_canonical_cbor(&bytes).map_err(|error| {
            CompatibilityLedgerStoreError::CorruptLedgerFile {
                path: path.clone(),
                error,
            }
        })?;
        let root = ledger
            .ledger_root()
            .map_err(CompatibilityLedgerStoreError::Ledger)?;
        let expected_name = format!("{root}.cbor");
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            return Err(CompatibilityLedgerStoreError::LedgerFileNameMismatch {
                path,
                expected: expected_name,
                observed_root: root.to_string(),
            });
        }
        state.ledgers.insert(root, ledger);
    }
    Ok(())
}

fn load_latest_pointers(
    latest_dir: &Path,
    state: &mut CompatibilityLedgerState,
) -> Result<(), CompatibilityLedgerStoreError> {
    for entry in read_dir(latest_dir)? {
        let entry = entry.map_err(|source| CompatibilityLedgerStoreError::StorageIo {
            path: latest_dir.to_path_buf(),
            message: source.to_string(),
        })?;
        let path = entry.path();
        if !has_extension(&path, "cbor") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|source| CompatibilityLedgerStoreError::StorageIo {
            path: path.clone(),
            message: source.to_string(),
        })?;
        let pointer: LatestLedgerPointer =
            ciborium::de::from_reader(bytes.as_slice()).map_err(|source| {
                CompatibilityLedgerStoreError::CorruptLatestPointer {
                    path: path.clone(),
                    message: source.to_string(),
                }
            })?;
        let recoded = to_canonical_cbor(&pointer).map_err(|err| {
            CompatibilityLedgerStoreError::Ledger(CompatibilityLedgerError::from(err))
        })?;
        if recoded != bytes {
            return Err(CompatibilityLedgerStoreError::CorruptLatestPointer {
                path,
                message: "latest pointer CBOR is not canonical".to_owned(),
            });
        }
        if !state.ledgers.contains_key(&pointer.root) {
            return Err(CompatibilityLedgerStoreError::MissingLatestLedger {
                mesh_id: pointer.mesh_id,
                latest_root: pointer.root.to_string(),
            });
        }
        state.latest_by_mesh.insert(pointer.mesh_id, pointer.root);
    }
    Ok(())
}

fn read_dir(path: &Path) -> Result<fs::ReadDir, CompatibilityLedgerStoreError> {
    fs::read_dir(path).map_err(|source| CompatibilityLedgerStoreError::StorageIo {
        path: path.to_path_buf(),
        message: source.to_string(),
    })
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CompatibilityLedgerStoreError> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Write as _;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| CompatibilityLedgerStoreError::StorageIo {
                    path: path.to_path_buf(),
                    message: source.to_string(),
                })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(CompatibilityLedgerStoreError::StorageIo {
            path: path.to_path_buf(),
            message: source.to_string(),
        }),
    }
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some(extension)
}

/// Errors returned by the compatibility-ledger backing store.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompatibilityLedgerStoreError {
    /// Ledger canonicalization or root derivation failed.
    #[error("compatibility ledger validation failed: {0}")]
    Ledger(CompatibilityLedgerError),
    /// Signature verification failed before persistence.
    #[error("compatibility ledger signature verification failed: {0}")]
    Verification(CompatibilityLedgerError),
    /// Two different ledgers derived the same root.
    #[error("compatibility ledger root collision at root {root}")]
    RootCollision {
        /// Colliding root.
        root: String,
    },
    /// Attempted to store an older or same-epoch ledger over a newer accepted root.
    #[error(
        "compatibility ledger epoch rollback for mesh {mesh_id}: latest {latest_epoch}, attempted {attempted_epoch}"
    )]
    EpochRollback {
        /// Mesh id.
        mesh_id: String,
        /// Latest accepted epoch.
        latest_epoch: u64,
        /// Attempted epoch.
        attempted_epoch: u64,
    },
    /// New ledger did not chain to the latest accepted root.
    #[error(
        "compatibility ledger previous root mismatch for mesh {mesh_id}: expected {expected:?}, observed {observed:?}"
    )]
    PreviousRootMismatch {
        /// Mesh id.
        mesh_id: String,
        /// Expected previous root, or `None` for genesis.
        expected: Option<String>,
        /// Observed previous root.
        observed: Option<String>,
    },
    /// Latest pointer referenced a root absent from the local map.
    #[error("compatibility ledger latest root {latest_root} for mesh {mesh_id} is missing")]
    MissingLatestLedger {
        /// Mesh id.
        mesh_id: String,
        /// Missing root.
        latest_root: String,
    },
    /// Durable store I/O failed.
    #[error("compatibility ledger durable store I/O failed at {}: {message}", path.display())]
    StorageIo {
        /// Path being accessed.
        path: PathBuf,
        /// I/O error text.
        message: String,
    },
    /// Stored ledger file failed canonical decoding.
    #[error("compatibility ledger file {} is corrupt: {error}", path.display())]
    CorruptLedgerFile {
        /// Path being decoded.
        path: PathBuf,
        /// Decode/canonicalization error.
        error: CompatibilityLedgerError,
    },
    /// Stored ledger filename did not match the decoded root.
    #[error(
        "compatibility ledger file {} has root {observed_root}; expected filename {expected}",
        path.display()
    )]
    LedgerFileNameMismatch {
        /// Path being decoded.
        path: PathBuf,
        /// Expected filename for the decoded root.
        expected: String,
        /// Decoded root.
        observed_root: String,
    },
    /// Latest pointer file failed canonical decoding.
    #[error("compatibility ledger latest pointer {} is corrupt: {message}", path.display())]
    CorruptLatestPointer {
        /// Path being decoded.
        path: PathBuf,
        /// Decode/canonicalization error.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use fcp_crypto::{
        CryptoResult, Ed25519SigningKey, HybridOwnerKeyIds, HybridOwnerSignature,
        MlDsa65SignatureBytes, MlDsa65VerifyingKeyBytes,
    };
    use fcp_evidence::{
        CompatibilityLedgerBody, CompatibilityLedgerTrustAnchors, CompatibilityPolicy,
        EntryEvidence, EntryState, KemSuite, MigrationPhase, NodeCompatibilityEntry,
        NodeFallbackPolicy, ProtocolVersion, SignatureSuite,
    };

    use super::*;

    fn ed25519_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[23_u8; 32]).expect("valid deterministic signing key")
    }

    fn ml_dsa_key() -> MlDsa65VerifyingKeyBytes {
        MlDsa65VerifyingKeyBytes::try_from_bytes(vec![
            0xB6_u8;
            fcp_crypto::ML_DSA_65_PUBLIC_KEY_SIZE
        ])
        .expect("valid ML-DSA-65 key length")
    }

    fn fake_ml_dsa_signature(
        key: &MlDsa65VerifyingKeyBytes,
        message: &[u8],
    ) -> MlDsa65SignatureBytes {
        let mut seed = Vec::with_capacity(key.as_bytes().len() + message.len());
        seed.extend_from_slice(key.as_bytes());
        seed.extend_from_slice(message);
        let digest = blake3::hash(&seed);
        let mut bytes = Vec::with_capacity(fcp_crypto::ML_DSA_65_SIGNATURE_SIZE);
        while bytes.len() < fcp_crypto::ML_DSA_65_SIGNATURE_SIZE {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.truncate(fcp_crypto::ML_DSA_65_SIGNATURE_SIZE);
        MlDsa65SignatureBytes::try_from_bytes(bytes).expect("expanded signature has valid length")
    }

    struct FakeHybridSigner {
        ed25519: Ed25519SigningKey,
        ml_dsa_65: MlDsa65VerifyingKeyBytes,
    }

    impl fcp_crypto::HybridOwnerSigner for FakeHybridSigner {
        fn hybrid_owner_key_ids(&self) -> HybridOwnerKeyIds {
            HybridOwnerKeyIds {
                ed25519: self.ed25519.verifying_key().key_id(),
                ml_dsa_65: self.ml_dsa_65.key_id(),
            }
        }

        fn sign_hybrid_owner(&self, transcript: &[u8]) -> CryptoResult<HybridOwnerSignature> {
            Ok(HybridOwnerSignature {
                ed25519: self.ed25519.sign(transcript),
                ml_dsa_65: fake_ml_dsa_signature(&self.ml_dsa_65, transcript),
            })
        }
    }

    struct FakeMlDsaVerifier;

    impl MlDsa65LedgerVerifier for FakeMlDsaVerifier {
        fn verify_ml_dsa65(
            &self,
            verifying_key: &MlDsa65VerifyingKeyBytes,
            message: &[u8],
            signature: &MlDsa65SignatureBytes,
        ) -> bool {
            &fake_ml_dsa_signature(verifying_key, message) == signature
        }
    }

    fn entry(node_id: &str) -> NodeCompatibilityEntry {
        NodeCompatibilityEntry {
            node_id: node_id.to_owned(),
            node_attestation_hash: [0x44; 32],
            claim_epoch: 1,
            claim_issued_at_ms: 1_700_000_000_000,
            claim_expires_at_ms: 1_700_086_400_000,
            supported_protocols: BTreeSet::from([ProtocolVersion::V3, ProtocolVersion::V4]),
            signature_suites: BTreeSet::from([SignatureSuite::Ed25519V3, SignatureSuite::MlDsa65]),
            kem_suites: BTreeSet::from([KemSuite::HpkeX25519V3, KemSuite::XWingMlKem768X25519]),
            fallback_policy: NodeFallbackPolicy::SafeReadOnlyOnly,
            state: EntryState::Verified,
            evidence: EntryEvidence {
                claim_hash: [0x55; 32],
                observed_by: vec!["observer".to_owned()],
                note: None,
            },
        }
    }

    fn body(epoch: u64, previous_root: Option<CompatibilityLedgerRoot>) -> CompatibilityLedgerBody {
        let mut entries = BTreeMap::new();
        entries.insert("node-a".to_owned(), entry("node-a"));
        CompatibilityLedgerBody {
            ledger_version: fcp_evidence::COMPATIBILITY_LEDGER_VERSION,
            mesh_id: "mesh-alpha".to_owned(),
            epoch,
            previous_root,
            valid_from_ms: 1_700_000_000_000 + epoch,
            expires_at_ms: 1_700_086_400_000 + epoch,
            phase: MigrationPhase::DualSignRequired,
            entries,
            tombstones: BTreeMap::new(),
            policy: CompatibilityPolicy::default(),
        }
    }

    fn signed_ledger(
        epoch: u64,
        previous_root: Option<CompatibilityLedgerRoot>,
        signer: &FakeHybridSigner,
    ) -> MeshCompatibilityLedger {
        MeshCompatibilityLedger::seal_with_hybrid_owner(body(epoch, previous_root), signer)
            .expect("ledger signs")
    }

    #[test]
    fn compatibility_ledger_store_persists_and_returns_latest() {
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let store = MemoryCompatibilityLedgerStore::new();
        let first = signed_ledger(1, None, &signer);
        let first_root = store.put_ledger(first.clone()).expect("stores genesis");
        let second = signed_ledger(2, Some(first_root), &signer);
        let second_root = store
            .put_ledger(second.clone())
            .expect("stores chained update");

        assert_eq!(store.get_ledger(&first_root), Some(first));
        assert_eq!(store.latest_ledger("mesh-alpha"), Some(second));
        assert_eq!(
            store
                .latest_ledger("mesh-alpha")
                .unwrap()
                .ledger_root()
                .unwrap(),
            second_root
        );
    }

    #[test]
    fn compatibility_ledger_durable_store_reopens_latest_epoch() {
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let store = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("open store");
        let first = signed_ledger(1, None, &signer);
        let first_root = store.put_ledger(first.clone()).expect("stores genesis");
        let second = signed_ledger(2, Some(first_root), &signer);
        let second_root = store
            .put_ledger(second.clone())
            .expect("stores chained update");

        drop(store);

        let reopened =
            DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("reopen store");
        assert_eq!(reopened.get_ledger(&first_root), Some(first));
        assert_eq!(reopened.latest_ledger("mesh-alpha"), Some(second.clone()));

        let stored_bytes = std::fs::read(
            temp_dir
                .path()
                .join("ledgers")
                .join(format!("{second_root}.cbor")),
        )
        .expect("read stored ledger");
        assert_eq!(
            MeshCompatibilityLedger::from_canonical_cbor(&stored_bytes)
                .expect("stored ledger is canonical"),
            second
        );
    }

    #[test]
    fn compatibility_ledger_store_rejects_epoch_rollback() {
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let store = MemoryCompatibilityLedgerStore::new();
        let first = signed_ledger(7, None, &signer);
        let first_root = store.put_ledger(first).expect("stores genesis");
        let rollback = signed_ledger(7, Some(first_root), &signer);

        let err = store
            .put_ledger(rollback)
            .expect_err("same epoch must be rejected");

        assert!(matches!(
            err,
            CompatibilityLedgerStoreError::EpochRollback {
                latest_epoch: 7,
                attempted_epoch: 7,
                ..
            }
        ));
    }

    #[test]
    fn compatibility_ledger_store_rejects_broken_previous_root() {
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let store = MemoryCompatibilityLedgerStore::new();
        let first = signed_ledger(1, None, &signer);
        let _first_root = store.put_ledger(first).expect("stores genesis");
        let wrong_root = CompatibilityLedgerRoot::from_bytes([0xEE; 32]);
        let second = signed_ledger(2, Some(wrong_root), &signer);

        let err = store
            .put_ledger(second)
            .expect_err("wrong previous root must fail");

        assert!(matches!(
            err,
            CompatibilityLedgerStoreError::PreviousRootMismatch { .. }
        ));
    }

    #[test]
    fn compatibility_ledger_store_verifies_before_persisting() {
        let ml_dsa_key = ml_dsa_key();
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key.clone(),
        };
        let anchors = CompatibilityLedgerTrustAnchors::new(
            vec![signer.ed25519.verifying_key()],
            vec![ml_dsa_key],
        );
        let store = MemoryCompatibilityLedgerStore::new();
        let ledger = signed_ledger(1, None, &signer);

        let root = store
            .put_verified_ledger(ledger.clone(), &anchors, &FakeMlDsaVerifier)
            .expect("verified ledger persists");

        assert_eq!(store.get_ledger(&root), Some(ledger));
    }

    #[test]
    fn compatibility_ledger_store_does_not_persist_failed_verification() {
        let ml_dsa_key = ml_dsa_key();
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key.clone(),
        };
        let anchors = CompatibilityLedgerTrustAnchors::new(
            vec![signer.ed25519.verifying_key()],
            vec![ml_dsa_key],
        );
        let store = MemoryCompatibilityLedgerStore::new();
        let mut ledger = signed_ledger(1, None, &signer);
        ledger.body.epoch += 1;

        let err = store
            .put_verified_ledger(ledger, &anchors, &FakeMlDsaVerifier)
            .expect_err("tampered signature must fail");

        assert!(matches!(
            err,
            CompatibilityLedgerStoreError::Verification(
                CompatibilityLedgerError::Ed25519SignatureVerificationFailed { .. }
            )
        ));
        assert!(store.latest_ledger("mesh-alpha").is_none());
    }
}
