//! Backing stores for V3/V4 compatibility ledgers.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use fcp_cbor::{MAX_DESERIALIZATION_RECURSION_LIMIT, to_canonical_cbor};
use fcp_crypto::MAX_V4_PAYLOAD_BYTES;
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

/// Persistent latest-ledger pointer.
///
/// **`sequence` and `published_at_ms` are V2 fields** added under
/// `flywheel_connectors-iqy2b` to defend against pointer-replay attacks.
/// VioletPine's audit found that the V1 pointer (just `mesh_id` + `root`)
/// could be silently rolled back on disk to point at an older signed
/// ledger that was still present, demoting policy from a newer
/// `V4Required` phase to an earlier `V3-permissive` phase without breaking
/// any signature.
///
/// The defence is two-layered:
///
/// 1. `sequence` MUST equal the underlying signed ledger's `epoch()`.
///    The ledger itself is hybrid-signed, so this binding transitively
///    authenticates `sequence` via the ledger's signature — there is no
///    separate pointer key to manage.
/// 2. On `open`, the loader cross-checks every pointer against the
///    high-water-mark epoch derived from the on-disk signed-ledger
///    inventory. A pointer whose `sequence` is below the on-disk maximum
///    for its mesh is treated as replay and silently upgraded to the
///    high-water-mark ledger (which is also signed, so policy cannot
///    regress).
///
/// `published_at_ms` is wall-clock at write time. It is NOT load-bearing
/// for security (sequence is) but is recorded so an operator
/// investigating a tampering incident can correlate the pointer's last
/// legitimate write with their backup/restore log.
///
/// V1 pointer files (no `sequence`, no `published_at_ms`) deserialise
/// with serde defaults (both 0). The loader detects this and reconstructs
/// the latest pointer from the signed-ledger chain — V1 pointers are
/// never trusted as authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LatestLedgerPointer {
    mesh_id: String,
    root: CompatibilityLedgerRoot,
    /// Monotonic sequence — equals the underlying signed ledger's
    /// `epoch()`. Strictly increases per mesh across legitimate writes;
    /// the on-open cross-check enforces this.
    #[serde(default)]
    sequence: u64,
    /// Wall-clock at write time (Unix milliseconds). Forensic only —
    /// not relied on for security; `sequence` is the authoritative
    /// monotonic field.
    #[serde(default)]
    published_at_ms: u64,
}

#[derive(Debug, Serialize)]
struct LegacyLatestLedgerPointer<'a> {
    mesh_id: &'a str,
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
        let pointer_repairs = load_latest_pointers(&latest_dir, &mut state)?;
        // br-iqy2b: a pointer file we found on disk pointed to a
        // lower-epoch root than the on-disk signed-ledger high-water
        // mark. Rewrite the file to the high-water-mark pointer so the
        // replay state is cleaned up — the in-memory state already
        // reflects the corrected mapping. Failure here is non-fatal at
        // load time; the in-memory upgrade is the load-bearing defence.
        for (mesh_id, root, sequence) in pointer_repairs {
            let _ = repair_replayed_pointer(&latest_dir, &mesh_id, root, sequence);
        }

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
        sequence: u64,
    ) -> Result<(), CompatibilityLedgerStoreError> {
        let pointer = LatestLedgerPointer {
            mesh_id: mesh_id.to_owned(),
            root,
            sequence,
            // Monotonic wall-clock. Cannot underflow on supported
            // platforms; if the system clock is broken before 1970 the
            // `unwrap_or(0)` keeps us forward-compatible without
            // panicking inside the storage layer.
            published_at_ms: u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0),
            )
            .unwrap_or(0),
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
                let sequence = ledger.epoch();
                drop(state);
                self.persist_latest_pointer(&mesh_id, root, sequence)?;
                self.state.write().latest_by_mesh.insert(mesh_id, root);
                return Ok(root);
            }
            state.validate_next(&ledger, root, &mesh_id)?;
        }

        let sequence = ledger.epoch();
        self.persist_ledger(root, &ledger)?;
        self.persist_latest_pointer(&mesh_id, root, sequence)?;

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

/// Compute the high-water-mark `(epoch, root)` per mesh from the on-disk
/// signed-ledger inventory. Used by [`load_latest_pointers`] to enforce
/// the pointer-replay defence (br-iqy2b).
fn high_water_marks_by_mesh(
    state: &CompatibilityLedgerState,
) -> BTreeMap<String, (u64, CompatibilityLedgerRoot)> {
    let mut max: BTreeMap<String, (u64, CompatibilityLedgerRoot)> = BTreeMap::new();
    for (root, ledger) in &state.ledgers {
        let mesh_id = ledger.mesh_id().to_owned();
        let epoch = ledger.epoch();
        max.entry(mesh_id)
            .and_modify(|cur| {
                if epoch > cur.0 {
                    *cur = (epoch, *root);
                }
            })
            .or_insert((epoch, *root));
    }
    max
}

/// Load latest-ledger pointers, enforcing the V2 replay-defence
/// (br-iqy2b):
///
/// 1. The pointer's `sequence` MUST match the underlying signed
///    ledger's `epoch()`. The ledger is hybrid-signed, so this binding
///    transitively authenticates `sequence`.
/// 2. The pointer's `sequence` MUST be ≥ the on-disk high-water-mark
///    epoch for its mesh. If it is below, the pointer is treated as a
///    replay attempt: the in-memory `latest_by_mesh` is set to the
///    high-water-mark ledger instead, and a `(mesh_id, hwm_root,
///    hwm_epoch)` repair is returned so the caller can rewrite the
///    pointer file on disk.
/// 3. Multiple pointer files for the same mesh (which should not
///    happen given the digest-based filename, but defence in depth) are
///    reduced to the highest-sequence entry.
///
/// V1 pointer files (no `sequence`, no `published_at_ms`) deserialise
/// with `sequence = 0`. Since any real ledger has `epoch ≥ 1`, the
/// per-pointer `sequence == ledger.epoch()` check would reject every V1
/// pointer; instead we treat `sequence == 0` as "legacy / unset" and
/// reconstruct using the high-water-mark, then enqueue a V2-pointer
/// rewrite on disk.
fn load_latest_pointers(
    latest_dir: &Path,
    state: &mut CompatibilityLedgerState,
) -> Result<Vec<(String, CompatibilityLedgerRoot, u64)>, CompatibilityLedgerStoreError> {
    let hwm_by_mesh = high_water_marks_by_mesh(state);
    let mut pointers_by_mesh: BTreeMap<String, (u64, CompatibilityLedgerRoot)> = BTreeMap::new();
    let mut repairs: Vec<(String, CompatibilityLedgerRoot, u64)> = Vec::new();

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
        if bytes.len() > MAX_V4_PAYLOAD_BYTES {
            return Err(CompatibilityLedgerStoreError::LatestPointerTooLarge {
                path,
                observed: bytes.len(),
                max: MAX_V4_PAYLOAD_BYTES,
            });
        }
        let mut reader = bytes.as_slice();
        let pointer: LatestLedgerPointer = ciborium::de::from_reader_with_recursion_limit(
            &mut reader,
            MAX_DESERIALIZATION_RECURSION_LIMIT,
        )
        .map_err(
            |source| CompatibilityLedgerStoreError::CorruptLatestPointer {
                path: path.clone(),
                message: source.to_string(),
            },
        )?;
        if !reader.is_empty() {
            return Err(CompatibilityLedgerStoreError::CorruptLatestPointer {
                path,
                message: "trailing bytes after latest pointer CBOR".to_owned(),
            });
        }
        let recoded = to_canonical_cbor(&pointer).map_err(|err| {
            CompatibilityLedgerStoreError::Ledger(CompatibilityLedgerError::from(err))
        })?;
        if recoded != bytes {
            let is_canonical_legacy_v1 = pointer.sequence == 0 && pointer.published_at_ms == 0 && {
                let legacy = LegacyLatestLedgerPointer {
                    mesh_id: &pointer.mesh_id,
                    root: pointer.root,
                };
                let legacy_recoded = to_canonical_cbor(&legacy).map_err(|err| {
                    CompatibilityLedgerStoreError::Ledger(CompatibilityLedgerError::from(err))
                })?;
                legacy_recoded == bytes
            };
            if !is_canonical_legacy_v1 {
                return Err(CompatibilityLedgerStoreError::CorruptLatestPointer {
                    path,
                    message: "latest pointer CBOR is not canonical".to_owned(),
                });
            }
        }
        let target_ledger = state.ledgers.get(&pointer.root).ok_or(
            CompatibilityLedgerStoreError::MissingLatestLedger {
                mesh_id: pointer.mesh_id.clone(),
                latest_root: pointer.root.to_string(),
            },
        )?;

        // br-iqy2b §1: pointer.sequence must equal the underlying
        // ledger.epoch (which is signed). Tampered sequence → reject.
        // Special case: sequence == 0 is the legacy V1 form; we
        // reconstruct from the high-water-mark below rather than
        // reject, so existing deployments transparently upgrade.
        let ledger_epoch = target_ledger.epoch();
        let is_legacy_v1 = pointer.sequence == 0;
        if !is_legacy_v1 && pointer.sequence != ledger_epoch {
            return Err(CompatibilityLedgerStoreError::PointerSequenceMismatch {
                mesh_id: pointer.mesh_id,
                pointer_sequence: pointer.sequence,
                ledger_epoch,
            });
        }

        // br-iqy2b §2: cross-check against the on-disk high-water-mark.
        // A stale pointer (e.g. restored from backup) below the HWM
        // gets silently upgraded.
        let (effective_root, effective_sequence) = match hwm_by_mesh.get(&pointer.mesh_id) {
            Some(&(hwm_epoch, hwm_root)) if is_legacy_v1 || pointer.sequence < hwm_epoch => {
                repairs.push((pointer.mesh_id.clone(), hwm_root, hwm_epoch));
                (hwm_root, hwm_epoch)
            }
            _ => (pointer.root, ledger_epoch),
        };

        // br-iqy2b §3: if multiple pointer files for the same mesh
        // exist (defence in depth), keep the highest-sequence entry.
        match pointers_by_mesh.get(&pointer.mesh_id) {
            Some(&(existing_seq, _)) if existing_seq >= effective_sequence => {}
            _ => {
                pointers_by_mesh.insert(pointer.mesh_id, (effective_sequence, effective_root));
            }
        }
    }

    for (mesh_id, (_seq, root)) in pointers_by_mesh {
        state.latest_by_mesh.insert(mesh_id, root);
    }

    Ok(repairs)
}

/// Rewrite a pointer file in place to the high-water-mark `(root,
/// sequence)` after a replay was detected during load. Best-effort —
/// caller treats failure as non-fatal because the in-memory state has
/// already been corrected.
fn repair_replayed_pointer(
    latest_dir: &Path,
    mesh_id: &str,
    root: CompatibilityLedgerRoot,
    sequence: u64,
) -> Result<(), CompatibilityLedgerStoreError> {
    let pointer = LatestLedgerPointer {
        mesh_id: mesh_id.to_owned(),
        root,
        sequence,
        published_at_ms: u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
        )
        .unwrap_or(0),
    };
    let bytes = to_canonical_cbor(&pointer)
        .map_err(|err| CompatibilityLedgerStoreError::Ledger(err.into()))?;
    let path = DurableCompatibilityLedgerStore::latest_path(mesh_id, latest_dir);
    fs::write(&path, bytes).map_err(|source| CompatibilityLedgerStoreError::StorageIo {
        path,
        message: source.to_string(),
    })
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
    /// Latest pointer file exceeded the pre-decode size bound.
    #[error(
        "compatibility ledger latest pointer {} is too large: observed {observed} bytes > max {max} bytes",
        path.display()
    )]
    LatestPointerTooLarge {
        /// Path being decoded.
        path: PathBuf,
        /// Observed payload length in bytes.
        observed: usize,
        /// Maximum accepted payload length in bytes.
        max: usize,
    },
    /// Latest pointer's `sequence` field disagreed with the underlying
    /// signed ledger's `epoch()` (br-iqy2b). Surfaces an attacker who
    /// edited the pointer to claim a different sequence than the
    /// ledger's signed epoch — the ledger signature transitively
    /// authenticates `sequence`, so any disagreement is rejected.
    #[error(
        "compatibility ledger latest pointer for mesh {mesh_id} sequence {pointer_sequence} \
         does not match underlying signed ledger epoch {ledger_epoch}"
    )]
    PointerSequenceMismatch {
        /// Mesh id from the pointer.
        mesh_id: String,
        /// Sequence the pointer claimed.
        pointer_sequence: u64,
        /// Epoch the ledger it points at actually has (signed).
        ledger_epoch: u64,
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

    fn deep_unknown_field_cbor(depth: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9 + (depth * 3) + 1);
        bytes.push(0xA1);
        bytes.push(0x67);
        bytes.extend_from_slice(b"unknown");
        for _ in 0..depth {
            bytes.push(0xA1);
            bytes.push(0x61);
            bytes.push(b'x');
        }
        bytes.push(0xF6);
        bytes
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
    fn durable_store_rejects_oversized_latest_pointer_before_decode() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let latest_dir = temp_dir.path().join("latest");
        std::fs::create_dir_all(&latest_dir).expect("latest dir");
        let pointer_path = latest_dir.join("oversized.latest.cbor");
        let bytes = vec![0xA1; MAX_V4_PAYLOAD_BYTES + 1];
        std::fs::write(&pointer_path, &bytes).expect("write oversized pointer");

        let err = DurableCompatibilityLedgerStore::open(temp_dir.path())
            .expect_err("oversized pointer must fail before decode");

        assert!(matches!(
            err,
            CompatibilityLedgerStoreError::LatestPointerTooLarge {
                path,
                observed,
                max: MAX_V4_PAYLOAD_BYTES
            } if path == pointer_path && observed == bytes.len()
        ));
    }

    #[test]
    fn durable_store_rejects_deep_latest_pointer_with_recursion_limit() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let latest_dir = temp_dir.path().join("latest");
        std::fs::create_dir_all(&latest_dir).expect("latest dir");
        let pointer_path = latest_dir.join("deep.latest.cbor");
        let bytes = deep_unknown_field_cbor(MAX_DESERIALIZATION_RECURSION_LIMIT + 80);
        assert!(bytes.len() <= MAX_V4_PAYLOAD_BYTES);
        std::fs::write(&pointer_path, bytes).expect("write deep pointer");

        let err = DurableCompatibilityLedgerStore::open(temp_dir.path())
            .expect_err("deep pointer must fail before full decode");

        assert!(
            matches!(
                err,
                CompatibilityLedgerStoreError::CorruptLatestPointer { ref path, ref message }
                    if *path == pointer_path && message.to_ascii_lowercase().contains("recursion")
            ),
            "expected recursion-limit latest-pointer error, got {err:?}"
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

    // ── br-iqy2b: latest-pointer replay defence ────────────────────────

    #[test]
    fn ledger_replay_attack_rolls_pointer_back_but_open_recovers_to_high_water_mark() {
        // VioletPine's audit (br-iqy2b): an attacker (or a partial
        // backup-restore) overwrites latest/<mesh>.latest.cbor with a
        // pointer to an OLDER signed ledger that is still on disk.
        // Both signature verification and root-exists checks pass on
        // the old ledger, so the V1 loader silently regressed policy.
        // The V2 loader cross-checks against the on-disk
        // signed-ledger high-water mark and recovers epoch 2 as
        // latest.
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let store = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("open");
        let first = signed_ledger(1, None, &signer);
        let first_root = store.put_ledger(first.clone()).expect("genesis");
        let second = signed_ledger(2, Some(first_root), &signer);
        let _second_root = store.put_ledger(second.clone()).expect("epoch 2");
        drop(store);

        // Tamper: rewrite the pointer to point at epoch 1 with the V1
        // (legacy) shape so we exercise both the legacy path AND the
        // explicit-replay path.
        let pointer_path = DurableCompatibilityLedgerStore::latest_path(
            "mesh-alpha",
            &temp_dir.path().join("latest"),
        );
        let replay_pointer = LatestLedgerPointer {
            mesh_id: "mesh-alpha".to_owned(),
            root: first_root,
            sequence: 1,
            published_at_ms: 0,
        };
        let bytes = to_canonical_cbor(&replay_pointer).expect("canonical CBOR");
        std::fs::write(&pointer_path, bytes).expect("rewrite pointer");

        // Reopen — the loader MUST cross-check against on-disk signed
        // ledgers and pick epoch 2.
        let reopened =
            DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("reopen succeeds");
        let latest = reopened
            .latest_ledger("mesh-alpha")
            .expect("latest is present after replay defence");
        assert_eq!(
            latest.epoch(),
            2,
            "replay defence must restore latest to epoch 2 (the on-disk high-water mark)"
        );

        // The on-disk pointer should also have been repaired to point
        // at epoch 2; reopening a third time must NOT need to repair
        // again.
        let second_reopen =
            DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("second reopen");
        let pointer_bytes = std::fs::read(&pointer_path).expect("read repaired pointer");
        let final_pointer: LatestLedgerPointer =
            ciborium::de::from_reader(pointer_bytes.as_slice()).expect("decode");
        assert_eq!(
            final_pointer.sequence, 2,
            "replay-repair must rewrite pointer to high-water-mark sequence"
        );
        assert_eq!(
            second_reopen.latest_ledger("mesh-alpha").unwrap().epoch(),
            2
        );
    }

    #[test]
    fn ledger_replay_v1_legacy_pointer_upgrades_transparently() {
        // br-iqy2b: existing on-disk deployments have V1 pointers (no
        // sequence, no published_at_ms — both default to 0). The
        // loader MUST treat sequence == 0 as legacy and reconstruct
        // from the high-water mark, then rewrite the pointer to V2.
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let store = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("open");
        let first = signed_ledger(1, None, &signer);
        let first_root = store.put_ledger(first).expect("genesis");
        let second = signed_ledger(2, Some(first_root), &signer);
        let _ = store.put_ledger(second).expect("epoch 2");
        drop(store);

        // Write a V1-shaped pointer (sequence/published_at_ms both 0)
        // pointing at epoch 1.
        let v1_pointer = LatestLedgerPointer {
            mesh_id: "mesh-alpha".to_owned(),
            root: first_root,
            sequence: 0,
            published_at_ms: 0,
        };
        let pointer_path = DurableCompatibilityLedgerStore::latest_path(
            "mesh-alpha",
            &temp_dir.path().join("latest"),
        );
        std::fs::write(
            &pointer_path,
            to_canonical_cbor(&v1_pointer).expect("canonical CBOR"),
        )
        .expect("write V1 pointer");

        // Reopen: V1 pointer is reconstructed from HWM → epoch 2.
        let reopened = DurableCompatibilityLedgerStore::open(temp_dir.path())
            .expect("V1 pointer must upgrade transparently");
        assert_eq!(reopened.latest_ledger("mesh-alpha").unwrap().epoch(), 2);

        // Pointer file is rewritten to the V2 form with sequence == 2.
        let final_pointer: LatestLedgerPointer = ciborium::de::from_reader(
            std::fs::read(&pointer_path)
                .expect("read repaired")
                .as_slice(),
        )
        .expect("decode");
        assert_eq!(final_pointer.sequence, 2);
    }

    #[test]
    fn ledger_replay_pointer_with_lying_sequence_is_rejected() {
        // br-iqy2b: pointer.sequence MUST equal the underlying signed
        // ledger.epoch(). An attacker that edits pointer.sequence to
        // claim a different value than what the (signed) ledger says
        // must be rejected as corrupt — the ledger signature
        // transitively authenticates the sequence claim.
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let store = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("open");
        let first = signed_ledger(1, None, &signer);
        let first_root = store.put_ledger(first).expect("genesis");
        let second = signed_ledger(2, Some(first_root), &signer);
        let second_root = store.put_ledger(second).expect("epoch 2");
        drop(store);

        // Tamper: pointer claims sequence == 99 but actually points at
        // epoch-2 ledger.
        let lying_pointer = LatestLedgerPointer {
            mesh_id: "mesh-alpha".to_owned(),
            root: second_root,
            sequence: 99, // Lie — second_root's ledger has epoch == 2.
            published_at_ms: 1_700_000_000_000,
        };
        let pointer_path = DurableCompatibilityLedgerStore::latest_path(
            "mesh-alpha",
            &temp_dir.path().join("latest"),
        );
        std::fs::write(
            &pointer_path,
            to_canonical_cbor(&lying_pointer).expect("canonical"),
        )
        .expect("write");

        let err = DurableCompatibilityLedgerStore::open(temp_dir.path())
            .expect_err("lying-sequence pointer must be rejected on open");
        assert!(
            matches!(
                err,
                CompatibilityLedgerStoreError::PointerSequenceMismatch {
                    pointer_sequence: 99,
                    ledger_epoch: 2,
                    ..
                }
            ),
            "expected PointerSequenceMismatch{{99→2}}, got {err:?}"
        );
    }

    #[test]
    fn ledger_replay_pointer_carries_sequence_and_timestamp_after_put() {
        // br-iqy2b: the pointer file written by put_ledger MUST carry
        // sequence == ledger.epoch and a non-zero published_at_ms.
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let store = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("open");
        let _ = store
            .put_ledger(signed_ledger(7, None, &signer))
            .expect("put");

        let pointer_path = DurableCompatibilityLedgerStore::latest_path(
            "mesh-alpha",
            &temp_dir.path().join("latest"),
        );
        let pointer: LatestLedgerPointer = ciborium::de::from_reader(
            std::fs::read(&pointer_path)
                .expect("pointer exists")
                .as_slice(),
        )
        .expect("decode");
        assert_eq!(pointer.sequence, 7, "sequence must equal ledger epoch");
        assert!(
            pointer.published_at_ms > 1_700_000_000_000,
            "published_at_ms must be a wall-clock timestamp, got {}",
            pointer.published_at_ms
        );
    }

    #[test]
    fn ledger_replay_high_water_mark_strictly_monotonic_on_read() {
        // br-iqy2b: even if the pointer file contains a perfectly-valid
        // (sequence == ledger.epoch) entry, that sequence MUST be ≥
        // the on-disk high-water mark. An attacker who deletes the
        // newer pointer file but leaves both signed ledgers on disk
        // cannot regress us: open() picks the HWM regardless.
        let signer = FakeHybridSigner {
            ed25519: ed25519_key(),
            ml_dsa_65: ml_dsa_key(),
        };
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let store = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("open");
        let first = signed_ledger(1, None, &signer);
        let first_root = store.put_ledger(first).expect("genesis");
        let second = signed_ledger(2, Some(first_root), &signer);
        let _ = store.put_ledger(second).expect("epoch 2");
        drop(store);

        // Write a V2 pointer pointing at epoch 1 (with the correctly-
        // signed-ledger-derived sequence == 1). This is the trickier
        // attack: the pointer's internal consistency check passes
        // because sequence == ledger.epoch == 1; only the HWM
        // cross-check catches the regression.
        let regressed_pointer = LatestLedgerPointer {
            mesh_id: "mesh-alpha".to_owned(),
            root: first_root,
            sequence: 1,
            published_at_ms: 1_700_000_000_000,
        };
        let pointer_path = DurableCompatibilityLedgerStore::latest_path(
            "mesh-alpha",
            &temp_dir.path().join("latest"),
        );
        std::fs::write(
            &pointer_path,
            to_canonical_cbor(&regressed_pointer).expect("canonical"),
        )
        .expect("write");

        let reopened = DurableCompatibilityLedgerStore::open(temp_dir.path()).expect("reopen");
        assert_eq!(
            reopened.latest_ledger("mesh-alpha").unwrap().epoch(),
            2,
            "HWM cross-check must override a sequence-consistent but stale pointer"
        );
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
