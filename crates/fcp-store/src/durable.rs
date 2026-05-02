//! Crash-safe durable object and symbol stores backed by the filesystem.
//!
//! The durability contract is:
//! - every mutating operation is appended to a checksummed WAL and `sync_all()`ed
//!   before in-memory state changes become visible;
//! - checkpoints are written to a temp file in the target directory, `sync_all()`ed,
//!   atomically renamed into place, and the containing directory is fsynced on
//!   platforms that support directory sync;
//! - startup replays only checksum-valid WAL records and truncates any torn or
//!   corrupt tail so a partial append cannot poison later recovery.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use fcp_prelude::{ObjectId, ObjectPlacementPolicy, RetentionClass, StoredObject, ZoneId};
use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::coverage::SymbolDistribution;
use crate::error::{ObjectStoreError, SymbolStoreError};
use crate::object_id_verifier::ObjectIdVerifier;
use crate::object_store::{MemoryObjectStoreConfig, ObjectStore};
use crate::symbol_store::{
    MemorySymbolStoreConfig, ObjectSymbolMeta, StoredSymbol, SymbolMeta, SymbolStore,
    validate_source_symbols,
};

const SNAPSHOT_VERSION: u32 = 1;
const WAL_VERSION: u32 = 1;
const DEFAULT_CHECKPOINT_AFTER_OPS: u64 = 64;

/// Maximum bytes the WAL recovery loop will buffer for a single record.
///
/// The serialized envelope contains a `StoredObject` whose body is a raw
/// `Vec<u8>` (capped at `fcp_cbor::MAX_CANONICAL_OBJECT_BYTES` = 64 MiB).
/// `serde_json` emits `Vec<u8>` as a JSON array of integers (~3-5×
/// inflation), so a worst-case legitimate envelope can reach ~320 MiB
/// before encoding overhead. 512 MiB leaves headroom for envelope
/// metadata and future field additions while still bounding recovery
/// memory: a torn write or adversarial single-line WAL cannot exhaust
/// memory by withholding the trailing newline.
///
/// Records exceeding this cap are treated as torn (truncated and
/// discarded), matching the existing behavior for unparseable records.
const MAX_WAL_RECORD_BYTES: usize = 512 * 1024 * 1024;

/// Maximum bytes the snapshot recovery loop will load.
///
/// Same reasoning as `MAX_WAL_RECORD_BYTES` applied to a full
/// `ObjectSnapshot` / `SymbolSnapshot` payload, scaled for the typical
/// number of objects per checkpoint. Larger snapshots are rejected with
/// a clear error rather than OOM-killing the recovery process.
const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DurableObjectStoreConfig {
    /// Directory containing the store snapshot and WAL files.
    pub root_dir: PathBuf,
    /// Maximum durable object bytes allowed in the store.
    pub max_bytes: u64,
    /// Number of durable mutations between automatic checkpoints.
    pub checkpoint_after_ops: u64,
}

impl DurableObjectStoreConfig {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            max_bytes: MemoryObjectStoreConfig::default().max_bytes,
            checkpoint_after_ops: DEFAULT_CHECKPOINT_AFTER_OPS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DurableSymbolStoreConfig {
    /// Directory containing the store snapshot and WAL files.
    pub root_dir: PathBuf,
    /// Maximum durable symbol bytes allowed in the store.
    pub max_bytes: u64,
    /// Local node ID used for coverage/distribution tracking.
    pub local_node_id: u64,
    /// Number of durable mutations between automatic checkpoints.
    pub checkpoint_after_ops: u64,
}

impl DurableSymbolStoreConfig {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let defaults = MemorySymbolStoreConfig::default();
        Self {
            root_dir: root_dir.into(),
            max_bytes: defaults.max_bytes,
            local_node_id: defaults.local_node_id,
            checkpoint_after_ops: DEFAULT_CHECKPOINT_AFTER_OPS,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotEnvelope<T> {
    version: u32,
    last_seq: u64,
    checksum: [u8; 32],
    payload: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalEnvelope<T> {
    version: u32,
    seq: u64,
    checksum: [u8; 32],
    op: T,
}

#[derive(Debug, Default)]
struct DurableObjectState {
    objects: HashMap<ObjectId, StoredObject>,
    zone_index: HashMap<ZoneId, Vec<ObjectId>>,
    used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectSnapshot {
    objects: Vec<StoredObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ObjectWalOp {
    Put(Box<StoredObject>),
    Delete {
        object_id: ObjectId,
    },
    SetRetention {
        object_id: ObjectId,
        retention: RetentionClass,
    },
}

pub struct DurableObjectStore {
    state: Mutex<DurableObjectState>,
    config: DurableObjectStoreConfig,
    write_guard: Mutex<()>,
    next_seq: AtomicU64,
    ops_since_checkpoint: AtomicU64,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    /// Optional content-id verifier. When set, every runtime `put`,
    /// every WAL record replayed at startup, and every snapshot entry
    /// is routed through `verifier.verify(&object)` before touching
    /// in-memory state. Closes the attacker-chosen-id injection vector
    /// documented in bead flywheel_connectors-4g0qr.
    verifier: Option<Arc<dyn ObjectIdVerifier>>,
}

#[derive(Debug, Clone)]
struct DurableObjectSymbols {
    meta: ObjectSymbolMeta,
    symbols: HashMap<u32, StoredSymbol>,
}

#[derive(Debug, Default)]
struct DurableSymbolState {
    objects: HashMap<ObjectId, DurableObjectSymbols>,
    used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStoredSymbol {
    meta: SymbolMeta,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SymbolSnapshotEntry {
    meta: ObjectSymbolMeta,
    symbols: Vec<PersistentStoredSymbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SymbolSnapshot {
    objects: Vec<SymbolSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SymbolWalOp {
    PutObjectMeta(ObjectSymbolMeta),
    PutSymbol(PersistentStoredSymbol),
    DeleteObject { object_id: ObjectId },
    DeleteSymbol { object_id: ObjectId, esi: u32 },
}

pub struct DurableSymbolStore {
    state: ParkingRwLock<DurableSymbolState>,
    config: DurableSymbolStoreConfig,
    write_guard: ParkingMutex<()>,
    next_seq: AtomicU64,
    ops_since_checkpoint: AtomicU64,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
}

impl DurableObjectState {
    fn object_size(object: &StoredObject) -> u64 {
        // Keep durable quota accounting aligned with the in-memory object
        // store: charge the exact canonical object bytes rather than the old
        // body-plus-512 estimate. Header-heavy objects can otherwise bypass
        // max_bytes by putting most of their payload in refs/placement.
        const MAX_CANONICAL_FALLBACK: u64 = 64 * 1024 * 1024;

        match StoredObject::canonical_bytes(&object.header, &object.body) {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => MAX_CANONICAL_FALLBACK,
        }
    }

    fn from_snapshot(
        snapshot: ObjectSnapshot,
        verifier: Option<&dyn ObjectIdVerifier>,
    ) -> Result<Self, ObjectStoreError> {
        let mut state = Self::default();
        for object in snapshot.objects {
            // Defense-in-depth: reject snapshot entries whose header is
            // not canonically encodable or whose total size exceeds
            // `MAX_CANONICAL_OBJECT_BYTES`. A snapshot file is on-disk
            // attacker-reachable (compromised host, restored backup,
            // imported from another node), so the recovery path must
            // not implicitly trust per-object structure.
            object.validate_structure().map_err(|err| {
                ObjectStoreError::Io(format!(
                    "invalid object structure in snapshot for {}: {err}",
                    object.object_id
                ))
            })?;
            // When a verifier is installed, enforce the content-id
            // binding on every snapshot entry. A forged snapshot
            // (restored-from-tampered-backup, malicious import) must
            // NOT survive load — the forged record is refused here and
            // surfaces as a hard `ContentIdMismatch` to the caller of
            // `DurableObjectStore::open_with_verifier`.
            if let Some(verifier) = verifier {
                verifier.verify(&object)?;
            }
            state.insert_loaded(object);
        }
        Ok(state)
    }

    fn to_snapshot(&self) -> ObjectSnapshot {
        let mut objects: Vec<_> = self.objects.values().cloned().collect();
        objects.sort_unstable_by_key(|object| object.object_id);
        ObjectSnapshot { objects }
    }

    fn insert_loaded(&mut self, object: StoredObject) {
        let object_id = object.object_id;
        let zone_id = object.header.zone_id.clone();
        self.used_bytes = self.used_bytes.saturating_add(Self::object_size(&object));
        self.zone_index.entry(zone_id).or_default().push(object_id);
        self.objects.insert(object_id, object);
    }

    fn validate_mutation(&self, op: &ObjectWalOp, max_bytes: u64) -> Result<(), ObjectStoreError> {
        match op {
            ObjectWalOp::Put(object) => {
                // Reject malformed or oversized objects before they reach
                // either the WAL or the in-memory map. Closes the gap that
                // bead flywheel_connectors-4g0qr documented: a peer (or
                // any process with WAL write access) could previously
                // smuggle in a `Put` whose `body` exceeds
                // `MAX_CANONICAL_OBJECT_BYTES` or whose `header` is not
                // canonically encodable. Full content-ID verification
                // requires the zone's `ObjectIdKey` and is the runtime
                // caller's responsibility.
                object.validate_structure().map_err(|err| {
                    ObjectStoreError::Io(format!("invalid object structure: {err}"))
                })?;
                if self.objects.contains_key(&object.object_id) {
                    return Err(ObjectStoreError::AlreadyExists(object.object_id));
                }
                let size = Self::object_size(object);
                if self.used_bytes.saturating_add(size) > max_bytes {
                    return Err(ObjectStoreError::QuotaExceeded {
                        used: self.used_bytes,
                        max: max_bytes,
                    });
                }
                Ok(())
            }
            ObjectWalOp::Delete { object_id } | ObjectWalOp::SetRetention { object_id, .. } => {
                if self.objects.contains_key(object_id) {
                    Ok(())
                } else {
                    Err(ObjectStoreError::NotFound(*object_id))
                }
            }
        }
    }

    fn apply_loaded_mutation(&mut self, op: ObjectWalOp) -> Result<(), ObjectStoreError> {
        match op {
            ObjectWalOp::Put(object) => {
                if self.objects.contains_key(&object.object_id) {
                    return Err(ObjectStoreError::AlreadyExists(object.object_id));
                }
                self.insert_loaded(*object);
                Ok(())
            }
            ObjectWalOp::Delete { object_id } => self.delete_unchecked(&object_id),
            ObjectWalOp::SetRetention {
                object_id,
                retention,
            } => self.set_retention_unchecked(&object_id, retention),
        }
    }

    fn delete_unchecked(&mut self, object_id: &ObjectId) -> Result<(), ObjectStoreError> {
        let object = self
            .objects
            .remove(object_id)
            .ok_or(ObjectStoreError::NotFound(*object_id))?;
        let zone_id = object.header.zone_id.clone();
        self.used_bytes = self.used_bytes.saturating_sub(Self::object_size(&object));
        let remove_zone_entry = if let Some(ids) = self.zone_index.get_mut(&zone_id) {
            ids.retain(|candidate| candidate != object_id);
            ids.is_empty()
        } else {
            false
        };
        if remove_zone_entry {
            self.zone_index.remove(&zone_id);
        }
        Ok(())
    }

    fn set_retention_unchecked(
        &mut self,
        object_id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        let object = self
            .objects
            .get_mut(object_id)
            .ok_or(ObjectStoreError::NotFound(*object_id))?;
        object.storage.retention = retention;
        Ok(())
    }
}

impl DurableSymbolState {
    const fn symbol_size(symbol: &StoredSymbol) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let size = symbol.data.len() as u64 + 64;
        size
    }

    fn has_required_symbols(symbol_count: usize, source_symbols: u32) -> bool {
        u32::try_from(symbol_count).map_or(true, |count| count >= source_symbols)
    }

    fn symbol_matches_meta(meta: &ObjectSymbolMeta, symbol: &StoredSymbol) -> bool {
        symbol.meta.object_id == meta.object_id
            && symbol.meta.zone_id == meta.zone_id
            && symbol.data.len() == usize::from(meta.oti.symbol_size)
    }

    fn scrub_corrupt_symbols_locked(object: &mut DurableObjectSymbols) -> u64 {
        let mut removed_bytes = 0_u64;
        object.symbols.retain(|_, symbol| {
            let keep = Self::symbol_matches_meta(&object.meta, symbol);
            if !keep {
                removed_bytes = removed_bytes.saturating_add(Self::symbol_size(symbol));
            }
            keep
        });
        removed_bytes
    }

    fn scrub_corrupt_symbols(&mut self) -> u64 {
        let mut removed_bytes = 0_u64;
        for object in self.objects.values_mut() {
            removed_bytes =
                removed_bytes.saturating_add(Self::scrub_corrupt_symbols_locked(object));
        }
        self.used_bytes = self.used_bytes.saturating_sub(removed_bytes);
        removed_bytes
    }

    fn scrub_object_if_present(&mut self, object_id: &ObjectId) -> bool {
        let removed_bytes = {
            let Some(object) = self.objects.get_mut(object_id) else {
                return false;
            };
            Self::scrub_corrupt_symbols_locked(object)
        };

        // Keep the scrub and quota repair inside one state-lock scope so a
        // concurrent durable write cannot validate against stale `used_bytes`
        // after a read path removes corrupt symbols.
        if removed_bytes > 0 {
            self.used_bytes = self.used_bytes.saturating_sub(removed_bytes);
        }

        true
    }

    fn from_snapshot(snapshot: SymbolSnapshot) -> Result<Self, SymbolStoreError> {
        let mut state = Self::default();
        for entry in snapshot.objects {
            validate_source_symbols(&entry.meta)?;
            state.load_entry(entry);
        }
        state.scrub_corrupt_symbols();
        Ok(state)
    }

    fn to_snapshot(&self) -> SymbolSnapshot {
        let mut objects = self
            .objects
            .values()
            .map(|object| {
                let mut symbols: Vec<_> = object
                    .symbols
                    .values()
                    .map(|symbol| PersistentStoredSymbol {
                        meta: symbol.meta.clone(),
                        data: symbol.data.to_vec(),
                    })
                    .collect();
                symbols.sort_unstable_by_key(|symbol| symbol.meta.esi);
                SymbolSnapshotEntry {
                    meta: object.meta.clone(),
                    symbols,
                }
            })
            .collect::<Vec<_>>();
        objects.sort_unstable_by_key(|entry| entry.meta.object_id);
        SymbolSnapshot { objects }
    }

    fn load_entry(&mut self, entry: SymbolSnapshotEntry) {
        let mut symbols = HashMap::with_capacity(entry.symbols.len());
        let meta = entry.meta.clone();
        for symbol in entry.symbols {
            let stored = StoredSymbol {
                meta: symbol.meta,
                data: Bytes::from(symbol.data),
            };
            self.used_bytes = self.used_bytes.saturating_add(Self::symbol_size(&stored));
            symbols.insert(stored.meta.esi, stored);
        }
        self.objects
            .insert(meta.object_id, DurableObjectSymbols { meta, symbols });
    }

    fn validate_mutation(&self, op: &SymbolWalOp, max_bytes: u64) -> Result<(), SymbolStoreError> {
        match op {
            SymbolWalOp::PutObjectMeta(meta) => {
                validate_source_symbols(meta)?;
                if let Some(object) = self.objects.get(&meta.object_id) {
                    if object.meta != *meta {
                        return Err(SymbolStoreError::InvalidSymbol {
                            reason: format!("Metadata mismatch for object {}", meta.object_id),
                        });
                    }
                }
                Ok(())
            }
            SymbolWalOp::PutSymbol(symbol) => {
                let object = self
                    .objects
                    .get(&symbol.meta.object_id)
                    .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;
                let expected_size = usize::from(object.meta.oti.symbol_size);
                if symbol.data.len() != expected_size {
                    return Err(SymbolStoreError::InvalidSymbol {
                        reason: format!(
                            "Symbol size mismatch: expected {}, got {}",
                            expected_size,
                            symbol.data.len()
                        ),
                    });
                }
                if symbol.meta.zone_id != object.meta.zone_id {
                    return Err(SymbolStoreError::InvalidSymbol {
                        reason: format!(
                            "Symbol zone mismatch: expected {}, got {}",
                            object.meta.zone_id, symbol.meta.zone_id
                        ),
                    });
                }
                if let Some(existing) = object.symbols.get(&symbol.meta.esi) {
                    // Idempotent when bytes match; conflicting bytes signal a
                    // crafted-symbol forgery or on-wire corruption and must be
                    // surfaced instead of silently dropped (see symbol_store.rs
                    // put_symbol for the full threat model — silent drop would
                    // let a poisoned ESI block every honest later write and
                    // permanently deny repair).
                    if existing.data.as_ref() == symbol.data.as_slice() {
                        return Ok(());
                    }
                    return Err(SymbolStoreError::InvalidSymbol {
                        reason: format!(
                            "conflicting symbol for object {} esi {}: stored bytes differ from incoming",
                            symbol.meta.object_id, symbol.meta.esi
                        ),
                    });
                }
                let stored = StoredSymbol {
                    meta: symbol.meta.clone(),
                    data: Bytes::copy_from_slice(&symbol.data),
                };
                let size = Self::symbol_size(&stored);
                if self.used_bytes.saturating_add(size) > max_bytes {
                    return Err(SymbolStoreError::QuotaExceeded {
                        used: self.used_bytes,
                        max: max_bytes,
                    });
                }
                Ok(())
            }
            SymbolWalOp::DeleteObject { object_id } => {
                if self.objects.contains_key(object_id) {
                    Ok(())
                } else {
                    Err(SymbolStoreError::ObjectNotFound(*object_id))
                }
            }
            SymbolWalOp::DeleteSymbol { object_id, esi } => {
                let object = self
                    .objects
                    .get(object_id)
                    .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
                if object.symbols.contains_key(esi) {
                    Ok(())
                } else {
                    Err(SymbolStoreError::NotFound {
                        object_id: *object_id,
                        esi: *esi,
                    })
                }
            }
        }
    }

    fn apply_loaded_mutation(&mut self, op: SymbolWalOp) -> Result<(), SymbolStoreError> {
        match op {
            SymbolWalOp::PutObjectMeta(meta) => self.apply_put_object_meta(meta),
            SymbolWalOp::PutSymbol(symbol) => self.apply_put_symbol(symbol),
            SymbolWalOp::DeleteObject { object_id } => self.apply_delete_object(&object_id),
            SymbolWalOp::DeleteSymbol { object_id, esi } => {
                self.apply_delete_symbol(&object_id, esi)
            }
        }
    }

    fn apply_put_object_meta(&mut self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        validate_source_symbols(&meta)?;
        if let Some(existing) = self.objects.get(&meta.object_id) {
            if existing.meta != meta {
                return Err(SymbolStoreError::InvalidSymbol {
                    reason: format!("Metadata mismatch for object {}", meta.object_id),
                });
            }
            return Ok(());
        }

        let object_id = meta.object_id;
        let source_symbols = meta.source_symbols;
        self.objects.insert(
            object_id,
            DurableObjectSymbols {
                meta,
                symbols: HashMap::with_capacity(source_symbols as usize),
            },
        );
        Ok(())
    }

    fn apply_put_symbol(&mut self, symbol: PersistentStoredSymbol) -> Result<(), SymbolStoreError> {
        let object = self
            .objects
            .get_mut(&symbol.meta.object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;
        if let Some(existing) = object.symbols.get(&symbol.meta.esi) {
            // Replay path: validate_mutation rejects conflicts before WAL
            // append, so a correctly-formed WAL only contains idempotent
            // duplicates. A bytewise mismatch here implies a replay against
            // a snapshot-plus-WAL sequence that contains corrupted or
            // tampered entries; treat as InvalidSymbol rather than silently
            // masking either the stored or the replayed payload.
            if existing.data.as_ref() == symbol.data.as_slice() {
                return Ok(());
            }
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "conflicting symbol for object {} esi {} during replay",
                    symbol.meta.object_id, symbol.meta.esi
                ),
            });
        }
        let stored = StoredSymbol {
            meta: symbol.meta,
            data: Bytes::from(symbol.data),
        };
        self.used_bytes = self.used_bytes.saturating_add(Self::symbol_size(&stored));
        object.symbols.insert(stored.meta.esi, stored);
        Ok(())
    }

    fn apply_delete_object(&mut self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        let object = self
            .objects
            .remove(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        let total_size: u64 = object.symbols.values().map(Self::symbol_size).sum();
        self.used_bytes = self.used_bytes.saturating_sub(total_size);
        Ok(())
    }

    fn apply_delete_symbol(
        &mut self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<(), SymbolStoreError> {
        let object = self
            .objects
            .get_mut(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        let symbol = object
            .symbols
            .remove(&esi)
            .ok_or(SymbolStoreError::NotFound {
                object_id: *object_id,
                esi,
            })?;
        self.used_bytes = self.used_bytes.saturating_sub(Self::symbol_size(&symbol));
        Ok(())
    }
}

impl DurableObjectStore {
    /// Open or create a crash-safe durable object store.
    ///
    /// # Errors
    /// Returns an error if the snapshot/WAL cannot be read or synced.
    pub fn open(config: DurableObjectStoreConfig) -> Result<Self, ObjectStoreError> {
        Self::open_with_verifier(config, None)
    }

    /// Open the durable store with an installed content-id verifier.
    ///
    /// The verifier is applied to every snapshot entry and every WAL
    /// record during replay, and to every runtime `put` thereafter.
    /// Any `StoredObject` whose claimed `object_id` does not match
    /// `derive_id(&header, &body, zone_key)` is rejected at the
    /// boundary — before it reaches the in-memory map. This is the
    /// concrete defense against the attacker-chosen-id injection
    /// vector from bead flywheel_connectors-4g0qr, where a process
    /// with WAL write access could previously inject a forged record
    /// that `apply_loaded_mutation` accepted without verification.
    ///
    /// Pass `None` to preserve the legacy "structural checks only"
    /// behaviour (equivalent to calling [`Self::open`]).
    ///
    /// # Errors
    /// Returns an error if the snapshot/WAL cannot be read or synced,
    /// or if any replayed record fails verification.
    pub fn open_with_verifier(
        config: DurableObjectStoreConfig,
        verifier: Option<Arc<dyn ObjectIdVerifier>>,
    ) -> Result<Self, ObjectStoreError> {
        fs::create_dir_all(&config.root_dir).map_err(object_io)?;
        sync_parent_dir(&config.root_dir).map_err(object_io)?;

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let (state, last_seq) =
            load_durable_object_state(&snapshot_path, &wal_path, verifier.as_deref())?;

        Ok(Self {
            state: Mutex::new(state),
            config,
            write_guard: Mutex::new(()),
            next_seq: AtomicU64::new(last_seq.saturating_add(1)),
            ops_since_checkpoint: AtomicU64::new(0),
            snapshot_path,
            wal_path,
            verifier,
        })
    }

    /// Force an immediate checkpoint and WAL compaction.
    ///
    /// # Errors
    /// Returns an error if the snapshot cannot be durably written.
    pub async fn checkpoint(&self) -> Result<(), ObjectStoreError> {
        let _guard = self.write_guard.lock().await;
        let last_seq = self.next_seq.load(Ordering::SeqCst).saturating_sub(1);
        self.checkpoint_locked(last_seq).await?;
        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
        Ok(())
    }

    async fn checkpoint_locked(&self, last_seq: u64) -> Result<(), ObjectStoreError> {
        let snapshot = self.state.lock().await.to_snapshot();
        write_snapshot_blocking(self.snapshot_path.clone(), last_seq, snapshot)
            .await
            .map_err(object_io)?;
        clear_wal_blocking(self.wal_path.clone())
            .await
            .map_err(object_io)?;
        Ok(())
    }

    async fn record_mutation(&self, op: ObjectWalOp) -> Result<(), ObjectStoreError> {
        let _guard = self.write_guard.lock().await;
        {
            // When a verifier is installed, enforce the content-id
            // binding at the runtime write boundary BEFORE structural
            // or duplicate-id checks. A forged `object_id` from an
            // in-process caller must surface as `ContentIdMismatch`,
            // not as `AlreadyExists` when the id happens to collide
            // with a legit record (flywheel_connectors-4g0qr).
            if let (Some(verifier), ObjectWalOp::Put(object)) = (self.verifier.as_ref(), &op) {
                verifier.verify(object)?;
            }
            self.state
                .lock()
                .await
                .validate_mutation(&op, self.config.max_bytes)?;
            // Reserve the seq but do not publish until the WAL append succeeds.
            // Advancing next_seq on a failed append leaves an irrecoverable gap
            // in the WAL sequence (load_wal_records rejects the gap at startup).
            let seq = self.next_seq.load(Ordering::SeqCst);
            append_wal_record_blocking(self.wal_path.clone(), seq, op.clone())
                .await
                .map_err(object_io)?;
            self.next_seq.store(seq.saturating_add(1), Ordering::SeqCst);
            self.state.lock().await.apply_loaded_mutation(op)?;

            if self.config.checkpoint_after_ops > 0 {
                let ops = self.ops_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
                if ops >= self.config.checkpoint_after_ops {
                    if let Err(error) = self.checkpoint_locked(seq).await {
                        tracing::warn!(error = %error, "durable object checkpoint failed after WAL sync");
                    } else {
                        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for DurableObjectStore {
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::Put(Box::new(object)))
            .await
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.state
            .lock()
            .await
            .objects
            .get(id)
            .cloned()
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.state.lock().await.objects.contains_key(id)
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::Delete { object_id: *id })
            .await
    }

    async fn get_header(&self, id: &ObjectId) -> Result<fcp_core::ObjectHeader, ObjectStoreError> {
        self.state
            .lock()
            .await
            .objects
            .get(id)
            .map(|object| object.header.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn get_storage_meta(
        &self,
        id: &ObjectId,
    ) -> Result<fcp_core::StorageMeta, ObjectStoreError> {
        self.state
            .lock()
            .await
            .objects
            .get(id)
            .map(|object| object.storage.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::SetRetention {
            object_id: *id,
            retention,
        })
        .await
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.state
            .lock()
            .await
            .zone_index
            .get(zone_id)
            .cloned()
            .unwrap_or_default()
    }

    async fn storage_used(&self) -> u64 {
        self.state.lock().await.used_bytes
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }
}

impl DurableSymbolStore {
    /// Open or create a crash-safe durable symbol store.
    ///
    /// # Errors
    /// Returns an error if the snapshot/WAL cannot be read or synced.
    pub fn open(config: DurableSymbolStoreConfig) -> Result<Self, SymbolStoreError> {
        fs::create_dir_all(&config.root_dir).map_err(symbol_io)?;
        sync_parent_dir(&config.root_dir).map_err(symbol_io)?;

        let snapshot_path = config.root_dir.join("symbols.snapshot.json");
        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let (state, last_seq) = load_durable_symbol_state(&snapshot_path, &wal_path)?;

        Ok(Self {
            state: ParkingRwLock::new(state),
            config,
            write_guard: ParkingMutex::new(()),
            next_seq: AtomicU64::new(last_seq.saturating_add(1)),
            ops_since_checkpoint: AtomicU64::new(0),
            snapshot_path,
            wal_path,
        })
    }

    /// Force an immediate checkpoint and WAL compaction.
    ///
    /// # Errors
    /// Returns an error if the snapshot cannot be durably written.
    pub fn checkpoint(&self) -> Result<(), SymbolStoreError> {
        let _guard = self.write_guard.lock();
        let last_seq = self.next_seq.load(Ordering::SeqCst).saturating_sub(1);
        self.checkpoint_locked(last_seq)?;
        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn checkpoint_locked(&self, last_seq: u64) -> Result<(), SymbolStoreError> {
        let snapshot = self.state.read().to_snapshot();
        write_snapshot(&self.snapshot_path, last_seq, &snapshot).map_err(symbol_io)?;
        clear_wal(&self.wal_path).map_err(symbol_io)?;
        Ok(())
    }

    fn record_mutation(&self, op: SymbolWalOp) -> Result<(), SymbolStoreError> {
        let _guard = self.write_guard.lock();
        {
            let mut state = self.state.write();
            state.validate_mutation(&op, self.config.max_bytes)?;
            // Reserve the seq but do not publish until the WAL append succeeds.
            // Advancing next_seq on a failed append leaves an irrecoverable gap
            // in the WAL sequence (load_wal_records rejects the gap at startup).
            let seq = self.next_seq.load(Ordering::SeqCst);
            append_wal_record(&self.wal_path, seq, &op).map_err(symbol_io)?;
            self.next_seq.store(seq.saturating_add(1), Ordering::SeqCst);
            state.apply_loaded_mutation(op)?;

            if self.config.checkpoint_after_ops > 0 {
                let ops = self.ops_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
                if ops >= self.config.checkpoint_after_ops {
                    drop(state);
                    if let Err(error) = self.checkpoint_locked(seq) {
                        tracing::warn!(error = %error, "durable symbol checkpoint failed after WAL sync");
                    } else {
                        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SymbolStore for DurableSymbolStore {
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::PutSymbol(PersistentStoredSymbol {
            meta: symbol.meta,
            data: symbol.data.to_vec(),
        }))
    }

    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::PutObjectMeta(meta))
    }

    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError> {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return Err(SymbolStoreError::ObjectNotFound(*object_id));
        }
        let symbol = state
            .objects
            .get(object_id)
            .and_then(|object| object.symbols.get(&esi))
            .cloned();
        drop(state);

        symbol.ok_or(SymbolStoreError::NotFound {
            object_id: *object_id,
            esi,
        })
    }

    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError> {
        self.state
            .read()
            .objects
            .get(object_id)
            .map(|object| object.meta.clone())
            .ok_or_else(|| SymbolStoreError::ObjectNotFound(*object_id))
    }

    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol> {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return Vec::new();
        }
        let mut symbols: Vec<_> = state
            .objects
            .get(object_id)
            .map(|object| object.symbols.values().cloned().collect())
            .unwrap_or_default();
        drop(state);

        symbols.sort_unstable_by_key(|symbol| symbol.meta.esi);
        symbols
    }

    async fn symbol_count(&self, object_id: &ObjectId) -> u32 {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return 0;
        }
        let count = state.objects.get(object_id).map_or(0, |object| {
            u32::try_from(object.symbols.len()).unwrap_or(u32::MAX)
        });
        drop(state);

        count
    }

    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::DeleteObject {
            object_id: *object_id,
        })
    }

    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::DeleteSymbol {
            object_id: *object_id,
            esi,
        })
    }

    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution> {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return None;
        }
        let object = state.objects.get(object_id)?;

        let mut distribution = SymbolDistribution::new(object.meta.source_symbols);
        for symbol in object.symbols.values() {
            let node_id = symbol.meta.source_node.unwrap_or(self.config.local_node_id);
            #[allow(clippy::cast_possible_truncation)]
            let size = symbol.data.len() as u64;
            distribution.add_symbol(node_id, size);
        }
        drop(state);

        Some(distribution)
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.state
            .read()
            .objects
            .values()
            .filter(|object| &object.meta.zone_id == zone_id)
            .map(|object| object.meta.object_id)
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        self.state.read().used_bytes
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }

    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return false;
        }
        let Some(object) = state.objects.get(object_id) else {
            return false;
        };
        let reconstructable = DurableSymbolState::has_required_symbols(
            object.symbols.len(),
            object.meta.source_symbols,
        );
        drop(state);

        reconstructable
    }

    async fn can_reconstruct_with_policy(
        &self,
        object_id: &ObjectId,
        policy: &ObjectPlacementPolicy,
    ) -> bool {
        if let Some(distribution) = self.get_distribution(object_id).await {
            let eval =
                crate::coverage::CoverageEvaluation::from_distribution(*object_id, &distribution);
            eval.meets_diversity_for_reconstruction(policy)
        } else {
            false
        }
    }
}

fn load_durable_object_state(
    snapshot_path: &Path,
    wal_path: &Path,
    verifier: Option<&dyn ObjectIdVerifier>,
) -> Result<(DurableObjectState, u64), ObjectStoreError> {
    let (mut state, last_snapshot_seq) =
        match read_snapshot::<ObjectSnapshot>(snapshot_path).map_err(object_io)? {
            Some((snapshot, seq)) => (DurableObjectState::from_snapshot(snapshot, verifier)?, seq),
            None => (DurableObjectState::default(), 0),
        };

    let records =
        read_wal_records::<ObjectWalOp>(wal_path, last_snapshot_seq).map_err(object_io)?;
    let mut last_seq = last_snapshot_seq;
    for record in records {
        last_seq = record.seq;
        // Mirror the runtime mutation path: validate the record's
        // structure (size cap + canonical-CBOR-encodable header) before
        // applying. Closes the WAL replay trust gap documented in bead
        // flywheel_connectors-4g0qr — `apply_loaded_mutation` alone
        // skips the structural check that `record_mutation` enforces
        // on the live write path.
        //
        // Order matters: run the content-id verifier BEFORE
        // `validate_mutation`'s duplicate-id check. A forged record
        // that happens to reuse a legit id would otherwise surface as
        // `AlreadyExists` (a correct but weaker signal) and hide the
        // real defect — the attacker substituted `(header, body)` for
        // the claimed id. The verifier failure is the more specific,
        // more actionable diagnosis.
        if let (Some(verifier), ObjectWalOp::Put(object)) = (verifier, &record.op) {
            verifier.verify(object)?;
        }
        state.validate_mutation(&record.op, u64::MAX)?;
        state.apply_loaded_mutation(record.op)?;
    }

    Ok((state, last_seq))
}

fn load_durable_symbol_state(
    snapshot_path: &Path,
    wal_path: &Path,
) -> Result<(DurableSymbolState, u64), SymbolStoreError> {
    let (mut state, last_snapshot_seq) =
        match read_snapshot::<SymbolSnapshot>(snapshot_path).map_err(symbol_io)? {
            Some((snapshot, seq)) => (DurableSymbolState::from_snapshot(snapshot)?, seq),
            None => (DurableSymbolState::default(), 0),
        };

    let records =
        read_wal_records::<SymbolWalOp>(wal_path, last_snapshot_seq).map_err(symbol_io)?;
    let mut last_seq = last_snapshot_seq;
    for record in records {
        last_seq = record.seq;
        // A WAL checksum only proves the record was not torn mid-write. It
        // does not prove the symbol payload still matches the object metadata,
        // so replay must re-run semantic validation before mutating state.
        state.validate_mutation(&record.op, u64::MAX)?;
        state.apply_loaded_mutation(record.op)?;
    }

    Ok((state, last_seq))
}

/// Bounded analogue of `BufRead::read_until` for the WAL recovery loop.
///
/// Reads bytes from `reader` into `buf` until `delim` is encountered
/// OR `max_bytes` would be exceeded. Returns `(bytes_read, hit_cap)`:
/// - `(n, false)` — record terminated naturally with `delim` (or EOF
///   before `delim` for `n > 0` — caller still treats as torn via the
///   parse step, since the envelope will not deserialize)
/// - `(n, true)` — `max_bytes` was reached without seeing `delim`;
///   caller should treat the record as torn and stop scanning
/// - `(0, false)` — clean EOF, no more records
fn read_until_bounded<R: BufRead>(
    reader: &mut R,
    delim: u8,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<(usize, bool)> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((total, false));
        }
        let available_len = available.len();
        let remaining = max_bytes.saturating_sub(total);
        if remaining == 0 {
            return Ok((total, true));
        }
        let scan_len = available_len.min(remaining);
        if let Some(pos) = available[..scan_len].iter().position(|&b| b == delim) {
            let take = pos + 1;
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            total = total.saturating_add(take);
            return Ok((total, false));
        }
        buf.extend_from_slice(&available[..scan_len]);
        reader.consume(scan_len);
        total = total.saturating_add(scan_len);
        if scan_len < available_len {
            // We exhausted the cap before the buffered window, but the
            // delimiter wasn't found in the inspected prefix. Signal cap.
            return Ok((total, true));
        }
    }
}

fn read_snapshot<T>(path: &Path) -> Result<Option<(T, u64)>, String>
where
    T: Serialize + DeserializeOwned,
{
    if !path.exists() {
        return Ok(None);
    }

    // Reject snapshot files larger than `MAX_SNAPSHOT_BYTES` before
    // allocating to avoid OOM on a corrupted or adversarial file.
    let metadata =
        fs::metadata(path).map_err(|error| format!("stat snapshot {}: {error}", path.display()))?;
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(format!(
            "snapshot {} exceeds {} bytes (got {})",
            path.display(),
            MAX_SNAPSHOT_BYTES,
            metadata.len()
        ));
    }

    let bytes =
        fs::read(path).map_err(|error| format!("read snapshot {}: {error}", path.display()))?;
    let envelope: SnapshotEnvelope<T> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse snapshot {}: {error}", path.display()))?;
    if envelope.version != SNAPSHOT_VERSION {
        return Err(format!(
            "unsupported snapshot version {} for {}",
            envelope.version,
            path.display()
        ));
    }
    let expected = checksum_json(&(envelope.version, envelope.last_seq, &envelope.payload))
        .map_err(|error| format!("checksum snapshot {}: {error}", path.display()))?;
    if expected != envelope.checksum {
        return Err(format!("snapshot checksum mismatch for {}", path.display()));
    }

    Ok(Some((envelope.payload, envelope.last_seq)))
}

fn read_wal_records<T>(path: &Path, min_seq: u64) -> Result<Vec<WalEnvelope<T>>, String>
where
    T: Serialize + DeserializeOwned,
{
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).map_err(|error| format!("open wal {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut raw = Vec::new();
    let mut valid_prefix_len = 0_u64;
    let mut last_seq_in_file = 0_u64;
    let mut expected_next_seq = min_seq.saturating_add(1);
    let mut records = Vec::new();
    let mut truncated = false;

    loop {
        raw.clear();
        let (bytes_read, hit_cap) =
            read_until_bounded(&mut reader, b'\n', &mut raw, MAX_WAL_RECORD_BYTES)
                .map_err(|error| format!("read wal {}: {error}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        if hit_cap {
            // Adversarial or torn record larger than `MAX_WAL_RECORD_BYTES`
            // — treat as a truncation point so recovery cannot be made to
            // OOM by a single oversized line. The on-disk file is then
            // truncated to the prior valid prefix, mirroring the behavior
            // for unparseable records.
            truncated = true;
            break;
        }

        let Ok(envelope) = serde_json::from_slice::<WalEnvelope<T>>(&raw) else {
            truncated = true;
            break;
        };

        if envelope.version != WAL_VERSION {
            truncated = true;
            break;
        }

        let expected = checksum_json(&(envelope.version, envelope.seq, &envelope.op))
            .map_err(|error| format!("checksum wal {}: {error}", path.display()))?;
        if expected != envelope.checksum || envelope.seq <= last_seq_in_file {
            truncated = true;
            break;
        }

        last_seq_in_file = envelope.seq;
        valid_prefix_len = valid_prefix_len.saturating_add(bytes_read as u64);

        if envelope.seq > min_seq {
            if envelope.seq != expected_next_seq {
                return Err(format!(
                    "wal sequence gap in {}: expected {}, found {}",
                    path.display(),
                    expected_next_seq,
                    envelope.seq
                ));
            }
            records.push(envelope);
            expected_next_seq = expected_next_seq.saturating_add(1);
        }
    }

    if truncated {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| format!("open wal for truncation {}: {error}", path.display()))?;
        file.set_len(valid_prefix_len)
            .map_err(|error| format!("truncate wal {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync truncated wal {}: {error}", path.display()))?;
        sync_parent_dir(path)
            .map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    }

    Ok(records)
}

fn append_wal_record<T>(path: &Path, seq: u64, op: &T) -> Result<(), String>
where
    T: Serialize,
{
    let checksum = checksum_json(&(WAL_VERSION, seq, op))
        .map_err(|error| format!("serialize wal checksum {}: {error}", path.display()))?;
    let envelope = WalEnvelope {
        version: WAL_VERSION,
        seq,
        checksum,
        op,
    };
    let mut bytes = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize wal {}: {error}", path.display()))?;
    bytes.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open wal {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .map_err(|error| format!("write wal {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync wal {}: {error}", path.display()))?;
    sync_parent_dir(path).map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    Ok(())
}

async fn append_wal_record_blocking<T>(path: PathBuf, seq: u64, op: T) -> Result<(), String>
where
    T: Serialize + Send + 'static,
{
    run_blocking_io("append durable object WAL record", move || {
        append_wal_record(&path, seq, &op)
    })
    .await
}

fn write_snapshot<T>(path: &Path, last_seq: u64, payload: &T) -> Result<(), String>
where
    T: Serialize + Clone,
{
    let checksum = checksum_json(&(SNAPSHOT_VERSION, last_seq, payload))
        .map_err(|error| format!("serialize snapshot checksum {}: {error}", path.display()))?;
    let envelope = SnapshotEnvelope {
        version: SNAPSHOT_VERSION,
        last_seq,
        checksum,
        payload: payload.clone(),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize snapshot {}: {error}", path.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid snapshot path {}", path.display()))?;
    let temp_file_name = format!("{file_name}.tmp.{}.{}", std::process::id(), last_seq);
    let (temp_path, mut file) = open_unique_snapshot_temp_file(path, &temp_file_name)?;
    file.write_all(&bytes)
        .map_err(|error| format!("write temp snapshot {}: {error}", temp_path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync temp snapshot {}: {error}", temp_path.display()))?;
    drop(file);

    fs::rename(&temp_path, path).map_err(|error| {
        format!(
            "rename snapshot {} -> {}: {error}",
            temp_path.display(),
            path.display()
        )
    })?;
    sync_parent_dir(path)
        .map_err(|error| format!("sync snapshot dir {}: {error}", path.display()))?;
    Ok(())
}

async fn write_snapshot_blocking<T>(path: PathBuf, last_seq: u64, payload: T) -> Result<(), String>
where
    T: Serialize + Clone + Send + 'static,
{
    run_blocking_io("write durable object snapshot", move || {
        write_snapshot(&path, last_seq, &payload)
    })
    .await
}

fn open_unique_snapshot_temp_file(path: &Path, base_name: &str) -> Result<(PathBuf, File), String> {
    const MAX_TEMP_FILE_RETRIES: u32 = 32;

    for suffix in 0..=MAX_TEMP_FILE_RETRIES {
        let candidate = if suffix == 0 {
            path.with_file_name(base_name)
        } else {
            path.with_file_name(format!("{base_name}.{suffix}"))
        };

        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "create temp snapshot {}: {error}",
                    candidate.display()
                ));
            }
        }
    }

    Err(format!(
        "create temp snapshot {}: exhausted unique-name retries for {base_name}",
        path.display()
    ))
}

fn clear_wal(path: &Path) -> Result<(), String> {
    let file =
        File::create(path).map_err(|error| format!("truncate wal {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync cleared wal {}: {error}", path.display()))?;
    sync_parent_dir(path).map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    Ok(())
}

async fn clear_wal_blocking(path: PathBuf) -> Result<(), String> {
    run_blocking_io("clear durable object WAL", move || clear_wal(&path)).await
}

async fn run_blocking_io<T, F>(operation: &'static str, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|error| format!("{operation} task failed: {error}"))?
}

fn checksum_json<T: Serialize>(value: &T) -> Result<[u8; 32], serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

#[cfg(not(windows))]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn object_io(error: impl ToString) -> ObjectStoreError {
    ObjectStoreError::Io(error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn symbol_io(error: impl ToString) -> SymbolStoreError {
    SymbolStoreError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::symbol_store::ObjectTransmissionInfo;
    use fcp_prelude::{ObjectHeader, Provenance, StorageMeta};
    use tempfile::TempDir;

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    const fn test_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn test_schema() -> fcp_cbor::SchemaId {
        fcp_cbor::SchemaId::new(
            "fcp.test",
            "DurableStoreObject",
            semver::Version::new(1, 0, 0),
        )
    }

    fn test_object(seed: u8) -> StoredObject {
        let zone = test_zone();
        StoredObject {
            object_id: test_object_id(seed),
            header: ObjectHeader {
                schema: test_schema(),
                zone_id: zone.clone(),
                created_at: 42,
                provenance: Provenance::new(zone),
                refs: Vec::new(),
                foreign_refs: Vec::new(),
                ttl_secs: None,
                placement: None,
            },
            body: vec![seed; 96],
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        }
    }

    fn test_symbol_meta(seed: u8) -> ObjectSymbolMeta {
        ObjectSymbolMeta {
            object_id: test_object_id(seed),
            zone_id: test_zone(),
            oti: ObjectTransmissionInfo {
                transfer_length: 2048,
                symbol_size: 128,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            },
            source_symbols: 4,
            first_symbol_at: 100,
        }
    }

    fn test_symbol(seed: u8, esi: u32, source_node: u64) -> StoredSymbol {
        StoredSymbol {
            meta: SymbolMeta {
                object_id: test_object_id(seed),
                esi,
                zone_id: test_zone(),
                source_node: Some(source_node),
                stored_at: 100 + u64::from(esi),
            },
            data: Bytes::from(vec![seed.wrapping_add(esi as u8); 128]),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_recovers_after_restart() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 64;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        let object_id = test_object_id(1);
        store.put(test_object(1)).await.expect("put object");
        store
            .set_retention(&object_id, RetentionClass::Lease { expires_at: 777 })
            .await
            .expect("set retention");
        store.put(test_object(2)).await.expect("put second object");
        store
            .delete(&test_object_id(2))
            .await
            .expect("delete second object");
        drop(store);

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        let recovered = reopened.get(&object_id).await.expect("get recovered");
        assert_eq!(recovered.body, test_object(1).body);
        assert!(matches!(
            recovered.storage.retention,
            RetentionClass::Lease { expires_at: 777 }
        ));
        assert!(matches!(
            reopened.get(&test_object_id(2)).await,
            Err(ObjectStoreError::NotFound(_))
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_counts_canonical_header_in_quota() {
        // Durable quota accounting must mirror MemoryObjectStore. The old
        // body-plus-512 estimate let tiny-body objects with large ref lists
        // bypass max_bytes by moving their cost into the canonical header.
        let temp_dir = TempDir::new().expect("temp dir");
        let mut header_heavy = test_object(9);
        header_heavy.body.clear();
        header_heavy.header.refs = (0_u8..=u8::MAX)
            .cycle()
            .take(512)
            .map(|seed| ObjectId::from_bytes([seed; 32]))
            .collect();

        let actual_size = DurableObjectState::object_size(&header_heavy);
        assert!(
            actual_size > 4_096,
            "canonical header-heavy object must cost > 4 KiB, got {actual_size}"
        );

        #[allow(clippy::cast_possible_truncation)]
        let old_estimate = header_heavy.body.len() as u64 + 512;
        assert!(
            actual_size > old_estimate * 8,
            "canonical accounting must dominate the old 512-byte estimate; actual={actual_size} old={old_estimate}"
        );

        let mut rejected_config = DurableObjectStoreConfig::new(temp_dir.path().join("reject"));
        rejected_config.max_bytes = actual_size - 1;
        let rejected_store = DurableObjectStore::open(rejected_config).expect("open reject store");
        let result = rejected_store.put(header_heavy.clone()).await;
        assert!(
            matches!(result, Err(ObjectStoreError::QuotaExceeded { .. })),
            "header-heavy object must be rejected when quota < canonical cost, got {result:?}"
        );

        let mut exact_config = DurableObjectStoreConfig::new(temp_dir.path().join("exact"));
        exact_config.max_bytes = actual_size;
        let exact_store = DurableObjectStore::open(exact_config).expect("open exact store");
        exact_store
            .put(header_heavy)
            .await
            .expect("exact-fit quota must accept the object");
    }

    #[fcp_async_core::runtime::test]
    async fn wal_replay_rejects_oversized_object_body() {
        // Regression for flywheel_connectors-4g0qr: WAL replay used to call
        // `apply_loaded_mutation` directly without `validate_mutation`, so
        // a forged WAL record with `body.len() > MAX_CANONICAL_OBJECT_BYTES`
        // would be admitted into the in-memory map. After the fix,
        // recovery must reject the forged record (the WAL is then truncated
        // by the surrounding torn-WAL handling).
        use std::io::Write;

        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path());
        config.max_bytes = u64::MAX;

        // 1) Open + put a legitimate object so we have a valid WAL prefix.
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(1)).await.expect("put legit object");
        drop(store);

        // 2) Construct a forged StoredObject whose body exceeds the
        //    canonical-bytes cap. `validate_structure` must reject this.
        let mut forged = test_object(2);
        forged.body = vec![0u8; fcp_cbor::MAX_CANONICAL_OBJECT_BYTES + 1];
        assert!(
            forged.validate_structure().is_err(),
            "structural check must reject oversized body"
        );

        // 3) Append the forged record to the object WAL with the correct
        //    checksum so the bytes-on-disk look authentic.
        let wal_path = temp_dir.path().join("objects.wal.jsonl");
        let op = ObjectWalOp::Put(Box::new(forged));
        let checksum = checksum_json(&(WAL_VERSION, 2u64, &op)).expect("compute forged checksum");
        let envelope = WalEnvelope {
            version: WAL_VERSION,
            seq: 2u64,
            checksum,
            op: &op,
        };
        let mut bytes = serde_json::to_vec(&envelope).expect("serialize forged envelope");
        bytes.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        file.write_all(&bytes).expect("append forged record");
        drop(file);

        // 4) Reopen. The fix must reject the forged record at recovery.
        match DurableObjectStore::open(config) {
            Ok(store) => {
                // If recovery succeeded (e.g. WAL truncation discarded the
                // bad tail), the forged object MUST NOT be present.
                assert!(
                    matches!(
                        store.get(&test_object_id(2)).await,
                        Err(ObjectStoreError::NotFound(_))
                    ),
                    "forged oversized object must not be recovered"
                );
            }
            Err(ObjectStoreError::Io(msg)) => {
                assert!(
                    msg.contains("invalid object structure"),
                    "expected structural-validation error, got: {msg}"
                );
            }
            Err(other) => panic!("unexpected error during recovery: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn wal_replay_with_verifier_rejects_forged_object_id() {
        // Regression for flywheel_connectors-4g0qr: a process with
        // WAL write access can append an `ObjectWalOp::Put(StoredObject {
        // object_id: H, header: H', body: B' })` where `(H', B')` are
        // NOT the canonical bytes behind `H`. The WAL checksum covers
        // only the outer `(version, seq, op)` tuple, so the on-disk
        // integrity check accepts the forged bytes. Without the
        // content-id verifier, `load_durable_object_state` would
        // `insert_loaded` the forged record and any subsequent
        // `get(H)` would return attacker-controlled `(H', B')`.
        // With a verifier installed, reopen must fail closed on the
        // forged record.
        use std::io::Write;

        use crate::object_id_verifier::KeyedObjectIdVerifier;
        use fcp_prelude::ObjectIdKey;

        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path());
        config.max_bytes = u64::MAX;

        // Zone key material the verifier will use.
        let zone = test_zone();
        let zone_key = ObjectIdKey::from_bytes([0xC3u8; 32]);

        // Helper: build a StoredObject whose object_id is the canonical
        // derive_id(header, body, zone_key) — i.e. a record that WOULD
        // verify cleanly if replayed under the matching verifier.
        let genuine = |seed: u8, body: &[u8]| -> StoredObject {
            let header = ObjectHeader {
                schema: test_schema(),
                zone_id: zone.clone(),
                created_at: 100,
                provenance: Provenance::new(zone.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            };
            let id = StoredObject::derive_id(&header, body, &zone_key).expect("derive id");
            let _ = seed; // only here to let callers pass distinct bodies
            StoredObject {
                object_id: id,
                header,
                body: body.to_vec(),
                storage: StorageMeta {
                    retention: RetentionClass::Pinned,
                },
            }
        };

        // 1) Open without a verifier and write one legitimate record so
        //    the WAL has a valid seq-1 prefix and the dir layout is
        //    initialized.
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        let legit = genuine(1, b"legit-body");
        store.put(legit.clone()).await.expect("put legit");
        drop(store);

        // 2) Construct a forged WAL record: claim `object_id =
        //    legit.object_id` but ship a different body. A verifier
        //    for `zone_key` will compute `derive_id(header, B',
        //    zone_key)` != `legit.object_id` and reject.
        let mut forged = genuine(2, b"attacker-body");
        let legit_id = legit.object_id;
        forged.object_id = legit_id;

        let wal_path = temp_dir.path().join("objects.wal.jsonl");
        let op = ObjectWalOp::Put(Box::new(forged));
        let checksum = checksum_json(&(WAL_VERSION, 2u64, &op)).expect("compute forged checksum");
        let envelope = WalEnvelope {
            version: WAL_VERSION,
            seq: 2u64,
            checksum,
            op: &op,
        };
        let mut bytes = serde_json::to_vec(&envelope).expect("serialize forged envelope");
        bytes.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        file.write_all(&bytes).expect("append forged record");
        drop(file);

        // 3) Reopen WITH the verifier. Must fail on the forged record.
        let mut verifier = KeyedObjectIdVerifier::default();
        verifier.insert(zone.clone(), zone_key);
        let result =
            DurableObjectStore::open_with_verifier(config.clone(), Some(verifier.into_arc()));
        match result {
            Err(ObjectStoreError::ContentIdMismatch { claimed, computed }) => {
                assert_eq!(claimed, legit_id, "forged record claimed the legit id");
                assert_ne!(
                    computed, legit_id,
                    "computed id over forged body must differ from claimed id"
                );
            }
            Err(ObjectStoreError::AlreadyExists(id)) => {
                // Defense-in-depth: `apply_loaded_mutation` rejects a
                // duplicate id. That path ALSO prevents the forged
                // record from overwriting the legit one, but it is NOT
                // the content-id defense — this branch fails the test
                // to force the verifier to be the detection path.
                panic!(
                    "forged record was caught only by dup-detection ({id}), \
                     verifier did not reject first as expected"
                );
            }
            Err(other) => panic!("unexpected error on recovery: {other:?}"),
            Ok(_) => panic!("forged WAL record was accepted despite verifier"),
        }

        // 4) Sanity: reopen WITHOUT the verifier to confirm the WAL
        //    record really is on disk (i.e., step 2 wrote bytes that
        //    the legacy code path would have admitted). The dup
        //    check still rejects since the legit seq-1 record holds
        //    the id — which is exactly why the bead notes the attack
        //    is more effective when the attacker deletes the
        //    legitimate record or starts from a pristine store.
        let _ = DurableObjectStore::open(config);
    }

    #[test]
    fn read_until_bounded_caps_oversized_record_without_oom() {
        // Regression for flywheel_connectors-yhmwv: WAL recovery used
        // `BufRead::read_until` which has no upper bound on buffer growth.
        // A torn write or adversarial WAL containing a single line larger
        // than `MAX_WAL_RECORD_BYTES` would allocate the entire line into
        // memory before the parse step rejected it. The bounded reader
        // must signal `hit_cap = true` and stop without growing past the
        // cap.
        use std::io::Cursor;

        let cap = 64usize;

        // Case 1: input has a newline within the cap → returns the record
        // and `hit_cap = false`.
        let normal = b"hello\nworld\n".to_vec();
        let mut reader = Cursor::new(normal);
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read normal");
        assert_eq!(n, 6);
        assert!(!capped);
        assert_eq!(buf, b"hello\n");

        // Case 2: single record larger than cap, no newline within first
        // `cap` bytes → returns `hit_cap = true` and `buf.len() <= cap`.
        let oversized: Vec<u8> = std::iter::repeat_n(b'A', cap * 4).collect();
        let mut reader = Cursor::new(oversized);
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read oversized");
        assert!(capped, "oversized record must signal hit_cap");
        assert!(
            buf.len() <= cap,
            "buffer must not grow past cap (got {})",
            buf.len()
        );
        assert_eq!(n, buf.len());

        // Case 3: empty input → clean EOF, no cap signal.
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read empty");
        assert_eq!(n, 0);
        assert!(!capped);
        assert!(buf.is_empty());

        // Case 4: record EXACTLY at the cap including the delimiter is
        // accepted as a normal record, not capped.
        let mut exact = vec![b'X'; cap - 1];
        exact.push(b'\n');
        let mut reader = Cursor::new(exact);
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read exact-cap");
        assert!(!capped, "record exactly at cap must not be flagged");
        assert_eq!(n, cap);
        assert_eq!(buf.len(), cap);
        assert_eq!(buf.last(), Some(&b'\n'));
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_truncates_torn_wal_tail() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 0;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(7)).await.expect("put object");
        drop(store);

        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let valid_len = fs::metadata(&wal_path).expect("wal metadata").len();
        let mut wal = OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        wal.write_all(br#"{"version":1,"seq":"broken"#)
            .expect("append torn tail");
        wal.sync_all().expect("sync torn tail");
        drop(wal);

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        assert!(reopened.exists(&test_object_id(7)).await);
        let truncated_len = fs::metadata(&wal_path)
            .expect("wal metadata after reopen")
            .len();
        assert_eq!(truncated_len, valid_len, "corrupt tail should be truncated");
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_auto_checkpoint_compacts_wal() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 1;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(3)).await.expect("put object");
        drop(store);

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        assert!(
            snapshot_path.exists(),
            "snapshot should exist after checkpoint"
        );
        assert_eq!(
            fs::metadata(&wal_path).expect("wal metadata").len(),
            0,
            "checkpoint should compact wal"
        );

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        assert!(reopened.exists(&test_object_id(3)).await);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_checkpoint_retries_past_stale_snapshot_temp_file() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 0;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        let object = test_object(13);
        let object_id = object.object_id;
        store.put(object.clone()).await.expect("put object");

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let stale_temp = snapshot_path.with_file_name(format!(
            "objects.snapshot.json.tmp.{}.1",
            std::process::id()
        ));
        fs::write(&stale_temp, b"stale snapshot temp").expect("write stale temp");

        store
            .checkpoint()
            .await
            .expect("checkpoint should ignore orphaned temp file names");
        assert!(
            snapshot_path.exists(),
            "checkpoint should still materialize the durable snapshot"
        );

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        let recovered = reopened.get(&object_id).await.expect("recover object");
        assert_eq!(recovered.body, object.body);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_conflicting_esi() {
        // Regression: silent first-write-wins on ESI let a crafted symbol
        // block all later honest writes and permanently deny repair for
        // the target object. Durable validate_mutation + apply_put_symbol
        // must reject bytewise conflicts before touching the WAL.
        let temp_dir = TempDir::new().expect("temp dir");
        let config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        let store = DurableSymbolStore::open(config).expect("open symbol store");
        store
            .put_object_meta(test_symbol_meta(9))
            .await
            .expect("put meta");
        let honest = test_symbol(9, 0, 2);
        store.put_symbol(honest.clone()).await.expect("put honest");

        // Idempotent resubmission.
        store
            .put_symbol(honest.clone())
            .await
            .expect("identical resubmission must remain idempotent");

        // Conflict → InvalidSymbol, not silent drop.
        let forged = StoredSymbol {
            meta: honest.meta.clone(),
            data: Bytes::from(vec![0xAA_u8; 128]),
        };
        let result = store.put_symbol(forged).await;
        assert!(
            matches!(&result, Err(SymbolStoreError::InvalidSymbol { reason }) if reason.contains("conflicting")),
            "expected InvalidSymbol with conflicting reason, got {result:?}"
        );

        let fetched = store
            .get_symbol(&test_object_id(9), 0)
            .await
            .expect("fetch honest");
        assert_eq!(fetched.data, honest.data);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_oversized_source_symbols() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        let store = DurableSymbolStore::open(config).expect("open symbol store");

        let mut poisoned = test_symbol_meta(12);
        poisoned.source_symbols = u32::MAX;
        let result = store.put_object_meta(poisoned).await;
        assert!(
            matches!(result, Err(SymbolStoreError::InvalidSymbol { .. })),
            "durable meta writes must reject oversized source_symbols before allocation, got {result:?}"
        );

        let mut zero = test_symbol_meta(13);
        zero.source_symbols = 0;
        let result = store.put_object_meta(zero).await;
        assert!(
            matches!(result, Err(SymbolStoreError::InvalidSymbol { .. })),
            "durable meta writes must reject zero source_symbols, got {result:?}"
        );

        assert!(
            store.list_zone(&test_zone()).await.is_empty(),
            "rejected metadata must not create durable symbol objects"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_invalid_snapshot_source_symbols() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        fs::create_dir_all(&config.root_dir).expect("create root dir");
        let snapshot_path = config.root_dir.join("symbols.snapshot.json");

        let mut invalid_meta = test_symbol_meta(14);
        invalid_meta.source_symbols = 0;
        let snapshot = SymbolSnapshot {
            objects: vec![SymbolSnapshotEntry {
                meta: invalid_meta,
                symbols: Vec::new(),
            }],
        };
        write_snapshot(&snapshot_path, 1, &snapshot).expect("write invalid snapshot");

        match DurableSymbolStore::open(config) {
            Err(SymbolStoreError::InvalidSymbol { .. }) => {}
            Err(other) => {
                panic!("expected InvalidSymbol for invalid source_symbols, got {other:?}")
            }
            Ok(_) => panic!("expected recovery to reject invalid source_symbols"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_semantically_invalid_wal_on_recovery() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.checkpoint_after_ops = 0;

        let store = DurableSymbolStore::open(config.clone()).expect("open symbol store");
        store
            .put_object_meta(test_symbol_meta(10))
            .await
            .expect("put meta");
        drop(store);

        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let forged = PersistentStoredSymbol {
            meta: test_symbol(10, 0, 5).meta,
            data: vec![0xAB; 7],
        };
        append_wal_record(&wal_path, 2, &SymbolWalOp::PutSymbol(forged)).expect("append wal");

        match DurableSymbolStore::open(config) {
            Err(SymbolStoreError::InvalidSymbol { reason }) => {
                assert!(
                    reason.contains("Symbol size mismatch"),
                    "expected size mismatch, got {reason}"
                );
            }
            Err(other) => panic!("expected InvalidSymbol, got {other:?}"),
            Ok(_) => panic!("expected reopen to fail on invalid replayed symbol"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_open_scrubs_invalid_snapshot_symbols_before_quota_checks() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.max_bytes = 256;
        config.checkpoint_after_ops = 0;

        fs::create_dir_all(&config.root_dir).expect("create root dir");
        let snapshot_path = config.root_dir.join("symbols.snapshot.json");
        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        clear_wal(&wal_path).expect("clear wal");

        let object_meta = test_symbol_meta(11);
        let invalid_symbol = PersistentStoredSymbol {
            meta: SymbolMeta {
                object_id: object_meta.object_id,
                esi: 0,
                zone_id: object_meta.zone_id.clone(),
                source_node: Some(7),
                stored_at: 100,
            },
            data: vec![0xCD; 200],
        };
        let snapshot = SymbolSnapshot {
            objects: vec![SymbolSnapshotEntry {
                meta: object_meta,
                symbols: vec![invalid_symbol],
            }],
        };
        write_snapshot(&snapshot_path, 0, &snapshot).expect("write snapshot");

        let reopened = DurableSymbolStore::open(config).expect("open symbol store");
        assert_eq!(
            reopened.storage_used().await,
            0,
            "invalid snapshot symbol should be scrubbed"
        );

        reopened
            .put_symbol(test_symbol(11, 0, 7))
            .await
            .expect("honest symbol should fit once invalid bytes are scrubbed");
        assert_eq!(reopened.symbol_count(&test_object_id(11)).await, 1);
    }

    #[test]
    fn durable_symbol_state_scrub_repairs_used_bytes_in_same_lock_scope() {
        let meta = test_symbol_meta(12);
        let valid = test_symbol(12, 0, 9);
        let valid_size = DurableSymbolState::symbol_size(&valid);

        let mut state = DurableSymbolState::default();
        state
            .apply_put_object_meta(meta.clone())
            .expect("object meta should load");
        state
            .apply_put_symbol(PersistentStoredSymbol {
                meta: valid.meta.clone(),
                data: valid.data.to_vec(),
            })
            .expect("valid symbol should load");

        let corrupt = StoredSymbol {
            meta: SymbolMeta {
                object_id: meta.object_id,
                esi: 99,
                zone_id: meta.zone_id.clone(),
                source_node: Some(99),
                stored_at: 99,
            },
            data: Bytes::from(vec![0xAB; usize::from(meta.oti.symbol_size) - 1]),
        };
        let corrupt_size = DurableSymbolState::symbol_size(&corrupt);
        state.used_bytes = state.used_bytes.saturating_add(corrupt_size);
        state
            .objects
            .get_mut(&meta.object_id)
            .expect("object must exist")
            .symbols
            .insert(corrupt.meta.esi, corrupt);

        assert_eq!(
            state.used_bytes,
            valid_size + corrupt_size,
            "setup should include the invalid symbol in used_bytes"
        );

        assert!(
            state.scrub_object_if_present(&meta.object_id),
            "object should still be present"
        );
        assert_eq!(
            state.used_bytes, valid_size,
            "scrub must repair quota accounting before releasing the state lock"
        );
        assert_eq!(
            state
                .objects
                .get(&meta.object_id)
                .expect("object should remain")
                .symbols
                .len(),
            1,
            "corrupt symbol should be removed"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_recovers_after_restart() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.checkpoint_after_ops = 64;
        config.local_node_id = 9;

        let store = DurableSymbolStore::open(config.clone()).expect("open symbol store");
        let object_id = test_object_id(5);
        store
            .put_object_meta(test_symbol_meta(5))
            .await
            .expect("put meta");
        store
            .put_symbol(test_symbol(5, 0, 2))
            .await
            .expect("put symbol 0");
        store
            .put_symbol(test_symbol(5, 1, 3))
            .await
            .expect("put symbol 1");
        drop(store);

        let reopened = DurableSymbolStore::open(config).expect("reopen symbol store");
        let meta = reopened
            .get_object_meta(&object_id)
            .await
            .expect("get meta");
        assert_eq!(meta.source_symbols, 4);
        assert_eq!(reopened.symbol_count(&object_id).await, 2);
        let distribution = reopened
            .get_distribution(&object_id)
            .await
            .expect("distribution");
        assert_eq!(distribution.total_symbols, 2);
        assert_eq!(distribution.distinct_nodes(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_truncates_torn_wal_tail() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.checkpoint_after_ops = 0;

        let store = DurableSymbolStore::open(config.clone()).expect("open symbol store");
        store
            .put_object_meta(test_symbol_meta(8))
            .await
            .expect("put meta");
        store
            .put_symbol(test_symbol(8, 0, 4))
            .await
            .expect("put symbol");
        drop(store);

        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let valid_len = fs::metadata(&wal_path).expect("wal metadata").len();
        let mut wal = OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        wal.write_all(br#"{"version":1,"seq":999"#)
            .expect("append torn tail");
        wal.sync_all().expect("sync torn tail");
        drop(wal);

        let reopened = DurableSymbolStore::open(config).expect("reopen symbol store");
        assert_eq!(reopened.symbol_count(&test_object_id(8)).await, 1);
        let truncated_len = fs::metadata(&wal_path)
            .expect("wal metadata after reopen")
            .len();
        assert_eq!(truncated_len, valid_len, "corrupt tail should be truncated");
    }
}
