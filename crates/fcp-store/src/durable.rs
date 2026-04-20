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
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use fcp_core::{ObjectId, ObjectPlacementPolicy, RetentionClass, StoredObject, ZoneId};
use parking_lot::{Mutex, RwLock};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::coverage::SymbolDistribution;
use crate::error::{ObjectStoreError, SymbolStoreError};
use crate::object_store::{MemoryObjectStoreConfig, ObjectStore};
use crate::symbol_store::{
    MemorySymbolStoreConfig, ObjectSymbolMeta, StoredSymbol, SymbolMeta, SymbolStore,
};

const SNAPSHOT_VERSION: u32 = 1;
const WAL_VERSION: u32 = 1;
const DEFAULT_CHECKPOINT_AFTER_OPS: u64 = 64;

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
    Put(StoredObject),
    Delete {
        object_id: ObjectId,
    },
    SetRetention {
        object_id: ObjectId,
        retention: RetentionClass,
    },
}

pub struct DurableObjectStore {
    state: RwLock<DurableObjectState>,
    config: DurableObjectStoreConfig,
    write_guard: Mutex<()>,
    next_seq: AtomicU64,
    ops_since_checkpoint: AtomicU64,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
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
    state: RwLock<DurableSymbolState>,
    config: DurableSymbolStoreConfig,
    write_guard: Mutex<()>,
    next_seq: AtomicU64,
    ops_since_checkpoint: AtomicU64,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
}

impl DurableObjectState {
    fn object_size(object: &StoredObject) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let size = object.body.len() as u64 + 512;
        size
    }

    fn from_snapshot(snapshot: ObjectSnapshot) -> Self {
        let mut state = Self::default();
        for object in snapshot.objects {
            state.insert_loaded(object);
        }
        state
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
                self.insert_loaded(object);
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
        let mut remove_zone_entry = false;
        if let Some(ids) = self.zone_index.get_mut(&zone_id) {
            ids.retain(|candidate| candidate != object_id);
            remove_zone_entry = ids.is_empty();
        }
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
    fn symbol_size(symbol: &StoredSymbol) -> u64 {
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

    fn from_snapshot(snapshot: SymbolSnapshot) -> Self {
        let mut state = Self::default();
        for entry in snapshot.objects {
            state.load_entry(entry);
        }
        state
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
        if let Some(existing) = self.objects.get(&meta.object_id) {
            if existing.meta != meta {
                return Err(SymbolStoreError::InvalidSymbol {
                    reason: format!("Metadata mismatch for object {}", meta.object_id),
                });
            }
            return Ok(());
        }

        self.objects.insert(
            meta.object_id,
            DurableObjectSymbols {
                meta: meta.clone(),
                symbols: HashMap::with_capacity(meta.source_symbols as usize),
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
        fs::create_dir_all(&config.root_dir).map_err(object_io)?;
        sync_parent_dir(&config.root_dir).map_err(object_io)?;

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let (state, last_seq) = load_durable_object_state(&snapshot_path, &wal_path)?;

        Ok(Self {
            state: RwLock::new(state),
            config,
            write_guard: Mutex::new(()),
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
    pub fn checkpoint(&self) -> Result<(), ObjectStoreError> {
        let _guard = self.write_guard.lock();
        let last_seq = self.next_seq.load(Ordering::SeqCst).saturating_sub(1);
        self.checkpoint_locked(last_seq)?;
        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn checkpoint_locked(&self, last_seq: u64) -> Result<(), ObjectStoreError> {
        let snapshot = self.state.read().to_snapshot();
        write_snapshot(&self.snapshot_path, last_seq, &snapshot).map_err(object_io)?;
        clear_wal(&self.wal_path).map_err(object_io)?;
        Ok(())
    }

    fn record_mutation(&self, op: ObjectWalOp) -> Result<(), ObjectStoreError> {
        let _guard = self.write_guard.lock();
        {
            let mut state = self.state.write();
            state.validate_mutation(&op, self.config.max_bytes)?;
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            append_wal_record(&self.wal_path, seq, &op).map_err(object_io)?;
            state.apply_loaded_mutation(op)?;

            if self.config.checkpoint_after_ops > 0 {
                let ops = self.ops_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
                if ops >= self.config.checkpoint_after_ops {
                    drop(state);
                    if let Err(error) = self.checkpoint_locked(seq) {
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
        self.record_mutation(ObjectWalOp::Put(object))
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.state
            .read()
            .objects
            .get(id)
            .cloned()
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.state.read().objects.contains_key(id)
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::Delete { object_id: *id })
    }

    async fn get_header(&self, id: &ObjectId) -> Result<fcp_core::ObjectHeader, ObjectStoreError> {
        self.state
            .read()
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
            .read()
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
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.state
            .read()
            .zone_index
            .get(zone_id)
            .cloned()
            .unwrap_or_default()
    }

    async fn storage_used(&self) -> u64 {
        self.state.read().used_bytes
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
            state: RwLock::new(state),
            config,
            write_guard: Mutex::new(()),
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
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            append_wal_record(&self.wal_path, seq, &op).map_err(symbol_io)?;
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
        let object = state
            .objects
            .get_mut(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        let removed_bytes = DurableSymbolState::scrub_corrupt_symbols_locked(object);
        let symbol = object.symbols.get(&esi).cloned();
        drop(state);

        if removed_bytes > 0 {
            let mut state = self.state.write();
            state.used_bytes = state.used_bytes.saturating_sub(removed_bytes);
        }

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
        let Some(object) = state.objects.get_mut(object_id) else {
            return Vec::new();
        };
        let removed_bytes = DurableSymbolState::scrub_corrupt_symbols_locked(object);
        let mut symbols: Vec<_> = object.symbols.values().cloned().collect();
        drop(state);

        if removed_bytes > 0 {
            let mut state = self.state.write();
            state.used_bytes = state.used_bytes.saturating_sub(removed_bytes);
        }

        symbols.sort_unstable_by_key(|symbol| symbol.meta.esi);
        symbols
    }

    async fn symbol_count(&self, object_id: &ObjectId) -> u32 {
        let mut state = self.state.write();
        let Some(object) = state.objects.get_mut(object_id) else {
            return 0;
        };
        let removed_bytes = DurableSymbolState::scrub_corrupt_symbols_locked(object);
        let count = u32::try_from(object.symbols.len()).unwrap_or(u32::MAX);
        drop(state);

        if removed_bytes > 0 {
            let mut state = self.state.write();
            state.used_bytes = state.used_bytes.saturating_sub(removed_bytes);
        }

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
        let object = state.objects.get_mut(object_id)?;
        let removed_bytes = DurableSymbolState::scrub_corrupt_symbols_locked(object);

        let mut distribution = SymbolDistribution::new(object.meta.source_symbols);
        for symbol in object.symbols.values() {
            let node_id = symbol.meta.source_node.unwrap_or(self.config.local_node_id);
            #[allow(clippy::cast_possible_truncation)]
            let size = symbol.data.len() as u64;
            distribution.add_symbol(node_id, size);
        }
        drop(state);

        if removed_bytes > 0 {
            let mut state = self.state.write();
            state.used_bytes = state.used_bytes.saturating_sub(removed_bytes);
        }

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
        let Some(object) = state.objects.get_mut(object_id) else {
            return false;
        };
        let removed_bytes = DurableSymbolState::scrub_corrupt_symbols_locked(object);
        let reconstructable = DurableSymbolState::has_required_symbols(
            object.symbols.len(),
            object.meta.source_symbols,
        );
        drop(state);

        if removed_bytes > 0 {
            let mut state = self.state.write();
            state.used_bytes = state.used_bytes.saturating_sub(removed_bytes);
        }

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
) -> Result<(DurableObjectState, u64), ObjectStoreError> {
    let (mut state, last_snapshot_seq) =
        match read_snapshot::<ObjectSnapshot>(snapshot_path).map_err(object_io)? {
            Some((snapshot, seq)) => (DurableObjectState::from_snapshot(snapshot), seq),
            None => (DurableObjectState::default(), 0),
        };

    let records =
        read_wal_records::<ObjectWalOp>(wal_path, last_snapshot_seq).map_err(object_io)?;
    let mut last_seq = last_snapshot_seq;
    for record in records {
        last_seq = record.seq;
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
            Some((snapshot, seq)) => (DurableSymbolState::from_snapshot(snapshot), seq),
            None => (DurableSymbolState::default(), 0),
        };

    let records =
        read_wal_records::<SymbolWalOp>(wal_path, last_snapshot_seq).map_err(symbol_io)?;
    let mut last_seq = last_snapshot_seq;
    for record in records {
        last_seq = record.seq;
        state.apply_loaded_mutation(record.op)?;
    }

    Ok((state, last_seq))
}

fn read_snapshot<T>(path: &Path) -> Result<Option<(T, u64)>, String>
where
    T: Serialize + DeserializeOwned,
{
    if !path.exists() {
        return Ok(None);
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
        let bytes_read = reader
            .read_until(b'\n', &mut raw)
            .map_err(|error| format!("read wal {}: {error}", path.display()))?;
        if bytes_read == 0 {
            break;
        }

        let envelope: WalEnvelope<T> = match serde_json::from_slice(&raw) {
            Ok(envelope) => envelope,
            Err(_) => {
                truncated = true;
                break;
            }
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
    let temp_path = path.with_file_name(format!(
        "{file_name}.tmp.{}.{}",
        std::process::id(),
        last_seq
    ));

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|error| format!("create temp snapshot {}: {error}", temp_path.display()))?;
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

fn clear_wal(path: &Path) -> Result<(), String> {
    let file =
        File::create(path).map_err(|error| format!("truncate wal {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync cleared wal {}: {error}", path.display()))?;
    sync_parent_dir(path).map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    Ok(())
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

fn object_io(error: impl ToString) -> ObjectStoreError {
    ObjectStoreError::Io(error.to_string())
}

fn symbol_io(error: impl ToString) -> SymbolStoreError {
    SymbolStoreError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::symbol_store::ObjectTransmissionInfo;
    use fcp_core::{ObjectHeader, Provenance, StorageMeta};
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
