//! Garbage collection for FCP2 stores (NORMATIVE).
//!
//! Implements reachability-based GC from `FCP_Specification_V2.md` §3.7.

use std::collections::{HashSet, VecDeque};

use fcp_core::{ObjectId, RetentionClass, ZoneId};
use serde::{Deserialize, Serialize};

use crate::error::GcError;
use crate::error::SymbolStoreError;
use crate::object_store::ObjectStore;
use crate::symbol_store::SymbolStore;

/// Result of a garbage collection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcResult {
    /// Number of live (reachable) objects.
    pub live: usize,
    /// Number of objects evicted.
    pub evicted: usize,
    /// Number of objects with expired leases.
    pub expired_leases: usize,
    /// Number of pinned objects (never evicted).
    pub pinned: usize,
}

/// GC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    /// Maximum objects to evict per GC run (prevents long pauses).
    pub max_evictions_per_run: usize,
    /// Whether to respect lease expiry times.
    pub enforce_lease_expiry: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            max_evictions_per_run: 10_000,
            enforce_lease_expiry: true,
        }
    }
}

/// GC root sources.
#[derive(Debug, Clone)]
pub struct GcRoots {
    /// Zone checkpoint object ID (canonical zone root).
    pub zone_checkpoint: Option<ObjectId>,
    /// Locally pinned objects.
    pub pinned: HashSet<ObjectId>,
}

impl GcRoots {
    /// Create empty GC roots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            zone_checkpoint: None,
            pinned: HashSet::new(),
        }
    }

    /// Set the zone checkpoint root.
    pub const fn set_checkpoint(&mut self, checkpoint: ObjectId) {
        self.zone_checkpoint = Some(checkpoint);
    }

    /// Add a pinned root.
    pub fn add_pin(&mut self, object_id: ObjectId) {
        self.pinned.insert(object_id);
    }

    /// Remove a pinned root.
    pub fn remove_pin(&mut self, object_id: &ObjectId) {
        self.pinned.remove(object_id);
    }

    /// Check if an object is a root.
    #[must_use]
    pub fn is_root(&self, object_id: &ObjectId) -> bool {
        self.zone_checkpoint.as_ref() == Some(object_id) || self.pinned.contains(object_id)
    }

    /// Get all root object IDs.
    #[must_use]
    pub fn all_roots(&self) -> HashSet<ObjectId> {
        let mut roots = self.pinned.clone();
        if let Some(checkpoint) = &self.zone_checkpoint {
            roots.insert(*checkpoint);
        }
        roots
    }
}

impl Default for GcRoots {
    fn default() -> Self {
        Self::new()
    }
}

/// Garbage collector for a zone.
pub struct GarbageCollector {
    config: GcConfig,
}

impl GarbageCollector {
    /// Create a new garbage collector.
    #[must_use]
    pub const fn new(config: GcConfig) -> Self {
        Self { config }
    }

    /// Run garbage collection on a zone (NORMATIVE algorithm).
    ///
    /// # Algorithm
    /// 1. Compute root set from zone checkpoint + local pins
    /// 2. Mark phase: traverse refs from roots
    /// 3. Sweep phase: evict unreachable non-pinned objects
    ///
    /// # Errors
    /// Returns error if object store operations fail.
    pub async fn collect(
        &self,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        current_time: u64,
    ) -> Result<GcResult, GcError> {
        let (result, _) = self
            .collect_internal(zone_id, roots, store, current_time)
            .await?;
        Ok(result)
    }

    /// Run GC and prune matching symbols from the symbol store.
    ///
    /// This ensures evicted objects cannot leave orphaned symbols behind.
    ///
    /// # Errors
    /// Returns error if object store or symbol store operations fail.
    pub async fn collect_and_prune_symbols(
        &self,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        symbol_store: &dyn SymbolStore,
        current_time: u64,
    ) -> Result<GcResult, GcError> {
        let (result, evicted_ids) = self
            .collect_internal(zone_id, roots, store, current_time)
            .await?;

        for object_id in evicted_ids {
            match symbol_store.delete_object(&object_id).await {
                Ok(()) | Err(SymbolStoreError::ObjectNotFound(_)) => {}
                Err(err) => return Err(GcError::SymbolStore(err)),
            }
        }

        Ok(result)
    }

    async fn collect_internal(
        &self,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        current_time: u64,
    ) -> Result<(GcResult, Vec<ObjectId>), GcError> {
        // 1. Compute root set
        let root_set = roots.all_roots();

        // 2. Mark phase: traverse refs from roots
        let mut live = HashSet::new();
        let mut queue: VecDeque<ObjectId> = root_set.into_iter().collect();

        while let Some(object_id) = queue.pop_front() {
            if live.insert(object_id) {
                if let Ok(header) = store.get_header(&object_id).await {
                    // Follow refs (NOT foreign_refs - those are handled by foreign zone's GC)
                    queue.extend(header.refs.iter().copied());
                }
            }
        }

        // 3. Sweep phase: evict unreachable non-pinned objects
        let mut evicted = 0;
        let mut expired_leases = 0;
        let mut pinned_count = 0;
        let mut evicted_ids = Vec::new();

        let all_objects = store.list_zone(zone_id).await;

        for object_id in all_objects {
            if evicted >= self.config.max_evictions_per_run {
                break; // Limit evictions per run
            }

            if live.contains(&object_id) {
                // Reachable objects are never evicted.
                continue;
            }

            // Object is unreachable
            if let Ok(meta) = store.get_storage_meta(&object_id).await {
                match meta.retention {
                    RetentionClass::Pinned => {
                        // Never evict pinned objects
                        pinned_count += 1;
                    }
                    RetentionClass::Lease { expires_at } => {
                        if (!self.config.enforce_lease_expiry || expires_at <= current_time)
                            && store.delete(&object_id).await.is_ok()
                        {
                            evicted += 1;
                            evicted_ids.push(object_id);
                            if expires_at <= current_time {
                                expired_leases += 1;
                            }
                        }
                    }
                    RetentionClass::Ephemeral => {
                        if store.delete(&object_id).await.is_ok() {
                            evicted += 1;
                            evicted_ids.push(object_id);
                        }
                    }
                }
            }
        }

        Ok((
            GcResult {
                live: live.len(),
                evicted,
                expired_leases,
                pinned: pinned_count,
            },
            evicted_ids,
        ))
    }

    /// Check if an object would be collected (for debugging/testing).
    pub async fn would_collect(
        &self,
        object_id: &ObjectId,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        current_time: u64,
    ) -> bool {
        // Check if object is a root
        if roots.is_root(object_id) {
            return false;
        }

        // Check if pinned
        if let Ok(meta) = store.get_storage_meta(object_id).await {
            if matches!(meta.retention, RetentionClass::Pinned) {
                return false;
            }

            // Check lease
            if let RetentionClass::Lease { expires_at } = meta.retention {
                if self.config.enforce_lease_expiry && expires_at > current_time {
                    // Valid lease blocks collection even if unreachable.
                    return false;
                }
            }
        }

        // Check reachability from roots
        let root_set = roots.all_roots();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<ObjectId> = root_set.into_iter().collect();

        while let Some(id) = queue.pop_front() {
            if &id == object_id {
                return false; // Found path to object
            }

            if visited.insert(id) {
                if let Ok(header) = store.get_header(&id).await {
                    // Only check if in same zone
                    if &header.zone_id == zone_id {
                        queue.extend(header.refs.iter().copied());
                    }
                }
            }
        }

        true // Not reachable, would be collected
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use bytes::Bytes;
    use chrono::Utc;
    use fcp_cbor::SchemaId;
    use fcp_core::{ObjectHeader, Provenance, StorageMeta, StoredObject};
    use semver::Version;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::object_store::{MemoryObjectStore, MemoryObjectStoreConfig};
    use crate::symbol_store::{
        MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
        StoredSymbol, SymbolMeta,
    };

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
        object_size: Option<u64>,
        symbol_count: Option<u32>,
        coverage_bps: Option<u32>,
        nodes_holding: Option<Vec<String>>,
        details: Option<serde_json::Value>,
    }

    fn run_store_test<F, Fut>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
    where
        F: FnOnce() -> Fut + panic::UnwindSafe,
        Fut: std::future::Future<Output = StoreLogData>,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            fcp_async_core::runtime::block_on_sync(f()).expect("runtime")
        }));
        let duration_us = start.elapsed().as_micros();

        let (passed, failed, outcome, data) = match &result {
            Ok(data) => (assertions, 0, "pass", Some(data)),
            Err(_) => (0, assertions, "fail", None),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-store",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_us": duration_us,
            "object_id": data.and_then(|d| d.object_id).map(|id| id.to_string()),
            "object_size": data.and_then(|d| d.object_size),
            "symbol_count": data.and_then(|d| d.symbol_count),
            "coverage_bps": data.and_then(|d| d.coverage_bps),
            "nodes_holding": data.and_then(|d| d.nodes_holding.clone()),
            "details": data.and_then(|d| d.details.clone()),
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            panic::resume_unwind(payload);
        }
    }

    fn log_gc_event(object_id: ObjectId, retention: &str, reason: &str) {
        let log = json!({
            "gc_action": "evict",
            "object_id": object_id.to_string(),
            "retention_class": retention,
            "reason": reason,
            "gc_root_checked": true
        });
        println!("{log}");
    }

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_object(id: u8, refs: Vec<u8>, retention: RetentionClass) -> StoredObject {
        StoredObject {
            object_id: ObjectId::from_bytes([id; 32]),
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
                zone_id: test_zone(),
                created_at: 1_000_000,
                provenance: Provenance::new(test_zone()),
                refs: refs
                    .into_iter()
                    .map(|r| ObjectId::from_bytes([r; 32]))
                    .collect(),
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            body: vec![0_u8; 100],
            storage: StorageMeta { retention },
        }
    }

    #[test]
    fn gc_evicts_unreachable() {
        run_store_test("gc_evicts_unreachable", "verify", "gc", 5, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(1, vec![2], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(2, vec![3], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(3, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(4, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.live, 3);
            assert_eq!(result.evicted, 1);

            assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
            assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);
            assert!(store.exists(&ObjectId::from_bytes([3; 32])).await);
            assert!(!store.exists(&ObjectId::from_bytes([4; 32])).await);

            log_gc_event(ObjectId::from_bytes([4; 32]), "Ephemeral", "UNREACHABLE");

            StoreLogData {
                object_id: Some(ObjectId::from_bytes([4; 32])),
                details: Some(json!({"live": result.live, "evicted": result.evicted})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_respects_pinned() {
        run_store_test("gc_respects_pinned", "verify", "gc", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(1, vec![], RetentionClass::Pinned))
                .await
                .unwrap();

            let roots = GcRoots::new();

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.pinned, 1);
            assert_eq!(result.evicted, 0);
            assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);

            StoreLogData {
                object_id: Some(ObjectId::from_bytes([1; 32])),
                details: Some(json!({"pinned": result.pinned})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_respects_lease() {
        run_store_test("gc_respects_lease", "verify", "gc", 4, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(
                    1,
                    vec![],
                    RetentionClass::Lease { expires_at: 2000 },
                ))
                .await
                .unwrap();
            store
                .put(test_object(
                    2,
                    vec![],
                    RetentionClass::Lease { expires_at: 500 },
                ))
                .await
                .unwrap();

            let roots = GcRoots::new();

            let result = gc
                .collect(&test_zone(), &roots, &store, 1000)
                .await
                .unwrap();

            assert_eq!(result.evicted, 1);
            assert_eq!(result.expired_leases, 1);
            assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
            assert!(!store.exists(&ObjectId::from_bytes([2; 32])).await);

            log_gc_event(ObjectId::from_bytes([2; 32]), "Lease", "LEASE_EXPIRED");

            StoreLogData {
                object_id: Some(ObjectId::from_bytes([2; 32])),
                details: Some(json!({"expired_leases": result.expired_leases})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_keeps_reachable_lease() {
        run_store_test("gc_keeps_reachable_lease", "verify", "gc", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            let id = ObjectId::from_bytes([1; 32]);
            store
                .put(test_object(
                    1,
                    vec![],
                    RetentionClass::Lease { expires_at: 500 },
                ))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            roots.set_checkpoint(id);

            let result = gc
                .collect(&test_zone(), &roots, &store, 1000)
                .await
                .unwrap();

            assert_eq!(result.evicted, 0);
            assert_eq!(result.expired_leases, 0);
            assert!(store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"evicted": result.evicted, "reachable": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_respects_max_evictions() {
        run_store_test("gc_respects_max_evictions", "verify", "gc", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let config = GcConfig {
                max_evictions_per_run: 2,
                ..Default::default()
            };
            let gc = GarbageCollector::new(config);

            for i in 1..=5 {
                store
                    .put(test_object(i, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
            }

            let roots = GcRoots::new();

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.evicted, 2);

            StoreLogData {
                details: Some(json!({"evicted": result.evicted})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_roots_management() {
        run_store_test("gc_roots_management", "verify", "gc", 4, || async {
            let mut roots = GcRoots::new();

            let id1 = ObjectId::from_bytes([1; 32]);
            let id2 = ObjectId::from_bytes([2; 32]);
            let id3 = ObjectId::from_bytes([3; 32]);

            roots.set_checkpoint(id1);
            roots.add_pin(id2);
            roots.add_pin(id3);

            assert!(roots.is_root(&id1));
            assert!(roots.is_root(&id2));
            assert!(roots.is_root(&id3));

            let all = roots.all_roots();
            assert_eq!(all.len(), 3);

            roots.remove_pin(&id2);
            assert!(!roots.is_root(&id2));

            StoreLogData {
                details: Some(json!({"root_count": all.len()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_prunes_symbol_store() {
        run_store_test("gc_prunes_symbol_store", "verify", "gc", 5, || async {
            let object_store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            let zone_id = test_zone();
            let object_id = ObjectId::from_bytes([5; 32]);

            object_store
                .put(test_object(5, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let meta = ObjectSymbolMeta {
                object_id,
                zone_id: zone_id.clone(),
                oti: ObjectTransmissionInfo {
                    transfer_length: 256,
                    symbol_size: 64,
                    source_blocks: 1,
                    sub_blocks: 1,
                    alignment: 8,
                },
                source_symbols: 4,
                first_symbol_at: 1_000_000,
            };
            symbol_store.put_object_meta(meta).await.unwrap();

            for esi in 0..4 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 1_000_000 + u64::from(esi),
                    },
                    data: Bytes::from(vec![0_u8; 64]),
                };
                symbol_store.put_symbol(symbol).await.unwrap();
            }

            let roots = GcRoots::new();
            let result = gc
                .collect_and_prune_symbols(&zone_id, &roots, &object_store, &symbol_store, 0)
                .await
                .unwrap();

            assert_eq!(result.evicted, 1);
            assert!(!object_store.exists(&object_id).await);
            assert!(matches!(
                symbol_store.get_object_meta(&object_id).await,
                Err(SymbolStoreError::ObjectNotFound(_))
            ));
            assert!(matches!(
                symbol_store.get_symbol(&object_id, 0).await,
                Err(SymbolStoreError::ObjectNotFound(_) | SymbolStoreError::NotFound { .. })
            ));

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(4),
                details: Some(json!({"symbols_pruned": true, "evicted": result.evicted})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn would_collect_unreachable() {
        run_store_test("would_collect_unreachable", "verify", "gc", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(1, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(2, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

            assert!(
                !gc.would_collect(
                    &ObjectId::from_bytes([1; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    0
                )
                .await
            );

            assert!(
                gc.would_collect(
                    &ObjectId::from_bytes([2; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    0
                )
                .await
            );

            StoreLogData {
                object_id: Some(ObjectId::from_bytes([2; 32])),
                details: Some(json!({"reachable": false})),
                ..StoreLogData::default()
            }
        });
    }
}
