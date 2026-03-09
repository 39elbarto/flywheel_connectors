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

    // --- Additional GC tests ---

    #[test]
    fn gc_config_default() {
        let config = GcConfig::default();
        assert_eq!(config.max_evictions_per_run, 10_000);
        assert!(config.enforce_lease_expiry);
    }

    #[test]
    fn gc_result_serde_roundtrip() {
        let result = GcResult {
            live: 10,
            evicted: 3,
            expired_leases: 1,
            pinned: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: GcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.live, 10);
        assert_eq!(deserialized.evicted, 3);
        assert_eq!(deserialized.expired_leases, 1);
        assert_eq!(deserialized.pinned, 2);
    }

    #[test]
    fn gc_result_clone() {
        let result = GcResult {
            live: 5,
            evicted: 2,
            expired_leases: 0,
            pinned: 1,
        };
        let cloned = result.clone();
        assert_eq!(cloned.live, result.live);
        assert_eq!(cloned.evicted, result.evicted);
    }

    #[test]
    fn gc_roots_new_is_empty() {
        let roots = GcRoots::new();
        assert!(roots.zone_checkpoint.is_none());
        assert!(roots.pinned.is_empty());
        assert_eq!(roots.all_roots().len(), 0);
    }

    #[test]
    fn gc_roots_default_same_as_new() {
        let new = GcRoots::new();
        let default = GcRoots::default();
        assert_eq!(new.zone_checkpoint, default.zone_checkpoint);
        assert_eq!(new.pinned.len(), default.pinned.len());
    }

    #[test]
    fn gc_roots_is_root_non_root() {
        let roots = GcRoots::new();
        let id = ObjectId::from_bytes([99; 32]);
        assert!(!roots.is_root(&id));
    }

    #[test]
    fn gc_roots_checkpoint_is_root() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([1; 32]);
        roots.set_checkpoint(id);
        assert!(roots.is_root(&id));
    }

    #[test]
    fn gc_roots_pin_is_root() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([2; 32]);
        roots.add_pin(id);
        assert!(roots.is_root(&id));
    }

    #[test]
    fn gc_roots_remove_pin_no_longer_root() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([3; 32]);
        roots.add_pin(id);
        assert!(roots.is_root(&id));
        roots.remove_pin(&id);
        assert!(!roots.is_root(&id));
    }

    #[test]
    fn gc_roots_all_roots_includes_checkpoint_and_pins() {
        let mut roots = GcRoots::new();
        let cp = ObjectId::from_bytes([1; 32]);
        let pin1 = ObjectId::from_bytes([2; 32]);
        let pin2 = ObjectId::from_bytes([3; 32]);
        roots.set_checkpoint(cp);
        roots.add_pin(pin1);
        roots.add_pin(pin2);
        let all = roots.all_roots();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&cp));
        assert!(all.contains(&pin1));
        assert!(all.contains(&pin2));
    }

    #[test]
    fn gc_roots_duplicate_pin_idempotent() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([4; 32]);
        roots.add_pin(id);
        roots.add_pin(id);
        assert_eq!(roots.pinned.len(), 1);
    }

    #[test]
    fn gc_roots_remove_nonexistent_pin_noop() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([5; 32]);
        roots.remove_pin(&id); // Should not panic
        assert!(roots.pinned.is_empty());
    }

    #[test]
    fn gc_collect_empty_store() {
        run_store_test("gc_collect_empty_store", "verify", "gc", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());
            let roots = GcRoots::new();

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.live, 0);
            assert_eq!(result.evicted, 0);
            assert_eq!(result.pinned, 0);

            StoreLogData {
                details: Some(json!({"empty_store": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_collect_all_ephemeral_no_roots() {
        run_store_test(
            "gc_collect_all_ephemeral_no_roots",
            "verify",
            "gc",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                for i in 1..=3 {
                    store
                        .put(test_object(i, vec![], RetentionClass::Ephemeral))
                        .await
                        .unwrap();
                }

                let roots = GcRoots::new();
                let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

                assert_eq!(result.live, 0);
                assert_eq!(result.evicted, 3);

                StoreLogData {
                    details: Some(json!({"evicted_all": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn gc_lease_expiry_disabled() {
        run_store_test("gc_lease_expiry_disabled", "verify", "gc", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let config = GcConfig {
                enforce_lease_expiry: false,
                ..Default::default()
            };
            let gc = GarbageCollector::new(config);

            // Object with future lease — should still be evicted when enforce_lease_expiry=false
            store
                .put(test_object(
                    1,
                    vec![],
                    RetentionClass::Lease { expires_at: 9999 },
                ))
                .await
                .unwrap();

            let roots = GcRoots::new();
            let result = gc.collect(&test_zone(), &roots, &store, 100).await.unwrap();

            assert_eq!(result.evicted, 1);
            assert!(!store.exists(&ObjectId::from_bytes([1; 32])).await);

            StoreLogData {
                details: Some(json!({"lease_expiry_disabled": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_collect_with_ref_chain() {
        run_store_test("gc_collect_with_ref_chain", "verify", "gc", 4, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            // Chain: 1 -> 2 -> 3
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
            // Disconnected: 4 -> 5
            store
                .put(test_object(4, vec![5], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(5, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.live, 3); // 1,2,3 reachable
            assert_eq!(result.evicted, 2); // 4,5 evicted
            assert!(store.exists(&ObjectId::from_bytes([3; 32])).await);
            assert!(!store.exists(&ObjectId::from_bytes([4; 32])).await);

            StoreLogData {
                details: Some(json!({"chain": "1->2->3", "evicted": "4,5"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_config_clone_and_debug() {
        let config = GcConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.max_evictions_per_run, config.max_evictions_per_run);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GcConfig"));
    }

    #[test]
    fn gc_prunes_symbol_store_nonexistent_ok() {
        run_store_test(
            "gc_prunes_symbol_nonexistent",
            "verify",
            "gc",
            2,
            || async {
                let object_store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                // Object in object store but NOT in symbol store
                object_store
                    .put(test_object(1, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();

                let roots = GcRoots::new();
                let result = gc
                    .collect_and_prune_symbols(
                        &test_zone(),
                        &roots,
                        &object_store,
                        &symbol_store,
                        0,
                    )
                    .await
                    .unwrap();

                assert_eq!(result.evicted, 1);
                assert!(!object_store.exists(&ObjectId::from_bytes([1; 32])).await);

                StoreLogData {
                    details: Some(json!({"symbol_store_empty": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn would_collect_pinned_object() {
        run_store_test("would_collect_pinned", "verify", "gc", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(1, vec![], RetentionClass::Pinned))
                .await
                .unwrap();

            let roots = GcRoots::new();

            // Pinned object should NOT be collected
            assert!(
                !gc.would_collect(
                    &ObjectId::from_bytes([1; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    0,
                )
                .await
            );

            StoreLogData {
                details: Some(json!({"pinned": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn would_collect_valid_lease() {
        run_store_test("would_collect_valid_lease", "verify", "gc", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(
                    1,
                    vec![],
                    RetentionClass::Lease { expires_at: 9999 },
                ))
                .await
                .unwrap();

            let roots = GcRoots::new();

            // Valid lease should NOT be collected
            assert!(
                !gc.would_collect(
                    &ObjectId::from_bytes([1; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    100,
                )
                .await
            );

            StoreLogData {
                details: Some(json!({"valid_lease": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn would_collect_expired_lease() {
        run_store_test("would_collect_expired_lease", "verify", "gc", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            store
                .put(test_object(
                    1,
                    vec![],
                    RetentionClass::Lease { expires_at: 50 },
                ))
                .await
                .unwrap();

            let roots = GcRoots::new();

            // Expired lease, unreachable → should be collected
            assert!(
                gc.would_collect(
                    &ObjectId::from_bytes([1; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    100,
                )
                .await
            );

            StoreLogData {
                details: Some(json!({"expired_lease": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn would_collect_root_object() {
        run_store_test("would_collect_root_object", "verify", "gc", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            let id = ObjectId::from_bytes([1; 32]);
            store
                .put(test_object(1, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            roots.set_checkpoint(id);

            // Root object should NOT be collected
            assert!(!gc.would_collect(&id, &test_zone(), &roots, &store, 0).await);

            StoreLogData {
                details: Some(json!({"is_root": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_config_serde_roundtrip() {
        let config = GcConfig {
            max_evictions_per_run: 42,
            enforce_lease_expiry: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: GcConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_evictions_per_run, 42);
        assert!(!deserialized.enforce_lease_expiry);
    }

    #[test]
    fn gc_result_debug() {
        let result = GcResult {
            live: 1,
            evicted: 2,
            expired_leases: 3,
            pinned: 4,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("GcResult"));
        assert!(dbg.contains("live: 1"));
    }

    #[test]
    fn gc_roots_clone() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([7; 32]);
        roots.set_checkpoint(id);
        roots.add_pin(ObjectId::from_bytes([8; 32]));

        let cloned = roots.clone();
        assert_eq!(cloned.zone_checkpoint, roots.zone_checkpoint);
        assert_eq!(cloned.pinned.len(), roots.pinned.len());
    }

    #[test]
    fn gc_roots_debug() {
        let roots = GcRoots::new();
        let dbg = format!("{roots:?}");
        assert!(dbg.contains("GcRoots"));
    }

    #[test]
    fn gc_roots_all_roots_only_checkpoint() {
        let mut roots = GcRoots::new();
        let cp = ObjectId::from_bytes([10; 32]);
        roots.set_checkpoint(cp);
        let all = roots.all_roots();
        assert_eq!(all.len(), 1);
        assert!(all.contains(&cp));
    }

    #[test]
    fn gc_roots_all_roots_only_pins() {
        let mut roots = GcRoots::new();
        roots.add_pin(ObjectId::from_bytes([11; 32]));
        roots.add_pin(ObjectId::from_bytes([12; 32]));
        let all = roots.all_roots();
        assert_eq!(all.len(), 2);
        assert!(roots.zone_checkpoint.is_none());
    }

    #[test]
    fn gc_collect_with_only_pinned_roots() {
        run_store_test("gc_collect_pinned_roots", "verify", "gc", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            // Object 1 -> 2, Object 3 unreachable
            store
                .put(test_object(1, vec![2], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(2, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(3, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            // Use add_pin instead of set_checkpoint
            roots.add_pin(ObjectId::from_bytes([1; 32]));

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.live, 2); // 1 and 2 reachable
            assert_eq!(result.evicted, 1); // 3 evicted
            assert!(!store.exists(&ObjectId::from_bytes([3; 32])).await);

            StoreLogData {
                details: Some(json!({"pinned_roots": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_collect_mixed_retention_types() {
        run_store_test("gc_mixed_retention", "verify", "gc", 4, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            // All unreachable, but different retention classes
            store
                .put(test_object(1, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(2, vec![], RetentionClass::Pinned))
                .await
                .unwrap();
            store
                .put(test_object(
                    3,
                    vec![],
                    RetentionClass::Lease { expires_at: 9999 },
                ))
                .await
                .unwrap();
            store
                .put(test_object(
                    4,
                    vec![],
                    RetentionClass::Lease { expires_at: 100 },
                ))
                .await
                .unwrap();

            let roots = GcRoots::new();
            let result = gc.collect(&test_zone(), &roots, &store, 500).await.unwrap();

            assert_eq!(result.pinned, 1); // obj2 pinned
            assert_eq!(result.expired_leases, 1); // obj4 expired
            assert_eq!(result.evicted, 2); // obj1 (ephemeral) + obj4 (expired lease)
            assert!(store.exists(&ObjectId::from_bytes([2; 32])).await); // pinned kept
            assert!(store.exists(&ObjectId::from_bytes([3; 32])).await); // valid lease kept

            StoreLogData {
                details: Some(json!({"mixed": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_collect_cyclic_refs() {
        run_store_test("gc_cyclic_refs", "verify", "gc", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            // Cycle: 1 -> 2 -> 3 -> 1
            store
                .put(test_object(1, vec![2], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(2, vec![3], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(3, vec![1], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let mut roots = GcRoots::new();
            roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.live, 3); // All reachable via cycle
            assert_eq!(result.evicted, 0);

            StoreLogData {
                details: Some(json!({"cyclic": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn would_collect_reachable_through_chain() {
        run_store_test("would_collect_chain", "verify", "gc", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            // Chain: 1 -> 2 -> 3
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

            let mut roots = GcRoots::new();
            roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

            // Object 3 is reachable through 1->2->3
            assert!(
                !gc.would_collect(
                    &ObjectId::from_bytes([3; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    0
                )
                .await
            );

            // Object with unknown ID is not in store, would be collected
            assert!(
                gc.would_collect(
                    &ObjectId::from_bytes([99; 32]),
                    &test_zone(),
                    &roots,
                    &store,
                    0
                )
                .await
            );

            StoreLogData {
                details: Some(json!({"chain_reachable": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_roots_overwrite_checkpoint() {
        let mut roots = GcRoots::new();
        let id1 = ObjectId::from_bytes([1; 32]);
        let id2 = ObjectId::from_bytes([2; 32]);

        roots.set_checkpoint(id1);
        assert!(roots.is_root(&id1));

        roots.set_checkpoint(id2);
        assert!(roots.is_root(&id2));
        assert!(!roots.is_root(&id1));
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

    // --- GcResult tests ---

    #[test]
    fn gc_result_serde_json_roundtrip() {
        let result = GcResult {
            live: 10,
            evicted: 3,
            expired_leases: 1,
            pinned: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: GcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.live, 10);
        assert_eq!(rt.evicted, 3);
        assert_eq!(rt.expired_leases, 1);
        assert_eq!(rt.pinned, 2);
    }

    #[test]
    fn gc_result_clone_preserves_fields() {
        let result = GcResult {
            live: 5,
            evicted: 2,
            expired_leases: 0,
            pinned: 1,
        };
        let cloned = result.clone();
        assert_eq!(result.live, cloned.live);
        assert_eq!(result.evicted, cloned.evicted);
    }

    // --- GcConfig tests ---

    #[test]
    fn gc_config_default_values() {
        let config = GcConfig::default();
        assert_eq!(config.max_evictions_per_run, 10_000);
        assert!(config.enforce_lease_expiry);
    }

    #[test]
    fn gc_config_serde_all_fields() {
        let config = GcConfig {
            max_evictions_per_run: 500,
            enforce_lease_expiry: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let rt: GcConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.max_evictions_per_run, 500);
        assert!(!rt.enforce_lease_expiry);
    }

    // --- GcRoots tests ---

    #[test]
    fn gc_roots_default() {
        let roots = GcRoots::default();
        assert!(roots.zone_checkpoint.is_none());
        assert!(roots.pinned.is_empty());
        assert!(roots.all_roots().is_empty());
    }

    #[test]
    fn gc_roots_remove_pin() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([1; 32]);
        roots.add_pin(id);
        assert!(roots.is_root(&id));
        roots.remove_pin(&id);
        assert!(!roots.is_root(&id));
    }

    #[test]
    fn gc_roots_is_root_checkpoint_only() {
        let mut roots = GcRoots::new();
        let cp = ObjectId::from_bytes([10; 32]);
        roots.set_checkpoint(cp);
        assert!(roots.is_root(&cp));
        assert!(!roots.is_root(&ObjectId::from_bytes([11; 32])));
    }

    #[test]
    fn gc_roots_is_root_pin_only() {
        let mut roots = GcRoots::new();
        let pin = ObjectId::from_bytes([20; 32]);
        roots.add_pin(pin);
        assert!(roots.is_root(&pin));
        assert!(!roots.is_root(&ObjectId::from_bytes([21; 32])));
    }

    #[test]
    fn gc_roots_all_roots_deduplicates_checkpoint_and_pin() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([5; 32]);
        roots.set_checkpoint(id);
        roots.add_pin(id);
        let all = roots.all_roots();
        assert_eq!(all.len(), 1);
    }

    // --- Additional GcRoots edge case tests ---

    #[test]
    fn gc_roots_multiple_pins() {
        let mut roots = GcRoots::new();
        for i in 0..5 {
            roots.add_pin(ObjectId::from_bytes([i; 32]));
        }
        assert_eq!(roots.all_roots().len(), 5);
    }

    #[test]
    fn gc_roots_remove_nonexistent_pin() {
        let mut roots = GcRoots::new();
        let id = ObjectId::from_bytes([77; 32]);
        roots.remove_pin(&id); // should not panic
        assert!(!roots.is_root(&id));
    }

    #[test]
    fn gc_roots_checkpoint_overwrite() {
        let mut roots = GcRoots::new();
        let cp1 = ObjectId::from_bytes([1; 32]);
        let cp2 = ObjectId::from_bytes([2; 32]);
        roots.set_checkpoint(cp1);
        roots.set_checkpoint(cp2);
        assert!(roots.is_root(&cp2));
        assert!(!roots.is_root(&cp1));
    }

    #[test]
    fn gc_roots_all_roots_checkpoint_plus_pins() {
        let mut roots = GcRoots::new();
        let cp = ObjectId::from_bytes([10; 32]);
        roots.set_checkpoint(cp);
        roots.add_pin(ObjectId::from_bytes([20; 32]));
        roots.add_pin(ObjectId::from_bytes([30; 32]));
        let all = roots.all_roots();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&cp));
    }

    #[test]
    fn gc_roots_debug_format() {
        let roots = GcRoots::new();
        let dbg = format!("{roots:?}");
        assert!(dbg.contains("GcRoots"));
    }

    #[test]
    fn gc_roots_clone_preserves_pins() {
        let mut roots = GcRoots::new();
        roots.add_pin(ObjectId::from_bytes([1; 32]));
        let cloned = roots.clone();
        assert_eq!(roots.all_roots().len(), cloned.all_roots().len());
    }

    // --- GcResult serde ---

    #[test]
    fn gc_result_serde_all_fields_rt() {
        let result = GcResult {
            live: 42,
            evicted: 7,
            expired_leases: 3,
            pinned: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: GcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.live, 42);
        assert_eq!(rt.evicted, 7);
        assert_eq!(rt.expired_leases, 3);
        assert_eq!(rt.pinned, 5);
    }

    #[test]
    fn gc_result_debug_format() {
        let result = GcResult {
            live: 1,
            evicted: 2,
            expired_leases: 3,
            pinned: 4,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("GcResult"));
        assert!(dbg.contains("evicted"));
    }

    #[test]
    fn gc_config_clone() {
        let config = GcConfig {
            max_evictions_per_run: 42,
            enforce_lease_expiry: false,
        };
        let cloned = config.clone();
        assert_eq!(config.max_evictions_per_run, cloned.max_evictions_per_run);
        assert_eq!(config.enforce_lease_expiry, cloned.enforce_lease_expiry);
    }

    #[test]
    fn gc_config_debug_format() {
        let config = GcConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("GcConfig"));
        assert!(dbg.contains("max_evictions_per_run"));
    }
}
