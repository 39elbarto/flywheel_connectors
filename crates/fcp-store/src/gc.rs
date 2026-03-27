//! Garbage collection for FCP2 stores (NORMATIVE).
//!
//! Implements reachability-based GC from `FCP_Specification_V2.md` §3.7.

use std::collections::{HashSet, VecDeque};

use fcp_core::{ObjectId, RetentionClass, ZoneId};
use serde::{Deserialize, Serialize};

use crate::error::{GcError, ObjectStoreError, SymbolStoreError};
use crate::object_store::ObjectStore;
use crate::symbol_store::{ObjectSymbolMeta, StoredSymbol, SymbolStore};

#[derive(Debug)]
struct SweepCandidate {
    object_id: ObjectId,
    expired_lease: bool,
}

#[derive(Debug)]
struct SweepPlan {
    live_count: usize,
    skipped_pinned_count: usize,
    candidates: Vec<SweepCandidate>,
}

#[derive(Debug)]
struct SymbolSnapshot {
    meta: ObjectSymbolMeta,
    symbols: Vec<StoredSymbol>,
}

/// Result of a garbage collection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcResult {
    /// Number of live (reachable) objects.
    pub live: usize,
    /// Number of objects evicted.
    pub evicted: usize,
    /// Number of objects with expired leases.
    pub expired_leases: usize,
    /// Number of unreachable pinned objects skipped during sweep.
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

    /// Iterate all root object IDs without allocating a new HashSet.
    pub fn root_iter(&self) -> impl Iterator<Item = ObjectId> + '_ {
        self.pinned
            .iter()
            .copied()
            .chain(self.zone_checkpoint.iter().copied())
    }

    /// Number of roots (zero allocation).
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.pinned.len() + usize::from(self.zone_checkpoint.is_some())
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
        let plan = self
            .collect_internal(zone_id, roots, store, current_time)
            .await?;
        self.execute_plan(&plan, store).await
    }

    /// Run GC and prune matching symbols from the symbol store.
    ///
    /// This keeps object and symbol stores consistent for evicted objects, even
    /// if one side of the delete sequence fails mid-flight.
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
        let plan = self
            .collect_internal(zone_id, roots, store, current_time)
            .await?;
        let mut evicted = 0;
        let mut expired_leases = 0;

        for candidate in &plan.candidates {
            let symbol_snapshot = load_symbol_snapshot(symbol_store, &candidate.object_id).await?;

            // Snapshot symbol data so we can roll back if object deletion fails
            // after symbol pruning.
            match symbol_store.delete_object(&candidate.object_id).await {
                Ok(()) | Err(SymbolStoreError::ObjectNotFound(_)) => {}
                Err(err) => return Err(GcError::SymbolStore(err)),
            }
            if let Err(err) = store.delete(&candidate.object_id).await {
                if let Some(snapshot) = symbol_snapshot {
                    restore_symbol_snapshot(symbol_store, snapshot).await?;
                }
                return Err(GcError::ObjectStore(err));
            }

            evicted += 1;
            if candidate.expired_lease {
                expired_leases += 1;
            }
        }

        Ok(self.build_result(&plan, evicted, expired_leases))
    }

    async fn collect_internal(
        &self,
        zone_id: &ZoneId,
        roots: &GcRoots,
        store: &dyn ObjectStore,
        current_time: u64,
    ) -> Result<SweepPlan, GcError> {
        // 1. Seed BFS queue directly from root iterator (zero-allocation).
        // 2. Mark phase: traverse refs from roots
        let mut visited = HashSet::new();
        let mut live = HashSet::new();
        let mut queue: VecDeque<ObjectId> = roots.root_iter().collect();

        while let Some(object_id) = queue.pop_front() {
            if visited.insert(object_id) {
                let header = store
                    .get_header(&object_id)
                    .await
                    .map_err(|err| match err {
                        ObjectStoreError::NotFound(_) if roots.is_root(&object_id) => {
                            GcError::InvalidRoot(object_id)
                        }
                        other => GcError::ObjectStore(other),
                    })?;

                if header.zone_id != *zone_id {
                    continue;
                }

                live.insert(object_id);

                // Follow refs (NOT foreign_refs - those are handled by foreign zone's GC)
                queue.extend(header.refs.iter().copied());
            }
        }

        // 3. Sweep planning phase: identify unreachable non-pinned objects first so
        // store read failures cannot partially advance deletions.
        let mut skipped_pinned_count = 0;
        let mut candidates = Vec::new();

        let all_objects = store.list_zone(zone_id).await;

        for object_id in all_objects {
            if live.contains(&object_id) {
                // Reachable objects are never evicted.
                continue;
            }

            // Object is unreachable
            let meta = store.get_storage_meta(&object_id).await?;
            match meta.retention {
                RetentionClass::Pinned => {
                    // Never evict pinned objects, even when unreachable.
                    skipped_pinned_count += 1;
                }
                RetentionClass::Lease { expires_at } => {
                    if candidates.len() < self.config.max_evictions_per_run
                        && (!self.config.enforce_lease_expiry || expires_at <= current_time)
                    {
                        candidates.push(SweepCandidate {
                            object_id,
                            expired_lease: expires_at <= current_time,
                        });
                    }
                }
                RetentionClass::Ephemeral => {
                    if candidates.len() < self.config.max_evictions_per_run {
                        candidates.push(SweepCandidate {
                            object_id,
                            expired_lease: false,
                        });
                    }
                }
            }
        }

        Ok(SweepPlan {
            live_count: live.len(),
            skipped_pinned_count,
            candidates,
        })
    }

    async fn execute_plan(
        &self,
        plan: &SweepPlan,
        store: &dyn ObjectStore,
    ) -> Result<GcResult, GcError> {
        let mut evicted = 0;
        let mut expired_leases = 0;

        for candidate in &plan.candidates {
            store.delete(&candidate.object_id).await?;
            evicted += 1;
            if candidate.expired_lease {
                expired_leases += 1;
            }
        }

        Ok(self.build_result(plan, evicted, expired_leases))
    }

    #[allow(clippy::unused_self, clippy::missing_const_for_fn)]
    fn build_result(&self, plan: &SweepPlan, evicted: usize, expired_leases: usize) -> GcResult {
        GcResult {
            live: plan.live_count,
            evicted,
            expired_leases,
            pinned: plan.skipped_pinned_count,
        }
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

        // Check reachability from roots (zero-allocation root seeding)
        let mut visited = HashSet::new();
        let mut queue: VecDeque<ObjectId> = roots.root_iter().collect();

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

async fn load_symbol_snapshot(
    symbol_store: &dyn SymbolStore,
    object_id: &ObjectId,
) -> Result<Option<SymbolSnapshot>, SymbolStoreError> {
    match symbol_store.get_object_meta(object_id).await {
        Ok(meta) => Ok(Some(SymbolSnapshot {
            meta,
            symbols: symbol_store.get_all_symbols(object_id).await,
        })),
        Err(SymbolStoreError::ObjectNotFound(_)) => Ok(None),
        Err(err) => Err(err),
    }
}

async fn restore_symbol_snapshot(
    symbol_store: &dyn SymbolStore,
    snapshot: SymbolSnapshot,
) -> Result<(), SymbolStoreError> {
    symbol_store.put_object_meta(snapshot.meta).await?;
    for symbol in snapshot.symbols {
        symbol_store.put_symbol(symbol).await?;
    }
    Ok(())
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

    struct FaultInjectingObjectStore {
        inner: MemoryObjectStore,
        fail_header_io: Option<ObjectId>,
        fail_storage_meta_io: Option<ObjectId>,
        fail_delete_io: Option<ObjectId>,
        list_zone_override: Option<Vec<ObjectId>>,
    }

    impl FaultInjectingObjectStore {
        fn new(inner: MemoryObjectStore) -> Self {
            Self {
                inner,
                fail_header_io: None,
                fail_storage_meta_io: None,
                fail_delete_io: None,
                list_zone_override: None,
            }
        }

        fn with_header_io(mut self, object_id: ObjectId) -> Self {
            self.fail_header_io = Some(object_id);
            self
        }

        fn with_storage_meta_io(mut self, object_id: ObjectId) -> Self {
            self.fail_storage_meta_io = Some(object_id);
            self
        }

        fn with_delete_io(mut self, object_id: ObjectId) -> Self {
            self.fail_delete_io = Some(object_id);
            self
        }

        fn with_list_zone(mut self, object_ids: Vec<ObjectId>) -> Self {
            self.list_zone_override = Some(object_ids);
            self
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for FaultInjectingObjectStore {
        async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
            self.inner.put(object).await
        }

        async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
            self.inner.get(id).await
        }

        async fn exists(&self, id: &ObjectId) -> bool {
            self.inner.exists(id).await
        }

        async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
            if self.fail_delete_io == Some(*id) {
                return Err(ObjectStoreError::Io("delete unavailable".to_owned()));
            }
            self.inner.delete(id).await
        }

        async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
            if self.fail_header_io == Some(*id) {
                return Err(ObjectStoreError::Io("root header unavailable".to_owned()));
            }
            self.inner.get_header(id).await
        }

        async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
            if self.fail_storage_meta_io == Some(*id) {
                return Err(ObjectStoreError::Io("metadata unavailable".to_owned()));
            }
            self.inner.get_storage_meta(id).await
        }

        async fn set_retention(
            &self,
            id: &ObjectId,
            retention: RetentionClass,
        ) -> Result<(), ObjectStoreError> {
            self.inner.set_retention(id, retention).await
        }

        async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
            if let Some(object_ids) = &self.list_zone_override {
                object_ids.clone()
            } else {
                self.inner.list_zone(zone_id).await
            }
        }

        async fn storage_used(&self) -> u64 {
            self.inner.storage_used().await
        }

        async fn storage_quota(&self) -> u64 {
            self.inner.storage_quota().await
        }
    }

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

    fn foreign_zone() -> ZoneId {
        "z:foreign".parse().unwrap()
    }

    fn test_object(id: u8, refs: Vec<u8>, retention: RetentionClass) -> StoredObject {
        test_object_in_zone(&test_zone(), id, refs, retention)
    }

    fn test_object_in_zone(
        zone_id: &ZoneId,
        id: u8,
        refs: Vec<u8>,
        retention: RetentionClass,
    ) -> StoredObject {
        StoredObject {
            object_id: ObjectId::from_bytes([id; 32]),
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
                zone_id: zone_id.clone(),
                created_at: 1_000_000,
                provenance: Provenance::new(zone_id.clone()),
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
    fn gc_does_not_follow_foreign_zone_hops() {
        run_store_test(
            "gc_ignores_foreign_zone_hops",
            "verify",
            "gc",
            6,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                let foreign_zone = foreign_zone();

                store
                    .put(test_object(1, vec![2], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                store
                    .put(test_object_in_zone(
                        &foreign_zone,
                        2,
                        vec![3],
                        RetentionClass::Ephemeral,
                    ))
                    .await
                    .unwrap();
                store
                    .put(test_object(3, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();

                let mut roots = GcRoots::new();
                roots.set_checkpoint(ObjectId::from_bytes([1; 32]));

                assert!(
                    gc.would_collect(
                        &ObjectId::from_bytes([3; 32]),
                        &test_zone(),
                        &roots,
                        &store,
                        0
                    )
                    .await
                );

                let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

                assert_eq!(result.live, 1);
                assert_eq!(result.evicted, 1);
                assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
                assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);
                assert!(!store.exists(&ObjectId::from_bytes([3; 32])).await);

                StoreLogData {
                    object_id: Some(ObjectId::from_bytes([3; 32])),
                    details: Some(json!({
                        "foreign_hop_ignored": true,
                        "live": result.live,
                        "evicted": result.evicted
                    })),
                    ..StoreLogData::default()
                }
            },
        );
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
    fn gc_counts_pinned_objects_beyond_eviction_limit() {
        run_store_test(
            "gc_counts_pinned_objects_beyond_eviction_limit",
            "verify",
            "gc",
            2,
            || async {
                let first_id = ObjectId::from_bytes([1; 32]);
                let second_id = ObjectId::from_bytes([2; 32]);
                let pinned_id = ObjectId::from_bytes([3; 32]);
                let inner = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                inner
                    .put(test_object(1, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                inner
                    .put(test_object(2, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                inner
                    .put(test_object(3, vec![], RetentionClass::Pinned))
                    .await
                    .unwrap();
                let store = FaultInjectingObjectStore::new(inner)
                    .with_list_zone(vec![first_id, second_id, pinned_id]);
                let gc = GarbageCollector::new(GcConfig {
                    max_evictions_per_run: 1,
                    ..GcConfig::default()
                });

                let result = gc
                    .collect(&test_zone(), &GcRoots::new(), &store, 0)
                    .await
                    .unwrap();

                assert_eq!(result.evicted, 1);
                assert_eq!(result.pinned, 1);

                StoreLogData {
                    details: Some(json!({
                        "evicted": result.evicted,
                        "pinned": result.pinned
                    })),
                    ..StoreLogData::default()
                }
            },
        );
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
    fn gc_missing_checkpoint_root_returns_invalid_root_without_sweeping() {
        run_store_test(
            "gc_missing_checkpoint_root_returns_invalid_root_without_sweeping",
            "adversarial",
            "gc",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());
                let surviving_object = ObjectId::from_bytes([2; 32]);

                store
                    .put(test_object(2, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();

                let missing_root = ObjectId::from_bytes([1; 32]);
                let mut roots = GcRoots::new();
                roots.set_checkpoint(missing_root);

                let result = gc.collect(&test_zone(), &roots, &store, 0).await;
                assert!(matches!(result, Err(GcError::InvalidRoot(id)) if id == missing_root));
                assert!(store.exists(&surviving_object).await);

                StoreLogData {
                    object_id: Some(missing_root),
                    details: Some(json!({
                        "invalid_root": missing_root.to_string(),
                        "sweep_aborted": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn gc_root_io_error_is_not_misclassified_as_invalid_root() {
        run_store_test(
            "gc_root_io_error_is_not_misclassified_as_invalid_root",
            "adversarial",
            "gc",
            1,
            || async {
                let root_id = ObjectId::from_bytes([7; 32]);
                let inner = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                inner
                    .put(test_object(7, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                let store = FaultInjectingObjectStore::new(inner).with_header_io(root_id);
                let gc = GarbageCollector::new(GcConfig::default());
                let mut roots = GcRoots::new();
                roots.set_checkpoint(root_id);

                let result = gc.collect(&test_zone(), &roots, &store, 0).await;
                assert!(
                    matches!(result, Err(GcError::ObjectStore(ObjectStoreError::Io(message))) if message == "root header unavailable")
                );

                StoreLogData {
                    object_id: Some(root_id),
                    details: Some(
                        json!({"error": "root-header-io", "classified_as": "object-store"}),
                    ),
                    ..StoreLogData::default()
                }
            },
        );
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
    fn gc_collect_and_prune_symbols_aborts_before_partial_delete_on_metadata_error() {
        run_store_test(
            "gc_collect_and_prune_symbols_aborts_before_partial_delete_on_metadata_error",
            "adversarial",
            "gc",
            5,
            || async {
                let first_id = ObjectId::from_bytes([1; 32]);
                let failing_id = ObjectId::from_bytes([2; 32]);
                let inner = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                inner
                    .put(test_object(1, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                inner
                    .put(test_object(2, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                let store = FaultInjectingObjectStore::new(inner)
                    .with_list_zone(vec![first_id, failing_id])
                    .with_storage_meta_io(failing_id);
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                let meta = ObjectSymbolMeta {
                    object_id: first_id,
                    zone_id: test_zone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: 256,
                        symbol_size: 64,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols: 1,
                    first_symbol_at: 1_000_000,
                };
                symbol_store.put_object_meta(meta).await.unwrap();
                symbol_store
                    .put_symbol(StoredSymbol {
                        meta: SymbolMeta {
                            object_id: first_id,
                            esi: 0,
                            zone_id: test_zone(),
                            source_node: Some(1),
                            stored_at: 1_000_000,
                        },
                        data: Bytes::from(vec![0_u8; 64]),
                    })
                    .await
                    .unwrap();

                let result = gc
                    .collect_and_prune_symbols(
                        &test_zone(),
                        &GcRoots::new(),
                        &store,
                        &symbol_store,
                        0,
                    )
                    .await;

                assert!(
                    matches!(result, Err(GcError::ObjectStore(ObjectStoreError::Io(message))) if message == "metadata unavailable")
                );
                assert!(store.exists(&first_id).await);
                assert!(store.exists(&failing_id).await);
                assert!(symbol_store.get_object_meta(&first_id).await.is_ok());
                assert!(symbol_store.get_symbol(&first_id, 0).await.is_ok());

                StoreLogData {
                    details: Some(json!({
                        "error": "metadata unavailable",
                        "deleted_before_failure": false,
                        "symbols_orphaned": false
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn gc_collect_and_prune_symbols_restores_symbols_when_object_delete_fails() {
        run_store_test(
            "gc_collect_and_prune_symbols_restores_symbols_when_object_delete_fails",
            "adversarial",
            "gc",
            5,
            || async {
                let object_id = ObjectId::from_bytes([7; 32]);
                let inner = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                inner
                    .put(test_object(7, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                let store = FaultInjectingObjectStore::new(inner)
                    .with_list_zone(vec![object_id])
                    .with_delete_io(object_id);
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: test_zone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: 256,
                        symbol_size: 64,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols: 1,
                    first_symbol_at: 2_000_000,
                };
                symbol_store.put_object_meta(meta.clone()).await.unwrap();
                let stored_symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi: 0,
                        zone_id: test_zone(),
                        source_node: Some(7),
                        stored_at: 2_000_000,
                    },
                    data: Bytes::from(vec![7_u8; 64]),
                };
                symbol_store
                    .put_symbol(stored_symbol.clone())
                    .await
                    .unwrap();

                let result = gc
                    .collect_and_prune_symbols(
                        &test_zone(),
                        &GcRoots::new(),
                        &store,
                        &symbol_store,
                        0,
                    )
                    .await;

                assert!(
                    matches!(result, Err(GcError::ObjectStore(ObjectStoreError::Io(message))) if message == "delete unavailable")
                );
                assert!(store.exists(&object_id).await);
                assert_eq!(
                    symbol_store.get_object_meta(&object_id).await.unwrap(),
                    meta
                );
                let restored_symbol = symbol_store.get_symbol(&object_id, 0).await.unwrap();
                assert_eq!(restored_symbol.meta.object_id, stored_symbol.meta.object_id);
                assert_eq!(restored_symbol.meta.esi, stored_symbol.meta.esi);
                assert_eq!(restored_symbol.meta.zone_id, stored_symbol.meta.zone_id);
                assert_eq!(
                    restored_symbol.meta.source_node,
                    stored_symbol.meta.source_node
                );
                assert_eq!(restored_symbol.meta.stored_at, stored_symbol.meta.stored_at);
                assert_eq!(restored_symbol.data, stored_symbol.data);

                StoreLogData {
                    details: Some(json!({
                        "error": "delete unavailable",
                        "object_preserved": true,
                        "symbols_restored": true
                    })),
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

    // =========================================================================
    // Lease boundary tests
    // =========================================================================

    #[test]
    fn gc_lease_expires_at_exact_current_time_is_evicted() {
        run_store_test(
            "gc_lease_expires_at_exact_current_time",
            "verify",
            "gc",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                // Lease expires_at == current_time (boundary condition)
                store
                    .put(test_object(
                        1,
                        vec![],
                        RetentionClass::Lease { expires_at: 500 },
                    ))
                    .await
                    .unwrap();

                let roots = GcRoots::new();
                let result = gc.collect(&test_zone(), &roots, &store, 500).await.unwrap();

                // expires_at <= current_time means evicted
                assert_eq!(result.evicted, 1);
                assert_eq!(result.expired_leases, 1);

                StoreLogData {
                    details: Some(json!({
                        "boundary": "expires_at == current_time",
                        "evicted": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn gc_lease_one_tick_before_expiry_is_kept() {
        run_store_test(
            "gc_lease_one_tick_before_expiry",
            "verify",
            "gc",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                // Lease expires_at = 500, current_time = 499 (one tick before)
                store
                    .put(test_object(
                        1,
                        vec![],
                        RetentionClass::Lease { expires_at: 500 },
                    ))
                    .await
                    .unwrap();

                let roots = GcRoots::new();
                let result = gc.collect(&test_zone(), &roots, &store, 499).await.unwrap();

                // Not yet expired — should not be evicted
                assert_eq!(result.evicted, 0);
                assert_eq!(result.expired_leases, 0);

                StoreLogData {
                    details: Some(json!({
                        "boundary": "expires_at - 1",
                        "evicted": false
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn gc_lease_enforcement_disabled_evicts_unexpired_unreachable_lease() {
        run_store_test(
            "gc_lease_enforcement_disabled_unexpired",
            "verify",
            "gc",
            3,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let config = GcConfig {
                    enforce_lease_expiry: false,
                    ..Default::default()
                };
                let gc = GarbageCollector::new(config);

                // Object with a far-future lease, but enforcement is off
                store
                    .put(test_object(
                        1,
                        vec![],
                        RetentionClass::Lease {
                            expires_at: u64::MAX,
                        },
                    ))
                    .await
                    .unwrap();

                let roots = GcRoots::new();
                let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

                assert_eq!(result.evicted, 1);
                // Not marked as expired_leases because it was force-evicted
                assert_eq!(result.expired_leases, 0);
                assert!(!store.exists(&ObjectId::from_bytes([1; 32])).await);

                StoreLogData {
                    details: Some(json!({
                        "lease_enforcement_disabled": true,
                        "far_future_lease_evicted": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Mixed retention class sweep tests
    // =========================================================================

    #[test]
    fn gc_mixed_retention_classes_sweeps_correctly() {
        run_store_test("gc_mixed_retention_classes", "verify", "gc", 4, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let gc = GarbageCollector::new(GcConfig::default());

            // Ephemeral (unreachable) → evict
            store
                .put(test_object(1, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
            // Pinned (unreachable) → skip
            store
                .put(test_object(2, vec![], RetentionClass::Pinned))
                .await
                .unwrap();
            // Expired lease (unreachable) → evict + mark expired
            store
                .put(test_object(
                    3,
                    vec![],
                    RetentionClass::Lease { expires_at: 50 },
                ))
                .await
                .unwrap();
            // Valid lease (unreachable) → keep
            store
                .put(test_object(
                    4,
                    vec![],
                    RetentionClass::Lease { expires_at: 9999 },
                ))
                .await
                .unwrap();

            let roots = GcRoots::new();
            let result = gc.collect(&test_zone(), &roots, &store, 100).await.unwrap();

            assert_eq!(result.live, 0);
            assert_eq!(result.evicted, 2); // ephemeral + expired lease
            assert_eq!(result.expired_leases, 1);
            assert_eq!(result.pinned, 1);
            assert!(!store.exists(&ObjectId::from_bytes([1; 32])).await);
            assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);
            assert!(!store.exists(&ObjectId::from_bytes([3; 32])).await);
            assert!(store.exists(&ObjectId::from_bytes([4; 32])).await);

            StoreLogData {
                details: Some(json!({
                    "ephemeral_evicted": true,
                    "pinned_skipped": true,
                    "expired_lease_evicted": true,
                    "valid_lease_kept": true
                })),
                ..StoreLogData::default()
            }
        });
    }

    // =========================================================================
    // Symbol snapshot edge cases
    // =========================================================================

    #[test]
    fn gc_collect_and_prune_symbols_multiple_objects_partial_symbol_coverage() {
        run_store_test(
            "gc_prune_symbols_partial_coverage",
            "verify",
            "gc",
            4,
            || async {
                let object_store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                // Object 1: has symbols
                let id1 = ObjectId::from_bytes([1; 32]);
                object_store
                    .put(test_object(1, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                let meta1 = ObjectSymbolMeta {
                    object_id: id1,
                    zone_id: test_zone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: 128,
                        symbol_size: 64,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols: 2,
                    first_symbol_at: 1_000_000,
                };
                symbol_store.put_object_meta(meta1).await.unwrap();
                for esi in 0..2 {
                    symbol_store
                        .put_symbol(StoredSymbol {
                            meta: SymbolMeta {
                                object_id: id1,
                                esi,
                                zone_id: test_zone(),
                                source_node: Some(1),
                                stored_at: 1_000_000 + u64::from(esi),
                            },
                            data: Bytes::from(vec![0_u8; 64]),
                        })
                        .await
                        .unwrap();
                }

                // Object 2: no symbols at all
                let id2 = ObjectId::from_bytes([2; 32]);
                object_store
                    .put(test_object(2, vec![], RetentionClass::Ephemeral))
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

                assert_eq!(result.evicted, 2);
                assert!(!object_store.exists(&id1).await);
                assert!(!object_store.exists(&id2).await);
                // Symbols for id1 should be pruned
                assert!(matches!(
                    symbol_store.get_object_meta(&id1).await,
                    Err(SymbolStoreError::ObjectNotFound(_))
                ));

                StoreLogData {
                    details: Some(json!({
                        "objects_evicted": 2,
                        "one_with_symbols": true,
                        "one_without_symbols": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn gc_collect_and_prune_preserves_reachable_symbols() {
        run_store_test(
            "gc_prune_preserves_reachable_symbols",
            "verify",
            "gc",
            4,
            || async {
                let object_store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                // Object 1: reachable root with symbols
                let id1 = ObjectId::from_bytes([1; 32]);
                object_store
                    .put(test_object(1, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();
                let meta1 = ObjectSymbolMeta {
                    object_id: id1,
                    zone_id: test_zone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: 128,
                        symbol_size: 64,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols: 1,
                    first_symbol_at: 1_000_000,
                };
                symbol_store.put_object_meta(meta1).await.unwrap();
                symbol_store
                    .put_symbol(StoredSymbol {
                        meta: SymbolMeta {
                            object_id: id1,
                            esi: 0,
                            zone_id: test_zone(),
                            source_node: Some(1),
                            stored_at: 1_000_000,
                        },
                        data: Bytes::from(vec![0_u8; 64]),
                    })
                    .await
                    .unwrap();

                // Object 2: unreachable with symbols → evicted
                let id2 = ObjectId::from_bytes([2; 32]);
                object_store
                    .put(test_object(2, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();

                let mut roots = GcRoots::new();
                roots.set_checkpoint(id1);

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

                assert_eq!(result.live, 1);
                assert_eq!(result.evicted, 1);
                // Reachable object and its symbols preserved
                assert!(object_store.exists(&id1).await);
                assert!(symbol_store.get_object_meta(&id1).await.is_ok());
                assert!(symbol_store.get_symbol(&id1, 0).await.is_ok());
                // Unreachable object evicted
                assert!(!object_store.exists(&id2).await);

                StoreLogData {
                    details: Some(json!({
                        "reachable_symbols_preserved": true,
                        "unreachable_evicted": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Max evictions boundary with mixed types
    // =========================================================================

    #[test]
    fn gc_max_evictions_zero_evicts_nothing() {
        run_store_test("gc_max_evictions_zero", "verify", "gc", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let config = GcConfig {
                max_evictions_per_run: 0,
                ..Default::default()
            };
            let gc = GarbageCollector::new(config);

            store
                .put(test_object(1, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();
            store
                .put(test_object(2, vec![], RetentionClass::Ephemeral))
                .await
                .unwrap();

            let roots = GcRoots::new();
            let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

            assert_eq!(result.evicted, 0);
            assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
            assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);

            StoreLogData {
                details: Some(json!({
                    "max_evictions": 0,
                    "all_preserved": true
                })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn gc_pinned_missing_pin_root_still_counts_as_unreachable_pinned() {
        run_store_test(
            "gc_pinned_not_in_roots_still_skipped",
            "verify",
            "gc",
            3,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let gc = GarbageCollector::new(GcConfig::default());

                // Pinned object NOT in GcRoots.pinned set
                store
                    .put(test_object(1, vec![], RetentionClass::Pinned))
                    .await
                    .unwrap();
                // Ephemeral object
                store
                    .put(test_object(2, vec![], RetentionClass::Ephemeral))
                    .await
                    .unwrap();

                let roots = GcRoots::new(); // empty roots

                let result = gc.collect(&test_zone(), &roots, &store, 0).await.unwrap();

                // Pinned objects are skipped even when not in root set
                assert_eq!(result.pinned, 1);
                assert_eq!(result.evicted, 1);
                assert!(store.exists(&ObjectId::from_bytes([1; 32])).await);
                assert!(!store.exists(&ObjectId::from_bytes([2; 32])).await);

                StoreLogData {
                    details: Some(json!({
                        "pinned_not_in_roots": true,
                        "still_skipped": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }
}
