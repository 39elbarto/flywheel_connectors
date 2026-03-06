//! Symbol store interface for FCP2.
//!
//! Provides storage for `RaptorQ` symbols to enable partial object availability.

use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;
use fcp_core::{ObjectId, ZoneId};
use fcp_raptorq::ObjectTransmissionInformation;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::coverage::SymbolDistribution;
use crate::error::SymbolStoreError;

/// Metadata for a stored symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMeta {
    /// Object this symbol belongs to.
    pub object_id: ObjectId,
    /// Encoding symbol ID.
    pub esi: u32,
    /// Zone ID for the object.
    pub zone_id: ZoneId,
    /// Node that provided this symbol (for source diversity tracking).
    pub source_node: Option<u64>,
    /// Timestamp when symbol was stored.
    pub stored_at: u64,
}

/// Stored symbol with data and metadata.
#[derive(Debug, Clone)]
pub struct StoredSymbol {
    /// Symbol metadata.
    pub meta: SymbolMeta,
    /// Symbol data.
    pub data: Bytes,
}

/// Serializable object transmission information.
///
/// This is a serializable wrapper around raptorq's `ObjectTransmissionInformation`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectTransmissionInfo {
    /// Transfer length (object size in bytes).
    pub transfer_length: u64,
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Number of source blocks.
    pub source_blocks: u8,
    /// Number of sub-blocks.
    pub sub_blocks: u16,
    /// Symbol alignment.
    pub alignment: u8,
}

impl ObjectTransmissionInfo {
    /// Create from raptorq's `ObjectTransmissionInformation`.
    #[must_use]
    pub const fn from_oti(oti: ObjectTransmissionInformation) -> Self {
        Self {
            transfer_length: oti.transfer_length(),
            symbol_size: oti.symbol_size(),
            source_blocks: oti.source_blocks(),
            sub_blocks: oti.sub_blocks(),
            alignment: oti.symbol_alignment(),
        }
    }

    /// Convert to raptorq's `ObjectTransmissionInformation`.
    #[must_use]
    pub const fn to_oti(self) -> ObjectTransmissionInformation {
        ObjectTransmissionInformation::new(
            self.transfer_length,
            self.symbol_size,
            self.source_blocks,
            self.sub_blocks,
            self.alignment,
        )
    }
}

impl From<ObjectTransmissionInformation> for ObjectTransmissionInfo {
    fn from(oti: ObjectTransmissionInformation) -> Self {
        Self::from_oti(oti)
    }
}

impl From<ObjectTransmissionInfo> for ObjectTransmissionInformation {
    fn from(info: ObjectTransmissionInfo) -> Self {
        info.to_oti()
    }
}

/// Object metadata for symbol reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSymbolMeta {
    /// Object ID.
    pub object_id: ObjectId,
    /// Zone ID.
    pub zone_id: ZoneId,
    /// Object transmission information for `RaptorQ` decoding.
    pub oti: ObjectTransmissionInfo,
    /// Number of source symbols (K).
    pub source_symbols: u32,
    /// Timestamp when first symbol was stored.
    pub first_symbol_at: u64,
}

/// Symbol store interface (NORMATIVE).
///
/// Stores `RaptorQ` symbols for partial object availability.
#[async_trait]
pub trait SymbolStore: Send + Sync {
    /// Store a symbol for an object.
    ///
    /// # Errors
    /// Returns error if quota exceeded.
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError>;

    /// Store object metadata (must be called before storing symbols).
    ///
    /// # Errors
    /// Returns error if quota exceeded.
    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError>;

    /// Get a specific symbol.
    ///
    /// # Errors
    /// Returns `NotFound` if symbol doesn't exist.
    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError>;

    /// Get object metadata.
    ///
    /// # Errors
    /// Returns `ObjectNotFound` if object metadata doesn't exist.
    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError>;

    /// Get all symbols for an object.
    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol>;

    /// Get symbol count for an object.
    async fn symbol_count(&self, object_id: &ObjectId) -> u32;

    /// Delete all symbols for an object.
    ///
    /// # Errors
    /// Returns `ObjectNotFound` if object doesn't exist.
    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError>;

    /// Delete a specific symbol.
    ///
    /// # Errors
    /// Returns `NotFound` if symbol doesn't exist.
    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError>;

    /// Get symbol distribution for an object (for coverage evaluation).
    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution>;

    /// List all object IDs with symbols in a zone.
    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId>;

    /// Get total storage used in bytes.
    async fn storage_used(&self) -> u64;

    /// Get storage quota in bytes.
    async fn storage_quota(&self) -> u64;

    /// Check if object can be reconstructed (has enough symbols).
    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool;

    /// Check if object can be reconstructed with diversity enforcement.
    ///
    /// Unlike `can_reconstruct`, this method also verifies that symbols come from
    /// at least `min_source_diversity` distinct nodes when the policy requires it.
    async fn can_reconstruct_with_policy(
        &self,
        object_id: &ObjectId,
        policy: &fcp_core::ObjectPlacementPolicy,
    ) -> bool;
}

/// Configuration for in-memory symbol store.
#[derive(Debug, Clone)]
pub struct MemorySymbolStoreConfig {
    /// Maximum storage in bytes.
    pub max_bytes: u64,
    /// Local node ID for distribution tracking.
    pub local_node_id: u64,
}

impl Default for MemorySymbolStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024, // 512MB
            local_node_id: 0,
        }
    }
}

/// Per-object symbol storage.
#[derive(Debug)]
struct ObjectSymbols {
    meta: ObjectSymbolMeta,
    symbols: HashMap<u32, StoredSymbol>, // ESI -> Symbol
}

/// In-memory symbol store implementation.
pub struct MemorySymbolStore {
    objects: RwLock<HashMap<ObjectId, ObjectSymbols>>,
    config: MemorySymbolStoreConfig,
    used_bytes: RwLock<u64>,
}

impl MemorySymbolStore {
    /// Create a new in-memory symbol store.
    #[must_use]
    pub fn new(config: MemorySymbolStoreConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            used_bytes: RwLock::new(0),
        }
    }

    const fn symbol_size(symbol: &StoredSymbol) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let size = symbol.data.len() as u64 + 64; // 64 byte metadata estimate
        size
    }
}

#[async_trait]
impl SymbolStore for MemorySymbolStore {
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();
        let obj = objects
            .get_mut(&symbol.meta.object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;

        // Check symbol size against OTI
        let expected_size = obj.meta.oti.symbol_size as usize;
        if symbol.data.len() != expected_size {
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "Symbol size mismatch: expected {}, got {}",
                    expected_size,
                    symbol.data.len()
                ),
            });
        }
        if symbol.meta.zone_id != obj.meta.zone_id {
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "Symbol zone mismatch: expected {}, got {}",
                    obj.meta.zone_id, symbol.meta.zone_id
                ),
            });
        }

        // Check for duplicate ESI
        if obj.symbols.contains_key(&symbol.meta.esi) {
            // Already have this symbol, skip
            return Ok(());
        }

        let size = Self::symbol_size(&symbol);
        let mut used = self.used_bytes.write();
        if *used + size > self.config.max_bytes {
            return Err(SymbolStoreError::QuotaExceeded {
                used: *used,
                max: self.config.max_bytes,
            });
        }

        obj.symbols.insert(symbol.meta.esi, symbol);
        *used += size;

        Ok(())
    }

    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();

        // If already exists, check consistency
        if let Some(obj) = objects.get(&meta.object_id) {
            if obj.meta != meta {
                return Err(SymbolStoreError::InvalidSymbol {
                    reason: format!("Metadata mismatch for object {}", meta.object_id),
                });
            }
            return Ok(());
        }

        objects.insert(
            meta.object_id,
            ObjectSymbols {
                meta,
                symbols: HashMap::new(),
            },
        );

        Ok(())
    }

    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError> {
        let objects = self.objects.read();
        let obj = objects
            .get(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;

        obj.symbols
            .get(&esi)
            .cloned()
            .ok_or(SymbolStoreError::NotFound {
                object_id: *object_id,
                esi,
            })
    }

    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError> {
        self.objects
            .read()
            .get(object_id)
            .map(|obj| obj.meta.clone())
            .ok_or_else(|| SymbolStoreError::ObjectNotFound(*object_id))
    }

    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol> {
        self.objects
            .read()
            .get(object_id)
            .map(|obj| obj.symbols.values().cloned().collect())
            .unwrap_or_default()
    }

    async fn symbol_count(&self, object_id: &ObjectId) -> u32 {
        self.objects.read().get(object_id).map_or(0, |obj| {
            u32::try_from(obj.symbols.len()).unwrap_or(u32::MAX)
        })
    }

    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();
        let obj = objects
            .remove(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;

        let total_size: u64 = obj.symbols.values().map(Self::symbol_size).sum();
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(total_size);

        Ok(())
    }

    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();
        let obj = objects
            .get_mut(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;

        let symbol = obj.symbols.remove(&esi).ok_or(SymbolStoreError::NotFound {
            object_id: *object_id,
            esi,
        })?;

        let size = Self::symbol_size(&symbol);
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(size);

        Ok(())
    }

    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution> {
        let objects = self.objects.read();
        let obj = objects.get(object_id)?;

        let mut dist = SymbolDistribution::new(obj.meta.source_symbols);

        for symbol in obj.symbols.values() {
            let node_id = symbol.meta.source_node.unwrap_or(self.config.local_node_id);
            #[allow(clippy::cast_possible_truncation)]
            let size = symbol.data.len() as u64;
            dist.add_symbol(node_id, size);
        }

        Some(dist)
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.objects
            .read()
            .values()
            .filter(|obj| &obj.meta.zone_id == zone_id)
            .map(|obj| obj.meta.object_id)
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        *self.used_bytes.read()
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }

    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool {
        let objects = self.objects.read();
        if let Some(obj) = objects.get(object_id) {
            // RaptorQ needs K' ≈ K × 1.002 symbols, we approximate with K
            obj.symbols.len() as u32 >= obj.meta.source_symbols
        } else {
            false
        }
    }

    async fn can_reconstruct_with_policy(
        &self,
        object_id: &ObjectId,
        policy: &fcp_core::ObjectPlacementPolicy,
    ) -> bool {
        // Get distribution and evaluate against policy
        if let Some(dist) = self.get_distribution(object_id).await {
            let eval = crate::coverage::CoverageEvaluation::from_distribution(*object_id, &dist);
            eval.meets_diversity_for_reconstruction(policy)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use super::*;
    use crate::coverage::CoverageEvaluation;
    use chrono::Utc;
    use fcp_testkit::LogCapture;
    use serde_json::json;
    use uuid::Uuid;

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
        object_size: Option<u64>,
        symbol_count: Option<u32>,
        coverage_bps: Option<u32>,
        nodes_holding: Option<Vec<String>>,
        details: Option<serde_json::Value>,
    }

    fn nodes_from_distribution(dist: &SymbolDistribution) -> Vec<String> {
        let mut nodes: Vec<String> = dist.nodes.keys().map(|id| format!("node-{id}")).collect();
        nodes.sort();
        nodes
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

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_object_id() -> ObjectId {
        ObjectId::from_bytes([1_u8; 32])
    }

    fn test_object_meta() -> ObjectSymbolMeta {
        ObjectSymbolMeta {
            object_id: test_object_id(),
            zone_id: test_zone(),
            oti: ObjectTransmissionInfo {
                transfer_length: 1024,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
            },
            source_symbols: 16,
            first_symbol_at: 1_000_000,
        }
    }

    fn test_symbol(esi: u32) -> StoredSymbol {
        StoredSymbol {
            meta: SymbolMeta {
                object_id: test_object_id(),
                esi,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1_000_000,
            },
            data: Bytes::from(vec![0_u8; 64]),
        }
    }

    #[test]
    fn put_and_get_symbol() {
        run_store_test("put_and_get_symbol", "verify", "write", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            let symbol = store.get_symbol(&test_object_id(), 0).await.unwrap();
            assert_eq!(symbol.meta.esi, 0);

            StoreLogData {
                object_id: Some(test_object_id()),
                object_size: Some(symbol.data.len() as u64),
                symbol_count: Some(1),
                details: Some(json!({"esi": symbol.meta.esi})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_without_object_meta_rejected() {
        run_store_test(
            "symbol_without_object_meta_rejected",
            "verify",
            "write",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let result = store.put_symbol(test_symbol(0)).await;
                assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

                StoreLogData {
                    object_id: Some(test_object_id()),
                    details: Some(json!({"error": "object_not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn duplicate_symbol_ignored() {
        run_store_test("duplicate_symbol_ignored", "verify", "write", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            let count = store.symbol_count(&test_object_id()).await;
            assert_eq!(count, 1);

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(count),
                details: Some(json!({"note": "duplicate_ignored"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_all_symbols() {
        run_store_test("get_all_symbols", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            for esi in 0..5 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }

            let symbols = store.get_all_symbols(&test_object_id()).await;
            assert_eq!(symbols.len(), 5);

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(u32::try_from(symbols.len()).unwrap_or(u32::MAX)),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct() {
        run_store_test("can_reconstruct", "verify", "repair", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            let mut meta = test_object_meta();
            meta.source_symbols = 10;
            store.put_object_meta(meta).await.unwrap();

            for esi in 0..5 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }
            assert!(!store.can_reconstruct(&test_object_id()).await);

            for esi in 5..10 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }
            assert!(store.can_reconstruct(&test_object_id()).await);

            let dist = store.get_distribution(&test_object_id()).await.unwrap();

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(
                    CoverageEvaluation::from_distribution(test_object_id(), &dist).coverage_bps,
                ),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_with_policy_diversity() {
        run_store_test(
            "can_reconstruct_with_policy_diversity",
            "verify",
            "repair",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let mut meta = test_object_meta();
                meta.source_symbols = 4;
                store.put_object_meta(meta).await.unwrap();

                for esi in 0..4 {
                    let mut symbol = test_symbol(esi);
                    symbol.meta.source_node = Some(1);
                    store.put_symbol(symbol).await.unwrap();
                }

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 2,
                };

                assert!(
                    !store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                let mut symbol = test_symbol(4);
                symbol.meta.source_node = Some(2);
                store.put_symbol(symbol).await.unwrap();

                assert!(
                    store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                let dist = store.get_distribution(&test_object_id()).await.unwrap();
                let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

                let capture = LogCapture::new();
                let entry = json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "test_name": "can_reconstruct_with_policy_diversity",
                    "module": "fcp-store",
                    "phase": "verify",
                    "correlation_id": Uuid::new_v4().to_string(),
                    "result": "pass",
                    "duration_ms": 0,
                    "assertions": { "passed": 3, "failed": 0 },
                    "details": {
                        "object_id": test_object_id().to_string(),
                        "source_count": eval.distinct_nodes,
                        "diversity_bps": eval.diversity_bps(policy.min_source_diversity)
                    }
                });
                capture.push_value(&entry).expect("serialize log entry");
                capture.assert_valid();

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "source_count": eval.distinct_nodes,
                        "diversity_bps": eval.diversity_bps(policy.min_source_diversity)
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_distribution() {
        run_store_test("get_distribution", "verify", "placement", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();

            let mut symbol = test_symbol(0);
            symbol.meta.source_node = Some(1);
            store.put_symbol(symbol).await.unwrap();

            let mut symbol = test_symbol(1);
            symbol.meta.source_node = Some(2);
            store.put_symbol(symbol).await.unwrap();

            let mut symbol = test_symbol(2);
            symbol.meta.source_node = Some(1);
            store.put_symbol(symbol).await.unwrap();

            let dist = store.get_distribution(&test_object_id()).await.unwrap();
            assert_eq!(dist.distinct_nodes(), 2);
            assert_eq!(dist.total_symbols, 3);

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(
                    CoverageEvaluation::from_distribution(test_object_id(), &dist).coverage_bps,
                ),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_symbol() {
        run_store_test("delete_symbol", "verify", "delete", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            store.delete_symbol(&test_object_id(), 0).await.unwrap();

            let result = store.get_symbol(&test_object_id(), 0).await;
            assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));

            StoreLogData {
                object_id: Some(test_object_id()),
                details: Some(json!({"deleted_esi": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_zone_mismatch_rejected() {
        run_store_test(
            "symbol_zone_mismatch_rejected",
            "verify",
            "write",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                store.put_object_meta(test_object_meta()).await.unwrap();

                let mut bad_symbol = test_symbol(0);
                bad_symbol.meta.zone_id = "z:other".parse().expect("zone parse");

                let result = store.put_symbol(bad_symbol).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                StoreLogData {
                    object_id: Some(test_object_id()),
                    details: Some(json!({"error": "zone_mismatch"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_object() {
        run_store_test("delete_object_symbols", "verify", "delete", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            for esi in 0..5 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }

            let used_before = store.storage_used().await;
            assert!(used_before > 0);

            store.delete_object(&test_object_id()).await.unwrap();

            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                object_id: Some(test_object_id()),
                details: Some(json!({"used_before": used_before})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_enforcement() {
        run_store_test("symbol_quota_enforcement", "verify", "write", 1, || async {
            let config = MemorySymbolStoreConfig {
                max_bytes: 200,
                local_node_id: 0,
            };
            let store = MemorySymbolStore::new(config);

            store.put_object_meta(test_object_meta()).await.unwrap();

            store.put_symbol(test_symbol(0)).await.unwrap();

            let result = store.put_symbol(test_symbol(1)).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::QuotaExceeded { .. })
            ));

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(1),
                details: Some(json!({"error": "quota_exceeded"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn duplicate_symbol_does_not_hit_quota() {
        run_store_test(
            "symbol_duplicate_does_not_hit_quota",
            "verify",
            "write",
            2,
            || async {
                let sample = test_symbol(0);
                let size = MemorySymbolStore::symbol_size(&sample);
                let config = MemorySymbolStoreConfig {
                    max_bytes: size,
                    local_node_id: 0,
                };
                let store = MemorySymbolStore::new(config);

                store.put_object_meta(test_object_meta()).await.unwrap();
                store.put_symbol(sample).await.unwrap();

                let used_before = store.storage_used().await;
                let duplicate = store.put_symbol(test_symbol(0)).await;
                assert!(duplicate.is_ok());

                let used_after = store.storage_used().await;
                assert_eq!(used_before, used_after);

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(1),
                    details: Some(json!({
                        "used_bytes": used_after,
                        "duplicate_insert": "ignored"
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // --- Additional symbol store tests ---

    #[test]
    fn oti_serde_roundtrip() {
        run_store_test("oti_serde_roundtrip", "verify", "serde", 1, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 4096,
                symbol_size: 128,
                source_blocks: 2,
                sub_blocks: 4,
                alignment: 16,
            };
            let json = serde_json::to_string(&oti).unwrap();
            let deserialized: ObjectTransmissionInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(oti, deserialized);

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_copy_and_clone() {
        run_store_test("oti_copy_clone", "verify", "traits", 1, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 256,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
            };
            let copied = oti;
            let cloned = oti;
            assert_eq!(copied, cloned);

            StoreLogData {
                details: Some(json!({"copy_eq_clone": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_serde_roundtrip() {
        run_store_test("osm_serde_roundtrip", "verify", "serde", 1, || async {
            let meta = test_object_meta();
            let json = serde_json::to_string(&meta).unwrap();
            let deserialized: ObjectSymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(meta, deserialized);

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_serde_roundtrip() {
        run_store_test("symbol_meta_serde", "verify", "serde", 1, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 5,
                zone_id: test_zone(),
                source_node: Some(42),
                stored_at: 999_999,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let deserialized: SymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.esi, 5);
            assert_eq!(deserialized.source_node, Some(42));

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_size_mismatch_rejected() {
        run_store_test("symbol_size_mismatch", "verify", "write", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            // test_object_meta has symbol_size=64, but we provide 32 bytes
            let bad_symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id: test_object_id(),
                    esi: 0,
                    zone_id: test_zone(),
                    source_node: Some(1),
                    stored_at: 1_000_000,
                },
                data: Bytes::from(vec![0u8; 32]), // Wrong size!
            };

            let result = store.put_symbol(bad_symbol).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::InvalidSymbol { .. })
            ));

            StoreLogData {
                details: Some(json!({"error": "size_mismatch"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_symbol_not_found_esi() {
        run_store_test("get_symbol_not_found_esi", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            // ESI 99 does not exist
            let result = store.get_symbol(&test_object_id(), 99).await;
            assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));

            StoreLogData {
                details: Some(json!({"error": "not_found", "esi": 99})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_symbol_object_not_found() {
        run_store_test(
            "get_symbol_object_not_found",
            "verify",
            "read",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([99; 32]);

                let result = store.get_symbol(&unknown_id, 0).await;
                assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

                StoreLogData {
                    details: Some(json!({"error": "object_not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_symbol_not_found_esi() {
        run_store_test(
            "delete_symbol_not_found_esi",
            "verify",
            "delete",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                store.put_object_meta(test_object_meta()).await.unwrap();

                let result = store.delete_symbol(&test_object_id(), 99).await;
                assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));

                StoreLogData {
                    details: Some(json!({"error": "not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_object_not_found() {
        run_store_test("delete_object_not_found", "verify", "delete", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            let result = store.delete_object(&unknown_id).await;
            assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

            StoreLogData {
                details: Some(json!({"error": "object_not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_missing_object() {
        run_store_test("can_reconstruct_missing", "verify", "repair", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            assert!(!store.can_reconstruct(&unknown_id).await);

            StoreLogData {
                details: Some(json!({"can_reconstruct": false})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_with_policy_missing_object() {
        run_store_test(
            "can_reconstruct_policy_missing",
            "verify",
            "repair",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([99; 32]);
                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 0,
                };

                assert!(
                    !store
                        .can_reconstruct_with_policy(&unknown_id, &policy)
                        .await
                );

                StoreLogData {
                    details: Some(json!({"can_reconstruct_with_policy": false})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_distribution_missing_object() {
        run_store_test(
            "get_distribution_missing",
            "verify",
            "placement",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([99; 32]);

                assert!(store.get_distribution(&unknown_id).await.is_none());

                StoreLogData {
                    details: Some(json!({"distribution": "none"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_all_symbols_missing_object() {
        run_store_test("get_all_symbols_missing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            let symbols = store.get_all_symbols(&unknown_id).await;
            assert!(symbols.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_count_missing_object() {
        run_store_test("symbol_count_missing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            assert_eq!(store.symbol_count(&unknown_id).await, 0);

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn put_object_meta_duplicate_same_data() {
        run_store_test("put_meta_dup_same_data", "verify", "write", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let meta = test_object_meta();

            store.put_object_meta(meta.clone()).await.unwrap();
            // Same meta again should succeed
            store.put_object_meta(meta).await.unwrap();

            StoreLogData {
                details: Some(json!({"duplicate": "ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn put_object_meta_duplicate_different_data() {
        run_store_test(
            "put_meta_dup_different_data",
            "verify",
            "write",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let meta = test_object_meta();
                store.put_object_meta(meta).await.unwrap();

                // Different meta with same object_id
                let mut different = test_object_meta();
                different.source_symbols = 999;

                let result = store.put_object_meta(different).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                StoreLogData {
                    details: Some(json!({"error": "metadata_mismatch"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn list_zone_empty() {
        run_store_test("list_zone_empty_symbols", "verify", "list", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            let ids = store.list_zone(&test_zone()).await;
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_quota_returns_config_value() {
        run_store_test(
            "storage_quota_symbol",
            "verify",
            "accounting",
            1,
            || async {
                let config = MemorySymbolStoreConfig {
                    max_bytes: 99_999,
                    local_node_id: 0,
                };
                let store = MemorySymbolStore::new(config);

                assert_eq!(store.storage_quota().await, 99_999);

                StoreLogData {
                    details: Some(json!({"quota": 99_999})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn config_default_values() {
        run_store_test("symbol_config_default", "verify", "config", 2, || async {
            let config = MemorySymbolStoreConfig::default();
            assert_eq!(config.max_bytes, 512 * 1024 * 1024);
            assert_eq!(config.local_node_id, 0);

            StoreLogData {
                details: Some(json!({"max_bytes": config.max_bytes})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_symbol_frees_storage() {
        run_store_test(
            "delete_symbol_frees_storage",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                store.put_object_meta(test_object_meta()).await.unwrap();
                store.put_symbol(test_symbol(0)).await.unwrap();

                let used_before = store.storage_used().await;
                assert!(used_before > 0);

                store.delete_symbol(&test_object_id(), 0).await.unwrap();
                let used_after = store.storage_used().await;
                assert!(used_after < used_before);

                StoreLogData {
                    details: Some(json!({"freed": used_before - used_after})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_distribution_tracks_local_node() {
        run_store_test(
            "distribution_local_node",
            "verify",
            "placement",
            2,
            || async {
                let config = MemorySymbolStoreConfig {
                    max_bytes: 512 * 1024 * 1024,
                    local_node_id: 42,
                };
                let store = MemorySymbolStore::new(config);
                store.put_object_meta(test_object_meta()).await.unwrap();

                // Symbol with no source_node → falls back to local_node_id
                let mut symbol = test_symbol(0);
                symbol.meta.source_node = None;
                store.put_symbol(symbol).await.unwrap();

                let dist = store.get_distribution(&test_object_id()).await.unwrap();
                assert_eq!(dist.distinct_nodes(), 1);
                assert!(dist.nodes.contains_key(&42));

                StoreLogData {
                    details: Some(json!({"local_node": 42})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn list_zone() {
        run_store_test("list_zone_symbols", "verify", "list", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();

            let mut meta2 = test_object_meta();
            meta2.object_id = ObjectId::from_bytes([2_u8; 32]);
            store.put_object_meta(meta2).await.unwrap();

            let ids = store.list_zone(&test_zone()).await;
            assert_eq!(ids.len(), 2);

            StoreLogData {
                details: Some(json!({"zone_id": test_zone().to_string(), "count": ids.len()})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: SymbolMeta traits ---

    #[test]
    fn symbol_meta_clone_independence() {
        run_store_test("symbol_meta_clone", "verify", "traits", 2, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 7,
                zone_id: test_zone(),
                source_node: Some(99),
                stored_at: 500_000,
            };
            let cloned = meta.clone();
            drop(meta);
            assert_eq!(cloned.esi, 7);
            assert_eq!(cloned.source_node, Some(99));

            StoreLogData {
                details: Some(json!({"clone": "independent"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_debug_format() {
        run_store_test("symbol_meta_debug", "verify", "traits", 2, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 3,
                zone_id: test_zone(),
                source_node: None,
                stored_at: 42,
            };
            let dbg = format!("{meta:?}");
            assert!(dbg.contains("SymbolMeta"));
            assert!(dbg.contains("esi: 3"));

            StoreLogData {
                details: Some(json!({"debug_contains": "SymbolMeta"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_serde_none_source_node() {
        run_store_test("symbol_meta_serde_none", "verify", "serde", 2, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 0,
                zone_id: test_zone(),
                source_node: None,
                stored_at: 0,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let deserialized: SymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.source_node, None);
            assert_eq!(deserialized.stored_at, 0);

            StoreLogData {
                details: Some(json!({"serde": "none_source_node_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: StoredSymbol traits ---

    #[test]
    fn stored_symbol_clone_independence() {
        run_store_test("stored_symbol_clone", "verify", "traits", 2, || async {
            let sym = test_symbol(5);
            let cloned = sym.clone();
            drop(sym);
            assert_eq!(cloned.meta.esi, 5);
            assert_eq!(cloned.data.len(), 64);

            StoreLogData {
                details: Some(json!({"clone": "independent", "esi": 5})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn stored_symbol_debug_format() {
        run_store_test("stored_symbol_debug", "verify", "traits", 1, || async {
            let sym = test_symbol(11);
            let dbg = format!("{sym:?}");
            assert!(dbg.contains("StoredSymbol"));

            StoreLogData {
                details: Some(json!({"debug_contains": "StoredSymbol"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: ObjectTransmissionInfo ---

    #[test]
    fn oti_from_and_to_raptorq_roundtrip() {
        run_store_test("oti_raptorq_roundtrip", "verify", "codec", 5, || async {
            let raptorq_oti = ObjectTransmissionInformation::new(8192, 256, 4, 2, 16);
            let info = ObjectTransmissionInfo::from_oti(raptorq_oti);
            assert_eq!(info.transfer_length, 8192);
            assert_eq!(info.symbol_size, 256);
            assert_eq!(info.source_blocks, 4);
            assert_eq!(info.sub_blocks, 2);
            assert_eq!(info.alignment, 16);

            let back = info.to_oti();
            assert_eq!(back.transfer_length(), 8192);
            assert_eq!(back.symbol_size(), 256);

            StoreLogData {
                details: Some(json!({"roundtrip": "raptorq_oti_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_from_trait_impl() {
        run_store_test("oti_from_trait", "verify", "codec", 2, || async {
            let raptorq_oti = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
            let info: ObjectTransmissionInfo = raptorq_oti.into();
            assert_eq!(info.transfer_length, 1024);
            assert_eq!(info.symbol_size, 64);

            let back: ObjectTransmissionInformation = info.into();
            assert_eq!(back.transfer_length(), 1024);

            StoreLogData {
                details: Some(json!({"from_trait": "ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_equality() {
        run_store_test("oti_equality", "verify", "traits", 2, || async {
            let a = ObjectTransmissionInfo {
                transfer_length: 512,
                symbol_size: 32,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 4,
            };
            let b = ObjectTransmissionInfo {
                transfer_length: 512,
                symbol_size: 32,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 4,
            };
            assert_eq!(a, b);

            let c = ObjectTransmissionInfo {
                transfer_length: 999,
                ..a
            };
            assert_ne!(a, c);

            StoreLogData {
                details: Some(json!({"eq": true, "ne": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_debug_format() {
        run_store_test("oti_debug", "verify", "traits", 1, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 2048,
                symbol_size: 128,
                source_blocks: 2,
                sub_blocks: 1,
                alignment: 8,
            };
            let dbg = format!("{oti:?}");
            assert!(dbg.contains("ObjectTransmissionInfo"));

            StoreLogData {
                details: Some(json!({"debug_contains": "ObjectTransmissionInfo"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: ObjectSymbolMeta ---

    #[test]
    fn object_symbol_meta_clone_independence() {
        run_store_test("osm_clone", "verify", "traits", 2, || async {
            let meta = test_object_meta();
            let cloned = meta.clone();
            drop(meta);
            assert_eq!(cloned.source_symbols, 16);
            assert_eq!(cloned.oti.symbol_size, 64);

            StoreLogData {
                details: Some(json!({"clone": "independent"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_equality() {
        run_store_test("osm_equality", "verify", "traits", 2, || async {
            let a = test_object_meta();
            let b = test_object_meta();
            assert_eq!(a, b);

            let mut c = test_object_meta();
            c.source_symbols = 999;
            assert_ne!(a, c);

            StoreLogData {
                details: Some(json!({"eq": true, "ne": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_debug_format() {
        run_store_test("osm_debug", "verify", "traits", 1, || async {
            let meta = test_object_meta();
            let dbg = format!("{meta:?}");
            assert!(dbg.contains("ObjectSymbolMeta"));

            StoreLogData {
                details: Some(json!({"debug_contains": "ObjectSymbolMeta"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: MemorySymbolStoreConfig ---

    #[test]
    fn config_clone() {
        run_store_test("config_clone", "verify", "traits", 2, || async {
            let config = MemorySymbolStoreConfig {
                max_bytes: 12345,
                local_node_id: 77,
            };
            let cloned = config.clone();
            assert_eq!(config.max_bytes, cloned.max_bytes);
            assert_eq!(cloned.max_bytes, 12345);
            assert_eq!(cloned.local_node_id, 77);

            StoreLogData {
                details: Some(json!({"clone_max_bytes": 12345})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn config_debug_format() {
        run_store_test("config_debug", "verify", "traits", 1, || async {
            let config = MemorySymbolStoreConfig::default();
            let dbg = format!("{config:?}");
            assert!(dbg.contains("MemorySymbolStoreConfig"));

            StoreLogData {
                details: Some(json!({"debug_contains": "MemorySymbolStoreConfig"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: MemorySymbolStore advanced operations ---

    #[test]
    fn list_zone_filters_by_zone() {
        run_store_test("list_zone_filter", "verify", "list", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            // Object in zone "z:test"
            store.put_object_meta(test_object_meta()).await.unwrap();

            // Object in zone "z:other"
            let meta2 = ObjectSymbolMeta {
                object_id: ObjectId::from_bytes([2_u8; 32]),
                zone_id: "z:other".parse().unwrap(),
                oti: test_object_meta().oti,
                source_symbols: 16,
                first_symbol_at: 1_000_000,
            };
            store.put_object_meta(meta2).await.unwrap();

            let test_ids = store.list_zone(&test_zone()).await;
            assert_eq!(test_ids.len(), 1);

            let other_zone: ZoneId = "z:other".parse().unwrap();
            let other_ids = store.list_zone(&other_zone).await;
            assert_eq!(other_ids.len(), 1);

            StoreLogData {
                details: Some(json!({"test_zone_count": 1, "other_zone_count": 1})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_distribution_single_node() {
        run_store_test("dist_single_node", "verify", "placement", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            for esi in 0..4 {
                let mut sym = test_symbol(esi);
                sym.meta.source_node = Some(7);
                store.put_symbol(sym).await.unwrap();
            }

            let dist = store.get_distribution(&test_object_id()).await.unwrap();
            assert_eq!(dist.distinct_nodes(), 1);
            assert_eq!(dist.total_symbols, 4);
            assert!(dist.nodes.contains_key(&7));

            StoreLogData {
                details: Some(json!({"nodes": 1, "symbols": 4})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_distribution_multi_node() {
        run_store_test("dist_multi_node", "verify", "placement", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            for esi in 0..3 {
                let mut sym = test_symbol(esi);
                sym.meta.source_node = Some(10);
                store.put_symbol(sym).await.unwrap();
            }
            for esi in 3..5 {
                let mut sym = test_symbol(esi);
                sym.meta.source_node = Some(20);
                store.put_symbol(sym).await.unwrap();
            }
            let mut sym = test_symbol(5);
            sym.meta.source_node = Some(30);
            store.put_symbol(sym).await.unwrap();

            let dist = store.get_distribution(&test_object_id()).await.unwrap();
            assert_eq!(dist.distinct_nodes(), 3);
            assert_eq!(dist.total_symbols, 6);
            assert_eq!(dist.max_node_symbols(), 3);

            StoreLogData {
                details: Some(json!({"nodes": 3, "symbols": 6, "max_per_node": 3})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_used_tracks_multiple_objects() {
        run_store_test("storage_tracks_multi", "verify", "accounting", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            assert_eq!(store.storage_used().await, 0);

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            let after_one = store.storage_used().await;
            assert!(after_one > 0);

            store.put_symbol(test_symbol(1)).await.unwrap();
            let after_two = store.storage_used().await;
            assert!(after_two > after_one);

            StoreLogData {
                details: Some(json!({"after_one": after_one, "after_two": after_two})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_object_then_reinsert() {
        run_store_test("delete_reinsert", "verify", "lifecycle", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 1);

            store.delete_object(&test_object_id()).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 0);

            // Re-insert the same object
            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 1);

            StoreLogData {
                details: Some(json!({"lifecycle": "delete_reinsert_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_object_meta_success() {
        run_store_test("get_object_meta_ok", "verify", "read", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let meta = test_object_meta();
            store.put_object_meta(meta.clone()).await.unwrap();

            let retrieved = store.get_object_meta(&test_object_id()).await.unwrap();
            assert_eq!(retrieved.object_id, meta.object_id);
            assert_eq!(retrieved.source_symbols, meta.source_symbols);
            assert_eq!(retrieved.oti, meta.oti);

            StoreLogData {
                details: Some(json!({"meta_retrieved": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_object_meta_not_found() {
        run_store_test("get_object_meta_missing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([88; 32]);

            let result = store.get_object_meta(&unknown_id).await;
            assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

            StoreLogData {
                details: Some(json!({"error": "object_not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_boundary() {
        run_store_test("can_reconstruct_boundary", "verify", "repair", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            let mut meta = test_object_meta();
            meta.source_symbols = 3;
            store.put_object_meta(meta).await.unwrap();

            // 2 symbols: not enough (need 3)
            store.put_symbol(test_symbol(0)).await.unwrap();
            store.put_symbol(test_symbol(1)).await.unwrap();
            assert!(!store.can_reconstruct(&test_object_id()).await);

            // 3 symbols: exactly enough
            store.put_symbol(test_symbol(2)).await.unwrap();
            assert!(store.can_reconstruct(&test_object_id()).await);

            StoreLogData {
                details: Some(json!({"boundary": "K=3"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_symbol_object_not_found() {
        run_store_test(
            "delete_symbol_obj_missing",
            "verify",
            "delete",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([77; 32]);

                let result = store.delete_symbol(&unknown_id, 0).await;
                assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

                StoreLogData {
                    details: Some(json!({"error": "object_not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn storage_used_zero_initially() {
        run_store_test("storage_used_zero", "verify", "accounting", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                details: Some(json!({"used": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_exact_boundary() {
        run_store_test("quota_exact_boundary", "verify", "accounting", 2, || async {
            let sample = test_symbol(0);
            let size = MemorySymbolStore::symbol_size(&sample);
            // Set quota to exactly 2 symbols worth
            let config = MemorySymbolStoreConfig {
                max_bytes: size * 2,
                local_node_id: 0,
            };
            let store = MemorySymbolStore::new(config);
            store.put_object_meta(test_object_meta()).await.unwrap();

            store.put_symbol(test_symbol(0)).await.unwrap();
            store.put_symbol(test_symbol(1)).await.unwrap();

            // Third symbol should exceed quota
            let result = store.put_symbol(test_symbol(2)).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::QuotaExceeded { .. })
            ));

            // Verify exactly 2 stored
            assert_eq!(store.symbol_count(&test_object_id()).await, 2);

            StoreLogData {
                details: Some(json!({"quota_boundary": "2_symbols_exact"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_frees_quota_for_new_symbols() {
        run_store_test("delete_frees_quota", "verify", "accounting", 2, || async {
            let sample = test_symbol(0);
            let size = MemorySymbolStore::symbol_size(&sample);
            let config = MemorySymbolStoreConfig {
                max_bytes: size,
                local_node_id: 0,
            };
            let store = MemorySymbolStore::new(config);
            store.put_object_meta(test_object_meta()).await.unwrap();

            store.put_symbol(test_symbol(0)).await.unwrap();

            // Full: cannot add more
            let result = store.put_symbol(test_symbol(1)).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::QuotaExceeded { .. })
            ));

            // Delete the symbol
            store.delete_symbol(&test_object_id(), 0).await.unwrap();

            // Now we can add again
            store.put_symbol(test_symbol(1)).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 1);

            StoreLogData {
                details: Some(json!({"freed_and_reused": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_all_symbols_empty_object() {
        run_store_test("get_all_symbols_empty", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            // Object exists but has no symbols
            let symbols = store.get_all_symbols(&test_object_id()).await;
            assert!(symbols.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_count_with_existing_symbols() {
        run_store_test("symbol_count_existing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            for esi in 0..7 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }
            assert_eq!(store.symbol_count(&test_object_id()).await, 7);

            StoreLogData {
                details: Some(json!({"count": 7})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_with_policy_no_diversity_required() {
        run_store_test(
            "reconstruct_policy_no_div",
            "verify",
            "repair",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let mut meta = test_object_meta();
                meta.source_symbols = 2;
                store.put_object_meta(meta).await.unwrap();

                // All from same node, but min_source_diversity=0
                for esi in 0..2 {
                    let mut sym = test_symbol(esi);
                    sym.meta.source_node = Some(1);
                    store.put_symbol(sym).await.unwrap();
                }

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 0,
                };

                assert!(
                    store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                StoreLogData {
                    details: Some(json!({"no_diversity": "passes"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn multiple_objects_independent() {
        run_store_test("multi_object_independent", "verify", "isolation", 4, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            // Object 1
            let meta1 = test_object_meta();
            store.put_object_meta(meta1).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            // Object 2 with different ID
            let obj2_id = ObjectId::from_bytes([2_u8; 32]);
            let meta2 = ObjectSymbolMeta {
                object_id: obj2_id,
                zone_id: test_zone(),
                oti: test_object_meta().oti,
                source_symbols: 16,
                first_symbol_at: 2_000_000,
            };
            store.put_object_meta(meta2).await.unwrap();
            let sym2 = StoredSymbol {
                meta: SymbolMeta {
                    object_id: obj2_id,
                    esi: 0,
                    zone_id: test_zone(),
                    source_node: Some(2),
                    stored_at: 2_000_000,
                },
                data: Bytes::from(vec![1_u8; 64]),
            };
            store.put_symbol(sym2).await.unwrap();

            assert_eq!(store.symbol_count(&test_object_id()).await, 1);
            assert_eq!(store.symbol_count(&obj2_id).await, 1);

            // Delete object 1 should not affect object 2
            store.delete_object(&test_object_id()).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 0);
            assert_eq!(store.symbol_count(&obj2_id).await, 1);

            StoreLogData {
                details: Some(json!({"objects_independent": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_serde_json_field_names() {
        run_store_test("oti_serde_fields", "verify", "serde", 3, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 4096,
                symbol_size: 128,
                source_blocks: 2,
                sub_blocks: 4,
                alignment: 16,
            };
            let json_str = serde_json::to_string(&oti).unwrap();
            assert!(json_str.contains("transfer_length"));
            assert!(json_str.contains("symbol_size"));
            assert!(json_str.contains("alignment"));

            StoreLogData {
                details: Some(json!({"fields": "present"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_serde_all_fields_preserved() {
        run_store_test("symbol_meta_serde_all", "verify", "serde", 5, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 42,
                zone_id: test_zone(),
                source_node: Some(777),
                stored_at: 123_456_789,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let rt: SymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(rt.object_id, test_object_id());
            assert_eq!(rt.esi, 42);
            assert_eq!(rt.zone_id, test_zone());
            assert_eq!(rt.source_node, Some(777));
            assert_eq!(rt.stored_at, 123_456_789);

            StoreLogData {
                details: Some(json!({"all_fields": "preserved"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_serde_all_fields() {
        run_store_test("osm_serde_all_fields", "verify", "serde", 4, || async {
            let meta = ObjectSymbolMeta {
                object_id: test_object_id(),
                zone_id: test_zone(),
                oti: ObjectTransmissionInfo {
                    transfer_length: 9999,
                    symbol_size: 200,
                    source_blocks: 3,
                    sub_blocks: 2,
                    alignment: 4,
                },
                source_symbols: 50,
                first_symbol_at: 999_888_777,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let rt: ObjectSymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(rt.oti.transfer_length, 9999);
            assert_eq!(rt.oti.symbol_size, 200);
            assert_eq!(rt.source_symbols, 50);
            assert_eq!(rt.first_symbol_at, 999_888_777);

            StoreLogData {
                details: Some(json!({"all_osm_fields": "preserved"})),
                ..StoreLogData::default()
            }
        });
    }
}
