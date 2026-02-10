//! Object store interface for FCP2.
//!
//! Provides content-addressed storage for complete mesh objects.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use fcp_core::{ObjectHeader, ObjectId, RetentionClass, StorageMeta, StoredObject, ZoneId};
use parking_lot::RwLock;

use crate::error::ObjectStoreError;

/// Object store interface (NORMATIVE).
///
/// Stores complete, content-addressed objects with retention policies.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Store an object.
    ///
    /// # Errors
    /// Returns error if object already exists or quota exceeded.
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError>;

    /// Retrieve an object by ID.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError>;

    /// Check if object exists.
    async fn exists(&self, id: &ObjectId) -> bool;

    /// Delete an object.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError>;

    /// Get object header without body.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError>;

    /// Get storage metadata.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError>;

    /// Update retention class for an object.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError>;

    /// List all object IDs in a zone.
    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId>;

    /// Get total storage used in bytes.
    async fn storage_used(&self) -> u64;

    /// Get storage quota in bytes.
    async fn storage_quota(&self) -> u64;
}

/// Configuration for in-memory object store.
#[derive(Debug, Clone)]
pub struct MemoryObjectStoreConfig {
    /// Maximum storage in bytes.
    pub max_bytes: u64,
}

impl Default for MemoryObjectStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024, // 256MB
        }
    }
}

/// In-memory object store implementation.
///
/// Suitable for testing and single-node deployments.
pub struct MemoryObjectStore {
    objects: RwLock<HashMap<ObjectId, StoredObject>>,
    config: MemoryObjectStoreConfig,
    used_bytes: AtomicU64,
}

impl MemoryObjectStore {
    /// Create a new in-memory object store.
    #[must_use]
    pub fn new(config: MemoryObjectStoreConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            used_bytes: AtomicU64::new(0),
        }
    }

    fn object_size(obj: &StoredObject) -> u64 {
        // Approximate size: body + header overhead
        #[allow(clippy::cast_possible_truncation)]
        let size = obj.body.len() as u64 + 512; // 512 byte header estimate
        size
    }
}

#[async_trait]
impl ObjectStore for MemoryObjectStore {
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
        let size = Self::object_size(&object);

        // Optimistically increment quota
        let prev_used = self.used_bytes.fetch_add(size, Ordering::SeqCst);
        if prev_used + size > self.config.max_bytes {
            // Rollback if exceeded
            self.used_bytes.fetch_sub(size, Ordering::SeqCst);
            return Err(ObjectStoreError::QuotaExceeded {
                used: prev_used,
                max: self.config.max_bytes,
            });
        }

        let mut objects = self.objects.write();

        if objects.contains_key(&object.object_id) {
            // Rollback if duplicate
            self.used_bytes.fetch_sub(size, Ordering::SeqCst);
            return Err(ObjectStoreError::AlreadyExists(object.object_id));
        }

        let id = object.object_id;
        objects.insert(id, object);

        Ok(())
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.objects.read().contains_key(id)
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        let mut objects = self.objects.write();
        let obj = objects.remove(id).ok_or(ObjectStoreError::NotFound(*id))?;

        let size = Self::object_size(&obj);
        self.used_bytes.fetch_sub(size, Ordering::SeqCst);

        Ok(())
    }

    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .map(|obj| obj.header.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .map(|obj| obj.storage.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        let mut objects = self.objects.write();
        let obj = objects.get_mut(id).ok_or(ObjectStoreError::NotFound(*id))?;

        obj.storage.retention = retention;
        Ok(())
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.objects
            .read()
            .values()
            .filter(|obj| &obj.header.zone_id == zone_id)
            .map(|obj| obj.object_id)
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        self.used_bytes.load(Ordering::SeqCst)
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use chrono::Utc;
    use fcp_cbor::SchemaId;
    use fcp_core::Provenance;
    use semver::Version;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

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
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            rt.block_on(f())
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

    fn test_stored_object(id_byte: u8, body: &[u8]) -> StoredObject {
        StoredObject {
            object_id: ObjectId::from_bytes([id_byte; 32]),
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
                zone_id: test_zone(),
                created_at: 1_000_000,
                provenance: Provenance::new(test_zone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            body: body.to_vec(),
            storage: StorageMeta {
                retention: RetentionClass::Ephemeral,
            },
        }
    }

    #[test]
    fn put_and_get() {
        run_store_test("put_and_get", "verify", "write", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"test body");
            let id = obj.object_id;
            let size = obj.body.len() as u64;

            store.put(obj.clone()).await.unwrap();

            let retrieved = store.get(&id).await.unwrap();
            assert_eq!(retrieved.body, b"test body");

            StoreLogData {
                object_id: Some(id),
                object_size: Some(size),
                details: Some(json!({"zone_id": test_zone().to_string()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_not_found() {
        run_store_test("get_not_found", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([99_u8; 32]);

            let result = store.get(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn put_duplicate_rejected() {
        run_store_test("put_duplicate_rejected", "verify", "write", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;

            store.put(obj.clone()).await.unwrap();
            let result = store.put(obj).await;
            assert!(matches!(result, Err(ObjectStoreError::AlreadyExists(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "already_exists"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_object() {
        run_store_test("delete_object", "verify", "delete", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            let size = obj.body.len() as u64;

            store.put(obj).await.unwrap();
            assert!(store.exists(&id).await);

            store.delete(&id).await.unwrap();
            assert!(!store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                object_size: Some(size),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_enforcement() {
        run_store_test("quota_enforcement", "verify", "write", 1, || async {
            let config = MemoryObjectStoreConfig { max_bytes: 1000 };
            let store = MemoryObjectStore::new(config);

            let obj = test_stored_object(1, &vec![0_u8; 1000]);
            let size = obj.body.len() as u64;

            let result = store.put(obj).await;
            assert!(matches!(
                result,
                Err(ObjectStoreError::QuotaExceeded { .. })
            ));

            StoreLogData {
                object_size: Some(size),
                details: Some(json!({"error": "quota_exceeded"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn duplicate_object_does_not_report_quota() {
        run_store_test(
            "duplicate_object_does_not_report_quota",
            "verify",
            "write",
            2,
            || async {
                let obj = test_stored_object(1, b"body");
                let size = MemoryObjectStore::object_size(&obj);
                let config = MemoryObjectStoreConfig { max_bytes: size };
                let store = MemoryObjectStore::new(config);

                store.put(obj.clone()).await.unwrap();

                let used_before = store.storage_used().await;
                let result = store.put(obj.clone()).await;
                assert!(matches!(result, Err(ObjectStoreError::AlreadyExists(_))));

                let used_after = store.storage_used().await;
                assert_eq!(used_before, used_after);

                StoreLogData {
                    object_id: Some(obj.object_id),
                    object_size: Some(obj.body.len() as u64),
                    details: Some(json!({
                        "used_bytes": used_after,
                        "duplicate_insert": "already_exists"
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn set_retention() {
        run_store_test("set_retention", "verify", "retention", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;

            store.put(obj).await.unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Ephemeral));

            store
                .set_retention(&id, RetentionClass::Pinned)
                .await
                .unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Pinned));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"retention": "Pinned"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone() {
        run_store_test("list_zone", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            store.put(test_stored_object(1, b"a")).await.unwrap();
            store.put(test_stored_object(2, b"b")).await.unwrap();
            store.put(test_stored_object(3, b"c")).await.unwrap();

            let ids = store.list_zone(&test_zone()).await;
            assert_eq!(ids.len(), 3);

            StoreLogData {
                details: Some(json!({"zone_id": test_zone().to_string(), "count": ids.len()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_accounting() {
        run_store_test("storage_accounting", "verify", "accounting", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            assert_eq!(store.storage_used().await, 0);

            let obj = test_stored_object(1, b"test body content");
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let used = store.storage_used().await;
            assert!(used > 0);

            store.delete(&id).await.unwrap();
            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"used_bytes": used})),
                ..StoreLogData::default()
            }
        });
    }
}
