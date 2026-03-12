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
        let mut objects = self.objects.write();

        if objects.contains_key(&object.object_id) {
            return Err(ObjectStoreError::AlreadyExists(object.object_id));
        }

        let size = Self::object_size(&object);
        let used = self.used_bytes.load(Ordering::SeqCst);
        if used.saturating_add(size) > self.config.max_bytes {
            return Err(ObjectStoreError::QuotaExceeded {
                used,
                max: self.config.max_bytes,
            });
        }

        let id = object.object_id;
        objects.insert(id, object);
        self.used_bytes.fetch_add(size, Ordering::SeqCst);

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

    // --- Additional object store tests ---

    #[test]
    fn get_header_success() {
        run_store_test("get_header_success", "verify", "read", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            let zone = obj.header.zone_id.clone();

            store.put(obj).await.unwrap();

            let header = store.get_header(&id).await.unwrap();
            assert_eq!(header.zone_id, zone);
            assert!(header.refs.is_empty());

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"header_zone": zone.to_string()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_header_not_found() {
        run_store_test("get_header_not_found", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([77; 32]);

            let result = store.get_header(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_storage_meta_success() {
        run_store_test("get_storage_meta_success", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;

            store.put(obj).await.unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Ephemeral));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"retention": "Ephemeral"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_storage_meta_not_found() {
        run_store_test(
            "get_storage_meta_not_found",
            "verify",
            "read",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let id = ObjectId::from_bytes([88; 32]);

                let result = store.get_storage_meta(&id).await;
                assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"error": "not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn set_retention_not_found() {
        run_store_test(
            "set_retention_not_found",
            "verify",
            "retention",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let id = ObjectId::from_bytes([99; 32]);

                let result = store.set_retention(&id, RetentionClass::Pinned).await;
                assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"error": "not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_not_found() {
        run_store_test("delete_not_found", "verify", "delete", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([55; 32]);

            let result = store.delete(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_empty() {
        run_store_test("list_zone_empty", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            let ids = store.list_zone(&test_zone()).await;
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_filters_by_zone() {
        run_store_test("list_zone_filters_by_zone", "verify", "list", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            // Objects in z:test
            store.put(test_stored_object(1, b"a")).await.unwrap();
            store.put(test_stored_object(2, b"b")).await.unwrap();

            // Object in different zone
            let mut other_zone_obj = test_stored_object(3, b"c");
            other_zone_obj.header.zone_id = "z:other".parse().unwrap();
            store.put(other_zone_obj).await.unwrap();

            let test_ids = store.list_zone(&test_zone()).await;
            assert_eq!(test_ids.len(), 2);

            let other_ids = store.list_zone(&"z:other".parse().unwrap()).await;
            assert_eq!(other_ids.len(), 1);

            StoreLogData {
                details: Some(json!({"test_count": 2, "other_count": 1})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_quota_returns_config_value() {
        run_store_test(
            "storage_quota_returns_config",
            "verify",
            "accounting",
            1,
            || async {
                let config = MemoryObjectStoreConfig { max_bytes: 42_000 };
                let store = MemoryObjectStore::new(config);

                assert_eq!(store.storage_quota().await, 42_000);

                StoreLogData {
                    details: Some(json!({"quota": 42_000})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn exists_returns_false_for_unknown() {
        run_store_test("exists_false_unknown", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([42; 32]);

            assert!(!store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"exists": false})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn set_retention_to_lease() {
        run_store_test(
            "set_retention_to_lease",
            "verify",
            "retention",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(1, b"body");
                let id = obj.object_id;

                store.put(obj).await.unwrap();

                store
                    .set_retention(&id, RetentionClass::Lease { expires_at: 5000 })
                    .await
                    .unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(
                    meta.retention,
                    RetentionClass::Lease { expires_at: 5000 }
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"retention": "Lease", "expires_at": 5000})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn config_default_values() {
        run_store_test("config_default_values", "verify", "config", 1, || async {
            let config = MemoryObjectStoreConfig::default();
            assert_eq!(config.max_bytes, 256 * 1024 * 1024);

            StoreLogData {
                details: Some(json!({"max_bytes": config.max_bytes})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn config_clone() {
        let config = MemoryObjectStoreConfig { max_bytes: 999 };
        let cloned = config.clone();
        assert_eq!(cloned.max_bytes, config.max_bytes);
    }

    #[test]
    fn config_debug() {
        let config = MemoryObjectStoreConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MemoryObjectStoreConfig"));
    }

    #[test]
    fn storage_used_accumulates() {
        run_store_test(
            "storage_used_accumulates",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                let obj1 = test_stored_object(1, b"aaaa");
                let obj2 = test_stored_object(2, b"bbbb");

                store.put(obj1).await.unwrap();
                let used1 = store.storage_used().await;

                store.put(obj2).await.unwrap();
                let used2 = store.storage_used().await;

                assert!(used2 > used1);
                assert_eq!(used2, used1 * 2); // Same size objects

                StoreLogData {
                    details: Some(json!({"used1": used1, "used2": used2})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_after_delete_returns_not_found() {
        run_store_test("get_after_delete", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"data");
            let id = obj.object_id;

            store.put(obj).await.unwrap();
            store.delete(&id).await.unwrap();

            let result = store.get(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"get_after_delete": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn set_retention_from_pinned_to_ephemeral() {
        run_store_test(
            "retention_pinned_to_ephemeral",
            "verify",
            "retention",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(1, b"body");
                let id = obj.object_id;

                store.put(obj).await.unwrap();
                store
                    .set_retention(&id, RetentionClass::Pinned)
                    .await
                    .unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(meta.retention, RetentionClass::Pinned));

                store
                    .set_retention(&id, RetentionClass::Ephemeral)
                    .await
                    .unwrap();
                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(meta.retention, RetentionClass::Ephemeral));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"pinned_to_ephemeral": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn list_zone_non_matching_empty() {
        run_store_test("list_zone_non_matching", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"a")).await.unwrap();

            let other_zone: ZoneId = "z:other".parse().unwrap();
            let ids = store.list_zone(&other_zone).await;
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"non_matching": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn multiple_put_delete_storage_returns_zero() {
        run_store_test("put_delete_cycles", "verify", "accounting", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            for i in 1..=5 {
                let obj = test_stored_object(i, &[0_u8; 100]);
                store.put(obj).await.unwrap();
            }
            for i in 1..=5 {
                store.delete(&ObjectId::from_bytes([i; 32])).await.unwrap();
            }

            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                details: Some(json!({"cycles": 5, "final_used": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_exact_boundary() {
        run_store_test("quota_exact_boundary", "verify", "write", 2, || async {
            // Object size = body.len() + 512 header estimate
            // So a body of 488 bytes → 1000 total
            let config = MemoryObjectStoreConfig { max_bytes: 1000 };
            let store = MemoryObjectStore::new(config);

            let obj = test_stored_object(1, &vec![0_u8; 488]);
            store.put(obj).await.unwrap(); // Exactly at quota

            // Second object should fail
            let obj2 = test_stored_object(2, b"x");
            let result = store.put(obj2).await;
            assert!(matches!(
                result,
                Err(ObjectStoreError::QuotaExceeded { .. })
            ));

            StoreLogData {
                details: Some(json!({"boundary": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_frees_storage() {
        run_store_test(
            "delete_frees_storage",
            "verify",
            "accounting",
            3,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                let obj = test_stored_object(1, b"some body data here");
                let id = obj.object_id;

                store.put(obj).await.unwrap();
                let used_after_put = store.storage_used().await;
                assert!(used_after_put > 0);

                store.delete(&id).await.unwrap();
                let used_after_delete = store.storage_used().await;
                assert_eq!(used_after_delete, 0);

                // Can re-add after delete
                let obj2 = test_stored_object(1, b"new body");
                store.put(obj2).await.unwrap();

                StoreLogData {
                    object_id: Some(id),
                    details: Some(
                        json!({"used_after_put": used_after_put, "used_after_delete": used_after_delete}),
                    ),
                    ..StoreLogData::default()
                }
            },
        );
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

    // --- MemoryObjectStoreConfig tests ---

    #[test]
    fn memory_object_store_config_default_value() {
        let config = MemoryObjectStoreConfig::default();
        assert_eq!(config.max_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn memory_object_store_config_debug_format() {
        let config = MemoryObjectStoreConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MemoryObjectStoreConfig"));
        assert!(dbg.contains("max_bytes"));
    }

    #[test]
    fn memory_object_store_config_clone_preserves() {
        let config = MemoryObjectStoreConfig { max_bytes: 42 };
        let cloned = config.clone();
        assert_eq!(config.max_bytes, cloned.max_bytes);
    }

    // --- Multiple object lifecycle tests ---

    #[test]
    fn put_multiple_get_each() {
        run_store_test("put_multiple_get_each", "verify", "read", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"aaa")).await.unwrap();
            store.put(test_stored_object(2, b"bbb")).await.unwrap();
            store.put(test_stored_object(3, b"ccc")).await.unwrap();

            let a = store.get(&ObjectId::from_bytes([1; 32])).await.unwrap();
            assert_eq!(a.body, b"aaa");
            let b = store.get(&ObjectId::from_bytes([2; 32])).await.unwrap();
            assert_eq!(b.body, b"bbb");
            let c = store.get(&ObjectId::from_bytes([3; 32])).await.unwrap();
            assert_eq!(c.body, b"ccc");

            StoreLogData {
                details: Some(json!({"count": 3})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_then_get_returns_not_found() {
        run_store_test("delete_then_get", "verify", "delete", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            store.delete(&id).await.unwrap();

            let result = store.get(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_used_increases_with_puts() {
        run_store_test(
            "storage_used_accumulates",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                store.put(test_stored_object(1, b"aaaa")).await.unwrap();
                let used1 = store.storage_used().await;

                store.put(test_stored_object(2, b"bbbb")).await.unwrap();
                let used2 = store.storage_used().await;

                assert!(used2 > used1);
                assert!(used1 > 0);

                StoreLogData {
                    details: Some(json!({"used1": used1, "used2": used2})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn exists_returns_true_after_put() {
        run_store_test("exists_true_after_put", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            assert!(store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn set_retention_ephemeral_to_pinned_to_lease() {
        run_store_test("retention_cycle", "verify", "retention", 3, || async {
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

            store
                .set_retention(&id, RetentionClass::Lease { expires_at: 9999 })
                .await
                .unwrap();
            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(
                meta.retention,
                RetentionClass::Lease { expires_at: 9999 }
            ));

            StoreLogData {
                object_id: Some(id),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_no_other_zone() {
        run_store_test("list_zone_no_other", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"a")).await.unwrap();

            let ids = store.list_zone(&"z:nonexistent".parse().unwrap()).await;
            assert!(ids.is_empty());

            StoreLogData::default()
        });
    }

    #[test]
    fn quota_boundary_exact_fit() {
        run_store_test("quota_boundary_exact", "verify", "write", 1, || async {
            // Object size = body.len() + 512 header estimate
            // If body is 0 bytes, object_size = 512. Set quota to exactly 512.
            let config = MemoryObjectStoreConfig { max_bytes: 512 };
            let store = MemoryObjectStore::new(config);
            let obj = test_stored_object(1, b"");
            let result = store.put(obj).await;
            assert!(result.is_ok());

            StoreLogData::default()
        });
    }

    #[test]
    fn quota_boundary_one_byte_short() {
        run_store_test("quota_boundary_short", "verify", "write", 1, || async {
            let config = MemoryObjectStoreConfig { max_bytes: 511 };
            let store = MemoryObjectStore::new(config);
            let obj = test_stored_object(1, b"");
            let result = store.put(obj).await;
            assert!(matches!(
                result,
                Err(ObjectStoreError::QuotaExceeded { .. })
            ));

            StoreLogData::default()
        });
    }

    #[test]
    fn get_header_zone_matches() {
        run_store_test("get_header_zone_matches", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(5, b"hello");
            let expected_zone = obj.header.zone_id.clone();
            store.put(obj).await.unwrap();

            let hdr = store
                .get_header(&ObjectId::from_bytes([5; 32]))
                .await
                .unwrap();
            assert_eq!(hdr.zone_id, expected_zone);

            StoreLogData::default()
        });
    }

    // --- Additional MemoryObjectStore edge case tests ---

    #[test]
    fn empty_body_object_stored_and_retrieved() {
        run_store_test("empty_body_object", "verify", "write", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"");
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let retrieved = store.get(&id).await.unwrap();
            assert!(retrieved.body.is_empty());
            assert!(store.exists(&id).await);

            StoreLogData::default()
        });
    }

    #[test]
    fn large_body_object_stored() {
        run_store_test("large_body_object", "verify", "write", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig {
                max_bytes: 10 * 1024 * 1024,
            });
            let body = vec![0xAB_u8; 8192];
            let obj = test_stored_object(1, &body);
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let retrieved = store.get(&id).await.unwrap();
            assert_eq!(retrieved.body.len(), 8192);

            StoreLogData::default()
        });
    }

    #[test]
    fn storage_used_zero_after_construction() {
        run_store_test(
            "storage_used_zero_init",
            "verify",
            "accounting",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                assert_eq!(store.storage_used().await, 0);
                StoreLogData::default()
            },
        );
    }

    #[test]
    fn delete_then_reinsert_same_id() {
        run_store_test("delete_then_reinsert", "verify", "write", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"original");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            store.delete(&id).await.unwrap();

            let obj2 = test_stored_object(1, b"replaced");
            store.put(obj2).await.unwrap();
            let retrieved = store.get(&id).await.unwrap();
            assert_eq!(retrieved.body, b"replaced");

            StoreLogData::default()
        });
    }

    #[test]
    fn exists_false_after_delete() {
        run_store_test("exists_false_after_delete", "verify", "read", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"data");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            assert!(store.exists(&id).await);
            store.delete(&id).await.unwrap();
            assert!(!store.exists(&id).await);

            StoreLogData::default()
        });
    }

    #[test]
    fn list_zone_after_delete() {
        run_store_test("list_zone_after_delete", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"a")).await.unwrap();
            store.put(test_stored_object(2, b"b")).await.unwrap();
            store.delete(&ObjectId::from_bytes([1; 32])).await.unwrap();

            let ids = store.list_zone(&test_zone()).await;
            assert_eq!(ids.len(), 1);

            StoreLogData::default()
        });
    }

    #[test]
    fn get_header_refs_empty() {
        run_store_test("get_header_refs_empty", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            store.put(obj).await.unwrap();

            let hdr = store
                .get_header(&ObjectId::from_bytes([1; 32]))
                .await
                .unwrap();
            assert!(hdr.refs.is_empty());
            assert!(hdr.foreign_refs.is_empty());

            StoreLogData::default()
        });
    }

    #[test]
    fn config_custom_max_bytes() {
        let config = MemoryObjectStoreConfig { max_bytes: 42 };
        assert_eq!(config.max_bytes, 42);
    }

    #[test]
    fn storage_decreases_after_delete() {
        run_store_test("storage_decreases", "verify", "accounting", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"some data");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            let used_before = store.storage_used().await;

            store.delete(&id).await.unwrap();
            let used_after = store.storage_used().await;
            assert!(used_after < used_before);

            StoreLogData::default()
        });
    }

    #[test]
    fn set_retention_lease_preserves_body() {
        run_store_test(
            "retention_preserves_body",
            "verify",
            "retention",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(1, b"important data");
                let id = obj.object_id;
                store.put(obj).await.unwrap();
                store
                    .set_retention(&id, RetentionClass::Lease { expires_at: 9999 })
                    .await
                    .unwrap();

                let retrieved = store.get(&id).await.unwrap();
                assert_eq!(retrieved.body, b"important data");

                StoreLogData::default()
            },
        );
    }

    // =========================================================================
    // Lease-to-lease retention update
    // =========================================================================

    #[test]
    fn set_retention_lease_to_lease_updates_expiry() {
        run_store_test(
            "retention_lease_update_expiry",
            "verify",
            "retention",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let mut obj = test_stored_object(1, b"data");
                obj.storage.retention = RetentionClass::Lease { expires_at: 1000 };
                let id = obj.object_id;
                store.put(obj).await.unwrap();

                store
                    .set_retention(&id, RetentionClass::Lease { expires_at: 5000 })
                    .await
                    .unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(
                    matches!(meta.retention, RetentionClass::Lease { expires_at } if expires_at == 5000)
                );

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"transition": "lease_1000_to_lease_5000"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Quota freed after delete allows new put
    // =========================================================================

    #[test]
    fn quota_freed_after_delete_allows_new_put() {
        run_store_test(
            "quota_freed_after_delete",
            "verify",
            "accounting",
            2,
            || async {
                let config = MemoryObjectStoreConfig { max_bytes: 1000 };
                let store = MemoryObjectStore::new(config);

                let obj1 = test_stored_object(1, &vec![0_u8; 488]);
                let id1 = obj1.object_id;
                store.put(obj1).await.unwrap();

                // Quota full — can't add another
                let obj2 = test_stored_object(2, &vec![0_u8; 488]);
                assert!(store.put(obj2).await.is_err());

                // Delete first, now second can fit
                store.delete(&id1).await.unwrap();
                let obj2b = test_stored_object(2, &vec![0_u8; 488]);
                store.put(obj2b).await.unwrap();
                assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);

                StoreLogData {
                    details: Some(json!({"freed_and_reused": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Accumulation with mixed sizes
    // =========================================================================

    #[test]
    fn storage_used_accumulates_mixed_sizes() {
        run_store_test(
            "storage_accumulates_mixed",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                store.put(test_stored_object(1, b"aaaa")).await.unwrap(); // 4 + 512
                store.put(test_stored_object(2, b"bb")).await.unwrap(); // 2 + 512

                let used = store.storage_used().await;
                assert_eq!(used, (4 + 512) + (2 + 512));

                StoreLogData {
                    details: Some(json!({"total_used": used})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Storage meta with initial pinned retention
    // =========================================================================

    #[test]
    fn get_storage_meta_returns_initial_pinned_retention() {
        run_store_test(
            "get_storage_meta_initial_pinned",
            "verify",
            "read",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let mut obj = test_stored_object(1, b"data");
                obj.storage.retention = RetentionClass::Pinned;
                let id = obj.object_id;
                store.put(obj).await.unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(meta.retention, RetentionClass::Pinned));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"retention": "pinned"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Header with refs
    // =========================================================================

    #[test]
    fn get_header_preserves_refs() {
        run_store_test("get_header_preserves_refs", "verify", "read", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            let ref_id = ObjectId::from_bytes([2; 32]);
            let mut obj = test_stored_object(1, b"data");
            obj.header.refs = vec![ref_id];
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let header = store.get_header(&id).await.unwrap();
            assert_eq!(header.refs.len(), 1);
            assert_eq!(header.refs[0], ref_id);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"refs_count": 1})),
                ..StoreLogData::default()
            }
        });
    }

    // =========================================================================
    // Quota matches config
    // =========================================================================

    #[test]
    fn storage_quota_matches_custom_config() {
        run_store_test(
            "storage_quota_matches_custom",
            "verify",
            "accounting",
            1,
            || async {
                let config = MemoryObjectStoreConfig { max_bytes: 12345 };
                let store = MemoryObjectStore::new(config);
                assert_eq!(store.storage_quota().await, 12345);

                StoreLogData {
                    details: Some(json!({"quota": 12345})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Delete all returns zero storage
    // =========================================================================

    #[test]
    fn storage_zero_after_deleting_all_objects() {
        run_store_test(
            "storage_zero_after_delete_all",
            "verify",
            "accounting",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                store.put(test_stored_object(1, b"aaa")).await.unwrap();
                store.put(test_stored_object(2, b"bbb")).await.unwrap();

                store
                    .delete(&ObjectId::from_bytes([1; 32]))
                    .await
                    .unwrap();
                store
                    .delete(&ObjectId::from_bytes([2; 32]))
                    .await
                    .unwrap();

                assert_eq!(store.storage_used().await, 0);

                StoreLogData {
                    details: Some(json!({"all_deleted": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }
}
