//! Quarantine store for untrusted/unreferenced objects (NORMATIVE).
//!
//! Implements the object admission pipeline from `FCP_Specification_V2.md` §8.4.1.

use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;
use fcp_core::{ObjectId, ZoneId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::QuarantineError;

/// Object admission classification (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectAdmissionClass {
    /// Unknown provenance, bounded retention, not gossiped.
    Quarantined,
    /// Verified reachable, normal retention, gossiped.
    Admitted,
}

/// Reason for promoting an object from quarantine (NORMATIVE).
///
/// Per FCP Specification §8.4.1, promotion from quarantine is allowed only if
/// one of these conditions is met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionReason {
    /// Object became reachable from the zone's pinned `ZoneCheckpoint`.
    ReachableFromCheckpoint {
        /// The checkpoint object ID that makes this object reachable.
        checkpoint_id: ObjectId,
    },
    /// Object was explicitly requested by an authenticated peer.
    AuthenticatedPeerRequest {
        /// The peer that requested the object.
        peer_id: u64,
        /// Request signature or token (opaque bytes for validation).
        request_token: Vec<u8>,
    },
    /// Object was explicitly pinned by local user action or policy.
    LocalPin {
        /// Reason for the pin (audit trail).
        reason: String,
    },
}

/// Object admission policy (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAdmissionPolicy {
    /// Maximum quarantine storage per zone (default: 256MB).
    pub max_quarantine_bytes_per_zone: u64,
    /// Maximum quarantined objects per zone (default: 100,000).
    pub max_quarantine_objects_per_zone: u32,
    /// TTL for quarantined objects before eviction (default: 3600s).
    pub quarantine_ttl_secs: u64,
    /// Whether to require schema validation on promotion (default: true).
    pub require_schema_validation: bool,
}

impl Default for ObjectAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_quarantine_bytes_per_zone: 256 * 1024 * 1024, // 256MB
            max_quarantine_objects_per_zone: 100_000,
            quarantine_ttl_secs: 3600,
            require_schema_validation: true,
        }
    }
}

/// Quarantined object entry.
#[derive(Debug, Clone)]
pub struct QuarantinedObject {
    /// Object ID.
    pub object_id: ObjectId,
    /// Zone this object belongs to.
    pub zone_id: ZoneId,
    /// Raw object data (symbols or reconstructed body).
    pub data: Bytes,
    /// Peer that sent this object.
    pub source_peer: Option<u64>,
    /// Timestamp when received.
    pub received_at: u64,
    /// Peer reputation score at time of receipt (lower = worse).
    pub peer_reputation: i32,
}

/// Entry for eviction priority queue.
#[derive(Debug, Clone, Eq, PartialEq)]
struct EvictionEntry {
    object_id: ObjectId,
    received_at: u64,
    peer_reputation: i32,
    size: u64,
}

impl Ord for EvictionEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Priority order: oldest first, then lowest reputation, then largest
        // We order such that the "worst" items (to be evicted) are smallest (Min),
        // so we can efficiently pop_first() from BTreeSet.

        // Oldest (smallest timestamp) is min -> evict first
        self.received_at
            .cmp(&other.received_at)
            // Lowest reputation (smallest value) is min -> evict first
            .then_with(|| self.peer_reputation.cmp(&other.peer_reputation))
            // Largest size is min -> evict first (so we reverse compare)
            .then_with(|| other.size.cmp(&self.size))
            // Tie-breaker to ensure unique entries in Set
            .then_with(|| self.object_id.as_bytes().cmp(other.object_id.as_bytes()))
    }
}

impl PartialOrd for EvictionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-zone quarantine state.
#[derive(Debug)]
struct ZoneQuarantine {
    objects: HashMap<ObjectId, QuarantinedObject>,
    used_bytes: u64,
    eviction_queue: BTreeSet<EvictionEntry>,
}

impl ZoneQuarantine {
    fn new() -> Self {
        Self {
            objects: HashMap::new(),
            used_bytes: 0,
            eviction_queue: BTreeSet::new(),
        }
    }
}

/// Quarantine store for untrusted objects (NORMATIVE).
///
/// Implements bounded admission with per-zone quotas and TTL eviction.
pub struct QuarantineStore {
    zones: RwLock<HashMap<ZoneId, ZoneQuarantine>>,
    policy: ObjectAdmissionPolicy,
}

impl QuarantineStore {
    /// Create a new quarantine store with the given policy.
    #[must_use]
    pub fn new(policy: ObjectAdmissionPolicy) -> Self {
        Self {
            zones: RwLock::new(HashMap::new()),
            policy,
        }
    }

    /// Add an object to quarantine.
    ///
    /// If quotas are exceeded, evicts objects according to policy.
    ///
    /// # Errors
    /// Returns error if the object cannot be quarantined even after eviction.
    pub fn quarantine(&self, obj: QuarantinedObject) -> Result<(), QuarantineError> {
        #[allow(clippy::cast_possible_truncation)]
        let obj_size = obj.data.len() as u64;

        let mut zones = self.zones.write();
        let zone = zones
            .entry(obj.zone_id.clone())
            .or_insert_with(ZoneQuarantine::new);

        // Check if already quarantined
        if zone.objects.contains_key(&obj.object_id) {
            return Ok(()); // Already in quarantine
        }

        // Evict if necessary to make room
        while zone.objects.len() as u32 >= self.policy.max_quarantine_objects_per_zone
            || zone.used_bytes + obj_size > self.policy.max_quarantine_bytes_per_zone
        {
            if let Some(entry) = zone.eviction_queue.pop_first() {
                if let Some(evicted) = zone.objects.remove(&entry.object_id) {
                    #[allow(clippy::cast_possible_truncation)]
                    let evicted_size = evicted.data.len() as u64;
                    zone.used_bytes = zone.used_bytes.saturating_sub(evicted_size);
                    tracing::debug!(
                        object_id = %entry.object_id,
                        "Evicted quarantined object"
                    );
                }
            } else {
                // No more objects to evict
                return Err(QuarantineError::QuotaExceeded {
                    used: zone.used_bytes,
                    max: self.policy.max_quarantine_bytes_per_zone,
                });
            }
        }

        // Add eviction entry
        zone.eviction_queue.insert(EvictionEntry {
            object_id: obj.object_id,
            received_at: obj.received_at,
            peer_reputation: obj.peer_reputation,
            size: obj_size,
        });

        zone.used_bytes += obj_size;
        zone.objects.insert(obj.object_id, obj);

        Ok(())
    }

    /// Get a quarantined object.
    pub fn get(&self, object_id: &ObjectId) -> Option<QuarantinedObject> {
        let zones = self.zones.read();
        for zone in zones.values() {
            if let Some(obj) = zone.objects.get(object_id) {
                return Some(obj.clone());
            }
        }
        None
    }

    /// Remove an object from quarantine (internal, no validation).
    ///
    /// # Errors
    /// Returns `NotFound` if object is not in quarantine.
    pub fn remove(&self, object_id: &ObjectId) -> Result<QuarantinedObject, QuarantineError> {
        let mut zones = self.zones.write();
        for zone in zones.values_mut() {
            if let Some(obj) = zone.objects.remove(object_id) {
                #[allow(clippy::cast_possible_truncation)]
                let obj_size = obj.data.len() as u64;

                // Construct entry to remove from set
                let entry = EvictionEntry {
                    object_id: *object_id,
                    received_at: obj.received_at,
                    peer_reputation: obj.peer_reputation,
                    size: obj_size,
                };
                zone.eviction_queue.remove(&entry);

                zone.used_bytes = zone.used_bytes.saturating_sub(obj_size);
                return Ok(obj);
            }
        }
        Err(QuarantineError::NotFound(*object_id))
    }

    /// Promote an object from quarantine to admitted status (NORMATIVE).
    ///
    /// Per FCP Specification §8.4.1, promotion requires:
    /// 1. A valid promotion reason (checkpoint reachability, peer request, or local pin)
    /// 2. Successful reconstruction (caller must verify object can be reconstructed)
    /// 3. Schema validation (if policy requires it)
    ///
    /// # Arguments
    /// * `object_id` - The object to promote
    /// * `reason` - The reason for promotion (must be valid)
    /// * `schema_valid` - Whether schema validation passed (caller must verify)
    ///
    /// # Errors
    /// Returns `PromotionDenied` if promotion rules are not satisfied.
    /// Returns `SchemaValidationFailed` if schema validation is required but failed.
    /// Returns `NotFound` if object is not in quarantine.
    pub fn promote(
        &self,
        object_id: &ObjectId,
        reason: &PromotionReason,
        schema_valid: bool,
    ) -> Result<QuarantinedObject, QuarantineError> {
        // Validate promotion reason
        self.validate_promotion_reason(object_id, reason)?;

        // Check schema validation if required
        if self.policy.require_schema_validation && !schema_valid {
            return Err(QuarantineError::SchemaValidationFailed {
                reason: "Schema validation is required but object failed validation".into(),
            });
        }

        // Remove from quarantine (promotion successful)
        self.remove(object_id)
    }

    /// Validate that a promotion reason is acceptable (NORMATIVE).
    ///
    /// This method enforces the promotion rules from FCP Specification §8.4.1.
    /// Takes `&self` for future extensibility (e.g., checking object presence).
    #[allow(clippy::unused_self)]
    fn validate_promotion_reason(
        &self,
        object_id: &ObjectId,
        reason: &PromotionReason,
    ) -> Result<(), QuarantineError> {
        match reason {
            PromotionReason::ReachableFromCheckpoint { checkpoint_id } => {
                // Caller must have verified reachability from checkpoint
                // We just validate the checkpoint_id is not the same as the object
                // (can't reach yourself from yourself)
                if checkpoint_id == object_id {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Object cannot be reachable from itself".into(),
                    });
                }
                Ok(())
            }
            PromotionReason::AuthenticatedPeerRequest {
                peer_id,
                request_token,
            } => {
                // Validate peer request has non-empty token
                if request_token.is_empty() {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Authenticated peer request requires a valid request token".into(),
                    });
                }
                // Validate peer_id is non-zero (0 typically means unknown/invalid)
                if *peer_id == 0 {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Invalid peer ID".into(),
                    });
                }
                Ok(())
            }
            PromotionReason::LocalPin { reason: pin_reason } => {
                // Local pin must have a non-empty reason for audit trail
                if pin_reason.is_empty() {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Local pin requires a reason for audit trail".into(),
                    });
                }
                Ok(())
            }
        }
    }

    /// Check if an object is in quarantine.
    #[must_use]
    pub fn contains(&self, object_id: &ObjectId) -> bool {
        let zones = self.zones.read();
        zones.values().any(|z| z.objects.contains_key(object_id))
    }

    /// Evict objects older than TTL.
    ///
    /// Returns the number of objects evicted.
    pub fn evict_expired(&self, current_time: u64) -> usize {
        let ttl = self.policy.quarantine_ttl_secs;
        let mut evicted = 0;

        let mut zones = self.zones.write();
        for zone in zones.values_mut() {
            let expired: Vec<ObjectId> = zone
                .objects
                .iter()
                .filter(|(_, obj)| current_time.saturating_sub(obj.received_at) > ttl)
                .map(|(id, _)| *id)
                .collect();

            for id in expired {
                if let Some(obj) = zone.objects.remove(&id) {
                    #[allow(clippy::cast_possible_truncation)]
                    let obj_size = obj.data.len() as u64;

                    let entry = EvictionEntry {
                        object_id: id,
                        received_at: obj.received_at,
                        peer_reputation: obj.peer_reputation,
                        size: obj_size,
                    };
                    zone.eviction_queue.remove(&entry);

                    zone.used_bytes = zone.used_bytes.saturating_sub(obj_size);
                    evicted += 1;
                }
            }
        }

        evicted
    }

    /// Get quarantine statistics for a zone.
    #[must_use]
    pub fn zone_stats(&self, zone_id: &ZoneId) -> QuarantineStats {
        let zones = self.zones.read();
        if let Some(zone) = zones.get(zone_id) {
            QuarantineStats {
                object_count: zone.objects.len() as u32,
                used_bytes: zone.used_bytes,
                max_bytes: self.policy.max_quarantine_bytes_per_zone,
                max_objects: self.policy.max_quarantine_objects_per_zone,
            }
        } else {
            QuarantineStats {
                object_count: 0,
                used_bytes: 0,
                max_bytes: self.policy.max_quarantine_bytes_per_zone,
                max_objects: self.policy.max_quarantine_objects_per_zone,
            }
        }
    }

    /// List all quarantined objects in a zone.
    pub fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        let zones = self.zones.read();
        zones
            .get(zone_id)
            .map(|z| z.objects.keys().copied().collect())
            .unwrap_or_default()
    }
}

/// Quarantine statistics for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineStats {
    /// Number of quarantined objects.
    pub object_count: u32,
    /// Bytes used by quarantined objects.
    pub used_bytes: u64,
    /// Maximum bytes allowed.
    pub max_bytes: u64,
    /// Maximum objects allowed.
    pub max_objects: u32,
}

impl QuarantineStats {
    /// Check if quarantine is near capacity.
    #[must_use]
    pub fn is_near_capacity(&self, threshold_pct: u8) -> bool {
        let threshold = u64::from(threshold_pct);
        let bytes_pct = self.used_bytes * 100 / self.max_bytes.max(1);
        let objects_pct = u64::from(self.object_count) * 100 / u64::from(self.max_objects.max(1));
        bytes_pct >= threshold || objects_pct >= threshold
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use chrono::Utc;
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

    fn run_store_test<F>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
    where
        F: FnOnce() -> StoreLogData + panic::UnwindSafe,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(f));
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

    fn test_object(id: u8, size: usize, received_at: u64) -> QuarantinedObject {
        QuarantinedObject {
            object_id: ObjectId::from_bytes([id; 32]),
            zone_id: test_zone(),
            data: Bytes::from(vec![0_u8; size]),
            source_peer: Some(1),
            received_at,
            peer_reputation: 50,
        }
    }

    #[test]
    fn quarantine_and_get() {
        run_store_test("quarantine_and_get", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 100, 1000);

            store.quarantine(obj.clone()).unwrap();

            let retrieved = store.get(&obj.object_id).unwrap();
            assert_eq!(retrieved.object_id, obj.object_id);

            StoreLogData {
                object_id: Some(obj.object_id),
                object_size: Some(obj.data.len() as u64),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantine_duplicate_ignored() {
        run_store_test(
            "quarantine_duplicate_ignored",
            "verify",
            "quarantine",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);

                store.quarantine(obj.clone()).unwrap();
                store.quarantine(obj).unwrap();

                let stats = store.zone_stats(&test_zone());
                assert_eq!(stats.object_count, 1);

                StoreLogData {
                    details: Some(json!({"object_count": stats.object_count})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn remove_from_quarantine() {
        run_store_test("remove_from_quarantine", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 100, 1000);
            let id = obj.object_id;

            store.quarantine(obj).unwrap();
            assert!(store.contains(&id));

            store.remove(&id).unwrap();
            assert!(!store.contains(&id));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"removed": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_oldest_on_object_quota() {
        run_store_test(
            "evict_oldest_on_object_quota",
            "verify",
            "quarantine",
            3,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 3,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                store.quarantine(test_object(1, 100, 1000)).unwrap();
                store.quarantine(test_object(2, 100, 2000)).unwrap();
                store.quarantine(test_object(3, 100, 3000)).unwrap();

                store.quarantine(test_object(4, 100, 4000)).unwrap();

                let stats = store.zone_stats(&test_zone());
                assert_eq!(stats.object_count, 3);
                assert!(!store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(store.contains(&ObjectId::from_bytes([4; 32])));

                StoreLogData {
                    details: Some(json!({"object_count": stats.object_count, "evicted": "oldest"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn evict_on_byte_quota() {
        run_store_test("evict_on_byte_quota", "verify", "quarantine", 1, || {
            let policy = ObjectAdmissionPolicy {
                max_quarantine_objects_per_zone: 100,
                max_quarantine_bytes_per_zone: 300,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 2000)).unwrap();
            store.quarantine(test_object(3, 100, 3000)).unwrap();

            store.quarantine(test_object(4, 100, 4000)).unwrap();

            assert!(!store.contains(&ObjectId::from_bytes([1; 32])));

            StoreLogData {
                details: Some(json!({"evicted": "byte_quota"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_expired() {
        run_store_test("evict_expired", "verify", "quarantine", 2, || {
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 100,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 1050)).unwrap();
            store.quarantine(test_object(3, 100, 1150)).unwrap();

            let evicted = store.evict_expired(1200);
            assert_eq!(evicted, 2);

            let stats = store.zone_stats(&test_zone());
            assert_eq!(stats.object_count, 1);
            assert!(store.contains(&ObjectId::from_bytes([3; 32])));

            StoreLogData {
                details: Some(json!({"evicted": evicted, "remaining": stats.object_count})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn zone_stats() {
        run_store_test("zone_stats", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 200, 2000)).unwrap();

            let stats = store.zone_stats(&test_zone());
            assert_eq!(stats.object_count, 2);
            assert_eq!(stats.used_bytes, 300);

            StoreLogData {
                details: Some(json!({
                    "object_count": stats.object_count,
                    "used_bytes": stats.used_bytes
                })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn is_near_capacity() {
        run_store_test("is_near_capacity", "verify", "quarantine", 2, || {
            let stats = QuarantineStats {
                object_count: 85,
                used_bytes: 200,
                max_bytes: 1000,
                max_objects: 100,
            };

            assert!(stats.is_near_capacity(80));
            assert!(!stats.is_near_capacity(90));

            StoreLogData {
                details: Some(json!({"object_pct": 85, "bytes_pct": 20})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone() {
        run_store_test("quarantine_list_zone", "verify", "list", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 2000)).unwrap();

            let ids = store.list_zone(&test_zone());
            assert_eq!(ids.len(), 2);

            StoreLogData {
                details: Some(json!({"zone_id": test_zone().to_string(), "count": ids.len()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn eviction_priority_order() {
        run_store_test("eviction_priority_order", "verify", "quarantine", 3, || {
            let policy = ObjectAdmissionPolicy {
                max_quarantine_objects_per_zone: 2,
                max_quarantine_bytes_per_zone: 1024 * 1024,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            let mut obj1 = test_object(1, 100, 2000);
            obj1.peer_reputation = 50;

            let mut obj2 = test_object(2, 100, 1000);
            obj2.peer_reputation = 50;

            store.quarantine(obj1).unwrap();
            store.quarantine(obj2).unwrap();

            store.quarantine(test_object(3, 100, 3000)).unwrap();

            assert!(store.contains(&ObjectId::from_bytes([1; 32])));
            assert!(!store.contains(&ObjectId::from_bytes([2; 32])));
            assert!(store.contains(&ObjectId::from_bytes([3; 32])));

            StoreLogData {
                details: Some(json!({"evicted": "oldest"})),
                ..StoreLogData::default()
            }
        });
    }

    // =========================================================================
    // Promotion validation tests (NORMATIVE)
    // =========================================================================

    #[test]
    fn promote_with_checkpoint_reachability() {
        run_store_test(
            "promote_with_checkpoint_reachability",
            "verify",
            "promotion",
            2,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();
                assert!(store.contains(&id));

                let checkpoint_id = ObjectId::from_bytes([99; 32]);
                let reason = PromotionReason::ReachableFromCheckpoint { checkpoint_id };

                let promoted = store.promote(&id, &reason, true).unwrap();
                assert_eq!(promoted.object_id, id);
                assert!(!store.contains(&id));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"promotion_reason": "checkpoint_reachability"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_with_authenticated_peer_request() {
        run_store_test(
            "promote_with_authenticated_peer_request",
            "verify",
            "promotion",
            2,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 42,
                    request_token: vec![1, 2, 3, 4],
                };

                let promoted = store.promote(&id, &reason, true).unwrap();
                assert_eq!(promoted.object_id, id);
                assert!(!store.contains(&id));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"promotion_reason": "authenticated_peer"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_with_local_pin() {
        run_store_test("promote_with_local_pin", "verify", "promotion", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 100, 1000);
            let id = obj.object_id;

            store.quarantine(obj).unwrap();

            let reason = PromotionReason::LocalPin {
                reason: "User explicitly requested this object".into(),
            };

            let promoted = store.promote(&id, &reason, true).unwrap();
            assert_eq!(promoted.object_id, id);
            assert!(!store.contains(&id));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"promotion_reason": "local_pin"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn promote_denied_self_referential_checkpoint() {
        run_store_test(
            "promote_denied_self_referential_checkpoint",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                // Try to promote with self as checkpoint (invalid)
                let reason = PromotionReason::ReachableFromCheckpoint { checkpoint_id: id };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));
                assert!(store.contains(&id)); // Still in quarantine

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "self_referential"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_empty_request_token() {
        run_store_test(
            "promote_denied_empty_request_token",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 42,
                    request_token: vec![], // Empty token
                };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "empty_token"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_invalid_peer_id() {
        run_store_test(
            "promote_denied_invalid_peer_id",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 0, // Invalid peer ID
                    request_token: vec![1, 2, 3],
                };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "invalid_peer_id"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_empty_pin_reason() {
        run_store_test(
            "promote_denied_empty_pin_reason",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: String::new(), // Empty reason
                };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "empty_pin_reason"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_schema_validation_required() {
        run_store_test(
            "promote_denied_schema_validation_required",
            "verify",
            "promotion",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    require_schema_validation: true,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: "User request".into(),
                };

                // schema_valid = false should fail
                let result = store.promote(&id, &reason, false);
                assert!(matches!(
                    result,
                    Err(QuarantineError::SchemaValidationFailed { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "schema_validation_failed"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_succeeds_without_schema_validation_when_not_required() {
        run_store_test(
            "promote_succeeds_without_schema_validation",
            "verify",
            "promotion",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    require_schema_validation: false, // Not required
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: "User request".into(),
                };

                // schema_valid = false should succeed when not required
                let promoted = store.promote(&id, &reason, false).unwrap();
                assert_eq!(promoted.object_id, id);

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"schema_validation_required": false})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Adversarial tests (attack scenarios)
    // =========================================================================

    #[test]
    fn adversarial_rapid_quota_exhaustion_attempt() {
        run_store_test(
            "adversarial_rapid_quota_exhaustion",
            "adversarial",
            "quarantine",
            2,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 10,
                    max_quarantine_bytes_per_zone: 1000,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                // Attacker tries to flood quarantine with many objects
                for i in 0..100 {
                    let obj = test_object(i, 50, u64::from(i));
                    let _ = store.quarantine(obj);
                }

                // Quota should be enforced
                let stats = store.zone_stats(&test_zone());
                assert!(stats.object_count <= 10);
                assert!(stats.used_bytes <= 1000);

                StoreLogData {
                    details: Some(json!({
                        "attack": "rapid_quota_exhaustion",
                        "objects_after": stats.object_count,
                        "bytes_after": stats.used_bytes,
                        "quota_enforced": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_large_object_injection() {
        run_store_test(
            "adversarial_large_object_injection",
            "adversarial",
            "quarantine",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_bytes_per_zone: 500,
                    max_quarantine_objects_per_zone: 100,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                // Attacker tries to inject an object larger than quota
                let large_obj = QuarantinedObject {
                    object_id: ObjectId::from_bytes([1; 32]),
                    zone_id: test_zone(),
                    data: Bytes::from(vec![0_u8; 600]), // Larger than quota
                    source_peer: Some(1),
                    received_at: 1000,
                    peer_reputation: 50,
                };

                let result = store.quarantine(large_obj);
                // Should fail because no room can be made
                assert!(matches!(result, Err(QuarantineError::QuotaExceeded { .. })));

                StoreLogData {
                    details: Some(json!({
                        "attack": "large_object_injection",
                        "object_size": 600,
                        "quota": 500,
                        "rejected": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_promotion_without_valid_reason() {
        run_store_test(
            "adversarial_promotion_without_valid_reason",
            "adversarial",
            "promotion",
            3,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                // Attacker tries various invalid promotion attempts
                let invalid_reasons = vec![
                    PromotionReason::ReachableFromCheckpoint { checkpoint_id: id }, // Self-ref
                    PromotionReason::AuthenticatedPeerRequest {
                        peer_id: 0,
                        request_token: vec![1],
                    },
                    PromotionReason::AuthenticatedPeerRequest {
                        peer_id: 1,
                        request_token: vec![],
                    },
                    PromotionReason::LocalPin {
                        reason: String::new(),
                    },
                ];

                let mut all_denied = true;
                for reason in &invalid_reasons {
                    if store.promote(&id, reason, true).is_ok() {
                        all_denied = false;
                        break;
                    }
                }

                assert!(all_denied);
                assert!(store.contains(&id)); // Still in quarantine

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({
                        "attack": "invalid_promotion_attempts",
                        "attempts": invalid_reasons.len(),
                        "all_denied": all_denied
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_promotion_not_in_quarantine() {
        run_store_test(
            "adversarial_promotion_not_in_quarantine",
            "adversarial",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

                // Attacker tries to promote an object that was never quarantined
                let fake_id = ObjectId::from_bytes([99; 32]);
                let reason = PromotionReason::LocalPin {
                    reason: "Fake promotion".into(),
                };

                let result = store.promote(&fake_id, &reason, true);
                assert!(matches!(result, Err(QuarantineError::NotFound(_))));

                StoreLogData {
                    object_id: Some(fake_id),
                    details: Some(json!({
                        "attack": "promote_non_existent",
                        "rejected": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }
}
