//! Offline capability tracking for FCP mesh objects.
//!
//! Implements quantifiable offline access from `FCP_Specification_V3.md` §11.5
//! (Offline and Repair Behavior).
//!
//! # Overview
//!
//! - **`OfflineAccess`**: Per-object availability tracking (local symbols vs K threshold)
//! - **`OfflineCapability`**: Aggregate tracking across multiple objects
//! - **`AccessPatternTracker`**: Predictive pre-staging based on access frequency/recency
//!
//! # Design Principles
//!
//! 1. **Local-first availability**: Objects are accessible offline if local symbol
//!    count meets or exceeds the reconstruction threshold (K).
//!
//! 2. **Coverage uses basis points**: All metrics use fixed-point basis points (10000 = 100%)
//!    for interop stability across implementations.
//!
//! 3. **Predictive pre-staging**: Access patterns inform which objects to prioritize
//!    for local caching before going offline.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use fcp_core::ObjectId;
use serde::{Deserialize, Serialize};

/// Per-object offline availability tracking.
///
/// Tracks how many symbols are stored locally versus the reconstruction threshold (K).
/// An object is accessible offline if `local_symbols >= k`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineAccess {
    /// The object being tracked.
    pub object_id: ObjectId,
    /// Number of symbols stored locally on this device.
    pub local_symbols: u32,
    /// Reconstruction threshold (K) - minimum symbols needed.
    pub k: u32,
    /// Total symbols in the encoding (N, where N >= K).
    pub n: u32,
    /// Size of each symbol in bytes.
    pub symbol_size: u32,
}

impl OfflineAccess {
    /// Create a new offline access tracker for an object.
    #[must_use]
    pub const fn new(object_id: ObjectId, k: u32, n: u32, symbol_size: u32) -> Self {
        Self {
            object_id,
            local_symbols: 0,
            k,
            n,
            symbol_size,
        }
    }

    /// Check if the object can be accessed offline (have enough local symbols).
    #[must_use]
    pub const fn can_access(&self) -> bool {
        self.local_symbols >= self.k
    }

    /// Calculate local coverage in basis points (10000 = 100% = K symbols).
    ///
    /// Returns coverage relative to the reconstruction threshold K.
    /// Values > 10000 indicate overcoverage (more than K symbols locally).
    #[must_use]
    pub const fn coverage_bps(&self) -> u32 {
        if self.k == 0 {
            // Zero-symbol objects are trivially reconstructable (no data to
            // reconstruct), matching can_access() which returns true for k==0.
            return 10_000;
        }
        // coverage_bps = (local_symbols / k) * 10000
        let bps = self.local_symbols as u64 * 10000 / self.k as u64;

        // Prevent silent numeric truncation if overcoverage is extreme
        if bps > u32::MAX as u64 {
            u32::MAX
        } else {
            bps as u32
        }
    }

    /// Calculate coverage as a floating-point ratio.
    ///
    /// Convenience method for when exact basis point precision isn't needed.
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.k == 0 {
            // Consistent with coverage_bps() and can_access(): k==0 means
            // the object is trivially complete.
            return 1.0;
        }
        f64::from(self.local_symbols) / f64::from(self.k)
    }

    /// Calculate how many more symbols needed for offline access.
    #[must_use]
    pub const fn symbols_needed(&self) -> u32 {
        self.k.saturating_sub(self.local_symbols)
    }

    /// Calculate bytes needed for offline access.
    #[must_use]
    pub const fn bytes_needed(&self) -> u64 {
        self.symbols_needed() as u64 * self.symbol_size as u64
    }

    /// Add locally stored symbols.
    pub const fn add_symbols(&mut self, count: u32) {
        self.local_symbols = self.local_symbols.saturating_add(count);
    }

    /// Remove locally stored symbols.
    pub const fn remove_symbols(&mut self, count: u32) {
        self.local_symbols = self.local_symbols.saturating_sub(count);
    }

    /// Set the exact local symbol count.
    pub const fn set_local_symbols(&mut self, count: u32) {
        self.local_symbols = count;
    }
}

/// Offline access status for quick categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfflineStatus {
    /// Object is fully available offline (`local_symbols` >= K).
    Available,
    /// Object is partially cached but not yet accessible offline.
    Partial,
    /// No local symbols stored.
    NotCached,
}

impl OfflineAccess {
    /// Get the current offline status.
    #[must_use]
    pub const fn status(&self) -> OfflineStatus {
        if self.local_symbols >= self.k {
            OfflineStatus::Available
        } else if self.local_symbols > 0 {
            OfflineStatus::Partial
        } else {
            OfflineStatus::NotCached
        }
    }
}

/// Aggregate offline capability tracking across multiple objects.
///
/// Provides a view of which objects can be accessed offline and
/// overall device offline readiness.
#[derive(Debug, Clone, Default)]
pub struct OfflineCapability {
    /// Per-object offline access tracking.
    objects: HashMap<ObjectId, OfflineAccess>,
}

impl OfflineCapability {
    /// Create a new empty capability tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a new object or update existing tracking.
    pub fn track(&mut self, access: OfflineAccess) {
        self.objects.insert(access.object_id, access);
    }

    /// Get offline access info for a specific object.
    #[must_use]
    pub fn get(&self, object_id: &ObjectId) -> Option<&OfflineAccess> {
        self.objects.get(object_id)
    }

    /// Get mutable offline access info for a specific object.
    pub fn get_mut(&mut self, object_id: &ObjectId) -> Option<&mut OfflineAccess> {
        self.objects.get_mut(object_id)
    }

    /// Remove tracking for an object.
    pub fn remove(&mut self, object_id: &ObjectId) -> Option<OfflineAccess> {
        self.objects.remove(object_id)
    }

    /// Check if a specific object can be accessed offline.
    #[must_use]
    pub fn can_access(&self, object_id: &ObjectId) -> bool {
        self.objects
            .get(object_id)
            .is_some_and(OfflineAccess::can_access)
    }

    /// Get the total number of tracked objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Get the number of objects available offline.
    #[must_use]
    pub fn available_count(&self) -> usize {
        self.objects.values().filter(|a| a.can_access()).count()
    }

    /// Get the number of partially cached objects.
    #[must_use]
    pub fn partial_count(&self) -> usize {
        self.objects
            .values()
            .filter(|a| a.status() == OfflineStatus::Partial)
            .count()
    }

    /// Calculate overall offline readiness in basis points.
    ///
    /// Returns (`available_objects` / `total_objects`) * 10000.
    #[must_use]
    pub fn readiness_bps(&self) -> u32 {
        if self.objects.is_empty() {
            return 0;
        }
        let available = self.available_count() as u64;
        let total = self.object_count() as u64;
        (available * 10000 / total) as u32
    }

    /// Iterate over all tracked objects.
    pub fn iter(&self) -> impl Iterator<Item = (&ObjectId, &OfflineAccess)> {
        self.objects.iter()
    }

    /// Get objects that are available offline.
    pub fn available_objects(&self) -> impl Iterator<Item = &OfflineAccess> {
        self.objects.values().filter(|a| a.can_access())
    }

    /// Get objects that need more symbols for offline access.
    pub fn incomplete_objects(&self) -> impl Iterator<Item = &OfflineAccess> {
        self.objects.values().filter(|a| !a.can_access())
    }

    /// Calculate total bytes needed to make all tracked objects available offline.
    #[must_use]
    pub fn total_bytes_needed(&self) -> u64 {
        self.objects.values().map(OfflineAccess::bytes_needed).sum()
    }

    /// Get objects sorted by coverage (lowest first) for prioritizing downloads.
    #[must_use]
    pub fn objects_by_coverage(&self) -> Vec<&OfflineAccess> {
        let mut objects: Vec<_> = self.objects.values().collect();
        objects.sort_by_key(|a| a.coverage_bps());
        objects
    }
}

/// Access pattern entry for a single object.
#[derive(Debug, Clone)]
struct AccessEntry {
    /// Number of times accessed.
    access_count: u64,
    /// Last access time.
    last_access: Instant,
    /// Exponentially weighted moving average of access frequency.
    ewma_frequency: f64,
}

impl AccessEntry {
    const fn new(now: Instant) -> Self {
        Self {
            access_count: 1,
            last_access: now,
            ewma_frequency: 1.0,
        }
    }
}

/// Predictive pre-staging tracker based on access patterns.
///
/// Tracks object access frequency and recency to predict which objects
/// should be prioritized for local caching before going offline.
///
/// Uses exponentially weighted moving average (EWMA) for frequency tracking
/// to balance recent and historical access patterns.
#[derive(Debug)]
pub struct AccessPatternTracker {
    /// Per-object access patterns.
    patterns: HashMap<ObjectId, AccessEntry>,
    /// EWMA smoothing factor (0..1). Higher = more weight on recent accesses.
    alpha: f64,
    /// Time window for frequency calculation.
    window: Duration,
    /// Maximum entries to track (LRU eviction when exceeded).
    max_entries: usize,
}

impl Default for AccessPatternTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessPatternTracker {
    /// Create a new tracker with default settings.
    ///
    /// Default: alpha=0.3, window=1 hour, `max_entries`=10000.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            alpha: 0.3,
            window: Duration::from_secs(3600),
            max_entries: 10000,
        }
    }

    /// Create a tracker with custom settings.
    #[must_use]
    pub fn with_config(alpha: f64, window: Duration, max_entries: usize) -> Self {
        Self {
            patterns: HashMap::new(),
            alpha: alpha.clamp(0.0, 1.0),
            window,
            max_entries,
        }
    }

    /// Record an access to an object.
    pub fn record_access(&mut self, object_id: ObjectId) {
        let now = Instant::now();

        if let Some(entry) = self.patterns.get_mut(&object_id) {
            entry.access_count += 1;
            entry.last_access = now;
            // Update EWMA: new_ewma = alpha * new_value + (1 - alpha) * old_ewma
            entry.ewma_frequency = (1.0 - self.alpha).mul_add(entry.ewma_frequency, self.alpha);
        } else {
            // Evict oldest entry if at capacity
            if self.patterns.len() >= self.max_entries {
                self.evict_oldest();
            }
            self.patterns.insert(object_id, AccessEntry::new(now));
        }
    }

    /// Evict the oldest (least recently accessed) entry.
    fn evict_oldest(&mut self) {
        if let Some(oldest_id) = self
            .patterns
            .iter()
            .min_by_key(|(_, e)| e.last_access)
            .map(|(id, _)| *id)
        {
            self.patterns.remove(&oldest_id);
        }
    }

    /// Get the access count for an object.
    #[must_use]
    pub fn access_count(&self, object_id: &ObjectId) -> u64 {
        self.patterns.get(object_id).map_or(0, |e| e.access_count)
    }

    /// Calculate a priority score for pre-staging.
    ///
    /// Higher scores indicate objects that should be prioritized for local caching.
    /// Score combines frequency (EWMA) and recency.
    #[must_use]
    pub fn priority_score(&self, object_id: &ObjectId) -> f64 {
        let Some(entry) = self.patterns.get(object_id) else {
            return 0.0;
        };

        let now = Instant::now();
        let age = now.saturating_duration_since(entry.last_access);

        // Recency factor: exponential decay based on time since last access
        let recency = if age < self.window {
            1.0 - (age.as_secs_f64() / self.window.as_secs_f64())
        } else {
            0.0
        };

        // Combined score: frequency * recency
        entry.ewma_frequency * recency
    }

    /// Get objects sorted by priority score (highest first) for pre-staging.
    #[must_use]
    pub fn prioritized_objects(&self) -> Vec<(ObjectId, f64)> {
        let mut scored: Vec<_> = self
            .patterns
            .keys()
            .map(|id| (*id, self.priority_score(id)))
            .collect();
        // Sort by score descending, then by ObjectId for determinism when scores are equal
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        scored
    }

    /// Get top N objects by priority for pre-staging.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(ObjectId, f64)> {
        let mut prioritized = self.prioritized_objects();
        prioritized.truncate(n);
        prioritized
    }

    /// Get the number of tracked objects.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.patterns.len()
    }

    /// Clear all tracked patterns.
    pub fn clear(&mut self) {
        self.patterns.clear();
    }

    /// Decay all frequency scores (call periodically to age out stale patterns).
    pub fn decay_all(&mut self, factor: f64) {
        let factor = factor.clamp(0.0, 1.0);
        for entry in self.patterns.values_mut() {
            entry.ewma_frequency *= factor;
        }
    }
}

/// Summary statistics for offline capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineSummary {
    /// Total objects tracked.
    pub total_objects: usize,
    /// Objects available offline.
    pub available_objects: usize,
    /// Objects partially cached.
    pub partial_objects: usize,
    /// Objects not cached at all.
    pub not_cached_objects: usize,
    /// Overall readiness in basis points.
    pub readiness_bps: u32,
    /// Total bytes needed for full offline capability.
    pub bytes_needed: u64,
}

impl OfflineCapability {
    /// Generate a summary of current offline capability.
    #[must_use]
    pub fn summary(&self) -> OfflineSummary {
        let available = self.available_count();
        let partial = self.partial_count();
        let total = self.object_count();

        OfflineSummary {
            total_objects: total,
            available_objects: available,
            partial_objects: partial,
            not_cached_objects: total - available - partial,
            readiness_bps: self.readiness_bps(),
            bytes_needed: self.total_bytes_needed(),
        }
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
    struct OfflineLogData {
        object_id: Option<ObjectId>,
        local_symbols: Option<u32>,
        k: Option<u32>,
        coverage_bps: Option<u32>,
        details: Option<serde_json::Value>,
    }

    fn run_offline_test<F>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
    where
        F: FnOnce() -> OfflineLogData + panic::UnwindSafe,
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
            "module": "fcp-store::offline",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_us": duration_us,
            "object_id": data.and_then(|d| d.object_id).map(|id| id.to_string()),
            "local_symbols": data.and_then(|d| d.local_symbols),
            "k": data.and_then(|d| d.k),
            "coverage_bps": data.and_then(|d| d.coverage_bps),
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

    fn test_object_id() -> ObjectId {
        ObjectId::from_bytes([1_u8; 32])
    }

    fn test_object_id_2() -> ObjectId {
        ObjectId::from_bytes([2_u8; 32])
    }

    fn test_object_id_3() -> ObjectId {
        ObjectId::from_bytes([3_u8; 32])
    }

    // =====================================================================
    // OfflineAccess tests
    // =====================================================================

    #[test]
    fn offline_access_new() {
        run_offline_test("offline_access_new", "init", "create", 4, || {
            let object_id = test_object_id();
            let access = OfflineAccess::new(object_id, 10, 15, 1024);

            assert_eq!(access.object_id, object_id);
            assert_eq!(access.local_symbols, 0);
            assert_eq!(access.k, 10);
            assert_eq!(access.n, 15);

            OfflineLogData {
                object_id: Some(object_id),
                local_symbols: Some(access.local_symbols),
                k: Some(access.k),
                coverage_bps: Some(access.coverage_bps()),
                details: Some(json!({"n": access.n, "symbol_size": access.symbol_size})),
            }
        });
    }

    #[test]
    fn offline_access_can_access_false() {
        run_offline_test(
            "offline_access_can_access_false",
            "verify",
            "access",
            2,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(5);

                assert!(!access.can_access());
                assert_eq!(access.symbols_needed(), 5);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: Some(access.coverage_bps()),
                    details: Some(json!({"can_access": false, "symbols_needed": 5})),
                }
            },
        );
    }

    #[test]
    fn offline_access_can_access_true() {
        run_offline_test(
            "offline_access_can_access_true",
            "verify",
            "access",
            2,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(10);

                assert!(access.can_access());
                assert_eq!(access.symbols_needed(), 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: Some(access.coverage_bps()),
                    details: Some(json!({"can_access": true})),
                }
            },
        );
    }

    #[test]
    fn offline_access_overcoverage() {
        run_offline_test(
            "offline_access_overcoverage",
            "verify",
            "coverage",
            2,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(15);

                assert!(access.can_access());
                assert_eq!(access.coverage_bps(), 15000);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: Some(access.coverage_bps()),
                    details: Some(json!({"coverage": access.coverage()})),
                }
            },
        );
    }

    #[test]
    fn offline_access_coverage_calculation() {
        run_offline_test(
            "offline_access_coverage_calculation",
            "verify",
            "coverage",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(5);

                assert_eq!(access.coverage_bps(), 5000);
                assert!((access.coverage() - 0.5).abs() < f64::EPSILON);
                assert_eq!(access.bytes_needed(), 5 * 1024);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: Some(access.coverage_bps()),
                    details: Some(json!({"bytes_needed": access.bytes_needed()})),
                }
            },
        );
    }

    #[test]
    fn offline_access_add_remove_symbols() {
        run_offline_test(
            "offline_access_add_remove_symbols",
            "verify",
            "mutation",
            4,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);

                access.add_symbols(5);
                assert_eq!(access.local_symbols, 5);

                access.add_symbols(3);
                assert_eq!(access.local_symbols, 8);

                access.remove_symbols(2);
                assert_eq!(access.local_symbols, 6);

                // Test saturating subtraction
                access.remove_symbols(100);
                assert_eq!(access.local_symbols, 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: Some(access.coverage_bps()),
                    details: Some(json!({"final_symbols": 0})),
                }
            },
        );
    }

    #[test]
    fn offline_access_status() {
        run_offline_test("offline_access_status", "verify", "status", 3, || {
            let object_id = test_object_id();
            let mut access = OfflineAccess::new(object_id, 10, 15, 1024);

            assert_eq!(access.status(), OfflineStatus::NotCached);

            access.set_local_symbols(5);
            assert_eq!(access.status(), OfflineStatus::Partial);

            access.set_local_symbols(10);
            assert_eq!(access.status(), OfflineStatus::Available);

            OfflineLogData {
                object_id: Some(object_id),
                local_symbols: Some(access.local_symbols),
                k: Some(access.k),
                coverage_bps: Some(access.coverage_bps()),
                details: Some(json!({"status": "Available"})),
            }
        });
    }

    // =====================================================================
    // OfflineCapability tests
    // =====================================================================

    #[test]
    fn offline_capability_empty() {
        run_offline_test("offline_capability_empty", "init", "create", 3, || {
            let cap = OfflineCapability::new();

            assert_eq!(cap.object_count(), 0);
            assert_eq!(cap.available_count(), 0);
            assert_eq!(cap.readiness_bps(), 0);

            OfflineLogData {
                object_id: None,
                local_symbols: None,
                k: None,
                coverage_bps: None,
                details: Some(json!({"object_count": 0})),
            }
        });
    }

    #[test]
    fn offline_capability_track_objects() {
        run_offline_test(
            "offline_capability_track_objects",
            "verify",
            "track",
            4,
            || {
                let mut cap = OfflineCapability::new();

                let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access1.set_local_symbols(10); // Available
                cap.track(access1);

                let mut access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
                access2.set_local_symbols(5); // Partial
                cap.track(access2);

                let access3 = OfflineAccess::new(test_object_id_3(), 10, 15, 1024);
                // Not cached
                cap.track(access3);

                assert_eq!(cap.object_count(), 3);
                assert_eq!(cap.available_count(), 1);
                assert_eq!(cap.partial_count(), 1);
                assert_eq!(cap.readiness_bps(), 3333); // 1/3 ≈ 33.33%

                OfflineLogData {
                    object_id: None,
                    local_symbols: None,
                    k: None,
                    coverage_bps: Some(cap.readiness_bps()),
                    details: Some(json!({
                        "object_count": 3,
                        "available_count": 1,
                        "partial_count": 1
                    })),
                }
            },
        );
    }

    #[test]
    fn offline_capability_can_access() {
        run_offline_test(
            "offline_capability_can_access",
            "verify",
            "access",
            3,
            || {
                let mut cap = OfflineCapability::new();

                let mut access = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access.set_local_symbols(10);
                cap.track(access);

                let access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
                cap.track(access2);

                assert!(cap.can_access(&test_object_id()));
                assert!(!cap.can_access(&test_object_id_2()));
                assert!(!cap.can_access(&test_object_id_3())); // Not tracked

                OfflineLogData {
                    object_id: Some(test_object_id()),
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({"can_access_obj1": true, "can_access_obj2": false})),
                }
            },
        );
    }

    #[test]
    fn offline_capability_bytes_needed() {
        run_offline_test(
            "offline_capability_bytes_needed",
            "verify",
            "calculation",
            1,
            || {
                let mut cap = OfflineCapability::new();

                let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access1.set_local_symbols(5); // Needs 5 * 1024 = 5120 bytes
                cap.track(access1);

                let mut access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 512);
                access2.set_local_symbols(7); // Needs 3 * 512 = 1536 bytes
                cap.track(access2);

                assert_eq!(cap.total_bytes_needed(), 5120 + 1536);

                OfflineLogData {
                    object_id: None,
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({"total_bytes_needed": cap.total_bytes_needed()})),
                }
            },
        );
    }

    #[test]
    fn offline_capability_objects_by_coverage() {
        run_offline_test(
            "offline_capability_objects_by_coverage",
            "verify",
            "sort",
            3,
            || {
                let mut cap = OfflineCapability::new();

                let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access1.set_local_symbols(8); // 80%
                cap.track(access1);

                let mut access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
                access2.set_local_symbols(3); // 30%
                cap.track(access2);

                let mut access3 = OfflineAccess::new(test_object_id_3(), 10, 15, 1024);
                access3.set_local_symbols(5); // 50%
                cap.track(access3);

                let sorted = cap.objects_by_coverage();
                assert_eq!(sorted[0].coverage_bps(), 3000); // obj2
                assert_eq!(sorted[1].coverage_bps(), 5000); // obj3
                assert_eq!(sorted[2].coverage_bps(), 8000); // obj1

                OfflineLogData {
                    object_id: None,
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({
                        "sorted_coverages": [3000, 5000, 8000]
                    })),
                }
            },
        );
    }

    #[test]
    fn offline_capability_summary() {
        run_offline_test("offline_capability_summary", "verify", "summary", 6, || {
            let mut cap = OfflineCapability::new();

            let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
            access1.set_local_symbols(10);
            cap.track(access1);

            let mut access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
            access2.set_local_symbols(5);
            cap.track(access2);

            let access3 = OfflineAccess::new(test_object_id_3(), 10, 15, 1024);
            cap.track(access3);

            let summary = cap.summary();

            assert_eq!(summary.total_objects, 3);
            assert_eq!(summary.available_objects, 1);
            assert_eq!(summary.partial_objects, 1);
            assert_eq!(summary.not_cached_objects, 1);
            assert_eq!(summary.readiness_bps, 3333);
            assert_eq!(summary.bytes_needed, (5 + 10) * 1024);

            OfflineLogData {
                object_id: None,
                local_symbols: None,
                k: None,
                coverage_bps: Some(summary.readiness_bps),
                details: Some(json!({
                    "total": summary.total_objects,
                    "available": summary.available_objects,
                    "partial": summary.partial_objects,
                    "not_cached": summary.not_cached_objects,
                    "bytes_needed": summary.bytes_needed
                })),
            }
        });
    }

    // =====================================================================
    // AccessPatternTracker tests
    // =====================================================================

    #[test]
    fn access_pattern_tracker_new() {
        run_offline_test("access_pattern_tracker_new", "init", "create", 1, || {
            let tracker = AccessPatternTracker::new();

            assert_eq!(tracker.tracked_count(), 0);

            OfflineLogData {
                object_id: None,
                local_symbols: None,
                k: None,
                coverage_bps: None,
                details: Some(json!({"tracked_count": 0})),
            }
        });
    }

    #[test]
    fn access_pattern_tracker_record_access() {
        run_offline_test(
            "access_pattern_tracker_record_access",
            "verify",
            "record",
            2,
            || {
                let mut tracker = AccessPatternTracker::new();
                let object_id = test_object_id();

                tracker.record_access(object_id);
                assert_eq!(tracker.access_count(&object_id), 1);

                tracker.record_access(object_id);
                assert_eq!(tracker.access_count(&object_id), 2);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({"access_count": 2})),
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_priority_score() {
        run_offline_test(
            "access_pattern_tracker_priority_score",
            "verify",
            "priority",
            2,
            || {
                let mut tracker = AccessPatternTracker::new();
                let object_id = test_object_id();

                // No accesses = 0 score
                #[allow(clippy::float_cmp)] // exact zero is valid for no accesses
                {
                    assert_eq!(tracker.priority_score(&object_id), 0.0);
                }

                tracker.record_access(object_id);
                let score = tracker.priority_score(&object_id);
                assert!(score > 0.0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({"priority_score": score})),
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_prioritized_objects() {
        run_offline_test(
            "access_pattern_tracker_prioritized_objects",
            "verify",
            "sort",
            2,
            || {
                let mut tracker = AccessPatternTracker::new();

                // Access obj1 once
                tracker.record_access(test_object_id());

                // Access obj2 multiple times (higher frequency)
                for _ in 0..5 {
                    tracker.record_access(test_object_id_2());
                }

                let prioritized = tracker.prioritized_objects();

                // obj2 should have higher priority due to more accesses
                assert_eq!(prioritized.len(), 2);
                assert_eq!(prioritized[0].0, test_object_id_2());

                OfflineLogData {
                    object_id: None,
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({
                        "top_object": prioritized[0].0.to_string(),
                        "top_score": prioritized[0].1
                    })),
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_top_n() {
        run_offline_test("access_pattern_tracker_top_n", "verify", "top_n", 2, || {
            let mut tracker = AccessPatternTracker::new();

            tracker.record_access(test_object_id());
            tracker.record_access(test_object_id_2());
            tracker.record_access(test_object_id_2());
            tracker.record_access(test_object_id_3());
            tracker.record_access(test_object_id_3());
            tracker.record_access(test_object_id_3());

            let top_2 = tracker.top_n(2);

            assert_eq!(top_2.len(), 2);
            // When all accesses happen in rapid succession, EWMA converges to 1.0
            // and recency differences are minimal. The sort is stable by ObjectId.
            // Verify that top_2 contains the two most recently accessed objects
            // (obj2 and obj3, since obj1 was only accessed once at the start).
            let top_ids: Vec<_> = top_2.iter().map(|(id, _)| *id).collect();
            assert!(
                top_ids.contains(&test_object_id_2()) && top_ids.contains(&test_object_id_3()),
                "Expected top_2 to contain obj2 and obj3, got: {top_ids:?}"
            );

            OfflineLogData {
                object_id: None,
                local_symbols: None,
                k: None,
                coverage_bps: None,
                details: Some(json!({
                    "top_2": top_2.iter().map(|(id, s)| (id.to_string(), s)).collect::<Vec<_>>()
                })),
            }
        });
    }

    #[test]
    fn access_pattern_tracker_eviction() {
        run_offline_test(
            "access_pattern_tracker_eviction",
            "verify",
            "eviction",
            2,
            || {
                let mut tracker =
                    AccessPatternTracker::with_config(0.3, Duration::from_secs(3600), 2);

                tracker.record_access(test_object_id());
                tracker.record_access(test_object_id_2());
                assert_eq!(tracker.tracked_count(), 2);

                // Adding a third should evict the oldest
                tracker.record_access(test_object_id_3());
                assert_eq!(tracker.tracked_count(), 2);

                OfflineLogData {
                    object_id: None,
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({"tracked_count": 2, "max_entries": 2})),
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_decay() {
        run_offline_test("access_pattern_tracker_decay", "verify", "decay", 1, || {
            let mut tracker = AccessPatternTracker::new();

            for _ in 0..10 {
                tracker.record_access(test_object_id());
            }

            let score_before = tracker.priority_score(&test_object_id());
            tracker.decay_all(0.5);
            let score_after = tracker.priority_score(&test_object_id());

            // Score should decrease after decay
            assert!(score_after < score_before);

            OfflineLogData {
                object_id: Some(test_object_id()),
                local_symbols: None,
                k: None,
                coverage_bps: None,
                details: Some(json!({
                    "score_before": score_before,
                    "score_after": score_after
                })),
            }
        });
    }

    #[test]
    fn access_pattern_tracker_clear() {
        run_offline_test("access_pattern_tracker_clear", "verify", "clear", 2, || {
            let mut tracker = AccessPatternTracker::new();

            tracker.record_access(test_object_id());
            tracker.record_access(test_object_id_2());
            assert_eq!(tracker.tracked_count(), 2);

            tracker.clear();
            assert_eq!(tracker.tracked_count(), 0);

            OfflineLogData {
                object_id: None,
                local_symbols: None,
                k: None,
                coverage_bps: None,
                details: Some(json!({"cleared": true})),
            }
        });
    }

    // =====================================================================
    // Edge case tests (per f3xi requirements)
    // =====================================================================

    #[test]
    fn offline_access_k_zero_edge_case() {
        run_offline_test(
            "offline_access_k_zero_edge_case",
            "verify",
            "edge_case",
            4,
            || {
                let object_id = test_object_id();
                // k=0 is an edge case - zero-symbol objects are already complete.
                let access = OfflineAccess::new(object_id, 0, 0, 1024);

                // With k=0, can_access should be true (0 >= 0)
                assert!(access.can_access());
                // Coverage should report 100% for a trivially complete object.
                assert_eq!(access.coverage_bps(), 10_000);
                #[allow(clippy::float_cmp)] // exact one is valid for k=0 edge case
                {
                    assert_eq!(access.coverage(), 1.0);
                }
                // No symbols needed
                assert_eq!(access.symbols_needed(), 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: Some(access.coverage_bps()),
                    details: Some(json!({"edge_case": "k=0"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_overflow_protection() {
        run_offline_test(
            "offline_access_overflow_protection",
            "verify",
            "edge_case",
            2,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);

                // Test saturating add
                access.set_local_symbols(u32::MAX - 5);
                access.add_symbols(100);
                assert_eq!(access.local_symbols, u32::MAX);

                // Test saturating sub from max
                access.remove_symbols(10);
                assert_eq!(access.local_symbols, u32::MAX - 10);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(access.local_symbols),
                    k: Some(access.k),
                    coverage_bps: None,
                    details: Some(json!({"edge_case": "overflow_protection"})),
                }
            },
        );
    }

    #[test]
    fn offline_capability_remove_object() {
        run_offline_test(
            "offline_capability_remove_object",
            "verify",
            "remove",
            5,
            || {
                let mut cap = OfflineCapability::new();

                let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access1.set_local_symbols(10); // Available
                cap.track(access1);

                let mut access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
                access2.set_local_symbols(10); // Available
                cap.track(access2);

                assert_eq!(cap.object_count(), 2);
                assert_eq!(cap.available_count(), 2);

                // Remove one object
                let removed = cap.remove(&test_object_id());
                assert!(removed.is_some());
                assert_eq!(cap.object_count(), 1);
                assert_eq!(cap.available_count(), 1);

                // Remove non-existent object
                let removed_none = cap.remove(&test_object_id_3());
                assert!(removed_none.is_none());

                OfflineLogData {
                    object_id: Some(test_object_id()),
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({
                        "removed": true,
                        "remaining_objects": cap.object_count()
                    })),
                }
            },
        );
    }

    #[test]
    fn offline_capability_get_mut() {
        run_offline_test(
            "offline_capability_get_mut",
            "verify",
            "mutation",
            3,
            || {
                let mut cap = OfflineCapability::new();

                let access = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                cap.track(access);

                assert!(!cap.can_access(&test_object_id()));

                // Mutate through get_mut
                if let Some(access) = cap.get_mut(&test_object_id()) {
                    access.set_local_symbols(10);
                }

                assert!(cap.can_access(&test_object_id()));
                assert_eq!(cap.available_count(), 1);

                OfflineLogData {
                    object_id: Some(test_object_id()),
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({"mutated": true})),
                }
            },
        );
    }

    #[test]
    fn offline_capability_incomplete_objects_iter() {
        run_offline_test(
            "offline_capability_incomplete_objects_iter",
            "verify",
            "iteration",
            2,
            || {
                let mut cap = OfflineCapability::new();

                let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access1.set_local_symbols(10); // Complete
                cap.track(access1);

                let mut access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
                access2.set_local_symbols(5); // Incomplete
                cap.track(access2);

                let access3 = OfflineAccess::new(test_object_id_3(), 10, 15, 1024);
                // Incomplete (0 symbols)
                cap.track(access3);

                assert_eq!(cap.incomplete_objects().count(), 2);
                assert_eq!(cap.available_objects().count(), 1);

                OfflineLogData {
                    object_id: None,
                    local_symbols: None,
                    k: None,
                    coverage_bps: None,
                    details: Some(json!({
                        "incomplete_count": 2,
                        "available_count": 1
                    })),
                }
            },
        );
    }

    // --- Additional edge case and serde tests ---

    #[test]
    fn offline_access_serde_roundtrip() {
        run_offline_test("offline_access_serde", "verify", "serde", 1, || {
            let object_id = test_object_id();
            let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
            access.set_local_symbols(7);

            let json = serde_json::to_string(&access).unwrap();
            let deserialized: OfflineAccess = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.local_symbols, 7);
            assert_eq!(deserialized.k, 10);
            assert_eq!(deserialized.n, 15);
            assert_eq!(deserialized.symbol_size, 1024);

            OfflineLogData {
                object_id: Some(object_id),
                local_symbols: Some(7),
                k: Some(10),
                coverage_bps: Some(access.coverage_bps()),
                details: Some(json!({"serde": "roundtrip_ok"})),
            }
        });
    }

    #[test]
    fn offline_status_serde_roundtrip() {
        run_offline_test("offline_status_serde", "verify", "serde", 3, || {
            for &status in &[
                OfflineStatus::Available,
                OfflineStatus::Partial,
                OfflineStatus::NotCached,
            ] {
                let json = serde_json::to_string(&status).unwrap();
                let deserialized: OfflineStatus = serde_json::from_str(&json).unwrap();
                assert_eq!(status, deserialized);
            }

            OfflineLogData {
                details: Some(json!({"serde": "all_variants_ok"})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_capability_iter() {
        run_offline_test("offline_capability_iter", "verify", "iteration", 1, || {
            let mut cap = OfflineCapability::new();

            let access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
            let access2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
            cap.track(access1);
            cap.track(access2);

            assert_eq!(cap.iter().count(), 2);

            OfflineLogData {
                details: Some(json!({"iter_count": 2})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_access_clone() {
        run_offline_test("offline_access_clone", "verify", "traits", 1, || {
            let object_id = test_object_id();
            let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
            access.set_local_symbols(5);

            let cloned = access.clone();
            assert_eq!(cloned.local_symbols, 5);
            assert_eq!(cloned.k, 10);
            assert_eq!(cloned.object_id, object_id);

            OfflineLogData {
                object_id: Some(object_id),
                details: Some(json!({"clone": "ok"})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_capability_total_bytes_needed_all_available() {
        run_offline_test(
            "bytes_needed_all_available",
            "verify",
            "calculation",
            1,
            || {
                let mut cap = OfflineCapability::new();

                let mut access = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access.set_local_symbols(10);
                cap.track(access);

                assert_eq!(cap.total_bytes_needed(), 0);

                OfflineLogData {
                    details: Some(json!({"bytes_needed": 0})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_readiness_all_available() {
        run_offline_test(
            "readiness_all_available",
            "verify",
            "calculation",
            1,
            || {
                let mut cap = OfflineCapability::new();

                let mut access1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access1.set_local_symbols(10);
                cap.track(access1);

                let mut access2 = OfflineAccess::new(test_object_id_2(), 5, 10, 512);
                access2.set_local_symbols(5);
                cap.track(access2);

                assert_eq!(cap.readiness_bps(), 10000);

                OfflineLogData {
                    coverage_bps: Some(10000),
                    details: Some(json!({"readiness": "100%"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_with_config_alpha_clamped() {
        run_offline_test("tracker_alpha_clamped", "verify", "config", 1, || {
            // Alpha > 1.0 should be clamped to 1.0
            let tracker = AccessPatternTracker::with_config(2.0, Duration::from_secs(3600), 100);
            // Just verify construction succeeds without panic
            assert_eq!(tracker.tracked_count(), 0);

            OfflineLogData {
                details: Some(json!({"alpha_clamped": true})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn access_pattern_tracker_access_count_unknown_object() {
        run_offline_test("tracker_unknown_access", "verify", "read", 1, || {
            let tracker = AccessPatternTracker::new();
            let unknown = ObjectId::from_bytes([99; 32]);

            assert_eq!(tracker.access_count(&unknown), 0);

            OfflineLogData {
                details: Some(json!({"count": 0})),
                ..OfflineLogData::default()
            }
        });
    }

    // =====================================================================
    // Additional OfflineAccess tests
    // =====================================================================

    #[test]
    fn offline_access_serde_roundtrip_all_fields() {
        run_offline_test(
            "offline_access_serde_roundtrip_all_fields",
            "verify",
            "serde",
            5,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 20, 30, 4096);
                access.set_local_symbols(15);

                let json = serde_json::to_string(&access).unwrap();
                let deserialized: OfflineAccess = serde_json::from_str(&json).unwrap();

                assert_eq!(deserialized.object_id, object_id);
                assert_eq!(deserialized.local_symbols, 15);
                assert_eq!(deserialized.k, 20);
                assert_eq!(deserialized.n, 30);
                assert_eq!(deserialized.symbol_size, 4096);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(15),
                    k: Some(20),
                    coverage_bps: Some(deserialized.coverage_bps()),
                    details: Some(json!({"serde": "all_fields_preserved"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_clone_independence() {
        run_offline_test(
            "offline_access_clone_independence",
            "verify",
            "traits",
            4,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(5);

                // Verify original state before cloning
                assert_eq!(access.local_symbols, 5);
                let mut cloned = access.clone();

                // Mutating clone should not affect original
                cloned.add_symbols(5);
                assert_eq!(cloned.local_symbols, 10);
                assert!(cloned.can_access());
                // Original unchanged
                assert_eq!(access.local_symbols, 5);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(cloned.local_symbols),
                    k: Some(cloned.k),
                    details: Some(json!({"clone": "independent_mutation"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_access_k_zero_with_local_symbols() {
        run_offline_test(
            "offline_access_k_zero_with_local_symbols",
            "verify",
            "edge_case",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 0, 10, 512);
                access.set_local_symbols(5);

                // k=0 means can_access is always true (0 >= 0 threshold)
                assert!(access.can_access());
                // k=0 means the object is trivially complete regardless of
                // local symbol count.
                assert_eq!(access.coverage_bps(), 10_000);
                // symbols_needed saturates: k(0) - local(5) = 0
                assert_eq!(access.symbols_needed(), 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(5),
                    k: Some(0),
                    coverage_bps: Some(10_000),
                    details: Some(json!({"edge_case": "k=0_with_symbols"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_local_symbols_exceeds_n() {
        run_offline_test(
            "offline_access_local_symbols_exceeds_n",
            "verify",
            "edge_case",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 5, 10, 256);
                // Set local_symbols beyond n (unusual but structurally allowed)
                access.set_local_symbols(20);

                assert!(access.can_access());
                // coverage = 20/5 * 10000 = 40000 bps
                assert_eq!(access.coverage_bps(), 40000);
                assert_eq!(access.symbols_needed(), 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(20),
                    k: Some(5),
                    coverage_bps: Some(40000),
                    details: Some(json!({"edge_case": "local_exceeds_n"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_coverage_bps_boundary_exact_k() {
        run_offline_test(
            "offline_access_coverage_bps_boundary_exact_k",
            "verify",
            "coverage",
            2,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(10); // exactly k

                assert_eq!(access.coverage_bps(), 10000);
                assert!(access.can_access());

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(10),
                    k: Some(10),
                    coverage_bps: Some(10000),
                    details: Some(json!({"boundary": "exact_k"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_coverage_bps_one_below_k() {
        run_offline_test(
            "offline_access_coverage_bps_one_below_k",
            "verify",
            "coverage",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(9); // one below k

                assert_eq!(access.coverage_bps(), 9000);
                assert!(!access.can_access());
                assert_eq!(access.symbols_needed(), 1);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(9),
                    k: Some(10),
                    coverage_bps: Some(9000),
                    details: Some(json!({"boundary": "one_below_k"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_coverage_bps_one_above_k() {
        run_offline_test(
            "offline_access_coverage_bps_one_above_k",
            "verify",
            "coverage",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);
                access.set_local_symbols(11); // one above k

                assert_eq!(access.coverage_bps(), 11000);
                assert!(access.can_access());
                assert_eq!(access.symbols_needed(), 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(11),
                    k: Some(10),
                    coverage_bps: Some(11000),
                    details: Some(json!({"boundary": "one_above_k"})),
                }
            },
        );
    }

    #[test]
    fn offline_access_coverage_float_precision() {
        run_offline_test(
            "offline_access_coverage_float_precision",
            "verify",
            "coverage",
            2,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 3, 5, 128);
                access.set_local_symbols(1);

                // 1/3 ≈ 0.333... - test fractional coverage
                assert_eq!(access.coverage_bps(), 3333); // integer truncation of 3333.33
                assert!((access.coverage() - 1.0 / 3.0).abs() < 1e-10);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(1),
                    k: Some(3),
                    coverage_bps: Some(3333),
                    details: Some(json!({"coverage_float": access.coverage()})),
                }
            },
        );
    }

    #[test]
    fn offline_access_bytes_needed_zero_symbol_size() {
        run_offline_test(
            "offline_access_bytes_needed_zero_symbol_size",
            "verify",
            "calculation",
            2,
            || {
                let object_id = test_object_id();
                let access = OfflineAccess::new(object_id, 10, 15, 0);

                // With symbol_size=0, bytes_needed is always 0 even when symbols are needed
                assert_eq!(access.symbols_needed(), 10);
                assert_eq!(access.bytes_needed(), 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(0),
                    k: Some(10),
                    details: Some(json!({"edge_case": "zero_symbol_size"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_access_is_available_exact_k_match() {
        run_offline_test(
            "offline_access_is_available_exact_k_match",
            "verify",
            "access",
            4,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 7, 10, 512);

                // Below k: not available
                access.set_local_symbols(6);
                assert!(!access.can_access());
                assert_eq!(access.status(), OfflineStatus::Partial);

                // Exactly k: available
                access.set_local_symbols(7);
                assert!(access.can_access());
                assert_eq!(access.status(), OfflineStatus::Available);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(7),
                    k: Some(7),
                    coverage_bps: Some(10000),
                    details: Some(json!({"exact_k_match": true})),
                }
            },
        );
    }

    #[test]
    fn offline_access_status_with_k_equals_one() {
        run_offline_test(
            "offline_access_status_with_k_equals_one",
            "verify",
            "status",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 1, 5, 256);

                assert_eq!(access.status(), OfflineStatus::NotCached);

                access.set_local_symbols(1);
                assert_eq!(access.status(), OfflineStatus::Available);
                assert!(access.can_access());

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(1),
                    k: Some(1),
                    details: Some(json!({"k_equals_one": true})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_access_add_then_remove_roundtrip() {
        run_offline_test(
            "offline_access_add_then_remove_roundtrip",
            "verify",
            "mutation",
            3,
            || {
                let object_id = test_object_id();
                let mut access = OfflineAccess::new(object_id, 10, 15, 1024);

                access.add_symbols(10);
                assert!(access.can_access());

                access.remove_symbols(10);
                assert!(!access.can_access());
                assert_eq!(access.local_symbols, 0);

                OfflineLogData {
                    object_id: Some(object_id),
                    local_symbols: Some(0),
                    k: Some(10),
                    details: Some(json!({"roundtrip": "add_remove"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    // =====================================================================
    // Additional OfflineCapability tests
    // =====================================================================

    #[test]
    fn offline_capability_add_and_remove_multiple() {
        run_offline_test(
            "offline_capability_add_and_remove_multiple",
            "verify",
            "mutation",
            5,
            || {
                let mut cap = OfflineCapability::new();

                let mut a1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                a1.set_local_symbols(10);
                cap.track(a1);

                let mut a2 = OfflineAccess::new(test_object_id_2(), 10, 15, 1024);
                a2.set_local_symbols(10);
                cap.track(a2);

                let a3 = OfflineAccess::new(test_object_id_3(), 10, 15, 1024);
                cap.track(a3);

                assert_eq!(cap.object_count(), 3);
                assert_eq!(cap.available_count(), 2);

                cap.remove(&test_object_id());
                cap.remove(&test_object_id_2());

                assert_eq!(cap.object_count(), 1);
                assert_eq!(cap.available_count(), 0);
                assert!(!cap.can_access(&test_object_id()));

                OfflineLogData {
                    details: Some(json!({"remaining": 1, "available": 0})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_mixed_availability_summary() {
        run_offline_test(
            "offline_capability_mixed_availability_summary",
            "verify",
            "summary",
            6,
            || {
                let mut cap = OfflineCapability::new();

                // 2 available
                let mut a1 = OfflineAccess::new(test_object_id(), 5, 10, 256);
                a1.set_local_symbols(5);
                cap.track(a1);

                let mut a2 = OfflineAccess::new(test_object_id_2(), 3, 6, 128);
                a2.set_local_symbols(6);
                cap.track(a2);

                // 1 partial
                let id3 = ObjectId::from_bytes([4_u8; 32]);
                let mut a3 = OfflineAccess::new(id3, 10, 20, 512);
                a3.set_local_symbols(3);
                cap.track(a3);

                // 1 not cached
                let id4 = ObjectId::from_bytes([5_u8; 32]);
                let a4 = OfflineAccess::new(id4, 8, 12, 1024);
                cap.track(a4);

                let summary = cap.summary();
                assert_eq!(summary.total_objects, 4);
                assert_eq!(summary.available_objects, 2);
                assert_eq!(summary.partial_objects, 1);
                assert_eq!(summary.not_cached_objects, 1);
                // readiness = 2/4 * 10000 = 5000
                assert_eq!(summary.readiness_bps, 5000);
                // bytes needed: a3 needs (10-3)*512=3584, a4 needs 8*1024=8192
                assert_eq!(summary.bytes_needed, 3584 + 8192);

                OfflineLogData {
                    coverage_bps: Some(5000),
                    details: Some(json!({
                        "total": 4,
                        "available": 2,
                        "partial": 1,
                        "not_cached": 1,
                        "bytes_needed": summary.bytes_needed
                    })),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_empty_set_summary() {
        run_offline_test(
            "offline_capability_empty_set_summary",
            "verify",
            "summary",
            6,
            || {
                let cap = OfflineCapability::new();
                let summary = cap.summary();

                assert_eq!(summary.total_objects, 0);
                assert_eq!(summary.available_objects, 0);
                assert_eq!(summary.partial_objects, 0);
                assert_eq!(summary.not_cached_objects, 0);
                assert_eq!(summary.readiness_bps, 0);
                assert_eq!(summary.bytes_needed, 0);

                OfflineLogData {
                    details: Some(json!({"empty_summary": true})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_track_overwrites_existing() {
        run_offline_test(
            "offline_capability_track_overwrites_existing",
            "verify",
            "track",
            4,
            || {
                let mut cap = OfflineCapability::new();

                let a1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                cap.track(a1);
                assert_eq!(cap.get(&test_object_id()).unwrap().local_symbols, 0);

                // Track same object with different state - should overwrite
                let mut a1_updated = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                a1_updated.set_local_symbols(10);
                cap.track(a1_updated);

                assert_eq!(cap.object_count(), 1); // still one object
                assert_eq!(cap.get(&test_object_id()).unwrap().local_symbols, 10);
                assert!(cap.can_access(&test_object_id()));

                OfflineLogData {
                    object_id: Some(test_object_id()),
                    details: Some(json!({"overwrite": true})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_get_returns_none_for_untracked() {
        run_offline_test(
            "offline_capability_get_returns_none_for_untracked",
            "verify",
            "read",
            2,
            || {
                let mut cap = OfflineCapability::new();

                assert!(cap.get(&test_object_id()).is_none());
                assert!(cap.get_mut(&test_object_id()).is_none());

                OfflineLogData {
                    details: Some(json!({"get_none": true})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_objects_by_coverage_single() {
        run_offline_test(
            "offline_capability_objects_by_coverage_single",
            "verify",
            "sort",
            2,
            || {
                let mut cap = OfflineCapability::new();

                let mut access = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                access.set_local_symbols(7);
                cap.track(access);

                let sorted = cap.objects_by_coverage();
                assert_eq!(sorted.len(), 1);
                assert_eq!(sorted[0].coverage_bps(), 7000);

                OfflineLogData {
                    coverage_bps: Some(7000),
                    details: Some(json!({"single_coverage_sort": true})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_clone_behavior() {
        run_offline_test(
            "offline_capability_clone_behavior",
            "verify",
            "traits",
            3,
            || {
                let mut cap = OfflineCapability::new();

                let mut a1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                a1.set_local_symbols(10);
                cap.track(a1);

                let cloned = cap.clone();
                drop(cap);

                assert_eq!(cloned.object_count(), 1);
                assert!(cloned.can_access(&test_object_id()));
                assert_eq!(cloned.available_count(), 1);

                OfflineLogData {
                    details: Some(json!({"clone": "offline_capability_ok"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_capability_default_is_empty() {
        run_offline_test(
            "offline_capability_default_is_empty",
            "init",
            "create",
            2,
            || {
                let cap = OfflineCapability::default();
                assert_eq!(cap.object_count(), 0);
                assert_eq!(cap.readiness_bps(), 0);

                OfflineLogData {
                    details: Some(json!({"default": "empty"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    // =====================================================================
    // Additional OfflineSummary tests
    // =====================================================================

    #[test]
    fn offline_summary_serde_roundtrip() {
        run_offline_test(
            "offline_summary_serde_roundtrip",
            "verify",
            "serde",
            6,
            || {
                let mut cap = OfflineCapability::new();

                let mut a1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                a1.set_local_symbols(10);
                cap.track(a1);

                let mut a2 = OfflineAccess::new(test_object_id_2(), 10, 15, 512);
                a2.set_local_symbols(3);
                cap.track(a2);

                let summary = cap.summary();
                let json_str = serde_json::to_string(&summary).unwrap();
                let deserialized: OfflineSummary = serde_json::from_str(&json_str).unwrap();

                assert_eq!(deserialized.total_objects, summary.total_objects);
                assert_eq!(deserialized.available_objects, summary.available_objects);
                assert_eq!(deserialized.partial_objects, summary.partial_objects);
                assert_eq!(deserialized.not_cached_objects, summary.not_cached_objects);
                assert_eq!(deserialized.readiness_bps, summary.readiness_bps);
                assert_eq!(deserialized.bytes_needed, summary.bytes_needed);

                OfflineLogData {
                    details: Some(json!({"serde": "summary_roundtrip_ok"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn offline_summary_clone() {
        run_offline_test("offline_summary_clone", "verify", "traits", 3, || {
            let mut cap = OfflineCapability::new();

            let mut a1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
            a1.set_local_symbols(5);
            cap.track(a1);

            let summary = cap.summary();
            let cloned = summary.clone();
            // Verify both original and clone hold same data
            assert_eq!(summary.total_objects, cloned.total_objects);
            assert_eq!(cloned.partial_objects, 1);
            assert_eq!(cloned.bytes_needed, 5 * 1024);

            OfflineLogData {
                details: Some(json!({"clone": "summary_ok"})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_summary_debug_format() {
        run_offline_test(
            "offline_summary_debug_format",
            "verify",
            "traits",
            1,
            || {
                let mut cap = OfflineCapability::new();
                let a1 = OfflineAccess::new(test_object_id(), 10, 15, 1024);
                cap.track(a1);

                let summary = cap.summary();
                let debug_str = format!("{summary:?}");
                assert!(debug_str.contains("OfflineSummary"));

                OfflineLogData {
                    details: Some(json!({"debug": "format_ok"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    // =====================================================================
    // Additional AccessPatternTracker tests
    // =====================================================================

    #[test]
    fn access_pattern_tracker_multiple_accesses_same_object() {
        run_offline_test(
            "tracker_multiple_accesses_same_object",
            "verify",
            "record",
            3,
            || {
                let mut tracker = AccessPatternTracker::new();
                let object_id = test_object_id();

                for _ in 0..20 {
                    tracker.record_access(object_id);
                }

                assert_eq!(tracker.access_count(&object_id), 20);
                assert_eq!(tracker.tracked_count(), 1); // still one entry
                let score = tracker.priority_score(&object_id);
                assert!(score > 0.0);

                OfflineLogData {
                    object_id: Some(object_id),
                    details: Some(json!({
                        "access_count": 20,
                        "priority_score": score
                    })),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_frequency_based_priority() {
        run_offline_test(
            "tracker_frequency_based_priority",
            "verify",
            "priority",
            2,
            || {
                let mut tracker = AccessPatternTracker::new();

                // Access obj1 once
                tracker.record_access(test_object_id());

                // Access obj2 many times (higher EWMA frequency)
                for _ in 0..10 {
                    tracker.record_access(test_object_id_2());
                }

                let score1 = tracker.priority_score(&test_object_id());
                let score2 = tracker.priority_score(&test_object_id_2());

                // obj2 should have a higher priority score due to higher EWMA
                assert!(score2 > score1);
                assert!(score1 > 0.0); // but obj1 still has non-zero score

                OfflineLogData {
                    details: Some(json!({
                        "score1": score1,
                        "score2": score2
                    })),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_clear_then_reuse() {
        run_offline_test("tracker_clear_then_reuse", "verify", "clear", 4, || {
            let mut tracker = AccessPatternTracker::new();

            tracker.record_access(test_object_id());
            tracker.record_access(test_object_id_2());
            assert_eq!(tracker.tracked_count(), 2);

            tracker.clear();
            assert_eq!(tracker.tracked_count(), 0);

            // After clear, accessing same object starts fresh
            tracker.record_access(test_object_id());
            assert_eq!(tracker.tracked_count(), 1);
            assert_eq!(tracker.access_count(&test_object_id()), 1);

            OfflineLogData {
                details: Some(json!({"clear_then_reuse": true})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn access_pattern_tracker_decay_to_near_zero() {
        run_offline_test("tracker_decay_to_near_zero", "verify", "decay", 2, || {
            let mut tracker = AccessPatternTracker::new();
            tracker.record_access(test_object_id());

            // Decay many times to drive EWMA toward zero
            for _ in 0..50 {
                tracker.decay_all(0.1);
            }

            let score = tracker.priority_score(&test_object_id());
            // After aggressive decay, score should be very small
            assert!(score < 0.001);
            // Access count is unchanged by decay
            assert_eq!(tracker.access_count(&test_object_id()), 1);

            OfflineLogData {
                details: Some(json!({"decayed_score": score})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn access_pattern_tracker_decay_factor_clamped() {
        run_offline_test("tracker_decay_factor_clamped", "verify", "decay", 2, || {
            let mut tracker = AccessPatternTracker::new();
            tracker.record_access(test_object_id());

            let score_before = tracker.priority_score(&test_object_id());

            // Factor > 1.0 should be clamped to 1.0 (no amplification)
            tracker.decay_all(5.0);
            let score_after = tracker.priority_score(&test_object_id());

            // With factor clamped to 1.0, score should remain approximately the same
            assert!((score_after - score_before).abs() < 0.01);

            OfflineLogData {
                details: Some(json!({
                    "score_before": score_before,
                    "score_after": score_after
                })),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn access_pattern_tracker_with_config_negative_alpha() {
        run_offline_test("tracker_negative_alpha", "verify", "config", 2, || {
            // Alpha < 0.0 should be clamped to 0.0
            let mut tracker = AccessPatternTracker::with_config(-1.0, Duration::from_secs(60), 50);
            assert_eq!(tracker.tracked_count(), 0);

            // Record access and verify it still works
            tracker.record_access(test_object_id());
            assert_eq!(tracker.access_count(&test_object_id()), 1);

            OfflineLogData {
                details: Some(json!({"negative_alpha_clamped": true})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn access_pattern_tracker_eviction_preserves_recent() {
        run_offline_test(
            "tracker_eviction_preserves_recent",
            "verify",
            "eviction",
            3,
            || {
                // Max 2 entries
                let mut tracker =
                    AccessPatternTracker::with_config(0.3, Duration::from_secs(3600), 2);

                // obj1 inserted first (oldest)
                tracker.record_access(test_object_id());
                // obj2 inserted second
                tracker.record_access(test_object_id_2());

                assert_eq!(tracker.tracked_count(), 2);

                // obj3 triggers eviction of oldest (obj1)
                tracker.record_access(test_object_id_3());
                assert_eq!(tracker.tracked_count(), 2);

                // obj1 should have been evicted (oldest last_access)
                assert_eq!(tracker.access_count(&test_object_id()), 0);
                // obj2 and obj3 should still be tracked
                assert!(tracker.access_count(&test_object_id_2()) > 0);
                assert!(tracker.access_count(&test_object_id_3()) > 0);

                OfflineLogData {
                    details: Some(json!({
                        "evicted": "obj1",
                        "remaining": ["obj2", "obj3"]
                    })),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_top_n_exceeds_tracked() {
        run_offline_test(
            "tracker_top_n_exceeds_tracked",
            "verify",
            "top_n",
            2,
            || {
                let mut tracker = AccessPatternTracker::new();
                tracker.record_access(test_object_id());

                // Requesting more than tracked should return all tracked
                let top_10 = tracker.top_n(10);
                assert_eq!(top_10.len(), 1);
                assert_eq!(top_10[0].0, test_object_id());

                OfflineLogData {
                    details: Some(json!({"top_n": 10, "actual": 1})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    #[test]
    fn access_pattern_tracker_top_n_zero() {
        run_offline_test("tracker_top_n_zero", "verify", "top_n", 1, || {
            let mut tracker = AccessPatternTracker::new();
            tracker.record_access(test_object_id());
            tracker.record_access(test_object_id_2());

            let top_0 = tracker.top_n(0);
            assert!(top_0.is_empty());

            OfflineLogData {
                details: Some(json!({"top_0": true})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn access_pattern_tracker_default_trait() {
        run_offline_test("tracker_default_trait", "init", "create", 1, || {
            let tracker = AccessPatternTracker::default();
            assert_eq!(tracker.tracked_count(), 0);

            OfflineLogData {
                details: Some(json!({"default": "tracker_ok"})),
                ..OfflineLogData::default()
            }
        });
    }

    // =====================================================================
    // Additional OfflineStatus tests
    // =====================================================================

    #[test]
    fn offline_status_equality() {
        run_offline_test("offline_status_equality", "verify", "traits", 3, || {
            assert_eq!(OfflineStatus::Available, OfflineStatus::Available);
            assert_eq!(OfflineStatus::Partial, OfflineStatus::Partial);
            assert_ne!(OfflineStatus::Available, OfflineStatus::NotCached);

            OfflineLogData {
                details: Some(json!({"equality": "verified"})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_status_clone_copy() {
        run_offline_test("offline_status_clone_copy", "verify", "traits", 2, || {
            let status = OfflineStatus::Partial;
            let copied = status; // Copy trait
            let cloned = copied; // also Copy

            assert_eq!(cloned, OfflineStatus::Partial);
            assert_eq!(copied, OfflineStatus::Partial);

            OfflineLogData {
                details: Some(json!({"clone_copy": "ok"})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_status_debug_format() {
        run_offline_test("offline_status_debug_format", "verify", "traits", 3, || {
            let debug_available = format!("{:?}", OfflineStatus::Available);
            let debug_partial = format!("{:?}", OfflineStatus::Partial);
            let debug_not_cached = format!("{:?}", OfflineStatus::NotCached);

            assert_eq!(debug_available, "Available");
            assert_eq!(debug_partial, "Partial");
            assert_eq!(debug_not_cached, "NotCached");

            OfflineLogData {
                details: Some(json!({"debug_format": "all_variants"})),
                ..OfflineLogData::default()
            }
        });
    }

    #[test]
    fn offline_status_serde_individual_variants() {
        run_offline_test(
            "offline_status_serde_individual_variants",
            "verify",
            "serde",
            3,
            || {
                let available_json = serde_json::to_string(&OfflineStatus::Available).unwrap();
                let partial_json = serde_json::to_string(&OfflineStatus::Partial).unwrap();
                let not_cached_json = serde_json::to_string(&OfflineStatus::NotCached).unwrap();

                assert_eq!(
                    serde_json::from_str::<OfflineStatus>(&available_json).unwrap(),
                    OfflineStatus::Available,
                );
                assert_eq!(
                    serde_json::from_str::<OfflineStatus>(&partial_json).unwrap(),
                    OfflineStatus::Partial,
                );
                assert_eq!(
                    serde_json::from_str::<OfflineStatus>(&not_cached_json).unwrap(),
                    OfflineStatus::NotCached,
                );

                OfflineLogData {
                    details: Some(json!({"serde_variants": "all_ok"})),
                    ..OfflineLogData::default()
                }
            },
        );
    }

    // --- OfflineAccess additional tests ---

    #[test]
    fn offline_access_set_local_symbols() {
        let id = ObjectId::from_bytes([1; 32]);
        let mut access = OfflineAccess::new(id, 10, 20, 64);
        assert_eq!(access.local_symbols, 0);
        access.set_local_symbols(7);
        assert_eq!(access.local_symbols, 7);
        assert!(!access.can_access());
        access.set_local_symbols(10);
        assert!(access.can_access());
    }

    #[test]
    fn offline_access_add_remove_saturating() {
        let id = ObjectId::from_bytes([2; 32]);
        let mut access = OfflineAccess::new(id, 10, 20, 64);
        access.add_symbols(5);
        assert_eq!(access.local_symbols, 5);
        access.remove_symbols(100); // Should saturate to 0
        assert_eq!(access.local_symbols, 0);
    }

    #[test]
    fn offline_access_coverage_k_zero() {
        let id = ObjectId::from_bytes([3; 32]);
        let access = OfflineAccess::new(id, 0, 0, 64);
        assert_eq!(access.coverage_bps(), 10_000);
        assert!((access.coverage() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn offline_access_bytes_needed_zero_when_full() {
        let id = ObjectId::from_bytes([4; 32]);
        let mut access = OfflineAccess::new(id, 10, 20, 64);
        access.set_local_symbols(10);
        assert_eq!(access.bytes_needed(), 0);
    }

    #[test]
    fn offline_access_debug() {
        let access = OfflineAccess::new(ObjectId::from_bytes([5; 32]), 10, 20, 64);
        let dbg = format!("{access:?}");
        assert!(dbg.contains("OfflineAccess"));
    }

    #[test]
    fn offline_access_clone_preserves_fields() {
        let id = ObjectId::from_bytes([6; 32]);
        let access = OfflineAccess::new(id, 10, 20, 64);
        let cloned = access.clone();
        assert_eq!(access.k, cloned.k);
        assert_eq!(access.n, cloned.n);
    }

    // --- OfflineStatus additional tests ---

    #[test]
    fn offline_status_debug() {
        let s = OfflineStatus::Available;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Available"));
    }

    #[test]
    fn offline_status_clone_copy_eq() {
        let a = OfflineStatus::Partial;
        let b = a;
        assert_eq!(a, b);
    }

    // --- OfflineSummary tests ---

    #[test]
    fn offline_summary_serde_json_roundtrip() {
        let summary = OfflineSummary {
            total_objects: 10,
            available_objects: 5,
            partial_objects: 3,
            not_cached_objects: 2,
            readiness_bps: 5000,
            bytes_needed: 1024,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let rt: OfflineSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.total_objects, 10);
        assert_eq!(rt.available_objects, 5);
        assert_eq!(rt.readiness_bps, 5000);
    }

    #[test]
    fn offline_summary_debug() {
        let summary = OfflineSummary {
            total_objects: 0,
            available_objects: 0,
            partial_objects: 0,
            not_cached_objects: 0,
            readiness_bps: 0,
            bytes_needed: 0,
        };
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("OfflineSummary"));
    }

    #[test]
    fn offline_summary_clone_preserves_fields() {
        let summary = OfflineSummary {
            total_objects: 3,
            available_objects: 1,
            partial_objects: 1,
            not_cached_objects: 1,
            readiness_bps: 3333,
            bytes_needed: 512,
        };
        let cloned = summary.clone();
        assert_eq!(summary.total_objects, cloned.total_objects);
    }

    // --- AccessPatternTracker tests ---

    #[test]
    fn access_pattern_tracker_default() {
        let tracker = AccessPatternTracker::default();
        assert_eq!(tracker.tracked_count(), 0);
    }

    #[test]
    fn access_pattern_tracker_debug() {
        let tracker = AccessPatternTracker::new();
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("AccessPatternTracker"));
    }

    #[test]
    fn access_pattern_tracker_clear_removes_all() {
        let mut tracker = AccessPatternTracker::new();
        let id = ObjectId::from_bytes([1; 32]);
        tracker.record_access(id);
        assert_eq!(tracker.tracked_count(), 1);
        tracker.clear();
        assert_eq!(tracker.tracked_count(), 0);
    }

    // --- OfflineAccess edge cases ---

    #[test]
    fn offline_access_coverage_bps_zero_k() {
        let access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 0, 10, 64);
        assert_eq!(access.coverage_bps(), 10_000);
    }

    #[test]
    fn offline_access_coverage_float_zero_k() {
        let access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 0, 10, 64);
        assert!((access.coverage() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn offline_access_overcoverage_bps() {
        let mut access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 5, 10, 64);
        access.set_local_symbols(15);
        // 15/5 * 10000 = 30000
        assert_eq!(access.coverage_bps(), 30_000);
    }

    #[test]
    fn offline_access_add_symbols_saturating() {
        let mut access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 10, 20, 64);
        access.add_symbols(u32::MAX);
        assert_eq!(access.local_symbols, u32::MAX);
        // Adding more should saturate
        access.add_symbols(1);
        assert_eq!(access.local_symbols, u32::MAX);
    }

    #[test]
    fn offline_access_remove_symbols_saturating() {
        let mut access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 10, 20, 64);
        access.set_local_symbols(5);
        access.remove_symbols(100);
        assert_eq!(access.local_symbols, 0);
    }

    #[test]
    fn offline_access_bytes_needed_zero_when_available() {
        let mut access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 10, 20, 64);
        access.set_local_symbols(10);
        assert_eq!(access.bytes_needed(), 0);
    }

    #[test]
    fn offline_access_bytes_needed_calculation() {
        let access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 10, 20, 128);
        // Need 10 symbols * 128 bytes = 1280
        assert_eq!(access.bytes_needed(), 1280);
    }

    #[test]
    fn offline_access_serde_json_rt() {
        let mut access = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 10, 20, 64);
        access.set_local_symbols(5);
        let json = serde_json::to_string(&access).unwrap();
        let rt: OfflineAccess = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.local_symbols, 5);
        assert_eq!(rt.k, 10);
        assert_eq!(rt.n, 20);
    }

    // --- OfflineStatus ---

    #[test]
    fn offline_status_serde_all_variants() {
        for status in [
            OfflineStatus::Available,
            OfflineStatus::Partial,
            OfflineStatus::NotCached,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let rt: OfflineStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, status);
        }
    }

    #[test]
    fn offline_status_copy_eq() {
        let s = OfflineStatus::Partial;
        let s2 = s;
        assert_eq!(s, s2);
        assert_ne!(s, OfflineStatus::Available);
    }

    // --- OfflineCapability ---

    #[test]
    fn offline_capability_remove() {
        let mut cap = OfflineCapability::new();
        let id = ObjectId::from_bytes([1; 32]);
        let access = OfflineAccess::new(id, 10, 20, 64);
        cap.track(access);
        assert_eq!(cap.object_count(), 1);
        let removed = cap.remove(&id);
        assert!(removed.is_some());
        assert_eq!(cap.object_count(), 0);
    }

    #[test]
    fn offline_capability_remove_nonexistent() {
        let mut cap = OfflineCapability::new();
        let id = ObjectId::from_bytes([99; 32]);
        assert!(cap.remove(&id).is_none());
    }

    #[test]
    fn offline_capability_readiness_bps_empty() {
        let cap = OfflineCapability::new();
        assert_eq!(cap.readiness_bps(), 0);
    }

    #[test]
    fn offline_capability_readiness_bps_all_available() {
        let mut cap = OfflineCapability::new();
        for i in 0..5 {
            let mut access = OfflineAccess::new(ObjectId::from_bytes([i; 32]), 10, 20, 64);
            access.set_local_symbols(10);
            cap.track(access);
        }
        assert_eq!(cap.readiness_bps(), 10_000);
    }

    #[test]
    fn offline_capability_readiness_bps_half_available() {
        let mut cap = OfflineCapability::new();
        for i in 0..4 {
            let mut access = OfflineAccess::new(ObjectId::from_bytes([i; 32]), 10, 20, 64);
            if i < 2 {
                access.set_local_symbols(10);
            }
            cap.track(access);
        }
        assert_eq!(cap.readiness_bps(), 5000);
    }

    // --- OfflineSummary ---

    #[test]
    fn offline_summary_all_not_cached() {
        let mut cap = OfflineCapability::new();
        for i in 0..3 {
            let access = OfflineAccess::new(ObjectId::from_bytes([i; 32]), 10, 20, 64);
            cap.track(access);
        }
        let summary = cap.summary();
        assert_eq!(summary.total_objects, 3);
        assert_eq!(summary.available_objects, 0);
        assert_eq!(summary.not_cached_objects, 3);
        assert_eq!(summary.partial_objects, 0);
    }

    #[test]
    fn offline_summary_mixed_states() {
        let mut cap = OfflineCapability::new();
        // Available
        let mut a1 = OfflineAccess::new(ObjectId::from_bytes([1; 32]), 10, 20, 64);
        a1.set_local_symbols(10);
        cap.track(a1);
        // Partial
        let mut a2 = OfflineAccess::new(ObjectId::from_bytes([2; 32]), 10, 20, 64);
        a2.set_local_symbols(5);
        cap.track(a2);
        // Not cached
        let a3 = OfflineAccess::new(ObjectId::from_bytes([3; 32]), 10, 20, 64);
        cap.track(a3);

        let summary = cap.summary();
        assert_eq!(summary.available_objects, 1);
        assert_eq!(summary.partial_objects, 1);
        assert_eq!(summary.not_cached_objects, 1);
    }

    #[test]
    fn offline_summary_serde_json_rt() {
        let summary = OfflineSummary {
            total_objects: 10,
            available_objects: 5,
            partial_objects: 3,
            not_cached_objects: 2,
            readiness_bps: 5000,
            bytes_needed: 1024,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let rt: OfflineSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.total_objects, 10);
        assert_eq!(rt.readiness_bps, 5000);
    }

    // --- AccessPatternTracker edge cases ---

    #[test]
    fn access_pattern_tracker_decay_all_zeros_out() {
        let mut tracker = AccessPatternTracker::new();
        let id = ObjectId::from_bytes([1; 32]);
        tracker.record_access(id);
        tracker.decay_all(0.0);
        // After decaying to 0, priority should be 0 (frequency = 0)
        let score = tracker.priority_score(&id);
        assert!(score.abs() < f64::EPSILON);
    }

    #[test]
    fn access_pattern_tracker_config_alpha_clamped_high() {
        let tracker = AccessPatternTracker::with_config(
            2.0, // > 1.0, should be clamped
            Duration::from_secs(60),
            100,
        );
        assert_eq!(tracker.tracked_count(), 0);
    }

    #[test]
    fn access_pattern_tracker_top_n_empty() {
        let tracker = AccessPatternTracker::new();
        let top = tracker.top_n(5);
        assert!(top.is_empty());
    }

    #[test]
    fn access_pattern_tracker_access_count_untracked() {
        let tracker = AccessPatternTracker::new();
        let id = ObjectId::from_bytes([1; 32]);
        assert_eq!(tracker.access_count(&id), 0);
    }

    #[test]
    fn access_pattern_tracker_priority_score_untracked() {
        let tracker = AccessPatternTracker::new();
        let id = ObjectId::from_bytes([1; 32]);
        assert!(tracker.priority_score(&id).abs() < f64::EPSILON);
    }
}
