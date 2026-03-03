//! Offline capability tracking for FCP2 mesh objects.
//!
//! Implements quantifiable offline access from `FCP_Specification_V2.md` section 21.
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
            return 0;
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
            return 0.0;
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
                // k=0 is an edge case - should return 0 coverage and can_access true (no symbols needed)
                let access = OfflineAccess::new(object_id, 0, 0, 1024);

                // With k=0, can_access should be true (0 >= 0)
                assert!(access.can_access());
                // Coverage should be 0 (division by zero protection)
                assert_eq!(access.coverage_bps(), 0);
                #[allow(clippy::float_cmp)] // exact zero is valid for k=0 edge case
                {
                    assert_eq!(access.coverage(), 0.0);
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
}
