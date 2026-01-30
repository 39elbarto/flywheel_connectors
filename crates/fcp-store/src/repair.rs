//! Repair controller for maintaining object coverage (NORMATIVE).
//!
//! Implements bounded, convergent repair from `FCP_Specification_V2.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fcp_core::{ObjectId, ObjectPlacementPolicy, ZoneId};
use fcp_telemetry::metrics;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::coverage::{CoverageEvaluation, CoverageHealth};
use crate::symbol_store::SymbolStore;

/// Repair request for an object.
#[derive(Debug, Clone)]
pub struct RepairRequest {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Zone the object belongs to.
    pub zone_id: ZoneId,
    /// Current coverage evaluation.
    pub coverage: CoverageEvaluation,
    /// Target placement policy.
    pub policy: ObjectPlacementPolicy,
    /// Priority (higher = more urgent).
    pub priority: u32,
}

/// Repair result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    /// Object that was repaired.
    pub object_id: ObjectId,
    /// Whether repair was successful.
    pub success: bool,
    /// New coverage after repair.
    pub new_coverage_bps: u32,
    /// Symbols added during repair.
    pub symbols_added: u32,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Repair controller configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairControllerConfig {
    /// Maximum concurrent repair operations.
    pub max_concurrent_repairs: usize,
    /// Maximum repairs per minute (rate limit).
    pub max_repairs_per_minute: u32,
    /// Interval between repair loop iterations.
    pub repair_interval: Duration,
    /// Minimum coverage deficit (bps) to trigger repair.
    pub min_deficit_bps: u32,
    /// Maximum symbols to request per repair.
    pub max_symbols_per_repair: u32,
}

impl Default for RepairControllerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_repairs: 10,
            max_repairs_per_minute: 100,
            repair_interval: Duration::from_secs(60),
            min_deficit_bps: 500, // 5% deficit triggers repair
            max_symbols_per_repair: 100,
        }
    }
}

/// Repair statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepairStats {
    /// Total repairs attempted.
    pub repairs_attempted: u64,
    /// Successful repairs.
    pub repairs_succeeded: u64,
    /// Failed repairs.
    pub repairs_failed: u64,
    /// Total symbols added.
    pub symbols_added: u64,
    /// Current repair queue depth.
    pub queue_depth: usize,
    /// Repairs blocked by rate limit.
    pub rate_limited: u64,
}

/// Rate limiter for repairs.
struct RateLimiter {
    tokens: RwLock<u32>,
    max_tokens: u32,
    last_refill: RwLock<std::time::Instant>,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            tokens: RwLock::new(max_per_minute),
            max_tokens: max_per_minute,
            last_refill: RwLock::new(std::time::Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        if self.max_tokens == 0 {
            return false;
        }

        // We need to lock both to update atomically
        let mut last = self.last_refill.write();
        let mut tokens = self.tokens.write();
        self.refill_locked(&mut last, &mut tokens);

        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }

    fn available(&self) -> u32 {
        if self.max_tokens == 0 {
            return 0;
        }

        let mut last = self.last_refill.write();
        let mut tokens = self.tokens.write();
        self.refill_locked(&mut last, &mut tokens);
        *tokens
    }

    fn refill_locked(&self, last: &mut std::time::Instant, tokens: &mut u32) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last);

        let nanos_per_token = 60_000_000_000u64 / u64::from(self.max_tokens);
        if nanos_per_token == 0 {
            *tokens = self.max_tokens;
            *last = now;
            return;
        }

        if let Some(new_tokens) = (elapsed.as_nanos() as u64).checked_div(nanos_per_token) {
            if new_tokens > 0 {
                // Determine new token count, capped at max
                let updated = tokens.saturating_add(u32::try_from(new_tokens).unwrap_or(u32::MAX));

                if updated >= self.max_tokens {
                    *tokens = self.max_tokens;
                    *last = now; // Reset time if bucket is full
                } else {
                    *tokens = updated;
                    // Advance time by the amount of tokens added to preserve phase
                    *last += Duration::from_nanos(new_tokens * nanos_per_token);
                }
            }
        } else {
            // Rate implies > 1 token/ns (unlikely), just fill
            *tokens = self.max_tokens;
            *last = now;
        }
    }
}

/// Repair controller for maintaining coverage across the mesh.
///
/// Implements bounded, rate-limited repair with convergent behavior.
pub struct RepairController {
    config: RepairControllerConfig,
    semaphore: Arc<Semaphore>,
    rate_limiter: RateLimiter,
    stats: RwLock<RepairStats>,
    queue: RwLock<Vec<RepairRequest>>,
}

impl RepairController {
    /// Create a new repair controller.
    #[must_use]
    pub fn new(config: RepairControllerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_repairs));
        let rate_limiter = RateLimiter::new(config.max_repairs_per_minute);

        Self {
            config,
            semaphore,
            rate_limiter,
            stats: RwLock::new(RepairStats::default()),
            queue: RwLock::new(Vec::new()),
        }
    }

    /// Queue a repair request.
    pub fn queue_repair(&self, request: RepairRequest) {
        let mut queue = self.queue.write();

        // Check if already queued
        if queue.iter().any(|r| r.object_id == request.object_id) {
            return;
        }

        queue.push(request);

        // Sort by priority (highest first)
        queue.sort_by_key(|r| std::cmp::Reverse(r.priority));

        self.stats.write().queue_depth = queue.len();
    }

    /// Get the next repair request if rate limit allows.
    pub fn next_repair(&self) -> Option<RepairRequest> {
        if !self.rate_limiter.try_acquire() {
            self.stats.write().rate_limited += 1;
            return None;
        }

        let mut queue = self.queue.write();
        let request = if queue.is_empty() {
            None
        } else {
            Some(queue.remove(0))
        };
        self.stats.write().queue_depth = queue.len();
        request
    }

    /// Try to acquire a repair permit.
    ///
    /// Returns `None` if max concurrent repairs reached.
    pub fn try_acquire_permit(&self) -> Option<RepairPermit> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| RepairPermit { _permit: permit })
    }

    /// Record a repair result.
    pub fn record_result(&self, result: &RepairResult) {
        let mut stats = self.stats.write();
        stats.repairs_attempted += 1;

        if result.success {
            stats.repairs_succeeded += 1;
            stats.symbols_added += u64::from(result.symbols_added);
        } else {
            stats.repairs_failed += 1;
        }
    }

    /// Get current repair statistics.
    #[must_use]
    pub fn stats(&self) -> RepairStats {
        self.stats.read().clone()
    }

    /// Get repair controller configuration.
    #[must_use]
    pub const fn config(&self) -> &RepairControllerConfig {
        &self.config
    }

    /// Check if an object needs repair based on coverage.
    #[must_use]
    pub const fn needs_repair(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> bool {
        let health = coverage.health(policy);
        let diversity_deficit = coverage.diversity_deficit(policy.min_source_diversity);

        match health {
            CoverageHealth::Unavailable => true,
            CoverageHealth::Degraded => {
                diversity_deficit > 0
                    || coverage.coverage_deficit_bps(policy.target_coverage_bps)
                        >= self.config.min_deficit_bps
            }
            CoverageHealth::Healthy => false,
        }
    }

    /// Calculate repair priority for an object.
    #[must_use]
    pub const fn calculate_priority(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> u32 {
        let health = coverage.health(policy);
        let diversity_deficit = coverage.diversity_deficit(policy.min_source_diversity);

        match health {
            CoverageHealth::Unavailable => {
                // Highest priority, but differentiate by coverage deficit
                // Objects with less coverage get higher priority
                let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
                1000 + deficit / 100 // 1000-1100+ range (higher deficit = higher priority)
            }
            CoverageHealth::Degraded => {
                // Priority based on deficit
                let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
                if diversity_deficit > 0 {
                    200 + (diversity_deficit as u32) * 10 + deficit / 100
                } else {
                    100 + deficit / 100 // 100-199 range
                }
            }
            CoverageHealth::Healthy => 0,
        }
    }

    /// Evaluate all objects in a zone and queue repairs as needed.
    pub async fn evaluate_zone(
        &self,
        zone_id: &ZoneId,
        symbol_store: &dyn SymbolStore,
        policies: &HashMap<ObjectId, ObjectPlacementPolicy>,
    ) {
        let object_ids = symbol_store.list_zone(zone_id).await;

        for object_id in object_ids {
            let policy = match policies.get(&object_id) {
                Some(p) => p.clone(),
                None => continue, // No policy, skip
            };

            let Some(dist) = symbol_store.get_distribution(&object_id).await else {
                continue;
            };

            let coverage = CoverageEvaluation::from_distribution(object_id, &dist);
            let diversity_bps = coverage.diversity_bps(policy.min_source_diversity);

            metrics::record_symbol_coverage(
                zone_id.as_ref(),
                coverage.distinct_nodes,
                coverage.coverage_bps,
                coverage.max_node_fraction_bps,
                diversity_bps,
            );
            if coverage.is_available
                && policy.min_source_diversity > 0
                && coverage.distinct_nodes < policy.min_source_diversity as usize
            {
                metrics::record_diversity_violation(
                    zone_id.as_ref(),
                    policy.min_source_diversity,
                    coverage.distinct_nodes,
                );
            }

            if self.needs_repair(&coverage, &policy) {
                let priority = self.calculate_priority(&coverage, &policy);
                self.queue_repair(RepairRequest {
                    object_id,
                    zone_id: zone_id.clone(),
                    coverage,
                    policy,
                    priority,
                });
            }
        }
    }

    /// Get available rate limit tokens.
    #[must_use]
    pub fn available_rate_tokens(&self) -> u32 {
        self.rate_limiter.available()
    }

    /// Get queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.read().len()
    }

    /// Clear the repair queue.
    pub fn clear_queue(&self) {
        self.queue.write().clear();
        self.stats.write().queue_depth = 0;
    }
}

/// RAII permit for concurrent repair operations.
pub struct RepairPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Targeted repair request for specific symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetedRepairRequest {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Specific ESIs to request.
    pub esis: Vec<u32>,
    /// Preferred source nodes (for source diversity).
    pub preferred_sources: Vec<u64>,
    /// Nodes to exclude (already have symbols from).
    pub excluded_sources: Vec<u64>,
}

impl TargetedRepairRequest {
    /// Create a new targeted repair request.
    #[must_use]
    pub const fn new(object_id: ObjectId) -> Self {
        Self {
            object_id,
            esis: Vec::new(),
            preferred_sources: Vec::new(),
            excluded_sources: Vec::new(),
        }
    }

    /// Add ESIs to request.
    #[must_use]
    pub fn with_esis(mut self, esis: Vec<u32>) -> Self {
        self.esis = esis;
        self
    }

    /// Set preferred sources.
    #[must_use]
    pub fn with_preferred_sources(mut self, sources: Vec<u64>) -> Self {
        self.preferred_sources = sources;
        self
    }

    /// Set excluded sources.
    #[must_use]
    pub fn with_excluded_sources(mut self, sources: Vec<u64>) -> Self {
        self.excluded_sources = sources;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use bytes::Bytes;
    use chrono::Utc;
    use fcp_testkit::LogCapture;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use serde_json::json;
    use uuid::Uuid;

    use crate::symbol_store::{ObjectTransmissionInfo, StoredSymbol, SymbolMeta};
    use crate::{MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, SymbolDistribution};

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
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

    fn log_repair_action(
        object_id: &ObjectId,
        source_node: u64,
        target_node: u64,
        coverage_before: u32,
        coverage_after: u32,
        reason_code: &str,
    ) {
        let log = json!({
            "repair_action": "replicate",
            "object_id": object_id.to_string(),
            "source_node": format!("node-{source_node}"),
            "target_node": format!("node-{target_node}"),
            "coverage_before_bps": coverage_before,
            "coverage_after_bps": coverage_after,
            "reason_code": reason_code,
        });
        println!("{log}");
    }

    fn test_coverage(total: u32, source: u32) -> CoverageEvaluation {
        CoverageEvaluation {
            object_id: ObjectId::from_bytes([1; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: total
                .saturating_mul(10_000)
                .checked_div(source)
                .unwrap_or(0),
            is_available: total >= source,
            total_symbols: total,
            source_symbols: source,
        }
    }

    fn test_policy() -> ObjectPlacementPolicy {
        ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000, // 100%
            min_source_diversity: 0,
        }
    }

    #[test]
    fn needs_repair_unavailable() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(5, 10); // 50% coverage, unavailable
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_degraded() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500, // 5%
            ..Default::default()
        });

        // 90% coverage = 10% deficit = 1000 bps deficit
        let coverage = test_coverage(9, 10);
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_diversity_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // fully available
        let mut policy = test_policy();
        policy.min_source_diversity = 2;

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn repair_queued_for_diversity_deficit() {
        run_store_test(
            "repair_queued_for_diversity_deficit",
            "verify",
            "repair",
            4,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });

                let zone_id: ZoneId = "z:test".parse().unwrap();
                let object_id = ObjectId::from_bytes([9; 32]);
                let oti = ObjectTransmissionInfo {
                    transfer_length: 256,
                    symbol_size: 64,
                    source_blocks: 1,
                    sub_blocks: 1,
                    alignment: 8,
                };
                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti,
                    source_symbols: 4,
                    first_symbol_at: 1_000_000,
                };
                store.put_object_meta(meta).await.unwrap();

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
                    store.put_symbol(symbol).await.unwrap();
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 2,
                };
                let mut policies = HashMap::new();
                policies.insert(object_id, policy.clone());

                let controller = RepairController::new(RepairControllerConfig::default());
                controller.evaluate_zone(&zone_id, &store, &policies).await;

                assert_eq!(controller.queue_depth(), 1);
                let request = controller.next_repair().expect("repair queued");
                assert_eq!(request.object_id, object_id);
                assert_eq!(request.coverage.distinct_nodes, 1);
                assert!(!request.coverage.meets_diversity_for_reconstruction(&policy));

                let capture = LogCapture::new();
                let entry = json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "test_name": "repair_queued_for_diversity_deficit",
                    "module": "fcp-store",
                    "phase": "verify",
                    "correlation_id": Uuid::new_v4().to_string(),
                    "result": "pass",
                    "duration_ms": 0,
                    "assertions": { "passed": 4, "failed": 0 },
                    "details": {
                        "object_id": object_id.to_string(),
                        "source_count": request.coverage.distinct_nodes,
                        "diversity_bps": request.coverage.diversity_bps(policy.min_source_diversity),
                        "repair_queued": true
                    }
                });
                capture.push_value(&entry).expect("serialize log entry");
                capture.assert_valid();

                let dist = store.get_distribution(&object_id).await.unwrap();

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(request.coverage.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "source_count": request.coverage.distinct_nodes,
                        "diversity_bps": request.coverage.diversity_bps(policy.min_source_diversity)
                    })),
                }
            },
        );
    }

    #[test]
    fn no_repair_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100% coverage
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn priority_calculation() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let policy = test_policy();

        // Unavailable = highest priority (1000 + deficit-based increment)
        // 5/10 symbols = 50% coverage = 5000 bps, target = 10000 bps, deficit = 5000 bps
        // priority = 1000 + 5000/100 = 1050
        let unavailable = test_coverage(5, 10);
        let priority = controller.calculate_priority(&unavailable, &policy);
        assert!(priority >= 1000, "unavailable should have priority >= 1000");
        assert_eq!(priority, 1050, "5/10 symbols should have priority 1050");

        // Degraded = medium priority
        let degraded = CoverageEvaluation {
            object_id: ObjectId::from_bytes([2; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10_000,
            coverage_bps: 9_000,
            is_available: true,
            total_symbols: 10,
            source_symbols: 10,
        };
        let priority = controller.calculate_priority(&degraded, &policy);
        assert!((100..200).contains(&priority));

        let mut diversity_policy = test_policy();
        diversity_policy.min_source_diversity = 3;
        let diversity_priority = controller.calculate_priority(&degraded, &diversity_policy);
        assert!(
            diversity_priority >= 200,
            "diversity deficits should elevate priority"
        );

        // Healthy = no priority
        let healthy = test_coverage(10, 10);
        assert_eq!(controller.calculate_priority(&healthy, &policy), 0);
    }

    #[test]
    fn queue_and_dequeue() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let request1 = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        let request2 = RepairRequest {
            object_id: ObjectId::from_bytes([2; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(3, 10),
            policy: test_policy(),
            priority: 1000, // Higher priority
        };

        controller.queue_repair(request1);
        controller.queue_repair(request2);

        assert_eq!(controller.queue_depth(), 2);

        // Should get highest priority first
        let next = controller.next_repair().unwrap();
        assert_eq!(next.priority, 1000);

        let next = controller.next_repair().unwrap();
        assert_eq!(next.priority, 100);
    }

    #[test]
    fn duplicate_queue_ignored() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let request = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        controller.queue_repair(request.clone());
        controller.queue_repair(request); // Duplicate

        assert_eq!(controller.queue_depth(), 1);
    }

    #[test]
    fn record_results() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let success = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };

        let failure = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };

        controller.record_result(&success);
        controller.record_result(&failure);

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 2);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.repairs_failed, 1);
        assert_eq!(stats.symbols_added, 5);
    }

    #[test]
    fn rate_limiting() {
        let config = RepairControllerConfig {
            max_repairs_per_minute: 2,
            ..Default::default()
        };
        let controller = RepairController::new(config);

        // Queue 5 repairs
        for i in 0..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        // Should only get 2 due to rate limit
        assert!(controller.next_repair().is_some());
        assert!(controller.next_repair().is_some());
        assert!(controller.next_repair().is_none()); // Rate limited

        let stats = controller.stats();
        assert!(stats.rate_limited > 0);
    }

    #[tokio::test]
    async fn concurrent_permits() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 2,
            ..Default::default()
        };
        let controller = RepairController::new(config);

        let permit1 = controller.try_acquire_permit();
        assert!(permit1.is_some());

        let permit2 = controller.try_acquire_permit();
        assert!(permit2.is_some());

        // Third should fail
        let permit3 = controller.try_acquire_permit();
        assert!(permit3.is_none());

        // Drop one permit
        drop(permit1);

        // Now should succeed
        let permit4 = controller.try_acquire_permit();
        assert!(permit4.is_some());
    }

    #[test]
    fn targeted_repair_request() {
        let request = TargetedRepairRequest::new(ObjectId::from_bytes([1; 32]))
            .with_esis(vec![0, 1, 2])
            .with_preferred_sources(vec![100, 200])
            .with_excluded_sources(vec![300]);

        assert_eq!(request.esis.len(), 3);
        assert_eq!(request.preferred_sources.len(), 2);
        assert_eq!(request.excluded_sources.len(), 1);
    }

    #[test]
    fn clear_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());

        for i in 0..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        assert_eq!(controller.queue_depth(), 5);

        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn repair_loop_improves_coverage() {
        run_store_test(
            "repair_loop_improves_coverage",
            "verify",
            "repair",
            3,
            || async {
                let zone_id: ZoneId = "z:store-sim".parse().unwrap();
                let object_id = ObjectId::from_bytes([7; 32]);
                let source_symbols: u32 = 10;
                let symbol_size: u16 = 64;
                let mut rng = StdRng::seed_from_u64(0x5EED);

                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });

                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                        symbol_size,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols,
                    first_symbol_at: 1_000_000,
                };

                store.put_object_meta(meta).await.unwrap();

                let mut next_esi = 0_u32;
                for _ in 0..5 {
                    let node = if rng.gen_bool(0.5) { 1 } else { 2 };
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(node),
                            stored_at: 1_000_000 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![0_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 2,
                    max_node_fraction_bps: 7000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 16,
                    ..Default::default()
                });

                let mut policies = HashMap::new();
                policies.insert(object_id, policy.clone());

                controller.evaluate_zone(&zone_id, &store, &policies).await;

                let before_dist = store.get_distribution(&object_id).await.unwrap();
                let before_eval = CoverageEvaluation::from_distribution(object_id, &before_dist);

                assert!(controller.queue_depth() > 0);

                if let Some(request) = controller.next_repair() {
                    let _permit = controller.try_acquire_permit().expect("permit");
                    let needed = request
                        .coverage
                        .symbols_needed(request.policy.target_coverage_bps);
                    let to_add = needed.min(controller.config().max_symbols_per_repair);

                    for _ in 0..to_add {
                        let node = if rng.gen_bool(0.5) { 1 } else { 3 };
                        let symbol = StoredSymbol {
                            meta: SymbolMeta {
                                object_id,
                                esi: next_esi,
                                zone_id: zone_id.clone(),
                                source_node: Some(node),
                                stored_at: 1_000_500 + u64::from(next_esi),
                            },
                            data: Bytes::from(vec![1_u8; symbol_size as usize]),
                        };
                        store.put_symbol(symbol).await.unwrap();
                        next_esi += 1;
                    }

                    let after_dist = store.get_distribution(&object_id).await.unwrap();
                    let after_eval = CoverageEvaluation::from_distribution(object_id, &after_dist);

                    log_repair_action(
                        &object_id,
                        1,
                        3,
                        request.coverage.coverage_bps,
                        after_eval.coverage_bps,
                        "BELOW_THRESHOLD",
                    );

                    controller.record_result(&RepairResult {
                        object_id,
                        success: true,
                        new_coverage_bps: after_eval.coverage_bps,
                        symbols_added: to_add,
                        error: None,
                    });
                }

                let after_dist = store.get_distribution(&object_id).await.unwrap();
                let after_eval = CoverageEvaluation::from_distribution(object_id, &after_dist);

                assert!(after_eval.coverage_bps >= policy.target_coverage_bps);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(after_dist.total_symbols),
                    coverage_bps: Some(after_eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&after_dist)),
                    details: Some(json!({
                        "coverage_before_bps": before_eval.coverage_bps,
                        "coverage_after_bps": after_eval.coverage_bps,
                    })),
                }
            },
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn repair_respects_budget_and_idempotent() {
        run_store_test(
            "repair_respects_budget_and_idempotent",
            "verify",
            "repair",
            4,
            || async {
                let zone_id: ZoneId = "z:store-sim".parse().unwrap();
                let object_id = ObjectId::from_bytes([9; 32]);
                let source_symbols: u32 = 10;
                let symbol_size: u16 = 64;

                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 2,
                });

                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                        symbol_size,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                    },
                    source_symbols,
                    first_symbol_at: 2_000_000,
                };

                store.put_object_meta(meta).await.unwrap();

                let mut next_esi = 0_u32;
                for node in [2_u64, 3_u64, 2_u64, 3_u64, 2_u64, 3_u64] {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(node),
                            stored_at: 2_000_000 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![2_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 2,
                    max_node_fraction_bps: 8000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 2,
                    ..Default::default()
                });

                let mut policies = HashMap::new();
                policies.insert(object_id, policy.clone());

                controller.evaluate_zone(&zone_id, &store, &policies).await;
                let before_dist = store.get_distribution(&object_id).await.unwrap();
                let before_eval = CoverageEvaluation::from_distribution(object_id, &before_dist);

                let mut total_added = 0_u32;
                for _ in 0..2 {
                    if let Some(request) = controller.next_repair() {
                        let _permit = controller.try_acquire_permit().expect("permit");
                        let needed = request
                            .coverage
                            .symbols_needed(request.policy.target_coverage_bps);
                        let to_add = needed.min(controller.config().max_symbols_per_repair);
                        total_added += to_add;

                        for _ in 0..to_add {
                            let symbol = StoredSymbol {
                                meta: SymbolMeta {
                                    object_id,
                                    esi: next_esi,
                                    zone_id: zone_id.clone(),
                                    source_node: Some(4),
                                    stored_at: 2_000_500 + u64::from(next_esi),
                                },
                                data: Bytes::from(vec![3_u8; symbol_size as usize]),
                            };
                            store.put_symbol(symbol).await.unwrap();
                            next_esi += 1;
                        }

                        let after_dist = store.get_distribution(&object_id).await.unwrap();
                        let after_eval =
                            CoverageEvaluation::from_distribution(object_id, &after_dist);

                        log_repair_action(
                            &object_id,
                            2,
                            4,
                            request.coverage.coverage_bps,
                            after_eval.coverage_bps,
                            "BELOW_THRESHOLD",
                        );

                        controller.record_result(&RepairResult {
                            object_id,
                            success: true,
                            new_coverage_bps: after_eval.coverage_bps,
                            symbols_added: to_add,
                            error: None,
                        });
                    }

                    controller.evaluate_zone(&zone_id, &store, &policies).await;
                }

                let after_dist = store.get_distribution(&object_id).await.unwrap();
                let after_eval = CoverageEvaluation::from_distribution(object_id, &after_dist);

                assert!(total_added <= 4);
                assert!(after_eval.coverage_bps >= policy.target_coverage_bps);

                controller.evaluate_zone(&zone_id, &store, &policies).await;
                assert_eq!(controller.queue_depth(), 0);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(after_dist.total_symbols),
                    coverage_bps: Some(after_eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&after_dist)),
                    details: Some(json!({
                        "coverage_before_bps": before_eval.coverage_bps,
                        "coverage_after_bps": after_eval.coverage_bps,
                        "symbols_added": total_added,
                    })),
                }
            },
        );
    }

    #[test]
    fn repair_prioritizes_unavailable_objects() {
        run_store_test(
            "repair_prioritizes_unavailable_objects",
            "verify",
            "repair",
            2,
            || async {
                let zone_id: ZoneId = "z:store-sim".parse().unwrap();
                let object_a = ObjectId::from_bytes([0xAA; 32]);
                let object_b = ObjectId::from_bytes([0xBB; 32]);
                let source_symbols: u32 = 10;
                let symbol_size: u16 = 32;

                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 3,
                });

                for object_id in [object_a, object_b] {
                    let meta = ObjectSymbolMeta {
                        object_id,
                        zone_id: zone_id.clone(),
                        oti: ObjectTransmissionInfo {
                            transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                            symbol_size,
                            source_blocks: 1,
                            sub_blocks: 1,
                            alignment: 8,
                        },
                        source_symbols,
                        first_symbol_at: 3_000_000,
                    };
                    store.put_object_meta(meta).await.unwrap();
                }

                let mut next_esi = 0_u32;
                for _ in 0..4 {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id: object_a,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(1),
                            stored_at: 3_000_000 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![4_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                for _ in 0..9 {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id: object_b,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(2),
                            stored_at: 3_000_500 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![5_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 4,
                    ..Default::default()
                });

                let mut policies = HashMap::new();
                policies.insert(object_a, policy.clone());
                policies.insert(object_b, policy.clone());

                controller.evaluate_zone(&zone_id, &store, &policies).await;

                let first = controller.next_repair().expect("first repair");
                let second = controller.next_repair().expect("second repair");

                assert_eq!(first.object_id, object_a);
                assert_eq!(second.object_id, object_b);

                let dist = store.get_distribution(&object_a).await.unwrap();
                let eval = CoverageEvaluation::from_distribution(object_a, &dist);

                StoreLogData {
                    object_id: Some(object_a),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "first_repair_object": first.object_id.to_string(),
                        "second_repair_object": second.object_id.to_string(),
                    })),
                }
            },
        );
    }
}
