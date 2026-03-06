//! Repair controller for maintaining object coverage (NORMATIVE).
//!
//! Implements bounded, convergent repair from `FCP_Specification_V2.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fcp_async_core::sync::{OwnedSemaphorePermit, Semaphore};
use fcp_core::{ObjectId, ObjectPlacementPolicy, ZoneId};
use fcp_telemetry::metrics;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

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
        let elapsed = now.saturating_duration_since(*last);

        let nanos_per_token = 60_000_000_000u64 / u64::from(self.max_tokens).max(1);
        if nanos_per_token == 0 {
            *tokens = self.max_tokens;
            *last = now;
            return;
        }

        let elapsed_nanos = elapsed.as_nanos();
        let new_tokens_u128 = elapsed_nanos / u128::from(nanos_per_token);

        if new_tokens_u128 > 0 {
            let new_tokens = u32::try_from(new_tokens_u128).unwrap_or(u32::MAX);
            let updated = tokens.saturating_add(new_tokens);

            if updated >= self.max_tokens {
                *tokens = self.max_tokens;
                let remainder_nanos = elapsed_nanos % u128::from(nanos_per_token);
                let rem_secs = u64::try_from(remainder_nanos / 1_000_000_000).unwrap_or(0);
                let rem_nanos = (remainder_nanos % 1_000_000_000) as u32;
                *last = now
                    .checked_sub(Duration::new(rem_secs, rem_nanos))
                    .unwrap_or(now);
            } else {
                *tokens = updated;
                // Advance time by the amount of tokens added to preserve phase
                let advance_nanos = new_tokens_u128.saturating_mul(u128::from(nanos_per_token));
                let adv_secs = u64::try_from(advance_nanos / 1_000_000_000).unwrap_or(u64::MAX);
                let adv_nanos = (advance_nanos % 1_000_000_000) as u32;
                if adv_secs < u64::MAX {
                    if let Some(advanced) = last.checked_add(Duration::new(adv_secs, adv_nanos)) {
                        *last = advanced;
                    } else {
                        *last = now;
                    }
                } else {
                    *last = now;
                }
            }
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

        // Deterministic ordering: highest priority first, then stable object-id tie-break.
        queue.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.object_id.cmp(&right.object_id))
        });

        self.stats.write().queue_depth = queue.len();
    }

    /// Get the next repair request if rate limit allows.
    pub fn next_repair(&self) -> Option<RepairRequest> {
        // Acquire write lock first, then check emptiness before consuming a
        // rate-limit token. This avoids a TOCTOU race where the queue is drained
        // between the emptiness check and token acquisition, wasting the token.
        let mut queue = self.queue.write();
        if queue.is_empty() {
            return None;
        }

        if !self.rate_limiter.try_acquire() {
            self.stats.write().rate_limited += 1;
            return None;
        }

        let request = Some(queue.remove(0));
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
                    #[allow(clippy::cast_possible_truncation)] // u8 -> u32 is always safe
                    {
                        200 + (diversity_deficit as u32) * 10 + deficit / 100
                    }
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
    _permit: OwnedSemaphorePermit,
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
    fn queue_tie_breaks_by_object_id() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let higher_object_id = RepairRequest {
            object_id: ObjectId::from_bytes([2; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        let lower_object_id = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        // Insert in reverse object-id order to prove deterministic tie-breaking.
        controller.queue_repair(higher_object_id);
        controller.queue_repair(lower_object_id);

        let first = controller.next_repair().expect("first item");
        let second = controller.next_repair().expect("second item");
        assert_eq!(first.object_id, ObjectId::from_bytes([1; 32]));
        assert_eq!(second.object_id, ObjectId::from_bytes([2; 32]));
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

    #[test]
    fn concurrent_permits() {
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

    // --- New edge case tests ---

    #[test]
    fn config_default_values() {
        let config = RepairControllerConfig::default();
        assert_eq!(config.max_concurrent_repairs, 10);
        assert_eq!(config.max_repairs_per_minute, 100);
        assert_eq!(config.repair_interval, Duration::from_secs(60));
        assert_eq!(config.min_deficit_bps, 500);
        assert_eq!(config.max_symbols_per_repair, 100);
    }

    #[test]
    fn repair_stats_default() {
        let stats = RepairStats::default();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.symbols_added, 0);
        assert_eq!(stats.queue_depth, 0);
        assert_eq!(stats.rate_limited, 0);
    }

    #[test]
    fn repair_result_serde_roundtrip() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.new_coverage_bps, 10000);
        assert_eq!(deserialized.symbols_added, 5);
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn repair_result_serde_with_error() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.success);
        assert_eq!(deserialized.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn repair_stats_serde_roundtrip() {
        let stats = RepairStats {
            repairs_attempted: 10,
            repairs_succeeded: 8,
            repairs_failed: 2,
            symbols_added: 40,
            queue_depth: 3,
            rate_limited: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.repairs_attempted, 10);
        assert_eq!(deserialized.repairs_succeeded, 8);
        assert_eq!(deserialized.symbols_added, 40);
    }

    #[test]
    fn next_repair_empty_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());
        assert!(controller.next_repair().is_none());
        // No rate_limited bump on empty queue
        assert_eq!(controller.stats().rate_limited, 0);
    }

    #[test]
    fn needs_repair_small_deficit_below_threshold() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500,
            ..Default::default()
        });

        // 96% coverage = 4% deficit = 400 bps (below 500 threshold)
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9600;
        coverage.is_available = true;
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn config_accessor() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 5,
            max_repairs_per_minute: 50,
            ..Default::default()
        };
        let controller = RepairController::new(config);
        assert_eq!(controller.config().max_concurrent_repairs, 5);
        assert_eq!(controller.config().max_repairs_per_minute, 50);
    }

    #[test]
    fn available_rate_tokens_initially_full() {
        let config = RepairControllerConfig {
            max_repairs_per_minute: 100,
            ..Default::default()
        };
        let controller = RepairController::new(config);
        assert_eq!(controller.available_rate_tokens(), 100);
    }

    #[test]
    fn targeted_repair_request_default() {
        let id = ObjectId::from_bytes([1; 32]);
        let request = TargetedRepairRequest::new(id);
        assert_eq!(request.object_id, id);
        assert!(request.esis.is_empty());
        assert!(request.preferred_sources.is_empty());
        assert!(request.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_repair_request_serde_roundtrip() {
        let request = TargetedRepairRequest::new(ObjectId::from_bytes([1; 32]))
            .with_esis(vec![0, 1, 2])
            .with_preferred_sources(vec![100])
            .with_excluded_sources(vec![200, 300]);

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.esis, vec![0, 1, 2]);
        assert_eq!(deserialized.preferred_sources, vec![100]);
        assert_eq!(deserialized.excluded_sources, vec![200, 300]);
    }

    #[test]
    fn clear_queue_resets_stats_depth() {
        let controller = RepairController::new(RepairControllerConfig::default());

        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });

        assert_eq!(controller.stats().queue_depth, 1);
        controller.clear_queue();
        assert_eq!(controller.stats().queue_depth, 0);
    }

    #[test]
    fn repair_controller_config_serde_roundtrip() {
        let config = RepairControllerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.max_concurrent_repairs,
            config.max_concurrent_repairs
        );
        assert_eq!(deserialized.min_deficit_bps, config.min_deficit_bps);
    }

    #[test]
    fn calculate_priority_healthy_is_zero() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let healthy = test_coverage(10, 10);
        let policy = test_policy();
        assert_eq!(controller.calculate_priority(&healthy, &policy), 0);
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
                    let node = if rng.gen_bool(0.5) { 1 } else { 3 };
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

    // ================================================================
    // Unit tests for types and controller logic (bead 3p99)
    // ================================================================

    // ---- RepairControllerConfig ----

    #[test]
    fn config_default_all_fields() {
        let c = RepairControllerConfig::default();
        assert_eq!(c.max_concurrent_repairs, 10);
        assert_eq!(c.max_repairs_per_minute, 100);
        assert_eq!(c.repair_interval, Duration::from_secs(60));
        assert_eq!(c.min_deficit_bps, 500);
        assert_eq!(c.max_symbols_per_repair, 100);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = RepairControllerConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_concurrent_repairs, 10);
        assert_eq!(back.max_repairs_per_minute, 100);
        assert_eq!(back.max_symbols_per_repair, 100);
    }

    #[test]
    fn config_debug_clone() {
        let c = RepairControllerConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("RepairControllerConfig"));
        let cloned = c.clone();
        assert_eq!(cloned.max_concurrent_repairs, c.max_concurrent_repairs);
    }

    // ---- RepairStats ----

    #[test]
    fn stats_default_all_zero() {
        let s = RepairStats::default();
        assert_eq!(s.repairs_attempted, 0);
        assert_eq!(s.repairs_succeeded, 0);
        assert_eq!(s.repairs_failed, 0);
        assert_eq!(s.symbols_added, 0);
        assert_eq!(s.queue_depth, 0);
        assert_eq!(s.rate_limited, 0);
    }

    #[test]
    fn stats_serde_roundtrip() {
        let s = RepairStats {
            repairs_attempted: 10,
            repairs_succeeded: 8,
            repairs_failed: 2,
            symbols_added: 500,
            queue_depth: 3,
            rate_limited: 1,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.repairs_attempted, 10);
        assert_eq!(back.repairs_succeeded, 8);
        assert_eq!(back.symbols_added, 500);
    }

    #[test]
    fn stats_debug_clone() {
        let s = RepairStats::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RepairStats"));
        assert_eq!(s.repairs_attempted, 0);
    }

    // ---- RepairResult ----

    #[test]
    fn repair_result_json_roundtrip() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.symbols_added, 5);
        assert!(back.error.is_none());
    }

    #[test]
    fn repair_result_with_error() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn repair_result_debug_clone() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([3; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 1,
            error: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RepairResult"));
        assert_eq!(r.symbols_added, 1);
    }

    // ---- TargetedRepairRequest ----

    #[test]
    fn targeted_repair_request_new() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([4; 32]));
        assert!(r.esis.is_empty());
        assert!(r.preferred_sources.is_empty());
        assert!(r.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_repair_request_builder() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([5; 32]))
            .with_esis(vec![1, 2, 3])
            .with_preferred_sources(vec![10, 20])
            .with_excluded_sources(vec![30]);
        assert_eq!(r.esis, vec![1, 2, 3]);
        assert_eq!(r.preferred_sources, vec![10, 20]);
        assert_eq!(r.excluded_sources, vec![30]);
    }

    #[test]
    fn targeted_repair_request_json_roundtrip() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([6; 32])).with_esis(vec![10, 20]);
        let json = serde_json::to_string(&r).unwrap();
        let back: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.esis, vec![10, 20]);
    }

    #[test]
    fn targeted_repair_request_debug_clone() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([7; 32])).with_esis(vec![42]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TargetedRepairRequest"));
        assert_eq!(r.esis, vec![42]);
    }

    // ---- RateLimiter ----

    #[test]
    fn rate_limiter_starts_full() {
        let rl = RateLimiter::new(10);
        assert_eq!(rl.available(), 10);
    }

    #[test]
    fn rate_limiter_depletes() {
        let rl = RateLimiter::new(3);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        // 4th should fail (no time for refill)
        assert!(!rl.try_acquire());
    }

    #[test]
    fn rate_limiter_zero_max() {
        let rl = RateLimiter::new(0);
        assert_eq!(rl.available(), 0);
        assert!(!rl.try_acquire());
    }

    // ---- RepairController: queue + dedup + ordering ----

    #[test]
    fn queue_repair_dedup() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let object_id = ObjectId::from_bytes([10; 32]);
        let coverage = test_coverage(5, 10);
        let policy = test_policy();

        let req = RepairRequest {
            object_id,
            zone_id: "z:test".parse().unwrap(),
            coverage,
            policy,
            priority: 100,
        };
        controller.queue_repair(req.clone());
        controller.queue_repair(req); // duplicate
        assert_eq!(controller.queue_depth(), 1);
    }

    #[test]
    fn queue_repair_priority_ordering() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let policy = test_policy();

        let low = RepairRequest {
            object_id: ObjectId::from_bytes([0xAA; 32]),
            zone_id: zone_id.clone(),
            coverage: test_coverage(9, 10),
            policy: policy.clone(),
            priority: 10,
        };
        let high = RepairRequest {
            object_id: ObjectId::from_bytes([0xBB; 32]),
            zone_id,
            coverage: test_coverage(5, 10),
            policy,
            priority: 100,
        };

        controller.queue_repair(low);
        controller.queue_repair(high);
        assert_eq!(controller.queue_depth(), 2);

        let first = controller.next_repair().unwrap();
        assert_eq!(first.priority, 100); // higher priority first
    }

    #[test]
    fn clear_queue_resets_depth() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([11; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 50,
        };
        controller.queue_repair(req);
        assert_eq!(controller.queue_depth(), 1);
        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
    }

    #[test]
    fn next_repair_returns_none_on_empty() {
        let controller = RepairController::new(RepairControllerConfig::default());
        assert!(controller.next_repair().is_none());
    }

    // ---- record_result ----

    #[test]
    fn record_result_success() {
        let controller = RepairController::new(RepairControllerConfig::default());
        controller.record_result(&RepairResult {
            object_id: ObjectId::from_bytes([12; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        });
        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 1);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.symbols_added, 5);
    }

    #[test]
    fn record_result_failure() {
        let controller = RepairController::new(RepairControllerConfig::default());
        controller.record_result(&RepairResult {
            object_id: ObjectId::from_bytes([13; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        });
        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 1);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 1);
        assert_eq!(stats.symbols_added, 0);
    }

    // ---- needs_repair / calculate_priority ----

    #[test]
    fn needs_repair_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100% coverage
        let policy = test_policy();
        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn calculate_priority_unavailable() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(5, 10); // 50% = unavailable
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        assert!(priority >= 1000); // unavailable range
    }

    #[test]
    fn calculate_priority_degraded() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Construct degraded: is_available=true but coverage below target
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([1; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 9000, // 90%, below target 100%
            is_available: true,
            total_symbols: 9,
            source_symbols: 10,
        };
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        assert!(priority >= 100);
        assert!(priority < 1000);
    }

    #[test]
    fn calculate_priority_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100%
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        assert_eq!(priority, 0);
    }

    // ---- config/stats accessors ----

    #[test]
    fn controller_config_accessor() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 5,
            ..Default::default()
        };
        let controller = RepairController::new(config);
        assert_eq!(controller.config().max_concurrent_repairs, 5);
    }

    #[test]
    fn controller_stats_initial() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.queue_depth, 0);
    }

    #[test]
    fn controller_available_rate_tokens() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 50,
            ..Default::default()
        });
        assert_eq!(controller.available_rate_tokens(), 50);
    }

    // ---- RepairPermit ----

    #[test]
    fn try_acquire_permit_succeeds() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 2,
            ..Default::default()
        });
        let p1 = controller.try_acquire_permit();
        assert!(p1.is_some());
        let p2 = controller.try_acquire_permit();
        assert!(p2.is_some());
        // 3rd should fail (max_concurrent_repairs = 2)
        let p3 = controller.try_acquire_permit();
        assert!(p3.is_none());
        // Drop one permit
        drop(p1);
        let p4 = controller.try_acquire_permit();
        assert!(p4.is_some());
    }

    // ---- RepairRequest ----

    #[test]
    fn repair_request_debug_clone() {
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([14; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 42,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("RepairRequest"));
        assert_eq!(req.priority, 42);
    }

    // ================================================================
    // Additional edge-case and coverage tests
    // ================================================================

    // ---- RepairControllerConfig additional ----

    #[test]
    fn config_custom_values_preserved() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 3,
            max_repairs_per_minute: 25,
            repair_interval: Duration::from_millis(500),
            min_deficit_bps: 1000,
            max_symbols_per_repair: 50,
        };
        assert_eq!(config.max_concurrent_repairs, 3);
        assert_eq!(config.max_repairs_per_minute, 25);
        assert_eq!(config.repair_interval, Duration::from_millis(500));
        assert_eq!(config.min_deficit_bps, 1000);
        assert_eq!(config.max_symbols_per_repair, 50);
    }

    #[test]
    fn config_serde_custom_roundtrip() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 1,
            max_repairs_per_minute: 1,
            repair_interval: Duration::from_secs(1),
            min_deficit_bps: 1,
            max_symbols_per_repair: 1,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_concurrent_repairs, 1);
        assert_eq!(back.max_repairs_per_minute, 1);
        assert_eq!(back.min_deficit_bps, 1);
        assert_eq!(back.max_symbols_per_repair, 1);
    }

    #[test]
    fn config_serde_json_contains_fields() {
        let config = RepairControllerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("max_concurrent_repairs"));
        assert!(json.contains("max_repairs_per_minute"));
        assert!(json.contains("min_deficit_bps"));
        assert!(json.contains("max_symbols_per_repair"));
        assert!(json.contains("repair_interval"));
    }

    #[test]
    fn config_clone_independence() {
        let original = RepairControllerConfig {
            max_concurrent_repairs: 7,
            ..Default::default()
        };
        let mut cloned = original.clone();
        cloned.max_concurrent_repairs = 99;
        assert_eq!(original.max_concurrent_repairs, 7);
        assert_eq!(cloned.max_concurrent_repairs, 99);
    }

    // ---- RepairStats additional ----

    #[test]
    fn stats_clone_independence() {
        let original = RepairStats {
            repairs_attempted: 5,
            repairs_succeeded: 3,
            repairs_failed: 2,
            symbols_added: 100,
            queue_depth: 1,
            rate_limited: 0,
        };
        let mut cloned = original.clone();
        cloned.repairs_attempted = 999;
        assert_eq!(original.repairs_attempted, 5);
        assert_eq!(cloned.repairs_attempted, 999);
    }

    #[test]
    fn stats_serde_all_fields_preserved() {
        let s = RepairStats {
            repairs_attempted: 42,
            repairs_succeeded: 30,
            repairs_failed: 12,
            symbols_added: 300,
            queue_depth: 7,
            rate_limited: 5,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.repairs_attempted, 42);
        assert_eq!(back.repairs_succeeded, 30);
        assert_eq!(back.repairs_failed, 12);
        assert_eq!(back.symbols_added, 300);
        assert_eq!(back.queue_depth, 7);
        assert_eq!(back.rate_limited, 5);
    }

    #[test]
    fn stats_json_contains_fields() {
        let s = RepairStats::default();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("repairs_attempted"));
        assert!(json.contains("repairs_succeeded"));
        assert!(json.contains("repairs_failed"));
        assert!(json.contains("symbols_added"));
        assert!(json.contains("queue_depth"));
        assert!(json.contains("rate_limited"));
    }

    // ---- RepairResult additional ----

    #[test]
    fn repair_result_clone_independence() {
        let original = RepairResult {
            object_id: ObjectId::from_bytes([20; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 10,
            error: None,
        };
        let cloned = original.clone();
        assert_eq!(cloned.object_id, original.object_id);
        assert_eq!(cloned.success, original.success);
        assert_eq!(cloned.new_coverage_bps, original.new_coverage_bps);
        assert_eq!(cloned.symbols_added, original.symbols_added);
        assert_eq!(cloned.error, original.error);
    }

    #[test]
    fn repair_result_serde_failure_roundtrip() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([21; 32]),
            success: false,
            new_coverage_bps: 0,
            symbols_added: 0,
            error: Some("network error: connection refused".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(!back.success);
        assert_eq!(back.new_coverage_bps, 0);
        assert_eq!(back.symbols_added, 0);
        assert_eq!(
            back.error.as_deref(),
            Some("network error: connection refused")
        );
    }

    #[test]
    fn repair_result_json_contains_fields() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([22; 32]),
            success: true,
            new_coverage_bps: 9500,
            symbols_added: 3,
            error: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("object_id"));
        assert!(json.contains("success"));
        assert!(json.contains("new_coverage_bps"));
        assert!(json.contains("symbols_added"));
        assert!(json.contains("error"));
    }

    #[test]
    fn repair_result_partial_coverage() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([23; 32]),
            success: true,
            new_coverage_bps: 7500,
            symbols_added: 2,
            error: None,
        };
        assert!(r.success);
        assert!(r.new_coverage_bps < 10000);
        assert!(r.new_coverage_bps > 0);
        assert_eq!(r.symbols_added, 2);
    }

    // ---- TargetedRepairRequest additional ----

    #[test]
    fn targeted_request_clone_independence() {
        let original =
            TargetedRepairRequest::new(ObjectId::from_bytes([30; 32])).with_esis(vec![1, 2]);
        let mut cloned = original.clone();
        cloned.esis.push(3);
        assert_eq!(original.esis.len(), 2);
        assert_eq!(cloned.esis.len(), 3);
    }

    #[test]
    fn targeted_request_empty_builder_chain() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([31; 32]))
            .with_esis(vec![])
            .with_preferred_sources(vec![])
            .with_excluded_sources(vec![]);
        assert!(r.esis.is_empty());
        assert!(r.preferred_sources.is_empty());
        assert!(r.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_request_large_esi_list() {
        let esis: Vec<u32> = (0..1000).collect();
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([32; 32])).with_esis(esis);
        assert_eq!(r.esis.len(), 1000);
        assert_eq!(r.esis[999], 999);
    }

    #[test]
    fn targeted_request_serde_with_all_fields() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([33; 32]))
            .with_esis(vec![0, 1, 2, 3])
            .with_preferred_sources(vec![100, 200, 300])
            .with_excluded_sources(vec![400, 500]);
        let json = serde_json::to_string(&r).unwrap();
        let back: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.object_id, ObjectId::from_bytes([33; 32]));
        assert_eq!(back.esis, vec![0, 1, 2, 3]);
        assert_eq!(back.preferred_sources, vec![100, 200, 300]);
        assert_eq!(back.excluded_sources, vec![400, 500]);
    }

    #[test]
    fn targeted_request_debug_contains_fields() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([34; 32]))
            .with_esis(vec![10])
            .with_preferred_sources(vec![1]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TargetedRepairRequest"));
        assert!(dbg.contains("esis"));
        assert!(dbg.contains("preferred_sources"));
        assert!(dbg.contains("excluded_sources"));
    }

    // ---- RateLimiter additional ----

    #[test]
    fn rate_limiter_single_token() {
        let rl = RateLimiter::new(1);
        assert_eq!(rl.available(), 1);
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire());
        assert_eq!(rl.available(), 0);
    }

    #[test]
    fn rate_limiter_large_capacity() {
        let rl = RateLimiter::new(10_000);
        assert_eq!(rl.available(), 10_000);
        for _ in 0..100 {
            assert!(rl.try_acquire());
        }
        assert_eq!(rl.available(), 9_900);
    }

    #[test]
    fn rate_limiter_available_after_partial_drain() {
        let rl = RateLimiter::new(5);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert_eq!(rl.available(), 3);
    }

    // ---- RepairController queue edge cases ----

    #[test]
    fn queue_depth_tracks_insertions() {
        let controller = RepairController::new(RepairControllerConfig::default());
        assert_eq!(controller.queue_depth(), 0);

        for i in 0..5_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: u32::from(i) * 10,
            });
            assert_eq!(controller.queue_depth(), (i as usize) + 1);
        }
    }

    #[test]
    fn queue_depth_tracks_removals() {
        let controller = RepairController::new(RepairControllerConfig::default());
        for i in 0..3_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }
        assert_eq!(controller.queue_depth(), 3);
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 2);
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 1);
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 0);
    }

    #[test]
    fn stats_reflects_multiple_operations() {
        let controller = RepairController::new(RepairControllerConfig::default());

        for i in 0..5_u8 {
            controller.record_result(&RepairResult {
                object_id: ObjectId::from_bytes([i; 32]),
                success: true,
                new_coverage_bps: 10000,
                symbols_added: 3,
                error: None,
            });
        }
        for i in 5..8_u8 {
            controller.record_result(&RepairResult {
                object_id: ObjectId::from_bytes([i; 32]),
                success: false,
                new_coverage_bps: 5000,
                symbols_added: 0,
                error: Some("failed".into()),
            });
        }

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 8);
        assert_eq!(stats.repairs_succeeded, 5);
        assert_eq!(stats.repairs_failed, 3);
        assert_eq!(stats.symbols_added, 15); // 5 * 3
    }

    #[test]
    fn stats_queue_depth_syncs_with_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());
        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([40; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });
        assert_eq!(controller.stats().queue_depth, 1);

        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([41; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 200,
        });
        assert_eq!(controller.stats().queue_depth, 2);

        let _ = controller.next_repair();
        assert_eq!(controller.stats().queue_depth, 1);
    }

    // ---- needs_repair edge cases ----

    #[test]
    fn needs_repair_deficit_exactly_at_threshold() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500,
            ..Default::default()
        });

        // Exactly 500 bps deficit (5%)
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9500;
        coverage.is_available = true;
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_deficit_one_below_threshold() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500,
            ..Default::default()
        });

        // 499 bps deficit (just below threshold)
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9501;
        coverage.is_available = true;
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_unavailable_always_true() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Zero coverage, unavailable
        let mut coverage = test_coverage(0, 10);
        coverage.is_available = false;
        coverage.coverage_bps = 0;
        let policy = test_policy();
        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_diversity_but_full_coverage() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Full coverage (10/10 = 10000 bps), but only 1 node when min_source_diversity = 3
        let coverage = test_coverage(10, 10);
        let mut policy = test_policy();
        policy.min_source_diversity = 3;
        // distinct_nodes = 1, min_source_diversity = 3 => diversity_deficit = 2
        assert!(controller.needs_repair(&coverage, &policy));
    }

    // ---- calculate_priority edge cases ----

    #[test]
    fn calculate_priority_unavailable_full_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Zero coverage: deficit = 10000 bps
        let mut coverage = test_coverage(0, 10);
        coverage.is_available = false;
        coverage.coverage_bps = 0;
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        // 1000 + 10000/100 = 1100
        assert_eq!(priority, 1100);
    }

    #[test]
    fn calculate_priority_degraded_diversity_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Available but degraded: 90% coverage, 1 node, min_diversity = 3
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([50; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 9000, // 10% deficit = 1000 bps
            is_available: true,
            total_symbols: 9,
            source_symbols: 10,
        };
        let mut policy = test_policy();
        policy.min_source_diversity = 3;
        let priority = controller.calculate_priority(&coverage, &policy);
        // diversity_deficit = 3 - 1 = 2
        // 200 + 2*10 + 1000/100 = 200 + 20 + 10 = 230
        assert_eq!(priority, 230);
    }

    #[test]
    fn calculate_priority_degraded_no_diversity() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Available but 80% coverage = 2000 bps deficit, no diversity requirement
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([51; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 8000,
            is_available: true,
            total_symbols: 8,
            source_symbols: 10,
        };
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        // 100 + 2000/100 = 120
        assert_eq!(priority, 120);
    }

    #[test]
    fn calculate_priority_ordering_is_correct() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let policy = test_policy();

        // Healthy
        let healthy = test_coverage(10, 10);
        let p_healthy = controller.calculate_priority(&healthy, &policy);

        // Degraded (80% coverage)
        let degraded = CoverageEvaluation {
            object_id: ObjectId::from_bytes([52; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 8000,
            is_available: true,
            total_symbols: 8,
            source_symbols: 10,
        };
        let p_degraded = controller.calculate_priority(&degraded, &policy);

        // Unavailable (50% coverage)
        let unavailable = test_coverage(5, 10);
        let p_unavailable = controller.calculate_priority(&unavailable, &policy);

        assert_eq!(p_healthy, 0);
        assert!(p_degraded > p_healthy);
        assert!(p_unavailable > p_degraded);
    }

    // ---- Queue multi-object ordering ----

    #[test]
    fn queue_three_priorities_dequeue_order() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let policy = test_policy();

        let priorities = [50_u32, 200, 100];
        for (i, &p) in priorities.iter().enumerate() {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i as u8; 32]),
                zone_id: zone_id.clone(),
                coverage: test_coverage(5, 10),
                policy: policy.clone(),
                priority: p,
            });
        }

        let first = controller.next_repair().unwrap();
        assert_eq!(first.priority, 200);
        let second = controller.next_repair().unwrap();
        assert_eq!(second.priority, 100);
        let third = controller.next_repair().unwrap();
        assert_eq!(third.priority, 50);
    }

    #[test]
    fn queue_dedup_preserves_first_inserted() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let id = ObjectId::from_bytes([60; 32]);

        let req1 = RepairRequest {
            object_id: id,
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };
        let req2 = RepairRequest {
            object_id: id,
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 999, // different priority, but same object_id
        };

        controller.queue_repair(req1);
        controller.queue_repair(req2); // should be ignored

        let dequeued = controller.next_repair().unwrap();
        assert_eq!(dequeued.priority, 100); // first one was kept
        assert!(controller.next_repair().is_none());
    }

    // ---- Controller rate limiting edge cases ----

    #[test]
    fn rate_limit_does_not_apply_to_empty_queue() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 0, // zero rate limit
            ..Default::default()
        });
        // Empty queue returns None without bumping rate_limited
        assert!(controller.next_repair().is_none());
        assert_eq!(controller.stats().rate_limited, 0);
    }

    #[test]
    fn rate_limited_bumps_stats() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 1,
            ..Default::default()
        });

        for i in 0..3_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        // First succeeds
        assert!(controller.next_repair().is_some());
        // Second fails due to rate limit
        assert!(controller.next_repair().is_none());
        assert!(controller.stats().rate_limited >= 1);
    }

    // ---- Permit edge cases ----

    #[test]
    fn permit_single_concurrent() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 1,
            ..Default::default()
        });
        let p1 = controller.try_acquire_permit();
        assert!(p1.is_some());
        assert!(controller.try_acquire_permit().is_none());
        drop(p1);
        assert!(controller.try_acquire_permit().is_some());
    }

    #[test]
    fn permit_reclaim_after_drop() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 3,
            ..Default::default()
        });
        let p1 = controller.try_acquire_permit().unwrap();
        let p2 = controller.try_acquire_permit().unwrap();
        let p3 = controller.try_acquire_permit().unwrap();
        assert!(controller.try_acquire_permit().is_none());

        // Drop one and verify one slot opens
        drop(p1);
        let p4 = controller.try_acquire_permit();
        assert!(p4.is_some());

        // Still at capacity
        assert!(controller.try_acquire_permit().is_none());

        // Drop two more to free two slots
        drop(p2);
        drop(p3);
        assert!(controller.try_acquire_permit().is_some());
    }

    // ---- Clear queue after partial drain ----

    #[test]
    fn clear_queue_after_partial_drain() {
        let controller = RepairController::new(RepairControllerConfig::default());
        for i in 0..5_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: u32::from(i) * 10,
            });
        }
        // Drain 2
        let _ = controller.next_repair();
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 3);
        // Clear remaining
        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
        assert!(controller.next_repair().is_none());
    }

    // ---- RepairRequest fields ----

    #[test]
    fn repair_request_zone_id_preserved() {
        let zone_id: ZoneId = "z:production".parse().unwrap();
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([70; 32]),
            zone_id: zone_id.clone(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 500,
        };
        assert_eq!(req.zone_id, zone_id);
        assert_eq!(req.priority, 500);
    }

    #[test]
    fn repair_request_coverage_accessible() {
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([71; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(7, 10),
            policy: test_policy(),
            priority: 100,
        };
        assert_eq!(req.coverage.total_symbols, 7);
        assert_eq!(req.coverage.source_symbols, 10);
    }

    // ---- Controller with various configs ----

    #[test]
    fn controller_zero_rate_limit_blocks_all() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 0,
            ..Default::default()
        });
        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([80; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });
        // Queue has item, but rate limiter blocks
        assert_eq!(controller.queue_depth(), 1);
        assert!(controller.next_repair().is_none());
        assert!(controller.stats().rate_limited >= 1);
    }

    #[test]
    fn controller_high_deficit_threshold_skips_minor() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 5000, // 50% deficit required
            ..Default::default()
        });
        // 80% coverage = 2000 bps deficit, below 5000 threshold
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 8000;
        coverage.is_available = true;
        let policy = test_policy();
        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn controller_low_deficit_threshold_triggers_easily() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 100, // 1% deficit is enough
            ..Default::default()
        });
        // 98% coverage = 200 bps deficit, above 100 threshold
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9800;
        coverage.is_available = true;
        let policy = test_policy();
        assert!(controller.needs_repair(&coverage, &policy));
    }

    // ---- Integration: queue + dequeue + record ----

    #[test]
    fn full_lifecycle_queue_dequeue_record() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let id = ObjectId::from_bytes([90; 32]);

        controller.queue_repair(RepairRequest {
            object_id: id,
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 500,
        });
        assert_eq!(controller.queue_depth(), 1);

        let req = controller.next_repair().unwrap();
        assert_eq!(req.object_id, id);
        assert_eq!(controller.queue_depth(), 0);

        let _permit = controller.try_acquire_permit().unwrap();

        controller.record_result(&RepairResult {
            object_id: id,
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        });

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 1);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.symbols_added, 5);
    }
}
