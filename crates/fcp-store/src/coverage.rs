//! Coverage evaluation for symbol distribution.
//!
//! Implements quantifiable offline resilience metrics from `FCP_Specification_V2.md`.

use std::collections::HashMap;

use fcp_core::ObjectId;
use serde::{Deserialize, Serialize};

/// Symbol distribution across nodes.
#[derive(Debug, Clone, Default)]
pub struct SymbolDistribution {
    /// Map of `node_id` -> (symbol count, total bytes).
    pub nodes: HashMap<u64, (u32, u64)>,
    /// Total source symbols (K).
    pub source_symbols: u32,
    /// Total symbols stored across all nodes.
    pub total_symbols: u32,
}

impl SymbolDistribution {
    /// Create a new empty distribution.
    #[must_use]
    pub fn new(source_symbols: u32) -> Self {
        Self {
            nodes: HashMap::new(),
            source_symbols,
            total_symbols: 0,
        }
    }

    /// Record a symbol stored on a node.
    pub fn add_symbol(&mut self, node_id: u64, symbol_bytes: u64) {
        let entry = self.nodes.entry(node_id).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += symbol_bytes;
        self.total_symbols += 1;
    }

    /// Remove a symbol from a node.
    pub fn remove_symbol(&mut self, node_id: u64, symbol_bytes: u64) {
        if let Some(entry) = self.nodes.get_mut(&node_id) {
            entry.0 = entry.0.saturating_sub(1);
            entry.1 = entry.1.saturating_sub(symbol_bytes);
            self.total_symbols = self.total_symbols.saturating_sub(1);
            if entry.0 == 0 {
                self.nodes.remove(&node_id);
            }
        }
    }

    /// Get the number of distinct nodes.
    #[must_use]
    pub fn distinct_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Get the maximum symbol count on any single node.
    #[must_use]
    pub fn max_node_symbols(&self) -> u32 {
        self.nodes
            .values()
            .map(|(count, _)| *count)
            .max()
            .unwrap_or(0)
    }
}

/// Symbol coverage evaluation result (NORMATIVE).
///
/// Uses fixed-point basis points for interop stability across implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEvaluation {
    /// The object being evaluated.
    pub object_id: ObjectId,
    /// Number of distinct nodes holding symbols.
    pub distinct_nodes: usize,
    /// Highest fraction of symbols on any single node (basis points, 0..=10000).
    pub max_node_fraction_bps: u16,
    /// Coverage ratio in basis points (10000 = 1.0x = exactly K symbols).
    pub coverage_bps: u32,
    /// Can object be reconstructed with current coverage?
    pub is_available: bool,
    /// Total symbols stored across all nodes.
    pub total_symbols: u32,
    /// Source symbols required (K).
    pub source_symbols: u32,
}

impl CoverageEvaluation {
    /// Evaluate coverage from a symbol distribution.
    #[must_use]
    pub fn from_distribution(object_id: ObjectId, dist: &SymbolDistribution) -> Self {
        let distinct_nodes = dist.distinct_nodes();
        let max_node_symbols = dist.max_node_symbols();

        // Calculate max node fraction in basis points
        let max_node_fraction_bps = if dist.total_symbols > 0 {
            #[allow(clippy::cast_possible_truncation)]
            let bps = (u64::from(max_node_symbols) * 10000 / u64::from(dist.total_symbols)) as u16;
            bps.min(10000)
        } else {
            0
        };

        // Calculate coverage in basis points
        // coverage_bps = (total_symbols / source_symbols) * 10000
        let coverage_bps = if dist.source_symbols > 0 {
            #[allow(clippy::cast_possible_truncation)]
            let bps =
                (u64::from(dist.total_symbols) * 10000 / u64::from(dist.source_symbols)) as u32;
            bps
        } else {
            0
        };

        // Object is available if we have at least K symbols (coverage >= 10000 bps)
        // RaptorQ actually needs K' ≈ K × 1.002, but we approximate with K
        let is_available = dist.total_symbols >= dist.source_symbols;

        Self {
            object_id,
            distinct_nodes,
            max_node_fraction_bps,
            coverage_bps,
            is_available,
            total_symbols: dist.total_symbols,
            source_symbols: dist.source_symbols,
        }
    }

    /// Check if coverage meets a placement policy's requirements.
    #[must_use]
    pub const fn meets_policy(&self, policy: &fcp_core::ObjectPlacementPolicy) -> bool {
        // Check minimum nodes
        if self.distinct_nodes < policy.min_nodes as usize {
            return false;
        }

        // Check max concentration
        if self.max_node_fraction_bps > policy.max_node_fraction_bps {
            return false;
        }

        // Check target coverage
        if self.coverage_bps < policy.target_coverage_bps {
            return false;
        }

        // Check source diversity requirement
        if policy.min_source_diversity > 0
            && self.distinct_nodes < policy.min_source_diversity as usize
        {
            return false;
        }

        true
    }

    /// Calculate deficit in basis points from target coverage.
    #[must_use]
    pub const fn coverage_deficit_bps(&self, target_bps: u32) -> u32 {
        target_bps.saturating_sub(self.coverage_bps)
    }

    /// Calculate how many additional symbols needed to reach target coverage.
    #[must_use]
    pub fn symbols_needed(&self, target_bps: u32) -> u32 {
        if self.coverage_bps >= target_bps {
            return 0;
        }

        // target_symbols = source_symbols * target_bps / 10000
        let target_symbols = u64::from(self.source_symbols) * u64::from(target_bps) / 10000;

        #[allow(clippy::cast_possible_truncation)]
        let needed = target_symbols.saturating_sub(u64::from(self.total_symbols)) as u32;
        needed
    }
}

/// Coverage health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageHealth {
    /// Coverage meets or exceeds policy targets.
    Healthy,
    /// Coverage is below target but object is still available.
    Degraded,
    /// Object cannot be reconstructed.
    Unavailable,
}

impl CoverageEvaluation {
    /// Determine health status based on policy.
    #[must_use]
    pub const fn health(&self, policy: &fcp_core::ObjectPlacementPolicy) -> CoverageHealth {
        if !self.is_available {
            CoverageHealth::Unavailable
        } else if self.meets_policy(policy) {
            CoverageHealth::Healthy
        } else {
            CoverageHealth::Degraded
        }
    }

    /// Check if source-diversity requirements are met for reconstruction.
    ///
    /// Returns `true` if the object can be reconstructed while respecting the
    /// source-diversity policy. This includes both `min_source_diversity` and
    /// `max_node_fraction_bps`. When both constraints are effectively disabled,
    /// this only checks basic availability (`is_available`).
    #[must_use]
    pub const fn meets_diversity_for_reconstruction(
        &self,
        policy: &fcp_core::ObjectPlacementPolicy,
    ) -> bool {
        if !self.is_available {
            return false;
        }
        if self.max_node_fraction_bps > policy.max_node_fraction_bps {
            return false;
        }
        if policy.min_source_diversity > 0
            && self.distinct_nodes < policy.min_source_diversity as usize
        {
            return false;
        }
        true
    }

    /// Calculate source diversity in basis points relative to the required minimum.
    ///
    /// When `min_diversity` is 0, returns 10000 (no requirement).
    #[must_use]
    pub const fn diversity_bps(&self, min_diversity: u8) -> u32 {
        if min_diversity == 0 {
            return 10_000;
        }

        let required = min_diversity as u64;
        let actual = self.distinct_nodes as u64;

        if actual >= required {
            10_000
        } else {
            #[allow(clippy::cast_possible_truncation)]
            {
                ((actual * 10_000) / required) as u32
            }
        }
    }

    /// Calculate how many additional source nodes are needed to meet diversity requirements.
    #[must_use]
    pub const fn diversity_deficit(&self, min_diversity: u8) -> u8 {
        if min_diversity == 0 || self.distinct_nodes >= min_diversity as usize {
            0
        } else {
            min_diversity - self.distinct_nodes as u8
        }
    }

    /// Calculate concentration overage in basis points above the allowed maximum.
    #[must_use]
    pub const fn concentration_deficit_bps(&self, max_concentration_bps: u16) -> u16 {
        self.max_node_fraction_bps
            .saturating_sub(max_concentration_bps)
    }

    /// Estimate how many symbols must be added from other nodes to dilute concentration.
    #[must_use]
    pub fn concentration_repair_symbols_needed(&self, max_concentration_bps: u16) -> u32 {
        if self.total_symbols == 0 || max_concentration_bps == 0 {
            return 0;
        }
        if self.max_node_fraction_bps <= max_concentration_bps {
            return 0;
        }

        // Recover the dominant source symbol count from the rounded basis-point share.
        let dominant_symbols = (u64::from(self.max_node_fraction_bps)
            .saturating_mul(u64::from(self.total_symbols))
            .saturating_add(9_999))
            / 10_000;
        let max_allowed = u64::from(max_concentration_bps);
        let numerator = dominant_symbols
            .saturating_mul(10_000)
            .saturating_sub(max_allowed.saturating_mul(u64::from(self.total_symbols)));

        #[allow(clippy::cast_possible_truncation)]
        {
            ((numerator.saturating_add(max_allowed.saturating_sub(1))) / max_allowed) as u32
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
    struct StoreLogData {
        object_id: Option<ObjectId>,
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

    fn nodes_from_distribution(dist: &SymbolDistribution) -> Vec<String> {
        let mut nodes: Vec<String> = dist.nodes.keys().map(|id| format!("node-{id}")).collect();
        nodes.sort();
        nodes
    }

    fn test_object_id() -> ObjectId {
        ObjectId::from_bytes([1_u8; 32])
    }

    #[test]
    fn empty_distribution() {
        run_store_test("empty_distribution", "verify", "placement", 3, || {
            let object_id = test_object_id();
            let dist = SymbolDistribution::new(10);
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 0);
            assert_eq!(eval.coverage_bps, 0);
            assert!(!eval.is_available);

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"distinct_nodes": eval.distinct_nodes})),
            }
        });
    }

    #[test]
    fn single_node_full_coverage() {
        run_store_test(
            "single_node_full_coverage",
            "verify",
            "placement",
            4,
            || {
                let object_id = test_object_id();
                let mut dist = SymbolDistribution::new(10);
                for _ in 0..10 {
                    dist.add_symbol(1, 100);
                }

                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                assert_eq!(eval.distinct_nodes, 1);
                assert_eq!(eval.coverage_bps, 10000);
                assert_eq!(eval.max_node_fraction_bps, 10000);
                assert!(eval.is_available);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({"max_node_fraction_bps": eval.max_node_fraction_bps})),
                }
            },
        );
    }

    #[test]
    fn distributed_coverage() {
        run_store_test("distributed_coverage", "verify", "placement", 4, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..4 {
                dist.add_symbol(1, 100);
            }
            for _ in 0..3 {
                dist.add_symbol(2, 100);
            }
            for _ in 0..3 {
                dist.add_symbol(3, 100);
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 3);
            assert_eq!(eval.coverage_bps, 10000);
            assert_eq!(eval.max_node_fraction_bps, 4000);
            assert!(eval.is_available);

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"max_node_fraction_bps": eval.max_node_fraction_bps})),
            }
        });
    }

    #[test]
    fn partial_coverage() {
        run_store_test("partial_coverage", "verify", "placement", 3, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..5 {
                dist.add_symbol(1, 100);
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 1);
            assert_eq!(eval.coverage_bps, 5000);
            assert!(!eval.is_available);

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"available": eval.is_available})),
            }
        });
    }

    #[test]
    fn overcoverage() {
        run_store_test("overcoverage", "verify", "placement", 2, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..15 {
                dist.add_symbol(1, 100);
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.coverage_bps, 15000);
            assert!(eval.is_available);

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"available": eval.is_available})),
            }
        });
    }

    #[test]
    fn meets_policy_all_requirements() {
        run_store_test(
            "meets_policy_all_requirements",
            "verify",
            "placement",
            1,
            || {
                let object_id = test_object_id();
                let mut dist = SymbolDistribution::new(10);
                for _ in 0..4 {
                    dist.add_symbol(1, 100);
                }
                for _ in 0..3 {
                    dist.add_symbol(2, 100);
                }
                for _ in 0..3 {
                    dist.add_symbol(3, 100);
                }

                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 3,
                    max_node_fraction_bps: 5000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                assert!(eval.meets_policy(&policy));

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({"meets_policy": true})),
                }
            },
        );
    }

    #[test]
    fn fails_min_nodes() {
        run_store_test("fails_min_nodes", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist.add_symbol(1, 100);
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            let policy = fcp_core::ObjectPlacementPolicy {
                min_nodes: 3,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };

            assert!(!eval.meets_policy(&policy));

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"min_nodes": policy.min_nodes})),
            }
        });
    }

    #[test]
    fn fails_max_concentration() {
        run_store_test("fails_max_concentration", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..7 {
                dist.add_symbol(1, 100);
            }
            for _ in 0..3 {
                dist.add_symbol(2, 100);
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            let policy = fcp_core::ObjectPlacementPolicy {
                min_nodes: 2,
                max_node_fraction_bps: 5000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };

            assert!(!eval.meets_policy(&policy));
            assert!(!eval.meets_diversity_for_reconstruction(&policy));
            assert_eq!(
                eval.concentration_deficit_bps(policy.max_node_fraction_bps),
                2000
            );
            assert_eq!(
                eval.concentration_repair_symbols_needed(policy.max_node_fraction_bps),
                4
            );

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(eval.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"max_node_fraction_bps": eval.max_node_fraction_bps})),
            }
        });
    }

    #[test]
    fn symbols_needed_calculation() {
        run_store_test(
            "symbols_needed_calculation",
            "verify",
            "placement",
            3,
            || {
                let object_id = test_object_id();
                let mut dist = SymbolDistribution::new(10);
                for _ in 0..5 {
                    dist.add_symbol(1, 100);
                }

                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                let need_full = eval.symbols_needed(10000);
                let need_over = eval.symbols_needed(15000);
                let need_half = eval.symbols_needed(5000);

                assert_eq!(need_full, 5);
                assert_eq!(need_over, 10);
                assert_eq!(need_half, 0);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "need_full": need_full,
                        "need_over": need_over,
                        "need_half": need_half
                    })),
                }
            },
        );
    }

    #[test]
    fn health_status() {
        run_store_test("health_status", "verify", "placement", 3, || {
            let object_id = test_object_id();
            let policy = fcp_core::ObjectPlacementPolicy {
                min_nodes: 2,
                max_node_fraction_bps: 6000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 0,
            };

            let mut dist_unavailable = SymbolDistribution::new(10);
            for _ in 0..5 {
                dist_unavailable.add_symbol(1, 100);
            }
            let eval_unavailable =
                CoverageEvaluation::from_distribution(object_id, &dist_unavailable);
            assert_eq!(
                eval_unavailable.health(&policy),
                CoverageHealth::Unavailable
            );

            let mut dist_degraded = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist_degraded.add_symbol(1, 100);
            }
            let eval_degraded = CoverageEvaluation::from_distribution(object_id, &dist_degraded);
            assert_eq!(eval_degraded.health(&policy), CoverageHealth::Degraded);

            let mut dist_healthy = SymbolDistribution::new(10);
            for _ in 0..6 {
                dist_healthy.add_symbol(1, 100);
            }
            for _ in 0..4 {
                dist_healthy.add_symbol(2, 100);
            }
            let eval_healthy = CoverageEvaluation::from_distribution(object_id, &dist_healthy);
            assert_eq!(eval_healthy.health(&policy), CoverageHealth::Healthy);

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist_healthy.total_symbols),
                coverage_bps: Some(eval_healthy.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist_healthy)),
                details: Some(json!({
                    "unavailable_bps": eval_unavailable.coverage_bps,
                    "degraded_bps": eval_degraded.coverage_bps,
                    "healthy_bps": eval_healthy.coverage_bps
                })),
            }
        });
    }

    #[test]
    fn remove_symbol() {
        run_store_test("remove_symbol", "verify", "placement", 6, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            dist.add_symbol(1, 100);
            dist.add_symbol(1, 100);
            dist.add_symbol(2, 100);

            assert_eq!(dist.distinct_nodes(), 2);
            assert_eq!(dist.total_symbols, 3);

            dist.remove_symbol(1, 100);
            assert_eq!(dist.distinct_nodes(), 2);
            assert_eq!(dist.total_symbols, 2);

            dist.remove_symbol(1, 100);
            assert_eq!(dist.distinct_nodes(), 1);
            assert_eq!(dist.total_symbols, 1);

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(
                    CoverageEvaluation::from_distribution(object_id, &dist).coverage_bps,
                ),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                details: Some(json!({"remaining_nodes": dist.distinct_nodes()})),
            }
        });
    }

    #[test]
    fn diversity_enforcement() {
        run_store_test("diversity_enforcement", "verify", "placement", 4, || {
            let object_id = test_object_id();

            // Create distribution with enough symbols but only 1 node
            let mut dist_single = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist_single.add_symbol(1, 100);
            }
            let eval_single = CoverageEvaluation::from_distribution(object_id, &dist_single);

            // Policy requiring 2 source nodes
            let policy_diversity = fcp_core::ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10000,
                min_source_diversity: 2,
            };

            // Should fail diversity check despite having enough symbols
            assert!(eval_single.is_available);
            assert!(!eval_single.meets_diversity_for_reconstruction(&policy_diversity));

            // Create distribution with 2 nodes
            let mut dist_diverse = SymbolDistribution::new(10);
            for _ in 0..5 {
                dist_diverse.add_symbol(1, 100);
            }
            for _ in 0..5 {
                dist_diverse.add_symbol(2, 100);
            }
            let eval_diverse = CoverageEvaluation::from_distribution(object_id, &dist_diverse);

            // Should pass diversity check
            assert!(eval_diverse.meets_diversity_for_reconstruction(&policy_diversity));

            StoreLogData {
                object_id: Some(object_id),
                symbol_count: Some(dist_diverse.total_symbols),
                coverage_bps: Some(eval_diverse.coverage_bps),
                nodes_holding: Some(nodes_from_distribution(&dist_diverse)),
                details: Some(json!({
                    "single_node_passes": eval_single.meets_diversity_for_reconstruction(&policy_diversity),
                    "diverse_passes": eval_diverse.meets_diversity_for_reconstruction(&policy_diversity)
                })),
            }
        });
    }

    #[test]
    fn diversity_deficit_calculation() {
        run_store_test(
            "diversity_deficit_calculation",
            "verify",
            "placement",
            4,
            || {
                let object_id = test_object_id();

                let mut dist = SymbolDistribution::new(10);
                dist.add_symbol(1, 100);
                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                // No requirement = no deficit
                assert_eq!(eval.diversity_deficit(0), 0);

                // Have 1 node, need 1 = no deficit
                assert_eq!(eval.diversity_deficit(1), 0);

                // Have 1 node, need 3 = deficit of 2
                assert_eq!(eval.diversity_deficit(3), 2);

                // Have 1 node, need 5 = deficit of 4
                assert_eq!(eval.diversity_deficit(5), 4);

                assert_eq!(eval.diversity_bps(0), 10_000);
                assert_eq!(eval.diversity_bps(2), 5_000);
                assert_eq!(eval.diversity_bps(4), 2_500);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "distinct_nodes": eval.distinct_nodes,
                        "deficit_for_3": eval.diversity_deficit(3),
                        "diversity_bps_for_4": eval.diversity_bps(4)
                    })),
                }
            },
        );
    }

    // --- Additional coverage tests ---

    #[test]
    fn zero_source_symbols_distribution() {
        run_store_test("zero_source_symbols", "verify", "placement", 3, || {
            let object_id = test_object_id();
            let dist = SymbolDistribution::new(0);
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.coverage_bps, 0);
            assert_eq!(eval.max_node_fraction_bps, 0);
            // 0 >= 0 is true: zero-source objects are trivially available
            assert!(eval.is_available);

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(0),
                details: Some(json!({"zero_source": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_evaluation_serde_roundtrip() {
        run_store_test("coverage_eval_serde", "verify", "serde", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            let json = serde_json::to_string(&eval).unwrap();
            let deserialized: CoverageEvaluation = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.coverage_bps, eval.coverage_bps);
            assert_eq!(deserialized.distinct_nodes, eval.distinct_nodes);
            assert_eq!(deserialized.is_available, eval.is_available);

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_health_serde_roundtrip() {
        run_store_test("coverage_health_serde", "verify", "serde", 3, || {
            for &health in &[
                CoverageHealth::Healthy,
                CoverageHealth::Degraded,
                CoverageHealth::Unavailable,
            ] {
                let json = serde_json::to_string(&health).unwrap();
                let deserialized: CoverageHealth = serde_json::from_str(&json).unwrap();
                assert_eq!(health, deserialized);
            }

            StoreLogData {
                details: Some(json!({"serde": "all_variants_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_health_copy_and_eq() {
        run_store_test("coverage_health_copy_eq", "verify", "traits", 2, || {
            let h1 = CoverageHealth::Healthy;
            let h2 = h1; // Copy
            assert_eq!(h1, h2);

            let h3 = CoverageHealth::Degraded;
            assert_ne!(h1, h3);

            StoreLogData {
                details: Some(json!({"copy_eq": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_deficit_at_target() {
        run_store_test("deficit_at_target", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.coverage_deficit_bps(10000), 0);

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"deficit": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_deficit_above_target() {
        run_store_test("deficit_above_target", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..15 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.coverage_deficit_bps(10000), 0);

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"overcoverage": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbols_needed_at_target() {
        run_store_test("symbols_needed_at_target", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.symbols_needed(10000), 0);

            StoreLogData {
                object_id: Some(object_id),
                details: Some(json!({"needed": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn max_node_symbols_empty() {
        run_store_test("max_node_symbols_empty", "verify", "placement", 1, || {
            let dist = SymbolDistribution::new(10);
            assert_eq!(dist.max_node_symbols(), 0);

            StoreLogData {
                details: Some(json!({"max": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn remove_symbol_nonexistent_node() {
        run_store_test(
            "remove_symbol_nonexistent_node",
            "verify",
            "placement",
            2,
            || {
                let mut dist = SymbolDistribution::new(10);
                dist.add_symbol(1, 100);

                // Remove from node that has no symbols
                dist.remove_symbol(999, 100);
                assert_eq!(dist.total_symbols, 1); // Unchanged
                assert_eq!(dist.distinct_nodes(), 1);

                StoreLogData {
                    details: Some(json!({"noop": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn symbol_distribution_default() {
        run_store_test("distribution_default", "verify", "placement", 3, || {
            let dist = SymbolDistribution::default();
            assert_eq!(dist.source_symbols, 0);
            assert_eq!(dist.total_symbols, 0);
            assert!(dist.nodes.is_empty());

            StoreLogData {
                details: Some(json!({"default": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_distribution_clone() {
        run_store_test("distribution_clone", "verify", "traits", 2, || {
            let mut dist = SymbolDistribution::new(5);
            dist.add_symbol(1, 50);
            dist.add_symbol(2, 50);

            let cloned = dist.clone();
            assert_eq!(cloned.total_symbols, dist.total_symbols);
            assert_eq!(cloned.distinct_nodes(), dist.distinct_nodes());

            StoreLogData {
                details: Some(json!({"clone": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn diversity_bps_exact_match() {
        run_store_test("diversity_bps_exact", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            dist.add_symbol(1, 100);
            dist.add_symbol(2, 100);
            dist.add_symbol(3, 100);
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            // Have 3 nodes, need 3 → 10000 bps
            assert_eq!(eval.diversity_bps(3), 10_000);

            StoreLogData {
                details: Some(json!({"diversity_bps": 10_000})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn meets_diversity_unavailable() {
        run_store_test(
            "meets_diversity_unavailable",
            "verify",
            "placement",
            1,
            || {
                let object_id = test_object_id();
                // Only 3 symbols but need 10 → unavailable
                let mut dist = SymbolDistribution::new(10);
                for _ in 0..3 {
                    dist.add_symbol(1, 100);
                }
                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                assert!(!eval.meets_diversity_for_reconstruction(&policy));

                StoreLogData {
                    details: Some(json!({"unavailable": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn coverage_evaluation_clone() {
        run_store_test("coverage_eval_clone", "verify", "traits", 2, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..5 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);
            let cloned = eval.clone();
            assert_eq!(cloned.coverage_bps, eval.coverage_bps);
            assert_eq!(cloned.is_available, eval.is_available);

            StoreLogData {
                details: Some(json!({"clone": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_deficit_below_target() {
        run_store_test("deficit_below_target", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..5 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            // 5000 bps coverage, target 10000 → deficit = 5000
            assert_eq!(eval.coverage_deficit_bps(10_000), 5000);

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"deficit": 5000})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbols_needed_zero_source() {
        run_store_test(
            "symbols_needed_zero_source",
            "verify",
            "placement",
            1,
            || {
                let object_id = test_object_id();
                let dist = SymbolDistribution::new(0);
                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                // Zero source symbols → always 0 needed
                assert_eq!(eval.symbols_needed(10_000), 0);

                StoreLogData {
                    details: Some(json!({"zero_source": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn from_distribution_many_nodes_even() {
        run_store_test("many_nodes_even", "verify", "placement", 3, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(20);
            // 4 symbols on each of 5 nodes = 20 total
            for node_id in 1..=5 {
                for _ in 0..4 {
                    dist.add_symbol(node_id, 50);
                }
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 5);
            assert_eq!(eval.max_node_fraction_bps, 2000); // 4/20 = 0.2 = 2000bps
            assert_eq!(eval.coverage_bps, 10_000);

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"nodes": 5, "even": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn meets_policy_fails_target_coverage() {
        run_store_test("fails_target_coverage", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            // Only 5 symbols → 5000 bps
            for _ in 0..5 {
                dist.add_symbol(1, 100);
            }

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            let policy = fcp_core::ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10_000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10_000,
                min_source_diversity: 0,
            };

            assert!(!eval.meets_policy(&policy));

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"fails_target": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn meets_diversity_zero_requirement() {
        run_store_test("diversity_zero_req", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            let policy = fcp_core::ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: 10_000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10_000,
                min_source_diversity: 0, // No diversity requirement
            };

            // Available + no diversity requirement → passes
            assert!(eval.meets_diversity_for_reconstruction(&policy));

            StoreLogData {
                details: Some(json!({"zero_diversity_req": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn diversity_bps_exceeds_requirement() {
        run_store_test("diversity_exceeds", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for node_id in 1..=5 {
                dist.add_symbol(node_id, 100);
                dist.add_symbol(node_id, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            // Have 5 nodes, need 3 → 10000 (capped)
            assert_eq!(eval.diversity_bps(3), 10_000);

            StoreLogData {
                details: Some(json!({"diversity_bps": 10_000})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn remove_symbol_saturating_bytes() {
        run_store_test("remove_saturating", "verify", "placement", 2, || {
            let mut dist = SymbolDistribution::new(10);
            dist.add_symbol(1, 50);

            // Remove more bytes than recorded → saturates to 0
            dist.remove_symbol(1, 200);
            assert_eq!(dist.total_symbols, 0);
            assert!(dist.nodes.is_empty()); // Node removed when count reaches 0

            StoreLogData {
                details: Some(json!({"saturating": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn add_symbol_max_node_symbols() {
        run_store_test("max_node_symbols", "verify", "placement", 2, || {
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..7 {
                dist.add_symbol(1, 100);
            }
            for _ in 0..3 {
                dist.add_symbol(2, 100);
            }

            assert_eq!(dist.max_node_symbols(), 7);
            assert_eq!(dist.total_symbols, 10);

            StoreLogData {
                details: Some(json!({"max": 7})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn coverage_evaluation_debug() {
        run_store_test("eval_debug", "verify", "traits", 1, || {
            let object_id = test_object_id();
            let dist = SymbolDistribution::new(10);
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);
            let dbg = format!("{eval:?}");
            assert!(dbg.contains("CoverageEvaluation"));

            StoreLogData {
                details: Some(json!({"debug": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_distribution_debug() {
        run_store_test("dist_debug", "verify", "traits", 1, || {
            let dist = SymbolDistribution::new(5);
            let dbg = format!("{dist:?}");
            assert!(dbg.contains("SymbolDistribution"));

            StoreLogData {
                details: Some(json!({"debug": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn from_distribution_single_symbol() {
        run_store_test("single_symbol", "verify", "placement", 3, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            dist.add_symbol(1, 100);

            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            assert_eq!(eval.distinct_nodes, 1);
            assert_eq!(eval.coverage_bps, 1000); // 1/10 = 10%
            assert_eq!(eval.max_node_fraction_bps, 10_000); // 1/1 = 100%

            StoreLogData {
                object_id: Some(object_id),
                coverage_bps: Some(eval.coverage_bps),
                details: Some(json!({"single_symbol": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn health_degraded_min_nodes_not_met() {
        run_store_test("health_degraded_nodes", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            for _ in 0..10 {
                dist.add_symbol(1, 100);
            }
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            let policy = fcp_core::ObjectPlacementPolicy {
                min_nodes: 3,
                max_node_fraction_bps: 10_000,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 10_000,
                min_source_diversity: 0,
            };

            // Available but doesn't meet min_nodes → Degraded
            assert_eq!(eval.health(&policy), CoverageHealth::Degraded);

            StoreLogData {
                details: Some(json!({"health": "degraded"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn diversity_deficit_exact_match() {
        run_store_test("diversity_deficit_exact", "verify", "placement", 1, || {
            let object_id = test_object_id();
            let mut dist = SymbolDistribution::new(10);
            dist.add_symbol(1, 100);
            dist.add_symbol(2, 100);
            dist.add_symbol(3, 100);
            let eval = CoverageEvaluation::from_distribution(object_id, &dist);

            // Have 3, need 3 → deficit 0
            assert_eq!(eval.diversity_deficit(3), 0);

            StoreLogData {
                details: Some(json!({"deficit": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn add_remove_cycle() {
        run_store_test("add_remove_cycle", "verify", "placement", 3, || {
            let mut dist = SymbolDistribution::new(10);

            dist.add_symbol(1, 100);
            dist.add_symbol(1, 100);
            assert_eq!(dist.total_symbols, 2);

            dist.remove_symbol(1, 100);
            assert_eq!(dist.total_symbols, 1);

            dist.remove_symbol(1, 100);
            assert_eq!(dist.total_symbols, 0);
            assert!(dist.nodes.is_empty());

            StoreLogData {
                details: Some(json!({"cycle": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn min_source_diversity_in_policy() {
        run_store_test(
            "min_source_diversity_in_policy",
            "verify",
            "placement",
            2,
            || {
                let object_id = test_object_id();

                // Distribution with 2 nodes, meeting min_nodes but not min_source_diversity
                let mut dist = SymbolDistribution::new(10);
                for _ in 0..5 {
                    dist.add_symbol(1, 100);
                }
                for _ in 0..5 {
                    dist.add_symbol(2, 100);
                }
                let eval = CoverageEvaluation::from_distribution(object_id, &dist);

                // Policy: min_nodes=2, min_source_diversity=3
                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 2,
                    max_node_fraction_bps: 6000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 3,
                };

                // Should fail meets_policy because of min_source_diversity
                assert!(!eval.meets_policy(&policy));

                // Same policy but with min_source_diversity=2
                let policy_met = fcp_core::ObjectPlacementPolicy {
                    min_source_diversity: 2,
                    ..policy
                };
                assert!(eval.meets_policy(&policy_met));

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "distinct_nodes": eval.distinct_nodes,
                        "policy_met": eval.meets_policy(&policy_met)
                    })),
                }
            },
        );
    }

    // --- SymbolDistribution additional tests ---

    #[test]
    fn symbol_distribution_default_empty() {
        let dist = SymbolDistribution::default();
        assert_eq!(dist.source_symbols, 0);
        assert_eq!(dist.total_symbols, 0);
        assert!(dist.nodes.is_empty());
        assert_eq!(dist.distinct_nodes(), 0);
        assert_eq!(dist.max_node_symbols(), 0);
    }

    #[test]
    fn symbol_distribution_clone_preserves_fields() {
        let mut dist = SymbolDistribution::new(8);
        dist.add_symbol(1, 100);
        dist.add_symbol(2, 200);
        let cloned = dist.clone();
        assert_eq!(dist.source_symbols, cloned.source_symbols);
        assert_eq!(dist.total_symbols, cloned.total_symbols);
        assert_eq!(dist.distinct_nodes(), cloned.distinct_nodes());
    }

    #[test]
    fn symbol_distribution_debug_format() {
        let dist = SymbolDistribution::new(5);
        let dbg = format!("{dist:?}");
        assert!(dbg.contains("SymbolDistribution"));
        assert!(dbg.contains("source_symbols"));
    }

    #[test]
    fn symbol_distribution_remove_nonexistent_node() {
        let mut dist = SymbolDistribution::new(10);
        dist.add_symbol(1, 100);
        // Removing from a node that doesn't exist should be a no-op
        dist.remove_symbol(99, 100);
        assert_eq!(dist.total_symbols, 1);
        assert_eq!(dist.distinct_nodes(), 1);
    }

    #[test]
    fn symbol_distribution_remove_last_symbol_removes_node() {
        let mut dist = SymbolDistribution::new(10);
        dist.add_symbol(1, 100);
        dist.add_symbol(2, 100);
        assert_eq!(dist.distinct_nodes(), 2);

        dist.remove_symbol(1, 100);
        assert_eq!(dist.distinct_nodes(), 1);
        assert!(!dist.nodes.contains_key(&1));
    }

    #[test]
    fn symbol_distribution_saturating_sub_on_remove() {
        let mut dist = SymbolDistribution::new(10);
        dist.add_symbol(1, 100);
        // Remove more bytes than added — should saturate to 0
        dist.remove_symbol(1, 999);
        assert_eq!(dist.total_symbols, 0);
        assert_eq!(dist.distinct_nodes(), 0);
    }

    #[test]
    fn symbol_distribution_max_node_symbols_multiple_nodes() {
        let mut dist = SymbolDistribution::new(20);
        for _ in 0..5 {
            dist.add_symbol(1, 50);
        }
        for _ in 0..8 {
            dist.add_symbol(2, 50);
        }
        for _ in 0..3 {
            dist.add_symbol(3, 50);
        }
        assert_eq!(dist.max_node_symbols(), 8);
    }

    // --- CoverageEvaluation additional tests ---

    #[test]
    fn coverage_evaluation_debug_format() {
        let dist = SymbolDistribution::new(10);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        let dbg = format!("{eval:?}");
        assert!(dbg.contains("CoverageEvaluation"));
        assert!(dbg.contains("coverage_bps"));
    }

    #[test]
    fn coverage_evaluation_clone_preserves_fields() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..6 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        let cloned = eval.clone();
        assert_eq!(eval.coverage_bps, cloned.coverage_bps);
        assert_eq!(eval.distinct_nodes, cloned.distinct_nodes);
        assert_eq!(eval.is_available, cloned.is_available);
    }

    #[test]
    fn coverage_evaluation_serde_json_roundtrip() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        let json = serde_json::to_string(&eval).unwrap();
        let rt: CoverageEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.coverage_bps, eval.coverage_bps);
        assert_eq!(rt.distinct_nodes, eval.distinct_nodes);
        assert_eq!(rt.is_available, eval.is_available);
        assert_eq!(rt.total_symbols, eval.total_symbols);
        assert_eq!(rt.source_symbols, eval.source_symbols);
    }

    #[test]
    fn coverage_evaluation_zero_source_symbols() {
        let dist = SymbolDistribution::new(0);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.coverage_bps, 0);
        assert!(eval.is_available); // 0 >= 0
    }

    #[test]
    fn coverage_deficit_bps_at_target() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.coverage_deficit_bps(10_000), 0);
    }

    #[test]
    fn coverage_deficit_bps_below_target() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.coverage_deficit_bps(10_000), 5_000);
    }

    #[test]
    fn symbols_needed_zero_source_symbols() {
        let dist = SymbolDistribution::new(0);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.symbols_needed(10_000), 0);
    }

    #[test]
    fn symbols_needed_already_met() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.symbols_needed(10_000), 0);
    }

    // --- CoverageHealth tests ---

    #[test]
    fn coverage_health_debug() {
        let h = CoverageHealth::Healthy;
        let dbg = format!("{h:?}");
        assert!(dbg.contains("Healthy"));
    }

    #[test]
    fn coverage_health_clone_and_eq() {
        let h1 = CoverageHealth::Degraded;
        let h2 = h1;
        assert_eq!(h1, h2);
    }

    #[test]
    fn coverage_health_serde_all_variants() {
        for variant in [
            CoverageHealth::Healthy,
            CoverageHealth::Degraded,
            CoverageHealth::Unavailable,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let rt: CoverageHealth = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, variant);
        }
    }

    #[test]
    fn concentration_repair_symbols_zero_total() {
        let dist = SymbolDistribution::new(10);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.concentration_repair_symbols_needed(5000), 0);
    }

    #[test]
    fn concentration_repair_symbols_zero_max_concentration() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.concentration_repair_symbols_needed(0), 0);
    }

    #[test]
    fn concentration_repair_symbols_already_ok() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..5 {
            dist.add_symbol(2, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        // max_node_fraction_bps = 5000, within limit
        assert_eq!(eval.concentration_repair_symbols_needed(5000), 0);
    }

    #[test]
    fn diversity_bps_zero_requirement() {
        let dist = SymbolDistribution::new(10);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.diversity_bps(0), 10_000);
    }

    #[test]
    fn diversity_bps_above_requirement() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..5 {
            dist.add_symbol(2, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.diversity_bps(2), 10_000);
    }

    #[test]
    fn diversity_bps_below_requirement() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        // 1 node, need 4 → 1*10000/4 = 2500
        assert_eq!(eval.diversity_bps(4), 2_500);
    }

    #[test]
    fn diversity_deficit_zero_requirement() {
        let dist = SymbolDistribution::new(10);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.diversity_deficit(0), 0);
    }

    #[test]
    fn diversity_deficit_met() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..5 {
            dist.add_symbol(1, 100);
        }
        for _ in 0..5 {
            dist.add_symbol(2, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.diversity_deficit(2), 0);
    }

    #[test]
    fn diversity_deficit_not_met() {
        let mut dist = SymbolDistribution::new(10);
        for _ in 0..10 {
            dist.add_symbol(1, 100);
        }
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        assert_eq!(eval.diversity_deficit(3), 2);
    }

    #[test]
    fn meets_diversity_for_reconstruction_not_available() {
        let dist = SymbolDistribution::new(10);
        let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);
        let policy = fcp_core::ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10_000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10_000,
            min_source_diversity: 0,
        };
        assert!(!eval.meets_diversity_for_reconstruction(&policy));
    }
}
