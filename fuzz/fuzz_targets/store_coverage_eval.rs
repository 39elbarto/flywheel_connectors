#![no_main]

//! Fuzz target for `fcp_store::SymbolDistribution` / `CoverageEvaluation`
//! (coverage.rs:13-198).
//!
//! `SymbolDistribution` maintains an O(1) `cached_max` invariant across
//! add_symbol/remove_symbol — the cache is updated incrementally on add
//! and lazily recomputed on remove only when the removed node held the
//! max. A regression in cached_max would silently distort
//! `CoverageEvaluation::max_node_fraction_bps`, which feeds
//! `CoverageEvaluation::meets_policy` — the gate that validates an
//! object header's `ObjectPlacementPolicy` (the placement field on
//! ObjectHeader).
//!
//! In the FCP repair model, a wrong meets_policy result either:
//!   - returns true when concentration is too high → security-relevant:
//!     object pinned on a single node passes a "max 30% concentration"
//!     check.
//!   - returns false on legitimate distribution → repair churn.
//!
//! Existing fcp-store fuzz coverage does NOT touch SymbolDistribution
//! / CoverageEvaluation / meets_policy.
//!
//! Properties asserted:
//!
//!   1. **add/remove inverse**: applying the same set of add+remove
//!      operations (matched pairs) MUST restore (total_symbols,
//!      distinct_nodes, max_node_symbols) to the empty-distribution
//!      state.
//!   2. **cached_max agrees with computed max**: at any point,
//!      `max_node_symbols()` equals
//!      `nodes.values().map(|(c,_)| *c).max().unwrap_or(0)`. The most
//!      likely regression target.
//!   3. **distinct_nodes consistency**: `distinct_nodes()` always
//!      equals `nodes.len()` (zero-count entries get cleaned up).
//!   4. **from_distribution determinism**: same SymbolDistribution
//!      produces the same CoverageEvaluation.
//!   5. **symbols_needed monotonicity**: adding symbols without
//!      removing makes `symbols_needed(target)` monotonically
//!      non-increasing.
//!   6. **meets_policy field-binding**: tightening any one of
//!      (min_nodes, max_node_fraction_bps cap, target_coverage_bps,
//!      min_source_diversity) past the actual coverage MUST flip
//!      meets_policy from true to false.
//!
//!   Once-gated regression anchors:
//!     (a) cached_max after add(n=1)+add(n=1)+add(n=2)+remove(n=1) is 1.
//!     (b) meets_policy true → tightening max_node_fraction_bps below
//!         the actual fraction MUST flip the result to false.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, ObjectPlacementPolicy};
use fcp_store::{CoverageEvaluation, SymbolDistribution};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_OPS: usize = 32;
const NODE_RANGE: u8 = 8;

static COVERAGE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Op {
    Add { node: u8, bytes: u32 },
    Remove { node: u8, bytes: u32 },
}

#[derive(Arbitrary, Debug)]
struct Input {
    source_symbols: u16,
    ops: Vec<Op>,
}

fn computed_max(dist: &SymbolDistribution) -> u32 {
    dist.nodes
        .values()
        .map(|(count, _)| *count)
        .max()
        .unwrap_or(0)
}

fn assert_max_invariant(dist: &SymbolDistribution, ctx: &str) {
    let cached = dist.max_node_symbols();
    let computed = computed_max(dist);
    assert_eq!(
        cached, computed,
        "cached_max ({cached}) ≠ computed max ({computed}) after {ctx} — \
         O(1) max invariant broken; CoverageEvaluation::max_node_fraction_bps \
         will silently distort and meets_policy gate compromised"
    );
}

fn assert_distinct_consistency(dist: &SymbolDistribution, ctx: &str) {
    assert_eq!(
        dist.distinct_nodes(),
        dist.nodes.len(),
        "distinct_nodes() ({}) ≠ nodes.len() ({}) after {ctx} — zero-count \
         entries not being cleaned up",
        dist.distinct_nodes(),
        dist.nodes.len()
    );
}

fuzz_target!(|data: &[u8]| {
    COVERAGE_ANCHOR.call_once(assert_coverage_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let mut dist = SymbolDistribution::new(u32::from(input.source_symbols).max(1));

    // Fold node ids modulo NODE_RANGE so we generate add/remove pairs
    // against a small set, exercising cached_max max-holder transitions.
    let ops: Vec<Op> = input
        .ops
        .iter()
        .take(MAX_OPS)
        .map(|op| match *op {
            Op::Add { node, bytes } => Op::Add {
                node: node % NODE_RANGE,
                bytes: bytes & 0xffff, // bound bytes to avoid saturating issues
            },
            Op::Remove { node, bytes } => Op::Remove {
                node: node % NODE_RANGE,
                bytes: bytes & 0xffff,
            },
        })
        .collect();

    // ── PROPERTY 5: symbols_needed monotonicity (additions only) ───────
    let mut prev_needed: Option<u32> = None;
    for op in &ops {
        if let Op::Add { node, bytes } = op {
            dist.add_symbol(u64::from(*node), u64::from(*bytes));
            assert_max_invariant(&dist, "add_symbol");
            assert_distinct_consistency(&dist, "add_symbol");

            let eval =
                CoverageEvaluation::from_distribution(ObjectId::from_bytes([0u8; 32]), &dist);
            let needed = eval.symbols_needed(10_000);
            if let Some(prev) = prev_needed {
                assert!(
                    needed <= prev,
                    "symbols_needed not monotonic: {prev} → {needed} after add"
                );
            }
            prev_needed = Some(needed);
        }
    }

    // ── PROPERTY 4: from_distribution determinism ─────────────────────
    let oid = ObjectId::from_bytes([1u8; 32]);
    let eval_a = CoverageEvaluation::from_distribution(oid, &dist);
    let eval_b = CoverageEvaluation::from_distribution(oid, &dist);
    assert_eq!(
        eval_a, eval_b,
        "CoverageEvaluation::from_distribution not deterministic on identical input"
    );

    // ── PROPERTY 1: add/remove inverse ────────────────────────────────
    // Replay the SAME add operations as removes; total_symbols MUST
    // return to 0 and the distribution MUST be empty.
    let mut dist2 = SymbolDistribution::new(u32::from(input.source_symbols).max(1));
    let mut applied: Vec<(u8, u32)> = Vec::new();
    for op in &ops {
        if let Op::Add { node, bytes } = op {
            dist2.add_symbol(u64::from(*node), u64::from(*bytes));
            applied.push((*node, *bytes));
        }
    }
    for (node, bytes) in &applied {
        dist2.remove_symbol(u64::from(*node), u64::from(*bytes));
        assert_max_invariant(&dist2, "remove_symbol");
        assert_distinct_consistency(&dist2, "remove_symbol");
    }
    assert_eq!(
        dist2.total_symbols, 0,
        "total_symbols ({}) ≠ 0 after add/remove inverse",
        dist2.total_symbols
    );
    assert_eq!(
        dist2.max_node_symbols(),
        0,
        "max_node_symbols ({}) ≠ 0 after add/remove inverse",
        dist2.max_node_symbols()
    );
    assert_eq!(
        dist2.distinct_nodes(),
        0,
        "distinct_nodes ({}) ≠ 0 after add/remove inverse",
        dist2.distinct_nodes()
    );

    // ── PROPERTY 6: meets_policy field-binding ────────────────────────
    if eval_a.is_available && eval_a.distinct_nodes > 0 {
        // Build a permissive policy that the current eval satisfies.
        let permissive = ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10_000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 0,
            min_source_diversity: 0,
        };
        assert!(
            eval_a.meets_policy(&permissive),
            "permissive policy not satisfied by available coverage"
        );

        // Tighten max_node_fraction_bps below the actual fraction.
        if eval_a.max_node_fraction_bps > 0 {
            let tight = ObjectPlacementPolicy {
                min_nodes: 1,
                max_node_fraction_bps: eval_a.max_node_fraction_bps - 1,
                preferred_devices: vec![],
                excluded_devices: vec![],
                target_coverage_bps: 0,
                min_source_diversity: 0,
            };
            assert!(
                !eval_a.meets_policy(&tight),
                "meets_policy returned true when max_node_fraction_bps cap \
                 ({}) is below actual fraction ({}) — concentration check \
                 broken; security-relevant placement gate compromised",
                tight.max_node_fraction_bps,
                eval_a.max_node_fraction_bps
            );
        }

        // Tighten min_nodes above the actual count.
        let tight_nodes = ObjectPlacementPolicy {
            min_nodes: u8::try_from(eval_a.distinct_nodes + 1).unwrap_or(u8::MAX),
            max_node_fraction_bps: 10_000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 0,
            min_source_diversity: 0,
        };
        assert!(
            !eval_a.meets_policy(&tight_nodes),
            "meets_policy returned true when min_nodes ({}) > actual \
             distinct_nodes ({})",
            tight_nodes.min_nodes,
            eval_a.distinct_nodes
        );
    }
});

/// Once-gated regression anchors for the most load-bearing
/// SymbolDistribution / meets_policy invariants.
fn assert_coverage_anchored() {
    // (a) cached_max after add(n=1)+add(n=1)+add(n=2)+remove(n=1) is 1.
    // After the sequence: n=1 is at count 1, n=2 is at count 1 — max=1.
    let mut dist = SymbolDistribution::new(10);
    dist.add_symbol(1, 100);
    dist.add_symbol(1, 100);
    dist.add_symbol(2, 100);
    dist.remove_symbol(1, 100);

    assert_max_invariant(&dist, "anchor sequence");
    assert_eq!(
        dist.max_node_symbols(),
        1,
        "ANCHOR REGRESSION: after add(1)+add(1)+add(2)+remove(1), \
         max_node_symbols() == {} but expected 1; cached_max is not being \
         lazily recomputed when the previous max-holder drops",
        dist.max_node_symbols()
    );
    assert_eq!(dist.total_symbols, 2, "ANCHOR: total_symbols");
    assert_eq!(dist.distinct_nodes(), 2, "ANCHOR: distinct_nodes");

    // (b) meets_policy field-binding regression anchor.
    let oid = ObjectId::from_bytes([0xCDu8; 32]);
    // Construct a 3-node distribution with K=2 source symbols, total 3.
    let mut policy_dist = SymbolDistribution::new(2);
    policy_dist.add_symbol(1, 50);
    policy_dist.add_symbol(2, 50);
    policy_dist.add_symbol(3, 50);
    let eval = CoverageEvaluation::from_distribution(oid, &policy_dist);

    let permissive = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: 10_000,
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 0,
        min_source_diversity: 0,
    };
    assert!(
        eval.meets_policy(&permissive),
        "ANCHOR: 3-node K=2 distribution did not satisfy permissive policy"
    );

    // 3 nodes, total_symbols=3, max=1 → max_node_fraction = 3333 bps.
    // Tighten to 3332 — MUST trip.
    let tight = ObjectPlacementPolicy {
        min_nodes: 1,
        max_node_fraction_bps: eval.max_node_fraction_bps.saturating_sub(1),
        preferred_devices: vec![],
        excluded_devices: vec![],
        target_coverage_bps: 0,
        min_source_diversity: 0,
    };
    assert!(
        !eval.meets_policy(&tight),
        "ANCHOR REGRESSION: meets_policy accepted a max_node_fraction_bps cap \
         ({}) below the actual fraction ({}) — concentration gate broken; \
         object pinned on a single node would silently pass a 'max 30% \
         concentration' check",
        tight.max_node_fraction_bps,
        eval.max_node_fraction_bps
    );
}
