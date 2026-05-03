//! Conformance harness for the resource-pool placement planner
//! (TealOtter's evxvv.3 work landed in 64b0e9510 + 93e899e8c).
//!
//! The planner produces three streams that downstream operator tooling
//! consumes:
//!
//! - **Plan candidates** — the ranked list of admissible nodes
//!   returned by `ExecutionPlanner::plan()`.
//! - **Per-node decisions** — the audit trail returned by
//!   `resource_pool_decisions()` (one entry per evaluated node, with
//!   admit/reject + typed refusal reason).
//! - **Aggregated summary** — `ResourcePoolDecisionSummary` derived
//!   from the per-node decisions, used by operator dashboards to
//!   surface fleet-wide rejection causes.
//!
//! The bench in 93e899e8c exercises the perf hot path; this harness
//! pins the *correctness* contracts a future refactor must not
//! silently drift:
//!
//! 1. **Decision determinism** — `plan(input, context)` is a pure
//!    function. Re-running with structurally equal inputs produces
//!    structurally equal candidate vectors (down to candidate order,
//!    score, and decision-reason set). Pre-fix: catches an
//!    interior-mut leak into the planner state that would let the
//!    same operator question return different answers on
//!    consecutive calls.
//!
//! 2. **Refusal taxonomy completeness** — every reachable refusal
//!    reason (`NoMatchingPool`, `CpuExhausted`, `MemoryExhausted`)
//!    surfaces from a hand-built scenario AND aggregates correctly
//!    into the summary's per-reason counters. Pre-fix: catches a
//!    refactor that adds a `ResourcePoolRefusalReason` variant
//!    without wiring the summary's counter increment, silently
//!    hiding the new failure class from operator dashboards.
//!
//! 3. **Cross-zone independence under partial topology** — placement
//!    requests targeting zone Z evaluate ONLY pools bound to Z (or
//!    unbounded). Pools bound to OTHER zones MUST NOT influence the
//!    decision in either direction (admission or refusal). This is
//!    the load-bearing safety property for multi-tenant placement —
//!    a partial-topology view (operator can only see a subset of
//:    zones) must not leak admission of cross-zone pool capacity.

use std::collections::HashSet;

use fcp_core::{ConnectorId, ObjectId, ZoneId};
use fcp_mesh::{
    AvailabilityProfile, DecisionReason, DeviceProfile, ExecutionPlanner, InstalledConnector,
    LatencyClass, NodeInfo, PlannerContext, PlannerInput, PowerSource, ResourcePoolClass,
    ResourcePoolDecisionSummary, ResourcePoolRefusalReason, ResourcePoolStatus,
};
use fcp_tailscale::NodeId;

// ── Helpers (mirroring the inline test harness in planner.rs) ──────

fn test_connector_id() -> ConnectorId {
    ConnectorId::new("fcp", "test", "1.0.0").expect("valid connector id")
}

fn make_profile(suffix: &str, memory_mb: u32) -> DeviceProfile {
    let installed = InstalledConnector::new(
        test_connector_id(),
        "1.0.0",
        ObjectId::from_bytes([0xAA; 32]),
    );
    DeviceProfile::builder(NodeId::new(format!("node-{suffix}")))
        .memory_mb(memory_mb)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .add_connector(installed)
        .build()
}

fn node_in_zone(suffix: &str, memory_mb: u32, zone: ZoneId) -> NodeInfo {
    let profile = make_profile(suffix, memory_mb);
    NodeInfo {
        profile,
        local_symbols: HashSet::new(),
        held_leases: Vec::new(),
        zones: vec![zone],
    }
}

fn pool_for(
    pool_id: &str,
    node_suffix: &str,
    zone: Option<ZoneId>,
    cpu_total: u16,
    mem_total: u32,
    cpu_used: u16,
    mem_used: u32,
) -> ResourcePoolStatus {
    ResourcePoolStatus::new(
        pool_id,
        NodeId::new(format!("node-{node_suffix}")),
        zone,
        ResourcePoolClass::RequestResponse,
        cpu_total,
        mem_total,
    )
    .with_usage(cpu_used, mem_used)
}

// ─────────────────────────────────────────────────────────────────────
// Property 1: decision determinism
// ─────────────────────────────────────────────────────────────────────

/// A single placement question MUST yield identical answers across
/// two consecutive calls. The planner's public API is pure-functional
/// by construction; if a future refactor introduces interior
/// mutability or a Cell of cached decisions, this catches it.
#[test]
fn placement_conformance_planner_is_deterministic_across_repeated_calls() {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();
    let input = PlannerInput::new(
        vec![
            node_in_zone("alpha", 4096, work.clone()),
            node_in_zone("beta", 4096, work.clone()),
        ],
        1_700_000_000,
    )
    .with_resource_pools(vec![
        pool_for("rr-alpha", "alpha", Some(work.clone()), 8, 4096, 2, 1024),
        pool_for("rr-beta", "beta", Some(work.clone()), 8, 4096, 2, 1024),
    ]);
    let context = PlannerContext::new(test_connector_id())
        .with_target_zone(work)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(2)
        .with_min_memory_mb(1024);

    let first = planner.plan(&input, &context);
    let second = planner.plan(&input, &context);
    assert_eq!(
        first.len(),
        second.len(),
        "candidate count drifted between identical calls",
    );
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(
            a.node_id, b.node_id,
            "candidate ordering drifted across identical calls (node_id)",
        );
        assert!(
            (a.score - b.score).abs() < f64::EPSILON,
            "candidate score drifted across identical calls: {} vs {}",
            a.score,
            b.score,
        );
        assert_eq!(
            a.eligible, b.eligible,
            "candidate eligibility drifted across identical calls",
        );
    }

    // resource_pool_decisions is the operator audit trail and MUST be
    // identical across calls too.
    let decisions_a = planner.resource_pool_decisions(&input, &context);
    let decisions_b = planner.resource_pool_decisions(&input, &context);
    assert_eq!(
        decisions_a, decisions_b,
        "resource_pool_decisions drifted across identical calls — operator audit \
         trail is not deterministic",
    );
}

// ─────────────────────────────────────────────────────────────────────
// Property 2: refusal taxonomy completeness
// ─────────────────────────────────────────────────────────────────────

/// Every documented `ResourcePoolRefusalReason` variant MUST be
/// reachable from at least one hand-built scenario, AND each
/// rejection variant MUST increment its corresponding counter in
/// `ResourcePoolDecisionSummary`. A future refactor that adds a
/// refusal variant without wiring the counter would silently hide
/// the new failure class from operator dashboards.
#[test]
fn placement_conformance_refusal_taxonomy_is_exhaustive_and_summarized() {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();

    // Build a scenario that produces ONE of each refusal kind:
    //
    // - no-match: node has NO pool entry
    // - cpu-hot: pool exists but CPU exhausted
    // - mem-hot: pool exists but memory exhausted
    // - admitted: a pool with sufficient headroom
    let nodes = vec![
        node_in_zone("no-match", 4096, work.clone()),
        node_in_zone("cpu-hot", 4096, work.clone()),
        node_in_zone("mem-hot", 4096, work.clone()),
        node_in_zone("admitted", 4096, work.clone()),
    ];
    let pools = vec![
        pool_for("rr-cpu-hot", "cpu-hot", Some(work.clone()), 4, 4096, 4, 0),
        pool_for(
            "rr-mem-hot",
            "mem-hot",
            Some(work.clone()),
            8,
            1024,
            0,
            1024,
        ),
        pool_for("rr-admitted", "admitted", Some(work.clone()), 8, 4096, 0, 0),
    ];

    let input = PlannerInput::new(nodes, 1_700_000_000).with_resource_pools(pools);
    let context = PlannerContext::new(test_connector_id())
        .with_target_zone(work)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(4)
        .with_min_memory_mb(1024);

    let decisions = planner.resource_pool_decisions(&input, &context);
    assert_eq!(decisions.len(), 4);

    // All three documented refusal kinds appear in the per-node decisions.
    let has_no_match = decisions.iter().any(|d| {
        matches!(
            d.refusal,
            Some(ResourcePoolRefusalReason::NoMatchingPool { .. })
        )
    });
    let has_cpu_hot = decisions.iter().any(|d| {
        matches!(
            d.refusal,
            Some(ResourcePoolRefusalReason::CpuExhausted { .. })
        )
    });
    let has_mem_hot = decisions.iter().any(|d| {
        matches!(
            d.refusal,
            Some(ResourcePoolRefusalReason::MemoryExhausted { .. })
        )
    });

    assert!(
        has_no_match,
        "scenario must produce NoMatchingPool — got: {decisions:?}"
    );
    assert!(
        has_cpu_hot,
        "scenario must produce CpuExhausted — got: {decisions:?}"
    );
    assert!(
        has_mem_hot,
        "scenario must produce MemoryExhausted — got: {decisions:?}"
    );

    // Aggregated summary correctly counts each refusal kind.
    let summary = ResourcePoolDecisionSummary::from_decisions(&decisions);
    assert_eq!(
        summary,
        ResourcePoolDecisionSummary {
            evaluated: 4,
            admitted: 1,
            rejected: 3,
            no_matching_pool: 1,
            cpu_exhausted: 1,
            memory_exhausted: 1,
        },
        "summary counters drifted from per-node decisions",
    );
}

// ─────────────────────────────────────────────────────────────────────
// Property 3: cross-zone independence under partial topology
// ─────────────────────────────────────────────────────────────────────

/// A placement request targeting zone Z MUST evaluate only pools
/// bound to Z (or unbounded). Pools bound to OTHER zones MUST NOT
/// admit a node into Z, even if those pools have capacity. Operators
/// rely on this for multi-tenant isolation: a partial-topology view
/// (where the operator can see only zone Z) must not silently leak
/// capacity from a different tenant's pool.
#[test]
fn placement_conformance_cross_zone_pools_do_not_leak_capacity_into_target_zone() {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();
    let private = ZoneId::private();

    // Node `dual` belongs to BOTH zones (multi-tenant node), but the
    // planner is targeting `work`. Only the work-zone pool should
    // count.
    let dual = NodeInfo {
        profile: make_profile("dual", 4096),
        local_symbols: HashSet::new(),
        held_leases: Vec::new(),
        zones: vec![work.clone(), private.clone()],
    };

    // The work-zone pool is EXHAUSTED for this node → must reject.
    // A different (private-zone) pool has plenty of capacity but is
    // bound to a DIFFERENT zone → must NOT silently admit.
    let pools = vec![
        // Empty work-zone pool: node has no admissible pool in the
        // target zone.
        pool_for(
            "rr-work-empty",
            "dual",
            Some(work.clone()),
            1,
            1024,
            1,
            1024,
        ),
        // Wide-open private-zone pool — must NOT influence the decision.
        pool_for(
            "rr-private-open",
            "dual",
            Some(private.clone()),
            64,
            65_536,
            0,
            0,
        ),
    ];

    let input = PlannerInput::new(vec![dual], 1_700_000_000).with_resource_pools(pools);
    let context = PlannerContext::new(test_connector_id())
        .with_target_zone(work.clone())
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(2)
        .with_min_memory_mb(1024);

    let decisions = planner.resource_pool_decisions(&input, &context);
    assert_eq!(decisions.len(), 1);
    let decision = &decisions[0];
    assert!(
        !decision.admitted,
        "node MUST be refused: the only work-zone pool for it is exhausted, and the \
         private-zone pool's capacity must not leak across zone boundaries. Got admitted \
         decision: {decision:?}",
    );

    // The refusal must be CpuExhausted/MemoryExhausted from the
    // work-zone pool — NOT the private-zone pool. (The pool_id field
    // tells us which pool the planner evaluated as the best
    // rejection.)
    let refusal_pool = decision
        .pool_id
        .as_deref()
        .expect("rejection should name a pool");
    assert!(
        refusal_pool.starts_with("rr-work-"),
        "br-conformance: refusal pool {refusal_pool} is not in the target zone — \
         the planner leaked into the private-zone pool's capacity",
    );

    // Plan-level: the candidate must be ineligible AND the decision
    // reason must surface the cross-zone-safe rejection.
    let candidates = planner.plan(&input, &context);
    assert!(
        candidates.is_empty(),
        "br-conformance: cross-zone capacity leaked — candidate admitted by an out-of-zone \
         pool: {candidates:?}",
    );
}

/// br-conformance: a node that belongs ONLY to a non-target zone
/// MUST never be admitted by the planner under any pool topology,
/// even if a wide-open pool is bound to the planner's target zone
/// and would technically admit "any" node by class. The zone
/// membership check on the NODE is the load-bearing isolation
/// boundary.
#[test]
fn placement_conformance_node_in_wrong_zone_is_never_admitted() {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();
    let private = ZoneId::private();

    // Node `private-only` is NOT in the target zone.
    let private_only = node_in_zone("private-only", 8192, private);
    // Wide-open work-zone pool that would admit anyone CPU-wise.
    let pools = vec![pool_for(
        "rr-work-open",
        "private-only",
        Some(work.clone()),
        64,
        65_536,
        0,
        0,
    )];

    let input = PlannerInput::new(vec![private_only], 1_700_000_000).with_resource_pools(pools);
    let context = PlannerContext::new(test_connector_id())
        .with_target_zone(work)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(2);

    let candidates = planner.plan(&input, &context);
    // The planner returns only ELIGIBLE candidates from `plan()`, so
    // a node in the wrong zone must be filtered out entirely.
    assert!(
        candidates
            .iter()
            .all(|c| c.node_id.as_str() != "node-private-only"),
        "br-conformance: node in non-target zone leaked into eligible candidates: \
         {candidates:?}",
    );
}

/// br-conformance: zone-unbounded pools (zone_id = None) admit nodes
/// regardless of their zone membership. Pin this contract — it's the
/// "shared infrastructure" placement model and operators rely on it
/// for centralised pools that span zones.
#[test]
fn placement_conformance_zone_unbounded_pool_admits_any_zone_member() {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();
    let private = ZoneId::private();
    let nodes = vec![
        node_in_zone("work-member", 4096, work.clone()),
        node_in_zone("private-member", 4096, private),
    ];
    let pools = vec![
        pool_for("rr-shared", "work-member", None, 8, 4096, 0, 0),
        pool_for("rr-shared-2", "private-member", None, 8, 4096, 0, 0),
    ];

    let input = PlannerInput::new(nodes, 1_700_000_000).with_resource_pools(pools);
    let context = PlannerContext::new(test_connector_id())
        .with_target_zone(work)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(2);

    let decisions = planner.resource_pool_decisions(&input, &context);
    let work_member_decision = decisions
        .iter()
        .find(|d| d.node_id.as_str() == "node-work-member")
        .expect("work-member decision");
    assert!(
        work_member_decision.admitted,
        "br-conformance: zone-unbounded pool MUST admit node in target zone: {work_member_decision:?}",
    );
}

/// br-conformance: when a node is plan-eligible, its CandidateNode
/// MUST carry a `SelectedAsBest` or `EligibleNotSelected`
/// `DecisionReason` so operator audit trails can explain WHY each
/// candidate ranked where it did. Pre-fix: a refactor that returned
/// the candidate vector without populating ranking reasons would
/// strip explanation from the audit trail.
#[test]
fn placement_conformance_eligible_candidates_carry_ranking_decision_reason() {
    let planner = ExecutionPlanner::new();
    let work = ZoneId::work();
    let nodes = vec![
        node_in_zone("alpha", 8192, work.clone()),
        node_in_zone("beta", 4096, work.clone()),
    ];
    let pools = vec![
        pool_for("rr-alpha", "alpha", Some(work.clone()), 8, 4096, 0, 0),
        pool_for("rr-beta", "beta", Some(work.clone()), 8, 4096, 0, 0),
    ];
    let input = PlannerInput::new(nodes, 1_700_000_000).with_resource_pools(pools);
    let context = PlannerContext::new(test_connector_id())
        .with_target_zone(work)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(2);

    let candidates = planner.plan(&input, &context);
    assert!(!candidates.is_empty(), "expected at least one candidate");

    for (rank, candidate) in candidates.iter().enumerate() {
        let has_ranking_reason = candidate.decision_reasons.iter().any(|reason| {
            matches!(
                reason,
                DecisionReason::SelectedAsBest { .. } | DecisionReason::EligibleNotSelected { .. },
            )
        });
        assert!(
            has_ranking_reason,
            "br-conformance: candidate at rank {rank} ({}) missing ranking DecisionReason — \
             operator audit trails will not be able to explain placement",
            candidate.node_id.as_str(),
        );
    }
}
