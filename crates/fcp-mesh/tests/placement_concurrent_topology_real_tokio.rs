//! Real-Tokio concurrency test for `ExecutionPlanner` under topology churn.
//!
//! `ExecutionPlanner::plan()` is documented as a pure function over a
//! `PlannerInput` snapshot, but every production caller drives it from
//! a coordinator that holds the topology (nodes + resource pools)
//! behind a shared async lock and mutates it from one task while
//! placement readers run on others. The single-threaded conformance
//! tests in `placement_conformance.rs` exercise the *value contract*;
//! this harness exercises the *concurrency contract*:
//!
//!   1. Plans never cite a node that is absent from the snapshot they
//!      were computed against. A torn read between `nodes` and
//!      `resource_pools` (e.g. interior-mut leak, reader observing a
//!      half-applied write) would let a removed node win the
//!      placement and cause the coordinator to dispatch work to a
//!      ghost.
//!
//!   2. `resource_pool_decisions()` audit rows always reference nodes
//!      that exist in the snapshot. Operator dashboards subtract
//!      `decisions.len() - admitted` to compute fleet-wide rejection
//!      rate; if a decision row points at a phantom node, the
//!      dashboard double-counts.
//!
//!   3. Determinism is preserved across heavy reader contention:
//!      re-running `plan(snapshot, ctx)` on the same snapshot from
//!      different reader threads yields the same ranked candidate
//!      vector. A future refactor that adds `&mut self` interior
//!      caching would silently make placement decisions depend on
//!      reader identity.
//!
//!   4. The system makes forward progress under churn — the writer
//!      completes its full mutation schedule and at least one reader
//!      records ≥`MIN_PLANS_PER_READER` plans. A regression that
//!      introduces an exclusive lock on the planner (e.g. someone
//!      replacing the pure scoring with an `Arc<Mutex<Cache>>`) would
//!      tank reader throughput below this floor.
//!
//! The harness does NOT spin a `MeshNode` because the planner is
//! deliberately decoupled from gossip; the realistic concurrency
//! shape is *coordinator owns topology lock, multiple consumers ask
//! for placements*. That's exactly what we model.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_async_core::sync::RwLock;
use fcp_async_core::{task, time};
use fcp_core::{ConnectorId, ObjectId, ZoneId};
use fcp_mesh::{
    AvailabilityProfile, DeviceProfile, ExecutionPlanner, InstalledConnector, LatencyClass,
    NodeInfo, PlannerContext, PlannerInput, PowerSource, ResourcePoolClass, ResourcePoolStatus,
};
use fcp_tailscale::NodeId;

const READER_TASKS: usize = 4;
const WRITER_MUTATIONS: usize = 240;
const MIN_PLANS_PER_READER: u64 = 25;
const READER_BUDGET_PLANS: u64 = 5_000;
const SHUTDOWN_AFTER_WRITER_GRACE_MS: u64 = 50;

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
    NodeInfo {
        profile: make_profile(suffix, memory_mb),
        local_symbols: HashSet::new(),
        held_leases: Vec::new(),
        zones: vec![zone],
    }
}

fn pool_for(
    pool_id: &str,
    node_suffix: &str,
    zone: ZoneId,
    cpu_total: u16,
    mem_total: u32,
    cpu_used: u16,
    mem_used: u32,
) -> ResourcePoolStatus {
    ResourcePoolStatus::new(
        pool_id,
        NodeId::new(format!("node-{node_suffix}")),
        Some(zone),
        ResourcePoolClass::RequestResponse,
        cpu_total,
        mem_total,
    )
    .with_usage(cpu_used, mem_used)
}

/// Apply one writer mutation step to the shared topology snapshot.
///
/// The schedule cycles through four mutation kinds so every code
/// path that reads `nodes` and `resource_pools` together has to
/// tolerate an interleaved reader observing any one of them mid-
/// transition:
///
///   - tick % 4 == 0: add a fresh node (and its pool) to the back
///   - tick % 4 == 1: remove the *first* node and its pool together
///   - tick % 4 == 2: rewrite the head node's pool capacity
///   - tick % 4 == 3: bump every pool's `current_time` proxy by
///     touching memory_used (forces a torn-read window between the
///     writes to individual ResourcePoolStatus entries)
///
/// We always keep at least one node/pool so readers never see an
/// empty topology — that's a separately-tested degenerate case.
fn apply_mutation(input: &mut PlannerInput, tick: usize, work: &ZoneId) {
    match tick % 4 {
        0 => {
            let suffix = format!("dyn-{tick}");
            input.nodes.push(node_in_zone(&suffix, 4096, work.clone()));
            input.resource_pools.push(pool_for(
                &format!("rr-{suffix}"),
                &suffix,
                work.clone(),
                8,
                4096,
                2,
                1024,
            ));
        }
        1 => {
            if input.nodes.len() > 1 {
                let removed = input.nodes.remove(0);
                let removed_id = removed.profile.node_id.clone();
                input.resource_pools.retain(|p| p.node_id != removed_id);
            }
        }
        2 => {
            if let Some(pool) = input.resource_pools.first_mut() {
                pool.cpu_cores_used = pool.cpu_cores_limit / 2;
                pool.memory_mb_used = pool.memory_mb_limit / 2;
            }
        }
        _ => {
            for pool in &mut input.resource_pools {
                pool.cpu_cores_used =
                    (pool.cpu_cores_used.saturating_add(1)).min(pool.cpu_cores_limit);
                pool.memory_mb_used =
                    (pool.memory_mb_used.saturating_add(64)).min(pool.memory_mb_limit);
            }
        }
    }
    input.current_time = input.current_time.wrapping_add(1);
}

/// Return error string when the candidate list violates the snapshot
/// invariants — every selected node MUST be in the snapshot's node
/// set, and every audit decision row MUST reference a snapshot node.
/// Returns `Ok(())` when the plan is consistent with the snapshot.
fn check_plan_against_snapshot(
    snapshot: &PlannerInput,
    candidates: &[fcp_mesh::CandidateNode],
    decisions: &[fcp_mesh::ResourcePoolDecision],
) -> Result<(), String> {
    let snapshot_node_ids: HashSet<&str> = snapshot
        .nodes
        .iter()
        .map(|n| n.profile.node_id.as_str())
        .collect();

    for candidate in candidates {
        if !snapshot_node_ids.contains(candidate.node_id.as_str()) {
            return Err(format!(
                "candidate cited node `{}` not present in snapshot of {} nodes \
                 — torn read between nodes and pools",
                candidate.node_id.as_str(),
                snapshot.nodes.len(),
            ));
        }
    }

    for decision in decisions {
        if !snapshot_node_ids.contains(decision.node_id.as_str()) {
            return Err(format!(
                "audit decision cited node `{}` not present in snapshot — \
                 phantom row would double-count in operator dashboards",
                decision.node_id.as_str(),
            ));
        }
    }

    Ok(())
}

#[fcp_async_core::runtime::test]
async fn placement_planner_under_concurrent_topology_churn() {
    let work = ZoneId::work();
    let initial_nodes = vec![
        node_in_zone("seed-a", 4096, work.clone()),
        node_in_zone("seed-b", 4096, work.clone()),
        node_in_zone("seed-c", 4096, work.clone()),
    ];
    let initial_pools = vec![
        pool_for("rr-seed-a", "seed-a", work.clone(), 8, 4096, 2, 1024),
        pool_for("rr-seed-b", "seed-b", work.clone(), 8, 4096, 2, 1024),
        pool_for("rr-seed-c", "seed-c", work.clone(), 8, 4096, 2, 1024),
    ];
    let initial_input =
        PlannerInput::new(initial_nodes, 1_700_000_000).with_resource_pools(initial_pools);

    let topology = Arc::new(RwLock::new(initial_input));
    let writer_done = Arc::new(AtomicU64::new(0));

    let writer_topology = Arc::clone(&topology);
    let writer_done_signal = Arc::clone(&writer_done);
    let writer_zone = work.clone();
    let writer = task::spawn(async move {
        for tick in 0..WRITER_MUTATIONS {
            {
                let mut guard = writer_topology.write().await;
                apply_mutation(&mut guard, tick, &writer_zone);
            }
            // Brief sleep keeps the writer realistic — production
            // coordinators don't churn topology in a tight loop.
            time::sleep(Duration::from_micros(50)).await;
        }
        writer_done_signal.store(1, Ordering::SeqCst);
    });

    let mut reader_handles = Vec::new();
    for reader_id in 0..READER_TASKS {
        let reader_topology = Arc::clone(&topology);
        let reader_done = Arc::clone(&writer_done);
        let reader_zone = work.clone();
        let handle = task::spawn(async move {
            let planner = ExecutionPlanner::new();
            let context = PlannerContext::new(test_connector_id())
                .with_target_zone(reader_zone)
                .with_resource_pool_class(ResourcePoolClass::RequestResponse)
                .with_requested_cpu_cores(2)
                .with_min_memory_mb(1024);

            let mut plans_completed: u64 = 0;
            let mut violations: Vec<String> = Vec::new();
            let mut last_snapshot_for_replay: Option<(PlannerInput, Vec<fcp_mesh::CandidateNode>)> =
                None;

            loop {
                if plans_completed >= READER_BUDGET_PLANS {
                    break;
                }
                let snapshot = {
                    let guard = reader_topology.read().await;
                    guard.clone()
                };
                let candidates = planner.plan(&snapshot, &context);
                let decisions = planner.resource_pool_decisions(&snapshot, &context);

                if let Err(violation) =
                    check_plan_against_snapshot(&snapshot, &candidates, &decisions)
                {
                    violations.push(format!("reader-{reader_id}: {violation}"));
                    // Cap violations so a torn-read storm doesn't OOM.
                    if violations.len() >= 16 {
                        break;
                    }
                }

                // Cross-thread determinism: re-run `plan` on the same
                // snapshot and confirm bit-identical candidate ordering.
                // Catches `&mut self` interior caching that depends on
                // call history (which would diverge across reader IDs).
                if plans_completed % 16 == 0 {
                    let replayed = planner.plan(&snapshot, &context);
                    if replayed.len() != candidates.len() {
                        violations.push(format!(
                            "reader-{reader_id}: replayed.len()={} != original.len()={} — \
                             planner is not pure across calls",
                            replayed.len(),
                            candidates.len(),
                        ));
                        break;
                    }
                    for (orig, repl) in candidates.iter().zip(replayed.iter()) {
                        if orig.node_id.as_str() != repl.node_id.as_str() {
                            violations.push(format!(
                                "reader-{reader_id}: replayed candidate ordering drifted — \
                                 `{}` vs `{}`",
                                orig.node_id.as_str(),
                                repl.node_id.as_str(),
                            ));
                            break;
                        }
                    }
                    last_snapshot_for_replay = Some((snapshot, candidates));
                }

                plans_completed += 1;

                if reader_done.load(Ordering::SeqCst) == 1 {
                    // Writer is done; let the reader drain a few more
                    // cycles to confirm the post-churn snapshot still
                    // produces a stable plan.
                    let drain_target = plans_completed + (READER_BUDGET_PLANS / 100).max(8);
                    while plans_completed < drain_target {
                        let snapshot = {
                            let guard = reader_topology.read().await;
                            guard.clone()
                        };
                        let candidates = planner.plan(&snapshot, &context);
                        let decisions = planner.resource_pool_decisions(&snapshot, &context);
                        if let Err(violation) =
                            check_plan_against_snapshot(&snapshot, &candidates, &decisions)
                        {
                            violations.push(format!("reader-{reader_id} drain: {violation}"));
                        }
                        plans_completed += 1;
                    }
                    break;
                }

                // Yield more aggressively than `task::yield_now` so the
                // writer is never starved by reader-only progress.
                if plans_completed.is_multiple_of(8) {
                    fcp_async_core::task::yield_now().await;
                }
            }

            (
                reader_id,
                plans_completed,
                violations,
                last_snapshot_for_replay,
            )
        });
        reader_handles.push(handle);
    }

    writer.await.expect("writer task joined");
    // Give readers a brief grace window after writer signals done.
    time::sleep(Duration::from_millis(SHUTDOWN_AFTER_WRITER_GRACE_MS)).await;

    let mut total_plans: u64 = 0;
    let mut violations: Vec<String> = Vec::new();
    let mut min_per_reader: u64 = u64::MAX;
    let mut last_witness: Option<(PlannerInput, Vec<fcp_mesh::CandidateNode>)> = None;
    for handle in reader_handles {
        let (reader_id, plans, mut reader_violations, witness) =
            handle.await.expect("reader task joined");
        eprintln!("reader {reader_id} completed {plans} plans");
        total_plans += plans;
        min_per_reader = min_per_reader.min(plans);
        violations.append(&mut reader_violations);
        if witness.is_some() {
            last_witness = witness;
        }
    }

    assert!(
        violations.is_empty(),
        "concurrent placement violated invariants under topology churn:\n{}",
        violations.join("\n"),
    );
    assert!(
        min_per_reader >= MIN_PLANS_PER_READER,
        "slowest reader only completed {min_per_reader} plans (floor {MIN_PLANS_PER_READER}) — \
         a regression has serialized the planner under contention",
    );
    assert!(
        total_plans >= MIN_PLANS_PER_READER * READER_TASKS as u64,
        "total plans across {READER_TASKS} readers = {total_plans} (floor {})",
        MIN_PLANS_PER_READER * READER_TASKS as u64,
    );

    // Final post-churn determinism check on the last witness: a fresh
    // planner ran on the witness snapshot must yield the same ranked
    // candidate ordering. This pins the property that determinism is
    // a property of the snapshot, not of the *reader thread that
    // observed it*.
    let (snapshot, original_candidates) =
        last_witness.expect("at least one reader recorded a determinism witness");
    let fresh_planner = ExecutionPlanner::new();
    let fresh_context = PlannerContext::new(test_connector_id())
        .with_target_zone(work)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(2)
        .with_min_memory_mb(1024);
    let final_candidates = fresh_planner.plan(&snapshot, &fresh_context);
    assert_eq!(
        original_candidates.len(),
        final_candidates.len(),
        "fresh-planner replay candidate count drifted",
    );
    for (orig, fresh) in original_candidates.iter().zip(final_candidates.iter()) {
        assert_eq!(
            orig.node_id.as_str(),
            fresh.node_id.as_str(),
            "fresh-planner replay candidate ordering drifted on witness snapshot",
        );
    }

    let final_topology = topology.read().await;
    eprintln!(
        "writer applied {WRITER_MUTATIONS} mutations; final topology: {} nodes, {} pools",
        final_topology.nodes.len(),
        final_topology.resource_pools.len(),
    );
    assert!(
        !final_topology.nodes.is_empty(),
        "writer schedule should never empty the topology",
    );
}
