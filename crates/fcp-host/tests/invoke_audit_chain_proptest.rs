//! Property test for the same-zone audit-chain combiner
//! (br-evxvv.8 / br-uwlj5).
//!
//! The existing unit tests in `invoke_audit.rs` pin three specific
//! shapes (sequential, contended-but-uncongested, storm) at fixed
//! thread-counts and append-counts. This file sweeps those parameters
//! through proptest so the chain-integrity invariant is exercised at
//! arbitrary points in the (zones × threads × appends-per-thread ×
//! phase-mix) space:
//!
//! 1. **No append loss** — `len_for_zone(z)` equals the total number
//!    of appends submitted to zone `z`, regardless of interleaving.
//!    Pre-fix: catches a storm-fallback regression that could swallow
//!    events by returning Ok without pushing.
//!
//! 2. **Per-zone monotonic seq + dense range** — for every zone, the
//!    set of `seq` values across appended entries is exactly
//!    `0..len_for_zone(z)`. Pre-fix: catches a refactor that skipped a
//!    seq under contention.
//!
//! 3. **Per-zone hash linkage** — for every zone, entry[0] is genesis
//!    and entry[i] follows entry[i-1]. Pre-fix: catches a refactor
//!    that broke the prev-link under storm fallback.
//!
//! 4. **Cross-zone independence** — appends to zone A never appear in
//!    zone B's chain (the per-zone Mutex sharding is the load-bearing
//!    safety property for multi-tenant audit isolation).

use std::sync::Arc;
use std::thread;

use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};
use proptest::prelude::*;

/// Generate a phase. We deliberately exercise all four event_type
/// branches because each carries a different metadata vector; a
/// bug in metadata serialisation would only surface for some
/// phases.
fn arb_phase() -> impl Strategy<Value = InvokePhase> {
    prop_oneof![
        Just(InvokePhase::PreflightAllow),
        "[a-z _]{1,16}".prop_map(|reason| InvokePhase::PreflightDeny { reason }),
        (
            proptest::option::of("[a-z0-9-]{4,8}".prop_map(String::from)),
            any::<bool>(),
            0_u64..10_000,
        )
            .prop_map(
                |(receipt_id, success, duration_ms)| InvokePhase::DispatchResult {
                    receipt_id,
                    success,
                    duration_ms,
                }
            ),
        ("[a-z _]{1,16}", 0_u64..10_000)
            .prop_map(|(error, duration_ms)| { InvokePhase::DispatchError { error, duration_ms } }),
    ]
}

#[derive(Debug, Clone)]
struct ZoneTask {
    zone_id: String,
    appends: Vec<InvokePhase>,
}

/// 1..=4 zones, each with 1..=8 appends spread across 1..=4 worker
/// threads. Bounds intentionally tight: each proptest case spawns
/// real OS threads, so the test budget is dominated by thread-spawn
/// overhead.
fn arb_zone_tasks() -> impl Strategy<Value = Vec<ZoneTask>> {
    proptest::collection::vec(
        (
            "z:[a-z]{4,8}",
            proptest::collection::vec(arb_phase(), 1..=8),
        )
            .prop_map(|(zone_id, appends)| ZoneTask {
                zone_id: zone_id.to_string(),
                appends,
            }),
        1..=4,
    )
    .prop_filter(
        "distinct zone IDs (the property is per-zone; duplicates would conflate tallies)",
        |tasks| {
            let mut seen = std::collections::HashSet::with_capacity(tasks.len());
            tasks.iter().all(|t| seen.insert(t.zone_id.clone()))
        },
    )
}

fn arb_thread_count() -> impl Strategy<Value = usize> {
    1_usize..=4
}

proptest! {
    // Each case spawns OS threads, so keep the budget modest.
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Pin all four chain-integrity invariants at once: no loss,
    /// dense monotonic seq, hash linkage, cross-zone independence.
    #[test]
    fn prop_chain_integrity_holds_for_arbitrary_workload(
        zones in arb_zone_tasks(),
        threads in arb_thread_count(),
    ) {
        let chain = Arc::new(InvokeAuditChain::new());

        // Total expected counts per zone (reference truth).
        let mut expected_per_zone: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for z in &zones {
            *expected_per_zone.entry(z.zone_id.clone()).or_insert(0) +=
                z.appends.len() * threads;
        }

        // Spawn `threads` worker threads. Each worker iterates the full
        // (zone × phase) program — N copies of the same workload.
        // Per-zone serialisation MUST hold across all workers.
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let chain_arc = Arc::clone(&chain);
            let zones = zones.clone();
            handles.push(thread::spawn(move || {
                for z in &zones {
                    for (i, phase) in z.appends.iter().enumerate() {
                        let ctx = InvokeAuditContext {
                            zone_id: z.zone_id.clone(),
                            actor: format!("agent:t-{t}"),
                            connector_id: "github".into(),
                            operation: "list_repos".into(),
                            operation_id: format!("op-{t}-{i}-{}", z.zone_id),
                            correlation_id: None,
                            occurred_at: 1_700_000_000,
                        };
                        chain_arc
                            .append(&ctx, phase.clone())
                            .expect("append must succeed (CAS retry + serialized fallback)");
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        // Property 1 + 4: no loss, no cross-zone bleed.
        for (zone_id, expected_count) in &expected_per_zone {
            let entries = chain.entries_for_zone(zone_id);
            prop_assert_eq!(
                entries.len(),
                *expected_count,
                "br-evxvv.8: zone `{}` lost or gained appends — expected {}, got {}",
                zone_id,
                expected_count,
                entries.len(),
            );
            // Property 4: every entry in this zone's chain has the right zone_id.
            for entry in &entries {
                prop_assert_eq!(
                    entry.zone_id.as_str(),
                    zone_id,
                    "br-evxvv.8: cross-zone bleed — entry tagged zone `{}` found in zone `{}`",
                    entry.zone_id,
                    zone_id,
                );
            }

            // Property 2: dense monotonic seq from 0 to len-1.
            for (i, entry) in entries.iter().enumerate() {
                prop_assert_eq!(
                    entry.seq,
                    i as u64,
                    "br-evxvv.8: zone `{}` seq drift at index {}: expected {}, got {}",
                    zone_id,
                    i,
                    i,
                    entry.seq,
                );
            }

            // Property 3: genesis + pairwise hash linkage.
            prop_assert!(
                entries[0].is_genesis(),
                "br-evxvv.8: zone `{}` first entry must be genesis",
                zone_id,
            );
            for i in 1..entries.len() {
                prop_assert!(
                    entries[i].follows(&entries[i - 1]),
                    "br-evxvv.8: zone `{}` hash-link broken at index {}",
                    zone_id,
                    i,
                );
            }
        }
    }
}

/// Targeted regression: K=1 zone, T=1 thread, M=1 append produces a
/// genesis-only chain. Sanity floor for the proptest bounds — proves
/// the harness wires up correctly even at the smallest sizes.
#[test]
fn single_thread_single_append_yields_genesis_only_chain() {
    let chain = InvokeAuditChain::new();
    let ctx = InvokeAuditContext {
        zone_id: "z:smoke".into(),
        actor: "agent:smoke".into(),
        connector_id: "github".into(),
        operation: "list_repos".into(),
        operation_id: "op-smoke".into(),
        correlation_id: None,
        occurred_at: 1_700_000_000,
    };
    chain
        .append(&ctx, InvokePhase::PreflightAllow)
        .expect("single append must succeed");

    let entries = chain.entries_for_zone("z:smoke");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_genesis());
}
