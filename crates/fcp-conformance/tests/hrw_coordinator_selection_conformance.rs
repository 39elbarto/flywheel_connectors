//! HRW (rendezvous hashing) coordinator-selection conformance.
//!
//! `fcp_core::select_coordinator` and `fcp_core::rank_nodes_by_hrw`
//! are the deterministic HRW primitives that let every mesh peer
//! independently arrive at the SAME coordinator for a given
//! (zone, subject) without any cross-peer communication. They back
//! `LeaseCoordinator` (br-9nee8) and `AuthorityView` (br-rybvy) but
//! had no direct conformance coverage.
//!
//! NORMATIVE properties pinned:
//!
//! 1. **Determinism.** Same (zone, subject, nodes) always returns
//!    the same coordinator. Without this, two peers observing the
//!    same input would disagree on coordination authority.
//! 2. **Input-order independence.** Reordering `eligible_nodes`
//!    MUST NOT change the result — peers receiving discovery
//!    snapshots in different orders must still agree.
//! 3. **`rank[0] == select_coordinator`.** The two APIs share an
//!    underlying ordering; consistency is required so callers can
//!    interchange them.
//! 4. **`rank_nodes_by_hrw` covers all eligible nodes.** No drops,
//!    no extras — failover routing depends on the full list.
//! 5. **Empty input → `None`.**
//! 6. **Single-node trivial case → that node.**
//! 7. **Subject-dependence.** Different subjects under the same
//!    eligible set distribute across nodes (probabilistic, but
//!    asserted on a small set of known-different subjects).

use fcp_core::{ObjectId, TailscaleNodeId, ZoneId, rank_nodes_by_hrw, select_coordinator};

fn nodes(names: &[&str]) -> Vec<TailscaleNodeId> {
    names.iter().map(|n| TailscaleNodeId::new(*n)).collect()
}

fn obj(label: &[u8]) -> ObjectId {
    ObjectId::from_unscoped_bytes(label)
}

#[test]
fn empty_eligible_set_yields_none_coordinator() {
    let zone = ZoneId::work();
    let subject = obj(b"any-subject");
    assert!(
        select_coordinator(&zone, &subject, &[]).is_none(),
        "select_coordinator on empty nodes MUST return None"
    );

    let ranked = rank_nodes_by_hrw(&zone, &subject, &[]);
    assert!(
        ranked.is_empty(),
        "rank_nodes_by_hrw on empty nodes MUST return empty Vec"
    );
}

#[test]
fn single_node_eligible_set_returns_that_node() {
    let zone = ZoneId::work();
    let subject = obj(b"any-subject");
    let only = nodes(&["node-only"]);

    let coord = select_coordinator(&zone, &subject, &only);
    assert_eq!(
        coord.as_ref().map(|n| n.as_str()),
        Some("node-only"),
        "single-node eligible set MUST select that node"
    );

    let ranked = rank_nodes_by_hrw(&zone, &subject, &only);
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].as_str(), "node-only");
}

#[test]
fn select_coordinator_is_deterministic_under_repeated_calls() {
    // Critical for distributed coordination: every call with the
    // same inputs MUST return the same result.
    let zone = ZoneId::work();
    let subject = obj(b"deterministic-subject");
    let eligible = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);

    let first = select_coordinator(&zone, &subject, &eligible).expect("non-empty selection");
    for _ in 0..32 {
        let again = select_coordinator(&zone, &subject, &eligible).expect("non-empty selection");
        assert_eq!(
            again.as_str(),
            first.as_str(),
            "select_coordinator MUST be deterministic across calls"
        );
    }
}

#[test]
fn select_coordinator_is_invariant_under_input_reordering() {
    // THE property that prevents distributed disagreement: two peers
    // that receive the same set of eligible nodes via discovery
    // gossip — but in different orders — MUST still arrive at the
    // same coordinator.
    let zone = ZoneId::work();
    let subject = obj(b"reorder-subject");

    let order_a = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);
    let order_b = nodes(&["echo", "delta", "charlie", "bravo", "alpha"]);
    let order_c = nodes(&["charlie", "echo", "alpha", "delta", "bravo"]);

    let coord_a = select_coordinator(&zone, &subject, &order_a);
    let coord_b = select_coordinator(&zone, &subject, &order_b);
    let coord_c = select_coordinator(&zone, &subject, &order_c);

    assert_eq!(
        coord_a, coord_b,
        "reorder-A vs reorder-B coordinator disagreement: {coord_a:?} vs {coord_b:?}"
    );
    assert_eq!(
        coord_a, coord_c,
        "reorder-A vs reorder-C coordinator disagreement: {coord_a:?} vs {coord_c:?}"
    );
}

#[test]
fn rank_nodes_by_hrw_first_element_equals_select_coordinator() {
    // Consistency contract between the two public APIs: callers
    // can use `rank[0]` interchangeably with select_coordinator.
    let zone = ZoneId::work();
    for subject_label in [
        &b"subject-1"[..],
        &b"subject-2"[..],
        &b"another-subject"[..],
        &b"yet-another"[..],
    ] {
        let subject = obj(subject_label);
        let eligible = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);

        let coord = select_coordinator(&zone, &subject, &eligible).expect("coord");
        let ranked = rank_nodes_by_hrw(&zone, &subject, &eligible);

        assert_eq!(
            ranked[0].as_str(),
            coord.as_str(),
            "rank_nodes_by_hrw[0] MUST equal select_coordinator for {subject_label:?}; \
             got rank={ranked:?}, coord={coord:?}"
        );
    }
}

#[test]
fn rank_nodes_by_hrw_is_a_total_permutation_of_eligible_set() {
    // Every node in eligible appears exactly once in the ranking.
    // No drops (failover would be incomplete) and no extras (would
    // suggest the function fabricated a node).
    let zone = ZoneId::work();
    let subject = obj(b"permutation-subject");
    let eligible = nodes(&["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]);

    let ranked = rank_nodes_by_hrw(&zone, &subject, &eligible);
    assert_eq!(
        ranked.len(),
        eligible.len(),
        "ranking must have the same length as the input"
    );

    let mut sorted_input: Vec<String> = eligible.iter().map(|n| n.as_str().to_string()).collect();
    sorted_input.sort();
    let mut sorted_output: Vec<String> = ranked.iter().map(|n| n.as_str().to_string()).collect();
    sorted_output.sort();
    assert_eq!(
        sorted_input, sorted_output,
        "ranking must be a permutation of the input — no drops, no extras"
    );
}

#[test]
fn rank_nodes_by_hrw_is_deterministic_under_repeated_calls() {
    let zone = ZoneId::work();
    let subject = obj(b"rank-determinism");
    let eligible = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);

    let first = rank_nodes_by_hrw(&zone, &subject, &eligible);
    for _ in 0..16 {
        let again = rank_nodes_by_hrw(&zone, &subject, &eligible);
        assert_eq!(first, again, "rank_nodes_by_hrw MUST be deterministic");
    }
}

#[test]
fn rank_nodes_by_hrw_is_invariant_under_input_reordering() {
    // Same property as for select_coordinator, but for the FULL
    // ranking — two peers seeing reordered discovery must produce
    // identical failover order.
    let zone = ZoneId::work();
    let subject = obj(b"rank-reorder");
    let order_a = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);
    let order_b = nodes(&["echo", "delta", "charlie", "bravo", "alpha"]);

    let rank_a = rank_nodes_by_hrw(&zone, &subject, &order_a);
    let rank_b = rank_nodes_by_hrw(&zone, &subject, &order_b);
    assert_eq!(
        rank_a, rank_b,
        "rank_nodes_by_hrw MUST be invariant under input order"
    );
}

#[test]
fn different_subjects_distribute_coordinators_across_nodes() {
    // HRW would be useless if every subject mapped to the same
    // coordinator. Probabilistically, with 5 nodes and 200
    // subjects, we expect EVERY node to win at least once.
    // (Pigeon-hole bound: 200/5 ≈ 40 expected wins per node;
    // the chance of a node winning zero is 0.8^200 ≈ 4e-20.)
    let zone = ZoneId::work();
    let eligible = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);

    use std::collections::BTreeSet;
    let mut winners = BTreeSet::new();
    for i in 0_u64..200 {
        let subject = obj(&i.to_le_bytes());
        if let Some(c) = select_coordinator(&zone, &subject, &eligible) {
            winners.insert(c.as_str().to_string());
        }
    }

    for name in &["alpha", "bravo", "charlie", "delta", "echo"] {
        assert!(
            winners.contains(*name),
            "subject distribution failed: node {name} never won across 200 subjects \
             — HRW must spread coordinator assignment, not concentrate on one node"
        );
    }
}

#[test]
fn different_zones_can_yield_different_coordinators_for_same_subject() {
    // The zone is part of the HRW input, so changing zones with the
    // same subject can change the coordinator. Pin that the zone
    // genuinely contributes to the hash (otherwise an attacker who
    // observed the zone-private mapping in zone X could replay it
    // in zone Y).
    let subject = obj(b"shared-subject");
    let eligible = nodes(&["alpha", "bravo", "charlie", "delta", "echo"]);

    // Try several zone pairs; at least one pair must produce
    // different coordinators (otherwise zone is being ignored).
    let zones = [
        ZoneId::work(),
        ZoneId::private(),
        ZoneId::owner(),
        ZoneId::public(),
    ];
    let mut coords = Vec::new();
    for z in &zones {
        if let Some(c) = select_coordinator(z, &subject, &eligible) {
            coords.push(c.as_str().to_string());
        }
    }
    let unique: std::collections::BTreeSet<_> = coords.iter().collect();
    assert!(
        unique.len() >= 2,
        "zone MUST contribute to HRW hash — across {} zones, all coords were the same: {coords:?}",
        zones.len()
    );
}
