//! Pin `select_checkpoint_coordinator` + `rank_checkpoint_coordinators` HRW
//! ordering invariants — the closest analogue to "ConnectorSelector ordering"
//! (flywheel_connectors-u0771).
//!
//! Bead asks for `ConnectorSelector` ordering pinning. No type literally named
//! `ConnectorSelector` exists in fcp-core. The closest analogue is the public
//! Highest-Random-Weight selector pair at `crates/fcp-core/src/checkpoint.rs:671+687`,
//! which returns the deterministically-chosen coordinator (or a fallback
//! ranking) for a `(zone_id, epoch, eligible_nodes)` tuple. This is the
//! ordering surface the rest of the system depends on for selecting which
//! node serves an operation.
//!
//! The existing checkpoint_golden_vectors.rs tests cover deterministic
//! selection, basic descending-hash ranking, and epoch sensitivity. This
//! test pins orthogonal ordering invariants:
//!   * Empty + single-node boundaries,
//!   * `select(...) == rank(...).first().cloned()` agreement,
//!   * Input-permutation invariance,
//!   * Zone sensitivity sentinel,
//!   * Removing one node only removes that node from output (HRW property),
//!   * Adding a single new node preserves the relative order of existing
//!     nodes (HRW insertion property),
//!   * Duplicate inputs are NOT silently deduplicated,
//!   * Distinct node names produce distinct hashes (collision smoke).

use fcp_core::{
    EpochId, TailscaleNodeId, ZoneId, hrw_hash_checkpoint, rank_checkpoint_coordinators,
    select_checkpoint_coordinator,
};

fn node(name: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(name)
}

fn epoch() -> EpochId {
    EpochId::new("epoch-2026-04-29")
}

fn nodes(names: &[&str]) -> Vec<TailscaleNodeId> {
    names.iter().copied().map(node).collect()
}

#[test]
fn select_on_empty_eligible_set_returns_none() {
    let zone = ZoneId::work();
    let result = select_checkpoint_coordinator(&zone, &epoch(), &[]);
    assert!(
        result.is_none(),
        "empty eligible set must produce no coordinator, got {result:?}"
    );
}

#[test]
fn rank_on_empty_eligible_set_returns_empty_vec() {
    let zone = ZoneId::work();
    let ranked = rank_checkpoint_coordinators(&zone, &epoch(), &[]);
    assert!(ranked.is_empty(), "empty input must produce empty ranking");
}

#[test]
fn select_on_single_node_returns_that_node() {
    let zone = ZoneId::work();
    let only = node("node-solo");
    let result = select_checkpoint_coordinator(&zone, &epoch(), std::slice::from_ref(&only));
    assert_eq!(result, Some(only.clone()));

    let ranked = rank_checkpoint_coordinators(&zone, &epoch(), std::slice::from_ref(&only));
    assert_eq!(ranked, vec![only]);
}

#[test]
fn select_agrees_with_rank_first() {
    // The two public APIs must agree: select(...) is rank(...).first().cloned().
    // Anyone implementing one without the other risks divergence on the very
    // input the rest of the system uses for fallback.
    let zone = ZoneId::work();
    let epoch = epoch();
    let nodes = nodes(&["alpha", "beta", "gamma", "delta", "epsilon", "zeta"]);

    let selected = select_checkpoint_coordinator(&zone, &epoch, &nodes);
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

    assert_eq!(
        selected.as_ref(),
        ranked.first(),
        "select() must equal rank().first()"
    );
}

#[test]
fn ranking_is_invariant_under_input_permutation() {
    // HRW selection orders by hash, NOT input order. Permuting eligible_nodes
    // must produce the same ranking — otherwise a caller passing nodes in
    // non-deterministic order (e.g. from a HashMap iter) gets non-deterministic
    // coordinator selection.
    let zone = ZoneId::work();
    let epoch = epoch();
    let original = nodes(&["alpha", "beta", "gamma", "delta", "epsilon"]);
    let mut shuffled = original.clone();
    shuffled.reverse();
    let mut rotated = original.clone();
    rotated.rotate_left(2);

    let r1 = rank_checkpoint_coordinators(&zone, &epoch, &original);
    let r2 = rank_checkpoint_coordinators(&zone, &epoch, &shuffled);
    let r3 = rank_checkpoint_coordinators(&zone, &epoch, &rotated);

    assert_eq!(r1, r2, "reversed input must produce same ranking");
    assert_eq!(r1, r3, "rotated input must produce same ranking");
}

#[test]
fn ranking_is_descending_by_hash_for_arbitrary_input() {
    let zone = ZoneId::work();
    let epoch = epoch();
    let nodes = nodes(&["n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"]);
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
    assert_eq!(ranked.len(), nodes.len());

    for window in ranked.windows(2) {
        let a = hrw_hash_checkpoint(&zone, &epoch, &window[0]);
        let b = hrw_hash_checkpoint(&zone, &epoch, &window[1]);
        assert!(
            a >= b,
            "ranking not descending: {} (h={a}) < {} (h={b})",
            window[0].as_str(),
            window[1].as_str(),
        );
    }
}

#[test]
fn changing_zone_can_change_coordinator() {
    // The HRW hash incorporates zone_id, so different zones can pick different
    // coordinators from the same eligible set. Find at least one node-list
    // that exhibits this — without it, the zone parameter would be dead
    // weight in the selector contract. We verify by scanning a handful of
    // node-lists; HRW collision over zone is astronomically unlikely.
    let epoch = epoch();
    let nodes = nodes(&[
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    ]);

    let work_coord = select_checkpoint_coordinator(&ZoneId::work(), &epoch, &nodes).unwrap();
    let private_coord = select_checkpoint_coordinator(&ZoneId::private(), &epoch, &nodes).unwrap();
    let public_coord = select_checkpoint_coordinator(&ZoneId::public(), &epoch, &nodes).unwrap();

    // At least one zone pair must differ — otherwise zone is a dead input.
    let all_same =
        work_coord == private_coord && private_coord == public_coord && work_coord == public_coord;
    assert!(
        !all_same,
        "zone must influence coordinator selection across {} candidates — got {work_coord:?} / {private_coord:?} / {public_coord:?}",
        nodes.len()
    );
}

#[test]
fn removing_one_node_only_removes_that_node_from_ranking() {
    // Core HRW property: removing a node from input only removes that node
    // from output — the remaining nodes keep their relative order. This is
    // why HRW (vs. hash-modulo) is preferred for fallback rankings: removing
    // a failed node doesn't reshuffle the rest of the queue.
    let zone = ZoneId::work();
    let epoch = epoch();
    let full = nodes(&["alpha", "beta", "gamma", "delta", "epsilon"]);
    let full_ranked = rank_checkpoint_coordinators(&zone, &epoch, &full);

    // Remove the SECOND-place node and rank the remainder.
    let runner_up = full_ranked[1].clone();
    let trimmed: Vec<TailscaleNodeId> = full.iter().filter(|n| **n != runner_up).cloned().collect();
    let trimmed_ranked = rank_checkpoint_coordinators(&zone, &epoch, &trimmed);

    let expected: Vec<TailscaleNodeId> = full_ranked
        .iter()
        .filter(|n| **n != runner_up)
        .cloned()
        .collect();
    assert_eq!(
        trimmed_ranked, expected,
        "removing runner-up must preserve relative order of remaining nodes"
    );
}

#[test]
fn adding_one_node_preserves_existing_relative_order() {
    // Dual to the removal property: adding a node can only insert it into the
    // existing ranking; the relative order of the original nodes does not
    // change. Otherwise scaling out would invalidate any caller that cached
    // a fallback queue.
    let zone = ZoneId::work();
    let epoch = epoch();
    let original = nodes(&["alpha", "beta", "gamma", "delta"]);
    let original_ranked = rank_checkpoint_coordinators(&zone, &epoch, &original);

    let mut expanded = original.clone();
    expanded.push(node("newcomer"));
    let expanded_ranked = rank_checkpoint_coordinators(&zone, &epoch, &expanded);
    assert_eq!(expanded_ranked.len(), original_ranked.len() + 1);

    // The relative order of the original 4 nodes within expanded_ranked must
    // match original_ranked.
    let filtered: Vec<TailscaleNodeId> = expanded_ranked
        .iter()
        .filter(|n| original.contains(n))
        .cloned()
        .collect();
    assert_eq!(
        filtered, original_ranked,
        "newcomer must not reshuffle existing nodes"
    );
}

#[test]
fn duplicate_inputs_are_not_silently_deduplicated() {
    // The selector takes an `&[TailscaleNodeId]` slice; it does not own a
    // set. Pin that duplicates flow through to the output — callers that
    // want uniqueness must dedupe upstream. Dropping this property would
    // surprise anyone counting on `ranked.len() == eligible_nodes.len()`.
    let zone = ZoneId::work();
    let epoch = epoch();
    let dup = vec![node("alpha"), node("beta"), node("alpha")];
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &dup);
    assert_eq!(
        ranked.len(),
        3,
        "duplicates preserved in output: {ranked:?}"
    );
    let alpha_count = ranked.iter().filter(|n| n.as_str() == "alpha").count();
    assert_eq!(alpha_count, 2);
}

#[test]
fn hash_is_deterministic_for_identical_inputs() {
    let zone = ZoneId::work();
    let epoch = epoch();
    let n = node("alpha");
    let h1 = hrw_hash_checkpoint(&zone, &epoch, &n);
    let h2 = hrw_hash_checkpoint(&zone, &epoch, &n);
    let h3 = hrw_hash_checkpoint(&zone, &epoch, &n);
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

#[test]
fn distinct_nodes_produce_distinct_hashes_smoke() {
    let zone = ZoneId::work();
    let epoch = epoch();
    let names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
    let mut seen = std::collections::HashSet::new();
    for name in names {
        let h = hrw_hash_checkpoint(&zone, &epoch, &node(name));
        assert!(
            seen.insert(h),
            "hash collision across distinct node names — node `{name}` collides"
        );
    }
}

#[test]
fn changing_node_id_changes_hash() {
    let zone = ZoneId::work();
    let epoch = epoch();
    let h_alpha = hrw_hash_checkpoint(&zone, &epoch, &node("alpha"));
    let h_beta = hrw_hash_checkpoint(&zone, &epoch, &node("beta"));
    assert_ne!(h_alpha, h_beta, "node-id must influence hash");
}

#[test]
fn changing_epoch_changes_hash_for_same_node() {
    let zone = ZoneId::work();
    let n = node("alpha");
    let h1 = hrw_hash_checkpoint(&zone, &EpochId::new("epoch-1"), &n);
    let h2 = hrw_hash_checkpoint(&zone, &EpochId::new("epoch-2"), &n);
    assert_ne!(h1, h2, "epoch must influence hash");
}

#[test]
fn ranking_with_one_node_is_singleton() {
    let zone = ZoneId::work();
    let epoch = epoch();
    let only = vec![node("solo")];
    let ranked = rank_checkpoint_coordinators(&zone, &epoch, &only);
    assert_eq!(ranked, only);
}
