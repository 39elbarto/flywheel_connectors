//! Public CRDT merge-law conformance for fcp-core.
//!
//! This exercises the exported `OrSet` API rather than internal state fields:
//! three replicas are merged through all six permutations, with explicit
//! assertions for associativity, commutativity, idempotence, and observed-remove
//! tombstone behavior.

use fcp_core::{CrdtActorId, OrSet, OrSetTag};

const ALL_ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

fn tag(actor: &str, nonce: u64) -> OrSetTag {
    OrSetTag::new(CrdtActorId::new(actor), nonce)
}

fn value(name: &str) -> String {
    name.to_owned()
}

fn build_replicas() -> [OrSet<String>; 3] {
    let removed = value("removed-by-b");
    let revived = value("revived-by-c");

    let mut replica_a = OrSet::default();
    replica_a.add(removed.clone(), tag("replica-a", 1));
    replica_a.add(revived.clone(), tag("replica-a", 2));
    replica_a.add(value("a-only"), tag("replica-a", 3));

    let mut replica_b = OrSet::default();
    replica_b.add(removed.clone(), tag("replica-a", 1));
    replica_b.add(revived.clone(), tag("replica-a", 2));
    replica_b.remove_observed(&removed);
    replica_b.remove_observed(&revived);
    replica_b.add(value("b-only"), tag("replica-b", 1));

    let mut replica_c = OrSet::default();
    replica_c.add(revived, tag("replica-c", 1));
    replica_c.add(value("c-only"), tag("replica-c", 2));

    [replica_a, replica_b, replica_c]
}

fn merge_left_associated(replicas: &[OrSet<String>; 3], order: [usize; 3]) -> OrSet<String> {
    let mut merged = replicas[order[0]].clone();
    merged.merge(&replicas[order[1]]);
    merged.merge(&replicas[order[2]]);
    merged
}

fn merge_right_associated(replicas: &[OrSet<String>; 3], order: [usize; 3]) -> OrSet<String> {
    let mut tail = replicas[order[1]].clone();
    tail.merge(&replicas[order[2]]);

    let mut merged = replicas[order[0]].clone();
    merged.merge(&tail);
    merged
}

fn assert_expected_tombstone_semantics(merged: &OrSet<String>) {
    assert!(
        !merged.contains(&value("removed-by-b")),
        "observed remove tombstone MUST suppress the original add in every merge order"
    );
    assert!(
        merged.contains(&value("revived-by-c")),
        "a concurrent add with a fresh tag MUST survive an observed remove of older tags"
    );
    assert_eq!(
        merged.values(),
        vec![
            value("a-only"),
            value("b-only"),
            value("c-only"),
            value("revived-by-c"),
        ],
        "merged OR-Set values MUST converge to the same live set"
    );
}

#[test]
fn or_set_three_replica_merge_laws_and_tombstones() {
    let replicas = build_replicas();
    let expected = merge_left_associated(&replicas, ALL_ORDERS[0]);
    assert_expected_tombstone_semantics(&expected);

    for replica in &replicas {
        let mut twice = replica.clone();
        twice.merge(replica);
        assert_eq!(twice, *replica, "merge with self MUST be idempotent");
    }

    for order in ALL_ORDERS {
        let left = merge_left_associated(&replicas, order);
        let right = merge_right_associated(&replicas, order);
        assert_eq!(
            left, right,
            "OR-Set merge MUST be associative for replica order {order:?}"
        );
        assert_eq!(
            left, expected,
            "OR-Set merge MUST be commutative across replica order {order:?}"
        );

        let mut repeated = left.clone();
        for replica in &replicas {
            repeated.merge(replica);
        }
        assert_eq!(
            repeated, left,
            "replaying all replica states MUST be idempotent for order {order:?}"
        );
        assert_expected_tombstone_semantics(&left);
    }
}
