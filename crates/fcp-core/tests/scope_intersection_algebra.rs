//! Pin set-intersection algebraic laws on the fcp-core scope-bearing
//! intersection primitive (flywheel_connectors-epqsi).
//!
//! Bead asks for "CapabilityScope intersection semantics". No such
//! `CapabilityScope` type exists in fcp-core, and `CapabilityConstraints`
//! has no `intersect` method either. The only scope-bearing
//! intersection primitive in fcp-core is `ForkEvidence::double_signers`
//! (checkpoint.rs:281), which intersects the signer sets of two
//! conflicting checkpoints to identify Byzantine nodes that signed
//! both forks.
//!
//! Signer sets ARE a kind of scope (a "scope of authority over which
//! a given checkpoint is valid"), so the four algebraic properties
//! the bead asks about are meaningful here:
//!
//!   1. **Identity**: `S ∩ S = S` — `double_signers` on
//!      `signers_a == signers_b` returns the full set.
//!   2. **Commutativity**: `A ∩ B = B ∩ A` — swapping the two
//!      `with_signers_*` calls produces the same `double_signers`.
//!   3. **Associativity**: `(A ∩ B) ∩ C = A ∩ (B ∩ C)` — applies
//!      to repeated intersections; built here by chaining
//!      `double_signers` results into a follow-up `ForkEvidence`.
//!   4. **Empty on disjoint**: `A ∩ B = ∅` when no element appears
//!      in both. The bead's "empty-on-disjoint" property maps to
//!      `double_signers().is_empty()`.
//!
//! All four laws follow from the underlying `BTreeSet::intersection`
//! contract, but pinning them on the production `double_signers`
//! method protects against a refactor that, e.g., switches to a
//! Vec-based representation that loses intersection semantics, or
//! accidentally swaps `intersection` for `union` / `difference`.

use std::collections::BTreeSet;

use fcp_core::{ForkEvidence, ObjectId, TailscaleNodeId, ZoneId};

fn zone() -> ZoneId {
    ZoneId::work()
}

fn fork_with(signers_a: &[&str], signers_b: &[&str]) -> ForkEvidence {
    ForkEvidence::new(
        zone(),
        1,
        ObjectId::from_bytes([1; 32]),
        ObjectId::from_bytes([2; 32]),
        0,
        TailscaleNodeId::new("detector"),
    )
    .with_signers_a(signers_a.iter().map(|s| (*s).to_string()))
    .with_signers_b(signers_b.iter().map(|s| (*s).to_string()))
}

fn signers(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Identity:  S ∩ S = S
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn double_signers_identity_law() {
    // double_signers on identical signer sets returns the full set.
    let s = ["alice", "bob", "charlie"];
    let evidence = fork_with(&s, &s);
    let result = evidence.double_signers();
    assert_eq!(
        result,
        signers(&s),
        "IDENTITY: S ∩ S MUST equal S; got {result:?}"
    );
}

#[test]
fn double_signers_identity_empty_set() {
    // S = ∅: ∅ ∩ ∅ = ∅.
    let evidence = fork_with(&[], &[]);
    assert!(
        evidence.double_signers().is_empty(),
        "IDENTITY on empty set: ∅ ∩ ∅ MUST be ∅"
    );
}

#[test]
fn double_signers_identity_singleton() {
    let evidence = fork_with(&["alice"], &["alice"]);
    assert_eq!(
        evidence.double_signers(),
        signers(&["alice"]),
        "IDENTITY on singleton: {{a}} ∩ {{a}} MUST be {{a}}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Commutativity: A ∩ B = B ∩ A
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn double_signers_commutativity() {
    let a = ["alice", "bob", "charlie"];
    let b = ["bob", "charlie", "dave"];

    let ab = fork_with(&a, &b).double_signers();
    let ba = fork_with(&b, &a).double_signers();

    assert_eq!(ab, ba, "COMMUTATIVITY: A ∩ B MUST equal B ∩ A");
    assert_eq!(
        ab,
        signers(&["bob", "charlie"]),
        "expected overlap {{bob, charlie}}"
    );
}

#[test]
fn double_signers_commutativity_disjoint() {
    let a = ["alice", "bob"];
    let b = ["charlie", "dave"];

    let ab = fork_with(&a, &b).double_signers();
    let ba = fork_with(&b, &a).double_signers();

    assert_eq!(ab, ba, "COMMUTATIVITY on disjoint sets MUST hold");
    assert!(ab.is_empty(), "disjoint A ∩ B MUST be ∅");
}

#[test]
fn double_signers_commutativity_with_empty() {
    let a = ["alice", "bob"];
    let b: [&str; 0] = [];

    let ab = fork_with(&a, &b).double_signers();
    let ba = fork_with(&b, &a).double_signers();

    assert_eq!(ab, ba);
    assert!(ab.is_empty(), "S ∩ ∅ MUST be ∅");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Associativity: (A ∩ B) ∩ C = A ∩ (B ∩ C)
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: wrap a signer set as `signers_a` and another as `signers_b`,
/// then take `double_signers` to compute the binary intersection.
fn intersect_pair(a: &BTreeSet<String>, b: &BTreeSet<String>) -> BTreeSet<String> {
    ForkEvidence::new(
        zone(),
        1,
        ObjectId::from_bytes([3; 32]),
        ObjectId::from_bytes([4; 32]),
        0,
        TailscaleNodeId::new("detector"),
    )
    .with_signers_a(a.iter().cloned())
    .with_signers_b(b.iter().cloned())
    .double_signers()
}

#[test]
fn double_signers_associativity() {
    // (A ∩ B) ∩ C = A ∩ (B ∩ C)
    let a = signers(&["alice", "bob", "charlie", "dave"]);
    let b = signers(&["bob", "charlie", "dave", "erin"]);
    let c = signers(&["charlie", "dave", "erin", "frank"]);

    let ab_then_c = intersect_pair(&intersect_pair(&a, &b), &c);
    let a_then_bc = intersect_pair(&a, &intersect_pair(&b, &c));

    assert_eq!(
        ab_then_c, a_then_bc,
        "ASSOCIATIVITY: (A ∩ B) ∩ C MUST equal A ∩ (B ∩ C)"
    );
    assert_eq!(
        ab_then_c,
        signers(&["charlie", "dave"]),
        "expected three-way overlap {{charlie, dave}}"
    );
}

#[test]
fn double_signers_associativity_with_empty_intermediate() {
    // (A ∩ B) ∩ C where (A ∩ B) is empty — the chain MUST stay empty
    // both ways.
    let a = signers(&["alice"]);
    let b = signers(&["bob"]);
    let c = signers(&["alice", "bob"]);

    let ab_then_c = intersect_pair(&intersect_pair(&a, &b), &c);
    let a_then_bc = intersect_pair(&a, &intersect_pair(&b, &c));

    assert_eq!(ab_then_c, a_then_bc);
    assert!(
        ab_then_c.is_empty(),
        "intersection chain through ∅ MUST be ∅"
    );
}

#[test]
fn double_signers_associativity_full_overlap() {
    // All three sets identical — every grouping equals S.
    let s = signers(&["alice", "bob", "charlie"]);

    let ab_then_c = intersect_pair(&intersect_pair(&s, &s), &s);
    let a_then_bc = intersect_pair(&s, &intersect_pair(&s, &s));

    assert_eq!(ab_then_c, a_then_bc);
    assert_eq!(ab_then_c, s, "(S ∩ S) ∩ S MUST equal S");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Empty on disjoint:  A ∩ B = ∅  iff  A and B share no elements
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn double_signers_empty_when_signers_disjoint() {
    let evidence = fork_with(&["alice", "bob"], &["charlie", "dave"]);
    assert!(
        evidence.double_signers().is_empty(),
        "EMPTY-ON-DISJOINT: A ∩ B MUST be ∅ when A and B share no elements"
    );
}

#[test]
fn double_signers_empty_when_one_side_empty() {
    let evidence_a_empty = fork_with(&[], &["alice", "bob"]);
    assert!(
        evidence_a_empty.double_signers().is_empty(),
        "∅ ∩ S MUST be ∅"
    );

    let evidence_b_empty = fork_with(&["alice", "bob"], &[]);
    assert!(
        evidence_b_empty.double_signers().is_empty(),
        "S ∩ ∅ MUST be ∅"
    );
}

#[test]
fn double_signers_nonempty_when_overlap_exists() {
    // The contrapositive of empty-on-disjoint: if A and B share at
    // least one element, the result MUST be non-empty AND MUST
    // contain exactly the shared elements.
    let evidence = fork_with(&["alice", "bob"], &["bob", "charlie"]);
    let overlap = evidence.double_signers();
    assert!(!overlap.is_empty(), "non-disjoint A and B MUST overlap");
    assert_eq!(
        overlap,
        signers(&["bob"]),
        "overlap MUST equal exactly the shared elements"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Subset property: A ∩ B ⊆ A  and  A ∩ B ⊆ B
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn double_signers_result_is_subset_of_both_inputs() {
    // The intersection MUST be contained in both input sets.
    let a = ["alice", "bob", "charlie"];
    let b = ["bob", "charlie", "dave"];
    let evidence = fork_with(&a, &b);
    let overlap = evidence.double_signers();

    let set_a = signers(&a);
    let set_b = signers(&b);

    for member in &overlap {
        assert!(
            set_a.contains(member),
            "result {member:?} MUST be in signers_a"
        );
        assert!(
            set_b.contains(member),
            "result {member:?} MUST be in signers_b"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Determinism — repeated calls return the same set.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn double_signers_is_deterministic() {
    let evidence = fork_with(&["alice", "bob", "charlie"], &["bob", "charlie", "dave"]);
    let r1 = evidence.double_signers();
    let r2 = evidence.double_signers();
    let r3 = evidence.double_signers();
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}
