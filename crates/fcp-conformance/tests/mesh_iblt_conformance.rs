//! br-zhmuc — Conformance mirror for IBLT (Goodrich & Mitzenmacher,
//! "Invertible Bloom Lookup Tables", 2011) as implemented in
//! `fcp_mesh::iblt::Iblt`.
//!
//! Each test is tagged with an `MSH-IBLT-N` invariant id in the
//! function name. Oracles are either algorithmic (encode/decode
//! round-trip), algebraic (subtraction symmetry), or spec-stated
//! (capacity-exceeded returns a partial decode rather than silently
//! truncating).

use fcp_mesh::iblt::{IBLT_HASH_COUNT, Iblt, IbltError};
use fcp_prelude::ObjectId;

fn obj(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn build_sketch(items: &[ObjectId], cell_count: usize) -> Iblt {
    let mut iblt = Iblt::with_cell_count(cell_count).expect("valid cell count");
    for id in items {
        iblt.insert(*id);
    }
    iblt
}

// ── MSH-IBLT-1: exact recovery when |symmetric diff| ≤ capacity ──────

#[test]
fn msh_iblt_1_exact_recovery_when_difference_within_capacity() {
    // Goodrich-Mitzenmacher §3: peeling decodes when k ≥ expected diff.
    // `with_expected_difference(N)` sizes for 1.5·N cells (floored at
    // MIN_RECOMMENDED_IBLT_CELLS), which is within the paper's bound.
    let only_in_left: Vec<ObjectId> = (0..20).map(|i| obj(&format!("L{i}"))).collect();
    let only_in_right: Vec<ObjectId> = (0..15).map(|i| obj(&format!("R{i}"))).collect();
    let expected_diff = only_in_left.len() + only_in_right.len();

    // Both peers see a common set too — decoding must filter that out.
    let common: Vec<ObjectId> = (0..30).map(|i| obj(&format!("C{i}"))).collect();

    let cells = Iblt::recommended_cell_count(expected_diff);
    let left_items: Vec<_> = common.iter().chain(&only_in_left).copied().collect();
    let right_items: Vec<_> = common.iter().chain(&only_in_right).copied().collect();
    let left = build_sketch(&left_items, cells);
    let right = build_sketch(&right_items, cells);

    let diff = left.subtract(&right).expect("matching cell counts");
    let result = diff.decode();

    assert!(
        result.is_complete(),
        "MSH-IBLT-1: decode must peel to empty"
    );
    assert_eq!(
        result.only_left.iter().copied().collect::<Vec<_>>(),
        {
            let mut expected = only_in_left;
            expected.sort();
            expected
        },
        "MSH-IBLT-1: only_left must equal exact left-only difference"
    );
    assert_eq!(
        result.only_right.iter().copied().collect::<Vec<_>>(),
        {
            let mut expected = only_in_right;
            expected.sort();
            expected
        },
        "MSH-IBLT-1: only_right must equal exact right-only difference"
    );
}

// ── MSH-IBLT-2: overflow beyond capacity never silently truncates ────

#[test]
fn msh_iblt_2_over_capacity_decode_reports_incomplete_not_silent_truncation() {
    // A sketch sized for ~5 differences MUST NOT silently drop entries
    // when the true difference is much larger — it must flag
    // `is_complete() == false` so the caller can retry with a larger
    // sketch or a fallback exchange.
    let cells = Iblt::recommended_cell_count(5);
    let only_in_left: Vec<ObjectId> = (0..200).map(|i| obj(&format!("X{i}"))).collect();
    let left = build_sketch(&only_in_left, cells);
    let right = build_sketch(&[], cells);

    let diff = left.subtract(&right).unwrap();
    let result = diff.decode();
    assert!(
        !result.is_complete(),
        "MSH-IBLT-2: |diff|={} ≫ capacity {} must NOT decode to complete",
        only_in_left.len(),
        cells
    );
    assert!(
        result.remaining_nonzero_cells > 0,
        "MSH-IBLT-2: residual cells must expose the incompleteness"
    );
}

// ── MSH-IBLT-3: subtraction is anti-symmetric (A-B == swap(only_left ↔ only_right) of B-A) ──

#[test]
fn msh_iblt_3_subtraction_is_antisymmetric_for_decode() {
    let left_items: Vec<_> = ["alpha", "beta", "gamma"].iter().map(|s| obj(s)).collect();
    let right_items: Vec<_> = ["beta", "delta", "epsilon"]
        .iter()
        .map(|s| obj(s))
        .collect();
    let cells = Iblt::recommended_cell_count(4);
    let left = build_sketch(&left_items, cells);
    let right = build_sketch(&right_items, cells);

    let ab = left.subtract(&right).unwrap().decode();
    let ba = right.subtract(&left).unwrap().decode();
    assert!(ab.is_complete() && ba.is_complete());
    assert_eq!(
        ab.only_left, ba.only_right,
        "MSH-IBLT-3: (A-B).only_left == (B-A).only_right"
    );
    assert_eq!(
        ab.only_right, ba.only_left,
        "MSH-IBLT-3: (A-B).only_right == (B-A).only_left"
    );
}

// ── MSH-IBLT-4: subtract requires matching cell counts ───────────────

#[test]
fn msh_iblt_4_mismatched_cell_counts_return_structured_error() {
    let left = Iblt::with_cell_count(64).unwrap();
    let right = Iblt::with_cell_count(96).unwrap();
    let err = left
        .subtract(&right)
        .expect_err("MSH-IBLT-4: different cell counts MUST NOT silently align");
    match err {
        IbltError::CellCountMismatch { left: l, right: r } => {
            assert_eq!(l, 64);
            assert_eq!(r, 96);
        }
        other => panic!("expected CellCountMismatch, got {other:?}"),
    }
}

// ── MSH-IBLT-5: construction below IBLT_HASH_COUNT is rejected ───────

#[test]
fn msh_iblt_5_with_cell_count_rejects_below_hash_count() {
    // Fewer cells than IBLT_HASH_COUNT (3) would collapse into
    // duplicate hash positions and break the peeling invariant.
    for bad in 0..IBLT_HASH_COUNT {
        let err = Iblt::with_cell_count(bad).unwrap_err();
        assert!(matches!(err, IbltError::InvalidCellCount { got } if got == bad));
    }
    Iblt::with_cell_count(IBLT_HASH_COUNT).expect("exact IBLT_HASH_COUNT must be accepted");
}

// ── MSH-IBLT-6: self-minus-self decodes to the empty difference ──────

#[test]
fn msh_iblt_6_self_minus_self_is_empty_diff() {
    let items: Vec<_> = (0..10).map(|i| obj(&format!("S{i}"))).collect();
    let cells = Iblt::recommended_cell_count(10);
    let sketch = build_sketch(&items, cells);
    let diff = sketch.subtract(&sketch).unwrap();
    let result = diff.decode();
    assert!(result.is_complete(), "MSH-IBLT-6: self-diff must peel");
    assert!(
        result.only_left.is_empty() && result.only_right.is_empty(),
        "MSH-IBLT-6: self-diff must have no unilateral entries"
    );
}
