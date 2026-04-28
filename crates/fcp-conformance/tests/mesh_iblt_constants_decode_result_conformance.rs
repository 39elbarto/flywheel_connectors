//! `fcp_mesh::iblt` constants + `recommended_cell_count` formula +
//! `IbltDecodeResult` contract conformance.
//!
//! `mesh_iblt_conformance.rs` already covers the decode behaviour
//! (recovery, mismatch, hash-count gate). This file pins the
//! foundational constants and the cell-budget formula that every
//! mesh-gossip node uses to size sketches:
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`IBLT_HASH_COUNT == 3`** — three independent hash positions
//!    per key. Drift would silently break the peeling invariant.
//! 2. **`MIN_RECOMMENDED_IBLT_CELLS == 64`** — the production
//!    minimum cell budget; smaller sketches under-fit common
//!    differences.
//! 3. **`recommended_cell_count(0) == MIN_RECOMMENDED_IBLT_CELLS`**
//!    (the floor).
//! 4. **`recommended_cell_count(N)` formula**: returns
//!    `max(MIN, ceil(3 * N / 2))` — covers 1.5x cell-per-difference
//!    overhead. Pin via known-input/output table.
//! 5. **`recommended_cell_count` saturates on `usize::MAX`** and
//!    does NOT panic on overflow.
//! 6. **`Iblt::default()` == `with_expected_difference(0)`** —
//!    yields a 64-cell sketch.
//! 7. **`IbltDecodeResult::default`** has empty diff sets,
//!    `complete=false`, `remaining_nonzero_cells=0`.
//! 8. **`IbltDecodeResult::is_complete()` reflects the `complete`
//!    field**.
//! 9. **`IbltError::InvalidCellCount` Display** contains
//!    "iblt cell count must be at least 3" + the bad value.
//! 10. **`IbltError::CellCountMismatch` Display** contains both
//!     left and right cell counts.

use fcp_core::ObjectId;
use fcp_mesh::iblt::{
    IBLT_HASH_COUNT, Iblt, IbltCell, IbltDecodeResult, IbltError, MIN_RECOMMENDED_IBLT_CELLS,
};

// ─── Constants ─────────────────────────────────────────────────────

#[test]
fn iblt_hash_count_is_three() {
    assert_eq!(
        IBLT_HASH_COUNT, 3,
        "IBLT_HASH_COUNT MUST be 3 — drift breaks the peeling invariant \
         (insert applies to 3 distinct cells; <3 would alias)"
    );
}

#[test]
fn min_recommended_iblt_cells_is_sixty_four() {
    assert_eq!(
        MIN_RECOMMENDED_IBLT_CELLS, 64,
        "production minimum cell budget MUST be 64"
    );
}

// ─── recommended_cell_count formula ───────────────────────────────

#[test]
fn recommended_cell_count_zero_returns_min_floor() {
    assert_eq!(
        Iblt::recommended_cell_count(0),
        MIN_RECOMMENDED_IBLT_CELLS,
        "expected_difference=0 MUST floor at MIN (64)"
    );
}

#[test]
fn recommended_cell_count_below_floor_returns_min() {
    // The formula `(N * 3 + 1) / 2` floors at 64 for small N.
    // For N=10: 31/2 = 15 < 64, so result MUST be 64.
    for n in [1, 5, 10, 20, 40] {
        assert_eq!(
            Iblt::recommended_cell_count(n),
            MIN_RECOMMENDED_IBLT_CELLS,
            "expected_difference={n} → ({n}*3+1)/2 < 64, MUST floor at MIN"
        );
    }
}

#[test]
fn recommended_cell_count_above_floor_uses_three_halves_formula() {
    // For N where (N*3+1)/2 > 64, formula wins.
    // N=43: (43*3+1)/2 = 130/2 = 65 — first value above floor.
    // N=100: (100*3+1)/2 = 301/2 = 150.
    // N=1000: (1000*3+1)/2 = 3001/2 = 1500.
    let cases = [
        (43_usize, 65_usize),
        (100, 150),
        (1000, 1500),
        (10_000, 15_000),
    ];
    for (n, expected) in cases {
        assert_eq!(
            Iblt::recommended_cell_count(n),
            expected,
            "recommended_cell_count({n}) MUST equal (3*{n}+1)/2 = {expected}"
        );
    }
}

#[test]
fn recommended_cell_count_saturates_on_usize_max_without_panic() {
    // The implementation uses saturating_mul/saturating_add so it
    // MUST NOT panic at usize::MAX.
    let result = Iblt::recommended_cell_count(usize::MAX);
    assert!(
        result > MIN_RECOMMENDED_IBLT_CELLS,
        "saturated result MUST be far above MIN; got {result}"
    );
}

#[test]
fn recommended_cell_count_is_const_fn() {
    // const fn surface — pin via use in const context.
    const COUNT: usize = Iblt::recommended_cell_count(100);
    assert_eq!(COUNT, 150);
}

// ─── Iblt::default ────────────────────────────────────────────────

#[test]
fn iblt_default_equals_with_expected_difference_zero() {
    let default_iblt = Iblt::default();
    let zero_diff = Iblt::with_expected_difference(0);
    assert_eq!(default_iblt.cell_count(), zero_diff.cell_count());
    assert_eq!(
        default_iblt.cell_count(),
        MIN_RECOMMENDED_IBLT_CELLS,
        "Iblt::default() MUST yield a sketch with MIN_RECOMMENDED_IBLT_CELLS cells"
    );
}

#[test]
fn iblt_with_cell_count_rejects_below_hash_count() {
    for cells in [0, 1, 2] {
        let r = Iblt::with_cell_count(cells);
        let err = r.expect_err("MUST fail");
        match err {
            IbltError::InvalidCellCount { got } => assert_eq!(got, cells),
            other => panic!("expected InvalidCellCount, got {other:?}"),
        }
    }
}

#[test]
fn iblt_with_cell_count_accepts_exactly_three() {
    let r = Iblt::with_cell_count(3);
    assert!(r.is_ok(), "exactly IBLT_HASH_COUNT (3) MUST be accepted");
}

// ─── IbltDecodeResult ─────────────────────────────────────────────

#[test]
fn decode_result_default_is_empty_and_incomplete() {
    let r = IbltDecodeResult::default();
    assert!(r.only_left.is_empty());
    assert!(r.only_right.is_empty());
    assert!(
        !r.complete,
        "default decode result MUST be incomplete (Default value)"
    );
    assert_eq!(r.remaining_nonzero_cells, 0);
    assert!(!r.is_complete());
}

#[test]
fn decode_result_is_complete_reflects_complete_field() {
    let r = IbltDecodeResult {
        only_left: std::collections::BTreeSet::new(),
        only_right: std::collections::BTreeSet::new(),
        complete: true,
        remaining_nonzero_cells: 0,
    };
    assert!(r.is_complete());

    let r2 = IbltDecodeResult {
        only_left: std::collections::BTreeSet::new(),
        only_right: std::collections::BTreeSet::new(),
        complete: false,
        remaining_nonzero_cells: 5,
    };
    assert!(!r2.is_complete());
}

#[test]
fn decode_result_partial_eq_compares_all_fields() {
    let mut left = std::collections::BTreeSet::new();
    left.insert(ObjectId::from_bytes([1u8; 32]));
    let a = IbltDecodeResult {
        only_left: left.clone(),
        only_right: std::collections::BTreeSet::new(),
        complete: true,
        remaining_nonzero_cells: 0,
    };
    let b = IbltDecodeResult {
        only_left: left,
        only_right: std::collections::BTreeSet::new(),
        complete: true,
        remaining_nonzero_cells: 0,
    };
    let c = IbltDecodeResult {
        only_left: std::collections::BTreeSet::new(),
        only_right: std::collections::BTreeSet::new(),
        complete: true,
        remaining_nonzero_cells: 0,
    };
    assert_eq!(a, b);
    assert_ne!(a, c, "different only_left MUST register on PartialEq");
}

// ─── IbltCell ──────────────────────────────────────────────────────

#[test]
fn iblt_cell_default_is_zero_count_zero_keysum_zero_hashcheck() {
    let c = IbltCell::default();
    assert_eq!(c.count, 0);
    assert_eq!(c.key_sum, [0u8; 32]);
    assert_eq!(c.hash_check, 0);
}

#[test]
fn iblt_cell_serde_roundtrip_preserves_all_fields() {
    let c = IbltCell {
        count: -7,
        key_sum: [42u8; 32],
        hash_check: 0xDEADBEEF,
    };
    let json_str = serde_json::to_string(&c).expect("serialize");
    let parsed: IbltCell = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, c);
}

// ─── IbltError Display ────────────────────────────────────────────

#[test]
fn iblt_error_invalid_cell_count_display_includes_keyword_and_value() {
    let err = IbltError::InvalidCellCount { got: 2 };
    let s = format!("{err}");
    assert!(
        s.contains("iblt cell count must be at least 3"),
        "Display MUST include guard literal 'iblt cell count must be at least 3'; got {s}"
    );
    assert!(s.contains("got 2"), "got {s}");
}

#[test]
fn iblt_error_cell_count_mismatch_display_includes_both_counts() {
    let err = IbltError::CellCountMismatch {
        left: 64,
        right: 96,
    };
    let s = format!("{err}");
    assert!(
        s.contains("cell count mismatch"),
        "Display MUST include 'cell count mismatch'; got {s}"
    );
    assert!(s.contains("64"), "got {s}");
    assert!(s.contains("96"), "got {s}");
}

#[test]
fn iblt_error_implements_copy() {
    fn takes_value(_: IbltError) {}
    let e = IbltError::InvalidCellCount { got: 1 };
    takes_value(e);
    takes_value(e);
}

#[test]
fn iblt_error_partial_eq_compares_payloads() {
    let a = IbltError::CellCountMismatch {
        left: 10,
        right: 20,
    };
    let b = IbltError::CellCountMismatch {
        left: 10,
        right: 20,
    };
    let c = IbltError::CellCountMismatch {
        left: 10,
        right: 30,
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}
