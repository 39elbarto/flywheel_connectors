//! jkcka.6 + m8j0q.A.6 — trybuild compile-fail tests for the
//! capability-token typestate ladder.
//!
//! These tests assert that **incorrect code does not compile**, which is
//! the whole point of typestate. A future refactor that silently widens
//! the type surface (e.g., making `BoundVerified` or `ConstraintsEnforced`
//! publicly constructible without going through the verifier + promotion
//! chain, or making the dispatch boundary accept a weaker token) will
//! fail these tests.
//!
//! Each `.rs` fixture in `tests/ui/` is a self-contained compile attempt.
//! `trybuild` runs them and diffs stderr against checked-in `.stderr`
//! expectations.
//!
//! ## Coverage matrix (current ladder)
//!
//! ```text
//!   token state             ↗ takes_bound      takes_constraints_enforced
//!   ─────────────────────────────────────────────────────────────────
//!   Unverified              compile error      compile error
//!   UnboundVerified         compile error      compile error  (this bead)
//!   BoundVerified           OK                 compile error  (this bead)
//!   ConstraintsEnforced     —                  OK             (this bead)
//! ```

#[test]
fn typestate_enforces_bound_vs_unbound_at_compile_time() {
    let t = trybuild::TestCases::new();
    // jkcka.6 — bound vs unbound enforcement
    t.compile_fail("tests/ui/unbound_cannot_reach_bound_api.rs");
    t.pass("tests/ui/promote_path_compiles.rs");

    // m8j0q.A.6 — constraints-enforced vs bound/unbound at the dispatch
    // boundary
    t.compile_fail("tests/ui/bound_cannot_reach_constraints_enforced_api.rs");
    t.compile_fail("tests/ui/unbound_cannot_reach_constraints_enforced_api.rs");
    t.pass("tests/ui/constraints_enforced_dispatch_compiles.rs");
}
