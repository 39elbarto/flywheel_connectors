//! jkcka.6 — trybuild compile-fail tests for the capability-token typestate.
//!
//! These tests assert that **incorrect code does not compile**, which is
//! the whole point of typestate. A future refactor that silently widens
//! the type surface (e.g., making `BoundVerified` publicly constructible
//! without a verifier) will fail these tests.
//!
//! Each `.rs` fixture in `tests/ui/` is a self-contained compile attempt.
//! `trybuild` runs them and diffs stderr against checked-in `.stderr`
//! expectations.

#[test]
fn typestate_enforces_bound_vs_unbound_at_compile_time() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/unbound_cannot_reach_bound_api.rs");
    t.pass("tests/ui/promote_path_compiles.rs");
}
