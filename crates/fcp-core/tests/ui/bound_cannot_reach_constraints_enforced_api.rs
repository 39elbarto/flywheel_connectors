// Compile-fail fixture: passing CapabilityToken<BoundVerified> to a
// function that requires CapabilityToken<ConstraintsEnforced> must fail
// to compile.
//
// This is the m8j0q.A.6 type-level guarantee — a token that has only
// been cryptographically verified (5/5 checks via promote_with_instance)
// cannot reach a dispatch entry that expects constraint enforcement
// to have run. Adding a new dispatch path that forgets to call
// promote_with_constraints fails CI before it can ship.

use fcp_core::{BoundVerified, CapabilityToken, ConstraintsEnforced};

fn takes_constraints_enforced(_: CapabilityToken<ConstraintsEnforced>) {}

fn main() {
    // Fabricate a BoundVerified token reference. The constructor is
    // private to fcp-core; the only legal route is through the
    // verifier + promote_with_instance chain. For the trybuild assertion
    // we don't need an actual token, just the type referenced in a
    // call site that the compiler must reject.
    let t: CapabilityToken<BoundVerified> = unimplemented!();
    takes_constraints_enforced(t);
}
