// Compile-fail fixture: passing CapabilityToken<UnboundVerified> to a
// function that requires CapabilityToken<ConstraintsEnforced> must fail
// to compile.
//
// Belt-and-braces sibling of bound_cannot_reach_constraints_enforced_api.rs:
// even the gateway-vantage typestate is rejected at the dispatch
// boundary. The full chain (verify_unbound → promote_with_instance →
// promote_with_constraints) is the ONLY path that produces a token
// satisfying the dispatch signature.

use fcp_core::{CapabilityToken, ConstraintsEnforced, UnboundVerified};

fn takes_constraints_enforced(_: CapabilityToken<ConstraintsEnforced>) {}

fn main() {
    let t: CapabilityToken<UnboundVerified> = unimplemented!();
    takes_constraints_enforced(t);
}
