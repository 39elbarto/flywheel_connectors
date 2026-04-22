// Compile-fail fixture: passing CapabilityToken<UnboundVerified> to a
// function that requires CapabilityToken<BoundVerified> must fail to
// compile.
//
// This is the core type-level guarantee from the jkcka epic — a token
// that has only been gateway-verified (4/5 checks) cannot reach a
// function that expects full (5/5) enforcement.

use fcp_core::{BoundVerified, CapabilityToken, UnboundVerified};

fn takes_bound(_: CapabilityToken<BoundVerified>) {}

fn main() {
    // Fabricate an UnboundVerified token reference. We can't actually
    // construct one outside the verifier, but we can reference the
    // type in an uninitialized binding for the purposes of the
    // compile error the test wants to assert.
    let t: CapabilityToken<UnboundVerified> = unimplemented!();
    takes_bound(t);
}
