// Positive trybuild fixture: the gateway→connector promotion path
// type-checks cleanly.
//
// This is the counterpart to `unbound_cannot_reach_bound_api.rs`: the
// CORRECT code must compile, or we've over-tightened the types.

use fcp_core::{BoundVerified, CapabilityToken, InstanceId, UnboundVerified};

fn takes_bound(_: CapabilityToken<BoundVerified>) {}

fn _do_handoff(
    unbound: CapabilityToken<UnboundVerified>,
    connector_instance: &InstanceId,
) -> fcp_core::FcpResult<()> {
    let bound = unbound.promote_with_instance(connector_instance)?;
    takes_bound(bound);
    Ok(())
}

fn main() {}
