// Positive trybuild fixture: the full
// verify_unbound → promote_with_instance → promote_with_constraints
// → dispatch chain type-checks cleanly.
//
// Counterpart to the compile-fail fixtures: the CORRECT code MUST
// compile, or we've over-tightened the types and made enforcement
// impossible to express.

use fcp_core::{
    BoundVerified, CapabilityConstraintEvaluator, CapabilityConstraints, CapabilityToken,
    ConstraintsEnforced, FcpResult, InstanceId, UnboundVerified,
};

#[derive(Debug)]
struct ToyDenialReason;

struct ToyAllowEnforcer;

impl CapabilityConstraintEvaluator<()> for ToyAllowEnforcer {
    type Denial = ToyDenialReason;

    fn evaluate_constraints(
        &self,
        constraints: &CapabilityConstraints,
        _request: &(),
    ) -> Result<(), Self::Denial> {
        assert!(!constraints.resource_allow.is_empty());
        Ok(())
    }
}

fn takes_constraints_enforced(_: CapabilityToken<ConstraintsEnforced>) {}

fn _do_full_chain(
    unbound: CapabilityToken<UnboundVerified>,
    connector_instance: &InstanceId,
) -> FcpResult<()> {
    // Step 1: gateway → connector handoff (jkcka.A — already shipped).
    let bound: CapabilityToken<BoundVerified> =
        unbound.promote_with_instance(connector_instance)?;

    // Step 2: constraint enforcement (m8j0q.A.6 — this bead). In
    // production the evaluator is typically fcp_policy::DefaultConstraintEnforcer.
    // Returning Ok(()) is the explicit witness that ConstraintEvaluation::Allow
    // was produced.
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let enforced: CapabilityToken<ConstraintsEnforced> = bound
        .promote_with_constraints(&ToyAllowEnforcer, &constraints, &())
        .expect("toy evaluator always allows in this fixture");

    // Step 3: dispatch — only ConstraintsEnforced satisfies the boundary.
    takes_constraints_enforced(enforced);
    Ok(())
}

fn main() {}
