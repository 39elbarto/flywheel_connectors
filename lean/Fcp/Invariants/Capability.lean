namespace Fcp.Invariants.Capability

inductive TokenStage where
  | unboundVerified
  | boundVerified
  | constraintsEnforced
  deriving DecidableEq, Repr

open TokenStage

inductive Step : TokenStage -> TokenStage -> Prop where
  | promoteWithInstance : Step unboundVerified boundVerified
  | enforceConstraints : Step boundVerified constraintsEnforced

def SoundTwoStep (first middle final : TokenStage) : Prop :=
  Step first middle /\ Step middle final

theorem no_direct_unbound_to_constraints :
    Not (Step unboundVerified constraintsEnforced) := by
  intro h
  cases h

theorem constraints_enforced_predecessor_is_bound
    {stage : TokenStage}
    (h : Step stage constraintsEnforced) :
    stage = boundVerified := by
  cases h
  rfl

theorem bound_verified_predecessor_is_unbound
    {stage : TokenStage}
    (h : Step stage boundVerified) :
    stage = unboundVerified := by
  cases h
  rfl

theorem capability_token_ladder_composes_only_through_bound
    {middle : TokenStage}
    (h : SoundTwoStep unboundVerified middle constraintsEnforced) :
    middle = boundVerified :=
  constraints_enforced_predecessor_is_bound h.right

end Fcp.Invariants.Capability
