namespace Fcp.Capability.Typestate

inductive TokenStage where
  | unverified
  | unboundVerified
  | boundVerified
  | constraintsEnforced
  deriving DecidableEq, Repr

open TokenStage

inductive Step : TokenStage -> TokenStage -> Prop where
  | verify : Step unverified unboundVerified
  | promoteWithInstance : Step unboundVerified boundVerified
  | enforceConstraints : Step boundVerified constraintsEnforced

theorem typestate_progression_no_skip :
    Not (Step unverified constraintsEnforced) := by
  intro h
  cases h

theorem constraints_enforced_requires_bound
    {stage : TokenStage}
    (h : Step stage constraintsEnforced) :
    stage = boundVerified := by
  cases h
  rfl

end Fcp.Capability.Typestate
