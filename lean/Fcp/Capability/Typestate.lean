namespace Fcp.Capability.Typestate

/--
TODO: connect this stage graph to the Rust `CapabilityToken` typestate witness
schema so the Lean statement tracks the production verifier boundary.
-/
inductive Stage where
  | unboundVerified
  | boundVerified
  | constraintsEnforced
  deriving DecidableEq, Repr

open Stage

inductive Step : Stage -> Stage -> Prop where
  | promoteWithInstance : Step unboundVerified boundVerified
  | enforceConstraints : Step boundVerified constraintsEnforced

theorem typestate_progression_no_skip :
    Not (Step unboundVerified constraintsEnforced) := by
  intro h
  cases h

theorem typestate_promote_reaches_bound :
    Step unboundVerified boundVerified :=
  Step.promoteWithInstance

end Fcp.Capability.Typestate
