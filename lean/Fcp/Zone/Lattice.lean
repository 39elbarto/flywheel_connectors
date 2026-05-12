namespace Fcp.Zone.Lattice

/--
TODO: strengthen this model from natural-number zone levels to the full
connector zone-flow lattice once the follow-on proof bead lands.
-/
structure ZoneFlow where
  sourceLevel : Nat
  targetLevel : Nat
  deriving DecidableEq, Repr

def FlowAllowed (flow : ZoneFlow) : Prop :=
  flow.targetLevel <= flow.sourceLevel

def FlowSound (flow : ZoneFlow) : Prop :=
  flow.targetLevel <= flow.sourceLevel

theorem zone_flow_soundness
    (flow : ZoneFlow)
    (h : FlowAllowed flow) :
    FlowSound flow :=
  h

theorem zone_flow_identity_allowed
    (level : Nat) :
    FlowAllowed { sourceLevel := level, targetLevel := level } :=
  Nat.le_refl level

end Fcp.Zone.Lattice
