namespace Fcp.Zone.Lattice

/-- A compact confidentiality lattice model.

Larger natural numbers represent more restrictive zones. A flow is allowed only
when the target is no more restrictive than the source; explicit
declassification is modeled outside this proof obligation. -/
structure ZoneFlow where
  sourceLevel : Nat
  targetLevel : Nat
  deriving DecidableEq, Repr

inductive CapClass where
  | direct
  | transitive
  deriving DecidableEq, Repr

inductive ZoneCheck where
  | pass
  | deny
  deriving DecidableEq, Repr

structure Trace where
  sourceLevel : Nat
  targetLevel : Nat
  deriving DecidableEq, Repr

structure Operation where
  flow : ZoneFlow
  capability : CapClass
  trace : Trace
  deriving DecidableEq, Repr

structure Leak where
  sourceLevel : Nat
  targetLevel : Nat
  deriving DecidableEq, Repr

structure CapabilityWitness where
  fromLevel : Nat
  viaLevel : Nat
  toLevel : Nat
  deriving DecidableEq, Repr

def ZoneJoin (left right : Nat) : Nat :=
  Nat.max left right

def capability_allows (sourceLevel targetLevel : Nat) (_capability : CapClass) : Prop :=
  targetLevel <= sourceLevel

def FlowAllowed (flow : ZoneFlow) : Prop :=
  capability_allows flow.sourceLevel flow.targetLevel CapClass.direct

instance (flow : ZoneFlow) : Decidable (FlowAllowed flow) := by
  unfold FlowAllowed capability_allows
  infer_instance

def FlowSound (flow : ZoneFlow) : Prop :=
  flow.targetLevel <= flow.sourceLevel

def zone_check (op : Operation) : ZoneCheck :=
  if FlowAllowed op.flow then ZoneCheck.pass else ZoneCheck.deny

def reachable (op : Operation) (leak : Leak) : Prop :=
  leak.sourceLevel = op.flow.sourceLevel /\
    leak.targetLevel = op.flow.targetLevel /\
    leak.sourceLevel < leak.targetLevel

def no_secret_leaked (sourceLevel targetLevel : Nat) (_trace : Trace) : Prop :=
  ¬ sourceLevel < targetLevel

theorem lattice_join_lemma
    (left right : Nat) :
    left <= ZoneJoin left right /\ right <= ZoneJoin left right := by
  constructor
  · exact Nat.le_max_left left right
  · exact Nat.le_max_right left right

theorem capability_transport_lemma
    (sourceLevel viaLevel targetLevel : Nat)
    (hFirst : capability_allows sourceLevel viaLevel CapClass.direct)
    (hSecond : capability_allows viaLevel targetLevel CapClass.direct) :
    capability_allows sourceLevel targetLevel CapClass.transitive :=
  Nat.le_trans hSecond hFirst

theorem no_silent_downgrade_lemma
    (flow : ZoneFlow)
    (h : FlowAllowed flow) :
    ¬ flow.sourceLevel < flow.targetLevel :=
  Nat.not_lt.mpr h

theorem zone_flow_soundness
    (flow : ZoneFlow)
    (h : FlowAllowed flow) :
    FlowSound flow :=
  h

theorem zone_flow_identity_allowed
    (level : Nat) :
    FlowAllowed { sourceLevel := level, targetLevel := level } :=
  Nat.le_refl level

theorem zone_isolation_invariant
    (op : Operation)
    (h : zone_check op = ZoneCheck.pass) :
    no_secret_leaked op.flow.sourceLevel op.flow.targetLevel op.trace := by
  unfold no_secret_leaked
  unfold zone_check at h
  by_cases allowed : FlowAllowed op.flow
  · exact no_silent_downgrade_lemma op.flow allowed
  · simp [allowed] at h

theorem zone_lattice_sound
    (op : Operation)
    (h : zone_check op = ZoneCheck.pass) :
    ¬ ∃ leak : Leak, reachable op leak := by
  unfold zone_check at h
  by_cases allowed : FlowAllowed op.flow
  · intro hLeakExists
    rcases hLeakExists with ⟨leak, hSource, hTarget, hOrder⟩
    have downgrade : op.flow.sourceLevel < op.flow.targetLevel := by
      rw [hSource, hTarget] at hOrder
      exact hOrder
    exact no_silent_downgrade_lemma op.flow allowed downgrade
  · simp [allowed] at h

theorem no_self_loop_leak
    (level : Nat) :
    ¬ ∃ leak : Leak,
      reachable
        { flow := { sourceLevel := level, targetLevel := level },
          capability := CapClass.direct,
          trace := { sourceLevel := level, targetLevel := level } }
        leak := by
  intro hLeakExists
  rcases hLeakExists with ⟨leak, hSource, hTarget, hOrder⟩
  have selfLoop : level < level := by
    rw [hSource, hTarget] at hOrder
    exact hOrder
  exact Nat.lt_irrefl level selfLoop

theorem transitive_capability_implies_witness
    (sourceLevel viaLevel targetLevel : Nat)
    (hFirst : capability_allows sourceLevel viaLevel CapClass.direct)
    (hSecond : capability_allows viaLevel targetLevel CapClass.direct) :
    ∃ witness : CapabilityWitness,
      witness.fromLevel = sourceLevel /\
        witness.viaLevel = viaLevel /\
        witness.toLevel = targetLevel /\
        capability_allows sourceLevel targetLevel CapClass.transitive := by
  refine
    ⟨{ fromLevel := sourceLevel, viaLevel := viaLevel, toLevel := targetLevel },
      rfl,
      rfl,
      rfl,
      ?_⟩
  exact capability_transport_lemma sourceLevel viaLevel targetLevel hFirst hSecond

end Fcp.Zone.Lattice
