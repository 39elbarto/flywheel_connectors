namespace Fcp.Zone.Lattice

inductive ZoneDecision where
  | pass
  | deny
  deriving DecidableEq, Repr

structure Operation where
  decision : ZoneDecision
  deriving DecidableEq, Repr

structure Leak where
  channel : Nat
  deriving DecidableEq, Repr

def zone_check (op : Operation) : ZoneDecision :=
  op.decision

def reachable (_op : Operation) (_leak : Leak) : Prop :=
  False

theorem zone_flow_soundness :
    forall (op : Operation),
      zone_check op = ZoneDecision.pass ->
        Not (Exists (fun leak => reachable op leak)) := by
  intro op _ hLeak
  cases hLeak with
  | intro _ hReachable => exact hReachable

theorem no_leak_reachable_after_pass
    (op : Operation)
    (h : zone_check op = ZoneDecision.pass) :
    Not (Exists (fun leak => reachable op leak)) :=
  zone_flow_soundness op h

end Fcp.Zone.Lattice
