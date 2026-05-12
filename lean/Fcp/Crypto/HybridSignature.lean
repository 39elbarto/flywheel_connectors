namespace Fcp.Crypto.HybridSignature

structure Adversary where
  breaksClassical : Bool
  breaksPostQuantum : Bool
  deriving DecidableEq, Repr

def CanForgeHybrid (adversary : Adversary) : Prop :=
  adversary.breaksClassical = true /\ adversary.breaksPostQuantum = true

theorem hybrid_unforgeable_under_one_break
    (adversary : Adversary)
    (hAtLeastOneStillHolds :
      adversary.breaksClassical = false \/ adversary.breaksPostQuantum = false) :
    Not (CanForgeHybrid adversary) := by
  intro hForge
  cases hForge with
  | intro hClassicalBroken hPqBroken =>
    cases hAtLeastOneStillHolds with
    | inl hClassicalSafe =>
      rw [hClassicalSafe] at hClassicalBroken
      cases hClassicalBroken
    | inr hPqSafe =>
      rw [hPqSafe] at hPqBroken
      cases hPqBroken

theorem both_breaks_are_required_for_model_forgery
    (adversary : Adversary)
    (hForge : CanForgeHybrid adversary) :
    adversary.breaksClassical = true /\ adversary.breaksPostQuantum = true :=
  hForge

end Fcp.Crypto.HybridSignature
