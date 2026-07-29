namespace Fcp.Crypto.HybridSignature

/--
TODO: refine this proposition-level hybrid verifier model into a reduction
statement for the concrete classical-plus-post-quantum envelope verifier.
-/
inductive BrokenAssumption where
  | classical
  | postQuantum
  deriving DecidableEq, Repr

structure Verification where
  classicalAuthentic : Prop
  postQuantumAuthentic : Prop

def HybridAccepts (verification : Verification) : Prop :=
  verification.classicalAuthentic /\ verification.postQuantumAuthentic

def OneBreakObserved
    (broken : BrokenAssumption)
    (verification : Verification) :
    Prop :=
  match broken with
  | BrokenAssumption.classical => Not verification.classicalAuthentic
  | BrokenAssumption.postQuantum => Not verification.postQuantumAuthentic

theorem hybrid_unforgeable_under_one_break
    (broken : BrokenAssumption)
    (verification : Verification)
    (h : OneBreakObserved broken verification) :
    Not (HybridAccepts verification) := by
  intro accepted
  cases broken with
  | classical =>
      exact h accepted.left
  | postQuantum =>
      exact h accepted.right

theorem hybrid_accepts_when_both_components_authentic
    (verification : Verification)
    (classical : verification.classicalAuthentic)
    (postQuantum : verification.postQuantumAuthentic) :
    HybridAccepts verification :=
  And.intro classical postQuantum

end Fcp.Crypto.HybridSignature
