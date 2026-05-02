namespace Fcp.Invariants.Revocation

structure RevocationSeal where
  epoch : Nat
  revoked : Bool
  deriving DecidableEq, Repr

structure DispatchRecord where
  acquiredEpoch : Nat
  dispatchedEpoch : Nat
  revokedAtDispatch : Bool
  deriving DecidableEq, Repr

def CanDispatch (revocationSeal : RevocationSeal) (currentEpoch : Nat) : Prop :=
  revocationSeal.revoked = false /\ revocationSeal.epoch = currentEpoch

def AtomicDispatch (record : DispatchRecord) : Prop :=
  record.acquiredEpoch = record.dispatchedEpoch /\ record.revokedAtDispatch = false

theorem revoked_seal_cannot_dispatch
    {epoch : Nat} :
    Not (CanDispatch { epoch := epoch, revoked := true } epoch) := by
  intro h
  cases h.left

theorem dispatch_epoch_matches_observed
    {revocationSeal : RevocationSeal}
    {currentEpoch : Nat}
    (h : CanDispatch revocationSeal currentEpoch) :
    revocationSeal.epoch = currentEpoch :=
  h.right

theorem revocation_seal_check_use_atomicity
    {record : DispatchRecord}
    (h : AtomicDispatch record) :
    record.acquiredEpoch = record.dispatchedEpoch /\ record.revokedAtDispatch = false :=
  h

end Fcp.Invariants.Revocation
