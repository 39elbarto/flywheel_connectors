namespace Fcp.Capability.Typestate

/--
Compile-time verifier stages mirrored by `CapabilityToken<S>`.
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

/--
Runtime lifecycle states mirrored by
`fcp_core::capability::CapabilityLifecycleState`.
-/
inductive CapState where
  | pending
  | approved
  | used
  | revoked
  | expired
  deriving DecidableEq, Repr

namespace CapState

def rustTag : CapState -> String
  | pending => "Pending"
  | approved => "Approved"
  | used => "Used"
  | revoked => "Revoked"
  | expired => "Expired"

end CapState

open CapState

/--
Abstract lifecycle transitions mirrored by
`CapabilityLifecycleTransition` and `CAPABILITY_LIFECYCLE_TRANSITIONS`.
-/
inductive LifecycleStep : CapState -> CapState -> Prop where
  | approve : LifecycleStep pending approved
  | useApproved : LifecycleStep approved used
  | revokePending : LifecycleStep pending revoked
  | revokeApproved : LifecycleStep approved revoked
  | expirePending : LifecycleStep pending expired
  | expireApproved : LifecycleStep approved expired
  | revocationObserved : LifecycleStep revoked revoked

def terminal : CapState -> Prop
  | used => True
  | revoked => True
  | expired => True
  | pending => False
  | approved => False

inductive WellTyped : CapState -> Prop where
  | pending : WellTyped pending
  | approved : WellTyped approved
  | used : WellTyped used
  | revoked : WellTyped revoked
  | expired : WellTyped expired

theorem capability_progress :
    forall s : CapState, terminal s \/ exists s' : CapState, LifecycleStep s s' := by
  intro s
  cases s with
  | pending =>
      right
      exact Exists.intro approved LifecycleStep.approve
  | approved =>
      right
      exact Exists.intro used LifecycleStep.useApproved
  | used =>
      left
      trivial
  | revoked =>
      left
      trivial
  | expired =>
      left
      trivial

theorem capability_preservation :
    forall {s s' : CapState}, WellTyped s -> LifecycleStep s s' -> WellTyped s' := by
  intro s s' _ hstep
  cases hstep with
  | approve => exact WellTyped.approved
  | useApproved => exact WellTyped.used
  | revokePending => exact WellTyped.revoked
  | revokeApproved => exact WellTyped.revoked
  | expirePending => exact WellTyped.expired
  | expireApproved => exact WellTyped.expired
  | revocationObserved => exact WellTyped.revoked

theorem revocation_is_absorbing :
    forall {s : CapState}, LifecycleStep revoked s -> s = revoked := by
  intro s hstep
  cases hstep
  rfl

theorem no_use_after_revoke :
    forall {s : CapState}, LifecycleStep revoked s -> Not (s = used) := by
  intro s hstep
  have h : s = revoked := revocation_is_absorbing hstep
  intro hused
  rw [hused] at h
  cases h

theorem approved_use_only_from_approved :
    forall {s : CapState}, LifecycleStep s used -> s = approved := by
  intro s hstep
  cases hstep
  rfl

end Fcp.Capability.Typestate
