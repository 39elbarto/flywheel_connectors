---- MODULE capability_lifecycle_broken ----
EXTENDS Naturals, Sequences, TLC

\* Broken fixture for flywheel_connectors-angoc.13.2. It deliberately permits
\* a revoked token to emit an operation receipt so TLC catches RevokeBeforeUse.

CONSTANTS MaxDepth, RevocationPropagationBound

CapabilityStates == {"Pending", "Approved", "Used", "Revoked", "Expired"}
CapabilityActions == {"Approve", "UseAndEmitReceipt", "RevokePending", "RevokeApproved", "ExpirePending", "ExpireApproved", "PushRevocation", "AdvanceRevocationClock"}
CapabilityTransitions == {<<"Pending", "Approved">>, <<"Approved", "Used">>, <<"Pending", "Revoked">>, <<"Approved", "Revoked">>, <<"Pending", "Expired">>, <<"Approved", "Expired">>, <<"Revoked", "Revoked">>}

VARIABLES state, depth, action_history, used_receipts, receipt_emitted, revoked_seen, revocation_pending, revocation_age

vars == <<state, depth, action_history, used_receipts, receipt_emitted, revoked_seen, revocation_pending, revocation_age>>

Init ==
    /\ state = "Pending"
    /\ depth = 0
    /\ action_history = <<>>
    /\ used_receipts = 0
    /\ receipt_emitted = FALSE
    /\ revoked_seen = FALSE
    /\ revocation_pending = FALSE
    /\ revocation_age = 0

Record(action) ==
    /\ depth' = depth + 1
    /\ action_history' = Append(action_history, action)

KeepReceipt ==
    /\ used_receipts' = used_receipts
    /\ receipt_emitted' = receipt_emitted

KeepRevocation ==
    /\ revoked_seen' = revoked_seen
    /\ revocation_pending' = revocation_pending
    /\ revocation_age' = revocation_age

ClearRevocation ==
    /\ revoked_seen' = revoked_seen
    /\ revocation_pending' = FALSE
    /\ revocation_age' = 0

Approve ==
    /\ state = "Pending"
    /\ state' = "Approved"
    /\ KeepReceipt
    /\ KeepRevocation
    /\ Record("Approve")

UseAndEmitReceipt ==
    /\ state = "Approved"
    /\ used_receipts = 0
    /\ state' = "Used"
    /\ used_receipts' = 1
    /\ receipt_emitted' = TRUE
    /\ ClearRevocation
    /\ Record("UseAndEmitReceipt")

UseAfterRevoke ==
    /\ state = "Revoked"
    /\ used_receipts = 0
    /\ state' = "Used"
    /\ used_receipts' = 1
    /\ receipt_emitted' = TRUE
    /\ revoked_seen' = revoked_seen
    /\ revocation_pending' = revocation_pending
    /\ revocation_age' = revocation_age
    /\ Record("UseAndEmitReceipt")

RevokePending ==
    /\ state = "Pending"
    /\ state' = "Revoked"
    /\ KeepReceipt
    /\ revoked_seen' = TRUE
    /\ revocation_pending' = TRUE
    /\ revocation_age' = 0
    /\ Record("RevokePending")

RevokeApproved ==
    /\ state = "Approved"
    /\ state' = "Revoked"
    /\ KeepReceipt
    /\ revoked_seen' = TRUE
    /\ revocation_pending' = TRUE
    /\ revocation_age' = 0
    /\ Record("RevokeApproved")

ExpirePending ==
    /\ state = "Pending"
    /\ state' = "Expired"
    /\ KeepReceipt
    /\ ClearRevocation
    /\ Record("ExpirePending")

ExpireApproved ==
    /\ state = "Approved"
    /\ state' = "Expired"
    /\ KeepReceipt
    /\ ClearRevocation
    /\ Record("ExpireApproved")

PushRevocation ==
    /\ state = "Revoked"
    /\ revocation_pending
    /\ state' = state
    /\ KeepReceipt
    /\ revoked_seen' = revoked_seen
    /\ revocation_pending' = FALSE
    /\ revocation_age' = 0
    /\ Record("PushRevocation")

AdvanceRevocationClock ==
    /\ state = "Revoked"
    /\ revocation_pending
    /\ revocation_age < RevocationPropagationBound
    /\ state' = state
    /\ KeepReceipt
    /\ revoked_seen' = revoked_seen
    /\ revocation_pending' = TRUE
    /\ revocation_age' = revocation_age + 1
    /\ Record("AdvanceRevocationClock")

Next ==
    /\ depth < MaxDepth
    /\ \/ Approve
       \/ UseAndEmitReceipt
       \/ UseAfterRevoke
       \/ RevokePending
       \/ RevokeApproved
       \/ ExpirePending
       \/ ExpireApproved
       \/ PushRevocation
       \/ AdvanceRevocationClock

Spec == Init /\ [][Next]_vars

ActionConstraint == depth' <= MaxDepth

RevokeBeforeUse ==
    revoked_seen => used_receipts = 0

NoDoubleSpend ==
    used_receipts \in 0..1

RevocationPropagationSLO ==
    revocation_pending => revocation_age <= RevocationPropagationBound

ActionHistoryValid ==
    \A idx \in 1..Len(action_history): action_history[idx] \in CapabilityActions

Safety ==
    /\ state \in CapabilityStates
    /\ depth <= MaxDepth
    /\ ActionHistoryValid
    /\ receipt_emitted \in BOOLEAN
    /\ revoked_seen \in BOOLEAN
    /\ revocation_pending \in BOOLEAN
    /\ revocation_age \in 0..RevocationPropagationBound
    /\ RevokeBeforeUse
    /\ NoDoubleSpend
    /\ RevocationPropagationSLO

====
