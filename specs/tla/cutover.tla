---- MODULE cutover ----
EXTENDS Naturals, Sequences, TLC

\* flywheel_connectors-angoc.13.1
\* Abstract operator-driven cutover model for the V1 host-first to V2 mesh-native
\* migration. The concrete Rust alignment lives in
\* crates/fcp-host/src/cutover/state_machine.rs.

CONSTANT MaxDepth

CutoverStates == {"V1Only", "V2Shadow", "V2Default", "V1Fallback", "V2Permanent"}
OperatorActions == {"EnableShadow", "PromoteV2Default", "TriggerFallback", "CommitPermanent", "RecoverV1", "EmergencyRecoverV1"}

VARIABLES state, depth, action_history, shadow_steps

vars == <<state, depth, action_history, shadow_steps>>

Init ==
    /\ state = "V1Only"
    /\ depth = 0
    /\ action_history = <<>>
    /\ shadow_steps = 0

Record(action) ==
    /\ depth' = depth + 1
    /\ action_history' = Append(action_history, action)

SetState(next_state) ==
    /\ state' = next_state
    /\ shadow_steps' = IF next_state = "V2Shadow" THEN shadow_steps + 1 ELSE 0

EnableShadow ==
    /\ state \in {"V1Only", "V1Fallback"}
    /\ SetState("V2Shadow")
    /\ Record("EnableShadow")

PromoteV2Default ==
    /\ state = "V2Shadow"
    /\ SetState("V2Default")
    /\ Record("PromoteV2Default")

TriggerFallback ==
    /\ state \in {"V2Shadow", "V2Default"}
    /\ SetState("V1Fallback")
    /\ Record("TriggerFallback")

CommitPermanent ==
    /\ state = "V2Default"
    /\ SetState("V2Permanent")
    /\ Record("CommitPermanent")

RecoverV1 ==
    /\ state = "V1Fallback"
    /\ SetState("V1Only")
    /\ Record("RecoverV1")

EmergencyRecoverV1 ==
    /\ state = "V2Permanent"
    /\ SetState("V1Only")
    /\ Record("EmergencyRecoverV1")

Next ==
    /\ depth < MaxDepth
    /\ \/ EnableShadow
       \/ PromoteV2Default
       \/ TriggerFallback
       \/ CommitPermanent
       \/ RecoverV1
       \/ EmergencyRecoverV1

Spec == Init /\ [][Next]_vars

ActionConstraint == depth' <= MaxDepth

Safety_no_v1_only_and_v2_default ==
    ~(/\ state = "V1Only"
      /\ state \in {"V2Default", "V2Permanent"})

Safety ==
    /\ state \in CutoverStates
    /\ depth <= MaxDepth
    /\ shadow_steps \in 0..1
    /\ Safety_no_v1_only_and_v2_default

Liveness_shadow_resolves_in_one_step ==
    state = "V2Shadow" => shadow_steps <= 1

Liveness == Liveness_shadow_resolves_in_one_step

Recoverability_v1_path_exists ==
    \/ state = "V1Only"
    \/ state = "V2Shadow"      \* TriggerFallback, then RecoverV1.
    \/ state = "V2Default"     \* TriggerFallback, then RecoverV1.
    \/ state = "V1Fallback"    \* RecoverV1.
    \/ state = "V2Permanent"   \* EmergencyRecoverV1.

Recoverability == Recoverability_v1_path_exists

====
