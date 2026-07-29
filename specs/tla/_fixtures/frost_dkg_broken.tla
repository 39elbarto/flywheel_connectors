---- MODULE frost_dkg_broken ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Deliberately broken fixture for flywheel_connectors-angoc.13.3. The
\* production spec's Finalize action requires `faulty_seen = {}` —
\* you cannot emit a key after detecting any malicious share. This
\* fixture drops that guard so Finalize can fire even when malicious
\* participants have been detected. TLC must surface a
\* `SafetyFaultyImpliesAbort` counter-example (or `SafetyNoKeyAfterAbort`
\* / `Safety` more generally).
\*
\* The Makefile broken target greps for the violation pattern. If
\* TLC accepts this fixture, the production safety properties are
\* too weak to catch malicious-share-then-finalize behavior.

CONSTANTS Participants, Honest, Threshold

ASSUME
    /\ Honest \subseteq Participants
    /\ Threshold \in 1..Cardinality(Participants)
    /\ Cardinality(Honest) >= Threshold

Phases == {"Round1Commit", "Round2Share", "Round3Verify",
           "Finalized", "Aborted"}

VARIABLES phase, commits, shares, verified, faulty_seen, final_key

vars == <<phase, commits, shares, verified, faulty_seen, final_key>>

Init ==
    /\ phase = "Round1Commit"
    /\ commits = {}
    /\ shares = {}
    /\ verified = {}
    /\ faulty_seen = {}
    /\ final_key = ""

BroadcastCommit ==
    /\ phase = "Round1Commit"
    /\ \E p \in Participants :
        /\ p \notin commits
        /\ commits' = commits \cup {p}
    /\ UNCHANGED <<phase, shares, verified, faulty_seen, final_key>>

AdvanceToRound2 ==
    /\ phase = "Round1Commit"
    /\ Honest \subseteq commits
    /\ phase' = "Round2Share"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen, final_key>>

BroadcastShare ==
    /\ phase = "Round2Share"
    /\ \E src \in Participants, dst \in Participants :
        /\ src \in commits
        /\ <<src, dst>> \notin shares
        /\ shares' = shares \cup {<<src, dst>>}
    /\ UNCHANGED <<phase, commits, verified, faulty_seen, final_key>>

AdvanceToRound3 ==
    /\ phase = "Round2Share"
    /\ \A src \in Honest, dst \in Participants : <<src, dst>> \in shares
    /\ phase' = "Round3Verify"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen, final_key>>

VerifyShareHonest ==
    /\ phase = "Round3Verify"
    /\ \E src \in Honest, dst \in Honest :
        /\ <<src, dst>> \in shares
        /\ <<src, dst>> \notin verified
        /\ verified' = verified \cup {<<src, dst>>}
    /\ UNCHANGED <<phase, commits, shares, faulty_seen, final_key>>

DetectFaulty ==
    /\ phase = "Round3Verify"
    /\ \E src \in (Participants \ Honest) :
        /\ src \notin faulty_seen
        /\ faulty_seen' = faulty_seen \cup {src}
    /\ UNCHANGED <<phase, commits, shares, verified, final_key>>

\* INTENTIONALLY BROKEN: removed the `faulty_seen = {}` guard from
\* Finalize. Now the ceremony can emit a key even after detecting
\* malicious participants. SafetyFaultyImpliesAbort must trip.
Finalize ==
    /\ phase = "Round3Verify"
    /\ \A src \in Honest, dst \in Honest : <<src, dst>> \in verified
    /\ phase' = "Finalized"
    /\ final_key' = "dkg_public_key_package"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen>>

Abort ==
    /\ phase = "Round3Verify"
    /\ faulty_seen # {}
    /\ phase' = "Aborted"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen, final_key>>

Next ==
    \/ BroadcastCommit
    \/ AdvanceToRound2
    \/ BroadcastShare
    \/ AdvanceToRound3
    \/ VerifyShareHonest
    \/ DetectFaulty
    \/ Finalize
    \/ Abort

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(BroadcastCommit)
    /\ WF_vars(AdvanceToRound2)
    /\ WF_vars(BroadcastShare)
    /\ WF_vars(AdvanceToRound3)
    /\ WF_vars(VerifyShareHonest)
    /\ WF_vars(Finalize)
    /\ WF_vars(Abort)

SafetyNoKeyAfterAbort ==
    (phase = "Aborted") => (final_key = "")

SafetyFaultyImpliesAbort ==
    (faulty_seen # {} /\ phase \in {"Finalized", "Aborted"})
        => (phase = "Aborted")

SafetyPhaseTyped ==
    phase \in Phases

SafetyFinalizedHasKey ==
    (phase = "Finalized") => (final_key # "")

SafetyTerminalsDisjoint ==
    ~(phase = "Finalized" /\ phase = "Aborted")

Safety ==
    /\ SafetyNoKeyAfterAbort
    /\ SafetyFaultyImpliesAbort
    /\ SafetyPhaseTyped
    /\ SafetyFinalizedHasKey
    /\ SafetyTerminalsDisjoint

Liveness ==
    <>(phase = "Finalized" \/ phase = "Aborted")

LivenessHappyPath ==
    (Participants = Honest) => <>(phase = "Finalized")

RecoverabilityNoStuckCeremony ==
    Cardinality(Honest) >= Threshold

Recoverability == RecoverabilityNoStuckCeremony

====
