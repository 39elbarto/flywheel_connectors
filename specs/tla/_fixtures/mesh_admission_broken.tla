---- MODULE mesh_admission_broken ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* Deliberately broken fixture for flywheel_connectors-angoc.13.6. The
\* production spec's `Decide` action gates admission on
\* `Cardinality(approvals[j]) >= Threshold`. This fixture drops the
\* quorum guard so a joiner can be admitted with zero approvals.
\* TLC must surface a `SafetyQuorum` counter-example.
\*
\* The Makefile broken target greps for `SafetyQuorum` (or `Safety`)
\* in the TLC log. If TLC accepts this fixture, the production
\* SafetyQuorum invariant is too weak and the mesh-admission
\* quorum-gate claim is not actually being checked.

CONSTANTS Admins, HonestAdmins, Joiners, Threshold

ASSUME
    /\ HonestAdmins \subseteq Admins
    /\ Threshold \in 1..Cardinality(Admins)
    /\ Cardinality(HonestAdmins) >= Threshold

VARIABLES approvals, admitted, rejected

vars == <<approvals, admitted, rejected>>

Init ==
    /\ approvals = [j \in Joiners |-> {}]
    /\ admitted = {}
    /\ rejected = {}

Vote ==
    \E a \in HonestAdmins, j \in Joiners :
        /\ a \notin approvals[j]
        /\ j \notin admitted
        /\ j \notin rejected
        /\ approvals' = [approvals EXCEPT ![j] = approvals[j] \cup {a}]
        /\ UNCHANGED <<admitted, rejected>>

\* INTENTIONALLY BROKEN: removed the Cardinality(approvals[j]) >= Threshold
\* guard. Now Decide can admit ANY joiner regardless of votes.
Decide ==
    \E j \in Joiners :
        /\ j \notin admitted
        /\ j \notin rejected
        /\ admitted' = admitted \cup {j}
        /\ UNCHANGED <<approvals, rejected>>

Next == Vote \/ Decide

Spec == Init /\ [][Next]_vars /\ WF_vars(Vote) /\ WF_vars(Decide)

SafetyQuorum ==
    \A j \in admitted : Cardinality(approvals[j]) >= Threshold

SafetyDisjoint ==
    admitted \cap rejected = {}

SafetyApproversAreAdmins ==
    \A j \in Joiners : approvals[j] \subseteq Admins

Safety ==
    /\ SafetyQuorum
    /\ SafetyDisjoint
    /\ SafetyApproversAreAdmins

Liveness ==
    \A j \in Joiners : <>(j \in admitted)

RecoverabilityNoDeadAdmission ==
    \A j \in Joiners :
        Cardinality(HonestAdmins) >= Threshold

Recoverability == RecoverabilityNoDeadAdmission

====
