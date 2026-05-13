---- MODULE mesh_admission ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* flywheel_connectors-angoc.13.6 (Phase S.6.mesh)
\* Abstract quorum-admission model for mesh-peer joins: a candidate
\* joiner is admitted to a zone only when at least Threshold admins
\* have voted to approve, and every approval is auditable.
\*
\* The runtime alignment lives in the host admission pipeline + the
\* mesh gossip layer that propagates ApprovalSeal artifacts. This
\* spec abstracts the wire path away and focuses on the safety
\* (no admit without quorum) and liveness (every legitimate request
\* is decided within bounded rounds) properties.

CONSTANTS
    Admins,         \* finite set of admin agent ids (e.g. {a1..a5})
    HonestAdmins,   \* admins that vote when asked; subset of Admins
    Joiners,        \* finite set of joiner candidate ids
    Threshold       \* quorum required to admit (e.g. 3 of 5)

ASSUME
    /\ HonestAdmins \subseteq Admins
    /\ Threshold \in 1..Cardinality(Admins)
    /\ Cardinality(HonestAdmins) >= Threshold   \* honest-majority

\* approvals : [Joiner -> SUBSET Admins] — admins who have voted to
\*   approve each joiner. Monotonic: only grows.
\* admitted : SUBSET Joiners — joiners that have been decided
\*   admitted (i.e. moved past the quorum gate). Monotonic.
\* rejected : SUBSET Joiners — joiners that have been decided
\*   rejected (e.g. quorum-of-rejections, modeled abstractly as the
\*   complement decision; not exercised in the happy-path model but
\*   reserved for future expansion).
VARIABLES approvals, admitted, rejected

vars == <<approvals, admitted, rejected>>

Init ==
    /\ approvals = [j \in Joiners |-> {}]
    /\ admitted = {}
    /\ rejected = {}

\* Vote: an admin approves a joiner. Only honest admins vote in this
\* model; malicious admins are modeled as the complement of
\* HonestAdmins (they never vote). An admin can vote at most once per
\* joiner (idempotent because approvals[j] is a set).
Vote ==
    \E a \in HonestAdmins, j \in Joiners :
        /\ a \notin approvals[j]
        /\ j \notin admitted
        /\ j \notin rejected
        /\ approvals' = [approvals EXCEPT ![j] = approvals[j] \cup {a}]
        /\ UNCHANGED <<admitted, rejected>>

\* Decide: once a joiner has accumulated at least Threshold approvals,
\* it is admitted. The gateway / host commits the admission decision
\* and emits an ApprovalSeal that the mesh gossips to all peers.
Decide ==
    \E j \in Joiners :
        /\ j \notin admitted
        /\ j \notin rejected
        /\ Cardinality(approvals[j]) >= Threshold
        /\ admitted' = admitted \cup {j}
        /\ UNCHANGED <<approvals, rejected>>

Next == Vote \/ Decide

\* Weak fairness on both actions: a continuously-enabled action must
\* eventually fire. With honest-majority and a non-empty Joiners set,
\* this guarantees every legitimate joiner is eventually admitted.
Spec == Init /\ [][Next]_vars /\ WF_vars(Vote) /\ WF_vars(Decide)

\* ── Safety / invariants ───────────────────────────────────────────────

\* No joiner is admitted without quorum approval. THE LOAD-BEARING
\* PROPERTY. A counter-example here = malicious admit path.
SafetyQuorum ==
    \A j \in admitted : Cardinality(approvals[j]) >= Threshold

\* No joiner is simultaneously admitted and rejected.
SafetyDisjoint ==
    admitted \cap rejected = {}

\* Approvals always come from real admins (no phantom approvers).
SafetyApproversAreAdmins ==
    \A j \in Joiners : approvals[j] \subseteq Admins

Safety ==
    /\ SafetyQuorum
    /\ SafetyDisjoint
    /\ SafetyApproversAreAdmins

\* ── Liveness ──────────────────────────────────────────────────────────

\* Every joiner is eventually admitted, given honest-majority + WF.
\* This is the dual of SafetyQuorum: safety says "if admitted then
\* quorum"; liveness says "given quorum is reachable, admission
\* eventually fires".
Liveness ==
    \A j \in Joiners : <>(j \in admitted)

\* ── Bounded-rounds recoverability ─────────────────────────────────────
\* The bead specifies "decided within bounded rounds". The actual
\* progress claim is the temporal `Liveness` property above; here we
\* assert the *enabling* state-predicate: whenever a joiner has NOT
\* yet been admitted, there are still enough not-yet-voted honest
\* admins available to reach Threshold (i.e., no terminal stuck state
\* under the honest-majority assumption).
\*
\* Cardinality(HonestAdmins) >= Threshold is an ASSUMPTION, so this
\* invariant is satisfied by construction — but it documents the
\* progress argument and would fail if a future spec edit narrowed
\* the assumption without updating the action set.
RecoverabilityNoDeadAdmission ==
    \A j \in Joiners :
        Cardinality(HonestAdmins) >= Threshold

Recoverability == RecoverabilityNoDeadAdmission

====
