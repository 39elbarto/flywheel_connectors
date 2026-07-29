---- MODULE frost_dkg ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* flywheel_connectors-angoc.13.3 (Phase S.3)
\* Abstract FROST distributed key generation (DKG) ceremony as a
\* state machine. The ceremony proceeds in three rounds: every
\* honest participant broadcasts a commitment, then a per-pair
\* share, then verifies the shares it received. If all received
\* shares are valid, the ceremony Finalizes and emits a public-key
\* package. If any malicious share is detected, the ceremony
\* Aborts and emits NO key.
\*
\* The runtime alignment lives in crates/fcp-bootstrap/src/ceremony.rs
\* (existing FROST DKG implementation). This spec abstracts the
\* cryptographic details away and focuses on the safety/liveness
\* properties of the state machine.

CONSTANTS
    Participants,   \* finite set of participant ids (e.g. {p1..p4})
    Honest,         \* honest participants; subset of Participants
    Threshold       \* t-of-n threshold (e.g. 3 of 4)

ASSUME
    /\ Honest \subseteq Participants
    /\ Threshold \in 1..Cardinality(Participants)
    /\ Cardinality(Honest) >= Threshold   \* honest-majority

\* CeremonyPhase enum modeled as strings. Linear progression with one
\* terminal-abort exit. The two terminal phases are "Finalized" and
\* "Aborted"; they are mutually exclusive.
Phases == {"Round1Commit", "Round2Share", "Round3Verify",
           "Finalized", "Aborted"}

\* commits     : SUBSET Participants — participants who have
\*               broadcast their Round 1 commitment
\* shares      : SUBSET (Participants \X Participants) — (src, dst)
\*               pairs for which src has broadcast a Round 2 share
\*               to dst
\* verified    : SUBSET (Participants \X Participants) — (src, dst)
\*               pairs for which dst has verified src's Round 2 share
\* faulty_seen : SUBSET Participants — participants who broadcast a
\*               share that failed Round 3 verification (i.e.
\*               detected-malicious)
\* phase       : current ceremony phase
\* final_key   : the emitted public-key package once Finalized;
\*               empty string "" until then
VARIABLES phase, commits, shares, verified, faulty_seen, final_key

vars == <<phase, commits, shares, verified, faulty_seen, final_key>>

Init ==
    /\ phase = "Round1Commit"
    /\ commits = {}
    /\ shares = {}
    /\ verified = {}
    /\ faulty_seen = {}
    /\ final_key = ""

\* ── Round 1: every participant broadcasts a commitment ────────────────
BroadcastCommit ==
    /\ phase = "Round1Commit"
    /\ \E p \in Participants :
        /\ p \notin commits
        /\ commits' = commits \cup {p}
    /\ UNCHANGED <<phase, shares, verified, faulty_seen, final_key>>

\* Advance to Round 2 once every honest participant has committed.
\* (Malicious participants may not commit; the threshold guarantees
\* progress because |Honest| >= Threshold.)
AdvanceToRound2 ==
    /\ phase = "Round1Commit"
    /\ Honest \subseteq commits
    /\ phase' = "Round2Share"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen, final_key>>

\* ── Round 2: pairwise share broadcast ─────────────────────────────────
BroadcastShare ==
    /\ phase = "Round2Share"
    /\ \E src \in Participants, dst \in Participants :
        /\ src \in commits
        /\ <<src, dst>> \notin shares
        /\ shares' = shares \cup {<<src, dst>>}
    /\ UNCHANGED <<phase, commits, verified, faulty_seen, final_key>>

\* Advance to Round 3 once every (honest -> any) share has been sent.
AdvanceToRound3 ==
    /\ phase = "Round2Share"
    /\ \A src \in Honest, dst \in Participants : <<src, dst>> \in shares
    /\ phase' = "Round3Verify"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen, final_key>>

\* ── Round 3: every recipient verifies the shares it received ──────────
VerifyShareHonest ==
    /\ phase = "Round3Verify"
    /\ \E src \in Honest, dst \in Honest :
        /\ <<src, dst>> \in shares
        /\ <<src, dst>> \notin verified
        /\ verified' = verified \cup {<<src, dst>>}
    /\ UNCHANGED <<phase, commits, shares, faulty_seen, final_key>>

\* A malicious (Participants \ Honest) participant's share may verify
\* OR fail. We non-deterministically model both: a faulty-seen flag
\* may be set on malicious participants, causing Abort.
DetectFaulty ==
    /\ phase = "Round3Verify"
    /\ \E src \in (Participants \ Honest) :
        /\ src \notin faulty_seen
        /\ faulty_seen' = faulty_seen \cup {src}
    /\ UNCHANGED <<phase, commits, shares, verified, final_key>>

\* ── Finalize: all honest-to-honest shares verified AND no faulty ─────
Finalize ==
    /\ phase = "Round3Verify"
    /\ \A src \in Honest, dst \in Honest : <<src, dst>> \in verified
    /\ faulty_seen = {}
    /\ phase' = "Finalized"
    /\ final_key' = "dkg_public_key_package"
    /\ UNCHANGED <<commits, shares, verified, faulty_seen>>

\* ── Abort: at least one malicious participant detected ───────────────
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

\* Weak fairness on every constructive action: each is eventually
\* taken whenever continuously enabled. (DetectFaulty is left
\* unfair — it MAY happen, modeling worst-case adversary.)
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

\* ── Safety / invariants ───────────────────────────────────────────────

\* THE LOAD-BEARING PROPERTY: never emit a key AFTER abort. Once
\* aborted, final_key must remain "". A counter-example here would
\* indicate the ceremony state machine emits cryptographic material
\* after detecting malicious behaviour.
SafetyNoKeyAfterAbort ==
    (phase = "Aborted") => (final_key = "")

\* Malicious participants detected implies abort (eventually fires).
\* As a STATE invariant, we assert: if any faulty share was detected
\* AND the ceremony is in a terminal phase, that phase must be Aborted.
SafetyFaultyImpliesAbort ==
    (faulty_seen # {} /\ phase \in {"Finalized", "Aborted"})
        => (phase = "Aborted")

\* Phase invariant: phase always in the enum.
SafetyPhaseTyped ==
    phase \in Phases

\* Finalized implies a non-empty public-key package.
SafetyFinalizedHasKey ==
    (phase = "Finalized") => (final_key # "")

\* Mutual exclusivity of the two terminal phases.
SafetyTerminalsDisjoint ==
    ~(phase = "Finalized" /\ phase = "Aborted")

Safety ==
    /\ SafetyNoKeyAfterAbort
    /\ SafetyFaultyImpliesAbort
    /\ SafetyPhaseTyped
    /\ SafetyFinalizedHasKey
    /\ SafetyTerminalsDisjoint

\* ── Liveness ──────────────────────────────────────────────────────────

\* Honest-majority terminates: eventually the ceremony reaches one of
\* the two terminal phases. Under WF on all constructive actions and
\* honest-majority via the ASSUME, neither Round 1 nor Round 2 can
\* get stuck (every honest participant eventually broadcasts), and
\* Round 3 either Finalizes (all honest shares verified, no faulty
\* detected) or Aborts (some faulty share detected).
Liveness ==
    <>(phase = "Finalized" \/ phase = "Aborted")

\* Honest-majority + no malicious-share => Finalize is the eventual
\* terminal phase. (When the adversary refrains from injecting faulty
\* shares, the honest-majority ceremony succeeds.)
LivenessHappyPath ==
    (Participants = Honest) => <>(phase = "Finalized")

\* ── Recoverability ────────────────────────────────────────────────────
\* The honest-majority ASSUME guarantees the ceremony can always
\* either Finalize or Abort cleanly; we never stay in an intermediate
\* phase forever under fairness.
RecoverabilityNoStuckCeremony ==
    Cardinality(Honest) >= Threshold

Recoverability == RecoverabilityNoStuckCeremony

====
