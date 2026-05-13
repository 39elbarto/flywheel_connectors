# Alien Graveyard EV Scoring — 2026-Q3 Commitment

> Filed under `flywheel_connectors-angoc.11.3` (Phase Q.K).
> Methodology version: `2026.Q3.v1`.
> Artifact timestamp: 2026-05-12T20:30:00Z.
> Supersedes: (none — inaugural pass).

## Scope

Score each of the 10 alien-graveyard buckets defined in
`docs/reality/2026-05-12-reality-check-bridge-plan.md` Phase Q (Q.A–Q.J) on a
10-dimensional EV rubric. Commit to a Top-5 set for 2026-Q3 landing; defer the
remainder to 2026-Q4 (or later) with explicit deferral rationale.

## 10-dimensional rubric

Each bucket is scored 1–10 on each dimension. Higher is better. Total EV is the
unweighted sum (max 100). A weighted variant can be applied per session by an
agent that has updated workload context; the unweighted baseline keeps the
methodology auditable.

| # | Dimension | Meaning |
|---|---|---|
| 1 | **Production impact** | How much does it move the needle on a README metric (perf target, status row, security invariant)? |
| 2 | **Feasibility** | Can we actually ship a closed implementation in 2026-Q3 with our current crate/skill mix? |
| 3 | **Risk / blast radius** | Failure-mode severity inverted (10 = least risky to roll back from a botched attempt) |
| 4 | **Prerequisites readiness** | Are the upstream substrates and APIs already in place? |
| 5 | **Time-to-value** | Weeks from start to first operator-visible benefit (10 = quick) |
| 6 | **Ecosystem fit** | Does it integrate cleanly with FCP's existing crate graph and data structures? |
| 7 | **Evidence available** | Published reference implementations, papers, production deployments to draw from |
| 8 | **Complexity (inverted)** | Implementation difficulty (10 = simple; 1 = research-grade) |
| 9 | **Reversibility** | Can we back out cleanly if the bucket doesn't pan out? (10 = purely additive / feature-flagged) |
| 10 | **Cross-phase synergy** | Does landing this unblock or accelerate other phases (B, C, M, N, O, R, S, T)? |

## Scoring matrix

| Bucket | Imp | Feas | Risk | Pre | TTV | Fit | Ev | !Cx | Rev | Syn | **Total** |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Q.A** STARK aggregation over `CapabilityInvocationBatch` | 5 | 4 | 5 | 6 | 4 | 6 | 7 | 3 | 8 | 6 | **54** |
| **Q.B** Quotient filter revocation cache | 6 | 8 | 8 | 9 | 8 | 9 | 9 | 7 | 10 | 5 | **79** |
| **Q.C** I-CONFLUENCE `coordination_class` | 7 | 7 | 6 | 6 | 6 | 8 | 7 | 5 | 9 | 8 | **69** |
| **Q.D** Flink-CEP + reservoir compactor | 4 | 5 | 6 | 5 | 3 | 4 | 8 | 3 | 7 | 4 | **49** |
| **Q.E** Datalog/Soufflé policy backend | 8 | 5 | 4 | 5 | 3 | 6 | 9 | 4 | 5 | 9 | **58** |
| **Q.F** io_uring + AF_XDP for RaptorQ | 8 | 5 | 6 | 4 | 4 | 6 | 8 | 4 | 9 | 7 | **61** |
| **Q.G** Threshold HPKE KEM reusing FROST | 7 | 7 | 5 | 9 | 6 | 9 | 7 | 5 | 8 | 8 | **71** |
| **Q.H** Bayesian K-selector for RaptorQ | 6 | 7 | 7 | 7 | 7 | 8 | 8 | 6 | 10 | 6 | **72** |
| **Q.I** Conformal-prediction `confidence: ConformalScore` | 5 | 8 | 8 | 7 | 8 | 7 | 9 | 7 | 10 | 5 | **74** |
| **Q.J** Three TLA+ specs (lifecycle / FROST DKG / agent-mail) | 7 | 8 | 8 | 9 | 6 | 8 | 10 | 5 | 10 | 7 | **78** |

## Ranked totals

| Rank | Bucket | EV | Verdict |
|---|---|---:|---|
| 1 | **Q.B** Quotient filter revocation | 79 | **Top-5 (Q3)** — already anchored as `angoc.11.2` |
| 2 | **Q.J** TLA+ specs (lifecycle / FROST DKG / agent-mail) | 78 | **Top-5 (Q3)** — already anchored as `angoc.13.{2,3,5}` (Phase S split) |
| 3 | **Q.I** Conformal-prediction confidence | 74 | **Top-5 (Q3)** — file new `angoc.11.4` (new) |
| 4 | **Q.H** Bayesian K-selector | 72 | **Top-5 (Q3)** — overlaps Phase J; file `angoc.11.5` linked to `angoc.4` |
| 5 | **Q.G** Threshold HPKE KEM | 71 | **Top-5 (Q3)** — file new `angoc.11.6` linked to `angoc.8` (Phase N) |
| 6 | Q.C I-CONFLUENCE | 69 | Q4 candidate — already anchored as `angoc.11.1`; can move up if Q.I/Q.H slip |
| 7 | Q.F io_uring + AF_XDP | 61 | **Q4 deferred** — Linux-only, gates broader work |
| 8 | Q.E Datalog policy backend | 58 | **Q4 deferred** — large paradigm shift; surface as `angoc.11.7` deferred |
| 9 | Q.A STARK aggregation | 54 | **Q4 deferred** — surface as `angoc.11.8` deferred |
| 10 | Q.D Flink-CEP + reservoir | 49 | **Q4 deferred** — surface as `angoc.11.9` deferred |

## Top-5 commitment (2026-Q3)

1. **Q.B Quotient filter revocation** (`angoc.11.2`, EV 79) — drop-in replacement
   for the current revocation lookup. Bender et al. 2012 quotient filter with
   deletes, sized for the production revocation cardinality. Acceptance: revocation
   lookup p99 ≤ current Bloom-fallback p50, no false-negative regression vs. the
   exact `HashMap` backing store, observable FPR ≤ configured FPR.
2. **Q.J TLA+ specs** (`angoc.13.{2,3,5}`, EV 78) — three independent specs:
   capability lifecycle, FROST DKG ceremony, agent-mail ordering. Each has TLC
   bounded model check + alignment E2E. Surfaces real bugs before they ship; the
   specs document the canonical state machines for future agents.
3. **Q.I Conformal-prediction confidence on `OperationReceipt`** (`angoc.11.4`,
   EV 74) — adds a calibrated `confidence: ConformalScore` field on every receipt
   so operators see a p-value-style reliability estimate alongside the boolean
   `success`. Calibrated from audit-chain history. Additive field; purely
   reversible. See: Vovk-Gammerman-Shafer conformal prediction.
4. **Q.H Bayesian-optimization `KSelector` for RaptorQ** (`angoc.11.5`, EV 72) —
   replaces the static `K` parameter in `fcp-raptorq` with a per-workload Bayesian
   optimizer (Thompson sampling over `(K, code_family)` arms). Surfaces a
   workload-aware tradeoff between decode latency and packet-loss tolerance.
   Overlaps Phase J's optimal-device cost model (shares the bandit substrate).
5. **Q.G Threshold HPKE KEM reusing FROST DKG** (`angoc.11.6`, EV 71) — the
   FROST DKG / Pedersen VSS infrastructure deployed for threshold signing also
   yields a threshold KEM: the same ceremony produces a key-encapsulation
   keypair without standing up a parallel ceremony. Unlocks cross-mesh sealed
   objects without single-point-of-trust. Defer until Phase N PQ hybrid (Ed25519
   + ML-DSA) lands first so hybrid HPKE follows naturally.

## Deferred to 2026-Q4 (or later)

- **Q.A STARK aggregation** (EV 54) — research-grade complexity. Need a STARK
  library decision (Plonky2 vs. Winterfell vs. RISC0) and concrete benchmark of
  proof generation latency before committing to the audit-chain integration.
  Filed as `angoc.11.8` deferred.
- **Q.D Flink-CEP + reservoir compactor** (EV 49) — heavy streaming infra for
  marginal audit observability gain. Filed as `angoc.11.9` deferred.
- **Q.E Datalog/Soufflé policy backend** (EV 58) — represents a paradigm shift
  for the policy engine. Filed as `angoc.11.7` deferred; revisit when the
  existing policy engine has documented friction points justifying the shift.
- **Q.F io_uring + AF_XDP** (EV 61) — Linux-only path; macOS-host operators
  would lose parity. Defer until cross-platform abstraction lands.

## Methodology notes

The unweighted EV sum is auditable and resists motivated reasoning. A weighted
variant (e.g., 2× Production impact, 0.5× Time-to-value) can be applied by an
agent for a specific quarter, but the unweighted baseline is the canonical
methodology for cross-quarter comparison.

The Top-5 cutoff at EV 71 captures the natural cliff in the ranking: a 2-point
gap between Q.G (71) and Q.C (69), and a 8-point gap between Q.C (69) and Q.F
(61). Five buckets is also the operational headcount we expect for the alien-
graveyard track during 2026-Q3.

## Cross-quarter ratchet

This artifact will be regenerated each quarter via
`scripts/alien-graveyard/score.sh`. Each regeneration:

1. Archives the previous artifact under
   `docs/architecture/archive/alien_graveyard_<YYYY-MM-DD>.md`.
2. Updates the methodology version.
3. Records what changed (new buckets added; deferred buckets graduated; Top-5
   adjustments based on landing progress).

The Phase K cadence epic (`angoc.5`) drives the regeneration cycle.

## Verification

- `scripts/alien-graveyard/score.sh` regenerates this artifact deterministically
  from the bridge plan + scoring matrix table.
- `crates/fcp-conformance/tests/alien_graveyard_q3_completeness.rs` asserts:
  - The artifact exists.
  - Every Top-5 bucket has an open or in-progress bead under `angoc.11`.
  - Every Q4-deferred bucket has a deferred-status bead with due date in
    2026-Q4.
- `fwc doctor --probe ev_top5` reports the artifact's timestamp, methodology
  version, Top-5 buckets with scores, and whether the commitment is signed.
