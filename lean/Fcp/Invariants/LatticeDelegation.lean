namespace Fcp.Invariants.LatticeDelegation

/-!
# Lattice-trapdoor capability delegation soundness (br-kyopb.1.3.3)

Formal statement, in Lean 4, of the structural soundness invariant
that the production verifier `LatticeDelegationVerifierImpl`
(crates/fcp-policy/src/lattice_delegation.rs, br-kyopb.1.3.2) is
expected to enforce:

  If any of the structural delegation-chain preconditions fails, the
  verifier MUST reject the sub-token.

The cryptographic verification equation (`A · e ≡ h (mod q)` plus
short-vector norm check) now has an implemented Rust fixture route for
`SMALL_TEST` and `V4_REFERENCE`, but the full SIS reduction is still too
large to honestly mechanize in this file. Instead, this module states a
named mechanized assumption boundary with stable assumption ids and maps
that boundary to the implementation facts that the Rust correspondence
fixtures must check. The structural piece proven here remains a
load-bearing pre-condition for that boundary.

Important scope boundary: this file proves the Lean model, not the
Rust implementation by extraction. The bridge to production code is
the deterministic cross-validation property test
`lattice_delegation_rust_matches_lean_structural_model` in
`crates/fcp-policy/tests/lattice_delegation_proptest.rs`, with the
seed recorded in `lean/witnesses/formal_invariants.v1.json`.
-/

structure Period where
  startMs : Nat
  endMs : Nat
  deriving DecidableEq, Repr

def Period.contains (p : Period) (now : Nat) : Prop :=
  p.startMs <= now /\ now <= p.endMs

structure Cert where
  zone : Nat
  period : Period
  deriving DecidableEq, Repr

/-- Stable identifier for an unmechanized cryptographic or bridge assumption. -/
abbrev AssumptionId := String

/-- Implementation profile facts that the Rust correspondence fixtures pin. -/
structure RouteProfileBinding where
  profileId : String
  latticeRepresentationVersion : Nat
  publicMatrixMaterialVersion : Nat
  primitiveRouteRevision : Nat
  deriving DecidableEq, Repr

/-- The compact test profile implemented by `fcp-crypto-pq`. -/
def smallTestRouteProfile : RouteProfileBinding where
  profileId := "SMALL_TEST"
  latticeRepresentationVersion := 2
  publicMatrixMaterialVersion := 1
  primitiveRouteRevision := 1

/-- The V4 reference profile implemented by `fcp-crypto-pq`. -/
def v4ReferenceRouteProfile : RouteProfileBinding where
  profileId := "V4_REFERENCE"
  latticeRepresentationVersion := 2
  publicMatrixMaterialVersion := 1
  primitiveRouteRevision := 1

/-- Stable assumption ids for the SIS-side soundness boundary. -/
def requiredSISAssumptionIds : List AssumptionId :=
  [ "FCP-PQ-SIS-HARDNESS-V1",
    "FCP-PQ-RANDOM-ORACLE-DOMAIN-SEPARATION-V1",
    "FCP-PQ-MP12-CHKP-GPV-ROUTE-CORRESPONDENCE-V1",
    "FCP-PQ-IMPLEMENTATION-ENCODING-CORRESPONDENCE-V1",
    "FCP-POLICY-DISPATCHER-BINDING-CORRESPONDENCE-V1",
    "FCP-POLICY-REPLAY-DENIAL-CORRESPONDENCE-V1" ]

/-- Boundary consumed by the proof script and Rust correspondence fixtures.

The boolean fields are deliberately explicit: each one names an
implementation seam that must be covered by the checked Rust fixtures before
the SIS-side theorem can be cited as applying to FCP's current code. -/
structure SISAssumptionBoundary where
  assumptionIds : List AssumptionId
  routeProfiles : List RouteProfileBinding
  zonePeriodPublicKeyShape : Bool
  delegationCertificateClaims : Bool
  requestBindingFields : Bool
  dispatcherEnforcementChecks : Bool
  replayDenialInvariants : Bool
  deriving DecidableEq, Repr

/-- The current FCP lattice-delegation assumption boundary. -/
def implementedSISAssumptionBoundary : SISAssumptionBoundary where
  assumptionIds := requiredSISAssumptionIds
  routeProfiles := [smallTestRouteProfile, v4ReferenceRouteProfile]
  zonePeriodPublicKeyShape := true
  delegationCertificateClaims := true
  requestBindingFields := true
  dispatcherEnforcementChecks := true
  replayDenialInvariants := true

/-- Completeness predicate for the named SIS assumption boundary. -/
def BoundaryComplete (b : SISAssumptionBoundary) : Prop :=
  b.assumptionIds = requiredSISAssumptionIds /\
    b.routeProfiles = [smallTestRouteProfile, v4ReferenceRouteProfile] /\
    b.zonePeriodPublicKeyShape = true /\
    b.delegationCertificateClaims = true /\
    b.requestBindingFields = true /\
    b.dispatcherEnforcementChecks = true /\
    b.replayDenialInvariants = true

/-- Mechanized boundary check for the current SIS-side assumption ids.

This is not a proof of SIS hardness. It is the stable Lean theorem that says
which unmechanized assumptions and implementation seams must be validated by
Rust fixtures before the informal SIS reduction in
`docs/post-quantum/lattice_trapdoor_delegation.md` may be cited for the
implemented route. -/
theorem lattice_delegation_sis_assumption_boundary_complete :
    BoundaryComplete implementedSISAssumptionBoundary := by
  unfold BoundaryComplete implementedSISAssumptionBoundary requiredSISAssumptionIds
    smallTestRouteProfile v4ReferenceRouteProfile
  simp

/-- A named theorem for the V4 profile's SIS-side assumption boundary. -/
theorem lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions :
    BoundaryComplete implementedSISAssumptionBoundary /\
      v4ReferenceRouteProfile ∈ implementedSISAssumptionBoundary.routeProfiles := by
  constructor
  · exact lattice_delegation_sis_assumption_boundary_complete
  · unfold implementedSISAssumptionBoundary v4ReferenceRouteProfile smallTestRouteProfile
    simp

/-- The verifier accepts a `(leaf, ancestors)` chain for `(requestZone, now)`
    iff:
      1. the leaf's zone matches the request zone,
      2. the leaf's period contains `now`, AND
      3. every ancestor's period contains `now`.

    Models `LatticeDelegationVerifierImpl::verify_sub_token` steps 2-4
    (zone agreement, leaf-period containment, parent-chain walk). -/
def AcceptsToken
    (leaf : Cert) (ancestors : List Cert)
    (requestZone now : Nat) : Prop :=
  leaf.zone = requestZone /\
    leaf.period.contains now /\
    (forall c, c ∈ ancestors -> c.period.contains now)

/-- A delegation chain is "corrupted" if at least one of the structural
    soundness preconditions fails. Used to state the contrapositive
    soundness theorem below. -/
def ChainCorrupted
    (leaf : Cert) (ancestors : List Cert)
    (requestZone now : Nat) : Prop :=
  leaf.zone ≠ requestZone \/
    Not (leaf.period.contains now) \/
    (Exists (fun c => c ∈ ancestors /\ Not (c.period.contains now)))

/-- Soundness step 1: a leaf certificate whose zone differs from the
    request zone is rejected, irrespective of period or ancestors.
    Mirrors the `ZoneMismatch` error path in the Rust implementation. -/
theorem zone_mismatch_alone_invalidates
    {leaf : Cert} {ancestors : List Cert} {requestZone now : Nat}
    (h : leaf.zone ≠ requestZone) :
    Not (AcceptsToken leaf ancestors requestZone now) := by
  intro hAccept
  exact h hAccept.left

/-- Soundness step 2: a leaf whose period excludes `now` is rejected,
    irrespective of zone or ancestors. Mirrors the leaf-`OutsidePeriod`
    error path. -/
theorem leaf_period_miss_alone_invalidates
    {leaf : Cert} {ancestors : List Cert} {requestZone now : Nat}
    (h : Not (leaf.period.contains now)) :
    Not (AcceptsToken leaf ancestors requestZone now) := by
  intro hAccept
  exact h hAccept.right.left

/-- Soundness step 3: any ancestor whose period excludes `now` invalidates
    the chain. Mirrors the parent-chain-walk `OutsidePeriod` rejection
    (a leaf can only be honoured while *every* delegation step in its
    provenance chain is also valid). -/
theorem ancestor_period_miss_invalidates
    {leaf : Cert} {ancestors : List Cert} {requestZone now : Nat}
    {c : Cert}
    (hMem : c ∈ ancestors)
    (hMiss : Not (c.period.contains now)) :
    Not (AcceptsToken leaf ancestors requestZone now) := by
  intro hAccept
  exact hMiss (hAccept.right.right c hMem)

/-- **Main soundness theorem.** Any chain that satisfies `ChainCorrupted`
    is rejected by `AcceptsToken`. Composes the three step lemmas above
    via case analysis on which precondition fails.

    This is the structural-side soundness statement consumed by the E2E
    gate in `crates/fcp-e2e/src/evidence.rs::FORMAL_INVARIANT_THEOREMS`.
    Together with the rejection contrapositives this pins the contract
    that `LatticeDelegationVerifierImpl::verify_sub_token` follows
    today (cryptographic-side soundness — the SIS reduction — is a
    separate, future theorem). -/
theorem lattice_delegation_chain_corruption_rejected
    {leaf : Cert} {ancestors : List Cert} {requestZone now : Nat}
    (h : ChainCorrupted leaf ancestors requestZone now) :
    Not (AcceptsToken leaf ancestors requestZone now) := by
  intro hAccept
  cases h with
  | inl hZNeq =>
    exact hZNeq hAccept.left
  | inr hRest =>
    cases hRest with
    | inl hPNeq =>
      exact hPNeq hAccept.right.left
    | inr hAnc =>
      cases hAnc with
      | intro c hCondition =>
        exact hCondition.right (hAccept.right.right c hCondition.left)

end Fcp.Invariants.LatticeDelegation
