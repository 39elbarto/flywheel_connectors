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
short-vector norm check) is **out of scope here** — that part of
soundness lives in the SIS-hardness reduction sketched in
`docs/post-quantum/lattice_trapdoor_delegation.md` §4. This file
proves only the structural / chain-walk side: zone agreement, leaf
period containment, and ancestor period containment must each hold,
or the verifier rejects.

This matches the soundness guarantees the Rust implementation
*actually* enforces today (the cryptographic body is a stub returning
`NotImplemented` per kyopb.1.3.1). When the lattice arithmetic lands,
this file should be augmented with the SIS-reduction theorem; the
structural piece proven here remains a load-bearing pre-condition
either way.

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
