# Lattice-Trapdoor Capability Delegation — Design Doc

**Bead:** `flywheel_connectors-kyopb.1.3` (J.5.3)
**Status:** DRAFT — representation profile scaffold exists; production lattice
arithmetic is not implemented yet.
**Authors:** AmberLark
**Date:** 2026-05-02
**Companion:** `docs/post-quantum/x_wing_kem_design.md` (kyopb.1.2 — KEM half) +
this doc (kyopb.1.3 — delegation half). Together they form the V4 spec's
post-quantum surface.

---

## 1. Motivation

FCP V3 capability delegation is online: the owner key signs every zone /
operation grant via Ed25519. To issue a sub-token bound to a per-zone
per-time-period scope, an operator-mediated ceremony involves the owner key
again. With FROST the ceremony is k-of-n threshold, but it is still
**online and per-issuance** — every sub-token mint requires a fresh round of
participant cooperation.

The post-quantum upgrade in V4 swaps Ed25519 for ML-DSA (FIPS 204,
the standardised CRYSTALS-Dilithium). That preserves the security guarantees
under quantum adversaries but does **not** change the operational model: every
sub-token still requires the owner-key ceremony.

**Lattice-trapdoor delegation is fundamentally different.** The owner generates
a master trapdoor once, then delegates to per-zone-per-time-period sub-tokens
via lattice basis-shortening operations. Future sub-tokens are derived from
the existing delegation tree **without involving the owner key for each
issuance**. The delegation tree is published once; downstream issuance is a
local computation against the shared trapdoor descendant.

This unlocks two operational properties impossible with ML-DSA:

1. **Offline-batched issuance.** A field operator with a delegation-tree leaf
   can mint zone-scoped sub-tokens without contacting the master-key holder.
   Useful when the master key is air-gapped, sharded across HSMs, or held by
   parties on different operational schedules.
2. **Forward-secure expiration without revocation.** Time-period delegation is
   built into the trapdoor structure: a sub-token for period T is mathematically
   incapable of signing a request claiming period T+1. A token whose period
   has elapsed is provably useless without any registry / revocation lookup.

These properties are alpha-level differentiators against every other
post-quantum capability scheme we evaluated (see §7). They cost more
implementation complexity than ML-DSA but the operational gain is a step
change, not an incremental improvement.

---

## 2. Background — what is lattice-trapdoor delegation?

### 2.1 The hard problem

Lattice-trapdoor schemes rest on the **Short Integer Solution (SIS)** problem
(Ajtai, 1996) and its dual, **Learning With Errors (LWE)** (Regev, 2005). For
a uniformly random matrix `A ∈ Z_q^{n × m}` with `m ≫ n log q`, finding a
short non-zero vector `x ∈ Z^m` such that `Ax = 0 mod q` is conjectured hard
classically and quantumly. The hardness reduces to worst-case lattice problems
(approximate-SVP / approximate-SIVP) — a much stronger foundation than the
average-case factoring or discrete-log assumptions Ed25519 / RSA rest on.

### 2.2 The trapdoor

A trapdoor for matrix `A` is a short basis `T_A` of the lattice
`Λ⊥(A) = { x : Ax = 0 mod q }`. Knowledge of `T_A` lets the holder solve SIS
instances in `Λ⊥(A)` in polynomial time; without `T_A`, solving SIS requires
breaking the lattice assumption.

**Construction (Micciancio-Peikert, 2012).** Generate `A` together with a
short basis `T_A` simultaneously: pick a structured trapdoor matrix `R` and a
"public part" `Ā`, then set `A = [Ā | -ĀR + G]` where `G` is the gadget
matrix. `T_A` is computed from `R` plus the well-understood basis of `G`.
Result: `A` is statistically indistinguishable from uniform, and `T_A` is a
short basis. ~50% smaller than earlier constructions (Alwen-Peikert, 2009).

### 2.3 Delegation via basis shortening

**Cash-Hofheinz-Kiltz-Peikert (2010), refined by Agrawal-Boneh-Boyen (2010).**
Given a trapdoor `T_A` for `A`, derive a trapdoor `T_{A'}` for an extended
matrix `A' = [A | A_ext]` (where `A_ext` encodes a delegation tag — zone id,
time period, etc.) **without** the original master secret. The extended
trapdoor is shorter on the master columns and longer on the new columns; the
shortening operation is local and deterministic given `T_A` and `A_ext`.

Crucially: a holder of `T_{A'}` can sign / derive sub-trapdoors **only for
matrices that extend `A'`** — they cannot back-derive `T_A`, and they cannot
delegate to siblings of `A'`. The delegation tree is monotonically narrowing.

### 2.4 Delegation tree shape (this design)

```
                       master_trapdoor (T_root)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         T_zone(work)    T_zone(home)    T_zone(public)
              │
   ┌──────────┼──────────┐
   ▼          ▼          ▼
 T_period(   T_period(  T_period(
   2026-01)    2026-02)   2026-03)
              │
   ┌──────────┼──────────┐
   ▼          ▼          ▼
 sub-token  sub-token  sub-token
 (op A)     (op B)     (op C)
```

- **Layer 0 (root):** master trapdoor, sealed offline (HSM, air-gap, FROST
  shares of `T_root`). Used to derive layer 1 once per zone, then archived.
- **Layer 1 (per-zone):** held by the zone-owner operator; used to derive
  layer 2 entries periodically (e.g., monthly).
- **Layer 2 (per-period):** held by an active issuance node; used to mint
  layer 3 sub-tokens for individual operations.
- **Layer 3 (sub-tokens):** the actual capability tokens carried by client
  invocations. Each one is a short vector `x` such that `A_op x = c mod q`
  where `c` is the operation hash and `A_op` is the per-operation extended
  matrix.

A layer-3 sub-token is **mathematically incapable** of being repurposed for a
different operation, zone, or period — the verifier checks that the signed
challenge `c` matches the requested operation, the public matrix `A_op`
encodes the period, and the period encoding is checked against
`now() ∈ [period_start, period_end]`.

---

## 3. Concrete scheme

### 3.1 Parameters

Following the V4 conservative profile (≥ Cat. 3 NIST PQ security):

| Symbol | Meaning                                  | Value      |
|--------|------------------------------------------|------------|
| `n`    | Lattice dimension                        | 512        |
| `q`    | Modulus                                  | `2^32 - 5` |
| `m`    | Public-matrix width per delegation layer | `≈ n log q ≈ 16384` |
| `σ`    | Discrete Gaussian width (per derivation) | `√(n log q) ≈ 113` |
| `L`    | Maximum delegation depth                 | 4          |

These values target **128-bit classical / Cat. 3 PQ** security per the
Micciancio-Peikert sample-quality bound and are conservative against all known
sieve / BKZ attacks as of 2026.

### 3.2 Representation profile and key sizes

The implemented scaffold now pins
`fcp_crypto_pq::LATTICE_REPRESENTATION_VERSION = 2`. Version 2 keeps the
version-1 public SHAKE fixture seeds stable, but moves secret trapdoors behind
a basis-capable metadata envelope:

- Public matrices serialize as a 32-byte SHAKE seed. The expanded
  `V4_REFERENCE` matrix is `512 * 16384 * 4 = 33,554,432` bytes and is
  never stored in certificates or tokens.
- Trapdoors are secret-only representation envelopes. Fixture trapdoors carry
  the existing 96-byte SHAKE seed bundle as `FixtureShakeSeedBundle`, while
  future reviewed arithmetic may carry `BasisEnvelope` material behind the
  same redacted, non-`Serialize`, zeroized boundary.
- Root and child trapdoors expose redaction-safe metadata and relation
  summaries: representation version, scope, material kind, parameter profile,
  public matrix hash, optional parent public matrix hash, relation result,
  norm/quality bucket, and secret storage length bucket. They never expose
  coefficients, secret seeds, or expanded secret matrices.
- Layer-3 preimages serialize as profile-derived packed coefficients. For
  `V4_REFERENCE`, the length is `16384 * 4 = 65,536` bytes; malformed lengths
  are rejected before cryptographic verification.
- The small deterministic test profile is `n=8, q=257, m=16`, yielding a
  256-byte expanded public matrix and a 32-byte preimage. It exists only for
  cheap dimension and serialization tests.

| Object                          | V4_REFERENCE representation | Notes                                      |
|---------------------------------|-----------------------------|--------------------------------------------|
| Public matrix seed              | 32 B                        | Serialized public certificate material     |
| Expanded public matrix `A`      | 33,554,432 B                | Derived on demand; guarded by a 64 MiB cap |
| Fixture trapdoor seed bundle    | 96 B                        | Secret-only, redacted, zeroized on drop    |
| Basis-envelope secret storage   | <= 1 MiB                    | Future reviewed route; bucketed in logs    |
| Sub-token preimage              | 65,536 B                    | Profile-derived packed `Z_q^m` vector      |
| Verification time               | ~0.5 ms projected           | One matrix-vector multiply mod q + norm check |

For comparison, an Ed25519 capability token is ~64 bytes signature + claims
(~256 bytes total). V4 lattice sub-tokens are much larger, but the operational
model lets us batch issuance, which Ed25519 cannot.

### 3.3 Algorithms (high-level)

**Setup (run once per master key):**

1. Sample `(A_root, T_root) ← TrapGen(n, m, q)` per Micciancio-Peikert.
2. Seal `T_root` via X-Wing KEM (kyopb.1.2) under the owner attestation key.
3. Publish `A_root` as part of the V4 zone-policy bundle.

**Delegate (zone owner; once per (zone, period) — typically monthly):**

1. Derive the per-zone-per-period extension tag
   `tag = SHAKE256(zone_id || period_start_unix_ms || period_end_unix_ms, 32)`.
2. Compute extended matrix `A_zp = [A_root | H(tag)]` where `H` is a public
   matrix-valued hash.
3. Derive trapdoor `T_zp ← Delegate(T_root, A_zp)` per Cash-Hofheinz-Kiltz-Peikert.
4. Publish `(zone_id, period_start, period_end, A_zp, ...)` as a
   **DelegationCertificate**. `T_zp` is held offline at the issuance node.

**Mint (issuance node; one per capability sub-token):**

1. Receive an operation request — `op_id`, `principal_id`, `zone_id`,
   `period`, `request_descriptor_hash`.
2. Verify the request's `(zone_id, period)` matches the held
   DelegationCertificate.
3. Compute extended matrix `A_op = [A_zp | H(op_id || principal_id)]`.
4. Sample short pre-image
   `s ← SamplePre(T_zp, A_op, request_descriptor_hash)` per Gentry-Peikert-Vaikuntanathan.
5. Return `(s, A_op, period, request_descriptor_hash)` as the sub-token.

**Verify (any verifier; per-token at request time):**

1. Reconstruct `A_op` from public seeds (`A_root` + zone tag + op_id +
   principal_id) — verifier needs only the DelegationCertificate, NOT
   the trapdoor.
2. Check `A_op · s ≡ request_descriptor_hash mod q`.
3. Check `‖s‖ ≤ σ · √m` (short-vector property — proves the signer held a
   trapdoor, not just a uniform-random short vector).
4. Check `now() ∈ [period_start, period_end]`.
5. Check that the DelegationCertificate is in the zone-policy bundle's
   accepted set (defends against rogue delegations from a compromised issuance
   node — see §4.3).

If all checks pass, the sub-token is admitted. The verifier never sees any
trapdoor; the math itself proves the signer held one valid for `(zone, period,
op, principal)`.

---

## 4. Security model

### 4.1 Soundness (informal)

**Theorem (informal):** Under the SIS_{n,m,q,σ√m} hardness assumption with
the parameters in §3.1, an adversary `A` with no access to any layer-2 or
layer-3 trapdoor cannot produce a valid layer-3 sub-token for any
`(zone, period, op, principal)` tuple of its choice, except with negligible
probability in `n`.

More formally: let `Adv_{LTC}^{EU-CMA}(A)` denote `A`'s advantage in an
existential-unforgeability-under-chosen-message-attack game against the
lattice-trapdoor-capability scheme. Then there exists an SIS solver `B` such
that:

```
Adv_{LTC}^{EU-CMA}(A) ≤ Q · Adv_{SIS_{n,m,q,σ√m}}(B) + negl(n)
```

where `Q` is the number of sub-tokens `A` requested during the security game.
The reduction is tight up to a factor of `Q` (lossy in the standard model;
tighter in the random oracle model since `H` is a random oracle).

### 4.2 Forward-period unforgeability (informal)

**Theorem (informal):** An adversary `A` that compromises a layer-2 trapdoor
`T_zp` for period `[t_a, t_b]` cannot produce a valid sub-token for any
period `[t_c, t_d]` outside `[t_a, t_b]` (specifically, with `t_c > t_b` or
`t_d < t_a`), except with negligible probability.

Proof sketch: a sub-token for period `[t_c, t_d]` requires a short
pre-image of a matrix that extends `A_zp(t_c, t_d)`, which the adversary does
not hold. Deriving `A_zp(t_c, t_d)` from `T_zp(t_a, t_b)` would require
solving SIS for `H(zone_id || t_c || t_d) − H(zone_id || t_a || t_b)`
which is a uniformly-random target by the random-oracle assumption on `H`.

This is the **forward-secure expiration** property. It is unique to the
lattice-trapdoor construction; ML-DSA + per-period certificates can revoke
old periods but cannot mathematically prevent forgery using a leaked
historical key.

### 4.3 Compromise containment

If a layer-3 sub-token leaks: zero impact (sub-token is bound to one request).

If a layer-2 trapdoor `T_zp` leaks: adversary can mint sub-tokens for the
compromised `(zone, period)` pair only — bounded blast radius. The owner
revokes the corresponding DelegationCertificate by removing it from the
zone-policy bundle's accepted set; the layer-2 trapdoor is then mathematically
useless for V4 verification even though the trapdoor still holds.

If the layer-1 (per-zone) trapdoor leaks: adversary can mint any
layer-2 + layer-3 for that zone for the trapdoor's lifetime. Defense:
layer-1 trapdoors are sealed offline and only accessed for periodic
delegation events; compromise window is bounded to the access window.

If the master trapdoor `T_root` leaks: full compromise. Defense: shard
`T_root` across FROST+lattice-threshold k-of-n holders (research direction;
not in the V4 scope).

### 4.4 Quantum security

The SIS / LWE reductions are **quantum-resistant**: best known attacks are
classical sieve algorithms (BKZ-2.0, G6K) which Shor's algorithm does not
speed up. Quantum-Grover gives at most a quadratic speedup on the symmetric-
hash component (`H` collision search) which we account for by sizing `H`'s
output for ≥ 256-bit pre-image resistance.

---

## 5. Formal soundness proof — Lean 4 sketch

The full proof will live in
`lean/Fcp/Invariants/LatticeTrapdoor/Soundness.lean` and consume the
toolkit from kyopb.E.10 (lattice formalisation primitives — Mathlib's
`Polynomial`, `ZMod`, `Matrix` modules with extensions for short-basis
distributions). Sketch:

```lean
-- Lattice-trapdoor capability scheme parameters.
structure LatticeTrapdoorParams where
  n : Nat                         -- lattice dimension
  q : Nat                         -- modulus, prime
  m : Nat                         -- public-matrix width
  sigma : ℝ                       -- Gaussian width
  L : Nat                         -- max delegation depth

-- A delegation certificate publishes an extended public matrix
-- but NOT the trapdoor.
structure DelegationCert (P : LatticeTrapdoorParams) where
  zone_id : ZoneId
  period_start_ms : Nat
  period_end_ms : Nat
  pub_matrix : Matrix (ZMod P.q) P.n P.m   -- A_zp (Sec 3.3)
  parent_cert_hash : ByteString             -- chains to parent layer

-- A sub-token is a short pre-image of a per-operation challenge.
structure SubToken (P : LatticeTrapdoorParams) where
  cert : DelegationCert P
  op_id : OperationId
  principal_id : PrincipalId
  request_descriptor_hash : ByteString
  preimage : Vector (ZMod P.q) (P.m + P.n)  -- short vector s

def SubToken.verify (P : LatticeTrapdoorParams) (st : SubToken P) (now_ms : Nat) : Bool :=
  -- (a) reconstruct A_op from cert + op + principal
  let A_op := extend_matrix st.cert.pub_matrix
                            (hash_to_matrix [st.op_id, st.principal_id])
  -- (b) check matrix-vector equation
  (matvec_mod_q A_op st.preimage = st.request_descriptor_hash) &&
  -- (c) check short-vector norm
  (l2_norm st.preimage ≤ P.sigma * Float.sqrt (P.m + P.n)) &&
  -- (d) check period
  (st.cert.period_start_ms ≤ now_ms ∧ now_ms ≤ st.cert.period_end_ms)

-- The unforgeability theorem (statement; proof TBD).
theorem lattice_trapdoor_capability_unforgeability
  (P : LatticeTrapdoorParams)
  (P_secure : SISHard P.n P.m P.q (P.sigma * Float.sqrt P.m))
  (A : PPTAdv P)
  (q_queries : Nat)
  : Adv_EU_CMA A ≤ q_queries * Adv_SIS A_to_B + negl P.n := by
  -- Reduction structure:
  --   1. Embed SIS challenge into A_root.
  --   2. Simulate Delegate / Mint queries by sampling fake but
  --      statistically-indistinguishable trapdoors at each layer.
  --   3. Extract a SIS solution from the adversary's forgery.
  -- Full proof: see lean/Fcp/Invariants/LatticeTrapdoor/Soundness.lean
  -- (J.5.3.4 — bead to be filed).
  sorry

-- The forward-period theorem (separate, smaller proof).
theorem lattice_trapdoor_forward_period_unforgeability
  (P : LatticeTrapdoorParams)
  (compromised_period : DelegationCert P)
  (target_period : DelegationCert P)
  (h_disjoint : ¬ periods_overlap compromised_period target_period)
  (A : PPTAdv P)
  : Pr[A produces SubToken with cert = target_period] ≤ negl P.n := by
  sorry
```

The two theorems together prove: (i) without a trapdoor, no sub-token
forgery; (ii) with a trapdoor, no sub-token forgery for unrelated periods.
Together they justify the operational claim "a leaked layer-2 trapdoor
cannot be replayed across periods."

---

## 6. Integration with FCP3 capability tokens

V3 capability tokens are COSE_Sign1 over CWT claims, signed with Ed25519.
V4 lattice-trapdoor tokens are NOT COSE — the wire format is
`(DelegationCert reference, sub_token_bytes)` with the sub_token_bytes being
the concatenation of `(period, op_id, principal_id, descriptor_hash, short_vector)`.

The compatibility ledger (see `docs/post-quantum/v3_v4_compatibility_ledger.md`)
documents how V3 and V4 tokens coexist during the migration window. In
brief:

- **V3 verifier seeing a V4 token**: rejects with structured
  `UnsupportedTokenFormat { reason: "v4-lattice-trapdoor" }`.
- **V4 verifier seeing a V3 token**: accepts during a configured grace
  window; rejects with `LegacyTokenFormatRetired { reason: "v3-cwt" }`
  after the window closes.
- **Hybrid V3+V4 dispatch**: the verifier accepts EITHER a valid V3
  signature OR a valid V4 sub-token over the same request; both verifications
  must complete before dispatch (defense in depth during the migration).

The `fcp_policy::lattice_delegation::LatticeDelegationVerifier` trait is the
policy abstraction layer; representation and primitive scaffolding live in
`fcp-crypto-pq`.

---

## 7. Trade-offs vs alternatives

| Scheme                          | PQ-safe | Offline batch issuance | Fwd-period unforgeable | Token size | Notes                                  |
|---------------------------------|---------|------------------------|------------------------|------------|----------------------------------------|
| Ed25519 + per-token sign        | ✗       | ✗                      | ✗                      | ~256 B     | V3 baseline                            |
| ML-DSA + per-token sign         | ✓       | ✗                      | ✗                      | ~3.3 KB    | V4 default (kyopb.1.1)                 |
| ML-DSA + FROST threshold        | ✓       | ✗ (online ceremony)    | ✗                      | ~3.5 KB    | k-of-n online; doesn't help offline    |
| **Lattice-trapdoor (this doc)** | ✓       | ✓                      | ✓                      | ~64 KiB    | The alpha play                         |
| ZK-SNARK over delegation tree   | ✓       | ✓ (after setup)        | ✓                      | ~256 B     | Proven verifier; trusted setup hairy   |
| Anonymous credentials (BBS+)    | classical| ✓                      | ✓                      | ~600 B     | Not PQ-safe; superseded by lattice     |

Lattice-trapdoor sits at the operational sweet spot: PQ-safe, supports
offline-batched issuance AND forward-period unforgeability, with no trusted
setup. The cost is implementation complexity (~2-3× ML-DSA's surface area)
and slightly larger sub-tokens than ZK-SNARK (which has its own trusted-setup
demons).

---

## 8. Implementation roadmap

The design, policy verifier wiring, and `fcp-crypto-pq` representation
profile scaffold are in-tree. The remaining production implementation splits
into the following sub-beads:

1. **kyopb.1.3.1** — `crates/fcp-crypto-pq` crate scaffolding +
   `TrapGen` / `Delegate` / `SamplePre` / `Verify` primitives. The
   version-2 basis-capable representation envelope is implemented; real
   MP12/CHKP/GPV arithmetic remains follow-up work. ~2-3 engineer-weeks total.
2. **kyopb.1.3.2** — `LatticeDelegationVerifier` trait implementation
   wiring stub from this commit to the kyopb.1.3.1 primitives.
   ~1 engineer-week.
3. **kyopb.1.3.3** — Lean 4 formal proof (the sketches in §5 made
   concrete in `lean/Fcp/Invariants/LatticeTrapdoor/`). Consumes the
   kyopb.E.10 toolkit. ~4-6 engineer-weeks (primary research output).
4. **kyopb.1.3.4** — Issuance throughput benchmark vs. Ed25519 + ML-DSA
   baselines (acceptance criterion from the original bead).
   `crates/fcp-crypto-pq/benches/lattice_delegation_throughput.rs`.
   ~1 engineer-week.

Total ~8-11 engineer-weeks of focused work. Research-grade — not on the
critical path for V3 → V4 migration (ML-DSA + X-Wing land first), but the
operational differentiator the alpha play promised.

---

## 9. Open questions

1. **Library choice for the lattice primitives.** Decided by
   `flywheel_connectors-kyopb.1.3.1.1.7`: no inspected off-the-shelf Rust
   dependency or public reference implementation is accepted as a direct
   production route for FCP V4 TrapGen, Delegate, SamplePre, and Verify.
   The representation bead (`flywheel_connectors-kyopb.1.3.1.1.8`) should
   proceed with a versioned basis-capable boundary, while arithmetic stays
   on formal hold until a vendored or internal implementation has an explicit
   cryptography review packet, deterministic fixtures, allocation evidence,
   and redaction-safe JSONL proof.
2. **Period granularity.** This design uses unix-millisecond
   `[period_start, period_end]`. Operational alternative: epoch-numbered
   periods (e.g., monthly buckets). Trade-off: ms gives flexibility,
   epochs are easier to canonicalize. Decided in kyopb.1.3.2.
3. **Layer-1 (per-zone) trapdoor revocation.** A leaked layer-1 trapdoor
   needs both a DelegationCertificate-removal AND an
   IssuerKeyRevocation cascade event (per the m8j0q.A.9 walker). The
   integration is straightforward but needs a written contract. TBD in
   kyopb.1.3.2.
4. **FROST sharing of the master trapdoor.** Lattice trapdoors don't
   immediately support FROST-style threshold signing — the math is
   different. Active research direction (Damgard-Ostrovsky-Pereira-Tessaro
   2024); out of scope for the V4 first cut.

---

## 10. References

- **Cash, Hofheinz, Kiltz, Peikert** (2010). "Bonsai Trees, or How to
  Delegate a Lattice Basis." EUROCRYPT 2010.
- **Agrawal, Boneh, Boyen** (2010). "Efficient Lattice (H)IBE in the
  Standard Model." EUROCRYPT 2010.
- **Micciancio, Peikert** (2012). "Trapdoors for Lattices: Simpler,
  Tighter, Faster, Smaller." EUROCRYPT 2012. (The trapdoor construction
  this design uses.)
- **Gentry, Peikert, Vaikuntanathan** (2008). "Trapdoors for Hard
  Lattices and New Cryptographic Constructions." STOC 2008. (The
  `SamplePre` algorithm.)
- **Boyen, Li** (2016). "All-but-Many Lossy Trapdoor Functions and
  Selective-Opening Security." (Refinements to the soundness reduction
  that achieve tight bounds in the random-oracle model.)
- **Ajtai** (1996). "Generating Hard Instances of Lattice Problems."
  STOC 1996. (The original SIS hardness reduction.)
- **Regev** (2005). "On lattices, learning with errors, random linear
  codes, and cryptography." STOC 2005. (LWE.)
- **NIST PQC Standardization, FIPS 203 + 204** (2024). (ML-KEM and
  ML-DSA — neighbouring V4 schemes that share the lattice foundation.)
- **draft-connolly-cfrg-xwing-kem** (2024+). (X-Wing — the KEM half
  this design composes with.)
