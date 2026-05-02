# Modes-of-Reasoning Audit · Beta Domain (post-quantum stack) · 2026-05-02

**Auditor:** CrimsonWolf
**Skill:** `/modes-of-reasoning-project-analysis`
**Scope:** `fcp-crypto`, `fcp-crypto-pq`, `fcp-cbor`, `fcp-protocol`, plus
the V4 schema/store touch-points and the Lean proof gate
(`lean/Fcp/Invariants/LatticeDelegation.lean`).
**Companion to:** `docs/audit/security-audit-saas-beta-2026-05-02.md`
(security audit) and the `/testing-fuzzing` proptest sweep
(commit `6f46e6a13`). This audit asks a different question: not
"can attacker-supplied input crash this code?" (fuzzing) or
"is this comparison constant-time?" (security), but rather
**"where does the code claim a property the type system / tests /
docs don't structurally prove?"**

## Methodology

For each module in scope, identified claims of the form:

- "X always holds" (in docstrings, README, or design docs).
- "Y is enforced" (in module-level comments).
- "Z is verified by the formal proof" (in Lean files / witness JSON).

Then asked: **what would actually fail if X / Y / Z were violated?**
Findings record the gap between the claim's promise and the structural
proof of it.

Triage: each finding classed as `(a) reasoning-gap-fixable`,
`(b) reasoning-gap-deep-design-question`, or `(c) just-needs-doc`.
Filed beads only for `(a)` + `(b)` per audit rules, tagged
`[modes-of-reasoning] [beta]`.

Skipped: `kyopb.1.3.1.1` (lattice arithmetic gap — already filed,
covers the cryptographic-side `NotImplemented` ambiguity).

## Findings

### (a) Reasoning-gap-fixable — 4

#### A1 · MlDsa65 byte-envelope pattern is incomplete (no SecretKey wrapper)
- **Bead:** `flywheel_connectors-6bz52` (P2)
- **Claim audited:** "fcp-crypto provides typed byte envelopes for
  every ML-DSA wire role, with length invariants enforced on
  construction + Deserialize" (the kfr9j patch documentation).
- **Reality:** Verifying-key + signature wrappers exist
  (`crates/fcp-crypto/src/owner_key.rs:49`, `:119`); the secret-key
  wrapper does NOT. `MlDsa65SigningKey` holds the seed inline
  (`crates/fcp-crypto/src/ml_dsa.rs:53`); a caller persisting a
  signing key has no canonical envelope to reach for and will
  re-roll a `Vec<u8>` that bypasses the kfr9j length invariant.
- **Gap:** the byte-envelope pattern is partial. The "every role"
  claim is the load-bearing reasoning a security review would
  consume; the missing role makes that reasoning false.

#### A2 · Compatibility-ledger V1 pointer silent upgrade is operator-invisible
- **Bead:** `flywheel_connectors-28nms` (P3)
- **Claim audited:** "every audit-relevant operation produces an
  observable event" (README + br-mvax3) AND "pointer-replay
  attempts are detected and corrected" (br-iqy2b).
- **Reality:** `crates/fcp-store/src/compatibility_ledger.rs::load_latest_pointers`
  silently treats both legitimate-V1-form pointers AND
  attacker-tampered low-sequence pointers via the same code path
  (the `is_legacy_v1` branch + the HWM-mismatch repair). There is
  no `tracing::warn!`, no metric, no audit-chain entry differentiating
  the two cases.
- **Gap:** the claim that replay attempts are "detected" is true at
  the data layer but false at the observability layer. An operator
  inspecting their host post-incident has no signal that the
  defence fired.

#### A3 · `migrated_to_v4` produces unsigned-by-construction manifest with no compile-time signal
- **Bead:** `flywheel_connectors-z8bsg` (P3)
- **Claim audited:** "`migrated_to_v4` produces a draft manifest;
  caller MUST re-sign before publishing" (doc comment at
  `crates/fcp-core/src/zone_keys.rs:435`).
- **Reality:** Returns a `ZoneKeyManifest` indistinguishable from a
  freshly-signed one. The OLD signature field is copied verbatim
  and silently invalidated by the migration; a caller who ignores
  the doc and publishes the result ships a manifest the verifier
  rejects as forged.
- **Gap:** safety claim made in prose, not enforced by the type
  system. The shape `ZoneKeyManifest::migrated_to_v4(...)
  → store.publish(...)` is reachable today and does the wrong
  thing silently.

#### A4 · V3 wrap usage post-V4-cutover has no per-call observability hook
- **Bead:** `flywheel_connectors-gtplu` (P3)
- **Claim audited:** "V3↔V4 cohabitation transitions are observable
  + gated by the compatibility ledger" (`docs/post-quantum/x_wing_kem_design.md`
  §6 + kyopb.1.4 design).
- **Reality:** `crates/fcp-core/src/zone_keys.rs:413-425`
  (`resolved_wrapped_key_for`) silently falls back to V3 wraps
  when the V4 list misses. After a host's compatibility-ledger
  phase advances to `V4Required`, every V3 fallback is a
  deprecation event the operator never sees. No log, no metric,
  no audit-chain entry.
- **Gap:** the cutover gate (kyopb.1.4) is supposed to consume
  per-call evidence to detect lingering V3 usage, but the per-call
  emission point doesn't exist in fcp-core.

### (b) Reasoning-gap-deep-design-question — 1

#### B1 · Lean lattice-delegation soundness theorem is not mechanically linked to the Rust verifier
- **Bead:** `flywheel_connectors-ta230` (P2)
- **Claim audited:** "`lattice_delegation_chain_corruption_rejected`
  is a Lean 4 formal proof of the verifier's structural soundness"
  (kyopb.1.3.3 close note + witness JSON gate).
- **Reality:** The Lean theorem proves a MODEL of the verifier
  (`AcceptsToken (leaf, ancestors, requestZone, now)`). The Rust
  implementation at
  `crates/fcp-policy/src/lattice_delegation.rs::LatticeDelegationVerifierImpl::verify_sub_token`
  runs the same three checks — but **the proof of "the Rust
  matches the Lean model" is by manual visual inspection of the
  comments**. There is no extraction, no harness that runs the
  Rust verifier on a sampled input space and asserts agreement
  with the Lean model. A future Rust refactor that adds a fourth
  acceptance branch would NOT break `lake build` or the witness
  JSON, and the operator-facing signal would still claim "sound
  by Lean proof."
- **Gap:** classic proof-vs-implementation drift. The formal-proof
  gate looks like end-to-end soundness from the outside but
  proves a model that nothing automatically verifies matches the
  shipping code.
- **Why "deep design":** the fix is a methodological choice
  between cross-validation property tests (cheap, partial),
  Lean→Rust extraction (heavy, complete), or a hybrid macro-based
  derivation. Each has 3+ days of scoping work before the first
  PR can land.

### (c) Just-needs-doc — not filed

- **`Fcp4Aad::version` field can be set to non-4 by direct
  construction.** The `Fcp4Aad::for_*_*` constructors set
  `version: FCP4_AAD_VERSION (= 4)` but the field is `pub`. A
  caller could construct `Fcp4Aad { version: 99, ... }` and
  encode it. The version byte is bound by the AEAD's AAD argument
  and the receiver can't be fooled (decryption fails on any
  version mismatch), but the type doesn't enforce that
  constructors are the only entry point. Documented in the
  security audit as "encode-only by design"; not a reasoning gap
  for the `(a)/(b)` triage.
- **X-Wing decap-failure constant-time argument relies on
  RustCrypto crate behaviour.** The fcp-crypto wrapper trusts
  that `chacha20poly1305::ChaCha20Poly1305::decrypt` is
  constant-time (per the upstream documentation) and that
  `x_wing::DecapsulationKey::decapsulate` runs ML-KEM's implicit
  rejection path constant-time (per FIPS 203). Both are true
  today; documenting the assumption ensures an upstream change
  trips a careful review.
- **The `MasterPublicKey` / `ZonePeriodPublicKey` content-hash
  placeholder claim** (32-byte BLAKE3 over canonical encoding of
  the matrix). The matrix isn't materialised yet — kyopb.1.3.1.1
  delivers the real `A_root` / `A_zp` and tightens the hash
  derivation. Until then, the placeholder is by-design but
  ambiguous between "intentional stub" and "missed work" —
  resolved by the existing kyopb.1.3.1.1 bead. Not a separate
  finding.
- **fcp-cbor `MAX_DESERIALIZATION_RECURSION_LIMIT = 128` claim
  applies to "the canonical wire form."** Production codepaths
  that bypass `from_reader_with_recursion_limit` (e.g. the
  three sites flagged in `gmak2`) do not honour this limit. That
  finding lives in the security audit; documenting that "all V4
  wire formats are canonical" requires the gmak2 hardening to
  land first.

### Cross-references

- `kfr9j` (security audit A1, P1, patched) — the `(a) "manifest
  deserialization is total"` reasoning gap from the user's
  examples; addressed by the kfr9j custom Deserialize.
- `1zlht` (security audit B3, P3, patched) — the `(b) "all PQ
  types are constant-time"` reasoning gap; addressed by the 1zlht
  ConstantTimeEq impl on six types.
- `gmak2` (security audit B1, P2, open) — the recursion-limit
  gap relevant to fcp-cbor consistency claims.
- `shbvv` (security audit B2, P2, patched) — the V3↔V4
  cohabitation safety property `validate_no_recipient_split_view`.
- `kyopb.1.3.1.1` (open) — the lattice arithmetic stub that
  resolves the `(f) "by-design stubs are ambiguous"` example
  from the user's prompt. Skipped per audit instructions.

## Files filed

- `flywheel_connectors-6bz52` — A1 (P2)
- `flywheel_connectors-28nms` — A2 (P3)
- `flywheel_connectors-z8bsg` — A3 (P3)
- `flywheel_connectors-gtplu` — A4 (P3)
- `flywheel_connectors-ta230` — B1 (P2)
