# Security Audit · Beta Domain (post-quantum stack) · 2026-05-02

**Auditor:** CrimsonWolf
**Skill:** `/security-audit-for-saas`
**Scope:** `fcp-core`, `fcp-protocol`, `fcp-cbor`, `fcp-crypto`, `fcp-crypto-pq`,
plus the V4 schema/store touch-points (`fcp-store::compatibility_ledger`,
`fcp-evidence::compatibility_ledger`).
**Trigger:** Followup to the `/testing-fuzzing` proptest sweep (commit
`6f46e6a13`) that ran ~7,600 randomised cases against the post-quantum
surfaces and found zero panics. Auditing complements fuzzing —
fuzzing proves "doesn't crash on garbage", auditing proves "doesn't
quietly mis-handle the *right* shape of garbage."

## Focus areas reviewed

- (a) **Timing side-channels** — secret-bearing comparisons,
  early-exit on mismatch, branching on secret data.
- (b) **CBOR / protocol input validation** — bounds, lengths,
  recursion limits, integer overflows.
- (c) **Crypto primitive misuse** — nonce reuse, IV randomness,
  key-separation domains, signature verification ordering.
- (d) **PQ-specific risks** — X-Wing decap-failure leakage, ML-DSA
  signature malleability, lattice-trapdoor walker exhaustion,
  ZoneKeyManifest V4 deserialization.
- (e) **Auth bypass via empty/null/missing fields** — `#[serde(default)]`
  defaults that flip authority bits, optional fields treated as
  authoritative when absent.
- (f) **Adversarial-input panic surfaces not caught by the proptest
  harnesses** — paths the fuzzer doesn't reach.

## Methodology

- Read the post-`kyopb.1.x` PQ codepaths line-by-line for each focus
  area, recording file:line evidence.
- Cross-checked claimed invariants (length checks, depth bounds,
  recursion limits) against the code that actually enforces them.
- Workspace-wide grep for production-code comparisons / panics /
  unwraps on the secret-bearing types.
- Compared each potential finding against the existing `/testing-fuzzing`
  proptest coverage to confirm whether the harness already catches it.
- Each candidate finding triaged into `(a) confirmed-vuln`,
  `(b) hardening-worth-doing`, or `(c) false-positive / already
  mitigated`. Filed beads only for `(a)` + `(b)` per audit rules,
  tagged `[security-audit] [beta]`.

## Findings

### (a) Confirmed vulnerabilities — 1

#### A1 · Length-bypass via transparent Deserialize on PQ byte envelopes — P1
- **Bead:** `flywheel_connectors-kfr9j`
- **Where:**
  - `crates/fcp-crypto/src/owner_key.rs:41-43` (`MlDsa65VerifyingKeyBytes`)
  - `crates/fcp-crypto/src/owner_key.rs:92-94` (`MlDsa65SignatureBytes`)
  - `crates/fcp-crypto/src/xwing.rs:132-138` (`XWingPublicKey`)
- **Mechanism:** Each type enforces a length invariant in
  `try_from_bytes` (1952 / 3309 / 1216) but uses
  `#[serde(transparent)]` Deserialize that delegates straight to
  `Vec<u8>`'s deserializer — the length check is bypassed entirely.
- **Attack:** A peer-supplied `OwnerKeyMigrationAttestation` /
  `NodeKeyAttestation` (with `xwing_public_key: Some(...)`) /
  `HybridOwnerSignature` envelope deserialises with arbitrary-length
  payload. Downstream verification code (`MlDsa65VerifyingKey::from_envelope`,
  `EncodedSignature::<MlDsa65>::try_from`, …) errors at use time —
  fail-fast semantics are lost. In less-defensive callers, the array-
  conversion is a panic vector.
- **Triage rationale:** `(a)` because the wrapper TYPE'S invariant is
  documented and the constructor enforces it; the bypass is a real
  invariant violation, not a missing feature. P1 because the PQ
  deserialisation surfaces are the entry points for V4 owner-key
  migration ceremony evidence (`kyopb.1.1.3`) and V4 attestation
  carrying (`kyopb.1.2.3`).
- **Patch in this session:** see Action below.

### (b) Hardening worth doing — 3

#### B1 · Unbounded ciborium decode in V4 sealed-box + compatibility-ledger paths — P2
- **Bead:** `flywheel_connectors-gmak2`
- **Where:**
  - `crates/fcp-crypto/src/xwing.rs:334` —
    `XWingSealedBox::from_canonical_cbor`.
  - `crates/fcp-store/src/compatibility_ledger.rs:467` —
    `load_latest_pointers` (production startup path).
  - `crates/fcp-evidence/src/compatibility_ledger.rs::MeshCompatibilityLedger::from_canonical_cbor`
    (signed-ledger decoder; deeper struct than the others).
- **Mechanism:** Workspace standard is
  `ciborium::de::from_reader_with_recursion_limit(bytes,
  fcp_cbor::MAX_DESERIALIZATION_RECURSION_LIMIT)` (= 128). These
  three sites use the unguarded `ciborium::from_reader` directly.
- **Risk:** Recursion-bomb CBOR triggers ciborium's stack recursion
  before per-field length checks fire. Practically harder to exploit
  for the flat XWingSealedBox shape; more plausible for the
  `BTreeMap`-bearing MeshCompatibilityLedger.
- **Triage rationale:** `(b)` because no concrete crash demo today,
  but the workspace standard exists for a reason and deviating from
  it is silent risk accumulation. Filing rather than dropping
  because the V4 ingest paths grow over time.

#### B2 · ZoneKeyManifest V4 split-view: per-recipient V3 vs V4 wraps may carry distinct ciphertexts — P2
- **Bead:** `flywheel_connectors-shbvv`
- **Where:** `crates/fcp-core/src/zone_keys.rs:417-425`
  (`resolved_wrapped_key_for`), `:441-472` (`migrated_to_v4`),
  `:474-495` (`add_xwing_wrap`).
- **Mechanism:** The V4 schema has parallel `wrapped_keys` (V3) and
  `wrapped_keys_v4` (V4) lists. `resolved_wrapped_key_for` returns
  V4 first, falls back to V3. There is no validation that, when a
  recipient appears in both lists, the wrapped contents resolve to
  the same zone-key material.
- **Risk:** A misbehaving issuer can sign one manifest such that V3
  and V4 readers see different keys for the same zone — silently
  partitioning encrypted content. The owner signature commits to
  both lists, so it's not a forgery, but it is a way to bypass the
  design-doc §6 promise that V3 and V4 readers see the same zone
  key.
- **Triage rationale:** `(b)` because it requires a malicious or
  buggy issuer (signature still valid). Shipping migration without
  this check leaves the cohabitation invariant on the honour system.

#### B3 · PartialEq on secret-bearing PQ types is short-circuit (timing side-channel ready) — P3
- **Bead:** `flywheel_connectors-1zlht`
- **Where:**
  - `crates/fcp-crypto/src/owner_key.rs:41` — `MlDsa65VerifyingKeyBytes` derives `PartialEq, Eq`.
  - `crates/fcp-crypto/src/owner_key.rs:92` — `MlDsa65SignatureBytes` derives `PartialEq, Eq`.
  - `crates/fcp-crypto/src/xwing.rs:169` — `XWingSecretKey` derives `PartialEq, Eq`.
- **Mechanism:** Default derive uses `Vec<u8>::eq` / `[u8; N]::eq`,
  both short-circuit on first mismatch.
- **Risk surface today:** A workspace-wide grep found ZERO production
  comparisons on these types; the only equality usage is in test
  golden vectors. Defensive — a future refactor that adds a
  comparison would silently introduce a timing oracle.
- **Triage rationale:** `(b) defensive`. Most-acute target is
  `XWingSecretKey` (32-byte seed = direct keying material).

### (c) False positives / already mitigated — not filed

- **Lattice walker exhaustion** — `LatticeDelegationVerifierImpl::verify_sub_token`
  (`crates/fcp-policy/src/lattice_delegation.rs:514-538`) bounds the
  parent-chain walk at `params.depth` (= 4 for `V4_REFERENCE`) via
  `if hops >= self.params.depth { return ChainTooDeep }`. Self-loops
  (A → A) and cycles (A → B → A) terminate after `depth` hops. No
  allocations in the walk loop. Already pinned by
  `lattice_delegation_proptest::lattice_walker_adversarial_chain_never_panics_or_loops`.
- **HpkeSealedBox::from_bytes unbounded clone** — has explicit
  `bytes.len() > HPKE_MAX_CIPHERTEXT` check at
  `crates/fcp-crypto/src/hpke_seal.rs:79` BEFORE the clone. ✓
- **ZoneKemAlgorithm unknown-variant deserialize** — serde's tagged
  enum decode rejects unknown labels with a typed error. Pinned by
  `zone_key_manifest_v4_proptest::zone_key_manifest_v4_zone_kem_algorithm_arbitrary_string_never_panics`.
- **Fcp4Aad version-byte spoofing** — `Fcp4Aad` derives
  `Serialize` but NOT `Deserialize` (encode-only by design). A V3
  verifier cannot produce a `Fcp4Aad`; the version byte is
  load-bearing on encoding only.
- **X-Wing AEAD all-zero nonce** — sound under per-encap HKDF
  derivation. The shared secret is unique per encap (X-Wing combiner
  binds the ML-KEM ciphertext + X25519 ephemeral pk + recipient pk),
  so the derived AEAD key is unique, so the all-zero nonce is safe
  (RFC 9180 single-shot pattern). Pinned in design doc §4.2.
- **ML-KEM implicit rejection** — handled inside the upstream
  `x-wing` crate (FIPS 203 conformance); decap of a tampered
  ciphertext yields a junk shared secret that AEAD then rejects.
  Already pinned by
  `xwing_proptest::xwing_decap_arbitrary_ciphertext_never_panics`.
- **ML-DSA signature malleability** — `verify` returns `Ok(())` /
  `Err(SignatureVerificationFailed)` without assuming uniqueness.
  No production code path was found that compares two signatures for
  byte equality and treats inequality as a fork condition.

### (e) Auth bypass via empty/null/missing — not filed

- `ZoneKeyManifest.kem` is `#[serde(default)] = HpkeX25519`. The
  default is load-bearing for V3 backward compat (br-kyopb.1.2.3
  test pin); a missing field deserialises to V3 semantics. Not a
  bypass — an attacker who controls the manifest already controls
  the wraps.
- `NodeKeyAttestation.xwing_public_key` is
  `Option<XWingPublicKey>` with `#[serde(default)]`. Absent → V3-only
  recipient. Not a bypass — V4 senders fall back to HPKE-X25519 per
  the cohabitation matrix (design doc §6).
- `ZoneKeyManifest.wrapped_keys_v4` defaults to empty Vec. Empty →
  no V4 recipients. Not a bypass.

## Action taken in this session

Per audit instructions ("If any (a) findings exist, claim and patch
the highest-priority one yourself in this same session"):

- **A1 (`kfr9j`)** — claimed and patched. Implemented custom
  Deserialize for the three transparent envelopes
  (`MlDsa65VerifyingKeyBytes`, `MlDsa65SignatureBytes`,
  `XWingPublicKey`) that calls `try_from_bytes` after the inner Vec
  is materialised, surfacing the existing typed length errors at
  deserialize time. Regression tests in `fcp-crypto/tests/`.

## Files filed

- `flywheel_connectors-kfr9j` — A1 (P1, patched in this session)
- `flywheel_connectors-gmak2` — B1 (P2)
- `flywheel_connectors-shbvv` — B2 (P2)
- `flywheel_connectors-1zlht` — B3 (P3)
