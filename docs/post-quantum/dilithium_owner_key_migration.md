# CRYSTALS-Dilithium Owner-Key Migration

**Bead:** `flywheel_connectors-kyopb.1.1` (J.5.1)
**Status:** DESIGN ONLY, plus fcp-crypto trait stubs; no ML-DSA provider in this commit.
**Author:** SilverFox
**Date:** 2026-05-02
**Scope:** V3 Ed25519 owner-key roots to V4 ML-DSA-65 owner-key roots with a V3-V4 cross-signed attestation chain.

## 1. Summary

FCP V3 owner authority is anchored by Ed25519 keys. Ed25519 remains the right
classical baseline, but it is not post-quantum. V4 owner authority moves to
ML-DSA-65, the FIPS 204 standardized parameter set that corresponds to the
old CRYSTALS-Dilithium-3 deployment target. The migration is not a key
replacement in place. It is an append-only chain transition:

1. freeze and hash the last trusted V3 owner state;
2. generate or import the new V4 ML-DSA-65 owner key;
3. build one canonical migration transcript binding the old key, the new key,
   and both attestation-state hashes;
4. sign that transcript with both the V3 Ed25519 owner key and the V4
   ML-DSA-65 owner key;
5. publish the cross-signed attestation before accepting any V4-only owner
   object.

The result is an auditable bridge: historical V3 owner objects remain
verifiable under their Ed25519 root, and every new V4 owner object is accepted
only if the verifier can walk through the dual-signed migration attestation to
the ML-DSA-65 root.

## 2. Terminology

| Term | Meaning |
| ---- | ------- |
| V3 owner key | Existing Ed25519 owner signing key used for owner-governed objects. |
| V4 owner key | New ML-DSA-65 owner signing key. |
| ML-DSA-65 | FIPS 204 Module-Lattice-Based Digital Signature Algorithm parameter set with category 3 strength; this is the standardized successor to the Dilithium-3 target. |
| Migration transcript | Canonical bytes signed by both owner keys. |
| Migration attestation | Envelope containing the transcript plus `signed_with_v3` and `signed_with_v4`. |
| Cutover epoch | Monotonic owner-governance epoch after which new owner objects require V4 policy. |

## 3. Security Objective

The migration must preserve these invariants:

- A verifier that trusted the V3 Ed25519 owner root can authenticate the V4
  ML-DSA-65 owner root without out-of-band key substitution.
- A verifier that starts after cutover can still validate historical V3
  objects by walking the append-only chain back through the migration object.
- No attacker can replace the V4 key, replay an old migration, downgrade a V4
  object to V3-only validation, or splice together signatures from different
  ceremonies.
- Rollback is explicit and append-only. No ledger entry is deleted or rewritten.

## 4. Cryptographic Choices

### 4.1 Parameter Set

Use ML-DSA-65 for V4 owner keys. FIPS 204 defines three ML-DSA parameter
sets; ML-DSA-65 is the category 3 middle option and maps to the previous
Dilithium-3 deployment target. It is a reasonable owner-key default because
owner signatures are less frequent than session signatures, while owner-key
compromise has high blast radius.

FIPS 204 Table 2 fixes these encoded sizes:

| Object | Bytes |
| ------ | ----: |
| ML-DSA-65 public key | 1952 |
| ML-DSA-65 private key | 4032 |
| ML-DSA-65 signature | 3309 |

The fcp-crypto stubs enforce the public-key and signature lengths before any
provider is wired. Provider selection remains a follow-up because the provider
must come with KATs, reproducible test vectors, side-channel notes, and a clear
maintenance posture.

### 4.2 Signing Mode

The migration transcript is small and canonical, so V4 should use pure
ML-DSA-65, not HashML-DSA, unless provider validation or CAVP requirements
force a different deployment profile. If a provider exposes both deterministic
and hedged signing, the ceremony should use hedged signing with approved
randomness and should record the provider/version in the evidence bundle.

### 4.3 Key Identifiers

FCP key identifiers continue to be derived from encoded public-key bytes. The
migration transcript carries both:

- `prior_v3_kid`: derived from the trusted Ed25519 V3 owner public key;
- `new_v4_kid`: derived from the encoded ML-DSA-65 V4 owner public key.

Verifiers must recompute both identifiers from the supplied public keys and
fail closed if either value does not match the transcript.

## 5. Attestation Object

The canonical attestation shape is:

```rust
struct OwnerKeyMigrationAttestation {
    transcript: OwnerKeyMigrationTranscript,
    signed_with_v3: Ed25519Signature,
    signed_with_v4: MlDsa65SignatureBytes,
}

struct OwnerKeyMigrationTranscript {
    schema: "fcp.owner-key-migration.v1",
    prior_v3_kid: KeyId,
    new_v4_kid: KeyId,
    prior_v3_attestation_hash: [u8; 32],
    new_v4_attestation_hash: [u8; 32],
    migration_epoch: u64,
    not_before_unix: u64,
    not_after_unix: u64,
}
```

The signed payload is:

```text
FCP-OWNER-KEY-MIGRATION-V1
|| len(schema) || schema
|| prior_v3_kid
|| new_v4_kid
|| prior_v3_attestation_hash
|| new_v4_attestation_hash
|| migration_epoch_le
|| not_before_unix_le
|| not_after_unix_le
```

Both signatures sign exactly the same bytes. Signatures are excluded from the
transcript hash and from the bytes being signed.

## 6. Migration Ceremony

### 6.1 Inventory and Freeze

1. Read the canonical V3 owner map and last accepted owner-governed objects.
2. Resolve the active V3 Ed25519 public key and compute `prior_v3_kid`.
3. Compute `prior_v3_attestation_hash` over the last trusted V3 owner-state
   object. This hash is the final V3 anchor for the migration.
4. Freeze owner-governed writes while the migration transcript is generated.
   Runtime reads may continue.

### 6.2 Generate or Import V4 Key

1. Generate or import one ML-DSA-65 owner key in the configured offline/HSM
   ceremony environment.
2. Export only the encoded public key and provider metadata to the ceremony
   workspace.
3. Compute `new_v4_kid` from the public key.
4. Build the first V4 owner-state object and compute
   `new_v4_attestation_hash`.

### 6.3 Cross-Sign

1. Build `OwnerKeyMigrationTranscript`.
2. Sign `transcript.signing_bytes()` with the V3 Ed25519 key.
3. Sign the same bytes with the V4 ML-DSA-65 key.
4. Verify both signatures in a fresh verifier process before publication.
5. Publish the migration attestation and evidence bundle atomically as an
   append-only owner-governance event.

### 6.4 Dual Verification Window

During the hybrid window, new owner-governed objects carry V4 ML-DSA-65
signatures and may additionally carry V3 Ed25519 signatures for compatibility.
V4-capable verifiers require:

- a valid migration attestation;
- a non-rollback `migration_epoch`;
- valid Ed25519 and ML-DSA-65 signatures over the migration transcript;
- a V4 object signature under `new_v4_kid`;
- no active revocation of either the migration object or the V4 owner key.

V3-only verifiers may keep reading historical V3 objects but must not be
allowed to authorize new Risky, Dangerous, or Critical owner actions after the
cutover policy enters `DualSignRequired`.

### 6.5 V4 Enforcement

After the configured cutover epoch:

- new owner-governed objects require ML-DSA-65;
- Ed25519 signatures on new objects are audit-only compatibility material;
- V3-only owner writes are rejected;
- historical V3 objects remain valid only when they chain into the accepted
  migration attestation.

## 7. Verifier Algorithm

For a candidate migration attestation:

1. Rebuild canonical signing bytes from the transcript.
2. Check `schema == "fcp.owner-key-migration.v1"`.
3. Check the validity window and reject expired or not-yet-valid objects.
4. Check `migration_epoch` is strictly greater than the last accepted owner
   migration epoch for the mesh.
5. Resolve `prior_v3_kid` in the trusted V3 owner map.
6. Recompute `new_v4_kid` from the supplied ML-DSA-65 public key.
7. Check both attestation-state hashes against their referenced objects.
8. Verify `signed_with_v3` with the V3 Ed25519 owner public key.
9. Verify `signed_with_v4` with the V4 ML-DSA-65 owner public key.
10. Persist acceptance as an append-only ledger event keyed by the transcript
    hash.

Any failure is terminal for that attestation. Verifiers must not accept a
single-signature bridge, a mismatched key id, or a replayed lower epoch.

## 8. Rollback and Cancellation

Rollback depends on phase.

| Phase | Rollback rule |
| ----- | ------------- |
| Before publication | Discard the unpublished ceremony output. No ledger object exists. |
| Published, before activation | Publish a cancellation object signed by the V3 key and, if available, the V4 key. |
| Hybrid window | Publish a rollback object signed by both owner keys with a higher epoch. Revoke the V4 key id for new writes. |
| After V4 enforcement | Do not allow unilateral V3 rollback. Use the V4 emergency owner-recovery process or owner quorum to publish a higher-epoch rollback/rekey object. |

Rollback objects are append-only. They do not remove the failed migration; they
mark it superseded and bind the reason, epoch, and replacement policy.

## 9. Risks and Mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Standards drift or errata | Track NIST FIPS 204 errata before provider lock-in; version the provider and KAT suite in the evidence bundle. |
| Provider maturity | Treat provider selection as a separate bead requiring KATs, negative tests, fuzzing, and maintenance review. |
| Side channels and signing randomness | Prefer hedged signing with approved randomness; record provider mode; keep V4 private keys offline/HSM-backed. |
| Signature/object size growth | Budget 3309-byte owner signatures in manifests, revocation pushes, supply-chain attestations, and gossip messages. |
| Transcript ambiguity | Sign only canonical bytes with a domain separator and explicit schema; exclude signatures from the transcript hash. |
| Downgrade to V3-only | After cutover, reject new owner-governed objects that lack V4 ML-DSA-65 signatures even if Ed25519 verifies. |
| Replay of old migration | Require monotonic `migration_epoch`, validity windows, and append-only acceptance state. |
| Key substitution | Recompute both KIDs from public keys and bind both attestation-state hashes in the transcript. |
| Ceremony operator error | Add `fwc bootstrap migrate-owner-key --dry-run`, machine-checkable evidence bundles, and independent fresh-process verification. |
| Historical verification loss | Preserve V3 owner public keys and the accepted migration attestation forever in the audit chain. |

## 10. Test Plan

Provider work must add:

- FIPS 204 ML-DSA-65 keygen/sign/verify known-answer tests;
- malformed public-key and signature length rejection;
- transcript golden vectors for the migration payload;
- positive verification of the cross-signed attestation;
- negative tests for swapped keys, swapped hashes, lower epochs, expired
  windows, missing signatures, and mismatched `new_v4_kid`;
- rollback and cancellation verification cases;
- fuzz coverage for canonical transcript decoding and signature envelope
  parsing;
- size/performance assertions for owner-governed paths that carry ML-DSA-65
  signatures.

## 11. Implementation Beads

The implementation work is intentionally split from this design/stub bead:

| Bead | Scope |
| ---- | ----- |
| `flywheel_connectors-kyopb.1.1.3` | Implement ML-DSA-65 provider and KATs in fcp-crypto. |
| `flywheel_connectors-kyopb.1.1.1` | Add V3-V4 owner-key migration attestation verifier. |
| `flywheel_connectors-kyopb.1.1.4` | Wire hybrid owner verification into enrollment, zone manifests, emergency revocation, and supply-chain owner-governed objects. |
| `flywheel_connectors-kyopb.1.1.2` | Add `fwc bootstrap migrate-owner-key --from v3 --to v4` ceremony tooling. |

## 12. References

- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 204 PDF](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)
- [FCP3 Canonical Owner Map](../FCP3_Canonical_Owner_Map.md)
- [V3/V4 Compatibility Ledger](v3_v4_compatibility_ledger.md)
