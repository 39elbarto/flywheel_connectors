# X-Wing KEM Zone-Key Replacement — Design Doc

**Bead:** `flywheel_connectors-kyopb.1.2` (J.5.2)
**Status:** DRAFT — design only; no implementation in this commit.
**Authors:** CrimsonWolf
**Date:** 2026-05-02
**Replaces (when implemented):** `fcp-crypto::hpke_seal::*` for the zone-key sealing path in V4 manifests.

---

## 1. Motivation

FCP V3 seals zone-key material with HPKE in the
`DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305` profile
(`crates/fcp-crypto/src/hpke_seal.rs`). The KEM half rests entirely on the
discrete-log problem in Curve25519. A future cryptographically relevant
quantum computer (CRQC) would let an attacker who **harvested** V3
`ZoneKeyManifest` blobs in 2026 decrypt them in, say, 2035 — exposing every
zone-encrypted object that ever existed under that key.

V4 needs a KEM that is secure against both:

- **classical adversaries today** (lattice schemes are still relatively young
  and have suffered cryptanalytic surprises — see SIDH/SIKE in 2022), and
- **quantum adversaries tomorrow** (X25519 is broken in polynomial time by
  Shor's algorithm).

The conservative answer is a **hybrid KEM**: combine a battle-tested
classical KEM with a NIST-standardised lattice KEM such that breaking either
component does not break the construction. X-Wing is the concrete hybrid the
IETF CFRG converged on for general-purpose deployments.

## 2. What is X-Wing?

X-Wing is a hybrid KEM specified in
**draft-connolly-cfrg-xwing-kem** (Connolly, Schwabe, Westerbaan, et al.,
2024+). It composes:

- **ML-KEM-768** (FIPS 203, the standardised version of CRYSTALS-Kyber-768) —
  Module-LWE, NIST PQC Round-3 winner, ≥ AES-192 classical / Cat. 3 PQ.
- **X25519** — Curve25519 ECDH, well-understood classical KEM.
- A **combiner** that hashes both shared secrets together with the
  ML-KEM ciphertext, the X25519 ephemeral public key, and the long-term
  X25519 public key, producing one 32-byte shared secret.

The combiner is what makes the construction *binding* (IND-CCA secure even
under decryption-failure attacks against ML-KEM and even if the X25519
public key is malleated). Specifically (paraphrasing the draft):

```
ss = SHA3-256(
    "\\.//^\\"                    // X-Wing label, 6 bytes
 || ml_kem_shared_secret           // 32 bytes
 || x25519_shared_secret           // 32 bytes
 || x25519_ephemeral_public        // 32 bytes
 || x25519_recipient_public        // 32 bytes
)
```

Both sub-KEMs run **independently** during encapsulation and decapsulation;
neither output is fed into the other. This is what gives the "hybrid"
guarantee: if ML-KEM is later broken (e.g. dramatic lattice attack), the
X25519 half still seals the secret — and vice versa for a CRQC.

### 2.1 Sizes

| Field             | Bytes  | Notes                                         |
| ----------------- | -----: | --------------------------------------------- |
| Public key        | 1216   | `pk_mlkem` (1184) ‖ `pk_x25519` (32)          |
| Secret key        | 32     | 32-byte seed (X-Wing draft 06; expanded to ~2.4 KiB on demand via SHAKE256, see ADR kyopb121-xwing-kem-vendor) |
| Ciphertext (enc)  | 1120   | `ct_mlkem` (1088) ‖ `ct_x25519` (32)          |
| Shared secret     | 32     | output of combiner                            |

Compared with our current X25519 HPKE profile, the V4 sealed wrapper grows
by **~1.15 KiB per recipient**. For a 32-node zone that's ~36 KiB extra
in the manifest. Acceptable; we already cap manifests at 64 KiB
(`HPKE_MAX_CIPHERTEXT`) and the V4 cap will be lifted accordingly.

### 2.2 Why X-Wing and not "ML-KEM only" or "Kyber + X25519 ad-hoc"

- **ML-KEM only** loses the classical hedge. If a structural break of
  Module-LWE shows up in 2028, V4 zone keys silently lose all
  confidentiality. Hybrid is cheap insurance.
- **Ad-hoc concatenation KEMs** (e.g. early TLS hybrid drafts that just
  XOR'd two shared secrets) have repeatedly proven fragile under modern
  IND-CCA proofs. X-Wing's combiner is *proved* binding in the draft;
  rolling our own combiner would be a footgun.
- **HPKE with hybrid KEM extension** (draft-westerbaan-cfrg-hpke-xyber)
  is an alternative — but it bakes the hybrid into HPKE's KDF and AEAD
  context, which is more invasive to swap. X-Wing as a standalone KEM
  composes cleanly with our existing AEAD layer.

## 3. Wire Format

### 3.1 Sealed-box envelope (`XWingSealedBox`)

```rust
struct XWingSealedBox {
    // V4 KEM ciphertext: ct_mlkem (1088 B) || ct_x25519 (32 B)
    enc:        [u8; 1120],

    // ChaCha20-Poly1305 ciphertext over the wrapped key material.
    // AEAD key is HKDF-SHA256(IKM = ss, salt = aad_bytes, info = "FCP4-XWING-AEAD")
    // truncated to 32 bytes.
    ciphertext: Vec<u8>,
}
```

CBOR shape (canonical, deterministic encoding via `fcp_crypto::canonicalize`):

```cbor
{
    1: bstr (1120 bytes),  ; enc
    2: bstr,               ; ciphertext (length = plaintext_len + 16 tag)
}
```

Encoding choices:

- The `enc` field is **fixed-length**; deserialisers MUST reject anything
  other than 1120 bytes.
- The `ciphertext` field MUST be ≤ `XWING_MAX_CIPHERTEXT = 64 * 1024` bytes
  (mirrors the existing HPKE cap in `hpke_seal.rs:35`).
- We do **not** use the IETF "OneShot encrypt" HPKE wrapper here, because
  X-Wing is the KEM-only primitive; AEAD framing is layered above it
  inside FCP exactly the way it is for HPKE today.

### 3.2 KEM identifier in `ZoneKeyManifest`

`fcp-core::zone_keys::ZoneKeyAlgorithm` currently encodes only the *symmetric*
zone-key cipher (`ChaCha20Poly1305`, `XChaCha20Poly1305`). A new field
`kem` is added to the V4 manifest to discriminate the KEM used to seal the
`WrappedZoneKey`:

```rust
#[serde(rename_all = "snake_case")]
pub enum ZoneKemAlgorithm {
    /// V3 baseline: HPKE(DHKEM-X25519, HKDF-SHA256, ChaCha20-Poly1305).
    HpkeX25519,
    /// V4 hybrid: X-Wing (ML-KEM-768 + X25519) + ChaCha20-Poly1305 AEAD.
    XWing,
}
```

The `WrappedZoneKey` struct gains an enum-tagged variant to carry whichever
sealed-box wire form was used:

```rust
#[serde(tag = "kem", rename_all = "snake_case")]
pub enum WrappedKey {
    HpkeX25519 { sealed: HpkeSealedBox },
    XWing      { sealed: XWingSealedBox },
}
```

Existing V3 manifests deserialise as `HpkeX25519` for backward
compatibility (see §6).

### 3.3 AAD binding

`Fcp2Aad` is reused unchanged (purpose string `b"FCP2-ZONE-KEY"` →
`b"FCP4-ZONE-KEY"` for the new path), and is fed into the AEAD `seal`
and `open` calls, exactly as today. The AEAD key is derived from the
X-Wing shared secret via HKDF-SHA256 with the AAD bytes as `salt`, so the
AAD is bound to both the AEAD nonce/auth-tag and the KDF output.

## 4. Key Generation, Encap, Decap

### 4.1 Key generation

```
(pk_mlkem, sk_mlkem) = ML-KEM-768.KeyGen(seed_mlkem_64B)
sk_x25519            = X25519.scalar_clamp(seed_x25519_32B)
pk_x25519            = X25519.derive_public(sk_x25519)
pk = pk_mlkem || pk_x25519                     // 1216 B
sk = 32-byte seed                              // wire/storage form (draft 06)
                                                // expand: SHAKE256(seed) → sk_mlkem || sk_x25519
                                                // pk_x25519 = X25519.derive_public(sk_x25519)
```

Both seeds come from `OsRng` (or a caller-provided `CryptoRng + RngCore`
for deterministic test vectors — same pattern as
`hpke_seal_with_rng`).

### 4.2 Encapsulation (`xwing_seal`)

```
(ss_mlkem, ct_mlkem) = ML-KEM-768.Encaps(pk_mlkem)
sk_eph_x25519        = X25519.generate_ephemeral()
pk_eph_x25519        = X25519.derive_public(sk_eph_x25519)
ss_x25519            = X25519.dh(sk_eph_x25519, pk_x25519)
ct_x25519            = pk_eph_x25519
ss = SHA3-256(LABEL || ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519)
enc = ct_mlkem || ct_x25519                    // 1120 B

aead_key = HKDF-SHA256(IKM = ss, salt = aad.encode(), info = "FCP4-XWING-AEAD")[0..32]
ciphertext = ChaCha20Poly1305(aead_key, nonce_zero, plaintext, aad.encode())
```

Notes:

- `LABEL = b"\\.//^\\"` per draft-connolly §3.
- `nonce_zero` is **required** for one-shot KEM/DEM construction: the AEAD
  key is unique per `enc` (because `ss` is bound to the ephemeral pk),
  so a fresh nonce per (key, recipient) pair is unnecessary. This matches
  how RFC 9180 HPKE single-shot mode operates.

### 4.3 Decapsulation (`xwing_open`)

```
ct_mlkem  = enc[0..1088]
ct_x25519 = enc[1088..1120]
ss_mlkem  = ML-KEM-768.Decaps(sk_mlkem, ct_mlkem)
ss_x25519 = X25519.dh(sk_x25519, ct_x25519)
ss = SHA3-256(LABEL || ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519)

aead_key  = HKDF-SHA256(IKM = ss, salt = aad.encode(), info = "FCP4-XWING-AEAD")[0..32]
plaintext = ChaCha20Poly1305.Open(aead_key, nonce_zero, ciphertext, aad.encode())
```

ML-KEM Decaps uses **implicit rejection**: invalid ciphertexts produce a
pseudo-random `ss_mlkem` rather than failing, so the AEAD `Open` step is
the single point of authenticity. This matches the X-Wing draft and is
necessary for IND-CCA in the joint construction.

## 5. Integration Points

### 5.1 fcp-crypto (this commit — stub only)

A new module `fcp-crypto::xwing` is added with:

- `XWingPublicKey`, `XWingSecretKey`, `XWingSealedBox` types (declared, not yet
  populated with crate-backed bytes).
- A `pub trait XWingKem` that names the four operations the production impl
  must satisfy (`generate`, `seal`, `open`, `wire_size`).
- A `XWingStub` type that implements the trait by returning
  `CryptoError::HpkeFailed("xwing not yet implemented (br-kyopb.1.2.{1..5})")`.
  The stub exists to give downstream code a concrete trait object to type
  against during the V4 wiring sub-beads, and to provide a single grep
  target for "where will the real impl plug in".

This crate gains **no** new third-party deps in this commit. The eventual
implementation will pull in either the `ml-kem` crate (RustCrypto) or
`pqcrypto-mlkem` (PQClean bindings) — the trade-off is captured in
sub-bead `kyopb.1.2.1`.

### 5.2 fcp-core (sub-bead `kyopb.1.2.3`)

`ZoneKeyManifest` gets a `kem: ZoneKemAlgorithm` field (defaulted to
`HpkeX25519` for serde-deserialisation of V3 manifests) and the
`WrappedZoneKey` struct's `sealed: HpkeSealedBox` becomes
`sealed: WrappedKey` (enum). The `wrapped_key_for(node_id)` method returns
the enum and callers match on it.

Cross-cutting impact: `ZoneKeyManifest::canonical_signing_bytes` MUST place
the `kem` field at a stable position in the CBOR map so that V3 verifiers
which skip unknown fields still get a verifying signature, *and* so that V4
verifiers see the new field. This is the standard CBOR-evolution trick we
already use elsewhere (e.g. `RekeyPolicy` is `Option`).

### 5.3 fcp-mesh zone-key rotation (sub-bead `kyopb.1.2.4`)

`fcp-mesh::node` builds and verifies `ZoneKeyManifest` blobs during:

- initial zone-key issuance (`MeshNode::publish_initial_zone_key`),
- rekey on membership change (`RekeyPolicy::rewrap_on_membership_change`),
- post-revocation rotation (the C1.x revocation-timing path).

Each of these call sites currently picks an `HpkeSealedBox` per recipient.
In V4 they pick a `WrappedKey` based on the local
`ProtocolVersionPolicy::preferred_kem` setting (new field, with fallback
matrix per §6). The recipient's published encryption key set determines
which KEMs are *available*: a node's `NodeKeyAttestation` will gain an
optional `xwing_public_key` field; if absent, sender falls back to
`HpkeX25519`.

### 5.4 fcp-protocol (sub-bead `kyopb.1.2.2`)

The wire-protocol-level enum `SymbolZoneKeyAlgorithm` (referenced in
`fcp-mesh::degraded::protocol_zone_key_algorithm`) currently mirrors only
the AEAD variants. It does not need to change for this work — the KEM
discrimination lives in `ZoneKeyManifest`, not in the per-symbol envelope.

## 6. Backward Compatibility (V3 ↔ V4)

The acceptance criterion in the bead requires that **V3 nodes can still
receive HPKE-sealed zone keys; V4-only nodes use X-Wing**. The compatibility
matrix is:

| Sender supports | Recipient supports | Wire format used                              |
| --------------- | ------------------ | --------------------------------------------- |
| V3 only         | V3 only            | `HpkeX25519`                                  |
| V3 only         | V4                 | `HpkeX25519` (recipient accepts V3 forever)   |
| V4              | V3 only            | `HpkeX25519` (sender downgrades per recipient)|
| V4              | V4                 | `XWing` (preferred)                           |
| V4-only         | V3 only            | **REFUSE** — surfaced as `KemNegotiationFailed` |

Mechanics:

1. The `ZoneKeyManifest.wrapped_keys` list is **per recipient**; the sender
   independently chooses a `WrappedKey` variant per entry. So a single V4
   manifest can carry an `XWing` sealed wrap for the V4 nodes and an
   `HpkeX25519` sealed wrap for the V3 nodes, in the same blob.
2. V3 deserialisers see the V4 `kem` field as unknown and skip it
   (CBOR map with unknown keys); they iterate `wrapped_keys` looking for
   their `HpkeX25519` variant. **This requires** the V3 deserialiser to
   tolerate enum-tagged variants it doesn't recognise — it currently does
   not (it expects a concrete `HpkeSealedBox`). Sub-bead `kyopb.1.2.3`
   includes a V3 deserialiser shim that accepts the V4 enum-tagged form
   and silently drops `XWing` entries.
3. V4-only nodes use `ProtocolVersionPolicy::reject_v3_recipients = true`
   to refuse to mint manifests that would emit `HpkeX25519` wraps. The
   default for V4 nodes is **false** (cohabit gracefully) until the
   migration ledger (`kyopb.1.4`) declares the cutover.

### 6.1 Downgrade attack mitigation

A V4 sender that *can* offer `XWing` to a V4 recipient MUST not be
silently downgraded to `HpkeX25519` by an adversary on the path. We rely
on the manifest signature for this: the `ZoneKeyManifest` is signed by
the owner key, so an attacker cannot rewrite the recipient's wrapped-key
variant from `XWing` to `HpkeX25519` without invalidating the signature.

The risk that remains is at *manifest issuance time* — a malicious sender
who chose to emit `HpkeX25519` even though both ends supported `XWing`.
Mitigation: the V4 receiver consults its policy; if its
`ProtocolVersionPolicy::require_pq_kem` is set, it refuses to load any
zone key whose wrap is non-PQ (raising `KemTooWeak`). This is opt-in
because it breaks compatibility, but it gives security-paranoid operators
a knob to pull.

## 7. Threat Model

### In scope

- **Harvest-now-decrypt-later** by a future CRQC.
  Defended by ML-KEM-768 component.
- **Classical adversary running today** with no quantum capability.
  Defended by X25519 component (and ML-KEM if Module-LWE truly is hard).
- **Cryptanalytic break of ML-KEM** that publishes shared secrets.
  Defended by the X-Wing combiner — `ss_x25519` is mixed in, so
  knowing `ss_mlkem` alone yields no leverage.
- **Cryptanalytic break of X25519** (e.g. an unexpected CDH break).
  Defended symmetrically — `ss_mlkem` is mixed in.

### Out of scope (explicitly punted)

- **Side-channel attacks against the implementation.** ML-KEM has known
  side-channel concerns (timing, power-analysis); production wiring must
  use a constant-time implementation. Sub-bead `kyopb.1.2.1` requires
  a vendor-selection note covering this.
- **Authentication of the recipient public key.** That's handled by the
  existing `NodeKeyAttestation` + `OwnerSigner` chain. X-Wing assumes
  it has been handed an authentic `pk_xwing`; if the attestation chain
  is forged, no KEM choice helps.
- **Long-term quantum signatures.** Owner keys are still Ed25519 in this
  bead; that migration is `kyopb.1.1` (Dilithium / ML-DSA).

## 8. Test Vectors and Conformance

- The X-Wing draft ships normative test vectors. Production impl MUST
  pass them byte-for-byte (sub-bead `kyopb.1.2.1`, "draft-spec test
  vectors" acceptance criterion from the parent bead).
- A round-trip property test: for any `(plaintext, aad)`, `xwing_seal`
  followed by `xwing_open` returns `plaintext`. (sub-bead `kyopb.1.2.5`)
- A hybrid-security regression: replace `ss_mlkem` with all-zeros and
  confirm `xwing_open` still succeeds (because X25519 still seals).
  Replace `ss_x25519` with all-zeros and confirm same. Then zero **both**
  and confirm `xwing_open` rejects (sanity-check that the AEAD actually
  authenticates). (sub-bead `kyopb.1.2.5`)
- A V3-recipient interop test: build a V4 manifest with a mix of
  `HpkeX25519` and `XWing` wraps and verify both kinds open with the
  appropriate keys. (sub-bead `kyopb.1.2.4`)

## 9. Performance

Indicative figures from public ML-KEM benchmarks on Apple M-series
silicon (single core):

| Operation     | HPKE-X25519 | X-Wing (X25519 + ML-KEM-768) | Ratio |
| ------------- | ----------- | ---------------------------- | ----- |
| KeyGen        | ~30 µs      | ~80 µs                       | 2.6×  |
| Encap         | ~30 µs      | ~70 µs                       | 2.3×  |
| Decap         | ~30 µs      | ~95 µs                       | 3.2×  |

Zone-key issuance and rotation are *control-plane* operations (one per
membership change, not per object), so even a 3× decap cost is
operationally negligible. Per-object encryption stays on
ChaCha20-Poly1305 and is unchanged.

The wire-size impact (~1.15 KiB extra per recipient) is the more
interesting cost and was discussed in §2.1.

## 10. Open Questions (to resolve in sub-beads)

- **Q1.** RustCrypto `ml-kem` (pure Rust, easier to audit) vs.
  `pqcrypto-mlkem` (PQClean C bindings, faster, more eyes on it).
  Decide in `kyopb.1.2.1`.
- **Q2.** Should the AEAD layer over the X-Wing shared secret be
  `XChaCha20Poly1305` (24-byte nonce, lets us pick a fixed all-zero
  nonce *or* a random one) instead of ChaCha20-Poly1305? Probably yes
  for V4 to give us nonce-misuse resistance. Decide in `kyopb.1.2.2`.
- **Q3.** Where do we store the V4 X-Wing public key alongside the V3
  X25519 encryption key in `NodeKeyAttestation`? Add a sibling field
  vs. a polymorphic `encryption_keys: Vec<EncryptionKey>` list.
  Decide in `kyopb.1.2.3`.
- **Q4.** Does the lattice-trapdoor capability work (`kyopb.1.3`) want
  to share the X-Wing key, or does it need its own lattice key pair?
  Cross-bead question; track in `kyopb.1.2.5`.
- **Q5.** Is X-Wing draft ratification timeline acceptable, or do we
  need to be ready to swap to a different IETF-blessed hybrid (e.g.
  HPKE-Xyber768) if the X-Wing draft stalls? Track in `kyopb.1.2.5`.

## 11. Sub-Beads Filed

- `kyopb.1.2.1` — vendor selection + draft test-vector harness
- `kyopb.1.2.2` — wire format + AEAD profile finalisation
- `kyopb.1.2.3` — `ZoneKeyManifest` V4 schema migration
- `kyopb.1.2.4` — fcp-mesh zone-key rotation cutover + interop
- `kyopb.1.2.5` — round-trip + hybrid-security + perf benchmarks

## 12. References

- Connolly, Schwabe, Westerbaan et al., **draft-connolly-cfrg-xwing-kem**
  (IETF CFRG, 2024+).
- NIST FIPS 203, **Module-Lattice-Based Key-Encapsulation Mechanism Standard**
  (ML-KEM), 2024.
- RFC 9180, **Hybrid Public Key Encryption** (HPKE), 2022.
- Bernstein, **Curve25519: New Diffie–Hellman Speed Records**, PKC 2006.
- Castryck & Decru, **An efficient key recovery attack on SIDH**, EUROCRYPT
  2023 — cautionary tale for "lattice-only" deployments.
