# Threshold HPKE KEM Reusing FROST DKG Substrate

Bead: `flywheel_connectors-angoc.11.6` (Phase Q.G — alien-graveyard
Top-5 rank 5)

## Goal

Reuse the FROST DKG / Pedersen VSS infrastructure already deployed
for **threshold signing** to ALSO yield a **threshold key-encapsulation
keypair** — the same ceremony produces both capabilities. This
unlocks cross-mesh sealed objects (objects encrypted to a quorum of
peers) without standing up a parallel ceremony for HPKE.

## Why this matters

Today, an object that must be readable only by a t-of-n quorum of
mesh peers requires either:

1. **Sealed to one peer**, who then redistributes — single point of
   trust until the quorum is reached, defeating the threshold goal.
2. **A separate threshold-KEM ceremony**, doubling the operator
   setup cost and the key-rotation surface.

By deriving the HPKE keypair from the SAME Pedersen VSS shares that
back the FROST signing key, both signing and encapsulation share:

- One ceremony per epoch (already deployed in `fcp-bootstrap`).
- One quorum-rotation event when the threshold set changes.
- One revocation mechanism (revoke a participant's share → both
  sign and encap capabilities are gone).

The cost: an additional ~16 ms per encap to derive the public key
from the VSS commitment, paid once per object-seal rather than per
decap.

## Cryptographic shape

FROST uses Ed25519 by default in `fcp-bootstrap`. The threshold
KEM lives on the SAME curve via a domain-separated derivation:

```
threshold_signing_keypair    = FROST_DKG(t, n, ctx="frost-sign-v1")
threshold_kem_keypair        = FROST_DKG(t, n, ctx="frost-kem-v1")
```

Both ceremonies run in parallel during the SAME DKG round trip — the
participants exchange two parallel commitment streams, double the
share size on the wire, but a single timing-controlled ceremony.

The public-key package emitted by the ceremony carries TWO group
elements:

```
PublicKeyPackage {
    signing_pk: VerifyingKey<Ed25519>,
    kem_pk: PublicKey<X25519>,  // derived from signing share via domain-separated HKDF
}
```

`kem_pk` is structurally a Curve25519 point (X25519), but it's
derived from the same Ed25519 share via the standard Ed25519-to-
Curve25519 mapping (RFC 7748 + clamping). This is a documented
deviation from RFC 9180 HPKE: standard HPKE uses an independent
X25519 keypair; we derive from the FROST share for the substrate-
reuse goal.

## Threshold encap / decap

Encapsulation (any single party can encap to the threshold KEM
public key — that's the point of asymmetric KEM):

```rust
let pkpkg: PublicKeyPackage = ceremony.public_key_package();
let (ct, ss) = threshold_hpke::encap(&pkpkg.kem_pk, info)?;
// ct = ciphertext for transmission; ss = shared secret for AEAD
```

Decapsulation requires t-of-n participants to contribute their share
of the X25519 secret:

```rust
let shares: Vec<DecapShare> = participants.iter()
    .map(|p| p.decap_share(&ct))
    .collect();
let ss = threshold_hpke::combine_decap(&shares, t)?;
// ss matches the encap's shared secret
```

The roundtrip property:

```
∀ payload P, ∀ ceremony (t, n), ∀ subset S ⊆ participants with |S| = t:
    decap(encap(pk, info, P), S) = P
```

The conformance test exercises this property with the 2-of-3
fixture (the default DKG config for FROST signing).

## Component layout

```
crates/fcp-crypto/src/threshold_hpke.rs        (encap, decap, combine)
crates/fcp-crypto/src/threshold_hpke/derive.rs (FROST share -> X25519 share)
crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs (2-of-3 RT)
crates/fcp-e2e/tests/threshold_hpke_sealed_object_e2e.rs
crates/fcp-conformance/tests/fixtures/threshold_hpke/  (golden vectors)
docs/architecture/threshold_hpke_kem.md         (THIS FILE)
```

## Threshold-encap public API

```rust
pub struct ThresholdHpkePublicKey { /* opaque X25519 point */ }
pub struct DecapShare { /* opaque per-participant decap share */ }
pub struct ThresholdHpkeCiphertext { /* encapsulated key + AEAD body */ }

impl ThresholdHpkePublicKey {
    /// Derive from a FROST public-key package (no ceremony rerun).
    pub fn from_frost_pkpkg(pkpkg: &PublicKeyPackage) -> CryptoResult<Self>;
}

pub fn encap(
    pk: &ThresholdHpkePublicKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<ThresholdHpkeCiphertext>;

pub fn decap_share(
    participant_signing_share: &SigningShare,
    ct: &ThresholdHpkeCiphertext,
) -> CryptoResult<DecapShare>;

pub fn combine_decap(
    shares: &[DecapShare],
    threshold: usize,
    ct: &ThresholdHpkeCiphertext,
    info: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>>;  // = plaintext
```

`combine_decap` errors with `ThresholdHpkeError::InsufficientShares`
if `shares.len() < threshold`, and with `ThresholdHpkeError::InconsistentShares`
if the shares disagree (a malicious participant submitted a bad
share — the canonical FROST byzantine-tolerance posture).

## Hybrid mode with Phase N PQ

When `angoc.8` (Phase N hybrid post-quantum signing) is fully wired,
the threshold-HPKE module gains a hybrid mode:

```rust
pub fn encap_hybrid(
    classical_pk: &ThresholdHpkePublicKey,         // X25519 derived from FROST
    pq_pk: &ThresholdHpkePqPublicKey,              // ML-KEM-768 from a parallel PQ ceremony
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<HybridThresholdCiphertext>;
```

The hybrid ciphertext concatenates the two encapsulations and
requires BOTH to decap successfully. Defends against future quantum
adversaries breaking X25519 without sacrificing today's deployed
substrate.

The PQ side reuses the ML-DSA-65 substrate already deployed for
Phase N hybrid signing (Kyber/ML-KEM-768 sits in the same crate).
This is the same substrate-reuse argument that motivates this bead
in the first place — one ceremony, two capabilities, doubled in
the PQ axis.

## Cross-mesh sealed-object protocol

Operators seal objects to a quorum-readable shape:

```
Sealer (any peer):
  1. Look up the current threshold-HPKE public key from the most recent
     ceremony epoch (zone-scoped).
  2. encap(pk, info=zone_id||epoch, plaintext=object_bytes, aad=object_id)
  3. Write the ciphertext to fcp-store; the object_id is content-addressed
     over the ciphertext (no plaintext hash visible in the index).

Reader (any peer with a share):
  1. Fetch the ciphertext from fcp-store.
  2. Compute decap_share locally.
  3. Gossip the decap_share to the quorum-formation protocol (a thin
     wrapper over the existing FROST signing-share gossip).
  4. Once t shares are collected, combine_decap to recover the plaintext.
```

Sealed objects appear in `fcp-store` like any other content-addressed
object; the `ObjectHeader.encryption_kind` field distinguishes them:

```toml
[object_header]
encryption_kind = "threshold_hpke_quorum"  # new variant
threshold = 2                               # how many decap shares required
epoch = 42                                  # ceremony epoch
```

## Conformance / e2e tests

`crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs`:

- `test_2_of_3_encap_decap_roundtrip`: 2-of-3 ceremony, encap a
  64-byte plaintext, collect 2 of 3 decap shares, combine, assert
  recovered plaintext bytes-equal.
- `test_decap_with_only_t_minus_1_shares_fails`: collect 1 share for
  a 2-of-3 ceremony, assert `InsufficientShares`.
- `test_decap_with_inconsistent_shares_fails`: 2 shares from
  different decap attempts on different ciphertexts, assert
  `InconsistentShares`.
- `test_decap_share_order_does_not_matter`: combine_decap with
  shares in 2 different orders → same plaintext.

`crates/fcp-e2e/tests/threshold_hpke_sealed_object_e2e.rs`:

- `test_mesh_peer_seals_object_addressable_to_threshold_quorum`:
  3 peers; peer 1 seals; peer 2 + 3 cooperate via gossip to decap;
  assert plaintext recovered AND no single peer's logs contain the
  plaintext bytes.

## Golden vectors

`crates/fcp-conformance/tests/fixtures/threshold_hpke/`:

| File | Content |
|---|---|
| `2of3_roundtrip.json` | Deterministic ceremony seed + plaintext + expected ciphertext shape + expected decap-share signatures |
| `hybrid_classical_plus_pq.json` | (placeholder for when Phase N hybrid mode lands) |

## Latency budget

| Operation | p99 budget |
|---|---|
| `from_frost_pkpkg` | 5 ms (one X25519 derivation from Ed25519 share) |
| `encap` | 10 ms (HPKE encap + AEAD) |
| `decap_share` | 10 ms |
| `combine_decap` (t=2) | 15 ms |

The bench at `crates/fcp-crypto/benches/threshold_hpke.rs`
(deferred to `angoc.11.6.1`) pins these.

## Cross-references

- `crates/fcp-bootstrap/src/ceremony.rs` — the FROST DKG ceremony
  whose shares back this KEM (reuse target)
- `crates/fcp-crypto/src/hpke_seal.rs` — existing direct HPKE
  surface (this module adds threshold mode alongside)
- `lean/Fcp/Crypto/HybridSignature.lean` — Lean proof corpus that
  this implementation should add to once landed
- Bead `angoc.8.1` Phase N hybrid signing — the precedent for
  hybrid (classical + PQ) cryptographic substrates
- Bead `angoc.17.4` Phase A.bis.4 BLS threshold aggregate quorum
  signatures — companion threshold primitive on a different curve

## Deferred Rust implementation

Filed as `angoc.11.6.1`. The runtime work needs:

1. `crates/fcp-crypto/src/threshold_hpke.rs` + `derive.rs`
2. FROST share → X25519 derivation (RFC 7748 + clamping)
3. `crates/fcp-crypto/tests/threshold_hpke_roundtrip.rs` (4 named tests)
4. `crates/fcp-e2e/tests/threshold_hpke_sealed_object_e2e.rs` (1 test)
5. `crates/fcp-store/src/` — `encryption_kind = "threshold_hpke_quorum"`
   variant on `ObjectHeader`
6. Benches for the 4 ops with the latency budgets above

Estimated 10-14h once writer has clean tree. Heavy crypto requires
careful constant-time auditing.
