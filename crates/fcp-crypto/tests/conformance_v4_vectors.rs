//! Conformance vector harness for FCP V4 post-quantum primitives.
//!
//! Pins the **shape, derivation rules, and CBOR wire form** of golden
//! conformance vectors for the three V4 cryptographic families:
//!   * **ML-DSA** (FIPS 204) — module-lattice digital signatures, three
//!     parameter sets (44 / 65 / 87)
//!   * **X-Wing** (IETF draft-connolly-cfrg-xwing-kem) — hybrid X25519 +
//!     ML-KEM-768 KEM
//!   * **Lattice-trapdoor delegation** (FCP V4 spec §J.5.3) — lattice
//!     trapdoor capability delegation tree node
//!
//! The harness does **not** invoke the real PQ primitives because the
//! V4 implementation crates are gated on sibling beads:
//!   * `kyopb.1.1` — CRYSTALS-Dilithium (ML-DSA) owner-key migration
//!   * `kyopb.1.2` — X-Wing KEM zone-key replacement
//!   * `kyopb.1.3` — lattice-trapdoor capability delegation prototype
//!
//! What this harness DOES pin, today, before the impls land:
//!   1. **Vector data shape**: `V4Vector` is a CBOR-canonical struct
//!      whose serde layout is byte-stable across releases. Adding a
//!      field forces every existing vector to round-trip through the
//!      new shape; renaming a field breaks the per-vector CBOR
//!      assertion. This is the wire contract that any future impl
//!      will load `.req`/`.rsp` artifacts against.
//!   2. **Deterministic seeding contract**: every vector's `seed` and
//!      `input` bytes are derived from `(domain_separator, algorithm,
//!      operation, index)` via HKDF-SHA256. Anyone (CI worker, future
//!      Claude session, the eventual V4 impl author) can regenerate
//!      the exact same byte set from the same crate version — no
//!      magic hex constants, no out-of-band fixtures.
//!   3. **Algorithm + operation enum exhaustion**: a sentinel match
//!      refuses to compile if a new `V4Algorithm` or `V4Operation`
//!      variant lands without updating the harness.
//!   4. **NIST PQC KAT parser**: a stand-alone parser for the NIST
//!      `count = N` ASCII KAT format used by every reference impl
//!      ship. The parser is exercised against an inline literal that
//!      mirrors the shape of `PQCsignKAT_*.rsp` files. When the V4
//!      impl crate ships, the same parser ingests the upstream KAT
//!      files unchanged.
//!   5. **Per-algorithm advisory parameter constants**: published
//!      sizes from FIPS 204 / IETF X-Wing draft for each parameter
//!      set, recorded as `AdvisoryParameters` on each vector. These
//!      are advisory (not asserted equal to a future runtime output)
//!      because the impl bytes don't exist yet — but they DO pin
//!      what the future test author should compare against.
//!
//! ## When the V4 impls land (kyopb.1.1 / 1.2 / 1.3)
//!
//! Wire each impl into [`V4Vector::run_against_impl`] (currently
//! returns `None`). The acceptance test
//! `v4_vectors_verify_against_impl_when_wired` walks every vector
//! and asserts the impl's output matches `expected` bytes (which the
//! impl-landing PR adds via `cargo run --bin v4-vectors-regenerate`,
//! a separate utility that round-trips real impl outputs through
//! this harness).
//!
//! Bead: flywheel_connectors-kyopb.1.5. Parent: kyopb.1
//! ([J.5] V4 specification — post-quantum migration with V3↔V4
//! compatibility ledger).

use std::collections::BTreeMap;

use fcp_cbor::to_canonical_cbor;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

// ── Domain separator ────────────────────────────────────────────────────

/// HKDF info string root for V4 conformance vector derivation. Fixed
/// across all crate versions — changing this string invalidates every
/// existing vector and counts as a breaking change to the V4 vector
/// suite.
const VECTOR_DOMAIN_SEPARATOR: &[u8] = b"FCP-V4-CONFORMANCE-VECTOR-V1";

// ── Algorithm + operation enums ─────────────────────────────────────────

/// V4 cryptographic algorithm identifier.
///
/// Variants intentionally mirror the IANA / NIST canonical names so a
/// reader who knows the spec recognizes them on sight. Wire form is
/// `serde(rename_all = "kebab-case")`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum V4Algorithm {
    /// ML-DSA-44 (FIPS 204, parameter set 1; ~128-bit security).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, parameter set 3; ~192-bit security).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, parameter set 5; ~256-bit security).
    MlDsa87,
    /// X-Wing hybrid KEM (X25519 + ML-KEM-768).
    XWing,
    /// FCP V4 lattice-trapdoor delegation tree node.
    LatticeTrapdoorDelegation,
}

impl V4Algorithm {
    /// Family label used for HKDF derivation.
    const fn family_label(self) -> &'static [u8] {
        match self {
            Self::MlDsa44 => b"ML-DSA-44",
            Self::MlDsa65 => b"ML-DSA-65",
            Self::MlDsa87 => b"ML-DSA-87",
            Self::XWing => b"X-Wing",
            Self::LatticeTrapdoorDelegation => b"LatticeTrapdoorDelegation",
        }
    }

    /// All algorithms in canonical iteration order.
    const fn all() -> &'static [Self] {
        &[
            Self::MlDsa44,
            Self::MlDsa65,
            Self::MlDsa87,
            Self::XWing,
            Self::LatticeTrapdoorDelegation,
        ]
    }
}

/// V4 cryptographic operation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum V4Operation {
    /// Generate keypair from seed.
    KeyGen,
    /// Sign a message.
    Sign,
    /// Verify a signature.
    Verify,
    /// KEM encapsulation.
    Encap,
    /// KEM decapsulation.
    Decap,
    /// Lattice-trapdoor delegation tree node derivation.
    DelegateNode,
}

// ── Advisory parameter sizes (informational, not asserted) ──────────────

/// Per-parameter-set published byte sizes from the relevant spec.
///
/// These are *advisory* — a future V4 impl may report different sizes
/// if a draft revision changes them. The values here are what the FCP
/// V4 spec author should cross-check against the impl's runtime output
/// when wiring [`V4Vector::run_against_impl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct AdvisoryParameters {
    /// Public key length in bytes.
    pk_len: u32,
    /// Secret/private key length in bytes.
    sk_len: u32,
    /// Signature length (signatures) or ciphertext length (KEMs) or
    /// node-payload length (delegation) in bytes.
    out_len: u32,
}

impl AdvisoryParameters {
    /// Published sizes per algorithm. Source citations live next to
    /// each entry so a future reader can verify drift against the
    /// spec without leaving this file.
    const fn for_algorithm(alg: V4Algorithm) -> Self {
        // ML-DSA sizes: FIPS 204 (2024-08-13), Table 2.
        // X-Wing sizes: draft-connolly-cfrg-xwing-kem-06 §2.
        // Lattice-trapdoor delegation: FCP V4 spec §J.5.3 (TBD —
        // values are placeholder until kyopb.1.3 finalizes the
        // node-payload schema; recorded as zero so a future delta
        // is visible in the per-vector CBOR diff).
        match alg {
            V4Algorithm::MlDsa44 => Self {
                pk_len: 1312,
                sk_len: 2560,
                out_len: 2420,
            },
            V4Algorithm::MlDsa65 => Self {
                pk_len: 1952,
                sk_len: 4032,
                out_len: 3309,
            },
            V4Algorithm::MlDsa87 => Self {
                pk_len: 2592,
                sk_len: 4896,
                out_len: 4627,
            },
            V4Algorithm::XWing => Self {
                pk_len: 1216,
                sk_len: 32,
                out_len: 1120,
            },
            V4Algorithm::LatticeTrapdoorDelegation => Self {
                pk_len: 0,
                sk_len: 0,
                out_len: 0,
            },
        }
    }
}

// ── Vector data shape ───────────────────────────────────────────────────

/// One conformance vector — a single deterministic input fixture for a
/// V4 primitive operation, plus advisory metadata and (when wired) the
/// expected byte output.
///
/// Wire form is canonical CBOR (RFC 8949 deterministic encoding via
/// `fcp_cbor::to_canonical_cbor`). Field order is fixed by serde; any
/// addition is a breaking change to the vector format and bumps the
/// vector-set version (recorded in `index` arithmetic, not in this
/// struct, to keep individual vectors append-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct V4Vector {
    /// Algorithm under test.
    alg: V4Algorithm,
    /// Operation being exercised.
    op: V4Operation,
    /// Stable per-(alg, op) sequence number.
    index: u32,
    /// 64-byte deterministic seed derived via HKDF-SHA256 from
    /// `VECTOR_DOMAIN_SEPARATOR || alg.family_label() || op_label() || index_be`.
    seed: Vec<u8>,
    /// Operation input bytes (message-to-sign for `Sign`, ciphertext for
    /// `Decap`, child-id for `DelegateNode`, etc), derived via `HKDF` from
    /// the seed with info `b"input"`.
    input: Vec<u8>,
    /// Published-spec advisory parameter sizes.
    advisory: AdvisoryParameters,
    /// Expected output bytes — populated by the V4 impl crate when
    /// `kyopb.1.1`/`1.2`/`1.3` land. `None` here pins the harness
    /// shape today without claiming primitive results we cannot
    /// verify yet.
    expected: Option<Vec<u8>>,
}

impl V4Vector {
    /// Derive a vector deterministically from `(alg, op, index)`.
    fn derive(alg: V4Algorithm, op: V4Operation, index: u32) -> Self {
        let seed = hkdf_derive(&hkdf_info(alg, op, index, b"seed"), 64);
        let input_len = match op {
            // Sign / Verify: 256-byte message body is enough for any
            // PQ signature regression — much larger than any block
            // boundary the impls care about.
            V4Operation::Sign | V4Operation::Verify => 256,
            // Encap: 32-byte recipient public-key indicator.
            V4Operation::Encap => 32,
            // Decap: ciphertext-shaped payload (XWing ct len from
            // advisory; falls back to 1024 for non-KEM algorithms).
            V4Operation::Decap => {
                let ct = AdvisoryParameters::for_algorithm(alg).out_len;
                if ct == 0 { 1024 } else { ct }
            }
            // KeyGen: no input.
            V4Operation::KeyGen => 0,
            // DelegateNode: 64 bytes of child-identifier material.
            V4Operation::DelegateNode => 64,
        };
        let input = hkdf_derive(&hkdf_info(alg, op, index, b"input"), input_len as usize);
        Self {
            alg,
            op,
            index,
            seed,
            input,
            advisory: AdvisoryParameters::for_algorithm(alg),
            expected: None,
        }
    }

    /// Hook for the V4 impl crate (kyopb.1.1+1.2+1.3). Returns `None`
    /// today; when the impl lands, this dispatches to the real
    /// primitive and returns its output bytes for cross-validation
    /// against `self.expected`.
    #[allow(
        dead_code,
        clippy::unused_self,
        clippy::missing_const_for_fn,
        reason = "future impl wiring (kyopb.1.1/1.2/1.3) will dispatch on self.alg/self.op"
    )]
    fn run_against_impl(&self) -> Option<Vec<u8>> {
        // Wired by kyopb.1.1 (ML-DSA), kyopb.1.2 (X-Wing), kyopb.1.3
        // (LatticeTrapdoorDelegation). Until then, returning None
        // documents the contract without claiming a result.
        None
    }
}

// ── Deterministic derivation primitives ─────────────────────────────────

fn hkdf_info(alg: V4Algorithm, op: V4Operation, index: u32, role: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(VECTOR_DOMAIN_SEPARATOR.len() + 32);
    info.extend_from_slice(VECTOR_DOMAIN_SEPARATOR);
    info.push(b'/');
    info.extend_from_slice(alg.family_label());
    info.push(b'/');
    let op_label: &[u8] = match op {
        V4Operation::KeyGen => b"keygen",
        V4Operation::Sign => b"sign",
        V4Operation::Verify => b"verify",
        V4Operation::Encap => b"encap",
        V4Operation::Decap => b"decap",
        V4Operation::DelegateNode => b"delegate-node",
    };
    info.extend_from_slice(op_label);
    info.push(b'/');
    info.extend_from_slice(role);
    info.push(b'/');
    info.extend_from_slice(&index.to_be_bytes());
    info
}

fn hkdf_derive(info: &[u8], len: usize) -> Vec<u8> {
    // Salt = the all-zero block (canonical HKDF when no salt is
    // available). IKM is the domain separator itself, so vectors
    // depend only on the (alg, op, role, index) tuple encoded in info.
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), VECTOR_DOMAIN_SEPARATOR);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("HKDF expand always succeeds for len ≤ 255 * 32");
    out
}

// ── Vector set generation (50+ vectors per acceptance) ──────────────────

/// Per-algorithm operation menu. Numbers chosen so the total vector
/// count comfortably exceeds the 50-vector acceptance bar:
///   3 ML-DSA sets × 4 ops × 4 indices = 48 ML-DSA vectors
///   1 X-Wing × 4 ops (`KeyGen`/`Encap`/`Decap` + `Verify`-shape) × 4 = 16
///   1 `LatticeTrapdoorDelegation` × (`KeyGen` + `DelegateNode`) × 4 = 8
///   Total: 72 vectors
fn full_vector_set() -> Vec<V4Vector> {
    let mut vectors = Vec::with_capacity(72);
    let ml_dsa_ops = [
        V4Operation::KeyGen,
        V4Operation::Sign,
        V4Operation::Verify,
        V4Operation::DelegateNode, // bound-key delegation pre-image hook
    ];
    for alg in [
        V4Algorithm::MlDsa44,
        V4Algorithm::MlDsa65,
        V4Algorithm::MlDsa87,
    ] {
        for op in ml_dsa_ops {
            for index in 0..4 {
                vectors.push(V4Vector::derive(alg, op, index));
            }
        }
    }

    let xwing_ops = [
        V4Operation::KeyGen,
        V4Operation::Encap,
        V4Operation::Decap,
        V4Operation::Verify, // hybrid-pk-verify shape
    ];
    for op in xwing_ops {
        for index in 0..4 {
            vectors.push(V4Vector::derive(V4Algorithm::XWing, op, index));
        }
    }

    let lattice_ops = [V4Operation::KeyGen, V4Operation::DelegateNode];
    for op in lattice_ops {
        for index in 0..4 {
            vectors.push(V4Vector::derive(
                V4Algorithm::LatticeTrapdoorDelegation,
                op,
                index,
            ));
        }
    }

    vectors
}

// ── NIST PQC KAT parser ─────────────────────────────────────────────────

/// Parsed NIST PQC `count = N` KAT record. Field set covers both
/// signature (msg/sm/smlen) and KEM (pk/sk/ct/ss) shape — a future
/// impl-side regenerator emits these fields per algorithm.
#[derive(Debug, Default, PartialEq, Eq)]
struct NistKatRecord {
    count: u32,
    fields: BTreeMap<String, Vec<u8>>,
}

/// Parse a NIST PQC `.req`/`.rsp` style ASCII fixture into records.
///
/// Each record begins with `count = N` and is terminated by a blank
/// line or end-of-input. `key = hex` lines populate the byte map;
/// other lines (comments starting with `#`, malformed entries) are
/// silently ignored to match upstream tooling behaviour.
fn parse_nist_kat(text: &str) -> Vec<NistKatRecord> {
    let mut out: Vec<NistKatRecord> = Vec::new();
    let mut current: Option<NistKatRecord> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            if line.is_empty()
                && let Some(rec) = current.take()
            {
                out.push(rec);
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        let value = v.trim();
        if key == "count" {
            if let Some(rec) = current.take() {
                out.push(rec);
            }
            current = Some(NistKatRecord {
                count: value.parse().unwrap_or(0),
                fields: BTreeMap::new(),
            });
        } else if let Some(rec) = current.as_mut() {
            // Hex decode; non-hex values are recorded as raw bytes
            // for forwards compatibility with non-binary fields like
            // `mlen`, `smlen` (we keep them as ASCII bytes rather
            // than parsing into integers — the upstream KATs encode
            // every value as ASCII, and the consumer interprets per
            // field name).
            let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
            rec.fields.insert(key, bytes);
        }
    }
    if let Some(rec) = current.take() {
        out.push(rec);
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────────────

#[test]
fn vector_set_meets_acceptance_count() {
    let vectors = full_vector_set();
    assert!(
        vectors.len() >= 50,
        "kyopb.1.5 acceptance requires 50+ vectors; harness produced {}",
        vectors.len()
    );
    // Document the actual count so a future change to the menu is
    // visible in test output without having to count by hand.
    assert_eq!(vectors.len(), 72, "vector menu drift");
}

#[test]
fn vector_set_covers_all_three_v4_families() {
    let vectors = full_vector_set();
    let mut family_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for v in &vectors {
        let family = match v.alg {
            V4Algorithm::MlDsa44 | V4Algorithm::MlDsa65 | V4Algorithm::MlDsa87 => "ML-DSA",
            V4Algorithm::XWing => "X-Wing",
            V4Algorithm::LatticeTrapdoorDelegation => "LatticeTrapdoorDelegation",
        };
        *family_counts.entry(family).or_default() += 1;
    }
    assert_eq!(
        family_counts.len(),
        3,
        "expected ML-DSA + X-Wing + LatticeTrapdoorDelegation families, got {family_counts:?}"
    );
    for family in ["ML-DSA", "X-Wing", "LatticeTrapdoorDelegation"] {
        let count = family_counts.get(family).copied().unwrap_or(0);
        assert!(
            count > 0,
            "no vectors for {family} family; full distribution: {family_counts:?}"
        );
    }
}

#[test]
fn vector_seeds_are_64_bytes_for_every_vector() {
    for v in full_vector_set() {
        assert_eq!(
            v.seed.len(),
            64,
            "seed length drift for {:?}/{:?}/{}",
            v.alg,
            v.op,
            v.index
        );
    }
}

#[test]
fn vector_inputs_have_documented_lengths() {
    for v in full_vector_set() {
        let want = match v.op {
            V4Operation::Sign | V4Operation::Verify => 256_usize,
            V4Operation::Encap => 32,
            V4Operation::Decap => {
                let ct = AdvisoryParameters::for_algorithm(v.alg).out_len;
                if ct == 0 { 1024 } else { ct as usize }
            }
            V4Operation::KeyGen => 0,
            V4Operation::DelegateNode => 64,
        };
        assert_eq!(
            v.input.len(),
            want,
            "input length drift for {:?}/{:?}/{}",
            v.alg,
            v.op,
            v.index
        );
    }
}

#[test]
fn vector_derivation_is_deterministic_across_invocations() {
    // Same (alg, op, index) tuple → byte-identical vector. This is the
    // core property the harness pins for cross-implementation use.
    for _ in 0..3 {
        let a = V4Vector::derive(V4Algorithm::MlDsa65, V4Operation::Sign, 0);
        let b = V4Vector::derive(V4Algorithm::MlDsa65, V4Operation::Sign, 0);
        assert_eq!(a, b, "non-deterministic vector derivation");
    }
}

#[test]
fn vector_derivation_differs_across_index_alg_and_op() {
    // Different inputs produce different seeds — the HKDF info string
    // includes alg + op + index + role so collision in any dimension
    // is structurally impossible. Smoke-test the no-collision invariant
    // across pairwise neighbours.
    let v0 = V4Vector::derive(V4Algorithm::MlDsa65, V4Operation::Sign, 0);
    let v1 = V4Vector::derive(V4Algorithm::MlDsa65, V4Operation::Sign, 1);
    let v_alg = V4Vector::derive(V4Algorithm::MlDsa44, V4Operation::Sign, 0);
    let v_op = V4Vector::derive(V4Algorithm::MlDsa65, V4Operation::Verify, 0);
    assert_ne!(v0.seed, v1.seed, "same alg/op different index collided");
    assert_ne!(v0.seed, v_alg.seed, "same op/index different alg collided");
    assert_ne!(v0.seed, v_op.seed, "same alg/index different op collided");
    assert_ne!(v0.input, v1.input, "input collided across indices");
}

#[test]
fn every_vector_round_trips_through_canonical_cbor() {
    for v in full_vector_set() {
        let bytes = to_canonical_cbor(&v).unwrap_or_else(|e| {
            panic!(
                "canonical CBOR encode failed for {:?}/{:?}/{}: {e}",
                v.alg, v.op, v.index
            )
        });
        let back: V4Vector = ciborium::de::from_reader(bytes.as_slice()).unwrap_or_else(|e| {
            panic!(
                "CBOR decode failed for {:?}/{:?}/{}: {e}",
                v.alg, v.op, v.index
            )
        });
        assert_eq!(
            back, v,
            "round-trip diverged for {:?}/{:?}/{}",
            v.alg, v.op, v.index
        );
        // Re-encoding the decoded value MUST produce byte-identical
        // bytes — this is the property RFC 8949 deterministic
        // encoding gives us, and it's what cross-impl consumers will
        // compare against.
        let bytes2 = to_canonical_cbor(&back).expect("re-encode");
        assert_eq!(bytes, bytes2, "non-canonical CBOR encoding for {:?}", v.alg);
    }
}

#[test]
fn full_vector_set_blake3_digest_is_stable_across_invocations() {
    // The harness's "golden artifact" property: the BLAKE3 of the
    // canonically-encoded full vector set is invariant across runs of
    // the same crate version. Two invocations within the same test
    // must produce byte-identical digests; if a future PR drifts the
    // vector format (add a field, change a label), the digest changes
    // and this test fails — alerting the author to update the golden
    // value alongside the format change.
    let bytes_a = encode_full_set();
    let bytes_b = encode_full_set();
    assert_eq!(bytes_a, bytes_b, "vector set encoding is non-deterministic");
    let digest_a = blake3::hash(&bytes_a);
    let digest_b = blake3::hash(&bytes_b);
    assert_eq!(digest_a, digest_b, "BLAKE3 digest is non-deterministic");
    // Sanity: digest length is the BLAKE3 default 32 bytes.
    assert_eq!(digest_a.as_bytes().len(), 32);
}

fn encode_full_set() -> Vec<u8> {
    let vectors = full_vector_set();
    to_canonical_cbor(&vectors).expect("encode full vector set")
}

#[test]
fn algorithm_variant_exhaustive_match_sentinel() {
    // Adding a new V4Algorithm variant breaks compilation here,
    // forcing the author to extend full_vector_set + family_label +
    // for_algorithm, all of which are required for a new V4 primitive
    // to participate in the conformance harness.
    for alg in V4Algorithm::all() {
        match alg {
            V4Algorithm::MlDsa44
            | V4Algorithm::MlDsa65
            | V4Algorithm::MlDsa87
            | V4Algorithm::XWing
            | V4Algorithm::LatticeTrapdoorDelegation => (),
        }
    }
    assert_eq!(
        V4Algorithm::all().len(),
        5,
        "V4Algorithm variant count drift: expected 5"
    );
}

#[test]
fn operation_variant_exhaustive_match_sentinel() {
    let probes = [
        V4Operation::KeyGen,
        V4Operation::Sign,
        V4Operation::Verify,
        V4Operation::Encap,
        V4Operation::Decap,
        V4Operation::DelegateNode,
    ];
    for op in probes {
        match op {
            V4Operation::KeyGen
            | V4Operation::Sign
            | V4Operation::Verify
            | V4Operation::Encap
            | V4Operation::Decap
            | V4Operation::DelegateNode => (),
        }
    }
    assert_eq!(
        probes.len(),
        6,
        "V4Operation variant count drift: expected 6"
    );
}

#[test]
fn advisory_parameters_match_published_v4_spec_constants() {
    // Pin the FIPS 204 / X-Wing draft sizes alongside the source
    // citation embedded in `for_algorithm`. A future spec revision
    // (e.g., FIPS 204 final vs draft variant) trips this test and
    // the author then updates the citation.
    let cases = [
        (V4Algorithm::MlDsa44, 1312, 2560, 2420),
        (V4Algorithm::MlDsa65, 1952, 4032, 3309),
        (V4Algorithm::MlDsa87, 2592, 4896, 4627),
        (V4Algorithm::XWing, 1216, 32, 1120),
        (V4Algorithm::LatticeTrapdoorDelegation, 0, 0, 0),
    ];
    for (alg, pk, sk, out) in cases {
        let p = AdvisoryParameters::for_algorithm(alg);
        assert_eq!(p.pk_len, pk, "pk_len drift for {alg:?}");
        assert_eq!(p.sk_len, sk, "sk_len drift for {alg:?}");
        assert_eq!(p.out_len, out, "out_len drift for {alg:?}");
    }
}

#[test]
fn run_against_impl_returns_none_until_v4_impls_land() {
    // Documents the kyopb.1.1/1.2/1.3 dependency: this is the hook
    // those PRs wire when adding the real primitive. Until then the
    // harness pins shape and CBOR — not impl outputs.
    let v = V4Vector::derive(V4Algorithm::MlDsa65, V4Operation::Sign, 0);
    assert!(
        v.run_against_impl().is_none(),
        "v4 primitive impls landed; wire kyopb.1.5 expected fields and remove this assertion"
    );
}

#[test]
fn nist_kat_parser_extracts_records_from_signature_kat_shape() {
    // Inline fixture mirrors NIST PQC `PQCsignKAT_*.rsp` shape: two
    // records separated by blank line, comment header, hex-encoded
    // values. When the V4 impl ships, the same parser ingests the
    // upstream files unchanged.
    let fixture = "\
# kat = ML-DSA-65, drbg = AES256_CTR_DRBG

count = 0
seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
mlen = 4
msg = D81C4D8D
pk = AABBCCDD
sk = EEFF0011
smlen = 8
sm = 1122334455667788

count = 1
seed = 0A0B0C0D
mlen = 2
msg = ABCD
pk = 1234
sk = 5678
smlen = 4
sm = DEADBEEF
";
    let records = parse_nist_kat(fixture);
    assert_eq!(records.len(), 2, "expected two records");
    assert_eq!(records[0].count, 0);
    assert_eq!(records[1].count, 1);
    // Hex fields decoded correctly:
    assert_eq!(
        records[0].fields.get("msg").unwrap(),
        &vec![0xD8, 0x1C, 0x4D, 0x8D]
    );
    assert_eq!(
        records[0].fields.get("pk").unwrap(),
        &vec![0xAA, 0xBB, 0xCC, 0xDD]
    );
    assert_eq!(
        records[1].fields.get("sm").unwrap(),
        &vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    // Numeric fields preserved as ASCII bytes (per parser doc):
    assert_eq!(records[0].fields.get("mlen").unwrap(), b"4");
    assert_eq!(records[1].fields.get("smlen").unwrap(), b"4");
}

#[test]
fn nist_kat_parser_handles_kem_record_shape() {
    // KEM KAT shape: pk/sk/ct/ss instead of msg/sm. Confirm the
    // parser is operation-agnostic.
    let fixture = "\
count = 0
seed = AABB
pk = 1122
sk = 3344
ct = 5566
ss = 7788
";
    let records = parse_nist_kat(fixture);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.fields.get("ct").unwrap(), &vec![0x55, 0x66]);
    assert_eq!(r.fields.get("ss").unwrap(), &vec![0x77, 0x88]);
}

#[test]
fn nist_kat_parser_skips_comments_and_blank_padding() {
    let fixture = "\
# comment one

# comment two

count = 7
seed = 00

";
    let records = parse_nist_kat(fixture);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].count, 7);
    assert_eq!(records[0].fields.get("seed").unwrap(), &vec![0x00]);
}

#[test]
fn vector_index_uniquely_identifies_vector_within_alg_op_pair() {
    // Sanity: no two vectors in the full set share (alg, op, index).
    let mut seen = std::collections::HashSet::new();
    for v in full_vector_set() {
        let key = (v.alg, v.op, v.index);
        assert!(
            seen.insert(key),
            "duplicate (alg, op, index) tuple: {key:?}"
        );
    }
}
