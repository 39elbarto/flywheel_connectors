//! # FCP post-quantum cryptographic primitives — lattice-trapdoor delegation
//!
//! API scaffolding (br-kyopb.1.3.1) for the four lattice-trapdoor primitives
//! that back V4 capability delegation. The full design is documented in
//! `docs/post-quantum/lattice_trapdoor_delegation.md`.
//!
//! ## Status
//!
//! **The MP12 / CHKP / GPV cryptographic operations are not implemented.**
//! `trap_gen` and `delegate` return deterministic SHAKE256-derived seeded
//! representations so downstream wiring can pin fixtures. `sample_pre` and
//! `verify` still return `Err(LatticePqError::NotImplemented { ... })` after
//! their cheap structural checks. This crate exists to pin the API contract
//! that:
//!
//! - `fcp_policy::lattice_delegation::LatticeDelegationVerifier` (br-kyopb.1.3.2)
//!   will implement against,
//! - the Lean 4 formal proof (br-kyopb.1.3.3) will model, and
//! - the throughput benchmark (br-kyopb.1.3.4) will measure.
//!
//! The `NotImplemented` discriminant names the responsible follow-up bead.
//! **Production code MUST treat `NotImplemented` as "fall back to V3
//! (Ed25519) capability verification" rather than as a hard failure.** See
//! `docs/post-quantum/v3_v4_compatibility_ledger.md` for the cross-version
//! dispatch rules.
//!
//! ## API surface
//!
//! Four primitives, exactly mirroring §3 of the design doc:
//!
//! | Primitive    | Purpose                                                    |
//! | ------------ | ---------------------------------------------------------- |
//! | [`trap_gen`] | Setup-time: sample the master matrix `A_root` + trapdoor   |
//! | [`delegate`] | Issuance-time: derive `(A_zp, T_zp)` for `(zone, period)`  |
//! | [`sample_pre`]| Mint-time: produce a short preimage `e` such that `A·e≡h`  |
//! | [`verify`]   | Verify-time: check `A·e ≡ h (mod q)` and `‖e‖₂ ≤ B`        |
//!
//! The public-matrix fixture profile remains seed-backed: public matrices are
//! transmitted as 32-byte seeds and expanded under explicit memory bounds.
//! Secret trapdoors now sit behind a versioned representation envelope so the
//! current fixture seed bundles cannot be mistaken for production bases.
//! Sub-token preimages use profile-derived packed coefficient lengths rather
//! than the old fixed 64-byte scaffold.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use thiserror::Error;

// ── Parameters and representation profile ─────────────────────────────────

/// Current lattice representation profile version.
///
/// Version 2 keeps the version-1 public SHAKE seed fixtures stable, but wraps
/// secret trapdoor material in a basis-capable metadata envelope. The envelope
/// can carry fixture seed bundles today and a future reviewed basis envelope
/// without changing public matrix or token wire formats.
pub const LATTICE_REPRESENTATION_VERSION: u16 = 2;

/// Public SHAKE fixture compatibility generation.
///
/// This stays at version 1 so previously pinned public matrix fixtures keep
/// their deterministic hashes while the secret representation evolves.
pub const FIXTURE_SHAKE_COMPATIBILITY_VERSION: u16 = 1;

const MATRIX_SEED_BYTES: usize = 32;
const SECRET_SEED_BUNDLE_BYTES: usize = 96;
const MAX_PUBLIC_MATRIX_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
const MAX_PREIMAGE_ENCODED_BYTES: usize = 1024 * 1024;
const MAX_TRAPDOOR_SECRET_BYTES: usize = 1024 * 1024;

/// Lattice security parameters (§3.2 of the design doc).
///
/// The stub carries these as opaque values so call-sites can already
/// thread them through dispatch code; the real cryptographic crate
/// (br-kyopb.1.3.1 implementation) will use them to drive matrix
/// dimensions and Gaussian widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeParams {
    /// Module rank `n`.
    pub n: u32,
    /// Modulus `q`. Stored as `u64` to leave headroom for future profiles.
    pub q: u64,
    /// Number of lattice columns `m`.
    pub m: u32,
    /// Discrete-Gaussian width parameter `σ` (×100, fixed-point — avoids
    /// `f64` in the public API).
    pub sigma_x100: u32,
    /// Maximum delegation depth `L`.
    pub depth: u8,
}

impl LatticeParams {
    /// Small deterministic test profile. This is not a security profile; it is
    /// intentionally tiny so representation and arithmetic tests can exercise
    /// dimension logic without allocating the V4 reference matrix.
    pub const SMALL_TEST: Self = Self {
        n: 8,
        q: 257,
        m: 16,
        sigma_x100: 320,
        depth: 2,
    };

    /// Reference V4 profile: `n=512`, `q=2^32-5`, `m=16384`, `σ≈113`,
    /// `L=4` (~128-bit classical / Cat. 3 PQ security per the design
    /// doc §3.2).
    pub const V4_REFERENCE: Self = Self {
        n: 512,
        q: 4_294_967_291, // 2^32 - 5
        m: 16_384,
        sigma_x100: 11_300, // σ ≈ 113.0
        depth: 4,
    };

    /// Validate basic arithmetic and allocation invariants for this profile.
    ///
    /// This intentionally does not prove cryptographic strength; it enforces
    /// the representation boundary so malformed external profiles cannot drive
    /// divide-by-zero, overflow, or unbounded allocation paths.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] for zero or otherwise
    /// malformed scalar parameters, or [`LatticePqError::RepresentationTooLarge`]
    /// when the profile would exceed the explicit allocation ceilings.
    pub fn validate(self) -> LatticePqResult<()> {
        if self.n == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "n",
                value: 0,
                reason: "lattice dimension must be non-zero",
            });
        }
        if self.m == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "m",
                value: 0,
                reason: "lattice width must be non-zero",
            });
        }
        if self.q < 2 {
            return Err(LatticePqError::InvalidParameter {
                field: "q",
                value: self.q,
                reason: "modulus must be at least 2",
            });
        }
        if self.sigma_x100 == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "sigma_x100",
                value: 0,
                reason: "Gaussian width must be non-zero",
            });
        }
        if self.depth == 0 {
            return Err(LatticePqError::InvalidParameter {
                field: "depth",
                value: 0,
                reason: "delegation depth must be non-zero",
            });
        }
        let _profile = self.representation_profile()?;
        Ok(())
    }

    /// Bytes required to store one coefficient modulo `q`.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] when `q < 2`.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` bit count.
    pub fn coefficient_bytes(self) -> LatticePqResult<usize> {
        if self.q < 2 {
            return Err(LatticePqError::InvalidParameter {
                field: "q",
                value: self.q,
                reason: "modulus must be at least 2",
            });
        }
        let bits = u64::BITS - (self.q - 1).leading_zeros();
        Ok(usize::try_from(bits.div_ceil(8)).expect("u32 bit count fits in usize"))
    }

    /// Expanded public matrix byte count for `n × m` coefficients.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] when `q < 2`, or
    /// [`LatticePqError::RepresentationTooLarge`] when the expanded matrix would
    /// exceed this crate's allocation ceiling.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` dimension.
    pub fn public_matrix_expanded_bytes(self) -> LatticePqResult<usize> {
        let coefficient_bytes = self.coefficient_bytes()?;
        checked_profile_product(
            "public_matrix",
            &[
                usize::try_from(self.n).expect("u32 n fits in usize"),
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        )
    }

    /// Packed byte count for a short-vector preimage in `Z_q^m`.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] when `q < 2`, or
    /// [`LatticePqError::RepresentationTooLarge`] when the packed preimage would
    /// exceed this crate's allocation ceiling.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` dimension.
    pub fn preimage_encoded_bytes(self) -> LatticePqResult<usize> {
        let coefficient_bytes = self.coefficient_bytes()?;
        checked_profile_product(
            "preimage",
            &[
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PREIMAGE_ENCODED_BYTES,
        )
    }

    /// Fixture seed-bundle bytes for the SHAKE compatibility trapdoor route.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::public_matrix_expanded_bytes`] because
    /// trapdoor storage is valid only for a bounded public-matrix profile.
    pub fn trapdoor_storage_bytes(self) -> LatticePqResult<usize> {
        self.public_matrix_expanded_bytes()?;
        Ok(SECRET_SEED_BUNDLE_BYTES)
    }

    /// Full representation profile implied by these parameters.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] for malformed parameters, or
    /// [`LatticePqError::RepresentationTooLarge`] for profiles that exceed the
    /// explicit matrix/preimage allocation ceilings.
    ///
    /// # Panics
    ///
    /// Panics only on targets where `usize` cannot represent a `u32` dimension.
    pub fn representation_profile(self) -> LatticePqResult<LatticeRepresentationProfile> {
        let coefficient_bytes = self.coefficient_bytes()?;
        let public_matrix_expanded_bytes = checked_profile_product(
            "public_matrix",
            &[
                usize::try_from(self.n).expect("u32 n fits in usize"),
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PUBLIC_MATRIX_EXPANDED_BYTES,
        )?;
        let preimage_encoded_bytes = checked_profile_product(
            "preimage",
            &[
                usize::try_from(self.m).expect("u32 m fits in usize"),
                coefficient_bytes,
            ],
            MAX_PREIMAGE_ENCODED_BYTES,
        )?;
        Ok(LatticeRepresentationProfile {
            version: LATTICE_REPRESENTATION_VERSION,
            params: self,
            coefficient_bytes,
            public_matrix_seed_bytes: MATRIX_SEED_BYTES,
            public_matrix_expanded_bytes,
            trapdoor_storage_bytes: SECRET_SEED_BUNDLE_BYTES,
            preimage_encoded_bytes,
        })
    }
}

/// Concrete encoding plan for a lattice parameter profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeRepresentationProfile {
    /// Representation version.
    pub version: u16,
    /// Parameter profile the representation is bound to.
    pub params: LatticeParams,
    /// Bytes per packed coefficient modulo `q`.
    pub coefficient_bytes: usize,
    /// Serialized public-matrix seed length.
    pub public_matrix_seed_bytes: usize,
    /// Upper-bound checked size for the expanded public matrix.
    pub public_matrix_expanded_bytes: usize,
    /// Fixture seed-bundle bytes for the SHAKE compatibility trapdoor route.
    pub trapdoor_storage_bytes: usize,
    /// Packed preimage byte length.
    pub preimage_encoded_bytes: usize,
}

/// Which trapdoor layer a secret representation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorScope {
    /// Root setup-time trapdoor.
    Root,
    /// Child trapdoor derived for a narrower delegation node.
    Child,
}

/// Secret material storage strategy for a trapdoor representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorMaterialKind {
    /// Deterministic SHAKE seed bundle used only by fixture scaffolding.
    FixtureShakeSeedBundle,
    /// Opaque envelope for a future reviewed MP12/CHKP/GPV basis route.
    BasisEnvelope,
}

/// Redaction-safe bucket for the stored secret size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretStorageLengthBucket {
    /// No secret bytes were present.
    Empty,
    /// Secret storage is at most 128 bytes.
    UpTo128,
    /// Secret storage is at most 4 KiB.
    UpTo4KiB,
    /// Secret storage is at most 64 KiB.
    UpTo64KiB,
    /// Secret storage is at most 1 MiB.
    UpTo1MiB,
    /// Secret storage exceeds the representation ceiling.
    TooLarge,
}

impl SecretStorageLengthBucket {
    #[must_use]
    const fn from_len(len: usize) -> Self {
        match len {
            0 => Self::Empty,
            1..=128 => Self::UpTo128,
            129..=4096 => Self::UpTo4KiB,
            4097..=65_536 => Self::UpTo64KiB,
            65_537..=MAX_TRAPDOOR_SECRET_BYTES => Self::UpTo1MiB,
            _ => Self::TooLarge,
        }
    }
}

/// Redaction-safe relation state for trapdoor/public-key metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorRelationResult {
    /// Metadata matches the deterministic fixture contract only.
    FixtureOnly,
    /// Metadata is structurally compatible with a future reviewed primitive.
    MetadataConsistent,
    /// Metadata does not match the public key, parent key, or parameter profile.
    MetadataMismatch,
    /// A cryptographic relation check needs arithmetic that is not implemented.
    UnsupportedPrimitive,
}

/// Redaction-safe quality bucket for the represented trapdoor basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrapdoorNormQualityBucket {
    /// Fixture seed bundle; no basis norm exists.
    FixtureSeed,
    /// Future basis route reports a small reviewed basis.
    Small,
    /// Future basis route is bounded for the configured V4 profile.
    V4Bounded,
    /// Future basis route reports an over-bound basis.
    Oversized,
    /// No quality statement is available yet.
    Unknown,
}

/// Public, serializable metadata for a secret trapdoor representation.
///
/// This structure is safe for logs and evidence: it contains public hashes,
/// parameter identifiers, and length buckets only. It never carries trapdoor
/// coefficients, seed bytes, or expanded secret matrices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapdoorRepresentationMetadata {
    /// Representation envelope version.
    pub version: u16,
    /// Root or child layer.
    pub scope: TrapdoorScope,
    /// Stored secret material route.
    pub material_kind: TrapdoorMaterialKind,
    /// Parameter profile bound into the secret.
    pub params: LatticeParams,
    /// Public matrix seed/hash this secret claims to support.
    pub public_matrix_hash: [u8; 32],
    /// Parent public matrix seed/hash for child trapdoors.
    pub parent_public_matrix_hash: Option<[u8; 32]>,
    /// Redaction-safe storage length bucket.
    pub secret_storage_len_bucket: SecretStorageLengthBucket,
}

impl TrapdoorRepresentationMetadata {
    /// Validate that metadata is structurally well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidTrapdoorSecret`] when the scope and
    /// parent linkage are inconsistent, or parameter validation fails.
    pub fn validate(self) -> LatticePqResult<()> {
        self.params.validate()?;
        if self.version != LATTICE_REPRESENTATION_VERSION {
            return Err(LatticePqError::InvalidEncodingLength {
                material: "trapdoor_version",
                expected: usize::from(LATTICE_REPRESENTATION_VERSION),
                got: usize::from(self.version),
            });
        }
        match self.material_kind {
            TrapdoorMaterialKind::FixtureShakeSeedBundle => {
                let expected_bucket =
                    SecretStorageLengthBucket::from_len(self.params.trapdoor_storage_bytes()?);
                if self.secret_storage_len_bucket != expected_bucket {
                    return Err(LatticePqError::InvalidTrapdoorSecret {
                        material: "fixture_trapdoor_seed_bundle",
                        reason: "fixture secret length bucket must match parameter profile",
                    });
                }
            }
            TrapdoorMaterialKind::BasisEnvelope
                if matches!(
                    self.secret_storage_len_bucket,
                    SecretStorageLengthBucket::Empty | SecretStorageLengthBucket::TooLarge
                ) =>
            {
                return Err(LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    reason: "basis envelope length bucket must be non-empty and within limits",
                });
            }
            TrapdoorMaterialKind::BasisEnvelope => {}
        }
        match (self.scope, self.parent_public_matrix_hash) {
            (TrapdoorScope::Root, None) | (TrapdoorScope::Child, Some(_)) => Ok(()),
            (TrapdoorScope::Root, Some(_)) => Err(LatticePqError::InvalidTrapdoorSecret {
                material: "root_trapdoor",
                reason: "root trapdoor metadata must not include a parent hash",
            }),
            (TrapdoorScope::Child, None) => Err(LatticePqError::InvalidTrapdoorSecret {
                material: "child_trapdoor",
                reason: "child trapdoor metadata must include a parent hash",
            }),
        }
    }
}

/// Redaction-safe summary of a trapdoor/public-key relation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapdoorRelationSummary {
    /// Metadata checked.
    pub metadata: TrapdoorRepresentationMetadata,
    /// Relation outcome without exposing coefficients or secret bytes.
    pub result: TrapdoorRelationResult,
    /// Norm/quality bucket without exposing basis vectors.
    pub norm_quality_bucket: TrapdoorNormQualityBucket,
}

fn validate_trapdoor_secret(
    material_kind: TrapdoorMaterialKind,
    params: LatticeParams,
    len: usize,
) -> LatticePqResult<SecretStorageLengthBucket> {
    let bucket = SecretStorageLengthBucket::from_len(len);
    if bucket == SecretStorageLengthBucket::TooLarge {
        return Err(LatticePqError::RepresentationTooLarge {
            material: "trapdoor_secret",
            requested: len,
            max: MAX_TRAPDOOR_SECRET_BYTES,
        });
    }
    match material_kind {
        TrapdoorMaterialKind::FixtureShakeSeedBundle => {
            let expected = params.trapdoor_storage_bytes()?;
            if len != expected {
                return Err(LatticePqError::InvalidEncodingLength {
                    material: "fixture_trapdoor_seed_bundle",
                    expected,
                    got: len,
                });
            }
        }
        TrapdoorMaterialKind::BasisEnvelope => {
            if len == 0 {
                return Err(LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    reason: "basis envelope must not be empty",
                });
            }
        }
    }
    Ok(bucket)
}

fn trapdoor_metadata(
    scope: TrapdoorScope,
    material_kind: TrapdoorMaterialKind,
    params: LatticeParams,
    public_matrix_hash: [u8; 32],
    parent_public_matrix_hash: Option<[u8; 32]>,
    secret_len: usize,
) -> LatticePqResult<TrapdoorRepresentationMetadata> {
    let secret_storage_len_bucket = validate_trapdoor_secret(material_kind, params, secret_len)?;
    let metadata = TrapdoorRepresentationMetadata {
        version: LATTICE_REPRESENTATION_VERSION,
        scope,
        material_kind,
        params,
        public_matrix_hash,
        parent_public_matrix_hash,
        secret_storage_len_bucket,
    };
    metadata.validate()?;
    Ok(metadata)
}

const fn norm_quality_bucket(
    material_kind: TrapdoorMaterialKind,
    secret_storage_len_bucket: SecretStorageLengthBucket,
) -> TrapdoorNormQualityBucket {
    match material_kind {
        TrapdoorMaterialKind::FixtureShakeSeedBundle => TrapdoorNormQualityBucket::FixtureSeed,
        TrapdoorMaterialKind::BasisEnvelope => match secret_storage_len_bucket {
            SecretStorageLengthBucket::Empty | SecretStorageLengthBucket::TooLarge => {
                TrapdoorNormQualityBucket::Oversized
            }
            SecretStorageLengthBucket::UpTo128 | SecretStorageLengthBucket::UpTo4KiB => {
                TrapdoorNormQualityBucket::Small
            }
            SecretStorageLengthBucket::UpTo64KiB | SecretStorageLengthBucket::UpTo1MiB => {
                TrapdoorNormQualityBucket::V4Bounded
            }
        },
    }
}

fn checked_profile_product(
    material: &'static str,
    factors: &[usize],
    max: usize,
) -> LatticePqResult<usize> {
    let mut requested = 1usize;
    for factor in factors {
        requested =
            requested
                .checked_mul(*factor)
                .ok_or(LatticePqError::RepresentationTooLarge {
                    material,
                    requested: usize::MAX,
                    max,
                })?;
    }
    if requested > max {
        return Err(LatticePqError::RepresentationTooLarge {
            material,
            requested,
            max,
        });
    }
    Ok(requested)
}

// ── Wire-format placeholders ──────────────────────────────────────────────

/// Time window `(start, end)` a delegation certificate is valid in,
/// in **monotonic seconds** since FCP epoch (matches
/// `fcp_policy::lattice_delegation::DelegationPeriod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPeriod {
    /// Inclusive lower bound.
    pub start_secs: u64,
    /// Exclusive upper bound.
    pub end_secs: u64,
}

impl DelegationPeriod {
    /// `true` if `secs` falls inside `[start, end)`.
    #[must_use]
    pub const fn contains(&self, secs: u64) -> bool {
        secs >= self.start_secs && secs < self.end_secs
    }
}

/// Master public-matrix bundle returned by [`trap_gen`].
///
/// In the real implementation `A_root` is an `n×m` matrix over `Z_q`
/// (≈30 KB at `V4_REFERENCE`); we expose only its 32-byte public seed
/// placeholder so the public type is fixed-size and copy-friendly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterPublicKey {
    /// 32-byte SHAKE256-derived public matrix seed placeholder.
    pub hash: [u8; 32],
    /// Parameters this key was generated for.
    pub params: LatticeParams,
}

/// Master trapdoor `T_root` held offline by the owner.
///
/// The current representation is a sealed seed bundle bound to
/// [`LATTICE_REPRESENTATION_VERSION`] and [`LatticeParams`]. It is not sent to
/// verifiers and intentionally does not implement `Serialize`: only public
/// matrix seeds and preimages cross the token boundary.
///
/// Serialization boundary:
///
/// ```compile_fail
/// use fcp_crypto_pq::{trap_gen, LatticeParams};
///
/// let (_, trapdoor) = trap_gen(LatticeParams::SMALL_TEST).unwrap();
/// let _json = serde_json::to_string(&trapdoor).unwrap();
/// ```
///
/// **Constant-time equality** (br-1zlht): the trapdoor IS the
/// load-bearing secret of the lattice-trapdoor scheme. Equality via
/// [`subtle::ConstantTimeEq`] not the derived `[u8; N]::eq`.
#[derive(Clone, Eq)]
pub struct MasterTrapdoor {
    metadata: TrapdoorRepresentationMetadata,
    pub(crate) bytes: Vec<u8>,
}

impl MasterTrapdoor {
    /// Build a fixture root trapdoor from encoded seed-bundle bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed or the fixture secret
    /// length does not match the profile-derived seed-bundle length.
    pub fn from_fixture_seed_bundle(
        params: LatticeParams,
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Root,
            TrapdoorMaterialKind::FixtureShakeSeedBundle,
            params,
            public_matrix_hash,
            None,
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Build a future basis-capable root trapdoor envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed or the basis envelope is
    /// empty or exceeds the secret storage ceiling.
    pub fn from_basis_envelope(
        params: LatticeParams,
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Root,
            TrapdoorMaterialKind::BasisEnvelope,
            params,
            public_matrix_hash,
            None,
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Redaction-safe metadata for this trapdoor.
    #[must_use]
    pub const fn metadata(&self) -> TrapdoorRepresentationMetadata {
        self.metadata
    }

    /// Representation version bound into this trapdoor.
    #[must_use]
    pub const fn representation_version(&self) -> u16 {
        self.metadata.version
    }

    /// Parameter profile bound into this trapdoor.
    #[must_use]
    pub const fn params(&self) -> LatticeParams {
        self.metadata.params
    }

    /// Secret material route for this trapdoor.
    #[must_use]
    pub const fn material_kind(&self) -> TrapdoorMaterialKind {
        self.metadata.material_kind
    }

    /// Redaction-safe secret storage length bucket.
    #[must_use]
    pub const fn secret_storage_len_bucket(&self) -> SecretStorageLengthBucket {
        self.metadata.secret_storage_len_bucket
    }

    /// Encoded secret storage byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Redaction-safe relation summary against the public root key.
    #[must_use]
    pub fn relation_summary(&self, public: &MasterPublicKey) -> TrapdoorRelationSummary {
        let metadata = self.metadata;
        let root_public_matrix_hash = public.hash;
        let structurally_matches = metadata.scope == TrapdoorScope::Root
            && metadata.parent_public_matrix_hash.is_none()
            && metadata.params == public.params
            && metadata.public_matrix_hash == root_public_matrix_hash;
        let result = if !structurally_matches {
            TrapdoorRelationResult::MetadataMismatch
        } else if metadata.material_kind == TrapdoorMaterialKind::FixtureShakeSeedBundle {
            TrapdoorRelationResult::FixtureOnly
        } else {
            TrapdoorRelationResult::UnsupportedPrimitive
        };
        TrapdoorRelationSummary {
            metadata,
            result,
            norm_quality_bucket: norm_quality_bucket(
                metadata.material_kind,
                metadata.secret_storage_len_bucket,
            ),
        }
    }
}

impl PartialEq for MasterTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata && constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for MasterTrapdoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterTrapdoor")
            .field("metadata", &self.metadata)
            .field("encoded_len", &self.bytes.len())
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

impl Drop for MasterTrapdoor {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Per-`(zone, period)` public matrix `A_zp` returned by [`delegate`].
///
/// As with [`MasterPublicKey`], we carry a public matrix seed placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZonePeriodPublicKey {
    /// 32-byte SHAKE256-derived public matrix seed placeholder.
    pub hash: [u8; 32],
    /// Zone identifier this delegation authorizes for. Opaque to this
    /// crate — `fcp_policy` owns the canonical `ZoneId` type.
    pub zone_id: [u8; 32],
    /// Time window this delegation is valid in.
    pub period: DelegationPeriod,
    /// Parameters inherited from the master key.
    pub params: LatticeParams,
}

/// Per-`(zone, period)` trapdoor `T_zp` returned by [`delegate`].
///
/// Held by the issuance node; used to derive sub-tokens via [`sample_pre`].
/// The secret child trapdoor intentionally does not implement `Serialize`.
///
/// ```compile_fail
/// use fcp_crypto_pq::{delegate, trap_gen, DelegationPeriod, LatticeParams};
///
/// let params = LatticeParams::SMALL_TEST;
/// let (master_public, master_trapdoor) = trap_gen(params).unwrap();
/// let period = DelegationPeriod {
///     start_secs: 1,
///     end_secs: 2,
/// };
/// let (_, child_trapdoor) =
///     delegate(&master_public, &master_trapdoor, [0_u8; 32], period, params).unwrap();
/// let _json = serde_json::to_string(&child_trapdoor).unwrap();
/// ```
///
/// **Constant-time equality** (br-1zlht): see [`MasterTrapdoor`].
#[derive(Clone, Eq)]
pub struct ZonePeriodTrapdoor {
    metadata: TrapdoorRepresentationMetadata,
    pub(crate) bytes: Vec<u8>,
}

impl ZonePeriodTrapdoor {
    /// Build a fixture child trapdoor from encoded seed-bundle bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed, parent linkage is
    /// missing, or the fixture secret length does not match the profile.
    pub fn from_fixture_seed_bundle(
        params: LatticeParams,
        parent_public_matrix_hash: [u8; 32],
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Child,
            TrapdoorMaterialKind::FixtureShakeSeedBundle,
            params,
            public_matrix_hash,
            Some(parent_public_matrix_hash),
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Build a future basis-capable child trapdoor envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when parameters are malformed or the basis envelope is
    /// empty or exceeds the secret storage ceiling.
    pub fn from_basis_envelope(
        params: LatticeParams,
        parent_public_matrix_hash: [u8; 32],
        public_matrix_hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> LatticePqResult<Self> {
        let metadata = trapdoor_metadata(
            TrapdoorScope::Child,
            TrapdoorMaterialKind::BasisEnvelope,
            params,
            public_matrix_hash,
            Some(parent_public_matrix_hash),
            bytes.len(),
        )?;
        Ok(Self { metadata, bytes })
    }

    /// Redaction-safe metadata for this trapdoor.
    #[must_use]
    pub const fn metadata(&self) -> TrapdoorRepresentationMetadata {
        self.metadata
    }

    /// Representation version bound into this trapdoor.
    #[must_use]
    pub const fn representation_version(&self) -> u16 {
        self.metadata.version
    }

    /// Parameter profile bound into this trapdoor.
    #[must_use]
    pub const fn params(&self) -> LatticeParams {
        self.metadata.params
    }

    /// Secret material route for this trapdoor.
    #[must_use]
    pub const fn material_kind(&self) -> TrapdoorMaterialKind {
        self.metadata.material_kind
    }

    /// Redaction-safe secret storage length bucket.
    #[must_use]
    pub const fn secret_storage_len_bucket(&self) -> SecretStorageLengthBucket {
        self.metadata.secret_storage_len_bucket
    }

    /// Encoded secret storage byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Redaction-safe relation summary against the child and parent public keys.
    #[must_use]
    pub fn relation_summary(
        &self,
        child_public: &ZonePeriodPublicKey,
        parent_public: &MasterPublicKey,
    ) -> TrapdoorRelationSummary {
        let metadata = self.metadata;
        let structurally_matches = metadata.scope == TrapdoorScope::Child
            && metadata.parent_public_matrix_hash == Some(parent_public.hash)
            && metadata.params == child_public.params
            && metadata.params == parent_public.params
            && metadata.public_matrix_hash == child_public.hash;
        let result = if !structurally_matches {
            TrapdoorRelationResult::MetadataMismatch
        } else if metadata.material_kind == TrapdoorMaterialKind::FixtureShakeSeedBundle {
            TrapdoorRelationResult::FixtureOnly
        } else {
            TrapdoorRelationResult::UnsupportedPrimitive
        };
        TrapdoorRelationSummary {
            metadata,
            result,
            norm_quality_bucket: norm_quality_bucket(
                metadata.material_kind,
                metadata.secret_storage_len_bucket,
            ),
        }
    }
}

impl PartialEq for ZonePeriodTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata && constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for ZonePeriodTrapdoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZonePeriodTrapdoor")
            .field("metadata", &self.metadata)
            .field("encoded_len", &self.bytes.len())
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

impl Drop for ZonePeriodTrapdoor {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Hash of an operation context `H(zone | period | op | principal)`,
/// expanded into the verification equation's right-hand side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationHash(pub [u8; 32]);

/// Short lattice preimage `e` such that `A_zp · e ≡ h (mod q)`.
///
/// Real impl: a vector in `Z_q^m` with `‖e‖₂ ≤ B`. The wire/storage encoding
/// is profile-derived (`m × coefficient_bytes`) and validated by
/// [`LatticePreimage::from_encoded_bytes`].
///
/// **Constant-time equality** (br-1zlht): the preimage is the
/// signature material of the lattice-trapdoor scheme; equality via
/// [`subtle::ConstantTimeEq`].
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct LatticePreimage {
    /// Opaque preimage bytes.
    #[serde(with = "hex_vec")]
    pub bytes: Vec<u8>,
}

impl LatticePreimage {
    /// Build a preimage from encoded bytes after checking the profile-derived
    /// wire length.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] or
    /// [`LatticePqError::RepresentationTooLarge`] when `params` do not define a
    /// bounded preimage profile, and [`LatticePqError::InvalidEncodingLength`]
    /// when `bytes` has the wrong profile-derived length.
    pub fn from_encoded_bytes(params: LatticeParams, bytes: Vec<u8>) -> LatticePqResult<Self> {
        let expected = params.preimage_encoded_bytes()?;
        if bytes.len() != expected {
            return Err(LatticePqError::InvalidEncodingLength {
                material: "preimage",
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Deterministic all-zero fixture with the correct profile-derived length.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePqError::InvalidParameter`] or
    /// [`LatticePqError::RepresentationTooLarge`] when `params` do not define a
    /// bounded preimage profile.
    pub fn fixture_zero(params: LatticeParams) -> LatticePqResult<Self> {
        let len = params.preimage_encoded_bytes()?;
        Ok(Self {
            bytes: vec![0_u8; len],
        })
    }

    /// Encoded preimage byte length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    /// Borrow the encoded preimage bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq for LatticePreimage {
    fn eq(&self, other: &Self) -> bool {
        constant_time_bytes_eq(&self.bytes, &other.bytes)
    }
}

impl std::fmt::Debug for LatticePreimage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LatticePreimage")
            .field("encoded_len", &self.bytes.len())
            .field("secret_material", &"<redacted>")
            .finish()
    }
}

impl Drop for LatticePreimage {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ── Deterministic expansion scaffolding ───────────────────────────────────

const SHAKE_DOMAIN_PREFIX: &[u8] = b"fcp-crypto-pq/lattice-v1";

fn shake256_fill(tag: &[u8], feed: impl FnOnce(&mut Shake256), out: &mut [u8]) {
    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
    update_len_prefixed(&mut shaker, tag);
    feed(&mut shaker);
    let mut reader = shaker.finalize_xof();
    reader.read(out);
}

fn update_len_prefixed(shaker: &mut Shake256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("SHAKE input length fits in u64");
    Update::update(shaker, &len.to_le_bytes());
    Update::update(shaker, bytes);
}

fn update_period(shaker: &mut Shake256, period: DelegationPeriod) {
    Update::update(shaker, &period.start_secs.to_le_bytes());
    Update::update(shaker, &period.end_secs.to_le_bytes());
}

fn update_params(shaker: &mut Shake256, params: LatticeParams) {
    Update::update(shaker, &params.n.to_le_bytes());
    Update::update(shaker, &params.q.to_le_bytes());
    Update::update(shaker, &params.m.to_le_bytes());
    Update::update(shaker, &params.sigma_x100.to_le_bytes());
    Update::update(shaker, &[params.depth]);
}

fn trap_gen_seed(params: LatticeParams, purpose: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"trap-gen-seed",
        |shaker| {
            update_params(shaker, params);
            update_len_prefixed(shaker, purpose);
        },
        &mut out,
    );
    out
}

fn zone_period_trapdoor_seed(
    parent_trap: &MasterTrapdoor,
    matrix_seed: &[u8; 32],
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> LatticePqResult<Vec<u8>> {
    let mut out = vec![0_u8; params.trapdoor_storage_bytes()?];
    shake256_fill(
        b"zone-period-trapdoor-seed-bundle",
        |shaker| {
            update_len_prefixed(shaker, &parent_trap.bytes);
            update_len_prefixed(shaker, matrix_seed);
            update_len_prefixed(shaker, zone_id);
            update_period(shaker, period);
            update_params(shaker, params);
        },
        &mut out,
    );
    Ok(out)
}

fn trap_gen_secret_bundle(params: LatticeParams) -> LatticePqResult<Vec<u8>> {
    let mut out = vec![0_u8; params.trapdoor_storage_bytes()?];
    shake256_fill(
        b"master-trapdoor-seed-bundle",
        |shaker| {
            update_params(shaker, params);
            update_len_prefixed(shaker, b"master-trapdoor");
        },
        &mut out,
    );
    Ok(out)
}

/// Deterministically derive the public matrix seed for a `(zone, period)` child.
///
/// This is only the SHAKE256 public-seed scaffold for the eventual
/// matrix-valued hash. It is **not** CHKP basis-shortening and does not prove
/// possession of a trapdoor.
#[must_use]
pub fn zone_period_matrix_seed(
    parent_pub: &MasterPublicKey,
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> [u8; 32] {
    let mut out = [0_u8; 32];
    shake256_fill(
        b"zone-period-matrix-seed",
        |shaker| {
            update_len_prefixed(shaker, &parent_pub.hash);
            update_len_prefixed(shaker, zone_id);
            update_period(shaker, period);
            update_params(shaker, params);
        },
        &mut out,
    );
    out
}

/// Expand an operation hash into the verification right-hand side in `Z_q^n`.
///
/// This pins the deterministic SHAKE256 rejection-sampling fixture needed by
/// the future `A · e ≡ h (mod q)` check. It does **not** sample a preimage,
/// validate a norm bound, or establish lattice soundness.
///
/// # Panics
///
/// Panics only on targets where `usize` cannot represent a `u32` lattice
/// dimension.
#[must_use]
pub fn expand_operation_hash_rhs(h: OperationHash, params: LatticeParams) -> Vec<u64> {
    let len = usize::try_from(params.n).expect("u32 lattice dimension fits in usize");
    let modulus = params.q.max(1);
    let modulus_u128 = u128::from(modulus);
    let range = u128::from(u64::MAX) + 1;
    let reject_above = range - (range % modulus_u128);

    let mut out = Vec::with_capacity(len);
    let mut reader_buf = [0_u8; 8];
    let mut shaker = Shake256::default();
    update_len_prefixed(&mut shaker, SHAKE_DOMAIN_PREFIX);
    update_len_prefixed(&mut shaker, b"operation-rhs-vector");
    update_len_prefixed(&mut shaker, &h.0);
    update_params(&mut shaker, params);
    let mut reader = shaker.finalize_xof();

    while out.len() < len {
        reader.read(&mut reader_buf);
        let candidate = u128::from(u64::from_le_bytes(reader_buf));
        if candidate < reject_above {
            let coeff = candidate % modulus_u128;
            out.push(u64::try_from(coeff).expect("coefficient fits in u64"));
        }
    }
    out
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Failure modes for the lattice-trapdoor primitives.
///
/// The `NotImplemented` variant is the dominant outcome from this stub
/// crate; production code MUST treat it as a graceful "V4 path not
/// available, fall back to V3" signal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LatticePqError {
    /// Stub crate hit — the primitive is not implemented yet.
    #[error("lattice primitive `{primitive}` not implemented (responsible bead: {bead})")]
    NotImplemented {
        /// Name of the primitive that was called.
        primitive: &'static str,
        /// Bead ID expected to land the implementation.
        bead: &'static str,
    },

    /// Parameter profile is malformed before any cryptographic work starts.
    #[error("invalid lattice parameter `{field}`={value}: {reason}")]
    InvalidParameter {
        /// Parameter field name.
        field: &'static str,
        /// Rejected value.
        value: u64,
        /// Human-readable reason.
        reason: &'static str,
    },

    /// Representation implied by the parameters would exceed the crate's
    /// explicit allocation ceiling.
    #[error(
        "lattice representation `{material}` too large: requested {requested} bytes, max {max}"
    )]
    RepresentationTooLarge {
        /// Material being represented.
        material: &'static str,
        /// Requested encoded or expanded byte count.
        requested: usize,
        /// Hard ceiling.
        max: usize,
    },

    /// Encoded material does not match the profile-derived wire length.
    #[error("invalid encoded `{material}` length: expected {expected} bytes, got {got}")]
    InvalidEncodingLength {
        /// Material being decoded.
        material: &'static str,
        /// Expected byte count.
        expected: usize,
        /// Supplied byte count.
        got: usize,
    },

    /// Parameters mismatch between caller and key (e.g. trapdoor was
    /// generated for `n=512` but verification passed `n=1024` params).
    #[error("parameter mismatch: caller passed {caller:?}, key expects {key:?}")]
    ParameterMismatch {
        /// Caller-supplied params.
        caller: LatticeParams,
        /// Params bound into the key being used.
        key: LatticeParams,
    },

    /// Secret trapdoor metadata or storage is malformed.
    #[error("invalid trapdoor secret `{material}`: {reason}")]
    InvalidTrapdoorSecret {
        /// Secret material being decoded.
        material: &'static str,
        /// Human-readable rejection reason.
        reason: &'static str,
    },

    /// `period.start_secs >= period.end_secs`.
    #[error("invalid delegation period: start {start_secs} not < end {end_secs}")]
    InvalidPeriod {
        /// Start bound that failed.
        start_secs: u64,
        /// End bound that failed.
        end_secs: u64,
    },

    /// Operation timestamp falls outside the certificate's valid window.
    #[error("timestamp {now_secs} outside delegation period [{start_secs}, {end_secs})")]
    OutsidePeriod {
        /// Current time the verifier was running at.
        now_secs: u64,
        /// Period lower bound.
        start_secs: u64,
        /// Period upper bound.
        end_secs: u64,
    },

    /// Preimage failed the verification equation `A · e ≡ h (mod q)`.
    /// Returned by future real implementation, never by the stub.
    #[error("preimage failed verification equation")]
    VerificationEquationFailed,

    /// Preimage norm exceeded the hard bound `B`.
    /// Returned by future real implementation, never by the stub.
    #[error("preimage norm exceeded bound (got {got_squared}, max squared {max_squared})")]
    PreimageNormTooLarge {
        /// Computed `‖e‖₂²`.
        got_squared: u128,
        /// Hard ceiling `B²`.
        max_squared: u128,
    },
}

/// Convenience alias.
pub type LatticePqResult<T> = Result<T, LatticePqError>;

// ── Primitives (stubs) ────────────────────────────────────────────────────

/// **`TrapGen`** (§3.3 layer 0).
///
/// Real impl: Micciancio-Peikert (TCC 2012) gadget-trapdoor matrix
/// sampler — produces `(A_root ∈ Z_q^{n×m}, T_root)` such that
/// `A_root · T_root ≡ G (mod q)` for the gadget matrix `G`.
///
/// **Scaffold:** returns deterministic SHAKE256-derived byte placeholders
/// from `params` so call-sites have stable handles to thread, but the bytes
/// are NOT cryptographic material. The public seed and trapdoor placeholder
/// use distinct domain tags.
///
/// # Errors
///
/// Currently always succeeds (it's a deterministic placeholder). The
/// real implementation may fail on entropy starvation; signature
/// remains `LatticePqResult` to preserve forward compatibility.
pub fn trap_gen(params: LatticeParams) -> LatticePqResult<(MasterPublicKey, MasterTrapdoor)> {
    params.validate()?;
    let public_hash = trap_gen_seed(params, b"master-public-matrix-seed");
    let trapdoor_bytes = trap_gen_secret_bundle(params)?;
    Ok((
        MasterPublicKey {
            hash: public_hash,
            params,
        },
        MasterTrapdoor::from_fixture_seed_bundle(params, public_hash, trapdoor_bytes)?,
    ))
}

/// **Delegate** (§3.3 layer 1).
///
/// Real impl: Cash-Hofheinz-Kiltz-Peikert (Eurocrypt 2010) basis-
/// shortening — given the parent `(A_par, T_par)` and a `(zone, period)`
/// label, derive `(A_zp, T_zp)` for the child certificate.
///
/// **Scaffold:** binds `(zone_id, period)` into a deterministic SHAKE256
/// public matrix seed plus a distinct trapdoor placeholder. Always succeeds
/// when `params` agree and `period` is well-ordered, but does NOT perform
/// CHKP basis-shortening.
///
/// # Errors
///
/// - [`LatticePqError::ParameterMismatch`] if `params` disagree with the
///   parent's bound parameters.
/// - [`LatticePqError::InvalidPeriod`] if `period.start_secs >=
///   period.end_secs`.
pub fn delegate(
    parent_pub: &MasterPublicKey,
    parent_trap: &MasterTrapdoor,
    zone_id: [u8; 32],
    period: DelegationPeriod,
    params: LatticeParams,
) -> LatticePqResult<(ZonePeriodPublicKey, ZonePeriodTrapdoor)> {
    if params != parent_pub.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: parent_pub.params,
        });
    }
    if params != parent_trap.params() {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: parent_trap.params(),
        });
    }
    params.validate()?;
    if period.start_secs >= period.end_secs {
        return Err(LatticePqError::InvalidPeriod {
            start_secs: period.start_secs,
            end_secs: period.end_secs,
        });
    }

    let pub_hash = zone_period_matrix_seed(parent_pub, &zone_id, period, params);
    let trap_bytes = zone_period_trapdoor_seed(parent_trap, &pub_hash, &zone_id, period, params);

    Ok((
        ZonePeriodPublicKey {
            hash: pub_hash,
            zone_id,
            period,
            params,
        },
        ZonePeriodTrapdoor::from_fixture_seed_bundle(
            params,
            parent_pub.hash,
            pub_hash,
            trap_bytes?,
        )?,
    ))
}

/// **`SamplePre`** (§3.3 layer 2).
///
/// Real impl: Gentry-Peikert-Vaikuntanathan (STOC 2008) preimage
/// sampling — given `(A_zp, T_zp, h)`, sample `e ← D_{Λ⊥(A_zp), h, σ}`
/// such that `A_zp · e ≡ h (mod q)` and `‖e‖₂ ≤ B = σ · √m · ω(√log n)`.
///
/// **Stub:** returns
/// `Err(LatticePqError::NotImplemented { primitive: "sample_pre", bead:
/// "kyopb.1.3.1.1.4" })`.
///
/// # Errors
///
/// - Always [`LatticePqError::NotImplemented`] until the real Gaussian
///   preimage sampler lands.
/// - [`LatticePqError::ParameterMismatch`] if `params` disagree with
///   `key.params`. Checked BEFORE the not-implemented return so
///   parameter-validation tests can already cover the path.
pub fn sample_pre(
    key: &ZonePeriodPublicKey,
    trap: &ZonePeriodTrapdoor,
    _h: OperationHash,
    params: LatticeParams,
) -> LatticePqResult<LatticePreimage> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    if params != trap.params() {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: trap.params(),
        });
    }
    params.validate()?;
    Err(LatticePqError::NotImplemented {
        primitive: "sample_pre",
        bead: "kyopb.1.3.1.1.4",
    })
}

/// **Verify** (§3.3 verification equation).
///
/// Real impl: check `A_zp · e ≡ h (mod q)` and `‖e‖₂ ≤ B`. Returns `Ok(())`
/// on success, an error variant explaining the failure mode otherwise.
///
/// **Stub:** does the cheap structural checks (parameter agreement,
/// period containment) so call-sites can already exercise the negative
/// branches; returns
/// `Err(LatticePqError::NotImplemented { primitive: "verify", bead:
/// "kyopb.1.3.1.1.4" })` for any positive case.
///
/// # Errors
///
/// - [`LatticePqError::ParameterMismatch`] if `params` disagree with
///   `key.params`.
/// - [`LatticePqError::OutsidePeriod`] if `now_secs ∉ key.period`.
/// - [`LatticePqError::NotImplemented`] for the cryptographic check
///   (until the real verification equation lands).
pub fn verify(
    key: &ZonePeriodPublicKey,
    _h: OperationHash,
    _preimage: &LatticePreimage,
    now_secs: u64,
    params: LatticeParams,
) -> LatticePqResult<()> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    params.validate()?;
    if !key.period.contains(now_secs) {
        return Err(LatticePqError::OutsidePeriod {
            now_secs,
            start_secs: key.period.start_secs,
            end_secs: key.period.end_secs,
        });
    }
    Err(LatticePqError::NotImplemented {
        primitive: "verify",
        bead: "kyopb.1.3.1.1.4",
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Compute the canonical operation hash
/// `H(zone | period | op | principal)`.
///
/// **Stub:** uses BLAKE3; real impl will use SHAKE256 expanded to
/// `Z_q^n` per §3.3 of the design doc. Domain-separated by a stable
/// tag so this output is forward-compatible with the eventual real
/// hash-to-`Z_q^n` (the SHAKE256 expansion will start from this same
/// 32-byte digest).
#[must_use]
pub fn operation_hash(
    zone_id: &[u8; 32],
    period: DelegationPeriod,
    op: &[u8],
    principal: &[u8],
) -> OperationHash {
    let mut h = blake3::Hasher::new();
    h.update(b"fcp-pq/operation-hash-v0|");
    h.update(zone_id);
    h.update(&period.start_secs.to_le_bytes());
    h.update(&period.end_secs.to_le_bytes());
    h.update(&(op.len() as u64).to_le_bytes());
    h.update(op);
    h.update(&(principal.len() as u64).to_le_bytes());
    h.update(principal);
    OperationHash(*h.finalize().as_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_period() -> DelegationPeriod {
        DelegationPeriod {
            start_secs: 1_000,
            end_secs: 2_000,
        }
    }

    #[test]
    fn v4_reference_params_have_expected_shape() {
        let p = LatticeParams::V4_REFERENCE;
        assert_eq!(p.n, 512);
        assert_eq!(p.q, 4_294_967_291);
        assert_eq!(p.m, 16_384);
        assert_eq!(p.sigma_x100, 11_300);
        assert_eq!(p.depth, 4);
        p.validate().expect("reference profile is valid");
        let profile = p
            .representation_profile()
            .expect("reference profile has bounded representation");
        assert_eq!(profile.version, LATTICE_REPRESENTATION_VERSION);
        assert_eq!(profile.coefficient_bytes, 4);
        assert_eq!(profile.public_matrix_seed_bytes, 32);
        assert_eq!(profile.public_matrix_expanded_bytes, 33_554_432);
        assert_eq!(profile.trapdoor_storage_bytes, 96);
        assert_eq!(profile.preimage_encoded_bytes, 65_536);
    }

    #[test]
    fn small_test_profile_has_tiny_deterministic_representation() {
        let p = LatticeParams::SMALL_TEST;
        p.validate().expect("small profile is valid");
        let profile = p.representation_profile().unwrap();
        assert_eq!(profile.coefficient_bytes, 2);
        assert_eq!(profile.public_matrix_expanded_bytes, 256);
        assert_eq!(profile.preimage_encoded_bytes, 32);
    }

    #[test]
    fn delegation_period_contains_handles_boundaries() {
        let p = ref_period();
        assert!(!p.contains(999), "before start is excluded");
        assert!(p.contains(1_000), "start is inclusive");
        assert!(p.contains(1_500), "interior is included");
        assert!(p.contains(1_999), "just-before-end is included");
        assert!(!p.contains(2_000), "end is exclusive");
        assert!(!p.contains(2_001), "after end is excluded");
    }

    #[test]
    fn trap_gen_is_deterministic_on_params() {
        let p = LatticeParams::V4_REFERENCE;
        let (pk1, tr1) = trap_gen(p).expect("stub trap_gen never fails");
        let (pk2, tr2) = trap_gen(p).expect("stub trap_gen never fails");
        assert_eq!(pk1, pk2, "same params → same public key");
        assert_eq!(tr1, tr2, "same params → same trapdoor");
        assert_ne!(
            &pk1.hash[..],
            &tr1.bytes[..],
            "public-key hash and trapdoor bytes are tagged differently"
        );
        assert_eq!(tr1.representation_version(), LATTICE_REPRESENTATION_VERSION);
        assert_eq!(tr1.params(), p);
        assert_eq!(tr1.encoded_len(), p.trapdoor_storage_bytes().unwrap());
    }

    #[test]
    fn trap_gen_distinguishes_param_variants() {
        let mut alt = LatticeParams::V4_REFERENCE;
        alt.depth = 3;
        let (pk_ref, _) = trap_gen(LatticeParams::V4_REFERENCE).unwrap();
        let (pk_alt, _) = trap_gen(alt).unwrap();
        assert_ne!(pk_ref.hash, pk_alt.hash, "different params → different key");
    }

    #[test]
    fn trap_gen_shake256_seed_fixtures_are_pinned() {
        let (master_pub, master_trap) = trap_gen(LatticeParams::V4_REFERENCE).unwrap();
        assert_eq!(
            hex::encode(master_pub.hash),
            "7f00d711a9de7cec422265e9cfb180de6c37aa7da3ff0375abf0249199b491ad"
        );
        assert_eq!(master_trap.encoded_len(), 96);
        assert!(
            format!("{master_trap:?}").contains("<redacted>"),
            "secret trapdoor debug output must redact material"
        );
    }

    #[test]
    fn delegate_round_trips_through_stub() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let zone = [7u8; 32];
        let period = ref_period();

        let (zp_pub, zp_trap) =
            delegate(&master_pub, &master_trap, zone, period, p).expect("delegate stub succeeds");

        assert_eq!(zp_pub.zone_id, zone);
        assert_eq!(zp_pub.period, period);
        assert_eq!(zp_pub.params, p);
        assert_ne!(
            zp_pub.hash, master_pub.hash,
            "child key hash differs from master"
        );
        assert_ne!(
            &zp_pub.hash[..],
            &zp_trap.bytes[..],
            "child public hash and child trapdoor are tagged differently"
        );
        assert_eq!(zp_trap.params(), p);
        assert_eq!(zp_trap.encoded_len(), p.trapdoor_storage_bytes().unwrap());
    }

    #[test]
    fn trapdoor_metadata_round_trips_without_secret_material() {
        let p = LatticeParams::SMALL_TEST;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let zone = [7u8; 32];
        let (zone_pub, zone_trap) =
            delegate(&master_pub, &master_trap, zone, ref_period(), p).unwrap();

        let master_metadata = master_trap.metadata();
        assert_eq!(master_metadata.version, LATTICE_REPRESENTATION_VERSION);
        assert_eq!(master_metadata.scope, TrapdoorScope::Root);
        assert_eq!(
            master_metadata.material_kind,
            TrapdoorMaterialKind::FixtureShakeSeedBundle
        );
        assert_eq!(master_metadata.public_matrix_hash, master_pub.hash);
        assert_eq!(master_metadata.parent_public_matrix_hash, None);
        assert_eq!(
            master_metadata.secret_storage_len_bucket,
            SecretStorageLengthBucket::UpTo128
        );

        let json = serde_json::to_string(&master_metadata).unwrap();
        assert!(!json.contains("secret_material"));
        assert!(!json.contains("seed_bundle"));
        let master_back: TrapdoorRepresentationMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(master_back, master_metadata);

        let zone_metadata = zone_trap.metadata();
        assert_eq!(zone_metadata.scope, TrapdoorScope::Child);
        assert_eq!(
            zone_metadata.parent_public_matrix_hash,
            Some(master_pub.hash)
        );
        assert_eq!(zone_metadata.public_matrix_hash, zone_pub.hash);
        let zone_json = serde_json::to_string(&zone_metadata).unwrap();
        let zone_back: TrapdoorRepresentationMetadata = serde_json::from_str(&zone_json).unwrap();
        assert_eq!(zone_back, zone_metadata);
    }

    #[test]
    fn trapdoor_metadata_validation_rejects_malformed_public_envelopes() {
        let p = LatticeParams::SMALL_TEST;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let (zone_pub, zone_trap) =
            delegate(&master_pub, &master_trap, [0x22; 32], ref_period(), p).unwrap();

        let mut wrong_version = master_trap.metadata();
        wrong_version.version = LATTICE_REPRESENTATION_VERSION + 1;
        let err = wrong_version.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "trapdoor_version",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut root_with_parent = master_trap.metadata();
        root_with_parent.parent_public_matrix_hash = Some(master_pub.hash);
        let err = root_with_parent.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "root_trapdoor",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut child_without_parent = zone_trap.metadata();
        child_without_parent.parent_public_matrix_hash = None;
        let err = child_without_parent.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "child_trapdoor",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut malformed_profile = zone_trap.metadata();
        malformed_profile.params.q = 1;
        let err = malformed_profile.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidParameter {
                    field: "q",
                    value: 1,
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut wrong_fixture_bucket = master_trap.metadata();
        wrong_fixture_bucket.secret_storage_len_bucket = SecretStorageLengthBucket::UpTo4KiB;
        let err = wrong_fixture_bucket.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "fixture_trapdoor_seed_bundle",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut empty_basis_bucket =
            MasterTrapdoor::from_basis_envelope(p, master_pub.hash, vec![0xAA])
                .unwrap()
                .metadata();
        empty_basis_bucket.secret_storage_len_bucket = SecretStorageLengthBucket::Empty;
        let err = empty_basis_bucket.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    ..
                }
            ),
            "got {err:?}"
        );

        let mut bad_tag = serde_json::to_value(master_trap.metadata()).unwrap();
        bad_tag["material_kind"] = serde_json::Value::String("ImaginaryTrapdoorRoute".to_owned());
        assert!(
            serde_json::from_value::<TrapdoorRepresentationMetadata>(bad_tag).is_err(),
            "unknown material route tags must fail deserialization"
        );

        assert_eq!(zone_pub.params, p, "fixture child public key still valid");
    }

    #[test]
    fn trapdoor_relation_summaries_are_redaction_safe() {
        let p = LatticeParams::SMALL_TEST;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let zone = [11u8; 32];
        let period = ref_period();
        let (zone_pub, zone_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();

        let root_summary = master_trap.relation_summary(&master_pub);
        assert_eq!(root_summary.result, TrapdoorRelationResult::FixtureOnly);
        assert_eq!(
            root_summary.norm_quality_bucket,
            TrapdoorNormQualityBucket::FixtureSeed
        );

        let child_summary = zone_trap.relation_summary(&zone_pub, &master_pub);
        assert_eq!(child_summary.result, TrapdoorRelationResult::FixtureOnly);
        assert_eq!(
            child_summary.norm_quality_bucket,
            TrapdoorNormQualityBucket::FixtureSeed
        );

        let summary_json = serde_json::to_string(&child_summary).unwrap();
        assert!(!summary_json.contains("secret_material"));
        assert!(!summary_json.contains("coeff"));
        assert!(!summary_json.contains("seed_bundle"));
    }

    #[test]
    fn trapdoor_relation_summaries_detect_public_metadata_mismatch() {
        let p = LatticeParams::SMALL_TEST;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let (zone_pub, zone_trap) =
            delegate(&master_pub, &master_trap, [0x33; 32], ref_period(), p).unwrap();

        let mut wrong_master_pub = master_pub.clone();
        wrong_master_pub.hash[0] ^= 0xFF;
        assert_eq!(
            master_trap.relation_summary(&wrong_master_pub).result,
            TrapdoorRelationResult::MetadataMismatch
        );

        let mut wrong_child_pub = zone_pub.clone();
        wrong_child_pub.hash[0] ^= 0xFF;
        assert_eq!(
            zone_trap
                .relation_summary(&wrong_child_pub, &master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );
        assert_eq!(
            zone_trap
                .relation_summary(&zone_pub, &wrong_master_pub)
                .result,
            TrapdoorRelationResult::MetadataMismatch
        );
    }

    #[test]
    fn basis_envelope_constructors_are_basis_capable_but_not_success_claims() {
        let p = LatticeParams::SMALL_TEST;
        let public_hash = [0x44; 32];
        let parent_hash = [0x55; 32];
        let root = MasterTrapdoor::from_basis_envelope(p, public_hash, vec![0xA5; 4096]).unwrap();
        let child =
            ZonePeriodTrapdoor::from_basis_envelope(p, parent_hash, [0x66; 32], vec![0x5A; 8192])
                .unwrap();

        assert_eq!(root.material_kind(), TrapdoorMaterialKind::BasisEnvelope);
        assert_eq!(
            root.secret_storage_len_bucket(),
            SecretStorageLengthBucket::UpTo4KiB
        );
        assert_eq!(
            child.secret_storage_len_bucket(),
            SecretStorageLengthBucket::UpTo64KiB
        );
        assert_eq!(root.encoded_len(), 4096);
        assert_eq!(child.encoded_len(), 8192);

        let public = MasterPublicKey {
            hash: public_hash,
            params: p,
        };
        let summary = root.relation_summary(&public);
        assert_eq!(summary.result, TrapdoorRelationResult::UnsupportedPrimitive);
        assert_eq!(
            summary.norm_quality_bucket,
            TrapdoorNormQualityBucket::Small
        );
    }

    #[test]
    fn malformed_trapdoor_secrets_are_rejected() {
        let p = LatticeParams::SMALL_TEST;
        let public_hash = [0x44; 32];

        let err =
            MasterTrapdoor::from_fixture_seed_bundle(p, public_hash, vec![0_u8; 95]).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "fixture_trapdoor_seed_bundle",
                    expected: 96,
                    got: 95
                }
            ),
            "got {err:?}"
        );

        let err = MasterTrapdoor::from_basis_envelope(p, public_hash, Vec::new()).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidTrapdoorSecret {
                    material: "basis_envelope",
                    ..
                }
            ),
            "got {err:?}"
        );

        let err = MasterTrapdoor::from_basis_envelope(
            p,
            public_hash,
            vec![0_u8; MAX_TRAPDOOR_SECRET_BYTES + 1],
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::RepresentationTooLarge {
                    material: "trapdoor_secret",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn zone_period_matrix_seed_is_deterministic_and_domain_separated() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let zone = [7u8; 32];
        let period = ref_period();

        let seed = zone_period_matrix_seed(&master_pub, &zone, period, p);
        assert_eq!(
            hex::encode(seed),
            "7fbac36f184f312452bf9a49cb8eca8b80d820079bfbeda16cc253448d23e3ea"
        );

        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        assert_eq!(zp_pub.hash, seed, "delegate exposes the public seed");
        assert_eq!(zp_trap.encoded_len(), 96);
        assert!(
            format!("{zp_trap:?}").contains("<redacted>"),
            "zone-period trapdoor debug output must redact material"
        );

        let different_zone_seed = zone_period_matrix_seed(&master_pub, &[8u8; 32], period, p);
        assert_ne!(seed, different_zone_seed, "zone id changes the seed");

        let shifted = DelegationPeriod {
            start_secs: period.start_secs + 1,
            end_secs: period.end_secs + 1,
        };
        let different_period_seed = zone_period_matrix_seed(&master_pub, &zone, shifted, p);
        assert_ne!(seed, different_period_seed, "period changes the seed");
    }

    #[test]
    fn delegate_rejects_param_mismatch() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let mut wrong = p;
        wrong.n = 256;
        let err = delegate(&master_pub, &master_trap, [0u8; 32], ref_period(), wrong).unwrap_err();
        assert!(
            matches!(err, LatticePqError::ParameterMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn delegate_rejects_invalid_period() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let bad = DelegationPeriod {
            start_secs: 5_000,
            end_secs: 5_000,
        };
        let err = delegate(&master_pub, &master_trap, [0u8; 32], bad, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidPeriod {
                    start_secs: 5_000,
                    end_secs: 5_000,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn full_pipeline_round_trip_terminates_at_not_implemented() {
        // TrapGen → Delegate → operation_hash → SamplePre → Verify
        // exercises every type and every cheap-check branch. The two
        // cryptographic primitives (sample_pre, verify) terminate at
        // NotImplemented so the test asserts the *contract*, not a fake
        // success.
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let zone = [42u8; 32];
        let period = ref_period();
        let (zp_pub, zp_trap) = delegate(&master_pub, &master_trap, zone, period, p).unwrap();
        let h = operation_hash(&zone, period, b"op:read.user.profile", b"principal:alice");

        let pre_err = sample_pre(&zp_pub, &zp_trap, h, p).unwrap_err();
        assert!(
            matches!(
                pre_err,
                LatticePqError::NotImplemented {
                    primitive: "sample_pre",
                    ..
                }
            ),
            "sample_pre stub must signal NotImplemented; got {pre_err:?}"
        );

        // Build a placeholder preimage so verify can run its cheap-check
        // path; verify itself must still terminate at NotImplemented.
        let placeholder_pre = LatticePreimage::fixture_zero(p).unwrap();
        let now = period.start_secs + 100;
        let v_err = verify(&zp_pub, h, &placeholder_pre, now, p).unwrap_err();
        assert!(
            matches!(
                v_err,
                LatticePqError::NotImplemented {
                    primitive: "verify",
                    ..
                }
            ),
            "verify stub must signal NotImplemented after cheap checks; got {v_err:?}"
        );
    }

    #[test]
    fn verify_rejects_outside_period_before_reaching_not_implemented() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let period = ref_period();
        let (zp_pub, _) = delegate(&master_pub, &master_trap, [0u8; 32], period, p).unwrap();
        let h = operation_hash(&[0u8; 32], period, b"op", b"princ");
        let placeholder_pre = LatticePreimage::fixture_zero(p).unwrap();

        // 999 is one second before the period opens.
        let err = verify(&zp_pub, h, &placeholder_pre, 999, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::OutsidePeriod {
                    now_secs: 999,
                    start_secs: 1_000,
                    end_secs: 2_000,
                }
            ),
            "got {err:?}"
        );

        // 2000 is the exclusive upper bound.
        let err = verify(&zp_pub, h, &placeholder_pre, 2_000, p).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::OutsidePeriod {
                    now_secs: 2_000,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_param_mismatch_before_reaching_not_implemented() {
        let p = LatticeParams::V4_REFERENCE;
        let (master_pub, master_trap) = trap_gen(p).unwrap();
        let (zp_pub, _) = delegate(&master_pub, &master_trap, [0u8; 32], ref_period(), p).unwrap();
        let h = operation_hash(&[0u8; 32], ref_period(), b"op", b"princ");
        let placeholder_pre = LatticePreimage::fixture_zero(p).unwrap();

        let mut wrong = p;
        wrong.q = 7919;
        let err = verify(&zp_pub, h, &placeholder_pre, 1_500, wrong).unwrap_err();
        assert!(
            matches!(err, LatticePqError::ParameterMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn operation_hash_is_deterministic_and_input_separated() {
        let zone = [1u8; 32];
        let p = ref_period();
        let h1 = operation_hash(&zone, p, b"op", b"principal");
        let h2 = operation_hash(&zone, p, b"op", b"principal");
        assert_eq!(h1, h2, "deterministic on identical inputs");

        let h_diff_op = operation_hash(&zone, p, b"op2", b"principal");
        assert_ne!(h1, h_diff_op, "different op → different hash");

        let h_diff_pri = operation_hash(&zone, p, b"op", b"principal2");
        assert_ne!(h1, h_diff_pri, "different principal → different hash");

        // Length-prefix domain separation: ("ab","cd") must NOT collide
        // with ("a","bcd") even though concatenation matches.
        let h_a = operation_hash(&zone, p, b"ab", b"cd");
        let h_b = operation_hash(&zone, p, b"a", b"bcd");
        assert_ne!(h_a, h_b, "length-prefix separation prevents splice");
    }

    #[test]
    fn operation_hash_rhs_expands_with_shake256_fixture() {
        let p = LatticeParams::V4_REFERENCE;
        let zone = [42u8; 32];
        let period = ref_period();
        let h = operation_hash(&zone, period, b"op:read.user.profile", b"principal:alice");
        assert_eq!(
            hex::encode(h.0),
            "375af0d88a424be189140204f0521bace77ef127291b14f609635265a7f7569e"
        );

        let rhs = expand_operation_hash_rhs(h, p);
        assert_eq!(
            rhs.len(),
            usize::try_from(p.n).expect("u32 lattice dimension fits in usize")
        );
        assert!(
            rhs.iter().all(|coeff| *coeff < p.q),
            "all coefficients must be reduced modulo q"
        );
        assert_eq!(
            &rhs[..8],
            &[
                988_739_933,
                1_627_499_036,
                20_657_642,
                332_982_869,
                4_070_681_389,
                1_380_482_524,
                3_733_962_268,
                4_263_286_768,
            ]
        );

        let different = expand_operation_hash_rhs(
            operation_hash(&zone, period, b"op:read.user.profile", b"principal:bob"),
            p,
        );
        assert_ne!(&rhs[..16], &different[..16], "principal changes the RHS");
    }

    #[test]
    fn public_key_representations_round_trip_through_json() {
        let params = LatticeParams::SMALL_TEST;
        let (master_pub, master_trap) = trap_gen(params).unwrap();
        let period = ref_period();
        let zone = [9_u8; 32];
        let (zone_pub, _zone_trap) =
            delegate(&master_pub, &master_trap, zone, period, params).unwrap();

        let master_json = serde_json::to_string(&master_pub).unwrap();
        let master_back: MasterPublicKey = serde_json::from_str(&master_json).unwrap();
        assert_eq!(master_back, master_pub);

        let zone_json = serde_json::to_string(&zone_pub).unwrap();
        let zone_back: ZonePeriodPublicKey = serde_json::from_str(&zone_json).unwrap();
        assert_eq!(zone_back, zone_pub);
        assert_eq!(zone_back.hash.len(), MATRIX_SEED_BYTES);
    }

    #[test]
    fn lattice_preimage_round_trips_through_json() {
        let params = LatticeParams::SMALL_TEST;
        let bytes = (0..params.preimage_encoded_bytes().unwrap())
            .map(|i| u8::try_from(i).expect("small profile fixture byte fits in u8"))
            .collect::<Vec<_>>();
        let pre = LatticePreimage::from_encoded_bytes(params, bytes).unwrap();
        let s = serde_json::to_string(&pre).unwrap();
        assert!(s.contains("\"bytes\":\""), "uses bytes field");
        let back: LatticePreimage = serde_json::from_str(&s).unwrap();
        assert_eq!(back, pre);
        assert_eq!(back.encoded_len(), params.preimage_encoded_bytes().unwrap());
        assert!(
            format!("{back:?}").contains("<redacted>"),
            "preimage debug output must redact bytes"
        );
    }

    #[test]
    fn lattice_preimage_rejects_malformed_profile_length() {
        let params = LatticeParams::SMALL_TEST;
        let err = LatticePreimage::from_encoded_bytes(params, vec![0_u8; 31]).unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidEncodingLength {
                    material: "preimage",
                    expected: 32,
                    got: 31
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn invalid_params_reject_before_allocation() {
        let mut params = LatticeParams::SMALL_TEST;
        params.q = 1;
        let err = params.validate().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::InvalidParameter {
                    field: "q",
                    value: 1,
                    ..
                }
            ),
            "got {err:?}"
        );

        params = LatticeParams::SMALL_TEST;
        params.n = 1;
        params.q = 2;
        params.m = 1_048_577;
        let err = params.representation_profile().unwrap_err();
        assert!(
            matches!(
                err,
                LatticePqError::RepresentationTooLarge {
                    material: "preimage",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn not_implemented_error_names_responsible_bead() {
        let err = LatticePqError::NotImplemented {
            primitive: "sample_pre",
            bead: "kyopb.1.3.1.1.4",
        };
        let msg = err.to_string();
        assert!(msg.contains("sample_pre"), "msg: {msg}");
        assert!(msg.contains("kyopb.1.3.1.1.4"), "msg: {msg}");
    }
}
