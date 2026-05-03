//! # FCP post-quantum cryptographic primitives — lattice-trapdoor delegation
//!
//! Stub implementation (br-kyopb.1.3.1) of the four lattice-trapdoor primitives
//! that back V4 capability delegation. The full design is documented in
//! `docs/post-quantum/lattice_trapdoor_delegation.md`.
//!
//! ## Status
//!
//! **All cryptographic operations are stubs.** This crate exists to pin the
//! API contract that:
//!
//! - `fcp_policy::lattice_delegation::LatticeDelegationVerifier` (br-kyopb.1.3.2)
//!   will implement against,
//! - the Lean 4 formal proof (br-kyopb.1.3.3) will model, and
//! - the throughput benchmark (br-kyopb.1.3.4) will measure.
//!
//! Calling any stub function returns `Err(LatticePqError::NotImplemented { ... })`
//! — the discriminant names the responsible follow-up bead. **Production code
//! MUST treat `NotImplemented` as "fall back to V3 (Ed25519) capability
//! verification" rather than as a hard failure.** See
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
//! Wire types ([`DelegationCertificate`], [`LatticeSubToken`]) are byte-bag
//! placeholders here; the canonical types live in
//! `fcp_policy::lattice_delegation` and are populated by br-kyopb.1.3.2 once
//! these primitives have real implementations.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Parameters ────────────────────────────────────────────────────────────

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
/// (≈30 KB at `V4_REFERENCE`); we expose only its 32-byte content-hash
/// so the public type is fixed-size and copy-friendly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterPublicKey {
    /// 32-byte BLAKE3 hash of the canonical encoding of `A_root`.
    pub hash: [u8; 32],
    /// Parameters this key was generated for.
    pub params: LatticeParams,
}

/// Master trapdoor `T_root` held offline by the owner.
///
/// **Stub:** the bytes here are placeholder; the real type will be the
/// Micciancio-Peikert gadget trapdoor. Wrapped in its own type so future
/// callers don't accidentally serialize it (and `Drop` can zeroize).
///
/// **Constant-time equality** (br-1zlht): the trapdoor IS the
/// load-bearing secret of the lattice-trapdoor scheme. Equality via
/// [`subtle::ConstantTimeEq`] not the derived `[u8; N]::eq`.
#[derive(Debug, Clone, Eq)]
pub struct MasterTrapdoor {
    /// Opaque trapdoor bytes. Length will be `O(n × log q × n)` in the
    /// real impl; here it's a fixed 32-byte placeholder.
    pub(crate) bytes: [u8; 32],
}

impl PartialEq for MasterTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

/// Per-`(zone, period)` public matrix `A_zp` returned by [`delegate`].
///
/// As with [`MasterPublicKey`], we carry a content-hash placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZonePeriodPublicKey {
    /// 32-byte BLAKE3 hash of the canonical encoding of `A_zp`.
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
///
/// **Constant-time equality** (br-1zlht): see [`MasterTrapdoor`].
#[derive(Debug, Clone, Eq)]
pub struct ZonePeriodTrapdoor {
    pub(crate) bytes: [u8; 32],
}

impl PartialEq for ZonePeriodTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

/// Hash of an operation context `H(zone | period | op | principal)`,
/// expanded into the verification equation's right-hand side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationHash(pub [u8; 32]);

/// Short lattice preimage `e` such that `A_zp · e ≡ h (mod q)`.
///
/// Real impl: a vector in `Z_q^m` with `‖e‖₂ ≤ B`. Here a fixed-size
/// 64-byte placeholder so the API surface is concrete.
///
/// **Constant-time equality** (br-1zlht): the preimage is the
/// signature material of the lattice-trapdoor scheme; equality via
/// [`subtle::ConstantTimeEq`].
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct LatticePreimage {
    /// Opaque preimage bytes.
    #[serde(with = "hex_array_64")]
    pub bytes: [u8; 64],
}

impl PartialEq for LatticePreimage {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

mod hex_array_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(arr)
    }
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

    /// Parameters mismatch between caller and key (e.g. trapdoor was
    /// generated for `n=512` but verification passed `n=1024` params).
    #[error("parameter mismatch: caller passed {caller:?}, key expects {key:?}")]
    ParameterMismatch {
        /// Caller-supplied params.
        caller: LatticeParams,
        /// Params bound into the key being used.
        key: LatticeParams,
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
/// **Stub:** returns deterministic byte placeholders derived from
/// `params` so call-sites have stable handles to thread, but the bytes
/// are NOT cryptographic material. `MasterPublicKey.hash` and
/// `MasterTrapdoor.bytes` are both `BLAKE3("trap_gen-stub-v0" || params)`
/// XOR'd with a tag — distinct, but reproducible.
///
/// # Errors
///
/// Currently always succeeds (it's a deterministic placeholder). The
/// real implementation may fail on entropy starvation; signature
/// remains `LatticePqResult` to preserve forward compatibility.
pub fn trap_gen(params: LatticeParams) -> LatticePqResult<(MasterPublicKey, MasterTrapdoor)> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"trap_gen-stub-v0|");
    hasher.update(&params.n.to_le_bytes());
    hasher.update(&params.q.to_le_bytes());
    hasher.update(&params.m.to_le_bytes());
    hasher.update(&params.sigma_x100.to_le_bytes());
    hasher.update(&[params.depth]);
    let seed = *hasher.finalize().as_bytes();

    let mut pub_hash = seed;
    pub_hash[0] ^= 0xA0;
    let mut trap_bytes = seed;
    trap_bytes[1] ^= 0xB1;

    Ok((
        MasterPublicKey {
            hash: pub_hash,
            params,
        },
        MasterTrapdoor { bytes: trap_bytes },
    ))
}

/// **Delegate** (§3.3 layer 1).
///
/// Real impl: Cash-Hofheinz-Kiltz-Peikert (Eurocrypt 2010) basis-
/// shortening — given the parent `(A_par, T_par)` and a `(zone, period)`
/// label, derive `(A_zp, T_zp)` for the child certificate.
///
/// **Stub:** binds `(zone_id, period)` into a deterministic placeholder
/// that matches the master key by content-hash chaining. Always
/// succeeds when `params` agree and `period` is well-ordered.
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
    if period.start_secs >= period.end_secs {
        return Err(LatticePqError::InvalidPeriod {
            start_secs: period.start_secs,
            end_secs: period.end_secs,
        });
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"delegate-stub-v0|");
    hasher.update(&parent_pub.hash);
    hasher.update(&parent_trap.bytes);
    hasher.update(&zone_id);
    hasher.update(&period.start_secs.to_le_bytes());
    hasher.update(&period.end_secs.to_le_bytes());
    let seed = *hasher.finalize().as_bytes();

    let mut pub_hash = seed;
    pub_hash[0] ^= 0xC2;
    let mut trap_bytes = seed;
    trap_bytes[0] ^= 0xD3;

    Ok((
        ZonePeriodPublicKey {
            hash: pub_hash,
            zone_id,
            period,
            params,
        },
        ZonePeriodTrapdoor { bytes: trap_bytes },
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
/// "kyopb.1.3.1" })`.
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
    _trap: &ZonePeriodTrapdoor,
    _h: OperationHash,
    params: LatticeParams,
) -> LatticePqResult<LatticePreimage> {
    if params != key.params {
        return Err(LatticePqError::ParameterMismatch {
            caller: params,
            key: key.params,
        });
    }
    Err(LatticePqError::NotImplemented {
        primitive: "sample_pre",
        bead: "kyopb.1.3.1",
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
/// "kyopb.1.3.1" })` for any positive case.
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
    if !key.period.contains(now_secs) {
        return Err(LatticePqError::OutsidePeriod {
            now_secs,
            start_secs: key.period.start_secs,
            end_secs: key.period.end_secs,
        });
    }
    Err(LatticePqError::NotImplemented {
        primitive: "verify",
        bead: "kyopb.1.3.1",
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
        let placeholder_pre = LatticePreimage { bytes: [0u8; 64] };
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
        let placeholder_pre = LatticePreimage { bytes: [0u8; 64] };

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
        let placeholder_pre = LatticePreimage { bytes: [0u8; 64] };

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
    fn lattice_preimage_round_trips_through_json() {
        let pre = LatticePreimage {
            bytes: {
                let mut b = [0u8; 64];
                for (i, byte) in b.iter_mut().enumerate() {
                    *byte = u8::try_from(i).expect("0..64 fits in u8");
                }
                b
            },
        };
        let s = serde_json::to_string(&pre).unwrap();
        // {"bytes":"<128 hex chars>"} = 10 + 128 + 2 = 140 chars
        assert_eq!(s.len(), 140, "JSON wrapper + hex-of-64-bytes");
        assert!(s.contains("\"bytes\":\""), "uses bytes field");
        let back: LatticePreimage = serde_json::from_str(&s).unwrap();
        assert_eq!(back, pre);
    }

    #[test]
    fn not_implemented_error_names_responsible_bead() {
        let err = LatticePqError::NotImplemented {
            primitive: "sample_pre",
            bead: "kyopb.1.3.1",
        };
        let msg = err.to_string();
        assert!(msg.contains("sample_pre"), "msg: {msg}");
        assert!(msg.contains("kyopb.1.3.1"), "msg: {msg}");
    }
}
