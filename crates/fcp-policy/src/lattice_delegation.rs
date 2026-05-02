//! Lattice-trapdoor capability delegation — stub trait surface (br-kyopb.1.3).
//!
//! This module is the **policy-layer abstraction** for the V4 lattice-
//! trapdoor capability scheme. The wire-format types, cryptographic
//! primitives (TrapGen / Delegate / SamplePre / Verify), and Lean 4
//! soundness proof live in separate sub-beads — see
//! `docs/post-quantum/lattice_trapdoor_delegation.md` §8 for the
//! 4-bead implementation roadmap (kyopb.1.3.1 through kyopb.1.3.4).
//!
//! ## Why the stub
//!
//! Other host-side code (admission gates, audit-event assembly, future
//! verification pipelines) will need to refer to the
//! [`LatticeDelegationVerifier`] trait by name long before a concrete
//! implementation exists. Landing the trait surface in this commit:
//!
//! 1. Pins the **API contract** the future cryptographic implementation
//!    must satisfy.
//! 2. Lets coordinating beads (audit denial events, dispatch wiring,
//!    enforcement-pipeline `EnforcementCheckId` additions) reference
//!    the trait without waiting for the months-long primitive work.
//! 3. Documents the operational shape (zone + period + op + principal
//!    quaternary binding) so other agents writing related code don't
//!    invent incompatible abstractions.
//!
//! ## Status
//!
//! **All trait methods are stubs** that return
//! [`LatticeDelegationError::NotImplemented`]. Calling code MUST treat
//! a `NotImplemented` return as "the V4 lattice path is not active on
//! this host yet — fall back to V3 ML-DSA" rather than as an
//! operational error. The compatibility ledger
//! (`docs/post-quantum/v3_v4_compatibility_ledger.md`) describes the
//! cross-version dispatch rules.
//!
//! ## Composition with the rest of the security chain
//!
//! At verification time, a [`LatticeDelegationVerifier`] runs in the
//! **same canonical pipeline slot** as the V3 capability-token
//! verifier (`EnforcementCheckId::CapabilityVerify`) — they are
//! mutually exclusive per-token (a token is either V3-CWT or
//! V4-lattice, never both, distinguished by an envelope tag). A V4
//! token that passes [`verify_sub_token`] still flows through the
//! downstream checks (DeploymentTier, RevocationCascade,
//! CapabilityConstraints, etc.) just like a V3 token would.
//!
//! See bead `flywheel_connectors-kyopb.1.3` and the full design at
//! `docs/post-quantum/lattice_trapdoor_delegation.md`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use fcp_core::{OperationId, PrincipalId, ZoneId};

/// Inclusive Unix-millisecond time window during which a
/// [`DelegationCertificate`] is valid (br-kyopb.1.3 §3.4).
///
/// Verifiers MUST reject sub-tokens whose certificate's window does
/// not contain `now()`. The window is part of the signed delegation
/// transcript so a rogue issuance node cannot extend an expired
/// certificate's validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPeriod {
    /// Inclusive start (Unix ms).
    pub start_unix_ms: u64,
    /// Inclusive end (Unix ms).
    pub end_unix_ms: u64,
}

impl DelegationPeriod {
    /// Whether the period contains the supplied wall-clock time.
    #[must_use]
    pub const fn contains(&self, now_unix_ms: u64) -> bool {
        self.start_unix_ms <= now_unix_ms && now_unix_ms <= self.end_unix_ms
    }
}

/// Opaque content-addressed identifier for a [`DelegationCertificate`].
///
/// Computed via BLAKE3 over the certificate's canonical encoding —
/// schema TBD in kyopb.1.3.1. Audit consumers index DelegationReceipts
/// by this id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DelegationCertificateId(#[serde(with = "fcp_core::util::hex_or_bytes")] pub [u8; 32]);

impl DelegationCertificateId {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase-hex rendering.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Public material of one node in the lattice-trapdoor delegation
/// tree (br-kyopb.1.3 §3.3 layer 1 or layer 2).
///
/// Concrete type is opaque pending kyopb.1.3.1 (the cryptographic
/// crate scaffolding bead). Holds:
///
/// - `cert_id` — content-addressed identifier
/// - `zone_id` — the zone this delegation authorizes for
/// - `period` — the time window this delegation is valid for
/// - `parent_cert_id` — `None` for root, `Some(...)` for layers 1+
/// - `pub_matrix_seed` — 32-byte seed; concrete `A_zp` matrix is
///   derived via SHAKE256 to keep certificate bytes small
///
/// The trapdoor itself (`T_zp`) is held offline by the issuance
/// node and NEVER appears in this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationCertificate {
    /// Content-addressed identifier.
    pub cert_id: DelegationCertificateId,
    /// Zone this certificate authorizes minting for.
    pub zone_id: ZoneId,
    /// Time window the certificate is valid in.
    pub period: DelegationPeriod,
    /// Parent certificate this one was derived from. `None` only for
    /// the root certificate (the master trapdoor's public companion).
    pub parent_cert_id: Option<DelegationCertificateId>,
    /// 32-byte seed for the per-certificate public matrix `A_zp`.
    /// Verifiers expand to the full matrix via SHAKE256 — saves
    /// ~32 KB per certificate on the wire.
    #[serde(with = "fcp_core::util::hex_or_bytes")]
    pub pub_matrix_seed: [u8; 32],
}

/// Layer-3 sub-token (br-kyopb.1.3 §3.3) — what a client carries on
/// each invocation. Wire format is a content-addressed compact
/// envelope; the concrete bytes layout is TBD in kyopb.1.3.1.
///
/// Holds:
///
/// - `cert_id` — which certificate's trapdoor minted this sub-token
/// - `op_id` + `principal_id` — the operation + principal this token
///   binds to (encoded into the verification matrix `A_op`)
/// - `request_descriptor_hash` — what the short-vector pre-image
///   solves (binds the token to one specific request)
/// - `preimage` — the short vector `s` such that `A_op · s = c mod q`
///
/// All four fields are part of the verification computation; mutating
/// any of them invalidates the token under [`verify_sub_token`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeSubToken {
    /// Certificate id this sub-token chains to.
    pub cert_id: DelegationCertificateId,
    /// Operation the token authorizes.
    pub op_id: OperationId,
    /// Principal the token is bound to.
    pub principal_id: PrincipalId,
    /// 32-byte request-descriptor hash (BLAKE3-keyed over the
    /// canonical request descriptor — same shape as
    /// `RequestDescriptorHash` in `fcp-evidence`).
    #[serde(with = "fcp_core::util::hex_or_bytes")]
    pub request_descriptor_hash: [u8; 32],
    /// Compact-encoded short-vector pre-image. Concrete encoding
    /// TBD in kyopb.1.3.1.
    pub preimage_bytes: Vec<u8>,
}

/// Outcome of [`LatticeDelegationVerifier::verify_sub_token`] on
/// success. A separate type from `()` so future audit consumers can
/// carry the reconstructed verification context (matrix dimensions,
/// detected delegation depth, period observed at verify time) without
/// changing the trait return type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatticeVerificationReceipt {
    /// Certificate id the verifier reconstructed `A_op` from.
    pub cert_id: DelegationCertificateId,
    /// Period the verifier observed at verification time. Useful for
    /// audit consumers that want to log "token was valid at
    /// `verified_at_unix_ms` because `period.contains(verified_at)`."
    pub period: DelegationPeriod,
    /// Wall-clock time at verification (Unix ms).
    pub verified_at_unix_ms: u64,
}

/// Errors returned by [`LatticeDelegationVerifier`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LatticeDelegationError {
    /// Trait method has no concrete implementation yet. Callers MUST
    /// treat this as "fall back to V3 ML-DSA path" — it is NOT an
    /// operational failure. See module docs.
    #[error("lattice-trapdoor delegation not yet implemented (kyopb.1.3.1-1.3.4 pending)")]
    NotImplemented,
    /// Sub-token references a certificate the verifier does not hold.
    #[error("delegation certificate {cert_id} not in trust set")]
    UnknownCertificate { cert_id: String },
    /// Sub-token's certificate window does not contain `now()`.
    #[error(
        "sub-token outside delegation period: now {now_unix_ms} not in [{start_unix_ms}, {end_unix_ms}]"
    )]
    OutsidePeriod {
        now_unix_ms: u64,
        start_unix_ms: u64,
        end_unix_ms: u64,
    },
    /// Matrix-vector verification failed: `A_op · s ≠ c mod q`.
    #[error("lattice verification equation failed for cert {cert_id}")]
    VerificationEquationFailed { cert_id: String },
    /// Pre-image norm exceeds the short-vector bound. A long
    /// pre-image proves the signer did NOT hold a trapdoor (anyone
    /// can find a long pre-image; only trapdoor-holders find short
    /// ones). Same security property the soundness theorem rests on.
    #[error("pre-image norm exceeds short-vector bound for cert {cert_id}")]
    PreimageTooLong { cert_id: String },
    /// Zone-id mismatch between sub-token's certificate and the
    /// request's zone — the certificate was minted for a different
    /// zone than the token is being used in.
    #[error(
        "zone mismatch: certificate zone {cert_zone} does not match request zone {request_zone}"
    )]
    ZoneMismatch {
        cert_zone: String,
        request_zone: String,
    },
    /// Certificate's parent chain references a cert not in the trust
    /// set — the delegation tree is incomplete relative to the
    /// verifier's view.
    #[error("delegation chain incomplete: missing parent for cert {cert_id}")]
    IncompleteDelegationChain { cert_id: String },
}

/// The policy-layer abstraction over lattice-trapdoor capability
/// verification (br-kyopb.1.3).
///
/// Concrete implementations live in `fcp-crypto-pq` (TBD in
/// kyopb.1.3.2). The trait is exposed here in fcp-policy because
/// capability-token verification is a policy concern (not a crypto
/// concern) — the crypto layer provides primitives; the policy layer
/// composes them with the rest of the enforcement chain.
///
/// Implementations MUST be `Send + Sync` so a single verifier can
/// serve concurrent dispatcher requests across the host's worker
/// threads.
pub trait LatticeDelegationVerifier: Send + Sync {
    /// Verify a [`LatticeSubToken`] against the verifier's
    /// trust set of [`DelegationCertificate`]s and the supplied
    /// `now_unix_ms` wall-clock time.
    ///
    /// On success, returns a [`LatticeVerificationReceipt`] that
    /// downstream audit consumers can attach to the per-request
    /// audit event.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`LatticeDelegationError`] variant on
    /// any verification failure. STUB IMPLEMENTATIONS MUST RETURN
    /// `NotImplemented`; CALLERS MUST treat that variant as "fall
    /// back to V3 ML-DSA," NOT as an operational failure.
    fn verify_sub_token(
        &self,
        sub_token: &LatticeSubToken,
        request_zone: &ZoneId,
        now_unix_ms: u64,
    ) -> Result<LatticeVerificationReceipt, LatticeDelegationError>;

    /// Whether this verifier holds a trust-set entry for the named
    /// certificate id.
    ///
    /// Stub implementations return `false`.
    fn has_certificate(&self, cert_id: &DelegationCertificateId) -> bool;
}

/// Stub implementation that always returns
/// [`LatticeDelegationError::NotImplemented`]. The default
/// production verifier until kyopb.1.3.2 lands a real one.
///
/// Hosts that want V4 lattice support today MUST replace this with a
/// concrete implementation (which doesn't exist yet — the design
/// doc and stub trait land in kyopb.1.3; the crypto crate scaffolding
/// is kyopb.1.3.1; the trait wiring is kyopb.1.3.2).
#[derive(Debug, Default, Clone, Copy)]
pub struct UnimplementedLatticeDelegationVerifier;

impl LatticeDelegationVerifier for UnimplementedLatticeDelegationVerifier {
    fn verify_sub_token(
        &self,
        _sub_token: &LatticeSubToken,
        _request_zone: &ZoneId,
        _now_unix_ms: u64,
    ) -> Result<LatticeVerificationReceipt, LatticeDelegationError> {
        Err(LatticeDelegationError::NotImplemented)
    }

    fn has_certificate(&self, _cert_id: &DelegationCertificateId) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_id(byte: u8) -> DelegationCertificateId {
        DelegationCertificateId::from_bytes([byte; 32])
    }

    fn period(start: u64, end: u64) -> DelegationPeriod {
        DelegationPeriod {
            start_unix_ms: start,
            end_unix_ms: end,
        }
    }

    fn sub_token(cert_id_byte: u8) -> LatticeSubToken {
        LatticeSubToken {
            cert_id: cert_id(cert_id_byte),
            op_id: OperationId::new("op.test").unwrap(),
            principal_id: PrincipalId::new("user:test").unwrap(),
            request_descriptor_hash: [0_u8; 32],
            preimage_bytes: vec![0_u8; 8],
        }
    }

    #[test]
    fn delegation_period_contains_at_boundaries() {
        let p = period(100, 200);
        assert!(p.contains(100), "lower boundary inclusive");
        assert!(p.contains(150), "interior");
        assert!(p.contains(200), "upper boundary inclusive");
        assert!(!p.contains(99), "below lower");
        assert!(!p.contains(201), "above upper");
    }

    #[test]
    fn delegation_certificate_id_round_trips_through_serde() {
        let id = cert_id(0xAB);
        let json = serde_json::to_string(&id).unwrap();
        let back: DelegationCertificateId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn delegation_certificate_id_to_hex_is_lowercase() {
        let id = cert_id(0xAB);
        let hex = id.to_hex();
        assert_eq!(hex, "ab".repeat(32));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn unimplemented_verifier_returns_not_implemented_for_verify() {
        let verifier = UnimplementedLatticeDelegationVerifier;
        let token = sub_token(0x01);
        let zone = ZoneId::work();
        let err = verifier
            .verify_sub_token(&token, &zone, 1_700_000_000_000)
            .expect_err("stub verifier MUST return NotImplemented");
        assert_eq!(err, LatticeDelegationError::NotImplemented);
    }

    #[test]
    fn unimplemented_verifier_has_no_certificates() {
        let verifier = UnimplementedLatticeDelegationVerifier;
        for byte in 0_u8..16 {
            assert!(
                !verifier.has_certificate(&cert_id(byte)),
                "stub verifier MUST hold zero certificates"
            );
        }
    }

    #[test]
    fn lattice_delegation_error_variants_round_trip_through_display() {
        // Pin the operator-readable Display strings for each variant —
        // operators reading audit logs / error responses depend on
        // these messages staying recognizable.
        let cases = [
            (
                LatticeDelegationError::NotImplemented,
                "not yet implemented",
            ),
            (
                LatticeDelegationError::UnknownCertificate {
                    cert_id: "deadbeef".to_string(),
                },
                "not in trust set",
            ),
            (
                LatticeDelegationError::OutsidePeriod {
                    now_unix_ms: 100,
                    start_unix_ms: 200,
                    end_unix_ms: 300,
                },
                "outside delegation period",
            ),
            (
                LatticeDelegationError::VerificationEquationFailed {
                    cert_id: "deadbeef".to_string(),
                },
                "verification equation failed",
            ),
            (
                LatticeDelegationError::PreimageTooLong {
                    cert_id: "deadbeef".to_string(),
                },
                "norm exceeds",
            ),
            (
                LatticeDelegationError::ZoneMismatch {
                    cert_zone: "z:work".to_string(),
                    request_zone: "z:public".to_string(),
                },
                "zone mismatch",
            ),
            (
                LatticeDelegationError::IncompleteDelegationChain {
                    cert_id: "deadbeef".to_string(),
                },
                "delegation chain incomplete",
            ),
        ];
        for (err, expected_substring) in cases {
            let s = err.to_string();
            assert!(
                s.contains(expected_substring),
                "Display for {err:?} should contain {expected_substring:?}, got {s:?}"
            );
        }
    }

    #[test]
    fn lattice_sub_token_round_trips_through_json() {
        // Wire-format pin: while the concrete bytes layout for
        // `preimage_bytes` is TBD in kyopb.1.3.1, the JSON envelope
        // shape MUST be stable across the design-doc → implementation
        // transition so audit consumers can already key off it.
        let token = sub_token(0x42);
        let json = serde_json::to_string(&token).unwrap();
        let back: LatticeSubToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, back);
    }
}
