//! Hybrid classical plus post-quantum signed envelopes.
//!
//! This module is the shared FCP V4 signing surface for object families that
//! need to move from Ed25519-only authenticity to dual Ed25519 plus ML-DSA-65
//! authenticity without inventing policy logic at every call site.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{
    CryptoError, CryptoResult, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey,
    MlDsa65SignatureBytes, MlDsa65SigningKey, MlDsa65VerifyingKey,
};

/// Domain separator used by both Ed25519 and ML-DSA-65 hybrid envelope signing.
pub const HYBRID_SIGNING_CONTEXT: &[u8] = b"FCP-HYBRID-SIGNED-ENVELOPE-V1";

/// Verification policy for classical and post-quantum signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PqSigningPolicy {
    /// Require a valid Ed25519 signature and do not require an ML-DSA signature.
    ClassicalOnly,
    /// Require a valid ML-DSA-65 signature and do not require an Ed25519 signature.
    PqOnly,
    /// Accept a valid signature from either algorithm.
    EitherOk,
    /// Require valid signatures from both algorithms.
    BothRequired,
}

impl PqSigningPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClassicalOnly => "ClassicalOnly",
            Self::PqOnly => "PqOnly",
            Self::EitherOk => "EitherOk",
            Self::BothRequired => "BothRequired",
        }
    }

    const fn signs_classical(self, has_classical_signer: bool) -> bool {
        match self {
            Self::ClassicalOnly | Self::BothRequired => true,
            Self::PqOnly => false,
            Self::EitherOk => has_classical_signer,
        }
    }

    const fn signs_pq(self, has_pq_signer: bool) -> bool {
        match self {
            Self::PqOnly | Self::BothRequired => true,
            Self::ClassicalOnly => false,
            Self::EitherOk => has_pq_signer,
        }
    }
}

/// Payload plus optional classical and post-quantum signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct SignedEnvelope<T> {
    /// Stable object family name used in logs and conformance coverage.
    pub object_type: String,
    /// The signed payload.
    pub payload: T,
    /// Ed25519 signature over the caller-provided canonical signing bytes.
    pub sig_classical: Option<Ed25519Signature>,
    /// ML-DSA-65 signature over the caller-provided canonical signing bytes.
    pub sig_pq: Option<MlDsa65SignatureBytes>,
}

impl<T> SignedEnvelope<T> {
    /// Sign an envelope with both Ed25519 and ML-DSA-65 signatures.
    ///
    /// # Errors
    ///
    /// Returns an error if ML-DSA signing fails.
    pub fn sign(
        object_type: impl Into<String>,
        payload: T,
        signing_bytes: &[u8],
        classical_signer: &Ed25519SigningKey,
        pq_signer: &MlDsa65SigningKey,
    ) -> CryptoResult<Self> {
        Self::sign_with_policy(
            object_type,
            payload,
            signing_bytes,
            PqSigningPolicy::BothRequired,
            Some(classical_signer),
            Some(pq_signer),
        )
    }

    /// Sign an envelope according to the supplied migration policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy cannot be satisfied by the supplied
    /// signer set or if ML-DSA signing fails.
    pub fn sign_with_policy(
        object_type: impl Into<String>,
        payload: T,
        signing_bytes: &[u8],
        policy: PqSigningPolicy,
        classical_signer: Option<&Ed25519SigningKey>,
        pq_signer: Option<&MlDsa65SigningKey>,
    ) -> CryptoResult<Self> {
        let should_sign_classical = policy.signs_classical(classical_signer.is_some());
        let should_sign_pq = policy.signs_pq(pq_signer.is_some());

        if !should_sign_classical && !should_sign_pq {
            return Err(CryptoError::HybridPolicyViolation {
                policy: policy.as_str(),
                reason: "no signer was supplied".to_string(),
            });
        }

        let classical_signature = if should_sign_classical {
            Some(
                classical_signer
                    .ok_or(CryptoError::MissingClassicalSigner {
                        policy: policy.as_str(),
                    })?
                    .sign_with_context(HYBRID_SIGNING_CONTEXT, signing_bytes),
            )
        } else {
            None
        };

        let pq_signature = if should_sign_pq {
            Some(
                pq_signer
                    .ok_or(CryptoError::MissingPqSigner {
                        policy: policy.as_str(),
                    })?
                    .sign(signing_bytes, HYBRID_SIGNING_CONTEXT)?,
            )
        } else {
            None
        };

        Ok(Self {
            object_type: object_type.into(),
            payload,
            sig_classical: classical_signature,
            sig_pq: pq_signature,
        })
    }

    /// Verify an envelope under the default both-required policy.
    ///
    /// # Errors
    ///
    /// Returns an error if either signature is missing or fails verification.
    pub fn verify(
        &self,
        signing_bytes: &[u8],
        classical_verifier: &Ed25519VerifyingKey,
        pq_verifier: &MlDsa65VerifyingKey,
    ) -> CryptoResult<HybridVerifyReport> {
        self.verify_with_policy(
            signing_bytes,
            PqSigningPolicy::BothRequired,
            Some(classical_verifier),
            Some(pq_verifier),
        )
    }

    /// Verify an envelope under the supplied policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy cannot be satisfied by the present
    /// signatures and supplied verifier set, or if any checked signature fails.
    pub fn verify_with_policy(
        &self,
        signing_bytes: &[u8],
        policy: PqSigningPolicy,
        classical_verifier: Option<&Ed25519VerifyingKey>,
        pq_verifier: Option<&MlDsa65VerifyingKey>,
    ) -> CryptoResult<HybridVerifyReport> {
        let _verify_span = tracing::info_span!(
            "hybrid_signed_envelope_verify",
            object_type = %self.object_type,
            policy = ?policy,
        )
        .entered();
        let signatures_present = SignatureStatus {
            classical: self.sig_classical.is_some(),
            pq: self.sig_pq.is_some(),
        };

        if matches!(
            policy,
            PqSigningPolicy::ClassicalOnly | PqSigningPolicy::BothRequired
        ) && !signatures_present.classical
        {
            if matches!(policy, PqSigningPolicy::BothRequired) {
                self.log_downgrade_rejection(
                    policy,
                    signatures_present,
                    if signatures_present.pq {
                        "stripped_classical_signature"
                    } else {
                        "missing_classical_signature"
                    },
                );
            }
            self.log_verdict(
                policy,
                signatures_present,
                SignatureStatus::NONE,
                "rejected",
            );
            return Err(CryptoError::MissingClassicalSignature {
                policy: policy.as_str(),
            });
        }

        if matches!(
            policy,
            PqSigningPolicy::PqOnly | PqSigningPolicy::BothRequired
        ) && !signatures_present.pq
        {
            if matches!(policy, PqSigningPolicy::BothRequired) {
                self.log_downgrade_rejection(
                    policy,
                    signatures_present,
                    if signatures_present.classical {
                        "stripped_pq_signature"
                    } else {
                        "missing_pq_signature"
                    },
                );
            }
            self.log_verdict(
                policy,
                signatures_present,
                SignatureStatus::NONE,
                "rejected",
            );
            return Err(CryptoError::MissingPqSignature {
                policy: policy.as_str(),
            });
        }

        let valid_classical = self.verify_classical(signing_bytes, policy, classical_verifier)?;
        let valid_pq = self.verify_pq(signing_bytes, policy, pq_verifier)?;
        let signatures_verified = SignatureStatus {
            classical: valid_classical,
            pq: valid_pq,
        };
        let accepted = match policy {
            PqSigningPolicy::ClassicalOnly => signatures_verified.classical,
            PqSigningPolicy::PqOnly => signatures_verified.pq,
            PqSigningPolicy::EitherOk => signatures_verified.classical || signatures_verified.pq,
            PqSigningPolicy::BothRequired => {
                signatures_verified.classical && signatures_verified.pq
            }
        };

        if accepted {
            let warning = HybridVerifyWarning::for_policy(policy, signatures_present);
            if let Some(warning) = warning {
                self.log_transitional_warning(policy, signatures_present, warning);
            }
            self.log_verdict(policy, signatures_present, signatures_verified, "accepted");
            Ok(HybridVerifyReport {
                policy,
                signatures_present,
                signatures_verified,
                warning,
            })
        } else {
            self.log_verdict(policy, signatures_present, signatures_verified, "rejected");
            Err(CryptoError::HybridPolicyViolation {
                policy: policy.as_str(),
                reason: "no acceptable signature verified".to_string(),
            })
        }
    }

    fn verify_classical(
        &self,
        signing_bytes: &[u8],
        policy: PqSigningPolicy,
        verifier: Option<&Ed25519VerifyingKey>,
    ) -> CryptoResult<bool> {
        let Some(signature) = &self.sig_classical else {
            return Ok(false);
        };
        let Some(verifier) = verifier else {
            if matches!(
                policy,
                PqSigningPolicy::ClassicalOnly | PqSigningPolicy::BothRequired
            ) {
                return Err(CryptoError::MissingClassicalVerifier {
                    policy: policy.as_str(),
                });
            }
            return Ok(false);
        };

        let started = Instant::now();
        let result = verifier.verify_with_context(HYBRID_SIGNING_CONTEXT, signing_bytes, signature);
        let elapsed_us = started.elapsed().as_micros();
        tracing::debug!(
            object_type = %self.object_type,
            sig_kind = "ed25519",
            elapsed_us,
            verdict = if result.is_ok() { "accepted" } else { "rejected" },
            "hybrid signed envelope signature verification"
        );
        result.map(|()| true)
    }

    fn verify_pq(
        &self,
        signing_bytes: &[u8],
        policy: PqSigningPolicy,
        verifier: Option<&MlDsa65VerifyingKey>,
    ) -> CryptoResult<bool> {
        let Some(signature) = &self.sig_pq else {
            return Ok(false);
        };
        let Some(verifier) = verifier else {
            if matches!(
                policy,
                PqSigningPolicy::PqOnly | PqSigningPolicy::BothRequired
            ) {
                return Err(CryptoError::MissingPqVerifier {
                    policy: policy.as_str(),
                });
            }
            return Ok(false);
        };

        let started = Instant::now();
        let result = verifier.verify(signing_bytes, HYBRID_SIGNING_CONTEXT, signature);
        let elapsed_us = started.elapsed().as_micros();
        tracing::debug!(
            object_type = %self.object_type,
            sig_kind = "ml-dsa-65",
            elapsed_us,
            verdict = if result.is_ok() { "accepted" } else { "rejected" },
            "hybrid signed envelope signature verification"
        );
        result.map(|()| true)
    }

    fn log_verdict(
        &self,
        policy: PqSigningPolicy,
        signatures_present: SignatureStatus,
        signatures_verified: SignatureStatus,
        verdict: &'static str,
    ) {
        tracing::info!(
            object_type = %self.object_type,
            sig_kinds_present = signatures_present.label(),
            sig_kinds_verified = signatures_verified.label(),
            verdict,
            policy = ?policy,
            "hybrid signed envelope verification"
        );
    }

    fn log_downgrade_rejection(
        &self,
        policy: PqSigningPolicy,
        signatures_present: SignatureStatus,
        attempted_downgrade: &'static str,
    ) {
        tracing::info!(
            object_type = %self.object_type,
            attempted_downgrade,
            reason_code = "DowngradeAttempt",
            attacker_pubkey_fpr = "unknown",
            sig_kinds_present = signatures_present.label(),
            policy = ?policy,
            "hybrid signed envelope downgrade attack rejected"
        );
    }

    fn log_transitional_warning(
        &self,
        policy: PqSigningPolicy,
        signatures_present: SignatureStatus,
        warning: HybridVerifyWarning,
    ) {
        tracing::warn!(
            object_type = %self.object_type,
            reason_code = warning.reason_code,
            missing_signature_kind = warning.missing_signature_kind,
            sig_kinds_present = signatures_present.label(),
            policy = ?policy,
            "hybrid signed envelope transitional verification warning"
        );
    }
}

/// Signature-kind state for an envelope or verification report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureStatus {
    /// Ed25519 signature state.
    pub classical: bool,
    /// ML-DSA-65 signature state.
    pub pq: bool,
}

impl SignatureStatus {
    const NONE: Self = Self {
        classical: false,
        pq: false,
    };

    const fn label(self) -> &'static str {
        match (self.classical, self.pq) {
            (true, true) => "ed25519,ml-dsa-65",
            (true, false) => "ed25519",
            (false, true) => "ml-dsa-65",
            (false, false) => "none",
        }
    }
}

/// Warning returned for an envelope accepted under a transitional policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridVerifyWarning {
    /// Stable reason code for audit and conformance assertions.
    pub reason_code: &'static str,
    /// Signature kind absent from an otherwise accepted transitional envelope.
    pub missing_signature_kind: &'static str,
}

impl HybridVerifyWarning {
    const fn for_policy(
        policy: PqSigningPolicy,
        signatures_present: SignatureStatus,
    ) -> Option<Self> {
        if !matches!(policy, PqSigningPolicy::EitherOk) {
            return None;
        }

        match (signatures_present.classical, signatures_present.pq) {
            (true, false) => Some(Self {
                reason_code: "PqSignatureMismatch",
                missing_signature_kind: "ml-dsa-65",
            }),
            (false, true) => Some(Self {
                reason_code: "PqSignatureMismatch",
                missing_signature_kind: "ed25519",
            }),
            _ => None,
        }
    }
}

/// Verification details returned for accepted hybrid envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridVerifyReport {
    /// Policy used for the verification decision.
    pub policy: PqSigningPolicy,
    /// Signature kinds carried by the envelope.
    pub signatures_present: SignatureStatus,
    /// Signature kinds that verified successfully.
    pub signatures_verified: SignatureStatus,
    /// Transitional warning emitted while accepting an envelope with one signature.
    pub warning: Option<HybridVerifyWarning>,
}
