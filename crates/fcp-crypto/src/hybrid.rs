//! Hybrid Ed25519 + ML-DSA-65 signed payload envelopes.
//!
//! This module is the generic crypto-layer surface for the post-quantum
//! signing cutover. It intentionally signs canonical payload bytes plus a
//! stable object-kind discriminator so signatures cannot be replayed across
//! capability, audit, manifest, gossip, revocation, receipt, and checkpoint
//! object families.

use serde::{Deserialize, Serialize};

use crate::{
    CryptoError, CryptoResult, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, KeyId,
    MlDsa65SignatureBytes, MlDsa65SigningKey, MlDsa65VerifyingKey,
};

/// Domain separator for hybrid signed envelopes.
pub const HYBRID_SIGNED_ENVELOPE_DOMAIN: &[u8] = b"FCP-HYBRID-SIGNED-ENVELOPE-V1";

/// Post-quantum signing policy for a hybrid envelope verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PqSigningPolicy {
    /// Accept only the classical Ed25519 signature.
    ClassicalOnly,
    /// Accept only the ML-DSA-65 signature.
    PqOnly,
    /// Transitional mode: either signature may satisfy verification.
    EitherOk,
    /// Steady-state mode: both signatures must be present and valid.
    BothRequired,
}

/// Signed object family bound into the hybrid signing transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HybridSignedObjectKind {
    /// FCP capability token.
    CapabilityToken,
    /// Audit-chain event.
    AuditEvent,
    /// Connector or package manifest.
    Manifest,
    /// Mesh gossip frame or summary.
    GossipFrame,
    /// Revocation object, event, or head.
    Revocation,
    /// Operation receipt.
    OperationReceipt,
    /// Zone checkpoint.
    ZoneCheckpoint,
}

impl HybridSignedObjectKind {
    /// Stable string written into signing transcripts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityToken => "capability-token",
            Self::AuditEvent => "audit-event",
            Self::Manifest => "manifest",
            Self::GossipFrame => "gossip-frame",
            Self::Revocation => "revocation",
            Self::OperationReceipt => "operation-receipt",
            Self::ZoneCheckpoint => "zone-checkpoint",
        }
    }

    /// All object kinds covered by the Phase N.1 hybrid signing gate.
    pub const ALL: [Self; 7] = [
        Self::CapabilityToken,
        Self::AuditEvent,
        Self::Manifest,
        Self::GossipFrame,
        Self::Revocation,
        Self::OperationReceipt,
        Self::ZoneCheckpoint,
    ];
}

/// Verification summary for one hybrid envelope check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridEnvelopeVerification {
    /// Object family verified.
    pub object_type: HybridSignedObjectKind,
    /// Effective verifier policy.
    pub policy: PqSigningPolicy,
    /// Signature kinds present on the envelope.
    pub sig_kinds_present: Vec<&'static str>,
    /// Signature kinds that were cryptographically verified.
    pub sig_kinds_verified: Vec<&'static str>,
    /// Transitional-policy warnings emitted while accepting the envelope.
    pub warnings: Vec<HybridDowngradeWarning>,
}

/// Redaction-safe warning emitted when transitional policy accepts a
/// single-signature envelope that steady-state policy would reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridDowngradeWarning {
    /// Object family being verified.
    pub object_type: HybridSignedObjectKind,
    /// Effective verifier policy.
    pub policy: PqSigningPolicy,
    /// Machine-readable downgrade or mismatch reason.
    pub reason_code: &'static str,
    /// Stable label for the accepted downgrade shape.
    pub attempted_downgrade: &'static str,
    /// Redaction-safe signing key fingerprint.
    pub attacker_pubkey_fpr: String,
}

/// Hardware-token authorization hook for emergency PQ-policy downgrade.
pub trait PqPolicyDowngradeAuthorizer {
    /// Stable, redaction-safe operator key fingerprint for audit.
    fn operator_fingerprint(&self) -> &str;

    /// Authorize a policy downgrade.
    ///
    /// # Errors
    ///
    /// Returns a crypto error when the hardware-token assertion is absent,
    /// expired, or does not authorize this exact downgrade reason.
    fn authorize_pq_policy_downgrade(
        &self,
        from: PqSigningPolicy,
        to: PqSigningPolicy,
        reason: &str,
    ) -> CryptoResult<()>;
}

/// Audit payload emitted when an operator downgrades PQ verification policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPolicyDowngradeAudit {
    /// Machine-readable audit event type.
    pub event_type: String,
    /// Policy in force before the downgrade.
    pub previous_policy: PqSigningPolicy,
    /// New transitional policy.
    pub new_policy: PqSigningPolicy,
    /// Redaction-safe hardware-token/operator fingerprint.
    pub operator_fingerprint: String,
    /// Operator-supplied reason for the downgrade.
    pub reason: String,
}

/// Audit event type for hybrid signing policy downgrade.
pub const EVENT_PQ_POLICY_DOWNGRADE: &str = "crypto.pq_policy_downgrade";

/// Generic hybrid signed payload envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEnvelope<T> {
    /// Object family whose transcript is signed.
    pub object_type: HybridSignedObjectKind,
    /// Payload carried by this envelope.
    pub payload: T,
    /// Ed25519 signing key identifier, when a classical signature is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classical_kid: Option<KeyId>,
    /// ML-DSA-65 signing key identifier, when a PQ signature is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_kid: Option<KeyId>,
    /// Classical Ed25519 signature over the hybrid transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_classical: Option<Ed25519Signature>,
    /// Post-quantum ML-DSA-65 signature over the hybrid transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_pq: Option<MlDsa65SignatureBytes>,
}

impl<T> SignedEnvelope<T> {
    /// Construct an unsigned envelope. Primarily useful for negative tests and
    /// staged migration code that fills signatures separately.
    #[must_use]
    pub const fn unsigned(object_type: HybridSignedObjectKind, payload: T) -> Self {
        Self {
            object_type,
            payload,
            classical_kid: None,
            pq_kid: None,
            sig_classical: None,
            sig_pq: None,
        }
    }

    /// Borrow the enclosed payload.
    #[must_use]
    pub const fn payload(&self) -> &T {
        &self.payload
    }
}

/// Object payload that has been migrated to the hybrid signing envelope.
pub trait HybridSignable: Serialize + Sized {
    /// Object family bound into the hybrid transcript.
    const OBJECT_KIND: HybridSignedObjectKind;

    /// Build the signed transcript for this payload.
    ///
    /// Implementors that still carry a legacy signature field should override
    /// this and normalize that field out before canonicalization.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization error if payload canonicalization fails.
    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        signing_bytes_for_payload(Self::OBJECT_KIND, self)
    }

    /// Sign this payload with both Ed25519 and ML-DSA-65.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization/signing error if payload canonicalization
    /// or the ML-DSA signing operation fails.
    fn sign_hybrid(
        self,
        classical_key: &Ed25519SigningKey,
        pq_key: &MlDsa65SigningKey,
    ) -> CryptoResult<SignedEnvelope<Self>> {
        let signing_bytes = self.hybrid_signing_bytes()?;
        SignedEnvelope::sign_with_signing_bytes(
            Self::OBJECT_KIND,
            self,
            &signing_bytes,
            classical_key,
            pq_key,
        )
    }

    /// Sign this payload with only Ed25519 for transitional rollouts.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization error if payload canonicalization fails.
    fn sign_hybrid_classical_only(
        self,
        classical_key: &Ed25519SigningKey,
    ) -> CryptoResult<SignedEnvelope<Self>> {
        let signing_bytes = self.hybrid_signing_bytes()?;
        Ok(SignedEnvelope::sign_classical_only_with_signing_bytes(
            Self::OBJECT_KIND,
            self,
            &signing_bytes,
            classical_key,
        ))
    }

    /// Sign this payload with only ML-DSA-65.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization/signing error if payload canonicalization
    /// or the ML-DSA signing operation fails.
    fn sign_hybrid_pq_only(self, pq_key: &MlDsa65SigningKey) -> CryptoResult<SignedEnvelope<Self>> {
        let signing_bytes = self.hybrid_signing_bytes()?;
        SignedEnvelope::sign_pq_only_with_signing_bytes(
            Self::OBJECT_KIND,
            self,
            &signing_bytes,
            pq_key,
        )
    }
}

impl<T> SignedEnvelope<T>
where
    T: HybridSignable,
{
    /// Verify the envelope with the payload type's hybrid signing transcript.
    ///
    /// This is the migrated call-site verifier. It lets legacy structs
    /// normalize embedded signature fields out before verification.
    ///
    /// # Errors
    ///
    /// Returns a crypto error when the object kind does not match the payload
    /// type, payload transcript construction fails, or signature verification
    /// fails under `policy`.
    pub fn verify_signable(
        &self,
        classical_key: &Ed25519VerifyingKey,
        pq_key: &MlDsa65VerifyingKey,
        policy: PqSigningPolicy,
    ) -> CryptoResult<HybridEnvelopeVerification> {
        if self.object_type != T::OBJECT_KIND {
            return Err(CryptoError::HeaderPolicyViolation(format!(
                "hybrid envelope object kind mismatch: expected {}, got {}",
                T::OBJECT_KIND.as_str(),
                self.object_type.as_str()
            )));
        }
        let signing_bytes = self.payload.hybrid_signing_bytes()?;
        self.verify_with_signing_bytes(classical_key, pq_key, policy, &signing_bytes)
    }
}

impl<T> SignedEnvelope<T>
where
    T: Serialize,
{
    /// Sign with both Ed25519 and ML-DSA-65.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization/signing error if payload canonicalization
    /// or the ML-DSA signing operation fails.
    pub fn sign(
        object_type: HybridSignedObjectKind,
        payload: T,
        classical_key: &Ed25519SigningKey,
        pq_key: &MlDsa65SigningKey,
    ) -> CryptoResult<Self> {
        let signing_bytes = signing_bytes_for_payload(object_type, &payload)?;
        Self::sign_with_signing_bytes(object_type, payload, &signing_bytes, classical_key, pq_key)
    }

    fn sign_with_signing_bytes(
        object_type: HybridSignedObjectKind,
        payload: T,
        signing_bytes: &[u8],
        classical_key: &Ed25519SigningKey,
        pq_key: &MlDsa65SigningKey,
    ) -> CryptoResult<Self> {
        Ok(Self {
            object_type,
            payload,
            classical_kid: Some(classical_key.key_id()),
            pq_kid: Some(pq_key.verifying_key().key_id()),
            sig_classical: Some(
                classical_key.sign_with_context(HYBRID_SIGNED_ENVELOPE_DOMAIN, signing_bytes),
            ),
            sig_pq: Some(pq_key.sign(signing_bytes, HYBRID_SIGNED_ENVELOPE_DOMAIN)?),
        })
    }

    /// Sign with only Ed25519 for transitional compatibility.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization error if payload canonicalization fails.
    pub fn sign_classical_only(
        object_type: HybridSignedObjectKind,
        payload: T,
        classical_key: &Ed25519SigningKey,
    ) -> CryptoResult<Self> {
        let signing_bytes = signing_bytes_for_payload(object_type, &payload)?;
        Ok(Self::sign_classical_only_with_signing_bytes(
            object_type,
            payload,
            &signing_bytes,
            classical_key,
        ))
    }

    fn sign_classical_only_with_signing_bytes(
        object_type: HybridSignedObjectKind,
        payload: T,
        signing_bytes: &[u8],
        classical_key: &Ed25519SigningKey,
    ) -> Self {
        Self {
            object_type,
            payload,
            classical_kid: Some(classical_key.key_id()),
            pq_kid: None,
            sig_classical: Some(
                classical_key.sign_with_context(HYBRID_SIGNED_ENVELOPE_DOMAIN, signing_bytes),
            ),
            sig_pq: None,
        }
    }

    /// Sign with only ML-DSA-65.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization/signing error if payload canonicalization
    /// or the ML-DSA signing operation fails.
    pub fn sign_pq_only(
        object_type: HybridSignedObjectKind,
        payload: T,
        pq_key: &MlDsa65SigningKey,
    ) -> CryptoResult<Self> {
        let signing_bytes = signing_bytes_for_payload(object_type, &payload)?;
        Self::sign_pq_only_with_signing_bytes(object_type, payload, &signing_bytes, pq_key)
    }

    fn sign_pq_only_with_signing_bytes(
        object_type: HybridSignedObjectKind,
        payload: T,
        signing_bytes: &[u8],
        pq_key: &MlDsa65SigningKey,
    ) -> CryptoResult<Self> {
        Ok(Self {
            object_type,
            payload,
            classical_kid: None,
            pq_kid: Some(pq_key.verifying_key().key_id()),
            sig_classical: None,
            sig_pq: Some(pq_key.sign(signing_bytes, HYBRID_SIGNED_ENVELOPE_DOMAIN)?),
        })
    }

    /// Verify the envelope under `policy`.
    ///
    /// # Errors
    ///
    /// Returns a policy-specific missing signature error when the envelope does
    /// not carry the required signature kind, or a signature verification error
    /// when a required signature is present but invalid.
    pub fn verify(
        &self,
        classical_key: &Ed25519VerifyingKey,
        pq_key: &MlDsa65VerifyingKey,
        policy: PqSigningPolicy,
    ) -> CryptoResult<HybridEnvelopeVerification> {
        let signing_bytes = signing_bytes_for_payload(self.object_type, &self.payload)?;
        self.verify_with_signing_bytes(classical_key, pq_key, policy, &signing_bytes)
    }

    fn verify_with_signing_bytes(
        &self,
        classical_key: &Ed25519VerifyingKey,
        pq_key: &MlDsa65VerifyingKey,
        policy: PqSigningPolicy,
        signing_bytes: &[u8],
    ) -> CryptoResult<HybridEnvelopeVerification> {
        let verify_start = std::time::Instant::now();
        let present = self.sig_kinds_present();
        let mut verified = Vec::new();
        let mut warnings = Vec::new();
        let span = tracing::info_span!(
            "fcp.crypto.verify",
            object_type = self.object_type.as_str(),
            sig_kinds = tracing::field::Empty,
            latency_us = tracing::field::Empty,
            downgrade_attempt = tracing::field::Empty,
        );
        let _span_guard = span.enter();

        match policy {
            PqSigningPolicy::ClassicalOnly => {
                self.verify_classical(classical_key, signing_bytes)?;
                verified.push("ed25519");
            }
            PqSigningPolicy::PqOnly => {
                self.verify_pq(pq_key, signing_bytes)?;
                verified.push("ml-dsa-65");
            }
            PqSigningPolicy::EitherOk => {
                if self.verify_classical(classical_key, signing_bytes).is_ok() {
                    verified.push("ed25519");
                    if self.sig_pq.is_none() {
                        let warning = self.transitional_warning(
                            policy,
                            "PqSignatureMismatch",
                            "pq-signature-absent-under-either-ok",
                            key_fingerprint("ed25519", &classical_key.key_id()),
                        );
                        self.log_transitional_warning(&warning);
                        warnings.push(warning);
                    }
                } else if self.verify_pq(pq_key, signing_bytes).is_ok() {
                    verified.push("ml-dsa-65");
                    if self.sig_classical.is_none() {
                        let warning = self.transitional_warning(
                            policy,
                            "ClassicalSignatureMismatch",
                            "classical-signature-absent-under-either-ok",
                            key_fingerprint("ml-dsa-65", &pq_key.key_id()),
                        );
                        self.log_transitional_warning(&warning);
                        warnings.push(warning);
                    }
                } else {
                    return Err(CryptoError::SignatureVerificationFailed);
                }
            }
            PqSigningPolicy::BothRequired => {
                if self.sig_classical.is_none() {
                    span.record("downgrade_attempt", true);
                    self.log_downgrade_rejection(
                        policy,
                        "classical-signature-absent-under-both-required",
                        &key_fingerprint("ml-dsa-65", &pq_key.key_id()),
                    );
                    return Err(CryptoError::ClassicalSignatureMissing);
                }
                if self.sig_pq.is_none() {
                    span.record("downgrade_attempt", true);
                    self.log_downgrade_rejection(
                        policy,
                        "pq-signature-absent-under-both-required",
                        &key_fingerprint("ed25519", &classical_key.key_id()),
                    );
                    return Err(CryptoError::PqSignatureMissing);
                }
                self.verify_classical(classical_key, signing_bytes)?;
                verified.push("ed25519");
                self.verify_pq(pq_key, signing_bytes)?;
                verified.push("ml-dsa-65");
            }
        }

        let latency_us = u64::try_from(verify_start.elapsed().as_micros()).unwrap_or(u64::MAX);
        span.record("sig_kinds", tracing::field::debug(&verified));
        span.record("latency_us", latency_us);
        span.record("downgrade_attempt", !warnings.is_empty());
        tracing::info!(
            object_type = self.object_type.as_str(),
            ?policy,
            sig_kinds_present = ?present,
            sig_kinds_verified = ?verified,
            downgrade_attempt = !warnings.is_empty(),
            verdict = "ok",
            "hybrid signed envelope verified",
        );

        Ok(HybridEnvelopeVerification {
            object_type: self.object_type,
            policy,
            sig_kinds_present: present,
            sig_kinds_verified: verified,
            warnings,
        })
    }

    #[allow(clippy::missing_const_for_fn)] // Moves a String payload into the warning record.
    fn transitional_warning(
        &self,
        policy: PqSigningPolicy,
        reason_code: &'static str,
        attempted_downgrade: &'static str,
        attacker_pubkey_fpr: String,
    ) -> HybridDowngradeWarning {
        HybridDowngradeWarning {
            object_type: self.object_type,
            policy,
            reason_code,
            attempted_downgrade,
            attacker_pubkey_fpr,
        }
    }

    fn log_transitional_warning(&self, warning: &HybridDowngradeWarning) {
        tracing::warn!(
            object_type = self.object_type.as_str(),
            ?warning.policy,
            reason_code = warning.reason_code,
            attempted_downgrade = warning.attempted_downgrade,
            attacker_pubkey_fpr = %warning.attacker_pubkey_fpr,
            "hybrid signed envelope accepted by transitional downgrade policy",
        );
    }

    fn log_downgrade_rejection(
        &self,
        policy: PqSigningPolicy,
        attempted_downgrade: &'static str,
        attacker_pubkey_fpr: &str,
    ) {
        tracing::info!(
            object_type = self.object_type.as_str(),
            ?policy,
            attempted_downgrade,
            reason_code = "DowngradeAttempt",
            attacker_pubkey_fpr = %attacker_pubkey_fpr,
            verdict = "rejected",
            "hybrid signed envelope downgrade attempt rejected",
        );
    }

    fn verify_classical(
        &self,
        verifying_key: &Ed25519VerifyingKey,
        signing_bytes: &[u8],
    ) -> CryptoResult<()> {
        let signature = self
            .sig_classical
            .as_ref()
            .ok_or(CryptoError::ClassicalSignatureMissing)?;

        let expected_kid = verifying_key.key_id();
        if self
            .classical_kid
            .as_ref()
            .is_some_and(|kid| kid != &expected_kid)
        {
            return Err(CryptoError::KeyIdMismatch {
                expected: expected_kid.to_string(),
                got: self
                    .classical_kid
                    .as_ref()
                    .map_or_else(|| "<missing>".to_string(), ToString::to_string),
            });
        }

        let start = std::time::Instant::now();
        let result = verifying_key.verify_with_context(
            HYBRID_SIGNED_ENVELOPE_DOMAIN,
            signing_bytes,
            signature,
        );
        tracing::debug!(
            object_type = self.object_type.as_str(),
            algorithm = "ed25519",
            latency_us = start.elapsed().as_micros(),
            "hybrid signed envelope algorithm verify timing",
        );
        result
    }

    fn verify_pq(
        &self,
        verifying_key: &MlDsa65VerifyingKey,
        signing_bytes: &[u8],
    ) -> CryptoResult<()> {
        let signature = self
            .sig_pq
            .as_ref()
            .ok_or(CryptoError::PqSignatureMissing)?;

        let expected_kid = verifying_key.key_id();
        if self.pq_kid.as_ref().is_some_and(|kid| kid != &expected_kid) {
            return Err(CryptoError::KeyIdMismatch {
                expected: expected_kid.to_string(),
                got: self
                    .pq_kid
                    .as_ref()
                    .map_or_else(|| "<missing>".to_string(), ToString::to_string),
            });
        }

        let start = std::time::Instant::now();
        let result = verifying_key.verify(signing_bytes, HYBRID_SIGNED_ENVELOPE_DOMAIN, signature);
        tracing::debug!(
            object_type = self.object_type.as_str(),
            algorithm = "ml-dsa-65",
            latency_us = start.elapsed().as_micros(),
            "hybrid signed envelope algorithm verify timing",
        );
        result
    }

    fn sig_kinds_present(&self) -> Vec<&'static str> {
        let mut present = Vec::with_capacity(2);
        if self.sig_classical.is_some() {
            present.push("ed25519");
        }
        if self.sig_pq.is_some() {
            present.push("ml-dsa-65");
        }
        present
    }
}

fn key_fingerprint(algorithm: &'static str, kid: &KeyId) -> String {
    format!("{algorithm}:kid:{kid}")
}

/// Downgrade steady-state hybrid verification policy to transitional
/// `EitherOk` after a hardware-token-gated admin authorization.
///
/// # Errors
///
/// Returns a crypto error when the requested transition is not the supported
/// emergency path or when the authorizer refuses the operation.
pub fn downgrade_policy_to_either_ok<A>(
    current_policy: PqSigningPolicy,
    authorizer: &A,
    reason: &str,
) -> CryptoResult<PqPolicyDowngradeAudit>
where
    A: PqPolicyDowngradeAuthorizer,
{
    if current_policy != PqSigningPolicy::BothRequired {
        return Err(CryptoError::HeaderPolicyViolation(format!(
            "PQ policy downgrade requires BothRequired as the current policy, got {current_policy:?}"
        )));
    }
    if reason.trim().is_empty() {
        return Err(CryptoError::MissingField(
            "pq policy downgrade reason".to_string(),
        ));
    }

    let new_policy = PqSigningPolicy::EitherOk;
    authorizer.authorize_pq_policy_downgrade(current_policy, new_policy, reason)?;
    Ok(PqPolicyDowngradeAudit {
        event_type: EVENT_PQ_POLICY_DOWNGRADE.to_string(),
        previous_policy: current_policy,
        new_policy,
        operator_fingerprint: authorizer.operator_fingerprint().to_string(),
        reason: reason.to_string(),
    })
}

/// Build the exact bytes signed by both algorithms for `payload`.
///
/// # Errors
///
/// Returns a serialization error if payload canonicalization fails.
pub fn signing_bytes_for_payload<T>(
    object_type: HybridSignedObjectKind,
    payload: &T,
) -> CryptoResult<Vec<u8>>
where
    T: Serialize,
{
    let payload_cbor = fcp_cbor::to_canonical_cbor(payload)
        .map_err(|err| CryptoError::SerializationError(err.to_string()))?;
    Ok(signing_bytes_for_canonical_payload(
        object_type,
        &payload_cbor,
    ))
}

/// Build signing bytes from already-canonical payload bytes.
#[must_use]
pub fn signing_bytes_for_canonical_payload(
    object_type: HybridSignedObjectKind,
    payload_cbor: &[u8],
) -> Vec<u8> {
    let object_type_bytes = object_type.as_str().as_bytes();
    let mut bytes = Vec::with_capacity(
        HYBRID_SIGNED_ENVELOPE_DOMAIN.len() + 4 + object_type_bytes.len() + 8 + payload_cbor.len(),
    );
    bytes.extend_from_slice(HYBRID_SIGNED_ENVELOPE_DOMAIN);
    bytes.extend_from_slice(
        &u32::try_from(object_type_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    bytes.extend_from_slice(object_type_bytes);
    bytes.extend_from_slice(
        &u64::try_from(payload_cbor.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload_cbor);
    bytes
}
