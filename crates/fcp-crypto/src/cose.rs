//! COSE/CWT helpers for FCP2 capability tokens.
//!
//! Implements `COSE_Sign1` tokens with deterministic CBOR payload maps
//! as required for `CapabilityToken` verification.
//!
//! ## Security Requirements
//! - Verify signature BEFORE trusting/parsing untrusted claims
//! - Extract protected `kid` and route to correct issuance pubkey
//! - Use deterministic CBOR for signing

use crate::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;
use chrono::{DateTime, Utc};
use coset::{
    Algorithm, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder,
    RegisteredLabelWithPrivate, TaggedCborSerializable, iana,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Cursor;

/// COSE algorithm identifier for Ed25519.
pub const COSE_ALG_EDDSA: i64 = iana::Algorithm::EdDSA as i64;

/// Maximum accepted byte length for any CBOR input fed into COSE/CWT
/// parsing (`CoseToken::from_cbor`, `CwtClaims::from_cbor`).
///
/// FCP capability tokens are typically 300–500 bytes; this cap is two orders
/// of magnitude above that, but stops attackers from exhausting memory by
/// pushing giant crafted CBOR payloads through the token-verify path.
pub const MAX_COSE_TOKEN_BYTES: usize = 64 * 1024;

/// CWT claim keys (registered claims from RFC 8392).
// CBOR claim labels are now owned by `fcp-auth-schema`. Re-export here
// so existing call sites (fcp-crypto::cose::fcp2_claims::*,
// fcp-crypto::cose::cwt_claims::*) keep working while the workspace
// migrates. After 8n0rm.4 migration is complete, external callers
// should prefer importing directly from `fcp_auth_schema::labels`.
pub use fcp_auth_schema::labels::{cwt_claims, fcp2_claims};

/// CWT (CBOR Web Token) claims map.
///
/// Claims are stored in a `BTreeMap` for stable construction; final wire
/// encoding still goes through `fcp-cbor` so map keys follow RFC 8949
/// deterministic byte ordering.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CwtClaims {
    claims: BTreeMap<i64, ciborium::Value>,
}

impl CwtClaims {
    /// Create empty claims.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set issuer (iss) claim.
    #[must_use]
    pub fn issuer(mut self, iss: &str) -> Self {
        self.claims
            .insert(cwt_claims::ISS, ciborium::Value::Text(iss.into()));
        self
    }

    /// Set subject (sub) claim.
    #[must_use]
    pub fn subject(mut self, sub: &str) -> Self {
        self.claims
            .insert(cwt_claims::SUB, ciborium::Value::Text(sub.into()));
        self
    }

    /// Set audience (aud) claim.
    #[must_use]
    pub fn audience(mut self, aud: &str) -> Self {
        self.claims
            .insert(cwt_claims::AUD, ciborium::Value::Text(aud.into()));
        self
    }

    /// Set expiration time (exp) claim.
    #[must_use]
    pub fn expiration(mut self, exp: DateTime<Utc>) -> Self {
        self.claims.insert(
            cwt_claims::EXP,
            ciborium::Value::Integer(exp.timestamp().into()),
        );
        self
    }

    /// Set not-before (nbf) claim.
    #[must_use]
    pub fn not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.claims.insert(
            cwt_claims::NBF,
            ciborium::Value::Integer(nbf.timestamp().into()),
        );
        self
    }

    /// Set issued-at (iat) claim.
    #[must_use]
    pub fn issued_at(mut self, iat: DateTime<Utc>) -> Self {
        self.claims.insert(
            cwt_claims::IAT,
            ciborium::Value::Integer(iat.timestamp().into()),
        );
        self
    }

    /// Set token ID (cti) claim.
    #[must_use]
    pub fn token_id(mut self, cti: &[u8]) -> Self {
        self.claims
            .insert(cwt_claims::CTI, ciborium::Value::Bytes(cti.to_vec()));
        self
    }

    /// Set FCP2 capability ID claim.
    #[must_use]
    pub fn capability_id(mut self, cap_id: &str) -> Self {
        self.claims.insert(
            fcp2_claims::CAPABILITY_ID,
            ciborium::Value::Text(cap_id.into()),
        );
        self
    }

    /// Set FCP2 zone ID claim.
    #[must_use]
    pub fn zone_id(mut self, zone_id: &str) -> Self {
        self.claims
            .insert(fcp2_claims::ZONE_ID, ciborium::Value::Text(zone_id.into()));
        self
    }

    /// Set FCP2 allowed operations claim.
    #[must_use]
    pub fn operations(mut self, ops: &[&str]) -> Self {
        let mut values = Vec::with_capacity(ops.len());
        for s in ops {
            values.push(ciborium::Value::Text((*s).into()));
        }
        self.claims
            .insert(fcp2_claims::OPERATIONS, ciborium::Value::Array(values));
        self
    }

    /// Set FCP2 principal ID claim.
    #[must_use]
    pub fn principal_id(mut self, principal: &str) -> Self {
        self.claims.insert(
            fcp2_claims::PRINCIPAL_ID,
            ciborium::Value::Text(principal.into()),
        );
        self
    }

    /// Set FCP2 issuing node ID.
    #[must_use]
    pub fn issuing_node(mut self, node_id: &str) -> Self {
        self.claims
            .insert(fcp2_claims::ISS_NODE, ciborium::Value::Text(node_id.into()));
        self
    }

    /// Set FCP2 binary audience (`ObjectId`).
    #[must_use]
    pub fn audience_binary(mut self, object_id: &[u8]) -> Self {
        self.claims.insert(
            fcp2_claims::AUD_BINARY,
            ciborium::Value::Bytes(object_id.to_vec()),
        );
        self
    }

    /// Set FCP2 grant object IDs.
    #[must_use]
    pub fn grant_objects(mut self, object_ids: &[&[u8]]) -> Self {
        let mut values = Vec::with_capacity(object_ids.len());
        for id in object_ids {
            values.push(ciborium::Value::Bytes(id.to_vec()));
        }
        self.claims.insert(
            fcp2_claims::GRANT_OBJECT_IDS,
            ciborium::Value::Array(values),
        );
        self
    }

    /// Set FCP2 holder node ID.
    #[must_use]
    pub fn holder_node(mut self, node_id: &str) -> Self {
        self.claims.insert(
            fcp2_claims::HOLDER_NODE,
            ciborium::Value::Text(node_id.into()),
        );
        self
    }

    /// Set FCP2 checkpoint ID and sequence.
    #[must_use]
    pub fn checkpoint(mut self, id: &[u8], seq: u64) -> Self {
        self.claims
            .insert(fcp2_claims::CHK_ID, ciborium::Value::Bytes(id.to_vec()));
        self.claims
            .insert(fcp2_claims::CHK_SEQ, ciborium::Value::Integer(seq.into()));
        self
    }

    /// Set target instance ID for this token.
    #[must_use]
    pub fn target_instance(mut self, instance_id: &str) -> Self {
        self.claims.insert(
            fcp2_claims::INSTANCE_ID,
            ciborium::Value::Text(instance_id.into()),
        );
        self
    }

    /// Set FCP2 constraints claim from pre-serialized CBOR bytes.
    ///
    /// The bytes are deserialized into a `ciborium::Value` so they are
    /// stored as a native CBOR map (not wrapped in a byte string).
    ///
    /// **Deprecated (br-zp1xx):** this variant panics on malformed
    /// CBOR and exposes a denial-of-service surface to any caller
    /// that forwards attacker-supplied bytes. Prefer
    /// [`Self::try_constraints_cbor`], which returns a typed
    /// [`CryptoError::SerializationError`]. For backward compatibility
    /// this method now tracing-warns and LEAVES THE CLAIM UNSET when
    /// the input is invalid, so an existing caller's worst-case
    /// outcome is a token without a constraints claim (which the
    /// verifier's constraint-required gate will then reject) rather
    /// than a process abort.
    #[must_use]
    #[deprecated(
        since = "0.2.0",
        note = "panic-prone; use `try_constraints_cbor` for the fallible variant (br-zp1xx)"
    )]
    pub fn constraints_cbor(mut self, cbor_bytes: &[u8]) -> Self {
        // Parse into a local value first so `self` stays owned for
        // both the success and fallback paths. On malformed CBOR we
        // tracing-warn and leave the constraints claim UNSET — the
        // verifier's C3.4 constraints-required gate will then reject
        // the resulting token at verify time, which is strictly
        // better than aborting the process mid-build.
        match ciborium::from_reader::<ciborium::Value, _>(cbor_bytes) {
            Ok(value) => {
                self.claims.insert(fcp2_claims::CONSTRAINTS, value);
            }
            Err(err) => {
                tracing::warn!(
                    component = "fcp_crypto.cose",
                    error = %err,
                    "constraints_cbor: ignoring malformed CBOR; caller should migrate to try_constraints_cbor"
                );
            }
        }
        self
    }

    /// Fallible variant of [`Self::constraints_cbor`] (br-zp1xx).
    ///
    /// The bytes are deserialized into a `ciborium::Value` so they are
    /// stored as a native CBOR map (not wrapped in a byte string).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SerializationError`] when `cbor_bytes`
    /// is not valid CBOR, rather than panicking.
    pub fn try_constraints_cbor(mut self, cbor_bytes: &[u8]) -> CryptoResult<Self> {
        let value: ciborium::Value = ciborium::from_reader(cbor_bytes).map_err(|err| {
            CryptoError::SerializationError(format!("constraints_cbor: invalid CBOR: {err}"))
        })?;
        self.claims.insert(fcp2_claims::CONSTRAINTS, value);
        Ok(self)
    }

    /// Set custom claim.
    #[must_use]
    pub fn custom(mut self, key: i64, value: ciborium::Value) -> Self {
        self.claims.insert(key, value);
        self
    }

    /// Get a claim value.
    #[must_use]
    pub fn get(&self, key: i64) -> Option<&ciborium::Value> {
        self.claims.get(&key)
    }

    /// Get issuer claim as string.
    #[must_use]
    pub fn get_issuer(&self) -> Option<&str> {
        self.get(cwt_claims::ISS).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get subject claim as string.
    #[must_use]
    pub fn get_subject(&self) -> Option<&str> {
        self.get(cwt_claims::SUB).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get audience (`aud`) claim as string.
    #[must_use]
    pub fn get_audience(&self) -> Option<&str> {
        self.get(cwt_claims::AUD).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get expiration as timestamp.
    #[must_use]
    pub fn get_expiration(&self) -> Option<i64> {
        self.get(cwt_claims::EXP).and_then(|v| match v {
            ciborium::Value::Integer(i) => i64::try_from(*i).ok(),
            _ => None,
        })
    }

    /// Get not-before as timestamp.
    #[must_use]
    pub fn get_not_before(&self) -> Option<i64> {
        self.get(cwt_claims::NBF).and_then(|v| match v {
            ciborium::Value::Integer(i) => i64::try_from(*i).ok(),
            _ => None,
        })
    }

    /// Get capability ID.
    #[must_use]
    pub fn get_capability_id(&self) -> Option<&str> {
        self.get(fcp2_claims::CAPABILITY_ID).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get zone ID.
    #[must_use]
    pub fn get_zone_id(&self) -> Option<&str> {
        self.get(fcp2_claims::ZONE_ID).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get principal ID.
    #[must_use]
    pub fn get_principal_id(&self) -> Option<&str> {
        self.get(fcp2_claims::PRINCIPAL_ID).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get holder node ID (NORMATIVE).
    ///
    /// When this claim is set, requests using this token MUST include
    /// a `holder_proof` signature from the specified node.
    #[must_use]
    pub fn get_holder_node(&self) -> Option<&str> {
        self.get(fcp2_claims::HOLDER_NODE).and_then(|v| match v {
            ciborium::Value::Text(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Get JWT ID (jti claim).
    ///
    /// The unique identifier for this token, used in `holder_proof` binding.
    #[must_use]
    pub fn get_jti(&self) -> Option<&[u8]> {
        self.get(cwt_claims::CTI).and_then(|v| match v {
            ciborium::Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
    }

    /// Encode claims to deterministic CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        fcp_cbor::to_canonical_cbor(&self.claims)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Decode claims from CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() > MAX_COSE_TOKEN_BYTES {
            return Err(CryptoError::SerializationError(format!(
                "CWT claims payload exceeds {} byte cap (got {})",
                MAX_COSE_TOKEN_BYTES,
                bytes.len()
            )));
        }

        let mut cursor = Cursor::new(bytes);
        let value: ciborium::Value = ciborium::from_reader(&mut cursor)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        #[allow(clippy::cast_possible_truncation)] // cursor position is bounded by bytes.len()
        if cursor.position() as usize != bytes.len() {
            return Err(CryptoError::SerializationError(
                "trailing bytes after CBOR value".into(),
            ));
        }

        let ciborium::Value::Map(map) = &value else {
            return Err(CryptoError::SerializationError("expected CBOR map".into()));
        };

        let mut claims = BTreeMap::new();
        for (k, v) in map {
            let key = match k {
                // `i: &ciborium::value::Integer`; deref to an owned copy
                // before `try_from` because ciborium's TryFrom impl is on
                // `Integer`, not `&Integer`.
                ciborium::Value::Integer(i) => i64::try_from(*i)
                    .map_err(|_| CryptoError::SerializationError("invalid claim key".into()))?,
                _ => {
                    return Err(CryptoError::SerializationError(
                        "claim key must be integer".into(),
                    ));
                }
            };
            // Align with fcp-cbor's strictness: reject any CBOR tag
            // that appears at or under a claim value. fcp-cbor's
            // `canonicalize_value_in_place` rejects `Value::Tag(_, _)`
            // anywhere in the tree, so a token accepted here but
            // handed to fcp-cbor-based downstream components (e.g.
            // the canonical re-encoder used for signature
            // verification, or schema validation) would fail. That
            // interop split is what bead flywheel_connectors-8azf9
            // documents: keep the two crates in lockstep so any
            // non-canonical shape is refused at the earliest layer.
            reject_cbor_tags(v)?;
            if claims.insert(key, v.clone()).is_some() {
                return Err(CryptoError::SerializationError(format!(
                    "duplicate claim key: {key}"
                )));
            }
        }

        let canonical = fcp_cbor::to_canonical_cbor(&value)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        if canonical != bytes {
            return Err(CryptoError::SerializationError(
                "non-canonical CBOR encoding".into(),
            ));
        }

        Ok(Self { claims })
    }
}

/// Recursively reject any `Value::Tag(..)` node beneath `value`.
///
/// Mirrors `fcp_cbor::canonicalize_value_in_place`'s tag refusal so
/// the two crates agree on what constitutes a canonical CBOR tree.
/// Recurses through `Map` and `Array` so a tag buried several layers
/// deep (e.g. inside a payload map whose outer shape is otherwise
/// valid) is still surfaced.
fn reject_cbor_tags(value: &ciborium::Value) -> CryptoResult<()> {
    match value {
        ciborium::Value::Tag(tag, _) => Err(CryptoError::InvalidCborTag { tag: *tag }),
        ciborium::Value::Array(items) => {
            for item in items {
                reject_cbor_tags(item)?;
            }
            Ok(())
        }
        ciborium::Value::Map(entries) => {
            for (k, v) in entries {
                reject_cbor_tags(k)?;
                reject_cbor_tags(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `COSE_Sign1` token for FCP2 capabilities.
#[derive(Debug, Clone)]
pub struct CoseToken {
    inner: CoseSign1,
}

impl CoseToken {
    fn reject_unprotected_security_headers(&self) -> CryptoResult<()> {
        if self.inner.unprotected.alg.is_some() {
            return Err(CryptoError::HeaderPolicyViolation(
                "alg must not appear in unprotected headers".into(),
            ));
        }

        if !self.inner.unprotected.key_id.is_empty() {
            return Err(CryptoError::HeaderPolicyViolation(
                "kid must not appear in unprotected headers".into(),
            ));
        }

        if !self.inner.unprotected.crit.is_empty() {
            return Err(CryptoError::HeaderPolicyViolation(
                "crit must not appear in unprotected headers".into(),
            ));
        }

        Ok(())
    }

    fn require_critical_headers_present_in_protected_bucket(&self) -> CryptoResult<()> {
        for label in &self.inner.protected.header.crit {
            match label {
                RegisteredLabelWithPrivate::Assigned(iana::HeaderParameter::Alg)
                    if self.inner.protected.header.alg.is_none() =>
                {
                    return Err(CryptoError::HeaderPolicyViolation(
                        "crit references alg, but alg is missing from protected headers".into(),
                    ));
                }
                RegisteredLabelWithPrivate::Assigned(iana::HeaderParameter::Kid)
                    if self.inner.protected.header.key_id.is_empty() =>
                {
                    return Err(CryptoError::HeaderPolicyViolation(
                        "crit references kid, but kid is missing from protected headers".into(),
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn validate_verification_headers(&self) -> CryptoResult<()> {
        // FCP capability tokens require the security-sensitive headers we
        // consume (`alg`, `kid`, `crit`) to be unambiguous and integrity
        // protected, even though bare COSE allows some of them to be
        // unprotected hints.
        self.reject_unprotected_security_headers()?;

        // RFC 8152 §4.4: bind the verifier to a specific algorithm.
        // Without this, alg is only implicitly bound through the TBS bytes,
        // which works for our single-algorithm registry but is brittle once
        // additional verifiers (or downgrade-prone callers) appear.
        match &self.inner.protected.header.alg {
            Some(Algorithm::Assigned(iana::Algorithm::EdDSA)) => {}
            Some(other) => {
                return Err(CryptoError::AlgorithmMismatch {
                    expected: "EdDSA",
                    got: format!("{other:?}"),
                });
            }
            None => {
                return Err(CryptoError::MissingField("alg in protected header".into()));
            }
        }

        // RFC 8152 §3.1: every label in `crit` MUST be one the recipient
        // understands; otherwise the message MUST be rejected. We process
        // only `Alg` and `Kid` from the protected header, so any other
        // label — assigned, private-use, or text — is unhandled.
        for label in &self.inner.protected.header.crit {
            match label {
                RegisteredLabelWithPrivate::Assigned(
                    iana::HeaderParameter::Alg | iana::HeaderParameter::Kid,
                ) => {}
                other => {
                    return Err(CryptoError::UnsupportedCriticalHeader(format!("{other:?}")));
                }
            }
        }

        // RFC 9052 §3.1: `crit` can only list labels that are actually
        // carried in the protected header bucket.
        self.require_critical_headers_present_in_protected_bucket()?;

        Ok(())
    }

    /// Create and sign a new `COSE_Sign1` token.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(signing_key: &Ed25519SigningKey, claims: &CwtClaims) -> CryptoResult<Self> {
        let mut claims = claims.clone();
        synthesize_schema_version(&mut claims);
        synthesize_audience_from_zone(&mut claims);
        let payload = claims.to_cbor()?;
        let kid = signing_key.key_id();

        // Build protected header with algorithm and key ID
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(kid.as_bytes().to_vec())
            .build();

        // Build a partial CoseSign1 to get the to-be-signed bytes
        let mut cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .build();

        // Get the to-be-signed bytes (Sig_structure)
        let tbs = cose_sign1.tbs_data(&[]);

        // Sign the TBS data
        let signature = signing_key.sign(&tbs);

        // Set the signature
        cose_sign1.signature = signature.to_bytes().to_vec();

        Ok(Self { inner: cose_sign1 })
    }

    /// Verify the token signature and extract claims.
    ///
    /// **IMPORTANT:** This verifies the signature BEFORE returning claims,
    /// as required by the spec.
    ///
    /// Per RFC 8152 §4.4 and §3.1, this rejects:
    /// - tokens whose protected-header `alg` is missing or anything other
    ///   than `EdDSA` (the only algorithm this verifier supports), and
    /// - tokens whose protected-header `crit` set lists any label this
    ///   verifier does not understand.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> CryptoResult<CwtClaims> {
        self.validate_verification_headers()?;

        // FCP routes issuance keys by protected `kid`, so direct verification
        // must reject tokens whose signed key hint does not match the
        // verifying key selected by the caller.
        let kid_bytes = self.get_key_id()?;
        let expected_kid = verifying_key.key_id();
        if kid_bytes != expected_kid.as_bytes() {
            return Err(CryptoError::KeyIdMismatch {
                expected: expected_kid.to_hex(),
                got: hex::encode(kid_bytes),
            });
        }

        // Extract signature
        let signature = Ed25519Signature::try_from_slice(&self.inner.signature)?;

        // Recreate to-be-signed bytes
        let tbs = self.inner.tbs_data(&[]);

        // Verify signature FIRST
        verifying_key.verify(&tbs, &signature)?;

        // Only after verification, parse the payload
        let payload = self
            .inner
            .payload
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("payload".into()))?;

        CwtClaims::from_cbor(payload)
    }

    /// Extract claims without verifying the signature.
    ///
    /// **DANGER:** This MUST NOT be used for security-critical decisions.
    /// Intended only for simulation tools and tests that need to inspect
    /// claims without access to the issuer public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is missing or cannot be decoded.
    pub fn claims_unverified(&self) -> CryptoResult<CwtClaims> {
        let payload = self
            .inner
            .payload
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("payload".into()))?;
        CwtClaims::from_cbor(payload)
    }

    /// Verify using a key lookup function.
    ///
    /// The lookup function receives the KID from the protected header
    /// and should return the corresponding verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if the KID is missing, key lookup fails, or verification fails.
    pub fn verify_with_lookup<F>(&self, key_lookup: F) -> CryptoResult<CwtClaims>
    where
        F: FnOnce(&KeyId) -> Option<Ed25519VerifyingKey>,
    {
        self.validate_verification_headers()?;

        // Extract KID from protected header
        let kid_bytes = self.get_key_id()?;
        let kid = KeyId::try_from_slice(&kid_bytes)?;

        // Look up the verifying key
        let verifying_key =
            key_lookup(&kid).ok_or_else(|| CryptoError::InvalidKeyId("key not found".into()))?;

        self.verify(&verifying_key)
    }

    /// Get the key ID from the protected header.
    ///
    /// # Errors
    ///
    /// Returns an error if the KID is missing.
    pub fn get_key_id(&self) -> CryptoResult<Vec<u8>> {
        let kid = &self.inner.protected.header.key_id;
        if kid.is_empty() {
            Err(CryptoError::MissingField("kid in protected header".into()))
        } else {
            Ok(kid.clone())
        }
    }

    /// Encode to CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        self.inner
            .clone()
            .to_vec()
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Decode from CBOR bytes.
    ///
    /// **NOTE:** This only parses the structure. You MUST call `verify()`
    /// before trusting any claims.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() > MAX_COSE_TOKEN_BYTES {
            return Err(CryptoError::SerializationError(format!(
                "COSE token payload exceeds {} byte cap (got {})",
                MAX_COSE_TOKEN_BYTES,
                bytes.len()
            )));
        }

        let inner = CoseSign1::from_slice(bytes)
            .or_else(|_| CoseSign1::from_tagged_slice(bytes))
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Validate token timing (exp, nbf).
    ///
    /// # Errors
    ///
    /// Returns an error if the token is expired or not yet valid.
    pub fn validate_timing(claims: &CwtClaims, now: DateTime<Utc>) -> CryptoResult<()> {
        let now_ts = now.timestamp();

        // Check expiration
        if let Some(exp) = claims.get_expiration() {
            if now_ts >= exp {
                return Err(CryptoError::TokenExpired);
            }
        }

        // Check not-before
        if let Some(nbf) = claims.get_not_before() {
            if now_ts < nbf {
                return Err(CryptoError::TokenNotYetValid);
            }
        }

        Ok(())
    }
}

/// Build a capability token with standard FCP2 claims.
pub struct CapabilityTokenBuilder {
    claims: CwtClaims,
}

impl CapabilityTokenBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            claims: CwtClaims::new(),
        }
    }

    /// Create a new builder from a typed [`fcp_auth_schema::AuthClaims`].
    ///
    /// This is the **preferred** constructor — it takes the shared
    /// typed schema and bypasses the per-field chain API that leaked
    /// FCP-specific label knowledge into this crate (br-8n0rm).
    ///
    /// The builder stores the claims as canonical CBOR, so
    /// downstream `.build(...)` / signing produces byte-for-byte
    /// identical output to a chain-built token with equivalent
    /// values.
    ///
    /// # Errors
    /// Returns the underlying CBOR error if encoding fails.
    pub fn with_claims(
        claims: &fcp_auth_schema::AuthClaims,
    ) -> Result<Self, fcp_auth_schema::SchemaError> {
        // AuthClaims emits canonical RFC 8949 CBOR. Re-parse it into a
        // CwtClaims BTreeMap so the existing build path (sign,
        // COSE_Sign1 wrap) continues to work unchanged.
        let bytes = claims.to_canonical_cbor()?;
        let value: ciborium::Value = ciborium::from_reader(&bytes[..])
            .map_err(|e| fcp_auth_schema::SchemaError::Decode(e.to_string()))?;
        let mut cwt = CwtClaims::new();
        if let ciborium::Value::Map(entries) = value {
            for (k, v) in entries {
                if let ciborium::Value::Integer(i) = k {
                    let as_i128: i128 = i.into();
                    if let Ok(label) = i64::try_from(as_i128) {
                        cwt = cwt.custom(label, v);
                    }
                }
            }
        }
        Ok(Self { claims: cwt })
    }

    /// Set the capability ID.
    #[must_use]
    pub fn capability_id(mut self, id: &str) -> Self {
        self.claims = self.claims.capability_id(id);
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, zone: &str) -> Self {
        self.claims = self.claims.zone_id(zone);
        self
    }

    /// Set the principal ID (who this token is for).
    #[must_use]
    pub fn principal(mut self, principal: &str) -> Self {
        self.claims = self.claims.principal_id(principal);
        self
    }

    /// Set allowed operations.
    #[must_use]
    pub fn operations(mut self, ops: &[&str]) -> Self {
        self.claims = self.claims.operations(ops);
        self
    }

    /// Set target instance ID.
    #[must_use]
    pub fn target_instance(mut self, instance_id: &str) -> Self {
        self.claims = self.claims.target_instance(instance_id);
        self
    }

    /// Set issuing node.
    #[must_use]
    pub fn issuing_node(mut self, node_id: &str) -> Self {
        self.claims = self.claims.issuing_node(node_id);
        self
    }

    /// Set checkpoint.
    #[must_use]
    pub fn checkpoint(mut self, id: &[u8], seq: u64) -> Self {
        self.claims = self.claims.checkpoint(id, seq);
        self
    }

    /// Set the issuer.
    #[must_use]
    pub fn issuer(mut self, iss: &str) -> Self {
        self.claims = self.claims.issuer(iss);
        self
    }

    /// Set the audience (`aud`) claim — typically the connector ID this
    /// token is intended for. Surfaces the underlying `CwtClaims::audience`
    /// builder hook so host-side persisted-state verifiers can match
    /// `audience` against the inbound `connector_id`.
    #[must_use]
    pub fn audience(mut self, aud: &str) -> Self {
        self.claims = self.claims.audience(aud);
        self
    }

    /// Set the JWT/COSE token ID (`cti`) claim. Required when the host
    /// needs to revoke or audit-trace a specific issued token, so the
    /// caller can plumb the token-id bytes returned by the issuance API
    /// straight into the signed token.
    #[must_use]
    pub fn token_id(mut self, cti: &[u8]) -> Self {
        self.claims = self.claims.token_id(cti);
        self
    }

    /// Set validity period.
    #[must_use]
    pub fn validity(mut self, not_before: DateTime<Utc>, expires: DateTime<Utc>) -> Self {
        self.claims = self.claims.not_before(not_before).expiration(expires);
        self
    }

    /// Set issued-at to now.
    #[must_use]
    pub fn issued_now(mut self) -> Self {
        self.claims = self.claims.issued_at(Utc::now());
        self
    }

    /// Set constraints from pre-serialized CBOR bytes.
    ///
    /// Use `ciborium::into_writer(&constraints, &mut buf)` to serialize
    /// a `CapabilityConstraints` before passing here.
    ///
    /// **Deprecated (br-zp1xx):** forwards to the panic-prone
    /// [`CwtClaims::constraints_cbor`] shim. Migrate to
    /// [`Self::try_constraints_cbor`] for typed error handling.
    #[must_use]
    #[deprecated(
        since = "0.2.0",
        note = "panic-prone; use `try_constraints_cbor` for the fallible variant (br-zp1xx)"
    )]
    pub fn constraints_cbor(mut self, cbor_bytes: &[u8]) -> Self {
        #[allow(deprecated)]
        {
            self.claims = self.claims.constraints_cbor(cbor_bytes);
        }
        self
    }

    /// Fallible variant of [`Self::constraints_cbor`] (br-zp1xx).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SerializationError`] when `cbor_bytes`
    /// is not valid CBOR, rather than panicking.
    pub fn try_constraints_cbor(mut self, cbor_bytes: &[u8]) -> CryptoResult<Self> {
        self.claims = self.claims.try_constraints_cbor(cbor_bytes)?;
        Ok(self)
    }

    /// Build and sign the token.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(mut self, signing_key: &Ed25519SigningKey) -> CryptoResult<CoseToken> {
        // br-8n0rm.8: synthesize canonical GRANTS from legacy (capability_id + operations)
        // so every token this builder emits carries the canonical shape the verifier prefers.
        // Unblocks 8n0rm.6 removal of the verifier's legacy OPERATIONS fallback.
        synthesize_grants_from_legacy_operations(&mut self.claims);
        CoseToken::sign(signing_key, &self.claims)
    }
}

/// Synthesize the canonical `fcp2_claims::GRANTS` claim from the legacy
/// (`capability_id` + `operations`) shape if `GRANTS` is absent.
///
/// The canonical `GRANTS` shape is an array of
/// `{capability: <id>, operation: <op>}` maps — matching the serde
/// derive on `fcp_core::capability::CapabilityGrant`. This function
/// builds that shape via raw ciborium without depending on `fcp-core`,
/// preserving the `fcp-auth-schema` → `fcp-crypto` → `fcp-core` layering.
///
/// No-op if `GRANTS` is already set OR if `capability_id`/`operations` are
/// missing (the verifier will surface an appropriate `MissingField` error
/// in those cases).
fn synthesize_grants_from_legacy_operations(claims: &mut CwtClaims) {
    if claims.get(fcp2_claims::GRANTS).is_some() {
        return; // canonical GRANTS already present; respect it.
    }
    let Some(cap_id) = claims.get(fcp2_claims::CAPABILITY_ID).cloned() else {
        return;
    };
    let Some(ops_val) = claims.get(fcp2_claims::OPERATIONS).cloned() else {
        return;
    };
    let ciborium::Value::Text(cap_text) = cap_id else {
        return; // malformed capability_id — let verifier reject it later
    };
    let ciborium::Value::Array(ops_array) = ops_val else {
        return;
    };
    let mut grants: Vec<ciborium::Value> = Vec::with_capacity(ops_array.len());
    for op in ops_array {
        let ciborium::Value::Text(op_text) = op else {
            continue; // skip non-Text entries; verifier's typed check will fire
        };
        grants.push(ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("capability".into()),
                ciborium::Value::Text(cap_text.clone()),
            ),
            (
                ciborium::Value::Text("operation".into()),
                ciborium::Value::Text(op_text),
            ),
        ]));
    }
    if grants.is_empty() {
        return;
    }
    *claims = claims
        .clone()
        .custom(fcp2_claims::GRANTS, ciborium::Value::Array(grants));
}

/// Stamp the current auth-claim schema version when the caller did not
/// provide one explicitly.
///
/// This keeps the legacy chain builder and direct `CoseToken::sign`
/// callers aligned with the typed `AuthClaims` path, which always emits
/// `SCHEMA_VERSION`. Existing explicit values are preserved so tests and
/// staged rollout fixtures can still construct mismatched-version tokens
/// intentionally.
fn synthesize_schema_version(claims: &mut CwtClaims) {
    if claims.get(fcp2_claims::SCHEMA_VERSION).is_some() {
        return;
    }
    *claims = claims.clone().custom(
        fcp2_claims::SCHEMA_VERSION,
        ciborium::Value::Integer(i64::from(fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION).into()),
    );
}

/// Stamp `aud` from `zone_id` when the caller omitted it.
///
/// Capability verifiers bind tokens to a target zone via `aud`, but most
/// legacy builder call sites only set the private `ZONE_ID` claim. Preserve
/// those call sites by synthesizing `aud = zone_id` here. Explicit `aud`
/// values, including `"*"`, always win.
fn synthesize_audience_from_zone(claims: &mut CwtClaims) {
    if claims.get(cwt_claims::AUD).is_some() {
        return;
    }
    let Some(zone) = claims.get_zone_id() else {
        return;
    };
    *claims = claims.clone().audience(zone);
}

impl Default for CapabilityTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::cell::Cell;

    // ── 8n0rm.8: legacy OPERATIONS → canonical GRANTS synthesis ──────────

    #[test]
    fn sign_synthesizes_grants_from_legacy_operations() {
        let signing_key = Ed25519SigningKey::generate();
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap:test")
            .zone_id("z:work")
            .operations(&["op:read", "op:write"])
            .validity(now, now + Duration::hours(1))
            .sign(&signing_key)
            .expect("sign");

        let verifying_key = signing_key.verifying_key();
        let claims = cose.verify(&verifying_key).expect("verify");
        // The signed token MUST carry canonical GRANTS now.
        let grants = claims
            .get(fcp2_claims::GRANTS)
            .expect("synthesize must emit GRANTS");
        let ciborium::Value::Array(arr) = grants else {
            panic!("GRANTS must be an Array");
        };
        assert_eq!(arr.len(), 2);
        // Each entry must be {capability: "cap:test", operation: "op:..."}
        for entry in arr {
            let ciborium::Value::Map(map) = entry else {
                panic!("grant entry must be a Map");
            };
            let cap_field = map
                .iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "capability"))
                .expect("capability field");
            let ciborium::Value::Text(cap_text) = &cap_field.1 else {
                panic!("capability must be Text");
            };
            assert_eq!(cap_text, "cap:test");
            let op_field = map
                .iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "operation"))
                .expect("operation field");
            let ciborium::Value::Text(op_text) = &op_field.1 else {
                panic!("operation must be Text");
            };
            assert!(op_text == "op:read" || op_text == "op:write");
        }
    }

    #[test]
    fn sign_preserves_existing_grants_claim() {
        // If the builder already has GRANTS set via .custom(...), the
        // synthesizer MUST NOT overwrite it.
        let signing_key = Ed25519SigningKey::generate();
        let now = Utc::now();
        let custom_grant = ciborium::Value::Array(vec![ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("capability".into()),
                ciborium::Value::Text("cap:prewritten".into()),
            ),
            (
                ciborium::Value::Text("operation".into()),
                ciborium::Value::Text("op:prewritten".into()),
            ),
        ])]);
        let mut builder = CapabilityTokenBuilder::new()
            .capability_id("cap:test") // NOT "cap:prewritten" - must be ignored
            .zone_id("z:work")
            .operations(&["op:test"]) // same — must be ignored in favor of custom GRANTS
            .validity(now, now + Duration::hours(1));
        builder.claims = builder.claims.custom(fcp2_claims::GRANTS, custom_grant);
        let cose = builder.sign(&signing_key).expect("sign");

        let claims = cose.verify(&signing_key.verifying_key()).expect("verify");
        let grants = claims.get(fcp2_claims::GRANTS).expect("grants");
        let ciborium::Value::Array(arr) = grants else {
            panic!()
        };
        assert_eq!(arr.len(), 1, "must not overwrite pre-set GRANTS");
        let ciborium::Value::Map(map) = &arr[0] else {
            panic!()
        };
        let (_, cap) = map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "capability"))
            .unwrap();
        assert!(matches!(cap, ciborium::Value::Text(s) if s == "cap:prewritten"));
    }

    #[test]
    fn cose_sign_stamps_current_schema_version_when_missing() {
        let signing_key = Ed25519SigningKey::generate();
        let now = Utc::now();
        let claims = CwtClaims::new()
            .issuer("z:work")
            .capability_id("cap:test")
            .zone_id("z:work")
            .expiration(now + Duration::hours(1));

        let token = CoseToken::sign(&signing_key, &claims).expect("sign");
        let verified = token
            .verify(&signing_key.verifying_key())
            .expect("verify current-schema token");

        match verified.get(fcp2_claims::SCHEMA_VERSION) {
            Some(ciborium::Value::Integer(version)) => {
                assert_eq!(
                    i64::try_from(*version).unwrap(),
                    i64::from(fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION)
                );
            }
            other => panic!("expected synthesized schema_version integer, got {other:?}"),
        }
    }

    #[test]
    fn cose_sign_stamps_audience_from_zone_when_missing() {
        let signing_key = Ed25519SigningKey::generate();
        let now = Utc::now();
        let claims = CwtClaims::new()
            .issuer("node:test")
            .zone_id("z:work")
            .capability_id("cap:test")
            .expiration(now + Duration::hours(1));

        let token = CoseToken::sign(&signing_key, &claims).expect("sign");
        let verified = token
            .verify(&signing_key.verifying_key())
            .expect("verify current-zone audience token");

        assert_eq!(verified.get_audience(), Some("z:work"));
    }

    // ── 8n0rm.4: typed AuthClaims ↔ CapabilityTokenBuilder interop ────────

    #[test]
    fn with_claims_constructs_builder_from_auth_claims() {
        let claims = fcp_auth_schema::AuthClaims {
            schema_version: fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION,
            capability_id: Some("cap:test".into()),
            zone_id: Some("z:work".into()),
            principal_id: Some("user@example".into()),
            ..fcp_auth_schema::AuthClaims::default()
        };
        let builder = CapabilityTokenBuilder::with_claims(&claims).expect("build");
        // Must expose the same labels
        assert_eq!(builder.claims.get_capability_id(), Some("cap:test"));
        assert_eq!(builder.claims.get_zone_id(), Some("z:work"));
    }

    #[test]
    fn with_claims_re_exports_labels_match_auth_schema() {
        // The fcp2_claims + cwt_claims re-exports preserve the integer
        // values that all existing callers depend on.
        assert_eq!(
            fcp2_claims::CAPABILITY_ID,
            fcp_auth_schema::labels::fcp2_claims::CAPABILITY_ID
        );
        assert_eq!(
            fcp2_claims::GRANTS,
            fcp_auth_schema::labels::fcp2_claims::GRANTS
        );
        assert_eq!(
            fcp2_claims::INSTANCE_ID,
            fcp_auth_schema::labels::fcp2_claims::INSTANCE_ID
        );
        assert_eq!(cwt_claims::EXP, fcp_auth_schema::labels::cwt_claims::EXP);
    }

    #[test]
    fn cwt_claims_cbor_roundtrip() {
        let claims = CwtClaims::new()
            .issuer("test-issuer")
            .subject("test-subject")
            .capability_id("cap:test.read");

        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();

        assert_eq!(parsed.get_issuer(), Some("test-issuer"));
        assert_eq!(parsed.get_subject(), Some("test-subject"));
        assert_eq!(parsed.get_capability_id(), Some("cap:test.read"));
    }

    #[test]
    fn cose_token_sign_verify() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let claims = CwtClaims::new()
            .issuer("test")
            .capability_id("cap:test.read")
            .zone_id("z:work");

        let token = CoseToken::sign(&sk, &claims).unwrap();
        let verified_claims = token.verify(&pk).unwrap();

        assert_eq!(verified_claims.get_issuer(), Some("test"));
        assert_eq!(verified_claims.get_capability_id(), Some("cap:test.read"));
        assert_eq!(verified_claims.get_zone_id(), Some("z:work"));
    }

    #[test]
    fn cose_token_wrong_key_fails() {
        let sk1 = Ed25519SigningKey::generate();
        let sk2 = Ed25519SigningKey::generate();
        let pk2 = sk2.verifying_key();

        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk1, &claims).unwrap();

        assert!(token.verify(&pk2).is_err());
    }

    #[test]
    fn cose_token_from_cbor_rejects_oversized_payload() {
        let blob = vec![0u8; MAX_COSE_TOKEN_BYTES + 1];
        let err = CoseToken::from_cbor(&blob).expect_err("oversized blob must be rejected");
        match err {
            CryptoError::SerializationError(msg) => {
                assert!(
                    msg.contains("exceeds") && msg.contains("byte cap"),
                    "error message should flag the size cap, got: {msg}"
                );
            }
            other => panic!("expected SerializationError for oversized input, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_from_cbor_rejects_oversized_payload() {
        let blob = vec![0u8; MAX_COSE_TOKEN_BYTES + 1];
        let err = CwtClaims::from_cbor(&blob).expect_err("oversized blob must be rejected");
        match err {
            CryptoError::SerializationError(msg) => {
                assert!(
                    msg.contains("exceeds") && msg.contains("byte cap"),
                    "error message should flag the size cap, got: {msg}"
                );
            }
            other => panic!("expected SerializationError for oversized input, got {other:?}"),
        }
    }

    /// Regression for bead flywheel_connectors-8azf9: fcp-crypto's
    /// `CwtClaims` decode used to accept a CBOR tag wrapping a claim
    /// value, while fcp-cbor (the project-wide canonicalizer) rejects
    /// any `Value::Tag(..)` anywhere in the tree. A token accepted
    /// here but re-encoded through fcp-cbor for signature verification
    /// or schema validation would fail downstream — an interop split.
    /// Both the outer value and a tag buried inside a nested array or
    /// map MUST be rejected at the earliest decode layer with the
    /// canonical `InvalidCborTag` variant.
    #[test]
    fn test_cwt_claim_with_cbor_tag_rejected() {
        // Case 1: claim value is *directly* a Tag.
        let map = vec![(
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Tag(24, Box::new(ciborium::Value::Text("iss".into()))),
        )];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes)
            .expect("serialize tagged claim");
        let err =
            CwtClaims::from_cbor(&bytes).expect_err("direct tagged claim value must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidCborTag { tag: 24 }),
            "expected InvalidCborTag{{tag:24}}, got {err:?}"
        );

        // Case 2: tag buried inside a nested array under the claim
        // value. The recursive walk must still catch it.
        let nested_array = ciborium::Value::Array(vec![
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Tag(1, Box::new(ciborium::Value::Integer(2.into()))),
        ]);
        let map = vec![(ciborium::Value::Integer(7.into()), nested_array)];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes)
            .expect("serialize nested tagged claim");
        let err =
            CwtClaims::from_cbor(&bytes).expect_err("nested tagged claim value must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidCborTag { tag: 1 }),
            "expected InvalidCborTag{{tag:1}} for nested tag, got {err:?}"
        );

        // Case 3: tag buried inside a nested map VALUE. Confirms the
        // walker descends through both array and map branches.
        let nested_map = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(99.into()),
            ciborium::Value::Tag(42, Box::new(ciborium::Value::Text("x".into()))),
        )]);
        let map = vec![(ciborium::Value::Integer(7.into()), nested_map)];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes)
            .expect("serialize nested-map tagged claim");
        let err = CwtClaims::from_cbor(&bytes).expect_err("tag inside nested map must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidCborTag { tag: 42 }),
            "expected InvalidCborTag{{tag:42}} for map-nested tag, got {err:?}"
        );
    }

    /// Regression guard: plain (untagged) CBOR values across all
    /// leaf types MUST still decode cleanly after the tag-rejection
    /// helper is added. Covers the full range of kinds fcp-crypto is
    /// likely to carry (text, integer, bytes, bool, null, nested
    /// map, nested array) so a future refactor of `reject_cbor_tags`
    /// that accidentally widens the rejection set is caught here.
    #[test]
    fn test_cwt_claim_plain_value_accepted() {
        let map = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text("issuer-x".into()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Integer(42.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Bytes(vec![0xAA, 0xBB]),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bool(true),
            ),
            (ciborium::Value::Integer(5.into()), ciborium::Value::Null),
            (
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Integer(7.into()),
                    ciborium::Value::Text("item".into()),
                ]),
            ),
            (
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Integer(9.into()),
                    ciborium::Value::Text("nested".into()),
                )]),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes)
            .expect("serialize plain claim map");

        let claims = CwtClaims::from_cbor(&bytes)
            .expect("plain untagged claims must still decode after the tag-refusal change");
        assert_eq!(
            claims.get_issuer(),
            Some("issuer-x"),
            "text claim must round-trip through the post-refusal decode"
        );
    }

    #[test]
    fn cose_token_from_cbor_accepts_payload_at_cap() {
        // A blob exactly at the cap must pass the size check (and fail later
        // on parse, since it's random bytes) — proves the cap is inclusive
        // and isn't off-by-one in the rejection direction.
        let blob = vec![0u8; MAX_COSE_TOKEN_BYTES];
        let err = CoseToken::from_cbor(&blob).expect_err("random bytes won't parse as COSE");
        match err {
            CryptoError::SerializationError(msg) => {
                assert!(
                    !msg.contains("byte cap"),
                    "at-cap payload must fail on CBOR/COSE parse, not the size check: {msg}"
                );
            }
            other => panic!("expected SerializationError for malformed input, got {other:?}"),
        }
    }

    #[test]
    fn cose_token_cbor_roundtrip() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let claims = CwtClaims::new().issuer("test").capability_id("cap:test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let cbor = token.to_cbor().unwrap();
        let parsed = CoseToken::from_cbor(&cbor).unwrap();
        let verified = parsed.verify(&pk).unwrap();

        assert_eq!(verified.get_issuer(), Some("test"));
    }

    // Metamorphic tamper-detection: for a valid signed token, flipping any
    // single byte of the encoded form MUST break verification. Either parse
    // fails outright or verify rejects — we never accept a silently-modified
    // token. Scoped to a reproducible byte stride to stay fast; still broad
    // enough to exercise protected-header, payload, and signature regions.
    #[test]
    fn cose_token_single_byte_flip_fails_verification() {
        let sk = Ed25519SigningKey::from_bytes(&[0x7c; 32]).unwrap();
        let pk = sk.verifying_key();
        let claims = CwtClaims::new()
            .issuer("node:tamper-test")
            .capability_id("cap:tamper")
            .subject("sub:tamper");
        let token = CoseToken::sign(&sk, &claims).unwrap();
        let cbor = token.to_cbor().unwrap();
        assert!(cbor.len() > 16, "encoded token should be non-trivial");

        let stride = (cbor.len() / 16).max(1);
        let mut checked = 0usize;
        for idx in (0..cbor.len()).step_by(stride) {
            let mut mutated = cbor.clone();
            mutated[idx] ^= 0x01;
            if let Ok(reparsed) = CoseToken::from_cbor(&mutated) {
                assert!(
                    reparsed.verify(&pk).is_err(),
                    "byte flip at offset {idx} must break signature verification"
                );
            } else {
                // Structural damage is also an acceptable rejection outcome.
            }
            checked += 1;
        }
        assert!(checked >= 8, "must have probed at least 8 distinct offsets");
    }

    #[test]
    fn cose_token_key_id() {
        let sk = Ed25519SigningKey::generate();
        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let kid_bytes = token.get_key_id().unwrap();
        assert_eq!(kid_bytes.len(), 8);
        assert_eq!(kid_bytes, sk.key_id().as_bytes());
    }

    #[test]
    fn cose_token_verify_with_lookup() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let kid = sk.key_id();

        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let verified = token
            .verify_with_lookup(|k| if k == &kid { Some(pk) } else { None })
            .unwrap();

        assert_eq!(verified.get_issuer(), Some("test"));
    }

    #[test]
    fn token_timing_validation() {
        let now = Utc::now();
        let past = now - Duration::hours(1);
        let future = now + Duration::hours(1);

        // Valid token
        let valid_claims = CwtClaims::new().not_before(past).expiration(future);
        assert!(CoseToken::validate_timing(&valid_claims, now).is_ok());

        // Expired token
        let expired_claims = CwtClaims::new().expiration(past);
        assert!(matches!(
            CoseToken::validate_timing(&expired_claims, now),
            Err(CryptoError::TokenExpired)
        ));

        // Not yet valid
        let future_claims = CwtClaims::new().not_before(future);
        assert!(matches!(
            CoseToken::validate_timing(&future_claims, now),
            Err(CryptoError::TokenNotYetValid)
        ));
    }

    #[test]
    fn capability_token_builder() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let now = Utc::now();
        let expires = now + Duration::hours(24);

        let token = CapabilityTokenBuilder::new()
            .capability_id("cap:discord.send")
            .zone_id("z:work")
            .principal("agent:claude")
            .operations(&["discord.send_message", "discord.read_messages"])
            .issuer("node:primary")
            .validity(now, expires)
            .issued_now()
            .sign(&sk)
            .unwrap();

        let claims = token.verify(&pk).unwrap();
        assert_eq!(claims.get_capability_id(), Some("cap:discord.send"));
        assert_eq!(claims.get_zone_id(), Some("z:work"));

        CoseToken::validate_timing(&claims, now).unwrap();
    }

    #[test]
    fn claims_deterministic_encoding() {
        // Same claims should produce same CBOR
        let claims1 = CwtClaims::new()
            .issuer("test")
            .subject("sub")
            .capability_id("cap");

        let claims2 = CwtClaims::new()
            .capability_id("cap")
            .issuer("test")
            .subject("sub");

        // BTreeMap ensures deterministic order regardless of insertion order
        assert_eq!(claims1.to_cbor().unwrap(), claims2.to_cbor().unwrap());
    }

    /// Build a `CoseSign1` with a caller-chosen protected `Header` and sign it
    /// with `signing_key` over the resulting TBS bytes. Used by the
    /// algorithm-confusion / crit-handling tests below.
    fn build_signed_token(signing_key: &Ed25519SigningKey, header: coset::Header) -> CoseToken {
        let claims = CwtClaims::new()
            .issuer("test")
            .capability_id("cap:test.read");
        let payload = claims.to_cbor().unwrap();
        let mut inner = CoseSign1Builder::new()
            .protected(header)
            .payload(payload)
            .build();
        let tbs = inner.tbs_data(&[]);
        let signature = signing_key.sign(&tbs);
        inner.signature = signature.to_bytes().to_vec();
        CoseToken { inner }
    }

    /// Build a `CoseSign1` with caller-chosen protected and unprotected headers.
    fn build_signed_token_with_unprotected(
        signing_key: &Ed25519SigningKey,
        protected: coset::Header,
        unprotected: coset::Header,
    ) -> CoseToken {
        let claims = CwtClaims::new()
            .issuer("test")
            .capability_id("cap:test.read");
        let payload = claims.to_cbor().unwrap();
        let mut inner = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .build();
        let tbs = inner.tbs_data(&[]);
        let signature = signing_key.sign(&tbs);
        inner.signature = signature.to_bytes().to_vec();
        CoseToken { inner }
    }

    #[test]
    fn verify_rejects_token_with_no_alg_in_protected_header() {
        // RFC 8152 §4.4: alg MUST be present and match what the verifier
        // expects. A token with no alg field (only kid) must be rejected
        // even if the Ed25519 signature is otherwise valid.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let header = HeaderBuilder::new()
            .key_id(sk.key_id().as_bytes().to_vec())
            .build();
        let token = build_signed_token(&sk, header);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::MissingField(ref s) if s.contains("alg")),
            "expected MissingField(alg…), got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_token_with_wrong_algorithm() {
        // Sign with our Ed25519 key but advertise alg=ES256 in the
        // protected header. The TBS bytes still cover alg, so the sig
        // verifies — but the verifier MUST refuse the algorithm mismatch
        // before that point so a future multi-alg key directory cannot be
        // tricked into running the wrong primitive.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(sk.key_id().as_bytes().to_vec())
            .build();
        let token = build_signed_token(&sk, header);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(
                err,
                CryptoError::AlgorithmMismatch {
                    expected: "EdDSA",
                    ..
                }
            ),
            "expected AlgorithmMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_token_with_mismatched_protected_kid() {
        // A token can be syntactically well-formed and signed by the correct
        // key while still carrying a forged protected `kid`. Direct verify()
        // must bind the header hint back to the verifying key so callers do
        // not accept a signature under one key while attributing it to
        // another.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let wrong_kid = Ed25519SigningKey::generate().key_id();
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(wrong_kid.as_bytes().to_vec())
            .build();
        let token = build_signed_token(&sk, header);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyIdMismatch { .. }),
            "expected KeyIdMismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_token_with_unknown_critical_header() {
        // RFC 8152 §3.1: if `crit` lists a header label the recipient does
        // not understand, the message MUST be rejected. Mark a private-use
        // label critical and expect rejection even though signing succeeds.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(sk.key_id().as_bytes().to_vec())
            .add_critical_label(RegisteredLabelWithPrivate::PrivateUse(-99_999))
            .build();
        let token = build_signed_token(&sk, header);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::UnsupportedCriticalHeader(_)),
            "expected UnsupportedCriticalHeader, got {err:?}"
        );
    }

    #[test]
    fn verify_accepts_alg_kid_in_crit_when_understood() {
        // crit listing only labels the verifier handles is permitted.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(sk.key_id().as_bytes().to_vec())
            .add_critical(iana::HeaderParameter::Alg)
            .add_critical(iana::HeaderParameter::Kid)
            .build();
        let token = build_signed_token(&sk, header);
        token.verify(&pk).expect("verify should succeed");
    }

    #[test]
    fn verify_rejects_token_with_unprotected_alg() {
        // RFC 9052 requires alg to be authenticated where possible. COSE_Sign1
        // has protected headers, so a second unprotected alg is an ambiguity we
        // reject rather than silently preferring one bucket.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(sk.key_id().as_bytes().to_vec())
            .build();
        let unprotected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let token = build_signed_token_with_unprotected(&sk, protected, unprotected);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::HeaderPolicyViolation(ref s) if s.contains("alg")),
            "expected HeaderPolicyViolation(alg…), got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_token_with_unprotected_kid() {
        // Bare COSE treats kid as a hint, but FCP routes by protected kid.
        // Reject a second unprotected kid to avoid key-selection ambiguity.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(sk.key_id().as_bytes().to_vec())
            .build();
        let unprotected = HeaderBuilder::new()
            .key_id(Ed25519SigningKey::generate().key_id().as_bytes().to_vec())
            .build();
        let token = build_signed_token_with_unprotected(&sk, protected, unprotected);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::HeaderPolicyViolation(ref s) if s.contains("kid")),
            "expected HeaderPolicyViolation(kid…), got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_token_with_unprotected_crit() {
        // RFC 9052 §3.1: crit itself must be integrity protected.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(sk.key_id().as_bytes().to_vec())
            .build();
        let unprotected = HeaderBuilder::new()
            .add_critical(iana::HeaderParameter::Kid)
            .build();
        let token = build_signed_token_with_unprotected(&sk, protected, unprotected);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::HeaderPolicyViolation(ref s) if s.contains("crit")),
            "expected HeaderPolicyViolation(crit…), got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_crit_label_missing_from_protected_bucket() {
        // RFC 9052 §3.1: if crit lists a label that is not actually present in
        // the protected header bucket, processing must fail.
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .add_critical(iana::HeaderParameter::Kid)
            .build();
        let token = build_signed_token(&sk, header);
        let err = token.verify(&pk).unwrap_err();
        assert!(
            matches!(err, CryptoError::HeaderPolicyViolation(ref s) if s.contains("crit")),
            "expected HeaderPolicyViolation(crit…), got {err:?}"
        );
    }

    // ---- CwtClaims builder coverage ----

    #[test]
    fn cwt_claims_audience() {
        let claims = CwtClaims::new().audience("aud:mesh");
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(cwt_claims::AUD).unwrap() {
            ciborium::Value::Text(s) => assert_eq!(s, "aud:mesh"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_token_id() {
        let cti = b"unique-id-123";
        let claims = CwtClaims::new().token_id(cti);
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        assert_eq!(parsed.get_jti(), Some(cti.as_slice()));
    }

    #[test]
    fn cwt_claims_issued_at_roundtrip() {
        let now = Utc::now();
        let claims = CwtClaims::new().issued_at(now);
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(cwt_claims::IAT).unwrap() {
            ciborium::Value::Integer(i) => {
                assert_eq!(i64::try_from(*i).unwrap(), now.timestamp());
            }
            other => panic!("expected integer, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_expiration_roundtrip() {
        let exp = Utc::now() + Duration::hours(2);
        let claims = CwtClaims::new().expiration(exp);
        assert_eq!(claims.get_expiration(), Some(exp.timestamp()));
    }

    #[test]
    fn cwt_claims_not_before_roundtrip() {
        let nbf = Utc::now() - Duration::minutes(5);
        let claims = CwtClaims::new().not_before(nbf);
        assert_eq!(claims.get_not_before(), Some(nbf.timestamp()));
    }

    #[test]
    fn cwt_claims_holder_node_roundtrip() {
        let claims = CwtClaims::new().holder_node("node:holder-1");
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        assert_eq!(parsed.get_holder_node(), Some("node:holder-1"));
    }

    #[test]
    fn cwt_claims_audience_binary() {
        let oid = b"\x01\x02\x03\x04";
        let claims = CwtClaims::new().audience_binary(oid);
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(fcp2_claims::AUD_BINARY).unwrap() {
            ciborium::Value::Bytes(b) => assert_eq!(b.as_slice(), oid.as_slice()),
            other => panic!("expected bytes, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_grant_objects() {
        let obj1 = b"\xaa\xbb";
        let obj2 = b"\xcc\xdd";
        let claims = CwtClaims::new().grant_objects(&[obj1, obj2]);
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(fcp2_claims::GRANT_OBJECT_IDS).unwrap() {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 2);
            }
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_checkpoint() {
        let chk_id = b"\x01\x02\x03";
        let claims = CwtClaims::new().checkpoint(chk_id, 42);
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(fcp2_claims::CHK_ID).unwrap() {
            ciborium::Value::Bytes(b) => assert_eq!(b.as_slice(), chk_id.as_slice()),
            other => panic!("expected bytes, got {other:?}"),
        }
        match parsed.get(fcp2_claims::CHK_SEQ).unwrap() {
            ciborium::Value::Integer(i) => assert_eq!(i64::try_from(*i).unwrap(), 42),
            other => panic!("expected integer, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_operations_roundtrip() {
        let claims = CwtClaims::new().operations(&["read", "write", "delete"]);
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(fcp2_claims::OPERATIONS).unwrap() {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 3);
                match &arr[0] {
                    ciborium::Value::Text(s) => assert_eq!(s, "read"),
                    other => panic!("expected text, got {other:?}"),
                }
            }
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_custom_claim() {
        let claims = CwtClaims::new().custom(-99999, ciborium::Value::Bool(true));
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        match parsed.get(-99999).unwrap() {
            ciborium::Value::Bool(b) => assert!(b),
            other => panic!("expected bool, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_to_cbor_uses_rfc8949_integer_key_order() {
        let claims = CwtClaims::new()
            .custom(
                fcp2_claims::SCHEMA_VERSION,
                ciborium::Value::Integer(1.into()),
            )
            .custom(fcp2_claims::ZONE_ID, ciborium::Value::Text("z:work".into()))
            .custom(
                fcp2_claims::CAPABILITY_ID,
                ciborium::Value::Text("cap:test".into()),
            )
            .issuer("issuer-x")
            .issued_at(Utc::now());

        let cbor = claims.to_cbor().unwrap();
        let value: ciborium::Value = ciborium::from_reader(&cbor[..]).unwrap();
        let ciborium::Value::Map(entries) = value else {
            panic!("expected map");
        };
        let keys: Vec<i64> = entries
            .iter()
            .map(|(k, _)| match k {
                ciborium::Value::Integer(i) => i64::try_from(*i).expect("claim labels fit i64"),
                other => panic!("expected integer key, got {other:?}"),
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                cwt_claims::ISS,
                cwt_claims::IAT,
                fcp2_claims::CAPABILITY_ID,
                fcp2_claims::ZONE_ID,
                fcp2_claims::SCHEMA_VERSION,
            ]
        );
    }

    #[test]
    fn cwt_claims_from_cbor_rejects_old_numeric_label_ordering() {
        let map = vec![
            (
                ciborium::Value::Integer(fcp2_claims::SCHEMA_VERSION.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(fcp2_claims::ZONE_ID.into()),
                ciborium::Value::Text("z:work".into()),
            ),
            (
                ciborium::Value::Integer(fcp2_claims::CAPABILITY_ID.into()),
                ciborium::Value::Text("cap:test".into()),
            ),
            (
                ciborium::Value::Integer(cwt_claims::ISS.into()),
                ciborium::Value::Text("issuer-x".into()),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes).unwrap();

        let err = CwtClaims::from_cbor(&bytes).expect_err("must reject non-canonical payload");
        assert!(err.to_string().contains("non-canonical CBOR encoding"));
    }

    #[test]
    fn cwt_claims_roundtrip_reserialize_is_byte_identical() {
        let claims = CwtClaims::new()
            .custom(
                fcp2_claims::SCHEMA_VERSION,
                ciborium::Value::Integer(1.into()),
            )
            .custom(fcp2_claims::ZONE_ID, ciborium::Value::Text("z:work".into()))
            .custom(
                fcp2_claims::CAPABILITY_ID,
                ciborium::Value::Text("cap:test".into()),
            )
            .issuer("issuer-x")
            .issued_at(Utc::now());

        let encoded = claims.to_cbor().unwrap();
        let decoded = CwtClaims::from_cbor(&encoded).unwrap();
        let reencoded = decoded.to_cbor().unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn cwt_claims_get_missing_returns_none() {
        let claims = CwtClaims::new();
        assert!(claims.get_issuer().is_none());
        assert!(claims.get_subject().is_none());
        assert!(claims.get_expiration().is_none());
        assert!(claims.get_not_before().is_none());
        assert!(claims.get_capability_id().is_none());
        assert!(claims.get_zone_id().is_none());
        assert!(claims.get_holder_node().is_none());
        assert!(claims.get_jti().is_none());
    }

    #[test]
    fn cwt_claims_get_wrong_type_returns_none() {
        // Store an integer where a string is expected
        let claims = CwtClaims::new().custom(cwt_claims::ISS, ciborium::Value::Integer(42.into()));
        assert!(claims.get_issuer().is_none());
    }

    // ---- from_cbor error paths ----

    #[test]
    fn cwt_claims_from_cbor_not_map() {
        // Encode an array instead of a map
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Array(vec![]), &mut bytes).unwrap();
        let err = CwtClaims::from_cbor(&bytes).unwrap_err();
        assert!(err.to_string().contains("expected CBOR map"));
    }

    #[test]
    fn cwt_claims_from_cbor_non_integer_key() {
        let map = vec![(
            ciborium::Value::Text("bad-key".into()),
            ciborium::Value::Bool(true),
        )];
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut bytes).unwrap();
        let err = CwtClaims::from_cbor(&bytes).unwrap_err();
        assert!(err.to_string().contains("claim key must be integer"));
    }

    #[test]
    fn cwt_claims_from_cbor_invalid_bytes() {
        let err = CwtClaims::from_cbor(&[0xff, 0xff]).unwrap_err();
        assert!(matches!(err, CryptoError::SerializationError(_)));
    }

    // ---- CoseToken additional coverage ----

    #[test]
    fn cose_token_claims_unverified() {
        let sk = Ed25519SigningKey::generate();
        let claims = CwtClaims::new()
            .issuer("test-unverified")
            .capability_id("cap:test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        // Should work without needing the public key
        let unverified = token.claims_unverified().unwrap();
        assert_eq!(unverified.get_issuer(), Some("test-unverified"));
        assert_eq!(unverified.get_capability_id(), Some("cap:test"));
    }

    #[test]
    fn cose_token_from_cbor_invalid() {
        let err = CoseToken::from_cbor(&[0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(err, CryptoError::SerializationError(_)));
    }

    #[test]
    fn cose_token_from_cbor_accepts_tagged_sign1() {
        let sk = Ed25519SigningKey::generate();
        let claims = CwtClaims::new()
            .issuer("tagged-issuer")
            .subject("tagged-subject")
            .capability_id("cap:test");
        let token = CoseToken::sign(&sk, &claims).unwrap();
        let tagged = token.inner.to_tagged_vec().unwrap();

        let parsed = CoseToken::from_cbor(&tagged).unwrap();
        let claims = parsed.claims_unverified().unwrap();
        assert_eq!(claims.get_issuer(), Some("tagged-issuer"));
        assert_eq!(claims.get_subject(), Some("tagged-subject"));
        assert_eq!(claims.get_capability_id(), Some("cap:test"));
    }

    #[test]
    fn cose_token_verify_with_lookup_wrong_key() {
        let sk = Ed25519SigningKey::generate();
        let sk2 = Ed25519SigningKey::generate();
        let pk2 = sk2.verifying_key();
        let kid = sk.key_id();

        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        // Lookup returns a different key — verification should fail
        let err = token
            .verify_with_lookup(|k| if k == &kid { Some(pk2) } else { None })
            .unwrap_err();
        assert!(matches!(err, CryptoError::KeyIdMismatch { .. }));
    }

    #[test]
    fn cose_token_verify_with_lookup_key_not_found() {
        let sk = Ed25519SigningKey::generate();
        let claims = CwtClaims::new().issuer("test");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        // Lookup always returns None
        let err = token.verify_with_lookup(|_| None).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyId(_)));
    }

    #[test]
    fn verify_with_lookup_rejects_wrong_algorithm_before_key_lookup() {
        let sk = Ed25519SigningKey::generate();
        let header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(sk.key_id().as_bytes().to_vec())
            .build();
        let token = build_signed_token(&sk, header);
        let lookup_called = Cell::new(false);

        let err = token
            .verify_with_lookup(|_| {
                lookup_called.set(true);
                Some(sk.verifying_key())
            })
            .unwrap_err();

        assert!(matches!(err, CryptoError::AlgorithmMismatch { .. }));
        assert!(
            !lookup_called.get(),
            "malformed alg must fail before key lookup"
        );
    }

    // ---- validate_timing edge cases ----

    #[test]
    fn validate_timing_no_claims_passes() {
        // Token with no exp or nbf should pass timing validation
        let claims = CwtClaims::new().issuer("test");
        assert!(CoseToken::validate_timing(&claims, Utc::now()).is_ok());
    }

    #[test]
    fn validate_timing_exactly_at_expiration_fails() {
        // now >= exp should fail (boundary)
        let now = Utc::now();
        let claims = CwtClaims::new().expiration(now);
        assert!(matches!(
            CoseToken::validate_timing(&claims, now),
            Err(CryptoError::TokenExpired)
        ));
    }

    #[test]
    fn validate_timing_just_before_expiration_passes() {
        let now = Utc::now();
        let exp = now + Duration::seconds(1);
        let claims = CwtClaims::new().expiration(exp);
        assert!(CoseToken::validate_timing(&claims, now).is_ok());
    }

    #[test]
    fn validate_timing_exactly_at_nbf_passes() {
        // now >= nbf should pass (boundary)
        let now = Utc::now();
        let claims = CwtClaims::new().not_before(now);
        assert!(CoseToken::validate_timing(&claims, now).is_ok());
    }

    // ---- CapabilityTokenBuilder coverage ----

    #[test]
    fn capability_token_builder_default() {
        let b1 = CapabilityTokenBuilder::new();
        let b2 = CapabilityTokenBuilder::default();
        // Both produce empty claims
        assert!(b1.claims.get_issuer().is_none());
        assert!(b2.claims.get_issuer().is_none());
    }

    #[test]
    fn capability_token_builder_with_checkpoint() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let token = CapabilityTokenBuilder::new()
            .capability_id("cap:test")
            .zone_id("z:work")
            .principal("user:test")
            .issuing_node("node:primary")
            .checkpoint(b"\x01\x02", 7)
            .issuer("node:primary")
            .validity(Utc::now(), Utc::now() + Duration::hours(1))
            .sign(&sk)
            .unwrap();

        let claims = token.verify(&pk).unwrap();
        assert_eq!(claims.get_capability_id(), Some("cap:test"));
        match claims.get(fcp2_claims::CHK_SEQ).unwrap() {
            ciborium::Value::Integer(i) => assert_eq!(i64::try_from(*i).unwrap(), 7),
            other => panic!("expected integer, got {other:?}"),
        }
    }

    #[test]
    fn capability_token_builder_issued_now_sets_iat() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let before = Utc::now().timestamp();

        let token = CapabilityTokenBuilder::new()
            .capability_id("cap:test")
            .issued_now()
            .sign(&sk)
            .unwrap();

        let claims = token.verify(&pk).unwrap();
        match claims.get(cwt_claims::IAT).unwrap() {
            ciborium::Value::Integer(i) => {
                let iat = i64::try_from(*i).unwrap();
                assert!(iat >= before);
            }
            other => panic!("expected integer, got {other:?}"),
        }
    }

    // ---- Claim key constants ----

    #[test]
    fn cwt_claim_keys_are_positive() {
        const _: () = {
            assert!(cwt_claims::ISS > 0);
            assert!(cwt_claims::SUB > 0);
            assert!(cwt_claims::AUD > 0);
            assert!(cwt_claims::EXP > 0);
            assert!(cwt_claims::NBF > 0);
            assert!(cwt_claims::IAT > 0);
            assert!(cwt_claims::CTI > 0);
        };
    }

    #[test]
    fn fcp2_claim_keys_are_negative() {
        const _: () = {
            assert!(fcp2_claims::CAPABILITY_ID < 0);
            assert!(fcp2_claims::ZONE_ID < 0);
            assert!(fcp2_claims::OPERATIONS < 0);
            assert!(fcp2_claims::PRINCIPAL_ID < 0);
            assert!(fcp2_claims::DELEGATION_DEPTH < 0);
            assert!(fcp2_claims::PARENT_TOKEN < 0);
            assert!(fcp2_claims::ISS_NODE < 0);
            assert!(fcp2_claims::AUD_BINARY < 0);
            assert!(fcp2_claims::GRANT_OBJECT_IDS < 0);
            assert!(fcp2_claims::HOLDER_NODE < 0);
            assert!(fcp2_claims::CHK_ID < 0);
            assert!(fcp2_claims::CHK_SEQ < 0);
            assert!(fcp2_claims::CONSTRAINTS < 0);
            assert!(fcp2_claims::GRANTS < 0);
            assert!(fcp2_claims::INSTANCE_ID < 0);
        };
    }

    #[test]
    fn fcp2_claim_keys_are_unique() {
        let keys = [
            fcp2_claims::CAPABILITY_ID,
            fcp2_claims::ZONE_ID,
            fcp2_claims::OPERATIONS,
            fcp2_claims::PRINCIPAL_ID,
            fcp2_claims::DELEGATION_DEPTH,
            fcp2_claims::PARENT_TOKEN,
            fcp2_claims::ISS_NODE,
            fcp2_claims::AUD_BINARY,
            fcp2_claims::GRANT_OBJECT_IDS,
            fcp2_claims::HOLDER_NODE,
            fcp2_claims::CHK_ID,
            fcp2_claims::CHK_SEQ,
            fcp2_claims::CONSTRAINTS,
            fcp2_claims::GRANTS,
            fcp2_claims::INSTANCE_ID,
        ];
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), keys.len(), "duplicate claim keys detected");
    }

    // ---- COSE_ALG_EDDSA constant ----

    #[test]
    fn cose_alg_eddsa_value() {
        // EdDSA is IANA algorithm -8
        assert_eq!(COSE_ALG_EDDSA, -8);
    }

    // ---- CwtClaims overwrite ----

    #[test]
    fn cwt_claims_overwrite_replaces_value() {
        let claims = CwtClaims::new().issuer("first").issuer("second");
        assert_eq!(claims.get_issuer(), Some("second"));
    }

    // ---- Multiple claims combined ----

    #[test]
    fn cwt_claims_all_standard_claims() {
        let now = Utc::now();
        let exp = now + Duration::hours(1);
        let claims = CwtClaims::new()
            .issuer("iss")
            .subject("sub")
            .audience("aud")
            .expiration(exp)
            .not_before(now)
            .issued_at(now)
            .token_id(b"tid")
            .capability_id("cap:all")
            .zone_id("z:all")
            .operations(&["op1"])
            .principal_id("p:test")
            .issuing_node("node:1")
            .holder_node("node:2");

        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();

        assert_eq!(parsed.get_issuer(), Some("iss"));
        assert_eq!(parsed.get_subject(), Some("sub"));
        assert_eq!(parsed.get_expiration(), Some(exp.timestamp()));
        assert_eq!(parsed.get_not_before(), Some(now.timestamp()));
        assert_eq!(parsed.get_capability_id(), Some("cap:all"));
        assert_eq!(parsed.get_zone_id(), Some("z:all"));
        assert_eq!(parsed.get_holder_node(), Some("node:2"));
        assert_eq!(parsed.get_jti(), Some(b"tid".as_slice()));
    }

    // ---- CoseToken sign→cbor→parse→verify full chain ----

    #[test]
    fn cose_token_full_chain_with_all_fcp2_claims() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let now = Utc::now();
        let claims = CwtClaims::new()
            .issuer("node:origin")
            .capability_id("cap:mesh.replicate")
            .zone_id("z:prod")
            .principal_id("agent:worker")
            .operations(&["replicate", "checkpoint"])
            .holder_node("node:holder-x")
            .checkpoint(b"\xde\xad", 99)
            .not_before(now - Duration::seconds(10))
            .expiration(now + Duration::hours(1))
            .token_id(b"tok-001");

        let token = CoseToken::sign(&sk, &claims).unwrap();
        let cbor = token.to_cbor().unwrap();
        let restored = CoseToken::from_cbor(&cbor).unwrap();
        let verified = restored.verify(&pk).unwrap();

        assert_eq!(verified.get_issuer(), Some("node:origin"));
        assert_eq!(verified.get_capability_id(), Some("cap:mesh.replicate"));
        assert_eq!(verified.get_holder_node(), Some("node:holder-x"));
        CoseToken::validate_timing(&verified, now).unwrap();
    }

    // ---- CwtClaims clone ----

    #[test]
    fn cwt_claims_clone_preserves_all_fields() {
        let claims = CwtClaims::new()
            .issuer("iss")
            .capability_id("cap:test")
            .zone_id("z:clone");
        let cloned = claims.clone();
        assert_eq!(cloned.get_issuer(), claims.get_issuer());
        assert_eq!(cloned.get_capability_id(), claims.get_capability_id());
        assert_eq!(cloned.get_zone_id(), claims.get_zone_id());
    }

    // ---- CwtClaims debug ----

    #[test]
    fn cwt_claims_debug_format() {
        let claims = CwtClaims::new().issuer("test-debug");
        let debug = format!("{claims:?}");
        assert!(debug.contains("CwtClaims"));
    }

    // ---- CwtClaims serde json roundtrip ----

    #[test]
    fn cwt_claims_serde_json_roundtrip() {
        let claims = CwtClaims::new()
            .issuer("json-iss")
            .capability_id("cap:json");
        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: CwtClaims = serde_json::from_str(&json).unwrap();
        // Access through CBOR roundtrip to verify
        let cbor1 = claims.to_cbor().unwrap();
        let cbor2 = deserialized.to_cbor().unwrap();
        assert_eq!(cbor1, cbor2);
    }

    // ---- CoseToken clone ----

    #[test]
    fn cose_token_clone_verifiable() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let claims = CwtClaims::new().issuer("clone-test");
        let token = CoseToken::sign(&sk, &claims).unwrap();
        let cloned = token.clone();
        // Both should verify
        let v1 = token.verify(&pk).unwrap();
        let v2 = cloned.verify(&pk).unwrap();
        assert_eq!(v1.get_issuer(), v2.get_issuer());
    }

    // ---- CoseToken debug ----

    #[test]
    fn cose_token_debug_format() {
        let sk = Ed25519SigningKey::generate();
        let claims = CwtClaims::new().issuer("debug");
        let token = CoseToken::sign(&sk, &claims).unwrap();
        let debug = format!("{token:?}");
        assert!(debug.contains("CoseToken"));
    }

    // ---- CwtClaims empty CBOR roundtrip ----

    #[test]
    fn cwt_claims_empty_cbor_roundtrip() {
        let claims = CwtClaims::new();
        let cbor = claims.to_cbor().unwrap();
        let parsed = CwtClaims::from_cbor(&cbor).unwrap();
        assert!(parsed.get_issuer().is_none());
        assert!(parsed.get_capability_id().is_none());
    }

    // ---- Token with unicode claims ----

    #[test]
    fn cose_token_unicode_claims() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let claims = CwtClaims::new()
            .issuer("nœud:primaire")
            .capability_id("cap:réseau.lire");
        let token = CoseToken::sign(&sk, &claims).unwrap();
        let verified = token.verify(&pk).unwrap();
        assert_eq!(verified.get_issuer(), Some("nœud:primaire"));
        assert_eq!(verified.get_capability_id(), Some("cap:réseau.lire"));
    }

    // ---- Token CBOR double roundtrip ----

    #[test]
    fn cose_token_double_cbor_roundtrip() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let claims = CwtClaims::new().issuer("double");
        let token = CoseToken::sign(&sk, &claims).unwrap();

        let cbor1 = token.to_cbor().unwrap();
        let parsed1 = CoseToken::from_cbor(&cbor1).unwrap();
        let cbor2 = parsed1.to_cbor().unwrap();
        let parsed2 = CoseToken::from_cbor(&cbor2).unwrap();

        let verified = parsed2.verify(&pk).unwrap();
        assert_eq!(verified.get_issuer(), Some("double"));
    }

    #[test]
    fn cwt_claims_rejects_duplicate_keys() {
        use ciborium::value::Value;
        // Construct CBOR map with duplicate keys: {1: "a", 1: "b"}
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("a".into())),
            (Value::Integer(1.into()), Value::Text("b".into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&map, &mut bytes).unwrap();

        let err = CwtClaims::from_cbor(&bytes).unwrap_err();
        assert!(err.to_string().contains("duplicate claim key: 1"));
    }

    // ── br-zp1xx: constraints_cbor panic -> fallible variant ──────────

    #[test]
    fn cwt_claims_try_constraints_cbor_rejects_malformed_cbor() {
        // Arbitrary non-CBOR bytes (0xFF is a CBOR "break" stop byte
        // outside any indefinite-length context, which ciborium
        // refuses at the top level).
        let garbage = vec![0xFF, 0xDE, 0xAD, 0xBE, 0xEF];
        let err = CwtClaims::new()
            .try_constraints_cbor(&garbage)
            .expect_err("malformed CBOR must yield an error, not a panic");
        match err {
            CryptoError::SerializationError(msg) => {
                assert!(
                    msg.contains("constraints_cbor"),
                    "error must name the field: {msg}"
                );
                assert!(
                    msg.contains("invalid CBOR"),
                    "error must describe cause: {msg}"
                );
            }
            other => panic!("expected SerializationError, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_try_constraints_cbor_accepts_valid_cbor() {
        // A well-formed CBOR map should round-trip without error.
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Map(vec![(
                ciborium::Value::Text("resource_allow".into()),
                ciborium::Value::Array(vec![ciborium::Value::Text("*".into())]),
            )]),
            &mut bytes,
        )
        .expect("serialize valid constraints");
        let claims = CwtClaims::new()
            .try_constraints_cbor(&bytes)
            .expect("valid CBOR must succeed");
        assert!(claims.get(fcp2_claims::CONSTRAINTS).is_some());
    }

    #[test]
    fn capability_token_builder_try_constraints_cbor_rejects_malformed_cbor() {
        // The builder wrapper delegates to CwtClaims::try_constraints_cbor
        // and MUST propagate the same typed error without panicking.
        let garbage = vec![0xFF, 0x00, 0xFF, 0x00];
        let result = CapabilityTokenBuilder::new().try_constraints_cbor(&garbage);
        match result {
            Ok(_) => panic!("builder wrapper must fail closed on malformed CBOR"),
            Err(CryptoError::SerializationError(msg)) => {
                assert!(
                    msg.contains("invalid CBOR"),
                    "error must describe cause: {msg}"
                );
            }
            Err(other) => panic!("expected SerializationError, got {other:?}"),
        }
    }

    #[test]
    fn cwt_claims_constraints_cbor_legacy_shim_skips_malformed_without_panic() {
        // The deprecated panicking variant now warn-and-skips so a
        // caller stuck on the old API no longer aborts the process.
        // The resulting token carries no constraints claim — which the
        // verifier's C3.4 constraints-required gate will reject at
        // verify time, strictly better than a panic here.
        let garbage = vec![0xFF, 0xFF];
        #[allow(deprecated)]
        let claims = CwtClaims::new().issuer("test").constraints_cbor(&garbage);
        assert!(claims.get(fcp2_claims::CONSTRAINTS).is_none());
        assert_eq!(claims.get_issuer(), Some("test"));
    }
}
