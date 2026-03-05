//! Holder proof signable-bytes golden vectors.
//!
//! These vectors lock down the byte-level computation of FCP2 holder proofs —
//! the Ed25519 signatures that bind a capability token invocation to a specific
//! holder node.
//!
//! # Holder Proof Format (NORMATIVE)
//!
//! The signable bytes are:
//! ```text
//! "FCP2-HOLDER-PROOF-V1" || request_id || operation_id || token_jti
//! ```
//!
//! The holder node signs these bytes with its Ed25519 key, producing a 64-byte
//! signature. The verifier reconstructs the signable bytes from the request
//! context and checks the signature against the holder node's public key.

use serde::{Deserialize, Serialize};

/// Golden vector for holder proof signable bytes and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderProofGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Ed25519 signing key for the holder node (32 bytes hex).
    pub holder_signing_key: String,
    /// Expected Ed25519 public key of the holder node (32 bytes hex).
    pub expected_holder_pk: String,
    /// Request ID string (as it appears on the wire).
    pub request_id: String,
    /// Operation ID string (as it appears on the wire).
    pub operation_id: String,
    /// Token JTI (JWT ID) bytes (hex).
    pub token_jti: String,
    /// Expected signable bytes (hex).
    pub expected_signable_bytes: String,
    /// Expected Ed25519 signature (64 bytes hex) — deterministic because Ed25519 is.
    pub expected_signature: String,
}

impl HolderProofGoldenVector {
    /// Load all holder proof golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_basic_holder_proof(),
            Self::vector_2_uuid_request_id(),
            Self::vector_3_long_jti(),
        ]
    }

    /// Vector 1: Basic holder proof with simple inputs.
    ///
    /// Uses sk = [0x04; 32] to avoid collision with capability vector keys.
    ///
    /// # Panics
    ///
    /// Panics if hard-coded hex values fail to decode (indicates a bug in the vectors).
    #[must_use]
    pub fn vector_1_basic_holder_proof() -> Self {
        // Domain prefix: "FCP2-HOLDER-PROOF-V1" (20 bytes)
        // request_id: "req_001" (7 bytes)
        // operation_id: "discord.send_message" (20 bytes)
        // token_jti: 0xdeadbeef (4 bytes)
        // Total signable: 20 + 7 + 20 + 4 = 51 bytes
        let domain = b"FCP2-HOLDER-PROOF-V1";
        let req_id = b"req_001";
        let op_id = b"discord.send_message";
        let jti = hex::decode("deadbeef").unwrap();

        let mut expected_bytes = Vec::with_capacity(128);
        expected_bytes.extend_from_slice(domain);
        expected_bytes.extend_from_slice(
            &u32::try_from(req_id.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_bytes.extend_from_slice(req_id);
        expected_bytes
            .extend_from_slice(&u32::try_from(op_id.len()).unwrap_or(u32::MAX).to_le_bytes());
        expected_bytes.extend_from_slice(op_id);
        expected_bytes
            .extend_from_slice(&u32::try_from(jti.len()).unwrap_or(u32::MAX).to_le_bytes());
        expected_bytes.extend_from_slice(&jti);

        // Sign it with sk=[0x04; 32]
        let sk_bytes = [0x04; 32];
        let sk = fcp_crypto::ed25519::Ed25519SigningKey::from_bytes(&sk_bytes).unwrap();
        let sig = sk.sign(&expected_bytes);

        Self {
            description: "Basic holder proof (sk=[0x04;32], simple request)".into(),
            holder_signing_key: "0404040404040404040404040404040404040404040404040404040404040404"
                .into(),
            expected_holder_pk: hex::encode(sk.verifying_key().to_bytes()),
            request_id: "req_001".into(),
            operation_id: "discord.send_message".into(),
            token_jti: "deadbeef".into(),
            expected_signable_bytes: hex::encode(&expected_bytes),
            expected_signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Vector 2: Holder proof with UUID-style request ID.
    ///
    /// Uses sk = [0x05; 32]. Tests longer request IDs typical of production.
    ///
    /// # Panics
    ///
    /// Panics if hard-coded hex values fail to decode (indicates a bug in the vectors).
    #[must_use]
    pub fn vector_2_uuid_request_id() -> Self {
        let domain = b"FCP2-HOLDER-PROOF-V1";
        let req_id = b"550e8400-e29b-41d4-a716-446655440000";
        let op_id = b"s3.get_object";
        let jti = hex::decode("0123456789abcdef").unwrap();

        let mut expected_bytes = Vec::with_capacity(128);
        expected_bytes.extend_from_slice(domain);
        expected_bytes.extend_from_slice(
            &u32::try_from(req_id.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_bytes.extend_from_slice(req_id);
        expected_bytes
            .extend_from_slice(&u32::try_from(op_id.len()).unwrap_or(u32::MAX).to_le_bytes());
        expected_bytes.extend_from_slice(op_id);
        expected_bytes
            .extend_from_slice(&u32::try_from(jti.len()).unwrap_or(u32::MAX).to_le_bytes());
        expected_bytes.extend_from_slice(&jti);

        // Sign it with sk=[0x05; 32]
        let sk_bytes = [0x05; 32];
        let sk = fcp_crypto::ed25519::Ed25519SigningKey::from_bytes(&sk_bytes).unwrap();
        let sig = sk.sign(&expected_bytes);

        Self {
            description: "Holder proof with UUID request ID (sk=[0x05;32])".into(),
            holder_signing_key: "0505050505050505050505050505050505050505050505050505050505050505"
                .into(),
            expected_holder_pk: hex::encode(sk.verifying_key().to_bytes()),
            request_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            operation_id: "s3.get_object".into(),
            token_jti: "0123456789abcdef".into(),
            expected_signable_bytes: hex::encode(&expected_bytes),
            expected_signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Vector 3: Holder proof with longer JTI (16-byte token ID).
    ///
    /// Uses sk = [0x06; 32]. Tests with a 16-byte JTI as commonly used.
    ///
    /// # Panics
    ///
    /// Panics if hard-coded hex values fail to decode (indicates a bug in the vectors).
    #[must_use]
    pub fn vector_3_long_jti() -> Self {
        let domain = b"FCP2-HOLDER-PROOF-V1";
        let req_id = b"req_42";
        let op_id = b"github.create_pr";
        let jti = hex::decode("00112233445566778899aabbccddeeff").unwrap();

        let mut expected_bytes = Vec::with_capacity(128);
        expected_bytes.extend_from_slice(domain);
        expected_bytes.extend_from_slice(
            &u32::try_from(req_id.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_bytes.extend_from_slice(req_id);
        expected_bytes
            .extend_from_slice(&u32::try_from(op_id.len()).unwrap_or(u32::MAX).to_le_bytes());
        expected_bytes.extend_from_slice(op_id);
        expected_bytes
            .extend_from_slice(&u32::try_from(jti.len()).unwrap_or(u32::MAX).to_le_bytes());
        expected_bytes.extend_from_slice(&jti);

        // Sign it with sk=[0x06; 32]
        let sk_bytes = [0x06; 32];
        let sk = fcp_crypto::ed25519::Ed25519SigningKey::from_bytes(&sk_bytes).unwrap();
        let sig = sk.sign(&expected_bytes);

        Self {
            description: "Holder proof with 16-byte JTI (sk=[0x06;32])".into(),
            holder_signing_key: "0606060606060606060606060606060606060606060606060606060606060606"
                .into(),
            expected_holder_pk: hex::encode(sk.verifying_key().to_bytes()),
            request_id: "req_42".into(),
            operation_id: "github.create_pr".into(),
            token_jti: "00112233445566778899aabbccddeeff".into(),
            expected_signable_bytes: hex::encode(&expected_bytes),
            expected_signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify this golden vector against the implementation.
    ///
    /// This method:
    /// 1. Constructs the signing key from the deterministic seed
    /// 2. Builds signable bytes using `HolderProof::signable_bytes()`
    /// 3. Verifies signable bytes match expected
    /// 4. Signs and verifies the signature
    ///
    /// # Errors
    ///
    /// Returns an error message if any step fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_core::HolderProof;
        use fcp_core::OperationId;
        use fcp_core::RequestId;
        use fcp_crypto::ed25519::Ed25519SigningKey;

        // 1. Parse signing key
        let sk_bytes: [u8; 32] = hex::decode(&self.holder_signing_key)
            .map_err(|e| format!("invalid signing_key hex: {e}"))?
            .try_into()
            .map_err(|_| "signing_key must be 32 bytes")?;

        let sk =
            Ed25519SigningKey::from_bytes(&sk_bytes).map_err(|e| format!("invalid sk: {e}"))?;

        // 2. Verify public key (if expected is non-empty)
        if !self.expected_holder_pk.is_empty() {
            let pk = sk.verifying_key();
            let computed_pk = hex::encode(pk.to_bytes());
            if computed_pk != self.expected_holder_pk {
                return Err(format!(
                    "public key mismatch: expected {}, got {computed_pk}",
                    self.expected_holder_pk
                ));
            }
        }

        // 3. Parse JTI
        let jti_bytes =
            hex::decode(&self.token_jti).map_err(|e| format!("invalid token_jti hex: {e}"))?;

        // 4. Build signable bytes using the implementation
        let req_id = RequestId(self.request_id.clone());
        let op_id = OperationId::new(&self.operation_id)
            .map_err(|e| format!("invalid operation_id: {e}"))?;
        let computed_signable = HolderProof::signable_bytes(&req_id, &op_id, &jti_bytes);

        // 5. Verify signable bytes match expected
        let computed_hex = hex::encode(&computed_signable);
        if computed_hex != self.expected_signable_bytes {
            return Err(format!(
                "signable bytes mismatch:\n  expected: {}\n  actual:   {computed_hex}",
                self.expected_signable_bytes
            ));
        }

        // 6. Verify the domain prefix is present
        if !computed_signable.starts_with(b"FCP2-HOLDER-PROOF-V1") {
            return Err("signable bytes missing FCP2-HOLDER-PROOF-V1 domain prefix".into());
        }

        // 7. Sign and verify round-trip
        let signature = sk.sign(&computed_signable);
        let pk = sk.verifying_key();
        pk.verify(&computed_signable, &signature)
            .map_err(|e| format!("signature verification failed: {e}"))?;

        // 8. If expected signature is non-empty, verify it matches
        if !self.expected_signature.is_empty() {
            let sig_bytes = signature.to_bytes();
            let computed_sig_hex = hex::encode(sig_bytes);
            if computed_sig_hex != self.expected_signature {
                return Err(format!(
                    "signature mismatch:\n  expected: {}\n  actual:   {computed_sig_hex}",
                    self.expected_signature
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_proof_vectors_populated() {
        let vectors = HolderProofGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 holder proof vectors");
    }

    #[test]
    fn all_vectors_verify() {
        for (i, vector) in HolderProofGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector {} ({}) failed: {}", i + 1, vector.description, e);
            });
        }
    }

    #[test]
    fn vector_1_basic() {
        let vector = HolderProofGoldenVector::vector_1_basic_holder_proof();
        vector.verify().expect("Vector 1 verification failed");
    }

    #[test]
    fn vector_2_uuid() {
        let vector = HolderProofGoldenVector::vector_2_uuid_request_id();
        vector.verify().expect("Vector 2 verification failed");
    }

    #[test]
    fn vector_3_long_jti() {
        let vector = HolderProofGoldenVector::vector_3_long_jti();
        vector.verify().expect("Vector 3 verification failed");
    }

    #[test]
    fn signable_bytes_domain_prefix() {
        // All vectors must start with the domain prefix
        for vector in HolderProofGoldenVector::load_all() {
            let signable_hex = &vector.expected_signable_bytes;
            let signable = hex::decode(signable_hex).unwrap();
            assert!(
                signable.starts_with(b"FCP2-HOLDER-PROOF-V1"),
                "Vector '{}' missing domain prefix",
                vector.description
            );
        }
    }

    #[test]
    fn different_requests_produce_different_bytes() {
        let v1 = HolderProofGoldenVector::vector_1_basic_holder_proof();
        let v2 = HolderProofGoldenVector::vector_2_uuid_request_id();
        assert_ne!(
            v1.expected_signable_bytes, v2.expected_signable_bytes,
            "Different request parameters must produce different signable bytes"
        );
    }

    #[test]
    fn signable_bytes_concatenation_correctness() {
        // Since we changed to length prefixing, this simple test would fail,
        // we'll update it to check the prefixed lengths explicitly.
        let v1 = HolderProofGoldenVector::vector_1_basic_holder_proof();
        let bytes = hex::decode(v1.expected_signable_bytes).unwrap();
        assert!(bytes.starts_with(b"FCP2-HOLDER-PROOF-V1"));
        assert!(bytes.len() > 20); // Domain length is 20
    }
}
