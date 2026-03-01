//! `COSE_Sign1` capability token golden vectors.
//!
//! These vectors lock down the byte-level encoding of FCP2 capability tokens
//! using deterministic Ed25519 keys and fixed CWT claims. Any implementation
//! must produce these exact bytes for the given inputs.
//!
//! # Token Structure (NORMATIVE)
//!
//! FCP2 capability tokens are `COSE_Sign1` structures (RFC 9052) containing
//! CWT claims (RFC 8392) plus FCP2 private claims (negative keys).
//!
//! Protected header: { alg: `EdDSA`, kid: <8-byte key ID> }
//! Payload: deterministic CBOR map of CWT + FCP2 claims
//! Signature: Ed25519 over `Sig_structure`

use serde::{Deserialize, Serialize};

/// Golden vector for a `COSE_Sign1` capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Ed25519 signing key (32 bytes hex).
    pub signing_key: String,
    /// Expected Ed25519 public key (32 bytes hex).
    pub expected_public_key: String,
    /// Expected key ID (8 bytes hex).
    pub expected_kid: String,
    /// Capability ID claim.
    pub capability_id: String,
    /// Zone ID claim.
    pub zone_id: String,
    /// Principal ID claim.
    pub principal_id: String,
    /// Allowed operations.
    pub operations: Vec<String>,
    /// Issuer claim.
    pub issuer: String,
    /// Issuing node ID claim.
    pub issuing_node: String,
    /// Holder node ID (optional — triggers `holder_proof` requirement).
    pub holder_node: Option<String>,
    /// Checkpoint ID (hex bytes, optional).
    pub checkpoint_id: Option<String>,
    /// Checkpoint sequence (optional).
    pub checkpoint_seq: Option<u64>,
    /// Not-before timestamp (Unix epoch seconds).
    pub not_before: i64,
    /// Expiration timestamp (Unix epoch seconds).
    pub expires: i64,
    /// Expected CWT claims payload (deterministic CBOR, hex).
    pub expected_claims_cbor: String,
    /// Expected full `COSE_Sign1` token (CBOR, hex).
    pub expected_token_cbor: String,
}

impl CapabilityTokenGoldenVector {
    /// Load all capability token golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_basic_capability(),
            Self::vector_2_with_holder_and_checkpoint(),
            Self::vector_3_multi_operation(),
        ]
    }

    /// Vector 1: Basic capability token with minimal claims.
    ///
    /// Uses sk = [0x01; 32] for deterministic key derivation.
    /// Single operation, no `holder_node`, no checkpoint.
    #[must_use]
    pub fn vector_1_basic_capability() -> Self {
        Self {
            description: "Basic capability token (sk=[0x01;32], single op, no holder)".into(),
            signing_key: "0101010101010101010101010101010101010101010101010101010101010101".into(),
            expected_public_key: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
                .into(),
            expected_kid: "a0c1f01ec0c902d8".into(),
            capability_id: "cap:discord.send".into(),
            zone_id: "z:work".into(),
            principal_id: "agent:claude".into(),
            operations: vec!["discord.send_message".into()],
            issuer: "node:primary".into(),
            issuing_node: "node:primary.mesh.ts.net".into(),
            holder_node: None,
            checkpoint_id: None,
            checkpoint_seq: None,
            not_before: 1_700_000_000,
            expires: 1_700_086_400,
            expected_claims_cbor: "a83a0001000678186e6f64653a7072696d6172792e6d6573682e74732e6e65743a000100036c6167656e743a636c617564653a000100028174646973636f72642e73656e645f6d6573736167653a00010001667a3a776f726b3a00010000706361703a646973636f72642e73656e64016c6e6f64653a7072696d617279041a65554280051a6553f100".into(),
            expected_token_cbor: "844da201270448a0c1f01ec0c902d8a05889a83a0001000678186e6f64653a7072696d6172792e6d6573682e74732e6e65743a000100036c6167656e743a636c617564653a000100028174646973636f72642e73656e645f6d6573736167653a00010001667a3a776f726b3a00010000706361703a646973636f72642e73656e64016c6e6f64653a7072696d617279041a65554280051a6553f1005840004fb869380ffc1dd11cdf0d98463db5dd489a43a2fd9e42b004b1537d6cc81e782d992df9bd97575b325c371926ca4a2a67ec5e402992dfb52bbf6c3639af0b".into(),
        }
    }

    /// Vector 2: Capability with `holder_node` binding and checkpoint.
    ///
    /// Uses sk = [0x02; 32]. Tests that `holder_node` and `chk_id`/`chk_seq`
    /// are correctly encoded in the CWT claims.
    #[must_use]
    pub fn vector_2_with_holder_and_checkpoint() -> Self {
        Self {
            description: "Capability with holder_node + checkpoint (sk=[0x02;32])".into(),
            signing_key: "0202020202020202020202020202020202020202020202020202020202020202".into(),
            expected_public_key: "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
                .into(),
            expected_kid: "50aecc5471a5c774".into(),
            capability_id: "cap:s3.read".into(),
            zone_id: "z:private".into(),
            principal_id: "agent:assistant".into(),
            operations: vec!["s3.get_object".into(), "s3.list_objects".into()],
            issuer: "node:owner".into(),
            issuing_node: "node:owner.mesh.ts.net".into(),
            holder_node: Some("node:laptop.mesh.ts.net".into()),
            checkpoint_id: Some("deadbeefcafebabe0000000000000001".into()),
            checkpoint_seq: Some(42),
            not_before: 1_700_000_000,
            expires: 1_700_172_800,
            expected_claims_cbor: "ab3a0001000b182a3a0001000a50deadbeefcafebabe00000000000000013a00010009776e6f64653a6c6170746f702e6d6573682e74732e6e65743a00010006766e6f64653a6f776e65722e6d6573682e74732e6e65743a000100036f6167656e743a617373697374616e743a00010002826d73332e6765745f6f626a6563746f73332e6c6973745f6f626a656374733a00010001697a3a707269766174653a000100006b6361703a73332e72656164016a6e6f64653a6f776e6572041a65569400051a6553f100".into(),
            expected_token_cbor: "844da20127044850aecc5471a5c774a058c8ab3a0001000b182a3a0001000a50deadbeefcafebabe00000000000000013a00010009776e6f64653a6c6170746f702e6d6573682e74732e6e65743a00010006766e6f64653a6f776e65722e6d6573682e74732e6e65743a000100036f6167656e743a617373697374616e743a00010002826d73332e6765745f6f626a6563746f73332e6c6973745f6f626a656374733a00010001697a3a707269766174653a000100006b6361703a73332e72656164016a6e6f64653a6f776e6572041a65569400051a6553f1005840b979d85a1102f29568c40ea773259e36bfa58fc512ab7f7c69ba1d849cb26e65a316cdbd989b049c56868b2833b2d2bfbcba05f1140c217a09db08ab4356570b".into(),
        }
    }

    /// Vector 3: Multi-operation capability in public zone.
    ///
    /// Uses sk = [0x03; 32]. Tests encoding of multiple operations
    /// and a different zone hierarchy level.
    #[must_use]
    pub fn vector_3_multi_operation() -> Self {
        Self {
            description: "Multi-operation capability in z:public (sk=[0x03;32])".into(),
            signing_key: "0303030303030303030303030303030303030303030303030303030303030303".into(),
            expected_public_key: "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
                .into(),
            expected_kid: "4edec0015cb03d73".into(),
            capability_id: "cap:github.manage".into(),
            zone_id: "z:public".into(),
            principal_id: "agent:devbot".into(),
            operations: vec![
                "github.create_issue".into(),
                "github.close_issue".into(),
                "github.create_pr".into(),
                "github.merge_pr".into(),
            ],
            issuer: "node:ci-runner".into(),
            issuing_node: "node:ci-runner.mesh.ts.net".into(),
            holder_node: None,
            checkpoint_id: None,
            checkpoint_seq: None,
            not_before: 1_700_000_000,
            expires: 1_700_003_600,
            expected_claims_cbor: "a83a00010006781a6e6f64653a63692d72756e6e65722e6d6573682e74732e6e65743a000100036c6167656e743a646576626f743a0001000284736769746875622e6372656174655f6973737565726769746875622e636c6f73655f6973737565706769746875622e6372656174655f70726f6769746875622e6d657267655f70723a00010001687a3a7075626c69633a00010000716361703a6769746875622e6d616e616765016e6e6f64653a63692d72756e6e6572041a6553ff10051a6553f100".into(),
            expected_token_cbor: "844da2012704484edec0015cb03d73a058c3a83a00010006781a6e6f64653a63692d72756e6e65722e6d6573682e74732e6e65743a000100036c6167656e743a646576626f743a0001000284736769746875622e6372656174655f6973737565726769746875622e636c6f73655f6973737565706769746875622e6372656174655f70726f6769746875622e6d657267655f70723a00010001687a3a7075626c69633a00010000716361703a6769746875622e6d616e616765016e6e6f64653a63692d72756e6e6572041a6553ff10051a6553f100584004a01183496e38ee05e4fe7965872a2fdb4206a686894bcf7e2017cf18548ee1dabc02b991ea0967623b0eb107cf02780affa74c73eb48abf85115e0be105c07".into(),
        }
    }

    /// Verify this golden vector against the implementation.
    ///
    /// This method:
    /// 1. Constructs the signing key from the deterministic seed
    /// 2. Verifies the public key matches
    /// 3. Builds CWT claims from the vector fields
    /// 4. Signs the token and verifies claims CBOR matches
    /// 5. Verifies the full `COSE_Sign1` encoding matches
    ///
    /// # Errors
    ///
    /// Returns an error message if any step fails.
    pub fn verify(&self) -> Result<(), String> {
        use chrono::DateTime;
        use fcp_crypto::cose::{CoseToken, CwtClaims};
        use fcp_crypto::ed25519::Ed25519SigningKey;

        // 1. Parse signing key
        let sk_bytes: [u8; 32] = hex::decode(&self.signing_key)
            .map_err(|e| format!("invalid signing_key hex: {e}"))?
            .try_into()
            .map_err(|_| "signing_key must be 32 bytes")?;

        let sk =
            Ed25519SigningKey::from_bytes(&sk_bytes).map_err(|e| format!("invalid sk: {e}"))?;

        // 2. Verify public key
        let pk = sk.verifying_key();
        let computed_pk = hex::encode(pk.to_bytes());
        if computed_pk != self.expected_public_key {
            return Err(format!(
                "public key mismatch: expected {}, got {computed_pk}",
                self.expected_public_key
            ));
        }

        // 3. Verify key ID (if expected_kid is non-empty)
        if !self.expected_kid.is_empty() {
            let computed_kid = hex::encode(sk.key_id().as_bytes());
            if computed_kid != self.expected_kid {
                return Err(format!(
                    "kid mismatch: expected {}, got {computed_kid}",
                    self.expected_kid
                ));
            }
        }

        // 4. Build claims
        let nbf =
            DateTime::from_timestamp(self.not_before, 0).ok_or("invalid not_before timestamp")?;
        let exp = DateTime::from_timestamp(self.expires, 0).ok_or("invalid expires timestamp")?;

        let mut claims = CwtClaims::new()
            .issuer(&self.issuer)
            .capability_id(&self.capability_id)
            .zone_id(&self.zone_id)
            .principal_id(&self.principal_id)
            .issuing_node(&self.issuing_node)
            .not_before(nbf)
            .expiration(exp);

        // Add operations
        let ops_refs: Vec<&str> = self.operations.iter().map(String::as_str).collect();
        claims = claims.operations(&ops_refs);

        // Add optional holder_node
        if let Some(ref holder) = self.holder_node {
            claims = claims.holder_node(holder);
        }

        // Add optional checkpoint
        if let (Some(chk_id_hex), Some(chk_seq)) = (&self.checkpoint_id, self.checkpoint_seq) {
            let chk_id_bytes =
                hex::decode(chk_id_hex).map_err(|e| format!("invalid checkpoint_id hex: {e}"))?;
            claims = claims.checkpoint(&chk_id_bytes, chk_seq);
        }

        // 5. Verify claims CBOR (if expected is non-empty)
        if !self.expected_claims_cbor.is_empty() {
            let computed_cbor = claims
                .to_cbor()
                .map_err(|e| format!("claims to_cbor: {e}"))?;
            let computed_hex = hex::encode(&computed_cbor);
            if computed_hex != self.expected_claims_cbor {
                return Err(format!(
                    "claims CBOR mismatch:\n  expected: {}\n  actual:   {computed_hex}",
                    self.expected_claims_cbor
                ));
            }
        }

        // 6. Sign and verify token CBOR (if expected is non-empty)
        if !self.expected_token_cbor.is_empty() {
            let token =
                CoseToken::sign(&sk, &claims).map_err(|e| format!("token sign failed: {e}"))?;
            let computed_token_cbor = token.to_cbor().map_err(|e| format!("token to_cbor: {e}"))?;
            let computed_hex = hex::encode(&computed_token_cbor);
            if computed_hex != self.expected_token_cbor {
                return Err(format!(
                    "token CBOR mismatch:\n  expected: {}\n  actual:   {computed_hex}",
                    self.expected_token_cbor
                ));
            }

            // 7. Verify round-trip: decode and verify
            let parsed = CoseToken::from_cbor(&computed_token_cbor)
                .map_err(|e| format!("token from_cbor: {e}"))?;
            let verified_claims = parsed
                .verify(&pk)
                .map_err(|e| format!("token verify: {e}"))?;

            // Verify key claims survived round-trip
            if verified_claims.get_capability_id() != Some(self.capability_id.as_str()) {
                return Err(format!(
                    "round-trip capability_id mismatch: expected {:?}, got {:?}",
                    self.capability_id,
                    verified_claims.get_capability_id()
                ));
            }
            if verified_claims.get_zone_id() != Some(self.zone_id.as_str()) {
                return Err(format!(
                    "round-trip zone_id mismatch: expected {:?}, got {:?}",
                    self.zone_id,
                    verified_claims.get_zone_id()
                ));
            }
        }

        // If no expected bytes, just verify the token can be signed and verified
        if self.expected_claims_cbor.is_empty() && self.expected_token_cbor.is_empty() {
            let token =
                CoseToken::sign(&sk, &claims).map_err(|e| format!("token sign failed: {e}"))?;
            let cbor = token.to_cbor().map_err(|e| format!("token to_cbor: {e}"))?;
            let parsed =
                CoseToken::from_cbor(&cbor).map_err(|e| format!("token from_cbor: {e}"))?;
            parsed.verify(&pk).map_err(|e| format!("verify: {e}"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_vectors_populated() {
        let vectors = CapabilityTokenGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 capability token vectors");
    }

    #[test]
    fn all_vectors_verify() {
        for (i, vector) in CapabilityTokenGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector {} ({}) failed: {}", i + 1, vector.description, e);
            });
        }
    }

    #[test]
    fn vector_1_basic_sign_verify() {
        let vector = CapabilityTokenGoldenVector::vector_1_basic_capability();
        vector.verify().expect("Vector 1 verification failed");
    }

    #[test]
    fn vector_2_holder_checkpoint() {
        let vector = CapabilityTokenGoldenVector::vector_2_with_holder_and_checkpoint();
        vector.verify().expect("Vector 2 verification failed");
    }

    #[test]
    fn vector_3_multi_op() {
        let vector = CapabilityTokenGoldenVector::vector_3_multi_operation();
        vector.verify().expect("Vector 3 verification failed");
    }

    #[test]
    fn deterministic_encoding() {
        use fcp_crypto::cose::{CoseToken, CwtClaims};
        use fcp_crypto::ed25519::Ed25519SigningKey;

        let sk_bytes = [0x01u8; 32];
        let sk = Ed25519SigningKey::from_bytes(&sk_bytes).unwrap();

        // Build same claims twice in different order
        let claims1 = CwtClaims::new()
            .issuer("test")
            .capability_id("cap:test")
            .zone_id("z:work");

        let claims2 = CwtClaims::new()
            .zone_id("z:work")
            .issuer("test")
            .capability_id("cap:test");

        // Claims CBOR must be identical (BTreeMap ensures deterministic order)
        let cbor1 = claims1.to_cbor().unwrap();
        let cbor2 = claims2.to_cbor().unwrap();
        assert_eq!(cbor1, cbor2, "Claims encoding must be deterministic");

        // Tokens must produce identical COSE_Sign1 bytes
        let token1 = CoseToken::sign(&sk, &claims1).unwrap();
        let token2 = CoseToken::sign(&sk, &claims2).unwrap();
        assert_eq!(
            token1.to_cbor().unwrap(),
            token2.to_cbor().unwrap(),
            "Token encoding must be deterministic for same claims + key"
        );
    }

    #[test]
    fn different_keys_produce_different_tokens() {
        use fcp_crypto::cose::{CoseToken, CwtClaims};
        use fcp_crypto::ed25519::Ed25519SigningKey;

        let sk1 = Ed25519SigningKey::from_bytes(&[0x01u8; 32]).unwrap();
        let sk2 = Ed25519SigningKey::from_bytes(&[0x02u8; 32]).unwrap();

        let claims = CwtClaims::new().issuer("test").capability_id("cap:test");

        let token1 = CoseToken::sign(&sk1, &claims).unwrap().to_cbor().unwrap();
        let token2 = CoseToken::sign(&sk2, &claims).unwrap().to_cbor().unwrap();

        assert_ne!(
            token1, token2,
            "Different keys must produce different tokens"
        );
    }

    #[test]
    fn holder_node_claim_roundtrip() {
        use fcp_crypto::cose::{CoseToken, CwtClaims};
        use fcp_crypto::ed25519::Ed25519SigningKey;

        let sk = Ed25519SigningKey::from_bytes(&[0x02u8; 32]).unwrap();
        let pk = sk.verifying_key();

        let claims = CwtClaims::new()
            .issuer("node:owner")
            .capability_id("cap:test")
            .holder_node("node:laptop.mesh.ts.net")
            .checkpoint(b"\xde\xad\xbe\xef", 42);

        let token = CoseToken::sign(&sk, &claims).unwrap();
        let cbor = token.to_cbor().unwrap();
        let parsed = CoseToken::from_cbor(&cbor).unwrap();
        let verified = parsed.verify(&pk).unwrap();

        assert_eq!(
            verified.get_holder_node(),
            Some("node:laptop.mesh.ts.net"),
            "holder_node must survive round-trip"
        );
    }
}
