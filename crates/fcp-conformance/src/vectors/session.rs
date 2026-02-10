//! Session handshake golden vectors.
//!
//! These vectors test the session handshake transcript and key derivation.
//! All values are deterministic and derived from fixed inputs for reproducibility.
//!
//! # Key Derivation Algorithm (NORMATIVE)
//!
//! 1. Compute X25519 shared secret from initiator and responder ephemeral keys
//! 2. Build info bytes: `"FCP2-SESSION-V1" || initiator_id || responder_id || hello_nonce || ack_nonce`
//! 3. PRK = HKDF-SHA256(salt=`session_id`, ikm=`shared_secret`, info=`info`)
//! 4. OKM = HKDF-SHA256-Expand(prk=PRK, info="FCP2-SESSION-KEYS-V1", length=96)
//! 5. Split: `k_mac_i2r` = OKM[0:32], `k_mac_r2i` = OKM[32:64], `k_ctx` = OKM[64:96]

use serde::{Deserialize, Serialize};

/// Golden vector for session handshake and key derivation.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Initiator node ID (Tailscale format).
    pub initiator_id: String,
    /// Responder node ID (Tailscale format).
    pub responder_id: String,
    /// Initiator ephemeral secret key (32 bytes hex) - for computing shared secret.
    pub initiator_ephemeral_sk: String,
    /// Initiator ephemeral public key (32 bytes hex).
    pub initiator_ephemeral_pk: String,
    /// Responder ephemeral secret key (32 bytes hex) - for computing shared secret.
    pub responder_ephemeral_sk: String,
    /// Responder ephemeral public key (32 bytes hex).

    pub responder_ephemeral_pk: String,
    /// Hello nonce (16 bytes hex).
    pub hello_nonce: String,
    /// Ack nonce (16 bytes hex).
    pub ack_nonce: String,
    /// Session ID (16 bytes hex).
    pub session_id: String,
    /// Expected X25519 shared secret (32 bytes hex).
    pub expected_shared_secret: String,

    /// Expected derived keys (hex).
    pub expected_keys: SessionDerivedKeys,
}

/// Derived session keys for verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDerivedKeys {
    /// MAC key for initiator-to-responder (32 bytes hex).
    pub k_mac_i2r: String,
    /// MAC key for responder-to-initiator (32 bytes hex).
    pub k_mac_r2i: String,
    /// Control-plane encryption key (32 bytes hex).
    pub k_ctx: String,
}

impl SessionGoldenVector {
    /// Load all session golden vectors.
    ///
    /// These vectors are designed to be byte-exact: if an implementation
    /// produces different keys, it is non-compliant.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_basic_handshake(),
            Self::vector_2_rfc7748_keys(),
            Self::vector_3_different_nonces(),
        ]
    }

    /// Vector 1: Basic handshake with simple deterministic keys.
    ///
    /// Uses sk = [1; 32] for initiator and sk = [2; 32] for responder.
    /// All values computed and verified against the implementation.
    #[must_use]
    pub fn vector_1_basic_handshake() -> Self {
        Self {
            description: "Basic handshake with deterministic keys (sk=[1;32] and sk=[2;32])".into(),
            initiator_id: "node.initiator.ts.net".into(),
            responder_id: "node.responder.ts.net".into(),
            initiator_ephemeral_sk:
                "0101010101010101010101010101010101010101010101010101010101010101".into(),
            initiator_ephemeral_pk:
                "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209".into(),
            responder_ephemeral_sk:
                "0202020202020202020202020202020202020202020202020202020202020202".into(),
            responder_ephemeral_pk:
                "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59".into(),
            hello_nonce: "00000000000000000000000000000001".into(),
            ack_nonce: "00000000000000000000000000000002".into(),
            session_id: "deadbeefcafebabe0123456789abcdef".into(),
            expected_shared_secret:
                "2ed76ab549b1e73c031eb49c9448f0798aea81b698279a0c3dc3e49fbfc4b953".into(),
            expected_keys: SessionDerivedKeys {
                k_mac_i2r: "d9af51ed221a05ea177c5382c0e71537fc62e64c4ee0b0771d3681e609f743a1"
                    .into(),
                k_mac_r2i: "330a4d3c684f52873e85ebc33e9441d1fc6ab4a50aba0329abfc698214e35c9e"
                    .into(),
                k_ctx: "7eda9f6a5f3d2855185740e5535970bfd39e0a695985ea0d17d9d357ab737309".into(),
            },
        }
    }

    /// Vector 2: Uses RFC 7748 test vector keys for ECDH verification.
    ///
    /// Alice's private: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    /// Bob's private: 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
    /// Shared: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
    #[must_use]
    pub fn vector_2_rfc7748_keys() -> Self {
        Self {
            description: "RFC 7748 Section 6.1 test vector keys".into(),
            initiator_id: "alice.mesh.ts.net".into(),
            responder_id: "bob.mesh.ts.net".into(),
            initiator_ephemeral_sk:
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".into(),
            initiator_ephemeral_pk:
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a".into(),
            responder_ephemeral_sk:
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb".into(),
            responder_ephemeral_pk:
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f".into(),
            hello_nonce: "a1b2c3d4e5f6071829304050deadbeef".into(),
            ack_nonce: "fedcba9876543210fedcba9876543210".into(),
            session_id: "01234567890abcdef01234567890abcd".into(),
            expected_shared_secret:
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742".into(),
            expected_keys: SessionDerivedKeys {
                k_mac_i2r: "f69616ef8fb6f437468429cb858f0cef91d4f6b1676e26400d4c96dc2ba63647"
                    .into(),
                k_mac_r2i: "1abf952bffeb02082daea1811c8c80a3d2d67aade79cdc861a536ff02b24ba8b"
                    .into(),
                k_ctx: "4da477bf4a24abc3bd5a6aa759ed1f4c3adcd2aa5fe500658aaa287f1c92dd60".into(),
            },
        }
    }

    /// Vector 3: Same keys as vector 1 but different nonces.
    ///
    /// Demonstrates that nonce changes affect derived keys (nonce binding).
    #[must_use]
    pub fn vector_3_different_nonces() -> Self {
        Self {
            description: "Same keys as vector 1, different nonces (demonstrates nonce binding)"
                .into(),
            initiator_id: "node.initiator.ts.net".into(),
            responder_id: "node.responder.ts.net".into(),
            initiator_ephemeral_sk:
                "0101010101010101010101010101010101010101010101010101010101010101".into(),
            initiator_ephemeral_pk:
                "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209".into(),
            responder_ephemeral_sk:
                "0202020202020202020202020202020202020202020202020202020202020202".into(),
            responder_ephemeral_pk:
                "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59".into(),
            hello_nonce: "ffffffffffffffffffffffffffffffff".into(),
            ack_nonce: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
            session_id: "deadbeefcafebabe0123456789abcdef".into(),
            // Same shared secret as vector 1 (same keys)
            expected_shared_secret:
                "2ed76ab549b1e73c031eb49c9448f0798aea81b698279a0c3dc3e49fbfc4b953".into(),
            // Different keys due to different nonces
            expected_keys: SessionDerivedKeys {
                k_mac_i2r: "527b3346f780151e7c893d78d75d725086bacc0f649f0fa98135508f339e2669"
                    .into(),
                k_mac_r2i: "7a8677b0f70f84511506dafd9d3fcb2ce5c14cd0d2bb368fb5e63313f9f3ebec"
                    .into(),
                k_ctx: "fd4028f9a1635a3a2406f7e2c46b612736df6eab9e57f9faed79af3e500a6494".into(),
            },
        }
    }

    /// Verify a vector against the actual implementation.
    ///
    /// # Errors
    /// Returns an error message if any value doesn't match.
    #[cfg(test)]
    pub fn verify(&self) -> Result<(), String> {
        use fcp_crypto::{HkdfSha256, X25519SecretKey, hkdf_sha256_array};

        // Parse keys
        let initiator_sk_bytes: [u8; 32] = hex::decode(&self.initiator_ephemeral_sk)
            .map_err(|e| format!("invalid initiator sk hex: {e}"))?
            .try_into()
            .map_err(|_| "initiator sk wrong length")?;
        let responder_sk_bytes: [u8; 32] = hex::decode(&self.responder_ephemeral_sk)
            .map_err(|e| format!("invalid responder sk hex: {e}"))?
            .try_into()
            .map_err(|_| "responder sk wrong length")?;

        let initiator_sk = X25519SecretKey::from_bytes(initiator_sk_bytes);
        let responder_sk = X25519SecretKey::from_bytes(responder_sk_bytes);

        // Verify public keys
        let computed_init_pk = initiator_sk.public_key().to_hex();
        if computed_init_pk != self.initiator_ephemeral_pk {
            return Err(format!(
                "initiator pk mismatch: expected {}, got {computed_init_pk}",
                self.initiator_ephemeral_pk
            ));
        }

        let computed_resp_pk = responder_sk.public_key().to_hex();
        if computed_resp_pk != self.responder_ephemeral_pk {
            return Err(format!(
                "responder pk mismatch: expected {}, got {computed_resp_pk}",
                self.responder_ephemeral_pk
            ));
        }

        // Verify shared secret
        let shared = initiator_sk.diffie_hellman(&responder_sk.public_key());
        let computed_shared = hex::encode(shared.as_bytes());
        if computed_shared != self.expected_shared_secret {
            return Err(format!(
                "shared secret mismatch: expected {}, got {computed_shared}",
                self.expected_shared_secret
            ));
        }

        // Verify key derivation
        let session_id =
            hex::decode(&self.session_id).map_err(|e| format!("invalid session_id hex: {e}"))?;
        let hello_nonce =
            hex::decode(&self.hello_nonce).map_err(|e| format!("invalid hello_nonce hex: {e}"))?;
        let ack_nonce =
            hex::decode(&self.ack_nonce).map_err(|e| format!("invalid ack_nonce hex: {e}"))?;

        let mut info = Vec::new();
        info.extend_from_slice(b"FCP2-SESSION-V1");
        info.extend_from_slice(self.initiator_id.as_bytes());
        info.extend_from_slice(self.responder_id.as_bytes());
        info.extend_from_slice(&hello_nonce);
        info.extend_from_slice(&ack_nonce);

        let prk: [u8; 32] = hkdf_sha256_array(Some(&session_id), shared.as_bytes(), &info)
            .map_err(|e| format!("HKDF error: {e}"))?;

        let hkdf = HkdfSha256::new(None, &prk);
        let okm: [u8; 96] = hkdf
            .expand_to_array(b"FCP2-SESSION-KEYS-V1")
            .map_err(|e| format!("HKDF expand error: {e}"))?;

        let computed_k_mac_i2r = hex::encode(&okm[0..32]);
        let computed_k_mac_r2i = hex::encode(&okm[32..64]);
        let computed_k_ctx = hex::encode(&okm[64..96]);

        if computed_k_mac_i2r != self.expected_keys.k_mac_i2r {
            return Err(format!(
                "k_mac_i2r mismatch: expected {}, got {computed_k_mac_i2r}",
                self.expected_keys.k_mac_i2r
            ));
        }
        if computed_k_mac_r2i != self.expected_keys.k_mac_r2i {
            return Err(format!(
                "k_mac_r2i mismatch: expected {}, got {computed_k_mac_r2i}",
                self.expected_keys.k_mac_r2i
            ));
        }
        if computed_k_ctx != self.expected_keys.k_ctx {
            return Err(format!(
                "k_ctx mismatch: expected {}, got {computed_k_ctx}",
                self.expected_keys.k_ctx
            ));
        }

        Ok(())

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_crypto::{HkdfSha256, X25519SecretKey, hkdf_sha256_array};

    #[test]
    fn golden_vectors_parseable() {
        let vectors = SessionGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 session golden vectors");
    }

    #[test]
    fn all_vectors_verify() {
        for (i, vector) in SessionGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector {} ({}) failed: {}", i + 1, vector.description, e)
            });
        }
    }

    #[test]
    fn vector_1_full_verification() {
        let vector = SessionGoldenVector::vector_1_basic_handshake();
        vector.verify().expect("Vector 1 verification failed");
    }

    #[test]
    fn vector_2_rfc7748_verification() {
        let vector = SessionGoldenVector::vector_2_rfc7748_keys();
        vector
            .verify()
            .expect("Vector 2 (RFC 7748) verification failed");
    }

    #[test]
    fn vector_3_nonce_binding_verification() {
        let vector = SessionGoldenVector::vector_3_different_nonces();
        vector.verify().expect("Vector 3 verification failed");
    }

    #[test]
    fn nonce_changes_affect_derived_keys() {
        let v1 = SessionGoldenVector::vector_1_basic_handshake();
        let v3 = SessionGoldenVector::vector_3_different_nonces();

        // Same shared secret (same ephemeral keys)
        assert_eq!(v1.expected_shared_secret, v3.expected_shared_secret);
        assert_eq!(v1.session_id, v3.session_id);

        // But different nonces
        assert_ne!(v1.hello_nonce, v3.hello_nonce);
        assert_ne!(v1.ack_nonce, v3.ack_nonce);

        // And therefore different keys
        assert_ne!(v1.expected_keys.k_mac_i2r, v3.expected_keys.k_mac_i2r);
        assert_ne!(v1.expected_keys.k_mac_r2i, v3.expected_keys.k_mac_r2i);
        assert_ne!(v1.expected_keys.k_ctx, v3.expected_keys.k_ctx);
    }

    #[test]
    fn dh_is_commutative() {
        let vector = SessionGoldenVector::vector_1_basic_handshake();

        let initiator_sk_bytes: [u8; 32] = hex::decode(&vector.initiator_ephemeral_sk)
            .unwrap()
            .try_into()
            .unwrap();
        let responder_sk_bytes: [u8; 32] = hex::decode(&vector.responder_ephemeral_sk)
            .unwrap()
            .try_into()
            .unwrap();

        let initiator_sk = X25519SecretKey::from_bytes(initiator_sk_bytes);
        let responder_sk = X25519SecretKey::from_bytes(responder_sk_bytes);

        let shared1 = initiator_sk.diffie_hellman(&responder_sk.public_key());
        let shared2 = responder_sk.diffie_hellman(&initiator_sk.public_key());

        assert_eq!(
            shared1.as_bytes(),
            shared2.as_bytes(),
            "DH must be commutative"
        );
    }

    #[test]
    fn keys_are_distinct() {
        for vector in SessionGoldenVector::load_all() {
            assert_ne!(
                vector.expected_keys.k_mac_i2r, vector.expected_keys.k_mac_r2i,
                "{}: k_mac_i2r and k_mac_r2i must differ",
                vector.description
            );
            assert_ne!(
                vector.expected_keys.k_mac_i2r, vector.expected_keys.k_ctx,
                "{}: k_mac_i2r and k_ctx must differ",
                vector.description
            );
            assert_ne!(
                vector.expected_keys.k_mac_r2i, vector.expected_keys.k_ctx,
                "{}: k_mac_r2i and k_ctx must differ",
                vector.description
            );
        }
    }

    #[test]
    fn session_id_affects_keys() {
        // Same everything except session_id should produce different keys
        let shared =
            hex::decode("2ed76ab549b1e73c031eb49c9448f0798aea81b698279a0c3dc3e49fbfc4b953")
                .unwrap();
        let hello_nonce = hex::decode("00000000000000000000000000000001").unwrap();
        let ack_nonce = hex::decode("00000000000000000000000000000002").unwrap();

        let mut info = Vec::new();
        info.extend_from_slice(b"FCP2-SESSION-V1");
        info.extend_from_slice(b"node.initiator.ts.net");
        info.extend_from_slice(b"node.responder.ts.net");
        info.extend_from_slice(&hello_nonce);
        info.extend_from_slice(&ack_nonce);

        let session_id_1 = hex::decode("deadbeefcafebabe0123456789abcdef").unwrap();
        let session_id_2 = hex::decode("00000000000000000000000000000000").unwrap();

        let prk1: [u8; 32] = hkdf_sha256_array(Some(&session_id_1), &shared, &info).unwrap();
        let prk2: [u8; 32] = hkdf_sha256_array(Some(&session_id_2), &shared, &info).unwrap();

        let hkdf1 = HkdfSha256::new(None, &prk1);
        let hkdf2 = HkdfSha256::new(None, &prk2);

        let okm1: [u8; 96] = hkdf1.expand_to_array(b"FCP2-SESSION-KEYS-V1").unwrap();
        let okm2: [u8; 96] = hkdf2.expand_to_array(b"FCP2-SESSION-KEYS-V1").unwrap();

        assert_ne!(
            okm1, okm2,
            "Different session IDs must produce different keys"
        );

    }
}
