//! HPKE sealed-box golden vectors.
//!
//! These vectors lock down the byte-level encoding of FCP2 HPKE sealed boxes
//! used for distributing zone keys and `ObjectId` derivation keys to mesh nodes.
//!
//! # HPKE Profile (NORMATIVE)
//!
//! - KEM: DHKEM(X25519, HKDF-SHA256)
//! - KDF: HKDF-SHA256
//! - AEAD: ChaCha20-Poly1305
//! - Info: `"FCP2-HPKE"`
//!
//! # AAD Binding (NORMATIVE)
//!
//! AAD is deterministic CBOR encoding of `Fcp2Aad { zone_id, recipient_node_id,
//! purpose, issued_at }`. All fields contribute to the binding — changing any
//! field MUST cause decryption to fail.

use serde::{Deserialize, Serialize};

/// Golden vector for an HPKE sealed box operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeSealedBoxGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Recipient X25519 secret key (32 bytes hex).
    pub recipient_sk: String,
    /// Expected recipient X25519 public key (32 bytes hex).
    pub expected_recipient_pk: String,
    /// Deterministic RNG seed (32 bytes hex) — fed to `ChaCha20Rng::from_seed()`.
    pub rng_seed: String,
    /// Plaintext to seal (hex).
    pub plaintext: String,
    /// Zone ID bytes for AAD (raw bytes, hex-encoded).
    pub zone_id: String,
    /// Recipient node ID bytes for AAD (raw bytes, hex-encoded).
    pub recipient_node_id: String,
    /// Purpose string for AAD (one of the `purpose::*` constants).
    pub purpose: String,
    /// Issued-at timestamp (Unix seconds).
    pub issued_at: u64,
    /// Expected AAD CBOR encoding (hex).
    pub expected_aad_cbor: String,
    /// Expected encapsulated key (32 bytes hex).
    pub expected_enc: String,
    /// Expected ciphertext including auth tag (hex).
    pub expected_ciphertext: String,
}

impl HpkeSealedBoxGoldenVector {
    /// Load all HPKE sealed box golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_zone_key_seal(),
            Self::vector_2_objectid_key_seal(),
            Self::vector_3_secret_share_seal(),
        ]
    }

    /// Vector 1: Zone key sealing with purpose `FCP2-ZONE-KEY`.
    ///
    /// Uses recipient sk = `[0x10; 32]`, rng seed = `[0xAA; 32]`.
    /// Seals a 32-byte zone key to a single recipient.
    #[must_use]
    pub fn vector_1_zone_key_seal() -> Self {
        Self {
            description: "Zone key seal (sk=[0x10;32], seed=[0xAA;32])".into(),
            recipient_sk: "1010101010101010101010101010101010101010101010101010101010101010".into(),
            expected_recipient_pk: "781faab908430150daccdd6f9d6c5086e34f73a93ebbaa271765e5036edfc519".into(),
            rng_seed: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            plaintext: "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".into(),
            zone_id: hex::encode(b"z:work"),
            recipient_node_id: hex::encode(b"node:laptop.mesh.ts.net"),
            purpose: "FCP2-ZONE-KEY".into(),
            issued_at: 1_700_000_000,
            expected_aad_cbor: "a467707572706f73654d464350322d5a4f4e452d4b4559677a6f6e655f6964467a3a776f726b696973737565645f61741a6553f10071726563697069656e745f6e6f64655f6964576e6f64653a6c6170746f702e6d6573682e74732e6e6574".into(),
            expected_enc: "812bdf224bf70d7ae7ef4505be7678dd3282dfe762e6e16af542e58672314b00".into(),
            expected_ciphertext: "2c309bb932b1952b52d08b27271866bf6572da7dc7b8616bde176dfeebfdf8c274f5d57296ea937d88f7be725d3d3eda".into(),
        }
    }

    /// Vector 2: `ObjectId` key sealing with purpose `FCP2-OBJECTID-KEY`.
    ///
    /// Uses recipient sk = `[0x20; 32]`, rng seed = `[0xBB; 32]`.
    /// Seals a 32-byte `ObjectIdKey` to a recipient in a private zone.
    #[must_use]
    pub fn vector_2_objectid_key_seal() -> Self {
        Self {
            description: "ObjectId key seal (sk=[0x20;32], seed=[0xBB;32])".into(),
            recipient_sk: "2020202020202020202020202020202020202020202020202020202020202020".into(),
            expected_recipient_pk: "06453fcd9cef5a1f53acc4f942104c0c8e9e27d5c7b37f5507cdcd1628105963".into(),
            rng_seed: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            plaintext: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            zone_id: hex::encode(b"z:private"),
            recipient_node_id: hex::encode(b"node:server.mesh.ts.net"),
            purpose: "FCP2-OBJECTID-KEY".into(),
            issued_at: 1_700_086_400,
            expected_aad_cbor: "a467707572706f736551464350322d4f424a45435449442d4b4559677a6f6e655f6964497a3a70726976617465696973737565645f61741a6555428071726563697069656e745f6e6f64655f6964576e6f64653a7365727665722e6d6573682e74732e6e6574".into(),
            expected_enc: "289e8e7e39cbcbc92b38a3f85ebfad2774ab877ba4a1ae5f9401b734c0edf914".into(),
            expected_ciphertext: "376c149d54dfb5caf5f527c52e3a75071e2368581c1e9f6bc39a698b0e488c1d8e621933ef2772f31cf0a5b1d2210c53".into(),
        }
    }

    /// Vector 3: Secret share sealing with purpose `FCP2-SECRET-SHARE`.
    ///
    /// Uses recipient sk = `[0x30; 32]`, rng seed = `[0xCC; 32]`.
    /// Seals a shorter payload (16-byte secret share).
    #[must_use]
    pub fn vector_3_secret_share_seal() -> Self {
        Self {
            description: "Secret share seal (sk=[0x30;32], seed=[0xCC;32])".into(),
            recipient_sk: "3030303030303030303030303030303030303030303030303030303030303030".into(),
            expected_recipient_pk: "e50c239bc204f1341664c9d9c50c6a0d0fff6fc79d9301f1e713aab2e0344b3f".into(),
            rng_seed: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            plaintext: "feedfacedeadbeeffeedfacedeadbeef".into(), // 16 bytes
            zone_id: hex::encode(b"z:public"),
            recipient_node_id: hex::encode(b"node:ci-runner.mesh.ts.net"),
            purpose: "FCP2-SECRET-SHARE".into(),
            issued_at: 1_700_172_800,
            expected_aad_cbor: "a467707572706f736551464350322d5345435245542d5348415245677a6f6e655f6964487a3a7075626c6963696973737565645f61741a6556940071726563697069656e745f6e6f64655f6964581a6e6f64653a63692d72756e6e65722e6d6573682e74732e6e6574".into(),
            expected_enc: "5b6a4a5000e2ae7bd20abc3a76e6cca5c068dc4ec0b2c4a8ba019d6f624d815b".into(),
            expected_ciphertext: "af016ffd986cfd6733141e52b65fa218054a01d40b0182fc91072b1b4756e6d9".into(),
        }
    }

    /// Verify this golden vector against the implementation.
    ///
    /// This method:
    /// 1. Constructs X25519 keys from deterministic bytes
    /// 2. Verifies the public key matches (if expected is non-empty)
    /// 3. Builds AAD and verifies its CBOR encoding
    /// 4. Seals with deterministic RNG and verifies enc + ciphertext
    /// 5. Opens the sealed box and verifies plaintext round-trips
    ///
    /// # Errors
    ///
    /// Returns an error message if any step fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_crypto::hpke_seal::{Fcp2Aad, HpkeSealedBox, hpke_open, hpke_seal_with_rng};
        use fcp_crypto::x25519::X25519SecretKey;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        // 1. Parse recipient secret key
        let sk_bytes: [u8; 32] = hex::decode(&self.recipient_sk)
            .map_err(|e| format!("invalid recipient_sk hex: {e}"))?
            .try_into()
            .map_err(|_| "recipient_sk must be 32 bytes")?;
        #[allow(clippy::similar_names)]
        let recipient_secret = X25519SecretKey::from_bytes(sk_bytes);
        let recipient_pk = recipient_secret.public_key();

        // 2. Verify public key (if expected is non-empty)
        if !self.expected_recipient_pk.is_empty() {
            let computed_pk = hex::encode(recipient_pk.to_bytes());
            if computed_pk != self.expected_recipient_pk {
                return Err(format!(
                    "public key mismatch: expected {}, got {computed_pk}",
                    self.expected_recipient_pk
                ));
            }
        }

        // 3. Parse plaintext
        let plaintext =
            hex::decode(&self.plaintext).map_err(|e| format!("invalid plaintext hex: {e}"))?;

        // 4. Build AAD
        let zone_id_bytes =
            hex::decode(&self.zone_id).map_err(|e| format!("invalid zone_id hex: {e}"))?;
        let node_id_bytes = hex::decode(&self.recipient_node_id)
            .map_err(|e| format!("invalid recipient_node_id hex: {e}"))?;
        let purpose_bytes = self.purpose.as_bytes();

        let aad = Fcp2Aad {
            zone_id: zone_id_bytes,
            recipient_node_id: node_id_bytes,
            purpose: purpose_bytes.to_vec(),
            issued_at: self.issued_at,
        };

        // 5. Verify AAD encoding (if expected is non-empty)
        let aad_encoded = aad
            .encode()
            .map_err(|e| format!("AAD encode failed: {e}"))?;
        if !self.expected_aad_cbor.is_empty() {
            let computed_aad = hex::encode(&aad_encoded);
            if computed_aad != self.expected_aad_cbor {
                return Err(format!(
                    "AAD CBOR mismatch:\n  expected: {}\n  actual:   {computed_aad}",
                    self.expected_aad_cbor
                ));
            }
        }

        // 6. Seal with deterministic RNG
        let rng_seed: [u8; 32] = hex::decode(&self.rng_seed)
            .map_err(|e| format!("invalid rng_seed hex: {e}"))?
            .try_into()
            .map_err(|_| "rng_seed must be 32 bytes")?;
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        let sealed = hpke_seal_with_rng(&recipient_pk, &plaintext, &aad, &mut rng)
            .map_err(|e| format!("hpke_seal_with_rng failed: {e}"))?;

        // 7. Verify enc (if expected is non-empty)
        if !self.expected_enc.is_empty() {
            let computed_enc = hex::encode(&sealed.enc);
            if computed_enc != self.expected_enc {
                return Err(format!(
                    "enc mismatch:\n  expected: {}\n  actual:   {computed_enc}",
                    self.expected_enc
                ));
            }
        }

        // 8. Verify ciphertext (if expected is non-empty)
        if !self.expected_ciphertext.is_empty() {
            let computed_ct = hex::encode(&sealed.ciphertext);
            if computed_ct != self.expected_ciphertext {
                return Err(format!(
                    "ciphertext mismatch:\n  expected: {}\n  actual:   {computed_ct}",
                    self.expected_ciphertext
                ));
            }
        }

        // 9. Open and verify plaintext round-trip
        let opened = hpke_open(&recipient_secret, &sealed, &aad)
            .map_err(|e| format!("hpke_open failed: {e}"))?;

        if opened != plaintext {
            return Err(format!(
                "plaintext round-trip mismatch:\n  expected: {}\n  actual:   {}",
                self.plaintext,
                hex::encode(&opened)
            ));
        }

        // 10. Verify serialization round-trip of sealed box
        let bytes = sealed.to_bytes();
        let parsed = HpkeSealedBox::from_bytes(&bytes)
            .map_err(|e| format!("sealed box from_bytes failed: {e}"))?;
        if parsed.enc != sealed.enc || parsed.ciphertext != sealed.ciphertext {
            return Err("sealed box bytes round-trip failed".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_vectors_populated() {
        let vectors = HpkeSealedBoxGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 HPKE sealed box vectors");
    }

    #[test]
    fn all_vectors_verify() {
        for (i, vector) in HpkeSealedBoxGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector {} ({}) failed: {}", i + 1, vector.description, e);
            });
        }
    }

    #[test]
    fn vector_1_zone_key() {
        let vector = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        vector.verify().expect("Vector 1 verification failed");
    }

    #[test]
    fn vector_2_objectid_key() {
        let vector = HpkeSealedBoxGoldenVector::vector_2_objectid_key_seal();
        vector.verify().expect("Vector 2 verification failed");
    }

    #[test]
    fn vector_3_secret_share() {
        let vector = HpkeSealedBoxGoldenVector::vector_3_secret_share_seal();
        vector.verify().expect("Vector 3 verification failed");
    }

    #[test]
    fn deterministic_rng_produces_identical_output() {
        use fcp_crypto::hpke_seal::{Fcp2Aad, hpke_seal_with_rng};
        use fcp_crypto::x25519::X25519SecretKey;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let sk = X25519SecretKey::from_bytes([0x10; 32]);
        let pk = sk.public_key();
        let plaintext = [0xABu8; 32];
        let aad = Fcp2Aad::for_zone_key(b"z:test", b"node:test", 1_000_000);

        let mut rng1 = ChaCha20Rng::from_seed([0xFF; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([0xFF; 32]);

        let sealed1 = hpke_seal_with_rng(&pk, &plaintext, &aad, &mut rng1).unwrap();
        let sealed2 = hpke_seal_with_rng(&pk, &plaintext, &aad, &mut rng2).unwrap();

        assert_eq!(
            sealed1.enc, sealed2.enc,
            "deterministic RNG must produce same enc"
        );
        assert_eq!(
            sealed1.ciphertext, sealed2.ciphertext,
            "deterministic RNG must produce same ciphertext"
        );
    }

    #[test]
    fn different_purposes_different_aad() {
        use fcp_crypto::hpke_seal::Fcp2Aad;

        let zone_aad = Fcp2Aad::for_zone_key(b"z:work", b"node:a", 1_700_000_000);
        let oid_aad = Fcp2Aad::for_objectid_key(b"z:work", b"node:a", 1_700_000_000);
        let share_aad = Fcp2Aad::for_secret_share(b"z:work", b"node:a", 1_700_000_000);

        let zone_bytes = zone_aad.encode().unwrap();
        let oid_bytes = oid_aad.encode().unwrap();
        let share_bytes = share_aad.encode().unwrap();

        assert_ne!(
            zone_bytes, oid_bytes,
            "ZONE_KEY and OBJECTID_KEY AAD must differ"
        );
        assert_ne!(
            zone_bytes, share_bytes,
            "ZONE_KEY and SECRET_SHARE AAD must differ"
        );
        assert_ne!(
            oid_bytes, share_bytes,
            "OBJECTID_KEY and SECRET_SHARE AAD must differ"
        );
    }

    #[test]
    fn aad_zone_id_binding() {
        use fcp_crypto::hpke_seal::{Fcp2Aad, hpke_open, hpke_seal};
        use fcp_crypto::x25519::X25519SecretKey;

        let sk = X25519SecretKey::from_bytes([0x10; 32]);
        let pk = sk.public_key();

        let aad_work = Fcp2Aad::for_zone_key(b"z:work", b"node:a", 1_700_000_000);
        let aad_private = Fcp2Aad::for_zone_key(b"z:private", b"node:a", 1_700_000_000);

        let sealed = hpke_seal(&pk, b"secret", &aad_work).unwrap();

        // Opening with wrong zone_id MUST fail
        assert!(
            hpke_open(&sk, &sealed, &aad_private).is_err(),
            "wrong zone_id must cause decryption failure"
        );
    }

    #[test]
    fn ciphertext_length_correctness() {
        use fcp_crypto::hpke_seal::{Fcp2Aad, HPKE_ENC_SIZE, HPKE_TAG_SIZE, hpke_seal};
        use fcp_crypto::x25519::X25519SecretKey;

        let sk = X25519SecretKey::from_bytes([0x10; 32]);
        let pk = sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node:a", 1_700_000_000);

        for pt_len in [0, 16, 32, 64, 256] {
            let plaintext = vec![0xABu8; pt_len];
            let sealed = hpke_seal(&pk, &plaintext, &aad).unwrap();

            assert_eq!(sealed.enc.len(), HPKE_ENC_SIZE, "enc must be 32 bytes");
            assert_eq!(
                sealed.ciphertext.len(),
                pt_len + HPKE_TAG_SIZE,
                "ciphertext must be plaintext_len + 16 (tag) for pt_len={pt_len}"
            );
        }
    }

    // ── Serde roundtrip tests ───────────────────────────────

    #[test]
    fn hpke_vector_serde_roundtrip() {
        let v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        let json = serde_json::to_string(&v).unwrap();
        let parsed: HpkeSealedBoxGoldenVector = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.description, v.description);
        assert_eq!(parsed.expected_enc, v.expected_enc);
        assert_eq!(parsed.expected_ciphertext, v.expected_ciphertext);
        parsed.verify().expect("deserialized vector should verify");
    }

    #[test]
    fn hpke_all_vectors_serde_roundtrip() {
        for v in HpkeSealedBoxGoldenVector::load_all() {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: HpkeSealedBoxGoldenVector = serde_json::from_str(&json).unwrap();
            parsed.verify().unwrap_or_else(|e| {
                panic!("deserialized '{}' failed: {e}", v.description);
            });
        }
    }

    // ── Clone and Debug tests ───────────────────────────────

    #[test]
    fn hpke_vector_clone() {
        let v = HpkeSealedBoxGoldenVector::vector_2_objectid_key_seal();
        let cloned = v.clone();
        assert_eq!(v.recipient_sk, cloned.recipient_sk);
        assert_eq!(v.expected_ciphertext, cloned.expected_ciphertext);
        cloned.verify().expect("cloned vector should verify");
    }

    #[test]
    fn hpke_vector_debug() {
        let v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        let debug = format!("{v:?}");
        assert!(debug.contains("Zone key seal"));
    }

    // ── Tampered field verification tests ───────────────────

    #[test]
    fn verify_fails_with_tampered_recipient_sk() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.recipient_sk = "ff".repeat(32);
        assert!(v.verify().is_err(), "wrong recipient_sk should fail");
    }

    #[test]
    fn verify_fails_with_tampered_rng_seed() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.rng_seed = "bb".repeat(32);
        assert!(
            v.verify().is_err(),
            "wrong rng_seed should produce different enc"
        );
    }

    #[test]
    fn verify_fails_with_tampered_plaintext() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.plaintext = "00".repeat(32);
        assert!(v.verify().is_err(), "wrong plaintext should fail");
    }

    #[test]
    fn verify_fails_with_tampered_zone_id() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.zone_id = hex::encode(b"z:private");
        assert!(
            v.verify().is_err(),
            "wrong zone_id should change AAD and fail"
        );
    }

    #[test]
    fn verify_fails_with_tampered_purpose() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.purpose = "FCP2-OBJECTID-KEY".into();
        assert!(
            v.verify().is_err(),
            "wrong purpose should change AAD and fail"
        );
    }

    #[test]
    fn verify_fails_with_tampered_issued_at() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.issued_at = 999_999_999;
        assert!(
            v.verify().is_err(),
            "wrong issued_at should change AAD and fail"
        );
    }

    #[test]
    fn verify_fails_with_tampered_node_id() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.recipient_node_id = hex::encode(b"node:other.mesh.ts.net");
        assert!(
            v.verify().is_err(),
            "wrong node_id should change AAD and fail"
        );
    }

    #[test]
    fn verify_fails_with_invalid_sk_hex() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.recipient_sk = "not_hex".into();
        assert!(v.verify().is_err(), "invalid hex should fail");
    }

    #[test]
    fn verify_fails_with_invalid_rng_seed_hex() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.rng_seed = "zzzz".into();
        assert!(v.verify().is_err(), "invalid rng hex should fail");
    }

    #[test]
    fn verify_fails_with_short_rng_seed() {
        let mut v = HpkeSealedBoxGoldenVector::vector_1_zone_key_seal();
        v.rng_seed = "aabb".into();
        assert!(v.verify().is_err(), "short rng seed should fail");
    }

    // ── Cross-vector uniqueness tests ───────────────────────

    #[test]
    fn all_vectors_have_unique_recipient_keys() {
        let vectors = HpkeSealedBoxGoldenVector::load_all();
        let keys: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.recipient_sk.as_str()).collect();
        assert_eq!(
            keys.len(),
            vectors.len(),
            "all recipient keys must be unique"
        );
    }

    #[test]
    fn all_vectors_have_unique_rng_seeds() {
        let vectors = HpkeSealedBoxGoldenVector::load_all();
        let seeds: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.rng_seed.as_str()).collect();
        assert_eq!(seeds.len(), vectors.len(), "all rng seeds must be unique");
    }

    #[test]
    fn all_vectors_have_unique_purposes() {
        let vectors = HpkeSealedBoxGoldenVector::load_all();
        let purposes: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.purpose.as_str()).collect();
        assert_eq!(purposes.len(), vectors.len(), "all purposes must be unique");
    }

    #[test]
    fn all_vectors_have_unique_enc() {
        let vectors = HpkeSealedBoxGoldenVector::load_all();
        let encs: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.expected_enc.as_str()).collect();
        assert_eq!(encs.len(), vectors.len(), "all enc values must be unique");
    }

    // ── Field validation tests ──────────────────────────────

    #[test]
    fn all_vectors_have_valid_hex_fields() {
        for v in HpkeSealedBoxGoldenVector::load_all() {
            assert!(hex::decode(&v.recipient_sk).is_ok(), "recipient_sk hex");
            assert!(hex::decode(&v.expected_recipient_pk).is_ok(), "pk hex");
            assert!(hex::decode(&v.rng_seed).is_ok(), "rng_seed hex");
            assert!(hex::decode(&v.plaintext).is_ok(), "plaintext hex");
            assert!(hex::decode(&v.zone_id).is_ok(), "zone_id hex");
            assert!(hex::decode(&v.recipient_node_id).is_ok(), "node_id hex");
            assert!(hex::decode(&v.expected_aad_cbor).is_ok(), "aad_cbor hex");
            assert!(hex::decode(&v.expected_enc).is_ok(), "enc hex");
            assert!(
                hex::decode(&v.expected_ciphertext).is_ok(),
                "ciphertext hex"
            );
        }
    }

    #[test]
    fn all_vectors_sk_is_32_bytes() {
        for v in HpkeSealedBoxGoldenVector::load_all() {
            let bytes = hex::decode(&v.recipient_sk).unwrap();
            assert_eq!(
                bytes.len(),
                32,
                "sk for '{}' must be 32 bytes",
                v.description
            );
        }
    }

    #[test]
    fn all_vectors_pk_is_32_bytes() {
        for v in HpkeSealedBoxGoldenVector::load_all() {
            let bytes = hex::decode(&v.expected_recipient_pk).unwrap();
            assert_eq!(
                bytes.len(),
                32,
                "pk for '{}' must be 32 bytes",
                v.description
            );
        }
    }

    #[test]
    fn all_vectors_enc_is_32_bytes() {
        for v in HpkeSealedBoxGoldenVector::load_all() {
            let bytes = hex::decode(&v.expected_enc).unwrap();
            assert_eq!(
                bytes.len(),
                32,
                "enc for '{}' must be 32 bytes",
                v.description
            );
        }
    }

    #[test]
    fn all_vectors_rng_seed_is_32_bytes() {
        for v in HpkeSealedBoxGoldenVector::load_all() {
            let bytes = hex::decode(&v.rng_seed).unwrap();
            assert_eq!(
                bytes.len(),
                32,
                "rng seed for '{}' must be 32 bytes",
                v.description
            );
        }
    }

    // ── AAD binding correctness test ────────────────────────

    #[test]
    fn aad_recipient_node_binding() {
        use fcp_crypto::hpke_seal::{Fcp2Aad, hpke_open, hpke_seal};
        use fcp_crypto::x25519::X25519SecretKey;

        let sk = X25519SecretKey::from_bytes([0x10; 32]);
        let pk = sk.public_key();

        let aad_a = Fcp2Aad::for_zone_key(b"z:work", b"node:laptop", 1_700_000_000);
        let aad_b = Fcp2Aad::for_zone_key(b"z:work", b"node:server", 1_700_000_000);

        let sealed = hpke_seal(&pk, b"key_material", &aad_a).unwrap();
        assert!(
            hpke_open(&sk, &sealed, &aad_b).is_err(),
            "wrong recipient_node_id must cause decryption failure"
        );
    }

    #[test]
    fn aad_timestamp_binding() {
        use fcp_crypto::hpke_seal::{Fcp2Aad, hpke_open, hpke_seal};
        use fcp_crypto::x25519::X25519SecretKey;

        let sk = X25519SecretKey::from_bytes([0x10; 32]);
        let pk = sk.public_key();

        let aad_t1 = Fcp2Aad::for_zone_key(b"z:work", b"node:a", 1_700_000_000);
        let aad_t2 = Fcp2Aad::for_zone_key(b"z:work", b"node:a", 1_700_000_001);

        let sealed = hpke_seal(&pk, b"data", &aad_t1).unwrap();
        assert!(
            hpke_open(&sk, &sealed, &aad_t2).is_err(),
            "wrong issued_at must cause decryption failure"
        );
    }
}
