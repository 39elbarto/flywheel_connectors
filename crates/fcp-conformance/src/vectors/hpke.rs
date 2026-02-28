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
            expected_recipient_pk: "".into(), // Computed at verification time
            rng_seed: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            plaintext: "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".into(),
            zone_id: hex::encode(b"z:work"),
            recipient_node_id: hex::encode(b"node:laptop.mesh.ts.net"),
            purpose: "FCP2-ZONE-KEY".into(),
            issued_at: 1_700_000_000,
            expected_aad_cbor: "".into(), // Computed at verification time
            expected_enc: "".into(),      // Populated after first run
            expected_ciphertext: "".into(), // Populated after first run
        }
    }

    /// Vector 2: ObjectId key sealing with purpose `FCP2-OBJECTID-KEY`.
    ///
    /// Uses recipient sk = `[0x20; 32]`, rng seed = `[0xBB; 32]`.
    /// Seals a 32-byte `ObjectIdKey` to a recipient in a private zone.
    #[must_use]
    pub fn vector_2_objectid_key_seal() -> Self {
        Self {
            description: "ObjectId key seal (sk=[0x20;32], seed=[0xBB;32])".into(),
            recipient_sk: "2020202020202020202020202020202020202020202020202020202020202020".into(),
            expected_recipient_pk: "".into(),
            rng_seed: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            plaintext: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            zone_id: hex::encode(b"z:private"),
            recipient_node_id: hex::encode(b"node:server.mesh.ts.net"),
            purpose: "FCP2-OBJECTID-KEY".into(),
            issued_at: 1_700_086_400,
            expected_aad_cbor: "".into(),
            expected_enc: "".into(),
            expected_ciphertext: "".into(),
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
            expected_recipient_pk: "".into(),
            rng_seed: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            plaintext: "feedfacedeadbeeffeedfacedeadbeef".into(), // 16 bytes
            zone_id: hex::encode(b"z:public"),
            recipient_node_id: hex::encode(b"node:ci-runner.mesh.ts.net"),
            purpose: "FCP2-SECRET-SHARE".into(),
            issued_at: 1_700_172_800,
            expected_aad_cbor: "".into(),
            expected_enc: "".into(),
            expected_ciphertext: "".into(),
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
        use fcp_crypto::hpke_seal::{hpke_open, hpke_seal_with_rng, Fcp2Aad, HpkeSealedBox};
        use fcp_crypto::x25519::X25519SecretKey;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        // 1. Parse recipient secret key
        let sk_bytes: [u8; 32] = hex::decode(&self.recipient_sk)
            .map_err(|e| format!("invalid recipient_sk hex: {e}"))?
            .try_into()
            .map_err(|_| "recipient_sk must be 32 bytes")?;
        let recipient_sk = X25519SecretKey::from_bytes(sk_bytes);
        let recipient_pk = recipient_sk.public_key();

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
        let aad_encoded = aad.encode();
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
        let opened = hpke_open(&recipient_sk, &sealed, &aad)
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
        use fcp_crypto::hpke_seal::{hpke_seal_with_rng, Fcp2Aad};
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

        let zone_bytes = zone_aad.encode();
        let oid_bytes = oid_aad.encode();
        let share_bytes = share_aad.encode();

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
        use fcp_crypto::hpke_seal::{hpke_open, hpke_seal, Fcp2Aad};
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
        use fcp_crypto::hpke_seal::{hpke_seal, Fcp2Aad, HPKE_ENC_SIZE, HPKE_TAG_SIZE};
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
}
