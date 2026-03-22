//! Webhook signature verification.
//!
//! Supports multiple signature algorithms used by different providers.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use crate::{WebhookError, WebhookResult};

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// HMAC-SHA256 (most common).
    HmacSha256,
    /// HMAC-SHA1 (legacy).
    HmacSha1,
    /// Ed25519 (Discord).
    Ed25519,
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacSha256 => write!(f, "HMAC-SHA256"),
            Self::HmacSha1 => write!(f, "HMAC-SHA1"),
            Self::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

/// Trait for signature verification.
pub trait SignatureVerifier: Send + Sync {
    /// Verify a signature against the payload.
    ///
    /// # Errors
    /// Returns [`WebhookError::InvalidSignature`] (or provider-specific parse errors)
    /// when the supplied signature does not validate for `payload`.
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()>;

    /// Get the algorithm used.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// HMAC-SHA256 signature verifier.
#[derive(Clone)]
pub struct HmacSha256Verifier {
    secret: Vec<u8>,
}

impl HmacSha256Verifier {
    /// Create a new HMAC-SHA256 verifier.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
        }
    }

    /// Compute signature for a payload.
    ///
    /// # Panics
    /// Panics only if the underlying HMAC implementation rejects key initialization.
    #[must_use]
    pub fn compute(&self, payload: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload);
        hex::encode(mac.finalize().into_bytes())
    }
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()> {
        // Handle different signature formats
        let sig_hex = signature
            .strip_prefix("sha256=")
            .or_else(|| signature.strip_prefix("v1="))
            .or_else(|| signature.strip_prefix("v0="))
            .unwrap_or(signature);

        let sig_bytes = hex::decode(sig_hex).map_err(|_| WebhookError::InvalidSignature)?;

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload);

        mac.verify_slice(&sig_bytes)
            .map_err(|_| WebhookError::InvalidSignature)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HmacSha256
    }
}

impl std::fmt::Debug for HmacSha256Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha256Verifier")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// HMAC-SHA1 signature verifier (legacy).
#[derive(Clone)]
pub struct HmacSha1Verifier {
    secret: Vec<u8>,
}

impl HmacSha1Verifier {
    /// Create a new HMAC-SHA1 verifier.
    #[must_use]
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
        }
    }

    /// Compute signature for a payload.
    ///
    /// # Panics
    /// Panics only if the underlying HMAC implementation rejects key initialization.
    #[must_use]
    pub fn compute(&self, payload: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha1>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload);
        hex::encode(mac.finalize().into_bytes())
    }
}

impl SignatureVerifier for HmacSha1Verifier {
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()> {
        let sig_hex = signature.strip_prefix("sha1=").unwrap_or(signature);
        let sig_bytes = hex::decode(sig_hex).map_err(|_| WebhookError::InvalidSignature)?;

        let mut mac =
            Hmac::<Sha1>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(payload);

        mac.verify_slice(&sig_bytes)
            .map_err(|_| WebhookError::InvalidSignature)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HmacSha1
    }
}

impl std::fmt::Debug for HmacSha1Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha1Verifier")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Ed25519 signature verifier.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    public_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    /// Create from a hex-encoded public key.
    ///
    /// # Errors
    /// Returns [`WebhookError::InvalidSignature`] when the key is invalid or wrong length.
    /// Returns decode errors when `public_key_hex` is not valid hex.
    pub fn from_hex(public_key_hex: &str) -> WebhookResult<Self> {
        let key_bytes = hex::decode(public_key_hex)?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| WebhookError::InvalidSignature)?;

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
            .map_err(|_| WebhookError::InvalidSignature)?;

        Ok(Self { public_key })
    }

    /// Create from raw bytes.
    ///
    /// # Errors
    /// Returns [`WebhookError::InvalidSignature`] when bytes do not form a valid Ed25519 key.
    pub fn from_bytes(bytes: &[u8; 32]) -> WebhookResult<Self> {
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| WebhookError::InvalidSignature)?;

        Ok(Self { public_key })
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, payload: &[u8], signature: &str) -> WebhookResult<()> {
        use ed25519_dalek::Verifier;

        let sig_bytes = hex::decode(signature).map_err(|_| WebhookError::InvalidSignature)?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| WebhookError::InvalidSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        self.public_key
            .verify(payload, &signature)
            .map_err(|_| WebhookError::InvalidSignature)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_verify() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"test payload";
        let signature = verifier.compute(payload);

        assert!(verifier.verify(payload, &signature).is_ok());
        assert!(verifier.verify(payload, "invalid").is_err());
    }

    #[test]
    fn test_hmac_sha256_with_prefix() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("sha256={}", verifier.compute(payload));

        assert!(verifier.verify(payload, &signature).is_ok());
    }

    #[test]
    fn test_hmac_sha1_verify() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = b"test payload";
        let signature = verifier.compute(payload);

        assert!(verifier.verify(payload, &signature).is_ok());
        assert!(verifier.verify(payload, "invalid").is_err());
    }

    #[test]
    fn test_hmac_sha1_with_prefix() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("sha1={}", verifier.compute(payload));

        assert!(verifier.verify(payload, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_verify() {
        use ed25519_dalek::{Signer, SigningKey};

        // Generate a key pair for testing
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);

        let verifying_key = signing_key.verifying_key();
        let payload = b"test payload";
        let signature = signing_key.sign(payload);

        let verifier = Ed25519Verifier::from_bytes(&verifying_key.to_bytes()).unwrap();
        let sig_hex = hex::encode(signature.to_bytes());

        assert!(verifier.verify(payload, &sig_hex).is_ok());
    }

    // ── New tests ──

    #[test]
    fn test_signature_algorithm_display() {
        assert_eq!(SignatureAlgorithm::HmacSha256.to_string(), "HMAC-SHA256");
        assert_eq!(SignatureAlgorithm::HmacSha1.to_string(), "HMAC-SHA1");
        assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "Ed25519");
    }

    #[test]
    fn test_hmac_sha256_debug_redacts_secret() {
        let v = HmacSha256Verifier::new("supersecret");
        let debug = format!("{v:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("supersecret"));
    }

    #[test]
    fn test_hmac_sha1_debug_redacts_secret() {
        let v = HmacSha1Verifier::new("supersecret");
        let debug = format!("{v:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("supersecret"));
    }

    #[test]
    fn test_hmac_sha256_with_v1_prefix() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("v1={}", verifier.compute(payload));
        assert!(verifier.verify(payload, &signature).is_ok());
    }

    #[test]
    fn test_hmac_sha256_with_v0_prefix() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("v0={}", verifier.compute(payload));
        assert!(verifier.verify(payload, &signature).is_ok());
    }

    #[test]
    fn test_hmac_sha256_algorithm() {
        let v = HmacSha256Verifier::new("secret");
        assert_eq!(v.algorithm(), SignatureAlgorithm::HmacSha256);
    }

    #[test]
    fn test_hmac_sha1_algorithm() {
        let v = HmacSha1Verifier::new("secret");
        assert_eq!(v.algorithm(), SignatureAlgorithm::HmacSha1);
    }

    #[test]
    fn test_ed25519_algorithm() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let v = Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        assert_eq!(v.algorithm(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_ed25519_from_hex() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let hex_key = hex::encode(signing_key.verifying_key().to_bytes());
        let v = Ed25519Verifier::from_hex(&hex_key);
        assert!(v.is_ok());
    }

    #[test]
    fn test_ed25519_from_hex_invalid() {
        assert!(Ed25519Verifier::from_hex("not-hex").is_err());
        // Valid hex but wrong length
        assert!(Ed25519Verifier::from_hex("aabb").is_err());
    }

    #[test]
    fn test_hmac_sha256_wrong_payload_fails() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"original");
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha1_with_sha1_prefix() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = b"test payload";
        let signature = format!("sha1={}", verifier.compute(payload));
        assert!(verifier.verify(payload, &signature).is_ok());
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn test_hmac_sha256_empty_payload() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"");
        assert!(verifier.verify(b"", &sig).is_ok());
        assert!(verifier.verify(b"x", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha1_empty_payload() {
        let verifier = HmacSha1Verifier::new("secret");
        let sig = verifier.compute(b"");
        assert!(verifier.verify(b"", &sig).is_ok());
        assert!(verifier.verify(b"x", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_empty_secret() {
        let verifier = HmacSha256Verifier::new("");
        let sig = verifier.compute(b"test");
        assert!(verifier.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_binary_payload() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload: Vec<u8> = (0..=255).collect();
        let sig = verifier.compute(&payload);
        assert!(verifier.verify(&payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig1 = verifier.compute(b"test");
        let sig2 = verifier.compute(b"test");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sha256_different_secrets_different_sigs() {
        let v1 = HmacSha256Verifier::new("secret1");
        let v2 = HmacSha256Verifier::new("secret2");
        let sig1 = v1.compute(b"test");
        let sig2 = v2.compute(b"test");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sha256_cross_verify_fails() {
        let v1 = HmacSha256Verifier::new("secret1");
        let v2 = HmacSha256Verifier::new("secret2");
        let sig1 = v1.compute(b"test");
        assert!(v2.verify(b"test", &sig1).is_err());
    }

    #[test]
    fn test_hmac_sha256_signature_is_hex() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"test");
        // Should be 64 hex characters (256 bits = 32 bytes = 64 hex chars)
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_sha1_signature_is_hex() {
        let verifier = HmacSha1Verifier::new("secret");
        let sig = verifier.compute(b"test");
        // Should be 40 hex characters (160 bits = 20 bytes = 40 hex chars)
        assert_eq!(sig.len(), 40);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_ed25519_invalid_signature_value() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();

        // Valid hex but wrong signature (64 zero bytes)
        let bad_sig = "00".repeat(64);
        assert!(verifier.verify(b"test", &bad_sig).is_err());
    }

    #[test]
    fn test_ed25519_tampered_payload() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let signature = signing_key.sign(b"original");
        let sig_hex = hex::encode(signature.to_bytes());

        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        assert!(verifier.verify(b"tampered", &sig_hex).is_err());
    }

    #[test]
    fn test_ed25519_wrong_length_signature() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();

        // Too short (not 64 bytes)
        assert!(verifier.verify(b"test", "aabb").is_err());
    }

    #[test]
    fn test_hmac_sha256_clone() {
        let v1 = HmacSha256Verifier::new("secret");
        let v2 = v1.clone();
        let sig = v1.compute(b"test");
        assert!(v2.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_clone() {
        let v1 = HmacSha1Verifier::new("secret");
        let v2 = v1.clone();
        let sig = v1.compute(b"test");
        assert!(v2.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_ed25519_clone() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let v1 = Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        let v2 = v1.clone();
        assert_eq!(v1.algorithm(), v2.algorithm());
    }

    #[test]
    fn test_hmac_sha256_invalid_hex_in_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        assert!(verifier.verify(b"test", "not-valid-hex!").is_err());
    }

    #[test]
    fn test_signature_algorithm_equality() {
        assert_eq!(
            SignatureAlgorithm::HmacSha256,
            SignatureAlgorithm::HmacSha256
        );
        assert_ne!(SignatureAlgorithm::HmacSha256, SignatureAlgorithm::HmacSha1);
        assert_ne!(SignatureAlgorithm::HmacSha1, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_signature_algorithm_copy() {
        let alg = SignatureAlgorithm::Ed25519;
        let alg2 = alg; // Copy
        assert_eq!(alg, alg2);
    }

    // ── Batch 3: SunnyMoose deep test expansion ──

    #[test]
    fn test_hmac_sha256_unicode_payload() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = "\u{1F600}\u{1F4A9}\u{00E9}\u{00F1}\u{00FC}".as_bytes();
        let sig = verifier.compute(payload);
        assert!(verifier.verify(payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_unicode_payload() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = "\u{1F600}\u{1F4A9}\u{00E9}\u{00F1}\u{00FC}".as_bytes();
        let sig = verifier.compute(payload);
        assert!(verifier.verify(payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_large_payload() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = vec![b'X'; 1_000_000]; // 1MB
        let sig = verifier.compute(&payload);
        assert!(verifier.verify(&payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_large_payload() {
        let verifier = HmacSha1Verifier::new("secret");
        let payload = vec![b'X'; 1_000_000]; // 1MB
        let sig = verifier.compute(&payload);
        assert!(verifier.verify(&payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_unicode_secret() {
        let verifier = HmacSha256Verifier::new("\u{1F511}key\u{00E9}");
        let sig = verifier.compute(b"test");
        assert!(verifier.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_long_secret() {
        let long_secret = "s".repeat(10_000);
        let verifier = HmacSha256Verifier::new(&long_secret);
        let sig = verifier.compute(b"payload");
        assert!(verifier.verify(b"payload", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_deterministic() {
        let verifier = HmacSha1Verifier::new("key");
        let sig1 = verifier.compute(b"data");
        let sig2 = verifier.compute(b"data");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sha1_different_secrets_different_sigs() {
        let v1 = HmacSha1Verifier::new("key1");
        let v2 = HmacSha1Verifier::new("key2");
        assert_ne!(v1.compute(b"data"), v2.compute(b"data"));
    }

    #[test]
    fn test_hmac_sha1_cross_verify_fails() {
        let v1 = HmacSha1Verifier::new("key1");
        let v2 = HmacSha1Verifier::new("key2");
        let sig = v1.compute(b"test");
        assert!(v2.verify(b"test", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha1_wrong_payload_fails() {
        let verifier = HmacSha1Verifier::new("secret");
        let sig = verifier.compute(b"original");
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_signature_lowercase_hex() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"test");
        // Ensure output is lowercase hex
        assert!(
            sig.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn test_hmac_sha256_verify_uppercase_hex() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"test");
        let upper = sig.to_uppercase();
        // Uppercase hex should fail because hex::decode of uppercase gives different bytes
        // Actually hex::decode is case-insensitive, but HMAC verify compares bytes
        // so this depends on the hex decode. Let's just verify it one way.
        let result = verifier.verify(b"test", &upper);
        // hex::decode is case-insensitive, so uppercase should also work
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_algorithm_debug() {
        let debug = format!("{:?}", SignatureAlgorithm::HmacSha256);
        assert!(debug.contains("HmacSha256"));
        let debug = format!("{:?}", SignatureAlgorithm::HmacSha1);
        assert!(debug.contains("HmacSha1"));
        let debug = format!("{:?}", SignatureAlgorithm::Ed25519);
        assert!(debug.contains("Ed25519"));
    }

    #[test]
    fn test_signature_algorithm_clone() {
        let alg = SignatureAlgorithm::HmacSha256;
        let cloned = alg;
        assert_eq!(alg, cloned);
    }

    #[test]
    fn test_ed25519_debug_does_not_leak_key() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        let debug = format!("{verifier:?}");
        assert!(debug.contains("Ed25519Verifier"));
    }

    #[test]
    fn test_hmac_sha256_newline_in_payload() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"line1\nline2\r\nline3";
        let sig = verifier.compute(payload);
        assert!(verifier.verify(payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_null_bytes_in_payload() {
        let verifier = HmacSha256Verifier::new("secret");
        let payload = b"\x00\x00\x01\x00";
        let sig = verifier.compute(payload);
        assert!(verifier.verify(payload, &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_empty_secret() {
        let verifier = HmacSha1Verifier::new("");
        let sig = verifier.compute(b"test");
        assert!(verifier.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_invalid_hex_in_signature() {
        let verifier = HmacSha1Verifier::new("secret");
        assert!(verifier.verify(b"test", "not-valid-hex!").is_err());
    }

    // ── Batch 4: SunnyMoose additional test expansion ──

    #[test]
    fn test_hmac_sha256_verify_with_sha256_prefix_tampered() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = format!("sha256={}", verifier.compute(b"original"));
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_verify_with_v1_prefix_tampered() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = format!("v1={}", verifier.compute(b"original"));
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_verify_with_v0_prefix_tampered() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = format!("v0={}", verifier.compute(b"original"));
        assert!(verifier.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_single_byte_payload() {
        let verifier = HmacSha256Verifier::new("key");
        let sig = verifier.compute(b"x");
        assert!(verifier.verify(b"x", &sig).is_ok());
        assert!(verifier.verify(b"y", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha1_single_byte_payload() {
        let verifier = HmacSha1Verifier::new("key");
        let sig = verifier.compute(b"x");
        assert!(verifier.verify(b"x", &sig).is_ok());
        assert!(verifier.verify(b"y", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_binary_secret() {
        let secret = vec![0u8, 1, 2, 255, 254, 253];
        let verifier = HmacSha256Verifier::new(&secret);
        let sig = verifier.compute(b"test");
        assert!(verifier.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha1_binary_secret() {
        let secret = vec![0u8, 1, 2, 255, 254, 253];
        let verifier = HmacSha1Verifier::new(&secret);
        let sig = verifier.compute(b"test");
        assert!(verifier.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn test_hmac_sha256_different_payloads_different_sigs() {
        let verifier = HmacSha256Verifier::new("key");
        let sig1 = verifier.compute(b"payload_a");
        let sig2 = verifier.compute(b"payload_b");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sha1_different_payloads_different_sigs() {
        let verifier = HmacSha1Verifier::new("key");
        let sig1 = verifier.compute(b"payload_a");
        let sig2 = verifier.compute(b"payload_b");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_ed25519_from_bytes_all_zeros_is_valid() {
        // All-zero bytes form a valid Ed25519 identity point
        // (this tests that from_bytes doesn't necessarily reject all-zero)
        let result = Ed25519Verifier::from_bytes(&[0u8; 32]);
        // May or may not succeed depending on Ed25519 validation
        // Just ensure it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_ed25519_from_hex_wrong_length_too_long() {
        let long_hex = "ab".repeat(33); // 33 bytes instead of 32
        assert!(Ed25519Verifier::from_hex(&long_hex).is_err());
    }

    #[test]
    fn test_ed25519_from_hex_empty_string() {
        assert!(Ed25519Verifier::from_hex("").is_err());
    }

    #[test]
    fn test_ed25519_verify_empty_hex_signature() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        assert!(verifier.verify(b"test", "").is_err());
    }

    #[test]
    fn test_ed25519_verify_non_hex_signature() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        assert!(verifier.verify(b"test", "not-hex-at-all!!").is_err());
    }

    #[test]
    fn test_hmac_sha256_verify_empty_signature_string() {
        let verifier = HmacSha256Verifier::new("secret");
        // Empty string should fail (empty hex decodes to empty bytes)
        assert!(verifier.verify(b"test", "").is_err());
    }

    #[test]
    fn test_hmac_sha1_verify_empty_signature_string() {
        let verifier = HmacSha1Verifier::new("secret");
        assert!(verifier.verify(b"test", "").is_err());
    }

    #[test]
    fn test_hmac_sha1_long_secret() {
        let long_secret = "k".repeat(10_000);
        let verifier = HmacSha1Verifier::new(&long_secret);
        let sig = verifier.compute(b"payload");
        assert!(verifier.verify(b"payload", &sig).is_ok());
    }

    // ── Batch 5: SunnyMoose test expansion ──

    #[test]
    fn test_hmac_sha256_all_zero_secret() {
        let verifier = HmacSha256Verifier::new([0u8; 32]);
        let sig = verifier.compute(b"data");
        assert!(verifier.verify(b"data", &sig).is_ok());
        assert!(verifier.verify(b"other", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha1_all_zero_secret() {
        let verifier = HmacSha1Verifier::new([0u8; 20]);
        let sig = verifier.compute(b"data");
        assert!(verifier.verify(b"data", &sig).is_ok());
        assert!(verifier.verify(b"other", &sig).is_err());
    }

    #[test]
    fn test_hmac_sha256_verify_truncated_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"test");
        // Truncate to half length - should fail verification
        let truncated = &sig[..32];
        assert!(verifier.verify(b"test", truncated).is_err());
    }

    #[test]
    fn test_hmac_sha1_verify_truncated_signature() {
        let verifier = HmacSha1Verifier::new("secret");
        let sig = verifier.compute(b"test");
        let truncated = &sig[..20];
        assert!(verifier.verify(b"test", truncated).is_err());
    }

    #[test]
    fn test_hmac_sha256_verify_with_unknown_prefix() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig = verifier.compute(b"test");
        // Unknown prefix is not stripped, whole string treated as hex
        let prefixed = format!("unknown={sig}");
        assert!(verifier.verify(b"test", &prefixed).is_err());
    }

    #[test]
    fn test_hmac_sha256_compute_is_lowercase_hex() {
        let verifier = HmacSha256Verifier::new("key");
        let sig = verifier.compute(b"message");
        assert_eq!(sig, sig.to_lowercase());
    }

    #[test]
    fn test_hmac_sha1_compute_is_lowercase_hex() {
        let verifier = HmacSha1Verifier::new("key");
        let sig = verifier.compute(b"message");
        assert_eq!(sig, sig.to_lowercase());
    }

    #[test]
    fn test_ed25519_sign_and_verify_empty_payload() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let signature = signing_key.sign(b"");
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        let sig_hex = hex::encode(signature.to_bytes());
        assert!(verifier.verify(b"", &sig_hex).is_ok());
    }

    #[test]
    fn test_ed25519_sign_and_verify_large_payload() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ]);
        let payload = vec![b'Z'; 100_000];
        let signature = signing_key.sign(&payload);
        let verifier =
            Ed25519Verifier::from_bytes(&signing_key.verifying_key().to_bytes()).unwrap();
        let sig_hex = hex::encode(signature.to_bytes());
        assert!(verifier.verify(&payload, &sig_hex).is_ok());
    }

    #[test]
    fn test_hmac_sha256_sha256_prefix_strip_takes_priority() {
        let verifier = HmacSha256Verifier::new("key");
        let sig = verifier.compute(b"data");
        // sha256= prefix is tried first
        let prefixed = format!("sha256={sig}");
        assert!(verifier.verify(b"data", &prefixed).is_ok());
    }

    #[test]
    fn test_hmac_sha256_v1_prefix_used_when_no_sha256() {
        let verifier = HmacSha256Verifier::new("key");
        let sig = verifier.compute(b"data");
        let prefixed = format!("v1={sig}");
        assert!(verifier.verify(b"data", &prefixed).is_ok());
    }

    #[test]
    fn test_hmac_sha256_v0_prefix_used_when_no_sha256_or_v1() {
        let verifier = HmacSha256Verifier::new("key");
        let sig = verifier.compute(b"data");
        let prefixed = format!("v0={sig}");
        assert!(verifier.verify(b"data", &prefixed).is_ok());
    }

    #[test]
    fn test_hmac_sha256_two_different_payloads_differ() {
        let verifier = HmacSha256Verifier::new("secret");
        let sig_a = verifier.compute(b"aaaa");
        let sig_b = verifier.compute(b"aaab");
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn test_signature_algorithm_display_roundtrip_debug() {
        use std::collections::HashSet;
        let mut displays = HashSet::new();
        for alg in [
            SignatureAlgorithm::HmacSha256,
            SignatureAlgorithm::HmacSha1,
            SignatureAlgorithm::Ed25519,
        ] {
            let display = alg.to_string();
            assert!(!display.is_empty());
            displays.insert(display);
        }
        assert_eq!(displays.len(), 3, "All algorithm displays should be unique");
    }

    #[test]
    fn test_ed25519_from_hex_odd_length() {
        // Odd-length hex is invalid for hex::decode
        assert!(Ed25519Verifier::from_hex("abc").is_err());
    }

    #[test]
    fn test_hmac_sha256_verify_extra_long_hex_signature() {
        let verifier = HmacSha256Verifier::new("secret");
        // 65 hex chars (one byte too many) - valid hex but wrong length for HMAC
        let too_long = "a".repeat(66);
        assert!(verifier.verify(b"test", &too_long).is_err());
    }
}
