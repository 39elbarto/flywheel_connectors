//! Ed25519 signing and verification for FCP2.
//!
//! This module provides type-safe wrappers around ed25519-dalek with
//! proper domain separation and key ID derivation.

use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Ed25519 secret key size in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Ed25519 public key size in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes.
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 signing key (secret key).
///
/// This is a wrapper around `ed25519_dalek::SigningKey` with zeroize-on-drop
/// semantics and FCP2 key ID derivation.
#[derive(ZeroizeOnDrop)]
pub struct Ed25519SigningKey {
    inner: SigningKey,
    kid: KeyId,
}

impl Ed25519SigningKey {
    /// Generate a new random signing key.
    #[must_use]
    pub fn generate() -> Self {
        let inner = SigningKey::generate(&mut rand::rngs::OsRng);
        let kid = KeyId::derive_from_public_key(inner.verifying_key().as_bytes());
        Self { inner, kid }
    }

    /// Create from raw secret key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid Ed25519 secret key.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> CryptoResult<Self> {
        let inner = SigningKey::from_bytes(bytes);
        let kid = KeyId::derive_from_public_key(inner.verifying_key().as_bytes());
        Ok(Self { inner, kid })
    }

    /// Export the secret key bytes.
    ///
    /// **Security Warning:** Handle with extreme care. The returned bytes
    /// should be zeroized when no longer needed.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Get the corresponding verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey {
            inner: self.inner.verifying_key(),
            kid: self.kid.clone(),
        }
    }

    /// Get the key ID for this signing key.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.kid.clone()
    }

    /// Sign a message.
    ///
    /// The signature is computed over the raw message bytes. For FCP2 protocol
    /// messages, use `sign_canonical` with proper domain separation.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.inner.sign(message);
        Ed25519Signature { inner: sig }
    }

    /// Sign with domain separation.
    ///
    /// Computes: `Sign(domain || message)` where domain is a context string.
    /// This prevents cross-protocol signature reuse attacks.
    #[must_use]
    pub fn sign_with_context(&self, context: &[u8], message: &[u8]) -> Ed25519Signature {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(context.len() as u64).to_le_bytes());
        hasher.update(context);
        hasher.update(message);
        let digest = hasher.finalize();
        self.sign(digest.as_bytes())
    }
}

impl Clone for Ed25519SigningKey {
    fn clone(&self) -> Self {
        Self {
            inner: SigningKey::from_bytes(&self.inner.to_bytes()),
            kid: self.kid.clone(),
        }
    }
}

impl std::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Ed25519 verifying key (public key).
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    inner: VerifyingKey,
    kid: KeyId,
}

impl Ed25519VerifyingKey {
    /// Create from raw public key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not a valid Ed25519 public key.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> CryptoResult<Self> {
        let inner = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        let kid = KeyId::derive_from_public_key(bytes);
        Ok(Self { inner, kid })
    }

    /// Export the public key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.kid.clone()
    }

    /// Verify a signature over a message.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> CryptoResult<()> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Verify with domain separation.
    ///
    /// Verifies: `Verify(domain || message)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    pub fn verify_with_context(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> CryptoResult<()> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(context.len() as u64).to_le_bytes());
        hasher.update(context);
        hasher.update(message);
        let digest = hasher.finalize();
        self.verify(digest.as_bytes(), signature)
    }
}

impl PartialEq for Ed25519VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for Ed25519VerifyingKey {}

impl std::fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519VerifyingKey")
            .field("kid", &self.kid)
            .field("inner", &hex::encode(self.to_bytes()))
            .finish()
    }
}

impl Serialize for Ed25519VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Ed25519VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(serde::de::Error::custom(format!(
                "invalid public key length: expected {PUBLIC_KEY_SIZE}, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

/// Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519Signature {
    #[serde(with = "signature_serde")]
    inner: Signature,
}

mod signature_serde {
    use super::{SIGNATURE_SIZE, Signature};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&sig.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != SIGNATURE_SIZE {
            return Err(serde::de::Error::custom(format!(
                "invalid signature length: expected {SIGNATURE_SIZE}, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Signature::from_bytes(&arr))
    }
}

impl Ed25519Signature {
    /// Create from raw signature bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        let inner = Signature::from_bytes(bytes);
        Self { inner }
    }

    /// Export the signature bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.inner.to_bytes()
    }

    /// Create a signature from a byte slice.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidSignatureLength`] if slice length != 64.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                expected: SIGNATURE_SIZE,
                actual: slice.len(),
            });
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(slice);
        Ok(Self::from_bytes(&arr))
    }

    /// Encode as lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519Signature({})", self.to_hex())
    }
}

impl std::fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let message = b"test message";

        let sig = sk.sign(message);
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let sig = sk.sign(b"message 1");
        assert!(pk.verify(b"message 2", &sig).is_err());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let sk1 = Ed25519SigningKey::generate();
        let sk2 = Ed25519SigningKey::generate();
        let pk2 = sk2.verifying_key();

        let sig = sk1.sign(b"message");
        assert!(pk2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn sign_with_context() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let context = b"FCP2-TEST";
        let message = b"test message";

        let sig = sk.sign_with_context(context, message);
        assert!(pk.verify_with_context(context, message, &sig).is_ok());

        // Wrong context should fail
        assert!(pk.verify_with_context(b"WRONG", message, &sig).is_err());
    }

    #[test]
    fn key_roundtrip() {
        let sk = Ed25519SigningKey::generate();
        let sk_bytes = sk.to_bytes();
        let sk2 = Ed25519SigningKey::from_bytes(&sk_bytes).unwrap();

        let pk = sk.verifying_key();
        let pk2 = sk2.verifying_key();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn signature_roundtrip() {
        let sk = Ed25519SigningKey::generate();
        let sig = sk.sign(b"message");
        let sig_bytes = sig.to_bytes();
        let sig2 = Ed25519Signature::from_bytes(&sig_bytes);
        assert_eq!(sig, sig2);
    }

    #[test]
    fn key_id_consistent() {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        assert_eq!(sk.key_id(), pk.key_id());
    }

    #[test]
    fn key_id_unique() {
        let sk1 = Ed25519SigningKey::generate();
        let sk2 = Ed25519SigningKey::generate();
        assert_ne!(sk1.key_id(), sk2.key_id());
    }

    #[test]
    fn deterministic_signature() {
        let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]).unwrap();
        let message = b"deterministic test";

        let sig1 = sk.sign(message);
        let sig2 = sk.sign(message);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn golden_vector_ed25519() {
        // Test vector from ed25519 reference implementation
        // Secret key: 32 bytes of zeros
        let sk = Ed25519SigningKey::from_bytes(&[0u8; 32]).unwrap();
        let pk = sk.verifying_key();

        // The public key for sk=0 is well-known
        assert_eq!(
            hex::encode(pk.to_bytes()),
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        );
    }

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 Section 7.1 - Test 1
        // SECRET KEY (seed):
        let sk_bytes =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let sk = Ed25519SigningKey::from_bytes(&sk_arr).unwrap();

        // PUBLIC KEY:
        let expected_pk =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        assert_eq!(
            sk.verifying_key().to_bytes().as_slice(),
            expected_pk.as_slice()
        );

        // MESSAGE: empty
        let message = b"";

        // SIGNATURE:
        let expected_sig = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).unwrap();

        let sig = sk.sign(message);
        assert_eq!(sig.to_bytes().as_slice(), expected_sig.as_slice());

        // Verify round-trip
        let pk = sk.verifying_key();
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn rfc8032_test_vector_2() {
        // RFC 8032 Section 7.1 - Test 2
        let sk_bytes =
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .unwrap();
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let sk = Ed25519SigningKey::from_bytes(&sk_arr).unwrap();

        // PUBLIC KEY:
        let expected_pk =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap();
        assert_eq!(
            sk.verifying_key().to_bytes().as_slice(),
            expected_pk.as_slice()
        );

        // MESSAGE: single byte 0x72
        let message = &[0x72u8];

        // SIGNATURE:
        let expected_sig = hex::decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ).unwrap();

        let sig = sk.sign(message);
        assert_eq!(sig.to_bytes().as_slice(), expected_sig.as_slice());

        // Verify round-trip
        let pk = sk.verifying_key();
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn rfc8032_test_vector_3() {
        // RFC 8032 Section 7.1 - Test 3 (two-byte message)
        let sk_bytes =
            hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
                .unwrap();
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_bytes);
        let sk = Ed25519SigningKey::from_bytes(&sk_arr).unwrap();

        // PUBLIC KEY:
        let expected_pk =
            hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .unwrap();
        assert_eq!(
            sk.verifying_key().to_bytes().as_slice(),
            expected_pk.as_slice()
        );

        // MESSAGE: 0xaf82
        let message = &[0xaf, 0x82];

        // SIGNATURE:
        let expected_sig = hex::decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ).unwrap();

        let sig = sk.sign(message);
        assert_eq!(sig.to_bytes().as_slice(), expected_sig.as_slice());

        // Verify round-trip
        let pk = sk.verifying_key();
        assert!(pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn signature_malleability_rejection() {
        // Ed25519 signatures must have S < L (where L is the order of the base point)
        // This tests that we correctly verify signatures and don't accept malleable ones
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();
        let message = b"test message";

        let sig = sk.sign(message);

        // Valid signature should verify
        assert!(pk.verify(message, &sig).is_ok());

        // Create an invalid signature (all 0xff bytes for S component)
        // This should fail verification
        let mut bad_sig_bytes = sig.to_bytes();
        // Set the S component (last 32 bytes) to values that would make S >= L
        bad_sig_bytes[63] = 0xff;
        bad_sig_bytes[62] = 0xff;
        let bad_sig = Ed25519Signature::from_bytes(&bad_sig_bytes);

        // This should fail because the signature is invalid
        assert!(pk.verify(message, &bad_sig).is_err());
    }

    #[test]
    fn empty_message_signature() {
        // Verify we can sign and verify empty messages
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let sig = sk.sign(b"");
        assert!(pk.verify(b"", &sig).is_ok());
    }

    #[test]
    fn large_message_signature() {
        // Verify we can sign and verify large messages
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key();

        let large_message = vec![0x42u8; 10000];
        let sig = sk.sign(&large_message);
        assert!(pk.verify(&large_message, &sig).is_ok());
    }
}
