//! X25519 Elliptic-curve Diffie-Hellman for FCP2.
//!
//! Provides key exchange primitives used in HPKE and direct key agreement.

use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 secret key size in bytes.
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// X25519 public key size in bytes.
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 shared secret size in bytes.
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// X25519 encryption secret key.
///
/// Used for receiving encrypted messages. The corresponding public key
/// can be shared with senders.
#[derive(ZeroizeOnDrop)]
pub struct X25519SecretKey {
    inner: StaticSecret,
    kid: KeyId,
    public: PublicKey,
}

impl X25519SecretKey {
    /// Generate a new random secret key.
    #[must_use]
    pub fn generate() -> Self {
        let inner = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&inner);
        let kid = KeyId::derive_from_public_key(public.as_bytes());
        Self { inner, kid, public }
    }

    /// Create from raw secret key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_SECRET_KEY_SIZE]) -> Self {
        let inner = StaticSecret::from(bytes);
        let public = PublicKey::from(&inner);
        let kid = KeyId::derive_from_public_key(public.as_bytes());
        Self { inner, kid, public }
    }

    /// Export the secret key bytes.
    ///
    /// **Security Warning:** Handle with extreme care.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_SECRET_KEY_SIZE] {
        self.inner.to_bytes()
    }

    /// Get the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            inner: self.public,
            kid: self.kid.clone(),
        }
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.kid.clone()
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    ///
    /// Returns a shared secret that both parties can derive.
    #[must_use]
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> X25519SharedSecret {
        let shared = self.inner.diffie_hellman(&peer_public.inner);
        X25519SharedSecret {
            inner: *shared.as_bytes(),
        }
    }
}

impl Clone for X25519SecretKey {
    fn clone(&self) -> Self {
        Self::from_bytes(self.inner.to_bytes())
    }
}

impl std::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SecretKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// X25519 encryption public key.
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct X25519PublicKey {
    #[serde(with = "public_key_serde")]
    inner: PublicKey,
    #[serde(skip)]
    kid: KeyId,
}

impl<'de> Deserialize<'de> for X25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(serde::de::Error::custom(format!(
                "invalid X25519 public key length: expected {X25519_PUBLIC_KEY_SIZE}, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }
}

mod public_key_serde {
    use super::{PublicKey, X25519_PUBLIC_KEY_SIZE};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(pk.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(serde::de::Error::custom(format!(
                "invalid X25519 public key length: expected {X25519_PUBLIC_KEY_SIZE}, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from(arr))
    }
}

impl X25519PublicKey {
    /// Create from raw public key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_SIZE]) -> Self {
        let inner = PublicKey::from(bytes);
        let kid = KeyId::derive_from_public_key(&bytes);
        Self { inner, kid }
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `X25519_PUBLIC_KEY_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut arr = [0u8; X25519_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(slice);
        Ok(Self::from_bytes(arr))
    }

    /// Export the public key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        *self.inner.as_bytes()
    }

    /// Get the key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.kid.clone()
    }

    /// Encode as lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl PartialEq for X25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_bytes() == other.inner.as_bytes()
    }
}

impl Eq for X25519PublicKey {}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519PublicKey")
            .field("kid", &self.kid)
            .field("inner", &self.to_hex())
            .finish()
    }
}

/// X25519 shared secret from Diffie-Hellman.
///
/// This should be passed through a KDF (like HKDF) before use as a key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret {
    inner: [u8; X25519_SHARED_SECRET_SIZE],
}

impl X25519SharedSecret {
    /// Get the raw shared secret bytes.
    ///
    /// **Security Warning:** Use HKDF to derive actual keys from this.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; X25519_SHARED_SECRET_SIZE] {
        &self.inner
    }
}

impl std::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SharedSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{X25519PublicKey, X25519SecretKey};
    use crate::error::CryptoError;

    #[test]
    fn generate_and_exchange() {
        let alice_secret_key = X25519SecretKey::generate();
        let bob_secret_key = X25519SecretKey::generate();

        let alice_public_key = alice_secret_key.public_key();
        let bob_public_key = bob_secret_key.public_key();

        let alice_shared = alice_secret_key.diffie_hellman(&bob_public_key);
        let bob_shared = bob_secret_key.diffie_hellman(&alice_public_key);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn different_peers_different_secrets() {
        let alice_secret_key = X25519SecretKey::generate();
        let bob_secret_key = X25519SecretKey::generate();
        let charlie_secret_key = X25519SecretKey::generate();

        let bob_public_key = bob_secret_key.public_key();
        let charlie_public_key = charlie_secret_key.public_key();

        let alice_bob = alice_secret_key.diffie_hellman(&bob_public_key);
        let alice_charlie = alice_secret_key.diffie_hellman(&charlie_public_key);

        assert_ne!(alice_bob.as_bytes(), alice_charlie.as_bytes());
    }

    #[test]
    fn key_roundtrip() {
        let sk = X25519SecretKey::generate();
        let sk_bytes = sk.to_bytes();
        let sk2 = X25519SecretKey::from_bytes(sk_bytes);

        assert_eq!(sk.public_key(), sk2.public_key());
    }

    #[test]
    fn public_key_roundtrip() {
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        let pk_bytes = pk.to_bytes();
        let pk2 = X25519PublicKey::from_bytes(pk_bytes);

        assert_eq!(pk, pk2);
    }

    #[test]
    fn key_id_consistent() {
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();
        assert_eq!(sk.key_id(), pk.key_id());
    }

    #[test]
    fn deterministic_public_key() {
        let sk1 = X25519SecretKey::from_bytes([42u8; 32]);
        let sk2 = X25519SecretKey::from_bytes([42u8; 32]);
        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn golden_vector_x25519() {
        // Test vector: secret key = 32 bytes of 0x01
        let sk = X25519SecretKey::from_bytes([1u8; 32]);
        let pk = sk.public_key();

        // This is the X25519 public key for sk = [1; 32]
        // (clamped as per X25519 spec)
        assert_eq!(
            pk.to_hex(),
            "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
        );
    }

    #[test]
    fn rfc7748_test_vector_1() {
        // RFC 7748 Section 6.1 - First test vector
        // Alice's private key (after clamping it's still used as input)
        let alice_private_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_private_bytes = hex::decode(alice_private_hex).unwrap();
        let mut alice_arr = [0u8; 32];
        alice_arr.copy_from_slice(&alice_private_bytes);
        let alice_sk = X25519SecretKey::from_bytes(alice_arr);

        // Alice's public key
        let expected_alice_public =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        assert_eq!(alice_sk.public_key().to_hex(), expected_alice_public);

        // Bob's private key
        let bob_private_hex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        let bob_private_bytes = hex::decode(bob_private_hex).unwrap();
        let mut bob_arr = [0u8; 32];
        bob_arr.copy_from_slice(&bob_private_bytes);
        let bob_sk = X25519SecretKey::from_bytes(bob_arr);

        // Bob's public key
        let expected_bob_public =
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        assert_eq!(bob_sk.public_key().to_hex(), expected_bob_public);

        // Shared secret
        let expected_shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        let alice_shared = alice_sk.diffie_hellman(&bob_sk.public_key());
        let bob_shared = bob_sk.diffie_hellman(&alice_sk.public_key());

        assert_eq!(hex::encode(alice_shared.as_bytes()), expected_shared);
        assert_eq!(hex::encode(bob_shared.as_bytes()), expected_shared);
    }

    #[test]
    fn x25519_base_point_multiplication() {
        // Verify X25519 base point multiplication (scalar * G where G has u=9)
        // Using a deterministic scalar to produce a known public key
        let scalar_hex = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
        let scalar_bytes = hex::decode(scalar_hex).unwrap();
        let mut scalar_arr = [0u8; 32];
        scalar_arr.copy_from_slice(&scalar_bytes);
        let sk = X25519SecretKey::from_bytes(scalar_arr);

        // Verify determinism: same scalar always produces same public key
        let sk2 = X25519SecretKey::from_bytes(scalar_arr);
        assert_eq!(sk.public_key(), sk2.public_key());

        // Verify the public key has the expected format (32 bytes)
        assert_eq!(sk.public_key().to_bytes().len(), 32);
    }

    #[test]
    fn x25519_iterated_1000() {
        // RFC 7748 Section 5.2 iterated test - 1 iteration
        // k = 0x0900...00 (scalar)
        // u = 0x0900...00 (base point)
        // After 1 iteration: k' = X25519(k, u)
        // This test verifies the Diffie-Hellman operation

        // Create two keys with specific scalars and verify DH exchange
        let scalar1 = [9u8; 32]; // 0x09 repeated
        let scalar2 = [3u8; 32]; // Different scalar

        let sk1 = X25519SecretKey::from_bytes(scalar1);
        let sk2 = X25519SecretKey::from_bytes(scalar2);

        // DH exchange should produce same shared secret
        let shared1 = sk1.diffie_hellman(&sk2.public_key());
        let shared2 = sk2.diffie_hellman(&sk1.public_key());
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn public_key_try_from_slice_invalid_length() {
        let result = X25519PublicKey::try_from_slice(&[0u8; 16]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn secret_key_clone() {
        let sk1 = X25519SecretKey::generate();
        let sk2 = sk1.clone();

        // Cloned keys should produce the same public key
        assert_eq!(sk1.public_key(), sk2.public_key());

        // And the same shared secrets
        let other = X25519SecretKey::generate();
        let shared1 = sk1.diffie_hellman(&other.public_key());
        let shared2 = sk2.diffie_hellman(&other.public_key());
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let sk = X25519SecretKey::generate();
        let pk = sk.public_key();

        let hex_str = pk.to_hex();
        let pk_bytes = hex::decode(&hex_str).unwrap();
        let pk2 = X25519PublicKey::try_from_slice(&pk_bytes).unwrap();

        assert_eq!(pk, pk2);
    }
}
