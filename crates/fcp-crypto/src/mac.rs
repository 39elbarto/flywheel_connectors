//! Session MACs for FCP2 frame authentication.
//!
//! Uses BLAKE3 keyed MAC for authenticating session frames.
//! This is preferred over Poly1305 for multi-frame authentication.

use crate::error::{CryptoError, CryptoResult};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// MAC output size (BLAKE3 truncated to 16 bytes for Poly1305 parity).
pub const MAC_SIZE: usize = 16;

/// Full BLAKE3 MAC size when truncation is not needed.
pub const BLAKE3_MAC_SIZE: usize = 32;

/// MAC key size.
pub const MAC_KEY_SIZE: usize = 32;

/// MAC key with zeroize semantics.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MacKey {
    bytes: [u8; MAC_KEY_SIZE],
}

impl MacKey {
    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; MAC_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Generate a random MAC key.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; MAC_KEY_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self { bytes }
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `MAC_KEY_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != MAC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: MAC_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; MAC_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MAC_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKey").finish_non_exhaustive()
    }
}

/// BLAKE3 keyed MAC for session frame authentication.
///
/// Uses BLAKE3's keyed mode for efficient and secure message authentication.
pub struct Blake3Mac {
    key: [u8; MAC_KEY_SIZE],
}

impl Blake3Mac {
    /// Create a new MAC instance.
    #[must_use]
    pub const fn new(key: &MacKey) -> Self {
        Self {
            key: *key.as_bytes(),
        }
    }

    /// Compute MAC over a message, returning truncated 16-byte tag.
    #[must_use]
    pub fn compute(&self, message: &[u8]) -> [u8; MAC_SIZE] {
        let hash = blake3::keyed_hash(&self.key, message);
        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(&hash.as_bytes()[..MAC_SIZE]);
        mac
    }

    /// Compute full 32-byte MAC.
    #[must_use]
    pub fn compute_full(&self, message: &[u8]) -> [u8; BLAKE3_MAC_SIZE] {
        let hash = blake3::keyed_hash(&self.key, message);
        *hash.as_bytes()
    }

    /// Verify a truncated MAC.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC is invalid.
    pub fn verify(&self, message: &[u8], tag: &[u8; MAC_SIZE]) -> CryptoResult<()> {
        let computed = self.compute(message);
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }

    /// Verify a full 32-byte MAC.
    ///
    /// # Errors
    ///
    /// Returns an error if the MAC is invalid.
    pub fn verify_full(&self, message: &[u8], tag: &[u8; BLAKE3_MAC_SIZE]) -> CryptoResult<()> {
        let computed = self.compute_full(message);
        if computed.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

impl Drop for Blake3Mac {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Incremental MAC for multi-part messages.
///
/// Useful for authenticating frames with headers and payloads.
pub struct IncrementalMac {
    hasher: blake3::Hasher,
}

impl IncrementalMac {
    /// Create a new incremental MAC.
    #[must_use]
    pub fn new(key: &MacKey) -> Self {
        let hasher = blake3::Hasher::new_keyed(key.as_bytes());
        Self { hasher }
    }

    /// Update with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the truncated 16-byte MAC.
    #[must_use]
    pub fn finalize(self) -> [u8; MAC_SIZE] {
        let hash = self.hasher.finalize();
        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(&hash.as_bytes()[..MAC_SIZE]);
        mac
    }

    /// Finalize and return the full 32-byte MAC.
    #[must_use]
    pub fn finalize_full(self) -> [u8; BLAKE3_MAC_SIZE] {
        let hash = self.hasher.finalize();
        *hash.as_bytes()
    }
}

/// Convenience function: compute BLAKE3 keyed MAC (16-byte).
#[must_use]
pub fn blake3_mac(key: &MacKey, message: &[u8]) -> [u8; MAC_SIZE] {
    Blake3Mac::new(key).compute(message)
}

/// Convenience function: compute full BLAKE3 keyed MAC (32-byte).
#[must_use]
pub fn blake3_mac_full(key: &MacKey, message: &[u8]) -> [u8; BLAKE3_MAC_SIZE] {
    Blake3Mac::new(key).compute_full(message)
}

/// Convenience function: verify BLAKE3 keyed MAC (16-byte).
///
/// # Errors
///
/// Returns an error if the MAC is invalid.
pub fn blake3_mac_verify(key: &MacKey, message: &[u8], tag: &[u8; MAC_SIZE]) -> CryptoResult<()> {
    Blake3Mac::new(key).verify(message, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let key = MacKey::generate();
        let message = b"test message";

        let tag = blake3_mac(&key, message);
        assert!(blake3_mac_verify(&key, message, &tag).is_ok());
    }

    #[test]
    fn mac_wrong_message() {
        let key = MacKey::generate();
        let tag = blake3_mac(&key, b"message 1");
        assert!(blake3_mac_verify(&key, b"message 2", &tag).is_err());
    }

    #[test]
    fn mac_wrong_key() {
        let key1 = MacKey::generate();
        let key2 = MacKey::generate();

        let tag = blake3_mac(&key1, b"message");
        assert!(blake3_mac_verify(&key2, b"message", &tag).is_err());
    }

    #[test]
    fn mac_deterministic() {
        let key = MacKey::from_bytes([42u8; 32]);
        let message = b"test";

        let tag1 = blake3_mac(&key, message);
        let tag2 = blake3_mac(&key, message);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn mac_different_messages() {
        let key = MacKey::generate();

        let tag1 = blake3_mac(&key, b"message 1");
        let tag2 = blake3_mac(&key, b"message 2");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn incremental_mac() {
        let key = MacKey::generate();
        let message = b"hello world";

        // One-shot
        let tag1 = blake3_mac(&key, message);

        // Incremental
        let mut mac = IncrementalMac::new(&key);
        mac.update(b"hello");
        mac.update(b" ");
        mac.update(b"world");
        let tag2 = mac.finalize();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn full_mac_length() {
        let key = MacKey::generate();
        let tag = blake3_mac_full(&key, b"message");
        assert_eq!(tag.len(), BLAKE3_MAC_SIZE);
    }

    #[test]
    fn truncated_mac_length() {
        let key = MacKey::generate();
        let tag = blake3_mac(&key, b"message");
        assert_eq!(tag.len(), MAC_SIZE);
    }

    #[test]
    fn golden_vector_blake3_keyed() {
        // BLAKE3 keyed hash test vector
        let key = MacKey::from_bytes([0u8; 32]);
        let tag = blake3_mac_full(&key, b"");

        // BLAKE3 keyed hash of empty input with zero key
        assert_eq!(
            hex::encode(tag),
            "a7f91ced0533c12cd59706f2dc38c2a8c39c007ae89ab6492698778c8684c483"
        );
    }

    #[test]
    fn mac_key_debug_redacted() {
        let key = MacKey::generate();
        let debug = format!("{key:?}");
        assert_eq!(debug, "MacKey { .. }");
    }

    #[test]
    fn mac_key_try_from_slice_valid() {
        let bytes = [0xAA; MAC_KEY_SIZE];
        let key = MacKey::try_from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn mac_key_try_from_slice_too_short() {
        let err = MacKey::try_from_slice(&[0; 16]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            }
        ));
    }

    #[test]
    fn mac_key_try_from_slice_empty() {
        let err = MacKey::try_from_slice(&[]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 0
            }
        ));
    }

    #[test]
    fn mac_verify_wrong_tag() {
        let key = MacKey::generate();
        let mac = Blake3Mac::new(&key);
        let wrong_tag = [0xFF; MAC_SIZE];
        let result = mac.verify(b"message", &wrong_tag);
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn mac_verify_full_wrong_tag() {
        let key = MacKey::generate();
        let mac = Blake3Mac::new(&key);
        let wrong_tag = [0xFF; BLAKE3_MAC_SIZE];
        let result = mac.verify_full(b"message", &wrong_tag);
        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn mac_verify_full_roundtrip() {
        let key = MacKey::generate();
        let mac = Blake3Mac::new(&key);
        let tag = mac.compute_full(b"message");
        assert!(mac.verify_full(b"message", &tag).is_ok());
    }

    #[test]
    fn incremental_mac_matches_full() {
        let key = MacKey::generate();
        let message = b"hello world";

        let full_tag = blake3_mac_full(&key, message);

        let mut inc = IncrementalMac::new(&key);
        inc.update(b"hello");
        inc.update(b" ");
        inc.update(b"world");
        let inc_tag = inc.finalize_full();

        assert_eq!(full_tag, inc_tag);
    }

    #[test]
    fn mac_empty_message() {
        let key = MacKey::generate();
        let tag = blake3_mac(&key, b"");
        assert!(blake3_mac_verify(&key, b"", &tag).is_ok());
    }
}
