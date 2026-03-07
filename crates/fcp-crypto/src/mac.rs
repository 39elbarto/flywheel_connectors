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

    // ---- MacKey clone ----

    #[test]
    fn mac_key_clone() {
        let key = MacKey::from_bytes([0xBB; MAC_KEY_SIZE]);
        let cloned = key.clone();
        assert_eq!(key.as_bytes(), cloned.as_bytes());
        // Use original after clone
        let tag = blake3_mac(&key, b"test");
        assert!(blake3_mac_verify(&cloned, b"test", &tag).is_ok());
    }

    // ---- Large message MAC ----

    #[test]
    fn mac_large_message() {
        let key = MacKey::generate();
        let large = vec![0xCD; 100_000];
        let tag = blake3_mac(&key, &large);
        assert!(blake3_mac_verify(&key, &large, &tag).is_ok());
    }

    #[test]
    fn mac_full_large_message() {
        let key = MacKey::generate();
        let large = vec![0xEF; 50_000];
        let mac = Blake3Mac::new(&key);
        let tag = mac.compute_full(&large);
        assert!(mac.verify_full(&large, &tag).is_ok());
    }

    // ---- Incremental MAC edge cases ----

    #[test]
    fn incremental_mac_empty_updates() {
        let key = MacKey::generate();
        let message = b"test";

        let one_shot = blake3_mac(&key, message);

        let mut inc = IncrementalMac::new(&key);
        inc.update(b"");
        inc.update(message);
        inc.update(b"");
        let incremental = inc.finalize();

        assert_eq!(one_shot, incremental);
    }

    #[test]
    fn incremental_mac_single_byte_updates() {
        let key = MacKey::from_bytes([0x11; MAC_KEY_SIZE]);
        let message = b"abcdef";

        let one_shot = blake3_mac(&key, message);

        let mut inc = IncrementalMac::new(&key);
        for &byte in message {
            inc.update(std::slice::from_ref(&byte));
        }
        let incremental = inc.finalize();

        assert_eq!(one_shot, incremental);
    }

    #[test]
    fn incremental_mac_full_single_byte_updates() {
        let key = MacKey::from_bytes([0x22; MAC_KEY_SIZE]);
        let message = b"xyz";

        let one_shot = blake3_mac_full(&key, message);

        let mut inc = IncrementalMac::new(&key);
        for &byte in message {
            inc.update(std::slice::from_ref(&byte));
        }
        let incremental = inc.finalize_full();

        assert_eq!(one_shot, incremental);
    }

    // ---- MAC key from_bytes constant ----

    #[test]
    fn mac_key_from_bytes_const() {
        let key = MacKey::from_bytes([0xFF; MAC_KEY_SIZE]);
        assert_eq!(key.as_bytes(), &[0xFF; MAC_KEY_SIZE]);
    }

    // ---- Different keys produce different MACs ----

    #[test]
    fn mac_different_keys_different_tags() {
        let key1 = MacKey::from_bytes([1u8; MAC_KEY_SIZE]);
        let key2 = MacKey::from_bytes([2u8; MAC_KEY_SIZE]);
        let message = b"same message";

        let tag1 = blake3_mac(&key1, message);
        let tag2 = blake3_mac(&key2, message);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn mac_full_different_keys_different_tags() {
        let key1 = MacKey::from_bytes([3u8; MAC_KEY_SIZE]);
        let key2 = MacKey::from_bytes([4u8; MAC_KEY_SIZE]);
        let message = b"same message";

        let tag1 = blake3_mac_full(&key1, message);
        let tag2 = blake3_mac_full(&key2, message);
        assert_ne!(tag1, tag2);
    }

    // ---- Constants ----

    #[test]
    fn mac_constants() {
        assert_eq!(MAC_SIZE, 16);
        assert_eq!(BLAKE3_MAC_SIZE, 32);
        assert_eq!(MAC_KEY_SIZE, 32);
    }

    // ---- Mac key try_from_slice too long ----

    #[test]
    fn mac_key_try_from_slice_too_long() {
        let err = MacKey::try_from_slice(&[0; 64]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 64
            }
        ));
    }

    // ---- Truncated vs full: truncated is prefix of full ----

    #[test]
    fn mac_truncated_is_prefix_of_full() {
        let key = MacKey::generate();
        let message = b"prefix test";

        let truncated = blake3_mac(&key, message);
        let full = blake3_mac_full(&key, message);

        assert_eq!(&full[..MAC_SIZE], &truncated);
    }
}
