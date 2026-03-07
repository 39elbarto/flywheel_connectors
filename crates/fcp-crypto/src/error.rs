//! Error types for FCP2 cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// Invalid signature length.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length provided.
        actual: usize,
    },

    /// Invalid signature.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid key ID format.
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),

    /// AEAD encryption failed.
    #[error("AEAD encryption failed")]
    AeadEncryptFailed,

    /// AEAD decryption failed (authentication failed or invalid ciphertext).
    #[error("AEAD decryption failed: authentication or decryption error")]
    AeadDecryptFailed,

    /// HPKE operation failed.
    #[error("HPKE operation failed: {0}")]
    HpkeFailed(String),

    /// COSE operation failed.
    #[error("COSE operation failed: {0}")]
    CoseFailed(String),

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length provided.
        actual: usize,
    },

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Token validation error.
    #[error("token validation error: {0}")]
    TokenValidationError(String),

    /// Token expired.
    #[error("token expired")]
    TokenExpired,

    /// Token not yet valid.
    #[error("token not yet valid")]
    TokenNotYetValid,

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Result type alias for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_key_length() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(err.to_string(), "invalid key length: expected 32, got 16");
    }

    #[test]
    fn error_display_invalid_signature_length() {
        let err = CryptoError::InvalidSignatureLength {
            expected: 64,
            actual: 32,
        };
        assert_eq!(err.to_string(), "invalid signature length: expected 64, got 32");
    }

    #[test]
    fn error_display_signature_verification_failed() {
        let err = CryptoError::SignatureVerificationFailed;
        assert_eq!(err.to_string(), "signature verification failed");
    }

    #[test]
    fn error_display_invalid_key_id() {
        let err = CryptoError::InvalidKeyId("bad hex".to_string());
        assert_eq!(err.to_string(), "invalid key ID: bad hex");
    }

    #[test]
    fn error_display_aead_encrypt_failed() {
        let err = CryptoError::AeadEncryptFailed;
        assert_eq!(err.to_string(), "AEAD encryption failed");
    }

    #[test]
    fn error_display_aead_decrypt_failed() {
        let err = CryptoError::AeadDecryptFailed;
        assert_eq!(
            err.to_string(),
            "AEAD decryption failed: authentication or decryption error"
        );
    }

    #[test]
    fn error_display_hpke_failed() {
        let err = CryptoError::HpkeFailed("encap error".to_string());
        assert_eq!(err.to_string(), "HPKE operation failed: encap error");
    }

    #[test]
    fn error_display_cose_failed() {
        let err = CryptoError::CoseFailed("invalid header".to_string());
        assert_eq!(err.to_string(), "COSE operation failed: invalid header");
    }

    #[test]
    fn error_display_invalid_nonce_length() {
        let err = CryptoError::InvalidNonceLength {
            expected: 12,
            actual: 8,
        };
        assert_eq!(err.to_string(), "invalid nonce length: expected 12, got 8");
    }

    #[test]
    fn error_display_key_derivation_failed() {
        let err = CryptoError::KeyDerivationFailed("bad ikm".to_string());
        assert_eq!(err.to_string(), "key derivation failed: bad ikm");
    }

    #[test]
    fn error_display_invalid_public_key() {
        let err = CryptoError::InvalidPublicKey;
        assert_eq!(err.to_string(), "invalid public key");
    }

    #[test]
    fn error_display_invalid_secret_key() {
        let err = CryptoError::InvalidSecretKey;
        assert_eq!(err.to_string(), "invalid secret key");
    }

    #[test]
    fn error_display_serialization_error() {
        let err = CryptoError::SerializationError("bad cbor".to_string());
        assert_eq!(err.to_string(), "serialization error: bad cbor");
    }

    #[test]
    fn error_display_token_validation_error() {
        let err = CryptoError::TokenValidationError("missing field".to_string());
        assert_eq!(err.to_string(), "token validation error: missing field");
    }

    #[test]
    fn error_display_token_expired() {
        let err = CryptoError::TokenExpired;
        assert_eq!(err.to_string(), "token expired");
    }

    #[test]
    fn error_display_token_not_yet_valid() {
        let err = CryptoError::TokenNotYetValid;
        assert_eq!(err.to_string(), "token not yet valid");
    }

    #[test]
    fn error_display_missing_field() {
        let err = CryptoError::MissingField("issuer".to_string());
        assert_eq!(err.to_string(), "missing required field: issuer");
    }
}
