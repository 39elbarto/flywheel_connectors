//! Pin the full 23-variant Display surface of [`CryptoError`].
//!
//! The inline `mod tests` block at `crates/fcp-crypto/src/error.rs:138`
//! has 18-variant exhaustion lists that pre-date the COSE-era additions:
//! `AlgorithmMismatch`, `UnsupportedCriticalHeader`, `KeyIdMismatch`,
//! `HeaderPolicyViolation`, and `InvalidCborTag`. The first three of
//! those have no Display assertion at all; the remaining two appear in
//! one Display test each but are absent from the variant-matrix loops.
//!
//! This integration test pins the *complete* current variant set with:
//!   * One Display assertion per variant (exact byte-for-byte string)
//!   * An exhaustive-match sentinel that refuses to compile if a new
//!     variant is added without updating the matrix above
//!
//! Bead: flywheel_connectors-8oak4. Pin lineage: 5fztw (fcp-cbor
//! `SerializationError` + `SchemaIdError`).

use fcp_crypto::CryptoError;

/// Build one representative instance of every current `CryptoError`
/// variant, paired with the canonical Display string the wire contract
/// guarantees.
fn variant_display_matrix() -> Vec<(CryptoError, &'static str)> {
    vec![
        (
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16,
            },
            "invalid key length: expected 32, got 16",
        ),
        (
            CryptoError::InvalidSignatureLength {
                expected: 64,
                actual: 32,
            },
            "invalid signature length: expected 64, got 32",
        ),
        (
            CryptoError::SignatureVerificationFailed,
            "signature verification failed",
        ),
        (
            CryptoError::InvalidKeyId(String::from("bad hex")),
            "invalid key ID: bad hex",
        ),
        (CryptoError::AeadEncryptFailed, "AEAD encryption failed"),
        (
            CryptoError::AeadDecryptFailed,
            "AEAD decryption failed: authentication or decryption error",
        ),
        (
            CryptoError::HpkeFailed(String::from("encap error")),
            "HPKE operation failed: encap error",
        ),
        (
            CryptoError::CoseFailed(String::from("invalid header")),
            "COSE operation failed: invalid header",
        ),
        (
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 8,
            },
            "invalid nonce length: expected 12, got 8",
        ),
        (
            CryptoError::KeyDerivationFailed(String::from("bad ikm")),
            "key derivation failed: bad ikm",
        ),
        (CryptoError::InvalidPublicKey, "invalid public key"),
        (CryptoError::InvalidSecretKey, "invalid secret key"),
        (
            CryptoError::FrostFailed(String::from("invalid identifier")),
            "FROST operation failed: invalid identifier",
        ),
        (
            CryptoError::SerializationError(String::from("bad cbor")),
            "serialization error: bad cbor",
        ),
        (
            CryptoError::TokenValidationError(String::from("missing field")),
            "token validation error: missing field",
        ),
        (CryptoError::TokenExpired, "token expired"),
        (CryptoError::TokenNotYetValid, "token not yet valid"),
        (
            CryptoError::MissingField(String::from("issuer")),
            "missing required field: issuer",
        ),
        (
            CryptoError::AlgorithmMismatch {
                expected: "EdDSA",
                got: String::from("ES256"),
            },
            "algorithm mismatch: expected EdDSA, got ES256",
        ),
        (
            CryptoError::UnsupportedCriticalHeader(String::from("urn:example:crit")),
            "unsupported critical header: urn:example:crit",
        ),
        (
            CryptoError::KeyIdMismatch {
                expected: String::from("0011223344556677"),
                got: String::from("8899aabbccddeeff"),
            },
            "key ID mismatch: expected 0011223344556677, got 8899aabbccddeeff",
        ),
        (
            CryptoError::HeaderPolicyViolation(String::from("kid must be protected")),
            "header policy violation: kid must be protected",
        ),
        (
            CryptoError::InvalidCborTag { tag: 1004 },
            "invalid CBOR tag 1004 in CWT claims (tags are not permitted)",
        ),
    ]
}

#[test]
fn crypto_error_full_variant_matrix_pins_display_per_variant() {
    let matrix = variant_display_matrix();
    assert_eq!(
        matrix.len(),
        23,
        "CryptoError variant matrix length drift: expected 23, got {}",
        matrix.len()
    );
    for (variant, expected) in &matrix {
        assert_eq!(
            variant.to_string(),
            *expected,
            "Display drifted for variant {variant:?}"
        );
    }
}

#[test]
fn crypto_error_exhaustive_match_sentinel() {
    // If a new CryptoError variant is added the compiler refuses to
    // build this match, forcing the author to extend the matrix above.
    let sample = CryptoError::AeadEncryptFailed;
    match sample {
        CryptoError::InvalidKeyLength { .. }
        | CryptoError::InvalidSignatureLength { .. }
        | CryptoError::SignatureVerificationFailed
        | CryptoError::InvalidKeyId(_)
        | CryptoError::AeadEncryptFailed
        | CryptoError::AeadDecryptFailed
        | CryptoError::HpkeFailed(_)
        | CryptoError::CoseFailed(_)
        | CryptoError::InvalidNonceLength { .. }
        | CryptoError::KeyDerivationFailed(_)
        | CryptoError::InvalidPublicKey
        | CryptoError::InvalidSecretKey
        | CryptoError::FrostFailed(_)
        | CryptoError::SerializationError(_)
        | CryptoError::TokenValidationError(_)
        | CryptoError::TokenExpired
        | CryptoError::TokenNotYetValid
        | CryptoError::MissingField(_)
        | CryptoError::AlgorithmMismatch { .. }
        | CryptoError::UnsupportedCriticalHeader(_)
        | CryptoError::KeyIdMismatch { .. }
        | CryptoError::HeaderPolicyViolation(_)
        | CryptoError::InvalidCborTag { .. } => (),
    }
}

#[test]
fn crypto_error_invalid_cbor_tag_renders_decimal_not_hex() {
    // Pins decimal rendering of the CBOR tag number — the spec
    // (RFC 8949) talks about tag numbers in decimal, and downstream
    // log-search depends on this.
    let err = CryptoError::InvalidCborTag { tag: 0xFF };
    assert_eq!(
        err.to_string(),
        "invalid CBOR tag 255 in CWT claims (tags are not permitted)"
    );
}

#[test]
fn crypto_error_algorithm_mismatch_static_str_expected_field() {
    // Pins the &'static str type of the `expected` field — downstream
    // verifiers rely on string-literal equality, not allocated strings.
    let err = CryptoError::AlgorithmMismatch {
        expected: "EdDSA",
        got: String::from("ES256"),
    };
    assert_eq!(err.to_string(), "algorithm mismatch: expected EdDSA, got ES256");
}
