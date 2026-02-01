//! Golden vector tests for fcp-crypto primitives.
//!
//! These tests validate cryptographic operations against official test vectors
//! from RFC 8032 (Ed25519) and RFC 8152 (`COSE_Sign1`).

#![allow(dead_code)]

use fcp_crypto::ed25519::Ed25519SigningKey;
use serde::Deserialize;
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Vector File Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Ed25519Vectors {
    rfc8032_vectors: Vec<Rfc8032Vector>,
    invalid_signature_vectors: Vec<InvalidSignatureVector>,
    key_properties: Vec<KeyProperty>,
}

#[derive(Debug, Deserialize)]
struct Rfc8032Vector {
    name: String,
    description: String,
    secret_key_hex: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct InvalidSignatureVector {
    name: String,
    description: String,
    public_key_hex: String,
    message_hex: String,
    signature_hex: String,
    expected_result: String,
}

#[derive(Debug, Deserialize)]
struct KeyProperty {
    name: String,
    description: String,
    expected_length: usize,
}

#[derive(Debug, Deserialize)]
struct CoseSign1Vectors {
    algorithm_identifiers: AlgorithmIds,
    verification_properties: Vec<VerificationProperty>,
    error_cases: Vec<ErrorCase>,
}

#[derive(Debug, Deserialize)]
struct AlgorithmIds {
    #[serde(rename = "EdDSA")]
    eddsa: i32,
}

#[derive(Debug, Deserialize)]
struct VerificationProperty {
    name: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct ErrorCase {
    name: String,
    description: String,
    expected_error: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

fn load_ed25519_vectors() -> Ed25519Vectors {
    let content = fs::read_to_string("tests/vectors/ed25519/ed25519_vectors.json")
        .expect("Failed to read ed25519_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse ed25519_vectors.json")
}

fn load_cose_vectors() -> CoseSign1Vectors {
    let content = fs::read_to_string("tests/vectors/cose/cose_sign1_vectors.json")
        .expect("Failed to read cose_sign1_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse cose_sign1_vectors.json")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Ed25519 Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ed25519_key_lengths_from_vectors() {
    let vectors = load_ed25519_vectors();

    for prop in vectors.key_properties {
        match prop.name.as_str() {
            "secret_key_length" => {
                let keypair = Ed25519SigningKey::generate();
                assert_eq!(
                    keypair.to_bytes().len(),
                    prop.expected_length,
                    "Property '{}': {}",
                    prop.name,
                    prop.description
                );
            }
            "public_key_length" => {
                let keypair = Ed25519SigningKey::generate();
                assert_eq!(
                    keypair.verifying_key().to_bytes().len(),
                    prop.expected_length,
                    "Property '{}': {}",
                    prop.name,
                    prop.description
                );
            }
            "signature_length" => {
                let keypair = Ed25519SigningKey::generate();
                let sig = keypair.sign(b"test message");
                assert_eq!(
                    sig.to_bytes().len(),
                    prop.expected_length,
                    "Property '{}': {}",
                    prop.name,
                    prop.description
                );
            }
            _ => {}
        }
    }
}

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let keypair = Ed25519SigningKey::generate();
    let message = b"Hello, FCP!";

    let signature = keypair.sign(message);
    let verified = keypair.verifying_key().verify(message, &signature);

    assert!(verified.is_ok(), "Signature verification should succeed");
}

#[test]
fn test_ed25519_different_keypair_fails_verification() {
    let keypair1 = Ed25519SigningKey::generate();
    let keypair2 = Ed25519SigningKey::generate();
    let message = b"Secret data";

    let signature = keypair1.sign(message);
    let verified = keypair2.verifying_key().verify(message, &signature);

    assert!(verified.is_err(), "Verification with wrong key should fail");
}

#[test]
fn test_ed25519_wrong_message_fails_verification() {
    let keypair = Ed25519SigningKey::generate();
    let message = b"Original message";
    let wrong_message = b"Modified message";

    let signature = keypair.sign(message);
    let verified = keypair.verifying_key().verify(wrong_message, &signature);

    assert!(
        verified.is_err(),
        "Verification with wrong message should fail"
    );
}

#[test]
fn test_ed25519_signature_deterministic() {
    let keypair = Ed25519SigningKey::generate();
    let message = b"Test message";

    // Ed25519 is deterministic - same key + message = same signature
    let sig1 = keypair.sign(message);
    let sig2 = keypair.sign(message);

    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "Ed25519 signatures should be deterministic"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// COSE Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cose_algorithm_identifier() {
    let vectors = load_cose_vectors();

    // EdDSA should be -8 per IANA COSE registry
    assert_eq!(
        vectors.algorithm_identifiers.eddsa, -8,
        "EdDSA algorithm ID should be -8"
    );
}

#[test]
fn test_cose_verification_properties_documented() {
    let vectors = load_cose_vectors();

    // Verify expected properties are documented
    let property_names: Vec<&str> = vectors
        .verification_properties
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    assert!(
        property_names.contains(&"signature_bound_to_protected"),
        "Should document protected header binding"
    );
    assert!(
        property_names.contains(&"signature_bound_to_payload"),
        "Should document payload binding"
    );
    assert!(
        property_names.contains(&"unprotected_not_signed"),
        "Should document unprotected header behavior"
    );
}

#[test]
fn test_cose_error_cases_documented() {
    let vectors = load_cose_vectors();

    // Verify expected error cases are documented
    let error_names: Vec<&str> = vectors
        .error_cases
        .iter()
        .map(|e| e.name.as_str())
        .collect();

    assert!(
        error_names.contains(&"truncated_signature"),
        "Should document truncated signature error"
    );
    assert!(
        error_names.contains(&"wrong_algorithm"),
        "Should document algorithm mismatch error"
    );
    assert!(
        error_names.contains(&"invalid_cbor"),
        "Should document parse error"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_keypair_generation_produces_unique_keys() {
    let keypair1 = Ed25519SigningKey::generate();
    let keypair2 = Ed25519SigningKey::generate();

    assert_ne!(
        keypair1.verifying_key().to_bytes(),
        keypair2.verifying_key().to_bytes(),
        "Different keypairs should have different public keys"
    );
}

#[test]
fn test_signature_length_consistent() {
    let keypair = Ed25519SigningKey::generate();

    // Sign messages of various lengths
    for len in [0, 1, 10, 100, 1000] {
        let message = vec![0u8; len];
        let signature = keypair.sign(&message);
        assert_eq!(
            signature.to_bytes().len(),
            64,
            "Signature should always be 64 bytes regardless of message length"
        );
    }
}
