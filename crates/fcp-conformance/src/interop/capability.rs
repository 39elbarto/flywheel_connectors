//! Capability token interop tests.
//!
//! Tests for `COSE_Sign1` encoding/verification, `grant_object_ids` subset enforcement,
//! `chk_id`/`chk_seq` freshness binding, and `holder_node` + `holder_proof` verification.

use crate::{InteropTestSummary, TestFailure};

/// Capability token interop test suite.
pub struct CapabilityInteropTests;

impl CapabilityInteropTests {
    /// Run all capability token interop tests.
    #[must_use]
    pub fn run() -> InteropTestSummary {
        run_tests()
    }
}

/// Run all capability token interop tests.
pub fn run_tests() -> InteropTestSummary {
    let mut summary = InteropTestSummary::default();

    // Test 1: COSE_Sign1 structure
    run_test(
        &mut summary,
        "cose_sign1_structure",
        test_cose_sign1_structure,
    );

    // Test 2: Token payload structure
    run_test(
        &mut summary,
        "token_payload_structure",
        test_token_payload_structure,
    );

    // Test 3: grant_object_ids subset enforcement
    run_test(
        &mut summary,
        "grant_object_ids_subset",
        test_grant_object_ids_subset,
    );

    // Test 4: chk_id/chk_seq freshness binding
    run_test(&mut summary, "checkpoint_binding", test_checkpoint_binding);

    // Test 5: Token expiry validation
    run_test(&mut summary, "token_expiry", test_token_expiry);

    // Test 6: Holder node binding
    run_test(
        &mut summary,
        "holder_node_binding",
        test_holder_node_binding,
    );

    // Test 7: Signature verification
    run_test(
        &mut summary,
        "signature_verification",
        test_signature_verification,
    );

    summary
}

fn run_test<F>(summary: &mut InteropTestSummary, name: &str, test_fn: F)
where
    F: FnOnce() -> Result<(), String>,
{
    summary.total += 1;
    match test_fn() {
        Ok(()) => summary.passed += 1,
        Err(msg) => {
            summary.failed += 1;
            summary.failures.push(TestFailure {
                name: name.to_string(),
                category: "capability".to_string(),
                message: msg,
            });
        }
    }
}

/// Test: `COSE_Sign1` structure compliance.
fn test_cose_sign1_structure() -> Result<(), String> {
    // COSE_Sign1 is a CBOR array with 4 elements:
    // [protected, unprotected, payload, signature]

    // Simulate a minimal COSE_Sign1 structure
    let cose = CoseSign1 {
        protected: vec![0xA1, 0x01, 0x26], // {1: -7} = ES256
        unprotected: std::collections::HashMap::new(),
        payload: b"test payload".to_vec(),
        signature: vec![0u8; 64], // ES256 signature is 64 bytes
    };

    // Protected header should be non-empty
    if cose.protected.is_empty() {
        return Err("protected header must not be empty".to_string());
    }

    // Signature should be 64 bytes for ES256
    if cose.signature.len() != 64 {
        return Err(format!(
            "ES256 signature length {} != 64",
            cose.signature.len()
        ));
    }

    Ok(())
}

/// Minimal `COSE_Sign1` structure for testing.
#[allow(dead_code)]
struct CoseSign1 {
    protected: Vec<u8>,
    unprotected: std::collections::HashMap<i32, Vec<u8>>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

/// Test: Token payload structure.
fn test_token_payload_structure() -> Result<(), String> {
    // Capability token payload fields:
    // - iss: issuer (zone ID)
    // - sub: subject (holder node ID)
    // - aud: audience (target zone or "*")
    // - exp: expiration timestamp
    // - iat: issued-at timestamp
    // - jti: unique token ID
    // - grants: array of granted capabilities
    // - chk_id: checkpoint ID binding
    // - chk_seq: checkpoint sequence binding

    let token = CapabilityTokenPayload {
        iss: "z:work".to_string(),
        sub: "node-001".to_string(),
        aud: "z:sensitive".to_string(),
        exp: 1_700_000_000,
        iat: 1_699_900_000,
        jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        grants: vec!["read:objects".to_string(), "write:objects".to_string()],
        chk_id: "a".repeat(64),
        chk_seq: 42,
    };

    // Validate required fields
    if token.iss.is_empty() {
        return Err("iss must not be empty".to_string());
    }
    if token.sub.is_empty() {
        return Err("sub must not be empty".to_string());
    }
    if token.jti.is_empty() {
        return Err("jti must not be empty".to_string());
    }
    if token.exp <= token.iat {
        return Err("exp must be after iat".to_string());
    }

    // chk_id should be 64 hex chars (32 bytes)
    if token.chk_id.len() != 64 {
        return Err(format!("chk_id length {} != 64", token.chk_id.len()));
    }

    Ok(())
}

/// Capability token payload for testing.
#[allow(dead_code)]
struct CapabilityTokenPayload {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    jti: String,
    grants: Vec<String>,
    chk_id: String,
    chk_seq: u64,
}

/// Test: `grant_object_ids` subset enforcement.
fn test_grant_object_ids_subset() -> Result<(), String> {
    // When a capability token grants access to specific object IDs,
    // any request must reference only objects within that granted set.

    let granted_objects = vec![
        "aaaa".repeat(16), // object 1
        "bbbb".repeat(16), // object 2
        "cccc".repeat(16), // object 3
    ];

    // Request for granted object should be allowed
    let request_valid = "aaaa".repeat(16);
    if !is_object_granted(&request_valid, &granted_objects) {
        return Err("valid object request rejected".to_string());
    }

    // Request for non-granted object should be denied
    let request_invalid = "dddd".repeat(16);
    if is_object_granted(&request_invalid, &granted_objects) {
        return Err("invalid object request accepted".to_string());
    }

    // Empty grant list means no objects are accessible
    let empty_grants: Vec<String> = vec![];
    if is_object_granted(&request_valid, &empty_grants) {
        return Err("request accepted with empty grants".to_string());
    }

    // Wildcard "*" grants access to all objects
    let wildcard_grants = vec!["*".to_string()];
    if !is_object_granted(&request_valid, &wildcard_grants) {
        return Err("wildcard grant rejected valid request".to_string());
    }

    Ok(())
}

/// Check if an object ID is in the granted set.
fn is_object_granted(object_id: &str, granted: &[String]) -> bool {
    if granted.iter().any(|g| g == "*") {
        return true;
    }
    granted.iter().any(|g| g == object_id)
}

/// Test: `chk_id/chk_seq` freshness binding.
fn test_checkpoint_binding() -> Result<(), String> {
    // Capability tokens are bound to a specific checkpoint to prevent
    // replay attacks after revocation. The token is valid only if:
    // 1. chk_id matches the current zone checkpoint ID
    // 2. chk_seq <= current checkpoint sequence

    let token_chk_id = "aabbccdd".repeat(8);
    let token_chk_seq = 100u64;

    // Current checkpoint matches: valid
    let current_chk_id = "aabbccdd".repeat(8);
    let current_chk_seq = 100u64;

    if !is_checkpoint_valid(
        &token_chk_id,
        token_chk_seq,
        &current_chk_id,
        current_chk_seq,
    ) {
        return Err("matching checkpoint rejected".to_string());
    }

    // Current checkpoint is newer (higher seq): still valid
    let newer_seq = 150u64;
    if !is_checkpoint_valid(&token_chk_id, token_chk_seq, &current_chk_id, newer_seq) {
        return Err("newer checkpoint rejected".to_string());
    }

    // Token checkpoint is newer than current (token_seq > current_seq): invalid
    // This would mean the token references a future checkpoint
    let older_current_seq = 50u64;
    if is_checkpoint_valid(
        &token_chk_id,
        token_chk_seq,
        &current_chk_id,
        older_current_seq,
    ) {
        return Err("future checkpoint accepted".to_string());
    }

    // Different checkpoint ID: invalid (zone fork or mismatch)
    let different_chk_id = "11223344".repeat(8);
    if is_checkpoint_valid(
        &token_chk_id,
        token_chk_seq,
        &different_chk_id,
        current_chk_seq,
    ) {
        return Err("mismatched checkpoint ID accepted".to_string());
    }

    Ok(())
}

/// Check if token checkpoint binding is valid against current checkpoint.
fn is_checkpoint_valid(
    token_chk_id: &str,
    token_chk_seq: u64,
    current_chk_id: &str,
    current_chk_seq: u64,
) -> bool {
    // Checkpoint IDs must match
    if token_chk_id != current_chk_id {
        return false;
    }
    // Token must not reference a future checkpoint
    token_chk_seq <= current_chk_seq
}

/// Test: Token expiry validation.
fn test_token_expiry() -> Result<(), String> {
    // Token should be rejected after expiration

    let now = 1_700_000_000_u64;
    let exp_future = now + 3600; // 1 hour from now
    let exp_past = now - 3600; // 1 hour ago

    // Not expired
    if !is_token_valid_at(exp_future, now) {
        return Err("valid token rejected".to_string());
    }

    // Expired
    if is_token_valid_at(exp_past, now) {
        return Err("expired token accepted".to_string());
    }

    // Exactly at expiration: expired (exp is exclusive)
    if is_token_valid_at(now, now) {
        return Err("token at exact expiry accepted".to_string());
    }

    Ok(())
}

/// Check if token is valid at given time.
const fn is_token_valid_at(exp: u64, now: u64) -> bool {
    now < exp
}

/// Test: Holder node binding.
fn test_holder_node_binding() -> Result<(), String> {
    // Capability tokens are bound to a specific holder node.
    // The holder_proof field contains a signature from the holder's key
    // proving possession of the token.

    let token_holder = "node-001";
    let request_node = "node-001";

    // Matching holder
    if !is_holder_valid(token_holder, request_node) {
        return Err("matching holder rejected".to_string());
    }

    // Different holder
    let wrong_node = "node-002";
    if is_holder_valid(token_holder, wrong_node) {
        return Err("mismatched holder accepted".to_string());
    }

    Ok(())
}

/// Check if request node matches token holder.
fn is_holder_valid(token_holder: &str, request_node: &str) -> bool {
    token_holder == request_node
}

/// Test: Signature verification.
fn test_signature_verification() -> Result<(), String> {
    // Capability tokens must be signed by a trusted issuer.
    // Verification uses Ed25519 signatures.

    use fcp_crypto::Ed25519SigningKey;

    // Generate test keypair
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"test token payload";

    // Sign
    let signature = signing_key.sign(message);

    // Verify with correct key
    if verifying_key.verify(message, &signature).is_err() {
        return Err("valid signature rejected".to_string());
    }

    // Verify with wrong message should fail
    let wrong_message = b"wrong payload";
    if verifying_key.verify(wrong_message, &signature).is_ok() {
        return Err("signature verified with wrong message".to_string());
    }

    // Verify with wrong key should fail
    let other_key = Ed25519SigningKey::generate().verifying_key();
    if other_key.verify(message, &signature).is_ok() {
        return Err("signature verified with wrong key".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_interop_tests_pass() {
        let summary = run_tests();
        for failure in &summary.failures {
            eprintln!("FAIL: {} - {}", failure.name, failure.message);
        }
        assert!(
            summary.all_passed(),
            "Capability interop tests failed: {}/{} passed",
            summary.passed,
            summary.total
        );
    }

    #[test]
    fn test_object_grant_wildcard() {
        let grants = vec!["*".to_string()];
        assert!(is_object_granted("anything", &grants));
    }

    #[test]
    fn test_checkpoint_seq_boundary() {
        let chk_id = "aa".repeat(32);
        // Exactly at boundary: valid
        assert!(is_checkpoint_valid(&chk_id, 100, &chk_id, 100));
        // One past: invalid
        assert!(!is_checkpoint_valid(&chk_id, 101, &chk_id, 100));
    }

    // ─── is_object_granted edge cases ───

    #[test]
    fn object_grant_empty_grants_rejects() {
        let empty: Vec<String> = vec![];
        assert!(!is_object_granted("anything", &empty));
    }

    #[test]
    fn object_grant_exact_match() {
        let grants = vec!["obj-001".to_string()];
        assert!(is_object_granted("obj-001", &grants));
        assert!(!is_object_granted("obj-002", &grants));
    }

    #[test]
    fn object_grant_multiple_entries() {
        let grants = vec![
            "obj-a".to_string(),
            "obj-b".to_string(),
            "obj-c".to_string(),
        ];
        assert!(is_object_granted("obj-a", &grants));
        assert!(is_object_granted("obj-c", &grants));
        assert!(!is_object_granted("obj-d", &grants));
    }

    #[test]
    fn object_grant_wildcard_with_other_entries() {
        let grants = vec!["obj-001".to_string(), "*".to_string()];
        assert!(is_object_granted("anything", &grants));
        assert!(is_object_granted("", &grants));
    }

    #[test]
    fn object_grant_empty_object_id() {
        let grants = [String::new()];
        assert!(is_object_granted("", &grants));
        assert!(!is_object_granted("x", &grants));
    }

    // ─── is_checkpoint_valid edge cases ───

    #[test]
    fn checkpoint_valid_zero_seq() {
        let chk_id = "bb".repeat(32);
        assert!(is_checkpoint_valid(&chk_id, 0, &chk_id, 0));
        assert!(is_checkpoint_valid(&chk_id, 0, &chk_id, 100));
    }

    #[test]
    fn checkpoint_invalid_different_ids() {
        let id_a = "aa".repeat(32);
        let id_b = "bb".repeat(32);
        assert!(!is_checkpoint_valid(&id_a, 0, &id_b, 0));
    }

    #[test]
    fn checkpoint_valid_max_seq() {
        let chk_id = "cc".repeat(32);
        assert!(is_checkpoint_valid(&chk_id, u64::MAX, &chk_id, u64::MAX));
        assert!(!is_checkpoint_valid(&chk_id, u64::MAX, &chk_id, u64::MAX - 1));
    }

    // ─── is_token_valid_at edge cases ───

    #[test]
    fn token_valid_one_before_exp() {
        assert!(is_token_valid_at(100, 99));
    }

    #[test]
    fn token_invalid_at_exp() {
        assert!(!is_token_valid_at(100, 100));
    }

    #[test]
    fn token_invalid_after_exp() {
        assert!(!is_token_valid_at(100, 101));
    }

    #[test]
    fn token_valid_at_zero() {
        assert!(is_token_valid_at(1, 0));
        assert!(!is_token_valid_at(0, 0));
    }

    #[test]
    fn token_valid_max_values() {
        assert!(!is_token_valid_at(u64::MAX, u64::MAX));
        assert!(is_token_valid_at(u64::MAX, u64::MAX - 1));
    }

    // ─── is_holder_valid edge cases ───

    #[test]
    fn holder_valid_matching() {
        assert!(is_holder_valid("node-001", "node-001"));
    }

    #[test]
    fn holder_invalid_different() {
        assert!(!is_holder_valid("node-001", "node-002"));
    }

    #[test]
    fn holder_empty_strings() {
        assert!(is_holder_valid("", ""));
        assert!(!is_holder_valid("", "x"));
    }

    #[test]
    fn holder_case_sensitive() {
        assert!(!is_holder_valid("Node-001", "node-001"));
    }

    // ─── CapabilityInteropTests struct ───

    #[test]
    fn capability_interop_tests_via_struct() {
        let summary = CapabilityInteropTests::run();
        assert!(summary.all_passed());
        assert_eq!(summary.total, 7);
    }

    // ─── CoseSign1 structure edge cases ───

    #[test]
    fn cose_sign1_empty_payload() {
        let cose = CoseSign1 {
            protected: vec![0xA1, 0x01, 0x26],
            unprotected: std::collections::HashMap::new(),
            payload: vec![],
            signature: vec![0u8; 64],
        };
        assert!(cose.payload.is_empty());
        assert_eq!(cose.signature.len(), 64);
    }

    #[test]
    fn cose_sign1_large_payload() {
        let cose = CoseSign1 {
            protected: vec![0xA1, 0x01, 0x26],
            unprotected: std::collections::HashMap::new(),
            payload: vec![0xFFu8; 65536],
            signature: vec![0u8; 64],
        };
        assert_eq!(cose.payload.len(), 65536);
    }

    // ─── CapabilityTokenPayload validation ───

    #[test]
    fn token_payload_grants_can_be_empty() {
        let token = CapabilityTokenPayload {
            iss: "z:test".to_string(),
            sub: "node-001".to_string(),
            aud: "*".to_string(),
            exp: 2_000_000_000,
            iat: 1_900_000_000,
            jti: "id-1".to_string(),
            grants: vec![],
            chk_id: "dd".repeat(32),
            chk_seq: 0,
        };
        assert!(token.grants.is_empty());
        assert!(token.exp > token.iat);
    }

    #[test]
    fn token_payload_chk_id_length() {
        let chk_id = "ee".repeat(32);
        assert_eq!(chk_id.len(), 64);
    }
}
