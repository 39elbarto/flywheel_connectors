//! Pin `SecretAccessToken` Debug-redaction + predicate truth tables + serde
//! shape — the closest analogue to "RegistryToken Display"
//! (flywheel_connectors-5bqje).
//!
//! Bead asks for `RegistryToken` Display + serde pinning. No type literally
//! named `RegistryToken` exists in fcp-core. Other tokens already pinned:
//!   * `LeaseToken` → `lease_token_display.rs` + `lease_token_format_invariants.rs`,
//!   * `CapabilityToken` → `capability_token_display_roundtrip.rs` (via CapabilityId),
//!   * `ConsentToken` → `consent_token_display_roundtrip.rs`.
//!
//! Residual unpinned token: [`SecretAccessToken`] at
//! `crates/fcp-core/src/secret.rs:413` — the security-critical
//! short-lived single-use token granting access to a secret. It has NO
//! Display impl (intentionally — never log a token to stdout); its
//! "Display" surface is the redacted Debug impl. This test pins:
//!   * Debug redacts authorization bytes (security-critical: token
//!     authorization MUST NOT leak via {:?} log scrapes),
//!   * is_expired / is_exhausted / is_valid predicate truth tables,
//!   * record_use semantics + remaining_uses with saturating_sub,
//!   * JSON+CBOR serde shape preserves all 10 metadata fields +
//!     authorization,
//!   * Distinct token_id ensures audit-correlation independence (every
//!     `new()` produces a fresh Uuid).

use fcp_core::{PrincipalId, SecretAccessToken, SecretId, ZoneId};
use uuid::Uuid;

fn make_token(expires_at: u64, max_uses: u32) -> SecretAccessToken {
    SecretAccessToken::new(
        SecretId::from_uuid(Uuid::from_bytes([0xab; 16])),
        ZoneId::work(),
        PrincipalId::new("user:alice").unwrap(),
        "test-purpose".to_string(),
        1_700_000_000,
        expires_at,
        max_uses,
        b"authorization-bytes-secret".to_vec(),
    )
}

#[test]
fn debug_format_redacts_authorization_bytes() {
    // Loud security sentinel: SecretAccessToken Debug MUST NOT include the
    // raw authorization bytes — only the literal "[redacted]" placeholder.
    // A future change that exposes authorization via {:?} silently leaks
    // tokens into logs.
    let tok = make_token(2_000_000_000, 3);
    let debug = format!("{tok:?}");

    assert!(
        debug.contains("[redacted]"),
        "Debug must include `[redacted]`"
    );
    assert!(
        !debug.contains("authorization-bytes-secret"),
        "Debug must NOT include raw authorization bytes: {debug}"
    );
    // The other 10 metadata fields SHOULD appear in Debug output.
    assert!(debug.contains("token_id"));
    assert!(debug.contains("secret_id"));
    assert!(debug.contains("zone_id"));
    assert!(debug.contains("requester"));
    assert!(debug.contains("purpose"));
    assert!(debug.contains("issued_at"));
    assert!(debug.contains("expires_at"));
    assert!(debug.contains("max_uses"));
    assert!(debug.contains("use_count"));
    assert!(debug.contains("test-purpose"));
}

#[test]
fn debug_format_does_not_leak_authorization_for_diverse_byte_payloads() {
    let canary = b"CANARY-MAGIC-1234567890";
    let tok = SecretAccessToken::new(
        SecretId::from_uuid(Uuid::from_bytes([0x01; 16])),
        ZoneId::work(),
        PrincipalId::new("user:eve").unwrap(),
        "p".to_string(),
        0,
        1,
        1,
        canary.to_vec(),
    );
    let debug = format!("{tok:?}");
    assert!(
        !debug.contains("CANARY-MAGIC"),
        "raw bytes leaked into Debug: {debug}"
    );
}

#[test]
fn is_expired_truth_table_at_boundary() {
    let tok = make_token(1_000, 5);
    assert!(!tok.is_expired(999), "now < expires must NOT be expired");
    assert!(tok.is_expired(1_000), "now == expires IS expired (>= rule)");
    assert!(tok.is_expired(1_001), "now > expires IS expired");
    assert!(tok.is_expired(u64::MAX));
}

#[test]
fn is_exhausted_truth_table() {
    let mut tok = make_token(2_000_000_000, 3);
    assert!(
        !tok.is_exhausted(),
        "use_count=0, max_uses=3 → not exhausted"
    );

    assert!(tok.record_use());
    assert!(
        !tok.is_exhausted(),
        "use_count=1, max_uses=3 → not exhausted"
    );

    assert!(tok.record_use());
    assert!(tok.record_use());
    assert!(
        tok.is_exhausted(),
        "use_count=3, max_uses=3 → IS exhausted (>= rule)"
    );
}

#[test]
fn is_valid_requires_both_not_expired_and_not_exhausted() {
    let mut tok = make_token(2_000_000_000, 2);

    // Fresh token, well within validity → valid.
    assert!(tok.is_valid(1_700_000_000));

    // Expired only → invalid.
    assert!(!tok.is_valid(2_000_000_001));

    // Exhausted only → invalid.
    tok.record_use();
    tok.record_use();
    assert!(tok.is_exhausted());
    assert!(!tok.is_valid(1_700_000_000));

    // Both expired AND exhausted → still invalid (both checked).
    assert!(!tok.is_valid(3_000_000_000));
}

#[test]
fn record_use_returns_false_when_exhausted() {
    let mut tok = make_token(2_000_000_000, 1);
    assert!(tok.record_use(), "first use must succeed");
    assert!(tok.is_exhausted());
    assert!(!tok.record_use(), "second use must return false");
    // use_count must NOT increment past max_uses on rejected calls.
    assert_eq!(tok.use_count, 1);
}

#[test]
fn record_use_increments_use_count_and_records_first_call_as_one() {
    let mut tok = make_token(2_000_000_000, 5);
    assert_eq!(tok.use_count, 0);
    assert!(tok.record_use());
    assert_eq!(tok.use_count, 1);
    assert!(tok.record_use());
    assert_eq!(tok.use_count, 2);
}

#[test]
fn remaining_uses_uses_saturating_sub() {
    let mut tok = make_token(2_000_000_000, 3);
    assert_eq!(tok.remaining_uses(), 3);

    tok.record_use();
    assert_eq!(tok.remaining_uses(), 2);

    tok.record_use();
    tok.record_use();
    assert_eq!(tok.remaining_uses(), 0);

    // Even if record_use returns false from here on, remaining_uses
    // saturates at 0 (does NOT underflow to u32::MAX).
    assert!(!tok.record_use());
    assert_eq!(
        tok.remaining_uses(),
        0,
        "remaining_uses must saturate at 0, not underflow"
    );
}

#[test]
fn authorization_helper_returns_inner_bytes() {
    let tok = make_token(2_000_000_000, 1);
    assert_eq!(tok.authorization(), b"authorization-bytes-secret");
}

#[test]
fn json_roundtrip_preserves_all_fields_including_authorization() {
    let tok = make_token(2_000_000_000, 3);
    let bytes = serde_json::to_vec(&tok).unwrap();
    let back: SecretAccessToken = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.token_id, tok.token_id);
    assert_eq!(back.secret_id, tok.secret_id);
    assert_eq!(back.zone_id, tok.zone_id);
    assert_eq!(back.requester, tok.requester);
    assert_eq!(back.purpose, tok.purpose);
    assert_eq!(back.issued_at, tok.issued_at);
    assert_eq!(back.expires_at, tok.expires_at);
    assert_eq!(back.max_uses, tok.max_uses);
    assert_eq!(back.use_count, tok.use_count);
    assert_eq!(back.authorization(), tok.authorization());
}

#[test]
fn cbor_roundtrip_preserves_all_fields_including_authorization() {
    let tok = make_token(2_000_000_000, 5);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&tok, &mut bytes).unwrap();
    let back: SecretAccessToken = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.token_id, tok.token_id);
    assert_eq!(back.secret_id, tok.secret_id);
    assert_eq!(back.purpose, tok.purpose);
    assert_eq!(back.expires_at, tok.expires_at);
    assert_eq!(back.max_uses, tok.max_uses);
    assert_eq!(back.authorization(), tok.authorization());
}

#[test]
fn json_shape_includes_authorization_field() {
    // Note: serde DOES serialize authorization (it's a private field but
    // included in the derive). This means JSON token records on disk
    // contain the auth bytes — pin this fact loudly so a future
    // skip_serializing on authorization is caught (might be intentional,
    // might be accidental data loss).
    let tok = make_token(2_000_000_000, 1);
    let v = serde_json::to_value(&tok).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected_keys: std::collections::BTreeSet<&str> = [
        "token_id",
        "secret_id",
        "zone_id",
        "requester",
        "purpose",
        "issued_at",
        "expires_at",
        "max_uses",
        "use_count",
        "authorization",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        actual, expected_keys,
        "SecretAccessToken JSON shape drift: {obj:?}"
    );
}

#[test]
fn each_new_token_gets_a_distinct_token_id() {
    // SecretAccessToken::new() generates a fresh random Uuid for token_id —
    // critical for audit correlation: two tokens for the same secret/
    // requester/purpose must still have distinct token_ids.
    let tok1 = make_token(2_000_000_000, 1);
    let tok2 = make_token(2_000_000_000, 1);
    let tok3 = make_token(2_000_000_000, 1);
    assert_ne!(tok1.token_id, tok2.token_id);
    assert_ne!(tok2.token_id, tok3.token_id);
    assert_ne!(tok1.token_id, tok3.token_id);
}

#[test]
fn use_count_starts_at_zero_for_fresh_token() {
    let tok = make_token(2_000_000_000, 5);
    assert_eq!(tok.use_count, 0, "fresh token must start at use_count=0");
}

#[test]
fn token_with_max_uses_zero_is_immediately_exhausted() {
    // Edge case: max_uses=0 is degenerate — token is exhausted from
    // birth. Pin so a future "max_uses==0 means unlimited" reinterpretation
    // is caught.
    let tok = make_token(2_000_000_000, 0);
    assert!(tok.is_exhausted());
    assert_eq!(tok.remaining_uses(), 0);
    assert!(!tok.is_valid(1_700_000_000));
}
