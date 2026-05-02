//! br-wsbgg — Conformance coverage for capability-token nbf/exp boundary
//! semantics at verification time.
//!
//! Existing `auth_claims_conformance.rs` pins the wire-format CBOR but
//! uses far-future `exp` (timestamp 2_000_000_000+) and far-past `nbf`,
//! so the at-boundary timing semantics are never exercised. This file
//! locks in the verifier's behavior at the exact bounds where
//! `validate_timing_with_clock_skew` toggles between accept and reject.
//!
//! Reference behavior in `crates/fcp-core/src/capability.rs:1762`:
//! ```text
//!   exp triggers TokenExpired when:    now >= exp + CAPABILITY_TOKEN_CLOCK_SKEW_SECS
//!   nbf triggers TokenNotYetValid when: now <  nbf - CAPABILITY_TOKEN_CLOCK_SKEW_SECS
//! ```
//!
//! `CAPABILITY_TOKEN_CLOCK_SKEW_SECS = 300` (RFC-7519 §4.1.4 strict
//! comparison is intentionally relaxed by 5 minutes on both sides to
//! tolerate operator clock drift). These tests pin both the in-window
//! ACCEPT semantics and the out-of-window REJECT semantics.

use chrono::{Duration, Utc};
use fcp_prelude::{
    CAPABILITY_TOKEN_CLOCK_SKEW_SECS, CapabilityId, CapabilityToken, CapabilityVerifier, FcpError,
    OperationId, ZoneId,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;

const TEST_CAPABILITY: &str = "cap.test";
const TEST_OPERATION: &str = "op.test";
const TEST_PRINCIPAL: &str = "user:test";
const TEST_ISSUER: &str = "node:primary";

/// Construct a CBOR-encoded constraints blob with a wildcard
/// `resource_allow`, matching the pattern used by
/// `crates/fcp-core/src/capability.rs::tests::test_constraints_cbor`.
fn wildcard_constraints_cbor() -> Vec<u8> {
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&constraints, &mut buf).expect("encode constraints");
    buf
}

/// Build a signed capability token with the given (`not_before`, `expiration`)
/// validity window. All other fields use fixed test values.
fn build_token(
    signing_key: &Ed25519SigningKey,
    not_before: chrono::DateTime<Utc>,
    expiration: chrono::DateTime<Utc>,
) -> CapabilityToken {
    let cose = CapabilityTokenBuilder::new()
        .capability_id(TEST_CAPABILITY)
        .zone_id(ZoneId::work().as_str())
        .principal(TEST_PRINCIPAL)
        .operations(&[TEST_OPERATION])
        .issuer(TEST_ISSUER)
        .validity(not_before, expiration)
        .constraints_cbor(&wildcard_constraints_cbor())
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

/// Build a verifier without instance binding (the gateway-vantage path
/// that runs nbf/exp checks via `validate_timing_with_clock_skew`).
fn build_verifier(signing_key: &Ed25519SigningKey) -> CapabilityVerifier {
    let pub_bytes = signing_key.verifying_key().to_bytes();
    CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
}

fn cap() -> CapabilityId {
    CapabilityId::new(TEST_CAPABILITY).expect("capability id")
}

fn op() -> OperationId {
    OperationId::new(TEST_OPERATION).expect("operation id")
}

// ─────────────────────────────────────────────────────────────────────────────
// nbf boundary
// ─────────────────────────────────────────────────────────────────────────────

/// CONTRACT: a token whose `not_before` equals the current instant
/// MUST verify. Issuance moment is part of the valid window.
#[test]
fn nbf_at_now_verifies() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let token = build_token(&signing_key, now, now + Duration::hours(1));
    build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("nbf == now must verify");
}

/// CONTRACT: a token whose `not_before` is inside the
/// CAPABILITY_TOKEN_CLOCK_SKEW_SECS grace window in the future MUST
/// verify. The verifier intentionally tolerates operator clock drift up
/// to the skew constant.
#[test]
fn nbf_in_future_within_skew_verifies() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let nbf = now + Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS / 2);
    let exp = now + Duration::hours(1);
    let token = build_token(&signing_key, nbf, exp);
    build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("nbf within skew window must verify");
}

/// CONTRACT: a token whose `not_before` is past the skew window in the
/// future MUST be rejected with `TokenNotYetValid`.
///
/// Validation: `now < nbf - skew` triggers when `nbf > now + skew`. We
/// pick `nbf = now + skew + 60s` to give the test a 60-second buffer
/// against scheduling jitter between issuance and verification.
#[test]
fn nbf_beyond_skew_rejected() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let nbf = now + Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 60);
    let exp = nbf + Duration::hours(1);
    let token = build_token(&signing_key, nbf, exp);
    let err = build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect_err("nbf beyond skew must reject");
    assert!(
        matches!(err, FcpError::TokenNotYetValid),
        "expected TokenNotYetValid, got {err:?}",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// exp boundary
// ─────────────────────────────────────────────────────────────────────────────

/// CONTRACT: a token whose `expiration` equals the current instant
/// MUST verify (still within the skew grace window).
///
/// This pins the FCP-specific deviation from RFC 7519 §4.1.4, which
/// requires "MUST NOT be processed on or after exp". FCP's verifier
/// allows up to CAPABILITY_TOKEN_CLOCK_SKEW_SECS of grace past exp.
#[test]
fn exp_at_now_verifies_within_skew() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let token = build_token(&signing_key, now - Duration::hours(1), now);
    build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("exp == now must verify within skew window");
}

/// CONTRACT: a token whose `expiration` is in the past but inside the
/// skew window MUST still verify.
#[test]
fn exp_recently_past_within_skew_verifies() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let exp = now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS / 2);
    let nbf = exp - Duration::hours(1);
    let token = build_token(&signing_key, nbf, exp);
    build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("exp within skew window must verify");
}

/// CONTRACT: a token whose `expiration` is past the skew window MUST be
/// rejected with `TokenExpired`.
///
/// Validation: `now >= exp + skew` triggers when `exp <= now - skew`.
/// We pick `exp = now - (skew + 60s)` to give the test a 60-second
/// buffer against clock jitter.
#[test]
fn exp_beyond_skew_rejected() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let exp = now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 60);
    let nbf = exp - Duration::hours(1);
    let token = build_token(&signing_key, nbf, exp);
    let err = build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect_err("exp beyond skew must reject");
    assert!(
        matches!(err, FcpError::TokenExpired),
        "expected TokenExpired, got {err:?}",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pathological windows: zero-duration and inverted
// ─────────────────────────────────────────────────────────────────────────────

/// CONTRACT: a token with `nbf == exp == now` (zero-duration window)
/// MUST verify because both bounds fall inside the skew grace.
///
/// This locks in the skew-aware behavior: the verifier does NOT
/// short-circuit on a degenerate validity window; instead it applies
/// the skew tolerance to each bound independently. A future hardening
/// pass that wants to reject zero-duration tokens MUST update this
/// test deliberately.
#[test]
fn zero_duration_window_inside_skew_verifies() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let token = build_token(&signing_key, now, now);
    build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("zero-duration window inside skew must verify");
}

/// CONTRACT: a token whose `nbf` is in the future AND `exp` is in the
/// past (logically inverted) MUST be rejected with `TokenExpired` once
/// `exp` falls outside the skew window. The exp check runs first, so
/// `TokenExpired` wins over `TokenNotYetValid`.
#[test]
fn inverted_window_with_exp_beyond_skew_is_token_expired() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let exp = now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 60);
    let nbf = now + Duration::hours(1);
    let token = build_token(&signing_key, nbf, exp);
    let err = build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect_err("inverted window with exp beyond skew must reject");
    assert!(
        matches!(err, FcpError::TokenExpired),
        "expected TokenExpired (exp check runs first), got {err:?}",
    );
}

/// CONTRACT: a token whose `nbf` is in the future beyond the skew
/// window AND `exp` is in the past beyond the skew window MUST be
/// rejected. The exp check is evaluated first in
/// `validate_timing_with_clock_skew`, so the surfaced error is
/// `TokenExpired` (not `TokenNotYetValid`).
#[test]
fn inverted_window_both_beyond_skew_surfaces_token_expired() {
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let exp = now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 120);
    let nbf = now + Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 120);
    let token = build_token(&signing_key, nbf, exp);
    let err = build_verifier(&signing_key)
        .verify_unbound(token, &cap(), &op(), &[])
        .expect_err("inverted window beyond skew must reject");
    assert!(
        matches!(err, FcpError::TokenExpired),
        "expected TokenExpired (exp check runs first), got {err:?}",
    );
}
