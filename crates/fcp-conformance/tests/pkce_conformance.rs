//! br-axxrd — Conformance mirror for RFC 7636 PKCE (Proof Key for Code Exchange).
//!
//! Each test is tagged with its RFC clause in the function name
//! (`rfc7636_<section>_<property>`). The oracles are deterministic —
//! either RFC-provided known-answer vectors (Appendix B) or spec-stated
//! accept/reject rules (§4.1 verifier length + charset, §4.2 challenge
//! derivation).
//!
//! Cross-reference: the fuzz targets `fuzz_pkce_verifier` /
//! `fuzz_oauth_token_response` / `fuzz_oauth_callback_url` find crashes;
//! this suite finds spec divergences.

use fcp_oauth::{OAuthError, Pkce, PkceMethod};

// ── RFC 7636 §4.1: verifier length matrix (43..=128) ─────────────────

#[test]
fn rfc7636_4_1_verifier_length_42_is_rejected() {
    let verifier = "a".repeat(42);
    let err = Pkce::from_verifier(&verifier, PkceMethod::S256)
        .expect_err("RFC 7636 §4.1: verifier below 43 chars MUST be rejected");
    assert!(matches!(err, OAuthError::PkceError(_)));
}

#[test]
fn rfc7636_4_1_verifier_length_43_is_accepted() {
    // RFC 7636 §4.1 lower bound — 43 chars is the minimum legal length.
    let verifier = "a".repeat(43);
    Pkce::from_verifier(&verifier, PkceMethod::S256)
        .expect("RFC 7636 §4.1: verifier of 43 chars MUST be accepted");
}

#[test]
fn rfc7636_4_1_verifier_length_128_is_accepted() {
    // RFC 7636 §4.1 upper bound — 128 chars is the maximum legal length.
    let verifier = "a".repeat(128);
    Pkce::from_verifier(&verifier, PkceMethod::S256)
        .expect("RFC 7636 §4.1: verifier of 128 chars MUST be accepted");
}

#[test]
fn rfc7636_4_1_verifier_length_129_is_rejected() {
    let verifier = "a".repeat(129);
    let err = Pkce::from_verifier(&verifier, PkceMethod::S256)
        .expect_err("RFC 7636 §4.1: verifier above 128 chars MUST be rejected");
    assert!(matches!(err, OAuthError::PkceError(_)));
}

// ── RFC 7636 §4.1: verifier charset — unreserved chars only ──────────

#[test]
fn rfc7636_4_1_verifier_accepts_all_unreserved_chars() {
    // RFC 7636 §4.1: verifier = 43*128unreserved
    //   unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".chars() {
        let verifier: String = std::iter::repeat_n(ch, 43).collect();
        Pkce::from_verifier(&verifier, PkceMethod::S256).unwrap_or_else(|err| {
            panic!("RFC 7636 §4.1: unreserved char {ch:?} must be accepted, got {err:?}");
        });
    }
}

#[test]
fn rfc7636_4_1_verifier_rejects_reserved_and_special_chars() {
    // Representative sample of characters outside the unreserved set.
    // Each MUST be rejected per RFC 7636 §4.1.
    for forbidden in [
        '+', '/', '=', '@', '#', '%', ' ', '\\', '|', '{', '}', '[', ']', '!', '$', '&', '*', '(',
        ')', '?', ',', ';', ':', '\'', '"', '<', '>', '\n', '\t',
    ] {
        let verifier: String = std::iter::repeat_n('a', 42)
            .chain(Some(forbidden))
            .collect();
        assert_eq!(verifier.chars().count(), 43);
        let err = Pkce::from_verifier(&verifier, PkceMethod::S256)
            .expect_err("forbidden char must be rejected by from_verifier");
        assert!(
            matches!(err, OAuthError::PkceError(_)),
            "RFC 7636 §4.1: char {forbidden:?} must be rejected with PkceError, got {err:?}"
        );
    }
}

#[test]
fn rfc7636_4_1_verifier_rejects_non_ascii() {
    // Unicode letters fall outside ALPHA / DIGIT / unreserved symbols.
    for ch in ['\u{00e9}', '\u{4e16}', '\u{1f600}'] {
        let verifier: String = std::iter::repeat_n('a', 42).chain(Some(ch)).collect();
        let err = Pkce::from_verifier(&verifier, PkceMethod::S256)
            .expect_err("non-ASCII char must be rejected");
        assert!(
            matches!(err, OAuthError::PkceError(_)),
            "RFC 7636 §4.1: non-ASCII char {ch:?} must be rejected"
        );
    }
}

// ── RFC 7636 §4.2: code_challenge derivation ─────────────────────────

#[test]
fn rfc7636_4_2_plain_method_challenge_equals_verifier() {
    // RFC 7636 §4.2: "plain" => code_challenge = code_verifier
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let pkce = Pkce::from_verifier(verifier, PkceMethod::Plain).unwrap();
    assert_eq!(pkce.verifier(), verifier);
    assert_eq!(pkce.challenge(), verifier);
}

#[test]
fn rfc7636_appendix_b_s256_known_answer_vector() {
    // RFC 7636 Appendix B publishes the canonical test vector:
    //   code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    //   code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    //   method         = "S256"
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
    assert_eq!(
        pkce.challenge(),
        expected_challenge,
        "RFC 7636 Appendix B: S256 challenge derivation diverged"
    );
    assert_eq!(pkce.method(), PkceMethod::S256);
}

#[test]
fn rfc7636_4_2_s256_challenge_is_base64url_no_padding() {
    // RFC 7636 §4.2: "base64url-encoded (see Appendix A) representation
    // of the SHA256 hash of the ASCII representation of the code_verifier."
    // base64url-no-pad MUST NOT emit `=` and MUST NOT include `+` or `/`.
    for _ in 0..8 {
        let pkce = Pkce::new();
        let challenge = pkce.challenge();
        assert_eq!(
            challenge.len(),
            43,
            "SHA-256(32 bytes) → base64url-no-pad = 43 chars"
        );
        assert!(!challenge.contains('='), "base64url-no-pad forbids padding");
        assert!(
            challenge
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "base64url-no-pad charset is [A-Za-z0-9-_], challenge {challenge} diverged"
        );
    }
}

#[test]
fn rfc7636_4_2_s256_derivation_is_deterministic() {
    // Same verifier → same challenge, across independent construction calls.
    let verifier = "z".repeat(60);
    let p1 = Pkce::from_verifier(&verifier, PkceMethod::S256).unwrap();
    let p2 = Pkce::from_verifier(&verifier, PkceMethod::S256).unwrap();
    assert_eq!(p1.challenge(), p2.challenge());
}

#[test]
fn rfc7636_4_2_s256_challenge_differs_from_verifier() {
    // §4.2: S256 applies SHA-256; the challenge MUST NOT equal the
    // verifier (that would collapse to the "plain" method).
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let pkce = Pkce::from_verifier(verifier, PkceMethod::S256).unwrap();
    assert_ne!(pkce.verifier(), pkce.challenge());
}
