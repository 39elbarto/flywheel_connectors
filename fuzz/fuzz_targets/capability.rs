//! Capability Token Fuzz Target (flywheel_connectors-wawhf)
//!
//! Fuzzes COSE_Sign1 token parsing and CWT claims extraction.
//! Goal: Ensure no panics or undefined behavior on arbitrary input while
//! pinning KID/signature, timing, and canonical round-trip invariants.

#![no_main]

use chrono::{Duration, TimeZone, Utc};
use fcp_crypto::cose::{CoseToken, CwtClaims};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::error::CryptoError;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const FIXED_SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
const WRONG_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];

fn canonical_now(data: &[u8]) -> chrono::DateTime<Utc> {
    let seed = i64::from(data.first().copied().unwrap_or(0));
    Utc.timestamp_opt(1_700_000_000 + seed, 0)
        .single()
        .expect("fixed fuzz timestamp should be valid")
}

fn claims_from_seed(data: &[u8], now: chrono::DateTime<Utc>) -> CwtClaims {
    let suffix = format!(
        "{:02x}{:02x}",
        data.first().copied().unwrap_or(0),
        data.len() & 0xff
    );
    CwtClaims::new()
        .issuer("fuzz-capability")
        .subject(&format!("subject-{suffix}"))
        .capability_id(&format!("cap:fuzz.{suffix}"))
        .zone_id("z:work")
        .principal_id("principal:fuzz")
        .token_id(&[0xC0, 0xDE, data.first().copied().unwrap_or(0)])
        .not_before(now - Duration::seconds(30))
        .expiration(now + Duration::seconds(30))
        .issued_at(now)
}

fn assert_claims_roundtrip(claims: &CwtClaims) {
    let canonical = claims.to_cbor().expect("claims must encode");
    let reparsed = CwtClaims::from_cbor(&canonical).expect("claims CBOR must reparse");
    assert_eq!(
        canonical,
        reparsed.to_cbor().expect("reparsed claims must re-encode"),
        "CWT claims must roundtrip through canonical CBOR bytes"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(parsed_token) = CoseToken::from_cbor(data) {
        let canonical = parsed_token
            .to_cbor()
            .expect("parsed COSE token must re-encode canonically");
        let reparsed = CoseToken::from_cbor(&canonical)
            .expect("canonical COSE token must parse after re-encode");
        assert_eq!(
            canonical,
            reparsed
                .to_cbor()
                .expect("reparsed token must remain canonically encodable"),
            "COSE token re-encode must equal the canonical input bytes"
        );

        if let Ok(unverified_claims) = parsed_token.claims_unverified() {
            assert_claims_roundtrip(&unverified_claims);
        }
    }

    if let Ok(parsed_claims) = CwtClaims::from_cbor(data) {
        assert_claims_roundtrip(&parsed_claims);
    }

    let now = canonical_now(data);
    let signing_key =
        Ed25519SigningKey::from_bytes(&FIXED_SIGNING_KEY_BYTES).expect("fixed key must parse");
    let verifying_key = signing_key.verifying_key();
    let wrong_verifying_key = Ed25519SigningKey::from_bytes(&WRONG_SIGNING_KEY_BYTES)
        .expect("wrong key must parse")
        .verifying_key();

    let claims = claims_from_seed(data, now);
    assert_claims_roundtrip(&claims);

    let signed = CoseToken::sign(&signing_key, &claims).expect("signing must succeed");
    let kid = signing_key.key_id();
    let verified_claims = signed
        .verify(&verifying_key)
        .expect("signed token must verify");
    assert_eq!(
        signed.get_key_id().expect("signed token must carry kid"),
        kid.as_bytes(),
        "signed token kid must match the signing key's derived kid"
    );
    assert_eq!(
        verified_claims
            .to_cbor()
            .expect("verified claims must encode"),
        claims.to_cbor().expect("seed claims must encode"),
        "verified claims must match the claims that were signed"
    );
    assert_claims_roundtrip(&verified_claims);

    let looked_up = signed
        .verify_with_lookup(|lookup_kid| {
            assert_eq!(
                lookup_kid, &kid,
                "verify_with_lookup must route by the protected kid"
            );
            Some(verifying_key.clone())
        })
        .expect("lookup-based verification must succeed for the matching kid");
    assert_eq!(
        looked_up.to_cbor().expect("lookup claims must encode"),
        verified_claims
            .to_cbor()
            .expect("directly verified claims must encode"),
        "lookup verification must agree with direct verification"
    );

    let wrong_key_err = signed
        .verify_with_lookup(|lookup_kid| {
            assert_eq!(
                lookup_kid, &kid,
                "wrong-key lookup should still receive the declared kid"
            );
            Some(wrong_verifying_key.clone())
        })
        .expect_err("kid-mismatched verifier must be rejected, not silently accepted");
    assert!(
        matches!(wrong_key_err, CryptoError::KeyIdMismatch { .. }),
        "wrong-key verification must fail with KeyIdMismatch, got {wrong_key_err:?}"
    );

    let missing_key_err = signed
        .verify_with_lookup(|lookup_kid| {
            assert_eq!(
                lookup_kid, &kid,
                "missing-key path should still use the declared kid"
            );
            None
        })
        .expect_err("missing-key lookup must be rejected");
    assert!(
        matches!(missing_key_err, CryptoError::InvalidKeyId(_)),
        "missing-key verification must fail with InvalidKeyId, got {missing_key_err:?}"
    );

    let canonical_signed = signed
        .to_cbor()
        .expect("signed token must encode canonically");
    let reparsed_signed =
        CoseToken::from_cbor(&canonical_signed).expect("canonical signed token must parse");
    assert_eq!(
        canonical_signed,
        reparsed_signed
            .to_cbor()
            .expect("reparsed signed token must re-encode"),
        "signed token re-encode must equal its canonical bytes"
    );

    let expired_claims = verified_claims
        .clone()
        .not_before(now - Duration::seconds(2))
        .expiration(now - Duration::seconds(1));
    let expired_err = CoseToken::validate_timing(&expired_claims, now)
        .expect_err("forged expired claims must fail timing validation");
    assert!(
        matches!(expired_err, CryptoError::TokenExpired),
        "expired claims must fail with TokenExpired, got {expired_err:?}"
    );

    let future_claims = verified_claims
        .clone()
        .not_before(now + Duration::seconds(1))
        .expiration(now + Duration::seconds(2));
    let future_err = CoseToken::validate_timing(&future_claims, now)
        .expect_err("forged future nbf claims must fail timing validation");
    assert!(
        matches!(future_err, CryptoError::TokenNotYetValid),
        "future nbf claims must fail with TokenNotYetValid, got {future_err:?}"
    );
});
