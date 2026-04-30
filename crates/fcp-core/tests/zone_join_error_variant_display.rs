//! Pin `ZoneKeyError` 5-variant Display matrix — the closest analogue to
//! "ZoneJoinError variant Display" (flywheel_connectors-jcxq8).
//!
//! Bead asks for `ZoneJoinError` Display + serde tag pinning. No type
//! literally named `ZoneJoinError` exists in fcp-core. The closest
//! zone-join-related error enum is [`ZoneKeyError`] at
//! `crates/fcp-core/src/zone_keys.rs:369` — a 5-variant error returned
//! by zone-key wrap/unwrap operations. Wrapping/unwrapping a zone key
//! IS the technical mechanism by which a node joins a zone (HPKE seal/
//! open of the symmetric zone key); failures during that flow are the
//! "ZoneJoinError" surface.
//!
//! No prior test pins ZoneKeyError — `grep` returns empty. Coverage:
//!   * 5 variants Display verbatim per variant (with payload preservation
//!     for u64/String fields),
//!   * `Crypto(#[from] CryptoError)` transparent forward — Display
//!     prefix `crypto failure:` followed by the inner CryptoError
//!     Display,
//!   * From<CryptoError> conversion sentinel,
//!   * Distinct-Display sentinel across all 5 variants,
//!   * std::error::Error impl,
//!   * Source-chain pinning: ZoneKeyError::Crypto's source() returns
//!     the underlying CryptoError (thiserror's #[from] preserves the
//!     chain).

use fcp_core::ZoneKeyError;
use fcp_crypto::CryptoError;
use std::error::Error;

#[test]
fn invalid_key_length_display_pins_phrasing() {
    let err = ZoneKeyError::InvalidKeyLength {
        expected: 32,
        found: 16,
    };
    assert_eq!(err.to_string(), "invalid key length (expected 32, got 16)");
}

#[test]
fn zone_id_mismatch_display_pins_phrasing() {
    let err = ZoneKeyError::ZoneIdMismatch {
        expected: "z:work".to_string(),
        found: "z:public".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "zone id mismatch (expected z:work, found z:public)"
    );
}

#[test]
fn missing_wrapped_zone_key_display_pins_phrasing() {
    let err = ZoneKeyError::MissingWrappedZoneKey {
        node_id: "node-alpha".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "missing wrapped zone key for node `node-alpha`"
    );
}

#[test]
fn missing_wrapped_object_id_key_display_pins_phrasing() {
    let err = ZoneKeyError::MissingWrappedObjectIdKey {
        node_id: "node-bravo".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "missing wrapped ObjectIdKey for node `node-bravo`"
    );
}

#[test]
fn crypto_variant_display_prefixes_and_forwards_inner_error() {
    // The Crypto variant uses `#[from] CryptoError` and Display formats
    // as `crypto failure: <inner>`. Pin both the prefix and the inner
    // message preservation.
    let inner = CryptoError::HpkeFailed("seal-failed".to_string());
    let inner_display = inner.to_string();

    let err = ZoneKeyError::Crypto(inner);
    let msg = err.to_string();

    assert!(
        msg.starts_with("crypto failure: "),
        "Crypto variant must prefix with `crypto failure: `, got `{msg}`"
    );
    assert!(
        msg.contains(&inner_display),
        "Crypto variant must forward inner CryptoError display `{inner_display}`, got `{msg}`"
    );
    assert_eq!(msg, format!("crypto failure: {inner_display}"));
}

#[test]
fn from_crypto_error_creates_crypto_variant() {
    // #[from] CryptoError generates a From impl. Verify it produces the
    // Crypto variant (the documented forward path for crypto subsystem
    // errors bubbling up through zone-key operations).
    let inner = CryptoError::SignatureVerificationFailed;
    let err: ZoneKeyError = inner.into();
    match err {
        ZoneKeyError::Crypto(_) => {}
        other => panic!("expected Crypto variant, got {other:?}"),
    }
}

#[test]
fn crypto_variant_preserves_source_chain() {
    // Loud sentinel: thiserror #[from] preserves std::error::Error::source().
    // Pin so a future change that drops the source forwarding is caught
    // — std error chain consumers (anyhow, eyre) walk source().
    let inner = CryptoError::HpkeFailed("test-source".to_string());
    let err = ZoneKeyError::Crypto(inner);

    let src = err.source().expect("Crypto variant must expose source()");
    let src_msg = src.to_string();
    assert!(
        src_msg.contains("HPKE") || src_msg.contains("test-source"),
        "source() must be the inner CryptoError, got `{src_msg}`"
    );
}

#[test]
fn non_crypto_variants_have_no_source() {
    // Variants without #[from] should NOT expose a source — they ARE
    // the leaf error.
    let leaf_variants: Vec<ZoneKeyError> = vec![
        ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 0,
        },
        ZoneKeyError::ZoneIdMismatch {
            expected: "a".to_string(),
            found: "b".to_string(),
        },
        ZoneKeyError::MissingWrappedZoneKey {
            node_id: "n".to_string(),
        },
        ZoneKeyError::MissingWrappedObjectIdKey {
            node_id: "n".to_string(),
        },
    ];
    for err in leaf_variants {
        assert!(
            err.source().is_none(),
            "{err:?} must not have source() — it's a leaf error"
        );
    }
}

#[test]
fn all_five_variants_have_distinct_display() {
    let variants = [
        ZoneKeyError::Crypto(CryptoError::HpkeFailed("x".to_string())),
        ZoneKeyError::InvalidKeyLength {
            expected: 32,
            found: 16,
        },
        ZoneKeyError::ZoneIdMismatch {
            expected: "z:a".to_string(),
            found: "z:b".to_string(),
        },
        ZoneKeyError::MissingWrappedZoneKey {
            node_id: "n1".to_string(),
        },
        ZoneKeyError::MissingWrappedObjectIdKey {
            node_id: "n1".to_string(),
        },
    ];
    let strings: std::collections::HashSet<_> =
        variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "Display collision across ZoneKeyError variants: {strings:?}"
    );
}

#[test]
fn zone_key_error_implements_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = ZoneKeyError::InvalidKeyLength {
        expected: 32,
        found: 0,
    };
    assert_error(&err);
}

#[test]
fn invalid_key_length_payload_preservation_in_display() {
    // Different payloads must produce different Display strings — pin so
    // a future format change that drops the numeric fields is caught.
    let a = ZoneKeyError::InvalidKeyLength {
        expected: 32,
        found: 16,
    };
    let b = ZoneKeyError::InvalidKeyLength {
        expected: 32,
        found: 31,
    };
    assert_ne!(a.to_string(), b.to_string());

    let c = ZoneKeyError::InvalidKeyLength {
        expected: 64,
        found: 16,
    };
    assert_ne!(a.to_string(), c.to_string());
}

#[test]
fn missing_wrapped_zone_key_and_object_id_key_have_distinct_phrasing() {
    // Loud sentinel: these two variants are syntactically similar
    // ("missing wrapped X for node `Y`") but differ on the X token.
    // Pin so a future refactor that consolidates them is caught.
    let zone = ZoneKeyError::MissingWrappedZoneKey {
        node_id: "n".to_string(),
    };
    let oid = ZoneKeyError::MissingWrappedObjectIdKey {
        node_id: "n".to_string(),
    };
    assert_ne!(zone.to_string(), oid.to_string());
    assert!(zone.to_string().contains("zone key"));
    assert!(oid.to_string().contains("ObjectIdKey"));
}

#[test]
fn zone_id_mismatch_payload_preservation() {
    let a = ZoneKeyError::ZoneIdMismatch {
        expected: "z:work".to_string(),
        found: "z:public".to_string(),
    };
    let b = ZoneKeyError::ZoneIdMismatch {
        expected: "z:work".to_string(),
        found: "z:private".to_string(),
    };
    assert_ne!(a.to_string(), b.to_string());
    assert!(a.to_string().contains("z:work"));
    assert!(a.to_string().contains("z:public"));
    assert!(!a.to_string().contains("z:private"));
}
