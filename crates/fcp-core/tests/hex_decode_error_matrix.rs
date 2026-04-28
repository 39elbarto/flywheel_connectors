//! Pin the fcp-core hex-decode error matrix
//! (flywheel_connectors-w674w).
//!
//! Two distinct hex-decode surfaces live in fcp-core, each with its
//! own documented contract:
//!
//! 1. **`ObjectId::parse_prefixed`** (object.rs:39) — strips an
//!    optional `objectid:` prefix, then `hex::decode`s the remainder
//!    and validates 32-byte length. Returns:
//!      - `Ok(ObjectId)` on success
//!      - `Err(InvalidHex)` if the post-prefix string fails hex decode
//!        (non-hex char, odd length)
//!      - `Err(WrongLength { actual })` if the decoded bytes aren't 32
//!
//! 2. **`util::hex_or_bytes::deserialize`** (util/hex_or_bytes.rs) —
//!    the serde codec used by `ObjectId`, `ZoneKeyId`,
//!    `NodeSignature.signature`, and other fixed-byte-array fields
//!    when deserializing from a human-readable format (JSON).
//!    Returns a serde error on hex decode failure or wrong length.
//!
//! Documented behaviors that this matrix pins:
//!
//! - **Empty input**:
//!   - `parse_prefixed("")` → `WrongLength { actual: 0 }` (empty hex
//!     decodes to 0 bytes, not 32).
//!   - `parse_prefixed("objectid:")` → `WrongLength { actual: 0 }`.
//! - **Odd-length input**: `parse_prefixed("abc")` → `InvalidHex`
//!   (hex::decode rejects odd length).
//! - **Non-hex char**: `parse_prefixed("zz...")` → `InvalidHex`.
//! - **Mixed-case acceptance**: `0xAaBb...` (32-byte mixed-case hex)
//!   decodes successfully via both `parse_prefixed` and the
//!   `hex_or_bytes` serde codec — this is the documented behavior of
//!   the underlying `hex` crate.
//! - **`0x` prefix is NOT stripped**: `parse_prefixed("0x" + hex)`
//!   fails with `InvalidHex` because the `x` is not a valid hex
//!   character. Only the `objectid:` prefix is documented as
//!   strippable. A regression that quietly added `0x` stripping
//!   would create two independent canonical-form decoders and
//!   fragment the content-address space.
//! - **`objectid:` prefix is stripped exactly once**: a doubled
//!   prefix `objectid:objectid:<hex>` fails because the second
//!   `objectid:` reaches `hex::decode` literally and trips on `o`.

use fcp_core::{ObjectId, ObjectIdParseError};
use serde::Deserialize;

/// Test wrapper for fixed-size 32-byte arrays via the
/// `util::hex_or_bytes` serde codec. Mirrors how `ObjectId`,
/// `ZoneKeyId`, `NodeSignature::signature`, etc. are wired.
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Key32 {
    #[serde(with = "fcp_core::util::hex_or_bytes")]
    data: [u8; 32],
}

const VALID_HEX: &str = "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe";

// ─────────────────────────────────────────────────────────────────────────────
// ObjectId::parse_prefixed — exact error variant per input class
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_prefixed_accepts_bare_lowercase_hex() {
    let id = ObjectId::parse_prefixed(VALID_HEX).expect("32-byte lowercase hex");
    let mut expected = [0u8; 32];
    hex::decode_to_slice(VALID_HEX, &mut expected).expect("decode reference");
    assert_eq!(*id.as_bytes(), expected);
}

#[test]
fn parse_prefixed_accepts_objectid_prefix() {
    let prefixed = format!("objectid:{VALID_HEX}");
    let id_a = ObjectId::parse_prefixed(&prefixed).expect("with objectid: prefix");
    let id_b = ObjectId::parse_prefixed(VALID_HEX).expect("without prefix");
    assert_eq!(
        id_a, id_b,
        "objectid: prefix MUST NOT change the decoded value"
    );
}

#[test]
fn parse_prefixed_accepts_uppercase_hex() {
    let upper = VALID_HEX.to_uppercase();
    let id = ObjectId::parse_prefixed(&upper).expect("uppercase hex");
    let id_lower = ObjectId::parse_prefixed(VALID_HEX).expect("lowercase");
    assert_eq!(
        id, id_lower,
        "uppercase hex MUST decode to the same ObjectId"
    );
}

#[test]
fn parse_prefixed_accepts_mixed_case_hex() {
    // Build a deliberately mixed-case version of VALID_HEX (every
    // other nibble swapped to uppercase).
    let mixed: String = VALID_HEX
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i.is_multiple_of(2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    let id = ObjectId::parse_prefixed(&mixed).expect("mixed-case hex");
    let id_lower = ObjectId::parse_prefixed(VALID_HEX).expect("lowercase");
    assert_eq!(
        id, id_lower,
        "mixed-case hex MUST decode to the same ObjectId as lowercase"
    );
}

#[test]
fn parse_prefixed_empty_input_is_wrong_length_zero() {
    // Empty string decodes to 0 bytes — falls into the WrongLength
    // branch, NOT InvalidHex. Pinning the exact branch matters
    // because a regression that promoted "empty" to InvalidHex would
    // silently drop the actual byte count from observability.
    match ObjectId::parse_prefixed("") {
        Err(ObjectIdParseError::WrongLength { actual: 0 }) => {}
        other => {
            panic!("POLICY REGRESSION: empty input expected WrongLength{{actual:0}}, got {other:?}")
        }
    }
}

#[test]
fn parse_prefixed_objectid_only_prefix_is_wrong_length_zero() {
    // The prefix is stripped before decode; the post-strip empty
    // string decodes to 0 bytes.
    match ObjectId::parse_prefixed("objectid:") {
        Err(ObjectIdParseError::WrongLength { actual: 0 }) => {}
        other => panic!("`objectid:` alone expected WrongLength{{actual:0}}, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_odd_length_is_invalid_hex() {
    // hex::decode rejects odd-length strings outright.
    match ObjectId::parse_prefixed("abc") {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!("odd-length input expected InvalidHex, got {other:?}"),
    }
    // Same with the prefix.
    match ObjectId::parse_prefixed("objectid:abc") {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!("prefixed odd-length input expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_non_hex_char_is_invalid_hex() {
    // Even-length but contains chars outside [0-9a-fA-F].
    let bad = "zz".repeat(32);
    match ObjectId::parse_prefixed(&bad) {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!("non-hex chars expected InvalidHex, got {other:?}"),
    }
    // A single non-hex char in the middle of a long string still
    // trips InvalidHex.
    let mut mostly_valid: String = VALID_HEX.into();
    mostly_valid.replace_range(2..3, "g");
    match ObjectId::parse_prefixed(&mostly_valid) {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!("single non-hex char expected InvalidHex, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_zero_x_prefix_is_invalid_hex() {
    // POLICY: ObjectId::parse_prefixed strips ONLY the `objectid:`
    // prefix. A `0x` prefix is NOT supported and MUST trip
    // InvalidHex (the `x` is not a valid hex character).
    let with_0x = format!("0x{VALID_HEX}");
    match ObjectId::parse_prefixed(&with_0x) {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!(
            "POLICY REGRESSION: `0x`-prefixed hex MUST be rejected as InvalidHex \
             (only `objectid:` is documented as strippable), got {other:?}"
        ),
    }
    // Same when both prefixes are present.
    let with_both = format!("objectid:0x{VALID_HEX}");
    match ObjectId::parse_prefixed(&with_both) {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!("`objectid:0x...` MUST be rejected as InvalidHex, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_objectid_prefix_is_stripped_exactly_once() {
    // A doubled prefix MUST fail because after stripping the first
    // `objectid:`, the remainder is `objectid:<hex>` which contains
    // non-hex chars.
    let doubled = format!("objectid:objectid:{VALID_HEX}");
    match ObjectId::parse_prefixed(&doubled) {
        Err(ObjectIdParseError::InvalidHex) => {}
        other => panic!(
            "POLICY: `objectid:` MUST be stripped exactly once; doubled prefix expected \
             InvalidHex, got {other:?}"
        ),
    }
}

#[test]
fn parse_prefixed_short_hex_is_wrong_length_with_actual_byte_count() {
    // 30 bytes (60 hex chars) — well-formed hex, just wrong length.
    // The error MUST carry the actual decoded byte count so callers
    // can render diagnostic messages.
    let short = "ab".repeat(30);
    match ObjectId::parse_prefixed(&short) {
        Err(ObjectIdParseError::WrongLength { actual: 30 }) => {}
        other => panic!("60-hex-char input expected WrongLength{{actual:30}}, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_long_hex_is_wrong_length_with_actual_byte_count() {
    let long = "ab".repeat(34);
    match ObjectId::parse_prefixed(&long) {
        Err(ObjectIdParseError::WrongLength { actual: 34 }) => {}
        other => panic!("68-hex-char input expected WrongLength{{actual:34}}, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_round_trip_via_to_prefixed_string() {
    // The Display/parse_prefixed pair is the canonical user-facing
    // round-trip. Any drift in the format breaks every connector
    // manifest using `objectid:<hex>` references.
    let id = ObjectId::from_bytes([0x42; 32]);
    let prefixed = id.to_prefixed_string();
    assert!(
        prefixed.starts_with("objectid:"),
        "to_prefixed_string MUST emit the `objectid:` prefix"
    );
    let decoded = ObjectId::parse_prefixed(&prefixed).expect("round-trip");
    assert_eq!(decoded, id);
}

// ─────────────────────────────────────────────────────────────────────────────
// hex_or_bytes serde codec — error variant per input class via JSON
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hex_or_bytes_json_accepts_lowercase_uppercase_and_mixed_case() {
    // Lowercase.
    let json_lower = format!(r#"{{"data":"{VALID_HEX}"}}"#);
    let lower: Key32 = serde_json::from_str(&json_lower).expect("lowercase");

    // Uppercase.
    let upper_hex = VALID_HEX.to_uppercase();
    let json_upper = format!(r#"{{"data":"{upper_hex}"}}"#);
    let upper: Key32 = serde_json::from_str(&json_upper).expect("uppercase");

    assert_eq!(
        lower, upper,
        "hex_or_bytes codec MUST treat case-insensitive hex as the same value"
    );

    // Mixed.
    let mixed_hex: String = VALID_HEX
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i.is_multiple_of(2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    let json_mixed = format!(r#"{{"data":"{mixed_hex}"}}"#);
    let mixed: Key32 = serde_json::from_str(&json_mixed).expect("mixed-case");
    assert_eq!(lower, mixed, "mixed-case hex MUST decode to the same value");
}

#[test]
fn hex_or_bytes_json_rejects_empty_string() {
    let bad = r#"{"data":""}"#;
    let result: Result<Key32, _> = serde_json::from_str(bad);
    assert!(
        result.is_err(),
        "empty hex string MUST be rejected (decodes to 0 bytes != 32)"
    );
}

#[test]
fn hex_or_bytes_json_rejects_odd_length() {
    // 63-char hex — odd length. hex::decode rejects.
    let odd = "a".repeat(63);
    let bad = format!(r#"{{"data":"{odd}"}}"#);
    let result: Result<Key32, _> = serde_json::from_str(&bad);
    assert!(result.is_err(), "odd-length hex MUST be rejected");
}

#[test]
fn hex_or_bytes_json_rejects_non_hex_char() {
    let bad = format!(r#"{{"data":"{}"}}"#, "zz".repeat(32));
    let result: Result<Key32, _> = serde_json::from_str(&bad);
    assert!(result.is_err(), "non-hex chars MUST be rejected");
}

#[test]
fn hex_or_bytes_json_rejects_zero_x_prefix() {
    // The serde codec uses `hex::decode` which does NOT strip `0x`.
    let with_0x = format!(r#"{{"data":"0x{VALID_HEX}"}}"#);
    let result: Result<Key32, _> = serde_json::from_str(&with_0x);
    assert!(
        result.is_err(),
        "POLICY REGRESSION: `0x`-prefixed hex MUST be rejected by hex_or_bytes codec"
    );
}

#[test]
fn hex_or_bytes_json_rejects_wrong_length_too_short() {
    // 30-byte (60-char) hex — well-formed but wrong length.
    let short_hex = "ab".repeat(30);
    let bad = format!(r#"{{"data":"{short_hex}"}}"#);
    let result: Result<Key32, _> = serde_json::from_str(&bad);
    assert!(
        result.is_err(),
        "60-hex-char input MUST be rejected as wrong length for [u8; 32]"
    );
}

#[test]
fn hex_or_bytes_json_rejects_wrong_length_too_long() {
    let long_hex = "ab".repeat(34);
    let bad = format!(r#"{{"data":"{long_hex}"}}"#);
    let result: Result<Key32, _> = serde_json::from_str(&bad);
    assert!(
        result.is_err(),
        "68-hex-char input MUST be rejected as wrong length for [u8; 32]"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-surface consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_prefixed_and_serde_codec_agree_on_canonical_input() {
    // Both surfaces decode the same canonical hex to identical bytes.
    let via_parse = ObjectId::parse_prefixed(VALID_HEX).expect("parse_prefixed");
    let json = format!(r#"{{"data":"{VALID_HEX}"}}"#);
    let via_serde: Key32 = serde_json::from_str(&json).expect("serde codec");
    assert_eq!(
        *via_parse.as_bytes(),
        via_serde.data,
        "ObjectId::parse_prefixed and hex_or_bytes serde codec MUST decode identical bytes"
    );
}

#[test]
fn neither_surface_accepts_zero_x_prefix() {
    let with_0x = format!("0x{VALID_HEX}");
    assert!(matches!(
        ObjectId::parse_prefixed(&with_0x),
        Err(ObjectIdParseError::InvalidHex)
    ));
    let json = format!(r#"{{"data":"{with_0x}"}}"#);
    let result: Result<Key32, _> = serde_json::from_str(&json);
    assert!(
        result.is_err(),
        "both hex-decode surfaces MUST consistently reject `0x` prefix"
    );
}
