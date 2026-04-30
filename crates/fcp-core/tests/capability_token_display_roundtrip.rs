//! Pin `CapabilityId` Display+FromStr+serde roundtrip + IdValidationError
//! 6-variant matrix — the closest analogue to "CapabilityToken
//! display roundtrip" (flywheel_connectors-p1xf4).
//!
//! Bead asks for `CapabilityToken` Display+FromStr+serde roundtrip pinning.
//! `CapabilityToken` is a COSE_Sign1 binary blob (no `Display` or `FromStr`
//! impl — and a meaningful binary-ID round-trip would be a base64/hex
//! contract, not a Display contract). The closest text-form analogue with
//! Display + FromStr + serde(try_from = "String") is [`CapabilityId`] at
//! `crates/fcp-core/src/capability.rs:124`. This is the actual identifier
//! that names a capability inside a token; pinning its text-form contract
//! is what the bead is reaching for.
//!
//! Existing `capability_id_display_roundtrip.rs` covers Display+FromStr
//! happy-path + equivalent-constructor equality. This pin adds:
//!   * Full IdValidationError 6-variant rejection matrix from
//!     `validate_canonical_id` (Empty / TooLong / NonAscii /
//!     UppercaseNotAllowed / InvalidStartChar / InvalidChar),
//!   * JSON shape: scalar string (transparent via serde(try_from/into String)),
//!   * CBOR shape: Text scalar,
//!   * JSON+CBOR roundtrip preserves canonical bytes,
//!   * Distinct canonical IDs hash + serialize distinctly,
//!   * Boundary case: 128-byte ID (the documented max) succeeds; 129 rejects,
//!   * Display equals as_str() byte-for-byte.

use ciborium::Value as CborValue;
use fcp_core::{CapabilityId, IdValidationError};
use serde_json::json;

#[test]
fn validate_rejects_empty_with_empty_variant() {
    let err = "".parse::<CapabilityId>().unwrap_err();
    assert_eq!(err, IdValidationError::Empty);
}

#[test]
fn validate_rejects_oversize_with_too_long_variant() {
    // 128 is the documented max; produce a 129-char ASCII lowercase id.
    let s: String = std::iter::repeat_n('a', 129).collect();
    let err = s.parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::TooLong { len, max } => {
            assert_eq!(len, 129);
            assert_eq!(max, 128);
        }
        other => panic!("expected TooLong, got {other:?}"),
    }
}

#[test]
fn validate_accepts_max_length_id() {
    // Boundary: exactly 128 chars must succeed.
    let s: String = std::iter::repeat_n('a', 128).collect();
    let id = s.parse::<CapabilityId>().expect("128-byte id must parse");
    assert_eq!(id.as_str().len(), 128);
}

#[test]
fn validate_rejects_non_ascii_with_non_ascii_variant() {
    let err = "cap.café".parse::<CapabilityId>().unwrap_err();
    assert_eq!(err, IdValidationError::NonAscii);
}

#[test]
fn validate_rejects_uppercase_with_uppercase_variant() {
    let err = "Cap.Read".parse::<CapabilityId>().unwrap_err();
    assert_eq!(err, IdValidationError::UppercaseNotAllowed);

    // Even uppercase tail still rejects.
    let err = "cap.Read".parse::<CapabilityId>().unwrap_err();
    assert_eq!(err, IdValidationError::UppercaseNotAllowed);
}

#[test]
fn validate_rejects_invalid_start_char() {
    // Leading separator is rejected.
    let err = ".cap".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidStartChar { ch } => assert_eq!(ch, '.'),
        other => panic!("expected InvalidStartChar('.'), got {other:?}"),
    }

    let err = "-cap".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidStartChar { ch } => assert_eq!(ch, '-'),
        other => panic!("expected InvalidStartChar('-'), got {other:?}"),
    }

    let err = "_cap".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidStartChar { ch } => assert_eq!(ch, '_'),
        other => panic!("expected InvalidStartChar('_'), got {other:?}"),
    }

    let err = ":cap".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidStartChar { ch } => assert_eq!(ch, ':'),
        other => panic!("expected InvalidStartChar(':'), got {other:?}"),
    }
}

#[test]
fn validate_accepts_digit_start() {
    // The grammar `^[a-z0-9][a-z0-9._:-]*$` allows digit start.
    let id = "9cap"
        .parse::<CapabilityId>()
        .expect("digit start must parse");
    assert_eq!(id.as_str(), "9cap");
}

#[test]
fn validate_rejects_invalid_inner_char_with_index() {
    let err = "cap@read".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidChar { ch, index } => {
            assert_eq!(ch, '@');
            assert_eq!(index, 3, "byte index of `@` in `cap@read` is 3");
        }
        other => panic!("expected InvalidChar('@', 3), got {other:?}"),
    }

    let err = "cap read".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidChar { ch, index } => {
            assert_eq!(ch, ' ');
            assert_eq!(index, 3);
        }
        other => panic!("expected InvalidChar(' ', 3), got {other:?}"),
    }

    let err = "cap/read".parse::<CapabilityId>().unwrap_err();
    match err {
        IdValidationError::InvalidChar { ch, index } => {
            assert_eq!(ch, '/');
            assert_eq!(index, 3);
        }
        other => panic!("expected InvalidChar('/', 3), got {other:?}"),
    }
}

#[test]
fn id_validation_error_variants_have_distinct_display() {
    let variants = [
        IdValidationError::Empty,
        IdValidationError::TooLong { len: 129, max: 128 },
        IdValidationError::NonAscii,
        IdValidationError::UppercaseNotAllowed,
        IdValidationError::InvalidStartChar { ch: '.' },
        IdValidationError::InvalidChar { ch: '@', index: 3 },
    ];
    let strings: std::collections::HashSet<_> = variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "IdValidationError Display collision: {strings:?}"
    );
}

#[test]
fn display_equals_as_str_byte_for_byte() {
    let id = CapabilityId::from_static("cap.read");
    assert_eq!(id.to_string(), id.as_str());
    assert_eq!(format!("{id}"), "cap.read");
}

#[test]
fn json_serializes_as_scalar_string() {
    // CapabilityId carries `#[serde(try_from = "String", into = "String")]`,
    // so JSON form is a bare scalar string (NOT an object wrapper).
    let id = CapabilityId::from_static("cap.read");
    let v = serde_json::to_value(&id).unwrap();
    assert_eq!(v, json!("cap.read"));

    let back: CapabilityId = serde_json::from_value(v).unwrap();
    assert_eq!(back, id);
}

#[test]
fn json_rejects_invalid_canonical_id_during_deserialize() {
    // serde(try_from = "String") must propagate validate_canonical_id errors.
    let result: Result<CapabilityId, _> = serde_json::from_value(json!("Cap.Read"));
    assert!(result.is_err(), "uppercase must reject: {result:?}");
    let result: Result<CapabilityId, _> = serde_json::from_value(json!(""));
    assert!(result.is_err(), "empty must reject: {result:?}");
    let result: Result<CapabilityId, _> = serde_json::from_value(json!("cap@read"));
    assert!(result.is_err(), "invalid char must reject: {result:?}");
}

#[test]
fn cbor_serializes_as_text_scalar() {
    let id = CapabilityId::from_static("cap.discord.send_message");
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&id, &mut bytes).unwrap();
    let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
    match value {
        CborValue::Text(text) => assert_eq!(text, "cap.discord.send_message"),
        other => panic!("expected Text scalar, got {other:?}"),
    }

    let back: CapabilityId = ciborium::de::from_reader(&bytes[..]).unwrap();
    assert_eq!(back, id);
}

#[test]
fn cbor_roundtrip_preserves_id_for_diverse_canonical_forms() {
    let cases = [
        "cap.read",
        "9cap",
        "fcp.example:files.read-v2",
        "a.b_c:d-e",
        "cap",
        "0",
    ];
    for case in cases {
        let id = case.parse::<CapabilityId>().unwrap();
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&id, &mut bytes).unwrap();
        let back: CapabilityId = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back.as_str(), case, "CBOR round-trip drift on `{case}`");
    }
}

#[test]
fn json_and_cbor_decode_to_same_id_for_canonical_text() {
    let canonical = "fcp.example:cap.compose-v3";
    let id_via_json: CapabilityId = serde_json::from_value(json!(canonical)).unwrap();
    let cbor_bytes = {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&id_via_json, &mut bytes).unwrap();
        bytes
    };
    let id_via_cbor: CapabilityId = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();
    assert_eq!(id_via_json, id_via_cbor);
}

#[test]
fn distinct_canonical_ids_serialize_and_hash_distinctly() {
    // CapabilityId is used as HashMap key in policy + capability storage —
    // pin that distinct canonical strings produce distinct hashes AND
    // distinct JSON. Otherwise a hash collision would silently merge two
    // separate capabilities.
    let ids = [
        CapabilityId::from_static("cap.read"),
        CapabilityId::from_static("cap.write"),
        CapabilityId::from_static("cap.admin"),
        CapabilityId::from_static("fcp.example:cap.compose-v3"),
        CapabilityId::from_static("9cap"),
    ];
    let mut hash_set = std::collections::HashSet::new();
    let mut json_set = std::collections::HashSet::new();
    for id in &ids {
        assert!(hash_set.insert(id.clone()), "hash collision on {id:?}");
        let v = serde_json::to_value(id).unwrap();
        assert!(json_set.insert(v.clone()), "JSON collision on {id:?}");
    }
}

#[test]
fn from_str_and_try_from_string_produce_equal_ids() {
    let canonical = "cap.read.v2";
    let via_parse = canonical.parse::<CapabilityId>().unwrap();
    let via_try = CapabilityId::try_from(canonical.to_string()).unwrap();
    let via_new = CapabilityId::new(canonical).unwrap();
    let via_static = CapabilityId::from_static(canonical);
    assert_eq!(via_parse, via_try);
    assert_eq!(via_try, via_new);
    assert_eq!(via_new, via_static);
    // String round-trip via Into<String> recovers the canonical text.
    let owned: String = via_parse.clone().into();
    assert_eq!(owned, canonical);
}

#[test]
fn display_roundtrip_fixed_point_for_canonical_text() {
    // f(x) = parse(display(x)) is the identity on canonical IDs.
    let cases = [
        "cap",
        "cap.read",
        "9cap",
        "a-b-c",
        "a_b_c",
        "fcp.example:cap.compose-v3",
        "0.0",
    ];
    for canonical in cases {
        let id: CapabilityId = canonical.parse().unwrap();
        let s = id.to_string();
        let id2: CapabilityId = s.parse().unwrap();
        assert_eq!(id, id2, "display-roundtrip drift on `{canonical}`");
        assert_eq!(s, canonical);
    }
}
