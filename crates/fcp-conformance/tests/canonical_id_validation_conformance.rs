//! Canonical-ID validation conformance for the FCP §3.1 identifier
//! family — `CapabilityId`, `ConnectorId`, `InstanceId`, `OperationId`.
//!
//! `fcp_core::validate_canonical_id` is the NORMATIVE rule set every
//! identifier in `FCP_Specification_V3.md` §3.1 is bound by:
//!
//! - ASCII only (no Unicode)
//! - lowercase only (no uppercase)
//! - length ≤ 128 bytes
//! - regex `^[a-z0-9][a-z0-9._:-]*$` — first char alphanumeric,
//!   later chars also accept `.`, `_`, `:`, `-`
//!
//! All four ID newtypes share this validator via `TryFrom<String>` and
//! the serde `try_from = "String"` attribute, which means: malformed
//! input MUST be rejected at deserialization time, and `from_static`
//! MUST panic when handed a non-canonical literal.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Empty rejection.** `""` MUST yield `Empty`.
//! 2. **Length cap = 128 bytes.** 128 ok, 129 rejected with `TooLong`.
//! 3. **Non-ASCII rejection.** Any non-ASCII byte → `NonAscii`.
//! 4. **Uppercase rejection.** Any uppercase ASCII → `UppercaseNotAllowed`.
//! 5. **Invalid start char.** First char MUST be `[a-z0-9]`; punctuation
//!    in position 0 → `InvalidStartChar`.
//! 6. **Invalid mid char.** Any char outside `[a-z0-9._:-]` after pos 0
//!    → `InvalidChar { index }` where `index` matches the byte offset.
//! 7. **All four ID types delegate to the same validator.** Identical
//!    inputs MUST be accepted/rejected uniformly.
//! 8. **`from_static` panics on non-canonical input.** This is the
//!    documented contract for compile-time-known IDs.
//! 9. **Serde uses `try_from = "String"`.** Malformed JSON strings
//!    MUST fail deserialization (not silently accept).
//! 10. **`FromStr`, `Display`, `AsRef<str>` parity.** Round-trip
//!     preserves byte-for-byte content.
//! 11. **`InstanceId::new` random output is canonical.** Generated IDs
//!     MUST round-trip through `validate_canonical_id`.
//! 12. **`InstanceId::new` collisions.** UUID-backed; two consecutive
//!     `new()` calls MUST differ.
//! 13. **`ConnectorId::new` composes `name:archetype:version`** with
//!     literal colons. Components MUST themselves be canonical-compatible.

use fcp_core::{
    CapabilityId, ConnectorId, IdValidationError, InstanceId, OperationId, validate_canonical_id,
};
use std::str::FromStr;

#[test]
fn empty_string_is_rejected() {
    assert_eq!(
        validate_canonical_id(""),
        Err(IdValidationError::Empty),
        "empty identifier MUST be rejected"
    );
}

#[test]
fn length_at_128_is_accepted() {
    let id_128 = "a".repeat(128);
    assert!(
        validate_canonical_id(&id_128).is_ok(),
        "128 bytes is the inclusive cap — MUST be accepted"
    );
}

#[test]
fn length_at_129_is_rejected_with_too_long() {
    let id_129 = "a".repeat(129);
    let err = validate_canonical_id(&id_129).expect_err("129 bytes MUST be rejected");
    match err {
        IdValidationError::TooLong { len, max } => {
            assert_eq!(len, 129);
            assert_eq!(max, 128);
        }
        other => panic!("expected TooLong, got {other:?}"),
    }
}

#[test]
fn non_ascii_is_rejected() {
    // Non-ASCII byte hidden inside an otherwise valid ID.
    let bad = "café";
    assert_eq!(
        validate_canonical_id(bad),
        Err(IdValidationError::NonAscii),
        "non-ASCII identifier MUST be rejected (no Unicode anywhere)"
    );
}

#[test]
fn uppercase_ascii_is_rejected() {
    // Single uppercase letter triggers the rule.
    assert_eq!(
        validate_canonical_id("Foo"),
        Err(IdValidationError::UppercaseNotAllowed)
    );
    assert_eq!(
        validate_canonical_id("aB"),
        Err(IdValidationError::UppercaseNotAllowed)
    );
}

#[test]
fn invalid_start_char_is_rejected() {
    // Punctuation at index 0 is documented as InvalidStartChar.
    let cases = [".foo", "-foo", "_foo", ":foo"];
    for s in cases {
        let err = validate_canonical_id(s).expect_err("start punctuation MUST be rejected");
        match err {
            IdValidationError::InvalidStartChar { ch } => {
                assert_eq!(ch, s.chars().next().expect("non-empty"));
            }
            other => panic!("expected InvalidStartChar for {s:?}, got {other:?}"),
        }
    }
}

#[test]
fn invalid_mid_char_reports_index_byte_offset() {
    // '@' at index 3 in "foo@bar" — index MUST match the byte offset
    // post-first-char (validator iterates char_indices on the rest).
    let err = validate_canonical_id("foo@bar").expect_err("'@' MUST be rejected");
    match err {
        IdValidationError::InvalidChar { ch, index } => {
            assert_eq!(ch, '@');
            assert_eq!(index, 3, "index MUST be the byte offset of the bad char");
        }
        other => panic!("expected InvalidChar, got {other:?}"),
    }
}

#[test]
fn allowed_punctuation_after_first_char_is_accepted() {
    // The four allowed punctuation marks — '.', '_', ':', '-' — MUST
    // each be accepted in non-leading position.
    for s in ["a.b", "a_b", "a:b", "a-b", "abc.def_ghi:jkl-mno"] {
        assert!(
            validate_canonical_id(s).is_ok(),
            "'{s}' is canonical — MUST be accepted"
        );
    }
}

#[test]
fn digit_is_an_allowed_start_char() {
    // The regex says `^[a-z0-9]` — digits at position 0 MUST be ok.
    for s in ["0foo", "9", "1.2.3"] {
        assert!(
            validate_canonical_id(s).is_ok(),
            "'{s}' starts with digit — MUST be accepted"
        );
    }
}

#[test]
fn capability_id_delegates_to_validator_for_rejections() {
    // Same rejections MUST appear via TryFrom<String>.
    let bad_inputs = ["", "Foo", "café", "@bad", "a@b"];
    for bad in bad_inputs {
        assert!(
            CapabilityId::new(bad).is_err(),
            "CapabilityId MUST reject '{bad}'"
        );
    }
}

#[test]
fn connector_id_delegates_to_validator_for_rejections() {
    // ConnectorId::new builds "name:archetype:version" then validates
    // the composite. Each rejection mode MUST surface.
    assert!(ConnectorId::new("", "arch", "v1").is_err());
    assert!(ConnectorId::new("Name", "arch", "v1").is_err());
    assert!(ConnectorId::new("name", "Arch", "v1").is_err());
    assert!(ConnectorId::new("name", "arch", "V1").is_err());
}

#[test]
fn operation_id_delegates_to_validator_for_rejections() {
    let bad_inputs = ["", "DoThing", "do thing", "do@thing"];
    for bad in bad_inputs {
        assert!(
            OperationId::new(bad).is_err(),
            "OperationId MUST reject '{bad}'"
        );
    }
}

#[test]
fn instance_id_try_from_rejects_malformed_strings() {
    // InstanceId is generated by `new()` but also accepts canonical
    // strings via TryFrom. Malformed input MUST be rejected the same
    // way the others are.
    assert!(InstanceId::try_from(String::new()).is_err());
    assert!(InstanceId::try_from("Bad".to_string()).is_err());
    assert!(InstanceId::try_from("with space".to_string()).is_err());
}

#[test]
fn capability_id_from_static_panics_on_non_canonical() {
    // Documented panic contract — pinned because it's how every
    // compile-time-known ID is constructed.
    let result = std::panic::catch_unwind(|| CapabilityId::from_static("Foo"));
    assert!(
        result.is_err(),
        "CapabilityId::from_static MUST panic on non-canonical input"
    );
}

#[test]
fn connector_id_from_static_panics_on_non_canonical() {
    let result = std::panic::catch_unwind(|| ConnectorId::from_static("Bad:Arch:v1"));
    assert!(
        result.is_err(),
        "ConnectorId::from_static MUST panic on non-canonical input"
    );
}

#[test]
fn operation_id_from_static_panics_on_non_canonical() {
    let result = std::panic::catch_unwind(|| OperationId::from_static("BadOp"));
    assert!(
        result.is_err(),
        "OperationId::from_static MUST panic on non-canonical input"
    );
}

#[test]
fn capability_id_serde_rejects_malformed_json_string() {
    // The serde `try_from = "String"` attribute MUST reject malformed
    // input at deserialization, not silently accept.
    let bad = "\"BAD\"";
    assert!(
        serde_json::from_str::<CapabilityId>(bad).is_err(),
        "CapabilityId serde MUST reject '{bad}'"
    );
}

#[test]
fn connector_id_serde_rejects_malformed_json_string() {
    let bad = "\"\"";
    assert!(
        serde_json::from_str::<ConnectorId>(bad).is_err(),
        "ConnectorId serde MUST reject empty string"
    );
}

#[test]
fn operation_id_serde_rejects_malformed_json_string() {
    let bad = "\"with space\"";
    assert!(
        serde_json::from_str::<OperationId>(bad).is_err(),
        "OperationId serde MUST reject '{bad}'"
    );
}

#[test]
fn instance_id_serde_rejects_malformed_json_string() {
    let bad = "\"@bad\"";
    assert!(
        serde_json::from_str::<InstanceId>(bad).is_err(),
        "InstanceId serde MUST reject '{bad}'"
    );
}

#[test]
fn capability_id_serde_roundtrip_preserves_value() {
    let original = CapabilityId::from_static("read.documents.v1");
    let json = serde_json::to_string(&original).expect("serialize");
    assert_eq!(json, "\"read.documents.v1\"");
    let parsed: CapabilityId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, original, "serde round-trip MUST be identity");
}

#[test]
fn connector_id_serde_roundtrip_preserves_value() {
    let original = ConnectorId::from_static("github:saas:v1");
    let json = serde_json::to_string(&original).expect("serialize");
    assert_eq!(json, "\"github:saas:v1\"");
    let parsed: ConnectorId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, original);
}

#[test]
fn capability_id_from_str_matches_new() {
    let via_new = CapabilityId::new("read.x").expect("new");
    let via_from_str = CapabilityId::from_str("read.x").expect("from_str");
    assert_eq!(via_new, via_from_str, "FromStr MUST match new()");
}

#[test]
fn connector_id_display_matches_as_str() {
    let id = ConnectorId::from_static("slack:saas:v1");
    assert_eq!(format!("{id}"), id.as_str());
}

#[test]
fn capability_id_as_ref_matches_as_str() {
    let id = CapabilityId::from_static("emit.events");
    let as_ref: &str = id.as_ref();
    assert_eq!(as_ref, id.as_str());
}

#[test]
fn instance_id_as_ref_matches_as_str() {
    let id = InstanceId::new();
    let as_ref: &str = id.as_ref();
    assert_eq!(as_ref, id.as_str());
}

#[test]
fn instance_id_new_produces_canonical_string() {
    // Random `inst_<uuid>` MUST itself satisfy validate_canonical_id.
    // If UUID-with-hyphens drifted into something the validator rejects,
    // the InstanceId would panic via TryFrom on its own output.
    let id = InstanceId::new();
    assert!(
        id.as_str().starts_with("inst_"),
        "InstanceId::new MUST prefix with 'inst_'; got {}",
        id.as_str()
    );
    assert!(
        validate_canonical_id(id.as_str()).is_ok(),
        "InstanceId::new MUST produce a canonical-validator-passing string; got {}",
        id.as_str()
    );
}

#[test]
fn instance_id_new_is_unique_per_call() {
    // UUID-backed: two consecutive `new()` calls MUST differ. Without
    // uniqueness, instance binding in CapabilityToken would alias.
    let a = InstanceId::new();
    let b = InstanceId::new();
    assert_ne!(
        a, b,
        "two consecutive InstanceId::new() calls MUST yield different IDs"
    );
}

#[test]
fn instance_id_default_matches_new() {
    // Default impl MUST produce canonical, unique IDs.
    let a = InstanceId::default();
    assert!(a.as_str().starts_with("inst_"));
    assert!(validate_canonical_id(a.as_str()).is_ok());
}

#[test]
fn connector_id_new_composes_three_colon_separated_components() {
    let id = ConnectorId::new("github", "saas", "v1").expect("canonical components");
    assert_eq!(
        id.as_str(),
        "github:saas:v1",
        "ConnectorId::new MUST format as 'name:archetype:version'"
    );
}

#[test]
fn capability_id_clone_eq_is_byte_for_byte() {
    let a = CapabilityId::from_static("foo.bar");
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.as_str(), b.as_str());
}

#[test]
fn capability_id_into_string_yields_original_bytes() {
    let original = "read.docs.v1";
    let id = CapabilityId::from_static(original);
    let back: String = id.into();
    assert_eq!(back, original, "Into<String> MUST yield original bytes");
}

#[test]
fn validate_canonical_id_accepts_max_complexity_string() {
    // Stress: every legal char class, max length region, all four
    // legal mid-punctuation marks. The validator MUST accept.
    let s = "a0b.c_d:e-f.g_h:i-j0k.l_m:n-o";
    assert!(validate_canonical_id(s).is_ok(), "complex canonical MUST pass");
    // And it round-trips through every ID type.
    assert!(CapabilityId::new(s).is_ok());
    assert!(ConnectorId::try_from(s.to_owned()).is_ok());
    assert!(OperationId::new(s).is_ok());
    assert!(InstanceId::try_from(s.to_owned()).is_ok());
}
