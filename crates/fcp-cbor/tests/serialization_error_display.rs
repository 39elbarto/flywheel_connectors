//! Pin the public Display surface for fcp-cbor's two error contracts:
//! [`SerializationError`] (11 variants — every canonical-CBOR failure mode)
//! and [`SchemaIdError`] (1 variant — reserved-separator rejection during
//! `SchemaId` construction).
//!
//! Both are user-facing: every fcp-host, fcp-protocol, and connector
//! request that touches canonical CBOR (i.e. all of them) flows through
//! `SerializationError`. A silent `thiserror` format-string change here
//! would mutate diagnostics shipped to operators and produce
//! cross-version log-comparison drift in audit replays.
//!
//! Bead: flywheel_connectors-5fztw.

use fcp_cbor::{SchemaHash, SchemaIdError, SerializationError, SCHEMA_HASH_LEN};

// ── SchemaIdError ───────────────────────────────────────────────────────

#[test]
fn schema_id_error_reserved_separator_display_matches_field_and_char() {
    let cases: &[(&'static str, char, &str)] = &[
        ("namespace", ':', "SchemaId namespace contains reserved separator ':'"),
        ("namespace", '@', "SchemaId namespace contains reserved separator '@'"),
        ("name", ':', "SchemaId name contains reserved separator ':'"),
        ("name", '@', "SchemaId name contains reserved separator '@'"),
    ];
    for (field, separator, expected) in cases {
        let err = SchemaIdError::ReservedSeparator {
            field,
            separator: *separator,
        };
        assert_eq!(
            err.to_string(),
            *expected,
            "SchemaIdError::ReservedSeparator Display drifted for ({field}, {separator})"
        );
    }
}

#[test]
fn schema_id_error_variant_count_is_one() {
    let err = SchemaIdError::ReservedSeparator {
        field: "namespace",
        separator: ':',
    };
    // Exhaustive match — adding a new variant breaks compilation, forcing
    // the author to also pin its Display string above.
    match err {
        SchemaIdError::ReservedSeparator { .. } => (),
    }
}

// ── SerializationError ──────────────────────────────────────────────────

const fn sample_hash(byte: u8) -> SchemaHash {
    SchemaHash::from_bytes([byte; SCHEMA_HASH_LEN])
}

#[test]
fn serialization_error_missing_schema_hash_prefix_display() {
    let err = SerializationError::MissingSchemaHashPrefix;
    assert_eq!(err.to_string(), "payload missing schema hash prefix");
}

#[test]
fn serialization_error_schema_mismatch_display_includes_both_hashes() {
    let expected = sample_hash(0xAA);
    let got = sample_hash(0xBB);
    let err = SerializationError::SchemaMismatch { expected, got };
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("schema hash mismatch (expected "),
        "SchemaMismatch Display prefix drifted: {rendered}"
    );
    assert!(
        rendered.contains(&expected.to_string()),
        "expected hash hex absent from Display: {rendered}"
    );
    assert!(
        rendered.contains(&got.to_string()),
        "got hash hex absent from Display: {rendered}"
    );
}

#[test]
fn serialization_error_payload_too_large_display() {
    let err = SerializationError::PayloadTooLarge {
        len: 12_345,
        max: 10_000,
    };
    assert_eq!(
        err.to_string(),
        "payload too large (12345 bytes > 10000 bytes)"
    );
}

#[test]
fn serialization_error_depth_exceeded_display() {
    let err = SerializationError::DepthExceeded { depth: 33, max: 32 };
    assert_eq!(
        err.to_string(),
        "canonicalization depth 33 exceeds limit 32"
    );
}

#[test]
fn serialization_error_trailing_bytes_display() {
    let err = SerializationError::TrailingBytes;
    assert_eq!(err.to_string(), "trailing bytes after CBOR value");
}

#[test]
fn serialization_error_non_canonical_encoding_display() {
    let err = SerializationError::NonCanonicalEncoding;
    assert_eq!(err.to_string(), "non-canonical CBOR encoding");
}

#[test]
fn serialization_error_cbor_value_display_includes_inner_message() {
    let inner = ciborium::value::Error::Custom(String::from("bad value"));
    let err = SerializationError::CborValue(inner);
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("cbor value conversion error: "),
        "CborValue Display prefix drifted: {rendered}"
    );
    assert!(
        rendered.contains("bad value"),
        "inner ciborium::value::Error message absent: {rendered}"
    );
}

#[test]
fn serialization_error_non_finite_float_display() {
    let err = SerializationError::NonFiniteFloat;
    assert_eq!(
        err.to_string(),
        "non-finite float (NaN or Infinity) not allowed in canonical CBOR"
    );
}

#[test]
fn serialization_error_duplicate_map_key_display_includes_key_hex() {
    let err = SerializationError::DuplicateMapKey {
        key_hex: String::from("deadbeef"),
    };
    assert_eq!(
        err.to_string(),
        "duplicate map key (canonical key bytes: deadbeef)"
    );
}

#[test]
fn serialization_error_unsupported_tag_display() {
    let err = SerializationError::UnsupportedTag { tag: 42 };
    assert_eq!(
        err.to_string(),
        "CBOR tag 42 is not allowed in canonical FCP payloads"
    );
}

#[test]
fn serialization_error_cbor_serialize_display_includes_inner_debug() {
    let inner: ciborium::ser::Error<std::io::Error> =
        ciborium::ser::Error::Value(String::from("inner-ser"));
    let err = SerializationError::CborSerialize(inner);
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("cbor serialization error: "),
        "CborSerialize Display prefix drifted: {rendered}"
    );
    assert!(
        rendered.contains("inner-ser"),
        "inner ser::Error message absent from Display: {rendered}"
    );
}

#[test]
fn serialization_error_cbor_deserialize_display_includes_inner_debug() {
    let inner: ciborium::de::Error<std::io::Error> = ciborium::de::Error::Syntax(7);
    let err = SerializationError::CborDeserialize(inner);
    let rendered = err.to_string();
    assert!(
        rendered.starts_with("cbor deserialization error: "),
        "CborDeserialize Display prefix drifted: {rendered}"
    );
    assert!(
        rendered.contains('7'),
        "inner de::Error offset absent from Display: {rendered}"
    );
}

#[test]
fn serialization_error_variant_count_is_eleven() {
    // Exhaustive match sentinel: adding a new SerializationError variant
    // forces this test to fail to compile, which forces the author to
    // also pin the new variant's Display string above. Counting eleven
    // arms here documents the variant cardinality.
    let probes: [SerializationError; 11] = [
        SerializationError::MissingSchemaHashPrefix,
        SerializationError::SchemaMismatch {
            expected: sample_hash(0),
            got: sample_hash(1),
        },
        SerializationError::PayloadTooLarge { len: 1, max: 1 },
        SerializationError::DepthExceeded { depth: 1, max: 1 },
        SerializationError::TrailingBytes,
        SerializationError::NonCanonicalEncoding,
        SerializationError::CborValue(ciborium::value::Error::Custom(String::new())),
        SerializationError::NonFiniteFloat,
        SerializationError::DuplicateMapKey {
            key_hex: String::new(),
        },
        SerializationError::UnsupportedTag { tag: 0 },
        SerializationError::CborSerialize(ciborium::ser::Error::Value(String::new())),
    ];
    for err in &probes {
        // Smoke: every probe Display-renders without panicking.
        let _ = err.to_string();

        // Exhaustive match — covers ALL twelve variants (11 probed above
        // plus CborDeserialize, which is exercised in its own test).
        match err {
            SerializationError::MissingSchemaHashPrefix
            | SerializationError::SchemaMismatch { .. }
            | SerializationError::PayloadTooLarge { .. }
            | SerializationError::DepthExceeded { .. }
            | SerializationError::TrailingBytes
            | SerializationError::NonCanonicalEncoding
            | SerializationError::CborValue(_)
            | SerializationError::NonFiniteFloat
            | SerializationError::DuplicateMapKey { .. }
            | SerializationError::UnsupportedTag { .. }
            | SerializationError::CborSerialize(_)
            | SerializationError::CborDeserialize(_) => (),
        }
    }
}
