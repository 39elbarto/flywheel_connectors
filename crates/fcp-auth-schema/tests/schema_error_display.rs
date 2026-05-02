//! Pin the public Display surface for [`SchemaError`] (6 variants).
//!
//! `SchemaError` surfaces in capability-token verification chains every
//! time `AuthClaims` decode fails (CWT label parsing, integer-range
//! checks, timestamp reconstruction, schema-version drift). Those
//! diagnostics propagate into operator-visible audit-log entries on
//! every connector handshake. A `thiserror` format-string drift here
//! silently mutates that wire contract.
//!
//! Existing inline tests at `crates/fcp-auth-schema/src/claims.rs:545`
//! exercise variant *construction* but assert on `match` shape rather
//! than Display strings. This integration test pins each variant's
//! exact byte-for-byte rendering plus an exhaustive-match sentinel
//! that fails to compile on a new variant.
//!
//! Bead: flywheel_connectors-khjxv. Pin lineage: 5fztw (fcp-cbor
//! `SerializationError` + `SchemaIdError`), 8oak4 (fcp-crypto
//! `CryptoError` 23-variant matrix).

use fcp_auth_schema::SchemaError;

fn variant_display_matrix() -> Vec<(SchemaError, &'static str)> {
    vec![
        (
            SchemaError::Encode(String::from("io error")),
            "CBOR encode error: io error",
        ),
        (
            SchemaError::Decode(String::from("syntax")),
            "CBOR decode error: syntax",
        ),
        (
            SchemaError::UnexpectedType {
                label: 1,
                expected: "Text",
                got: "Integer",
            },
            "claim 1: expected Text, got Integer",
        ),
        (
            SchemaError::OutOfRange {
                label: 4,
                value: 1_000_000_i128,
                expected: "u16",
            },
            "claim 4: integer value 1000000 out of range for u16",
        ),
        (
            SchemaError::InvalidTimestamp {
                label: 6,
                value: i64::MIN,
            },
            "claim 6: invalid timestamp -9223372036854775808",
        ),
        (
            SchemaError::UnsupportedSchemaVersion {
                got: 99,
                expected: 1,
            },
            "schema_version 99 not accepted (expected 1)",
        ),
    ]
}

#[test]
fn schema_error_full_variant_matrix_pins_display_per_variant() {
    let matrix = variant_display_matrix();
    assert_eq!(
        matrix.len(),
        6,
        "SchemaError variant matrix length drift: expected 6, got {}",
        matrix.len()
    );
    for (variant, expected) in &matrix {
        assert_eq!(
            variant.to_string(),
            *expected,
            "Display drifted for variant {variant:?}"
        );
    }
}

#[test]
fn schema_error_exhaustive_match_sentinel() {
    // If a new SchemaError variant lands the compiler refuses to build
    // this match, forcing the author to also extend the matrix above.
    let sample = SchemaError::Decode(String::from("anything"));
    match sample {
        SchemaError::Encode(_)
        | SchemaError::Decode(_)
        | SchemaError::UnexpectedType { .. }
        | SchemaError::OutOfRange { .. }
        | SchemaError::InvalidTimestamp { .. }
        | SchemaError::UnsupportedSchemaVersion { .. } => (),
    }
}

#[test]
fn schema_error_out_of_range_renders_full_i128_value() {
    // OutOfRange carries `value: i128` precisely so the diagnostic can
    // surface CBOR integers wider than the destination type. Pin that
    // the full i128 — including negative values that wouldn't fit in
    // any of our destination types (u16/u64) — renders as decimal.
    let neg = SchemaError::OutOfRange {
        label: 4,
        value: -1_i128,
        expected: "u64",
    };
    assert_eq!(
        neg.to_string(),
        "claim 4: integer value -1 out of range for u64"
    );

    let big = SchemaError::OutOfRange {
        label: 4,
        value: i128::MAX,
        expected: "u64",
    };
    assert_eq!(
        big.to_string(),
        "claim 4: integer value 170141183460469231731687303715884105727 out of range for u64"
    );
}

#[test]
fn schema_error_unsupported_schema_version_renders_decimal_for_both_versions() {
    // schema_version is u16 — pin decimal rendering and that both
    // numerical fields appear in the documented {got, expected} order.
    for (got, expected, want) in [
        (0_u16, 1_u16, "schema_version 0 not accepted (expected 1)"),
        (1, 2, "schema_version 1 not accepted (expected 2)"),
        (
            u16::MAX,
            1,
            "schema_version 65535 not accepted (expected 1)",
        ),
    ] {
        let err = SchemaError::UnsupportedSchemaVersion { got, expected };
        assert_eq!(err.to_string(), want);
    }
}

#[test]
fn schema_error_unexpected_type_carries_static_str_type_names() {
    // The `expected` field is &'static str by design — type names are
    // string literals chosen at the call-site, not allocated. Pin that
    // assignment compiles only with &'static str.
    let err = SchemaError::UnexpectedType {
        label: 7,
        expected: "Bytes",
        got: "Map",
    };
    assert_eq!(err.to_string(), "claim 7: expected Bytes, got Map");
}
