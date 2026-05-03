//! Pin `ZoneId` 5-zone classifier matrix + `ZoneIdError` 8-variant Display
//! — the closest analogue to "ZoneClass variant Display"
//! (flywheel_connectors-y4lj9).
//!
//! Bead asks for `ZoneClass` Display + serde tag pinning. No type literally
//! named `ZoneClass` exists in fcp-core. The closest closed-taxonomy analogue
//! is [`ZoneId`] at `crates/fcp-core/src/capability.rs:386` with its 5
//! documented zone constants:
//!   * `OWNER` (`z:owner`) — highest trust,
//!   * `PRIVATE` (`z:private`) — personal data,
//!   * `WORK` (`z:work`) — project collaboration,
//!   * `COMMUNITY` (`z:community`) — public/semi-public,
//!   * `PUBLIC` (`z:public`) — internet-facing, untrusted.
//! These ARE the documented zone classes. ZoneIdError at
//! `crates/fcp-core/src/capability.rs:419` is the 8-variant rejection
//! enum that pins the boundary of the taxonomy.
//!
//! Existing coverage: zone_id_display.rs (Display roundtrip),
//! zone_id_equality_across_paths.rs (equality), zone_id_parse_error_matrix.rs
//! (variant selection during parsing). NOT covered: per-zone-constant
//! string pinning, ZoneId serde scalar-string shape, CBOR Text shape,
//! per-zone is_canonical/distinct sentinels, ZoneIdError per-variant
//! Display verbatim + distinct-Display sentinel.
//!
//! Coverage:
//!   * 5 zone constants pinned to exact `z:<class>` strings,
//!   * 5 constructor methods produce expected text + as_bytes / as_str
//!     consistency,
//!   * Pairwise distinctness across all 5 zones (Display + Hash + JSON),
//!   * JSON scalar string shape (transparent via serde(try_from/into)),
//!   * CBOR Text scalar shape,
//!   * Round-trip via Display+FromStr for every canonical zone,
//!   * 8-variant ZoneIdError Display verbatim with payload preservation,
//!   * Distinct-Display sentinel across all 8 ZoneIdError variants.

use ciborium::Value as CborValue;
use fcp_core::{ZoneId, ZoneIdError};
use serde_json::json;

const ALL_CANONICAL_ZONES: &[(&str, fn() -> ZoneId)] = &[
    ("z:owner", ZoneId::owner),
    ("z:private", ZoneId::private),
    ("z:work", ZoneId::work),
    ("z:community", ZoneId::community),
    ("z:public", ZoneId::public),
];

#[test]
fn zone_id_constants_pin_exact_canonical_strings() {
    assert_eq!(ZoneId::OWNER, "z:owner");
    assert_eq!(ZoneId::PRIVATE, "z:private");
    assert_eq!(ZoneId::WORK, "z:work");
    assert_eq!(ZoneId::COMMUNITY, "z:community");
    assert_eq!(ZoneId::PUBLIC, "z:public");
}

#[test]
fn each_canonical_zone_constructor_matches_constant() {
    assert_eq!(ZoneId::owner().as_str(), ZoneId::OWNER);
    assert_eq!(ZoneId::private().as_str(), ZoneId::PRIVATE);
    assert_eq!(ZoneId::work().as_str(), ZoneId::WORK);
    assert_eq!(ZoneId::community().as_str(), ZoneId::COMMUNITY);
    assert_eq!(ZoneId::public().as_str(), ZoneId::PUBLIC);
}

#[test]
fn as_bytes_matches_as_str_bytes_for_each_canonical_zone() {
    for &(text, ctor) in ALL_CANONICAL_ZONES {
        let z = ctor();
        assert_eq!(z.as_bytes(), text.as_bytes());
        assert_eq!(z.as_str(), text);
    }
}

#[test]
fn all_canonical_zones_are_pairwise_distinct() {
    let zones: Vec<ZoneId> = ALL_CANONICAL_ZONES
        .iter()
        .map(|&(_, ctor)| ctor())
        .collect();
    for i in 0..zones.len() {
        for j in 0..zones.len() {
            if i == j {
                assert_eq!(zones[i], zones[j]);
            } else {
                assert_ne!(zones[i], zones[j], "zones must differ at ({i}, {j})");
            }
        }
    }
}

#[test]
fn canonical_zones_hash_distinctly_via_hashmap_buckets() {
    let mut counts: std::collections::HashMap<ZoneId, u32> = std::collections::HashMap::new();
    for &(_, ctor) in ALL_CANONICAL_ZONES {
        *counts.entry(ctor()).or_insert(0) += 1;
    }
    // Each constructor inserts once; all 5 buckets exist with count == 1.
    assert_eq!(counts.len(), 5);
    for &(_, ctor) in ALL_CANONICAL_ZONES {
        assert_eq!(counts.get(&ctor()), Some(&1));
    }
}

#[test]
fn zone_id_serializes_as_scalar_string_per_zone() {
    // ZoneId carries #[serde(try_from = "String", into = "String")]; the JSON
    // form is a bare scalar string for every canonical zone.
    for &(text, ctor) in ALL_CANONICAL_ZONES {
        let z = ctor();
        let v = serde_json::to_value(&z).unwrap();
        assert_eq!(v, json!(text));

        let back: ZoneId = serde_json::from_value(v).unwrap();
        assert_eq!(back, z);
    }
}

#[test]
fn zone_id_json_decode_rejects_non_canonical_strings() {
    // try_from = "String" must propagate validate errors for malformed
    // zone strings.
    let cases = [
        json!(""),
        json!("owner"),    // missing z: prefix
        json!("Z:owner"),  // uppercase prefix
        json!("z:OWNER"),  // uppercase content
        json!("z:"),       // missing identifier
        json!("z::owner"), // empty segment
    ];
    for v in cases {
        let result: Result<ZoneId, _> = serde_json::from_value(v.clone());
        assert!(
            result.is_err(),
            "ZoneId must reject `{v:?}`, got {result:?}"
        );
    }
}

#[test]
fn zone_id_cbor_serializes_as_text_scalar_per_zone() {
    for &(text, ctor) in ALL_CANONICAL_ZONES {
        let z = ctor();
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&z, &mut bytes).unwrap();
        let value: CborValue = ciborium::de::from_reader(&bytes[..]).unwrap();
        match value {
            CborValue::Text(t) => assert_eq!(t, text),
            other => panic!("ZoneId must encode as CBOR Text, got {other:?}"),
        }

        let back: ZoneId = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, z);
    }
}

#[test]
fn display_and_from_str_form_a_fixed_point_for_canonical_zones() {
    for &(text, ctor) in ALL_CANONICAL_ZONES {
        let z = ctor();
        let s = z.to_string();
        let parsed: ZoneId = s.parse().unwrap();
        assert_eq!(parsed, z, "{text}: roundtrip drift");
        assert_eq!(s, text);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneIdError 8-variant Display matrix
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zone_id_error_empty_display() {
    let err = ZoneIdError::Empty;
    assert_eq!(err.to_string(), "zone id must not be empty");
}

#[test]
fn zone_id_error_empty_segment_display() {
    let err = ZoneIdError::EmptySegment { index: 2 };
    assert_eq!(
        err.to_string(),
        "zone id contains an empty segment at byte 2"
    );
}

#[test]
fn zone_id_error_too_long_display() {
    let err = ZoneIdError::TooLong { len: 200, max: 128 };
    assert_eq!(err.to_string(), "zone id too long (200 bytes > 128 bytes)");
}

#[test]
fn zone_id_error_non_ascii_display() {
    let err = ZoneIdError::NonAscii;
    assert_eq!(err.to_string(), "zone id must be ASCII");
}

#[test]
fn zone_id_error_missing_prefix_display() {
    let err = ZoneIdError::MissingPrefix;
    assert_eq!(err.to_string(), "zone id must start with `z:`");
}

#[test]
fn zone_id_error_invalid_tailscale_tag_prefix_display() {
    let err = ZoneIdError::InvalidTailscaleTagPrefix;
    assert_eq!(err.to_string(), "tailscale tag must start with `tag:fcp-`");
}

#[test]
fn zone_id_error_reserved_prefix_display() {
    let err = ZoneIdError::ReservedPrefix { prefix: "z:proj-" };
    assert_eq!(err.to_string(), "zone id prefix `z:proj-` is reserved");
}

#[test]
fn zone_id_error_invalid_char_display() {
    let err = ZoneIdError::InvalidChar { ch: '@', index: 5 };
    assert_eq!(
        err.to_string(),
        "zone id has invalid character '@' at byte 5"
    );
}

#[test]
fn all_eight_zone_id_error_variants_have_distinct_display() {
    let variants = [
        ZoneIdError::Empty,
        ZoneIdError::EmptySegment { index: 0 },
        ZoneIdError::TooLong { len: 1, max: 128 },
        ZoneIdError::NonAscii,
        ZoneIdError::MissingPrefix,
        ZoneIdError::InvalidTailscaleTagPrefix,
        ZoneIdError::ReservedPrefix { prefix: "z:x-" },
        ZoneIdError::InvalidChar { ch: '@', index: 0 },
    ];
    let strings: std::collections::HashSet<_> = variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "Display collision across ZoneIdError: {strings:?}"
    );
}

#[test]
fn zone_id_error_implements_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = ZoneIdError::Empty;
    assert_error(&err);
}

#[test]
fn distinct_canonical_zones_serialize_distinctly_in_json() {
    let mut seen = std::collections::HashSet::new();
    for &(_, ctor) in ALL_CANONICAL_ZONES {
        let v = serde_json::to_value(ctor()).unwrap();
        assert!(seen.insert(v.clone()), "duplicate JSON: {v:?}");
    }
}
