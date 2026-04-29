//! Pin `PostureRequirement` serde tag matrix — the closest analogue
//! to "ConnectorRequirement variant Display + serde tag"
//! (flywheel_connectors-jl6ne).
//!
//! Bead asks for `ConnectorRequirement variant Display + serde tag`.
//! No type literally named `ConnectorRequirement` exists in fcp-core.
//! The closest "requirement" classifier is `PostureRequirement`
//! (posture.rs:244) — a 7-variant internally-tagged enum with
//! `#[serde(tag = "type", rename_all = "snake_case")]`:
//!
//!  - `RequireTrue { attribute }`            → `require_true`
//!  - `RequireFalse { attribute }`           → `require_false`
//!  - `RequireEqual { attribute, value }`    → `require_equal`
//!  - `RequireOneOf { attribute, values }`   → `require_one_of`
//!  - `RequireMinVersion { attribute, min_version }` → `require_min_version`
//!  - `RequireMinValue { attribute, min_value }`     → `require_min_value`
//!  - `RequireMaxValue { attribute, max_value }`     → `require_max_value`
//!
//! Used in posture_tests.rs fixtures via the builder but NOT yet
//! pinned for serde tag matrix. Does NOT implement Display, so the
//! bead's "Display" ask has no analogue — pinning targets the serde
//! wire form and the `attribute()` accessor.
//!
//! Targets:
//!
//!   1. **Per-variant `type` tag** in JSON (snake_case for all 7).
//!   2. **JSON shape** per variant — internally-tagged with
//!      flattened struct payload.
//!   3. **JSON round-trip** preserves variant + nested fields.
//!   4. **CBOR `type` tag carried** for every variant via Value
//!      inspection (CBOR full round-trip on internally-tagged
//!      with binary fields hits the Content-shim quirk; use
//!      Value-inspection workaround).
//!   5. **`attribute()` accessor** returns the right key per variant.
//!   6. **PascalCase + unknown rejected**.
//!   7. **7-variant count + pairwise distinct serializations**.

use ciborium::value::Value as CborValue;
use fcp_core::{PostureAttributeKey, PostureRequirement};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Per-variant `type` tag in JSON
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn require_true_type_tag_pinned() {
    let req = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("require_true"));
    assert_eq!(
        value.get("attribute").and_then(|v| v.as_str()),
        Some("disk_encryption")
    );
}

#[test]
fn require_false_type_tag_pinned() {
    let req = PostureRequirement::RequireFalse {
        attribute: PostureAttributeKey::FirewallEnabled,
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("require_false"));
}

#[test]
fn require_equal_type_tag_with_value_pinned() {
    let req = PostureRequirement::RequireEqual {
        attribute: PostureAttributeKey::OsType,
        value: "macos".to_string(),
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("require_equal")
    );
    assert_eq!(
        value.get("attribute").and_then(|v| v.as_str()),
        Some("os_type")
    );
    assert_eq!(value.get("value").and_then(|v| v.as_str()), Some("macos"));
}

#[test]
fn require_one_of_type_tag_with_values_array_pinned() {
    let req = PostureRequirement::RequireOneOf {
        attribute: PostureAttributeKey::OsType,
        values: vec!["macos".to_string(), "linux".to_string()],
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("require_one_of")
    );
    let values = value
        .get("values")
        .and_then(|v| v.as_array())
        .expect("values array");
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].as_str(), Some("macos"));
    assert_eq!(values[1].as_str(), Some("linux"));
}

#[test]
fn require_min_version_type_tag_pinned() {
    let req = PostureRequirement::RequireMinVersion {
        attribute: PostureAttributeKey::OsVersion,
        min_version: "14.0.0".to_string(),
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("require_min_version")
    );
    assert_eq!(
        value.get("min_version").and_then(|v| v.as_str()),
        Some("14.0.0")
    );
}

#[test]
fn require_min_value_type_tag_pinned() {
    let req = PostureRequirement::RequireMinValue {
        attribute: PostureAttributeKey::ScreenLockTimeout,
        min_value: 300,
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("require_min_value")
    );
    assert_eq!(
        value.get("min_value").and_then(|v| v.as_i64()),
        Some(300)
    );
}

#[test]
fn require_max_value_type_tag_pinned() {
    let req = PostureRequirement::RequireMaxValue {
        attribute: PostureAttributeKey::ScreenLockTimeout,
        max_value: 600,
    };
    let value = serde_json::to_value(&req).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("require_max_value")
    );
    assert_eq!(
        value.get("max_value").and_then(|v| v.as_i64()),
        Some(600)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON round-trip preserves variant + nested fields
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_require_true() {
    let original = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: PostureRequirement = serde_json::from_str(&json).expect("deserialize");
    match back {
        PostureRequirement::RequireTrue { attribute } => {
            assert_eq!(attribute, PostureAttributeKey::DiskEncryption);
        }
        other => panic!("expected RequireTrue, got {other:?}"),
    }
}

#[test]
fn json_roundtrip_preserves_require_one_of_values_order() {
    let original = PostureRequirement::RequireOneOf {
        attribute: PostureAttributeKey::OsType,
        values: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: PostureRequirement = serde_json::from_str(&json).expect("deserialize");
    match back {
        PostureRequirement::RequireOneOf { attribute, values } => {
            assert_eq!(attribute, PostureAttributeKey::OsType);
            assert_eq!(values, vec!["a", "b", "c"]);
        }
        other => panic!("expected RequireOneOf, got {other:?}"),
    }
}

#[test]
fn json_roundtrip_preserves_min_value_with_negative_value() {
    let original = PostureRequirement::RequireMinValue {
        attribute: PostureAttributeKey::ScreenLockTimeout,
        min_value: -100,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: PostureRequirement = serde_json::from_str(&json).expect("deserialize");
    match back {
        PostureRequirement::RequireMinValue { min_value, .. } => assert_eq!(min_value, -100),
        other => panic!("expected RequireMinValue, got {other:?}"),
    }
}

#[test]
fn json_roundtrip_preserves_min_value_with_i64_max() {
    let original = PostureRequirement::RequireMinValue {
        attribute: PostureAttributeKey::ScreenLockTimeout,
        min_value: i64::MAX,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: PostureRequirement = serde_json::from_str(&json).expect("deserialize");
    match back {
        PostureRequirement::RequireMinValue { min_value, .. } => {
            assert_eq!(min_value, i64::MAX);
        }
        other => panic!("expected RequireMinValue, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CBOR `type` tag carried for every variant
// ─────────────────────────────────────────────────────────────────────────────

fn cbor_type_tag(req: &PostureRequirement) -> String {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(req, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("PostureRequirement MUST encode as Map, got {other:?}"),
    };
    let type_value = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "type" => Some(v),
            _ => None,
        })
        .expect("missing `type` discriminator");
    match type_value {
        CborValue::Text(s) => s.clone(),
        other => panic!("`type` MUST be Text, got {other:?}"),
    }
}

#[test]
fn cbor_type_tag_for_every_variant() {
    let cases = [
        (
            PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DiskEncryption,
            },
            "require_true",
        ),
        (
            PostureRequirement::RequireFalse {
                attribute: PostureAttributeKey::FirewallEnabled,
            },
            "require_false",
        ),
        (
            PostureRequirement::RequireEqual {
                attribute: PostureAttributeKey::OsType,
                value: "macos".to_string(),
            },
            "require_equal",
        ),
        (
            PostureRequirement::RequireOneOf {
                attribute: PostureAttributeKey::OsType,
                values: vec![],
            },
            "require_one_of",
        ),
        (
            PostureRequirement::RequireMinVersion {
                attribute: PostureAttributeKey::OsVersion,
                min_version: "1.0".to_string(),
            },
            "require_min_version",
        ),
        (
            PostureRequirement::RequireMinValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                min_value: 0,
            },
            "require_min_value",
        ),
        (
            PostureRequirement::RequireMaxValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                max_value: 0,
            },
            "require_max_value",
        ),
    ];
    for (variant, expected) in cases {
        assert_eq!(
            cbor_type_tag(&variant),
            expected,
            "CBOR type tag drift on {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. attribute() accessor returns the right key per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn attribute_accessor_returns_right_key_per_variant() {
    let cases = [
        (
            PostureRequirement::RequireTrue {
                attribute: PostureAttributeKey::DiskEncryption,
            },
            PostureAttributeKey::DiskEncryption,
        ),
        (
            PostureRequirement::RequireFalse {
                attribute: PostureAttributeKey::FirewallEnabled,
            },
            PostureAttributeKey::FirewallEnabled,
        ),
        (
            PostureRequirement::RequireEqual {
                attribute: PostureAttributeKey::OsType,
                value: "x".to_string(),
            },
            PostureAttributeKey::OsType,
        ),
        (
            PostureRequirement::RequireOneOf {
                attribute: PostureAttributeKey::OsVersion,
                values: vec![],
            },
            PostureAttributeKey::OsVersion,
        ),
        (
            PostureRequirement::RequireMinVersion {
                attribute: PostureAttributeKey::OsVersion,
                min_version: "1.0".to_string(),
            },
            PostureAttributeKey::OsVersion,
        ),
        (
            PostureRequirement::RequireMinValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                min_value: 0,
            },
            PostureAttributeKey::ScreenLockTimeout,
        ),
        (
            PostureRequirement::RequireMaxValue {
                attribute: PostureAttributeKey::ScreenLockTimeout,
                max_value: 0,
            },
            PostureAttributeKey::ScreenLockTimeout,
        ),
    ];
    for (req, expected) in cases {
        assert_eq!(
            req.attribute(),
            &expected,
            "attribute() drift on {req:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rejects_pascal_case_type_tag() {
    let bad = serde_json::json!({
        "type": "RequireTrue",
        "attribute": "disk_encryption"
    });
    let parsed = serde_json::from_value::<PostureRequirement>(bad);
    assert!(
        parsed.is_err(),
        "PascalCase `type` MUST be rejected — only snake_case is canonical"
    );
}

#[test]
fn rejects_unknown_type_tag() {
    let bad = serde_json::json!({
        "type": "require_anything",
        "attribute": "disk_encryption"
    });
    let parsed = serde_json::from_value::<PostureRequirement>(bad);
    assert!(parsed.is_err(), "unknown `type` MUST be rejected");
}

#[test]
fn rejects_camel_case_type_tag() {
    let bad = serde_json::json!({
        "type": "requireMinVersion",
        "attribute": "os_version",
        "min_version": "1.0"
    });
    let parsed = serde_json::from_value::<PostureRequirement>(bad);
    assert!(parsed.is_err(), "camelCase `type` MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. 7-variant count + pairwise distinct serializations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn seven_variants_produce_distinct_type_tags() {
    let tags = [
        cbor_type_tag(&PostureRequirement::RequireTrue {
            attribute: PostureAttributeKey::DiskEncryption,
        }),
        cbor_type_tag(&PostureRequirement::RequireFalse {
            attribute: PostureAttributeKey::DiskEncryption,
        }),
        cbor_type_tag(&PostureRequirement::RequireEqual {
            attribute: PostureAttributeKey::OsType,
            value: "x".to_string(),
        }),
        cbor_type_tag(&PostureRequirement::RequireOneOf {
            attribute: PostureAttributeKey::OsType,
            values: vec![],
        }),
        cbor_type_tag(&PostureRequirement::RequireMinVersion {
            attribute: PostureAttributeKey::OsVersion,
            min_version: "1.0".to_string(),
        }),
        cbor_type_tag(&PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 0,
        }),
        cbor_type_tag(&PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 0,
        }),
    ];
    let unique: std::collections::HashSet<&String> = tags.iter().collect();
    assert_eq!(unique.len(), 7, "all 7 type tags MUST be distinct");
    assert_eq!(
        tags,
        [
            "require_true".to_string(),
            "require_false".to_string(),
            "require_equal".to_string(),
            "require_one_of".to_string(),
            "require_min_version".to_string(),
            "require_min_value".to_string(),
            "require_max_value".to_string(),
        ],
        "PostureRequirement variant declaration order pinned"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Multi-word variants use underscore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn multi_word_type_tags_use_underscore_not_camel_case() {
    // Pin that the rename_all snake_case correctly splits multi-
    // word variant names: RequireMinVersion → require_min_version
    // (not requireMinVersion or require-min-version).
    let req = PostureRequirement::RequireMinVersion {
        attribute: PostureAttributeKey::OsVersion,
        min_version: "1.0".to_string(),
    };
    let value = serde_json::to_value(&req).expect("serialize");
    let tag = value
        .get("type")
        .and_then(|v| v.as_str())
        .expect("type field");
    assert_eq!(tag, "require_min_version");
    assert!(!tag.contains('-'));
    assert_ne!(tag, "requireMinVersion");
    assert_ne!(tag, "requireminversion");
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Distinct variants produce distinct serializations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn require_true_and_require_false_produce_distinct_json() {
    let t = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let f = PostureRequirement::RequireFalse {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    assert_ne!(
        serde_json::to_string(&t).unwrap(),
        serde_json::to_string(&f).unwrap()
    );
}

#[test]
fn distinct_attribute_produces_distinct_json() {
    let a = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::DiskEncryption,
    };
    let b = PostureRequirement::RequireTrue {
        attribute: PostureAttributeKey::FirewallEnabled,
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}
