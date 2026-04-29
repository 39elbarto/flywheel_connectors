//! Pin `BackpressureLevel` + `BackpressureSignal` serde tag and shape
//! (flywheel_connectors-yaan6).
//!
//! Bead asks for `BackpressureSignal Display formatting`. Neither
//! `BackpressureSignal` (ratelimit.rs:280) nor `BackpressureLevel`
//! (ratelimit.rs:37) implements `Display`, so the bead's "Display
//! formatting" ask has no direct analogue. Pinning targets the
//! serde wire form — which is what audit logs / dashboards filter
//! on — plus the struct shape with its `skip_serializing_if`
//! semantics on `retry_after_ms`.
//!
//! `BackpressureLevel` carries `#[serde(rename_all = "snake_case")]`
//! with 4 variants (Normal / Warning / SoftLimit / HardLimit).
//! `BackpressureSignal` is a 3-field struct with the level, an
//! `utilization_bps: u16` (0..=10_000 basis points), and an
//! optional `retry_after_ms`.
//!
//! Targets:
//!
//!   1. **`BackpressureLevel` per-variant JSON tag** (snake_case).
//!   2. **JSON + CBOR round-trip** preserves variant.
//!   3. **CBOR encodes as Text** (not integer discriminant) for
//!      cross-language consumers.
//!   4. **PascalCase + unknown rejected** — drift sentinel.
//!   5. **Multi-word variants use underscore** (soft_limit /
//!      hard_limit, not soft-limit / hardlimit).
//!   6. **4-variant count + pairwise distinctness**.
//!   7. **`BackpressureSignal` 3-field JSON shape** pinned.
//!   8. **`retry_after_ms` omitted when None** via
//!      `skip_serializing_if = "Option::is_none"`.
//!   9. **`BackpressureSignal` JSON + CBOR round-trip** preserves
//!      all 3 fields including nested `BackpressureLevel`.
//!  10. **Boundary `utilization_bps`** values (0 and 10_000) round-trip.
//!  11. **`retry_after_ms` boundary** (0 and u64::MAX) round-trip.

use ciborium::value::Value as CborValue;
use fcp_core::{BackpressureLevel, BackpressureSignal};

const ALL_LEVELS: &[(BackpressureLevel, &str)] = &[
    (BackpressureLevel::Normal, "normal"),
    (BackpressureLevel::Warning, "warning"),
    (BackpressureLevel::SoftLimit, "soft_limit"),
    (BackpressureLevel::HardLimit, "hard_limit"),
];

// ─────────────────────────────────────────────────────────────────────────────
// 1. BackpressureLevel per-variant JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_level_json_tag_pinned_per_variant() {
    for (variant, expected) in ALL_LEVELS {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "BACKPRESSURE REGRESSION: BackpressureLevel JSON tag drift on {variant:?} — \
             rate-limiter dashboards filter on this exact token"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_level_json_roundtrip_per_variant() {
    for (variant, _) in ALL_LEVELS {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: BackpressureLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back, "JSON round-trip lost {variant:?}");
    }
}

#[test]
fn backpressure_level_cbor_roundtrip_per_variant() {
    for (variant, _) in ALL_LEVELS {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: BackpressureLevel = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back, "CBOR round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CBOR encodes as Text not integer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_level_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in ALL_LEVELS {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => {
                panic!("BackpressureLevel MUST encode as CBOR Text({expected:?}); got {other:?}")
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_level_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Normal""#,
        r#""SoftLimit""#,
        r#""HardLimit""#,
        r#""throttled""#,  // wrong vocabulary
        r#""hard-limit""#, // kebab-case
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<BackpressureLevel>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case is canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Multi-word variants use underscore
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn soft_limit_uses_underscore_not_hyphen_or_smush() {
    let json = serde_json::to_string(&BackpressureLevel::SoftLimit).unwrap();
    assert_eq!(json, r#""soft_limit""#);
    assert!(!json.contains('-'), "snake_case MUST NOT use hyphens");
    assert_ne!(
        json, r#""softlimit""#,
        "MUST NOT smush words together — snake_case keeps the underscore"
    );
}

#[test]
fn hard_limit_uses_underscore_not_hyphen_or_smush() {
    let json = serde_json::to_string(&BackpressureLevel::HardLimit).unwrap();
    assert_eq!(json, r#""hard_limit""#);
    assert!(!json.contains('-'));
    assert_ne!(json, r#""hardlimit""#);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Variant count + pairwise distinctness
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_level_documented_count_is_four() {
    assert_eq!(
        ALL_LEVELS.len(),
        4,
        "BackpressureLevel has 4 documented variants — count drifted"
    );
}

#[test]
fn backpressure_level_variants_pairwise_unequal() {
    for i in 0..ALL_LEVELS.len() {
        for j in (i + 1)..ALL_LEVELS.len() {
            assert_ne!(
                ALL_LEVELS[i].0, ALL_LEVELS[j].0,
                "{:?} and {:?} MUST be distinct",
                ALL_LEVELS[i].0, ALL_LEVELS[j].0
            );
        }
    }
}

#[test]
fn backpressure_level_serde_forms_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in ALL_LEVELS {
        assert!(seen.insert(*label), "duplicate token {label:?}");
    }
    assert_eq!(seen.len(), ALL_LEVELS.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. BackpressureSignal 3-field JSON shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_signal_json_shape_pinned() {
    let signal = BackpressureSignal {
        level: BackpressureLevel::SoftLimit,
        utilization_bps: 7_500,
        retry_after_ms: Some(250),
    };
    let value = serde_json::to_value(&signal).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "level": "soft_limit",
            "utilization_bps": 7_500,
            "retry_after_ms": 250,
        }),
        "BackpressureSignal JSON shape drift — field names + nested level form"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. retry_after_ms omitted when None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn retry_after_ms_omitted_from_wire_form_when_none() {
    let signal = BackpressureSignal {
        level: BackpressureLevel::Normal,
        utilization_bps: 0,
        retry_after_ms: None,
    };
    let value = serde_json::to_value(&signal).expect("serialize");
    let obj = value
        .as_object()
        .expect("BackpressureSignal is JSON object");
    assert!(
        !obj.contains_key("retry_after_ms"),
        "retry_after_ms MUST be omitted when None — got {value}"
    );
    // Other fields still present.
    assert!(obj.contains_key("level"));
    assert!(obj.contains_key("utilization_bps"));
}

#[test]
fn retry_after_ms_present_in_wire_form_when_some() {
    let signal = BackpressureSignal {
        level: BackpressureLevel::Warning,
        utilization_bps: 5_000,
        retry_after_ms: Some(0),
    };
    let value = serde_json::to_value(&signal).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(
        obj.get("retry_after_ms").and_then(|v| v.as_u64()),
        Some(0),
        "retry_after_ms MUST appear as 0 when Some(0) — distinguishable from None"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. BackpressureSignal JSON + CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn backpressure_signal_json_roundtrip_preserves_all_fields() {
    let original = BackpressureSignal {
        level: BackpressureLevel::HardLimit,
        utilization_bps: 9_999,
        retry_after_ms: Some(1_000),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: BackpressureSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.level, original.level);
    assert_eq!(back.utilization_bps, original.utilization_bps);
    assert_eq!(back.retry_after_ms, original.retry_after_ms);
}

#[test]
fn backpressure_signal_cbor_roundtrip_preserves_all_fields() {
    let original = BackpressureSignal {
        level: BackpressureLevel::SoftLimit,
        utilization_bps: 8_000,
        retry_after_ms: Some(500),
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: BackpressureSignal = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.level, original.level);
    assert_eq!(back.utilization_bps, original.utilization_bps);
    assert_eq!(back.retry_after_ms, original.retry_after_ms);
}

#[test]
fn backpressure_signal_roundtrip_preserves_none_retry_after_ms() {
    let original = BackpressureSignal {
        level: BackpressureLevel::Normal,
        utilization_bps: 100,
        retry_after_ms: None,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: BackpressureSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.retry_after_ms, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Boundary utilization_bps values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn utilization_bps_zero_round_trips() {
    let signal = BackpressureSignal {
        level: BackpressureLevel::Normal,
        utilization_bps: 0,
        retry_after_ms: None,
    };
    let json = serde_json::to_string(&signal).unwrap();
    let back: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back.utilization_bps, 0);
}

#[test]
fn utilization_bps_documented_max_round_trips() {
    // utilization_bps is documented as 0..=10_000 (basis points, full range).
    let signal = BackpressureSignal {
        level: BackpressureLevel::HardLimit,
        utilization_bps: 10_000,
        retry_after_ms: Some(500),
    };
    let json = serde_json::to_string(&signal).unwrap();
    let back: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back.utilization_bps, 10_000);
}

#[test]
fn utilization_bps_u16_max_round_trips_by_serde_even_above_documented_range() {
    // Pin: serde does not enforce the documented 0..=10_000 cap;
    // any u16 round-trips. Drift in this contract (e.g., adding a
    // serde validator) would surface here.
    let signal = BackpressureSignal {
        level: BackpressureLevel::Warning,
        utilization_bps: u16::MAX,
        retry_after_ms: None,
    };
    let json = serde_json::to_string(&signal).unwrap();
    let back: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(
        back.utilization_bps,
        u16::MAX,
        "serde currently allows utilization_bps above the documented 10_000 cap; \
         pin so any future tightening is intentional"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. retry_after_ms boundary values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn retry_after_ms_zero_round_trips() {
    let signal = BackpressureSignal {
        level: BackpressureLevel::Warning,
        utilization_bps: 5_000,
        retry_after_ms: Some(0),
    };
    let json = serde_json::to_string(&signal).unwrap();
    let back: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back.retry_after_ms, Some(0));
}

#[test]
fn retry_after_ms_u64_max_round_trips() {
    let signal = BackpressureSignal {
        level: BackpressureLevel::HardLimit,
        utilization_bps: 10_000,
        retry_after_ms: Some(u64::MAX),
    };
    // JSON
    let json = serde_json::to_string(&signal).unwrap();
    let back_json: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back_json.retry_after_ms, Some(u64::MAX));

    // CBOR
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&signal, &mut buf).expect("CBOR encode");
    let back_cbor: BackpressureSignal =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(back_cbor.retry_after_ms, Some(u64::MAX));
}
