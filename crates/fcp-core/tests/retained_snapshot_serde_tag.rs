//! Pin the externally-tagged serde shape on the closest analogue to
//! "RetainedSnapshot" (flywheel_connectors-x2yxk).
//!
//! Bead asks for "RetainedSnapshot serde tag". No type literally
//! named `RetainedSnapshot` exists in fcp-core. The retention surface
//! splits across two types:
//!
//!  - `EvictionPolicy` (object.rs:215, also re-exported as
//!    `RetentionClass` at object.rs:216) — the 3-variant tagged enum
//!    that decides retention for stored objects (Pinned / Lease /
//!    Ephemeral). It is the "tag" the bead points at: an
//!    externally-tagged serde enum carrying the retention class.
//!  - `ConnectorStateSnapshot` (connector_state.rs:477) — the actual
//!    "snapshot" type for state compaction. (Already covered by
//!    `connector_state_golden_vectors.rs`.)
//!
//! Existing `eviction_policy_display.rs` pins Display + equality but
//! NOT the on-the-wire serde tag — this test pins the gap:
//!
//!   1. **Externally-tagged JSON form per variant** — no
//!      `#[serde(rename_all = ...)]`, no `#[serde(tag = ...)]`, so
//!      serde uses the default externally-tagged encoding:
//!        - `Pinned` → `"Pinned"` (bare string for unit)
//!        - `Lease { expires_at }` → `{"Lease":{"expires_at":<u64>}}`
//!        - `Ephemeral` → `"Ephemeral"`
//!   2. **JSON round-trip** preserves variant + nested fields.
//!   3. **CBOR round-trip** preserves variant + nested fields.
//!   4. **CBOR encoding shape per variant** — unit variants as
//!      Text, struct variant as Map (the only-key form).
//!   5. **Lease payload survives `expires_at` boundary values**
//!      (0, u64::MAX).
//!   6. **`RetentionClass` alias agrees byte-for-byte** with
//!      `EvictionPolicy`.
//!   7. **Wrapped in `StorageMeta`** the externally-tagged form
//!      lives inside the `retention` field — pin that nested shape.
//!   8. **PascalCase is canonical, snake_case rejected** — drift
//!      sentinel for any future `rename_all` swap.

use ciborium::value::Value as CborValue;
use fcp_core::{EvictionPolicy, RetentionClass, StorageMeta};

const LEASE_EXPIRES_AT: u64 = 1_700_000_000;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Externally-tagged JSON form per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pinned_serializes_as_bare_string() {
    let json = serde_json::to_value(&EvictionPolicy::Pinned).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!("Pinned"),
        "Pinned MUST encode as the bare quoted PascalCase string in externally-tagged form"
    );
}

#[test]
fn ephemeral_serializes_as_bare_string() {
    let json = serde_json::to_value(&EvictionPolicy::Ephemeral).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!("Ephemeral"),
        "Ephemeral MUST encode as the bare quoted PascalCase string"
    );
}

#[test]
fn lease_serializes_as_externally_tagged_object_with_expires_at() {
    let json = serde_json::to_value(&EvictionPolicy::Lease {
        expires_at: LEASE_EXPIRES_AT,
    })
    .expect("serialize");
    assert_eq!(
        json,
        serde_json::json!({"Lease": {"expires_at": LEASE_EXPIRES_AT}}),
        "Lease MUST encode externally-tagged: a single-key object \
         keyed on the variant name with the struct payload as value"
    );
}

#[test]
fn pinned_and_ephemeral_serialize_to_distinct_strings() {
    // Both unit variants — pin that they are distinguishable on the
    // wire (no accidental collapsing to the same token).
    assert_ne!(
        serde_json::to_string(&EvictionPolicy::Pinned).unwrap(),
        serde_json::to_string(&EvictionPolicy::Ephemeral).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_pinned() {
    let original = EvictionPolicy::Pinned;
    let json = serde_json::to_string(&original).expect("serialize");
    let back: EvictionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
}

#[test]
fn json_roundtrip_preserves_ephemeral() {
    let original = EvictionPolicy::Ephemeral;
    let json = serde_json::to_string(&original).expect("serialize");
    let back: EvictionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
}

#[test]
fn json_roundtrip_preserves_lease_payload() {
    let original = EvictionPolicy::Lease {
        expires_at: LEASE_EXPIRES_AT,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: EvictionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
    if let EvictionPolicy::Lease { expires_at } = back {
        assert_eq!(expires_at, LEASE_EXPIRES_AT);
    } else {
        panic!("expected Lease variant after round-trip");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_every_variant() {
    let cases = [
        EvictionPolicy::Pinned,
        EvictionPolicy::Lease {
            expires_at: LEASE_EXPIRES_AT,
        },
        EvictionPolicy::Ephemeral,
    ];
    for variant in cases {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: EvictionPolicy = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(variant, back, "CBOR round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CBOR encoding shape per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_unit_variants_encode_as_text_strings() {
    for (variant, expected_text) in [
        (EvictionPolicy::Pinned, "Pinned"),
        (EvictionPolicy::Ephemeral, "Ephemeral"),
    ] {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(
                s, expected_text,
                "CBOR Text mismatch for {variant:?}"
            ),
            other => panic!("{variant:?} MUST encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn cbor_lease_variant_encodes_as_single_key_map() {
    let original = EvictionPolicy::Lease {
        expires_at: LEASE_EXPIRES_AT,
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("Lease MUST encode as CBOR Map (externally tagged), got {other:?}"),
    };
    assert_eq!(map.len(), 1, "externally-tagged form is a single-key map");
    let (key, payload) = &map[0];
    match key {
        CborValue::Text(s) => assert_eq!(s, "Lease", "outer key MUST be variant name"),
        other => panic!("outer key MUST be Text, got {other:?}"),
    }
    let inner_map = match payload {
        CborValue::Map(m) => m,
        other => panic!("Lease payload MUST be Map, got {other:?}"),
    };
    let expires_at_value = inner_map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "expires_at" => Some(v),
            _ => None,
        })
        .expect("expires_at key");
    match expires_at_value {
        CborValue::Integer(n) => {
            // ciborium::value::Integer round-trip back to u64.
            let n_u64: u64 = (*n).try_into().expect("expires_at fits in u64");
            assert_eq!(n_u64, LEASE_EXPIRES_AT);
        }
        other => panic!("expires_at MUST be Integer, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Lease boundary values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn lease_expires_at_zero_round_trips() {
    let original = EvictionPolicy::Lease { expires_at: 0 };
    let json = serde_json::to_string(&original).unwrap();
    let back: EvictionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(original, back);
}

#[test]
fn lease_expires_at_u64_max_round_trips() {
    let original = EvictionPolicy::Lease {
        expires_at: u64::MAX,
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: EvictionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(original, back);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("CBOR encode");
    let from_cbor: EvictionPolicy =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(original, from_cbor);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. RetentionClass alias agrees byte-for-byte
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn retention_class_alias_serializes_identically_to_eviction_policy() {
    // RetentionClass is `pub type RetentionClass = EvictionPolicy;`
    // — a type alias, NOT a newtype. Serialized bytes MUST match
    // exactly across the two names.
    let cases = [
        EvictionPolicy::Pinned,
        EvictionPolicy::Lease { expires_at: 42 },
        EvictionPolicy::Ephemeral,
    ];
    for variant in cases {
        let as_eviction = serde_json::to_string(&variant).unwrap();
        let as_retention: RetentionClass = variant;
        let from_alias = serde_json::to_string(&as_retention).unwrap();
        assert_eq!(
            as_eviction, from_alias,
            "RetentionClass alias MUST match EvictionPolicy bytes for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. StorageMeta wrapping
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn storage_meta_carries_retention_in_externally_tagged_form() {
    // StorageMeta { retention: RetentionClass } — pin that the
    // wrapped form preserves the externally-tagged shape inside the
    // `retention` field.
    let meta = StorageMeta {
        retention: RetentionClass::Lease {
            expires_at: LEASE_EXPIRES_AT,
        },
    };
    let value = serde_json::to_value(&meta).expect("serialize");
    assert_eq!(
        value,
        serde_json::json!({
            "retention": {"Lease": {"expires_at": LEASE_EXPIRES_AT}}
        }),
        "StorageMeta wraps the externally-tagged retention shape verbatim"
    );

    // Round-trip the StorageMeta wrapper.
    let json = serde_json::to_string(&meta).unwrap();
    let back: StorageMeta = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.retention, meta.retention);
}

#[test]
fn storage_meta_with_pinned_retention_uses_bare_string() {
    let meta = StorageMeta {
        retention: RetentionClass::Pinned,
    };
    let value = serde_json::to_value(&meta).expect("serialize");
    assert_eq!(value, serde_json::json!({"retention": "Pinned"}));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. PascalCase canonical / snake_case rejected (rename_all sentinel)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn snake_case_token_is_rejected_for_unit_variants() {
    // The enum has NO `#[serde(rename_all = ...)]` — PascalCase is
    // canonical. snake_case MUST be rejected so any future
    // rename_all swap is loudly surfaced (would silently rebrand
    // every `Pinned` to `pinned` on the wire).
    for bad in [r#""pinned""#, r#""ephemeral""#, r#""lease""#] {
        let parsed = serde_json::from_str::<EvictionPolicy>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — PascalCase is canonical"
        );
    }
}

#[test]
fn unknown_variant_string_is_rejected() {
    for bad in [r#""Retained""#, r#""Snapshot""#, r#""Unknown""#] {
        let parsed = serde_json::from_str::<EvictionPolicy>(bad);
        assert!(parsed.is_err(), "{bad} MUST be rejected — unknown variant");
    }
}

#[test]
fn snake_case_lease_outer_key_is_rejected() {
    let bad = r#"{"lease":{"expires_at":123}}"#;
    let parsed = serde_json::from_str::<EvictionPolicy>(bad);
    assert!(
        parsed.is_err(),
        "snake_case outer key MUST be rejected — only PascalCase `Lease` is canonical"
    );
}
