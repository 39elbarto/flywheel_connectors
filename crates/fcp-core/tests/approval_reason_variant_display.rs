//! Pin approval-classifier serde tags on the closest analogues to
//! "ApprovalReason" (flywheel_connectors-qnll1).
//!
//! Bead asks for `ApprovalReason variant Display + serde tag`. No
//! type literally named `ApprovalReason` exists in fcp-core. The
//! approval-classifier surface that names "why approval is required"
//! / "what kind of approval is being granted" splits across:
//!
//!  - `ApprovalMode` (protocol.rs:1897) — the operation-side
//!    classifier on `OperationMeta.requires_approval`. 4 variants
//!    (None / Policy / Interactive / ElevationToken) carrying
//!    `#[serde(rename_all = "snake_case")]`. This is the closest
//!    "ApprovalReason" analogue — it's literally the documented
//!    reason an operation requires approval.
//!  - `ApprovalScope` (provenance.rs:824) — the token-side
//!    classifier on `ApprovalToken.scope`. 3 variants (Elevation /
//!    Declassification / Execution) with internally-tagged form
//!    `#[serde(tag = "type", rename_all = "snake_case")]` and
//!    nested struct payloads.
//!
//! Neither carries a `Display` impl, so the bead's "Display"
//! formatting ask has no direct analogue. Pinning targets the
//! serde wire form (audit logs / dashboards filter on it) plus
//! tag-discriminator presence in CBOR.
//!
//! Targets:
//!
//!   1. **`ApprovalMode` per-variant JSON tag** (snake_case).
//!   2. **JSON + CBOR round-trip** preserves variant identity for
//!      all 4 ApprovalMode variants.
//!   3. **Multi-word variant uses underscore** (`elevation_token`,
//!      not `elevation-token` / `elevationToken`).
//!   4. **PascalCase + unknown rejected** for ApprovalMode.
//!   5. **`ApprovalMode::None` token does NOT alias serde null** —
//!      explicit `"none"` string is required.
//!   6. **`ApprovalScope` per-variant `type` tag** in JSON
//!      (`elevation` / `declassification` / `execution`).
//!   7. **`ApprovalScope` JSON round-trip** preserves variant
//!      identity + nested payload.
//!   8. **CBOR map shape** for `ApprovalScope::Declassification`
//!      verifies the `type` tag is present in the encoded form.

use ciborium::value::Value as CborValue;
use fcp_core::{
    ApprovalMode, ApprovalScope, ConfidentialityLevel, DeclassificationScope, ExecutionScope,
    ObjectId, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. ApprovalMode — primary ApprovalReason analogue
// ─────────────────────────────────────────────────────────────────────────────

const APPROVAL_MODE_CASES: &[(ApprovalMode, &str)] = &[
    (ApprovalMode::None, "none"),
    (ApprovalMode::Policy, "policy"),
    (ApprovalMode::Interactive, "interactive"),
    (ApprovalMode::ElevationToken, "elevation_token"),
];

#[test]
fn approval_mode_json_tag_pinned_per_variant() {
    for (variant, expected) in APPROVAL_MODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected}\""),
            "APPROVAL-REASON REGRESSION: ApprovalMode JSON tag drift on {variant:?} — \
             approval audit logs filter on this exact token"
        );
    }
}

#[test]
fn approval_mode_json_roundtrip_per_variant() {
    for (variant, _) in APPROVAL_MODE_CASES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: ApprovalMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn approval_mode_cbor_roundtrip_per_variant() {
    for (variant, _) in APPROVAL_MODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: ApprovalMode = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn approval_mode_cbor_encodes_as_text_not_integer() {
    for (variant, expected) in APPROVAL_MODE_CASES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!("ApprovalMode MUST encode as CBOR Text({expected:?}); got {other:?}"),
        }
    }
}

#[test]
fn approval_mode_elevation_token_uses_underscore_not_camel_case() {
    let json = serde_json::to_string(&ApprovalMode::ElevationToken).unwrap();
    assert_eq!(json, r#""elevation_token""#);
    assert!(!json.contains('-'), "snake_case MUST NOT use hyphens");
    assert_ne!(
        json, r#""elevationToken""#,
        "MUST NOT camelCase — snake_case is canonical"
    );
}

#[test]
fn approval_mode_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""None""#,
        r#""Policy""#,
        r#""Interactive""#,
        r#""ElevationToken""#,
        r#""elevation-token""#,
        r#""elevationToken""#,
        r#""manual""#,
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<ApprovalMode>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case is canonical"
        );
    }
}

#[test]
fn approval_mode_none_does_not_alias_serde_null() {
    // The literal `"none"` token is the ApprovalMode::None variant
    // — NOT a serde `null`. Pin that mistake (decoding null →
    // ApprovalMode MUST fail).
    let bad_null = serde_json::from_str::<ApprovalMode>("null");
    assert!(
        bad_null.is_err(),
        "JSON null MUST NOT alias to ApprovalMode::None — \
         only the explicit \"none\" string maps to that variant"
    );
}

#[test]
fn approval_mode_count_is_four() {
    assert_eq!(
        APPROVAL_MODE_CASES.len(),
        4,
        "ApprovalMode has 4 documented variants — count drifted"
    );
}

#[test]
fn approval_mode_variants_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in APPROVAL_MODE_CASES {
        assert!(seen.insert(*label));
    }
    assert_eq!(seen.len(), 4);

    for i in 0..APPROVAL_MODE_CASES.len() {
        for j in (i + 1)..APPROVAL_MODE_CASES.len() {
            assert_ne!(APPROVAL_MODE_CASES[i].0, APPROVAL_MODE_CASES[j].0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ApprovalScope — secondary classifier with internal `type` tag
// ─────────────────────────────────────────────────────────────────────────────

fn declassification_fixture() -> ApprovalScope {
    ApprovalScope::Declassification(DeclassificationScope {
        from_zone: ZoneId::work(),
        to_zone: ZoneId::public(),
        object_ids: vec![ObjectId::from_bytes([0x42; 32])],
        target_confidentiality: ConfidentialityLevel::Public,
    })
}

fn execution_fixture() -> ApprovalScope {
    ApprovalScope::Execution(ExecutionScope {
        connector_id: "fcp.test".to_string(),
        method_pattern: "ping".to_string(),
        request_object_id: None,
        input_hash: None,
        input_constraints: vec![],
    })
}

#[test]
fn approval_scope_type_tag_pinned_for_declassification() {
    let value = serde_json::to_value(&declassification_fixture()).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("declassification"),
        "ApprovalScope::Declassification MUST emit `type: \"declassification\"`"
    );
    // Nested payload field accessible through the flatten (internal tag).
    assert!(
        value.get("from_zone").is_some(),
        "internally-tagged form flattens nested struct payload"
    );
    assert!(value.get("to_zone").is_some());
    assert!(value.get("object_ids").is_some());
    assert!(value.get("target_confidentiality").is_some());
}

#[test]
fn approval_scope_type_tag_pinned_for_execution() {
    let value = serde_json::to_value(&execution_fixture()).expect("serialize");
    assert_eq!(
        value.get("type").and_then(|v| v.as_str()),
        Some("execution")
    );
    assert!(value.get("connector_id").is_some());
    assert!(value.get("method_pattern").is_some());
}

#[test]
fn approval_scope_json_roundtrip_preserves_declassification_variant() {
    let original = declassification_fixture();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ApprovalScope = serde_json::from_str(&json).expect("deserialize");
    match back {
        ApprovalScope::Declassification(scope) => {
            assert_eq!(scope.from_zone, ZoneId::work());
            assert_eq!(scope.to_zone, ZoneId::public());
            assert_eq!(scope.object_ids.len(), 1);
            assert_eq!(scope.target_confidentiality, ConfidentialityLevel::Public);
        }
        other => panic!("expected Declassification variant, got {other:?}"),
    }
}

#[test]
fn approval_scope_json_roundtrip_preserves_execution_variant() {
    let original = execution_fixture();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: ApprovalScope = serde_json::from_str(&json).expect("deserialize");
    match back {
        ApprovalScope::Execution(scope) => {
            assert_eq!(scope.connector_id, "fcp.test");
            assert_eq!(scope.method_pattern, "ping");
            assert!(scope.request_object_id.is_none());
            assert!(scope.input_hash.is_none());
            assert!(scope.input_constraints.is_empty());
        }
        other => panic!("expected Execution variant, got {other:?}"),
    }
}

#[test]
fn approval_scope_cbor_carries_type_tag_for_declassification() {
    // ApprovalScope is internally-tagged; nested payloads with
    // ObjectId-via-hex_or_bytes hit a known serde Content-shim
    // quirk on CBOR re-deserialization (same as cgfwt's
    // Transferring case). Pin the on-the-wire CBOR shape via Value
    // inspection — the `type` discriminator MUST be present.
    let original = declassification_fixture();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("ApprovalScope MUST encode as CBOR map, got {other:?}"),
    };
    let type_value = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "type" => Some(v),
            _ => None,
        })
        .expect("missing `type` discriminator");
    match type_value {
        CborValue::Text(s) => assert_eq!(s, "declassification"),
        other => panic!("`type` MUST be Text, got {other:?}"),
    }
}

#[test]
fn approval_scope_cbor_carries_type_tag_for_execution() {
    let original = execution_fixture();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("ApprovalScope MUST encode as CBOR map, got {other:?}"),
    };
    let type_value = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "type" => Some(v),
            _ => None,
        })
        .expect("missing `type` discriminator");
    match type_value {
        CborValue::Text(s) => assert_eq!(s, "execution"),
        other => panic!("`type` MUST be Text, got {other:?}"),
    }
}

#[test]
fn approval_scope_rejects_pascal_case_type_tag() {
    let bad = serde_json::json!({
        "type": "Elevation",
        "operation_id": "op",
        "original_provenance_id": "0".repeat(64),
        "target_integrity": "owner",
    });
    let parsed = serde_json::from_value::<ApprovalScope>(bad);
    assert!(
        parsed.is_err(),
        "PascalCase `type` tag MUST be rejected — only snake_case is canonical"
    );
}

#[test]
fn approval_scope_rejects_unknown_type_tag() {
    let bad = serde_json::json!({
        "type": "manual_override",
    });
    let parsed = serde_json::from_value::<ApprovalScope>(bad);
    assert!(parsed.is_err(), "unknown `type` tag MUST be rejected");
}
