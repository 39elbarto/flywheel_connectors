//! Pin `RevocationCheckResult` as the closest analogue to a
//! "RegistryQuery" serde JSON+CBOR round-trip
//! (flywheel_connectors-8gfcv).
//!
//! Bead asks for `RegistryQuery serde JSON+CBOR roundtrip`. No type
//! literally named `RegistryQuery` exists in fcp-core. The closest
//! "query/lookup result" type with serde derives is
//! `RevocationCheckResult` (revocation.rs:409) — the result of
//! looking up an `ObjectId` against the revocation registry. It
//! carries 5 fields (3 scalar + 2 Option<> with
//! `skip_serializing_if = "Option::is_none"`) and a nested
//! `RevocationScope` enum that itself carries snake_case Display
//! tokens.
//!
//! `RegistryEntry` (the other "registry-shaped" type at
//! connector_artifacts.rs:249) is already pinned by
//! `connector_bundle_serde_extended.rs` (huv65) — this test focuses
//! on the lookup-result surface that's still a gap.
//!
//! Targets:
//!
//!   1. **`RevocationCheckResult` JSON shape** when the object IS
//!      revoked (all fields populated).
//!   2. **JSON shape when the object is NOT revoked** — Optional
//!      fields omitted via `skip_serializing_if`, scalar fields
//!      always present.
//!   3. **JSON round-trip** preserves every field including Some/None
//!      states for both Optional fields.
//!   4. **CBOR round-trip** preserves every field.
//!   5. **`RevocationScope` per-variant snake_case Display** —
//!      tokens used inside the query result for filtering.
//!   6. **`RevocationScope` JSON form is PascalCase variant name
//!      verbatim** (no rename_all on this enum) — pin the same kind
//!      of dual-encoding sentinel used for RiskTier.
//!   7. **Distinct check results produce distinct serializations**
//!      (the result's wire identity reflects every field).
//!   8. **`RevocationScope` JSON + CBOR round-trip** for every
//!      variant.

use ciborium::value::Value as CborValue;
use fcp_core::{ObjectId, RevocationCheckResult, RevocationScope};

const ALL_SCOPES_DISPLAY: &[(RevocationScope, &str)] = &[
    (RevocationScope::Capability, "capability"),
    (RevocationScope::IssuerKey, "issuer_key"),
    (RevocationScope::NodeAttestation, "node_attestation"),
    (RevocationScope::ZoneKey, "zone_key"),
    (RevocationScope::ConnectorBinary, "connector_binary"),
];

const ALL_SCOPES_SERDE: &[(RevocationScope, &str)] = &[
    (RevocationScope::Capability, "Capability"),
    (RevocationScope::IssuerKey, "IssuerKey"),
    (RevocationScope::NodeAttestation, "NodeAttestation"),
    (RevocationScope::ZoneKey, "ZoneKey"),
    (RevocationScope::ConnectorBinary, "ConnectorBinary"),
];

fn revoked_result() -> RevocationCheckResult {
    RevocationCheckResult {
        is_revoked: true,
        revocation: Some(ObjectId::from_bytes([0x42; 32])),
        scope: Some(RevocationScope::Capability),
        stale_data: false,
        head_age_secs: 60,
    }
}

fn not_revoked_result() -> RevocationCheckResult {
    RevocationCheckResult {
        is_revoked: false,
        revocation: None,
        scope: None,
        stale_data: false,
        head_age_secs: 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. JSON shape — revoked case (all fields populated)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_check_result_json_shape_pinned_for_revoked_case() {
    let result = revoked_result();
    let value = serde_json::to_value(&result).expect("serialize");
    let obj = value.as_object().expect("object");

    assert_eq!(obj.get("is_revoked").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(obj.get("stale_data").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(obj.get("head_age_secs").and_then(|v| v.as_u64()), Some(60));
    assert!(
        obj.contains_key("revocation"),
        "Some(revocation) MUST be present"
    );
    assert!(obj.contains_key("scope"), "Some(scope) MUST be present");
    assert_eq!(
        obj.get("scope").and_then(|v| v.as_str()),
        Some("Capability"),
        "RevocationScope serialized as PascalCase variant name verbatim"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. JSON shape — not-revoked case (Optional fields omitted)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_check_result_json_shape_pinned_for_not_revoked_case() {
    let result = not_revoked_result();
    let value = serde_json::to_value(&result).expect("serialize");
    let obj = value.as_object().expect("object");

    // Scalar fields always present.
    assert_eq!(obj.get("is_revoked").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(obj.get("stale_data").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(obj.get("head_age_secs").and_then(|v| v.as_u64()), Some(0));

    // Optional fields omitted via skip_serializing_if.
    assert!(
        !obj.contains_key("revocation"),
        "revocation MUST be omitted when None — got {value}"
    );
    assert!(
        !obj.contains_key("scope"),
        "scope MUST be omitted when None — got {value}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. JSON round-trip preserves every field
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_check_result_json_roundtrip_preserves_revoked_case() {
    let original = revoked_result();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: RevocationCheckResult = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.is_revoked, original.is_revoked);
    assert_eq!(back.revocation, original.revocation);
    assert_eq!(back.scope, original.scope);
    assert_eq!(back.stale_data, original.stale_data);
    assert_eq!(back.head_age_secs, original.head_age_secs);
}

#[test]
fn revocation_check_result_json_roundtrip_preserves_not_revoked_case() {
    let original = not_revoked_result();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: RevocationCheckResult = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.is_revoked, false);
    assert_eq!(back.revocation, None);
    assert_eq!(back.scope, None);
    assert_eq!(back.stale_data, false);
    assert_eq!(back.head_age_secs, 0);
}

#[test]
fn revocation_check_result_json_roundtrip_preserves_stale_data_flag() {
    // Pin: stale_data is independent of is_revoked — pin the
    // matrix combination where the registry replied stale even
    // though the object IS revoked.
    let original = RevocationCheckResult {
        is_revoked: true,
        revocation: Some(ObjectId::from_bytes([0x99; 32])),
        scope: Some(RevocationScope::ConnectorBinary),
        stale_data: true,
        head_age_secs: u64::MAX,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: RevocationCheckResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.is_revoked, true);
    assert_eq!(back.stale_data, true);
    assert_eq!(back.head_age_secs, u64::MAX);
    assert_eq!(back.scope, Some(RevocationScope::ConnectorBinary));
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CBOR round-trip preserves every field
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_check_result_cbor_roundtrip_preserves_revoked_case() {
    let original = revoked_result();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: RevocationCheckResult = ciborium::de::from_reader(buf.as_slice()).expect("decode");

    assert_eq!(back.is_revoked, original.is_revoked);
    assert_eq!(back.revocation, original.revocation);
    assert_eq!(back.scope, original.scope);
    assert_eq!(back.stale_data, original.stale_data);
    assert_eq!(back.head_age_secs, original.head_age_secs);
}

#[test]
fn revocation_check_result_cbor_roundtrip_preserves_not_revoked_case() {
    let original = not_revoked_result();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: RevocationCheckResult = ciborium::de::from_reader(buf.as_slice()).expect("decode");

    assert_eq!(back.is_revoked, false);
    assert_eq!(back.revocation, None);
    assert_eq!(back.scope, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. RevocationScope per-variant snake_case Display
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_scope_display_token_pinned_per_variant() {
    for (variant, expected) in ALL_SCOPES_DISPLAY {
        assert_eq!(
            variant.to_string(),
            *expected,
            "RevocationScope::Display drift on {variant:?}"
        );
        assert_eq!(variant.as_str(), *expected, "as_str agrees");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. RevocationScope JSON form is PascalCase (different from Display)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_scope_serde_json_form_is_pascal_case() {
    // RevocationScope has NO #[serde(rename_all = ...)] — the wire
    // form is PascalCase variant name verbatim, DIFFERENT from
    // Display/as_str (snake_case). Same dual-encoding pattern as
    // RiskTier (mesh_node_role_serde_tag.rs) — pin loud so any
    // future rename_all swap is caught.
    for (variant, expected_pascal) in ALL_SCOPES_SERDE {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(
            json,
            format!("\"{expected_pascal}\""),
            "RevocationScope JSON form drift on {variant:?} — \
             current contract is PascalCase verbatim, NOT the snake_case Display"
        );
    }
}

#[test]
fn revocation_scope_display_and_serde_disagree_on_multi_word_variants() {
    // For multi-word variants the {snake_case Display, PascalCase
    // serde} encodings produce different tokens. Pin the
    // disagreement loudly.
    let display_issuer = RevocationScope::IssuerKey.to_string();
    let serde_issuer = serde_json::to_string(&RevocationScope::IssuerKey).unwrap();
    assert_eq!(display_issuer, "issuer_key");
    assert_eq!(serde_issuer, r#""IssuerKey""#);
    assert_ne!(
        display_issuer,
        serde_issuer.trim_matches('"'),
        "Display and serde MUST disagree on IssuerKey — drift sentinel"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Distinct check results produce distinct serializations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_check_results_produce_distinct_json() {
    let a = revoked_result();
    let mut b = revoked_result();
    b.scope = Some(RevocationScope::ZoneKey);
    let json_a = serde_json::to_string(&a).unwrap();
    let json_b = serde_json::to_string(&b).unwrap();
    assert_ne!(
        json_a, json_b,
        "different scope MUST produce different JSON bytes"
    );

    let mut c = revoked_result();
    c.head_age_secs = 999;
    let json_c = serde_json::to_string(&c).unwrap();
    assert_ne!(json_a, json_c);
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. RevocationScope JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn revocation_scope_json_roundtrip_preserves_every_variant() {
    for (variant, _) in ALL_SCOPES_SERDE {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: RevocationScope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn revocation_scope_cbor_roundtrip_preserves_every_variant() {
    for (variant, _) in ALL_SCOPES_SERDE {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: RevocationScope = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back);
    }
}

#[test]
fn revocation_scope_cbor_encodes_as_text_pascal_case() {
    for (variant, expected) in ALL_SCOPES_SERDE {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!("RevocationScope MUST encode as Text({expected:?}); got {other:?}"),
        }
    }
}

#[test]
fn revocation_scope_rejects_lower_snake_case_for_multi_word_variants() {
    // The {snake_case Display, PascalCase serde} mismatch — pin
    // that lower snake_case is rejected as wire input.
    for bad in [
        r#""capability""#, // snake_case (would alias as_str output)
        r#""issuer_key""#,
        r#""node_attestation""#,
        r#""zone_key""#,
        r#""connector_binary""#,
    ] {
        let parsed = serde_json::from_str::<RevocationScope>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — wire form is PascalCase, NOT the snake_case Display"
        );
    }
}

#[test]
fn revocation_scope_count_matches_documented_five() {
    assert_eq!(ALL_SCOPES_SERDE.len(), 5);
    assert_eq!(ALL_SCOPES_DISPLAY.len(), 5);
}
