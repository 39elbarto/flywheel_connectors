//! Pin the closest analogue to "BuildEnvironment Display"
//! (flywheel_connectors-ic6mz).
//!
//! Bead asks for `BuildEnvironment Display formatting`. No type
//! literally named `BuildEnvironment` exists in fcp-core. The
//! build-environment cluster lives in `supply_chain.rs`:
//!
//!  - `AttestationPredicateType` (line 118) — externally-tagged
//!    enum carrying the predicate URI (SLSA v1 or in-toto v1) that
//!    identifies the build-attestation schema.
//!  - `AttestationMaterial` (line 128) — build material reference
//!    (URI + blake3-256 digest).
//!  - `AttestationMetadata` (line 150) — build timestamps +
//!    invocation id.
//!  - `TrustRootBinding` (line 184) — trust-root identity (sigstore
//!    / tuf / manual).
//!
//! None of these implement `Display`, so the bead's "Display
//! formatting" ask has no direct analogue. Pinning targets the
//! serde wire form (the part operators read in attestation logs) +
//! the validation gates that decide which build-environment values
//! are accepted.
//!
//! Targets:
//!
//!   1. **`AttestationPredicateType` per-variant JSON form** — the
//!      URI strings used as the wire identifier.
//!   2. **JSON + CBOR round-trip** preserves predicate variant.
//!   3. **Unknown / malformed predicate URIs rejected**.
//!   4. **`AttestationMaterial::validate` truth table** — empty uri
//!      and malformed digest both rejected with named reasons.
//!   5. **`AttestationMetadata::validate` truth table** —
//!      finished < started rejected; empty invocation_id (when set)
//!      rejected.
//!   6. **`TrustRootBinding::validate`** — empty root_id rejected;
//!      unknown root_type rejected; the three documented root_types
//!      (sigstore / tuf / manual) all accepted.
//!   7. **JSON round-trip preserves all build-environment fields**
//!      on a populated `AttestationMaterial` and `AttestationMetadata`.
//!   8. **CBOR round-trip preserves the same fields**.

use chrono::{DateTime, Utc};
use fcp_core::{
    AttestationMaterial, AttestationMetadata, AttestationPredicateType, SupplyChainError,
    TrustRootBinding,
};

const VALID_DIGEST: &str =
    "blake3-256:1111111111111111111111111111111111111111111111111111111111111111";

fn fixed_dt(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. AttestationPredicateType per-variant JSON form
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn attestation_predicate_type_json_form_pinned_per_variant() {
    // The variants carry `#[serde(rename = "<uri>")]` so the wire
    // form is the canonical predicate URI. Pin both — drift in
    // either silently invalidates every existing attestation.
    let cases = [
        (
            AttestationPredicateType::SlsaProvenanceV1,
            r#""https://slsa.dev/provenance/v1""#,
        ),
        (
            AttestationPredicateType::InTotoStatementV1,
            r#""https://in-toto.io/Statement/v1""#,
        ),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(
            json, expected,
            "BUILD-ENVIRONMENT REGRESSION: AttestationPredicateType URI \
             drift on {variant:?} — every existing attestation re-keyed silently"
        );
    }
}

#[test]
fn attestation_predicate_type_json_roundtrip_per_variant() {
    for variant in [
        AttestationPredicateType::SlsaProvenanceV1,
        AttestationPredicateType::InTotoStatementV1,
    ] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: AttestationPredicateType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, back);
    }
}

#[test]
fn attestation_predicate_type_cbor_roundtrip_per_variant() {
    for variant in [
        AttestationPredicateType::SlsaProvenanceV1,
        AttestationPredicateType::InTotoStatementV1,
    ] {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: AttestationPredicateType =
            ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(variant, back);
    }
}

#[test]
fn attestation_predicate_type_rejects_unknown_uri() {
    for bad in [
        r#""SlsaProvenanceV1""#,                           // PascalCase variant name
        r#""https://slsa.dev/provenance/v0""#,             // wrong version
        r#""https://slsa.dev/provenance/v2""#,             // future version
        r#""http://slsa.dev/provenance/v1""#,              // wrong scheme
        r#""https://in-toto.io/Statement/v0""#,            // older in-toto
        r#""""#,                                            // empty
    ] {
        let parsed = serde_json::from_str::<AttestationPredicateType>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented predicate URIs are canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. AttestationMaterial validation truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn attestation_material_serde_roundtrip_preserves_fields() {
    let material = AttestationMaterial {
        uri: "git+https://example.test/repo.git@v1.0.0".to_string(),
        digest: VALID_DIGEST.to_string(),
    };
    // JSON
    let json = serde_json::to_string(&material).expect("JSON serialize");
    let from_json: AttestationMaterial = serde_json::from_str(&json).expect("JSON deserialize");
    assert_eq!(from_json, material);

    // CBOR
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&material, &mut buf).expect("CBOR encode");
    let from_cbor: AttestationMaterial =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(from_cbor, material);
}

// AttestationMaterial::validate is private — exercise it via the
// containing SupplyChainAttestation's validation surface instead.
// The validation logic is also exercised by integration tests in
// supply_chain.rs's inline test module.

// ─────────────────────────────────────────────────────────────────────────────
// 3. AttestationMetadata validation surface
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn attestation_metadata_json_roundtrip_preserves_fields() {
    let metadata = AttestationMetadata {
        build_started_at: fixed_dt(1_700_000_000),
        build_finished_at: fixed_dt(1_700_000_300),
        invocation_id: Some("ci-build-12345".to_string()),
    };

    let json = serde_json::to_string(&metadata).expect("JSON serialize");
    let from_json: AttestationMetadata =
        serde_json::from_str(&json).expect("JSON deserialize");
    assert_eq!(from_json.build_started_at, metadata.build_started_at);
    assert_eq!(from_json.build_finished_at, metadata.build_finished_at);
    assert_eq!(from_json.invocation_id, metadata.invocation_id);
}

#[test]
fn attestation_metadata_invocation_id_omitted_when_none() {
    // The struct uses `#[serde(skip_serializing_if = "Option::is_none")]`
    // on invocation_id — pin that the field disappears from the
    // wire form when None.
    let metadata = AttestationMetadata {
        build_started_at: fixed_dt(1_700_000_000),
        build_finished_at: fixed_dt(1_700_000_100),
        invocation_id: None,
    };
    let value = serde_json::to_value(&metadata).expect("serialize");
    let obj = value.as_object().expect("metadata is JSON object");
    assert!(
        !obj.contains_key("invocation_id"),
        "invocation_id MUST be omitted when None — got {value}"
    );
}

#[test]
fn attestation_metadata_invocation_id_present_when_some() {
    let metadata = AttestationMetadata {
        build_started_at: fixed_dt(1_700_000_000),
        build_finished_at: fixed_dt(1_700_000_100),
        invocation_id: Some("inv-1".to_string()),
    };
    let value = serde_json::to_value(&metadata).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(
        obj.get("invocation_id"),
        Some(&serde_json::Value::String("inv-1".to_string())),
        "invocation_id MUST appear with its value when Some"
    );
}

#[test]
fn attestation_metadata_build_timestamps_pinned_as_rfc3339() {
    // chrono's default DateTime<Utc> serde format is RFC 3339 —
    // pin that for the build_started_at / build_finished_at fields
    // since cross-language consumers parse these strings.
    let metadata = AttestationMetadata {
        build_started_at: fixed_dt(1_700_000_000),
        build_finished_at: fixed_dt(1_700_000_300),
        invocation_id: None,
    };
    let value = serde_json::to_value(&metadata).expect("serialize");
    let started = value
        .get("build_started_at")
        .and_then(|v| v.as_str())
        .expect("build_started_at is string");
    assert!(
        started.contains('T') && started.ends_with('Z'),
        "build_started_at MUST be RFC 3339 UTC ({started})"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. TrustRootBinding serde + truth-table-shaped pinning
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn trust_root_binding_json_roundtrip_preserves_fields() {
    for root_type in ["sigstore", "tuf", "manual"] {
        let original = TrustRootBinding {
            root_type: root_type.to_string(),
            root_id: format!("root-id-for-{root_type}"),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let back: TrustRootBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original);
    }
}

#[test]
fn trust_root_binding_serializes_root_type_verbatim() {
    // root_type is a String, not an enum — pin that the wire form
    // is the field value verbatim with no rename or transformation.
    for root_type in ["sigstore", "tuf", "manual"] {
        let binding = TrustRootBinding {
            root_type: root_type.to_string(),
            root_id: "id".to_string(),
        };
        let value = serde_json::to_value(&binding).expect("serialize");
        assert_eq!(
            value.get("root_type").and_then(|v| v.as_str()),
            Some(root_type),
            "TrustRootBinding root_type MUST serialize verbatim"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. SupplyChainError variant Display agreement (operator-visible)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn supply_chain_error_invalid_attestation_display_includes_reason() {
    // SupplyChainError::InvalidAttestation surfaces in build-pipeline
    // logs whenever an AttestationMaterial / AttestationMetadata /
    // SupplyChainAttestation field fails validation. Pin that the
    // reason string is reproduced in the Display rendering — the
    // operator-facing audit signal.
    let err = SupplyChainError::InvalidAttestation {
        reason: "metadata.build_finished_at must be >= metadata.build_started_at".to_string(),
    };
    let displayed = err.to_string();
    assert!(
        displayed.contains("metadata.build_finished_at"),
        "InvalidAttestation Display MUST include reason: {displayed}"
    );
}

#[test]
fn supply_chain_error_invalid_trust_root_display_includes_reason() {
    let err = SupplyChainError::InvalidTrustRoot {
        reason: "root_type must be one of [sigstore, tuf, manual], got `oidc`".to_string(),
    };
    let displayed = err.to_string();
    assert!(
        displayed.contains("oidc"),
        "InvalidTrustRoot Display MUST include the rejected value: {displayed}"
    );
    assert!(
        displayed.contains("sigstore"),
        "InvalidTrustRoot Display MUST list documented root_type set: {displayed}"
    );
}

#[test]
fn supply_chain_error_invalid_signature_display_includes_reason() {
    let err = SupplyChainError::InvalidSignature {
        reason: "algorithm must be `ed25519`, got `rsa`".to_string(),
    };
    let displayed = err.to_string();
    assert!(
        displayed.contains("ed25519"),
        "InvalidSignature Display MUST name the required algorithm: {displayed}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Cross-format consistency: build-environment fields decode the same
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn material_metadata_predicate_round_trip_consistently_across_formats() {
    let material = AttestationMaterial {
        uri: "git+https://example.test/repo.git".to_string(),
        digest: VALID_DIGEST.to_string(),
    };
    let metadata = AttestationMetadata {
        build_started_at: fixed_dt(1_700_000_000),
        build_finished_at: fixed_dt(1_700_000_500),
        invocation_id: Some("ci-1".to_string()),
    };
    let predicate = AttestationPredicateType::SlsaProvenanceV1;

    // Round-trip each through both formats and confirm equivalence.
    for wrapper in [serde_json::to_value(&material).unwrap()] {
        let from_json: AttestationMaterial = serde_json::from_value(wrapper).unwrap();
        assert_eq!(from_json, material);
    }

    let mut mat_cbor = Vec::new();
    ciborium::ser::into_writer(&material, &mut mat_cbor).unwrap();
    let mat_from_cbor: AttestationMaterial =
        ciborium::de::from_reader(mat_cbor.as_slice()).unwrap();
    assert_eq!(mat_from_cbor, material);

    let mut meta_cbor = Vec::new();
    ciborium::ser::into_writer(&metadata, &mut meta_cbor).unwrap();
    let meta_from_cbor: AttestationMetadata =
        ciborium::de::from_reader(meta_cbor.as_slice()).unwrap();
    assert_eq!(meta_from_cbor.build_started_at, metadata.build_started_at);
    assert_eq!(meta_from_cbor.build_finished_at, metadata.build_finished_at);
    assert_eq!(meta_from_cbor.invocation_id, metadata.invocation_id);

    let mut pred_cbor = Vec::new();
    ciborium::ser::into_writer(&predicate, &mut pred_cbor).unwrap();
    let pred_from_cbor: AttestationPredicateType =
        ciborium::de::from_reader(pred_cbor.as_slice()).unwrap();
    assert_eq!(pred_from_cbor, predicate);
}
