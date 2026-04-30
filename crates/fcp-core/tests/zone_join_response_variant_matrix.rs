//! Pin `EnrollmentStatus` as fcp-core's public zone-join response vocabulary
//! for `flywheel_connectors-q7oel`.
//!
//! No type literally named `ZoneJoinResponse` exists in fcp-core. The enrollment
//! module documents `DeviceEnrollmentRequest` as the request from a new device
//! to join the mesh, with `DeviceEnrollmentApproval` binding that device to a
//! zone. The exported response/status vocabulary for that join flow is
//! `EnrollmentStatus`, so this test pins every variant's Display text and serde
//! tag in that role.

use ciborium::Value as CborValue;
use fcp_core::EnrollmentStatus;
use serde_json::json;

const JOIN_RESPONSE_VARIANTS: &[(EnrollmentStatus, &str)] = &[
    (EnrollmentStatus::Pending, "pending"),
    (EnrollmentStatus::Approved, "approved"),
    (EnrollmentStatus::Rejected, "rejected"),
    (EnrollmentStatus::Revoked, "revoked"),
    (EnrollmentStatus::Expired, "expired"),
];

#[test]
fn zone_join_response_display_and_json_tags_are_pinned() {
    for &(variant, tag) in JOIN_RESPONSE_VARIANTS {
        assert_eq!(
            variant.to_string(),
            tag,
            "Display for zone-join response {variant:?} drifted"
        );

        let json = serde_json::to_value(variant).unwrap();
        assert_eq!(
            json,
            json!(tag),
            "JSON serde tag for zone-join response {variant:?} drifted"
        );

        let decoded: EnrollmentStatus = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, variant);
    }
}

#[test]
fn zone_join_response_cbor_tags_are_text_scalars() {
    for &(variant, tag) in JOIN_RESPONSE_VARIANTS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes).unwrap();

        let decoded: EnrollmentStatus = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, variant);

        let value: CborValue = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        match value {
            CborValue::Text(text) => assert_eq!(text, tag),
            other => panic!("zone-join response must encode as CBOR Text, got {other:?}"),
        }
    }
}

#[test]
fn zone_join_response_tags_are_distinct_and_complete() {
    let mut seen = std::collections::HashSet::new();
    for &(variant, tag) in JOIN_RESPONSE_VARIANTS {
        assert!(
            seen.insert(tag),
            "duplicate zone-join response tag for {variant:?}: {tag}"
        );
    }

    assert_eq!(
        seen,
        std::collections::HashSet::from(["pending", "approved", "rejected", "revoked", "expired"]),
        "zone-join response variant set drifted"
    );
}

#[test]
fn zone_join_response_rejects_noncanonical_tags() {
    for bad in ["Pending", "Approved", "REJECTED", "revoked-zone", "unknown"] {
        let result: Result<EnrollmentStatus, _> = serde_json::from_value(json!(bad));
        assert!(
            result.is_err(),
            "zone-join response must reject noncanonical tag `{bad}`, got {result:?}"
        );
    }
}

#[test]
fn zone_join_response_join_semantics_are_pinned() {
    for &(variant, _) in JOIN_RESPONSE_VARIANTS {
        let accepted = variant.is_enrolled();
        let renewable = variant.is_renewable();

        assert_eq!(
            accepted,
            variant == EnrollmentStatus::Approved,
            "{variant:?} join-accepted predicate drifted"
        );
        assert_eq!(
            renewable,
            matches!(
                variant,
                EnrollmentStatus::Approved | EnrollmentStatus::Expired
            ),
            "{variant:?} join-renewable predicate drifted"
        );
    }
}
