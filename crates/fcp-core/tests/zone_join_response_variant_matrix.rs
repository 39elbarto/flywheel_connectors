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
use std::error::Error;
use std::fmt::Debug;

type TestResult = Result<(), Box<dyn Error>>;

fn err(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure_eq<T>(actual: T, expected: T, context: &str) -> TestResult
where
    T: PartialEq + Debug,
{
    if actual == expected {
        Ok(())
    } else {
        Err(err(format!(
            "{context}: expected {expected:?}, got {actual:?}"
        )))
    }
}

fn ensure(condition: bool, context: impl Into<String>) -> TestResult {
    if condition { Ok(()) } else { Err(err(context)) }
}

const JOIN_RESPONSE_VARIANTS: &[(EnrollmentStatus, &str)] = &[
    (EnrollmentStatus::Pending, "pending"),
    (EnrollmentStatus::Approved, "approved"),
    (EnrollmentStatus::Rejected, "rejected"),
    (EnrollmentStatus::Revoked, "revoked"),
    (EnrollmentStatus::Expired, "expired"),
];

#[test]
fn zone_join_response_display_and_json_tags_are_pinned() -> TestResult {
    for &(variant, tag) in JOIN_RESPONSE_VARIANTS {
        ensure_eq(
            variant.to_string(),
            tag.to_string(),
            &format!("Display for zone-join response {variant:?}"),
        )?;

        let json = serde_json::to_value(variant)?;
        ensure_eq(
            json,
            json!(tag),
            &format!("JSON serde tag for zone-join response {variant:?}"),
        )?;

        let decoded: EnrollmentStatus = serde_json::from_value(json!(tag))?;
        ensure_eq(decoded, variant, "JSON roundtrip")?;
    }

    Ok(())
}

#[test]
fn zone_join_response_cbor_tags_are_text_scalars() -> TestResult {
    for &(variant, tag) in JOIN_RESPONSE_VARIANTS {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&variant, &mut bytes)?;

        let decoded: EnrollmentStatus = ciborium::de::from_reader(bytes.as_slice())?;
        ensure_eq(decoded, variant, "CBOR roundtrip")?;

        let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
        match value {
            CborValue::Text(text) => ensure_eq(text, tag.to_string(), "CBOR text tag")?,
            other => {
                return Err(err(format!(
                    "zone-join response must encode as CBOR Text, got {other:?}"
                )));
            }
        }
    }

    Ok(())
}

#[test]
fn zone_join_response_tags_are_distinct_and_complete() -> TestResult {
    let mut seen = std::collections::HashSet::new();
    for &(variant, tag) in JOIN_RESPONSE_VARIANTS {
        ensure(
            seen.insert(tag),
            format!("duplicate zone-join response tag for {variant:?}: {tag}"),
        )?;
    }

    ensure_eq(
        seen,
        std::collections::HashSet::from(["pending", "approved", "rejected", "revoked", "expired"]),
        "zone-join response variant set",
    )?;

    Ok(())
}

#[test]
fn zone_join_response_rejects_noncanonical_tags() -> TestResult {
    for bad in ["Pending", "Approved", "REJECTED", "revoked-zone", "unknown"] {
        let result: Result<EnrollmentStatus, _> = serde_json::from_value(json!(bad));
        ensure(
            result.is_err(),
            format!("zone-join response must reject noncanonical tag `{bad}`, got {result:?}"),
        )?;
    }

    Ok(())
}

#[test]
fn zone_join_response_join_semantics_are_pinned() -> TestResult {
    for &(variant, _) in JOIN_RESPONSE_VARIANTS {
        let accepted = variant.is_enrolled();
        let renewable = variant.is_renewable();

        ensure_eq(
            accepted,
            variant == EnrollmentStatus::Approved,
            &format!("{variant:?} join-accepted predicate"),
        )?;
        ensure_eq(
            renewable,
            matches!(
                variant,
                EnrollmentStatus::Approved | EnrollmentStatus::Expired
            ),
            &format!("{variant:?} join-renewable predicate"),
        )?;
    }

    Ok(())
}
