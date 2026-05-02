//! Pin fcp-core preflight-check Display text and serde tags.
//!
//! fcp-core names the public preflight check variants `EnforcementCheckId`.
//! Those identifiers are the ordered checks a runtime evaluates before an
//! operation proceeds.

use ciborium::value::Value as CborValue;
use fcp_core::{EnforcementCheckId, EnforcementCheckOrder};
use std::error::Error;
use std::fmt::Debug;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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

fn cbor_tag(check: EnforcementCheckId) -> TestResult<String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&check, &mut bytes)?;
    let value: CborValue = ciborium::de::from_reader(bytes.as_slice())?;
    let CborValue::Text(tag) = value else {
        return Err(err(format!(
            "EnforcementCheckId CBOR must encode as a text tag, got {value:?}"
        )));
    };
    Ok(tag)
}

#[test]
fn preflight_check_display_and_serde_tags_are_pinned() -> TestResult {
    let cases = [
        (EnforcementCheckId::CanonicalDecode, "canonical_decode"),
        (EnforcementCheckId::ZoneMembership, "zone_membership"),
        (EnforcementCheckId::CapabilityVerify, "capability_verify"),
        (EnforcementCheckId::HolderProof, "holder_proof"),
        (
            EnforcementCheckId::CheckpointFreshness,
            "checkpoint_freshness",
        ),
        (
            EnforcementCheckId::RevocationFreshness,
            "revocation_freshness",
        ),
        (EnforcementCheckId::TaintApproval, "taint_approval"),
        (EnforcementCheckId::PolicyCeiling, "policy_ceiling"),
        (
            EnforcementCheckId::CapabilityConstraints,
            "capability_constraints",
        ),
        (EnforcementCheckId::ConnectorManifest, "connector_manifest"),
        (EnforcementCheckId::Budget, "budget"),
        (EnforcementCheckId::RateLimit, "rate_limit"),
    ];

    ensure_eq(
        EnforcementCheckOrder::canonical_order(),
        cases.map(|(check, _)| check),
        "canonical preflight check order",
    )?;

    for (check, tag) in cases {
        ensure_eq(check.as_str(), tag, "as_str tag")?;
        ensure_eq(check.to_string(), tag.to_string(), "Display tag")?;

        let json = serde_json::to_value(check)?;
        ensure_eq(json.clone(), serde_json::json!(tag), "JSON tag")?;

        let decoded_json: EnforcementCheckId = serde_json::from_value(json)?;
        ensure_eq(decoded_json, check, "JSON roundtrip")?;

        ensure_eq(cbor_tag(check)?, tag.to_string(), "CBOR tag")?;

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&check, &mut bytes)?;
        let decoded_cbor: EnforcementCheckId = ciborium::de::from_reader(bytes.as_slice())?;
        ensure_eq(decoded_cbor, check, "CBOR roundtrip")?;
    }

    Ok(())
}
