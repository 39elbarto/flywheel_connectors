//! Pin fcp-core enforcement-error Display text and serde tags.
//!
//! fcp-core does not expose a type literally named `EnforcementError`.
//! Enforcement failures in the public core API are surfaced as `FcpError`
//! variants, while `CheckOutcome` carries the enforcement decision tag.

use ciborium::value::Value as CborValue;
use fcp_core::{CheckOutcome, ErrorCategory, FcpError, UsageMetricKind};

fn json_category(error: &FcpError) -> String {
    let json = serde_json::to_value(error).expect("serialize FcpError to JSON");
    json.get("category")
        .and_then(serde_json::Value::as_str)
        .expect("FcpError JSON must carry category tag")
        .to_string()
}

fn cbor_category(error: &FcpError) -> String {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(error, &mut bytes).expect("serialize FcpError to CBOR");
    let value: CborValue = ciborium::de::from_reader(bytes.as_slice()).expect("decode CBOR value");
    let CborValue::Map(entries) = value else {
        panic!("FcpError CBOR must encode as a tagged map, got {value:?}");
    };

    entries
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (CborValue::Text(key), CborValue::Text(tag)) if key == "category" => Some(tag.clone()),
            _ => None,
        })
        .expect("FcpError CBOR must carry category tag")
}

#[test]
fn enforcement_error_display_and_serde_tag_are_pinned() {
    let cases = [
        (
            FcpError::CapabilityDenied {
                capability: "cap.files.write".to_string(),
                reason: "policy ceiling exceeded".to_string(),
            },
            "Capability denied: cap.files.write",
            "CapabilityDenied",
            ErrorCategory::Capability,
            3001,
        ),
        (
            FcpError::RateLimited {
                retry_after_ms: 2_500,
                violation: None,
            },
            "Rate limited: retry after 2500ms",
            "RateLimited",
            ErrorCategory::Capability,
            3002,
        ),
        (
            FcpError::ZoneViolation {
                source_zone: "z:public".to_string(),
                target_zone: "z:private".to_string(),
                message: "cross-zone access denied".to_string(),
            },
            "Zone violation: cross-zone access denied",
            "ZoneViolation",
            ErrorCategory::Zone,
            4001,
        ),
        (
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::Requests,
                used: 101,
                limit: 100,
                window_seconds: 60,
            },
            "Budget exceeded for Requests: used 101 of 100 per 60s",
            "BudgetExceeded",
            ErrorCategory::Resource,
            6004,
        ),
    ];

    for (error, display, serde_tag, category, numeric_code) in cases {
        assert_eq!(error.to_string(), display);
        assert_eq!(json_category(&error), serde_tag);
        assert_eq!(cbor_category(&error), serde_tag);
        assert_eq!(error.category(), category);
        assert_eq!(error.numeric_code(), numeric_code);

        let json = serde_json::to_string(&error).expect("serialize FcpError JSON");
        let decoded: FcpError = serde_json::from_str(&json).expect("deserialize FcpError JSON");
        assert_eq!(decoded.to_string(), display);
        assert_eq!(decoded.category(), category);
        assert_eq!(decoded.numeric_code(), numeric_code);
    }
}

#[test]
fn enforcement_decision_deny_tag_is_pinned() {
    let deny = CheckOutcome::Deny {
        reason_code: "capability.denied".to_string(),
        explanation: "capability was not granted".to_string(),
    };

    let json = serde_json::to_value(&deny).expect("serialize CheckOutcome::Deny");
    assert_eq!(json["outcome"], "deny");
    assert_eq!(json["reason_code"], "capability.denied");
    assert_eq!(json["explanation"], "capability was not granted");

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&deny, &mut bytes).expect("serialize CheckOutcome::Deny to CBOR");
    let decoded: CheckOutcome =
        ciborium::de::from_reader(bytes.as_slice()).expect("deserialize CheckOutcome::Deny CBOR");
    assert_eq!(decoded, deny);
}
