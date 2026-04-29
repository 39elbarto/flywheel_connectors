//! Pin the fcp-core resource-limit display and ordering contract.
//!
//! There is no public fcp-core type literally named `ResourceLimit`. Resource
//! limits are represented on the protocol surface by `LimitType`, the
//! classifier embedded in throttle/resource-limit violation records.

use fcp_core::LimitType;
use std::cmp::Ordering;

const RESOURCE_LIMIT_CASES: &[(LimitType, &str)] = &[
    (LimitType::Rpm, "rpm"),
    (LimitType::Concurrent, "concurrent"),
    (LimitType::Burst, "burst"),
    (LimitType::Quota, "quota"),
];

#[test]
fn resource_limit_display_tokens_are_stable() {
    for (limit, token) in RESOURCE_LIMIT_CASES {
        assert_eq!(limit.to_string(), *token);
    }
}

#[test]
fn resource_limit_display_matches_json_serde_tag() -> Result<(), Box<dyn std::error::Error>> {
    for (limit, token) in RESOURCE_LIMIT_CASES {
        let json = serde_json::to_string(limit)?;
        assert_eq!(json, format!("\"{token}\""));
        assert_eq!(json.trim_matches('"'), limit.to_string());

        let decoded: LimitType = serde_json::from_str(&json)?;
        assert_eq!(decoded, *limit);
    }

    Ok(())
}

#[test]
fn resource_limit_ordering_is_declaration_order() {
    let ordered: Vec<_> = RESOURCE_LIMIT_CASES
        .iter()
        .map(|(limit, _)| *limit)
        .collect();
    let mut sorted = ordered.clone();
    sorted.sort();

    assert_eq!(
        sorted, ordered,
        "Resource-limit ordering must remain rpm < concurrent < burst < quota"
    );

    assert_eq!(LimitType::Rpm.cmp(&LimitType::Concurrent), Ordering::Less);
    assert_eq!(LimitType::Concurrent.cmp(&LimitType::Burst), Ordering::Less);
    assert_eq!(LimitType::Burst.cmp(&LimitType::Quota), Ordering::Less);
}

#[test]
fn resource_limit_pairwise_ordering_is_total_and_distinct() {
    for (left_index, (left, _)) in RESOURCE_LIMIT_CASES.iter().enumerate() {
        for (right_index, (right, _)) in RESOURCE_LIMIT_CASES.iter().enumerate() {
            match left_index.cmp(&right_index) {
                Ordering::Less => assert!(left < right, "{left} must sort before {right}"),
                Ordering::Equal => assert_eq!(left.cmp(right), Ordering::Equal),
                Ordering::Greater => assert!(left > right, "{left} must sort after {right}"),
            }
        }
    }
}

#[test]
fn resource_limit_rejects_noncanonical_display_tokens() {
    for invalid in [
        r#""Rpm""#,
        r#""RPM""#,
        r#""requests_per_minute""#,
        r#""soft_limit""#,
        r#""resource-limit""#,
        r#""""#,
    ] {
        assert!(
            serde_json::from_str::<LimitType>(invalid).is_err(),
            "{invalid} must not decode as a canonical resource-limit tag"
        );
    }
}
