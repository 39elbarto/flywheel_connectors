//! Pin `BudgetStatus` as the closest fcp-core analogue to `ConnectorBudget`.
//!
//! Bead asks for `ConnectorBudget` Display + serde tag. No type literally named
//! `ConnectorBudget` exists in fcp-core. The connector-facing budget classifier
//! currently exposed by fcp-core is `BudgetStatus`, carried by
//! `UsageBudgetUsage::status` in connector/zone budget snapshots.

use fcp_core::BudgetStatus;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct ConnectorBudgetCase {
    value: BudgetStatus,
    tag: &'static str,
    cbor_hex: &'static str,
}

const CASES: &[ConnectorBudgetCase] = &[
    ConnectorBudgetCase {
        value: BudgetStatus::Ok,
        tag: "ok",
        cbor_hex: "626f6b",
    },
    ConnectorBudgetCase {
        value: BudgetStatus::Exceeded,
        tag: "exceeded",
        cbor_hex: "686578636565646564",
    },
];

#[test]
fn connector_budget_display_matches_stable_serde_tag() {
    for case in CASES {
        assert_eq!(case.value.as_str(), case.tag);
        assert_eq!(case.value.to_string(), case.tag);
    }
}

#[test]
fn connector_budget_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let encoded = serde_json::to_string(&case.value)?;
        assert_eq!(encoded, format!("\"{}\"", case.tag));

        let decoded: BudgetStatus = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, case.value);
        assert_eq!(decoded.to_string(), encoded.trim_matches('"'));
    }

    Ok(())
}

#[test]
fn connector_budget_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in CASES {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;
        assert_eq!(hex::encode(&encoded), case.cbor_hex);

        let decoded: BudgetStatus = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(decoded, case.value);
        assert_eq!(decoded.to_string(), case.tag);
    }

    Ok(())
}

#[test]
fn connector_budget_rejects_noncanonical_tags() {
    for invalid in [
        r#""Ok""#,
        r#""Exceeded""#,
        r#""over_budget""#,
        r#""within_budget""#,
        r#""warning""#,
        r#""""#,
    ] {
        assert!(
            serde_json::from_str::<BudgetStatus>(invalid).is_err(),
            "{invalid} must not decode as a canonical connector budget tag"
        );
    }
}

#[test]
fn connector_budget_tags_are_pairwise_distinct() {
    assert_eq!(CASES.len(), 2);
    assert_ne!(BudgetStatus::Ok, BudgetStatus::Exceeded);
    assert_ne!(
        BudgetStatus::Ok.to_string(),
        BudgetStatus::Exceeded.to_string()
    );
    assert_ne!(
        serde_json::to_string(&BudgetStatus::Ok).expect("serialize ok"),
        serde_json::to_string(&BudgetStatus::Exceeded).expect("serialize exceeded")
    );
}
