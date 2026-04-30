//! Pin `UsageBudgetSnapshot` as the fcp-core budget snapshot wire type.
//!
//! No public type is literally named `BudgetSnapshot`; `UsageBudgetSnapshot`
//! is the exposed zone budget snapshot carrying enforcement state plus the
//! ordered per-metric usage entries.

use fcp_core::{
    BudgetEnforcement, BudgetStatus, UsageBudgetSnapshot, UsageBudgetUsage, UsageMetricKind, ZoneId,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn populated_snapshot() -> UsageBudgetSnapshot {
    UsageBudgetSnapshot {
        zone_id: ZoneId::work(),
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![
            UsageBudgetUsage {
                metric: UsageMetricKind::ApiCredits,
                used: 9_500,
                limit: 10_000,
                remaining: 500,
                window_started_at: 1_764_460_800,
                window_resets_at: 1_764_547_200,
                status: BudgetStatus::Ok,
            },
            UsageBudgetUsage {
                metric: UsageMetricKind::Tokens,
                used: 1_000_001,
                limit: 1_000_000,
                remaining: 0,
                window_started_at: 1_764_460_800,
                window_resets_at: 1_764_547_200,
                status: BudgetStatus::Exceeded,
            },
        ],
        updated_at: 1_764_463_600,
    }
}

fn empty_snapshot() -> UsageBudgetSnapshot {
    UsageBudgetSnapshot {
        zone_id: ZoneId::public(),
        enforcement: BudgetEnforcement::Warn,
        budgets: Vec::new(),
        updated_at: 0,
    }
}

fn assert_snapshots_equal(actual: &UsageBudgetSnapshot, expected: &UsageBudgetSnapshot) {
    assert_eq!(actual.zone_id, expected.zone_id);
    assert_eq!(actual.enforcement, expected.enforcement);
    assert_eq!(actual.updated_at, expected.updated_at);
    assert_eq!(actual.budgets.len(), expected.budgets.len());

    for (actual, expected) in actual.budgets.iter().zip(&expected.budgets) {
        assert_eq!(actual.metric, expected.metric);
        assert_eq!(actual.used, expected.used);
        assert_eq!(actual.limit, expected.limit);
        assert_eq!(actual.remaining, expected.remaining);
        assert_eq!(actual.window_started_at, expected.window_started_at);
        assert_eq!(actual.window_resets_at, expected.window_resets_at);
        assert_eq!(actual.status, expected.status);
    }
}

#[test]
fn budget_snapshot_json_shape_and_roundtrip_are_pinned() -> TestResult {
    let snapshot = populated_snapshot();
    let encoded = serde_json::to_string(&snapshot)?;

    assert_eq!(
        encoded,
        concat!(
            r#"{"zone_id":"z:work","enforcement":"deny","budgets":["#,
            r#"{"metric":"api_credits","used":9500,"limit":10000,"remaining":500,"#,
            r#""window_started_at":1764460800,"window_resets_at":1764547200,"status":"ok"},"#,
            r#"{"metric":"tokens","used":1000001,"limit":1000000,"remaining":0,"#,
            r#""window_started_at":1764460800,"window_resets_at":1764547200,"status":"exceeded"}"#,
            r#"],"updated_at":1764463600}"#,
        )
    );

    let decoded: UsageBudgetSnapshot = serde_json::from_str(&encoded)?;
    assert_snapshots_equal(&decoded, &snapshot);

    Ok(())
}

#[test]
fn budget_snapshot_cbor_roundtrip_preserves_all_fields() -> TestResult {
    let snapshot = populated_snapshot();
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&snapshot, &mut encoded)?;
    assert!(!encoded.is_empty());

    let decoded: UsageBudgetSnapshot = ciborium::de::from_reader(encoded.as_slice())?;
    assert_snapshots_equal(&decoded, &snapshot);

    let mut reencoded = Vec::new();
    ciborium::ser::into_writer(&decoded, &mut reencoded)?;
    assert_eq!(reencoded, encoded);

    Ok(())
}

#[test]
fn budget_snapshot_empty_budget_list_roundtrips_as_present_empty_array() -> TestResult {
    let snapshot = empty_snapshot();
    let encoded = serde_json::to_string(&snapshot)?;
    assert_eq!(
        encoded,
        r#"{"zone_id":"z:public","enforcement":"warn","budgets":[],"updated_at":0}"#
    );

    let json_decoded: UsageBudgetSnapshot = serde_json::from_str(&encoded)?;
    assert_snapshots_equal(&json_decoded, &snapshot);

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&snapshot, &mut cbor)?;
    let cbor_decoded: UsageBudgetSnapshot = ciborium::de::from_reader(cbor.as_slice())?;
    assert_snapshots_equal(&cbor_decoded, &snapshot);

    Ok(())
}
