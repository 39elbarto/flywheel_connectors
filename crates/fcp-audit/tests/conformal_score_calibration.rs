use fcp_audit::{ConformalScoreEstimator, Decision, DecisionReceipt};

fn receipt(
    decision: Decision,
    decided_at: u64,
    connector_id: &str,
    operation_id: &str,
) -> DecisionReceipt {
    DecisionReceipt {
        id: format!("receipt-{connector_id}-{operation_id}-{decided_at}"),
        request_id: format!("request-{decided_at}"),
        decision,
        reason_code: "policy.evaluated".to_string(),
        evidence: Vec::new(),
        audit_entry_id: None,
        explanation: None,
        decided_at,
        zone_id: "z:test".to_string(),
        correlation_id: None,
        trace_context: None,
        connector_id: Some(connector_id.to_string()),
        operation_id: Some(operation_id.to_string()),
        confidence: None,
        issuer_kid: None,
        signature: None,
    }
}

fn history(
    total: usize,
    failures: usize,
    connector_id: &str,
    operation_id: &str,
) -> Vec<DecisionReceipt> {
    (0..total)
        .map(|idx| {
            let decision = if idx < failures {
                Decision::Deny
            } else {
                Decision::Allow
            };
            receipt(
                decision,
                1_700_000_000 + u64::try_from(idx).unwrap_or(u64::MAX),
                connector_id,
                operation_id,
            )
        })
        .collect()
}

#[test]
fn score_stays_in_unit_interval_and_decreases_with_failures() {
    let estimator = ConformalScoreEstimator::new().with_min_history(5);
    let target = receipt(Decision::Allow, 1_700_000_100, "stripe", "charges.create");
    let healthy = history(20, 1, "stripe", "charges.create");
    let failing = history(20, 10, "stripe", "charges.create");

    let healthy_score = estimator.score_receipt(&target, &healthy, 1_700_000_200);
    let failing_score = estimator.score_receipt(&target, &failing, 1_700_000_200);

    assert!((0.0..=1.0).contains(&healthy_score.value()));
    assert!((0.0..=1.0).contains(&failing_score.value()));
    assert!(
        failing_score.value() < healthy_score.value(),
        "confidence should decrease as the nonconforming rate rises"
    );
}

#[test]
fn insufficient_history_uses_conservative_score() {
    let estimator = ConformalScoreEstimator::new().with_min_history(5);
    let target = receipt(Decision::Allow, 1_700_000_100, "slack", "chat.post");
    let sparse = history(2, 0, "slack", "chat.post");

    let score = estimator.score_receipt(&target, &sparse, 1_700_000_200);

    assert_eq!(score.display_value(), "0.250");
    assert_eq!(score.sample_count, 2);
    assert_eq!(
        score.conservative_reason.as_deref(),
        Some("insufficient_history")
    );
}

#[test]
fn receipt_carries_serialized_confidence() {
    let estimator = ConformalScoreEstimator::new().with_min_history(5);
    let mut target = receipt(Decision::Allow, 1_700_000_100, "github", "issues.create");
    let calibration = history(8, 2, "github", "issues.create");
    target.confidence = Some(estimator.score_receipt(&target, &calibration, 1_700_000_200));

    let json = serde_json::to_string(&target).expect("receipt serializes");
    assert!(json.contains("\"confidence\""));
    let parsed: DecisionReceipt = serde_json::from_str(&json).expect("receipt deserializes");

    let confidence = parsed.confidence.expect("confidence round-trips");
    assert!((0.0..=1.0).contains(&confidence.value()));
    assert_eq!(confidence.sample_count, 8);
    assert_eq!(confidence.nonconforming_count, 2);
}

#[test]
fn stale_history_decays_confidence() {
    let estimator = ConformalScoreEstimator::new()
        .with_min_history(5)
        .with_staleness_half_life_secs(10);
    let target = receipt(Decision::Allow, 1_700_000_100, "gmail", "messages.send");
    let calibration = history(10, 0, "gmail", "messages.send");

    let fresh = estimator.score_receipt(&target, &calibration, 1_700_000_020);
    let stale = estimator.score_receipt(&target, &calibration, 1_700_001_000);

    assert!(stale.value() < fresh.value());
}
