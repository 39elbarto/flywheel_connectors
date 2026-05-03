//! `fcp-host::BudgetTracker` per-zone usage accounting conformance.
//!
//! BudgetTracker is the per-zone usage budget enforcement that backs
//! invoke-budget admission decisions. 129 inline tests cover internals
//! but no cross-crate conformance pinned the contract that callers
//! (the host gateway, admin reporting CLI, connector preflight)
//! depend on:
//!
//! 1. **Within-budget** → `BudgetAction::Allow`.
//! 2. **Exceeded under `BudgetEnforcement::Deny`** → `BudgetAction::Deny`,
//!    and `to_error()` returns `Some(FcpError::BudgetExceeded)`
//!    carrying the metric / used / limit / window_seconds — the
//!    structured payload triagers grep for.
//! 3. **Exceeded under `BudgetEnforcement::Warn`** → `BudgetAction::Warn`
//!    and `to_error()` returns `None` (warn-only must NOT surface as
//!    a denial error).
//! 4. **Accumulating usage within a single window** sums correctly.
//! 5. **Multiple metrics in one record_usage call** track independently.
//! 6. **Per-zone isolation** — one zone exhausting their budget MUST
//!    NOT affect another zone's evaluation.

use fcp_host::{BudgetAction, BudgetEvaluation, BudgetTracker};
use fcp_prelude::{
    BudgetEnforcement, BudgetStatus, FcpError, UsageBudgetLimit, UsageBudgetPolicy, UsageMetric,
    UsageMetricKind, ZoneId,
};

fn budget_for_metric(
    enforcement: BudgetEnforcement,
    metric: UsageMetricKind,
    limit: u64,
) -> UsageBudgetPolicy {
    UsageBudgetPolicy {
        enforcement,
        budgets: vec![UsageBudgetLimit {
            metric,
            limit,
            window_seconds: 3600,
        }],
    }
}

fn token_metric(amount: u64) -> UsageMetric {
    UsageMetric::tokens(amount)
}

fn assert_budget_status(eval: &BudgetEvaluation, metric: UsageMetricKind, status: BudgetStatus) {
    let entry = eval
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == metric)
        .unwrap_or_else(|| panic!("snapshot must contain metric {metric:?}"));
    assert_eq!(
        entry.status, status,
        "metric {metric:?} had unexpected status: {entry:?}"
    );
}

#[test]
fn within_budget_evaluates_to_allow() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    let eval = tracker.record_usage(&zone, &policy, &[token_metric(50)]);

    assert_eq!(
        eval.action,
        BudgetAction::Allow,
        "50 tokens against a 100-token cap MUST evaluate to Allow"
    );
    assert!(
        eval.to_error().is_none(),
        "Allow MUST NOT convert to a BudgetExceeded error"
    );
    assert_budget_status(&eval, UsageMetricKind::Tokens, BudgetStatus::Ok);
}

#[test]
fn exceeded_under_deny_mode_evaluates_to_deny_and_converts_to_error() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    let eval = tracker.record_usage(&zone, &policy, &[token_metric(150)]);

    assert_eq!(eval.action, BudgetAction::Deny);
    assert_budget_status(&eval, UsageMetricKind::Tokens, BudgetStatus::Exceeded);

    match eval.to_error() {
        Some(FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        }) => {
            assert_eq!(metric, UsageMetricKind::Tokens, "metric must be propagated");
            assert_eq!(used, 150, "used must reflect actual usage");
            assert_eq!(limit, 100, "limit must reflect the policy cap");
            assert_eq!(
                window_seconds, 3600,
                "window_seconds must reflect the configured window"
            );
        }
        other => panic!("expected Some(BudgetExceeded), got {other:?}"),
    }
}

#[test]
fn exceeded_under_warn_mode_evaluates_to_warn_and_does_not_convert_to_error() {
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Warn, UsageMetricKind::Tokens, 100);

    let eval = tracker.record_usage(&zone, &policy, &[token_metric(150)]);

    assert_eq!(
        eval.action,
        BudgetAction::Warn,
        "Warn enforcement on overrun MUST yield Warn (not Deny)"
    );
    assert!(
        eval.to_error().is_none(),
        "Warn MUST NOT convert to FcpError — to_error returns None even on overrun"
    );
    assert_budget_status(&eval, UsageMetricKind::Tokens, BudgetStatus::Exceeded);
}

#[test]
fn accumulating_usage_within_same_window_sums() {
    // Two record_usage calls in the same wall-clock window must
    // sum into the same MetricWindow. Otherwise budget is reset on
    // every call.
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    let first = tracker.record_usage(&zone, &policy, &[token_metric(60)]);
    assert_eq!(first.action, BudgetAction::Allow);

    let second = tracker.record_usage(&zone, &policy, &[token_metric(60)]);
    assert_eq!(
        second.action,
        BudgetAction::Deny,
        "60 + 60 = 120 over a 100-cap MUST overflow to Deny in the second call"
    );
    let entry = second
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry");
    assert_eq!(
        entry.used, 120,
        "accumulating usage must report the running total, not the last delta"
    );
}

#[test]
fn multiple_metrics_in_one_record_usage_track_independently() {
    // Tokens AND Bytes both have caps. A request that exceeds one
    // but not the other must surface only the exceeded metric in
    // BudgetStatus::Exceeded.
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = UsageBudgetPolicy {
        enforcement: BudgetEnforcement::Deny,
        budgets: vec![
            UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 1_000,
                window_seconds: 3600,
            },
            UsageBudgetLimit {
                metric: UsageMetricKind::Bytes,
                limit: 10_000,
                window_seconds: 3600,
            },
        ],
    };

    let eval = tracker.record_usage(
        &zone,
        &policy,
        &[UsageMetric::tokens(500), UsageMetric::bytes(20_000)],
    );

    assert_eq!(
        eval.action,
        BudgetAction::Deny,
        "Bytes overrun under Deny mode must trigger Deny"
    );
    assert_budget_status(&eval, UsageMetricKind::Tokens, BudgetStatus::Ok);
    assert_budget_status(&eval, UsageMetricKind::Bytes, BudgetStatus::Exceeded);

    // The to_error must point at the EXCEEDED metric (Bytes), not
    // the OK metric (Tokens).
    match eval.to_error() {
        Some(FcpError::BudgetExceeded { metric, .. }) => {
            assert_eq!(
                metric,
                UsageMetricKind::Bytes,
                "to_error must propagate the exceeded metric, not the OK one"
            );
        }
        other => panic!("expected BudgetExceeded for Bytes, got {other:?}"),
    }
}

#[test]
fn per_zone_isolation_one_zone_overrun_does_not_affect_another() {
    let mut tracker = BudgetTracker::new();
    let work = ZoneId::work();
    let private_zone = ZoneId::private();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    // Drive `work` over its budget.
    let work_eval = tracker.record_usage(&work, &policy, &[token_metric(200)]);
    assert_eq!(work_eval.action, BudgetAction::Deny);

    // `private` must remain untouched even with the same policy.
    let private_eval = tracker.record_usage(&private_zone, &policy, &[token_metric(50)]);
    assert_eq!(
        private_eval.action,
        BudgetAction::Allow,
        "per-zone isolation broken: private's evaluation is affected by work's overrun"
    );
    let entry = private_eval
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry");
    assert_eq!(
        entry.used, 50,
        "private's usage must be its OWN 50, not work's 200"
    );
}

#[test]
fn snapshot_remaining_decreases_as_usage_grows() {
    // The remaining field is what admin-reporting / preflight UI
    // surfaces to operators. It MUST decrease monotonically as
    // usage accumulates within the same window.
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    let after_30 = tracker.record_usage(&zone, &policy, &[token_metric(30)]);
    let r1 = after_30
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry")
        .remaining;
    assert_eq!(r1, 70);

    let after_50 = tracker.record_usage(&zone, &policy, &[token_metric(20)]);
    let r2 = after_50
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry")
        .remaining;
    assert_eq!(r2, 50);
    assert!(
        r2 < r1,
        "remaining must decrease monotonically as usage grows in the same window"
    );
}

#[test]
fn allow_at_exact_limit_is_allowed_not_exceeded() {
    // The cap is `used > budget.limit` for Exceeded; usage exactly
    // AT the limit is therefore Ok / Allow. Pin this boundary.
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    let eval = tracker.record_usage(&zone, &policy, &[token_metric(100)]);
    assert_eq!(
        eval.action,
        BudgetAction::Allow,
        "usage exactly equal to the limit MUST be Allow (cap is exclusive above)"
    );
    assert_budget_status(&eval, UsageMetricKind::Tokens, BudgetStatus::Ok);
}

#[test]
fn empty_metrics_evaluates_as_allow_and_does_not_drift_usage() {
    // record_usage with an empty metrics slice must not bump usage
    // and must evaluate to Allow.
    let mut tracker = BudgetTracker::new();
    let zone = ZoneId::work();
    let policy = budget_for_metric(BudgetEnforcement::Deny, UsageMetricKind::Tokens, 100);

    // Seed some usage first.
    let _ = tracker.record_usage(&zone, &policy, &[token_metric(40)]);

    let empty = tracker.record_usage(&zone, &policy, &[]);
    assert_eq!(empty.action, BudgetAction::Allow);
    let entry = empty
        .snapshot
        .budgets
        .iter()
        .find(|b| b.metric == UsageMetricKind::Tokens)
        .expect("entry");
    assert_eq!(
        entry.used, 40,
        "empty metrics slice must NOT bump usage; total stays at the prior 40"
    );
}
