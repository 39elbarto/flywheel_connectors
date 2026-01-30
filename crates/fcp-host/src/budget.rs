//! Usage budget tracking and enforcement helpers.
//!
//! Tracks per-zone usage against configured budget policies and surfaces
//! snapshots suitable for CLI/operator reporting.

use std::collections::HashMap;

use chrono::Utc;
use fcp_core::{
    BudgetEnforcement, BudgetStatus, UsageBudgetPolicy, UsageBudgetSnapshot, UsageBudgetUsage,
    UsageMetric, UsageMetricKind, ZoneId,
};

/// Action to take when a budget is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAction {
    /// Within budgets.
    Allow,
    /// Exceeded budget but warn-only.
    Warn,
    /// Exceeded budget and deny operations.
    Deny,
}

/// Result of evaluating usage against budgets.
#[derive(Debug, Clone)]
pub struct BudgetEvaluation {
    /// Action to take for the operation.
    pub action: BudgetAction,
    /// Snapshot of budget usage after applying metrics.
    pub snapshot: UsageBudgetSnapshot,
}

/// Tracks usage per zone and enforces budget policies.
#[derive(Debug, Default)]
pub struct BudgetTracker {
    zones: HashMap<ZoneId, ZoneBudgetState>,
}

#[derive(Debug, Default)]
struct ZoneBudgetState {
    metrics: HashMap<UsageMetricKind, MetricWindow>,
}

#[derive(Debug, Clone)]
struct MetricWindow {
    window_seconds: u64,
    window_started_at: u64,
    used: u64,
}

impl BudgetTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record usage metrics for a zone and evaluate budgets.
    #[must_use]
    pub fn record_usage(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        metrics: &[UsageMetric],
    ) -> BudgetEvaluation {
        let now = now_secs();
        let usage_by_kind = aggregate_metrics(metrics);
        let state = self.zones.entry(zone_id.clone()).or_default();

        let mut entries = Vec::new();
        let mut exceeded = false;

        for budget in &policy.budgets {
            let used_delta = usage_by_kind.get(&budget.metric).copied().unwrap_or(0);
            let window = state
                .metrics
                .entry(budget.metric)
                .or_insert_with(|| MetricWindow::new(budget.window_seconds, now));
            window.roll_if_needed(now, budget.window_seconds);
            window.used = window.used.saturating_add(used_delta);

            let status = if window.used > budget.limit {
                exceeded = true;
                BudgetStatus::Exceeded
            } else {
                BudgetStatus::Ok
            };

            let remaining = budget.limit.saturating_sub(window.used);
            entries.push(UsageBudgetUsage {
                metric: budget.metric,
                used: window.used,
                limit: budget.limit,
                remaining,
                window_started_at: window.window_started_at,
                window_resets_at: window
                    .window_started_at
                    .saturating_add(window.window_seconds),
                status,
            });
        }

        let snapshot = UsageBudgetSnapshot {
            zone_id: zone_id.clone(),
            enforcement: policy.enforcement,
            budgets: entries,
            updated_at: now,
        };

        let action = match (exceeded, policy.enforcement) {
            (true, BudgetEnforcement::Deny) => BudgetAction::Deny,
            (true, BudgetEnforcement::Warn) => BudgetAction::Warn,
            (false, _) => BudgetAction::Allow,
        };

        BudgetEvaluation { action, snapshot }
    }

    /// Get a snapshot of current usage for a zone without recording new usage.
    #[must_use]
    pub fn snapshot(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
    ) -> UsageBudgetSnapshot {
        let now = now_secs();
        let state = self.zones.entry(zone_id.clone()).or_default();

        let mut entries = Vec::new();
        for budget in &policy.budgets {
            let window = state
                .metrics
                .entry(budget.metric)
                .or_insert_with(|| MetricWindow::new(budget.window_seconds, now));
            window.roll_if_needed(now, budget.window_seconds);

            let status = if window.used > budget.limit {
                BudgetStatus::Exceeded
            } else {
                BudgetStatus::Ok
            };

            let remaining = budget.limit.saturating_sub(window.used);
            entries.push(UsageBudgetUsage {
                metric: budget.metric,
                used: window.used,
                limit: budget.limit,
                remaining,
                window_started_at: window.window_started_at,
                window_resets_at: window
                    .window_started_at
                    .saturating_add(window.window_seconds),
                status,
            });
        }

        UsageBudgetSnapshot {
            zone_id: zone_id.clone(),
            enforcement: policy.enforcement,
            budgets: entries,
            updated_at: now,
        }
    }
}

impl MetricWindow {
    const fn new(window_seconds: u64, now: u64) -> Self {
        Self {
            window_seconds,
            window_started_at: now,
            used: 0,
        }
    }

    const fn roll_if_needed(&mut self, now: u64, configured_window: u64) {
        if self.window_seconds != configured_window {
            self.window_seconds = configured_window;
            self.window_started_at = now;
            self.used = 0;
            return;
        }

        let elapsed = now.saturating_sub(self.window_started_at);
        if elapsed >= self.window_seconds {
            self.window_started_at = now;
            self.used = 0;
        }
    }
}

fn aggregate_metrics(metrics: &[UsageMetric]) -> HashMap<UsageMetricKind, u64> {
    let mut totals: HashMap<UsageMetricKind, u64> = HashMap::new();
    for metric in metrics {
        let entry = totals.entry(metric.kind).or_insert(0);
        *entry = entry.saturating_add(metric.amount);
    }
    totals
}

fn now_secs() -> u64 {
    let ts = Utc::now().timestamp();
    u64::try_from(ts).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{
        BudgetEnforcement, UsageBudgetLimit, UsageBudgetPolicy, UsageMetricKind, ZoneId,
    };

    #[test]
    fn budget_tracker_warns_on_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        assert_eq!(eval.action, BudgetAction::Warn);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[test]
    fn budget_tracker_denies_on_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 1,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(2)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }
}
