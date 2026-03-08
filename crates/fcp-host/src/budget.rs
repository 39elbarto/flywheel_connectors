//! Usage budget tracking and enforcement helpers.
//!
//! Tracks per-zone usage against configured budget policies and surfaces
//! snapshots suitable for CLI/operator reporting.

use std::collections::HashMap;

use chrono::Utc;
use fcp_async_core::sync::{Mutex, RwLock};
use fcp_core::{
    BudgetEnforcement, BudgetStatus, FcpError, UsageBudgetPolicy, UsageBudgetSnapshot,
    UsageBudgetUsage, UsageMetric, UsageMetricKind, ZoneId,
};

use crate::{PolicyEngine, PreflightRequest, PreflightResponse};

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

impl BudgetEvaluation {
    /// Convert a denial into an FCP error.
    #[must_use]
    pub fn to_error(&self) -> Option<FcpError> {
        if self.action != BudgetAction::Deny {
            return None;
        }

        let exceeded = self
            .snapshot
            .budgets
            .iter()
            .find(|entry| entry.status == BudgetStatus::Exceeded)?;
        let window_seconds = exceeded
            .window_resets_at
            .saturating_sub(exceeded.window_started_at);

        Some(FcpError::BudgetExceeded {
            metric: exceeded.metric,
            used: exceeded.used,
            limit: exceeded.limit,
            window_seconds,
        })
    }
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
            (true, BudgetEnforcement::Deny) => {
                let exceeded_budgets: Vec<_> = snapshot
                    .budgets
                    .iter()
                    .filter(|b| b.status == BudgetStatus::Exceeded)
                    .collect();
                tracing::warn!(
                    zone_id = %zone_id,
                    action = "deny",
                    exceeded_count = exceeded_budgets.len(),
                    "budget exceeded"
                );
                for exceeded in exceeded_budgets {
                    tracing::debug!(
                        zone_id = %zone_id,
                        metric = ?exceeded.metric,
                        used = exceeded.used,
                        limit = exceeded.limit,
                        remaining = exceeded.remaining,
                        "budget limit exceeded"
                    );
                }
                BudgetAction::Deny
            }
            (true, BudgetEnforcement::Warn) => {
                let exceeded_budgets: Vec<_> = snapshot
                    .budgets
                    .iter()
                    .filter(|b| b.status == BudgetStatus::Exceeded)
                    .collect();
                tracing::warn!(
                    zone_id = %zone_id,
                    action = "warn",
                    exceeded_count = exceeded_budgets.len(),
                    "budget warning threshold exceeded"
                );
                for exceeded in exceeded_budgets {
                    tracing::debug!(
                        zone_id = %zone_id,
                        metric = ?exceeded.metric,
                        used = exceeded.used,
                        limit = exceeded.limit,
                        remaining = exceeded.remaining,
                        "budget limit exceeded"
                    );
                }
                BudgetAction::Warn
            }
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

/// Policy engine that surfaces budget snapshots and enforces deny-on-exceeded.
#[derive(Debug)]
pub struct BudgetPolicyEngine {
    tracker: Mutex<BudgetTracker>,
    policies: RwLock<HashMap<ZoneId, UsageBudgetPolicy>>,
}

impl BudgetPolicyEngine {
    /// Create a new budget policy engine with no policies configured.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a budget policy engine with predefined policies.
    #[must_use]
    pub fn with_policies(policies: HashMap<ZoneId, UsageBudgetPolicy>) -> Self {
        Self {
            tracker: Mutex::new(BudgetTracker::new()),
            policies: RwLock::new(policies),
        }
    }

    /// Insert or update the budget policy for a zone.
    pub async fn upsert_policy(&self, zone_id: ZoneId, policy: UsageBudgetPolicy) {
        let mut write = self.policies.write().await;
        write.insert(zone_id, policy);
    }

    /// Remove the budget policy for a zone.
    pub async fn remove_policy(&self, zone_id: &ZoneId) -> Option<UsageBudgetPolicy> {
        let mut write = self.policies.write().await;
        write.remove(zone_id)
    }

    /// Record usage metrics and evaluate budgets for a zone.
    pub async fn record_usage(
        &self,
        zone_id: &ZoneId,
        metrics: &[UsageMetric],
    ) -> Option<BudgetEvaluation> {
        let policy = {
            let read = self.policies.read().await;
            read.get(zone_id).cloned()
        }?;
        let mut tracker = self.tracker.lock().await;
        Some(tracker.record_usage(zone_id, &policy, metrics))
    }

    /// Fetch the latest budget snapshot for a zone (if configured).
    pub async fn snapshot(&self, zone_id: &ZoneId) -> Option<UsageBudgetSnapshot> {
        let policy = {
            let read = self.policies.read().await;
            read.get(zone_id).cloned()
        }?;
        let mut tracker = self.tracker.lock().await;
        Some(tracker.snapshot(zone_id, &policy))
    }
}

impl Default for BudgetPolicyEngine {
    fn default() -> Self {
        Self {
            tracker: Mutex::new(BudgetTracker::new()),
            policies: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for BudgetPolicyEngine {
    async fn evaluate_preflight(&self, request: &PreflightRequest) -> PreflightResponse {
        let mut response = PreflightResponse::allowed();
        let Some(zone_id) = request.zone_id.as_ref() else {
            return response;
        };
        let policy = {
            let read = self.policies.read().await;
            read.get(zone_id).cloned()
        };
        let Some(policy) = policy else {
            return response;
        };

        let snapshot = self.tracker.lock().await.snapshot(zone_id, &policy);
        let exceeded = snapshot
            .budgets
            .iter()
            .any(|entry| entry.status == BudgetStatus::Exceeded);

        response.budget_status = Some(snapshot);
        if exceeded && policy.enforcement == BudgetEnforcement::Deny {
            response.allowed = false;
            response.reason = Some("usage budget exceeded".to_string());
        }

        response
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
        if self.window_seconds != configured_window || configured_window == 0 {
            self.window_seconds = configured_window;
            self.window_started_at = now;
            self.used = 0;
            return;
        }

        let elapsed = now.saturating_sub(self.window_started_at);
        if elapsed >= self.window_seconds {
            // Align the new window start time to prevent drift
            let windows_passed = elapsed / self.window_seconds;
            self.window_started_at = self
                .window_started_at
                .saturating_add(windows_passed.saturating_mul(self.window_seconds));
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

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_denies_on_exceeded_preflight() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        let eval = engine
            .record_usage(&zone, &[UsageMetric::tokens(150)])
            .await
            .expect("budget policy");
        assert_eq!(eval.action, BudgetAction::Deny);

        let request = PreflightRequest {
            connector_id: fcp_core::ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone.clone()),
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(!response.allowed);
        assert_eq!(response.reason.as_deref(), Some("usage budget exceeded"));
        let snapshot = response.budget_status.expect("budget status");
        assert_eq!(snapshot.zone_id, zone);
        assert_eq!(snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[test]
    fn budget_tracker_allows_when_within_budget() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Ok);
        assert_eq!(eval.snapshot.budgets[0].used, 50);
        assert_eq!(eval.snapshot.budgets[0].remaining, 50);
    }

    #[test]
    fn budget_tracker_allows_with_no_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Ok);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
        assert_eq!(eval.snapshot.budgets[0].remaining, 100);
    }

    #[test]
    fn budget_evaluation_to_error_returns_budget_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 10,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(15)]);
        assert_eq!(eval.action, BudgetAction::Deny);

        let error = eval.to_error().expect("expected FcpError::BudgetExceeded");
        if let FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        } = error
        {
            assert_eq!(metric, UsageMetricKind::Requests);
            assert_eq!(used, 15);
            assert_eq!(limit, 10);
            assert_eq!(window_seconds, 3600);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    #[test]
    fn budget_evaluation_to_error_returns_none_for_allow() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert!(eval.to_error().is_none());
    }

    #[test]
    fn budget_evaluation_to_error_returns_none_for_warn() {
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
        assert!(eval.to_error().is_none());
    }

    #[test]
    fn budget_tracker_accumulates_usage_within_window() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();

        let eval1 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(30)]);
        assert_eq!(eval1.action, BudgetAction::Allow);
        assert_eq!(eval1.snapshot.budgets[0].used, 30);

        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(40)]);
        assert_eq!(eval2.action, BudgetAction::Allow);
        assert_eq!(eval2.snapshot.budgets[0].used, 70);

        let eval3 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval3.action, BudgetAction::Deny);
        assert_eq!(eval3.snapshot.budgets[0].used, 120);
        assert_eq!(eval3.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[test]
    fn budget_tracker_tracks_zones_independently() {
        let zone_work = ZoneId::work();
        let zone_private = ZoneId::private();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();

        let eval_work = tracker.record_usage(&zone_work, &policy, &[UsageMetric::tokens(80)]);
        assert_eq!(eval_work.action, BudgetAction::Allow);
        assert_eq!(eval_work.snapshot.budgets[0].used, 80);
        assert_eq!(eval_work.snapshot.zone_id, zone_work);

        let eval_private = tracker.record_usage(&zone_private, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval_private.action, BudgetAction::Allow);
        assert_eq!(eval_private.snapshot.budgets[0].used, 50);
        assert_eq!(eval_private.snapshot.zone_id, zone_private);

        let eval_work2 = tracker.record_usage(&zone_work, &policy, &[UsageMetric::tokens(30)]);
        assert_eq!(eval_work2.action, BudgetAction::Deny);
        assert_eq!(eval_work2.snapshot.budgets[0].used, 110);

        let eval_private2 =
            tracker.record_usage(&zone_private, &policy, &[UsageMetric::tokens(30)]);
        assert_eq!(eval_private2.action, BudgetAction::Allow);
        assert_eq!(eval_private2.snapshot.budgets[0].used, 80);
    }

    #[test]
    fn budget_snapshot_reflects_current_state() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(45)]);

        let snapshot = tracker.snapshot(&zone, &policy);
        assert_eq!(snapshot.zone_id, zone);
        assert_eq!(snapshot.budgets[0].used, 45);
        assert_eq!(snapshot.budgets[0].limit, 100);
        assert_eq!(snapshot.budgets[0].remaining, 55);
        assert_eq!(snapshot.budgets[0].status, BudgetStatus::Ok);

        let snapshot2 = tracker.snapshot(&zone, &policy);
        assert_eq!(snapshot2.budgets[0].used, 45);
    }

    #[test]
    fn budget_tracker_aggregates_multiple_metrics() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 10,
                    window_seconds: 60,
                },
            ],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[
                UsageMetric::tokens(30),
                UsageMetric::requests(5),
                UsageMetric::tokens(20),
            ],
        );

        assert_eq!(eval.action, BudgetAction::Allow);
        let tokens_entry = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .expect("tokens entry");
        assert_eq!(tokens_entry.used, 50);
        let requests_entry = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Requests)
            .expect("requests entry");
        assert_eq!(requests_entry.used, 5);
    }

    #[test]
    fn budget_snapshot_includes_zone_id() {
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
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);

        assert_eq!(eval.snapshot.zone_id, zone);
        assert_eq!(eval.snapshot.enforcement, BudgetEnforcement::Warn);
    }

    #[test]
    fn budget_deny_emits_structured_log_with_zone_id() {
        use fcp_testkit::LogCapture;

        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("warn");

        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        assert_eq!(eval.action, BudgetAction::Deny);

        let logs = capture.jsonl();
        assert!(
            logs.contains("budget exceeded"),
            "expected 'budget exceeded' in logs, got: {logs}"
        );
        assert!(
            logs.contains("zone_id"),
            "expected 'zone_id' in logs, got: {logs}"
        );
        assert!(
            logs.contains("deny"),
            "expected 'deny' action in logs, got: {logs}"
        );
    }

    #[test]
    fn budget_warn_emits_structured_log_with_zone_id() {
        use fcp_testkit::LogCapture;

        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("warn");

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

        let logs = capture.jsonl();
        assert!(
            logs.contains("budget warning threshold exceeded"),
            "expected 'budget warning threshold exceeded' in logs, got: {logs}"
        );
        assert!(
            logs.contains("zone_id"),
            "expected 'zone_id' in logs, got: {logs}"
        );
        assert!(
            logs.contains("warn"),
            "expected 'warn' action in logs, got: {logs}"
        );
    }

    // ── BudgetAction tests ──

    #[test]
    fn budget_action_eq_and_copy() {
        let a = BudgetAction::Allow;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(BudgetAction::Allow, BudgetAction::Deny);
        assert_ne!(BudgetAction::Warn, BudgetAction::Deny);
    }

    // ── BudgetTracker default/new ──

    #[test]
    fn budget_tracker_new_is_empty() {
        let tracker = BudgetTracker::new();
        assert!(tracker.zones.is_empty());
    }

    #[test]
    fn budget_tracker_default_is_new() {
        let tracker = BudgetTracker::default();
        assert!(tracker.zones.is_empty());
    }

    // ── aggregate_metrics tests ──

    #[test]
    fn aggregate_metrics_empty() {
        let result = aggregate_metrics(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn aggregate_metrics_deduplicates() {
        let metrics = vec![
            UsageMetric::tokens(10),
            UsageMetric::tokens(20),
            UsageMetric::requests(5),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 30);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 5);
    }

    // ── BudgetEvaluation to_error edge cases ──

    #[test]
    fn budget_evaluation_to_error_deny_with_empty_budgets() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![],
                updated_at: 0,
            },
        };
        // No exceeded entry to find, returns None even though action is Deny
        assert!(eval.to_error().is_none());
    }

    // ── BudgetPolicyEngine async tests ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_snapshot_without_policy_returns_none() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        assert!(engine.snapshot(&zone).await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_usage_without_policy_returns_none() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        assert!(
            engine
                .record_usage(&zone, &[UsageMetric::tokens(10)])
                .await
                .is_none()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_remove_policy() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        engine.upsert_policy(zone.clone(), policy).await;
        assert!(engine.snapshot(&zone).await.is_some());

        let removed = engine.remove_policy(&zone).await;
        assert!(removed.is_some());
        assert!(engine.snapshot(&zone).await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_upsert_replaces() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();

        let policy1 = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        engine.upsert_policy(zone.clone(), policy1).await;

        let snap1 = engine.snapshot(&zone).await.unwrap();
        assert_eq!(snap1.enforcement, BudgetEnforcement::Warn);

        let policy2 = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 200,
                window_seconds: 120,
            }],
        };
        engine.upsert_policy(zone.clone(), policy2).await;

        let snap2 = engine.snapshot(&zone).await.unwrap();
        assert_eq!(snap2.enforcement, BudgetEnforcement::Deny);
        assert_eq!(snap2.budgets[0].limit, 200);
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_allows_within_budget() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        // Record some usage within budget
        let eval = engine
            .record_usage(&zone, &[UsageMetric::tokens(50)])
            .await
            .unwrap();
        assert_eq!(eval.action, BudgetAction::Allow);

        let request = PreflightRequest {
            connector_id: fcp_core::ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone),
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
        assert!(response.reason.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_no_zone_always_allows() {
        let engine = BudgetPolicyEngine::new();

        let request = PreflightRequest {
            connector_id: fcp_core::ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: None,
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_warn_enforcement_allows_preflight() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        // Exceed the budget
        engine
            .record_usage(&zone, &[UsageMetric::tokens(200)])
            .await;

        let request = PreflightRequest {
            connector_id: fcp_core::ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone),
        };

        // Warn enforcement does not deny
        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
    }

    // ── Budget snapshot with no prior usage ──

    #[test]
    fn budget_snapshot_fresh_zone_shows_zero_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 500,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets[0].used, 0);
        assert_eq!(snap.budgets[0].remaining, 500);
        assert_eq!(snap.budgets[0].status, BudgetStatus::Ok);
    }

    // ── Multiple budget limits ──

    #[test]
    fn budget_tracker_partial_exceed_still_denies() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 1000,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 5,
                    window_seconds: 60,
                },
            ],
        };

        let mut tracker = BudgetTracker::new();
        // Exceed requests but not tokens
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[UsageMetric::tokens(100), UsageMetric::requests(10)],
        );
        assert_eq!(eval.action, BudgetAction::Deny);

        let tokens = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .unwrap();
        assert_eq!(tokens.status, BudgetStatus::Ok);

        let requests = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Requests)
            .unwrap();
        assert_eq!(requests.status, BudgetStatus::Exceeded);
    }

    // ── Empty policy budgets ──

    #[test]
    fn budget_tracker_empty_budgets_always_allows() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(1_000_000)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert!(eval.snapshot.budgets.is_empty());
    }

    // ── MetricWindow roll_if_needed edge cases ──

    #[test]
    fn metric_window_roll_resets_when_window_size_changes() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 42;
        // configured_window differs from window_seconds → full reset
        window.roll_if_needed(1005, 120);
        assert_eq!(window.window_seconds, 120);
        assert_eq!(window.window_started_at, 1005);
        assert_eq!(window.used, 0);
    }

    #[test]
    fn metric_window_roll_resets_when_configured_window_zero() {
        let mut window = MetricWindow::new(0, 1000);
        window.used = 99;
        // configured_window == 0 → always reset
        window.roll_if_needed(1050, 0);
        assert_eq!(window.window_started_at, 1050);
        assert_eq!(window.used, 0);
    }

    #[test]
    fn metric_window_roll_no_roll_within_window() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 10;
        // 30s elapsed < 60s window → no roll
        window.roll_if_needed(1030, 60);
        assert_eq!(window.used, 10);
        assert_eq!(window.window_started_at, 1000);
    }

    #[test]
    fn metric_window_roll_exactly_at_boundary() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 50;
        // elapsed == window_seconds → rolls
        window.roll_if_needed(1060, 60);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1060);
    }

    #[test]
    fn metric_window_roll_multiple_windows_passed() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 77;
        // 180s elapsed = 3 windows → should align start to 1000 + 3*60 = 1180
        window.roll_if_needed(1180, 60);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1180);
    }

    #[test]
    fn metric_window_roll_partial_extra_window() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 33;
        // 150s = 2 full windows + 30s partial
        // windows_passed = 150/60 = 2, new start = 1000 + 2*60 = 1120
        window.roll_if_needed(1150, 60);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1120);
    }

    #[test]
    fn metric_window_roll_now_before_start_saturates() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 5;
        // now < window_started_at → saturating_sub gives 0, no roll
        window.roll_if_needed(500, 60);
        assert_eq!(window.used, 5);
        assert_eq!(window.window_started_at, 1000);
    }

    // ── aggregate_metrics edge cases ──

    #[test]
    fn aggregate_metrics_saturates_on_overflow() {
        let metrics = vec![UsageMetric::tokens(u64::MAX), UsageMetric::tokens(1)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), u64::MAX);
    }

    #[test]
    fn aggregate_metrics_single_entry() {
        let metrics = vec![UsageMetric::requests(42)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(result.len(), 1);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 42);
    }

    // ── Budget limit = 0 ──

    #[test]
    fn budget_tracker_zero_limit_exceeds_on_any_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 0,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(1)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    #[test]
    fn budget_tracker_zero_limit_allows_zero_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 0,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
    }

    // ── BudgetEvaluation to_error picks first exceeded ──

    #[test]
    fn budget_evaluation_to_error_picks_first_exceeded_budget() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 10,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 5,
                    window_seconds: 60,
                },
            ],
        };

        let mut tracker = BudgetTracker::new();
        // Exceed both
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[UsageMetric::tokens(20), UsageMetric::requests(10)],
        );
        assert_eq!(eval.action, BudgetAction::Deny);

        let error = eval.to_error().expect("should produce error");
        // First exceeded in the budgets vec is Tokens
        if let FcpError::BudgetExceeded { metric, .. } = error {
            assert_eq!(metric, UsageMetricKind::Tokens);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── BudgetPolicyEngine::with_policies ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_with_policies_constructor() {
        let zone = ZoneId::work();
        let mut policies = HashMap::new();
        policies.insert(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 500,
                    window_seconds: 3600,
                }],
            },
        );

        let engine = BudgetPolicyEngine::with_policies(policies);
        let snap = engine.snapshot(&zone).await.unwrap();
        assert_eq!(snap.budgets[0].limit, 500);
        assert_eq!(snap.budgets[0].used, 0);
        assert_eq!(snap.enforcement, BudgetEnforcement::Deny);
    }

    // ── BudgetPolicyEngine remove_policy idempotency ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_remove_policy_idempotent() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();

        // Remove from empty → None
        assert!(engine.remove_policy(&zone).await.is_none());

        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![],
                },
            )
            .await;

        // First removal → Some
        assert!(engine.remove_policy(&zone).await.is_some());
        // Second removal → None
        assert!(engine.remove_policy(&zone).await.is_none());
    }

    // ── BudgetPolicyEngine record_usage with empty metrics ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_usage_empty_metrics() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        let eval = engine.record_usage(&zone, &[]).await.unwrap();
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
    }

    // ── BudgetAction Debug ──

    #[test]
    fn budget_action_debug() {
        assert_eq!(format!("{:?}", BudgetAction::Allow), "Allow");
        assert_eq!(format!("{:?}", BudgetAction::Warn), "Warn");
        assert_eq!(format!("{:?}", BudgetAction::Deny), "Deny");
    }

    // ── BudgetEvaluation clone ──

    #[test]
    fn budget_evaluation_clone() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Allow,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![],
                updated_at: 123,
            },
        };
        let cloned = eval.clone();
        assert_eq!(cloned.action, eval.action);
        assert_eq!(cloned.snapshot.zone_id, eval.snapshot.zone_id);
        assert_eq!(cloned.snapshot.updated_at, eval.snapshot.updated_at);
    }

    // ── Snapshot window timing ──

    #[test]
    fn budget_snapshot_window_resets_at_correct() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(10)]);
        let entry = &eval.snapshot.budgets[0];
        // resets_at should be started_at + window_seconds
        assert_eq!(entry.window_resets_at, entry.window_started_at + 3600);
    }

    // ── Multiple record_usage calls with different metric types ──

    #[test]
    fn budget_tracker_untracked_metric_ignored() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        // Record requests but policy only tracks tokens
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1000)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
    }

    // ── Budget enforcement field in snapshot ──

    #[test]
    fn budget_snapshot_enforcement_preserved() {
        let zone = ZoneId::work();
        for enforcement in [BudgetEnforcement::Deny, BudgetEnforcement::Warn] {
            let policy = UsageBudgetPolicy {
                enforcement,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                }],
            };

            let mut tracker = BudgetTracker::new();
            let snap = tracker.snapshot(&zone, &policy);
            assert_eq!(snap.enforcement, enforcement);
        }
    }

    // ── BudgetAction debug for all variants ──

    #[test]
    fn budget_action_all_variants_debug() {
        let actions = [BudgetAction::Allow, BudgetAction::Warn, BudgetAction::Deny];
        for action in &actions {
            let dbg = format!("{action:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── BudgetEvaluation debug ──

    #[test]
    fn budget_evaluation_debug() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Allow,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![],
                updated_at: 0,
            },
        };
        let dbg = format!("{eval:?}");
        assert!(dbg.contains("BudgetEvaluation"));
        assert!(dbg.contains("Allow"));
    }

    // ── BudgetTracker debug ──

    #[test]
    fn budget_tracker_debug() {
        let tracker = BudgetTracker::new();
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("BudgetTracker"));
    }

    // ── BudgetPolicyEngine debug ──

    #[test]
    fn budget_policy_engine_debug() {
        let engine = BudgetPolicyEngine::new();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("BudgetPolicyEngine"));
    }

    // ── BudgetPolicyEngine default ──

    #[test]
    fn budget_policy_engine_default() {
        let engine = BudgetPolicyEngine::default();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("BudgetPolicyEngine"));
    }

    // ── MetricWindow constructor ──

    #[test]
    fn metric_window_new_fields() {
        let w = MetricWindow::new(300, 5000);
        assert_eq!(w.window_seconds, 300);
        assert_eq!(w.window_started_at, 5000);
        assert_eq!(w.used, 0);
    }

    // ── MetricWindow clone ──

    #[test]
    fn metric_window_clone() {
        let original = MetricWindow::new(60, 1000);
        let cloned = original.clone();
        assert_eq!(original.window_seconds, cloned.window_seconds);
        assert_eq!(original.window_started_at, cloned.window_started_at);
        assert_eq!(original.used, cloned.used);
    }

    // ── aggregate_metrics with many entries ──

    #[test]
    fn aggregate_metrics_many_same_kind() {
        let metrics: Vec<UsageMetric> = (0..100).map(|_| UsageMetric::tokens(1)).collect();
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 100);
    }

    // ── Budget tracker snapshot does not modify state ──

    #[test]
    fn budget_tracker_snapshot_idempotent() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        let snap1 = tracker.snapshot(&zone, &policy);
        let snap2 = tracker.snapshot(&zone, &policy);
        assert_eq!(snap1.budgets[0].used, snap2.budgets[0].used);
        assert_eq!(snap1.budgets[0].remaining, snap2.budgets[0].remaining);
    }

    // ── Budget evaluation to_error with non-exceeded budgets ──

    #[test]
    fn budget_evaluation_deny_no_exceeded_returns_none() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 50,
                    limit: 100,
                    remaining: 50,
                    window_started_at: 0,
                    window_resets_at: 60,
                    status: BudgetStatus::Ok,
                }],
                updated_at: 0,
            },
        };
        // Even though action is Deny, no budget has Exceeded status
        assert!(eval.to_error().is_none());
    }

    // ── Budget saturating add ──

    #[test]
    fn budget_tracker_saturating_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: u64::MAX,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(u64::MAX - 10)]);
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(20)]);
        // Should saturate at u64::MAX
        assert_eq!(eval.snapshot.budgets[0].used, u64::MAX);
    }

    // ── now_secs ──

    #[test]
    fn now_secs_is_positive() {
        let ts = now_secs();
        // Should be well past epoch year 2000 = 946684800
        assert!(ts > 946_684_800);
    }

    // ── BudgetAction clone and copy semantics ──

    #[test]
    fn budget_action_clone_all_variants() {
        for action in [BudgetAction::Allow, BudgetAction::Warn, BudgetAction::Deny] {
            let cloned = action;
            assert_eq!(action, cloned);
        }
    }

    #[test]
    fn budget_action_ne_all_pairs() {
        assert_ne!(BudgetAction::Allow, BudgetAction::Warn);
        assert_ne!(BudgetAction::Allow, BudgetAction::Deny);
        assert_ne!(BudgetAction::Warn, BudgetAction::Deny);
    }

    // ── BudgetAction Eq reflexivity ──

    #[test]
    fn budget_action_eq_reflexive() {
        let a = BudgetAction::Allow;
        let w = BudgetAction::Warn;
        let d = BudgetAction::Deny;
        assert_eq!(a, a);
        assert_eq!(w, w);
        assert_eq!(d, d);
    }

    // ── BudgetEvaluation to_error window_seconds calculation ──

    #[test]
    fn budget_evaluation_to_error_window_seconds_from_timestamps() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Bytes,
                    used: 2000,
                    limit: 1000,
                    remaining: 0,
                    window_started_at: 1000,
                    window_resets_at: 4600,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 2000,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        } = error
        {
            assert_eq!(metric, UsageMetricKind::Bytes);
            assert_eq!(used, 2000);
            assert_eq!(limit, 1000);
            // window_seconds = resets_at - started_at = 4600 - 1000 = 3600
            assert_eq!(window_seconds, 3600);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    #[test]
    fn budget_evaluation_to_error_saturating_sub_on_window_times() {
        // When resets_at < started_at (shouldn't happen, but test saturating behavior)
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 200,
                    limit: 100,
                    remaining: 0,
                    window_started_at: 5000,
                    window_resets_at: 3000,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 5000,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded { window_seconds, .. } = error {
            assert_eq!(window_seconds, 0);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── aggregate_metrics with all metric kinds ──

    #[test]
    fn aggregate_metrics_all_kinds() {
        let metrics = vec![
            UsageMetric::tokens(10),
            UsageMetric::requests(5),
            UsageMetric::bytes(1024),
            UsageMetric::api_credits(3),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(result.len(), 4);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 10);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 5);
        assert_eq!(*result.get(&UsageMetricKind::Bytes).unwrap(), 1024);
        assert_eq!(*result.get(&UsageMetricKind::ApiCredits).unwrap(), 3);
    }

    #[test]
    fn aggregate_metrics_triple_same_kind() {
        let metrics = vec![
            UsageMetric::bytes(100),
            UsageMetric::bytes(200),
            UsageMetric::bytes(300),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Bytes).unwrap(), 600);
    }

    #[test]
    fn aggregate_metrics_zero_amounts() {
        let metrics = vec![UsageMetric::tokens(0), UsageMetric::tokens(0)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 0);
    }

    #[test]
    fn aggregate_metrics_mixed_zero_and_nonzero() {
        let metrics = vec![
            UsageMetric::requests(0),
            UsageMetric::requests(42),
            UsageMetric::requests(0),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 42);
    }

    // ── MetricWindow edge cases ──

    #[test]
    fn metric_window_new_zero_window() {
        let w = MetricWindow::new(0, 9999);
        assert_eq!(w.window_seconds, 0);
        assert_eq!(w.window_started_at, 9999);
        assert_eq!(w.used, 0);
    }

    #[test]
    fn metric_window_new_max_values() {
        let w = MetricWindow::new(u64::MAX, u64::MAX);
        assert_eq!(w.window_seconds, u64::MAX);
        assert_eq!(w.window_started_at, u64::MAX);
        assert_eq!(w.used, 0);
    }

    #[test]
    fn metric_window_roll_one_second_before_boundary() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 25;
        // 59s elapsed < 60s → no roll
        window.roll_if_needed(1059, 60);
        assert_eq!(window.used, 25);
        assert_eq!(window.window_started_at, 1000);
    }

    #[test]
    fn metric_window_roll_one_second_after_boundary() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 25;
        // 61s elapsed >= 60s → roll
        window.roll_if_needed(1061, 60);
        assert_eq!(window.used, 0);
        // 1 full window passed, new start = 1000 + 60 = 1060
        assert_eq!(window.window_started_at, 1060);
    }

    #[test]
    fn metric_window_roll_max_elapsed() {
        let mut window = MetricWindow::new(60, 0);
        window.used = 99;
        // Very large elapsed time
        window.roll_if_needed(u64::MAX, 60);
        assert_eq!(window.used, 0);
    }

    #[test]
    fn metric_window_roll_window_change_from_nonzero_to_different() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 50;
        // Change window size from 60 to 300 → full reset
        window.roll_if_needed(1010, 300);
        assert_eq!(window.window_seconds, 300);
        assert_eq!(window.window_started_at, 1010);
        assert_eq!(window.used, 0);
    }

    #[test]
    fn metric_window_clone_preserves_used() {
        let mut original = MetricWindow::new(120, 5000);
        original.used = 77;
        let cloned = original.clone();
        assert_eq!(original.window_seconds, cloned.window_seconds);
        assert_eq!(original.window_started_at, cloned.window_started_at);
        assert_eq!(original.used, cloned.used);
    }

    // ── BudgetTracker with multiple zones and multiple metrics ──

    #[test]
    fn budget_tracker_three_zones_independent() {
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::private();
        let zone_c = ZoneId::owner();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 50,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone_a, &policy, &[UsageMetric::tokens(30)]);
        let _ = tracker.record_usage(&zone_b, &policy, &[UsageMetric::tokens(40)]);
        let _ = tracker.record_usage(&zone_c, &policy, &[UsageMetric::tokens(10)]);

        let snap_a = tracker.snapshot(&zone_a, &policy);
        let snap_b = tracker.snapshot(&zone_b, &policy);
        let snap_c = tracker.snapshot(&zone_c, &policy);

        assert_eq!(snap_a.budgets[0].used, 30);
        assert_eq!(snap_b.budgets[0].used, 40);
        assert_eq!(snap_c.budgets[0].used, 10);
    }

    #[test]
    fn budget_tracker_multiple_metrics_independent_tracking() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 1000,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 100,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Bytes,
                    limit: 1_000_000,
                    window_seconds: 60,
                },
            ],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[
                UsageMetric::tokens(500),
                UsageMetric::requests(10),
                UsageMetric::bytes(500_000),
            ],
        );

        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets.len(), 3);

        let tokens = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .unwrap();
        assert_eq!(tokens.used, 500);
        assert_eq!(tokens.remaining, 500);

        let requests = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Requests)
            .unwrap();
        assert_eq!(requests.used, 10);
        assert_eq!(requests.remaining, 90);

        let bytes_entry = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Bytes)
            .unwrap();
        assert_eq!(bytes_entry.used, 500_000);
        assert_eq!(bytes_entry.remaining, 500_000);
    }

    // ── Budget tracker: exceed exactly at limit ──

    #[test]
    fn budget_tracker_exactly_at_limit_allows() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(100)]);
        // used == limit is NOT exceeded (> check)
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Ok);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    #[test]
    fn budget_tracker_one_over_limit_denies() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(101)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    // ── Budget tracker: large limit ──

    #[test]
    fn budget_tracker_large_limit_allows_large_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Bytes,
                limit: u64::MAX - 1,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::bytes(u64::MAX - 1)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, u64::MAX - 1);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    // ── Budget tracker: zero usage on zero limit ──

    #[test]
    fn budget_tracker_zero_usage_zero_limit_allows() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 0,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(0)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    // ── Budget evaluation clone preserves all fields ──

    #[test]
    fn budget_evaluation_clone_with_budgets() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::private(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Tokens,
                        used: 200,
                        limit: 100,
                        remaining: 0,
                        window_started_at: 1000,
                        window_resets_at: 1060,
                        status: BudgetStatus::Exceeded,
                    },
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Requests,
                        used: 3,
                        limit: 10,
                        remaining: 7,
                        window_started_at: 1000,
                        window_resets_at: 1060,
                        status: BudgetStatus::Ok,
                    },
                ],
                updated_at: 1050,
            },
        };
        let cloned = eval.clone();
        assert_eq!(cloned.action, eval.action);
        assert_eq!(cloned.snapshot.zone_id, eval.snapshot.zone_id);
        assert_eq!(cloned.snapshot.enforcement, eval.snapshot.enforcement);
        assert_eq!(cloned.snapshot.budgets.len(), eval.snapshot.budgets.len());
        assert_eq!(cloned.snapshot.budgets[0].used, eval.snapshot.budgets[0].used);
        assert_eq!(cloned.snapshot.budgets[1].remaining, eval.snapshot.budgets[1].remaining);
        assert_eq!(cloned.snapshot.updated_at, eval.snapshot.updated_at);
    }

    // ── Budget evaluation debug with populated budgets ──

    #[test]
    fn budget_evaluation_debug_with_entries() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Warn,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 150,
                    limit: 100,
                    remaining: 0,
                    window_started_at: 0,
                    window_resets_at: 60,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 30,
            },
        };
        let dbg = format!("{eval:?}");
        assert!(dbg.contains("Warn"));
        assert!(dbg.contains("Exceeded"));
        assert!(dbg.contains("150"));
    }

    // ── BudgetTracker records different zones with different policies ──

    #[test]
    fn budget_tracker_different_policies_per_zone() {
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::private();

        let policy_a = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 50,
                window_seconds: 60,
            }],
        };
        let policy_b = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 200,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval_a = tracker.record_usage(&zone_a, &policy_a, &[UsageMetric::tokens(60)]);
        let eval_b = tracker.record_usage(&zone_b, &policy_b, &[UsageMetric::tokens(60)]);

        assert_eq!(eval_a.action, BudgetAction::Deny);
        assert_eq!(eval_b.action, BudgetAction::Allow);
    }

    // ── BudgetTracker: recording with metric not in policy ──

    #[test]
    fn budget_tracker_extra_metrics_not_in_policy_ignored() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 10,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[
                UsageMetric::tokens(999_999),
                UsageMetric::bytes(999_999),
                UsageMetric::requests(5),
            ],
        );
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets.len(), 1);
        assert_eq!(eval.snapshot.budgets[0].used, 5);
    }

    // ── Snapshot updated_at is recent ──

    #[test]
    fn budget_snapshot_updated_at_is_recent() {
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
        let snap = tracker.snapshot(&zone, &policy);
        // updated_at should be a recent timestamp
        assert!(snap.updated_at > 946_684_800);
    }

    // ── Budget evaluation to_error with multiple exceeded entries picks first ──

    #[test]
    fn budget_evaluation_to_error_skips_ok_finds_first_exceeded() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Tokens,
                        used: 50,
                        limit: 100,
                        remaining: 50,
                        window_started_at: 0,
                        window_resets_at: 60,
                        status: BudgetStatus::Ok,
                    },
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Requests,
                        used: 20,
                        limit: 10,
                        remaining: 0,
                        window_started_at: 0,
                        window_resets_at: 60,
                        status: BudgetStatus::Exceeded,
                    },
                ],
                updated_at: 30,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded { metric, used, limit, .. } = error {
            assert_eq!(metric, UsageMetricKind::Requests);
            assert_eq!(used, 20);
            assert_eq!(limit, 10);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── BudgetTracker: multiple records accumulate ──

    #[test]
    fn budget_tracker_five_incremental_records() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 500,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        for _ in 0u64..5 {
            let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(80)]);
        }
        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets[0].used, 400);
        assert_eq!(snap.budgets[0].remaining, 100);
        assert_eq!(snap.budgets[0].status, BudgetStatus::Ok);
    }

    #[test]
    fn budget_tracker_accumulate_to_exactly_deny() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 3,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let e1 = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1)]);
        assert_eq!(e1.action, BudgetAction::Allow);
        let e2 = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1)]);
        assert_eq!(e2.action, BudgetAction::Allow);
        let e3 = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1)]);
        // 3 == limit → still allowed (> not >=)
        assert_eq!(e3.action, BudgetAction::Allow);
        let e4 = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1)]);
        assert_eq!(e4.action, BudgetAction::Deny);
        assert_eq!(e4.snapshot.budgets[0].used, 4);
    }

    // ── Snapshot with no budgets in policy ──

    #[test]
    fn budget_snapshot_empty_policy_returns_empty_budgets() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![],
        };

        let mut tracker = BudgetTracker::new();
        let snap = tracker.snapshot(&zone, &policy);
        assert!(snap.budgets.is_empty());
        assert_eq!(snap.zone_id, zone);
        assert_eq!(snap.enforcement, BudgetEnforcement::Warn);
    }

    // ── BudgetPolicyEngine async: multi-zone isolation ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_multi_zone_independent() {
        let engine = BudgetPolicyEngine::new();
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::private();

        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        engine.upsert_policy(zone_a.clone(), policy.clone()).await;
        engine.upsert_policy(zone_b.clone(), policy).await;

        let _ = engine
            .record_usage(&zone_a, &[UsageMetric::tokens(80)])
            .await;
        let _ = engine
            .record_usage(&zone_b, &[UsageMetric::tokens(30)])
            .await;

        let snap_a = engine.snapshot(&zone_a).await.unwrap();
        let snap_b = engine.snapshot(&zone_b).await.unwrap();

        assert_eq!(snap_a.budgets[0].used, 80);
        assert_eq!(snap_b.budgets[0].used, 30);
    }

    // ── BudgetPolicyEngine async: upsert changes enforcement ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_upsert_changes_enforcement_mode() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();

        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 10,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        // Exceed: warn mode → action is Warn
        let eval = engine
            .record_usage(&zone, &[UsageMetric::tokens(20)])
            .await
            .unwrap();
        assert_eq!(eval.action, BudgetAction::Warn);

        // Switch to deny mode
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 10,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        // Still exceeded → now should be Deny
        let eval2 = engine
            .record_usage(&zone, &[UsageMetric::tokens(0)])
            .await
            .unwrap();
        assert_eq!(eval2.action, BudgetAction::Deny);
    }

    // ── BudgetPolicyEngine async: preflight with unconfigured zone ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_unconfigured_zone_allows() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::private();

        let request = PreflightRequest {
            connector_id: fcp_core::ConnectorId::new("test", "budget", "v1")
                .expect("connector id"),
            operation: "read".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone),
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
        assert!(response.budget_status.is_none());
    }

    // ── BudgetPolicyEngine async: with_policies multiple zones ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_with_policies_multiple_zones() {
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::private();
        let mut policies = HashMap::new();
        policies.insert(
            zone_a.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                }],
            },
        );
        policies.insert(
            zone_b.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 50,
                    window_seconds: 120,
                }],
            },
        );

        let engine = BudgetPolicyEngine::with_policies(policies);
        let snap_a = engine.snapshot(&zone_a).await.unwrap();
        let snap_b = engine.snapshot(&zone_b).await.unwrap();

        assert_eq!(snap_a.enforcement, BudgetEnforcement::Deny);
        assert_eq!(snap_a.budgets[0].limit, 100);
        assert_eq!(snap_b.enforcement, BudgetEnforcement::Warn);
        assert_eq!(snap_b.budgets[0].limit, 50);
    }

    // ── Budget tracker: snapshot after exceeded ──

    #[test]
    fn budget_snapshot_after_exceed_shows_exceeded_status() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);

        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets[0].status, BudgetStatus::Exceeded);
        assert_eq!(snap.budgets[0].used, 150);
        assert_eq!(snap.budgets[0].remaining, 0);
    }

    // ── Budget tracker: saturating remaining ──

    #[test]
    fn budget_remaining_saturates_at_zero() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 10,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(999)]);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    // ── now_secs consistency ──

    #[test]
    fn now_secs_monotonic_within_call() {
        let a = now_secs();
        let b = now_secs();
        // b should be >= a (monotonic)
        assert!(b >= a);
    }

    // ── BudgetTracker debug with zones populated ──

    #[test]
    fn budget_tracker_debug_with_data() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(25)]);
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("BudgetTracker"));
        assert!(dbg.contains("MetricWindow"));
    }

    // ── BudgetAction as index in array ──

    #[test]
    fn budget_action_can_be_matched_exhaustively() {
        let actions = [BudgetAction::Allow, BudgetAction::Warn, BudgetAction::Deny];
        for action in actions {
            let label = match action {
                BudgetAction::Allow => "allow",
                BudgetAction::Warn => "warn",
                BudgetAction::Deny => "deny",
            };
            assert!(!label.is_empty());
        }
    }

    // ── Budget policy engine: record then snapshot consistency ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_then_snapshot_consistent() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 1000,
                        window_seconds: 3600,
                    }],
                },
            )
            .await;

        let eval = engine
            .record_usage(&zone, &[UsageMetric::tokens(250)])
            .await
            .unwrap();
        assert_eq!(eval.snapshot.budgets[0].used, 250);

        let snap = engine.snapshot(&zone).await.unwrap();
        assert_eq!(snap.budgets[0].used, 250);
        assert_eq!(snap.budgets[0].remaining, 750);
    }

    // ── Budget evaluation: to_error with zero window ──

    #[test]
    fn budget_evaluation_to_error_zero_window() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::ApiCredits,
                    used: 5,
                    limit: 3,
                    remaining: 0,
                    window_started_at: 100,
                    window_resets_at: 100,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 100,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded {
            metric,
            window_seconds,
            ..
        } = error
        {
            assert_eq!(metric, UsageMetricKind::ApiCredits);
            assert_eq!(window_seconds, 0);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── aggregate_metrics with u64::MAX single entry ──

    #[test]
    fn aggregate_metrics_single_max() {
        let metrics = vec![UsageMetric::bytes(u64::MAX)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Bytes).unwrap(), u64::MAX);
    }

    // ── Budget tracker: warn enforcement still accumulates ──

    #[test]
    fn budget_tracker_warn_continues_accumulating_after_exceed() {
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
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval2.action, BudgetAction::Warn);
        assert_eq!(eval2.snapshot.budgets[0].used, 200);
    }

    // ── Budget tracker: deny enforcement still accumulates ──

    #[test]
    fn budget_tracker_deny_continues_accumulating_after_exceed() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval2.action, BudgetAction::Deny);
        assert_eq!(eval2.snapshot.budgets[0].used, 200);
    }

    // ── BudgetPolicyEngine: remove nonexistent returns None ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_remove_nonexistent_zone() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::owner();
        assert!(engine.remove_policy(&zone).await.is_none());
    }
}
