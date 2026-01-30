//! Usage budget tracking and enforcement helpers.
//!
//! Tracks per-zone usage against configured budget policies and surfaces
//! snapshots suitable for CLI/operator reporting.

use std::collections::HashMap;

use chrono::Utc;
use fcp_core::{
    BudgetEnforcement, BudgetStatus, FcpError, UsageBudgetPolicy, UsageBudgetSnapshot,
    UsageBudgetUsage, UsageMetric, UsageMetricKind, ZoneId,
};
use tokio::sync::{Mutex, RwLock};

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

    #[tokio::test]
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
}
