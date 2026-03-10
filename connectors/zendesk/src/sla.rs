//! Zendesk SLA tracking and breach monitoring.
//!
//! Exposes SLA state and warnings for agent monitoring, monitors compliance,
//! prioritizes tickets at risk of breach, and triggers escalation workflows.

use serde::{Deserialize, Serialize};

// ── SLA Metric ──────────────────────────────────────────────────────────

/// Zendesk SLA metric types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaMetric {
    FirstReplyTime,
    NextReplyTime,
    RequesterWaitTime,
    AgentWorkTime,
    PauseableUpdateTime,
}

impl SlaMetric {
    /// Machine-readable string for this metric.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstReplyTime => "first_reply_time",
            Self::NextReplyTime => "next_reply_time",
            Self::RequesterWaitTime => "requester_wait_time",
            Self::AgentWorkTime => "agent_work_time",
            Self::PauseableUpdateTime => "pauseable_update_time",
        }
    }

    /// Human-readable description of this metric.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::FirstReplyTime => "Time until the first public agent reply",
            Self::NextReplyTime => "Time until the next public agent reply",
            Self::RequesterWaitTime => "Total time the requester has been waiting",
            Self::AgentWorkTime => "Total time agents have worked on the ticket",
            Self::PauseableUpdateTime => "Time for updates, paused when on hold",
        }
    }
}

impl std::fmt::Display for SlaMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Filter Condition ────────────────────────────────────────────────────

/// A filter condition for SLA policy matching.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

// ── Policy Metric ───────────────────────────────────────────────────────

/// A metric target within an SLA policy, scoped to a ticket priority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMetric {
    pub priority: String,
    pub metric: SlaMetric,
    pub target_seconds: u64,
    pub business_hours: bool,
}

// ── SLA Policy ──────────────────────────────────────────────────────────

/// A Zendesk SLA policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaPolicy {
    pub id: u64,
    pub title: String,
    pub description: Option<String>,
    pub position: u32,
    pub filter_conditions: Vec<FilterCondition>,
    pub policy_metrics: Vec<PolicyMetric>,
    pub active: bool,
}

// ── SLA Stage ───────────────────────────────────────────────────────────

/// The lifecycle stage of an SLA metric for a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaStage {
    Active,
    Paused,
    Fulfilled,
    Breached,
}

impl SlaStage {
    /// Whether this stage represents a terminal (final) state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Fulfilled | Self::Breached)
    }
}

impl std::fmt::Display for SlaStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Fulfilled => "fulfilled",
            Self::Breached => "breached",
        };
        f.write_str(s)
    }
}

// ── Breach Risk ─────────────────────────────────────────────────────────

/// Risk level for SLA breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachRisk {
    None,
    Low,
    Medium,
    High,
    Critical,
    Breached,
}

impl BreachRisk {
    /// Determine breach risk from percentage of time remaining.
    ///
    /// `remaining_pct` is 0.0..=1.0 where 1.0 means 100% of time is left.
    #[must_use]
    pub fn from_remaining_pct(remaining_pct: f64) -> Self {
        if remaining_pct <= 0.0 {
            Self::Breached
        } else if remaining_pct <= 0.1 {
            Self::Critical
        } else if remaining_pct <= 0.25 {
            Self::High
        } else if remaining_pct <= 0.5 {
            Self::Medium
        } else if remaining_pct <= 0.75 {
            Self::Low
        } else {
            Self::None
        }
    }

    /// Machine-readable string for this risk level.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Breached => "breached",
        }
    }

    /// Whether this risk level warrants action.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::High | Self::Critical | Self::Breached)
    }
}

impl std::fmt::Display for BreachRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Metric Status ───────────────────────────────────────────────────────

/// Per-metric SLA status for a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStatus {
    pub metric: SlaMetric,
    pub stage: SlaStage,
    pub target_seconds: u64,
    pub elapsed_seconds: u64,
    pub remaining_seconds: Option<i64>,
    pub breached: bool,
    pub breach_at: Option<String>,
    pub fulfilled_at: Option<String>,
}

impl MetricStatus {
    /// Returns true if remaining time is below the given threshold percentage
    /// of the target. For example, `is_at_risk(0.25)` returns true when less
    /// than 25% of target time remains.
    #[must_use]
    pub fn is_at_risk(&self, threshold_pct: f64) -> bool {
        if self.breached {
            return true;
        }
        match self.remaining_seconds {
            Some(remaining) if self.target_seconds > 0 => {
                if remaining <= 0 {
                    return true;
                }
                let remaining_pct = remaining as f64 / self.target_seconds as f64;
                remaining_pct < threshold_pct
            }
            _ => false,
        }
    }

    /// Compute the breach risk for this metric.
    fn breach_risk(&self) -> BreachRisk {
        if self.breached {
            return BreachRisk::Breached;
        }
        match self.remaining_seconds {
            Some(remaining) if self.target_seconds > 0 => {
                let pct = remaining as f64 / self.target_seconds as f64;
                BreachRisk::from_remaining_pct(pct)
            }
            _ => BreachRisk::None,
        }
    }
}

// ── Ticket SLA Status ───────────────────────────────────────────────────

/// SLA status for a single ticket across all tracked metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketSlaStatus {
    pub ticket_id: u64,
    pub policy_id: Option<u64>,
    pub policy_name: Option<String>,
    pub metrics: Vec<MetricStatus>,
    pub breach_risk: BreachRisk,
}

impl TicketSlaStatus {
    /// Whether any metric on this ticket has been breached.
    #[must_use]
    pub fn is_breached(&self) -> bool {
        self.metrics.iter().any(|m| m.breached)
    }

    /// The highest breach risk across all metrics.
    #[must_use]
    pub fn highest_risk(&self) -> BreachRisk {
        self.metrics
            .iter()
            .map(|m| m.breach_risk())
            .max()
            .unwrap_or(BreachRisk::None)
    }

    /// Seconds until the next metric breach, or `None` if no active metrics.
    #[must_use]
    pub fn time_to_next_breach(&self) -> Option<i64> {
        self.metrics
            .iter()
            .filter(|m| !m.breached && !m.stage.is_terminal())
            .filter_map(|m| m.remaining_seconds)
            .filter(|&r| r > 0)
            .min()
    }
}

// ── SLA Query ───────────────────────────────────────────────────────────

/// Query builder for filtering SLA status results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaQuery {
    pub ticket_ids: Option<Vec<u64>>,
    pub policy_ids: Option<Vec<u64>>,
    pub breach_risk_filter: Option<BreachRisk>,
    pub include_fulfilled: bool,
    pub limit: usize,
}

impl Default for SlaQuery {
    fn default() -> Self {
        Self {
            ticket_ids: None,
            policy_ids: None,
            breach_risk_filter: None,
            include_fulfilled: false,
            limit: 100,
        }
    }
}

impl SlaQuery {
    /// Create a new query with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter to specific tickets.
    #[must_use]
    pub fn with_tickets(mut self, ids: Vec<u64>) -> Self {
        self.ticket_ids = Some(ids);
        self
    }

    /// Filter to specific policies.
    #[must_use]
    pub fn with_policies(mut self, ids: Vec<u64>) -> Self {
        self.policy_ids = Some(ids);
        self
    }

    /// Only include tickets at or above this risk level.
    #[must_use]
    pub fn with_risk_filter(mut self, risk: BreachRisk) -> Self {
        self.breach_risk_filter = Some(risk);
        self
    }

    /// Include tickets whose SLA metrics are all fulfilled.
    #[must_use]
    pub fn include_fulfilled(mut self) -> Self {
        self.include_fulfilled = true;
        self
    }

    /// Set the maximum number of results.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Validate the query parameters. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.limit == 0 {
            return Err("limit must be greater than zero".to_string());
        }
        if self.limit > 10_000 {
            return Err("limit must not exceed 10000".to_string());
        }
        if let Some(ref ids) = self.ticket_ids {
            if ids.is_empty() {
                return Err("ticket_ids must not be empty when specified".to_string());
            }
        }
        if let Some(ref ids) = self.policy_ids {
            if ids.is_empty() {
                return Err("policy_ids must not be empty when specified".to_string());
            }
        }
        Ok(())
    }

    /// Check whether a ticket SLA status passes this query's filters.
    #[must_use]
    pub fn matches(&self, status: &TicketSlaStatus) -> bool {
        if let Some(ref ids) = self.ticket_ids {
            if !ids.contains(&status.ticket_id) {
                return false;
            }
        }
        if let Some(ref ids) = self.policy_ids {
            if let Some(pid) = status.policy_id {
                if !ids.contains(&pid) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(risk_filter) = self.breach_risk_filter {
            if status.breach_risk < risk_filter {
                return false;
            }
        }
        if !self.include_fulfilled {
            let all_fulfilled = !status.metrics.is_empty()
                && status
                    .metrics
                    .iter()
                    .all(|m| m.stage == SlaStage::Fulfilled);
            if all_fulfilled {
                return false;
            }
        }
        true
    }
}

// ── SLA Report ──────────────────────────────────────────────────────────

/// Summary report of SLA status across multiple tickets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaReport {
    pub tickets: Vec<TicketSlaStatus>,
    pub total_at_risk: usize,
    pub total_breached: usize,
    pub generated_at: String,
}

impl SlaReport {
    /// The fraction of tracked tickets that have been breached (0.0..=1.0).
    #[must_use]
    pub fn breach_rate(&self) -> f64 {
        if self.tickets.is_empty() {
            return 0.0;
        }
        self.total_breached as f64 / self.tickets.len() as f64
    }

    /// Build a report from a list of ticket statuses.
    #[must_use]
    pub fn from_statuses(tickets: Vec<TicketSlaStatus>, generated_at: String) -> Self {
        let total_breached = tickets.iter().filter(|t| t.is_breached()).count();
        let total_at_risk = tickets
            .iter()
            .filter(|t| t.breach_risk.is_actionable())
            .count();
        Self {
            tickets,
            total_at_risk,
            total_breached,
            generated_at,
        }
    }
}

// ── Escalation ──────────────────────────────────────────────────────────

/// An action to take when escalating a ticket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EscalationAction {
    Notify { target: String },
    Reassign { group_id: u64 },
    SetPriority { priority: String },
    AddTag { tag: String },
    Custom { action_type: String },
}

/// A rule mapping breach risk thresholds to escalation actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub risk_threshold: BreachRisk,
    pub action: EscalationAction,
    pub cooldown_seconds: u32,
}

impl EscalationRule {
    /// Whether this rule should trigger for the given risk level.
    #[must_use]
    pub fn should_trigger(&self, risk: BreachRisk) -> bool {
        risk >= self.risk_threshold
    }
}

// ── SLA Audit Event ─────────────────────────────────────────────────────

/// Type of SLA audit action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SlaAuditAction {
    Query,
    BreachDetected,
    EscalationTriggered,
}

/// An audit trail event for SLA monitoring activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaAuditEvent {
    pub timestamp: String,
    pub action: SlaAuditAction,
    pub ticket_count: usize,
    pub breach_count: usize,
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helpers ─────────────────────────────────────────────────────

    fn make_metric_status(
        metric: SlaMetric,
        stage: SlaStage,
        target: u64,
        elapsed: u64,
        remaining: Option<i64>,
        breached: bool,
    ) -> MetricStatus {
        MetricStatus {
            metric,
            stage,
            target_seconds: target,
            elapsed_seconds: elapsed,
            remaining_seconds: remaining,
            breached,
            breach_at: None,
            fulfilled_at: None,
        }
    }

    fn make_ticket_status(
        ticket_id: u64,
        policy_id: Option<u64>,
        metrics: Vec<MetricStatus>,
        breach_risk: BreachRisk,
    ) -> TicketSlaStatus {
        TicketSlaStatus {
            ticket_id,
            policy_id,
            policy_name: policy_id.map(|id| format!("Policy {id}")),
            metrics,
            breach_risk,
        }
    }

    fn sample_policy() -> SlaPolicy {
        SlaPolicy {
            id: 1,
            title: "Premium SLA".to_string(),
            description: Some("Enterprise-tier SLA policy".to_string()),
            position: 0,
            filter_conditions: vec![FilterCondition {
                field: "priority".to_string(),
                operator: "is".to_string(),
                value: "urgent".to_string(),
            }],
            policy_metrics: vec![PolicyMetric {
                priority: "urgent".to_string(),
                metric: SlaMetric::FirstReplyTime,
                target_seconds: 3600,
                business_hours: true,
            }],
            active: true,
        }
    }

    // ── SlaMetric ───────────────────────────────────────────────────

    #[test]
    fn metric_as_str_first_reply() {
        assert_eq!(SlaMetric::FirstReplyTime.as_str(), "first_reply_time");
    }

    #[test]
    fn metric_as_str_next_reply() {
        assert_eq!(SlaMetric::NextReplyTime.as_str(), "next_reply_time");
    }

    #[test]
    fn metric_as_str_requester_wait() {
        assert_eq!(SlaMetric::RequesterWaitTime.as_str(), "requester_wait_time");
    }

    #[test]
    fn metric_as_str_agent_work() {
        assert_eq!(SlaMetric::AgentWorkTime.as_str(), "agent_work_time");
    }

    #[test]
    fn metric_as_str_pauseable_update() {
        assert_eq!(
            SlaMetric::PauseableUpdateTime.as_str(),
            "pauseable_update_time"
        );
    }

    #[test]
    fn metric_description_first_reply() {
        let desc = SlaMetric::FirstReplyTime.description();
        assert!(desc.contains("first"));
    }

    #[test]
    fn metric_description_agent_work() {
        let desc = SlaMetric::AgentWorkTime.description();
        assert!(desc.contains("agents"));
    }

    #[test]
    fn metric_display_matches_as_str() {
        let m = SlaMetric::NextReplyTime;
        assert_eq!(format!("{m}"), m.as_str());
    }

    #[test]
    fn metric_serde_roundtrip() {
        let m = SlaMetric::RequesterWaitTime;
        let json = serde_json::to_string(&m).unwrap();
        let back: SlaMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn metric_deserialize_snake_case() {
        let m: SlaMetric = serde_json::from_str("\"first_reply_time\"").unwrap();
        assert_eq!(m, SlaMetric::FirstReplyTime);
    }

    #[test]
    fn metric_all_variants_have_descriptions() {
        let variants = [
            SlaMetric::FirstReplyTime,
            SlaMetric::NextReplyTime,
            SlaMetric::RequesterWaitTime,
            SlaMetric::AgentWorkTime,
            SlaMetric::PauseableUpdateTime,
        ];
        for v in variants {
            assert!(!v.description().is_empty());
            assert!(!v.as_str().is_empty());
        }
    }

    // ── SlaStage ────────────────────────────────────────────────────

    #[test]
    fn stage_active_not_terminal() {
        assert!(!SlaStage::Active.is_terminal());
    }

    #[test]
    fn stage_paused_not_terminal() {
        assert!(!SlaStage::Paused.is_terminal());
    }

    #[test]
    fn stage_fulfilled_is_terminal() {
        assert!(SlaStage::Fulfilled.is_terminal());
    }

    #[test]
    fn stage_breached_is_terminal() {
        assert!(SlaStage::Breached.is_terminal());
    }

    #[test]
    fn stage_display() {
        assert_eq!(format!("{}", SlaStage::Active), "active");
        assert_eq!(format!("{}", SlaStage::Paused), "paused");
        assert_eq!(format!("{}", SlaStage::Fulfilled), "fulfilled");
        assert_eq!(format!("{}", SlaStage::Breached), "breached");
    }

    #[test]
    fn stage_serde_roundtrip() {
        let s = SlaStage::Paused;
        let json = serde_json::to_string(&s).unwrap();
        let back: SlaStage = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ── BreachRisk ──────────────────────────────────────────────────

    #[test]
    fn breach_risk_from_remaining_pct_breached() {
        assert_eq!(BreachRisk::from_remaining_pct(0.0), BreachRisk::Breached);
        assert_eq!(BreachRisk::from_remaining_pct(-0.5), BreachRisk::Breached);
    }

    #[test]
    fn breach_risk_from_remaining_pct_critical() {
        assert_eq!(BreachRisk::from_remaining_pct(0.05), BreachRisk::Critical);
        assert_eq!(BreachRisk::from_remaining_pct(0.1), BreachRisk::Critical);
    }

    #[test]
    fn breach_risk_from_remaining_pct_high() {
        assert_eq!(BreachRisk::from_remaining_pct(0.15), BreachRisk::High);
        assert_eq!(BreachRisk::from_remaining_pct(0.25), BreachRisk::High);
    }

    #[test]
    fn breach_risk_from_remaining_pct_medium() {
        assert_eq!(BreachRisk::from_remaining_pct(0.3), BreachRisk::Medium);
        assert_eq!(BreachRisk::from_remaining_pct(0.5), BreachRisk::Medium);
    }

    #[test]
    fn breach_risk_from_remaining_pct_low() {
        assert_eq!(BreachRisk::from_remaining_pct(0.6), BreachRisk::Low);
        assert_eq!(BreachRisk::from_remaining_pct(0.75), BreachRisk::Low);
    }

    #[test]
    fn breach_risk_from_remaining_pct_none() {
        assert_eq!(BreachRisk::from_remaining_pct(0.8), BreachRisk::None);
        assert_eq!(BreachRisk::from_remaining_pct(1.0), BreachRisk::None);
    }

    #[test]
    fn breach_risk_as_str() {
        assert_eq!(BreachRisk::None.as_str(), "none");
        assert_eq!(BreachRisk::Low.as_str(), "low");
        assert_eq!(BreachRisk::Medium.as_str(), "medium");
        assert_eq!(BreachRisk::High.as_str(), "high");
        assert_eq!(BreachRisk::Critical.as_str(), "critical");
        assert_eq!(BreachRisk::Breached.as_str(), "breached");
    }

    #[test]
    fn breach_risk_is_actionable() {
        assert!(!BreachRisk::None.is_actionable());
        assert!(!BreachRisk::Low.is_actionable());
        assert!(!BreachRisk::Medium.is_actionable());
        assert!(BreachRisk::High.is_actionable());
        assert!(BreachRisk::Critical.is_actionable());
        assert!(BreachRisk::Breached.is_actionable());
    }

    #[test]
    fn breach_risk_ordering() {
        assert!(BreachRisk::None < BreachRisk::Low);
        assert!(BreachRisk::Low < BreachRisk::Medium);
        assert!(BreachRisk::Medium < BreachRisk::High);
        assert!(BreachRisk::High < BreachRisk::Critical);
        assert!(BreachRisk::Critical < BreachRisk::Breached);
    }

    #[test]
    fn breach_risk_display() {
        assert_eq!(format!("{}", BreachRisk::Critical), "critical");
    }

    #[test]
    fn breach_risk_serde_roundtrip() {
        let r = BreachRisk::High;
        let json = serde_json::to_string(&r).unwrap();
        let back: BreachRisk = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── MetricStatus ────────────────────────────────────────────────

    #[test]
    fn metric_status_is_at_risk_when_breached() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Breached,
            3600,
            4000,
            Some(-400),
            true,
        );
        assert!(ms.is_at_risk(0.5));
    }

    #[test]
    fn metric_status_is_at_risk_low_remaining() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            3200,
            Some(400),
            false,
        );
        // 400/3600 ~ 0.11 < 0.25
        assert!(ms.is_at_risk(0.25));
    }

    #[test]
    fn metric_status_not_at_risk_plenty_remaining() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            600,
            Some(3000),
            false,
        );
        // 3000/3600 ~ 0.83 > 0.25
        assert!(!ms.is_at_risk(0.25));
    }

    #[test]
    fn metric_status_at_risk_zero_remaining() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            3600,
            Some(0),
            false,
        );
        assert!(ms.is_at_risk(0.5));
    }

    #[test]
    fn metric_status_not_at_risk_no_remaining() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Fulfilled,
            3600,
            1800,
            None,
            false,
        );
        assert!(!ms.is_at_risk(0.25));
    }

    #[test]
    fn metric_status_at_risk_negative_remaining() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            4000,
            Some(-400),
            false,
        );
        assert!(ms.is_at_risk(0.1));
    }

    #[test]
    fn metric_status_breach_risk_breached() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Breached,
            3600,
            4000,
            Some(-400),
            true,
        );
        assert_eq!(ms.breach_risk(), BreachRisk::Breached);
    }

    #[test]
    fn metric_status_breach_risk_critical() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            3500,
            Some(100),
            false,
        );
        // 100/3600 ~ 0.028
        assert_eq!(ms.breach_risk(), BreachRisk::Critical);
    }

    #[test]
    fn metric_status_breach_risk_none_when_fulfilled() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Fulfilled,
            3600,
            1000,
            None,
            false,
        );
        assert_eq!(ms.breach_risk(), BreachRisk::None);
    }

    #[test]
    fn metric_status_breach_risk_medium() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            2400,
            Some(1200),
            false,
        );
        // 1200/3600 ~ 0.33 → Medium
        assert_eq!(ms.breach_risk(), BreachRisk::Medium);
    }

    #[test]
    fn metric_status_serde_roundtrip() {
        let ms = MetricStatus {
            metric: SlaMetric::AgentWorkTime,
            stage: SlaStage::Active,
            target_seconds: 7200,
            elapsed_seconds: 1800,
            remaining_seconds: Some(5400),
            breached: false,
            breach_at: Some("2026-03-10T12:00:00Z".to_string()),
            fulfilled_at: None,
        };
        let json = serde_json::to_string(&ms).unwrap();
        let back: MetricStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metric, SlaMetric::AgentWorkTime);
        assert_eq!(back.remaining_seconds, Some(5400));
    }

    #[test]
    fn metric_status_at_risk_zero_target() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            0,
            0,
            Some(0),
            false,
        );
        assert!(!ms.is_at_risk(0.5));
    }

    #[test]
    fn metric_status_breach_risk_zero_target() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            0,
            0,
            Some(100),
            false,
        );
        assert_eq!(ms.breach_risk(), BreachRisk::None);
    }

    // ── TicketSlaStatus ─────────────────────────────────────────────

    #[test]
    fn ticket_sla_is_breached_true() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Breached,
            3600,
            4000,
            Some(-400),
            true,
        );
        let ticket = make_ticket_status(1, Some(10), vec![ms], BreachRisk::Breached);
        assert!(ticket.is_breached());
    }

    #[test]
    fn ticket_sla_is_breached_false() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            1000,
            Some(2600),
            false,
        );
        let ticket = make_ticket_status(1, Some(10), vec![ms], BreachRisk::Low);
        assert!(!ticket.is_breached());
    }

    #[test]
    fn ticket_sla_highest_risk_multiple_metrics() {
        let m1 = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            3200,
            Some(400),
            false,
        );
        let m2 = make_metric_status(
            SlaMetric::NextReplyTime,
            SlaStage::Active,
            3600,
            2000,
            Some(1600),
            false,
        );
        let ticket = make_ticket_status(1, Some(10), vec![m1, m2], BreachRisk::None);
        // m1: 400/3600 ~ 0.11 → High, m2: 1600/3600 ~ 0.44 → Medium
        assert_eq!(ticket.highest_risk(), BreachRisk::High);
    }

    #[test]
    fn ticket_sla_highest_risk_empty_metrics() {
        let ticket = make_ticket_status(1, Some(10), vec![], BreachRisk::None);
        assert_eq!(ticket.highest_risk(), BreachRisk::None);
    }

    #[test]
    fn ticket_sla_time_to_next_breach() {
        let m1 = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            3200,
            Some(400),
            false,
        );
        let m2 = make_metric_status(
            SlaMetric::NextReplyTime,
            SlaStage::Active,
            7200,
            2000,
            Some(5200),
            false,
        );
        let ticket = make_ticket_status(1, Some(10), vec![m1, m2], BreachRisk::None);
        assert_eq!(ticket.time_to_next_breach(), Some(400));
    }

    #[test]
    fn ticket_sla_time_to_next_breach_none_when_all_breached() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Breached,
            3600,
            4000,
            Some(-400),
            true,
        );
        let ticket = make_ticket_status(1, Some(10), vec![ms], BreachRisk::Breached);
        assert_eq!(ticket.time_to_next_breach(), None);
    }

    #[test]
    fn ticket_sla_time_to_next_breach_none_when_empty() {
        let ticket = make_ticket_status(1, None, vec![], BreachRisk::None);
        assert_eq!(ticket.time_to_next_breach(), None);
    }

    #[test]
    fn ticket_sla_time_to_breach_skips_fulfilled() {
        let m1 = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Fulfilled,
            3600,
            1000,
            Some(2600),
            false,
        );
        let m2 = make_metric_status(
            SlaMetric::NextReplyTime,
            SlaStage::Active,
            7200,
            2000,
            Some(5200),
            false,
        );
        let ticket = make_ticket_status(1, Some(10), vec![m1, m2], BreachRisk::None);
        assert_eq!(ticket.time_to_next_breach(), Some(5200));
    }

    #[test]
    fn ticket_sla_serde_roundtrip() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            1000,
            Some(2600),
            false,
        );
        let ticket = make_ticket_status(42, Some(10), vec![ms], BreachRisk::Low);
        let json = serde_json::to_string(&ticket).unwrap();
        let back: TicketSlaStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ticket_id, 42);
        assert_eq!(back.policy_id, Some(10));
    }

    #[test]
    fn ticket_sla_is_breached_mixed_metrics() {
        let m1 = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Fulfilled,
            3600,
            1000,
            None,
            false,
        );
        let m2 = make_metric_status(
            SlaMetric::NextReplyTime,
            SlaStage::Breached,
            3600,
            4000,
            Some(-400),
            true,
        );
        let ticket = make_ticket_status(1, Some(10), vec![m1, m2], BreachRisk::Breached);
        assert!(ticket.is_breached());
    }

    // ── SlaPolicy ───────────────────────────────────────────────────

    #[test]
    fn sla_policy_serde_roundtrip() {
        let p = sample_policy();
        let json = serde_json::to_string(&p).unwrap();
        let back: SlaPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 1);
        assert_eq!(back.title, "Premium SLA");
        assert!(back.active);
    }

    #[test]
    fn sla_policy_no_description() {
        let mut p = sample_policy();
        p.description = None;
        let json = serde_json::to_string(&p).unwrap();
        let back: SlaPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.description.is_none());
    }

    #[test]
    fn sla_policy_multiple_conditions() {
        let p = SlaPolicy {
            id: 2,
            title: "Standard SLA".to_string(),
            description: None,
            position: 1,
            filter_conditions: vec![
                FilterCondition {
                    field: "priority".to_string(),
                    operator: "is".to_string(),
                    value: "high".to_string(),
                },
                FilterCondition {
                    field: "group_id".to_string(),
                    operator: "is".to_string(),
                    value: "123".to_string(),
                },
            ],
            policy_metrics: vec![],
            active: true,
        };
        assert_eq!(p.filter_conditions.len(), 2);
    }

    #[test]
    fn sla_policy_multiple_metrics() {
        let p = SlaPolicy {
            id: 3,
            title: "Multi-metric SLA".to_string(),
            description: Some("Tracks multiple metrics".to_string()),
            position: 0,
            filter_conditions: vec![],
            policy_metrics: vec![
                PolicyMetric {
                    priority: "urgent".to_string(),
                    metric: SlaMetric::FirstReplyTime,
                    target_seconds: 1800,
                    business_hours: true,
                },
                PolicyMetric {
                    priority: "urgent".to_string(),
                    metric: SlaMetric::NextReplyTime,
                    target_seconds: 3600,
                    business_hours: true,
                },
                PolicyMetric {
                    priority: "high".to_string(),
                    metric: SlaMetric::FirstReplyTime,
                    target_seconds: 7200,
                    business_hours: false,
                },
            ],
            active: true,
        };
        assert_eq!(p.policy_metrics.len(), 3);
    }

    #[test]
    fn sla_policy_inactive() {
        let mut p = sample_policy();
        p.active = false;
        assert!(!p.active);
    }

    #[test]
    fn sla_policy_clone() {
        let p = sample_policy();
        let cloned = p.clone();
        assert_eq!(cloned.id, p.id);
        assert_eq!(cloned.title, p.title);
    }

    #[test]
    fn sla_policy_debug() {
        let p = sample_policy();
        let debug = format!("{p:?}");
        assert!(debug.contains("Premium SLA"));
    }

    // ── FilterCondition ─────────────────────────────────────────────

    #[test]
    fn filter_condition_serde_roundtrip() {
        let fc = FilterCondition {
            field: "status".to_string(),
            operator: "is_not".to_string(),
            value: "closed".to_string(),
        };
        let json = serde_json::to_string(&fc).unwrap();
        let back: FilterCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(fc, back);
    }

    #[test]
    fn filter_condition_equality() {
        let a = FilterCondition {
            field: "f".to_string(),
            operator: "op".to_string(),
            value: "v".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── PolicyMetric ────────────────────────────────────────────────

    #[test]
    fn policy_metric_serde_roundtrip() {
        let pm = PolicyMetric {
            priority: "normal".to_string(),
            metric: SlaMetric::RequesterWaitTime,
            target_seconds: 28800,
            business_hours: true,
        };
        let json = serde_json::to_string(&pm).unwrap();
        let back: PolicyMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(pm, back);
    }

    #[test]
    fn policy_metric_calendar_hours() {
        let pm = PolicyMetric {
            priority: "low".to_string(),
            metric: SlaMetric::AgentWorkTime,
            target_seconds: 86400,
            business_hours: false,
        };
        assert!(!pm.business_hours);
    }

    // ── SlaQuery ────────────────────────────────────────────────────

    #[test]
    fn sla_query_default() {
        let q = SlaQuery::new();
        assert!(q.ticket_ids.is_none());
        assert!(q.policy_ids.is_none());
        assert!(q.breach_risk_filter.is_none());
        assert!(!q.include_fulfilled);
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn sla_query_builder_chain() {
        let q = SlaQuery::new()
            .with_tickets(vec![1, 2, 3])
            .with_policies(vec![10])
            .with_risk_filter(BreachRisk::High)
            .include_fulfilled()
            .with_limit(50);
        assert_eq!(q.ticket_ids, Some(vec![1, 2, 3]));
        assert_eq!(q.policy_ids, Some(vec![10]));
        assert_eq!(q.breach_risk_filter, Some(BreachRisk::High));
        assert!(q.include_fulfilled);
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn sla_query_validate_ok() {
        let q = SlaQuery::new();
        assert!(q.validate().is_ok());
    }

    #[test]
    fn sla_query_validate_zero_limit() {
        let q = SlaQuery::new().with_limit(0);
        assert!(q.validate().is_err());
    }

    #[test]
    fn sla_query_validate_excessive_limit() {
        let q = SlaQuery::new().with_limit(20_000);
        assert!(q.validate().is_err());
    }

    #[test]
    fn sla_query_validate_empty_ticket_ids() {
        let q = SlaQuery::new().with_tickets(vec![]);
        assert!(q.validate().is_err());
    }

    #[test]
    fn sla_query_validate_empty_policy_ids() {
        let q = SlaQuery::new().with_policies(vec![]);
        assert!(q.validate().is_err());
    }

    #[test]
    fn sla_query_matches_ticket_filter() {
        let q = SlaQuery::new().with_tickets(vec![1, 2]);
        let t1 = make_ticket_status(
            1,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        let t3 = make_ticket_status(
            3,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        assert!(q.matches(&t1));
        assert!(!q.matches(&t3));
    }

    #[test]
    fn sla_query_matches_policy_filter() {
        let q = SlaQuery::new().with_policies(vec![10]);
        let t1 = make_ticket_status(
            1,
            Some(10),
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        let t2 = make_ticket_status(
            2,
            Some(20),
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        let t3 = make_ticket_status(
            3,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        assert!(q.matches(&t1));
        assert!(!q.matches(&t2));
        assert!(!q.matches(&t3));
    }

    #[test]
    fn sla_query_matches_risk_filter() {
        let q = SlaQuery::new().with_risk_filter(BreachRisk::High);
        let t_low = make_ticket_status(1, None, vec![], BreachRisk::Low);
        let t_high = make_ticket_status(2, None, vec![], BreachRisk::High);
        let t_breach = make_ticket_status(3, None, vec![], BreachRisk::Breached);
        assert!(!q.matches(&t_low));
        assert!(q.matches(&t_high));
        assert!(q.matches(&t_breach));
    }

    #[test]
    fn sla_query_excludes_fulfilled_by_default() {
        let q = SlaQuery::new();
        let t = make_ticket_status(
            1,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Fulfilled,
                3600,
                1000,
                None,
                false,
            )],
            BreachRisk::None,
        );
        assert!(!q.matches(&t));
    }

    #[test]
    fn sla_query_includes_fulfilled_when_set() {
        let q = SlaQuery::new().include_fulfilled();
        let t = make_ticket_status(
            1,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Fulfilled,
                3600,
                1000,
                None,
                false,
            )],
            BreachRisk::None,
        );
        assert!(q.matches(&t));
    }

    #[test]
    fn sla_query_no_filter_matches_active() {
        let q = SlaQuery::new();
        let t = make_ticket_status(
            1,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        assert!(q.matches(&t));
    }

    #[test]
    fn sla_query_serde_roundtrip() {
        let q = SlaQuery::new().with_tickets(vec![1]).with_limit(50);
        let json = serde_json::to_string(&q).unwrap();
        let back: SlaQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back.limit, 50);
    }

    #[test]
    fn sla_query_empty_metrics_not_excluded_as_fulfilled() {
        let q = SlaQuery::new();
        let t = make_ticket_status(1, None, vec![], BreachRisk::None);
        assert!(q.matches(&t));
    }

    // ── SlaReport ───────────────────────────────────────────────────

    #[test]
    fn sla_report_breach_rate_zero() {
        let report = SlaReport {
            tickets: vec![make_ticket_status(
                1,
                None,
                vec![make_metric_status(
                    SlaMetric::FirstReplyTime,
                    SlaStage::Active,
                    3600,
                    1000,
                    Some(2600),
                    false,
                )],
                BreachRisk::None,
            )],
            total_at_risk: 0,
            total_breached: 0,
            generated_at: "2026-03-09T00:00:00Z".to_string(),
        };
        assert!((report.breach_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sla_report_breach_rate_half() {
        let report = SlaReport {
            tickets: vec![
                make_ticket_status(1, None, vec![], BreachRisk::None),
                make_ticket_status(2, None, vec![], BreachRisk::Breached),
            ],
            total_at_risk: 1,
            total_breached: 1,
            generated_at: "2026-03-09T00:00:00Z".to_string(),
        };
        assert!((report.breach_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn sla_report_breach_rate_empty() {
        let report = SlaReport {
            tickets: vec![],
            total_at_risk: 0,
            total_breached: 0,
            generated_at: "2026-03-09T00:00:00Z".to_string(),
        };
        assert!((report.breach_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sla_report_from_statuses() {
        let t1 = make_ticket_status(
            1,
            Some(10),
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Breached,
                3600,
                4000,
                Some(-400),
                true,
            )],
            BreachRisk::Breached,
        );
        let t2 = make_ticket_status(
            2,
            Some(10),
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                3400,
                Some(200),
                false,
            )],
            BreachRisk::High,
        );
        let t3 = make_ticket_status(
            3,
            Some(10),
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                1000,
                Some(2600),
                false,
            )],
            BreachRisk::None,
        );
        let report = SlaReport::from_statuses(vec![t1, t2, t3], "2026-03-09T12:00:00Z".to_string());
        assert_eq!(report.total_breached, 1);
        assert_eq!(report.total_at_risk, 2); // Breached + High are both actionable
        assert_eq!(report.tickets.len(), 3);
    }

    #[test]
    fn sla_report_breach_rate_all_breached() {
        let t1 = make_ticket_status(
            1,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Breached,
                3600,
                5000,
                Some(-1400),
                true,
            )],
            BreachRisk::Breached,
        );
        let t2 = make_ticket_status(
            2,
            None,
            vec![make_metric_status(
                SlaMetric::NextReplyTime,
                SlaStage::Breached,
                7200,
                8000,
                Some(-800),
                true,
            )],
            BreachRisk::Breached,
        );
        let report = SlaReport::from_statuses(vec![t1, t2], "2026-03-09T00:00:00Z".to_string());
        assert!((report.breach_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sla_report_serde_roundtrip() {
        let report = SlaReport {
            tickets: vec![],
            total_at_risk: 0,
            total_breached: 0,
            generated_at: "2026-03-09T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: SlaReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.generated_at, "2026-03-09T00:00:00Z");
    }

    // ── EscalationAction ────────────────────────────────────────────

    #[test]
    fn escalation_action_notify_serde() {
        let a = EscalationAction::Notify {
            target: "ops-team@example.com".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn escalation_action_reassign_serde() {
        let a = EscalationAction::Reassign { group_id: 42 };
        let json = serde_json::to_string(&a).unwrap();
        let back: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn escalation_action_set_priority_serde() {
        let a = EscalationAction::SetPriority {
            priority: "urgent".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn escalation_action_add_tag_serde() {
        let a = EscalationAction::AddTag {
            tag: "sla_breach".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn escalation_action_custom_serde() {
        let a = EscalationAction::Custom {
            action_type: "webhook".to_string(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn escalation_action_equality() {
        let a = EscalationAction::Notify {
            target: "x".to_string(),
        };
        let b = EscalationAction::Notify {
            target: "x".to_string(),
        };
        let c = EscalationAction::Notify {
            target: "y".to_string(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── EscalationRule ──────────────────────────────────────────────

    #[test]
    fn escalation_rule_should_trigger_exact() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::High,
            action: EscalationAction::Notify {
                target: "team".to_string(),
            },
            cooldown_seconds: 300,
        };
        assert!(rule.should_trigger(BreachRisk::High));
    }

    #[test]
    fn escalation_rule_should_trigger_above() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::High,
            action: EscalationAction::Notify {
                target: "team".to_string(),
            },
            cooldown_seconds: 300,
        };
        assert!(rule.should_trigger(BreachRisk::Critical));
        assert!(rule.should_trigger(BreachRisk::Breached));
    }

    #[test]
    fn escalation_rule_should_not_trigger_below() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::High,
            action: EscalationAction::Notify {
                target: "team".to_string(),
            },
            cooldown_seconds: 300,
        };
        assert!(!rule.should_trigger(BreachRisk::Medium));
        assert!(!rule.should_trigger(BreachRisk::Low));
        assert!(!rule.should_trigger(BreachRisk::None));
    }

    #[test]
    fn escalation_rule_serde_roundtrip() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::Critical,
            action: EscalationAction::Reassign { group_id: 99 },
            cooldown_seconds: 600,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: EscalationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cooldown_seconds, 600);
    }

    #[test]
    fn escalation_rule_clone() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::Medium,
            action: EscalationAction::AddTag {
                tag: "escalated".to_string(),
            },
            cooldown_seconds: 120,
        };
        let cloned = rule.clone();
        assert_eq!(cloned.risk_threshold, rule.risk_threshold);
        assert_eq!(cloned.cooldown_seconds, rule.cooldown_seconds);
    }

    // ── SlaAuditEvent ───────────────────────────────────────────────

    #[test]
    fn audit_event_query_serde() {
        let e = SlaAuditEvent {
            timestamp: "2026-03-09T10:00:00Z".to_string(),
            action: SlaAuditAction::Query,
            ticket_count: 50,
            breach_count: 3,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: SlaAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, SlaAuditAction::Query);
        assert_eq!(back.ticket_count, 50);
    }

    #[test]
    fn audit_event_breach_detected_serde() {
        let e = SlaAuditEvent {
            timestamp: "2026-03-09T10:05:00Z".to_string(),
            action: SlaAuditAction::BreachDetected,
            ticket_count: 1,
            breach_count: 1,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("breach_detected"));
    }

    #[test]
    fn audit_event_escalation_triggered_serde() {
        let e = SlaAuditEvent {
            timestamp: "2026-03-09T10:10:00Z".to_string(),
            action: SlaAuditAction::EscalationTriggered,
            ticket_count: 5,
            breach_count: 2,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("escalation_triggered"));
    }

    #[test]
    fn audit_event_clone() {
        let e = SlaAuditEvent {
            timestamp: "2026-03-09T10:00:00Z".to_string(),
            action: SlaAuditAction::Query,
            ticket_count: 10,
            breach_count: 0,
        };
        let cloned = e.clone();
        assert_eq!(cloned.ticket_count, e.ticket_count);
    }

    // ── JSON deserialization from API-like payloads ──────────────────

    #[test]
    fn deserialize_sla_policy_from_json() {
        let payload = json!({
            "id": 42,
            "title": "Enterprise SLA",
            "description": "Top-tier support",
            "position": 0,
            "filter_conditions": [
                {"field": "priority", "operator": "is", "value": "urgent"}
            ],
            "policy_metrics": [
                {"priority": "urgent", "metric": "first_reply_time", "target_seconds": 1800, "business_hours": true}
            ],
            "active": true
        });
        let p: SlaPolicy = serde_json::from_value(payload).unwrap();
        assert_eq!(p.id, 42);
        assert_eq!(p.policy_metrics[0].target_seconds, 1800);
    }

    #[test]
    fn deserialize_ticket_sla_status_from_json() {
        let payload = json!({
            "ticket_id": 999,
            "policy_id": 42,
            "policy_name": "Enterprise SLA",
            "metrics": [{
                "metric": "first_reply_time",
                "stage": "active",
                "target_seconds": 3600,
                "elapsed_seconds": 1200,
                "remaining_seconds": 2400,
                "breached": false,
                "breach_at": "2026-03-09T14:00:00Z",
                "fulfilled_at": null
            }],
            "breach_risk": "low"
        });
        let t: TicketSlaStatus = serde_json::from_value(payload).unwrap();
        assert_eq!(t.ticket_id, 999);
        assert_eq!(t.metrics[0].remaining_seconds, Some(2400));
    }

    #[test]
    fn deserialize_escalation_action_tagged() {
        let payload = json!({"type": "reassign", "group_id": 77});
        let a: EscalationAction = serde_json::from_value(payload).unwrap();
        assert_eq!(a, EscalationAction::Reassign { group_id: 77 });
    }

    #[test]
    fn deserialize_escalation_action_custom() {
        let payload = json!({"type": "custom", "action_type": "pagerduty"});
        let a: EscalationAction = serde_json::from_value(payload).unwrap();
        assert_eq!(
            a,
            EscalationAction::Custom {
                action_type: "pagerduty".to_string()
            }
        );
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn breach_risk_boundary_exactly_zero() {
        assert_eq!(BreachRisk::from_remaining_pct(0.0), BreachRisk::Breached);
    }

    #[test]
    fn breach_risk_boundary_just_above_zero() {
        assert_eq!(BreachRisk::from_remaining_pct(0.001), BreachRisk::Critical);
    }

    #[test]
    fn breach_risk_boundary_exactly_point_one() {
        assert_eq!(BreachRisk::from_remaining_pct(0.1), BreachRisk::Critical);
    }

    #[test]
    fn breach_risk_boundary_just_above_point_one() {
        assert_eq!(BreachRisk::from_remaining_pct(0.101), BreachRisk::High);
    }

    #[test]
    fn breach_risk_boundary_exactly_point_two_five() {
        assert_eq!(BreachRisk::from_remaining_pct(0.25), BreachRisk::High);
    }

    #[test]
    fn breach_risk_boundary_just_above_point_two_five() {
        assert_eq!(BreachRisk::from_remaining_pct(0.251), BreachRisk::Medium);
    }

    #[test]
    fn breach_risk_boundary_exactly_point_five() {
        assert_eq!(BreachRisk::from_remaining_pct(0.5), BreachRisk::Medium);
    }

    #[test]
    fn breach_risk_boundary_just_above_point_five() {
        assert_eq!(BreachRisk::from_remaining_pct(0.501), BreachRisk::Low);
    }

    #[test]
    fn breach_risk_boundary_exactly_point_seven_five() {
        assert_eq!(BreachRisk::from_remaining_pct(0.75), BreachRisk::Low);
    }

    #[test]
    fn breach_risk_boundary_just_above_point_seven_five() {
        assert_eq!(BreachRisk::from_remaining_pct(0.751), BreachRisk::None);
    }

    #[test]
    fn metric_status_is_at_risk_exact_threshold() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            1000,
            750,
            Some(250),
            false,
        );
        // 250/1000 = 0.25, threshold_pct = 0.25 → NOT at risk (strictly less than)
        assert!(!ms.is_at_risk(0.25));
    }

    #[test]
    fn metric_status_is_at_risk_just_below_threshold() {
        let ms = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            1000,
            751,
            Some(249),
            false,
        );
        // 249/1000 = 0.249 < 0.25 → at risk
        assert!(ms.is_at_risk(0.25));
    }

    #[test]
    fn sla_query_combined_filters() {
        let q = SlaQuery::new()
            .with_tickets(vec![1, 2, 3])
            .with_policies(vec![10])
            .with_risk_filter(BreachRisk::Medium);
        let t_pass = make_ticket_status(1, Some(10), vec![], BreachRisk::High);
        let t_wrong_ticket = make_ticket_status(5, Some(10), vec![], BreachRisk::High);
        let t_wrong_policy = make_ticket_status(1, Some(20), vec![], BreachRisk::High);
        let t_low_risk = make_ticket_status(1, Some(10), vec![], BreachRisk::Low);
        assert!(q.matches(&t_pass));
        assert!(!q.matches(&t_wrong_ticket));
        assert!(!q.matches(&t_wrong_policy));
        assert!(!q.matches(&t_low_risk));
    }

    #[test]
    fn ticket_sla_time_to_breach_ignores_zero_remaining() {
        let m1 = make_metric_status(
            SlaMetric::FirstReplyTime,
            SlaStage::Active,
            3600,
            3600,
            Some(0),
            false,
        );
        let m2 = make_metric_status(
            SlaMetric::NextReplyTime,
            SlaStage::Active,
            7200,
            2000,
            Some(5200),
            false,
        );
        let ticket = make_ticket_status(1, None, vec![m1, m2], BreachRisk::None);
        // m1 has 0 remaining (filtered out), m2 has 5200
        assert_eq!(ticket.time_to_next_breach(), Some(5200));
    }

    #[test]
    fn sla_report_from_statuses_all_healthy() {
        let t1 = make_ticket_status(
            1,
            None,
            vec![make_metric_status(
                SlaMetric::FirstReplyTime,
                SlaStage::Active,
                3600,
                500,
                Some(3100),
                false,
            )],
            BreachRisk::None,
        );
        let report = SlaReport::from_statuses(vec![t1], "2026-03-09T00:00:00Z".to_string());
        assert_eq!(report.total_breached, 0);
        assert_eq!(report.total_at_risk, 0);
    }

    #[test]
    fn sla_report_from_statuses_empty() {
        let report = SlaReport::from_statuses(vec![], "2026-03-09T00:00:00Z".to_string());
        assert_eq!(report.tickets.len(), 0);
        assert_eq!(report.total_breached, 0);
        assert!((report.breach_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn escalation_rule_none_threshold_always_triggers() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::None,
            action: EscalationAction::Notify {
                target: "t".to_string(),
            },
            cooldown_seconds: 0,
        };
        assert!(rule.should_trigger(BreachRisk::None));
        assert!(rule.should_trigger(BreachRisk::Low));
        assert!(rule.should_trigger(BreachRisk::Breached));
    }

    #[test]
    fn escalation_rule_breached_threshold_only_breached() {
        let rule = EscalationRule {
            risk_threshold: BreachRisk::Breached,
            action: EscalationAction::SetPriority {
                priority: "urgent".to_string(),
            },
            cooldown_seconds: 0,
        };
        assert!(!rule.should_trigger(BreachRisk::Critical));
        assert!(rule.should_trigger(BreachRisk::Breached));
    }

    #[test]
    fn sla_query_max_valid_limit() {
        let q = SlaQuery::new().with_limit(10_000);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn sla_query_just_over_max_limit() {
        let q = SlaQuery::new().with_limit(10_001);
        assert!(q.validate().is_err());
    }

    #[test]
    fn sla_stage_serde_all_variants() {
        for stage in [
            SlaStage::Active,
            SlaStage::Paused,
            SlaStage::Fulfilled,
            SlaStage::Breached,
        ] {
            let json = serde_json::to_string(&stage).unwrap();
            let back: SlaStage = serde_json::from_str(&json).unwrap();
            assert_eq!(stage, back);
        }
    }

    #[test]
    fn sla_audit_action_serde_all_variants() {
        for action in [
            SlaAuditAction::Query,
            SlaAuditAction::BreachDetected,
            SlaAuditAction::EscalationTriggered,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: SlaAuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn breach_risk_large_negative_pct() {
        assert_eq!(BreachRisk::from_remaining_pct(-100.0), BreachRisk::Breached);
    }

    #[test]
    fn breach_risk_large_positive_pct() {
        assert_eq!(BreachRisk::from_remaining_pct(10.0), BreachRisk::None);
    }

    #[test]
    fn ticket_sla_no_policy() {
        let t = make_ticket_status(1, None, vec![], BreachRisk::None);
        assert!(t.policy_id.is_none());
        assert!(t.policy_name.is_none());
    }

    #[test]
    fn metric_status_with_breach_and_fulfilled_timestamps() {
        let ms = MetricStatus {
            metric: SlaMetric::FirstReplyTime,
            stage: SlaStage::Breached,
            target_seconds: 3600,
            elapsed_seconds: 4200,
            remaining_seconds: Some(-600),
            breached: true,
            breach_at: Some("2026-03-09T12:00:00Z".to_string()),
            fulfilled_at: None,
        };
        assert!(ms.is_at_risk(0.5));
        assert_eq!(ms.breach_risk(), BreachRisk::Breached);
    }

    #[test]
    fn metric_status_fulfilled_with_timestamp() {
        let ms = MetricStatus {
            metric: SlaMetric::NextReplyTime,
            stage: SlaStage::Fulfilled,
            target_seconds: 7200,
            elapsed_seconds: 3600,
            remaining_seconds: None,
            breached: false,
            breach_at: None,
            fulfilled_at: Some("2026-03-09T11:00:00Z".to_string()),
        };
        assert!(!ms.is_at_risk(0.5));
        assert_eq!(ms.breach_risk(), BreachRisk::None);
    }

    #[test]
    fn sla_query_matches_mixed_fulfilled_and_active() {
        let q = SlaQuery::new();
        let t = make_ticket_status(
            1,
            None,
            vec![
                make_metric_status(
                    SlaMetric::FirstReplyTime,
                    SlaStage::Fulfilled,
                    3600,
                    1000,
                    None,
                    false,
                ),
                make_metric_status(
                    SlaMetric::NextReplyTime,
                    SlaStage::Active,
                    3600,
                    500,
                    Some(3100),
                    false,
                ),
            ],
            BreachRisk::None,
        );
        // Not all fulfilled, so should match even without include_fulfilled
        assert!(q.matches(&t));
    }
}
