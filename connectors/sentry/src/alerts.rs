//! Sentry alert rule configuration and management.
//!
//! Provides controlled access to Sentry alert rule configuration including
//! issue alerts, performance alerts, and notification routing. Read operations
//! (listing rules, getting definitions) use `sentry.alerts.read`. Write
//! operations (create/update/delete, enable/disable) use `sentry.alerts.write`
//! which is dangerous and requires approval.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── Alert Rule Type ─────────────────────────────────────────────────

/// The type of alert rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertRuleType {
    /// Issue-based alert (e.g., first seen, regression, reappeared).
    Issue,
    /// Metric-based alert (e.g., error rate, transaction duration).
    Metric,
    /// Crash detection alert.
    Crash,
    /// Custom user-defined alert.
    Custom,
}

impl fmt::Display for AlertRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issue => write!(f, "issue"),
            Self::Metric => write!(f, "metric"),
            Self::Crash => write!(f, "crash"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

// ── Alert Condition ─────────────────────────────────────────────────

/// A condition that triggers an alert rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertCondition {
    /// Unique identifier for this condition instance.
    pub condition_id: String,
    /// The condition type (e.g., `first_seen`, `regression`, `event_frequency`).
    pub condition_type: String,
    /// Additional parameters for the condition.
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

impl AlertCondition {
    /// Create a new alert condition.
    #[must_use]
    pub fn new(condition_id: impl Into<String>, condition_type: impl Into<String>) -> Self {
        Self {
            condition_id: condition_id.into(),
            condition_type: condition_type.into(),
            parameters: HashMap::new(),
        }
    }

    /// Add a parameter to this condition.
    #[must_use]
    pub fn with_parameter(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }
}

// ── Alert Action ────────────────────────────────────────────────────

/// An action to take when an alert rule fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertAction {
    /// Unique identifier for this action instance.
    pub action_id: String,
    /// The action type (e.g., `notify_email`, `slack`, `pagerduty`).
    pub action_type: String,
    /// Target type for the action (e.g., "Member", "Team", `IssueOwners`).
    pub target_type: Option<String>,
    /// Target identifier (e.g., user ID, channel name).
    pub target_identifier: Option<String>,
    /// Additional parameters for the action.
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

impl AlertAction {
    /// Create a new alert action.
    #[must_use]
    pub fn new(action_id: impl Into<String>, action_type: impl Into<String>) -> Self {
        Self {
            action_id: action_id.into(),
            action_type: action_type.into(),
            target_type: None,
            target_identifier: None,
            parameters: HashMap::new(),
        }
    }

    /// Set the target type.
    #[must_use]
    pub fn with_target_type(mut self, target_type: impl Into<String>) -> Self {
        self.target_type = Some(target_type.into());
        self
    }

    /// Set the target identifier.
    #[must_use]
    pub fn with_target_identifier(mut self, target_identifier: impl Into<String>) -> Self {
        self.target_identifier = Some(target_identifier.into());
        self
    }

    /// Add a parameter to this action.
    #[must_use]
    pub fn with_parameter(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }
}

// ── Alert Filter ────────────────────────────────────────────────────

/// A filter that refines when an alert rule fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertFilter {
    /// Unique identifier for this filter instance.
    pub filter_id: String,
    /// The filter type (e.g., `age_comparison`, `issue_occurrences`, "level").
    pub filter_type: String,
    /// Additional parameters for the filter.
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

impl AlertFilter {
    /// Create a new alert filter.
    #[must_use]
    pub fn new(filter_id: impl Into<String>, filter_type: impl Into<String>) -> Self {
        Self {
            filter_id: filter_id.into(),
            filter_type: filter_type.into(),
            parameters: HashMap::new(),
        }
    }

    /// Add a parameter to this filter.
    #[must_use]
    pub fn with_parameter(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }
}

// ── Alert Rule ──────────────────────────────────────────────────────

/// A fully-resolved Sentry alert rule with all metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRule {
    /// Rule ID (assigned by Sentry).
    pub id: String,
    /// Human-readable rule name.
    pub name: String,
    /// The type of alert.
    pub rule_type: AlertRuleType,
    /// Project slug this rule belongs to.
    pub project_slug: String,
    /// Optional environment filter (e.g., "production", "staging").
    pub environment: Option<String>,
    /// Conditions that trigger the rule.
    #[serde(default)]
    pub conditions: Vec<AlertCondition>,
    /// Actions to execute when the rule triggers.
    #[serde(default)]
    pub actions: Vec<AlertAction>,
    /// Filters to refine triggering.
    #[serde(default)]
    pub filters: Vec<AlertFilter>,
    /// Minimum minutes between alerts (frequency throttle).
    pub frequency_minutes: u32,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
    /// ISO 8601 creation timestamp.
    pub date_created: Option<String>,
    /// ISO 8601 last-modified timestamp.
    pub date_modified: Option<String>,
    /// Owner identifier (e.g., "team:backend" or "user:alice").
    pub owner: Option<String>,
}

impl fmt::Display for AlertRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.enabled { "enabled" } else { "disabled" };
        write!(
            f,
            "[{}] {} ({}, {}, {})",
            self.id, self.name, self.rule_type, self.project_slug, status
        )
    }
}

// ── Alert Rule Config (Builder) ─────────────────────────────────────

/// Configuration for creating or updating an alert rule.
///
/// Use the builder methods to construct a valid configuration, then
/// call [`validate`](AlertRuleConfig::validate) before submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleConfig {
    /// Rule name.
    pub name: String,
    /// Alert rule type.
    pub rule_type: AlertRuleType,
    /// Conditions that trigger the rule.
    #[serde(default)]
    pub conditions: Vec<AlertCondition>,
    /// Actions to execute.
    #[serde(default)]
    pub actions: Vec<AlertAction>,
    /// Filters to refine triggering.
    #[serde(default)]
    pub filters: Vec<AlertFilter>,
    /// Minimum minutes between alerts.
    pub frequency_minutes: u32,
    /// Optional environment filter.
    pub environment: Option<String>,
    /// Optional owner identifier.
    pub owner: Option<String>,
}

impl AlertRuleConfig {
    /// Create a new alert rule configuration with the given name and type.
    #[must_use]
    pub fn new(name: impl Into<String>, rule_type: AlertRuleType) -> Self {
        Self {
            name: name.into(),
            rule_type,
            conditions: Vec::new(),
            actions: Vec::new(),
            filters: Vec::new(),
            frequency_minutes: 30,
            environment: None,
            owner: None,
        }
    }

    /// Add a condition to the rule.
    #[must_use]
    pub fn with_condition(mut self, condition: AlertCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Add an action to the rule.
    #[must_use]
    pub fn with_action(mut self, action: AlertAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Add a filter to the rule.
    #[must_use]
    pub fn with_filter(mut self, filter: AlertFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Set the frequency throttle in minutes.
    #[must_use]
    pub const fn with_frequency(mut self, minutes: u32) -> Self {
        self.frequency_minutes = minutes;
        self
    }

    /// Set the environment filter.
    #[must_use]
    pub fn with_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Set the owner.
    #[must_use]
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Validate this configuration using default rules.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if the config is invalid.
    pub fn validate(&self) -> Result<(), ValidationError> {
        AlertRuleValidator::new().validate(self)
    }
}

impl fmt::Display for AlertRuleConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, {} conditions, {} actions, every {}m)",
            self.name,
            self.rule_type,
            self.conditions.len(),
            self.actions.len(),
            self.frequency_minutes,
        )
    }
}

// ── Alert Rule Validator ────────────────────────────────────────────

/// Validates alert rule configurations against configurable constraints.
#[derive(Debug, Clone)]
pub struct AlertRuleValidator {
    /// Maximum number of conditions allowed.
    pub max_conditions: usize,
    /// Maximum number of actions allowed.
    pub max_actions: usize,
    /// Maximum name length.
    pub max_name_length: usize,
    /// Allowed rule types (empty = all allowed).
    pub allowed_rule_types: Vec<AlertRuleType>,
}

impl AlertRuleValidator {
    /// Create a new validator with sensible defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_conditions: 10,
            max_actions: 10,
            max_name_length: 256,
            allowed_rule_types: Vec::new(),
        }
    }

    /// Validate the given alert rule configuration.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` describing the first violation found.
    pub fn validate(&self, config: &AlertRuleConfig) -> Result<(), ValidationError> {
        if config.name.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        if config.name.len() > self.max_name_length {
            return Err(ValidationError::NameTooLong {
                length: config.name.len(),
                max: self.max_name_length,
            });
        }
        if config.conditions.is_empty() {
            return Err(ValidationError::NoConditions);
        }
        if config.actions.is_empty() {
            return Err(ValidationError::NoActions);
        }
        if config.conditions.len() > self.max_conditions {
            return Err(ValidationError::TooManyConditions {
                count: config.conditions.len(),
                max: self.max_conditions,
            });
        }
        if config.actions.len() > self.max_actions {
            return Err(ValidationError::TooManyActions {
                count: config.actions.len(),
                max: self.max_actions,
            });
        }
        if config.frequency_minutes == 0 {
            return Err(ValidationError::InvalidFrequency {
                value: 0,
                reason: "frequency must be at least 1 minute".into(),
            });
        }
        // Check for duplicate condition IDs.
        let mut seen_conditions = std::collections::HashSet::new();
        for cond in &config.conditions {
            if !seen_conditions.insert(&cond.condition_id) {
                return Err(ValidationError::DuplicateCondition {
                    condition_id: cond.condition_id.clone(),
                });
            }
        }
        // Check allowed rule types if configured.
        if !self.allowed_rule_types.is_empty()
            && !self.allowed_rule_types.contains(&config.rule_type)
        {
            return Err(ValidationError::UnsupportedRuleType {
                rule_type: config.rule_type,
            });
        }
        // Validate individual conditions.
        for cond in &config.conditions {
            self.validate_condition(cond)?;
        }
        // Validate individual actions.
        for action in &config.actions {
            self.validate_action(action)?;
        }
        Ok(())
    }

    /// Validate a single condition.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if the condition is invalid.
    pub fn validate_condition(&self, condition: &AlertCondition) -> Result<(), ValidationError> {
        if condition.condition_id.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        if condition.condition_type.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        Ok(())
    }

    /// Validate a single action.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if the action is invalid.
    pub fn validate_action(&self, action: &AlertAction) -> Result<(), ValidationError> {
        if action.action_id.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        if action.action_type.is_empty() {
            return Err(ValidationError::EmptyName);
        }
        Ok(())
    }
}

impl Default for AlertRuleValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Validation Error ────────────────────────────────────────────────

/// Errors that can occur when validating an alert rule configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The rule name is empty.
    EmptyName,
    /// The rule name exceeds the maximum length.
    NameTooLong { length: usize, max: usize },
    /// No conditions were specified.
    NoConditions,
    /// No actions were specified.
    NoActions,
    /// Too many conditions.
    TooManyConditions { count: usize, max: usize },
    /// Too many actions.
    TooManyActions { count: usize, max: usize },
    /// Invalid frequency value.
    InvalidFrequency { value: u32, reason: String },
    /// Duplicate condition ID found.
    DuplicateCondition { condition_id: String },
    /// The rule type is not allowed by the validator.
    UnsupportedRuleType { rule_type: AlertRuleType },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "alert rule name must not be empty"),
            Self::NameTooLong { length, max } => {
                write!(f, "alert rule name too long ({length} > {max})")
            }
            Self::NoConditions => write!(f, "alert rule must have at least one condition"),
            Self::NoActions => write!(f, "alert rule must have at least one action"),
            Self::TooManyConditions { count, max } => {
                write!(f, "too many conditions ({count} > {max})")
            }
            Self::TooManyActions { count, max } => {
                write!(f, "too many actions ({count} > {max})")
            }
            Self::InvalidFrequency { value, reason } => {
                write!(f, "invalid frequency {value}: {reason}")
            }
            Self::DuplicateCondition { condition_id } => {
                write!(f, "duplicate condition ID: {condition_id}")
            }
            Self::UnsupportedRuleType { rule_type } => {
                write!(f, "unsupported rule type: {rule_type}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ── Alert Rule Diff ─────────────────────────────────────────────────

/// Tracks a single field change for audit purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleDiff {
    /// Name of the field that changed.
    pub field_name: String,
    /// Previous value (serialized).
    pub old_value: String,
    /// New value (serialized).
    pub new_value: String,
}

impl AlertRuleDiff {
    /// Create a new diff entry.
    #[must_use]
    pub fn new(
        field_name: impl Into<String>,
        old_value: impl Into<String>,
        new_value: impl Into<String>,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            old_value: old_value.into(),
            new_value: new_value.into(),
        }
    }
}

impl fmt::Display for AlertRuleDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}",
            self.field_name, self.old_value, self.new_value
        )
    }
}

// ── Audit Action ────────────────────────────────────────────────────

/// The type of audit action performed on an alert rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuditAction {
    /// Alert rule was created.
    Create,
    /// Alert rule was updated.
    Update,
    /// Alert rule was deleted.
    Delete,
    /// Alert rule was enabled.
    Enable,
    /// Alert rule was disabled.
    Disable,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::Enable => write!(f, "enable"),
            Self::Disable => write!(f, "disable"),
        }
    }
}

// ── Alert Audit Event ───────────────────────────────────────────────

/// An audit trail entry for alert rule changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertAuditEvent {
    /// ISO 8601 timestamp of when the action occurred.
    pub timestamp: String,
    /// The action that was performed.
    pub action: AuditAction,
    /// The ID of the rule that was affected.
    pub rule_id: String,
    /// The name of the rule at the time of the action.
    pub rule_name: String,
    /// List of field-level changes (empty for create/delete).
    #[serde(default)]
    pub changes: Vec<AlertRuleDiff>,
    /// Who performed the action (e.g., "user:alice", "api-key:deploy").
    pub actor: String,
}

impl AlertAuditEvent {
    /// Create a new audit event.
    #[must_use]
    pub fn new(
        timestamp: impl Into<String>,
        action: AuditAction,
        rule_id: impl Into<String>,
        rule_name: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: timestamp.into(),
            action,
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            changes: Vec::new(),
            actor: actor.into(),
        }
    }

    /// Add a change to this audit event.
    #[must_use]
    pub fn with_change(mut self, diff: AlertRuleDiff) -> Self {
        self.changes.push(diff);
        self
    }
}

impl fmt::Display for AlertAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} \"{}\" (rule {}) by {}",
            self.timestamp,
            self.action,
            if self.changes.is_empty() {
                String::new()
            } else {
                format!("({} changes) ", self.changes.len())
            },
            self.rule_name,
            self.rule_id,
            self.actor,
        )
    }
}

// ── Diff computation helpers ────────────────────────────────────────

/// Compute the differences between two alert rules.
#[must_use]
pub fn diff_rules(old: &AlertRule, new: &AlertRule) -> Vec<AlertRuleDiff> {
    let mut diffs = Vec::new();

    if old.name != new.name {
        diffs.push(AlertRuleDiff::new("name", &old.name, &new.name));
    }
    if old.rule_type != new.rule_type {
        diffs.push(AlertRuleDiff::new(
            "rule_type",
            old.rule_type.to_string(),
            new.rule_type.to_string(),
        ));
    }
    if old.project_slug != new.project_slug {
        diffs.push(AlertRuleDiff::new(
            "project_slug",
            &old.project_slug,
            &new.project_slug,
        ));
    }
    if old.environment != new.environment {
        diffs.push(AlertRuleDiff::new(
            "environment",
            format!("{:?}", old.environment),
            format!("{:?}", new.environment),
        ));
    }
    if old.frequency_minutes != new.frequency_minutes {
        diffs.push(AlertRuleDiff::new(
            "frequency_minutes",
            old.frequency_minutes.to_string(),
            new.frequency_minutes.to_string(),
        ));
    }
    if old.enabled != new.enabled {
        diffs.push(AlertRuleDiff::new(
            "enabled",
            old.enabled.to_string(),
            new.enabled.to_string(),
        ));
    }
    if old.owner != new.owner {
        diffs.push(AlertRuleDiff::new(
            "owner",
            format!("{:?}", old.owner),
            format!("{:?}", new.owner),
        ));
    }
    if old.conditions != new.conditions {
        diffs.push(AlertRuleDiff::new(
            "conditions",
            format!("{} conditions", old.conditions.len()),
            format!("{} conditions", new.conditions.len()),
        ));
    }
    if old.actions != new.actions {
        diffs.push(AlertRuleDiff::new(
            "actions",
            format!("{} actions", old.actions.len()),
            format!("{} actions", new.actions.len()),
        ));
    }
    if old.filters != new.filters {
        diffs.push(AlertRuleDiff::new(
            "filters",
            format!("{} filters", old.filters.len()),
            format!("{} filters", new.filters.len()),
        ));
    }

    diffs
}

// ── Capability Constants ────────────────────────────────────────────

/// Capability ID for reading alert rules.
pub const CAPABILITY_ALERTS_READ: &str = "sentry.alerts.read";

/// Capability ID for writing (creating/updating/deleting) alert rules.
/// This is a dangerous capability that requires approval.
pub const CAPABILITY_ALERTS_WRITE: &str = "sentry.alerts.write";

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── AlertRuleType ───────────────────────────────────────────────

    #[test]
    fn alert_rule_type_display_issue() {
        assert_eq!(AlertRuleType::Issue.to_string(), "issue");
    }

    #[test]
    fn alert_rule_type_display_metric() {
        assert_eq!(AlertRuleType::Metric.to_string(), "metric");
    }

    #[test]
    fn alert_rule_type_display_crash() {
        assert_eq!(AlertRuleType::Crash.to_string(), "crash");
    }

    #[test]
    fn alert_rule_type_display_custom() {
        assert_eq!(AlertRuleType::Custom.to_string(), "custom");
    }

    #[test]
    fn alert_rule_type_serde_roundtrip() {
        for rt in [
            AlertRuleType::Issue,
            AlertRuleType::Metric,
            AlertRuleType::Crash,
            AlertRuleType::Custom,
        ] {
            let v = serde_json::to_value(rt).unwrap();
            let back: AlertRuleType = serde_json::from_value(v).unwrap();
            assert_eq!(rt, back);
        }
    }

    #[test]
    fn alert_rule_type_deserialize_camel_case() {
        let t: AlertRuleType = serde_json::from_value(json!("issue")).unwrap();
        assert_eq!(t, AlertRuleType::Issue);
    }

    #[test]
    fn alert_rule_type_clone_and_copy() {
        let t = AlertRuleType::Metric;
        let cloned = t;
        assert_eq!(t, cloned);
    }

    #[test]
    fn alert_rule_type_debug() {
        let dbg = format!("{:?}", AlertRuleType::Crash);
        assert!(dbg.contains("Crash"));
    }

    #[test]
    fn alert_rule_type_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AlertRuleType::Issue);
        set.insert(AlertRuleType::Issue);
        set.insert(AlertRuleType::Metric);
        assert_eq!(set.len(), 2);
    }

    // ── AlertCondition ──────────────────────────────────────────────

    #[test]
    fn alert_condition_new() {
        let c = AlertCondition::new("c1", "first_seen");
        assert_eq!(c.condition_id, "c1");
        assert_eq!(c.condition_type, "first_seen");
        assert!(c.parameters.is_empty());
    }

    #[test]
    fn alert_condition_with_parameter() {
        let c = AlertCondition::new("c1", "event_frequency")
            .with_parameter("value", json!(100))
            .with_parameter("interval", json!("1h"));
        assert_eq!(c.parameters.len(), 2);
        assert_eq!(c.parameters["value"], json!(100));
        assert_eq!(c.parameters["interval"], json!("1h"));
    }

    #[test]
    fn alert_condition_serde_roundtrip() {
        let c = AlertCondition::new("c1", "regression")
            .with_parameter("threshold", json!(5));
        let v = serde_json::to_value(&c).unwrap();
        let back: AlertCondition = serde_json::from_value(v).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn alert_condition_deserialize_json() {
        let c: AlertCondition = serde_json::from_value(json!({
            "conditionId": "c1",
            "conditionType": "reappeared",
            "parameters": {"key": "val"}
        }))
        .unwrap();
        assert_eq!(c.condition_id, "c1");
        assert_eq!(c.condition_type, "reappeared");
        assert_eq!(c.parameters["key"], json!("val"));
    }

    #[test]
    fn alert_condition_default_parameters() {
        let c: AlertCondition = serde_json::from_value(json!({
            "conditionId": "c1",
            "conditionType": "first_seen"
        }))
        .unwrap();
        assert!(c.parameters.is_empty());
    }

    #[test]
    fn alert_condition_clone_and_debug() {
        let c = AlertCondition::new("c1", "first_seen");
        let cloned = c.clone();
        assert_eq!(c.condition_id, "c1");
        assert_eq!(cloned.condition_type, "first_seen");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertCondition"));
    }

    #[test]
    fn alert_condition_eq() {
        let a = AlertCondition::new("c1", "first_seen");
        let b = AlertCondition::new("c1", "first_seen");
        let c = AlertCondition::new("c2", "first_seen");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn alert_condition_common_types() {
        for ct in [
            "first_seen",
            "regression",
            "reappeared",
            "event_frequency",
            "event_unique_user_frequency",
        ] {
            let c = AlertCondition::new("id", ct);
            assert_eq!(c.condition_type, ct);
        }
    }

    #[test]
    fn alert_condition_multiple_params() {
        let c = AlertCondition::new("c1", "event_frequency")
            .with_parameter("value", json!(50))
            .with_parameter("comparisonType", json!("count"))
            .with_parameter("interval", json!("1h"));
        assert_eq!(c.parameters.len(), 3);
    }

    #[test]
    fn alert_condition_overwrite_param() {
        let c = AlertCondition::new("c1", "event_frequency")
            .with_parameter("value", json!(10))
            .with_parameter("value", json!(20));
        assert_eq!(c.parameters["value"], json!(20));
    }

    // ── AlertAction ─────────────────────────────────────────────────

    #[test]
    fn alert_action_new() {
        let a = AlertAction::new("a1", "notify_email");
        assert_eq!(a.action_id, "a1");
        assert_eq!(a.action_type, "notify_email");
        assert!(a.target_type.is_none());
        assert!(a.target_identifier.is_none());
        assert!(a.parameters.is_empty());
    }

    #[test]
    fn alert_action_with_target() {
        let a = AlertAction::new("a1", "slack")
            .with_target_type("Channel")
            .with_target_identifier("#alerts");
        assert_eq!(a.target_type.as_deref(), Some("Channel"));
        assert_eq!(a.target_identifier.as_deref(), Some("#alerts"));
    }

    #[test]
    fn alert_action_with_parameter() {
        let a = AlertAction::new("a1", "pagerduty")
            .with_parameter("severity", json!("critical"));
        assert_eq!(a.parameters["severity"], json!("critical"));
    }

    #[test]
    fn alert_action_serde_roundtrip() {
        let a = AlertAction::new("a1", "notify_email")
            .with_target_type("Member")
            .with_target_identifier("user-123")
            .with_parameter("digest", json!(true));
        let v = serde_json::to_value(&a).unwrap();
        let back: AlertAction = serde_json::from_value(v).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn alert_action_deserialize_json() {
        let a: AlertAction = serde_json::from_value(json!({
            "actionId": "a1",
            "actionType": "slack",
            "targetType": "Channel",
            "targetIdentifier": "#ops",
            "parameters": {"workspace": "my-workspace"}
        }))
        .unwrap();
        assert_eq!(a.action_type, "slack");
        assert_eq!(a.target_type.as_deref(), Some("Channel"));
        assert_eq!(a.parameters["workspace"], json!("my-workspace"));
    }

    #[test]
    fn alert_action_default_parameters() {
        let a: AlertAction = serde_json::from_value(json!({
            "actionId": "a1",
            "actionType": "notify_email"
        }))
        .unwrap();
        assert!(a.parameters.is_empty());
        assert!(a.target_type.is_none());
    }

    #[test]
    fn alert_action_clone_and_debug() {
        let a = AlertAction::new("a1", "pagerduty");
        let cloned = a.clone();
        assert_eq!(a.action_id, "a1");
        assert_eq!(cloned.action_type, "pagerduty");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertAction"));
    }

    #[test]
    fn alert_action_eq() {
        let a = AlertAction::new("a1", "slack");
        let b = AlertAction::new("a1", "slack");
        let c = AlertAction::new("a2", "slack");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn alert_action_common_types() {
        for at in [
            "notify_email",
            "notify_event_service",
            "slack",
            "pagerduty",
        ] {
            let a = AlertAction::new("id", at);
            assert_eq!(a.action_type, at);
        }
    }

    // ── AlertFilter ─────────────────────────────────────────────────

    #[test]
    fn alert_filter_new() {
        let f = AlertFilter::new("f1", "age_comparison");
        assert_eq!(f.filter_id, "f1");
        assert_eq!(f.filter_type, "age_comparison");
        assert!(f.parameters.is_empty());
    }

    #[test]
    fn alert_filter_with_parameter() {
        let f = AlertFilter::new("f1", "issue_occurrences")
            .with_parameter("value", json!(10));
        assert_eq!(f.parameters["value"], json!(10));
    }

    #[test]
    fn alert_filter_serde_roundtrip() {
        let f = AlertFilter::new("f1", "level")
            .with_parameter("match", json!("gte"))
            .with_parameter("level", json!("error"));
        let v = serde_json::to_value(&f).unwrap();
        let back: AlertFilter = serde_json::from_value(v).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn alert_filter_deserialize_json() {
        let f: AlertFilter = serde_json::from_value(json!({
            "filterId": "f1",
            "filterType": "assigned_to",
            "parameters": {"targetType": "Team", "targetIdentifier": 42}
        }))
        .unwrap();
        assert_eq!(f.filter_type, "assigned_to");
        assert_eq!(f.parameters["targetIdentifier"], json!(42));
    }

    #[test]
    fn alert_filter_default_parameters() {
        let f: AlertFilter = serde_json::from_value(json!({
            "filterId": "f1",
            "filterType": "level"
        }))
        .unwrap();
        assert!(f.parameters.is_empty());
    }

    #[test]
    fn alert_filter_clone_and_debug() {
        let f = AlertFilter::new("f1", "level");
        let cloned = f.clone();
        assert_eq!(f.filter_id, "f1");
        assert_eq!(cloned.filter_type, "level");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertFilter"));
    }

    #[test]
    fn alert_filter_eq() {
        let a = AlertFilter::new("f1", "level");
        let b = AlertFilter::new("f1", "level");
        let c = AlertFilter::new("f2", "level");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn alert_filter_common_types() {
        for ft in [
            "age_comparison",
            "issue_occurrences",
            "assigned_to",
            "level",
        ] {
            let f = AlertFilter::new("id", ft);
            assert_eq!(f.filter_type, ft);
        }
    }

    // ── AlertRule ────────────────────────────────────────────────────

    fn sample_rule() -> AlertRule {
        AlertRule {
            id: "42".into(),
            name: "High error rate".into(),
            rule_type: AlertRuleType::Issue,
            project_slug: "backend".into(),
            environment: Some("production".into()),
            conditions: vec![AlertCondition::new("c1", "event_frequency")],
            actions: vec![AlertAction::new("a1", "notify_email")],
            filters: vec![AlertFilter::new("f1", "level")],
            frequency_minutes: 30,
            enabled: true,
            date_created: Some("2026-01-01T00:00:00Z".into()),
            date_modified: Some("2026-03-01T00:00:00Z".into()),
            owner: Some("team:backend".into()),
        }
    }

    #[test]
    fn alert_rule_serde_roundtrip() {
        let rule = sample_rule();
        let v = serde_json::to_value(&rule).unwrap();
        let back: AlertRule = serde_json::from_value(v).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn alert_rule_display_enabled() {
        let rule = sample_rule();
        let display = rule.to_string();
        assert!(display.contains("42"));
        assert!(display.contains("High error rate"));
        assert!(display.contains("issue"));
        assert!(display.contains("backend"));
        assert!(display.contains("enabled"));
    }

    #[test]
    fn alert_rule_display_disabled() {
        let mut rule = sample_rule();
        rule.enabled = false;
        let display = rule.to_string();
        assert!(display.contains("disabled"));
    }

    #[test]
    fn alert_rule_clone_and_debug() {
        let rule = sample_rule();
        let cloned = rule.clone();
        assert_eq!(rule.id, "42");
        assert_eq!(cloned.name, "High error rate");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertRule"));
    }

    #[test]
    fn alert_rule_deserialize_json() {
        let rule: AlertRule = serde_json::from_value(json!({
            "id": "99",
            "name": "Crash detector",
            "ruleType": "crash",
            "projectSlug": "mobile",
            "environment": null,
            "conditions": [],
            "actions": [],
            "filters": [],
            "frequencyMinutes": 60,
            "enabled": false,
            "dateCreated": "2026-02-01T00:00:00Z",
            "owner": "user:alice"
        }))
        .unwrap();
        assert_eq!(rule.id, "99");
        assert_eq!(rule.rule_type, AlertRuleType::Crash);
        assert_eq!(rule.project_slug, "mobile");
        assert!(rule.environment.is_none());
        assert!(!rule.enabled);
        assert_eq!(rule.frequency_minutes, 60);
        assert_eq!(rule.owner.as_deref(), Some("user:alice"));
    }

    #[test]
    fn alert_rule_defaults_empty_vecs() {
        let rule: AlertRule = serde_json::from_value(json!({
            "id": "1",
            "name": "test",
            "ruleType": "issue",
            "projectSlug": "p",
            "frequencyMinutes": 5,
            "enabled": true
        }))
        .unwrap();
        assert!(rule.conditions.is_empty());
        assert!(rule.actions.is_empty());
        assert!(rule.filters.is_empty());
    }

    #[test]
    fn alert_rule_eq() {
        let a = sample_rule();
        let b = sample_rule();
        assert_eq!(a, b);
    }

    #[test]
    fn alert_rule_ne_different_name() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.name = "Different".into();
        assert_ne!(a, b);
    }

    #[test]
    fn alert_rule_serialize_camel_case() {
        let rule = sample_rule();
        let v = serde_json::to_value(&rule).unwrap();
        assert!(v.get("ruleType").is_some());
        assert!(v.get("projectSlug").is_some());
        assert!(v.get("frequencyMinutes").is_some());
        assert!(v.get("dateCreated").is_some());
        assert!(v.get("dateModified").is_some());
    }

    #[test]
    fn alert_rule_with_multiple_conditions() {
        let rule = AlertRule {
            conditions: vec![
                AlertCondition::new("c1", "first_seen"),
                AlertCondition::new("c2", "regression"),
                AlertCondition::new("c3", "event_frequency"),
            ],
            ..sample_rule()
        };
        assert_eq!(rule.conditions.len(), 3);
    }

    #[test]
    fn alert_rule_with_multiple_actions() {
        let rule = AlertRule {
            actions: vec![
                AlertAction::new("a1", "notify_email"),
                AlertAction::new("a2", "slack"),
                AlertAction::new("a3", "pagerduty"),
            ],
            ..sample_rule()
        };
        assert_eq!(rule.actions.len(), 3);
    }

    // ── AlertRuleConfig ─────────────────────────────────────────────

    #[test]
    fn config_new_defaults() {
        let c = AlertRuleConfig::new("My rule", AlertRuleType::Issue);
        assert_eq!(c.name, "My rule");
        assert_eq!(c.rule_type, AlertRuleType::Issue);
        assert!(c.conditions.is_empty());
        assert!(c.actions.is_empty());
        assert!(c.filters.is_empty());
        assert_eq!(c.frequency_minutes, 30);
        assert!(c.environment.is_none());
        assert!(c.owner.is_none());
    }

    #[test]
    fn config_builder_chain() {
        let c = AlertRuleConfig::new("Error spike", AlertRuleType::Metric)
            .with_condition(AlertCondition::new("c1", "event_frequency"))
            .with_action(AlertAction::new("a1", "slack"))
            .with_filter(AlertFilter::new("f1", "level"))
            .with_frequency(15)
            .with_environment("production")
            .with_owner("team:ops");
        assert_eq!(c.name, "Error spike");
        assert_eq!(c.rule_type, AlertRuleType::Metric);
        assert_eq!(c.conditions.len(), 1);
        assert_eq!(c.actions.len(), 1);
        assert_eq!(c.filters.len(), 1);
        assert_eq!(c.frequency_minutes, 15);
        assert_eq!(c.environment.as_deref(), Some("production"));
        assert_eq!(c.owner.as_deref(), Some("team:ops"));
    }

    #[test]
    fn config_multiple_conditions_actions_filters() {
        let c = AlertRuleConfig::new("Multi", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_condition(AlertCondition::new("c2", "regression"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_action(AlertAction::new("a2", "slack"))
            .with_filter(AlertFilter::new("f1", "level"))
            .with_filter(AlertFilter::new("f2", "assigned_to"));
        assert_eq!(c.conditions.len(), 2);
        assert_eq!(c.actions.len(), 2);
        assert_eq!(c.filters.len(), 2);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = AlertRuleConfig::new("Test", AlertRuleType::Custom)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_frequency(10);
        let v = serde_json::to_value(&c).unwrap();
        let back: AlertRuleConfig = serde_json::from_value(v).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn config_display() {
        let c = AlertRuleConfig::new("My rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_frequency(15);
        let display = c.to_string();
        assert!(display.contains("My rule"));
        assert!(display.contains("issue"));
        assert!(display.contains("1 conditions"));
        assert!(display.contains("1 actions"));
        assert!(display.contains("15m"));
    }

    #[test]
    fn config_clone_and_debug() {
        let c = AlertRuleConfig::new("Test", AlertRuleType::Issue);
        let cloned = c.clone();
        assert_eq!(c.name, "Test");
        assert_eq!(cloned.rule_type, AlertRuleType::Issue);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertRuleConfig"));
    }

    #[test]
    fn config_validate_valid() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_validate_empty_name() {
        let c = AlertRuleConfig::new("", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert_eq!(c.validate().unwrap_err(), ValidationError::EmptyName);
    }

    #[test]
    fn config_validate_no_conditions() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_action(AlertAction::new("a1", "notify_email"));
        assert_eq!(c.validate().unwrap_err(), ValidationError::NoConditions);
    }

    #[test]
    fn config_validate_no_actions() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"));
        assert_eq!(c.validate().unwrap_err(), ValidationError::NoActions);
    }

    #[test]
    fn config_validate_zero_frequency() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_frequency(0);
        match c.validate().unwrap_err() {
            ValidationError::InvalidFrequency { value, .. } => assert_eq!(value, 0),
            other => panic!("expected InvalidFrequency, got {other:?}"),
        }
    }

    // ── AlertRuleValidator ──────────────────────────────────────────

    #[test]
    fn validator_new_defaults() {
        let v = AlertRuleValidator::new();
        assert_eq!(v.max_conditions, 10);
        assert_eq!(v.max_actions, 10);
        assert_eq!(v.max_name_length, 256);
        assert!(v.allowed_rule_types.is_empty());
    }

    #[test]
    fn validator_default_trait() {
        let v = AlertRuleValidator::default();
        assert_eq!(v.max_conditions, 10);
    }

    #[test]
    fn validator_name_too_long() {
        let mut v = AlertRuleValidator::new();
        v.max_name_length = 5;
        let c = AlertRuleConfig::new("Too Long Name", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        match v.validate(&c).unwrap_err() {
            ValidationError::NameTooLong { length, max } => {
                assert_eq!(length, 13);
                assert_eq!(max, 5);
            }
            other => panic!("expected NameTooLong, got {other:?}"),
        }
    }

    #[test]
    fn validator_too_many_conditions() {
        let mut v = AlertRuleValidator::new();
        v.max_conditions = 2;
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_condition(AlertCondition::new("c2", "regression"))
            .with_condition(AlertCondition::new("c3", "reappeared"))
            .with_action(AlertAction::new("a1", "notify_email"));
        match v.validate(&c).unwrap_err() {
            ValidationError::TooManyConditions { count, max } => {
                assert_eq!(count, 3);
                assert_eq!(max, 2);
            }
            other => panic!("expected TooManyConditions, got {other:?}"),
        }
    }

    #[test]
    fn validator_too_many_actions() {
        let mut v = AlertRuleValidator::new();
        v.max_actions = 1;
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_action(AlertAction::new("a2", "slack"));
        match v.validate(&c).unwrap_err() {
            ValidationError::TooManyActions { count, max } => {
                assert_eq!(count, 2);
                assert_eq!(max, 1);
            }
            other => panic!("expected TooManyActions, got {other:?}"),
        }
    }

    #[test]
    fn validator_duplicate_condition() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_condition(AlertCondition::new("c1", "regression"))
            .with_action(AlertAction::new("a1", "notify_email"));
        match AlertRuleValidator::new().validate(&c).unwrap_err() {
            ValidationError::DuplicateCondition { condition_id } => {
                assert_eq!(condition_id, "c1");
            }
            other => panic!("expected DuplicateCondition, got {other:?}"),
        }
    }

    #[test]
    fn validator_unsupported_rule_type() {
        let mut v = AlertRuleValidator::new();
        v.allowed_rule_types = vec![AlertRuleType::Issue, AlertRuleType::Metric];
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Custom)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        match v.validate(&c).unwrap_err() {
            ValidationError::UnsupportedRuleType { rule_type } => {
                assert_eq!(rule_type, AlertRuleType::Custom);
            }
            other => panic!("expected UnsupportedRuleType, got {other:?}"),
        }
    }

    #[test]
    fn validator_allowed_rule_types_pass() {
        let mut v = AlertRuleValidator::new();
        v.allowed_rule_types = vec![AlertRuleType::Issue];
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(v.validate(&c).is_ok());
    }

    #[test]
    fn validator_empty_allowed_types_allows_all() {
        let v = AlertRuleValidator::new();
        assert!(v.allowed_rule_types.is_empty());
        for rt in [
            AlertRuleType::Issue,
            AlertRuleType::Metric,
            AlertRuleType::Crash,
            AlertRuleType::Custom,
        ] {
            let c = AlertRuleConfig::new("Rule", rt)
                .with_condition(AlertCondition::new("c1", "first_seen"))
                .with_action(AlertAction::new("a1", "notify_email"));
            assert!(v.validate(&c).is_ok());
        }
    }

    #[test]
    fn validator_validate_condition_empty_id() {
        let v = AlertRuleValidator::new();
        let c = AlertCondition::new("", "first_seen");
        assert_eq!(v.validate_condition(&c).unwrap_err(), ValidationError::EmptyName);
    }

    #[test]
    fn validator_validate_condition_empty_type() {
        let v = AlertRuleValidator::new();
        let c = AlertCondition::new("c1", "");
        assert_eq!(v.validate_condition(&c).unwrap_err(), ValidationError::EmptyName);
    }

    #[test]
    fn validator_validate_action_empty_id() {
        let v = AlertRuleValidator::new();
        let a = AlertAction::new("", "slack");
        assert_eq!(v.validate_action(&a).unwrap_err(), ValidationError::EmptyName);
    }

    #[test]
    fn validator_validate_action_empty_type() {
        let v = AlertRuleValidator::new();
        let a = AlertAction::new("a1", "");
        assert_eq!(v.validate_action(&a).unwrap_err(), ValidationError::EmptyName);
    }

    #[test]
    fn validator_validate_condition_valid() {
        let v = AlertRuleValidator::new();
        assert!(v.validate_condition(&AlertCondition::new("c1", "first_seen")).is_ok());
    }

    #[test]
    fn validator_validate_action_valid() {
        let v = AlertRuleValidator::new();
        assert!(v.validate_action(&AlertAction::new("a1", "slack")).is_ok());
    }

    #[test]
    fn validator_clone_and_debug() {
        let v = AlertRuleValidator::new();
        let cloned = v.clone();
        assert_eq!(v.max_conditions, cloned.max_conditions);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertRuleValidator"));
    }

    #[test]
    fn validator_rejects_config_with_empty_condition_id() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        // Duplicate check passes (only one condition), but individual validation fails
        // Actually: empty condition_id won't trigger DuplicateCondition since HashSet will just insert ""
        assert!(AlertRuleValidator::new().validate(&c).is_err());
    }

    #[test]
    fn validator_rejects_config_with_empty_action_type() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", ""));
        assert!(AlertRuleValidator::new().validate(&c).is_err());
    }

    // ── ValidationError ─────────────────────────────────────────────

    #[test]
    fn validation_error_display_empty_name() {
        assert_eq!(ValidationError::EmptyName.to_string(), "alert rule name must not be empty");
    }

    #[test]
    fn validation_error_display_name_too_long() {
        let e = ValidationError::NameTooLong {
            length: 300,
            max: 256,
        };
        let s = e.to_string();
        assert!(s.contains("300"));
        assert!(s.contains("256"));
    }

    #[test]
    fn validation_error_display_no_conditions() {
        assert!(ValidationError::NoConditions.to_string().contains("condition"));
    }

    #[test]
    fn validation_error_display_no_actions() {
        assert!(ValidationError::NoActions.to_string().contains("action"));
    }

    #[test]
    fn validation_error_display_too_many_conditions() {
        let e = ValidationError::TooManyConditions { count: 15, max: 10 };
        let s = e.to_string();
        assert!(s.contains("15"));
        assert!(s.contains("10"));
    }

    #[test]
    fn validation_error_display_too_many_actions() {
        let e = ValidationError::TooManyActions { count: 12, max: 10 };
        let s = e.to_string();
        assert!(s.contains("12"));
        assert!(s.contains("10"));
    }

    #[test]
    fn validation_error_display_invalid_frequency() {
        let e = ValidationError::InvalidFrequency {
            value: 0,
            reason: "must be positive".into(),
        };
        let s = e.to_string();
        assert!(s.contains('0'));
        assert!(s.contains("must be positive"));
    }

    #[test]
    fn validation_error_display_duplicate_condition() {
        let e = ValidationError::DuplicateCondition {
            condition_id: "c1".into(),
        };
        assert!(e.to_string().contains("c1"));
    }

    #[test]
    fn validation_error_display_unsupported_type() {
        let e = ValidationError::UnsupportedRuleType {
            rule_type: AlertRuleType::Custom,
        };
        assert!(e.to_string().contains("custom"));
    }

    #[test]
    fn validation_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(ValidationError::EmptyName);
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn validation_error_debug() {
        let e = ValidationError::NoConditions;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("NoConditions"));
    }

    #[test]
    fn validation_error_clone_and_eq() {
        let a = ValidationError::NoActions;
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── AlertRuleDiff ───────────────────────────────────────────────

    #[test]
    fn diff_new() {
        let d = AlertRuleDiff::new("name", "old", "new");
        assert_eq!(d.field_name, "name");
        assert_eq!(d.old_value, "old");
        assert_eq!(d.new_value, "new");
    }

    #[test]
    fn diff_display() {
        let d = AlertRuleDiff::new("frequency", "30", "60");
        assert_eq!(d.to_string(), "frequency: 30 -> 60");
    }

    #[test]
    fn diff_serde_roundtrip() {
        let d = AlertRuleDiff::new("enabled", "true", "false");
        let v = serde_json::to_value(&d).unwrap();
        let back: AlertRuleDiff = serde_json::from_value(v).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn diff_serialize_camel_case() {
        let d = AlertRuleDiff::new("name", "old", "new");
        let v = serde_json::to_value(&d).unwrap();
        assert!(v.get("fieldName").is_some());
        assert!(v.get("oldValue").is_some());
        assert!(v.get("newValue").is_some());
    }

    #[test]
    fn diff_clone_and_debug() {
        let d = AlertRuleDiff::new("name", "a", "b");
        let cloned = d.clone();
        assert_eq!(d.field_name, "name");
        assert_eq!(cloned.old_value, "a");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertRuleDiff"));
    }

    #[test]
    fn diff_eq() {
        let a = AlertRuleDiff::new("name", "old", "new");
        let b = AlertRuleDiff::new("name", "old", "new");
        let c = AlertRuleDiff::new("name", "old", "different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── AuditAction ─────────────────────────────────────────────────

    #[test]
    fn audit_action_display() {
        assert_eq!(AuditAction::Create.to_string(), "create");
        assert_eq!(AuditAction::Update.to_string(), "update");
        assert_eq!(AuditAction::Delete.to_string(), "delete");
        assert_eq!(AuditAction::Enable.to_string(), "enable");
        assert_eq!(AuditAction::Disable.to_string(), "disable");
    }

    #[test]
    fn audit_action_serde_roundtrip() {
        for action in [
            AuditAction::Create,
            AuditAction::Update,
            AuditAction::Delete,
            AuditAction::Enable,
            AuditAction::Disable,
        ] {
            let v = serde_json::to_value(action).unwrap();
            let back: AuditAction = serde_json::from_value(v).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn audit_action_clone_copy_debug() {
        let a = AuditAction::Create;
        let b = a;
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Create"));
    }

    #[test]
    fn audit_action_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AuditAction::Create);
        set.insert(AuditAction::Create);
        set.insert(AuditAction::Delete);
        assert_eq!(set.len(), 2);
    }

    // ── AlertAuditEvent ─────────────────────────────────────────────

    #[test]
    fn audit_event_new() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Create,
            "42",
            "My rule",
            "user:alice",
        );
        assert_eq!(e.timestamp, "2026-03-01T00:00:00Z");
        assert_eq!(e.action, AuditAction::Create);
        assert_eq!(e.rule_id, "42");
        assert_eq!(e.rule_name, "My rule");
        assert_eq!(e.actor, "user:alice");
        assert!(e.changes.is_empty());
    }

    #[test]
    fn audit_event_with_changes() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Update,
            "42",
            "My rule",
            "user:bob",
        )
        .with_change(AlertRuleDiff::new("name", "Old name", "New name"))
        .with_change(AlertRuleDiff::new("frequency", "30", "60"));
        assert_eq!(e.changes.len(), 2);
        assert_eq!(e.changes[0].field_name, "name");
        assert_eq!(e.changes[1].field_name, "frequency");
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Enable,
            "10",
            "Test rule",
            "api-key:deploy",
        )
        .with_change(AlertRuleDiff::new("enabled", "false", "true"));
        let v = serde_json::to_value(&e).unwrap();
        let back: AlertAuditEvent = serde_json::from_value(v).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn audit_event_display_no_changes() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Create,
            "42",
            "My rule",
            "user:alice",
        );
        let display = e.to_string();
        assert!(display.contains("create"));
        assert!(display.contains("My rule"));
        assert!(display.contains("42"));
        assert!(display.contains("user:alice"));
    }

    #[test]
    fn audit_event_display_with_changes() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Update,
            "42",
            "My rule",
            "user:bob",
        )
        .with_change(AlertRuleDiff::new("name", "old", "new"));
        let display = e.to_string();
        assert!(display.contains("1 changes"));
    }

    #[test]
    fn audit_event_clone_and_debug() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Delete,
            "42",
            "My rule",
            "user:charlie",
        );
        let cloned = e.clone();
        assert_eq!(e.rule_id, "42");
        assert_eq!(cloned.actor, "user:charlie");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("AlertAuditEvent"));
    }

    #[test]
    fn audit_event_serialize_camel_case() {
        let e = AlertAuditEvent::new(
            "2026-03-01T00:00:00Z",
            AuditAction::Create,
            "1",
            "rule",
            "actor",
        );
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("ruleId").is_some());
        assert!(v.get("ruleName").is_some());
    }

    // ── diff_rules ──────────────────────────────────────────────────

    #[test]
    fn diff_rules_no_changes() {
        let a = sample_rule();
        let b = sample_rule();
        assert!(diff_rules(&a, &b).is_empty());
    }

    #[test]
    fn diff_rules_name_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.name = "New name".into();
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "name");
        assert_eq!(diffs[0].old_value, "High error rate");
        assert_eq!(diffs[0].new_value, "New name");
    }

    #[test]
    fn diff_rules_type_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.rule_type = AlertRuleType::Metric;
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "rule_type");
    }

    #[test]
    fn diff_rules_project_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.project_slug = "frontend".into();
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "project_slug");
    }

    #[test]
    fn diff_rules_environment_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.environment = None;
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "environment");
    }

    #[test]
    fn diff_rules_frequency_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.frequency_minutes = 60;
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "frequency_minutes");
        assert_eq!(diffs[0].old_value, "30");
        assert_eq!(diffs[0].new_value, "60");
    }

    #[test]
    fn diff_rules_enabled_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.enabled = false;
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "enabled");
        assert_eq!(diffs[0].old_value, "true");
        assert_eq!(diffs[0].new_value, "false");
    }

    #[test]
    fn diff_rules_owner_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.owner = Some("user:alice".into());
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "owner");
    }

    #[test]
    fn diff_rules_conditions_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.conditions.push(AlertCondition::new("c2", "regression"));
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "conditions");
    }

    #[test]
    fn diff_rules_actions_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.actions = vec![];
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "actions");
    }

    #[test]
    fn diff_rules_filters_changed() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.filters = vec![];
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].field_name, "filters");
    }

    #[test]
    fn diff_rules_multiple_changes() {
        let a = sample_rule();
        let mut b = sample_rule();
        b.name = "New name".into();
        b.frequency_minutes = 60;
        b.enabled = false;
        let diffs = diff_rules(&a, &b);
        assert_eq!(diffs.len(), 3);
        let fields: Vec<&str> = diffs.iter().map(|d| d.field_name.as_str()).collect();
        assert!(fields.contains(&"name"));
        assert!(fields.contains(&"frequency_minutes"));
        assert!(fields.contains(&"enabled"));
    }

    // ── Capability constants ────────────────────────────────────────

    #[test]
    fn capability_read_constant() {
        assert_eq!(CAPABILITY_ALERTS_READ, "sentry.alerts.read");
    }

    #[test]
    fn capability_write_constant() {
        assert_eq!(CAPABILITY_ALERTS_WRITE, "sentry.alerts.write");
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn config_name_at_max_length() {
        let c = AlertRuleConfig::new("x".repeat(256), AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(c.validate().is_ok());
        assert_eq!(c.name.len(), 256);
    }

    #[test]
    fn config_name_exceeds_max_length() {
        let name = "x".repeat(257);
        let c = AlertRuleConfig::new(name, AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(matches!(
            c.validate().unwrap_err(),
            ValidationError::NameTooLong { .. }
        ));
    }

    #[test]
    fn config_max_conditions_at_limit() {
        let mut c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_action(AlertAction::new("a1", "notify_email"));
        for i in 0..10 {
            c = c.with_condition(AlertCondition::new(format!("c{i}"), "first_seen"));
        }
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_max_conditions_exceeds_limit() {
        let mut c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_action(AlertAction::new("a1", "notify_email"));
        for i in 0..11 {
            c = c.with_condition(AlertCondition::new(format!("c{i}"), "first_seen"));
        }
        assert!(matches!(
            c.validate().unwrap_err(),
            ValidationError::TooManyConditions { .. }
        ));
    }

    #[test]
    fn config_max_actions_at_limit() {
        let mut c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"));
        for i in 0..10 {
            c = c.with_action(AlertAction::new(format!("a{i}"), "notify_email"));
        }
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_max_actions_exceeds_limit() {
        let mut c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"));
        for i in 0..11 {
            c = c.with_action(AlertAction::new(format!("a{i}"), "notify_email"));
        }
        assert!(matches!(
            c.validate().unwrap_err(),
            ValidationError::TooManyActions { .. }
        ));
    }

    #[test]
    fn alert_rule_with_no_optional_fields() {
        let rule: AlertRule = serde_json::from_value(json!({
            "id": "1",
            "name": "minimal",
            "ruleType": "issue",
            "projectSlug": "p",
            "frequencyMinutes": 5,
            "enabled": true
        }))
        .unwrap();
        assert!(rule.environment.is_none());
        assert!(rule.date_created.is_none());
        assert!(rule.date_modified.is_none());
        assert!(rule.owner.is_none());
    }

    #[test]
    fn alert_condition_with_complex_parameters() {
        let c = AlertCondition::new("c1", "event_frequency")
            .with_parameter("value", json!(100))
            .with_parameter("comparisonType", json!("count"))
            .with_parameter("interval", json!("1h"))
            .with_parameter("nested", json!({"a": [1, 2, 3]}));
        assert_eq!(c.parameters.len(), 4);
        let v = serde_json::to_value(&c).unwrap();
        let back: AlertCondition = serde_json::from_value(v).unwrap();
        assert_eq!(back.parameters["nested"]["a"][1], 2);
    }

    #[test]
    fn alert_action_full_chain() {
        let a = AlertAction::new("a1", "slack")
            .with_target_type("Channel")
            .with_target_identifier("#prod-alerts")
            .with_parameter("workspace", json!("my-workspace"))
            .with_parameter("icon_emoji", json!(":warning:"));
        assert_eq!(a.parameters.len(), 2);
        assert_eq!(a.target_type.as_deref(), Some("Channel"));
        assert_eq!(a.target_identifier.as_deref(), Some("#prod-alerts"));
    }

    #[test]
    fn alert_filter_with_complex_parameters() {
        let f = AlertFilter::new("f1", "age_comparison")
            .with_parameter("comparison_type", json!("older"))
            .with_parameter("value", json!(24))
            .with_parameter("time", json!("hour"));
        assert_eq!(f.parameters.len(), 3);
        let v = serde_json::to_value(&f).unwrap();
        let back: AlertFilter = serde_json::from_value(v).unwrap();
        assert_eq!(back.parameters["value"], json!(24));
    }

    #[test]
    fn diff_rules_all_same_returns_empty() {
        let rule = sample_rule();
        let diffs = diff_rules(&rule, &rule);
        assert!(diffs.is_empty());
    }

    #[test]
    fn audit_event_default_empty_changes() {
        let e: AlertAuditEvent = serde_json::from_value(json!({
            "timestamp": "2026-01-01T00:00:00Z",
            "action": "delete",
            "ruleId": "1",
            "ruleName": "rule",
            "actor": "system"
        }))
        .unwrap();
        assert!(e.changes.is_empty());
        assert_eq!(e.action, AuditAction::Delete);
    }

    #[test]
    fn audit_event_multiple_changes_chain() {
        let e = AlertAuditEvent::new("ts", AuditAction::Update, "1", "rule", "actor")
            .with_change(AlertRuleDiff::new("a", "1", "2"))
            .with_change(AlertRuleDiff::new("b", "3", "4"))
            .with_change(AlertRuleDiff::new("c", "5", "6"));
        assert_eq!(e.changes.len(), 3);
    }

    #[test]
    fn alert_rule_type_all_variants_deserialize() {
        for (json_val, expected) in [
            ("issue", AlertRuleType::Issue),
            ("metric", AlertRuleType::Metric),
            ("crash", AlertRuleType::Crash),
            ("custom", AlertRuleType::Custom),
        ] {
            let v: AlertRuleType = serde_json::from_value(json!(json_val)).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_frequency_1_is_valid() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_frequency(1);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_frequency_large_is_valid() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"))
            .with_frequency(1440);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_without_environment_is_valid() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(c.environment.is_none());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_without_owner_is_valid() {
        let c = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(c.owner.is_none());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_eq() {
        let a = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        let b = AlertRuleConfig::new("Rule", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert_eq!(a, b);
    }

    #[test]
    fn config_ne_different_type() {
        let a = AlertRuleConfig::new("Rule", AlertRuleType::Issue);
        let b = AlertRuleConfig::new("Rule", AlertRuleType::Metric);
        assert_ne!(a, b);
    }

    #[test]
    fn validator_custom_limits() {
        let mut v = AlertRuleValidator::new();
        v.max_conditions = 3;
        v.max_actions = 2;
        v.max_name_length = 50;
        v.allowed_rule_types = vec![AlertRuleType::Issue];

        let c = AlertRuleConfig::new("Short", AlertRuleType::Issue)
            .with_condition(AlertCondition::new("c1", "first_seen"))
            .with_action(AlertAction::new("a1", "notify_email"));
        assert!(v.validate(&c).is_ok());
    }

    #[test]
    fn diff_empty_field_name() {
        let d = AlertRuleDiff::new("", "old", "new");
        assert_eq!(d.to_string(), ": old -> new");
    }

    #[test]
    fn diff_empty_values() {
        let d = AlertRuleDiff::new("field", "", "");
        assert_eq!(d.to_string(), "field:  -> ");
    }

    #[test]
    fn audit_action_deserialize_camel_case() {
        let a: AuditAction = serde_json::from_value(json!("enable")).unwrap();
        assert_eq!(a, AuditAction::Enable);
    }

    #[test]
    fn alert_rule_environment_none_to_some() {
        let mut a = sample_rule();
        a.environment = None;
        let mut b = sample_rule();
        b.environment = Some("staging".into());
        let diffs = diff_rules(&a, &b);
        assert!(diffs.iter().any(|d| d.field_name == "environment"));
    }

    #[test]
    fn alert_rule_owner_none_to_some() {
        let mut a = sample_rule();
        a.owner = None;
        let b = sample_rule();
        let diffs = diff_rules(&a, &b);
        assert!(diffs.iter().any(|d| d.field_name == "owner"));
    }
}
