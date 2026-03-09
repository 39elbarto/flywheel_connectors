//! Event-triggered operation execution with reactive rules.
//!
//! Defines the rule engine for automatically invoking operations when matching
//! events arrive. Supports TOML rule definitions with event matching, template
//! rendering, throttle enforcement, and circuit breaker logic.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ── Event Trigger ─────────────────────────────────────────────────

/// Defines which events trigger a rule.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventTrigger {
    /// Connector that emits the event.
    pub connector: String,
    /// Event type (e.g., `"message.new"`, `"issue.created"`).
    #[serde(rename = "type")]
    pub event_type: String,
    /// Optional match expression on event data (e.g., `"data.text~bug|Bug"`).
    #[serde(rename = "match")]
    pub match_expr: Option<String>,
}

impl EventTrigger {
    /// Create a new trigger.
    pub fn new(connector: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            event_type: event_type.into(),
            match_expr: None,
        }
    }

    /// Builder: add a match expression.
    pub fn with_match(mut self, expr: impl Into<String>) -> Self {
        self.match_expr = Some(expr.into());
        self
    }
}

// ── Action ────────────────────────────────────────────────────────

/// Defines what to do when a rule triggers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleAction {
    /// Target connector.
    pub connector: String,
    /// Operation to invoke.
    pub operation: String,
    /// Input template (keys may contain `{{event.data.field}}` placeholders).
    #[serde(default)]
    pub input: BTreeMap<String, String>,
}

impl RuleAction {
    /// Create a new action.
    pub fn new(connector: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            operation: operation.into(),
            input: BTreeMap::new(),
        }
    }

    /// Builder: add an input field.
    pub fn with_input(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.input.insert(key.into(), value.into());
        self
    }
}

// ── Throttle Config ───────────────────────────────────────────────

/// Throttle settings to prevent runaway automation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleThrottle {
    /// Maximum number of triggers in the window.
    pub max: u32,
    /// Window duration string (e.g., `"1h"`, `"30m"`, `"1d"`).
    pub window: String,
}

impl RuleThrottle {
    /// Create a throttle config.
    pub fn new(max: u32, window: impl Into<String>) -> Self {
        Self {
            max,
            window: window.into(),
        }
    }

    /// Parse the window string into a `Duration`.
    pub fn window_duration(&self) -> Option<Duration> {
        parse_window(&self.window)
    }
}

impl Default for RuleThrottle {
    fn default() -> Self {
        Self {
            max: 10,
            window: "1h".to_string(),
        }
    }
}

// ── Rule Definition ───────────────────────────────────────────────

/// A complete reactive rule definition.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    /// Unique rule name.
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// What triggers this rule.
    pub trigger: EventTrigger,
    /// What to do when triggered.
    pub action: RuleAction,
    /// Throttle settings.
    #[serde(default)]
    pub throttle: RuleThrottle,
    /// Whether the rule is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_true() -> bool {
    true
}

impl Rule {
    /// Create a new rule.
    pub fn new(
        name: impl Into<String>,
        trigger: EventTrigger,
        action: RuleAction,
    ) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            trigger,
            action,
            throttle: RuleThrottle::default(),
            enabled: true,
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set throttle.
    pub fn with_throttle(mut self, throttle: RuleThrottle) -> Self {
        self.throttle = throttle;
        self
    }

    /// Builder: set enabled.
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

// ── Event Data ────────────────────────────────────────────────────

/// An incoming event that may trigger rules.
#[derive(Clone, Debug, Serialize)]
pub struct IncomingEvent {
    /// Source connector.
    pub connector: String,
    /// Event type.
    pub event_type: String,
    /// Event data as key-value pairs.
    pub data: BTreeMap<String, String>,
    /// When the event was received.
    pub received_at: DateTime<Utc>,
}

impl IncomingEvent {
    /// Create a new event.
    pub fn new(connector: impl Into<String>, event_type: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            event_type: event_type.into(),
            data: BTreeMap::new(),
            received_at: Utc::now(),
        }
    }

    /// Builder: add a data field.
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }

    /// Get a nested field (dot-separated, e.g., `"data.text"`).
    pub fn get_field(&self, path: &str) -> Option<&str> {
        let field = path.strip_prefix("data.").unwrap_or(path);
        self.data.get(field).map(String::as_str)
    }
}

// ── Match Result ──────────────────────────────────────────────────

/// Result of testing a rule against an event.
#[derive(Clone, Debug, Serialize)]
pub struct MatchResult {
    /// Rule name.
    pub rule_name: String,
    /// Whether the event matched.
    pub matched: bool,
    /// Reason for match/mismatch.
    pub reason: String,
    /// Rendered action inputs (only if matched).
    pub rendered_inputs: Option<BTreeMap<String, String>>,
}

/// Outcome of rule execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Action executed successfully.
    Executed,
    /// Rule matched but throttled.
    Throttled,
    /// Rule matched but circuit breaker is open.
    CircuitBroken,
    /// Rule matched but in dry-run mode.
    DryRun,
    /// Rule did not match.
    NoMatch,
    /// Rule is disabled.
    Disabled,
}

impl fmt::Display for ExecutionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executed => f.write_str("executed"),
            Self::Throttled => f.write_str("throttled"),
            Self::CircuitBroken => f.write_str("circuit_broken"),
            Self::DryRun => f.write_str("dry_run"),
            Self::NoMatch => f.write_str("no_match"),
            Self::Disabled => f.write_str("disabled"),
        }
    }
}

// ── Throttle State ────────────────────────────────────────────────

/// Tracks trigger history for throttle enforcement.
#[derive(Clone, Debug)]
pub struct ThrottleState {
    /// Rule name.
    pub rule_name: String,
    /// Timestamps of recent triggers within the window.
    pub triggers: Vec<DateTime<Utc>>,
}

impl ThrottleState {
    /// Create empty state for a rule.
    pub fn new(rule_name: impl Into<String>) -> Self {
        Self {
            rule_name: rule_name.into(),
            triggers: Vec::new(),
        }
    }

    /// Record a trigger now.
    pub fn record_trigger(&mut self) {
        self.triggers.push(Utc::now());
    }

    /// Record a trigger at a specific time (for testing).
    pub fn record_trigger_at(&mut self, at: DateTime<Utc>) {
        self.triggers.push(at);
    }

    /// Count triggers within the given window from now.
    pub fn count_in_window(&self, window: Duration) -> usize {
        let cutoff = Utc::now() - window;
        self.triggers.iter().filter(|t| **t >= cutoff).count()
    }

    /// Whether throttle limit has been reached.
    pub fn is_throttled(&self, throttle: &RuleThrottle) -> bool {
        let window = throttle.window_duration().unwrap_or_else(|| Duration::hours(1));
        let count = self.count_in_window(window);
        count >= throttle.max as usize
    }

    /// Prune old triggers outside the window.
    pub fn prune(&mut self, window: Duration) {
        let cutoff = Utc::now() - window;
        self.triggers.retain(|t| *t >= cutoff);
    }
}

// ── Circuit Breaker ───────────────────────────────────────────────

/// Circuit breaker state for a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Too many errors, rule is disabled.
    Open,
    /// Testing if the rule has recovered.
    HalfOpen,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("closed"),
            Self::Open => f.write_str("open"),
            Self::HalfOpen => f.write_str("half_open"),
        }
    }
}

/// Circuit breaker for automatic rule disabling on errors.
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    /// Current state.
    pub state: CircuitState,
    /// Consecutive error count.
    pub error_count: u32,
    /// Threshold to trip the breaker.
    pub error_threshold: u32,
    /// When the circuit was opened (for reset timing).
    pub opened_at: Option<DateTime<Utc>>,
    /// How long to wait before half-open test.
    pub reset_timeout: Duration,
    /// Total executions.
    pub total_executions: u64,
    /// Total errors.
    pub total_errors: u64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    pub const fn new(error_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            error_count: 0,
            error_threshold,
            opened_at: None,
            reset_timeout,
            total_executions: 0,
            total_errors: 0,
        }
    }

    /// Whether the circuit allows execution.
    pub fn allows_execution(&self) -> bool {
        match self.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => {
                // Check if reset timeout has elapsed
                self.opened_at
                    .is_some_and(|opened| Utc::now() - opened >= self.reset_timeout)
            }
        }
    }

    /// Record a successful execution.
    pub fn record_success(&mut self) {
        self.total_executions += 1;
        self.error_count = 0;
        if self.state == CircuitState::HalfOpen {
            self.state = CircuitState::Closed;
            self.opened_at = None;
        }
    }

    /// Record a failed execution.
    pub fn record_failure(&mut self) {
        self.total_executions += 1;
        self.total_errors += 1;
        self.error_count += 1;

        if self.error_count >= self.error_threshold {
            self.state = CircuitState::Open;
            self.opened_at = Some(Utc::now());
        }
    }

    /// Transition to half-open for a test execution.
    pub fn try_half_open(&mut self) -> bool {
        if self.state == CircuitState::Open && self.allows_execution() {
            self.state = CircuitState::HalfOpen;
            self.error_count = 0;
            true
        } else {
            false
        }
    }

    /// Error rate as a percentage (0-100).
    pub fn error_rate(&self) -> u8 {
        if self.total_executions == 0 {
            return 0;
        }
        (self.total_errors * 100)
            .checked_div(self.total_executions)
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(100)
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, Duration::minutes(5))
    }
}

// ── Event Matching ────────────────────────────────────────────────

/// Check if an event matches a trigger's criteria.
pub fn matches_trigger(event: &IncomingEvent, trigger: &EventTrigger) -> bool {
    // Connector must match
    if event.connector != trigger.connector {
        return false;
    }

    // Event type must match
    if event.event_type != trigger.event_type {
        return false;
    }

    // Match expression (if present)
    if let Some(ref expr) = trigger.match_expr {
        return evaluate_match_expr(event, expr);
    }

    true
}

/// Evaluate a match expression against event data.
///
/// Format: `"field~pattern1|pattern2"` — field value contains any of the patterns.
fn evaluate_match_expr(event: &IncomingEvent, expr: &str) -> bool {
    // Parse "field~patterns"
    let Some((field, patterns)) = expr.split_once('~') else {
        return false;
    };

    let Some(value) = event.get_field(field) else {
        return false;
    };

    // Check if value matches any of the pipe-separated patterns
    patterns
        .split('|')
        .any(|pattern| value.contains(pattern.trim()))
}

/// Render template strings with event data.
///
/// Replaces `{{event.data.field}}` and `{{event.connector}}` etc.
pub fn render_template(template: &str, event: &IncomingEvent) -> String {
    let mut result = template.to_string();

    // Replace {{event.connector}}
    result = result.replace("{{event.connector}}", &event.connector);
    result = result.replace("{{event.event_type}}", &event.event_type);

    // Replace {{event.data.field}} patterns
    for (key, value) in &event.data {
        let placeholder = format!("{{{{event.data.{key}}}}}");
        result = result.replace(&placeholder, value);
    }

    // Handle truncate filter: {{event.data.field | truncate(N)}}
    while let Some(start) = result.find("{{event.data.") {
        let Some(end) = result[start..].find("}}") else {
            break;
        };
        let full = &result[start..start + end + 2];

        // Check for truncate filter
        if let Some(inner) = full
            .strip_prefix("{{")
            .and_then(|s| s.strip_suffix("}}"))
        {
            if let Some((field_part, filter_part)) = inner.split_once('|') {
                let trimmed = field_part.trim();
                let field = trimmed.strip_prefix("event.data.").unwrap_or(trimmed);
                let filter = filter_part.trim();

                if let Some(limit_str) = filter
                    .strip_prefix("truncate(")
                    .and_then(|s| s.strip_suffix(')'))
                {
                    if let Ok(limit) = limit_str.parse::<usize>() {
                        let value = event.data.get(field).map_or("", String::as_str);
                        let truncated = if value.len() > limit {
                            format!("{}...", &value[..limit])
                        } else {
                            value.to_string()
                        };
                        result = result.replacen(full, &truncated, 1);
                        continue;
                    }
                }
            }
        }

        // If we couldn't process this placeholder, replace with empty to avoid infinite loop
        result = result.replacen(full, "", 1);
    }

    result
}

/// Render all action inputs with event data.
pub fn render_action_inputs(
    action: &RuleAction,
    event: &IncomingEvent,
) -> BTreeMap<String, String> {
    action
        .input
        .iter()
        .map(|(k, v)| (k.clone(), render_template(v, event)))
        .collect()
}

// ── Rule Evaluation ───────────────────────────────────────────────

/// Evaluate a rule against an event, checking match + throttle + circuit breaker.
pub fn evaluate_rule(
    rule: &Rule,
    event: &IncomingEvent,
    throttle_state: &ThrottleState,
    circuit_breaker: &CircuitBreaker,
    dry_run: bool,
) -> (ExecutionOutcome, MatchResult) {
    let rule_name = rule.name.clone();

    // Check if disabled
    if !rule.enabled {
        return (
            ExecutionOutcome::Disabled,
            MatchResult {
                rule_name,
                matched: false,
                reason: "rule is disabled".to_string(),
                rendered_inputs: None,
            },
        );
    }

    // Check event match
    if !matches_trigger(event, &rule.trigger) {
        return (
            ExecutionOutcome::NoMatch,
            MatchResult {
                rule_name,
                matched: false,
                reason: "event does not match trigger".to_string(),
                rendered_inputs: None,
            },
        );
    }

    // Render inputs
    let rendered = render_action_inputs(&rule.action, event);

    // Check circuit breaker
    if !circuit_breaker.allows_execution() {
        return (
            ExecutionOutcome::CircuitBroken,
            MatchResult {
                rule_name,
                matched: true,
                reason: "circuit breaker is open".to_string(),
                rendered_inputs: Some(rendered),
            },
        );
    }

    // Check throttle
    if throttle_state.is_throttled(&rule.throttle) {
        return (
            ExecutionOutcome::Throttled,
            MatchResult {
                rule_name,
                matched: true,
                reason: format!(
                    "throttled: {} triggers in {}",
                    rule.throttle.max, rule.throttle.window
                ),
                rendered_inputs: Some(rendered),
            },
        );
    }

    // Dry run?
    if dry_run {
        return (
            ExecutionOutcome::DryRun,
            MatchResult {
                rule_name,
                matched: true,
                reason: "dry run — would execute".to_string(),
                rendered_inputs: Some(rendered),
            },
        );
    }

    // Execute
    (
        ExecutionOutcome::Executed,
        MatchResult {
            rule_name,
            matched: true,
            reason: "matched and executed".to_string(),
            rendered_inputs: Some(rendered),
        },
    )
}

// ── Rule Set ──────────────────────────────────────────────────────

/// A collection of rules.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleSet {
    /// Rules in the set.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Create an empty rule set.
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule.
    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Get a rule by name.
    pub fn get(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.name == name)
    }

    /// Get a mutable rule by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Rule> {
        self.rules.iter_mut().find(|r| r.name == name)
    }

    /// Remove a rule by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.name != name);
        self.rules.len() < len_before
    }

    /// Count of active (enabled) rules.
    pub fn active_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// All enabled rules that match a given event.
    pub fn matching_rules(&self, event: &IncomingEvent) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.enabled && matches_trigger(event, &r.trigger))
            .collect()
    }

    /// Total number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the rule set is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// ── Display helpers ───────────────────────────────────────────────

/// Format a rule for TOON display.
pub fn format_rule_summary(rule: &Rule) -> String {
    let status = if rule.enabled { "enabled" } else { "disabled" };
    let desc = if rule.description.is_empty() {
        String::new()
    } else {
        format!(" — {}", rule.description)
    };
    format!(
        "{} [{}] {} → {}.{}{}",
        rule.name, status, rule.trigger.event_type, rule.action.connector, rule.action.operation, desc
    )
}

/// Format a match result for TOON display.
pub fn format_match_result(result: &MatchResult) -> String {
    let status = if result.matched { "✓" } else { "✗" };
    let mut output = format!("{status} {} — {}", result.rule_name, result.reason);
    if let Some(ref inputs) = result.rendered_inputs {
        if !inputs.is_empty() {
            output.push_str("\n  Inputs:");
            for (k, v) in inputs {
                use std::fmt::Write;
                let _ = write!(output, "\n    {k}: {v}");
            }
        }
    }
    output
}

// ── Parsing helpers ───────────────────────────────────────────────

/// Parse a window duration string (e.g., "30m", "1h", "1d").
fn parse_window(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = s.strip_suffix('s').map_or_else(
        || {
            s.strip_suffix('m').map_or_else(
                || {
                    s.strip_suffix('h').map_or_else(
                        || {
                            s.strip_suffix('d')
                                .map_or_else(|| (s, 's'), |stripped| (stripped, 'd'))
                        },
                        |stripped| (stripped, 'h'),
                    )
                },
                |stripped| (stripped, 'm'),
            )
        },
        |stripped| (stripped, 's'),
    );
    let num: i64 = num_str.parse().ok()?;
    if num < 0 {
        return None;
    }
    match unit {
        's' => Some(Duration::seconds(num)),
        'm' => Some(Duration::minutes(num)),
        'h' => Some(Duration::hours(num)),
        'd' => Some(Duration::days(num)),
        _ => None,
    }
}

/// Validate a rule definition.
pub fn validate_rule(rule: &Rule) -> Vec<String> {
    let mut errors = Vec::new();

    if rule.name.is_empty() {
        errors.push("rule name is required".to_string());
    }
    if rule.name.len() > 128 {
        errors.push("rule name must be <= 128 characters".to_string());
    }
    if rule.trigger.connector.is_empty() {
        errors.push("trigger connector is required".to_string());
    }
    if rule.trigger.event_type.is_empty() {
        errors.push("trigger event type is required".to_string());
    }
    if rule.action.connector.is_empty() {
        errors.push("action connector is required".to_string());
    }
    if rule.action.operation.is_empty() {
        errors.push("action operation is required".to_string());
    }
    if rule.throttle.max == 0 {
        errors.push("throttle max must be > 0".to_string());
    }
    if rule.throttle.window_duration().is_none() {
        errors.push(format!("invalid throttle window: '{}'", rule.throttle.window));
    }

    errors
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trigger() -> EventTrigger {
        EventTrigger::new("slack", "message.new")
    }

    fn sample_action() -> RuleAction {
        RuleAction::new("github", "create_issue")
            .with_input("title", "Bug: {{event.data.text}}")
            .with_input("body", "From {{event.data.user}}")
    }

    fn sample_rule() -> Rule {
        Rule::new("bug-to-issue", sample_trigger(), sample_action())
    }

    fn sample_event() -> IncomingEvent {
        IncomingEvent::new("slack", "message.new")
            .with_data("text", "Found a bug in login")
            .with_data("user", "alice")
            .with_data("channel", "general")
    }

    // ── EventTrigger ──────────────────────────────────────────────

    #[test]
    fn trigger_basic() {
        let t = EventTrigger::new("slack", "message.new");
        assert_eq!(t.connector, "slack");
        assert_eq!(t.event_type, "message.new");
        assert!(t.match_expr.is_none());
    }

    #[test]
    fn trigger_with_match() {
        let t = EventTrigger::new("slack", "message.new")
            .with_match("data.text~bug|Bug");
        assert_eq!(t.match_expr.as_deref(), Some("data.text~bug|Bug"));
    }

    #[test]
    fn trigger_serializes() {
        let t = EventTrigger::new("slack", "message.new");
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["connector"], "slack");
        assert_eq!(json["type"], "message.new");
    }

    // ── RuleAction ────────────────────────────────────────────────

    #[test]
    fn action_basic() {
        let a = RuleAction::new("github", "create_issue");
        assert_eq!(a.connector, "github");
        assert_eq!(a.operation, "create_issue");
        assert!(a.input.is_empty());
    }

    #[test]
    fn action_with_inputs() {
        let a = sample_action();
        assert_eq!(a.input.len(), 2);
        assert!(a.input.contains_key("title"));
    }

    // ── RuleThrottle ──────────────────────────────────────────────

    #[test]
    fn throttle_default() {
        let t = RuleThrottle::default();
        assert_eq!(t.max, 10);
        assert_eq!(t.window, "1h");
    }

    #[test]
    fn throttle_window_duration() {
        let t = RuleThrottle::new(5, "1h");
        assert_eq!(t.window_duration(), Some(Duration::hours(1)));
    }

    #[test]
    fn throttle_window_minutes() {
        let t = RuleThrottle::new(5, "30m");
        assert_eq!(t.window_duration(), Some(Duration::minutes(30)));
    }

    #[test]
    fn throttle_window_days() {
        let t = RuleThrottle::new(5, "1d");
        assert_eq!(t.window_duration(), Some(Duration::days(1)));
    }

    #[test]
    fn throttle_window_invalid() {
        let t = RuleThrottle::new(5, "xyz");
        assert!(t.window_duration().is_none());
    }

    // ── Rule ──────────────────────────────────────────────────────

    #[test]
    fn rule_basic() {
        let r = sample_rule();
        assert_eq!(r.name, "bug-to-issue");
        assert!(r.enabled);
        assert!(r.description.is_empty());
    }

    #[test]
    fn rule_with_description() {
        let r = sample_rule().with_description("Auto-create issues from Slack bugs");
        assert_eq!(r.description, "Auto-create issues from Slack bugs");
    }

    #[test]
    fn rule_with_throttle() {
        let r = sample_rule().with_throttle(RuleThrottle::new(5, "1h"));
        assert_eq!(r.throttle.max, 5);
    }

    #[test]
    fn rule_disabled() {
        let r = sample_rule().with_enabled(false);
        assert!(!r.enabled);
    }

    #[test]
    fn rule_serializes() {
        let r = sample_rule();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["name"], "bug-to-issue");
        assert_eq!(json["enabled"], true);
    }

    // ── IncomingEvent ─────────────────────────────────────────────

    #[test]
    fn event_basic() {
        let e = sample_event();
        assert_eq!(e.connector, "slack");
        assert_eq!(e.event_type, "message.new");
        assert_eq!(e.data.len(), 3);
    }

    #[test]
    fn event_get_field() {
        let e = sample_event();
        assert_eq!(e.get_field("data.text"), Some("Found a bug in login"));
        assert_eq!(e.get_field("text"), Some("Found a bug in login"));
        assert_eq!(e.get_field("data.missing"), None);
    }

    // ── ExecutionOutcome ──────────────────────────────────────────

    #[test]
    fn outcome_display() {
        assert_eq!(ExecutionOutcome::Executed.to_string(), "executed");
        assert_eq!(ExecutionOutcome::Throttled.to_string(), "throttled");
        assert_eq!(ExecutionOutcome::CircuitBroken.to_string(), "circuit_broken");
        assert_eq!(ExecutionOutcome::DryRun.to_string(), "dry_run");
        assert_eq!(ExecutionOutcome::NoMatch.to_string(), "no_match");
        assert_eq!(ExecutionOutcome::Disabled.to_string(), "disabled");
    }

    #[test]
    fn outcome_serializes() {
        let json = serde_json::to_value(ExecutionOutcome::Executed).unwrap();
        assert_eq!(json, "executed");
    }

    // ── matches_trigger ───────────────────────────────────────────

    #[test]
    fn trigger_matches_basic() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.new");
        assert!(matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_no_match_connector() {
        let event = sample_event();
        let trigger = EventTrigger::new("discord", "message.new");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_no_match_type() {
        let event = sample_event();
        let trigger = EventTrigger::new("slack", "message.deleted");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_matches_with_expr() {
        let event = sample_event();
        let trigger =
            EventTrigger::new("slack", "message.new").with_match("data.text~bug|Bug");
        assert!(matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_no_match_expr() {
        let event = sample_event();
        let trigger =
            EventTrigger::new("slack", "message.new").with_match("data.text~CRITICAL|urgent");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_match_expr_missing_field() {
        let event = sample_event();
        let trigger =
            EventTrigger::new("slack", "message.new").with_match("data.missing~test");
        assert!(!matches_trigger(&event, &trigger));
    }

    #[test]
    fn trigger_match_expr_invalid_format() {
        let event = sample_event();
        let trigger =
            EventTrigger::new("slack", "message.new").with_match("no-tilde-here");
        assert!(!matches_trigger(&event, &trigger));
    }

    // ── render_template ───────────────────────────────────────────

    #[test]
    fn template_simple_replacement() {
        let event = sample_event();
        let result = render_template("Hello {{event.data.user}}", &event);
        assert_eq!(result, "Hello alice");
    }

    #[test]
    fn template_connector_replacement() {
        let event = sample_event();
        let result = render_template("From {{event.connector}}", &event);
        assert_eq!(result, "From slack");
    }

    #[test]
    fn template_event_type_replacement() {
        let event = sample_event();
        let result = render_template("Type: {{event.event_type}}", &event);
        assert_eq!(result, "Type: message.new");
    }

    #[test]
    fn template_multiple_replacements() {
        let event = sample_event();
        let result = render_template(
            "{{event.data.user}} in #{{event.data.channel}}: {{event.data.text}}",
            &event,
        );
        assert_eq!(result, "alice in #general: Found a bug in login");
    }

    #[test]
    fn template_no_placeholders() {
        let event = sample_event();
        let result = render_template("plain text", &event);
        assert_eq!(result, "plain text");
    }

    #[test]
    fn template_truncate_filter() {
        let event = sample_event();
        let result = render_template("{{event.data.text | truncate(10)}}", &event);
        assert_eq!(result, "Found a bu...");
    }

    #[test]
    fn template_truncate_no_truncation_needed() {
        let event = IncomingEvent::new("slack", "message.new").with_data("text", "short");
        let result = render_template("{{event.data.text | truncate(80)}}", &event);
        assert_eq!(result, "short");
    }

    // ── render_action_inputs ──────────────────────────────────────

    #[test]
    fn render_inputs() {
        let event = sample_event();
        let action = sample_action();
        let rendered = render_action_inputs(&action, &event);
        assert_eq!(rendered["title"], "Bug: Found a bug in login");
        assert_eq!(rendered["body"], "From alice");
    }

    // ── ThrottleState ─────────────────────────────────────────────

    #[test]
    fn throttle_state_empty() {
        let state = ThrottleState::new("rule1");
        assert_eq!(state.count_in_window(Duration::hours(1)), 0);
    }

    #[test]
    fn throttle_state_counts() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger();
        state.record_trigger();
        assert_eq!(state.count_in_window(Duration::hours(1)), 2);
    }

    #[test]
    fn throttle_state_old_triggers_excluded() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger_at(Utc::now() - Duration::hours(2));
        state.record_trigger();
        assert_eq!(state.count_in_window(Duration::hours(1)), 1);
    }

    #[test]
    fn throttle_not_throttled() {
        let state = ThrottleState::new("rule1");
        let throttle = RuleThrottle::new(5, "1h");
        assert!(!state.is_throttled(&throttle));
    }

    #[test]
    fn throttle_is_throttled() {
        let mut state = ThrottleState::new("rule1");
        for _ in 0..5 {
            state.record_trigger();
        }
        let throttle = RuleThrottle::new(5, "1h");
        assert!(state.is_throttled(&throttle));
    }

    #[test]
    fn throttle_prune() {
        let mut state = ThrottleState::new("rule1");
        state.record_trigger_at(Utc::now() - Duration::hours(3));
        state.record_trigger_at(Utc::now() - Duration::hours(2));
        state.record_trigger();
        state.prune(Duration::hours(1));
        assert_eq!(state.triggers.len(), 1);
    }

    // ── CircuitBreaker ────────────────────────────────────────────

    #[test]
    fn circuit_default_closed() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.allows_execution());
    }

    #[test]
    fn circuit_opens_after_threshold() {
        let mut cb = CircuitBreaker::new(3, Duration::minutes(5));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        assert!(!cb.allows_execution());
    }

    #[test]
    fn circuit_success_resets_count() {
        let mut cb = CircuitBreaker::new(3, Duration::minutes(5));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.error_count, 0);
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn circuit_half_open_on_timeout() {
        let mut cb = CircuitBreaker::new(3, Duration::seconds(0));
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        // Timeout is 0s, so immediate half-open
        assert!(cb.try_half_open());
        assert_eq!(cb.state, CircuitState::HalfOpen);
    }

    #[test]
    fn circuit_half_open_success_closes() {
        let mut cb = CircuitBreaker::new(3, Duration::seconds(0));
        for _ in 0..3 {
            cb.record_failure();
        }
        cb.try_half_open();
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn circuit_error_rate() {
        let mut cb = CircuitBreaker::new(10, Duration::minutes(5));
        for _ in 0..7 {
            cb.record_success();
        }
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.error_rate(), 30);
    }

    #[test]
    fn circuit_error_rate_zero() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.error_rate(), 0);
    }

    #[test]
    fn circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }

    // ── evaluate_rule ─────────────────────────────────────────────

    #[test]
    fn eval_rule_executes() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Executed);
        assert!(result.matched);
        assert!(result.rendered_inputs.is_some());
    }

    #[test]
    fn eval_rule_no_match() {
        let rule = sample_rule();
        let event = IncomingEvent::new("discord", "message.new");
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::NoMatch);
    }

    #[test]
    fn eval_rule_disabled() {
        let rule = sample_rule().with_enabled(false);
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Disabled);
    }

    #[test]
    fn eval_rule_throttled() {
        let rule = sample_rule().with_throttle(RuleThrottle::new(2, "1h"));
        let event = sample_event();
        let mut state = ThrottleState::new("bug-to-issue");
        state.record_trigger();
        state.record_trigger();
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::Throttled);
        assert!(result.matched);
    }

    #[test]
    fn eval_rule_circuit_broken() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let mut cb = CircuitBreaker::new(1, Duration::hours(1));
        cb.record_failure();
        let (outcome, _) = evaluate_rule(&rule, &event, &state, &cb, false);
        assert_eq!(outcome, ExecutionOutcome::CircuitBroken);
    }

    #[test]
    fn eval_rule_dry_run() {
        let rule = sample_rule();
        let event = sample_event();
        let state = ThrottleState::new("bug-to-issue");
        let cb = CircuitBreaker::default();
        let (outcome, result) = evaluate_rule(&rule, &event, &state, &cb, true);
        assert_eq!(outcome, ExecutionOutcome::DryRun);
        assert!(result.matched);
        assert!(result.rendered_inputs.is_some());
    }

    // ── RuleSet ───────────────────────────────────────────────────

    #[test]
    fn ruleset_empty() {
        let rs = RuleSet::new();
        assert!(rs.is_empty());
        assert_eq!(rs.len(), 0);
    }

    #[test]
    fn ruleset_add_and_get() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        assert_eq!(rs.len(), 1);
        assert!(rs.get("bug-to-issue").is_some());
        assert!(rs.get("nonexistent").is_none());
    }

    #[test]
    fn ruleset_remove() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        assert!(rs.remove("bug-to-issue"));
        assert!(rs.is_empty());
        assert!(!rs.remove("nonexistent"));
    }

    #[test]
    fn ruleset_active_count() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        rs.add(sample_rule().with_enabled(false));
        assert_eq!(rs.active_count(), 1);
    }

    #[test]
    fn ruleset_matching_rules() {
        let mut rs = RuleSet::new();
        rs.add(Rule::new(
            "slack-rule",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("github", "create_issue"),
        ));
        rs.add(Rule::new(
            "discord-rule",
            EventTrigger::new("discord", "message.new"),
            RuleAction::new("github", "create_issue"),
        ));
        let event = sample_event();
        let matched = rs.matching_rules(&event);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "slack-rule");
    }

    #[test]
    fn ruleset_matching_excludes_disabled() {
        let mut rs = RuleSet::new();
        rs.add(
            Rule::new(
                "disabled-rule",
                EventTrigger::new("slack", "message.new"),
                RuleAction::new("github", "create_issue"),
            )
            .with_enabled(false),
        );
        let event = sample_event();
        assert!(rs.matching_rules(&event).is_empty());
    }

    #[test]
    fn ruleset_get_mut() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        if let Some(r) = rs.get_mut("bug-to-issue") {
            r.enabled = false;
        }
        assert!(!rs.get("bug-to-issue").unwrap().enabled);
    }

    #[test]
    fn ruleset_serializes() {
        let mut rs = RuleSet::new();
        rs.add(sample_rule());
        let json = serde_json::to_value(&rs).unwrap();
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
    }

    // ── validate_rule ─────────────────────────────────────────────

    #[test]
    fn validate_valid_rule() {
        let r = sample_rule();
        assert!(validate_rule(&r).is_empty());
    }

    #[test]
    fn validate_empty_name() {
        let r = Rule::new("", sample_trigger(), sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("name")));
    }

    #[test]
    fn validate_long_name() {
        let name = "x".repeat(200);
        let r = Rule::new(name, sample_trigger(), sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("128")));
    }

    #[test]
    fn validate_empty_trigger_connector() {
        let t = EventTrigger::new("", "message.new");
        let r = Rule::new("rule", t, sample_action());
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("trigger connector")));
    }

    #[test]
    fn validate_empty_action_operation() {
        let a = RuleAction::new("github", "");
        let r = Rule::new("rule", sample_trigger(), a);
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("action operation")));
    }

    #[test]
    fn validate_zero_throttle_max() {
        let r = sample_rule().with_throttle(RuleThrottle::new(0, "1h"));
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("throttle max")));
    }

    #[test]
    fn validate_invalid_throttle_window() {
        let r = sample_rule().with_throttle(RuleThrottle::new(5, "xyz"));
        let errors = validate_rule(&r);
        assert!(errors.iter().any(|e| e.contains("invalid throttle window")));
    }

    // ── format helpers ────────────────────────────────────────────

    #[test]
    fn format_rule_summary_enabled() {
        let r = sample_rule().with_description("Create issues from bugs");
        let s = format_rule_summary(&r);
        assert!(s.contains("bug-to-issue"));
        assert!(s.contains("enabled"));
        assert!(s.contains("github.create_issue"));
    }

    #[test]
    fn format_rule_summary_disabled() {
        let r = sample_rule().with_enabled(false);
        let s = format_rule_summary(&r);
        assert!(s.contains("disabled"));
    }

    #[test]
    fn format_match_result_matched() {
        let result = MatchResult {
            rule_name: "test".to_string(),
            matched: true,
            reason: "matched".to_string(),
            rendered_inputs: Some(BTreeMap::from([(
                "title".to_string(),
                "Bug report".to_string(),
            )])),
        };
        let s = format_match_result(&result);
        assert!(s.starts_with('✓'));
        assert!(s.contains("title: Bug report"));
    }

    #[test]
    fn format_match_result_no_match() {
        let result = MatchResult {
            rule_name: "test".to_string(),
            matched: false,
            reason: "no match".to_string(),
            rendered_inputs: None,
        };
        let s = format_match_result(&result);
        assert!(s.starts_with('✗'));
    }

    // ── parse_window ──────────────────────────────────────────────

    #[test]
    fn parse_window_seconds() {
        assert_eq!(parse_window("30s"), Some(Duration::seconds(30)));
    }

    #[test]
    fn parse_window_minutes() {
        assert_eq!(parse_window("5m"), Some(Duration::minutes(5)));
    }

    #[test]
    fn parse_window_hours() {
        assert_eq!(parse_window("1h"), Some(Duration::hours(1)));
    }

    #[test]
    fn parse_window_days() {
        assert_eq!(parse_window("7d"), Some(Duration::days(7)));
    }

    #[test]
    fn parse_window_invalid() {
        assert_eq!(parse_window("abc"), None);
        assert_eq!(parse_window(""), None);
    }
}
