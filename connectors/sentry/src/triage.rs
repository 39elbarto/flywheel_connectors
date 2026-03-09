//! Sentry issue triage engine — auto-create actionable work items (beads) from Sentry issues.
//!
//! Maps Sentry issue severity and frequency to bead priority, deduplicates
//! issues, and tracks which issues have already been triaged.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ── Issue level ──────────────────────────────────────────────────────

/// Sentry issue severity level, ordered from most to least critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IssueLevel {
    Fatal,
    Error,
    Warning,
    Info,
    Debug,
}

impl IssueLevel {
    /// Returns a numeric rank where lower numbers are more critical.
    const fn rank(self) -> u8 {
        match self {
            Self::Fatal => 0,
            Self::Error => 1,
            Self::Warning => 2,
            Self::Info => 3,
            Self::Debug => 4,
        }
    }

    /// Parses a level string (case-insensitive) into an `IssueLevel`.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fatal" => Some(Self::Fatal),
            "error" => Some(Self::Error),
            "warning" | "warn" => Some(Self::Warning),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            _ => None,
        }
    }
}

impl PartialOrd for IssueLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IssueLevel {
    /// More critical levels compare as *less* (Fatal < Error < Warning < Info < Debug).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fatal => write!(f, "fatal"),
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
            Self::Info => write!(f, "info"),
            Self::Debug => write!(f, "debug"),
        }
    }
}

// ── Bead priority ────────────────────────────────────────────────────

/// Priority for a created bead, from most to least urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BeadPriority {
    P0,
    P1,
    P2,
    P3,
}

impl BeadPriority {
    /// Derive priority from the issue level alone.
    pub const fn from_issue_level(level: IssueLevel) -> Self {
        match level {
            IssueLevel::Fatal => Self::P0,
            IssueLevel::Error => Self::P1,
            IssueLevel::Warning => Self::P2,
            IssueLevel::Info | IssueLevel::Debug => Self::P3,
        }
    }

    /// Derive priority from the total event count.
    pub const fn from_event_count(count: u64) -> Self {
        match count {
            1000.. => Self::P0,
            100..=999 => Self::P1,
            10..=99 => Self::P2,
            _ => Self::P3,
        }
    }

    /// Returns the more urgent of two priorities.
    #[must_use]
    pub const fn higher(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
        }
    }
}

impl PartialOrd for BeadPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BeadPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for BeadPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P0 => write!(f, "P0"),
            Self::P1 => write!(f, "P1"),
            Self::P2 => write!(f, "P2"),
            Self::P3 => write!(f, "P3"),
        }
    }
}

// ── Issue summary ────────────────────────────────────────────────────

/// Lightweight summary of a Sentry issue, suitable for passing to the triage engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueSummary {
    pub id: String,
    pub title: String,
    pub level: IssueLevel,
    pub event_count: u64,
    pub user_count: u64,
    pub project_slug: String,
    pub first_seen: String,
    pub last_seen: String,
    pub culprit: Option<String>,
}

// ── Triage rule ──────────────────────────────────────────────────────

/// A rule that determines whether a Sentry issue should be auto-triaged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageRule {
    pub name: String,
    pub min_event_count: u64,
    pub min_user_count: u64,
    pub levels: Vec<IssueLevel>,
    pub projects: Vec<String>,
    pub auto_assign: Option<String>,
    pub priority_override: Option<BeadPriority>,
}

impl TriageRule {
    /// Returns `true` if the given issue matches all of this rule's criteria.
    pub fn matches_issue(&self, issue: &IssueSummary) -> bool {
        if issue.event_count < self.min_event_count {
            return false;
        }
        if issue.user_count < self.min_user_count {
            return false;
        }
        if !self.levels.is_empty() && !self.levels.contains(&issue.level) {
            return false;
        }
        if !self.projects.is_empty() && !self.projects.contains(&issue.project_slug) {
            return false;
        }
        true
    }
}

// ── Triage result ────────────────────────────────────────────────────

/// The outcome of triaging a single Sentry issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageResult {
    pub issue_id: String,
    pub issue_title: String,
    pub suggested_priority: BeadPriority,
    pub suggested_labels: Vec<String>,
    pub assignee: Option<String>,
    pub deduplicated: bool,
    pub existing_bead_id: Option<String>,
}

// ── Triage config ────────────────────────────────────────────────────

/// Configuration for the triage engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageConfig {
    pub default_priority: BeadPriority,
    pub dedup_enabled: bool,
    pub max_beads_per_run: usize,
    pub cooldown_seconds: u64,
    pub label_prefix: String,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            default_priority: BeadPriority::P2,
            dedup_enabled: true,
            max_beads_per_run: 50,
            cooldown_seconds: 300,
            label_prefix: "sentry".into(),
        }
    }
}

// ── Triage audit event ───────────────────────────────────────────────

/// Action taken during triage of a single issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TriageAction {
    Created,
    Skipped,
    Deduplicated,
}

impl std::fmt::Display for TriageAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Skipped => write!(f, "skipped"),
            Self::Deduplicated => write!(f, "deduplicated"),
        }
    }
}

/// An audit record for a triage decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageAuditEvent {
    pub timestamp: String,
    pub action: TriageAction,
    pub issue_id: String,
    pub bead_id: Option<String>,
    pub reason: String,
}

// ── Triage stats ─────────────────────────────────────────────────────

/// Aggregate statistics about a triage run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageStats {
    pub total_triaged: u64,
    pub beads_created: u64,
    pub deduplicated: u64,
    pub by_priority: HashMap<String, u64>,
}

impl Default for TriageStats {
    fn default() -> Self {
        Self {
            total_triaged: 0,
            beads_created: 0,
            deduplicated: 0,
            by_priority: HashMap::new(),
        }
    }
}

// ── Triage engine ────────────────────────────────────────────────────

/// Core triage engine: evaluates Sentry issues against rules, deduplicates,
/// and produces `TriageResult` outcomes with audit trails.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageEngine {
    rules: Vec<TriageRule>,
    seen_issues: HashSet<String>,
    created_beads: HashMap<String, String>,
    config: TriageConfig,
    #[serde(skip)]
    audit_log: Vec<TriageAuditEvent>,
    #[serde(skip)]
    run_stats: TriageStats,
}

impl TriageEngine {
    /// Create a new triage engine with the given config.
    pub fn new(config: TriageConfig) -> Self {
        Self {
            rules: Vec::new(),
            seen_issues: HashSet::new(),
            created_beads: HashMap::new(),
            config,
            audit_log: Vec::new(),
            run_stats: TriageStats::default(),
        }
    }

    /// Add a triage rule.
    pub fn add_rule(&mut self, rule: TriageRule) {
        self.rules.push(rule);
    }

    /// Mark an issue as already seen (won't create a new bead).
    pub fn mark_seen(&mut self, issue_id: &str) {
        self.seen_issues.insert(issue_id.to_owned());
    }

    /// Check whether an issue has already been seen.
    pub fn is_seen(&self, issue_id: &str) -> bool {
        self.seen_issues.contains(issue_id)
    }

    /// Look up the bead ID created for a given issue, if any.
    pub fn bead_for_issue(&self, issue_id: &str) -> Option<&str> {
        self.created_beads.get(issue_id).map(String::as_str)
    }

    /// Return aggregate statistics for the current run.
    pub const fn stats(&self) -> &TriageStats {
        &self.run_stats
    }

    /// Return the accumulated audit log.
    pub fn audit_log(&self) -> &[TriageAuditEvent] {
        &self.audit_log
    }

    /// Return the current config.
    pub const fn config(&self) -> &TriageConfig {
        &self.config
    }

    /// Return the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Triage a single issue, returning a result describing the action taken.
    pub fn triage_issue(&mut self, issue: &IssueSummary) -> TriageResult {
        self.run_stats.total_triaged += 1;

        // Deduplication check.
        if self.config.dedup_enabled && self.seen_issues.contains(&issue.id) {
            let existing_bead = self.created_beads.get(&issue.id).cloned();
            self.run_stats.deduplicated += 1;
            self.audit_log.push(TriageAuditEvent {
                timestamp: issue.last_seen.clone(),
                action: TriageAction::Deduplicated,
                issue_id: issue.id.clone(),
                bead_id: existing_bead.clone(),
                reason: "issue already triaged".into(),
            });
            return TriageResult {
                issue_id: issue.id.clone(),
                issue_title: issue.title.clone(),
                suggested_priority: self.config.default_priority,
                suggested_labels: Vec::new(),
                assignee: None,
                deduplicated: true,
                existing_bead_id: existing_bead,
            };
        }

        // Check max beads per run.
        if self.run_stats.beads_created >= self.config.max_beads_per_run as u64 {
            self.audit_log.push(TriageAuditEvent {
                timestamp: issue.last_seen.clone(),
                action: TriageAction::Skipped,
                issue_id: issue.id.clone(),
                bead_id: None,
                reason: "max beads per run reached".into(),
            });
            return TriageResult {
                issue_id: issue.id.clone(),
                issue_title: issue.title.clone(),
                suggested_priority: self.config.default_priority,
                suggested_labels: Vec::new(),
                assignee: None,
                deduplicated: false,
                existing_bead_id: None,
            };
        }

        // Find matching rules.
        let matching: Vec<&TriageRule> =
            self.rules.iter().filter(|r| r.matches_issue(issue)).collect();

        if matching.is_empty() {
            self.audit_log.push(TriageAuditEvent {
                timestamp: issue.last_seen.clone(),
                action: TriageAction::Skipped,
                issue_id: issue.id.clone(),
                bead_id: None,
                reason: "no matching rules".into(),
            });
            return TriageResult {
                issue_id: issue.id.clone(),
                issue_title: issue.title.clone(),
                suggested_priority: self.config.default_priority,
                suggested_labels: Vec::new(),
                assignee: None,
                deduplicated: false,
                existing_bead_id: None,
            };
        }

        // Compute priority: start from level+count, then apply overrides.
        let level_priority = BeadPriority::from_issue_level(issue.level);
        let count_priority = BeadPriority::from_event_count(issue.event_count);
        let mut priority = level_priority.higher(count_priority);

        let mut assignee: Option<String> = None;
        let mut labels: Vec<String> = Vec::new();

        // Add standard labels.
        labels.push(format!("{}:level:{}", self.config.label_prefix, issue.level));
        labels.push(format!(
            "{}:project:{}",
            self.config.label_prefix, issue.project_slug
        ));

        for rule in &matching {
            if let Some(override_p) = rule.priority_override {
                priority = priority.higher(override_p);
            }
            if assignee.is_none() {
                assignee.clone_from(&rule.auto_assign);
            }
            labels.push(format!("{}:rule:{}", self.config.label_prefix, rule.name));
        }

        labels.sort();
        labels.dedup();

        // Create the bead.
        let bead_id = format!("bead-{}", issue.id);
        self.seen_issues.insert(issue.id.clone());
        self.created_beads.insert(issue.id.clone(), bead_id.clone());
        self.run_stats.beads_created += 1;
        *self
            .run_stats
            .by_priority
            .entry(priority.to_string())
            .or_insert(0) += 1;

        self.audit_log.push(TriageAuditEvent {
            timestamp: issue.last_seen.clone(),
            action: TriageAction::Created,
            issue_id: issue.id.clone(),
            bead_id: Some(bead_id.clone()),
            reason: format!("matched {} rule(s)", matching.len()),
        });

        TriageResult {
            issue_id: issue.id.clone(),
            issue_title: issue.title.clone(),
            suggested_priority: priority,
            suggested_labels: labels,
            assignee,
            deduplicated: false,
            existing_bead_id: Some(bead_id),
        }
    }

    /// Triage a batch of issues, returning results for each.
    pub fn triage_batch(&mut self, issues: &[IssueSummary]) -> Vec<TriageResult> {
        issues.iter().map(|i| self.triage_issue(i)).collect()
    }

    /// Reset the per-run statistics and audit log (keeps rules and seen state).
    pub fn reset_run(&mut self) {
        self.run_stats = TriageStats::default();
        self.audit_log.clear();
    }
}

// ── Helper to build test issues ──────────────────────────────────────

fn make_issue(id: &str, title: &str, level: IssueLevel, events: u64, users: u64, project: &str) -> IssueSummary {
    IssueSummary {
        id: id.into(),
        title: title.into(),
        level,
        event_count: events,
        user_count: users,
        project_slug: project.into(),
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-03-01T00:00:00Z".into(),
        culprit: None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helper ───────────────────────────────────────────────────────

    fn default_engine() -> TriageEngine {
        TriageEngine::new(TriageConfig::default())
    }

    fn simple_rule(name: &str) -> TriageRule {
        TriageRule {
            name: name.into(),
            min_event_count: 0,
            min_user_count: 0,
            levels: Vec::new(),
            projects: Vec::new(),
            auto_assign: None,
            priority_override: None,
        }
    }

    fn issue(id: &str, level: IssueLevel, events: u64, users: u64, project: &str) -> IssueSummary {
        make_issue(id, &format!("Issue {id}"), level, events, users, project)
    }

    // ── IssueLevel tests ─────────────────────────────────────────────

    #[test]
    fn issue_level_ordering() {
        assert!(IssueLevel::Fatal < IssueLevel::Error);
        assert!(IssueLevel::Error < IssueLevel::Warning);
        assert!(IssueLevel::Warning < IssueLevel::Info);
        assert!(IssueLevel::Info < IssueLevel::Debug);
    }

    #[test]
    fn issue_level_eq() {
        assert_eq!(IssueLevel::Fatal, IssueLevel::Fatal);
        assert_ne!(IssueLevel::Fatal, IssueLevel::Error);
    }

    #[test]
    fn issue_level_from_str_loose_all() {
        assert_eq!(IssueLevel::from_str_loose("fatal"), Some(IssueLevel::Fatal));
        assert_eq!(IssueLevel::from_str_loose("error"), Some(IssueLevel::Error));
        assert_eq!(IssueLevel::from_str_loose("warning"), Some(IssueLevel::Warning));
        assert_eq!(IssueLevel::from_str_loose("warn"), Some(IssueLevel::Warning));
        assert_eq!(IssueLevel::from_str_loose("info"), Some(IssueLevel::Info));
        assert_eq!(IssueLevel::from_str_loose("debug"), Some(IssueLevel::Debug));
    }

    #[test]
    fn issue_level_from_str_case_insensitive() {
        assert_eq!(IssueLevel::from_str_loose("FATAL"), Some(IssueLevel::Fatal));
        assert_eq!(IssueLevel::from_str_loose("Error"), Some(IssueLevel::Error));
        assert_eq!(IssueLevel::from_str_loose("WARNING"), Some(IssueLevel::Warning));
    }

    #[test]
    fn issue_level_from_str_unknown() {
        assert_eq!(IssueLevel::from_str_loose("unknown"), None);
        assert_eq!(IssueLevel::from_str_loose(""), None);
        assert_eq!(IssueLevel::from_str_loose("critical"), None);
    }

    #[test]
    fn issue_level_display() {
        assert_eq!(IssueLevel::Fatal.to_string(), "fatal");
        assert_eq!(IssueLevel::Error.to_string(), "error");
        assert_eq!(IssueLevel::Warning.to_string(), "warning");
        assert_eq!(IssueLevel::Info.to_string(), "info");
        assert_eq!(IssueLevel::Debug.to_string(), "debug");
    }

    #[test]
    fn issue_level_clone() {
        let level = IssueLevel::Error;
        let cloned = level;
        assert_eq!(level, cloned);
    }

    #[test]
    fn issue_level_hash() {
        let mut set = HashSet::new();
        set.insert(IssueLevel::Fatal);
        set.insert(IssueLevel::Fatal);
        assert_eq!(set.len(), 1);
        set.insert(IssueLevel::Error);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn issue_level_debug_format() {
        let dbg = format!("{:?}", IssueLevel::Warning);
        assert!(dbg.contains("Warning"));
    }

    #[test]
    fn issue_level_serde_roundtrip() {
        let level = IssueLevel::Error;
        let json = serde_json::to_string(&level).unwrap();
        let back: IssueLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, IssueLevel::Error);
    }

    #[test]
    fn issue_level_serde_camel_case() {
        let json = serde_json::to_string(&IssueLevel::Fatal).unwrap();
        // camelCase rename
        assert!(json.contains("fatal"));
    }

    #[test]
    fn issue_level_sort_vec() {
        let mut levels = [
            IssueLevel::Debug,
            IssueLevel::Fatal,
            IssueLevel::Warning,
            IssueLevel::Error,
            IssueLevel::Info,
        ];
        levels.sort();
        assert_eq!(levels[0], IssueLevel::Fatal);
        assert_eq!(levels[4], IssueLevel::Debug);
    }

    #[test]
    fn issue_level_partial_ord_consistent() {
        assert!(IssueLevel::Fatal.partial_cmp(&IssueLevel::Error) == Some(std::cmp::Ordering::Less));
        assert!(IssueLevel::Debug.partial_cmp(&IssueLevel::Info) == Some(std::cmp::Ordering::Greater));
        assert!(IssueLevel::Warning.partial_cmp(&IssueLevel::Warning) == Some(std::cmp::Ordering::Equal));
    }

    // ── BeadPriority tests ───────────────────────────────────────────

    #[test]
    fn bead_priority_from_issue_level_fatal() {
        assert_eq!(BeadPriority::from_issue_level(IssueLevel::Fatal), BeadPriority::P0);
    }

    #[test]
    fn bead_priority_from_issue_level_error() {
        assert_eq!(BeadPriority::from_issue_level(IssueLevel::Error), BeadPriority::P1);
    }

    #[test]
    fn bead_priority_from_issue_level_warning() {
        assert_eq!(BeadPriority::from_issue_level(IssueLevel::Warning), BeadPriority::P2);
    }

    #[test]
    fn bead_priority_from_issue_level_info() {
        assert_eq!(BeadPriority::from_issue_level(IssueLevel::Info), BeadPriority::P3);
    }

    #[test]
    fn bead_priority_from_issue_level_debug() {
        assert_eq!(BeadPriority::from_issue_level(IssueLevel::Debug), BeadPriority::P3);
    }

    #[test]
    fn bead_priority_from_event_count_zero() {
        assert_eq!(BeadPriority::from_event_count(0), BeadPriority::P3);
    }

    #[test]
    fn bead_priority_from_event_count_low() {
        assert_eq!(BeadPriority::from_event_count(5), BeadPriority::P3);
    }

    #[test]
    fn bead_priority_from_event_count_medium() {
        assert_eq!(BeadPriority::from_event_count(50), BeadPriority::P2);
    }

    #[test]
    fn bead_priority_from_event_count_high() {
        assert_eq!(BeadPriority::from_event_count(500), BeadPriority::P1);
    }

    #[test]
    fn bead_priority_from_event_count_very_high() {
        assert_eq!(BeadPriority::from_event_count(5000), BeadPriority::P0);
    }

    #[test]
    fn bead_priority_from_event_count_boundaries() {
        assert_eq!(BeadPriority::from_event_count(9), BeadPriority::P3);
        assert_eq!(BeadPriority::from_event_count(10), BeadPriority::P2);
        assert_eq!(BeadPriority::from_event_count(99), BeadPriority::P2);
        assert_eq!(BeadPriority::from_event_count(100), BeadPriority::P1);
        assert_eq!(BeadPriority::from_event_count(999), BeadPriority::P1);
        assert_eq!(BeadPriority::from_event_count(1000), BeadPriority::P0);
    }

    #[test]
    fn bead_priority_higher_picks_more_urgent() {
        assert_eq!(BeadPriority::P2.higher(BeadPriority::P0), BeadPriority::P0);
        assert_eq!(BeadPriority::P0.higher(BeadPriority::P3), BeadPriority::P0);
    }

    #[test]
    fn bead_priority_higher_same() {
        assert_eq!(BeadPriority::P1.higher(BeadPriority::P1), BeadPriority::P1);
    }

    #[test]
    fn bead_priority_ordering() {
        assert!(BeadPriority::P0 < BeadPriority::P1);
        assert!(BeadPriority::P1 < BeadPriority::P2);
        assert!(BeadPriority::P2 < BeadPriority::P3);
    }

    #[test]
    fn bead_priority_display() {
        assert_eq!(BeadPriority::P0.to_string(), "P0");
        assert_eq!(BeadPriority::P1.to_string(), "P1");
        assert_eq!(BeadPriority::P2.to_string(), "P2");
        assert_eq!(BeadPriority::P3.to_string(), "P3");
    }

    #[test]
    fn bead_priority_serde_roundtrip() {
        let p = BeadPriority::P1;
        let json = serde_json::to_string(&p).unwrap();
        let back: BeadPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, BeadPriority::P1);
    }

    #[test]
    fn bead_priority_debug_format() {
        let dbg = format!("{:?}", BeadPriority::P0);
        assert!(dbg.contains("P0"));
    }

    #[test]
    fn bead_priority_hash() {
        let mut set = HashSet::new();
        set.insert(BeadPriority::P0);
        set.insert(BeadPriority::P0);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn bead_priority_sort_vec() {
        let mut priorities = vec![BeadPriority::P3, BeadPriority::P0, BeadPriority::P2, BeadPriority::P1];
        priorities.sort();
        assert_eq!(priorities, vec![BeadPriority::P0, BeadPriority::P1, BeadPriority::P2, BeadPriority::P3]);
    }

    // ── IssueSummary tests ───────────────────────────────────────────

    #[test]
    fn issue_summary_construction() {
        let s = issue("42", IssueLevel::Error, 100, 10, "backend");
        assert_eq!(s.id, "42");
        assert_eq!(s.level, IssueLevel::Error);
        assert_eq!(s.event_count, 100);
        assert_eq!(s.user_count, 10);
        assert_eq!(s.project_slug, "backend");
    }

    #[test]
    fn issue_summary_with_culprit() {
        let mut s = issue("1", IssueLevel::Fatal, 1, 1, "api");
        s.culprit = Some("com.example.Handler".into());
        assert_eq!(s.culprit.as_deref(), Some("com.example.Handler"));
    }

    #[test]
    fn issue_summary_clone() {
        let s = issue("1", IssueLevel::Warning, 50, 5, "web");
        let cloned = s.clone();
        assert_eq!(s.id, "1");
        assert_eq!(cloned.id, "1");
        assert_eq!(cloned.level, IssueLevel::Warning);
    }

    #[test]
    fn issue_summary_debug() {
        let s = issue("1", IssueLevel::Info, 10, 2, "mobile");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("IssueSummary"));
    }

    #[test]
    fn issue_summary_serde_roundtrip() {
        let s = issue("99", IssueLevel::Error, 200, 30, "backend");
        let json = serde_json::to_string(&s).unwrap();
        let back: IssueSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "99");
        assert_eq!(back.level, IssueLevel::Error);
        assert_eq!(back.event_count, 200);
    }

    #[test]
    fn issue_summary_serde_camel_case() {
        let s = issue("1", IssueLevel::Fatal, 1, 1, "api");
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("eventCount"));
        assert!(json.contains("userCount"));
        assert!(json.contains("projectSlug"));
        assert!(json.contains("firstSeen"));
        assert!(json.contains("lastSeen"));
    }

    // ── TriageRule tests ─────────────────────────────────────────────

    #[test]
    fn rule_matches_any_issue_when_empty_filters() {
        let rule = simple_rule("catch-all");
        let i = issue("1", IssueLevel::Debug, 0, 0, "any");
        assert!(rule.matches_issue(&i));
    }

    #[test]
    fn rule_filters_by_min_event_count() {
        let mut rule = simple_rule("high-volume");
        rule.min_event_count = 100;
        assert!(!rule.matches_issue(&issue("1", IssueLevel::Error, 99, 0, "api")));
        assert!(rule.matches_issue(&issue("2", IssueLevel::Error, 100, 0, "api")));
        assert!(rule.matches_issue(&issue("3", IssueLevel::Error, 200, 0, "api")));
    }

    #[test]
    fn rule_filters_by_min_user_count() {
        let mut rule = simple_rule("wide-impact");
        rule.min_user_count = 10;
        assert!(!rule.matches_issue(&issue("1", IssueLevel::Error, 50, 9, "api")));
        assert!(rule.matches_issue(&issue("2", IssueLevel::Error, 50, 10, "api")));
    }

    #[test]
    fn rule_filters_by_level() {
        let mut rule = simple_rule("critical-only");
        rule.levels = vec![IssueLevel::Fatal, IssueLevel::Error];
        assert!(rule.matches_issue(&issue("1", IssueLevel::Fatal, 1, 1, "api")));
        assert!(rule.matches_issue(&issue("2", IssueLevel::Error, 1, 1, "api")));
        assert!(!rule.matches_issue(&issue("3", IssueLevel::Warning, 1, 1, "api")));
        assert!(!rule.matches_issue(&issue("4", IssueLevel::Debug, 1, 1, "api")));
    }

    #[test]
    fn rule_filters_by_project() {
        let mut rule = simple_rule("backend-only");
        rule.projects = vec!["backend".into(), "api".into()];
        assert!(rule.matches_issue(&issue("1", IssueLevel::Error, 1, 1, "backend")));
        assert!(rule.matches_issue(&issue("2", IssueLevel::Error, 1, 1, "api")));
        assert!(!rule.matches_issue(&issue("3", IssueLevel::Error, 1, 1, "frontend")));
    }

    #[test]
    fn rule_combined_filters() {
        let rule = TriageRule {
            name: "critical-backend".into(),
            min_event_count: 50,
            min_user_count: 5,
            levels: vec![IssueLevel::Fatal, IssueLevel::Error],
            projects: vec!["backend".into()],
            auto_assign: None,
            priority_override: None,
        };
        // All criteria met.
        assert!(rule.matches_issue(&issue("1", IssueLevel::Error, 100, 10, "backend")));
        // Wrong project.
        assert!(!rule.matches_issue(&issue("2", IssueLevel::Error, 100, 10, "frontend")));
        // Wrong level.
        assert!(!rule.matches_issue(&issue("3", IssueLevel::Warning, 100, 10, "backend")));
        // Too few events.
        assert!(!rule.matches_issue(&issue("4", IssueLevel::Error, 49, 10, "backend")));
        // Too few users.
        assert!(!rule.matches_issue(&issue("5", IssueLevel::Error, 100, 4, "backend")));
    }

    #[test]
    fn rule_clone() {
        let rule = simple_rule("test");
        let cloned = rule.clone();
        assert_eq!(rule.name, "test");
        assert_eq!(cloned.name, "test");
    }

    #[test]
    fn rule_debug() {
        let rule = simple_rule("debug-rule");
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("TriageRule"));
        assert!(dbg.contains("debug-rule"));
    }

    #[test]
    fn rule_serde_roundtrip() {
        let rule = TriageRule {
            name: "test".into(),
            min_event_count: 10,
            min_user_count: 5,
            levels: vec![IssueLevel::Error],
            projects: vec!["backend".into()],
            auto_assign: Some("alice".into()),
            priority_override: Some(BeadPriority::P0),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: TriageRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
        assert_eq!(back.min_event_count, 10);
        assert_eq!(back.auto_assign.as_deref(), Some("alice"));
        assert_eq!(back.priority_override, Some(BeadPriority::P0));
    }

    #[test]
    fn rule_with_auto_assign() {
        let mut rule = simple_rule("assign-rule");
        rule.auto_assign = Some("bob".into());
        assert_eq!(rule.auto_assign.as_deref(), Some("bob"));
    }

    #[test]
    fn rule_with_priority_override() {
        let mut rule = simple_rule("override-rule");
        rule.priority_override = Some(BeadPriority::P0);
        assert_eq!(rule.priority_override, Some(BeadPriority::P0));
    }

    // ── TriageConfig tests ───────────────────────────────────────────

    #[test]
    fn triage_config_defaults() {
        let cfg = TriageConfig::default();
        assert_eq!(cfg.default_priority, BeadPriority::P2);
        assert!(cfg.dedup_enabled);
        assert_eq!(cfg.max_beads_per_run, 50);
        assert_eq!(cfg.cooldown_seconds, 300);
        assert_eq!(cfg.label_prefix, "sentry");
    }

    #[test]
    fn triage_config_custom() {
        let cfg = TriageConfig {
            default_priority: BeadPriority::P0,
            dedup_enabled: false,
            max_beads_per_run: 10,
            cooldown_seconds: 60,
            label_prefix: "custom".into(),
        };
        assert_eq!(cfg.default_priority, BeadPriority::P0);
        assert!(!cfg.dedup_enabled);
        assert_eq!(cfg.max_beads_per_run, 10);
    }

    #[test]
    fn triage_config_clone() {
        let cfg = TriageConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cfg.default_priority, cloned.default_priority);
        assert_eq!(cfg.label_prefix, cloned.label_prefix);
    }

    #[test]
    fn triage_config_debug() {
        let cfg = TriageConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("TriageConfig"));
    }

    #[test]
    fn triage_config_serde_roundtrip() {
        let cfg = TriageConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: TriageConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.default_priority, BeadPriority::P2);
        assert_eq!(back.max_beads_per_run, 50);
    }

    // ── TriageAction tests ───────────────────────────────────────────

    #[test]
    fn triage_action_display() {
        assert_eq!(TriageAction::Created.to_string(), "created");
        assert_eq!(TriageAction::Skipped.to_string(), "skipped");
        assert_eq!(TriageAction::Deduplicated.to_string(), "deduplicated");
    }

    #[test]
    fn triage_action_eq() {
        assert_eq!(TriageAction::Created, TriageAction::Created);
        assert_ne!(TriageAction::Created, TriageAction::Skipped);
    }

    #[test]
    fn triage_action_clone() {
        let action = TriageAction::Deduplicated;
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    fn triage_action_debug() {
        let dbg = format!("{:?}", TriageAction::Created);
        assert!(dbg.contains("Created"));
    }

    #[test]
    fn triage_action_serde_roundtrip() {
        let action = TriageAction::Skipped;
        let json = serde_json::to_string(&action).unwrap();
        let back: TriageAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TriageAction::Skipped);
    }

    // ── TriageAuditEvent tests ───────────────────────────────────────

    #[test]
    fn audit_event_construction() {
        let ev = TriageAuditEvent {
            timestamp: "2026-03-01T00:00:00Z".into(),
            action: TriageAction::Created,
            issue_id: "42".into(),
            bead_id: Some("bead-42".into()),
            reason: "matched rule".into(),
        };
        assert_eq!(ev.issue_id, "42");
        assert_eq!(ev.action, TriageAction::Created);
    }

    #[test]
    fn audit_event_clone() {
        let ev = TriageAuditEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: TriageAction::Skipped,
            issue_id: "1".into(),
            bead_id: None,
            reason: "no rules".into(),
        };
        let cloned = ev.clone();
        assert_eq!(ev.issue_id, "1");
        assert_eq!(cloned.action, TriageAction::Skipped);
    }

    #[test]
    fn audit_event_debug() {
        let ev = TriageAuditEvent {
            timestamp: "ts".into(),
            action: TriageAction::Deduplicated,
            issue_id: "99".into(),
            bead_id: None,
            reason: "dup".into(),
        };
        let dbg = format!("{ev:?}");
        assert!(dbg.contains("TriageAuditEvent"));
        assert!(dbg.contains("99"));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let ev = TriageAuditEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            action: TriageAction::Created,
            issue_id: "10".into(),
            bead_id: Some("bead-10".into()),
            reason: "test".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: TriageAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.issue_id, "10");
        assert_eq!(back.action, TriageAction::Created);
        assert_eq!(back.bead_id.as_deref(), Some("bead-10"));
    }

    // ── TriageResult tests ───────────────────────────────────────────

    #[test]
    fn triage_result_construction() {
        let r = TriageResult {
            issue_id: "1".into(),
            issue_title: "Error".into(),
            suggested_priority: BeadPriority::P1,
            suggested_labels: vec!["sentry:level:error".into()],
            assignee: Some("alice".into()),
            deduplicated: false,
            existing_bead_id: Some("bead-1".into()),
        };
        assert_eq!(r.issue_id, "1");
        assert_eq!(r.suggested_priority, BeadPriority::P1);
        assert!(!r.deduplicated);
    }

    #[test]
    fn triage_result_clone() {
        let r = TriageResult {
            issue_id: "1".into(),
            issue_title: "Err".into(),
            suggested_priority: BeadPriority::P2,
            suggested_labels: vec![],
            assignee: None,
            deduplicated: true,
            existing_bead_id: None,
        };
        let cloned = r.clone();
        assert_eq!(r.issue_id, "1");
        assert!(cloned.deduplicated);
    }

    #[test]
    fn triage_result_debug() {
        let r = TriageResult {
            issue_id: "1".into(),
            issue_title: "Err".into(),
            suggested_priority: BeadPriority::P3,
            suggested_labels: vec![],
            assignee: None,
            deduplicated: false,
            existing_bead_id: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TriageResult"));
    }

    #[test]
    fn triage_result_serde_roundtrip() {
        let r = TriageResult {
            issue_id: "55".into(),
            issue_title: "NPE".into(),
            suggested_priority: BeadPriority::P0,
            suggested_labels: vec!["sentry:level:fatal".into()],
            assignee: Some("bob".into()),
            deduplicated: false,
            existing_bead_id: Some("bead-55".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: TriageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.issue_id, "55");
        assert_eq!(back.suggested_priority, BeadPriority::P0);
        assert_eq!(back.assignee.as_deref(), Some("bob"));
    }

    // ── TriageStats tests ────────────────────────────────────────────

    #[test]
    fn triage_stats_default() {
        let stats = TriageStats::default();
        assert_eq!(stats.total_triaged, 0);
        assert_eq!(stats.beads_created, 0);
        assert_eq!(stats.deduplicated, 0);
        assert!(stats.by_priority.is_empty());
    }

    #[test]
    fn triage_stats_clone() {
        let stats = TriageStats {
            total_triaged: 10,
            beads_created: 5,
            ..TriageStats::default()
        };
        let cloned = stats.clone();
        assert_eq!(stats.total_triaged, 10);
        assert_eq!(cloned.beads_created, 5);
    }

    #[test]
    fn triage_stats_debug() {
        let stats = TriageStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("TriageStats"));
    }

    #[test]
    fn triage_stats_serde_roundtrip() {
        let mut by_priority = HashMap::new();
        by_priority.insert("P1".into(), 3);
        let stats = TriageStats {
            total_triaged: 42,
            by_priority,
            ..TriageStats::default()
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: TriageStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_triaged, 42);
        assert_eq!(back.by_priority.get("P1"), Some(&3));
    }

    // ── TriageEngine core tests ──────────────────────────────────────

    #[test]
    fn engine_new_empty() {
        let engine = default_engine();
        assert_eq!(engine.rule_count(), 0);
        assert_eq!(engine.stats().total_triaged, 0);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn engine_add_rules() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        engine.add_rule(simple_rule("r2"));
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn engine_mark_seen_and_check() {
        let mut engine = default_engine();
        assert!(!engine.is_seen("42"));
        engine.mark_seen("42");
        assert!(engine.is_seen("42"));
    }

    #[test]
    fn engine_bead_for_issue_none() {
        let engine = default_engine();
        assert!(engine.bead_for_issue("missing").is_none());
    }

    #[test]
    fn engine_config_accessor() {
        let engine = default_engine();
        assert_eq!(engine.config().default_priority, BeadPriority::P2);
    }

    // ── TriageEngine triage flow tests ───────────────────────────────

    #[test]
    fn engine_triage_no_rules_skips() {
        let mut engine = default_engine();
        let i = issue("1", IssueLevel::Error, 100, 10, "backend");
        let result = engine.triage_issue(&i);
        assert!(!result.deduplicated);
        assert!(result.existing_bead_id.is_none());
        assert_eq!(result.suggested_priority, BeadPriority::P2); // default
        assert_eq!(engine.stats().total_triaged, 1);
        assert_eq!(engine.stats().beads_created, 0);
    }

    #[test]
    fn engine_triage_matching_rule_creates_bead() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let i = issue("1", IssueLevel::Error, 100, 10, "backend");
        let result = engine.triage_issue(&i);
        assert!(!result.deduplicated);
        assert_eq!(result.existing_bead_id, Some("bead-1".into()));
        assert_eq!(engine.stats().beads_created, 1);
        assert!(engine.is_seen("1"));
        assert_eq!(engine.bead_for_issue("1"), Some("bead-1"));
    }

    #[test]
    fn engine_triage_priority_from_level_and_count() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        // Fatal + 5000 events → P0 from both
        let i = issue("1", IssueLevel::Fatal, 5000, 10, "api");
        let result = engine.triage_issue(&i);
        assert_eq!(result.suggested_priority, BeadPriority::P0);
    }

    #[test]
    fn engine_triage_priority_higher_of_level_and_count() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        // Warning (P2) but 1000 events (P0) → P0
        let i = issue("1", IssueLevel::Warning, 1000, 1, "api");
        let result = engine.triage_issue(&i);
        assert_eq!(result.suggested_priority, BeadPriority::P0);
    }

    #[test]
    fn engine_triage_priority_override() {
        let mut engine = default_engine();
        let mut rule = simple_rule("override");
        rule.priority_override = Some(BeadPriority::P0);
        engine.add_rule(rule);
        // Debug (P3) + 1 event (P3) but rule overrides to P0
        let i = issue("1", IssueLevel::Debug, 1, 1, "api");
        let result = engine.triage_issue(&i);
        assert_eq!(result.suggested_priority, BeadPriority::P0);
    }

    #[test]
    fn engine_triage_auto_assign() {
        let mut engine = default_engine();
        let mut rule = simple_rule("auto");
        rule.auto_assign = Some("alice".into());
        engine.add_rule(rule);
        let i = issue("1", IssueLevel::Error, 50, 5, "backend");
        let result = engine.triage_issue(&i);
        assert_eq!(result.assignee.as_deref(), Some("alice"));
    }

    #[test]
    fn engine_triage_labels() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("my-rule"));
        let i = issue("1", IssueLevel::Error, 50, 5, "backend");
        let result = engine.triage_issue(&i);
        assert!(result.suggested_labels.contains(&"sentry:level:error".into()));
        assert!(result.suggested_labels.contains(&"sentry:project:backend".into()));
        assert!(result.suggested_labels.contains(&"sentry:rule:my-rule".into()));
    }

    #[test]
    fn engine_triage_labels_sorted_deduped() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("a-rule"));
        engine.add_rule(simple_rule("b-rule"));
        let i = issue("1", IssueLevel::Warning, 50, 5, "frontend");
        let result = engine.triage_issue(&i);
        let labels = &result.suggested_labels;
        for w in labels.windows(2) {
            assert!(w[0] <= w[1], "labels not sorted: {labels:?}");
        }
        let set: HashSet<&String> = labels.iter().collect();
        assert_eq!(set.len(), labels.len(), "duplicate labels found");
    }

    #[test]
    fn engine_triage_custom_label_prefix() {
        let cfg = TriageConfig {
            label_prefix: "myprefix".into(),
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("r1"));
        let i = issue("1", IssueLevel::Error, 50, 5, "api");
        let result = engine.triage_issue(&i);
        assert!(result.suggested_labels.iter().all(|l| l.starts_with("myprefix:")));
    }

    // ── Deduplication tests ──────────────────────────────────────────

    #[test]
    fn engine_dedup_same_issue() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let i = issue("1", IssueLevel::Error, 50, 5, "api");
        let first = engine.triage_issue(&i);
        assert!(!first.deduplicated);
        assert_eq!(engine.stats().beads_created, 1);

        let second = engine.triage_issue(&i);
        assert!(second.deduplicated);
        assert_eq!(second.existing_bead_id, Some("bead-1".into()));
        assert_eq!(engine.stats().beads_created, 1);
        assert_eq!(engine.stats().deduplicated, 1);
    }

    #[test]
    fn engine_dedup_disabled() {
        let cfg = TriageConfig {
            dedup_enabled: false,
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("catch-all"));
        let i = issue("1", IssueLevel::Error, 50, 5, "api");
        let first = engine.triage_issue(&i);
        assert!(!first.deduplicated);

        // Even though already seen, dedup is disabled so it won't flag.
        let second = engine.triage_issue(&i);
        assert!(!second.deduplicated);
        assert_eq!(engine.stats().deduplicated, 0);
    }

    #[test]
    fn engine_dedup_pre_marked() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        engine.mark_seen("42");
        let i = issue("42", IssueLevel::Error, 50, 5, "api");
        let result = engine.triage_issue(&i);
        assert!(result.deduplicated);
    }

    #[test]
    fn engine_dedup_different_issues() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let i1 = issue("1", IssueLevel::Error, 50, 5, "api");
        let i2 = issue("2", IssueLevel::Warning, 30, 2, "api");
        let r1 = engine.triage_issue(&i1);
        let r2 = engine.triage_issue(&i2);
        assert!(!r1.deduplicated);
        assert!(!r2.deduplicated);
        assert_eq!(engine.stats().beads_created, 2);
    }

    // ── Max beads per run tests ──────────────────────────────────────

    #[test]
    fn engine_max_beads_per_run() {
        let cfg = TriageConfig {
            max_beads_per_run: 2,
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("catch-all"));

        let r1 = engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert!(r1.existing_bead_id.is_some());
        let r2 = engine.triage_issue(&issue("2", IssueLevel::Error, 50, 5, "api"));
        assert!(r2.existing_bead_id.is_some());
        let r3 = engine.triage_issue(&issue("3", IssueLevel::Error, 50, 5, "api"));
        assert!(r3.existing_bead_id.is_none());
        assert_eq!(engine.stats().beads_created, 2);
    }

    #[test]
    fn engine_max_beads_audit_reason() {
        let cfg = TriageConfig {
            max_beads_per_run: 1,
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("catch-all"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        engine.triage_issue(&issue("2", IssueLevel::Error, 50, 5, "api"));
        let log = engine.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].action, TriageAction::Skipped);
        assert!(log[1].reason.contains("max beads"));
    }

    // ── Batch triage tests ───────────────────────────────────────────

    #[test]
    fn engine_triage_batch_empty() {
        let mut engine = default_engine();
        let results = engine.triage_batch(&[]);
        assert!(results.is_empty());
        assert_eq!(engine.stats().total_triaged, 0);
    }

    #[test]
    fn engine_triage_batch_multiple() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let issues = vec![
            issue("1", IssueLevel::Fatal, 100, 10, "api"),
            issue("2", IssueLevel::Error, 50, 5, "web"),
            issue("3", IssueLevel::Warning, 10, 2, "mobile"),
        ];
        let results = engine.triage_batch(&issues);
        assert_eq!(results.len(), 3);
        assert_eq!(engine.stats().total_triaged, 3);
        assert_eq!(engine.stats().beads_created, 3);
    }

    #[test]
    fn engine_triage_batch_with_dedup() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let issues = vec![
            issue("1", IssueLevel::Error, 50, 5, "api"),
            issue("1", IssueLevel::Error, 50, 5, "api"), // duplicate
            issue("2", IssueLevel::Warning, 10, 2, "api"),
        ];
        let results = engine.triage_batch(&issues);
        assert!(!results[0].deduplicated);
        assert!(results[1].deduplicated);
        assert!(!results[2].deduplicated);
        assert_eq!(engine.stats().beads_created, 2);
        assert_eq!(engine.stats().deduplicated, 1);
    }

    // ── Audit log tests ──────────────────────────────────────────────

    #[test]
    fn engine_audit_log_created() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        let log = engine.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, TriageAction::Created);
        assert_eq!(log[0].issue_id, "1");
        assert!(log[0].bead_id.is_some());
        assert!(log[0].reason.contains("matched"));
    }

    #[test]
    fn engine_audit_log_skipped() {
        let mut engine = default_engine();
        // No rules → skip.
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        let log = engine.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, TriageAction::Skipped);
        assert!(log[0].reason.contains("no matching"));
    }

    #[test]
    fn engine_audit_log_deduplicated() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        let i = issue("1", IssueLevel::Error, 50, 5, "api");
        engine.triage_issue(&i);
        engine.triage_issue(&i);
        let log = engine.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].action, TriageAction::Created);
        assert_eq!(log[1].action, TriageAction::Deduplicated);
    }

    #[test]
    fn engine_audit_log_multiple_rules_match_count() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        engine.add_rule(simple_rule("r2"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        let log = engine.audit_log();
        assert!(log[0].reason.contains("2 rule(s)"));
    }

    // ── Stats tests ──────────────────────────────────────────────────

    #[test]
    fn engine_stats_by_priority() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        engine.triage_issue(&issue("1", IssueLevel::Fatal, 1000, 10, "api")); // P0
        engine.triage_issue(&issue("2", IssueLevel::Error, 100, 5, "api")); // P1 (higher of P1 level, P1 count)
        engine.triage_issue(&issue("3", IssueLevel::Warning, 5, 1, "api")); // P2 (higher of P2 level, P3 count)
        let stats = engine.stats();
        assert_eq!(stats.beads_created, 3);
        assert_eq!(stats.by_priority.get("P0"), Some(&1));
        assert_eq!(stats.by_priority.get("P1"), Some(&1));
        assert_eq!(stats.by_priority.get("P2"), Some(&1));
    }

    #[test]
    fn engine_stats_total_triaged_includes_all() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let i = issue("1", IssueLevel::Error, 50, 5, "api");
        engine.triage_issue(&i);
        engine.triage_issue(&i); // dedup
        assert_eq!(engine.stats().total_triaged, 2);
    }

    // ── Reset run tests ──────────────────────────────────────────────

    #[test]
    fn engine_reset_run_clears_stats_and_audit() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert_eq!(engine.stats().beads_created, 1);
        assert_eq!(engine.audit_log().len(), 1);

        engine.reset_run();
        assert_eq!(engine.stats().total_triaged, 0);
        assert_eq!(engine.stats().beads_created, 0);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn engine_reset_run_keeps_seen_state() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        engine.reset_run();

        // Issue 1 is still seen, so dedup fires.
        let result = engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert!(result.deduplicated);
    }

    #[test]
    fn engine_reset_run_allows_new_beads() {
        let cfg = TriageConfig {
            max_beads_per_run: 1,
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("catch-all"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        // Max reached.
        let r = engine.triage_issue(&issue("2", IssueLevel::Error, 50, 5, "api"));
        assert!(r.existing_bead_id.is_none());

        engine.reset_run();
        // New run, counter reset, but issue 2 is not yet seen.
        let r2 = engine.triage_issue(&issue("2", IssueLevel::Error, 50, 5, "api"));
        assert!(r2.existing_bead_id.is_some());
    }

    // ── Engine serde tests ───────────────────────────────────────────

    #[test]
    fn engine_serde_roundtrip() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        engine.mark_seen("42");
        let json = serde_json::to_string(&engine).unwrap();
        let back: TriageEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule_count(), 1);
        assert!(back.is_seen("42"));
    }

    #[test]
    fn engine_serde_skips_audit_log() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert!(!engine.audit_log().is_empty());

        let json = serde_json::to_string(&engine).unwrap();
        let back: TriageEngine = serde_json::from_str(&json).unwrap();
        // Audit log is #[serde(skip)].
        assert!(back.audit_log().is_empty());
    }

    #[test]
    fn engine_clone() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        engine.mark_seen("5");
        let cloned = engine.clone();
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(cloned.rule_count(), 1);
        assert!(cloned.is_seen("5"));
    }

    #[test]
    fn engine_debug() {
        let engine = default_engine();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("TriageEngine"));
    }

    // ── Multiple rules matching ──────────────────────────────────────

    #[test]
    fn engine_multiple_rules_first_assignee_wins() {
        let mut engine = default_engine();
        let mut r1 = simple_rule("r1");
        r1.auto_assign = Some("alice".into());
        let mut r2 = simple_rule("r2");
        r2.auto_assign = Some("bob".into());
        engine.add_rule(r1);
        engine.add_rule(r2);
        let result = engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert_eq!(result.assignee.as_deref(), Some("alice"));
    }

    #[test]
    fn engine_multiple_rules_priority_override_picks_highest() {
        let mut engine = default_engine();
        let mut r1 = simple_rule("r1");
        r1.priority_override = Some(BeadPriority::P2);
        let mut r2 = simple_rule("r2");
        r2.priority_override = Some(BeadPriority::P0);
        engine.add_rule(r1);
        engine.add_rule(r2);
        // Debug (P3) + 1 event (P3) → overridden to P0 by r2.
        let result = engine.triage_issue(&issue("1", IssueLevel::Debug, 1, 1, "api"));
        assert_eq!(result.suggested_priority, BeadPriority::P0);
    }

    #[test]
    fn engine_only_matching_rules_apply() {
        let mut engine = default_engine();
        let mut r1 = simple_rule("backend-only");
        r1.projects = vec!["backend".into()];
        r1.auto_assign = Some("alice".into());

        let mut r2 = simple_rule("frontend-only");
        r2.projects = vec!["frontend".into()];
        r2.auto_assign = Some("bob".into());

        engine.add_rule(r1);
        engine.add_rule(r2);

        let result = engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "frontend"));
        assert_eq!(result.assignee.as_deref(), Some("bob"));
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn engine_issue_title_preserved() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        let i = make_issue("1", "NullPointerException in com.example.Main", IssueLevel::Fatal, 100, 10, "backend");
        let result = engine.triage_issue(&i);
        assert_eq!(result.issue_title, "NullPointerException in com.example.Main");
    }

    #[test]
    fn engine_zero_events_and_users() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let i = issue("1", IssueLevel::Debug, 0, 0, "test");
        let result = engine.triage_issue(&i);
        assert_eq!(result.suggested_priority, BeadPriority::P3);
    }

    #[test]
    fn engine_very_high_event_count() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let i = issue("1", IssueLevel::Info, 1_000_000, 50_000, "api");
        let result = engine.triage_issue(&i);
        assert_eq!(result.suggested_priority, BeadPriority::P0);
    }

    #[test]
    fn rule_min_event_count_boundary_exact() {
        let mut rule = simple_rule("exact");
        rule.min_event_count = 42;
        assert!(rule.matches_issue(&issue("1", IssueLevel::Error, 42, 0, "api")));
        assert!(!rule.matches_issue(&issue("2", IssueLevel::Error, 41, 0, "api")));
    }

    #[test]
    fn rule_min_user_count_boundary_exact() {
        let mut rule = simple_rule("exact");
        rule.min_user_count = 10;
        assert!(rule.matches_issue(&issue("1", IssueLevel::Error, 0, 10, "api")));
        assert!(!rule.matches_issue(&issue("2", IssueLevel::Error, 0, 9, "api")));
    }

    #[test]
    fn engine_bead_id_format() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let result = engine.triage_issue(&issue("abc-123", IssueLevel::Error, 50, 5, "api"));
        assert_eq!(result.existing_bead_id.as_deref(), Some("bead-abc-123"));
    }

    // ── make_issue helper ────────────────────────────────────────────

    #[test]
    fn make_issue_defaults() {
        let i = make_issue("id1", "title1", IssueLevel::Error, 10, 5, "proj");
        assert_eq!(i.id, "id1");
        assert_eq!(i.title, "title1");
        assert_eq!(i.first_seen, "2026-01-01T00:00:00Z");
        assert!(i.culprit.is_none());
    }

    // ── Additional priority edge cases ───────────────────────────────

    #[test]
    fn bead_priority_higher_symmetry() {
        let pairs = [
            (BeadPriority::P0, BeadPriority::P3),
            (BeadPriority::P1, BeadPriority::P2),
            (BeadPriority::P2, BeadPriority::P1),
            (BeadPriority::P3, BeadPriority::P0),
        ];
        for (a, b) in pairs {
            assert_eq!(a.higher(b), b.higher(a));
        }
    }

    #[test]
    fn bead_priority_from_event_count_one() {
        assert_eq!(BeadPriority::from_event_count(1), BeadPriority::P3);
    }

    // ── Complex scenario tests ───────────────────────────────────────

    #[test]
    fn scenario_mixed_batch_with_dedup_and_max() {
        let cfg = TriageConfig {
            max_beads_per_run: 2,
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("catch-all"));
        engine.mark_seen("pre-existing");

        let issues = vec![
            issue("pre-existing", IssueLevel::Fatal, 1000, 100, "api"), // dedup
            issue("new-1", IssueLevel::Error, 500, 50, "api"),          // create
            issue("new-2", IssueLevel::Warning, 100, 10, "api"),        // create
            issue("new-3", IssueLevel::Info, 10, 2, "api"),             // skipped (max)
        ];
        let results = engine.triage_batch(&issues);

        assert!(results[0].deduplicated);
        assert!(!results[1].deduplicated);
        assert!(results[1].existing_bead_id.is_some());
        assert!(!results[2].deduplicated);
        assert!(results[2].existing_bead_id.is_some());
        assert!(!results[3].deduplicated);
        assert!(results[3].existing_bead_id.is_none());

        let stats = engine.stats();
        assert_eq!(stats.total_triaged, 4);
        assert_eq!(stats.beads_created, 2);
        assert_eq!(stats.deduplicated, 1);
    }

    #[test]
    fn scenario_rule_project_filter_with_batch() {
        let mut engine = default_engine();
        let mut rule = simple_rule("backend-errors");
        rule.projects = vec!["backend".into()];
        rule.levels = vec![IssueLevel::Error, IssueLevel::Fatal];
        engine.add_rule(rule);

        let issues = vec![
            issue("1", IssueLevel::Error, 50, 5, "backend"),   // match
            issue("2", IssueLevel::Error, 50, 5, "frontend"),  // no match (project)
            issue("3", IssueLevel::Warning, 50, 5, "backend"), // no match (level)
            issue("4", IssueLevel::Fatal, 50, 5, "backend"),   // match
        ];
        let results = engine.triage_batch(&issues);
        assert!(results[0].existing_bead_id.is_some());
        assert!(results[1].existing_bead_id.is_none());
        assert!(results[2].existing_bead_id.is_none());
        assert!(results[3].existing_bead_id.is_some());
        assert_eq!(engine.stats().beads_created, 2);
    }

    #[test]
    fn scenario_multiple_runs_with_reset() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));

        // Run 1
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert_eq!(engine.stats().beads_created, 1);

        engine.reset_run();

        // Run 2 — issue 1 is deduplicated, issue 2 is new.
        engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        engine.triage_issue(&issue("2", IssueLevel::Warning, 10, 2, "api"));
        assert_eq!(engine.stats().beads_created, 1);
        assert_eq!(engine.stats().deduplicated, 1);
        assert_eq!(engine.stats().total_triaged, 2);
    }

    // ── IssueLevel additional coverage ───────────────────────────────

    #[test]
    fn issue_level_all_variants_rank() {
        let levels = [
            IssueLevel::Fatal,
            IssueLevel::Error,
            IssueLevel::Warning,
            IssueLevel::Info,
            IssueLevel::Debug,
        ];
        for w in levels.windows(2) {
            assert!(w[0].rank() < w[1].rank());
        }
    }

    #[test]
    fn issue_level_deserialize_all_variants() {
        for s in &["\"fatal\"", "\"error\"", "\"warning\"", "\"info\"", "\"debug\""] {
            let level: IssueLevel = serde_json::from_str(s).unwrap();
            let back = serde_json::to_string(&level).unwrap();
            assert_eq!(&back, s);
        }
    }

    // ── BeadPriority edge coverage ───────────────────────────────────

    #[test]
    fn bead_priority_partial_ord_consistent_with_ord() {
        let all = [BeadPriority::P0, BeadPriority::P1, BeadPriority::P2, BeadPriority::P3];
        for a in &all {
            for b in &all {
                assert_eq!(a.partial_cmp(b), Some(a.cmp(b)));
            }
        }
    }

    // ── TriageResult labels edge ─────────────────────────────────────

    #[test]
    fn triage_result_no_labels_when_no_rules_match() {
        let mut engine = default_engine();
        let mut rule = simple_rule("filtered");
        rule.projects = vec!["other".into()];
        engine.add_rule(rule);
        let result = engine.triage_issue(&issue("1", IssueLevel::Error, 50, 5, "api"));
        assert!(result.suggested_labels.is_empty());
    }

    // ── Cooldown config ──────────────────────────────────────────────

    #[test]
    fn triage_config_cooldown_custom() {
        let cfg = TriageConfig {
            cooldown_seconds: 600,
            ..TriageConfig::default()
        };
        assert_eq!(cfg.cooldown_seconds, 600);
    }

    // ── Engine with multiple projects ────────────────────────────────

    #[test]
    fn rule_matches_multiple_projects() {
        let mut rule = simple_rule("multi-proj");
        rule.projects = vec!["api".into(), "web".into(), "mobile".into()];
        assert!(rule.matches_issue(&issue("1", IssueLevel::Error, 1, 1, "api")));
        assert!(rule.matches_issue(&issue("2", IssueLevel::Error, 1, 1, "web")));
        assert!(rule.matches_issue(&issue("3", IssueLevel::Error, 1, 1, "mobile")));
        assert!(!rule.matches_issue(&issue("4", IssueLevel::Error, 1, 1, "desktop")));
    }

    #[test]
    fn rule_matches_multiple_levels() {
        let mut rule = simple_rule("multi-level");
        rule.levels = vec![IssueLevel::Fatal, IssueLevel::Error, IssueLevel::Warning];
        assert!(rule.matches_issue(&issue("1", IssueLevel::Fatal, 1, 1, "api")));
        assert!(rule.matches_issue(&issue("2", IssueLevel::Error, 1, 1, "api")));
        assert!(rule.matches_issue(&issue("3", IssueLevel::Warning, 1, 1, "api")));
        assert!(!rule.matches_issue(&issue("4", IssueLevel::Info, 1, 1, "api")));
        assert!(!rule.matches_issue(&issue("5", IssueLevel::Debug, 1, 1, "api")));
    }

    // ── Audit log timestamp tracking ─────────────────────────────────

    #[test]
    fn audit_event_uses_last_seen_timestamp() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("r1"));
        let mut i = issue("1", IssueLevel::Error, 50, 5, "api");
        i.last_seen = "2026-03-09T12:00:00Z".into();
        engine.triage_issue(&i);
        assert_eq!(engine.audit_log()[0].timestamp, "2026-03-09T12:00:00Z");
    }

    // ── Large batch stress ───────────────────────────────────────────

    #[test]
    fn engine_large_batch() {
        let mut engine = default_engine();
        engine.add_rule(simple_rule("catch-all"));
        let issues: Vec<IssueSummary> = (0..100)
            .map(|i| issue(&i.to_string(), IssueLevel::Error, 50, 5, "api"))
            .collect();
        let results = engine.triage_batch(&issues);
        assert_eq!(results.len(), 100);
        // Default max is 50 — first 50 created, rest skipped.
        assert_eq!(engine.stats().beads_created, 50);
    }

    #[test]
    fn engine_large_batch_all_unique_under_limit() {
        let cfg = TriageConfig {
            max_beads_per_run: 200,
            ..TriageConfig::default()
        };
        let mut engine = TriageEngine::new(cfg);
        engine.add_rule(simple_rule("catch-all"));
        let issues: Vec<IssueSummary> = (0..100)
            .map(|i| issue(&i.to_string(), IssueLevel::Error, 50, 5, "api"))
            .collect();
        let results = engine.triage_batch(&issues);
        assert_eq!(results.len(), 100);
        assert_eq!(engine.stats().beads_created, 100);
        assert_eq!(engine.stats().deduplicated, 0);
    }
}
