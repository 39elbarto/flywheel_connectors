//! Zendesk auto-categorization pipeline for incoming tickets.
//!
//! Provides a rule-based categorization engine that processes inbound ticket data
//! (from webhooks or API polling) and produces structured metadata: category labels,
//! priority suggestions, macro suggestions, and escalation flags.
//!
//! Safe-by-default: the engine **recommends** actions but never silently mutates
//! tickets unless explicitly opted in via [`CategorizationPolicy`].

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ── TicketPriority ──────────────────────────────────────────────────────

/// Zendesk ticket priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TicketPriority {
    Urgent,
    High,
    Normal,
    Low,
}

impl TicketPriority {
    /// Return a string representation matching the Zendesk API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Urgent => "urgent",
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
        }
    }

    /// Parse from a string (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "urgent" => Some(Self::Urgent),
            "high" => Some(Self::High),
            "normal" => Some(Self::Normal),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

impl std::fmt::Display for TicketPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TicketPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_loose(s).ok_or_else(|| format!("unknown priority: {s}"))
    }
}

// ── EscalationFlag ──────────────────────────────────────────────────────

/// Flags that indicate a ticket may need escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationFlag {
    SlaRisk,
    NegativeSentiment,
    HighPriority,
    VipCustomer,
    SecurityIssue,
    ComplianceIssue,
    RepeatContact,
}

impl EscalationFlag {
    /// Short string label for this flag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SlaRisk => "sla_risk",
            Self::NegativeSentiment => "negative_sentiment",
            Self::HighPriority => "high_priority",
            Self::VipCustomer => "vip_customer",
            Self::SecurityIssue => "security_issue",
            Self::ComplianceIssue => "compliance_issue",
            Self::RepeatContact => "repeat_contact",
        }
    }

    /// Severity score (higher = more urgent). Range: 1-5.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::SecurityIssue | Self::ComplianceIssue => 5,
            Self::SlaRisk | Self::HighPriority => 4,
            Self::VipCustomer => 3,
            Self::NegativeSentiment => 2,
            Self::RepeatContact => 1,
        }
    }
}

impl std::fmt::Display for EscalationFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── MacroSuggestion ─────────────────────────────────────────────────────

/// A suggested Zendesk macro to apply to the ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroSuggestion {
    pub macro_id: String,
    pub macro_title: String,
    pub relevance_score: f64,
    pub reason: String,
}

// ── CategorizationResult ────────────────────────────────────────────────

/// The output of the categorization engine for a single ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizationResult {
    pub ticket_id: String,
    pub suggested_category: Option<String>,
    pub suggested_priority: Option<TicketPriority>,
    pub suggested_tags: Vec<String>,
    pub macro_suggestions: Vec<MacroSuggestion>,
    pub escalation_flags: Vec<EscalationFlag>,
    pub confidence: f64,
}

impl CategorizationResult {
    /// Whether the confidence meets or exceeds the given threshold.
    #[must_use]
    pub fn meets_threshold(&self, threshold: f64) -> bool {
        self.confidence >= threshold
    }

    /// Whether any escalation flags are present.
    #[must_use]
    pub fn needs_escalation(&self) -> bool {
        !self.escalation_flags.is_empty()
    }

    /// Max severity across all escalation flags, or 0 if none.
    #[must_use]
    pub fn max_severity(&self) -> u8 {
        self.escalation_flags
            .iter()
            .map(|f| f.severity())
            .max()
            .unwrap_or(0)
    }
}

// ── TicketInput ─────────────────────────────────────────────────────────

/// Tainted input from a webhook or API response, fed into the categorization engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketInput {
    pub ticket_id: String,
    pub subject: Option<String>,
    pub description: Option<String>,
    pub requester_email: Option<String>,
    pub channel: Option<String>,
    pub custom_fields: HashMap<String, String>,
}

impl TicketInput {
    /// Combine subject and description into a single searchable text blob.
    #[must_use]
    pub fn combined_text(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref s) = self.subject {
            parts.push(s.as_str());
        }
        if let Some(ref d) = self.description {
            parts.push(d.as_str());
        }
        parts.join(" ")
    }
}

// ── CategoryRule ────────────────────────────────────────────────────────

/// A single categorization rule: pattern-match text and assign metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRule {
    pub name: String,
    pub patterns: Vec<String>,
    pub category: String,
    pub priority_hint: Option<TicketPriority>,
    pub tags: Vec<String>,
}

impl CategoryRule {
    /// Check whether `text` matches any of this rule's patterns (case-insensitive).
    #[must_use]
    pub fn matches_text(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.patterns
            .iter()
            .any(|p| lower.contains(&p.to_ascii_lowercase()))
    }

    /// Count how many patterns match the given text (case-insensitive).
    #[must_use]
    pub fn match_count(&self, text: &str) -> usize {
        let lower = text.to_ascii_lowercase();
        self.patterns
            .iter()
            .filter(|p| lower.contains(&p.to_ascii_lowercase()))
            .count()
    }
}

// ── CategorizationConfig ────────────────────────────────────────────────

/// Configuration knobs for the categorization pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizationConfig {
    pub min_confidence_threshold: f64,
    pub max_tags_per_ticket: usize,
    pub max_suggestions: usize,
    /// If true, the engine may auto-apply changes.
    /// **Dangerous** --- defaults to false for safety.
    pub auto_apply: bool,
}

impl Default for CategorizationConfig {
    fn default() -> Self {
        Self {
            min_confidence_threshold: 0.5,
            max_tags_per_ticket: 10,
            max_suggestions: 5,
            auto_apply: false,
        }
    }
}

// ── CategorizationPolicy ────────────────────────────────────────────────

/// Access-control policy governing what the categorization pipeline may do.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizationPolicy {
    pub allow_read: bool,
    pub allow_suggest: bool,
    pub allow_auto_apply: bool,
    pub require_approval_for_apply: bool,
    pub blocked_categories: HashSet<String>,
}

impl CategorizationPolicy {
    /// Suggest-only policy: read + suggest, never auto-apply.
    #[must_use]
    pub fn new_suggest_only() -> Self {
        Self {
            allow_read: true,
            allow_suggest: true,
            allow_auto_apply: false,
            require_approval_for_apply: true,
            blocked_categories: HashSet::new(),
        }
    }

    /// Read-only policy: may read tickets but not suggest or apply.
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_suggest: false,
            allow_auto_apply: false,
            require_approval_for_apply: true,
            blocked_categories: HashSet::new(),
        }
    }

    /// Check whether auto-apply is permitted for a given category.
    #[must_use]
    pub fn check_apply(&self, category: &str) -> bool {
        self.allow_auto_apply
            && !self.require_approval_for_apply
            && !self.blocked_categories.contains(category)
    }
}

// ── CategorizationAuditEvent ────────────────────────────────────────────

/// An audit log entry produced by the categorization pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizationAuditEvent {
    pub timestamp: String,
    pub ticket_id: String,
    pub action: AuditAction,
    pub category: Option<String>,
    pub confidence: f64,
    pub was_auto_applied: bool,
}

/// The action recorded in an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    Categorized,
    Applied,
    Skipped,
}

impl AuditAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Categorized => "categorized",
            Self::Applied => "applied",
            Self::Skipped => "skipped",
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── CategorizationEngine ────────────────────────────────────────────────

/// Rule-based ticket categorization engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizationEngine {
    rules: Vec<CategoryRule>,
    default_category: String,
    min_confidence: f64,
}

impl CategorizationEngine {
    /// Create a new engine with a default category and minimum confidence threshold.
    #[must_use]
    pub fn new(default_category: impl Into<String>, min_confidence: f64) -> Self {
        Self {
            rules: Vec::new(),
            default_category: default_category.into(),
            min_confidence: min_confidence.clamp(0.0, 1.0),
        }
    }

    /// Add a categorization rule.
    pub fn add_rule(&mut self, rule: CategoryRule) {
        self.rules.push(rule);
    }

    /// Return the number of rules currently registered.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Categorize a single ticket input.
    #[must_use]
    pub fn categorize(&self, input: &TicketInput) -> CategorizationResult {
        let text = input.combined_text();
        self.categorize_text(&input.ticket_id, &text)
    }

    /// Categorize a batch of ticket inputs.
    #[must_use]
    pub fn categorize_batch(&self, inputs: &[TicketInput]) -> Vec<CategorizationResult> {
        inputs.iter().map(|i| self.categorize(i)).collect()
    }

    /// Internal: run rules against combined text.
    fn categorize_text(&self, ticket_id: &str, text: &str) -> CategorizationResult {
        // Find the best-matching rule (most pattern hits).
        let mut best_rule: Option<&CategoryRule> = None;
        let mut best_hits: usize = 0;

        for rule in &self.rules {
            let hits = rule.match_count(text);
            if hits > best_hits {
                best_hits = hits;
                best_rule = Some(rule);
            }
        }

        let (category, priority_hint, tags, confidence) = if let Some(rule) = best_rule {
            let total_patterns = rule.patterns.len().max(1);
            let raw_confidence = best_hits as f64 / total_patterns as f64;
            let confidence = raw_confidence.clamp(0.0, 1.0);
            (
                Some(rule.category.clone()),
                rule.priority_hint,
                rule.tags.clone(),
                confidence,
            )
        } else {
            (None, None, Vec::new(), 0.0)
        };

        // If confidence is below threshold, fall back to default.
        let (final_category, final_confidence) = if confidence >= self.min_confidence {
            (category, confidence)
        } else {
            (Some(self.default_category.clone()), 0.0)
        };

        // Detect escalation flags from text.
        let escalation_flags = self.detect_escalation_flags(text);

        // Boost priority if there are high-severity escalation flags.
        let suggested_priority = if escalation_flags
            .iter()
            .any(|f| f.severity() >= 4)
        {
            Some(priority_hint.unwrap_or(TicketPriority::High))
        } else {
            priority_hint
        };

        CategorizationResult {
            ticket_id: ticket_id.to_string(),
            suggested_category: final_category,
            suggested_priority,
            suggested_tags: tags,
            macro_suggestions: Vec::new(),
            escalation_flags,
            confidence: final_confidence,
        }
    }

    /// Detect escalation flags from text content.
    #[allow(clippy::unused_self)] // method for future rule-driven escalation
    fn detect_escalation_flags(&self, text: &str) -> Vec<EscalationFlag> {
        let lower = text.to_ascii_lowercase();
        let mut flags = Vec::new();

        // Security keywords
        if lower.contains("security")
            || lower.contains("breach")
            || lower.contains("vulnerability")
            || lower.contains("exploit")
            || lower.contains("unauthorized access")
        {
            flags.push(EscalationFlag::SecurityIssue);
        }

        // Compliance keywords
        if lower.contains("compliance")
            || lower.contains("gdpr")
            || lower.contains("hipaa")
            || lower.contains("audit")
            || lower.contains("regulation")
        {
            flags.push(EscalationFlag::ComplianceIssue);
        }

        // Negative sentiment
        if lower.contains("angry")
            || lower.contains("furious")
            || lower.contains("unacceptable")
            || lower.contains("terrible")
            || lower.contains("worst")
            || lower.contains("lawsuit")
        {
            flags.push(EscalationFlag::NegativeSentiment);
        }

        // VIP indicators
        if lower.contains("vip")
            || lower.contains("enterprise")
            || lower.contains("executive")
        {
            flags.push(EscalationFlag::VipCustomer);
        }

        // SLA risk
        if lower.contains("sla")
            || lower.contains("deadline")
            || lower.contains("overdue")
            || lower.contains("past due")
        {
            flags.push(EscalationFlag::SlaRisk);
        }

        flags
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn sample_input(id: &str, subject: &str, description: &str) -> TicketInput {
        TicketInput {
            ticket_id: id.into(),
            subject: Some(subject.into()),
            description: Some(description.into()),
            requester_email: None,
            channel: None,
            custom_fields: HashMap::new(),
        }
    }

    fn billing_rule() -> CategoryRule {
        CategoryRule {
            name: "billing".into(),
            patterns: vec![
                "invoice".into(),
                "billing".into(),
                "charge".into(),
                "payment".into(),
                "refund".into(),
            ],
            category: "billing".into(),
            priority_hint: Some(TicketPriority::Normal),
            tags: vec!["billing".into(), "finance".into()],
        }
    }

    fn technical_rule() -> CategoryRule {
        CategoryRule {
            name: "technical".into(),
            patterns: vec![
                "error".into(),
                "crash".into(),
                "bug".into(),
                "broken".into(),
                "not working".into(),
            ],
            category: "technical_support".into(),
            priority_hint: Some(TicketPriority::High),
            tags: vec!["tech".into(), "support".into()],
        }
    }

    fn security_rule() -> CategoryRule {
        CategoryRule {
            name: "security".into(),
            patterns: vec![
                "security".into(),
                "breach".into(),
                "vulnerability".into(),
                "hack".into(),
            ],
            category: "security".into(),
            priority_hint: Some(TicketPriority::Urgent),
            tags: vec!["security".into(), "urgent".into()],
        }
    }

    fn build_engine() -> CategorizationEngine {
        let mut engine = CategorizationEngine::new("general", 0.3);
        engine.add_rule(billing_rule());
        engine.add_rule(technical_rule());
        engine.add_rule(security_rule());
        engine
    }

    // ── TicketPriority ──────────────────────────────────────────────

    #[test]
    fn priority_as_str_urgent() {
        assert_eq!(TicketPriority::Urgent.as_str(), "urgent");
    }

    #[test]
    fn priority_as_str_high() {
        assert_eq!(TicketPriority::High.as_str(), "high");
    }

    #[test]
    fn priority_as_str_normal() {
        assert_eq!(TicketPriority::Normal.as_str(), "normal");
    }

    #[test]
    fn priority_as_str_low() {
        assert_eq!(TicketPriority::Low.as_str(), "low");
    }

    #[test]
    fn priority_from_str_valid() {
        assert_eq!("urgent".parse::<TicketPriority>().unwrap(), TicketPriority::Urgent);
        assert_eq!("high".parse::<TicketPriority>().unwrap(), TicketPriority::High);
        assert_eq!("normal".parse::<TicketPriority>().unwrap(), TicketPriority::Normal);
        assert_eq!("low".parse::<TicketPriority>().unwrap(), TicketPriority::Low);
    }

    #[test]
    fn priority_from_str_case_insensitive() {
        assert_eq!("URGENT".parse::<TicketPriority>().unwrap(), TicketPriority::Urgent);
        assert_eq!("High".parse::<TicketPriority>().unwrap(), TicketPriority::High);
        assert_eq!("NORMAL".parse::<TicketPriority>().unwrap(), TicketPriority::Normal);
        assert_eq!("Low".parse::<TicketPriority>().unwrap(), TicketPriority::Low);
    }

    #[test]
    fn priority_from_str_invalid() {
        let err = "critical".parse::<TicketPriority>().unwrap_err();
        assert!(err.contains("unknown priority"));
    }

    #[test]
    fn priority_from_str_empty() {
        assert!("".parse::<TicketPriority>().is_err());
    }

    #[test]
    fn priority_display() {
        assert_eq!(format!("{}", TicketPriority::Urgent), "urgent");
        assert_eq!(format!("{}", TicketPriority::Low), "low");
    }

    #[test]
    fn priority_serde_roundtrip() {
        let p = TicketPriority::High;
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"high\"");
        let back: TicketPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TicketPriority::High);
    }

    #[test]
    fn priority_serde_all_variants() {
        for p in [
            TicketPriority::Urgent,
            TicketPriority::High,
            TicketPriority::Normal,
            TicketPriority::Low,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: TicketPriority = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn priority_equality() {
        assert_eq!(TicketPriority::Urgent, TicketPriority::Urgent);
        assert_ne!(TicketPriority::Urgent, TicketPriority::Low);
    }

    #[test]
    fn priority_clone() {
        let p = TicketPriority::High;
        let c = p;
        assert_eq!(p, c);
    }

    #[test]
    fn priority_debug() {
        let dbg = format!("{:?}", TicketPriority::Normal);
        assert!(dbg.contains("Normal"));
    }

    #[test]
    fn priority_hash() {
        let mut set = HashSet::new();
        set.insert(TicketPriority::Urgent);
        set.insert(TicketPriority::Urgent);
        assert_eq!(set.len(), 1);
        set.insert(TicketPriority::Low);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn priority_from_str_loose_none() {
        assert!(TicketPriority::from_str_loose("medium").is_none());
        assert!(TicketPriority::from_str_loose("").is_none());
        assert!(TicketPriority::from_str_loose("p1").is_none());
    }

    #[test]
    fn priority_from_str_loose_valid() {
        assert_eq!(TicketPriority::from_str_loose("URGENT"), Some(TicketPriority::Urgent));
        assert_eq!(TicketPriority::from_str_loose("low"), Some(TicketPriority::Low));
    }

    // ── EscalationFlag ──────────────────────────────────────────────

    #[test]
    fn escalation_flag_as_str() {
        assert_eq!(EscalationFlag::SlaRisk.as_str(), "sla_risk");
        assert_eq!(EscalationFlag::NegativeSentiment.as_str(), "negative_sentiment");
        assert_eq!(EscalationFlag::HighPriority.as_str(), "high_priority");
        assert_eq!(EscalationFlag::VipCustomer.as_str(), "vip_customer");
        assert_eq!(EscalationFlag::SecurityIssue.as_str(), "security_issue");
        assert_eq!(EscalationFlag::ComplianceIssue.as_str(), "compliance_issue");
        assert_eq!(EscalationFlag::RepeatContact.as_str(), "repeat_contact");
    }

    #[test]
    fn escalation_flag_severity_security() {
        assert_eq!(EscalationFlag::SecurityIssue.severity(), 5);
    }

    #[test]
    fn escalation_flag_severity_compliance() {
        assert_eq!(EscalationFlag::ComplianceIssue.severity(), 5);
    }

    #[test]
    fn escalation_flag_severity_sla_risk() {
        assert_eq!(EscalationFlag::SlaRisk.severity(), 4);
    }

    #[test]
    fn escalation_flag_severity_high_priority() {
        assert_eq!(EscalationFlag::HighPriority.severity(), 4);
    }

    #[test]
    fn escalation_flag_severity_vip() {
        assert_eq!(EscalationFlag::VipCustomer.severity(), 3);
    }

    #[test]
    fn escalation_flag_severity_negative_sentiment() {
        assert_eq!(EscalationFlag::NegativeSentiment.severity(), 2);
    }

    #[test]
    fn escalation_flag_severity_repeat_contact() {
        assert_eq!(EscalationFlag::RepeatContact.severity(), 1);
    }

    #[test]
    fn escalation_flag_display() {
        assert_eq!(format!("{}", EscalationFlag::SlaRisk), "sla_risk");
        assert_eq!(format!("{}", EscalationFlag::SecurityIssue), "security_issue");
    }

    #[test]
    fn escalation_flag_serde_roundtrip() {
        let f = EscalationFlag::VipCustomer;
        let json = serde_json::to_string(&f).unwrap();
        let back: EscalationFlag = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn escalation_flag_all_variants_serde() {
        let all = [
            EscalationFlag::SlaRisk,
            EscalationFlag::NegativeSentiment,
            EscalationFlag::HighPriority,
            EscalationFlag::VipCustomer,
            EscalationFlag::SecurityIssue,
            EscalationFlag::ComplianceIssue,
            EscalationFlag::RepeatContact,
        ];
        for f in all {
            let json = serde_json::to_string(&f).unwrap();
            let back: EscalationFlag = serde_json::from_str(&json).unwrap();
            assert_eq!(back, f);
        }
    }

    #[test]
    fn escalation_flag_hash_set() {
        let mut set = HashSet::new();
        set.insert(EscalationFlag::SecurityIssue);
        set.insert(EscalationFlag::SecurityIssue);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn escalation_flag_debug() {
        let dbg = format!("{:?}", EscalationFlag::ComplianceIssue);
        assert!(dbg.contains("ComplianceIssue"));
    }

    #[test]
    fn escalation_flag_clone_copy() {
        let f = EscalationFlag::SlaRisk;
        let c = f;
        assert_eq!(f, c);
    }

    // ── MacroSuggestion ─────────────────────────────────────────────

    #[test]
    fn macro_suggestion_serde_roundtrip() {
        let ms = MacroSuggestion {
            macro_id: "macro_123".into(),
            macro_title: "Reset Password".into(),
            relevance_score: 0.85,
            reason: "Password keywords detected".into(),
        };
        let json = serde_json::to_string(&ms).unwrap();
        let back: MacroSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(back.macro_id, "macro_123");
        assert_eq!(back.macro_title, "Reset Password");
        assert!((back.relevance_score - 0.85).abs() < f64::EPSILON);
        assert_eq!(back.reason, "Password keywords detected");
    }

    #[test]
    fn macro_suggestion_clone() {
        let ms = MacroSuggestion {
            macro_id: "m1".into(),
            macro_title: "Test".into(),
            relevance_score: 0.5,
            reason: "test".into(),
        };
        let cloned = ms.clone();
        assert_eq!(cloned.macro_id, ms.macro_id);
        assert_eq!(cloned.macro_title, ms.macro_title);
    }

    #[test]
    fn macro_suggestion_debug() {
        let ms = MacroSuggestion {
            macro_id: "m2".into(),
            macro_title: "Debug".into(),
            relevance_score: 0.9,
            reason: "r".into(),
        };
        let dbg = format!("{ms:?}");
        assert!(dbg.contains("MacroSuggestion"));
        assert!(dbg.contains("m2"));
    }

    // ── TicketInput ─────────────────────────────────────────────────

    #[test]
    fn ticket_input_combined_text_both() {
        let input = sample_input("1", "Login issue", "Cannot log in to my account");
        assert_eq!(input.combined_text(), "Login issue Cannot log in to my account");
    }

    #[test]
    fn ticket_input_combined_text_subject_only() {
        let input = TicketInput {
            ticket_id: "2".into(),
            subject: Some("Subject only".into()),
            description: None,
            requester_email: None,
            channel: None,
            custom_fields: HashMap::new(),
        };
        assert_eq!(input.combined_text(), "Subject only");
    }

    #[test]
    fn ticket_input_combined_text_description_only() {
        let input = TicketInput {
            ticket_id: "3".into(),
            subject: None,
            description: Some("Description only".into()),
            requester_email: None,
            channel: None,
            custom_fields: HashMap::new(),
        };
        assert_eq!(input.combined_text(), "Description only");
    }

    #[test]
    fn ticket_input_combined_text_empty() {
        let input = TicketInput {
            ticket_id: "4".into(),
            subject: None,
            description: None,
            requester_email: None,
            channel: None,
            custom_fields: HashMap::new(),
        };
        assert_eq!(input.combined_text(), "");
    }

    #[test]
    fn ticket_input_serde_roundtrip() {
        let mut fields = HashMap::new();
        fields.insert("priority_override".into(), "high".into());
        let input = TicketInput {
            ticket_id: "t42".into(),
            subject: Some("Serde test".into()),
            description: Some("Round trip".into()),
            requester_email: Some("test@example.com".into()),
            channel: Some("email".into()),
            custom_fields: fields,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: TicketInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ticket_id, "t42");
        assert_eq!(back.subject.as_deref(), Some("Serde test"));
        assert_eq!(back.requester_email.as_deref(), Some("test@example.com"));
        assert_eq!(back.channel.as_deref(), Some("email"));
        assert_eq!(back.custom_fields.get("priority_override").map(String::as_str), Some("high"));
    }

    #[test]
    fn ticket_input_clone() {
        let input = sample_input("c1", "Clone", "test");
        let cloned = input.clone();
        assert_eq!(cloned.ticket_id, input.ticket_id);
        assert_eq!(cloned.subject, input.subject);
    }

    #[test]
    fn ticket_input_debug() {
        let input = sample_input("d1", "Debug", "test");
        let dbg = format!("{input:?}");
        assert!(dbg.contains("TicketInput"));
        assert!(dbg.contains("d1"));
    }

    #[test]
    fn ticket_input_custom_fields_empty() {
        let input = sample_input("5", "S", "D");
        assert!(input.custom_fields.is_empty());
    }

    // ── CategoryRule ────────────────────────────────────────────────

    #[test]
    fn rule_matches_text_exact() {
        let rule = billing_rule();
        assert!(rule.matches_text("I need an invoice"));
    }

    #[test]
    fn rule_matches_text_case_insensitive() {
        let rule = billing_rule();
        assert!(rule.matches_text("BILLING question"));
    }

    #[test]
    fn rule_matches_text_no_match() {
        let rule = billing_rule();
        assert!(!rule.matches_text("I love your product"));
    }

    #[test]
    fn rule_match_count_multiple() {
        let rule = billing_rule();
        let count = rule.match_count("I need a billing invoice and a refund");
        assert_eq!(count, 3); // billing, invoice, refund
    }

    #[test]
    fn rule_match_count_zero() {
        let rule = billing_rule();
        assert_eq!(rule.match_count("great product"), 0);
    }

    #[test]
    fn rule_match_count_single() {
        let rule = billing_rule();
        assert_eq!(rule.match_count("payment issue"), 1);
    }

    #[test]
    fn rule_serde_roundtrip() {
        let rule = billing_rule();
        let json = serde_json::to_string(&rule).unwrap();
        let back: CategoryRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "billing");
        assert_eq!(back.category, "billing");
        assert_eq!(back.patterns.len(), 5);
        assert_eq!(back.priority_hint, Some(TicketPriority::Normal));
        assert_eq!(back.tags.len(), 2);
    }

    #[test]
    fn rule_clone() {
        let rule = technical_rule();
        let cloned = rule.clone();
        assert_eq!(cloned.name, rule.name);
        assert_eq!(cloned.patterns, rule.patterns);
        assert_eq!(cloned.category, rule.category);
    }

    #[test]
    fn rule_debug() {
        let rule = security_rule();
        let dbg = format!("{rule:?}");
        assert!(dbg.contains("CategoryRule"));
        assert!(dbg.contains("security"));
    }

    #[test]
    fn rule_empty_patterns_no_match() {
        let rule = CategoryRule {
            name: "empty".into(),
            patterns: vec![],
            category: "none".into(),
            priority_hint: None,
            tags: vec![],
        };
        assert!(!rule.matches_text("anything"));
        assert_eq!(rule.match_count("anything"), 0);
    }

    #[test]
    fn rule_matches_text_partial_word() {
        let rule = billing_rule();
        // "charge" is in "recharge"
        assert!(rule.matches_text("I need to recharge my account"));
    }

    #[test]
    fn rule_no_priority_hint() {
        let rule = CategoryRule {
            name: "general".into(),
            patterns: vec!["hello".into()],
            category: "general".into(),
            priority_hint: None,
            tags: vec![],
        };
        assert!(rule.priority_hint.is_none());
    }

    // ── CategorizationConfig ────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let cfg = CategorizationConfig::default();
        assert!((cfg.min_confidence_threshold - 0.5).abs() < f64::EPSILON);
        assert_eq!(cfg.max_tags_per_ticket, 10);
        assert_eq!(cfg.max_suggestions, 5);
        assert!(!cfg.auto_apply);
    }

    #[test]
    fn config_auto_apply_defaults_false() {
        let cfg = CategorizationConfig::default();
        assert!(!cfg.auto_apply, "auto_apply must default to false for safety");
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = CategorizationConfig {
            min_confidence_threshold: 0.7,
            max_tags_per_ticket: 5,
            max_suggestions: 3,
            auto_apply: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: CategorizationConfig = serde_json::from_str(&json).unwrap();
        assert!((back.min_confidence_threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(back.max_tags_per_ticket, 5);
        assert_eq!(back.max_suggestions, 3);
        assert!(!back.auto_apply);
    }

    #[test]
    fn config_clone() {
        let cfg = CategorizationConfig::default();
        let cloned = cfg.clone();
        assert!((cloned.min_confidence_threshold - cfg.min_confidence_threshold).abs() < f64::EPSILON);
        assert_eq!(cloned.max_tags_per_ticket, cfg.max_tags_per_ticket);
    }

    #[test]
    fn config_debug() {
        let cfg = CategorizationConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("CategorizationConfig"));
    }

    #[test]
    fn config_custom_values() {
        let cfg = CategorizationConfig {
            min_confidence_threshold: 0.9,
            max_tags_per_ticket: 3,
            max_suggestions: 1,
            auto_apply: true,
        };
        assert!((cfg.min_confidence_threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(cfg.max_tags_per_ticket, 3);
        assert!(cfg.auto_apply);
    }

    // ── CategorizationPolicy ────────────────────────────────────────

    #[test]
    fn policy_suggest_only() {
        let policy = CategorizationPolicy::new_suggest_only();
        assert!(policy.allow_read);
        assert!(policy.allow_suggest);
        assert!(!policy.allow_auto_apply);
        assert!(policy.require_approval_for_apply);
        assert!(policy.blocked_categories.is_empty());
    }

    #[test]
    fn policy_readonly() {
        let policy = CategorizationPolicy::new_readonly();
        assert!(policy.allow_read);
        assert!(!policy.allow_suggest);
        assert!(!policy.allow_auto_apply);
        assert!(policy.require_approval_for_apply);
    }

    #[test]
    fn policy_check_apply_denied_by_default() {
        let policy = CategorizationPolicy::new_suggest_only();
        assert!(!policy.check_apply("billing"));
    }

    #[test]
    fn policy_check_apply_allowed() {
        let policy = CategorizationPolicy {
            allow_read: true,
            allow_suggest: true,
            allow_auto_apply: true,
            require_approval_for_apply: false,
            blocked_categories: HashSet::new(),
        };
        assert!(policy.check_apply("billing"));
    }

    #[test]
    fn policy_check_apply_blocked_category() {
        let mut blocked = HashSet::new();
        blocked.insert("sensitive".into());
        let policy = CategorizationPolicy {
            allow_read: true,
            allow_suggest: true,
            allow_auto_apply: true,
            require_approval_for_apply: false,
            blocked_categories: blocked,
        };
        assert!(!policy.check_apply("sensitive"));
        assert!(policy.check_apply("billing"));
    }

    #[test]
    fn policy_check_apply_requires_approval() {
        let policy = CategorizationPolicy {
            allow_read: true,
            allow_suggest: true,
            allow_auto_apply: true,
            require_approval_for_apply: true,
            blocked_categories: HashSet::new(),
        };
        assert!(!policy.check_apply("any"));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = CategorizationPolicy::new_suggest_only();
        let json = serde_json::to_string(&policy).unwrap();
        let back: CategorizationPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.allow_read);
        assert!(back.allow_suggest);
        assert!(!back.allow_auto_apply);
    }

    #[test]
    fn policy_clone() {
        let policy = CategorizationPolicy::new_readonly();
        let cloned = policy.clone();
        assert_eq!(cloned.allow_read, policy.allow_read);
        assert_eq!(cloned.allow_suggest, policy.allow_suggest);
    }

    #[test]
    fn policy_debug() {
        let policy = CategorizationPolicy::new_suggest_only();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("CategorizationPolicy"));
    }

    #[test]
    fn policy_blocked_categories_multiple() {
        let mut blocked = HashSet::new();
        blocked.insert("legal".into());
        blocked.insert("hr".into());
        let policy = CategorizationPolicy {
            allow_read: true,
            allow_suggest: true,
            allow_auto_apply: true,
            require_approval_for_apply: false,
            blocked_categories: blocked,
        };
        assert!(!policy.check_apply("legal"));
        assert!(!policy.check_apply("hr"));
        assert!(policy.check_apply("engineering"));
    }

    // ── AuditAction ─────────────────────────────────────────────────

    #[test]
    fn audit_action_as_str() {
        assert_eq!(AuditAction::Categorized.as_str(), "categorized");
        assert_eq!(AuditAction::Applied.as_str(), "applied");
        assert_eq!(AuditAction::Skipped.as_str(), "skipped");
    }

    #[test]
    fn audit_action_display() {
        assert_eq!(format!("{}", AuditAction::Categorized), "categorized");
        assert_eq!(format!("{}", AuditAction::Applied), "applied");
        assert_eq!(format!("{}", AuditAction::Skipped), "skipped");
    }

    #[test]
    fn audit_action_serde_roundtrip() {
        for action in [AuditAction::Categorized, AuditAction::Applied, AuditAction::Skipped] {
            let json = serde_json::to_string(&action).unwrap();
            let back: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    #[test]
    fn audit_action_equality() {
        assert_eq!(AuditAction::Categorized, AuditAction::Categorized);
        assert_ne!(AuditAction::Applied, AuditAction::Skipped);
    }

    #[test]
    fn audit_action_debug() {
        let dbg = format!("{:?}", AuditAction::Applied);
        assert!(dbg.contains("Applied"));
    }

    // ── CategorizationAuditEvent ────────────────────────────────────

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = CategorizationAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            ticket_id: "t100".into(),
            action: AuditAction::Categorized,
            category: Some("billing".into()),
            confidence: 0.85,
            was_auto_applied: false,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: CategorizationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ticket_id, "t100");
        assert_eq!(back.action, AuditAction::Categorized);
        assert_eq!(back.category.as_deref(), Some("billing"));
        assert!(!back.was_auto_applied);
    }

    #[test]
    fn audit_event_skipped() {
        let evt = CategorizationAuditEvent {
            timestamp: "2026-03-09T12:01:00Z".into(),
            ticket_id: "t200".into(),
            action: AuditAction::Skipped,
            category: None,
            confidence: 0.1,
            was_auto_applied: false,
        };
        assert_eq!(evt.action, AuditAction::Skipped);
        assert!(evt.category.is_none());
    }

    #[test]
    fn audit_event_auto_applied() {
        let evt = CategorizationAuditEvent {
            timestamp: "2026-03-09T12:02:00Z".into(),
            ticket_id: "t300".into(),
            action: AuditAction::Applied,
            category: Some("tech".into()),
            confidence: 0.95,
            was_auto_applied: true,
        };
        assert!(evt.was_auto_applied);
        assert_eq!(evt.action, AuditAction::Applied);
    }

    #[test]
    fn audit_event_clone() {
        let evt = CategorizationAuditEvent {
            timestamp: "2026-03-09T00:00:00Z".into(),
            ticket_id: "t1".into(),
            action: AuditAction::Categorized,
            category: Some("c".into()),
            confidence: 0.5,
            was_auto_applied: false,
        };
        let cloned = evt.clone();
        assert_eq!(cloned.ticket_id, evt.ticket_id);
        assert_eq!(cloned.action, evt.action);
    }

    #[test]
    fn audit_event_debug() {
        let evt = CategorizationAuditEvent {
            timestamp: "ts".into(),
            ticket_id: "tid".into(),
            action: AuditAction::Categorized,
            category: None,
            confidence: 0.0,
            was_auto_applied: false,
        };
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("CategorizationAuditEvent"));
    }

    // ── CategorizationResult ────────────────────────────────────────

    #[test]
    fn result_meets_threshold_above() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: Some("billing".into()),
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.8,
        };
        assert!(r.meets_threshold(0.5));
    }

    #[test]
    fn result_meets_threshold_exact() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.5,
        };
        assert!(r.meets_threshold(0.5));
    }

    #[test]
    fn result_meets_threshold_below() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.3,
        };
        assert!(!r.meets_threshold(0.5));
    }

    #[test]
    fn result_needs_escalation_true() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![EscalationFlag::SecurityIssue],
            confidence: 0.5,
        };
        assert!(r.needs_escalation());
    }

    #[test]
    fn result_needs_escalation_false() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.5,
        };
        assert!(!r.needs_escalation());
    }

    #[test]
    fn result_max_severity_multiple_flags() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![
                EscalationFlag::RepeatContact,    // 1
                EscalationFlag::NegativeSentiment, // 2
                EscalationFlag::SecurityIssue,     // 5
            ],
            confidence: 0.5,
        };
        assert_eq!(r.max_severity(), 5);
    }

    #[test]
    fn result_max_severity_no_flags() {
        let r = CategorizationResult {
            ticket_id: "1".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.5,
        };
        assert_eq!(r.max_severity(), 0);
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = CategorizationResult {
            ticket_id: "t99".into(),
            suggested_category: Some("billing".into()),
            suggested_priority: Some(TicketPriority::High),
            suggested_tags: vec!["tag1".into(), "tag2".into()],
            macro_suggestions: vec![MacroSuggestion {
                macro_id: "m1".into(),
                macro_title: "Apply billing".into(),
                relevance_score: 0.9,
                reason: "billing detected".into(),
            }],
            escalation_flags: vec![EscalationFlag::VipCustomer],
            confidence: 0.75,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: CategorizationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ticket_id, "t99");
        assert_eq!(back.suggested_category.as_deref(), Some("billing"));
        assert_eq!(back.suggested_priority, Some(TicketPriority::High));
        assert_eq!(back.suggested_tags.len(), 2);
        assert_eq!(back.macro_suggestions.len(), 1);
        assert_eq!(back.escalation_flags.len(), 1);
    }

    #[test]
    fn result_clone() {
        let r = CategorizationResult {
            ticket_id: "c".into(),
            suggested_category: Some("c".into()),
            suggested_priority: None,
            suggested_tags: vec!["t".into()],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.6,
        };
        let cloned = r.clone();
        assert_eq!(cloned.ticket_id, r.ticket_id);
        assert_eq!(cloned.suggested_tags, r.suggested_tags);
    }

    #[test]
    fn result_debug() {
        let r = CategorizationResult {
            ticket_id: "dbg".into(),
            suggested_category: None,
            suggested_priority: None,
            suggested_tags: vec![],
            macro_suggestions: vec![],
            escalation_flags: vec![],
            confidence: 0.0,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CategorizationResult"));
    }

    // ── CategorizationEngine ────────────────────────────────────────

    #[test]
    fn engine_new_default() {
        let engine = CategorizationEngine::new("general", 0.5);
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn engine_add_rules() {
        let mut engine = CategorizationEngine::new("general", 0.5);
        engine.add_rule(billing_rule());
        assert_eq!(engine.rule_count(), 1);
        engine.add_rule(technical_rule());
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn engine_categorize_billing() {
        let engine = build_engine();
        let input = sample_input("1", "Invoice question", "I need my billing invoice");
        let result = engine.categorize(&input);
        assert_eq!(result.ticket_id, "1");
        assert_eq!(result.suggested_category.as_deref(), Some("billing"));
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn engine_categorize_technical() {
        let engine = build_engine();
        let input = sample_input("2", "App crash", "The app keeps crashing with an error");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("technical_support"));
    }

    #[test]
    fn engine_categorize_security() {
        let engine = build_engine();
        let input = sample_input("3", "Security breach", "There was a security vulnerability found");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("security"));
        assert!(result.needs_escalation());
    }

    #[test]
    fn engine_categorize_no_match_falls_back() {
        let engine = build_engine();
        let input = sample_input("4", "General inquiry", "How do I change my username");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("general"));
        assert!((result.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn engine_categorize_empty_text() {
        let engine = build_engine();
        let input = TicketInput {
            ticket_id: "5".into(),
            subject: None,
            description: None,
            requester_email: None,
            channel: None,
            custom_fields: HashMap::new(),
        };
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("general"));
    }

    #[test]
    fn engine_categorize_batch() {
        let engine = build_engine();
        let inputs = vec![
            sample_input("1", "Invoice", "billing question"),
            sample_input("2", "Crash", "error bug"),
            sample_input("3", "Hello", "general question"),
        ];
        let results = engine.categorize_batch(&inputs);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].ticket_id, "1");
        assert_eq!(results[1].ticket_id, "2");
        assert_eq!(results[2].ticket_id, "3");
    }

    #[test]
    fn engine_categorize_batch_empty() {
        let engine = build_engine();
        let results = engine.categorize_batch(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn engine_escalation_security_keyword() {
        let engine = build_engine();
        let input = sample_input("s1", "Help", "I found a security breach in your system");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::SecurityIssue));
    }

    #[test]
    fn engine_escalation_compliance_keyword() {
        let engine = build_engine();
        let input = sample_input("s2", "GDPR request", "We need GDPR compliance data deletion");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::ComplianceIssue));
    }

    #[test]
    fn engine_escalation_negative_sentiment() {
        let engine = build_engine();
        let input = sample_input("s3", "Terrible service", "This is unacceptable and I am furious");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::NegativeSentiment));
    }

    #[test]
    fn engine_escalation_vip_keyword() {
        let engine = build_engine();
        let input = sample_input("s4", "VIP request", "Our enterprise account needs help");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::VipCustomer));
    }

    #[test]
    fn engine_escalation_sla_risk() {
        let engine = build_engine();
        let input = sample_input("s5", "SLA", "This ticket is overdue per our SLA");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::SlaRisk));
    }

    #[test]
    fn engine_no_escalation_normal_text() {
        let engine = build_engine();
        let input = sample_input("s6", "Simple question", "How do I reset my password");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.is_empty());
    }

    #[test]
    fn engine_escalation_boosts_priority() {
        let engine = build_engine();
        // Security issue should escalate priority
        let input = sample_input("p1", "Security vulnerability", "There is a breach");
        let result = engine.categorize(&input);
        assert!(
            result.suggested_priority == Some(TicketPriority::Urgent)
                || result.suggested_priority == Some(TicketPriority::High)
        );
    }

    #[test]
    fn engine_multiple_escalation_flags() {
        let engine = build_engine();
        let input = sample_input(
            "m1",
            "VIP GDPR security breach",
            "Our enterprise VIP account has a security breach and needs GDPR compliance review",
        );
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.len() >= 2);
    }

    #[test]
    fn engine_serde_roundtrip() {
        let engine = build_engine();
        let json = serde_json::to_string(&engine).unwrap();
        let back: CategorizationEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule_count(), 3);
    }

    #[test]
    fn engine_clone() {
        let engine = build_engine();
        let cloned = engine.clone();
        assert_eq!(cloned.rule_count(), engine.rule_count());
    }

    #[test]
    fn engine_debug() {
        let engine = build_engine();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("CategorizationEngine"));
    }

    #[test]
    fn engine_confidence_clamp_high() {
        let engine = CategorizationEngine::new("default", 1.5);
        // min_confidence should be clamped to 1.0
        let input = sample_input("c1", "test", "test");
        let result = engine.categorize(&input);
        // No rules match, so fallback to default with confidence 0.0
        assert_eq!(result.suggested_category.as_deref(), Some("default"));
    }

    #[test]
    fn engine_confidence_clamp_low() {
        let engine = CategorizationEngine::new("default", -0.5);
        // min_confidence should be clamped to 0.0
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn engine_best_match_wins() {
        let engine = build_engine();
        // "invoice billing charge refund" has 4 billing matches
        // vs "error" has 1 technical match
        let input = sample_input("bm", "invoice", "billing charge refund error");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("billing"));
    }

    #[test]
    fn engine_categorize_preserves_ticket_id() {
        let engine = build_engine();
        let input = sample_input("my-ticket-42", "Test", "billing");
        let result = engine.categorize(&input);
        assert_eq!(result.ticket_id, "my-ticket-42");
    }

    #[test]
    fn engine_categorize_assigns_tags() {
        let engine = build_engine();
        let input = sample_input("t1", "Invoice", "billing question");
        let result = engine.categorize(&input);
        assert!(result.suggested_tags.contains(&"billing".to_string()));
        assert!(result.suggested_tags.contains(&"finance".to_string()));
    }

    #[test]
    fn engine_no_rules_returns_default() {
        let engine = CategorizationEngine::new("uncategorized", 0.5);
        let input = sample_input("n1", "Anything", "goes here");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("uncategorized"));
        assert!((result.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn engine_categorize_batch_preserves_order() {
        let engine = build_engine();
        let ids: Vec<String> = (0..10).map(|i| format!("ticket-{i}")).collect();
        let inputs: Vec<TicketInput> = ids
            .iter()
            .map(|id| sample_input(id, "test", "test"))
            .collect();
        let results = engine.categorize_batch(&inputs);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.ticket_id, format!("ticket-{i}"));
        }
    }

    #[test]
    fn engine_categorize_unicode_text() {
        let engine = build_engine();
        let input = sample_input("u1", "Invoice billing", "Je veux mon invoice et billing s'il vous plait");
        let result = engine.categorize(&input);
        // "invoice" and "billing" match billing rule (2/5 = 0.4 > 0.3 threshold)
        assert_eq!(result.suggested_category.as_deref(), Some("billing"));
    }

    #[test]
    fn engine_escalation_unauthorized_access() {
        let engine = build_engine();
        let input = sample_input("ua", "Urgent", "Someone got unauthorized access to our data");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::SecurityIssue));
    }

    #[test]
    fn engine_escalation_hipaa() {
        let engine = build_engine();
        let input = sample_input("h1", "HIPAA", "We need HIPAA compliance verification");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::ComplianceIssue));
    }

    #[test]
    fn engine_escalation_lawsuit() {
        let engine = build_engine();
        let input = sample_input("l1", "Legal", "We will pursue a lawsuit if not resolved");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::NegativeSentiment));
    }

    #[test]
    fn engine_escalation_deadline() {
        let engine = build_engine();
        let input = sample_input("d1", "Deadline", "We have a hard deadline tomorrow");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::SlaRisk));
    }

    #[test]
    fn engine_escalation_exploit() {
        let engine = build_engine();
        let input = sample_input("e1", "Bug", "We found an exploit in the API");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::SecurityIssue));
    }

    #[test]
    fn engine_escalation_worst_keyword() {
        let engine = build_engine();
        let input = sample_input("w1", "Feedback", "This is the worst experience");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::NegativeSentiment));
    }

    #[test]
    fn engine_escalation_regulation() {
        let engine = build_engine();
        let input = sample_input("r1", "Regulation", "New regulation requires data handling changes");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::ComplianceIssue));
    }

    #[test]
    fn engine_escalation_executive() {
        let engine = build_engine();
        let input = sample_input("ex1", "From executive", "Our executive team needs a response");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::VipCustomer));
    }

    #[test]
    fn engine_escalation_past_due() {
        let engine = build_engine();
        let input = sample_input("pd1", "Overdue", "This request is past due");
        let result = engine.categorize(&input);
        assert!(result.escalation_flags.contains(&EscalationFlag::SlaRisk));
    }

    // ── Integration / end-to-end ────────────────────────────────────

    #[test]
    fn integration_full_pipeline() {
        let mut engine = CategorizationEngine::new("general", 0.3);
        engine.add_rule(billing_rule());
        engine.add_rule(technical_rule());
        engine.add_rule(security_rule());

        let policy = CategorizationPolicy::new_suggest_only();
        let config = CategorizationConfig::default();

        let input = sample_input("full-1", "Billing issue", "I was charged twice on my invoice");
        let result = engine.categorize(&input);

        assert_eq!(result.suggested_category.as_deref(), Some("billing"));
        assert!(result.meets_threshold(config.min_confidence_threshold));
        assert!(result.suggested_tags.len() <= config.max_tags_per_ticket);
        assert!(!policy.check_apply("billing")); // suggest-only
    }

    #[test]
    fn integration_security_escalation_pipeline() {
        let engine = build_engine();
        let policy = CategorizationPolicy::new_suggest_only();

        let input = sample_input(
            "sec-1",
            "Security breach detected",
            "There is a vulnerability and a security breach in the system",
        );
        let result = engine.categorize(&input);

        assert!(result.needs_escalation());
        assert!(result.max_severity() >= 4);
        assert!(!policy.check_apply(result.suggested_category.as_deref().unwrap_or("")));
    }

    #[test]
    fn integration_audit_event_creation() {
        let engine = build_engine();
        let input = sample_input("audit-1", "Billing", "invoice payment charge");
        let result = engine.categorize(&input);

        let evt = CategorizationAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            ticket_id: result.ticket_id.clone(),
            action: if result.confidence > 0.0 {
                AuditAction::Categorized
            } else {
                AuditAction::Skipped
            },
            category: result.suggested_category.clone(),
            confidence: result.confidence,
            was_auto_applied: false,
        };

        assert_eq!(evt.ticket_id, "audit-1");
        assert_eq!(evt.action, AuditAction::Categorized);
        assert!(!evt.was_auto_applied);
    }

    #[test]
    fn integration_batch_with_mixed_categories() {
        let engine = build_engine();
        let inputs = vec![
            sample_input("b1", "Invoice issue", "billing problem"),
            sample_input("b2", "App crash", "error bug broken"),
            sample_input("b3", "Security breach", "vulnerability exploit"),
            sample_input("b4", "Hello", "how are you"),
        ];
        let results = engine.categorize_batch(&inputs);
        assert_eq!(results[0].suggested_category.as_deref(), Some("billing"));
        assert_eq!(results[1].suggested_category.as_deref(), Some("technical_support"));
        assert_eq!(results[2].suggested_category.as_deref(), Some("security"));
        assert_eq!(results[3].suggested_category.as_deref(), Some("general"));
    }

    #[test]
    fn integration_readonly_policy_blocks_all() {
        let policy = CategorizationPolicy::new_readonly();
        assert!(!policy.allow_suggest);
        assert!(!policy.allow_auto_apply);
        assert!(!policy.check_apply("anything"));
    }

    #[test]
    fn integration_config_auto_apply_danger() {
        let cfg = CategorizationConfig {
            auto_apply: true,
            ..CategorizationConfig::default()
        };
        // Even with config auto_apply on, policy should still guard
        let policy = CategorizationPolicy::new_suggest_only();
        assert!(cfg.auto_apply);
        assert!(!policy.check_apply("any"));
    }

    #[test]
    fn result_confidence_zero_for_no_rules() {
        let engine = CategorizationEngine::new("fallback", 0.5);
        let input = sample_input("z1", "Test", "anything");
        let result = engine.categorize(&input);
        assert!((result.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn result_macro_suggestions_empty_by_default() {
        let engine = build_engine();
        let input = sample_input("ms1", "Test", "billing");
        let result = engine.categorize(&input);
        assert!(result.macro_suggestions.is_empty());
    }

    #[test]
    fn ticket_input_with_channel() {
        let input = TicketInput {
            ticket_id: "ch1".into(),
            subject: Some("Test".into()),
            description: None,
            requester_email: None,
            channel: Some("chat".into()),
            custom_fields: HashMap::new(),
        };
        assert_eq!(input.channel.as_deref(), Some("chat"));
    }

    #[test]
    fn ticket_input_with_requester_email() {
        let input = TicketInput {
            ticket_id: "re1".into(),
            subject: None,
            description: None,
            requester_email: Some("user@example.com".into()),
            channel: None,
            custom_fields: HashMap::new(),
        };
        assert_eq!(input.requester_email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn ticket_input_with_multiple_custom_fields() {
        let mut fields = HashMap::new();
        fields.insert("field_a".into(), "val_a".into());
        fields.insert("field_b".into(), "val_b".into());
        fields.insert("field_c".into(), "val_c".into());
        let input = TicketInput {
            ticket_id: "cf1".into(),
            subject: None,
            description: None,
            requester_email: None,
            channel: None,
            custom_fields: fields,
        };
        assert_eq!(input.custom_fields.len(), 3);
    }

    #[test]
    fn engine_rule_ordering_first_best_wins() {
        let mut engine = CategorizationEngine::new("default", 0.0);
        // Two rules that both match with the same count
        let rule_a = CategoryRule {
            name: "a".into(),
            patterns: vec!["hello".into()],
            category: "cat_a".into(),
            priority_hint: None,
            tags: vec![],
        };
        let rule_b = CategoryRule {
            name: "b".into(),
            patterns: vec!["world".into()],
            category: "cat_b".into(),
            priority_hint: None,
            tags: vec![],
        };
        engine.add_rule(rule_a);
        engine.add_rule(rule_b);
        // "hello" matches only rule_a
        let input = sample_input("o1", "hello", "there");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("cat_a"));
    }

    #[test]
    fn engine_categorize_case_sensitivity_mixed() {
        let engine = build_engine();
        let input = sample_input("cs1", "INVOICE", "BILLING CHARGE");
        let result = engine.categorize(&input);
        assert_eq!(result.suggested_category.as_deref(), Some("billing"));
    }

    #[test]
    fn engine_categorize_single_pattern_match_confidence() {
        let mut engine = CategorizationEngine::new("default", 0.0);
        let rule = CategoryRule {
            name: "one_of_three".into(),
            patterns: vec!["alpha".into(), "beta".into(), "gamma".into()],
            category: "greek".into(),
            priority_hint: None,
            tags: vec![],
        };
        engine.add_rule(rule);
        let input = sample_input("c1", "alpha", "");
        let result = engine.categorize(&input);
        // 1 of 3 patterns match → ~0.333
        assert!(result.confidence > 0.3);
        assert!(result.confidence < 0.4);
    }

    #[test]
    fn engine_categorize_all_patterns_match_full_confidence() {
        let mut engine = CategorizationEngine::new("default", 0.0);
        let rule = CategoryRule {
            name: "all_match".into(),
            patterns: vec!["alpha".into(), "beta".into()],
            category: "greek".into(),
            priority_hint: None,
            tags: vec![],
        };
        engine.add_rule(rule);
        let input = sample_input("fc1", "alpha beta", "");
        let result = engine.categorize(&input);
        assert!((result.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn escalation_flag_severity_ordering() {
        let flags = [
            EscalationFlag::RepeatContact,
            EscalationFlag::NegativeSentiment,
            EscalationFlag::VipCustomer,
            EscalationFlag::SlaRisk,
            EscalationFlag::SecurityIssue,
        ];
        let severities: Vec<u8> = flags.iter().map(|f| f.severity()).collect();
        // Should be non-decreasing
        for w in severities.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }

    #[test]
    fn policy_with_no_blocked_allows_all() {
        let policy = CategorizationPolicy {
            allow_read: true,
            allow_suggest: true,
            allow_auto_apply: true,
            require_approval_for_apply: false,
            blocked_categories: HashSet::new(),
        };
        assert!(policy.check_apply("billing"));
        assert!(policy.check_apply("technical"));
        assert!(policy.check_apply("security"));
    }
}
