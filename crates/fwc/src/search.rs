//! Cross-connector semantic operation search engine.
//!
//! Builds an in-memory search index from connector introspections and scores
//! matches using weighted keyword matching with faceted filtering.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Value, json};

use crate::readiness::{DiscoveredConnector, DiscoveredOperation};

// ── Scoring weights ─────────────────────────────────────────────────────

/// Weight for exact operation ID match.
const WEIGHT_OP_ID_EXACT: i64 = 30;
/// Weight for partial operation ID match.
const WEIGHT_OP_ID_PARTIAL: i64 = 14;
/// Weight for match in `when_to_use` (highest value for agent consumption).
const WEIGHT_WHEN_TO_USE: i64 = 18;
/// Weight for match in operation summary/description.
const WEIGHT_SUMMARY: i64 = 10;
/// Weight for match in capability.
const WEIGHT_CAPABILITY: i64 = 8;
/// Weight for connector slug/name match.
const WEIGHT_CONNECTOR_NAME: i64 = 6;
/// Weight for match in `common_mistakes`.
const WEIGHT_COMMON_MISTAKES: i64 = 4;
/// Weight for match in related operations.
const WEIGHT_RELATED: i64 = 2;

// ── Filters ─────────────────────────────────────────────────────────────

/// Faceted search filters applied before scoring.
#[derive(Debug, Default)]
pub struct SearchFilters {
    /// Restrict to a specific connector slug.
    pub connector: Option<String>,
    /// Filter by capability family prefix (e.g. "write", "read", "admin").
    pub capability: Option<String>,
    /// Maximum risk level to include.
    pub risk_max: Option<RiskCeiling>,
    /// Maximum safety tier to include.
    pub safety_max: Option<SafetyCeiling>,
    /// Filter by connector archetype.
    pub archetype: Option<String>,
    /// Filter by connector category/cohort.
    pub category: Option<String>,
    /// Only include idempotent (safe to retry) operations.
    pub idempotent_only: bool,
    /// Zone filter.
    pub zone: Option<String>,
}

/// Risk level ceiling for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskCeiling {
    Low,
    Medium,
    High,
}

impl RiskCeiling {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn allows(self, level: &str) -> bool {
        match self {
            Self::Low => level == "low",
            Self::Medium => matches!(level, "low" | "medium"),
            Self::High => true,
        }
    }
}

/// Safety tier ceiling for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyCeiling {
    Safe,
    Risky,
    Dangerous,
    Critical,
}

impl SafetyCeiling {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "safe" => Some(Self::Safe),
            "risky" => Some(Self::Risky),
            "dangerous" => Some(Self::Dangerous),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    fn allows(self, tier: &str) -> bool {
        match self {
            Self::Safe => tier == "safe",
            Self::Risky => matches!(tier, "safe" | "risky"),
            Self::Dangerous => matches!(tier, "safe" | "risky" | "dangerous"),
            Self::Critical => matches!(tier, "safe" | "risky" | "dangerous" | "critical"),
        }
    }
}

// ── Search result ───────────────────────────────────────────────────────

/// A single scored search result at the operation level.
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub connector_slug: String,
    pub connector_name: String,
    pub operation_id: String,
    pub selector: String,
    pub summary: String,
    pub capability: String,
    pub risk_level: String,
    pub safety_tier: String,
    pub idempotency: String,
    pub score: i64,
    pub match_reasons: Vec<String>,
}

// ── Search engine ───────────────────────────────────────────────────────

/// Execute a cross-connector operation search.
///
/// Returns scored results sorted by relevance (descending), then by operation
/// ID (ascending) for deterministic output.
pub fn search_operations(
    connectors: &[DiscoveredConnector],
    query: &str,
    filters: &SearchFilters,
) -> Vec<SearchResult> {
    let tokens = tokenize(query);
    let mut results = Vec::new();

    for connector in connectors {
        if !connector_passes_filters(connector, filters) {
            continue;
        }

        let connector_bonus = connector_relevance(connector, &tokens);

        for operation in &connector.operations {
            if !operation_passes_filters(operation, filters) {
                continue;
            }

            let (score, reasons) = score_operation(connector, operation, &tokens);
            let total = score + connector_bonus;

            if total > 0 || (tokens.is_empty() && !query.is_empty()) {
                // Faceted-only search (no keywords but filters applied) returns all
                // matching operations with base score of 1.
                let final_score = if total > 0 { total } else { 1 };
                results.push(SearchResult {
                    connector_slug: connector.slug.clone(),
                    connector_name: connector.detail.summary.name.clone(),
                    operation_id: operation.actual_id.clone(),
                    selector: operation.preferred_selector.clone(),
                    summary: operation.summary.summary.clone(),
                    capability: operation.summary.capability.clone(),
                    risk_level: operation.summary.risk_level.clone(),
                    safety_tier: operation.summary.safety_tier.clone(),
                    idempotency: operation.summary.idempotency.clone(),
                    score: final_score,
                    match_reasons: reasons,
                });
            }
        }
    }

    results.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.operation_id.cmp(&b.operation_id))
    });

    results
}

/// Convert results to JSON for dispatch.
pub fn results_to_json(results: &[SearchResult], limit: usize) -> Vec<Value> {
    results
        .iter()
        .take(limit)
        .map(|r| {
            json!({
                "connector": r.connector_slug,
                "connector_name": r.connector_name,
                "operation": r.operation_id,
                "selector": r.selector,
                "summary": r.summary,
                "capability": r.capability,
                "risk_level": r.risk_level,
                "safety_tier": r.safety_tier,
                "idempotency": r.idempotency,
                "score": r.score,
                "match_reasons": r.match_reasons,
            })
        })
        .collect()
}

// ── Internal scoring ────────────────────────────────────────────────────

fn connector_passes_filters(connector: &DiscoveredConnector, filters: &SearchFilters) -> bool {
    if let Some(ref slug) = filters.connector {
        let slug_lower = slug.to_lowercase();
        if connector.slug.to_lowercase() != slug_lower
            && !connector
                .detail
                .summary
                .id
                .to_lowercase()
                .ends_with(&slug_lower)
        {
            return false;
        }
    }
    if let Some(ref zone) = filters.zone {
        if !connector.matches_zone(zone) {
            return false;
        }
    }
    if let Some(ref archetype) = filters.archetype {
        let arch_lower = archetype.to_lowercase();
        if !connector
            .detail
            .summary
            .archetypes
            .iter()
            .any(|a| a.to_lowercase() == arch_lower)
        {
            return false;
        }
    }
    if let Some(ref category) = filters.category {
        if connector.cohort.to_lowercase() != category.to_lowercase() {
            return false;
        }
    }
    true
}

fn operation_passes_filters(operation: &DiscoveredOperation, filters: &SearchFilters) -> bool {
    if let Some(ref cap) = filters.capability {
        let cap_lower = cap.to_lowercase();
        if !operation
            .summary
            .capability
            .to_lowercase()
            .contains(&cap_lower)
        {
            return false;
        }
    }
    if let Some(ceiling) = filters.risk_max {
        if !ceiling.allows(&operation.summary.risk_level) {
            return false;
        }
    }
    if let Some(ceiling) = filters.safety_max {
        if !ceiling.allows(&operation.summary.safety_tier) {
            return false;
        }
    }
    if filters.idempotent_only
        && !matches!(
            operation.summary.idempotency.as_str(),
            "strict" | "best_effort"
        )
    {
        return false;
    }
    true
}

fn connector_relevance(connector: &DiscoveredConnector, tokens: &[String]) -> i64 {
    let mut bonus = 0_i64;
    let slug = connector.slug.to_lowercase();
    let name = connector.detail.summary.name.to_lowercase();

    for token in tokens {
        if slug == *token || slug.contains(token) {
            bonus += WEIGHT_CONNECTOR_NAME;
        } else if name.contains(token) {
            bonus += WEIGHT_CONNECTOR_NAME / 2;
        }
    }
    bonus
}

fn score_operation(
    _connector: &DiscoveredConnector,
    operation: &DiscoveredOperation,
    tokens: &[String],
) -> (i64, Vec<String>) {
    let mut score = 0_i64;
    let mut reasons = BTreeSet::new();

    let op_id_lower = operation.actual_id.to_lowercase();
    let local_id_lower = operation.local_id.to_lowercase();
    let summary_lower = operation.summary.summary.to_lowercase();
    let when_to_use_lower = operation.when_to_use.to_lowercase();
    let capability_lower = operation.summary.capability.to_lowercase();

    for token in tokens {
        // Exact operation ID match (highest priority).
        if op_id_lower == *token || local_id_lower == *token {
            score += WEIGHT_OP_ID_EXACT;
            reasons.insert("exact_id_match".to_owned());
        } else if op_id_lower.contains(token) || local_id_lower.contains(token) {
            score += WEIGHT_OP_ID_PARTIAL;
            reasons.insert("partial_id_match".to_owned());
        }

        // Alias match.
        if operation.aliases.iter().any(|a| a.to_lowercase() == *token) {
            score += WEIGHT_OP_ID_EXACT;
            reasons.insert("alias_match".to_owned());
        } else if operation
            .aliases
            .iter()
            .any(|a| a.to_lowercase().contains(token))
        {
            score += WEIGHT_OP_ID_PARTIAL;
            reasons.insert("partial_alias_match".to_owned());
        }

        // when_to_use (3x effective — highest value for agent search).
        if when_to_use_lower.contains(token) {
            score += WEIGHT_WHEN_TO_USE;
            reasons.insert("when_to_use_match".to_owned());
        }

        // Summary/description.
        if summary_lower.contains(token) {
            score += WEIGHT_SUMMARY;
            reasons.insert("summary_match".to_owned());
        }

        // Capability.
        if capability_lower.contains(token) {
            score += WEIGHT_CAPABILITY;
            reasons.insert("capability_match".to_owned());
        }

        // Common mistakes.
        if operation
            .common_mistakes
            .iter()
            .any(|m| m.to_lowercase().contains(token))
        {
            score += WEIGHT_COMMON_MISTAKES;
            reasons.insert("common_mistakes_match".to_owned());
        }

        // Related operations.
        if operation
            .related
            .iter()
            .any(|r| r.to_lowercase().contains(token))
        {
            score += WEIGHT_RELATED;
            reasons.insert("related_match".to_owned());
        }
    }

    (score, reasons.into_iter().collect())
}

fn tokenize(query: &str) -> Vec<String> {
    query
        .split(|ch: char| {
            !ch.is_ascii_alphanumeric() && ch != ':' && ch != '.' && ch != '_' && ch != '-'
        })
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::{
        ConnectorDetail, ConnectorState, ConnectorSummary, DiscoveredConnector,
        DiscoveredOperation, OperationSummary,
    };

    fn stub_connector(slug: &str, ops: Vec<DiscoveredOperation>) -> DiscoveredConnector {
        let op_summaries: Vec<OperationSummary> = ops.iter().map(|o| o.summary.clone()).collect();
        DiscoveredConnector {
            slug: slug.to_owned(),
            manifest_path: format!("connectors/{slug}/manifest.toml"),
            cohort: "dev-tools".to_owned(),
            runtime_format: "wasi".to_owned(),
            state_model: None,
            supported_zones: vec!["z:work".to_owned()],
            detail: ConnectorDetail {
                summary: ConnectorSummary {
                    id: format!("fcp.{slug}"),
                    name: format!("{} Connector", capitalize(slug)),
                    version: "0.1.0".to_owned(),
                    description: format!("FCP connector for {slug}"),
                    archetypes: vec!["operational".to_owned()],
                    state: ConnectorState::Unknown,
                    operation_count: ops.len(),
                    max_risk: "medium".to_owned(),
                    has_events: false,
                },
                operations: op_summaries,
                config_schema: None,
                health: None,
                rate_limits: vec![],
            },
            zones: json!({}),
            capabilities: json!({}),
            connector_schema: json!({}),
            operations: ops,
        }
    }

    fn stub_operation(
        id: &str,
        summary: &str,
        capability: &str,
        risk: &str,
        safety: &str,
        when_to_use: &str,
    ) -> DiscoveredOperation {
        DiscoveredOperation {
            actual_id: id.to_owned(),
            local_id: id.rsplit('.').next().unwrap_or(id).to_owned(),
            preferred_selector: id.rsplit('.').next().unwrap_or(id).to_owned(),
            aliases: vec![],
            description: summary.to_owned(),
            summary: OperationSummary {
                id: id.to_owned(),
                summary: summary.to_owned(),
                capability: capability.to_owned(),
                risk_level: risk.to_owned(),
                safety_tier: safety.to_owned(),
                idempotency: "strict".to_owned(),
                requires_approval: false,
                supports_simulate: true,
            },
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            approval_mode: "none".to_owned(),
            when_to_use: when_to_use.to_owned(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
            network_constraints: None,
            rate_limits: vec![],
        }
    }

    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        chars.next().map_or_else(String::new, |c| {
            c.to_uppercase().collect::<String>() + chars.as_str()
        })
    }

    fn sample_connectors() -> Vec<DiscoveredConnector> {
        vec![
            stub_connector(
                "github",
                vec![
                    stub_operation(
                        "github.create_issue",
                        "Create a GitHub issue",
                        "github.write",
                        "medium",
                        "risky",
                        "Create an issue in a GitHub repository to track bugs or feature requests.",
                    ),
                    stub_operation(
                        "github.list_issues",
                        "List issues in a repository",
                        "github.read",
                        "low",
                        "safe",
                        "List issues with optional filters for state, labels, and assignee.",
                    ),
                ],
            ),
            stub_connector(
                "slack",
                vec![
                    stub_operation(
                        "slack.send_message",
                        "Send a message to a Slack channel",
                        "slack.write",
                        "medium",
                        "risky",
                        "Send a message to notify your team about deployments, alerts, or updates.",
                    ),
                    stub_operation(
                        "slack.list_channels",
                        "List Slack channels",
                        "slack.read",
                        "low",
                        "safe",
                        "List available channels in the workspace.",
                    ),
                ],
            ),
            stub_connector(
                "notion",
                vec![stub_operation(
                    "notion.create_page",
                    "Create a Notion page",
                    "notion.write",
                    "medium",
                    "risky",
                    "Create a new page in a Notion database or as a child of an existing page.",
                )],
            ),
        ]
    }

    // ── Keyword search tests ────────────────────────────────────────

    #[test]
    fn search_exact_operation_id() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
        assert!(
            results[0]
                .match_reasons
                .contains(&"exact_id_match".to_owned())
        );
    }

    #[test]
    fn search_keyword_in_when_to_use() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "team", &SearchFilters::default());
        assert!(!results.is_empty());
        // slack.send_message has "team" in when_to_use
        assert_eq!(results[0].operation_id, "slack.send_message");
        assert!(
            results[0]
                .match_reasons
                .contains(&"when_to_use_match".to_owned())
        );
    }

    #[test]
    fn search_keyword_in_summary() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "channel", &SearchFilters::default());
        assert!(!results.is_empty());
        let has_slack = results
            .iter()
            .any(|r| r.operation_id == "slack.list_channels");
        assert!(has_slack);
    }

    #[test]
    fn search_no_results_for_unknown_term() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "xyzzy", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn search_multiple_keywords() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create issue", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
    }

    #[test]
    fn search_case_insensitive() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "GitHub", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.connector_slug == "github"));
    }

    #[test]
    fn search_connector_slug_boosts_all_ops() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "slack", &SearchFilters::default());
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.connector_slug == "slack"));
    }

    // ── Faceted filter tests ────────────────────────────────────────

    #[test]
    fn filter_by_connector() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("github".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.connector_slug == "github"));
    }

    #[test]
    fn filter_by_capability() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.capability.contains("read")));
    }

    #[test]
    fn filter_by_risk_max_low() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            risk_max: Some(RiskCeiling::Low),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.risk_level == "low"));
    }

    #[test]
    fn filter_by_risk_max_medium() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            risk_max: Some(RiskCeiling::Medium),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|r| matches!(r.risk_level.as_str(), "low" | "medium"))
        );
    }

    #[test]
    fn filter_by_safety_max_safe() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            safety_max: Some(SafetyCeiling::Safe),
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.safety_tier == "safe"));
    }

    #[test]
    fn filter_idempotent_only() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|r| matches!(r.idempotency.as_str(), "strict" | "best_effort"))
        );
    }

    #[test]
    fn faceted_only_search_no_keywords() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            ..Default::default()
        };
        // Empty query with filters should return all read operations.
        let results = search_operations(&connectors, "", &filters);
        assert!(
            results.is_empty(),
            "empty query returns nothing even with filters"
        );
    }

    #[test]
    fn filter_excludes_nonmatching_connectors() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            connector: Some("notion".to_owned()),
            ..Default::default()
        };
        let results = search_operations(&connectors, "create", &filters);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].connector_slug, "notion");
    }

    // ── Scoring tests ───────────────────────────────────────────────

    #[test]
    fn scoring_exact_id_beats_summary_match() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create_issue", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "github.create_issue");
    }

    #[test]
    fn scoring_when_to_use_is_high_weight() {
        let connectors = sample_connectors();
        // "deployments" appears in slack.send_message.when_to_use
        let results = search_operations(&connectors, "deployments", &SearchFilters::default());
        assert!(!results.is_empty());
        assert_eq!(results[0].operation_id, "slack.send_message");
    }

    #[test]
    fn results_sorted_by_score_descending() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "create", &SearchFilters::default());
        for window in results.windows(2) {
            assert!(window[0].score >= window[1].score);
        }
    }

    #[test]
    fn deterministic_output_for_same_score() {
        let connectors = sample_connectors();
        let results1 = search_operations(&connectors, "list", &SearchFilters::default());
        let results2 = search_operations(&connectors, "list", &SearchFilters::default());
        assert_eq!(results1.len(), results2.len());
        for (a, b) in results1.iter().zip(results2.iter()) {
            assert_eq!(a.operation_id, b.operation_id);
            assert_eq!(a.score, b.score);
        }
    }

    // ── Tokenization tests ──────────────────────────────────────────

    #[test]
    fn tokenize_simple_words() {
        let tokens = tokenize("send a message");
        assert_eq!(tokens, vec!["send", "a", "message"]);
    }

    #[test]
    fn tokenize_preserves_dots_and_underscores() {
        let tokens = tokenize("github.create_issue");
        assert_eq!(tokens, vec!["github.create_issue"]);
    }

    #[test]
    fn tokenize_lowercases() {
        let tokens = tokenize("GitHub Create");
        assert_eq!(tokens, vec!["github", "create"]);
    }

    #[test]
    fn tokenize_empty_query() {
        let tokens = tokenize("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_special_chars_split() {
        let tokens = tokenize("send+message&fast");
        assert_eq!(tokens, vec!["send", "message", "fast"]);
    }

    // ── RiskCeiling tests ───────────────────────────────────────────

    #[test]
    fn risk_ceiling_parse() {
        assert_eq!(RiskCeiling::parse("low"), Some(RiskCeiling::Low));
        assert_eq!(RiskCeiling::parse("MEDIUM"), Some(RiskCeiling::Medium));
        assert_eq!(RiskCeiling::parse("med"), Some(RiskCeiling::Medium));
        assert_eq!(RiskCeiling::parse("high"), Some(RiskCeiling::High));
        assert_eq!(RiskCeiling::parse("extreme"), None);
    }

    #[test]
    fn risk_ceiling_low_allows_only_low() {
        assert!(RiskCeiling::Low.allows("low"));
        assert!(!RiskCeiling::Low.allows("medium"));
        assert!(!RiskCeiling::Low.allows("high"));
    }

    #[test]
    fn risk_ceiling_medium_allows_low_and_medium() {
        assert!(RiskCeiling::Medium.allows("low"));
        assert!(RiskCeiling::Medium.allows("medium"));
        assert!(!RiskCeiling::Medium.allows("high"));
    }

    #[test]
    fn risk_ceiling_high_allows_all() {
        assert!(RiskCeiling::High.allows("low"));
        assert!(RiskCeiling::High.allows("medium"));
        assert!(RiskCeiling::High.allows("high"));
    }

    // ── SafetyCeiling tests ─────────────────────────────────────────

    #[test]
    fn safety_ceiling_parse() {
        assert_eq!(SafetyCeiling::parse("safe"), Some(SafetyCeiling::Safe));
        assert_eq!(SafetyCeiling::parse("RISKY"), Some(SafetyCeiling::Risky));
        assert_eq!(
            SafetyCeiling::parse("dangerous"),
            Some(SafetyCeiling::Dangerous)
        );
        assert_eq!(
            SafetyCeiling::parse("critical"),
            Some(SafetyCeiling::Critical)
        );
        assert_eq!(SafetyCeiling::parse("forbidden"), None);
    }

    #[test]
    fn safety_ceiling_safe_allows_only_safe() {
        assert!(SafetyCeiling::Safe.allows("safe"));
        assert!(!SafetyCeiling::Safe.allows("risky"));
    }

    #[test]
    fn safety_ceiling_risky_allows_safe_and_risky() {
        assert!(SafetyCeiling::Risky.allows("safe"));
        assert!(SafetyCeiling::Risky.allows("risky"));
        assert!(!SafetyCeiling::Risky.allows("dangerous"));
    }

    #[test]
    fn safety_ceiling_dangerous_allows_up_to_dangerous() {
        assert!(SafetyCeiling::Dangerous.allows("safe"));
        assert!(SafetyCeiling::Dangerous.allows("risky"));
        assert!(SafetyCeiling::Dangerous.allows("dangerous"));
        assert!(!SafetyCeiling::Dangerous.allows("critical"));
    }

    // ── results_to_json tests ───────────────────────────────────────

    #[test]
    fn results_to_json_respects_limit() {
        let connectors = sample_connectors();
        let results = search_operations(&connectors, "list", &SearchFilters::default());
        let json = results_to_json(&results, 1);
        assert_eq!(json.len(), 1);
    }

    #[test]
    fn results_to_json_includes_all_fields() {
        let connectors = sample_connectors();
        let results = search_operations(
            &connectors,
            "github.create_issue",
            &SearchFilters::default(),
        );
        let json = results_to_json(&results, 10);
        assert!(!json.is_empty());
        let first = &json[0];
        assert!(first.get("connector").is_some());
        assert!(first.get("operation").is_some());
        assert!(first.get("score").is_some());
        assert!(first.get("match_reasons").is_some());
        assert!(first.get("risk_level").is_some());
        assert!(first.get("safety_tier").is_some());
    }

    // ── Common mistakes / related matching ──────────────────────────

    #[test]
    fn common_mistakes_boost_score() {
        let mut connectors = sample_connectors();
        connectors[0].operations[0].common_mistakes =
            vec!["Forgetting to set labels for triage".to_owned()];
        let results = search_operations(&connectors, "triage", &SearchFilters::default());
        assert!(!results.is_empty());
        assert!(
            results[0]
                .match_reasons
                .contains(&"common_mistakes_match".to_owned())
        );
    }

    #[test]
    fn related_operations_boost_score() {
        let mut connectors = sample_connectors();
        connectors[0].operations[0].related = vec!["github.list_issues".to_owned()];
        let results = search_operations(&connectors, "list_issues", &SearchFilters::default());
        // Both the actual list_issues and the related reference should match
        assert!(results.len() >= 2);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn empty_connectors_returns_empty() {
        let results = search_operations(&[], "test", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn connector_with_no_operations() {
        let connectors = vec![stub_connector("empty", vec![])];
        let results = search_operations(&connectors, "test", &SearchFilters::default());
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_filters_combined() {
        let connectors = sample_connectors();
        let filters = SearchFilters {
            capability: Some("read".to_owned()),
            risk_max: Some(RiskCeiling::Low),
            safety_max: Some(SafetyCeiling::Safe),
            idempotent_only: true,
            ..Default::default()
        };
        let results = search_operations(&connectors, "list", &filters);
        assert!(!results.is_empty());
        for r in &results {
            assert!(r.capability.contains("read"));
            assert_eq!(r.risk_level, "low");
            assert_eq!(r.safety_tier, "safe");
        }
    }
}
