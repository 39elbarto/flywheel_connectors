//! Identifier discovery and disambiguation helpers for `fwc`.
//!
//! Agents often know what action they want but lack the exact project,
//! workspace, channel, page, issue, or account identifier needed to form a
//! valid request. This module defines the UX contract for how `fwc` helps
//! agents discover, narrow, and disambiguate resource identifiers before
//! write operations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ── Lookup request ──────────────────────────────────────────────────────

/// A request to look up a resource identifier by human-readable name.
///
/// Used when an agent says something like "the Notion page named Roadmap"
/// or "the GitHub repo called fwc".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupRequest {
    /// Connector to search within (e.g. `"notion"`, `"github"`).
    pub connector: String,
    /// Resource type hint (e.g. `"page"`, `"repo"`, `"channel"`, `"issue"`).
    pub resource_type: Option<String>,
    /// Human-readable query (e.g. `"Roadmap"`, `"fwc"`, `"#general"`).
    pub query: String,
    /// Optional operation hint to narrow scope (e.g. `"pages.update"`).
    pub operation_hint: Option<String>,
    /// Maximum number of candidates to return.
    pub limit: usize,
}

impl LookupRequest {
    /// Create a basic lookup request.
    pub fn new(connector: impl Into<String>, query: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            resource_type: None,
            query: query.into(),
            operation_hint: None,
            limit: 5,
        }
    }

    /// Narrow the lookup to a specific resource type.
    pub fn with_resource_type(mut self, resource_type: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self
    }

    /// Narrow the lookup to support a specific operation.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation_hint = Some(operation.into());
        self
    }
}

// ── Lookup response ─────────────────────────────────────────────────────

/// Result of an identifier lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LookupResult {
    /// Original query.
    pub query: String,
    /// Connector searched.
    pub connector: String,
    /// Resolution outcome.
    pub outcome: LookupOutcome,
}

/// Outcome of a lookup — exactly one match, multiple candidates, or none.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LookupOutcome {
    /// Exactly one match found — agent can proceed.
    Resolved {
        /// The resolved candidate.
        candidate: ResourceCandidate,
        /// Suggested next command using this identifier.
        next_command: String,
    },
    /// Multiple matches found — agent must disambiguate.
    Ambiguous {
        /// Ranked candidates, most likely first.
        candidates: Vec<ResourceCandidate>,
        /// Question to present to the agent.
        prompt: DisambiguationPrompt,
    },
    /// No matches found.
    NotFound {
        /// Suggestions for what to try next.
        suggestions: Vec<String>,
    },
    /// Lookup not supported for this connector/resource type.
    Unsupported {
        /// Why lookup isn't supported.
        reason: String,
    },
}

/// A candidate resource returned from lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceCandidate {
    /// The machine identifier needed for the operation (e.g. UUID, slug, numeric ID).
    pub id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Resource type (e.g. `"page"`, `"repo"`, `"channel"`).
    pub resource_type: String,
    /// Optional extra context to help disambiguation (e.g. workspace name, parent).
    pub context: BTreeMap<String, String>,
    /// Match confidence: `exact`, `prefix`, `fuzzy`, `partial`.
    pub match_quality: MatchQuality,
}

/// How well a candidate matches the query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchQuality {
    /// Exact name match (case-insensitive).
    Exact,
    /// Name starts with query.
    Prefix,
    /// Name contains query as a substring.
    Partial,
    /// Fuzzy/edit-distance match.
    Fuzzy,
}

// ── Disambiguation ──────────────────────────────────────────────────────

/// A prompt to help an agent choose between multiple candidates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisambiguationPrompt {
    /// The binding key to set (e.g. `"page_id"`, `"repo"`).
    pub binding_key: String,
    /// Human-readable question.
    pub question: String,
    /// Compact options the agent can choose from.
    pub options: Vec<DisambiguationOption>,
    /// Suggested fwc commands for each option.
    pub next_commands: Vec<String>,
}

/// One option in a disambiguation prompt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisambiguationOption {
    /// Value to bind (the identifier).
    pub value: String,
    /// Display label.
    pub label: String,
    /// Short context (e.g. `"in workspace Engineering"`).
    pub context: Option<String>,
}

// ── Connector resource model ────────────────────────────────────────────

/// Metadata about what resource types a connector exposes for lookup.
///
/// Connectors that support identifier discovery declare their resource
/// types here so `fwc` knows what kinds of lookups are possible.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorResourceModel {
    /// Connector id.
    pub connector: String,
    /// Resource types available for lookup.
    pub resource_types: Vec<ResourceTypeDescriptor>,
}

/// Descriptor for a single resource type that supports name-based lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceTypeDescriptor {
    /// Resource type name (e.g. `"page"`, `"issue"`, `"channel"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The connector operation that performs lookup/search for this type.
    pub lookup_operation: String,
    /// The field in the lookup result that contains the identifier.
    pub id_field: String,
    /// The field that contains the display name.
    pub name_field: String,
    /// Operations that consume this resource type as input.
    pub consumed_by: Vec<String>,
    /// Example queries.
    pub example_queries: Vec<String>,
}

// ── Well-known resource types ───────────────────────────────────────────

/// Well-known resource type families across connector ecosystems.
///
/// These are the common identifier shapes that agents encounter repeatedly.
/// Connectors map their domain-specific types to these families for
/// consistent UX.
pub const RESOURCE_FAMILIES: &[ResourceFamily] = &[
    ResourceFamily {
        family: "project",
        connectors: &["github", "gitlab", "jira", "linear", "asana", "clickup"],
        typical_id_shape: "slug or UUID",
        discovery_hint: "list/search projects or repositories",
    },
    ResourceFamily {
        family: "issue",
        connectors: &["github", "jira", "linear", "asana", "clickup"],
        typical_id_shape: "numeric ID or key (e.g. PROJ-123)",
        discovery_hint: "search issues by title or key",
    },
    ResourceFamily {
        family: "page",
        connectors: &["notion", "confluence"],
        typical_id_shape: "UUID",
        discovery_hint: "search pages by title",
    },
    ResourceFamily {
        family: "channel",
        connectors: &["slack", "discord", "telegram"],
        typical_id_shape: "channel ID or name with #prefix",
        discovery_hint: "list channels or search by name",
    },
    ResourceFamily {
        family: "document",
        connectors: &[
            "google-docs",
            "google-sheets",
            "google-drive",
            "dropbox",
            "box",
        ],
        typical_id_shape: "file ID or path",
        discovery_hint: "search files by name",
    },
    ResourceFamily {
        family: "record",
        connectors: &["airtable", "salesforce", "hubspot", "bigquery", "snowflake"],
        typical_id_shape: "record ID or external key",
        discovery_hint: "query records by field value",
    },
    ResourceFamily {
        family: "contact",
        connectors: &["hubspot", "salesforce", "gmail", "google-contacts"],
        typical_id_shape: "email address or contact ID",
        discovery_hint: "search contacts by name or email",
    },
    ResourceFamily {
        family: "workspace",
        connectors: &["notion", "slack", "figma", "airtable"],
        typical_id_shape: "workspace ID or slug",
        discovery_hint: "list workspaces the connector has access to",
    },
];

/// A family of resource types that share similar identifier patterns.
pub struct ResourceFamily {
    /// Family name.
    pub family: &'static str,
    /// Connectors that have this resource type.
    pub connectors: &'static [&'static str],
    /// Typical shape of the identifier.
    pub typical_id_shape: &'static str,
    /// How to discover identifiers for this family.
    pub discovery_hint: &'static str,
}

// ── Resolution helpers ──────────────────────────────────────────────────

/// Resolve a lookup result into a concrete identifier or a disambiguation prompt.
///
/// Given candidates from a connector search, produce the appropriate outcome.
pub fn resolve_candidates(
    query: &str,
    binding_key: &str,
    connector: &str,
    candidates: Vec<ResourceCandidate>,
    next_command_template: &str,
) -> LookupResult {
    let outcome = match candidates.len() {
        0 => LookupOutcome::NotFound {
            suggestions: vec![
                format!("Try a broader search query instead of \"{query}\""),
                format!("Run `fwc search {connector}` to see available resources"),
                format!("Check that you have access to the {connector} workspace"),
            ],
        },
        1 => {
            let candidate = candidates.into_iter().next().expect("checked len == 1");
            let next_command = next_command_template.replace("{id}", &candidate.id);
            LookupOutcome::Resolved {
                candidate,
                next_command,
            }
        }
        _ => {
            let options: Vec<DisambiguationOption> = candidates
                .iter()
                .map(|c| DisambiguationOption {
                    value: c.id.clone(),
                    label: c.display_name.clone(),
                    context: c.context.get("parent").cloned(),
                })
                .collect();

            let next_commands: Vec<String> = candidates
                .iter()
                .map(|c| next_command_template.replace("{id}", &c.id))
                .collect();

            let prompt = DisambiguationPrompt {
                binding_key: binding_key.to_owned(),
                question: format!("Multiple {connector} resources match \"{query}\". Which one?"),
                options,
                next_commands,
            };

            LookupOutcome::Ambiguous { candidates, prompt }
        }
    };

    LookupResult {
        query: query.to_owned(),
        connector: connector.to_owned(),
        outcome,
    }
}

/// Find the resource family for a connector and resource type.
pub fn find_resource_family(
    connector: &str,
    resource_type: &str,
) -> Option<&'static ResourceFamily> {
    RESOURCE_FAMILIES
        .iter()
        .find(|f| f.family == resource_type && f.connectors.iter().any(|c| connector.contains(c)))
}

/// Suggest discovery commands for a connector that needs identifier resolution.
pub fn suggest_discovery_commands(connector: &str, resource_type: Option<&str>) -> Vec<String> {
    let mut suggestions = Vec::new();

    if let Some(rt) = resource_type {
        if let Some(family) = find_resource_family(connector, rt) {
            suggestions.push(format!("# {}: {}", family.family, family.discovery_hint));
        }
        suggestions.push(format!("fwc search {connector} --type {rt}"));
    }

    suggestions.push(format!("fwc ops {connector}"));
    suggestions.push(format!("fwc show {connector}"));
    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LookupRequest ───────────────────────────────────────────────────

    #[test]
    fn lookup_request_builder() {
        let req = LookupRequest::new("notion", "Roadmap")
            .with_resource_type("page")
            .with_operation("pages.update");

        assert_eq!(req.connector, "notion");
        assert_eq!(req.query, "Roadmap");
        assert_eq!(req.resource_type.as_deref(), Some("page"));
        assert_eq!(req.operation_hint.as_deref(), Some("pages.update"));
        assert_eq!(req.limit, 5);
    }

    #[test]
    fn lookup_request_serde_round_trip() {
        let req = LookupRequest::new("github", "fwc").with_resource_type("repo");
        let json = serde_json::to_string(&req).unwrap();
        let back: LookupRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector, "github");
        assert_eq!(back.query, "fwc");
    }

    // ── MatchQuality ────────────────────────────────────────────────────

    #[test]
    fn match_quality_ordering() {
        assert!(MatchQuality::Exact < MatchQuality::Prefix);
        assert!(MatchQuality::Prefix < MatchQuality::Partial);
        assert!(MatchQuality::Partial < MatchQuality::Fuzzy);
    }

    #[test]
    fn match_quality_serde() {
        let json = serde_json::to_string(&MatchQuality::Exact).unwrap();
        assert_eq!(json, "\"exact\"");
        let back: MatchQuality = serde_json::from_str("\"fuzzy\"").unwrap();
        assert_eq!(back, MatchQuality::Fuzzy);
    }

    // ── ResourceCandidate ───────────────────────────────────────────────

    #[test]
    fn resource_candidate_serde() {
        let candidate = ResourceCandidate {
            id: "abc-123".to_owned(),
            display_name: "Roadmap".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::from([("workspace".to_owned(), "Engineering".to_owned())]),
            match_quality: MatchQuality::Exact,
        };

        let json = serde_json::to_value(&candidate).unwrap();
        assert_eq!(json["id"], "abc-123");
        assert_eq!(json["display_name"], "Roadmap");
        assert_eq!(json["match_quality"], "exact");
        assert_eq!(json["context"]["workspace"], "Engineering");
    }

    // ── resolve_candidates ──────────────────────────────────────────────

    #[test]
    fn resolve_single_match() {
        let candidates = vec![ResourceCandidate {
            id: "page-001".to_owned(),
            display_name: "Roadmap".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        }];

        let result = resolve_candidates(
            "Roadmap",
            "page_id",
            "notion",
            candidates,
            "fwc invoke notion pages.update --page_id={id}",
        );

        assert_eq!(result.query, "Roadmap");
        match &result.outcome {
            LookupOutcome::Resolved {
                candidate,
                next_command,
            } => {
                assert_eq!(candidate.id, "page-001");
                assert!(next_command.contains("page-001"));
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_no_matches() {
        let result = resolve_candidates(
            "NonExistent",
            "page_id",
            "notion",
            vec![],
            "fwc invoke notion pages.update --page_id={id}",
        );

        match &result.outcome {
            LookupOutcome::NotFound { suggestions } => {
                assert!(!suggestions.is_empty());
                assert!(suggestions[0].contains("NonExistent"));
            }
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn resolve_multiple_matches_produces_disambiguation() {
        let candidates = vec![
            ResourceCandidate {
                id: "page-001".to_owned(),
                display_name: "Roadmap Q1".to_owned(),
                resource_type: "page".to_owned(),
                context: BTreeMap::from([("parent".to_owned(), "Engineering".to_owned())]),
                match_quality: MatchQuality::Prefix,
            },
            ResourceCandidate {
                id: "page-002".to_owned(),
                display_name: "Roadmap Q2".to_owned(),
                resource_type: "page".to_owned(),
                context: BTreeMap::from([("parent".to_owned(), "Product".to_owned())]),
                match_quality: MatchQuality::Prefix,
            },
        ];

        let result = resolve_candidates(
            "Roadmap",
            "page_id",
            "notion",
            candidates,
            "fwc invoke notion pages.update --page_id={id}",
        );

        match &result.outcome {
            LookupOutcome::Ambiguous { candidates, prompt } => {
                assert_eq!(candidates.len(), 2);
                assert_eq!(prompt.binding_key, "page_id");
                assert!(prompt.question.contains("Roadmap"));
                assert_eq!(prompt.options.len(), 2);
                assert_eq!(prompt.options[0].label, "Roadmap Q1");
                assert_eq!(prompt.options[0].context.as_deref(), Some("Engineering"));
                assert_eq!(prompt.next_commands.len(), 2);
            }
            _ => panic!("expected Ambiguous"),
        }
    }

    // ── LookupOutcome serde ─────────────────────────────────────────────

    #[test]
    fn lookup_outcome_resolved_serde() {
        let outcome = LookupOutcome::Resolved {
            candidate: ResourceCandidate {
                id: "ch-001".to_owned(),
                display_name: "#general".to_owned(),
                resource_type: "channel".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Exact,
            },
            next_command: "fwc invoke slack messages.send --channel=ch-001".to_owned(),
        };

        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["type"], "resolved");
        assert_eq!(json["candidate"]["id"], "ch-001");
    }

    #[test]
    fn lookup_outcome_not_found_serde() {
        let outcome = LookupOutcome::NotFound {
            suggestions: vec!["try broader search".to_owned()],
        };

        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["type"], "not-found");
    }

    #[test]
    fn lookup_outcome_unsupported_serde() {
        let outcome = LookupOutcome::Unsupported {
            reason: "This connector requires direct ID input".to_owned(),
        };

        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["type"], "unsupported");
    }

    // ── DisambiguationPrompt ────────────────────────────────────────────

    #[test]
    fn disambiguation_prompt_serde() {
        let prompt = DisambiguationPrompt {
            binding_key: "repo".to_owned(),
            question: "Which repository?".to_owned(),
            options: vec![
                DisambiguationOption {
                    value: "owner/repo-a".to_owned(),
                    label: "repo-a".to_owned(),
                    context: Some("owner org".to_owned()),
                },
                DisambiguationOption {
                    value: "owner/repo-b".to_owned(),
                    label: "repo-b".to_owned(),
                    context: None,
                },
            ],
            next_commands: vec![
                "fwc invoke github issues.list --repo=owner/repo-a".to_owned(),
                "fwc invoke github issues.list --repo=owner/repo-b".to_owned(),
            ],
        };

        let json = serde_json::to_value(&prompt).unwrap();
        assert_eq!(json["binding_key"], "repo");
        assert_eq!(json["options"].as_array().unwrap().len(), 2);
    }

    // ── ConnectorResourceModel ──────────────────────────────────────────

    #[test]
    fn connector_resource_model_serde() {
        let model = ConnectorResourceModel {
            connector: "notion".to_owned(),
            resource_types: vec![ResourceTypeDescriptor {
                name: "page".to_owned(),
                description: "Notion page".to_owned(),
                lookup_operation: "pages.search".to_owned(),
                id_field: "id".to_owned(),
                name_field: "title".to_owned(),
                consumed_by: vec!["pages.update".to_owned(), "pages.append".to_owned()],
                example_queries: vec!["Roadmap".to_owned(), "Sprint Planning".to_owned()],
            }],
        };

        let json = serde_json::to_value(&model).unwrap();
        assert_eq!(json["connector"], "notion");
        assert_eq!(json["resource_types"][0]["name"], "page");
        assert_eq!(
            json["resource_types"][0]["consumed_by"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    // ── RESOURCE_FAMILIES ───────────────────────────────────────────────

    #[test]
    fn resource_families_are_populated() {
        assert!(RESOURCE_FAMILIES.len() >= 8);
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "project"));
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "issue"));
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "page"));
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "channel"));
    }

    #[test]
    fn resource_families_have_connectors() {
        for family in RESOURCE_FAMILIES {
            assert!(
                !family.connectors.is_empty(),
                "family {} has no connectors",
                family.family
            );
        }
    }

    // ── find_resource_family ────────────────────────────────────────────

    #[test]
    fn find_known_family() {
        let family = find_resource_family("notion", "page");
        assert!(family.is_some());
        assert_eq!(family.unwrap().family, "page");
    }

    #[test]
    fn find_unknown_family() {
        let family = find_resource_family("notion", "unknown");
        assert!(family.is_none());
    }

    #[test]
    fn find_family_by_connector_substring() {
        let family = find_resource_family("google-docs", "document");
        assert!(family.is_some());
    }

    // ── suggest_discovery_commands ───────────────────────────────────────

    #[test]
    fn suggest_commands_with_resource_type() {
        let cmds = suggest_discovery_commands("notion", Some("page"));
        assert!(cmds.iter().any(|c| c.contains("search")));
        assert!(cmds.iter().any(|c| c.contains("ops")));
    }

    #[test]
    fn suggest_commands_without_resource_type() {
        let cmds = suggest_discovery_commands("github", None);
        assert!(cmds.iter().any(|c| c.contains("ops")));
        assert!(cmds.iter().any(|c| c.contains("show")));
    }

    // ── LookupResult full serde ─────────────────────────────────────────

    #[test]
    fn lookup_result_full_serde_round_trip() {
        let result = LookupResult {
            query: "Roadmap".to_owned(),
            connector: "notion".to_owned(),
            outcome: LookupOutcome::Resolved {
                candidate: ResourceCandidate {
                    id: "page-001".to_owned(),
                    display_name: "Roadmap".to_owned(),
                    resource_type: "page".to_owned(),
                    context: BTreeMap::new(),
                    match_quality: MatchQuality::Exact,
                },
                next_command: "fwc invoke notion pages.update --page_id=page-001".to_owned(),
            },
        };

        let json = serde_json::to_string_pretty(&result).unwrap();
        let back: LookupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.query, "Roadmap");
        assert_eq!(back.connector, "notion");
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn resolve_with_empty_query() {
        let result = resolve_candidates(
            "",
            "page_id",
            "notion",
            vec![],
            "fwc invoke notion pages.update --page_id={id}",
        );
        matches!(result.outcome, LookupOutcome::NotFound { .. });
    }

    #[test]
    fn resource_candidate_with_rich_context() {
        let candidate = ResourceCandidate {
            id: "ws-001/db-002/rec-003".to_owned(),
            display_name: "Customer Record #42".to_owned(),
            resource_type: "record".to_owned(),
            context: BTreeMap::from([
                ("workspace".to_owned(), "Sales".to_owned()),
                ("database".to_owned(), "CRM".to_owned()),
                ("parent".to_owned(), "Accounts".to_owned()),
            ]),
            match_quality: MatchQuality::Partial,
        };

        assert_eq!(candidate.context.len(), 3);
        assert_eq!(candidate.context["database"], "CRM");
    }

    #[test]
    fn disambiguation_option_without_context() {
        let opt = DisambiguationOption {
            value: "id-1".to_owned(),
            label: "Item One".to_owned(),
            context: None,
        };
        let json = serde_json::to_value(&opt).unwrap();
        assert!(json["context"].is_null());
    }
}
