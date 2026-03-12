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

    // ── Additional LookupRequest tests ─────────────────────────────

    #[test]
    fn lookup_request_defaults() {
        let req = LookupRequest::new("slack", "general");
        assert_eq!(req.connector, "slack");
        assert_eq!(req.query, "general");
        assert!(req.resource_type.is_none());
        assert!(req.operation_hint.is_none());
        assert_eq!(req.limit, 5);
    }

    #[test]
    fn lookup_request_chained_builders() {
        let req = LookupRequest::new("github", "fwc")
            .with_resource_type("repo")
            .with_operation("repos.get");
        assert_eq!(req.resource_type.as_deref(), Some("repo"));
        assert_eq!(req.operation_hint.as_deref(), Some("repos.get"));
    }

    #[test]
    fn lookup_request_clone() {
        let req = LookupRequest::new("notion", "Roadmap").with_resource_type("page");
        let cloned = req.clone();
        assert_eq!(cloned.connector, req.connector);
        assert_eq!(cloned.query, req.query);
        assert_eq!(cloned.resource_type, req.resource_type);
    }

    #[test]
    fn lookup_request_debug() {
        let req = LookupRequest::new("slack", "general");
        let debug = format!("{req:?}");
        assert!(debug.contains("slack"));
        assert!(debug.contains("general"));
    }

    #[test]
    fn lookup_request_serde_all_fields() {
        let req = LookupRequest::new("jira", "PROJ-123")
            .with_resource_type("issue")
            .with_operation("issues.get");
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["connector"], "jira");
        assert_eq!(json["query"], "PROJ-123");
        assert_eq!(json["resource_type"], "issue");
        assert_eq!(json["operation_hint"], "issues.get");
        assert_eq!(json["limit"], 5);
    }

    // ── Additional MatchQuality tests ──────────────────────────────

    #[test]
    fn match_quality_all_variants_serde() {
        for (variant, expected) in [
            (MatchQuality::Exact, "\"exact\""),
            (MatchQuality::Prefix, "\"prefix\""),
            (MatchQuality::Partial, "\"partial\""),
            (MatchQuality::Fuzzy, "\"fuzzy\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: MatchQuality = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn match_quality_equality() {
        assert_eq!(MatchQuality::Exact, MatchQuality::Exact);
        assert_ne!(MatchQuality::Exact, MatchQuality::Fuzzy);
    }

    #[test]
    fn match_quality_clone() {
        let q = MatchQuality::Prefix;
        let cloned = q;
        assert_eq!(q, cloned);
    }

    #[test]
    fn match_quality_debug() {
        let debug = format!("{:?}", MatchQuality::Partial);
        assert_eq!(debug, "Partial");
    }

    // ── Additional ResourceCandidate tests ─────────────────────────

    #[test]
    fn resource_candidate_empty_context() {
        let candidate = ResourceCandidate {
            id: "id-1".to_owned(),
            display_name: "Item".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        };
        assert!(candidate.context.is_empty());
    }

    #[test]
    fn resource_candidate_clone() {
        let candidate = ResourceCandidate {
            id: "id-1".to_owned(),
            display_name: "Item".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        };
        let cloned = candidate.clone();
        assert_eq!(cloned.id, candidate.id);
        assert_eq!(cloned.match_quality, candidate.match_quality);
    }

    #[test]
    fn resource_candidate_roundtrip() {
        let candidate = ResourceCandidate {
            id: "uuid-123".to_owned(),
            display_name: "My Page".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::from([("parent".to_owned(), "Root".to_owned())]),
            match_quality: MatchQuality::Prefix,
        };
        let json = serde_json::to_string(&candidate).unwrap();
        let back: ResourceCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "uuid-123");
        assert_eq!(back.display_name, "My Page");
        assert_eq!(back.match_quality, MatchQuality::Prefix);
        assert_eq!(back.context["parent"], "Root");
    }

    // ── Additional resolve_candidates tests ────────────────────────

    #[test]
    fn resolve_single_match_next_command_substitution() {
        let candidates = vec![ResourceCandidate {
            id: "ch-42".to_owned(),
            display_name: "#general".to_owned(),
            resource_type: "channel".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        }];
        let result = resolve_candidates(
            "general",
            "channel_id",
            "slack",
            candidates,
            "fwc invoke slack messages.send --channel={id}",
        );
        match &result.outcome {
            LookupOutcome::Resolved { next_command, .. } => {
                assert_eq!(
                    next_command,
                    "fwc invoke slack messages.send --channel=ch-42"
                );
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_not_found_suggestions_content() {
        let result = resolve_candidates(
            "missing",
            "page_id",
            "notion",
            vec![],
            "fwc invoke notion pages.update --page_id={id}",
        );
        match &result.outcome {
            LookupOutcome::NotFound { suggestions } => {
                assert_eq!(suggestions.len(), 3);
                assert!(suggestions[0].contains("missing"));
                assert!(suggestions[1].contains("notion"));
                assert!(suggestions[2].contains("access"));
            }
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn resolve_ambiguous_prompt_content() {
        let candidates = vec![
            ResourceCandidate {
                id: "1".to_owned(),
                display_name: "A".to_owned(),
                resource_type: "repo".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Partial,
            },
            ResourceCandidate {
                id: "2".to_owned(),
                display_name: "B".to_owned(),
                resource_type: "repo".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Fuzzy,
            },
            ResourceCandidate {
                id: "3".to_owned(),
                display_name: "C".to_owned(),
                resource_type: "repo".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Fuzzy,
            },
        ];
        let result = resolve_candidates(
            "test",
            "repo_id",
            "github",
            candidates,
            "fwc invoke github repos.get --repo={id}",
        );
        match &result.outcome {
            LookupOutcome::Ambiguous { candidates, prompt } => {
                assert_eq!(candidates.len(), 3);
                assert_eq!(prompt.binding_key, "repo_id");
                assert!(prompt.question.contains("github"));
                assert!(prompt.question.contains("test"));
                assert_eq!(prompt.options.len(), 3);
                assert_eq!(prompt.next_commands.len(), 3);
                assert!(prompt.next_commands[0].contains("repo=1"));
                assert!(prompt.next_commands[2].contains("repo=3"));
            }
            _ => panic!("expected Ambiguous"),
        }
    }

    #[test]
    fn resolve_candidates_result_fields() {
        let result = resolve_candidates("q", "key", "conn", vec![], "cmd {id}");
        assert_eq!(result.query, "q");
        assert_eq!(result.connector, "conn");
    }

    // ── Additional LookupOutcome serde tests ───────────────────────

    #[test]
    fn lookup_outcome_ambiguous_serde() {
        let outcome = LookupOutcome::Ambiguous {
            candidates: vec![ResourceCandidate {
                id: "1".to_owned(),
                display_name: "A".to_owned(),
                resource_type: "page".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Fuzzy,
            }],
            prompt: DisambiguationPrompt {
                binding_key: "page_id".to_owned(),
                question: "Which one?".to_owned(),
                options: vec![],
                next_commands: vec![],
            },
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["type"], "ambiguous");
        assert!(json["candidates"].is_array());
        assert!(json["prompt"].is_object());
    }

    #[test]
    fn lookup_outcome_all_variants_tagged() {
        let resolved = serde_json::to_value(&LookupOutcome::Resolved {
            candidate: ResourceCandidate {
                id: "x".to_owned(),
                display_name: "X".to_owned(),
                resource_type: "t".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Exact,
            },
            next_command: "cmd".to_owned(),
        })
        .unwrap();
        assert_eq!(resolved["type"], "resolved");

        let not_found = serde_json::to_value(&LookupOutcome::NotFound {
            suggestions: vec![],
        })
        .unwrap();
        assert_eq!(not_found["type"], "not-found");

        let unsupported = serde_json::to_value(&LookupOutcome::Unsupported {
            reason: "r".to_owned(),
        })
        .unwrap();
        assert_eq!(unsupported["type"], "unsupported");
    }

    // ── Additional LookupResult tests ──────────────────────────────

    #[test]
    fn lookup_result_not_found_roundtrip() {
        let result = LookupResult {
            query: "missing".to_owned(),
            connector: "github".to_owned(),
            outcome: LookupOutcome::NotFound {
                suggestions: vec!["try again".to_owned()],
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LookupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.query, "missing");
        match back.outcome {
            LookupOutcome::NotFound { suggestions } => assert_eq!(suggestions.len(), 1),
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn lookup_result_unsupported_roundtrip() {
        let result = LookupResult {
            query: "test".to_owned(),
            connector: "custom".to_owned(),
            outcome: LookupOutcome::Unsupported {
                reason: "not implemented".to_owned(),
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LookupResult = serde_json::from_str(&json).unwrap();
        match back.outcome {
            LookupOutcome::Unsupported { reason } => assert_eq!(reason, "not implemented"),
            _ => panic!("expected Unsupported"),
        }
    }

    // ── Additional DisambiguationPrompt tests ──────────────────────

    #[test]
    fn disambiguation_prompt_roundtrip() {
        let prompt = DisambiguationPrompt {
            binding_key: "id".to_owned(),
            question: "Which?".to_owned(),
            options: vec![DisambiguationOption {
                value: "v1".to_owned(),
                label: "L1".to_owned(),
                context: Some("ctx".to_owned()),
            }],
            next_commands: vec!["cmd1".to_owned()],
        };
        let json = serde_json::to_string(&prompt).unwrap();
        let back: DisambiguationPrompt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.binding_key, "id");
        assert_eq!(back.options.len(), 1);
        assert_eq!(back.next_commands.len(), 1);
    }

    #[test]
    fn disambiguation_option_with_context_roundtrip() {
        let opt = DisambiguationOption {
            value: "val".to_owned(),
            label: "Lab".to_owned(),
            context: Some("in workspace X".to_owned()),
        };
        let json = serde_json::to_string(&opt).unwrap();
        let back: DisambiguationOption = serde_json::from_str(&json).unwrap();
        assert_eq!(back.context.as_deref(), Some("in workspace X"));
    }

    // ── Additional ConnectorResourceModel tests ────────────────────

    #[test]
    fn connector_resource_model_roundtrip() {
        let model = ConnectorResourceModel {
            connector: "github".to_owned(),
            resource_types: vec![ResourceTypeDescriptor {
                name: "repo".to_owned(),
                description: "GitHub repository".to_owned(),
                lookup_operation: "repos.search".to_owned(),
                id_field: "full_name".to_owned(),
                name_field: "name".to_owned(),
                consumed_by: vec!["repos.get".to_owned()],
                example_queries: vec!["fwc".to_owned()],
            }],
        };
        let json = serde_json::to_string(&model).unwrap();
        let back: ConnectorResourceModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector, "github");
        assert_eq!(back.resource_types.len(), 1);
        assert_eq!(back.resource_types[0].name, "repo");
    }

    #[test]
    fn connector_resource_model_multiple_types() {
        let model = ConnectorResourceModel {
            connector: "github".to_owned(),
            resource_types: vec![
                ResourceTypeDescriptor {
                    name: "repo".to_owned(),
                    description: "Repository".to_owned(),
                    lookup_operation: "repos.search".to_owned(),
                    id_field: "full_name".to_owned(),
                    name_field: "name".to_owned(),
                    consumed_by: vec!["repos.get".to_owned()],
                    example_queries: vec!["fwc".to_owned()],
                },
                ResourceTypeDescriptor {
                    name: "issue".to_owned(),
                    description: "Issue".to_owned(),
                    lookup_operation: "issues.search".to_owned(),
                    id_field: "number".to_owned(),
                    name_field: "title".to_owned(),
                    consumed_by: vec!["issues.get".to_owned(), "issues.update".to_owned()],
                    example_queries: vec!["bug".to_owned(), "feature".to_owned()],
                },
            ],
        };
        assert_eq!(model.resource_types.len(), 2);
        assert_eq!(model.resource_types[1].consumed_by.len(), 2);
        assert_eq!(model.resource_types[1].example_queries.len(), 2);
    }

    // ── Additional RESOURCE_FAMILIES tests ─────────────────────────

    #[test]
    fn resource_families_all_have_discovery_hints() {
        for family in RESOURCE_FAMILIES {
            assert!(
                !family.discovery_hint.is_empty(),
                "family {} has no discovery hint",
                family.family
            );
        }
    }

    #[test]
    fn resource_families_all_have_id_shapes() {
        for family in RESOURCE_FAMILIES {
            assert!(
                !family.typical_id_shape.is_empty(),
                "family {} has no id shape",
                family.family
            );
        }
    }

    #[test]
    fn resource_families_contain_document() {
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "document"));
    }

    #[test]
    fn resource_families_contain_record() {
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "record"));
    }

    #[test]
    fn resource_families_contain_contact() {
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "contact"));
    }

    #[test]
    fn resource_families_contain_workspace() {
        assert!(RESOURCE_FAMILIES.iter().any(|f| f.family == "workspace"));
    }

    #[test]
    fn resource_families_unique_names() {
        let mut names: Vec<&str> = RESOURCE_FAMILIES.iter().map(|f| f.family).collect();
        let original_len = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), original_len, "duplicate family names found");
    }

    // ── Additional find_resource_family tests ──────────────────────

    #[test]
    fn find_family_github_project() {
        let f = find_resource_family("github", "project").unwrap();
        assert!(f.connectors.contains(&"github"));
    }

    #[test]
    fn find_family_slack_channel() {
        let f = find_resource_family("slack", "channel").unwrap();
        assert_eq!(f.family, "channel");
    }

    #[test]
    fn find_family_unknown_connector() {
        assert!(find_resource_family("unknown-connector", "project").is_none());
    }

    #[test]
    fn find_family_salesforce_record() {
        let f = find_resource_family("salesforce", "record").unwrap();
        assert_eq!(f.family, "record");
    }

    #[test]
    fn find_family_hubspot_contact() {
        let f = find_resource_family("hubspot", "contact").unwrap();
        assert_eq!(f.family, "contact");
    }

    // ── Additional suggest_discovery_commands tests ─────────────────

    #[test]
    fn suggest_commands_include_show() {
        let cmds = suggest_discovery_commands("slack", None);
        assert!(cmds.iter().any(|c| c.contains("show")));
    }

    #[test]
    fn suggest_commands_known_resource_type_includes_hint() {
        let cmds = suggest_discovery_commands("github", Some("project"));
        assert!(cmds.iter().any(|c| c.contains("list/search")));
    }

    #[test]
    fn suggest_commands_unknown_resource_type() {
        let cmds = suggest_discovery_commands("github", Some("unknown_type"));
        // Should still include ops and search commands even if family not found
        assert!(cmds.iter().any(|c| c.contains("ops")));
        assert!(cmds.iter().any(|c| c.contains("search")));
    }

    #[test]
    fn suggest_commands_length_with_type() {
        let cmds = suggest_discovery_commands("notion", Some("page"));
        // Should have: hint comment, search command, ops command, show command
        assert!(cmds.len() >= 3);
    }

    #[test]
    fn suggest_commands_length_without_type() {
        let cmds = suggest_discovery_commands("notion", None);
        // Should have: ops and show commands
        assert_eq!(cmds.len(), 2);
    }

    // ── ResourceTypeDescriptor edge cases ──────────────────────────

    #[test]
    fn resource_type_descriptor_empty_consumed_by() {
        let desc = ResourceTypeDescriptor {
            name: "webhook".to_owned(),
            description: "Webhook endpoint".to_owned(),
            lookup_operation: "webhooks.list".to_owned(),
            id_field: "id".to_owned(),
            name_field: "url".to_owned(),
            consumed_by: vec![],
            example_queries: vec![],
        };
        let json = serde_json::to_value(&desc).unwrap();
        assert!(json["consumed_by"].as_array().unwrap().is_empty());
        assert!(json["example_queries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn resource_type_descriptor_roundtrip() {
        let desc = ResourceTypeDescriptor {
            name: "channel".to_owned(),
            description: "Slack channel".to_owned(),
            lookup_operation: "channels.list".to_owned(),
            id_field: "id".to_owned(),
            name_field: "name".to_owned(),
            consumed_by: vec!["messages.send".to_owned()],
            example_queries: vec!["#general".to_owned(), "#random".to_owned()],
        };
        let json = serde_json::to_string(&desc).unwrap();
        let back: ResourceTypeDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "channel");
        assert_eq!(back.example_queries.len(), 2);
    }

    // ── LookupRequest additional edge cases ─────────────────────────

    #[test]
    fn lookup_request_with_empty_connector() {
        let req = LookupRequest::new("", "query");
        assert!(req.connector.is_empty());
        assert_eq!(req.query, "query");
    }

    #[test]
    fn lookup_request_with_empty_query() {
        let req = LookupRequest::new("github", "");
        assert!(req.query.is_empty());
        assert_eq!(req.connector, "github");
    }

    #[test]
    fn lookup_request_with_unicode_query() {
        let req = LookupRequest::new("notion", "\u{1f4d6} Roadmap");
        assert_eq!(req.query, "\u{1f4d6} Roadmap");
    }

    #[test]
    fn lookup_request_with_special_chars() {
        let req = LookupRequest::new("slack", "#general & <special>");
        assert_eq!(req.query, "#general & <special>");
    }

    #[test]
    fn lookup_request_deserialize_from_json() {
        let json = r#"{
            "connector": "jira",
            "resource_type": null,
            "query": "BUG-42",
            "operation_hint": null,
            "limit": 10
        }"#;
        let req: LookupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.connector, "jira");
        assert_eq!(req.query, "BUG-42");
        assert!(req.resource_type.is_none());
        assert_eq!(req.limit, 10);
    }

    #[test]
    fn lookup_request_deserialize_with_all_fields() {
        let json = r#"{
            "connector": "github",
            "resource_type": "repo",
            "query": "fwc",
            "operation_hint": "repos.get",
            "limit": 3
        }"#;
        let req: LookupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.resource_type.as_deref(), Some("repo"));
        assert_eq!(req.operation_hint.as_deref(), Some("repos.get"));
        assert_eq!(req.limit, 3);
    }

    #[test]
    fn lookup_request_with_resource_type_replaces() {
        let req = LookupRequest::new("github", "test")
            .with_resource_type("repo")
            .with_resource_type("issue");
        assert_eq!(req.resource_type.as_deref(), Some("issue"));
    }

    #[test]
    fn lookup_request_with_operation_replaces() {
        let req = LookupRequest::new("github", "test")
            .with_operation("repos.get")
            .with_operation("issues.list");
        assert_eq!(req.operation_hint.as_deref(), Some("issues.list"));
    }

    // ── MatchQuality additional tests ───────────────────────────────

    #[test]
    fn match_quality_copy_semantics() {
        let a = MatchQuality::Exact;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn match_quality_full_ordering_chain() {
        let mut qualities = vec![
            MatchQuality::Fuzzy,
            MatchQuality::Exact,
            MatchQuality::Partial,
            MatchQuality::Prefix,
        ];
        qualities.sort();
        assert_eq!(
            qualities,
            vec![
                MatchQuality::Exact,
                MatchQuality::Prefix,
                MatchQuality::Partial,
                MatchQuality::Fuzzy,
            ]
        );
    }

    #[test]
    fn match_quality_deserialize_all_kebab_case() {
        for (s, expected) in [
            ("\"exact\"", MatchQuality::Exact),
            ("\"prefix\"", MatchQuality::Prefix),
            ("\"partial\"", MatchQuality::Partial),
            ("\"fuzzy\"", MatchQuality::Fuzzy),
        ] {
            let mq: MatchQuality = serde_json::from_str(s).unwrap();
            assert_eq!(mq, expected);
        }
    }

    #[test]
    fn match_quality_invalid_variant_errors() {
        let result = serde_json::from_str::<MatchQuality>("\"invalid\"");
        assert!(result.is_err());
    }

    // ── ResourceCandidate additional tests ──────────────────────────

    #[test]
    fn resource_candidate_debug_output() {
        let candidate = ResourceCandidate {
            id: "x".to_owned(),
            display_name: "X".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        };
        let dbg = format!("{candidate:?}");
        assert!(dbg.contains("id"));
        assert!(dbg.contains("display_name"));
    }

    #[test]
    fn resource_candidate_multiple_context_keys_serialized() {
        let candidate = ResourceCandidate {
            id: "r1".to_owned(),
            display_name: "Record".to_owned(),
            resource_type: "record".to_owned(),
            context: BTreeMap::from([
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned()),
                ("c".to_owned(), "3".to_owned()),
            ]),
            match_quality: MatchQuality::Fuzzy,
        };
        let json = serde_json::to_value(&candidate).unwrap();
        let ctx = json["context"].as_object().unwrap();
        assert_eq!(ctx.len(), 3);
        assert_eq!(ctx["a"], "1");
        assert_eq!(ctx["b"], "2");
        assert_eq!(ctx["c"], "3");
    }

    #[test]
    fn resource_candidate_with_long_id() {
        let long_id = "a".repeat(256);
        let candidate = ResourceCandidate {
            id: long_id.clone(),
            display_name: "Test".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        };
        let json = serde_json::to_string(&candidate).unwrap();
        let back: ResourceCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id.len(), 256);
        assert_eq!(back.id, long_id);
    }

    #[test]
    fn resource_candidate_unicode_display_name() {
        let candidate = ResourceCandidate {
            id: "u1".to_owned(),
            display_name: "\u{65e5}\u{672c}\u{8a9e}\u{30c6}\u{30b9}\u{30c8}".to_owned(),
            resource_type: "page".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        };
        let json = serde_json::to_string(&candidate).unwrap();
        let back: ResourceCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.display_name, "\u{65e5}\u{672c}\u{8a9e}\u{30c6}\u{30b9}\u{30c8}");
    }

    // ── resolve_candidates additional edge cases ────────────────────

    #[test]
    fn resolve_candidates_two_matches() {
        let candidates = vec![
            ResourceCandidate {
                id: "a".to_owned(),
                display_name: "A".to_owned(),
                resource_type: "t".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Exact,
            },
            ResourceCandidate {
                id: "b".to_owned(),
                display_name: "B".to_owned(),
                resource_type: "t".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Fuzzy,
            },
        ];
        let result = resolve_candidates("q", "k", "c", candidates, "cmd {id}");
        match &result.outcome {
            LookupOutcome::Ambiguous { candidates, prompt } => {
                assert_eq!(candidates.len(), 2);
                assert_eq!(prompt.options.len(), 2);
            }
            _ => panic!("expected Ambiguous for 2 candidates"),
        }
    }

    #[test]
    fn resolve_candidates_with_parent_context_in_options() {
        let candidates = vec![
            ResourceCandidate {
                id: "p1".to_owned(),
                display_name: "Page A".to_owned(),
                resource_type: "page".to_owned(),
                context: BTreeMap::from([("parent".to_owned(), "Workspace 1".to_owned())]),
                match_quality: MatchQuality::Prefix,
            },
            ResourceCandidate {
                id: "p2".to_owned(),
                display_name: "Page B".to_owned(),
                resource_type: "page".to_owned(),
                context: BTreeMap::from([("parent".to_owned(), "Workspace 2".to_owned())]),
                match_quality: MatchQuality::Prefix,
            },
        ];
        let result = resolve_candidates("Page", "page_id", "notion", candidates, "cmd --id={id}");
        match &result.outcome {
            LookupOutcome::Ambiguous { prompt, .. } => {
                assert_eq!(prompt.options[0].context.as_deref(), Some("Workspace 1"));
                assert_eq!(prompt.options[1].context.as_deref(), Some("Workspace 2"));
            }
            _ => panic!("expected Ambiguous"),
        }
    }

    #[test]
    fn resolve_candidates_without_parent_context_gives_none() {
        let candidates = vec![
            ResourceCandidate {
                id: "x".to_owned(),
                display_name: "X".to_owned(),
                resource_type: "t".to_owned(),
                context: BTreeMap::from([("workspace".to_owned(), "W".to_owned())]),
                match_quality: MatchQuality::Exact,
            },
            ResourceCandidate {
                id: "y".to_owned(),
                display_name: "Y".to_owned(),
                resource_type: "t".to_owned(),
                context: BTreeMap::new(),
                match_quality: MatchQuality::Fuzzy,
            },
        ];
        let result = resolve_candidates("test", "k", "c", candidates, "cmd {id}");
        match &result.outcome {
            LookupOutcome::Ambiguous { prompt, .. } => {
                assert!(prompt.options[0].context.is_none());
                assert!(prompt.options[1].context.is_none());
            }
            _ => panic!("expected Ambiguous"),
        }
    }

    #[test]
    fn resolve_single_match_preserves_candidate_fields() {
        let candidates = vec![ResourceCandidate {
            id: "id-99".to_owned(),
            display_name: "My Resource".to_owned(),
            resource_type: "widget".to_owned(),
            context: BTreeMap::from([("env".to_owned(), "prod".to_owned())]),
            match_quality: MatchQuality::Partial,
        }];
        let result = resolve_candidates("res", "widget_id", "acme", candidates, "do {id}");
        match &result.outcome {
            LookupOutcome::Resolved { candidate, .. } => {
                assert_eq!(candidate.display_name, "My Resource");
                assert_eq!(candidate.resource_type, "widget");
                assert_eq!(candidate.match_quality, MatchQuality::Partial);
                assert_eq!(candidate.context["env"], "prod");
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_not_found_mentions_connector_in_suggestion() {
        let result =
            resolve_candidates("xyz", "key", "salesforce", vec![], "fwc invoke salesforce {id}");
        match &result.outcome {
            LookupOutcome::NotFound { suggestions } => {
                assert!(suggestions.iter().any(|s| s.contains("salesforce")));
            }
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn resolve_candidates_template_without_id_placeholder() {
        let candidates = vec![ResourceCandidate {
            id: "123".to_owned(),
            display_name: "X".to_owned(),
            resource_type: "t".to_owned(),
            context: BTreeMap::new(),
            match_quality: MatchQuality::Exact,
        }];
        let result = resolve_candidates("q", "k", "c", candidates, "static-command");
        match &result.outcome {
            LookupOutcome::Resolved { next_command, .. } => {
                assert_eq!(next_command, "static-command");
            }
            _ => panic!("expected Resolved"),
        }
    }

    // ── LookupOutcome additional deserialization ────────────────────

    #[test]
    fn lookup_outcome_resolved_full_roundtrip() {
        let outcome = LookupOutcome::Resolved {
            candidate: ResourceCandidate {
                id: "abc".to_owned(),
                display_name: "ABC".to_owned(),
                resource_type: "repo".to_owned(),
                context: BTreeMap::from([("org".to_owned(), "myorg".to_owned())]),
                match_quality: MatchQuality::Prefix,
            },
            next_command: "fwc invoke github repos.get --repo=abc".to_owned(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: LookupOutcome = serde_json::from_str(&json).unwrap();
        match back {
            LookupOutcome::Resolved {
                candidate,
                next_command,
            } => {
                assert_eq!(candidate.id, "abc");
                assert_eq!(candidate.context["org"], "myorg");
                assert!(next_command.contains("abc"));
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn lookup_outcome_not_found_roundtrip() {
        let outcome = LookupOutcome::NotFound {
            suggestions: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: LookupOutcome = serde_json::from_str(&json).unwrap();
        match back {
            LookupOutcome::NotFound { suggestions } => {
                assert_eq!(suggestions.len(), 3);
            }
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn lookup_outcome_unsupported_roundtrip() {
        let outcome = LookupOutcome::Unsupported {
            reason: "custom connectors do not support lookup".to_owned(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: LookupOutcome = serde_json::from_str(&json).unwrap();
        match back {
            LookupOutcome::Unsupported { reason } => {
                assert!(reason.contains("custom connectors"));
            }
            _ => panic!("expected Unsupported"),
        }
    }

    #[test]
    fn lookup_outcome_ambiguous_roundtrip() {
        let outcome = LookupOutcome::Ambiguous {
            candidates: vec![
                ResourceCandidate {
                    id: "1".to_owned(),
                    display_name: "One".to_owned(),
                    resource_type: "page".to_owned(),
                    context: BTreeMap::new(),
                    match_quality: MatchQuality::Exact,
                },
                ResourceCandidate {
                    id: "2".to_owned(),
                    display_name: "Two".to_owned(),
                    resource_type: "page".to_owned(),
                    context: BTreeMap::new(),
                    match_quality: MatchQuality::Partial,
                },
            ],
            prompt: DisambiguationPrompt {
                binding_key: "page_id".to_owned(),
                question: "Which page?".to_owned(),
                options: vec![
                    DisambiguationOption {
                        value: "1".to_owned(),
                        label: "One".to_owned(),
                        context: None,
                    },
                    DisambiguationOption {
                        value: "2".to_owned(),
                        label: "Two".to_owned(),
                        context: None,
                    },
                ],
                next_commands: vec!["cmd 1".to_owned(), "cmd 2".to_owned()],
            },
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: LookupOutcome = serde_json::from_str(&json).unwrap();
        match back {
            LookupOutcome::Ambiguous { candidates, prompt } => {
                assert_eq!(candidates.len(), 2);
                assert_eq!(prompt.options.len(), 2);
                assert_eq!(prompt.question, "Which page?");
            }
            _ => panic!("expected Ambiguous"),
        }
    }

    // ── LookupResult additional tests ───────────────────────────────

    #[test]
    fn lookup_result_ambiguous_roundtrip() {
        let result = LookupResult {
            query: "test".to_owned(),
            connector: "slack".to_owned(),
            outcome: LookupOutcome::Ambiguous {
                candidates: vec![ResourceCandidate {
                    id: "ch-1".to_owned(),
                    display_name: "#test".to_owned(),
                    resource_type: "channel".to_owned(),
                    context: BTreeMap::new(),
                    match_quality: MatchQuality::Prefix,
                }],
                prompt: DisambiguationPrompt {
                    binding_key: "channel".to_owned(),
                    question: "Which channel?".to_owned(),
                    options: vec![],
                    next_commands: vec![],
                },
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LookupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.query, "test");
        assert_eq!(back.connector, "slack");
    }

    #[test]
    fn lookup_result_clone() {
        let result = LookupResult {
            query: "q".to_owned(),
            connector: "c".to_owned(),
            outcome: LookupOutcome::NotFound {
                suggestions: vec!["s".to_owned()],
            },
        };
        let cloned = result.clone();
        assert_eq!(cloned.query, result.query);
        assert_eq!(cloned.connector, result.connector);
    }

    #[test]
    fn lookup_result_debug() {
        let result = LookupResult {
            query: "dbg".to_owned(),
            connector: "test".to_owned(),
            outcome: LookupOutcome::NotFound {
                suggestions: vec![],
            },
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("dbg"));
        assert!(dbg.contains("test"));
    }

    // ── DisambiguationPrompt additional tests ───────────────────────

    #[test]
    fn disambiguation_prompt_empty_options() {
        let prompt = DisambiguationPrompt {
            binding_key: "k".to_owned(),
            question: "Q?".to_owned(),
            options: vec![],
            next_commands: vec![],
        };
        let json = serde_json::to_value(&prompt).unwrap();
        assert!(json["options"].as_array().unwrap().is_empty());
        assert!(json["next_commands"].as_array().unwrap().is_empty());
    }

    #[test]
    fn disambiguation_prompt_clone() {
        let prompt = DisambiguationPrompt {
            binding_key: "k".to_owned(),
            question: "Q?".to_owned(),
            options: vec![DisambiguationOption {
                value: "v".to_owned(),
                label: "L".to_owned(),
                context: Some("ctx".to_owned()),
            }],
            next_commands: vec!["cmd".to_owned()],
        };
        let cloned = prompt.clone();
        assert_eq!(cloned.binding_key, prompt.binding_key);
        assert_eq!(cloned.options.len(), 1);
    }

    #[test]
    fn disambiguation_prompt_debug() {
        let prompt = DisambiguationPrompt {
            binding_key: "page_id".to_owned(),
            question: "Which page?".to_owned(),
            options: vec![],
            next_commands: vec![],
        };
        let dbg = format!("{prompt:?}");
        assert!(dbg.contains("page_id"));
        assert!(dbg.contains("Which page?"));
    }

    #[test]
    fn disambiguation_option_clone() {
        let opt = DisambiguationOption {
            value: "v".to_owned(),
            label: "L".to_owned(),
            context: Some("c".to_owned()),
        };
        let cloned = opt.clone();
        assert_eq!(cloned.value, opt.value);
        assert_eq!(cloned.label, opt.label);
        assert_eq!(cloned.context, opt.context);
    }

    #[test]
    fn disambiguation_option_debug() {
        let opt = DisambiguationOption {
            value: "v1".to_owned(),
            label: "Label".to_owned(),
            context: None,
        };
        let dbg = format!("{opt:?}");
        assert!(dbg.contains("v1"));
        assert!(dbg.contains("Label"));
    }

    // ── ConnectorResourceModel additional tests ─────────────────────

    #[test]
    fn connector_resource_model_empty_types() {
        let model = ConnectorResourceModel {
            connector: "empty".to_owned(),
            resource_types: vec![],
        };
        let json = serde_json::to_value(&model).unwrap();
        assert!(json["resource_types"].as_array().unwrap().is_empty());
    }

    #[test]
    fn connector_resource_model_clone() {
        let model = ConnectorResourceModel {
            connector: "github".to_owned(),
            resource_types: vec![ResourceTypeDescriptor {
                name: "repo".to_owned(),
                description: "Repository".to_owned(),
                lookup_operation: "repos.search".to_owned(),
                id_field: "id".to_owned(),
                name_field: "name".to_owned(),
                consumed_by: vec![],
                example_queries: vec![],
            }],
        };
        let cloned = model.clone();
        assert_eq!(cloned.connector, model.connector);
        assert_eq!(cloned.resource_types.len(), 1);
    }

    #[test]
    fn connector_resource_model_debug() {
        let model = ConnectorResourceModel {
            connector: "test".to_owned(),
            resource_types: vec![],
        };
        let dbg = format!("{model:?}");
        assert!(dbg.contains("test"));
    }

    // ── ResourceTypeDescriptor additional tests ─────────────────────

    #[test]
    fn resource_type_descriptor_clone() {
        let desc = ResourceTypeDescriptor {
            name: "page".to_owned(),
            description: "A page".to_owned(),
            lookup_operation: "pages.search".to_owned(),
            id_field: "id".to_owned(),
            name_field: "title".to_owned(),
            consumed_by: vec!["pages.update".to_owned()],
            example_queries: vec!["Roadmap".to_owned()],
        };
        let cloned = desc.clone();
        assert_eq!(cloned.name, desc.name);
        assert_eq!(cloned.consumed_by, desc.consumed_by);
        assert_eq!(cloned.example_queries, desc.example_queries);
    }

    #[test]
    fn resource_type_descriptor_debug() {
        let desc = ResourceTypeDescriptor {
            name: "issue".to_owned(),
            description: "An issue".to_owned(),
            lookup_operation: "issues.search".to_owned(),
            id_field: "number".to_owned(),
            name_field: "title".to_owned(),
            consumed_by: vec![],
            example_queries: vec![],
        };
        let dbg = format!("{desc:?}");
        assert!(dbg.contains("issue"));
    }

    // ── RESOURCE_FAMILIES field validation ──────────────────────────

    #[test]
    fn resource_family_project_connectors() {
        let family = RESOURCE_FAMILIES
            .iter()
            .find(|f| f.family == "project")
            .unwrap();
        assert!(family.connectors.contains(&"github"));
        assert!(family.connectors.contains(&"jira"));
        assert!(family.connectors.contains(&"linear"));
    }

    #[test]
    fn resource_family_issue_connectors() {
        let family = RESOURCE_FAMILIES
            .iter()
            .find(|f| f.family == "issue")
            .unwrap();
        assert!(family.connectors.contains(&"github"));
        assert!(family.connectors.contains(&"jira"));
        assert!(family.connectors.contains(&"asana"));
    }

    #[test]
    fn resource_family_channel_connectors() {
        let family = RESOURCE_FAMILIES
            .iter()
            .find(|f| f.family == "channel")
            .unwrap();
        assert!(family.connectors.contains(&"slack"));
        assert!(family.connectors.contains(&"discord"));
    }

    #[test]
    fn resource_family_document_connectors() {
        let family = RESOURCE_FAMILIES
            .iter()
            .find(|f| f.family == "document")
            .unwrap();
        assert!(family.connectors.contains(&"google-docs"));
        assert!(family.connectors.contains(&"dropbox"));
    }

    #[test]
    fn resource_family_workspace_connectors() {
        let family = RESOURCE_FAMILIES
            .iter()
            .find(|f| f.family == "workspace")
            .unwrap();
        assert!(family.connectors.contains(&"notion"));
        assert!(family.connectors.contains(&"slack"));
    }

    #[test]
    fn resource_families_exact_count() {
        assert_eq!(RESOURCE_FAMILIES.len(), 8);
    }

    // ── find_resource_family additional tests ───────────────────────

    #[test]
    fn find_family_google_drive_document() {
        let f = find_resource_family("google-drive", "document").unwrap();
        assert_eq!(f.family, "document");
        assert!(f.connectors.contains(&"google-drive"));
    }

    #[test]
    fn find_family_airtable_record() {
        let f = find_resource_family("airtable", "record").unwrap();
        assert_eq!(f.family, "record");
    }

    #[test]
    fn find_family_notion_workspace() {
        let f = find_resource_family("notion", "workspace").unwrap();
        assert_eq!(f.family, "workspace");
    }

    #[test]
    fn find_family_discord_channel() {
        let f = find_resource_family("discord", "channel").unwrap();
        assert_eq!(f.family, "channel");
    }

    #[test]
    fn find_family_wrong_connector_for_type() {
        // slack does not have "issue" family
        assert!(find_resource_family("slack", "issue").is_none());
    }

    #[test]
    fn find_family_empty_connector() {
        assert!(find_resource_family("", "project").is_none());
    }

    #[test]
    fn find_family_empty_resource_type() {
        assert!(find_resource_family("github", "").is_none());
    }

    // ── suggest_discovery_commands additional tests ──────────────────

    #[test]
    fn suggest_commands_for_slack_channel() {
        let cmds = suggest_discovery_commands("slack", Some("channel"));
        assert!(cmds.iter().any(|c| c.contains("channel")));
        assert!(cmds.iter().any(|c| c.contains("slack")));
    }

    #[test]
    fn suggest_commands_ops_always_present() {
        let cmds = suggest_discovery_commands("notion", Some("page"));
        assert!(cmds.iter().any(|c| c.contains("fwc ops notion")));
    }

    #[test]
    fn suggest_commands_show_always_present() {
        let cmds = suggest_discovery_commands("notion", Some("page"));
        assert!(cmds.iter().any(|c| c.contains("fwc show notion")));
    }

    #[test]
    fn suggest_commands_empty_connector() {
        let cmds = suggest_discovery_commands("", None);
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].contains("fwc ops"));
        assert!(cmds[1].contains("fwc show"));
    }
}
