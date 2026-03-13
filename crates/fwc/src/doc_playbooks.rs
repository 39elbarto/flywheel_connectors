//! Operator and agent playbook infrastructure for FWC documentation.
//!
//! Provides structured, searchable playbooks and migration guides that cover
//! getting started, daily operations, troubleshooting, security, performance,
//! and connector development workflows.  All content is available in TOON
//! format for terminal display.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── Enums ─────────────────────────────────────────────────────────────

/// Target audience for a playbook.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    Operator,
    Agent,
    Developer,
}

impl Audience {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Operator => "Operator",
            Self::Agent => "Agent",
            Self::Developer => "Developer",
        }
    }

    /// All variants.
    pub const fn all() -> &'static [Self] {
        &[Self::Operator, Self::Agent, Self::Developer]
    }
}

impl std::fmt::Display for Audience {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Playbook category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookCategory {
    GettingStarted,
    DailyOperations,
    Troubleshooting,
    Migration,
    Security,
    Performance,
    Integration,
    Advanced,
}

impl PlaybookCategory {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::GettingStarted => "Getting Started",
            Self::DailyOperations => "Daily Operations",
            Self::Troubleshooting => "Troubleshooting",
            Self::Migration => "Migration",
            Self::Security => "Security",
            Self::Performance => "Performance",
            Self::Integration => "Integration",
            Self::Advanced => "Advanced",
        }
    }

    /// All variants in display order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::GettingStarted,
            Self::DailyOperations,
            Self::Troubleshooting,
            Self::Migration,
            Self::Security,
            Self::Performance,
            Self::Integration,
            Self::Advanced,
        ]
    }
}

impl std::fmt::Display for PlaybookCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── Core types ────────────────────────────────────────────────────────

/// A single example within a playbook section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Example {
    /// Short description of what the example demonstrates.
    pub description: String,
    /// The CLI command to run.
    pub command: String,
    /// Expected output (may be a representative snippet).
    pub expected_output: String,
    /// Explanation of the command and its output.
    pub explanation: String,
}

impl Example {
    /// Returns true if the example has all required fields populated.
    pub fn is_valid(&self) -> bool {
        !self.description.is_empty()
            && !self.command.is_empty()
            && !self.expected_output.is_empty()
            && !self.explanation.is_empty()
    }
}

/// A section within a playbook.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Section {
    /// Section title.
    pub title: String,
    /// Main content text.
    pub content: String,
    /// Illustrative examples.
    #[serde(default)]
    pub examples: Vec<Example>,
    /// Warning messages (things to be careful about).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Tips and best practices.
    #[serde(default)]
    pub tips: Vec<String>,
}

/// A complete playbook document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Playbook {
    /// Unique identifier (slug form, e.g. "getting-started").
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Target audience.
    pub audience: Audience,
    /// Topic category.
    pub category: PlaybookCategory,
    /// Ordered sections.
    pub sections: Vec<Section>,
    /// Prerequisites that should be met before following this playbook.
    #[serde(default)]
    pub prerequisites: Vec<String>,
    /// IDs of related playbooks.
    #[serde(default)]
    pub related_playbooks: Vec<String>,
}

impl Playbook {
    /// Returns all keywords from the playbook for search purposes.
    pub fn keywords(&self) -> Vec<String> {
        let mut words = Vec::new();
        // Title words
        for w in self.title.split_whitespace() {
            words.push(w.to_lowercase());
        }
        // Section title words
        for sec in &self.sections {
            for w in sec.title.split_whitespace() {
                words.push(w.to_lowercase());
            }
            for w in sec.content.split_whitespace() {
                words.push(w.to_lowercase());
            }
        }
        // Category label
        for w in self.category.label().split_whitespace() {
            words.push(w.to_lowercase());
        }
        words
    }

    /// Returns total number of examples across all sections.
    pub fn example_count(&self) -> usize {
        self.sections.iter().map(|s| s.examples.len()).sum()
    }

    /// Returns true if all examples in the playbook are valid.
    pub fn all_examples_valid(&self) -> bool {
        self.sections
            .iter()
            .flat_map(|s| &s.examples)
            .all(Example::is_valid)
    }
}

// ── Breaking change and migration ─────────────────────────────────────

/// A single breaking change in a migration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreakingChange {
    /// Component affected (e.g. "fwc invoke", "Connector manifest").
    pub component: String,
    /// Description of the change.
    pub description: String,
    /// How to migrate.
    pub migration_path: String,
    /// Code/config before the change.
    pub before_code: String,
    /// Code/config after the change.
    pub after_code: String,
}

/// Estimated effort for a migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationEffort {
    /// Under 30 minutes.
    Low,
    /// 30 minutes to 2 hours.
    Medium,
    /// 2+ hours.
    High,
}

impl MigrationEffort {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "Low (< 30 min)",
            Self::Medium => "Medium (30 min - 2 hr)",
            Self::High => "High (2+ hr)",
        }
    }
}

impl std::fmt::Display for MigrationEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A complete migration guide between versions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationGuide {
    /// Version migrating from.
    pub from_version: String,
    /// Version migrating to.
    pub to_version: String,
    /// List of breaking changes.
    pub breaking_changes: Vec<BreakingChange>,
    /// Ordered steps to perform the migration.
    pub migration_steps: Vec<String>,
    /// Steps to revert if migration fails.
    pub rollback_plan: Vec<String>,
    /// Estimated effort.
    pub estimated_effort: MigrationEffort,
}

impl MigrationGuide {
    /// Version range as "from -> to".
    pub fn version_range(&self) -> String {
        format!("{} -> {}", self.from_version, self.to_version)
    }
}

// ── Playbook index ────────────────────────────────────────────────────

/// Searchable index of playbooks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaybookIndex {
    /// All playbooks in the index.
    pub playbooks: Vec<Playbook>,
    /// Playbooks by category (id list).
    pub by_category: HashMap<PlaybookCategory, Vec<String>>,
    /// Playbooks by audience (id list).
    pub by_audience: HashMap<Audience, Vec<String>>,
}

impl PlaybookIndex {
    /// Build an index from a list of playbooks.
    pub fn new(playbooks: Vec<Playbook>) -> Self {
        let mut by_category: HashMap<PlaybookCategory, Vec<String>> = HashMap::new();
        let mut by_audience: HashMap<Audience, Vec<String>> = HashMap::new();

        for pb in &playbooks {
            by_category
                .entry(pb.category)
                .or_default()
                .push(pb.id.clone());
            by_audience
                .entry(pb.audience)
                .or_default()
                .push(pb.id.clone());
        }

        Self {
            playbooks,
            by_category,
            by_audience,
        }
    }

    /// Find all playbooks in a given category.
    pub fn find_by_category(&self, category: PlaybookCategory) -> Vec<&Playbook> {
        let Some(ids) = self.by_category.get(&category) else {
            return Vec::new();
        };
        self.playbooks
            .iter()
            .filter(|pb| ids.contains(&pb.id))
            .collect()
    }

    /// Find all playbooks for a given audience.
    pub fn find_by_audience(&self, audience: Audience) -> Vec<&Playbook> {
        let Some(ids) = self.by_audience.get(&audience) else {
            return Vec::new();
        };
        self.playbooks
            .iter()
            .filter(|pb| ids.contains(&pb.id))
            .collect()
    }

    /// Simple keyword search across playbook titles, section titles, and content.
    pub fn search(&self, query: &str) -> Vec<&Playbook> {
        if query.is_empty() {
            return Vec::new();
        }
        let needle = query.to_lowercase();
        let terms: Vec<&str> = needle.split_whitespace().collect();
        if terms.is_empty() {
            return Vec::new();
        }

        self.playbooks
            .iter()
            .filter(|pb| {
                let keywords = pb.keywords();
                let text = keywords.join(" ");
                terms.iter().all(|t| text.contains(t))
            })
            .collect()
    }

    /// Find a playbook by its exact ID.
    pub fn find_by_id(&self, id: &str) -> Option<&Playbook> {
        self.playbooks.iter().find(|pb| pb.id == id)
    }

    /// Total number of playbooks.
    pub fn len(&self) -> usize {
        self.playbooks.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.playbooks.is_empty()
    }
}

// ── TOON formatting ───────────────────────────────────────────────────

/// Format a single playbook in TOON text format.
pub fn format_playbook_toon(playbook: &Playbook) -> String {
    let mut out = String::new();

    // Header
    let _ = writeln!(out, "== {} ==", playbook.title);
    let _ = writeln!(
        out,
        "   ID: {}  |  Audience: {}  |  Category: {}",
        playbook.id, playbook.audience, playbook.category
    );
    out.push('\n');

    // Prerequisites
    if !playbook.prerequisites.is_empty() {
        let _ = writeln!(out, "  Prerequisites:");
        for prereq in &playbook.prerequisites {
            let _ = writeln!(out, "    - {prereq}");
        }
        out.push('\n');
    }

    // Sections
    for (i, section) in playbook.sections.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", i + 1, section.title);
        let _ = writeln!(out, "     {}", section.content);

        // Warnings
        for warning in &section.warnings {
            let _ = writeln!(out, "     WARNING: {warning}");
        }

        // Tips
        for tip in &section.tips {
            let _ = writeln!(out, "     TIP: {tip}");
        }

        // Examples
        for example in &section.examples {
            out.push('\n');
            let _ = writeln!(out, "     Example: {}", example.description);
            let _ = writeln!(out, "       $ {}", example.command);
            let _ = writeln!(out, "       > {}", example.expected_output);
            let _ = writeln!(out, "       # {}", example.explanation);
        }
        out.push('\n');
    }

    // Related playbooks
    if !playbook.related_playbooks.is_empty() {
        let _ = writeln!(out, "  See also: {}", playbook.related_playbooks.join(", "));
    }

    out
}

/// Format the full playbook index in TOON text format.
pub fn format_playbook_index_toon(index: &PlaybookIndex) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "== FWC Playbook Index ==");
    let _ = writeln!(out, "   {} playbook(s) available", index.len());
    out.push('\n');

    for cat in PlaybookCategory::all() {
        let pbs = index.find_by_category(*cat);
        if pbs.is_empty() {
            continue;
        }
        let _ = writeln!(out, "  [{cat}]");
        for pb in &pbs {
            let _ = writeln!(out, "    {:<30} {} ({})", pb.id, pb.title, pb.audience);
        }
        out.push('\n');
    }

    out
}

/// Format a migration guide in TOON text format.
pub fn format_migration_guide_toon(guide: &MigrationGuide) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "== Migration Guide: {} -> {} ==",
        guide.from_version, guide.to_version
    );
    let _ = writeln!(out, "   Estimated effort: {}", guide.estimated_effort);
    out.push('\n');

    // Breaking changes
    if !guide.breaking_changes.is_empty() {
        let _ = writeln!(
            out,
            "  Breaking Changes ({}):",
            guide.breaking_changes.len()
        );
        for (i, bc) in guide.breaking_changes.iter().enumerate() {
            let _ = writeln!(out, "    {}. [{}] {}", i + 1, bc.component, bc.description);
            let _ = writeln!(out, "       Migration: {}", bc.migration_path);
            let _ = writeln!(out, "       Before: {}", bc.before_code);
            let _ = writeln!(out, "       After:  {}", bc.after_code);
        }
        out.push('\n');
    }

    // Migration steps
    if !guide.migration_steps.is_empty() {
        let _ = writeln!(out, "  Migration Steps:");
        for (i, step) in guide.migration_steps.iter().enumerate() {
            let _ = writeln!(out, "    {}. {step}", i + 1);
        }
        out.push('\n');
    }

    // Rollback plan
    if !guide.rollback_plan.is_empty() {
        let _ = writeln!(out, "  Rollback Plan:");
        for (i, step) in guide.rollback_plan.iter().enumerate() {
            let _ = writeln!(out, "    {}. {step}", i + 1);
        }
        out.push('\n');
    }

    out
}

// ── Built-in playbooks ────────────────────────────────────────────────

/// Returns the set of built-in playbooks shipped with FWC.
pub fn get_builtin_playbooks() -> Vec<Playbook> {
    vec![
        playbook_getting_started(),
        playbook_daily_ops(),
        playbook_troubleshooting_auth(),
        playbook_troubleshooting_connectivity(),
        playbook_batch_operations(),
        playbook_migration_fcp2_to_fcp3(),
        playbook_security_hardening(),
        playbook_performance_tuning(),
        playbook_agent_integration(),
        playbook_connector_development(),
        playbook_pipeline_authoring(),
        playbook_fleet_management(),
    ]
}

fn playbook_getting_started() -> Playbook {
    Playbook {
        id: "getting-started".into(),
        title: "First-Time FWC Setup and Connector Discovery".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::GettingStarted,
        prerequisites: vec![
            "FWC binary installed and on PATH".into(),
            "Network access to connector registry".into(),
        ],
        related_playbooks: vec!["daily-ops".into(), "troubleshooting-auth".into()],
        sections: vec![
            Section {
                title: "Verify Installation".into(),
                content: "Confirm fwc is installed and can reach the host.".into(),
                examples: vec![Example {
                    description: "Check fwc version".into(),
                    command: "fwc --version".into(),
                    expected_output: "fwc 0.1.0".into(),
                    explanation: "Prints the installed version of fwc.".into(),
                }],
                warnings: vec![],
                tips: vec!["Run fwc doctor to diagnose issues.".into()],
            },
            Section {
                title: "Discover Connectors".into(),
                content: "List available connectors and their operations.".into(),
                examples: vec![
                    Example {
                        description: "List all connectors".into(),
                        command: "fwc catalog list".into(),
                        expected_output: "github   5 ops  Running\nslack    8 ops  Running".into(),
                        explanation: "Shows all registered connectors with operation counts."
                            .into(),
                    },
                    Example {
                        description: "Search for a connector by keyword".into(),
                        command: "fwc search github".into(),
                        expected_output: "github: list_repos, create_issue, ...".into(),
                        explanation: "Finds connectors and operations matching the query.".into(),
                    },
                ],
                warnings: vec![],
                tips: vec!["Use --format json to get machine-readable output.".into()],
            },
            Section {
                title: "Run Your First Operation".into(),
                content: "Invoke a connector operation to validate the end-to-end flow.".into(),
                examples: vec![Example {
                    description: "Invoke a simple read operation".into(),
                    command: "fwc invoke github list_repos --input '{}'".into(),
                    expected_output: "{\"status\":\"ok\",\"repos\":[...]}".into(),
                    explanation: "Calls the github list_repos operation with empty input.".into(),
                }],
                warnings: vec!["Ensure you have valid credentials before invoking.".into()],
                tips: vec![],
            },
        ],
    }
}

fn playbook_daily_ops() -> Playbook {
    Playbook {
        id: "daily-ops".into(),
        title: "Common Daily Operations".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::DailyOperations,
        prerequisites: vec![
            "FWC configured and connected to host".into(),
        ],
        related_playbooks: vec![
            "getting-started".into(),
            "troubleshooting-auth".into(),
            "batch-operations".into(),
        ],
        sections: vec![
            Section {
                title: "Check Connector Health".into(),
                content: "Monitor the health status of all connectors in the fleet.".into(),
                examples: vec![Example {
                    description: "View health dashboard".into(),
                    command: "fwc health".into(),
                    expected_output: "Health: 5 total, 4 healthy, 1 degraded".into(),
                    explanation: "Shows aggregate health with per-connector status.".into(),
                }],
                warnings: vec![],
                tips: vec!["Pipe to --format json for alerting integration.".into()],
            },
            Section {
                title: "Invoke Operations".into(),
                content: "Run connector operations for day-to-day tasks.".into(),
                examples: vec![Example {
                    description: "Invoke with structured input".into(),
                    command: "fwc invoke slack send_message --set channel=#ops --set text='Deploy complete'".into(),
                    expected_output: "{\"status\":\"ok\",\"ts\":\"1234567890.123\"}".into(),
                    explanation: "Sends a Slack message using --set for field binding.".into(),
                }],
                warnings: vec![],
                tips: vec!["Use --dry-run to preview without executing.".into()],
            },
            Section {
                title: "Review Operation History".into(),
                content: "Inspect past invocations for auditing and debugging.".into(),
                examples: vec![Example {
                    description: "List recent history".into(),
                    command: "fwc history --limit 10".into(),
                    expected_output: "2026-03-12 14:30  github.list_repos  ok  142ms".into(),
                    explanation: "Shows the 10 most recent invocations with status and latency.".into(),
                }],
                warnings: vec![],
                tips: vec!["Use fwc history <id> for full request/response details.".into()],
            },
        ],
    }
}

fn playbook_troubleshooting_auth() -> Playbook {
    Playbook {
        id: "troubleshooting-auth".into(),
        title: "Diagnosing and Fixing Auth/Credential Issues".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::Troubleshooting,
        prerequisites: vec![
            "Understanding of connector credential types".into(),
        ],
        related_playbooks: vec![
            "security-hardening".into(),
            "troubleshooting-connectivity".into(),
        ],
        sections: vec![
            Section {
                title: "Identify Auth Failures".into(),
                content: "Recognize FCP_ERR_UNAUTHORIZED and FCP_ERR_TOKEN_EXPIRED errors.".into(),
                examples: vec![Example {
                    description: "Check auth status".into(),
                    command: "fwc auth status".into(),
                    expected_output: "github: Bearer token  VALID  expires 2026-04-01\nslack:  OAuth2        EXPIRED".into(),
                    explanation: "Lists credential status for each connector.".into(),
                }],
                warnings: vec!["Expired tokens will cause all operations to fail.".into()],
                tips: vec!["Run auth status before batch operations.".into()],
            },
            Section {
                title: "Refresh Credentials".into(),
                content: "Rotate or refresh expired credentials.".into(),
                examples: vec![Example {
                    description: "Refresh a specific connector's credentials".into(),
                    command: "fwc credential refresh slack".into(),
                    expected_output: "Credential refreshed for slack. New expiry: 2026-04-12".into(),
                    explanation: "Triggers OAuth2 refresh flow for the slack connector.".into(),
                }],
                warnings: vec![
                    "Some connectors require manual API key rotation.".into(),
                ],
                tips: vec![
                    "Set up credential rotation alerts with fwc health --watch.".into(),
                ],
            },
            Section {
                title: "Verify Capability Tokens".into(),
                content: "Ensure capability tokens are valid and not expired.".into(),
                examples: vec![Example {
                    description: "Validate a capability token".into(),
                    command: "fwc validate token --file cap.cose".into(),
                    expected_output: "Token valid. Subject: agent-1, Expires: 2026-06-01".into(),
                    explanation: "Parses and validates a COSE-signed capability token.".into(),
                }],
                warnings: vec![],
                tips: vec![],
            },
        ],
    }
}

fn playbook_troubleshooting_connectivity() -> Playbook {
    Playbook {
        id: "troubleshooting-connectivity".into(),
        title: "Host Connectivity and Network Issues".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::Troubleshooting,
        prerequisites: vec!["FWC installed".into(), "Host endpoint URL known".into()],
        related_playbooks: vec!["troubleshooting-auth".into(), "fleet-management".into()],
        sections: vec![
            Section {
                title: "Diagnose Connectivity".into(),
                content: "Use fwc doctor and fwc net to identify network problems.".into(),
                examples: vec![
                    Example {
                        description: "Run connectivity diagnostics".into(),
                        command: "fwc doctor".into(),
                        expected_output:
                            "Host: reachable (42ms)\nRegistry: reachable (105ms)\nDNS: ok".into(),
                        explanation: "Performs health checks on all endpoints.".into(),
                    },
                    Example {
                        description: "Test a specific endpoint".into(),
                        command: "fwc net ping --host api.example.com".into(),
                        expected_output: "api.example.com: 200 OK (38ms)".into(),
                        explanation: "Sends an HTTP health-check request.".into(),
                    },
                ],
                warnings: vec!["Firewall rules may block outbound FCP traffic on port 443.".into()],
                tips: vec!["Use FWC_HOST_URL env var to override the default host.".into()],
            },
            Section {
                title: "DNS and Proxy Issues".into(),
                content: "Resolve DNS resolution failures and proxy misconfigurations.".into(),
                examples: vec![Example {
                    description: "Check effective proxy settings".into(),
                    command: "fwc net proxy-info".into(),
                    expected_output:
                        "HTTP_PROXY: http://proxy.corp:8080\nNO_PROXY: localhost,127.0.0.1".into(),
                    explanation: "Displays the proxy environment variables in use.".into(),
                }],
                warnings: vec![],
                tips: vec!["Set HTTPS_PROXY for TLS-terminated proxies.".into()],
            },
        ],
    }
}

fn playbook_batch_operations() -> Playbook {
    Playbook {
        id: "batch-operations".into(),
        title: "Running Batch and Pipeline Operations Effectively".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::DailyOperations,
        prerequisites: vec![
            "Familiarity with fwc invoke".into(),
            "At least one connector configured".into(),
        ],
        related_playbooks: vec!["pipeline-authoring".into(), "performance-tuning".into()],
        sections: vec![
            Section {
                title: "Batch Invocations".into(),
                content: "Run multiple operations in a single batch request.".into(),
                examples: vec![Example {
                    description: "Run batch from file".into(),
                    command: "fwc batch run --file ops.json --concurrency 4".into(),
                    expected_output: "Batch complete: 10/10 succeeded, 0 failed (2.3s)".into(),
                    explanation: "Executes all operations in ops.json with 4 concurrent workers."
                        .into(),
                }],
                warnings: vec!["High concurrency may trigger rate limits.".into()],
                tips: vec!["Use --stop-on-error to halt on first failure.".into()],
            },
            Section {
                title: "Batch Progress Tracking".into(),
                content: "Monitor batch execution in real time.".into(),
                examples: vec![Example {
                    description: "Watch batch progress".into(),
                    command: "fwc batch status --watch".into(),
                    expected_output: "[=====>     ] 5/10 complete  ETA 1.2s".into(),
                    explanation: "Live progress bar with ETA calculation.".into(),
                }],
                warnings: vec![],
                tips: vec!["Batch results are saved in history for later review.".into()],
            },
        ],
    }
}

fn playbook_migration_fcp2_to_fcp3() -> Playbook {
    Playbook {
        id: "migration-fcp2-to-fcp3".into(),
        title: "Migrating from FCP2 to FCP3 Connectors".into(),
        audience: Audience::Developer,
        category: PlaybookCategory::Migration,
        prerequisites: vec![
            "Existing FCP2 connector source code".into(),
            "FCP3 SDK installed".into(),
        ],
        related_playbooks: vec![
            "connector-development".into(),
            "security-hardening".into(),
        ],
        sections: vec![
            Section {
                title: "Understand the Changes".into(),
                content: "FCP3 introduces typed OperationInfo, COSE-signed capability tokens, and the mesh-native protocol. Connectors must declare operations via introspect() instead of static manifests.".into(),
                examples: vec![],
                warnings: vec![
                    "FCP2 connectors are not binary-compatible with FCP3 hosts.".into(),
                ],
                tips: vec![
                    "Use fwc validate manifest to check compatibility.".into(),
                ],
            },
            Section {
                title: "Update Manifest Format".into(),
                content: "Convert TOML manifests from FCP2 format to FCP3 format.".into(),
                examples: vec![Example {
                    description: "Validate updated manifest".into(),
                    command: "fwc validate manifest connector.toml".into(),
                    expected_output: "Manifest valid. 5 operations declared.".into(),
                    explanation: "Validates the manifest against the FCP3 schema.".into(),
                }],
                warnings: vec![],
                tips: vec!["The fwc new --from-fcp2 flag can scaffold the migration.".into()],
            },
            Section {
                title: "Implement introspect()".into(),
                content: "Replace static operation declarations with the introspect() trait method that returns Vec<OperationInfo>.".into(),
                examples: vec![Example {
                    description: "Check introspection output".into(),
                    command: "fwc catalog inspect my-connector".into(),
                    expected_output: "my-connector: 5 operations\n  list_items     Read   SafetyTier::Observe".into(),
                    explanation: "Verifies the connector reports operations via introspect().".into(),
                }],
                warnings: vec![],
                tips: vec![],
            },
        ],
    }
}

fn playbook_security_hardening() -> Playbook {
    Playbook {
        id: "security-hardening".into(),
        title: "Credential Rotation, Audit, and Supply-Chain Verification".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::Security,
        prerequisites: vec![
            "Admin access to connector credentials".into(),
            "Understanding of FCP capability model".into(),
        ],
        related_playbooks: vec!["troubleshooting-auth".into(), "fleet-management".into()],
        sections: vec![
            Section {
                title: "Credential Rotation".into(),
                content: "Regularly rotate API keys and tokens to limit blast radius.".into(),
                examples: vec![Example {
                    description: "Rotate all expiring credentials".into(),
                    command: "fwc credential rotate --expiring-within 7d".into(),
                    expected_output: "Rotated 3 credentials: github, slack, jira".into(),
                    explanation: "Finds and rotates credentials expiring within 7 days.".into(),
                }],
                warnings: vec!["Rotation may cause brief downtime for affected connectors.".into()],
                tips: vec!["Schedule rotation during maintenance windows.".into()],
            },
            Section {
                title: "Audit Trail".into(),
                content: "Review the audit chain for compliance and forensics.".into(),
                examples: vec![Example {
                    description: "View recent audit entries".into(),
                    command: "fwc audit timeline --last 24h".into(),
                    expected_output: "2026-03-12 10:00  INVOKE  github.create_issue  agent-1  ok"
                        .into(),
                    explanation: "Shows timestamped audit entries for all operations.".into(),
                }],
                warnings: vec![],
                tips: vec![
                    "Export audit logs to SIEM with fwc audit export --format syslog.".into(),
                ],
            },
            Section {
                title: "Supply-Chain Verification".into(),
                content: "Verify connector binary integrity and provenance.".into(),
                examples: vec![Example {
                    description: "Verify connector binary".into(),
                    command: "fwc supply-chain verify github".into(),
                    expected_output: "github: signature VALID, hash matches, provenance OK".into(),
                    explanation: "Checks the binary signature and hash against the registry."
                        .into(),
                }],
                warnings: vec!["Never run unverified connectors in production.".into()],
                tips: vec![],
            },
        ],
    }
}

fn playbook_performance_tuning() -> Playbook {
    Playbook {
        id: "performance-tuning".into(),
        title: "Token Budget, Batch Concurrency, and Caching".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::Performance,
        prerequisites: vec![
            "FWC configured with at least one connector".into(),
            "Basic familiarity with batch operations".into(),
        ],
        related_playbooks: vec!["batch-operations".into(), "fleet-management".into()],
        sections: vec![
            Section {
                title: "Token Budget Management".into(),
                content: "Configure and monitor token budgets to avoid overspending.".into(),
                examples: vec![Example {
                    description: "Check budget usage".into(),
                    command: "fwc budget report".into(),
                    expected_output:
                        "Daily: 450/1000 tokens used (45%)\nMonthly: 12,000/30,000 (40%)".into(),
                    explanation: "Shows current token usage against configured limits.".into(),
                }],
                warnings: vec!["Exceeding budget triggers FCP_ERR_BUDGET_EXCEEDED.".into()],
                tips: vec!["Set per-connector budgets with fwc budget set.".into()],
            },
            Section {
                title: "Batch Concurrency Tuning".into(),
                content: "Optimize concurrency settings for throughput vs. rate limits.".into(),
                examples: vec![Example {
                    description: "Benchmark optimal concurrency".into(),
                    command: "fwc bench --connector github --concurrency 1,2,4,8".into(),
                    expected_output:
                        "Concurrency 4: 120 ops/s (optimal)\nConcurrency 8: 95 ops/s (rate-limited)"
                            .into(),
                    explanation: "Tests different concurrency levels to find the sweet spot."
                        .into(),
                }],
                warnings: vec![],
                tips: vec!["Start with concurrency=2 and increase gradually.".into()],
            },
            Section {
                title: "Response Caching".into(),
                content: "Enable caching for idempotent read operations to reduce latency.".into(),
                examples: vec![Example {
                    description: "Enable caching for a connector".into(),
                    command: "fwc cache enable github --ttl 60s".into(),
                    expected_output: "Caching enabled for github (TTL: 60s)".into(),
                    explanation: "Caches responses for read operations for 60 seconds.".into(),
                }],
                warnings: vec!["Only cache idempotent operations.".into()],
                tips: vec!["Use fwc cache stats to monitor hit rates.".into()],
            },
        ],
    }
}

fn playbook_agent_integration() -> Playbook {
    Playbook {
        id: "agent-integration".into(),
        title: "Configuring FWC for AI Agent Workflows".into(),
        audience: Audience::Agent,
        category: PlaybookCategory::Integration,
        prerequisites: vec![
            "FWC installed and configured".into(),
            "MCP server capability available".into(),
        ],
        related_playbooks: vec!["pipeline-authoring".into(), "security-hardening".into()],
        sections: vec![
            Section {
                title: "MCP Server Mode".into(),
                content: "Run fwc as an MCP server to expose connector operations as tools.".into(),
                examples: vec![Example {
                    description: "Start MCP server".into(),
                    command: "fwc serve-mcp --port 8080".into(),
                    expected_output: "MCP server listening on :8080 (23 tools exported)".into(),
                    explanation: "Starts an MCP server that exposes all connector ops as tools."
                        .into(),
                }],
                warnings: vec!["MCP server inherits the credentials of the host process.".into()],
                tips: vec!["Use --export-filter to limit which operations are exposed.".into()],
            },
            Section {
                title: "Intent Resolution".into(),
                content: "Let fwc resolve natural-language intents to connector operations.".into(),
                examples: vec![Example {
                    description: "Resolve an intent".into(),
                    command: "fwc intent resolve 'create a github issue about login bug'".into(),
                    expected_output: "Resolved: github.create_issue (confidence: 0.94)".into(),
                    explanation: "Maps the natural language query to the best matching operation."
                        .into(),
                }],
                warnings: vec![],
                tips: vec!["Use --top-k 3 to see alternative matches.".into()],
            },
            Section {
                title: "Agent Coordination".into(),
                content: "Coordinate multiple agents accessing the same connector fleet.".into(),
                examples: vec![Example {
                    description: "Check agent coordination status".into(),
                    command: "fwc agent-coord status".into(),
                    expected_output: "Active agents: 3, Lock contention: 0, Queue depth: 2".into(),
                    explanation: "Shows multi-agent coordination metrics.".into(),
                }],
                warnings: vec![],
                tips: vec!["Use op-lock to prevent conflicting mutations.".into()],
            },
        ],
    }
}

fn playbook_connector_development() -> Playbook {
    Playbook {
        id: "connector-development".into(),
        title: "Building and Testing New Connectors".into(),
        audience: Audience::Developer,
        category: PlaybookCategory::Advanced,
        prerequisites: vec![
            "Rust nightly toolchain installed".into(),
            "FCP SDK available".into(),
        ],
        related_playbooks: vec![
            "migration-fcp2-to-fcp3".into(),
            "security-hardening".into(),
        ],
        sections: vec![
            Section {
                title: "Scaffold a New Connector".into(),
                content: "Use fwc new to generate a connector project from a template.".into(),
                examples: vec![Example {
                    description: "Create a new connector".into(),
                    command: "fwc new my-api --template rest".into(),
                    expected_output: "Created connector project at connectors/my-api/".into(),
                    explanation: "Generates a REST connector scaffold with main.rs, lib.rs, manifest, and test stubs.".into(),
                }],
                warnings: vec![],
                tips: vec!["Templates: rest, graphql, grpc, websocket.".into()],
            },
            Section {
                title: "Implement Operations".into(),
                content: "Define operations using OperationInfo and implement the dispatch function.".into(),
                examples: vec![Example {
                    description: "Run connector tests".into(),
                    command: "cargo test -p my-api".into(),
                    expected_output: "test result: ok. 25 passed; 0 failed".into(),
                    explanation: "Runs unit and integration tests for the connector.".into(),
                }],
                warnings: vec![
                    "Every operation must have at least one happy-path test.".into(),
                ],
                tips: vec!["Use wiremock::MockServer for HTTP mocking.".into()],
            },
            Section {
                title: "Validate and Package".into(),
                content: "Validate the manifest and package the connector for distribution.".into(),
                examples: vec![Example {
                    description: "Package the connector".into(),
                    command: "fwc package build my-api --sign".into(),
                    expected_output: "Package built: my-api-0.1.0.fcp (signed, 2.3 MB)".into(),
                    explanation: "Builds, signs, and packages the connector for deployment.".into(),
                }],
                warnings: vec!["Always sign packages for production deployment.".into()],
                tips: vec![],
            },
        ],
    }
}

fn playbook_pipeline_authoring() -> Playbook {
    Playbook {
        id: "pipeline-authoring".into(),
        title: "Defining and Running Multi-Step Pipelines".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::Advanced,
        prerequisites: vec![
            "Familiarity with fwc invoke and batch".into(),
            "At least two connectors configured".into(),
        ],
        related_playbooks: vec!["batch-operations".into(), "agent-integration".into()],
        sections: vec![
            Section {
                title: "Define a Pipeline".into(),
                content:
                    "Create a TOML pipeline definition with steps, dependencies, and data flow."
                        .into(),
                examples: vec![Example {
                    description: "Create a simple pipeline".into(),
                    command: "fwc pipeline validate my-pipeline.toml".into(),
                    expected_output: "Pipeline valid: 4 steps, 2 connectors, no cycles".into(),
                    explanation: "Validates pipeline structure and dependency graph.".into(),
                }],
                warnings: vec!["Circular dependencies will cause validation failure.".into()],
                tips: vec!["Use fwc pipeline visualize to see the DAG.".into()],
            },
            Section {
                title: "Run a Pipeline".into(),
                content: "Execute a pipeline with error handling and conditional branching.".into(),
                examples: vec![Example {
                    description: "Run a pipeline".into(),
                    command: "fwc pipeline run my-pipeline.toml --env prod".into(),
                    expected_output: "Pipeline complete: 4/4 steps succeeded (12.3s)".into(),
                    explanation: "Executes all pipeline steps in dependency order.".into(),
                }],
                warnings: vec![],
                tips: vec!["Use --resume to restart from a failed step.".into()],
            },
            Section {
                title: "Pipeline Templates".into(),
                content: "Use parameterized pipeline templates for reusable workflows.".into(),
                examples: vec![Example {
                    description: "Instantiate a pipeline template".into(),
                    command: "fwc pipeline from-template deploy --set version=1.2.3".into(),
                    expected_output:
                        "Pipeline instantiated from template 'deploy' with version=1.2.3".into(),
                    explanation:
                        "Creates a pipeline instance from a template with parameter substitution."
                            .into(),
                }],
                warnings: vec![],
                tips: vec!["Templates support Handlebars syntax for variable substitution.".into()],
            },
        ],
    }
}

fn playbook_fleet_management() -> Playbook {
    Playbook {
        id: "fleet-management".into(),
        title: "Managing Connector Fleets at Scale".into(),
        audience: Audience::Operator,
        category: PlaybookCategory::Advanced,
        prerequisites: vec![
            "Multiple connectors deployed".into(),
            "Admin access to host".into(),
        ],
        related_playbooks: vec![
            "security-hardening".into(),
            "performance-tuning".into(),
            "troubleshooting-connectivity".into(),
        ],
        sections: vec![
            Section {
                title: "Fleet Overview".into(),
                content: "Get a high-level view of all connectors in the fleet.".into(),
                examples: vec![Example {
                    description: "List fleet status".into(),
                    command: "fwc catalog list --format table".into(),
                    expected_output: "Connector       Status    Ops   Health\ngithub          Running   5     healthy\nslack           Running   8     healthy\njira            Degraded  24    auth_issue".into(),
                    explanation: "Tabular view of all connectors with health indicators.".into(),
                }],
                warnings: vec![],
                tips: vec!["Use --filter status=degraded to focus on problems.".into()],
            },
            Section {
                title: "Lifecycle Management".into(),
                content: "Enable, disable, and restart connectors across the fleet.".into(),
                examples: vec![Example {
                    description: "Restart a degraded connector".into(),
                    command: "fwc lifecycle restart jira --reason 'auth refresh'".into(),
                    expected_output: "jira: Stopping... Stopped. Starting... Running (1.2s)".into(),
                    explanation: "Gracefully restarts the jira connector with an audit reason.".into(),
                }],
                warnings: vec![
                    "Force-stop will drop in-flight operations.".into(),
                ],
                tips: vec!["Use --drain-timeout 30s for graceful shutdown.".into()],
            },
            Section {
                title: "Rolling Updates".into(),
                content: "Update connectors with zero-downtime rolling deployment.".into(),
                examples: vec![Example {
                    description: "Rolling update".into(),
                    command: "fwc fleet update github --version 2.1.0 --strategy rolling".into(),
                    expected_output: "Rolling update: 3/3 instances updated (0 downtime)".into(),
                    explanation: "Updates connector instances one at a time to avoid downtime.".into(),
                }],
                warnings: vec![
                    "Rollback with fwc fleet rollback if health checks fail.".into(),
                ],
                tips: vec![],
            },
        ],
    }
}

// ── Built-in migration guides ─────────────────────────────────────────

/// Returns the set of built-in migration guides shipped with FWC.
pub fn get_migration_guides() -> Vec<MigrationGuide> {
    vec![
        migration_fcp2_to_fcp3(),
        migration_fcp3_0_to_3_1(),
        migration_fcp3_1_to_3_2(),
    ]
}

fn migration_fcp2_to_fcp3() -> MigrationGuide {
    MigrationGuide {
        from_version: "FCP 2.x".into(),
        to_version: "FCP 3.0".into(),
        breaking_changes: vec![
            BreakingChange {
                component: "Connector manifest".into(),
                description: "Manifest format changed from JSON to TOML with typed operations"
                    .into(),
                migration_path: "Convert manifest.json to manifest.toml using fwc migrate manifest"
                    .into(),
                before_code: r#"{"operations": [{"name": "list"}]}"#.into(),
                after_code: r#"[[operations]]\nname = "list"\ntier = "observe""#.into(),
            },
            BreakingChange {
                component: "fwc invoke".into(),
                description: "Operation names must be fully qualified (connector.operation)".into(),
                migration_path: "Prefix bare operation names with connector ID".into(),
                before_code: "fwc invoke list_repos".into(),
                after_code: "fwc invoke github list_repos".into(),
            },
            BreakingChange {
                component: "Capability tokens".into(),
                description: "Plain JWT tokens replaced with COSE-signed capability tokens".into(),
                migration_path: "Regenerate tokens using fwc auth issue-token".into(),
                before_code: "Authorization: Bearer eyJhbG...".into(),
                after_code: "fwc invoke --cap-token cap.cose github list_repos".into(),
            },
        ],
        migration_steps: vec![
            "Back up existing configuration and credentials".into(),
            "Install FCP 3.0 SDK and fwc CLI".into(),
            "Convert manifests: fwc migrate manifest *.json".into(),
            "Update connector source to implement introspect()".into(),
            "Regenerate capability tokens with fwc auth issue-token".into(),
            "Run fwc validate manifest on all converted manifests".into(),
            "Run integration tests against the new host".into(),
            "Deploy connectors to staging and verify health".into(),
            "Cut over production traffic".into(),
        ],
        rollback_plan: vec![
            "Keep FCP2 host running in parallel during migration".into(),
            "Restore backed-up configuration files".into(),
            "Revert DNS/routing to FCP2 host".into(),
            "Re-issue FCP2 JWT tokens if needed".into(),
        ],
        estimated_effort: MigrationEffort::High,
    }
}

fn migration_fcp3_0_to_3_1() -> MigrationGuide {
    MigrationGuide {
        from_version: "FCP 3.0".into(),
        to_version: "FCP 3.1".into(),
        breaking_changes: vec![
            BreakingChange {
                component: "SafetyTier".into(),
                description: "SafetyTier::ReadOnly renamed to SafetyTier::Observe".into(),
                migration_path: "Find-and-replace ReadOnly with Observe in connector source".into(),
                before_code: "SafetyTier::ReadOnly".into(),
                after_code: "SafetyTier::Observe".into(),
            },
            BreakingChange {
                component: "Batch API".into(),
                description: "Batch response format now includes per-operation timing".into(),
                migration_path: "Update batch response parsers to handle timing field".into(),
                before_code: r#"{"results": [{"status": "ok"}]}"#.into(),
                after_code: r#"{"results": [{"status": "ok", "duration_ms": 142}]}"#.into(),
            },
        ],
        migration_steps: vec![
            "Update fwc CLI to 3.1".into(),
            "Search connector source for SafetyTier::ReadOnly and replace".into(),
            "Update batch response parsing if used programmatically".into(),
            "Re-run test suite to catch any breakage".into(),
            "Deploy updated connectors".into(),
        ],
        rollback_plan: vec![
            "Revert fwc CLI to 3.0".into(),
            "Restore previous connector binaries".into(),
        ],
        estimated_effort: MigrationEffort::Low,
    }
}

fn migration_fcp3_1_to_3_2() -> MigrationGuide {
    MigrationGuide {
        from_version: "FCP 3.1".into(),
        to_version: "FCP 3.2".into(),
        breaking_changes: vec![
            BreakingChange {
                component: "Mesh protocol".into(),
                description: "Mesh node registration now requires zone declaration".into(),
                migration_path: "Add zone_id to mesh registration config".into(),
                before_code: r#"[mesh]\nnode_id = "node-1""#.into(),
                after_code: r#"[mesh]\nnode_id = "node-1"\nzone_id = "us-east-1""#.into(),
            },
            BreakingChange {
                component: "fwc pipeline".into(),
                description: "Pipeline TOML schema v2 with conditional branching".into(),
                migration_path: "Add schema_version = 2 to pipeline files".into(),
                before_code: "[pipeline]\nname = \"deploy\"".into(),
                after_code: "[pipeline]\nname = \"deploy\"\nschema_version = 2".into(),
            },
            BreakingChange {
                component: "OperationInfo".into(),
                description: "OperationInfo now requires idempotency_class field".into(),
                migration_path: "Add IdempotencyClass to all OperationInfo declarations".into(),
                before_code: "OperationInfo { name: \"list\", tier: Observe, .. }".into(),
                after_code: "OperationInfo { name: \"list\", tier: Observe, idempotency: IdempotencyClass::ReadOnly, .. }".into(),
            },
        ],
        migration_steps: vec![
            "Update fwc CLI to 3.2".into(),
            "Add zone_id to mesh configuration".into(),
            "Add schema_version = 2 to all pipeline TOML files".into(),
            "Add idempotency_class to all OperationInfo declarations".into(),
            "Run fwc validate manifest on all connectors".into(),
            "Run test suite".into(),
            "Deploy updated connectors and host".into(),
        ],
        rollback_plan: vec![
            "Revert fwc CLI to 3.1".into(),
            "Remove zone_id from mesh config (optional, backward-compatible)".into(),
            "Restore previous connector binaries".into(),
        ],
        estimated_effort: MigrationEffort::Medium,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Audience tests ────────────────────────────────────────────────

    #[test]
    fn audience_label_operator() {
        assert_eq!(Audience::Operator.label(), "Operator");
    }

    #[test]
    fn audience_label_agent() {
        assert_eq!(Audience::Agent.label(), "Agent");
    }

    #[test]
    fn audience_label_developer() {
        assert_eq!(Audience::Developer.label(), "Developer");
    }

    #[test]
    fn audience_display() {
        assert_eq!(format!("{}", Audience::Operator), "Operator");
        assert_eq!(format!("{}", Audience::Agent), "Agent");
        assert_eq!(format!("{}", Audience::Developer), "Developer");
    }

    #[test]
    fn audience_all_variants() {
        let all = Audience::all();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&Audience::Operator));
        assert!(all.contains(&Audience::Agent));
        assert!(all.contains(&Audience::Developer));
    }

    #[test]
    fn audience_serde_roundtrip() {
        let json = serde_json::to_string(&Audience::Agent).unwrap();
        let back: Audience = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Audience::Agent);
    }

    #[test]
    fn audience_clone_eq() {
        let a = Audience::Developer;
        let b = a;
        assert_eq!(a, b);
    }

    // ── PlaybookCategory tests ────────────────────────────────────────

    #[test]
    fn category_label_all_variants() {
        assert_eq!(PlaybookCategory::GettingStarted.label(), "Getting Started");
        assert_eq!(
            PlaybookCategory::DailyOperations.label(),
            "Daily Operations"
        );
        assert_eq!(PlaybookCategory::Troubleshooting.label(), "Troubleshooting");
        assert_eq!(PlaybookCategory::Migration.label(), "Migration");
        assert_eq!(PlaybookCategory::Security.label(), "Security");
        assert_eq!(PlaybookCategory::Performance.label(), "Performance");
        assert_eq!(PlaybookCategory::Integration.label(), "Integration");
        assert_eq!(PlaybookCategory::Advanced.label(), "Advanced");
    }

    #[test]
    fn category_display() {
        assert_eq!(
            format!("{}", PlaybookCategory::Troubleshooting),
            "Troubleshooting"
        );
    }

    #[test]
    fn category_all_has_eight() {
        assert_eq!(PlaybookCategory::all().len(), 8);
    }

    #[test]
    fn category_serde_roundtrip() {
        let json = serde_json::to_string(&PlaybookCategory::Security).unwrap();
        let back: PlaybookCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PlaybookCategory::Security);
    }

    #[test]
    fn category_hash_and_eq() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PlaybookCategory::Migration);
        set.insert(PlaybookCategory::Migration);
        assert_eq!(set.len(), 1);
    }

    // ── Example tests ─────────────────────────────────────────────────

    #[test]
    fn example_is_valid_all_populated() {
        let ex = Example {
            description: "test".into(),
            command: "fwc test".into(),
            expected_output: "ok".into(),
            explanation: "runs a test".into(),
        };
        assert!(ex.is_valid());
    }

    #[test]
    fn example_is_invalid_empty_description() {
        let ex = Example {
            description: String::new(),
            command: "fwc test".into(),
            expected_output: "ok".into(),
            explanation: "runs a test".into(),
        };
        assert!(!ex.is_valid());
    }

    #[test]
    fn example_is_invalid_empty_command() {
        let ex = Example {
            description: "test".into(),
            command: String::new(),
            expected_output: "ok".into(),
            explanation: "runs a test".into(),
        };
        assert!(!ex.is_valid());
    }

    #[test]
    fn example_is_invalid_empty_output() {
        let ex = Example {
            description: "test".into(),
            command: "fwc test".into(),
            expected_output: String::new(),
            explanation: "runs a test".into(),
        };
        assert!(!ex.is_valid());
    }

    #[test]
    fn example_is_invalid_empty_explanation() {
        let ex = Example {
            description: "test".into(),
            command: "fwc test".into(),
            expected_output: "ok".into(),
            explanation: String::new(),
        };
        assert!(!ex.is_valid());
    }

    #[test]
    fn example_clone() {
        let ex = Example {
            description: "test".into(),
            command: "fwc test".into(),
            expected_output: "ok".into(),
            explanation: "runs a test".into(),
        };
        let cloned = ex.clone();
        assert_eq!(cloned.description, ex.description);
        assert_eq!(cloned.command, ex.command);
    }

    #[test]
    fn example_serde_roundtrip() {
        let ex = Example {
            description: "test".into(),
            command: "fwc test".into(),
            expected_output: "ok".into(),
            explanation: "does something".into(),
        };
        let json = serde_json::to_string(&ex).unwrap();
        let back: Example = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command, "fwc test");
    }

    // ── Section tests ─────────────────────────────────────────────────

    #[test]
    fn section_empty_optional_fields() {
        let sec = Section {
            title: "Intro".into(),
            content: "Welcome".into(),
            examples: vec![],
            warnings: vec![],
            tips: vec![],
        };
        assert!(sec.examples.is_empty());
        assert!(sec.warnings.is_empty());
        assert!(sec.tips.is_empty());
    }

    #[test]
    fn section_with_warnings_and_tips() {
        let sec = Section {
            title: "Safety".into(),
            content: "Be careful.".into(),
            examples: vec![],
            warnings: vec!["Do not delete prod.".into()],
            tips: vec!["Use --dry-run first.".into()],
        };
        assert_eq!(sec.warnings.len(), 1);
        assert_eq!(sec.tips.len(), 1);
    }

    #[test]
    fn section_serde_roundtrip() {
        let sec = Section {
            title: "Test".into(),
            content: "Content".into(),
            examples: vec![],
            warnings: vec!["warn".into()],
            tips: vec![],
        };
        let json = serde_json::to_string(&sec).unwrap();
        let back: Section = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, "Test");
        assert_eq!(back.warnings, vec!["warn"]);
    }

    // ── Playbook tests ────────────────────────────────────────────────

    #[test]
    fn playbook_keywords_include_title() {
        let pb = playbook_getting_started();
        let kw = pb.keywords();
        assert!(kw.contains(&"first-time".to_owned()));
        assert!(kw.contains(&"setup".to_owned()));
    }

    #[test]
    fn playbook_keywords_include_category() {
        let pb = playbook_getting_started();
        let kw = pb.keywords();
        assert!(kw.contains(&"getting".to_owned()));
        assert!(kw.contains(&"started".to_owned()));
    }

    #[test]
    fn playbook_example_count() {
        let pb = playbook_getting_started();
        assert!(pb.example_count() >= 3);
    }

    #[test]
    fn playbook_all_examples_valid() {
        let pb = playbook_getting_started();
        assert!(pb.all_examples_valid());
    }

    #[test]
    fn playbook_serde_roundtrip() {
        let pb = playbook_getting_started();
        let json = serde_json::to_string(&pb).unwrap();
        let back: Playbook = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "getting-started");
    }

    #[test]
    fn playbook_related_playbooks() {
        let pb = playbook_getting_started();
        assert!(pb.related_playbooks.contains(&"daily-ops".to_owned()));
    }

    #[test]
    fn playbook_prerequisites_present() {
        let pb = playbook_getting_started();
        assert!(!pb.prerequisites.is_empty());
    }

    // ── Builtin playbooks tests ───────────────────────────────────────

    #[test]
    fn builtin_playbooks_count() {
        let pbs = get_builtin_playbooks();
        assert!(
            pbs.len() >= 12,
            "expected >= 12 playbooks, got {}",
            pbs.len()
        );
    }

    #[test]
    fn builtin_playbooks_unique_ids() {
        let pbs = get_builtin_playbooks();
        let mut ids: Vec<&str> = pbs.iter().map(|p| p.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), pbs.len(), "duplicate playbook IDs found");
    }

    #[test]
    fn builtin_playbooks_have_sections() {
        for pb in get_builtin_playbooks() {
            assert!(
                !pb.sections.is_empty(),
                "playbook '{}' has no sections",
                pb.id
            );
        }
    }

    #[test]
    fn builtin_playbooks_all_examples_valid() {
        for pb in get_builtin_playbooks() {
            assert!(
                pb.all_examples_valid(),
                "playbook '{}' has invalid examples",
                pb.id
            );
        }
    }

    #[test]
    fn builtin_playbooks_have_examples() {
        for pb in get_builtin_playbooks() {
            assert!(
                pb.example_count() > 0,
                "playbook '{}' has no examples",
                pb.id
            );
        }
    }

    #[test]
    fn builtin_playbooks_cover_multiple_audiences() {
        let pbs = get_builtin_playbooks();
        let audiences: std::collections::HashSet<Audience> =
            pbs.iter().map(|p| p.audience).collect();
        assert!(audiences.len() >= 2);
    }

    #[test]
    fn builtin_playbooks_cover_multiple_categories() {
        let pbs = get_builtin_playbooks();
        let cats: std::collections::HashSet<PlaybookCategory> =
            pbs.iter().map(|p| p.category).collect();
        assert!(cats.len() >= 5);
    }

    #[test]
    fn builtin_getting_started_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "getting-started"));
    }

    #[test]
    fn builtin_daily_ops_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "daily-ops"));
    }

    #[test]
    fn builtin_troubleshooting_auth_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "troubleshooting-auth"));
    }

    #[test]
    fn builtin_troubleshooting_connectivity_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "troubleshooting-connectivity"));
    }

    #[test]
    fn builtin_batch_operations_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "batch-operations"));
    }

    #[test]
    fn builtin_migration_fcp2_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "migration-fcp2-to-fcp3"));
    }

    #[test]
    fn builtin_security_hardening_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "security-hardening"));
    }

    #[test]
    fn builtin_performance_tuning_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "performance-tuning"));
    }

    #[test]
    fn builtin_agent_integration_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "agent-integration"));
    }

    #[test]
    fn builtin_connector_development_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "connector-development"));
    }

    #[test]
    fn builtin_pipeline_authoring_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "pipeline-authoring"));
    }

    #[test]
    fn builtin_fleet_management_exists() {
        let pbs = get_builtin_playbooks();
        assert!(pbs.iter().any(|p| p.id == "fleet-management"));
    }

    // ── BreakingChange tests ──────────────────────────────────────────

    #[test]
    fn breaking_change_serde_roundtrip() {
        let bc = BreakingChange {
            component: "fwc invoke".into(),
            description: "Changed args".into(),
            migration_path: "Update scripts".into(),
            before_code: "old".into(),
            after_code: "new".into(),
        };
        let json = serde_json::to_string(&bc).unwrap();
        let back: BreakingChange = serde_json::from_str(&json).unwrap();
        assert_eq!(back.component, "fwc invoke");
    }

    #[test]
    fn breaking_change_clone() {
        let bc = BreakingChange {
            component: "manifest".into(),
            description: "format change".into(),
            migration_path: "convert".into(),
            before_code: "json".into(),
            after_code: "toml".into(),
        };
        let cloned = bc.clone();
        assert_eq!(cloned.component, bc.component);
    }

    // ── MigrationEffort tests ─────────────────────────────────────────

    #[test]
    fn migration_effort_labels() {
        assert!(MigrationEffort::Low.label().contains("30 min"));
        assert!(MigrationEffort::Medium.label().contains("2 hr"));
        assert!(MigrationEffort::High.label().contains("2+"));
    }

    #[test]
    fn migration_effort_display() {
        assert_eq!(
            format!("{}", MigrationEffort::Low),
            MigrationEffort::Low.label()
        );
    }

    #[test]
    fn migration_effort_serde_roundtrip() {
        let json = serde_json::to_string(&MigrationEffort::Medium).unwrap();
        let back: MigrationEffort = serde_json::from_str(&json).unwrap();
        assert_eq!(back, MigrationEffort::Medium);
    }

    // ── MigrationGuide tests ──────────────────────────────────────────

    #[test]
    fn migration_guide_version_range() {
        let g = migration_fcp2_to_fcp3();
        assert_eq!(g.version_range(), "FCP 2.x -> FCP 3.0");
    }

    #[test]
    fn migration_guide_has_breaking_changes() {
        let g = migration_fcp2_to_fcp3();
        assert!(!g.breaking_changes.is_empty());
    }

    #[test]
    fn migration_guide_has_steps() {
        let g = migration_fcp2_to_fcp3();
        assert!(!g.migration_steps.is_empty());
    }

    #[test]
    fn migration_guide_has_rollback() {
        let g = migration_fcp2_to_fcp3();
        assert!(!g.rollback_plan.is_empty());
    }

    #[test]
    fn migration_guide_serde_roundtrip() {
        let g = migration_fcp2_to_fcp3();
        let json = serde_json::to_string(&g).unwrap();
        let back: MigrationGuide = serde_json::from_str(&json).unwrap();
        assert_eq!(back.from_version, "FCP 2.x");
        assert_eq!(back.to_version, "FCP 3.0");
    }

    // ── Builtin migration guides tests ────────────────────────────────

    #[test]
    fn migration_guides_count() {
        let guides = get_migration_guides();
        assert!(guides.len() >= 3);
    }

    #[test]
    fn migration_guides_all_have_steps() {
        for g in get_migration_guides() {
            assert!(
                !g.migration_steps.is_empty(),
                "{} has no steps",
                g.version_range()
            );
        }
    }

    #[test]
    fn migration_guides_all_have_rollback() {
        for g in get_migration_guides() {
            assert!(
                !g.rollback_plan.is_empty(),
                "{} has no rollback",
                g.version_range()
            );
        }
    }

    #[test]
    fn migration_guides_all_have_breaking_changes() {
        for g in get_migration_guides() {
            assert!(
                !g.breaking_changes.is_empty(),
                "{} has no breaking changes",
                g.version_range()
            );
        }
    }

    #[test]
    fn migration_guides_version_chain() {
        let guides = get_migration_guides();
        // Verify we cover FCP 2.x -> 3.0, 3.0 -> 3.1, 3.1 -> 3.2
        let ranges: Vec<String> = guides.iter().map(|g| g.version_range()).collect();
        assert!(
            ranges
                .iter()
                .any(|r| r.contains("2.x") && r.contains("3.0"))
        );
        assert!(
            ranges
                .iter()
                .any(|r| r.contains("3.0") && r.contains("3.1"))
        );
        assert!(
            ranges
                .iter()
                .any(|r| r.contains("3.1") && r.contains("3.2"))
        );
    }

    // ── PlaybookIndex tests ───────────────────────────────────────────

    #[test]
    fn index_new_builds_maps() {
        let pbs = get_builtin_playbooks();
        let idx = PlaybookIndex::new(pbs);
        assert!(!idx.by_category.is_empty());
        assert!(!idx.by_audience.is_empty());
    }

    #[test]
    fn index_len() {
        let pbs = get_builtin_playbooks();
        let len = pbs.len();
        let idx = PlaybookIndex::new(pbs);
        assert_eq!(idx.len(), len);
    }

    #[test]
    fn index_is_empty_false() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        assert!(!idx.is_empty());
    }

    #[test]
    fn index_is_empty_true() {
        let idx = PlaybookIndex::new(vec![]);
        assert!(idx.is_empty());
    }

    #[test]
    fn index_find_by_category_getting_started() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.find_by_category(PlaybookCategory::GettingStarted);
        assert!(!found.is_empty());
        for pb in &found {
            assert_eq!(pb.category, PlaybookCategory::GettingStarted);
        }
    }

    #[test]
    fn index_find_by_category_troubleshooting() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.find_by_category(PlaybookCategory::Troubleshooting);
        assert!(found.len() >= 2, "expected >= 2 troubleshooting playbooks");
    }

    #[test]
    fn index_find_by_category_empty_result() {
        let pbs = vec![playbook_getting_started()];
        let idx = PlaybookIndex::new(pbs);
        let found = idx.find_by_category(PlaybookCategory::Migration);
        assert!(found.is_empty());
    }

    #[test]
    fn index_find_by_audience_operator() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.find_by_audience(Audience::Operator);
        assert!(!found.is_empty());
        for pb in &found {
            assert_eq!(pb.audience, Audience::Operator);
        }
    }

    #[test]
    fn index_find_by_audience_agent() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.find_by_audience(Audience::Agent);
        assert!(!found.is_empty());
    }

    #[test]
    fn index_find_by_audience_developer() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.find_by_audience(Audience::Developer);
        assert!(!found.is_empty());
    }

    #[test]
    fn index_find_by_audience_empty_result() {
        // An index with no Agent playbooks
        let pbs = vec![playbook_getting_started()]; // Operator audience
        let idx = PlaybookIndex::new(pbs);
        let found = idx.find_by_audience(Audience::Agent);
        assert!(found.is_empty());
    }

    #[test]
    fn index_find_by_id_found() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let pb = idx.find_by_id("getting-started");
        assert!(pb.is_some());
        assert_eq!(pb.unwrap().id, "getting-started");
    }

    #[test]
    fn index_find_by_id_not_found() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        assert!(idx.find_by_id("nonexistent").is_none());
    }

    #[test]
    fn index_search_single_term() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("auth");
        assert!(!found.is_empty(), "search for 'auth' should find results");
    }

    #[test]
    fn index_search_multi_term() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("connector health");
        assert!(
            !found.is_empty(),
            "search for 'connector health' should find results"
        );
    }

    #[test]
    fn index_search_empty_query() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("");
        assert!(found.is_empty());
    }

    #[test]
    fn index_search_whitespace_only() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("   ");
        assert!(found.is_empty());
    }

    #[test]
    fn index_search_no_match() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("zzzzxyzzy12345");
        assert!(found.is_empty());
    }

    #[test]
    fn index_search_case_insensitive() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let lower = idx.search("security");
        let upper = idx.search("SECURITY");
        assert_eq!(lower.len(), upper.len());
    }

    #[test]
    fn index_search_partial_word() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("migrat");
        assert!(
            !found.is_empty(),
            "partial word 'migrat' should match migration playbooks"
        );
    }

    #[test]
    fn index_serde_roundtrip() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let json = serde_json::to_string(&idx).unwrap();
        let back: PlaybookIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), idx.len());
    }

    // ── TOON formatting tests ─────────────────────────────────────────

    #[test]
    fn format_playbook_toon_contains_title() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("First-Time FWC Setup"));
    }

    #[test]
    fn format_playbook_toon_contains_id() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("getting-started"));
    }

    #[test]
    fn format_playbook_toon_contains_audience() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Operator"));
    }

    #[test]
    fn format_playbook_toon_contains_category() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Getting Started"));
    }

    #[test]
    fn format_playbook_toon_contains_sections() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("1. Verify Installation"));
        assert!(out.contains("2. Discover Connectors"));
    }

    #[test]
    fn format_playbook_toon_contains_examples() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("$ fwc --version"));
    }

    #[test]
    fn format_playbook_toon_contains_prerequisites() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("Prerequisites:"));
        assert!(out.contains("FWC binary installed"));
    }

    #[test]
    fn format_playbook_toon_contains_related() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("See also:"));
        assert!(out.contains("daily-ops"));
    }

    #[test]
    fn format_playbook_toon_contains_warnings() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("WARNING:"));
    }

    #[test]
    fn format_playbook_toon_contains_tips() {
        let pb = playbook_getting_started();
        let out = format_playbook_toon(&pb);
        assert!(out.contains("TIP:"));
    }

    #[test]
    fn format_playbook_toon_no_prerequisites_no_section() {
        let pb = Playbook {
            id: "test".into(),
            title: "Test".into(),
            audience: Audience::Operator,
            category: PlaybookCategory::GettingStarted,
            sections: vec![Section {
                title: "S".into(),
                content: "C".into(),
                examples: vec![],
                warnings: vec![],
                tips: vec![],
            }],
            prerequisites: vec![],
            related_playbooks: vec![],
        };
        let out = format_playbook_toon(&pb);
        assert!(!out.contains("Prerequisites:"));
        assert!(!out.contains("See also:"));
    }

    #[test]
    fn format_playbook_toon_all_builtins() {
        for pb in get_builtin_playbooks() {
            let out = format_playbook_toon(&pb);
            assert!(
                out.contains(&pb.title),
                "TOON for '{}' missing title",
                pb.id
            );
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn format_index_toon_contains_header() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let out = format_playbook_index_toon(&idx);
        assert!(out.contains("FWC Playbook Index"));
    }

    #[test]
    fn format_index_toon_contains_count() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let out = format_playbook_index_toon(&idx);
        assert!(out.contains("playbook(s) available"));
    }

    #[test]
    fn format_index_toon_contains_categories() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let out = format_playbook_index_toon(&idx);
        assert!(out.contains("[Getting Started]"));
        assert!(out.contains("[Troubleshooting]"));
    }

    #[test]
    fn format_index_toon_contains_playbook_ids() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let out = format_playbook_index_toon(&idx);
        assert!(out.contains("getting-started"));
        assert!(out.contains("daily-ops"));
    }

    #[test]
    fn format_index_toon_empty_index() {
        let idx = PlaybookIndex::new(vec![]);
        let out = format_playbook_index_toon(&idx);
        assert!(out.contains("0 playbook(s)"));
    }

    #[test]
    fn format_migration_guide_toon_header() {
        let g = migration_fcp2_to_fcp3();
        let out = format_migration_guide_toon(&g);
        assert!(out.contains("Migration Guide:"));
        assert!(out.contains("FCP 2.x -> FCP 3.0"));
    }

    #[test]
    fn format_migration_guide_toon_effort() {
        let g = migration_fcp2_to_fcp3();
        let out = format_migration_guide_toon(&g);
        assert!(out.contains("Estimated effort:"));
    }

    #[test]
    fn format_migration_guide_toon_breaking_changes() {
        let g = migration_fcp2_to_fcp3();
        let out = format_migration_guide_toon(&g);
        assert!(out.contains("Breaking Changes"));
        assert!(out.contains("Before:"));
        assert!(out.contains("After:"));
        assert!(out.contains("Migration:"));
    }

    #[test]
    fn format_migration_guide_toon_steps() {
        let g = migration_fcp2_to_fcp3();
        let out = format_migration_guide_toon(&g);
        assert!(out.contains("Migration Steps:"));
    }

    #[test]
    fn format_migration_guide_toon_rollback() {
        let g = migration_fcp2_to_fcp3();
        let out = format_migration_guide_toon(&g);
        assert!(out.contains("Rollback Plan:"));
    }

    #[test]
    fn format_migration_guide_toon_all_builtins() {
        for g in get_migration_guides() {
            let out = format_migration_guide_toon(&g);
            assert!(!out.is_empty(), "TOON for {} is empty", g.version_range());
            assert!(out.contains("Migration Guide:"));
        }
    }

    // ── Edge case tests ───────────────────────────────────────────────

    #[test]
    fn playbook_empty_sections() {
        let pb = Playbook {
            id: "empty".into(),
            title: "Empty".into(),
            audience: Audience::Operator,
            category: PlaybookCategory::GettingStarted,
            sections: vec![],
            prerequisites: vec![],
            related_playbooks: vec![],
        };
        assert_eq!(pb.example_count(), 0);
        assert!(pb.all_examples_valid()); // vacuously true
    }

    #[test]
    fn playbook_many_examples() {
        let examples: Vec<Example> = (0..50)
            .map(|i| Example {
                description: format!("ex-{i}"),
                command: format!("cmd-{i}"),
                expected_output: format!("out-{i}"),
                explanation: format!("explain-{i}"),
            })
            .collect();
        let pb = Playbook {
            id: "many".into(),
            title: "Many Examples".into(),
            audience: Audience::Developer,
            category: PlaybookCategory::Advanced,
            sections: vec![Section {
                title: "All".into(),
                content: "Lots of examples.".into(),
                examples,
                warnings: vec![],
                tips: vec![],
            }],
            prerequisites: vec![],
            related_playbooks: vec![],
        };
        assert_eq!(pb.example_count(), 50);
        assert!(pb.all_examples_valid());
    }

    #[test]
    fn index_single_playbook() {
        let idx = PlaybookIndex::new(vec![playbook_getting_started()]);
        assert_eq!(idx.len(), 1);
        let found = idx.find_by_category(PlaybookCategory::GettingStarted);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn search_finds_security_playbook() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("credential rotation");
        assert!(!found.is_empty());
    }

    #[test]
    fn search_finds_performance_playbook() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("budget");
        assert!(!found.is_empty());
    }

    #[test]
    fn search_finds_pipeline_playbook() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("pipeline");
        assert!(!found.is_empty());
    }

    #[test]
    fn search_finds_batch_playbook() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let found = idx.search("batch");
        assert!(!found.is_empty());
    }

    #[test]
    fn format_playbook_toon_expected_output_marker() {
        let pb = playbook_daily_ops();
        let out = format_playbook_toon(&pb);
        // Verify expected_output is shown with the > prefix
        assert!(out.contains("> "));
    }

    #[test]
    fn format_playbook_toon_explanation_marker() {
        let pb = playbook_daily_ops();
        let out = format_playbook_toon(&pb);
        // Verify explanation is shown with the # prefix
        assert!(out.contains("# "));
    }

    #[test]
    fn migration_guide_clone() {
        let g = migration_fcp2_to_fcp3();
        let cloned = g.clone();
        assert_eq!(cloned.from_version, g.from_version);
        assert_eq!(cloned.breaking_changes.len(), g.breaking_changes.len());
    }

    #[test]
    fn playbook_index_clone() {
        let idx = PlaybookIndex::new(get_builtin_playbooks());
        let cloned = idx.clone();
        assert_eq!(cloned.len(), idx.len());
    }

    #[test]
    fn category_all_order_stable() {
        let a = PlaybookCategory::all();
        let b = PlaybookCategory::all();
        assert_eq!(a, b);
    }

    #[test]
    fn audience_all_order_stable() {
        let a = Audience::all();
        let b = Audience::all();
        assert_eq!(a, b);
    }
}
