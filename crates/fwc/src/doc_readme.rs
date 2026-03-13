//! FWC command taxonomy and mental model documentation contract (bead 21.1).
//!
//! Encodes the FWC command taxonomy, mental model, and glossary as testable
//! structures so that documentation stays in sync with the actual CLI surface.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── Command Taxonomy ─────────────────────────────────────────────────────────

/// High-level category for a FWC command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandCategory {
    /// Commands that explore available connectors, operations, and schemas.
    Discovery,
    /// Commands that invoke operations against connectors.
    Execution,
    /// Commands that chain, batch, or pipeline operations.
    Workflow,
    /// Commands for host management, lifecycle, and policy.
    Administration,
    /// Commands about FWC itself (version, help, doctor).
    Meta,
    /// Commands for connector lifecycle (enable, disable, restart).
    Lifecycle,
    /// Commands for health, events, and observability.
    Monitoring,
}

impl CommandCategory {
    /// Short lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Execution => "execution",
            Self::Workflow => "workflow",
            Self::Administration => "administration",
            Self::Meta => "meta",
            Self::Lifecycle => "lifecycle",
            Self::Monitoring => "monitoring",
        }
    }

    /// All variants in definition order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Discovery,
            Self::Execution,
            Self::Workflow,
            Self::Administration,
            Self::Meta,
            Self::Lifecycle,
            Self::Monitoring,
        ]
    }

    /// Parse from lowercase label.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "discovery" => Some(Self::Discovery),
            "execution" => Some(Self::Execution),
            "workflow" => Some(Self::Workflow),
            "administration" => Some(Self::Administration),
            "meta" => Some(Self::Meta),
            "lifecycle" => Some(Self::Lifecycle),
            "monitoring" => Some(Self::Monitoring),
            _ => None,
        }
    }

    /// Human-readable description of this category.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Discovery => "Explore connectors, operations, schemas, and capabilities",
            Self::Execution => "Invoke operations against live or mock connectors",
            Self::Workflow => "Chain, batch, and pipeline operations together",
            Self::Administration => "Manage host configuration, policies, and credentials",
            Self::Meta => "Information about FWC itself",
            Self::Lifecycle => "Control connector lifecycle state transitions",
            Self::Monitoring => "Observe health, events, and resource usage",
        }
    }
}

impl std::fmt::Display for CommandCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Command Entry ────────────────────────────────────────────────────────────

/// A single command in the FWC taxonomy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandEntry {
    /// Command name as invoked (e.g. "search", "invoke", "pipeline run").
    pub name: String,
    /// Category this command belongs to.
    pub category: CommandCategory,
    /// One-line description.
    pub description: String,
    /// Usage synopsis (e.g. "fwc search <QUERY> [--connector <ID>]").
    pub synopsis: String,
    /// Whether this command is read-only (no side effects on the connector).
    pub is_read_only: bool,
    /// Whether this command requires a running host to function.
    pub requires_host: bool,
}

// ── Mental Model ─────────────────────────────────────────────────────────────

/// Description of a category for the mental model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryDescription {
    /// The category being described.
    pub category: CommandCategory,
    /// Narrative description of what this category is for.
    pub description: String,
    /// Commands that belong to this category.
    pub commands: Vec<String>,
    /// Typical flow / usage pattern for this category.
    pub typical_flow: String,
}

/// The FWC mental model: how the command-line is organized and why.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MentalModel {
    /// Category descriptions, one per category.
    pub categories: Vec<CategoryDescription>,
    /// Core principles governing FWC design.
    pub principles: Vec<String>,
    /// Glossary of FWC terms: (term, definition).
    pub glossary: Vec<(String, String)>,
}

// ── Taxonomy Data ────────────────────────────────────────────────────────────

/// Returns the canonical FWC command taxonomy (at least 30 entries).
#[must_use]
pub fn get_command_taxonomy() -> Vec<CommandEntry> {
    vec![
        // ── Discovery ────────────────────────────────────────────────
        CommandEntry {
            name: "search".into(),
            category: CommandCategory::Discovery,
            description: "Search for connectors and operations by keyword".into(),
            synopsis: "fwc search <QUERY> [--connector <ID>]".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "introspect".into(),
            category: CommandCategory::Discovery,
            description: "List operations exposed by a connector".into(),
            synopsis: "fwc introspect <CONNECTOR>".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "schema".into(),
            category: CommandCategory::Discovery,
            description: "Show input/output schema for an operation".into(),
            synopsis: "fwc schema <CONNECTOR> <OPERATION>".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "catalog".into(),
            category: CommandCategory::Discovery,
            description: "Browse the connector catalog with filters".into(),
            synopsis: "fwc catalog [--category <CAT>] [--format <FMT>]".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "manifest show".into(),
            category: CommandCategory::Discovery,
            description: "Display a connector manifest".into(),
            synopsis: "fwc manifest show <CONNECTOR>".into(),
            is_read_only: true,
            requires_host: false,
        },
        // ── Execution ────────────────────────────────────────────────
        CommandEntry {
            name: "invoke".into(),
            category: CommandCategory::Execution,
            description: "Invoke a single operation on a connector".into(),
            synopsis: "fwc invoke <CONNECTOR> <OPERATION> [--input <JSON>]".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "batch".into(),
            category: CommandCategory::Execution,
            description: "Execute multiple operations in one batch request".into(),
            synopsis: "fwc batch <FILE> [--parallel <N>]".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "replay".into(),
            category: CommandCategory::Execution,
            description: "Replay a previous invocation from history".into(),
            synopsis: "fwc replay <ENTRY_ID> [--override-input <JSON>]".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "undo".into(),
            category: CommandCategory::Execution,
            description: "Reverse a previous invocation if the operation supports it".into(),
            synopsis: "fwc undo <ENTRY_ID>".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "extract".into(),
            category: CommandCategory::Execution,
            description: "Apply jq-style field extraction to invocation output".into(),
            synopsis: "fwc extract <EXPR> [--input <JSON>]".into(),
            is_read_only: true,
            requires_host: false,
        },
        // ── Workflow ─────────────────────────────────────────────────
        CommandEntry {
            name: "pipeline run".into(),
            category: CommandCategory::Workflow,
            description: "Execute a multi-step pipeline from a definition file".into(),
            synopsis: "fwc pipeline run <FILE> [--dry-run]".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "pipeline list".into(),
            category: CommandCategory::Workflow,
            description: "List saved pipeline definitions".into(),
            synopsis: "fwc pipeline list [--format <FMT>]".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "pipeline validate".into(),
            category: CommandCategory::Workflow,
            description: "Validate a pipeline definition without executing".into(),
            synopsis: "fwc pipeline validate <FILE>".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "template apply".into(),
            category: CommandCategory::Workflow,
            description: "Apply a Handlebars template to operation output".into(),
            synopsis: "fwc template apply <TEMPLATE> [--data <JSON>]".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "pipe".into(),
            category: CommandCategory::Workflow,
            description: "Chain operations via stdin/stdout piping".into(),
            synopsis: "fwc pipe <CONNECTOR> <OP> | fwc pipe <CONNECTOR2> <OP2>".into(),
            is_read_only: false,
            requires_host: true,
        },
        // ── Administration ───────────────────────────────────────────
        CommandEntry {
            name: "credential set".into(),
            category: CommandCategory::Administration,
            description: "Store a credential in the secure credential store".into(),
            synopsis: "fwc credential set <CONNECTOR> [--token <TOK>]".into(),
            is_read_only: false,
            requires_host: false,
        },
        CommandEntry {
            name: "credential verify".into(),
            category: CommandCategory::Administration,
            description: "Test that stored credentials are valid".into(),
            synopsis: "fwc credential verify <CONNECTOR>".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "policy show".into(),
            category: CommandCategory::Administration,
            description: "Display current policy configuration".into(),
            synopsis: "fwc policy show [--connector <ID>]".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "policy set".into(),
            category: CommandCategory::Administration,
            description: "Update policy rules for a connector or globally".into(),
            synopsis: "fwc policy set <RULE> [--connector <ID>]".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "validate".into(),
            category: CommandCategory::Administration,
            description: "Validate a connector manifest or configuration".into(),
            synopsis: "fwc validate <PATH>".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "supply-chain verify".into(),
            category: CommandCategory::Administration,
            description: "Verify supply chain attestations for a connector".into(),
            synopsis: "fwc supply-chain verify <CONNECTOR>".into(),
            is_read_only: true,
            requires_host: false,
        },
        // ── Meta ─────────────────────────────────────────────────────
        CommandEntry {
            name: "version".into(),
            category: CommandCategory::Meta,
            description: "Show the FWC version and build info".into(),
            synopsis: "fwc version".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "doctor".into(),
            category: CommandCategory::Meta,
            description: "Run diagnostics and report system health".into(),
            synopsis: "fwc doctor [--fix]".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "help".into(),
            category: CommandCategory::Meta,
            description: "Show help for a command or subcommand".into(),
            synopsis: "fwc help [COMMAND]".into(),
            is_read_only: true,
            requires_host: false,
        },
        CommandEntry {
            name: "new".into(),
            category: CommandCategory::Meta,
            description: "Scaffold a new connector project from a template".into(),
            synopsis: "fwc new <NAME> [--template <TMPL>]".into(),
            is_read_only: false,
            requires_host: false,
        },
        CommandEntry {
            name: "bench".into(),
            category: CommandCategory::Meta,
            description: "Run performance benchmarks against a connector".into(),
            synopsis: "fwc bench <CONNECTOR> [--iterations <N>]".into(),
            is_read_only: true,
            requires_host: true,
        },
        // ── Lifecycle ────────────────────────────────────────────────
        CommandEntry {
            name: "lifecycle enable".into(),
            category: CommandCategory::Lifecycle,
            description: "Enable a connector for operation dispatch".into(),
            synopsis: "fwc lifecycle enable <CONNECTOR>".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "lifecycle disable".into(),
            category: CommandCategory::Lifecycle,
            description: "Disable a connector, rejecting new requests".into(),
            synopsis: "fwc lifecycle disable <CONNECTOR>".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "lifecycle restart".into(),
            category: CommandCategory::Lifecycle,
            description: "Restart a connector process".into(),
            synopsis: "fwc lifecycle restart <CONNECTOR>".into(),
            is_read_only: false,
            requires_host: true,
        },
        CommandEntry {
            name: "lifecycle status".into(),
            category: CommandCategory::Lifecycle,
            description: "Show current lifecycle state of a connector".into(),
            synopsis: "fwc lifecycle status <CONNECTOR>".into(),
            is_read_only: true,
            requires_host: true,
        },
        // ── Monitoring ───────────────────────────────────────────────
        CommandEntry {
            name: "health".into(),
            category: CommandCategory::Monitoring,
            description: "Show health status of all connectors".into(),
            synopsis: "fwc health [--connector <ID>] [--format <FMT>]".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "events".into(),
            category: CommandCategory::Monitoring,
            description: "Stream or query connector events".into(),
            synopsis: "fwc events [--connector <ID>] [--since <TS>]".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "trace".into(),
            category: CommandCategory::Monitoring,
            description: "Show distributed trace for an invocation".into(),
            synopsis: "fwc trace <REQUEST_ID>".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "history".into(),
            category: CommandCategory::Monitoring,
            description: "Query invocation history with filters".into(),
            synopsis: "fwc history [--connector <ID>] [--limit <N>]".into(),
            is_read_only: true,
            requires_host: true,
        },
        CommandEntry {
            name: "net check".into(),
            category: CommandCategory::Monitoring,
            description: "Check network connectivity to connector endpoints".into(),
            synopsis: "fwc net check <CONNECTOR>".into(),
            is_read_only: true,
            requires_host: true,
        },
    ]
}

/// Returns the FWC mental model.
#[must_use]
pub fn get_mental_model() -> MentalModel {
    MentalModel {
        categories: CommandCategory::all()
            .iter()
            .map(|&cat| {
                let taxonomy = get_command_taxonomy();
                let cmds: Vec<String> = taxonomy
                    .iter()
                    .filter(|e| e.category == cat)
                    .map(|e| e.name.clone())
                    .collect();
                CategoryDescription {
                    category: cat,
                    description: cat.description().to_string(),
                    commands: cmds,
                    typical_flow: typical_flow_for(cat),
                }
            })
            .collect(),
        principles: vec![
            "Progressive disclosure: simple commands first, advanced options behind flags".into(),
            "Read-only by default: discovery commands never mutate state".into(),
            "Uniform output: all commands support --format json|table|yaml".into(),
            "Host independence: catalog and validation work offline".into(),
            "Explicit over implicit: no hidden side-effects".into(),
            "Fail fast, fail loud: clear error messages with actionable hints".into(),
            "Composability: pipe output between commands via JSON".into(),
            "Idempotency awareness: operations declare their idempotency class".into(),
            "Safety tiers: destructive operations require explicit confirmation".into(),
            "Audit trail: every mutation is logged in invocation history".into(),
            "Credential isolation: secrets never appear in logs or output".into(),
            "Zone scoping: operations can be scoped to specific deployment zones".into(),
        ],
        glossary: vec![
            (
                "Connector".into(),
                "A plugin that bridges FWC to an external service API".into(),
            ),
            (
                "Operation".into(),
                "A single action exposed by a connector (e.g. list_users, create_issue)".into(),
            ),
            (
                "Manifest".into(),
                "TOML file describing a connector's metadata, operations, and capabilities".into(),
            ),
            (
                "Invocation".into(),
                "A single execution of an operation with specific inputs".into(),
            ),
            (
                "Pipeline".into(),
                "A multi-step workflow that chains operations together".into(),
            ),
            (
                "Batch".into(),
                "Parallel or sequential execution of multiple operations in one request".into(),
            ),
            (
                "Host".into(),
                "The FCP host process that manages connectors and dispatches requests".into(),
            ),
            (
                "Zone".into(),
                "A logical deployment boundary for connector isolation".into(),
            ),
            (
                "Policy".into(),
                "Rules governing what operations are allowed and under what conditions".into(),
            ),
            (
                "Capability".into(),
                "A cryptographic token authorizing specific operations".into(),
            ),
            (
                "Safety Tier".into(),
                "Classification of operation risk: read-only, write, or destructive".into(),
            ),
            (
                "Idempotency Class".into(),
                "Whether an operation can be safely retried: idempotent, at-most-once, or unknown"
                    .into(),
            ),
            (
                "Schema".into(),
                "JSON Schema describing the expected input and output of an operation".into(),
            ),
            (
                "Credential Store".into(),
                "Secure local storage for connector authentication tokens".into(),
            ),
            (
                "Agent Hint".into(),
                "Metadata attached to requests identifying the calling agent".into(),
            ),
            (
                "Request ID".into(),
                "Unique identifier for tracing a single invocation across systems".into(),
            ),
            (
                "Lifecycle State".into(),
                "Current status of a connector: enabled, disabled, starting, stopping, errored"
                    .into(),
            ),
            (
                "Supply Chain".into(),
                "Verification of connector provenance and integrity via attestations".into(),
            ),
            (
                "Template".into(),
                "Handlebars template for formatting operation output".into(),
            ),
            (
                "Replay".into(),
                "Re-execution of a historical invocation, optionally with modified inputs".into(),
            ),
            (
                "Circuit Breaker".into(),
                "Automatic failure detection that stops routing to unhealthy connectors".into(),
            ),
        ],
    }
}

fn typical_flow_for(cat: CommandCategory) -> String {
    match cat {
        CommandCategory::Discovery => "search → introspect → schema → invoke".into(),
        CommandCategory::Execution => {
            "invoke → check history → replay if needed → undo if wrong".into()
        }
        CommandCategory::Workflow => {
            "pipeline validate → pipeline run → template apply for reporting".into()
        }
        CommandCategory::Administration => {
            "credential set → validate → policy set → supply-chain verify".into()
        }
        CommandCategory::Meta => "doctor → version → help <command>".into(),
        CommandCategory::Lifecycle => {
            "lifecycle status → lifecycle disable → lifecycle restart → lifecycle enable".into()
        }
        CommandCategory::Monitoring => "health → events --since 1h → trace <id> → history".into(),
    }
}

// ── Formatting ───────────────────────────────────────────────────────────────

/// Format the taxonomy as a human-readable string.
#[must_use]
pub fn format_taxonomy_toon(entries: &[CommandEntry]) -> String {
    let mut by_cat: BTreeMap<String, Vec<&CommandEntry>> = BTreeMap::new();
    for e in entries {
        by_cat
            .entry(e.category.as_str().to_string())
            .or_default()
            .push(e);
    }
    let mut out = String::new();
    let _ = writeln!(out, "FWC Command Taxonomy");
    let _ = writeln!(out, "====================");
    for (cat, cmds) in &by_cat {
        let _ = writeln!(out);
        let _ = writeln!(out, "## {cat}");
        for c in cmds {
            let ro = if c.is_read_only { " [read-only]" } else { "" };
            let host = if c.requires_host { " [host]" } else { "" };
            let _ = writeln!(out, "  {:<24} {}{}{}", c.name, c.description, ro, host);
        }
    }
    out
}

/// Format the mental model as a human-readable string.
#[must_use]
pub fn format_mental_model_toon(model: &MentalModel) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "FWC Mental Model");
    let _ = writeln!(out, "================");

    let _ = writeln!(out, "\n## Categories");
    for cd in &model.categories {
        let _ = writeln!(out, "\n### {}", cd.category.as_str());
        let _ = writeln!(out, "{}", cd.description);
        let _ = writeln!(out, "Commands: {}", cd.commands.join(", "));
        let _ = writeln!(out, "Typical flow: {}", cd.typical_flow);
    }

    let _ = writeln!(out, "\n## Principles");
    for (i, p) in model.principles.iter().enumerate() {
        let _ = writeln!(out, "  {}. {p}", i + 1);
    }

    let _ = writeln!(out, "\n## Glossary");
    for (term, def) in &model.glossary {
        let _ = writeln!(out, "  {term}: {def}");
    }

    out
}

// ── Quickstart Guide ─────────────────────────────────────────────────────────

/// A quickstart step with a command and explanation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuickstartStep {
    /// Step number.
    pub step: usize,
    /// The command to run.
    pub command: String,
    /// What this step accomplishes.
    pub explanation: String,
}

/// Returns the FWC quickstart guide.
#[must_use]
pub fn get_quickstart() -> Vec<QuickstartStep> {
    vec![
        QuickstartStep {
            step: 1,
            command: "fwc list".into(),
            explanation: "See all available connectors and their status".into(),
        },
        QuickstartStep {
            step: 2,
            command: "fwc search 'create issue'".into(),
            explanation: "Find operations by keyword across all connectors".into(),
        },
        QuickstartStep {
            step: 3,
            command: "fwc ops github".into(),
            explanation: "List all operations for a specific connector".into(),
        },
        QuickstartStep {
            step: 4,
            command: "fwc schema github create_issue".into(),
            explanation: "View the input/output schema before invoking".into(),
        },
        QuickstartStep {
            step: 5,
            command: "fwc template github create_issue".into(),
            explanation: "Generate a fill-in-the-blanks JSON template".into(),
        },
        QuickstartStep {
            step: 6,
            command: "fwc simulate github create_issue --input '{...}'".into(),
            explanation: "Dry-run the operation to validate without side effects".into(),
        },
        QuickstartStep {
            step: 7,
            command: "fwc invoke github create_issue --input '{...}'".into(),
            explanation: "Execute the operation for real".into(),
        },
        QuickstartStep {
            step: 8,
            command: "fwc history --limit 5".into(),
            explanation: "Review recent invocations".into(),
        },
    ]
}

/// Format the quickstart guide as TOON text.
#[must_use]
pub fn format_quickstart_toon(steps: &[QuickstartStep]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "FWC Quickstart");
    let _ = writeln!(out, "==============");
    let _ = writeln!(out);
    for s in steps {
        let _ = writeln!(out, "  {}. {}", s.step, s.explanation);
        let _ = writeln!(out, "     $ {}", s.command);
        let _ = writeln!(out);
    }
    out
}

// ── Output Format Guide ──────────────────────────────────────────────────────

/// Description of an output format mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputFormatGuide {
    /// Format name (e.g., "toon", "json").
    pub name: String,
    /// Flag to activate this format.
    pub flag: String,
    /// When to use this format.
    pub when_to_use: String,
    /// Whether this is the default.
    pub is_default: bool,
}

/// Returns the FWC output format guide.
#[must_use]
pub fn get_output_format_guide() -> Vec<OutputFormatGuide> {
    vec![
        OutputFormatGuide {
            name: "TOON".into(),
            flag: "(default)".into(),
            when_to_use: "Human-readable table output for terminal use. Best for interactive exploration and quick answers.".into(),
            is_default: true,
        },
        OutputFormatGuide {
            name: "JSON".into(),
            flag: "--json".into(),
            when_to_use: "Machine-readable output for piping to jq, scripts, or other tools. Use when composing commands.".into(),
            is_default: false,
        },
        OutputFormatGuide {
            name: "NDJSON".into(),
            flag: "--format ndjson".into(),
            when_to_use: "Streaming line-delimited JSON. Each result on its own line. Best for real-time processing and piping between commands.".into(),
            is_default: false,
        },
        OutputFormatGuide {
            name: "Table".into(),
            flag: "--format table".into(),
            when_to_use: "Explicit tabular output with column headers. Good for structured reports.".into(),
            is_default: false,
        },
        OutputFormatGuide {
            name: "CSV".into(),
            flag: "--format csv".into(),
            when_to_use: "Comma-separated values for spreadsheet import.".into(),
            is_default: false,
        },
        OutputFormatGuide {
            name: "YAML".into(),
            flag: "--format yaml".into(),
            when_to_use: "YAML output for config files and human-readable structured data.".into(),
            is_default: false,
        },
        OutputFormatGuide {
            name: "Markdown".into(),
            flag: "--format markdown".into(),
            when_to_use: "Markdown table output for documentation and reports.".into(),
            is_default: false,
        },
    ]
}

// ── Decision Guide: When to Use What ─────────────────────────────────────────

/// A decision guide entry: agent need → recommended command path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionGuideEntry {
    /// What the agent wants to accomplish.
    pub goal: String,
    /// The recommended command or command sequence.
    pub recommended_command: String,
    /// Why this is the right choice.
    pub rationale: String,
    /// Whether this is a primitive command or a workflow surface.
    pub surface: String,
}

/// Returns the "when to use what" decision guide.
#[must_use]
pub fn get_decision_guide() -> Vec<DecisionGuideEntry> {
    vec![
        DecisionGuideEntry {
            goal: "Run a single operation".into(),
            recommended_command: "fwc invoke <conn> <op>".into(),
            rationale: "Direct, auditable, one operation = one history entry".into(),
            surface: "primitive".into(),
        },
        DecisionGuideEntry {
            goal: "Chain two operations (A's output → B's input)".into(),
            recommended_command: "fwc pipe <conn.op_a> <conn.op_b> --field-map ...".into(),
            rationale: "Explicit field mapping, both operations recorded".into(),
            surface: "primitive".into(),
        },
        DecisionGuideEntry {
            goal: "Run a complex multi-step workflow".into(),
            recommended_command: "fwc pipeline run workflow.toml".into(),
            rationale: "Reusable, versionable, validates before running".into(),
            surface: "workflow".into(),
        },
        DecisionGuideEntry {
            goal: "Apply one operation to many inputs".into(),
            recommended_command: "fwc map <conn> <op> --inputs items.json".into(),
            rationale: "Parallel execution, one receipt per input".into(),
            surface: "primitive".into(),
        },
        DecisionGuideEntry {
            goal: "Run mixed operations from a file".into(),
            recommended_command: "fwc batch-file ops.jsonl".into(),
            rationale: "Heterogeneous operations, sequential or parallel".into(),
            surface: "primitive".into(),
        },
        DecisionGuideEntry {
            goal: "Save reusable input for an operation".into(),
            recommended_command: "fwc template <conn> <op> > tpl.json".into(),
            rationale: "Schema-seeded template, fill in values per use".into(),
            surface: "template".into(),
        },
        DecisionGuideEntry {
            goal: "Resume interrupted work".into(),
            recommended_command: "fwc session resume <handle>".into(),
            rationale: "Restores context without repeating discovery".into(),
            surface: "session".into(),
        },
        DecisionGuideEntry {
            goal: "Understand why something failed".into(),
            recommended_command: "fwc history <entry_id>".into(),
            rationale: "Full invocation detail with error codes and timing".into(),
            surface: "primitive".into(),
        },
        DecisionGuideEntry {
            goal: "Check if an operation is allowed".into(),
            recommended_command: "fwc preflight <conn> <op>".into(),
            rationale: "Risk analysis, approval check, capability verification".into(),
            surface: "primitive".into(),
        },
        DecisionGuideEntry {
            goal: "Export connector tools for AI agent".into(),
            recommended_command: "fwc export-tools --format mcp".into(),
            rationale: "Schema-compliant tool export for MCP/Claude/OpenAI".into(),
            surface: "primitive".into(),
        },
    ]
}

/// Format the decision guide as TOON text.
#[must_use]
pub fn format_decision_guide_toon(entries: &[DecisionGuideEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "FWC Decision Guide: When to Use What");
    let _ = writeln!(out, "=====================================");
    let _ = writeln!(out);
    let _ = writeln!(out, "{:<42} {:<40} {}", "GOAL", "COMMAND", "SURFACE");
    for e in entries {
        let _ = writeln!(
            out,
            "{:<42} {:<40} {}",
            e.goal, e.recommended_command, e.surface
        );
    }
    out
}

// ── TOON-First Behavior Documentation ────────────────────────────────────────

/// Explains the TOON-first design philosophy.
#[must_use]
pub fn toon_first_explanation() -> String {
    [
        "TOON-First Output Behavior",
        "==========================",
        "",
        "FWC defaults to TOON (Text-Oriented Output Notation) for all commands.",
        "TOON is designed for human readability in a terminal:",
        "",
        "  - Aligned columns with meaningful headers",
        "  - Status indicators and color hints",
        "  - Truncation of long values with '...'",
        "  - Summary counts and timing information",
        "",
        "For machine consumption, switch to JSON:",
        "",
        "  $ fwc list --json           # Full JSON array",
        "  $ fwc list --format ndjson   # One JSON line per item (streaming)",
        "",
        "JSON output includes all fields (no truncation), stable field names,",
        "and structured error objects with error_code fields.",
        "",
        "The same data is available in both formats. TOON is lossy (truncates",
        "for readability); JSON is lossless. An agent should use --json when",
        "parsing output programmatically and TOON when presenting to a human.",
        "",
        "Safety Boundaries:",
        "  - Read-only commands (search, list, schema) never mutate state",
        "  - Write commands (invoke, pipe) require explicit confirmation",
        "  - Destructive commands require --force or interactive approval",
        "  - Simulate mode (--dry-run) is available for all write commands",
    ]
    .join("\n")
}

// ── Validation ───────────────────────────────────────────────────────────────

/// Validate the taxonomy for gaps and duplicates.
/// Returns a list of warning/error messages (empty = valid).
#[must_use]
pub fn validate_taxonomy(entries: &[CommandEntry]) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check for duplicate names.
    let mut seen = BTreeSet::new();
    for e in entries {
        if !seen.insert(&e.name) {
            warnings.push(format!("Duplicate command name: {}", e.name));
        }
    }

    // Check every category has at least one command.
    for cat in CommandCategory::all() {
        if !entries.iter().any(|e| e.category == *cat) {
            warnings.push(format!("Category {} has no commands", cat.as_str()));
        }
    }

    // Check all entries have non-empty descriptions.
    for e in entries {
        if e.description.is_empty() {
            warnings.push(format!("Command {} has empty description", e.name));
        }
        if e.synopsis.is_empty() {
            warnings.push(format!("Command {} has empty synopsis", e.name));
        }
    }

    // Check that read-only commands don't require host when they shouldn't.
    // (This is informational, not enforced.)

    warnings
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;

    // ── CommandCategory tests ────────────────────────────────────────────

    #[test]
    fn category_all_returns_seven() {
        assert_eq!(CommandCategory::all().len(), 7);
    }

    #[test]
    fn category_as_str_roundtrips() {
        for cat in CommandCategory::all() {
            let s = cat.as_str();
            let parsed = CommandCategory::parse(s).unwrap();
            assert_eq!(*cat, parsed);
        }
    }

    #[test]
    fn category_parse_unknown_returns_none() {
        assert!(CommandCategory::parse("unknown").is_none());
        assert!(CommandCategory::parse("").is_none());
        assert!(CommandCategory::parse("DISCOVERY").is_none());
    }

    #[test]
    fn category_display_matches_as_str() {
        for cat in CommandCategory::all() {
            assert_eq!(format!("{cat}"), cat.as_str());
        }
    }

    #[test]
    fn category_description_non_empty() {
        for cat in CommandCategory::all() {
            assert!(
                !cat.description().is_empty(),
                "{} has empty description",
                cat.as_str()
            );
        }
    }

    #[test]
    fn category_serialize_deserialize_roundtrip() {
        for cat in CommandCategory::all() {
            let json = serde_json::to_string(cat).unwrap();
            let back: CommandCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn category_clone_eq() {
        let a = CommandCategory::Discovery;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn category_debug_format() {
        let dbg = format!("{:?}", CommandCategory::Execution);
        assert!(dbg.contains("Execution"));
    }

    // ── Taxonomy tests ───────────────────────────────────────────────────

    #[test]
    fn taxonomy_has_at_least_30_entries() {
        let tax = get_command_taxonomy();
        assert!(tax.len() >= 30, "Taxonomy has only {} entries", tax.len());
    }

    #[test]
    fn taxonomy_covers_all_categories() {
        let tax = get_command_taxonomy();
        let covered: BTreeSet<String> = tax
            .iter()
            .map(|e| e.category.as_str().to_string())
            .collect();
        for cat in CommandCategory::all() {
            assert!(
                covered.contains(cat.as_str()),
                "Missing category: {}",
                cat.as_str()
            );
        }
    }

    #[test]
    fn taxonomy_no_duplicate_names() {
        let tax = get_command_taxonomy();
        let mut names = BTreeSet::new();
        for e in &tax {
            assert!(names.insert(&e.name), "Duplicate: {}", e.name);
        }
    }

    #[test]
    fn taxonomy_all_have_descriptions() {
        for e in &get_command_taxonomy() {
            assert!(!e.description.is_empty(), "{} missing description", e.name);
        }
    }

    #[test]
    fn taxonomy_all_have_synopses() {
        for e in &get_command_taxonomy() {
            assert!(!e.synopsis.is_empty(), "{} missing synopsis", e.name);
        }
    }

    #[test]
    fn taxonomy_synopses_start_with_fwc() {
        for e in &get_command_taxonomy() {
            assert!(
                e.synopsis.starts_with("fwc"),
                "{} synopsis doesn't start with fwc: {}",
                e.name,
                e.synopsis
            );
        }
    }

    #[test]
    fn taxonomy_discovery_commands_are_read_only() {
        for e in get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Discovery)
        {
            assert!(
                e.is_read_only,
                "Discovery command {} is not read-only",
                e.name
            );
        }
    }

    #[test]
    fn taxonomy_meta_commands_are_read_only() {
        for e in get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Meta)
        {
            // All meta commands except "new" should be read-only.
            if e.name != "new" {
                assert!(e.is_read_only, "Meta command {} is not read-only", e.name);
            }
        }
    }

    #[test]
    fn taxonomy_monitoring_commands_are_read_only() {
        for e in get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Monitoring)
        {
            assert!(
                e.is_read_only,
                "Monitoring command {} is not read-only",
                e.name
            );
        }
    }

    #[test]
    fn taxonomy_lifecycle_commands_require_host() {
        for e in get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Lifecycle)
        {
            assert!(
                e.requires_host,
                "Lifecycle command {} doesn't require host",
                e.name
            );
        }
    }

    #[test]
    fn taxonomy_invoke_is_not_read_only() {
        let tax = get_command_taxonomy();
        let invoke = tax.iter().find(|e| e.name == "invoke").unwrap();
        assert!(!invoke.is_read_only);
    }

    #[test]
    fn taxonomy_search_is_read_only() {
        let tax = get_command_taxonomy();
        let search = tax.iter().find(|e| e.name == "search").unwrap();
        assert!(search.is_read_only);
    }

    #[test]
    fn taxonomy_validate_returns_empty_for_canonical() {
        let tax = get_command_taxonomy();
        let warnings = validate_taxonomy(&tax);
        assert!(warnings.is_empty(), "Unexpected warnings: {warnings:?}");
    }

    #[test]
    fn taxonomy_validate_detects_duplicates() {
        let mut tax = get_command_taxonomy();
        tax.push(tax[0].clone());
        let warnings = validate_taxonomy(&tax);
        assert!(warnings.iter().any(|w| w.contains("Duplicate")));
    }

    #[test]
    fn taxonomy_validate_detects_empty_description() {
        let tax = vec![CommandEntry {
            name: "test".into(),
            category: CommandCategory::Meta,
            description: String::new(),
            synopsis: "fwc test".into(),
            is_read_only: true,
            requires_host: false,
        }];
        let warnings = validate_taxonomy(&tax);
        assert!(warnings.iter().any(|w| w.contains("empty description")));
    }

    #[test]
    fn taxonomy_validate_detects_empty_synopsis() {
        let tax = vec![CommandEntry {
            name: "test".into(),
            category: CommandCategory::Meta,
            description: "Testing".into(),
            synopsis: String::new(),
            is_read_only: true,
            requires_host: false,
        }];
        let warnings = validate_taxonomy(&tax);
        assert!(warnings.iter().any(|w| w.contains("empty synopsis")));
    }

    #[test]
    fn taxonomy_validate_detects_missing_category() {
        // Only Discovery commands — all other categories missing.
        let tax: Vec<CommandEntry> = get_command_taxonomy()
            .into_iter()
            .filter(|e| e.category == CommandCategory::Discovery)
            .collect();
        let warnings = validate_taxonomy(&tax);
        assert!(warnings.iter().any(|w| w.contains("has no commands")));
    }

    #[test]
    fn taxonomy_entry_serializes() {
        let entry = &get_command_taxonomy()[0];
        let json = serde_json::to_string(entry).unwrap();
        assert!(json.contains(&entry.name));
    }

    #[test]
    fn taxonomy_entry_deserializes() {
        let entry = &get_command_taxonomy()[0];
        let json = serde_json::to_string(entry).unwrap();
        let back: CommandEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.name, back.name);
        assert_eq!(entry.category, back.category);
    }

    #[test]
    fn taxonomy_category_distribution() {
        let tax = get_command_taxonomy();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for e in &tax {
            *counts.entry(e.category.as_str().to_string()).or_default() += 1;
        }
        // Every category should have at least 2 commands for a rich taxonomy.
        for cat in CommandCategory::all() {
            let count = counts.get(cat.as_str()).copied().unwrap_or(0);
            assert!(
                count >= 2,
                "Category {} has only {count} commands",
                cat.as_str()
            );
        }
    }

    // ── Mental Model tests ───────────────────────────────────────────────

    #[test]
    fn mental_model_has_seven_categories() {
        let model = get_mental_model();
        assert_eq!(model.categories.len(), 7);
    }

    #[test]
    fn mental_model_has_at_least_10_principles() {
        let model = get_mental_model();
        assert!(
            model.principles.len() >= 10,
            "Only {} principles",
            model.principles.len()
        );
    }

    #[test]
    fn mental_model_has_at_least_20_glossary_terms() {
        let model = get_mental_model();
        assert!(
            model.glossary.len() >= 20,
            "Only {} glossary terms",
            model.glossary.len()
        );
    }

    #[test]
    fn mental_model_categories_match_taxonomy() {
        let model = get_mental_model();
        let tax = get_command_taxonomy();
        for cd in &model.categories {
            let tax_cmds: Vec<String> = tax
                .iter()
                .filter(|e| e.category == cd.category)
                .map(|e| e.name.clone())
                .collect();
            assert_eq!(
                cd.commands,
                tax_cmds,
                "Mismatch for {}",
                cd.category.as_str()
            );
        }
    }

    #[test]
    fn mental_model_categories_have_descriptions() {
        for cd in &get_mental_model().categories {
            assert!(!cd.description.is_empty());
        }
    }

    #[test]
    fn mental_model_categories_have_typical_flows() {
        for cd in &get_mental_model().categories {
            assert!(!cd.typical_flow.is_empty());
        }
    }

    #[test]
    fn mental_model_principles_non_empty() {
        for p in &get_mental_model().principles {
            assert!(!p.is_empty());
        }
    }

    #[test]
    fn mental_model_glossary_terms_non_empty() {
        for (term, def) in &get_mental_model().glossary {
            assert!(!term.is_empty());
            assert!(!def.is_empty());
        }
    }

    #[test]
    fn mental_model_glossary_no_duplicate_terms() {
        let model = get_mental_model();
        let mut seen = BTreeSet::new();
        for (term, _) in &model.glossary {
            assert!(seen.insert(term), "Duplicate glossary term: {term}");
        }
    }

    #[test]
    fn mental_model_serializes() {
        let model = get_mental_model();
        let json = serde_json::to_string(&model).unwrap();
        assert!(json.contains("principles"));
        assert!(json.contains("glossary"));
    }

    #[test]
    fn mental_model_deserializes_roundtrip() {
        let model = get_mental_model();
        let json = serde_json::to_string(&model).unwrap();
        let back: MentalModel = serde_json::from_str(&json).unwrap();
        assert_eq!(model.principles.len(), back.principles.len());
        assert_eq!(model.glossary.len(), back.glossary.len());
    }

    #[test]
    fn mental_model_principles_cover_key_topics() {
        let model = get_mental_model();
        let all = model.principles.join(" ").to_lowercase();
        assert!(
            all.contains("disclosure"),
            "Missing progressive disclosure principle"
        );
        assert!(all.contains("composab"), "Missing composability principle");
        assert!(all.contains("safety"), "Missing safety principle");
    }

    #[test]
    fn mental_model_glossary_covers_core_terms() {
        let model = get_mental_model();
        let terms: Vec<&str> = model.glossary.iter().map(|(t, _)| t.as_str()).collect();
        assert!(terms.contains(&"Connector"));
        assert!(terms.contains(&"Operation"));
        assert!(terms.contains(&"Manifest"));
        assert!(terms.contains(&"Host"));
    }

    // ── Format tests ─────────────────────────────────────────────────────

    #[test]
    fn format_taxonomy_toon_contains_header() {
        let out = format_taxonomy_toon(&get_command_taxonomy());
        assert!(out.contains("FWC Command Taxonomy"));
    }

    #[test]
    fn format_taxonomy_toon_contains_categories() {
        let out = format_taxonomy_toon(&get_command_taxonomy());
        assert!(out.contains("discovery"));
        assert!(out.contains("execution"));
    }

    #[test]
    fn format_taxonomy_toon_contains_commands() {
        let out = format_taxonomy_toon(&get_command_taxonomy());
        assert!(out.contains("search"));
        assert!(out.contains("invoke"));
    }

    #[test]
    fn format_taxonomy_toon_marks_read_only() {
        let out = format_taxonomy_toon(&get_command_taxonomy());
        assert!(out.contains("[read-only]"));
    }

    #[test]
    fn format_taxonomy_toon_marks_host() {
        let out = format_taxonomy_toon(&get_command_taxonomy());
        assert!(out.contains("[host]"));
    }

    #[test]
    fn format_taxonomy_toon_empty_input() {
        let out = format_taxonomy_toon(&[]);
        assert!(out.contains("FWC Command Taxonomy"));
        assert!(!out.contains("##"));
    }

    #[test]
    fn format_mental_model_toon_contains_header() {
        let out = format_mental_model_toon(&get_mental_model());
        assert!(out.contains("FWC Mental Model"));
    }

    #[test]
    fn format_mental_model_toon_contains_principles() {
        let out = format_mental_model_toon(&get_mental_model());
        assert!(out.contains("Principles"));
    }

    #[test]
    fn format_mental_model_toon_contains_glossary() {
        let out = format_mental_model_toon(&get_mental_model());
        assert!(out.contains("Glossary"));
    }

    #[test]
    fn format_mental_model_toon_contains_categories() {
        let out = format_mental_model_toon(&get_mental_model());
        assert!(out.contains("Categories"));
    }

    #[test]
    fn format_mental_model_toon_contains_typical_flow() {
        let out = format_mental_model_toon(&get_mental_model());
        assert!(out.contains("Typical flow"));
    }

    // ── CommandEntry property tests ──────────────────────────────────────

    #[test]
    fn command_entry_clone() {
        let entry = &get_command_taxonomy()[0];
        let cloned = entry.clone();
        assert_eq!(entry.name, cloned.name);
    }

    #[test]
    fn command_entry_debug() {
        let entry = &get_command_taxonomy()[0];
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("name"));
    }

    #[test]
    fn category_description_clone() {
        let model = get_mental_model();
        let cd = model.categories[0].clone();
        assert_eq!(cd.category, model.categories[0].category);
    }

    #[test]
    fn category_description_debug() {
        let model = get_mental_model();
        let dbg = format!("{:?}", model.categories[0]);
        assert!(dbg.contains("category"));
    }

    // ── Category-specific count tests ────────────────────────────────────

    #[test]
    fn discovery_has_at_least_5_commands() {
        let count = get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Discovery)
            .count();
        assert!(count >= 5, "Discovery has only {count} commands");
    }

    #[test]
    fn execution_has_at_least_4_commands() {
        let count = get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Execution)
            .count();
        assert!(count >= 4, "Execution has only {count} commands");
    }

    #[test]
    fn workflow_has_at_least_4_commands() {
        let count = get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Workflow)
            .count();
        assert!(count >= 4, "Workflow has only {count} commands");
    }

    #[test]
    fn administration_has_at_least_4_commands() {
        let count = get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Administration)
            .count();
        assert!(count >= 4, "Administration has only {count} commands");
    }

    #[test]
    fn lifecycle_has_at_least_4_commands() {
        let count = get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Lifecycle)
            .count();
        assert!(count >= 4, "Lifecycle has only {count} commands");
    }

    #[test]
    fn monitoring_has_at_least_4_commands() {
        let count = get_command_taxonomy()
            .iter()
            .filter(|e| e.category == CommandCategory::Monitoring)
            .count();
        assert!(count >= 4, "Monitoring has only {count} commands");
    }

    // ── Validation edge cases ────────────────────────────────────────────

    #[test]
    fn validate_empty_taxonomy() {
        let warnings = validate_taxonomy(&[]);
        // Should warn about missing categories.
        assert!(warnings.len() >= 7);
    }

    #[test]
    fn validate_single_entry_per_category() {
        let entries: Vec<CommandEntry> = CommandCategory::all()
            .iter()
            .map(|cat| CommandEntry {
                name: format!("test_{}", cat.as_str()),
                category: *cat,
                description: "Test".into(),
                synopsis: "fwc test".into(),
                is_read_only: true,
                requires_host: false,
            })
            .collect();
        let warnings = validate_taxonomy(&entries);
        assert!(warnings.is_empty(), "Unexpected warnings: {warnings:?}");
    }

    // ── Typical flow tests ───────────────────────────────────────────────

    #[test]
    fn typical_flow_discovery_mentions_search() {
        let flow = typical_flow_for(CommandCategory::Discovery);
        assert!(flow.contains("search"));
    }

    #[test]
    fn typical_flow_execution_mentions_invoke() {
        let flow = typical_flow_for(CommandCategory::Execution);
        assert!(flow.contains("invoke"));
    }

    #[test]
    fn typical_flow_workflow_mentions_pipeline() {
        let flow = typical_flow_for(CommandCategory::Workflow);
        assert!(flow.contains("pipeline"));
    }

    #[test]
    fn typical_flow_administration_mentions_credential() {
        let flow = typical_flow_for(CommandCategory::Administration);
        assert!(flow.contains("credential"));
    }

    #[test]
    fn typical_flow_meta_mentions_doctor() {
        let flow = typical_flow_for(CommandCategory::Meta);
        assert!(flow.contains("doctor"));
    }

    #[test]
    fn typical_flow_lifecycle_mentions_enable() {
        let flow = typical_flow_for(CommandCategory::Lifecycle);
        assert!(flow.contains("enable"));
    }

    #[test]
    fn typical_flow_monitoring_mentions_health() {
        let flow = typical_flow_for(CommandCategory::Monitoring);
        assert!(flow.contains("health"));
    }

    // ── Hash/BTreeSet tests ──────────────────────────────────────────────

    #[test]
    fn category_hash_distinct() {
        use std::collections::HashSet;
        let set: HashSet<CommandCategory> = CommandCategory::all().iter().copied().collect();
        assert_eq!(set.len(), 7);
    }

    #[test]
    fn category_btreeset() {
        let tax = get_command_taxonomy();
        let cats: BTreeSet<String> = tax
            .iter()
            .map(|e| e.category.as_str().to_string())
            .collect();
        assert_eq!(cats.len(), 7);
    }

    // ── Mental model clone ───────────────────────────────────────────────

    #[test]
    fn mental_model_clone() {
        let model = get_mental_model();
        let cloned = model.clone();
        assert_eq!(model.principles.len(), cloned.principles.len());
    }

    #[test]
    fn mental_model_debug() {
        let model = get_mental_model();
        let dbg = format!("{model:?}");
        assert!(dbg.contains("MentalModel"));
    }

    // ── Quickstart guide ────────────────────────────────────────────────

    #[test]
    fn quickstart_has_steps() {
        let steps = get_quickstart();
        assert!(steps.len() >= 5);
    }

    #[test]
    fn quickstart_steps_sequential() {
        let steps = get_quickstart();
        for (i, s) in steps.iter().enumerate() {
            assert_eq!(s.step, i + 1);
        }
    }

    #[test]
    fn quickstart_starts_with_discovery() {
        let steps = get_quickstart();
        assert!(steps[0].command.contains("list"));
    }

    #[test]
    fn quickstart_ends_with_review() {
        let steps = get_quickstart();
        let last = steps.last().unwrap();
        assert!(last.command.contains("history"));
    }

    #[test]
    fn quickstart_all_have_content() {
        for s in &get_quickstart() {
            assert!(!s.command.is_empty());
            assert!(!s.explanation.is_empty());
        }
    }

    #[test]
    fn quickstart_serializes() {
        let steps = get_quickstart();
        let json = serde_json::to_value(&steps).unwrap();
        assert!(json.is_array());
    }

    #[test]
    fn quickstart_toon_format() {
        let steps = get_quickstart();
        let toon = format_quickstart_toon(&steps);
        assert!(toon.contains("FWC Quickstart"));
        assert!(toon.contains("$ fwc list"));
        assert!(toon.contains("$ fwc search"));
    }

    #[test]
    fn quickstart_toon_empty() {
        let toon = format_quickstart_toon(&[]);
        assert!(toon.contains("FWC Quickstart"));
    }

    // ── Output format guide ─────────────────────────────────────────────

    #[test]
    fn output_format_guide_has_entries() {
        let guide = get_output_format_guide();
        assert!(guide.len() >= 5);
    }

    #[test]
    fn output_format_guide_has_default() {
        let guide = get_output_format_guide();
        let defaults: Vec<_> = guide.iter().filter(|g| g.is_default).collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].name, "TOON");
    }

    #[test]
    fn output_format_guide_includes_json() {
        let guide = get_output_format_guide();
        assert!(guide.iter().any(|g| g.name == "JSON"));
    }

    #[test]
    fn output_format_guide_includes_ndjson() {
        let guide = get_output_format_guide();
        assert!(guide.iter().any(|g| g.name == "NDJSON"));
    }

    #[test]
    fn output_format_guide_all_have_content() {
        for g in &get_output_format_guide() {
            assert!(!g.name.is_empty());
            assert!(!g.flag.is_empty());
            assert!(!g.when_to_use.is_empty());
        }
    }

    #[test]
    fn output_format_guide_serializes() {
        let guide = get_output_format_guide();
        let json = serde_json::to_value(&guide).unwrap();
        assert!(json.is_array());
    }

    // ── Decision guide ──────────────────────────────────────────────────

    #[test]
    fn decision_guide_has_entries() {
        let guide = get_decision_guide();
        assert!(guide.len() >= 8);
    }

    #[test]
    fn decision_guide_covers_primitive_and_workflow() {
        let guide = get_decision_guide();
        assert!(guide.iter().any(|e| e.surface == "primitive"));
        assert!(guide.iter().any(|e| e.surface == "workflow"));
    }

    #[test]
    fn decision_guide_covers_invoke() {
        let guide = get_decision_guide();
        assert!(
            guide
                .iter()
                .any(|e| e.recommended_command.contains("invoke"))
        );
    }

    #[test]
    fn decision_guide_covers_pipeline() {
        let guide = get_decision_guide();
        assert!(
            guide
                .iter()
                .any(|e| e.recommended_command.contains("pipeline"))
        );
    }

    #[test]
    fn decision_guide_covers_template() {
        let guide = get_decision_guide();
        assert!(guide.iter().any(|e| e.surface == "template"));
    }

    #[test]
    fn decision_guide_covers_session() {
        let guide = get_decision_guide();
        assert!(guide.iter().any(|e| e.surface == "session"));
    }

    #[test]
    fn decision_guide_all_have_content() {
        for e in &get_decision_guide() {
            assert!(!e.goal.is_empty());
            assert!(!e.recommended_command.is_empty());
            assert!(!e.rationale.is_empty());
            assert!(!e.surface.is_empty());
        }
    }

    #[test]
    fn decision_guide_serializes() {
        let guide = get_decision_guide();
        let json = serde_json::to_value(&guide).unwrap();
        assert!(json.is_array());
    }

    #[test]
    fn decision_guide_toon_format() {
        let guide = get_decision_guide();
        let toon = format_decision_guide_toon(&guide);
        assert!(toon.contains("FWC Decision Guide"));
        assert!(toon.contains("GOAL"));
        assert!(toon.contains("COMMAND"));
        assert!(toon.contains("SURFACE"));
    }

    #[test]
    fn decision_guide_toon_empty() {
        let toon = format_decision_guide_toon(&[]);
        assert!(toon.contains("FWC Decision Guide"));
    }

    // ── TOON-first explanation ──────────────────────────────────────────

    #[test]
    fn toon_first_explanation_covers_key_topics() {
        let text = toon_first_explanation();
        assert!(text.contains("TOON"));
        assert!(text.contains("JSON"));
        assert!(text.contains("--json"));
        assert!(text.contains("ndjson"));
        assert!(text.contains("Safety"));
        assert!(text.contains("Read-only"));
    }

    #[test]
    fn toon_first_explanation_has_examples() {
        let text = toon_first_explanation();
        assert!(text.contains("$ fwc list --json"));
        assert!(text.contains("$ fwc list --format ndjson"));
    }

    #[test]
    fn toon_first_explanation_non_empty() {
        let text = toon_first_explanation();
        assert!(text.len() > 200);
    }

    // ── QuickstartStep struct ───────────────────────────────────────────

    #[test]
    fn quickstart_step_clone() {
        let s = QuickstartStep {
            step: 1,
            command: "fwc list".into(),
            explanation: "List connectors".into(),
        };
        let s2 = s.clone();
        assert_eq!(s.step, s2.step);
        assert_eq!(s.command, s2.command);
    }

    // ── OutputFormatGuide struct ────────────────────────────────────────

    #[test]
    fn output_format_guide_clone() {
        let g = OutputFormatGuide {
            name: "JSON".into(),
            flag: "--json".into(),
            when_to_use: "Machine output".into(),
            is_default: false,
        };
        let g2 = g.clone();
        assert_eq!(g.name, g2.name);
    }

    // ── DecisionGuideEntry struct ───────────────────────────────────────

    #[test]
    fn decision_guide_entry_clone() {
        let e = DecisionGuideEntry {
            goal: "Run one op".into(),
            recommended_command: "fwc invoke".into(),
            rationale: "Direct".into(),
            surface: "primitive".into(),
        };
        let e2 = e.clone();
        assert_eq!(e.goal, e2.goal);
        assert_eq!(e.surface, e2.surface);
    }
}
