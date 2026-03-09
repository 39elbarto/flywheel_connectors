#![deny(unsafe_code)]

#[allow(dead_code)] // Multi-agent coordination wired when Agent Mail integration lands.
mod agent_coord;
#[allow(dead_code)]
mod auth_status;
#[allow(dead_code)] // Audit types used by later CLI commands.
mod audit;
#[allow(
    dead_code,
    clippy::str_split_at_newline,
    clippy::needless_raw_string_hashes
)]
mod batch;
#[allow(dead_code)] // Result types wired when host integration lands.
mod batch_file;
#[allow(dead_code)] // Progress tracking wired when host integration lands.
mod batch_progress;
mod catalog;
#[allow(dead_code)] // Event checkpoint and replay from sequence/time.
mod checkpoint;
#[allow(dead_code)] // Auth verify + credential backend trait.
mod credential;
#[allow(dead_code)]
mod credential_store;
#[allow(dead_code)]
mod doctor;
#[allow(dead_code)] // Stream types wired when host integration lands.
mod event_stream;
#[allow(dead_code)] // Comprehensive event filtering engine.
mod events;
mod export_tools;
mod format_table;
#[allow(dead_code)] // Cross-connector health aggregation dashboard.
mod health;
#[allow(
    dead_code,
    clippy::writeln_empty_string,
    clippy::missing_const_for_fn,
    clippy::collection_is_never_read,
    clippy::needless_continue
)]
mod history;
#[allow(dead_code)] // Discovery types wired into host-backed commands in later beads.
mod identifier;
mod intent;
#[allow(dead_code)]
mod json_diff;
#[allow(dead_code)]
mod mcp_resources;
#[allow(dead_code)]
mod op_lock;
#[allow(dead_code)]
mod pipe;
#[allow(dead_code)] // Pipeline conditional branching and error handling.
mod pipeline_cond;
#[allow(dead_code)]
mod pipeline_recipes;
#[allow(dead_code)]
mod rate_limit;
#[allow(dead_code)]
mod reactive_rules;
#[allow(dead_code)] // Contract types wired into host-backed commands in later beads.
mod readiness;
mod recovery;
#[allow(dead_code)] // Extract/transform features pending invoke integration.
mod render;
#[allow(dead_code)] // Operation replay from history with input override.
mod replay;
#[allow(dead_code)] // Smart connector auto-routing for ambiguous intents.
mod routing;
mod schema_nav;
mod search;
#[allow(dead_code)] // Secretless injection wired when egress proxy integration lands.
mod secretless;
#[allow(dead_code)]
mod session;
mod template;
#[allow(dead_code)]
mod throttle;
#[allow(dead_code)] // Idempotent undo for reversible operations.
mod undo;
mod validate;
#[allow(dead_code)]
mod zone_scope;
mod workflow;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use serde_json::{Value, json};

use crate::readiness::{
    DiscoveredConnector, DiscoveredOperation, DiscoveryCatalog, SelectorError, SelectorErrorKind,
};
use crate::render::{
    ExtractRender, OutputFormat, RenderOptions, TemplateRender, render_with_options, token_stats,
};

const ABOUT: &str =
    "Standalone Flywheel connector console with TOON-first, progressive-disclosure output.";

const LONG_ABOUT: &str = "\
Standalone Flywheel connector console for discovery, lifecycle management, configuration, and
invocation across every connector in the workspace.

Defaults:
  - TOON output is the default because agent-facing output should stay token-efficient.
  - Use --format json when you need full-fidelity structured output.
  - For resumable work, prefer `task '<intent>'` so the workflow can survive agent/context resets.
  - For goal-oriented work, prefer `plan` -> `explain` -> `do --simulate` -> `do --approve`.
  - Prefer progressive disclosure: list -> show -> ops -> schema -> config doctor -> simulate -> invoke.
";

const AFTER_HELP: &str = "\
Examples:
  fwc guide
  fwc task \"append this summary to the Notion page named Roadmap\"
  fwc task show w:deadbeef
  fwc task resolve w:deadbeef --until ready
  fwc task ask w:deadbeef
  fwc task bind w:deadbeef connector=notion payload_json='{...}'
  fwc task approve w:deadbeef
  fwc task run w:deadbeef
  fwc list
  fwc plan \"create a GitHub issue titled 'FWC: add workflow macros'\"
  fwc explain \"find the Notion page named Roadmap and append this summary\"
  fwc do \"disable the slack connector in z:work\" --simulate
  fwc show github
  fwc show github --template '{{connector.slug}} => {{connector.name}}'
  fwc ops github
  fwc schema github issues.create
  fwc config schema github
  fwc simulate github issues.create --file payload.json
  fwc invoke github issues.create --file payload.json
  fwc invoke github issues.create --template-file issue_summary.hbs
  fwc show github --json --extract '.connector.slug'
  fwc pipeline list
  fwc pipeline validate .fwc/pipelines/notify-on-new-issues.toml
  fwc pipeline dry-run .fwc/pipelines/notify-on-new-issues.toml --param owner=octocat --param repo=hello-world
  fwc pipeline estimate .fwc/pipelines/notify-on-new-issues.toml --param owner=octocat --param repo=hello-world
  fwc recipe list
  fwc recipe show github-pr-review-notify
  fwc recipe dry-run github-pr-review-notify
  fwc recipe export github-pr-review-notify > .fwc/pipelines/github-pr-review-notify.toml
  fwc export-tools --format mcp --json
  fwc export-tools --format claude github
  fwc export-tools --format openai --risk-max medium --output tools.json
";

#[derive(Parser, Debug)]
#[command(name = "fwc")]
#[command(version, about = ABOUT, long_about = LONG_ABOUT, after_help = AFTER_HELP)]
#[command(arg_required_else_help = true, subcommand_required = true)]
struct Cli {
    /// Output format. Defaults to TOON for token-efficient agent consumption.
    #[arg(long, global = true, env = "FWC_FORMAT", value_enum, default_value_t = OutputFormat::Toon)]
    format: OutputFormat,

    /// Shortcut for `--format json`.
    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    /// Include token-efficiency statistics comparing TOON vs JSON byte counts.
    #[arg(long, global = true, default_value_t = false)]
    token_stats: bool,

    /// Render the JSON payload through an inline Handlebars template.
    #[arg(long, global = true, conflicts_with = "template_file")]
    template: Option<String>,

    /// Render the JSON payload through a Handlebars template loaded from a file.
    #[arg(long, global = true, value_name = "PATH", conflicts_with = "template")]
    template_file: Option<PathBuf>,

    /// Apply a jq/jaq filter to successful JSON output.
    #[arg(long, global = true, alias = "jq", value_name = "FILTER", conflicts_with_all = ["template", "template_file"])]
    extract: Option<String>,

    /// Explicit column list for table/CSV/TSV/Markdown formats (comma-separated).
    #[arg(long, global = true, value_delimiter = ',')]
    columns: Vec<String>,

    /// Sort tabular output by this column name.
    #[arg(long, global = true)]
    sort_by: Option<String>,

    /// Maximum number of rows in tabular output.
    #[arg(long, global = true, default_value_t = 0)]
    limit: usize,

    /// Suppress column headers in tabular output.
    #[arg(long, global = true, default_value_t = false)]
    no_headers: bool,

    /// Host endpoint or socket path for future host-backed execution.
    #[arg(long, global = true)]
    host: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Explain the fwc command taxonomy and UX contract in structured form.
    #[command(visible_alias = "contract")]
    Guide(GuideArgs),

    /// Create and resume durable workflow capsules for connector jobs.
    #[command(visible_alias = "tasks")]
    Task(TaskArgs),

    /// Compile a natural-language goal into exact primitive fwc steps.
    #[command(visible_alias = "workflow")]
    Plan(IntentArgs),

    /// Explain why the intent compiler chose a specific connector, template, and step sequence.
    #[command(visible_alias = "why")]
    Explain(IntentArgs),

    /// Materialize a compiled intent workflow with safe-by-default simulation.
    #[command(visible_alias = "run")]
    Do(DoIntentArgs),

    /// List connectors with concise lifecycle and health signals.
    List(ListArgs),

    /// Search connectors and operations without expanding full schemas.
    Search(SearchArgs),

    /// Show one connector's high-signal detail view.
    #[command(visible_alias = "info")]
    Show(ShowArgs),

    /// List operations for a connector.
    #[command(visible_alias = "operations")]
    Ops(OpsArgs),

    /// Show a single connector or operation schema.
    #[command(visible_alias = "spec")]
    Schema(SchemaArgs),

    /// Show a minimal example payload or config snippet.
    #[command(visible_alias = "example")]
    Examples(ExampleArgs),

    /// Report connector or fleet status.
    Status(StatusArgs),

    /// Enable a connector.
    Enable(TargetArgs),

    /// Disable a connector.
    Disable(TargetArgs),

    /// Start a connector runtime.
    Start(TargetArgs),

    /// Stop a connector runtime.
    Stop(TargetArgs),

    /// Restart a connector runtime.
    Restart(TargetArgs),

    /// Install a connector package.
    Install(InstallArgs),

    /// Update a connector package or channel.
    Update(UpdateArgs),

    /// Pin a connector to a specific version or channel.
    Pin(PinArgs),

    /// Remove a connector pin.
    Unpin(TargetArgs),

    /// Manage connector configuration with redaction-aware workflows.
    Config(ConfigArgs),

    /// Execute a connector operation.
    Invoke(InvokeArgs),

    /// Preflight or dry-run a connector operation.
    Simulate(InvokeArgs),

    /// Read connector logs or event streams.
    Logs(LogsArgs),

    /// Export tool schemas for AI agent runtimes (MCP, Claude, `OpenAI`).
    ///
    /// Generates tool definitions from connector introspection so every
    /// FCP connector becomes a tool in any agent runtime.
    #[command(visible_alias = "tools")]
    ExportTools(ExportToolsArgs),

    /// Suggest relevant operations based on context, goal, or recent usage.
    ///
    /// Exploration mode that helps agents discover what they can do without
    /// already knowing connector names or operation IDs.
    #[command(visible_alias = "what-can-i-do")]
    Suggest(SuggestArgs),

    /// Generate a fill-in-the-blanks JSON template for an operation.
    ///
    /// Produces scaffolded JSON with placeholder values and type annotations.
    #[command(visible_alias = "scaffold")]
    Template(TemplateArgs),

    /// Validate an operation input against its schema before invoking.
    ///
    /// Reports structured errors with fix suggestions for each problem.
    #[command(visible_alias = "check")]
    Validate(ValidateArgs),

    /// Browse the append-only operation audit log.
    ///
    /// Every invoke and simulate call is recorded. Query by connector,
    /// status, time range, or entry ID for debugging and replay.
    #[command(visible_alias = "audit")]
    History(HistoryArgs),

    /// Chain two operations: output of A feeds input of B via field mapping.
    ///
    /// Use `--map` to define source-to-target field mappings, or `--map-file`
    /// for complex mappings defined in a JSON file.
    #[command(visible_alias = "chain")]
    Pipe(PipeArgs),

    /// Define and plan named multi-step pipelines from TOML files.
    ///
    /// Pipelines let agents reuse validated step graphs instead of rebuilding
    /// multi-step connector workflows from scratch every time.
    #[command(visible_alias = "pipelines")]
    Pipeline(PipelineArgs),

    /// Browse and plan bundled cross-connector pipeline recipes.
    ///
    /// Recipes ship with starter parameter defaults so agents can inspect,
    /// validate, estimate, export, and customize common multi-step workflows.
    #[command(visible_alias = "recipes")]
    Recipe(RecipeArgs),

    /// Apply one operation to many inputs in parallel.
    ///
    /// Feed an inline JSON array, JSONL file, or template + items list
    /// and execute the same operation for each input with concurrency control.
    #[command(visible_alias = "batch")]
    Map(MapArgs),

    /// Execute a JSONL file of heterogeneous operations with dependency ordering.
    ///
    /// Each line is a different operation (possibly different connectors).
    /// Independent operations run in parallel; dependent ones follow topological order.
    #[command(name = "batch-file", visible_alias = "batch-ops")]
    BatchFile(BatchFileArgs),

    /// Tail real-time events from one or more connectors.
    ///
    /// Streams events in unified format. Use `--all` for all streaming
    /// connectors or specify a comma-separated list.
    #[command(visible_alias = "tail")]
    Events(EventsArgs),
}

#[derive(Args, Debug, Serialize)]
struct GuideArgs {
    /// Narrow the guide to a specific top-level command.
    #[arg(long)]
    command: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct IntentArgs {
    /// Natural-language task intent to compile into primitive fwc commands.
    intent: String,

    /// Optional explicit connector override when the service is already known.
    #[arg(long)]
    connector: Option<String>,

    /// Optional explicit zone hint such as z:work.
    #[arg(long)]
    zone: Option<String>,
}

impl IntentArgs {
    fn request(&self, mode: intent::IntentMode) -> intent::IntentRequest {
        intent::IntentRequest {
            intent: self.intent.clone(),
            connector_override: self.connector.clone(),
            zone_override: self.zone.clone(),
            mode,
        }
    }
}

#[derive(Args, Debug, Serialize)]
struct DoIntentArgs {
    /// Natural-language task intent to compile and materialize.
    intent: String,

    /// Optional explicit connector override when the service is already known.
    #[arg(long)]
    connector: Option<String>,

    /// Optional explicit zone hint such as z:work.
    #[arg(long)]
    zone: Option<String>,

    /// Force simulation mode explicitly. If omitted, `do` still defaults to simulation.
    #[arg(long, default_value_t = false)]
    simulate: bool,

    /// Explicitly approve the compiled workflow. The scaffold stays honest and still will not claim host-backed side effects.
    #[arg(long, default_value_t = false)]
    approve: bool,
}

impl DoIntentArgs {
    fn request(&self) -> intent::IntentRequest {
        intent::IntentRequest {
            intent: self.intent.clone(),
            connector_override: self.connector.clone(),
            zone_override: self.zone.clone(),
            mode: if self.approve {
                intent::IntentMode::DoApprove
            } else {
                intent::IntentMode::DoSimulate
            },
        }
    }
}

#[derive(Args, Debug, Serialize)]
struct TaskArgs {
    #[command(subcommand)]
    command: TaskCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum TaskCommand {
    /// Create a resumable workflow capsule from a natural-language intent.
    Create(IntentArgs),

    /// Show the current state of one workflow capsule.
    Show(TaskIdArgs),

    /// List recent workflow capsules.
    List(TaskListArgs),

    /// Resolve draft bindings, identifier candidates, and remaining questions without side effects.
    Resolve(TaskResolveArgs),

    /// Return the smallest current clarification question for a workflow capsule.
    Ask(TaskIdArgs),

    /// Advance a workflow capsule by executing the next safe stage.
    Advance(TaskIdArgs),

    /// Bind resolved values such as connector ids, payload files, or resource identifiers.
    Bind(TaskBindArgs),

    /// Mark the workflow capsule as approved for side-effecting execution.
    Approve(TaskIdArgs),

    /// Execute the workflow capsule according to its current approvals and bindings.
    Run(TaskIdArgs),
}

#[derive(Args, Debug, Serialize)]
struct TaskIdArgs {
    /// Workflow capsule id such as w:7f3k9a1b.
    task_id: String,
}

#[derive(Args, Debug, Serialize)]
struct TaskListArgs {
    /// Optional status filter such as ready-to-simulate, needs-bindings, approved, or materialized.
    #[arg(long)]
    status: Option<String>,

    /// Maximum number of capsules to list.
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum ResolveUntil {
    Ready,
}

#[derive(Args, Debug, Serialize)]
struct TaskResolveArgs {
    /// Workflow capsule id such as w:7f3k9a1b.
    task_id: String,

    /// Continue resolving until the capsule is ready or one external answer blocks progress.
    #[arg(long, value_enum)]
    until: Option<ResolveUntil>,

    /// Shortcut for `--until ready`.
    #[arg(long, default_value_t = false)]
    until_ready: bool,
}

impl TaskResolveArgs {
    const fn should_resolve_until_ready(&self) -> bool {
        self.until_ready || matches!(self.until, Some(ResolveUntil::Ready))
    }
}

#[derive(Args, Debug, Serialize)]
struct TaskBindArgs {
    /// Workflow capsule id such as w:7f3k9a1b.
    task_id: String,

    /// One or more `key=value` bindings, for example `connector=notion` or `payload_file=payload.json`.
    bindings: Vec<String>,
}

#[derive(Args, Debug, Serialize)]
struct ListArgs {
    /// Filter to a zone such as z:work or z:private.
    #[arg(long)]
    zone: Option<String>,

    /// Filter to a connector category such as messaging or analytics.
    #[arg(long)]
    category: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct SearchArgs {
    /// Search term across connector ids, names, and operation labels.
    query: String,

    /// Narrow search to one zone.
    #[arg(long)]
    zone: Option<String>,

    /// Restrict to a specific connector (slug or id).
    #[arg(long)]
    connector: Option<String>,

    /// Filter by capability family (e.g. "read", "write", "admin").
    #[arg(long)]
    capability: Option<String>,

    /// Maximum risk level to include (low, medium, high).
    #[arg(long)]
    risk: Option<String>,

    /// Maximum safety tier to include (safe, risky, dangerous, critical).
    #[arg(long)]
    safety: Option<String>,

    /// Filter by connector archetype (e.g. "operational", "streaming").
    #[arg(long)]
    archetype: Option<String>,

    /// Filter by connector category (e.g. "messaging", "dev-tools").
    #[arg(long)]
    category: Option<String>,

    /// Only show idempotent (safe to retry) operations.
    #[arg(long)]
    idempotent: bool,

    /// Maximum number of results to return.
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args, Debug, Serialize)]
struct ShowArgs {
    /// Connector id, alias, or family name.
    connector: String,
}

#[derive(Args, Debug, Serialize)]
struct OpsArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Optional risk ceiling to hide more dangerous operations.
    #[arg(long)]
    risk_at_most: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct SchemaArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Optional operation name. Omit to inspect the connector contract schema.
    operation: Option<String>,

    /// Show only required fields.
    #[arg(long)]
    required_only: bool,

    /// Drill into a specific field path (e.g. `spec.containers`).
    #[arg(long)]
    field: Option<String>,

    /// Include example values from `ai_hints`.
    #[arg(long)]
    examples: bool,

    /// Generate a minimal JSON scaffold with required-field placeholders.
    #[arg(long)]
    scaffold: bool,
}

#[derive(Args, Debug, Serialize)]
struct ExampleArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Optional operation name for an operation-specific example.
    operation: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct StatusArgs {
    /// Optional connector id. Omit for fleet status.
    connector: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct TargetArgs {
    /// Connector id, alias, or family name.
    connector: String,
}

#[derive(Args, Debug, Serialize)]
struct InstallArgs {
    /// Connector id, alias, or package coordinate.
    connector: String,

    /// Optional version or channel.
    #[arg(long)]
    version: Option<String>,

    /// Verify only and do not activate the connector.
    #[arg(long, default_value_t = false)]
    verify_only: bool,
}

#[derive(Args, Debug, Serialize)]
struct UpdateArgs {
    /// Connector id, alias, or package coordinate.
    connector: String,

    /// Optional target version or channel.
    #[arg(long)]
    to: Option<String>,

    /// Explain the update plan without applying it.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Args, Debug, Serialize)]
struct PinArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Version or channel to pin.
    #[arg(long)]
    to: String,
}

#[derive(Args, Debug, Serialize)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum ConfigCommand {
    /// Show config schema for one connector.
    Schema(TargetArgs),

    /// Read current config state.
    Get(TargetArgs),

    /// Set a single config key.
    Set(ConfigSetArgs),

    /// Remove a single config key.
    Unset(ConfigUnsetArgs),

    /// Import config from a file.
    Import(ConfigFileArgs),

    /// Export config to stdout or a file.
    Export(ConfigFileArgs),

    /// Validate config and surface actionable remediation.
    Doctor(TargetArgs),
}

#[derive(Args, Debug, Serialize)]
struct ConfigSetArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Configuration key path.
    key: String,

    /// New value.
    value: String,
}

#[derive(Args, Debug, Serialize)]
struct ConfigUnsetArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Configuration key path to remove.
    key: String,
}

#[derive(Args, Debug, Serialize)]
struct ConfigFileArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// File path for import/export.
    #[arg(long)]
    file: Option<PathBuf>,
}

#[derive(Args, Debug, Serialize)]
struct InvokeArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Operation name.
    operation: String,

    /// Inline JSON string for small requests.
    #[arg(long)]
    input: Option<String>,

    /// File path for a request payload.
    #[arg(long)]
    file: Option<PathBuf>,

    /// Read request payload from stdin.
    #[arg(long, default_value_t = false)]
    stdin: bool,
}

#[derive(Args, Debug, Serialize)]
struct LogsArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Follow log output as it arrives.
    #[arg(long, default_value_t = false)]
    follow: bool,

    /// Optional duration like 15m or 1h for historical log windows.
    #[arg(long)]
    since: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct ExportToolsArgs {
    /// Tool schema format to export.
    #[arg(long, value_enum)]
    format: export_tools::ToolSchemaFormat,

    /// Optional connector selector. Omit to export all connectors.
    connector: Option<String>,

    /// Maximum risk level to include (low, medium, high, critical).
    #[arg(long)]
    risk_max: Option<String>,

    /// Filter to a capability prefix (e.g. `github.read`).
    #[arg(long)]
    capability: Option<String>,

    /// Strip a connector namespace prefix from tool names.
    #[arg(long)]
    strip_prefix: Option<String>,

    /// Exclude safety metadata from descriptions and annotations.
    #[arg(long, default_value_t = false)]
    no_safety: bool,

    /// Exclude AI hints from descriptions.
    #[arg(long, default_value_t = false)]
    no_hints: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Args, Debug, Serialize)]
struct SuggestArgs {
    /// Natural-language goal to find operations for.
    #[arg(long)]
    goal: Option<String>,

    /// Restrict to a specific connector.
    #[arg(long)]
    connector: Option<String>,

    /// Suggest follow-up operations after a specific operation.
    #[arg(long)]
    after: Option<String>,

    /// Maximum risk level to include (low, medium, high).
    #[arg(long)]
    risk: Option<String>,

    /// Group results by action family (read, write, manage).
    #[arg(long, default_value_t = false)]
    grouped: bool,

    /// Maximum number of suggestions.
    #[arg(long, default_value_t = 10)]
    limit: usize,
}

#[derive(Args, Debug, Serialize)]
struct TemplateArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Operation name.
    operation: String,

    /// Only include required fields.
    #[arg(long, default_value_t = false)]
    required_only: bool,

    /// Pre-fill values as key=value pairs (comma separated).
    #[arg(long)]
    fill: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct ValidateArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Operation name.
    operation: String,

    /// Inline JSON string input to validate.
    #[arg(long)]
    input: Option<String>,

    /// File path for input JSON to validate.
    #[arg(long, value_name = "PATH")]
    input_file: Option<std::path::PathBuf>,
}

#[derive(Args, Debug, Serialize)]
struct HistoryArgs {
    /// Show details for a specific entry ID.
    entry_id: Option<String>,

    /// Filter by connector slug.
    #[arg(long)]
    connector: Option<String>,

    /// Filter by status (success, error, timeout, `rate_limited`, denied, simulated).
    #[arg(long)]
    status: Option<String>,

    /// Show entries since duration (e.g. `1h`, `30m`, `7d`).
    #[arg(long)]
    since: Option<String>,

    /// Maximum number of entries to return.
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args, Debug, Serialize)]
struct PipeArgs {
    /// Source operation (e.g. `github.list_issues`).
    source: String,

    /// Target operation (e.g. `slack.send_message`).
    target: String,

    /// Field mapping expression (e.g. `"title -> text, body -> desc"`).
    #[arg(long)]
    map: Option<String>,

    /// Path to a JSON mapping file.
    #[arg(long, value_name = "PATH")]
    map_file: Option<PathBuf>,

    /// Preview the mapped input without executing the target operation.
    #[arg(long)]
    dry_run: bool,

    /// Include intermediate output from the source operation.
    #[arg(long)]
    include_intermediate: bool,
}

#[derive(Args, Debug, Serialize)]
struct RecipeArgs {
    #[command(subcommand)]
    command: RecipeCommand,
}

#[derive(Subcommand, Debug, Serialize)]
enum RecipeCommand {
    /// List bundled built-in recipes.
    List(RecipeListArgs),

    /// Show one built-in recipe definition, estimate, and export target.
    Show(RecipeRefArgs),

    /// Validate one built-in recipe definition without planning execution.
    Validate(RecipeRefArgs),

    /// Plan one built-in recipe with bound parameters.
    Run(RecipeRunArgs),

    /// Build a recipe plan without pretending to execute it.
    #[command(name = "dry-run", visible_alias = "preview")]
    DryRun(RecipeRunArgs),

    /// Summarize recipe cost, risk, approvals, and declared rate-limit impact.
    Estimate(RecipeRunArgs),

    /// Export one built-in recipe as raw TOML for local customization.
    Export(RecipeRefArgs),
}

#[derive(Args, Debug, Default, Serialize)]
struct RecipeListArgs {}

#[derive(Args, Debug, Serialize)]
struct RecipeRefArgs {
    /// Built-in recipe slug.
    recipe: String,
}

#[derive(Args, Debug, Serialize)]
struct RecipeRunArgs {
    /// Built-in recipe slug.
    recipe: String,

    /// Bind a recipe parameter as KEY=VALUE.
    #[arg(long = "param", value_name = "KEY=VALUE")]
    params: Vec<String>,
}

#[derive(Args, Debug, Serialize)]
struct PipelineArgs {
    #[command(subcommand)]
    command: PipelineCommand,
}

#[derive(Subcommand, Debug, Serialize)]
enum PipelineCommand {
    /// List discovered project and user pipeline definitions.
    List(PipelineListArgs),

    /// Show one pipeline definition and its validation report.
    Show(PipelineRefArgs),

    /// Validate one pipeline definition without planning execution.
    Validate(PipelineRefArgs),

    /// Plan a pipeline run with bound parameters.
    Run(PipelineRunArgs),

    /// Build a pipeline plan without pretending to execute it.
    #[command(name = "dry-run", visible_alias = "preview")]
    DryRun(PipelineRunArgs),

    /// Summarize pipeline cost, risk, approvals, and declared rate-limit impact.
    Estimate(PipelineRunArgs),
}

#[derive(Args, Debug, Default, Serialize)]
struct PipelineListArgs {}

#[derive(Args, Debug, Serialize)]
struct PipelineRefArgs {
    /// Pipeline name or explicit TOML path.
    pipeline: String,
}

#[derive(Args, Debug, Serialize)]
struct PipelineRunArgs {
    /// Pipeline name or explicit TOML path.
    pipeline: String,

    /// Bind a pipeline parameter as KEY=VALUE.
    #[arg(long = "param", value_name = "KEY=VALUE")]
    params: Vec<String>,
}

#[derive(Args, Debug, Serialize)]
struct MapArgs {
    /// Operation to apply to every input (e.g. `github.get_issue`).
    operation: String,

    /// Inline JSON array of inputs.
    #[arg(long, value_name = "JSON")]
    inputs: Option<String>,

    /// Path to a JSONL file of inputs (one JSON object per line).
    #[arg(long, value_name = "PATH")]
    input_file: Option<PathBuf>,

    /// JSON template with `{{item}}` placeholder.
    #[arg(long, value_name = "TEMPLATE")]
    input_template: Option<String>,

    /// Comma-separated items to substitute into the template.
    #[arg(long, value_name = "ITEMS")]
    items: Option<String>,

    /// Maximum number of concurrent operations.
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// What to do when an item fails: `abort` or `continue`.
    #[arg(long, default_value = "abort")]
    on_error: String,
}

#[derive(Args, Debug, Serialize)]
struct BatchFileArgs {
    /// Path to a JSONL batch file.
    file: PathBuf,

    /// Preview the execution plan without running anything.
    #[arg(long)]
    dry_run: bool,

    /// Maximum number of concurrent operations per wave.
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// What to do when an operation fails: `abort` or `continue`.
    #[arg(long, default_value = "abort")]
    on_error: String,
}

#[derive(Args, Debug, Serialize)]
struct EventsArgs {
    /// Connectors to tail (comma-separated, e.g. `slack,discord`).
    connectors: Option<String>,

    /// Tail all streaming connectors.
    #[arg(long)]
    all: bool,

    /// Include events from this duration ago (e.g. `5m`, `1h`, `30s`).
    #[arg(long, value_name = "DURATION")]
    since: Option<String>,

    /// Backpressure buffer size.
    #[arg(long, default_value_t = 1000)]
    buffer_size: usize,
}

fn main() -> ExitCode {
    let raw_args = std::env::args().collect::<Vec<_>>();
    let fallback_format = infer_output_format(&raw_args);
    let include_token_stats = infer_token_stats_requested(&raw_args);
    match execute(&raw_args) {
        Ok(outcome) => {
            print!("{}", outcome.text);
            outcome.exit_code
        }
        Err(error) => {
            match render_dispatch(
                internal_error_dispatch(&raw_args, &error),
                fallback_format,
                include_token_stats,
                &RenderOptions::default(),
            ) {
                Ok(outcome) => {
                    print!("{}", outcome.text);
                    outcome.exit_code
                }
                Err(render_error) => {
                    eprintln!("fwc: {error:#}");
                    eprintln!("fwc: failed to render structured internal error: {render_error:#}");
                    CliExitCode::Internal.into()
                }
            }
        }
    }
}

fn execute(raw_args: &[String]) -> Result<ExecutionOutcome> {
    let fallback_format = infer_output_format(raw_args);
    let include_token_stats = infer_token_stats_requested(raw_args);

    match prepare_cli(raw_args) {
        Ok(prepared) => {
            let mut dispatch = dispatch(&prepared.cli)?;
            annotate_with_corrections(
                &mut dispatch.payload,
                &prepared.received_args,
                &prepared.normalized_args,
                &prepared.corrections,
            );
            match render_dispatch(
                dispatch,
                prepared.format,
                prepared.cli.token_stats,
                &prepared.render_options,
            ) {
                Ok(outcome) => Ok(outcome),
                Err(error) if prepared.render_options.has_extract() => render_dispatch(
                    extract_render_failure_dispatch(
                        &prepared.received_args,
                        &prepared.normalized_args,
                        &error,
                        &prepared.render_options,
                    ),
                    prepared.format,
                    false,
                    &RenderOptions::default(),
                ),
                Err(error) if prepared.render_options.has_template() => render_dispatch(
                    template_render_failure_dispatch(
                        &prepared.received_args,
                        &prepared.normalized_args,
                        &error,
                        &prepared.render_options,
                    ),
                    prepared.format,
                    false,
                    &RenderOptions::default(),
                ),
                Err(error) => Err(error),
            }
        }
        Err(PrepareCliError::Clap(error)) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => Ok(ExecutionOutcome {
                text: error.to_string(),
                exit_code: ExitCode::SUCCESS,
            }),
            _ => {
                let dispatch = parse_failure_dispatch(raw_args, &error);
                render_dispatch(
                    dispatch,
                    fallback_format,
                    include_token_stats,
                    &RenderOptions::default(),
                )
            }
        },
        Err(PrepareCliError::Structured(dispatch)) => render_dispatch(
            dispatch,
            fallback_format,
            include_token_stats,
            &RenderOptions::default(),
        ),
    }
}

fn render_dispatch(
    mut dispatch: DispatchOutcome,
    format: OutputFormat,
    include_token_stats: bool,
    render_options: &RenderOptions,
) -> Result<ExecutionOutcome> {
    let effective_render_options = if dispatch.exit_code.is_success() {
        render_options.clone()
    } else {
        render_options.without_extract()
    };

    annotate_output_contract(
        &mut dispatch.payload,
        format,
        dispatch.exit_code,
        include_token_stats,
        &effective_render_options,
    );

    Ok(ExecutionOutcome {
        text: render_with_options(dispatch.payload, format, &effective_render_options)?,
        exit_code: dispatch.exit_code.into(),
    })
}

fn annotate_output_contract(
    payload: &mut Value,
    format: OutputFormat,
    exit_code: CliExitCode,
    include_token_stats: bool,
    render_options: &RenderOptions,
) {
    let template_active = render_options.has_template();
    let extract_active = render_options.has_extract();
    let transform_active = render_options.has_transform();
    let token_stats_enabled = include_token_stats && !transform_active;
    let exit = json!({
        "code": exit_code.as_u8(),
        "name": exit_code.label(),
        "category": exit_code.category(),
        "success": exit_code.is_success(),
    });
    let stats = token_stats_enabled.then(|| token_stats(payload, format));

    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "_output".to_owned(),
            json!({
                "default_format": OutputFormat::Toon.as_str(),
                "selected_format": if template_active { "template" } else { format.as_str() },
                "base_format": format.as_str(),
                "transform": render_options.transform_metadata(),
                "newline_terminated": true,
                "token_stats_requested": include_token_stats,
                "token_stats_enabled": token_stats_enabled,
                "token_stats_unavailable_reason": if include_token_stats && transform_active {
                    Some(if template_active {
                        "disabled when output is post-processed by a Handlebars template"
                    } else if extract_active {
                        "disabled when output is post-processed by a jq extract filter"
                    } else {
                        "disabled when output is post-processed"
                    })
                } else {
                    None
                },
                "exit": exit,
                "token_stats": stats,
            }),
        );
    }
    if let Some(error) = payload.get_mut("error").and_then(Value::as_object_mut) {
        error.insert(
            "exit".to_owned(),
            json!({
                "code": exit_code.as_u8(),
                "name": exit_code.label(),
                "category": exit_code.category(),
                "success": exit_code.is_success(),
            }),
        );
    }
}

fn infer_token_stats_requested(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--token-stats")
}

#[allow(clippy::too_many_lines)]
fn build_render_options(
    cli: &Cli,
    format: OutputFormat,
    received_args: &[String],
    normalized_args: &[String],
) -> std::result::Result<RenderOptions, PrepareCliError> {
    let template = match (cli.template.as_ref(), cli.template_file.as_ref()) {
        (Some(template), None) => Some(TemplateRender::inline(template.clone()).map_err(|error| {
            PrepareCliError::Structured(structured_error(
                "invalid-template",
                format!("The inline Handlebars template is invalid: {error:#}"),
                CliExitCode::Validation,
                true,
                received_args,
                normalized_args,
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec![
                        "fwc show github --template '{{connector.slug}}'".to_owned(),
                        "fwc show github --template '{{json connector}}'".to_owned(),
                    ],
                    next_actions: vec![
                        "Fix the template syntax and retry.".to_owned(),
                        "Use `--template-file <path>` if inline quoting is getting in the way."
                            .to_owned(),
                    ],
                },
            ))
        })?),
        (None, Some(path)) => Some(TemplateRender::from_file(path).map_err(|error| {
            PrepareCliError::Structured(structured_error(
                "invalid-template-file",
                format!("The Handlebars template file could not be loaded: {error:#}"),
                CliExitCode::Validation,
                true,
                received_args,
                normalized_args,
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec![
                        format!("fwc show github --template-file {}", path.display()),
                        "fwc show github --template '{{connector.slug}}'".to_owned(),
                    ],
                    next_actions: vec![
                        "Check that the template file exists, is readable, and contains valid Handlebars syntax."
                            .to_owned(),
                        "Rerun with `--format json` and no template if you need to inspect the raw payload shape first."
                            .to_owned(),
                    ],
                },
            ))
        })?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces template flag conflicts"),
    };

    let extract = match cli.extract.as_ref() {
        Some(_filter) if !format.is_json_like() => {
            return Err(PrepareCliError::Structured(structured_error(
                "extract-requires-json-output",
                "The `--extract` filter only runs on JSON output. Re-run with `--json`, `--format jsonl`, or `--format ndjson`.",
                CliExitCode::Validation,
                true,
                received_args,
                normalized_args,
                ErrorDetails {
                    did_you_mean: vec![
                        "Did you mean `--json --extract '<filter>'`?".to_owned(),
                        "Or `--format ndjson --extract '<filter>'` for line-oriented JSON output?"
                            .to_owned(),
                    ],
                    examples: vec![
                        "fwc show github --json --extract '.connector.slug'".to_owned(),
                        "fwc search github --format ndjson --extract '.results[]'".to_owned(),
                    ],
                    next_actions: vec![
                        "Switch the output format to JSON before applying `--extract`."
                            .to_owned(),
                        "Use plain TOON or tabular output without `--extract` if you want the full human-oriented view."
                            .to_owned(),
                    ],
                },
            )));
        }
        Some(filter) => Some(ExtractRender::inline(filter.clone()).map_err(|error| {
            PrepareCliError::Structured(structured_error(
                "invalid-extract-filter",
                format!("The jq extract filter is invalid: {error:#}"),
                CliExitCode::Validation,
                true,
                received_args,
                normalized_args,
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec![
                        "fwc show github --json --extract '.connector.slug'".to_owned(),
                        "fwc search github --json --extract '.results | length'".to_owned(),
                        "fwc invoke github issues.create --json --extract '.captures.operation'".to_owned(),
                    ],
                    next_actions: vec![
                        "Fix the jq syntax and retry.".to_owned(),
                        "Inspect the raw payload with `--json` first if you are unsure about the field path."
                            .to_owned(),
                    ],
                },
            ))
        })?),
        None => None,
    };

    Ok(RenderOptions {
        template,
        extract,
        tabular_columns: cli.columns.clone(),
        tabular_sort_by: cli.sort_by.clone(),
        tabular_limit: cli.limit,
        tabular_no_headers: cli.no_headers,
    })
}

fn internal_error_dispatch(args: &[String], error: &anyhow::Error) -> DispatchOutcome {
    let mut dispatch = structured_error(
        "internal-error",
        "fwc hit an unexpected internal error before it could finish the request.",
        CliExitCode::Internal,
        false,
        args,
        args,
        ErrorDetails {
            did_you_mean: Vec::new(),
            examples: vec!["fwc guide".to_owned(), "fwc list --format json".to_owned()],
            next_actions: vec![
                "Retry the command with `--format json` if you need the full structured envelope."
                    .to_owned(),
                "Inspect the attached debug chain before filing or triaging the failure."
                    .to_owned(),
            ],
        },
    );

    if let Some(error_obj) = dispatch
        .payload
        .get_mut("error")
        .and_then(Value::as_object_mut)
    {
        error_obj.insert(
            "debug_chain".to_owned(),
            json!(error.chain().map(ToString::to_string).collect::<Vec<_>>()),
        );
    }

    dispatch
}

fn template_render_failure_dispatch(
    received_args: &[String],
    normalized_args: &[String],
    error: &anyhow::Error,
    render_options: &RenderOptions,
) -> DispatchOutcome {
    let mut dispatch = structured_error(
        "template-render-failed",
        format!(
            "The Handlebars template could not be rendered against this command's JSON payload: {error:#}"
        ),
        CliExitCode::Validation,
        true,
        received_args,
        normalized_args,
        ErrorDetails {
            did_you_mean: Vec::new(),
            examples: vec![
                "fwc show github --format json".to_owned(),
                "fwc show github --template '{{connector.slug}}'".to_owned(),
                "fwc show github --template '{{json connector}}'".to_owned(),
            ],
            next_actions: vec![
                "Inspect the raw payload with `--format json` to verify the field paths you are referencing."
                    .to_owned(),
                "Use `{{json ...}}` or `{{compact ...}}` inside the template to inspect nested values."
                    .to_owned(),
            ],
        },
    );

    if let Some(error_obj) = dispatch
        .payload
        .get_mut("error")
        .and_then(Value::as_object_mut)
    {
        error_obj.insert(
            "debug_chain".to_owned(),
            json!(error.chain().map(ToString::to_string).collect::<Vec<_>>()),
        );
        error_obj.insert(
            "transform".to_owned(),
            render_options.transform_metadata().unwrap_or(Value::Null),
        );
    }

    dispatch
}

fn extract_render_failure_dispatch(
    received_args: &[String],
    normalized_args: &[String],
    error: &anyhow::Error,
    render_options: &RenderOptions,
) -> DispatchOutcome {
    let mut dispatch = structured_error(
        "extract-render-failed",
        format!("The jq extract filter could not be evaluated against this command's JSON payload: {error:#}"),
        CliExitCode::Validation,
        true,
        received_args,
        normalized_args,
        ErrorDetails {
            did_you_mean: Vec::new(),
            examples: vec![
                "fwc show github --json --extract '.connector.slug'".to_owned(),
                "fwc search github --json --extract '.results | length'".to_owned(),
                "fwc show github --json".to_owned(),
            ],
            next_actions: vec![
                "Inspect the raw payload with `--json` first to confirm the field path you are selecting."
                    .to_owned(),
                "Use jq-safe patterns like `?`, `//`, or narrower selectors if the payload shape can vary."
                    .to_owned(),
            ],
        },
    );

    if let Some(error_obj) = dispatch
        .payload
        .get_mut("error")
        .and_then(Value::as_object_mut)
    {
        error_obj.insert(
            "debug_chain".to_owned(),
            json!(error.chain().map(ToString::to_string).collect::<Vec<_>>()),
        );
        error_obj.insert(
            "transform".to_owned(),
            render_options.transform_metadata().unwrap_or(Value::Null),
        );
    }

    dispatch
}

fn dispatch(cli: &Cli) -> Result<DispatchOutcome> {
    let outcome = match &cli.command {
        Commands::Guide(args) => {
            let mut payload = catalog::guide_payload(args.command.as_deref());
            let exit_code = if payload["status"] == "unknown-command" {
                enrich_unknown_guide_command(&mut payload, args.command.as_deref());
                CliExitCode::UnknownCommand
            } else {
                CliExitCode::Success
            };
            DispatchOutcome { payload, exit_code }
        }
        Commands::Task(args) => task_dispatch(args)?,
        Commands::Plan(args) => intent_plan_dispatch(&args.request(intent::IntentMode::Plan))?,
        Commands::Explain(args) => {
            intent_explain_dispatch(&args.request(intent::IntentMode::Explain))?
        }
        Commands::Do(args) => intent_do_dispatch(args)?,
        Commands::List(args) => list_dispatch(args)?,
        Commands::Search(args) => search_dispatch(args)?,
        Commands::Show(args) => show_dispatch(args)?,
        Commands::Ops(args) => ops_dispatch(args)?,
        Commands::Schema(args) => schema_dispatch(args)?,
        Commands::Examples(args) => examples_dispatch(args)?,
        Commands::Status(args) => planned("status", args)?,
        Commands::Enable(args) => planned("enable", args)?,
        Commands::Disable(args) => planned("disable", args)?,
        Commands::Start(args) => planned("start", args)?,
        Commands::Stop(args) => planned("stop", args)?,
        Commands::Restart(args) => planned("restart", args)?,
        Commands::Install(args) => planned("install", args)?,
        Commands::Update(args) => planned("update", args)?,
        Commands::Pin(args) => planned("pin", args)?,
        Commands::Unpin(args) => planned("unpin", args)?,
        Commands::Config(args) => planned("config", args)?,
        Commands::Invoke(args) => planned("invoke", args)?,
        Commands::Simulate(args) => planned("simulate", args)?,
        Commands::Logs(args) => planned("logs", args)?,
        Commands::ExportTools(args) => export_tools_dispatch(args)?,
        Commands::Suggest(args) => suggest_dispatch(args)?,
        Commands::Template(args) => template_dispatch(args)?,
        Commands::Validate(args) => validate_dispatch(args)?,
        Commands::History(args) => history_dispatch(args)?,
        Commands::Pipe(args) => pipe_dispatch(args)?,
        Commands::Pipeline(args) => pipeline_dispatch(args)?,
        Commands::Recipe(args) => planned("recipe", args)?,
        Commands::Map(args) => map_dispatch(args)?,
        Commands::BatchFile(args) => batch_file_dispatch(args)?,
        Commands::Events(args) => planned("events", args)?,
    };

    Ok(outcome)
}

fn planned<T>(command: &str, args: &T) -> Result<DispatchOutcome>
where
    T: Serialize,
{
    Ok(DispatchOutcome {
        payload: catalog::planned_payload(command, &serde_json::to_value(args)?),
        exit_code: CliExitCode::Success,
    })
}

fn list_dispatch(args: &ListArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connectors = catalog
        .list(args.zone.as_deref(), args.category.as_deref())
        .into_iter()
        .map(connector_list_entry)
        .collect::<Vec<_>>();
    let filters = json!({
        "zone": args.zone.clone(),
        "category": args.category.clone(),
    });

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "list",
            "source": "workspace-manifests",
            "message": format!("Listed {} connectors from workspace manifests.", connectors.len()),
            "filters": filters,
            "connectors": connectors,
            "next_actions": [
                "Use `fwc show <connector>` to inspect one connector in detail.",
                "Use `fwc ops <connector>` to enumerate operations before asking for schemas.",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn search_dispatch(args: &SearchArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;

    let filters = search::SearchFilters {
        connector: args.connector.clone(),
        capability: args.capability.clone(),
        risk_max: args.risk.as_deref().and_then(search::RiskCeiling::parse),
        safety_max: args
            .safety
            .as_deref()
            .and_then(search::SafetyCeiling::parse),
        archetype: args.archetype.clone(),
        category: args.category.clone(),
        idempotent_only: args.idempotent,
        zone: args.zone.clone(),
    };

    let results = search::search_operations(catalog.connectors(), &args.query, &filters);
    let total = results.len();
    let json_results = search::results_to_json(&results, args.limit);

    let active_filters: Vec<String> = [
        args.connector.as_deref().map(|v| format!("connector={v}")),
        args.capability
            .as_deref()
            .map(|v| format!("capability={v}")),
        args.risk.as_deref().map(|v| format!("risk<={v}")),
        args.safety.as_deref().map(|v| format!("safety<={v}")),
        args.archetype.as_deref().map(|v| format!("archetype={v}")),
        args.category.as_deref().map(|v| format!("category={v}")),
        args.zone.as_deref().map(|v| format!("zone={v}")),
        if args.idempotent {
            Some("idempotent=true".to_owned())
        } else {
            None
        },
    ]
    .into_iter()
    .flatten()
    .collect();

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "search",
            "source": "workspace-manifests",
            "message": format!("Found {} matching operations ({} shown).", total, json_results.len()),
            "query": &args.query,
            "filters": active_filters,
            "total_results": total,
            "results": json_results,
            "next_actions": [
                "Use `fwc show <connector>` to inspect a connector in more detail.",
                "Use `fwc schema <connector> <operation>` for the input/output schema.",
                "Add --capability, --risk, --safety, --idempotent flags to narrow results.",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn show_dispatch(args: &ShowArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "show",
                &args.connector,
                &error,
            ));
        }
    };
    let preview = connector
        .operations
        .iter()
        .take(8)
        .map(operation_summary_entry)
        .collect::<Vec<_>>();
    let preview_truncated = connector.operations.len() > preview.len();
    let risky_count = connector
        .operations
        .iter()
        .filter(|operation| {
            matches!(
                operation.summary.safety_tier.as_str(),
                "risky" | "dangerous" | "critical"
            )
        })
        .count();
    let example_operation = connector.operations.first().map_or_else(
        || "<operation>".to_owned(),
        |operation| operation.preferred_selector.clone(),
    );
    let slug = connector.slug.clone();
    let summary = &connector.detail.summary;

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "show",
            "source": "workspace-manifests",
            "message": "Loaded connector detail from the workspace manifest.",
            "connector": {
                "slug": &slug,
                "canonical_id": &summary.id,
                "name": &summary.name,
                "version": &summary.version,
                "description": &summary.description,
                "cohort": &connector.cohort,
                "format": &connector.runtime_format,
                "state": summary.state,
                "state_model": connector.state_model.clone(),
                "archetypes": summary.archetypes.clone(),
                "operation_count": summary.operation_count,
                "max_risk": &summary.max_risk,
                "has_events": summary.has_events,
                "manifest_path": &connector.manifest_path,
            },
            "zones": connector.zones.clone(),
            "capabilities": connector.capabilities.clone(),
            "rate_limits": connector.detail.rate_limits.clone(),
            "operations": {
                "preview": preview,
                "preview_truncated": preview_truncated,
                "risky_count": risky_count,
                "safe_count": connector.operations.len().saturating_sub(risky_count),
            },
            "next_actions": [
                format!("fwc ops {slug}"),
                format!("fwc schema {slug} {example_operation}"),
                format!("fwc examples {slug} {example_operation}"),
                format!("fwc config schema {slug}"),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn ops_dispatch(args: &OpsArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "ops",
                &args.connector,
                &error,
            ));
        }
    };
    let slug = connector.slug.clone();
    let operations = connector
        .operations
        .iter()
        .filter(|operation| risk_filter_allows(operation, args.risk_at_most.as_deref()))
        .map(operation_summary_entry)
        .collect::<Vec<_>>();

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "ops",
            "source": "workspace-manifests",
            "message": format!("Listed {} operations for `{slug}`.", operations.len()),
            "connector": {
                "slug": &slug,
                "canonical_id": &connector.detail.summary.id,
                "name": &connector.detail.summary.name,
            },
            "filters": {
                "risk_at_most": args.risk_at_most.clone(),
            },
            "operations": operations,
            "next_actions": [
                format!("fwc schema {slug} <operation>"),
                format!("fwc examples {slug} <operation>"),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(clippy::too_many_lines)]
fn schema_dispatch(args: &SchemaArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "schema",
                &args.connector,
                &error,
            ));
        }
    };

    if let Some(operation_selector) = args.operation.as_deref() {
        let operation = match connector.resolve_operation(operation_selector) {
            Ok(operation) => operation,
            Err(error) => {
                return Ok(operation_resolution_dispatch(
                    "schema",
                    connector,
                    operation_selector,
                    &error,
                ));
            }
        };

        // ── Deep navigator mode ────────────────────────────────────
        if args.scaffold {
            let scaffold = schema_nav::scaffold_template(&operation.input_schema);
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "ok",
                    "command": "schema",
                    "source": "workspace-manifests",
                    "scope": "scaffold",
                    "connector": { "slug": &connector.slug },
                    "operation": { "selector": &operation.preferred_selector },
                    "scaffold": scaffold,
                }),
                exit_code: CliExitCode::Success,
            });
        }

        let example_strs: &[String] = if args.examples {
            &operation.examples
        } else {
            &[]
        };

        let mut fields = schema_nav::walk_schema(&operation.input_schema, example_strs);

        if args.required_only {
            fields.retain(|f| f.required);
        }
        if let Some(ref field_path) = args.field {
            fields = schema_nav::filter_by_field(&fields, field_path);
        }

        // When any navigator flag is active, return the annotated field listing.
        if args.required_only || args.field.is_some() || args.examples {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "ok",
                    "command": "schema",
                    "source": "workspace-manifests",
                    "scope": "fields",
                    "connector": {
                        "slug": &connector.slug,
                        "canonical_id": &connector.detail.summary.id,
                    },
                    "operation": {
                        "selector": &operation.preferred_selector,
                        "canonical_id": &operation.actual_id,
                    },
                    "field_count": fields.len(),
                    "fields": fields,
                    "next_actions": [
                        format!("fwc schema {} {} --scaffold", connector.slug, operation.preferred_selector),
                    ],
                }),
                exit_code: CliExitCode::Success,
            });
        }

        // ── Default: full schema view ────────────────────────────────
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "ok",
                "command": "schema",
                "source": "workspace-manifests",
                "scope": "operation",
                "message": "Loaded one operation schema from the connector manifest.",
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": &connector.detail.summary.id,
                    "name": &connector.detail.summary.name,
                },
                "operation": {
                    "requested_selector": operation_selector,
                    "selector": &operation.preferred_selector,
                    "canonical_id": &operation.actual_id,
                    "aliases": operation.aliases.clone(),
                    "summary": &operation.summary.summary,
                    "capability": &operation.summary.capability,
                    "risk_level": &operation.summary.risk_level,
                    "safety_tier": &operation.summary.safety_tier,
                    "approval_mode": &operation.approval_mode,
                },
                "input_schema": operation.input_schema.clone(),
                "output_schema": operation.output_schema.clone(),
                "guidance": {
                    "when_to_use": &operation.when_to_use,
                    "common_mistakes": operation.common_mistakes.clone(),
                    "related": operation.related.clone(),
                },
                "next_actions": [
                    format!("fwc examples {} {}", connector.slug, operation.preferred_selector),
                    format!("fwc schema {} {} --required-only", connector.slug, operation.preferred_selector),
                    format!("fwc schema {} {} --scaffold", connector.slug, operation.preferred_selector),
                    format!("fwc simulate {} {} --file payload.json", connector.slug, operation.preferred_selector),
                ],
            }),
            exit_code: CliExitCode::Success,
        });
    }

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "schema",
            "source": "workspace-manifests",
            "scope": "connector",
            "message": "Loaded the connector contract schema from the manifest.",
            "connector": {
                "slug": &connector.slug,
                "canonical_id": &connector.detail.summary.id,
                "name": &connector.detail.summary.name,
            },
            "schema": connector.connector_schema.clone(),
            "next_actions": [
                format!("fwc ops {}", connector.slug),
                format!("fwc config schema {}", connector.slug),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn examples_dispatch(args: &ExampleArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "examples",
                &args.connector,
                &error,
            ));
        }
    };

    if let Some(operation_selector) = args.operation.as_deref() {
        let operation = match connector.resolve_operation(operation_selector) {
            Ok(operation) => operation,
            Err(error) => {
                return Ok(operation_resolution_dispatch(
                    "examples",
                    connector,
                    operation_selector,
                    &error,
                ));
            }
        };

        return Ok(DispatchOutcome {
            payload: json!({
                "status": "ok",
                "command": "examples",
                "source": "workspace-manifests",
                "scope": "operation",
                "message": "Loaded operation examples from the connector manifest.",
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": &connector.detail.summary.id,
                    "name": &connector.detail.summary.name,
                },
                "operation": {
                    "requested_selector": operation_selector,
                    "selector": &operation.preferred_selector,
                    "canonical_id": &operation.actual_id,
                    "aliases": operation.aliases.clone(),
                    "when_to_use": &operation.when_to_use,
                },
                "examples": operation.examples.clone(),
                "common_mistakes": operation.common_mistakes.clone(),
                "next_actions": [
                    format!("fwc schema {} {}", connector.slug, operation.preferred_selector),
                    format!("fwc simulate {} {} --file payload.json", connector.slug, operation.preferred_selector),
                ],
            }),
            exit_code: CliExitCode::Success,
        });
    }

    let operation_examples = connector
        .operations
        .iter()
        .filter(|operation| !operation.examples.is_empty())
        .take(3)
        .map(|operation| {
            json!({
                "selector": &operation.preferred_selector,
                "canonical_id": &operation.actual_id,
                "when_to_use": &operation.when_to_use,
                "example": &operation.examples[0],
            })
        })
        .collect::<Vec<_>>();

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "examples",
            "source": "workspace-manifests",
            "scope": "connector",
            "message": "Loaded connector-level examples and suggested follow-up commands.",
            "connector": {
                "slug": &connector.slug,
                "canonical_id": &connector.detail.summary.id,
                "name": &connector.detail.summary.name,
            },
            "examples": {
                "commands": [
                    format!("fwc show {}", connector.slug),
                    format!("fwc ops {}", connector.slug),
                    format!("fwc config schema {}", connector.slug),
                ],
                "operations": operation_examples,
            },
            "next_actions": [
                format!("fwc ops {}", connector.slug),
                format!("fwc schema {} <operation>", connector.slug),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn export_tools_dispatch(args: &ExportToolsArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;

    let options = export_tools::ExportOptions {
        include_safety_metadata: !args.no_safety,
        include_ai_hints: !args.no_hints,
        include_examples: !args.no_hints,
        strip_prefix: args.strip_prefix.clone(),
        risk_max: args.risk_max.clone(),
        capability_filter: args.capability.clone(),
    };

    // Collect connectors (one or all).
    let connectors: Vec<&DiscoveredConnector> = if let Some(selector) = &args.connector {
        match catalog.resolve_connector(selector) {
            Ok(connector) => vec![connector],
            Err(error) => {
                return Ok(connector_resolution_dispatch(
                    "export-tools",
                    selector,
                    &error,
                ));
            }
        }
    } else {
        catalog.list(None, None)
    };

    // Gather all operations with filters applied.
    let operations: Vec<&DiscoveredOperation> = connectors
        .iter()
        .flat_map(|c| c.operations.iter())
        .filter(|op| export_tools::passes_risk_filter(op, options.risk_max.as_deref()))
        .filter(|op| {
            export_tools::passes_capability_filter(op, options.capability_filter.as_deref())
        })
        .collect();

    let tools_json = export_tools::export_tools(&operations, args.format, &options);
    let tool_count = operations.len();
    let connector_count = connectors.len();

    // Write to file if requested.
    if let Some(path) = &args.output {
        let content = serde_json::to_string_pretty(&tools_json)?;
        std::fs::write(path, &content)?;
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "ok",
                "command": "export-tools",
                "format": args.format.to_string(),
                "message": format!(
                    "Exported {tool_count} tool schemas ({connector_count} connectors) to {}.",
                    path.display()
                ),
                "tool_count": tool_count,
                "connector_count": connector_count,
                "output_file": path.display().to_string(),
            }),
            exit_code: CliExitCode::Success,
        });
    }

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "export-tools",
            "format": args.format.to_string(),
            "message": format!(
                "Exported {tool_count} tool schemas from {connector_count} connectors.",
            ),
            "tool_count": tool_count,
            "connector_count": connector_count,
            "tools": tools_json,
            "next_actions": [
                "Pipe to a file: fwc export-tools --format mcp --json > tools.json",
                "Filter by risk: fwc export-tools --format mcp --risk-max medium",
                "One connector: fwc export-tools --format claude github",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code, clippy::too_many_lines)]
fn suggest_dispatch(args: &SuggestArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;

    // If --after is specified, find related operations.
    if let Some(after_op) = &args.after {
        return suggest_after_dispatch(&catalog, after_op, args);
    }

    // If --goal is specified, use the search engine for goal-directed suggestions.
    if let Some(goal) = &args.goal {
        let filters = search::SearchFilters {
            connector: args.connector.clone(),
            risk_max: args.risk.as_deref().and_then(search::RiskCeiling::parse),
            ..Default::default()
        };
        let results = search::search_operations(catalog.connectors(), goal, &filters);
        let json_results = search::results_to_json(&results, args.limit);

        return Ok(DispatchOutcome {
            payload: json!({
                "status": "ok",
                "command": "suggest",
                "mode": "goal-directed",
                "message": format!("Found {} operations matching goal '{goal}'.", results.len()),
                "goal": goal,
                "suggestions": json_results,
                "next_actions": [
                    "Use `fwc schema <connector> <operation>` to see input/output schema.",
                    "Use `fwc simulate <connector> <operation> --file payload.json` to test safely.",
                ],
            }),
            exit_code: CliExitCode::Success,
        });
    }

    // General suggestions: overview of available operations grouped by action family.
    let connectors: Vec<&DiscoveredConnector> = if let Some(slug) = &args.connector {
        match catalog.resolve_connector(slug) {
            Ok(c) => vec![c],
            Err(error) => {
                return Ok(connector_resolution_dispatch("suggest", slug, &error));
            }
        }
    } else {
        catalog.list(None, None)
    };

    let mut by_family: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let risk_ceiling = args.risk.as_deref().and_then(search::RiskCeiling::parse);

    for connector in &connectors {
        for operation in &connector.operations {
            if let Some(ceiling) = risk_ceiling {
                if !ceiling.allows(&operation.summary.risk_level) {
                    continue;
                }
            }
            let family = classify_action_family(&operation.summary.capability);
            let entry = json!({
                "connector": &connector.slug,
                "operation": &operation.actual_id,
                "selector": &operation.preferred_selector,
                "summary": &operation.summary.summary,
                "risk_level": &operation.summary.risk_level,
                "safety_tier": &operation.summary.safety_tier,
            });
            by_family.entry(family).or_default().push(entry);
        }
    }

    // Flatten and limit.
    let mut flat: Vec<Value> = Vec::new();
    if args.grouped {
        let grouped: Vec<Value> = by_family
            .iter()
            .map(|(family, ops)| {
                json!({
                    "family": family,
                    "operation_count": ops.len(),
                    "operations": ops.iter().take(5).collect::<Vec<_>>(),
                })
            })
            .collect();
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "ok",
                "command": "suggest",
                "mode": "overview-grouped",
                "message": format!(
                    "Grouped {} action families across {} connectors.",
                    by_family.len(), connectors.len()
                ),
                "families": grouped,
                "next_actions": [
                    "Use `fwc suggest --goal '<intent>'` for goal-directed search.",
                    "Use `fwc search '<query>'` for keyword-based search.",
                ],
            }),
            exit_code: CliExitCode::Success,
        });
    }

    for ops in by_family.values() {
        flat.extend(ops.iter().cloned());
    }
    flat.truncate(args.limit);

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "suggest",
            "mode": "overview",
            "message": format!(
                "Showing {} of {} available operations across {} connectors.",
                flat.len(),
                by_family.values().map(Vec::len).sum::<usize>(),
                connectors.len(),
            ),
            "suggestions": flat,
            "action_families": by_family.keys().collect::<Vec<_>>(),
            "next_actions": [
                "Use `fwc suggest --goal '<intent>'` for goal-directed search.",
                "Use `fwc suggest --grouped` to see operations grouped by action family.",
                "Use `fwc suggest --connector <name>` to narrow to one connector.",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code, clippy::unnecessary_wraps, clippy::assigning_clones)]
fn suggest_after_dispatch(
    catalog: &DiscoveryCatalog,
    after_op: &str,
    args: &SuggestArgs,
) -> Result<DispatchOutcome> {
    // Find the operation and its related hints.
    let mut related_ids: Vec<String> = Vec::new();
    let mut source_connector = String::new();
    let mut source_summary = String::new();

    for connector in catalog.connectors() {
        for operation in &connector.operations {
            if operation.actual_id == after_op
                || operation.local_id == after_op
                || operation.preferred_selector == after_op
            {
                related_ids = operation.related.clone();
                source_connector = connector.slug.clone();
                source_summary = operation.summary.summary.clone();
                break;
            }
        }
        if !source_connector.is_empty() {
            break;
        }
    }

    if source_connector.is_empty() {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "suggest",
                "error": {
                    "type": "operation-not-found",
                    "message": format!("Operation '{after_op}' not found in any connector."),
                    "selector": after_op,
                },
                "next_actions": [
                    "Use `fwc search '<query>'` to find the operation.",
                    "Use `fwc ops <connector>` to list operations for a connector.",
                ],
            }),
            exit_code: CliExitCode::UnknownCommand,
        });
    }

    // Find the related operations by ID.
    let mut suggestions: Vec<Value> = Vec::new();
    for connector in catalog.connectors() {
        for operation in &connector.operations {
            if related_ids
                .iter()
                .any(|r| r == &operation.actual_id || r == &operation.summary.capability)
            {
                suggestions.push(json!({
                    "connector": &connector.slug,
                    "operation": &operation.actual_id,
                    "selector": &operation.preferred_selector,
                    "summary": &operation.summary.summary,
                    "risk_level": &operation.summary.risk_level,
                    "reason": "related via ai_hints",
                }));
            }
        }
    }
    suggestions.truncate(args.limit);

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "suggest",
            "mode": "after",
            "message": format!(
                "Found {} follow-up suggestions after '{after_op}'.",
                suggestions.len()
            ),
            "after": {
                "operation": after_op,
                "connector": source_connector,
                "summary": source_summary,
            },
            "suggestions": suggestions,
            "next_actions": [
                format!("fwc schema {} <operation>", source_connector),
                "Use `fwc suggest --goal '<next intent>'` for goal-directed search.",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)]
fn classify_action_family(capability: &str) -> String {
    let lower = capability.to_lowercase();
    if lower.contains("read") || lower.contains("list") || lower.contains("get") {
        "read".to_string()
    } else if lower.contains("write") || lower.contains("create") || lower.contains("update") {
        "write".to_string()
    } else if lower.contains("delete") || lower.contains("remove") {
        "delete".to_string()
    } else if lower.contains("admin") || lower.contains("manage") || lower.contains("config") {
        "manage".to_string()
    } else if lower.contains("monitor") || lower.contains("watch") || lower.contains("stream") {
        "monitor".to_string()
    } else {
        "other".to_string()
    }
}

fn template_dispatch(args: &TemplateArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "template",
                &args.connector,
                &error,
            ));
        }
    };

    let operation = match connector.resolve_operation(&args.operation) {
        Ok(operation) => operation,
        Err(error) => {
            return Ok(operation_resolution_dispatch(
                "template",
                connector,
                &args.operation,
                &error,
            ));
        }
    };

    let fill = args
        .fill
        .as_deref()
        .map(template::parse_fill_args)
        .unwrap_or_default();

    let template_json =
        template::generate_template(&operation.input_schema, args.required_only, &fill);

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "template",
            "source": "workspace-manifests",
            "message": format!(
                "Generated {} template for `{}.{}`.",
                if args.required_only { "required-only" } else { "full" },
                connector.slug,
                operation.preferred_selector,
            ),
            "connector": {
                "slug": &connector.slug,
                "canonical_id": &connector.detail.summary.id,
            },
            "operation": {
                "selector": &operation.preferred_selector,
                "canonical_id": &operation.actual_id,
                "summary": &operation.summary.summary,
            },
            "template": template_json,
            "fill_applied": !fill.is_empty(),
            "required_only": args.required_only,
            "next_actions": [
                format!("fwc schema {} {}", connector.slug, operation.preferred_selector),
                format!("fwc simulate {} {} --file payload.json", connector.slug, operation.preferred_selector),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn validate_dispatch(args: &ValidateArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "validate",
                &args.connector,
                &error,
            ));
        }
    };

    let operation = match connector.resolve_operation(&args.operation) {
        Ok(operation) => operation,
        Err(error) => {
            return Ok(operation_resolution_dispatch(
                "validate",
                connector,
                &args.operation,
                &error,
            ));
        }
    };

    // Parse input from --input or --input-file.
    let input: Value = if let Some(json_str) = &args.input {
        serde_json::from_str(json_str)?
    } else if let Some(path) = &args.input_file {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "validate",
                "error": {
                    "type": "missing-input",
                    "message": "No input provided. Use --input or --input-file.",
                },
                "next_actions": [
                    format!("fwc validate {} {} --input '{{...}}'", connector.slug, operation.preferred_selector),
                    format!("fwc template {} {}", connector.slug, operation.preferred_selector),
                ],
            }),
            exit_code: CliExitCode::UnknownCommand,
        });
    };

    let result = validate::validate(&input, &operation.input_schema);

    if result.is_valid() {
        Ok(DispatchOutcome {
            payload: json!({
                "status": "ok",
                "command": "validate",
                "message": format!(
                    "Input is valid for `{}.{}`.",
                    connector.slug, operation.preferred_selector
                ),
                "connector": &connector.slug,
                "operation": &operation.preferred_selector,
                "valid": true,
                "next_actions": [
                    format!("fwc simulate {} {} --input '...'", connector.slug, operation.preferred_selector),
                    format!("fwc invoke {} {} --input '...'", connector.slug, operation.preferred_selector),
                ],
            }),
            exit_code: CliExitCode::Success,
        })
    } else {
        let error_details: Vec<Value> = result
            .errors
            .iter()
            .map(|e| {
                json!({
                    "path": e.path,
                    "message": e.message,
                    "suggestion": e.suggestion,
                })
            })
            .collect();

        Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "validate",
                "message": format!(
                    "Validation failed for `{}.{}`: {} error(s).",
                    connector.slug, operation.preferred_selector, result.errors.len()
                ),
                "connector": &connector.slug,
                "operation": &operation.preferred_selector,
                "valid": false,
                "error_count": result.errors.len(),
                "errors": error_details,
                "next_actions": [
                    format!("fwc template {} {}", connector.slug, operation.preferred_selector),
                    format!("fwc schema {} {}", connector.slug, operation.preferred_selector),
                ],
            }),
            exit_code: CliExitCode::UnknownCommand,
        })
    }
}

#[allow(clippy::option_if_let_else)]
fn history_dispatch(args: &HistoryArgs) -> Result<DispatchOutcome> {
    let store_path = history::HistoryStore::default_path()?;
    let store = history::HistoryStore::new(store_path);

    // Single entry lookup.
    if let Some(ref entry_id) = args.entry_id {
        return store.get(entry_id)?.map_or_else(
            || {
                Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "history",
                        "error": {
                            "type": "not-found",
                            "message": format!("No history entry with ID '{entry_id}'."),
                        },
                        "next_actions": ["fwc history"],
                    }),
                    exit_code: CliExitCode::UnknownCommand,
                })
            },
            |entry| {
                Ok(DispatchOutcome {
                    payload: json!({
                        "status": "ok",
                        "command": "history",
                        "scope": "entry",
                        "entry": entry,
                    }),
                    exit_code: CliExitCode::Success,
                })
            },
        );
    }

    // Build filter.
    let mut filter = history::HistoryFilter::new();
    filter.limit = args.limit;
    filter.connector.clone_from(&args.connector);
    if let Some(ref status_str) = args.status {
        filter.status = history::parse_status(status_str);
    }
    if let Some(ref since_str) = args.since {
        if let Some(dur) = history::parse_since(since_str) {
            filter.since = Some(chrono::Utc::now() - dur);
        }
    }

    let entries = store.query(&filter)?;
    let total = store.count()?;

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "history",
            "scope": "list",
            "total_entries": total,
            "returned": entries.len(),
            "filter": {
                "connector": args.connector,
                "status": args.status,
                "since": args.since,
                "limit": args.limit,
            },
            "entries": entries,
            "next_actions": [
                "fwc history <entry_id>",
                "fwc history --connector github",
                "fwc history --status error",
                "fwc history --since 1h",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn pipe_dispatch(args: &PipeArgs) -> Result<DispatchOutcome> {
    // Parse the mapping spec.
    let spec = if let Some(ref map_expr) = args.map {
        pipe::parse_map_expression(map_expr).map_err(|e| anyhow::anyhow!("{e}"))?
    } else if let Some(ref path) = args.map_file {
        let content = std::fs::read_to_string(path)?;
        pipe::parse_map_file(&content).map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "pipe",
                "error": {
                    "type": "missing-mapping",
                    "message": "No mapping provided. Use --map or --map-file.",
                },
                "next_actions": [
                    format!("fwc pipe {} {} --map 'field_a -> field_b'", args.source, args.target),
                ],
            }),
            exit_code: CliExitCode::UnknownCommand,
        });
    };

    // Build pipe plan.
    let plan = pipe::PipePlan {
        source_operation: args.source.clone(),
        target_operation: args.target.clone(),
        mapping: spec,
        requires_approval: false,
        preview_input: None,
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": "planned",
            "command": "pipe",
            "message": format!(
                "Pipe plan: {} -> {} ({} mapping rule(s)). \
                 Execution requires host integration (not yet available).",
                args.source, args.target, plan.mapping.rules.len()
            ),
            "plan": plan,
            "dry_run": args.dry_run,
            "include_intermediate": args.include_intermediate,
            "next_actions": [
                format!("fwc schema {} --scaffold", args.source),
                format!("fwc schema {} --required-only", args.target),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)] // Wired when host integration lands.
fn pipeline_dispatch(args: &PipelineArgs) -> Result<DispatchOutcome> {
    let cwd = std::env::current_dir()?;
    let roots = pipe::default_pipeline_roots(&cwd);

    match &args.command {
        PipelineCommand::List(_) => pipeline_list_dispatch(&roots),
        PipelineCommand::Show(args) => Ok(pipeline_show_dispatch(&roots, args)),
        PipelineCommand::Validate(args) => Ok(pipeline_validate_dispatch(&roots, args)),
        PipelineCommand::Run(args) => pipeline_run_dispatch(&roots, args, PipelinePlanMode::Run),
        PipelineCommand::DryRun(args) => {
            pipeline_run_dispatch(&roots, args, PipelinePlanMode::DryRun)
        }
        PipelineCommand::Estimate(args) => {
            pipeline_run_dispatch(&roots, args, PipelinePlanMode::Estimate)
        }
    }
}

#[derive(Clone, Copy)]
enum PipelinePlanMode {
    Run,
    DryRun,
    Estimate,
}

impl PipelinePlanMode {
    const fn subcommand(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::DryRun => "dry-run",
            Self::Estimate => "estimate",
        }
    }

    const fn include_plan(self) -> bool {
        !matches!(self, Self::Estimate)
    }

    const fn dry_run(self) -> bool {
        matches!(self, Self::DryRun)
    }
}

fn recipe_dispatch(args: &RecipeArgs) -> Result<DispatchOutcome> {
    match &args.command {
        RecipeCommand::List(_) => recipe_list_dispatch(),
        RecipeCommand::Show(args) => recipe_show_dispatch(args),
        RecipeCommand::Validate(args) => Ok(recipe_validate_dispatch(args)),
        RecipeCommand::Run(args) => recipe_run_dispatch(args, PipelinePlanMode::Run),
        RecipeCommand::DryRun(args) => recipe_run_dispatch(args, PipelinePlanMode::DryRun),
        RecipeCommand::Estimate(args) => recipe_run_dispatch(args, PipelinePlanMode::Estimate),
        RecipeCommand::Export(args) => Ok(recipe_export_dispatch(args)),
    }
}

fn recipe_list_dispatch() -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let recipes = pipe::builtin_recipe_summaries()
        .into_iter()
        .map(|summary| {
            let estimate = pipe::load_builtin_recipe(&summary.slug)
                .ok()
                .and_then(|recipe| default_recipe_estimate(&catalog, &recipe));
            json!({
                "slug": summary.slug,
                "title": summary.title,
                "category": summary.category,
                "summary": summary.summary,
                "required_connectors": summary.required_connectors,
                "export_path": summary.export_path,
                "step_count": summary.step_count,
                "valid": summary.valid,
                "errors": summary.errors,
                "risk_level": estimate.as_ref().map(|value| value.risk_assessment.level.clone()),
                "highest_safety_tier": estimate.as_ref().map(|value| value.risk_assessment.highest_safety_tier.clone()),
                "estimated_api_calls": estimate.as_ref().map(|value| value.estimated_api_calls.summary.clone()),
                "required_capabilities": estimate.as_ref().map(|value| value.required_capabilities.clone()),
                "approval_count": estimate.as_ref().map(|value| value.required_approvals.len()),
            })
        })
        .collect::<Vec<_>>();
    let category_counts = recipes.iter().fold(BTreeMap::new(), |mut acc, recipe| {
        let category = recipe["category"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        *acc.entry(category).or_insert(0usize) += 1;
        acc
    });

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "recipe",
            "subcommand": "list",
            "message": "Bundled recipe library loaded. Built-ins include placeholder defaults so agents can inspect, estimate, and export them deterministically before customization.",
            "recipe_count": recipes.len(),
            "categories": category_counts,
            "recipes": recipes,
            "next_actions": [
                "fwc recipe show github-pr-review-notify".to_owned(),
                "fwc recipe dry-run github-pr-review-notify".to_owned(),
                "fwc recipe export github-pr-review-notify".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn recipe_show_dispatch(args: &RecipeRefArgs) -> Result<DispatchOutcome> {
    let recipe = match load_recipe_definition(&args.recipe, "show") {
        Ok(recipe) => recipe,
        Err(outcome) => return Ok(outcome),
    };
    if !recipe.validation.valid {
        return Ok(recipe_invalid_definition_dispatch("show", &recipe));
    }

    let catalog = DiscoveryCatalog::load()?;
    let estimate = default_recipe_estimate(&catalog, &recipe)
        .ok_or_else(|| anyhow::anyhow!("built-in recipe estimate unexpectedly failed"))?;

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "recipe",
            "subcommand": "show",
            "recipe": {
                "slug": recipe.slug,
                "title": recipe.title,
                "category": recipe.category,
                "summary": recipe.summary,
                "required_connectors": recipe.required_connectors,
                "export_path": recipe.export_path,
            },
            "definition": recipe.definition,
            "validation": recipe.validation,
            "estimate": estimate,
            "next_actions": recipe_next_actions(&args.recipe),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn recipe_validate_dispatch(args: &RecipeRefArgs) -> DispatchOutcome {
    let recipe = match load_recipe_definition(&args.recipe, "validate") {
        Ok(recipe) => recipe,
        Err(outcome) => return outcome,
    };
    if !recipe.validation.valid {
        return recipe_invalid_definition_dispatch("validate", &recipe);
    }

    DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "recipe",
            "subcommand": "validate",
            "recipe": {
                "slug": recipe.slug,
                "title": recipe.title,
                "category": recipe.category,
                "summary": recipe.summary,
                "required_connectors": recipe.required_connectors,
                "export_path": recipe.export_path,
            },
            "validation": recipe.validation,
            "next_actions": recipe_next_actions(&args.recipe),
        }),
        exit_code: CliExitCode::Success,
    }
}

fn recipe_run_dispatch(
    args: &RecipeRunArgs,
    mode: PipelinePlanMode,
) -> Result<DispatchOutcome> {
    let recipe = match load_recipe_definition(&args.recipe, mode.subcommand()) {
        Ok(recipe) => recipe,
        Err(outcome) => return Ok(outcome),
    };
    if !recipe.validation.valid {
        return Ok(recipe_invalid_definition_dispatch(mode.subcommand(), &recipe));
    }

    let params = match pipe::bind_pipeline_params(&recipe.definition, &args.params) {
        Ok(params) => params,
        Err(errors) => {
            return Ok(recipe_error_dispatch(
                mode.subcommand(),
                "invalid-recipe-parameters",
                "The provided recipe parameters are incomplete or invalid.",
                Some(&recipe.slug),
                &errors,
                &recipe_next_actions(&recipe.slug),
            ));
        }
    };

    let plan = pipe::build_pipeline_plan(&recipe.definition, &params)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let catalog = DiscoveryCatalog::load()?;
    let operation_metadata =
        match resolve_recipe_operation_metadata(&catalog, &plan, mode.subcommand(), &recipe.slug) {
            Ok(metadata) => metadata,
            Err(outcome) => return Ok(outcome),
        };
    let estimate = pipe::estimate_pipeline(&plan, &operation_metadata)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let message = match mode {
        PipelinePlanMode::Run => format!(
            "Recipe plan: {} ({} step(s), {}, highest risk {}). Execution requires host integration (not yet available).",
            recipe.title,
            plan.step_count,
            estimate.estimated_api_calls.summary,
            estimate.risk_assessment.level,
        ),
        PipelinePlanMode::DryRun => format!(
            "Recipe dry-run: {} ({} step(s), {}, highest risk {}). Execution requires host integration (not yet available).",
            recipe.title,
            plan.step_count,
            estimate.estimated_api_calls.summary,
            estimate.risk_assessment.level,
        ),
        PipelinePlanMode::Estimate => format!(
            "Recipe estimate: {} ({} step(s), {}, highest risk {}). No host execution was attempted.",
            recipe.title,
            plan.step_count,
            estimate.estimated_api_calls.summary,
            estimate.risk_assessment.level,
        ),
    };
    let mut payload = json!({
        "status": "planned",
        "command": "recipe",
        "subcommand": mode.subcommand(),
        "recipe": recipe.slug,
        "export_path": recipe.export_path,
        "message": message,
        "estimate": estimate,
        "dry_run": mode.dry_run(),
        "next_actions": recipe_next_actions(&recipe.slug),
    });
    if mode.include_plan() {
        payload["plan"] = serde_json::to_value(&plan)?;
    }

    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn recipe_export_dispatch(args: &RecipeRefArgs) -> DispatchOutcome {
    let recipe = match load_recipe_definition(&args.recipe, "export") {
        Ok(recipe) => recipe,
        Err(outcome) => return outcome,
    };

    DispatchOutcome {
        payload: Value::String(recipe.toml),
        exit_code: CliExitCode::Success,
    }
}

fn recipe_next_actions(recipe: &str) -> Vec<String> {
    vec![
        format!("fwc recipe show {recipe}"),
        format!("fwc recipe validate {recipe}"),
        format!("fwc recipe estimate {recipe}"),
        format!("fwc recipe dry-run {recipe}"),
        format!("fwc recipe export {recipe}"),
    ]
}

fn recipe_invalid_definition_dispatch(
    subcommand: &str,
    recipe: &pipe::BuiltInRecipe,
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "recipe",
            "subcommand": subcommand,
            "recipe": recipe.slug,
            "error": {
                "type": "invalid-recipe-definition",
                "message": "The recipe definition is structurally invalid.",
                "details": recipe.validation.errors,
                "next_actions": recipe_next_actions(&recipe.slug),
            },
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn recipe_error_dispatch(
    subcommand: &str,
    error_type: &str,
    message: impl Into<String>,
    reference: Option<&str>,
    details: &[String],
    next_actions: &[String],
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "recipe",
            "subcommand": subcommand,
            "reference": reference,
            "error": {
                "type": error_type,
                "message": message.into(),
                "details": details,
                "next_actions": next_actions,
            },
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn resolve_recipe_operation_metadata(
    catalog: &DiscoveryCatalog,
    plan: &pipe::PipelinePlan,
    subcommand: &str,
    slug: &str,
) -> Result<BTreeMap<String, pipe::PipelineOperationMetadata>, DispatchOutcome> {
    resolve_pipeline_operation_metadata(catalog, plan, subcommand, &std::path::PathBuf::from(slug))
}

fn load_recipe_definition(
    reference: &str,
    subcommand: &str,
) -> Result<pipe::BuiltInRecipe, DispatchOutcome> {
    pipe::load_builtin_recipe(reference).map_err(|error| {
        recipe_error_dispatch(
            subcommand,
            "recipe-not-found",
            error,
            Some(reference),
            &[],
            &["fwc recipe list".to_owned()],
        )
    })
}

fn default_recipe_estimate(
    catalog: &DiscoveryCatalog,
    recipe: &pipe::BuiltInRecipe,
) -> Option<pipe::PipelineEstimate> {
    let params = pipe::bind_pipeline_params(&recipe.definition, &[]).ok()?;
    let plan = pipe::build_pipeline_plan(&recipe.definition, &params).ok()?;
    let metadata = resolve_recipe_operation_metadata(catalog, &plan, "show", &recipe.slug).ok()?;
    pipe::estimate_pipeline(&plan, &metadata).ok()
}

#[allow(dead_code)]
fn pipeline_list_dispatch(roots: &pipe::PipelineRoots) -> Result<DispatchOutcome> {
    let pipelines = pipe::discover_pipelines(roots).map_err(|error| anyhow::anyhow!("{error}"))?;
    let search_paths = vec![
        roots.project.display().to_string(),
        roots.user.as_ref().map_or_else(
            || "<home unavailable>".to_owned(),
            |path| path.display().to_string(),
        ),
    ];
    let valid_count = pipelines.iter().filter(|pipeline| pipeline.valid).count();

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "pipeline",
            "subcommand": "list",
            "message": if pipelines.is_empty() {
                "No pipeline definitions were found in the project or user pipeline directories."
            } else {
                "Discovered pipeline definitions from the project and user pipeline directories."
            },
            "search_paths": search_paths,
            "pipeline_count": pipelines.len(),
            "valid_count": valid_count,
            "pipelines": pipelines,
            "next_actions": [
                "Create `.fwc/pipelines/<name>.toml` in the current project to register a project-scoped pipeline."
                    .to_owned(),
                "Run `fwc pipeline validate <name-or-path>` before attempting `fwc pipeline estimate` or `fwc pipeline dry-run`."
                    .to_owned(),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)]
fn pipeline_show_dispatch(roots: &pipe::PipelineRoots, args: &PipelineRefArgs) -> DispatchOutcome {
    let (path, definition, validation) = match load_pipeline_definition(roots, &args.pipeline) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };
    if !validation.valid {
        return pipeline_invalid_definition_dispatch("show", &path, Some(&definition), &validation);
    }

    DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "pipeline",
            "subcommand": "show",
            "path": path.display().to_string(),
            "definition": definition,
            "validation": validation,
            "next_actions": [
                format!("fwc pipeline validate {}", path.display()),
                format!("fwc pipeline estimate {} --param key=value", path.display()),
                format!("fwc pipeline dry-run {} --param key=value", path.display()),
            ],
        }),
        exit_code: CliExitCode::Success,
    }
}

#[allow(dead_code)]
fn pipeline_validate_dispatch(
    roots: &pipe::PipelineRoots,
    args: &PipelineRefArgs,
) -> DispatchOutcome {
    let (path, definition, validation) = match load_pipeline_definition(roots, &args.pipeline) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };
    if !validation.valid {
        return pipeline_invalid_definition_dispatch(
            "validate",
            &path,
            Some(&definition),
            &validation,
        );
    }

    DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "pipeline",
            "subcommand": "validate",
            "path": path.display().to_string(),
            "validation": validation,
            "next_actions": [
                format!("fwc pipeline show {}", path.display()),
                format!("fwc pipeline estimate {} --param key=value", path.display()),
                format!("fwc pipeline dry-run {} --param key=value", path.display()),
            ],
        }),
        exit_code: CliExitCode::Success,
    }
}

#[allow(dead_code)]
fn pipeline_run_dispatch(
    roots: &pipe::PipelineRoots,
    args: &PipelineRunArgs,
    mode: PipelinePlanMode,
) -> Result<DispatchOutcome> {
    let (path, definition, validation) = match load_pipeline_definition(roots, &args.pipeline) {
        Ok(v) => v,
        Err(outcome) => return Ok(outcome),
    };
    let subcommand = mode.subcommand();

    if !validation.valid {
        return Ok(pipeline_invalid_definition_dispatch(
            subcommand,
            &path,
            Some(&definition),
            &validation,
        ));
    }

    let params = match pipe::bind_pipeline_params(&definition, &args.params) {
        Ok(params) => params,
        Err(errors) => {
            return Ok(pipeline_error_dispatch(
                subcommand,
                "invalid-pipeline-parameters",
                "The provided pipeline parameters are incomplete or invalid.",
                Some(&path),
                &errors,
                &[
                    format!("fwc pipeline show {}", path.display()),
                    format!("fwc pipeline validate {}", path.display()),
                ],
            ));
        }
    };

    let plan = pipe::build_pipeline_plan(&definition, &params)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let catalog = DiscoveryCatalog::load()?;
    let operation_metadata =
        match resolve_pipeline_operation_metadata(&catalog, &plan, subcommand, &path) {
            Ok(metadata) => metadata,
            Err(outcome) => return Ok(outcome),
        };
    let estimate = pipe::estimate_pipeline(&plan, &operation_metadata)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let message = match mode {
        PipelinePlanMode::Run => format!(
            "Pipeline plan: {} ({} step(s), {}, highest risk {}). Execution requires host integration (not yet available).",
            definition.pipeline.name,
            plan.step_count,
            estimate.estimated_api_calls.summary,
            estimate.risk_assessment.level,
        ),
        PipelinePlanMode::DryRun => format!(
            "Pipeline dry-run: {} ({} step(s), {}, highest risk {}). Execution requires host integration (not yet available).",
            definition.pipeline.name,
            plan.step_count,
            estimate.estimated_api_calls.summary,
            estimate.risk_assessment.level,
        ),
        PipelinePlanMode::Estimate => format!(
            "Pipeline estimate: {} ({} step(s), {}, highest risk {}). No host execution was attempted.",
            definition.pipeline.name,
            plan.step_count,
            estimate.estimated_api_calls.summary,
            estimate.risk_assessment.level,
        ),
    };
    let mut payload = json!({
        "status": "planned",
        "command": "pipeline",
        "subcommand": subcommand,
        "path": path.display().to_string(),
        "message": message,
        "estimate": estimate,
        "dry_run": mode.dry_run(),
        "next_actions": [
            format!("fwc pipeline show {}", path.display()),
            format!("fwc pipeline validate {}", path.display()),
            format!("fwc pipeline estimate {} --param key=value", path.display()),
            format!("fwc pipeline dry-run {} --param key=value", path.display()),
        ],
    });
    if mode.include_plan() {
        payload["plan"] = serde_json::to_value(&plan)?;
    }

    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)]
fn load_pipeline_definition(
    roots: &pipe::PipelineRoots,
    reference: &str,
) -> Result<(PathBuf, pipe::PipelineDefinition, pipe::PipelineValidation), DispatchOutcome> {
    let path = match pipe::resolve_pipeline_reference(reference, roots) {
        Ok(path) => path,
        Err(error) => {
            return Err(pipeline_error_dispatch(
                "load",
                "pipeline-not-found",
                error,
                None,
                &[],
                &[
                    "Run `fwc pipeline list` to discover available pipeline names.".to_owned(),
                    "Or pass an explicit TOML path such as `.fwc/pipelines/<name>.toml`."
                        .to_owned(),
                ],
            ));
        }
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) => {
            return Err(pipeline_error_dispatch(
                "load",
                "pipeline-read-failed",
                format!("The pipeline definition could not be read: {error}"),
                Some(&path),
                &[],
                &[
                    "Check that the pipeline file exists and is readable.".to_owned(),
                    "Re-run `fwc pipeline list` to confirm the expected search roots.".to_owned(),
                ],
            ));
        }
    };

    let definition = match pipe::parse_pipeline_definition(&content) {
        Ok(definition) => definition,
        Err(error) => {
            return Err(pipeline_error_dispatch(
                "load",
                "invalid-pipeline-toml",
                error,
                Some(&path),
                &[],
                &["Fix the TOML syntax and re-run `fwc pipeline validate <path>`.".to_owned()],
            ));
        }
    };

    let validation = pipe::validate_pipeline_definition(&definition);
    Ok((path, definition, validation))
}

#[allow(dead_code)]
fn pipeline_invalid_definition_dispatch(
    subcommand: &str,
    path: &std::path::Path,
    definition: Option<&pipe::PipelineDefinition>,
    validation: &pipe::PipelineValidation,
) -> DispatchOutcome {
    let payload = definition.map_or_else(
        || {
            json!({
                "status": "error",
                "command": "pipeline",
                "subcommand": subcommand,
                "path": path.display().to_string(),
                "error": {
                    "type": "invalid-pipeline-definition",
                    "message": "The pipeline definition is structurally invalid.",
                    "details": validation.errors,
                    "next_actions": [
                        format!("fwc pipeline validate {}", path.display()),
                    ],
                },
            })
        },
        |definition| {
            json!({
                "status": "error",
                "command": "pipeline",
                "subcommand": subcommand,
                "path": path.display().to_string(),
                "definition": definition,
                "error": {
                    "type": "invalid-pipeline-definition",
                    "message": "The pipeline definition is structurally invalid.",
                    "details": validation.errors,
                    "next_actions": [
                        format!("fwc pipeline show {}", path.display()),
                        format!("fwc pipeline validate {}", path.display()),
                    ],
                },
            })
        },
    );

    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Validation,
    }
}

#[allow(dead_code)]
fn pipeline_error_dispatch(
    subcommand: &str,
    error_type: &str,
    message: impl Into<String>,
    path: Option<&std::path::Path>,
    details: &[String],
    next_actions: &[String],
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "pipeline",
            "subcommand": subcommand,
            "path": path.map(|path| path.display().to_string()),
            "error": {
                "type": error_type,
                "message": message.into(),
                "details": details,
                "next_actions": next_actions,
            },
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn resolve_pipeline_operation_metadata(
    catalog: &DiscoveryCatalog,
    plan: &pipe::PipelinePlan,
    subcommand: &str,
    path: &std::path::Path,
) -> Result<BTreeMap<String, pipe::PipelineOperationMetadata>, DispatchOutcome> {
    let mut operations = BTreeMap::new();

    for step in &plan.steps {
        if operations.contains_key(&step.operation) {
            continue;
        }

        let Some((connector_selector, operation_selector)) = step.operation.split_once('.') else {
            return Err(pipeline_error_dispatch(
                subcommand,
                "invalid-pipeline-operation-reference",
                format!(
                    "Pipeline step `{}` must use `<connector>.<operation>` syntax, but `{}` does not.",
                    step.id, step.operation
                ),
                Some(path),
                &[],
                &[
                    format!("fwc pipeline show {}", path.display()),
                    "Use operation references like `github.list_issues` or `slack.send_message`."
                        .to_owned(),
                ],
            ));
        };

        let connector = match catalog.resolve_connector(connector_selector) {
            Ok(connector) => connector,
            Err(error) => {
                let details = if error.suggestions.is_empty() {
                    Vec::new()
                } else {
                    error.suggestions.clone()
                };
                let next_actions = if error.suggestions.is_empty() {
                    vec!["fwc list".to_owned()]
                } else {
                    error
                        .suggestions
                        .iter()
                        .map(|suggestion| format!("fwc show {suggestion}"))
                        .collect()
                };
                return Err(pipeline_error_dispatch(
                    subcommand,
                    "pipeline-connector-not-found",
                    format!(
                        "Pipeline step `{}` refers to unknown connector `{connector_selector}` in `{}`.",
                        step.id, step.operation
                    ),
                    Some(path),
                    &details,
                    &next_actions,
                ));
            }
        };
        let operation = match connector.resolve_operation(operation_selector) {
            Ok(operation) => operation,
            Err(error) => {
                let details = if error.suggestions.is_empty() {
                    Vec::new()
                } else {
                    error.suggestions.clone()
                };
                let next_actions = if error.suggestions.is_empty() {
                    vec![format!("fwc ops {}", connector.slug)]
                } else {
                    error
                        .suggestions
                        .iter()
                        .map(|suggestion| format!("fwc schema {} {suggestion}", connector.slug))
                        .collect()
                };
                return Err(pipeline_error_dispatch(
                    subcommand,
                    "pipeline-operation-not-found",
                    format!(
                        "Pipeline step `{}` refers to unknown operation `{}` on connector `{}`.",
                        step.id, operation_selector, connector.slug
                    ),
                    Some(path),
                    &details,
                    &next_actions,
                ));
            }
        };

        operations.insert(
            step.operation.clone(),
            pipe::PipelineOperationMetadata {
                connector: connector.slug.clone(),
                selector: operation.preferred_selector.clone(),
                canonical_id: operation.actual_id.clone(),
                capability: operation.summary.capability.clone(),
                risk_level: operation.summary.risk_level.clone(),
                safety_tier: operation.summary.safety_tier.clone(),
                requires_approval: operation.summary.requires_approval,
                approval_mode: operation.approval_mode.clone(),
                rate_limits: operation.rate_limits.clone(),
            },
        );
    }

    Ok(operations)
}

fn map_dispatch(args: &MapArgs) -> Result<DispatchOutcome> {
    // Parse the on-error mode.
    let on_error = batch::OnError::parse(&args.on_error).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid --on-error value '{}'. Use 'abort' or 'continue'.",
            args.on_error
        )
    })?;

    // Parse inputs from exactly one source.
    let inputs = if let Some(ref json) = args.inputs {
        batch::BatchInputs::from_json_array(json).map_err(|e| anyhow::anyhow!("{e}"))?
    } else if let Some(ref path) = args.input_file {
        let content = std::fs::read_to_string(path)?;
        batch::BatchInputs::from_jsonl(&content).map_err(|e| anyhow::anyhow!("{e}"))?
    } else if let Some(ref template) = args.input_template {
        let items_csv = args.items.as_deref().unwrap_or("");
        batch::BatchInputs::from_template(template, items_csv)
            .map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "map",
                "error": {
                    "type": "missing-inputs",
                    "message": "No inputs provided. Use --inputs, --input-file, or --input-template + --items.",
                },
                "next_actions": [
                    format!("fwc map {} --inputs '[{{\"id\":1}},{{\"id\":2}}]'", args.operation),
                    format!("fwc map {} --input-file inputs.jsonl", args.operation),
                    format!(
                        "fwc map {} --input-template '{{\"id\":{{{{item}}}}}}' --items '1,2,3'",
                        args.operation
                    ),
                ],
            }),
            exit_code: CliExitCode::UnknownCommand,
        });
    };

    // Build batch plan.
    let preview_count = inputs.len().min(3);
    let plan = batch::BatchPlan {
        operation: args.operation.clone(),
        input_count: inputs.len(),
        concurrency: args.concurrency,
        on_error,
        preview_inputs: inputs.items[..preview_count].to_vec(),
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": "planned",
            "command": "map",
            "message": format!(
                "Batch plan: {} x {} inputs (concurrency={}, on_error={}). \
                 Execution requires host integration (not yet available).",
                args.operation, inputs.len(), args.concurrency, on_error
            ),
            "plan": plan,
            "next_actions": [
                format!("fwc schema {}", args.operation),
                format!("fwc validate {} --input '<first_input>'", args.operation),
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn batch_file_dispatch(args: &BatchFileArgs) -> Result<DispatchOutcome> {
    let content = std::fs::read_to_string(&args.file)?;
    let batch = batch_file::BatchFile::parse(&content).map_err(|e| anyhow::anyhow!("{e}"))?;
    let plan = batch_file::ExecutionPlan::from_batch(&batch, args.concurrency, &args.on_error);

    Ok(DispatchOutcome {
        payload: json!({
            "status": "planned",
            "command": "batch-file",
            "message": format!(
                "Batch file: {} operations across {} connectors in {} waves. \
                 Execution requires host integration (not yet available).",
                plan.total_operations,
                plan.connectors.len(),
                plan.waves.len()
            ),
            "plan": plan,
            "dry_run": args.dry_run,
            "file": args.file.display().to_string(),
            "next_actions": plan.connectors.iter().map(|c| {
                format!("fwc show {c}")
            }).collect::<Vec<_>>(),
        }),
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)] // Wired when host integration lands.
fn events_dispatch(args: &EventsArgs) -> Result<DispatchOutcome> {
    // Parse connectors.
    let connectors = if args.all {
        Vec::new() // Empty = all.
    } else if let Some(ref s) = args.connectors {
        event_stream::TailConfig::parse_connectors(s)
    } else {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "events",
                "error": {
                    "type": "missing-target",
                    "message": "Specify connectors to tail or use --all.",
                },
                "next_actions": [
                    "fwc events slack",
                    "fwc events slack,discord",
                    "fwc events --all",
                ],
            }),
            exit_code: CliExitCode::UnknownCommand,
        });
    };

    // Parse since duration.
    let since_seconds = if let Some(ref since) = args.since {
        Some(event_stream::parse_since(since).map_err(|e| anyhow::anyhow!("{e}"))?)
    } else {
        None
    };

    let plan = event_stream::TailPlan {
        connectors: if args.all {
            vec!["<all streaming connectors>".to_owned()]
        } else {
            connectors
        },
        all: args.all,
        since: args.since.clone(),
        buffer_size: args.buffer_size,
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": "planned",
            "command": "events",
            "message": format!(
                "Tail plan: {} connector(s){}. \
                 Execution requires host integration (not yet available).",
                plan.connectors.len(),
                since_seconds.map_or_else(String::new, |s| format!(", since {s}s ago")),
            ),
            "plan": plan,
            "next_actions": [
                "fwc list --streaming",
            ],
        }),
        exit_code: CliExitCode::Success,
    })
}

fn connector_list_entry(connector: &DiscoveredConnector) -> Value {
    json!({
        "slug": &connector.slug,
        "canonical_id": &connector.detail.summary.id,
        "name": &connector.detail.summary.name,
        "description": &connector.detail.summary.description,
        "version": &connector.detail.summary.version,
        "cohort": &connector.cohort,
        "format": &connector.runtime_format,
        "state": connector.detail.summary.state,
        "archetypes": connector.detail.summary.archetypes.clone(),
        "home_zone": connector.zones.get("home").cloned().unwrap_or(Value::Null),
        "operation_count": connector.detail.summary.operation_count,
        "max_risk": &connector.detail.summary.max_risk,
        "has_events": connector.detail.summary.has_events,
        "next_actions": [
            format!("fwc show {}", connector.slug),
            format!("fwc ops {}", connector.slug),
        ],
    })
}

fn operation_summary_entry(operation: &DiscoveredOperation) -> Value {
    json!({
        "selector": &operation.preferred_selector,
        "canonical_id": &operation.actual_id,
        "local_id": &operation.local_id,
        "aliases": operation.aliases.clone(),
        "summary": &operation.summary.summary,
        "capability": &operation.summary.capability,
        "risk_level": &operation.summary.risk_level,
        "safety_tier": &operation.summary.safety_tier,
        "idempotency": &operation.summary.idempotency,
        "requires_approval": operation.summary.requires_approval,
        "supports_simulate": operation.summary.supports_simulate,
        "example_count": operation.examples.len(),
        "rate_limits": operation.rate_limits.clone(),
    })
}

fn risk_filter_allows(operation: &DiscoveredOperation, risk_at_most: Option<&str>) -> bool {
    let Some(limit) = risk_at_most else {
        return true;
    };

    risk_rank(&operation.summary.risk_level) <= risk_rank(limit)
}

fn risk_rank(risk: &str) -> u8 {
    match risk.to_ascii_lowercase().as_str() {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => u8::MAX,
    }
}

fn connector_resolution_dispatch(
    command: &str,
    selector: &str,
    error: &SelectorError,
) -> DispatchOutcome {
    let error_type = match error.kind {
        SelectorErrorKind::NotFound => "connector-not-found",
        SelectorErrorKind::Ambiguous => "ambiguous-connector",
    };
    let message = match error.kind {
        SelectorErrorKind::NotFound => {
            format!("`{selector}` did not match any connector in the workspace catalog.")
        }
        SelectorErrorKind::Ambiguous => {
            format!("`{selector}` matches multiple connectors; choose one explicit slug.")
        }
    };
    let examples = if error.suggestions.is_empty() {
        vec!["fwc list".to_owned()]
    } else {
        error
            .suggestions
            .iter()
            .map(|suggestion| format!("fwc {command} {suggestion}"))
            .collect()
    };

    discovery_error(
        command,
        error_type,
        message,
        selector,
        &error.suggestions,
        &examples,
    )
}

fn operation_resolution_dispatch(
    command: &str,
    connector: &DiscoveredConnector,
    selector: &str,
    error: &SelectorError,
) -> DispatchOutcome {
    let error_type = match error.kind {
        SelectorErrorKind::NotFound => "operation-not-found",
        SelectorErrorKind::Ambiguous => "ambiguous-operation",
    };
    let message = match error.kind {
        SelectorErrorKind::NotFound => format!(
            "`{selector}` did not match any operation exposed by `{}`.",
            connector.slug
        ),
        SelectorErrorKind::Ambiguous => format!(
            "`{selector}` matches multiple operations on `{}`; choose one explicit selector.",
            connector.slug
        ),
    };
    let mut examples = if error.suggestions.is_empty() {
        vec![format!("fwc ops {}", connector.slug)]
    } else {
        error
            .suggestions
            .iter()
            .map(|suggestion| format!("fwc {command} {} {suggestion}", connector.slug))
            .collect::<Vec<_>>()
    };
    examples.push(format!("fwc ops {}", connector.slug));

    discovery_error(
        command,
        error_type,
        message,
        selector,
        &error.suggestions,
        &examples,
    )
}

fn discovery_error(
    command: &str,
    error_type: &str,
    message: impl Into<String>,
    selector: &str,
    suggestions: &[String],
    examples: &[String],
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": command,
            "error": {
                "type": error_type,
                "message": message.into(),
                "recoverable": true,
                "selector": selector,
                "did_you_mean": suggestions,
                "examples": examples,
                "next_actions": [
                    "Use `fwc list` or `fwc search <term>` to narrow the connector first.",
                    "Use `fwc ops <connector>` before `schema` or `examples` when the operation name is uncertain.",
                ],
            },
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn task_dispatch(args: &TaskArgs) -> Result<DispatchOutcome> {
    match &args.command {
        TaskCommand::Create(args) => task_create_dispatch(args),
        TaskCommand::Show(args) => task_show_dispatch(args),
        TaskCommand::List(args) => task_list_dispatch(args),
        TaskCommand::Resolve(args) => task_resolve_dispatch(args),
        TaskCommand::Ask(args) => task_ask_dispatch(args),
        TaskCommand::Advance(args) => task_advance_dispatch(args),
        TaskCommand::Bind(args) => task_bind_dispatch(args),
        TaskCommand::Approve(args) => task_approve_dispatch(args),
        TaskCommand::Run(args) => task_run_dispatch(args),
    }
}

fn task_create_dispatch(args: &IntentArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let task = store.create(workflow::WorkflowRequest {
        intent: args.intent.clone(),
        connector_override: args.connector.clone(),
        zone_override: args.zone.clone(),
    })?;
    Ok(DispatchOutcome {
        payload: json!({
            "status": "created",
            "command": "task",
            "subcommand": "create",
            "message": "Created a resumable workflow capsule from the requested intent.",
            "task": task_payload_view(&task),
            "state_root": store.root_dir().display().to_string(),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_show_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.load(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "task",
            "subcommand": "show",
            "message": "Loaded the current workflow capsule state.",
            "task": task_payload_view(&task),
            "state_root": store.root_dir().display().to_string(),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_list_dispatch(args: &TaskListArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let tasks = store.list(args.limit, args.status.as_deref())?;
    Ok(DispatchOutcome {
        payload: json!({
            "status": "ok",
            "command": "task",
            "subcommand": "list",
            "message": "Listed recent workflow capsules.",
            "tasks": serde_json::to_value(tasks)?,
            "state_root": store.root_dir().display().to_string(),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_resolve_dispatch(args: &TaskResolveArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(mut task) = store.refresh(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    let until_ready = args.should_resolve_until_ready();
    let mode = if until_ready {
        "until-ready"
    } else {
        "single-pass"
    };
    let mut pass_count = 0usize;
    let mut safe_step_count = 0usize;
    let mut changed_any = false;
    let mut pass_summaries = Vec::new();
    let stop_reason = loop {
        if pass_count > 0 && workflow::ready_for_execution(&task) {
            break "ready";
        }

        pass_count += 1;
        let patch = workflow::resolution_patch(&task);
        let bindings = {
            let mut bindings = workflow::effective_bindings(&task);
            bindings.extend(patch.draft_bindings.clone());
            bindings
        };
        let patch_changes = workflow::resolution_patch_would_change(&task, &patch);
        let (pass_safe_step_count, safe_execution) = if can_materialize_resolution_steps(&task) {
            materialize_safe_resolution_steps(&task, &bindings)?
        } else {
            (
                0,
                json!({
                    "status": "skipped",
                    "reason": "Resolution did not materialize primitive commands because the connector choice is still ambiguous.",
                    "safe_step_count": 0,
                }),
            )
        };
        safe_step_count += pass_safe_step_count;

        let Some(applied) = store.append_resolution(
            &args.task_id,
            "resolve",
            mode,
            pass_count,
            safe_step_count,
            patch,
        )?
        else {
            return Ok(missing_task_dispatch(&args.task_id));
        };

        changed_any |= applied.receipt.changed;
        task = applied.task;
        pass_summaries.push(json!({
            "pass": pass_count,
            "receipt": resolution_receipt_summary(&applied.receipt),
            "safe_execution": safe_execution,
        }));

        if workflow::ready_for_execution(&task) {
            break "ready";
        }
        if task.resolution.pending_question.is_some() {
            break "pending-question";
        }
        if !until_ready {
            break if patch_changes {
                "single-pass"
            } else {
                "no-further-progress"
            };
        }
        if !patch_changes {
            break "no-further-progress";
        }
        if pass_count >= 4 {
            break "iteration-cap";
        }
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": task.capsule_status,
            "command": "task",
            "subcommand": "resolve",
            "message": resolve_message(stop_reason, until_ready),
            "resolution": {
                "mode": mode,
                "pass_count": pass_count,
                "safe_step_count": safe_step_count,
                "changed": changed_any,
                "stop_reason": stop_reason,
                "pending_question": task.resolution.pending_question,
                "passes": pass_summaries,
            },
            "task": task_payload_view(&task),
            "state_root": store.root_dir().display().to_string(),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_ask_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.refresh(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    let (status, message) = if workflow::ready_for_execution(&task) {
        (
            "ready",
            "The workflow capsule has no blocking question and is ready for execution.",
        )
    } else if task.resolution.pending_question.is_some() {
        (
            "question",
            "Surfaced the smallest current clarification question for this workflow capsule.",
        )
    } else {
        (
            "no-question",
            "No single clarification question is available yet; inspect the capsule for broader missing information.",
        )
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": status,
            "command": "task",
            "subcommand": "ask",
            "message": message,
            "question": task.resolution.pending_question,
            "task": task_payload_view(&task),
            "state_root": store.root_dir().display().to_string(),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_bind_dispatch(args: &TaskBindArgs) -> Result<DispatchOutcome> {
    let bindings = match workflow::validate_binding_entries(&args.bindings) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(structured_error(
                "invalid-task-binding",
                error.to_string(),
                CliExitCode::Validation,
                true,
                &std::env::args().collect::<Vec<_>>(),
                &std::env::args().collect::<Vec<_>>(),
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec![
                        format!(
                            "fwc task bind {} connector=notion payload_file=payload.json",
                            args.task_id
                        ),
                        format!(
                            "fwc task bind {} zone=z:work payload_json='{{\"text\":\"hello\"}}'",
                            args.task_id
                        ),
                    ],
                    next_actions: vec![
                        "Pass one or more bindings as `key=value` pairs.".to_owned(),
                        "Use `connector=` or `zone=` to refine the compiler request itself."
                            .to_owned(),
                    ],
                },
            ));
        }
    };
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.bind(&args.task_id, bindings)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": "updated",
            "command": "task",
            "subcommand": "bind",
            "message": "Updated the workflow capsule bindings and recomputed its status.",
            "task": task_payload_view(&task),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_approve_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.approve(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": "approved",
            "command": "task",
            "subcommand": "approve",
            "message": "Marked the workflow capsule as approved for side-effecting execution.",
            "task": task_payload_view(&task),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_advance_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.refresh(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };
    if !workflow::ready_for_execution(&task) {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": task.capsule_status,
                "command": "task",
                "subcommand": "advance",
                "message": "The workflow capsule still needs resolution before it can advance safely.",
                "task": task_payload_view(&task),
            }),
            exit_code: CliExitCode::Validation,
        });
    }

    let approve = !task.has_side_effects();
    let bindings = workflow::effective_bindings(&task);
    let execution = materialize_compiled_steps(&task.compiled, approve, Some(&bindings))?;
    let Some(task) = store.append_execution(
        &args.task_id,
        "advance",
        if approve { "approve" } else { "simulate" },
        execution.clone(),
    )?
    else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": task.capsule_status,
            "command": "task",
            "subcommand": "advance",
            "message": if approve {
                "Advanced the workflow capsule by executing its current non-side-effecting plan."
            } else {
                "Advanced the workflow capsule by materializing its next safe simulation step."
            },
            "execution": execution,
            "task": task_payload_view(&task),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_run_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.refresh(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };
    if !workflow::ready_for_execution(&task) {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": task.capsule_status,
                "command": "task",
                "subcommand": "run",
                "message": "The workflow capsule cannot run yet because it still needs resolution or a final answer.",
                "task": task_payload_view(&task),
            }),
            exit_code: CliExitCode::Validation,
        });
    }
    if task.has_side_effects() && !task.approval.workflow {
        return Ok(structured_error(
            "task-approval-required",
            format!(
                "Workflow capsule `{}` contains side-effecting steps and must be approved before `run`.",
                task.id
            ),
            CliExitCode::Validation,
            true,
            &std::env::args().collect::<Vec<_>>(),
            &std::env::args().collect::<Vec<_>>(),
            ErrorDetails {
                did_you_mean: Vec::new(),
                examples: vec![
                    format!("fwc task show {}", task.id),
                    format!("fwc task approve {}", task.id),
                    format!("fwc task run {}", task.id),
                ],
                next_actions: vec![
                    "Inspect the simulated plan before approval if you have not done that yet."
                        .to_owned(),
                    format!(
                        "Run `fwc task approve {}` once you are ready to proceed.",
                        task.id
                    ),
                ],
            },
        ));
    }

    let bindings = workflow::effective_bindings(&task);
    let execution =
        materialize_compiled_steps(&task.compiled, task.approval.workflow, Some(&bindings))?;
    let Some(task) = store.append_execution(
        &args.task_id,
        "run",
        if task.approval.workflow {
            "approve"
        } else {
            "simulate"
        },
        execution.clone(),
    )?
    else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    Ok(DispatchOutcome {
        payload: json!({
            "status": task.capsule_status,
            "command": "task",
            "subcommand": "run",
            "message": if task.approval.workflow {
                "Ran the approved workflow capsule. External side effects are still scaffold-backed until host-backed execution lands."
            } else {
                "Ran the workflow capsule in non-side-effecting mode."
            },
            "execution": execution,
            "task": task_payload_view(&task),
        }),
        exit_code: CliExitCode::Success,
    })
}

fn task_payload_view(task: &workflow::WorkflowTask) -> Value {
    json!({
        "schema_version": task.schema_version,
        "id": task.id,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "capsule_status": task.capsule_status,
        "request": task.request,
        "bindings": task.bindings,
        "approval": task.approval,
        "compiled": task.compiled,
        "unresolved_bindings": task.unresolved_bindings,
        "next_actions": task.next_actions,
        "resolution": {
            "draft_bindings": task.resolution.draft_bindings,
            "identifier_candidates": task.resolution.identifier_candidates,
            "evidence": task.resolution.evidence,
            "pending_question": task.resolution.pending_question,
            "history_count": task.resolution.history.len(),
            "last_receipt": task.last_resolution().map(resolution_receipt_summary),
        },
        "execution_history_count": task.execution_history.len(),
        "last_execution": task.last_execution().map(execution_receipt_summary),
    })
}

fn execution_receipt_summary(receipt: &workflow::ExecutionReceipt) -> Value {
    json!({
        "recorded_at": receipt.recorded_at,
        "trigger": receipt.trigger,
        "mode": receipt.mode,
        "status": receipt.status,
        "executed_count": receipt.executed_count,
        "withheld_count": receipt.withheld_count,
        "stopped_before_side_effect": receipt.stopped_before_side_effect,
    })
}

fn resolution_receipt_summary(receipt: &workflow::ResolutionReceipt) -> Value {
    json!({
        "recorded_at": receipt.recorded_at,
        "trigger": receipt.trigger,
        "mode": receipt.mode,
        "status": receipt.status,
        "status_before": receipt.status_before,
        "status_after": receipt.status_after,
        "stop_reason": receipt.stop_reason,
        "pass_count": receipt.pass_count,
        "safe_step_count": receipt.safe_step_count,
        "changed": receipt.changed,
        "added_draft_bindings": receipt.added_draft_bindings,
        "identifier_candidates_added": receipt.identifier_candidates_added,
        "evidence_added": receipt.evidence_added,
        "pending_question_key": receipt.pending_question_key,
    })
}

fn intent_plan_dispatch(request: &intent::IntentRequest) -> Result<DispatchOutcome> {
    let compiled = intent::compile(request);
    Ok(DispatchOutcome {
        payload: json!({
            "status": compiled.status,
            "command": "plan",
            "message": "Compiled the requested intent into an explicit primitive workflow.",
            "workflow": serde_json::to_value(compiled)?,
        }),
        exit_code: CliExitCode::Success,
    })
}

fn intent_explain_dispatch(request: &intent::IntentRequest) -> Result<DispatchOutcome> {
    let compiled = intent::compile(request);
    Ok(DispatchOutcome {
        payload: json!({
            "status": compiled.status,
            "command": "explain",
            "message": "Explained why the compiler chose this connector, template, and step sequence.",
            "analysis": serde_json::to_value(compiled)?,
        }),
        exit_code: CliExitCode::Success,
    })
}

fn intent_do_dispatch(args: &DoIntentArgs) -> Result<DispatchOutcome> {
    let compiled = intent::compile(&args.request());

    if compiled.status != "ready" {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": compiled.status,
                "command": "do",
                "message": "The intent compiler needs clarification before workflow materialization can continue.",
                "error": {
                    "type": "intent-not-ready",
                    "message": "Resolve the reported ambiguity or missing information before using `fwc do`.",
                    "recoverable": true,
                    "did_you_mean": compiled
                        .alternative_connectors
                        .iter()
                        .map(|candidate| format!("Retry with `--connector {}`.", candidate.id))
                        .take(3)
                        .collect::<Vec<_>>(),
                    "examples": compiled.suggested_command_lines.iter().take(3).cloned().collect::<Vec<_>>(),
                    "next_actions": compiled.next_actions,
                },
                "workflow": serde_json::to_value(compiled)?,
            }),
            exit_code: CliExitCode::Validation,
        });
    }

    let approve = args.approve;
    let execution = materialize_compiled_steps(&compiled, approve, None)?;
    let defaulted_to_simulation = !args.simulate && !args.approve;

    Ok(DispatchOutcome {
        payload: json!({
            "status": if approve { "materialized" } else { "simulated" },
            "command": "do",
            "message": if approve {
                "Materialized the full primitive workflow in approval mode. External side effects are still scaffold-backed in this repo state."
            } else {
                "Materialized the safe prefix of the primitive workflow and stopped before the first side-effecting step."
            },
            "execution_mode": {
                "requested": if approve { "approve" } else if args.simulate { "simulate" } else { "default-simulate" },
                "effective": if approve { "approve" } else { "simulate" },
                "defaulted": defaulted_to_simulation,
            },
            "workflow": serde_json::to_value(compiled)?,
            "execution": execution,
        }),
        exit_code: CliExitCode::Success,
    })
}

fn can_materialize_resolution_steps(task: &workflow::WorkflowTask) -> bool {
    task.compiled.chosen_connector.is_some() && task.compiled.status != "ambiguous"
}

fn materialize_safe_resolution_steps(
    task: &workflow::WorkflowTask,
    bindings: &BTreeMap<String, String>,
) -> Result<(usize, Value)> {
    let steps = task
        .compiled
        .steps
        .iter()
        .filter(|step| is_resolution_safe_step(step))
        .map(|step| rewrite_resolution_step(step, bindings))
        .collect::<Vec<_>>();

    if steps.is_empty() {
        return Ok((
            0,
            json!({
                "status": "no-safe-steps",
                "safe_step_count": 0,
                "executed_steps": [],
            }),
        ));
    }

    let mut compiled = task.compiled.clone();
    compiled.steps = steps;
    let safe_step_count = compiled.steps.len();
    let execution = materialize_compiled_steps(&compiled, true, Some(bindings))?;
    Ok((safe_step_count, execution))
}

fn is_resolution_safe_step(step: &intent::CompiledStep) -> bool {
    match step.command.as_str() {
        "show" | "ops" | "schema" | "examples" | "search" | "list" | "status" => true,
        "config" => matches!(
            step.argv.get(2).map(String::as_str),
            Some("schema" | "get" | "doctor" | "export")
        ),
        _ => false,
    }
}

fn rewrite_resolution_step(
    step: &intent::CompiledStep,
    bindings: &BTreeMap<String, String>,
) -> intent::CompiledStep {
    let mut rewritten = step.clone();
    if rewritten.command == "search"
        && let Some(query) = resolution_search_query(bindings)
        && let Some(slot) = rewritten.argv.get_mut(2)
    {
        *slot = query;
        rewritten.command_line = intent::shell_join(&rewritten.argv);
    }
    rewritten
}

fn resolution_search_query(bindings: &BTreeMap<String, String>) -> Option<String> {
    [
        "page_query",
        "issue_query",
        "message_query",
        "resource_query",
    ]
    .into_iter()
    .find_map(|key| bindings.get(key).cloned())
    .or_else(|| {
        bindings
            .iter()
            .find(|(key, _)| key.ends_with("_query"))
            .map(|(_, value)| value.clone())
    })
}

fn resolve_message(stop_reason: &str, until_ready: bool) -> &'static str {
    match stop_reason {
        "ready" if until_ready => "Resolved the workflow capsule until it became execution-ready.",
        "ready" => "Ran one safe resolution pass and left the capsule execution-ready.",
        "pending-question" => {
            "Resolved everything that could be inferred locally and stopped at one external question."
        }
        "no-further-progress" => {
            "Resolution could not infer any additional state from the current capsule."
        }
        "iteration-cap" => {
            "Stopped after multiple resolution passes to avoid looping on scaffold-only state."
        }
        _ => "Ran a safe resolution pass for the current workflow capsule.",
    }
}

fn materialize_compiled_steps(
    compiled: &intent::CompiledIntent,
    approve: bool,
    bindings: Option<&BTreeMap<String, String>>,
) -> Result<Value> {
    let mut executed_steps = Vec::new();
    let mut withheld_steps = Vec::new();
    let mut stopped_before_side_effect = false;

    for step in &compiled.steps {
        let (resolved_argv, resolved_command_line) = resolve_step_argv(step, bindings);
        if !approve && (stopped_before_side_effect || step.side_effecting) {
            let reason = if step.side_effecting {
                "Simulation mode stops before the first side-effecting primitive."
            } else {
                "This downstream step was withheld because an earlier side-effecting primitive was not executed."
            };
            stopped_before_side_effect = true;
            withheld_steps.push(json!({
                "ordinal": step.ordinal,
                "phase": step.phase,
                "purpose": step.purpose,
                "command": step.command,
                "command_line": resolved_command_line,
                "argv": resolved_argv,
                "approval_required": step.approval_required,
                "side_effecting": step.side_effecting,
                "notes": step.notes,
                "status": "withheld",
                "reason": reason,
            }));
            continue;
        }

        let parsed = Cli::try_parse_from(&resolved_argv).map_err(|error| {
            anyhow::anyhow!("failed to parse compiled primitive `{resolved_command_line}`: {error}")
        })?;
        let primitive = dispatch(&parsed)?;
        let primitive_succeeded = primitive.exit_code == CliExitCode::Success;
        let primitive_payload = primitive.payload;

        executed_steps.push(json!({
            "ordinal": step.ordinal,
            "phase": step.phase,
            "purpose": step.purpose,
            "command": step.command,
            "command_line": resolved_command_line,
            "argv": resolved_argv,
            "approval_required": step.approval_required,
            "side_effecting": step.side_effecting,
            "notes": step.notes,
            "status": if primitive_succeeded { "executed" } else { "failed" },
            "result": primitive_payload,
        }));

        if !primitive_succeeded {
            return Ok(json!({
                "status": "stopped-on-primitive-error",
                "executed_steps": executed_steps,
                "withheld_steps": withheld_steps,
                "executed_count": executed_steps.len(),
                "withheld_count": withheld_steps.len(),
                "stopped_before_side_effect": stopped_before_side_effect,
                "scaffold_backed": true,
            }));
        }
    }

    Ok(json!({
        "status": if approve { "materialized" } else { "simulated" },
        "executed_steps": executed_steps,
        "withheld_steps": withheld_steps,
        "executed_count": executed_steps.len(),
        "withheld_count": withheld_steps.len(),
        "stopped_before_side_effect": stopped_before_side_effect,
        "scaffold_backed": true,
    }))
}

fn resolve_step_argv(
    step: &intent::CompiledStep,
    bindings: Option<&BTreeMap<String, String>>,
) -> (Vec<String>, String) {
    let Some(bindings) = bindings else {
        return (step.argv.clone(), step.command_line.clone());
    };

    let mut argv = Vec::new();
    let mut index = 0;

    while index < step.argv.len() {
        if step.argv[index] == "--file"
            && step
                .argv
                .get(index + 1)
                .is_some_and(|value| value == "./intent-payload.json")
        {
            if let Some(payload_json) = bindings.get("payload_json") {
                argv.push("--input".to_owned());
                argv.push(payload_json.clone());
                index += 2;
                continue;
            }
            if let Some(payload_file) = bindings.get("payload_file") {
                argv.push("--file".to_owned());
                argv.push(payload_file.clone());
                index += 2;
                continue;
            }
        }

        let segment = &step.argv[index];
        if let Some(name) = segment
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        {
            argv.push(
                bindings
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| segment.clone()),
            );
        } else {
            argv.push(segment.clone());
        }
        index += 1;
    }

    (argv.clone(), intent::shell_join(&argv))
}

fn missing_task_dispatch(task_id: &str) -> DispatchOutcome {
    structured_error(
        "unknown-task",
        format!("No workflow capsule with id `{task_id}` was found."),
        CliExitCode::Validation,
        true,
        &std::env::args().collect::<Vec<_>>(),
        &std::env::args().collect::<Vec<_>>(),
        ErrorDetails {
            did_you_mean: Vec::new(),
            examples: vec![
                "fwc task list".to_owned(),
                "fwc task \"create a GitHub issue titled 'FWC: add workflow macros'\"".to_owned(),
            ],
            next_actions: vec![
                "Use `fwc task list` to discover existing workflow capsules.".to_owned(),
                "Create a new capsule if this workflow has not been saved yet.".to_owned(),
            ],
        },
    )
}

#[derive(Debug)]
struct DispatchOutcome {
    payload: Value,
    exit_code: CliExitCode,
}

struct ExecutionOutcome {
    text: String,
    exit_code: ExitCode,
}

#[derive(Debug)]
struct PreparedCli {
    cli: Cli,
    format: OutputFormat,
    render_options: RenderOptions,
    received_args: Vec<String>,
    normalized_args: Vec<String>,
    corrections: Vec<InputCorrection>,
}

enum PrepareCliError {
    Clap(clap::Error),
    Structured(DispatchOutcome),
}

// Reserved variants keep the exit-code contract stable as host-backed errors land.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum CliExitCode {
    Success = 0,
    Parse = 2,
    UnknownCommand = 3,
    AmbiguousCorrection = 4,
    Validation = 5,
    PolicyDenied = 6,
    Connector = 7,
    Transport = 8,
    Internal = 1,
}

impl From<CliExitCode> for ExitCode {
    fn from(value: CliExitCode) -> Self {
        Self::from(value as u8)
    }
}

impl CliExitCode {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Parse => "parse-error",
            Self::UnknownCommand => "unknown-command",
            Self::AmbiguousCorrection => "ambiguous-correction",
            Self::Validation => "validation-error",
            Self::PolicyDenied => "policy-denied",
            Self::Connector => "connector-error",
            Self::Transport => "transport-error",
            Self::Internal => "internal-error",
        }
    }

    const fn category(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Parse | Self::UnknownCommand | Self::AmbiguousCorrection | Self::Validation => {
                "usage"
            }
            Self::PolicyDenied => "policy",
            Self::Connector => "connector",
            Self::Transport => "transport",
            Self::Internal => "internal",
        }
    }

    const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

#[derive(Clone, Debug, Serialize)]
struct InputCorrection {
    from: String,
    to: String,
    rationale: &'static str,
}

#[derive(Debug)]
struct NormalizedArgs {
    args: Vec<String>,
    corrections: Vec<InputCorrection>,
}

struct ErrorDetails {
    did_you_mean: Vec<String>,
    examples: Vec<String>,
    next_actions: Vec<String>,
}

const CONFIG_SUBCOMMANDS: &[&str] = &[
    "schema", "get", "set", "unset", "import", "export", "doctor",
];
const RECIPE_SUBCOMMANDS: &[&str] = &[
    "list",
    "show",
    "validate",
    "run",
    "dry-run",
    "estimate",
    "export",
];
const PIPELINE_SUBCOMMANDS: &[&str] = &["list", "show", "validate", "run", "dry-run", "estimate"];

fn prepare_cli(received_args: &[String]) -> std::result::Result<PreparedCli, PrepareCliError> {
    let normalized = normalize_args(received_args).map_err(PrepareCliError::Structured)?;

    match Cli::try_parse_from(&normalized.args) {
        Ok(cli) => {
            if matches!(
                &cli.command,
                Commands::Do(DoIntentArgs {
                    simulate: true,
                    approve: true,
                    ..
                })
            ) {
                return Err(PrepareCliError::Structured(structured_error(
                    "conflicting-execution-mode",
                    "Choose either `--simulate` or `--approve` for `fwc do`, not both. Omitting both defaults to simulation.",
                    CliExitCode::Validation,
                    true,
                    received_args,
                    &normalized.args,
                    ErrorDetails {
                        did_you_mean: Vec::new(),
                        examples: vec![
                            "fwc do \"disable the slack connector in z:work\"".to_owned(),
                            "fwc do \"disable the slack connector in z:work\" --approve".to_owned(),
                        ],
                        next_actions: vec![
                            "Use the default simulation mode to review the workflow safely."
                                .to_owned(),
                            "Rerun with `--approve` only after the materialized plan looks correct."
                                .to_owned(),
                        ],
                    },
                )));
            }

            let format = if cli.json {
                OutputFormat::Json
            } else {
                cli.format
            };
            let render_options =
                build_render_options(&cli, format, received_args, &normalized.args)?;
            Ok(PreparedCli {
                cli,
                format,
                render_options,
                received_args: received_args.to_vec(),
                normalized_args: normalized.args,
                corrections: normalized.corrections,
            })
        }
        Err(error) => Err(PrepareCliError::Clap(error)),
    }
}

#[allow(clippy::too_many_lines)]
fn normalize_args(
    received_args: &[String],
) -> std::result::Result<NormalizedArgs, DispatchOutcome> {
    let mut args = received_args.to_vec();
    let mut corrections = Vec::new();

    // ── Phase 0: detect dangerous shapes before any normalization ────
    if let Some(shape) = recovery::is_dangerous_shape(&args) {
        return Err(dangerous_shape_dispatch(&args, &shape));
    }

    let Some(command_index) = first_command_index(&args) else {
        return Ok(NormalizedArgs { args, corrections });
    };

    // ── Phase 1: strip redundant namespace prefixes ─────────────────
    if args
        .get(command_index)
        .is_some_and(|segment| recovery::is_redundant_prefix(segment))
    {
        if let Some(next) = args.get(command_index + 1) {
            corrections.push(InputCorrection {
                from: format!("{} {}", args[command_index], next),
                to: next.clone(),
                rationale: "Dropped the redundant namespace prefix because `fwc` is already connector-scoped.",
            });
            args.remove(command_index);
        }
    }

    let Some(command_index) = first_command_index(&args) else {
        return Ok(NormalizedArgs { args, corrections });
    };

    // ── Phase 2: reject ambiguous `op show` shape ───────────────────
    if matches!(
        args.get(command_index).map(String::as_str),
        Some("op" | "operation" | "operations")
    ) && args
        .get(command_index + 1)
        .is_some_and(|segment| segment == "show")
    {
        return Err(ambiguous_operation_show_dispatch(&args));
    }

    // ── Phase 3: resolve command alias/typo ─────────────────────────
    if let Some(resolution) = recovery::resolve_command(&args[command_index]) {
        let safety = recovery::correction_safety(&resolution);
        match safety {
            recovery::CorrectionSafety::Safe => {
                if resolution.canonical != args[command_index] {
                    corrections.push(InputCorrection {
                        from: args[command_index].clone(),
                        to: resolution.canonical.to_owned(),
                        rationale: resolution.rationale,
                    });
                    resolution.canonical.clone_into(&mut args[command_index]);
                }
            }
            recovery::CorrectionSafety::Ambiguous => {
                return Err(ambiguous_typo_dispatch(
                    &args,
                    &args[command_index],
                    resolution.canonical,
                ));
            }
            recovery::CorrectionSafety::Dangerous => {
                return Err(dangerous_typo_dispatch(
                    &args,
                    &args[command_index],
                    resolution.canonical,
                ));
            }
        }
    }

    let Some(command_index) = first_command_index(&args) else {
        return Ok(NormalizedArgs { args, corrections });
    };

    // ── Phase 4: normalize task subcommands ─────────────────────────
    if args
        .get(command_index)
        .is_some_and(|segment| segment == "task")
    {
        if let Some(sub) = args.get(command_index + 1) {
            if !sub.starts_with('-') && !workflow::task_subcommands().contains(&sub.as_str()) {
                // Try task subcommand alias resolution first
                if let Some(canonical) = recovery::task_subcommand_alias(sub) {
                    corrections.push(InputCorrection {
                        from: sub.clone(),
                        to: canonical.to_owned(),
                        rationale: "Canonicalized a task subcommand alias.",
                    });
                    canonical.clone_into(&mut args[command_index + 1]);
                } else {
                    // Treat unrecognized subcommand as intent for `task create`
                    let raw_intent = args[command_index + 1].clone();
                    corrections.push(InputCorrection {
                        from: intent::shell_join(&["task".to_owned(), raw_intent.clone()]),
                        to: intent::shell_join(&[
                            "task".to_owned(),
                            "create".to_owned(),
                            raw_intent,
                        ]),
                        rationale: "Defaulted `fwc task <intent>` to `fwc task create <intent>` because intent-first workflow creation is the canonical capsule entrypoint.",
                    });
                    args.insert(command_index + 1, "create".to_owned());
                }
            }
        }
    }

    // ── Phase 5: normalize config subcommands ───────────────────────
    if args
        .get(command_index)
        .is_some_and(|segment| segment == "config")
    {
        if let Some(sub) = args.get(command_index + 1) {
            if let Some(resolution) = recovery::resolve_config_subcommand(sub) {
                corrections.push(InputCorrection {
                    from: sub.clone(),
                    to: resolution.canonical.to_owned(),
                    rationale: resolution.rationale,
                });
                resolution
                    .canonical
                    .clone_into(&mut args[command_index + 1]);
            }
        }
    }

    Ok(NormalizedArgs { args, corrections })
}

fn dangerous_shape_dispatch(args: &[String], shape: &recovery::DangerousShape) -> DispatchOutcome {
    structured_error(
        shape.kind,
        shape.message,
        CliExitCode::AmbiguousCorrection,
        true,
        args,
        args,
        ErrorDetails {
            did_you_mean: shape
                .candidates
                .iter()
                .map(|candidate| format!("Did you mean `{candidate}`?"))
                .collect(),
            examples: shape
                .candidates
                .iter()
                .map(|candidate| (*candidate).to_owned())
                .collect(),
            next_actions: vec!["Choose the specific command that matches your intent.".to_owned()],
        },
    )
}

fn ambiguous_typo_dispatch(args: &[String], typo: &str, canonical: &str) -> DispatchOutcome {
    structured_error(
        "ambiguous-typo",
        format!(
            "`{typo}` looks like a typo for the mutating command `{canonical}`. Auto-correction was blocked because `{canonical}` has side effects."
        ),
        CliExitCode::AmbiguousCorrection,
        true,
        args,
        args,
        ErrorDetails {
            did_you_mean: vec![format!("Did you mean `{canonical}`?")],
            examples: vec![format!("fwc {canonical} <connector>")],
            next_actions: vec![
                format!(
                    "Retry with the exact spelling `{canonical}` if that is what you intended."
                ),
                "Typo corrections for mutating commands are never applied automatically."
                    .to_owned(),
            ],
        },
    )
}

fn dangerous_typo_dispatch(args: &[String], typo: &str, canonical: &str) -> DispatchOutcome {
    structured_error(
        "dangerous-correction",
        format!(
            "`{typo}` was not corrected to `{canonical}` because the target command is destructive."
        ),
        CliExitCode::AmbiguousCorrection,
        false,
        args,
        args,
        ErrorDetails {
            did_you_mean: vec![format!("Did you mean `{canonical}`?")],
            examples: vec![format!("fwc {canonical} <connector>")],
            next_actions: vec![format!(
                "Retry with the exact spelling `{canonical}` if that is truly what you intended."
            )],
        },
    )
}

fn infer_output_format(args: &[String]) -> OutputFormat {
    if args.iter().any(|arg| arg == "--json") {
        return OutputFormat::Json;
    }

    args.iter()
        .enumerate()
        .find_map(|(index, arg)| {
            if let Some((_, value)) = arg.split_once('=') {
                return (arg.starts_with("--format=")).then(|| parse_output_format(value));
            }

            (arg == "--format")
                .then(|| args.get(index + 1).map(String::as_str))
                .flatten()
                .map(parse_output_format)
        })
        .unwrap_or(OutputFormat::Toon)
}

fn parse_output_format(value: &str) -> OutputFormat {
    match value {
        "json" => OutputFormat::Json,
        "jsonl" => OutputFormat::Jsonl,
        "ndjson" => OutputFormat::Ndjson,
        "table" => OutputFormat::Table,
        "csv" => OutputFormat::Csv,
        "tsv" => OutputFormat::Tsv,
        "markdown" => OutputFormat::Markdown,
        _ => OutputFormat::Toon,
    }
}

fn first_command_index(args: &[String]) -> Option<usize> {
    let mut index = 1;

    while index < args.len() {
        let current = args[index].as_str();
        match current {
            "--format" | "--host" | "--template" | "--template-file" | "--extract"
            | "--sort-by" | "--limit" | "--columns" => index += 2,
            "--json" | "--token-stats" | "--no-headers" | "-h" | "--help" | "-V" | "--version" => {
                index += 1;
            }
            _ if current.starts_with("--format=")
                || current.starts_with("--host=")
                || current.starts_with("--template=")
                || current.starts_with("--template-file=")
                || current.starts_with("--extract=")
                || current.starts_with("--sort-by=")
                || current.starts_with("--limit=")
                || current.starts_with("--columns=") =>
            {
                index += 1;
            }
            _ if current.starts_with('-') => index += 1,
            _ => return Some(index),
        }
    }

    None
}

fn ambiguous_operation_show_dispatch(args: &[String]) -> DispatchOutcome {
    let connector = args
        .get(first_command_index(args).unwrap_or(0) + 2)
        .cloned();
    let operation = args
        .get(first_command_index(args).unwrap_or(0) + 3)
        .cloned();
    let mut examples = vec!["fwc ops <connector>".to_owned()];
    let mut next_actions = vec![
        "Choose whether you want the connector's operation list or one operation schema."
            .to_owned(),
        "Use `fwc ops <connector>` when you need a short operation inventory.".to_owned(),
    ];

    if let Some(connector) = connector.as_deref() {
        examples[0] = format!("fwc ops {connector}");
        next_actions.push(format!(
            "Use `fwc ops {connector}` to scan the available operations before narrowing further."
        ));
    }

    if let (Some(connector), Some(operation)) = (connector.as_deref(), operation.as_deref()) {
        examples.push(format!("fwc schema {connector} {operation}"));
        next_actions.push(format!(
            "Use `fwc schema {connector} {operation}` if you already know the exact operation and need its payload shape."
        ));
    }

    structured_error(
        "ambiguous-correction",
        "The `op show` shape is ambiguous and was not auto-corrected.",
        CliExitCode::AmbiguousCorrection,
        true,
        args,
        args,
        ErrorDetails {
            did_you_mean: vec![
                "Did you mean `fwc ops <connector>`?".to_owned(),
                "Or did you mean `fwc schema <connector> <operation>`?".to_owned(),
            ],
            examples,
            next_actions,
        },
    )
}

#[allow(clippy::too_many_lines)]
fn parse_failure_dispatch(args: &[String], error: &clap::Error) -> DispatchOutcome {
    let normalized_args = args.to_vec();
    let command_index = first_command_index(args);
    let command = command_index.and_then(|index| args.get(index).map(String::as_str));

    match error.kind() {
        ErrorKind::MissingSubcommand => {
            if command == Some("task") {
                return structured_error(
                    "missing-task-subcommand",
                    "No task intent or task subcommand was provided.",
                    CliExitCode::Parse,
                    true,
                    args,
                    &normalized_args,
                    ErrorDetails {
                        did_you_mean: Vec::new(),
                        examples: vec![
                            "fwc task \"disable the slack connector in z:work\"".to_owned(),
                            "fwc task list".to_owned(),
                        ],
                        next_actions: vec![
                            "Pass a quoted intent after `fwc task` to create a new capsule.".to_owned(),
                            "Or use `fwc task show|list|resolve|ask|advance|bind|approve|run` with an existing task id.".to_owned(),
                        ],
                    },
                );
            }

            if command == Some("pipeline") {
                return structured_error(
                    "missing-pipeline-subcommand",
                    "No pipeline subcommand was provided.",
                    CliExitCode::Parse,
                    true,
                    args,
                    &normalized_args,
                    ErrorDetails {
                        did_you_mean: Vec::new(),
                        examples: vec![
                            "fwc pipeline list".to_owned(),
                            "fwc pipeline validate .fwc/pipelines/<name>.toml".to_owned(),
                        ],
                        next_actions: vec![
                            "Use `fwc pipeline list` to discover registered pipeline definitions."
                                .to_owned(),
                            "Use `fwc pipeline show|validate|run|dry-run|estimate <name-or-path>` once you know the target pipeline."
                                .to_owned(),
                        ],
                    },
                );
            }

            if command == Some("recipe") {
                return structured_error(
                    "missing-recipe-subcommand",
                    "No recipe subcommand was provided.",
                    CliExitCode::Parse,
                    true,
                    args,
                    &normalized_args,
                    ErrorDetails {
                        did_you_mean: Vec::new(),
                        examples: vec![
                            "fwc recipe list".to_owned(),
                            "fwc recipe show github-pr-review-notify".to_owned(),
                        ],
                        next_actions: vec![
                            "Use `fwc recipe list` to discover the bundled recipe library."
                                .to_owned(),
                            "Use `fwc recipe show|validate|run|dry-run|estimate|export <slug>` once you know the target recipe."
                                .to_owned(),
                        ],
                    },
                );
            }

            structured_error(
                "missing-command",
                "No `fwc` command was provided.",
                CliExitCode::Parse,
                true,
                args,
                &normalized_args,
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec!["fwc guide".to_owned(), "fwc list".to_owned()],
                    next_actions: vec![
                        "Run `fwc guide` to inspect the command taxonomy.".to_owned(),
                        "Run `fwc list` if you want to start from connector discovery.".to_owned(),
                    ],
                },
            )
        }
        ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument => match command {
            Some("config") => unknown_subcommand_dispatch(
                "config-subcommand",
                "config",
                args,
                &normalized_args,
                command_index
                    .and_then(|index| args.get(index + 1))
                    .map(String::as_str),
                CONFIG_SUBCOMMANDS,
                vec![
                    "fwc config schema github".to_owned(),
                    "fwc config doctor github".to_owned(),
                ],
            ),
            Some("pipeline") => unknown_subcommand_dispatch(
                "pipeline-subcommand",
                "pipeline",
                args,
                &normalized_args,
                command_index
                    .and_then(|index| args.get(index + 1))
                    .map(String::as_str),
                PIPELINE_SUBCOMMANDS,
                vec![
                    "fwc pipeline list".to_owned(),
                    "fwc pipeline validate .fwc/pipelines/<name>.toml".to_owned(),
                    "fwc pipeline estimate .fwc/pipelines/<name>.toml --param key=value".to_owned(),
                    "fwc pipeline dry-run .fwc/pipelines/<name>.toml --param key=value".to_owned(),
                ],
            ),
            Some("recipe") => unknown_subcommand_dispatch(
                "recipe-subcommand",
                "recipe",
                args,
                &normalized_args,
                command_index
                    .and_then(|index| args.get(index + 1))
                    .map(String::as_str),
                RECIPE_SUBCOMMANDS,
                vec![
                    "fwc recipe list".to_owned(),
                    "fwc recipe show github-pr-review-notify".to_owned(),
                    "fwc recipe export github-pr-review-notify".to_owned(),
                    "fwc recipe dry-run github-pr-review-notify".to_owned(),
                ],
            ),
            Some("task") => unknown_subcommand_dispatch(
                "task-subcommand",
                "task",
                args,
                &normalized_args,
                command_index
                    .and_then(|index| args.get(index + 1))
                    .map(String::as_str),
                workflow::task_subcommands(),
                vec![
                    "fwc task \"disable the slack connector in z:work\"".to_owned(),
                    "fwc task list".to_owned(),
                    "fwc task show <task-id>".to_owned(),
                    "fwc task resolve <task-id> --until ready".to_owned(),
                ],
            ),
            Some(token) => unknown_subcommand_dispatch(
                "unknown-command",
                "fwc",
                args,
                &normalized_args,
                Some(token),
                catalog::COMMANDS,
                vec!["fwc guide".to_owned(), "fwc list".to_owned()],
            ),
            None => structured_error(
                "parse-error",
                parser_summary(error),
                CliExitCode::Parse,
                true,
                args,
                &normalized_args,
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec!["fwc guide".to_owned()],
                    next_actions: vec![
                        "Retry with one top-level command after any global flags.".to_owned(),
                    ],
                },
            ),
        },
        ErrorKind::MissingRequiredArgument => {
            if let Some(command) = command {
                if matches!(command, "invoke" | "simulate")
                    && args.get(command_index.unwrap_or(0) + 1).is_some()
                {
                    return structured_error(
                        "missing-operation",
                        "Connector invocation needs both a connector id and an operation name.",
                        CliExitCode::Validation,
                        true,
                        args,
                        &normalized_args,
                        ErrorDetails {
                            did_you_mean: Vec::new(),
                            examples: vec![
                                format!("fwc ops {}", args[command_index.unwrap_or(0) + 1]),
                                format!(
                                    "fwc {command} {} issues.create --file payload.json",
                                    args[command_index.unwrap_or(0) + 1]
                                ),
                            ],
                            next_actions: vec![
                                format!(
                                    "Run `fwc ops {}` to discover the valid operations first.",
                                    args[command_index.unwrap_or(0) + 1]
                                ),
                                format!(
                                    "Retry with `fwc {command} <connector> <operation>` once the operation is known."
                                ),
                            ],
                        },
                    );
                }

                if command == "config"
                    && args
                        .get(command_index.unwrap_or(0) + 1)
                        .is_some_and(|segment| segment == "set")
                {
                    let connector = args
                        .get(command_index.unwrap_or(0) + 2)
                        .cloned()
                        .unwrap_or_else(|| "<connector>".to_owned());
                    return structured_error(
                        "missing-config-fields",
                        "`fwc config set` needs a connector, key path, and value.",
                        CliExitCode::Validation,
                        true,
                        args,
                        &normalized_args,
                        ErrorDetails {
                            did_you_mean: Vec::new(),
                            examples: vec![
                                format!("fwc config schema {connector}"),
                                format!(
                                    "fwc config set {connector} auth.token secret-ref:prod/github"
                                ),
                            ],
                            next_actions: vec![
                                "Inspect the config schema before writing new values.".to_owned(),
                                "Prefer secret references or credential ids instead of inline secrets when the connector supports them.".to_owned(),
                            ],
                        },
                    );
                }

                if command == "task"
                    && args
                        .get(command_index.unwrap_or(0) + 1)
                        .is_some_and(|segment| segment == "bind")
                {
                    let task_id = args
                        .get(command_index.unwrap_or(0) + 2)
                        .cloned()
                        .unwrap_or_else(|| "<task-id>".to_owned());
                    return structured_error(
                        "missing-task-bindings",
                        "`fwc task bind` needs a workflow id plus one or more `key=value` bindings.",
                        CliExitCode::Validation,
                        true,
                        args,
                        &normalized_args,
                        ErrorDetails {
                            did_you_mean: Vec::new(),
                            examples: vec![
                                format!("fwc task show {task_id}"),
                                format!(
                                    "fwc task bind {task_id} connector=notion payload_file=payload.json"
                                ),
                            ],
                            next_actions: vec![
                                "Pass one or more `key=value` bindings after the task id.".to_owned(),
                                "Use `connector=` and `zone=` to refine compiler inference; use `payload_file=` or `payload_json=` for request materialization.".to_owned(),
                            ],
                        },
                    );
                }
            }

            structured_error(
                "validation-error",
                parser_summary(error),
                CliExitCode::Validation,
                true,
                args,
                &normalized_args,
                ErrorDetails {
                    did_you_mean: Vec::new(),
                    examples: vec!["fwc guide".to_owned()],
                    next_actions: vec![
                        "Retry with the missing required arguments filled in.".to_owned(),
                    ],
                },
            )
        }
        _ => structured_error(
            "parse-error",
            parser_summary(error),
            CliExitCode::Parse,
            true,
            args,
            &normalized_args,
            ErrorDetails {
                did_you_mean: Vec::new(),
                examples: vec!["fwc guide".to_owned()],
                next_actions: vec![
                    "Retry with a valid command shape or inspect `fwc --help`.".to_owned(),
                ],
            },
        ),
    }
}

fn unknown_subcommand_dispatch(
    error_type: &str,
    scope: &str,
    received_args: &[String],
    normalized_args: &[String],
    token: Option<&str>,
    candidates: &[&str],
    examples: Vec<String>,
) -> DispatchOutcome {
    let unknown = token.unwrap_or("<unknown>").to_owned();
    let suggestions = suggest_values(&unknown, candidates);
    let next_actions = if scope == "config" {
        vec![
            "Use `fwc config schema <connector>` to inspect configuration requirements.".to_owned(),
            "Use `fwc config doctor <connector>` after any config change.".to_owned(),
        ]
    } else if scope == "task" {
        vec![
            "Use `fwc task \"<intent>\"` to create a new workflow capsule.".to_owned(),
            "Use `fwc task list` to discover existing capsules before `show`, `resolve`, `ask`, `bind`, `advance`, `approve`, or `run`.".to_owned(),
        ]
    } else {
        vec![format!(
            "Run `fwc guide` if you need the full `{scope}` command taxonomy."
        )]
    };

    structured_error(
        error_type,
        format!("`{unknown}` is not a valid {scope} command."),
        CliExitCode::UnknownCommand,
        true,
        received_args,
        normalized_args,
        ErrorDetails {
            did_you_mean: suggestions
                .iter()
                .map(|suggestion| format!("Did you mean `{suggestion}`?"))
                .collect(),
            examples,
            next_actions,
        },
    )
}

#[allow(clippy::needless_pass_by_value)]
fn structured_error(
    error_type: &str,
    message: impl Into<String>,
    exit_code: CliExitCode,
    recoverable: bool,
    received_args: &[String],
    normalized_args: &[String],
    details: ErrorDetails,
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "error": {
                "type": error_type,
                "message": message.into(),
                "recoverable": recoverable,
                "did_you_mean": details.did_you_mean,
                "examples": details.examples,
                "next_actions": details.next_actions,
            },
            "input": {
                "received": received_args,
                "normalized": normalized_args,
            },
        }),
        exit_code,
    }
}

fn parser_summary(error: &clap::Error) -> String {
    error
        .to_string()
        .lines()
        .find(|line| !line.trim().is_empty() && !line.starts_with("Usage:"))
        .unwrap_or("The command line could not be parsed.")
        .trim()
        .to_owned()
}

fn suggest_values(value: &str, candidates: &[&str]) -> Vec<String> {
    let mut matches = candidates
        .iter()
        .map(|candidate| (*candidate, levenshtein(value, candidate)))
        .filter(|(candidate, distance)| candidate.starts_with(value) || *distance <= 3)
        .collect::<Vec<_>>();

    matches.sort_by_key(|(candidate, distance)| (*distance, candidate.len()));
    matches
        .into_iter()
        .take(3)
        .map(|(candidate, _)| candidate.to_owned())
        .collect()
}

fn levenshtein(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut costs = (0..=right_chars.len()).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = left_index + 1;

        for (right_index, right_char) in right_chars.iter().enumerate() {
            let insertion = costs[right_index + 1] + 1;
            let deletion = costs[right_index] + 1;
            let substitution = previous + usize::from(left_char != *right_char);
            previous = costs[right_index + 1];
            costs[right_index + 1] = insertion.min(deletion).min(substitution);
        }
    }

    costs[right_chars.len()]
}

fn annotate_with_corrections(
    payload: &mut Value,
    received_args: &[String],
    normalized_args: &[String],
    corrections: &[InputCorrection],
) {
    if corrections.is_empty() {
        return;
    }

    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "input_normalization".to_owned(),
            json!({
                "applied": corrections,
                "received": received_args,
                "normalized": normalized_args,
            }),
        );
    }
}

fn enrich_unknown_guide_command(payload: &mut Value, command: Option<&str>) {
    let Some(command) = command else {
        return;
    };

    let did_you_mean = suggest_values(command, catalog::COMMANDS)
        .into_iter()
        .map(|suggestion| format!("fwc guide --command {suggestion}"))
        .collect::<Vec<_>>();
    let examples = vec![
        "fwc guide".to_owned(),
        "fwc guide --command show".to_owned(),
    ];
    let next_actions = vec![
        "Retry with one canonical top-level command name.".to_owned(),
        "Run `fwc guide` without `--command` to inspect the full taxonomy.".to_owned(),
    ];

    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "error".to_owned(),
            json!({
                "type": "unknown-command",
                "recoverable": true,
                "did_you_mean": did_you_mean,
                "examples": examples,
                "next_actions": next_actions,
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{Cli, CliExitCode, PrepareCliError, catalog, execute, normalize_args, prepare_cli};
    use clap::CommandFactory;
    use serde_json::Value;

    fn execute_json(args: &[&str]) -> (std::process::ExitCode, Value) {
        let owned_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let outcome = execute(&owned_args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");
        (outcome.exit_code, payload)
    }

    fn execute_text(args: &[&str]) -> (std::process::ExitCode, String) {
        let owned_args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        let outcome = execute(&owned_args).expect("execution should not fail internally");
        (outcome.exit_code, outcome.text)
    }

    #[test]
    fn clap_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn guide_lists_progressive_disclosure_workflow() {
        let payload = catalog::guide_payload(None);
        assert_eq!(payload["recommended_workflow"][0], "fwc task \"<intent>\"");
        assert_eq!(
            payload["recommended_workflow"][1],
            "fwc task resolve <task-id> --until ready"
        );
        assert_eq!(
            payload["phase"]["current_bead"],
            "flywheel_connectors-1g7z0.2"
        );
    }

    #[test]
    fn guide_unknown_command_maps_to_nonzero_contract() {
        let payload = catalog::guide_payload(Some("nope"));
        assert_eq!(payload["status"], "unknown-command");
    }

    #[test]
    fn normalize_drops_redundant_connector_prefix_and_aliases_info() {
        let normalized = normalize_args(&["fwc", "connector", "info", "github"].map(str::to_owned))
            .expect("normalization should succeed");
        assert_eq!(normalized.args, vec!["fwc", "show", "github"]);
        assert_eq!(normalized.corrections.len(), 2);
    }

    #[test]
    fn normalize_rejects_ambiguous_op_show_shape() {
        let error =
            normalize_args(&["fwc", "op", "show", "github", "issues.create"].map(str::to_owned))
                .expect_err("op show should not auto-correct");
        assert_eq!(error.exit_code, CliExitCode::AmbiguousCorrection);
        assert_eq!(error.payload["error"]["type"], "ambiguous-verb-object");
    }

    #[test]
    fn normalize_defaults_task_intent_to_create() {
        let normalized = normalize_args(
            &["fwc", "task", "disable the slack connector in z:work"].map(str::to_owned),
        )
        .expect("task intent should normalize");

        assert_eq!(
            normalized.args,
            vec![
                "fwc",
                "task",
                "create",
                "disable the slack connector in z:work"
            ]
        );
        assert_eq!(normalized.corrections.len(), 1);
        assert_eq!(
            normalized.corrections[0].from,
            "task 'disable the slack connector in z:work'"
        );
        assert_eq!(
            normalized.corrections[0].to,
            "task create 'disable the slack connector in z:work'"
        );
    }

    #[test]
    fn execute_returns_structured_unknown_command_recovery() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "connectorz".to_owned(),
            "slack".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::UnknownCommand.into());
        assert_eq!(payload["error"]["type"], "unknown-command");
        assert!(payload["error"]["recoverable"] == true);
    }

    #[test]
    fn execute_auto_corrects_exmaples_typo() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "exmaples".to_owned(),
            "slack".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        // exmaples is a typo for examples (readonly command), so auto-corrected
        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "examples");
        assert_eq!(
            payload["input_normalization"]["applied"][0]["from"],
            "exmaples"
        );
        assert_eq!(
            payload["input_normalization"]["applied"][0]["to"],
            "examples"
        );
    }

    #[test]
    fn execute_explains_missing_invoke_operation() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "invoke".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "missing-operation");
        assert_eq!(payload["error"]["recoverable"], true);
    }

    #[test]
    fn execute_renders_show_output_with_inline_template() {
        let (exit_code, text) = execute_text(&[
            "fwc",
            "show",
            "github",
            "--template",
            "{{connector.slug}} => {{connector.name}}",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(text, "github => GitHub Connector\n");
    }

    #[test]
    fn execute_renders_invoke_output_with_inline_template() {
        let (exit_code, text) = execute_text(&[
            "fwc",
            "invoke",
            "github",
            "issues.create",
            "--input",
            "{}",
            "--template",
            "{{command}} {{captures.connector}} {{captures.operation}}",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(text, "invoke github issues.create\n");
    }

    #[test]
    fn execute_renders_output_with_template_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fwc-main-template-{unique}.hbs"));
        std::fs::write(&path, "{{connector.slug}} from file").unwrap();

        let (exit_code, text) = execute_text(&[
            "fwc",
            "show",
            "github",
            "--template-file",
            &path.display().to_string(),
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(text, "github from file\n");
    }

    #[test]
    fn execute_returns_validation_error_for_missing_template_field() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "show",
            "github",
            "--template",
            "{{connector.nope}}",
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "template-render-failed");
        assert_eq!(payload["error"]["transform"]["source"], "inline");
    }

    #[test]
    fn execute_returns_validation_error_for_missing_template_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fwc-main-missing-{unique}.hbs"));
        let path_string = path.display().to_string();

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "show",
            "github",
            "--template-file",
            &path_string,
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "invalid-template-file");
    }

    #[test]
    fn execute_show_supports_extract_with_json_output() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "show",
            "github",
            "--extract",
            ".connector.slug",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload, Value::String("github".to_owned()));
    }

    #[test]
    fn execute_show_supports_extract_alias() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "show", "github", "--jq", ".connector.slug"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload, Value::String("github".to_owned()));
    }

    #[test]
    fn execute_returns_validation_error_for_invalid_extract_filter() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "show",
            "github",
            "--extract",
            ".connector[",
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "invalid-extract-filter");
    }

    #[test]
    fn prepare_cli_rejects_extract_without_json_output() {
        let Err(error) = prepare_cli(
            &["fwc", "show", "github", "--extract", ".connector.slug"].map(str::to_owned),
        ) else {
            panic!("TOON output should reject --extract");
        };

        let PrepareCliError::Structured(dispatch) = error else {
            panic!("expected structured validation error");
        };

        assert_eq!(dispatch.exit_code, CliExitCode::Validation);
        assert_eq!(
            dispatch.payload["error"]["type"],
            "extract-requires-json-output"
        );
    }

    #[test]
    fn execute_extract_is_skipped_when_command_fails() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "show",
            "definitely-not-a-real-connector",
            "--extract",
            ".connector.slug",
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "connector-not-found");
    }

    #[test]
    fn execute_canonicalizes_example_alias_and_records_normalization() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "example".to_owned(),
            "slack".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "examples");
        assert_eq!(
            payload["input_normalization"]["applied"][0]["to"],
            "examples"
        );
    }

    #[test]
    fn execute_plan_returns_compiled_github_issue_workflow() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "plan".to_owned(),
            "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "plan");
        assert_eq!(payload["workflow"]["status"], "ready");
        assert_eq!(payload["workflow"]["chosen_connector"]["id"], "github");
        assert_eq!(payload["workflow"]["operation_hint"], "issues.create");
    }

    #[test]
    fn execute_task_create_and_show_round_trips_capsule() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let show_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "show".to_owned(),
            task_id,
        ];
        let shown = execute(&show_args).expect("task show should succeed");
        let shown_payload: Value =
            serde_json::from_str(&shown.text).expect("json output should parse cleanly");

        assert_eq!(created.exit_code, CliExitCode::Success.into());
        assert_eq!(shown.exit_code, CliExitCode::Success.into());
        assert_eq!(
            shown_payload["task"]["compiled"]["chosen_connector"]["id"],
            "github"
        );
        assert_eq!(shown_payload["task"]["capsule_status"], "ready-to-simulate");
    }

    #[test]
    fn execute_task_bind_and_approve_updates_capsule_state() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "send a message to a channel".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let bind_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "bind".to_owned(),
            task_id.clone(),
            "connector=slack".to_owned(),
            "payload_json={\"text\":\"hello\"}".to_owned(),
        ];
        let bound = execute(&bind_args).expect("task bind should succeed");
        let bound_payload: Value =
            serde_json::from_str(&bound.text).expect("json output should parse cleanly");
        assert_eq!(
            bound_payload["task"]["compiled"]["chosen_connector"]["id"],
            "slack"
        );

        let approve_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "approve".to_owned(),
            task_id,
        ];
        let approved = execute(&approve_args).expect("task approve should succeed");
        let approved_payload: Value =
            serde_json::from_str(&approved.text).expect("json output should parse cleanly");

        assert_eq!(approved.exit_code, CliExitCode::Success.into());
        assert_eq!(approved_payload["task"]["approval"]["workflow"], true);
    }

    #[test]
    fn execute_task_resolve_persists_payload_draft_for_github_issue() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let resolve_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "resolve".to_owned(),
            task_id,
            "--until".to_owned(),
            "ready".to_owned(),
        ];
        let resolved = execute(&resolve_args).expect("task resolve should succeed");
        let resolved_payload: Value =
            serde_json::from_str(&resolved.text).expect("json output should parse cleanly");

        assert_eq!(resolved.exit_code, CliExitCode::Success.into());
        assert_eq!(resolved_payload["resolution"]["stop_reason"], "ready");
        assert_eq!(
            resolved_payload["task"]["resolution"]["draft_bindings"]["payload_json"],
            "{\"title\":\"FWC: add workflow macros\"}"
        );
        assert_eq!(resolved_payload["task"]["resolution"]["history_count"], 1);
    }

    #[test]
    fn execute_task_search_intent_does_not_require_fake_payload_binding() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "search GitHub issues for auth".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["task"]["capsule_status"], "ready");
        assert!(
            payload["task"]["unresolved_bindings"]
                .as_array()
                .is_some_and(std::vec::Vec::is_empty)
        );
        assert!(payload["task"]["resolution"]["pending_question"].is_null());
    }

    #[test]
    fn execute_task_ask_surfaces_connector_question_for_ambiguous_message_intent() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "send a message to a channel".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let ask_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "ask".to_owned(),
            task_id,
        ];
        let asked = execute(&ask_args).expect("task ask should succeed");
        let asked_payload: Value =
            serde_json::from_str(&asked.text).expect("json output should parse cleanly");

        assert_eq!(asked.exit_code, CliExitCode::Success.into());
        assert_eq!(asked_payload["status"], "question");
        assert_eq!(asked_payload["question"]["key"], "connector");
    }

    #[test]
    fn execute_task_resolve_salvages_append_and_blocks_on_identifier_question() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "find the Notion page named Roadmap and append Summary".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let resolve_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "resolve".to_owned(),
            task_id,
        ];
        let resolved = execute(&resolve_args).expect("task resolve should succeed");
        let resolved_payload: Value =
            serde_json::from_str(&resolved.text).expect("json output should parse cleanly");

        assert_eq!(resolved.exit_code, CliExitCode::Success.into());
        assert_eq!(resolved_payload["status"], "needs-answer");
        assert_eq!(
            resolved_payload["task"]["resolution"]["draft_bindings"]["payload_json"],
            "{\"content\":\"Summary\"}"
        );
        assert_eq!(
            resolved_payload["task"]["resolution"]["pending_question"]["key"],
            "page_id"
        );
        assert!(
            resolved_payload["resolution"]["passes"][0]["safe_execution"]["executed_steps"][2]["command_line"]
                .as_str()
                .is_some_and(|line| line == "fwc search Roadmap")
        );
    }

    #[test]
    fn execute_task_advance_rejects_when_identifier_question_remains() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "find the Notion page named Roadmap and append Summary".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let resolve_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "resolve".to_owned(),
            task_id.clone(),
        ];
        let _resolved = execute(&resolve_args).expect("task resolve should succeed");

        let advance_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "advance".to_owned(),
            task_id,
        ];
        let advanced = execute(&advance_args).expect("task advance should return validation");
        let advanced_payload: Value =
            serde_json::from_str(&advanced.text).expect("json output should parse cleanly");

        assert_eq!(advanced.exit_code, CliExitCode::Validation.into());
        assert_eq!(advanced_payload["status"], "needs-answer");
    }

    #[test]
    fn execute_task_bind_connector_resets_stale_resolution_state() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "find the Notion page named Roadmap and append Summary".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let resolve_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "resolve".to_owned(),
            task_id.clone(),
        ];
        let _resolved = execute(&resolve_args).expect("task resolve should succeed");

        let bind_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "bind".to_owned(),
            task_id,
            "connector=slack".to_owned(),
        ];
        let rebound = execute(&bind_args).expect("task bind should succeed");
        let rebound_payload: Value =
            serde_json::from_str(&rebound.text).expect("json output should parse cleanly");

        assert_eq!(rebound.exit_code, CliExitCode::Success.into());
        assert!(
            rebound_payload["task"]["resolution"]["identifier_candidates"]
                .as_array()
                .is_some_and(std::vec::Vec::is_empty)
        );
        assert!(
            rebound_payload["task"]["resolution"]["draft_bindings"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        );
    }

    #[test]
    fn execute_task_bind_after_advance_clears_stale_execution_history() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let advance_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "advance".to_owned(),
            task_id.clone(),
        ];
        let advanced = execute(&advance_args).expect("task advance should succeed");
        let advanced_payload: Value =
            serde_json::from_str(&advanced.text).expect("json output should parse cleanly");

        assert_eq!(
            advanced_payload["task"]["capsule_status"],
            "ready-to-approve"
        );
        assert_eq!(advanced_payload["task"]["execution_history_count"], 1);

        let bind_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "bind".to_owned(),
            task_id,
            "payload_json={\"title\":\"changed\"}".to_owned(),
        ];
        let rebound = execute(&bind_args).expect("task bind should succeed");
        let rebound_payload: Value =
            serde_json::from_str(&rebound.text).expect("json output should parse cleanly");

        assert_eq!(rebound.exit_code, CliExitCode::Success.into());
        assert_eq!(
            rebound_payload["task"]["capsule_status"],
            "ready-to-simulate"
        );
        assert_eq!(rebound_payload["task"]["execution_history_count"], 0);
        assert!(rebound_payload["task"]["last_execution"].is_null());
    }

    #[test]
    fn execute_task_bind_payload_file_overrides_resolved_payload_json() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let resolve_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "resolve".to_owned(),
            task_id.clone(),
        ];
        let _resolved = execute(&resolve_args).expect("task resolve should succeed");

        let bind_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "bind".to_owned(),
            task_id.clone(),
            "payload_file=payload.json".to_owned(),
        ];
        let rebound = execute(&bind_args).expect("task bind should succeed");
        let rebound_payload: Value =
            serde_json::from_str(&rebound.text).expect("json output should parse cleanly");

        assert_eq!(rebound.exit_code, CliExitCode::Success.into());
        assert_eq!(
            rebound_payload["task"]["bindings"]["payload_file"],
            "payload.json"
        );
        assert!(rebound_payload["task"]["resolution"]["draft_bindings"]["payload_json"].is_null());

        let advance_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "advance".to_owned(),
            task_id,
        ];
        let advanced = execute(&advance_args).expect("task advance should succeed");
        let advanced_payload: Value =
            serde_json::from_str(&advanced.text).expect("json output should parse cleanly");
        let executed_steps = advanced_payload["execution"]["executed_steps"]
            .as_array()
            .expect("executed steps should be present");
        let simulate_step = executed_steps
            .iter()
            .find(|step| step["command"] == "simulate")
            .expect("simulate step should be present");
        let argv = simulate_step["argv"]
            .as_array()
            .expect("simulate argv should be an array")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();

        assert!(
            argv.windows(2)
                .any(|pair| pair == ["--file", "payload.json"])
        );
        assert!(!argv.contains(&"--input"));
    }

    #[test]
    fn execute_task_bind_rejects_multiple_payload_sources() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "bind".to_owned(),
            "w:deadbeef".to_owned(),
            "payload_json={\"title\":\"hello\"}".to_owned(),
            "payload_file=payload.json".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "invalid-task-binding");
        assert!(
            payload["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("mutually exclusive"))
        );
    }

    #[test]
    fn execute_task_advance_keeps_task_projection_compact() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "create a GitHub issue titled \"FWC: compact task history\"".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let created_payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = created_payload["task"]["id"]
            .as_str()
            .expect("task id should be present")
            .to_owned();

        let advance_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "advance".to_owned(),
            task_id,
        ];
        let advanced = execute(&advance_args).expect("task advance should succeed");
        let advanced_payload: Value =
            serde_json::from_str(&advanced.text).expect("json output should parse cleanly");

        assert_eq!(advanced.exit_code, CliExitCode::Success.into());
        assert_eq!(advanced_payload["execution"]["status"], "simulated");
        assert_eq!(advanced_payload["task"]["execution_history_count"], 1);
        assert_eq!(
            advanced_payload["task"]["last_execution"]["status"],
            "simulated"
        );
        assert!(advanced_payload["task"]["last_execution"]["execution"].is_null());
    }

    #[test]
    fn execute_explain_surfaces_reasoning() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "explain".to_owned(),
            "find the Notion page named Roadmap and append \"Summary\"".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "explain");
        assert_eq!(payload["analysis"]["chosen_connector"]["id"], "notion");
        assert!(
            payload["analysis"]["explanation"]["template_reasoning"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
        );
    }

    #[test]
    fn execute_do_defaults_to_safe_simulation() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "do".to_owned(),
            "create a GitHub issue titled \"FWC: add workflow macros\"".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "simulated");
        assert_eq!(payload["execution_mode"]["defaulted"], true);
        assert_eq!(payload["execution"]["executed_count"], 5);
        assert_eq!(payload["execution"]["withheld_count"], 1);
    }

    #[test]
    fn execute_do_rejects_conflicting_execution_flags() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "do".to_owned(),
            "disable the slack connector in z:work".to_owned(),
            "--simulate".to_owned(),
            "--approve".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "conflicting-execution-mode");
    }

    #[test]
    fn execute_do_returns_validation_when_intent_is_ambiguous() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "do".to_owned(),
            "send a message to a channel".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["status"], "ambiguous");
        assert_eq!(payload["error"]["type"], "intent-not-ready");
    }

    // ── Intent recovery: alias auto-corrections ─────────────────────────

    #[test]
    fn execute_find_alias_resolves_to_search() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "find".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "search");
        assert_eq!(payload["input_normalization"]["applied"][0]["from"], "find");
        assert_eq!(payload["input_normalization"]["applied"][0]["to"], "search");
    }

    #[test]
    fn execute_call_alias_resolves_to_invoke() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "call".to_owned(),
            "github".to_owned(),
            "issues.create".to_owned(),
            "--input".to_owned(),
            "{}".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "invoke");
        assert_eq!(payload["input_normalization"]["applied"][0]["from"], "call");
    }

    #[test]
    fn execute_health_alias_resolves_to_status() {
        let args = vec!["fwc".to_owned(), "--json".to_owned(), "health".to_owned()];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "status");
    }

    #[test]
    fn execute_activate_alias_resolves_to_enable() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "activate".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "enable");
    }

    #[test]
    fn execute_upgrade_alias_resolves_to_update() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "upgrade".to_owned(),
            "slack".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "update");
    }

    #[test]
    fn execute_preview_alias_resolves_to_simulate() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "preview".to_owned(),
            "github".to_owned(),
            "issues.create".to_owned(),
            "--input".to_owned(),
            "{}".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "simulate");
    }

    #[test]
    fn execute_tail_alias_resolves_to_logs() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "tail".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "logs");
    }

    #[test]
    fn execute_cfg_alias_resolves_to_config() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "cfg".to_owned(),
            "schema".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "config");
    }

    // ── Intent recovery: typo auto-corrections (readonly) ───────────────

    #[test]
    fn execute_shwo_typo_resolves_to_show() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "shwo".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "show");
        assert_eq!(payload["input_normalization"]["applied"][0]["from"], "shwo");
        assert_eq!(payload["input_normalization"]["applied"][0]["to"], "show");
    }

    #[test]
    fn execute_lsit_typo_resolves_to_list() {
        let args = vec!["fwc".to_owned(), "--json".to_owned(), "lsit".to_owned()];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "list");
    }

    #[test]
    fn execute_schmea_typo_resolves_to_schema() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "schmea".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "schema");
    }

    #[test]
    fn execute_serach_typo_resolves_to_search() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "serach".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "search");
    }

    // ── Intent recovery: mutating typos are rejected ────────────────────

    #[test]
    fn execute_enbale_typo_is_rejected_as_ambiguous() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "enbale".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::AmbiguousCorrection.into());
        assert_eq!(payload["error"]["type"], "ambiguous-typo");
        assert!(
            payload["error"]["message"]
                .as_str()
                .unwrap()
                .contains("enable")
        );
    }

    #[test]
    fn execute_insatll_typo_is_rejected_as_ambiguous() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "insatll".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::AmbiguousCorrection.into());
        assert_eq!(payload["error"]["type"], "ambiguous-typo");
        assert!(
            payload["error"]["message"]
                .as_str()
                .unwrap()
                .contains("install")
        );
    }

    #[test]
    fn execute_invoe_typo_is_rejected_as_ambiguous() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "invoe".to_owned(),
            "github".to_owned(),
            "issues.create".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::AmbiguousCorrection.into());
        assert_eq!(payload["error"]["type"], "ambiguous-typo");
        assert!(
            payload["error"]["did_you_mean"][0]
                .as_str()
                .unwrap()
                .contains("invoke")
        );
    }

    // ── Intent recovery: dangerous shapes ───────────────────────────────

    #[test]
    fn execute_delete_shape_is_rejected() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "delete".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::AmbiguousCorrection.into());
        assert_eq!(payload["error"]["type"], "destructive-ambiguity");
        assert!(payload["error"]["recoverable"] == true);
    }

    #[test]
    fn execute_remove_shape_is_rejected() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "remove".to_owned(),
            "slack".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(payload["error"]["type"], "destructive-ambiguity");
    }

    #[test]
    fn execute_force_flag_is_rejected() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "--force".to_owned(),
            "invoke".to_owned(),
            "github".to_owned(),
            "issues.create".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(payload["error"]["type"], "unsupported-force-flag");
    }

    // ── Intent recovery: redundant prefix stripping ─────────────────────

    #[test]
    fn execute_fcp_prefix_stripped() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "fcp".to_owned(),
            "list".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "list");
    }

    #[test]
    fn execute_flywheel_prefix_stripped() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "flywheel".to_owned(),
            "show".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "show");
    }

    #[test]
    fn execute_service_prefix_stripped() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "service".to_owned(),
            "status".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "status");
    }

    #[test]
    fn execute_plugin_prefix_stripped() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "plugin".to_owned(),
            "ops".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "ops");
    }

    #[test]
    fn execute_list_returns_manifest_backed_inventory() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "list"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "list");
        assert_eq!(payload["source"], "workspace-manifests");
        assert!(
            payload["connectors"]
                .as_array()
                .is_some_and(|connectors| !connectors.is_empty())
        );
        assert!(
            payload["connectors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|connector| {
                    connector["slug"] == "github" && connector["canonical_id"] == "fcp.github"
                })
        );
    }

    #[test]
    fn execute_search_surfaces_github_issue_matches() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "search", "github issue"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "search");
        assert!(payload["results"].as_array().unwrap().iter().any(|result| {
            result["connector"] == "github" && result["operation"] == "github.create_issue"
        }));
    }

    #[test]
    fn execute_show_github_returns_manifest_detail() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "show", "github"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "show");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_eq!(payload["connector"]["slug"], "github");
        assert_eq!(payload["connector"]["canonical_id"], "fcp.github");
        assert_eq!(payload["connector"]["format"], "wasi");
        assert_eq!(payload["connector"]["state"], "unknown");
        assert_eq!(payload["zones"]["home"], "z:work");
        assert!(
            payload["operations"]["preview"]
                .as_array()
                .is_some_and(|preview| !preview.is_empty())
        );
    }

    #[test]
    fn execute_ops_filters_out_risky_operations() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "ops", "github", "--risk-at-most", "low"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "ops");
        assert_eq!(payload["connector"]["slug"], "github");
        assert!(
            payload["operations"]
                .as_array()
                .unwrap()
                .iter()
                .all(|operation| { operation["risk_level"] == "low" })
        );
        assert!(
            payload["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operation| { operation["canonical_id"] == "github.get_issue" })
        );
    }

    #[test]
    fn execute_schema_resolves_friendly_operation_selector() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "schema", "github", "issues.create"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "schema");
        assert_eq!(payload["scope"], "operation");
        assert_eq!(payload["operation"]["requested_selector"], "issues.create");
        assert_eq!(payload["operation"]["selector"], "issues.create");
        assert_eq!(payload["operation"]["canonical_id"], "github.create_issue");
        assert_eq!(
            payload["input_schema"]["properties"]["title"]["type"],
            "string"
        );
        assert_eq!(
            payload["guidance"]["when_to_use"],
            "Create a new issue in a GitHub repository."
        );
    }

    #[test]
    fn execute_examples_resolves_friendly_operation_selector() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "examples", "github", "issues.create"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "examples");
        assert_eq!(payload["scope"], "operation");
        assert_eq!(payload["operation"]["selector"], "issues.create");
        assert_eq!(payload["operation"]["canonical_id"], "github.create_issue");
        assert!(payload["examples"].as_array().is_some_and(|examples| {
            examples
                .first()
                .and_then(Value::as_str)
                .is_some_and(|example| example.contains("\"title\": \"Bug report\""))
        }));
    }

    // ── Intent recovery: config subcommand aliases ──────────────────────

    #[test]
    fn execute_config_validate_resolves_to_doctor() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "config".to_owned(),
            "validate".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "config");
        // The config subcommand is captured inside the serialized args
        assert_eq!(payload["captures"]["command"]["subcommand"], "doctor");
    }

    #[test]
    fn execute_config_show_resolves_to_get() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "config".to_owned(),
            "show".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "config");
        assert_eq!(payload["captures"]["command"]["subcommand"], "get");
    }

    #[test]
    fn execute_config_rm_resolves_to_unset() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "config".to_owned(),
            "rm".to_owned(),
            "github".to_owned(),
            "auth.token".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "config");
        assert_eq!(payload["captures"]["command"]["subcommand"], "unset");
    }

    // ── Intent recovery: task subcommand aliases ────────────────────────

    #[test]
    fn execute_task_view_resolves_to_show() {
        // First create a capsule
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "show github issues".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = payload["task"]["id"].as_str().unwrap().to_owned();

        // Then use "view" alias
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "view".to_owned(),
            task_id,
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let view_payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(view_payload["subcommand"], "show");
    }

    #[test]
    fn execute_task_ls_resolves_to_list() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "ls".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["subcommand"], "list");
    }

    #[test]
    fn execute_task_confirm_resolves_to_approve() {
        let create_args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "show github issues".to_owned(),
        ];
        let created = execute(&create_args).expect("task creation should succeed");
        let payload: Value =
            serde_json::from_str(&created.text).expect("json output should parse cleanly");
        let task_id = payload["task"]["id"].as_str().unwrap().to_owned();

        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "task".to_owned(),
            "confirm".to_owned(),
            task_id,
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let approve_payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(approve_payload["subcommand"], "approve");
    }

    // ── Intent recovery: combined corrections ───────────────────────────

    #[test]
    fn execute_connector_prefix_plus_alias_combined() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "connector".to_owned(),
            "info".to_owned(),
            "github".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "show");
        // Should have two corrections: prefix strip + alias canonicalization
        assert_eq!(
            payload["input_normalization"]["applied"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    // ── Intent recovery: all error payloads have required fields ────────

    #[test]
    fn error_payloads_always_have_structured_envelope() {
        let test_cases: Vec<Vec<String>> = vec![
            // delete shape
            vec!["fwc", "--json", "delete", "github"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            // force flag
            vec!["fwc", "--json", "--force", "list"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            // mutating typo
            vec!["fwc", "--json", "enbale", "github"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            // op show ambiguity
            vec!["fwc", "--json", "op", "show", "github"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ];

        for args in test_cases {
            let outcome = execute(&args).expect("execution should not fail internally");
            let payload: Value =
                serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

            assert_eq!(payload["status"], "error", "args={args:?}");
            assert!(
                payload["error"]["type"].is_string(),
                "missing error.type for args={args:?}"
            );
            assert!(
                payload["error"]["message"].is_string(),
                "missing error.message for args={args:?}"
            );
            assert!(
                payload["error"]["did_you_mean"].is_array(),
                "missing error.did_you_mean for args={args:?}"
            );
            assert!(
                payload["error"]["examples"].is_array(),
                "missing error.examples for args={args:?}"
            );
            assert!(
                payload["error"]["next_actions"].is_array(),
                "missing error.next_actions for args={args:?}"
            );
            assert!(
                payload["input"]["received"].is_array(),
                "missing input.received for args={args:?}"
            );
        }
    }

    // ── Intent recovery: exit code contract ─────────────────────────────

    #[test]
    fn exit_code_success_for_safe_alias() {
        let aliases = vec![
            vec!["fwc", "--json", "info", "github"],
            vec!["fwc", "--json", "find", "github"],
            vec!["fwc", "--json", "health"],
            vec!["fwc", "--json", "tail", "github"],
        ];
        for tokens in aliases {
            let args: Vec<String> = tokens.into_iter().map(str::to_owned).collect();
            let outcome = execute(&args).expect("execution should not fail internally");
            assert_eq!(
                outcome.exit_code,
                CliExitCode::Success.into(),
                "safe alias should succeed: {args:?}"
            );
        }
    }

    #[test]
    fn exit_code_success_for_safe_typo() {
        let typos = vec![
            vec!["fwc", "--json", "shwo", "github"],
            vec!["fwc", "--json", "lsit"],
            vec!["fwc", "--json", "gudie"],
        ];
        for tokens in typos {
            let args: Vec<String> = tokens.into_iter().map(str::to_owned).collect();
            let outcome = execute(&args).expect("execution should not fail internally");
            assert_eq!(
                outcome.exit_code,
                CliExitCode::Success.into(),
                "safe typo should succeed: {args:?}"
            );
        }
    }

    #[test]
    fn exit_code_ambiguous_for_mutating_typo() {
        let typos = vec![
            vec!["fwc", "--json", "enbale", "github"],
            vec!["fwc", "--json", "disabel", "slack"],
            vec!["fwc", "--json", "insatll", "github"],
            vec!["fwc", "--json", "invoe", "github", "issues.create"],
        ];
        for tokens in typos {
            let args: Vec<String> = tokens.into_iter().map(str::to_owned).collect();
            let outcome = execute(&args).expect("execution should not fail internally");
            assert_eq!(
                outcome.exit_code,
                CliExitCode::AmbiguousCorrection.into(),
                "mutating typo should use ambiguous exit code: {args:?}"
            );
        }
    }

    // ── Map (batch) integration tests ──────────────────────────────

    #[test]
    fn execute_map_inline_json_array() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"number":1},{"number":2},{"number":3}]"#,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "map");
        assert_eq!(payload["plan"]["operation"], "github.get_issue");
        assert_eq!(payload["plan"]["input_count"], 3);
        assert_eq!(payload["plan"]["concurrency"], 5);
        assert_eq!(payload["plan"]["on_error"], "abort");
        assert_eq!(
            payload["plan"]["preview_inputs"].as_array().unwrap().len(),
            3
        );
    }

    #[test]
    fn execute_map_on_error_continue() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "map",
            "slack.send_message",
            "--inputs",
            r#"[{"channel":"general","text":"hi"}]"#,
            "--on-error",
            "continue",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["plan"]["on_error"], "continue");
    }

    #[test]
    fn execute_map_custom_concurrency() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"n":1},{"n":2}]"#,
            "--concurrency",
            "10",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["plan"]["concurrency"], 10);
    }

    #[test]
    fn execute_map_no_inputs_error() {
        let args: Vec<String> = vec!["fwc", "--json", "map", "github.get_issue"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["error"]["type"], "missing-inputs");
    }

    #[test]
    fn execute_map_invalid_on_error() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"n":1}]"#,
            "--on-error",
            "panic",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let result = execute(&args);
        assert!(result.is_err());
    }

    #[test]
    fn execute_map_template_with_items() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "map",
            "github.get_issue",
            "--input-template",
            r#"{"owner":"octocat","repo":"hw","number":{{item}}}"#,
            "--items",
            "1,2,3",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["plan"]["input_count"], 3);
        assert_eq!(payload["plan"]["preview_inputs"][0]["number"], 1);
        assert_eq!(payload["plan"]["preview_inputs"][2]["number"], 3);
    }

    #[test]
    fn execute_map_preview_capped_at_three() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"n":1},{"n":2},{"n":3},{"n":4},{"n":5}]"#,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["plan"]["input_count"], 5);
        assert_eq!(
            payload["plan"]["preview_inputs"].as_array().unwrap().len(),
            3
        );
    }

    #[test]
    fn execute_map_batch_alias() {
        let args: Vec<String> = vec![
            "fwc",
            "--json",
            "batch",
            "github.get_issue",
            "--inputs",
            r#"[{"n":1}]"#,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "map");
    }

    #[test]
    fn execute_pipeline_validate_with_explicit_path() {
        let root = std::env::temp_dir().join(format!(
            "fwc-pipeline-validate-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notify.toml");
        std::fs::write(
            &path,
            r##"
[pipeline]
name = "notify-on-new-issues"

[[steps]]
id = "fetch"
operation = "github.search_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "New issues: {{steps.fetch.output.issues | length}}" }

[params.owner]
type = "string"
required = true

[params.repo]
type = "string"
required = true

[params.channel]
type = "string"
default = "#general"
"##,
        )
        .unwrap();

        let path_str = path.display().to_string();
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "pipeline", "validate", &path_str]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "pipeline");
        assert_eq!(payload["subcommand"], "validate");
        assert_eq!(payload["validation"]["valid"], true);
        assert_eq!(payload["validation"]["execution_order"][0], "fetch");
        assert_eq!(payload["validation"]["execution_order"][1], "notify");
    }

    #[test]
    fn execute_pipeline_dry_run_binds_params_and_defers_dynamic_templates() {
        let root = std::env::temp_dir().join(format!(
            "fwc-pipeline-dry-run-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notify.toml");
        std::fs::write(
            &path,
            r##"
[pipeline]
name = "notify-on-new-issues"

[[steps]]
id = "fetch"
operation = "github.search_issues"
input = { owner = "{{params.owner}}", repo = "{{params.repo}}" }

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
input = { channel = "{{params.channel}}", text = "New issues: {{steps.fetch.output.issues | length}}" }
condition = "{{steps.fetch.output.issues | length}} > 0"

[params.owner]
type = "string"
required = true

[params.repo]
type = "string"
required = true

[params.channel]
type = "string"
default = "#general"
"##,
        )
        .unwrap();

        let path_str = path.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "pipeline",
            "dry-run",
            &path_str,
            "--param",
            "owner=octocat",
            "--param",
            "repo=hello-world",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["plan"]["execution_order"][0], "fetch");
        assert_eq!(payload["plan"]["steps"][0]["input"]["owner"], "octocat");
        assert_eq!(payload["plan"]["steps"][0]["input"]["repo"], "hello-world");
        assert_eq!(payload["plan"]["steps"][1]["input"]["channel"], "#general");
        assert_eq!(
            payload["plan"]["steps"][1]["unresolved_templates"][0],
            "steps.fetch.output.issues | length"
        );
        assert_eq!(
            payload["plan"]["steps"][1]["condition"],
            "{{steps.fetch.output.issues | length}} > 0"
        );
        assert_eq!(payload["estimate"]["estimated_api_calls"]["min"], 1);
        assert_eq!(payload["estimate"]["estimated_api_calls"]["max"], 2);
        assert_eq!(payload["estimate"]["risk_assessment"]["level"], "medium");
        assert_eq!(
            payload["estimate"]["required_capabilities"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            payload["estimate"]["required_approvals"][0]["step_id"],
            "notify"
        );
    }

    #[test]
    fn execute_pipeline_estimate_returns_summary_without_plan() {
        let root = std::env::temp_dir().join(format!(
            "fwc-pipeline-estimate-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("notify.toml");
        std::fs::write(
            &path,
            r#"
[pipeline]
name = "notify-on-new-issues"

[[steps]]
id = "fetch"
operation = "github.search_issues"

[[steps]]
id = "notify"
operation = "slack.post_message"
depends_on = ["fetch"]
condition = "{{steps.fetch.output.issues | length}} > 0"
"#,
        )
        .unwrap();

        let path_str = path.display().to_string();
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "pipeline", "estimate", &path_str]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["subcommand"], "estimate");
        assert!(payload.get("plan").is_none());
        assert_eq!(payload["estimate"]["step_count"], 2);
        assert_eq!(
            payload["estimate"]["estimated_api_calls"]["summary"],
            "~1-2 API calls"
        );
    }

    #[test]
    fn execute_pipeline_dry_run_reports_unknown_operation_references() {
        let root = std::env::temp_dir().join(format!(
            "fwc-pipeline-missing-op-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("broken.toml");
        std::fs::write(
            &path,
            r#"
[pipeline]
name = "broken"

[[steps]]
id = "fetch"
operation = "github.not_a_real_operation"
"#,
        )
        .unwrap();

        let path_str = path.display().to_string();
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "pipeline", "dry-run", &path_str]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "pipeline-operation-not-found");
    }

    #[test]
    fn execute_pipeline_validate_reports_definition_errors() {
        let root = std::env::temp_dir().join(format!(
            "fwc-pipeline-invalid-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("broken.toml");
        std::fs::write(
            &path,
            r#"
[pipeline]
name = "broken"

[[steps]]
id = "fetch"
operation = "github.list_issues"
depends_on = ["missing"]
"#,
        )
        .unwrap();

        let path_str = path.display().to_string();
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "pipeline", "validate", &path_str]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "invalid-pipeline-definition");
        assert!(
            payload["error"]["details"]
                .as_array()
                .unwrap()
                .iter()
                .any(|detail| detail
                    .as_str()
                    .is_some_and(|text| text.contains("unknown step")))
        );
    }

    // ── BatchFile (heterogeneous batch) integration tests ──────────

    fn batch_test_file(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("fwc-batch-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(name);
        std::fs::write(&file, content).unwrap();
        file
    }

    #[test]
    fn execute_batch_file_valid() {
        let file = batch_test_file(
            "valid.jsonl",
            r#"{"id":"s1","connector":"github","operation":"list_issues","input":{"owner":"o","repo":"r"}}
{"id":"s2","connector":"slack","operation":"send_message","input":{"channel":"dev","text":"hi"},"depends_on":["s1"]}"#,
        );
        let args: Vec<String> = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "batch-file".to_owned(),
            file.display().to_string(),
        ];
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "batch-file");
        assert_eq!(payload["plan"]["total_operations"], 2);
        assert_eq!(payload["plan"]["waves"].as_array().unwrap().len(), 2);
        assert_eq!(payload["plan"]["connectors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn execute_batch_file_all_independent_single_wave() {
        let file = batch_test_file(
            "independent.jsonl",
            r#"{"id":"a","connector":"g","operation":"o","input":{}}
{"id":"b","connector":"g","operation":"o","input":{}}
{"id":"c","connector":"g","operation":"o","input":{}}"#,
        );
        let args: Vec<String> = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "batch-file".to_owned(),
            file.display().to_string(),
        ];
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["plan"]["waves"].as_array().unwrap().len(), 1);
        assert_eq!(payload["plan"]["total_operations"], 3);
    }

    #[test]
    fn execute_batch_file_custom_concurrency() {
        let file = batch_test_file(
            "concurrency.jsonl",
            r#"{"id":"a","connector":"g","operation":"o","input":{}}"#,
        );
        let args: Vec<String> = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "batch-file".to_owned(),
            file.display().to_string(),
            "--concurrency".to_owned(),
            "10".to_owned(),
        ];
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["plan"]["concurrency"], 10);
    }

    #[test]
    fn execute_batch_file_invalid_content() {
        let file = batch_test_file("invalid.jsonl", "not json");
        let args: Vec<String> = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "batch-file".to_owned(),
            file.display().to_string(),
        ];
        let result = execute(&args);
        assert!(result.is_err());
    }

    #[test]
    fn execute_batch_file_missing_file() {
        let args: Vec<String> = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "batch-file".to_owned(),
            "/nonexistent/ops.jsonl".to_owned(),
        ];
        let result = execute(&args);
        assert!(result.is_err());
    }

    #[test]
    fn execute_batch_ops_alias() {
        let file = batch_test_file(
            "alias.jsonl",
            r#"{"id":"a","connector":"g","operation":"o","input":{}}"#,
        );
        let args: Vec<String> = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "batch-ops".to_owned(),
            file.display().to_string(),
        ];
        let outcome = execute(&args).unwrap();
        let payload: Value = serde_json::from_str(&outcome.text).unwrap();
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "batch-file");
    }
}
