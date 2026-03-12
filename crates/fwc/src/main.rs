#![deny(unsafe_code)]

#[allow(dead_code)] // Multi-agent coordination wired when Agent Mail integration lands.
mod agent_coord;
#[allow(dead_code)] // Agent Mail multi-agent coordination.
mod agent_mail;
#[allow(dead_code)] // Audit types used by later CLI commands.
mod audit;
#[allow(dead_code)] // Legacy file-based audit-chain verify/timeline support.
mod audit_chain;
#[allow(dead_code)]
mod auth_status;
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
#[allow(dead_code)] // Error taxonomy wired when host-backed dispatch lands.
mod error_taxonomy;
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
mod manifest_cmd;
#[allow(dead_code)]
mod mcp_resources;
mod net_cmd;
#[allow(dead_code)]
mod op_lock;
mod package_cmd;
#[allow(dead_code)]
mod pipe;
#[allow(dead_code)] // Pipeline conditional branching and error handling.
mod pipeline_cond;
#[allow(dead_code)]
mod pipeline_recipes;
mod policy_cmd;
#[allow(dead_code, clippy::cast_precision_loss)]
mod rate_forecast;
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
#[allow(dead_code)] // Retry controller with exponential backoff and jitter.
mod retry_controller;
#[allow(dead_code)] // Smart connector auto-routing for ambiguous intents.
mod routing;
mod schema_nav;
mod search;
#[allow(dead_code)] // Secretless injection wired when egress proxy integration lands.
mod secretless;
#[allow(dead_code)] // MCP server module — data layer for `fwc serve-mcp`.
mod serve_mcp;
#[allow(dead_code)]
mod session;
mod supply_chain_cmd;
mod template;
#[allow(dead_code)] // Test observability contract: logging, artifact, redaction, and replay.
mod test_observability;
#[allow(dead_code)]
mod throttle;
mod trace_cmd;
#[allow(dead_code)] // Idempotent undo for reversible operations.
mod undo;
mod validate;
mod workflow;
#[allow(dead_code)]
mod zone_scope;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use reqwest::blocking::{Client as BlockingClient, ClientBuilder as BlockingClientBuilder};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use fcp_core::{
    AgentHint, ApprovalToken, CapabilityToken, CapabilityUsageKey, ConnectorId, InvokeRequest,
    InvokeResponse, InvokeStatus, LifecycleStatus, OperationId, OperationInfo, RequestId,
    SafetyTier, ZoneId,
};
use fcp_crypto::{canonicalize::to_deterministic_cbor, cose::CoseToken};
use fcp_host::{
    BatchInvokeResponse as HostBatchInvokeResponse, BatchOptions as HostBatchOptions,
    BudgetReportRequest as HostBudgetReportRequest,
    BudgetReportResponse as HostBudgetReportResponse, CancelReason,
    CancellationRequest as HostCancellationRequest,
    CancellationResponse as HostCancellationResponse, CleanupBehavior,
    ConnectorAdminStatus as HostConnectorAdminStatus,
    ConnectorInventoryMutationKind as HostConnectorInventoryMutationKind,
    ConnectorInventoryMutationRequest as HostConnectorInventoryMutationRequest,
    ConnectorInventoryMutationResponse as HostConnectorInventoryMutationResponse,
    ConnectorInventoryResponse as HostConnectorInventoryResponse,
    DiscoveryFilter as HostDiscoveryFilter, DiscoveryResponse as HostDiscoveryResponse,
    DoctorReport as HostDoctorReport, DoctorRequest as HostDoctorRequest, HostHealthResponse,
    HostPreflightRequest, IntrospectionResponse as HostIntrospectionResponse,
    ManagedConnectorConfig, PreflightResponse as HostPreflightResponse,
    ToolDescriptor as HostToolDescriptor,
};
use fcp_manifest::ConnectorManifest;
use fcp_telemetry::{
    CapabilityRecommendation, CapabilitySuggestionKind, CapabilityUsageAggregate,
    RecommendationConfig, recommend_capabilities,
};

use crate::package_cmd::{
    BuildMetadata as PackageBuildMetadata, PACKAGE_OUTPUT_FILENAME,
    PackageArgs as PackageBuildArgs, PackageOutput,
};
use crate::readiness::{
    CommandAvailability, CommandEnvelope, ConnectorDetail, ConnectorState, ConnectorSummary,
    DiscoveredConnector, DiscoveredOperation, DiscoveryCatalog, MetadataField, OperationSummary,
    RateLimitSummary, SelectorError, SelectorErrorKind, idempotency_label,
    normalize_connector_selector, normalize_operation_selector, risk_level_label,
    safety_tier_label, selector_distance,
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
  fwc session start --agent BronzeValley --goal \"triage issues\" --zone z:work
  fwc session show
  fwc session list --status active
  fwc agent announce --agent BronzeValley --connector github --purpose \"triage issue backlog\"
  fwc agent send --from BronzeValley --to GoldenWolf --kind info --payload '{\"bead\":\"flywheel_connectors-qnchs.13.3\"}'
  fwc agent inbox --agent GoldenWolf
  fwc list
  fwc plan \"create a GitHub issue titled 'FWC: add workflow macros'\"
  fwc explain \"find the Notion page named Roadmap and append this summary\"
  fwc do \"create a GitHub issue titled 'FWC: add workflow macros'\" --simulate
  fwc show github
  fwc show github --template '{{connector.slug}} => {{connector.name}}'
  fwc ops github
  fwc schema github issues.create
  fwc doctor --zone z:work --host http://127.0.0.1:8787
  fwc budget --host http://127.0.0.1:8787
  fwc capabilities report
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
  fwc export-tools --host http://127.0.0.1:8787 --format mcp --json
  fwc export-tools --offline --format claude github
  fwc export-tools --format openai --risk-max medium --output tools.json
  fwc serve-mcp --host http://127.0.0.1:8787 github --capability-token <token>
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

    /// Manage named host contexts stored in `~/.fcp/contexts.toml`.
    Context(ContextArgs),

    /// Create and resume durable workflow capsules for connector jobs.
    #[command(visible_alias = "tasks")]
    Task(TaskArgs),

    /// Track the current agent session and persist resumable context.
    Session(SessionArgs),

    /// Coordinate local multi-agent work through the fwc agent-mail hub.
    Agent(AgentArgs),

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

    /// Verify or summarize supply-chain evidence for a connector artifact.
    #[command(name = "supply-chain")]
    SupplyChain(supply_chain_cmd::SupplyChainArgs),

    /// Work with audit-chain artifacts and reports.
    Audit(audit_chain::AuditArgs),

    /// Validate and repair connector manifests.
    Manifest(manifest_cmd::ManifestArgs),

    /// Explain network egress allow and deny decisions for one manifest operation.
    Net(net_cmd::NetArgs),

    /// Replay captured trace artifacts deterministically.
    Trace(trace_cmd::TraceArgs),

    /// Diff, preview, and manage policy simulations and bundles.
    Policy(policy_cmd::PolicyArgs),

    /// Package a connector crate into a distributable artifact bundle.
    Package(package_cmd::PackageArgs),

    /// Diagnose live zone and connector health through `fcp-host`.
    Doctor(DoctorArgs),

    /// Report connector or fleet status.
    Status(StatusArgs),

    /// Report live usage-budget state through `fcp-host`.
    Budget(BudgetArgs),

    /// Report and recommend capability usage from real execution history.
    Capabilities(CapabilitiesArgs),

    /// Install a connector package.
    Install(InstallArgs),

    /// Update a connector package from a replacement source.
    Update(UpdateArgs),

    /// Pin a connector to a specific version or channel.
    Pin(PinArgs),

    /// Remove a connector pin.
    Unpin(TargetArgs),

    /// Manage canary rollout state and manual rollback.
    Rollout(RolloutArgs),

    /// Manage connector configuration with redaction-aware workflows.
    Config(ConfigArgs),

    /// Execute a connector operation.
    Invoke(InvokeArgs),

    /// Preflight or dry-run a connector operation.
    Simulate(InvokeArgs),

    /// Cancel an in-flight connector operation.
    Cancel(CancelArgs),

    /// Export tool schemas for AI agent runtimes (MCP, Claude, `OpenAI`).
    ///
    /// Generates tool definitions from connector introspection so every
    /// FCP connector becomes a tool in any agent runtime.
    #[command(visible_alias = "tools")]
    ExportTools(ExportToolsArgs),

    /// Serve discovered connectors as MCP tools over stdio JSON-RPC.
    #[command(name = "serve-mcp")]
    ServeMcp(ServeMcpArgs),

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
}

#[derive(Args, Debug, Serialize)]
struct GuideArgs {
    /// Narrow the guide to a specific top-level command.
    #[arg(long)]
    command: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct ContextArgs {
    #[command(subcommand)]
    command: ContextCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum ContextCommand {
    /// List configured contexts and show the active one.
    List,

    /// Show the current active context.
    Current,

    /// Switch the active context.
    Use(ContextNameArgs),

    /// Create a new context entry.
    Create(ContextCreateArgs),

    /// Delete a non-active context entry.
    Delete(ContextNameArgs),

    /// Rename an existing context entry.
    Rename(ContextRenameArgs),
}

#[derive(Args, Debug, Serialize)]
struct ContextNameArgs {
    /// Context name.
    name: String,
}

#[derive(Args, Debug, Serialize)]
struct ContextCreateArgs {
    /// Context name.
    name: String,

    /// Host endpoint or socket path (e.g. `unix:///tmp/fcp-dev.sock`, `tcp://127.0.0.1:9000`).
    #[arg(long)]
    endpoint: String,

    /// Default zone for this context.
    #[arg(long)]
    zone: Option<String>,

    /// Optional node identity key path.
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Make the new context active immediately.
    #[arg(long, default_value_t = false)]
    set_current: bool,
}

#[derive(Args, Debug, Serialize)]
struct ContextRenameArgs {
    /// Existing context name.
    old_name: String,

    /// New context name.
    new_name: String,
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

    /// Explicitly approve the compiled workflow so real mutating primitives may run.
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
struct SessionArgs {
    #[command(subcommand)]
    command: SessionCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum SessionCommand {
    /// Start a new active agent session.
    Start(SessionStartArgs),

    /// List recent agent sessions.
    List(SessionListArgs),

    /// Show one session, defaulting to the current active session.
    Show(SessionTargetArgs),

    /// End one session, defaulting to the current active session.
    End(SessionTargetArgs),

    /// Resume a paused or ended session.
    Resume(SessionTargetArgs),
}

#[derive(Args, Debug, Serialize)]
struct SessionStartArgs {
    /// Agent identity recorded in the session.
    #[arg(long)]
    agent: String,

    /// Short goal statement describing the session intent.
    #[arg(long)]
    goal: String,

    /// Optional zone binding for the session.
    #[arg(long)]
    zone: Option<String>,

    /// Initial session context entries as `key=value` pairs.
    #[arg(long = "context", value_name = "KEY=VALUE")]
    context: Vec<String>,
}

#[derive(Args, Debug, Serialize)]
struct SessionListArgs {
    /// Optional status filter: active, paused, or ended.
    #[arg(long)]
    status: Option<String>,

    /// Maximum number of sessions to return (0 = unlimited).
    #[arg(long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args, Debug, Serialize)]
struct SessionTargetArgs {
    /// Session id such as `s:deadbeef`.
    session_id: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum AgentCommand {
    /// List active announcements and reservations in the local coordination hub.
    List(AgentListArgs),

    /// Announce connector usage intent to other local agents.
    Announce(AgentAnnounceArgs),

    /// Reserve a connector resource for coordinated local work.
    Reserve(AgentReserveArgs),

    /// Send a message to another local agent inbox.
    Send(AgentSendArgs),

    /// Inspect or drain one local agent inbox.
    #[command(visible_alias = "recv")]
    Inbox(AgentInboxArgs),
}

#[derive(Args, Debug, Default, Serialize)]
struct AgentListArgs {
    /// Optional connector filter.
    #[arg(long)]
    connector: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct AgentAnnounceArgs {
    /// Agent identity announcing the work.
    #[arg(long)]
    agent: String,

    /// Connector being used.
    #[arg(long)]
    connector: String,

    /// Human-readable purpose for the work.
    #[arg(long)]
    purpose: String,

    /// Optional specific operation being targeted.
    #[arg(long)]
    operation: Option<String>,

    /// Expected announcement duration in seconds (0 = indefinite).
    #[arg(long, default_value_t = 0)]
    duration: u64,
}

#[derive(Args, Debug, Serialize)]
struct AgentReserveArgs {
    /// Agent identity requesting the reservation.
    #[arg(long)]
    agent: String,

    /// Connector being coordinated.
    #[arg(long)]
    connector: String,

    /// Resource identifier within the connector.
    #[arg(long)]
    resource: String,

    /// Reservation TTL in seconds.
    #[arg(long, default_value_t = 3600)]
    ttl: u64,

    /// Require exclusive access to the resource.
    #[arg(long, default_value_t = false)]
    exclusive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum AgentMessageKindArg {
    Request,
    Response,
    Info,
    Warning,
    Release,
}

#[derive(Args, Debug, Serialize)]
struct AgentSendArgs {
    /// Sender agent identity.
    #[arg(long)]
    from: String,

    /// Recipient agent identity.
    #[arg(long)]
    to: String,

    /// Message kind.
    #[arg(long, value_enum, default_value_t = AgentMessageKindArg::Info)]
    kind: AgentMessageKindArg,

    /// JSON payload or plain text payload.
    #[arg(long)]
    payload: String,
}

#[derive(Args, Debug, Serialize)]
struct AgentInboxArgs {
    /// Agent identity whose inbox should be inspected.
    #[arg(long)]
    agent: String,

    /// Drain the inbox instead of peeking non-destructively.
    #[arg(long, default_value_t = false)]
    drain: bool,
}

#[derive(Args, Debug, Serialize)]
struct ListArgs {
    /// Filter to a zone such as z:work or z:private.
    #[arg(long)]
    zone: Option<String>,

    /// Filter to a connector category such as messaging or analytics.
    #[arg(long)]
    category: Option<String>,

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
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

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
}

#[derive(Args, Debug, Serialize)]
struct ShowArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
}

#[derive(Args, Debug, Serialize)]
struct OpsArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Optional risk ceiling to hide more dangerous operations.
    #[arg(long)]
    risk_at_most: Option<String>,

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
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

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
}

#[derive(Args, Debug, Serialize)]
struct ExampleArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Optional operation name for an operation-specific example.
    operation: Option<String>,

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
}

#[derive(Args, Debug, Serialize)]
struct StatusArgs {
    /// Optional connector id. Omit for fleet status.
    connector: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct DoctorArgs {
    /// Zone to diagnose.
    #[arg(long, short = 'z')]
    zone: String,

    /// Connector ids, aliases, or family names to self-check.
    #[arg(long, value_name = "CONNECTOR")]
    connector: Vec<String>,

    /// Force connector self-check execution. Implied when `--connector` is present.
    #[arg(long, default_value_t = false)]
    self_check: bool,
}

#[derive(Args, Debug, Serialize)]
struct BudgetArgs {
    /// Optional zone filter. Omit for all configured zones.
    #[arg(long, short = 'z')]
    zone: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct CapabilitiesArgs {
    #[command(subcommand)]
    command: CapabilitiesCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum CapabilitiesCommand {
    /// Report capability usage grouped by zone and connector.
    Report(CapabilitiesFilterArgs),

    /// Suggest least-privilege capability grants based on execution history.
    Suggest(CapabilitiesSuggestArgs),

    /// Export raw capability usage aggregates.
    Export(CapabilitiesFilterArgs),
}

#[derive(Args, Debug, Serialize)]
struct CapabilitiesFilterArgs {
    /// Optional zone filter.
    #[arg(long, short = 'z')]
    zone: Option<String>,

    /// Optional connector filter.
    #[arg(long, short = 'c')]
    connector: Option<String>,
}

#[derive(Args, Debug, Serialize)]
struct CapabilitiesSuggestArgs {
    /// Optional zone filter.
    #[arg(long, short = 'z')]
    zone: Option<String>,

    /// Optional connector filter.
    #[arg(long, short = 'c')]
    connector: Option<String>,

    /// Restrict results to one recommendation kind.
    #[arg(long, value_enum, default_value_t = CapabilitySuggestionFilter::All)]
    filter: CapabilitySuggestionFilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum CapabilitySuggestionFilter {
    All,
    RemoveUnused,
    ReviewRisky,
    Keep,
}

impl CapabilitySuggestionFilter {
    const fn matches(self, suggestion: CapabilitySuggestionKind) -> bool {
        match self {
            Self::All => true,
            Self::RemoveUnused => matches!(suggestion, CapabilitySuggestionKind::RemoveUnused),
            Self::ReviewRisky => matches!(suggestion, CapabilitySuggestionKind::ReviewRisky),
            Self::Keep => matches!(suggestion, CapabilitySuggestionKind::Keep),
        }
    }
}

#[derive(Args, Debug, Serialize)]
struct TargetArgs {
    /// Connector id, alias, or family name.
    connector: String,
}

#[derive(Args, Debug, Serialize)]
struct RolloutArgs {
    #[command(subcommand)]
    command: RolloutCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum RolloutCommand {
    /// Set the canary percentage for a connector rollout.
    Set(RolloutSetArgs),

    /// Show current rollout state for a connector.
    Status(TargetArgs),

    /// Roll back a connector to a specific prior version.
    Rollback(RolloutRollbackArgs),
}

#[derive(Args, Debug, Serialize)]
struct RolloutSetArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Canary percentage from 0 to 100.
    #[arg(long)]
    canary: u8,
}

#[derive(Args, Debug, Serialize)]
struct RolloutRollbackArgs {
    /// Connector id, alias, or family name.
    connector: String,

    /// Version to roll back to.
    #[arg(long)]
    to: String,
}

#[derive(Args, Debug, Serialize)]
struct InstallArgs {
    /// Package source path, connector crate path, or workspace connector selector.
    source: String,

    /// Optional version to require from the resolved package artifact.
    #[arg(long)]
    version: Option<String>,

    /// Verify only and do not write the connector into the managed inventory.
    #[arg(long, default_value_t = false)]
    verify_only: bool,

    /// Connector configuration file consumed by `fcp-host`.
    #[arg(long, env = "FCP_HOST_CONNECTORS_FILE")]
    connectors_file: Option<PathBuf>,
}

#[derive(Args, Debug, Serialize)]
struct UpdateArgs {
    /// Installed connector id, alias, or family name.
    connector: String,

    /// Optional replacement package source path, connector crate path, or workspace connector selector.
    #[arg(long)]
    source: Option<String>,

    /// Explain the update plan without applying it.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Connector configuration file consumed by `fcp-host`.
    #[arg(long, env = "FCP_HOST_CONNECTORS_FILE")]
    connectors_file: Option<PathBuf>,
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
    /// Connector configuration file consumed by `fcp-host`.
    #[arg(long, env = "FCP_HOST_CONNECTORS_FILE")]
    connectors_file: Option<PathBuf>,

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

#[derive(Args, Debug, Clone, Default, Serialize)]
struct LiveAuthArgs {
    /// Capability token authorizing the live request. Accepts base64 CBOR or a JSON byte array/string.
    #[arg(long, value_name = "TOKEN")]
    #[serde(skip_serializing)]
    capability_token: Option<String>,

    /// Read the capability token from a file containing base64, JSON, or raw CBOR bytes.
    #[arg(long, value_name = "PATH")]
    capability_token_file: Option<PathBuf>,

    /// Approval token JSON payload. Repeat for multiple approvals.
    #[arg(long = "approval-token", value_name = "JSON")]
    #[serde(skip_serializing)]
    approval_token: Vec<String>,

    /// Read an approval token JSON payload from a file. Repeat for multiple approvals.
    #[arg(long = "approval-token-file", value_name = "PATH")]
    approval_token_file: Vec<PathBuf>,
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

    /// Set or override one payload field as `path=value`.
    #[arg(long = "set", value_name = "PATH=VALUE")]
    set: Vec<String>,

    /// Execution zone. Defaults to the active context zone or `z:work`.
    #[arg(long)]
    zone: Option<String>,

    /// Optional principal identity for preflight and invoke.
    #[arg(long)]
    principal: Option<String>,

    /// Optional idempotency key for retries or risky operations.
    #[arg(long)]
    idempotency_key: Option<String>,

    /// Optional deadline in milliseconds.
    #[arg(long)]
    deadline_ms: Option<u64>,

    #[command(flatten)]
    auth: LiveAuthArgs,
}

#[derive(Args, Debug, Serialize)]
struct CancelArgs {
    /// Operation id returned by a prior invoke or batch execution.
    operation_id: String,

    /// Cancellation reason kind.
    #[arg(long, default_value = "user-requested")]
    reason: String,

    /// Optional reason detail for `agent-abort`.
    #[arg(long)]
    detail: Option<String>,

    /// Remaining milliseconds before timeout when `--reason timeout-approaching` is used.
    #[arg(long)]
    remaining_ms: Option<u64>,

    /// Resource name when `--reason resource-limit` is used.
    #[arg(long)]
    resource: Option<String>,

    /// Current resource usage when `--reason resource-limit` is used.
    #[arg(long)]
    current: Option<u64>,

    /// Resource limit threshold when `--reason resource-limit` is used.
    #[arg(long)]
    limit: Option<u64>,

    /// Optional superseding operation id for `superseded`.
    #[arg(long)]
    superseded_by: Option<String>,

    /// Cleanup behavior: `best-effort`, `full`, `abandon`, or `checkpoint`.
    #[arg(long, default_value = "best-effort")]
    cleanup: String,

    /// Cleanup timeout in milliseconds when `--cleanup full` is used.
    #[arg(long)]
    cleanup_timeout_ms: Option<u64>,

    /// Return partial results if available.
    #[arg(long, default_value_t = false)]
    return_partial: bool,
}

#[derive(Args, Debug, Serialize)]
struct ExportToolsArgs {
    /// Tool schema format to export. `--format` after `export-tools` is normalized here.
    #[arg(long = "tool-format", value_enum)]
    tool_format: export_tools::ToolSchemaFormat,

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

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
}

#[derive(Args, Debug, Serialize)]
struct ServeMcpArgs {
    /// Optional connector selector. Omit to expose all discovered connectors.
    connector: Option<String>,

    /// Restrict tool exposure to connectors matching this zone.
    #[arg(long)]
    zone: Option<String>,

    /// Optional principal identity forwarded on each live tool call.
    #[arg(long)]
    principal: Option<String>,

    #[command(flatten)]
    auth: LiveAuthArgs,
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

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
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

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
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

    /// Read explicit offline workspace-manifest metadata instead of live host inventory.
    #[arg(long, default_value_t = false)]
    offline: bool,
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

    /// Execute each step in this zone.
    #[arg(long)]
    zone: Option<String>,

    #[command(flatten)]
    auth: LiveAuthArgs,
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

    /// Execute each step in this zone.
    #[arg(long)]
    zone: Option<String>,

    #[command(flatten)]
    auth: LiveAuthArgs,
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

    /// Execution zone for all mapped inputs. Defaults to the active context zone or `z:work`.
    #[arg(long)]
    zone: Option<String>,

    #[command(flatten)]
    auth: LiveAuthArgs,
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

    /// Default execution zone for operations that do not specify one in the JSONL file.
    #[arg(long)]
    zone: Option<String>,

    #[command(flatten)]
    auth: LiveAuthArgs,
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
            if let Some(outcome) = execute_passthrough_command(&prepared)? {
                return Ok(outcome);
            }
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

fn execute_passthrough_command(prepared: &PreparedCli) -> Result<Option<ExecutionOutcome>> {
    match &prepared.cli.command {
        Commands::ServeMcp(args) => execute_serve_mcp(prepared, args).map(Some),
        Commands::SupplyChain(args) => {
            supply_chain_cmd::run(args)?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        Commands::Audit(args) => {
            audit_chain::run(args.clone())?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        Commands::Manifest(args) => {
            manifest_cmd::run(args.clone())?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        Commands::Net(args) => {
            net_cmd::run(args.clone())?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        Commands::Trace(args) => {
            trace_cmd::run(args.clone())?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        Commands::Policy(args) => {
            policy_cmd::run(args)?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        Commands::Package(args) => {
            package_cmd::run(args)?;
            Ok(Some(ExecutionOutcome {
                text: String::new(),
                exit_code: ExitCode::SUCCESS,
            }))
        }
        _ => Ok(None),
    }
}

fn execute_serve_mcp(prepared: &PreparedCli, args: &ServeMcpArgs) -> Result<ExecutionOutcome> {
    let Some(resolved_host) = resolve_host_config(prepared.cli.host.as_deref())? else {
        return render_dispatch(
            missing_host_dispatch(
                "serve-mcp",
                json!({
                    "connector": args.connector,
                    "zone": args.zone,
                }),
                vec![
                    "fwc serve-mcp --host <endpoint>".to_owned(),
                    "Use `fwc export-tools --offline` if you only need offline tool definitions without live execution."
                        .to_owned(),
                ],
            ),
            prepared.format,
            prepared.cli.token_stats,
            &prepared.render_options,
        );
    };
    if let Err(error) = resolve_live_auth(&args.auth) {
        return render_dispatch(
            live_auth_dispatch(
                "serve-mcp",
                &error,
                &[
                    "Pass `--capability-token` or `--capability-token-file` so MCP tool calls can execute against the live host."
                        .to_owned(),
                    "Pass `--approval-token` or `--approval-token-file` as needed for risky or dangerous tools."
                        .to_owned(),
                ],
            ),
            prepared.format,
            prepared.cli.token_stats,
            &prepared.render_options,
        );
    }
    if let Some(zone) = args.zone.as_deref() {
        return render_dispatch(
            DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "serve-mcp",
                    "source": "host-admin-api",
                    "error": {
                        "type": "unsupported-live-zone-filter",
                        "message": format!(
                            "`fwc serve-mcp` cannot prove connector availability for zone `{zone}` because live host discovery does not expose per-zone inventory metadata."
                        ),
                        "recoverable": true,
                    },
                    "filters": {
                        "connector": args.connector,
                        "zone": zone,
                    },
                    "next_actions": [
                        "Retry without `--zone` so `fwc` can expose the live host inventory truthfully.".to_owned(),
                        "Use host contexts or explicit `fwc invoke/simulate --zone ...` commands when you need zone-scoped execution.".to_owned(),
                    ],
                }),
                exit_code: CliExitCode::Validation,
            },
            prepared.format,
            prepared.cli.token_stats,
            &prepared.render_options,
        );
    }
    let client = HostAdminClient::new(&resolved_host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let connectors = if let Some(selector) = &args.connector {
        let connector = match catalog.resolve_connector(selector) {
            Ok(connector) => connector,
            Err(error) => {
                return render_dispatch(
                    connector_resolution_dispatch("serve-mcp", selector, &error),
                    prepared.format,
                    prepared.cli.token_stats,
                    &prepared.render_options,
                );
            }
        };
        vec![connector.clone()]
    } else {
        catalog.connectors.clone()
    };

    let mut config = serve_mcp::McpServerConfig::new();
    if let Some(connector) = &args.connector {
        config = config.with_connector_filter(connector.clone());
    }

    let mut tools = Vec::new();
    for connector in &connectors {
        let introspection = client.introspect(connector.summary.id.as_str())?;
        tools.extend(host_mcp_tool_definitions(connector, &introspection));
    }

    let zone = args.zone.clone();
    let state = serve_mcp::state_from_tools(tools, config);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;

    runtime.block_on(async {
        let reader = tokio::io::BufReader::new(tokio::io::stdin());
        let writer = tokio::io::stdout();
        let host_context = resolved_host.clone();
        let principal = args.principal.clone();
        let auth = args.auth.clone();
        let zone = zone.clone();
        serve_mcp::run_stdio_transport(&state, reader, writer, move |tool, id, arguments| {
            mcp_tool_call_response(
                tool,
                id,
                &arguments,
                Some(&host_context),
                principal.as_deref(),
                zone.as_deref(),
                &auth,
            )
        })
        .await
    })?;

    Ok(ExecutionOutcome {
        text: String::new(),
        exit_code: ExitCode::SUCCESS,
    })
}

fn mcp_tool_call_response(
    tool: &serve_mcp::McpToolDefinition,
    id: Value,
    arguments: &Value,
    host: Option<&ResolvedHostConfig>,
    principal: Option<&str>,
    zone: Option<&str>,
    auth: &LiveAuthArgs,
) -> serve_mcp::JsonRpcResponse {
    let invoke_args = mcp_tool_invoke_args(tool, arguments, host, principal, zone, auth);

    match invoke_dispatch(
        "invoke",
        &invoke_args,
        host.map(|config| config.endpoint.as_str()),
    ) {
        Ok(dispatch) => {
            let mut structured_content = dispatch.payload;
            let message = structured_content["message"]
                .as_str()
                .unwrap_or("Tool call completed.")
                .to_owned();
            if let Some(object) = structured_content.as_object_mut() {
                object.insert(
                    "tool".to_owned(),
                    json!({
                        "name": &tool.name,
                        "connector": &tool.connector_id,
                        "operation": &tool.operation_id,
                    }),
                );
            }

            serve_mcp::JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": message,
                    }],
                    "structuredContent": structured_content,
                    "isError": !dispatch.exit_code.is_success(),
                }),
            )
        }
        Err(error) => serve_mcp::JsonRpcResponse::error(
            id,
            serve_mcp::JsonRpcError::internal(format!(
                "Failed to execute tool call `{}`: {error}",
                tool.name
            )),
        ),
    }
}

fn mcp_tool_invoke_args(
    tool: &serve_mcp::McpToolDefinition,
    arguments: &Value,
    host: Option<&ResolvedHostConfig>,
    principal: Option<&str>,
    zone: Option<&str>,
    auth: &LiveAuthArgs,
) -> InvokeArgs {
    InvokeArgs {
        connector: tool.connector_id.clone(),
        operation: tool.operation_id.clone(),
        input: Some(arguments.to_string()),
        file: None,
        stdin: false,
        set: Vec::new(),
        zone: zone
            .map(str::to_owned)
            .or_else(|| host.and_then(|config| config.default_zone.clone())),
        principal: principal.map(str::to_owned),
        idempotency_key: None,
        deadline_ms: None,
        auth: auth.clone(),
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
            let (exit_code, availability) = if payload["status"] == "unknown-command" {
                enrich_unknown_guide_command(&mut payload, args.command.as_deref());
                (
                    CliExitCode::UnknownCommand,
                    CommandAvailability::Unsupported,
                )
            } else {
                (CliExitCode::Success, CommandAvailability::OfflineArtifact)
            };
            let envelope = CommandEnvelope::new(availability, "guide");
            envelope.inject_into(&mut payload);
            DispatchOutcome { payload, exit_code }
        }
        Commands::Context(args) => context_dispatch(args)?,
        Commands::Task(args) => task_dispatch(args)?,
        Commands::Session(args) => session_dispatch(args)?,
        Commands::Agent(args) => agent_dispatch(args)?,
        Commands::Plan(args) => intent_plan_dispatch(&args.request(intent::IntentMode::Plan))?,
        Commands::Explain(args) => {
            intent_explain_dispatch(&args.request(intent::IntentMode::Explain))?
        }
        Commands::Do(args) => intent_do_dispatch(args)?,
        Commands::List(args) => list_dispatch(args, cli.host.as_deref())?,
        Commands::Search(args) => search_dispatch(args, cli.host.as_deref())?,
        Commands::Show(args) => show_dispatch(args, cli.host.as_deref())?,
        Commands::Ops(args) => ops_dispatch(args, cli.host.as_deref())?,
        Commands::Schema(args) => schema_dispatch(args, cli.host.as_deref())?,
        Commands::Examples(args) => examples_dispatch(args, cli.host.as_deref())?,
        Commands::SupplyChain(_) => passthrough_only_dispatch("supply-chain"),
        Commands::Audit(_) => passthrough_only_dispatch("audit"),
        Commands::Manifest(_) => passthrough_only_dispatch("manifest"),
        Commands::Net(_) => passthrough_only_dispatch("net"),
        Commands::Trace(_) => passthrough_only_dispatch("trace"),
        Commands::Policy(_) => passthrough_only_dispatch("policy"),
        Commands::Package(_) => passthrough_only_dispatch("package"),
        Commands::Doctor(args) => doctor_dispatch(args, cli.host.as_deref())?,
        Commands::Status(args) => status_dispatch(args, cli.host.as_deref())?,
        Commands::Budget(args) => budget_dispatch(args, cli.host.as_deref())?,
        Commands::Capabilities(args) => capabilities_dispatch(args, cli.host.as_deref())?,
        Commands::Install(args) => install_dispatch(args, cli.host.as_deref())?,
        Commands::Update(args) => update_dispatch(args, cli.host.as_deref())?,
        Commands::Pin(args) => pin_dispatch(args, cli.host.as_deref())?,
        Commands::Unpin(args) => unpin_dispatch(args, cli.host.as_deref())?,
        Commands::Rollout(args) => rollout_dispatch(args, cli.host.as_deref())?,
        Commands::Config(args) => config_dispatch(args)?,
        Commands::Invoke(args) => invoke_dispatch("invoke", args, cli.host.as_deref())?,
        Commands::Simulate(args) => invoke_dispatch("simulate", args, cli.host.as_deref())?,
        Commands::Cancel(args) => cancel_dispatch(args, cli.host.as_deref())?,
        Commands::ExportTools(args) => export_tools_dispatch(args, cli.host.as_deref())?,
        Commands::ServeMcp(args) => planned("serve-mcp", args)?,
        Commands::Suggest(args) => suggest_dispatch(args, cli.host.as_deref())?,
        Commands::Template(args) => template_dispatch(args, cli.host.as_deref())?,
        Commands::Validate(args) => validate_dispatch(args, cli.host.as_deref())?,
        Commands::History(args) => history_dispatch(args)?,
        Commands::Pipe(args) => pipe_dispatch(args)?,
        Commands::Pipeline(args) => pipeline_dispatch(args, cli.host.as_deref())?,
        Commands::Recipe(args) => recipe_dispatch(args, cli.host.as_deref())?,
        Commands::Map(args) => map_dispatch(args, cli.host.as_deref())?,
        Commands::BatchFile(args) => batch_file_dispatch(args, cli.host.as_deref())?,
    };

    Ok(outcome)
}

fn passthrough_only_dispatch(command: &str) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": command,
            "error": {
                "type": "passthrough-command-reached-structured-dispatch",
                "message": format!(
                    "`{command}` should have been executed through the direct passthrough path."
                ),
            },
        }),
        exit_code: CliExitCode::Internal,
    }
}

fn planned<T>(command: &str, args: &T) -> Result<DispatchOutcome>
where
    T: Serialize,
{
    let envelope = CommandEnvelope::new(CommandAvailability::Planned, command);
    let mut payload = catalog::planned_payload(command, &serde_json::to_value(args)?);
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[derive(Clone, Debug)]
struct ResolvedHostConfig {
    endpoint: String,
    default_zone: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ContextConfigFile {
    current_context: String,
    contexts: BTreeMap<String, MeshContextFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MeshContextFile {
    endpoint: String,
    #[serde(default)]
    default_zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_identity: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    config_overrides: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HostPinState {
    connector_id: String,
    pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<semver::Version>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HostRolloutStatus {
    #[serde(flatten)]
    status: LifecycleStatus,
    pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pinned_version: Option<semver::Version>,
    canary_percent: u8,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct HostRollbackResponse {
    connector_id: String,
    state: fcp_core::LifecycleState,
    from_version: semver::Version,
    to_version: semver::Version,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
struct HostRolloutScheduleRequest {
    connector_id: String,
    version: semver::Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_version: Option<semver::Version>,
    policy: fcp_core::RolloutPolicy,
}

#[derive(Clone, Debug, Serialize)]
struct HostBatchInvokeRequest {
    operations: Vec<HostBatchOperation>,
    options: HostBatchOptions,
}

#[derive(Clone, Debug, Serialize)]
struct HostBatchOperation {
    id: String,
    request: InvokeRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
}

fn resolve_host_config(explicit_host: Option<&str>) -> Result<Option<ResolvedHostConfig>> {
    if let Some(host) = explicit_host.map(str::trim).filter(|host| !host.is_empty()) {
        return Ok(Some(ResolvedHostConfig {
            endpoint: host.to_owned(),
            default_zone: None,
        }));
    }

    for env_name in ["FWC_HOST", "FCP_HOST_ENDPOINT", "FCP_HOST_BIND"] {
        if let Ok(endpoint) = std::env::var(env_name)
            && !endpoint.trim().is_empty()
        {
            return Ok(Some(ResolvedHostConfig {
                endpoint,
                default_zone: None,
            }));
        }
    }

    let Some(path) = context_config_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read host context file `{}`", path.display()))?;
    let config: ContextConfigFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse host context file `{}`", path.display()))?;
    let Some(context) = config.contexts.get(&config.current_context) else {
        return Ok(None);
    };
    if context.endpoint.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(ResolvedHostConfig {
        endpoint: context.endpoint.clone(),
        default_zone: context.default_zone.clone(),
    }))
}

fn context_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("FCP_CONFIG_DIR")
        && !dir.trim().is_empty()
    {
        return Some(PathBuf::from(dir).join("contexts.toml"));
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    home.map(|home| PathBuf::from(home).join(".fcp").join("contexts.toml"))
}

fn default_context_config() -> ContextConfigFile {
    let mut contexts = BTreeMap::new();
    contexts.insert(
        "local".to_owned(),
        MeshContextFile {
            endpoint: "unix:///tmp/fcp-dev.sock".to_owned(),
            default_zone: Some(ZoneId::work().to_string()),
            node_identity: None,
            config_overrides: BTreeMap::new(),
        },
    );
    ContextConfigFile {
        current_context: "local".to_owned(),
        contexts,
    }
}

fn required_context_config_path() -> Result<PathBuf> {
    context_config_path().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot determine the FCP context config path. Set `HOME`, `USERPROFILE`, or `FCP_CONFIG_DIR`."
        )
    })
}

fn load_context_config() -> Result<(PathBuf, ContextConfigFile)> {
    let path = required_context_config_path()?;
    if !path.exists() {
        return Ok((path, default_context_config()));
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read host context file `{}`", path.display()))?;
    let config: ContextConfigFile = toml::from_str(&raw)
        .with_context(|| format!("failed to parse host context file `{}`", path.display()))?;
    Ok((path, config))
}

fn save_context_config(path: &PathBuf, config: &ContextConfigFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create the parent directory for `{}`",
                path.display()
            )
        })?;
    }
    let raw = toml::to_string_pretty(config)?;
    std::fs::write(path, raw)
        .with_context(|| format!("failed to write host context file `{}`", path.display()))
}

fn resolved_zone(explicit_zone: Option<&str>, host: &ResolvedHostConfig) -> String {
    explicit_zone
        .map(str::trim)
        .filter(|zone| !zone.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| host.default_zone.clone())
        .unwrap_or_else(|| ZoneId::work().to_string())
}

#[derive(Debug)]
struct HostAdminClient {
    client: BlockingClient,
    base_url: String,
}

#[derive(Clone, Debug)]
struct HostConnectorRecord {
    slug: String,
    aliases: Vec<String>,
    summary: fcp_host::ConnectorSummary,
}

#[derive(Clone, Debug)]
struct HostConnectorCatalog {
    connectors: Vec<HostConnectorRecord>,
}

impl HostAdminClient {
    fn new(endpoint: &str) -> Result<Self> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            bail!("`--host` cannot be empty");
        }

        #[cfg(unix)]
        {
            if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
                let socket_path = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
                let client = BlockingClientBuilder::new()
                    .unix_socket(socket_path)
                    .build()
                    .with_context(|| {
                        format!(
                            "failed to build Unix-socket client for host endpoint `{socket_path}`"
                        )
                    })?;
                return Ok(Self {
                    client,
                    base_url: "http://localhost".to_owned(),
                });
            }
        }

        let normalized_endpoint =
            if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
                endpoint.to_owned()
            } else {
                let stripped = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);
                format!("http://{stripped}")
            };

        let client = BlockingClientBuilder::new()
            .build()
            .context("failed to build HTTP host client")?;
        Ok(Self {
            client,
            base_url: normalized_endpoint.trim_end_matches('/').to_owned(),
        })
    }

    fn catalog(
        &self,
        filter: Option<&HostDiscoveryFilter>,
    ) -> Result<(HostConnectorCatalog, HostDiscoveryResponse)> {
        let response = self.discover(filter)?;
        Ok((HostConnectorCatalog::from_response(&response), response))
    }

    fn discover(&self, filter: Option<&HostDiscoveryFilter>) -> Result<HostDiscoveryResponse> {
        self.post_json("/rpc/discover", &json!({ "filter": filter }))
    }

    fn connector(&self, connector_id: &str) -> Result<HostConnectorInventoryResponse> {
        self.get_json(&format!("/rpc/connectors/{connector_id}"))
    }

    fn introspect(&self, connector_id: &str) -> Result<HostIntrospectionResponse> {
        self.get_json(&format!("/rpc/introspect/{connector_id}"))
    }

    fn doctor(&self, request: &HostDoctorRequest) -> Result<HostDoctorReport> {
        self.post_json("/doctor", request)
    }

    fn health(&self) -> Result<HostHealthResponse> {
        self.get_json("/rpc/health")
    }

    fn connector_status(&self, connector_id: &str) -> Result<HostConnectorAdminStatus> {
        self.get_json(&format!("/rpc/connectors/{connector_id}/status"))
    }

    fn preflight(&self, request: &HostPreflightRequest) -> Result<HostPreflightResponse> {
        self.post_json("/rpc/preflight", request)
    }

    fn budget_report(&self, request: &HostBudgetReportRequest) -> Result<HostBudgetReportResponse> {
        self.post_json("/rpc/budget/report", request)
    }

    fn mutate_inventory(
        &self,
        request: &HostConnectorInventoryMutationRequest,
    ) -> Result<HostConnectorInventoryMutationResponse> {
        self.post_json("/rpc/connectors/apply", request)
    }

    fn invoke(&self, request: &InvokeRequest) -> Result<InvokeResponse> {
        self.post_json("/rpc/invoke", request)
    }

    fn cancel(&self, request: &HostCancellationRequest) -> Result<HostCancellationResponse> {
        self.post_json("/rpc/cancel", request)
    }

    fn batch(&self, request: &HostBatchInvokeRequest) -> Result<HostBatchInvokeResponse> {
        self.post_json("/rpc/batch", request)
    }

    fn pin(&self, connector_id: &str, version: &semver::Version) -> Result<HostPinState> {
        self.put_json(
            &format!("/rpc/rollout/pin/{connector_id}"),
            &json!({ "version": version }),
        )
    }

    fn unpin(&self, connector_id: &str) -> Result<HostPinState> {
        self.delete_json(&format!("/rpc/rollout/pin/{connector_id}"))
    }

    fn pin_status(&self, connector_id: &str) -> Result<HostPinState> {
        self.get_json(&format!("/rpc/rollout/pin/{connector_id}"))
    }

    fn rollout_status(&self, connector_id: &str) -> Result<HostRolloutStatus> {
        self.get_json(&format!("/rpc/rollout/{connector_id}"))
    }

    fn schedule_rollout(
        &self,
        request: &HostRolloutScheduleRequest,
    ) -> Result<fcp_host::RolloutOutcome> {
        self.post_json("/rpc/rollout/schedule", request)
    }

    #[allow(dead_code)]
    fn rollback(
        &self,
        connector_id: &str,
        to_version: &semver::Version,
    ) -> Result<HostRollbackResponse> {
        self.post_json(
            "/rpc/rollout/rollback",
            &json!({
                "connector_id": connector_id,
                "to_version": to_version,
            }),
        )
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .with_context(|| format!("GET {path} from host admin API failed"))?;
        Self::decode_response(response, "GET", path)
    }

    fn post_json<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .with_context(|| format!("POST {path} to host admin API failed"))?;
        Self::decode_response(response, "POST", path)
    }

    fn put_json<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let response = self
            .client
            .put(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .with_context(|| format!("PUT {path} to host admin API failed"))?;
        Self::decode_response(response, "PUT", path)
    }

    fn delete_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .client
            .delete(format!("{}{}", self.base_url, path))
            .send()
            .with_context(|| format!("DELETE {path} to host admin API failed"))?;
        Self::decode_response(response, "DELETE", path)
    }

    fn decode_response<T: DeserializeOwned>(
        response: reqwest::blocking::Response,
        method: &str,
        path: &str,
    ) -> Result<T> {
        let status = response.status();
        let body = response
            .text()
            .with_context(|| format!("{method} {path} returned an unreadable response body"))?;
        if !status.is_success() {
            bail!(
                "{method} {path} returned {}: {}",
                status,
                if body.trim().is_empty() {
                    "<empty body>"
                } else {
                    body.trim()
                }
            );
        }
        serde_json::from_str(&body)
            .with_context(|| format!("{method} {path} returned invalid JSON"))
    }
}

impl HostConnectorCatalog {
    fn from_response(response: &HostDiscoveryResponse) -> Self {
        let connectors = response
            .connectors
            .iter()
            .cloned()
            .map(|summary| HostConnectorRecord {
                slug: host_connector_slug(&summary),
                aliases: host_connector_aliases(&summary),
                summary,
            })
            .collect();
        Self { connectors }
    }

    fn resolve_connector(&self, selector: &str) -> Result<&HostConnectorRecord, SelectorError> {
        let normalized = normalize_connector_selector(selector);
        let exact = self
            .connectors
            .iter()
            .filter(|connector| connector.aliases.iter().any(|alias| alias == &normalized))
            .collect::<Vec<_>>();

        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        if exact.len() > 1 {
            return Err(SelectorError::ambiguous(
                selector,
                exact
                    .iter()
                    .map(|connector| connector.slug.clone())
                    .collect(),
            ));
        }

        let prefix = self
            .connectors
            .iter()
            .filter(|connector| {
                connector
                    .aliases
                    .iter()
                    .any(|alias| alias.starts_with(&normalized))
            })
            .collect::<Vec<_>>();

        match prefix.as_slice() {
            [connector] => Ok(*connector),
            [] => Err(SelectorError::not_found(
                selector,
                suggest_host_connector_slugs(&self.connectors, &normalized),
            )),
            _ => Err(SelectorError::ambiguous(
                selector,
                prefix
                    .iter()
                    .map(|connector| connector.slug.clone())
                    .collect(),
            )),
        }
    }
}

fn host_connector_slug(summary: &fcp_host::ConnectorSummary) -> String {
    let raw = summary.id.as_str().to_ascii_lowercase();
    raw.strip_prefix("fcp.")
        .unwrap_or(&raw)
        .split(':')
        .next()
        .unwrap_or(raw.as_str())
        .replace('_', "-")
}

fn host_connector_aliases(summary: &fcp_host::ConnectorSummary) -> Vec<String> {
    let raw = summary.id.as_str();
    let mut aliases = BTreeSet::from([normalize_connector_selector(raw)]);

    if let Some(stripped) = raw.strip_prefix("fcp.") {
        aliases.insert(normalize_connector_selector(stripped));
    }
    if let Some((head, _)) = raw.split_once(':') {
        aliases.insert(normalize_connector_selector(head));
        if let Some(stripped) = head.strip_prefix("fcp.") {
            aliases.insert(normalize_connector_selector(stripped));
        }
    }
    if !summary.name.is_empty() {
        aliases.insert(normalize_connector_selector(&summary.name));
    }

    aliases.into_iter().collect()
}

fn suggest_host_connector_slugs(connectors: &[HostConnectorRecord], selector: &str) -> Vec<String> {
    let mut candidates = connectors
        .iter()
        .map(|connector| {
            let distance = selector_distance(selector, &connector.slug);
            (connector.slug.clone(), distance)
        })
        .filter(|(slug, distance)| slug.starts_with(selector) || *distance <= 4)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    candidates
        .into_iter()
        .map(|(slug, _)| slug)
        .take(5)
        .collect()
}

fn resolve_host_tool<'a>(
    tools: &'a [HostToolDescriptor],
    selector: &str,
) -> Result<&'a HostToolDescriptor, SelectorError> {
    let normalized = normalize_operation_selector(selector);
    let exact = tools
        .iter()
        .filter(|tool| {
            host_tool_aliases(tool)
                .iter()
                .any(|alias| alias == &normalized)
        })
        .collect::<Vec<_>>();

    if exact.len() == 1 {
        return Ok(exact[0]);
    }
    if exact.len() > 1 {
        return Err(SelectorError::ambiguous(
            selector,
            exact.iter().map(|tool| tool.name.clone()).collect(),
        ));
    }

    let prefix = tools
        .iter()
        .filter(|tool| {
            host_tool_aliases(tool)
                .iter()
                .any(|alias| alias.starts_with(&normalized))
        })
        .collect::<Vec<_>>();

    match prefix.as_slice() {
        [tool] => Ok(*tool),
        [] => Err(SelectorError::not_found(
            selector,
            suggest_host_tool_names(tools, &normalized),
        )),
        _ => Err(SelectorError::ambiguous(
            selector,
            prefix.iter().map(|tool| tool.name.clone()).collect(),
        )),
    }
}

fn host_tool_aliases(tool: &HostToolDescriptor) -> Vec<String> {
    let mut aliases = BTreeSet::from([normalize_operation_selector(&tool.name)]);
    if let Some(local_id) = tool.name.rsplit('.').next() {
        aliases.insert(normalize_operation_selector(local_id));
        aliases.extend(host_transposed_aliases(local_id));
    }
    aliases.into_iter().collect()
}

fn host_transposed_aliases(local_id: &str) -> BTreeSet<String> {
    let mut parts = local_id.split('_');
    let Some(verb) = parts.next() else {
        return BTreeSet::new();
    };
    let resource_parts = parts.collect::<Vec<_>>();
    if resource_parts.is_empty() {
        return BTreeSet::new();
    }

    let resource = resource_parts.join("_");
    host_resource_selector_forms(&resource)
        .into_iter()
        .map(|resource_form| normalize_operation_selector(&format!("{resource_form}.{verb}")))
        .collect()
}

fn host_resource_selector_forms(resource: &str) -> BTreeSet<String> {
    let mut forms = BTreeSet::from([resource.to_owned()]);
    if resource.ends_with('s') {
        let singular = resource.trim_end_matches('s');
        if !singular.is_empty() {
            forms.insert(singular.to_owned());
        }
    } else {
        forms.insert(format!("{resource}s"));
    }
    forms
}

fn suggest_host_tool_names(tools: &[HostToolDescriptor], selector: &str) -> Vec<String> {
    let mut candidates = tools
        .iter()
        .map(|tool| {
            let distance = selector_distance(selector, &tool.name);
            (tool.name.clone(), distance)
        })
        .filter(|(name, distance)| name.starts_with(selector) || *distance <= 6)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    candidates
        .into_iter()
        .map(|(name, _)| name)
        .take(5)
        .collect()
}

fn host_filter_gaps(zone: Option<&str>) -> Vec<Value> {
    let mut gaps = Vec::new();
    if let Some(zone) = zone {
        gaps.push(json!({
            "field": "filters.zone",
            "status": "unavailable",
            "message": format!(
                "Host discovery does not currently expose supported-zone metadata, so the requested zone filter `{zone}` was not applied."
            ),
        }));
    }
    gaps
}

fn host_metadata_gaps(introspection: &HostIntrospectionResponse) -> Vec<Value> {
    let mut gaps = Vec::new();
    if introspection.rate_limits.is_none() {
        gaps.push(json!({
            "field": "rate_limits",
            "status": "missing",
            "message": "Host introspection did not include rate-limit declarations for this connector.",
        }));
    }
    if introspection
        .tools
        .iter()
        .any(|tool| tool.ai_hints.is_none())
    {
        gaps.push(json!({
            "field": "tools[].ai_hints",
            "status": "partial",
            "message": "One or more operations are missing AI hints, so CLI guidance is incomplete.",
        }));
    }
    if introspection
        .tools
        .iter()
        .all(|tool| tool.examples.is_empty())
    {
        gaps.push(json!({
            "field": "tools[].examples",
            "status": "missing",
            "message": "No operation examples were exposed by host introspection.",
        }));
    }
    gaps
}

#[allow(clippy::missing_const_for_fn)]
fn host_connector_state_label(health: &fcp_core::ConnectorHealth) -> &'static str {
    if health.is_healthy() {
        "ready"
    } else if health.is_available() {
        "degraded"
    } else {
        "error"
    }
}

fn human_window_duration(window: std::time::Duration) -> String {
    let window_ms = window.as_millis();
    if let Ok(window_ms) = u64::try_from(window_ms) {
        match window_ms {
            1_000 => "1s".to_owned(),
            60_000 => "60s".to_owned(),
            3_600_000 => "1h".to_owned(),
            86_400_000 => "1d".to_owned(),
            _ if window_ms % 1_000 == 0 => format!("{}s", window_ms / 1_000),
            _ => format!("{window_ms}ms"),
        }
    } else {
        format!("{window_ms}ms")
    }
}

fn host_rate_limit_summaries(
    declarations: &fcp_core::RateLimitDeclarations,
    pool_ids: impl IntoIterator<Item = String>,
) -> Vec<RateLimitSummary> {
    let mut seen = BTreeSet::new();
    let mut summaries = Vec::new();

    for pool_id in pool_ids {
        if !seen.insert(pool_id.clone()) {
            continue;
        }
        let Some(pool) = declarations.limits.iter().find(|pool| pool.id == pool_id) else {
            continue;
        };
        summaries.push(RateLimitSummary {
            scope: pool.id.clone(),
            requests: pool.config.requests,
            window: human_window_duration(pool.config.window),
        });
    }

    summaries
}

fn host_connector_archetypes(
    introspection: &HostIntrospectionResponse,
) -> MetadataField<Vec<String>> {
    match introspection.archetype {
        fcp_host::ConnectorArchetype::Unknown => MetadataField::Unknown,
        archetype => serde_json::to_value(archetype)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .map_or(MetadataField::Unknown, |label| {
                MetadataField::Known(vec![label])
            }),
    }
}

fn host_connector_rate_limits(
    introspection: &HostIntrospectionResponse,
) -> MetadataField<Vec<RateLimitSummary>> {
    match introspection.rate_limits.as_ref() {
        Some(declarations) => MetadataField::Known(host_rate_limit_summaries(
            declarations,
            declarations.limits.iter().map(|pool| pool.id.clone()),
        )),
        None => MetadataField::Unknown,
    }
}

fn host_operation_rate_limits(
    tool: &HostToolDescriptor,
    declarations: Option<&fcp_core::RateLimitDeclarations>,
) -> Option<Vec<RateLimitSummary>> {
    declarations.map(|declarations| {
        let declared_pool_ids = declarations
            .tool_pool_map
            .get(&tool.name)
            .into_iter()
            .flatten()
            .cloned();
        let inline_pool_ids = tool.rate_limits.iter().cloned();

        host_rate_limit_summaries(declarations, declared_pool_ids.chain(inline_pool_ids))
    })
}

fn host_tool_summary_entry(tool: &HostToolDescriptor) -> Value {
    json!({
        "selector": &tool.name,
        "canonical_id": &tool.name,
        "local_id": tool.name.rsplit('.').next().unwrap_or(tool.name.as_str()),
        "aliases": host_tool_aliases(tool),
        "summary": &tool.description,
        "capability": tool.capability.as_str(),
        "risk_level": risk_level_label(tool.risk_level),
        "safety_tier": safety_tier_label(tool.safety_tier),
        "idempotency": idempotency_label(tool.idempotency),
        "requires_approval": tool.approval_mode.is_some(),
        "supports_simulate": tool.supports_simulate,
        "example_count": tool.examples.len(),
        "rate_limits": tool.rate_limits.clone(),
    })
}

fn host_connector_list_entry(connector: &HostConnectorRecord) -> Value {
    json!({
        "slug": &connector.slug,
        "canonical_id": connector.summary.id.as_str(),
        "name": &connector.summary.name,
        "description": &connector.summary.description,
        "version": connector.summary.version.to_string(),
        "cohort": Value::Null,
        "categories": connector.summary.categories.clone(),
        "format": Value::Null,
        "state": host_connector_state_label(&connector.summary.health),
        "home_zone": Value::Null,
        "archetypes": Value::Null,
        "operation_count": connector.summary.tool_count,
        "max_risk": safety_tier_label(connector.summary.max_safety_tier),
        "has_events": Value::Null,
        "next_actions": [
            format!("fwc show {}", connector.slug),
            format!("fwc ops {}", connector.slug),
        ],
    })
}

fn host_tool_example_strings(tool: &HostToolDescriptor) -> Vec<String> {
    tool.examples
        .iter()
        .filter_map(|example| serde_json::to_string(&example.input).ok())
        .collect()
}

fn host_tool_when_to_use(tool: &HostToolDescriptor) -> String {
    tool.ai_hints
        .as_ref()
        .map(|hints| hints.when_to_use.trim())
        .filter(|when_to_use| !when_to_use.is_empty())
        .map_or_else(
            || "Host introspection did not include `when_to_use` guidance.".to_owned(),
            std::borrow::ToOwned::to_owned,
        )
}

fn host_tool_common_mistakes(tool: &HostToolDescriptor) -> Vec<String> {
    tool.ai_hints
        .as_ref()
        .map_or_else(Vec::new, |hints| hints.common_mistakes.clone())
}

fn host_tool_related(tool: &HostToolDescriptor) -> Vec<String> {
    tool.ai_hints.as_ref().map_or_else(Vec::new, |hints| {
        hints.related.iter().map(ToString::to_string).collect()
    })
}

const fn host_approval_mode_label(mode: fcp_core::ApprovalMode) -> &'static str {
    match mode {
        fcp_core::ApprovalMode::None => "none",
        fcp_core::ApprovalMode::Policy => "policy",
        fcp_core::ApprovalMode::Interactive => "interactive",
        fcp_core::ApprovalMode::ElevationToken => "elevation_token",
    }
}

fn host_tool_agent_hints(tool: &HostToolDescriptor) -> AgentHint {
    let mut hints = tool.ai_hints.clone().unwrap_or_default();
    let mut seen_examples = hints.examples.iter().cloned().collect::<BTreeSet<_>>();
    for example in host_tool_example_strings(tool) {
        if seen_examples.insert(example.clone()) {
            hints.examples.push(example);
        }
    }
    hints
}

fn host_tool_operation_info(tool: &HostToolDescriptor) -> OperationInfo {
    let summary = if tool.description.trim().is_empty() {
        tool.name.clone()
    } else {
        tool.description.clone()
    };
    OperationInfo {
        id: OperationId::new(tool.name.clone())
            .expect("host introspection should only surface canonical operation ids"),
        summary: summary.clone(),
        description: Some(tool.description.clone())
            .filter(|description| !description.trim().is_empty() && description != &summary),
        input_schema: tool.input_schema.clone(),
        output_schema: tool.output_schema.clone(),
        capability: tool.capability.clone(),
        risk_level: tool.risk_level,
        safety_tier: tool.safety_tier,
        idempotency: tool.idempotency,
        ai_hints: host_tool_agent_hints(tool),
        rate_limit: None,
        requires_approval: tool.approval_mode,
    }
}

fn host_tool_passes_risk_filter(tool: &HostToolDescriptor, risk_max: Option<&str>) -> bool {
    let Some(limit) = risk_max else {
        return true;
    };
    risk_rank(risk_level_label(tool.risk_level)) <= risk_rank(limit)
}

fn host_tool_passes_capability_filter(tool: &HostToolDescriptor, capability: Option<&str>) -> bool {
    let Some(filter) = capability else {
        return true;
    };
    tool.capability.as_str().starts_with(filter)
}

fn host_mcp_tool_definitions(
    connector: &HostConnectorRecord,
    introspection: &HostIntrospectionResponse,
) -> Vec<serve_mcp::McpToolDefinition> {
    let options = export_tools::ExportOptions::default();
    introspection
        .tools
        .iter()
        .map(|tool| {
            let exported =
                export_tools::to_mcp_tool_info(&host_tool_operation_info(tool), &options);
            serve_mcp::McpToolDefinition::new(
                exported.name,
                exported.description,
                exported.input_schema,
                connector.slug.clone(),
                tool.name.clone(),
            )
        })
        .collect()
}

fn host_discovered_operation(
    tool: &HostToolDescriptor,
    connector_rate_limits: Option<&fcp_core::RateLimitDeclarations>,
) -> DiscoveredOperation {
    let local_id = tool.name.rsplit('.').next().unwrap_or(tool.name.as_str());
    let summary = if tool.description.trim().is_empty() {
        tool.name.clone()
    } else {
        tool.description.clone()
    };

    DiscoveredOperation {
        actual_id: tool.name.clone(),
        local_id: local_id.to_owned(),
        preferred_selector: tool.name.clone(),
        aliases: host_tool_aliases(tool),
        description: summary.clone(),
        summary: OperationSummary {
            id: tool.name.clone(),
            summary,
            capability: tool.capability.to_string(),
            risk_level: risk_level_label(tool.risk_level).to_owned(),
            safety_tier: safety_tier_label(tool.safety_tier).to_owned(),
            idempotency: idempotency_label(tool.idempotency).to_owned(),
            requires_approval: tool.approval_mode.is_some(),
            supports_simulate: tool.supports_simulate,
        },
        input_schema: tool.input_schema.clone(),
        output_schema: tool.output_schema.clone(),
        approval_mode: tool.approval_mode.map_or_else(
            || "none".to_owned(),
            |mode| host_approval_mode_label(mode).to_owned(),
        ),
        when_to_use: host_tool_when_to_use(tool),
        common_mistakes: host_tool_common_mistakes(tool),
        examples: host_tool_example_strings(tool),
        related: host_tool_related(tool),
        network_constraints: None,
        rate_limits: host_operation_rate_limits(tool, connector_rate_limits),
    }
}

fn host_discovered_connector(
    connector: &HostConnectorRecord,
    introspection: &HostIntrospectionResponse,
) -> DiscoveredConnector {
    let mut operations = introspection
        .tools
        .iter()
        .map(|tool| host_discovered_operation(tool, introspection.rate_limits.as_ref()))
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| left.preferred_selector.cmp(&right.preferred_selector));

    let max_risk = operations
        .iter()
        .map(|operation| operation.summary.risk_level.as_str())
        .max_by_key(|risk| risk_rank(risk))
        .unwrap_or("low")
        .to_owned();
    let has_events = introspection.introspection.event_caps.is_some()
        || !introspection.introspection.events.is_empty();
    let archetypes = host_connector_archetypes(introspection);
    let categories = connector.summary.categories.clone();
    let slug = connector.slug.clone();

    DiscoveredConnector {
        slug,
        manifest_path: String::new(),
        cohort: categories
            .first()
            .cloned()
            .unwrap_or_else(|| "other".to_owned()),
        runtime_format: "host-admin-api".to_owned(),
        state_model: MetadataField::Unknown,
        supported_zones: Vec::new(),
        detail: ConnectorDetail {
            summary: ConnectorSummary {
                id: connector.summary.id.as_str().to_owned(),
                name: connector.summary.name.clone(),
                version: connector.summary.version.to_string(),
                description: connector.summary.description.clone().unwrap_or_else(|| {
                    "Host discovery did not include a connector description.".to_owned()
                }),
                archetypes,
                state: ConnectorState::Unknown,
                operation_count: operations.len(),
                max_risk,
                has_events,
            },
            operations: operations
                .iter()
                .map(|operation| operation.summary.clone())
                .collect(),
            config_schema: MetadataField::Unknown,
            health: MetadataField::Unknown,
            rate_limits: host_connector_rate_limits(introspection),
        },
        zones: Value::Null,
        capabilities: Value::Null,
        connector_schema: Value::Null,
        operations,
    }
}

fn load_live_discovered_connectors(
    client: &HostAdminClient,
    catalog: &HostConnectorCatalog,
) -> Result<(Vec<DiscoveredConnector>, Vec<Value>)> {
    let mut connectors = Vec::with_capacity(catalog.connectors.len());
    let mut metadata_gaps = Vec::new();

    for connector in &catalog.connectors {
        let introspection = client.introspect(connector.summary.id.as_str())?;
        metadata_gaps.extend(host_metadata_gaps(&introspection).into_iter().map(|gap| {
            json!({
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.summary.id.as_str(),
                    "name": &connector.summary.name,
                },
                "gap": gap,
            })
        }));
        connectors.push(host_discovered_connector(connector, &introspection));
    }

    Ok((connectors, metadata_gaps))
}

fn host_connector_schema_glossary(
    connector: &HostConnectorInventoryResponse,
    introspection: &HostIntrospectionResponse,
    metadata_gaps: &[Value],
) -> Value {
    json!({
        "connector_inventory_fields": [
            { "field": "connector.id", "type": "connector-id", "description": "Canonical connector identifier exposed by `fcp-host`." },
            { "field": "connector.name", "type": "string", "description": "Human-readable connector name." },
            { "field": "connector.description", "type": "string|null", "description": "Operator-facing connector summary." },
            { "field": "connector.version", "type": "semver", "description": "Installed connector version." },
            { "field": "connector.categories", "type": "string[]", "description": "Host-side grouping categories for discovery filters." },
            { "field": "connector.tool_count", "type": "u32", "description": "Number of operation descriptors currently exposed by the connector." },
            { "field": "connector.max_safety_tier", "type": "safety-tier", "description": "Highest safety tier across the connector's operation set." },
            { "field": "connector.enabled", "type": "bool", "description": "Whether the connector is enabled for execution." },
            { "field": "connector.health", "type": "connector-health", "description": "Current merged runtime health reported by the host." },
            { "field": "connector.last_health_check", "type": "timestamp|null", "description": "Timestamp of the most recent health observation." }
        ],
        "tool_descriptor_fields": [
            { "field": "tools[].name", "type": "string", "description": "Stable operation selector used by `fwc ops/schema/examples`." },
            { "field": "tools[].description", "type": "string", "description": "One-line operation summary." },
            { "field": "tools[].input_schema", "type": "json-schema", "description": "Machine-readable input schema for invoke/simulate payloads." },
            { "field": "tools[].output_schema", "type": "json-schema", "description": "Machine-readable output schema returned by the connector." },
            { "field": "tools[].capability", "type": "capability-id", "description": "Capability requirement that the host enforces before execution." },
            { "field": "tools[].risk_level", "type": "risk-level", "description": "Operator-facing risk label for the operation." },
            { "field": "tools[].safety_tier", "type": "safety-tier", "description": "Safety tier surfaced to agents and policy UX." },
            { "field": "tools[].idempotency", "type": "idempotency-class", "description": "Retry semantics for the operation." },
            { "field": "tools[].approval_mode", "type": "approval-mode|null", "description": "Approval requirement when the host requires explicit authorization." },
            { "field": "tools[].supports_simulate", "type": "bool", "description": "Whether the operation supports host-backed simulate flows." },
            { "field": "tools[].rate_limits", "type": "string[]", "description": "Rate-limit pools attached to the operation descriptor." },
            { "field": "tools[].examples", "type": "tool-example[]", "description": "Example inputs surfaced for `fwc examples`." },
            { "field": "tools[].ai_hints", "type": "agent-hint|null", "description": "Agent guidance including when-to-use, mistakes, and related operations." }
        ],
        "introspection_fields": [
            { "field": "archetype", "type": "connector-archetype", "description": "Primary archetype classification chosen by the host." },
            { "field": "rate_limits", "type": "rate-limit-declarations|null", "description": "Connector-wide rate-limit declarations returned by host introspection." },
            { "field": "introspection.events", "type": "event-descriptor[]", "description": "Declared event surfaces from connector introspection." },
            { "field": "introspection.resource_types", "type": "string[]", "description": "Named resource families exposed by the connector." },
            { "field": "introspection.auth_caps", "type": "auth-descriptor|null", "description": "Authentication capability metadata surfaced by the connector." },
            { "field": "introspection.event_caps", "type": "event-caps|null", "description": "Streaming/replay capabilities surfaced by the connector." }
        ],
        "sample": {
            "connector": &connector.connector,
            "archetype": introspection.archetype,
            "rate_limits": &introspection.rate_limits,
            "introspection": &introspection.introspection,
        },
        "metadata_gaps": metadata_gaps,
    })
}

fn host_operation_resolution_dispatch(
    command: &str,
    connector_slug: &str,
    selector: &str,
    error: &SelectorError,
) -> DispatchOutcome {
    let error_type = match error.kind {
        SelectorErrorKind::NotFound => "operation-not-found",
        SelectorErrorKind::Ambiguous => "ambiguous-operation",
    };
    let message = match error.kind {
        SelectorErrorKind::NotFound => {
            format!("`{selector}` did not match any operation exposed by `{connector_slug}`.")
        }
        SelectorErrorKind::Ambiguous => format!(
            "`{selector}` matches multiple operations on `{connector_slug}`; choose one explicit selector."
        ),
    };
    let mut examples = if error.suggestions.is_empty() {
        vec![format!("fwc ops {connector_slug}")]
    } else {
        error
            .suggestions
            .iter()
            .map(|suggestion| format!("fwc {command} {connector_slug} {suggestion}"))
            .collect::<Vec<_>>()
    };
    examples.push(format!("fwc ops {connector_slug}"));

    discovery_error(
        command,
        error_type,
        message,
        selector,
        &error.suggestions,
        &examples,
    )
}

fn discovery_mode_label(source: &catalog::DiscoveryDataSource) -> &'static str {
    match source {
        catalog::DiscoveryDataSource::LiveHostInventory => "live-inventory",
        catalog::DiscoveryDataSource::LiveHostIntrospection => "live-introspection",
        catalog::DiscoveryDataSource::WorkspaceManifest
        | catalog::DiscoveryDataSource::LocalCatalogCache
        | catalog::DiscoveryDataSource::StaticSchema => "offline-artifact",
    }
}

fn attach_discovery_provenance(
    payload: &mut Value,
    command: &str,
    source: catalog::DiscoveryDataSource,
) {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "mode".to_owned(),
            Value::String(discovery_mode_label(&source).to_owned()),
        );
        obj.insert(
            "provenance".to_owned(),
            serde_json::to_value(catalog::discovery_provenance(command, source))
                .unwrap_or(Value::Null),
        );
    }
}

fn template_mode_label(source: &catalog::TemplateDataSource) -> &'static str {
    match source {
        catalog::TemplateDataSource::LiveHostIntrospection => "live-introspection",
        catalog::TemplateDataSource::WorkspaceManifest
        | catalog::TemplateDataSource::StaticSchema => "offline-artifact",
        catalog::TemplateDataSource::Unknown => "unknown",
    }
}

fn attach_template_provenance(
    payload: &mut Value,
    command: &str,
    source: catalog::TemplateDataSource,
) {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "mode".to_owned(),
            Value::String(template_mode_label(&source).to_owned()),
        );
        obj.insert(
            "provenance".to_owned(),
            serde_json::to_value(catalog::template_provenance(command, source))
                .unwrap_or(Value::Null),
        );
    }
}

fn list_dispatch_host(args: &ListArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let filter = HostDiscoveryFilter {
        category: args.category.clone(),
        ..HostDiscoveryFilter::default()
    };
    let (catalog, response) = client.catalog(Some(&filter))?;
    let filter_gaps = host_filter_gaps(args.zone.as_deref());
    let connectors = catalog
        .connectors
        .iter()
        .map(host_connector_list_entry)
        .collect::<Vec<_>>();

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "list");
    let mut payload = json!({
        "status": "ok",
        "command": "list",
        "source": "host-admin-api",
        "message": format!("Listed {} connectors from `fcp-host` discovery.", connectors.len()),
        "filters": {
            "zone": args.zone.clone(),
            "category": args.category.clone(),
        },
        "filter_gaps": filter_gaps,
        "registry_version": response.registry_version,
        "cache": response.cache,
        "connectors": connectors,
        "next_actions": [
            "Use `fwc show <connector> --host <endpoint>` to inspect one connector in detail.",
            "Use `fwc ops <connector> --host <endpoint>` to enumerate host-backed operations.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "list",
        catalog::DiscoveryDataSource::LiveHostInventory,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn show_dispatch_host(args: &ShowArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
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
    let inventory = client.connector(connector.summary.id.as_str())?;
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let preview = introspection
        .tools
        .iter()
        .take(8)
        .map(host_tool_summary_entry)
        .collect::<Vec<_>>();
    let preview_truncated = introspection.tools.len() > preview.len();
    let risky_count = introspection
        .tools
        .iter()
        .filter(|tool| {
            matches!(
                safety_tier_label(tool.safety_tier),
                "risky" | "dangerous" | "critical"
            )
        })
        .count();
    let example_operation = introspection
        .tools
        .first()
        .map_or_else(|| "<operation>".to_owned(), |tool| tool.name.clone());
    let metadata_gaps = host_metadata_gaps(&introspection);

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "show");
    let mut payload = json!({
        "status": "ok",
        "command": "show",
        "source": "host-admin-api",
        "message": "Loaded connector detail from `fcp-host` inventory and introspection.",
        "connector": {
            "slug": &connector.slug,
            "canonical_id": inventory.connector.id.as_str(),
            "name": &inventory.connector.name,
            "version": inventory.connector.version.to_string(),
            "description": &inventory.connector.description,
            "cohort": Value::Null,
            "categories": &inventory.connector.categories,
            "format": Value::Null,
            "state": host_connector_state_label(&inventory.connector.health),
            "enabled": inventory.connector.enabled,
            "health": &inventory.connector.health,
            "last_health_check": inventory.connector.last_health_check,
            "archetype": introspection.archetype,
            "operation_count": introspection.tools.len(),
            "max_risk": safety_tier_label(inventory.connector.max_safety_tier),
            "has_events": introspection.introspection.event_caps.is_some() || !introspection.introspection.events.is_empty(),
            "manifest_path": Value::Null,
        },
        "rate_limits": introspection.rate_limits,
        "metadata_gaps": metadata_gaps,
        "operations": {
            "preview": preview,
            "preview_truncated": preview_truncated,
            "risky_count": risky_count,
            "safe_count": introspection.tools.len().saturating_sub(risky_count),
        },
        "next_actions": [
            format!("fwc ops {} --host {host}", connector.slug),
            format!("fwc schema {} {} --host {host}", connector.slug, example_operation),
            format!("fwc examples {} {} --host {host}", connector.slug, example_operation),
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "show",
        catalog::DiscoveryDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn ops_dispatch_host(args: &OpsArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
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
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let operations = introspection
        .tools
        .iter()
        .filter(|tool| {
            args.risk_at_most.as_deref().is_none_or(|limit| {
                risk_rank(risk_level_label(tool.risk_level)) <= risk_rank(limit)
            })
        })
        .map(host_tool_summary_entry)
        .collect::<Vec<_>>();

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "ops");
    let mut payload = json!({
        "status": "ok",
        "command": "ops",
        "source": "host-admin-api",
        "message": format!("Listed {} operations for `{}` from host introspection.", operations.len(), connector.slug),
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
            "name": &connector.summary.name,
        },
        "filters": {
            "risk_at_most": args.risk_at_most.clone(),
        },
        "metadata_gaps": host_metadata_gaps(&introspection),
        "operations": operations,
        "next_actions": [
            format!("fwc schema {} <operation> --host {host}", connector.slug),
            format!("fwc examples {} <operation> --host {host}", connector.slug),
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "ops",
        catalog::DiscoveryDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(clippy::too_many_lines)]
fn schema_dispatch_host(args: &SchemaArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
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
    let inventory = client.connector(connector.summary.id.as_str())?;
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let metadata_gaps = host_metadata_gaps(&introspection);

    if let Some(operation_selector) = args.operation.as_deref() {
        let operation = match resolve_host_tool(&introspection.tools, operation_selector) {
            Ok(operation) => operation,
            Err(error) => {
                return Ok(host_operation_resolution_dispatch(
                    "schema",
                    &connector.slug,
                    operation_selector,
                    &error,
                ));
            }
        };

        if args.scaffold {
            let scaffold = schema_nav::scaffold_template(&operation.input_schema);
            let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "schema");
            let mut payload = json!({
                "status": "ok",
                "command": "schema",
                "source": "host-admin-api",
                "scope": "scaffold",
                "connector": { "slug": &connector.slug },
                "operation": { "selector": &operation.name },
                "scaffold": scaffold,
            });
            attach_discovery_provenance(
                &mut payload,
                "schema",
                catalog::DiscoveryDataSource::LiveHostIntrospection,
            );
            envelope.inject_into(&mut payload);
            return Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            });
        }

        let example_strs = if args.examples {
            host_tool_example_strings(operation)
        } else {
            Vec::new()
        };
        let mut fields = schema_nav::walk_schema(&operation.input_schema, &example_strs);
        if args.required_only {
            fields.retain(|field| field.required);
        }
        if let Some(ref field_path) = args.field {
            fields = schema_nav::filter_by_field(&fields, field_path);
        }

        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "schema");
        let mut payload = json!({
            "status": "ok",
            "command": "schema",
            "source": "host-admin-api",
            "scope": "operation",
            "message": "Loaded operation schemas from `fcp-host` introspection.",
            "connector": {
                "slug": &connector.slug,
                "canonical_id": connector.summary.id.as_str(),
                "name": &connector.summary.name,
            },
            "operation": {
                "requested_selector": operation_selector,
                "selector": &operation.name,
                "canonical_id": &operation.name,
                "aliases": host_tool_aliases(operation),
                "summary": &operation.description,
                "capability": operation.capability.as_str(),
                "risk_level": risk_level_label(operation.risk_level),
                "safety_tier": safety_tier_label(operation.safety_tier),
                "idempotency": idempotency_label(operation.idempotency),
                "approval_mode": &operation.approval_mode,
                "supports_simulate": operation.supports_simulate,
            },
            "input_schema": &operation.input_schema,
            "output_schema": &operation.output_schema,
            "fields": fields,
            "guidance": {
                "when_to_use": host_tool_when_to_use(operation),
                "common_mistakes": host_tool_common_mistakes(operation),
                "related": host_tool_related(operation),
            },
            "metadata_gaps": metadata_gaps,
            "next_actions": [
                format!("fwc examples {} {} --host {host}", connector.slug, operation.name),
                format!("fwc schema {} {} --required-only --host {host}", connector.slug, operation.name),
                format!("fwc schema {} {} --scaffold --host {host}", connector.slug, operation.name),
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "schema",
            catalog::DiscoveryDataSource::LiveHostIntrospection,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "schema");
    let mut payload = json!({
        "status": "ok",
        "command": "schema",
        "source": "host-admin-api",
        "scope": "connector",
        "message": "Loaded the connector inventory/introspection field glossary from `fcp-host`.",
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
            "name": &connector.summary.name,
        },
        "schema": host_connector_schema_glossary(&inventory, &introspection, &metadata_gaps),
        "next_actions": [
            format!("fwc ops {} --host {host}", connector.slug),
            format!("fwc schema {} <operation> --host {host}", connector.slug),
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "schema",
        catalog::DiscoveryDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(clippy::too_many_lines)]
fn examples_dispatch_host(args: &ExampleArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
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
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let metadata_gaps = host_metadata_gaps(&introspection);

    if let Some(operation_selector) = args.operation.as_deref() {
        let operation = match resolve_host_tool(&introspection.tools, operation_selector) {
            Ok(operation) => operation,
            Err(error) => {
                return Ok(host_operation_resolution_dispatch(
                    "examples",
                    &connector.slug,
                    operation_selector,
                    &error,
                ));
            }
        };

        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "examples");
        let mut payload = json!({
            "status": "ok",
            "command": "examples",
            "source": "host-admin-api",
            "scope": "operation",
            "message": "Loaded operation examples from `fcp-host` introspection.",
            "connector": {
                "slug": &connector.slug,
                "canonical_id": connector.summary.id.as_str(),
                "name": &connector.summary.name,
            },
            "operation": {
                "requested_selector": operation_selector,
                "selector": &operation.name,
                "canonical_id": &operation.name,
                "aliases": host_tool_aliases(operation),
                "when_to_use": host_tool_when_to_use(operation),
            },
            "examples": operation.examples.iter().map(|example| {
                json!({
                    "description": &example.description,
                    "input": &example.input,
                    "output": &example.output,
                })
            }).collect::<Vec<_>>(),
            "common_mistakes": host_tool_common_mistakes(operation),
            "metadata_gaps": metadata_gaps,
            "next_actions": [
                format!("fwc schema {} {} --host {host}", connector.slug, operation.name),
                format!("fwc simulate {} {} --file payload.json", connector.slug, operation.name),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "examples",
            catalog::TemplateDataSource::LiveHostIntrospection,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let operation_examples = introspection
        .tools
        .iter()
        .filter(|tool| !tool.examples.is_empty())
        .take(3)
        .map(|tool| {
            json!({
                "selector": &tool.name,
                "canonical_id": &tool.name,
                "when_to_use": host_tool_when_to_use(tool),
                "example": tool
                    .examples
                    .first()
                    .map_or(Value::Null, |example| example.input.clone()),
            })
        })
        .collect::<Vec<_>>();

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "examples");
    let mut payload = json!({
        "status": "ok",
        "command": "examples",
        "source": "host-admin-api",
        "scope": "connector",
        "message": "Loaded connector-level examples and suggested follow-up commands from `fcp-host`.",
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
            "name": &connector.summary.name,
        },
        "examples": {
            "commands": [
                format!("fwc show {} --host {host}", connector.slug),
                format!("fwc ops {} --host {host}", connector.slug),
                format!("fwc schema {} <operation> --host {host}", connector.slug),
            ],
            "operations": operation_examples,
        },
        "metadata_gaps": metadata_gaps,
        "next_actions": [
            format!("fwc ops {} --host {host}", connector.slug),
            format!("fwc schema {} <operation> --host {host}", connector.slug),
        ],
    });
    attach_template_provenance(
        &mut payload,
        "examples",
        catalog::TemplateDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn list_dispatch(args: &ListArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("list"));
        }
    } else if let Some(host) = resolved_host {
        return list_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "list",
            json!({
                "filters": {
                    "zone": args.zone,
                    "category": args.category,
                },
            }),
            vec![
                "fwc list --host <endpoint>".to_owned(),
                "fwc list --offline".to_owned(),
            ],
        ));
    }

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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "list");
    let mut payload = json!({
        "status": "ok",
        "command": "list",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": format!("Listed {} connectors from workspace manifests.", connectors.len()),
        "filters": filters,
        "connectors": connectors,
        "next_actions": [
            "Use `fwc show <connector> --offline` to inspect one connector in detail.",
            "Use `fwc ops <connector> --offline` to enumerate operations before asking for schemas.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "list",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(clippy::too_many_lines)]
fn context_dispatch(args: &ContextArgs) -> Result<DispatchOutcome> {
    match &args.command {
        ContextCommand::List => {
            let (path, config) = load_context_config()?;
            let contexts = config
                .contexts
                .iter()
                .map(|(name, context)| {
                    json!({
                        "name": name,
                        "active": *name == config.current_context,
                        "endpoint": &context.endpoint,
                        "default_zone": &context.default_zone,
                        "node_identity": context.node_identity.as_ref().map(|path| path.display().to_string()),
                        "config_overrides": &context.config_overrides,
                    })
                })
                .collect::<Vec<_>>();

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "context");
            let mut payload = json!({
                "status": "ok",
                "command": "context",
                "subcommand": "list",
                "config_path": path.display().to_string(),
                "current_context": &config.current_context,
                "contexts": contexts,
                "next_actions": [
                    "fwc context current".to_owned(),
                    "fwc context use <name>".to_owned(),
                    "fwc context create <name> --endpoint <endpoint>".to_owned(),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ContextCommand::Current => {
            let (path, config) = load_context_config()?;
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "context");
            let mut payload = json!({
                "status": "ok",
                "command": "context",
                "subcommand": "current",
                "config_path": path.display().to_string(),
                "current_context": &config.current_context,
                "context": config.contexts.get(&config.current_context).map_or(Value::Null, |context| json!({
                    "name": &config.current_context,
                    "endpoint": &context.endpoint,
                    "default_zone": &context.default_zone,
                    "node_identity": context.node_identity.as_ref().map(|path| path.display().to_string()),
                    "config_overrides": &context.config_overrides,
                })),
                "next_actions": [
                    "fwc context list".to_owned(),
                    "fwc list".to_owned(),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ContextCommand::Use(args) => {
            let (path, mut config) = load_context_config()?;
            if !config.contexts.contains_key(&args.name) {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "context",
                        "subcommand": "use",
                        "error": {
                            "type": "context-not-found",
                            "message": format!("`{}` is not a configured context.", args.name),
                            "recoverable": true,
                        },
                        "available_contexts": config.contexts.keys().collect::<Vec<_>>(),
                        "next_actions": [
                            "fwc context list".to_owned(),
                            format!("fwc context create {} --endpoint <endpoint>", args.name),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
            config.current_context.clone_from(&args.name);
            save_context_config(&path, &config)?;
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "context");
            let mut payload = json!({
                "status": "ok",
                "command": "context",
                "subcommand": "use",
                "message": format!("Switched the active context to `{}`.", args.name),
                "config_path": path.display().to_string(),
                "current_context": &config.current_context,
                "next_actions": [
                    "fwc context current".to_owned(),
                    "fwc list".to_owned(),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ContextCommand::Create(args) => {
            let (path, mut config) = load_context_config()?;
            if config.contexts.contains_key(&args.name) {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "context",
                        "subcommand": "create",
                        "error": {
                            "type": "context-already-exists",
                            "message": format!("`{}` already exists.", args.name),
                            "recoverable": true,
                        },
                        "next_actions": [
                            "fwc context list".to_owned(),
                            format!("fwc context rename {} <new-name>", args.name),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
            config.contexts.insert(
                args.name.clone(),
                MeshContextFile {
                    endpoint: args.endpoint.clone(),
                    default_zone: args.zone.clone(),
                    node_identity: args.identity.clone(),
                    config_overrides: BTreeMap::new(),
                },
            );
            if args.set_current {
                config.current_context.clone_from(&args.name);
            }
            save_context_config(&path, &config)?;
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "context");
            let mut payload = json!({
                "status": "ok",
                "command": "context",
                "subcommand": "create",
                "message": format!("Created context `{}`.", args.name),
                "config_path": path.display().to_string(),
                "context": {
                    "name": &args.name,
                    "endpoint": &args.endpoint,
                    "default_zone": &args.zone,
                    "node_identity": args.identity.as_ref().map(|path| path.display().to_string()),
                    "set_current": args.set_current,
                },
                "current_context": &config.current_context,
                "next_actions": [
                    "fwc context list".to_owned(),
                    format!("fwc context use {}", args.name),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ContextCommand::Delete(args) => {
            let (path, mut config) = load_context_config()?;
            if !config.contexts.contains_key(&args.name) {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "context",
                        "subcommand": "delete",
                        "error": {
                            "type": "context-not-found",
                            "message": format!("`{}` is not a configured context.", args.name),
                            "recoverable": true,
                        },
                        "next_actions": [
                            "fwc context list".to_owned(),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
            if config.current_context == args.name {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "context",
                        "subcommand": "delete",
                        "error": {
                            "type": "cannot-delete-current-context",
                            "message": format!(
                                "Cannot delete the active context `{}`. Switch to another context first.",
                                args.name
                            ),
                            "recoverable": true,
                        },
                        "current_context": &config.current_context,
                        "next_actions": [
                            "fwc context list".to_owned(),
                            "fwc context use <other-context>".to_owned(),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
            config.contexts.remove(&args.name);
            save_context_config(&path, &config)?;
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "context");
            let mut payload = json!({
                "status": "ok",
                "command": "context",
                "subcommand": "delete",
                "message": format!("Deleted context `{}`.", args.name),
                "config_path": path.display().to_string(),
                "current_context": &config.current_context,
                "next_actions": [
                    "fwc context list".to_owned(),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ContextCommand::Rename(args) => {
            let (path, mut config) = load_context_config()?;
            if !config.contexts.contains_key(&args.old_name) {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "context",
                        "subcommand": "rename",
                        "error": {
                            "type": "context-not-found",
                            "message": format!("`{}` is not a configured context.", args.old_name),
                            "recoverable": true,
                        },
                        "next_actions": [
                            "fwc context list".to_owned(),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
            if config.contexts.contains_key(&args.new_name) {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "context",
                        "subcommand": "rename",
                        "error": {
                            "type": "context-already-exists",
                            "message": format!("`{}` already exists.", args.new_name),
                            "recoverable": true,
                        },
                        "next_actions": [
                            "fwc context list".to_owned(),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
            let context = config
                .contexts
                .remove(&args.old_name)
                .expect("checked above");
            config.contexts.insert(args.new_name.clone(), context);
            if config.current_context == args.old_name {
                config.current_context.clone_from(&args.new_name);
            }
            save_context_config(&path, &config)?;
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "context");
            let mut payload = json!({
                "status": "ok",
                "command": "context",
                "subcommand": "rename",
                "message": format!("Renamed context `{}` to `{}`.", args.old_name, args.new_name),
                "config_path": path.display().to_string(),
                "current_context": &config.current_context,
                "next_actions": [
                    "fwc context list".to_owned(),
                    "fwc context current".to_owned(),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
    }
}

fn session_dispatch(args: &SessionArgs) -> Result<DispatchOutcome> {
    match &args.command {
        SessionCommand::Start(args) => {
            let store = cli_session_store();
            let mut paused_session = store.active_session()?;
            if let Some(session) = paused_session.as_mut() {
                session.pause();
                store.save(session)?;
            }

            let mut session = session::Session::new(&args.agent, &args.goal, args.zone.clone());
            for binding in &args.context {
                let (key, value) = parse_session_context_binding(binding).map_err(|message| {
                    anyhow::anyhow!("invalid `--context` binding `{binding}`: {message}")
                })?;
                session.set_context(key, value);
            }
            store.save(&session)?;

            let (active_locks, lock_warning) = session_active_locks(&session.agent_name);
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "session");
            let mut payload = json!({
                "status": "ok",
                "command": "session",
                "subcommand": "start",
                "message": format!(
                    "Started session `{}` for agent `{}`.",
                    session.id, session.agent_name
                ),
                "session": session_detail_value(&session, &active_locks),
                "paused_previous_session": paused_session
                    .as_ref()
                    .map(|session| session_summary_value(session, 0))
                    .unwrap_or(Value::Null),
                "next_actions": [
                    "fwc session show".to_owned(),
                    "fwc session list".to_owned(),
                    format!("fwc session end {}", session.id),
                ],
            });
            if let Some(warning) = lock_warning {
                payload["warnings"] = json!([warning]);
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        SessionCommand::List(args) => {
            let filter = match parse_session_status_filter(args.status.as_deref(), "list") {
                Ok(filter) => filter,
                Err(outcome) => return Ok(outcome),
            };
            let store = cli_session_store();
            let mut sessions = store.list(filter)?;
            if args.limit > 0 && sessions.len() > args.limit {
                sessions.truncate(args.limit);
            }

            let mut warnings = Vec::new();
            let sessions = sessions
                .iter()
                .map(|session| {
                    let (count, warning) = session_active_lock_count(&session.agent_name);
                    if let Some(warning) = warning {
                        warnings.push(warning);
                    }
                    session_summary_value(session, count)
                })
                .collect::<Vec<_>>();

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "session");
            let mut payload = json!({
                "status": "ok",
                "command": "session",
                "subcommand": "list",
                "status_filter": args.status.as_deref(),
                "sessions": sessions,
                "next_actions": [
                    "fwc session show".to_owned(),
                    "fwc session start --agent <name> --goal <goal>".to_owned(),
                ],
            });
            if !warnings.is_empty() {
                payload["warnings"] = json!(warnings);
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        SessionCommand::Show(args) => {
            let store = cli_session_store();
            let session =
                match resolve_session_for_show_or_end(&store, args.session_id.as_deref(), "show") {
                    Ok(session) => session,
                    Err(outcome) => return Ok(outcome),
                };
            let (active_locks, lock_warning) = session_active_locks(&session.agent_name);
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "session");
            let mut payload = json!({
                "status": "ok",
                "command": "session",
                "subcommand": "show",
                "session": session_detail_value(&session, &active_locks),
                "next_actions": session_next_actions(&session),
            });
            if let Some(warning) = lock_warning {
                payload["warnings"] = json!([warning]);
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        SessionCommand::End(args) => {
            let store = cli_session_store();
            let mut session =
                match resolve_session_for_show_or_end(&store, args.session_id.as_deref(), "end") {
                    Ok(session) => session,
                    Err(outcome) => return Ok(outcome),
                };
            session.end();
            store.save(&session)?;

            let (active_locks, lock_warning) = session_active_locks(&session.agent_name);
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "session");
            let mut payload = json!({
                "status": "ok",
                "command": "session",
                "subcommand": "end",
                "message": format!("Ended session `{}`.", session.id),
                "session": session_detail_value(&session, &active_locks),
                "next_actions": [
                    "fwc session list".to_owned(),
                    format!("fwc session resume {}", session.id),
                ],
            });
            if let Some(warning) = lock_warning {
                payload["warnings"] = json!([warning]);
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        SessionCommand::Resume(args) => {
            let store = cli_session_store();
            let mut paused_session = store.active_session()?;
            let mut session = match resolve_session_for_resume(&store, args.session_id.as_deref()) {
                Ok(session) => session,
                Err(outcome) => return Ok(outcome),
            };

            if let Some(current) = paused_session.as_mut()
                && current.id != session.id
            {
                current.pause();
                store.save(current)?;
            }

            session.resume();
            store.save(&session)?;

            let (active_locks, lock_warning) = session_active_locks(&session.agent_name);
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "session");
            let mut payload = json!({
                "status": "ok",
                "command": "session",
                "subcommand": "resume",
                "message": format!("Resumed session `{}`.", session.id),
                "session": session_detail_value(&session, &active_locks),
                "paused_previous_session": paused_session
                    .as_ref()
                    .filter(|current| current.id != session.id)
                    .map(|current| session_summary_value(current, 0))
                    .unwrap_or(Value::Null),
                "next_actions": [
                    "fwc session show".to_owned(),
                    "fwc session list".to_owned(),
                    format!("fwc session end {}", session.id),
                ],
            });
            if let Some(warning) = lock_warning {
                payload["warnings"] = json!([warning]);
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
    }
}

fn parse_session_context_binding(binding: &str) -> std::result::Result<(String, Value), String> {
    let (key, raw_value) = binding
        .split_once('=')
        .ok_or_else(|| "expected `key=value`".to_owned())?;
    let key = key.trim();
    if key.is_empty() {
        return Err("context key cannot be empty".to_owned());
    }

    let value = if raw_value.is_empty() {
        Value::String(String::new())
    } else {
        serde_json::from_str(raw_value).unwrap_or_else(|_| Value::String(raw_value.to_owned()))
    };
    Ok((key.to_owned(), value))
}

fn parse_session_status_filter(
    raw_status: Option<&str>,
    subcommand: &str,
) -> std::result::Result<Option<session::SessionStatus>, DispatchOutcome> {
    let Some(raw_status) = raw_status else {
        return Ok(None);
    };
    session::SessionStatus::parse(raw_status).map(Some).ok_or_else(|| DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "session",
            "subcommand": subcommand,
            "error": {
                "type": "invalid-session-status",
                "message": format!(
                    "`{raw_status}` is not a supported session status. Use `active`, `paused`, or `ended`."
                ),
                "recoverable": true,
            },
            "next_actions": [
                "fwc session list".to_owned(),
                "fwc session list --status active".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Validation,
    })
}

fn resolve_session_for_show_or_end(
    store: &session::SessionStore,
    session_id: Option<&str>,
    subcommand: &str,
) -> std::result::Result<session::Session, DispatchOutcome> {
    if let Some(session_id) = session_id {
        return store
            .load_resolved(session_id)
            .map_err(|error| session_store_error_dispatch(subcommand, &error.to_string()))?
            .ok_or_else(|| session_missing_dispatch(subcommand, session_id));
    }

    store
        .active_session()
        .map_err(|error| session_store_error_dispatch(subcommand, &error.to_string()))?
        .ok_or_else(|| session_missing_dispatch(subcommand, "<active>"))
}

fn resolve_session_for_resume(
    store: &session::SessionStore,
    session_id: Option<&str>,
) -> std::result::Result<session::Session, DispatchOutcome> {
    if let Some(session_id) = session_id {
        return store
            .load_resolved(session_id)
            .map_err(|error| session_store_error_dispatch("resume", &error.to_string()))?
            .ok_or_else(|| session_missing_dispatch("resume", session_id));
    }

    let paused = store
        .list(Some(session::SessionStatus::Paused))
        .map_err(|error| session_store_error_dispatch("resume", &error.to_string()))?
        .into_iter()
        .next();
    if let Some(session) = paused {
        return Ok(session);
    }

    store
        .list(Some(session::SessionStatus::Ended))
        .map_err(|error| session_store_error_dispatch("resume", &error.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| session_missing_dispatch("resume", "<paused-or-ended>"))
}

fn session_store_error_dispatch(subcommand: &str, message: &str) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "session",
            "subcommand": subcommand,
            "error": {
                "type": "session-store-error",
                "message": format!("Failed to access the session store: {message}"),
                "recoverable": true,
            },
            "next_actions": [
                "fwc session list".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Internal,
    }
}

fn session_missing_dispatch(subcommand: &str, session_id: &str) -> DispatchOutcome {
    let message = if session_id == "<active>" {
        "There is no active session to use as the default target.".to_owned()
    } else if session_id == "<paused-or-ended>" {
        "There is no paused or ended session available to resume.".to_owned()
    } else {
        format!("Session `{session_id}` was not found.")
    };
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "session",
            "subcommand": subcommand,
            "error": {
                "type": "session-not-found",
                "message": message,
                "recoverable": true,
            },
            "next_actions": [
                "fwc session list".to_owned(),
                "fwc session start --agent <name> --goal <goal>".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn agent_dispatch(args: &AgentArgs) -> Result<DispatchOutcome> {
    match &args.command {
        AgentCommand::List(args) => {
            let store = cli_agent_coord_store();
            let mut hub = match store.load() {
                Ok(hub) => hub,
                Err(error) => return Ok(agent_store_error_dispatch("list", &error.to_string())),
            };
            let cleaned = hub.cleanup_expired();
            if cleaned > 0 {
                if let Err(error) = store.save(&hub) {
                    return Ok(agent_store_error_dispatch("list", &error.to_string()));
                }
            }

            let announcements = if let Some(connector) = args.connector.as_deref() {
                hub.announcements_for(connector)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                hub.active_announcements()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let reservations = if let Some(connector) = args.connector.as_deref() {
                hub.reservations_for(connector)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                hub.active_reservations()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>()
            };

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "agent");
            let mut payload = json!({
                "status": "ok",
                "command": "agent",
                "subcommand": "list",
                "connector_filter": args.connector,
                "store_path": store.path().display().to_string(),
                "summary": {
                    "announcement_count": announcements.len(),
                    "reservation_count": reservations.len(),
                },
                "announcements": announcements,
                "reservations": reservations,
                "next_actions": [
                    "fwc agent announce --agent <name> --connector <connector> --purpose <purpose>".to_owned(),
                    "fwc agent reserve --agent <name> --connector <connector> --resource <resource>".to_owned(),
                    "fwc agent inbox --agent <name>".to_owned(),
                ],
            });
            if cleaned > 0 {
                payload["cleanup"] = json!({
                    "expired_entries_removed": cleaned,
                });
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        AgentCommand::Announce(args) => {
            let agent = match parse_coord_agent_id(&args.agent, "announce", "agent") {
                Ok(agent) => agent,
                Err(outcome) => return Ok(outcome),
            };
            let store = cli_agent_coord_store();
            let mut hub = match store.load() {
                Ok(hub) => hub,
                Err(error) => {
                    return Ok(agent_store_error_dispatch("announce", &error.to_string()));
                }
            };
            let cleaned = hub.cleanup_expired();

            let mut announcement = agent_coord::UsageAnnouncement::new(
                agent.clone(),
                args.connector.clone(),
                args.purpose.clone(),
            );
            if let Some(operation) = args.operation.as_deref() {
                announcement = announcement.with_operation(operation);
            }
            if args.duration > 0 {
                announcement = announcement.with_duration(args.duration);
            }

            hub.announce(announcement.clone());
            if let Err(error) = store.save(&hub) {
                return Ok(agent_store_error_dispatch("announce", &error.to_string()));
            }

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "agent");
            let mut payload = json!({
                "status": "ok",
                "command": "agent",
                "subcommand": "announce",
                "message": format!(
                    "Recorded coordination announcement for `{}` on connector `{}`.",
                    args.agent, args.connector
                ),
                "store_path": store.path().display().to_string(),
                "announcement": announcement,
                "summary": {
                    "announcement_count": hub.announcement_count(),
                    "reservation_count": hub.reservation_count(),
                },
                "next_actions": [
                    "fwc agent list".to_owned(),
                    format!("fwc agent reserve --agent {} --connector {} --resource <resource>", args.agent, args.connector),
                    format!("fwc agent send --from {} --to <other-agent> --kind info --payload '{{\"connector\":\"{}\"}}'", args.agent, args.connector),
                ],
            });
            if cleaned > 0 {
                payload["cleanup"] = json!({
                    "expired_entries_removed": cleaned,
                });
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        AgentCommand::Reserve(args) => {
            let agent = match parse_coord_agent_id(&args.agent, "reserve", "agent") {
                Ok(agent) => agent,
                Err(outcome) => return Ok(outcome),
            };
            let store = cli_agent_coord_store();
            let mut hub = match store.load() {
                Ok(hub) => hub,
                Err(error) => return Ok(agent_store_error_dispatch("reserve", &error.to_string())),
            };
            let cleaned = hub.cleanup_expired();
            if cleaned > 0 {
                if let Err(error) = store.save(&hub) {
                    return Ok(agent_store_error_dispatch("reserve", &error.to_string()));
                }
            }

            let reservation_id = match hub.reserve(
                agent.clone(),
                args.connector.clone(),
                args.resource.clone(),
                args.ttl,
                args.exclusive,
            ) {
                Ok(id) => id,
                Err(agent_coord::CoordError::ResourceConflict { resource, held_by }) => {
                    return Ok(DispatchOutcome {
                        payload: json!({
                            "status": "error",
                            "command": "agent",
                            "subcommand": "reserve",
                            "error": {
                                "type": "resource-conflict",
                                "message": format!(
                                    "Resource `{resource}` is already reserved by `{held_by}`."
                                ),
                                "recoverable": true,
                            },
                            "connector": args.connector,
                            "resource": resource,
                            "held_by": held_by,
                            "next_actions": [
                                "fwc agent list".to_owned(),
                                format!("fwc agent inbox --agent {}", args.agent),
                            ],
                        }),
                        exit_code: CliExitCode::Validation,
                    });
                }
                Err(error) => {
                    return Ok(agent_store_error_dispatch("reserve", &error.to_string()));
                }
            };

            let reservation = hub
                .active_reservations()
                .into_iter()
                .find(|reservation| reservation.id == reservation_id)
                .cloned()
                .expect("newly created reservation should exist");
            if let Err(error) = store.save(&hub) {
                return Ok(agent_store_error_dispatch("reserve", &error.to_string()));
            }

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "agent");
            let mut payload = json!({
                "status": "ok",
                "command": "agent",
                "subcommand": "reserve",
                "message": format!(
                    "Reserved `{}` on connector `{}` for agent `{}`.",
                    args.resource, args.connector, args.agent
                ),
                "store_path": store.path().display().to_string(),
                "reservation": reservation,
                "summary": {
                    "announcement_count": hub.announcement_count(),
                    "reservation_count": hub.reservation_count(),
                },
                "next_actions": [
                    "fwc agent list".to_owned(),
                    format!("fwc agent send --from {} --to <other-agent> --kind warning --payload '{{\"resource\":\"{}\"}}'", args.agent, args.resource),
                ],
            });
            if cleaned > 0 {
                payload["cleanup"] = json!({
                    "expired_entries_removed": cleaned,
                });
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        AgentCommand::Send(args) => {
            let from = match parse_coord_agent_id(&args.from, "send", "from") {
                Ok(agent) => agent,
                Err(outcome) => return Ok(outcome),
            };
            let to = match parse_coord_agent_id(&args.to, "send", "to") {
                Ok(agent) => agent,
                Err(outcome) => return Ok(outcome),
            };
            let store = cli_agent_coord_store();
            let mut hub = match store.load() {
                Ok(hub) => hub,
                Err(error) => return Ok(agent_store_error_dispatch("send", &error.to_string())),
            };
            let cleaned = hub.cleanup_expired();
            let payload_value = parse_agent_message_payload(&args.payload);
            let kind = agent_message_kind(args.kind);
            hub.send(from.clone(), &to, kind, payload_value.clone());
            let unread_count = hub.unread_count(&to);
            if let Err(error) = store.save(&hub) {
                return Ok(agent_store_error_dispatch("send", &error.to_string()));
            }

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "agent");
            let mut payload = json!({
                "status": "ok",
                "command": "agent",
                "subcommand": "send",
                "message": format!(
                    "Delivered a `{}` message from `{}` to `{}`.",
                    agent_message_kind_name(args.kind),
                    args.from,
                    args.to
                ),
                "store_path": store.path().display().to_string(),
                "from": args.from,
                "to": args.to,
                "kind": args.kind,
                "payload_sent": payload_value,
                "recipient_unread_count": unread_count,
                "next_actions": [
                    format!("fwc agent inbox --agent {}", args.to),
                    "fwc agent list".to_owned(),
                ],
            });
            if cleaned > 0 {
                payload["cleanup"] = json!({
                    "expired_entries_removed": cleaned,
                });
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        AgentCommand::Inbox(args) => {
            let agent = match parse_coord_agent_id(&args.agent, "inbox", "agent") {
                Ok(agent) => agent,
                Err(outcome) => return Ok(outcome),
            };
            let store = cli_agent_coord_store();
            let mut hub = match store.load() {
                Ok(hub) => hub,
                Err(error) => return Ok(agent_store_error_dispatch("inbox", &error.to_string())),
            };
            let cleaned = hub.cleanup_expired();
            let unread_before = hub.unread_count(&agent);
            let messages = if args.drain {
                hub.read_inbox(&agent)
            } else {
                hub.inbox(&agent).into_iter().cloned().collect::<Vec<_>>()
            };
            if args.drain || cleaned > 0 {
                if let Err(error) = store.save(&hub) {
                    return Ok(agent_store_error_dispatch("inbox", &error.to_string()));
                }
            }

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "agent");
            let mut payload = json!({
                "status": "ok",
                "command": "agent",
                "subcommand": "inbox",
                "store_path": store.path().display().to_string(),
                "agent": args.agent,
                "drained": args.drain,
                "message_count": messages.len(),
                "unread_count": unread_before,
                "messages": messages,
                "next_actions": [
                    "fwc agent list".to_owned(),
                    format!("fwc agent send --from {} --to <other-agent> --kind response --payload '{{\"status\":\"received\"}}'", args.agent),
                ],
            });
            if cleaned > 0 {
                payload["cleanup"] = json!({
                    "expired_entries_removed": cleaned,
                });
            }
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
    }
}

fn parse_coord_agent_id(
    raw: &str,
    subcommand: &str,
    field: &str,
) -> std::result::Result<agent_coord::AgentId, DispatchOutcome> {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && agent_mail::AgentId::parse(trimmed).is_some() {
        return Ok(agent_coord::AgentId::new(trimmed));
    }

    Err(DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "agent",
            "subcommand": subcommand,
            "error": {
                "type": "invalid-agent-name",
                "message": format!(
                    "`{raw}` is not a valid Agent Mail identifier for `{field}`. Use a two-word PascalCase name such as `BronzeValley` or `GoldenWolf`."
                ),
                "recoverable": true,
            },
            "next_actions": [
                "fwc agent list".to_owned(),
                "Choose a two-word PascalCase agent identifier.".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Validation,
    })
}

fn parse_agent_message_payload(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_owned()))
}

fn agent_message_kind(kind: AgentMessageKindArg) -> agent_coord::MessageKind {
    match kind {
        AgentMessageKindArg::Request => agent_coord::MessageKind::Request,
        AgentMessageKindArg::Response => agent_coord::MessageKind::Response,
        AgentMessageKindArg::Info => agent_coord::MessageKind::Info,
        AgentMessageKindArg::Warning => agent_coord::MessageKind::Warning,
        AgentMessageKindArg::Release => agent_coord::MessageKind::Release,
    }
}

fn agent_message_kind_name(kind: AgentMessageKindArg) -> &'static str {
    match kind {
        AgentMessageKindArg::Request => "request",
        AgentMessageKindArg::Response => "response",
        AgentMessageKindArg::Info => "info",
        AgentMessageKindArg::Warning => "warning",
        AgentMessageKindArg::Release => "release",
    }
}

fn agent_store_error_dispatch(subcommand: &str, message: &str) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "agent",
            "subcommand": subcommand,
            "error": {
                "type": "agent-store-error",
                "message": format!("Failed to access the local agent coordination store: {message}"),
                "recoverable": true,
            },
            "next_actions": [
                "fwc agent list".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Internal,
    }
}

fn session_active_locks(agent_name: &str) -> (Vec<Value>, Option<String>) {
    match cli_lock_store().list_by_agent(agent_name) {
        Ok(locks) => (
            locks
                .into_iter()
                .map(|lock| {
                    json!({
                        "resource": lock.resource,
                        "agent": lock.agent,
                        "acquired_at": lock.acquired_at,
                        "expires_at": lock.expires_at,
                        "remaining": lock.remaining_display(),
                        "reason": lock.reason,
                    })
                })
                .collect(),
            None,
        ),
        Err(error) => (
            Vec::new(),
            Some(format!(
                "Failed to inspect active locks for agent `{agent_name}`: {error}"
            )),
        ),
    }
}

fn session_active_lock_count(agent_name: &str) -> (usize, Option<String>) {
    let (locks, warning) = session_active_locks(agent_name);
    (locks.len(), warning)
}

fn session_summary_value(session: &session::Session, active_lock_count: usize) -> Value {
    json!({
        "id": session.id.to_string(),
        "agent_name": &session.agent_name,
        "goal": &session.goal,
        "status": session.status.as_str(),
        "zone": &session.zone,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "ended_at": session.ended_at,
        "operations_completed": session.operations_completed,
        "context_key_count": session.context.len(),
        "active_lock_count": active_lock_count,
    })
}

fn session_detail_value(session: &session::Session, active_locks: &[Value]) -> Value {
    let mut detail = session_summary_value(session, active_locks.len());
    if let Some(object) = detail.as_object_mut() {
        object.insert("context".to_owned(), json!(session.context));
        object.insert("active_locks".to_owned(), json!(active_locks));
    }
    detail
}

fn session_next_actions(session: &session::Session) -> Vec<String> {
    match session.status {
        session::SessionStatus::Active => vec![
            format!("fwc session end {}", session.id),
            "fwc session list".to_owned(),
        ],
        session::SessionStatus::Paused | session::SessionStatus::Ended => vec![
            format!("fwc session resume {}", session.id),
            "fwc session list".to_owned(),
        ],
    }
}

fn search_dispatch_host(args: &SearchArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
    let (connectors, metadata_gaps) = load_live_discovered_connectors(&client, &catalog)?;
    let filter_gaps = host_filter_gaps(args.zone.as_deref());
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
        zone: if filter_gaps.is_empty() {
            args.zone.clone()
        } else {
            None
        },
    };
    let results = search::search_operations(&connectors, &args.query, &filters);
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

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "search");
    let mut payload = json!({
        "status": "ok",
        "command": "search",
        "source": "host-admin-api",
        "mode": "live-introspection",
        "message": format!("Found {} live matching operations ({} shown).", total, json_results.len()),
        "query": &args.query,
        "filters": active_filters,
        "filter_gaps": filter_gaps,
        "metadata_gaps": metadata_gaps,
        "total_results": total,
        "results": json_results,
        "next_actions": [
            "Use `fwc show <connector> --host <endpoint>` to inspect a connector in more detail.",
            "Use `fwc schema <connector> <operation> --host <endpoint>` for the live input/output schema.",
            "Add --capability, --risk, --safety, or --idempotent flags to narrow results.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "search",
        catalog::DiscoveryDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn search_dispatch(args: &SearchArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("search"));
        }
    } else if let Some(host) = resolved_host {
        return search_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "search",
            json!({
                "query": &args.query,
                "filters": {
                    "zone": args.zone,
                    "connector": args.connector,
                    "capability": args.capability,
                    "risk": args.risk,
                    "safety": args.safety,
                    "archetype": args.archetype,
                    "category": args.category,
                    "idempotent": args.idempotent,
                },
            }),
            vec![
                "fwc search <query> --host <endpoint>".to_owned(),
                "fwc search <query> --offline".to_owned(),
            ],
        ));
    }

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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "search");
    let mut payload = json!({
        "status": "ok",
        "command": "search",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "message": format!("Found {} matching operations ({} shown).", total, json_results.len()),
        "query": &args.query,
        "filters": active_filters,
        "total_results": total,
        "results": json_results,
        "next_actions": [
            "Use `fwc show <connector> --offline` to inspect a connector in more detail.",
            "Use `fwc schema <connector> <operation> --offline` for the input/output schema.",
            "Add --capability, --risk, --safety, --idempotent flags to narrow results.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "search",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn show_dispatch(args: &ShowArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("show"));
        }
    } else if let Some(host) = resolved_host {
        return show_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "show",
            json!({
                "connector": &args.connector,
            }),
            vec![
                format!("fwc show {} --host <endpoint>", args.connector),
                format!("fwc show {} --offline", args.connector),
            ],
        ));
    }

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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "show");
    let mut payload = json!({
        "status": "ok",
        "command": "show",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
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
            "state_model": connector.state_model.as_known().cloned(),
            "archetypes": summary.archetypes.as_known().cloned(),
            "operation_count": summary.operation_count,
            "max_risk": &summary.max_risk,
            "has_events": summary.has_events,
            "manifest_path": &connector.manifest_path,
        },
        "zones": connector.zones.clone(),
        "capabilities": connector.capabilities.clone(),
        "rate_limits": connector.detail.rate_limits.as_known().cloned(),
        "shared_descriptor": connector.shared_descriptor(),
        "operations": {
            "preview": preview,
            "preview_truncated": preview_truncated,
            "risky_count": risky_count,
            "safe_count": connector.operations.len().saturating_sub(risky_count),
        },
        "next_actions": [
            format!("fwc ops {slug} --offline"),
            format!("fwc schema {slug} {example_operation} --offline"),
            format!("fwc examples {slug} {example_operation} --offline"),
            format!("fwc config schema {slug}"),
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "show",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn ops_dispatch(args: &OpsArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("ops"));
        }
    } else if let Some(host) = resolved_host {
        return ops_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "ops",
            json!({
                "connector": &args.connector,
                "filters": {
                    "risk_at_most": args.risk_at_most,
                },
            }),
            vec![
                format!("fwc ops {} --host <endpoint>", args.connector),
                format!("fwc ops {} --offline", args.connector),
            ],
        ));
    }

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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "ops");
    let mut payload = json!({
        "status": "ok",
        "command": "ops",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
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
            format!("fwc schema {slug} <operation> --offline"),
            format!("fwc examples {slug} <operation> --offline"),
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "ops",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(clippy::too_many_lines)]
fn schema_dispatch(args: &SchemaArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("schema"));
        }
    } else if let Some(host) = resolved_host {
        return schema_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "schema",
            json!({
                "connector": &args.connector,
                "operation": args.operation,
                "field": args.field,
                "required_only": args.required_only,
                "examples": args.examples,
                "scaffold": args.scaffold,
            }),
            vec![
                format!(
                    "fwc schema {} <operation> --host <endpoint>",
                    args.connector
                ),
                format!("fwc schema {} <operation> --offline", args.connector),
            ],
        ));
    }

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
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "schema");
            let mut payload = json!({
                "status": "ok",
                "command": "schema",
                "source": "workspace-manifests",
                "mode": "offline-artifact",
                "scope": "scaffold",
                "connector": { "slug": &connector.slug },
                "operation": { "selector": &operation.preferred_selector },
                "scaffold": scaffold,
            });
            attach_discovery_provenance(
                &mut payload,
                "schema",
                catalog::DiscoveryDataSource::WorkspaceManifest,
            );
            envelope.inject_into(&mut payload);
            return Ok(DispatchOutcome {
                payload,
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
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "schema");
            let mut payload = json!({
                "status": "ok",
                "command": "schema",
                "source": "workspace-manifests",
                "mode": "offline-artifact",
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
                    format!("fwc schema {} {} --scaffold --offline", connector.slug, operation.preferred_selector),
                ],
            });
            attach_discovery_provenance(
                &mut payload,
                "schema",
                catalog::DiscoveryDataSource::WorkspaceManifest,
            );
            envelope.inject_into(&mut payload);
            return Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            });
        }

        // ── Default: full schema view ────────────────────────────────
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "schema");
        let mut payload = json!({
            "status": "ok",
            "command": "schema",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
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
                format!("fwc examples {} {} --offline", connector.slug, operation.preferred_selector),
                format!("fwc schema {} {} --required-only --offline", connector.slug, operation.preferred_selector),
                format!("fwc schema {} {} --scaffold --offline", connector.slug, operation.preferred_selector),
                format!("fwc simulate {} {} --file payload.json", connector.slug, operation.preferred_selector),
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "schema",
            catalog::DiscoveryDataSource::WorkspaceManifest,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "schema");
    let mut payload = json!({
        "status": "ok",
        "command": "schema",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "scope": "connector",
        "message": "Loaded the connector contract schema from the manifest.",
        "connector": {
            "slug": &connector.slug,
            "canonical_id": &connector.detail.summary.id,
            "name": &connector.detail.summary.name,
        },
        "schema": connector.connector_schema.clone(),
        "next_actions": [
            format!("fwc ops {} --offline", connector.slug),
            format!("fwc config schema {}", connector.slug),
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "schema",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn examples_dispatch(args: &ExampleArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("examples"));
        }
    } else if let Some(host) = resolved_host {
        return examples_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "examples",
            json!({
                "connector": &args.connector,
                "operation": args.operation,
            }),
            vec![
                format!(
                    "fwc examples {} <operation> --host <endpoint>",
                    args.connector
                ),
                format!("fwc examples {} <operation> --offline", args.connector),
            ],
        ));
    }

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

        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "examples");
        let mut payload = json!({
            "status": "ok",
            "command": "examples",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
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
                format!("fwc schema {} {} --offline", connector.slug, operation.preferred_selector),
                format!("fwc simulate {} {} --file payload.json", connector.slug, operation.preferred_selector),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "examples",
            catalog::TemplateDataSource::WorkspaceManifest,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "examples");
    let mut payload = json!({
        "status": "ok",
        "command": "examples",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "scope": "connector",
        "message": "Loaded connector-level examples and suggested follow-up commands.",
        "connector": {
            "slug": &connector.slug,
            "canonical_id": &connector.detail.summary.id,
            "name": &connector.detail.summary.name,
        },
        "examples": {
            "commands": [
                format!("fwc show {} --offline", connector.slug),
                format!("fwc ops {} --offline", connector.slug),
                format!("fwc config schema {}", connector.slug),
            ],
            "operations": operation_examples,
        },
        "next_actions": [
            format!("fwc ops {} --offline", connector.slug),
            format!("fwc schema {} <operation> --offline", connector.slug),
        ],
    });
    attach_template_provenance(
        &mut payload,
        "examples",
        catalog::TemplateDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn doctor_dispatch(args: &DoctorArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "doctor",
            serde_json::to_value(args)?,
            vec![
                format!("fwc doctor --zone {} --host <endpoint>", args.zone),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    if args.self_check && args.connector.is_empty() {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "doctor",
                "error": {
                    "type": "missing-connectors",
                    "message": "`fwc doctor --self-check` requires at least one `--connector` selector.",
                    "recoverable": true,
                },
                "details": serde_json::to_value(args)?,
                "next_actions": [
                    format!("fwc doctor --zone {} --connector <connector> --host {}", args.zone, host.endpoint),
                    format!("fwc list --host {}", host.endpoint),
                ],
            }),
            exit_code: CliExitCode::Validation,
        });
    }

    let zone = match args.zone.parse::<ZoneId>() {
        Ok(zone) => zone,
        Err(error) => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "doctor",
                    "error": {
                        "type": "invalid-zone",
                        "message": format!("`{}` is not a valid zone id: {error}", args.zone),
                        "recoverable": true,
                    },
                    "details": {
                        "zone": &args.zone,
                    },
                    "next_actions": [
                        format!("fwc doctor --zone z:work --host {}", host.endpoint),
                        format!("fwc doctor --zone z:project:<name> --host {}", host.endpoint),
                    ],
                }),
                exit_code: CliExitCode::Validation,
            });
        }
    };

    let client = HostAdminClient::new(&host.endpoint)?;
    let mut requested_connectors = Vec::new();
    let mut connector_ids = Vec::new();
    if !args.connector.is_empty() {
        let (catalog, _) = client.catalog(None)?;
        for selector in &args.connector {
            let connector = match catalog.resolve_connector(selector) {
                Ok(connector) => connector,
                Err(error) => return Ok(connector_resolution_dispatch("doctor", selector, &error)),
            };
            requested_connectors.push(json!({
                "selector": selector,
                "slug": &connector.slug,
                "canonical_id": connector.summary.id.as_str(),
                "name": &connector.summary.name,
            }));
            connector_ids.push(connector.summary.id.to_string());
        }
    }

    let report = client.doctor(&HostDoctorRequest {
        zone_id: zone.to_string(),
        connectors: connector_ids,
        self_check: args.self_check || !args.connector.is_empty(),
    })?;

    let mut next_actions = vec![format!("fwc status --host {}", host.endpoint)];
    if let Some(first) = requested_connectors
        .first()
        .and_then(|connector| connector.get("slug"))
        .and_then(Value::as_str)
    {
        next_actions.push(format!("fwc show {first} --host {}", host.endpoint));
        next_actions.push(format!("fwc status {first} --host {}", host.endpoint));
    } else {
        next_actions.push(format!("fwc list --host {}", host.endpoint));
    }

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "doctor");
    let mut payload = json!({
        "status": "ok",
        "command": "doctor",
        "source": "host-admin-api",
        "message": format!("Loaded a live doctor report for `{}` from `fcp-host`.", report.zone_id),
        "zone": report.zone_id,
        "requested_connectors": requested_connectors,
        "self_check": args.self_check || !args.connector.is_empty(),
        "summary": {
            "overall_status": report.overall_status,
            "check_count": report.checks.len(),
            "connector_self_check_count": report.connector_self_checks.len(),
            "is_degraded": report.degraded_mode.is_degraded,
        },
        "report": report,
        "next_actions": next_actions,
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn status_dispatch(args: &StatusArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "status",
            json!({
                "scope": if args.connector.is_some() { "connector" } else { "fleet" },
                "connector": args.connector.as_deref(),
            }),
            vec![
                "fwc status --host <endpoint>".to_owned(),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, discovery) = client.catalog(None)?;
    let health = client.health()?;

    if let Some(selector) = args.connector.as_deref() {
        let connector = match catalog.resolve_connector(selector) {
            Ok(connector) => connector,
            Err(error) => return Ok(connector_resolution_dispatch("status", selector, &error)),
        };
        let admin = client.connector_status(connector.summary.id.as_str())?;
        let pin = client.pin_status(connector.summary.id.as_str())?;
        let rollout = client.rollout_status(connector.summary.id.as_str()).ok();

        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "status");
        let mut payload = json!({
            "status": "ok",
            "command": "status",
            "scope": "connector",
            "source": "host-admin-api",
            "message": format!("Loaded live connector admin status for `{}` from `fcp-host`.", connector.slug),
            "connector": {
                "slug": &connector.slug,
                "canonical_id": connector.summary.id.as_str(),
                "name": &connector.summary.name,
                "version": connector.summary.version.to_string(),
                "enabled": connector.summary.enabled,
                "health": &connector.summary.health,
            },
            "admin": admin,
            "pin": pin,
            "rollout": rollout,
            "host_health": {
                "status": health.status,
                "timestamp": health.timestamp,
            },
            "registry_version": discovery.registry_version,
            "next_actions": [
                format!("fwc show {} --host {}", connector.slug, host.endpoint),
                format!("fwc ops {} --host {}", connector.slug, host.endpoint),
                format!("fwc pin {} --to {} --host {}", connector.slug, connector.summary.version, host.endpoint),
            ],
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let connector_rows = catalog
        .connectors
        .iter()
        .map(|connector| {
            json!({
                "slug": &connector.slug,
                "canonical_id": connector.summary.id.as_str(),
                "name": &connector.summary.name,
                "enabled": connector.summary.enabled,
                "health": &connector.summary.health,
                "state": host_connector_state_label(&connector.summary.health),
                "version": connector.summary.version.to_string(),
                "tool_count": connector.summary.tool_count,
                "max_safety_tier": safety_tier_label(connector.summary.max_safety_tier),
            })
        })
        .collect::<Vec<_>>();

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "status");
    let mut payload = json!({
        "status": "ok",
        "command": "status",
        "scope": "fleet",
        "source": "host-admin-api",
        "message": format!("Loaded live fleet status for {} connectors from `fcp-host`.", connector_rows.len()),
        "host_health": health,
        "registry_version": discovery.registry_version,
        "connectors": connector_rows,
        "next_actions": [
            format!("fwc status <connector> --host {}", host.endpoint),
            format!("fwc list --host {}", host.endpoint),
            format!("fwc show <connector> --host {}", host.endpoint),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn budget_dispatch(args: &BudgetArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "budget",
            serde_json::to_value(args)?,
            vec![
                "fwc budget --host <endpoint>".to_owned(),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };

    if let Some(zone) = args.zone.as_deref()
        && let Err(error) = zone.parse::<ZoneId>()
    {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "budget",
                "error": {
                    "type": "invalid-zone",
                    "message": format!("`{zone}` is not a valid zone id: {error}"),
                    "recoverable": true,
                },
                "details": {
                    "zone": zone,
                },
                "next_actions": [
                    format!("fwc budget --zone z:work --host {}", host.endpoint),
                    format!("fwc budget --host {}", host.endpoint),
                ],
            }),
            exit_code: CliExitCode::Validation,
        });
    }

    let client = HostAdminClient::new(&host.endpoint)?;
    let report = client.budget_report(&HostBudgetReportRequest {
        zone_id: args.zone.clone(),
    })?;
    let budget_count = report
        .zones
        .iter()
        .map(|zone| zone.budgets.len())
        .sum::<usize>();
    let exceeded_count = report
        .zones
        .iter()
        .flat_map(|zone| zone.budgets.iter())
        .filter(|budget| budget.status == fcp_core::BudgetStatus::Exceeded)
        .count();
    let next_actions = args.zone.as_ref().map_or_else(
        || {
            vec![
                format!("fwc status --host {}", host.endpoint),
                format!("fwc list --host {}", host.endpoint),
            ]
        },
        |zone| {
            vec![
                format!("fwc doctor --zone {zone} --host {}", host.endpoint),
                format!("fwc status --host {}", host.endpoint),
            ]
        },
    );

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "budget");
    let mut payload = json!({
        "status": "ok",
        "command": "budget",
        "source": "host-admin-api",
        "message": if report.zones.is_empty() {
            "No live usage-budget policies are currently configured on `fcp-host`.".to_owned()
        } else {
            format!("Loaded live budget snapshots for {} zone(s) from `fcp-host`.", report.zones.len())
        },
        "filter": {
            "zone": &args.zone,
        },
        "schema_version": report.schema_version,
        "generated_at": report.generated_at,
        "summary": {
            "zone_count": report.zones.len(),
            "budget_count": budget_count,
            "exceeded_count": exceeded_count,
        },
        "zones": report.zones,
        "next_actions": next_actions,
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn pin_dispatch(args: &PinArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "pin",
            json!({
                "connector": &args.connector,
                "to": &args.to,
            }),
            vec![
                format!(
                    "fwc pin {} --to {} --host <endpoint>",
                    args.connector, args.to
                ),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "pin",
                &args.connector,
                &error,
            ));
        }
    };
    let version = args.to.parse::<semver::Version>().map_err(|error| {
        anyhow::anyhow!(
            "`fwc pin` currently requires an explicit semantic version because `fcp-host` only exposes version pins today: {error}"
        )
    })?;
    let pin = client.pin(connector.summary.id.as_str(), &version)?;

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "pin");
    let mut payload = json!({
        "status": "ok",
        "command": "pin",
        "source": "host-admin-api",
        "message": format!("Pinned `{}` to `{}` via `fcp-host`.", connector.slug, version),
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
        },
        "pin": pin,
        "next_actions": [
            format!("fwc status {} --host {}", connector.slug, host.endpoint),
            format!("fwc unpin {} --host {}", connector.slug, host.endpoint),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn unpin_dispatch(args: &TargetArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "unpin",
            json!({
                "connector": &args.connector,
            }),
            vec![
                format!("fwc unpin {} --host <endpoint>", args.connector),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                "unpin",
                &args.connector,
                &error,
            ));
        }
    };
    let pin = client.unpin(connector.summary.id.as_str())?;

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "unpin");
    let mut payload = json!({
        "status": "ok",
        "command": "unpin",
        "source": "host-admin-api",
        "message": format!("Removed the live rollout pin for `{}`.", connector.slug),
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
        },
        "pin": pin,
        "next_actions": [
            format!("fwc status {} --host {}", connector.slug, host.endpoint),
            format!("fwc pin {} --to <version> --host {}", connector.slug, host.endpoint),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn rollout_dispatch(args: &RolloutArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let command = match &args.command {
        RolloutCommand::Set(_) => "rollout set",
        RolloutCommand::Status(_) => "rollout status",
        RolloutCommand::Rollback(_) => "rollout rollback",
    };

    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            command,
            serde_json::to_value(args)?,
            vec![
                format!("fwc {command} <connector> --host <endpoint>"),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };

    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;

    match &args.command {
        RolloutCommand::Set(set_args) => {
            if set_args.canary > 100 {
                anyhow::bail!("canary percentage must be 0-100, got {}", set_args.canary);
            }
            let connector = match catalog.resolve_connector(&set_args.connector) {
                Ok(connector) => connector,
                Err(error) => {
                    return Ok(connector_resolution_dispatch(
                        "rollout set",
                        &set_args.connector,
                        &error,
                    ));
                }
            };
            let pin_state = client.pin_status(connector.summary.id.as_str())?;
            let version = pin_state.version.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "no pinned version is configured for `{}`. Pin a version first with `fwc pin {} --to <version>`.",
                    connector.slug,
                    connector.slug
                )
            })?;
            let previous_version = Some(
                client
                    .rollout_status(connector.summary.id.as_str())?
                    .status
                    .version,
            );
            let policy = fcp_core::RolloutPolicy::builder()
                .canary_percent(set_args.canary)
                .build();
            policy.validate()?;
            let schedule = HostRolloutScheduleRequest {
                connector_id: connector.summary.id.to_string(),
                version,
                previous_version,
                policy,
            };
            let outcome = client.schedule_rollout(&schedule)?;

            let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "rollout");
            let mut payload = json!({
                "status": "ok",
                "command": "rollout",
                "subcommand": "set",
                "source": "host-admin-api",
                "message": format!(
                    "Scheduled a {}% canary rollout for `{}`.",
                    set_args.canary,
                    connector.slug
                ),
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.summary.id.as_str(),
                },
                "requested_canary_percent": set_args.canary,
                "pin": pin_state,
                "rollout": outcome,
                "next_actions": [
                    format!("fwc rollout status {} --host {}", connector.slug, host.endpoint),
                    format!("fwc status {} --host {}", connector.slug, host.endpoint),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        RolloutCommand::Status(status_args) => {
            let connector = match catalog.resolve_connector(&status_args.connector) {
                Ok(connector) => connector,
                Err(error) => {
                    return Ok(connector_resolution_dispatch(
                        "rollout status",
                        &status_args.connector,
                        &error,
                    ));
                }
            };
            let pin = client.pin_status(connector.summary.id.as_str())?;
            let rollout = client.rollout_status(connector.summary.id.as_str())?;

            let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "rollout");
            let mut payload = json!({
                "status": "ok",
                "command": "rollout",
                "subcommand": "status",
                "source": "host-admin-api",
                "message": format!("Loaded live rollout state for `{}`.", connector.slug),
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.summary.id.as_str(),
                },
                "pin": pin,
                "rollout": rollout,
                "next_actions": [
                    format!("fwc status {} --host {}", connector.slug, host.endpoint),
                    format!("fwc rollout rollback {} --to <version> --host {}", connector.slug, host.endpoint),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        RolloutCommand::Rollback(rollback_args) => {
            let connector = match catalog.resolve_connector(&rollback_args.connector) {
                Ok(connector) => connector,
                Err(error) => {
                    return Ok(connector_resolution_dispatch(
                        "rollout rollback",
                        &rollback_args.connector,
                        &error,
                    ));
                }
            };
            let version = rollback_args.to.parse::<semver::Version>().map_err(|error| {
                anyhow::anyhow!(
                    "`fwc rollout rollback` requires an explicit semantic version target: {error}"
                )
            })?;
            let response = client.rollback(connector.summary.id.as_str(), &version)?;

            let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "rollout");
            let mut payload = json!({
                "status": "ok",
                "command": "rollout",
                "subcommand": "rollback",
                "source": "host-admin-api",
                "message": format!(
                    "Rolled `{}` from `{}` back to `{}`.",
                    connector.slug, response.from_version, response.to_version
                ),
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.summary.id.as_str(),
                },
                "rollback": response,
                "next_actions": [
                    format!("fwc rollout status {} --host {}", connector.slug, host.endpoint),
                    format!("fwc status {} --host {}", connector.slug, host.endpoint),
                ],
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
    }
}

fn config_dispatch(args: &ConfigArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connectors_file = resolve_connectors_file_path(args.connectors_file.as_ref())?;

    match &args.command {
        ConfigCommand::Schema(target) => {
            let connector = match catalog.resolve_connector(&target.connector) {
                Ok(connector) => connector,
                Err(error) => {
                    return Ok(connector_resolution_dispatch(
                        "config schema",
                        &target.connector,
                        &error,
                    ));
                }
            };
            let Some(schema) = connector.detail.config_schema.as_known() else {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "unavailable",
                        "command": "config",
                        "subcommand": "schema",
                        "source": "workspace-discovery",
                        "message": format!(
                            "No config schema is available for `{}` from the current discovery sources.",
                            connector.slug
                        ),
                        "connector": {
                            "slug": &connector.slug,
                            "canonical_id": connector.detail.summary.id.as_str(),
                        },
                        "connectors_file": connectors_file.display().to_string(),
                    }),
                    exit_code: CliExitCode::Validation,
                });
            };

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": "ok",
                "command": "config",
                "subcommand": "schema",
                "source": "workspace-discovery",
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.detail.summary.id.as_str(),
                },
                "connectors_file": connectors_file.display().to_string(),
                "schema": schema,
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ConfigCommand::Get(target) => {
            let configs = read_managed_connector_configs(&connectors_file)?;
            let (entry, resolved) =
                resolve_managed_connector(&catalog, &configs, &target.connector)?;
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": "ok",
                "command": "config",
                "subcommand": "get",
                "source": "connectors-file",
                "connector": connector_descriptor_json(&entry, resolved),
                "connectors_file": connectors_file.display().to_string(),
                "config": entry.config.clone().unwrap_or_else(|| json!({})),
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ConfigCommand::Set(set_args) => {
            let mut configs = read_managed_connector_configs(&connectors_file)?;
            let resolved = catalog.resolve_connector(&set_args.connector).ok();
            let index = find_managed_connector_index(&configs, &set_args.connector, resolved)?;
            let path = parse_invoke_path(&set_args.key).map_err(|error| {
                anyhow::anyhow!("invalid config path `{}`: {error:?}", set_args.key)
            })?;
            let schema = resolved.and_then(|connector| connector.detail.config_schema.as_known());
            let schema_at_path = schema.and_then(|schema| invoke_schema_at_path(schema, &path));
            let value = coerce_invoke_value(&set_args.value, schema_at_path)
                .map_err(|error| anyhow::anyhow!("failed to parse config value: {error}"))?;

            let mut config_value = configs[index].config.clone().unwrap_or_else(|| json!({}));
            apply_invoke_binding(&mut config_value, &path, value).map_err(|error| {
                anyhow::anyhow!("failed to set config path `{}`: {error}", set_args.key)
            })?;
            let validation_errors = validate_config_value(schema, &config_value);
            if !validation_errors.is_empty() {
                return Ok(config_validation_dispatch(
                    "set",
                    &connectors_file,
                    &configs[index],
                    resolved,
                    config_value,
                    validation_errors,
                ));
            }

            configs[index].config = Some(config_value.clone());
            write_managed_connector_configs(&connectors_file, &configs)?;
            let entry = &configs[index];

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": "ok",
                "command": "config",
                "subcommand": "set",
                "source": "connectors-file",
                "connector": connector_descriptor_json(entry, resolved),
                "connectors_file": connectors_file.display().to_string(),
                "updated_path": set_args.key,
                "config": config_value,
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ConfigCommand::Unset(unset_args) => {
            let mut configs = read_managed_connector_configs(&connectors_file)?;
            let resolved = catalog.resolve_connector(&unset_args.connector).ok();
            let index = find_managed_connector_index(&configs, &unset_args.connector, resolved)?;
            let path = parse_invoke_path(&unset_args.key).map_err(|error| {
                anyhow::anyhow!("invalid config path `{}`: {error:?}", unset_args.key)
            })?;
            let mut config_value = configs[index].config.clone().unwrap_or_else(|| json!({}));
            remove_invoke_binding(&mut config_value, &path).map_err(|error| {
                anyhow::anyhow!("failed to unset config path `{}`: {error}", unset_args.key)
            })?;
            let schema = resolved.and_then(|connector| connector.detail.config_schema.as_known());
            let validation_errors = validate_config_value(schema, &config_value);
            if !validation_errors.is_empty() {
                return Ok(config_validation_dispatch(
                    "unset",
                    &connectors_file,
                    &configs[index],
                    resolved,
                    config_value,
                    validation_errors,
                ));
            }

            configs[index].config = Some(config_value.clone());
            write_managed_connector_configs(&connectors_file, &configs)?;
            let entry = &configs[index];

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": "ok",
                "command": "config",
                "subcommand": "unset",
                "source": "connectors-file",
                "connector": connector_descriptor_json(entry, resolved),
                "connectors_file": connectors_file.display().to_string(),
                "updated_path": unset_args.key,
                "config": config_value,
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ConfigCommand::Import(file_args) => {
            let mut configs = read_managed_connector_configs(&connectors_file)?;
            let resolved = catalog.resolve_connector(&file_args.connector).ok();
            let index = find_managed_connector_index(&configs, &file_args.connector, resolved)?;
            let import_path = file_args
                .file
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("`fwc config import` requires --file <path>"))?;
            let imported = read_json_file(import_path)?;
            let schema = resolved.and_then(|connector| connector.detail.config_schema.as_known());
            let validation_errors = validate_config_value(schema, &imported);
            if !validation_errors.is_empty() {
                return Ok(config_validation_dispatch(
                    "import",
                    &connectors_file,
                    &configs[index],
                    resolved,
                    imported,
                    validation_errors,
                ));
            }

            configs[index].config = Some(imported.clone());
            write_managed_connector_configs(&connectors_file, &configs)?;
            let entry = &configs[index];

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": "ok",
                "command": "config",
                "subcommand": "import",
                "source": "connectors-file",
                "connector": connector_descriptor_json(entry, resolved),
                "connectors_file": connectors_file.display().to_string(),
                "input_file": import_path.display().to_string(),
                "config": imported,
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ConfigCommand::Export(file_args) => {
            let configs = read_managed_connector_configs(&connectors_file)?;
            let (entry, resolved) =
                resolve_managed_connector(&catalog, &configs, &file_args.connector)?;
            let config_value = entry.config.clone().unwrap_or_else(|| json!({}));
            if let Some(path) = &file_args.file {
                write_json_file(path, &config_value)?;
            }
            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": "ok",
                "command": "config",
                "subcommand": "export",
                "source": "connectors-file",
                "connector": connector_descriptor_json(&entry, resolved),
                "connectors_file": connectors_file.display().to_string(),
                "output_file": file_args.file.as_ref().map(|path| path.display().to_string()),
                "config": config_value,
            });
            envelope.inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        ConfigCommand::Doctor(target) => {
            let configs = read_managed_connector_configs(&connectors_file)?;
            let (entry, resolved) =
                resolve_managed_connector(&catalog, &configs, &target.connector)?;
            let config_value = entry.config.clone().unwrap_or_else(|| json!({}));
            let schema = resolved.and_then(|connector| connector.detail.config_schema.as_known());
            let validation_errors = validate_config_value(schema, &config_value);
            let schema_available = schema.is_some();
            let status = if validation_errors.is_empty() {
                "ok"
            } else {
                "invalid"
            };
            let exit_code = if validation_errors.is_empty() {
                CliExitCode::Success
            } else {
                CliExitCode::Validation
            };

            let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "config");
            let mut payload = json!({
                "status": status,
                "command": "config",
                "subcommand": "doctor",
                "source": "connectors-file",
                "connector": connector_descriptor_json(&entry, resolved),
                "connectors_file": connectors_file.display().to_string(),
                "schema_available": schema_available,
                "checks": [
                    {
                        "name": "connectors_file",
                        "status": "ok",
                        "detail": format!("Loaded {}", connectors_file.display()),
                    },
                    {
                        "name": "connector_entry",
                        "status": "ok",
                        "detail": format!("Found connector entry `{}`", entry.id),
                    },
                    {
                        "name": "schema",
                        "status": if schema_available { "ok" } else { "unavailable" },
                        "detail": if schema_available {
                            "Config schema loaded from workspace discovery."
                        } else {
                            "No config schema is available from workspace discovery."
                        },
                    },
                    {
                        "name": "validation",
                        "status": if validation_errors.is_empty() { "ok" } else { "fail" },
                        "detail": if validation_errors.is_empty() {
                            "Current config satisfies all available schema checks."
                        } else {
                            "Current config failed schema validation."
                        },
                    }
                ],
                "errors": validation_errors,
                "config": config_value,
                "schema": schema,
            });
            if exit_code.is_success() {
                envelope.inject_into(&mut payload);
            }
            Ok(DispatchOutcome { payload, exit_code })
        }
    }
}

fn resolve_connectors_file_path(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.clone());
    }

    match std::env::var("FCP_HOST_CONNECTORS_FILE") {
        Ok(raw) if !raw.trim().is_empty() => Ok(PathBuf::from(raw)),
        _ => bail!(
            "No connectors file configured. Pass `--connectors-file <path>` or set `FCP_HOST_CONNECTORS_FILE`."
        ),
    }
}

fn read_managed_connector_configs(path: &PathBuf) -> Result<Vec<ManagedConnectorConfig>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read connectors file: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("invalid connectors file JSON: {}", path.display()))
}

fn write_managed_connector_configs(
    path: &PathBuf,
    configs: &[ManagedConnectorConfig],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create parent directory for connectors file: {}",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_string_pretty(configs)?;
    std::fs::write(path, format!("{encoded}\n"))
        .with_context(|| format!("failed to write connectors file: {}", path.display()))
}

fn resolve_managed_connector<'a>(
    catalog: &'a DiscoveryCatalog,
    configs: &'a [ManagedConnectorConfig],
    selector: &str,
) -> Result<(&'a ManagedConnectorConfig, Option<&'a DiscoveredConnector>)> {
    let resolved = catalog.resolve_connector(selector).ok();
    let index = find_managed_connector_index(configs, selector, resolved)?;
    Ok((&configs[index], resolved))
}

fn find_managed_connector_index(
    configs: &[ManagedConnectorConfig],
    selector: &str,
    resolved: Option<&DiscoveredConnector>,
) -> Result<usize> {
    let canonical_id = resolved.map(|connector| connector.detail.summary.id.as_str());
    configs
        .iter()
        .position(|entry| {
            canonical_id.is_some_and(|id| entry.id == id)
                || entry.id == selector
                || entry
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(selector))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("connector `{selector}` was not found in the managed connectors file")
        })
}

fn connector_descriptor_json(
    entry: &ManagedConnectorConfig,
    resolved: Option<&DiscoveredConnector>,
) -> Value {
    json!({
        "slug": resolved.map(|connector| connector.slug.clone()),
        "canonical_id": entry.id,
        "name": entry.name,
        "binary": entry.binary,
        "version": entry.version,
    })
}

fn validate_config_value(schema: Option<&Value>, payload: &Value) -> Vec<Value> {
    match schema {
        Some(schema) => {
            let (_valid, errors) = validate_payload_against_schema(payload, schema);
            errors
        }
        None => Vec::new(),
    }
}

fn config_validation_dispatch(
    subcommand: &str,
    connectors_file: &PathBuf,
    entry: &ManagedConnectorConfig,
    resolved: Option<&DiscoveredConnector>,
    attempted_config: Value,
    validation_errors: Vec<Value>,
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "invalid",
            "command": "config",
            "subcommand": subcommand,
            "source": "connectors-file",
            "message": "The requested config change would leave the connector config in an invalid state, so nothing was written.",
            "connector": connector_descriptor_json(entry, resolved),
            "connectors_file": connectors_file.display().to_string(),
            "config": attempted_config,
            "errors": validation_errors,
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn write_json_file(path: &PathBuf, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create parent directory for output file: {}",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_string_pretty(value)?;
    std::fs::write(path, format!("{encoded}\n"))
        .with_context(|| format!("failed to write JSON file: {}", path.display()))
}

fn read_json_file(path: &PathBuf) -> Result<Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON file: {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid JSON file: {}", path.display()))
}

#[derive(Debug)]
struct PreparedPackageArtifact {
    package_output: PackageOutput,
    manifest: ConnectorManifest,
    build_metadata: PackageBuildMetadata,
    verification: Vec<Value>,
    source_description: String,
}

fn install_dispatch(args: &InstallArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let artifact = match prepare_package_artifact(&args.source, args.version.as_deref()) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "install",
                    "error": {
                        "type": "invalid-install-source",
                        "message": error.to_string(),
                    },
                    "source": args.source,
                    "next_actions": [
                        "Run `fwc package --json` on a connector crate first, or pass a package directory containing package-output.json.".to_owned(),
                        "Pass a workspace connector selector such as `github` when installing from local source.".to_owned(),
                    ],
                }),
                exit_code: CliExitCode::Validation,
            });
        }
    };

    let candidate = managed_connector_from_artifact(&artifact, None);

    if args.verify_only {
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "install");
        let mut payload = json!({
            "status": "ok",
            "command": "install",
            "mode": "verify-only",
            "message": format!(
                "Verified install candidate `{}` without mutating host inventory.",
                candidate.id
            ),
            "source": artifact.source_description,
            "package": package_output_json(&artifact),
            "candidate": connector_descriptor_json(&candidate, None),
            "verification": artifact.verification,
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "install",
            json!({
                "source": args.source,
                "version": args.version,
                "verify_only": args.verify_only,
            }),
            vec![
                "fwc install <source> --host <endpoint>".to_owned(),
                "Use `--verify-only` when you only want package verification without changing a running host."
                    .to_owned(),
            ],
        ));
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let applied = match client.mutate_inventory(&HostConnectorInventoryMutationRequest {
        kind: HostConnectorInventoryMutationKind::Install,
        dry_run: false,
        connector: candidate.clone(),
    }) {
        Ok(applied) => applied,
        Err(error) => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "install",
                    "error": {
                        "type": "host-mutation-failed",
                        "message": error.to_string(),
                        "recoverable": true,
                    },
                    "host": host.endpoint,
                    "package_source": artifact.source_description,
                    "candidate": connector_descriptor_json(&candidate, None),
                    "package": package_output_json(&artifact),
                    "verification": artifact.verification,
                    "next_actions": [
                        format!("fwc status --host {}", host.endpoint),
                        format!("fwc doctor --zone z:work --host {}", host.endpoint),
                    ],
                }),
                exit_code: CliExitCode::Transport,
            });
        }
    };

    if let Some(previous) = applied.previous.as_ref() {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "warning",
                "command": "install",
                "message": format!(
                    "Host reported an existing connector entry while processing install for `{}`.",
                    previous.id
                ),
                "host": host.endpoint,
                "existing": connector_descriptor_json(previous, None),
                "candidate": connector_descriptor_json(&candidate, None),
                "response": applied,
                "next_actions": [
                    format!("fwc update {} --source {} --host {}", previous.id, args.source, host.endpoint),
                ],
            }),
            exit_code: CliExitCode::Transport,
        });
    }

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "install");
    let mut payload = json!({
        "status": "ok",
        "command": "install",
        "message": format!(
            "Installed `{}` into the live host connector inventory and applied it immediately.",
            applied.current.id
        ),
        "source": "host-admin-api",
        "host": host.endpoint,
        "package_source": artifact.source_description,
        "connectors_file": applied.connectors_file,
        "package": package_output_json(&artifact),
        "installed": connector_descriptor_json(&applied.current, None),
        "verification": artifact.verification,
        "activation": {
            "inventory_updated": true,
            "live_reload_applied": true,
            "registry_version": applied.apply.registry_version,
            "added": applied.apply.added,
            "updated": applied.apply.updated,
            "removed": applied.apply.removed,
            "unchanged": applied.apply.unchanged,
        },
        "admin_state": {
            "tracked_connectors": applied.admin_state.tracked_connectors,
            "created_connectors": applied.admin_state.created_connectors,
            "observed_updates": applied.admin_state.observed_updates,
            "drifted_connectors": applied.admin_state.drifted_connectors,
        },
        "response": applied,
        "next_actions": [
            format!("fwc status {} --host {}", candidate.id, host.endpoint),
            format!("fwc show {} --host {}", candidate.id, host.endpoint),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn update_dispatch(args: &UpdateArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "update",
            json!({
                "connector": args.connector,
                "source": args.source,
                "dry_run": args.dry_run,
            }),
            vec![
                "fwc update <connector> --host <endpoint>".to_owned(),
                "Update planning and application both require a live host so `fwc` can reason about the actual installed inventory."
                    .to_owned(),
            ],
        ));
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (host_catalog, _) = client.catalog(None)?;
    let target_connector_id = match host_catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector.summary.id.to_string(),
        Err(error) => {
            if args.connector.contains(':') {
                args.connector.clone()
            } else {
                return Ok(connector_resolution_dispatch(
                    "update",
                    &args.connector,
                    &error,
                ));
            }
        }
    };
    let source = args.source.as_deref().unwrap_or(&args.connector);
    let artifact = match prepare_package_artifact(source, None) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "update",
                    "error": {
                        "type": "invalid-update-source",
                        "message": error.to_string(),
                    },
                    "source": source,
                    "next_actions": [
                        "Run `fwc package --json` on a connector crate first, or pass a package directory containing package-output.json.".to_owned(),
                        "Pass a workspace connector selector such as `github` when updating from local source.".to_owned(),
                    ],
                }),
                exit_code: CliExitCode::Validation,
            });
        }
    };

    if artifact.manifest.connector.id.as_str() != target_connector_id {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "update",
                "error": {
                    "type": "connector-id-mismatch",
                    "message": format!(
                        "Update source resolves to `{}`, but the live host target is `{}`.",
                        artifact.manifest.connector.id,
                        target_connector_id
                    ),
                },
                "host": host.endpoint,
                "target_connector_id": target_connector_id,
                "package": package_output_json(&artifact),
            }),
            exit_code: CliExitCode::Validation,
        });
    }

    let updated = managed_connector_from_artifact(&artifact, None);
    let applied = match client.mutate_inventory(&HostConnectorInventoryMutationRequest {
        kind: HostConnectorInventoryMutationKind::Update,
        dry_run: args.dry_run,
        connector: updated.clone(),
    }) {
        Ok(applied) => applied,
        Err(error) => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "update",
                    "error": {
                        "type": "host-mutation-failed",
                        "message": error.to_string(),
                        "recoverable": true,
                    },
                    "host": host.endpoint,
                    "target_connector_id": target_connector_id,
                    "package_source": artifact.source_description,
                    "package": package_output_json(&artifact),
                    "verification": artifact.verification,
                    "next_actions": [
                        format!("fwc status --host {}", host.endpoint),
                        format!("fwc doctor --zone z:work --host {}", host.endpoint),
                    ],
                }),
                exit_code: CliExitCode::Transport,
            });
        }
    };

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "update");
    let mut payload = json!({
        "status": "ok",
        "command": "update",
        "mode": if applied.dry_run { "dry-run" } else { "apply" },
        "message": format!(
            "{} `{}` against the live host connector inventory.",
            if applied.dry_run { "Planned" } else { "Updated" },
            applied.current.id
        ),
        "source": "host-admin-api",
        "host": host.endpoint,
        "package_source": artifact.source_description,
        "connectors_file": applied.connectors_file,
        "current": applied.previous.as_ref().map(|entry| connector_descriptor_json(entry, None)),
        "updated": connector_descriptor_json(&applied.current, None),
        "package": package_output_json(&artifact),
        "verification": artifact.verification,
        "activation": {
            "inventory_updated": !applied.dry_run,
            "live_reload_applied": !applied.dry_run,
            "registry_version": applied.apply.registry_version,
            "added": applied.apply.added,
            "updated": applied.apply.updated,
            "removed": applied.apply.removed,
            "unchanged": applied.apply.unchanged,
        },
        "admin_state": {
            "tracked_connectors": applied.admin_state.tracked_connectors,
            "created_connectors": applied.admin_state.created_connectors,
            "observed_updates": applied.admin_state.observed_updates,
            "drifted_connectors": applied.admin_state.drifted_connectors,
        },
        "response": applied,
        "next_actions": [
            format!("fwc status {} --host {}", target_connector_id, host.endpoint),
            format!("fwc show {} --host {}", target_connector_id, host.endpoint),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn prepare_package_artifact(
    source: &str,
    requested_version: Option<&str>,
) -> Result<PreparedPackageArtifact> {
    let (package_output, source_description) = resolve_package_output(source)?;
    let (manifest, build_metadata, verification) =
        inspect_package_output(&package_output, requested_version)?;
    Ok(PreparedPackageArtifact {
        package_output,
        manifest,
        build_metadata,
        verification,
        source_description,
    })
}

fn resolve_package_output(source: &str) -> Result<(PackageOutput, String)> {
    let path = PathBuf::from(source);
    if path.exists() {
        let output = load_package_output_from_path(&path)?;
        return Ok((output, path.display().to_string()));
    }

    let catalog = DiscoveryCatalog::load()?;
    let connector = catalog.resolve_connector(source).map_err(|error| {
        anyhow::anyhow!(
            "`{source}` is neither an existing path nor a known workspace connector selector (kind: {:?}, suggestions: {}).",
            error.kind,
            if error.suggestions.is_empty() {
                "none".to_owned()
            } else {
                error.suggestions.join(", ")
            }
        )
    })?;
    let manifest_path = PathBuf::from(&connector.manifest_path);
    let crate_path = manifest_path.parent().with_context(|| {
        format!(
            "workspace manifest `{}` has no parent directory",
            manifest_path.display()
        )
    })?;
    let output = package_cmd::package_connector(&PackageBuildArgs {
        path: crate_path.to_path_buf(),
        output: None,
        skip_sbom: false,
        release: true,
        cargo_flags: Vec::new(),
        format: crate::package_cmd::OutputFormat::Human,
    })?;
    Ok((output, format!("workspace connector `{}`", connector.slug)))
}

fn load_package_output_from_path(path: &Path) -> Result<PackageOutput> {
    if path.is_file() {
        let file_name = path.file_name().and_then(|value| value.to_str());
        if file_name != Some(PACKAGE_OUTPUT_FILENAME) {
            bail!(
                "file source `{}` must be `{PACKAGE_OUTPUT_FILENAME}`",
                path.display()
            );
        }
        return read_package_output_metadata(path);
    }

    if !path.is_dir() {
        bail!(
            "package source `{}` is not a file or directory",
            path.display()
        );
    }

    let metadata_path = path.join(PACKAGE_OUTPUT_FILENAME);
    if metadata_path.exists() {
        return read_package_output_metadata(&metadata_path);
    }

    if path.join("Cargo.toml").exists() {
        return package_cmd::package_connector(&PackageBuildArgs {
            path: path.to_path_buf(),
            output: None,
            skip_sbom: false,
            release: true,
            cargo_flags: Vec::new(),
            format: crate::package_cmd::OutputFormat::Human,
        });
    }

    bail!(
        "directory `{}` is neither a connector crate nor a packaged connector directory containing `{PACKAGE_OUTPUT_FILENAME}`",
        path.display()
    )
}

fn read_package_output_metadata(path: &Path) -> Result<PackageOutput> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read package metadata: {}", path.display()))?;
    let mut output: PackageOutput = serde_json::from_str(&raw)
        .with_context(|| format!("invalid package metadata JSON: {}", path.display()))?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    output.output_dir = resolve_package_metadata_path(base_dir, &output.output_dir);
    output.binary_path = resolve_package_metadata_path(base_dir, &output.binary_path);
    output.manifest_path = resolve_package_metadata_path(base_dir, &output.manifest_path);
    output.build_metadata_path =
        resolve_package_metadata_path(base_dir, &output.build_metadata_path);
    output.sbom_path = output
        .sbom_path
        .as_ref()
        .map(|value| resolve_package_metadata_path(base_dir, value));
    Ok(output)
}

fn resolve_package_metadata_path(base_dir: &Path, value: &Path) -> PathBuf {
    if value.is_absolute() {
        value.to_path_buf()
    } else {
        base_dir.join(value)
    }
}

fn inspect_package_output(
    package_output: &PackageOutput,
    requested_version: Option<&str>,
) -> Result<(ConnectorManifest, PackageBuildMetadata, Vec<Value>)> {
    if !package_output.binary_path.is_file() {
        bail!(
            "packaged binary `{}` does not exist",
            package_output.binary_path.display()
        );
    }
    if !package_output.manifest_path.is_file() {
        bail!(
            "packaged manifest `{}` does not exist",
            package_output.manifest_path.display()
        );
    }
    if !package_output.build_metadata_path.is_file() {
        bail!(
            "build metadata `{}` does not exist",
            package_output.build_metadata_path.display()
        );
    }

    let manifest_raw =
        std::fs::read_to_string(&package_output.manifest_path).with_context(|| {
            format!(
                "failed to read manifest: {}",
                package_output.manifest_path.display()
            )
        })?;
    let manifest = ConnectorManifest::parse_str(&manifest_raw).with_context(|| {
        format!(
            "invalid connector manifest: {}",
            package_output.manifest_path.display()
        )
    })?;

    let build_metadata_raw = std::fs::read_to_string(&package_output.build_metadata_path)
        .with_context(|| {
            format!(
                "failed to read build metadata: {}",
                package_output.build_metadata_path.display()
            )
        })?;
    let build_metadata: PackageBuildMetadata = serde_json::from_str(&build_metadata_raw)
        .with_context(|| {
            format!(
                "invalid build metadata JSON: {}",
                package_output.build_metadata_path.display()
            )
        })?;

    let actual_sha256 = compute_file_sha256(&package_output.binary_path)?;
    if actual_sha256 != package_output.binary_sha256 {
        bail!(
            "package metadata hash mismatch for `{}`: expected {}, found {}",
            package_output.binary_path.display(),
            package_output.binary_sha256,
            actual_sha256
        );
    }

    let manifest_connector_id = manifest.connector.id.to_string();
    let manifest_version = manifest.connector.version.to_string();

    if package_output.connector_id != manifest_connector_id {
        bail!(
            "package metadata connector id mismatch: expected `{}`, found `{}` in manifest",
            package_output.connector_id,
            manifest_connector_id
        );
    }

    if package_output.version != manifest_version {
        bail!(
            "package metadata version mismatch: expected `{}`, found `{}` in manifest",
            package_output.version,
            manifest_version
        );
    }

    if let Some(expected_version) = requested_version
        && package_output.version != expected_version
    {
        bail!(
            "resolved package version `{}` does not match requested version `{expected_version}`",
            package_output.version
        );
    }

    let verification = vec![
        json!({
            "check": "binary-exists",
            "status": "ok",
            "detail": package_output.binary_path.display().to_string(),
        }),
        json!({
            "check": "manifest-valid",
            "status": "ok",
            "detail": manifest.connector.id.to_string(),
        }),
        json!({
            "check": "build-metadata-valid",
            "status": "ok",
            "detail": build_metadata.build_timestamp.clone(),
        }),
        json!({
            "check": "binary-sha256",
            "status": "ok",
            "detail": actual_sha256,
        }),
        json!({
            "check": "version",
            "status": "ok",
            "detail": manifest_version,
        }),
    ];

    Ok((manifest, build_metadata, verification))
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("failed to hash file: {}", path.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn managed_connector_from_artifact(
    artifact: &PreparedPackageArtifact,
    existing: Option<&ManagedConnectorConfig>,
) -> ManagedConnectorConfig {
    ManagedConnectorConfig {
        id: artifact.manifest.connector.id.to_string(),
        binary: artifact.package_output.binary_path.display().to_string(),
        name: Some(artifact.manifest.connector.name.clone()),
        description: Some(artifact.manifest.connector.description.clone()),
        args: existing.map_or_else(Vec::new, |entry| entry.args.clone()),
        env: existing.map_or_else(BTreeMap::new, |entry| entry.env.clone()),
        config: existing.and_then(|entry| entry.config.clone()),
        categories: existing.map_or_else(Vec::new, |entry| entry.categories.clone()),
        version: Some(artifact.manifest.connector.version.to_string()),
    }
}

fn package_output_json(artifact: &PreparedPackageArtifact) -> Value {
    json!({
        "output_dir": artifact.package_output.output_dir.display().to_string(),
        "binary_path": artifact.package_output.binary_path.display().to_string(),
        "manifest_path": artifact.package_output.manifest_path.display().to_string(),
        "build_metadata_path": artifact.package_output.build_metadata_path.display().to_string(),
        "sbom_path": artifact.package_output.sbom_path.as_ref().map(|path| path.display().to_string()),
        "connector_id": artifact.package_output.connector_id.clone(),
        "version": artifact.package_output.version.clone(),
        "binary_sha256": artifact.package_output.binary_sha256.clone(),
        "build": {
            "target_triple": artifact.build_metadata.target_triple.clone(),
            "profile": artifact.build_metadata.profile.clone(),
            "git_commit": artifact.build_metadata.git_commit.clone(),
            "git_dirty": artifact.build_metadata.git_dirty,
        },
    })
}

fn remove_invoke_binding(
    target: &mut Value,
    path: &[InvokePathSegment],
) -> std::result::Result<(), String> {
    if path.is_empty() {
        *target = Value::Null;
        return Ok(());
    }

    match &path[0] {
        InvokePathSegment::Field(name) => {
            let Some(object) = target.as_object_mut() else {
                return Err(format!("Cannot remove `{name}` from a non-object value."));
            };
            if path.len() == 1 {
                object.remove(name);
                return Ok(());
            }
            let Some(next) = object.get_mut(name) else {
                return Ok(());
            };
            remove_invoke_binding(next, &path[1..])
        }
        InvokePathSegment::Index(index) => {
            let Some(array) = target.as_array_mut() else {
                return Err(format!(
                    "Cannot remove index [{index}] from a non-array value."
                ));
            };
            if *index >= array.len() {
                return Ok(());
            }
            if path.len() == 1 {
                array.remove(*index);
                return Ok(());
            }
            remove_invoke_binding(&mut array[*index], &path[1..])
        }
    }
}

fn export_tools_dispatch(args: &ExportToolsArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("export-tools"));
        }
    } else if let Some(host) = resolved_host {
        return export_tools_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "export-tools",
            json!({
                "format": args.tool_format,
                "connector": args.connector,
                "risk_max": args.risk_max,
                "capability": args.capability,
                "output_file": args.output.as_ref().map(|path| path.display().to_string()),
            }),
            vec![
                "fwc export-tools --host <endpoint> --format mcp".to_owned(),
                "fwc export-tools --offline --format mcp".to_owned(),
            ],
        ));
    }

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

    let tools_json = export_tools::export_tools(&operations, args.tool_format, &options);
    let tool_count = operations.len();
    let connector_count = connectors.len();

    // Write to file if requested.
    if let Some(path) = &args.output {
        let content = serde_json::to_string_pretty(&tools_json)?;
        std::fs::write(path, &content)?;
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "export-tools");
        let mut payload = json!({
            "status": "ok",
            "command": "export-tools",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
            "format": args.tool_format.to_string(),
            "message": format!(
                "Exported {tool_count} tool schemas ({connector_count} connectors) to {} from workspace manifests.",
                path.display()
            ),
            "tool_count": tool_count,
            "connector_count": connector_count,
            "output_file": path.display().to_string(),
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "export-tools");
    let mut payload = json!({
        "status": "ok",
        "command": "export-tools",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "format": args.tool_format.to_string(),
        "message": format!(
            "Exported {tool_count} tool schemas from {connector_count} workspace connectors. This is an offline artifact view, not live host inventory.",
        ),
        "tool_count": tool_count,
        "connector_count": connector_count,
        "tools": tools_json,
        "next_actions": [
            "Use `fwc export-tools --host <endpoint> --format mcp` for the live host-backed inventory.".to_owned(),
            "Pipe to a file: fwc export-tools --offline --format mcp --json > tools.json",
            "Filter by risk: fwc export-tools --offline --format mcp --risk-max medium",
            "One connector: fwc export-tools --offline --format claude github",
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn export_tools_dispatch_host(args: &ExportToolsArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
    let options = export_tools::ExportOptions {
        include_safety_metadata: !args.no_safety,
        include_ai_hints: !args.no_hints,
        include_examples: !args.no_hints,
        strip_prefix: args.strip_prefix.clone(),
        risk_max: args.risk_max.clone(),
        capability_filter: args.capability.clone(),
    };
    let connectors = if let Some(selector) = &args.connector {
        match catalog.resolve_connector(selector) {
            Ok(connector) => vec![connector.clone()],
            Err(error) => {
                return Ok(connector_resolution_dispatch(
                    "export-tools",
                    selector,
                    &error,
                ));
            }
        }
    } else {
        catalog.connectors.clone()
    };

    let mut metadata_gaps = Vec::new();
    let mut operations = Vec::new();
    for connector in &connectors {
        let introspection = client.introspect(connector.summary.id.as_str())?;
        metadata_gaps.extend(host_metadata_gaps(&introspection).into_iter().map(|gap| {
            json!({
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.summary.id.as_str(),
                },
                "gap": gap,
            })
        }));
        operations.extend(
            introspection
                .tools
                .iter()
                .filter(|tool| host_tool_passes_risk_filter(tool, options.risk_max.as_deref()))
                .filter(|tool| {
                    host_tool_passes_capability_filter(tool, options.capability_filter.as_deref())
                })
                .map(host_tool_operation_info),
        );
    }

    let tools_json = export_tools::export_operation_infos(&operations, args.tool_format, &options);
    let tool_count = operations.len();
    let connector_count = connectors.len();

    if let Some(path) = &args.output {
        let content = serde_json::to_string_pretty(&tools_json)?;
        std::fs::write(path, &content)?;
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "export-tools");
        let mut payload = json!({
            "status": "ok",
            "command": "export-tools",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "format": args.tool_format.to_string(),
            "host": host,
            "message": format!(
                "Exported {tool_count} live tool schemas ({connector_count} connectors) to {}.",
                path.display()
            ),
            "tool_count": tool_count,
            "connector_count": connector_count,
            "metadata_gaps": metadata_gaps,
            "output_file": path.display().to_string(),
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "export-tools");
    let mut payload = json!({
        "status": "ok",
        "command": "export-tools",
        "source": "host-admin-api",
        "mode": "live-introspection",
        "format": args.tool_format.to_string(),
        "host": host,
        "message": format!(
            "Exported {tool_count} live tool schemas from {connector_count} connectors exposed by `fcp-host`."
        ),
        "tool_count": tool_count,
        "connector_count": connector_count,
        "metadata_gaps": metadata_gaps,
        "tools": tools_json,
        "next_actions": [
            format!("Use `fwc serve-mcp --host {host}` to expose the same live inventory over MCP."),
            format!("Use `fwc ops <connector> --host {host}` to inspect one connector before exporting again."),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code, clippy::too_many_lines)]
fn suggest_dispatch_host(args: &SuggestArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
    let (all_connectors, metadata_gaps) = load_live_discovered_connectors(&client, &catalog)?;

    if let Some(after_op) = &args.after {
        let mut related_ids: Vec<String> = Vec::new();
        let mut source_connector = String::new();
        let mut source_summary = String::new();

        for connector in &all_connectors {
            for operation in &connector.operations {
                if operation.actual_id == *after_op
                    || operation.local_id == *after_op
                    || operation.preferred_selector == *after_op
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
                    "source": "host-admin-api",
                    "mode": "live-introspection",
                    "error": {
                        "type": "operation-not-found",
                        "message": format!("Operation '{after_op}' not found in live host inventory."),
                        "selector": after_op,
                    },
                    "metadata_gaps": metadata_gaps,
                    "next_actions": [
                        "Use `fwc search '<query>' --host <endpoint>` to find the live operation.",
                        "Use `fwc ops <connector> --host <endpoint>` to list operations for a connector.",
                    ],
                }),
                exit_code: CliExitCode::UnknownCommand,
            });
        }

        let mut suggestions: Vec<Value> = Vec::new();
        for connector in &all_connectors {
            for operation in &connector.operations {
                if related_ids.iter().any(|related| {
                    related == &operation.actual_id || related == &operation.summary.capability
                }) {
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

        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "suggest");
        let mut payload = json!({
            "status": "ok",
            "command": "suggest",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "suggest_mode": "after",
            "message": format!(
                "Found {} live follow-up suggestions after '{after_op}'.",
                suggestions.len()
            ),
            "after": {
                "operation": after_op,
                "connector": source_connector,
                "summary": source_summary,
            },
            "suggestions": suggestions,
            "metadata_gaps": metadata_gaps,
            "next_actions": [
                format!("fwc schema {} <operation> --host {host}", source_connector),
                "Use `fwc suggest --goal '<next intent>' --host <endpoint>` for goal-directed search.".to_owned(),
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "suggest",
            catalog::DiscoveryDataSource::LiveHostIntrospection,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let connectors: Vec<&DiscoveredConnector> = if let Some(selector) = &args.connector {
        match catalog.resolve_connector(selector) {
            Ok(record) => all_connectors
                .iter()
                .filter(|connector| connector.slug == record.slug)
                .collect(),
            Err(error) => return Ok(connector_resolution_dispatch("suggest", selector, &error)),
        }
    } else {
        all_connectors.iter().collect()
    };

    if let Some(goal) = &args.goal {
        let filters = search::SearchFilters {
            connector: args.connector.clone(),
            risk_max: args.risk.as_deref().and_then(search::RiskCeiling::parse),
            ..Default::default()
        };
        let results = search::search_operations(&all_connectors, goal, &filters);
        let json_results = search::results_to_json(&results, args.limit);

        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "suggest");
        let mut payload = json!({
            "status": "ok",
            "command": "suggest",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "suggest_mode": "goal-directed",
            "message": format!("Found {} live operations matching goal '{goal}'.", results.len()),
            "goal": goal,
            "suggestions": json_results,
            "metadata_gaps": metadata_gaps,
            "next_actions": [
                "Use `fwc schema <connector> <operation> --host <endpoint>` to see the live input/output schema.",
                "Use `fwc simulate <connector> <operation> --host <endpoint> --file payload.json` to test safely.",
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "suggest",
            catalog::DiscoveryDataSource::LiveHostIntrospection,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let mut by_family: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let risk_ceiling = args.risk.as_deref().and_then(search::RiskCeiling::parse);
    for connector in &connectors {
        for operation in &connector.operations {
            if let Some(ceiling) = risk_ceiling
                && !ceiling.allows(&operation.summary.risk_level)
            {
                continue;
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
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "suggest");
        let mut payload = json!({
            "status": "ok",
            "command": "suggest",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "suggest_mode": "overview-grouped",
            "message": format!(
                "Grouped {} live action families across {} connectors.",
                by_family.len(), connectors.len()
            ),
            "families": grouped,
            "metadata_gaps": metadata_gaps,
            "next_actions": [
                "Use `fwc suggest --goal '<intent>' --host <endpoint>` for goal-directed search.",
                "Use `fwc search '<query>' --host <endpoint>` for keyword-based live search.",
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "suggest",
            catalog::DiscoveryDataSource::LiveHostIntrospection,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let mut flat: Vec<Value> = Vec::new();
    for ops in by_family.values() {
        flat.extend(ops.iter().cloned());
    }
    flat.truncate(args.limit);

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "suggest");
    let mut payload = json!({
        "status": "ok",
        "command": "suggest",
        "source": "host-admin-api",
        "mode": "live-introspection",
        "suggest_mode": "overview",
        "message": format!(
            "Showing {} of {} live available operations across {} connectors.",
            flat.len(),
            by_family.values().map(Vec::len).sum::<usize>(),
            connectors.len(),
        ),
        "suggestions": flat,
        "action_families": by_family.keys().collect::<Vec<_>>(),
        "metadata_gaps": metadata_gaps,
        "next_actions": [
            "Use `fwc suggest --goal '<intent>' --host <endpoint>` for goal-directed search.",
            "Use `fwc suggest --grouped --host <endpoint>` to see operations grouped by action family.",
            "Use `fwc suggest --connector <name> --host <endpoint>` to narrow to one connector.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "suggest",
        catalog::DiscoveryDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code, clippy::too_many_lines)]
fn suggest_dispatch(args: &SuggestArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("suggest"));
        }
    } else if let Some(host) = resolved_host {
        return suggest_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "suggest",
            json!({
                "goal": args.goal,
                "connector": args.connector,
                "after": args.after,
                "risk": args.risk,
                "grouped": args.grouped,
                "limit": args.limit,
            }),
            vec![
                "fwc suggest --goal '<intent>' --host <endpoint>".to_owned(),
                "fwc suggest --goal '<intent>' --offline".to_owned(),
            ],
        ));
    }

    let catalog = DiscoveryCatalog::load()?;

    if let Some(after_op) = &args.after {
        return suggest_after_dispatch(&catalog, after_op, args);
    }

    if let Some(goal) = &args.goal {
        let filters = search::SearchFilters {
            connector: args.connector.clone(),
            risk_max: args.risk.as_deref().and_then(search::RiskCeiling::parse),
            ..Default::default()
        };
        let results = search::search_operations(catalog.connectors(), goal, &filters);
        let json_results = search::results_to_json(&results, args.limit);

        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "suggest");
        let mut payload = json!({
            "status": "ok",
            "command": "suggest",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
            "suggest_mode": "goal-directed",
            "message": format!("Found {} operations matching goal '{goal}'.", results.len()),
            "goal": goal,
            "suggestions": json_results,
            "next_actions": [
                "Use `fwc schema <connector> <operation> --offline` to see input/output schema.",
                "Use `fwc simulate <connector> <operation> --file payload.json` to test safely.",
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "suggest",
            catalog::DiscoveryDataSource::WorkspaceManifest,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

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
            if let Some(ceiling) = risk_ceiling
                && !ceiling.allows(&operation.summary.risk_level)
            {
                continue;
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
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "suggest");
        let mut payload = json!({
            "status": "ok",
            "command": "suggest",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
            "suggest_mode": "overview-grouped",
            "message": format!(
                "Grouped {} action families across {} connectors.",
                by_family.len(), connectors.len()
            ),
            "families": grouped,
            "next_actions": [
                "Use `fwc suggest --goal '<intent>' --offline` for goal-directed search.",
                "Use `fwc search '<query>' --offline` for keyword-based search.",
            ],
        });
        attach_discovery_provenance(
            &mut payload,
            "suggest",
            catalog::DiscoveryDataSource::WorkspaceManifest,
        );
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    for ops in by_family.values() {
        flat.extend(ops.iter().cloned());
    }
    flat.truncate(args.limit);

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "suggest");
    let mut payload = json!({
        "status": "ok",
        "command": "suggest",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "suggest_mode": "overview",
        "message": format!(
            "Showing {} of {} available operations across {} connectors.",
            flat.len(),
            by_family.values().map(Vec::len).sum::<usize>(),
            connectors.len(),
        ),
        "suggestions": flat,
        "action_families": by_family.keys().collect::<Vec<_>>(),
        "next_actions": [
            "Use `fwc suggest --goal '<intent>' --offline` for goal-directed search.",
            "Use `fwc suggest --grouped --offline` to see operations grouped by action family.",
            "Use `fwc suggest --connector <name> --offline` to narrow to one connector.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "suggest",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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
                "source": "workspace-manifests",
                "mode": "offline-artifact",
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "suggest");
    let mut payload = json!({
        "status": "ok",
        "command": "suggest",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
        "suggest_mode": "after",
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
            format!("fwc schema {} <operation> --offline", source_connector),
            "Use `fwc suggest --goal '<next intent>' --offline` for goal-directed search.",
        ],
    });
    attach_discovery_provenance(
        &mut payload,
        "suggest",
        catalog::DiscoveryDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

fn template_dispatch_host(args: &TemplateArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
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
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let operation = match resolve_host_tool(&introspection.tools, &args.operation) {
        Ok(operation) => operation,
        Err(error) => {
            return Ok(host_operation_resolution_dispatch(
                "template",
                &connector.slug,
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

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "template");
    let mut payload = json!({
        "status": "ok",
        "command": "template",
        "source": "host-admin-api",
        "mode": "live-introspection",
        "message": format!(
            "Generated {} live template for `{}.{}`.",
            if args.required_only { "required-only" } else { "full" },
            connector.slug,
            operation.name,
        ),
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
        },
        "operation": {
            "selector": &operation.name,
            "canonical_id": &operation.name,
            "summary": &operation.description,
        },
        "metadata_gaps": host_metadata_gaps(&introspection),
        "template": template_json,
        "fill_applied": !fill.is_empty(),
        "required_only": args.required_only,
        "next_actions": [
            format!("fwc schema {} {} --host {host}", connector.slug, operation.name),
            format!("fwc simulate {} {} --host {host} --file payload.json", connector.slug, operation.name),
        ],
    });
    attach_template_provenance(
        &mut payload,
        "template",
        catalog::TemplateDataSource::LiveHostIntrospection,
    );
    envelope.inject_into(&mut payload);

    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn template_dispatch(args: &TemplateArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("template"));
        }
    } else if let Some(host) = resolved_host {
        return template_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "template",
            json!({
                "connector": &args.connector,
                "operation": &args.operation,
                "required_only": args.required_only,
            }),
            vec![
                format!(
                    "fwc template {} {} --host <endpoint>",
                    args.connector, args.operation
                ),
                format!(
                    "fwc template {} {} --offline",
                    args.connector, args.operation
                ),
            ],
        ));
    }

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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "template");
    let mut payload = json!({
        "status": "ok",
        "command": "template",
        "source": "workspace-manifests",
        "mode": "offline-artifact",
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
            format!("fwc schema {} {} --offline", connector.slug, operation.preferred_selector),
            format!("fwc simulate {} {} --file payload.json", connector.slug, operation.preferred_selector),
        ],
    });
    attach_template_provenance(
        &mut payload,
        "template",
        catalog::TemplateDataSource::WorkspaceManifest,
    );
    envelope.inject_into(&mut payload);

    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn validate_dispatch_host(args: &ValidateArgs, host: &str) -> Result<DispatchOutcome> {
    let client = HostAdminClient::new(host)?;
    let (catalog, _) = client.catalog(None)?;
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
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let operation = match resolve_host_tool(&introspection.tools, &args.operation) {
        Ok(operation) => operation,
        Err(error) => {
            return Ok(host_operation_resolution_dispatch(
                "validate",
                &connector.slug,
                &args.operation,
                &error,
            ));
        }
    };

    let input: Value = if let Some(json_str) = &args.input {
        serde_json::from_str(json_str)?
    } else if let Some(path) = &args.input_file {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        let mut payload = json!({
            "status": "error",
            "command": "validate",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "error": {
                "type": "missing-input",
                "message": "No input provided. Use --input or --input-file.",
            },
            "next_actions": [
                format!("fwc validate {} {} --host {host} --input '{{...}}'", connector.slug, operation.name),
                format!("fwc template {} {} --host {host}", connector.slug, operation.name),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "validate",
            catalog::TemplateDataSource::LiveHostIntrospection,
        );
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::UnknownCommand,
        });
    };

    let result = validate::validate(&input, &operation.input_schema);
    if result.is_valid() {
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "validate");
        let mut payload = json!({
            "status": "ok",
            "command": "validate",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "message": format!("Input is valid for live `{}`.`{}`.", connector.slug, operation.name),
            "connector": &connector.slug,
            "operation": &operation.name,
            "valid": true,
            "metadata_gaps": host_metadata_gaps(&introspection),
            "next_actions": [
                format!("fwc simulate {} {} --host {host} --input '...'", connector.slug, operation.name),
                format!("fwc invoke {} {} --host {host} --input '...'", connector.slug, operation.name),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "validate",
            catalog::TemplateDataSource::LiveHostIntrospection,
        );
        envelope.inject_into(&mut payload);

        Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        })
    } else {
        let error_details: Vec<Value> = result
            .errors
            .iter()
            .map(|error| {
                json!({
                    "path": error.path,
                    "message": error.message,
                    "suggestion": error.suggestion,
                })
            })
            .collect();

        let mut payload = json!({
            "status": "error",
            "command": "validate",
            "source": "host-admin-api",
            "mode": "live-introspection",
            "message": format!(
                "Validation failed for live `{}.{}`: {} error(s).",
                connector.slug, operation.name, result.errors.len()
            ),
            "connector": &connector.slug,
            "operation": &operation.name,
            "valid": false,
            "error_count": result.errors.len(),
            "errors": error_details,
            "metadata_gaps": host_metadata_gaps(&introspection),
            "next_actions": [
                format!("fwc template {} {} --host {host}", connector.slug, operation.name),
                format!("fwc schema {} {} --host {host}", connector.slug, operation.name),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "validate",
            catalog::TemplateDataSource::LiveHostIntrospection,
        );
        Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::UnknownCommand,
        })
    }
}

fn validate_dispatch(args: &ValidateArgs, host: Option<&str>) -> Result<DispatchOutcome> {
    let resolved_host = resolve_host_config(host)?;
    if args.offline {
        if resolved_host.is_some() {
            return Ok(conflicting_catalog_mode_dispatch("validate"));
        }
    } else if let Some(host) = resolved_host {
        return validate_dispatch_host(args, &host.endpoint);
    } else {
        return Ok(missing_host_dispatch(
            "validate",
            json!({
                "connector": &args.connector,
                "operation": &args.operation,
                "input_file": args.input_file.as_ref().map(|path| path.display().to_string()),
            }),
            vec![
                format!(
                    "fwc validate {} {} --host <endpoint> --input '{{...}}'",
                    args.connector, args.operation
                ),
                format!(
                    "fwc validate {} {} --offline --input '{{...}}'",
                    args.connector, args.operation
                ),
            ],
        ));
    }

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
        let mut payload = json!({
            "status": "error",
            "command": "validate",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
            "error": {
                "type": "missing-input",
                "message": "No input provided. Use --input or --input-file.",
            },
            "next_actions": [
                format!("fwc validate {} {} --offline --input '{{...}}'", connector.slug, operation.preferred_selector),
                format!("fwc template {} {} --offline", connector.slug, operation.preferred_selector),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "validate",
            catalog::TemplateDataSource::WorkspaceManifest,
        );
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::UnknownCommand,
        });
    };

    let result = validate::validate(&input, &operation.input_schema);

    if result.is_valid() {
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "validate");
        let mut payload = json!({
            "status": "ok",
            "command": "validate",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
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
        });
        attach_template_provenance(
            &mut payload,
            "validate",
            catalog::TemplateDataSource::WorkspaceManifest,
        );
        envelope.inject_into(&mut payload);

        Ok(DispatchOutcome {
            payload,
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

        let mut payload = json!({
            "status": "error",
            "command": "validate",
            "source": "workspace-manifests",
            "mode": "offline-artifact",
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
                format!("fwc template {} {} --offline", connector.slug, operation.preferred_selector),
                format!("fwc schema {} {} --offline", connector.slug, operation.preferred_selector),
            ],
        });
        attach_template_provenance(
            &mut payload,
            "validate",
            catalog::TemplateDataSource::WorkspaceManifest,
        );
        Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::UnknownCommand,
        })
    }
}

#[derive(Debug, Clone)]
enum InvokePathSegment {
    Field(String),
    Index(usize),
}

#[derive(Debug)]
struct PreparedInvokeInput {
    payload: Value,
    primary_source: &'static str,
    sources: Vec<Value>,
    binding_count: usize,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct InvokeInputError {
    error_type: &'static str,
    message: String,
    next_actions: Vec<String>,
    details: Option<Value>,
}

#[derive(Debug, Clone)]
struct ResolvedLiveAuth {
    capability_token: CapabilityToken,
    approval_tokens: Vec<ApprovalToken>,
    principal_hint: Option<String>,
}

#[derive(Debug)]
enum LiveAuthError {
    MissingCapabilityToken,
    ConflictingCapabilityTokenSources,
    InvalidCapabilityToken { source: String, message: String },
    InvalidApprovalToken { source: String, message: String },
}

impl LiveAuthError {
    const fn error_type(&self) -> &'static str {
        match self {
            Self::MissingCapabilityToken => "missing-capability-token",
            Self::ConflictingCapabilityTokenSources => "ambiguous-capability-token-source",
            Self::InvalidCapabilityToken { .. } => "invalid-capability-token",
            Self::InvalidApprovalToken { .. } => "invalid-approval-token",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::MissingCapabilityToken => "Live host execution requires a real capability token. `fwc` will not fabricate one.".to_owned(),
            Self::ConflictingCapabilityTokenSources => "Specify either `--capability-token` or `--capability-token-file`, not both.".to_owned(),
            Self::InvalidCapabilityToken { source, message } => {
                format!("Failed to parse the capability token from {source}: {message}")
            }
            Self::InvalidApprovalToken { source, message } => {
                format!("Failed to parse an approval token from {source}: {message}")
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ApprovalTokenEnvelope {
    One(ApprovalToken),
    Many(Vec<ApprovalToken>),
}

impl ApprovalTokenEnvelope {
    fn into_tokens(self) -> Vec<ApprovalToken> {
        match self {
            Self::One(token) => vec![token],
            Self::Many(tokens) => tokens,
        }
    }
}

fn resolve_live_auth(args: &LiveAuthArgs) -> std::result::Result<ResolvedLiveAuth, LiveAuthError> {
    let capability_token = match (&args.capability_token, &args.capability_token_file) {
        (Some(_), Some(_)) => Err(LiveAuthError::ConflictingCapabilityTokenSources),
        (Some(raw), None) => parse_capability_token_str(raw, "--capability-token"),
        (None, Some(path)) => parse_capability_token_file(path),
        (None, None) => Err(LiveAuthError::MissingCapabilityToken),
    }?;

    let mut approval_tokens = Vec::new();
    for raw in &args.approval_token {
        approval_tokens.extend(parse_approval_tokens_str(raw, "--approval-token")?);
    }
    for path in &args.approval_token_file {
        approval_tokens.extend(parse_approval_tokens_file(path)?);
    }

    let principal_hint = capability_token
        .raw
        .claims_unverified()
        .ok()
        .and_then(|claims| claims.get_subject().map(ToOwned::to_owned));

    Ok(ResolvedLiveAuth {
        capability_token,
        approval_tokens,
        principal_hint,
    })
}

fn parse_capability_token_file(path: &Path) -> std::result::Result<CapabilityToken, LiveAuthError> {
    let bytes = std::fs::read(path).map_err(|error| LiveAuthError::InvalidCapabilityToken {
        source: format!("`{}`", path.display()),
        message: error.to_string(),
    })?;
    parse_capability_token_bytes(&bytes, &format!("`{}`", path.display()))
}

fn parse_capability_token_bytes(
    bytes: &[u8],
    source: &str,
) -> std::result::Result<CapabilityToken, LiveAuthError> {
    if let Ok(raw) = std::str::from_utf8(bytes) {
        let trimmed = raw.trim();
        if !trimmed.is_empty()
            && let Ok(token) = parse_capability_token_str(trimmed, source)
        {
            return Ok(token);
        }
    }

    let raw =
        CoseToken::from_cbor(bytes).map_err(|error| LiveAuthError::InvalidCapabilityToken {
            source: source.to_owned(),
            message: error.to_string(),
        })?;
    Ok(CapabilityToken { raw })
}

fn parse_capability_token_str(
    raw: &str,
    source: &str,
) -> std::result::Result<CapabilityToken, LiveAuthError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(LiveAuthError::InvalidCapabilityToken {
            source: source.to_owned(),
            message: "token payload is empty".to_owned(),
        });
    }

    if let Ok(token) = serde_json::from_str::<CapabilityToken>(trimmed) {
        return Ok(token);
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .map_err(|error| LiveAuthError::InvalidCapabilityToken {
            source: source.to_owned(),
            message: format!(
                "{error}. Expected base64 COSE bytes, a JSON string, or a JSON byte array."
            ),
        })?;
    parse_capability_token_bytes(&bytes, source)
}

fn parse_approval_tokens_file(
    path: &Path,
) -> std::result::Result<Vec<ApprovalToken>, LiveAuthError> {
    let raw =
        std::fs::read_to_string(path).map_err(|error| LiveAuthError::InvalidApprovalToken {
            source: format!("`{}`", path.display()),
            message: error.to_string(),
        })?;
    parse_approval_tokens_str(&raw, &format!("`{}`", path.display()))
}

fn parse_approval_tokens_str(
    raw: &str,
    source: &str,
) -> std::result::Result<Vec<ApprovalToken>, LiveAuthError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(LiveAuthError::InvalidApprovalToken {
            source: source.to_owned(),
            message: "approval token payload is empty".to_owned(),
        });
    }

    serde_json::from_str::<ApprovalTokenEnvelope>(trimmed)
        .map(ApprovalTokenEnvelope::into_tokens)
        .map_err(|error| LiveAuthError::InvalidApprovalToken {
            source: source.to_owned(),
            message: format!(
                "{error}. Expected a JSON approval token object or an array of approval tokens."
            ),
        })
}

fn live_auth_dispatch(
    command: &str,
    error: &LiveAuthError,
    next_actions: &[String],
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": command,
            "error": {
                "type": error.error_type(),
                "message": error.message(),
                "recoverable": true,
            },
            "next_actions": next_actions,
        }),
        exit_code: CliExitCode::Validation,
    }
}

fn derive_live_request_id(
    connector_id: &str,
    operation_name: &str,
    zone: &str,
    payload: &Value,
    idempotency_key: Option<&str>,
    scope_salt: Option<&str>,
) -> Result<RequestId> {
    let payload_bytes = to_deterministic_cbor(payload)
        .map_err(|error| anyhow::anyhow!("failed to canonicalize request payload: {error}"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fwc-live-request-v1");
    hasher.update(connector_id.as_bytes());
    hasher.update(operation_name.as_bytes());
    hasher.update(zone.as_bytes());
    hasher.update(&payload_bytes);
    if let Some(key) = idempotency_key {
        hasher.update(key.as_bytes());
    }
    if let Some(salt) = scope_salt {
        hasher.update(salt.as_bytes());
    }

    let digest = hasher.finalize().to_hex().to_string();
    Ok(RequestId::new(format!("req_{}", &digest[..32])))
}

fn invoke_dispatch(
    command: &str,
    args: &InvokeArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    if let Some(host) = resolve_host_config(explicit_host)? {
        return invoke_dispatch_host(command, args, &host);
    }
    invoke_dispatch_without_host(command, args)
}

#[allow(clippy::too_many_lines)]
fn invoke_dispatch_host(
    command: &str,
    args: &InvokeArgs,
    host: &ResolvedHostConfig,
) -> Result<DispatchOutcome> {
    let auth = match resolve_live_auth(&args.auth) {
        Ok(auth) => auth,
        Err(error) => {
            return Ok(live_auth_dispatch(
                command,
                &error,
                &[
                    format!(
                        "fwc {command} {} {} --host {} --capability-token-file <token.cbor> --input '{{...}}'",
                        args.connector, args.operation, host.endpoint
                    ),
                    "Provide real approval tokens with `--approval-token-file` when the operation requires explicit approval.".to_owned(),
                ],
            ));
        }
    };

    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                command,
                &args.connector,
                &error,
            ));
        }
    };
    let introspection = client.introspect(connector.summary.id.as_str())?;
    let operation = match resolve_host_tool(&introspection.tools, &args.operation) {
        Ok(operation) => operation,
        Err(error) => {
            return Ok(host_operation_resolution_dispatch(
                command,
                &connector.slug,
                &args.operation,
                &error,
            ));
        }
    };

    let prepared = match prepare_invoke_input(command, args, &operation.input_schema) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(host_invoke_input_error_dispatch(
                command, args, connector, operation, error,
            ));
        }
    };

    let validation = validate::validate(&prepared.payload, &operation.input_schema);
    let valid = validation.is_valid();
    let validation_errors = validation
        .errors
        .iter()
        .map(|error| {
            json!({
                "path": error.path,
                "message": error.message,
                "suggestion": error.suggestion,
            })
        })
        .collect::<Vec<_>>();
    let payload_preview = invoke_payload_preview(&prepared.payload);
    let payload_json = serde_json::to_string(&prepared.payload)?;
    let PreparedInvokeInput {
        payload: prepared_payload,
        primary_source,
        sources,
        binding_count,
        warnings,
    } = prepared;

    let zone = resolved_zone(args.zone.as_deref(), host);
    let zone_id: ZoneId = zone.parse().map_err(|error| {
        anyhow::anyhow!("`{zone}` is not a valid FCP zone for `{command}`: {error}")
    })?;
    let connector_id: ConnectorId = connector.summary.id.as_str().parse().map_err(|error| {
        anyhow::anyhow!(
            "host connector id `{}` is not canonical: {error}",
            connector.summary.id
        )
    })?;
    let operation_id: OperationId = operation.name.parse().map_err(|error| {
        anyhow::anyhow!(
            "host operation id `{}` is not canonical: {error}",
            operation.name
        )
    })?;
    let request_id = derive_live_request_id(
        connector.summary.id.as_str(),
        &operation.name,
        &zone,
        &prepared_payload,
        args.idempotency_key.as_deref(),
        None,
    )?;
    let effective_principal = args
        .principal
        .clone()
        .or_else(|| auth.principal_hint.clone());

    let mut payload = json!({
        "status": if valid { "ready" } else { "error" },
        "command": command,
        "source": "host-admin-api",
        "phase": "input-authoring",
        "message": if valid {
            format!(
                "Prepared a live `{command}` request for `{}.{}` against `fcp-host`.",
                connector.slug, operation.name
            )
        } else {
            format!(
                "Prepared a live `{command}` request for `{}.{}`, but the payload fails schema validation before host execution.",
                connector.slug, operation.name
            )
        },
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
            "name": &connector.summary.name,
        },
        "operation": {
            "requested_selector": &args.operation,
            "selector": &operation.name,
            "canonical_id": &operation.name,
            "summary": &operation.description,
            "capability": operation.capability.as_str(),
            "risk_level": risk_level_label(operation.risk_level),
            "safety_tier": safety_tier_label(operation.safety_tier),
            "approval_mode": &operation.approval_mode,
            "supports_simulate": operation.supports_simulate,
        },
        "request": {
            "zone": &zone,
            "principal": &effective_principal,
            "request_id": request_id.to_string(),
            "idempotency_key": args.idempotency_key.clone(),
            "deadline_ms": args.deadline_ms,
            "approval_token_count": auth.approval_tokens.len(),
        },
        "input_authoring": {
            "primary_source": primary_source,
            "sources": sources,
            "binding_count": binding_count,
            "warnings": warnings,
            "payload": &prepared_payload,
            "payload_preview": payload_preview,
            "required_template": schema_nav::scaffold_template(&operation.input_schema),
            "examples": operation.examples.iter().take(2).collect::<Vec<_>>(),
            "validation": {
                "valid": valid,
                "error_count": validation_errors.len(),
                "errors": validation_errors,
            },
        },
    });
    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "invoke");

    if !valid {
        payload["error"] = json!({
            "type": "invalid-input-payload",
            "message": format!(
                "Local schema validation failed for `{}.{}`; the live host call was not attempted.",
                connector.slug, operation.name
            ),
            "recoverable": true,
        });
        payload["next_actions"] = json!([
            format!(
                "fwc schema {} {} --host {}",
                connector.slug, operation.name, host.endpoint
            ),
            format!(
                "fwc validate {} {} --input '{}'",
                connector.slug, operation.name, payload_json
            ),
            format!("fwc template {} {}", connector.slug, operation.name),
        ]);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Validation,
        });
    }

    let preflight_request = HostPreflightRequest {
        request_id: request_id.clone(),
        connector_id: connector_id.clone(),
        operation: operation.name.clone(),
        params: Some(prepared_payload.clone()),
        principal: effective_principal,
        zone_id: Some(zone_id.clone()),
        capability_token: Some(auth.capability_token.clone()),
        approval_tokens: auth.approval_tokens.clone(),
    };
    let preflight = client.preflight(&preflight_request)?;
    payload["preflight"] = serde_json::to_value(&preflight)?;

    if command == "simulate" {
        let history_status = if preflight.allowed {
            history::OpStatus::Simulated
        } else {
            history::OpStatus::Denied
        };
        let latency_ms = 0;
        payload["status"] = json!(if preflight.allowed { "ok" } else { "denied" });
        payload["phase"] = json!("preflight");
        payload["message"] = json!(if preflight.allowed {
            format!(
                "Evaluated a real preflight for `{}.{}` against live host policy and current connector state.",
                connector.slug, operation.name
            )
        } else {
            format!(
                "Live preflight denied `{}.{}` before execution.",
                connector.slug, operation.name
            )
        });
        payload["next_actions"] = json!(if preflight.allowed {
            vec![format!(
                "fwc invoke {} {} --host {} --zone {} --input '{}'",
                connector.slug, operation.name, host.endpoint, zone, payload_json
            )]
        } else {
            vec![
                format!("fwc status {} --host {}", connector.slug, host.endpoint),
                format!(
                    "fwc schema {} {} --host {}",
                    connector.slug, operation.name, host.endpoint
                ),
            ]
        });
        let _ = append_history_entry(
            history_status,
            connector.summary.id.as_str(),
            &operation.name,
            Some(zone.as_str()),
            &prepared_payload,
            Some(&serde_json::to_value(&preflight)?),
            preflight.reason.clone(),
            args.idempotency_key.as_deref(),
            latency_ms,
        );
        if preflight.allowed {
            envelope.inject_into(&mut payload);
        }
        return Ok(DispatchOutcome {
            payload,
            exit_code: if preflight.allowed {
                CliExitCode::Success
            } else {
                CliExitCode::PolicyDenied
            },
        });
    }

    if !preflight.allowed {
        let reason = preflight
            .reason
            .clone()
            .unwrap_or_else(|| "preflight denied invoke request".to_owned());
        let _ = append_history_entry(
            history::OpStatus::Denied,
            connector.summary.id.as_str(),
            &operation.name,
            Some(zone.as_str()),
            &prepared_payload,
            Some(&serde_json::to_value(&preflight)?),
            Some(reason.clone()),
            args.idempotency_key.as_deref(),
            0,
        );
        payload["status"] = json!("denied");
        payload["phase"] = json!("preflight");
        payload["message"] = json!(format!(
            "Live preflight denied `{}.{}` before execution.",
            connector.slug, operation.name
        ));
        payload["error"] = json!({
            "type": "policy-denied",
            "message": reason,
            "recoverable": true,
        });
        payload["next_actions"] = json!([
            format!("fwc status {} --host {}", connector.slug, host.endpoint),
            format!(
                "fwc simulate {} {} --host {}",
                connector.slug, operation.name, host.endpoint
            ),
        ]);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::PolicyDenied,
        });
    }

    let invoke_request = InvokeRequest {
        r#type: "invoke".to_owned(),
        id: request_id,
        connector_id,
        operation: operation_id,
        zone_id,
        input: prepared_payload.clone(),
        capability_token: auth.capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: args.idempotency_key.clone(),
        lease_seq: None,
        deadline_ms: args.deadline_ms,
        correlation_id: None,
        provenance: None,
        approval_tokens: auth.approval_tokens,
    };
    let started_at = std::time::Instant::now();
    let response = client.invoke(&invoke_request)?;
    let latency_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let response_value = serde_json::to_value(&response)?;
    let history_status = match response.status {
        InvokeStatus::Ok => history::OpStatus::Success,
        InvokeStatus::Error => history::OpStatus::Error,
    };
    let _ = append_history_entry(
        history_status,
        connector.summary.id.as_str(),
        &operation.name,
        Some(zone.as_str()),
        &prepared_payload,
        Some(&response_value),
        response.error.as_ref().map(ToString::to_string),
        args.idempotency_key.as_deref(),
        latency_ms,
    );

    payload["phase"] = json!("execution");
    payload["status"] = json!(match response.status {
        InvokeStatus::Ok => "ok",
        InvokeStatus::Error => "error",
    });
    payload["message"] = json!(match response.status {
        InvokeStatus::Ok => format!(
            "Executed `{}.{}` through `fcp-host`.",
            connector.slug, operation.name
        ),
        InvokeStatus::Error => format!(
            "`fcp-host` ran `{}.{}` and the connector returned an error response.",
            connector.slug, operation.name
        ),
    });
    payload["response"] = response_value;
    payload["next_actions"] = json!(match response.status {
        InvokeStatus::Ok => vec![
            format!("fwc history --connector {}", connector.slug),
            format!("fwc status {} --host {}", connector.slug, host.endpoint),
        ],
        InvokeStatus::Error => vec![
            format!(
                "fwc simulate {} {} --host {}",
                connector.slug, operation.name, host.endpoint
            ),
            format!("fwc status {} --host {}", connector.slug, host.endpoint),
        ],
    });

    if matches!(response.status, InvokeStatus::Ok) {
        envelope.inject_into(&mut payload);
    }
    Ok(DispatchOutcome {
        payload,
        exit_code: match response.status {
            InvokeStatus::Ok => CliExitCode::Success,
            InvokeStatus::Error => CliExitCode::Connector,
        },
    })
}

#[allow(clippy::too_many_lines)]
fn invoke_dispatch_without_host(command: &str, args: &InvokeArgs) -> Result<DispatchOutcome> {
    let catalog = DiscoveryCatalog::load()?;
    let connector = match catalog.resolve_connector(&args.connector) {
        Ok(connector) => connector,
        Err(error) => {
            return Ok(connector_resolution_dispatch(
                command,
                &args.connector,
                &error,
            ));
        }
    };

    let operation = match connector.resolve_operation(&args.operation) {
        Ok(operation) => operation,
        Err(error) => {
            return Ok(operation_resolution_dispatch(
                command,
                connector,
                &args.operation,
                &error,
            ));
        }
    };

    let prepared = match prepare_invoke_input(command, args, &operation.input_schema) {
        Ok(prepared) => prepared,
        Err(error) => {
            return Ok(invoke_input_error_dispatch(
                command, args, connector, operation, error,
            ));
        }
    };

    let validation = validate::validate(&prepared.payload, &operation.input_schema);
    let valid = validation.is_valid();
    let validation_errors = validation
        .errors
        .iter()
        .map(|error| {
            json!({
                "path": error.path,
                "message": error.message,
                "suggestion": error.suggestion,
            })
        })
        .collect::<Vec<_>>();
    let validation_error_count = validation_errors.len();
    let payload_preview = invoke_payload_preview(&prepared.payload);
    let payload_json = serde_json::to_string(&prepared.payload)?;
    let PreparedInvokeInput {
        payload: prepared_payload,
        primary_source,
        sources,
        binding_count,
        warnings,
    } = prepared;

    let scaffold = schema_nav::scaffold_template(&operation.input_schema);
    let contract =
        catalog::planned_payload(command, &serde_json::to_value(args)?)["contract"].clone();
    let captures = serde_json::to_value(args)?;
    let examples = operation
        .examples
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let exit_code = if valid {
        CliExitCode::Transport
    } else {
        CliExitCode::Validation
    };

    let mut payload = json!({
        "status": "error",
        "command": command,
        "phase": "input-authoring",
        "message": if valid {
            format!(
                "Prepared a schema-aware `{command}` payload for `{}.{}`, but no live host endpoint is configured so `fwc` refuses to fake execution.",
                connector.slug, operation.preferred_selector
            )
        } else {
            format!(
                "Prepared a schema-aware `{command}` payload for `{}.{}`, but the payload still fails local schema validation and no live host endpoint is configured.",
                connector.slug, operation.preferred_selector
            )
        },
        "captures": captures,
        "contract": contract,
        "connector": {
            "slug": &connector.slug,
            "canonical_id": &connector.detail.summary.id,
            "name": &connector.detail.summary.name,
        },
        "operation": {
            "requested_selector": &args.operation,
            "selector": &operation.preferred_selector,
            "canonical_id": &operation.actual_id,
            "summary": &operation.summary.summary,
            "capability": &operation.summary.capability,
            "risk_level": &operation.summary.risk_level,
            "safety_tier": &operation.summary.safety_tier,
            "approval_mode": &operation.approval_mode,
        },
        "input_authoring": {
            "primary_source": primary_source,
            "sources": sources,
            "binding_count": binding_count,
            "warnings": warnings,
            "payload": prepared_payload,
            "payload_preview": payload_preview,
            "required_template": scaffold,
            "examples": examples,
            "validation": {
                "valid": valid,
                "error_count": validation_error_count,
                "errors": validation_errors,
            },
        },
        "next_actions": if valid {
            vec![
                format!("fwc {} {} {} --host <endpoint> --input '{}'", command, connector.slug, operation.preferred_selector, payload_json),
                format!("fwc schema {} {}", connector.slug, operation.preferred_selector),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context.".to_owned(),
            ]
        } else {
            vec![
                format!("fwc schema {} {} --required-only", connector.slug, operation.preferred_selector),
                format!("fwc template {} {}", connector.slug, operation.preferred_selector),
                format!("fwc validate {} {} --input '{{...}}'", connector.slug, operation.preferred_selector),
            ]
        },
    });

    payload["error"] = json!({
        "type": if valid { "missing-host-endpoint" } else { "invalid-input-payload" },
        "message": if valid {
            format!(
                "No live host endpoint is configured for `{command}`. `fwc` will not fabricate connector execution."
            )
        } else {
            format!(
                "Local schema validation failed for `{}.{}` and the live host call was not attempted.",
                connector.slug, operation.preferred_selector
            )
        },
        "recoverable": true,
    });

    Ok(DispatchOutcome { payload, exit_code })
}

fn host_invoke_input_error_dispatch(
    command: &str,
    args: &InvokeArgs,
    connector: &HostConnectorRecord,
    operation: &HostToolDescriptor,
    error: InvokeInputError,
) -> DispatchOutcome {
    let InvokeInputError {
        error_type,
        message,
        next_actions,
        details,
    } = error;

    let mut payload = json!({
        "status": "error",
        "command": command,
        "source": "host-admin-api",
        "phase": "input-authoring",
        "message": &message,
        "captures": serde_json::to_value(args).unwrap_or(Value::Null),
        "connector": {
            "slug": &connector.slug,
            "canonical_id": connector.summary.id.as_str(),
            "name": &connector.summary.name,
        },
        "operation": {
            "requested_selector": &args.operation,
            "selector": &operation.name,
            "canonical_id": &operation.name,
        },
        "error": {
            "type": error_type,
            "message": &message,
            "recoverable": true,
        },
        "input_authoring": {
            "required_template": schema_nav::scaffold_template(&operation.input_schema),
            "examples": operation.examples.iter().take(2).collect::<Vec<_>>(),
            "accepted_sources": ["--input", "--file", "--stdin", "--set path=value"],
        },
        "next_actions": next_actions,
    });

    if let Some(details) = details {
        payload["error"]["details"] = details;
    }

    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Validation,
    }
}

fn invoke_input_error_dispatch(
    command: &str,
    args: &InvokeArgs,
    connector: &DiscoveredConnector,
    operation: &DiscoveredOperation,
    error: InvokeInputError,
) -> DispatchOutcome {
    let InvokeInputError {
        error_type,
        message,
        next_actions,
        details,
    } = error;
    let contract = catalog::planned_payload(
        command,
        &serde_json::to_value(args).unwrap_or(Value::Null),
    )["contract"]
        .clone();

    let mut payload = json!({
        "status": "error",
        "command": command,
        "phase": "input-authoring",
        "message": &message,
        "captures": serde_json::to_value(args).unwrap_or(Value::Null),
        "contract": contract,
        "connector": {
            "slug": &connector.slug,
            "canonical_id": &connector.detail.summary.id,
            "name": &connector.detail.summary.name,
        },
        "operation": {
            "requested_selector": &args.operation,
            "selector": &operation.preferred_selector,
            "canonical_id": &operation.actual_id,
        },
        "error": {
            "type": error_type,
            "message": &message,
            "recoverable": true,
        },
        "input_authoring": {
            "required_template": schema_nav::scaffold_template(&operation.input_schema),
            "examples": operation.examples.iter().take(2).cloned().collect::<Vec<_>>(),
            "accepted_sources": ["--input", "--file", "--stdin", "--set path=value"],
        },
        "next_actions": next_actions,
    });

    if let Some(details) = details {
        payload["error"]["details"] = details;
    }

    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Validation,
    }
}

#[allow(clippy::result_large_err, clippy::too_many_lines)]
fn prepare_invoke_input(
    command: &str,
    args: &InvokeArgs,
    schema: &Value,
) -> std::result::Result<PreparedInvokeInput, InvokeInputError> {
    let mut sources = Vec::new();
    let mut warnings = Vec::new();
    let mut primary_source_count = 0_usize;
    let mut payload = Value::Null;
    let mut primary_source = "none";

    if let Some(raw_input) = &args.input {
        primary_source_count += 1;
        primary_source = "inline-json";
        payload = serde_json::from_str(raw_input).map_err(|error| InvokeInputError {
            error_type: "invalid-inline-input",
            message: format!("The `--input` payload is not valid JSON: {error}"),
            next_actions: vec![
                "Fix the inline JSON syntax and retry.".to_owned(),
                "Use `--set path=value` for small payloads when inline JSON quoting becomes cumbersome.".to_owned(),
            ],
            details: None,
        })?;
        sources.push(json!({
            "kind": "inline-json",
            "bytes": raw_input.len(),
        }));
    }

    if let Some(path) = &args.file {
        primary_source_count += 1;
        primary_source = "file";
        let content = std::fs::read_to_string(path).map_err(|error| InvokeInputError {
            error_type: "unreadable-input-file",
            message: format!("Could not read `{}`: {error}", path.display()),
            next_actions: vec![
                "Check that the file exists and is readable.".to_owned(),
                "Switch to `--input` or `--set path=value` if you only need a small payload."
                    .to_owned(),
            ],
            details: Some(json!({ "path": path.display().to_string() })),
        })?;
        payload = serde_json::from_str(&content).map_err(|error| InvokeInputError {
            error_type: "invalid-input-file",
            message: format!("`{}` does not contain valid JSON: {error}", path.display()),
            next_actions: vec![
                "Fix the JSON file contents and retry.".to_owned(),
                "Use `fwc validate` first if you want a pure schema check.".to_owned(),
            ],
            details: Some(json!({ "path": path.display().to_string() })),
        })?;
        sources.push(json!({
            "kind": "file",
            "path": path.display().to_string(),
            "bytes": content.len(),
        }));
    }

    if args.stdin {
        primary_source_count += 1;
        primary_source = "stdin";
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|error| InvokeInputError {
                error_type: "stdin-read-failed",
                message: format!("Could not read stdin for `{command}` payload authoring: {error}"),
                next_actions: vec![
                    "Pipe JSON into stdin or remove `--stdin`.".to_owned(),
                    "Use `--input` or `--file` if the payload already lives elsewhere.".to_owned(),
                ],
                details: None,
            })?;
        if content.trim().is_empty() {
            return Err(InvokeInputError {
                error_type: "empty-stdin-input",
                message:
                    "Stdin was selected as the payload source, but no JSON bytes were provided."
                        .to_owned(),
                next_actions: vec![
                    "Pipe a JSON document into `fwc ... --stdin`.".to_owned(),
                    "Use `--input`, `--file`, or `--set path=value` instead.".to_owned(),
                ],
                details: None,
            });
        }
        payload = serde_json::from_str(&content).map_err(|error| InvokeInputError {
            error_type: "invalid-stdin-input",
            message: format!("The stdin payload is not valid JSON: {error}"),
            next_actions: vec![
                "Fix the piped JSON and retry.".to_owned(),
                "Use `--set path=value` for small payloads that do not need full JSON.".to_owned(),
            ],
            details: None,
        })?;
        sources.push(json!({
            "kind": "stdin",
            "bytes": content.len(),
        }));
    }

    if primary_source_count > 1 {
        return Err(InvokeInputError {
            error_type: "conflicting-input-sources",
            message: "Choose only one primary payload source among `--input`, `--file`, and `--stdin`.".to_owned(),
            next_actions: vec![
                "Keep one primary payload source and retry.".to_owned(),
                "Use `--set path=value` to patch that payload instead of supplying multiple primaries.".to_owned(),
            ],
            details: Some(json!({
                "input": args.input.is_some(),
                "file": args.file.as_ref().map(|path| path.display().to_string()),
                "stdin": args.stdin,
            })),
        });
    }

    for binding in &args.set {
        let (raw_path, raw_value) = parse_invoke_binding(binding)?;
        let path = parse_invoke_path(&raw_path)?;
        let field_schema = invoke_schema_at_path(schema, &path);
        if field_schema.is_none() {
            warnings.push(format!(
                "`{raw_path}` does not map cleanly to the published input schema; applying it anyway and leaving final validation to catch drift."
            ));
        }
        let value = coerce_invoke_value(&raw_value, field_schema).map_err(|message| {
            InvokeInputError {
                error_type: "binding-coercion-failed",
                message: format!("Could not coerce `{raw_path}={raw_value}` into the schema shape: {message}"),
                next_actions: vec![
                    "Adjust the value to match the schema type shown by `fwc schema <connector> <operation>`.".to_owned(),
                    "For object or array fields, pass valid JSON on the right-hand side.".to_owned(),
                ],
                details: Some(json!({
                    "path": raw_path,
                    "raw_value": raw_value,
                })),
            }
        })?;
        apply_invoke_binding(&mut payload, &path, value).map_err(|message| InvokeInputError {
            error_type: "binding-apply-failed",
            message,
            next_actions: vec![
                "Adjust the binding path so it matches the JSON shape you want to build.".to_owned(),
                "Use `--input` or `--file` when the root payload is not an object/array that can be patched incrementally.".to_owned(),
            ],
            details: Some(json!({
                "binding": binding,
            })),
        })?;
    }

    if sources.is_empty() && args.set.is_empty() {
        return Err(InvokeInputError {
            error_type: "missing-input-source",
            message: "No payload source was provided. Use `--input`, `--file`, `--stdin`, or one or more `--set path=value` bindings.".to_owned(),
            next_actions: vec![
                "Use `fwc template <connector> <operation>` to scaffold a starting payload.".to_owned(),
                "Use `fwc schema <connector> <operation> --required-only` to see the minimum fields.".to_owned(),
                "Use `--set path=value` for small requests or `--input/--file` for full JSON.".to_owned(),
            ],
            details: None,
        });
    }

    if !args.set.is_empty() {
        sources.push(json!({
            "kind": "binding-set",
            "count": args.set.len(),
            "bindings": &args.set,
        }));
        if primary_source == "none" {
            primary_source = "binding-set";
        }
    }

    Ok(PreparedInvokeInput {
        payload,
        primary_source,
        sources,
        binding_count: args.set.len(),
        warnings,
    })
}

#[allow(clippy::result_large_err)]
fn parse_invoke_binding(binding: &str) -> std::result::Result<(String, String), InvokeInputError> {
    binding
        .split_once('=')
        .map(|(path, value)| (path.trim().to_owned(), value.trim().to_owned()))
        .filter(|(path, _)| !path.is_empty())
        .ok_or_else(|| InvokeInputError {
            error_type: "invalid-input-binding",
            message: format!("`{binding}` is not a valid `path=value` binding."),
            next_actions: vec![
                "Use `--set owner=octocat --set repo=hello-world` style bindings.".to_owned(),
                "Quote JSON fragments on the right-hand side when setting object or array values."
                    .to_owned(),
            ],
            details: Some(json!({ "binding": binding })),
        })
}

#[allow(clippy::result_large_err)]
fn parse_invoke_path(
    raw_path: &str,
) -> std::result::Result<Vec<InvokePathSegment>, InvokeInputError> {
    let mut segments = Vec::new();
    for raw_part in raw_path.split('.') {
        if raw_part.is_empty() {
            return Err(InvokeInputError {
                error_type: "invalid-input-binding-path",
                message: format!("`{raw_path}` is not a valid payload path."),
                next_actions: vec![
                    "Use dot paths like `metadata.owner` or indexed paths like `labels[0]`."
                        .to_owned(),
                ],
                details: Some(json!({ "path": raw_path })),
            });
        }

        let mut remaining = raw_part;
        loop {
            let Some(open_index) = remaining.find('[') else {
                if !remaining.is_empty() {
                    segments.push(InvokePathSegment::Field(remaining.to_owned()));
                }
                break;
            };

            if open_index > 0 {
                segments.push(InvokePathSegment::Field(remaining[..open_index].to_owned()));
            }

            let after_open = &remaining[open_index + 1..];
            let Some(close_index) = after_open.find(']') else {
                return Err(InvokeInputError {
                    error_type: "invalid-input-binding-path",
                    message: format!("`{raw_path}` is missing a closing `]`."),
                    next_actions: vec![
                        "Use indexed paths like `labels[0]` or `containers[1].image`.".to_owned(),
                    ],
                    details: Some(json!({ "path": raw_path })),
                });
            };

            let index_str = &after_open[..close_index];
            let index = index_str.parse::<usize>().map_err(|_| InvokeInputError {
                error_type: "invalid-input-binding-path",
                message: format!("`{raw_path}` uses a non-numeric array index `{index_str}`."),
                next_actions: vec![
                    "Array indices must be zero-based integers such as `[0]` or `[1]`.".to_owned(),
                ],
                details: Some(json!({ "path": raw_path, "index": index_str })),
            })?;
            segments.push(InvokePathSegment::Index(index));
            remaining = &after_open[close_index + 1..];
        }
    }

    Ok(segments)
}

fn invoke_schema_at_path<'a>(schema: &'a Value, path: &[InvokePathSegment]) -> Option<&'a Value> {
    let mut current = schema;
    for segment in path {
        match segment {
            InvokePathSegment::Field(name) => {
                current = current
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get(name))
                    .or_else(|| invoke_variant_schema(current, name))?;
            }
            InvokePathSegment::Index(_) => {
                current = current
                    .get("items")
                    .or_else(|| invoke_items_from_variant(current))?;
            }
        }
    }
    Some(current)
}

fn invoke_variant_schema<'a>(schema: &'a Value, field: &str) -> Option<&'a Value> {
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = schema.get(key).and_then(Value::as_array) {
            for variant in variants {
                if let Some(match_schema) = variant
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get(field))
                {
                    return Some(match_schema);
                }
            }
        }
    }
    None
}

fn invoke_items_from_variant(schema: &Value) -> Option<&Value> {
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(variants) = schema.get(key).and_then(Value::as_array) {
            for variant in variants {
                if let Some(items) = variant.get("items") {
                    return Some(items);
                }
            }
        }
    }
    None
}

fn coerce_invoke_value(
    raw_value: &str,
    schema: Option<&Value>,
) -> std::result::Result<Value, String> {
    let expected_type = schema.and_then(invoke_expected_type);
    match expected_type {
        Some("string") => Ok(Value::String(raw_value.to_owned())),
        Some("integer") => raw_value
            .parse::<i64>()
            .map(|parsed| Value::Number(parsed.into()))
            .or_else(|_| {
                raw_value
                    .parse::<u64>()
                    .map(|parsed| Value::Number(parsed.into()))
            })
            .map_err(|_| "expected an integer".to_owned()),
        Some("number") => {
            let parsed = raw_value
                .parse::<f64>()
                .map_err(|_| "expected a number".to_owned())?;
            serde_json::Number::from_f64(parsed)
                .map(Value::Number)
                .ok_or_else(|| "expected a finite number".to_owned())
        }
        Some("boolean") => match raw_value {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err("expected `true` or `false`".to_owned()),
        },
        Some("object" | "array") => serde_json::from_str(raw_value)
            .map_err(|error| format!("expected valid JSON for a composite value: {error}")),
        Some("null") => {
            if raw_value == "null" {
                Ok(Value::Null)
            } else {
                Err("expected the literal `null`".to_owned())
            }
        }
        _ => serde_json::from_str(raw_value).or_else(|_| Ok(Value::String(raw_value.to_owned()))),
    }
}

fn invoke_expected_type(schema: &Value) -> Option<&str> {
    if let Some(type_name) = schema.get("type").and_then(Value::as_str) {
        return Some(type_name);
    }

    schema
        .get("type")
        .and_then(Value::as_array)
        .and_then(|types| {
            types
                .iter()
                .filter_map(Value::as_str)
                .find(|type_name| *type_name != "null")
        })
}

fn apply_invoke_binding(
    target: &mut Value,
    path: &[InvokePathSegment],
    value: Value,
) -> std::result::Result<(), String> {
    if path.is_empty() {
        *target = value;
        return Ok(());
    }

    match &path[0] {
        InvokePathSegment::Field(name) => {
            if target.is_null() {
                *target = Value::Object(serde_json::Map::new());
            }
            let Some(object) = target.as_object_mut() else {
                return Err(format!(
                    "Cannot set `{name}` on a non-object payload root. Use `--input`/`--file` for the full JSON body instead."
                ));
            };
            let entry = object.entry(name.clone()).or_insert(Value::Null);
            apply_invoke_binding(entry, &path[1..], value)
        }
        InvokePathSegment::Index(index) => {
            if target.is_null() {
                *target = Value::Array(Vec::new());
            }
            let Some(array) = target.as_array_mut() else {
                return Err(format!(
                    "Cannot set array index [{index}] on a non-array payload. Use a JSON array source or patch a valid array field."
                ));
            };
            while array.len() <= *index {
                array.push(Value::Null);
            }
            apply_invoke_binding(&mut array[*index], &path[1..], value)
        }
    }
}

fn invoke_payload_preview(payload: &Value) -> Value {
    let bytes = serde_json::to_vec(payload).map_or(0, |encoded| encoded.len());
    match payload {
        Value::Object(object) => json!({
            "shape": "object",
            "top_level_keys": object.keys().take(8).cloned().collect::<Vec<_>>(),
            "field_count": invoke_leaf_field_count(payload),
            "bytes": bytes,
        }),
        Value::Array(array) => json!({
            "shape": "array",
            "item_count": array.len(),
            "bytes": bytes,
        }),
        Value::String(value) => json!({
            "shape": "string",
            "chars": value.chars().count(),
            "bytes": bytes,
        }),
        Value::Bool(_) => json!({
            "shape": "boolean",
            "bytes": bytes,
        }),
        Value::Number(_) => json!({
            "shape": "number",
            "bytes": bytes,
        }),
        Value::Null => json!({
            "shape": "null",
            "bytes": bytes,
        }),
    }
}

fn invoke_leaf_field_count(value: &Value) -> usize {
    match value {
        Value::Object(object) => object.values().map(invoke_leaf_field_count).sum::<usize>(),
        Value::Array(array) => array.iter().map(invoke_leaf_field_count).sum::<usize>(),
        Value::Null => 0,
        _ => 1,
    }
}

#[cfg(test)]
thread_local! {
    static TEST_SESSION_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static TEST_LOCK_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static TEST_AGENT_COORD_PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

fn cli_session_store() -> session::SessionStore {
    #[cfg(test)]
    if let Some(path) = TEST_SESSION_DIR_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return session::SessionStore::new(path);
    }

    session::SessionStore::default_path()
}

fn cli_lock_store() -> op_lock::LockStore {
    #[cfg(test)]
    if let Some(path) = TEST_LOCK_DIR_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return op_lock::LockStore::new(path);
    }

    op_lock::LockStore::default_path()
}

fn cli_agent_coord_store() -> agent_coord::CoordinationStore {
    #[cfg(test)]
    if let Some(path) = TEST_AGENT_COORD_PATH_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return agent_coord::CoordinationStore::new(path);
    }

    agent_coord::CoordinationStore::default_path()
}

#[cfg(test)]
struct SessionDirOverrideGuard;

#[cfg(test)]
fn install_test_session_dir(path: PathBuf) -> SessionDirOverrideGuard {
    TEST_SESSION_DIR_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = Some(path);
    });
    SessionDirOverrideGuard
}

#[cfg(test)]
impl Drop for SessionDirOverrideGuard {
    fn drop(&mut self) {
        TEST_SESSION_DIR_OVERRIDE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[cfg(test)]
struct LockDirOverrideGuard;

#[cfg(test)]
fn install_test_lock_dir(path: PathBuf) -> LockDirOverrideGuard {
    TEST_LOCK_DIR_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = Some(path);
    });
    LockDirOverrideGuard
}

#[cfg(test)]
impl Drop for LockDirOverrideGuard {
    fn drop(&mut self) {
        TEST_LOCK_DIR_OVERRIDE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[cfg(test)]
struct AgentCoordPathOverrideGuard;

#[cfg(test)]
fn install_test_agent_coord_path(path: PathBuf) -> AgentCoordPathOverrideGuard {
    TEST_AGENT_COORD_PATH_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = Some(path);
    });
    AgentCoordPathOverrideGuard
}

#[cfg(test)]
impl Drop for AgentCoordPathOverrideGuard {
    fn drop(&mut self) {
        TEST_AGENT_COORD_PATH_OVERRIDE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[cfg(test)]
thread_local! {
    static TEST_HISTORY_PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

fn cli_history_store_path() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_HISTORY_PATH_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return Ok(path);
    }

    history::HistoryStore::default_path()
}

fn cli_history_store() -> Result<history::HistoryStore> {
    Ok(history::HistoryStore::new(cli_history_store_path()?))
}

#[cfg(test)]
struct HistoryPathOverrideGuard;

#[cfg(test)]
fn install_test_history_path(path: PathBuf) -> HistoryPathOverrideGuard {
    TEST_HISTORY_PATH_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = Some(path);
    });
    HistoryPathOverrideGuard
}

#[cfg(test)]
impl Drop for HistoryPathOverrideGuard {
    fn drop(&mut self) {
        TEST_HISTORY_PATH_OVERRIDE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn append_history_entry(
    status: history::OpStatus,
    connector_id: &str,
    operation_id: &str,
    zone: Option<&str>,
    input: &Value,
    output: Option<&Value>,
    error_code: Option<String>,
    idempotency_key: Option<&str>,
    latency_ms: u64,
) -> Result<()> {
    let store = cli_history_store()?;
    let active_session = cli_session_store().active_session().ok().flatten();
    let entry = history::HistoryEntry {
        entry_id: RequestId::random().to_string(),
        timestamp: chrono::Utc::now(),
        connector_id: connector_id.to_owned(),
        operation_id: operation_id.to_owned(),
        zone: zone.map(ToOwned::to_owned),
        input_hash: history::content_hash(input),
        input_summary: history::summarize_input(input),
        output_hash: output.map(history::content_hash),
        output_summary: output.map(history::summarize_input),
        status,
        latency_ms,
        error_code,
        idempotency_key: idempotency_key.map(ToOwned::to_owned),
        agent_session: active_session
            .as_ref()
            .map(|session| session.id.to_string()),
    };
    store.append(&entry)?;

    if let Some(mut session) = active_session {
        session.record_operation();
        let _ = cli_session_store().save(&session);
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct ResolvedHostOperation {
    connector: HostConnectorRecord,
    operation: HostToolDescriptor,
    rate_limits: Option<Vec<RateLimitSummary>>,
}

fn parse_operation_reference(reference: &str) -> Option<(&str, &str)> {
    let (connector, operation) = reference.split_once('.')?;
    let connector = connector.trim();
    let operation = operation.trim();
    if connector.is_empty() || operation.is_empty() {
        return None;
    }
    Some((connector, operation))
}

fn invalid_operation_reference_dispatch(command: &str, reference: &str) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": command,
            "error": {
                "type": "invalid-operation-reference",
                "message": format!(
                    "`{reference}` must use `<connector>.<operation>` syntax so `fwc` can resolve the target against the live host."
                ),
                "recoverable": true,
            },
            "next_actions": [
                format!("fwc schema {reference}"),
                "Use a selector like `github.issues.get` or `slack.chat.post_message`.".to_owned(),
            ],
        }),
        exit_code: CliExitCode::Validation,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn missing_host_dispatch(
    command: &str,
    details: Value,
    next_actions: Vec<String>,
) -> DispatchOutcome {
    let envelope = CommandEnvelope::new(CommandAvailability::Unavailable, command);
    let mut payload = json!({
        "status": "error",
        "command": command,
        "error": {
            "type": "missing-host-endpoint",
            "message": format!(
                "`{command}` requires a live `fcp-host` endpoint. `fwc` will not simulate runtime behavior or fabricate results."
            ),
            "recoverable": true,
        },
        "details": details,
        "next_actions": next_actions,
    });
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Transport,
    }
}

fn conflicting_catalog_mode_dispatch(command: &str) -> DispatchOutcome {
    let envelope = CommandEnvelope::new(CommandAvailability::Denied, command);
    let mut payload = json!({
        "status": "error",
        "command": command,
        "error": {
            "type": "ambiguous-catalog-source",
            "message": format!(
                "`{command}` cannot combine live host mode with `--offline`. Choose one source of truth."
            ),
            "recoverable": true,
        },
        "next_actions": [
            format!("Retry `{command}` with `--host <endpoint>` for live host truth."),
            format!("Retry `{command}` with `--offline` to inspect workspace manifests explicitly."),
        ],
    });
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Validation,
    }
}

fn resolve_host_operation_from_catalog(
    command: &str,
    client: &HostAdminClient,
    catalog: &HostConnectorCatalog,
    connector_selector: &str,
    operation_selector: &str,
) -> Result<ResolvedHostOperation, DispatchOutcome> {
    let connector = match catalog.resolve_connector(connector_selector) {
        Ok(connector) => connector.clone(),
        Err(error) => {
            return Err(connector_resolution_dispatch(
                command,
                connector_selector,
                &error,
            ));
        }
    };
    let introspection = client
        .introspect(connector.summary.id.as_str())
        .map_err(|error| DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": command,
                "source": "host-admin-api",
                "connector": {
                    "slug": &connector.slug,
                    "canonical_id": connector.summary.id.as_str(),
                    "name": &connector.summary.name,
                },
                "error": {
                    "type": "host-introspection-failed",
                    "message": format!(
                        "Failed to load live operation descriptors for `{}` from `fcp-host`: {error}",
                        connector.slug
                    ),
                    "recoverable": true,
                },
                "next_actions": [
                    format!("fwc show {} --host {}", connector.slug, client.base_url),
                    format!("fwc status {} --host {}", connector.slug, client.base_url),
                ],
            }),
            exit_code: CliExitCode::Transport,
        })?;
    let operation = match resolve_host_tool(&introspection.tools, operation_selector) {
        Ok(operation) => operation.clone(),
        Err(error) => {
            return Err(host_operation_resolution_dispatch(
                command,
                &connector.slug,
                operation_selector,
                &error,
            ));
        }
    };

    Ok(ResolvedHostOperation {
        connector,
        rate_limits: host_operation_rate_limits(&operation, introspection.rate_limits.as_ref()),
        operation,
    })
}

fn build_live_invoke_request(
    connector_id_raw: &str,
    operation_name: &str,
    zone: &str,
    payload: Value,
    request_id: RequestId,
    capability_token: CapabilityToken,
    approval_tokens: Vec<ApprovalToken>,
    idempotency_key: Option<String>,
    deadline_ms: Option<u64>,
) -> Result<InvokeRequest> {
    let zone_id: ZoneId = zone
        .parse()
        .map_err(|error| anyhow::anyhow!("`{zone}` is not a valid FCP zone: {error}"))?;
    let connector_id: ConnectorId = connector_id_raw.parse().map_err(|error| {
        anyhow::anyhow!("host connector id `{connector_id_raw}` is not canonical: {error}")
    })?;
    let operation_id: OperationId = operation_name.parse().map_err(|error| {
        anyhow::anyhow!("host operation id `{operation_name}` is not canonical: {error}")
    })?;

    Ok(InvokeRequest {
        r#type: "invoke".to_owned(),
        id: request_id,
        connector_id,
        operation: operation_id,
        zone_id,
        input: payload,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key,
        lease_seq: None,
        deadline_ms,
        correlation_id: None,
        provenance: None,
        approval_tokens,
    })
}

fn build_host_batch_options(concurrency: usize, on_error: batch::OnError) -> HostBatchOptions {
    HostBatchOptions {
        max_parallelism: u32::try_from(concurrency).unwrap_or(u32::MAX).max(1),
        stop_on_first_error: matches!(on_error, batch::OnError::Abort),
        ..HostBatchOptions::default()
    }
}

fn validate_payload_against_schema(payload: &Value, schema: &Value) -> (bool, Vec<Value>) {
    let validation = validate::validate(payload, schema);
    let errors = validation
        .errors
        .iter()
        .map(|error| {
            json!({
                "path": error.path,
                "message": error.message,
                "suggestion": error.suggestion,
            })
        })
        .collect::<Vec<_>>();
    (validation.is_valid(), errors)
}

fn preflight_status_label(preflights: &[Value]) -> (&'static str, CliExitCode) {
    let allowed = preflights
        .iter()
        .filter(|entry| entry["allowed"].as_bool().unwrap_or(false))
        .count();
    if allowed == preflights.len() {
        ("ok", CliExitCode::Success)
    } else if allowed == 0 {
        ("denied", CliExitCode::PolicyDenied)
    } else {
        ("partial", CliExitCode::PolicyDenied)
    }
}

#[allow(clippy::missing_const_for_fn)]
fn batch_status_label(response: &HostBatchInvokeResponse) -> (&'static str, CliExitCode) {
    if response.failed == 0 && response.skipped == 0 {
        ("ok", CliExitCode::Success)
    } else if response.completed > 0 {
        ("partial", CliExitCode::Connector)
    } else {
        ("error", CliExitCode::Connector)
    }
}

#[allow(clippy::too_many_lines)]
fn cancel_dispatch(args: &CancelArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "cancel",
            json!({
                "operation_id": &args.operation_id,
                "reason": &args.reason,
                "cleanup": &args.cleanup,
            }),
            vec![
                format!("fwc cancel {} --host <endpoint>", args.operation_id),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let client = HostAdminClient::new(&host.endpoint)?;

    let reason = match args.reason.as_str() {
        "user-requested" | "user_requested" => CancelReason::UserRequested,
        "agent-abort" | "agent_abort" => CancelReason::AgentAbort {
            reason: args
                .detail
                .clone()
                .unwrap_or_else(|| "agent requested cancellation".to_owned()),
        },
        "timeout-approaching" | "timeout_approaching" => {
            let Some(remaining_ms) = args.remaining_ms else {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "cancel",
                        "error": {
                            "type": "missing-timeout-detail",
                            "message": "`--reason timeout-approaching` requires `--remaining-ms`.",
                            "recoverable": true,
                        },
                        "next_actions": [
                            format!("fwc cancel {} --reason timeout-approaching --remaining-ms 2500", args.operation_id),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            };
            CancelReason::TimeoutApproaching { remaining_ms }
        }
        "resource-limit" | "resource_limit" => {
            let (Some(resource), Some(current), Some(limit)) =
                (args.resource.clone(), args.current, args.limit)
            else {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "cancel",
                        "error": {
                            "type": "missing-resource-limit-detail",
                            "message": "`--reason resource-limit` requires `--resource`, `--current`, and `--limit`.",
                            "recoverable": true,
                        },
                        "next_actions": [
                            format!("fwc cancel {} --reason resource-limit --resource memory --current 950 --limit 1024", args.operation_id),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            };
            CancelReason::ResourceLimit {
                resource,
                current,
                limit,
            }
        }
        "superseded" => {
            let Some(by_operation_id) = args.superseded_by.clone() else {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "cancel",
                        "error": {
                            "type": "missing-superseded-detail",
                            "message": "`--reason superseded` requires `--superseded-by`.",
                            "recoverable": true,
                        },
                        "next_actions": [
                            format!("fwc cancel {} --reason superseded --superseded-by <new-operation-id>", args.operation_id),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            };
            CancelReason::Superseded { by_operation_id }
        }
        "session-closing" | "session_closing" => CancelReason::SessionClosing,
        other => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "cancel",
                    "error": {
                        "type": "invalid-cancel-reason",
                        "message": format!(
                            "`{other}` is not a supported cancel reason. Use `user-requested`, `agent-abort`, `timeout-approaching`, `resource-limit`, `superseded`, or `session-closing`."
                        ),
                        "recoverable": true,
                    },
                    "next_actions": [
                        format!("fwc cancel {} --reason user-requested", args.operation_id),
                    ],
                }),
                exit_code: CliExitCode::Validation,
            });
        }
    };

    let cleanup = match args.cleanup.as_str() {
        "best-effort" | "best_effort" => CleanupBehavior::BestEffort,
        "full" => CleanupBehavior::Full {
            timeout_ms: args.cleanup_timeout_ms.unwrap_or(30_000),
        },
        "abandon" => CleanupBehavior::Abandon,
        "checkpoint" => CleanupBehavior::Checkpoint,
        other => {
            return Ok(DispatchOutcome {
                payload: json!({
                    "status": "error",
                    "command": "cancel",
                    "error": {
                        "type": "invalid-cleanup-behavior",
                        "message": format!(
                            "`{other}` is not a supported cleanup mode. Use `best-effort`, `full`, `abandon`, or `checkpoint`."
                        ),
                        "recoverable": true,
                    },
                    "next_actions": [
                        format!("fwc cancel {} --cleanup best-effort", args.operation_id),
                    ],
                }),
                exit_code: CliExitCode::Validation,
            });
        }
    };

    let request = HostCancellationRequest {
        operation_id: args.operation_id.clone(),
        reason,
        cleanup,
        return_partial: args.return_partial,
    };
    let response = client.cancel(&request)?;
    let exit_code = if matches!(response.outcome, fcp_host::CancellationOutcome::Failed) {
        CliExitCode::Connector
    } else {
        CliExitCode::Success
    };

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "cancel");
    let mut payload = json!({
        "status": if exit_code.is_success() { "ok" } else { "error" },
        "command": "cancel",
        "source": "host-admin-api",
        "message": format!(
            "Submitted a live cancellation request for operation `{}` against `fcp-host`.",
            args.operation_id
        ),
        "request": request,
        "response": response,
        "next_actions": [
            format!("fwc history --status error --limit 10"),
            format!("fwc status --host {}", host.endpoint),
        ],
    });
    if exit_code.is_success() {
        envelope.inject_into(&mut payload);
    }
    Ok(DispatchOutcome { payload, exit_code })
}

#[allow(clippy::option_if_let_else)]
fn history_dispatch(args: &HistoryArgs) -> Result<DispatchOutcome> {
    let store = cli_history_store()?;

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
                let envelope =
                    CommandEnvelope::new(CommandAvailability::OfflineArtifact, "history");
                let mut payload = json!({
                    "status": "ok",
                    "command": "history",
                    "scope": "entry",
                    "entry": entry,
                });
                envelope.inject_into(&mut payload);
                Ok(DispatchOutcome {
                    payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "history");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[derive(Clone, Debug)]
struct CapabilityOperationMetadata {
    connector_slug: String,
    capability_id: fcp_core::CapabilityId,
    risk_tier: SafetyTier,
}

#[derive(Debug, Default)]
struct CapabilityAggregationResult {
    aggregates: Vec<CapabilityUsageAggregate>,
    total_entries: usize,
    skipped_simulated: usize,
    unresolved_entry_count: usize,
    unresolved_samples: Vec<Value>,
}

fn capabilities_dispatch(
    args: &CapabilitiesArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    let host = resolve_host_config(explicit_host)?;
    let host_client = host
        .as_ref()
        .map(|resolved| HostAdminClient::new(&resolved.endpoint))
        .transpose()?;
    let manifest_catalog = DiscoveryCatalog::load()?;
    let mut source_gaps = Vec::new();
    let host_catalog = if let (Some(resolved), Some(client)) = (host.as_ref(), host_client.as_ref())
    {
        match client.catalog(None) {
            Ok((catalog, _)) => Some(catalog),
            Err(error) => {
                source_gaps.push(json!({
                    "source": "host-admin-api",
                    "status": "unavailable",
                    "message": format!(
                        "Failed to load live connector metadata from `{}`; falling back to manifest-backed metadata: {error}",
                        resolved.endpoint
                    ),
                }));
                None
            }
        }
    } else {
        None
    };

    let (subcommand, zone_filter_arg, connector_filter_arg, suggestion_filter) = match &args.command
    {
        CapabilitiesCommand::Report(filters) => (
            "report",
            filters.zone.clone(),
            filters.connector.clone(),
            CapabilitySuggestionFilter::All,
        ),
        CapabilitiesCommand::Suggest(args) => (
            "suggest",
            args.zone.clone(),
            args.connector.clone(),
            args.filter,
        ),
        CapabilitiesCommand::Export(filters) => (
            "export",
            filters.zone.clone(),
            filters.connector.clone(),
            CapabilitySuggestionFilter::All,
        ),
    };
    let filters = CapabilitiesFilterArgs {
        zone: zone_filter_arg,
        connector: connector_filter_arg,
    };
    let command_name = format!("capabilities {subcommand}");

    let zone_filter = match filters.zone.as_deref() {
        Some(zone) => match zone.parse::<ZoneId>() {
            Ok(zone_id) => Some(zone_id.to_string()),
            Err(error) => {
                return Ok(DispatchOutcome {
                    payload: json!({
                        "status": "error",
                        "command": "capabilities",
                        "subcommand": subcommand,
                        "error": {
                            "type": "invalid-zone",
                            "message": format!("`{zone}` is not a valid zone id: {error}"),
                            "recoverable": true,
                        },
                        "details": {
                            "zone": zone,
                        },
                        "next_actions": [
                            "fwc capabilities report --zone z:work".to_owned(),
                            "fwc capabilities suggest --zone z:project:<name>".to_owned(),
                        ],
                    }),
                    exit_code: CliExitCode::Validation,
                });
            }
        },
        None => None,
    };

    let store = cli_history_store()?;
    let history_path = cli_history_store_path()?;
    let mut history_filter = history::HistoryFilter::new();
    history_filter.limit = usize::MAX;
    let mut entries = store.query(&history_filter)?;

    let connector_filter = match filters.connector.as_deref() {
        Some(selector) => match resolve_capability_connector_filter(
            &command_name,
            selector,
            host_catalog.as_ref(),
            &manifest_catalog,
            &entries,
        ) {
            Ok(connector_id) => Some(connector_id),
            Err(outcome) => return Ok(outcome),
        },
        None => None,
    };

    if let Some(zone) = zone_filter.as_deref() {
        entries.retain(|entry| entry.zone.as_deref() == Some(zone));
    }
    if let Some(connector_id) = connector_filter.as_deref() {
        entries.retain(|entry| entry.connector_id == *connector_id);
    }

    let unique_connector_ids = entries
        .iter()
        .map(|entry| entry.connector_id.clone())
        .collect::<BTreeSet<_>>();
    let mut operation_metadata = local_capability_metadata_map(&manifest_catalog);
    if let Some(client) = host_client.as_ref() {
        operation_metadata.extend(host_capability_metadata_map(
            client,
            &unique_connector_ids,
            &mut source_gaps,
        ));
    }

    let aggregation = aggregate_capability_usage(&entries, &operation_metadata);
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let recommendation_report = recommend_capabilities(
        &aggregation.aggregates,
        now,
        RecommendationConfig::default(),
    );

    let payload = match subcommand {
        "report" => capability_report_payload(
            &aggregation,
            &recommendation_report,
            &source_gaps,
            &history_path,
            &filters,
            &operation_metadata,
        ),
        "suggest" => capability_suggest_payload(
            &aggregation,
            &recommendation_report,
            suggestion_filter,
            &source_gaps,
            &history_path,
            &filters,
        ),
        "export" => capability_export_payload(
            &aggregation,
            &recommendation_report,
            &source_gaps,
            &history_path,
            &filters,
        ),
        _ => unreachable!("subcommand normalized above"),
    };

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "capabilities");
    let mut payload = payload;
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn resolve_capability_connector_filter(
    command: &str,
    selector: &str,
    host_catalog: Option<&HostConnectorCatalog>,
    manifest_catalog: &DiscoveryCatalog,
    history_entries: &[history::HistoryEntry],
) -> Result<String, DispatchOutcome> {
    if let Some(catalog) = host_catalog
        && let Ok(connector) = catalog.resolve_connector(selector)
    {
        return Ok(connector.summary.id.to_string());
    }
    if let Ok(connector) = manifest_catalog.resolve_connector(selector) {
        return Ok(connector.detail.summary.id.clone());
    }
    if history_entries
        .iter()
        .any(|entry| entry.connector_id == selector)
    {
        return Ok(selector.to_owned());
    }
    if let Some(catalog) = host_catalog
        && let Err(error) = catalog.resolve_connector(selector)
    {
        return Err(connector_resolution_dispatch(command, selector, &error));
    }
    match manifest_catalog.resolve_connector(selector) {
        Ok(connector) => Ok(connector.detail.summary.id.clone()),
        Err(error) => Err(connector_resolution_dispatch(command, selector, &error)),
    }
}

fn local_capability_metadata_map(
    manifest_catalog: &DiscoveryCatalog,
) -> HashMap<(String, String), CapabilityOperationMetadata> {
    let mut metadata = HashMap::new();
    for connector in manifest_catalog.connectors() {
        for operation in &connector.operations {
            let info = operation.operation_info();
            let entry = CapabilityOperationMetadata {
                connector_slug: connector.slug.clone(),
                capability_id: info.capability,
                risk_tier: info.safety_tier,
            };
            let mut keys = BTreeSet::from([
                operation.actual_id.clone(),
                operation.local_id.clone(),
                operation.preferred_selector.clone(),
            ]);
            keys.extend(operation.aliases.iter().cloned());
            for operation_key in keys {
                metadata.insert(
                    (connector.detail.summary.id.clone(), operation_key),
                    entry.clone(),
                );
            }
        }
    }
    metadata
}

fn host_capability_metadata_map(
    client: &HostAdminClient,
    connector_ids: &BTreeSet<String>,
    source_gaps: &mut Vec<Value>,
) -> HashMap<(String, String), CapabilityOperationMetadata> {
    let mut metadata = HashMap::new();
    for connector_id in connector_ids {
        match client.introspect(connector_id) {
            Ok(introspection) => {
                let connector_slug = host_connector_slug(&introspection.connector);
                for tool in introspection.tools {
                    metadata.insert(
                        (connector_id.clone(), tool.name.clone()),
                        CapabilityOperationMetadata {
                            connector_slug: connector_slug.clone(),
                            capability_id: tool.capability,
                            risk_tier: tool.safety_tier,
                        },
                    );
                }
            }
            Err(error) => source_gaps.push(json!({
                "source": "host-admin-api",
                "status": "partial",
                "connector_id": connector_id,
                "message": format!(
                    "Failed to load live operation metadata for `{connector_id}` from `fcp-host`; using manifest metadata when available: {error}"
                ),
            })),
        }
    }
    metadata
}

fn aggregate_capability_usage(
    entries: &[history::HistoryEntry],
    operation_metadata: &HashMap<(String, String), CapabilityOperationMetadata>,
) -> CapabilityAggregationResult {
    let mut aggregates = HashMap::<CapabilityUsageKey, CapabilityUsageAggregate>::new();
    let mut unresolved_samples = Vec::new();
    let mut unresolved_entry_count = 0usize;
    let mut skipped_simulated = 0usize;

    for entry in entries {
        if entry.status == history::OpStatus::Simulated {
            skipped_simulated += 1;
            continue;
        }

        let Some(zone) = entry.zone.as_deref() else {
            unresolved_entry_count += 1;
            if unresolved_samples.len() < 10 {
                unresolved_samples.push(json!({
                    "entry_id": &entry.entry_id,
                    "connector_id": &entry.connector_id,
                    "operation_id": &entry.operation_id,
                    "reason": "missing-zone",
                }));
            }
            continue;
        };
        let Ok(zone_id) = zone.parse::<ZoneId>() else {
            unresolved_entry_count += 1;
            if unresolved_samples.len() < 10 {
                unresolved_samples.push(json!({
                    "entry_id": &entry.entry_id,
                    "connector_id": &entry.connector_id,
                    "operation_id": &entry.operation_id,
                    "reason": "invalid-zone",
                    "zone": zone,
                }));
            }
            continue;
        };
        let Ok(connector_id) = entry.connector_id.parse::<ConnectorId>() else {
            unresolved_entry_count += 1;
            if unresolved_samples.len() < 10 {
                unresolved_samples.push(json!({
                    "entry_id": &entry.entry_id,
                    "connector_id": &entry.connector_id,
                    "operation_id": &entry.operation_id,
                    "reason": "invalid-connector-id",
                }));
            }
            continue;
        };
        let Some(metadata) =
            operation_metadata.get(&(entry.connector_id.clone(), entry.operation_id.clone()))
        else {
            unresolved_entry_count += 1;
            if unresolved_samples.len() < 10 {
                unresolved_samples.push(json!({
                    "entry_id": &entry.entry_id,
                    "connector_id": &entry.connector_id,
                    "operation_id": &entry.operation_id,
                    "reason": "unresolved-operation-metadata",
                }));
            }
            continue;
        };

        let key = CapabilityUsageKey::new(zone_id, connector_id, metadata.capability_id.clone());
        let occurred_at = u64::try_from(entry.timestamp.timestamp()).unwrap_or(0);
        let aggregate = aggregates
            .entry(key.clone())
            .or_insert_with(|| CapabilityUsageAggregate {
                key,
                total: 0,
                allowed: 0,
                denied: 0,
                errors: 0,
                first_seen: occurred_at,
                last_seen: occurred_at,
                last_risk_tier: metadata.risk_tier,
            });
        aggregate.total = aggregate.total.saturating_add(1);
        aggregate.first_seen = aggregate.first_seen.min(occurred_at);
        aggregate.last_seen = aggregate.last_seen.max(occurred_at);
        aggregate.last_risk_tier = metadata.risk_tier;

        match entry.status {
            history::OpStatus::Success => {
                aggregate.allowed = aggregate.allowed.saturating_add(1);
            }
            history::OpStatus::Denied => {
                aggregate.denied = aggregate.denied.saturating_add(1);
            }
            history::OpStatus::Error
            | history::OpStatus::Timeout
            | history::OpStatus::RateLimited => {
                aggregate.errors = aggregate.errors.saturating_add(1);
            }
            history::OpStatus::Simulated => {}
        }
    }

    let mut aggregates = aggregates.into_values().collect::<Vec<_>>();
    aggregates.sort_by(|left, right| {
        (
            left.key.zone_id.as_str(),
            left.key.connector_id.as_str(),
            left.key.capability_id.as_str(),
        )
            .cmp(&(
                right.key.zone_id.as_str(),
                right.key.connector_id.as_str(),
                right.key.capability_id.as_str(),
            ))
    });

    CapabilityAggregationResult {
        total_entries: entries.len(),
        aggregates,
        skipped_simulated,
        unresolved_entry_count,
        unresolved_samples,
    }
}

fn capability_report_payload(
    aggregation: &CapabilityAggregationResult,
    recommendation_report: &fcp_telemetry::CapabilityRecommendationReport,
    source_gaps: &[Value],
    history_path: &Path,
    filters: &CapabilitiesFilterArgs,
    operation_metadata: &HashMap<(String, String), CapabilityOperationMetadata>,
) -> Value {
    let recommendation_lookup = recommendation_report
        .recommendations
        .iter()
        .map(|recommendation| {
            (
                (
                    recommendation.key.zone_id.to_string(),
                    recommendation.key.connector_id.to_string(),
                    recommendation.key.capability_id.to_string(),
                ),
                recommendation,
            )
        })
        .collect::<HashMap<_, _>>();
    let mut aggregates_by_zone = BTreeMap::<String, Vec<&CapabilityUsageAggregate>>::new();
    for aggregate in &aggregation.aggregates {
        aggregates_by_zone
            .entry(aggregate.key.zone_id.to_string())
            .or_default()
            .push(aggregate);
    }

    let zones = aggregates_by_zone
        .into_iter()
        .map(|(zone_id, aggregates)| {
            let mut connector_ids = BTreeSet::new();
            let mut remove_unused = 0usize;
            let mut review_risky = 0usize;
            let mut keep = 0usize;
            let capabilities = aggregates
                .iter()
                .map(|aggregate| {
                    connector_ids.insert(aggregate.key.connector_id.to_string());
                    let recommendation = recommendation_lookup.get(&(
                        aggregate.key.zone_id.to_string(),
                        aggregate.key.connector_id.to_string(),
                        aggregate.key.capability_id.to_string(),
                    ));
                    if let Some(recommendation) = recommendation {
                        match recommendation.suggestion {
                            CapabilitySuggestionKind::RemoveUnused => remove_unused += 1,
                            CapabilitySuggestionKind::ReviewRisky => review_risky += 1,
                            CapabilitySuggestionKind::Keep => keep += 1,
                        }
                    }
                    let connector_slug =
                        operation_metadata
                            .iter()
                            .find_map(|((connector_id, _), metadata)| {
                                (connector_id == aggregate.key.connector_id.as_str())
                                    .then(|| metadata.connector_slug.clone())
                            });
                    json!({
                        "connector_id": aggregate.key.connector_id.as_str(),
                        "connector_slug": connector_slug,
                        "capability_id": aggregate.key.capability_id.as_str(),
                        "total": aggregate.total,
                        "allowed": aggregate.allowed,
                        "denied": aggregate.denied,
                        "errors": aggregate.errors,
                        "first_seen": aggregate.first_seen,
                        "last_seen": aggregate.last_seen,
                        "risk_tier": safety_tier_label(aggregate.last_risk_tier),
                        "suggestion": recommendation.map(|value| value.suggestion),
                        "reason_code": recommendation.map(|value| value.reason_code.clone()),
                    })
                })
                .collect::<Vec<_>>();

            let total = aggregates
                .iter()
                .map(|aggregate| aggregate.total)
                .sum::<u64>();
            let allowed = aggregates
                .iter()
                .map(|aggregate| aggregate.allowed)
                .sum::<u64>();
            let denied = aggregates
                .iter()
                .map(|aggregate| aggregate.denied)
                .sum::<u64>();
            let errors = aggregates
                .iter()
                .map(|aggregate| aggregate.errors)
                .sum::<u64>();

            json!({
                "zone_id": zone_id,
                "totals": {
                    "capability_count": capabilities.len(),
                    "connector_count": connector_ids.len(),
                    "invocation_count": total,
                    "allowed": allowed,
                    "denied": denied,
                    "errors": errors,
                    "remove_unused": remove_unused,
                    "review_risky": review_risky,
                    "keep": keep,
                },
                "capabilities": capabilities,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "status": "ok",
        "command": "capabilities",
        "subcommand": "report",
        "source": "history-log",
        "message": "Built a truthful capability-usage report from recorded `fwc` execution history and current connector metadata.",
        "history_path": history_path.display().to_string(),
        "filters": {
            "zone": &filters.zone,
            "connector": &filters.connector,
        },
        "summary": {
            "history_entries_considered": aggregation.total_entries,
            "aggregate_count": aggregation.aggregates.len(),
            "zone_count": zones.len(),
            "invocation_count": aggregation.aggregates.iter().map(|aggregate| aggregate.total).sum::<u64>(),
            "allowed": aggregation.aggregates.iter().map(|aggregate| aggregate.allowed).sum::<u64>(),
            "denied": aggregation.aggregates.iter().map(|aggregate| aggregate.denied).sum::<u64>(),
            "errors": aggregation.aggregates.iter().map(|aggregate| aggregate.errors).sum::<u64>(),
            "skipped_simulated": aggregation.skipped_simulated,
            "unresolved_entries": aggregation.unresolved_entry_count,
        },
        "recommendation_summary": recommendation_report.summary(),
        "risk_summaries": &recommendation_report.risk_summaries,
        "zones": zones,
        "metadata_gaps": source_gaps,
        "unresolved_samples": &aggregation.unresolved_samples,
        "next_actions": [
            "fwc capabilities suggest".to_owned(),
            "fwc capabilities export".to_owned(),
            "fwc history --status denied".to_owned(),
        ],
    })
}

fn capability_suggest_payload(
    aggregation: &CapabilityAggregationResult,
    recommendation_report: &fcp_telemetry::CapabilityRecommendationReport,
    suggestion_filter: CapabilitySuggestionFilter,
    source_gaps: &[Value],
    history_path: &Path,
    filters: &CapabilitiesFilterArgs,
) -> Value {
    let recommendations = recommendation_report
        .recommendations
        .iter()
        .filter(|recommendation| suggestion_filter.matches(recommendation.suggestion))
        .cloned()
        .collect::<Vec<CapabilityRecommendation>>();

    json!({
        "status": "ok",
        "command": "capabilities",
        "subcommand": "suggest",
        "source": "history-log",
        "message": "Generated least-privilege capability recommendations from recorded `fwc` execution history.",
        "history_path": history_path.display().to_string(),
        "filters": {
            "zone": &filters.zone,
            "connector": &filters.connector,
            "suggestion": suggestion_filter,
        },
        "summary": recommendation_report.summary(),
        "risk_summaries": &recommendation_report.risk_summaries,
        "recommendations": recommendations,
        "metadata_gaps": source_gaps,
        "supporting_stats": {
            "history_entries_considered": aggregation.total_entries,
            "aggregate_count": aggregation.aggregates.len(),
            "skipped_simulated": aggregation.skipped_simulated,
            "unresolved_entries": aggregation.unresolved_entry_count,
        },
        "unresolved_samples": &aggregation.unresolved_samples,
        "next_actions": [
            "fwc capabilities report".to_owned(),
            "fwc capabilities export".to_owned(),
        ],
    })
}

fn capability_export_payload(
    aggregation: &CapabilityAggregationResult,
    recommendation_report: &fcp_telemetry::CapabilityRecommendationReport,
    source_gaps: &[Value],
    history_path: &Path,
    filters: &CapabilitiesFilterArgs,
) -> Value {
    json!({
        "status": "ok",
        "command": "capabilities",
        "subcommand": "export",
        "source": "history-log",
        "message": "Exported raw capability usage aggregates derived from recorded `fwc` execution history.",
        "history_path": history_path.display().to_string(),
        "filters": {
            "zone": &filters.zone,
            "connector": &filters.connector,
        },
        "summary": {
            "history_entries_considered": aggregation.total_entries,
            "aggregate_count": aggregation.aggregates.len(),
            "skipped_simulated": aggregation.skipped_simulated,
            "unresolved_entries": aggregation.unresolved_entry_count,
        },
        "aggregates": &aggregation.aggregates,
        "recommendation_summary": recommendation_report.summary(),
        "risk_summaries": &recommendation_report.risk_summaries,
        "metadata_gaps": source_gaps,
        "unresolved_samples": &aggregation.unresolved_samples,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "pipe");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)] // Wired when host integration lands.
fn pipeline_dispatch(args: &PipelineArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let cwd = std::env::current_dir()?;
    let roots = pipe::default_pipeline_roots(&cwd);

    match &args.command {
        PipelineCommand::List(_) => pipeline_list_dispatch(&roots),
        PipelineCommand::Show(args) => Ok(pipeline_show_dispatch(&roots, args)),
        PipelineCommand::Validate(args) => Ok(pipeline_validate_dispatch(&roots, args)),
        PipelineCommand::Run(args) => {
            pipeline_run_dispatch(&roots, args, PipelinePlanMode::Run, explicit_host)
        }
        PipelineCommand::DryRun(args) => {
            pipeline_run_dispatch(&roots, args, PipelinePlanMode::DryRun, explicit_host)
        }
        PipelineCommand::Estimate(args) => {
            pipeline_run_dispatch(&roots, args, PipelinePlanMode::Estimate, explicit_host)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
}

#[derive(Debug)]
struct LivePipelineExecutionResult {
    status: &'static str,
    exit_code: CliExitCode,
    executed_steps: usize,
    preflight_only_steps: usize,
    skipped_steps: usize,
    blocked_steps: usize,
    denied_steps: usize,
    error_steps: usize,
    step_results: Vec<Value>,
    outputs: BTreeMap<String, Value>,
}

fn pipeline_execution_context(
    params: &BTreeMap<String, pipe::PipelineParamBinding>,
    step_outputs: &BTreeMap<String, Value>,
) -> Value {
    let params_value = params
        .iter()
        .map(|(name, binding)| (name.clone(), binding.value.clone()))
        .collect::<serde_json::Map<_, _>>();
    let steps_value = step_outputs
        .iter()
        .map(|(step_id, output)| {
            (
                step_id.clone(),
                json!({
                    "output": output,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();

    json!({
        "params": Value::Object(params_value),
        "steps": Value::Object(steps_value),
    })
}

fn pipeline_filter_expression(expr: &str) -> String {
    let expr = expr.trim();
    if expr.starts_with('.') {
        expr.to_owned()
    } else {
        format!(".{expr}")
    }
}

fn pipeline_eval_expression(context: &Value, expr: &str) -> Result<Value> {
    render::apply_extract_filter(context, &pipeline_filter_expression(expr))
}

fn pipeline_value_to_text(value: &Value) -> Result<String> {
    Ok(match value {
        Value::String(text) => text.clone(),
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value)?,
    })
}

fn pipeline_exact_placeholder_expr(template: &str) -> Option<&str> {
    let trimmed = template.trim();
    let inner = trimmed.strip_prefix("{{")?.strip_suffix("}}")?;
    (!inner.contains("{{") && !inner.contains("}}")).then_some(inner.trim())
}

fn pipeline_render_template(template: &str, context: &Value) -> Result<String> {
    let mut rendered = String::new();
    let mut cursor = 0usize;

    while let Some(relative_start) = template[cursor..].find("{{") {
        let start = cursor + relative_start;
        rendered.push_str(&template[cursor..start]);
        let search_start = start + 2;
        let Some(relative_end) = template[search_start..].find("}}") else {
            bail!("unterminated pipeline template placeholder in `{template}`");
        };
        let end = search_start + relative_end;
        let expr = template[search_start..end].trim();
        let value = pipeline_eval_expression(context, expr)?;
        rendered.push_str(&pipeline_value_to_text(&value)?);
        cursor = end + 2;
    }

    rendered.push_str(&template[cursor..]);
    Ok(rendered)
}

fn pipeline_render_value(value: &Value, context: &Value) -> Result<Value> {
    match value {
        Value::String(template) => {
            if let Some(expr) = pipeline_exact_placeholder_expr(template) {
                pipeline_eval_expression(context, expr)
            } else if template.contains("{{") {
                Ok(Value::String(pipeline_render_template(template, context)?))
            } else {
                Ok(Value::String(template.clone()))
            }
        }
        Value::Array(items) => {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(pipeline_render_value(item, context)?);
            }
            Ok(Value::Array(rendered))
        }
        Value::Object(fields) => {
            let mut rendered = serde_json::Map::with_capacity(fields.len());
            for (key, field) in fields {
                rendered.insert(key.clone(), pipeline_render_value(field, context)?);
            }
            Ok(Value::Object(rendered))
        }
        primitive => Ok(primitive.clone()),
    }
}

fn pipeline_condition_filter(template: &str) -> Result<String> {
    let mut rendered = String::new();
    let mut cursor = 0usize;

    while let Some(relative_start) = template[cursor..].find("{{") {
        let start = cursor + relative_start;
        rendered.push_str(&template[cursor..start]);
        let search_start = start + 2;
        let Some(relative_end) = template[search_start..].find("}}") else {
            bail!("unterminated pipeline condition placeholder in `{template}`");
        };
        let end = search_start + relative_end;
        let expr = template[search_start..end].trim();
        rendered.push('(');
        rendered.push_str(&pipeline_filter_expression(expr));
        rendered.push(')');
        cursor = end + 2;
    }

    rendered.push_str(&template[cursor..]);
    Ok(rendered)
}

fn pipeline_evaluate_condition(template: &str, context: &Value) -> Result<bool> {
    let value = render::apply_extract_filter(context, &pipeline_condition_filter(template)?)?;
    match value {
        Value::Bool(flag) => Ok(flag),
        Value::Null => Ok(false),
        other => bail!("pipeline condition `{template}` did not evaluate to a boolean: {other}"),
    }
}

fn pipeline_value_uses_dynamic_outputs(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains("{{steps."),
        Value::Array(items) => items.iter().any(pipeline_value_uses_dynamic_outputs),
        Value::Object(fields) => fields.values().any(pipeline_value_uses_dynamic_outputs),
        _ => false,
    }
}

fn pipeline_step_uses_dynamic_outputs(step: &pipe::PlannedPipelineStep) -> bool {
    pipeline_value_uses_dynamic_outputs(&step.input)
        || step
            .condition
            .as_deref()
            .is_some_and(|condition| condition.contains("{{steps."))
}

const fn pipeline_dry_run_can_materialize_output(operation: &HostToolDescriptor) -> bool {
    operation.idempotent
        && operation.approval_mode.is_none()
        && matches!(operation.safety_tier, SafetyTier::Safe)
}

fn resolve_live_pipeline_operations(
    command: &str,
    plan: &pipe::PipelinePlan,
    client: &HostAdminClient,
    catalog: &HostConnectorCatalog,
) -> Result<BTreeMap<String, ResolvedHostOperation>, DispatchOutcome> {
    let mut operations = BTreeMap::new();

    for step in &plan.steps {
        if operations.contains_key(&step.operation) {
            continue;
        }
        let Some((connector_selector, operation_selector)) = step.operation.split_once('.') else {
            return Err(invalid_operation_reference_dispatch(
                command,
                &step.operation,
            ));
        };
        let resolved = match resolve_host_operation_from_catalog(
            command,
            client,
            catalog,
            connector_selector,
            operation_selector,
        ) {
            Ok(resolved) => resolved,
            Err(outcome) => return Err(outcome),
        };
        operations.insert(step.operation.clone(), resolved);
    }

    Ok(operations)
}

fn live_pipeline_operation_metadata(
    operations: &BTreeMap<String, ResolvedHostOperation>,
) -> BTreeMap<String, pipe::PipelineOperationMetadata> {
    operations
        .iter()
        .map(|(reference, resolved)| {
            (
                reference.clone(),
                pipe::PipelineOperationMetadata {
                    connector: resolved.connector.slug.clone(),
                    selector: resolved.operation.name.clone(),
                    canonical_id: resolved.operation.name.clone(),
                    capability: resolved.operation.capability.to_string(),
                    risk_level: risk_level_label(resolved.operation.risk_level).to_owned(),
                    safety_tier: safety_tier_label(resolved.operation.safety_tier).to_owned(),
                    requires_approval: resolved.operation.approval_mode.is_some(),
                    approval_mode: resolved.operation.approval_mode.as_ref().map_or_else(
                        || "none".to_owned(),
                        |mode| match mode {
                            fcp_core::ApprovalMode::None => "none".to_owned(),
                            fcp_core::ApprovalMode::Policy => "policy".to_owned(),
                            fcp_core::ApprovalMode::Interactive => "interactive".to_owned(),
                            fcp_core::ApprovalMode::ElevationToken => "elevation_token".to_owned(),
                        },
                    ),
                    rate_limits: resolved.rate_limits.clone(),
                },
            )
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn execute_live_pipeline_plan(
    _command: &str,
    plan: &pipe::PipelinePlan,
    operations: &BTreeMap<String, ResolvedHostOperation>,
    mode: PipelinePlanMode,
    host: &ResolvedHostConfig,
    zone: &str,
    auth: &ResolvedLiveAuth,
) -> Result<LivePipelineExecutionResult> {
    let client = HostAdminClient::new(&host.endpoint)?;
    let steps_by_id = plan
        .steps
        .iter()
        .map(|step| (step.id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    let mut step_outputs = BTreeMap::<String, Value>::new();
    let mut step_statuses = BTreeMap::<String, &'static str>::new();
    let mut step_results = Vec::with_capacity(plan.steps.len());
    let mut executed_steps = 0usize;
    let mut preflight_only_steps = 0usize;
    let mut skipped_steps = 0usize;
    let mut blocked_steps = 0usize;
    let mut denied_steps = 0usize;
    let mut error_steps = 0usize;

    for step_id in &plan.execution_order {
        let step = steps_by_id.get(step_id.as_str()).ok_or_else(|| {
            anyhow::anyhow!("pipeline step `{step_id}` disappeared during execution")
        })?;
        let resolved = operations.get(&step.operation).ok_or_else(|| {
            anyhow::anyhow!("pipeline step `{step_id}` is missing resolved live metadata")
        })?;

        let dependency_failures = step
            .depends_on
            .iter()
            .filter(|dependency| {
                step_statuses
                    .get(dependency.as_str())
                    .is_some_and(|status| matches!(*status, "error" | "denied" | "blocked"))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !dependency_failures.is_empty() {
            blocked_steps += 1;
            step_statuses.insert(step.id.clone(), "blocked");
            step_results.push(json!({
                "id": &step.id,
                "operation": &step.operation,
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "status": "blocked",
                "reason": "dependency-failed",
                "depends_on": &step.depends_on,
                "blocked_by": dependency_failures,
            }));
            continue;
        }

        let missing_outputs = step
            .depends_on
            .iter()
            .filter(|dependency| !step_outputs.contains_key(dependency.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_outputs.is_empty() && pipeline_step_uses_dynamic_outputs(step) {
            blocked_steps += 1;
            step_statuses.insert(step.id.clone(), "blocked");
            step_results.push(json!({
                "id": &step.id,
                "operation": &step.operation,
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "status": "blocked",
                "reason": "missing-dependency-output",
                "depends_on": &step.depends_on,
                "missing_outputs": missing_outputs,
                "notes": [
                    "A prior step did not materialize an output value, so this step could not render a truthful live input."
                ],
            }));
            continue;
        }

        let context = pipeline_execution_context(&plan.params, &step_outputs);
        let condition_evaluation = if let Some(condition) = &step.condition {
            Some(pipeline_evaluate_condition(condition, &context)?)
        } else {
            None
        };
        if condition_evaluation == Some(false) {
            skipped_steps += 1;
            step_statuses.insert(step.id.clone(), "skipped");
            step_results.push(json!({
                "id": &step.id,
                "operation": &step.operation,
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "status": "skipped",
                "reason": "condition-false",
                "depends_on": &step.depends_on,
                "condition": {
                    "template": &step.condition,
                    "allowed": false,
                },
            }));
            continue;
        }

        let rendered_input = pipeline_render_value(&step.input, &context)?;
        let (valid, validation_errors) =
            validate_payload_against_schema(&rendered_input, &resolved.operation.input_schema);
        if !valid {
            error_steps += 1;
            step_statuses.insert(step.id.clone(), "error");
            step_results.push(json!({
                "id": &step.id,
                "operation": &step.operation,
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "status": "error",
                "reason": "invalid-input-payload",
                "depends_on": &step.depends_on,
                "condition": condition_evaluation.map(|allowed| {
                    json!({
                        "template": &step.condition,
                        "allowed": allowed,
                    })
                }),
                "input": rendered_input,
                "validation": {
                    "valid": false,
                    "errors": validation_errors,
                },
            }));
            continue;
        }

        let request_id = derive_live_request_id(
            resolved.connector.summary.id.as_str(),
            &resolved.operation.name,
            zone,
            &rendered_input,
            None,
            Some(step.id.as_str()),
        )?;
        let idempotency_key = (mode == PipelinePlanMode::Run).then(|| request_id.to_string());
        let connector_id: ConnectorId =
            resolved
                .connector
                .summary
                .id
                .as_str()
                .parse()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "host connector id `{}` is not canonical: {error}",
                        resolved.connector.summary.id
                    )
                })?;
        let zone_id: ZoneId = zone
            .parse()
            .map_err(|error| anyhow::anyhow!("`{zone}` is not a valid FCP zone: {error}"))?;
        let preflight_request = HostPreflightRequest {
            request_id: request_id.clone(),
            connector_id: connector_id.clone(),
            operation: resolved.operation.name.clone(),
            params: Some(rendered_input.clone()),
            principal: auth.principal_hint.clone(),
            zone_id: Some(zone_id.clone()),
            capability_token: Some(auth.capability_token.clone()),
            approval_tokens: auth.approval_tokens.clone(),
        };
        let preflight = client.preflight(&preflight_request)?;
        let preflight_value = serde_json::to_value(&preflight)?;

        if !preflight.allowed {
            denied_steps += 1;
            step_statuses.insert(step.id.clone(), "denied");
            let reason = preflight
                .reason
                .clone()
                .unwrap_or_else(|| "preflight denied pipeline step".to_owned());
            let history_status = history::OpStatus::Denied;
            let _ = append_history_entry(
                history_status,
                resolved.connector.summary.id.as_str(),
                &resolved.operation.name,
                Some(zone),
                &rendered_input,
                Some(&preflight_value),
                Some(reason.clone()),
                idempotency_key.as_deref(),
                0,
            );
            step_results.push(json!({
                "id": &step.id,
                "operation": &step.operation,
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "status": "denied",
                "mode": if mode == PipelinePlanMode::DryRun { "preflight" } else { "invoke" },
                "depends_on": &step.depends_on,
                "condition": condition_evaluation.map(|allowed| {
                    json!({
                        "template": &step.condition,
                        "allowed": allowed,
                    })
                }),
                "input": rendered_input,
                "request_id": request_id.to_string(),
                "idempotency_key": idempotency_key,
                "preflight": preflight_value,
                "error": {
                    "type": "policy-denied",
                    "message": reason,
                    "recoverable": true,
                },
            }));
            continue;
        }

        if mode == PipelinePlanMode::DryRun
            && !pipeline_dry_run_can_materialize_output(&resolved.operation)
        {
            preflight_only_steps += 1;
            step_statuses.insert(step.id.clone(), "preflight");
            let _ = append_history_entry(
                history::OpStatus::Simulated,
                resolved.connector.summary.id.as_str(),
                &resolved.operation.name,
                Some(zone),
                &rendered_input,
                Some(&preflight_value),
                None,
                None,
                0,
            );
            step_results.push(json!({
                "id": &step.id,
                "operation": &step.operation,
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "status": "ok",
                "mode": "preflight",
                "depends_on": &step.depends_on,
                "condition": condition_evaluation.map(|allowed| {
                    json!({
                        "template": &step.condition,
                        "allowed": allowed,
                    })
                }),
                "input": rendered_input,
                "request_id": request_id.to_string(),
                "preflight": preflight_value,
                "notes": [
                    "Dry-run performed a real host preflight only. This step was not invoked because it is not clearly safe, read-only, and idempotent."
                ],
            }));
            continue;
        }

        let invoke_request = build_live_invoke_request(
            resolved.connector.summary.id.as_str(),
            &resolved.operation.name,
            zone,
            rendered_input.clone(),
            request_id.clone(),
            auth.capability_token.clone(),
            auth.approval_tokens.clone(),
            idempotency_key.clone(),
            None,
        )?;
        let started_at = std::time::Instant::now();
        let response = client.invoke(&invoke_request)?;
        let latency_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let response_value = serde_json::to_value(&response)?;
        let history_status = match response.status {
            InvokeStatus::Ok => history::OpStatus::Success,
            InvokeStatus::Error => history::OpStatus::Error,
        };
        let _ = append_history_entry(
            history_status,
            resolved.connector.summary.id.as_str(),
            &resolved.operation.name,
            Some(zone),
            &rendered_input,
            Some(&response_value),
            response.error.as_ref().map(ToString::to_string),
            idempotency_key.as_deref(),
            latency_ms,
        );

        match response.status {
            InvokeStatus::Ok => {
                executed_steps += 1;
                step_statuses.insert(step.id.clone(), "ok");
                step_outputs.insert(
                    step.id.clone(),
                    response.result.clone().unwrap_or(Value::Null),
                );
                step_results.push(json!({
                    "id": &step.id,
                    "operation": &step.operation,
                    "connector": {
                        "slug": &resolved.connector.slug,
                        "canonical_id": resolved.connector.summary.id.as_str(),
                        "name": &resolved.connector.summary.name,
                    },
                    "status": "ok",
                    "mode": if mode == PipelinePlanMode::DryRun {
                        "dry-run-read"
                    } else {
                        "invoke"
                    },
                    "depends_on": &step.depends_on,
                    "condition": condition_evaluation.map(|allowed| {
                        json!({
                            "template": &step.condition,
                            "allowed": allowed,
                        })
                    }),
                    "input": rendered_input,
                    "request_id": request_id.to_string(),
                    "idempotency_key": idempotency_key,
                    "preflight": preflight_value,
                    "response": response_value,
                }));
            }
            InvokeStatus::Error => {
                error_steps += 1;
                step_statuses.insert(step.id.clone(), "error");
                step_results.push(json!({
                    "id": &step.id,
                    "operation": &step.operation,
                    "connector": {
                        "slug": &resolved.connector.slug,
                        "canonical_id": resolved.connector.summary.id.as_str(),
                        "name": &resolved.connector.summary.name,
                    },
                    "status": "error",
                    "mode": if mode == PipelinePlanMode::DryRun {
                        "dry-run-read"
                    } else {
                        "invoke"
                    },
                    "depends_on": &step.depends_on,
                    "condition": condition_evaluation.map(|allowed| {
                        json!({
                            "template": &step.condition,
                            "allowed": allowed,
                        })
                    }),
                    "input": rendered_input,
                    "request_id": request_id.to_string(),
                    "idempotency_key": idempotency_key,
                    "preflight": preflight_value,
                    "response": response_value,
                }));
            }
        }
    }

    let status = if error_steps > 0 {
        "error"
    } else if denied_steps > 0 && executed_steps == 0 && preflight_only_steps == 0 {
        "denied"
    } else if denied_steps > 0 || blocked_steps > 0 {
        "partial"
    } else {
        "ok"
    };
    let exit_code = if error_steps > 0 {
        CliExitCode::Connector
    } else if denied_steps > 0 {
        CliExitCode::PolicyDenied
    } else {
        CliExitCode::Success
    };

    Ok(LivePipelineExecutionResult {
        status,
        exit_code,
        executed_steps,
        preflight_only_steps,
        skipped_steps,
        blocked_steps,
        denied_steps,
        error_steps,
        step_results,
        outputs: step_outputs,
    })
}

#[allow(dead_code)]
fn recipe_dispatch(args: &RecipeArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    match &args.command {
        RecipeCommand::List(_) => recipe_list_dispatch(),
        RecipeCommand::Show(args) => recipe_show_dispatch(args),
        RecipeCommand::Validate(args) => Ok(recipe_validate_dispatch(args)),
        RecipeCommand::Run(args) => recipe_run_dispatch(args, PipelinePlanMode::Run, explicit_host),
        RecipeCommand::DryRun(args) => {
            recipe_run_dispatch(args, PipelinePlanMode::DryRun, explicit_host)
        }
        RecipeCommand::Estimate(args) => {
            recipe_run_dispatch(args, PipelinePlanMode::Estimate, explicit_host)
        }
        RecipeCommand::Export(args) => Ok(recipe_export_dispatch(args)),
    }
}

#[allow(dead_code)]
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
        let category = recipe["category"].as_str().unwrap_or("unknown").to_owned();
        *acc.entry(category).or_insert(0usize) += 1;
        acc
    });

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "recipe");
    let mut payload = json!({
        "status": "ok",
        "command": "recipe",
        "subcommand": "list",
        "message": "Bundled recipe library loaded. Built-ins include editable defaults so agents can inspect, estimate, and export them deterministically before customization.",
        "recipe_count": recipes.len(),
        "categories": category_counts,
        "recipes": recipes,
        "next_actions": [
            "fwc recipe show github-pr-review-notify".to_owned(),
            "fwc recipe dry-run github-pr-review-notify".to_owned(),
            "fwc recipe export github-pr-review-notify".to_owned(),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)]
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "recipe");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

#[allow(dead_code)]
fn recipe_validate_dispatch(args: &RecipeRefArgs) -> DispatchOutcome {
    let recipe = match load_recipe_definition(&args.recipe, "validate") {
        Ok(recipe) => recipe,
        Err(outcome) => return outcome,
    };
    if !recipe.validation.valid {
        return recipe_invalid_definition_dispatch("validate", &recipe);
    }

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "recipe");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    }
}

#[allow(dead_code)]
fn recipe_run_dispatch(
    args: &RecipeRunArgs,
    mode: PipelinePlanMode,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    let recipe = match load_recipe_definition(&args.recipe, mode.subcommand()) {
        Ok(recipe) => recipe,
        Err(outcome) => return Ok(outcome),
    };
    if !recipe.validation.valid {
        return Ok(recipe_invalid_definition_dispatch(
            mode.subcommand(),
            &recipe,
        ));
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
    if mode == PipelinePlanMode::Estimate {
        let catalog = DiscoveryCatalog::load()?;
        let operation_metadata = match resolve_recipe_operation_metadata(
            &catalog,
            &plan,
            mode.subcommand(),
            &recipe.slug,
        ) {
            Ok(metadata) => metadata,
            Err(outcome) => return Ok(outcome),
        };
        let estimate = pipe::estimate_pipeline(&plan, &operation_metadata)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "recipe");
        let mut payload = json!({
            "status": "ok",
            "command": "recipe",
            "subcommand": mode.subcommand(),
            "recipe": recipe.slug,
            "export_path": recipe.export_path,
            "message": format!(
                "Recipe estimate: {} ({} step(s), {}, highest risk {}). No host execution was attempted.",
                recipe.title,
                plan.step_count,
                estimate.estimated_api_calls.summary,
                estimate.risk_assessment.level,
            ),
            "estimate": estimate,
            "dry_run": false,
            "next_actions": recipe_next_actions(&recipe.slug),
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "recipe",
            json!({
                "subcommand": mode.subcommand(),
                "recipe": &recipe.slug,
                "step_count": plan.step_count,
            }),
            vec![
                format!(
                    "fwc recipe {} {} --host <endpoint> --capability-token-file <token.cbor>",
                    mode.subcommand(),
                    recipe.slug
                ),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let auth = match resolve_live_auth(&args.auth) {
        Ok(auth) => auth,
        Err(error) => {
            return Ok(live_auth_dispatch(
                "recipe",
                &error,
                &[
                    format!(
                        "fwc recipe {} {} --host {} --capability-token-file <token.cbor>",
                        mode.subcommand(),
                        recipe.slug,
                        host.endpoint
                    ),
                    "Provide approval tokens with `--approval-token-file` when recipe steps require explicit authorization.".to_owned(),
                ],
            ));
        }
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let resolved_operations =
        match resolve_live_pipeline_operations("recipe", &plan, &client, &catalog) {
            Ok(operations) => operations,
            Err(outcome) => return Ok(outcome),
        };
    let estimate = pipe::estimate_pipeline(
        &plan,
        &live_pipeline_operation_metadata(&resolved_operations),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let zone = resolved_zone(args.zone.as_deref(), &host);
    let execution = execute_live_pipeline_plan(
        "recipe",
        &plan,
        &resolved_operations,
        mode,
        &host,
        &zone,
        &auth,
    )?;

    let message = match mode {
        PipelinePlanMode::Run => format!(
            "Executed recipe `{}` against the live host in zone `{}` ({} invoked, {} skipped, {} blocked, {} denied, {} errored).",
            recipe.slug,
            zone,
            execution.executed_steps,
            execution.skipped_steps,
            execution.blocked_steps,
            execution.denied_steps,
            execution.error_steps,
        ),
        PipelinePlanMode::DryRun => format!(
            "Ran a truthful dry-run for recipe `{}` in zone `{}` ({} safe step(s) materialized, {} preflight-only, {} skipped, {} blocked).",
            recipe.slug,
            zone,
            execution.executed_steps,
            execution.preflight_only_steps,
            execution.skipped_steps,
            execution.blocked_steps,
        ),
        PipelinePlanMode::Estimate => unreachable!("handled above"),
    };

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "recipe");
    let mut payload = json!({
        "status": execution.status,
        "command": "recipe",
        "subcommand": mode.subcommand(),
        "source": "host-admin-api",
        "recipe": recipe.slug,
        "export_path": recipe.export_path,
        "zone": zone,
        "message": message,
        "estimate": estimate,
        "plan": serde_json::to_value(&plan)?,
        "execution": {
            "mode": mode.subcommand(),
            "executed_steps": execution.executed_steps,
            "preflight_only_steps": execution.preflight_only_steps,
            "skipped_steps": execution.skipped_steps,
            "blocked_steps": execution.blocked_steps,
            "denied_steps": execution.denied_steps,
            "error_steps": execution.error_steps,
            "steps": execution.step_results,
            "outputs": execution.outputs,
        },
        "next_actions": [
            format!("fwc recipe show {}", recipe.slug),
            format!("fwc history --limit {}", plan.step_count.max(10)),
            format!("fwc status --host {}", host.endpoint),
        ],
    });
    let exit_code = execution.exit_code;
    if exit_code.is_success() {
        envelope.inject_into(&mut payload);
    }
    Ok(DispatchOutcome { payload, exit_code })
}

#[allow(dead_code)]
fn recipe_export_dispatch(args: &RecipeRefArgs) -> DispatchOutcome {
    let recipe = match load_recipe_definition(&args.recipe, "export") {
        Ok(recipe) => recipe,
        Err(outcome) => return outcome,
    };

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "recipe");
    let mut payload = json!({
        "status": "ok",
        "command": "recipe",
        "subcommand": "export",
        "content": recipe.toml,
    });
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    }
}

#[allow(dead_code)]
fn recipe_next_actions(recipe: &str) -> Vec<String> {
    vec![
        format!("fwc recipe show {recipe}"),
        format!("fwc recipe validate {recipe}"),
        format!("fwc recipe estimate {recipe}"),
        format!("fwc recipe dry-run {recipe}"),
        format!("fwc recipe export {recipe}"),
    ]
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
fn recipe_invalid_definition_dispatch(
    subcommand: &str,
    recipe: &pipe::BuiltInRecipe,
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "recipe",
            "subcommand": subcommand,
            "recipe": {
                "slug": recipe.slug,
                "title": recipe.title,
                "category": recipe.category,
                "summary": recipe.summary,
                "required_connectors": recipe.required_connectors,
                "export_path": recipe.export_path,
            },
            "definition": &recipe.definition,
            "error": {
                "type": "invalid-recipe-definition",
                "message": "The built-in recipe definition is structurally invalid.",
                "details": &recipe.validation.errors,
                "next_actions": recipe_next_actions(&recipe.slug),
            },
        }),
        exit_code: CliExitCode::Validation,
    }
}

#[allow(dead_code)]
fn recipe_error_dispatch(
    subcommand: &str,
    error_type: &str,
    message: impl Into<String>,
    recipe: Option<&str>,
    details: &[String],
    next_actions: &[String],
) -> DispatchOutcome {
    DispatchOutcome {
        payload: json!({
            "status": "error",
            "command": "recipe",
            "subcommand": subcommand,
            "recipe": recipe,
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

#[allow(dead_code)]
fn resolve_recipe_operation_metadata(
    catalog: &DiscoveryCatalog,
    plan: &pipe::PipelinePlan,
    subcommand: &str,
    recipe: &str,
) -> Result<BTreeMap<String, pipe::PipelineOperationMetadata>, DispatchOutcome> {
    let mut operations = BTreeMap::new();

    for step in &plan.steps {
        if operations.contains_key(&step.operation) {
            continue;
        }

        let Some((connector_selector, operation_selector)) = step.operation.split_once('.') else {
            let next_actions = recipe_next_actions(recipe);
            return Err(recipe_error_dispatch(
                subcommand,
                "invalid-recipe-operation-reference",
                format!(
                    "Recipe step `{}` must use `<connector>.<operation>` syntax, but `{}` does not.",
                    step.id, step.operation
                ),
                Some(recipe),
                &[],
                &next_actions,
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
                let mut next_actions = vec![format!("fwc recipe show {recipe}")];
                if error.suggestions.is_empty() {
                    next_actions.push("fwc list".to_owned());
                } else {
                    next_actions.extend(
                        error
                            .suggestions
                            .iter()
                            .map(|suggestion| format!("fwc show {suggestion}")),
                    );
                }
                return Err(recipe_error_dispatch(
                    subcommand,
                    "recipe-connector-not-found",
                    format!(
                        "Recipe step `{}` refers to unknown connector `{connector_selector}` in `{}`.",
                        step.id, step.operation
                    ),
                    Some(recipe),
                    &details,
                    &next_actions,
                ));
            }
        };
        let operation =
            match connector.resolve_operation(operation_selector) {
                Ok(operation) => operation,
                Err(error) => {
                    let details = if error.suggestions.is_empty() {
                        Vec::new()
                    } else {
                        error.suggestions.clone()
                    };
                    let mut next_actions = vec![format!("fwc recipe show {recipe}")];
                    if error.suggestions.is_empty() {
                        next_actions.push(format!("fwc ops {}", connector.slug));
                    } else {
                        next_actions.extend(error.suggestions.iter().map(|suggestion| {
                            format!("fwc schema {} {suggestion}", connector.slug)
                        }));
                    }
                    return Err(recipe_error_dispatch(
                        subcommand,
                        "recipe-operation-not-found",
                        format!(
                            "Recipe step `{}` refers to unknown operation `{}` on connector `{}`.",
                            step.id, operation_selector, connector.slug
                        ),
                        Some(recipe),
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "pipeline");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "pipeline");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "pipeline");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    }
}

#[allow(dead_code)]
fn pipeline_run_dispatch(
    roots: &pipe::PipelineRoots,
    args: &PipelineRunArgs,
    mode: PipelinePlanMode,
    explicit_host: Option<&str>,
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
    if mode == PipelinePlanMode::Estimate {
        let catalog = DiscoveryCatalog::load()?;
        let operation_metadata =
            match resolve_pipeline_operation_metadata(&catalog, &plan, subcommand, &path) {
                Ok(metadata) => metadata,
                Err(outcome) => return Ok(outcome),
            };
        let estimate = pipe::estimate_pipeline(&plan, &operation_metadata)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "pipeline");
        let mut payload = json!({
            "status": "ok",
            "command": "pipeline",
            "subcommand": subcommand,
            "path": path.display().to_string(),
            "message": format!(
                "Pipeline estimate: {} ({} step(s), {}, highest risk {}). No host execution was attempted.",
                definition.pipeline.name,
                plan.step_count,
                estimate.estimated_api_calls.summary,
                estimate.risk_assessment.level,
            ),
            "estimate": estimate,
            "dry_run": false,
            "next_actions": [
                format!("fwc pipeline show {}", path.display()),
                format!("fwc pipeline validate {}", path.display()),
                format!("fwc pipeline dry-run {} --host <endpoint>", path.display()),
            ],
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Success,
        });
    }

    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "pipeline",
            json!({
                "subcommand": subcommand,
                "path": path.display().to_string(),
                "step_count": plan.step_count,
            }),
            vec![
                format!(
                    "fwc pipeline {} {} --host <endpoint> --capability-token-file <token.cbor>",
                    subcommand,
                    path.display()
                ),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let auth = match resolve_live_auth(&args.auth) {
        Ok(auth) => auth,
        Err(error) => {
            return Ok(live_auth_dispatch(
                "pipeline",
                &error,
                &[
                    format!(
                        "fwc pipeline {} {} --host {} --capability-token-file <token.cbor>",
                        subcommand,
                        path.display(),
                        host.endpoint
                    ),
                    "Provide approval tokens with `--approval-token-file` when pipeline steps require explicit authorization.".to_owned(),
                ],
            ));
        }
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let resolved_operations =
        match resolve_live_pipeline_operations("pipeline", &plan, &client, &catalog) {
            Ok(operations) => operations,
            Err(outcome) => return Ok(outcome),
        };
    let estimate = pipe::estimate_pipeline(
        &plan,
        &live_pipeline_operation_metadata(&resolved_operations),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let zone = resolved_zone(args.zone.as_deref(), &host);
    let execution = execute_live_pipeline_plan(
        "pipeline",
        &plan,
        &resolved_operations,
        mode,
        &host,
        &zone,
        &auth,
    )?;
    let message = match mode {
        PipelinePlanMode::Run => format!(
            "Executed pipeline `{}` against the live host in zone `{}` ({} invoked, {} skipped, {} blocked, {} denied, {} errored).",
            definition.pipeline.name,
            zone,
            execution.executed_steps,
            execution.skipped_steps,
            execution.blocked_steps,
            execution.denied_steps,
            execution.error_steps,
        ),
        PipelinePlanMode::DryRun => format!(
            "Ran a truthful dry-run for pipeline `{}` in zone `{}` ({} safe step(s) materialized, {} preflight-only, {} skipped, {} blocked).",
            definition.pipeline.name,
            zone,
            execution.executed_steps,
            execution.preflight_only_steps,
            execution.skipped_steps,
            execution.blocked_steps,
        ),
        PipelinePlanMode::Estimate => unreachable!("handled above"),
    };

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "pipeline");
    let mut payload = json!({
        "status": execution.status,
        "command": "pipeline",
        "subcommand": subcommand,
        "source": "host-admin-api",
        "path": path.display().to_string(),
        "zone": zone,
        "message": message,
        "estimate": estimate,
        "plan": serde_json::to_value(&plan)?,
        "execution": {
            "mode": subcommand,
            "executed_steps": execution.executed_steps,
            "preflight_only_steps": execution.preflight_only_steps,
            "skipped_steps": execution.skipped_steps,
            "blocked_steps": execution.blocked_steps,
            "denied_steps": execution.denied_steps,
            "error_steps": execution.error_steps,
            "steps": execution.step_results,
            "outputs": execution.outputs,
        },
        "next_actions": [
            format!("fwc pipeline show {}", path.display()),
            format!("fwc history --limit {}", plan.step_count.max(10)),
            format!("fwc status --host {}", host.endpoint),
        ],
    });
    let exit_code = execution.exit_code;
    if exit_code.is_success() {
        envelope.inject_into(&mut payload);
    }
    Ok(DispatchOutcome { payload, exit_code })
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

#[allow(clippy::too_many_lines)]
fn map_dispatch(args: &MapArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
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

    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "map",
            json!({
                "operation": &args.operation,
                "input_count": inputs.len(),
                "concurrency": args.concurrency,
                "on_error": args.on_error,
            }),
            vec![
                format!(
                    "fwc map {} --host <endpoint> --inputs '[{{...}}]'",
                    args.operation
                ),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let Some((connector_selector, operation_selector)) = parse_operation_reference(&args.operation)
    else {
        return Ok(invalid_operation_reference_dispatch("map", &args.operation));
    };
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let resolved = match resolve_host_operation_from_catalog(
        "map",
        &client,
        &catalog,
        connector_selector,
        operation_selector,
    ) {
        Ok(resolved) => resolved,
        Err(outcome) => return Ok(outcome),
    };
    let zone = resolved_zone(args.zone.as_deref(), &host);
    let auth = match resolve_live_auth(&args.auth) {
        Ok(auth) => auth,
        Err(error) => {
            return Ok(live_auth_dispatch(
                "map",
                &error,
                &[
                    format!(
                        "fwc map {} --host {} --capability-token-file <token.cbor> --inputs '[{{...}}]'",
                        args.operation, host.endpoint
                    ),
                    "Provide approval tokens with `--approval-token-file` when the mapped operation requires explicit authorization.".to_owned(),
                ],
            ));
        }
    };

    let preview_count = inputs.len().min(3);
    let plan = batch::BatchPlan {
        operation: args.operation.clone(),
        input_count: inputs.len(),
        concurrency: args.concurrency,
        on_error,
        preview_inputs: inputs.items[..preview_count].to_vec(),
    };

    let mut invalid_items = Vec::new();
    let mut operations = Vec::new();
    for (index, payload) in inputs.items.iter().cloned().enumerate() {
        let (valid, errors) =
            validate_payload_against_schema(&payload, &resolved.operation.input_schema);
        if !valid {
            invalid_items.push(json!({
                "index": index,
                "input": payload,
                "errors": errors,
            }));
            continue;
        }
        let request = build_live_invoke_request(
            resolved.connector.summary.id.as_str(),
            &resolved.operation.name,
            &zone,
            payload,
            derive_live_request_id(
                resolved.connector.summary.id.as_str(),
                &resolved.operation.name,
                &zone,
                &inputs.items[index],
                None,
                Some(&format!("map-item-{}", index + 1)),
            )?,
            auth.capability_token.clone(),
            auth.approval_tokens.clone(),
            None,
            None,
        )?;
        operations.push(HostBatchOperation {
            id: format!("item-{}", index + 1),
            request,
            depends_on: Vec::new(),
        });
    }

    if !invalid_items.is_empty() {
        return Ok(DispatchOutcome {
            payload: json!({
                "status": "error",
                "command": "map",
                "source": "host-admin-api",
                "message": format!(
                    "{} mapped input(s) failed local schema validation, so no live batch call was attempted.",
                    invalid_items.len()
                ),
                "connector": {
                    "slug": &resolved.connector.slug,
                    "canonical_id": resolved.connector.summary.id.as_str(),
                    "name": &resolved.connector.summary.name,
                },
                "operation": {
                    "requested_selector": &args.operation,
                    "selector": &resolved.operation.name,
                    "canonical_id": &resolved.operation.name,
                },
                "plan": plan,
                "invalid_items": invalid_items,
                "next_actions": [
                    format!("fwc schema {} {} --host {}", resolved.connector.slug, resolved.operation.name, host.endpoint),
                    format!("fwc template {} {}", resolved.connector.slug, resolved.operation.name),
                ],
            }),
            exit_code: CliExitCode::Validation,
        });
    }

    let request = HostBatchInvokeRequest {
        operations,
        options: build_host_batch_options(args.concurrency, on_error),
    };
    let response = client.batch(&request)?;
    let (status, exit_code) = batch_status_label(&response);

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "map");
    let mut payload = json!({
    "status": status,
    "command": "map",
    "source": "host-admin-api",
        "message": format!(
            "Executed a live mapped batch for `{}.{}` against `fcp-host` ({} inputs, concurrency={}, on_error={}).",
            resolved.connector.slug,
            resolved.operation.name,
            inputs.len(),
            args.concurrency,
            on_error
        ),
        "connector": {
            "slug": &resolved.connector.slug,
            "canonical_id": resolved.connector.summary.id.as_str(),
            "name": &resolved.connector.summary.name,
        },
        "operation": {
            "requested_selector": &args.operation,
            "selector": &resolved.operation.name,
            "canonical_id": &resolved.operation.name,
        },
        "zone": zone,
        "plan": plan,
        "response": response,
        "next_actions": [
            format!("fwc status {} --host {}", resolved.connector.slug, host.endpoint),
            format!("fwc history --connector {} --limit 20", resolved.connector.slug),
        ],
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome { payload, exit_code })
}

#[allow(clippy::too_many_lines)]
fn batch_file_dispatch(
    args: &BatchFileArgs,
    explicit_host: Option<&str>,
) -> Result<DispatchOutcome> {
    let content = std::fs::read_to_string(&args.file)?;
    let batch = batch_file::BatchFile::parse(&content).map_err(|e| anyhow::anyhow!("{e}"))?;
    let plan = batch_file::ExecutionPlan::from_batch(&batch, args.concurrency, &args.on_error);
    let Some(host) = resolve_host_config(explicit_host)? else {
        return Ok(missing_host_dispatch(
            "batch-file",
            json!({
                "file": args.file.display().to_string(),
                "operation_count": plan.total_operations,
                "connector_count": plan.connectors.len(),
                "dry_run": args.dry_run,
            }),
            vec![
                format!("fwc batch-file {} --host <endpoint>", args.file.display()),
                "Set `FWC_HOST` or `FCP_HOST_ENDPOINT`, or configure an active FCP context."
                    .to_owned(),
            ],
        ));
    };
    let on_error = batch::OnError::parse(&args.on_error).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid --on-error value '{}'. Use 'abort' or 'continue'.",
            args.on_error
        )
    })?;
    let client = HostAdminClient::new(&host.endpoint)?;
    let (catalog, _) = client.catalog(None)?;
    let auth = match resolve_live_auth(&args.auth) {
        Ok(auth) => auth,
        Err(error) => {
            return Ok(live_auth_dispatch(
                "batch-file",
                &error,
                &[
                    format!(
                        "fwc batch-file {} --host {} --capability-token-file <token.cbor>",
                        args.file.display(),
                        host.endpoint
                    ),
                    "Provide approval tokens with `--approval-token-file` when batch operations require explicit authorization.".to_owned(),
                ],
            ));
        }
    };
    let mut invalid_operations = Vec::new();
    let mut request_operations = Vec::new();
    let mut preflights = Vec::new();
    let mut introspection_cache: BTreeMap<String, HostIntrospectionResponse> = BTreeMap::new();

    for op in &batch.operations {
        let connector = match catalog.resolve_connector(&op.connector) {
            Ok(connector) => connector.clone(),
            Err(error) => {
                return Ok(connector_resolution_dispatch(
                    "batch-file",
                    &op.connector,
                    &error,
                ));
            }
        };
        let introspection =
            if let Some(introspection) = introspection_cache.get(connector.summary.id.as_str()) {
                introspection.clone()
            } else {
                let introspection = client.introspect(connector.summary.id.as_str())?;
                introspection_cache.insert(
                    connector.summary.id.as_str().to_owned(),
                    introspection.clone(),
                );
                introspection
            };
        let operation = match resolve_host_tool(&introspection.tools, &op.operation) {
            Ok(operation) => operation.clone(),
            Err(error) => {
                return Ok(host_operation_resolution_dispatch(
                    "batch-file",
                    &connector.slug,
                    &op.operation,
                    &error,
                ));
            }
        };
        let zone = op.zone.as_deref().map_or_else(
            || resolved_zone(args.zone.as_deref(), &host),
            ToOwned::to_owned,
        );
        let (valid, errors) = validate_payload_against_schema(&op.input, &operation.input_schema);
        if !valid {
            invalid_operations.push(json!({
                "id": &op.id,
                "connector": &connector.slug,
                "operation": &operation.name,
                "zone": &zone,
                "errors": errors,
            }));
            continue;
        }

        if args.dry_run {
            let request_id = derive_live_request_id(
                connector.summary.id.as_str(),
                &operation.name,
                &zone,
                &op.input,
                None,
                Some(op.id.as_str()),
            )?;
            let preflight_request = HostPreflightRequest {
                request_id,
                connector_id: connector.summary.id.as_str().parse().map_err(|error| {
                    anyhow::anyhow!(
                        "host connector id `{}` is not canonical: {error}",
                        connector.summary.id
                    )
                })?,
                operation: operation.name.clone(),
                params: Some(op.input.clone()),
                principal: None,
                zone_id: Some(zone.parse().map_err(|error| {
                    anyhow::anyhow!("`{zone}` is not a valid FCP zone for `batch-file`: {error}")
                })?),
                capability_token: Some(auth.capability_token.clone()),
                approval_tokens: auth.approval_tokens.clone(),
            };
            let response = client.preflight(&preflight_request)?;
            preflights.push(json!({
                "id": &op.id,
                "connector": &connector.slug,
                "operation": &operation.name,
                "zone": &zone,
                "allowed": response.allowed,
                "reason": response.reason,
                "missing_capabilities": response.missing_capabilities,
                "rate_limit": response.rate_limit,
                "estimated_cost": response.estimated_cost,
                "budget_status": response.budget_status,
            }));
            continue;
        }

        let request = build_live_invoke_request(
            connector.summary.id.as_str(),
            &operation.name,
            &zone,
            op.input.clone(),
            derive_live_request_id(
                connector.summary.id.as_str(),
                &operation.name,
                &zone,
                &op.input,
                None,
                Some(op.id.as_str()),
            )?,
            auth.capability_token.clone(),
            auth.approval_tokens.clone(),
            None,
            None,
        )?;
        request_operations.push(HostBatchOperation {
            id: op.id.clone(),
            request,
            depends_on: op.depends_on.clone(),
        });
    }

    if !invalid_operations.is_empty() {
        let validation_envelope =
            CommandEnvelope::new(CommandAvailability::LiveRuntime, "batch-file");
        let mut payload = json!({
            "status": "error",
            "command": "batch-file",
            "source": "host-admin-api",
            "message": format!(
                "{} operation(s) in `{}` failed local schema validation, so no live execution was attempted.",
                invalid_operations.len(),
                args.file.display()
            ),
            "file": args.file.display().to_string(),
            "plan": plan,
            "dry_run": args.dry_run,
            "invalid_operations": invalid_operations,
            "next_actions": plan.connectors.iter().map(|connector| {
                format!("fwc show {connector} --host {}", host.endpoint)
            }).collect::<Vec<_>>(),
        });
        validation_envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome {
            payload,
            exit_code: CliExitCode::Validation,
        });
    }

    if args.dry_run {
        let (status, exit_code) = preflight_status_label(&preflights);
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "batch");
        let mut payload = json!({
            "status": status,
            "command": "batch-file",
            "source": "host-admin-api",
            "message": format!(
                "Evaluated real preflight checks for `{}` across {} operation(s) and {} wave(s).",
                args.file.display(),
                plan.total_operations,
                plan.waves.len()
            ),
            "file": args.file.display().to_string(),
            "dry_run": true,
            "plan": plan,
            "preflights": preflights,
            "next_actions": [
                format!("fwc batch-file {} --host {}", args.file.display(), host.endpoint),
            ],
        });
        envelope.inject_into(&mut payload);
        return Ok(DispatchOutcome { payload, exit_code });
    }

    let request = HostBatchInvokeRequest {
        operations: request_operations,
        options: build_host_batch_options(args.concurrency, on_error),
    };
    let response = client.batch(&request)?;
    let (status, exit_code) = batch_status_label(&response);

    let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "batch");
    let mut payload = json!({
        "status": status,
        "command": "batch-file",
        "source": "host-admin-api",
        "message": format!(
            "Executed `{}` as a live batch through `fcp-host` ({} operations across {} connectors).",
            args.file.display(),
            plan.total_operations,
            plan.connectors.len()
        ),
        "file": args.file.display().to_string(),
        "dry_run": false,
        "plan": plan,
        "response": response,
        "next_actions": plan.connectors.iter().map(|connector| {
            format!("fwc status {connector} --host {}", host.endpoint)
        }).collect::<Vec<_>>(),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome { payload, exit_code })
}

#[allow(dead_code)] // Wired when host integration lands.
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
        "archetypes": connector.detail.summary.archetypes.as_known().cloned(),
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
    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": "created",
        "command": "task",
        "subcommand": "create",
        "message": "Created a resumable workflow capsule from the requested intent.",
        "task": task_payload_view(&task),
        "state_root": store.root_dir().display().to_string(),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn task_show_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.load(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": "ok",
        "command": "task",
        "subcommand": "show",
        "message": "Loaded the current workflow capsule state.",
        "task": task_payload_view(&task),
        "state_root": store.root_dir().display().to_string(),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn task_list_dispatch(args: &TaskListArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let tasks = store.list(args.limit, args.status.as_deref())?;
    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": "ok",
        "command": "task",
        "subcommand": "list",
        "message": "Listed recent workflow capsules.",
        "tasks": serde_json::to_value(tasks)?,
        "state_root": store.root_dir().display().to_string(),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": status,
        "command": "task",
        "subcommand": "ask",
        "message": message,
        "question": task.resolution.pending_question,
        "task": task_payload_view(&task),
        "state_root": store.root_dir().display().to_string(),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": "updated",
        "command": "task",
        "subcommand": "bind",
        "message": "Updated the workflow capsule bindings and recomputed its status.",
        "task": task_payload_view(&task),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn task_approve_dispatch(args: &TaskIdArgs) -> Result<DispatchOutcome> {
    let store = workflow::TaskStore::discover()?;
    let Some(task) = store.approve(&args.task_id)? else {
        return Ok(missing_task_dispatch(&args.task_id));
    };

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": "approved",
        "command": "task",
        "subcommand": "approve",
        "message": "Marked the workflow capsule as approved for side-effecting execution.",
        "task": task_payload_view(&task),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "task");
    let mut payload = json!({
        "status": task.capsule_status,
        "command": "task",
        "subcommand": "run",
        "message": if task.approval.workflow {
            "Ran the approved workflow capsule and surfaced the live result of each primitive step."
        } else {
            "Ran the workflow capsule in non-side-effecting mode."
        },
        "execution": execution,
        "task": task_payload_view(&task),
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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
    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "intent");
    let mut payload = json!({
        "status": compiled.status,
        "command": "plan",
        "message": "Compiled the requested intent into an explicit primitive workflow.",
        "workflow": serde_json::to_value(compiled)?,
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    })
}

fn intent_explain_dispatch(request: &intent::IntentRequest) -> Result<DispatchOutcome> {
    let compiled = intent::compile(request);
    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "intent");
    let mut payload = json!({
        "status": compiled.status,
        "command": "explain",
        "message": "Explained why the compiler chose this connector, template, and step sequence.",
        "analysis": serde_json::to_value(compiled)?,
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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
                "message": "The intent compiler reported a blocking state before workflow materialization can continue.",
                "error": {
                    "type": "intent-not-ready",
                    "message": "Resolve the reported ambiguity, unsupported primitive, or missing information before using `fwc do`.",
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

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "do");
    let mut payload = json!({
        "status": if approve { "materialized" } else { "simulated" },
        "command": "do",
        "message": if approve {
            "Materialized the full primitive workflow in approval mode and surfaced the live result of each primitive step."
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
    });
    envelope.inject_into(&mut payload);
    Ok(DispatchOutcome {
        payload,
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
            "Stopped after multiple resolution passes to avoid looping without any new durable resolution progress."
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

#[derive(Debug)]
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
    "list", "show", "validate", "run", "dry-run", "estimate", "export",
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
                            "fwc do \"create a GitHub issue titled 'FWC: add workflow macros'\"".to_owned(),
                            "fwc do \"create a GitHub issue titled 'FWC: add workflow macros'\" --approve".to_owned(),
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

    // ── Phase 6: disambiguate export-tools format flag ───────────────
    if args
        .get(command_index)
        .is_some_and(|segment| segment == "export-tools")
    {
        for index in (command_index + 1)..args.len() {
            if args[index] == "--format" {
                corrections.push(InputCorrection {
                    from: "--format".to_owned(),
                    to: "--tool-format".to_owned(),
                    rationale: "Interpreted `export-tools --format` as the tool schema format flag to avoid colliding with the global output `--format` option.",
                });
                "--tool-format".clone_into(&mut args[index]);
                break;
            }
            if let Some(value) = args[index].strip_prefix("--format=") {
                corrections.push(InputCorrection {
                    from: args[index].clone(),
                    to: format!("--tool-format={value}"),
                    rationale: "Interpreted `export-tools --format` as the tool schema format flag to avoid colliding with the global output `--format` option.",
                });
                args[index] = format!("--tool-format={value}");
                break;
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
                            "fwc task \"create a GitHub issue titled 'FWC: add workflow macros'\"".to_owned(),
                            "fwc task list".to_owned(),
                        ],
                        next_actions: vec![
                            "Pass a quoted intent after `fwc task` to create a new capsule.".to_owned(),
                            "Or use `fwc task show|list|resolve|ask|advance|bind|approve|run` with an existing task id.".to_owned(),
                        ],
                    },
                );
            }

            if command == Some("agent") {
                return structured_error(
                    "missing-agent-subcommand",
                    "No agent coordination subcommand was provided.",
                    CliExitCode::Parse,
                    true,
                    args,
                    &normalized_args,
                    ErrorDetails {
                        did_you_mean: Vec::new(),
                        examples: vec![
                            "fwc agent list".to_owned(),
                            "fwc agent inbox --agent BronzeValley".to_owned(),
                        ],
                        next_actions: vec![
                            "Use `fwc agent list` to inspect the local coordination hub.".to_owned(),
                            "Use `fwc agent announce|reserve|send|inbox` to record or inspect coordinated work.".to_owned(),
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
                    "fwc task \"create a GitHub issue titled 'FWC: add workflow macros'\""
                        .to_owned(),
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
    use std::collections::BTreeMap as StdBTreeMap;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::{
        Cli, CliExitCode, Commands, ConnectorManifest, HostConnectorCatalog, LiveAuthArgs,
        PACKAGE_OUTPUT_FILENAME, PackageBuildMetadata, PackageOutput, PrepareCliError,
        ResolvedHostConfig, catalog, execute, host_discovered_connector, host_mcp_tool_definitions,
        mcp_tool_invoke_args, normalize_args, prepare_cli, serve_mcp,
    };
    use clap::CommandFactory;
    use fcp_core::{
        BudgetEnforcement, BudgetStatus, ConnectorHealth, InvokeResponse, RequestId,
        UsageBudgetSnapshot, UsageBudgetUsage, UsageMetricKind, ZoneId,
    };
    use fcp_host::{
        BudgetReportResponse as HostBudgetReportResponse, ConnectorInventoryApplyReport,
        ConnectorInventoryMutationKind, ConnectorInventoryMutationResponse,
        DiscoveryResponse as HostDiscoveryResponse, DoctorReport as HostDoctorReport,
        IntrospectionResponse as HostIntrospectionResponse, ManagedConnectorConfig,
        PreflightResponse as HostPreflightResponse, StartupReconciliationReport,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

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

    fn assert_discovery_provenance(payload: &Value, source: &str, authoritative: bool, mode: &str) {
        assert_eq!(payload["mode"], mode);
        assert_eq!(payload["provenance"]["source"], source);
        assert_eq!(payload["provenance"]["authoritative"], authoritative);
        assert_eq!(payload["provenance"]["command"], payload["command"]);
        assert!(
            payload["provenance"]["caveat"]
                .as_str()
                .is_some_and(|caveat| !caveat.is_empty())
        );
    }

    fn assert_template_provenance(payload: &Value, source: &str, authoritative: bool, mode: &str) {
        assert_eq!(payload["mode"], mode);
        assert_eq!(payload["provenance"]["source"], source);
        assert_eq!(payload["provenance"]["authoritative"], authoritative);
        assert_eq!(payload["provenance"]["command"], payload["command"]);
        assert!(
            payload["provenance"]["caveat"]
                .as_str()
                .is_some_and(|caveat| !caveat.is_empty())
        );
    }

    fn spawn_mock_host(
        routes: StdBTreeMap<String, Value>,
        expected_requests: usize,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock host should bind");
        listener
            .set_nonblocking(true)
            .expect("mock host should configure nonblocking accept");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("mock host address")
        );
        let responses = routes
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    serde_json::to_string(&value).expect("mock response should serialize"),
                )
            })
            .collect::<StdBTreeMap<_, _>>();

        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut served = 0usize;

            while served < expected_requests && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("mock host accept failed: {error}"),
                };

                served += 1;
                stream
                    .set_nonblocking(false)
                    .expect("mock host stream should switch back to blocking mode");

                let mut reader =
                    BufReader::new(stream.try_clone().expect("mock host should clone socket"));
                let mut request_line = String::new();
                reader
                    .read_line(&mut request_line)
                    .expect("mock host should read request line");
                assert!(
                    !request_line.trim().is_empty(),
                    "mock host received an empty request line"
                );

                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    reader
                        .read_line(&mut header)
                        .expect("mock host should read headers");
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value
                            .trim()
                            .parse()
                            .expect("content-length should be numeric");
                    }
                }

                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    reader
                        .read_exact(&mut body)
                        .expect("mock host should read request body");
                }

                let mut parts = request_line.split_whitespace();
                let method = parts.next().expect("request method should exist");
                let path = parts.next().expect("request path should exist");
                let key = format!("{method} {path}");
                let body = responses.get(&key).unwrap_or_else(|| {
                    panic!(
                        "unexpected mock host request `{key}`; expected one of {:?}",
                        responses.keys().collect::<Vec<_>>()
                    )
                });

                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("mock host should write response");
                stream.flush().expect("mock host should flush response");
            }

            assert_eq!(
                served, expected_requests,
                "mock host served {served} request(s), expected {expected_requests}"
            );
        });

        (endpoint, handle)
    }

    fn spawn_mock_host_sequence(routes: Vec<(String, Value)>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock host should bind");
        listener
            .set_nonblocking(true)
            .expect("mock host should configure nonblocking accept");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("mock host address")
        );
        let expected_requests = routes.len();
        let responses = routes
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    serde_json::to_string(&value).expect("mock response should serialize"),
                )
            })
            .collect::<Vec<_>>();

        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut served = 0usize;

            while served < expected_requests && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("mock host accept failed: {error}"),
                };

                stream
                    .set_nonblocking(false)
                    .expect("mock host stream should switch back to blocking mode");

                let mut reader =
                    BufReader::new(stream.try_clone().expect("mock host should clone socket"));
                let mut request_line = String::new();
                reader
                    .read_line(&mut request_line)
                    .expect("mock host should read request line");
                assert!(
                    !request_line.trim().is_empty(),
                    "mock host received an empty request line"
                );

                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    reader
                        .read_line(&mut header)
                        .expect("mock host should read headers");
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value
                            .trim()
                            .parse()
                            .expect("content-length should be numeric");
                    }
                }

                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    reader
                        .read_exact(&mut body)
                        .expect("mock host should read request body");
                }

                let mut parts = request_line.split_whitespace();
                let method = parts.next().expect("request method should exist");
                let path = parts.next().expect("request path should exist");
                let key = format!("{method} {path}");
                let Some((expected_key, body)) = responses.get(served) else {
                    panic!("missing expected mock response for request {}", served + 1);
                };
                assert_eq!(
                    &key,
                    expected_key,
                    "unexpected mock host request order at position {}",
                    served + 1
                );

                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("mock host should write response");
                stream.flush().expect("mock host should flush response");
                served += 1;
            }

            assert_eq!(
                served, expected_requests,
                "mock host served {served} request(s), expected {expected_requests}"
            );
        });

        (endpoint, handle)
    }

    fn mock_connector_summary_json() -> Value {
        let health =
            serde_json::to_value(ConnectorHealth::healthy()).expect("health should serialize");
        json!({
            "id": "fcp.github:enterprise:v1",
            "name": "GitHub Enterprise",
            "description": "GitHub connector surfaced through fcp-host.",
            "version": "1.2.3",
            "categories": ["code", "dev-tools"],
            "tool_count": 2,
            "max_safety_tier": "risky",
            "enabled": true,
            "health": health,
            "last_health_check": "2026-03-10T00:00:00Z",
        })
    }

    fn mock_connector_summary_custom_json(
        id: &str,
        name: &str,
        tool_count: usize,
        max_safety_tier: &str,
    ) -> Value {
        let health =
            serde_json::to_value(ConnectorHealth::healthy()).expect("health should serialize");
        json!({
            "id": id,
            "name": name,
            "description": format!("{name} connector surfaced through fcp-host."),
            "version": "1.2.3",
            "categories": ["code", "dev-tools"],
            "tool_count": tool_count,
            "max_safety_tier": max_safety_tier,
            "enabled": true,
            "health": health,
            "last_health_check": "2026-03-10T00:00:00Z",
        })
    }

    fn mock_tools_json() -> Vec<Value> {
        vec![
            json!({
                "name": "github.create_issue",
                "description": "Create a GitHub issue in a repository.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": { "type": "string" },
                        "repo": { "type": "string" },
                        "title": { "type": "string" },
                        "body": { "type": "string" }
                    },
                    "required": ["owner", "repo", "title"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "number": { "type": "integer" },
                        "url": { "type": "string" }
                    },
                    "required": ["number"]
                },
                "capability": "github.issue_write",
                "risk_level": "medium",
                "safety_tier": "risky",
                "idempotency": "none",
                "approval_mode": "interactive",
                "requires_confirmation": true,
                "idempotent": false,
                "supports_simulate": true,
                "rate_limits": ["core"],
                "examples": [
                    {
                        "description": "Minimal issue creation payload.",
                        "input": {
                            "owner": "octocat",
                            "repo": "hello-world",
                            "title": "Bug report"
                        },
                        "output": {
                            "number": 42,
                            "url": "https://example.test/issues/42"
                        }
                    }
                ],
                "ai_hints": {
                    "when_to_use": "Use this when you need to file a new task or bug in GitHub.",
                    "common_mistakes": ["Forgetting the repository owner."],
                    "examples": [],
                    "related": ["github.get_issue"]
                }
            }),
            json!({
                "name": "github.get_issue",
                "description": "Fetch an existing GitHub issue by number.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": { "type": "string" },
                        "repo": { "type": "string" },
                        "number": { "type": "integer" }
                    },
                    "required": ["owner", "repo", "number"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" }
                    }
                },
                "capability": "github.issue_read",
                "risk_level": "low",
                "safety_tier": "safe",
                "idempotency": "strict",
                "requires_confirmation": false,
                "idempotent": true,
                "supports_simulate": true,
                "examples": [
                    {
                        "description": "Fetch one issue.",
                        "input": {
                            "owner": "octocat",
                            "repo": "hello-world",
                            "number": 42
                        }
                    }
                ],
                "ai_hints": {
                    "when_to_use": "Use this when you need details about an existing issue.",
                    "common_mistakes": ["Passing a pull request number instead of an issue number."],
                    "examples": [],
                    "related": ["github.create_issue"]
                }
            }),
        ]
    }

    fn mock_discovery_response_json() -> Value {
        json!({
            "connectors": [mock_connector_summary_json()],
            "registry_version": 7,
            "supports_streaming": true,
            "supports_batching": true,
            "timestamp": "2026-03-10T00:00:00Z"
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn mock_discovery_response_with_connectors(connectors: Vec<Value>) -> Value {
        json!({
            "connectors": connectors,
            "registry_version": 7,
            "supports_streaming": true,
            "supports_batching": true,
            "timestamp": "2026-03-10T00:00:00Z"
        })
    }

    fn mock_inventory_response_json() -> Value {
        json!({
            "connector": mock_connector_summary_json(),
            "registry_version": 7
        })
    }

    fn mock_introspection_response_json() -> Value {
        json!({
            "connector": mock_connector_summary_json(),
            "tools": mock_tools_json(),
            "rate_limits": {
                "limits": [],
                "tool_pool_map": {}
            },
            "archetype": "request_response",
            "introspection": {
                "operations": [],
                "events": [],
                "resource_types": [],
                "auth_caps": null,
                "event_caps": null
            }
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn mock_introspection_response_with_tools(connector: Value, tools: Vec<Value>) -> Value {
        json!({
            "connector": connector,
            "tools": tools,
            "rate_limits": {
                "limits": [],
                "tool_pool_map": {}
            },
            "archetype": "request_response",
            "introspection": {
                "operations": [],
                "events": [],
                "resource_types": [],
                "auth_caps": null,
                "event_caps": null
            }
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn mock_tool_descriptor_json(
        name: &str,
        capability: &str,
        risk_level: &str,
        safety_tier: &str,
        idempotency: &str,
        approval_mode: Option<&str>,
        input_schema: Value,
        output_schema: Value,
    ) -> Value {
        json!({
            "name": name,
            "description": format!("Mock descriptor for {name}."),
            "input_schema": input_schema,
            "output_schema": output_schema,
            "capability": capability,
            "risk_level": risk_level,
            "safety_tier": safety_tier,
            "idempotency": idempotency,
            "approval_mode": approval_mode,
            "requires_confirmation": approval_mode.is_some(),
            "idempotent": matches!(idempotency, "strict" | "best_effort"),
            "supports_simulate": true,
        })
    }

    fn mock_preflight_response_json(allowed: bool) -> Value {
        serde_json::to_value(if allowed {
            HostPreflightResponse::allowed()
        } else {
            HostPreflightResponse::denied("connector policy denied the request")
        })
        .expect("preflight response should serialize")
    }

    fn mock_doctor_report_json() -> Value {
        serde_json::to_value(HostDoctorReport::baseline("z:work"))
            .expect("doctor report should serialize")
    }

    fn mock_budget_report_response_json() -> Value {
        serde_json::to_value(HostBudgetReportResponse {
            schema_version: HostBudgetReportResponse::SCHEMA_VERSION.to_string(),
            generated_at: chrono::Utc::now(),
            zones: vec![UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Requests,
                    used: 3,
                    limit: 10,
                    remaining: 7,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_000_060,
                    status: BudgetStatus::Ok,
                }],
                updated_at: 1_700_000_001,
            }],
        })
        .expect("budget report should serialize")
    }

    fn mock_invoke_response_json(result: Value) -> Value {
        serde_json::to_value(InvokeResponse::ok(RequestId::random(), result))
            .expect("invoke response should serialize")
    }

    fn mock_batch_response_json(ids: &[&str]) -> Value {
        json!({
            "status": "success",
            "completed": ids.len(),
            "failed": 0,
            "skipped": 0,
            "results": ids.iter().map(|id| {
                json!({
                    "id": id,
                    "status": "success",
                    "output": {
                        "ok": true,
                    },
                    "duration_ms": 1,
                })
            }).collect::<Vec<_>>(),
            "total_duration_ms": ids.len(),
        })
    }

    fn test_capability_token_arg() -> String {
        use base64::Engine as _;

        let token = super::CapabilityToken::test_token();
        base64::engine::general_purpose::STANDARD
            .encode(token.raw.to_cbor().expect("test token should encode"))
    }

    fn write_test_package_output(connector_id: &str, version: &str) -> (TempDir, PathBuf) {
        const PLACEHOLDER_INTERFACE_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

        let tempdir = tempfile::tempdir().expect("temp package dir");
        let package_dir = tempdir.path().join("package");
        fs::create_dir_all(&package_dir).expect("package dir");

        let manifest_template = format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "{PLACEHOLDER_INTERFACE_HASH}"

[connector]
id = "{connector_id}"
name = "Fixture Connector"
version = "{version}"
description = "Fixture connector used by fwc install/update tests"
archetypes = ["operational"]
format = "wasi"

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
migration_hint = "init"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.echo]
description = "Echo fixture operation"
capability = "fixture.echo"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(&manifest_template)
            .expect("fixture manifest should parse unchecked");
        let interface_hash = unchecked
            .compute_interface_hash()
            .expect("fixture interface hash should compute");
        let manifest_text =
            manifest_template.replace(PLACEHOLDER_INTERFACE_HASH, &interface_hash.to_string());
        let manifest =
            ConnectorManifest::parse_str(&manifest_text).expect("fixture manifest should validate");

        let binary_path = package_dir.join("fixture-connector");
        fs::write(&binary_path, format!("fixture:{connector_id}:{version}")).expect("binary");
        let manifest_path = package_dir.join("manifest.toml");
        fs::write(&manifest_path, &manifest_text).expect("manifest");
        let build_metadata_path = package_dir.join("build-metadata.json");
        fs::write(
            &build_metadata_path,
            serde_json::to_vec_pretty(&PackageBuildMetadata {
                rust_version: "1.86.0-nightly".to_string(),
                cargo_version: "1.86.0-nightly".to_string(),
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
                build_timestamp: "2026-03-11T07:00:00Z".to_string(),
                profile: "release".to_string(),
                git_commit: Some("deadbeef".to_string()),
                git_dirty: Some(false),
                features: vec![],
                build_env: std::collections::HashMap::new(),
                cargo_flags: vec!["--release".to_string()],
            })
            .expect("build metadata json"),
        )
        .expect("build metadata");

        let package_output = PackageOutput {
            output_dir: package_dir.clone(),
            binary_path: binary_path.clone(),
            manifest_path,
            sbom_path: None,
            build_metadata_path,
            binary_sha256: super::compute_file_sha256(&binary_path).expect("binary sha"),
            connector_id: manifest.connector.id.to_string(),
            version: manifest.connector.version.to_string(),
        };
        let package_output_path = package_dir.join(PACKAGE_OUTPUT_FILENAME);
        fs::write(
            &package_output_path,
            serde_json::to_vec_pretty(&package_output).expect("package output json"),
        )
        .expect("package output");

        (tempdir, package_output_path)
    }

    fn mock_inventory_mutation_response_json(
        kind: ConnectorInventoryMutationKind,
        dry_run: bool,
        current: ManagedConnectorConfig,
        previous: Option<ManagedConnectorConfig>,
    ) -> Value {
        serde_json::to_value(ConnectorInventoryMutationResponse {
            kind,
            dry_run,
            connectors_file: "/tmp/fcp-host-connectors.json".to_string(),
            previous,
            current,
            inventory_size: 1,
            apply: ConnectorInventoryApplyReport {
                added: if matches!(kind, ConnectorInventoryMutationKind::Install) && !dry_run {
                    vec!["fcp.github:enterprise:v1".to_string()]
                } else {
                    Vec::new()
                },
                updated: if matches!(kind, ConnectorInventoryMutationKind::Update) && !dry_run {
                    vec!["fcp.github:enterprise:v1".to_string()]
                } else {
                    Vec::new()
                },
                removed: Vec::new(),
                unchanged: if dry_run {
                    vec!["fcp.github:enterprise:v1".to_string()]
                } else {
                    Vec::new()
                },
                registry_version: 11,
            },
            admin_state: StartupReconciliationReport {
                reconciled_at: chrono::Utc::now(),
                tracked_connectors: 1,
                created_connectors: 0,
                observed_updates: usize::from(!dry_run),
                drifted_connectors: 0,
                entries: Vec::new(),
            },
        })
        .expect("inventory mutation response should serialize")
    }

    fn mock_github_host_routes(extra: StdBTreeMap<String, Value>) -> StdBTreeMap<String, Value> {
        let mut routes = StdBTreeMap::from([
            (
                "POST /rpc/discover".to_owned(),
                mock_discovery_response_json(),
            ),
            (
                "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                mock_introspection_response_json(),
            ),
        ]);
        routes.extend(extra);
        routes
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
            &[
                "fwc",
                "task",
                "create a GitHub issue titled 'FWC: add workflow macros'",
            ]
            .map(str::to_owned),
        )
        .expect("task intent should normalize");

        assert_eq!(
            normalized.args,
            vec![
                "fwc",
                "task",
                "create",
                "create a GitHub issue titled 'FWC: add workflow macros'"
            ]
        );
        assert_eq!(normalized.corrections.len(), 1);
        assert_eq!(
            normalized.corrections[0].from,
            "task 'create a GitHub issue titled '\\''FWC: add workflow macros'\\'''"
        );
        assert_eq!(
            normalized.corrections[0].to,
            "task create 'create a GitHub issue titled '\\''FWC: add workflow macros'\\'''"
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
            "--offline".to_owned(),
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
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([
                (
                    "POST /rpc/preflight".to_owned(),
                    mock_preflight_response_json(true),
                ),
                (
                    "POST /rpc/invoke".to_owned(),
                    mock_invoke_response_json(json!({
                        "number": 42,
                        "url": "https://example.test/issues/42",
                    })),
                ),
            ])),
            4,
        );
        let (exit_code, text) = execute_text(&[
            "fwc",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}",
            "--capability-token",
            &capability_token,
            "--template",
            "{{command}} {{connector.slug}} {{operation.requested_selector}}",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(text, "invoke github issues.create\n");
    }

    #[test]
    fn execute_invoke_accepts_set_bindings_for_payload_authoring() {
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([
                (
                    "POST /rpc/preflight".to_owned(),
                    mock_preflight_response_json(true),
                ),
                (
                    "POST /rpc/invoke".to_owned(),
                    mock_invoke_response_json(json!({
                        "number": 42,
                        "url": "https://example.test/issues/42",
                    })),
                ),
            ])),
            4,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "invoke",
            "github",
            "issues.create",
            "--set",
            "owner=octocat",
            "--set",
            "repo=hello-world",
            "--set",
            "title=Bug report",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["phase"], "execution");
        assert_eq!(payload["input_authoring"]["primary_source"], "binding-set");
        assert_eq!(payload["input_authoring"]["binding_count"], 3);
        assert_eq!(
            payload["input_authoring"]["payload"],
            json!({
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Bug report",
            })
        );
        assert_eq!(payload["input_authoring"]["validation"]["valid"], true);
        assert_eq!(payload["response"]["result"]["number"], 42);
    }

    #[test]
    fn execute_invoke_returns_validation_for_schema_invalid_payload() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "invoke",
            "github",
            "issues.create",
            "--input",
            "{}",
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["error"]["type"], "invalid-input-payload");
        assert_eq!(payload["input_authoring"]["validation"]["valid"], false);
        assert_eq!(payload["input_authoring"]["validation"]["error_count"], 3);
    }

    #[test]
    fn execute_invoke_rejects_conflicting_primary_sources() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fwc-main-invoke-input-{unique}.json"));
        std::fs::write(
            &path,
            r#"{"owner":"octocat","repo":"hello-world","title":"Bug report"}"#,
        )
        .unwrap();
        let path_string = path.display().to_string();

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "invoke",
            "github",
            "issues.create",
            "--input",
            r#"{"owner":"octocat","repo":"hello-world","title":"Bug report"}"#,
            "--file",
            &path_string,
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["error"]["type"], "conflicting-input-sources");
        assert_eq!(payload["error"]["recoverable"], true);
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
    fn execute_list_with_host_uses_host_discovery_api() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([(
                "POST /rpc/discover".to_owned(),
                mock_discovery_response_json(),
            )]),
            1,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "list",
            "--zone",
            "z:work",
            "--category",
            "code",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["source"], "host-admin-api");
        assert_discovery_provenance(&payload, "live_host_inventory", true, "live-inventory");
        assert_eq!(payload["filters"]["category"], "code");
        assert_eq!(payload["filters"]["zone"], "z:work");
        assert_eq!(payload["connectors"][0]["slug"], "github");
        assert_eq!(
            payload["connectors"][0]["canonical_id"],
            "fcp.github:enterprise:v1"
        );
        assert_eq!(payload["filter_gaps"][0]["field"], "filters.zone");
    }

    #[test]
    fn execute_export_tools_without_host_requires_explicit_offline_mode() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "export-tools", "--format", "mcp", "github"]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_export_tools_offline_stays_in_offline_artifact_mode() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "export-tools",
            "--offline",
            "--format",
            "mcp",
            "github",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["source"], "workspace-manifests");
        assert_eq!(payload["mode"], "offline-artifact");
    }

    #[test]
    fn execute_export_tools_with_host_uses_live_introspection() {
        let (host, server) = spawn_mock_host(mock_github_host_routes(StdBTreeMap::new()), 2);

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "export-tools",
            "--format",
            "mcp",
            "github",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["mode"], "live-introspection");
        assert_eq!(payload["connector_count"], 1);
        assert_eq!(payload["tool_count"], 2);
        assert_eq!(payload["tools"][0]["name"], "github.create_issue");
    }

    #[test]
    fn execute_show_with_host_uses_inventory_and_introspection() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/connectors/fcp.github:enterprise:v1".to_owned(),
                    mock_inventory_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            3,
        );

        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "--host", &host, "show", "github"]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["source"], "host-admin-api");
        assert_discovery_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert_eq!(payload["connector"]["slug"], "github");
        assert_eq!(payload["connector"]["archetype"], "request_response");
        assert_eq!(payload["connector"]["operation_count"], 2);
        assert_eq!(
            payload["operations"]["preview"][0]["selector"],
            "github.create_issue"
        );
        assert_eq!(payload["metadata_gaps"], json!([]));
    }

    #[test]
    fn execute_ops_with_host_honors_risk_filter() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            2,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "ops",
            "github",
            "--risk-at-most",
            "low",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["source"], "host-admin-api");
        assert_discovery_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert_eq!(payload["operations"].as_array().unwrap().len(), 1);
        assert_eq!(payload["operations"][0]["selector"], "github.get_issue");
    }

    #[test]
    fn execute_schema_and_examples_with_host_resolve_local_operation_selector() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/connectors/fcp.github:enterprise:v1".to_owned(),
                    mock_inventory_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            5,
        );

        let (schema_exit, schema_payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "schema",
            "github",
            "create_issue",
            "--examples",
        ]);
        let (examples_exit, examples_payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "examples",
            "github",
            "create_issue",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(schema_exit, CliExitCode::Success.into());
        assert_eq!(schema_payload["source"], "host-admin-api");
        assert_discovery_provenance(
            &schema_payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert_eq!(
            schema_payload["operation"]["selector"],
            "github.create_issue"
        );
        assert_eq!(
            schema_payload["guidance"]["when_to_use"],
            "Use this when you need to file a new task or bug in GitHub."
        );
        assert!(
            schema_payload["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["path"] == "owner"),
            "expected schema fields to include the required `owner` path"
        );

        assert_eq!(examples_exit, CliExitCode::Success.into());
        assert_eq!(examples_payload["source"], "host-admin-api");
        assert_discovery_provenance(
            &examples_payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert_eq!(
            examples_payload["operation"]["selector"],
            "github.create_issue"
        );
        assert_eq!(
            examples_payload["examples"][0]["input"]["title"],
            "Bug report"
        );
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
            "execution-error"
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
        assert_eq!(advanced_payload["status"], "execution-error");
        assert_eq!(
            advanced_payload["execution"]["status"],
            "stopped-on-primitive-error"
        );
        assert_eq!(advanced_payload["task"]["execution_history_count"], 1);
        assert_eq!(
            advanced_payload["task"]["last_execution"]["status"],
            "stopped-on-primitive-error"
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
        assert_eq!(payload["execution"]["status"], "stopped-on-primitive-error");
        assert_eq!(payload["execution"]["executed_count"], 5);
        assert_eq!(payload["execution"]["withheld_count"], 0);
    }

    #[test]
    fn execute_do_rejects_conflicting_execution_flags() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "do".to_owned(),
            "create a GitHub issue titled 'FWC: add workflow macros'".to_owned(),
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
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "invoke");
        assert_eq!(payload["input_normalization"]["applied"][0]["from"], "call");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_health_alias_resolves_to_status() {
        let args = vec!["fwc".to_owned(), "--json".to_owned(), "health".to_owned()];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "status");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_preview_alias_resolves_to_simulate() {
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/preflight".to_owned(),
                mock_preflight_response_json(true),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "preview",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "simulate");
        assert_eq!(payload["phase"], "preflight");
    }

    #[test]
    fn execute_simulate_host_requires_real_capability_token() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            "http://127.0.0.1:9999",
            "simulate",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}",
        ]);

        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["command"], "simulate");
        assert_eq!(payload["error"]["type"], "missing-capability-token");
    }

    #[test]
    fn execute_doctor_reads_live_host_report() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([("POST /doctor".to_owned(), mock_doctor_report_json())]),
            1,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc", "--json", "--host", &host, "doctor", "--zone", "z:work",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "doctor");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["report"]["zone_id"], "z:work");
        assert_eq!(payload["summary"]["overall_status"], "OK");
    }

    #[test]
    fn execute_budget_reads_live_host_report() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([(
                "POST /rpc/budget/report".to_owned(),
                mock_budget_report_response_json(),
            )]),
            1,
        );
        let (exit_code, payload) = execute_json(&["fwc", "--json", "--host", &host, "budget"]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "budget");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["summary"]["zone_count"], 1);
        assert_eq!(payload["zones"][0]["zone_id"], "z:work");
    }

    #[test]
    fn execute_install_applies_live_host_inventory_mutation() {
        let (_package_dir, package_output_path) =
            write_test_package_output("fcp.github:enterprise:v1", "1.2.4");
        let package_output_path = package_output_path.display().to_string();
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([(
                "POST /rpc/connectors/apply".to_owned(),
                mock_inventory_mutation_response_json(
                    ConnectorInventoryMutationKind::Install,
                    false,
                    ManagedConnectorConfig {
                        id: "fcp.github:enterprise:v1".to_string(),
                        binary: "/opt/fcp/github-enterprise".to_string(),
                        name: Some("GitHub Enterprise".to_string()),
                        description: Some("Live installed GitHub connector".to_string()),
                        args: Vec::new(),
                        env: StdBTreeMap::new(),
                        config: None,
                        categories: vec!["code".to_string()],
                        version: Some("1.2.4".to_string()),
                    },
                    None,
                ),
            )]),
            1,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "install",
            &package_output_path,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "install");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["activation"]["live_reload_applied"], true);
        assert_eq!(payload["activation"]["registry_version"], 11);
        assert_eq!(
            payload["installed"]["canonical_id"],
            "fcp.github:enterprise:v1"
        );
    }

    #[test]
    fn execute_update_dry_run_uses_live_host_inventory_preview() {
        let (_package_dir, package_output_path) =
            write_test_package_output("fcp.github:enterprise:v1", "1.2.4");
        let package_output_path = package_output_path.display().to_string();
        let previous = ManagedConnectorConfig {
            id: "fcp.github:enterprise:v1".to_string(),
            binary: "/opt/fcp/github-enterprise-old".to_string(),
            name: Some("GitHub Enterprise".to_string()),
            description: Some("Existing live GitHub connector".to_string()),
            args: vec!["--existing".to_string()],
            env: StdBTreeMap::from([("LOG_LEVEL".to_string(), "debug".to_string())]),
            config: Some(json!({ "profile": "work" })),
            categories: vec!["code".to_string(), "dev-tools".to_string()],
            version: Some("1.2.3".to_string()),
        };
        let planned = ManagedConnectorConfig {
            id: "fcp.github:enterprise:v1".to_string(),
            binary: "/opt/fcp/github-enterprise-new".to_string(),
            name: Some("GitHub Enterprise".to_string()),
            description: Some("Updated live GitHub connector".to_string()),
            args: previous.args.clone(),
            env: previous.env.clone(),
            config: previous.config.clone(),
            categories: previous.categories.clone(),
            version: Some("1.2.4".to_string()),
        };
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "POST /rpc/connectors/apply".to_owned(),
                    mock_inventory_mutation_response_json(
                        ConnectorInventoryMutationKind::Update,
                        true,
                        planned,
                        Some(previous),
                    ),
                ),
            ]),
            2,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "update",
            "github",
            "--source",
            &package_output_path,
            "--dry-run",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "update");
        assert_eq!(payload["mode"], "dry-run");
        assert_eq!(payload["activation"]["inventory_updated"], false);
        assert_eq!(payload["response"]["dry_run"], true);
        assert_eq!(payload["response"]["current"]["args"][0], "--existing");
        assert_eq!(payload["updated"]["version"], "1.2.4");
    }

    #[test]
    fn execute_capabilities_report_uses_real_history_entries() {
        let root = std::env::temp_dir().join(format!(
            "fwc-capabilities-history-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let history_path = root.join("history.jsonl");
        let _guard = super::install_test_history_path(history_path);

        super::append_history_entry(
            super::history::OpStatus::Success,
            "fcp.slack",
            "slack.post_message",
            Some("z:work"),
            &json!({"channel":"C123","text":"hello"}),
            Some(&json!({"ok":true})),
            None,
            None,
            12,
        )
        .expect("history append should succeed");
        super::append_history_entry(
            super::history::OpStatus::Denied,
            "fcp.discord",
            "delete_message",
            Some("z:work"),
            &json!({"channel_id":"1","message_id":"2"}),
            Some(&json!({"allowed":false})),
            Some("policy denied".to_owned()),
            None,
            0,
        )
        .expect("history append should succeed");
        super::append_history_entry(
            super::history::OpStatus::Simulated,
            "fcp.slack",
            "slack.post_message",
            Some("z:work"),
            &json!({"channel":"C123","text":"preview"}),
            Some(&json!({"allowed":true})),
            None,
            None,
            0,
        )
        .expect("history append should succeed");

        let (exit_code, payload) = execute_json(&["fwc", "--json", "capabilities", "report"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "capabilities");
        assert_eq!(payload["subcommand"], "report");
        assert_eq!(payload["summary"]["aggregate_count"], 2);
        assert_eq!(payload["summary"]["skipped_simulated"], 1);
        assert_eq!(payload["zones"][0]["zone_id"], "z:work");
        assert!(
            payload["zones"][0]["capabilities"]
                .as_array()
                .is_some_and(|entries| entries
                    .iter()
                    .any(|entry| entry["capability_id"] == "slack.write"))
        );
        assert!(
            payload["zones"][0]["capabilities"]
                .as_array()
                .is_some_and(|entries| entries
                    .iter()
                    .any(|entry| entry["capability_id"] == "discord.delete"))
        );
    }

    #[test]
    fn execute_capabilities_suggest_filters_review_risky() {
        let root = std::env::temp_dir().join(format!(
            "fwc-capabilities-suggest-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let history_path = root.join("history.jsonl");
        let _guard = super::install_test_history_path(history_path);

        super::append_history_entry(
            super::history::OpStatus::Denied,
            "fcp.discord",
            "delete_message",
            Some("z:work"),
            &json!({"channel_id":"1","message_id":"2"}),
            Some(&json!({"allowed":false})),
            Some("policy denied".to_owned()),
            None,
            0,
        )
        .expect("history append should succeed");

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "capabilities",
            "suggest",
            "--filter",
            "review-risky",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "capabilities");
        assert_eq!(payload["subcommand"], "suggest");
        assert_eq!(payload["recommendations"][0]["suggestion"], "review_risky");
        assert_eq!(
            payload["recommendations"][0]["key"]["capability_id"],
            "discord.delete"
        );
    }

    // ── Intent recovery: typo auto-corrections (readonly) ───────────────

    #[test]
    fn execute_gudie_typo_resolves_to_guide() {
        let args = vec!["fwc".to_owned(), "--json".to_owned(), "gudie".to_owned()];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "guide");
        assert_eq!(
            payload["input_normalization"]["applied"][0]["from"],
            "gudie"
        );
        assert_eq!(payload["input_normalization"]["applied"][0]["to"], "guide");
    }

    #[test]
    fn execute_lsit_typo_resolves_to_list() {
        let args = vec![
            "fwc".to_owned(),
            "--json".to_owned(),
            "--offline".to_owned(),
            "lsit".to_owned(),
        ];
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
            "--offline".to_owned(),
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
            "--offline".to_owned(),
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

        assert_eq!(outcome.exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "status");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
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

        assert_eq!(outcome.exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "ops");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_list_without_host_requires_explicit_offline_mode() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "list"]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "list");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_list_offline_returns_manifest_backed_inventory() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "list", "--offline"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "list");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
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
    fn execute_search_offline_surfaces_github_issue_matches() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "search", "github issue", "--offline"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "search");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
        assert!(payload["results"].as_array().unwrap().iter().any(|result| {
            result["connector"] == "github" && result["operation"] == "github.create_issue"
        }));
    }

    #[test]
    fn execute_search_with_host_uses_live_introspection() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            2,
        );

        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "--host", &host, "search", "github issue"]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "search");
        assert_eq!(payload["source"], "host-admin-api");
        assert_discovery_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert!(payload["results"].as_array().unwrap().iter().any(|result| {
            result["connector"] == "github" && result["operation"] == "github.create_issue"
        }));
    }

    #[test]
    fn execute_show_github_offline_returns_manifest_detail() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "show", "github", "--offline"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "show");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
        assert_eq!(payload["connector"]["slug"], "github");
        assert_eq!(payload["connector"]["canonical_id"], "fcp.github");
        assert_eq!(payload["connector"]["format"], "wasi");
        assert_eq!(payload["connector"]["state"], "unknown");
        assert_eq!(payload["zones"]["home"], "z:work");
        assert_eq!(payload["shared_descriptor"]["connector_id"], "fcp.github");
        assert_eq!(
            payload["shared_descriptor"]["auth"]["status"],
            "unverifiable"
        );
        assert_eq!(
            payload["shared_descriptor"]["readiness"]["status"],
            "unverifiable"
        );
        assert!(
            payload["operations"]["preview"]
                .as_array()
                .is_some_and(|preview| !preview.is_empty())
        );
    }

    #[test]
    fn execute_ops_offline_filters_out_risky_operations() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "ops",
            "github",
            "--risk-at-most",
            "low",
            "--offline",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "ops");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
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
    fn execute_schema_offline_resolves_friendly_operation_selector() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "schema",
            "github",
            "issues.create",
            "--offline",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "schema");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
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
    fn execute_examples_offline_resolves_friendly_operation_selector() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "examples",
            "github",
            "issues.create",
            "--offline",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "examples");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
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

    #[test]
    fn execute_suggest_without_host_requires_explicit_offline_mode() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "suggest", "--goal", "create github issue"]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "suggest");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_suggest_offline_returns_manifest_backed_recommendations() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "suggest",
            "--goal",
            "create github issue",
            "--offline",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "suggest");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_discovery_provenance(&payload, "workspace_manifest", false, "offline-artifact");
        assert!(
            payload["suggestions"]
                .as_array()
                .is_some_and(|suggestions| {
                    suggestions
                        .iter()
                        .any(|suggestion| suggestion["operation"] == "github.create_issue")
                })
        );
    }

    #[test]
    fn execute_suggest_with_host_uses_live_introspection() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            2,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "suggest",
            "--goal",
            "create github issue",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "suggest");
        assert_eq!(payload["source"], "host-admin-api");
        assert_discovery_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert!(
            payload["suggestions"]
                .as_array()
                .is_some_and(|suggestions| {
                    suggestions
                        .iter()
                        .any(|suggestion| suggestion["operation"] == "github.create_issue")
                })
        );
    }

    #[test]
    fn execute_template_without_host_requires_explicit_offline_mode() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "template", "github", "issues.create"]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "template");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_template_offline_returns_offline_artifact_template() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "template",
            "github",
            "issues.create",
            "--offline",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "template");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_template_provenance(&payload, "workspace_manifest", false, "offline-artifact");
        assert_eq!(payload["operation"]["canonical_id"], "github.create_issue");
        assert_eq!(payload["template"]["title"], "example-string");
    }

    #[test]
    fn execute_template_with_host_uses_live_introspection() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            2,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "template",
            "github",
            "issues.create",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "template");
        assert_eq!(payload["source"], "host-admin-api");
        assert_template_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert_eq!(payload["operation"]["selector"], "github.create_issue");
        assert_eq!(payload["template"]["title"], "<string:required>");
    }

    #[test]
    fn execute_validate_without_host_requires_explicit_offline_mode() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "validate",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}",
        ]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "validate");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_validate_offline_requires_input_with_template_provenance() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "validate",
            "github",
            "issues.create",
            "--offline",
        ]);

        assert_eq!(exit_code, CliExitCode::UnknownCommand.into());
        assert_eq!(payload["command"], "validate");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_eq!(payload["error"]["type"], "missing-input");
        assert_template_provenance(&payload, "workspace_manifest", false, "offline-artifact");
    }

    #[test]
    fn execute_validate_offline_returns_offline_artifact_result() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "validate",
            "github",
            "issues.create",
            "--offline",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}",
        ]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "validate");
        assert_eq!(payload["source"], "workspace-manifests");
        assert_template_provenance(&payload, "workspace_manifest", false, "offline-artifact");
        assert_eq!(payload["valid"], true);
    }

    #[test]
    fn execute_validate_with_host_requires_input_with_template_provenance() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            2,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "validate",
            "github",
            "issues.create",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::UnknownCommand.into());
        assert_eq!(payload["command"], "validate");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["error"]["type"], "missing-input");
        assert_template_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
    }

    #[test]
    fn execute_validate_with_host_uses_live_introspection() {
        let (host, server) = spawn_mock_host(
            StdBTreeMap::from([
                (
                    "POST /rpc/discover".to_owned(),
                    mock_discovery_response_json(),
                ),
                (
                    "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                    mock_introspection_response_json(),
                ),
            ]),
            2,
        );

        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "validate",
            "github",
            "issues.create",
            "--input",
            "{\"owner\":\"octocat\",\"repo\":\"hello-world\",\"title\":\"Bug report\"}",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "validate");
        assert_eq!(payload["source"], "host-admin-api");
        assert_template_provenance(
            &payload,
            "live_host_introspection",
            true,
            "live-introspection",
        );
        assert_eq!(payload["valid"], true);
    }

    // ── Intent recovery: config subcommand aliases ──────────────────────

    #[test]
    fn execute_config_validate_resolves_to_doctor() {
        let prepared = prepare_cli(&[
            "fwc".to_owned(),
            "--json".to_owned(),
            "config".to_owned(),
            "validate".to_owned(),
            "github".to_owned(),
        ])
        .expect("config alias should parse");

        match prepared.cli.command {
            Commands::Config(super::ConfigArgs {
                command: super::ConfigCommand::Doctor(super::TargetArgs { connector }),
                ..
            }) => assert_eq!(connector, "github"),
            command => panic!("expected config doctor command, got {command:?}"),
        }
    }

    #[test]
    fn execute_config_show_resolves_to_get() {
        let prepared = prepare_cli(&[
            "fwc".to_owned(),
            "--json".to_owned(),
            "config".to_owned(),
            "show".to_owned(),
            "github".to_owned(),
        ])
        .expect("config alias should parse");

        match prepared.cli.command {
            Commands::Config(super::ConfigArgs {
                command: super::ConfigCommand::Get(super::TargetArgs { connector }),
                ..
            }) => assert_eq!(connector, "github"),
            command => panic!("expected config get command, got {command:?}"),
        }
    }

    #[test]
    fn execute_config_rm_resolves_to_unset() {
        let prepared = prepare_cli(&[
            "fwc".to_owned(),
            "--json".to_owned(),
            "config".to_owned(),
            "rm".to_owned(),
            "github".to_owned(),
            "auth.token".to_owned(),
        ])
        .expect("config alias should parse");

        match prepared.cli.command {
            Commands::Config(super::ConfigArgs {
                command: super::ConfigCommand::Unset(super::ConfigUnsetArgs { connector, key }),
                ..
            }) => {
                assert_eq!(connector, "github");
                assert_eq!(key, "auth.token");
            }
            command => panic!("expected config unset command, got {command:?}"),
        }
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
            vec!["fwc", "--json", "insatll", "github"]
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
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["item-1", "item-2", "item-3"]),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"owner":"octocat","repo":"hello-world","number":1},{"owner":"octocat","repo":"hello-world","number":2},{"owner":"octocat","repo":"hello-world","number":3}]"#,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "map");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["plan"]["operation"], "github.get_issue");
        assert_eq!(payload["plan"]["input_count"], 3);
        assert_eq!(payload["plan"]["concurrency"], 5);
        assert_eq!(payload["plan"]["on_error"], "abort");
        assert_eq!(
            payload["plan"]["preview_inputs"].as_array().unwrap().len(),
            3
        );
        assert_eq!(payload["response"]["completed"], 3);
    }

    #[test]
    fn execute_map_on_error_continue() {
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["item-1"]),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"owner":"octocat","repo":"hello-world","number":1}]"#,
            "--on-error",
            "continue",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["plan"]["on_error"], "continue");
        assert_eq!(payload["response"]["completed"], 1);
    }

    #[test]
    fn execute_map_custom_concurrency() {
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["item-1", "item-2"]),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"owner":"octocat","repo":"hello-world","number":1},{"owner":"octocat","repo":"hello-world","number":2}]"#,
            "--concurrency",
            "10",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["plan"]["concurrency"], 10);
        assert_eq!(payload["response"]["completed"], 2);
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
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["item-1", "item-2", "item-3"]),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "map",
            "github.get_issue",
            "--input-template",
            r#"{"owner":"octocat","repo":"hello-world","number":{{item}}}"#,
            "--items",
            "1,2,3",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["plan"]["input_count"], 3);
        assert_eq!(payload["plan"]["preview_inputs"][0]["number"], 1);
        assert_eq!(payload["plan"]["preview_inputs"][2]["number"], 3);
        assert_eq!(payload["response"]["completed"], 3);
    }

    #[test]
    fn execute_map_preview_capped_at_three() {
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["item-1", "item-2", "item-3", "item-4", "item-5"]),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "map",
            "github.get_issue",
            "--inputs",
            r#"[{"owner":"octocat","repo":"hello-world","number":1},{"owner":"octocat","repo":"hello-world","number":2},{"owner":"octocat","repo":"hello-world","number":3},{"owner":"octocat","repo":"hello-world","number":4},{"owner":"octocat","repo":"hello-world","number":5}]"#,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["plan"]["input_count"], 5);
        assert_eq!(
            payload["plan"]["preview_inputs"].as_array().unwrap().len(),
            3
        );
        assert_eq!(payload["response"]["completed"], 5);
    }

    #[test]
    fn execute_map_batch_alias() {
        let capability_token = test_capability_token_arg();
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["item-1"]),
            )])),
            3,
        );
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "batch",
            "github.get_issue",
            "--inputs",
            r#"[{"owner":"octocat","repo":"hello-world","number":1}]"#,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "map");
        assert_eq!(payload["response"]["completed"], 1);
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

        let capability_token = test_capability_token_arg();
        let github_connector = mock_connector_summary_custom_json(
            "fcp.github:enterprise:v1",
            "GitHub Enterprise",
            1,
            "safe",
        );
        let slack_connector =
            mock_connector_summary_custom_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
        let github_search_tool = mock_tool_descriptor_json(
            "github.search_issues",
            "github.read",
            "low",
            "safe",
            "strict",
            None,
            json!({
                "type": "object",
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                },
                "required": ["owner", "repo"]
            }),
            json!({
                "type": "object",
                "properties": {
                    "issues": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": { "type": "string" }
                            }
                        }
                    }
                }
            }),
        );
        let slack_post_tool = mock_tool_descriptor_json(
            "slack.post_message",
            "slack.post_message",
            "medium",
            "risky",
            "none",
            Some("interactive"),
            json!({
                "type": "object",
                "properties": {
                    "channel": { "type": "string" },
                    "text": { "type": "string" }
                },
                "required": ["channel", "text"]
            }),
            json!({
                "type": "object",
                "properties": {
                    "ok": { "type": "boolean" }
                }
            }),
        );
        let (host, server) = spawn_mock_host_sequence(vec![
            (
                "POST /rpc/discover".to_owned(),
                mock_discovery_response_with_connectors(vec![
                    github_connector.clone(),
                    slack_connector.clone(),
                ]),
            ),
            (
                "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                mock_introspection_response_with_tools(github_connector, vec![github_search_tool]),
            ),
            (
                "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
                mock_introspection_response_with_tools(slack_connector, vec![slack_post_tool]),
            ),
            (
                "POST /rpc/preflight".to_owned(),
                mock_preflight_response_json(true),
            ),
            (
                "POST /rpc/invoke".to_owned(),
                mock_invoke_response_json(json!({
                    "issues": [
                        { "title": "Bug report" }
                    ]
                })),
            ),
            (
                "POST /rpc/preflight".to_owned(),
                mock_preflight_response_json(true),
            ),
        ]);
        let path_str = path.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "pipeline",
            "dry-run",
            &path_str,
            "--capability-token",
            &capability_token,
            "--param",
            "owner=octocat",
            "--param",
            "repo=hello-world",
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "pipeline");
        assert_eq!(payload["subcommand"], "dry-run");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["plan"]["execution_order"][0], "fetch");
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
        assert_eq!(payload["execution"]["executed_steps"], 1);
        assert_eq!(payload["execution"]["preflight_only_steps"], 1);
        assert_eq!(payload["execution"]["skipped_steps"], 0);
        assert_eq!(payload["execution"]["blocked_steps"], 0);
        assert_eq!(
            payload["execution"]["outputs"]["fetch"]["issues"][0]["title"],
            "Bug report"
        );
        let steps = payload["execution"]["steps"]
            .as_array()
            .expect("execution steps should be present");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["id"], "fetch");
        assert_eq!(steps[0]["mode"], "dry-run-read");
        assert_eq!(steps[0]["input"]["owner"], "octocat");
        assert_eq!(steps[0]["input"]["repo"], "hello-world");
        assert_eq!(
            steps[0]["response"]["result"]["issues"][0]["title"],
            "Bug report"
        );
        assert_eq!(steps[1]["id"], "notify");
        assert_eq!(steps[1]["status"], "ok");
        assert_eq!(steps[1]["mode"], "preflight");
        assert_eq!(steps[1]["input"]["channel"], "#general");
        assert_eq!(steps[1]["input"]["text"], "New issues: 1");
        assert_eq!(steps[1]["condition"]["allowed"], true);
    }

    #[test]
    fn execute_pipeline_dry_run_requires_live_host() {
        let root = std::env::temp_dir().join(format!(
            "fwc-pipeline-dry-run-no-host-{}-{}",
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
"#,
        )
        .unwrap();

        let path_str = path.display().to_string();
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "pipeline", "dry-run", &path_str]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "pipeline");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
        assert_eq!(payload["details"]["subcommand"], "dry-run");
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

        let capability_token = test_capability_token_arg();
        let github_connector = mock_connector_summary_custom_json(
            "fcp.github:enterprise:v1",
            "GitHub Enterprise",
            1,
            "safe",
        );
        let github_search_tool = mock_tool_descriptor_json(
            "github.search_issues",
            "github.read",
            "low",
            "safe",
            "strict",
            None,
            json!({
                "type": "object",
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                },
                "required": ["owner", "repo"]
            }),
            json!({
                "type": "object",
                "properties": {
                    "issues": {
                        "type": "array",
                        "items": { "type": "object" }
                    }
                }
            }),
        );
        let (host, server) = spawn_mock_host_sequence(vec![
            (
                "POST /rpc/discover".to_owned(),
                mock_discovery_response_with_connectors(vec![github_connector.clone()]),
            ),
            (
                "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                mock_introspection_response_with_tools(github_connector, vec![github_search_tool]),
            ),
        ]);
        let path_str = path.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "pipeline",
            "dry-run",
            &path_str,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["command"], "pipeline");
        assert_eq!(payload["error"]["type"], "operation-not-found");
        assert_eq!(payload["error"]["selector"], "not_a_real_operation");
        assert!(
            payload["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("github"))
        );
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

    #[test]
    fn execute_recipe_list_reports_builtin_recipes() {
        let (exit_code, payload) = execute_json(&["fwc", "--json", "recipe", "list"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "recipe");
        assert_eq!(payload["subcommand"], "list");
        assert!(
            payload["recipe_count"].as_u64().unwrap() >= 15,
            "expected bundled recipe catalog to have at least 15 entries"
        );
        assert!(payload["categories"].is_object());
        assert!(payload["recipes"].as_array().unwrap().iter().any(|recipe| {
            recipe["slug"] == "github-pr-review-notify" && recipe["valid"] == Value::Bool(true)
        }));
    }

    #[test]
    fn execute_recipe_show_returns_definition_and_estimate() {
        let (exit_code, payload) =
            execute_json(&["fwc", "--json", "recipe", "show", "github-pr-review-notify"]);

        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["command"], "recipe");
        assert_eq!(payload["subcommand"], "show");
        assert_eq!(payload["recipe"]["slug"], "github-pr-review-notify");
        assert_eq!(
            payload["recipe"]["export_path"],
            ".fwc/pipelines/github-pr-review-notify.toml"
        );
        assert_eq!(
            payload["definition"]["pipeline"]["name"],
            "github-pr-review-notify"
        );
        assert_eq!(payload["estimate"]["step_count"], 2);
        assert_eq!(payload["estimate"]["risk_assessment"]["level"], "medium");
    }

    #[test]
    fn execute_recipe_export_returns_raw_toml() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "recipe",
            "export",
            "github-pr-review-notify",
        ]);

        let export = payload
            .as_str()
            .expect("recipe export should serialize as a JSON string");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert!(export.starts_with("[pipeline]"));
        assert!(export.contains("name = \"github-pr-review-notify\""));
        assert!(export.contains("operation = \"github.get_pull_request\""));
    }

    #[test]
    fn execute_recipe_dry_run_uses_bundled_defaults() {
        let capability_token = test_capability_token_arg();
        let github_connector = mock_connector_summary_custom_json(
            "fcp.github:enterprise:v1",
            "GitHub Enterprise",
            1,
            "safe",
        );
        let slack_connector =
            mock_connector_summary_custom_json("fcp.slack:team:v1", "Slack Team", 1, "risky");
        let github_get_pr_tool = mock_tool_descriptor_json(
            "github.get_pull_request",
            "github.read",
            "low",
            "safe",
            "strict",
            None,
            json!({
                "type": "object",
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" },
                    "pull_number": { "type": "integer" }
                },
                "required": ["owner", "repo", "pull_number"]
            }),
            json!({
                "type": "object",
                "properties": {
                    "pull_request": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }
                }
            }),
        );
        let slack_post_tool = mock_tool_descriptor_json(
            "slack.post_message",
            "slack.post_message",
            "medium",
            "risky",
            "none",
            Some("interactive"),
            json!({
                "type": "object",
                "properties": {
                    "channel": { "type": "string" },
                    "text": { "type": "string" }
                },
                "required": ["channel", "text"]
            }),
            json!({
                "type": "object",
                "properties": {
                    "ok": { "type": "boolean" }
                }
            }),
        );
        let (host, server) = spawn_mock_host_sequence(vec![
            (
                "POST /rpc/discover".to_owned(),
                mock_discovery_response_with_connectors(vec![
                    github_connector.clone(),
                    slack_connector.clone(),
                ]),
            ),
            (
                "GET /rpc/introspect/fcp.github:enterprise:v1".to_owned(),
                mock_introspection_response_with_tools(github_connector, vec![github_get_pr_tool]),
            ),
            (
                "GET /rpc/introspect/fcp.slack:team:v1".to_owned(),
                mock_introspection_response_with_tools(slack_connector, vec![slack_post_tool]),
            ),
            (
                "POST /rpc/preflight".to_owned(),
                mock_preflight_response_json(true),
            ),
            (
                "POST /rpc/invoke".to_owned(),
                mock_invoke_response_json(json!({
                    "pull_request": {
                        "title": "Review the concurrency fix"
                    }
                })),
            ),
            (
                "POST /rpc/preflight".to_owned(),
                mock_preflight_response_json(true),
            ),
        ]);
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "recipe",
            "dry-run",
            "github-pr-review-notify",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "recipe");
        assert_eq!(payload["subcommand"], "dry-run");
        assert_eq!(payload["source"], "host-admin-api");
        assert_eq!(payload["recipe"], "github-pr-review-notify");
        assert_eq!(
            payload["estimate"]["estimated_api_calls"]["summary"],
            "~2 API calls"
        );
        assert_eq!(payload["execution"]["executed_steps"], 1);
        assert_eq!(payload["execution"]["preflight_only_steps"], 1);
        assert_eq!(
            payload["execution"]["outputs"]["fetch"]["pull_request"]["title"],
            "Review the concurrency fix"
        );
        let steps = payload["execution"]["steps"]
            .as_array()
            .expect("execution steps should be present");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["id"], "fetch");
        assert_eq!(steps[0]["mode"], "dry-run-read");
        assert_eq!(steps[0]["input"]["owner"], "octocat");
        assert_eq!(steps[0]["input"]["repo"], "hello-world");
        assert_eq!(steps[0]["input"]["pull_number"], 1);
        assert_eq!(
            steps[0]["response"]["result"]["pull_request"]["title"],
            "Review the concurrency fix"
        );
        assert_eq!(steps[1]["id"], "notify");
        assert_eq!(steps[1]["mode"], "preflight");
        assert_eq!(steps[1]["input"]["channel"], "C01234567");
        assert_eq!(
            steps[1]["input"]["text"],
            "PR review requested for octocat/hello-world#1: Review the concurrency fix"
        );
    }

    #[test]
    fn execute_recipe_dry_run_requires_live_host() {
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "recipe",
            "dry-run",
            "github-pr-review-notify",
        ]);

        assert_eq!(exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "recipe");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
        assert_eq!(payload["details"]["subcommand"], "dry-run");
        assert_eq!(payload["details"]["recipe"], "github-pr-review-notify");
    }

    #[test]
    fn execute_all_builtin_recipes_estimate_successfully() {
        for slug in super::pipe::builtin_recipe_slugs() {
            let (exit_code, payload) = execute_json(&["fwc", "--json", "recipe", "estimate", slug]);

            assert_eq!(
                exit_code,
                CliExitCode::Success.into(),
                "recipe estimate should succeed for {slug}"
            );
            assert_eq!(
                payload["command"], "recipe",
                "unexpected command for {slug}"
            );
            assert_eq!(
                payload["subcommand"], "estimate",
                "unexpected subcommand for {slug}"
            );
            assert_eq!(payload["recipe"], slug, "unexpected recipe slug for {slug}");
            assert_eq!(
                payload["estimate"]["step_count"].as_u64().unwrap(),
                2,
                "all bundled recipes currently have two steps: {slug}"
            );
            assert!(
                payload.get("plan").is_none(),
                "estimate should omit plan for {slug}"
            );
        }
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
        let capability_token = test_capability_token_arg();
        let file = batch_test_file(
            "valid.jsonl",
            r#"{"id":"s1","connector":"github","operation":"get_issue","input":{"owner":"octocat","repo":"hello-world","number":1}}
{"id":"s2","connector":"github","operation":"create_issue","input":{"owner":"octocat","repo":"hello-world","title":"Follow-up"},"depends_on":["s1"]}"#,
        );
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["s1", "s2"]),
            )])),
            3,
        );
        let file_path = file.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "batch-file",
            &file_path,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "batch-file");
        assert_eq!(payload["plan"]["total_operations"], 2);
        assert_eq!(payload["plan"]["waves"].as_array().unwrap().len(), 2);
        assert_eq!(payload["plan"]["connectors"].as_array().unwrap().len(), 1);
        assert_eq!(payload["response"]["completed"], 2);
    }

    #[test]
    fn execute_batch_file_all_independent_single_wave() {
        let capability_token = test_capability_token_arg();
        let file = batch_test_file(
            "independent.jsonl",
            r#"{"id":"a","connector":"github","operation":"get_issue","input":{"owner":"octocat","repo":"hello-world","number":1}}
{"id":"b","connector":"github","operation":"get_issue","input":{"owner":"octocat","repo":"hello-world","number":2}}
{"id":"c","connector":"github","operation":"get_issue","input":{"owner":"octocat","repo":"hello-world","number":3}}"#,
        );
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["a", "b", "c"]),
            )])),
            3,
        );
        let file_path = file.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "batch-file",
            &file_path,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["plan"]["waves"].as_array().unwrap().len(), 1);
        assert_eq!(payload["plan"]["total_operations"], 3);
        assert_eq!(payload["response"]["completed"], 3);
    }

    #[test]
    fn execute_batch_file_custom_concurrency() {
        let capability_token = test_capability_token_arg();
        let file = batch_test_file(
            "concurrency.jsonl",
            r#"{"id":"a","connector":"github","operation":"get_issue","input":{"owner":"octocat","repo":"hello-world","number":1}}"#,
        );
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["a"]),
            )])),
            3,
        );
        let file_path = file.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "batch-file",
            &file_path,
            "--concurrency",
            "10",
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["plan"]["concurrency"], 10);
        assert_eq!(payload["response"]["completed"], 1);
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
        let capability_token = test_capability_token_arg();
        let file = batch_test_file(
            "alias.jsonl",
            r#"{"id":"a","connector":"github","operation":"get_issue","input":{"owner":"octocat","repo":"hello-world","number":1}}"#,
        );
        let (host, server) = spawn_mock_host(
            mock_github_host_routes(StdBTreeMap::from([(
                "POST /rpc/batch".to_owned(),
                mock_batch_response_json(&["a"]),
            )])),
            3,
        );
        let file_path = file.display().to_string();
        let (exit_code, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &host,
            "batch-ops",
            &file_path,
            "--capability-token",
            &capability_token,
        ]);

        server.join().expect("mock host thread should complete");
        assert_eq!(exit_code, CliExitCode::Success.into());
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "batch-file");
        assert_eq!(payload["response"]["completed"], 1);
    }

    #[test]
    fn prepare_cli_parses_serve_mcp_command() {
        let capability_token = test_capability_token_arg();
        let prepared = prepare_cli(&[
            "fwc".to_owned(),
            "serve-mcp".to_owned(),
            "github".to_owned(),
            "--zone".to_owned(),
            "z:work".to_owned(),
            "--principal".to_owned(),
            "agent:blackoak".to_owned(),
            "--capability-token".to_owned(),
            capability_token,
        ])
        .unwrap();

        match prepared.cli.command {
            Commands::ServeMcp(args) => {
                assert_eq!(args.connector.as_deref(), Some("github"));
                assert_eq!(args.zone.as_deref(), Some("z:work"));
                assert_eq!(args.principal.as_deref(), Some("agent:blackoak"));
                assert!(args.auth.capability_token.is_some());
            }
            command => panic!("expected serve-mcp command, got {command:?}"),
        }
    }

    #[test]
    fn prepare_cli_parses_session_start_command() {
        let prepared = prepare_cli(&[
            "fwc".to_owned(),
            "session".to_owned(),
            "start".to_owned(),
            "--agent".to_owned(),
            "BronzeValley".to_owned(),
            "--goal".to_owned(),
            "triage active beads".to_owned(),
            "--zone".to_owned(),
            "z:work".to_owned(),
            "--context".to_owned(),
            "bead=\"flywheel_connectors-qnchs.13.1\"".to_owned(),
            "--context".to_owned(),
            "attempt=1".to_owned(),
        ])
        .unwrap();

        match prepared.cli.command {
            Commands::Session(args) => match args.command {
                super::SessionCommand::Start(args) => {
                    assert_eq!(args.agent, "BronzeValley");
                    assert_eq!(args.goal, "triage active beads");
                    assert_eq!(args.zone.as_deref(), Some("z:work"));
                    assert_eq!(args.context.len(), 2);
                    assert_eq!(args.context[0], "bead=\"flywheel_connectors-qnchs.13.1\"");
                    assert_eq!(args.context[1], "attempt=1");
                }
                command => panic!("expected session start command, got {command:?}"),
            },
            command => panic!("expected session command, got {command:?}"),
        }
    }

    #[test]
    fn prepare_cli_parses_agent_send_command() {
        let prepared = prepare_cli(&[
            "fwc".to_owned(),
            "agent".to_owned(),
            "send".to_owned(),
            "--from".to_owned(),
            "BronzeValley".to_owned(),
            "--to".to_owned(),
            "GoldenWolf".to_owned(),
            "--kind".to_owned(),
            "info".to_owned(),
            "--payload".to_owned(),
            "{\"bead\":\"flywheel_connectors-qnchs.13.3\"}".to_owned(),
        ])
        .unwrap();

        match prepared.cli.command {
            Commands::Agent(args) => match args.command {
                super::AgentCommand::Send(args) => {
                    assert_eq!(args.from, "BronzeValley");
                    assert_eq!(args.to, "GoldenWolf");
                    assert_eq!(args.kind, super::AgentMessageKindArg::Info);
                    assert_eq!(
                        args.payload,
                        "{\"bead\":\"flywheel_connectors-qnchs.13.3\"}"
                    );
                }
                command => panic!("expected agent send command, got {command:?}"),
            },
            command => panic!("expected agent command, got {command:?}"),
        }
    }

    #[test]
    fn execute_serve_mcp_requires_live_host() {
        let outcome = execute(&[
            "fwc".to_owned(),
            "--json".to_owned(),
            "serve-mcp".to_owned(),
            "github".to_owned(),
        ])
        .expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Transport.into());
        assert_eq!(payload["command"], "serve-mcp");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
    }

    #[test]
    fn execute_serve_mcp_requires_real_capability_token() {
        let outcome = execute(&[
            "fwc".to_owned(),
            "--json".to_owned(),
            "--host".to_owned(),
            "http://127.0.0.1:8787".to_owned(),
            "serve-mcp".to_owned(),
            "github".to_owned(),
        ])
        .expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["command"], "serve-mcp");
        assert_eq!(payload["error"]["type"], "missing-capability-token");
    }

    #[test]
    fn execute_session_start_show_end_resume_flow() {
        let session_dir = TempDir::new().expect("session tempdir should exist");
        let lock_dir = TempDir::new().expect("lock tempdir should exist");
        let _session_guard = super::install_test_session_dir(session_dir.path().join("sessions"));
        let _lock_guard = super::install_test_lock_dir(lock_dir.path().join("locks"));

        let acquire = super::cli_lock_store()
            .acquire(
                "github.issues",
                "BronzeValley",
                30,
                Some("triage lane".to_owned()),
            )
            .expect("lock acquisition should succeed");
        match acquire {
            super::op_lock::AcquireResult::Acquired { lock } => {
                assert_eq!(lock.resource, "github.issues");
            }
            other @ super::op_lock::AcquireResult::Conflict { .. } => {
                panic!("expected acquired lock, got {other:?}");
            }
        }

        let (start_exit, start_payload) = execute_json(&[
            "fwc",
            "--json",
            "session",
            "start",
            "--agent",
            "BronzeValley",
            "--goal",
            "triage active beads",
            "--zone",
            "z:work",
            "--context",
            "bead=\"flywheel_connectors-qnchs.13.1\"",
            "--context",
            "attempt=1",
        ]);

        assert_eq!(start_exit, CliExitCode::Success.into());
        assert_eq!(start_payload["command"], "session");
        assert_eq!(start_payload["subcommand"], "start");
        assert!(start_payload["paused_previous_session"].is_null());
        assert_eq!(start_payload["session"]["agent_name"], "BronzeValley");
        assert_eq!(start_payload["session"]["goal"], "triage active beads");
        assert_eq!(start_payload["session"]["zone"], "z:work");
        assert_eq!(
            start_payload["session"]["context"]["bead"],
            "flywheel_connectors-qnchs.13.1"
        );
        assert_eq!(start_payload["session"]["context"]["attempt"], 1);
        assert_eq!(start_payload["session"]["active_lock_count"], 1);
        assert_eq!(
            start_payload["session"]["active_locks"][0]["resource"],
            "github.issues"
        );
        assert_eq!(
            start_payload["session"]["active_locks"][0]["reason"],
            "triage lane"
        );
        let session_id = start_payload["session"]["id"]
            .as_str()
            .expect("session id should be present")
            .to_owned();

        let (show_exit, show_payload) = execute_json(&["fwc", "--json", "session", "show"]);
        assert_eq!(show_exit, CliExitCode::Success.into());
        assert_eq!(show_payload["subcommand"], "show");
        assert_eq!(show_payload["session"]["id"], session_id);
        assert_eq!(show_payload["session"]["status"], "active");
        assert_eq!(show_payload["session"]["active_lock_count"], 1);

        let (end_exit, end_payload) = execute_json(&["fwc", "--json", "session", "end"]);
        assert_eq!(end_exit, CliExitCode::Success.into());
        assert_eq!(end_payload["subcommand"], "end");
        assert_eq!(end_payload["session"]["id"], session_id);
        assert_eq!(end_payload["session"]["status"], "ended");
        assert!(end_payload["session"]["ended_at"].is_string());

        let (resume_exit, resume_payload) = execute_json(&["fwc", "--json", "session", "resume"]);
        assert_eq!(resume_exit, CliExitCode::Success.into());
        assert_eq!(resume_payload["subcommand"], "resume");
        assert_eq!(resume_payload["session"]["id"], session_id);
        assert_eq!(resume_payload["session"]["status"], "active");
        assert!(resume_payload["session"]["ended_at"].is_null());
        assert!(resume_payload["paused_previous_session"].is_null());
    }

    #[test]
    fn execute_session_start_pauses_previous_active_session() {
        let session_dir = TempDir::new().expect("session tempdir should exist");
        let _session_guard = super::install_test_session_dir(session_dir.path().join("sessions"));

        let (first_exit, first_payload) = execute_json(&[
            "fwc",
            "--json",
            "session",
            "start",
            "--agent",
            "BronzeValley",
            "--goal",
            "first sweep",
        ]);
        assert_eq!(first_exit, CliExitCode::Success.into());
        let first_id = first_payload["session"]["id"]
            .as_str()
            .expect("first session id should exist")
            .to_owned();

        let (second_exit, second_payload) = execute_json(&[
            "fwc",
            "--json",
            "session",
            "start",
            "--agent",
            "BronzeValley",
            "--goal",
            "second sweep",
        ]);
        assert_eq!(second_exit, CliExitCode::Success.into());
        assert_eq!(
            second_payload["paused_previous_session"]["id"],
            Value::String(first_id.clone())
        );

        let previous = super::cli_session_store()
            .load_resolved(&first_id)
            .expect("session load should succeed")
            .expect("first session should still exist");
        assert_eq!(previous.status, super::session::SessionStatus::Paused);

        let active = super::cli_session_store()
            .active_session()
            .expect("active session lookup should succeed")
            .expect("second session should be active");
        assert_eq!(active.goal, "second sweep");
        assert_eq!(active.status, super::session::SessionStatus::Active);
    }

    #[test]
    fn execute_agent_list_announce_reserve_send_and_inbox_flow() {
        let coord_dir = TempDir::new().expect("coordination tempdir should exist");
        let _coord_guard =
            super::install_test_agent_coord_path(coord_dir.path().join("coordination.json"));

        let (empty_exit, empty_payload) = execute_json(&["fwc", "--json", "agent", "list"]);
        assert_eq!(empty_exit, CliExitCode::Success.into());
        assert_eq!(empty_payload["summary"]["announcement_count"], 0);
        assert_eq!(empty_payload["summary"]["reservation_count"], 0);

        let (announce_exit, announce_payload) = execute_json(&[
            "fwc",
            "--json",
            "agent",
            "announce",
            "--agent",
            "BronzeValley",
            "--connector",
            "github",
            "--purpose",
            "triage active beads",
            "--operation",
            "issues.create",
            "--duration",
            "300",
        ]);
        assert_eq!(announce_exit, CliExitCode::Success.into());
        assert_eq!(announce_payload["command"], "agent");
        assert_eq!(announce_payload["subcommand"], "announce");
        assert_eq!(announce_payload["announcement"]["agent"], "BronzeValley");
        assert_eq!(announce_payload["announcement"]["connector"], "github");
        assert_eq!(
            announce_payload["announcement"]["operation"],
            "issues.create"
        );

        let (reserve_exit, reserve_payload) = execute_json(&[
            "fwc",
            "--json",
            "agent",
            "reserve",
            "--agent",
            "BronzeValley",
            "--connector",
            "github",
            "--resource",
            "repo:octocat/hello-world",
            "--ttl",
            "120",
            "--exclusive",
        ]);
        assert_eq!(reserve_exit, CliExitCode::Success.into());
        assert_eq!(reserve_payload["subcommand"], "reserve");
        assert_eq!(
            reserve_payload["reservation"]["resource"],
            "repo:octocat/hello-world"
        );
        assert_eq!(reserve_payload["reservation"]["exclusive"], true);

        let (send_exit, send_payload) = execute_json(&[
            "fwc",
            "--json",
            "agent",
            "send",
            "--from",
            "BronzeValley",
            "--to",
            "GoldenWolf",
            "--kind",
            "info",
            "--payload",
            "{\"status\":\"claimed\"}",
        ]);
        assert_eq!(send_exit, CliExitCode::Success.into());
        assert_eq!(send_payload["subcommand"], "send");
        assert_eq!(send_payload["recipient_unread_count"], 1);

        let (peek_exit, peek_payload) =
            execute_json(&["fwc", "--json", "agent", "inbox", "--agent", "GoldenWolf"]);
        assert_eq!(peek_exit, CliExitCode::Success.into());
        assert_eq!(peek_payload["message_count"], 1);
        assert_eq!(peek_payload["messages"][0]["from"], "BronzeValley");
        assert_eq!(peek_payload["messages"][0]["kind"], "info");
        assert_eq!(peek_payload["messages"][0]["payload"]["status"], "claimed");

        let (drain_exit, drain_payload) = execute_json(&[
            "fwc",
            "--json",
            "agent",
            "inbox",
            "--agent",
            "GoldenWolf",
            "--drain",
        ]);
        assert_eq!(drain_exit, CliExitCode::Success.into());
        assert_eq!(drain_payload["message_count"], 1);
        assert_eq!(drain_payload["drained"], true);

        let (final_list_exit, final_list_payload) =
            execute_json(&["fwc", "--json", "agent", "list"]);
        assert_eq!(final_list_exit, CliExitCode::Success.into());
        assert_eq!(final_list_payload["summary"]["announcement_count"], 1);
        assert_eq!(final_list_payload["summary"]["reservation_count"], 1);
    }

    #[test]
    fn append_history_entry_records_active_session_metadata_and_increments_operations() {
        let session_dir = TempDir::new().expect("session tempdir should exist");
        let history_dir = TempDir::new().expect("history tempdir should exist");
        let _session_guard = super::install_test_session_dir(session_dir.path().join("sessions"));
        let _history_guard =
            super::install_test_history_path(history_dir.path().join("history.jsonl"));

        let session = super::session::Session::new(
            "BronzeValley",
            "triage active beads",
            Some("z:work".to_owned()),
        );
        let session_id = session.id.to_string();
        super::cli_session_store()
            .save(&session)
            .expect("session save should succeed");

        super::append_history_entry(
            super::history::OpStatus::Success,
            "fcp.github",
            "github.create_issue",
            Some("z:work"),
            &json!({"owner":"octocat","repo":"hello-world","title":"bead fix"}),
            Some(&json!({"ok":true})),
            None,
            Some("idemp-1"),
            14,
        )
        .expect("history append should succeed");
        super::append_history_entry(
            super::history::OpStatus::Denied,
            "fcp.github",
            "github.delete_issue",
            Some("z:work"),
            &json!({"owner":"octocat","repo":"hello-world","number":42}),
            Some(&json!({"allowed":false})),
            Some("policy denied".to_owned()),
            None,
            0,
        )
        .expect("history append should succeed");

        let entries = super::cli_history_store()
            .expect("history store should open")
            .query(&super::history::HistoryFilter::new())
            .expect("history query should succeed");
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .all(|entry| entry.agent_session.as_deref() == Some(session_id.as_str()))
        );

        let updated_session = super::cli_session_store()
            .load_resolved(&session_id)
            .expect("session load should succeed")
            .expect("session should still exist");
        assert_eq!(updated_session.operations_completed, 2);
        assert_eq!(
            updated_session.status,
            super::session::SessionStatus::Active
        );
    }

    #[test]
    fn execute_serve_mcp_rejects_unprovable_live_zone_filter() {
        let capability_token = test_capability_token_arg();
        let outcome = execute(&[
            "fwc".to_owned(),
            "--json".to_owned(),
            "--host".to_owned(),
            "http://127.0.0.1:8787".to_owned(),
            "serve-mcp".to_owned(),
            "github".to_owned(),
            "--zone".to_owned(),
            "z:work".to_owned(),
            "--capability-token".to_owned(),
            capability_token,
        ])
        .expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::Validation.into());
        assert_eq!(payload["command"], "serve-mcp");
        assert_eq!(payload["error"]["type"], "unsupported-live-zone-filter");
    }

    #[test]
    fn host_mcp_tool_definitions_use_live_tool_names_and_selectors() {
        let response: HostDiscoveryResponse =
            serde_json::from_value(mock_discovery_response_json())
                .expect("mock discovery response should deserialize");
        let catalog = HostConnectorCatalog::from_response(&response);
        let connector = catalog
            .connectors
            .first()
            .expect("mock catalog should contain a connector");
        let introspection: HostIntrospectionResponse =
            serde_json::from_value(mock_introspection_response_json())
                .expect("mock introspection response should deserialize");

        let tools = host_mcp_tool_definitions(connector, &introspection);

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "github.create_issue");
        assert_eq!(tools[0].connector_id, "github");
        assert_eq!(tools[0].operation_id, "github.create_issue");
    }

    #[test]
    fn host_discovered_connector_keeps_unknown_metadata_unknown() {
        let response: HostDiscoveryResponse =
            serde_json::from_value(mock_discovery_response_json())
                .expect("mock discovery response should deserialize");
        let catalog = HostConnectorCatalog::from_response(&response);
        let connector = catalog
            .connectors
            .first()
            .expect("mock catalog should contain a connector");
        let mut introspection: HostIntrospectionResponse =
            serde_json::from_value(mock_introspection_response_json())
                .expect("mock introspection response should deserialize");
        introspection.archetype = fcp_host::ConnectorArchetype::Unknown;
        introspection.rate_limits = None;

        let discovered = host_discovered_connector(connector, &introspection);

        assert!(!discovered.detail.summary.archetypes.is_known());
        assert!(!discovered.detail.rate_limits.is_known());
        assert!(
            discovered
                .operations
                .iter()
                .all(|operation| operation.rate_limits.is_none())
        );
    }

    #[test]
    fn host_discovered_connector_preserves_declared_rate_limits() {
        let response: HostDiscoveryResponse =
            serde_json::from_value(mock_discovery_response_json())
                .expect("mock discovery response should deserialize");
        let catalog = HostConnectorCatalog::from_response(&response);
        let connector = catalog
            .connectors
            .first()
            .expect("mock catalog should contain a connector");
        let mut introspection: HostIntrospectionResponse =
            serde_json::from_value(mock_introspection_response_json())
                .expect("mock introspection response should deserialize");
        introspection.rate_limits = Some(fcp_core::RateLimitDeclarations {
            limits: vec![fcp_core::RateLimitPool {
                id: "core".to_owned(),
                description: "GitHub primary API limit".to_owned(),
                config: fcp_core::RateLimitConfig {
                    requests: 5_000,
                    window: std::time::Duration::from_secs(3_600),
                    burst: None,
                    unit: fcp_core::RateLimitUnit::Requests,
                },
                enforcement: fcp_core::RateLimitEnforcement::Hard,
                scope: fcp_core::RateLimitScope::Instance,
            }],
            tool_pool_map: std::collections::HashMap::from([(
                "github.create_issue".to_owned(),
                vec!["core".to_owned()],
            )]),
        });

        let discovered = host_discovered_connector(connector, &introspection);
        let connector_rate_limits = discovered
            .detail
            .rate_limits
            .as_known()
            .expect("connector rate limits should stay available");
        let create_issue = discovered
            .operations
            .iter()
            .find(|operation| operation.actual_id == "github.create_issue")
            .expect("create_issue operation should exist");
        let operation_rate_limits = create_issue
            .rate_limits
            .as_ref()
            .expect("operation rate limits should stay available");

        assert_eq!(connector_rate_limits.len(), 1);
        assert_eq!(connector_rate_limits[0].scope, "core");
        assert_eq!(connector_rate_limits[0].requests, 5_000);
        assert_eq!(connector_rate_limits[0].window, "1h");
        assert_eq!(operation_rate_limits.len(), 1);
        assert_eq!(operation_rate_limits[0].scope, "core");
    }

    #[test]
    fn mcp_tool_invoke_args_prefers_explicit_zone_over_host_default() {
        let tool = serve_mcp::McpToolDefinition::new(
            "github.create_issue",
            "Create an issue",
            json!({"type": "object"}),
            "github",
            "github.create_issue",
        );
        let host = ResolvedHostConfig {
            endpoint: "http://127.0.0.1:8787".to_owned(),
            default_zone: Some("z:work".to_owned()),
        };

        let args = mcp_tool_invoke_args(
            &tool,
            &json!({"title": "hello"}),
            Some(&host),
            Some("agent:blackoak"),
            Some("z:community"),
            &LiveAuthArgs::default(),
        );

        assert_eq!(args.zone.as_deref(), Some("z:community"));
        assert_eq!(args.principal.as_deref(), Some("agent:blackoak"));
    }
}
