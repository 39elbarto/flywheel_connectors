#![deny(unsafe_code)]

#[allow(dead_code)] // Audit types used by later CLI commands.
mod audit;
mod catalog;
#[allow(dead_code)] // Discovery types wired into host-backed commands in later beads.
mod identifier;
mod intent;
#[allow(dead_code)] // Contract types wired into host-backed commands in later beads.
mod readiness;
mod render;
mod workflow;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::Serialize;
use serde_json::{Value, json};

use crate::render::{OutputFormat, render, token_stats};

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
  fwc ops github
  fwc schema github issues.create
  fwc config schema github
  fwc simulate github issues.create --file payload.json
  fwc invoke github issues.create --file payload.json
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

    /// Optional operation name. Omit to ask for connector-level config schema.
    operation: Option<String>,
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

fn main() -> ExitCode {
    let raw_args = std::env::args().collect::<Vec<_>>();
    match execute(&raw_args) {
        Ok(outcome) => {
            print!("{}", outcome.text);
            outcome.exit_code
        }
        Err(error) => {
            eprintln!("fwc: {error:#}");
            ExitCode::from(CliExitCode::Internal as u8)
        }
    }
}

fn execute(raw_args: &[String]) -> Result<ExecutionOutcome> {
    let fallback_format = infer_output_format(raw_args);

    match prepare_cli(raw_args) {
        Ok(prepared) => {
            let mut dispatch = dispatch(&prepared.cli)?;
            annotate_with_corrections(
                &mut dispatch.payload,
                &prepared.received_args,
                &prepared.normalized_args,
                &prepared.corrections,
            );

            if prepared.cli.token_stats {
                let stats = token_stats(&dispatch.payload);
                dispatch.payload["_token_stats"] = serde_json::to_value(&stats)?;
            }

            Ok(ExecutionOutcome {
                text: render(dispatch.payload, prepared.format)?,
                exit_code: dispatch.exit_code,
            })
        }
        Err(PrepareCliError::Clap(error)) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => Ok(ExecutionOutcome {
                text: error.to_string(),
                exit_code: ExitCode::SUCCESS,
            }),
            _ => {
                let dispatch = parse_failure_dispatch(raw_args, &error);
                Ok(ExecutionOutcome {
                    text: render(dispatch.payload, fallback_format)?,
                    exit_code: dispatch.exit_code,
                })
            }
        },
        Err(PrepareCliError::Structured(dispatch)) => Ok(ExecutionOutcome {
            text: render(dispatch.payload, fallback_format)?,
            exit_code: dispatch.exit_code,
        }),
    }
}

fn dispatch(cli: &Cli) -> Result<DispatchOutcome> {
    let outcome = match &cli.command {
        Commands::Guide(args) => {
            let mut payload = catalog::guide_payload(args.command.as_deref());
            let exit_code = if payload["status"] == "unknown-command" {
                enrich_unknown_guide_command(&mut payload, args.command.as_deref());
                CliExitCode::UnknownCommand.into()
            } else {
                ExitCode::SUCCESS
            };
            DispatchOutcome { payload, exit_code }
        }
        Commands::Task(args) => task_dispatch(args)?,
        Commands::Plan(args) => intent_plan_dispatch(&args.request(intent::IntentMode::Plan))?,
        Commands::Explain(args) => {
            intent_explain_dispatch(&args.request(intent::IntentMode::Explain))?
        }
        Commands::Do(args) => intent_do_dispatch(args)?,
        Commands::List(args) => planned("list", args)?,
        Commands::Search(args) => planned("search", args)?,
        Commands::Show(args) => planned("show", args)?,
        Commands::Ops(args) => planned("ops", args)?,
        Commands::Schema(args) => planned("schema", args)?,
        Commands::Examples(args) => planned("examples", args)?,
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
    };

    Ok(outcome)
}

fn planned<T>(command: &str, args: &T) -> Result<DispatchOutcome>
where
    T: Serialize,
{
    Ok(DispatchOutcome {
        payload: catalog::planned_payload(command, &serde_json::to_value(args)?),
        exit_code: ExitCode::SUCCESS,
    })
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
            exit_code: CliExitCode::Validation.into(),
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
        exit_code: ExitCode::SUCCESS,
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
            exit_code: CliExitCode::Validation.into(),
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
        exit_code: ExitCode::SUCCESS,
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
            exit_code: CliExitCode::Validation.into(),
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
        exit_code: ExitCode::SUCCESS,
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
        let primitive_succeeded = primitive.exit_code == ExitCode::SUCCESS;
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
    exit_code: ExitCode,
}

struct ExecutionOutcome {
    text: String,
    exit_code: ExitCode,
}

struct PreparedCli {
    cli: Cli,
    format: OutputFormat,
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
#[derive(Clone, Copy)]
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
            Ok(PreparedCli {
                cli,
                format,
                received_args: received_args.to_vec(),
                normalized_args: normalized.args,
                corrections: normalized.corrections,
            })
        }
        Err(error) => Err(PrepareCliError::Clap(error)),
    }
}

fn normalize_args(
    received_args: &[String],
) -> std::result::Result<NormalizedArgs, DispatchOutcome> {
    let mut args = received_args.to_vec();
    let mut corrections = Vec::new();

    let Some(command_index) = first_command_index(&args) else {
        return Ok(NormalizedArgs { args, corrections });
    };

    if matches!(
        args.get(command_index).map(String::as_str),
        Some("connector" | "connectors")
    ) {
        if let Some(next) = args.get(command_index + 1) {
            corrections.push(InputCorrection {
                from: format!("{} {}", args[command_index], next),
                to: next.clone(),
                rationale: "Dropped the redundant connector namespace prefix because `fwc` is already connector-scoped.",
            });
            args.remove(command_index);
        }
    }

    let Some(command_index) = first_command_index(&args) else {
        return Ok(NormalizedArgs { args, corrections });
    };

    if matches!(
        args.get(command_index).map(String::as_str),
        Some("op" | "operation" | "operations")
    ) && args
        .get(command_index + 1)
        .is_some_and(|segment| segment == "show")
    {
        return Err(ambiguous_operation_show_dispatch(&args));
    }

    if let Some(canonical) = canonical_command_alias(&args[command_index]) {
        if canonical != args[command_index] {
            corrections.push(InputCorrection {
                from: args[command_index].clone(),
                to: canonical.to_owned(),
                rationale: "Canonicalized a safe discovery-style alias so downstream payloads stay consistent.",
            });
            canonical.clone_into(&mut args[command_index]);
        }
    }

    let Some(command_index) = first_command_index(&args) else {
        return Ok(NormalizedArgs { args, corrections });
    };

    if args
        .get(command_index)
        .is_some_and(|segment| segment == "task")
        && args.get(command_index + 1).is_some_and(|segment| {
            !segment.starts_with('-') && !workflow::task_subcommands().contains(&segment.as_str())
        })
    {
        let raw_intent = args[command_index + 1].clone();
        corrections.push(InputCorrection {
            from: intent::shell_join(&["task".to_owned(), raw_intent.clone()]),
            to: intent::shell_join(&["task".to_owned(), "create".to_owned(), raw_intent]),
            rationale: "Defaulted `fwc task <intent>` to `fwc task create <intent>` because intent-first workflow creation is the canonical capsule entrypoint.",
        });
        args.insert(command_index + 1, "create".to_owned());
    }

    Ok(NormalizedArgs { args, corrections })
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
        _ => OutputFormat::Toon,
    }
}

fn first_command_index(args: &[String]) -> Option<usize> {
    let mut index = 1;

    while index < args.len() {
        let current = args[index].as_str();
        match current {
            "--format" | "--host" => index += 2,
            "--json" | "-h" | "--help" | "-V" | "--version" => index += 1,
            _ if current.starts_with("--format=") || current.starts_with("--host=") => index += 1,
            _ if current.starts_with('-') => index += 1,
            _ => return Some(index),
        }
    }

    None
}

fn canonical_command_alias(token: &str) -> Option<&'static str> {
    match token {
        "contract" => Some("guide"),
        "workflow" => Some("plan"),
        "why" => Some("explain"),
        "run" => Some("do"),
        "tasks" => Some("task"),
        "ls" => Some("list"),
        "info" | "inspect" | "describe" => Some("show"),
        "operations" | "operation" | "op" => Some("ops"),
        "spec" => Some("schema"),
        "example" => Some("examples"),
        "preview" | "dry-run" => Some("simulate"),
        _ => None,
    }
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
        exit_code: exit_code.into(),
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
    use super::{Cli, CliExitCode, catalog, execute, normalize_args};
    use clap::CommandFactory;
    use serde_json::Value;

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
            "flywheel_connectors-3kbu1"
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
        assert_eq!(error.exit_code, CliExitCode::AmbiguousCorrection.into());
        assert_eq!(error.payload["error"]["type"], "ambiguous-correction");
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
            "exmaples".to_owned(),
            "slack".to_owned(),
        ];
        let outcome = execute(&args).expect("execution should not fail internally");
        let payload: Value =
            serde_json::from_str(&outcome.text).expect("json output should parse cleanly");

        assert_eq!(outcome.exit_code, CliExitCode::UnknownCommand.into());
        assert_eq!(payload["error"]["type"], "unknown-command");
        assert!(
            payload["error"]["did_you_mean"][0]
                .as_str()
                .unwrap()
                .contains("examples")
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
}
