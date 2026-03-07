#![deny(unsafe_code)]

mod catalog;
mod render;

use std::path::PathBuf;

use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::render::{OutputFormat, render};

const ABOUT: &str =
    "Standalone Flywheel connector console with TOON-first, progressive-disclosure output.";

const LONG_ABOUT: &str = "\
Standalone Flywheel connector console for discovery, lifecycle management, configuration, and
invocation across every connector in the workspace.

Defaults:
  - TOON output is the default because agent-facing output should stay token-efficient.
  - Use --format json when you need full-fidelity structured output.
  - Prefer progressive disclosure: list -> show -> ops -> schema -> config doctor -> simulate -> invoke.
";

const AFTER_HELP: &str = "\
Examples:
  fwc guide
  fwc list
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
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("fwc: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let dispatch = dispatch(&cli)?;
    let format = if cli.json {
        OutputFormat::Json
    } else {
        cli.format
    };
    print!("{}", render(dispatch.payload, format)?);
    Ok(dispatch.exit_code)
}

fn dispatch(cli: &Cli) -> Result<DispatchOutcome> {
    let outcome = match &cli.command {
        Commands::Guide(args) => {
            let payload = catalog::guide_payload(args.command.as_deref());
            let exit_code = if payload["status"] == "unknown-command" {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
            DispatchOutcome { payload, exit_code }
        }
        Commands::List(args) => planned("list", args)?,
        Commands::Search(args) => planned("search", args)?,
        Commands::Show(args) => planned("show", args)?,
        Commands::Ops(args) => planned("ops", args)?,
        Commands::Schema(args) => planned("schema", args)?,
        Commands::Examples(args) => planned("example", args)?,
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
        payload: catalog::planned_payload(command, serde_json::to_value(args)?),
        exit_code: ExitCode::SUCCESS,
    })
}

struct DispatchOutcome {
    payload: serde_json::Value,
    exit_code: ExitCode,
}

#[cfg(test)]
mod tests {
    use super::{Cli, catalog};
    use clap::CommandFactory;

    #[test]
    fn clap_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn guide_lists_progressive_disclosure_workflow() {
        let payload = catalog::guide_payload(None);
        assert_eq!(payload["recommended_workflow"][0], "fwc list");
        assert_eq!(
            payload["phase"]["current_bead"],
            "flywheel_connectors-1g7z0.1"
        );
    }

    #[test]
    fn guide_unknown_command_maps_to_nonzero_contract() {
        let payload = catalog::guide_payload(Some("nope"));
        assert_eq!(payload["status"], "unknown-command");
    }
}
