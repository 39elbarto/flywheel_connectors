//! FCP2 developer/operator CLI entrypoint.
//!
//! This CLI provides tooling for FCP2 operators and developers:
//! - `fcp audit` - Audit chain operations for incident response
//! - `fcp budget` - Usage budget status per zone
//! - `fcp bench` - Performance benchmarking suite
//! - `fcp connector` - Connector discovery and introspection
//! - `fcp explain` - Operation decision explanations
//! - `fcp install` - Connector installation with verification
//! - `fcp manifest` - Manifest repair and lint checks
//! - `fcp net` - Egress policy debugging (`NetworkConstraints`)
//! - `fcp policy` - Policy simulation and preflight checks
//! - `fcp repair` - Coverage status and repair planning

#![forbid(unsafe_code)]

mod audit;
mod bench;
mod budget;
mod connector;
mod doctor;
mod explain;
mod install;
mod manifest;
mod net;
mod new;
mod package;
mod policy;
mod repair;

use std::io::{IsTerminal, Read, Write};
use std::process::Stdio;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

/// FCP2 developer/operator CLI.
#[derive(Parser)]
#[command(name = "fcp")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Read input from stdin (for piping).
    #[arg(long, global = true, default_value_t = false)]
    input_stdin: bool,

    /// Input format for stdin (json, toml, raw).
    #[arg(long, global = true, value_enum, default_value_t = InputFormat::Json)]
    input_format: InputFormat,

    /// Disable pager for long human-readable output.
    #[arg(long, global = true, default_value_t = false)]
    no_pager: bool,

    /// Force pager even for short output.
    #[arg(
        long,
        global = true,
        default_value_t = false,
        conflicts_with = "no_pager"
    )]
    pager: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit chain operations for incident response and debugging.
    ///
    /// Stream audit events from a zone's audit chain with filtering.
    Audit(audit::AuditArgs),

    /// Performance benchmark suite.
    ///
    /// Run benchmarks to measure and track FCP2 performance characteristics.
    /// Outputs machine-readable JSON with environment metadata for regression tracking.
    Bench(bench::BenchArgs),

    /// Report usage budgets per zone.
    ///
    /// Shows current usage vs budget and enforcement mode for each zone.
    Budget(budget::BudgetArgs),

    /// Connector discovery and introspection.
    ///
    /// List, inspect, and introspect registered connectors. The introspect
    /// subcommand provides tool schemas optimized for AI agent consumption.
    Connector(connector::ConnectorArgs),

    /// Diagnose zone health and freshness.
    ///
    /// Checks checkpoint freshness, revocation status, and degraded mode state.
    Doctor(doctor::DoctorArgs),

    /// Explain an allow/deny decision by rendering the `DecisionReceipt`.
    ///
    /// Load and display the mechanical evidence behind an operation decision.
    Explain(explain::ExplainArgs),

    /// Install a connector with full verification chain.
    ///
    /// Verify manifest signatures, binary checksums, and supply chain policy,
    /// then mirror the connector to the mesh store.
    Install(install::InstallArgs),

    /// Repair and validate connector manifests.
    ///
    /// Recompute interface hashes and lint manifest defaults.
    Manifest(manifest::ManifestArgs),

    /// Create a new FCP2-compliant connector scaffold.
    ///
    /// Generates a complete connector crate with manifest, source files,
    /// and test scaffolding. Runs compliance prechecks automatically.
    New(new::NewArgs),

    /// Explain egress policy decisions for a URL.
    Net(net::NetArgs),

    /// Package a connector for distribution.
    ///
    /// Build the connector with deterministic flags, embed manifest,
    /// generate SBOM, and output a complete package directory.
    Package(package::PackageArgs),

    /// Policy simulation and preflight checks.
    ///
    /// Simulate policy outcomes for an `InvokeRequest` without side effects.
    Policy(policy::PolicyArgs),

    /// Coverage status and repair planning.
    Repair(repair::RepairArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InputFormat {
    Json,
    Toml,
    Raw,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct PagerConfig {
    command: String,
    args: Vec<String>,
    threshold: usize,
    disabled: bool,
    force: bool,
}

impl PagerConfig {
    fn from_cli(cli: &Cli) -> Self {
        let command = std::env::var("PAGER").unwrap_or_else(|_| "less".to_string());
        Self {
            command,
            args: vec!["-R".to_string()],
            threshold: 50,
            disabled: cli.no_pager,
            force: cli.pager,
        }
    }
}

#[allow(dead_code)]
pub(crate) fn output_with_pager(
    content: &str,
    config: &PagerConfig,
    json_output: bool,
) -> Result<()> {
    if json_output {
        print!("{content}");
        return Ok(());
    }

    let should_page = if config.disabled {
        false
    } else if config.force {
        true
    } else if !std::io::stdout().is_terminal() {
        false
    } else {
        content.lines().count() >= config.threshold
    };

    if !should_page {
        print!("{content}");
        return Ok(());
    }

    let Ok(mut child) = std::process::Command::new(&config.command)
        .args(&config.args)
        .stdin(Stdio::piped())
        .spawn()
    else {
        print!("{content}");
        return Ok(());
    };

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(content.as_bytes())
            .context("failed to write to pager stdin")?;
    }

    let _ = child.wait();
    Ok(())
}

fn read_stdin_input(format: InputFormat) -> Result<serde_json::Value> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("failed to read stdin")?;

    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("stdin input is empty");
    }

    match format {
        InputFormat::Json => Ok(serde_json::from_str(trimmed)?),
        InputFormat::Toml => {
            let toml_value: toml::Value = toml::from_str(trimmed)?;
            Ok(serde_json::to_value(toml_value)?)
        }
        InputFormat::Raw => Ok(serde_json::json!({ "raw": trimmed })),
    }
}

fn main() -> Result<()> {
    // Initialize tracing subscriber for structured logging.
    // Write logs to stderr so stdout is clean for JSON output.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();
    let _pager = PagerConfig::from_cli(&cli);

    let stdin_input = if cli.input_stdin {
        Some(read_stdin_input(cli.input_format)?)
    } else {
        None
    };

    match cli.command {
        Commands::Audit(args) => audit::run(args),
        Commands::Bench(args) => bench::run(args),
        Commands::Budget(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            budget::run(&args)
        }
        Commands::Connector(args) => connector::run(&args),
        Commands::Doctor(args) => doctor::run(&args, stdin_input.as_ref()),
        Commands::Explain(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            explain::run(&args)
        }
        Commands::Install(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            install::run(args)
        }
        Commands::Manifest(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            manifest::run(args)
        }
        Commands::New(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            new::run(&args)
        }
        Commands::Net(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            net::run(args)
        }
        Commands::Package(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            package::run(&args)
        }
        Commands::Policy(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            policy::run(&args)
        }
        Commands::Repair(args) => {
            if cli.input_stdin {
                anyhow::bail!("--input-stdin is currently supported only for `fcp doctor`");
            }
            repair::run(args)
        }
    }
}
