//! `fcp manifest` command implementation.
//!
//! Provides tools to validate and repair connector manifests.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use fcp_manifest::ConnectorManifest;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `fcp manifest` command.
#[derive(Args, Debug)]
pub struct ManifestArgs {
    #[command(subcommand)]
    pub command: ManifestCommand,
}

/// Manifest subcommands.
#[derive(Subcommand, Debug)]
pub enum ManifestCommand {
    /// Fix manifest interface hash and report lint results.
    Fix(FixArgs),
}

/// Arguments for `fcp manifest fix`.
#[derive(Args, Debug)]
pub struct FixArgs {
    /// Path to manifest.toml.
    #[arg(default_value = "manifest.toml")]
    pub manifest_path: PathBuf,

    /// Check without writing changes (default).
    #[arg(long, default_value_t = false)]
    pub check: bool,

    /// Write changes to disk.
    #[arg(long, default_value_t = false, conflicts_with = "check")]
    pub write: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct ManifestFixReport {
    path: String,
    mode: String,
    changed: bool,
    wrote: bool,
    interface_hash_before: String,
    interface_hash_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_error: Option<String>,
}

/// Run the manifest command.
pub fn run(args: ManifestArgs) -> Result<()> {
    match args.command {
        ManifestCommand::Fix(args) => run_fix(&args),
    }
}

fn run_fix(args: &FixArgs) -> Result<()> {
    let check_only = args.check || !args.write;
    let manifest_path = &args.manifest_path;

    let raw = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read manifest: {}", manifest_path.display()))?;

    let mut manifest =
        ConnectorManifest::parse_str_unchecked(&raw).context("failed to parse manifest TOML")?;

    let before = manifest.manifest.interface_hash.to_string();
    let expected = manifest.compute_interface_hash()?;
    let after = expected.to_string();
    let changed = before != after;

    if changed {
        manifest.manifest.interface_hash = expected;
    }

    let validation_error = manifest.validate().err().map(|err| err.to_string());

    let wrote = if args.write && changed {
        let rendered = toml::to_string_pretty(&manifest).context("failed to render manifest")?;
        fs::write(manifest_path, rendered)
            .with_context(|| format!("failed to write manifest: {}", manifest_path.display()))?;
        true
    } else {
        false
    };

    let report = ManifestFixReport {
        path: manifest_path.display().to_string(),
        mode: if check_only {
            "check".to_string()
        } else {
            "write".to_string()
        },
        changed,
        wrote,
        interface_hash_before: before,
        interface_hash_after: after,
        validation_error,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report, check_only);
    }

    if check_only {
        if report.changed || report.validation_error.is_some() {
            std::process::exit(1);
        }
    } else if report.validation_error.is_some() {
        std::process::exit(1);
    }

    Ok(())
}

fn print_human_report(report: &ManifestFixReport, check_only: bool) {
    println!();
    println!("Manifest: {}", report.path);
    if report.changed {
        println!(
            "Interface hash: {} -> {}",
            report.interface_hash_before, report.interface_hash_after
        );
    } else {
        println!("Interface hash: {}", report.interface_hash_after);
    }

    if let Some(error) = &report.validation_error {
        println!("Validation: {error}");
    } else {
        println!("Validation: ok");
    }

    if check_only {
        if report.changed {
            println!("Status: changes required (run with --write)");
        } else {
            println!("Status: no changes needed");
        }
    } else if report.changed && report.wrote {
        println!("Status: updated manifest written");
    } else if report.changed {
        println!("Status: changes available (use --write)");
    } else {
        println!("Status: no changes needed");
    }
}
