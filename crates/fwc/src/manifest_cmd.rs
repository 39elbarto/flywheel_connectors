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
#[derive(Args, Debug, Clone)]
pub struct ManifestArgs {
    #[command(subcommand)]
    pub command: ManifestCommand,
}

/// Manifest subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum ManifestCommand {
    /// Fix manifest interface hash and report lint results.
    Fix(FixArgs),
}

/// Arguments for `fcp manifest fix`.
#[derive(Args, Debug, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(
        changed: bool,
        wrote: bool,
        validation_error: Option<&str>,
    ) -> ManifestFixReport {
        ManifestFixReport {
            path: "connectors/test/manifest.toml".to_string(),
            mode: if wrote { "write" } else { "check" }.to_string(),
            changed,
            wrote,
            interface_hash_before: "abc123".to_string(),
            interface_hash_after: if changed {
                "def456".to_string()
            } else {
                "abc123".to_string()
            },
            validation_error: validation_error.map(String::from),
        }
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = sample_report(true, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["path"], "connectors/test/manifest.toml");
        assert_eq!(back["changed"], true);
        assert_eq!(back["wrote"], false);
    }

    #[test]
    fn report_no_change_no_write() {
        let report = sample_report(false, false, None);
        assert!(!report.changed);
        assert!(!report.wrote);
        assert_eq!(report.interface_hash_before, report.interface_hash_after);
    }

    #[test]
    fn report_changed_but_not_written() {
        let report = sample_report(true, false, None);
        assert!(report.changed);
        assert!(!report.wrote);
        assert_ne!(report.interface_hash_before, report.interface_hash_after);
    }

    #[test]
    fn report_changed_and_written() {
        let report = sample_report(true, true, None);
        assert!(report.changed);
        assert!(report.wrote);
    }

    #[test]
    fn report_with_validation_error() {
        let report = sample_report(false, false, Some("missing required field"));
        assert!(report.validation_error.is_some());
        assert_eq!(report.validation_error.unwrap(), "missing required field");
    }

    #[test]
    fn report_skip_serializing_none_validation_error() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("validation_error"));
    }

    #[test]
    fn report_includes_validation_error_when_present() {
        let report = sample_report(false, false, Some("bad hash"));
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("validation_error"));
        assert!(json.contains("bad hash"));
    }

    #[test]
    fn report_mode_check() {
        let report = sample_report(false, false, None);
        assert_eq!(report.mode, "check");
    }

    #[test]
    fn report_mode_write() {
        let report = sample_report(true, true, None);
        assert_eq!(report.mode, "write");
    }

    #[test]
    fn fix_args_debug() {
        let args = FixArgs {
            manifest_path: PathBuf::from("manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("manifest.toml"));
    }

    #[test]
    fn fix_args_default_path() {
        let args = FixArgs {
            manifest_path: PathBuf::from("manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert_eq!(args.manifest_path, PathBuf::from("manifest.toml"));
    }

    // ── print_human_report tests ────────────────────────────────

    #[test]
    fn print_human_report_no_change_check() {
        let report = sample_report(false, false, None);
        // Should not panic
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_changed_check() {
        let report = sample_report(true, false, None);
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_changed_written() {
        let report = sample_report(true, true, None);
        print_human_report(&report, false);
    }

    #[test]
    fn print_human_report_no_change_write_mode() {
        let report = sample_report(false, false, None);
        print_human_report(&report, false);
    }

    #[test]
    fn print_human_report_with_validation_error_check() {
        let report = sample_report(false, false, Some("invalid field: zones.forbidden"));
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_with_validation_error_write() {
        let report = sample_report(true, true, Some("missing capability"));
        print_human_report(&report, false);
    }

    #[test]
    fn print_human_report_changed_but_not_written_write_mode() {
        let report = sample_report(true, false, None);
        print_human_report(&report, false);
    }

    // ── ManifestFixReport serialization ─────────────────────────

    #[test]
    fn report_json_all_fields_present() {
        let report = sample_report(true, true, Some("err"));
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("\"path\""));
        assert!(json.contains("\"mode\""));
        assert!(json.contains("\"changed\""));
        assert!(json.contains("\"wrote\""));
        assert!(json.contains("\"interface_hash_before\""));
        assert!(json.contains("\"interface_hash_after\""));
        assert!(json.contains("\"validation_error\""));
    }

    #[test]
    fn report_json_pretty_parses_back() {
        let report = sample_report(true, false, Some("bad"));
        let json = serde_json::to_string_pretty(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["changed"], true);
        assert_eq!(v["wrote"], false);
        assert_eq!(v["validation_error"], "bad");
    }

    // ── ManifestCommand/ManifestArgs tests ──────────────────────

    #[test]
    fn manifest_args_debug() {
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: PathBuf::from("test.toml"),
                check: true,
                write: false,
                json: false,
            }),
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("Fix"));
        assert!(debug.contains("test.toml"));
    }

    #[test]
    fn fix_args_check_and_json() {
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: true,
            write: false,
            json: true,
        };
        assert!(args.check);
        assert!(!args.write);
        assert!(args.json);
    }

    #[test]
    fn fix_args_write_mode() {
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: false,
            write: true,
            json: false,
        };
        assert!(args.write);
        assert!(!args.check);
    }
}
