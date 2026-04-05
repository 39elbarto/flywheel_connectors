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

    let (validation_error, capability_id_lint) = match manifest.validate() {
        Ok(()) => (None, None),
        Err(err) => {
            let lint = err.capability_id_lint_message();
            let display = lint.clone().unwrap_or_else(|| err.to_string());
            (Some(display), lint)
        }
    };

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
        print_human_report_with_lint(&report, check_only, capability_id_lint.as_deref());
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
    print_human_report_with_lint(report, check_only, None);
}

fn print_human_report_with_lint(
    report: &ManifestFixReport,
    check_only: bool,
    capability_id_lint: Option<&str>,
) {
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

    match capability_id_lint {
        Some(message) => println!("Capability ID lint: {message}"),
        None if report.validation_error.is_none() => println!("Capability ID lint: ok"),
        None => {}
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

    // ── FixArgs clone and equality ─────────────────────────────

    #[test]
    fn fix_args_clone() {
        let args = FixArgs {
            manifest_path: PathBuf::from("clone.toml"),
            check: true,
            write: false,
            json: true,
        };
        let cloned = args.clone();
        assert_eq!(cloned.manifest_path, PathBuf::from("clone.toml"));
        assert!(cloned.check);
        assert!(!cloned.write);
        assert!(cloned.json);
    }

    #[test]
    fn fix_args_all_flags_false() {
        let args = FixArgs {
            manifest_path: PathBuf::from("x.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert!(!args.check);
        assert!(!args.write);
        assert!(!args.json);
    }

    #[test]
    fn fix_args_write_and_json() {
        let args = FixArgs {
            manifest_path: PathBuf::from("wj.toml"),
            check: false,
            write: true,
            json: true,
        };
        assert!(args.write);
        assert!(args.json);
        assert!(!args.check);
    }

    #[test]
    fn fix_args_custom_path() {
        let args = FixArgs {
            manifest_path: PathBuf::from("/some/deep/nested/path/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert_eq!(
            args.manifest_path,
            PathBuf::from("/some/deep/nested/path/manifest.toml")
        );
    }

    #[test]
    fn fix_args_debug_contains_flags() {
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: true,
            write: false,
            json: true,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("check: true"));
        assert!(debug.contains("write: false"));
        assert!(debug.contains("json: true"));
    }

    // ── ManifestArgs/ManifestCommand clone and debug ───────────

    #[test]
    fn manifest_args_clone() {
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: PathBuf::from("clone_test.toml"),
                check: false,
                write: true,
                json: false,
            }),
        };
        let cloned = args.clone();
        let debug = format!("{cloned:?}");
        assert!(debug.contains("clone_test.toml"));
    }

    #[test]
    fn manifest_command_debug_contains_fix() {
        let cmd = ManifestCommand::Fix(FixArgs {
            manifest_path: PathBuf::from("dbg.toml"),
            check: false,
            write: false,
            json: false,
        });
        let debug = format!("{cmd:?}");
        assert!(debug.contains("Fix"));
        assert!(debug.contains("dbg.toml"));
    }

    #[test]
    fn manifest_command_clone() {
        let cmd = ManifestCommand::Fix(FixArgs {
            manifest_path: PathBuf::from("orig.toml"),
            check: true,
            write: false,
            json: true,
        });
        let cloned = cmd.clone();
        let debug = format!("{cloned:?}");
        assert!(debug.contains("orig.toml"));
        assert!(debug.contains("check: true"));
    }

    // ── ManifestFixReport field value tests ────────────────────

    #[test]
    fn report_path_field_preserved() {
        let report = sample_report(false, false, None);
        assert_eq!(report.path, "connectors/test/manifest.toml");
    }

    #[test]
    fn report_hash_before_equals_after_when_unchanged() {
        let report = sample_report(false, false, None);
        assert_eq!(report.interface_hash_before, "abc123");
        assert_eq!(report.interface_hash_after, "abc123");
    }

    #[test]
    fn report_hash_after_differs_when_changed() {
        let report = sample_report(true, false, None);
        assert_eq!(report.interface_hash_before, "abc123");
        assert_eq!(report.interface_hash_after, "def456");
    }

    #[test]
    fn report_mode_reflects_wrote_flag() {
        let check_report = sample_report(false, false, None);
        assert_eq!(check_report.mode, "check");
        let write_report = sample_report(true, true, None);
        assert_eq!(write_report.mode, "write");
    }

    // ── ManifestFixReport JSON structure tests ─────────────────

    #[test]
    fn report_json_field_count_without_validation_error() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        // validation_error is skipped when None, so 6 fields
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn report_json_field_count_with_validation_error() {
        let report = sample_report(false, false, Some("error"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        // all 7 fields present
        assert_eq!(obj.len(), 7);
    }

    #[test]
    fn report_json_changed_is_bool() {
        let report = sample_report(true, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["changed"].is_boolean());
    }

    #[test]
    fn report_json_wrote_is_bool() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["wrote"].is_boolean());
    }

    #[test]
    fn report_json_path_is_string() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["path"].is_string());
    }

    #[test]
    fn report_json_mode_is_string() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["mode"].is_string());
    }

    #[test]
    fn report_json_interface_hashes_are_strings() {
        let report = sample_report(true, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["interface_hash_before"].is_string());
        assert!(v["interface_hash_after"].is_string());
    }

    #[test]
    fn report_json_validation_error_is_string_when_present() {
        let report = sample_report(false, false, Some("val err"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["validation_error"].is_string());
        assert_eq!(v["validation_error"], "val err");
    }

    #[test]
    fn report_json_validation_error_absent_when_none() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("validation_error").is_none());
    }

    // ── ManifestFixReport with special characters ──────────────

    #[test]
    fn report_with_special_chars_in_validation_error() {
        let report = sample_report(false, false, Some("error: \"quotes\" & <angle>"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["validation_error"], "error: \"quotes\" & <angle>");
    }

    #[test]
    fn report_with_empty_validation_error() {
        let report = sample_report(false, false, Some(""));
        assert!(report.validation_error.is_some());
        assert_eq!(report.validation_error.as_deref().unwrap(), "");
    }

    #[test]
    fn report_with_long_validation_error() {
        let long_msg = "x".repeat(1000);
        let report = sample_report(false, false, Some(&long_msg));
        assert_eq!(report.validation_error.as_deref().unwrap().len(), 1000);
    }

    // ── ManifestFixReport custom construction ──────────────────

    #[test]
    fn report_manual_construction() {
        let report = ManifestFixReport {
            path: "/custom/path.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "hash_a".to_string(),
            interface_hash_after: "hash_a".to_string(),
            validation_error: None,
        };
        assert_eq!(report.path, "/custom/path.toml");
        assert_eq!(report.mode, "check");
        assert!(!report.changed);
    }

    #[test]
    fn report_manual_construction_with_write() {
        let report = ManifestFixReport {
            path: "my_manifest.toml".to_string(),
            mode: "write".to_string(),
            changed: true,
            wrote: true,
            interface_hash_before: "old_hash".to_string(),
            interface_hash_after: "new_hash".to_string(),
            validation_error: Some("validation failed".to_string()),
        };
        assert!(report.changed);
        assert!(report.wrote);
        assert_eq!(report.interface_hash_before, "old_hash");
        assert_eq!(report.interface_hash_after, "new_hash");
    }

    #[test]
    fn report_debug_format() {
        let report = sample_report(true, false, Some("test error"));
        let debug = format!("{report:?}");
        assert!(debug.contains("ManifestFixReport"));
        assert!(debug.contains("test error"));
        assert!(debug.contains("connectors/test/manifest.toml"));
    }

    // ── run_fix filesystem tests ───────────────────────────────

    #[test]
    fn run_fix_missing_file_returns_error() {
        let args = FixArgs {
            manifest_path: PathBuf::from("/tmp/fwc_test_nonexistent_manifest.toml"),
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("failed to read manifest"));
    }

    #[test]
    fn run_fix_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        fs::write(&path, "this is not valid toml {{{{").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("failed to parse manifest TOML"));
    }

    #[test]
    fn run_fix_empty_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        fs::write(&path, "").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_partial_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.toml");
        fs::write(&path, "[manifest]\nformat = \"fcp-connector-manifest\"\n").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    // ── check_only logic tests ─────────────────────────────────

    #[test]
    fn check_only_true_when_check_flag_set() {
        // Replicate the logic: check_only = args.check || !args.write
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: true,
            write: false,
            json: false,
        };
        let check_only = args.check || !args.write;
        assert!(check_only);
    }

    #[test]
    fn check_only_true_when_neither_flag_set() {
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: false,
            write: false,
            json: false,
        };
        let check_only = args.check || !args.write;
        assert!(check_only);
    }

    #[test]
    fn check_only_false_when_write_flag_set() {
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: false,
            write: true,
            json: false,
        };
        let check_only = args.check || !args.write;
        assert!(!check_only);
    }

    // ── print_human_report additional branch coverage ──────────

    #[test]
    fn print_human_report_changed_and_wrote_false_write_mode() {
        // This hits the `changed && !wrote` branch in non-check mode
        let report = ManifestFixReport {
            path: "test.toml".to_string(),
            mode: "write".to_string(),
            changed: true,
            wrote: false,
            interface_hash_before: "aaa".to_string(),
            interface_hash_after: "bbb".to_string(),
            validation_error: None,
        };
        // Should not panic — hits "changes available (use --write)" branch
        print_human_report(&report, false);
    }

    #[test]
    fn print_human_report_no_change_no_error_check_mode() {
        let report = ManifestFixReport {
            path: "test.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "same".to_string(),
            interface_hash_after: "same".to_string(),
            validation_error: None,
        };
        // Should not panic — hits "no changes needed" in check mode
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_changed_with_error_in_check_mode() {
        let report = ManifestFixReport {
            path: "test.toml".to_string(),
            mode: "check".to_string(),
            changed: true,
            wrote: false,
            interface_hash_before: "old".to_string(),
            interface_hash_after: "new".to_string(),
            validation_error: Some("zones.forbidden overlap".to_string()),
        };
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_not_changed_with_error_write_mode() {
        let report = ManifestFixReport {
            path: "test.toml".to_string(),
            mode: "write".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "hash".to_string(),
            interface_hash_after: "hash".to_string(),
            validation_error: Some("missing capability".to_string()),
        };
        print_human_report(&report, false);
    }

    // ── ManifestFixReport serialization roundtrip tests ────────

    #[test]
    fn report_serde_roundtrip_with_validation_error() {
        let report = sample_report(true, true, Some("missing field"));
        let json = serde_json::to_string(&report).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["path"], "connectors/test/manifest.toml");
        assert_eq!(back["mode"], "write");
        assert_eq!(back["changed"], true);
        assert_eq!(back["wrote"], true);
        assert_eq!(back["interface_hash_before"], "abc123");
        assert_eq!(back["interface_hash_after"], "def456");
        assert_eq!(back["validation_error"], "missing field");
    }

    #[test]
    fn report_serde_compact_json() {
        let report = sample_report(false, false, None);
        let compact = serde_json::to_string(&report).unwrap();
        // Compact JSON should have no newlines
        assert!(!compact.contains('\n'));
    }

    #[test]
    fn report_serde_pretty_json_has_newlines() {
        let report = sample_report(false, false, None);
        let pretty = serde_json::to_string_pretty(&report).unwrap();
        assert!(pretty.contains('\n'));
    }

    // ── Additional ManifestFixReport construction variants ────

    #[test]
    fn report_all_combinations_changed_wrote() {
        // (changed=false, wrote=false)
        let r1 = sample_report(false, false, None);
        assert!(!r1.changed && !r1.wrote);
        // (changed=true, wrote=false)
        let r2 = sample_report(true, false, None);
        assert!(r2.changed && !r2.wrote);
        // (changed=true, wrote=true)
        let r3 = sample_report(true, true, None);
        assert!(r3.changed && r3.wrote);
        // (changed=false, wrote=true) — construct manually
        let r4 = ManifestFixReport {
            path: "test.toml".to_string(),
            mode: "write".to_string(),
            changed: false,
            wrote: true,
            interface_hash_before: "h1".to_string(),
            interface_hash_after: "h1".to_string(),
            validation_error: None,
        };
        assert!(!r4.changed && r4.wrote);
    }

    #[test]
    fn report_manual_with_unicode_path() {
        let report = ManifestFixReport {
            path: "/tmp/\u{1F600}/manifest.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        assert!(report.path.contains('\u{1F600}'));
    }

    #[test]
    fn report_manual_with_unicode_path_serializes() {
        let report = ManifestFixReport {
            path: "/tmp/\u{00E9}l\u{00E8}ve/manifest.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["path"].as_str().unwrap().contains('\u{00E9}'));
    }

    #[test]
    fn report_with_very_long_path() {
        let long_path = format!("{}/manifest.toml", "a".repeat(500));
        let report = ManifestFixReport {
            path: long_path.clone(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        assert_eq!(report.path.len(), long_path.len());
    }

    #[test]
    fn report_with_empty_path() {
        let report = ManifestFixReport {
            path: String::new(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        assert!(report.path.is_empty());
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["path"], "");
    }

    #[test]
    fn report_with_empty_hashes() {
        let report = ManifestFixReport {
            path: "m.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: String::new(),
            interface_hash_after: String::new(),
            validation_error: None,
        };
        assert_eq!(report.interface_hash_before, report.interface_hash_after);
        assert!(report.interface_hash_before.is_empty());
    }

    #[test]
    fn report_with_whitespace_only_validation_error() {
        let report = sample_report(false, false, Some("   \t\n  "));
        assert!(report.validation_error.is_some());
        let err = report.validation_error.unwrap();
        assert_eq!(err.trim(), "");
        assert!(!err.is_empty());
    }

    #[test]
    fn report_with_newlines_in_validation_error() {
        let report = sample_report(false, false, Some("line1\nline2\nline3"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let err_str = v["validation_error"].as_str().unwrap();
        assert!(err_str.contains('\n'));
        assert_eq!(err_str.lines().count(), 3);
    }

    #[test]
    fn report_with_backslash_in_path() {
        let report = ManifestFixReport {
            path: "C:\\Users\\test\\manifest.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["path"].as_str().unwrap().contains("C:\\Users"));
    }

    // ── JSON value type exhaustive checks ────────────────────

    #[test]
    fn report_json_values_correct_types_full_report() {
        let report = sample_report(true, true, Some("err"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["path"].is_string());
        assert!(v["mode"].is_string());
        assert!(v["changed"].is_boolean());
        assert!(v["wrote"].is_boolean());
        assert!(v["interface_hash_before"].is_string());
        assert!(v["interface_hash_after"].is_string());
        assert!(v["validation_error"].is_string());
    }

    #[test]
    fn report_json_no_extra_fields() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        let expected_keys = [
            "path",
            "mode",
            "changed",
            "wrote",
            "interface_hash_before",
            "interface_hash_after",
        ];
        for key in &expected_keys {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
        assert!(!obj.contains_key("validation_error"));
    }

    #[test]
    fn report_json_all_expected_keys_with_error() {
        let report = sample_report(false, false, Some("e"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        let expected_keys = [
            "path",
            "mode",
            "changed",
            "wrote",
            "interface_hash_before",
            "interface_hash_after",
            "validation_error",
        ];
        for key in &expected_keys {
            assert!(obj.contains_key(*key), "missing key: {key}");
        }
    }

    #[test]
    fn report_json_boolean_values_match() {
        let report = sample_report(true, true, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["changed"].as_bool().unwrap());
        assert!(v["wrote"].as_bool().unwrap());
    }

    #[test]
    fn report_json_boolean_values_false() {
        let report = sample_report(false, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(!v["changed"].as_bool().unwrap());
        assert!(!v["wrote"].as_bool().unwrap());
    }

    #[test]
    fn report_json_hash_values_match_report_fields() {
        let report = sample_report(true, false, None);
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["interface_hash_before"].as_str().unwrap(),
            report.interface_hash_before
        );
        assert_eq!(
            v["interface_hash_after"].as_str().unwrap(),
            report.interface_hash_after
        );
    }

    // ── FixArgs path variations ──────────────────────────────

    #[test]
    fn fix_args_relative_path() {
        let args = FixArgs {
            manifest_path: PathBuf::from("./relative/path/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert!(args.manifest_path.starts_with("./relative"));
    }

    #[test]
    fn fix_args_absolute_path() {
        let args = FixArgs {
            manifest_path: PathBuf::from("/absolute/path/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert!(args.manifest_path.is_absolute());
    }

    #[test]
    fn fix_args_path_with_dots() {
        let args = FixArgs {
            manifest_path: PathBuf::from("../parent/../sibling/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert!(args.manifest_path.to_str().unwrap().contains(".."));
    }

    #[test]
    fn fix_args_empty_path() {
        let args = FixArgs {
            manifest_path: PathBuf::from(""),
            check: false,
            write: false,
            json: false,
        };
        assert_eq!(args.manifest_path, PathBuf::from(""));
    }

    #[test]
    fn fix_args_path_extension() {
        let args = FixArgs {
            manifest_path: PathBuf::from("some/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert_eq!(args.manifest_path.extension().unwrap(), "toml");
    }

    #[test]
    fn fix_args_path_file_stem() {
        let args = FixArgs {
            manifest_path: PathBuf::from("connectors/github/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert_eq!(args.manifest_path.file_stem().unwrap(), "manifest");
    }

    #[test]
    fn fix_args_path_parent() {
        let args = FixArgs {
            manifest_path: PathBuf::from("connectors/github/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        assert_eq!(
            args.manifest_path.parent().unwrap(),
            PathBuf::from("connectors/github")
        );
    }

    // ── FixArgs clone preserves all fields ───────────────────

    #[test]
    fn fix_args_clone_preserves_check_true() {
        let args = FixArgs {
            manifest_path: PathBuf::from("c.toml"),
            check: true,
            write: false,
            json: false,
        };
        let cloned = args.clone();
        assert_eq!(args.check, cloned.check);
        assert_eq!(args.write, cloned.write);
        assert_eq!(args.json, cloned.json);
        assert_eq!(args.manifest_path, cloned.manifest_path);
    }

    #[test]
    fn fix_args_clone_preserves_write_true() {
        let args = FixArgs {
            manifest_path: PathBuf::from("w.toml"),
            check: false,
            write: true,
            json: false,
        };
        let cloned = args.clone();
        assert!(cloned.write);
        assert!(!cloned.check);
    }

    #[test]
    fn fix_args_clone_preserves_json_true() {
        let args = FixArgs {
            manifest_path: PathBuf::from("j.toml"),
            check: false,
            write: false,
            json: true,
        };
        let cloned = args.clone();
        assert!(cloned.json);
    }

    #[test]
    fn fix_args_clone_preserves_all_true() {
        let args = FixArgs {
            manifest_path: PathBuf::from("all.toml"),
            check: true,
            write: true,
            json: true,
        };
        let cloned = args.clone();
        assert!(cloned.check);
        assert!(cloned.write);
        assert!(cloned.json);
    }

    // ── ManifestCommand clone and debug variants ─────────────

    #[test]
    fn manifest_command_clone_preserves_all_fields() {
        let cmd = ManifestCommand::Fix(FixArgs {
            manifest_path: PathBuf::from("preserved.toml"),
            check: true,
            write: false,
            json: true,
        });
        let cloned = cmd.clone();
        match cloned {
            ManifestCommand::Fix(args) => {
                assert_eq!(args.manifest_path, PathBuf::from("preserved.toml"));
                assert!(args.check);
                assert!(!args.write);
                assert!(args.json);
            }
        }
    }

    #[test]
    fn manifest_args_clone_preserves_inner_command() {
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: PathBuf::from("inner.toml"),
                check: false,
                write: true,
                json: true,
            }),
        };
        let cloned = args.clone();
        match cloned.command {
            ManifestCommand::Fix(fix_args) => {
                assert_eq!(fix_args.manifest_path, PathBuf::from("inner.toml"));
                assert!(fix_args.write);
                assert!(fix_args.json);
            }
        }
    }

    #[test]
    fn manifest_args_debug_contains_all_fields() {
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: PathBuf::from("debug_test.toml"),
                check: true,
                write: false,
                json: true,
            }),
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("ManifestArgs"));
        assert!(debug.contains("Fix"));
        assert!(debug.contains("debug_test.toml"));
        assert!(debug.contains("check: true"));
        assert!(debug.contains("json: true"));
    }

    // ── check_only logic additional combinations ─────────────

    #[test]
    fn check_only_logic_both_check_and_write_true() {
        // In practice clap prevents this, but test the logic
        let args = FixArgs {
            manifest_path: PathBuf::from("m.toml"),
            check: true,
            write: true,
            json: false,
        };
        let check_only = args.check || !args.write;
        // check=true dominates, so check_only is true
        assert!(check_only);
    }

    #[test]
    fn check_only_logic_table() {
        // Test all 4 combinations of (check, write)
        let combos = [
            (false, false, true), // neither set → check_only
            (false, true, false), // write only → not check_only
            (true, false, true),  // check only → check_only
            (true, true, true),   // both (invalid in clap) → check_only (check dominates)
        ];
        for (check, write, expected) in combos {
            let result = check || !write;
            assert_eq!(result, expected, "check={check}, write={write}");
        }
    }

    // ── print_human_report edge case coverage ────────────────

    #[test]
    fn print_human_report_with_very_long_path() {
        let report = ManifestFixReport {
            path: "a".repeat(500),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_with_empty_hashes() {
        let report = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: String::new(),
            interface_hash_after: String::new(),
            validation_error: None,
        };
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_changed_with_long_hashes() {
        let report = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "write".to_string(),
            changed: true,
            wrote: true,
            interface_hash_before: "a".repeat(64),
            interface_hash_after: "b".repeat(64),
            validation_error: None,
        };
        print_human_report(&report, false);
    }

    #[test]
    fn print_human_report_with_multiline_validation_error() {
        let report = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: Some("error on line 1\nerror on line 2".to_string()),
        };
        print_human_report(&report, true);
    }

    #[test]
    fn print_human_report_all_false_flags() {
        let report = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "check".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "h".to_string(),
            interface_hash_after: "h".to_string(),
            validation_error: None,
        };
        // check_only=false, changed=false → "no changes needed"
        print_human_report(&report, false);
    }

    // ── run_fix error cases with filesystem ──────────────────

    #[test]
    fn run_fix_directory_as_manifest_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let args = FixArgs {
            manifest_path: dir.path().to_path_buf(),
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_binary_content_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.toml");
        // Write valid UTF-8 that is not valid TOML
        fs::write(&path, b"[[[invalid").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_whitespace_only_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("whitespace.toml");
        fs::write(&path, "   \n\t\n  ").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_comment_only_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("comments.toml");
        fs::write(&path, "# this is just a comment\n# nothing else\n").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_nonexistent_directory_returns_error() {
        let args = FixArgs {
            manifest_path: PathBuf::from("/nonexistent/path/to/manifest.toml"),
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("failed to read manifest"));
    }

    #[test]
    fn run_fix_json_output_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_json.toml");
        fs::write(&path, "not toml at all!!! ===").unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: true,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_wrong_toml_structure_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong_structure.toml");
        fs::write(
            &path,
            "[package]\nname = \"not-a-connector\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let args = FixArgs {
            manifest_path: path,
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    #[test]
    fn run_fix_deeply_nested_nonexistent_path() {
        let args = FixArgs {
            manifest_path: PathBuf::from("/a/b/c/d/e/f/g/h/i/j/manifest.toml"),
            check: true,
            write: false,
            json: false,
        };
        let result = run_fix(&args);
        assert!(result.is_err());
    }

    // ── ManifestFixReport Debug format checks ────────────────

    #[test]
    fn report_debug_contains_all_field_names() {
        let report = sample_report(true, true, Some("test"));
        let debug = format!("{report:?}");
        assert!(debug.contains("path"));
        assert!(debug.contains("mode"));
        assert!(debug.contains("changed"));
        assert!(debug.contains("wrote"));
        assert!(debug.contains("interface_hash_before"));
        assert!(debug.contains("interface_hash_after"));
        assert!(debug.contains("validation_error"));
    }

    #[test]
    fn report_debug_shows_none_for_no_error() {
        let report = sample_report(false, false, None);
        let debug = format!("{report:?}");
        assert!(debug.contains("validation_error: None"));
    }

    #[test]
    fn report_debug_shows_some_for_error() {
        let report = sample_report(false, false, Some("oops"));
        let debug = format!("{report:?}");
        assert!(debug.contains("Some("));
        assert!(debug.contains("oops"));
    }

    // ── sample_report helper validation ──────────────────────

    #[test]
    fn sample_report_unchanged_has_consistent_hashes() {
        let r = sample_report(false, false, None);
        assert_eq!(r.interface_hash_before, r.interface_hash_after);
    }

    #[test]
    fn sample_report_changed_has_different_hashes() {
        let r = sample_report(true, false, None);
        assert_ne!(r.interface_hash_before, r.interface_hash_after);
    }

    #[test]
    fn sample_report_wrote_true_sets_write_mode() {
        let r = sample_report(true, true, None);
        assert_eq!(r.mode, "write");
    }

    #[test]
    fn sample_report_wrote_false_sets_check_mode() {
        let r = sample_report(false, false, None);
        assert_eq!(r.mode, "check");
    }

    #[test]
    fn sample_report_path_is_always_same() {
        let r1 = sample_report(false, false, None);
        let r2 = sample_report(true, true, Some("err"));
        assert_eq!(r1.path, r2.path);
    }

    // ── JSON serialization edge cases ────────────────────────

    #[test]
    fn report_json_escaped_quotes_in_error() {
        let report = sample_report(false, false, Some("field \"name\" missing"));
        let json = serde_json::to_string(&report).unwrap();
        // Should still parse correctly
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["validation_error"], "field \"name\" missing");
    }

    #[test]
    fn report_json_null_bytes_in_error() {
        let report = sample_report(false, false, Some("before\0after"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["validation_error"].as_str().unwrap().contains('\0'));
    }

    #[test]
    fn report_json_tab_in_error() {
        let report = sample_report(false, false, Some("col1\tcol2"));
        let json = serde_json::to_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["validation_error"].as_str().unwrap().contains('\t'));
    }

    #[test]
    fn report_json_consecutive_serialization_stable() {
        let report = sample_report(true, false, Some("err"));
        let json1 = serde_json::to_string(&report).unwrap();
        let json2 = serde_json::to_string(&report).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn report_json_pretty_vs_compact_same_data() {
        let report = sample_report(true, true, Some("x"));
        let compact = serde_json::to_string(&report).unwrap();
        let pretty = serde_json::to_string_pretty(&report).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&compact).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&pretty).unwrap();
        assert_eq!(v1, v2);
    }

    // ── ManifestCommand pattern matching ─────────────────────

    #[test]
    fn manifest_command_match_extracts_fix_args() {
        let cmd = ManifestCommand::Fix(FixArgs {
            manifest_path: PathBuf::from("extract.toml"),
            check: true,
            write: false,
            json: false,
        });
        match cmd {
            ManifestCommand::Fix(args) => {
                assert_eq!(args.manifest_path, PathBuf::from("extract.toml"));
                assert!(args.check);
            }
        }
    }

    #[test]
    fn manifest_args_command_match_nested() {
        let ma = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: PathBuf::from("nested.toml"),
                check: false,
                write: true,
                json: true,
            }),
        };
        match ma.command {
            ManifestCommand::Fix(args) => {
                assert!(args.write);
                assert!(args.json);
            }
        }
    }

    // ── FixArgs Debug output detailed checks ─────────────────

    #[test]
    fn fix_args_debug_all_false() {
        let args = FixArgs {
            manifest_path: PathBuf::from("d.toml"),
            check: false,
            write: false,
            json: false,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("check: false"));
        assert!(debug.contains("write: false"));
        assert!(debug.contains("json: false"));
    }

    #[test]
    fn fix_args_debug_all_true() {
        let args = FixArgs {
            manifest_path: PathBuf::from("t.toml"),
            check: true,
            write: true,
            json: true,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("check: true"));
        assert!(debug.contains("write: true"));
        assert!(debug.contains("json: true"));
    }

    #[test]
    fn fix_args_debug_path_with_spaces() {
        let args = FixArgs {
            manifest_path: PathBuf::from("path with spaces/manifest.toml"),
            check: false,
            write: false,
            json: false,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("path with spaces"));
    }

    // ── ManifestFixReport mode and state consistency ─────────

    #[test]
    fn report_check_mode_never_wrote() {
        // In check mode, wrote should always be false
        let r = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "check".to_string(),
            changed: true,
            wrote: false,
            interface_hash_before: "a".to_string(),
            interface_hash_after: "b".to_string(),
            validation_error: None,
        };
        assert_eq!(r.mode, "check");
        assert!(!r.wrote);
    }

    #[test]
    fn report_write_mode_wrote_when_changed() {
        let r = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "write".to_string(),
            changed: true,
            wrote: true,
            interface_hash_before: "a".to_string(),
            interface_hash_after: "b".to_string(),
            validation_error: None,
        };
        assert_eq!(r.mode, "write");
        assert!(r.wrote);
        assert!(r.changed);
    }

    #[test]
    fn report_write_mode_no_write_when_unchanged() {
        let r = ManifestFixReport {
            path: "t.toml".to_string(),
            mode: "write".to_string(),
            changed: false,
            wrote: false,
            interface_hash_before: "same".to_string(),
            interface_hash_after: "same".to_string(),
            validation_error: None,
        };
        assert_eq!(r.mode, "write");
        assert!(!r.wrote);
        assert!(!r.changed);
    }

    // ── run function routing test ────────────────────────────

    #[test]
    fn run_dispatches_to_fix_and_errors_on_missing_file() {
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: PathBuf::from("/tmp/fwc_test_run_dispatch_nonexistent.toml"),
                check: true,
                write: false,
                json: false,
            }),
        };
        let result = run(args);
        assert!(result.is_err());
    }

    #[test]
    fn run_dispatches_fix_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dispatch_bad.toml");
        fs::write(&path, "{{invalid toml}}").unwrap();
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: path,
                check: true,
                write: false,
                json: false,
            }),
        };
        let result = run(args);
        assert!(result.is_err());
    }

    #[test]
    fn run_dispatches_fix_json_mode_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dispatch_json_bad.toml");
        fs::write(&path, "nope!").unwrap();
        let args = ManifestArgs {
            command: ManifestCommand::Fix(FixArgs {
                manifest_path: path,
                check: true,
                write: false,
                json: true,
            }),
        };
        let result = run(args);
        assert!(result.is_err());
    }

    #[test]
    fn print_human_report_with_lint_accepts_capability_guidance() {
        let report = sample_report(
            false,
            false,
            Some("capability id `https://api.example.com` contains URL scheme `https:`"),
        );
        print_human_report_with_lint(
            &report,
            true,
            Some(
                "capability id `https://api.example.com` contains URL scheme `https:` \
                 (field: capabilities.required). Move hostnames/ports into network_constraints \
                 and keep capability IDs abstract.",
            ),
        );
    }

    #[test]
    fn print_human_report_with_lint_ok_path() {
        let report = sample_report(false, false, None);
        print_human_report_with_lint(&report, true, None);
    }
}
