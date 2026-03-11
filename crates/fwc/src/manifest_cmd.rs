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
        assert_eq!(
            v["validation_error"],
            "error: \"quotes\" & <angle>"
        );
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
}
