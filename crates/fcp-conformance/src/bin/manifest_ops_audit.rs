//! Connector manifest operation inventory audit.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use chrono::Utc;
use clap::Parser;
use fcp_conformance::manifest_operations::{audit_connector_manifests, audit_report_jsonl};
use fcp_conformance::schemas::validate_e2e_log_jsonl;
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "fcp-manifest-ops-audit")]
#[command(about = "Audit connector manifests for missing operation declarations")]
struct Args {
    /// Repository root containing the connectors/ directory.
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    /// Write structured JSONL evidence to this path.
    #[arg(long)]
    log_jsonl: Option<PathBuf>,

    /// Print the full JSON report.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Return success even when findings are present.
    #[arg(long, default_value_t = false)]
    allow_findings: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let command_line = std::env::args().collect::<Vec<_>>();
    let timestamp = Utc::now().to_rfc3339();
    let correlation_id = Uuid::new_v4().to_string();
    let git_revision = git_revision(&args.repo_root);

    let report = match audit_connector_manifests(&args.repo_root) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("manifest operations audit failed before scan: {error}");
            return ExitCode::from(2);
        }
    };

    let jsonl = match audit_report_jsonl(
        &report,
        &command_line,
        &git_revision,
        &correlation_id,
        &timestamp,
    ) {
        Ok(jsonl) => jsonl,
        Err(error) => {
            eprintln!("manifest operations audit could not serialize JSONL: {error}");
            return ExitCode::from(2);
        }
    };

    if let Err(error) = validate_e2e_log_jsonl(&jsonl) {
        eprintln!("manifest operations audit generated invalid JSONL evidence: {error}");
        return ExitCode::from(2);
    }

    if let Some(path) = &args.log_jsonl
        && let Err(error) = fs::write(path, &jsonl)
    {
        eprintln!("failed to write JSONL evidence {}: {error}", path.display());
        return ExitCode::from(2);
    }

    if args.json {
        let output = json!({
            "timestamp": timestamp,
            "git_revision": git_revision,
            "valid": report.passed(),
            "report": report,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("audit report serializes")
        );
    } else {
        print_human_summary(&report, args.log_jsonl.as_ref());
    }

    if report.passed() || args.allow_findings {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn git_revision(repo_root: &PathBuf) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(repo_root)
        .output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "unknown".to_owned(),
    }
}

fn print_human_summary(
    report: &fcp_conformance::manifest_operations::ManifestOperationsAuditReport,
    log_jsonl: Option<&PathBuf>,
) {
    println!("Manifest Operations Audit");
    println!("=========================");
    println!("Repo root: {}", report.repo_root);
    println!("Connectors scanned: {}", report.connector_count);
    println!("Failures: {}", report.failed_count);
    println!("Structured skips: {}", report.skipped_count);
    if let Some(path) = log_jsonl {
        println!("JSONL evidence: {}", path.display());
    }
    println!();

    let failing = report.failed_connector_ids();
    if failing.is_empty() {
        println!("No manifest operation audit failures found.");
    } else {
        println!("Manifest operation audit failures ({}):", failing.len());
        for connector_id in failing {
            println!("  - {connector_id}");
        }
    }
}
