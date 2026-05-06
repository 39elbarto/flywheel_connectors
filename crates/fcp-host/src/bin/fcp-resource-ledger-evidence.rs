//! Emit a local resource-ledger JSONL smoke bundle.
//!
//! This runner intentionally emits deterministic, redaction-safe records for
//! the ledger contract. It does not claim a live high-scale host+mesh swarm run;
//! unavailable production prerequisites must be represented by structured skip
//! records rather than by silent success.

use std::env;
use std::process::{Command, ExitCode};

use fcp_host::{
    ResourceLedgerInput, ResourceLedgerOutcome, ResourceLedgerRecord, ResourceLedgerRecordKind,
    ResourceLedgerSamples, ResourceTelemetryState,
};

const USAGE: &str = "\
Usage: fcp-resource-ledger-evidence [OPTIONS]

Options:
  --scenario-id <id>               Stable scenario id
  --operation-id <id>              Base operation id
  --worker <id>                    Worker/node identity to hash
  --git-revision <rev>             Git revision under test
  --skip-host-mesh <reason>        Emit only a structured skip record
  -h, --help                       Print this help

Environment:
  FCP_RESOURCE_LEDGER_GIT_REVISION Fallback for --git-revision
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    scenario_id: String,
    operation_id: String,
    worker_identity: String,
    git_revision: Option<String>,
    skip_host_mesh_reason: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            scenario_id: "swarm.resource-ledger.local-smoke".to_string(),
            operation_id: "resource-ledger-smoke".to_string(),
            worker_identity: "local-worker".to_string(),
            git_revision: None,
            skip_host_mesh_reason: None,
        }
    }
}

fn main() -> ExitCode {
    let command_line = env::args().collect::<Vec<_>>();
    let cli = match parse_cli(&command_line) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let git_revision = cli
        .git_revision
        .clone()
        .or_else(|| env::var("FCP_RESOURCE_LEDGER_GIT_REVISION").ok())
        .unwrap_or_else(detect_git_revision);

    let records = if let Some(reason) = cli.skip_host_mesh_reason {
        vec![ResourceLedgerRecord::structured_skip(
            cli.scenario_id,
            cli.operation_id,
            command_line,
            git_revision,
            cli.worker_identity,
            reason,
        )]
    } else {
        local_smoke_records(&cli, &command_line, &git_revision)
    };

    for record in records {
        match record.to_jsonl_line() {
            Ok(line) => println!("{line}"),
            Err(error) => {
                eprintln!("failed to serialize resource ledger evidence: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn parse_cli(args: &[String]) -> Result<Option<Cli>, String> {
    let mut cli = Cli::default();
    let mut iter = args.iter().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--scenario-id" => {
                cli.scenario_id = iter
                    .next()
                    .ok_or_else(|| "--scenario-id requires a value".to_string())?
                    .clone();
            }
            "--operation-id" => {
                cli.operation_id = iter
                    .next()
                    .ok_or_else(|| "--operation-id requires a value".to_string())?
                    .clone();
            }
            "--worker" => {
                cli.worker_identity = iter
                    .next()
                    .ok_or_else(|| "--worker requires a value".to_string())?
                    .clone();
            }
            "--git-revision" => {
                cli.git_revision = Some(
                    iter.next()
                        .ok_or_else(|| "--git-revision requires a value".to_string())?
                        .clone(),
                );
            }
            "--skip-host-mesh" => {
                cli.skip_host_mesh_reason = Some(
                    iter.next()
                        .ok_or_else(|| "--skip-host-mesh requires a value".to_string())?
                        .clone(),
                );
            }
            value if value.starts_with("--scenario-id=") => {
                cli.scenario_id = split_value(value, "--scenario-id")?.to_string();
            }
            value if value.starts_with("--operation-id=") => {
                cli.operation_id = split_value(value, "--operation-id")?.to_string();
            }
            value if value.starts_with("--worker=") => {
                cli.worker_identity = split_value(value, "--worker")?.to_string();
            }
            value if value.starts_with("--git-revision=") => {
                cli.git_revision = Some(split_value(value, "--git-revision")?.to_string());
            }
            value if value.starts_with("--skip-host-mesh=") => {
                cli.skip_host_mesh_reason =
                    Some(split_value(value, "--skip-host-mesh")?.to_string());
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }

    Ok(Some(cli))
}

fn split_value<'a>(value: &'a str, option: &str) -> Result<&'a str, String> {
    value
        .split_once('=')
        .map(|(_, raw)| raw)
        .filter(|raw| !raw.is_empty())
        .ok_or_else(|| format!("{option} requires a value"))
}

fn local_smoke_records(
    cli: &Cli,
    command_line: &[String],
    git_revision: &str,
) -> Vec<ResourceLedgerRecord> {
    let base = |suffix: &str, kind, outcome, samples, latency_samples_ns| ResourceLedgerInput {
        scenario_id: cli.scenario_id.clone(),
        operation_id: format!("{}-{suffix}", cli.operation_id),
        kind,
        outcome,
        command_line: command_line.to_vec(),
        git_revision: git_revision.to_string(),
        worker_identity: cli.worker_identity.clone(),
        zone_id: Some("z:work".to_string()),
        principal_id: Some("principal:resource-ledger-smoke".to_string()),
        connector_id: Some("fcp.synthetic-smoke".to_string()),
        controller_decision: Some(outcome_label(outcome).to_string()),
        samples,
        latency_samples_ns,
        audit_receipt_id: None,
        fallback_reason: None,
        skip_reason: None,
    };

    vec![
        ResourceLedgerRecord::new(base(
            "invoke",
            ResourceLedgerRecordKind::Invoke,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(120),
                cpu_pressure_per_mille: Some(180),
                memory_pressure_per_mille: Some(210),
                in_flight: Some(8),
                queue_depth: Some(2),
                retry_after_ms: None,
            },
            vec![10_000, 12_000, 15_000, 20_000],
        )),
        ResourceLedgerRecord::new(base(
            "backpressure",
            ResourceLedgerRecordKind::Backpressure,
            ResourceLedgerOutcome::Delayed,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(820),
                cpu_pressure_per_mille: Some(760),
                memory_pressure_per_mille: Some(650),
                in_flight: Some(64),
                queue_depth: Some(31),
                retry_after_ms: Some(25),
            },
            vec![20_000, 22_000, 30_000],
        )),
        ResourceLedgerRecord::new(base(
            "retry",
            ResourceLedgerRecordKind::Retry,
            ResourceLedgerOutcome::Retried,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(400),
                cpu_pressure_per_mille: Some(500),
                memory_pressure_per_mille: None,
                in_flight: Some(14),
                queue_depth: Some(7),
                retry_after_ms: Some(100),
            },
            vec![30_000, 50_000, 80_000],
        )),
        ResourceLedgerRecord::new(ResourceLedgerInput {
            audit_receipt_id: Some("audit-receipt-resource-ledger-smoke".to_string()),
            ..base(
                "audit",
                ResourceLedgerRecordKind::Audit,
                ResourceLedgerOutcome::Admitted,
                ResourceLedgerSamples {
                    state: ResourceTelemetryState::NotApplicable,
                    ..ResourceLedgerSamples::default()
                },
                Vec::new(),
            )
        }),
    ]
}

fn outcome_label(outcome: ResourceLedgerOutcome) -> &'static str {
    match outcome {
        ResourceLedgerOutcome::Admitted => "admitted",
        ResourceLedgerOutcome::Warned => "warned",
        ResourceLedgerOutcome::Delayed => "delayed",
        ResourceLedgerOutcome::Denied => "denied",
        ResourceLedgerOutcome::Cancelled => "cancelled",
        ResourceLedgerOutcome::Retried => "retried",
        ResourceLedgerOutcome::Skipped => "skipped",
        ResourceLedgerOutcome::Unknown => "unknown",
    }
}

fn detect_git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parse_cli_uses_documented_defaults() {
        let cli = parse_cli(&args(&["fcp-resource-ledger-evidence"]))
            .expect("parse")
            .expect("not help");

        assert_eq!(cli.scenario_id, "swarm.resource-ledger.local-smoke");
        assert_eq!(cli.operation_id, "resource-ledger-smoke");
        assert_eq!(cli.worker_identity, "local-worker");
    }

    #[test]
    fn parse_cli_accepts_inline_and_split_options() {
        let cli = parse_cli(&args(&[
            "fcp-resource-ledger-evidence",
            "--scenario-id=custom.scenario",
            "--operation-id",
            "op42",
            "--worker=worker-secret-name",
            "--git-revision",
            "abc123",
            "--skip-host-mesh=missing live mesh fixture",
        ]))
        .expect("parse")
        .expect("not help");

        assert_eq!(cli.scenario_id, "custom.scenario");
        assert_eq!(cli.operation_id, "op42");
        assert_eq!(cli.worker_identity, "worker-secret-name");
        assert_eq!(cli.git_revision.as_deref(), Some("abc123"));
        assert_eq!(
            cli.skip_host_mesh_reason.as_deref(),
            Some("missing live mesh fixture")
        );
    }

    #[test]
    fn parse_cli_rejects_unknown_options() {
        let err = parse_cli(&args(&["fcp-resource-ledger-evidence", "--wat"]))
            .expect_err("unknown option should fail");
        assert!(err.contains("unknown option"));
    }

    #[test]
    fn local_smoke_records_cover_core_decision_surfaces() {
        let cli = Cli::default();
        let records = local_smoke_records(&cli, &args(&["fcp-resource-ledger-evidence"]), "abc123");

        assert_eq!(records.len(), 4);
        assert!(
            records
                .iter()
                .any(|record| record.kind == ResourceLedgerRecordKind::Backpressure)
        );
        assert!(
            records
                .iter()
                .any(|record| record.kind == ResourceLedgerRecordKind::Audit
                    && record.audit_receipt_id.is_some())
        );
        assert!(
            records
                .iter()
                .all(|record| record.worker_ref.starts_with("worker:blake3:"))
        );
    }
}
