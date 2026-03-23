//! Minimal CLI for fcp-e2e JSONL output.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::{env, process};

use fcp_core::CorrelationId;
use fcp_e2e::{
    AssertionsSummary, ConnectorProcessRunner, E2eArtifactRecord, E2eCommandMetadata,
    E2eFailureSummary, E2eLogEntry, E2eLogger, E2ePrerequisiteState, E2eReport, E2eRunReport,
    E2eRunner, E2eStepReport, LogScanReport, scan_log_jsonl, validate_log_entry_value,
};
use serde::Serialize;

#[derive(Debug, Default)]
struct CliArgs {
    interop: bool,
    validate_log: Option<PathBuf>,
    scan_log: Option<PathBuf>,
    scan_report: Option<PathBuf>,
    output: Option<PathBuf>,
    stable_output: Option<PathBuf>,
    report_json: Option<PathBuf>,
    summary_output: Option<PathBuf>,
    bundle_dir: Option<PathBuf>,
    scenario_id: Option<String>,
    module: String,
    test_name: String,
    connector_cmd: Option<String>,
    connector_args: Vec<String>,
    requests: Vec<serde_json::Value>,
    request_files: Vec<PathBuf>,
    help: bool,
}

fn usage() -> &'static str {
    "Usage:
  fcp-e2e --interop [--output <file>] [--stable-output <file>] [--report-json <file>] [--summary-output <file>] [--bundle-dir <dir>] [--scenario-id <id>] [--test-name <name>] [--module <name>]
  fcp-e2e --validate-log <file>
  fcp-e2e --scan-log <file> --output <jsonl> --scan-report <report.json> [--report-json <file>] [--summary-output <file>] [--bundle-dir <dir>] [--scenario-id <id>] [--test-name <name>] [--module <name>]
  fcp-e2e --connector-cmd <path> [--request <json> ...] [--request-file <path> ...] \\
         [--connector-arg <arg> ...] [--output <file>] [--stable-output <file>] [--report-json <file>] [--summary-output <file>] [--bundle-dir <dir>] [--scenario-id <id>] [--test-name <name>] [--module <name>]
"
}

fn normalize_request_payload(
    value: serde_json::Value,
    source: &str,
) -> Result<Vec<serde_json::Value>, String> {
    match value {
        serde_json::Value::Object(_) => Ok(vec![value]),
        serde_json::Value::Array(values) => {
            if values.is_empty() {
                return Err(format!("{source} must contain at least one request object"));
            }
            let mut requests = Vec::with_capacity(values.len());
            for (index, entry) in values.into_iter().enumerate() {
                if !entry.is_object() {
                    return Err(format!(
                        "{source} entry {} must be a JSON object",
                        index + 1
                    ));
                }
                requests.push(entry);
            }
            Ok(requests)
        }
        _ => Err(format!(
            "{source} must be a JSON object or an array of JSON objects"
        )),
    }
}

fn parse_request_payload(value: &str, source: &str) -> Result<Vec<serde_json::Value>, String> {
    let json =
        serde_json::from_str(value).map_err(|err| format!("{source} JSON invalid: {err}"))?;
    normalize_request_payload(json, source)
}

fn load_requests_from_file(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    let payload = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read request file {}: {err}", path.display()))?;
    parse_request_payload(&payload, &format!("request file {}", path.display()))
}

fn parse_args() -> Result<CliArgs, String> {
    let mut args = env::args().skip(1);
    let mut parsed = CliArgs {
        interop: false,
        validate_log: None,
        scan_log: None,
        scan_report: None,
        output: None,
        stable_output: None,
        report_json: None,
        summary_output: None,
        bundle_dir: None,
        scenario_id: None,
        module: "fcp-e2e".to_string(),
        test_name: "fcp-e2e".to_string(),
        connector_cmd: None,
        connector_args: Vec::new(),
        requests: Vec::new(),
        request_files: Vec::new(),
        help: false,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                parsed.help = true;
            }
            "--interop" => {
                parsed.interop = true;
            }
            "--validate-log" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--validate-log requires a value".to_string())?;
                parsed.validate_log = Some(PathBuf::from(value));
            }
            "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output requires a value".to_string())?;
                parsed.output = Some(PathBuf::from(value));
            }
            "--stable-output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--stable-output requires a value".to_string())?;
                parsed.stable_output = Some(PathBuf::from(value));
            }
            "--report-json" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--report-json requires a value".to_string())?;
                parsed.report_json = Some(PathBuf::from(value));
            }
            "--summary-output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--summary-output requires a value".to_string())?;
                parsed.summary_output = Some(PathBuf::from(value));
            }
            "--bundle-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--bundle-dir requires a value".to_string())?;
                parsed.bundle_dir = Some(PathBuf::from(value));
            }
            "--scenario-id" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--scenario-id requires a value".to_string())?;
                parsed.scenario_id = Some(value);
            }
            "--scan-log" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--scan-log requires a value".to_string())?;
                parsed.scan_log = Some(PathBuf::from(value));
            }
            "--scan-report" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--scan-report requires a value".to_string())?;
                parsed.scan_report = Some(PathBuf::from(value));
            }
            "--module" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--module requires a value".to_string())?;
                parsed.module = value;
            }
            "--test-name" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--test-name requires a value".to_string())?;
                parsed.test_name = value;
            }
            "--connector-cmd" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--connector-cmd requires a value".to_string())?;
                parsed.connector_cmd = Some(value);
            }
            "--connector-arg" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--connector-arg requires a value".to_string())?;
                parsed.connector_args.push(value);
            }
            "--request" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--request requires a value".to_string())?;
                parsed
                    .requests
                    .extend(parse_request_payload(&value, "--request")?);
            }
            "--request-file" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--request-file requires a value".to_string())?;
                parsed.request_files.push(PathBuf::from(value));
            }
            unknown => {
                return Err(format!("Unknown argument: {unknown}"));
            }
        }
    }

    if parsed.help {
        return Ok(parsed);
    }

    let mode_count = parsed.validate_log.is_some() as u8
        + parsed.scan_log.is_some() as u8
        + parsed.interop as u8
        + parsed.connector_cmd.is_some() as u8;
    if mode_count == 0 {
        return Err(
            "Missing mode: use --validate-log, --scan-log, --interop, or --connector-cmd"
                .to_string(),
        );
    }

    if mode_count > 1 {
        return Err(
            "Choose only one of --validate-log, --scan-log, --interop, or --connector-cmd"
                .to_string(),
        );
    }

    for path in &parsed.request_files {
        parsed.requests.extend(load_requests_from_file(path)?);
    }

    if parsed.connector_cmd.is_some() && parsed.requests.is_empty() {
        return Err(
            "At least one --request or --request-file is required for connector mode".to_string(),
        );
    }

    if parsed.scan_log.is_some() && parsed.output.is_none() && parsed.bundle_dir.is_none() {
        return Err(
            "--scan-log requires --output or --bundle-dir to persist JSONL logs".to_string(),
        );
    }

    if parsed.scan_log.is_some() && parsed.scan_report.is_none() && parsed.bundle_dir.is_none() {
        return Err(
            "--scan-log requires --scan-report or --bundle-dir to persist the scan report"
                .to_string(),
        );
    }

    Ok(parsed)
}

fn validate_entries(entries: &[E2eLogEntry]) -> Result<(), String> {
    if entries.is_empty() {
        return Err("no log entries recorded".to_string());
    }
    for (index, entry) in entries.iter().enumerate() {
        if let Err(err) = entry.validate() {
            return Err(format!("entry {}: {}", index + 1, err));
        }
    }
    Ok(())
}

fn validate_jsonl_file(path: &Path) -> Result<(), String> {
    let file = File::open(path)
        .map_err(|err| format!("failed to open log file {}: {}", path.display(), err))?;
    let reader = io::BufReader::new(file);
    let mut seen = 0_u64;
    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| format!("failed to read line {}: {}", index + 1, err))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        seen += 1;
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|err| format!("line {}: invalid JSON: {}", index + 1, err))?;
        validate_log_entry_value(&value).map_err(|err| format!("line {}: {}", index + 1, err))?;
    }
    if seen == 0 {
        return Err("no log entries found".to_string());
    }
    Ok(())
}

fn write_scan_report(report: &LogScanReport, output: &Path) -> io::Result<()> {
    let payload = serialize_pretty_json(report)?;
    write_scanned_text(Some(output), &payload, "scan report")
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn write_pretty_json<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> io::Result<()> {
    ensure_parent_dir(path.as_ref())?;
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

fn write_text_file(path: &Path, payload: &str) -> io::Result<()> {
    ensure_parent_dir(path)?;
    std::fs::write(path, payload)
}

fn serialize_pretty_json<T: Serialize>(value: &T) -> io::Result<String> {
    serde_json::to_string_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

fn write_scanned_text(path: Option<&Path>, payload: &str, label: &str) -> io::Result<()> {
    let scan = scan_log_jsonl(payload);
    if scan.error_count > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{label} failed secret scan: {} errors, {} warnings",
                scan.error_count, scan.warn_count
            ),
        ));
    }

    if let Some(path) = path {
        write_text_file(path, payload)
    } else {
        print!("{payload}");
        Ok(())
    }
}

fn write_report(report: &E2eReport, output: Option<PathBuf>) -> io::Result<()> {
    let payload = report.to_json_lines();
    write_scanned_text(output.as_deref(), &payload, "generated JSONL log")
}

fn default_output_path(
    explicit: &Option<PathBuf>,
    bundle_dir: Option<&Path>,
    file_name: &str,
) -> Option<PathBuf> {
    explicit
        .clone()
        .or_else(|| bundle_dir.map(|dir| dir.join(file_name)))
}

fn artifact_record_from_payload(
    label: impl Into<String>,
    path: &Path,
    kind: impl Into<String>,
    description: impl Into<String>,
    payload: &str,
) -> E2eArtifactRecord {
    E2eArtifactRecord {
        label: label.into(),
        path: path.display().to_string(),
        kind: kind.into(),
        description: Some(description.into()),
        scan: Some(scan_log_jsonl(payload)),
    }
}

fn build_run_report(
    run_id: &str,
    module: &str,
    report: &E2eReport,
    scenario_id: Option<&str>,
    step_reports: Vec<E2eStepReport>,
    log_artifacts: Vec<E2eArtifactRecord>,
    failure: Option<E2eFailureSummary>,
) -> E2eRunReport {
    let mut run_report = E2eRunReport::new(
        run_id.to_string(),
        report.test_name.clone(),
        module.to_string(),
        report.passed,
        report.duration_ms,
        scan_log_jsonl(&report.to_json_lines()),
    )
    .with_step_reports(step_reports)
    .with_log_artifacts(log_artifacts);
    if let Some(scenario_id) = scenario_id {
        run_report = run_report.with_scenario_id(scenario_id.to_string());
    }
    if let Some(failure) = failure {
        run_report = run_report.with_failure(failure);
    }
    run_report.refresh_human_summary();
    run_report
}

#[fcp_async_core::runtime::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = match parse_args() {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            eprintln!("{}", usage());
            process::exit(2);
        }
    };

    if args.help {
        println!("{}", usage());
        return Ok(());
    }

    if let Some(path) = args.validate_log.as_ref() {
        if let Err(err) = validate_jsonl_file(path) {
            eprintln!("log schema validation failed: {err}");
            process::exit(1);
        }
        println!("log schema OK: {}", path.display());
        return Ok(());
    }

    if let Some(path) = args.scan_log.as_ref() {
        let payload = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read scan log {}: {err}", path.display()))?;
        let source_scan = scan_log_jsonl(&payload);
        let run_id = CorrelationId::new().to_string();
        let passed = source_scan.error_count == 0;
        let mut entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            args.test_name.clone(),
            args.module.clone(),
            "execute",
            run_id.clone(),
            if passed { "pass" } else { "fail" },
            0,
            AssertionsSummary::new(if passed { 1 } else { 0 }, if passed { 0 } else { 1 }),
            serde_json::json!({
                "total_lines": source_scan.total_lines,
                "finding_count": source_scan.findings.len(),
                "error_count": source_scan.error_count,
                "warn_count": source_scan.warn_count,
                "source": path.display().to_string(),
            }),
        )
        .with_run_id(run_id.clone())
        .with_step("scan-log", 1)
        .with_attempt(1)
        .with_command(serde_json::json!({
            "command": "scan-log",
            "args": [path.display().to_string()],
        }))
        .with_scan(serde_json::to_value(&source_scan).unwrap_or(serde_json::Value::Null));
        if let Some(scenario_id) = args.scenario_id.clone() {
            entry = entry.with_scenario_id(scenario_id);
        }
        let mut logger = E2eLogger::new();
        logger.push(entry);
        let log_report = E2eReport {
            test_name: args.test_name.clone(),
            passed,
            duration_ms: 0,
            logs: logger.drain(),
        };
        if let Err(err) = validate_entries(&log_report.logs) {
            eprintln!("log schema validation failed: {err}");
            process::exit(1);
        }
        let bundle_dir = args.bundle_dir.as_deref();
        let output_path = default_output_path(&args.output, bundle_dir, "logs.jsonl");
        let stable_output_path =
            default_output_path(&args.stable_output, bundle_dir, "logs.stable.jsonl");
        let report_json_path = default_output_path(&args.report_json, bundle_dir, "report.json");
        let summary_output_path =
            default_output_path(&args.summary_output, bundle_dir, "summary.txt");
        let scan_report_path = args
            .scan_report
            .clone()
            .or_else(|| bundle_dir.map(|dir| dir.join("scan-report.json")));

        write_report(&log_report, output_path.clone())?;
        if let Some(path) = stable_output_path.as_ref() {
            let payload = log_report.to_stable_json_lines();
            write_scanned_text(Some(path), &payload, "stable JSONL log")?;
        }
        if let Some(path) = scan_report_path.as_ref() {
            write_scan_report(&source_scan, path)?;
        }

        let mut artifacts = vec![E2eArtifactRecord {
            label: "scan-source".to_string(),
            path: path.display().to_string(),
            kind: "jsonl".to_string(),
            description: Some("source payload scanned for secrets".to_string()),
            scan: Some(source_scan.clone()),
        }];
        if let Some(path) = output_path.as_ref() {
            artifacts.push(artifact_record_from_payload(
                "logs-jsonl",
                path,
                "jsonl",
                "generated E2E JSONL log",
                &log_report.to_json_lines(),
            ));
        }
        if let Some(path) = stable_output_path.as_ref() {
            artifacts.push(artifact_record_from_payload(
                "logs-stable-jsonl",
                path,
                "jsonl",
                "stable normalized E2E JSONL log",
                &log_report.to_stable_json_lines(),
            ));
        }
        if let Some(path) = scan_report_path.as_ref() {
            artifacts.push(artifact_record_from_payload(
                "scan-report",
                path,
                "json",
                "scan report for the source payload",
                &serde_json::to_string_pretty(&source_scan).unwrap_or_else(|_| "{}".to_string()),
            ));
        }

        let failure = (!passed).then(|| E2eFailureSummary {
            step_id: Some("scan-log".to_string()),
            reason: format!(
                "source payload produced {} error findings and {} warnings",
                source_scan.error_count, source_scan.warn_count
            ),
            error_code: Some("log_scan_detected_secret".to_string()),
            stderr_excerpt: None,
        });
        let step_reports = vec![E2eStepReport {
            step_id: "scan-log".to_string(),
            step_number: 1,
            phase: "execute".to_string(),
            attempt: 1,
            result: if passed { "pass" } else { "fail" }.to_string(),
            duration_ms: 0,
            command: Some(E2eCommandMetadata {
                command: "scan-log".to_string(),
                args: vec![path.display().to_string()],
                runner_prefix: None,
                working_directory: std::env::current_dir()
                    .ok()
                    .map(|cwd| cwd.display().to_string()),
                env_keys: Vec::new(),
            }),
            stdout_path: output_path
                .as_ref()
                .map(|value| value.display().to_string()),
            stderr_path: None,
            artifacts: scan_report_path
                .as_ref()
                .map(|value| vec![value.display().to_string()])
                .unwrap_or_default(),
            prerequisites: vec![E2ePrerequisiteState {
                name: "scan_input".to_string(),
                status: "satisfied".to_string(),
                detail: Some(path.display().to_string()),
            }],
            failure: failure.clone(),
        }];
        let run_report = build_run_report(
            &run_id,
            &args.module,
            &log_report,
            args.scenario_id.as_deref(),
            step_reports,
            artifacts,
            failure,
        );
        if let Some(path) = summary_output_path.as_ref() {
            write_scanned_text(Some(path), &run_report.human_summary, "human summary")?;
        }
        if let Some(path) = report_json_path.as_ref() {
            let payload = serialize_pretty_json(&run_report)?;
            write_scanned_text(Some(path), &payload, "machine-readable report")?;
        }
        if !passed || run_report.scan.error_count > 0 {
            eprintln!(
                "log scan failed: {} source errors, {} source warnings, {} generated-log errors",
                source_scan.error_count, source_scan.warn_count, run_report.scan.error_count
            );
            process::exit(1);
        }
        return Ok(());
    }

    if args.interop {
        let run_id = CorrelationId::new().to_string();
        let mut runner = E2eRunner::new(args.module.clone());
        let report = runner.run_interop_suite(args.test_name.clone());
        if let Err(err) = validate_entries(&report.logs) {
            eprintln!("log schema validation failed: {err}");
            process::exit(1);
        }
        let bundle_dir = args.bundle_dir.as_deref();
        let output_path = default_output_path(&args.output, bundle_dir, "logs.jsonl");
        let stable_output_path =
            default_output_path(&args.stable_output, bundle_dir, "logs.stable.jsonl");
        let report_json_path = default_output_path(&args.report_json, bundle_dir, "report.json");
        let summary_output_path =
            default_output_path(&args.summary_output, bundle_dir, "summary.txt");

        write_report(&report, output_path.clone())?;
        if let Some(path) = stable_output_path.as_ref() {
            let payload = report.to_stable_json_lines();
            write_scanned_text(Some(path), &payload, "stable JSONL log")?;
        }

        let mut artifacts = Vec::new();
        if let Some(path) = output_path.as_ref() {
            artifacts.push(artifact_record_from_payload(
                "logs-jsonl",
                path,
                "jsonl",
                "interop suite JSONL log",
                &report.to_json_lines(),
            ));
        }
        if let Some(path) = stable_output_path.as_ref() {
            artifacts.push(artifact_record_from_payload(
                "logs-stable-jsonl",
                path,
                "jsonl",
                "stable normalized interop suite JSONL log",
                &report.to_stable_json_lines(),
            ));
        }

        let failure = (!report.passed).then(|| E2eFailureSummary {
            step_id: Some("interop-suite".to_string()),
            reason: "interop suite recorded failing checks".to_string(),
            error_code: Some("interop_suite_failed".to_string()),
            stderr_excerpt: None,
        });
        let step_reports = vec![E2eStepReport {
            step_id: "interop-suite".to_string(),
            step_number: 1,
            phase: "verify".to_string(),
            attempt: 1,
            result: if report.passed { "pass" } else { "fail" }.to_string(),
            duration_ms: report.duration_ms,
            command: Some(E2eCommandMetadata {
                command: "interop".to_string(),
                args: Vec::new(),
                runner_prefix: None,
                working_directory: std::env::current_dir()
                    .ok()
                    .map(|cwd| cwd.display().to_string()),
                env_keys: Vec::new(),
            }),
            stdout_path: output_path
                .as_ref()
                .map(|value| value.display().to_string()),
            stderr_path: None,
            artifacts: Vec::new(),
            prerequisites: Vec::new(),
            failure: failure.clone(),
        }];
        let run_report = build_run_report(
            &run_id,
            &args.module,
            &report,
            args.scenario_id.as_deref(),
            step_reports,
            artifacts,
            failure,
        );
        if let Some(path) = summary_output_path.as_ref() {
            write_scanned_text(Some(path), &run_report.human_summary, "human summary")?;
        }
        if let Some(path) = report_json_path.as_ref() {
            let payload = serialize_pretty_json(&run_report)?;
            write_scanned_text(Some(path), &payload, "machine-readable report")?;
        }
        if run_report.scan.error_count > 0 {
            eprintln!(
                "generated interop log failed secret scan: {} errors, {} warnings",
                run_report.scan.error_count, run_report.scan.warn_count
            );
            process::exit(1);
        }
        return Ok(());
    }

    let connector_cmd = match args.connector_cmd {
        Some(cmd) => cmd,
        None => {
            eprintln!("No connector command provided.");
            eprintln!("{}", usage());
            process::exit(2);
        }
    };

    let bundle_dir = args.bundle_dir.clone();
    if let Some(dir) = bundle_dir.as_ref() {
        std::fs::create_dir_all(dir)?;
    }
    let output_path = default_output_path(&args.output, bundle_dir.as_deref(), "logs.jsonl");
    let stable_output_path = default_output_path(
        &args.stable_output,
        bundle_dir.as_deref(),
        "logs.stable.jsonl",
    );
    let report_json_path =
        default_output_path(&args.report_json, bundle_dir.as_deref(), "report.json");
    let summary_output_path =
        default_output_path(&args.summary_output, bundle_dir.as_deref(), "summary.txt");

    let arg_refs: Vec<&str> = args.connector_args.iter().map(String::as_str).collect();
    let mut runner = ConnectorProcessRunner::spawn(&connector_cmd, &arg_refs, &[]).await?;
    let command_metadata = runner.command_metadata();

    let mut logger = E2eLogger::new();
    let run_id = CorrelationId::new().to_string();
    let start = std::time::Instant::now();
    let mut passed = true;
    let mut assertions_passed = 0_u32;
    let mut assertions_failed = 0_u32;
    let mut step_reports = Vec::new();
    let mut artifacts = Vec::new();

    for (index, request) in args.requests.iter().enumerate() {
        let step_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let step_id = format!("ipc-request-{step_number:03}");
        let request_path = bundle_dir
            .as_ref()
            .map(|dir| dir.join(format!("{step_id}-request.json")));
        let response_path = bundle_dir
            .as_ref()
            .map(|dir| dir.join(format!("{step_id}-response.json")));
        let stdout_path = bundle_dir
            .as_ref()
            .map(|dir| dir.join(format!("{step_id}-stdout.txt")));
        let stderr_path = bundle_dir
            .as_ref()
            .map(|dir| dir.join(format!("{step_id}-stderr.txt")));
        if let Some(path) = request_path.as_ref() {
            write_pretty_json(path, request)?;
        }
        let request_start = std::time::Instant::now();
        let response = runner.request(request).await;
        let duration_ms = request_start.elapsed().as_millis() as u64;
        let stdout_lines = runner.drain_stdout_lines().await;
        let stderr_lines = runner.drain_stderr_lines().await;
        if let Some(path) = stdout_path.as_ref() {
            if !stdout_lines.is_empty() {
                write_text_file(path, &stdout_lines.join("\n"))?;
            }
        }
        if let Some(path) = stderr_path.as_ref() {
            if !stderr_lines.is_empty() {
                write_text_file(path, &stderr_lines.join("\n"))?;
            }
        }

        let mut step_artifacts = Vec::new();
        if let Some(path) = request_path.as_ref() {
            step_artifacts.push(path.display().to_string());
            artifacts.push(artifact_record_from_payload(
                format!("{step_id}-request-json"),
                path,
                "json",
                format!("request payload for {step_id}"),
                &serialize_pretty_json(request)?,
            ));
        }
        if let Some(path) = stdout_path.as_ref() {
            if !stdout_lines.is_empty() {
                step_artifacts.push(path.display().to_string());
                artifacts.push(artifact_record_from_payload(
                    format!("{step_id}-stdout-txt"),
                    path,
                    "text",
                    format!("raw stdout captured for {step_id}"),
                    &stdout_lines.join("\n"),
                ));
            }
        }
        if let Some(path) = stderr_path.as_ref() {
            if !stderr_lines.is_empty() {
                step_artifacts.push(path.display().to_string());
                artifacts.push(artifact_record_from_payload(
                    format!("{step_id}-stderr-txt"),
                    path,
                    "text",
                    format!("stderr captured for {step_id}"),
                    &stderr_lines.join("\n"),
                ));
            }
        }

        let (level, result, context, failure, stdout_path) = match response {
            Ok(response) => {
                assertions_passed += 1;
                if let Some(path) = response_path.as_ref() {
                    write_pretty_json(path, &response)?;
                    step_artifacts.push(path.display().to_string());
                    artifacts.push(artifact_record_from_payload(
                        format!("{step_id}-response-json"),
                        path,
                        "json",
                        format!("parsed response payload for {step_id}"),
                        &serialize_pretty_json(&response)?,
                    ));
                }
                (
                    "info",
                    "pass",
                    serde_json::json!({
                        "operation": "ipc_request",
                        "request_index": index,
                        "request": request,
                        "response": response,
                    }),
                    None,
                    response_path
                        .as_ref()
                        .and_then(|_| stdout_path.as_ref())
                        .and_then(|path| {
                            if step_artifacts
                                .iter()
                                .any(|artifact| artifact == &path.display().to_string())
                            {
                                Some(path.display().to_string())
                            } else {
                                None
                            }
                        }),
                )
            }
            Err(err) => {
                assertions_failed += 1;
                passed = false;
                (
                    "error",
                    "fail",
                    serde_json::json!({
                        "operation": "ipc_request",
                        "request_index": index,
                        "request": request,
                        "error": err.to_string(),
                    }),
                    Some(E2eFailureSummary {
                        step_id: Some(step_id.clone()),
                        reason: err.to_string(),
                        error_code: Some("connector_request_failed".to_string()),
                        stderr_excerpt: stderr_lines.first().cloned(),
                    }),
                    None,
                )
            }
        };

        let mut entry = E2eLogEntry::new(
            level,
            args.test_name.clone(),
            args.module.clone(),
            "execute",
            run_id.clone(),
            result,
            duration_ms,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            context,
        )
        .with_run_id(run_id.clone())
        .with_step(step_id.clone(), step_number)
        .with_attempt(1)
        .with_command(serde_json::to_value(&command_metadata).unwrap_or(serde_json::Value::Null))
        .with_prerequisites(serde_json::json!([
            {
                "name": "connector_process",
                "status": "spawned",
                "detail": connector_cmd.clone(),
            }
        ]))
        .with_artifacts(step_artifacts.clone())
        .with_details(serde_json::json!({
            "request_index": index,
            "request_file_count": args.request_files.len(),
            "stdout_line_count": stdout_lines.len(),
            "stderr_line_count": stderr_lines.len(),
            "stdout_path": stdout_path,
            "stderr_path": stderr_path.as_ref().map(|path| path.display().to_string()),
        }));
        if let Some(scenario_id) = args.scenario_id.clone() {
            entry = entry.with_scenario_id(scenario_id);
        }
        if let Some(failure) = failure.as_ref() {
            entry = entry
                .with_error_code(
                    failure
                        .error_code
                        .clone()
                        .unwrap_or_else(|| "connector_request_failed".to_string()),
                )
                .with_failure_summary(
                    serde_json::to_value(failure).unwrap_or(serde_json::Value::Null),
                );
        }
        logger.push(entry);

        for line in stderr_lines {
            let mut entry = E2eLogEntry::new(
                "warn",
                args.test_name.clone(),
                args.module.clone(),
                "observe",
                run_id.clone(),
                "pass",
                0,
                AssertionsSummary::new(assertions_passed, assertions_failed),
                serde_json::json!({
                    "operation": "stderr",
                    "line": line,
                }),
            )
            .with_run_id(run_id.clone())
            .with_step(step_id.clone(), step_number)
            .with_attempt(1);
            if let Some(scenario_id) = args.scenario_id.clone() {
                entry = entry.with_scenario_id(scenario_id);
            }
            logger.push(entry);
        }

        step_reports.push(E2eStepReport {
            step_id: step_id.clone(),
            step_number,
            phase: "execute".to_string(),
            attempt: 1,
            result: result.to_string(),
            duration_ms,
            command: Some(command_metadata.clone()),
            stdout_path,
            stderr_path: stderr_path
                .as_ref()
                .filter(|_| !step_artifacts.is_empty())
                .and_then(|path| {
                    if step_artifacts
                        .iter()
                        .any(|artifact| artifact == &path.display().to_string())
                    {
                        Some(path.display().to_string())
                    } else {
                        None
                    }
                }),
            artifacts: step_artifacts,
            prerequisites: vec![E2ePrerequisiteState {
                name: "connector_process".to_string(),
                status: "spawned".to_string(),
                detail: Some(connector_cmd.clone()),
            }],
            failure,
        });
    }

    let replay_path = bundle_dir.as_ref().map(|dir| dir.join("replay.sh"));
    if let Some(path) = replay_path.as_ref() {
        runner.write_replay_script(path)?;
        artifacts.push(artifact_record_from_payload(
            "replay-sh",
            path,
            "replay",
            "deterministic replay script for the connector subprocess boundary",
            &runner.replay_script(),
        ));
    }

    let exit_status_payload = runner
        .terminate_and_capture_exit_status(std::time::Duration::from_millis(250))
        .await?;
    let exit_status_path = bundle_dir.as_ref().map(|dir| dir.join("exit-status.json"));
    if let Some(path) = exit_status_path.as_ref() {
        let payload = serialize_pretty_json(&exit_status_payload)?;
        write_scanned_text(Some(path), &payload, "connector subprocess exit status")?;
        artifacts.push(artifact_record_from_payload(
            "exit-status-json",
            path,
            "json",
            "captured connector subprocess exit status after teardown",
            &payload,
        ));
    }

    let stderr_lines = runner.drain_stderr_lines().await;
    for line in stderr_lines {
        let mut entry = E2eLogEntry::new(
            "warn",
            args.test_name.clone(),
            args.module.clone(),
            "observe",
            run_id.clone(),
            "pass",
            0,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({
                "operation": "stderr",
                "line": line,
            }),
        )
        .with_run_id(run_id.clone())
        .with_step(
            "teardown-stderr",
            u32::try_from(args.requests.len() + 1).unwrap_or(u32::MAX),
        )
        .with_attempt(1);
        if let Some(scenario_id) = args.scenario_id.clone() {
            entry = entry.with_scenario_id(scenario_id);
        }
        logger.push(entry);
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut summary_entry = E2eLogEntry::new(
        "info",
        args.test_name.clone(),
        args.module.clone(),
        "teardown",
        run_id.clone(),
        if passed { "pass" } else { "fail" },
        duration_ms,
        AssertionsSummary::new(assertions_passed, assertions_failed),
        serde_json::json!({
            "connector_cmd": connector_cmd.clone(),
            "connector_args": args.connector_args.clone(),
            "request_files": args
                .request_files
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>(),
            "request_count": args.requests.len(),
        }),
    )
    .with_run_id(run_id.clone())
    .with_step(
        "run-summary",
        u32::try_from(args.requests.len() + 1).unwrap_or(u32::MAX),
    )
    .with_summary(serde_json::json!({
        "request_count": args.requests.len(),
        "assertions_passed": assertions_passed,
        "assertions_failed": assertions_failed,
        "request_files": args
            .request_files
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>(),
    }));
    if let Some(scenario_id) = args.scenario_id.clone() {
        summary_entry = summary_entry.with_scenario_id(scenario_id);
    }
    logger.push(summary_entry);

    let report = E2eReport {
        test_name: args.test_name.clone(),
        passed,
        duration_ms,
        logs: logger.drain(),
    };
    if let Err(err) = validate_entries(&report.logs) {
        eprintln!("log schema validation failed: {err}");
        process::exit(1);
    }
    write_report(&report, output_path.clone())?;
    if let Some(path) = stable_output_path.as_ref() {
        let payload = report.to_stable_json_lines();
        write_scanned_text(Some(path), &payload, "stable JSONL log")?;
    }

    if let Some(path) = output_path.as_ref() {
        artifacts.push(artifact_record_from_payload(
            "logs-jsonl",
            path,
            "jsonl",
            "connector mode JSONL log",
            &report.to_json_lines(),
        ));
    }
    if let Some(path) = stable_output_path.as_ref() {
        artifacts.push(artifact_record_from_payload(
            "logs-stable-jsonl",
            path,
            "jsonl",
            "stable normalized connector mode JSONL log",
            &report.to_stable_json_lines(),
        ));
    }
    let failure = (!passed).then(|| E2eFailureSummary {
        step_id: step_reports
            .iter()
            .find(|step| step.result == "fail")
            .map(|step| step.step_id.clone()),
        reason: "one or more connector requests failed".to_string(),
        error_code: Some("connector_run_failed".to_string()),
        stderr_excerpt: step_reports.iter().find_map(|step| {
            step.failure
                .as_ref()
                .and_then(|failure| failure.stderr_excerpt.clone())
        }),
    });
    let mut run_report = build_run_report(
        &run_id,
        &args.module,
        &report,
        args.scenario_id.as_deref(),
        step_reports,
        artifacts,
        failure,
    );
    if let Some(path) = summary_output_path.as_ref() {
        run_report.log_artifacts.push(E2eArtifactRecord {
            label: "summary-txt".to_string(),
            path: path.display().to_string(),
            kind: "text".to_string(),
            description: Some("human-readable connector mode summary".to_string()),
            scan: None,
        });
    }
    if let Some(path) = report_json_path.as_ref() {
        run_report.log_artifacts.push(E2eArtifactRecord {
            label: "report-json".to_string(),
            path: path.display().to_string(),
            kind: "json".to_string(),
            description: Some("machine-readable connector mode run report".to_string()),
            scan: None,
        });
    }
    run_report.refresh_human_summary();
    if let Some(path) = summary_output_path.as_ref() {
        write_scanned_text(Some(path), &run_report.human_summary, "human summary")?;
    }
    if let Some(path) = report_json_path.as_ref() {
        let payload = serialize_pretty_json(&run_report)?;
        write_scanned_text(Some(path), &payload, "machine-readable report")?;
    }
    if run_report.scan.error_count > 0 {
        eprintln!(
            "generated connector log failed secret scan: {} errors, {} warnings",
            run_report.scan.error_count, run_report.scan.warn_count
        );
        process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{load_requests_from_file, parse_request_payload, write_scanned_text};
    use fcp_e2e::{AssertionsSummary, E2eLogEntry, E2eReport};

    #[test]
    fn parse_request_payload_accepts_single_object() {
        let requests = parse_request_payload(
            r#"{"jsonrpc":"2.0","id":"1","method":"health","params":{}}"#,
            "inline",
        )
        .expect("single object should parse");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "health");
    }

    #[test]
    fn parse_request_payload_accepts_array_of_objects() {
        let requests = parse_request_payload(
            r#"[{"jsonrpc":"2.0","id":"1","method":"health","params":{}},{"jsonrpc":"2.0","id":"2","method":"introspect","params":{}}]"#,
            "inline",
        )
        .expect("array should parse");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["method"], "introspect");
    }

    #[test]
    fn parse_request_payload_rejects_non_object_entries() {
        let err = parse_request_payload(r#"[{"jsonrpc":"2.0"},42]"#, "inline")
            .expect_err("non-object entries should fail");
        assert!(err.contains("entry 2"));
    }

    #[test]
    fn load_requests_from_file_supports_arrays() {
        let unique = format!(
            "fcp-e2e-request-file-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::write(
            &path,
            r#"[{"jsonrpc":"2.0","id":"1","method":"health","params":{}},{"jsonrpc":"2.0","id":"2","method":"introspect","params":{}}]"#,
        )
        .expect("temp request file write");

        let requests = load_requests_from_file(&path).expect("request file should parse");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["method"], "health");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn write_scanned_text_rejects_secret_payload_before_writing() {
        let unique = format!(
            "fcp-e2e-secret-scan-{}-{}.txt",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let path = std::env::temp_dir().join(unique);

        let error = write_scanned_text(
            Some(&path),
            "token=sk-abc123def456ghi789jkl012mno345pqr",
            "human summary",
        )
        .expect_err("secret-bearing payload should be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!path.exists(), "dirty payload must not be written");
    }

    #[test]
    fn write_report_rejects_secret_log_before_writing() {
        let unique = format!(
            "fcp-e2e-secret-report-{}-{}.jsonl",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let path = std::env::temp_dir().join(unique);
        let report = E2eReport {
            test_name: "sk-abc123def456ghi789jkl012mno345pqr".to_string(),
            passed: false,
            duration_ms: 1,
            logs: vec![E2eLogEntry::new(
                "error",
                "sk-abc123def456ghi789jkl012mno345pqr",
                "fcp-e2e",
                "execute",
                "run-1",
                "fail",
                0,
                AssertionsSummary::new(0, 1),
                serde_json::json!({ "status": "failed" }),
            )],
        };

        let error = super::write_report(&report, Some(path.clone()))
            .expect_err("secret-bearing logs should be rejected before persistence");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!path.exists(), "dirty logs must not be written");
    }
}
