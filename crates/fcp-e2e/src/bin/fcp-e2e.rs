//! Minimal CLI for fcp-e2e JSONL output.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::{env, process};

use fcp_core::CorrelationId;
use fcp_e2e::{
    AssertionsSummary, ConnectorProcessRunner, E2eLogEntry, E2eLogger, E2eReport, E2eRunner,
    LogScanReport, scan_log_jsonl, validate_log_entry_value,
};

#[derive(Debug, Default)]
struct CliArgs {
    interop: bool,
    validate_log: Option<PathBuf>,
    scan_log: Option<PathBuf>,
    scan_report: Option<PathBuf>,
    output: Option<PathBuf>,
    module: String,
    test_name: String,
    connector_cmd: Option<String>,
    connector_args: Vec<String>,
    requests: Vec<serde_json::Value>,
    help: bool,
}

fn usage() -> &'static str {
    "Usage:
  fcp-e2e --interop [--output <file>] [--test-name <name>] [--module <name>]
  fcp-e2e --validate-log <file>
  fcp-e2e --scan-log <file> --output <jsonl> --scan-report <report.json> [--test-name <name>] [--module <name>]
  fcp-e2e --connector-cmd <path> --request <json> [--request <json> ...] \\
         [--connector-arg <arg> ...] [--output <file>] [--test-name <name>] [--module <name>]
"
}

fn parse_args() -> Result<CliArgs, String> {
    let mut args = env::args().skip(1);
    let mut parsed = CliArgs {
        interop: false,
        validate_log: None,
        scan_log: None,
        scan_report: None,
        output: None,
        module: "fcp-e2e".to_string(),
        test_name: "fcp-e2e".to_string(),
        connector_cmd: None,
        connector_args: Vec::new(),
        requests: Vec::new(),
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
                let json = serde_json::from_str(&value)
                    .map_err(|err| format!("--request JSON invalid: {err}"))?;
                parsed.requests.push(json);
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

    if parsed.connector_cmd.is_some() && parsed.requests.is_empty() {
        return Err("At least one --request is required for connector mode".to_string());
    }

    if parsed.scan_log.is_some() && parsed.output.is_none() {
        return Err("--scan-log requires --output to persist JSONL logs".to_string());
    }

    if parsed.scan_log.is_some() && parsed.scan_report.is_none() {
        return Err("--scan-log requires --scan-report to persist JSON report".to_string());
    }

    Ok(parsed)
}

fn write_report(report: &E2eReport, output: Option<PathBuf>) -> io::Result<()> {
    if let Some(path) = output {
        report.write_json_lines(path)
    } else {
        println!("{}", report.to_json_lines());
        Ok(())
    }
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
    let file = File::create(output)?;
    serde_json::to_writer_pretty(file, report)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
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
        let report = scan_log_jsonl(&payload);
        let correlation_id = CorrelationId::new().to_string();
        let passed = report.error_count == 0;
        let entry = E2eLogEntry::new(
            if passed { "info" } else { "error" },
            args.test_name.clone(),
            args.module.clone(),
            "execute",
            correlation_id,
            if passed { "pass" } else { "fail" },
            0,
            AssertionsSummary::new(if passed { 1 } else { 0 }, if passed { 0 } else { 1 }),
            serde_json::json!({
                "total_lines": report.total_lines,
                "finding_count": report.findings.len(),
                "error_count": report.error_count,
                "warn_count": report.warn_count,
                "source": path.display().to_string(),
            }),
        );
        let mut logger = E2eLogger::new();
        logger.push(entry);
        let log_report = E2eReport {
            test_name: args.test_name,
            passed,
            duration_ms: 0,
            logs: logger.drain(),
        };
        if let Err(err) = validate_entries(&log_report.logs) {
            eprintln!("log schema validation failed: {err}");
            process::exit(1);
        }
        write_report(&log_report, args.output)?;
        if let Some(report_path) = args.scan_report.as_ref() {
            write_scan_report(&report, report_path)?;
        }
        if !passed {
            eprintln!(
                "log scan failed: {} error findings, {} warnings",
                report.error_count, report.warn_count
            );
            process::exit(1);
        }
        return Ok(());
    }

    if args.interop {
        let mut runner = E2eRunner::new(args.module);
        let report = runner.run_interop_suite(args.test_name);
        if let Err(err) = validate_entries(&report.logs) {
            eprintln!("log schema validation failed: {err}");
            process::exit(1);
        }
        write_report(&report, args.output)?;
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

    let arg_refs: Vec<&str> = args.connector_args.iter().map(String::as_str).collect();
    let mut runner = ConnectorProcessRunner::spawn(&connector_cmd, &arg_refs, &[]).await?;

    let mut logger = E2eLogger::new();
    let correlation_id = CorrelationId::new().to_string();
    let start = std::time::Instant::now();
    let mut passed = true;
    let mut assertions_passed = 0_u32;
    let mut assertions_failed = 0_u32;

    for (index, request) in args.requests.iter().enumerate() {
        let request_start = std::time::Instant::now();
        let response = runner.request(request).await;
        let duration_ms = request_start.elapsed().as_millis() as u64;

        let (level, result, context) = match response {
            Ok(response) => {
                assertions_passed += 1;
                (
                    "info",
                    "pass",
                    serde_json::json!({
                        "operation": "ipc_request",
                        "request_index": index,
                        "request": request,
                        "response": response,
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
                )
            }
        };

        let entry = E2eLogEntry::new(
            level,
            args.test_name.clone(),
            args.module.clone(),
            "execute",
            correlation_id.clone(),
            result,
            duration_ms,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            context,
        );
        logger.push(entry);

        let stderr_lines = runner.drain_stderr_lines().await;
        for line in stderr_lines {
            let entry = E2eLogEntry::new(
                "warn",
                args.test_name.clone(),
                args.module.clone(),
                "observe",
                correlation_id.clone(),
                "pass",
                0,
                AssertionsSummary::new(assertions_passed, assertions_failed),
                serde_json::json!({
                    "operation": "stderr",
                    "line": line,
                }),
            );
            logger.push(entry);
        }
    }

    runner.terminate().await?;
    let stderr_lines = runner.drain_stderr_lines().await;
    for line in stderr_lines {
        let entry = E2eLogEntry::new(
            "warn",
            args.test_name.clone(),
            args.module.clone(),
            "observe",
            correlation_id.clone(),
            "pass",
            0,
            AssertionsSummary::new(assertions_passed, assertions_failed),
            serde_json::json!({
                "operation": "stderr",
                "line": line,
            }),
        );
        logger.push(entry);
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let summary_entry = E2eLogEntry::new(
        "info",
        args.test_name.clone(),
        args.module.clone(),
        "teardown",
        correlation_id,
        if passed { "pass" } else { "fail" },
        duration_ms,
        AssertionsSummary::new(assertions_passed, assertions_failed),
        serde_json::json!({
            "connector_cmd": connector_cmd,
            "connector_args": args.connector_args,
            "request_count": args.requests.len(),
        }),
    );
    logger.push(summary_entry);

    let report = E2eReport {
        test_name: args.test_name,
        passed,
        duration_ms,
        logs: logger.drain(),
    };
    if let Err(err) = validate_entries(&report.logs) {
        eprintln!("log schema validation failed: {err}");
        process::exit(1);
    }
    write_report(&report, args.output)?;
    Ok(())
}
