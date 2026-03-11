//! `fcp audit` command implementation.
//!
//! Provides audit chain operations for incident response and debugging.
//!
//! # Commands
//!
//! ## `fcp audit tail`
//!
//! Stream audit events from a zone's audit chain with optional filtering.
//!
//! ```text
//! # Tail all events in a zone
//! fcp audit tail --zone z:work
//!
//! # Filter by connector
//! fcp audit tail --zone z:work --connector fcp.telegram:base:v1
//!
//! # Filter by correlation ID for incident investigation
//! fcp audit tail --zone z:work --correlation abc123...
//!
//! # JSON output for piping to jq/tools
//! fcp audit tail --zone z:work --json
//! ```

pub mod types;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Args, Subcommand};
use fcp_core::{AuditEvent, AuditHead, ObjectId, ZoneId};
use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use types::{AuditEventOutput, AuditFilter, AuditTailError};

/// Arguments for the `fcp audit` command.
#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

/// Audit subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum AuditCommands {
    /// Tail audit events from a zone's audit chain.
    ///
    /// Streams audit events in order (by seq) with optional filtering.
    /// Useful for incident response and debugging.
    Tail(TailArgs),
    /// Verify integrity of an audit chain and head.
    Verify(VerifyArgs),
    /// Render a timeline of audit events.
    Timeline(TimelineArgs),
}

/// Arguments for the `fcp audit tail` command.
#[derive(Args, Debug, Clone)]
pub struct TailArgs {
    /// Zone to tail audit events from.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Filter by connector ID.
    #[arg(long, short = 'c')]
    pub connector: Option<String>,

    /// Filter by operation ID.
    #[arg(long, short = 'o')]
    pub operation: Option<String>,

    /// Filter by correlation ID (hex, 32 chars).
    #[arg(long)]
    pub correlation: Option<String>,

    /// Filter by trace ID (hex, 32 chars).
    #[arg(long)]
    pub trace: Option<String>,

    /// Filter by event type (e.g., "capability.invoke", "secret.access").
    #[arg(long, short = 'e')]
    pub event_type: Option<String>,

    /// Filter by actor (e.g., "user:alice").
    #[arg(long, short = 'a')]
    pub actor: Option<String>,

    /// Number of events to show (0 = stream indefinitely until interrupted).
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,

    /// Starting sequence number (default: latest minus limit).
    #[arg(long)]
    pub since: Option<u64>,

    /// Follow mode: continue streaming new events (like tail -f).
    #[arg(long, short = 'f', default_value_t = false)]
    pub follow: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for the `fcp audit verify` command.
#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Zone to verify (optional; ensures all events match this zone).
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Audit event records input (JSONL or JSON array). Use "-" for stdin.
    #[arg(long)]
    pub events: PathBuf,

    /// Audit head input (JSON). Use "-" for stdin.
    #[arg(long)]
    pub head: Option<PathBuf>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for the `fcp audit timeline` command.
#[derive(Args, Debug, Clone)]
pub struct TimelineArgs {
    /// Zone to render (optional; filters events by zone).
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Audit event records input (JSONL or JSON array). Use "-" for stdin.
    #[arg(long)]
    pub events: PathBuf,

    /// Number of events to include (0 = all).
    #[arg(long, short = 'n', default_value_t = 100)]
    pub limit: usize,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the audit command.
///
/// # Errors
///
/// Returns an error if the audit operation fails.
pub fn run(args: AuditArgs) -> Result<()> {
    match args.command {
        AuditCommands::Tail(tail_args) => run_tail(&tail_args),
        AuditCommands::Verify(verify_args) => run_verify(&verify_args),
        AuditCommands::Timeline(timeline_args) => run_timeline(&timeline_args),
    }
}

/// Run the audit tail command.
fn run_tail(args: &TailArgs) -> Result<()> {
    let filter = AuditFilter {
        connector_id: args.connector.clone(),
        operation_id: args.operation.clone(),
        correlation_id: args.correlation.clone(),
        trace_id: args.trace.clone(),
        event_type: args.event_type.clone(),
        actor: args.actor.clone(),
    };
    let filter_hint = if filter.is_empty() {
        None
    } else {
        Some(format!(
            "Requested filters: connector={:?}, operation={:?}, correlation={:?}, trace={:?}, event_type={:?}, actor={:?}",
            filter.connector_id,
            filter.operation_id,
            filter.correlation_id,
            filter.trace_id,
            filter.event_type,
            filter.actor
        ))
    };

    if args.json {
        let error = AuditTailError {
            code: "audit.tail.not_implemented".to_string(),
            message: format!(
                "Live audit tailing for zone '{}' requires a host-backed audit stream. `fwc` will not fabricate audit events.",
                args.zone
            ),
            hints: filter_hint.into_iter().collect(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&error).context("failed to serialize audit tail error")?
        );
        std::process::exit(2);
    }

    eprintln!(
        "Audit tail for zone '{}' is not implemented without a live host-backed audit stream.",
        args.zone
    );
    if let Some(hint) = filter_hint {
        eprintln!("{hint}");
    }
    std::process::exit(2);
}

// ============================================================================
// Audit Verify + Timeline
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEventRecord {
    object_id: ObjectId,
    event: AuditEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuditVerifyStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditVerifyIssue {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditVerifyReport {
    status: AuditVerifyStatus,
    zone_id: Option<String>,
    chain_len: usize,
    head_seq: Option<u64>,
    head_event: Option<String>,
    issues: Vec<AuditVerifyIssue>,
}

fn run_verify(args: &VerifyArgs) -> Result<()> {
    let zone_filter = match args.zone.as_deref() {
        Some(zone) => Some(zone.parse::<ZoneId>().context("invalid zone id")?),
        None => None,
    };

    let events_input = read_input(&args.events)?;
    let mut records = parse_event_records(&events_input)?;
    if records.is_empty() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Warn,
            zone_id: args.zone.clone(),
            chain_len: 0,
            head_seq: None,
            head_event: None,
            issues: vec![AuditVerifyIssue {
                code: "audit.chain.empty".to_string(),
                message: "no audit events provided".to_string(),
                seq: None,
                object_id: None,
            }],
        };
        return output_verify_report(&report, args.json);
    }

    // Sort by seq for deterministic verification.
    records.sort_by(|a, b| {
        a.event
            .seq
            .cmp(&b.event.seq)
            .then_with(|| a.object_id.to_string().cmp(&b.object_id.to_string()))
    });

    let head = if let Some(ref path) = args.head {
        let head_input = read_input(path)?;
        Some(parse_audit_head(&head_input)?)
    } else {
        None
    };

    let report = verify_chain(&records, head.as_ref(), zone_filter.as_ref());
    output_verify_report(&report, args.json)
}

fn run_timeline(args: &TimelineArgs) -> Result<()> {
    let zone_filter = match args.zone.as_deref() {
        Some(zone) => Some(zone.parse::<ZoneId>().context("invalid zone id")?),
        None => None,
    };

    let events_input = read_input(&args.events)?;
    let mut records = parse_event_records(&events_input)?;
    if let Some(ref zone) = zone_filter {
        records.retain(|rec| rec.event.zone_id() == zone);
    }

    records.sort_by_key(|a| a.event.seq);

    if args.limit > 0 && records.len() > args.limit {
        let start = records.len().saturating_sub(args.limit);
        records = records.split_off(start);
    }

    let outputs: Vec<AuditEventOutput> = records.iter().map(to_event_output).collect();
    if args.json {
        output_json(&outputs)?;
    } else {
        let zone_label = zone_filter
            .as_ref()
            .map_or_else(|| "all-zones".to_string(), ToString::to_string);
        output_human(&outputs, &zone_label, &AuditFilter::default());
    }

    Ok(())
}

fn read_input(path: &Path) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read stdin")?;
        return Ok(buf);
    }

    fs::read_to_string(path).with_context(|| format!("failed to read input {}", path.display()))
}

fn parse_event_records(input: &str) -> Result<Vec<AuditEventRecord>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).context("failed to parse audit event array");
    }

    let mut records = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: AuditEventRecord = serde_json::from_str(line)
            .with_context(|| format!("failed to parse audit event record on line {}", idx + 1))?;
        records.push(record);
    }

    Ok(records)
}

fn parse_audit_head(input: &str) -> Result<AuditHead> {
    let trimmed = input.trim();
    if trimmed.starts_with('[') {
        anyhow::bail!("audit head input must be a single JSON object, not an array");
    }
    serde_json::from_str(trimmed).context("failed to parse audit head")
}

#[allow(clippy::too_many_lines)]
fn verify_chain(
    records: &[AuditEventRecord],
    head: Option<&AuditHead>,
    zone: Option<&ZoneId>,
) -> AuditVerifyReport {
    let mut issues = Vec::new();
    let mut seen_seq = std::collections::HashMap::new();

    for record in records {
        if let Some(zone) = zone {
            if record.event.zone_id() != zone {
                issues.push(AuditVerifyIssue {
                    code: "audit.zone_mismatch".to_string(),
                    message: format!(
                        "event zone {} does not match requested zone {}",
                        record.event.zone_id(),
                        zone
                    ),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }
        }

        if let Some(prev) = seen_seq.insert(record.event.seq, record.object_id) {
            if prev != record.object_id {
                issues.push(AuditVerifyIssue {
                    code: "audit.fork_detected".to_string(),
                    message: "multiple events share the same seq with different ids".to_string(),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }
        }
    }

    let mut iter = records.iter();
    if let Some(first) = iter.next() {
        if first.event.seq != 0 || first.event.prev.is_some() {
            issues.push(AuditVerifyIssue {
                code: "audit.genesis_invalid".to_string(),
                message: "genesis event must have seq 0 and no prev".to_string(),
                seq: Some(first.event.seq),
                object_id: Some(first.object_id.to_string()),
            });
        }

        let mut prev = first;
        for record in iter {
            let expected_seq = prev.event.seq.saturating_add(1);
            if record.event.seq != expected_seq {
                issues.push(AuditVerifyIssue {
                    code: "audit.seq_gap".to_string(),
                    message: format!("expected seq {}, found {}", expected_seq, record.event.seq),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }

            if record.event.prev.as_ref() != Some(&prev.object_id) {
                issues.push(AuditVerifyIssue {
                    code: "audit.prev_mismatch".to_string(),
                    message: "prev pointer does not match previous event id".to_string(),
                    seq: Some(record.event.seq),
                    object_id: Some(record.object_id.to_string()),
                });
            }

            prev = record;
        }
    }

    if let Some(head) = head {
        if let Some(last) = records.last() {
            if head.head_event != last.object_id {
                issues.push(AuditVerifyIssue {
                    code: "audit.head_mismatch".to_string(),
                    message: "audit head does not reference chain tip".to_string(),
                    seq: Some(last.event.seq),
                    object_id: Some(last.object_id.to_string()),
                });
            }
            if head.head_seq != last.event.seq {
                issues.push(AuditVerifyIssue {
                    code: "audit.head_seq_mismatch".to_string(),
                    message: "audit head seq does not match chain tip".to_string(),
                    seq: Some(last.event.seq),
                    object_id: Some(last.object_id.to_string()),
                });
            }
        }

        if let Some(zone) = zone {
            if head.zone_id() != zone {
                issues.push(AuditVerifyIssue {
                    code: "audit.head_zone_mismatch".to_string(),
                    message: format!("audit head zone {} does not match {}", head.zone_id(), zone),
                    seq: Some(head.head_seq),
                    object_id: Some(head.head_event.to_string()),
                });
            }
        }
    }

    let is_fail = issues.iter().any(|issue| {
        matches!(
            issue.code.as_str(),
            "audit.fork_detected"
                | "audit.prev_mismatch"
                | "audit.seq_gap"
                | "audit.genesis_invalid"
                | "audit.head_mismatch"
                | "audit.head_seq_mismatch"
        )
    });

    let status = if issues.is_empty() {
        AuditVerifyStatus::Ok
    } else if is_fail {
        AuditVerifyStatus::Fail
    } else {
        AuditVerifyStatus::Warn
    };

    AuditVerifyReport {
        status,
        zone_id: zone.map(ToString::to_string),
        chain_len: records.len(),
        head_seq: head.map(|h| h.head_seq),
        head_event: head.map(|h| h.head_event.to_string()),
        issues,
    }
}

fn output_verify_report(report: &AuditVerifyReport, json: bool) -> Result<()> {
    if json {
        let payload =
            serde_json::to_string_pretty(report).context("failed to serialize verify report")?;
        println!("{payload}");
        return Ok(());
    }

    println!();
    println!("Audit Verify Status: {:?}", report.status);
    if let Some(ref zone) = report.zone_id {
        println!("Zone: {zone}");
    }
    println!("Chain length: {}", report.chain_len);
    if let Some(seq) = report.head_seq {
        println!("Head seq: {seq}");
    }
    if let Some(ref head) = report.head_event {
        println!("Head event: {head}");
    }

    if report.issues.is_empty() {
        println!("Issues: none");
        return Ok(());
    }

    println!();
    println!("Issues:");
    for issue in &report.issues {
        println!("  - {}: {}", issue.code, issue.message);
        if let Some(seq) = issue.seq {
            println!("    seq: {seq}");
        }
        if let Some(ref id) = issue.object_id {
            println!("    id: {id}");
        }
    }

    Ok(())
}

fn to_event_output(record: &AuditEventRecord) -> AuditEventOutput {
    let event = &record.event;
    let trace_id = event
        .trace_context
        .as_ref()
        .map(|trace| hex_encode(trace.trace_id));
    let span_id = event
        .trace_context
        .as_ref()
        .map(|trace| hex_encode(trace.span_id));

    AuditEventOutput {
        seq: event.seq,
        occurred_at: event.occurred_at,
        occurred_at_iso: format_timestamp(event.occurred_at),
        event_type: event.event_type.clone(),
        actor: event.actor.to_string(),
        zone_id: event.zone_id.to_string(),
        correlation_id: hex_encode(event.correlation_id.0.as_bytes()),
        trace_id,
        span_id,
        connector_id: event.connector_id.as_ref().map(ToString::to_string),
        operation_id: event.operation.as_ref().map(ToString::to_string),
        prev: event.prev.as_ref().map(ToString::to_string),
    }
}

#[cfg(test)]
/// Test-only audit event fixture loader used by audit-chain unit tests.
#[allow(clippy::too_many_lines)]
fn load_audit_events(
    zone: &str,
    since: Option<u64>,
    limit: usize,
    filter: &AuditFilter,
) -> Result<Vec<AuditEventOutput>, AuditTailError> {
    // Stub: Return demo data for the "z:work" zone, otherwise "zone not found"
    if !zone.starts_with("z:") {
        return Err(AuditTailError::zone_not_found(zone));
    }

    if zone != "z:work" && zone != "z:demo" {
        // For unknown zones, return empty to simulate no events
        return Ok(vec![]);
    }

    let base_seq = since.unwrap_or(100);
    #[allow(clippy::cast_sign_loss)] // Timestamps after 1970 are positive
    let now = Utc::now().timestamp() as u64;

    // Generate sample events
    let all_events = vec![
        AuditEventOutput {
            seq: base_seq,
            occurred_at: now - 300,
            occurred_at_iso: format_timestamp(now - 300),
            event_type: "capability.invoke".to_string(),
            actor: "user:alice".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "a".repeat(32),
            trace_id: Some("t".repeat(32)),
            span_id: Some("s".repeat(16)),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: None,
        },
        AuditEventOutput {
            seq: base_seq + 1,
            occurred_at: now - 240,
            occurred_at_iso: format_timestamp(now - 240),
            event_type: "secret.access".to_string(),
            actor: "user:alice".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "b".repeat(32),
            trace_id: Some("t".repeat(32)),
            span_id: Some("s".repeat(16)),
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("get_api_key".to_string()),
            prev: Some("prev1".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 2,
            occurred_at: now - 180,
            occurred_at_iso: format_timestamp(now - 180),
            event_type: "capability.invoke".to_string(),
            actor: "user:bob".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "c".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: Some("fcp.discord:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            prev: Some("prev2".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 3,
            occurred_at: now - 120,
            occurred_at_iso: format_timestamp(now - 120),
            event_type: "elevation.granted".to_string(),
            actor: "user:admin".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "d".repeat(32),
            trace_id: Some("u".repeat(32)),
            span_id: Some("v".repeat(16)),
            connector_id: None,
            operation_id: None,
            prev: Some("prev3".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 4,
            occurred_at: now - 60,
            occurred_at_iso: format_timestamp(now - 60),
            event_type: "revocation.issued".to_string(),
            actor: "user:admin".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "e".repeat(32),
            trace_id: Some("u".repeat(32)),
            span_id: Some("w".repeat(16)),
            connector_id: None,
            operation_id: None,
            prev: Some("prev4".to_string()),
        },
        AuditEventOutput {
            seq: base_seq + 5,
            occurred_at: now - 30,
            occurred_at_iso: format_timestamp(now - 30),
            event_type: "security.violation".to_string(),
            actor: "user:mallory".to_string(),
            zone_id: zone.to_string(),
            correlation_id: "f".repeat(32),
            trace_id: None,
            span_id: None,
            connector_id: Some("fcp.github:base:v1".to_string()),
            operation_id: Some("delete_repo".to_string()),
            prev: Some("prev5".to_string()),
        },
    ];

    // Apply filter and limit
    let events: Vec<_> = all_events
        .into_iter()
        .filter(|e| filter.matches(e))
        .take(limit)
        .collect();

    Ok(events)
}

/// Format a Unix timestamp as ISO-8601.
fn format_timestamp(ts: u64) -> String {
    #[allow(clippy::cast_possible_wrap)] // Timestamps fit in i64 until year 292 billion
    let ts_i64 = ts as i64;
    Utc.timestamp_opt(ts_i64, 0).single().map_or_else(
        || ts.to_string(),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

/// Output events as JSON.
fn output_json(events: &[AuditEventOutput]) -> Result<()> {
    for event in events {
        let json = serde_json::to_string(event).context("failed to serialize event")?;
        println!("{json}");
    }
    Ok(())
}

/// Output events in human-readable format.
fn output_human(events: &[AuditEventOutput], zone: &str, filter: &AuditFilter) {
    let reset = AuditEventOutput::ansi_reset();

    // Header
    println!();
    println!("Audit Events for zone: {zone}");
    if !filter.is_empty() {
        print!("Filters:");
        if let Some(ref c) = filter.connector_id {
            print!(" connector={c}");
        }
        if let Some(ref o) = filter.operation_id {
            print!(" operation={o}");
        }
        if let Some(ref corr) = filter.correlation_id {
            print!(" correlation={}...", &corr[..8.min(corr.len())]);
        }
        if let Some(ref t) = filter.trace_id {
            print!(" trace={}...", &t[..8.min(t.len())]);
        }
        if let Some(ref e) = filter.event_type {
            print!(" event_type={e}");
        }
        if let Some(ref a) = filter.actor {
            print!(" actor={a}");
        }
        println!();
    }
    println!("{}", "─".repeat(80));
    println!();

    for event in events {
        let color = event.event_type_color();
        let symbol = event.event_type_symbol();

        // Timestamp and seq
        print!("\x1b[90m[{}]\x1b[0m ", event.occurred_at_iso);
        print!("\x1b[90mseq={:<6}\x1b[0m ", event.seq);

        // Event type with color
        print!("{color}{symbol} {:<26}{reset} ", event.event_type);

        // Actor
        print!("actor={:<16} ", truncate(&event.actor, 16));

        // Connector/operation if present
        if let Some(ref cid) = event.connector_id {
            print!("connector={} ", truncate(cid, 20));
        }
        if let Some(ref oid) = event.operation_id {
            print!("op={} ", truncate(oid, 15));
        }

        println!();

        // Second line: correlation/trace IDs
        if event.trace_id.is_some() || !event.correlation_id.is_empty() {
            print!("    ");
            print!("correlation={} ", truncate(&event.correlation_id, 12));
            if let Some(ref tid) = event.trace_id {
                print!("trace={} ", truncate(tid, 12));
            }
            if let Some(ref sid) = event.span_id {
                print!("span={} ", truncate(sid, 8));
            }
            println!();
        }
    }

    println!();
    println!("{}", "─".repeat(80));
    println!("Showing {} events", events.len());
    println!();
}

/// Truncate a string and add "..." if needed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_valid() {
        let ts = 1_700_000_000;
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2023"));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("abcdefghij", 6), "abc...");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
    }

    #[test]
    fn load_events_valid_zone() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 10, &filter);
        assert!(events.is_ok());
        let events = events.unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn load_events_invalid_zone_format() {
        let filter = AuditFilter::default();
        let events = load_audit_events("invalid", None, 10, &filter);
        assert!(events.is_err());
        let err = events.unwrap_err();
        assert_eq!(err.code, "FCP-4001");
    }

    #[test]
    fn load_events_unknown_zone_empty() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:unknown", None, 10, &filter);
        assert!(events.is_ok());
        assert!(events.unwrap().is_empty());
    }

    #[test]
    fn load_events_respects_limit() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 2, &filter).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn load_events_respects_filter() {
        let filter = AuditFilter {
            actor: Some("user:admin".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.iter().all(|e| e.actor == "user:admin"));
    }

    #[test]
    fn load_events_filter_by_event_type() {
        let filter = AuditFilter {
            event_type: Some("capability.invoke".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(events.iter().all(|e| e.event_type == "capability.invoke"));
    }

    // ---- format_timestamp edge cases ----

    #[test]
    fn format_timestamp_epoch_zero() {
        let formatted = format_timestamp(0);
        assert!(formatted.contains("1970"));
    }

    #[test]
    fn format_timestamp_iso_format() {
        let formatted = format_timestamp(1_700_000_000);
        assert!(formatted.ends_with('Z'));
        assert!(formatted.contains('T'));
    }

    // ---- truncate edge cases ----

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn truncate_very_short_max() {
        // max_len <= 3 means no room for "...", just truncate
        assert_eq!(truncate("abcdef", 3), "abc");
    }

    #[test]
    fn truncate_one_char_over() {
        assert_eq!(truncate("abcdefg", 6), "abc...");
    }

    // ---- load_events with since ----

    #[test]
    fn load_events_with_since_parameter() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", Some(50), 10, &filter).unwrap();
        assert!(!events.is_empty());
        assert_eq!(events[0].seq, 50);
    }

    #[test]
    fn load_events_demo_zone() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:demo", None, 10, &filter).unwrap();
        assert!(!events.is_empty());
    }

    // ---- load_events filter by connector ----

    #[test]
    fn load_events_filter_by_connector() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(
            events
                .iter()
                .all(|e| e.connector_id.as_deref() == Some("fcp.telegram:base:v1"))
        );
    }

    #[test]
    fn load_events_filter_by_operation() {
        let filter = AuditFilter {
            operation_id: Some("send_message".to_string()),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert!(
            events
                .iter()
                .all(|e| e.operation_id.as_deref() == Some("send_message"))
        );
    }

    #[test]
    fn load_events_filter_by_correlation() {
        let filter = AuditFilter {
            correlation_id: Some("a".repeat(32)),
            ..Default::default()
        };
        let events = load_audit_events("z:work", None, 10, &filter).unwrap();
        assert_eq!(events.len(), 1);
    }

    // ---- parse_event_records ----

    #[test]
    fn parse_event_records_empty() {
        let records = parse_event_records("").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_event_records_whitespace() {
        let records = parse_event_records("   \n  \n  ").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn parse_event_records_invalid_json() {
        let result = parse_event_records("{not json}");
        assert!(result.is_err());
    }

    // ---- parse_audit_head ----

    #[test]
    fn parse_audit_head_rejects_array() {
        let result = parse_audit_head("[1,2,3]");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("single JSON object")
        );
    }

    // ---- verify_chain ----

    #[test]
    fn verify_chain_empty_records() {
        let report = verify_chain(&[], None, None);
        assert!(matches!(report.status, AuditVerifyStatus::Ok));
        assert_eq!(report.chain_len, 0);
        assert!(report.issues.is_empty());
    }

    // ---- AuditVerifyStatus serde ----

    #[test]
    fn verify_status_serde() {
        let json = serde_json::to_string(&AuditVerifyStatus::Ok).unwrap();
        assert_eq!(json, "\"ok\"");
        let json = serde_json::to_string(&AuditVerifyStatus::Warn).unwrap();
        assert_eq!(json, "\"warn\"");
        let json = serde_json::to_string(&AuditVerifyStatus::Fail).unwrap();
        assert_eq!(json, "\"fail\"");
    }

    // ---- AuditVerifyReport serde ----

    #[test]
    fn verify_report_serde_roundtrip() {
        let report = AuditVerifyReport {
            status: AuditVerifyStatus::Ok,
            zone_id: Some("z:work".to_string()),
            chain_len: 5,
            head_seq: Some(4),
            head_event: Some("event-id".to_string()),
            issues: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditVerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_len, 5);
        assert!(parsed.issues.is_empty());
    }

    // ---- AuditVerifyIssue ----

    #[test]
    fn verify_issue_skips_none_fields() {
        let issue = AuditVerifyIssue {
            code: "test".to_string(),
            message: "msg".to_string(),
            seq: None,
            object_id: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(!json.contains("seq"));
        assert!(!json.contains("object_id"));
    }

    // ---- load_events all event types present ----

    #[test]
    fn load_events_has_diverse_event_types() {
        let filter = AuditFilter::default();
        let events = load_audit_events("z:work", None, 100, &filter).unwrap();
        let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
        assert!(types.contains(&"capability.invoke"));
        assert!(types.contains(&"secret.access"));
        assert!(types.contains(&"elevation.granted"));
        assert!(types.contains(&"revocation.issued"));
        assert!(types.contains(&"security.violation"));
    }

    // ---- AuditTailError display ----

    #[test]
    fn audit_tail_error_display() {
        let err = AuditTailError::zone_not_found("z:test");
        let display = format!("{err}");
        assert!(display.contains("FCP-4001"));
        assert!(display.contains("z:test"));
    }

    #[test]
    fn audit_tail_error_interrupted() {
        let err = AuditTailError::interrupted();
        assert_eq!(err.code, "FCP-9001");
    }
}
