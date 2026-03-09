//! `fcp trace` command implementation.
//!
//! Provides deterministic trace replay for mesh debugging workflows.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use fcp_mesh::{TraceReplayEngine, TraceReplayInputFormat, TraceReplayReport};

/// Arguments for `fcp trace`.
#[derive(Args, Debug)]
pub struct TraceArgs {
    #[command(subcommand)]
    command: TraceCommands,
}

/// Trace subcommands.
#[derive(Subcommand, Debug)]
enum TraceCommands {
    /// Replay a captured trace file and compare expected vs actual decisions.
    Replay(TraceReplayArgs),
}

/// Arguments for `fcp trace replay`.
#[derive(Args, Debug)]
pub struct TraceReplayArgs {
    /// Path to the trace file (JSON or CBOR).
    pub file: String,

    /// Input format (`auto`, `json`, `cbor`).
    #[arg(long, value_enum, default_value_t = TraceFormatArg::Auto)]
    pub format: TraceFormatArg,

    /// Emit machine-parseable JSON report.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Trace input format for CLI parsing.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TraceFormatArg {
    /// Auto-detect from input bytes.
    Auto,
    /// Parse as JSON.
    Json,
    /// Parse as CBOR.
    Cbor,
}

impl From<TraceFormatArg> for TraceReplayInputFormat {
    fn from(value: TraceFormatArg) -> Self {
        match value {
            TraceFormatArg::Auto => Self::Auto,
            TraceFormatArg::Json => Self::Json,
            TraceFormatArg::Cbor => Self::Cbor,
        }
    }
}

/// Run the trace command.
pub fn run(args: TraceArgs) -> Result<()> {
    match args.command {
        TraceCommands::Replay(replay) => run_replay(&replay),
    }
}

fn run_replay(args: &TraceReplayArgs) -> Result<()> {
    let report = TraceReplayEngine::replay_path(&args.file, args.format.into())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_readable(&report);
    }

    if report.summary.mismatched_events > 0 || report.summary.mismatched_decisions > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn print_human_readable(report: &TraceReplayReport) {
    println!();
    println!("FCP Trace Replay Report");
    println!("=======================");
    println!("Trace ID:          {}", report.source_trace_id);
    println!(
        "Capturing Node:    {}",
        report
            .source_capturing_node
            .as_deref()
            .unwrap_or("<unknown>")
    );
    println!("Input Events:      {}", report.input_events);
    println!("Replayed Events:   {}", report.replayed_events);
    println!();

    println!("Summary:");
    println!("  Matched events:        {}", report.summary.matched_events);
    println!(
        "  Mismatched events:     {}",
        report.summary.mismatched_events
    );
    println!(
        "  Matched decisions:     {}",
        report.summary.matched_decisions
    );
    println!(
        "  Mismatched decisions:  {}",
        report.summary.mismatched_decisions
    );
    println!();

    println!("Event Type Counts:");
    for (event_type, count) in &report.summary.event_type_counts {
        println!("  {event_type}: {count}");
    }
    println!();

    println!("Expected Decision Counts:");
    if report.summary.expected_decision_counts.is_empty() {
        println!("  <none>");
    } else {
        for (decision, count) in &report.summary.expected_decision_counts {
            println!("  {decision}: {count}");
        }
    }
    println!();

    println!("Actual Decision Counts:");
    if report.summary.actual_decision_counts.is_empty() {
        println!("  <none>");
    } else {
        for (decision, count) in &report.summary.actual_decision_counts {
            println!("  {decision}: {count}");
        }
    }
    println!();

    if report.diffs.is_empty() {
        println!("Decision Diff:      no mismatches");
    } else {
        println!("Decision Diff:");
        for diff in &report.diffs {
            println!(
                "  - idx={} type={} expected={:?} actual={:?} detail={}",
                diff.index,
                diff.event_type,
                diff.expected_decision,
                diff.actual_decision,
                diff.detail
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mapping_matches_replay_engine() {
        assert_eq!(
            TraceReplayInputFormat::from(TraceFormatArg::Auto),
            TraceReplayInputFormat::Auto
        );
        assert_eq!(
            TraceReplayInputFormat::from(TraceFormatArg::Json),
            TraceReplayInputFormat::Json
        );
        assert_eq!(
            TraceReplayInputFormat::from(TraceFormatArg::Cbor),
            TraceReplayInputFormat::Cbor
        );
    }

    #[test]
    fn trace_format_arg_debug() {
        assert!(format!("{:?}", TraceFormatArg::Auto).contains("Auto"));
        assert!(format!("{:?}", TraceFormatArg::Json).contains("Json"));
        assert!(format!("{:?}", TraceFormatArg::Cbor).contains("Cbor"));
    }

    #[test]
    fn trace_format_arg_clone() {
        let arg = TraceFormatArg::Json;
        let cloned = arg;
        assert!(matches!(cloned, TraceFormatArg::Json));
    }

    #[test]
    fn trace_replay_args_debug() {
        let args = TraceReplayArgs {
            file: "test.json".to_string(),
            format: TraceFormatArg::Auto,
            json: false,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("test.json"));
        assert!(debug.contains("Auto"));
    }

    #[test]
    fn trace_replay_args_json_flag_default() {
        let args = TraceReplayArgs {
            file: "trace.cbor".to_string(),
            format: TraceFormatArg::Cbor,
            json: false,
        };
        assert!(!args.json);
    }

    #[test]
    fn format_auto_is_default() {
        let args = TraceReplayArgs {
            file: "x.json".to_string(),
            format: TraceFormatArg::Auto,
            json: false,
        };
        assert!(matches!(args.format, TraceFormatArg::Auto));
    }

    #[test]
    fn all_format_variants_convert_successfully() {
        let variants = [
            TraceFormatArg::Auto,
            TraceFormatArg::Json,
            TraceFormatArg::Cbor,
        ];
        for v in variants {
            let _: TraceReplayInputFormat = v.into();
        }
    }

    // ── print_human_readable tests ──────────────────────────────

    fn make_report(
        mismatched_events: usize,
        mismatched_decisions: usize,
        diffs: Vec<fcp_mesh::TraceReplayDiff>,
    ) -> TraceReplayReport {
        use std::collections::BTreeMap;
        let mut event_type_counts = BTreeMap::new();
        event_type_counts.insert("routing".to_string(), 5);
        event_type_counts.insert("admission".to_string(), 3);

        TraceReplayReport {
            source_trace_id: "trace-001".to_string(),
            source_capturing_node: Some("node-a".to_string()),
            input_events: 10,
            replayed_events: 10,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 10,
                event_type_counts,
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 10 - mismatched_events,
                mismatched_events,
                matched_decisions: 8 - mismatched_decisions,
                mismatched_decisions,
            },
            diffs,
        }
    }

    #[test]
    fn print_human_readable_no_mismatches() {
        let report = make_report(0, 0, vec![]);
        // Should not panic
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_with_diffs() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 3,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "zone mismatch".to_string(),
        }];
        let report = make_report(0, 1, diffs);
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_unknown_node() {
        let report = TraceReplayReport {
            source_trace_id: "trace-002".to_string(),
            source_capturing_node: None,
            input_events: 0,
            replayed_events: 0,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 0,
                event_type_counts: std::collections::BTreeMap::new(),
                expected_decision_counts: std::collections::BTreeMap::new(),
                actual_decision_counts: std::collections::BTreeMap::new(),
                matched_events: 0,
                mismatched_events: 0,
                matched_decisions: 0,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_with_decision_counts() {
        use std::collections::BTreeMap;
        let mut expected = BTreeMap::new();
        expected.insert("allow".to_string(), 7);
        expected.insert("deny".to_string(), 3);
        let mut actual = BTreeMap::new();
        actual.insert("allow".to_string(), 6);
        actual.insert("deny".to_string(), 4);

        let report = TraceReplayReport {
            source_trace_id: "trace-003".to_string(),
            source_capturing_node: Some("mesh-node-1".to_string()),
            input_events: 10,
            replayed_events: 10,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 10,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: expected,
                actual_decision_counts: actual,
                matched_events: 10,
                mismatched_events: 0,
                matched_decisions: 9,
                mismatched_decisions: 1,
            },
            diffs: vec![],
        };
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_multiple_diffs() {
        let diffs = vec![
            fcp_mesh::TraceReplayDiff {
                index: 0,
                event_type: "routing".to_string(),
                expected_decision: Some("allow".to_string()),
                actual_decision: Some("deny".to_string()),
                detail: "capability missing".to_string(),
            },
            fcp_mesh::TraceReplayDiff {
                index: 5,
                event_type: "admission".to_string(),
                expected_decision: None,
                actual_decision: Some("reject".to_string()),
                detail: "rate limit exceeded".to_string(),
            },
        ];
        let report = make_report(1, 2, diffs);
        print_human_readable(&report);
    }

    // ── TraceReplayReport JSON serialization ────────────────────

    #[test]
    fn report_json_roundtrip() {
        let report = make_report(0, 0, vec![]);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source_trace_id, "trace-001");
        assert_eq!(parsed.input_events, 10);
    }

    #[test]
    fn report_with_diffs_json_roundtrip() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 1,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "zone changed".to_string(),
        }];
        let report = make_report(0, 1, diffs);
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.diffs.len(), 1);
        assert_eq!(parsed.diffs[0].event_type, "routing");
    }
}
