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
}
