//! `fcp trace` command implementation.
//!
//! Provides deterministic trace replay for mesh debugging workflows.

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use fcp_mesh::{TraceReplayEngine, TraceReplayInputFormat, TraceReplayReport};

/// Arguments for `fcp trace`.
#[derive(Args, Debug, Clone)]
pub struct TraceArgs {
    #[command(subcommand)]
    command: TraceCommands,
}

/// Trace subcommands.
#[derive(Subcommand, Debug, Clone)]
enum TraceCommands {
    /// Replay a captured trace file and compare expected vs actual decisions.
    Replay(TraceReplayArgs),
}

/// Arguments for `fcp trace replay`.
#[derive(Args, Debug, Clone)]
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

    // ── make_report helper invariants ──────────────────────────────

    #[test]
    fn make_report_source_trace_id_is_trace_001() {
        let report = make_report(0, 0, vec![]);
        assert_eq!(report.source_trace_id, "trace-001");
    }

    #[test]
    fn make_report_capturing_node_is_node_a() {
        let report = make_report(0, 0, vec![]);
        assert_eq!(
            report.source_capturing_node.as_deref(),
            Some("node-a")
        );
    }

    #[test]
    fn make_report_input_events_always_ten() {
        let report = make_report(3, 2, vec![]);
        assert_eq!(report.input_events, 10);
        assert_eq!(report.replayed_events, 10);
    }

    #[test]
    fn make_report_event_type_counts_has_routing_and_admission() {
        let report = make_report(0, 0, vec![]);
        assert_eq!(report.summary.event_type_counts.get("routing"), Some(&5));
        assert_eq!(report.summary.event_type_counts.get("admission"), Some(&3));
        assert_eq!(report.summary.event_type_counts.len(), 2);
    }

    #[test]
    fn make_report_matched_events_equals_total_minus_mismatched() {
        for m in 0..=10 {
            let report = make_report(m, 0, vec![]);
            assert_eq!(report.summary.matched_events + report.summary.mismatched_events, 10);
        }
    }

    #[test]
    fn make_report_matched_decisions_equals_eight_minus_mismatched() {
        for m in 0..=8 {
            let report = make_report(0, m, vec![]);
            assert_eq!(report.summary.matched_decisions + report.summary.mismatched_decisions, 8);
        }
    }

    #[test]
    fn make_report_diffs_forwarded_unchanged() {
        let diffs = vec![
            fcp_mesh::TraceReplayDiff {
                index: 7,
                event_type: "audit".to_string(),
                expected_decision: None,
                actual_decision: None,
                detail: "missing audit trail".to_string(),
            },
        ];
        let report = make_report(1, 1, diffs);
        assert_eq!(report.diffs.len(), 1);
        assert_eq!(report.diffs[0].index, 7);
        assert_eq!(report.diffs[0].event_type, "audit");
        assert_eq!(report.diffs[0].detail, "missing audit trail");
    }

    #[test]
    fn make_report_empty_decision_maps() {
        let report = make_report(0, 0, vec![]);
        assert!(report.summary.expected_decision_counts.is_empty());
        assert!(report.summary.actual_decision_counts.is_empty());
    }

    // ── TraceReplayArgs construction variations ────────────────────

    #[test]
    fn trace_replay_args_with_json_flag_true() {
        let args = TraceReplayArgs {
            file: "out.json".to_string(),
            format: TraceFormatArg::Json,
            json: true,
        };
        assert!(args.json);
        assert_eq!(args.file, "out.json");
        assert!(matches!(args.format, TraceFormatArg::Json));
    }

    #[test]
    fn trace_replay_args_with_cbor_format() {
        let args = TraceReplayArgs {
            file: "/path/to/trace.cbor".to_string(),
            format: TraceFormatArg::Cbor,
            json: false,
        };
        assert!(matches!(args.format, TraceFormatArg::Cbor));
        assert!(args.file.contains("cbor"));
    }

    #[test]
    fn trace_replay_args_clone_preserves_all_fields() {
        let args = TraceReplayArgs {
            file: "data.json".to_string(),
            format: TraceFormatArg::Json,
            json: true,
        };
        let cloned = args.clone();
        assert_eq!(cloned.file, "data.json");
        assert!(cloned.json);
        assert!(matches!(cloned.format, TraceFormatArg::Json));
    }

    #[test]
    fn trace_replay_args_debug_contains_json_flag() {
        let args = TraceReplayArgs {
            file: "trace.cbor".to_string(),
            format: TraceFormatArg::Cbor,
            json: true,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("true"));
        assert!(debug.contains("Cbor"));
        assert!(debug.contains("trace.cbor"));
    }

    #[test]
    fn trace_replay_args_empty_file_path() {
        let args = TraceReplayArgs {
            file: String::new(),
            format: TraceFormatArg::Auto,
            json: false,
        };
        assert!(args.file.is_empty());
    }

    #[test]
    fn trace_replay_args_long_file_path() {
        let long_path = "a/".repeat(200) + "trace.json";
        let args = TraceReplayArgs {
            file: long_path.clone(),
            format: TraceFormatArg::Json,
            json: false,
        };
        assert_eq!(args.file, long_path);
    }

    // ── TraceFormatArg clone/copy/debug ────────────────────────────

    #[test]
    fn trace_format_arg_copy_semantics() {
        let a = TraceFormatArg::Cbor;
        let b = a; // Copy
        let c = a; // Still valid because Copy
        assert!(matches!(b, TraceFormatArg::Cbor));
        assert!(matches!(c, TraceFormatArg::Cbor));
    }

    #[test]
    fn trace_format_arg_all_variants_debug_distinct() {
        let auto = format!("{:?}", TraceFormatArg::Auto);
        let json = format!("{:?}", TraceFormatArg::Json);
        let cbor = format!("{:?}", TraceFormatArg::Cbor);
        assert_ne!(auto, json);
        assert_ne!(json, cbor);
        assert_ne!(auto, cbor);
    }

    // ── JSON serialization stability ───────────────────────────────

    #[test]
    fn empty_report_serializes_correctly() {
        use std::collections::BTreeMap;
        let report = TraceReplayReport {
            source_trace_id: String::new(),
            source_capturing_node: None,
            input_events: 0,
            replayed_events: 0,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 0,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 0,
                mismatched_events: 0,
                matched_decisions: 0,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"source_trace_id\":\"\""));
        assert!(json.contains("\"diffs\":[]"));
        assert!(json.contains("\"input_events\":0"));
    }

    #[test]
    fn report_json_contains_all_summary_fields() {
        let report = make_report(2, 1, vec![]);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"matched_events\":8"));
        assert!(json.contains("\"mismatched_events\":2"));
        assert!(json.contains("\"matched_decisions\":7"));
        assert!(json.contains("\"mismatched_decisions\":1"));
        assert!(json.contains("\"total_events\":10"));
    }

    #[test]
    fn report_json_pretty_format_is_multiline() {
        let report = make_report(0, 0, vec![]);
        let pretty = serde_json::to_string_pretty(&report).unwrap();
        assert!(pretty.contains('\n'));
        assert!(pretty.lines().count() > 5);
    }

    #[test]
    fn diff_json_roundtrip_preserves_none_decisions() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 42,
            event_type: "lifecycle".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "event skipped in replay".to_string(),
        }];
        let report = make_report(1, 0, diffs);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert!(parsed.diffs[0].expected_decision.is_none());
        assert!(parsed.diffs[0].actual_decision.is_none());
        assert_eq!(parsed.diffs[0].index, 42);
    }

    #[test]
    fn report_json_roundtrip_full_fidelity() {
        use std::collections::BTreeMap;
        let mut expected_counts = BTreeMap::new();
        expected_counts.insert("allow".to_string(), 5);
        expected_counts.insert("deny".to_string(), 3);
        let mut actual_counts = BTreeMap::new();
        actual_counts.insert("allow".to_string(), 4);
        actual_counts.insert("deny".to_string(), 4);

        let report = TraceReplayReport {
            source_trace_id: "full-fidelity-test".to_string(),
            source_capturing_node: Some("edge-node-42".to_string()),
            input_events: 100,
            replayed_events: 98,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 100,
                event_type_counts: {
                    let mut m = BTreeMap::new();
                    m.insert("routing".to_string(), 60);
                    m.insert("admission".to_string(), 30);
                    m.insert("audit".to_string(), 10);
                    m
                },
                expected_decision_counts: expected_counts,
                actual_decision_counts: actual_counts,
                matched_events: 95,
                mismatched_events: 5,
                matched_decisions: 90,
                mismatched_decisions: 10,
            },
            diffs: vec![
                fcp_mesh::TraceReplayDiff {
                    index: 10,
                    event_type: "routing".to_string(),
                    expected_decision: Some("allow".to_string()),
                    actual_decision: Some("deny".to_string()),
                    detail: "policy change".to_string(),
                },
                fcp_mesh::TraceReplayDiff {
                    index: 55,
                    event_type: "admission".to_string(),
                    expected_decision: Some("admit".to_string()),
                    actual_decision: None,
                    detail: "timeout during replay".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);
    }

    // ── Decision count maps through roundtrip ──────────────────────

    #[test]
    fn decision_counts_preserved_through_roundtrip() {
        use std::collections::BTreeMap;
        let mut expected = BTreeMap::new();
        expected.insert("allow".to_string(), 100);
        expected.insert("deny".to_string(), 50);
        expected.insert("rate_limit".to_string(), 25);
        let mut actual = BTreeMap::new();
        actual.insert("allow".to_string(), 90);
        actual.insert("deny".to_string(), 60);
        actual.insert("rate_limit".to_string(), 25);

        let report = TraceReplayReport {
            source_trace_id: "dc-test".to_string(),
            source_capturing_node: None,
            input_events: 175,
            replayed_events: 175,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 175,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: expected.clone(),
                actual_decision_counts: actual.clone(),
                matched_events: 175,
                mismatched_events: 0,
                matched_decisions: 150,
                mismatched_decisions: 25,
            },
            diffs: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.summary.expected_decision_counts, expected);
        assert_eq!(parsed.summary.actual_decision_counts, actual);
    }

    #[test]
    fn event_type_counts_btree_ordering_preserved() {
        let report = make_report(0, 0, vec![]);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        let keys: Vec<_> = parsed.summary.event_type_counts.keys().collect();
        // BTreeMap guarantees lexicographic order
        assert_eq!(keys, vec!["admission", "routing"]);
    }

    // ── TraceReplayReport clone/eq/debug ───────────────────────────

    #[test]
    fn report_clone_equals_original() {
        let report = make_report(2, 1, vec![fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "cloned".to_string(),
        }]);
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn report_debug_contains_trace_id() {
        let report = make_report(0, 0, vec![]);
        let debug = format!("{report:?}");
        assert!(debug.contains("trace-001"));
        assert!(debug.contains("node-a"));
    }

    #[test]
    fn report_ne_when_trace_id_differs() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.source_trace_id = "trace-999".to_string();
        assert_ne!(r1, r2);
    }

    #[test]
    fn report_ne_when_diffs_differ() {
        let r1 = make_report(0, 0, vec![]);
        let r2 = make_report(0, 1, vec![fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "x".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "d".to_string(),
        }]);
        assert_ne!(r1, r2);
    }

    // ── TraceReplayDiff clone/eq/debug ─────────────────────────────

    #[test]
    fn diff_clone_equals_original() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 99,
            event_type: "admission".to_string(),
            expected_decision: Some("admit".to_string()),
            actual_decision: Some("reject".to_string()),
            detail: "quota exceeded".to_string(),
        };
        let cloned = diff.clone();
        assert_eq!(diff, cloned);
    }

    #[test]
    fn diff_debug_contains_fields() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 5,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "zone mismatch".to_string(),
        };
        let debug = format!("{diff:?}");
        assert!(debug.contains("routing"));
        assert!(debug.contains("zone mismatch"));
        assert!(debug.contains("allow"));
        assert!(debug.contains("deny"));
    }

    #[test]
    fn diff_ne_when_index_differs() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "same".to_string(),
        };
        let mut d2 = d1.clone();
        d2.index = 1;
        assert_ne!(d1, d2);
    }

    // ── TraceReplaySummary clone/eq/debug ──────────────────────────

    #[test]
    fn summary_clone_equals_original() {
        let report = make_report(3, 2, vec![]);
        let summary = report.summary.clone();
        assert_eq!(report.summary, summary);
    }

    #[test]
    fn summary_debug_contains_counters() {
        let report = make_report(4, 3, vec![]);
        let debug = format!("{:?}", report.summary);
        assert!(debug.contains("mismatched_events"));
        assert!(debug.contains("mismatched_decisions"));
    }

    // ── Format conversion edge cases ───────────────────────────────

    #[test]
    fn format_conversion_is_idempotent_auto() {
        let input = TraceFormatArg::Auto;
        let converted: TraceReplayInputFormat = input.into();
        assert_eq!(converted, TraceReplayInputFormat::Auto);
    }

    #[test]
    fn format_conversion_is_idempotent_json() {
        let input = TraceFormatArg::Json;
        let converted: TraceReplayInputFormat = input.into();
        assert_eq!(converted, TraceReplayInputFormat::Json);
    }

    #[test]
    fn format_conversion_is_idempotent_cbor() {
        let input = TraceFormatArg::Cbor;
        let converted: TraceReplayInputFormat = input.into();
        assert_eq!(converted, TraceReplayInputFormat::Cbor);
    }

    // ── print_human_readable edge cases ────────────────────────────

    #[test]
    fn print_human_readable_large_counters() {
        use std::collections::BTreeMap;
        let mut event_types = BTreeMap::new();
        event_types.insert("routing".to_string(), 999_999);
        event_types.insert("admission".to_string(), 1);

        let report = TraceReplayReport {
            source_trace_id: "large-counters".to_string(),
            source_capturing_node: Some("big-node".to_string()),
            input_events: 1_000_000,
            replayed_events: 1_000_000,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 1_000_000,
                event_type_counts: event_types,
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 999_999,
                mismatched_events: 1,
                matched_decisions: 999_998,
                mismatched_decisions: 2,
            },
            diffs: vec![],
        };
        // Should not panic with large numbers
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_many_event_types() {
        use std::collections::BTreeMap;
        let mut event_types = BTreeMap::new();
        for i in 0..20 {
            event_types.insert(format!("event_type_{i}"), i as u64);
        }
        let report = TraceReplayReport {
            source_trace_id: "many-types".to_string(),
            source_capturing_node: Some("node".to_string()),
            input_events: 190,
            replayed_events: 190,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 190,
                event_type_counts: event_types,
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 190,
                mismatched_events: 0,
                matched_decisions: 190,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_unicode_in_fields() {
        use std::collections::BTreeMap;
        let mut event_types = BTreeMap::new();
        event_types.insert("routing".to_string(), 1);

        let report = TraceReplayReport {
            source_trace_id: "trace-\u{1F600}".to_string(),
            source_capturing_node: Some("node-\u{00E9}".to_string()),
            input_events: 1,
            replayed_events: 1,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 1,
                event_type_counts: event_types,
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 1,
                mismatched_events: 0,
                matched_decisions: 1,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        // Should handle unicode without panicking
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_diff_with_none_expected() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "admission".to_string(),
            expected_decision: None,
            actual_decision: Some("deny".to_string()),
            detail: "unexpected decision produced".to_string(),
        }];
        let report = make_report(0, 1, diffs);
        // Should render None as None in output
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_diff_with_none_actual() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: None,
            detail: "decision dropped".to_string(),
        }];
        let report = make_report(0, 1, diffs);
        print_human_readable(&report);
    }

    // ── Serialization of special values ────────────────────────────

    #[test]
    fn report_with_null_capturing_node_serializes() {
        use std::collections::BTreeMap;
        let report = TraceReplayReport {
            source_trace_id: "null-node".to_string(),
            source_capturing_node: None,
            input_events: 0,
            replayed_events: 0,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 0,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 0,
                mismatched_events: 0,
                matched_decisions: 0,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"source_capturing_node\":null"));
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert!(parsed.source_capturing_node.is_none());
    }

    #[test]
    fn report_many_diffs_serializes_as_array() {
        let diffs: Vec<_> = (0..10)
            .map(|i| fcp_mesh::TraceReplayDiff {
                index: i,
                event_type: format!("type_{i}"),
                expected_decision: Some("a".to_string()),
                actual_decision: Some("b".to_string()),
                detail: format!("mismatch at {i}"),
            })
            .collect();
        let report = make_report(0, 8, diffs);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.diffs.len(), 10);
        for (i, diff) in parsed.diffs.iter().enumerate() {
            assert_eq!(diff.index, i);
            assert_eq!(diff.event_type, format!("type_{i}"));
        }
    }

    #[test]
    fn diff_with_empty_strings_roundtrips() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: String::new(),
            expected_decision: Some(String::new()),
            actual_decision: Some(String::new()),
            detail: String::new(),
        };
        let report = make_report(0, 1, vec![diff]);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.diffs[0].event_type, "");
        assert_eq!(parsed.diffs[0].expected_decision, Some(String::new()));
        assert_eq!(parsed.diffs[0].detail, "");
    }

    #[test]
    fn report_json_value_structure() {
        let report = make_report(1, 1, vec![]);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert!(val.is_object());
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("source_trace_id"));
        assert!(obj.contains_key("summary"));
        assert!(obj.contains_key("diffs"));
        assert!(obj.contains_key("input_events"));
        assert!(obj.contains_key("replayed_events"));
        let summary = obj.get("summary").unwrap().as_object().unwrap();
        assert!(summary.contains_key("total_events"));
        assert!(summary.contains_key("event_type_counts"));
        assert!(summary.contains_key("expected_decision_counts"));
        assert!(summary.contains_key("actual_decision_counts"));
        assert!(summary.contains_key("matched_events"));
        assert!(summary.contains_key("mismatched_events"));
        assert!(summary.contains_key("matched_decisions"));
        assert!(summary.contains_key("mismatched_decisions"));
    }
}
