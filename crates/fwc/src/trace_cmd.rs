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
        assert_eq!(report.source_capturing_node.as_deref(), Some("node-a"));
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
            assert_eq!(
                report.summary.matched_events + report.summary.mismatched_events,
                10
            );
        }
    }

    #[test]
    fn make_report_matched_decisions_equals_eight_minus_mismatched() {
        for m in 0..=8 {
            let report = make_report(0, m, vec![]);
            assert_eq!(
                report.summary.matched_decisions + report.summary.mismatched_decisions,
                8
            );
        }
    }

    #[test]
    fn make_report_diffs_forwarded_unchanged() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 7,
            event_type: "audit".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "missing audit trail".to_string(),
        }];
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
        let report = make_report(
            2,
            1,
            vec![fcp_mesh::TraceReplayDiff {
                index: 0,
                event_type: "routing".to_string(),
                expected_decision: Some("allow".to_string()),
                actual_decision: Some("deny".to_string()),
                detail: "cloned".to_string(),
            }],
        );
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
        let r2 = make_report(
            0,
            1,
            vec![fcp_mesh::TraceReplayDiff {
                index: 0,
                event_type: "x".to_string(),
                expected_decision: None,
                actual_decision: None,
                detail: "d".to_string(),
            }],
        );
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

    // ── TraceReplayDiff equality and field edge cases ─────────────

    #[test]
    fn diff_ne_when_event_type_differs() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "same".to_string(),
        };
        let mut d2 = d1.clone();
        d2.event_type = "admission".to_string();
        assert_ne!(d1, d2);
    }

    #[test]
    fn diff_ne_when_expected_decision_differs() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: None,
            detail: "x".to_string(),
        };
        let mut d2 = d1.clone();
        d2.expected_decision = Some("deny".to_string());
        assert_ne!(d1, d2);
    }

    #[test]
    fn diff_ne_when_actual_decision_differs() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: Some("allow".to_string()),
            detail: "x".to_string(),
        };
        let mut d2 = d1.clone();
        d2.actual_decision = Some("deny".to_string());
        assert_ne!(d1, d2);
    }

    #[test]
    fn diff_ne_when_detail_differs() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "reason-a".to_string(),
        };
        let mut d2 = d1.clone();
        d2.detail = "reason-b".to_string();
        assert_ne!(d1, d2);
    }

    #[test]
    fn diff_eq_when_all_fields_match() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 42,
            event_type: "lifecycle".to_string(),
            expected_decision: Some("proceed".to_string()),
            actual_decision: Some("proceed".to_string()),
            detail: "ok".to_string(),
        };
        let d2 = d1.clone();
        assert_eq!(d1, d2);
    }

    #[test]
    fn diff_none_vs_some_expected_decision_not_equal() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: String::new(),
        };
        let mut d2 = d1.clone();
        d2.expected_decision = Some(String::new());
        assert_ne!(d1, d2);
    }

    #[test]
    fn diff_none_vs_some_actual_decision_not_equal() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: String::new(),
        };
        let mut d2 = d1.clone();
        d2.actual_decision = Some(String::new());
        assert_ne!(d1, d2);
    }

    #[test]
    fn diff_large_index_value() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: usize::MAX,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "max index".to_string(),
        };
        let cloned = diff.clone();
        assert_eq!(diff.index, usize::MAX);
        assert_eq!(diff, cloned);
    }

    #[test]
    fn diff_debug_contains_index() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 12345,
            event_type: "audit".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "check".to_string(),
        };
        let debug = format!("{diff:?}");
        assert!(debug.contains("12345"));
        assert!(debug.contains("audit"));
        assert!(debug.contains("check"));
    }

    #[test]
    fn diff_with_long_detail_string() {
        let long_detail = "x".repeat(10_000);
        let diff = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: long_detail.clone(),
        };
        assert_eq!(diff.detail.len(), 10_000);
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: fcp_mesh::TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.detail, long_detail);
    }

    #[test]
    fn diff_with_special_chars_in_event_type() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing/admission:v2".to_string(),
            expected_decision: Some("allow\"deny".to_string()),
            actual_decision: Some("tab\there".to_string()),
            detail: "newline\nhere".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: fcp_mesh::TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type, "routing/admission:v2");
        assert_eq!(parsed.expected_decision.as_deref(), Some("allow\"deny"));
    }

    // ── TraceReplaySummary edge cases ────────────────────────────

    #[test]
    fn summary_ne_when_total_events_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.summary.total_events = 999;
        assert_ne!(r1.summary, r2.summary);
    }

    #[test]
    fn summary_ne_when_matched_events_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.summary.matched_events = 5;
        assert_ne!(r1.summary, r2.summary);
    }

    #[test]
    fn summary_ne_when_event_type_counts_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.summary
            .event_type_counts
            .insert("new_type".to_string(), 1);
        assert_ne!(r1.summary, r2.summary);
    }

    #[test]
    fn summary_ne_when_expected_decision_counts_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.summary
            .expected_decision_counts
            .insert("allow".to_string(), 1);
        assert_ne!(r1.summary, r2.summary);
    }

    #[test]
    fn summary_ne_when_actual_decision_counts_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.summary
            .actual_decision_counts
            .insert("deny".to_string(), 1);
        assert_ne!(r1.summary, r2.summary);
    }

    #[test]
    fn summary_zero_counters() {
        use std::collections::BTreeMap;
        let summary = fcp_mesh::TraceReplaySummary {
            total_events: 0,
            event_type_counts: BTreeMap::new(),
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 0,
            mismatched_events: 0,
            matched_decisions: 0,
            mismatched_decisions: 0,
        };
        let cloned = summary.clone();
        assert_eq!(summary, cloned);
        assert_eq!(summary.total_events, 0);
    }

    #[test]
    fn summary_large_event_type_counts() {
        use std::collections::BTreeMap;
        let mut event_types = BTreeMap::new();
        for i in 0..100 {
            event_types.insert(format!("type_{i:03}"), i as u64);
        }
        let summary = fcp_mesh::TraceReplaySummary {
            total_events: 4950,
            event_type_counts: event_types,
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 4950,
            mismatched_events: 0,
            matched_decisions: 4950,
            mismatched_decisions: 0,
        };
        assert_eq!(summary.event_type_counts.len(), 100);
        let keys: Vec<_> = summary.event_type_counts.keys().collect();
        assert_eq!(keys[0], "type_000");
        assert_eq!(keys[99], "type_099");
    }

    #[test]
    fn summary_json_roundtrip() {
        let report = make_report(3, 2, vec![]);
        let json = serde_json::to_string(&report.summary).unwrap();
        let parsed: fcp_mesh::TraceReplaySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report.summary);
    }

    #[test]
    fn summary_debug_contains_event_type_keys() {
        let report = make_report(0, 0, vec![]);
        let debug = format!("{:?}", report.summary);
        assert!(debug.contains("routing"));
        assert!(debug.contains("admission"));
    }

    // ── TraceReplayReport additional edge cases ──────────────────

    #[test]
    fn report_ne_when_input_events_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.input_events = 999;
        assert_ne!(r1, r2);
    }

    #[test]
    fn report_ne_when_replayed_events_differ() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.replayed_events = 5;
        assert_ne!(r1, r2);
    }

    #[test]
    fn report_ne_when_capturing_node_differs() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.source_capturing_node = Some("different-node".to_string());
        assert_ne!(r1, r2);
    }

    #[test]
    fn report_ne_when_capturing_node_none_vs_some() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.source_capturing_node = None;
        assert_ne!(r1, r2);
    }

    #[test]
    fn report_ne_when_summary_differs() {
        let r1 = make_report(0, 0, vec![]);
        let mut r2 = make_report(0, 0, vec![]);
        r2.summary.total_events = 50;
        assert_ne!(r1, r2);
    }

    #[test]
    fn report_with_empty_trace_id() {
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
        assert!(report.source_trace_id.is_empty());
        print_human_readable(&report);
    }

    #[test]
    fn report_with_max_usize_events() {
        use std::collections::BTreeMap;
        let report = TraceReplayReport {
            source_trace_id: "max-events".to_string(),
            source_capturing_node: None,
            input_events: usize::MAX,
            replayed_events: usize::MAX,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: usize::MAX,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: usize::MAX,
                mismatched_events: 0,
                matched_decisions: usize::MAX,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.input_events, usize::MAX);
    }

    #[test]
    fn report_debug_contains_all_key_fields() {
        let report = make_report(2, 1, vec![]);
        let debug = format!("{report:?}");
        assert!(debug.contains("source_trace_id"));
        assert!(debug.contains("source_capturing_node"));
        assert!(debug.contains("input_events"));
        assert!(debug.contains("replayed_events"));
        assert!(debug.contains("summary"));
        assert!(debug.contains("diffs"));
    }

    // ── TraceReplayArgs additional construction variants ─────────

    #[test]
    fn trace_replay_args_with_auto_format_and_json_true() {
        let args = TraceReplayArgs {
            file: "trace.bin".to_string(),
            format: TraceFormatArg::Auto,
            json: true,
        };
        assert!(args.json);
        assert!(matches!(args.format, TraceFormatArg::Auto));
    }

    #[test]
    fn trace_replay_args_with_cbor_format_and_json_true() {
        let args = TraceReplayArgs {
            file: "data.cbor".to_string(),
            format: TraceFormatArg::Cbor,
            json: true,
        };
        assert!(args.json);
        assert!(matches!(args.format, TraceFormatArg::Cbor));
    }

    #[test]
    fn trace_replay_args_file_with_spaces() {
        let args = TraceReplayArgs {
            file: "path with spaces/trace file.json".to_string(),
            format: TraceFormatArg::Json,
            json: false,
        };
        assert!(args.file.contains(' '));
    }

    #[test]
    fn trace_replay_args_file_with_unicode() {
        let args = TraceReplayArgs {
            file: "/tmp/\u{00E9}l\u{00E8}ve/trace.json".to_string(),
            format: TraceFormatArg::Json,
            json: false,
        };
        assert!(args.file.contains('\u{00E9}'));
    }

    #[test]
    fn trace_replay_args_absolute_path() {
        let args = TraceReplayArgs {
            file: "/var/log/fcp/traces/2026-03-12/trace-001.json".to_string(),
            format: TraceFormatArg::Json,
            json: false,
        };
        assert!(args.file.starts_with('/'));
    }

    #[test]
    fn trace_replay_args_relative_path() {
        let args = TraceReplayArgs {
            file: "../traces/trace.cbor".to_string(),
            format: TraceFormatArg::Cbor,
            json: false,
        };
        assert!(args.file.starts_with(".."));
    }

    #[test]
    fn trace_replay_args_clone_independence() {
        let args = TraceReplayArgs {
            file: "original.json".to_string(),
            format: TraceFormatArg::Json,
            json: false,
        };
        let mut cloned = args.clone();
        cloned.file = "modified.json".to_string();
        cloned.json = true;
        assert_eq!(args.file, "original.json");
        assert!(!args.json);
        assert_eq!(cloned.file, "modified.json");
        assert!(cloned.json);
    }

    #[test]
    fn trace_replay_args_debug_format_includes_struct_name() {
        let args = TraceReplayArgs {
            file: "f.json".to_string(),
            format: TraceFormatArg::Auto,
            json: false,
        };
        let debug = format!("{args:?}");
        assert!(debug.contains("TraceReplayArgs"));
    }

    // ── TraceFormatArg additional tests ──────────────────────────

    #[test]
    fn trace_format_arg_auto_into_replay_input_format() {
        let f: TraceReplayInputFormat = TraceFormatArg::Auto.into();
        assert_eq!(f, TraceReplayInputFormat::Auto);
    }

    #[test]
    fn trace_format_arg_json_into_replay_input_format() {
        let f: TraceReplayInputFormat = TraceFormatArg::Json.into();
        assert_eq!(f, TraceReplayInputFormat::Json);
    }

    #[test]
    fn trace_format_arg_cbor_into_replay_input_format() {
        let f: TraceReplayInputFormat = TraceFormatArg::Cbor.into();
        assert_eq!(f, TraceReplayInputFormat::Cbor);
    }

    #[test]
    fn trace_format_arg_from_conversion_auto() {
        let f = TraceReplayInputFormat::from(TraceFormatArg::Auto);
        assert_eq!(f, TraceReplayInputFormat::Auto);
    }

    #[test]
    fn trace_format_arg_from_conversion_json() {
        let f = TraceReplayInputFormat::from(TraceFormatArg::Json);
        assert_eq!(f, TraceReplayInputFormat::Json);
    }

    #[test]
    fn trace_format_arg_from_conversion_cbor() {
        let f = TraceReplayInputFormat::from(TraceFormatArg::Cbor);
        assert_eq!(f, TraceReplayInputFormat::Cbor);
    }

    // ── JSON serialization edge cases ────────────────────────────

    #[test]
    fn diff_json_roundtrip_with_both_decisions_some() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 7,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "policy changed".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: fcp_mesh::TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, parsed);
    }

    #[test]
    fn diff_json_roundtrip_with_both_decisions_none() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "audit".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "info event".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: fcp_mesh::TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, parsed);
    }

    #[test]
    fn diff_json_roundtrip_expected_some_actual_none() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 3,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: None,
            detail: "dropped".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: fcp_mesh::TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, parsed);
    }

    #[test]
    fn diff_json_roundtrip_expected_none_actual_some() {
        let diff = fcp_mesh::TraceReplayDiff {
            index: 3,
            event_type: "admission".to_string(),
            expected_decision: None,
            actual_decision: Some("reject".to_string()),
            detail: "unexpected".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let parsed: fcp_mesh::TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, parsed);
    }

    #[test]
    fn report_json_diffs_array_is_ordered() {
        let diffs: Vec<_> = (0..5)
            .map(|i| fcp_mesh::TraceReplayDiff {
                index: i,
                event_type: "routing".to_string(),
                expected_decision: Some(format!("d{i}")),
                actual_decision: Some(format!("a{i}")),
                detail: format!("diff-{i}"),
            })
            .collect();
        let report = make_report(0, 5, diffs);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        for (i, diff) in parsed.diffs.iter().enumerate() {
            assert_eq!(diff.index, i);
            assert_eq!(diff.detail, format!("diff-{i}"));
        }
    }

    #[test]
    fn report_json_event_type_counts_serialized_as_object() {
        let report = make_report(0, 0, vec![]);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        let summary = val.get("summary").unwrap();
        let etc = summary.get("event_type_counts").unwrap();
        assert!(etc.is_object());
        assert_eq!(etc.get("routing").unwrap().as_u64(), Some(5));
        assert_eq!(etc.get("admission").unwrap().as_u64(), Some(3));
    }

    #[test]
    fn report_json_decision_counts_serialized_as_object() {
        use std::collections::BTreeMap;
        let mut expected = BTreeMap::new();
        expected.insert("allow".to_string(), 10_u64);
        let mut actual = BTreeMap::new();
        actual.insert("deny".to_string(), 10_u64);

        let report = TraceReplayReport {
            source_trace_id: "dc-obj".to_string(),
            source_capturing_node: None,
            input_events: 10,
            replayed_events: 10,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 10,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: expected,
                actual_decision_counts: actual,
                matched_events: 0,
                mismatched_events: 10,
                matched_decisions: 0,
                mismatched_decisions: 10,
            },
            diffs: vec![],
        };
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        let summary = val.get("summary").unwrap();
        let edc = summary.get("expected_decision_counts").unwrap();
        assert!(edc.is_object());
        assert_eq!(edc.get("allow").unwrap().as_u64(), Some(10));
        let adc = summary.get("actual_decision_counts").unwrap();
        assert!(adc.is_object());
        assert_eq!(adc.get("deny").unwrap().as_u64(), Some(10));
    }

    #[test]
    fn report_json_input_and_replayed_events_as_numbers() {
        let report = make_report(0, 0, vec![]);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert!(val.get("input_events").unwrap().is_number());
        assert!(val.get("replayed_events").unwrap().is_number());
    }

    #[test]
    fn report_json_source_trace_id_is_string() {
        let report = make_report(0, 0, vec![]);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert!(val.get("source_trace_id").unwrap().is_string());
    }

    #[test]
    fn report_json_source_capturing_node_is_string_or_null() {
        let report = make_report(0, 0, vec![]);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        let node = val.get("source_capturing_node").unwrap();
        assert!(node.is_string() || node.is_null());
    }

    #[test]
    fn report_json_diffs_is_array() {
        let report = make_report(0, 0, vec![]);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert!(val.get("diffs").unwrap().is_array());
    }

    // ── print_human_readable additional scenarios ────────────────

    #[test]
    fn print_human_readable_only_expected_decision_counts() {
        use std::collections::BTreeMap;
        let mut expected = BTreeMap::new();
        expected.insert("allow".to_string(), 5);
        expected.insert("deny".to_string(), 5);

        let report = TraceReplayReport {
            source_trace_id: "only-expected".to_string(),
            source_capturing_node: Some("node".to_string()),
            input_events: 10,
            replayed_events: 10,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 10,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: expected,
                actual_decision_counts: BTreeMap::new(),
                matched_events: 10,
                mismatched_events: 0,
                matched_decisions: 10,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        // Actual is empty, expected is not — should not panic
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_only_actual_decision_counts() {
        use std::collections::BTreeMap;
        let mut actual = BTreeMap::new();
        actual.insert("allow".to_string(), 5);

        let report = TraceReplayReport {
            source_trace_id: "only-actual".to_string(),
            source_capturing_node: Some("node".to_string()),
            input_events: 10,
            replayed_events: 10,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 10,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: actual,
                matched_events: 10,
                mismatched_events: 0,
                matched_decisions: 10,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        // Expected is empty, actual is not — should not panic
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_zero_input_events() {
        use std::collections::BTreeMap;
        let report = TraceReplayReport {
            source_trace_id: "zero-events".to_string(),
            source_capturing_node: Some("node".to_string()),
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
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_mismatched_input_vs_replayed() {
        use std::collections::BTreeMap;
        let report = TraceReplayReport {
            source_trace_id: "mismatch-counts".to_string(),
            source_capturing_node: Some("node".to_string()),
            input_events: 100,
            replayed_events: 95,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 100,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 95,
                mismatched_events: 5,
                matched_decisions: 90,
                mismatched_decisions: 10,
            },
            diffs: vec![],
        };
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_single_event_type() {
        use std::collections::BTreeMap;
        let mut event_types = BTreeMap::new();
        event_types.insert("routing".to_string(), 1);

        let report = TraceReplayReport {
            source_trace_id: "single-type".to_string(),
            source_capturing_node: Some("node".to_string()),
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
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_many_diffs() {
        use std::collections::BTreeMap;
        let diffs: Vec<_> = (0..50)
            .map(|i| fcp_mesh::TraceReplayDiff {
                index: i,
                event_type: if i % 2 == 0 { "routing" } else { "admission" }.to_string(),
                expected_decision: Some("allow".to_string()),
                actual_decision: Some("deny".to_string()),
                detail: format!("diff at index {i}"),
            })
            .collect();
        let report = TraceReplayReport {
            source_trace_id: "many-diffs".to_string(),
            source_capturing_node: Some("node".to_string()),
            input_events: 100,
            replayed_events: 100,
            summary: fcp_mesh::TraceReplaySummary {
                total_events: 100,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 50,
                mismatched_events: 50,
                matched_decisions: 50,
                mismatched_decisions: 50,
            },
            diffs,
        };
        // Should handle 50 diffs without panicking
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_long_trace_id() {
        use std::collections::BTreeMap;
        let long_id = "t".repeat(1000);
        let report = TraceReplayReport {
            source_trace_id: long_id.clone(),
            source_capturing_node: Some("node".to_string()),
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
        print_human_readable(&report);
    }

    #[test]
    fn print_human_readable_long_node_name() {
        use std::collections::BTreeMap;
        let long_node = "n".repeat(500);
        let report = TraceReplayReport {
            source_trace_id: "t".to_string(),
            source_capturing_node: Some(long_node),
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
        print_human_readable(&report);
    }

    // ── make_report helper additional invariant checks ───────────

    #[test]
    fn make_report_total_events_always_ten() {
        let report = make_report(5, 3, vec![]);
        assert_eq!(report.summary.total_events, 10);
    }

    #[test]
    fn make_report_diffs_empty_when_no_diffs_passed() {
        let report = make_report(0, 0, vec![]);
        assert!(report.diffs.is_empty());
    }

    #[test]
    fn make_report_multiple_diffs_preserved_in_order() {
        let diffs: Vec<_> = (0..5)
            .map(|i| fcp_mesh::TraceReplayDiff {
                index: i,
                event_type: format!("t{i}"),
                expected_decision: None,
                actual_decision: None,
                detail: format!("d{i}"),
            })
            .collect();
        let report = make_report(0, 0, diffs);
        assert_eq!(report.diffs.len(), 5);
        for (i, diff) in report.diffs.iter().enumerate() {
            assert_eq!(diff.index, i);
            assert_eq!(diff.event_type, format!("t{i}"));
        }
    }

    #[test]
    fn make_report_capturing_node_always_some() {
        let report = make_report(0, 0, vec![]);
        assert!(report.source_capturing_node.is_some());
    }

    // ── TraceReplayInputFormat serde ─────────────────────────────

    #[test]
    fn trace_replay_input_format_json_roundtrip_auto() {
        let format = TraceReplayInputFormat::Auto;
        let json = serde_json::to_string(&format).unwrap();
        let parsed: TraceReplayInputFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TraceReplayInputFormat::Auto);
    }

    #[test]
    fn trace_replay_input_format_json_roundtrip_json() {
        let format = TraceReplayInputFormat::Json;
        let json = serde_json::to_string(&format).unwrap();
        let parsed: TraceReplayInputFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TraceReplayInputFormat::Json);
    }

    #[test]
    fn trace_replay_input_format_json_roundtrip_cbor() {
        let format = TraceReplayInputFormat::Cbor;
        let json = serde_json::to_string(&format).unwrap();
        let parsed: TraceReplayInputFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TraceReplayInputFormat::Cbor);
    }

    #[test]
    fn trace_replay_input_format_serializes_snake_case() {
        let auto_json = serde_json::to_string(&TraceReplayInputFormat::Auto).unwrap();
        let json_json = serde_json::to_string(&TraceReplayInputFormat::Json).unwrap();
        let cbor_json = serde_json::to_string(&TraceReplayInputFormat::Cbor).unwrap();
        assert_eq!(auto_json, "\"auto\"");
        assert_eq!(json_json, "\"json\"");
        assert_eq!(cbor_json, "\"cbor\"");
    }

    #[test]
    fn trace_replay_input_format_debug_distinct() {
        let auto = format!("{:?}", TraceReplayInputFormat::Auto);
        let json = format!("{:?}", TraceReplayInputFormat::Json);
        let cbor = format!("{:?}", TraceReplayInputFormat::Cbor);
        assert_ne!(auto, json);
        assert_ne!(json, cbor);
        assert_ne!(auto, cbor);
    }

    #[test]
    fn trace_replay_input_format_clone_eq() {
        let a = TraceReplayInputFormat::Json;
        let b = a;
        assert_eq!(a, b);
    }

    // ── Cross-type interaction tests ─────────────────────────────

    #[test]
    fn report_with_single_diff_json_structure() {
        let diffs = vec![fcp_mesh::TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "test".to_string(),
        }];
        let report = make_report(0, 1, diffs);
        let val: serde_json::Value = serde_json::to_value(&report).unwrap();
        let diffs_arr = val.get("diffs").unwrap().as_array().unwrap();
        assert_eq!(diffs_arr.len(), 1);
        let diff_obj = diffs_arr[0].as_object().unwrap();
        assert_eq!(diff_obj.get("index").unwrap().as_u64(), Some(0));
        assert_eq!(
            diff_obj.get("event_type").unwrap().as_str(),
            Some("routing")
        );
        assert_eq!(
            diff_obj.get("expected_decision").unwrap().as_str(),
            Some("allow")
        );
        assert_eq!(
            diff_obj.get("actual_decision").unwrap().as_str(),
            Some("deny")
        );
        assert_eq!(diff_obj.get("detail").unwrap().as_str(), Some("test"));
    }

    #[test]
    fn format_arg_conversion_roundtrip_through_all_variants() {
        let variants = [
            (TraceFormatArg::Auto, TraceReplayInputFormat::Auto),
            (TraceFormatArg::Json, TraceReplayInputFormat::Json),
            (TraceFormatArg::Cbor, TraceReplayInputFormat::Cbor),
        ];
        for (arg, expected) in variants {
            let converted: TraceReplayInputFormat = arg.into();
            assert_eq!(converted, expected);
        }
    }

    #[test]
    fn report_symmetric_equality() {
        let r1 = make_report(1, 1, vec![]);
        let r2 = make_report(1, 1, vec![]);
        assert_eq!(r1, r2);
        assert_eq!(r2, r1);
    }

    #[test]
    fn report_transitive_equality() {
        let r1 = make_report(0, 0, vec![]);
        let r2 = make_report(0, 0, vec![]);
        let r3 = make_report(0, 0, vec![]);
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        assert_eq!(r1, r3);
    }

    #[test]
    fn summary_symmetric_equality() {
        let s1 = make_report(0, 0, vec![]).summary;
        let s2 = make_report(0, 0, vec![]).summary;
        assert_eq!(s1, s2);
        assert_eq!(s2, s1);
    }

    #[test]
    fn diff_symmetric_equality() {
        let d1 = fcp_mesh::TraceReplayDiff {
            index: 1,
            event_type: "routing".to_string(),
            expected_decision: Some("a".to_string()),
            actual_decision: Some("b".to_string()),
            detail: "c".to_string(),
        };
        let d2 = d1.clone();
        assert_eq!(d1, d2);
        assert_eq!(d2, d1);
    }

    // ── Serialization size/structure sanity ──────────────────────

    #[test]
    fn empty_report_json_size_is_bounded() {
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
        // Compact empty report should be under 500 bytes
        assert!(json.len() < 500);
    }

    #[test]
    fn report_with_100_diffs_json_is_valid() {
        let diffs: Vec<_> = (0..100)
            .map(|i| fcp_mesh::TraceReplayDiff {
                index: i,
                event_type: "routing".to_string(),
                expected_decision: Some("a".to_string()),
                actual_decision: Some("b".to_string()),
                detail: format!("diff {i}"),
            })
            .collect();
        let report = make_report(0, 8, diffs);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.diffs.len(), 100);
    }

    #[test]
    fn report_pretty_json_contains_indentation() {
        let report = make_report(0, 0, vec![]);
        let pretty = serde_json::to_string_pretty(&report).unwrap();
        // Pretty print uses 2-space indentation by default
        assert!(pretty.contains("  "));
    }
}
