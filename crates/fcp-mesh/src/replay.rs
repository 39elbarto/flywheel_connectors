//! Trace replay engine for deterministic offline debugging.
//!
//! Replays a captured mesh trace by feeding events into a `MeshNode` trace buffer and
//! comparing expected decisions in the source trace against replayed decisions.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, QuarantineStore,
};
use fcp_telemetry::trace_capture::{CapturedTrace, TraceCaptureConfig, TraceError, TraceEvent};
use serde::{Deserialize, Serialize};

use crate::{MeshNode, MeshNodeConfig, MeshNodeError};

/// Input format for replay trace files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceReplayInputFormat {
    /// Auto-detect from content.
    Auto,
    /// Parse as JSON.
    Json,
    /// Parse as CBOR.
    Cbor,
}

/// A mismatch between expected and replayed decisions/events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceReplayDiff {
    /// Event index in replay order.
    pub index: usize,
    /// Event type label (`routing`, `admission`, ...).
    pub event_type: String,
    /// Expected decision from source trace (if the event type carries one).
    pub expected_decision: Option<String>,
    /// Actual decision from replayed trace (if the event type carries one).
    pub actual_decision: Option<String>,
    /// Human-readable mismatch description.
    pub detail: String,
}

/// Replay summary counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceReplaySummary {
    /// Total events in input trace.
    pub total_events: usize,
    /// Event counts grouped by type.
    pub event_type_counts: BTreeMap<String, u64>,
    /// Decision counts from input trace.
    pub expected_decision_counts: BTreeMap<String, u64>,
    /// Decision counts from replay output.
    pub actual_decision_counts: BTreeMap<String, u64>,
    /// Count of events that exactly matched.
    pub matched_events: usize,
    /// Count of events that mismatched.
    pub mismatched_events: usize,
    /// Count of decisions that exactly matched.
    pub matched_decisions: usize,
    /// Count of decisions that mismatched.
    pub mismatched_decisions: usize,
}

/// Full replay report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceReplayReport {
    /// Trace capture ID from source file.
    pub source_trace_id: String,
    /// Optional capture node from source file.
    pub source_capturing_node: Option<String>,
    /// Number of events in the source file.
    pub input_events: usize,
    /// Number of events captured after replay.
    pub replayed_events: usize,
    /// Summary counters.
    pub summary: TraceReplaySummary,
    /// Expected/actual diffs.
    pub diffs: Vec<TraceReplayDiff>,
}

/// Replay engine for mesh traces.
pub struct TraceReplayEngine;

impl TraceReplayEngine {
    /// Load a trace from a file.
    ///
    /// # Errors
    ///
    /// Returns [`TraceReplayError`] when file IO or parsing fails.
    pub fn load_trace_from_path<P: AsRef<Path>>(
        path: P,
        format: TraceReplayInputFormat,
    ) -> Result<CapturedTrace, TraceReplayError> {
        let path_ref = path.as_ref();
        let bytes = std::fs::read(path_ref).map_err(|err| TraceReplayError::Io {
            path: path_ref.display().to_string(),
            message: err.to_string(),
        })?;
        decode_trace_bytes(&bytes, format)
    }

    /// Replay a trace file and generate a deterministic report.
    ///
    /// # Errors
    ///
    /// Returns [`TraceReplayError`] when loading or replay fails.
    pub fn replay_path<P: AsRef<Path>>(
        path: P,
        format: TraceReplayInputFormat,
    ) -> Result<TraceReplayReport, TraceReplayError> {
        let trace = Self::load_trace_from_path(path, format)?;
        Self::replay(&trace)
    }

    /// Replay a parsed trace and compare expected vs actual decisions.
    ///
    /// # Errors
    ///
    /// Returns [`TraceReplayError`] when replay infrastructure cannot ingest events.
    pub fn replay(trace: &CapturedTrace) -> Result<TraceReplayReport, TraceReplayError> {
        let replay_node = trace
            .capturing_node
            .as_deref()
            .unwrap_or("trace-replay-node");
        let trace_config = TraceCaptureConfig::new()
            .enabled()
            .with_sample_rate(1.0)
            .with_max_events(trace.events.len().saturating_add(16));

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new(replay_node).with_trace_capture_config(trace_config),
            object_store,
            symbol_store,
            quarantine_store,
        );

        for event in &trace.events {
            node.ingest_trace_event_for_replay(event.clone())?;
        }

        let replayed_trace = node
            .trace_debug_unredacted_snapshot()
            .ok_or(TraceReplayError::TraceCaptureUnavailable)?;

        let (diffs, summary) = compare_traces(trace, &replayed_trace);

        Ok(TraceReplayReport {
            source_trace_id: trace.id.clone(),
            source_capturing_node: trace.capturing_node.clone(),
            input_events: trace.events.len(),
            replayed_events: replayed_trace.events.len(),
            summary,
            diffs,
        })
    }
}

/// Replay/trace loading error.
#[derive(Debug, thiserror::Error)]
pub enum TraceReplayError {
    /// File read/write error.
    #[error("trace IO error at {path}: {message}")]
    Io {
        /// Source file path.
        path: String,
        /// Human-readable message.
        message: String,
    },

    /// Parsing error.
    #[error("failed to parse trace as {format}: {message}")]
    Parse {
        /// Attempted format.
        format: &'static str,
        /// Human-readable message.
        message: String,
    },

    /// Mesh replay infrastructure failed.
    #[error("mesh replay failed: {0}")]
    Mesh(#[from] MeshNodeError),

    /// Trace capture was disabled/unavailable in replay node.
    #[error("trace capture unavailable during replay")]
    TraceCaptureUnavailable,
}

fn decode_trace_bytes(
    bytes: &[u8],
    format: TraceReplayInputFormat,
) -> Result<CapturedTrace, TraceReplayError> {
    match format {
        TraceReplayInputFormat::Json => parse_json_trace(bytes),
        TraceReplayInputFormat::Cbor => parse_cbor_trace(bytes),
        TraceReplayInputFormat::Auto => {
            if looks_like_json(bytes) {
                parse_json_trace(bytes).or_else(|_| parse_cbor_trace(bytes))
            } else {
                parse_cbor_trace(bytes).or_else(|_| parse_json_trace(bytes))
            }
        }
    }
}

fn parse_json_trace(bytes: &[u8]) -> Result<CapturedTrace, TraceReplayError> {
    let text = std::str::from_utf8(bytes).map_err(|err| TraceReplayError::Parse {
        format: "json",
        message: err.to_string(),
    })?;
    CapturedTrace::from_json(text).map_err(|err| TraceReplayError::Parse {
        format: "json",
        message: err.to_string(),
    })
}

fn parse_cbor_trace(bytes: &[u8]) -> Result<CapturedTrace, TraceReplayError> {
    CapturedTrace::from_cbor(bytes).map_err(|err| TraceReplayError::Parse {
        format: "cbor",
        message: err.to_string(),
    })
}

fn looks_like_json(bytes: &[u8]) -> bool {
    let trimmed = bytes.iter().copied().skip_while(u8::is_ascii_whitespace);
    matches!(trimmed.take(1).next(), Some(b'{' | b'['))
}

fn compare_traces(
    expected: &CapturedTrace,
    actual: &CapturedTrace,
) -> (Vec<TraceReplayDiff>, TraceReplaySummary) {
    let mut event_type_counts = BTreeMap::new();
    let mut expected_decision_counts = BTreeMap::new();
    let mut actual_decision_counts = BTreeMap::new();

    for event in &expected.events {
        *event_type_counts
            .entry(event_type_label(event).to_string())
            .or_insert(0) += 1;
        if let Some(decision) = decision_label(event) {
            *expected_decision_counts
                .entry(decision.to_string())
                .or_insert(0) += 1;
        }
    }
    for event in &actual.events {
        if let Some(decision) = decision_label(event) {
            *actual_decision_counts
                .entry(decision.to_string())
                .or_insert(0) += 1;
        }
    }

    let max_len = expected.events.len().max(actual.events.len());
    let mut diffs = Vec::new();
    let mut matched_events = 0usize;
    let mut matched_decisions = 0usize;
    let mut mismatched_decisions = 0usize;

    for index in 0..max_len {
        let expected_event = expected.events.get(index);
        let actual_event = actual.events.get(index);
        match (expected_event, actual_event) {
            (Some(exp), Some(act)) => {
                let event_type = event_type_label(exp).to_string();
                if exp == act {
                    matched_events = matched_events.saturating_add(1);
                } else {
                    diffs.push(TraceReplayDiff {
                        index,
                        event_type: event_type.clone(),
                        expected_decision: decision_label(exp).map(ToString::to_string),
                        actual_decision: decision_label(act).map(ToString::to_string),
                        detail: "event payload mismatch".to_string(),
                    });
                }

                if decision_label(exp) == decision_label(act) {
                    if decision_label(exp).is_some() {
                        matched_decisions = matched_decisions.saturating_add(1);
                    }
                } else {
                    mismatched_decisions = mismatched_decisions.saturating_add(1);
                    diffs.push(TraceReplayDiff {
                        index,
                        event_type,
                        expected_decision: decision_label(exp).map(ToString::to_string),
                        actual_decision: decision_label(act).map(ToString::to_string),
                        detail: "decision mismatch".to_string(),
                    });
                }
            }
            (Some(exp), None) => {
                diffs.push(TraceReplayDiff {
                    index,
                    event_type: event_type_label(exp).to_string(),
                    expected_decision: decision_label(exp).map(ToString::to_string),
                    actual_decision: None,
                    detail: "missing replay event".to_string(),
                });
                if decision_label(exp).is_some() {
                    mismatched_decisions = mismatched_decisions.saturating_add(1);
                }
            }
            (None, Some(act)) => {
                diffs.push(TraceReplayDiff {
                    index,
                    event_type: event_type_label(act).to_string(),
                    expected_decision: None,
                    actual_decision: decision_label(act).map(ToString::to_string),
                    detail: "unexpected replay event".to_string(),
                });
                if decision_label(act).is_some() {
                    mismatched_decisions = mismatched_decisions.saturating_add(1);
                }
            }
            (None, None) => {}
        }
    }

    let mismatched_events = max_len.saturating_sub(matched_events);
    let summary = TraceReplaySummary {
        total_events: expected.events.len(),
        event_type_counts,
        expected_decision_counts,
        actual_decision_counts,
        matched_events,
        mismatched_events,
        matched_decisions,
        mismatched_decisions,
    };

    (dedupe_diffs(diffs), summary)
}

fn dedupe_diffs(diffs: Vec<TraceReplayDiff>) -> Vec<TraceReplayDiff> {
    let mut out = Vec::new();
    for diff in diffs {
        if out
            .iter()
            .any(|existing: &TraceReplayDiff| existing == &diff)
        {
            continue;
        }
        out.push(diff);
    }
    out
}

fn event_type_label(event: &TraceEvent) -> &'static str {
    match event {
        TraceEvent::Routing(_) => "routing",
        TraceEvent::Admission(_) => "admission",
        TraceEvent::Gossip(_) => "gossip",
        TraceEvent::Lease(_) => "lease",
        TraceEvent::Session(_) => "session",
        TraceEvent::Policy(_) => "policy",
    }
}

fn decision_label(event: &TraceEvent) -> Option<&str> {
    match event {
        TraceEvent::Routing(event) => Some(event.decision.as_str()),
        TraceEvent::Admission(event) => Some(event.decision.as_str()),
        TraceEvent::Policy(event) => Some(event.decision.as_str()),
        TraceEvent::Gossip(_) | TraceEvent::Lease(_) | TraceEvent::Session(_) => None,
    }
}

impl From<TraceError> for TraceReplayError {
    fn from(value: TraceError) -> Self {
        Self::Parse {
            format: "trace",
            message: value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fcp_telemetry::trace_capture::{AdmissionOutcome, PolicyDecision, RoutingDecision};

    fn sample_trace() -> CapturedTrace {
        let mut trace = CapturedTrace::new("trace-replay-test");
        trace.capturing_node = Some("node-test".to_string());
        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1000,
            trace_id: "trace-a".to_string(),
            source_node: "node-1".to_string(),
            target_node: Some("node-2".to_string()),
            object_id: "obj-1".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        }));
        trace.push(TraceEvent::Admission(AdmissionOutcome {
            timestamp: 1001,
            trace_id: "trace-a".to_string(),
            peer_node: "node-2".to_string(),
            request_type: "invoke".to_string(),
            decision: "admit".to_string(),
            reason_code: None,
            budget_remaining: Some(42),
            authenticated: true,
        }));
        trace.push(TraceEvent::Policy(PolicyDecision {
            timestamp: 1002,
            trace_id: "trace-a".to_string(),
            zone_id: "z:work".to_string(),
            operation: "op.send".to_string(),
            connector_id: "fcp.telegram".to_string(),
            decision: "allow".to_string(),
            reason_code: "CAP_OK".to_string(),
            evidence: vec!["obj-1".to_string()],
        }));
        trace
    }

    #[test]
    fn replay_produces_deterministic_match_report() {
        let trace = sample_trace();
        let report = TraceReplayEngine::replay(&trace).expect("replay should succeed");

        assert_eq!(report.input_events, 3);
        assert_eq!(report.replayed_events, 3);
        assert_eq!(report.summary.mismatched_events, 0);
        assert_eq!(report.summary.mismatched_decisions, 0);
        assert!(report.diffs.is_empty());
        assert_eq!(report.summary.event_type_counts["routing"], 1);
        assert_eq!(report.summary.event_type_counts["admission"], 1);
        assert_eq!(report.summary.event_type_counts["policy"], 1);
        assert_eq!(report.summary.expected_decision_counts["allow"], 1);
        assert_eq!(report.summary.expected_decision_counts["admit"], 1);
        assert_eq!(report.summary.expected_decision_counts["routed"], 1);
    }

    #[test]
    fn decode_auto_accepts_json_trace() {
        let trace = sample_trace();
        let json = trace.to_json().expect("serialize json");
        let parsed =
            decode_trace_bytes(json.as_bytes(), TraceReplayInputFormat::Auto).expect("auto decode");
        assert_eq!(parsed.id, trace.id);
        assert_eq!(parsed.events.len(), trace.events.len());
    }

    #[test]
    fn decode_auto_accepts_cbor_trace() {
        let trace = sample_trace();
        let cbor = trace.to_cbor().expect("serialize cbor");
        let parsed =
            decode_trace_bytes(&cbor, TraceReplayInputFormat::Auto).expect("auto decode cbor");
        assert_eq!(parsed.id, trace.id);
        assert_eq!(parsed.events.len(), trace.events.len());
    }

    // ---- looks_like_json ----

    #[test]
    fn looks_like_json_object() {
        assert!(looks_like_json(b"{\"key\": 1}"));
    }

    #[test]
    fn looks_like_json_array() {
        assert!(looks_like_json(b"[1, 2, 3]"));
    }

    #[test]
    fn looks_like_json_with_whitespace() {
        assert!(looks_like_json(b"  \n\t{\"key\": 1}"));
    }

    #[test]
    fn looks_like_json_cbor_bytes() {
        assert!(!looks_like_json(&[0xa2, 0x62]));
    }

    #[test]
    fn looks_like_json_empty() {
        assert!(!looks_like_json(b""));
    }

    // ---- event_type_label ----

    #[test]
    fn event_type_label_routing() {
        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 0,
            trace_id: String::new(),
            source_node: String::new(),
            target_node: None,
            object_id: String::new(),
            path_type: String::new(),
            decision: String::new(),
            reason: None,
        });
        assert_eq!(event_type_label(&event), "routing");
    }

    #[test]
    fn event_type_label_admission() {
        let event = TraceEvent::Admission(AdmissionOutcome {
            timestamp: 0,
            trace_id: String::new(),
            peer_node: String::new(),
            request_type: String::new(),
            decision: String::new(),
            reason_code: None,
            budget_remaining: None,
            authenticated: false,
        });
        assert_eq!(event_type_label(&event), "admission");
    }

    #[test]
    fn event_type_label_policy() {
        let event = TraceEvent::Policy(PolicyDecision {
            timestamp: 0,
            trace_id: String::new(),
            zone_id: String::new(),
            operation: String::new(),
            connector_id: String::new(),
            decision: String::new(),
            reason_code: String::new(),
            evidence: vec![],
        });
        assert_eq!(event_type_label(&event), "policy");
    }

    // ---- decision_label ----

    #[test]
    fn decision_label_routing_has_decision() {
        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 0,
            trace_id: String::new(),
            source_node: String::new(),
            target_node: None,
            object_id: String::new(),
            path_type: String::new(),
            decision: "routed".to_string(),
            reason: None,
        });
        assert_eq!(decision_label(&event), Some("routed"));
    }

    #[test]
    fn decision_label_admission_has_decision() {
        let event = TraceEvent::Admission(AdmissionOutcome {
            timestamp: 0,
            trace_id: String::new(),
            peer_node: String::new(),
            request_type: String::new(),
            decision: "deny".to_string(),
            reason_code: None,
            budget_remaining: None,
            authenticated: false,
        });
        assert_eq!(decision_label(&event), Some("deny"));
    }

    #[test]
    fn decision_label_policy_has_decision() {
        let event = TraceEvent::Policy(PolicyDecision {
            timestamp: 0,
            trace_id: String::new(),
            zone_id: String::new(),
            operation: String::new(),
            connector_id: String::new(),
            decision: "allow".to_string(),
            reason_code: String::new(),
            evidence: vec![],
        });
        assert_eq!(decision_label(&event), Some("allow"));
    }

    // ---- dedupe_diffs ----

    #[test]
    fn dedupe_diffs_removes_duplicates() {
        let diff = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("a".to_string()),
            actual_decision: Some("b".to_string()),
            detail: "mismatch".to_string(),
        };
        let diffs = vec![diff.clone(), diff.clone(), diff];
        let deduped = dedupe_diffs(diffs);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn dedupe_diffs_keeps_distinct() {
        let diff1 = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("a".to_string()),
            actual_decision: Some("b".to_string()),
            detail: "mismatch".to_string(),
        };
        let diff2 = TraceReplayDiff {
            index: 1,
            event_type: "admission".to_string(),
            expected_decision: Some("c".to_string()),
            actual_decision: Some("d".to_string()),
            detail: "mismatch".to_string(),
        };
        let deduped = dedupe_diffs(vec![diff1, diff2]);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn dedupe_diffs_empty() {
        let deduped = dedupe_diffs(vec![]);
        assert!(deduped.is_empty());
    }

    // ---- compare_traces ----

    #[test]
    fn compare_traces_identical() {
        let trace = sample_trace();
        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.total_events, 3);
        assert_eq!(summary.matched_events, 3);
        assert_eq!(summary.mismatched_events, 0);
        assert_eq!(summary.matched_decisions, 3);
        assert_eq!(summary.mismatched_decisions, 0);
    }

    #[test]
    fn compare_traces_empty() {
        let trace = CapturedTrace::new("empty");
        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.matched_events, 0);
    }

    #[test]
    fn compare_traces_missing_replay_events() {
        let trace = sample_trace();
        let empty = CapturedTrace::new("empty");
        let (diffs, summary) = compare_traces(&trace, &empty);
        assert!(!diffs.is_empty());
        assert_eq!(summary.total_events, 3);
        assert_eq!(summary.matched_events, 0);
        assert_eq!(summary.mismatched_decisions, 3);
    }

    #[test]
    fn compare_traces_extra_replay_events() {
        let empty = CapturedTrace::new("empty");
        let trace = sample_trace();
        let (diffs, _summary) = compare_traces(&empty, &trace);
        assert!(!diffs.is_empty());
        assert!(diffs.iter().any(|d| d.detail == "unexpected replay event"));
    }

    // ---- TraceReplayDiff serde ----

    #[test]
    fn trace_replay_diff_serde_roundtrip() {
        let diff = TraceReplayDiff {
            index: 5,
            event_type: "routing".to_string(),
            expected_decision: Some("allow".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "decision mismatch".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let back: TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, diff);
    }

    // ---- TraceReplaySummary serde ----

    #[test]
    fn trace_replay_summary_serde_roundtrip() {
        let summary = TraceReplaySummary {
            total_events: 10,
            event_type_counts: BTreeMap::from([("routing".to_string(), 5)]),
            expected_decision_counts: BTreeMap::from([("allow".to_string(), 3)]),
            actual_decision_counts: BTreeMap::from([("allow".to_string(), 3)]),
            matched_events: 10,
            mismatched_events: 0,
            matched_decisions: 3,
            mismatched_decisions: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TraceReplaySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    // ---- TraceReplayReport serde ----

    #[test]
    fn trace_replay_report_serde_roundtrip() {
        let report = TraceReplayReport {
            source_trace_id: "trace-1".to_string(),
            source_capturing_node: Some("node-1".to_string()),
            input_events: 5,
            replayed_events: 5,
            summary: TraceReplaySummary {
                total_events: 5,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 5,
                mismatched_events: 0,
                matched_decisions: 0,
                mismatched_decisions: 0,
            },
            diffs: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    // ---- TraceReplayInputFormat serde ----

    #[test]
    fn trace_replay_input_format_serde() {
        for fmt in [
            TraceReplayInputFormat::Auto,
            TraceReplayInputFormat::Json,
            TraceReplayInputFormat::Cbor,
        ] {
            let json = serde_json::to_string(&fmt).unwrap();
            let back: TraceReplayInputFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(back, fmt);
        }
    }

    #[test]
    fn trace_replay_input_format_snake_case() {
        assert_eq!(
            serde_json::to_string(&TraceReplayInputFormat::Auto).unwrap(),
            "\"auto\""
        );
        assert_eq!(
            serde_json::to_string(&TraceReplayInputFormat::Json).unwrap(),
            "\"json\""
        );
    }

    // ---- TraceReplayError display ----

    #[test]
    fn trace_replay_error_io_display() {
        let err = TraceReplayError::Io {
            path: "/tmp/trace.json".to_string(),
            message: "not found".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/trace.json"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn trace_replay_error_parse_display() {
        let err = TraceReplayError::Parse {
            format: "json",
            message: "unexpected EOF".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("json"));
        assert!(msg.contains("unexpected EOF"));
    }

    #[test]
    fn trace_replay_error_unavailable_display() {
        let err = TraceReplayError::TraceCaptureUnavailable;
        assert!(err.to_string().contains("unavailable"));
    }

    // ---- decode_trace_bytes explicit formats ----

    #[test]
    fn decode_trace_explicit_json() {
        let trace = sample_trace();
        let json = trace.to_json().expect("to_json");
        let parsed =
            decode_trace_bytes(json.as_bytes(), TraceReplayInputFormat::Json).expect("json decode");
        assert_eq!(parsed.id, trace.id);
    }

    #[test]
    fn decode_trace_explicit_cbor() {
        let trace = sample_trace();
        let cbor = trace.to_cbor().expect("to_cbor");
        let parsed = decode_trace_bytes(&cbor, TraceReplayInputFormat::Cbor).expect("cbor decode");
        assert_eq!(parsed.id, trace.id);
    }

    #[test]
    fn decode_trace_json_format_rejects_cbor() {
        let trace = sample_trace();
        let cbor = trace.to_cbor().expect("to_cbor");
        assert!(decode_trace_bytes(&cbor, TraceReplayInputFormat::Json).is_err());
    }

    #[test]
    fn decode_trace_invalid_bytes() {
        assert!(decode_trace_bytes(b"not valid", TraceReplayInputFormat::Json).is_err());
        assert!(decode_trace_bytes(b"not valid", TraceReplayInputFormat::Cbor).is_err());
        assert!(decode_trace_bytes(b"not valid", TraceReplayInputFormat::Auto).is_err());
    }

    // ---- TraceReplayInputFormat Copy/Clone ----

    #[test]
    fn trace_replay_input_format_copy() {
        let a = TraceReplayInputFormat::Json;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn trace_replay_input_format_eq_all_variants() {
        assert_eq!(TraceReplayInputFormat::Auto, TraceReplayInputFormat::Auto);
        assert_eq!(TraceReplayInputFormat::Json, TraceReplayInputFormat::Json);
        assert_eq!(TraceReplayInputFormat::Cbor, TraceReplayInputFormat::Cbor);
        assert_ne!(TraceReplayInputFormat::Auto, TraceReplayInputFormat::Json);
        assert_ne!(TraceReplayInputFormat::Json, TraceReplayInputFormat::Cbor);
        assert_ne!(TraceReplayInputFormat::Cbor, TraceReplayInputFormat::Auto);
    }

    #[test]
    fn trace_replay_input_format_debug() {
        let auto_dbg = format!("{:?}", TraceReplayInputFormat::Auto);
        assert!(auto_dbg.contains("Auto"));
        let json_dbg = format!("{:?}", TraceReplayInputFormat::Json);
        assert!(json_dbg.contains("Json"));
        let cbor_dbg = format!("{:?}", TraceReplayInputFormat::Cbor);
        assert!(cbor_dbg.contains("Cbor"));
    }

    #[test]
    fn trace_replay_input_format_cbor_snake_case() {
        assert_eq!(
            serde_json::to_string(&TraceReplayInputFormat::Cbor).unwrap(),
            "\"cbor\""
        );
    }

    // ---- TraceReplayDiff ----

    #[test]
    fn trace_replay_diff_clone() {
        let diff = TraceReplayDiff {
            index: 7,
            event_type: "policy".to_string(),
            expected_decision: None,
            actual_decision: Some("deny".to_string()),
            detail: "missing".to_string(),
        };
        let cloned = diff.clone();
        assert_eq!(diff, cloned);
    }

    #[test]
    fn trace_replay_diff_with_none_decisions() {
        let diff = TraceReplayDiff {
            index: 0,
            event_type: "gossip".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "event mismatch".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let back: TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expected_decision, None);
        assert_eq!(back.actual_decision, None);
    }

    #[test]
    fn trace_replay_diff_debug() {
        let diff = TraceReplayDiff {
            index: 3,
            event_type: "admission".to_string(),
            expected_decision: Some("admit".to_string()),
            actual_decision: Some("deny".to_string()),
            detail: "mismatch".to_string(),
        };
        let dbg = format!("{diff:?}");
        assert!(dbg.contains("admission"));
        assert!(dbg.contains("admit"));
    }

    #[test]
    fn trace_replay_diff_large_index() {
        let diff = TraceReplayDiff {
            index: usize::MAX,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "max index".to_string(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let back: TraceReplayDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, usize::MAX);
    }

    // ---- TraceReplaySummary ----

    #[test]
    fn trace_replay_summary_clone() {
        let summary = TraceReplaySummary {
            total_events: 5,
            event_type_counts: BTreeMap::from([("routing".to_string(), 3)]),
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 5,
            mismatched_events: 0,
            matched_decisions: 0,
            mismatched_decisions: 0,
        };
        let cloned = summary.clone();
        assert_eq!(summary, cloned);
    }

    #[test]
    fn trace_replay_summary_empty_maps() {
        let summary = TraceReplaySummary {
            total_events: 0,
            event_type_counts: BTreeMap::new(),
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 0,
            mismatched_events: 0,
            matched_decisions: 0,
            mismatched_decisions: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TraceReplaySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_events, 0);
        assert!(back.event_type_counts.is_empty());
    }

    #[test]
    fn trace_replay_summary_multiple_types() {
        let summary = TraceReplaySummary {
            total_events: 10,
            event_type_counts: BTreeMap::from([
                ("routing".to_string(), 3),
                ("admission".to_string(), 4),
                ("policy".to_string(), 2),
                ("gossip".to_string(), 1),
            ]),
            expected_decision_counts: BTreeMap::from([
                ("allow".to_string(), 5),
                ("deny".to_string(), 2),
            ]),
            actual_decision_counts: BTreeMap::from([("allow".to_string(), 4)]),
            matched_events: 8,
            mismatched_events: 2,
            matched_decisions: 4,
            mismatched_decisions: 3,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TraceReplaySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_type_counts.len(), 4);
        assert_eq!(back.expected_decision_counts["deny"], 2);
    }

    #[test]
    fn trace_replay_summary_debug() {
        let summary = TraceReplaySummary {
            total_events: 1,
            event_type_counts: BTreeMap::new(),
            expected_decision_counts: BTreeMap::new(),
            actual_decision_counts: BTreeMap::new(),
            matched_events: 0,
            mismatched_events: 1,
            matched_decisions: 0,
            mismatched_decisions: 0,
        };
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("mismatched_events"));
    }

    // ---- TraceReplayReport ----

    #[test]
    fn trace_replay_report_clone() {
        let report = TraceReplayReport {
            source_trace_id: "t1".to_string(),
            source_capturing_node: None,
            input_events: 0,
            replayed_events: 0,
            summary: TraceReplaySummary {
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
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn trace_replay_report_no_capturing_node() {
        let report = TraceReplayReport {
            source_trace_id: "trace-abc".to_string(),
            source_capturing_node: None,
            input_events: 0,
            replayed_events: 0,
            summary: TraceReplaySummary {
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
        let back: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert!(back.source_capturing_node.is_none());
    }

    #[test]
    fn trace_replay_report_with_diffs() {
        let diff = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("routed".to_string()),
            actual_decision: Some("dropped".to_string()),
            detail: "decision mismatch".to_string(),
        };
        let report = TraceReplayReport {
            source_trace_id: "trace-1".to_string(),
            source_capturing_node: Some("n1".to_string()),
            input_events: 1,
            replayed_events: 1,
            summary: TraceReplaySummary {
                total_events: 1,
                event_type_counts: BTreeMap::from([("routing".to_string(), 1)]),
                expected_decision_counts: BTreeMap::from([("routed".to_string(), 1)]),
                actual_decision_counts: BTreeMap::from([("dropped".to_string(), 1)]),
                matched_events: 0,
                mismatched_events: 1,
                matched_decisions: 0,
                mismatched_decisions: 1,
            },
            diffs: vec![diff],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.diffs.len(), 1);
        assert_eq!(back.diffs[0].detail, "decision mismatch");
    }

    #[test]
    fn trace_replay_report_debug() {
        let report = TraceReplayReport {
            source_trace_id: "t".to_string(),
            source_capturing_node: None,
            input_events: 0,
            replayed_events: 0,
            summary: TraceReplaySummary {
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
        let dbg = format!("{report:?}");
        assert!(dbg.contains("source_trace_id"));
    }

    // ---- TraceReplayError ----

    #[test]
    fn trace_replay_error_io_fields() {
        let err = TraceReplayError::Io {
            path: "/some/path".to_string(),
            message: "file not found".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("/some/path"));
        assert!(s.contains("file not found"));
    }

    #[test]
    fn trace_replay_error_parse_various_formats() {
        for fmt in ["json", "cbor", "trace", "unknown"] {
            let err = TraceReplayError::Parse {
                format: fmt,
                message: "bad data".to_string(),
            };
            let s = err.to_string();
            assert!(s.contains(fmt));
            assert!(s.contains("bad data"));
        }
    }

    #[test]
    fn trace_replay_error_debug() {
        let err = TraceReplayError::TraceCaptureUnavailable;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TraceCaptureUnavailable"));
    }

    #[test]
    fn trace_replay_error_from_trace_error() {
        // TraceError → TraceReplayError::Parse via From impl
        let te = TraceError::BufferFull;
        let re: TraceReplayError = te.into();
        let s = re.to_string();
        assert!(s.contains("trace"));
    }

    // ---- looks_like_json edge cases ----

    #[test]
    fn looks_like_json_only_whitespace() {
        assert!(!looks_like_json(b"   \t\n  "));
    }

    #[test]
    fn looks_like_json_starts_with_number() {
        assert!(!looks_like_json(b"123"));
    }

    #[test]
    fn looks_like_json_starts_with_string() {
        assert!(!looks_like_json(b"\"hello\""));
    }

    #[test]
    fn looks_like_json_nested_object() {
        assert!(looks_like_json(b"  { \"inner\": { \"key\": 1 } }"));
    }

    #[test]
    fn looks_like_json_empty_array() {
        assert!(looks_like_json(b"[]"));
    }

    #[test]
    fn looks_like_json_empty_object() {
        assert!(looks_like_json(b"{}"));
    }

    #[test]
    fn looks_like_json_single_byte_open_brace() {
        assert!(looks_like_json(b"{"));
    }

    #[test]
    fn looks_like_json_single_byte_open_bracket() {
        assert!(looks_like_json(b"["));
    }

    #[test]
    fn looks_like_json_binary_prefix() {
        assert!(!looks_like_json(&[0x00, 0x01, 0x02]));
    }

    #[test]
    fn looks_like_json_high_bytes() {
        assert!(!looks_like_json(&[0xff, 0xfe, 0xfd]));
    }

    // ---- event_type_label for all variants ----

    #[test]
    fn event_type_label_gossip() {
        use fcp_telemetry::trace_capture::GossipEvent;
        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 0,
            trace_id: String::new(),
            gossip_type: "announce".to_string(),
            object_count: 0,
            peer_node: None,
            success: true,
        });
        assert_eq!(event_type_label(&event), "gossip");
    }

    #[test]
    fn event_type_label_lease() {
        use fcp_telemetry::trace_capture::LeaseEvent;
        let event = TraceEvent::Lease(LeaseEvent {
            timestamp: 0,
            trace_id: String::new(),
            operation: "acquire".to_string(),
            subject_id: String::new(),
            purpose: "singleton_writer".to_string(),
            node_id: String::new(),
            success: true,
            conflict_holder: None,
        });
        assert_eq!(event_type_label(&event), "lease");
    }

    #[test]
    fn event_type_label_session() {
        use fcp_telemetry::trace_capture::SessionEvent;
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 0,
            trace_id: String::new(),
            session_id: "abc".to_string(),
            kind: "hello".to_string(),
            peer_node: String::new(),
            suite: None,
            failure_reason: None,
        });
        assert_eq!(event_type_label(&event), "session");
    }

    // ---- decision_label for non-decision variants ----

    #[test]
    fn decision_label_gossip_none() {
        use fcp_telemetry::trace_capture::GossipEvent;
        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 0,
            trace_id: String::new(),
            gossip_type: "reconcile".to_string(),
            object_count: 5,
            peer_node: Some("peer-1".to_string()),
            success: false,
        });
        assert_eq!(decision_label(&event), None);
    }

    #[test]
    fn decision_label_lease_none() {
        use fcp_telemetry::trace_capture::LeaseEvent;
        let event = TraceEvent::Lease(LeaseEvent {
            timestamp: 0,
            trace_id: String::new(),
            operation: "release".to_string(),
            subject_id: String::new(),
            purpose: "coordinator".to_string(),
            node_id: "n1".to_string(),
            success: true,
            conflict_holder: None,
        });
        assert_eq!(decision_label(&event), None);
    }

    #[test]
    fn decision_label_session_none() {
        use fcp_telemetry::trace_capture::SessionEvent;
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 0,
            trace_id: String::new(),
            session_id: "sess-1".to_string(),
            kind: "established".to_string(),
            peer_node: "p1".to_string(),
            suite: Some("suite-a".to_string()),
            failure_reason: None,
        });
        assert_eq!(decision_label(&event), None);
    }

    #[test]
    fn decision_label_routing_empty_decision() {
        let event = TraceEvent::Routing(RoutingDecision {
            timestamp: 0,
            trace_id: String::new(),
            source_node: String::new(),
            target_node: None,
            object_id: String::new(),
            path_type: String::new(),
            decision: String::new(),
            reason: None,
        });
        assert_eq!(decision_label(&event), Some(""));
    }

    // ---- dedupe_diffs edge cases ----

    #[test]
    fn dedupe_diffs_single_element() {
        let diff = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "solo".to_string(),
        };
        let deduped = dedupe_diffs(vec![diff]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].detail, "solo");
    }

    #[test]
    fn dedupe_diffs_preserves_order() {
        let d1 = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "first".to_string(),
        };
        let d2 = TraceReplayDiff {
            index: 1,
            event_type: "admission".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "second".to_string(),
        };
        let d3 = TraceReplayDiff {
            index: 2,
            event_type: "policy".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "third".to_string(),
        };
        let deduped = dedupe_diffs(vec![d1, d2, d3]);
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped[0].detail, "first");
        assert_eq!(deduped[1].detail, "second");
        assert_eq!(deduped[2].detail, "third");
    }

    #[test]
    fn dedupe_diffs_many_duplicates() {
        let diff = TraceReplayDiff {
            index: 5,
            event_type: "gossip".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "repeated".to_string(),
        };
        let diffs = vec![diff.clone(), diff.clone(), diff.clone(), diff.clone(), diff];
        let deduped = dedupe_diffs(diffs);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn dedupe_diffs_partial_overlap() {
        let d1 = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("a".to_string()),
            actual_decision: Some("b".to_string()),
            detail: "mismatch".to_string(),
        };
        let d2 = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("a".to_string()),
            actual_decision: Some("c".to_string()), // different
            detail: "mismatch".to_string(),
        };
        let deduped = dedupe_diffs(vec![d1.clone(), d1, d2]);
        assert_eq!(deduped.len(), 2);
    }

    // ---- compare_traces edge cases ----

    #[test]
    fn compare_traces_single_event_match() {
        let mut trace = CapturedTrace::new("single");
        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 100,
            trace_id: "t1".to_string(),
            source_node: "n1".to_string(),
            target_node: None,
            object_id: "o1".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        }));
        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.matched_events, 1);
        assert_eq!(summary.matched_decisions, 1);
    }

    #[test]
    fn compare_traces_decision_mismatch() {
        let mut expected = CapturedTrace::new("expected");
        expected.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 100,
            trace_id: "t1".to_string(),
            source_node: "n1".to_string(),
            target_node: None,
            object_id: "o1".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        }));

        let mut actual = CapturedTrace::new("actual");
        actual.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 100,
            trace_id: "t1".to_string(),
            source_node: "n1".to_string(),
            target_node: None,
            object_id: "o1".to_string(),
            path_type: "direct".to_string(),
            decision: "dropped".to_string(),
            reason: None,
        }));

        let (diffs, summary) = compare_traces(&expected, &actual);
        assert!(!diffs.is_empty());
        assert_eq!(summary.mismatched_decisions, 1);
        assert!(diffs.iter().any(|d| d.detail == "decision mismatch"));
    }

    #[test]
    fn compare_traces_with_gossip_events_no_decisions() {
        use fcp_telemetry::trace_capture::GossipEvent;
        let mut trace = CapturedTrace::new("gossip-trace");
        trace.push(TraceEvent::Gossip(GossipEvent {
            timestamp: 100,
            trace_id: "t1".to_string(),
            gossip_type: "announce".to_string(),
            object_count: 3,
            peer_node: Some("peer-1".to_string()),
            success: true,
        }));
        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.total_events, 1);
        assert_eq!(summary.matched_events, 1);
        // Gossip has no decision
        assert_eq!(summary.matched_decisions, 0);
        assert_eq!(summary.mismatched_decisions, 0);
    }

    #[test]
    fn compare_traces_with_lease_events() {
        use fcp_telemetry::trace_capture::LeaseEvent;
        let mut trace = CapturedTrace::new("lease-trace");
        trace.push(TraceEvent::Lease(LeaseEvent {
            timestamp: 200,
            trace_id: "t2".to_string(),
            operation: "acquire".to_string(),
            subject_id: "sub-1".to_string(),
            purpose: "singleton_writer".to_string(),
            node_id: "node-a".to_string(),
            success: true,
            conflict_holder: None,
        }));
        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.event_type_counts["lease"], 1);
    }

    #[test]
    fn compare_traces_with_session_events() {
        use fcp_telemetry::trace_capture::SessionEvent;
        let mut trace = CapturedTrace::new("session-trace");
        trace.push(TraceEvent::Session(SessionEvent {
            timestamp: 300,
            trace_id: "t3".to_string(),
            session_id: "sess-abc".to_string(),
            kind: "hello".to_string(),
            peer_node: "peer-2".to_string(),
            suite: None,
            failure_reason: None,
        }));
        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.event_type_counts["session"], 1);
    }

    #[test]
    fn compare_traces_mixed_event_types() {
        use fcp_telemetry::trace_capture::{GossipEvent, LeaseEvent, SessionEvent};
        let mut trace = CapturedTrace::new("mixed");
        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: "t".to_string(),
            source_node: "n".to_string(),
            target_node: None,
            object_id: "o".to_string(),
            path_type: "d".to_string(),
            decision: "r".to_string(),
            reason: None,
        }));
        trace.push(TraceEvent::Admission(AdmissionOutcome {
            timestamp: 2,
            trace_id: "t".to_string(),
            peer_node: "p".to_string(),
            request_type: "i".to_string(),
            decision: "a".to_string(),
            reason_code: None,
            budget_remaining: None,
            authenticated: true,
        }));
        trace.push(TraceEvent::Gossip(GossipEvent {
            timestamp: 3,
            trace_id: "t".to_string(),
            gossip_type: "reconcile".to_string(),
            object_count: 0,
            peer_node: None,
            success: true,
        }));
        trace.push(TraceEvent::Lease(LeaseEvent {
            timestamp: 4,
            trace_id: "t".to_string(),
            operation: "renew".to_string(),
            subject_id: "s".to_string(),
            purpose: "op".to_string(),
            node_id: "n".to_string(),
            success: true,
            conflict_holder: None,
        }));
        trace.push(TraceEvent::Session(SessionEvent {
            timestamp: 5,
            trace_id: "t".to_string(),
            session_id: "s".to_string(),
            kind: "ack".to_string(),
            peer_node: "p".to_string(),
            suite: None,
            failure_reason: None,
        }));
        trace.push(TraceEvent::Policy(PolicyDecision {
            timestamp: 6,
            trace_id: "t".to_string(),
            zone_id: "z".to_string(),
            operation: "op".to_string(),
            connector_id: "c".to_string(),
            decision: "deny".to_string(),
            reason_code: "NO_CAP".to_string(),
            evidence: vec![],
        }));

        let (diffs, summary) = compare_traces(&trace, &trace);
        assert!(diffs.is_empty());
        assert_eq!(summary.total_events, 6);
        assert_eq!(summary.matched_events, 6);
        assert_eq!(summary.event_type_counts.len(), 6);
        // 3 events have decisions: routing, admission, policy
        assert_eq!(summary.matched_decisions, 3);
    }

    #[test]
    fn compare_traces_actual_longer_than_expected() {
        let mut expected = CapturedTrace::new("short");
        expected.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: "t".to_string(),
            source_node: "n".to_string(),
            target_node: None,
            object_id: "o".to_string(),
            path_type: "d".to_string(),
            decision: "r".to_string(),
            reason: None,
        }));

        let mut actual = CapturedTrace::new("long");
        actual.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: "t".to_string(),
            source_node: "n".to_string(),
            target_node: None,
            object_id: "o".to_string(),
            path_type: "d".to_string(),
            decision: "r".to_string(),
            reason: None,
        }));
        actual.push(TraceEvent::Policy(PolicyDecision {
            timestamp: 2,
            trace_id: "t".to_string(),
            zone_id: "z".to_string(),
            operation: "op".to_string(),
            connector_id: "c".to_string(),
            decision: "allow".to_string(),
            reason_code: "OK".to_string(),
            evidence: vec![],
        }));

        let (diffs, summary) = compare_traces(&expected, &actual);
        assert!(!diffs.is_empty());
        assert!(diffs.iter().any(|d| d.detail == "unexpected replay event"));
        assert_eq!(summary.total_events, 1); // total_events is from expected
    }

    #[test]
    fn compare_traces_both_empty() {
        let t1 = CapturedTrace::new("e1");
        let t2 = CapturedTrace::new("e2");
        let (diffs, summary) = compare_traces(&t1, &t2);
        assert!(diffs.is_empty());
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.matched_events, 0);
        assert_eq!(summary.mismatched_events, 0);
    }

    // ---- decode_trace_bytes edge cases ----

    #[test]
    fn decode_trace_auto_prefers_json_for_json_like() {
        let trace = sample_trace();
        let json = trace.to_json().expect("to_json");
        let parsed = decode_trace_bytes(json.as_bytes(), TraceReplayInputFormat::Auto)
            .expect("auto should pick json");
        assert_eq!(parsed.events.len(), trace.events.len());
    }

    #[test]
    fn decode_trace_auto_prefers_cbor_for_binary() {
        let trace = sample_trace();
        let cbor = trace.to_cbor().expect("to_cbor");
        // CBOR does not start with { or [, so auto tries CBOR first
        let parsed =
            decode_trace_bytes(&cbor, TraceReplayInputFormat::Auto).expect("auto should pick cbor");
        assert_eq!(parsed.events.len(), trace.events.len());
    }

    #[test]
    fn decode_trace_cbor_rejects_json() {
        let trace = sample_trace();
        let json = trace.to_json().expect("to_json");
        // CBOR format should reject valid JSON text
        assert!(decode_trace_bytes(json.as_bytes(), TraceReplayInputFormat::Cbor).is_err());
    }

    #[test]
    fn decode_trace_empty_bytes_all_formats() {
        assert!(decode_trace_bytes(b"", TraceReplayInputFormat::Json).is_err());
        assert!(decode_trace_bytes(b"", TraceReplayInputFormat::Cbor).is_err());
        assert!(decode_trace_bytes(b"", TraceReplayInputFormat::Auto).is_err());
    }

    #[test]
    fn decode_trace_truncated_json() {
        assert!(decode_trace_bytes(b"{\"id\":", TraceReplayInputFormat::Json).is_err());
    }

    #[test]
    fn decode_trace_non_utf8_json() {
        let bad_bytes: &[u8] = &[0xff, 0xfe, 0x7b]; // invalid UTF-8 then {
        assert!(decode_trace_bytes(bad_bytes, TraceReplayInputFormat::Json).is_err());
    }

    // ---- replay with various trace configurations ----

    #[test]
    fn replay_empty_trace() {
        let trace = CapturedTrace::new("empty-replay");
        let report = TraceReplayEngine::replay(&trace).expect("replay empty trace");
        assert_eq!(report.input_events, 0);
        assert_eq!(report.replayed_events, 0);
        assert!(report.diffs.is_empty());
        assert_eq!(report.summary.total_events, 0);
    }

    #[test]
    fn replay_trace_source_id_preserved() {
        let trace = CapturedTrace::new("my-unique-trace-id");
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert_eq!(report.source_trace_id, "my-unique-trace-id");
    }

    #[test]
    fn replay_trace_capturing_node_preserved() {
        let mut trace = CapturedTrace::new("t");
        trace.capturing_node = Some("my-node".to_string());
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert_eq!(report.source_capturing_node.as_deref(), Some("my-node"));
    }

    #[test]
    fn replay_trace_no_capturing_node_uses_default() {
        let trace = CapturedTrace::new("t");
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert!(report.source_capturing_node.is_none());
    }

    #[test]
    fn replay_single_routing_event() {
        let mut trace = CapturedTrace::new("single-routing");
        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 500,
            trace_id: "tr-1".to_string(),
            source_node: "src".to_string(),
            target_node: Some("dst".to_string()),
            object_id: "obj-x".to_string(),
            path_type: "relay".to_string(),
            decision: "forwarded".to_string(),
            reason: Some("best path".to_string()),
        }));
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert_eq!(report.input_events, 1);
        assert_eq!(report.replayed_events, 1);
    }

    #[test]
    fn replay_single_admission_event() {
        let mut trace = CapturedTrace::new("single-admission");
        trace.push(TraceEvent::Admission(AdmissionOutcome {
            timestamp: 600,
            trace_id: "tr-2".to_string(),
            peer_node: "peer-x".to_string(),
            request_type: "query".to_string(),
            decision: "deny".to_string(),
            reason_code: Some("RATE_LIMITED".to_string()),
            budget_remaining: Some(0),
            authenticated: false,
        }));
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert_eq!(report.input_events, 1);
        assert_eq!(report.summary.expected_decision_counts["deny"], 1);
    }

    #[test]
    fn replay_single_policy_event() {
        let mut trace = CapturedTrace::new("single-policy");
        trace.push(TraceEvent::Policy(PolicyDecision {
            timestamp: 700,
            trace_id: "tr-3".to_string(),
            zone_id: "z:prod".to_string(),
            operation: "op.write".to_string(),
            connector_id: "fcp.storage".to_string(),
            decision: "deny".to_string(),
            reason_code: "NO_CAP".to_string(),
            evidence: vec!["ev-1".to_string(), "ev-2".to_string()],
        }));
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert_eq!(report.input_events, 1);
    }

    #[test]
    fn replay_gossip_lease_session_events() {
        use fcp_telemetry::trace_capture::{GossipEvent, LeaseEvent, SessionEvent};
        let mut trace = CapturedTrace::new("non-decision-events");
        trace.push(TraceEvent::Gossip(GossipEvent {
            timestamp: 100,
            trace_id: "t".to_string(),
            gossip_type: "announce".to_string(),
            object_count: 2,
            peer_node: None,
            success: true,
        }));
        trace.push(TraceEvent::Lease(LeaseEvent {
            timestamp: 200,
            trace_id: "t".to_string(),
            operation: "acquire".to_string(),
            subject_id: "s1".to_string(),
            purpose: "op".to_string(),
            node_id: "n1".to_string(),
            success: true,
            conflict_holder: None,
        }));
        trace.push(TraceEvent::Session(SessionEvent {
            timestamp: 300,
            trace_id: "t".to_string(),
            session_id: "s".to_string(),
            kind: "established".to_string(),
            peer_node: "p".to_string(),
            suite: Some("chacha".to_string()),
            failure_reason: None,
        }));
        let report = TraceReplayEngine::replay(&trace).expect("replay");
        assert_eq!(report.input_events, 3);
        assert_eq!(report.replayed_events, 3);
    }

    // ---- load_trace_from_path error ----

    #[test]
    fn load_trace_from_nonexistent_path() {
        let result = TraceReplayEngine::load_trace_from_path(
            "/tmp/nonexistent_trace_file_abc123.json",
            TraceReplayInputFormat::Json,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nonexistent_trace_file_abc123"));
    }

    #[test]
    fn replay_path_nonexistent() {
        let result = TraceReplayEngine::replay_path(
            "/tmp/no_such_trace_xyz.cbor",
            TraceReplayInputFormat::Cbor,
        );
        assert!(result.is_err());
    }

    // ---- JSON roundtrip for TraceReplayInputFormat deserialization edge cases ----

    #[test]
    fn trace_replay_input_format_deserialize_unknown_rejects() {
        let result = serde_json::from_str::<TraceReplayInputFormat>("\"xml\"");
        assert!(result.is_err());
    }

    #[test]
    fn trace_replay_input_format_deserialize_number_rejects() {
        let result = serde_json::from_str::<TraceReplayInputFormat>("42");
        assert!(result.is_err());
    }

    // ---- TraceReplayReport serde with multiple diffs ----

    #[test]
    fn trace_replay_report_serde_multiple_diffs() {
        let diffs = vec![
            TraceReplayDiff {
                index: 0,
                event_type: "routing".to_string(),
                expected_decision: Some("a".to_string()),
                actual_decision: Some("b".to_string()),
                detail: "d1".to_string(),
            },
            TraceReplayDiff {
                index: 1,
                event_type: "admission".to_string(),
                expected_decision: None,
                actual_decision: Some("x".to_string()),
                detail: "d2".to_string(),
            },
            TraceReplayDiff {
                index: 2,
                event_type: "policy".to_string(),
                expected_decision: Some("allow".to_string()),
                actual_decision: None,
                detail: "d3".to_string(),
            },
        ];
        let report = TraceReplayReport {
            source_trace_id: "multi-diff".to_string(),
            source_capturing_node: Some("n1".to_string()),
            input_events: 3,
            replayed_events: 2,
            summary: TraceReplaySummary {
                total_events: 3,
                event_type_counts: BTreeMap::new(),
                expected_decision_counts: BTreeMap::new(),
                actual_decision_counts: BTreeMap::new(),
                matched_events: 0,
                mismatched_events: 3,
                matched_decisions: 0,
                mismatched_decisions: 3,
            },
            diffs,
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: TraceReplayReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.diffs.len(), 3);
    }

    // ---- TraceReplayDiff equality ----

    #[test]
    fn trace_replay_diff_equality_sensitive_to_all_fields() {
        let base = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: Some("a".to_string()),
            actual_decision: Some("b".to_string()),
            detail: "mismatch".to_string(),
        };

        let diff_index = TraceReplayDiff {
            index: 1,
            ..base.clone()
        };
        assert_ne!(base, diff_index);

        let diff_type = TraceReplayDiff {
            event_type: "admission".to_string(),
            ..base.clone()
        };
        assert_ne!(base, diff_type);

        let diff_expected = TraceReplayDiff {
            expected_decision: None,
            ..base.clone()
        };
        assert_ne!(base, diff_expected);

        let diff_actual = TraceReplayDiff {
            actual_decision: Some("z".to_string()),
            ..base.clone()
        };
        assert_ne!(base, diff_actual);

        let diff_detail = TraceReplayDiff {
            detail: "other".to_string(),
            ..base.clone()
        };
        assert_ne!(base, diff_detail);
    }

    // ---- compare_traces decision counting ----

    #[test]
    fn compare_traces_counts_expected_decisions() {
        let mut trace = CapturedTrace::new("count-test");
        trace.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 0,
            trace_id: String::new(),
            source_node: String::new(),
            target_node: None,
            object_id: String::new(),
            path_type: String::new(),
            decision: "allow".to_string(),
            reason: None,
        }));
        trace.push(TraceEvent::Admission(AdmissionOutcome {
            timestamp: 1,
            trace_id: String::new(),
            peer_node: String::new(),
            request_type: String::new(),
            decision: "allow".to_string(),
            reason_code: None,
            budget_remaining: None,
            authenticated: true,
        }));
        trace.push(TraceEvent::Policy(PolicyDecision {
            timestamp: 2,
            trace_id: String::new(),
            zone_id: String::new(),
            operation: String::new(),
            connector_id: String::new(),
            decision: "deny".to_string(),
            reason_code: String::new(),
            evidence: vec![],
        }));

        let (_, summary) = compare_traces(&trace, &trace);
        assert_eq!(summary.expected_decision_counts["allow"], 2);
        assert_eq!(summary.expected_decision_counts["deny"], 1);
    }

    // ---- Summary mismatched_events calculation ----

    #[test]
    fn summary_mismatched_events_calculated_correctly() {
        let mut expected = CapturedTrace::new("e");
        expected.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 0,
            trace_id: String::new(),
            source_node: String::new(),
            target_node: None,
            object_id: String::new(),
            path_type: String::new(),
            decision: "a".to_string(),
            reason: None,
        }));
        expected.push(TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: String::new(),
            source_node: String::new(),
            target_node: None,
            object_id: String::new(),
            path_type: String::new(),
            decision: "b".to_string(),
            reason: None,
        }));
        // actual has none of these
        let actual = CapturedTrace::new("a");
        let (_, summary) = compare_traces(&expected, &actual);
        assert_eq!(summary.mismatched_events, 2);
        assert_eq!(summary.matched_events, 0);
    }
}
