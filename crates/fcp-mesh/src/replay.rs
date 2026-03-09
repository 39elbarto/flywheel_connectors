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
            .trace_snapshot()
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

    use fcp_telemetry::trace_capture::{
        AdmissionOutcome, GossipEvent, LeaseEvent, PolicyDecision, RoutingDecision, SessionEvent,
    };

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

    // ── Batch: additional replay tests ──

    #[test]
    fn trace_replay_diff_clone() {
        let diff = TraceReplayDiff {
            index: 3,
            event_type: "admission".to_string(),
            expected_decision: Some("deny".to_string()),
            actual_decision: None,
            detail: "missing".to_string(),
        };
        let cloned = diff.clone();
        assert_eq!(diff, cloned);
    }

    #[test]
    fn trace_replay_diff_debug() {
        let diff = TraceReplayDiff {
            index: 0,
            event_type: "routing".to_string(),
            expected_decision: None,
            actual_decision: None,
            detail: "test".to_string(),
        };
        let debug = format!("{diff:?}");
        assert!(debug.contains("TraceReplayDiff"));
    }

    #[test]
    fn trace_replay_summary_clone() {
        let summary = TraceReplaySummary {
            total_events: 5,
            event_type_counts: BTreeMap::new(),
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
    fn trace_replay_report_clone() {
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
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    #[test]
    fn trace_replay_input_format_clone_copy() {
        let fmt = TraceReplayInputFormat::Cbor;
        let cloned = fmt;
        assert_eq!(fmt, cloned);
    }

    #[test]
    fn event_type_label_gossip() {
        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 0,
            trace_id: String::new(),
            gossip_type: String::new(),
            object_count: 0,
            peer_node: None,
            success: true,
        });
        assert_eq!(event_type_label(&event), "gossip");
    }

    #[test]
    fn event_type_label_lease() {
        let event = TraceEvent::Lease(LeaseEvent {
            timestamp: 0,
            trace_id: String::new(),
            operation: String::new(),
            subject_id: String::new(),
            purpose: String::new(),
            node_id: String::new(),
            success: true,
            conflict_holder: None,
        });
        assert_eq!(event_type_label(&event), "lease");
    }

    #[test]
    fn event_type_label_session() {
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 0,
            trace_id: String::new(),
            session_id: String::new(),
            kind: String::new(),
            peer_node: String::new(),
            suite: None,
            failure_reason: None,
        });
        assert_eq!(event_type_label(&event), "session");
    }

    #[test]
    fn decision_label_gossip_is_none() {
        let event = TraceEvent::Gossip(GossipEvent {
            timestamp: 0,
            trace_id: String::new(),
            gossip_type: String::new(),
            object_count: 0,
            peer_node: None,
            success: true,
        });
        assert!(decision_label(&event).is_none());
    }

    #[test]
    fn decision_label_lease_is_none() {
        let event = TraceEvent::Lease(LeaseEvent {
            timestamp: 0,
            trace_id: String::new(),
            operation: String::new(),
            subject_id: String::new(),
            purpose: String::new(),
            node_id: String::new(),
            success: true,
            conflict_holder: None,
        });
        assert!(decision_label(&event).is_none());
    }

    #[test]
    fn decision_label_session_is_none() {
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 0,
            trace_id: String::new(),
            session_id: String::new(),
            kind: String::new(),
            peer_node: String::new(),
            suite: None,
            failure_reason: None,
        });
        assert!(decision_label(&event).is_none());
    }

    #[test]
    fn load_trace_from_nonexistent_path() {
        let result =
            TraceReplayEngine::load_trace_from_path("/nonexistent/path.json", TraceReplayInputFormat::Auto);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("/nonexistent/path.json"));
    }

    #[test]
    fn replay_path_nonexistent_returns_io_error() {
        let result =
            TraceReplayEngine::replay_path("/nonexistent.json", TraceReplayInputFormat::Json);
        assert!(result.is_err());
    }

    #[test]
    fn looks_like_json_plain_text() {
        assert!(!looks_like_json(b"hello world"));
    }

    #[test]
    fn looks_like_json_only_whitespace() {
        assert!(!looks_like_json(b"   \n\t  "));
    }
}
