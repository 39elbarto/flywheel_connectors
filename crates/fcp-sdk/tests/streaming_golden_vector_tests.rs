//! Golden vector tests for SDK streaming functionality.
//!
//! These tests validate streaming behavior against canonical test vectors stored
//! in `tests/vectors/streaming/`. This ensures deterministic, spec-compliant behavior.

#![allow(dead_code)]

use fcp_sdk::prelude::*;
use fcp_sdk::streaming::{BufferLimits, EventStreamManager, ReplayError};
use serde::Deserialize;
use serde_json::json;
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Vector File Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CursorFormatsVectors {
    valid_cursors: Vec<ValidCursor>,
    invalid_cursors: Vec<InvalidCursor>,
    stale_cursor_scenarios: Vec<StaleCursorScenario>,
}

#[derive(Debug, Deserialize)]
struct ValidCursor {
    input: String,
    expected_seq: Option<u64>,
    description: String,
    #[serde(default)]
    special: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InvalidCursor {
    input: String,
    expected_error: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct StaleCursorScenario {
    buffer_oldest_seq: u64,
    buffer_newest_seq: u64,
    requested_cursor: String,
    #[serde(default)]
    expected_error: Option<String>,
    #[serde(default)]
    expected_result_count: Option<usize>,
    description: String,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct AckSequencesVectors {
    ack_scenarios: Vec<AckScenario>,
    nack_scenarios: Vec<NackScenario>,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Deserialize)]
struct AckScenario {
    name: String,
    description: String,
    initial_state: AckInitialState,
    action: AckAction,
    expected_result: AckExpectedResult,
}

#[derive(Debug, Deserialize)]
struct AckInitialState {
    pending_acks: Vec<u64>,
    buffer_seqs: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct AckAction {
    #[serde(rename = "type")]
    action_type: String,
    seqs: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct AckExpectedResult {
    acked: Vec<u64>,
    missing: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct NackScenario {
    name: String,
    description: String,
    initial_state: AckInitialState,
    action: NackAction,
    expected_result: NackExpectedResult,
}

#[derive(Debug, Deserialize)]
struct NackAction {
    #[serde(rename = "type")]
    action_type: String,
    seqs: Vec<u64>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct NackExpectedResult {
    redeliver_seqs: Vec<u64>,
    missing: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct ReplayScenario {
    name: String,
    description: String,
    initial_state: ReplayInitialState,
    action: ReplayAction,
    expected_result: ReplayExpectedResult,
}

#[derive(Debug, Deserialize)]
struct ReplayInitialState {
    buffer_seqs: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct ReplayAction {
    #[serde(rename = "type")]
    action_type: String,
    cursor: String,
}

#[derive(Debug, Deserialize)]
struct ReplayExpectedResult {
    replayed_seqs: Vec<u64>,
    error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

fn load_cursor_vectors() -> CursorFormatsVectors {
    let content = fs::read_to_string("tests/vectors/streaming/cursor_formats.json")
        .expect("Failed to read cursor_formats.json");
    serde_json::from_str(&content).expect("Failed to parse cursor_formats.json")
}

fn load_ack_vectors() -> AckSequencesVectors {
    let content = fs::read_to_string("tests/vectors/streaming/ack_sequences.json")
        .expect("Failed to read ack_sequences.json");
    serde_json::from_str(&content).expect("Failed to parse ack_sequences.json")
}

fn sample_event_data() -> EventData {
    EventData::new(
        ConnectorId::from_static("test:golden:v1"),
        InstanceId::new(),
        ZoneId::work(),
        Principal {
            kind: "user".to_string(),
            id: "test-user".to_string(),
            trust: TrustLevel::Paired,
            display: Some("Test User".to_string()),
        },
        json!({"test": "data"}),
    )
}

const fn event_caps(replay: bool, requires_ack: bool, min_buffer: u32) -> EventCaps {
    EventCaps {
        streaming: true,
        replay,
        min_buffer_events: min_buffer,
        requires_ack,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor Format Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_valid_cursors_from_vectors() {
    let vectors = load_cursor_vectors();

    for cursor in vectors.valid_cursors {
        if cursor.special.as_deref() == Some("replay_all") {
            // Empty cursor is handled specially by replay_from
            continue;
        }

        let parsed: Result<u64, _> = cursor.input.parse();
        assert!(
            parsed.is_ok(),
            "Vector '{}' ({}) should parse as u64",
            cursor.input,
            cursor.description
        );

        if let Some(expected) = cursor.expected_seq {
            assert_eq!(
                parsed.unwrap(),
                expected,
                "Vector '{}' ({}) should equal {}",
                cursor.input,
                cursor.description,
                expected
            );
        }
    }
}

#[test]
fn test_invalid_cursors_from_vectors() {
    let vectors = load_cursor_vectors();
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Emit an event so the topic exists
    manager.emit("test.topic", sample_event_data());

    for cursor in vectors.invalid_cursors {
        let result = manager.replay_from("test.topic", &cursor.input);

        assert!(
            matches!(result, Err(ReplayError::InvalidCursor { .. })),
            "Vector '{}' ({}) should produce InvalidCursor error, got {:?}",
            cursor.input,
            cursor.description,
            result
        );
    }
}

#[test]
fn test_stale_cursor_scenarios_from_vectors() {
    let vectors = load_cursor_vectors();

    for scenario in vectors.stale_cursor_scenarios {
        let mut manager = EventStreamManager::with_limits(
            event_caps(true, false, 1000),
            BufferLimits::new(1000, 1000),
        );

        // Populate buffer with events from oldest to newest
        for seq in scenario.buffer_oldest_seq..=scenario.buffer_newest_seq {
            manager.emit_with_seq("test.topic", seq, sample_event_data());
        }

        let result = manager.replay_from("test.topic", &scenario.requested_cursor);

        match (&scenario.expected_error, scenario.expected_result_count) {
            (Some(err), _) if err == "CursorStale" => {
                assert!(
                    matches!(result, Err(ReplayError::CursorStale { .. })),
                    "Scenario '{}' should produce CursorStale error, got {:?}",
                    scenario.description,
                    result
                );
            }
            (None, Some(count)) => {
                let events = result.unwrap_or_else(|_| {
                    panic!("Scenario '{}' should succeed", scenario.description)
                });
                assert_eq!(
                    events.len(),
                    count,
                    "Scenario '{}' should return {} events, got {}",
                    scenario.description,
                    count,
                    events.len()
                );
            }
            _ => panic!("Invalid test vector: {}", scenario.description),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ack Sequence Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_ack_scenarios_from_vectors() {
    let vectors = load_ack_vectors();

    for scenario in vectors.ack_scenarios {
        let mut manager = EventStreamManager::new(event_caps(true, true, 100));

        // Setup initial state
        for seq in &scenario.initial_state.buffer_seqs {
            manager.emit_with_seq("test.ack", *seq, sample_event_data());
        }

        // Build ack request
        let ack = EventAck::new("test.ack", scenario.action.seqs.clone()).with_cursors(
            scenario
                .action
                .seqs
                .iter()
                .map(ToString::to_string)
                .collect(),
        );

        // Execute
        let result = manager.handle_ack(&ack);

        // Verify
        assert_eq!(
            result.acked, scenario.expected_result.acked,
            "Scenario '{}' ({}) acked mismatch",
            scenario.name, scenario.description
        );
        assert_eq!(
            result.missing, scenario.expected_result.missing,
            "Scenario '{}' ({}) missing mismatch",
            scenario.name, scenario.description
        );
    }
}

#[test]
fn test_nack_scenarios_from_vectors() {
    let vectors = load_ack_vectors();

    for scenario in vectors.nack_scenarios {
        let mut manager = EventStreamManager::new(event_caps(true, true, 100));

        // Setup initial state
        for seq in &scenario.initial_state.buffer_seqs {
            manager.emit_with_seq("test.nack", *seq, sample_event_data());
        }

        // Build nack request
        let nack = EventNack::new(
            "test.nack",
            scenario.action.seqs.clone(),
            scenario.action.reason.clone(),
        );

        // Execute
        let result = manager.handle_nack(&nack);

        // Verify redeliver sequences
        let redeliver_seqs: Vec<u64> = result.redeliver.iter().map(|e| e.seq).collect();
        assert_eq!(
            redeliver_seqs, scenario.expected_result.redeliver_seqs,
            "Scenario '{}' ({}) redeliver mismatch",
            scenario.name, scenario.description
        );
        assert_eq!(
            result.missing, scenario.expected_result.missing,
            "Scenario '{}' ({}) missing mismatch",
            scenario.name, scenario.description
        );
    }
}

#[test]
fn test_replay_scenarios_from_vectors() {
    let vectors = load_ack_vectors();

    for scenario in vectors.replay_scenarios {
        let mut manager = EventStreamManager::new(event_caps(true, false, 100));

        // Setup initial state
        for seq in &scenario.initial_state.buffer_seqs {
            manager.emit_with_seq("test.replay", *seq, sample_event_data());
        }

        // Execute replay
        let result = manager.replay_from("test.replay", &scenario.action.cursor);

        // Verify
        if let Some(ref err) = scenario.expected_result.error {
            assert!(
                result.is_err(),
                "Scenario '{}' ({}) should error with {}",
                scenario.name,
                scenario.description,
                err
            );
        } else {
            let events =
                result.unwrap_or_else(|_| panic!("Scenario '{}' should succeed", scenario.name));
            let replayed_seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
            assert_eq!(
                replayed_seqs, scenario.expected_result.replayed_seqs,
                "Scenario '{}' ({}) replayed seqs mismatch",
                scenario.name, scenario.description
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism Tests (ensure same input produces same output)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cursor_assignment_deterministic() {
    // Two managers with same sequence of operations should produce identical cursors
    let mut manager1 = EventStreamManager::new(event_caps(true, false, 10));
    let mut manager2 = EventStreamManager::new(event_caps(true, false, 10));

    let e1_1 = manager1.emit("determinism.test", sample_event_data());
    let e1_2 = manager2.emit("determinism.test", sample_event_data());

    assert_eq!(e1_1.seq, e1_2.seq, "Sequences must match");
    assert_eq!(e1_1.cursor, e1_2.cursor, "Cursors must match");

    let e2_1 = manager1.emit("determinism.test", sample_event_data());
    let e2_2 = manager2.emit("determinism.test", sample_event_data());

    assert_eq!(e2_1.seq, e2_2.seq);
    assert_eq!(e2_1.cursor, e2_2.cursor);
}

#[test]
fn test_replay_order_deterministic() {
    let mut manager = EventStreamManager::new(event_caps(true, false, 10));

    // Emit events
    for i in 0..5 {
        manager.emit_with_seq("order.test", i, sample_event_data());
    }

    // Replay twice and compare
    let replay1 = manager.replay_from("order.test", "").unwrap();
    let replay2 = manager.replay_from("order.test", "").unwrap();

    assert_eq!(replay1.len(), replay2.len());
    for (e1, e2) in replay1.iter().zip(replay2.iter()) {
        assert_eq!(e1.seq, e2.seq);
        assert_eq!(e1.cursor, e2.cursor);
    }
}
