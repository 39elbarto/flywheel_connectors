//! Session-Script DSL for streaming, websocket, SSE, long-poll, and webhook
//! acceptance testing.
//!
//! This module provides a canonical vocabulary for scripting and recording
//! session-oriented connector test scenarios.  Every streaming, bidirectional,
//! polling, or webhook acceptance test speaks this DSL so that:
//!
//! - Scripts are portable across connector families.
//! - Transcripts are machine-readable and align with the E2E log schema.
//! - Health assertions use the same `StreamHealthState` model as production.
//!
//! # Architecture
//!
//! A **session script** is a sequence of [`ScriptStep`] values that describe
//! what the test harness should do (send, expect, wait, assert health, inject
//! faults, etc.).  Executing a script against a connector produces a
//! **transcript** — a timestamped log of what actually happened.
//!
//! ```text
//! ScriptStep[]  ──▶  SessionRunner  ──▶  Transcript
//!                        │
//!                   connector under test
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::session_script::*;
//!
//! let script = SessionScript::new("websocket.reconnect_after_drop")
//!     .step(ScriptStep::connect(Transport::WebSocket, "/ws"))
//!     .step(ScriptStep::expect_message(json!({"type": "hello"})))
//!     .step(ScriptStep::send_message(json!({"type": "ping"})))
//!     .step(ScriptStep::expect_message(json!({"type": "pong"})))
//!     .step(ScriptStep::inject_fault(Fault::ConnectionDrop))
//!     .step(ScriptStep::assert_health(ScriptHealthState::Reconnecting))
//!     .step(ScriptStep::wait(Duration::from_millis(500)))
//!     .step(ScriptStep::assert_health(ScriptHealthState::Connected))
//!     .step(ScriptStep::disconnect());
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Transport protocol for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    WebSocket,
    Sse,
    LongPoll,
    WebhookIngress,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebSocket => write!(f, "websocket"),
            Self::Sse => write!(f, "sse"),
            Self::LongPoll => write!(f, "long_poll"),
            Self::WebhookIngress => write!(f, "webhook_ingress"),
        }
    }
}

// ---------------------------------------------------------------------------
// StreamHealthState (mirrors fcp-streaming::health but self-contained)
// ---------------------------------------------------------------------------

/// Health state used in script assertions.  Mirrors
/// `fcp_streaming::StreamHealthState` but is self-contained so test scripts
/// do not depend on the streaming crate at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ScriptHealthState {
    Connected,
    Degraded,
    Reconnecting,
    Unhealthy,
}

impl std::fmt::Display for ScriptHealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Degraded => write!(f, "degraded"),
            Self::Reconnecting => write!(f, "reconnecting"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

/// Simulated fault that the harness injects into the session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Fault {
    /// Drop the transport connection immediately.
    ConnectionDrop,
    /// Delay all outbound frames for the given duration.
    Latency {
        #[serde(with = "humantime_serde")]
        duration: Duration,
    },
    /// Reject the next N inbound frames with the given status.
    RejectFrames { count: u32, status: u16 },
    /// Corrupt the next outbound payload (bit-flip).
    CorruptPayload,
    /// Simulate server returning an error-close frame (websocket 1011, etc.).
    ErrorClose { code: u16 },
}

// ---------------------------------------------------------------------------
// Message matching
// ---------------------------------------------------------------------------

/// How to match an expected message against actual received data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum MessageMatcher {
    // NOTE: intentionally no Eq — serde_json::Value does not impl Eq
    /// Exact JSON equality.
    Exact { body: serde_json::Value },
    /// JSON sub-object match (all specified keys must match; extra keys OK).
    Contains { fragment: serde_json::Value },
    /// Regex match against the serialized JSON string.
    Regex { pattern: String },
    /// Match any message (just assert receipt within timeout).
    Any,
}

// ---------------------------------------------------------------------------
// Ack semantics
// ---------------------------------------------------------------------------

/// Acknowledgement mode for received messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AckMode {
    /// Automatically acknowledge after matching.
    Auto,
    /// Do not acknowledge (test nack / redelivery).
    Suppress,
    /// Acknowledge after a delay.
    Delayed,
}

// ---------------------------------------------------------------------------
// ScriptStep
// ---------------------------------------------------------------------------

/// A single step in a session script.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum ScriptStep {
    /// Open a connection to the given path.
    Connect {
        transport: Transport,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<Vec<(String, String)>>,
    },
    /// Close the connection gracefully.
    Disconnect,
    /// Send a message to the remote endpoint.
    SendMessage {
        body: serde_json::Value,
    },
    /// Expect a message matching the given criteria within the timeout.
    ExpectMessage {
        matcher: MessageMatcher,
        #[serde(
            default = "default_expect_timeout",
            with = "humantime_serde"
        )]
        timeout: Duration,
        #[serde(default = "default_ack_mode")]
        ack: AckMode,
    },
    /// Expect exactly N messages within the timeout.
    ExpectCount {
        count: u32,
        matcher: MessageMatcher,
        #[serde(
            default = "default_expect_timeout",
            with = "humantime_serde"
        )]
        timeout: Duration,
    },
    /// Expect no messages for the given duration (silence assertion).
    ExpectSilence {
        #[serde(with = "humantime_serde")]
        duration: Duration,
    },
    /// Wait without asserting anything.
    Wait {
        #[serde(with = "humantime_serde")]
        duration: Duration,
    },
    /// Assert the current health state.
    AssertHealth {
        expected: ScriptHealthState,
    },
    /// Assert the reconnect count.
    AssertReconnectCount {
        expected: u32,
    },
    /// Assert the total number of messages received so far.
    AssertMessagesReceived {
        min: u64,
    },
    /// Inject a simulated fault.
    InjectFault {
        fault: Fault,
    },
    /// Send a webhook payload to the connector's ingress endpoint.
    WebhookDeliver {
        event_type: String,
        body: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature_scheme: Option<String>,
    },
    /// Expect a webhook acknowledgement (HTTP 200-299).
    WebhookExpectAck {
        #[serde(
            default = "default_expect_timeout",
            with = "humantime_serde"
        )]
        timeout: Duration,
    },
    /// Log an annotation into the transcript.
    Annotate {
        message: String,
    },
}

const fn default_expect_timeout() -> Duration {
    Duration::from_secs(5)
}

const fn default_ack_mode() -> AckMode {
    AckMode::Auto
}

impl ScriptStep {
    // -- Convenience constructors --

    #[must_use]
    pub fn connect(transport: Transport, path: &str) -> Self {
        Self::Connect {
            transport,
            path: path.to_owned(),
            headers: None,
        }
    }

    #[must_use]
    pub fn connect_with_headers(
        transport: Transport,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self::Connect {
            transport,
            path: path.to_owned(),
            headers: Some(headers),
        }
    }

    #[must_use]
    pub fn disconnect() -> Self {
        Self::Disconnect
    }

    #[must_use]
    pub fn send_message(body: serde_json::Value) -> Self {
        Self::SendMessage { body }
    }

    #[must_use]
    pub fn expect_message(body: serde_json::Value) -> Self {
        Self::ExpectMessage {
            matcher: MessageMatcher::Exact { body },
            timeout: default_expect_timeout(),
            ack: AckMode::Auto,
        }
    }

    #[must_use]
    pub fn expect_message_containing(fragment: serde_json::Value) -> Self {
        Self::ExpectMessage {
            matcher: MessageMatcher::Contains { fragment },
            timeout: default_expect_timeout(),
            ack: AckMode::Auto,
        }
    }

    #[must_use]
    pub fn expect_any_message() -> Self {
        Self::ExpectMessage {
            matcher: MessageMatcher::Any,
            timeout: default_expect_timeout(),
            ack: AckMode::Auto,
        }
    }

    #[must_use]
    pub fn expect_count(count: u32, matcher: MessageMatcher) -> Self {
        Self::ExpectCount {
            count,
            matcher,
            timeout: default_expect_timeout(),
        }
    }

    #[must_use]
    pub fn expect_silence(duration: Duration) -> Self {
        Self::ExpectSilence { duration }
    }

    #[must_use]
    pub fn wait(duration: Duration) -> Self {
        Self::Wait { duration }
    }

    #[must_use]
    pub fn assert_health(expected: ScriptHealthState) -> Self {
        Self::AssertHealth { expected }
    }

    #[must_use]
    pub fn assert_reconnect_count(expected: u32) -> Self {
        Self::AssertReconnectCount { expected }
    }

    #[must_use]
    pub fn assert_messages_received(min: u64) -> Self {
        Self::AssertMessagesReceived { min }
    }

    #[must_use]
    pub fn inject_fault(fault: Fault) -> Self {
        Self::InjectFault { fault }
    }

    #[must_use]
    pub fn webhook_deliver(event_type: &str, body: serde_json::Value) -> Self {
        Self::WebhookDeliver {
            event_type: event_type.to_owned(),
            body,
            signature_scheme: None,
        }
    }

    #[must_use]
    pub fn webhook_expect_ack() -> Self {
        Self::WebhookExpectAck {
            timeout: default_expect_timeout(),
        }
    }

    #[must_use]
    pub fn annotate(message: &str) -> Self {
        Self::Annotate {
            message: message.to_owned(),
        }
    }

    /// Override the timeout for expect-style steps.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        match &mut self {
            Self::ExpectMessage { timeout: t, .. }
            | Self::ExpectCount { timeout: t, .. }
            | Self::WebhookExpectAck { timeout: t } => *t = timeout,
            _ => {}
        }
        self
    }

    /// Override the ack mode for expect-message steps.
    #[must_use]
    pub fn with_ack(mut self, ack: AckMode) -> Self {
        if let Self::ExpectMessage { ack: a, .. } = &mut self {
            *a = ack;
        }
        self
    }
}

// ---------------------------------------------------------------------------
// SessionScript
// ---------------------------------------------------------------------------

/// A complete session script: metadata + ordered steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionScript {
    /// Unique scenario identifier (e.g. `"websocket.reconnect_after_drop"`).
    pub scenario_id: String,
    /// Transport to use (can be overridden per-step via `Connect`).
    pub default_transport: Option<Transport>,
    /// Steps to execute in order.
    pub steps: Vec<ScriptStep>,
    /// Optional labels for categorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SessionScript {
    #[must_use]
    pub fn new(scenario_id: &str) -> Self {
        Self {
            scenario_id: scenario_id.to_owned(),
            default_transport: None,
            steps: Vec::new(),
            labels: Vec::new(),
            description: None,
        }
    }

    #[must_use]
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.default_transport = Some(transport);
        self
    }

    #[must_use]
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_owned());
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: &str) -> Self {
        self.labels.push(label.to_owned());
        self
    }

    #[must_use]
    pub fn step(mut self, step: ScriptStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Number of steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True if the script contains no steps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

}

// ---------------------------------------------------------------------------
// Transcript types
// ---------------------------------------------------------------------------

/// Outcome of executing a single script step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Pass,
    Fail,
    Skip,
    Timeout,
}

impl std::fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Skip => write!(f, "skip"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

/// A single entry in the session transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    /// Wall-clock timestamp.
    pub timestamp: DateTime<Utc>,
    /// Zero-based step index in the script.
    pub step_index: usize,
    /// The step that was executed.
    pub step: ScriptStep,
    /// Outcome.
    pub outcome: StepOutcome,
    /// Duration of this step.
    #[serde(with = "humantime_serde")]
    pub duration: Duration,
    /// Optional detail (error message, matched payload, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    /// Correlation ID (from `AsyncTestContext`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Complete transcript from executing a session script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript {
    /// Scenario identifier (from the script).
    pub scenario_id: String,
    /// Run identifier (from `AsyncTestContext`).
    pub run_id: String,
    /// Transport used.
    pub transport: Option<Transport>,
    /// Start time.
    pub started_at: DateTime<Utc>,
    /// End time.
    pub finished_at: DateTime<Utc>,
    /// Total wall-clock duration.
    #[serde(with = "humantime_serde")]
    pub total_duration: Duration,
    /// Per-step entries.
    pub entries: Vec<TranscriptEntry>,
    /// Overall outcome.
    pub outcome: StepOutcome,
    /// Number of steps that passed / failed / skipped / timed out.
    pub summary: TranscriptSummary,
}

/// Aggregate counts for a transcript.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TranscriptSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub timed_out: usize,
}

impl SessionTranscript {
    /// Convert to JSONL lines compatible with the E2E log schema.
    ///
    /// Each entry becomes one JSON object per line with the fields expected by
    /// `fcp_conformance::schemas::validate_e2e_log_entry`.
    ///
    /// # Panics
    ///
    /// Panics if any entry cannot be serialized to JSON (should not happen
    /// with well-formed transcript data).
    pub fn to_jsonl(&self) -> String {
        let mut lines = Vec::with_capacity(self.entries.len() + 2);
        // Header line
        let header = serde_json::json!({
            "timestamp": self.started_at.to_rfc3339(),
            "test_name": self.scenario_id,
            "module": "session_script",
            "phase": "setup",
            "correlation_id": self.run_id,
            "result": self.outcome.to_string(),
            "duration_ms": self.total_duration.as_millis() as u64,
            "assertions": {
                "passed": self.summary.passed,
                "failed": self.summary.failed
            }
        });
        lines.push(
            serde_json::to_string(&header).expect("transcript header should serialize"),
        );

        // Per-step lines
        for entry in &self.entries {
            let line = serde_json::json!({
                "timestamp": entry.timestamp.to_rfc3339(),
                "test_name": self.scenario_id,
                "module": "session_script",
                "phase": step_phase(&entry.step),
                "correlation_id": entry.correlation_id.as_deref()
                    .unwrap_or(&self.run_id),
                "step_number": entry.step_index,
                "result": entry.outcome.to_string(),
                "duration_ms": entry.duration.as_millis() as u64,
                "details": entry.detail,
            });
            lines.push(
                serde_json::to_string(&line).expect("transcript entry should serialize"),
            );
        }
        lines.join("\n")
    }

    /// True if every step passed.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        matches!(self.outcome, StepOutcome::Pass)
    }
}

/// Map a script step to its E2E log phase.
const fn step_phase(step: &ScriptStep) -> &'static str {
    match step {
        ScriptStep::Connect { .. } => "setup",
        ScriptStep::Disconnect => "teardown",
        ScriptStep::SendMessage { .. } => "invoke",
        ScriptStep::ExpectMessage { .. }
        | ScriptStep::ExpectCount { .. }
        | ScriptStep::ExpectSilence { .. } => "invoke",
        ScriptStep::Wait { .. } => "invoke",
        ScriptStep::AssertHealth { .. }
        | ScriptStep::AssertReconnectCount { .. }
        | ScriptStep::AssertMessagesReceived { .. } => "invoke",
        ScriptStep::InjectFault { .. } => "invoke",
        ScriptStep::WebhookDeliver { .. } => "invoke",
        ScriptStep::WebhookExpectAck { .. } => "invoke",
        ScriptStep::Annotate { .. } => "invoke",
    }
}

// ---------------------------------------------------------------------------
// Canonical scenario templates
// ---------------------------------------------------------------------------

/// Pre-built canonical scenarios that connector acceptance tests can reuse.
pub mod scenarios {
    use super::*;
    use std::time::Duration;

    /// WebSocket: connect, exchange hello/pong, verify health.
    #[must_use]
    pub fn websocket_hello_pong(path: &str) -> SessionScript {
        SessionScript::new("websocket.hello_pong")
            .with_transport(Transport::WebSocket)
            .with_description("Basic WebSocket hello/pong exchange")
            .step(ScriptStep::connect(Transport::WebSocket, path))
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::send_message(serde_json::json!({"type": "ping"})))
            .step(ScriptStep::expect_message_containing(
                serde_json::json!({"type": "pong"}),
            ))
            .step(ScriptStep::disconnect())
    }

    /// WebSocket: connect, drop connection, verify reconnection.
    #[must_use]
    pub fn websocket_reconnect(path: &str) -> SessionScript {
        SessionScript::new("websocket.reconnect_after_drop")
            .with_transport(Transport::WebSocket)
            .with_description("Verify reconnection after connection drop")
            .step(ScriptStep::connect(Transport::WebSocket, path))
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::inject_fault(Fault::ConnectionDrop))
            .step(ScriptStep::assert_health(ScriptHealthState::Reconnecting))
            .step(ScriptStep::wait(Duration::from_secs(2)))
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::assert_reconnect_count(1))
            .step(ScriptStep::disconnect())
    }

    /// SSE: connect, receive N events, verify ordering.
    #[must_use]
    pub fn sse_receive_events(path: &str, count: u32) -> SessionScript {
        SessionScript::new("sse.receive_events")
            .with_transport(Transport::Sse)
            .with_description("Receive and count SSE events")
            .step(ScriptStep::connect(Transport::Sse, path))
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::expect_count(count, MessageMatcher::Any))
            .step(ScriptStep::assert_messages_received(u64::from(count)))
            .step(ScriptStep::disconnect())
    }

    /// Webhook: deliver event, expect ack, verify processing.
    #[must_use]
    pub fn webhook_deliver_and_ack(event_type: &str) -> SessionScript {
        SessionScript::new("webhook.deliver_and_ack")
            .with_transport(Transport::WebhookIngress)
            .with_description("Deliver webhook event and verify acknowledgement")
            .step(ScriptStep::webhook_deliver(
                event_type,
                serde_json::json!({"id": "test-event-1", "action": "created"}),
            ))
            .step(ScriptStep::webhook_expect_ack())
            .step(ScriptStep::assert_messages_received(1))
    }

    /// Long-poll: connect, receive batch, reconnect cycle.
    #[must_use]
    pub fn long_poll_cycle(path: &str) -> SessionScript {
        SessionScript::new("long_poll.receive_cycle")
            .with_transport(Transport::LongPoll)
            .with_description("Long-poll receive batch and reconnect cycle")
            .step(ScriptStep::connect(Transport::LongPoll, path))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::expect_silence(Duration::from_millis(500)))
            .step(ScriptStep::disconnect())
    }

    /// Graceful shutdown: verify connector drains pending messages.
    #[must_use]
    pub fn graceful_shutdown(transport: Transport, path: &str) -> SessionScript {
        SessionScript::new("lifecycle.graceful_shutdown")
            .with_transport(transport)
            .with_description("Verify graceful shutdown drains pending work")
            .step(ScriptStep::connect(transport, path))
            .step(ScriptStep::assert_health(ScriptHealthState::Connected))
            .step(ScriptStep::send_message(serde_json::json!({"type": "work"})))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::annotate("initiating graceful shutdown"))
            .step(ScriptStep::disconnect())
    }

    /// Nack/redelivery: suppress ack, expect redelivery.
    #[must_use]
    pub fn nack_redelivery(transport: Transport, path: &str) -> SessionScript {
        SessionScript::new("delivery.nack_redelivery")
            .with_transport(transport)
            .with_description("Verify message redelivery when ack is suppressed")
            .step(ScriptStep::connect(transport, path))
            .step(
                ScriptStep::expect_any_message()
                    .with_ack(AckMode::Suppress),
            )
            .step(ScriptStep::annotate("ack suppressed, expecting redelivery"))
            .step(ScriptStep::expect_any_message().with_timeout(Duration::from_secs(10)))
            .step(ScriptStep::assert_messages_received(2))
            .step(ScriptStep::disconnect())
    }
}

// ---------------------------------------------------------------------------
// humantime_serde helper for Duration serialization
// ---------------------------------------------------------------------------

mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}ms", duration.as_millis()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        if let Some(ms) = s.strip_suffix("ms") {
            ms.parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|e| e.to_string())
        } else if let Some(secs) = s.strip_suffix('s') {
            secs.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| e.to_string())
        } else if let Some(mins) = s.strip_suffix('m') {
            mins.parse::<u64>()
                .map(|m| Duration::from_secs(m * 60))
                .map_err(|e| e.to_string())
        } else {
            s.parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|e| format!("cannot parse duration '{s}': {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn script_builder_produces_correct_steps() {
        let script = SessionScript::new("ws.test")
            .with_transport(Transport::WebSocket)
            .step(ScriptStep::connect(Transport::WebSocket, "/ws"))
            .step(ScriptStep::send_message(json!({"ping": true})))
            .step(ScriptStep::expect_message(json!({"pong": true})))
            .step(ScriptStep::disconnect());

        assert_eq!(script.scenario_id, "ws.test");
        assert_eq!(script.steps.len(), 4);
        assert_eq!(script.default_transport, Some(Transport::WebSocket));
    }

    #[test]
    fn script_serializes_to_json() {
        let script = SessionScript::new("sse.basic")
            .step(ScriptStep::connect(Transport::Sse, "/events"))
            .step(ScriptStep::expect_any_message())
            .step(ScriptStep::disconnect());

        let json = serde_json::to_string_pretty(&script).unwrap();
        assert!(json.contains("sse.basic"));
        assert!(json.contains("\"transport\": \"sse\""));
    }

    #[test]
    fn script_round_trips_through_json() {
        let original = SessionScript::new("roundtrip")
            .with_transport(Transport::WebSocket)
            .with_label("smoke")
            .step(ScriptStep::connect(Transport::WebSocket, "/ws"))
            .step(ScriptStep::expect_message_containing(json!({"type": "hello"})))
            .step(ScriptStep::inject_fault(Fault::ConnectionDrop))
            .step(ScriptStep::wait(Duration::from_millis(500)))
            .step(ScriptStep::assert_health(ScriptHealthState::Reconnecting))
            .step(ScriptStep::disconnect());

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: SessionScript = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.scenario_id, "roundtrip");
        assert_eq!(deserialized.steps.len(), 6);
        assert_eq!(deserialized.labels, vec!["smoke"]);
    }

    #[test]
    fn fault_variants_serialize_correctly() {
        let drop_fault = Fault::ConnectionDrop;
        let json = serde_json::to_string(&drop_fault).unwrap();
        assert!(json.contains("connection_drop"));

        let latency_fault = Fault::Latency {
            duration: Duration::from_millis(200),
        };
        let json = serde_json::to_string(&latency_fault).unwrap();
        assert!(json.contains("latency"));
        assert!(json.contains("200ms"));

        let reject_fault = Fault::RejectFrames {
            count: 3,
            status: 503,
        };
        let json = serde_json::to_string(&reject_fault).unwrap();
        assert!(json.contains("reject_frames"));
    }

    #[test]
    fn message_matcher_variants() {
        let exact = MessageMatcher::Exact {
            body: json!({"ok": true}),
        };
        let json = serde_json::to_string(&exact).unwrap();
        assert!(json.contains("exact"));

        let contains = MessageMatcher::Contains {
            fragment: json!({"type": "pong"}),
        };
        let json = serde_json::to_string(&contains).unwrap();
        assert!(json.contains("contains"));

        let regex = MessageMatcher::Regex {
            pattern: "event_\\d+".to_owned(),
        };
        let json = serde_json::to_string(&regex).unwrap();
        assert!(json.contains("regex"));
    }

    #[test]
    fn with_timeout_overrides_expect_steps() {
        let step =
            ScriptStep::expect_message(json!({"ok": true})).with_timeout(Duration::from_secs(30));
        if let ScriptStep::ExpectMessage { timeout, .. } = &step {
            assert_eq!(*timeout, Duration::from_secs(30));
        } else {
            panic!("expected ExpectMessage variant");
        }
    }

    #[test]
    fn with_ack_overrides_expect_steps() {
        let step = ScriptStep::expect_any_message().with_ack(AckMode::Suppress);
        if let ScriptStep::ExpectMessage { ack, .. } = &step {
            assert_eq!(*ack, AckMode::Suppress);
        } else {
            panic!("expected ExpectMessage variant");
        }
    }

    #[test]
    fn transcript_to_jsonl_produces_valid_lines() {
        let transcript = SessionTranscript {
            scenario_id: "test.jsonl".to_owned(),
            run_id: "run-abc".to_owned(),
            transport: Some(Transport::WebSocket),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            total_duration: Duration::from_millis(100),
            entries: vec![TranscriptEntry {
                timestamp: Utc::now(),
                step_index: 0,
                step: ScriptStep::connect(Transport::WebSocket, "/ws"),
                outcome: StepOutcome::Pass,
                duration: Duration::from_millis(10),
                detail: None,
                correlation_id: Some("corr-1".to_owned()),
            }],
            outcome: StepOutcome::Pass,
            summary: TranscriptSummary {
                total: 1,
                passed: 1,
                ..TranscriptSummary::default()
            },
        };

        let jsonl = transcript.to_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 entry

        // Verify each line is valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("timestamp").is_some());
            assert!(parsed.get("test_name").is_some());
            assert!(parsed.get("module").is_some());
            assert_eq!(parsed["module"], "session_script");
        }
    }

    #[test]
    fn canonical_scenario_websocket_hello_pong() {
        let script = scenarios::websocket_hello_pong("/ws");
        assert_eq!(script.scenario_id, "websocket.hello_pong");
        assert!(!script.is_empty());
        assert!(script.len() >= 4);
    }

    #[test]
    fn canonical_scenario_websocket_reconnect() {
        let script = scenarios::websocket_reconnect("/ws");
        assert_eq!(script.scenario_id, "websocket.reconnect_after_drop");
        assert!(script.len() >= 7);
    }

    #[test]
    fn canonical_scenario_sse_receive() {
        let script = scenarios::sse_receive_events("/events", 5);
        assert_eq!(script.scenario_id, "sse.receive_events");
    }

    #[test]
    fn canonical_scenario_webhook_deliver() {
        let script = scenarios::webhook_deliver_and_ack("push");
        assert_eq!(script.scenario_id, "webhook.deliver_and_ack");
    }

    #[test]
    fn canonical_scenario_long_poll() {
        let script = scenarios::long_poll_cycle("/poll");
        assert_eq!(script.scenario_id, "long_poll.receive_cycle");
    }

    #[test]
    fn canonical_scenario_graceful_shutdown() {
        let script = scenarios::graceful_shutdown(Transport::WebSocket, "/ws");
        assert_eq!(script.scenario_id, "lifecycle.graceful_shutdown");
    }

    #[test]
    fn canonical_scenario_nack_redelivery() {
        let script = scenarios::nack_redelivery(Transport::WebSocket, "/ws");
        assert_eq!(script.scenario_id, "delivery.nack_redelivery");
    }

    #[test]
    fn transport_display() {
        assert_eq!(Transport::WebSocket.to_string(), "websocket");
        assert_eq!(Transport::Sse.to_string(), "sse");
        assert_eq!(Transport::LongPoll.to_string(), "long_poll");
        assert_eq!(Transport::WebhookIngress.to_string(), "webhook_ingress");
    }

    #[test]
    fn health_state_display() {
        assert_eq!(ScriptHealthState::Connected.to_string(), "connected");
        assert_eq!(ScriptHealthState::Degraded.to_string(), "degraded");
        assert_eq!(ScriptHealthState::Reconnecting.to_string(), "reconnecting");
        assert_eq!(ScriptHealthState::Unhealthy.to_string(), "unhealthy");
    }

    #[test]
    fn step_outcome_display() {
        assert_eq!(StepOutcome::Pass.to_string(), "pass");
        assert_eq!(StepOutcome::Fail.to_string(), "fail");
        assert_eq!(StepOutcome::Skip.to_string(), "skip");
        assert_eq!(StepOutcome::Timeout.to_string(), "timeout");
    }

    #[test]
    fn empty_script() {
        let script = SessionScript::new("empty");
        assert!(script.is_empty());
        assert_eq!(script.len(), 0);
    }

    #[test]
    fn duration_serde_round_trip() {
        let step = ScriptStep::wait(Duration::from_millis(1500));
        let json = serde_json::to_string(&step).unwrap();
        let deserialized: ScriptStep = serde_json::from_str(&json).unwrap();
        if let ScriptStep::Wait { duration } = deserialized {
            assert_eq!(duration, Duration::from_millis(1500));
        } else {
            panic!("expected Wait variant");
        }
    }

    #[test]
    fn webhook_deliver_with_signature_scheme() {
        let step = ScriptStep::WebhookDeliver {
            event_type: "push".to_owned(),
            body: json!({"ref": "refs/heads/main"}),
            signature_scheme: Some("github_hmac_sha256".to_owned()),
        };
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("github_hmac_sha256"));
    }

    #[test]
    fn annotate_step() {
        let step = ScriptStep::annotate("test checkpoint reached");
        if let ScriptStep::Annotate { message } = &step {
            assert_eq!(message, "test checkpoint reached");
        } else {
            panic!("expected Annotate variant");
        }
    }

    #[test]
    fn error_close_fault() {
        let fault = Fault::ErrorClose { code: 1011 };
        let json = serde_json::to_string(&fault).unwrap();
        assert!(json.contains("error_close"));
        assert!(json.contains("1011"));
    }

    #[test]
    fn transcript_summary_default() {
        let summary = TranscriptSummary::default();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.timed_out, 0);
    }

    #[test]
    fn transcript_all_passed() {
        let transcript = SessionTranscript {
            scenario_id: "test".to_owned(),
            run_id: "run-1".to_owned(),
            transport: None,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            total_duration: Duration::from_millis(50),
            entries: vec![],
            outcome: StepOutcome::Pass,
            summary: TranscriptSummary {
                total: 3,
                passed: 3,
                ..TranscriptSummary::default()
            },
        };
        assert!(transcript.all_passed());
    }

    #[test]
    fn transcript_not_all_passed() {
        let transcript = SessionTranscript {
            scenario_id: "test".to_owned(),
            run_id: "run-1".to_owned(),
            transport: None,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            total_duration: Duration::from_millis(50),
            entries: vec![],
            outcome: StepOutcome::Fail,
            summary: TranscriptSummary {
                total: 3,
                passed: 2,
                failed: 1,
                ..TranscriptSummary::default()
            },
        };
        assert!(!transcript.all_passed());
    }

    #[test]
    fn connect_with_headers() {
        let step = ScriptStep::connect_with_headers(
            Transport::WebSocket,
            "/ws",
            vec![("Authorization".to_owned(), "Bearer tok".to_owned())],
        );
        if let ScriptStep::Connect { headers, .. } = &step {
            assert!(headers.is_some());
            assert_eq!(headers.as_ref().unwrap().len(), 1);
        } else {
            panic!("expected Connect variant");
        }
    }

    #[test]
    fn expect_count_step() {
        let step = ScriptStep::expect_count(5, MessageMatcher::Any);
        if let ScriptStep::ExpectCount { count, .. } = &step {
            assert_eq!(*count, 5);
        } else {
            panic!("expected ExpectCount variant");
        }
    }

    #[test]
    fn assert_reconnect_count_step() {
        let step = ScriptStep::assert_reconnect_count(3);
        if let ScriptStep::AssertReconnectCount { expected } = &step {
            assert_eq!(*expected, 3);
        } else {
            panic!("expected AssertReconnectCount variant");
        }
    }
}
