//! Unified event stream tailing across connectors.
//!
//! Parses connector event streams into a unified format, handles backpressure
//! via bounded ring buffer, and formats output in both TOON and JSON modes.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Event types ────────────────────────────────────────────────────────

/// A single event from a connector's event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorEvent {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Connector slug that produced this event.
    pub connector: String,
    /// Event type/category (e.g. `message.new`, `issue.created`).
    pub event_type: String,
    /// Human-readable context (channel, repo, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Human-readable summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Full event payload.
    pub data: Value,
}

impl ConnectorEvent {
    /// Format as a TOON-style line: `[HH:MM:SS] connector  event_type  context  summary`.
    pub fn format_toon(&self) -> String {
        let time = extract_time(&self.timestamp);
        let ctx = self.context.as_deref().unwrap_or("");
        let summary = self.summary.as_deref().unwrap_or("");

        if ctx.is_empty() && summary.is_empty() {
            format!("[{time}] {}  {}", self.connector, self.event_type)
        } else if ctx.is_empty() {
            format!(
                "[{time}] {}  {}  {summary}",
                self.connector, self.event_type
            )
        } else {
            format!(
                "[{time}] {}  {}  {ctx}  {summary}",
                self.connector, self.event_type
            )
        }
    }

    /// Format as a single-line JSON string.
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Extract `HH:MM:SS` from an ISO 8601 timestamp, falling back to the raw string.
fn extract_time(timestamp: &str) -> &str {
    // Look for "T" separator and take the time part.
    if let Some(t_pos) = timestamp.find('T') {
        let after_t = &timestamp[t_pos + 1..];
        // Take up to 8 chars (HH:MM:SS) or until non-time char.
        let end = after_t
            .find(|c: char| !c.is_ascii_digit() && c != ':')
            .unwrap_or(after_t.len())
            .min(8);
        &after_t[..end]
    } else {
        timestamp
    }
}

// ── Since duration parsing ─────────────────────────────────────────────

/// Parse a human-readable duration like `5m`, `1h`, `30s`, `2d` into seconds.
pub fn parse_since(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_owned());
    }

    let (num_str, suffix) = if s.ends_with('s') {
        (&s[..s.len() - 1], "s")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with('d') {
        (&s[..s.len() - 1], "d")
    } else {
        // Assume seconds if no suffix.
        (s, "s")
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid number in duration: '{num_str}'"))?;

    let multiplier = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(format!("unknown duration suffix: '{suffix}'")),
    };

    Ok(num * multiplier)
}

// ── Backpressure ring buffer ───────────────────────────────────────────

/// Bounded ring buffer for event backpressure handling.
///
/// When full, the oldest events are dropped to make room for new ones.
#[derive(Debug)]
pub struct EventBuffer {
    events: VecDeque<ConnectorEvent>,
    capacity: usize,
    dropped: u64,
}

impl EventBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    /// Push an event into the buffer, dropping the oldest if full.
    pub fn push(&mut self, event: ConnectorEvent) {
        if self.events.len() >= self.capacity {
            self.events.pop_front();
            self.dropped += 1;
        }
        self.events.push_back(event);
    }

    /// Drain all buffered events in order.
    pub fn drain(&mut self) -> Vec<ConnectorEvent> {
        self.events.drain(..).collect()
    }

    /// Number of events currently buffered.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Number of events dropped due to backpressure.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// Maximum capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ── Tail configuration ─────────────────────────────────────────────────

/// Configuration for an event tail session.
#[derive(Debug, Clone, Serialize)]
pub struct TailConfig {
    /// Connectors to tail (empty = all).
    pub connectors: Vec<String>,
    /// Whether to tail all streaming connectors.
    pub all: bool,
    /// Historical lookback in seconds.
    pub since_seconds: Option<u64>,
    /// Backpressure buffer size.
    pub buffer_size: usize,
}

impl TailConfig {
    /// Parse connector list from a comma-separated string.
    pub fn parse_connectors(s: &str) -> Vec<String> {
        s.split(',')
            .map(|c| c.trim().to_owned())
            .filter(|c| !c.is_empty())
            .collect()
    }
}

impl Default for TailConfig {
    fn default() -> Self {
        Self {
            connectors: Vec::new(),
            all: false,
            since_seconds: None,
            buffer_size: 1000,
        }
    }
}

// ── Tail plan (dry-run output) ─────────────────────────────────────────

/// Plan for a tail session (used for dry-run / preview).
#[derive(Debug, Clone, Serialize)]
pub struct TailPlan {
    /// Connectors that will be tailed.
    pub connectors: Vec<String>,
    /// Whether all connectors were requested.
    pub all: bool,
    /// Historical lookback.
    pub since: Option<String>,
    /// Buffer capacity.
    pub buffer_size: usize,
}

// ── Stream status ──────────────────────────────────────────────────────

/// Status of a connector's event stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    /// Stream is active and producing events.
    Active,
    /// Stream is connected but no events yet.
    Waiting,
    /// Stream encountered an error.
    Error,
    /// Stream was disconnected.
    Disconnected,
    /// Connector does not support streaming.
    Unsupported,
}

impl fmt::Display for StreamStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Waiting => f.write_str("waiting"),
            Self::Error => f.write_str("error"),
            Self::Disconnected => f.write_str("disconnected"),
            Self::Unsupported => f.write_str("unsupported"),
        }
    }
}

/// Per-connector stream state in a tail session.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectorStreamState {
    pub connector: String,
    pub status: StreamStatus,
    pub events_received: u64,
    pub last_event_at: Option<String>,
}

/// Summary of a tail session.
#[derive(Debug, Clone, Serialize)]
pub struct TailSummary {
    pub streams: Vec<ConnectorStreamState>,
    pub total_events: u64,
    pub dropped_events: u64,
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── ConnectorEvent formatting ──────────────────────────────────

    fn sample_event() -> ConnectorEvent {
        ConnectorEvent {
            timestamp: "2026-03-09T14:32:05Z".to_owned(),
            connector: "slack".to_owned(),
            event_type: "message.new".to_owned(),
            context: Some("#general".to_owned()),
            summary: Some("@alice: Hey team".to_owned()),
            data: json!({"text": "Hey team", "user": "alice"}),
        }
    }

    #[test]
    fn toon_format_full() {
        let event = sample_event();
        let line = event.format_toon();
        assert_eq!(line, "[14:32:05] slack  message.new  #general  @alice: Hey team");
    }

    #[test]
    fn toon_format_no_context() {
        let mut event = sample_event();
        event.context = None;
        let line = event.format_toon();
        assert_eq!(line, "[14:32:05] slack  message.new  @alice: Hey team");
    }

    #[test]
    fn toon_format_no_summary() {
        let mut event = sample_event();
        event.summary = None;
        let line = event.format_toon();
        assert_eq!(line, "[14:32:05] slack  message.new  #general  ");
    }

    #[test]
    fn toon_format_minimal() {
        let mut event = sample_event();
        event.context = None;
        event.summary = None;
        let line = event.format_toon();
        assert_eq!(line, "[14:32:05] slack  message.new");
    }

    #[test]
    fn json_format() {
        let event = sample_event();
        let json = event.format_json();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["connector"], "slack");
        assert_eq!(parsed["event_type"], "message.new");
        assert_eq!(parsed["context"], "#general");
    }

    #[test]
    fn event_roundtrip() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: ConnectorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector, "slack");
        assert_eq!(back.event_type, "message.new");
        assert_eq!(back.timestamp, "2026-03-09T14:32:05Z");
    }

    #[test]
    fn event_omits_none_fields() {
        let event = ConnectorEvent {
            timestamp: "2026-03-09T14:00:00Z".to_owned(),
            connector: "github".to_owned(),
            event_type: "push".to_owned(),
            context: None,
            summary: None,
            data: json!({}),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("context"));
        assert!(!json.contains("summary"));
    }

    // ── extract_time ───────────────────────────────────────────────

    #[test]
    fn extract_time_iso() {
        assert_eq!(extract_time("2026-03-09T14:32:05Z"), "14:32:05");
    }

    #[test]
    fn extract_time_with_millis() {
        assert_eq!(extract_time("2026-03-09T14:32:05.123Z"), "14:32:05");
    }

    #[test]
    fn extract_time_with_offset() {
        assert_eq!(extract_time("2026-03-09T14:32:05+05:30"), "14:32:05");
    }

    #[test]
    fn extract_time_no_t_separator() {
        assert_eq!(extract_time("14:32:05"), "14:32:05");
    }

    #[test]
    fn extract_time_short() {
        assert_eq!(extract_time("2026-03-09T09:05:01Z"), "09:05:01");
    }

    // ── parse_since ────────────────────────────────────────────────

    #[test]
    fn parse_since_seconds() {
        assert_eq!(parse_since("30s"), Ok(30));
    }

    #[test]
    fn parse_since_minutes() {
        assert_eq!(parse_since("5m"), Ok(300));
    }

    #[test]
    fn parse_since_hours() {
        assert_eq!(parse_since("2h"), Ok(7200));
    }

    #[test]
    fn parse_since_days() {
        assert_eq!(parse_since("1d"), Ok(86400));
    }

    #[test]
    fn parse_since_no_suffix_defaults_to_seconds() {
        assert_eq!(parse_since("60"), Ok(60));
    }

    #[test]
    fn parse_since_empty_error() {
        assert!(parse_since("").is_err());
    }

    #[test]
    fn parse_since_invalid_number() {
        assert!(parse_since("abcm").is_err());
    }

    #[test]
    fn parse_since_whitespace_trimmed() {
        assert_eq!(parse_since("  5m  "), Ok(300));
    }

    // ── EventBuffer ────────────────────────────────────────────────

    #[test]
    fn buffer_push_and_drain() {
        let mut buf = EventBuffer::new(10);
        buf.push(sample_event());
        buf.push(sample_event());
        assert_eq!(buf.len(), 2);

        let events = buf.drain();
        assert_eq!(events.len(), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn buffer_backpressure_drops_oldest() {
        let mut buf = EventBuffer::new(2);
        let mut e1 = sample_event();
        e1.event_type = "first".to_owned();
        let mut e2 = sample_event();
        e2.event_type = "second".to_owned();
        let mut e3 = sample_event();
        e3.event_type = "third".to_owned();

        buf.push(e1);
        buf.push(e2);
        assert_eq!(buf.dropped_count(), 0);

        buf.push(e3);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.dropped_count(), 1);

        let events = buf.drain();
        assert_eq!(events[0].event_type, "second");
        assert_eq!(events[1].event_type, "third");
    }

    #[test]
    fn buffer_capacity_one() {
        let mut buf = EventBuffer::new(1);
        let mut e1 = sample_event();
        e1.event_type = "a".to_owned();
        let mut e2 = sample_event();
        e2.event_type = "b".to_owned();

        buf.push(e1);
        buf.push(e2);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.dropped_count(), 1);

        let events = buf.drain();
        assert_eq!(events[0].event_type, "b");
    }

    #[test]
    fn buffer_empty_drain() {
        let mut buf = EventBuffer::new(10);
        assert!(buf.is_empty());
        let events = buf.drain();
        assert!(events.is_empty());
    }

    #[test]
    fn buffer_capacity() {
        let buf = EventBuffer::new(42);
        assert_eq!(buf.capacity(), 42);
    }

    #[test]
    fn buffer_heavy_backpressure() {
        let mut buf = EventBuffer::new(3);
        for i in 0..100 {
            let mut event = sample_event();
            event.event_type = format!("event_{i}");
            buf.push(event);
        }
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 97);

        let events = buf.drain();
        assert_eq!(events[0].event_type, "event_97");
        assert_eq!(events[1].event_type, "event_98");
        assert_eq!(events[2].event_type, "event_99");
    }

    // ── TailConfig ─────────────────────────────────────────────────

    #[test]
    fn parse_connectors_single() {
        let connectors = TailConfig::parse_connectors("slack");
        assert_eq!(connectors, vec!["slack"]);
    }

    #[test]
    fn parse_connectors_multiple() {
        let connectors = TailConfig::parse_connectors("slack,discord,github");
        assert_eq!(connectors, vec!["slack", "discord", "github"]);
    }

    #[test]
    fn parse_connectors_with_spaces() {
        let connectors = TailConfig::parse_connectors(" slack , discord ");
        assert_eq!(connectors, vec!["slack", "discord"]);
    }

    #[test]
    fn parse_connectors_empty_items_filtered() {
        let connectors = TailConfig::parse_connectors("slack,,discord");
        assert_eq!(connectors, vec!["slack", "discord"]);
    }

    #[test]
    fn parse_connectors_empty_string() {
        let connectors = TailConfig::parse_connectors("");
        assert!(connectors.is_empty());
    }

    #[test]
    fn tail_config_default() {
        let config = TailConfig::default();
        assert!(config.connectors.is_empty());
        assert!(!config.all);
        assert_eq!(config.since_seconds, None);
        assert_eq!(config.buffer_size, 1000);
    }

    // ── TailPlan serialization ─────────────────────────────────────

    #[test]
    fn tail_plan_serializes() {
        let plan = TailPlan {
            connectors: vec!["slack".to_owned(), "discord".to_owned()],
            all: false,
            since: Some("5m".to_owned()),
            buffer_size: 500,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["connectors"].as_array().unwrap().len(), 2);
        assert_eq!(json["since"], "5m");
        assert_eq!(json["buffer_size"], 500);
    }

    // ── StreamStatus ───────────────────────────────────────────────

    #[test]
    fn stream_status_display() {
        assert_eq!(StreamStatus::Active.to_string(), "active");
        assert_eq!(StreamStatus::Waiting.to_string(), "waiting");
        assert_eq!(StreamStatus::Error.to_string(), "error");
        assert_eq!(StreamStatus::Disconnected.to_string(), "disconnected");
        assert_eq!(StreamStatus::Unsupported.to_string(), "unsupported");
    }

    #[test]
    fn stream_status_roundtrip() {
        for status in [
            StreamStatus::Active,
            StreamStatus::Waiting,
            StreamStatus::Error,
            StreamStatus::Disconnected,
            StreamStatus::Unsupported,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: StreamStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn stream_status_equality() {
        assert_eq!(StreamStatus::Active, StreamStatus::Active);
        assert_ne!(StreamStatus::Active, StreamStatus::Error);
    }

    // ── ConnectorStreamState ───────────────────────────────────────

    #[test]
    fn connector_stream_state_serializes() {
        let state = ConnectorStreamState {
            connector: "slack".to_owned(),
            status: StreamStatus::Active,
            events_received: 42,
            last_event_at: Some("2026-03-09T14:32:05Z".to_owned()),
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["connector"], "slack");
        assert_eq!(json["status"], "active");
        assert_eq!(json["events_received"], 42);
    }

    // ── TailSummary ────────────────────────────────────────────────

    #[test]
    fn tail_summary_serializes() {
        let summary = TailSummary {
            streams: vec![ConnectorStreamState {
                connector: "slack".to_owned(),
                status: StreamStatus::Active,
                events_received: 10,
                last_event_at: None,
            }],
            total_events: 10,
            dropped_events: 0,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["total_events"], 10);
        assert_eq!(json["dropped_events"], 0);
        assert_eq!(json["streams"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn tail_summary_with_drops() {
        let summary = TailSummary {
            streams: vec![],
            total_events: 1000,
            dropped_events: 50,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["dropped_events"], 50);
    }
}
