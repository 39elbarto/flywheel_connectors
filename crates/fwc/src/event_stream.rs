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
    timestamp.split_once('T').map_or(timestamp, |(_, after_t)| {
        let end = after_t
            .find(|c: char| !c.is_ascii_digit() && c != ':')
            .unwrap_or(after_t.len())
            .min(8);
        &after_t[..end]
    })
}

// ── Since duration parsing ─────────────────────────────────────────────

/// Parse a human-readable duration like `5m`, `1h`, `30s`, `2d` into seconds.
pub fn parse_since(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_owned());
    }

    let (num_str, suffix) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], "s"),
        Some(b'm') => (&s[..s.len() - 1], "m"),
        Some(b'h') => (&s[..s.len() - 1], "h"),
        Some(b'd') => (&s[..s.len() - 1], "d"),
        _ => (s, "s"), // Assume seconds if no suffix.
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
    pub const fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// Maximum capacity.
    pub const fn capacity(&self) -> usize {
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
        assert_eq!(
            line,
            "[14:32:05] slack  message.new  #general  @alice: Hey team"
        );
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

    // ── ConnectorEvent additional ─────────────────────────────────

    #[test]
    fn event_clone() {
        let event = sample_event();
        let cloned = event.clone();
        assert_eq!(cloned.connector, event.connector);
        assert_eq!(cloned.event_type, event.event_type);
        assert_eq!(cloned.timestamp, event.timestamp);
    }

    #[test]
    fn event_debug_format() {
        let event = sample_event();
        let debug = format!("{event:?}");
        assert!(debug.contains("ConnectorEvent"));
        assert!(debug.contains("slack"));
    }

    #[test]
    fn event_json_format_parses_back() {
        let event = sample_event();
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.connector, "slack");
        assert_eq!(back.context.as_deref(), Some("#general"));
        assert_eq!(back.summary.as_deref(), Some("@alice: Hey team"));
    }

    #[test]
    fn event_with_empty_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            connector: "test".to_owned(),
            event_type: "ping".to_owned(),
            context: None,
            summary: None,
            data: json!({}),
        };
        let json = event.format_json();
        assert!(json.contains("\"data\":{}"));
    }

    #[test]
    fn event_with_complex_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T12:00:00Z".to_owned(),
            connector: "github".to_owned(),
            event_type: "push".to_owned(),
            context: Some("main".to_owned()),
            summary: Some("3 commits pushed".to_owned()),
            data: json!({"commits": [{"sha": "abc123"}, {"sha": "def456"}]}),
        };
        let json_str = event.format_json();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["data"]["commits"].is_array());
        assert_eq!(parsed["data"]["commits"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn toon_format_with_context_no_summary() {
        let event = ConnectorEvent {
            timestamp: "2026-06-15T08:30:00Z".to_owned(),
            connector: "discord".to_owned(),
            event_type: "voice.join".to_owned(),
            context: Some("lobby".to_owned()),
            summary: None,
            data: json!({}),
        };
        let line = event.format_toon();
        assert!(line.contains("[08:30:00]"));
        assert!(line.contains("discord"));
        assert!(line.contains("lobby"));
    }

    // ── extract_time additional ───────────────────────────────────

    #[test]
    fn extract_time_midnight() {
        assert_eq!(extract_time("2026-01-01T00:00:00Z"), "00:00:00");
    }

    #[test]
    fn extract_time_end_of_day() {
        assert_eq!(extract_time("2026-12-31T23:59:59Z"), "23:59:59");
    }

    #[test]
    fn extract_time_with_negative_offset() {
        assert_eq!(extract_time("2026-03-09T14:32:05-07:00"), "14:32:05");
    }

    #[test]
    fn extract_time_no_timezone() {
        // No Z or offset, just the time
        assert_eq!(extract_time("2026-03-09T10:20:30"), "10:20:30");
    }

    #[test]
    fn extract_time_empty_string() {
        // Falls back to raw string
        assert_eq!(extract_time(""), "");
    }

    #[test]
    fn extract_time_just_date() {
        // No T separator, returns raw
        assert_eq!(extract_time("2026-03-09"), "2026-03-09");
    }

    // ── parse_since additional ────────────────────────────────────

    #[test]
    fn parse_since_zero_seconds() {
        assert_eq!(parse_since("0s"), Ok(0));
    }

    #[test]
    fn parse_since_zero_minutes() {
        assert_eq!(parse_since("0m"), Ok(0));
    }

    #[test]
    fn parse_since_large_day_value() {
        assert_eq!(parse_since("30d"), Ok(2_592_000));
    }

    #[test]
    fn parse_since_large_hour_value() {
        assert_eq!(parse_since("48h"), Ok(172_800));
    }

    #[test]
    fn parse_since_one_second() {
        assert_eq!(parse_since("1s"), Ok(1));
    }

    #[test]
    fn parse_since_only_whitespace_is_error() {
        assert!(parse_since("   ").is_err());
    }

    #[test]
    fn parse_since_negative_number() {
        // "-5m" — the numeric part is "-5", which is not a valid u64
        assert!(parse_since("-5m").is_err());
    }

    #[test]
    fn parse_since_decimal_number() {
        // "1.5h" — not an integer
        assert!(parse_since("1.5h").is_err());
    }

    // ── EventBuffer additional ────────────────────────────────────

    #[test]
    fn buffer_push_preserves_order() {
        let mut buf = EventBuffer::new(5);
        for i in 0..3 {
            let mut e = sample_event();
            e.event_type = format!("ev_{i}");
            buf.push(e);
        }
        let events = buf.drain();
        assert_eq!(events[0].event_type, "ev_0");
        assert_eq!(events[1].event_type, "ev_1");
        assert_eq!(events[2].event_type, "ev_2");
    }

    #[test]
    fn buffer_drain_resets_state() {
        let mut buf = EventBuffer::new(10);
        buf.push(sample_event());
        buf.push(sample_event());
        let _ = buf.drain();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        // Dropped count is NOT reset by drain
        assert_eq!(buf.dropped_count(), 0);
    }

    #[test]
    fn buffer_multiple_drain_cycles() {
        let mut buf = EventBuffer::new(5);
        buf.push(sample_event());
        let first = buf.drain();
        assert_eq!(first.len(), 1);

        buf.push(sample_event());
        buf.push(sample_event());
        let second = buf.drain();
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn buffer_dropped_count_accumulates() {
        let mut buf = EventBuffer::new(1);
        for _ in 0..10 {
            buf.push(sample_event());
        }
        assert_eq!(buf.dropped_count(), 9);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn buffer_exact_capacity_no_drop() {
        let mut buf = EventBuffer::new(3);
        buf.push(sample_event());
        buf.push(sample_event());
        buf.push(sample_event());
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 0);
    }

    // ── TailConfig additional ─────────────────────────────────────

    #[test]
    fn parse_connectors_trailing_comma() {
        let connectors = TailConfig::parse_connectors("slack,discord,");
        assert_eq!(connectors, vec!["slack", "discord"]);
    }

    #[test]
    fn parse_connectors_leading_comma() {
        let connectors = TailConfig::parse_connectors(",slack");
        assert_eq!(connectors, vec!["slack"]);
    }

    #[test]
    fn tail_config_serializes() {
        let config = TailConfig {
            connectors: vec!["slack".to_owned()],
            all: true,
            since_seconds: Some(300),
            buffer_size: 500,
        };
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["all"], true);
        assert_eq!(json["since_seconds"], 300);
        assert_eq!(json["buffer_size"], 500);
    }

    // ── TailPlan additional ──────────────────────────────────────

    #[test]
    fn tail_plan_no_since() {
        let plan = TailPlan {
            connectors: vec!["github".to_owned()],
            all: false,
            since: None,
            buffer_size: 1000,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json["since"].is_null());
    }

    #[test]
    fn tail_plan_all_mode() {
        let plan = TailPlan {
            connectors: Vec::new(),
            all: true,
            since: Some("1h".to_owned()),
            buffer_size: 2000,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["all"], true);
        assert!(json["connectors"].as_array().unwrap().is_empty());
    }

    // ── StreamStatus additional ──────────────────────────────────

    #[test]
    fn stream_status_serde_values() {
        assert_eq!(
            serde_json::to_string(&StreamStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&StreamStatus::Waiting).unwrap(),
            "\"waiting\""
        );
        assert_eq!(
            serde_json::to_string(&StreamStatus::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&StreamStatus::Disconnected).unwrap(),
            "\"disconnected\""
        );
        assert_eq!(
            serde_json::to_string(&StreamStatus::Unsupported).unwrap(),
            "\"unsupported\""
        );
    }

    #[test]
    fn stream_status_clone() {
        let s = StreamStatus::Active;
        let c = s.clone();
        assert_eq!(s, c);
    }

    #[test]
    fn stream_status_debug() {
        let debug = format!("{:?}", StreamStatus::Disconnected);
        assert!(debug.contains("Disconnected"));
    }

    // ── ConnectorStreamState additional ───────────────────────────

    #[test]
    fn connector_stream_state_no_last_event() {
        let state = ConnectorStreamState {
            connector: "discord".to_owned(),
            status: StreamStatus::Waiting,
            events_received: 0,
            last_event_at: None,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["events_received"], 0);
        assert!(json["last_event_at"].is_null());
    }

    #[test]
    fn connector_stream_state_clone() {
        let state = ConnectorStreamState {
            connector: "slack".to_owned(),
            status: StreamStatus::Active,
            events_received: 100,
            last_event_at: Some("2026-03-09T15:00:00Z".to_owned()),
        };
        let cloned = state.clone();
        assert_eq!(state.connector, "slack");
        assert_eq!(cloned.events_received, 100);
    }

    // ── TailSummary additional ───────────────────────────────────

    #[test]
    fn tail_summary_multiple_streams() {
        let summary = TailSummary {
            streams: vec![
                ConnectorStreamState {
                    connector: "slack".to_owned(),
                    status: StreamStatus::Active,
                    events_received: 50,
                    last_event_at: Some("2026-03-09T15:00:00Z".to_owned()),
                },
                ConnectorStreamState {
                    connector: "discord".to_owned(),
                    status: StreamStatus::Disconnected,
                    events_received: 10,
                    last_event_at: None,
                },
            ],
            total_events: 60,
            dropped_events: 5,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["streams"].as_array().unwrap().len(), 2);
        assert_eq!(json["total_events"], 60);
    }

    #[test]
    fn tail_summary_clone() {
        let summary = TailSummary {
            streams: vec![],
            total_events: 0,
            dropped_events: 0,
        };
        let cloned = summary.clone();
        assert_eq!(summary.total_events, 0);
        assert!(cloned.streams.is_empty());
    }

    // ── ConnectorEvent edge cases ────────────────────────────────

    #[test]
    fn event_with_null_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            connector: "test".to_owned(),
            event_type: "null_data".to_owned(),
            context: None,
            summary: None,
            data: Value::Null,
        };
        let json_str = event.format_json();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["data"].is_null());
    }

    #[test]
    fn event_with_array_data() {
        let event = ConnectorEvent {
            timestamp: "2026-06-01T12:00:00Z".to_owned(),
            connector: "webhook".to_owned(),
            event_type: "batch".to_owned(),
            context: None,
            summary: Some("batch of 3".to_owned()),
            data: json!([1, 2, 3]),
        };
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert!(back.data.is_array());
        assert_eq!(back.data.as_array().unwrap().len(), 3);
    }

    #[test]
    fn event_with_numeric_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            connector: "sensor".to_owned(),
            event_type: "reading".to_owned(),
            context: None,
            summary: None,
            data: json!(42.5),
        };
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.data.as_f64().unwrap(), 42.5);
    }

    #[test]
    fn event_with_string_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            connector: "log".to_owned(),
            event_type: "line".to_owned(),
            context: None,
            summary: None,
            data: json!("raw log line"),
        };
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.data.as_str().unwrap(), "raw log line");
    }

    #[test]
    fn event_with_boolean_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            connector: "flag".to_owned(),
            event_type: "toggle".to_owned(),
            context: None,
            summary: None,
            data: json!(true),
        };
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.data.as_bool().unwrap(), true);
    }

    #[test]
    fn event_with_deeply_nested_data() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            connector: "nested".to_owned(),
            event_type: "deep".to_owned(),
            context: None,
            summary: None,
            data: json!({"a": {"b": {"c": {"d": "deep_value"}}}}),
        };
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.data["a"]["b"]["c"]["d"], "deep_value");
    }

    #[test]
    fn event_with_empty_strings() {
        let event = ConnectorEvent {
            timestamp: "".to_owned(),
            connector: "".to_owned(),
            event_type: "".to_owned(),
            context: Some("".to_owned()),
            summary: Some("".to_owned()),
            data: json!({}),
        };
        // Empty context/summary serialized because they are Some("")
        let json_str = event.format_json();
        assert!(json_str.contains("\"context\":\"\""));
        assert!(json_str.contains("\"summary\":\"\""));
    }

    #[test]
    fn event_toon_with_empty_context_some() {
        // context is Some("") which is treated as empty by format_toon
        let event = ConnectorEvent {
            timestamp: "2026-01-01T10:00:00Z".to_owned(),
            connector: "test".to_owned(),
            event_type: "ping".to_owned(),
            context: Some("".to_owned()),
            summary: Some("hello".to_owned()),
            data: json!({}),
        };
        let line = event.format_toon();
        // Empty context treated as no context, so format is: [time] connector  type  summary
        assert_eq!(line, "[10:00:00] test  ping  hello");
    }

    #[test]
    fn event_toon_both_empty_some() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T10:00:00Z".to_owned(),
            connector: "test".to_owned(),
            event_type: "ping".to_owned(),
            context: Some("".to_owned()),
            summary: Some("".to_owned()),
            data: json!({}),
        };
        let line = event.format_toon();
        // Both empty, treated as minimal
        assert_eq!(line, "[10:00:00] test  ping");
    }

    #[test]
    fn event_with_unicode_content() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T12:00:00Z".to_owned(),
            connector: "chat".to_owned(),
            event_type: "message".to_owned(),
            context: Some("general".to_owned()),
            summary: Some("Hello world".to_owned()),
            data: json!({"text": "Hello world"}),
        };
        let json_str = event.format_json();
        let back: ConnectorEvent = serde_json::from_str(&json_str).unwrap();
        assert!(back.summary.unwrap().contains("Hello"));
    }

    #[test]
    fn event_with_special_characters_in_connector() {
        let event = ConnectorEvent {
            timestamp: "2026-01-01T12:00:00Z".to_owned(),
            connector: "my-connector_v2.1".to_owned(),
            event_type: "test.event".to_owned(),
            context: None,
            summary: None,
            data: json!({}),
        };
        let line = event.format_toon();
        assert!(line.contains("my-connector_v2.1"));
    }

    #[test]
    fn event_deserialize_from_raw_json() {
        let raw = r#"{
            "timestamp": "2026-05-01T09:00:00Z",
            "connector": "jira",
            "event_type": "issue.created",
            "context": "PROJ-123",
            "summary": "New bug report",
            "data": {"key": "PROJ-123", "status": "open"}
        }"#;
        let event: ConnectorEvent = serde_json::from_str(raw).unwrap();
        assert_eq!(event.connector, "jira");
        assert_eq!(event.event_type, "issue.created");
        assert_eq!(event.context.as_deref(), Some("PROJ-123"));
        assert_eq!(event.data["status"], "open");
    }

    #[test]
    fn event_deserialize_without_optional_fields() {
        let raw = r#"{
            "timestamp": "2026-05-01T09:00:00Z",
            "connector": "minimal",
            "event_type": "heartbeat",
            "data": null
        }"#;
        let event: ConnectorEvent = serde_json::from_str(raw).unwrap();
        assert!(event.context.is_none());
        assert!(event.summary.is_none());
        assert!(event.data.is_null());
    }

    #[test]
    fn event_clone_independence() {
        let event = sample_event();
        let mut cloned = event.clone();
        cloned.connector = "modified".to_owned();
        cloned.event_type = "changed".to_owned();
        // Original unchanged
        assert_eq!(event.connector, "slack");
        assert_eq!(event.event_type, "message.new");
    }

    #[test]
    fn event_debug_contains_all_fields() {
        let event = sample_event();
        let debug = format!("{event:?}");
        assert!(debug.contains("timestamp"));
        assert!(debug.contains("connector"));
        assert!(debug.contains("event_type"));
        assert!(debug.contains("context"));
        assert!(debug.contains("summary"));
        assert!(debug.contains("data"));
    }

    #[test]
    fn event_json_format_includes_all_present_fields() {
        let event = sample_event();
        let json_str = event.format_json();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("connector").is_some());
        assert!(parsed.get("event_type").is_some());
        assert!(parsed.get("context").is_some());
        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("data").is_some());
    }

    #[test]
    fn event_format_json_is_single_line() {
        let event = sample_event();
        let json_str = event.format_json();
        assert!(!json_str.contains('\n'));
    }

    // ── extract_time edge cases ─────────────────────────────────

    #[test]
    fn extract_time_with_microseconds() {
        assert_eq!(extract_time("2026-01-01T12:34:56.789012Z"), "12:34:56");
    }

    #[test]
    fn extract_time_with_nanoseconds() {
        assert_eq!(extract_time("2026-01-01T12:34:56.123456789Z"), "12:34:56");
    }

    #[test]
    fn extract_time_t_at_start() {
        // Weird but valid for the parser: T immediately
        let result = extract_time("T12:30:00Z");
        assert_eq!(result, "12:30:00");
    }

    #[test]
    fn extract_time_t_at_end() {
        // T with nothing after
        let result = extract_time("2026-01-01T");
        assert_eq!(result, "");
    }

    #[test]
    fn extract_time_multiple_t_uses_first() {
        // split_once uses the first T
        let result = extract_time("2026-01-01T08:00:00T09:00:00");
        assert_eq!(result, "08:00:00");
    }

    #[test]
    fn extract_time_short_time_portion() {
        // Time portion shorter than 8 chars and no terminator
        assert_eq!(extract_time("2026-01-01T08:00"), "08:00");
    }

    #[test]
    fn extract_time_with_space_after_time() {
        // Space is not a digit and not ':'
        assert_eq!(extract_time("2026-01-01T08:30:00 UTC"), "08:30:00");
    }

    // ── parse_since boundary cases ──────────────────────────────

    #[test]
    fn parse_since_zero_no_suffix() {
        assert_eq!(parse_since("0"), Ok(0));
    }

    #[test]
    fn parse_since_zero_hours() {
        assert_eq!(parse_since("0h"), Ok(0));
    }

    #[test]
    fn parse_since_zero_days() {
        assert_eq!(parse_since("0d"), Ok(0));
    }

    #[test]
    fn parse_since_one_minute() {
        assert_eq!(parse_since("1m"), Ok(60));
    }

    #[test]
    fn parse_since_one_hour() {
        assert_eq!(parse_since("1h"), Ok(3600));
    }

    #[test]
    fn parse_since_one_day() {
        assert_eq!(parse_since("1d"), Ok(86400));
    }

    #[test]
    fn parse_since_large_seconds() {
        assert_eq!(parse_since("86400s"), Ok(86400));
    }

    #[test]
    fn parse_since_very_large_value() {
        assert_eq!(parse_since("365d"), Ok(365 * 86400));
    }

    #[test]
    fn parse_since_error_message_contains_input() {
        let result = parse_since("xyzm");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("xyz"));
    }

    #[test]
    fn parse_since_empty_error_message() {
        let result = parse_since("");
        assert_eq!(result.unwrap_err(), "empty duration");
    }

    #[test]
    fn parse_since_whitespace_only_error_message() {
        let result = parse_since("   ");
        assert_eq!(result.unwrap_err(), "empty duration");
    }

    #[test]
    fn parse_since_double_suffix_is_error() {
        // "5ms" -> suffix is 's', num_str is "5m" -> parse error
        assert!(parse_since("5ms").is_err());
    }

    #[test]
    fn parse_since_just_suffix_is_error() {
        assert!(parse_since("m").is_err());
        assert!(parse_since("h").is_err());
        assert!(parse_since("d").is_err());
        assert!(parse_since("s").is_err());
    }

    #[test]
    fn parse_since_tab_trimmed() {
        assert_eq!(parse_since("\t10s\t"), Ok(10));
    }

    #[test]
    fn parse_since_max_u64_seconds() {
        // Very large u64 value
        let val = format!("{}s", u64::MAX);
        let result = parse_since(&val);
        assert_eq!(result.unwrap(), u64::MAX);
    }

    // ── EventBuffer edge cases ──────────────────────────────────

    #[test]
    fn buffer_zero_capacity_behavior() {
        // With capacity 0, len (0) >= capacity (0) is true, so pop_front (no-op on
        // empty deque) + dropped++, then push_back adds the event. The buffer
        // effectively holds 1 element and each subsequent push drops the previous.
        let mut buf = EventBuffer::new(0);
        buf.push(sample_event());
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.dropped_count(), 1);

        let mut e2 = sample_event();
        e2.event_type = "second".to_owned();
        buf.push(e2);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.dropped_count(), 2);

        let events = buf.drain();
        assert_eq!(events[0].event_type, "second");
    }

    #[test]
    fn buffer_debug_format() {
        let buf = EventBuffer::new(5);
        let debug = format!("{buf:?}");
        assert!(debug.contains("EventBuffer"));
        assert!(debug.contains("capacity"));
        assert!(debug.contains("dropped"));
    }

    #[test]
    fn buffer_large_capacity() {
        let buf = EventBuffer::new(100_000);
        assert_eq!(buf.capacity(), 100_000);
        assert!(buf.is_empty());
        assert_eq!(buf.dropped_count(), 0);
    }

    #[test]
    fn buffer_drain_then_push_works() {
        let mut buf = EventBuffer::new(2);
        buf.push(sample_event());
        buf.push(sample_event());
        let _ = buf.drain();
        assert!(buf.is_empty());

        // Should accept new events after drain
        let mut e = sample_event();
        e.event_type = "after_drain".to_owned();
        buf.push(e);
        assert_eq!(buf.len(), 1);
        let events = buf.drain();
        assert_eq!(events[0].event_type, "after_drain");
    }

    #[test]
    fn buffer_dropped_count_persists_after_drain() {
        let mut buf = EventBuffer::new(1);
        buf.push(sample_event());
        buf.push(sample_event()); // drops first
        assert_eq!(buf.dropped_count(), 1);
        let _ = buf.drain();
        // Dropped count persists
        assert_eq!(buf.dropped_count(), 1);
    }

    #[test]
    fn buffer_interleave_push_drain() {
        let mut buf = EventBuffer::new(3);
        for i in 0..5 {
            let mut e = sample_event();
            e.event_type = format!("batch1_{i}");
            buf.push(e);
        }
        let first_drain = buf.drain();
        assert_eq!(first_drain.len(), 3);
        assert_eq!(first_drain[0].event_type, "batch1_2");
        assert_eq!(buf.dropped_count(), 2);

        for i in 0..2 {
            let mut e = sample_event();
            e.event_type = format!("batch2_{i}");
            buf.push(e);
        }
        let second_drain = buf.drain();
        assert_eq!(second_drain.len(), 2);
        assert_eq!(second_drain[0].event_type, "batch2_0");
        // Dropped count unchanged from second batch
        assert_eq!(buf.dropped_count(), 2);
    }

    #[test]
    fn buffer_exactly_at_capacity_boundary() {
        let mut buf = EventBuffer::new(5);
        for i in 0..5 {
            let mut e = sample_event();
            e.event_type = format!("e{i}");
            buf.push(e);
        }
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.dropped_count(), 0);

        // One more triggers drop
        let mut e = sample_event();
        e.event_type = "overflow".to_owned();
        buf.push(e);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.dropped_count(), 1);

        let events = buf.drain();
        assert_eq!(events[0].event_type, "e1");
        assert_eq!(events[4].event_type, "overflow");
    }

    // ── TailConfig edge cases ───────────────────────────────────

    #[test]
    fn parse_connectors_only_commas() {
        let connectors = TailConfig::parse_connectors(",,,");
        assert!(connectors.is_empty());
    }

    #[test]
    fn parse_connectors_whitespace_only_items() {
        let connectors = TailConfig::parse_connectors(" , , ");
        assert!(connectors.is_empty());
    }

    #[test]
    fn parse_connectors_many() {
        let input = (0..20)
            .map(|i| format!("conn_{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let connectors = TailConfig::parse_connectors(&input);
        assert_eq!(connectors.len(), 20);
        assert_eq!(connectors[0], "conn_0");
        assert_eq!(connectors[19], "conn_19");
    }

    #[test]
    fn parse_connectors_preserves_case() {
        let connectors = TailConfig::parse_connectors("Slack,DISCORD,gitHub");
        assert_eq!(connectors, vec!["Slack", "DISCORD", "gitHub"]);
    }

    #[test]
    fn parse_connectors_preserves_hyphens_and_underscores() {
        let connectors = TailConfig::parse_connectors("my-app,your_service");
        assert_eq!(connectors, vec!["my-app", "your_service"]);
    }

    #[test]
    fn tail_config_default_buffer_size() {
        let config = TailConfig::default();
        assert_eq!(config.buffer_size, 1000);
    }

    #[test]
    fn tail_config_clone() {
        let config = TailConfig {
            connectors: vec!["a".to_owned(), "b".to_owned()],
            all: true,
            since_seconds: Some(600),
            buffer_size: 2000,
        };
        let cloned = config.clone();
        assert_eq!(config.connectors.len(), 2);
        assert_eq!(cloned.connectors.len(), 2);
        assert_eq!(cloned.all, true);
        assert_eq!(cloned.since_seconds, Some(600));
    }

    #[test]
    fn tail_config_debug() {
        let config = TailConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("TailConfig"));
        assert!(debug.contains("buffer_size"));
    }

    #[test]
    fn tail_config_serialize_no_since() {
        let config = TailConfig {
            connectors: vec![],
            all: false,
            since_seconds: None,
            buffer_size: 1000,
        };
        let json = serde_json::to_value(&config).unwrap();
        assert!(json["since_seconds"].is_null());
        assert!(json["connectors"].as_array().unwrap().is_empty());
    }

    // ── TailPlan edge cases ─────────────────────────────────────

    #[test]
    fn tail_plan_clone() {
        let plan = TailPlan {
            connectors: vec!["slack".to_owned()],
            all: false,
            since: Some("5m".to_owned()),
            buffer_size: 500,
        };
        let cloned = plan.clone();
        assert_eq!(plan.connectors, cloned.connectors);
        assert_eq!(plan.since, cloned.since);
    }

    #[test]
    fn tail_plan_debug() {
        let plan = TailPlan {
            connectors: vec![],
            all: true,
            since: None,
            buffer_size: 1000,
        };
        let debug = format!("{plan:?}");
        assert!(debug.contains("TailPlan"));
        assert!(debug.contains("all"));
    }

    #[test]
    fn tail_plan_serialize_empty_connectors() {
        let plan = TailPlan {
            connectors: vec![],
            all: false,
            since: None,
            buffer_size: 1000,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json["connectors"].as_array().unwrap().is_empty());
        assert_eq!(json["all"], false);
    }

    #[test]
    fn tail_plan_serialize_many_connectors() {
        let plan = TailPlan {
            connectors: (0..10).map(|i| format!("c{i}")).collect(),
            all: false,
            since: Some("1h".to_owned()),
            buffer_size: 5000,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["connectors"].as_array().unwrap().len(), 10);
        assert_eq!(json["buffer_size"], 5000);
    }

    // ── StreamStatus edge cases ─────────────────────────────────

    #[test]
    fn stream_status_deserialize_from_string() {
        let active: StreamStatus = serde_json::from_str("\"active\"").unwrap();
        assert_eq!(active, StreamStatus::Active);

        let waiting: StreamStatus = serde_json::from_str("\"waiting\"").unwrap();
        assert_eq!(waiting, StreamStatus::Waiting);

        let error: StreamStatus = serde_json::from_str("\"error\"").unwrap();
        assert_eq!(error, StreamStatus::Error);

        let disc: StreamStatus = serde_json::from_str("\"disconnected\"").unwrap();
        assert_eq!(disc, StreamStatus::Disconnected);

        let unsup: StreamStatus = serde_json::from_str("\"unsupported\"").unwrap();
        assert_eq!(unsup, StreamStatus::Unsupported);
    }

    #[test]
    fn stream_status_invalid_value_fails() {
        let result = serde_json::from_str::<StreamStatus>("\"unknown_status\"");
        assert!(result.is_err());
    }

    #[test]
    fn stream_status_display_matches_serde() {
        for status in [
            StreamStatus::Active,
            StreamStatus::Waiting,
            StreamStatus::Error,
            StreamStatus::Disconnected,
            StreamStatus::Unsupported,
        ] {
            let display = status.to_string();
            let serde_str = serde_json::to_string(&status).unwrap();
            // serde wraps in quotes
            assert_eq!(format!("\"{display}\""), serde_str);
        }
    }

    #[test]
    fn stream_status_clone_all_variants() {
        let variants = [
            StreamStatus::Active,
            StreamStatus::Waiting,
            StreamStatus::Error,
            StreamStatus::Disconnected,
            StreamStatus::Unsupported,
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn stream_status_debug_all_variants() {
        let variants = [
            (StreamStatus::Active, "Active"),
            (StreamStatus::Waiting, "Waiting"),
            (StreamStatus::Error, "Error"),
            (StreamStatus::Disconnected, "Disconnected"),
            (StreamStatus::Unsupported, "Unsupported"),
        ];
        for (v, expected) in &variants {
            let debug = format!("{v:?}");
            assert!(debug.contains(expected));
        }
    }

    #[test]
    fn stream_status_inequality_all_pairs() {
        let variants = vec![
            StreamStatus::Active,
            StreamStatus::Waiting,
            StreamStatus::Error,
            StreamStatus::Disconnected,
            StreamStatus::Unsupported,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ── ConnectorStreamState edge cases ─────────────────────────

    #[test]
    fn connector_stream_state_debug() {
        let state = ConnectorStreamState {
            connector: "test".to_owned(),
            status: StreamStatus::Error,
            events_received: 0,
            last_event_at: None,
        };
        let debug = format!("{state:?}");
        assert!(debug.contains("ConnectorStreamState"));
        assert!(debug.contains("Error"));
    }

    #[test]
    fn connector_stream_state_high_event_count() {
        let state = ConnectorStreamState {
            connector: "firehose".to_owned(),
            status: StreamStatus::Active,
            events_received: u64::MAX,
            last_event_at: Some("2026-12-31T23:59:59Z".to_owned()),
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["events_received"], u64::MAX);
    }

    #[test]
    fn connector_stream_state_all_statuses() {
        for status in [
            StreamStatus::Active,
            StreamStatus::Waiting,
            StreamStatus::Error,
            StreamStatus::Disconnected,
            StreamStatus::Unsupported,
        ] {
            let expected_str = status.to_string();
            let state = ConnectorStreamState {
                connector: "test".to_owned(),
                status,
                events_received: 0,
                last_event_at: None,
            };
            let json = serde_json::to_value(&state).unwrap();
            assert_eq!(json["status"].as_str().unwrap(), expected_str);
        }
    }

    #[test]
    fn connector_stream_state_clone_independence() {
        let state = ConnectorStreamState {
            connector: "original".to_owned(),
            status: StreamStatus::Active,
            events_received: 10,
            last_event_at: Some("2026-01-01T00:00:00Z".to_owned()),
        };
        let mut cloned = state.clone();
        cloned.connector = "modified".to_owned();
        cloned.events_received = 20;
        assert_eq!(state.connector, "original");
        assert_eq!(state.events_received, 10);
    }

    // ── TailSummary edge cases ──────────────────────────────────

    #[test]
    fn tail_summary_debug() {
        let summary = TailSummary {
            streams: vec![],
            total_events: 0,
            dropped_events: 0,
        };
        let debug = format!("{summary:?}");
        assert!(debug.contains("TailSummary"));
        assert!(debug.contains("total_events"));
    }

    #[test]
    fn tail_summary_high_counters() {
        let summary = TailSummary {
            streams: vec![],
            total_events: u64::MAX,
            dropped_events: u64::MAX,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["total_events"], u64::MAX);
        assert_eq!(json["dropped_events"], u64::MAX);
    }

    #[test]
    fn tail_summary_many_streams() {
        let streams: Vec<ConnectorStreamState> = (0..50)
            .map(|i| ConnectorStreamState {
                connector: format!("conn_{i}"),
                status: if i % 2 == 0 {
                    StreamStatus::Active
                } else {
                    StreamStatus::Waiting
                },
                events_received: i as u64,
                last_event_at: None,
            })
            .collect();
        let summary = TailSummary {
            streams,
            total_events: 1225,
            dropped_events: 0,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["streams"].as_array().unwrap().len(), 50);
    }

    #[test]
    fn tail_summary_clone_independence() {
        let summary = TailSummary {
            streams: vec![ConnectorStreamState {
                connector: "x".to_owned(),
                status: StreamStatus::Active,
                events_received: 5,
                last_event_at: None,
            }],
            total_events: 5,
            dropped_events: 0,
        };
        let cloned = summary.clone();
        assert_eq!(summary.streams.len(), cloned.streams.len());
        assert_eq!(summary.total_events, cloned.total_events);
    }

    // ── Cross-type integration scenarios ────────────────────────

    #[test]
    fn event_through_buffer_preserves_data() {
        let mut buf = EventBuffer::new(10);
        let event = ConnectorEvent {
            timestamp: "2026-06-01T12:00:00Z".to_owned(),
            connector: "github".to_owned(),
            event_type: "push".to_owned(),
            context: Some("main".to_owned()),
            summary: Some("Fix bug".to_owned()),
            data: json!({"sha": "abc123", "files": ["a.rs", "b.rs"]}),
        };
        buf.push(event);
        let drained = buf.drain();
        assert_eq!(drained.len(), 1);
        let e = &drained[0];
        assert_eq!(e.connector, "github");
        assert_eq!(e.data["sha"], "abc123");
        assert_eq!(e.data["files"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn buffer_format_after_drain() {
        let mut buf = EventBuffer::new(5);
        for i in 0..3 {
            let mut e = sample_event();
            e.event_type = format!("type_{i}");
            buf.push(e);
        }
        let events = buf.drain();
        for (i, e) in events.iter().enumerate() {
            let toon = e.format_toon();
            assert!(toon.contains(&format!("type_{i}")));
            let json_str = e.format_json();
            let parsed: Value = serde_json::from_str(&json_str).unwrap();
            assert_eq!(parsed["event_type"], format!("type_{i}"));
        }
    }

    #[test]
    fn tail_config_to_event_buffer() {
        let config = TailConfig {
            connectors: vec!["slack".to_owned()],
            all: false,
            since_seconds: Some(300),
            buffer_size: 3,
        };
        let mut buf = EventBuffer::new(config.buffer_size);
        assert_eq!(buf.capacity(), 3);

        for i in 0..5 {
            let mut e = sample_event();
            e.event_type = format!("msg_{i}");
            buf.push(e);
        }
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 2);
    }

    #[test]
    fn summary_reflects_buffer_state() {
        let mut buf = EventBuffer::new(2);
        for i in 0..10 {
            let mut e = sample_event();
            e.event_type = format!("ev_{i}");
            buf.push(e);
        }
        let drained = buf.drain();
        let summary = TailSummary {
            streams: vec![ConnectorStreamState {
                connector: "slack".to_owned(),
                status: StreamStatus::Active,
                events_received: 10,
                last_event_at: Some("2026-03-09T14:32:05Z".to_owned()),
            }],
            total_events: drained.len() as u64,
            dropped_events: buf.dropped_count(),
        };
        assert_eq!(summary.total_events, 2);
        assert_eq!(summary.dropped_events, 8);
    }

    #[test]
    fn parse_since_feeds_tail_config() {
        let since = parse_since("10m").unwrap();
        let config = TailConfig {
            connectors: TailConfig::parse_connectors("slack,discord"),
            all: false,
            since_seconds: Some(since),
            buffer_size: 1000,
        };
        assert_eq!(config.since_seconds, Some(600));
        assert_eq!(config.connectors.len(), 2);
    }
}
