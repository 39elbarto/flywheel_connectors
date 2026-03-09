//! Unified event stream tailing and filtering for `fwc`.
//!
//! Models connector event streams with typed envelopes, bounded ring buffers
//! for backpressure, hierarchical event-type matching, and composable filters.
//! The actual async stream consumption happens in the host integration layer;
//! this module provides the event primitives, formatting, and filter pipeline.

use std::collections::VecDeque;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Event types ─────────────────────────────────────────────────────────

/// Parsed, hierarchical event type (e.g. `"message.new"` -> `["message", "new"]`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventType {
    /// The raw dotted string, e.g. `"message.new"`.
    raw: String,
    /// Pre-split parts for matching.
    parts: Vec<String>,
}

impl EventType {
    /// Create a new event type from a dotted string.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let parts = raw.split('.').map(String::from).collect();
        Self { raw, parts }
    }

    /// The raw string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The constituent parts of this type.
    #[must_use]
    pub fn parts(&self) -> &[String] {
        &self.parts
    }

    /// Check whether this event type matches a glob-style pattern.
    ///
    /// Supported patterns:
    /// - `"*"` matches everything
    /// - `"message.*"` matches any type starting with `"message."` (prefix glob)
    /// - `"*.error"` matches any type ending with `".error"` (suffix glob)
    /// - `"message.new"` exact match
    #[must_use]
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix(".*") {
            // Prefix glob: "message.*" matches "message.new", "message.updated"
            // but NOT "message" alone or "messages.new".
            let prefix_parts: Vec<&str> = prefix.split('.').collect();
            if self.parts.len() <= prefix_parts.len() {
                return false;
            }
            return self.parts[..prefix_parts.len()]
                .iter()
                .zip(prefix_parts.iter())
                .all(|(a, b)| a == b);
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Suffix glob: "*.error" matches "network.error", "auth.error"
            // but NOT "error" alone.
            let suffix_parts: Vec<&str> = suffix.split('.').collect();
            if self.parts.len() <= suffix_parts.len() {
                return false;
            }
            let start = self.parts.len() - suffix_parts.len();
            return self.parts[start..]
                .iter()
                .zip(suffix_parts.iter())
                .all(|(a, b)| a.as_str() == *b);
        }
        // Exact match.
        self.raw == pattern
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Unified event envelope from a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Which connector produced the event.
    pub connector_id: String,
    /// Parsed event type.
    pub event_type: EventType,
    /// Optional channel / topic / stream name.
    pub channel: Option<String>,
    /// Human-readable one-line summary.
    pub summary: Option<String>,
    /// Arbitrary event payload.
    pub data: Value,
    /// Monotonically increasing sequence within the source stream.
    pub sequence: u64,
}

impl ConnectorEvent {
    /// Shorthand constructor for tests and simple use.
    #[must_use]
    pub fn new(
        connector_id: impl Into<String>,
        event_type: impl Into<String>,
        sequence: u64,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            connector_id: connector_id.into(),
            event_type: EventType::new(event_type),
            channel: None,
            summary: None,
            data: Value::Null,
            sequence,
        }
    }

    /// Set the channel.
    #[must_use]
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// Set the summary.
    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Set the data payload.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    /// Set the timestamp explicitly.
    #[must_use]
    pub const fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts;
        self
    }
}

/// Tracks metadata about an active event source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSource {
    /// Connector producing events.
    pub connector_id: String,
    /// Opaque stream identifier assigned by the connector.
    pub stream_id: String,
    /// When this source started producing events.
    pub started_at: DateTime<Utc>,
    /// Running count of events received from this source.
    pub event_count: u64,
}

impl EventSource {
    /// Create a new source tracker.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, stream_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
            stream_id: stream_id.into(),
            started_at: Utc::now(),
            event_count: 0,
        }
    }

    /// Record that an event was received.
    pub const fn record_event(&mut self) {
        self.event_count += 1;
    }
}

// ── Event buffer ────────────────────────────────────────────────────────

/// Bounded ring buffer for backpressure handling.
///
/// When the buffer is full, the oldest event is evicted to make room for
/// new arrivals.  The total number of dropped events is tracked.
pub struct EventBuffer {
    /// Maximum number of events the buffer can hold.
    capacity: usize,
    /// The ring of buffered events.
    ring: VecDeque<ConnectorEvent>,
    /// Running count of events evicted due to capacity.
    dropped: u64,
}

impl EventBuffer {
    /// Create a new buffer with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "EventBuffer capacity must be > 0");
        Self {
            capacity,
            ring: VecDeque::with_capacity(capacity),
            dropped: 0,
        }
    }

    /// Push an event into the buffer.
    ///
    /// Returns the evicted event if the buffer was already full.
    pub fn push(&mut self, event: ConnectorEvent) -> Option<ConnectorEvent> {
        let evicted = if self.ring.len() == self.capacity {
            self.dropped += 1;
            self.ring.pop_front()
        } else {
            None
        };
        self.ring.push_back(event);
        evicted
    }

    /// Drain all buffered events in order.
    pub fn drain(&mut self) -> Vec<ConnectorEvent> {
        self.ring.drain(..).collect()
    }

    /// Number of events currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Whether the buffer is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.ring.len() == self.capacity
    }

    /// Total number of events that were dropped (evicted) since creation.
    #[must_use]
    pub const fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// The configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

// ── Event formatting ────────────────────────────────────────────────────

/// Output format for event rendering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventOutputFormat {
    /// Compact one-liner suitable for agent tailing.
    #[default]
    Toon,
    /// Pretty-printed JSON.
    Json,
    /// Newline-delimited JSON (single-line).
    Ndjson,
}

/// Format a `ConnectorEvent` according to the chosen output style.
#[must_use]
pub fn format_event(event: &ConnectorEvent, format: EventOutputFormat) -> String {
    match format {
        EventOutputFormat::Toon => format_toon(event),
        EventOutputFormat::Json => format_json(event),
        EventOutputFormat::Ndjson => format_ndjson(event),
    }
}

/// TOON-style compact one-liner.
///
/// Layout: `[HH:MM:SS] <connector>  <event_type>  <channel?>  <summary?>`
#[must_use]
pub fn format_toon(event: &ConnectorEvent) -> String {
    let ts = event.timestamp.format("%H:%M:%S");
    let mut line = format!("[{ts}] {}  {}", event.connector_id, event.event_type);
    if let Some(ref ch) = event.channel {
        line.push_str("  ");
        line.push_str(ch);
    }
    if let Some(ref s) = event.summary {
        line.push_str("  ");
        line.push_str(s);
    }
    line
}

/// Pretty-printed JSON.
#[must_use]
pub fn format_json(event: &ConnectorEvent) -> String {
    serde_json::to_string_pretty(event).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Single-line newline-delimited JSON.
#[must_use]
pub fn format_ndjson(event: &ConnectorEvent) -> String {
    serde_json::to_string(event).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

// ── Filters ─────────────────────────────────────────────────────────────

/// Trait for event filters.
pub trait EventFilter {
    /// Returns `true` if the event should be included.
    fn matches(&self, event: &ConnectorEvent) -> bool;
}

/// Matches events by event-type pattern.
pub struct TypeFilter {
    pattern: String,
}

impl TypeFilter {
    /// Create a new type filter from a glob-style pattern.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// The pattern string.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Parse a pattern string into a [`TypeFilter`].
#[must_use]
pub fn parse_type_filter(pattern: &str) -> TypeFilter {
    TypeFilter::new(pattern)
}

impl EventFilter for TypeFilter {
    fn matches(&self, event: &ConnectorEvent) -> bool {
        event.event_type.matches_pattern(&self.pattern)
    }
}

/// Matches events by a data field value.
pub struct FieldFilter {
    /// Dot-separated path into `event.data` (e.g. `"channel"`, `"user.name"`).
    path: Vec<String>,
    /// Match mode.
    mode: FieldMatchMode,
}

/// How the field value is compared.
enum FieldMatchMode {
    /// Exact string equality (`=`).
    Equality(String),
    /// Substring contains (`~`).
    Contains(String),
}

impl FieldFilter {
    /// Access the field path.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }
}

/// Parse a field filter expression.
///
/// Supported formats:
/// - `"field.path=value"` equality
/// - `"field.path~pattern"` substring contains
///
/// # Errors
///
/// Returns an error if the expression contains neither `=` nor `~`.
pub fn parse_field_filter(expr: &str) -> anyhow::Result<FieldFilter> {
    // Try equality first.
    if let Some((field, value)) = expr.split_once('=') {
        let path = field.split('.').map(String::from).collect();
        return Ok(FieldFilter {
            path,
            mode: FieldMatchMode::Equality(value.to_owned()),
        });
    }
    if let Some((field, value)) = expr.split_once('~') {
        let path = field.split('.').map(String::from).collect();
        return Ok(FieldFilter {
            path,
            mode: FieldMatchMode::Contains(value.to_owned()),
        });
    }
    anyhow::bail!(
        "invalid field filter expression (expected `field=value` or `field~pattern`): {expr}"
    )
}

impl EventFilter for FieldFilter {
    fn matches(&self, event: &ConnectorEvent) -> bool {
        let mut cursor = &event.data;
        for segment in &self.path {
            match cursor.get(segment.as_str()) {
                Some(next) => cursor = next,
                None => {
                    // Try array index.
                    if let Ok(idx) = segment.parse::<usize>() {
                        match cursor.get(idx) {
                            Some(next) => cursor = next,
                            None => return false,
                        }
                    } else {
                        return false;
                    }
                }
            }
        }
        match &self.mode {
            FieldMatchMode::Equality(expected) => match cursor {
                Value::String(s) => s == expected,
                Value::Number(n) => n.to_string() == *expected,
                Value::Bool(b) => b.to_string() == *expected,
                Value::Null => expected == "null",
                _ => false,
            },
            FieldMatchMode::Contains(needle) => {
                if let Value::String(s) = cursor {
                    s.contains(needle.as_str())
                } else {
                    let rendered = serde_json::to_string(cursor).unwrap_or_default();
                    rendered.contains(needle.as_str())
                }
            }
        }
    }
}

/// Inverts any filter — events matching the inner filter are excluded.
pub struct ExcludeFilter<F: EventFilter> {
    inner: F,
}

impl<F: EventFilter> ExcludeFilter<F> {
    /// Create an exclude wrapper around an inner filter.
    #[must_use]
    pub const fn new(inner: F) -> Self {
        Self { inner }
    }
}

/// Convenience: parse an exclude-by-type filter.
#[must_use]
pub fn parse_exclude(pattern: &str) -> ExcludeFilter<TypeFilter> {
    ExcludeFilter::new(TypeFilter::new(pattern))
}

impl<F: EventFilter> EventFilter for ExcludeFilter<F> {
    fn matches(&self, event: &ConnectorEvent) -> bool {
        !self.inner.matches(event)
    }
}

/// Matches events by connector id.
pub struct ConnectorFilter {
    connector_id: String,
}

impl ConnectorFilter {
    /// Create a connector filter.
    #[must_use]
    pub fn new(connector_id: impl Into<String>) -> Self {
        Self {
            connector_id: connector_id.into(),
        }
    }

    /// The connector id being filtered on.
    #[must_use]
    pub fn connector_id(&self) -> &str {
        &self.connector_id
    }
}

impl EventFilter for ConnectorFilter {
    fn matches(&self, event: &ConnectorEvent) -> bool {
        event.connector_id == self.connector_id
    }
}

/// Composable chain of filters with AND semantics.
///
/// All filters in the chain must match for an event to pass.  An empty chain
/// passes everything.
pub struct FilterChain {
    filters: Vec<Box<dyn EventFilter>>,
}

impl FilterChain {
    /// Create an empty filter chain (passes everything).
    #[must_use]
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Add a filter to the chain.
    pub fn add(&mut self, filter: Box<dyn EventFilter>) {
        self.filters.push(filter);
    }

    /// Apply the chain to an event.
    #[must_use]
    pub fn matches(&self, event: &ConnectorEvent) -> bool {
        self.filters.iter().all(|f| f.matches(event))
    }

    /// Number of filters in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the chain has no filters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

impl EventFilter for FilterChain {
    fn matches(&self, event: &ConnectorEvent) -> bool {
        self.filters.iter().all(|f| f.matches(event))
    }
}

/// Builder for composing a [`FilterChain`] declaratively.
pub struct FilterChainBuilder {
    filters: Vec<Box<dyn EventFilter>>,
}

impl FilterChainBuilder {
    /// Start building a filter chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Include only events whose type matches the given pattern.
    #[must_use]
    pub fn with_type(mut self, pattern: &str) -> Self {
        self.filters.push(Box::new(TypeFilter::new(pattern)));
        self
    }

    /// Include only events matching a field expression (e.g. `"channel=#general"`).
    ///
    /// If the expression is malformed the filter is silently skipped.
    #[must_use]
    pub fn with_field_match(mut self, expr: &str) -> Self {
        if let Ok(f) = parse_field_filter(expr) {
            self.filters.push(Box::new(f));
        }
        self
    }

    /// Exclude events whose type matches the given pattern.
    #[must_use]
    pub fn exclude_type(mut self, pattern: &str) -> Self {
        self.filters.push(Box::new(parse_exclude(pattern)));
        self
    }

    /// Include only events from a specific connector.
    #[must_use]
    pub fn with_connector(mut self, connector_id: &str) -> Self {
        self.filters
            .push(Box::new(ConnectorFilter::new(connector_id)));
        self
    }

    /// Finalize the chain.
    #[must_use]
    pub fn build(self) -> FilterChain {
        FilterChain {
            filters: self.filters,
        }
    }
}

impl Default for FilterChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn event(connector: &str, etype: &str, seq: u64) -> ConnectorEvent {
        ConnectorEvent::new(connector, etype, seq)
    }

    fn event_with_data(connector: &str, etype: &str, seq: u64, data: Value) -> ConnectorEvent {
        ConnectorEvent::new(connector, etype, seq).with_data(data)
    }

    // ── EventType tests ─────────────────────────────────────────────

    #[test]
    fn event_type_parts() {
        let et = EventType::new("message.new");
        assert_eq!(et.parts(), &["message", "new"]);
        assert_eq!(et.as_str(), "message.new");
    }

    #[test]
    fn event_type_single_part() {
        let et = EventType::new("heartbeat");
        assert_eq!(et.parts(), &["heartbeat"]);
    }

    #[test]
    fn event_type_three_parts() {
        let et = EventType::new("project.issue.created");
        assert_eq!(et.parts().len(), 3);
        assert_eq!(et.parts()[2], "created");
    }

    #[test]
    fn event_type_display() {
        let et = EventType::new("issue.updated");
        assert_eq!(format!("{et}"), "issue.updated");
    }

    #[test]
    fn event_type_exact_match() {
        let et = EventType::new("message.new");
        assert!(et.matches_pattern("message.new"));
        assert!(!et.matches_pattern("message.old"));
    }

    #[test]
    fn event_type_wildcard_everything() {
        let et = EventType::new("issue.closed");
        assert!(et.matches_pattern("*"));
    }

    #[test]
    fn event_type_prefix_glob() {
        let et = EventType::new("message.new");
        assert!(et.matches_pattern("message.*"));
    }

    #[test]
    fn event_type_prefix_glob_no_match() {
        let et = EventType::new("issue.closed");
        assert!(!et.matches_pattern("message.*"));
    }

    #[test]
    fn event_type_prefix_glob_requires_deeper() {
        // "message" alone should NOT match "message.*" because there is no sub-part.
        let et = EventType::new("message");
        assert!(!et.matches_pattern("message.*"));
    }

    #[test]
    fn event_type_suffix_glob() {
        let et = EventType::new("network.error");
        assert!(et.matches_pattern("*.error"));
    }

    #[test]
    fn event_type_suffix_glob_deeper() {
        let et = EventType::new("auth.token.error");
        assert!(et.matches_pattern("*.error"));
    }

    #[test]
    fn event_type_suffix_glob_no_match() {
        let et = EventType::new("message.new");
        assert!(!et.matches_pattern("*.error"));
    }

    #[test]
    fn event_type_suffix_glob_requires_prefix() {
        // "error" alone should NOT match "*.error" — must have something before.
        let et = EventType::new("error");
        assert!(!et.matches_pattern("*.error"));
    }

    #[test]
    fn event_type_case_sensitive() {
        let et = EventType::new("Message.New");
        assert!(!et.matches_pattern("message.new"));
        assert!(et.matches_pattern("Message.New"));
    }

    #[test]
    fn event_type_multi_segment_prefix_glob() {
        let et = EventType::new("project.issue.created");
        assert!(et.matches_pattern("project.issue.*"));
        assert!(et.matches_pattern("project.*"));
        assert!(!et.matches_pattern("project.issue.created.*"));
    }

    // ── ConnectorEvent tests ────────────────────────────────────────

    #[test]
    fn connector_event_construction() {
        let e = event("slack", "message.new", 1);
        assert_eq!(e.connector_id, "slack");
        assert_eq!(e.event_type.as_str(), "message.new");
        assert_eq!(e.sequence, 1);
        assert!(e.channel.is_none());
        assert!(e.summary.is_none());
        assert_eq!(e.data, Value::Null);
    }

    #[test]
    fn connector_event_builder_chain() {
        let e = ConnectorEvent::new("github", "issue.opened", 42)
            .with_channel("fcp-core")
            .with_summary("Issue #123 opened")
            .with_data(json!({"number": 123}));
        assert_eq!(e.channel.as_deref(), Some("fcp-core"));
        assert_eq!(e.summary.as_deref(), Some("Issue #123 opened"));
        assert_eq!(e.data["number"], 123);
        assert_eq!(e.sequence, 42);
    }

    #[test]
    fn connector_event_serialization_roundtrip() {
        let e = ConnectorEvent::new("linear", "issue.updated", 7)
            .with_channel("eng")
            .with_data(json!({"priority": "high"}));
        let json_str = serde_json::to_string(&e).expect("serialize");
        let back: ConnectorEvent = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.connector_id, "linear");
        assert_eq!(back.event_type.as_str(), "issue.updated");
        assert_eq!(back.sequence, 7);
        assert_eq!(back.data["priority"], "high");
    }

    #[test]
    fn connector_event_with_timestamp() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 9, 14, 32, 5).unwrap();
        let e = ConnectorEvent::new("slack", "message.new", 1).with_timestamp(ts);
        assert_eq!(e.timestamp, ts);
    }

    // ── EventSource tests ───────────────────────────────────────────

    #[test]
    fn event_source_initial_count() {
        let src = EventSource::new("slack", "stream-1");
        assert_eq!(src.connector_id, "slack");
        assert_eq!(src.stream_id, "stream-1");
        assert_eq!(src.event_count, 0);
    }

    #[test]
    fn event_source_record_increments() {
        let mut src = EventSource::new("github", "events");
        src.record_event();
        src.record_event();
        src.record_event();
        assert_eq!(src.event_count, 3);
    }

    #[test]
    fn event_source_serializable() {
        let src = EventSource::new("linear", "webhooks");
        let json_str = serde_json::to_string(&src).expect("serialize");
        assert!(json_str.contains("linear"));
        assert!(json_str.contains("webhooks"));
    }

    // ── EventBuffer tests ───────────────────────────────────────────

    #[test]
    fn buffer_empty_initially() {
        let buf = EventBuffer::new(10);
        assert!(buf.is_empty());
        assert!(!buf.is_full());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 10);
        assert_eq!(buf.dropped_count(), 0);
    }

    #[test]
    fn buffer_push_and_drain() {
        let mut buf = EventBuffer::new(5);
        buf.push(event("a", "x.y", 1));
        buf.push(event("b", "x.z", 2));
        assert_eq!(buf.len(), 2);

        let drained = buf.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].connector_id, "a");
        assert_eq!(drained[1].connector_id, "b");
        assert!(buf.is_empty());
    }

    #[test]
    fn buffer_evicts_oldest_when_full() {
        let mut buf = EventBuffer::new(2);
        assert!(buf.push(event("a", "x", 1)).is_none());
        assert!(buf.push(event("b", "x", 2)).is_none());
        assert!(buf.is_full());

        let evicted = buf.push(event("c", "x", 3));
        assert!(evicted.is_some());
        assert_eq!(evicted.unwrap().connector_id, "a");
        assert_eq!(buf.dropped_count(), 1);
        assert_eq!(buf.len(), 2);

        let drained = buf.drain();
        assert_eq!(drained[0].connector_id, "b");
        assert_eq!(drained[1].connector_id, "c");
    }

    #[test]
    fn buffer_dropped_count_accumulates() {
        let mut buf = EventBuffer::new(1);
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2));
        buf.push(event("c", "x", 3));
        assert_eq!(buf.dropped_count(), 2);
        assert_eq!(buf.len(), 1);
        let drained = buf.drain();
        assert_eq!(drained[0].connector_id, "c");
    }

    #[test]
    fn buffer_capacity_one() {
        let mut buf = EventBuffer::new(1);
        buf.push(event("a", "x", 1));
        assert!(buf.is_full());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn buffer_large_capacity() {
        let mut buf = EventBuffer::new(1000);
        for i in 0..1000 {
            buf.push(event("x", "y", i));
        }
        assert!(buf.is_full());
        assert_eq!(buf.dropped_count(), 0);
        buf.push(event("x", "y", 1000));
        assert_eq!(buf.dropped_count(), 1);
    }

    #[test]
    fn buffer_drain_resets_len_not_dropped() {
        let mut buf = EventBuffer::new(2);
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2));
        buf.push(event("c", "x", 3));
        assert_eq!(buf.dropped_count(), 1);
        buf.drain();
        assert!(buf.is_empty());
        // Dropped count persists.
        assert_eq!(buf.dropped_count(), 1);
    }

    #[test]
    fn buffer_push_returns_none_when_not_full() {
        let mut buf = EventBuffer::new(5);
        for i in 0..5 {
            assert!(buf.push(event("x", "y", i)).is_none());
        }
    }

    #[test]
    fn buffer_sequences_preserved_in_order() {
        let mut buf = EventBuffer::new(5);
        for i in 0..5 {
            buf.push(event("x", "y", i * 10));
        }
        let drained = buf.drain();
        let seqs: Vec<u64> = drained.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![0, 10, 20, 30, 40]);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn buffer_zero_capacity_panics() {
        let _ = EventBuffer::new(0);
    }

    // ── EventFormatter tests ────────────────────────────────────────

    #[test]
    fn format_toon_basic() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 9, 14, 32, 5).unwrap();
        let e = ConnectorEvent::new("slack", "message.new", 1)
            .with_timestamp(ts)
            .with_channel("#general")
            .with_summary("@alice: Hey team");
        let line = format_toon(&e);
        assert_eq!(
            line,
            "[14:32:05] slack  message.new  #general  @alice: Hey team"
        );
    }

    #[test]
    fn format_toon_no_optional_fields() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let e = ConnectorEvent::new("github", "push", 1).with_timestamp(ts);
        let line = format_toon(&e);
        assert_eq!(line, "[00:00:00] github  push");
    }

    #[test]
    fn format_toon_channel_only() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 6, 15, 8, 5, 30).unwrap();
        let e = ConnectorEvent::new("discord", "message.new", 3)
            .with_timestamp(ts)
            .with_channel("#dev");
        let line = format_toon(&e);
        assert_eq!(line, "[08:05:30] discord  message.new  #dev");
    }

    #[test]
    fn format_json_is_pretty() {
        let e = event("test", "x.y", 1);
        let out = format_json(&e);
        // Pretty JSON has newlines and indentation.
        assert!(out.contains('\n'));
        assert!(out.contains("  "));
        assert!(out.contains("\"connector_id\""));
    }

    #[test]
    fn format_ndjson_single_line() {
        let e = event("test", "x.y", 1);
        let out = format_ndjson(&e);
        assert!(!out.contains('\n'));
        assert!(out.contains("\"connector_id\""));
        assert!(out.contains("\"event_type\""));
    }

    #[test]
    fn format_event_dispatch() {
        let e = event("test", "x", 1);
        let toon = format_event(&e, EventOutputFormat::Toon);
        let json = format_event(&e, EventOutputFormat::Json);
        let ndjson = format_event(&e, EventOutputFormat::Ndjson);
        assert!(toon.starts_with('['));
        assert!(json.contains('\n'));
        assert!(!ndjson.contains('\n'));
    }

    #[test]
    fn format_toon_unicode_summary() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 9, 12, 0, 0).unwrap();
        let e = ConnectorEvent::new("slack", "message.new", 1)
            .with_timestamp(ts)
            .with_summary("Deployment complete \u{2705}");
        let line = format_toon(&e);
        assert!(line.contains("\u{2705}"));
    }

    #[test]
    fn format_ndjson_parseable() {
        let e = ConnectorEvent::new("test", "a.b", 99).with_data(json!({"key": "value"}));
        let line = format_ndjson(&e);
        let parsed: Value = serde_json::from_str(&line).expect("should parse");
        assert_eq!(parsed["data"]["key"], "value");
        assert_eq!(parsed["sequence"], 99);
    }

    // ── TypeFilter tests ────────────────────────────────────────────

    #[test]
    fn type_filter_exact() {
        let f = parse_type_filter("message.new");
        assert!(f.matches(&event("s", "message.new", 1)));
        assert!(!f.matches(&event("s", "message.old", 1)));
    }

    #[test]
    fn type_filter_prefix_wildcard() {
        let f = parse_type_filter("message.*");
        assert!(f.matches(&event("s", "message.new", 1)));
        assert!(f.matches(&event("s", "message.updated", 1)));
        assert!(!f.matches(&event("s", "issue.new", 1)));
    }

    #[test]
    fn type_filter_suffix_wildcard() {
        let f = parse_type_filter("*.error");
        assert!(f.matches(&event("s", "network.error", 1)));
        assert!(f.matches(&event("s", "auth.error", 1)));
        assert!(!f.matches(&event("s", "network.success", 1)));
    }

    #[test]
    fn type_filter_star_matches_all() {
        let f = parse_type_filter("*");
        assert!(f.matches(&event("s", "anything", 1)));
        assert!(f.matches(&event("s", "deeply.nested.type", 1)));
    }

    #[test]
    fn type_filter_no_match() {
        let f = parse_type_filter("webhook.received");
        assert!(!f.matches(&event("s", "message.new", 1)));
    }

    #[test]
    fn type_filter_case_sensitive() {
        let f = parse_type_filter("Message.*");
        assert!(!f.matches(&event("s", "message.new", 1)));
        assert!(f.matches(&event("s", "Message.new", 1)));
    }

    #[test]
    fn type_filter_pattern_accessor() {
        let f = parse_type_filter("issue.*");
        assert_eq!(f.pattern(), "issue.*");
    }

    #[test]
    fn type_filter_multi_segment_prefix() {
        let f = parse_type_filter("project.issue.*");
        assert!(f.matches(&event("s", "project.issue.created", 1)));
        assert!(!f.matches(&event("s", "project.pr.created", 1)));
    }

    // ── FieldFilter tests ───────────────────────────────────────────

    #[test]
    fn field_filter_equality_string() {
        let f = parse_field_filter("channel=#general").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"channel": "#general"}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_equality_no_match() {
        let f = parse_field_filter("channel=#random").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"channel": "#general"}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_equality_number() {
        let f = parse_field_filter("severity=3").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"severity": 3}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_equality_bool() {
        let f = parse_field_filter("active=true").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"active": true}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_contains() {
        let f = parse_field_filter("text~deploy").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"text": "Starting deploy v2.3"}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_contains_no_match() {
        let f = parse_field_filter("text~rollback").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"text": "Starting deploy v2.3"}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_nested_path() {
        let f = parse_field_filter("user.name=alice").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"user": {"name": "alice"}}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_deeply_nested() {
        let f = parse_field_filter("a.b.c=deep").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"a": {"b": {"c": "deep"}}}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_missing_field() {
        let f = parse_field_filter("missing=value").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"other": "stuff"}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_null_field() {
        let f = parse_field_filter("status=null").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"status": null}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_contains_on_array() {
        let f = parse_field_filter("tags~deploy").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"tags": ["deploy", "prod"]}));
        // Contains works by serializing non-strings.
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_path_accessor() {
        let f = parse_field_filter("a.b.c=x").expect("parse");
        assert_eq!(f.path(), &["a", "b", "c"]);
    }

    #[test]
    fn field_filter_invalid_expression() {
        let result = parse_field_filter("no_operator_here");
        assert!(result.is_err());
    }

    // ── ExcludeFilter tests ─────────────────────────────────────────

    #[test]
    fn exclude_filter_inverts() {
        let f = parse_exclude("message.delete");
        assert!(!f.matches(&event("s", "message.delete", 1)));
        assert!(f.matches(&event("s", "message.new", 1)));
    }

    #[test]
    fn exclude_filter_with_wildcard() {
        let f = parse_exclude("*.error");
        assert!(!f.matches(&event("s", "network.error", 1)));
        assert!(f.matches(&event("s", "network.success", 1)));
    }

    #[test]
    fn exclude_filter_star_excludes_all() {
        let f = parse_exclude("*");
        assert!(!f.matches(&event("s", "anything", 1)));
    }

    #[test]
    fn exclude_combined_with_type_filter() {
        let include = TypeFilter::new("message.*");
        let exclude = ExcludeFilter::new(TypeFilter::new("message.delete"));

        let new_msg = event("s", "message.new", 1);
        let del_msg = event("s", "message.delete", 2);

        assert!(include.matches(&new_msg) && exclude.matches(&new_msg));
        assert!(include.matches(&del_msg) && !exclude.matches(&del_msg));
    }

    // ── ConnectorFilter tests ───────────────────────────────────────

    #[test]
    fn connector_filter_matches() {
        let f = ConnectorFilter::new("slack");
        assert!(f.matches(&event("slack", "message.new", 1)));
        assert!(!f.matches(&event("github", "push", 1)));
    }

    #[test]
    fn connector_filter_accessor() {
        let f = ConnectorFilter::new("linear");
        assert_eq!(f.connector_id(), "linear");
    }

    // ── FilterChain tests ───────────────────────────────────────────

    #[test]
    fn empty_chain_passes_everything() {
        let chain = FilterChain::new();
        assert!(chain.is_empty());
        assert!(chain.matches(&event("any", "thing", 1)));
    }

    #[test]
    fn chain_single_filter() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(TypeFilter::new("message.*")));
        assert!(chain.matches(&event("s", "message.new", 1)));
        assert!(!chain.matches(&event("s", "issue.closed", 1)));
    }

    #[test]
    fn chain_multiple_and_filters() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(TypeFilter::new("message.*")));
        chain.add(Box::new(ConnectorFilter::new("slack")));
        // Both must match.
        assert!(chain.matches(&event("slack", "message.new", 1)));
        assert!(!chain.matches(&event("github", "message.new", 1)));
        assert!(!chain.matches(&event("slack", "issue.closed", 1)));
    }

    #[test]
    fn chain_no_match() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(TypeFilter::new("webhook.received")));
        assert!(!chain.matches(&event("s", "message.new", 1)));
    }

    #[test]
    fn chain_len() {
        let mut chain = FilterChain::new();
        assert_eq!(chain.len(), 0);
        chain.add(Box::new(TypeFilter::new("*")));
        assert_eq!(chain.len(), 1);
        chain.add(Box::new(ConnectorFilter::new("x")));
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn chain_as_event_filter_trait() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(TypeFilter::new("message.*")));
        let filter: &dyn EventFilter = &chain;
        assert!(filter.matches(&event("s", "message.new", 1)));
    }

    // ── FilterChainBuilder tests ────────────────────────────────────

    #[test]
    fn builder_type_and_field() {
        let chain = FilterChainBuilder::new()
            .with_type("message.*")
            .with_field_match("channel=#general")
            .build();
        assert_eq!(chain.len(), 2);

        let matching = ConnectorEvent::new("slack", "message.new", 1)
            .with_data(json!({"channel": "#general"}));
        assert!(chain.matches(&matching));

        let wrong_channel =
            ConnectorEvent::new("slack", "message.new", 2).with_data(json!({"channel": "#random"}));
        assert!(!chain.matches(&wrong_channel));
    }

    #[test]
    fn builder_exclude_type() {
        let chain = FilterChainBuilder::new()
            .with_type("message.*")
            .exclude_type("message.delete")
            .build();
        assert!(chain.matches(&event("s", "message.new", 1)));
        assert!(!chain.matches(&event("s", "message.delete", 2)));
    }

    #[test]
    fn builder_with_connector() {
        let chain = FilterChainBuilder::new().with_connector("slack").build();
        assert!(chain.matches(&event("slack", "x", 1)));
        assert!(!chain.matches(&event("github", "x", 1)));
    }

    #[test]
    fn builder_complex_compound() {
        let chain = FilterChainBuilder::new()
            .with_type("message.*")
            .with_connector("slack")
            .with_field_match("channel=#general")
            .exclude_type("message.delete")
            .build();
        assert_eq!(chain.len(), 4);

        let good = ConnectorEvent::new("slack", "message.new", 1)
            .with_data(json!({"channel": "#general"}));
        assert!(chain.matches(&good));

        // Wrong connector.
        let wrong_conn = ConnectorEvent::new("github", "message.new", 2)
            .with_data(json!({"channel": "#general"}));
        assert!(!chain.matches(&wrong_conn));

        // Excluded type.
        let excluded = ConnectorEvent::new("slack", "message.delete", 3)
            .with_data(json!({"channel": "#general"}));
        assert!(!chain.matches(&excluded));
    }

    #[test]
    fn builder_empty_builds_pass_all() {
        let chain = FilterChainBuilder::new().build();
        assert!(chain.is_empty());
        assert!(chain.matches(&event("any", "thing", 1)));
    }

    #[test]
    fn builder_default_builds_pass_all() {
        let chain = FilterChainBuilder::default().build();
        assert!(chain.is_empty());
    }

    #[test]
    fn builder_invalid_field_match_silently_skipped() {
        let chain = FilterChainBuilder::new()
            .with_field_match("no_operator")
            .build();
        // Invalid expression is skipped, so chain is empty.
        assert!(chain.is_empty());
    }

    // ── Integration / edge case tests ───────────────────────────────

    #[test]
    fn filter_chain_with_buffer() {
        let chain = FilterChainBuilder::new().with_type("message.*").build();

        let mut buf = EventBuffer::new(10);
        for i in 0..5 {
            buf.push(event("s", "message.new", i));
        }
        for i in 5..10 {
            buf.push(event("s", "issue.closed", i));
        }

        let filtered: Vec<ConnectorEvent> = buf
            .drain()
            .into_iter()
            .filter(|e| chain.matches(e))
            .collect();
        assert_eq!(filtered.len(), 5);
        assert!(
            filtered
                .iter()
                .all(|e| e.event_type.as_str() == "message.new")
        );
    }

    #[test]
    fn format_all_three_for_same_event() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 9, 10, 0, 0).unwrap();
        let e = ConnectorEvent::new("linear", "issue.created", 5)
            .with_timestamp(ts)
            .with_channel("eng-team")
            .with_summary("FCP-1234: Add event filtering");

        let toon = format_toon(&e);
        assert!(toon.starts_with("[10:00:00]"));
        assert!(toon.contains("linear"));
        assert!(toon.contains("eng-team"));

        let json = format_json(&e);
        let parsed: Value = serde_json::from_str(&json).expect("json parse");
        assert_eq!(parsed["connector_id"], "linear");

        let ndjson = format_ndjson(&e);
        assert!(!ndjson.contains('\n'));
        let parsed2: Value = serde_json::from_str(&ndjson).expect("ndjson parse");
        assert_eq!(parsed2["sequence"], 5);
    }

    #[test]
    fn field_filter_equality_on_empty_string() {
        let f = parse_field_filter("name=").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"name": ""}));
        assert!(f.matches(&e));
        let e2 = event_with_data("s", "x", 1, json!({"name": "notempty"}));
        assert!(!f.matches(&e2));
    }

    #[test]
    fn field_filter_contains_empty_needle() {
        let f = parse_field_filter("text~").expect("parse");
        // Empty needle matches everything.
        let e = event_with_data("s", "x", 1, json!({"text": "anything"}));
        assert!(f.matches(&e));
    }

    #[test]
    fn event_type_empty_string() {
        let et = EventType::new("");
        assert_eq!(et.parts(), &[""]);
        assert_eq!(et.as_str(), "");
    }

    #[test]
    fn buffer_drain_then_push() {
        let mut buf = EventBuffer::new(3);
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2));
        let _ = buf.drain();
        assert!(buf.is_empty());
        buf.push(event("c", "x", 3));
        assert_eq!(buf.len(), 1);
        let drained = buf.drain();
        assert_eq!(drained[0].connector_id, "c");
    }
}
