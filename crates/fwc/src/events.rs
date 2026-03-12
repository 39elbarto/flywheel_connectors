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

    // ── Additional EventType tests ─────────────────────────────────

    #[test]
    fn event_type_deeply_nested_four_parts() {
        let et = EventType::new("a.b.c.d");
        assert_eq!(et.parts().len(), 4);
        assert_eq!(et.parts()[0], "a");
        assert_eq!(et.parts()[3], "d");
        assert_eq!(et.as_str(), "a.b.c.d");
    }

    #[test]
    fn event_type_clone_equality() {
        let et = EventType::new("message.new");
        let cloned = et.clone();
        assert_eq!(et, cloned);
        assert_eq!(et.as_str(), cloned.as_str());
        assert_eq!(et.parts(), cloned.parts());
    }

    #[test]
    fn event_type_not_equal_different_raw() {
        let a = EventType::new("message.new");
        let b = EventType::new("message.old");
        assert_ne!(a, b);
    }

    #[test]
    fn event_type_serde_roundtrip() {
        let et = EventType::new("project.issue.created");
        let json_str = serde_json::to_string(&et).expect("serialize");
        let back: EventType = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(et, back);
    }

    #[test]
    fn event_type_prefix_glob_multi_level_no_match_at_boundary() {
        // "a.b" should not match "a.b.*" because there's no sub-part beyond a.b
        let et = EventType::new("a.b");
        assert!(!et.matches_pattern("a.b.*"));
    }

    #[test]
    fn event_type_prefix_glob_deep_matches() {
        let et = EventType::new("a.b.c.d.e");
        assert!(et.matches_pattern("a.*"));
        assert!(et.matches_pattern("a.b.*"));
        assert!(et.matches_pattern("a.b.c.*"));
        assert!(et.matches_pattern("a.b.c.d.*"));
    }

    #[test]
    fn event_type_suffix_glob_multi_segment_suffix() {
        let et = EventType::new("x.y.z.error.fatal");
        assert!(et.matches_pattern("*.fatal"));
        assert!(et.matches_pattern("*.error.fatal"));
    }

    #[test]
    fn event_type_suffix_glob_exact_boundary() {
        // "a.error" has 2 parts; "*.error" suffix is 1 part.
        // Need parts.len() > suffix_parts.len(), so 2 > 1 => true.
        let et = EventType::new("a.error");
        assert!(et.matches_pattern("*.error"));
    }

    #[test]
    fn event_type_exact_match_single_segment() {
        let et = EventType::new("heartbeat");
        assert!(et.matches_pattern("heartbeat"));
        assert!(!et.matches_pattern("heartbeats"));
    }

    #[test]
    fn event_type_with_underscores() {
        let et = EventType::new("user_event.account_created");
        assert!(et.matches_pattern("user_event.*"));
        assert!(et.matches_pattern("user_event.account_created"));
    }

    #[test]
    fn event_type_with_numbers_in_parts() {
        let et = EventType::new("v2.message.new");
        assert!(et.matches_pattern("v2.*"));
        assert!(et.matches_pattern("v2.message.*"));
    }

    #[test]
    fn event_type_display_matches_as_str() {
        let et = EventType::new("a.b.c");
        assert_eq!(format!("{et}"), et.as_str());
    }

    #[test]
    fn event_type_prefix_glob_wrong_prefix() {
        let et = EventType::new("messages.new");
        // "message.*" should NOT match "messages.new" — different prefix.
        assert!(!et.matches_pattern("message.*"));
    }

    #[test]
    fn event_type_suffix_glob_wrong_suffix() {
        let et = EventType::new("network.errors");
        assert!(!et.matches_pattern("*.error"));
    }

    // ── Additional ConnectorEvent tests ────────────────────────────

    #[test]
    fn connector_event_with_all_builders() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
        let e = ConnectorEvent::new("jira", "issue.created", 100)
            .with_channel("eng-board")
            .with_summary("New ticket FCP-999")
            .with_data(json!({"priority": "P1", "labels": ["urgent"]}))
            .with_timestamp(ts);
        assert_eq!(e.connector_id, "jira");
        assert_eq!(e.event_type.as_str(), "issue.created");
        assert_eq!(e.sequence, 100);
        assert_eq!(e.channel.as_deref(), Some("eng-board"));
        assert_eq!(e.summary.as_deref(), Some("New ticket FCP-999"));
        assert_eq!(e.data["priority"], "P1");
        assert_eq!(e.timestamp, ts);
    }

    #[test]
    fn connector_event_clone_preserves_all_fields() {
        let e = ConnectorEvent::new("slack", "message.new", 7)
            .with_channel("#dev")
            .with_summary("Hello")
            .with_data(json!({"text": "world"}));
        let cloned = e.clone();
        assert_eq!(e.connector_id, cloned.connector_id);
        assert_eq!(e.event_type, cloned.event_type);
        assert_eq!(e.sequence, cloned.sequence);
        assert_eq!(e.channel, cloned.channel);
        assert_eq!(e.summary, cloned.summary);
        assert_eq!(e.data, cloned.data);
        assert_eq!(e.timestamp, cloned.timestamp);
    }

    #[test]
    fn connector_event_data_null_by_default() {
        let e = ConnectorEvent::new("test", "ping", 0);
        assert!(e.data.is_null());
    }

    #[test]
    fn connector_event_sequence_zero() {
        let e = ConnectorEvent::new("test", "start", 0);
        assert_eq!(e.sequence, 0);
    }

    #[test]
    fn connector_event_large_sequence() {
        let e = ConnectorEvent::new("test", "x", u64::MAX);
        assert_eq!(e.sequence, u64::MAX);
    }

    #[test]
    fn connector_event_empty_connector_id() {
        let e = ConnectorEvent::new("", "x", 1);
        assert_eq!(e.connector_id, "");
    }

    #[test]
    fn connector_event_complex_data_payload() {
        let data = json!({
            "nested": {
                "array": [1, 2, 3],
                "map": {"key": "value"},
                "null_field": null,
                "bool_field": true
            }
        });
        let e = ConnectorEvent::new("test", "x", 1).with_data(data.clone());
        assert_eq!(e.data, data);
    }

    #[test]
    fn connector_event_overwrite_data() {
        let e = ConnectorEvent::new("test", "x", 1)
            .with_data(json!({"first": 1}))
            .with_data(json!({"second": 2}));
        assert!(e.data.get("first").is_none());
        assert_eq!(e.data["second"], 2);
    }

    #[test]
    fn connector_event_serialization_with_all_fields() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 1, 15, 8, 30, 0).unwrap();
        let e = ConnectorEvent::new("github", "pr.merged", 42)
            .with_timestamp(ts)
            .with_channel("fcp-core")
            .with_summary("PR #100 merged")
            .with_data(json!({"author": "alice"}));
        let json_str = serde_json::to_string(&e).expect("serialize");
        let back: ConnectorEvent = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.connector_id, "github");
        assert_eq!(back.channel.as_deref(), Some("fcp-core"));
        assert_eq!(back.summary.as_deref(), Some("PR #100 merged"));
        assert_eq!(back.data["author"], "alice");
        assert_eq!(back.timestamp, ts);
    }

    // ── Additional EventSource tests ───────────────────────────────

    #[test]
    fn event_source_clone() {
        let mut src = EventSource::new("slack", "s1");
        src.record_event();
        src.record_event();
        let cloned = src.clone();
        assert_eq!(cloned.connector_id, "slack");
        assert_eq!(cloned.stream_id, "s1");
        assert_eq!(cloned.event_count, 2);
        assert_eq!(cloned.started_at, src.started_at);
    }

    #[test]
    fn event_source_serde_roundtrip() {
        let mut src = EventSource::new("github", "events");
        src.record_event();
        let json_str = serde_json::to_string(&src).expect("serialize");
        let back: EventSource = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(back.connector_id, "github");
        assert_eq!(back.stream_id, "events");
        assert_eq!(back.event_count, 1);
    }

    #[test]
    fn event_source_many_events() {
        let mut src = EventSource::new("test", "stream");
        for _ in 0..1000 {
            src.record_event();
        }
        assert_eq!(src.event_count, 1000);
    }

    #[test]
    fn event_source_empty_ids() {
        let src = EventSource::new("", "");
        assert_eq!(src.connector_id, "");
        assert_eq!(src.stream_id, "");
    }

    // ── Additional EventBuffer tests ───────────────────────────────

    #[test]
    fn buffer_multiple_drain_cycles() {
        let mut buf = EventBuffer::new(3);
        // First cycle
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2));
        let d1 = buf.drain();
        assert_eq!(d1.len(), 2);

        // Second cycle
        buf.push(event("c", "x", 3));
        buf.push(event("d", "x", 4));
        buf.push(event("e", "x", 5));
        let d2 = buf.drain();
        assert_eq!(d2.len(), 3);
        assert_eq!(d2[0].connector_id, "c");
    }

    #[test]
    fn buffer_drain_empty_returns_empty() {
        let mut buf = EventBuffer::new(5);
        let d = buf.drain();
        assert!(d.is_empty());
    }

    #[test]
    fn buffer_push_exactly_to_capacity() {
        let mut buf = EventBuffer::new(3);
        for i in 0..3 {
            assert!(buf.push(event("x", "y", i)).is_none());
        }
        assert!(buf.is_full());
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 0);
    }

    #[test]
    fn buffer_eviction_preserves_newer_events() {
        let mut buf = EventBuffer::new(3);
        for i in 0..10 {
            buf.push(event("x", "y", i));
        }
        assert_eq!(buf.dropped_count(), 7);
        let drained = buf.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].sequence, 7);
        assert_eq!(drained[1].sequence, 8);
        assert_eq!(drained[2].sequence, 9);
    }

    #[test]
    fn buffer_mixed_connectors_preserved_order() {
        let mut buf = EventBuffer::new(4);
        buf.push(event("slack", "msg", 1));
        buf.push(event("github", "push", 2));
        buf.push(event("linear", "issue", 3));
        buf.push(event("jira", "ticket", 4));
        let drained = buf.drain();
        assert_eq!(drained[0].connector_id, "slack");
        assert_eq!(drained[1].connector_id, "github");
        assert_eq!(drained[2].connector_id, "linear");
        assert_eq!(drained[3].connector_id, "jira");
    }

    #[test]
    fn buffer_is_full_after_eviction() {
        let mut buf = EventBuffer::new(2);
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2));
        buf.push(event("c", "x", 3)); // evicts a
        assert!(buf.is_full());
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn buffer_capacity_accessor_unchanged() {
        let mut buf = EventBuffer::new(5);
        assert_eq!(buf.capacity(), 5);
        for i in 0..10 {
            buf.push(event("x", "y", i));
        }
        assert_eq!(buf.capacity(), 5); // capacity doesn't change
    }

    #[test]
    fn buffer_drain_then_fill_again_to_capacity() {
        let mut buf = EventBuffer::new(2);
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2));
        buf.drain();
        buf.push(event("c", "x", 3));
        buf.push(event("d", "x", 4));
        assert!(buf.is_full());
        let d = buf.drain();
        assert_eq!(d[0].connector_id, "c");
        assert_eq!(d[1].connector_id, "d");
    }

    #[test]
    fn buffer_dropped_count_persists_across_drains() {
        let mut buf = EventBuffer::new(1);
        buf.push(event("a", "x", 1));
        buf.push(event("b", "x", 2)); // drops a
        buf.drain();
        buf.push(event("c", "x", 3));
        buf.push(event("d", "x", 4)); // drops c
        assert_eq!(buf.dropped_count(), 2);
    }

    // ── Additional EventOutputFormat tests ─────────────────────────

    #[test]
    fn event_output_format_default_is_toon() {
        let fmt = EventOutputFormat::default();
        assert_eq!(fmt, EventOutputFormat::Toon);
    }

    #[test]
    fn event_output_format_equality() {
        assert_eq!(EventOutputFormat::Json, EventOutputFormat::Json);
        assert_ne!(EventOutputFormat::Json, EventOutputFormat::Ndjson);
        assert_ne!(EventOutputFormat::Toon, EventOutputFormat::Json);
    }

    #[test]
    fn event_output_format_clone() {
        let fmt = EventOutputFormat::Ndjson;
        let cloned = fmt;
        assert_eq!(fmt, cloned);
    }

    #[test]
    fn event_output_format_debug() {
        let fmt = EventOutputFormat::Json;
        let dbg = format!("{fmt:?}");
        assert!(dbg.contains("Json"));
    }

    // ── Additional format_toon tests ───────────────────────────────

    #[test]
    fn format_toon_summary_only_no_channel() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 9, 9, 0, 0).unwrap();
        let e = ConnectorEvent::new("github", "push", 1)
            .with_timestamp(ts)
            .with_summary("3 commits to main");
        let line = format_toon(&e);
        assert_eq!(line, "[09:00:00] github  push  3 commits to main");
    }

    #[test]
    fn format_toon_empty_connector_id() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let e = ConnectorEvent::new("", "event", 1).with_timestamp(ts);
        let line = format_toon(&e);
        assert_eq!(line, "[00:00:00]   event");
    }

    #[test]
    fn format_toon_long_event_type() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
        let e = ConnectorEvent::new("svc", "a.b.c.d.e.f.g", 1).with_timestamp(ts);
        let line = format_toon(&e);
        assert!(line.contains("a.b.c.d.e.f.g"));
        assert!(line.starts_with("[23:59:59]"));
    }

    // ── Additional format_json / format_ndjson tests ───────────────

    #[test]
    fn format_json_contains_all_fields() {
        let e = ConnectorEvent::new("test", "a.b", 10)
            .with_channel("ch1")
            .with_summary("sum")
            .with_data(json!({"k": "v"}));
        let out = format_json(&e);
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert_eq!(parsed["connector_id"], "test");
        assert_eq!(parsed["sequence"], 10);
        assert_eq!(parsed["channel"], "ch1");
        assert_eq!(parsed["summary"], "sum");
        assert_eq!(parsed["data"]["k"], "v");
    }

    #[test]
    fn format_ndjson_contains_all_fields() {
        let e = ConnectorEvent::new("test", "a.b", 10)
            .with_channel("ch1")
            .with_summary("sum")
            .with_data(json!({"k": "v"}));
        let out = format_ndjson(&e);
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert_eq!(parsed["connector_id"], "test");
        assert_eq!(parsed["sequence"], 10);
        assert_eq!(parsed["channel"], "ch1");
        assert_eq!(parsed["summary"], "sum");
    }

    #[test]
    fn format_json_null_data_serialized() {
        let e = ConnectorEvent::new("test", "x", 1);
        let out = format_json(&e);
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert!(parsed["data"].is_null());
    }

    #[test]
    fn format_ndjson_null_optional_fields() {
        let e = ConnectorEvent::new("test", "x", 1);
        let out = format_ndjson(&e);
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert!(parsed["channel"].is_null());
        assert!(parsed["summary"].is_null());
    }

    #[test]
    fn format_json_with_nested_data() {
        let e = ConnectorEvent::new("test", "x", 1)
            .with_data(json!({"a": {"b": [1, 2, {"c": true}]}}));
        let out = format_json(&e);
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert_eq!(parsed["data"]["a"]["b"][2]["c"], true);
    }

    #[test]
    fn format_ndjson_with_special_chars() {
        let e = ConnectorEvent::new("test", "x", 1)
            .with_data(json!({"text": "line1\nline2\ttab"}));
        let out = format_ndjson(&e);
        // NDJSON is single-line, so newlines in data are escaped
        assert!(!out.contains('\n'));
        let parsed: Value = serde_json::from_str(&out).expect("parse");
        assert_eq!(parsed["data"]["text"], "line1\nline2\ttab");
    }

    // ── Additional TypeFilter tests ────────────────────────────────

    #[test]
    fn type_filter_single_segment_exact() {
        let f = parse_type_filter("heartbeat");
        assert!(f.matches(&event("s", "heartbeat", 1)));
        assert!(!f.matches(&event("s", "heartbeat.check", 1)));
    }

    #[test]
    fn type_filter_empty_pattern_exact() {
        let f = parse_type_filter("");
        assert!(f.matches(&event("s", "", 1)));
        assert!(!f.matches(&event("s", "x", 1)));
    }

    #[test]
    fn type_filter_prefix_glob_deep_hierarchy() {
        let f = parse_type_filter("project.*");
        assert!(f.matches(&event("s", "project.a", 1)));
        assert!(f.matches(&event("s", "project.a.b.c", 1)));
        assert!(!f.matches(&event("s", "project", 1)));
    }

    #[test]
    fn type_filter_suffix_glob_deep_hierarchy() {
        let f = parse_type_filter("*.completed");
        assert!(f.matches(&event("s", "task.completed", 1)));
        assert!(f.matches(&event("s", "a.b.c.completed", 1)));
        assert!(!f.matches(&event("s", "completed", 1)));
    }

    // ── Additional FieldFilter tests ───────────────────────────────

    #[test]
    fn field_filter_array_index_access() {
        let f = parse_field_filter("items.0=first").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"items": ["first", "second"]}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_array_index_out_of_bounds() {
        let f = parse_field_filter("items.5=nope").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"items": ["a", "b"]}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_nested_array_index() {
        let f = parse_field_filter("matrix.1.0=center").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"matrix": [["tl"], ["center"]]}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_equality_bool_false() {
        let f = parse_field_filter("active=false").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"active": false}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_equality_number_float() {
        let f = parse_field_filter("score=3.14").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"score": 3.14}));
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_equality_mismatch_type() {
        // "3" as string vs 3 as number
        let f = parse_field_filter("count=3").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"count": "three"}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_contains_on_object() {
        let f = parse_field_filter("meta~alice").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"meta": {"name": "alice"}}));
        // Contains mode serializes non-strings, so should find "alice" in the JSON
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_contains_no_match_on_object() {
        let f = parse_field_filter("meta~zzz").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"meta": {"name": "alice"}}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_deeply_nested_missing_intermediate() {
        let f = parse_field_filter("a.b.c.d=x").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"a": {"z": 1}}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_equality_on_null_mismatch() {
        let f = parse_field_filter("status=active").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"status": null}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_equality_on_array_value_no_match() {
        // Arrays are not handled by equality mode
        let f = parse_field_filter("tags=deploy").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"tags": ["deploy"]}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_single_segment_path() {
        let f = parse_field_filter("x=hello").expect("parse");
        assert_eq!(f.path(), &["x"]);
    }

    #[test]
    fn field_filter_contains_case_sensitive() {
        let f = parse_field_filter("text~Deploy").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"text": "deploy in progress"}));
        assert!(!f.matches(&e));
    }

    #[test]
    fn field_filter_equality_with_special_chars() {
        let f = parse_field_filter("tag=#foo-bar_baz").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"tag": "#foo-bar_baz"}));
        assert!(f.matches(&e));
    }

    // ── Additional ExcludeFilter tests ─────────────────────────────

    #[test]
    fn exclude_filter_prefix_glob() {
        let f = parse_exclude("debug.*");
        assert!(!f.matches(&event("s", "debug.trace", 1)));
        assert!(!f.matches(&event("s", "debug.verbose", 1)));
        assert!(f.matches(&event("s", "info.status", 1)));
    }

    #[test]
    fn exclude_filter_exact_type() {
        let f = parse_exclude("heartbeat");
        assert!(!f.matches(&event("s", "heartbeat", 1)));
        assert!(f.matches(&event("s", "heartbeat.check", 1)));
    }

    #[test]
    fn exclude_filter_from_explicit_constructor() {
        let inner = TypeFilter::new("system.*");
        let f = ExcludeFilter::new(inner);
        assert!(!f.matches(&event("s", "system.health", 1)));
        assert!(f.matches(&event("s", "user.action", 1)));
    }

    // ── Additional ConnectorFilter tests ───────────────────────────

    #[test]
    fn connector_filter_case_sensitive() {
        let f = ConnectorFilter::new("Slack");
        assert!(!f.matches(&event("slack", "x", 1)));
        assert!(f.matches(&event("Slack", "x", 1)));
    }

    #[test]
    fn connector_filter_empty_connector() {
        let f = ConnectorFilter::new("");
        assert!(f.matches(&event("", "x", 1)));
        assert!(!f.matches(&event("slack", "x", 1)));
    }

    #[test]
    fn connector_filter_with_special_chars() {
        let f = ConnectorFilter::new("my-connector_v2");
        assert!(f.matches(&event("my-connector_v2", "x", 1)));
        assert!(!f.matches(&event("my-connector_v3", "x", 1)));
    }

    // ── Additional FilterChain tests ───────────────────────────────

    #[test]
    fn filter_chain_default_trait() {
        let chain = FilterChain::default();
        assert!(chain.is_empty());
        assert!(chain.matches(&event("any", "x", 1)));
    }

    #[test]
    fn filter_chain_three_filters_all_must_match() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(ConnectorFilter::new("slack")));
        chain.add(Box::new(TypeFilter::new("message.*")));
        chain.add(Box::new(parse_exclude("message.delete")));

        assert!(chain.matches(&event("slack", "message.new", 1)));
        assert!(!chain.matches(&event("slack", "message.delete", 1)));
        assert!(!chain.matches(&event("github", "message.new", 1)));
        assert!(!chain.matches(&event("slack", "issue.closed", 1)));
    }

    #[test]
    fn filter_chain_with_field_filter() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(parse_field_filter("status=open").expect("parse")));
        let open = event_with_data("s", "x", 1, json!({"status": "open"}));
        let closed = event_with_data("s", "x", 2, json!({"status": "closed"}));
        assert!(chain.matches(&open));
        assert!(!chain.matches(&closed));
    }

    #[test]
    fn filter_chain_len_after_multiple_adds() {
        let mut chain = FilterChain::new();
        for _ in 0..5 {
            chain.add(Box::new(TypeFilter::new("*")));
        }
        assert_eq!(chain.len(), 5);
        assert!(!chain.is_empty());
    }

    // ── Additional FilterChainBuilder tests ────────────────────────

    #[test]
    fn builder_multiple_type_filters() {
        // Multiple with_type calls add separate filters (AND semantics)
        let chain = FilterChainBuilder::new()
            .with_type("message.*")
            .with_type("*.new")
            .build();
        assert_eq!(chain.len(), 2);
        // "message.new" matches both patterns
        assert!(chain.matches(&event("s", "message.new", 1)));
        // "message.delete" matches first but not second
        assert!(!chain.matches(&event("s", "message.delete", 1)));
    }

    #[test]
    fn builder_exclude_multiple_types() {
        let chain = FilterChainBuilder::new()
            .exclude_type("*.error")
            .exclude_type("*.fatal")
            .build();
        assert!(chain.matches(&event("s", "network.success", 1)));
        assert!(!chain.matches(&event("s", "network.error", 1)));
        assert!(!chain.matches(&event("s", "system.fatal", 1)));
    }

    #[test]
    fn builder_with_field_match_equality_and_contains() {
        let chain = FilterChainBuilder::new()
            .with_field_match("channel=#general")
            .with_field_match("text~deploy")
            .build();
        assert_eq!(chain.len(), 2);
        let good = event_with_data(
            "s",
            "x",
            1,
            json!({"channel": "#general", "text": "deploy v2.3"}),
        );
        assert!(chain.matches(&good));
        let wrong_text = event_with_data(
            "s",
            "x",
            1,
            json!({"channel": "#general", "text": "rollback v1"}),
        );
        assert!(!chain.matches(&wrong_text));
    }

    #[test]
    fn builder_with_connector_and_exclude() {
        let chain = FilterChainBuilder::new()
            .with_connector("slack")
            .exclude_type("heartbeat")
            .build();
        assert!(chain.matches(&event("slack", "message.new", 1)));
        assert!(!chain.matches(&event("slack", "heartbeat", 1)));
        assert!(!chain.matches(&event("github", "message.new", 1)));
    }

    // ── Additional integration / edge case tests ───────────────────

    #[test]
    fn buffer_filter_format_pipeline() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let mut buf = EventBuffer::new(10);
        buf.push(
            ConnectorEvent::new("slack", "message.new", 1)
                .with_timestamp(ts)
                .with_channel("#dev")
                .with_data(json!({"text": "hello"})),
        );
        buf.push(ConnectorEvent::new("slack", "heartbeat", 2).with_timestamp(ts));
        buf.push(
            ConnectorEvent::new("github", "push", 3)
                .with_timestamp(ts)
                .with_data(json!({"branch": "main"})),
        );

        let chain = FilterChainBuilder::new()
            .with_connector("slack")
            .exclude_type("heartbeat")
            .build();

        let results: Vec<String> = buf
            .drain()
            .into_iter()
            .filter(|e| chain.matches(e))
            .map(|e| format_event(&e, EventOutputFormat::Toon))
            .collect();

        assert_eq!(results.len(), 1);
        assert!(results[0].contains("slack"));
        assert!(results[0].contains("message.new"));
    }

    #[test]
    fn filter_chain_on_events_with_varied_data() {
        let chain = FilterChainBuilder::new()
            .with_type("alert.*")
            .with_field_match("severity=critical")
            .build();

        let critical_alert = event_with_data(
            "monitor",
            "alert.triggered",
            1,
            json!({"severity": "critical", "message": "CPU > 95%"}),
        );
        let warn_alert = event_with_data(
            "monitor",
            "alert.triggered",
            2,
            json!({"severity": "warning", "message": "CPU > 80%"}),
        );
        let non_alert = event_with_data(
            "monitor",
            "metric.reported",
            3,
            json!({"severity": "critical"}),
        );

        assert!(chain.matches(&critical_alert));
        assert!(!chain.matches(&warn_alert));
        assert!(!chain.matches(&non_alert));
    }

    #[test]
    fn multiple_connectors_in_buffer_filtered_separately() {
        let mut buf = EventBuffer::new(20);
        for i in 0..5 {
            buf.push(event("slack", "message.new", i));
        }
        for i in 5..10 {
            buf.push(event("github", "push", i));
        }
        for i in 10..15 {
            buf.push(event("linear", "issue.created", i));
        }

        let slack_chain = FilterChainBuilder::new().with_connector("slack").build();
        let github_chain = FilterChainBuilder::new().with_connector("github").build();

        let events = buf.drain();
        let slack_events: Vec<_> = events.iter().filter(|e| slack_chain.matches(e)).collect();
        let github_events: Vec<_> = events.iter().filter(|e| github_chain.matches(e)).collect();

        assert_eq!(slack_events.len(), 5);
        assert_eq!(github_events.len(), 5);
    }

    #[test]
    fn format_ndjson_multiple_events_each_parseable() {
        let events = vec![
            event("a", "x.y", 1),
            event("b", "z.w", 2),
            event("c", "q.r", 3),
        ];
        for e in &events {
            let line = format_ndjson(e);
            assert!(!line.contains('\n'));
            let parsed: Value = serde_json::from_str(&line).expect("parse");
            assert!(parsed["connector_id"].is_string());
        }
    }

    #[test]
    fn event_type_pattern_matching_exhaustive() {
        let et = EventType::new("a.b.c");
        // Exact
        assert!(et.matches_pattern("a.b.c"));
        assert!(!et.matches_pattern("a.b.d"));
        // Wildcard
        assert!(et.matches_pattern("*"));
        // Prefix globs
        assert!(et.matches_pattern("a.*"));
        assert!(et.matches_pattern("a.b.*"));
        assert!(!et.matches_pattern("a.b.c.*"));
        // Suffix globs
        assert!(et.matches_pattern("*.c"));
        assert!(et.matches_pattern("*.b.c"));
        assert!(!et.matches_pattern("*.a.b.c"));
    }

    #[test]
    fn connector_event_debug_format() {
        let e = ConnectorEvent::new("test", "x", 1);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ConnectorEvent"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn event_source_debug_format() {
        let src = EventSource::new("test", "stream-1");
        let dbg = format!("{src:?}");
        assert!(dbg.contains("EventSource"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn event_type_debug_format() {
        let et = EventType::new("a.b");
        let dbg = format!("{et:?}");
        assert!(dbg.contains("EventType"));
        assert!(dbg.contains("a.b"));
    }

    #[test]
    fn buffer_with_data_events_preserves_payload() {
        let mut buf = EventBuffer::new(3);
        buf.push(event_with_data("s", "x", 1, json!({"key": "val1"})));
        buf.push(event_with_data("s", "x", 2, json!({"key": "val2"})));
        let drained = buf.drain();
        assert_eq!(drained[0].data["key"], "val1");
        assert_eq!(drained[1].data["key"], "val2");
    }

    #[test]
    fn format_event_toon_dispatch_matches_direct() {
        let e = event("test", "x", 1);
        let via_dispatch = format_event(&e, EventOutputFormat::Toon);
        let direct = format_toon(&e);
        assert_eq!(via_dispatch, direct);
    }

    #[test]
    fn format_event_json_dispatch_matches_direct() {
        let e = event("test", "x", 1);
        let via_dispatch = format_event(&e, EventOutputFormat::Json);
        let direct = format_json(&e);
        assert_eq!(via_dispatch, direct);
    }

    #[test]
    fn format_event_ndjson_dispatch_matches_direct() {
        let e = event("test", "x", 1);
        let via_dispatch = format_event(&e, EventOutputFormat::Ndjson);
        let direct = format_ndjson(&e);
        assert_eq!(via_dispatch, direct);
    }

    #[test]
    fn field_filter_contains_number_serialized() {
        let f = parse_field_filter("count~42").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"count": 42}));
        // Non-string: serialized to "42", contains "42"
        assert!(f.matches(&e));
    }

    #[test]
    fn field_filter_contains_bool_serialized() {
        let f = parse_field_filter("flag~true").expect("parse");
        let e = event_with_data("s", "x", 1, json!({"flag": true}));
        assert!(f.matches(&e));
    }

    #[test]
    fn exclude_filter_combined_with_connector_filter() {
        let mut chain = FilterChain::new();
        chain.add(Box::new(ConnectorFilter::new("slack")));
        chain.add(Box::new(parse_exclude("*.error")));

        assert!(chain.matches(&event("slack", "message.new", 1)));
        assert!(!chain.matches(&event("slack", "network.error", 1)));
        assert!(!chain.matches(&event("github", "message.new", 1)));
    }

    #[test]
    fn parse_field_filter_error_message() {
        match parse_field_filter("noop") {
            Err(err) => {
                let msg = format!("{err}");
                assert!(msg.contains("invalid field filter"));
                assert!(msg.contains("noop"));
            }
            Ok(_) => panic!("expected error for invalid expression"),
        }
    }
}
