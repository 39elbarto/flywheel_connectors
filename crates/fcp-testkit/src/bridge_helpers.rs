//! Bridge and daemon connector test helpers.
//!
//! Provides utilities for testing connectors that bridge to external daemons
//! or local services (e.g., browser automation via CDP, home automation via
//! local API, desktop apps via IPC).
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::bridge_helpers::*;
//!
//! let mut tracker = BridgeConnectionTracker::new();
//! tracker.record_connect("ws://localhost:9222");
//! tracker.record_message_sent("Page.navigate");
//! tracker.record_message_received("Page.loadEventFired");
//! tracker.record_disconnect();
//!
//! assert_bridge_connected_once(&tracker);
//! assert_bridge_messages_exchanged(&tracker, 1, 1);
//! assert_bridge_clean_disconnect(&tracker);
//! ```

use std::time::{Duration, Instant};

use serde_json::{Value, json};

// ─────────────────────────────────────────────────────────────────────────────
// Bridge Connection Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// State of a bridge connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeState {
    /// Not yet connected.
    Disconnected,
    /// Connected to the bridge target.
    Connected,
    /// Connection failed.
    Failed,
    /// Cleanly disconnected.
    Closed,
}

/// A recorded bridge event.
#[derive(Debug, Clone)]
pub struct BridgeEvent {
    /// Event kind.
    pub kind: BridgeEventKind,
    /// When the event occurred.
    pub timestamp: Instant,
    /// Optional payload.
    pub payload: Option<Value>,
}

/// Kind of bridge event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeEventKind {
    /// Connection initiated to an endpoint.
    Connect(String),
    /// Message sent to the bridge target.
    MessageSent(String),
    /// Message received from the bridge target.
    MessageReceived(String),
    /// Connection closed cleanly.
    Disconnect,
    /// Connection error.
    Error(String),
    /// Reconnection attempt.
    Reconnect(u32),
}

/// Tracks bridge connection lifecycle for test assertions.
#[derive(Debug)]
pub struct BridgeConnectionTracker {
    events: Vec<BridgeEvent>,
    state: BridgeState,
    connect_count: u32,
    disconnect_count: u32,
    messages_sent: u32,
    messages_received: u32,
    errors: Vec<String>,
}

impl BridgeConnectionTracker {
    /// Create a new tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            state: BridgeState::Disconnected,
            connect_count: 0,
            disconnect_count: 0,
            messages_sent: 0,
            messages_received: 0,
            errors: Vec::new(),
        }
    }

    /// Record a connection event.
    pub fn record_connect(&mut self, endpoint: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Connect(endpoint.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.state = BridgeState::Connected;
        self.connect_count += 1;
    }

    /// Record a message sent to the bridge target.
    pub fn record_message_sent(&mut self, method: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::MessageSent(method.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.messages_sent += 1;
    }

    /// Record a message received from the bridge target.
    pub fn record_message_received(&mut self, method: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::MessageReceived(method.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.messages_received += 1;
    }

    /// Record a clean disconnect.
    pub fn record_disconnect(&mut self) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Disconnect,
            timestamp: Instant::now(),
            payload: None,
        });
        self.state = BridgeState::Closed;
        self.disconnect_count += 1;
    }

    /// Record a connection error.
    pub fn record_error(&mut self, error: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Error(error.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.state = BridgeState::Failed;
        self.errors.push(error.to_string());
    }

    /// Record a reconnection attempt.
    pub fn record_reconnect(&mut self, attempt: u32) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Reconnect(attempt),
            timestamp: Instant::now(),
            payload: None,
        });
    }

    /// Current connection state.
    #[must_use]
    pub const fn state(&self) -> BridgeState {
        self.state
    }

    /// Number of connection attempts.
    #[must_use]
    pub const fn connect_count(&self) -> u32 {
        self.connect_count
    }

    /// All recorded events.
    #[must_use]
    pub fn events(&self) -> &[BridgeEvent] {
        &self.events
    }

    /// Messages sent count.
    #[must_use]
    pub const fn messages_sent(&self) -> u32 {
        self.messages_sent
    }

    /// Messages received count.
    #[must_use]
    pub const fn messages_received(&self) -> u32 {
        self.messages_received
    }

    /// All recorded errors.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl Default for BridgeConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock Bridge Responses
// ─────────────────────────────────────────────────────────────────────────────

/// Build a mock bridge discovery response (e.g., CDP target list).
#[must_use]
pub fn mock_bridge_discovery(targets: &[(&str, &str)]) -> Value {
    let items: Vec<Value> = targets
        .iter()
        .map(|(id, title)| {
            json!({
                "id": id,
                "title": title,
                "type": "page",
                "url": format!("about:blank#{id}"),
            })
        })
        .collect();
    json!(items)
}

/// Build a mock bridge command response.
#[must_use]
pub fn mock_bridge_command_response(id: u64, result: &Value) -> Value {
    json!({
        "id": id,
        "result": result,
    })
}

/// Build a mock bridge error response.
#[must_use]
pub fn mock_bridge_error_response(id: u64, code: i64, message: &str) -> Value {
    json!({
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

/// Build a mock bridge event (unsolicited server-sent message).
#[must_use]
pub fn mock_bridge_event(method: &str, params: &Value) -> Value {
    json!({
        "method": method,
        "params": params,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Prerequisites Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A prerequisite check result for bridge/daemon connectors.
#[derive(Debug, Clone)]
pub struct PrerequisiteCheck {
    /// Name of the prerequisite (e.g., "chromium", "docker").
    pub name: String,
    /// Whether it is available.
    pub available: bool,
    /// Version string if available.
    pub version: Option<String>,
    /// Path to the binary if found.
    pub path: Option<String>,
    /// Error message if unavailable.
    pub error: Option<String>,
}

/// Builder for prerequisite checks.
pub struct PrerequisiteCheckBuilder {
    name: String,
    available: bool,
    version: Option<String>,
    path: Option<String>,
    error: Option<String>,
}

impl PrerequisiteCheckBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            available: false,
            version: None,
            path: None,
            error: None,
        }
    }

    /// Mark as available with version.
    #[must_use]
    pub fn available(mut self, version: &str, path: &str) -> Self {
        self.available = true;
        self.version = Some(version.to_string());
        self.path = Some(path.to_string());
        self
    }

    /// Mark as unavailable with error.
    #[must_use]
    pub fn unavailable(mut self, error: &str) -> Self {
        self.available = false;
        self.error = Some(error.to_string());
        self
    }

    /// Build the check.
    #[must_use]
    pub fn build(self) -> PrerequisiteCheck {
        PrerequisiteCheck {
            name: self.name,
            available: self.available,
            version: self.version,
            path: self.path,
            error: self.error,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that the bridge connected exactly once.
///
/// # Panics
///
/// Panics if the connect count is not 1.
pub fn assert_bridge_connected_once(tracker: &BridgeConnectionTracker) {
    assert_eq!(
        tracker.connect_count(),
        1,
        "expected exactly one connection, got {}",
        tracker.connect_count()
    );
}

/// Assert the count of messages exchanged.
///
/// # Panics
///
/// Panics if sent or received counts don't match.
pub fn assert_bridge_messages_exchanged(
    tracker: &BridgeConnectionTracker,
    expected_sent: u32,
    expected_received: u32,
) {
    assert_eq!(
        tracker.messages_sent(),
        expected_sent,
        "expected {expected_sent} messages sent, got {}",
        tracker.messages_sent()
    );
    assert_eq!(
        tracker.messages_received(),
        expected_received,
        "expected {expected_received} messages received, got {}",
        tracker.messages_received()
    );
}

/// Assert that the bridge disconnected cleanly.
///
/// # Panics
///
/// Panics if the state is not `Closed` or there are recorded errors.
pub fn assert_bridge_clean_disconnect(tracker: &BridgeConnectionTracker) {
    assert_eq!(
        tracker.state(),
        BridgeState::Closed,
        "expected clean disconnect, state is {:?}",
        tracker.state()
    );
    assert!(
        tracker.errors().is_empty(),
        "expected no errors, got: {:?}",
        tracker.errors()
    );
}

/// Assert that a prerequisite check passed.
///
/// # Panics
///
/// Panics if the check is not available.
pub fn assert_prerequisite_available(check: &PrerequisiteCheck) {
    assert!(
        check.available,
        "prerequisite '{}' should be available but got error: {:?}",
        check.name, check.error
    );
}

/// Assert that a bridge had no errors during its lifecycle.
///
/// # Panics
///
/// Panics if any errors were recorded.
pub fn assert_bridge_no_errors(tracker: &BridgeConnectionTracker) {
    assert!(
        tracker.errors().is_empty(),
        "expected no bridge errors, got {} errors: {:?}",
        tracker.errors().len(),
        tracker.errors()
    );
}

/// Assert bridge connection happened within a timeout.
///
/// # Panics
///
/// Panics if there are no connect events, or the first occurred after the timeout.
pub fn assert_bridge_connected_within(tracker: &BridgeConnectionTracker, timeout: Duration) {
    let first_connect = tracker.events().iter().find(|e| {
        matches!(e.kind, BridgeEventKind::Connect(_))
    });
    assert!(first_connect.is_some(), "no connect event found");
    let first = tracker.events().first().expect("events not empty");
    let connect = first_connect.expect("connect event");
    let elapsed = connect.timestamp.duration_since(first.timestamp);
    assert!(
        elapsed <= timeout,
        "connection took {elapsed:?}, expected within {timeout:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_lifecycle() {
        let mut tracker = BridgeConnectionTracker::new();
        assert_eq!(tracker.state(), BridgeState::Disconnected);
        assert_eq!(tracker.connect_count(), 0);

        tracker.record_connect("ws://localhost:9222");
        assert_eq!(tracker.state(), BridgeState::Connected);
        assert_eq!(tracker.connect_count(), 1);

        tracker.record_message_sent("Page.navigate");
        tracker.record_message_received("Page.loadEventFired");
        assert_eq!(tracker.messages_sent(), 1);
        assert_eq!(tracker.messages_received(), 1);

        tracker.record_disconnect();
        assert_eq!(tracker.state(), BridgeState::Closed);
    }

    #[test]
    fn tracker_error_recording() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_error("connection refused");
        assert_eq!(tracker.state(), BridgeState::Failed);
        assert_eq!(tracker.errors().len(), 1);
    }

    #[test]
    fn tracker_reconnect_counting() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_error("timeout");
        tracker.record_reconnect(1);
        tracker.record_connect("ws://localhost:9222");
        assert_eq!(tracker.connect_count(), 2);
    }

    #[test]
    fn mock_bridge_discovery_format() {
        let disco = mock_bridge_discovery(&[("t1", "Tab 1"), ("t2", "Tab 2")]);
        let arr = disco.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], "t1");
        assert_eq!(arr[1]["title"], "Tab 2");
    }

    #[test]
    fn mock_bridge_command_response_format() {
        let resp = mock_bridge_command_response(42, &json!({"status": "ok"}));
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["status"], "ok");
    }

    #[test]
    fn mock_bridge_error_response_format() {
        let resp = mock_bridge_error_response(7, -32_600, "Invalid Request");
        assert_eq!(resp["id"], 7);
        assert_eq!(resp["error"]["code"], -32_600);
    }

    #[test]
    fn mock_bridge_event_format() {
        let evt = mock_bridge_event("Page.loadEventFired", &json!({"timestamp": 123.0}));
        assert_eq!(evt["method"], "Page.loadEventFired");
    }

    #[test]
    fn prerequisite_check_available() {
        let check = PrerequisiteCheckBuilder::new("chromium")
            .available("120.0.1", "/usr/bin/chromium")
            .build();
        assert!(check.available);
        assert_eq!(check.version.as_deref(), Some("120.0.1"));
        assert_prerequisite_available(&check);
    }

    #[test]
    fn prerequisite_check_unavailable() {
        let check = PrerequisiteCheckBuilder::new("docker")
            .unavailable("not found in PATH")
            .build();
        assert!(!check.available);
        assert_eq!(check.error.as_deref(), Some("not found in PATH"));
    }

    #[test]
    fn assert_clean_disconnect_passes() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_disconnect();
        assert_bridge_clean_disconnect(&tracker);
    }

    #[test]
    #[should_panic(expected = "expected clean disconnect")]
    fn assert_clean_disconnect_fails_on_connected() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        assert_bridge_clean_disconnect(&tracker);
    }

    #[test]
    fn assert_messages_exchanged_passes() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_message_sent("cmd1");
        tracker.record_message_sent("cmd2");
        tracker.record_message_received("resp1");
        assert_bridge_messages_exchanged(&tracker, 2, 1);
    }

    #[test]
    fn default_tracker() {
        let tracker = BridgeConnectionTracker::default();
        assert_eq!(tracker.state(), BridgeState::Disconnected);
    }

    #[test]
    fn assert_no_errors_passes_when_clean() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_disconnect();
        assert_bridge_no_errors(&tracker);
    }

    #[test]
    #[should_panic(expected = "expected no bridge errors")]
    fn assert_no_errors_fails_with_errors() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_error("boom");
        assert_bridge_no_errors(&tracker);
    }

    #[test]
    fn events_preserved_in_order() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_message_sent("a");
        tracker.record_message_received("b");
        tracker.record_disconnect();
        assert_eq!(tracker.events().len(), 4);
        assert!(matches!(tracker.events()[0].kind, BridgeEventKind::Connect(_)));
        assert!(matches!(tracker.events()[3].kind, BridgeEventKind::Disconnect));
    }
}
