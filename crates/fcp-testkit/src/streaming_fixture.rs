//! Reusable streaming and bidirectional fixture harnesses for session-oriented
//! connector acceptance tests.
//!
//! These fixtures run real TCP listeners that speak SSE or raw line-delimited
//! JSON, giving connectors a genuine network boundary to test against without
//! requiring a remote SaaS provider.
//!
//! # Integration with session-script DSL
//!
//! The fixtures in this module are designed to be scripted using
//! [`crate::session_script::SessionScript`] and produce
//! [`crate::session_script::SessionTranscript`] records.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SSE Event
// ---------------------------------------------------------------------------

/// A server-sent event to be delivered by the fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseEvent {
    /// Optional event type (SSE `event:` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Event data (SSE `data:` field).
    pub data: String,
    /// Optional event ID (SSE `id:` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optional retry hint in milliseconds (SSE `retry:` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_ms: Option<u64>,
}

impl SseEvent {
    /// Create a simple data-only SSE event.
    #[must_use]
    pub fn data(data: &str) -> Self {
        Self {
            event: None,
            data: data.to_owned(),
            id: None,
            retry_ms: None,
        }
    }

    /// Create a typed SSE event.
    #[must_use]
    pub fn typed(event_type: &str, data: &str) -> Self {
        Self {
            event: Some(event_type.to_owned()),
            data: data.to_owned(),
            id: None,
            retry_ms: None,
        }
    }

    /// Set the event ID.
    #[must_use]
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_owned());
        self
    }

    /// Set the retry hint.
    #[must_use]
    pub const fn with_retry(mut self, retry_ms: u64) -> Self {
        self.retry_ms = Some(retry_ms);
        self
    }

    /// Format as SSE wire format.
    #[must_use]
    pub fn to_sse_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(ref event) = self.event {
            buf.extend_from_slice(format!("event: {event}\n").as_bytes());
        }
        if let Some(ref id) = self.id {
            buf.extend_from_slice(format!("id: {id}\n").as_bytes());
        }
        if let Some(retry) = self.retry_ms {
            buf.extend_from_slice(format!("retry: {retry}\n").as_bytes());
        }
        for line in self.data.lines() {
            buf.extend_from_slice(format!("data: {line}\n").as_bytes());
        }
        buf.extend_from_slice(b"\n");
        buf
    }
}

// ---------------------------------------------------------------------------
// Streaming behavior scripts
// ---------------------------------------------------------------------------

/// A scripted action for the streaming fixture server to perform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum StreamingAction {
    /// Send an SSE event.
    SendSse { event: SseEvent },
    /// Send a raw line-delimited JSON message.
    SendJson { body: serde_json::Value },
    /// Wait before the next action.
    Delay {
        #[serde(with = "duration_ms_serde")]
        duration: Duration,
    },
    /// Drop the connection (simulating a server crash).
    DropConnection,
    /// Send an SSE comment (keep-alive heartbeat).
    SendHeartbeat,
}

impl StreamingAction {
    /// Send a data-only SSE event.
    #[must_use]
    pub fn send_sse(data: &str) -> Self {
        Self::SendSse {
            event: SseEvent::data(data),
        }
    }

    /// Send a typed SSE event.
    #[must_use]
    pub fn send_typed_sse(event_type: &str, data: &str) -> Self {
        Self::SendSse {
            event: SseEvent::typed(event_type, data),
        }
    }

    /// Send a JSON line.
    #[must_use]
    pub fn send_json(body: serde_json::Value) -> Self {
        Self::SendJson { body }
    }

    /// Wait for a duration.
    #[must_use]
    pub const fn delay(duration: Duration) -> Self {
        Self::Delay { duration }
    }

    /// Drop the connection.
    #[must_use]
    pub const fn drop_connection() -> Self {
        Self::DropConnection
    }

    /// Send a heartbeat comment.
    #[must_use]
    pub const fn heartbeat() -> Self {
        Self::SendHeartbeat
    }
}

// ---------------------------------------------------------------------------
// StreamingFixtureServer
// ---------------------------------------------------------------------------

/// Internal state shared between the accept thread and the test.
struct FixtureState {
    actions: Mutex<VecDeque<StreamingAction>>,
    connections_accepted: AtomicU64,
    messages_sent: AtomicU64,
    running: AtomicBool,
}

/// A real TCP server that delivers scripted SSE or JSON-line events.
///
/// The fixture binds to a random local port, accepts connections, and plays
/// back the scripted actions in order.  Tests use this to exercise real
/// reconnection, backpressure, and shutdown behavior.
pub struct StreamingFixtureServer {
    address: SocketAddr,
    state: Arc<FixtureState>,
    _handle: JoinHandle<()>,
}

impl StreamingFixtureServer {
    /// Start the fixture server on a random port.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind.
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let state = Arc::new(FixtureState {
            actions: Mutex::new(VecDeque::new()),
            connections_accepted: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            running: AtomicBool::new(true),
        });

        let thread_state = Arc::clone(&state);
        let handle = thread::spawn(move || {
            Self::accept_loop(listener, thread_state);
        });

        Ok(Self {
            address,
            state,
            _handle: handle,
        })
    }

    /// The local address the fixture is listening on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The base URL for HTTP connections.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The SSE endpoint URL.
    #[must_use]
    pub fn sse_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// Enqueue scripted actions to be played back on the next connection.
    pub fn script(&self, actions: Vec<StreamingAction>) {
        let mut queue = self.state.actions.lock().expect("actions lock poisoned");
        queue.extend(actions);
    }

    /// Enqueue a single action.
    pub fn enqueue(&self, action: StreamingAction) {
        let mut queue = self.state.actions.lock().expect("actions lock poisoned");
        queue.push_back(action);
    }

    /// Number of connections accepted so far.
    #[must_use]
    pub fn connections_accepted(&self) -> u64 {
        self.state.connections_accepted.load(Ordering::Relaxed)
    }

    /// Number of messages sent so far.
    #[must_use]
    pub fn messages_sent(&self) -> u64 {
        self.state.messages_sent.load(Ordering::Relaxed)
    }

    /// Stop the fixture server.
    pub fn stop(&self) {
        self.state.running.store(false, Ordering::Relaxed);
    }

    fn accept_loop(listener: TcpListener, state: Arc<FixtureState>) {
        while state.running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    state.connections_accepted.fetch_add(1, Ordering::Relaxed);
                    let conn_state = Arc::clone(&state);
                    thread::spawn(move || {
                        Self::handle_connection(stream, conn_state);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, state: Arc<FixtureState>) {
        // Read the HTTP request (we don't parse it fully, just consume it)
        let mut buf = [0u8; 4096];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let _ = stream.read(&mut buf);

        // Send SSE response headers
        let headers = "HTTP/1.1 200 OK\r\n\
                       Content-Type: text/event-stream\r\n\
                       Cache-Control: no-cache\r\n\
                       Connection: keep-alive\r\n\
                       \r\n";
        if stream.write_all(headers.as_bytes()).is_err() {
            return;
        }
        let _ = stream.flush();

        // Play back scripted actions
        loop {
            let action = {
                let mut queue = match state.actions.lock() {
                    Ok(q) => q,
                    Err(_) => return,
                };
                queue.pop_front()
            };

            match action {
                Some(StreamingAction::SendSse { event }) => {
                    if stream.write_all(&event.to_sse_bytes()).is_err() {
                        return;
                    }
                    let _ = stream.flush();
                    state.messages_sent.fetch_add(1, Ordering::Relaxed);
                }
                Some(StreamingAction::SendJson { body }) => {
                    let json = serde_json::to_string(&body)
                        .expect("StreamingAction::SendJson body should serialize");
                    let line = format!("{json}\n");
                    if stream.write_all(line.as_bytes()).is_err() {
                        return;
                    }
                    let _ = stream.flush();
                    state.messages_sent.fetch_add(1, Ordering::Relaxed);
                }
                Some(StreamingAction::Delay { duration }) => {
                    thread::sleep(duration);
                }
                Some(StreamingAction::DropConnection) => {
                    drop(stream);
                    return;
                }
                Some(StreamingAction::SendHeartbeat) => {
                    if stream.write_all(b": heartbeat\n\n").is_err() {
                        return;
                    }
                    let _ = stream.flush();
                }
                None => {
                    if !state.running.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

impl Drop for StreamingFixtureServer {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Canonical streaming scenarios
// ---------------------------------------------------------------------------

/// Pre-built streaming scenario scripts for common acceptance patterns.
pub mod streaming_scenarios {
    use super::*;
    use serde_json::json;

    /// SSE: deliver N events with sequential IDs.
    #[must_use]
    pub fn sse_sequential_events(count: u32) -> Vec<StreamingAction> {
        (0..count)
            .map(|i| {
                StreamingAction::SendSse {
                    event: SseEvent::typed("message", &json!({"seq": i}).to_string())
                        .with_id(&i.to_string()),
                }
            })
            .collect()
    }

    /// SSE: deliver events with heartbeat intervals.
    #[must_use]
    pub fn sse_events_with_heartbeats(event_count: u32) -> Vec<StreamingAction> {
        let mut actions = Vec::new();
        for i in 0..event_count {
            actions.push(StreamingAction::heartbeat());
            actions.push(StreamingAction::delay(Duration::from_millis(50)));
            actions.push(StreamingAction::SendSse {
                event: SseEvent::typed("data", &json!({"n": i}).to_string()),
            });
        }
        actions
    }

    /// SSE: deliver some events, drop connection, then deliver more on reconnect.
    #[must_use]
    pub fn sse_reconnect_scenario() -> Vec<StreamingAction> {
        vec![
            StreamingAction::send_typed_sse("message", r#"{"seq":0}"#),
            StreamingAction::send_typed_sse("message", r#"{"seq":1}"#),
            StreamingAction::delay(Duration::from_millis(100)),
            StreamingAction::drop_connection(),
            // After reconnect, client will reconnect and these will be delivered
            StreamingAction::send_typed_sse("message", r#"{"seq":2}"#),
            StreamingAction::send_typed_sse("message", r#"{"seq":3}"#),
        ]
    }

    /// JSON-lines: deliver N JSON objects.
    #[must_use]
    pub fn jsonl_sequential(count: u32) -> Vec<StreamingAction> {
        (0..count)
            .map(|i| StreamingAction::send_json(json!({"index": i, "type": "event"})))
            .collect()
    }

    /// Slow drip: deliver events with configurable inter-event delay.
    #[must_use]
    pub fn slow_drip(count: u32, inter_delay: Duration) -> Vec<StreamingAction> {
        let mut actions = Vec::new();
        for i in 0..count {
            actions.push(StreamingAction::send_sse(
                &json!({"drip": i}).to_string(),
            ));
            if i < count - 1 {
                actions.push(StreamingAction::delay(inter_delay));
            }
        }
        actions
    }

    /// Backpressure: send a burst of events with no delay.
    #[must_use]
    pub fn burst(count: u32) -> Vec<StreamingAction> {
        (0..count)
            .map(|i| StreamingAction::send_sse(&json!({"burst": i}).to_string()))
            .collect()
    }

    /// Graceful shutdown: deliver events then signal completion.
    #[must_use]
    pub fn graceful_shutdown(event_count: u32) -> Vec<StreamingAction> {
        let mut actions: Vec<StreamingAction> = (0..event_count)
            .map(|i| StreamingAction::send_typed_sse("data", &json!({"n": i}).to_string()))
            .collect();
        actions.push(StreamingAction::send_typed_sse("done", r#"{"complete":true}"#));
        actions
    }
}

// ---------------------------------------------------------------------------
// Duration serialization helper
// ---------------------------------------------------------------------------

mod duration_ms_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ms = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(ms))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sse_event_data_only() {
        let event = SseEvent::data("hello world");
        let bytes = event.to_sse_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("data: hello world\n"));
        assert!(text.ends_with("\n\n"));
        assert!(!text.contains("event:"));
    }

    #[test]
    fn sse_event_typed_with_id() {
        let event = SseEvent::typed("message", r#"{"ok":true}"#).with_id("42");
        let bytes = event.to_sse_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("event: message\n"));
        assert!(text.contains("id: 42\n"));
        assert!(text.contains(r#"data: {"ok":true}"#));
    }

    #[test]
    fn sse_event_with_retry() {
        let event = SseEvent::data("retry-test").with_retry(3000);
        let bytes = event.to_sse_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("retry: 3000\n"));
    }

    #[test]
    fn sse_event_multiline_data() {
        let event = SseEvent::data("line1\nline2\nline3");
        let bytes = event.to_sse_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("data: line1\n"));
        assert!(text.contains("data: line2\n"));
        assert!(text.contains("data: line3\n"));
    }

    #[test]
    fn streaming_action_serde_round_trip() {
        let actions = vec![
            StreamingAction::send_sse("test-data"),
            StreamingAction::delay(Duration::from_millis(100)),
            StreamingAction::drop_connection(),
            StreamingAction::heartbeat(),
        ];

        let json = serde_json::to_string(&actions).unwrap();
        let deserialized: Vec<StreamingAction> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 4);
    }

    #[test]
    fn scenario_sse_sequential_events() {
        let actions = streaming_scenarios::sse_sequential_events(3);
        assert_eq!(actions.len(), 3);
        for (i, action) in actions.iter().enumerate() {
            if let StreamingAction::SendSse { event } = action {
                assert_eq!(event.event.as_deref(), Some("message"));
                assert_eq!(event.id.as_deref(), Some(i.to_string().as_str()));
            } else {
                panic!("expected SendSse at index {i}");
            }
        }
    }

    #[test]
    fn scenario_sse_events_with_heartbeats() {
        let actions = streaming_scenarios::sse_events_with_heartbeats(2);
        // Each event gets: heartbeat + delay + event = 3 actions
        assert_eq!(actions.len(), 6);
        assert!(matches!(actions[0], StreamingAction::SendHeartbeat));
        assert!(matches!(actions[1], StreamingAction::Delay { .. }));
        assert!(matches!(actions[2], StreamingAction::SendSse { .. }));
    }

    #[test]
    fn scenario_reconnect() {
        let actions = streaming_scenarios::sse_reconnect_scenario();
        assert_eq!(actions.len(), 6);
        assert!(matches!(actions[3], StreamingAction::DropConnection));
    }

    #[test]
    fn scenario_jsonl_sequential() {
        let actions = streaming_scenarios::jsonl_sequential(5);
        assert_eq!(actions.len(), 5);
        for action in &actions {
            assert!(matches!(action, StreamingAction::SendJson { .. }));
        }
    }

    #[test]
    fn scenario_slow_drip() {
        let actions = streaming_scenarios::slow_drip(3, Duration::from_millis(100));
        // 3 events + 2 delays = 5 actions
        assert_eq!(actions.len(), 5);
    }

    #[test]
    fn scenario_burst() {
        let actions = streaming_scenarios::burst(10);
        assert_eq!(actions.len(), 10);
    }

    #[test]
    fn scenario_graceful_shutdown() {
        let actions = streaming_scenarios::graceful_shutdown(3);
        assert_eq!(actions.len(), 4); // 3 data + 1 done
        if let StreamingAction::SendSse { event } = &actions[3] {
            assert_eq!(event.event.as_deref(), Some("done"));
        } else {
            panic!("expected done event");
        }
    }

    #[test]
    fn fixture_server_starts_and_stops() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        assert_eq!(fixture.connections_accepted(), 0);
        assert_eq!(fixture.messages_sent(), 0);
        assert!(!fixture.base_url().is_empty());
        fixture.stop();
    }

    #[test]
    fn fixture_server_enqueue_actions() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        fixture.enqueue(StreamingAction::send_sse("test"));
        fixture.enqueue(StreamingAction::heartbeat());
        fixture.stop();
    }

    #[test]
    fn fixture_server_script_batch() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        fixture.script(streaming_scenarios::sse_sequential_events(5));
        fixture.stop();
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_server_delivers_sse_events() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        fixture.script(vec![
            StreamingAction::send_typed_sse("message", r#"{"hello":"world"}"#),
            StreamingAction::send_typed_sse("message", r#"{"seq":1}"#),
            // Drop connection so response.text() completes
            StreamingAction::drop_connection(),
        ]);

        let client = reqwest::Client::new();
        let response = client
            .get(fixture.sse_url("/events"))
            .header("Accept", "text/event-stream")
            .send()
            .await
            .expect("SSE connection should succeed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );

        let body = fcp_async_core::time::timeout(
            Duration::from_secs(5),
            response.text(),
        )
        .await
        .expect("should receive within timeout")
        .expect("body text");

        assert!(body.contains("event: message"));
        assert!(body.contains(r#"data: {"hello":"world"}"#));
        assert!(body.contains(r#"data: {"seq":1}"#));
        assert!(fixture.connections_accepted() >= 1);
        assert_eq!(fixture.messages_sent(), 2);
        fixture.stop();
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_server_drops_connection() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        fixture.script(vec![
            StreamingAction::send_sse("before-drop"),
            StreamingAction::drop_connection(),
        ]);

        let client = reqwest::Client::new();
        let response = client
            .get(fixture.sse_url("/events"))
            .send()
            .await
            .expect("initial connection should succeed");

        let body = fcp_async_core::time::timeout(
            Duration::from_secs(2),
            response.text(),
        )
        .await
        .expect("should complete within timeout")
        .expect("body text");

        assert!(body.contains("data: before-drop"));
        assert_eq!(fixture.connections_accepted(), 1);
        fixture.stop();
    }

    #[fcp_async_core::runtime::test]
    async fn fixture_server_reconnect_delivers_more_events() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        // Script: send 2 events, drop, then send 2 more + drop (so second
        // response.text() also completes).
        fixture.script(vec![
            StreamingAction::send_typed_sse("message", r#"{"seq":0}"#),
            StreamingAction::send_typed_sse("message", r#"{"seq":1}"#),
            StreamingAction::delay(Duration::from_millis(50)),
            StreamingAction::drop_connection(),
            StreamingAction::send_typed_sse("message", r#"{"seq":2}"#),
            StreamingAction::send_typed_sse("message", r#"{"seq":3}"#),
            StreamingAction::drop_connection(),
        ]);

        let client = reqwest::Client::new();
        let url = fixture.sse_url("/events");

        // First connection - gets events then drop
        let response = client.get(&url).send().await.expect("first connect");
        let body1 = fcp_async_core::time::timeout(Duration::from_secs(5), response.text())
            .await
            .expect("first timeout")
            .expect("first body");
        assert!(body1.contains(r#"{"seq":0}"#));

        // Small wait for reconnect scripted events to be ready
        fcp_async_core::time::sleep(Duration::from_millis(200)).await;

        // Second connection - gets remaining events
        let response2 = client.get(&url).send().await.expect("reconnect");
        let body2 = fcp_async_core::time::timeout(Duration::from_secs(5), response2.text())
            .await
            .expect("second timeout")
            .expect("second body");
        assert!(body2.contains(r#"{"seq":2}"#) || body2.contains(r#"{"seq":3}"#));

        assert!(fixture.connections_accepted() >= 2);
        fixture.stop();
    }

    #[test]
    fn sse_url_format() {
        let fixture = StreamingFixtureServer::start().expect("fixture should bind");
        let url = fixture.sse_url("/events");
        assert!(url.starts_with("http://127.0.0.1:"));
        assert!(url.ends_with("/events"));
        fixture.stop();
    }

    #[test]
    fn send_json_action() {
        let action = StreamingAction::send_json(json!({"key": "value"}));
        if let StreamingAction::SendJson { body } = &action {
            assert_eq!(body["key"], "value");
        } else {
            panic!("expected SendJson");
        }
    }

    #[test]
    fn sse_event_serde_round_trip() {
        let event = SseEvent::typed("update", r#"{"v":1}"#)
            .with_id("evt-42")
            .with_retry(5000);

        let json = serde_json::to_string(&event).unwrap();
        let back: SseEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(back.event, Some("update".to_owned()));
        assert_eq!(back.id, Some("evt-42".to_owned()));
        assert_eq!(back.retry_ms, Some(5000));
    }
}
