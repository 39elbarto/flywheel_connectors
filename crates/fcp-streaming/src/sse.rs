//! Server-Sent Events (SSE) implementation.
//!
//! Implements SSE parsing and client per the WHATWG HTML Living Standard.

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::stream::Stream;
use pin_project_lite::pin_project;
use reqwest::Client;

use crate::{StreamError, StreamResult};

/// SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Event type (from "event:" field).
    pub event: Option<String>,
    /// Event data (from "data:" fields, joined with newlines).
    pub data: String,
    /// Event ID (from "id:" field).
    pub id: Option<String>,
    /// Retry interval in milliseconds (from "retry:" field).
    pub retry: Option<u64>,
}

impl SseEvent {
    /// Create a new SSE event with data.
    #[must_use]
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            event: None,
            data: data.into(),
            id: None,
            retry: None,
        }
    }

    /// Set the event type.
    #[must_use]
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set the event ID.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Check if this is a specific event type.
    #[must_use]
    pub fn is_event(&self, event_type: &str) -> bool {
        self.event.as_deref() == Some(event_type)
    }

    /// Parse data as JSON.
    ///
    /// # Errors
    /// Returns a JSON parsing error if the data is not valid JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.data)
    }
}

/// SSE parser state.
#[derive(Debug, Default)]
struct SseParser {
    /// Buffer for incomplete data.
    buffer: BytesMut,
    /// Current event being built.
    event_type: Option<String>,
    /// Accumulated data lines.
    data_lines: Vec<String>,
    /// Current event ID.
    event_id: Option<String>,
    /// Current retry interval.
    retry: Option<u64>,
    /// Last event ID (for reconnection).
    last_event_id: Option<String>,
}

impl SseParser {
    /// Create a new parser.
    fn new() -> Self {
        Self::default()
    }

    /// Parse incoming data and return complete events.
    fn parse(&mut self, data: &Bytes) -> Vec<SseEvent> {
        self.buffer.extend_from_slice(data);
        let mut events = Vec::new();

        // Process complete lines
        while let Some(line_end) = self.find_line_end() {
            let line = self.buffer.split_to(line_end);
            // Skip the line ending
            if self.buffer.starts_with(b"\r\n") {
                self.buffer.advance(2);
            } else if self.buffer.starts_with(b"\n") || self.buffer.starts_with(b"\r") {
                self.buffer.advance(1);
            }

            let line_str = String::from_utf8_lossy(&line);

            if line_str.is_empty() {
                // Empty line = dispatch event
                if let Some(event) = self.dispatch_event() {
                    events.push(event);
                }
            } else if line_str.starts_with(':') {
                // Comment, ignore
            } else {
                self.process_field(&line_str);
            }
        }

        events
    }

    /// Find the end of a line in the buffer.
    fn find_line_end(&self) -> Option<usize> {
        for (i, byte) in self.buffer.iter().enumerate() {
            if *byte == b'\n' || *byte == b'\r' {
                return Some(i);
            }
        }
        None
    }

    /// Process a field line.
    fn process_field(&mut self, line: &str) {
        let (field, value) = line.find(':').map_or((line, ""), |colon_pos| {
            let field = &line[..colon_pos];
            let value = &line[colon_pos + 1..];
            // Skip leading space after colon
            let value = value.strip_prefix(' ').unwrap_or(value);
            (field, value)
        });

        match field {
            "event" => self.event_type = Some(value.to_string()),
            "data" => self.data_lines.push(value.to_string()),
            "id" => {
                if !value.contains('\0') {
                    self.event_id = Some(value.to_string());
                }
            }
            "retry" => {
                if let Ok(ms) = value.parse() {
                    self.retry = Some(ms);
                }
            }
            _ => {} // Unknown field, ignore
        }
    }

    /// Dispatch the current event.
    fn dispatch_event(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() {
            // Reset state but don't dispatch
            self.event_type = None;
            return None;
        }

        let data = self.data_lines.join("\n");
        let event = SseEvent {
            event: self.event_type.take(),
            data,
            id: self.event_id.clone(),
            retry: self.retry.take(),
        };

        // Update last event ID
        if event.id.is_some() {
            self.last_event_id.clone_from(&event.id);
        }

        self.data_lines.clear();

        Some(event)
    }

    /// Get the last event ID for reconnection.
    fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }
}

/// SSE client configuration.
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// Request timeout.
    pub timeout: Option<Duration>,
    /// Maximum buffer size.
    pub max_buffer_size: usize,
    /// Additional headers.
    pub headers: HashMap<String, String>,
    /// Whether to auto-reconnect.
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts.
    pub max_reconnect_attempts: Option<u32>,
    /// Initial reconnection delay.
    pub reconnect_delay: Duration,
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            max_buffer_size: 1024 * 1024, // 1MB
            headers: HashMap::new(),
            auto_reconnect: true,
            max_reconnect_attempts: Some(10),
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

impl SseConfig {
    /// Create a new SSE configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set maximum buffer size.
    #[must_use]
    pub const fn with_max_buffer_size(mut self, size: usize) -> Self {
        self.max_buffer_size = size;
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set auto-reconnect.
    #[must_use]
    pub const fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Set maximum reconnection attempts.
    #[must_use]
    pub const fn with_max_reconnect_attempts(mut self, attempts: u32) -> Self {
        self.max_reconnect_attempts = Some(attempts);
        self
    }

    /// Set reconnection delay.
    #[must_use]
    pub const fn with_reconnect_delay(mut self, delay: Duration) -> Self {
        self.reconnect_delay = delay;
        self
    }
}

/// SSE client.
#[derive(Debug, Clone)]
pub struct SseClient {
    url: String,
    config: SseConfig,
    http_client: Client,
}

impl SseClient {
    /// Create a new SSE client.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            config: SseConfig::default(),
            http_client: Client::new(),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(url: impl Into<String>, config: SseConfig) -> Self {
        Self {
            url: url.into(),
            config,
            http_client: Client::new(),
        }
    }

    /// Create with custom HTTP client.
    #[must_use]
    pub fn with_http_client(url: impl Into<String>, http_client: Client) -> Self {
        Self {
            url: url.into(),
            config: SseConfig::default(),
            http_client,
        }
    }

    /// Connect and return an event stream.
    ///
    /// # Errors
    /// Returns a stream error if the HTTP request fails or returns a non-2xx status.
    pub async fn connect(&self) -> StreamResult<SseStream> {
        self.connect_with_last_id(None).await
    }

    /// Connect with a last event ID for resumption.
    ///
    /// # Errors
    /// Returns a stream error if the HTTP request fails or returns a non-2xx status.
    pub async fn connect_with_last_id(
        &self,
        last_event_id: Option<&str>,
    ) -> StreamResult<SseStream> {
        let mut request = self
            .http_client
            .get(&self.url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache");

        if let Some(id) = last_event_id {
            request = request.header("Last-Event-ID", id);
        }

        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(StreamError::HttpError {
                status: response.status().as_u16(),
                message: response.status().to_string(),
            });
        }

        Ok(SseStream::new(
            response.bytes_stream(),
            self.config.max_buffer_size,
        ))
    }

    /// Get the URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &SseConfig {
        &self.config
    }
}

pin_project! {
    /// SSE event stream.
    pub struct SseStream {
        #[pin]
        inner: futures_util::stream::BoxStream<'static, Result<Bytes, reqwest::Error>>,
        parser: SseParser,
        pending_events: Vec<SseEvent>,
        max_buffer_size: usize,
    }
}

impl SseStream {
    /// Create a new SSE stream.
    fn new<S>(stream: S, max_buffer_size: usize) -> Self
    where
        S: Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
    {
        Self {
            inner: Box::pin(stream),
            parser: SseParser::new(),
            pending_events: Vec::new(),
            max_buffer_size,
        }
    }

    /// Get the last event ID.
    #[must_use]
    pub fn last_event_id(&self) -> Option<&str> {
        self.parser.last_event_id()
    }
}

impl Stream for SseStream {
    type Item = StreamResult<SseEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Return pending events first
        if !this.pending_events.is_empty() {
            return Poll::Ready(Some(Ok(this.pending_events.remove(0))));
        }

        // Poll for more data
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Check buffer size
                if this.parser.buffer.len() + data.len() > *this.max_buffer_size {
                    return Poll::Ready(Some(Err(StreamError::BufferOverflow {
                        size: this.parser.buffer.len() + data.len(),
                        limit: *this.max_buffer_size,
                    })));
                }

                // Parse events
                let events = this.parser.parse(&data);
                if events.is_empty() {
                    // No complete events yet, poll again
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    // Store events and return the first one
                    *this.pending_events = events;
                    Poll::Ready(Some(Ok(this.pending_events.remove(0))))
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(StreamError::ReqwestError(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_event() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: hello world\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello world");
        assert_eq!(events[0].event, None);
    }

    #[test]
    fn test_parse_typed_event() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: message\ndata: hello\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("message".to_string()));
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_multiline_data() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: line 1\ndata: line 2\ndata: line 3\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line 1\nline 2\nline 3");
    }

    #[test]
    fn test_parse_event_with_id() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: 123\ndata: test\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some("123".to_string()));
        assert_eq!(parser.last_event_id(), Some("123"));
    }

    #[test]
    fn test_parse_retry() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 5000\ndata: test\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, Some(5000));
    }

    #[test]
    fn test_parse_comment() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": this is a comment\ndata: actual data\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "actual data");
    }

    #[test]
    fn test_parse_multiple_events() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: event1\n\ndata: event2\n\n");
        let events = parser.parse(&data);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "event1");
        assert_eq!(events[1].data, "event2");
    }

    #[test]
    fn test_parse_incomplete_event() {
        let mut parser = SseParser::new();

        // First chunk
        let data1 = Bytes::from("data: hello ");
        let events1 = parser.parse(&data1);
        assert!(events1.is_empty());

        // Second chunk
        let data2 = Bytes::from("world\n\n");
        let events2 = parser.parse(&data2);
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].data, "hello world");
    }

    #[test]
    fn test_sse_event_json() {
        #[derive(serde::Deserialize)]
        struct Data {
            message: String,
        }

        let event = SseEvent::new(r#"{"message": "hello"}"#);
        let data: Data = event.json().unwrap();
        assert_eq!(data.message, "hello");
    }

    #[test]
    fn test_sse_event_is_event() {
        let event = SseEvent::new("data").with_event("message");
        assert!(event.is_event("message"));
        assert!(!event.is_event("error"));
    }

    // ── New tests ──

    #[test]
    fn test_sse_event_new_fields() {
        let event = SseEvent::new("test data");
        assert_eq!(event.data, "test data");
        assert_eq!(event.event, None);
        assert_eq!(event.id, None);
        assert_eq!(event.retry, None);
    }

    #[test]
    fn test_sse_event_with_id() {
        let event = SseEvent::new("data").with_id("42");
        assert_eq!(event.id, Some("42".to_string()));
    }

    #[test]
    fn test_sse_event_json_failure() {
        let event = SseEvent::new("not json");
        let result: Result<serde_json::Value, _> = event.json();
        assert!(result.is_err());
    }

    #[test]
    fn test_sse_event_is_event_without_type() {
        let event = SseEvent::new("data");
        assert!(!event.is_event("message"));
    }

    #[test]
    fn test_parse_crlf_line_endings() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: hello\r\n\r\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_cr_line_endings() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: hello\r\r");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_id_with_null_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: abc\0def\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // id containing null should be ignored per spec
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn test_parse_retry_non_numeric_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: abc\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, None);
    }

    #[test]
    fn test_parse_field_without_colon() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data\n\n");
        let events = parser.parse(&data);
        // "data" without colon → field "data", value "" → data_lines has ""
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn test_parse_empty_dispatch_no_event() {
        let mut parser = SseParser::new();
        // event type set but no data lines → no event dispatched
        let data = Bytes::from("event: test\n\n");
        let events = parser.parse(&data);
        assert!(events.is_empty());
    }

    #[test]
    fn test_last_event_id_persists() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: first\ndata: a\n\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("first".to_string()));
        // Second event has no id field, but last_event_id persists
        assert_eq!(parser.last_event_id(), Some("first"));
    }

    #[test]
    fn test_sse_config_default() {
        let config = SseConfig::default();
        assert_eq!(config.timeout, None);
        assert_eq!(config.max_buffer_size, 1024 * 1024);
        assert!(config.headers.is_empty());
        assert!(config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, Some(10));
        assert_eq!(config.reconnect_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_sse_config_builder() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(30))
            .with_max_buffer_size(2048)
            .with_header("Authorization", "Bearer token")
            .with_auto_reconnect(false)
            .with_max_reconnect_attempts(5)
            .with_reconnect_delay(Duration::from_millis(500));

        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
        assert_eq!(config.max_buffer_size, 2048);
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
        assert!(!config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, Some(5));
        assert_eq!(config.reconnect_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_sse_client_accessors() {
        let client = SseClient::new("https://example.com/events");
        assert_eq!(client.url(), "https://example.com/events");
        assert_eq!(client.config().max_buffer_size, 1024 * 1024);
    }

    #[test]
    fn test_sse_client_with_config() {
        let config = SseConfig::new().with_max_buffer_size(4096);
        let client = SseClient::with_config("https://example.com/events", config);
        assert_eq!(client.url(), "https://example.com/events");
        assert_eq!(client.config().max_buffer_size, 4096);
    }
}
