//! Server-Sent Events (SSE) implementation.
//!
//! Implements SSE parsing and client per the WHATWG HTML Living Standard.

use std::collections::HashMap;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use fcp_async_core::bytes::Buf as _;
use fcp_async_core::http::body::Body as _;
use fcp_async_core::http::client_io::ClientIo;
use fcp_async_core::http::{ClientIncomingBody, HttpClient, HttpClientBuilder, Method};
use fcp_async_core::time;
use futures_util::stream::Stream;
use pin_project_lite::pin_project;

use crate::{StreamError, StreamResult};

const ACCEPT_HEADER: &str = "Accept";
const CACHE_CONTROL_HEADER: &str = "Cache-Control";
const LAST_EVENT_ID_HEADER: &str = "Last-Event-ID";
const NO_CACHE_VALUE: &str = "no-cache";
const SSE_MIME_TYPE: &str = "text/event-stream";

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

#[cfg(test)]
const DEFAULT_MAX_DATA_BYTES: usize = 10 * 1024 * 1024;

/// SSE parser state.
#[derive(Debug)]
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
    /// Total bytes accumulated in `data_lines` (`DoS` protection).
    data_bytes_len: usize,
    /// Maximum `data:` payload bytes retained for an in-progress event.
    max_data_bytes: usize,
}

impl SseParser {
    /// Create a new parser.
    #[cfg(test)]
    fn new() -> Self {
        Self::with_max_data_bytes(DEFAULT_MAX_DATA_BYTES)
    }

    /// Create a new parser with a specific retained payload limit.
    fn with_max_data_bytes(max_data_bytes: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            event_type: None,
            data_lines: Vec::new(),
            event_id: None,
            retry: None,
            last_event_id: None,
            data_bytes_len: 0,
            max_data_bytes,
        }
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
            "data" => {
                let val_len = value.len();
                if self.data_bytes_len.saturating_add(val_len) <= self.max_data_bytes {
                    self.data_lines.push(value.to_string());
                    self.data_bytes_len += val_len;
                }
            }
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
        self.data_bytes_len = 0;

        Some(event)
    }

    /// Get the last event ID for reconnection.
    fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Bytes currently retained for the in-progress event.
    fn retained_bytes(&self) -> usize {
        self.buffer.len().saturating_add(self.data_bytes_len)
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
#[derive(Clone)]
pub struct SseClient {
    url: String,
    config: SseConfig,
    http_client: Arc<HttpClient>,
}

impl fmt::Debug for SseClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SseClient")
            .field("url", &self.url)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SseClient {
    /// Create a new SSE client.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            config: SseConfig::default(),
            http_client: Arc::new(HttpClientBuilder::new().build()),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(url: impl Into<String>, config: SseConfig) -> Self {
        Self {
            url: url.into(),
            config,
            http_client: Arc::new(HttpClientBuilder::new().build()),
        }
    }

    /// Create with custom HTTP client.
    #[must_use]
    pub fn with_http_client(url: impl Into<String>, http_client: HttpClient) -> Self {
        Self {
            url: url.into(),
            config: SseConfig::default(),
            http_client: Arc::new(http_client),
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
        let mut headers = vec![
            (ACCEPT_HEADER.to_string(), SSE_MIME_TYPE.to_string()),
            (CACHE_CONTROL_HEADER.to_string(), NO_CACHE_VALUE.to_string()),
        ];
        if let Some(id) = last_event_id {
            headers.push((LAST_EVENT_ID_HEADER.to_string(), id.to_string()));
        }

        headers.extend(
            self.config
                .headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );

        let cx = fcp_async_core::compatibility_cx();
        let request =
            self.http_client
                .request_streaming(&cx, Method::Get, &self.url, headers, Vec::new());
        let response = if let Some(timeout) = self.config.timeout {
            match time::timeout(timeout, request).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(StreamError::from(error)),
                Err(_) => return Err(StreamError::Timeout(timeout)),
            }
        } else {
            request.await?
        };

        if !(200..300).contains(&response.head.status) {
            return Err(StreamError::HttpError {
                status: response.head.status,
                message: response.head.reason,
            });
        }

        Ok(SseStream::new(response.body, self.config.max_buffer_size))
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
    #[derive(Debug)]
    struct SseChunkStream {
        #[pin]
        body: Option<ClientIncomingBody<ClientIo>>,
    }
}

impl SseChunkStream {
    const fn new(body: ClientIncomingBody<ClientIo>) -> Self {
        Self { body: Some(body) }
    }
}

impl Stream for SseChunkStream {
    type Item = StreamResult<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            let Some(body) = this.body.as_mut().as_pin_mut() else {
                return Poll::Ready(None);
            };

            match ready!(body.poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.into_data() {
                        return Poll::Ready(Some(Ok(Bytes::copy_from_slice(data.chunk()))));
                    }
                }
                Some(Err(error)) => {
                    this.body.set(None);
                    return Poll::Ready(Some(Err(StreamError::from(error))));
                }
                None => {
                    this.body.set(None);
                    return Poll::Ready(None);
                }
            }
        }
    }
}

pin_project! {
    /// SSE event stream.
    pub struct SseStream {
        #[pin]
        inner: SseChunkStream,
        parser: SseParser,
        pending_events: Vec<SseEvent>,
        max_buffer_size: usize,
    }
}

impl SseStream {
    /// Create a new SSE stream.
    fn new(body: ClientIncomingBody<ClientIo>, max_buffer_size: usize) -> Self {
        Self {
            inner: SseChunkStream::new(body),
            parser: SseParser::with_max_data_bytes(max_buffer_size),
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
                let retained_bytes = this.parser.retained_bytes();
                if retained_bytes.saturating_add(data.len()) > *this.max_buffer_size {
                    return Poll::Ready(Some(Err(StreamError::BufferOverflow {
                        size: retained_bytes.saturating_add(data.len()),
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
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
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

    // ── SseEvent trait impls ──

    #[test]
    fn test_sse_event_clone() {
        let event = SseEvent::new("data").with_event("msg").with_id("1");
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn test_sse_event_partial_eq() {
        let a = SseEvent::new("data").with_event("msg");
        let b = SseEvent::new("data").with_event("msg");
        let c = SseEvent::new("other");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sse_event_debug() {
        let event = SseEvent::new("test");
        let debug = format!("{event:?}");
        assert!(debug.contains("SseEvent"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_sse_event_chained_builder() {
        let event = SseEvent::new("payload").with_event("update").with_id("42");
        assert_eq!(event.data, "payload");
        assert_eq!(event.event, Some("update".to_string()));
        assert_eq!(event.id, Some("42".to_string()));
        assert_eq!(event.retry, None);
    }

    // ── SseParser edge cases ──

    #[test]
    fn test_parse_unknown_field_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("unknown: value\ndata: hello\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_data_with_colon_in_value() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: key:value:extra\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "key:value:extra");
    }

    #[test]
    fn test_parse_data_no_space_after_colon() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:no_space\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "no_space");
    }

    #[test]
    fn test_parse_empty_data_field() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn test_parse_only_comments() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": comment 1\n: comment 2\n\n");
        let events = parser.parse(&data);
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_event_type_reset_after_dispatch() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: first\ndata: a\n\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, Some("first".to_string()));
        // Event type resets after dispatch
        assert_eq!(events[1].event, None);
    }

    #[test]
    fn test_parse_multiple_id_updates() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: 1\ndata: a\n\nid: 2\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("1".to_string()));
        assert_eq!(events[1].id, Some("2".to_string()));
        assert_eq!(parser.last_event_id(), Some("2"));
    }

    #[test]
    fn test_parse_retry_overrides() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 1000\nretry: 2000\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // Last retry value wins
        assert_eq!(events[0].retry, Some(2000));
    }

    #[test]
    fn test_parse_incremental_three_chunks() {
        let mut parser = SseParser::new();
        assert!(parser.parse(&Bytes::from("da")).is_empty());
        assert!(parser.parse(&Bytes::from("ta: hel")).is_empty());
        let events = parser.parse(&Bytes::from("lo\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn test_parse_mixed_line_endings() {
        let mut parser = SseParser::new();
        // Mix of \n, \r\n, and \r
        let data = Bytes::from("data: a\ndata: b\r\n\r\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "a\nb");
    }

    #[test]
    fn test_parse_empty_id_field() {
        let mut parser = SseParser::new();
        // Set ID first, then empty ID resets per spec
        let data = Bytes::from("id: old\ndata: a\n\nid:\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, Some("old".to_string()));
        // Empty id field sets event_id to empty string
        assert_eq!(events[1].id, Some(String::new()));
    }

    #[test]
    fn test_parse_comment_between_fields() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: msg\n: comment\ndata: hello\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("msg".to_string()));
        assert_eq!(events[0].data, "hello");
    }

    // ── SseConfig trait impls ──

    #[test]
    fn test_sse_config_clone() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(5))
            .with_header("X-Key", "val");
        let moved = config;
        assert_eq!(moved.timeout, Some(Duration::from_secs(5)));
        assert_eq!(moved.headers.get("X-Key"), Some(&"val".to_string()));
    }

    #[test]
    fn test_sse_config_debug() {
        let config = SseConfig::new();
        let debug = format!("{config:?}");
        assert!(debug.contains("SseConfig"));
    }

    #[test]
    fn test_sse_config_new_equals_default() {
        let new = SseConfig::new();
        let default = SseConfig::default();
        assert_eq!(new.timeout, default.timeout);
        assert_eq!(new.max_buffer_size, default.max_buffer_size);
        assert_eq!(new.auto_reconnect, default.auto_reconnect);
        assert_eq!(new.max_reconnect_attempts, default.max_reconnect_attempts);
        assert_eq!(new.reconnect_delay, default.reconnect_delay);
    }

    #[test]
    fn test_sse_config_multiple_headers() {
        let config = SseConfig::new()
            .with_header("Authorization", "Bearer abc")
            .with_header("X-Custom", "value");
        assert_eq!(config.headers.len(), 2);
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer abc".to_string())
        );
        assert_eq!(config.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    // ── SseClient tests ──

    #[test]
    fn test_sse_client_with_http_client() {
        let http_client = HttpClient::new();
        let client = SseClient::with_http_client("https://example.com/events", http_client);
        assert_eq!(client.url(), "https://example.com/events");
    }

    #[test]
    fn test_sse_client_debug() {
        let client = SseClient::new("https://example.com/sse");
        let debug = format!("{client:?}");
        assert!(debug.contains("SseClient"));
    }

    #[test]
    fn test_sse_client_clone() {
        let client = SseClient::new("https://example.com/sse");
        let moved = client;
        assert_eq!(moved.url(), "https://example.com/sse");
    }

    // ── SseEvent JSON edge cases ──

    #[test]
    fn test_sse_event_json_array() {
        let event = SseEvent::new("[1, 2, 3]");
        let result: Vec<i32> = event.json().unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_sse_event_json_empty_object() {
        let event = SseEvent::new("{}");
        let result: serde_json::Value = event.json().unwrap();
        assert!(result.is_object());
        assert!(result.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_sse_event_is_event_empty_string() {
        let event = SseEvent::new("data").with_event("");
        assert!(event.is_event(""));
        assert!(!event.is_event("message"));
    }

    // ── SseEvent: unicode content ───────────────────────────────────────

    #[test]
    fn test_sse_event_unicode_data() {
        let event = SseEvent::new("\u{1F600}\u{1F4A9}\u{2764}\u{FE0F}");
        assert_eq!(event.data, "\u{1F600}\u{1F4A9}\u{2764}\u{FE0F}");
    }

    #[test]
    fn test_sse_event_unicode_event_type() {
        let event = SseEvent::new("data").with_event("\u{00C9}v\u{00E9}nement");
        assert!(event.is_event("\u{00C9}v\u{00E9}nement"));
    }

    #[test]
    fn test_sse_event_unicode_id() {
        let event = SseEvent::new("data").with_id("\u{00FC}ber-42");
        assert_eq!(event.id, Some("\u{00FC}ber-42".to_string()));
    }

    // ── SseEvent: large data ────────────────────────────────────────────

    #[test]
    fn test_sse_event_large_data() {
        let big = "x".repeat(100_000);
        let event = SseEvent::new(big);
        assert_eq!(event.data.len(), 100_000);
    }

    #[test]
    fn test_sse_event_empty_data() {
        let event = SseEvent::new("");
        assert_eq!(event.data, "");
    }

    // ── SseEvent: json edge cases ───────────────────────────────────────

    #[test]
    fn test_sse_event_json_nested_object() {
        let event = SseEvent::new(r#"{"a":{"b":{"c":1}}}"#);
        let val: serde_json::Value = event.json().unwrap();
        assert_eq!(val["a"]["b"]["c"], 1);
    }

    #[test]
    fn test_sse_event_json_number() {
        let event = SseEvent::new("42");
        let val: i64 = event.json().unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_sse_event_json_string() {
        let event = SseEvent::new(r#""hello""#);
        let val: String = event.json().unwrap();
        assert_eq!(val, "hello");
    }

    #[test]
    fn test_sse_event_json_bool() {
        let event = SseEvent::new("false");
        let val: bool = event.json().unwrap();
        assert!(!val);
    }

    #[test]
    fn test_sse_event_json_null() {
        let event = SseEvent::new("null");
        let val: serde_json::Value = event.json().unwrap();
        assert!(val.is_null());
    }

    // ── SseParser: data overflow protection ─────────────────────────────

    #[test]
    fn test_parse_data_exceeds_10mb_ignored() {
        use std::fmt::Write;
        let mut parser = SseParser::new();
        // Push enough data lines to exceed the 10MB limit
        let big_line = "a".repeat(1_000_000);
        let mut input = String::new();
        for _ in 0..11 {
            let _ = writeln!(input, "data: {big_line}");
        }
        input.push('\n');
        let events = parser.parse(&Bytes::from(input));
        // Event dispatches, but not all data lines were accepted
        assert_eq!(events.len(), 1);
        assert!(events[0].data.len() <= 10 * 1024 * 1024);
    }

    #[test]
    fn test_parse_data_honors_custom_retained_limit() {
        use std::fmt::Write;

        let mut parser = SseParser::with_max_data_bytes(12 * 1024 * 1024);
        let big_line = "a".repeat(11 * 1024 * 1024);
        let mut input = String::new();
        let _ = writeln!(input, "data: {big_line}");
        input.push('\n');

        let events = parser.parse(&Bytes::from(input));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data.len(), big_line.len());
    }

    #[test]
    fn test_retained_bytes_counts_payload_and_raw_buffer() {
        let mut parser = SseParser::new();

        let events = parser.parse(&Bytes::from("data: hello\n"));
        assert!(events.is_empty());
        assert_eq!(parser.retained_bytes(), "hello".len());

        let events = parser.parse(&Bytes::from("data: world"));
        assert!(events.is_empty());
        assert_eq!(parser.retained_bytes(), "hello".len() + "data: world".len());

        let events = parser.parse(&Bytes::from("\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello\nworld");
        assert_eq!(parser.retained_bytes(), 0);
    }

    // ── SseParser: multiple sequential parses ───────────────────────────

    #[test]
    fn test_parse_multiple_independent_events() {
        let mut parser = SseParser::new();
        for i in 0..5 {
            let data = Bytes::from(format!("data: event{i}\n\n"));
            let events = parser.parse(&data);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].data, format!("event{i}"));
        }
    }

    #[test]
    fn test_parse_interleaved_events_and_comments() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": heartbeat\ndata: a\n\n: another heartbeat\ndata: b\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "a");
        assert_eq!(events[1].data, "b");
    }

    #[test]
    fn test_parse_event_with_all_fields() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: update\nid: 99\nretry: 3000\ndata: payload\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("update".to_string()));
        assert_eq!(events[0].id, Some("99".to_string()));
        assert_eq!(events[0].retry, Some(3000));
        assert_eq!(events[0].data, "payload");
    }

    // ── SseParser: field edge cases ─────────────────────────────────────

    #[test]
    fn test_parse_retry_zero() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 0\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events[0].retry, Some(0));
    }

    #[test]
    fn test_parse_retry_large_value() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 999999999\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events[0].retry, Some(999_999_999));
    }

    #[test]
    fn test_parse_data_with_spaces() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:  leading space\n\n");
        let events = parser.parse(&data);
        // Per spec, one leading space is stripped after colon
        assert_eq!(events[0].data, " leading space");
    }

    #[test]
    fn test_parse_multiple_empty_lines() {
        let mut parser = SseParser::new();
        // Two empty lines after data field = dispatch + empty dispatch (no event)
        let data = Bytes::from("data: hello\n\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
    }

    // ── SseConfig: builder edge cases ───────────────────────────────────

    #[test]
    fn test_sse_config_zero_buffer() {
        let config = SseConfig::new().with_max_buffer_size(0);
        assert_eq!(config.max_buffer_size, 0);
    }

    #[test]
    fn test_sse_config_large_buffer() {
        let config = SseConfig::new().with_max_buffer_size(usize::MAX);
        assert_eq!(config.max_buffer_size, usize::MAX);
    }

    #[test]
    fn test_sse_config_zero_reconnect_delay() {
        let config = SseConfig::new().with_reconnect_delay(Duration::ZERO);
        assert_eq!(config.reconnect_delay, Duration::ZERO);
    }

    #[test]
    fn test_sse_config_header_overwrite() {
        let config = SseConfig::new()
            .with_header("Key", "val1")
            .with_header("Key", "val2");
        assert_eq!(config.headers.get("Key"), Some(&"val2".to_string()));
        assert_eq!(config.headers.len(), 1);
    }

    #[test]
    fn test_sse_config_auto_reconnect_toggle() {
        let config = SseConfig::new()
            .with_auto_reconnect(true)
            .with_auto_reconnect(false)
            .with_auto_reconnect(true);
        assert!(config.auto_reconnect);
    }

    #[test]
    fn test_sse_config_max_reconnect_zero() {
        let config = SseConfig::new().with_max_reconnect_attempts(0);
        assert_eq!(config.max_reconnect_attempts, Some(0));
    }

    // ── SseParser: incremental multi-field parsing ──────────────────────

    #[test]
    fn test_parse_incremental_event_type_then_data() {
        let mut parser = SseParser::new();
        assert!(parser.parse(&Bytes::from("event: up")).is_empty());
        assert!(parser.parse(&Bytes::from("date\n")).is_empty());
        let events = parser.parse(&Bytes::from("data: payload\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("update".to_string()));
        assert_eq!(events[0].data, "payload");
    }

    #[test]
    fn test_parse_incremental_id_across_chunks() {
        let mut parser = SseParser::new();
        assert!(parser.parse(&Bytes::from("id: abc")).is_empty());
        assert!(parser.parse(&Bytes::from("123\n")).is_empty());
        let events = parser.parse(&Bytes::from("data: test\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some("abc123".to_string()));
    }

    // ── SseParser: retry field edge cases ───────────────────────────────

    #[test]
    fn test_parse_retry_negative_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: -100\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // Negative values can't parse as u64, so retry is None
        assert_eq!(events[0].retry, None);
    }

    #[test]
    fn test_parse_retry_float_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry: 1.5\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, None);
    }

    #[test]
    fn test_parse_retry_empty_ignored() {
        let mut parser = SseParser::new();
        let data = Bytes::from("retry:\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].retry, None);
    }

    // ── SseParser: last_event_id updates ────────────────────────────────

    #[test]
    fn test_last_event_id_not_updated_without_id_field() {
        let mut parser = SseParser::new();
        // First event sets ID
        parser.parse(&Bytes::from("id: first\ndata: a\n\n"));
        assert_eq!(parser.last_event_id(), Some("first"));

        // Second event has no ID; last_event_id stays
        parser.parse(&Bytes::from("data: b\n\n"));
        assert_eq!(parser.last_event_id(), Some("first"));
    }

    #[test]
    fn test_last_event_id_updated_to_empty() {
        let mut parser = SseParser::new();
        parser.parse(&Bytes::from("id: abc\ndata: a\n\n"));
        assert_eq!(parser.last_event_id(), Some("abc"));

        // Empty id: field sets event_id to empty string
        parser.parse(&Bytes::from("id:\ndata: b\n\n"));
        assert_eq!(parser.last_event_id(), Some(""));
    }

    // ── SseParser: data_bytes_len reset after dispatch ──────────────────

    #[test]
    fn test_parse_data_bytes_reset_after_dispatch() {
        let mut parser = SseParser::new();
        // First event with some data
        let events = parser.parse(&Bytes::from("data: hello world\n\n"));
        assert_eq!(events.len(), 1);

        // Second event should accept data fine (counter was reset)
        let events = parser.parse(&Bytes::from("data: another message\n\n"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "another message");
    }

    // ── SseEvent: PartialEq edge cases ──────────────────────────────────

    #[test]
    fn test_sse_event_ne_different_id() {
        let a = SseEvent::new("data").with_id("1");
        let b = SseEvent::new("data").with_id("2");
        assert_ne!(a, b);
    }

    #[test]
    fn test_sse_event_ne_different_event_type() {
        let a = SseEvent::new("data").with_event("msg");
        let b = SseEvent::new("data").with_event("err");
        assert_ne!(a, b);
    }

    #[test]
    fn test_sse_event_eq_both_with_retry() {
        let mut a = SseEvent::new("data");
        a.retry = Some(1000);
        let mut b = SseEvent::new("data");
        b.retry = Some(1000);
        assert_eq!(a, b);
    }

    #[test]
    fn test_sse_event_ne_different_retry() {
        let mut a = SseEvent::new("data");
        a.retry = Some(1000);
        let mut b = SseEvent::new("data");
        b.retry = Some(2000);
        assert_ne!(a, b);
    }

    // ── SseClient: URL handling ─────────────────────────────────────────

    #[test]
    fn test_sse_client_url_with_query_params() {
        let client = SseClient::new("https://example.com/events?token=abc&channel=test");
        assert_eq!(
            client.url(),
            "https://example.com/events?token=abc&channel=test"
        );
    }

    #[test]
    fn test_sse_client_url_with_fragment() {
        let client = SseClient::new("https://example.com/events#section");
        assert_eq!(client.url(), "https://example.com/events#section");
    }

    // ── SseParser: unicode in data fields ──

    #[test]
    fn test_parse_unicode_data() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data: \u{1F600} hello \u{4E16}\u{754C}\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert!(events[0].data.contains('\u{1F600}'));
        assert!(events[0].data.contains('\u{4E16}'));
    }

    #[test]
    fn test_parse_unicode_event_type() {
        let mut parser = SseParser::new();
        let data = Bytes::from("event: \u{00E9}v\u{00E9}nement\ndata: payload\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, Some("\u{00E9}v\u{00E9}nement".to_string()));
    }

    #[test]
    fn test_parse_unicode_id() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: \u{00FC}ber-42\ndata: test\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some("\u{00FC}ber-42".to_string()));
    }

    // ── SseParser: complex multi-event scenarios ──

    #[test]
    fn test_parse_ten_events_sequentially() {
        use std::fmt::Write;
        let mut parser = SseParser::new();
        let mut input = String::new();
        for i in 0..10 {
            let _ = write!(input, "data: event-{i}\n\n");
        }
        let events = parser.parse(&Bytes::from(input));
        assert_eq!(events.len(), 10);
        for (i, evt) in events.iter().enumerate() {
            assert_eq!(evt.data, format!("event-{i}"));
        }
    }

    #[test]
    fn test_parse_event_with_multiple_data_lines_and_id() {
        let mut parser = SseParser::new();
        let data = Bytes::from("id: 77\nevent: batch\ndata: line1\ndata: line2\ndata: line3\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line1\nline2\nline3");
        assert_eq!(events[0].id, Some("77".to_string()));
        assert_eq!(events[0].event, Some("batch".to_string()));
    }

    #[test]
    fn test_parse_alternating_comments_and_events() {
        let mut parser = SseParser::new();
        let data = Bytes::from(": ping\ndata: a\n\n: ping\ndata: b\n\n: ping\ndata: c\n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].data, "a");
        assert_eq!(events[1].data, "b");
        assert_eq!(events[2].data, "c");
    }

    // ── SseEvent: builder with all fields ──

    #[test]
    fn test_sse_event_full_construction() {
        let mut event = SseEvent::new("payload").with_event("update").with_id("123");
        event.retry = Some(5000);
        assert_eq!(event.data, "payload");
        assert_eq!(event.event, Some("update".to_string()));
        assert_eq!(event.id, Some("123".to_string()));
        assert_eq!(event.retry, Some(5000));
    }

    #[test]
    fn test_sse_event_clone_independence() {
        let original = SseEvent::new("data").with_event("msg").with_id("1");
        let cloned = original.clone();
        // Verify they are equal but independent
        assert_eq!(original, cloned);
        assert_eq!(original.data, cloned.data);
        assert_eq!(original.event, cloned.event);
        assert_eq!(original.id, cloned.id);
    }

    // ── SseConfig: clone preserves all fields ──

    #[test]
    fn test_sse_config_clone_all_fields() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(30))
            .with_max_buffer_size(4096)
            .with_header("Auth", "Bearer tok")
            .with_auto_reconnect(false)
            .with_max_reconnect_attempts(3)
            .with_reconnect_delay(Duration::from_millis(500));
        let cloned = config.clone();
        assert_eq!(config.timeout, cloned.timeout);
        assert_eq!(config.max_buffer_size, cloned.max_buffer_size);
        assert_eq!(config.auto_reconnect, cloned.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, cloned.max_reconnect_attempts);
        assert_eq!(config.reconnect_delay, cloned.reconnect_delay);
        assert_eq!(config.headers.get("Auth"), cloned.headers.get("Auth"));
    }

    // ── SseParser: empty buffer initially ──

    #[test]
    fn test_parser_initial_state_empty() {
        let parser = SseParser::new();
        assert!(parser.last_event_id().is_none());
    }

    #[test]
    fn test_parser_parse_empty_bytes() {
        let mut parser = SseParser::new();
        let events = parser.parse(&Bytes::new());
        assert!(events.is_empty());
    }

    // ── SseParser: data field with only whitespace ──

    #[test]
    fn test_parse_data_only_spaces() {
        let mut parser = SseParser::new();
        let data = Bytes::from("data:    \n\n");
        let events = parser.parse(&data);
        assert_eq!(events.len(), 1);
        // One leading space stripped, rest preserved
        assert_eq!(events[0].data, "   ");
    }

    // ── SseEvent: JSON with unicode keys ──

    #[test]
    fn test_sse_event_json_unicode_key() {
        let event = SseEvent::new(r#"{"\u00e9":"accent"}"#);
        let val: serde_json::Value = event.json().unwrap();
        assert!(val.is_object());
    }

    // ── SseClient: empty URL ──

    #[test]
    fn test_sse_client_empty_url() {
        let client = SseClient::new("");
        assert_eq!(client.url(), "");
    }

    // ── SseConfig: timeout override ──

    #[test]
    fn test_sse_config_timeout_override() {
        let config = SseConfig::new()
            .with_timeout(Duration::from_secs(10))
            .with_timeout(Duration::from_secs(30));
        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
    }
}
