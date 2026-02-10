//! WebSocket client implementation.
//!
//! Provides full WebSocket protocol support with automatic reconnection.

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::Stream;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use url::Url;

use crate::reconnect::ReconnectHandler;
use crate::{StreamError, StreamResult};

/// WebSocket message types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// Text message.
    Text(String),
    /// Binary message.
    Binary(Vec<u8>),
    /// Ping message.
    Ping(Vec<u8>),
    /// Pong message.
    Pong(Vec<u8>),
    /// Close message.
    Close(Option<WsCloseFrame>),
}

impl WsMessage {
    /// Create a text message.
    #[must_use]
    pub fn text(data: impl Into<String>) -> Self {
        Self::Text(data.into())
    }

    /// Create a binary message.
    #[must_use]
    pub fn binary(data: impl Into<Vec<u8>>) -> Self {
        Self::Binary(data.into())
    }

    /// Check if this is a text message.
    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Check if this is a binary message.
    #[must_use]
    pub const fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_))
    }

    /// Check if this is a close message.
    #[must_use]
    pub const fn is_close(&self) -> bool {
        matches!(self, Self::Close(_))
    }

    /// Get text data if this is a text message.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Get binary data if this is a binary message.
    #[must_use]
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(b) => Some(b),
            _ => None,
        }
    }

    /// Parse text as JSON.
    ///
    /// # Errors
    /// Returns a JSON parsing error if the payload is not valid JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match self {
            Self::Text(s) => serde_json::from_str(s),
            Self::Binary(b) => serde_json::from_slice(b),
            _ => Err(serde::de::Error::custom("Not a data message")),
        }
    }
}

impl From<Message> for WsMessage {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Text(s) => Self::Text(s.to_string()),
            Message::Binary(b) => Self::Binary(b.to_vec()),
            Message::Ping(b) => Self::Ping(b.to_vec()),
            Message::Pong(b) => Self::Pong(b.to_vec()),
            Message::Close(frame) => Self::Close(frame.map(|f| WsCloseFrame {
                code: f.code.into(),
                reason: f.reason.to_string(),
            })),
            Message::Frame(_) => Self::Binary(vec![]),
        }
    }
}

impl From<WsMessage> for Message {
    fn from(msg: WsMessage) -> Self {
        match msg {
            WsMessage::Text(s) => Self::Text(s.into()),
            WsMessage::Binary(b) => Self::Binary(b.into()),
            WsMessage::Ping(b) => Self::Ping(b.into()),
            WsMessage::Pong(b) => Self::Pong(b.into()),
            WsMessage::Close(frame) => {
                use tokio_tungstenite::tungstenite::protocol::CloseFrame;
                use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
                Self::Close(frame.map(|f| CloseFrame {
                    code: CloseCode::from(f.code),
                    reason: f.reason.into(),
                }))
            }
        }
    }
}

/// WebSocket close frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsCloseFrame {
    /// Close code.
    pub code: u16,
    /// Close reason.
    pub reason: String,
}

impl WsCloseFrame {
    /// Create a new close frame.
    #[must_use]
    pub fn new(code: u16, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// Normal closure.
    #[must_use]
    pub fn normal() -> Self {
        Self::new(1000, "Normal closure")
    }

    /// Going away.
    #[must_use]
    pub fn going_away() -> Self {
        Self::new(1001, "Going away")
    }
}

/// WebSocket configuration.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Ping interval.
    pub ping_interval: Option<Duration>,
    /// Pong timeout.
    pub pong_timeout: Duration,
    /// Maximum message size.
    pub max_message_size: usize,
    /// Additional headers.
    pub headers: HashMap<String, String>,
    /// Auto-reconnect on disconnect.
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts.
    pub max_reconnect_attempts: Option<u32>,
    /// Reconnection delay.
    pub reconnect_delay: Duration,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            ping_interval: Some(Duration::from_secs(30)),
            pong_timeout: Duration::from_secs(10),
            max_message_size: 64 * 1024 * 1024, // 64MB
            headers: HashMap::new(),
            auto_reconnect: true,
            max_reconnect_attempts: Some(10),
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

impl WsConfig {
    /// Create new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connection timeout.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set ping interval.
    #[must_use]
    pub const fn with_ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Set maximum message size.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
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
}

/// WebSocket client.
#[derive(Clone)]
pub struct WsClient {
    url: String,
    config: WsConfig,
}

impl WsClient {
    /// Create a new WebSocket client.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            config: WsConfig::default(),
        }
    }

    /// Create with configuration.
    #[must_use]
    pub fn with_config(url: impl Into<String>, config: WsConfig) -> Self {
        Self {
            url: url.into(),
            config,
        }
    }

    /// Connect to the WebSocket server.
    ///
    /// # Errors
    /// Returns an error if the connection attempt fails or times out.
    pub async fn connect(&self) -> StreamResult<WsConnection> {
        let url = Url::parse(&self.url)
            .map_err(|e: url::ParseError| StreamError::ConnectionFailed(e.to_string()))?;

        let connect_result =
            tokio::time::timeout(self.config.connect_timeout, connect_async(url.as_str())).await;

        let Ok(ws_result) = connect_result else {
            return Err(StreamError::Timeout(self.config.connect_timeout));
        };

        let (ws_stream, _response) =
            ws_result.map_err(|e: tokio_tungstenite::tungstenite::Error| {
                StreamError::WebSocketError(e.to_string())
            })?;

        Ok(WsConnection::new(ws_stream, self.config.clone()))
    }

    /// Get the URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &WsConfig {
        &self.config
    }

    /// Create a reconnecting stream.
    pub fn stream(&self) -> ReconnectingWsStream {
        ReconnectingWsStream::new(self.clone())
    }
}

/// Active WebSocket connection.
pub struct WsConnection {
    inner: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    config: WsConfig,
    closed: bool,
}

impl WsConnection {
    /// Create a new connection wrapper.
    const fn new(
        stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        config: WsConfig,
    ) -> Self {
        Self {
            inner: stream,
            config,
            closed: false,
        }
    }

    /// Send a message.
    ///
    /// # Errors
    /// Returns a stream error if the message cannot be sent.
    pub async fn send(&mut self, message: WsMessage) -> StreamResult<()> {
        if self.closed {
            return Err(StreamError::InvalidState("Connection is closed".into()));
        }

        self.inner
            .send(message.into())
            .await
            .map_err(|e| StreamError::WebSocketError(e.to_string()))
    }

    /// Send a text message.
    ///
    /// # Errors
    /// Returns a stream error if the message cannot be sent.
    pub async fn send_text(&mut self, text: impl Into<String>) -> StreamResult<()> {
        self.send(WsMessage::text(text)).await
    }

    /// Send a binary message.
    ///
    /// # Errors
    /// Returns a stream error if the message cannot be sent.
    pub async fn send_binary(&mut self, data: impl Into<Vec<u8>>) -> StreamResult<()> {
        self.send(WsMessage::binary(data)).await
    }

    /// Send JSON data.
    ///
    /// # Errors
    /// Returns a stream error if serialization or send fails.
    pub async fn send_json<T: serde::Serialize + Sync>(&mut self, data: &T) -> StreamResult<()> {
        let json =
            serde_json::to_string(data).map_err(|e| StreamError::ParseError(e.to_string()))?;
        self.send_text(json).await
    }

    /// Receive the next message.
    ///
    /// # Errors
    /// Returns a stream error if the underlying socket fails.
    pub async fn recv(&mut self) -> StreamResult<Option<WsMessage>> {
        if self.closed {
            return Ok(None);
        }

        match self.inner.next().await {
            Some(Ok(msg)) => {
                let ws_msg: WsMessage = msg.into();
                if ws_msg.is_close() {
                    self.closed = true;
                }
                Ok(Some(ws_msg))
            }
            Some(Err(e)) => Err(StreamError::WebSocketError(e.to_string())),
            None => {
                self.closed = true;
                Ok(None)
            }
        }
    }

    /// Close the connection.
    ///
    /// # Errors
    /// Returns a stream error if the close frame fails to send.
    pub async fn close(&mut self) -> StreamResult<()> {
        if !self.closed {
            self.closed = true;
            self.inner
                .close(None)
                .await
                .map_err(|e| StreamError::WebSocketError(e.to_string()))?;
        }
        Ok(())
    }

    /// Close with a specific frame.
    ///
    /// # Errors
    /// Returns a stream error if the close frame fails to send.
    pub async fn close_with_frame(&mut self, frame: WsCloseFrame) -> StreamResult<()> {
        if !self.closed {
            self.closed = true;
            self.send(WsMessage::Close(Some(frame))).await?;
        }
        Ok(())
    }

    /// Check if the connection is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &WsConfig {
        &self.config
    }
}

impl Stream for WsConnection {
    type Item = StreamResult<WsMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                let ws_msg: WsMessage = msg.into();
                if ws_msg.is_close() {
                    self.closed = true;
                }
                Poll::Ready(Some(Ok(ws_msg)))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(StreamError::WebSocketError(e.to_string()))))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Reconnecting WebSocket stream.
pub struct ReconnectingWsStream {
    client: WsClient,
    handler: ReconnectHandler,
    state: ReconnectState,
}

enum ReconnectState {
    /// Initial state or between attempts.
    Idle,
    /// Waiting for backoff delay.
    Waiting(Pin<Box<tokio::time::Sleep>>),
    /// Connection attempt in progress.
    Connecting(Pin<Box<dyn std::future::Future<Output = StreamResult<WsConnection>> + Send>>),
    /// Active connection.
    Connected(WsConnection),
}

impl ReconnectingWsStream {
    fn new(client: WsClient) -> Self {
        let config = crate::reconnect::ReconnectConfig::new()
            .with_max_attempts(if client.config.auto_reconnect {
                client.config.max_reconnect_attempts.unwrap_or(u32::MAX)
            } else {
                0
            })
            .with_initial_delay(client.config.reconnect_delay);

        Self {
            handler: ReconnectHandler::new(config),
            client,
            state: ReconnectState::Idle,
        }
    }
}

impl Stream for ReconnectingWsStream {
    type Item = StreamResult<WsMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match &mut self.state {
                ReconnectState::Idle => {
                    // Start connecting
                    let client_clone = WsClient {
                        url: self.client.url.clone(),
                        config: self.client.config.clone(),
                    };
                    // We need a way to clone the client future or spawn it?
                    // connect is async.
                    let future = Box::pin(async move { client_clone.connect().await });
                    self.state = ReconnectState::Connecting(future);
                }
                ReconnectState::Waiting(delay) => match delay.as_mut().poll(cx) {
                    Poll::Ready(_) => {
                        self.state = ReconnectState::Idle;
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Connecting(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(conn)) => {
                        self.handler.reset();
                        self.state = ReconnectState::Connected(conn);
                    }
                    Poll::Ready(Err(e)) => {
                        if !self.handler.can_reconnect() {
                            return Poll::Ready(Some(Err(e)));
                        }

                        let attempt = self.handler.attempts();
                        let delay_duration = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure(); // Increment attempts

                        let sleep = Box::pin(tokio::time::sleep(delay_duration));
                        self.state = ReconnectState::Waiting(sleep);
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Connected(conn) => match Pin::new(conn).poll_next(cx) {
                    Poll::Ready(Some(Ok(msg))) => return Poll::Ready(Some(Ok(msg))),
                    Poll::Ready(Some(Err(e))) => {
                        if !self.handler.can_reconnect() {
                            return Poll::Ready(Some(Err(e)));
                        }

                        let attempt = self.handler.attempts();
                        let delay_duration = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure();

                        let sleep = Box::pin(tokio::time::sleep(delay_duration));
                        self.state = ReconnectState::Waiting(sleep);
                    }
                    Poll::Ready(None) => {
                        if !self.handler.can_reconnect() {
                            return Poll::Ready(None);
                        }

                        let attempt = self.handler.attempts();
                        let delay_duration = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure();

                        let sleep = Box::pin(tokio::time::sleep(delay_duration));
                        self.state = ReconnectState::Waiting(sleep);
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_message_text() {
        let msg = WsMessage::text("hello");
        assert!(msg.is_text());
        assert!(!msg.is_binary());
        assert_eq!(msg.as_text(), Some("hello"));
    }

    #[test]
    fn test_ws_message_binary() {
        let msg = WsMessage::binary(vec![1, 2, 3]);
        assert!(msg.is_binary());
        assert!(!msg.is_text());
        assert_eq!(msg.as_binary(), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn test_ws_message_json() {
        #[derive(serde::Deserialize)]
        struct Data {
            key: String,
        }

        let msg = WsMessage::text(r#"{"key": "value"}"#);
        let data: Data = msg.json().unwrap();
        assert_eq!(data.key, "value");
    }

    #[test]
    fn test_ws_close_frame() {
        let frame = WsCloseFrame::normal();
        assert_eq!(frame.code, 1000);

        let frame = WsCloseFrame::going_away();
        assert_eq!(frame.code, 1001);
    }

    #[test]
    fn test_ws_config() {
        let config = WsConfig::new()
            .with_connect_timeout(Duration::from_secs(60))
            .with_ping_interval(Some(Duration::from_secs(15)))
            .with_max_message_size(1024)
            .with_header("Authorization", "Bearer token")
            .with_auto_reconnect(false);

        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(15)));
        assert_eq!(config.max_message_size, 1024);
        assert!(!config.auto_reconnect);
    }

    // ── New tests ──

    #[test]
    fn test_ws_message_is_close() {
        let msg = WsMessage::Close(None);
        assert!(msg.is_close());
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
    }

    #[test]
    fn test_ws_message_as_text_on_binary() {
        let msg = WsMessage::binary(vec![1, 2, 3]);
        assert_eq!(msg.as_text(), None);
    }

    #[test]
    fn test_ws_message_as_binary_on_text() {
        let msg = WsMessage::text("hello");
        assert_eq!(msg.as_binary(), None);
    }

    #[test]
    fn test_ws_message_json_from_binary() {
        #[derive(serde::Deserialize)]
        struct Data {
            key: String,
        }

        let msg = WsMessage::binary(br#"{"key": "value"}"#.to_vec());
        let data: Data = msg.json().unwrap();
        assert_eq!(data.key, "value");
    }

    #[test]
    fn test_ws_message_json_parse_failure() {
        let msg = WsMessage::text("not json");
        let result: Result<serde_json::Value, _> = msg.json();
        assert!(result.is_err());
    }

    #[test]
    fn test_ws_message_json_on_close() {
        let msg = WsMessage::Close(None);
        let result: Result<serde_json::Value, _> = msg.json();
        assert!(result.is_err());
    }

    #[test]
    fn test_ws_close_frame_custom() {
        let frame = WsCloseFrame::new(4000, "Custom reason");
        assert_eq!(frame.code, 4000);
        assert_eq!(frame.reason, "Custom reason");
    }

    #[test]
    fn test_ws_config_default() {
        let config = WsConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(30)));
        assert_eq!(config.pong_timeout, Duration::from_secs(10));
        assert_eq!(config.max_message_size, 64 * 1024 * 1024);
        assert!(config.headers.is_empty());
        assert!(config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, Some(10));
        assert_eq!(config.reconnect_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_ws_client_accessors() {
        let client = WsClient::new("ws://localhost:8080");
        assert_eq!(client.url(), "ws://localhost:8080");
        assert_eq!(client.config().connect_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_ws_client_with_config() {
        let config = WsConfig::new().with_connect_timeout(Duration::from_secs(60));
        let client = WsClient::with_config("ws://localhost:8080", config);
        assert_eq!(client.url(), "ws://localhost:8080");
        assert_eq!(client.config().connect_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_ws_message_ping_pong() {
        let ping = WsMessage::Ping(vec![1, 2, 3]);
        assert!(!ping.is_text());
        assert!(!ping.is_binary());
        assert!(!ping.is_close());

        let pong = WsMessage::Pong(vec![4, 5, 6]);
        assert!(!pong.is_text());
        assert!(!pong.is_binary());
        assert!(!pong.is_close());
    }

    #[test]
    fn test_ws_message_close_with_frame() {
        let frame = WsCloseFrame::normal();
        let msg = WsMessage::Close(Some(frame.clone()));
        assert!(msg.is_close());
        assert_eq!(frame.code, 1000);
    }

    #[test]
    fn test_ws_message_from_tungstenite_text() {
        let msg: WsMessage = Message::Text("hello".into()).into();
        assert!(msg.is_text());
        assert_eq!(msg.as_text(), Some("hello"));
    }

    #[test]
    fn test_ws_message_from_tungstenite_binary() {
        let msg: WsMessage = Message::Binary(vec![1, 2, 3].into()).into();
        assert!(msg.is_binary());
        assert_eq!(msg.as_binary(), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn test_ws_message_to_tungstenite_roundtrip_text() {
        let original = WsMessage::text("roundtrip");
        let tungstenite: Message = original.into();
        let back: WsMessage = tungstenite.into();
        assert!(back.is_text());
        assert_eq!(back.as_text(), Some("roundtrip"));
    }

    #[test]
    fn test_ws_message_to_tungstenite_roundtrip_binary() {
        let original = WsMessage::binary(vec![10, 20, 30]);
        let tungstenite: Message = original.into();
        let back: WsMessage = tungstenite.into();
        assert!(back.is_binary());
        assert_eq!(back.as_binary(), Some(&[10, 20, 30][..]));
    }
}
