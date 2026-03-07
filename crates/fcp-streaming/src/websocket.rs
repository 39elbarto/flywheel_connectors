//! WebSocket client implementation.
//!
//! Provides full WebSocket protocol support with automatic reconnection.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use asupersync::bytes::Bytes;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::websocket::{
    ClientHandshake, CloseCode, CloseConfig, CloseReason, HttpResponse, Message, WebSocket,
    WebSocketConfig, WsError, WsUrl,
};
use asupersync::tls::{TlsConnectorBuilder, TlsStream};
use fcp_async_core::{
    AsyncError,
    net::TcpStream,
    time::{Sleep, sleep, timeout},
};
use futures_util::stream::Stream;

use crate::reconnect::ReconnectHandler;
use crate::{StreamError, StreamResult};

fn websocket_cx() -> asupersync::Cx {
    asupersync::Cx::current().unwrap_or_else(asupersync::Cx::for_testing)
}

fn websocket_config(config: &WsConfig) -> WebSocketConfig {
    let mut websocket_config = WebSocketConfig::new()
        .max_message_size(config.max_message_size)
        .ping_interval(config.ping_interval)
        .connect_timeout(Some(config.connect_timeout));
    websocket_config.close_config = CloseConfig::new().with_timeout(config.pong_timeout);
    websocket_config
}

fn socket_addr(url: &WsUrl) -> String {
    if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

fn connection_failed(message: impl Into<String>) -> StreamError {
    StreamError::ConnectionFailed(message.into())
}

fn websocket_error(err: WsError) -> StreamError {
    match err {
        WsError::PayloadTooLarge { size, max } => StreamError::BufferOverflow {
            size: usize::try_from(size).unwrap_or(usize::MAX),
            limit: max,
        },
        other => StreamError::WebSocketError(other.to_string()),
    }
}

fn build_handshake(url: &str, headers: &HashMap<String, String>) -> StreamResult<ClientHandshake> {
    let cx = websocket_cx();
    let mut handshake = ClientHandshake::new(url, cx.entropy())
        .map_err(|err| connection_failed(err.to_string()))?;
    for (name, value) in headers {
        handshake = handshake.header(name.clone(), value.clone());
    }
    Ok(handshake)
}

async fn write_all<IO>(io: &mut IO, buf: &[u8]) -> io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    let mut written = 0;
    while written < buf.len() {
        let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, &buf[written..])).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        written += n;
    }
    Ok(())
}

async fn read_http_response<IO>(io: &mut IO) -> io::Result<Vec<u8>>
where
    IO: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];

    loop {
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }

        if response.len() >= 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response too large",
            ));
        }

        let n = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut byte);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before HTTP response complete",
            ));
        }

        response.push(byte[0]);
    }
}

async fn perform_handshake<IO>(
    mut io: IO,
    url: &str,
    config: &WsConfig,
) -> StreamResult<WebSocket<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = build_handshake(url, &config.headers)?;
    let request = handshake.request_bytes();
    write_all(&mut io, &request)
        .await
        .map_err(|err| connection_failed(err.to_string()))?;

    let response_bytes = read_http_response(&mut io)
        .await
        .map_err(|err| connection_failed(err.to_string()))?;
    let response =
        HttpResponse::parse(&response_bytes).map_err(|err| connection_failed(err.to_string()))?;
    handshake
        .validate_response(&response)
        .map_err(|err| connection_failed(err.to_string()))?;

    Ok(WebSocket::from_upgraded(io, websocket_config(config)))
}

fn build_tls_connector() -> StreamResult<asupersync::tls::TlsConnector> {
    TlsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|err| connection_failed(err.to_string()))?
        .alpn_http()
        .build()
        .map_err(|err| connection_failed(err.to_string()))
}

enum WsTransport {
    Plain(Box<WebSocket<TcpStream>>),
    Tls(Box<WebSocket<TlsStream<TcpStream>>>),
}

impl WsTransport {
    async fn send(&mut self, message: Message) -> Result<(), WsError> {
        let cx = websocket_cx();
        match self {
            Self::Plain(socket) => socket.send(&cx, message).await,
            Self::Tls(socket) => socket.send(&cx, message).await,
        }
    }

    async fn recv(&mut self) -> Result<Option<Message>, WsError> {
        let cx = websocket_cx();
        match self {
            Self::Plain(socket) => socket.recv(&cx).await,
            Self::Tls(socket) => socket.recv(&cx).await,
        }
    }

    async fn close(&mut self, reason: CloseReason) -> Result<(), WsError> {
        match self {
            Self::Plain(socket) => socket.close(reason).await,
            Self::Tls(socket) => socket.close(reason).await,
        }
    }
}

async fn connect_websocket(url: String, config: WsConfig) -> StreamResult<WsTransport> {
    let parsed = WsUrl::parse(&url).map_err(|err| connection_failed(err.to_string()))?;
    let address = socket_addr(&parsed);
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|err| connection_failed(err.to_string()))?;
    let _ = tcp.set_nodelay(true);

    if parsed.tls {
        let connector = build_tls_connector()?;
        let tls_stream = connector
            .connect(&parsed.host, tcp)
            .await
            .map_err(|err| connection_failed(err.to_string()))?;
        perform_handshake(tls_stream, &url, &config)
            .await
            .map(Box::new)
            .map(WsTransport::Tls)
    } else {
        perform_handshake(tcp, &url, &config)
            .await
            .map(Box::new)
            .map(WsTransport::Plain)
    }
}

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
            Self::Text(data) => Some(data),
            _ => None,
        }
    }

    /// Get binary data if this is a binary message.
    #[must_use]
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(data) => Some(data),
            _ => None,
        }
    }

    /// Parse text as JSON.
    ///
    /// # Errors
    /// Returns a JSON parsing error if the payload is not valid JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match self {
            Self::Text(data) => serde_json::from_str(data),
            Self::Binary(data) => serde_json::from_slice(data),
            _ => Err(serde::de::Error::custom("Not a data message")),
        }
    }
}

impl From<CloseReason> for WsCloseFrame {
    fn from(reason: CloseReason) -> Self {
        Self {
            code: reason.wire_code().unwrap_or(1000),
            reason: reason.text.unwrap_or_default(),
        }
    }
}

impl From<WsCloseFrame> for CloseReason {
    fn from(frame: WsCloseFrame) -> Self {
        let raw_code = CloseCode::is_valid_code(frame.code).then_some(frame.code);
        Self {
            code: raw_code.and_then(CloseCode::from_u16),
            raw_code,
            text: (!frame.reason.is_empty()).then_some(frame.reason),
        }
    }
}

impl From<Message> for WsMessage {
    fn from(message: Message) -> Self {
        match message {
            Message::Text(text) => Self::Text(text),
            Message::Binary(data) => Self::Binary(data.to_vec()),
            Message::Ping(data) => Self::Ping(data.to_vec()),
            Message::Pong(data) => Self::Pong(data.to_vec()),
            Message::Close(reason) => Self::Close(reason.map(Self::close_frame_from_reason)),
        }
    }
}

impl WsMessage {
    fn close_frame_from_reason(reason: CloseReason) -> WsCloseFrame {
        reason.into()
    }
}

impl From<WsMessage> for Message {
    fn from(message: WsMessage) -> Self {
        match message {
            WsMessage::Text(text) => Self::Text(text),
            WsMessage::Binary(data) => Self::Binary(Bytes::from(data)),
            WsMessage::Ping(data) => Self::Ping(Bytes::from(data)),
            WsMessage::Pong(data) => Self::Pong(Bytes::from(data)),
            WsMessage::Close(frame) => Self::Close(frame.map(CloseReason::from)),
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
            max_message_size: 64 * 1024 * 1024,
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
        let connect_future = Box::pin(connect_websocket(self.url.clone(), self.config.clone()));
        let result = timeout(self.config.connect_timeout, connect_future)
            .await
            .map_err(|error| match error {
                AsyncError::Timeout { .. } => StreamError::Timeout(self.config.connect_timeout),
                other => StreamError::ConnectionFailed(other.to_string()),
            })?;

        Ok(WsConnection::new(result?, self.config.clone()))
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
    #[must_use]
    pub fn stream(&self) -> ReconnectingWsStream {
        ReconnectingWsStream::new(self.clone())
    }
}

/// Active WebSocket connection.
pub struct WsConnection {
    inner: WsTransport,
    config: WsConfig,
    closed: bool,
}

impl WsConnection {
    const fn new(inner: WsTransport, config: WsConfig) -> Self {
        Self {
            inner,
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

        let is_close = message.is_close();
        self.inner
            .send(message.into())
            .await
            .map_err(websocket_error)?;
        if is_close {
            self.closed = true;
        }
        Ok(())
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
            serde_json::to_string(data).map_err(|err| StreamError::ParseError(err.to_string()))?;
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

        if let Some(message) = self.inner.recv().await.map_err(websocket_error)? {
            let message: WsMessage = message.into();
            if message.is_close() {
                self.closed = true;
            }
            Ok(Some(message))
        } else {
            self.closed = true;
            Ok(None)
        }
    }

    /// Close the connection.
    ///
    /// # Errors
    /// Returns a stream error if the close handshake fails.
    pub async fn close(&mut self) -> StreamResult<()> {
        if !self.closed {
            self.inner
                .close(CloseReason::normal())
                .await
                .map_err(websocket_error)?;
            self.closed = true;
        }
        Ok(())
    }

    /// Close with a specific frame.
    ///
    /// # Errors
    /// Returns a stream error if the close handshake fails.
    pub async fn close_with_frame(&mut self, frame: WsCloseFrame) -> StreamResult<()> {
        if !self.closed {
            self.inner
                .close(frame.into())
                .await
                .map_err(websocket_error)?;
            self.closed = true;
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

type ConnectFuture = Pin<Box<dyn Future<Output = StreamResult<WsConnection>>>>;
type ReceiveFuture =
    Pin<Box<dyn Future<Output = (Box<WsConnection>, StreamResult<Option<WsMessage>>)>>>;

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
    Waiting(Pin<Box<Sleep>>),
    /// Connection attempt in progress.
    Connecting(ConnectFuture),
    /// Active connection ready to receive.
    Connected(Box<WsConnection>),
    /// Message receive in progress.
    Receiving(ReceiveFuture),
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
            client,
            handler: ReconnectHandler::new(config),
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
                    let client = self.client.clone();
                    self.state =
                        ReconnectState::Connecting(Box::pin(async move { client.connect().await }));
                }
                ReconnectState::Waiting(delay) => match delay.as_mut().poll(cx) {
                    Poll::Ready(()) => self.state = ReconnectState::Idle,
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Connecting(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(connection)) => {
                        self.handler.reset();
                        self.state = ReconnectState::Connected(Box::new(connection));
                    }
                    Poll::Ready(Err(err)) => {
                        if !self.handler.can_reconnect() {
                            return Poll::Ready(Some(Err(err)));
                        }
                        let attempt = self.handler.attempts();
                        let delay = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReconnectState::Connected(_) => {
                    let ReconnectState::Connected(connection) =
                        std::mem::replace(&mut self.state, ReconnectState::Idle)
                    else {
                        unreachable!();
                    };
                    self.state = ReconnectState::Receiving(Box::pin(async move {
                        let mut connection = connection;
                        let result = connection.recv().await;
                        (connection, result)
                    }));
                }
                ReconnectState::Receiving(future) => match future.as_mut().poll(cx) {
                    Poll::Ready((connection, Ok(Some(message)))) => {
                        self.state = ReconnectState::Connected(connection);
                        return Poll::Ready(Some(Ok(message)));
                    }
                    Poll::Ready((connection, Ok(None))) => {
                        drop(connection);
                        if !self.handler.can_reconnect() {
                            return Poll::Ready(None);
                        }
                        let attempt = self.handler.attempts();
                        let delay = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
                    }
                    Poll::Ready((connection, Err(err))) => {
                        drop(connection);
                        if !self.handler.can_reconnect() {
                            return Poll::Ready(Some(Err(err)));
                        }
                        let attempt = self.handler.attempts();
                        let delay = self.handler.config().delay_for_attempt(attempt);
                        self.handler.record_failure();
                        self.state = ReconnectState::Waiting(Box::pin(sleep(delay)));
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

    fn block_on<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn ws_message_text_accessors() {
        let message = WsMessage::text("hello");
        assert!(message.is_text());
        assert!(!message.is_binary());
        assert_eq!(message.as_text(), Some("hello"));
        assert_eq!(message.as_binary(), None);
    }

    #[test]
    fn ws_message_binary_accessors() {
        let message = WsMessage::binary(vec![1, 2, 3]);
        assert!(message.is_binary());
        assert!(!message.is_text());
        assert_eq!(message.as_binary(), Some(&[1, 2, 3][..]));
        assert_eq!(message.as_text(), None);
    }

    #[test]
    fn ws_message_json_supports_text_and_binary() {
        #[derive(Debug, serde::Deserialize, PartialEq, Eq)]
        struct Payload {
            key: String,
        }

        let text = WsMessage::text(r#"{"key":"value"}"#);
        let binary = WsMessage::binary(br#"{"key":"value"}"#.to_vec());

        assert_eq!(
            text.json::<Payload>().expect("text json"),
            Payload {
                key: "value".into(),
            }
        );
        assert_eq!(
            binary.json::<Payload>().expect("binary json"),
            Payload {
                key: "value".into(),
            }
        );
    }

    #[test]
    fn ws_message_json_rejects_control_messages() {
        assert!(WsMessage::Ping(vec![]).json::<serde_json::Value>().is_err());
        assert!(WsMessage::Pong(vec![]).json::<serde_json::Value>().is_err());
        assert!(WsMessage::Close(None).json::<serde_json::Value>().is_err());
    }

    #[test]
    fn ws_close_frame_builders() {
        assert_eq!(
            WsCloseFrame::normal(),
            WsCloseFrame::new(1000, "Normal closure")
        );
        assert_eq!(
            WsCloseFrame::going_away(),
            WsCloseFrame::new(1001, "Going away")
        );
    }

    #[test]
    fn ws_message_roundtrip_asupersync_text() {
        let original = WsMessage::text("roundtrip");
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_asupersync_binary() {
        let original = WsMessage::binary(vec![10, 20, 30]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_from_asupersync_close_frame() {
        let reason = CloseReason::with_text(CloseCode::Normal, "bye");
        let message: WsMessage = Message::Close(Some(reason)).into();
        assert_eq!(
            message,
            WsMessage::Close(Some(WsCloseFrame::new(1000, "bye")))
        );
    }

    #[test]
    fn ws_message_to_asupersync_close_frame() {
        let message: Message = WsMessage::Close(Some(WsCloseFrame::going_away())).into();
        let Message::Close(Some(reason)) = message else {
            panic!("expected close message");
        };
        assert_eq!(reason.wire_code(), Some(1001));
        assert_eq!(reason.text.as_deref(), Some("Going away"));
    }

    #[test]
    fn ws_config_builder() {
        let config = WsConfig::new()
            .with_connect_timeout(Duration::from_secs(60))
            .with_ping_interval(Some(Duration::from_secs(15)))
            .with_max_message_size(1024)
            .with_header("Authorization", "Bearer token")
            .with_auto_reconnect(false);

        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert_eq!(config.ping_interval, Some(Duration::from_secs(15)));
        assert_eq!(config.max_message_size, 1024);
        assert_eq!(
            config.headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
        assert!(!config.auto_reconnect);
    }

    #[test]
    fn ws_client_accessors() {
        let config = WsConfig::new().with_connect_timeout(Duration::from_secs(45));
        let client = WsClient::with_config("ws://localhost:8080", config);

        assert_eq!(client.url(), "ws://localhost:8080");
        assert_eq!(client.config().connect_timeout, Duration::from_secs(45));
    }

    #[test]
    fn ws_client_stream_construction() {
        let client = WsClient::new("ws://localhost:9999");
        let _stream = client.stream();
    }

    #[test]
    fn ws_client_invalid_url_returns_connection_failed() {
        block_on(async {
            let client = WsClient::new("not-a-valid-url");
            let result = client.connect().await;
            assert!(matches!(result, Err(StreamError::ConnectionFailed(_))));
        });
    }

    #[test]
    fn ws_client_connection_refused() {
        block_on(async {
            let client = WsClient::with_config(
                "ws://127.0.0.1:1",
                WsConfig::new().with_connect_timeout(Duration::from_millis(200)),
            );
            assert!(client.connect().await.is_err());
        });
    }

    // ── WsMessage: close variant ───────────────────────────────────────

    #[test]
    fn ws_message_close_none() {
        let msg = WsMessage::Close(None);
        assert!(msg.is_close());
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
        assert!(msg.as_text().is_none());
        assert!(msg.as_binary().is_none());
    }

    #[test]
    fn ws_message_close_with_frame() {
        let msg = WsMessage::Close(Some(WsCloseFrame::normal()));
        assert!(msg.is_close());
    }

    // ── WsMessage: ping/pong ───────────────────────────────────────────

    #[test]
    fn ws_message_ping_is_not_data() {
        let msg = WsMessage::Ping(vec![1, 2, 3]);
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
        assert!(!msg.is_close());
        assert!(msg.as_text().is_none());
        assert!(msg.as_binary().is_none());
    }

    #[test]
    fn ws_message_pong_is_not_data() {
        let msg = WsMessage::Pong(vec![4, 5]);
        assert!(!msg.is_text());
        assert!(!msg.is_binary());
        assert!(!msg.is_close());
    }

    // ── WsMessage: equality ────────────────────────────────────────────

    #[test]
    fn ws_message_equality() {
        assert_eq!(WsMessage::text("a"), WsMessage::text("a"));
        assert_ne!(WsMessage::text("a"), WsMessage::text("b"));
        assert_ne!(WsMessage::text("a"), WsMessage::binary(b"a".to_vec()));
        assert_eq!(WsMessage::binary(vec![1, 2]), WsMessage::binary(vec![1, 2]));
        assert_ne!(WsMessage::binary(vec![1, 2]), WsMessage::binary(vec![3, 4]));
    }

    #[test]
    fn ws_message_clone() {
        let msg = WsMessage::text("clone me");
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn ws_message_debug() {
        let msg = WsMessage::text("debug");
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Text"));
        assert!(dbg.contains("debug"));
    }

    // ── WsMessage: json edge cases ─────────────────────────────────────

    #[test]
    fn ws_message_json_invalid_text() {
        let msg = WsMessage::text("not json{");
        assert!(msg.json::<serde_json::Value>().is_err());
    }

    #[test]
    fn ws_message_json_binary_valid() {
        let msg = WsMessage::binary(b"42".to_vec());
        let val: i32 = msg.json().unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn ws_message_json_empty_text() {
        let msg = WsMessage::text("");
        assert!(msg.json::<serde_json::Value>().is_err());
    }

    // ── WsMessage: empty payloads ──────────────────────────────────────

    #[test]
    fn ws_message_text_empty() {
        let msg = WsMessage::text("");
        assert!(msg.is_text());
        assert_eq!(msg.as_text(), Some(""));
    }

    #[test]
    fn ws_message_binary_empty() {
        let msg = WsMessage::binary(vec![]);
        assert!(msg.is_binary());
        assert_eq!(msg.as_binary(), Some(&[][..]));
    }

    // ── WsCloseFrame ───────────────────────────────────────────────────

    #[test]
    fn ws_close_frame_custom() {
        let frame = WsCloseFrame::new(4000, "custom close");
        assert_eq!(frame.code, 4000);
        assert_eq!(frame.reason, "custom close");
    }

    #[test]
    fn ws_close_frame_debug_clone_eq() {
        let frame = WsCloseFrame::normal();
        let cloned = frame.clone();
        assert_eq!(frame, cloned);
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("WsCloseFrame"));
        assert!(dbg.contains("1000"));
    }

    #[test]
    fn ws_close_frame_empty_reason() {
        let frame = WsCloseFrame::new(1000, "");
        assert_eq!(frame.reason, "");
    }

    // ── WsCloseFrame conversions ───────────────────────────────────────

    #[test]
    fn ws_close_frame_roundtrip_through_close_reason() {
        let original = WsCloseFrame::new(1000, "normal");
        let reason: CloseReason = original.clone().into();
        let back: WsCloseFrame = reason.into();
        assert_eq!(back.code, original.code);
        assert_eq!(back.reason, original.reason);
    }

    #[test]
    fn ws_close_frame_from_close_reason_no_text() {
        let reason = CloseReason {
            code: Some(CloseCode::Normal),
            raw_code: Some(1000),
            text: None,
        };
        let frame: WsCloseFrame = reason.into();
        assert_eq!(frame.code, 1000);
        assert_eq!(frame.reason, "");
    }

    // ── WsConfig defaults ──────────────────────────────────────────────

    #[test]
    fn ws_config_defaults() {
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
    fn ws_config_new_equals_default() {
        let a = WsConfig::new();
        let b = WsConfig::default();
        assert_eq!(a.connect_timeout, b.connect_timeout);
        assert_eq!(a.ping_interval, b.ping_interval);
        assert_eq!(a.max_message_size, b.max_message_size);
        assert_eq!(a.auto_reconnect, b.auto_reconnect);
    }

    #[test]
    fn ws_config_debug() {
        let config = WsConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("WsConfig"));
    }

    #[test]
    fn ws_config_clone() {
        let config = WsConfig::new()
            .with_header("X-Custom", "value")
            .with_max_message_size(1024);
        let cloned = config.clone();
        assert_eq!(config.max_message_size, cloned.max_message_size);
        assert_eq!(cloned.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn ws_config_multiple_headers() {
        let config = WsConfig::new()
            .with_header("A", "1")
            .with_header("B", "2")
            .with_header("A", "3"); // overwrite
        assert_eq!(config.headers.len(), 2);
        assert_eq!(config.headers.get("A"), Some(&"3".to_string()));
        assert_eq!(config.headers.get("B"), Some(&"2".to_string()));
    }

    #[test]
    fn ws_config_no_ping_interval() {
        let config = WsConfig::new().with_ping_interval(None);
        assert!(config.ping_interval.is_none());
    }

    // ── socket_addr helper ─────────────────────────────────────────────

    #[test]
    fn socket_addr_ipv4() {
        let url = WsUrl::parse("ws://127.0.0.1:8080/ws").unwrap();
        assert_eq!(socket_addr(&url), "127.0.0.1:8080");
    }

    #[test]
    fn socket_addr_hostname() {
        let url = WsUrl::parse("ws://example.com:443/ws").unwrap();
        assert_eq!(socket_addr(&url), "example.com:443");
    }

    #[test]
    fn socket_addr_ipv6() {
        let url = WsUrl {
            host: "::1".to_string(),
            port: 9090,
            path: "/ws".to_string(),
            tls: false,
        };
        assert_eq!(socket_addr(&url), "[::1]:9090");
    }

    // ── websocket_error conversion ─────────────────────────────────────

    #[test]
    fn websocket_error_payload_too_large() {
        let err = WsError::PayloadTooLarge {
            size: 2048,
            max: 1024,
        };
        let stream_err = websocket_error(err);
        assert!(matches!(
            stream_err,
            StreamError::BufferOverflow {
                size: 2048,
                limit: 1024
            }
        ));
    }

    #[test]
    fn websocket_error_generic() {
        let err = WsError::ProtocolViolation("test violation");
        let stream_err = websocket_error(err);
        assert!(matches!(stream_err, StreamError::WebSocketError(_)));
        assert!(stream_err.to_string().contains("test violation"));
    }

    // ── connection_failed helper ───────────────────────────────────────

    #[test]
    fn connection_failed_helper() {
        let err = connection_failed("test failure");
        assert!(matches!(err, StreamError::ConnectionFailed(ref s) if s == "test failure"));
    }

    // ── WsMessage roundtrips: ping/pong ────────────────────────────────

    #[test]
    fn ws_message_roundtrip_ping() {
        let original = WsMessage::Ping(vec![1, 2, 3]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_pong() {
        let original = WsMessage::Pong(vec![4, 5, 6]);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn ws_message_roundtrip_close_none() {
        let original = WsMessage::Close(None);
        let message: Message = original.clone().into();
        let roundtrip: WsMessage = message.into();
        assert_eq!(roundtrip, original);
    }

    // ── WsClient clone ────────────────────────────────────────────────

    #[test]
    fn ws_client_clone() {
        let client = WsClient::new("ws://localhost:8080");
        let cloned = client.clone();
        assert_eq!(client.url(), cloned.url());
    }
}
