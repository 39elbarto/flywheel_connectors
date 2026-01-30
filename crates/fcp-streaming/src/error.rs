//! Streaming error types.

use std::time::Duration;

/// Streaming errors.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection closed unexpectedly.
    #[error("Connection closed: {reason}")]
    ConnectionClosed {
        /// Close reason.
        reason: String,
        /// Close code (for WebSocket).
        code: Option<u16>,
    },

    /// HTTP error.
    #[error("HTTP error: {status} - {message}")]
    HttpError {
        /// HTTP status code.
        status: u16,
        /// Error message.
        message: String,
    },

    /// Parse error.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Timeout.
    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    /// Reconnection limit exceeded.
    #[error("Reconnection limit exceeded after {attempts} attempts")]
    ReconnectLimitExceeded {
        /// Number of reconnection attempts.
        attempts: u32,
    },

    /// Buffer overflow.
    #[error("Buffer overflow: {size} bytes exceeds limit of {limit}")]
    BufferOverflow {
        /// Current size.
        size: usize,
        /// Maximum allowed size.
        limit: usize,
    },

    /// Invalid state.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// WebSocket error.
    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    /// SSE error.
    #[error("SSE error: {0}")]
    SseError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP client error.
    #[error("HTTP client error: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

/// Result type for streaming operations.
pub type StreamResult<T> = Result<T, StreamError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_display() {
        let e = StreamError::ConnectionFailed("refused".into());
        assert_eq!(e.to_string(), "Connection failed: refused");
    }

    #[test]
    fn connection_closed_display() {
        let e = StreamError::ConnectionClosed {
            reason: "gone".into(),
            code: Some(1001),
        };
        assert_eq!(e.to_string(), "Connection closed: gone");
    }

    #[test]
    fn connection_closed_without_code() {
        let e = StreamError::ConnectionClosed {
            reason: "eof".into(),
            code: None,
        };
        assert_eq!(e.to_string(), "Connection closed: eof");
    }

    #[test]
    fn http_error_display() {
        let e = StreamError::HttpError {
            status: 404,
            message: "Not Found".into(),
        };
        assert_eq!(e.to_string(), "HTTP error: 404 - Not Found");
    }

    #[test]
    fn parse_error_display() {
        let e = StreamError::ParseError("bad json".into());
        assert_eq!(e.to_string(), "Parse error: bad json");
    }

    #[test]
    fn timeout_display() {
        let e = StreamError::Timeout(Duration::from_secs(5));
        assert_eq!(e.to_string(), "Timeout after 5s");
    }

    #[test]
    fn reconnect_limit_exceeded_display() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 10 };
        assert_eq!(
            e.to_string(),
            "Reconnection limit exceeded after 10 attempts"
        );
    }

    #[test]
    fn buffer_overflow_display() {
        let e = StreamError::BufferOverflow {
            size: 2048,
            limit: 1024,
        };
        assert_eq!(
            e.to_string(),
            "Buffer overflow: 2048 bytes exceeds limit of 1024"
        );
    }

    #[test]
    fn invalid_state_display() {
        let e = StreamError::InvalidState("closed".into());
        assert_eq!(e.to_string(), "Invalid state: closed");
    }

    #[test]
    fn websocket_error_display() {
        let e = StreamError::WebSocketError("protocol error".into());
        assert_eq!(e.to_string(), "WebSocket error: protocol error");
    }

    #[test]
    fn sse_error_display() {
        let e = StreamError::SseError("invalid event".into());
        assert_eq!(e.to_string(), "SSE error: invalid event");
    }

    #[test]
    fn io_error_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let stream_err: StreamError = io_err.into();
        assert!(matches!(stream_err, StreamError::IoError(_)));
        assert!(stream_err.to_string().contains("broken"));
    }
}
