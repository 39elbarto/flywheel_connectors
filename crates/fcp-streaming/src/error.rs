//! Streaming error types.

use std::time::Duration;

use asupersync::http::h1::{ClientError as HttpClientError, HttpError};

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
    HttpClientError(#[from] HttpClientError),

    /// HTTP protocol/body error.
    #[error("HTTP protocol error: {0}")]
    HttpProtocolError(#[from] HttpError),
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

    // ── std::error::Error trait tests ──

    #[test]
    fn connection_failed_is_std_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(StreamError::ConnectionFailed("refused".into()));
        assert!(e.to_string().contains("refused"));
    }

    #[test]
    fn io_error_source_is_inner() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let stream_err = StreamError::IoError(io_err);
        let source = std::error::Error::source(&stream_err);
        assert!(source.is_some(), "IoError variant should expose source");
    }

    #[test]
    fn connection_failed_source_is_none() {
        let e = StreamError::ConnectionFailed("no source".into());
        let source = std::error::Error::source(&e);
        assert!(source.is_none());
    }

    // ── Debug tests ──

    #[test]
    fn connection_failed_debug() {
        let e = StreamError::ConnectionFailed("refused".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("ConnectionFailed"));
    }

    #[test]
    fn connection_closed_debug() {
        let e = StreamError::ConnectionClosed {
            reason: "gone".into(),
            code: Some(1001),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("ConnectionClosed"));
        assert!(debug.contains("1001"));
    }

    #[test]
    fn http_error_debug() {
        let e = StreamError::HttpError {
            status: 503,
            message: "Service Unavailable".into(),
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("503"));
    }

    #[test]
    fn timeout_debug() {
        let e = StreamError::Timeout(Duration::from_millis(2500));
        let debug = format!("{e:?}");
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn buffer_overflow_debug() {
        let e = StreamError::BufferOverflow {
            size: 4096,
            limit: 2048,
        };
        let debug = format!("{e:?}");
        assert!(debug.contains("4096"));
        assert!(debug.contains("2048"));
    }

    #[test]
    fn reconnect_limit_debug() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 5 };
        let debug = format!("{e:?}");
        assert!(debug.contains('5'));
    }

    #[test]
    fn websocket_error_debug() {
        let e = StreamError::WebSocketError("protocol".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("WebSocketError"));
    }

    #[test]
    fn sse_error_debug() {
        let e = StreamError::SseError("invalid".into());
        let debug = format!("{e:?}");
        assert!(debug.contains("SseError"));
    }

    #[test]
    fn io_error_debug() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let e = StreamError::IoError(io_err);
        let debug = format!("{e:?}");
        assert!(debug.contains("IoError"));
    }

    // ── Display boundary tests ──

    #[test]
    fn connection_closed_empty_reason() {
        let e = StreamError::ConnectionClosed {
            reason: String::new(),
            code: None,
        };
        assert_eq!(e.to_string(), "Connection closed: ");
    }

    #[test]
    fn http_error_boundary_status() {
        let e = StreamError::HttpError {
            status: 0,
            message: "zero".into(),
        };
        assert_eq!(e.to_string(), "HTTP error: 0 - zero");
    }

    #[test]
    fn timeout_zero_duration() {
        let e = StreamError::Timeout(Duration::ZERO);
        let display = e.to_string();
        assert!(display.contains('0'));
    }

    #[test]
    fn buffer_overflow_equal_size_and_limit() {
        let e = StreamError::BufferOverflow {
            size: 1024,
            limit: 1024,
        };
        assert!(e.to_string().contains("1024"));
    }

    #[test]
    fn reconnect_zero_attempts() {
        let e = StreamError::ReconnectLimitExceeded { attempts: 0 };
        assert!(e.to_string().contains("0 attempts"));
    }

    #[test]
    fn parse_error_empty_message() {
        let e = StreamError::ParseError(String::new());
        assert_eq!(e.to_string(), "Parse error: ");
    }

    #[test]
    fn invalid_state_empty_message() {
        let e = StreamError::InvalidState(String::new());
        assert_eq!(e.to_string(), "Invalid state: ");
    }
}
