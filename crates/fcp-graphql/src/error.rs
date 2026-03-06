//! Error types for the GraphQL client.

use std::time::Duration;

use asupersync::http::h1::{ClientError as HttpClientError, StatusCode};
use fcp_core::FcpError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// HTTP error information captured from the transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpErrorInfo {
    /// Error message.
    pub message: String,
    /// HTTP status code (if available).
    pub status_code: Option<u16>,
    /// Whether the error was a timeout.
    pub is_timeout: bool,
    /// Whether the error was a connection failure.
    pub is_connect: bool,
    /// Whether the error was a request error.
    pub is_request: bool,
}

impl HttpErrorInfo {
    /// Construct a timeout-shaped HTTP error.
    #[must_use]
    pub fn timeout(timeout: Duration) -> Self {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        Self {
            message: format!("request deadline exceeded after {timeout_ms}ms"),
            status_code: Some(StatusCode::REQUEST_TIMEOUT.as_u16()),
            is_timeout: true,
            is_connect: false,
            is_request: false,
        }
    }

    /// Construct a cancelled request error.
    #[must_use]
    pub fn cancelled() -> Self {
        Self {
            message: "request cancelled".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        }
    }
}

impl From<HttpClientError> for HttpErrorInfo {
    fn from(err: HttpClientError) -> Self {
        match err {
            HttpClientError::InvalidUrl(url) => Self {
                message: format!("invalid URL: {url}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::DnsError(error) => Self {
                message: format!("DNS resolution failed: {error}"),
                status_code: None,
                is_timeout: error.kind() == std::io::ErrorKind::TimedOut,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::ConnectError(error) => Self {
                message: format!("connection failed: {error}"),
                status_code: None,
                is_timeout: error.kind() == std::io::ErrorKind::TimedOut,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::TlsError(error) => Self {
                message: format!("TLS error: {error}"),
                status_code: None,
                is_timeout: false,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::HttpError(error) => Self {
                message: format!("HTTP error: {error}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::TooManyRedirects { count, max } => Self {
                message: format!("too many redirects ({count} of max {max})"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::Io(error) => Self {
                message: format!("I/O error: {error}"),
                status_code: None,
                is_timeout: error.kind() == std::io::ErrorKind::TimedOut,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::ConnectTunnelRefused { status, reason } => Self {
                message: format!("HTTP CONNECT tunnel rejected with status {status} ({reason})"),
                status_code: Some(status),
                is_timeout: false,
                is_connect: true,
                is_request: false,
            },
            HttpClientError::InvalidConnectInput(message) => Self {
                message: format!("invalid CONNECT input: {message}"),
                status_code: None,
                is_timeout: false,
                is_connect: false,
                is_request: false,
            },
            HttpClientError::ProxyError(message) => Self {
                message: format!("proxy error: {message}"),
                status_code: None,
                is_timeout: false,
                is_connect: true,
                is_request: false,
            },
        }
    }
}

/// GraphQL error location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphqlErrorLocation {
    /// Line number in the query (1-based).
    pub line: u32,
    /// Column number in the query (1-based).
    pub column: u32,
}

/// GraphQL path segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GraphqlPathSegment {
    /// Field name.
    Key(String),
    /// Array index.
    Index(i64),
}

/// GraphQL error (per GraphQL spec).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct GraphqlError {
    /// Human-readable error message.
    pub message: String,
    /// Location(s) within the query.
    #[serde(default)]
    pub locations: Vec<GraphqlErrorLocation>,
    /// Path within the response where the error occurred.
    #[serde(default)]
    pub path: Vec<GraphqlPathSegment>,
    /// Extensions metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Error type for GraphQL client operations.
#[derive(Debug, Clone, Error)]
pub enum GraphqlClientError {
    /// HTTP/network error.
    #[error("HTTP error: {0:?}")]
    Http(HttpErrorInfo),

    /// HTTP response status error.
    #[error("HTTP status {status} with body: {body}")]
    HttpStatus {
        /// HTTP status code.
        status: StatusCode,
        /// Response body (truncated if needed).
        body: String,
        /// Retry-After duration when supplied.
        retry_after: Option<Duration>,
    },

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(String),

    /// GraphQL-level errors returned by the server.
    #[error("GraphQL errors: {errors:?}")]
    GraphqlErrors {
        /// GraphQL error list.
        errors: Vec<GraphqlError>,
    },

    /// GraphQL protocol violation.
    #[error("GraphQL protocol error: {message}")]
    Protocol {
        /// Details.
        message: String,
    },

    /// Schema validation error.
    #[error("Schema validation failed: {message}")]
    SchemaValidation {
        /// Summary message.
        message: String,
        /// Individual validation errors.
        errors: Vec<String>,
    },

    /// Retry policy exhausted.
    #[error("Retry policy exhausted after {attempts} attempts")]
    RetriesExhausted {
        /// Attempt count.
        attempts: usize,
    },
}

impl From<HttpClientError> for GraphqlClientError {
    fn from(err: HttpClientError) -> Self {
        Self::Http(HttpErrorInfo::from(err))
    }
}

impl From<serde_json::Error> for GraphqlClientError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

impl GraphqlClientError {
    /// Returns `true` if the error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(info) => info.is_timeout || info.is_connect || info.is_request,
            Self::HttpStatus { status, .. } => {
                status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
            }
            _ => false,
        }
    }

    /// Convert the error to an FCP error for a named service.
    #[must_use]
    pub fn to_fcp_error(&self, service: &str) -> FcpError {
        match self {
            Self::Http(info) => FcpError::External {
                service: service.into(),
                message: info.message.clone(),
                status_code: info.status_code,
                retryable: info.is_timeout || info.is_connect,
                retry_after: None,
            },
            Self::HttpStatus {
                status,
                body,
                retry_after,
            } => {
                if *status == StatusCode::TOO_MANY_REQUESTS {
                    if let Some(duration) = retry_after {
                        let retry_after_ms =
                            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
                        return FcpError::RateLimited {
                            retry_after_ms,
                            violation: None,
                        };
                    }
                    return FcpError::RateLimited {
                        retry_after_ms: 1000,
                        violation: None,
                    };
                }
                if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN {
                    return FcpError::Unauthorized {
                        code: 2001,
                        message: format!("{service} unauthorized: {body}"),
                    };
                }
                FcpError::External {
                    service: service.into(),
                    message: body.clone(),
                    status_code: Some(status.as_u16()),
                    retryable: status.is_server_error(),
                    retry_after: *retry_after,
                }
            }
            Self::Json(message) => FcpError::MalformedFrame {
                code: 2004,
                message: format!("JSON parsing error: {message}"),
            },
            Self::GraphqlErrors { errors } => {
                let message = errors
                    .first()
                    .map_or_else(|| "GraphQL error".to_string(), |err| err.message.clone());
                FcpError::External {
                    service: service.into(),
                    message,
                    status_code: None,
                    retryable: false,
                    retry_after: None,
                }
            }
            Self::Protocol { message } => FcpError::InvalidRequest {
                code: 1002,
                message: message.clone(),
            },
            Self::SchemaValidation { message, .. } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::RetriesExhausted { attempts } => FcpError::External {
                service: service.into(),
                message: format!("Retry policy exhausted after {attempts} attempts"),
                status_code: None,
                retryable: false,
                retry_after: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- HttpErrorInfo ----

    #[test]
    fn http_error_info_serde_roundtrip() {
        let info = HttpErrorInfo {
            message: "connection refused".into(),
            status_code: Some(502),
            is_timeout: false,
            is_connect: true,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn http_error_info_none_status() {
        let info = HttpErrorInfo {
            message: "DNS resolution failed".into(),
            status_code: None,
            is_timeout: false,
            is_connect: true,
            is_request: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"status_code\":null"));
        let back: HttpErrorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_code, None);
    }

    // ---- GraphqlErrorLocation ----

    #[test]
    fn error_location_serde_roundtrip() {
        let loc = GraphqlErrorLocation {
            line: 3,
            column: 12,
        };
        let json = serde_json::to_string(&loc).unwrap();
        let back: GraphqlErrorLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(loc, back);
    }

    // ---- GraphqlPathSegment ----

    #[test]
    fn path_segment_key_serde() {
        let seg = GraphqlPathSegment::Key("user".into());
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, "\"user\"");
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    #[test]
    fn path_segment_index_serde() {
        let seg = GraphqlPathSegment::Index(5);
        let json = serde_json::to_string(&seg).unwrap();
        assert_eq!(json, "5");
        let back: GraphqlPathSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }

    // ---- GraphqlError ----

    #[test]
    fn graphql_error_serde_roundtrip() {
        let err = GraphqlError {
            message: "Not found".into(),
            locations: vec![GraphqlErrorLocation { line: 1, column: 5 }],
            path: vec![
                GraphqlPathSegment::Key("user".into()),
                GraphqlPathSegment::Index(0),
            ],
            extensions: Some(serde_json::json!({"code": "NOT_FOUND"})),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: GraphqlError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn graphql_error_minimal_serde() {
        let json = r#"{"message":"oops"}"#;
        let err: GraphqlError = serde_json::from_str(json).unwrap();
        assert_eq!(err.message, "oops");
        assert!(err.locations.is_empty());
        assert!(err.path.is_empty());
        assert!(err.extensions.is_none());
    }

    // ---- GraphqlClientError Display ----

    #[test]
    fn display_http_error() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "timeout".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        });
        assert!(err.to_string().contains("HTTP error"));
    }

    #[test]
    fn display_http_status_error() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_GATEWAY,
            body: "upstream error".into(),
            retry_after: None,
        };
        let s = err.to_string();
        assert!(s.contains("502"));
        assert!(s.contains("upstream error"));
    }

    #[test]
    fn display_json_error() {
        let err = GraphqlClientError::Json("unexpected token".into());
        assert!(err.to_string().contains("JSON error"));
    }

    #[test]
    fn display_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors {
            errors: vec![GraphqlError {
                message: "syntax error".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
        };
        assert!(err.to_string().contains("GraphQL errors"));
    }

    #[test]
    fn display_protocol_error() {
        let err = GraphqlClientError::Protocol {
            message: "invalid frame".into(),
        };
        assert!(err.to_string().contains("protocol error"));
    }

    #[test]
    fn display_schema_validation_error() {
        let err = GraphqlClientError::SchemaValidation {
            message: "type mismatch".into(),
            errors: vec!["field x is wrong".into()],
        };
        assert!(err.to_string().contains("Schema validation"));
    }

    #[test]
    fn display_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 5 };
        assert!(err.to_string().contains("5 attempts"));
    }

    // ---- is_retryable ----

    #[test]
    fn is_retryable_http_timeout() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "timed out".into(),
            status_code: None,
            is_timeout: true,
            is_connect: false,
            is_request: false,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_http_connect() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "connection refused".into(),
            status_code: None,
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_http_request() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "request error".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: true,
        });
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_http_non_transient() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "decode error".into(),
            status_code: None,
            is_timeout: false,
            is_connect: false,
            is_request: false,
        });
        assert!(!err.is_retryable());
    }

    #[test]
    fn is_retryable_500() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_503() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn is_retryable_429() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_400() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::BAD_REQUEST,
            body: "bad input".into(),
            retry_after: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_json_error() {
        let err = GraphqlClientError::Json("unexpected".into());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors { errors: vec![] };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_protocol() {
        let err = GraphqlClientError::Protocol {
            message: "bad".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_schema_validation() {
        let err = GraphqlClientError::SchemaValidation {
            message: "invalid".into(),
            errors: vec![],
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 3 };
        assert!(!err.is_retryable());
    }

    // ---- to_fcp_error ----

    #[test]
    fn to_fcp_http_error() {
        let err = GraphqlClientError::Http(HttpErrorInfo {
            message: "connection refused".into(),
            status_code: Some(502),
            is_timeout: false,
            is_connect: true,
            is_request: false,
        });
        let fcp = err.to_fcp_error("github");
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "github");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_429_with_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: "slow down".into(),
            retry_after: Some(Duration::from_secs(30)),
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 30_000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_429_without_retry_after() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::TOO_MANY_REQUESTS,
            body: String::new(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::RateLimited { retry_after_ms, .. } => {
                assert_eq!(retry_after_ms, 1000);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_401_unauthorized() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::UNAUTHORIZED,
            body: "bad token".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("github");
        match fcp {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("github unauthorized"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_403_forbidden() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::FORBIDDEN,
            body: "no access".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("gitlab");
        match fcp {
            FcpError::Unauthorized { message, .. } => {
                assert!(message.contains("gitlab unauthorized"));
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_500_server_error() {
        let err = GraphqlClientError::HttpStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "crash".into(),
            retry_after: None,
        };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External {
                service,
                retryable,
                status_code,
                ..
            } => {
                assert_eq!(service, "svc");
                assert!(retryable);
                assert_eq!(status_code, Some(500));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_json_error() {
        let err = GraphqlClientError::Json("bad json".into());
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::MalformedFrame { message, .. } => {
                assert!(message.contains("JSON parsing"));
            }
            other => panic!("expected MalformedFrame, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_graphql_errors() {
        let err = GraphqlClientError::GraphqlErrors {
            errors: vec![GraphqlError {
                message: "field not found".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
        };
        let fcp = err.to_fcp_error("github");
        match fcp {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("field not found"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_graphql_errors_empty() {
        let err = GraphqlClientError::GraphqlErrors { errors: vec![] };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::External { message, .. } => {
                assert_eq!(message, "GraphQL error");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_protocol_error() {
        let err = GraphqlClientError::Protocol {
            message: "bad frame".into(),
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1002);
                assert_eq!(message, "bad frame");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_schema_validation() {
        let err = GraphqlClientError::SchemaValidation {
            message: "type mismatch".into(),
            errors: vec!["field x".into()],
        };
        let fcp = err.to_fcp_error("api");
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "type mismatch");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn to_fcp_retries_exhausted() {
        let err = GraphqlClientError::RetriesExhausted { attempts: 5 };
        let fcp = err.to_fcp_error("svc");
        match fcp {
            FcpError::External {
                message, retryable, ..
            } => {
                assert!(message.contains("5 attempts"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    // ---- From impls ----

    #[test]
    fn from_serde_json_error() {
        let err: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let gql_err: GraphqlClientError = err.unwrap_err().into();
        match gql_err {
            GraphqlClientError::Json(msg) => {
                assert!(!msg.is_empty());
            }
            other => panic!("expected Json, got {other:?}"),
        }
    }
}
