//! Webhook Receiver error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for Webhook Receiver operations.
pub type WebhookReceiverResult<T> = Result<T, WebhookReceiverError>;

/// Webhook Receiver errors.
#[derive(Error, Debug)]
pub enum WebhookReceiverError {
    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Endpoint not found
    #[error("Endpoint not found: {endpoint_id}")]
    EndpointNotFound { endpoint_id: String },

    /// Duplicate endpoint path
    #[error("Endpoint path already registered: {path}")]
    DuplicatePath { path: String },

    /// Invalid input
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// Store capacity exceeded
    #[error("Store capacity exceeded: {message}")]
    CapacityExceeded { message: String },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl WebhookReceiverError {
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::CapacityExceeded { .. } => true,
            Self::EndpointNotFound { .. }
            | Self::DuplicatePath { .. }
            | Self::InvalidInput { .. }
            | Self::Json(_)
            | Self::Internal { .. } => false,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::CapacityExceeded { .. } => Some(Duration::from_secs(5)),
            _ => None,
        }
    }

    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
            Self::EndpointNotFound { endpoint_id } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Endpoint not found: {endpoint_id}"),
                status_code: Some(404),
                retryable: false,
                retry_after: None,
            },
            Self::DuplicatePath { path } => FcpError::External {
                service: "webhook-receiver".into(),
                message: format!("Endpoint path already registered: {path}"),
                status_code: Some(409),
                retryable: false,
                retry_after: None,
            },
            Self::InvalidInput { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(400),
                retryable: false,
                retry_after: None,
            },
            Self::CapacityExceeded { message } => FcpError::External {
                service: "webhook-receiver".into(),
                message: message.clone(),
                status_code: Some(429),
                retryable: true,
                retry_after: self.retry_after(),
            },
            Self::Internal { message } => FcpError::Internal {
                message: message.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_not_found_not_retryable() {
        assert!(
            !WebhookReceiverError::EndpointNotFound { endpoint_id: "ep_1".into() }.is_retryable()
        );
    }

    #[test]
    fn duplicate_path_not_retryable() {
        assert!(
            !WebhookReceiverError::DuplicatePath { path: "/hooks/test".into() }.is_retryable()
        );
    }

    #[test]
    fn invalid_input_not_retryable() {
        assert!(!WebhookReceiverError::InvalidInput { message: "bad".into() }.is_retryable());
    }

    #[test]
    fn capacity_exceeded_is_retryable() {
        assert!(
            WebhookReceiverError::CapacityExceeded { message: "full".into() }.is_retryable()
        );
    }

    #[test]
    fn internal_not_retryable() {
        assert!(!WebhookReceiverError::Internal { message: "err".into() }.is_retryable());
    }

    #[test]
    fn retry_after_for_capacity_exceeded() {
        let err = WebhookReceiverError::CapacityExceeded { message: "full".into() };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_none_for_not_found() {
        let err = WebhookReceiverError::EndpointNotFound { endpoint_id: "ep_1".into() };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_duplicate_path() {
        let err = WebhookReceiverError::DuplicatePath { path: "/x".into() };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_invalid_input() {
        let err = WebhookReceiverError::InvalidInput { message: "bad".into() };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_internal() {
        let err = WebhookReceiverError::Internal { message: "err".into() };
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn endpoint_not_found_to_fcp_error() {
        match (WebhookReceiverError::EndpointNotFound { endpoint_id: "ep_abc".into() })
            .to_fcp_error()
        {
            FcpError::External { service, status_code, retryable, message, .. } => {
                assert_eq!(service, "webhook-receiver");
                assert_eq!(status_code, Some(404));
                assert!(!retryable);
                assert!(message.contains("ep_abc"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_path_to_fcp_error() {
        match (WebhookReceiverError::DuplicatePath { path: "/hooks/github".into() }).to_fcp_error()
        {
            FcpError::External { service, status_code, retryable, message, .. } => {
                assert_eq!(service, "webhook-receiver");
                assert_eq!(status_code, Some(409));
                assert!(!retryable);
                assert!(message.contains("/hooks/github"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn invalid_input_to_fcp_error() {
        match (WebhookReceiverError::InvalidInput { message: "missing field".into() })
            .to_fcp_error()
        {
            FcpError::External { status_code, retryable, message, .. } => {
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
                assert_eq!(message, "missing field");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn capacity_exceeded_to_fcp_error() {
        match (WebhookReceiverError::CapacityExceeded { message: "too many".into() })
            .to_fcp_error()
        {
            FcpError::External { status_code, retryable, retry_after, message, .. } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
                assert_eq!(message, "too many");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn internal_to_fcp_error() {
        match (WebhookReceiverError::Internal { message: "boom".into() }).to_fcp_error() {
            FcpError::Internal { message } => assert_eq!(message, "boom"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match WebhookReceiverError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn error_display_endpoint_not_found() {
        assert_eq!(
            WebhookReceiverError::EndpointNotFound { endpoint_id: "ep_1".into() }.to_string(),
            "Endpoint not found: ep_1"
        );
    }

    #[test]
    fn error_display_duplicate_path() {
        assert_eq!(
            WebhookReceiverError::DuplicatePath { path: "/hooks/test".into() }.to_string(),
            "Endpoint path already registered: /hooks/test"
        );
    }

    #[test]
    fn error_display_invalid_input() {
        assert_eq!(
            WebhookReceiverError::InvalidInput { message: "bad data".into() }.to_string(),
            "Invalid input: bad data"
        );
    }

    #[test]
    fn error_display_capacity_exceeded() {
        assert_eq!(
            WebhookReceiverError::CapacityExceeded { message: "store full".into() }.to_string(),
            "Store capacity exceeded: store full"
        );
    }

    #[test]
    fn error_display_internal() {
        assert_eq!(
            WebhookReceiverError::Internal { message: "something broke".into() }.to_string(),
            "Internal error: something broke"
        );
    }

    #[test]
    fn json_error_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = WebhookReceiverError::Json(bad.unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_retry_after_none() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let err = WebhookReceiverError::Json(bad.unwrap_err());
        assert_eq!(err.retry_after(), None);
    }
}
