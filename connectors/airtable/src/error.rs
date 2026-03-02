//! Airtable-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Airtable-specific errors.
#[derive(Error, Debug)]
pub enum AirtableError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Airtable API returned an error
    #[error("Airtable API error: {error_type} - {message}")]
    Api {
        error_type: String,
        message: String,
        status_code: Option<u16>,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Airtable token")]
    Unauthorized,

    /// Base not found
    #[error("Base not found: {base_id}")]
    BaseNotFound { base_id: String },

    /// Record not found
    #[error("Record not found: {record_id}")]
    RecordNotFound { record_id: String },

    /// Table not found
    #[error("Table not found: {table_id}")]
    TableNotFound { table_id: String },
}

impl AirtableError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { error_type, .. } => {
                matches!(
                    error_type.as_str(),
                    "SERVER_ERROR"
                        | "SERVICE_UNAVAILABLE"
                        | "REQUEST_TIMEOUT"
                        | "GATEWAY_TIMEOUT"
                )
            }
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => {
                Some(Duration::from_secs(*retry_after_secs))
            }
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "airtable".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                error_type,
                message,
                status_code,
            } => {
                if error_type == "AUTHENTICATION_REQUIRED"
                    || error_type == "INVALID_API_KEY"
                    || *status_code == Some(401)
                    || *status_code == Some(403)
                {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Airtable token".into(),
                    }
                } else if error_type == "NOT_FOUND" || *status_code == Some(404) {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "airtable".into(),
                        message: format!("{error_type}: {message}"),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_secs } => FcpError::RateLimited {
                retry_after_ms: retry_after_secs * 1000,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired Airtable token".into(),
            },
            Self::BaseNotFound { base_id } => FcpError::ResourceNotFound {
                resource: format!("base:{base_id}"),
            },
            Self::RecordNotFound { record_id } => FcpError::ResourceNotFound {
                resource: format!("record:{record_id}"),
            },
            Self::TableNotFound { table_id } => FcpError::ResourceNotFound {
                resource: format!("table:{table_id}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Airtable operations.
pub type AirtableResult<T> = Result<T, AirtableError>;
