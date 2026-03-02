//! Google Calendar-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Google Calendar-specific errors.
#[derive(Error, Debug)]
pub enum GoogleCalendarError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Google Calendar API returned an error
    #[error("Google Calendar API error: {message} (code: {code})")]
    Api { code: u32, message: String },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Google Calendar credentials")]
    Unauthorized,

    /// Event not found
    #[error("Event not found: {event_id}")]
    EventNotFound { event_id: String },

    /// Calendar not found
    #[error("Calendar not found: {calendar_id}")]
    CalendarNotFound { calendar_id: String },
}

impl GoogleCalendarError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { code, .. } => {
                matches!(code, 429 | 500 | 502 | 503)
            }
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_secs } => Some(Duration::from_secs(*retry_after_secs)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "google-calendar".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { code, message } => {
                if *code == 401 {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Google Calendar credentials".into(),
                    }
                } else if *code == 429 {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if *code == 404 {
                    FcpError::ResourceNotFound {
                        resource: message.clone(),
                    }
                } else {
                    FcpError::External {
                        service: "google-calendar".into(),
                        message: message.clone(),
                        status_code: Some((*code).try_into().unwrap_or(500)),
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
                message: "Invalid or expired Google Calendar credentials".into(),
            },
            Self::EventNotFound { event_id } => FcpError::ResourceNotFound {
                resource: format!("event:{event_id}"),
            },
            Self::CalendarNotFound { calendar_id } => FcpError::ResourceNotFound {
                resource: format!("calendar:{calendar_id}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Google Calendar operations.
pub type GCalResult<T> = Result<T, GoogleCalendarError>;
