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

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    #[test]
    fn test_api_401_maps_to_unauthorized() {
        let err = GoogleCalendarError::Api {
            code: 401,
            message: "bad token".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_api_404_maps_to_resource_not_found() {
        let err = GoogleCalendarError::Api {
            code: 404,
            message: "calendar not found".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
    }

    #[test]
    fn test_api_429_maps_to_rate_limited() {
        let err = GoogleCalendarError::Api {
            code: 429,
            message: "rate limited".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                ..
            }
        ));
    }

    #[test]
    fn test_api_500_maps_to_external() {
        let err = GoogleCalendarError::Api {
            code: 500,
            message: "server error".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn test_rate_limited_maps_with_correct_ms() {
        let err = GoogleCalendarError::RateLimited {
            retry_after_secs: 30,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                violation: None
            }
        ));
    }

    #[test]
    fn test_unauthorized_maps_to_fcp_unauthorized() {
        let err = GoogleCalendarError::Unauthorized;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_event_not_found_maps_to_resource_not_found() {
        let err = GoogleCalendarError::EventNotFound {
            event_id: "evt123".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("evt123"))
        );
    }

    #[test]
    fn test_calendar_not_found_maps_to_resource_not_found() {
        let err = GoogleCalendarError::CalendarNotFound {
            calendar_id: "cal456".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("cal456"))
        );
    }

    #[test]
    fn test_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = GoogleCalendarError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Internal { message } if message.contains("JSON error")));
    }

    #[test]
    fn test_retryable_checks() {
        // Retryable
        assert!(
            GoogleCalendarError::RateLimited {
                retry_after_secs: 1
            }
            .is_retryable()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 429,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 500,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 502,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 503,
                message: String::new()
            }
            .is_retryable()
        );

        // Not retryable
        assert!(!GoogleCalendarError::Unauthorized.is_retryable());
        assert!(
            !GoogleCalendarError::EventNotFound {
                event_id: "x".into()
            }
            .is_retryable()
        );
        assert!(
            !GoogleCalendarError::CalendarNotFound {
                calendar_id: "x".into()
            }
            .is_retryable()
        );
        assert!(
            !GoogleCalendarError::Api {
                code: 401,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(
            !GoogleCalendarError::Api {
                code: 403,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(
            !GoogleCalendarError::Api {
                code: 404,
                message: String::new()
            }
            .is_retryable()
        );
    }

    #[test]
    fn test_retry_after_extraction() {
        assert_eq!(
            GoogleCalendarError::RateLimited {
                retry_after_secs: 60
            }
            .retry_after()
            .map(|d| d.as_secs()),
            Some(60)
        );
        assert!(GoogleCalendarError::Unauthorized.retry_after().is_none());
        assert!(
            GoogleCalendarError::EventNotFound {
                event_id: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GoogleCalendarError::Api {
                code: 429,
                message: String::new()
            }
            .retry_after()
            .is_none()
        );
    }

    #[test]
    fn test_api_502_503_are_retryable_external() {
        for code in [502, 503] {
            let err = GoogleCalendarError::Api {
                code,
                message: format!("error {code}"),
            };
            assert!(err.is_retryable(), "API {code} should be retryable");
            let fcp = err.to_fcp_error();
            assert!(
                matches!(
                    fcp,
                    FcpError::External {
                        retryable: true,
                        ..
                    }
                ),
                "API {code} should map to retryable External"
            );
        }
    }
}
