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
                    "SERVER_ERROR" | "SERVICE_UNAVAILABLE" | "REQUEST_TIMEOUT" | "GATEWAY_TIMEOUT"
                )
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

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    // ── Display messages ────────────────────────────────────────

    #[test]
    fn display_api_error() {
        let err = AirtableError::Api {
            error_type: "INVALID_REQUEST".into(),
            message: "Bad field".into(),
            status_code: Some(422),
        };
        assert_eq!(
            err.to_string(),
            "Airtable API error: INVALID_REQUEST - Bad field"
        );
    }

    #[test]
    fn display_rate_limited() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 30,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 30s");
    }

    #[test]
    fn display_unauthorized() {
        let err = AirtableError::Unauthorized;
        assert_eq!(err.to_string(), "Invalid or expired Airtable token");
    }

    #[test]
    fn display_base_not_found() {
        let err = AirtableError::BaseNotFound {
            base_id: "app123".into(),
        };
        assert_eq!(err.to_string(), "Base not found: app123");
    }

    #[test]
    fn display_record_not_found() {
        let err = AirtableError::RecordNotFound {
            record_id: "rec456".into(),
        };
        assert_eq!(err.to_string(), "Record not found: rec456");
    }

    #[test]
    fn display_table_not_found() {
        let err = AirtableError::TableNotFound {
            table_id: "tblABC".into(),
        };
        assert_eq!(err.to_string(), "Table not found: tblABC");
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AirtableError::Json(json_err);
        assert!(err.to_string().starts_with("JSON error:"));
    }

    // ── is_retryable ─────────────────────────────────────────────

    #[test]
    fn rate_limited_is_retryable() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 5,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn server_error_api_is_retryable() {
        for error_type in [
            "SERVER_ERROR",
            "SERVICE_UNAVAILABLE",
            "REQUEST_TIMEOUT",
            "GATEWAY_TIMEOUT",
        ] {
            let err = AirtableError::Api {
                error_type: error_type.into(),
                message: "oops".into(),
                status_code: Some(500),
            };
            assert!(err.is_retryable(), "{error_type} should be retryable");
        }
    }

    #[test]
    fn client_error_api_not_retryable() {
        for error_type in [
            "INVALID_REQUEST",
            "NOT_FOUND",
            "AUTHENTICATION_REQUIRED",
            "INVALID_API_KEY",
        ] {
            let err = AirtableError::Api {
                error_type: error_type.into(),
                message: "no".into(),
                status_code: Some(400),
            };
            assert!(!err.is_retryable(), "{error_type} should NOT be retryable");
        }
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!AirtableError::Unauthorized.is_retryable());
    }

    #[test]
    fn base_not_found_not_retryable() {
        let err = AirtableError::BaseNotFound {
            base_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn record_not_found_not_retryable() {
        let err = AirtableError::RecordNotFound {
            record_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn table_not_found_not_retryable() {
        let err = AirtableError::TableNotFound {
            table_id: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn json_error_not_retryable() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AirtableError::Json(json_err);
        assert!(!err.is_retryable());
    }

    // ── retry_after ──────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 42,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(42)));
    }

    #[test]
    fn retry_after_zero() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 0,
        };
        assert_eq!(err.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_none_for_other_errors() {
        assert!(AirtableError::Unauthorized.retry_after().is_none());
        let api = AirtableError::Api {
            error_type: "SERVER_ERROR".into(),
            message: "x".into(),
            status_code: Some(500),
        };
        assert!(api.retry_after().is_none());
    }

    // ── to_fcp_error ─────────────────────────────────────────────

    #[test]
    fn to_fcp_error_rate_limited() {
        let err = AirtableError::RateLimited {
            retry_after_secs: 10,
        };
        match err.to_fcp_error() {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 10_000);
                assert!(violation.is_none());
            }
            other => panic!("Expected RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_unauthorized_variant() {
        match AirtableError::Unauthorized.to_fcp_error() {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("Airtable"));
            }
            other => panic!("Expected Unauthorized, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_auth_required() {
        let err = AirtableError::Api {
            error_type: "AUTHENTICATION_REQUIRED".into(),
            message: "need auth".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_invalid_key() {
        let err = AirtableError::Api {
            error_type: "INVALID_API_KEY".into(),
            message: "bad key".into(),
            status_code: Some(401),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_403_status() {
        let err = AirtableError::Api {
            error_type: "FORBIDDEN".into(),
            message: "denied".into(),
            status_code: Some(403),
        };
        assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
    }

    #[test]
    fn to_fcp_error_api_not_found() {
        let err = AirtableError::Api {
            error_type: "NOT_FOUND".into(),
            message: "record xyz".into(),
            status_code: Some(404),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "record xyz");
            }
            other => panic!("Expected ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_404_status_non_not_found_type() {
        let err = AirtableError::Api {
            error_type: "UNKNOWN_ERROR".into(),
            message: "gone".into(),
            status_code: Some(404),
        };
        assert!(matches!(
            err.to_fcp_error(),
            FcpError::ResourceNotFound { .. }
        ));
    }

    #[test]
    fn to_fcp_error_api_server_error_retryable() {
        let err = AirtableError::Api {
            error_type: "SERVER_ERROR".into(),
            message: "internal".into(),
            status_code: Some(500),
        };
        match err.to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(service, "airtable");
                assert!(retryable);
                assert!(retry_after.is_none());
            }
            other => panic!("Expected External, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_api_client_error_not_retryable() {
        let err = AirtableError::Api {
            error_type: "INVALID_REQUEST".into(),
            message: "bad".into(),
            status_code: Some(422),
        };
        match err.to_fcp_error() {
            FcpError::External {
                retryable,
                status_code,
                ..
            } => {
                assert!(!retryable);
                assert_eq!(status_code, Some(422));
            }
            other => panic!("Expected External, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_base_not_found() {
        let err = AirtableError::BaseNotFound {
            base_id: "appXYZ".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "base:appXYZ");
            }
            other => panic!("Expected ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_record_not_found() {
        let err = AirtableError::RecordNotFound {
            record_id: "rec123".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "record:rec123");
            }
            other => panic!("Expected ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_table_not_found() {
        let err = AirtableError::TableNotFound {
            table_id: "tblABC".into(),
        };
        match err.to_fcp_error() {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "table:tblABC");
            }
            other => panic!("Expected ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn to_fcp_error_json() {
        let json_err = serde_json::from_str::<i32>("nope").unwrap_err();
        let err = AirtableError::Json(json_err);
        match err.to_fcp_error() {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"));
            }
            other => panic!("Expected Internal, got: {other:?}"),
        }
    }

    // ── Debug format ─────────────────────────────────────────────

    #[test]
    fn debug_format_contains_variant_name() {
        let err = AirtableError::Unauthorized;
        assert!(format!("{err:?}").contains("Unauthorized"));

        let err = AirtableError::RateLimited {
            retry_after_secs: 5,
        };
        assert!(format!("{err:?}").contains("RateLimited"));

        let err = AirtableError::BaseNotFound {
            base_id: "x".into(),
        };
        assert!(format!("{err:?}").contains("BaseNotFound"));
    }

    // ── std::error::Error trait ──────────────────────────────────

    #[test]
    fn implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AirtableError::Unauthorized);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn json_error_source_chain() {
        let json_err = serde_json::from_str::<i32>("bad").unwrap_err();
        let err = AirtableError::Json(json_err);
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_some());
    }

    // ── Api error with no status code ────────────────────────────

    #[test]
    fn api_error_no_status_code() {
        let err = AirtableError::Api {
            error_type: "SERVER_ERROR".into(),
            message: "oops".into(),
            status_code: None,
        };
        match err.to_fcp_error() {
            FcpError::External { status_code, .. } => {
                assert!(status_code.is_none());
            }
            other => panic!("Expected External, got: {other:?}"),
        }
    }

    // ── Result type alias ────────────────────────────────────────

    #[test]
    fn result_type_alias_compiles() {
        let ok: AirtableResult<u32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: AirtableResult<u32> = Err(AirtableError::Unauthorized);
        assert!(err.is_err());
    }
}
