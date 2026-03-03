//! Slack-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// Slack-specific errors.
#[derive(Error, Debug)]
pub enum SlackError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Slack API returned an error
    #[error("Slack API error: {error} (code: {code:?})")]
    Api {
        error: String,
        code: Option<String>,
        ok: bool,
    },

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired Slack token")]
    Unauthorized,

    /// Channel not found
    #[error("Channel not found: {channel}")]
    ChannelNotFound { channel: String },

    /// User not found
    #[error("User not found: {user}")]
    UserNotFound { user: String },
}

impl SlackError {
    /// Check if this error is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) | Self::RateLimited { .. } => true,
            Self::Api { error, .. } => {
                // Slack transient errors
                matches!(
                    error.as_str(),
                    "internal_error" | "request_timeout" | "service_unavailable" | "fatal_error"
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
                service: "slack".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api { error, .. } => {
                if error == "not_authed" || error == "invalid_auth" || error == "token_revoked" {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient Slack token".into(),
                    }
                } else if error == "ratelimited" {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else if error == "missing_scope"
                    || error == "not_in_channel"
                    || error == "restricted_action"
                    || error == "ekm_access_denied"
                    || error == "access_denied"
                {
                    FcpError::CapabilityDenied {
                        capability: "slack".into(),
                        reason: format!("Slack permission error: {error}"),
                    }
                } else if error == "channel_not_found" {
                    FcpError::ResourceNotFound {
                        resource: "channel".into(),
                    }
                } else if error == "user_not_found" {
                    FcpError::ResourceNotFound {
                        resource: "user".into(),
                    }
                } else {
                    FcpError::External {
                        service: "slack".into(),
                        message: error.clone(),
                        status_code: None,
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
                message: "Invalid or expired Slack token".into(),
            },
            Self::ChannelNotFound { channel } => FcpError::ResourceNotFound {
                resource: format!("channel:{channel}"),
            },
            Self::UserNotFound { user } => FcpError::ResourceNotFound {
                resource: format!("user:{user}"),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for Slack operations.
pub type SlackResult<T> = Result<T, SlackError>;

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::FcpError;

    #[test]
    fn test_not_authed_maps_to_unauthorized() {
        let err = SlackError::Api {
            error: "not_authed".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_invalid_auth_maps_to_unauthorized() {
        let err = SlackError::Api {
            error: "invalid_auth".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_token_revoked_maps_to_unauthorized() {
        let err = SlackError::Api {
            error: "token_revoked".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_ratelimited_api_maps_to_rate_limited() {
        let err = SlackError::Api {
            error: "ratelimited".into(),
            code: None,
            ok: false,
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
    fn test_missing_scope_maps_to_capability_denied() {
        let err = SlackError::Api {
            error: "missing_scope".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::CapabilityDenied { .. }));
    }

    #[test]
    fn test_permission_errors_map_to_capability_denied() {
        for error_str in &[
            "not_in_channel",
            "restricted_action",
            "ekm_access_denied",
            "access_denied",
        ] {
            let err = SlackError::Api {
                error: (*error_str).into(),
                code: None,
                ok: false,
            };
            let fcp = err.to_fcp_error();
            assert!(
                matches!(fcp, FcpError::CapabilityDenied { .. }),
                "{error_str} should map to CapabilityDenied"
            );
        }
    }

    #[test]
    fn test_channel_not_found_api_maps_to_resource_not_found() {
        let err = SlackError::Api {
            error: "channel_not_found".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { resource } if resource == "channel"));
    }

    #[test]
    fn test_user_not_found_api_maps_to_resource_not_found() {
        let err = SlackError::Api {
            error: "user_not_found".into(),
            code: None,
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::ResourceNotFound { resource } if resource == "user"));
    }

    #[test]
    fn test_unknown_api_error_maps_to_external() {
        let err = SlackError::Api {
            error: "some_unknown_error".into(),
            code: Some("42".into()),
            ok: false,
        };
        let fcp = err.to_fcp_error();
        assert!(matches!(
            fcp,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn test_rate_limited_variant_maps_with_correct_ms() {
        let err = SlackError::RateLimited {
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
    fn test_unauthorized_variant_maps_to_fcp_unauthorized() {
        let err = SlackError::Unauthorized;
        let fcp = err.to_fcp_error();
        assert!(matches!(fcp, FcpError::Unauthorized { code: 2001, .. }));
    }

    #[test]
    fn test_channel_not_found_variant_maps_to_resource_not_found() {
        let err = SlackError::ChannelNotFound {
            channel: "C12345".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("C12345"))
        );
    }

    #[test]
    fn test_user_not_found_variant_maps_to_resource_not_found() {
        let err = SlackError::UserNotFound {
            user: "U98765".into(),
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::ResourceNotFound { resource } if resource.contains("U98765"))
        );
    }

    #[test]
    fn test_json_error_maps_to_internal() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = SlackError::Json(json_err);
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::Internal { message } if message.contains("JSON error"))
        );
    }

    #[test]
    fn test_retryable_checks() {
        // Retryable
        assert!(SlackError::RateLimited { retry_after_secs: 1 }.is_retryable());
        for error_str in &[
            "internal_error",
            "request_timeout",
            "service_unavailable",
            "fatal_error",
        ] {
            assert!(
                SlackError::Api {
                    error: (*error_str).into(),
                    code: None,
                    ok: false,
                }
                .is_retryable(),
                "{error_str} should be retryable"
            );
        }

        // Not retryable
        assert!(!SlackError::Unauthorized.is_retryable());
        assert!(!SlackError::ChannelNotFound {
            channel: "x".into()
        }
        .is_retryable());
        assert!(!SlackError::UserNotFound { user: "x".into() }.is_retryable());
        assert!(!SlackError::Api {
            error: "not_authed".into(),
            code: None,
            ok: false,
        }
        .is_retryable());
        assert!(!SlackError::Api {
            error: "channel_not_found".into(),
            code: None,
            ok: false,
        }
        .is_retryable());
    }

    #[test]
    fn test_retry_after_extraction() {
        assert_eq!(
            SlackError::RateLimited {
                retry_after_secs: 60
            }
            .retry_after()
            .map(|d| d.as_secs()),
            Some(60)
        );
        assert!(SlackError::Unauthorized.retry_after().is_none());
        assert!(SlackError::ChannelNotFound {
            channel: "x".into()
        }
        .retry_after()
        .is_none());
        assert!(SlackError::Api {
            error: "internal_error".into(),
            code: None,
            ok: false,
        }
        .retry_after()
        .is_none());
    }

    #[test]
    fn test_transient_api_errors_are_retryable_external() {
        for error_str in &["internal_error", "service_unavailable"] {
            let err = SlackError::Api {
                error: (*error_str).into(),
                code: None,
                ok: false,
            };
            assert!(err.is_retryable(), "{error_str} should be retryable");
            let fcp = err.to_fcp_error();
            assert!(
                matches!(fcp, FcpError::External { retryable: true, .. }),
                "{error_str} should map to retryable External"
            );
        }
    }
}
