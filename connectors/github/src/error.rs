//! GitHub-specific error types.

use std::time::Duration;

use fcp_core::FcpError;
use thiserror::Error;

/// GitHub-specific errors.
#[derive(Error, Debug)]
pub enum GitHubError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// GitHub API returned an error
    #[error("GitHub API error: {message} (status {status_code:?})")]
    Api {
        message: String,
        status_code: Option<u16>,
        documentation_url: Option<String>,
    },

    /// Rate limited (primary or secondary)
    #[error("Rate limited, retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    /// Invalid or expired token
    #[error("Invalid or expired GitHub token")]
    Unauthorized,

    /// Resource not found (404)
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    /// Validation error (422)
    #[error("Validation error: {message}")]
    ValidationError { message: String },

    /// Merge conflict or not mergeable
    #[error("Merge conflict: {message}")]
    MergeConflict { message: String },
}

impl GitHubError {
    /// Check if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::RateLimited { .. } => true,
            Self::Api { status_code, .. } => matches!(status_code, Some(500..=599 | 429 | 403)),
            _ => false,
        }
    }

    /// Get the suggested retry delay.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after_ms } => Some(Duration::from_millis(*retry_after_ms)),
            _ => None,
        }
    }

    /// Convert to FCP error.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::Http(e) => FcpError::External {
                service: "github".into(),
                message: e.to_string(),
                status_code: e.status().map(|s| s.as_u16()),
                retryable: self.is_retryable(),
                retry_after: self.retry_after(),
            },
            Self::Api {
                message,
                status_code,
                ..
            } => {
                if *status_code == Some(401) || *status_code == Some(403) {
                    FcpError::Unauthorized {
                        code: 2001,
                        message: "Invalid or insufficient GitHub token".into(),
                    }
                } else if *status_code == Some(429) {
                    FcpError::RateLimited {
                        retry_after_ms: 60_000,
                        violation: None,
                    }
                } else {
                    FcpError::External {
                        service: "github".into(),
                        message: message.clone(),
                        status_code: *status_code,
                        retryable: self.is_retryable(),
                        retry_after: self.retry_after(),
                    }
                }
            }
            Self::RateLimited { retry_after_ms } => FcpError::RateLimited {
                retry_after_ms: *retry_after_ms,
                violation: None,
            },
            Self::Unauthorized => FcpError::Unauthorized {
                code: 2001,
                message: "Invalid or expired GitHub token".into(),
            },
            Self::NotFound { resource } => FcpError::ResourceNotFound {
                resource: resource.clone(),
            },
            Self::ValidationError { message } => FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::MergeConflict { message } => FcpError::Conflict {
                message: message.clone(),
            },
            Self::Json(e) => FcpError::Internal {
                message: format!("JSON error: {e}"),
            },
        }
    }
}

/// Result type for GitHub operations.
pub type GitHubResult<T> = Result<T, GitHubError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── Display messages ────────────────────────────────────────────

    #[test]
    fn display_http_error() {
        // We cannot easily construct a reqwest::Error, so test via Json variant
        // which is constructable. Http tested via the From impl path in integration tests.
        let err =
            GitHubError::Json(serde_json::from_str::<serde_json::Value>("{{bad").unwrap_err());
        let msg = err.to_string();
        assert!(msg.starts_with("JSON error:"), "got: {msg}");
    }

    #[test]
    fn display_api_error_with_status() {
        let err = GitHubError::Api {
            message: "Bad credentials".into(),
            status_code: Some(401),
            documentation_url: Some("https://docs.github.com/".into()),
        };
        let msg = err.to_string();
        assert!(msg.contains("Bad credentials"), "got: {msg}");
        assert!(
            msg.contains("401"),
            "should contain status code, got: {msg}"
        );
    }

    #[test]
    fn display_api_error_without_status() {
        let err = GitHubError::Api {
            message: "Server error".into(),
            status_code: None,
            documentation_url: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("Server error"), "got: {msg}");
        assert!(
            msg.contains("None"),
            "status_code None should appear, got: {msg}"
        );
    }

    #[test]
    fn display_rate_limited() {
        let err = GitHubError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.to_string(), "Rate limited, retry after 5000ms");
    }

    #[test]
    fn display_unauthorized() {
        let err = GitHubError::Unauthorized;
        assert_eq!(err.to_string(), "Invalid or expired GitHub token");
    }

    #[test]
    fn display_not_found() {
        let err = GitHubError::NotFound {
            resource: "repos/octocat/missing".into(),
        };
        assert_eq!(err.to_string(), "Resource not found: repos/octocat/missing");
    }

    #[test]
    fn display_validation_error() {
        let err = GitHubError::ValidationError {
            message: "Title is required".into(),
        };
        assert_eq!(err.to_string(), "Validation error: Title is required");
    }

    #[test]
    fn display_merge_conflict() {
        let err = GitHubError::MergeConflict {
            message: "Head branch was modified".into(),
        };
        assert_eq!(err.to_string(), "Merge conflict: Head branch was modified");
    }

    // ── is_retryable ────────────────────────────────────────────────

    #[test]
    fn retryable_rate_limited() {
        let err = GitHubError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_api_500() {
        let err = GitHubError::Api {
            message: "Internal".into(),
            status_code: Some(500),
            documentation_url: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_api_502() {
        let err = GitHubError::Api {
            message: "Bad Gateway".into(),
            status_code: Some(502),
            documentation_url: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_api_503() {
        let err = GitHubError::Api {
            message: "Service Unavailable".into(),
            status_code: Some(503),
            documentation_url: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_api_429() {
        let err = GitHubError::Api {
            message: "Rate limit".into(),
            status_code: Some(429),
            documentation_url: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn retryable_api_403() {
        let err = GitHubError::Api {
            message: "Forbidden".into(),
            status_code: Some(403),
            documentation_url: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn not_retryable_unauthorized() {
        assert!(!GitHubError::Unauthorized.is_retryable());
    }

    #[test]
    fn not_retryable_not_found() {
        let err = GitHubError::NotFound {
            resource: "x".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_validation_error() {
        let err = GitHubError::ValidationError {
            message: "invalid".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_merge_conflict() {
        let err = GitHubError::MergeConflict {
            message: "conflict".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_json_error() {
        let err = GitHubError::Json(serde_json::from_str::<serde_json::Value>("{{").unwrap_err());
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_400() {
        let err = GitHubError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
            documentation_url: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_404() {
        let err = GitHubError::Api {
            message: "Not Found".into(),
            status_code: Some(404),
            documentation_url: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn not_retryable_api_no_status() {
        let err = GitHubError::Api {
            message: "Unknown".into(),
            status_code: None,
            documentation_url: None,
        };
        assert!(!err.is_retryable());
    }

    // ── retry_after ─────────────────────────────────────────────────

    #[test]
    fn retry_after_rate_limited() {
        let err = GitHubError::RateLimited {
            retry_after_ms: 3000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn retry_after_zero() {
        let err = GitHubError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_none_for_other_variants() {
        assert!(GitHubError::Unauthorized.retry_after().is_none());
        assert!(
            GitHubError::NotFound {
                resource: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GitHubError::ValidationError {
                message: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GitHubError::MergeConflict {
                message: "x".into()
            }
            .retry_after()
            .is_none()
        );
        assert!(
            GitHubError::Api {
                message: "x".into(),
                status_code: Some(500),
                documentation_url: None,
            }
            .retry_after()
            .is_none()
        );
    }

    // ── to_fcp_error ────────────────────────────────────────────────

    #[test]
    fn fcp_error_from_api_401() {
        let err = GitHubError::Api {
            message: "Bad credentials".into(),
            status_code: Some(401),
            documentation_url: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("GitHub token"), "got: {message}");
            }
            other => panic!("expected Unauthorized, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_api_403() {
        let err = GitHubError::Api {
            message: "Forbidden".into(),
            status_code: Some(403),
            documentation_url: None,
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::Unauthorized { .. }),
            "403 should map to Unauthorized, got: {fcp:?}"
        );
    }

    #[test]
    fn fcp_error_from_api_429() {
        let err = GitHubError::Api {
            message: "Rate limit".into(),
            status_code: Some(429),
            documentation_url: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 60_000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_api_500() {
        let err = GitHubError::Api {
            message: "Internal server error".into(),
            status_code: Some(500),
            documentation_url: Some("https://docs.github.com/".into()),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "github");
                assert_eq!(message, "Internal server error");
                assert_eq!(status_code, Some(500));
                assert!(retryable);
            }
            other => panic!("expected External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_api_no_status() {
        let err = GitHubError::Api {
            message: "Something went wrong".into(),
            status_code: None,
            documentation_url: None,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                message,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "github");
                assert_eq!(message, "Something went wrong");
                assert!(status_code.is_none());
                assert!(!retryable);
            }
            other => panic!("expected External, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_rate_limited() {
        let err = GitHubError::RateLimited {
            retry_after_ms: 5000,
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::RateLimited {
                retry_after_ms,
                violation,
            } => {
                assert_eq!(retry_after_ms, 5000);
                assert!(violation.is_none());
            }
            other => panic!("expected RateLimited, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_unauthorized() {
        let fcp = GitHubError::Unauthorized.to_fcp_error();
        match fcp {
            FcpError::Unauthorized { code, message } => {
                assert_eq!(code, 2001);
                assert!(message.contains("expired"), "got: {message}");
            }
            other => panic!("expected Unauthorized, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_not_found() {
        let err = GitHubError::NotFound {
            resource: "repos/owner/repo".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert_eq!(resource, "repos/owner/repo");
            }
            other => panic!("expected ResourceNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_validation_error() {
        let err = GitHubError::ValidationError {
            message: "Title is required".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "Title is required");
            }
            other => panic!("expected InvalidRequest, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_merge_conflict() {
        let err = GitHubError::MergeConflict {
            message: "Branch out of date".into(),
        };
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Conflict { message } => {
                assert_eq!(message, "Branch out of date");
            }
            other => panic!("expected Conflict, got: {other:?}"),
        }
    }

    #[test]
    fn fcp_error_from_json_error() {
        let err =
            GitHubError::Json(serde_json::from_str::<serde_json::Value>("not json").unwrap_err());
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.starts_with("JSON error:"), "got: {message}");
            }
            other => panic!("expected Internal, got: {other:?}"),
        }
    }

    // ── Debug format ────────────────────────────────────────────────

    #[test]
    fn debug_format_all_variants() {
        let variants: Vec<GitHubError> = vec![
            GitHubError::Api {
                message: "test".into(),
                status_code: Some(500),
                documentation_url: None,
            },
            GitHubError::RateLimited {
                retry_after_ms: 1000,
            },
            GitHubError::Unauthorized,
            GitHubError::NotFound {
                resource: "r".into(),
            },
            GitHubError::ValidationError {
                message: "v".into(),
            },
            GitHubError::MergeConflict {
                message: "m".into(),
            },
            GitHubError::Json(serde_json::from_str::<serde_json::Value>("!").unwrap_err()),
        ];
        for variant in &variants {
            let debug = format!("{variant:?}");
            assert!(!debug.is_empty(), "Debug should produce non-empty output");
        }
    }

    // ── std::error::Error trait ─────────────────────────────────────

    #[test]
    fn error_trait_source_json() {
        use std::error::Error;
        let err = GitHubError::Json(serde_json::from_str::<serde_json::Value>("bad").unwrap_err());
        // Json variant should have a source (the serde_json::Error)
        assert!(err.source().is_some(), "Json should have a source error");
    }

    #[test]
    fn error_trait_source_none_for_leaf_variants() {
        use std::error::Error;
        assert!(GitHubError::Unauthorized.source().is_none());
        assert!(
            GitHubError::NotFound {
                resource: "r".into()
            }
            .source()
            .is_none()
        );
        assert!(
            GitHubError::ValidationError {
                message: "v".into()
            }
            .source()
            .is_none()
        );
        assert!(
            GitHubError::MergeConflict {
                message: "m".into()
            }
            .source()
            .is_none()
        );
        assert!(
            GitHubError::RateLimited {
                retry_after_ms: 100
            }
            .source()
            .is_none()
        );
        assert!(
            GitHubError::Api {
                message: "a".into(),
                status_code: None,
                documentation_url: None,
            }
            .source()
            .is_none()
        );
    }

    // ── GitHubResult type alias ─────────────────────────────────────

    #[test]
    fn result_type_alias_ok() {
        let result: GitHubResult<u32> = Ok(42);
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn result_type_alias_err() {
        let result: GitHubResult<u32> = Err(GitHubError::Unauthorized);
        assert!(result.is_err());
    }

    // ── From impls ──────────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err: GitHubError = json_err.into();
        assert!(matches!(err, GitHubError::Json(_)));
        assert!(!err.is_retryable());
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn rate_limited_large_retry() {
        let err = GitHubError::RateLimited {
            retry_after_ms: u64::MAX,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(u64::MAX)));
        assert!(err.is_retryable());
    }

    #[test]
    fn api_error_boundary_status_codes() {
        // 499 is not retryable (not in 500..=599 or 429 or 403)
        let err = GitHubError::Api {
            message: String::new(),
            status_code: Some(499),
            documentation_url: None,
        };
        assert!(!err.is_retryable());

        // 599 is retryable
        let err = GitHubError::Api {
            message: String::new(),
            status_code: Some(599),
            documentation_url: None,
        };
        assert!(err.is_retryable());

        // 600 is not retryable
        let err = GitHubError::Api {
            message: String::new(),
            status_code: Some(600),
            documentation_url: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn fcp_error_api_200_maps_to_external() {
        // Even 200 as status_code in an Api error maps to External (unusual but valid)
        let err = GitHubError::Api {
            message: "Weird".into(),
            status_code: Some(200),
            documentation_url: None,
        };
        let fcp = err.to_fcp_error();
        assert!(
            matches!(fcp, FcpError::External { .. }),
            "200 in Api should map to External, got: {fcp:?}"
        );
    }

    #[test]
    fn not_found_empty_resource() {
        let err = GitHubError::NotFound {
            resource: String::new(),
        };
        assert_eq!(err.to_string(), "Resource not found: ");
        let fcp = err.to_fcp_error();
        match fcp {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.is_empty());
            }
            other => panic!("expected ResourceNotFound, got: {other:?}"),
        }
    }
}
