//! Error types for fcp-host.

use thiserror::Error;

/// Errors that can occur in fcp-host operations.
#[derive(Debug, Error)]
pub enum HostError {
    /// Connector not found in registry.
    #[error("connector not found: {0}")]
    ConnectorNotFound(String),

    /// Invalid filter parameter.
    #[error("invalid filter: {0}")]
    InvalidFilter(String),

    /// Registry error.
    #[error("registry error: {0}")]
    RegistryError(String),

    /// Preflight check failed.
    #[error("preflight failed: {0}")]
    PreflightFailed(String),

    /// Cache error.
    #[error("cache error: {0}")]
    CacheError(String),

    /// Connector or host surface is temporarily unavailable.
    #[error("unavailable: {0}")]
    Unavailable(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for host operations.
pub type HostResult<T> = Result<T, HostError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_not_found_display() {
        let err = HostError::ConnectorNotFound("my.connector:utility:1.0.0".into());
        assert!(err.to_string().contains("connector not found"));
        assert!(err.to_string().contains("my.connector:utility:1.0.0"));
    }

    #[test]
    fn invalid_filter_display() {
        let err = HostError::InvalidFilter("bad zone_id".into());
        assert!(err.to_string().contains("invalid filter"));
        assert!(err.to_string().contains("bad zone_id"));
    }

    #[test]
    fn registry_error_display() {
        let err = HostError::RegistryError("connection refused".into());
        assert!(err.to_string().contains("registry error"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn preflight_failed_display() {
        let err = HostError::PreflightFailed("budget exceeded".into());
        assert!(err.to_string().contains("preflight failed"));
        assert!(err.to_string().contains("budget exceeded"));
    }

    #[test]
    fn cache_error_display() {
        let err = HostError::CacheError("eviction failed".into());
        assert!(err.to_string().contains("cache error"));
        assert!(err.to_string().contains("eviction failed"));
    }

    #[test]
    fn unavailable_display() {
        let err = HostError::Unavailable("circuit breaker open".into());
        assert!(err.to_string().contains("unavailable"));
        assert!(err.to_string().contains("circuit breaker open"));
    }

    #[test]
    fn internal_error_display() {
        let err = HostError::Internal("unexpected state".into());
        assert!(err.to_string().contains("internal error"));
        assert!(err.to_string().contains("unexpected state"));
    }

    #[test]
    fn host_error_debug() {
        let err = HostError::ConnectorNotFound("test".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ConnectorNotFound"));
    }

    #[test]
    fn host_error_is_std_error() {
        let err = HostError::Internal("test".into());
        let _: &dyn std::error::Error = &err;
    }

    // ── Empty string messages ──

    #[test]
    fn connector_not_found_empty_string() {
        let err = HostError::ConnectorNotFound(String::new());
        let msg = err.to_string();
        assert!(msg.contains("connector not found"));
        assert!(msg.contains(':'));
    }

    #[test]
    fn invalid_filter_empty_string() {
        let err = HostError::InvalidFilter(String::new());
        assert!(err.to_string().contains("invalid filter"));
    }

    #[test]
    fn registry_error_empty_string() {
        let err = HostError::RegistryError(String::new());
        assert!(err.to_string().contains("registry error"));
    }

    #[test]
    fn preflight_failed_empty_string() {
        let err = HostError::PreflightFailed(String::new());
        assert!(err.to_string().contains("preflight failed"));
    }

    #[test]
    fn cache_error_empty_string() {
        let err = HostError::CacheError(String::new());
        assert!(err.to_string().contains("cache error"));
    }

    #[test]
    fn unavailable_empty_string() {
        let err = HostError::Unavailable(String::new());
        assert!(err.to_string().contains("unavailable"));
    }

    #[test]
    fn internal_error_empty_string() {
        let err = HostError::Internal(String::new());
        assert!(err.to_string().contains("internal error"));
    }

    // ── Unicode messages ──

    #[test]
    fn connector_not_found_unicode() {
        let err = HostError::ConnectorNotFound("konnektor-\u{00e9}\u{00e8}\u{00ea}".into());
        let msg = err.to_string();
        assert!(msg.contains('\u{00e9}'));
        assert!(msg.contains("konnektor"));
    }

    #[test]
    fn internal_error_unicode_emoji() {
        let err = HostError::Internal("crash \u{1F4A5}".into());
        let msg = err.to_string();
        assert!(msg.contains('\u{1F4A5}'));
    }

    // ── Long messages ──

    #[test]
    fn registry_error_long_message() {
        let long_msg = "x".repeat(10_000);
        let err = HostError::RegistryError(long_msg.clone());
        let display = err.to_string();
        assert!(display.contains(&long_msg));
    }

    // ── Debug for all variants ──

    #[test]
    fn all_variants_debug() {
        let variants: Vec<HostError> = vec![
            HostError::ConnectorNotFound("a".into()),
            HostError::InvalidFilter("b".into()),
            HostError::RegistryError("c".into()),
            HostError::PreflightFailed("d".into()),
            HostError::CacheError("e".into()),
            HostError::Unavailable("f".into()),
            HostError::Internal("g".into()),
        ];
        for err in &variants {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── HostResult type alias ──

    #[test]
    fn host_result_ok() {
        let result: HostResult<u32> = Ok(42);
        match result {
            Ok(v) => assert_eq!(v, 42),
            Err(e) => panic!("expected Ok(42), got Err({e:?})"),
        }
    }

    #[test]
    fn host_result_err() {
        let result: HostResult<u32> = Err(HostError::Internal("test".into()));
        assert!(result.is_err());
    }
}
