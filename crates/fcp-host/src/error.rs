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
}
