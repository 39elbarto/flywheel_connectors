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

    // ── Display exact format verification ──

    #[test]
    fn connector_not_found_display_exact() {
        let err = HostError::ConnectorNotFound("acme:utility:2.0.0".into());
        assert_eq!(err.to_string(), "connector not found: acme:utility:2.0.0");
    }

    #[test]
    fn invalid_filter_display_exact() {
        let err = HostError::InvalidFilter("zone_id must be non-empty".into());
        assert_eq!(err.to_string(), "invalid filter: zone_id must be non-empty");
    }

    #[test]
    fn registry_error_display_exact() {
        let err = HostError::RegistryError("timeout after 30s".into());
        assert_eq!(err.to_string(), "registry error: timeout after 30s");
    }

    #[test]
    fn preflight_failed_display_exact() {
        let err = HostError::PreflightFailed("missing capability net:egress".into());
        assert_eq!(
            err.to_string(),
            "preflight failed: missing capability net:egress"
        );
    }

    #[test]
    fn cache_error_display_exact() {
        let err = HostError::CacheError("disk quota exceeded".into());
        assert_eq!(err.to_string(), "cache error: disk quota exceeded");
    }

    #[test]
    fn unavailable_display_exact() {
        let err = HostError::Unavailable("maintenance window".into());
        assert_eq!(err.to_string(), "unavailable: maintenance window");
    }

    #[test]
    fn internal_error_display_exact() {
        let err = HostError::Internal("null pointer in scheduler".into());
        assert_eq!(err.to_string(), "internal error: null pointer in scheduler");
    }

    // ── Error source chain (thiserror) ──

    #[test]
    fn host_error_source_is_none() {
        // All HostError variants wrap String, not other errors,
        // so source() should be None for every variant.
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
            assert!(
                std::error::Error::source(err).is_none(),
                "expected source() == None for {err:?}"
            );
        }
    }

    // ── Debug format contains variant name + inner string ──

    #[test]
    fn debug_connector_not_found_contains_inner() {
        let err = HostError::ConnectorNotFound("xyz:archetype:1.0".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ConnectorNotFound"));
        assert!(dbg.contains("xyz:archetype:1.0"));
    }

    #[test]
    fn debug_invalid_filter_contains_inner() {
        let err = HostError::InvalidFilter("bad param".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidFilter"));
        assert!(dbg.contains("bad param"));
    }

    #[test]
    fn debug_registry_error_contains_inner() {
        let err = HostError::RegistryError("dns failure".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RegistryError"));
        assert!(dbg.contains("dns failure"));
    }

    #[test]
    fn debug_preflight_failed_contains_inner() {
        let err = HostError::PreflightFailed("budget limit".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PreflightFailed"));
        assert!(dbg.contains("budget limit"));
    }

    #[test]
    fn debug_cache_error_contains_inner() {
        let err = HostError::CacheError("corrupted entry".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("CacheError"));
        assert!(dbg.contains("corrupted entry"));
    }

    #[test]
    fn debug_unavailable_contains_inner() {
        let err = HostError::Unavailable("shutting down".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Unavailable"));
        assert!(dbg.contains("shutting down"));
    }

    #[test]
    fn debug_internal_contains_inner() {
        let err = HostError::Internal("assertion failed".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Internal"));
        assert!(dbg.contains("assertion failed"));
    }

    // ── Display and Debug differ ──

    #[test]
    fn display_and_debug_differ_for_all_variants() {
        let variants: Vec<HostError> = vec![
            HostError::ConnectorNotFound("v".into()),
            HostError::InvalidFilter("v".into()),
            HostError::RegistryError("v".into()),
            HostError::PreflightFailed("v".into()),
            HostError::CacheError("v".into()),
            HostError::Unavailable("v".into()),
            HostError::Internal("v".into()),
        ];
        for err in &variants {
            let display = err.to_string();
            let debug = format!("{err:?}");
            assert_ne!(
                display, debug,
                "Display and Debug should differ for {display}"
            );
        }
    }

    // ── Whitespace-only messages ──

    #[test]
    fn connector_not_found_whitespace_message() {
        let err = HostError::ConnectorNotFound("   ".into());
        assert_eq!(err.to_string(), "connector not found:    ");
    }

    #[test]
    fn internal_error_newline_message() {
        let err = HostError::Internal("line1\nline2".into());
        let msg = err.to_string();
        assert!(msg.contains("line1\nline2"));
    }

    // ── Special characters ──

    #[test]
    fn registry_error_with_special_chars() {
        let err = HostError::RegistryError("err <code>: &\"quote\"".into());
        let msg = err.to_string();
        assert!(msg.contains('<'));
        assert!(msg.contains('&'));
        assert!(msg.contains('"'));
    }

    #[test]
    fn cache_error_with_path_separators() {
        let err = HostError::CacheError("/var/cache/fcp/entry.dat: permission denied".into());
        assert!(err.to_string().contains("/var/cache/fcp/entry.dat"));
    }

    // ── HostResult with different types ──

    #[test]
    fn host_result_ok_string() {
        let result: HostResult<String> = Ok("hello".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn host_result_ok_unit() {
        let result: HostResult<()> = Ok(());
        assert!(result.is_ok());
    }

    #[test]
    fn host_result_ok_vec() {
        let result: HostResult<Vec<u8>> = Ok(vec![1, 2, 3]);
        assert!(result.is_ok());
    }

    #[test]
    fn host_result_ok_option() {
        let result: HostResult<Option<i32>> = Ok(Some(7));
        assert!(result.is_ok());
    }

    #[test]
    fn host_result_err_map_err() {
        let result: HostResult<u32> = Err(HostError::Internal("oops".into()));
        let mapped = result.map_err(|e| e.to_string());
        assert!(mapped.is_err());
        assert_eq!(mapped.expect_err("should be err"), "internal error: oops");
    }

    #[test]
    fn host_result_err_unwrap_err() {
        let result: HostResult<u32> = Err(HostError::Unavailable("down".into()));
        assert!(result.is_err());
    }

    // ── Error variant discrimination ──

    #[test]
    fn different_variants_have_different_display_prefixes() {
        let pairs = [
            (
                HostError::ConnectorNotFound("x".into()),
                "connector not found",
            ),
            (HostError::InvalidFilter("x".into()), "invalid filter"),
            (HostError::RegistryError("x".into()), "registry error"),
            (HostError::PreflightFailed("x".into()), "preflight failed"),
            (HostError::CacheError("x".into()), "cache error"),
            (HostError::Unavailable("x".into()), "unavailable"),
            (HostError::Internal("x".into()), "internal error"),
        ];
        for (i, (err_a, prefix_a)) in pairs.iter().enumerate() {
            assert!(
                err_a.to_string().starts_with(prefix_a),
                "variant {i} should start with '{prefix_a}', got '{err_a}'"
            );
        }
    }

    #[test]
    fn same_message_different_variant_produces_different_display() {
        let msg = "something went wrong";
        let a = HostError::ConnectorNotFound(msg.into());
        let b = HostError::Internal(msg.into());
        assert_ne!(a.to_string(), b.to_string());
    }

    // ── Error as dyn Error ──

    #[test]
    fn all_variants_upcast_to_dyn_error() {
        let variants: Vec<HostError> = vec![
            HostError::ConnectorNotFound("a".into()),
            HostError::InvalidFilter("b".into()),
            HostError::RegistryError("c".into()),
            HostError::PreflightFailed("d".into()),
            HostError::CacheError("e".into()),
            HostError::Unavailable("f".into()),
            HostError::Internal("g".into()),
        ];
        for err in variants {
            let dyn_err: Box<dyn std::error::Error> = Box::new(err);
            assert!(!dyn_err.to_string().is_empty());
        }
    }

    // ── Very long message round-trip ──

    #[test]
    fn all_variants_long_message_preserved() {
        let long = "y".repeat(50_000);
        let variants: Vec<HostError> = vec![
            HostError::ConnectorNotFound(long.clone()),
            HostError::InvalidFilter(long.clone()),
            HostError::RegistryError(long.clone()),
            HostError::PreflightFailed(long.clone()),
            HostError::CacheError(long.clone()),
            HostError::Unavailable(long.clone()),
            HostError::Internal(long.clone()),
        ];
        for err in &variants {
            assert!(
                err.to_string().contains(&long),
                "long message should be preserved in Display"
            );
        }
    }

    // ── Null byte in message ──

    #[test]
    fn connector_not_found_null_byte() {
        let err = HostError::ConnectorNotFound("before\0after".into());
        let msg = err.to_string();
        assert!(msg.contains("before"));
        assert!(msg.contains("after"));
    }

    // ── Tab characters ──

    #[test]
    fn preflight_failed_tab_chars() {
        let err = HostError::PreflightFailed("col1\tcol2\tcol3".into());
        let msg = err.to_string();
        assert!(msg.contains('\t'));
    }

    // ── Display consistency: calling to_string twice yields same result ──

    #[test]
    fn display_idempotent() {
        let err = HostError::CacheError("stale".into());
        let first = err.to_string();
        let second = err.to_string();
        assert_eq!(first, second);
    }

    // ── HostResult with nested Result ──

    #[test]
    fn host_result_nested() {
        let result: HostResult<Result<u32, String>> = Ok(Err("inner".to_string()));
        assert!(result.is_ok());
    }

    // ── HostResult question mark operator emulation ──

    #[test]
    fn host_result_question_mark_propagation() {
        fn inner() -> HostResult<u32> {
            Err(HostError::ConnectorNotFound("missing".into()))
        }
        fn outer() -> HostResult<u32> {
            let val = inner()?;
            Ok(val + 1)
        }
        let result = outer();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing"));
    }
}
