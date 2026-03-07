//! FCP Redis Cache and Pub/Sub Connector library.

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::derivable_impls,
    clippy::future_not_send,
    clippy::manual_unwrap_or_default,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unreadable_literal,
    clippy::unused_async
)]

pub mod client;
pub mod connector;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fcp_core::{CredentialId, FcpError};
    use serde_json::json;
    use wiremock::matchers::{body_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::client::{DEFAULT_BASE_URL, RedisAuth, RedisClient};
    use crate::connector::RedisConnector;
    use crate::error::RedisError;
    use crate::types::{ApiErrorResponse, SetOptions, UpstashResponse};

    // ===== Config parsing tests =====

    #[test]
    fn config_from_api_token() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_token": "test-token" })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_from_credential_id() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "api_token": "token",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({})));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_token() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_token": "" })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_token() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_token": "   " })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "credential_id": 12345 })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "credential_id": "not-a-uuid" })));
        assert!(result.is_err());
    }

    #[test]
    fn config_custom_base_url() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "api_token": "tok",
            "base_url": "https://custom-redis.example.com"
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_default_base_url() {
        let client = RedisClient::new(RedisAuth::ApiToken("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn config_trims_api_token() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_token": "  my_token  " })));
        assert!(result.is_ok());
    }

    // ===== Error type Display tests =====

    #[test]
    fn error_display_http() {
        // Cannot construct reqwest::Error easily, test others
        let err = RedisError::Command {
            message: "ERR wrong number of arguments".into(),
        };
        assert!(err.to_string().contains("ERR wrong number of arguments"));
    }

    #[test]
    fn error_display_command() {
        let err = RedisError::Command {
            message: "WRONGTYPE operation".into(),
        };
        assert_eq!(err.to_string(), "Redis command error: WRONGTYPE operation");
    }

    #[test]
    fn error_display_connection() {
        let err = RedisError::Connection("connection refused".into());
        assert_eq!(
            err.to_string(),
            "Redis connection error: connection refused"
        );
    }

    #[test]
    fn error_display_unauthorized() {
        assert_eq!(
            RedisError::Unauthorized.to_string(),
            "Authentication failed: invalid or expired API token"
        );
    }

    #[test]
    fn error_display_forbidden() {
        assert_eq!(
            RedisError::Forbidden.to_string(),
            "Forbidden: insufficient permissions"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            RedisError::RateLimited {
                retry_after_ms: 3000
            }
            .to_string(),
            "Rate limited, retry after 3000ms"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            RedisError::Api {
                status_code: 500,
                message: "Internal".into()
            }
            .to_string(),
            "Redis API error (500): Internal"
        );
    }

    #[test]
    fn error_display_key_not_found() {
        assert_eq!(
            RedisError::KeyNotFound {
                key: "mykey".into()
            }
            .to_string(),
            "Key not found: mykey"
        );
    }

    #[test]
    fn error_display_type_mismatch() {
        assert_eq!(
            RedisError::TypeMismatch {
                expected: "string".into(),
                actual: "list".into()
            }
            .to_string(),
            "Type mismatch: expected string, got list"
        );
    }

    #[test]
    fn error_display_timeout() {
        assert_eq!(
            RedisError::Timeout("30s exceeded".into()).to_string(),
            "Redis timeout: 30s exceeded"
        );
    }

    // ===== Error retryable tests =====

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            RedisError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn connection_is_retryable() {
        assert!(RedisError::Connection("err".into()).is_retryable());
    }

    #[test]
    fn timeout_is_retryable() {
        assert!(RedisError::Timeout("err".into()).is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            RedisError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            RedisError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            RedisError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn unauthorized_not_retryable() {
        assert!(!RedisError::Unauthorized.is_retryable());
    }

    #[test]
    fn forbidden_not_retryable() {
        assert!(!RedisError::Forbidden.is_retryable());
    }

    #[test]
    fn command_not_retryable() {
        assert!(
            !RedisError::Command {
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn key_not_found_not_retryable() {
        assert!(
            !RedisError::KeyNotFound {
                key: "k".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn type_mismatch_not_retryable() {
        assert!(
            !RedisError::TypeMismatch {
                expected: "a".into(),
                actual: "b".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !RedisError::Api {
                status_code: 400,
                message: "bad".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            RedisError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            RedisError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !RedisError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    // ===== Error retry_after tests =====

    #[test]
    fn retry_after_for_rate_limited() {
        let err = RedisError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_unauthorized() {
        assert_eq!(RedisError::Unauthorized.retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_command() {
        assert_eq!(
            RedisError::Command {
                message: "err".into()
            }
            .retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_none_for_connection() {
        assert_eq!(RedisError::Connection("err".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_timeout() {
        assert_eq!(RedisError::Timeout("err".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = RedisError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = RedisError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    // ===== Error to_fcp_error tests =====

    #[test]
    fn unauthorized_to_fcp_error() {
        match RedisError::Unauthorized.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "redis");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn forbidden_to_fcp_error() {
        match RedisError::Forbidden.to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "redis");
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (RedisError::RateLimited {
            retry_after_ms: 60_000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn command_to_fcp_error() {
        match (RedisError::Command {
            message: "ERR syntax".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service, message, ..
            } => {
                assert_eq!(service, "redis");
                assert_eq!(message, "ERR syntax");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn connection_to_fcp_error() {
        match RedisError::Connection("refused".into()).to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                ..
            } => {
                assert_eq!(service, "redis");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn key_not_found_to_fcp_error() {
        match (RedisError::KeyNotFound {
            key: "mykey".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                status_code,
                message,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("mykey"));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn type_mismatch_to_fcp_error() {
        match (RedisError::TypeMismatch {
            expected: "string".into(),
            actual: "hash".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service, message, ..
            } => {
                assert_eq!(service, "redis");
                assert!(message.contains("string"));
                assert!(message.contains("hash"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn timeout_to_fcp_error() {
        match RedisError::Timeout("30s".into()).to_fcp_error() {
            FcpError::External {
                service,
                retryable,
                ..
            } => {
                assert_eq!(service, "redis");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (RedisError::Api {
            status_code: 503,
            message: "unavailable".into(),
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                message,
                ..
            } => {
                assert_eq!(service, "redis");
                assert_eq!(status_code, Some(503));
                assert!(retryable);
                assert_eq!(message, "unavailable");
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn json_error_to_fcp_internal() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        match RedisError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ===== Client construction tests =====

    #[test]
    fn client_new_default_url() {
        let client = RedisClient::new(RedisAuth::ApiToken("key".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_new_custom_url() {
        let client = RedisClient::new(
            RedisAuth::ApiToken("key".into()),
            Some("https://custom-redis.upstash.io/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://custom-redis.upstash.io"));
        assert!(!dbg.contains("https://custom-redis.upstash.io/"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = RedisClient::new(
            RedisAuth::ApiToken("k".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("///"));
    }

    #[test]
    fn client_debug_redacts_token() {
        let client =
            RedisClient::new(RedisAuth::ApiToken("supersecrettoken123".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("supersecrettoken123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let client = RedisClient::new(RedisAuth::CredentialId(cred), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = RedisClient::new(RedisAuth::ApiToken("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("RedisClient"));
        assert!(dbg.contains("base_url"));
    }

    // ===== Auth tests =====

    #[test]
    fn auth_debug_redacts_token() {
        let auth = RedisAuth::ApiToken("secret-token-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-token-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = RedisAuth::ApiToken("token".into());
        assert!(!token.is_secretless());
        let cred = RedisAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_token() {
        let auth = RedisAuth::ApiToken("tok".into());
        assert_eq!(auth.redacted_label(), "api_token:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let auth = RedisAuth::CredentialId(CredentialId::new());
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_clone() {
        let auth = RedisAuth::ApiToken("key123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "api_token:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = RedisAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_debug_shows_tuple_name() {
        let auth = RedisAuth::ApiToken("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiToken"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let auth = RedisAuth::CredentialId(CredentialId::new());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    // ===== Default base URL tests =====

    #[test]
    fn default_base_url_contains_redis() {
        assert!(DEFAULT_BASE_URL.contains("redis"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    // ===== Connector lifecycle tests =====

    #[test]
    fn connector_default() {
        let c = RedisConnector::default();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "unconfigured");
    }

    #[test]
    fn connector_new_eq_default() {
        let a = RedisConnector::new();
        let b = RedisConnector::default();
        let rt = tokio_runtime();
        let ha = rt.block_on(a.handle_health()).unwrap();
        let hb = rt.block_on(b.handle_health()).unwrap();
        assert_eq!(ha["status"], hb["status"]);
    }

    #[test]
    fn health_unconfigured() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["status"], "unconfigured");
        assert_eq!(h["configured"], false);
        assert_eq!(h["handshaken"], false);
        assert_eq!(h["requests"], 0);
        assert_eq!(h["errors"], 0);
    }

    #[test]
    fn health_configured_not_handshaken() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["status"], "degraded");
        assert_eq!(h["configured"], true);
        assert_eq!(h["handshaken"], false);
    }

    #[test]
    fn health_fully_connected() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["status"], "healthy");
        assert_eq!(h["configured"], true);
        assert_eq!(h["handshaken"], true);
    }

    #[test]
    fn handshake_before_configure_fails() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })));
        assert!(result.is_err());
    }

    #[test]
    fn handshake_response_fields() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        let resp = rt
            .block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        assert_eq!(resp["protocol_version"], "2.0");
        assert_eq!(resp["connector_id"], "fcp.redis");
        assert_eq!(resp["connector_version"], "0.1.0");
        let caps = resp["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 14);
    }

    #[test]
    fn handshake_capabilities_contains_all_ops() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        let resp = rt
            .block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let caps: Vec<&str> = resp["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        for op in &[
            "redis.get",
            "redis.set",
            "redis.del",
            "redis.exists",
            "redis.expire",
            "redis.ttl",
            "redis.incr",
            "redis.hget",
            "redis.hset",
            "redis.hgetall",
            "redis.lpush",
            "redis.lrange",
            "redis.sadd",
            "redis.smembers",
        ] {
            assert!(caps.contains(op), "missing capability: {op}");
        }
    }

    #[test]
    fn handshake_without_session_id() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        let resp = rt.block_on(c.handle_handshake(json!({}))).unwrap();
        assert_eq!(resp["protocol_version"], "2.0");
    }

    // ===== Doctor tests =====

    #[test]
    fn doctor_unconfigured() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(d["status"], "unhealthy");
    }

    #[test]
    fn doctor_configured() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(d["status"], "degraded");
    }

    #[test]
    fn doctor_fully_connected() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(d["status"], "healthy");
    }

    #[test]
    fn doctor_checks_count() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        let checks = d["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 3);
    }

    // ===== Self check tests =====

    #[test]
    fn self_check_unconfigured() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let sc = rt.block_on(c.handle_self_check()).unwrap();
        assert_eq!(sc["status"], "unconfigured");
        assert_eq!(sc["connector_id"], "fcp.redis");
        assert_eq!(sc["version"], "0.1.0");
    }

    #[test]
    fn self_check_configured() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        let sc = rt.block_on(c.handle_self_check()).unwrap();
        assert_eq!(sc["status"], "ready");
    }

    // ===== Introspect tests =====

    #[test]
    fn introspect_has_14_operations() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let ops = intr["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 14);
    }

    #[test]
    fn introspect_operations_have_required_fields() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
            assert!(op.get("input_schema").is_some(), "missing input_schema");
            assert!(op.get("output_schema").is_some(), "missing output_schema");
        }
    }

    #[test]
    fn introspect_operations_ids_are_unique() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let ids: Vec<&str> = intr["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn introspect_operations_ids_follow_naming() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("redis."),
                "op id should start with 'redis.': {id}"
            );
        }
    }

    #[test]
    fn introspect_operations_contain_expected_ids() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let ids: Vec<&str> = intr["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        for expected in &[
            "redis.get",
            "redis.set",
            "redis.del",
            "redis.exists",
            "redis.expire",
            "redis.ttl",
            "redis.incr",
            "redis.hget",
            "redis.hset",
            "redis.hgetall",
            "redis.lpush",
            "redis.lrange",
            "redis.sadd",
            "redis.smembers",
        ] {
            assert!(ids.contains(expected), "missing op id: {expected}");
        }
    }

    #[test]
    fn introspect_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn introspect_safety_tiers_valid() {
        let valid = ["safe", "moderate", "risky", "dangerous"];
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn introspect_idempotency_values_valid() {
        let valid = ["strict", "best_effort", "none"];
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let v = op["idempotency"].as_str().unwrap();
            assert!(valid.contains(&v), "invalid idempotency: {v}");
        }
    }

    #[test]
    fn introspect_capabilities_valid() {
        let valid = ["redis.read", "redis.write"];
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(valid.contains(&cap), "invalid capability: {cap}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn introspect_read_ops_are_safe() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn introspect_read_count() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let count = intr["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("redis.read"))
            .count();
        // get, exists, ttl, hget, hgetall, lrange, smembers = 7
        assert_eq!(count, 7);
    }

    #[test]
    fn introspect_write_count() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let count = intr["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("redis.write"))
            .count();
        // set, del, expire, incr, hset, lpush, sadd = 7
        assert_eq!(count, 7);
    }

    #[test]
    fn introspect_summaries_non_empty() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let s = op["summary"].as_str().unwrap();
            assert!(!s.is_empty(), "empty summary for {}", op["id"]);
        }
    }

    #[test]
    fn introspect_schemas_are_objects() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            assert!(
                op["input_schema"].is_object(),
                "input_schema should be object for {}",
                op["id"]
            );
            assert!(
                op["output_schema"].is_object(),
                "output_schema should be object for {}",
                op["id"]
            );
        }
    }

    #[test]
    fn introspect_connector_id() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        assert_eq!(intr["connector_id"], "fcp.redis");
        assert_eq!(intr["version"], "0.1.0");
    }

    // ===== Simulate tests =====

    #[test]
    fn simulate_known_operation() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let resp = rt
            .block_on(c.handle_simulate(json!({ "operation_id": "redis.get" })))
            .unwrap();
        assert_eq!(resp["allowed"], true);
        assert_eq!(resp["reason"], "Operation supported");
    }

    #[test]
    fn simulate_unknown_operation() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let resp = rt
            .block_on(c.handle_simulate(json!({ "operation_id": "redis.unknown" })))
            .unwrap();
        assert_eq!(resp["allowed"], false);
        assert_eq!(resp["reason"], "Unknown operation");
    }

    #[test]
    fn simulate_empty_operation() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let resp = rt.block_on(c.handle_simulate(json!({}))).unwrap();
        assert_eq!(resp["allowed"], false);
    }

    #[test]
    fn simulate_all_14_operations() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        for op in &[
            "redis.get",
            "redis.set",
            "redis.del",
            "redis.exists",
            "redis.expire",
            "redis.ttl",
            "redis.incr",
            "redis.hget",
            "redis.hset",
            "redis.hgetall",
            "redis.lpush",
            "redis.lrange",
            "redis.sadd",
            "redis.smembers",
        ] {
            let resp = rt
                .block_on(c.handle_simulate(json!({ "operation_id": op })))
                .unwrap();
            assert_eq!(resp["allowed"], true, "simulate should allow {op}");
        }
    }

    // ===== Shutdown tests =====

    #[test]
    fn shutdown_resets_state() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        rt.block_on(c.handle_shutdown(json!({}))).unwrap();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["status"], "unconfigured");
    }

    #[test]
    fn shutdown_returns_empty_object() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        let resp = rt.block_on(c.handle_shutdown(json!({}))).unwrap();
        assert!(resp.as_object().unwrap().is_empty());
    }

    // ===== Invoke without handshake fails =====

    #[test]
    fn invoke_without_configure_fails() {
        let c = RedisConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "redis.get",
            "input": { "key": "test" }
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_unknown_operation_fails() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "redis.nonexistent",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_missing_operation_id_fails() {
        let mut c = RedisConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_token": "tok" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({ "input": {} })));
        assert!(result.is_err());
    }

    // ===== Wiremock integration tests for each operation =====

    #[test]
    fn wiremock_get_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_json(json!(["GET", "mykey"])))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": "myvalue"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "mykey" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["value"], "myvalue");
        });
    }

    #[test]
    fn wiremock_get_null_result() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": null
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "missing" }
                }))
                .await
                .unwrap();
            assert!(resp["value"].is_null());
        });
    }

    #[test]
    fn wiremock_set_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": "OK"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.set",
                    "input": { "key": "k1", "value": "v1" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["result"], "OK");
        });
    }

    #[test]
    fn wiremock_set_with_ttl() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_json(json!(["SET", "k1", "v1", "EX", "300"])))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": "OK"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.set",
                    "input": { "key": "k1", "value": "v1", "ttl_seconds": 300 }
                }))
                .await
                .unwrap();
            assert_eq!(resp["result"], "OK");
        });
    }

    #[test]
    fn wiremock_set_with_nx() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_json(json!(["SET", "k1", "v1", "NX"])))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": "OK"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.set",
                    "input": { "key": "k1", "value": "v1", "nx": true }
                }))
                .await
                .unwrap();
            assert_eq!(resp["result"], "OK");
        });
    }

    #[test]
    fn wiremock_del_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_json(json!(["DEL", "k1", "k2"])))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 2
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.del",
                    "input": { "keys": ["k1", "k2"] }
                }))
                .await
                .unwrap();
            assert_eq!(resp["deleted"], 2);
        });
    }

    #[test]
    fn wiremock_exists_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 1
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.exists",
                    "input": { "keys": ["k1"] }
                }))
                .await
                .unwrap();
            assert_eq!(resp["count"], 1);
        });
    }

    #[test]
    fn wiremock_expire_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 1
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.expire",
                    "input": { "key": "k1", "seconds": 60 }
                }))
                .await
                .unwrap();
            assert_eq!(resp["result"], 1);
        });
    }

    #[test]
    fn wiremock_ttl_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 120
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.ttl",
                    "input": { "key": "k1" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["ttl"], 120);
        });
    }

    #[test]
    fn wiremock_incr_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 42
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.incr",
                    "input": { "key": "counter" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["value"], 42);
        });
    }

    #[test]
    fn wiremock_hget_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": "field_value"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.hget",
                    "input": { "key": "myhash", "field": "name" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["value"], "field_value");
        });
    }

    #[test]
    fn wiremock_hset_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 2
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.hset",
                    "input": { "key": "myhash", "fields": { "name": "Alice", "age": "30" } }
                }))
                .await
                .unwrap();
            assert_eq!(resp["result"], 2);
        });
    }

    #[test]
    fn wiremock_hgetall_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": ["name", "Alice", "age", "30"]
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.hgetall",
                    "input": { "key": "myhash" }
                }))
                .await
                .unwrap();
            let fields = resp["fields"].as_array().unwrap();
            assert_eq!(fields.len(), 4);
        });
    }

    #[test]
    fn wiremock_lpush_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 3
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.lpush",
                    "input": { "key": "mylist", "elements": ["a", "b", "c"] }
                }))
                .await
                .unwrap();
            assert_eq!(resp["length"], 3);
        });
    }

    #[test]
    fn wiremock_lrange_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": ["c", "b", "a"]
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.lrange",
                    "input": { "key": "mylist", "start": 0, "stop": -1 }
                }))
                .await
                .unwrap();
            let vals = resp["values"].as_array().unwrap();
            assert_eq!(vals.len(), 3);
        });
    }

    #[test]
    fn wiremock_sadd_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": 2
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.sadd",
                    "input": { "key": "myset", "members": ["x", "y"] }
                }))
                .await
                .unwrap();
            assert_eq!(resp["added"], 2);
        });
    }

    #[test]
    fn wiremock_smembers_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": ["x", "y", "z"]
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.smembers",
                    "input": { "key": "myset" }
                }))
                .await
                .unwrap();
            let members = resp["members"].as_array().unwrap();
            assert_eq!(members.len(), 3);
        });
    }

    // ===== Error handling wiremock tests =====

    #[test]
    fn wiremock_401_unauthorized() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                    "error": "Unauthorized"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "bad",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "k" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_403_forbidden() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(403))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "k" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_429_rate_limited() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(429))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "k" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_500_server_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                    "error": "Internal server error"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "k" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_command_error_in_response() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "error": "WRONGTYPE Operation against a key holding the wrong kind of value"
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": { "key": "k" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Missing field tests =====

    #[test]
    fn invoke_get_missing_key() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.get",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_set_missing_value() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.set",
                    "input": { "key": "k1" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_del_missing_keys() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.del",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_expire_missing_seconds() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.expire",
                    "input": { "key": "k1" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_hget_missing_field() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.hget",
                    "input": { "key": "myhash" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_hset_missing_fields() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.hset",
                    "input": { "key": "myhash" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_hset_fields_not_object() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.hset",
                    "input": { "key": "myhash", "fields": "not_an_object" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_lpush_missing_elements() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.lpush",
                    "input": { "key": "list" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_sadd_missing_members() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "redis.sadd",
                    "input": { "key": "myset" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Types serde tests =====

    #[test]
    fn set_options_default() {
        let opts = SetOptions::default();
        assert!(opts.ttl_seconds.is_none());
        assert!(!opts.nx);
        assert!(!opts.xx);
    }

    #[test]
    fn set_options_serde_roundtrip() {
        let opts = SetOptions {
            ttl_seconds: Some(300),
            nx: true,
            xx: false,
        };
        let v = serde_json::to_value(&opts).unwrap();
        assert_eq!(v["ttl_seconds"], 300);
        assert_eq!(v["nx"], true);
        assert_eq!(v["xx"], false);
        let opts2: SetOptions = serde_json::from_value(v).unwrap();
        assert_eq!(opts2.ttl_seconds, Some(300));
        assert!(opts2.nx);
        assert!(!opts2.xx);
    }

    #[test]
    fn set_options_skip_none_ttl() {
        let opts = SetOptions {
            ttl_seconds: None,
            nx: false,
            xx: false,
        };
        let v = serde_json::to_value(&opts).unwrap();
        assert!(!v.as_object().unwrap().contains_key("ttl_seconds"));
    }

    #[test]
    fn set_options_from_empty_json() {
        let opts: SetOptions = serde_json::from_value(json!({})).unwrap();
        assert!(opts.ttl_seconds.is_none());
        assert!(!opts.nx);
        assert!(!opts.xx);
    }

    #[test]
    fn set_options_clone() {
        let opts = SetOptions {
            ttl_seconds: Some(60),
            nx: true,
            xx: false,
        };
        let cloned = opts.clone();
        #[allow(clippy::drop_non_drop)]
        drop(opts);
        assert_eq!(cloned.ttl_seconds, Some(60));
    }

    #[test]
    fn set_options_debug() {
        let opts = SetOptions::default();
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("SetOptions"));
    }

    #[test]
    fn upstash_response_with_result() {
        let r: UpstashResponse =
            serde_json::from_value(json!({ "result": "hello" })).unwrap();
        assert_eq!(r.result, Some(json!("hello")));
        assert!(r.error.is_none());
    }

    #[test]
    fn upstash_response_with_error() {
        let r: UpstashResponse = serde_json::from_value(json!({
            "error": "ERR unknown command"
        }))
        .unwrap();
        assert!(r.result.is_none());
        assert_eq!(r.error, Some("ERR unknown command".into()));
    }

    #[test]
    fn upstash_response_null_result() {
        let r: UpstashResponse =
            serde_json::from_value(json!({ "result": null })).unwrap();
        assert!(r.result.is_none());
    }

    #[test]
    fn upstash_response_integer_result() {
        let r: UpstashResponse = serde_json::from_value(json!({ "result": 42 })).unwrap();
        assert_eq!(r.result, Some(json!(42)));
    }

    #[test]
    fn upstash_response_array_result() {
        let r: UpstashResponse =
            serde_json::from_value(json!({ "result": ["a", "b"] })).unwrap();
        let arr = r.result.unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 2);
    }

    #[test]
    fn upstash_response_empty_json() {
        let r: UpstashResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.result.is_none());
        assert!(r.error.is_none());
    }

    #[test]
    fn upstash_response_clone() {
        let r: UpstashResponse =
            serde_json::from_value(json!({ "result": "val" })).unwrap();
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.result, Some(json!("val")));
    }

    #[test]
    fn upstash_response_debug() {
        let r: UpstashResponse =
            serde_json::from_value(json!({ "result": "val" })).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("UpstashResponse"));
    }

    #[test]
    fn api_error_response_with_error() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({ "error": "ERR bad command" })).unwrap();
        assert_eq!(e.error, Some("ERR bad command".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error: Some("test".into()),
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.error, Some("test".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse { error: None };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    // ===== Edge case tests =====

    #[test]
    fn wiremock_lrange_default_range() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_json(json!(["LRANGE", "mylist", "0", "-1"])))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": ["a"]
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.lrange",
                    "input": { "key": "mylist" }
                }))
                .await
                .unwrap();
            assert!(resp["values"].is_array());
        });
    }

    #[test]
    fn wiremock_set_with_xx() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_json(json!(["SET", "k1", "v1", "XX"])))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": null
                })))
                .mount(&mock_server)
                .await;

            let mut c = RedisConnector::new();
            c.handle_configure(json!({
                "api_token": "tok",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "redis.set",
                    "input": { "key": "k1", "value": "v1", "xx": true }
                }))
                .await
                .unwrap();
            assert!(resp["result"].is_null());
        });
    }

    #[test]
    fn error_debug_format_command() {
        let err = RedisError::Command {
            message: "WRONGTYPE".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Command"));
        assert!(dbg.contains("WRONGTYPE"));
    }

    #[test]
    fn error_debug_format_connection() {
        let err = RedisError::Connection("refused".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Connection"));
    }

    #[test]
    fn error_debug_format_unauthorized() {
        let dbg = format!("{:?}", RedisError::Unauthorized);
        assert!(dbg.contains("Unauthorized"));
    }

    #[test]
    fn error_debug_format_key_not_found() {
        let err = RedisError::KeyNotFound {
            key: "mykey".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("KeyNotFound"));
        assert!(dbg.contains("mykey"));
    }

    #[test]
    fn error_debug_format_type_mismatch() {
        let err = RedisError::TypeMismatch {
            expected: "string".into(),
            actual: "list".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TypeMismatch"));
    }

    #[test]
    fn error_debug_format_timeout() {
        let err = RedisError::Timeout("30s".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Timeout"));
    }

    #[test]
    fn error_debug_format_rate_limited() {
        let err = RedisError::RateLimited {
            retry_after_ms: 5000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimited"));
        assert!(dbg.contains("5000"));
    }

    #[test]
    fn error_debug_format_api() {
        let err = RedisError::Api {
            status_code: 503,
            message: "unavailable".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Api"));
        assert!(dbg.contains("503"));
    }

    #[test]
    fn json_not_retryable() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert!(!RedisError::Json(bad.unwrap_err()).is_retryable());
    }

    #[test]
    fn retry_after_none_for_json_error() {
        let bad: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        assert_eq!(RedisError::Json(bad.unwrap_err()).retry_after(), None);
    }

    // ===== Helper =====

    fn tokio_runtime() -> fcp_async_core::runtime::Runtime {
        fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
}
