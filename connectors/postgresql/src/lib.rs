//! FCP `PostgreSQL` Database Connector library.

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

    use fcp_prelude::{CredentialId, FcpError};
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::client::{DEFAULT_BASE_URL, PostgresAuth, PostgresClient};
    use crate::connector::PostgreSqlConnector;
    use crate::error::PostgresError;
    use crate::types::{
        ApiErrorResponse, BatchRequest, ColumnDetail, ColumnInfo, ExplainResult, IndexInfo,
        PostgresApiResponse, PreparedRequest, QueryParams, QueryResult, TableInfo,
        TransactionRequest,
    };

    // ===== Config parsing tests =====

    #[test]
    fn config_from_api_key() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "test-key" })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_from_credential_id() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({})));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "" })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "   " })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "credential_id": 12345 })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "credential_id": "not-a-uuid" })));
        assert!(result.is_err());
    }

    #[test]
    fn config_custom_base_url() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "api_key": "key",
            "base_url": "https://custom-pg.example.com"
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_default_base_url() {
        let client = PostgresClient::new(PostgresAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn config_trims_api_key() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "  my_key  " })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_strips_trailing_slash_from_base_url() {
        let client =
            PostgresClient::new(PostgresAuth::ApiKey("k".into()), Some("https://pg.test/"))
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://pg.test"));
        assert!(!dbg.contains("https://pg.test/\""));
    }

    // ===== Error type Display tests =====

    #[test]
    fn error_display_connection() {
        let err = PostgresError::Connection("connection refused".into());
        assert_eq!(
            err.to_string(),
            "PostgreSQL connection error: connection refused"
        );
    }

    #[test]
    fn error_display_auth() {
        let err = PostgresError::Auth("invalid token".into());
        assert_eq!(
            err.to_string(),
            "PostgreSQL authentication error: invalid token"
        );
    }

    #[test]
    fn error_display_query() {
        let err = PostgresError::Query("syntax error at position 42".into());
        assert_eq!(
            err.to_string(),
            "PostgreSQL query error: syntax error at position 42"
        );
    }

    #[test]
    fn error_display_transaction() {
        let err = PostgresError::Transaction("deadlock detected".into());
        assert_eq!(
            err.to_string(),
            "PostgreSQL transaction error: deadlock detected"
        );
    }

    #[test]
    fn error_display_schema() {
        let err = PostgresError::Schema("table not found".into());
        assert_eq!(err.to_string(), "PostgreSQL schema error: table not found");
    }

    #[test]
    fn error_display_constraint_violation() {
        let err = PostgresError::ConstraintViolation("unique key violated".into());
        assert_eq!(
            err.to_string(),
            "PostgreSQL constraint violation: unique key violated"
        );
    }

    #[test]
    fn error_display_timeout() {
        let err = PostgresError::Timeout("query exceeded 30s".into());
        assert_eq!(err.to_string(), "PostgreSQL timeout: query exceeded 30s");
    }

    #[test]
    fn error_display_permission_denied() {
        let err = PostgresError::PermissionDenied("read-only user".into());
        assert_eq!(
            err.to_string(),
            "PostgreSQL permission denied: read-only user"
        );
    }

    #[test]
    fn error_display_rate_limited() {
        assert_eq!(
            PostgresError::RateLimited {
                retry_after_ms: 5000
            }
            .to_string(),
            "PostgreSQL rate limited (retry after 5000ms)"
        );
    }

    #[test]
    fn error_display_api() {
        assert_eq!(
            PostgresError::Api {
                status_code: 500,
                message: "internal error".into()
            }
            .to_string(),
            "PostgreSQL API error (500): internal error"
        );
    }

    // ===== Error is_retryable tests =====

    #[test]
    fn error_retryable_connection() {
        assert!(PostgresError::Connection("refused".into()).is_retryable());
    }

    #[test]
    fn error_retryable_timeout() {
        assert!(PostgresError::Timeout("exceeded".into()).is_retryable());
    }

    #[test]
    fn error_retryable_rate_limited() {
        assert!(
            PostgresError::RateLimited {
                retry_after_ms: 1000
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_retryable_api_500() {
        assert!(
            PostgresError::Api {
                status_code: 500,
                message: "internal".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_retryable_api_503() {
        assert!(
            PostgresError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_retryable_api_429() {
        assert!(
            PostgresError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_not_retryable_query() {
        assert!(!PostgresError::Query("syntax error".into()).is_retryable());
    }

    #[test]
    fn error_not_retryable_auth() {
        assert!(!PostgresError::Auth("bad token".into()).is_retryable());
    }

    #[test]
    fn error_not_retryable_permission() {
        assert!(!PostgresError::PermissionDenied("denied".into()).is_retryable());
    }

    #[test]
    fn error_not_retryable_constraint() {
        assert!(!PostgresError::ConstraintViolation("dup".into()).is_retryable());
    }

    #[test]
    fn error_not_retryable_schema() {
        assert!(!PostgresError::Schema("not found".into()).is_retryable());
    }

    #[test]
    fn error_not_retryable_transaction() {
        assert!(!PostgresError::Transaction("deadlock".into()).is_retryable());
    }

    #[test]
    fn error_not_retryable_api_400() {
        assert!(
            !PostgresError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn error_not_retryable_api_404() {
        assert!(
            !PostgresError::Api {
                status_code: 404,
                message: "not found".into()
            }
            .is_retryable()
        );
    }

    // ===== Error retry_after tests =====

    #[test]
    fn error_retry_after_rate_limited() {
        let err = PostgresError::RateLimited {
            retry_after_ms: 3000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn error_retry_after_none_for_query() {
        assert_eq!(PostgresError::Query("err".into()).retry_after(), None);
    }

    #[test]
    fn error_retry_after_none_for_connection() {
        assert_eq!(PostgresError::Connection("err".into()).retry_after(), None);
    }

    #[test]
    fn error_retry_after_none_for_timeout() {
        assert_eq!(PostgresError::Timeout("err".into()).retry_after(), None);
    }

    // ===== Error to_fcp_error tests =====

    #[test]
    fn error_to_fcp_connection() {
        let fcp = PostgresError::Connection("refused".into()).to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "postgresql");
                assert!(retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_auth() {
        let fcp = PostgresError::Auth("bad".into()).to_fcp_error();
        match fcp {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "postgresql");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_query() {
        let fcp = PostgresError::Query("syntax error".into()).to_fcp_error();
        match fcp {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "postgresql");
                assert!(!retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_transaction() {
        let fcp = PostgresError::Transaction("deadlock".into()).to_fcp_error();
        match fcp {
            FcpError::External { service, .. } => {
                assert_eq!(service, "postgresql");
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_schema() {
        let fcp = PostgresError::Schema("not found".into()).to_fcp_error();
        match fcp {
            FcpError::External { service, .. } => {
                assert_eq!(service, "postgresql");
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_constraint_violation() {
        let fcp = PostgresError::ConstraintViolation("dup key".into()).to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(409));
                assert!(!retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_timeout() {
        let fcp = PostgresError::Timeout("exceeded".into()).to_fcp_error();
        match fcp {
            FcpError::External { retryable, .. } => {
                assert!(retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_permission_denied() {
        let fcp = PostgresError::PermissionDenied("read only".into()).to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(403));
                assert!(!retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_rate_limited() {
        let fcp = PostgresError::RateLimited {
            retry_after_ms: 5000,
        }
        .to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                retry_after,
                ..
            } => {
                assert_eq!(status_code, Some(429));
                assert!(retryable);
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_api() {
        let fcp = PostgresError::Api {
            status_code: 502,
            message: "bad gateway".into(),
        }
        .to_fcp_error();
        match fcp {
            FcpError::External {
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(status_code, Some(502));
                assert!(retryable);
            }
            _ => panic!("Expected External"),
        }
    }

    #[test]
    fn error_to_fcp_json() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("bad").unwrap_err();
        let fcp = PostgresError::Json(json_err).to_fcp_error();
        match fcp {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON error"));
            }
            _ => panic!("Expected Internal"),
        }
    }

    // ===== Client construction tests =====

    #[test]
    fn client_new_with_api_key() {
        let client = PostgresClient::new(PostgresAuth::ApiKey("test-key".into()), None);
        assert!(client.is_ok());
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let client = PostgresClient::new(PostgresAuth::CredentialId(cred), None);
        assert!(client.is_ok());
    }

    #[test]
    fn client_new_with_custom_base_url() {
        let client = PostgresClient::new(
            PostgresAuth::ApiKey("key".into()),
            Some("https://my-pg.example.com"),
        );
        assert!(client.is_ok());
        let dbg = format!("{:?}", client.unwrap());
        assert!(dbg.contains("https://my-pg.example.com"));
    }

    #[test]
    fn client_default_base_url_used() {
        let client = PostgresClient::new(PostgresAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("db.example.com"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client =
            PostgresClient::new(PostgresAuth::ApiKey("k".into()), Some("https://pg.test/"))
                .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("pg.test/\""));
    }

    // ===== Auth tests =====

    #[test]
    fn auth_redacted_label_api_key() {
        let auth = PostgresAuth::ApiKey("secret".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential_id() {
        let cred = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = PostgresAuth::CredentialId(cred);
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
        assert!(label.contains("550e8400"));
    }

    #[test]
    fn auth_is_secretless_api_key() {
        assert!(!PostgresAuth::ApiKey("k".into()).is_secretless());
    }

    #[test]
    fn auth_is_secretless_credential_id() {
        let cred = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert!(PostgresAuth::CredentialId(cred).is_secretless());
    }

    #[test]
    fn auth_debug_api_key_redacted() {
        let auth = PostgresAuth::ApiKey("super-secret-key".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("super-secret-key"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = PostgresAuth::CredentialId(cred);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    // ===== Handshake tests =====

    #[test]
    fn handshake_before_configure_fails() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_handshake(json!({})));
        assert!(result.is_err());
    }

    #[test]
    fn handshake_after_configure_succeeds() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_handshake(json!({"session_id": "sess-1"})));
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["connector_id"], "fcp.postgresql");
        assert_eq!(val["protocol_version"], "2.0");
    }

    #[test]
    fn handshake_capabilities_list() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_handshake(json!({}))).unwrap();
        let caps = result["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 12);
        assert!(caps.iter().any(|v| v == "pg.query"));
        assert!(caps.iter().any(|v| v == "pg.execute"));
        assert!(caps.iter().any(|v| v == "pg.explain"));
        assert!(caps.iter().any(|v| v == "pg.schema.tables"));
        assert!(caps.iter().any(|v| v == "pg.schema.columns"));
        assert!(caps.iter().any(|v| v == "pg.schema.indexes"));
        assert!(caps.iter().any(|v| v == "pg.transaction.begin"));
        assert!(caps.iter().any(|v| v == "pg.transaction.commit"));
        assert!(caps.iter().any(|v| v == "pg.transaction.rollback"));
        assert!(caps.iter().any(|v| v == "pg.batch"));
        assert!(caps.iter().any(|v| v == "pg.prepared"));
        assert!(caps.iter().any(|v| v == "pg.health"));
    }

    #[test]
    fn handshake_with_session_id() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        let _ = rt
            .block_on(c.handle_handshake(json!({"session_id": "my-session"})))
            .unwrap();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "healthy");
    }

    #[test]
    fn handshake_without_session_id() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_handshake(json!({}))).unwrap();
        assert_eq!(result["connector_version"], "0.1.0");
    }

    // ===== Health tests =====

    #[test]
    fn health_unconfigured() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "unconfigured");
        assert_eq!(health["configured"], false);
        assert_eq!(health["handshaken"], false);
    }

    #[test]
    fn health_configured_not_handshaken() {
        let c = configured_connector();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["configured"], true);
        assert_eq!(health["handshaken"], false);
    }

    #[test]
    fn health_fully_ready() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        rt.block_on(c.handle_handshake(json!({"session_id": "s"})))
            .unwrap();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["configured"], true);
        assert_eq!(health["handshaken"], true);
    }

    #[test]
    fn health_request_count_zero() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["requests"], 0);
        assert_eq!(health["errors"], 0);
    }

    // ===== Doctor tests =====

    #[test]
    fn doctor_unconfigured() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let doc = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(doc["status"], "unhealthy");
        let checks = doc["checks"].as_array().unwrap();
        assert!(checks.len() >= 3);
    }

    #[test]
    fn doctor_configured_no_handshake() {
        let c = configured_connector();
        let rt = tokio_runtime();
        let doc = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(doc["status"], "degraded");
    }

    #[test]
    fn doctor_fully_healthy() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        rt.block_on(c.handle_handshake(json!({"session_id": "s"})))
            .unwrap();
        let doc = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(doc["status"], "healthy");
    }

    #[test]
    fn doctor_check_names() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let doc = rt.block_on(c.handle_doctor()).unwrap();
        let names: Vec<&str> = doc["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"configuration"));
        assert!(names.contains(&"client_initialized"));
        assert!(names.contains(&"handshake"));
    }

    // ===== Self-check tests =====

    #[test]
    fn self_check_unconfigured() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_self_check()).unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["connector_id"], "fcp.postgresql");
    }

    #[test]
    fn self_check_configured() {
        let c = configured_connector();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_self_check()).unwrap();
        assert_eq!(result["status"], "ok");
    }

    // ===== Introspect tests =====

    #[test]
    fn introspect_returns_all_operations() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_introspect()).unwrap();
        assert_eq!(result["connector_id"], "fcp.postgresql");
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 12);
    }

    #[test]
    fn introspect_operation_ids() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"pg.query"));
        assert!(ids.contains(&"pg.execute"));
        assert!(ids.contains(&"pg.explain"));
        assert!(ids.contains(&"pg.schema.tables"));
        assert!(ids.contains(&"pg.schema.columns"));
        assert!(ids.contains(&"pg.schema.indexes"));
        assert!(ids.contains(&"pg.transaction.begin"));
        assert!(ids.contains(&"pg.transaction.commit"));
        assert!(ids.contains(&"pg.transaction.rollback"));
        assert!(ids.contains(&"pg.batch"));
        assert!(ids.contains(&"pg.prepared"));
        assert!(ids.contains(&"pg.health"));
    }

    #[test]
    fn introspect_has_input_output_schemas() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(
                op.get("input_schema").is_some(),
                "Missing input_schema for {}",
                op["id"]
            );
            assert!(
                op.get("output_schema").is_some(),
                "Missing output_schema for {}",
                op["id"]
            );
        }
    }

    #[test]
    fn introspect_has_safety_tiers() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                tier == "safe" || tier == "risky" || tier == "dangerous",
                "Invalid safety_tier: {tier}"
            );
        }
    }

    #[test]
    fn introspect_read_ops_are_safe() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let safe_ops = [
            "pg.query",
            "pg.explain",
            "pg.schema.tables",
            "pg.schema.columns",
            "pg.schema.indexes",
            "pg.health",
        ];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if safe_ops.contains(&id) {
                assert_eq!(op["safety_tier"], "safe", "{id} should be safe");
            }
        }
    }

    #[test]
    fn introspect_write_ops_are_risky() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let risky_ops = ["pg.execute", "pg.batch", "pg.prepared"];
        for op in ops {
            let id = op["id"].as_str().unwrap();
            if risky_ops.contains(&id) {
                assert_eq!(op["safety_tier"], "risky", "{id} should be risky");
            }
        }
    }

    // ===== Simulate tests =====

    #[test]
    fn simulate_known_operation() {
        let c = ready_connector();
        let rt = tokio_runtime();
        let result = rt
            .block_on(c.handle_simulate(json!({
                "operation_id": "pg.query",
                "input": {"sql": "SELECT 1"}
            })))
            .unwrap();
        assert_eq!(result["allowed"], true);
        assert_eq!(result["capability"], "pg.read");
    }

    #[test]
    fn simulate_before_configure_denied() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt
            .block_on(c.handle_simulate(json!({
                "operation_id": "pg.query",
                "input": {"sql": "SELECT 1"}
            })))
            .unwrap();
        assert_eq!(result["allowed"], false);
        assert_eq!(result["error_code"], "FCP-5002");
        assert!(
            result["reason"]
                .as_str()
                .unwrap()
                .contains("not configured")
        );
    }

    #[test]
    fn simulate_before_handshake_denied() {
        let c = configured_connector();
        let rt = tokio_runtime();
        let result = rt
            .block_on(c.handle_simulate(json!({
                "operation_id": "pg.query",
                "input": {"sql": "SELECT 1"}
            })))
            .unwrap();
        assert_eq!(result["allowed"], false);
        assert_eq!(result["error_code"], "FCP-5003");
        assert!(result["reason"].as_str().unwrap().contains("handshaken"));
    }

    #[test]
    fn simulate_missing_required_input_denied() {
        let c = ready_connector();
        let rt = tokio_runtime();
        let result = rt
            .block_on(c.handle_simulate(json!({"operation_id": "pg.query"})))
            .unwrap();
        assert_eq!(result["allowed"], false);
        assert_eq!(result["error_code"], "FCP-1003");
        assert!(result["reason"].as_str().unwrap().contains("sql"));
    }

    #[test]
    fn simulate_unknown_operation() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt
            .block_on(c.handle_simulate(json!({"operation_id": "pg.nonexistent"})))
            .unwrap();
        assert_eq!(result["allowed"], false);
    }

    #[test]
    fn simulate_all_operations() {
        let c = ready_connector();
        let rt = tokio_runtime();
        let all_ops = [
            ("pg.query", json!({"sql": "SELECT 1"})),
            ("pg.execute", json!({"sql": "UPDATE things SET n = 1"})),
            ("pg.explain", json!({"sql": "SELECT 1"})),
            ("pg.schema.tables", json!({})),
            ("pg.schema.columns", json!({"table": "things"})),
            ("pg.schema.indexes", json!({"table": "things"})),
            ("pg.transaction.begin", json!({})),
            ("pg.transaction.commit", json!({"txn_id": "txn-1"})),
            ("pg.transaction.rollback", json!({"txn_id": "txn-1"})),
            ("pg.batch", json!({"statements": ["SELECT 1", "SELECT 2"]})),
            ("pg.prepared", json!({"name": "lookup_thing"})),
            ("pg.health", json!({})),
        ];
        for (op, input) in all_ops {
            let result = rt
                .block_on(c.handle_simulate(json!({"operation_id": op, "input": input})))
                .unwrap();
            assert_eq!(result["allowed"], true, "simulate should allow {op}");
        }
    }

    #[test]
    fn simulate_empty_operation_id() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt
            .block_on(c.handle_simulate(json!({"operation_id": ""})))
            .unwrap();
        assert_eq!(result["allowed"], false);
    }

    #[test]
    fn simulate_missing_operation_id() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_simulate(json!({}))).unwrap();
        assert_eq!(result["allowed"], false);
    }

    // ===== Shutdown tests =====

    #[test]
    fn shutdown_clears_state() {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        rt.block_on(c.handle_handshake(json!({"session_id": "s"})))
            .unwrap();
        let result = rt.block_on(c.handle_shutdown(json!({}))).unwrap();
        assert_eq!(result, json!({}));
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "unconfigured");
    }

    #[test]
    fn shutdown_unconfigured_is_ok() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_shutdown(json!({})));
        assert!(result.is_ok());
    }

    // ===== Invoke tests — unknown operation =====

    #[test]
    fn invoke_unknown_operation() {
        let c = ready_connector();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "pg.nonexistent",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_missing_operation_id() {
        let c = ready_connector();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_invoke(json!({"input": {}})));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_before_ready_fails() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "pg.query",
            "input": {"sql": "SELECT 1"}
        })));
        assert!(result.is_err());
    }

    // ===== Wiremock tests: pg.query =====

    #[test]
    fn invoke_query_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [{"id": 1, "name": "Alice"}],
                    "columns": [
                        {"name": "id", "data_type": "integer", "nullable": false},
                        {"name": "name", "data_type": "text", "nullable": true}
                    ],
                    "row_count": 1
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT * FROM users WHERE id = $1", "params": [1]}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_query_empty_result() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [],
                    "columns": [],
                    "row_count": 0
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT * FROM empty_table"}
                }))
                .await
                .unwrap();
            let res = &result["result"];
            assert_eq!(res["row_count"], 0);
        });
    }

    #[test]
    fn invoke_query_with_timeout() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [{"count": 42}],
                    "row_count": 1
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT count(*) FROM big_table", "timeout_ms": 5000}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_query_missing_sql() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_query_null_values_in_rows() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [{"id": 1, "email": null}],
                    "row_count": 1
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT id, email FROM users"}
                }))
                .await
                .unwrap();
            let rows = result["result"]["rows"].as_array().unwrap();
            assert_eq!(rows[0]["email"], serde_json::Value::Null);
        });
    }

    #[test]
    fn invoke_query_error_response() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                    "message": "syntax error at position 10",
                    "code": "42601"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELEC * FROM users"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_query_auth_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                    "message": "Invalid API key"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT 1"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_query_rate_limited() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(429))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT 1"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.execute =====

    #[test]
    fn invoke_execute_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "affected_rows": 3
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.execute",
                    "input": {"sql": "UPDATE users SET active = true WHERE role = $1", "params": ["admin"]}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_execute_missing_sql() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.execute",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_execute_no_params() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "affected_rows": 0
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.execute",
                    "input": {"sql": "DELETE FROM logs WHERE created_at < now() - interval '90 days'"}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_execute_constraint_violation() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                    "message": "duplicate key value violates unique constraint",
                    "code": "23505"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.execute",
                    "input": {"sql": "INSERT INTO users (email) VALUES ($1)", "params": ["dup@test.com"]}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.explain =====

    #[test]
    fn invoke_explain_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/explain"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "plan": {
                        "Node Type": "Seq Scan",
                        "Relation Name": "users",
                        "Total Cost": 1.23
                    }
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.explain",
                    "input": {"sql": "SELECT * FROM users"}
                }))
                .await
                .unwrap();
            assert!(result.get("plan").is_some());
        });
    }

    #[test]
    fn invoke_explain_missing_sql() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.explain",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.schema.tables =====

    #[test]
    fn invoke_schema_tables_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/schema/tables"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {"name": "users", "schema": "public", "row_count_estimate": 1000},
                    {"name": "orders", "schema": "public", "row_count_estimate": 5000}
                ])))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.tables",
                    "input": {}
                }))
                .await
                .unwrap();
            assert!(result.get("tables").is_some());
        });
    }

    #[test]
    fn invoke_schema_tables_with_schema_filter() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/schema/tables"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.tables",
                    "input": {"schema": "analytics"}
                }))
                .await
                .unwrap();
            assert!(result.get("tables").is_some());
        });
    }

    #[test]
    fn invoke_schema_tables_empty() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/schema/tables"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.tables",
                    "input": {}
                }))
                .await
                .unwrap();
            let tables = result["tables"].as_array().unwrap();
            assert!(tables.is_empty());
        });
    }

    // ===== Wiremock tests: pg.schema.columns =====

    #[test]
    fn invoke_schema_columns_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/schema/columns"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {"name": "id", "data_type": "integer", "nullable": false, "is_primary_key": true},
                    {"name": "email", "data_type": "text", "nullable": true, "is_primary_key": false}
                ])))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.columns",
                    "input": {"table": "users"}
                }))
                .await
                .unwrap();
            assert!(result.get("columns").is_some());
        });
    }

    #[test]
    fn invoke_schema_columns_missing_table() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.columns",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.schema.indexes =====

    #[test]
    fn invoke_schema_indexes_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/schema/indexes"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {"name": "users_pkey", "table": "users", "columns": ["id"], "unique": true, "type": "btree"},
                    {"name": "users_email_idx", "table": "users", "columns": ["email"], "unique": true, "type": "btree"}
                ])))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.indexes",
                    "input": {"table": "users"}
                }))
                .await
                .unwrap();
            assert!(result.get("indexes").is_some());
        });
    }

    #[test]
    fn invoke_schema_indexes_missing_table() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.indexes",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.transaction.begin =====

    #[test]
    fn invoke_transaction_begin_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/transaction"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "txn_id": "txn-abc-123"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.begin",
                    "input": {}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_transaction_begin_with_isolation() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/transaction"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "txn_id": "txn-456",
                    "isolation_level": "serializable"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.begin",
                    "input": {"isolation_level": "serializable"}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    // ===== Wiremock tests: pg.transaction.commit =====

    #[test]
    fn invoke_transaction_commit_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/transaction"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "status": "committed"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.commit",
                    "input": {"txn_id": "txn-abc-123"}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_transaction_commit_missing_txn_id() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.commit",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.transaction.rollback =====

    #[test]
    fn invoke_transaction_rollback_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/transaction"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "status": "rolled_back"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.rollback",
                    "input": {"txn_id": "txn-abc-123"}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_transaction_rollback_missing_txn_id() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.rollback",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.batch =====

    #[test]
    fn invoke_batch_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/batch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [
                        {"affected_rows": 1},
                        {"affected_rows": 1}
                    ]
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.batch",
                    "input": {
                        "statements": [
                            "INSERT INTO users (name) VALUES ($1)",
                            "INSERT INTO users (name) VALUES ($1)"
                        ],
                        "params": [["Alice"], ["Bob"]]
                    }
                }))
                .await
                .unwrap();
            assert!(result.get("results").is_some());
        });
    }

    #[test]
    fn invoke_batch_missing_statements() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.batch",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_batch_empty_statements() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/batch"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": []
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.batch",
                    "input": {"statements": []}
                }))
                .await
                .unwrap();
            assert!(result.get("results").is_some());
        });
    }

    #[test]
    fn invoke_batch_non_string_statement() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.batch",
                    "input": {"statements": [123, 456]}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: pg.prepared =====

    #[test]
    fn invoke_prepared_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/prepared"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [{"id": 1}],
                    "row_count": 1
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.prepared",
                    "input": {"name": "get_user_by_id", "params": [1]}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    #[test]
    fn invoke_prepared_missing_name() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.prepared",
                    "input": {"params": [1]}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_prepared_no_params() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/prepared"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [],
                    "row_count": 0
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.prepared",
                    "input": {"name": "list_all"}
                }))
                .await
                .unwrap();
            assert!(result.get("result").is_some());
        });
    }

    // ===== Wiremock tests: pg.health =====

    #[test]
    fn invoke_pg_health_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/health"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "status": "ok",
                    "version": "15.2",
                    "uptime_seconds": 86400
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.health",
                    "input": {}
                }))
                .await
                .unwrap();
            assert!(result.get("health").is_some());
        });
    }

    #[test]
    fn invoke_pg_health_server_down() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/health"))
                .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                    "message": "database unavailable"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.health",
                    "input": {}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: error status codes =====

    #[test]
    fn invoke_403_permission_denied() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                    "message": "insufficient privileges"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "DROP TABLE users"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_408_timeout() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(408).set_body_json(json!({
                    "message": "query timed out"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT pg_sleep(300)"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_500_internal_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                    "message": "internal server error"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT 1"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn invoke_empty_error_body() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT 1"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Wiremock tests: response with error field =====

    #[test]
    fn invoke_query_response_with_error_field() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "error": "relation \"nonexistent\" does not exist"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT * FROM nonexistent"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Types serde roundtrip tests =====

    #[test]
    fn query_params_serde_roundtrip() {
        let qp = QueryParams {
            sql: "SELECT $1".into(),
            params: vec![json!(42)],
            timeout_ms: Some(5000),
        };
        let s = serde_json::to_string(&qp).unwrap();
        let qp2: QueryParams = serde_json::from_str(&s).unwrap();
        assert_eq!(qp2.sql, "SELECT $1");
        assert_eq!(qp2.params.len(), 1);
        assert_eq!(qp2.timeout_ms, Some(5000));
    }

    #[test]
    fn query_params_no_timeout() {
        let qp = QueryParams {
            sql: "SELECT 1".into(),
            params: vec![],
            timeout_ms: None,
        };
        let s = serde_json::to_string(&qp).unwrap();
        assert!(!s.contains("timeout_ms"));
    }

    #[test]
    fn query_result_serde_roundtrip() {
        let qr = QueryResult {
            rows: vec![json!({"id": 1})],
            columns: vec![ColumnInfo {
                name: "id".into(),
                data_type: "integer".into(),
                nullable: false,
            }],
            row_count: 1,
        };
        let s = serde_json::to_string(&qr).unwrap();
        let qr2: QueryResult = serde_json::from_str(&s).unwrap();
        assert_eq!(qr2.row_count, 1);
        assert_eq!(qr2.columns[0].name, "id");
    }

    #[test]
    fn column_info_serde_roundtrip() {
        let ci = ColumnInfo {
            name: "email".into(),
            data_type: "text".into(),
            nullable: true,
        };
        let s = serde_json::to_string(&ci).unwrap();
        let ci2: ColumnInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(ci2.name, "email");
        assert!(ci2.nullable);
    }

    #[test]
    fn explain_result_serde_roundtrip() {
        let er = ExplainResult {
            plan: json!({"Node Type": "Seq Scan"}),
        };
        let s = serde_json::to_string(&er).unwrap();
        let er2: ExplainResult = serde_json::from_str(&s).unwrap();
        assert_eq!(er2.plan["Node Type"], "Seq Scan");
    }

    #[test]
    fn table_info_serde_roundtrip() {
        let ti = TableInfo {
            name: "users".into(),
            schema: "public".into(),
            row_count_estimate: 42_000,
        };
        let s = serde_json::to_string(&ti).unwrap();
        let ti2: TableInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(ti2.name, "users");
        assert_eq!(ti2.row_count_estimate, 42_000);
    }

    #[test]
    fn column_detail_serde_roundtrip() {
        let cd = ColumnDetail {
            name: "id".into(),
            data_type: "serial".into(),
            nullable: false,
            default_value: Some("nextval('users_id_seq')".into()),
            is_primary_key: true,
        };
        let s = serde_json::to_string(&cd).unwrap();
        let cd2: ColumnDetail = serde_json::from_str(&s).unwrap();
        assert_eq!(cd2.name, "id");
        assert!(cd2.is_primary_key);
        assert!(cd2.default_value.is_some());
    }

    #[test]
    fn column_detail_no_default() {
        let cd = ColumnDetail {
            name: "email".into(),
            data_type: "text".into(),
            nullable: true,
            default_value: None,
            is_primary_key: false,
        };
        let s = serde_json::to_string(&cd).unwrap();
        assert!(!s.contains("default_value"));
    }

    #[test]
    fn index_info_serde_roundtrip() {
        let ii = IndexInfo {
            name: "users_pkey".into(),
            table: "users".into(),
            columns: vec!["id".into()],
            unique: true,
            index_type: "btree".into(),
        };
        let s = serde_json::to_string(&ii).unwrap();
        let ii2: IndexInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(ii2.name, "users_pkey");
        assert!(ii2.unique);
        assert_eq!(ii2.index_type, "btree");
    }

    #[test]
    fn index_info_multi_column() {
        let ii = IndexInfo {
            name: "idx_composite".into(),
            table: "orders".into(),
            columns: vec!["user_id".into(), "created_at".into()],
            unique: false,
            index_type: "btree".into(),
        };
        let s = serde_json::to_string(&ii).unwrap();
        let ii2: IndexInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(ii2.columns.len(), 2);
    }

    #[test]
    fn transaction_request_serde_roundtrip() {
        let tr = TransactionRequest {
            isolation_level: Some("serializable".into()),
        };
        let s = serde_json::to_string(&tr).unwrap();
        let tr2: TransactionRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(tr2.isolation_level.as_deref(), Some("serializable"));
    }

    #[test]
    fn transaction_request_default() {
        let tr = TransactionRequest::default();
        assert!(tr.isolation_level.is_none());
        let s = serde_json::to_string(&tr).unwrap();
        assert!(!s.contains("isolation_level"));
    }

    #[test]
    fn batch_request_serde_roundtrip() {
        let br = BatchRequest {
            statements: vec!["INSERT INTO t VALUES ($1)".into()],
            params: vec![vec![json!(1)]],
        };
        let s = serde_json::to_string(&br).unwrap();
        let br2: BatchRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(br2.statements.len(), 1);
        assert_eq!(br2.params.len(), 1);
    }

    #[test]
    fn batch_request_no_params() {
        let br = BatchRequest {
            statements: vec!["CREATE TABLE t (id serial)".into()],
            params: vec![],
        };
        let s = serde_json::to_string(&br).unwrap();
        let br2: BatchRequest = serde_json::from_str(&s).unwrap();
        assert!(br2.params.is_empty());
    }

    #[test]
    fn prepared_request_serde_roundtrip() {
        let pr = PreparedRequest {
            name: "get_user".into(),
            params: vec![json!(1), json!("active")],
        };
        let s = serde_json::to_string(&pr).unwrap();
        let pr2: PreparedRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(pr2.name, "get_user");
        assert_eq!(pr2.params.len(), 2);
    }

    #[test]
    fn prepared_request_no_params() {
        let pr = PreparedRequest {
            name: "list_all".into(),
            params: vec![],
        };
        let s = serde_json::to_string(&pr).unwrap();
        let pr2: PreparedRequest = serde_json::from_str(&s).unwrap();
        assert!(pr2.params.is_empty());
    }

    #[test]
    fn api_response_with_result() {
        let resp: PostgresApiResponse = serde_json::from_value(json!({
            "result": {"rows": [{"id": 1}]},
            "error": null,
            "code": null
        }))
        .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn api_response_with_error() {
        let resp: PostgresApiResponse = serde_json::from_value(json!({
            "result": null,
            "error": "relation does not exist",
            "code": "42P01"
        }))
        .unwrap();
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_deref(), Some("relation does not exist"));
        assert_eq!(resp.code.as_deref(), Some("42P01"));
    }

    #[test]
    fn api_error_response_full() {
        let resp: ApiErrorResponse = serde_json::from_value(json!({
            "message": "duplicate key",
            "code": "23505",
            "details": "Key (id)=(1) already exists"
        }))
        .unwrap();
        assert_eq!(resp.message.as_deref(), Some("duplicate key"));
        assert_eq!(resp.code.as_deref(), Some("23505"));
        assert!(resp.details.is_some());
    }

    #[test]
    fn api_error_response_partial() {
        let resp: ApiErrorResponse = serde_json::from_value(json!({
            "message": "error"
        }))
        .unwrap();
        assert_eq!(resp.message.as_deref(), Some("error"));
        assert!(resp.code.is_none());
        assert!(resp.details.is_none());
    }

    // ===== Default / constructor tests =====

    #[test]
    fn connector_default_impl() {
        let c = PostgreSqlConnector::default();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "unconfigured");
    }

    #[test]
    fn connector_new_returns_unconfigured() {
        let c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["configured"], false);
    }

    // ===== Parameterized queries (SQL injection prevention) =====

    #[test]
    fn parameterized_query_uses_params_array() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .and(body_json(json!({
                    "sql": "SELECT * FROM users WHERE name = $1 AND age > $2",
                    "params": ["Robert'; DROP TABLE users;--", 25]
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [],
                    "row_count": 0
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {
                        "sql": "SELECT * FROM users WHERE name = $1 AND age > $2",
                        "params": ["Robert'; DROP TABLE users;--", 25]
                    }
                }))
                .await
                .unwrap();
            assert_eq!(result["result"]["row_count"], 0);
        });
    }

    // ===== Multiple queries in sequence =====

    #[test]
    fn multiple_queries_in_sequence() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [{"count": 5}],
                    "row_count": 1
                })))
                .expect(2)
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let r1 = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT count(*) FROM users"}
                }))
                .await;
            assert!(r1.is_ok());

            let r2 = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT count(*) FROM orders"}
                }))
                .await;
            assert!(r2.is_ok());
        });
    }

    // ===== Complex response data types =====

    #[test]
    fn query_with_various_data_types() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [{
                        "id": 1,
                        "name": "Alice",
                        "balance": 123.45,
                        "active": true,
                        "tags": ["admin", "user"],
                        "metadata": {"role": "superadmin"},
                        "deleted_at": null
                    }],
                    "row_count": 1
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT * FROM users WHERE id = $1", "params": [1]}
                }))
                .await
                .unwrap();
            let row = &result["result"]["rows"][0];
            assert_eq!(row["id"], 1);
            assert_eq!(row["name"], "Alice");
            assert_eq!(row["active"], true);
            assert!(row["tags"].is_array());
            assert!(row["metadata"].is_object());
            assert!(row["deleted_at"].is_null());
        });
    }

    // ===== Large result sets =====

    #[test]
    fn query_large_result_set() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            let rows: Vec<serde_json::Value> = (0..100)
                .map(|i| json!({"id": i, "name": format!("user_{i}")}))
                .collect();
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": rows,
                    "row_count": 100
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT * FROM users LIMIT 100"}
                }))
                .await
                .unwrap();
            assert_eq!(result["result"]["row_count"], 100);
        });
    }

    // ===== Transaction error handling =====

    #[test]
    fn transaction_error_from_server() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/transaction"))
                .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                    "message": "transaction already committed"
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.transaction.commit",
                    "input": {"txn_id": "expired-txn"}
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Connector reconfiguration =====

    #[test]
    fn reconfigure_resets_client() {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "key-1" })))
            .unwrap();
        rt.block_on(c.handle_configure(json!({ "api_key": "key-2" })))
            .unwrap();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["configured"], true);
    }

    // ===== Empty response body handling =====

    #[test]
    fn handle_empty_success_body() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/health"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.health",
                    "input": {}
                }))
                .await
                .unwrap();
            assert!(result.get("health").is_some());
        });
    }

    // ===== Invoke with default input =====

    #[test]
    fn invoke_with_no_input_field() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/v1/schema/tables"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let result = c
                .handle_invoke(json!({
                    "operation_id": "pg.schema.tables"
                }))
                .await
                .unwrap();
            assert!(result.get("tables").is_some());
        });
    }

    // ===== Auth clone =====

    #[test]
    fn auth_clone_api_key() {
        let auth = PostgresAuth::ApiKey("secret".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "api_key:redacted");
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred = CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let auth = PostgresAuth::CredentialId(cred);
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.is_secretless());
    }

    // ===== QueryResult with empty columns =====

    #[test]
    fn query_result_empty_columns() {
        let qr = QueryResult {
            rows: vec![],
            columns: vec![],
            row_count: 0,
        };
        let s = serde_json::to_string(&qr).unwrap();
        let qr2: QueryResult = serde_json::from_str(&s).unwrap();
        assert!(qr2.columns.is_empty());
        assert!(qr2.rows.is_empty());
    }

    // ===== Index types =====

    #[test]
    fn index_info_gin_type() {
        let ii = IndexInfo {
            name: "idx_tags_gin".into(),
            table: "articles".into(),
            columns: vec!["tags".into()],
            unique: false,
            index_type: "gin".into(),
        };
        let s = serde_json::to_string(&ii).unwrap();
        assert!(s.contains("\"type\":\"gin\""));
    }

    #[test]
    fn index_info_gist_type() {
        let ii = IndexInfo {
            name: "idx_location_gist".into(),
            table: "places".into(),
            columns: vec!["location".into()],
            unique: false,
            index_type: "gist".into(),
        };
        let s = serde_json::to_string(&ii).unwrap();
        let ii2: IndexInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(ii2.index_type, "gist");
    }

    // ===== Batch with params =====

    #[test]
    fn batch_request_multiple_params() {
        let br = BatchRequest {
            statements: vec![
                "INSERT INTO t1 (a) VALUES ($1)".into(),
                "INSERT INTO t2 (b) VALUES ($1)".into(),
            ],
            params: vec![vec![json!(1)], vec![json!("hello")]],
        };
        let s = serde_json::to_string(&br).unwrap();
        let br2: BatchRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(br2.statements.len(), 2);
        assert_eq!(br2.params.len(), 2);
    }

    // ===== Multiple error variant tests =====

    #[test]
    fn error_api_not_retryable_for_4xx() {
        for code in [400u16, 401, 403, 404, 405, 409, 422] {
            let err = PostgresError::Api {
                status_code: code,
                message: "err".into(),
            };
            if code == 429 {
                assert!(err.is_retryable());
            } else {
                assert!(!err.is_retryable(), "code {code} should not be retryable");
            }
        }
    }

    #[test]
    fn error_api_retryable_for_5xx() {
        for code in [500u16, 502, 503, 504] {
            let err = PostgresError::Api {
                status_code: code,
                message: "err".into(),
            };
            assert!(err.is_retryable(), "code {code} should be retryable");
        }
    }

    // ===== Health after invoke tracks request count =====

    #[test]
    fn request_count_increments() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "rows": [],
                    "row_count": 0
                })))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            c.handle_invoke(json!({
                "operation_id": "pg.query",
                "input": {"sql": "SELECT 1"}
            }))
            .await
            .unwrap();

            let health = c.handle_health().await.unwrap();
            assert_eq!(health["requests"], 1);
        });
    }

    #[test]
    fn error_count_increments_on_failure() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/rest/v1/rpc/query"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&mock)
                .await;

            let c = connector_with_mock(&mock);
            let _ = c
                .handle_invoke(json!({
                    "operation_id": "pg.query",
                    "input": {"sql": "SELECT 1"}
                }))
                .await;

            let health = c.handle_health().await.unwrap();
            assert_eq!(health["requests"], 1);
            assert_eq!(health["errors"], 1);
        });
    }

    // ===== Helpers =====

    fn tokio_runtime() -> fcp_async_core::runtime::Runtime {
        fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn configured_connector() -> PostgreSqlConnector {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "test-key" })))
            .unwrap();
        c
    }

    fn ready_connector() -> PostgreSqlConnector {
        let mut c = configured_connector();
        let rt = tokio_runtime();
        rt.block_on(c.handle_handshake(json!({"session_id": "test-session"})))
            .unwrap();
        c
    }

    fn connector_with_mock(mock: &MockServer) -> PostgreSqlConnector {
        let mut c = PostgreSqlConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({
            "api_key": "test-key",
            "base_url": mock.uri()
        })))
        .unwrap();
        rt.block_on(c.handle_handshake(json!({"session_id": "mock-session"})))
            .unwrap();
        c
    }
}
