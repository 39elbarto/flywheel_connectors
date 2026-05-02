//! FCP Whisper Audio Transcription Connector library.

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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::client::{DEFAULT_BASE_URL, WhisperAuth, WhisperClient};
    use crate::connector::WhisperConnector;
    use crate::error::WhisperError;
    use crate::types::{
        ApiErrorDetail, ApiErrorResponse, AudioFormat, TranscribeRequest, TranscriptionResult,
        TranscriptionSegment, TranslateRequest, TranslationResult, VerboseTranscription,
        WhisperModel, WordTimestamp,
    };

    // ===== Config parsing tests =====

    #[test]
    fn config_from_api_key() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "sk-test-key" })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_from_credential_id() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "api_key": "sk-key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({})));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "" })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "   " })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "credential_id": 12345 })));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "credential_id": "not-a-uuid" })));
        assert!(result.is_err());
    }

    #[test]
    fn config_custom_base_url() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({
            "api_key": "sk-key",
            "base_url": "https://custom-whisper.example.com/v1"
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn config_default_base_url() {
        let client = WhisperClient::new(WhisperAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn config_trims_api_key() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_configure(json!({ "api_key": "  sk-key  " })));
        assert!(result.is_ok());
    }

    // ===== Error type Display tests =====

    #[test]
    fn error_display_connection() {
        let err = WhisperError::Connection("connection refused".into());
        assert_eq!(
            err.to_string(),
            "Whisper API connection error: connection refused"
        );
    }

    #[test]
    fn error_display_auth() {
        let err = WhisperError::Auth("invalid key".into());
        assert_eq!(err.to_string(), "Whisper authentication error: invalid key");
    }

    #[test]
    fn error_display_transcription() {
        let err = WhisperError::Transcription("failed to decode".into());
        assert_eq!(
            err.to_string(),
            "Whisper transcription error: failed to decode"
        );
    }

    #[test]
    fn error_display_unsupported_format() {
        let err = WhisperError::UnsupportedFormat("aac".into());
        assert_eq!(err.to_string(), "Whisper unsupported format: aac");
    }

    #[test]
    fn error_display_file_too_large() {
        let err = WhisperError::FileTooLarge {
            size_bytes: 30_000_000,
            max_bytes: 25_000_000,
        };
        assert!(err.to_string().contains("30000000"));
        assert!(err.to_string().contains("25000000"));
    }

    #[test]
    fn error_display_model_not_found() {
        let err = WhisperError::ModelNotFound("whisper-99".into());
        assert_eq!(err.to_string(), "Whisper model not found: whisper-99");
    }

    #[test]
    fn error_display_timeout() {
        let err = WhisperError::Timeout("120s exceeded".into());
        assert_eq!(err.to_string(), "Whisper timeout: 120s exceeded");
    }

    #[test]
    fn error_display_rate_limited() {
        let err = WhisperError::RateLimited {
            retry_after_ms: 5000,
        };
        assert_eq!(err.to_string(), "Whisper rate limited (retry after 5000ms)");
    }

    #[test]
    fn error_display_invalid_audio() {
        let err = WhisperError::InvalidAudio("empty data".into());
        assert_eq!(err.to_string(), "Whisper invalid audio: empty data");
    }

    #[test]
    fn error_display_api() {
        let err = WhisperError::Api {
            status_code: 500,
            message: "Internal Server Error".into(),
        };
        assert_eq!(
            err.to_string(),
            "Whisper API error (500): Internal Server Error"
        );
    }

    // ===== Error retryable tests =====

    #[test]
    fn rate_limited_is_retryable() {
        assert!(
            WhisperError::RateLimited {
                retry_after_ms: 5000
            }
            .is_retryable()
        );
    }

    #[test]
    fn connection_is_retryable() {
        assert!(WhisperError::Connection("err".into()).is_retryable());
    }

    #[test]
    fn timeout_is_retryable() {
        assert!(WhisperError::Timeout("err".into()).is_retryable());
    }

    #[test]
    fn api_500_is_retryable() {
        assert!(
            WhisperError::Api {
                status_code: 500,
                message: "err".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_503_is_retryable() {
        assert!(
            WhisperError::Api {
                status_code: 503,
                message: "unavailable".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_429_is_retryable() {
        assert!(
            WhisperError::Api {
                status_code: 429,
                message: "too many".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_502_is_retryable() {
        assert!(
            WhisperError::Api {
                status_code: 502,
                message: "bad gateway".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_504_is_retryable() {
        assert!(
            WhisperError::Api {
                status_code: 504,
                message: "gateway timeout".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn auth_not_retryable() {
        assert!(!WhisperError::Auth("bad key".into()).is_retryable());
    }

    #[test]
    fn transcription_not_retryable() {
        assert!(!WhisperError::Transcription("decode fail".into()).is_retryable());
    }

    #[test]
    fn unsupported_format_not_retryable() {
        assert!(!WhisperError::UnsupportedFormat("aac".into()).is_retryable());
    }

    #[test]
    fn file_too_large_not_retryable() {
        assert!(
            !WhisperError::FileTooLarge {
                size_bytes: 30_000_000,
                max_bytes: 25_000_000
            }
            .is_retryable()
        );
    }

    #[test]
    fn model_not_found_not_retryable() {
        assert!(!WhisperError::ModelNotFound("x".into()).is_retryable());
    }

    #[test]
    fn invalid_audio_not_retryable() {
        assert!(!WhisperError::InvalidAudio("bad".into()).is_retryable());
    }

    #[test]
    fn api_400_not_retryable() {
        assert!(
            !WhisperError::Api {
                status_code: 400,
                message: "bad request".into()
            }
            .is_retryable()
        );
    }

    #[test]
    fn api_422_not_retryable() {
        assert!(
            !WhisperError::Api {
                status_code: 422,
                message: "unprocessable".into()
            }
            .is_retryable()
        );
    }

    // ===== Error retry_after tests =====

    #[test]
    fn retry_after_for_rate_limited() {
        let err = WhisperError::RateLimited {
            retry_after_ms: 30_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn retry_after_none_for_auth() {
        assert_eq!(WhisperError::Auth("err".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_connection() {
        assert_eq!(WhisperError::Connection("err".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_timeout() {
        assert_eq!(WhisperError::Timeout("err".into()).retry_after(), None);
    }

    #[test]
    fn retry_after_none_for_transcription() {
        assert_eq!(
            WhisperError::Transcription("err".into()).retry_after(),
            None
        );
    }

    #[test]
    fn retry_after_zero_ms() {
        let err = WhisperError::RateLimited { retry_after_ms: 0 };
        assert_eq!(err.retry_after(), Some(Duration::from_millis(0)));
    }

    #[test]
    fn retry_after_large_value() {
        let err = WhisperError::RateLimited {
            retry_after_ms: 3_600_000,
        };
        assert_eq!(err.retry_after(), Some(Duration::from_secs(3600)));
    }

    // ===== Error to_fcp_error tests =====

    #[test]
    fn auth_to_fcp_error() {
        match WhisperError::Auth("bad key".into()).to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "whisper");
                assert_eq!(status_code, Some(401));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_to_fcp_error() {
        match (WhisperError::RateLimited {
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
    fn connection_to_fcp_error() {
        match WhisperError::Connection("refused".into()).to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "whisper");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn transcription_to_fcp_error() {
        match WhisperError::Transcription("decode fail".into()).to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "whisper");
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_format_to_fcp_error() {
        match WhisperError::UnsupportedFormat("aac".into()).to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                ..
            } => {
                assert_eq!(service, "whisper");
                assert_eq!(status_code, Some(400));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn file_too_large_to_fcp_error() {
        match (WhisperError::FileTooLarge {
            size_bytes: 30_000_000,
            max_bytes: 25_000_000,
        })
        .to_fcp_error()
        {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "whisper");
                assert_eq!(status_code, Some(413));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn model_not_found_to_fcp_error() {
        match WhisperError::ModelNotFound("whisper-99".into()).to_fcp_error() {
            FcpError::External {
                status_code,
                message,
                ..
            } => {
                assert_eq!(status_code, Some(404));
                assert!(message.contains("whisper-99"));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn timeout_to_fcp_error() {
        match WhisperError::Timeout("120s".into()).to_fcp_error() {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "whisper");
                assert!(retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn invalid_audio_to_fcp_error() {
        match WhisperError::InvalidAudio("empty".into()).to_fcp_error() {
            FcpError::External {
                service,
                status_code,
                retryable,
                ..
            } => {
                assert_eq!(service, "whisper");
                assert_eq!(status_code, Some(400));
                assert!(!retryable);
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn api_error_to_fcp_error() {
        match (WhisperError::Api {
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
                assert_eq!(service, "whisper");
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
        match WhisperError::Json(bad.unwrap_err()).to_fcp_error() {
            FcpError::Internal { message } => assert!(message.starts_with("JSON error:")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ===== Client construction tests =====

    #[test]
    fn client_new_default_url() {
        let client = WhisperClient::new(WhisperAuth::ApiKey("sk-key".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn client_new_custom_url() {
        let client = WhisperClient::new(
            WhisperAuth::ApiKey("sk-key".into()),
            Some("https://custom-api.example.com/v1/"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("https://custom-api.example.com/v1"));
        assert!(!dbg.contains("https://custom-api.example.com/v1/"));
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = WhisperClient::new(
            WhisperAuth::ApiKey("k".into()),
            Some("https://example.com///"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("///"));
    }

    #[test]
    fn client_debug_redacts_key() {
        let client =
            WhisperClient::new(WhisperAuth::ApiKey("sk-supersecretkey123".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("sk-supersecretkey123"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_new_with_credential_id() {
        let cred = CredentialId::new();
        let client = WhisperClient::new(WhisperAuth::CredentialId(cred), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = WhisperClient::new(WhisperAuth::ApiKey("k".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("WhisperClient"));
        assert!(dbg.contains("base_url"));
    }

    // ===== Auth tests =====

    #[test]
    fn auth_debug_redacts_key() {
        let auth = WhisperAuth::ApiKey("sk-secret-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("sk-secret-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = WhisperAuth::ApiKey("sk-key".into());
        assert!(!key.is_secretless());
        let cred = WhisperAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_key() {
        let auth = WhisperAuth::ApiKey("sk-key".into());
        assert_eq!(auth.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let auth = WhisperAuth::CredentialId(CredentialId::new());
        let label = auth.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn auth_clone() {
        let auth = WhisperAuth::ApiKey("sk-key123".into());
        let cloned = auth.clone();
        drop(auth);
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = WhisperAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        drop(auth);
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_debug_shows_tuple_name() {
        let auth = WhisperAuth::ApiKey("secret".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ApiKey"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let auth = WhisperAuth::CredentialId(CredentialId::new());
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("CredentialId"));
    }

    // ===== Default base URL tests =====

    #[test]
    fn default_base_url_is_openai() {
        assert!(DEFAULT_BASE_URL.contains("openai.com"));
    }

    #[test]
    fn default_base_url_is_https() {
        assert!(DEFAULT_BASE_URL.starts_with("https://"));
    }

    #[test]
    fn default_base_url_ends_with_v1() {
        assert!(DEFAULT_BASE_URL.ends_with("/v1"));
    }

    // ===== Connector lifecycle tests =====

    #[test]
    fn connector_default() {
        let c = WhisperConnector::default();
        let rt = tokio_runtime();
        let health = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(health["status"], "unconfigured");
    }

    #[test]
    fn connector_new_eq_default() {
        let a = WhisperConnector::new();
        let b = WhisperConnector::default();
        let rt = tokio_runtime();
        let ha = rt.block_on(a.handle_health()).unwrap();
        let hb = rt.block_on(b.handle_health()).unwrap();
        assert_eq!(ha["status"], hb["status"]);
    }

    #[test]
    fn health_unconfigured() {
        let c = WhisperConnector::new();
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
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["status"], "degraded");
        assert_eq!(h["configured"], true);
        assert_eq!(h["handshaken"], false);
    }

    #[test]
    fn health_fully_connected() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
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
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })));
        assert!(result.is_err());
    }

    #[test]
    fn handshake_response_fields() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        let resp = rt
            .block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        assert_eq!(resp["protocol_version"], "2.0");
        assert_eq!(resp["connector_id"], "fcp.whisper");
        assert_eq!(resp["connector_version"], "0.1.0");
        let caps = resp["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 8);
    }

    #[test]
    fn handshake_capabilities_contains_all_ops() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
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
            "whisper.transcribe",
            "whisper.translate",
            "whisper.detect_language",
            "whisper.transcribe_verbose",
            "whisper.list_models",
            "whisper.health",
            "whisper.usage",
            "whisper.formats",
        ] {
            assert!(caps.contains(op), "missing capability: {op}");
        }
    }

    #[test]
    fn handshake_without_session_id() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        let resp = rt.block_on(c.handle_handshake(json!({}))).unwrap();
        assert_eq!(resp["protocol_version"], "2.0");
    }

    // ===== Doctor tests =====

    #[test]
    fn doctor_unconfigured() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(d["status"], "unhealthy");
    }

    #[test]
    fn doctor_configured() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(d["status"], "degraded");
    }

    #[test]
    fn doctor_fully_connected() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        assert_eq!(d["status"], "healthy");
    }

    #[test]
    fn doctor_checks_count() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let d = rt.block_on(c.handle_doctor()).unwrap();
        let checks = d["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 3);
    }

    // ===== Self check tests =====

    #[test]
    fn self_check_unconfigured() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let sc = rt.block_on(c.handle_self_check()).unwrap();
        assert_eq!(sc["status"], "degraded");
        assert_eq!(sc["connector_id"], "fcp.whisper");
        assert_eq!(sc["version"], "0.1.0");
    }

    #[test]
    fn self_check_configured() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        let sc = rt.block_on(c.handle_self_check()).unwrap();
        assert_eq!(sc["status"], "ok");
    }

    // ===== Introspect tests =====

    #[test]
    fn introspect_has_8_operations() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let ops = intr["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn introspect_operations_have_required_fields() {
        let c = WhisperConnector::new();
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
        let c = WhisperConnector::new();
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
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("whisper."),
                "op id should start with 'whisper.': {id}"
            );
        }
    }

    #[test]
    fn introspect_operations_contain_expected_ids() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        let ids: Vec<&str> = intr["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        for expected in &[
            "whisper.transcribe",
            "whisper.translate",
            "whisper.detect_language",
            "whisper.transcribe_verbose",
            "whisper.list_models",
            "whisper.health",
            "whisper.usage",
            "whisper.formats",
        ] {
            assert!(ids.contains(expected), "missing op id: {expected}");
        }
    }

    #[test]
    fn introspect_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let c = WhisperConnector::new();
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
        let c = WhisperConnector::new();
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
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let v = op["idempotency"].as_str().unwrap();
            assert!(valid.contains(&v), "invalid idempotency: {v}");
        }
    }

    #[test]
    fn introspect_all_ops_are_safe() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            assert_eq!(
                op["safety_tier"].as_str().unwrap(),
                "safe",
                "op {} should be safe",
                op["id"]
            );
            assert_eq!(
                op["risk_level"].as_str().unwrap(),
                "low",
                "op {} should be low risk",
                op["id"]
            );
        }
    }

    #[test]
    fn introspect_summaries_non_empty() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        for op in intr["operations"].as_array().unwrap() {
            let s = op["summary"].as_str().unwrap();
            assert!(!s.is_empty(), "empty summary for {}", op["id"]);
        }
    }

    #[test]
    fn introspect_schemas_are_objects() {
        let c = WhisperConnector::new();
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
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let intr = rt.block_on(c.handle_introspect()).unwrap();
        assert_eq!(intr["connector_id"], "fcp.whisper");
        assert_eq!(intr["version"], "0.1.0");
    }

    // ===== Simulate tests =====

    #[test]
    fn simulate_known_operation() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let resp = rt
            .block_on(c.handle_simulate(json!({ "operation_id": "whisper.transcribe" })))
            .unwrap();
        assert_eq!(resp["allowed"], true);
        assert_eq!(resp["reason"], "Operation supported");
    }

    #[test]
    fn simulate_unknown_operation() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let resp = rt
            .block_on(c.handle_simulate(json!({ "operation_id": "whisper.unknown" })))
            .unwrap();
        assert_eq!(resp["allowed"], false);
        assert_eq!(resp["reason"], "Unknown operation");
    }

    #[test]
    fn simulate_empty_operation() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let resp = rt.block_on(c.handle_simulate(json!({}))).unwrap();
        assert_eq!(resp["allowed"], false);
    }

    #[test]
    fn simulate_all_8_operations() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        for op in &[
            "whisper.transcribe",
            "whisper.translate",
            "whisper.detect_language",
            "whisper.transcribe_verbose",
            "whisper.list_models",
            "whisper.health",
            "whisper.usage",
            "whisper.formats",
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
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        rt.block_on(c.handle_shutdown(json!({}))).unwrap();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["status"], "unconfigured");
    }

    #[test]
    fn shutdown_returns_empty_object() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        let resp = rt.block_on(c.handle_shutdown(json!({}))).unwrap();
        assert!(resp.as_object().unwrap().is_empty());
    }

    // ===== Invoke without handshake fails =====

    #[test]
    fn invoke_without_configure_fails() {
        let c = WhisperConnector::new();
        let rt = tokio_runtime();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.transcribe",
            "input": { "audio_base64": "AAAA" }
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_unknown_operation_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.nonexistent",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_missing_operation_id_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({ "input": {} })));
        assert!(result.is_err());
    }

    // ===== Wiremock integration tests for each operation =====

    #[test]
    fn wiremock_transcribe_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Hello world",
                    "language": "en",
                    "duration": 2.5,
                    "segments": []
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["text"], "Hello world");
            assert_eq!(resp["language"], "en");
        });
    }

    #[test]
    fn wiremock_transcribe_with_language() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Bonjour le monde",
                    "language": "fr",
                    "duration": 3.0,
                    "segments": []
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": {
                        "audio_base64": "AAAA",
                        "language": "fr"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(resp["text"], "Bonjour le monde");
            assert_eq!(resp["language"], "fr");
        });
    }

    #[test]
    fn wiremock_transcribe_with_url() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Audio from URL",
                    "language": "en",
                    "duration": 5.0,
                    "segments": []
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": {
                        "audio_url": "https://example.com/audio.mp3"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(resp["text"], "Audio from URL");
        });
    }

    #[test]
    fn wiremock_translate_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/translations"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Hello world",
                    "language": "fr",
                    "duration": 2.5
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.translate",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["text"], "Hello world");
        });
    }

    #[test]
    fn wiremock_detect_language_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Hola",
                    "language": "es",
                    "confidence": 0.95
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.detect_language",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["language"], "es");
        });
    }

    #[test]
    fn wiremock_transcribe_verbose_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Hello world",
                    "language": "en",
                    "duration": 2.5,
                    "segments": [{
                        "id": 0,
                        "start": 0.0,
                        "end": 2.5,
                        "text": "Hello world"
                    }],
                    "words": [{
                        "word": "Hello",
                        "start": 0.0,
                        "end": 1.0
                    }, {
                        "word": "world",
                        "start": 1.0,
                        "end": 2.5
                    }]
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe_verbose",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await
                .unwrap();
            assert_eq!(resp["text"], "Hello world");
            let words = resp["words"].as_array().unwrap();
            assert_eq!(words.len(), 2);
            assert_eq!(words[0]["word"], "Hello");
        });
    }

    #[test]
    fn wiremock_list_models() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.list_models",
                    "input": {}
                }))
                .await
                .unwrap();
            let models = resp["models"].as_array().unwrap();
            assert_eq!(models.len(), 2);
            assert_eq!(models[0]["id"], "whisper-1");
            assert_eq!(models[1]["id"], "whisper-large-v3");
        });
    }

    #[test]
    fn wiremock_health_check_success() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/models"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": [{"id": "whisper-1"}]
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.health",
                    "input": {}
                }))
                .await
                .unwrap();
            assert_eq!(resp["status"], "ok");
            assert_eq!(resp["api_reachable"], true);
        });
    }

    #[test]
    fn wiremock_health_check_failure() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/models"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                    "error": {"message": "Invalid API key", "type": "invalid_request_error"}
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-bad",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.health",
                    "input": {}
                }))
                .await
                .unwrap();
            assert_eq!(resp["status"], "error");
            assert_eq!(resp["api_reachable"], false);
        });
    }

    #[test]
    fn wiremock_usage() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.usage",
                    "input": {}
                }))
                .await
                .unwrap();
            assert_eq!(resp["total_requests"], 1); // The invoke itself counts
            assert_eq!(resp["total_errors"], 0);
        });
    }

    #[test]
    fn wiremock_formats() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.formats",
                    "input": {}
                }))
                .await
                .unwrap();
            let formats = resp["formats"].as_array().unwrap();
            assert_eq!(formats.len(), 9);
            assert_eq!(resp["max_file_size_mb"], 25);

            let exts: Vec<&str> = formats
                .iter()
                .filter_map(|f| f["extension"].as_str())
                .collect();
            assert!(exts.contains(&"mp3"));
            assert!(exts.contains(&"wav"));
            assert!(exts.contains(&"flac"));
            assert!(exts.contains(&"ogg"));
        });
    }

    // ===== Wiremock error handling tests =====

    #[test]
    fn wiremock_transcribe_401_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                    "error": {"message": "Invalid API key", "type": "invalid_request_error"}
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-bad",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_transcribe_429_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(
                    ResponseTemplate::new(429)
                        .set_body_json(json!({
                            "error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}
                        }))
                        .insert_header("retry-after", "30"),
                )
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_transcribe_500_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                    "error": {"message": "Internal server error", "type": "server_error"}
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn wiremock_translate_401_error() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/translations"))
                .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                    "error": {"message": "Invalid API key", "type": "invalid_request_error"}
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-bad",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let result = c
                .handle_invoke(json!({
                    "operation_id": "whisper.translate",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await;
            assert!(result.is_err());
        });
    }

    // ===== Edge case tests =====

    #[test]
    fn invoke_transcribe_no_audio_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.transcribe",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_translate_no_audio_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.translate",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_detect_language_no_audio_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.detect_language",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_transcribe_verbose_no_audio_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.transcribe_verbose",
            "input": {}
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_transcribe_empty_base64_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.transcribe",
            "input": { "audio_base64": "" }
        })));
        assert!(result.is_err());
    }

    #[test]
    fn invoke_transcribe_empty_url_fails() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key" })))
            .unwrap();
        rt.block_on(c.handle_handshake(json!({ "session_id": "s1" })))
            .unwrap();
        let result = rt.block_on(c.handle_invoke(json!({
            "operation_id": "whisper.transcribe",
            "input": { "audio_url": "" }
        })));
        assert!(result.is_err());
    }

    // ===== JSON roundtrip type tests =====

    #[test]
    fn transcribe_request_default() {
        let req = TranscribeRequest::default();
        assert_eq!(req.model, "whisper-1");
        assert!(req.audio_base64.is_none());
        assert!(req.audio_url.is_none());
        assert!(req.language.is_none());
        assert!(req.response_format.is_none());
        assert!(req.temperature.is_none());
    }

    #[test]
    fn transcribe_request_roundtrip() {
        let req = TranscribeRequest {
            audio_base64: Some("AAAA".into()),
            audio_url: None,
            model: "whisper-1".into(),
            language: Some("en".into()),
            response_format: Some("json".into()),
            temperature: Some(0.5),
        };
        let json_val = serde_json::to_value(&req).unwrap();
        let deserialized: TranscribeRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.model, "whisper-1");
        assert_eq!(deserialized.language.as_deref(), Some("en"));
    }

    #[test]
    fn transcription_result_roundtrip() {
        let result = TranscriptionResult {
            text: "Hello world".into(),
            language: Some("en".into()),
            duration_seconds: Some(2.5),
            segments: vec![TranscriptionSegment {
                id: 0,
                start: 0.0,
                end: 2.5,
                text: "Hello world".into(),
                tokens: vec![1, 2, 3],
                temperature: Some(0.0),
                avg_logprob: Some(-0.5),
                no_speech_prob: Some(0.01),
            }],
        };
        let json_val = serde_json::to_value(&result).unwrap();
        let deserialized: TranscriptionResult = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.text, "Hello world");
        assert_eq!(deserialized.segments.len(), 1);
        assert_eq!(deserialized.segments[0].tokens, vec![1, 2, 3]);
    }

    #[test]
    fn transcription_segment_roundtrip() {
        let seg = TranscriptionSegment {
            id: 1,
            start: 1.0,
            end: 3.5,
            text: "test".into(),
            tokens: vec![10, 20],
            temperature: Some(0.2),
            avg_logprob: Some(-1.0),
            no_speech_prob: Some(0.05),
        };
        let json_val = serde_json::to_value(&seg).unwrap();
        let deserialized: TranscriptionSegment = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.id, 1);
        assert!((deserialized.start - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn word_timestamp_roundtrip() {
        let wt = WordTimestamp {
            word: "hello".into(),
            start: 0.0,
            end: 0.5,
        };
        let json_val = serde_json::to_value(&wt).unwrap();
        let deserialized: WordTimestamp = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.word, "hello");
    }

    #[test]
    fn verbose_transcription_roundtrip() {
        let vt = VerboseTranscription {
            text: "Hello world".into(),
            language: Some("en".into()),
            duration: Some(2.5),
            segments: vec![],
            words: vec![WordTimestamp {
                word: "Hello".into(),
                start: 0.0,
                end: 1.0,
            }],
        };
        let json_val = serde_json::to_value(&vt).unwrap();
        let deserialized: VerboseTranscription = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.words.len(), 1);
    }

    #[test]
    fn translate_request_default() {
        let req = TranslateRequest::default();
        assert_eq!(req.model, "whisper-1");
        assert!(req.audio_base64.is_none());
        assert!(req.audio_url.is_none());
        assert!(req.temperature.is_none());
    }

    #[test]
    fn translate_request_roundtrip() {
        let req = TranslateRequest {
            audio_base64: Some("AAAA".into()),
            audio_url: None,
            model: "whisper-1".into(),
            temperature: Some(0.3),
        };
        let json_val = serde_json::to_value(&req).unwrap();
        let deserialized: TranslateRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.model, "whisper-1");
    }

    #[test]
    fn translation_result_roundtrip() {
        let result = TranslationResult {
            text: "Hello world".into(),
            source_language: Some("fr".into()),
            duration_seconds: Some(3.0),
        };
        let json_val = serde_json::to_value(&result).unwrap();
        let deserialized: TranslationResult = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.text, "Hello world");
        assert_eq!(deserialized.source_language.as_deref(), Some("fr"));
    }

    #[test]
    fn whisper_model_roundtrip() {
        let model = WhisperModel {
            id: "whisper-1".into(),
            name: "Whisper V2".into(),
            description: "General-purpose model".into(),
            max_file_size_mb: 25,
            supported_languages: 97,
        };
        let json_val = serde_json::to_value(&model).unwrap();
        let deserialized: WhisperModel = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.id, "whisper-1");
        assert_eq!(deserialized.max_file_size_mb, 25);
    }

    #[test]
    fn audio_format_roundtrip() {
        let fmt = AudioFormat {
            extension: "mp3".into(),
            mime_type: "audio/mpeg".into(),
            description: "MPEG Audio Layer 3".into(),
        };
        let json_val = serde_json::to_value(&fmt).unwrap();
        let deserialized: AudioFormat = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.extension, "mp3");
        assert_eq!(deserialized.mime_type, "audio/mpeg");
    }

    #[test]
    fn api_error_response_roundtrip() {
        let resp: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "message": "Invalid API key",
                "type": "invalid_request_error",
                "code": "invalid_api_key"
            }
        }))
        .unwrap();
        let detail = resp.error.unwrap();
        assert_eq!(detail.message.as_deref(), Some("Invalid API key"));
        assert_eq!(detail.error_type.as_deref(), Some("invalid_request_error"));
        assert_eq!(detail.code.as_deref(), Some("invalid_api_key"));
    }

    #[test]
    fn api_error_response_without_error() {
        let resp: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(resp.error.is_none());
    }

    #[test]
    fn api_error_detail_partial() {
        let detail: ApiErrorDetail = serde_json::from_value(json!({
            "message": "test error"
        }))
        .unwrap();
        assert_eq!(detail.message.as_deref(), Some("test error"));
        assert!(detail.error_type.is_none());
        assert!(detail.code.is_none());
    }

    // ===== Models list content tests =====

    #[test]
    fn list_models_returns_whisper_1() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.list_models",
                    "input": {}
                }))
                .await
                .unwrap();
            let models = resp["models"].as_array().unwrap();
            let ids: Vec<&str> = models.iter().filter_map(|m| m["id"].as_str()).collect();
            assert!(ids.contains(&"whisper-1"));
            assert!(ids.contains(&"whisper-large-v3"));
        });
    }

    #[test]
    fn list_models_max_file_size() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.list_models",
                    "input": {}
                }))
                .await
                .unwrap();
            let models = resp["models"].as_array().unwrap();
            for model in models {
                assert_eq!(model["max_file_size_mb"], 25);
            }
        });
    }

    // ===== Formats content tests =====

    #[test]
    fn formats_contains_all_supported() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.formats",
                    "input": {}
                }))
                .await
                .unwrap();
            let formats = resp["formats"].as_array().unwrap();
            let exts: Vec<&str> = formats
                .iter()
                .filter_map(|f| f["extension"].as_str())
                .collect();
            for expected in &[
                "mp3", "mp4", "mpeg", "mpga", "m4a", "wav", "webm", "flac", "ogg",
            ] {
                assert!(exts.contains(expected), "missing format: {expected}");
            }
        });
    }

    #[test]
    fn formats_have_mime_types() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.formats",
                    "input": {}
                }))
                .await
                .unwrap();
            let formats = resp["formats"].as_array().unwrap();
            for fmt in formats {
                let mime = fmt["mime_type"].as_str().unwrap();
                assert!(mime.contains('/'), "mime_type should contain '/': {mime}");
            }
        });
    }

    #[test]
    fn formats_have_descriptions() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.formats",
                    "input": {}
                }))
                .await
                .unwrap();
            let formats = resp["formats"].as_array().unwrap();
            for fmt in formats {
                let desc = fmt["description"].as_str().unwrap();
                assert!(!desc.is_empty(), "description should not be empty");
            }
        });
    }

    // ===== Reconfigure tests =====

    #[test]
    fn reconfigure_resets_client() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key1" })))
            .unwrap();
        rt.block_on(c.handle_configure(json!({ "api_key": "sk-key2" })))
            .unwrap();
        let h = rt.block_on(c.handle_health()).unwrap();
        assert_eq!(h["configured"], true);
    }

    // ===== Transcription result with empty segments =====

    #[test]
    fn transcription_result_empty_segments_skip() {
        let result = TranscriptionResult {
            text: "Hello".into(),
            language: None,
            duration_seconds: None,
            segments: vec![],
        };
        let json_val = serde_json::to_value(&result).unwrap();
        assert!(json_val.get("segments").is_none());
    }

    #[test]
    fn verbose_transcription_empty_words_skip() {
        let vt = VerboseTranscription {
            text: "Hello".into(),
            language: None,
            duration: None,
            segments: vec![],
            words: vec![],
        };
        let json_val = serde_json::to_value(&vt).unwrap();
        assert!(json_val.get("words").is_none());
        assert!(json_val.get("segments").is_none());
    }

    #[test]
    fn translation_result_no_optional_fields() {
        let result = TranslationResult {
            text: "test".into(),
            source_language: None,
            duration_seconds: None,
        };
        let json_val = serde_json::to_value(&result).unwrap();
        assert!(json_val.get("source_language").is_none());
        assert!(json_val.get("duration_seconds").is_none());
    }

    // ===== Segment field tests =====

    #[test]
    fn segment_no_optional_fields() {
        let seg = TranscriptionSegment {
            id: 0,
            start: 0.0,
            end: 1.0,
            text: "test".into(),
            tokens: vec![],
            temperature: None,
            avg_logprob: None,
            no_speech_prob: None,
        };
        let json_val = serde_json::to_value(&seg).unwrap();
        assert!(json_val.get("temperature").is_none());
        assert!(json_val.get("avg_logprob").is_none());
        assert!(json_val.get("no_speech_prob").is_none());
        assert!(json_val.get("tokens").is_none());
    }

    // ===== Request count tracking =====

    #[test]
    fn request_count_increments() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            // list_models does not need mock, it's hardcoded
            c.handle_invoke(json!({
                "operation_id": "whisper.list_models",
                "input": {}
            }))
            .await
            .unwrap();

            c.handle_invoke(json!({
                "operation_id": "whisper.formats",
                "input": {}
            }))
            .await
            .unwrap();

            let h = c.handle_health().await.unwrap();
            assert_eq!(h["requests"], 2);
        });
    }

    // ===== Usage after errors =====

    #[test]
    fn error_count_increments_on_failure() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mut c = WhisperConnector::new();
            c.handle_configure(json!({ "api_key": "sk-key" }))
                .await
                .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            // This will fail since no audio provided
            let _ = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": {}
                }))
                .await;

            let h = c.handle_health().await.unwrap();
            assert_eq!(h["errors"], 1);
        });
    }

    // ===== Multiple shutdowns =====

    #[test]
    fn double_shutdown_ok() {
        let mut c = WhisperConnector::new();
        let rt = tokio_runtime();
        rt.block_on(c.handle_shutdown(json!({}))).unwrap();
        rt.block_on(c.handle_shutdown(json!({}))).unwrap();
    }

    // ===== Transcribe with segments response =====

    #[test]
    fn wiremock_transcribe_with_segments() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/transcriptions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "First. Second.",
                    "language": "en",
                    "duration": 5.0,
                    "segments": [
                        {"id": 0, "start": 0.0, "end": 2.5, "text": "First."},
                        {"id": 1, "start": 2.5, "end": 5.0, "text": "Second."}
                    ]
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.transcribe",
                    "input": { "audio_base64": "AAAA" }
                }))
                .await
                .unwrap();
            let segments = resp["segments"].as_array().unwrap();
            assert_eq!(segments.len(), 2);
        });
    }

    // ===== Additional coverage tests =====

    #[test]
    fn wiremock_translate_with_url() {
        let rt = tokio_runtime();
        rt.block_on(async {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audio/translations"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "text": "Hello from URL",
                    "language": "de",
                    "duration": 4.0
                })))
                .mount(&mock_server)
                .await;

            let mut c = WhisperConnector::new();
            c.handle_configure(json!({
                "api_key": "sk-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
            c.handle_handshake(json!({ "session_id": "s1" }))
                .await
                .unwrap();

            let resp = c
                .handle_invoke(json!({
                    "operation_id": "whisper.translate",
                    "input": {
                        "audio_url": "https://example.com/audio.wav"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(resp["text"], "Hello from URL");
        });
    }

    #[test]
    fn transcription_result_with_language() {
        let result = TranscriptionResult {
            text: "Hola mundo".into(),
            language: Some("es".into()),
            duration_seconds: Some(1.5),
            segments: vec![],
        };
        let json_val = serde_json::to_value(&result).unwrap();
        assert_eq!(json_val["text"], "Hola mundo");
        assert_eq!(json_val["language"], "es");
    }

    #[test]
    fn transcribe_request_with_url() {
        let req = TranscribeRequest {
            audio_base64: None,
            audio_url: Some("https://example.com/audio.mp3".into()),
            model: "whisper-1".into(),
            language: None,
            response_format: None,
            temperature: None,
        };
        let json_val = serde_json::to_value(&req).unwrap();
        assert_eq!(json_val["audio_url"], "https://example.com/audio.mp3");
        assert!(json_val.get("audio_base64").is_none());
    }

    #[test]
    fn translate_request_with_temperature() {
        let req = TranslateRequest {
            audio_base64: Some("AAAA".into()),
            audio_url: None,
            model: "whisper-1".into(),
            temperature: Some(0.7),
        };
        let json_val = serde_json::to_value(&req).unwrap();
        let temp = json_val["temperature"].as_f64().unwrap();
        assert!((temp - 0.7).abs() < f64::EPSILON);
    }

    // ===== Helper =====

    fn tokio_runtime() -> fcp_async_core::runtime::Runtime {
        fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
}
