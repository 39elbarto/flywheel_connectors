//! Structured logging with JSON output and sensitive data redaction.

use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    prelude::*,
};

use crate::{TelemetryConfig, TelemetryError};

/// Initialize the logging subsystem.
///
/// # Errors
/// Returns `TelemetryError::LoggingInit` if the subscriber cannot be installed.
pub fn init_logging(config: &TelemetryConfig) -> Result<(), TelemetryError> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    if config.json_logs {
        let json_layer = fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE);

        subscriber
            .with(json_layer)
            .try_init()
            .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
    } else {
        let pretty_layer = fmt::layer()
            .with_ansi(true)
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_span_events(FmtSpan::CLOSE);

        subscriber
            .with(pretty_layer)
            .try_init()
            .map_err(|e| TelemetryError::LoggingInit(e.to_string()))?;
    }

    Ok(())
}

/// Redact sensitive fields from a JSON value.
#[must_use]
pub fn redact_sensitive(value: &serde_json::Value, fields: &[String]) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                if fields
                    .iter()
                    .any(|f| key.to_lowercase().contains(&f.to_lowercase()))
                {
                    result.insert(
                        key.clone(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                } else {
                    result.insert(key.clone(), redact_sensitive(val, fields));
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| redact_sensitive(v, fields)).collect())
        }
        other => other.clone(),
    }
}

/// Log a structured event with automatic field injection.
#[macro_export]
macro_rules! log_event {
    ($level:ident, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::$level!(
            message = $message,
            $($key = %$value,)*
        );
    };
}

/// Log an error with context.
#[macro_export]
macro_rules! log_error {
    ($err:expr, $message:expr $(, $key:ident = $value:expr)* $(,)?) => {
        tracing::error!(
            error = %$err,
            error_type = %std::any::type_name_of_val(&$err),
            message = $message,
            $($key = %$value,)*
        );
    };
}

/// Log a request/response pair.
pub fn log_request_response(
    operation: &str,
    request: &serde_json::Value,
    response: &serde_json::Value,
    duration_ms: u64,
    success: bool,
) {
    let redact_fields = vec![
        "password".to_string(),
        "api_key".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "authorization".to_string(),
    ];

    let redacted_request = redact_sensitive(request, &redact_fields);
    let redacted_response = redact_sensitive(response, &redact_fields);

    if success {
        tracing::info!(
            operation = operation,
            request = %redacted_request,
            response = %redacted_response,
            duration_ms = duration_ms,
            "Request completed successfully"
        );
    } else {
        tracing::warn!(
            operation = operation,
            request = %redacted_request,
            response = %redacted_response,
            duration_ms = duration_ms,
            "Request completed with error"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_sensitive() {
        let value = json!({
            "user": "john",
            "password": "secret123",
            "api_key": "key-abc",
            "data": {
                "token": "tok-xyz",
                "name": "test"
            }
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "password".to_string(),
                "api_key".to_string(),
                "token".to_string(),
            ],
        );

        assert_eq!(redacted["user"], "john");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["data"]["token"], "[REDACTED]");
        assert_eq!(redacted["data"]["name"], "test");
    }

    #[test]
    fn test_redact_nested_array() {
        let value = json!({
            "users": [
                {"name": "john", "password": "pass1"},
                {"name": "jane", "password": "pass2"}
            ]
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["users"][0]["name"], "john");
        assert_eq!(redacted["users"][0]["password"], "[REDACTED]");
        assert_eq!(redacted["users"][1]["name"], "jane");
        assert_eq!(redacted["users"][1]["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_case_insensitive() {
        let value = json!({
            "PASSWORD": "secret1",
            "Password": "secret2",
            "password": "secret3",
            "user_password": "secret4"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // All variations should be redacted due to case-insensitive contains check
        assert_eq!(redacted["PASSWORD"], "[REDACTED]");
        assert_eq!(redacted["Password"], "[REDACTED]");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["user_password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_partial_match() {
        let value = json!({
            "api_key_id": "key-123",
            "secret_token": "tok-456",
            "authorization_header": "Bearer xyz"
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "key".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        );

        assert_eq!(redacted["api_key_id"], "[REDACTED]");
        assert_eq!(redacted["secret_token"], "[REDACTED]");
        assert_eq!(redacted["authorization_header"], "[REDACTED]");
    }

    #[test]
    fn test_redact_deeply_nested() {
        let value = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "password": "deep-secret"
                        }
                    }
                }
            }
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(
            redacted["level1"]["level2"]["level3"]["level4"]["password"],
            "[REDACTED]"
        );
    }

    #[test]
    fn test_redact_array_of_arrays() {
        let value = json!({
            "matrix": [
                [{"password": "p1"}, {"password": "p2"}],
                [{"password": "p3"}, {"safe": "data"}]
            ]
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["matrix"][0][0]["password"], "[REDACTED]");
        assert_eq!(redacted["matrix"][0][1]["password"], "[REDACTED]");
        assert_eq!(redacted["matrix"][1][0]["password"], "[REDACTED]");
        assert_eq!(redacted["matrix"][1][1]["safe"], "data");
    }

    #[test]
    fn test_redact_preserves_primitives() {
        let value = json!({
            "string": "hello",
            "number": 42,
            "float": 1.234,
            "boolean": true,
            "null_value": null
        });

        let redacted = redact_sensitive(&value, &["nonexistent".to_string()]);

        assert_eq!(redacted["string"], "hello");
        assert_eq!(redacted["number"], 42);
        assert_eq!(redacted["float"], 1.234);
        assert_eq!(redacted["boolean"], true);
        assert!(redacted["null_value"].is_null());
    }

    #[test]
    fn test_redact_empty_object() {
        let value = json!({});
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!({}));
    }

    #[test]
    fn test_redact_empty_array() {
        let value = json!([]);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!([]));
    }

    #[test]
    fn test_redact_no_fields() {
        let value = json!({"safe": "data", "also_safe": "more data"});
        let redacted = redact_sensitive(&value, &[]);
        assert_eq!(redacted["safe"], "data");
        assert_eq!(redacted["also_safe"], "more data");
    }

    #[test]
    fn test_redact_multiple_sensitive_fields() {
        let value = json!({
            "credentials": {
                "password": "pass123",
                "api_key": "key456",
                "secret": "sec789",
                "token": "tok012",
                "authorization": "auth345"
            }
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "password".to_string(),
                "api_key".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "authorization".to_string(),
            ],
        );

        assert_eq!(redacted["credentials"]["password"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["api_key"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["secret"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["token"], "[REDACTED]");
        assert_eq!(redacted["credentials"]["authorization"], "[REDACTED]");
    }

    #[test]
    fn test_redact_primitive_value() {
        // Redacting a primitive should return it unchanged
        let value = json!("just a string");
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, "just a string");

        let number = json!(42);
        let redacted_num = redact_sensitive(&number, &["password".to_string()]);
        assert_eq!(redacted_num, 42);
    }

    #[test]
    fn test_redact_array_of_primitives() {
        let value = json!(["one", "two", "three"]);
        let redacted = redact_sensitive(&value, &["password".to_string()]);
        assert_eq!(redacted, json!(["one", "two", "three"]));
    }

    #[test]
    fn test_redact_mixed_array() {
        let value = json!([
            "string",
            42,
            {"password": "secret"},
            null,
            true
        ]);

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted[0], "string");
        assert_eq!(redacted[1], 42);
        assert_eq!(redacted[2]["password"], "[REDACTED]");
        assert!(redacted[3].is_null());
        assert_eq!(redacted[4], true);
    }

    #[test]
    fn test_redact_fcp_standard_fields() {
        // Test with the default FCP redaction fields
        let fcp_redact_fields = vec![
            "password".to_string(),
            "api_key".to_string(),
            "secret".to_string(),
            "token".to_string(),
            "authorization".to_string(),
        ];

        let value = json!({
            "request": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                },
                "body": {
                    "user": "admin",
                    "password": "admin123",
                    "api_key": "sk-1234567890"
                }
            },
            "response": {
                "access_token": "at_abc123",
                "refresh_token": "rt_xyz789"
            }
        });

        let redacted = redact_sensitive(&value, &fcp_redact_fields);

        // Headers with Authorization
        assert_eq!(
            redacted["request"]["headers"]["Authorization"],
            "[REDACTED]"
        );
        // Body fields
        assert_eq!(redacted["request"]["body"]["user"], "admin");
        assert_eq!(redacted["request"]["body"]["password"], "[REDACTED]");
        assert_eq!(redacted["request"]["body"]["api_key"], "[REDACTED]");
        // Response tokens
        assert_eq!(redacted["response"]["access_token"], "[REDACTED]");
        assert_eq!(redacted["response"]["refresh_token"], "[REDACTED]");
    }

    // ============ Unicode and edge case tests ============

    #[test]
    fn test_redact_unicode_field_names() {
        let value = json!({
            "密码": "secret123",  // Chinese for "password"
            "パスワード": "secret456",  // Japanese for "password"
            "пароль": "secret789",  // Russian for "password"
            "normal_field": "visible"
        });

        // Should not redact these since our patterns are ASCII
        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["密码"], "secret123");
        assert_eq!(redacted["パスワード"], "secret456");
        assert_eq!(redacted["пароль"], "secret789");
        assert_eq!(redacted["normal_field"], "visible");
    }

    #[test]
    fn test_redact_unicode_field_values() {
        let value = json!({
            "password": "密码🔐secure",  // Unicode value with emoji
            "message": "Hello 世界 🌍"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["message"], "Hello 世界 🌍");
    }

    #[test]
    fn test_redact_empty_string_value() {
        let value = json!({
            "password": "",
            "api_key": ""
        });

        let redacted = redact_sensitive(&value, &["password".to_string(), "api_key".to_string()]);

        // Empty strings in sensitive fields should still be redacted
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
    }

    #[test]
    fn test_redact_numeric_sensitive_values() {
        let value = json!({
            "password": 12345,  // Numeric password (bad practice but possible)
            "token": 999_999,
            "user_id": 42
        });

        let redacted = redact_sensitive(&value, &["password".to_string(), "token".to_string()]);

        // Numeric values in sensitive fields should be redacted
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["token"], "[REDACTED]");
        assert_eq!(redacted["user_id"], 42);
    }

    #[test]
    fn test_redact_boolean_sensitive_values() {
        let value = json!({
            "has_secret": true,  // Field name contains "secret"
            "is_active": true
        });

        let redacted = redact_sensitive(&value, &["secret".to_string()]);

        assert_eq!(redacted["has_secret"], "[REDACTED]");
        assert_eq!(redacted["is_active"], true);
    }

    #[test]
    fn test_redact_null_sensitive_values() {
        let value = json!({
            "password": null,
            "name": null
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // Null values in sensitive fields should be redacted
        assert_eq!(redacted["password"], "[REDACTED]");
        assert!(redacted["name"].is_null());
    }

    #[test]
    fn test_redact_object_in_sensitive_field() {
        let value = json!({
            "secret_config": {
                "key": "value",
                "nested": "data"
            },
            "public_config": {
                "setting": "visible"
            }
        });

        let redacted = redact_sensitive(&value, &["secret".to_string()]);

        // Entire object should be redacted when field name matches
        assert_eq!(redacted["secret_config"], "[REDACTED]");
        assert_eq!(redacted["public_config"]["setting"], "visible");
    }

    #[test]
    fn test_redact_array_in_sensitive_field() {
        let value = json!({
            "api_keys": ["key1", "key2", "key3"],
            "names": ["alice", "bob"]
        });

        let redacted = redact_sensitive(&value, &["key".to_string()]);

        // Entire array should be redacted when field name matches
        assert_eq!(redacted["api_keys"], "[REDACTED]");
        assert_eq!(redacted["names"], json!(["alice", "bob"]));
    }

    #[test]
    fn test_redact_very_long_field_name() {
        let long_key = format!("password_{}", "x".repeat(1000));
        let value = json!({
            long_key.clone(): "secret"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted[&long_key], "[REDACTED]");
    }

    #[test]
    fn test_redact_very_long_value() {
        let long_value = "secret".repeat(10000);
        let value = json!({
            "password": long_value
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_special_json_characters() {
        let value = json!({
            "password": "secret\"with\\special\nchars\t",
            "message": "normal\"text"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["message"], "normal\"text");
    }

    #[test]
    fn test_redact_preserves_object_key_order() {
        // Note: serde_json uses BTreeMap internally, so order is alphabetical
        let value = json!({
            "zebra": "last",
            "apple": "first",
            "password": "secret",
            "middle": "middle"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // All keys should still be present
        assert!(redacted.get("zebra").is_some());
        assert!(redacted.get("apple").is_some());
        assert!(redacted.get("middle").is_some());
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_with_regex_like_patterns() {
        // Field patterns that look like regex but should be treated literally
        let value = json!({
            "pass.*word": "should_not_match",
            "password": "should_match"
        });

        // The pattern should match literally, not as regex
        let redacted = redact_sensitive(&value, &["password".to_string()]);

        assert_eq!(redacted["pass.*word"], "should_not_match");
        assert_eq!(redacted["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_concurrent_field_matches() {
        // Field that matches multiple patterns
        let value = json!({
            "api_key_token_secret": "ultra_sensitive"
        });

        let redacted = redact_sensitive(
            &value,
            &[
                "api".to_string(),
                "key".to_string(),
                "token".to_string(),
                "secret".to_string(),
            ],
        );

        // Should be redacted (matches all patterns, but only needs one)
        assert_eq!(redacted["api_key_token_secret"], "[REDACTED]");
    }

    #[test]
    fn test_redact_whitespace_in_field_names() {
        let value = json!({
            "pass word": "with space",
            "password": "no space"
        });

        let redacted = redact_sensitive(&value, &["password".to_string()]);

        // "pass word" should not match "password" pattern
        assert_eq!(redacted["pass word"], "with space");
        assert_eq!(redacted["password"], "[REDACTED]");
    }
}
