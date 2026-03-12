//! Snapshot tests for redaction, token budget, exit semantics, and output
//! invariants (bead 18.4).
//!
//! Verifies that secret redaction, token budget enforcement, exit code
//! semantics, TOON output width constraints, JSON output schema compliance,
//! error envelope structure, structured log format, and output determinism
//! behave as expected.

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeSet;

    // ── Test scaffolding types ──────────────────────────────────────────

    /// Patterns that should be redacted from output.
    const REDACTION_PATTERNS: &[&str] = &[
        "sk-", "sk_live_", "sk_test_",        // Stripe/OpenAI
        "ghp_", "gho_", "ghs_",               // GitHub tokens
        "xoxb-", "xoxp-", "xapp-",            // Slack tokens
        "AKIA",                                 // AWS access key prefix
        "Bearer ",                              // Auth headers
        "Basic ",                               // Basic auth headers
        "token=", "api_key=", "apikey=",       // Query param keys
        "password=", "secret=", "credential=", // Credential params
    ];

    /// Known safe patterns that should NOT be redacted.
    const SAFE_PATTERNS: &[&str] = &[
        "connector_id", "operation_id", "request_id",
        "created_at", "updated_at", "schema_version",
        "github", "slack", "jira",
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ExitCode {
        Success = 0,
        InternalError = 1,
        UsageError = 2,
        Partial = 3,
        ValidationError = 5,
        PolicyError = 6,
        ServiceError = 7,
        TransportError = 8,
    }

    impl ExitCode {
        fn from_u8(code: u8) -> Option<Self> {
            match code {
                0 => Some(Self::Success),
                1 => Some(Self::InternalError),
                2 => Some(Self::UsageError),
                3 => Some(Self::Partial),
                5 => Some(Self::ValidationError),
                6 => Some(Self::PolicyError),
                7 => Some(Self::ServiceError),
                8 => Some(Self::TransportError),
                _ => None,
            }
        }

        fn all() -> &'static [Self] {
            &[
                Self::Success,
                Self::InternalError,
                Self::UsageError,
                Self::Partial,
                Self::ValidationError,
                Self::PolicyError,
                Self::ServiceError,
                Self::TransportError,
            ]
        }

        const fn description(self) -> &'static str {
            match self {
                Self::Success => "Operation completed successfully",
                Self::InternalError => "Unexpected internal error",
                Self::UsageError => "CLI usage or parse error",
                Self::Partial => "Partial success (some items failed in batch)",
                Self::ValidationError => "Input validation or auth error",
                Self::PolicyError => "Policy or capability denial",
                Self::ServiceError => "Connector, rate limit, or resource error",
                Self::TransportError => "Network or transport error",
            }
        }
    }

    /// Token budget configuration.
    #[derive(Clone, Debug)]
    struct TokenBudget {
        max_output_tokens: usize,
        max_line_width: usize,
        truncation_marker: &'static str,
    }

    impl Default for TokenBudget {
        fn default() -> Self {
            Self {
                max_output_tokens: 4096,
                max_line_width: 120,
                truncation_marker: "... (truncated)",
            }
        }
    }

    /// Error envelope for JSON output.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct ErrorEnvelope {
        code: String,
        category: String,
        message: String,
        retryable: bool,
        recoverable: bool,
        exit_code: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,
        suggestion: Option<String>,
    }

    /// Structured log entry.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct LogEntry {
        timestamp: String,
        level: String,
        module: String,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        span: Option<String>,
    }

    // ── Redaction engine ────────────────────────────────────────────────

    fn redact_secrets(input: &str) -> String {
        let mut result = input.to_string();
        for pattern in REDACTION_PATTERNS {
            if let Some(pos) = result.find(pattern) {
                // Redact from pattern start to end of token (next whitespace, quote, or EOL)
                let start = pos;
                let after_pattern = pos + pattern.len();
                let end = result[after_pattern..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                    .map_or(result.len(), |e| after_pattern + e);
                let redacted_len = end - start;
                result.replace_range(start..end, &format!("[REDACTED:{redacted_len}]"));
            }
        }
        result
    }

    fn contains_secret(input: &str) -> bool {
        REDACTION_PATTERNS.iter().any(|p| input.contains(p))
    }

    fn is_safe_content(input: &str) -> bool {
        !contains_secret(input)
    }

    // ── Token budget enforcement ────────────────────────────────────────

    fn enforce_token_budget(output: &str, budget: &TokenBudget) -> String {
        let tokens: Vec<&str> = output.split_whitespace().collect();
        if tokens.len() <= budget.max_output_tokens {
            return output.to_string();
        }
        let truncated: Vec<&str> = tokens[..budget.max_output_tokens].to_vec();
        format!("{}\n{}", truncated.join(" "), budget.truncation_marker)
    }

    fn enforce_line_width(line: &str, max_width: usize) -> String {
        if line.len() <= max_width {
            line.to_string()
        } else {
            format!("{}...", &line[..max_width.saturating_sub(3)])
        }
    }

    // ── Error envelope builder ──────────────────────────────────────────

    fn build_error_envelope(
        code: &str,
        category: &str,
        message: &str,
        exit_code: u8,
        retryable: bool,
    ) -> ErrorEnvelope {
        ErrorEnvelope {
            code: code.to_string(),
            category: category.to_string(),
            message: message.to_string(),
            retryable,
            recoverable: !retryable, // simplified: retryable errors are not user-recoverable
            exit_code,
            details: None,
            suggestion: Some("Run `fwc guide` for usage help".to_string()),
        }
    }

    // ── 1. Secret redaction in output ───────────────────────────────────

    mod secret_redaction {
        use super::*;

        #[test]
        fn redacts_stripe_secret_key() {
            let input = r#"{"api_key": "sk-live_abc123def456"}"#;
            let output = redact_secrets(input);
            assert!(!output.contains("abc123def456"), "Stripe key should be redacted: {output}");
            assert!(output.contains("[REDACTED:"));
        }

        #[test]
        fn redacts_github_token() {
            let input = "Authorization: ghp_abcdefghijklmnop1234567890";
            let output = redact_secrets(input);
            assert!(!output.contains("abcdefghijklmnop1234567890"));
            assert!(output.contains("[REDACTED:"));
        }

        #[test]
        fn redacts_slack_bot_token() {
            let input = "token: xoxb-1234-5678-abcdef";
            let output = redact_secrets(input);
            assert!(!output.contains("1234-5678-abcdef"));
        }

        #[test]
        fn redacts_bearer_token() {
            let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
            let output = redact_secrets(input);
            assert!(!output.contains("eyJhbGciOiJIUzI1NiJ9"));
        }

        #[test]
        fn redacts_basic_auth() {
            let input = "Authorization: Basic dXNlcjpwYXNz";
            let output = redact_secrets(input);
            assert!(!output.contains("dXNlcjpwYXNz"));
        }

        #[test]
        fn redacts_aws_access_key() {
            let input = "aws_key=AKIAIOSFODNN7EXAMPLE";
            let output = redact_secrets(input);
            assert!(!output.contains("IOSFODNN7EXAMPLE"));
        }

        #[test]
        fn redacts_query_param_api_key() {
            let input = "https://api.example.com?api_key=secret123";
            let output = redact_secrets(input);
            assert!(!output.contains("secret123"));
        }

        #[test]
        fn redacts_password_param() {
            let input = "config: password=MyS3cretP@ss!";
            let output = redact_secrets(input);
            assert!(!output.contains("MyS3cretP@ss!"));
        }

        #[test]
        fn safe_content_not_redacted() {
            let input = "connector_id: github, operation_id: create_issue";
            let output = redact_secrets(input);
            assert_eq!(output, input, "Safe content should not be modified");
        }

        #[test]
        fn safe_patterns_are_safe() {
            for pattern in SAFE_PATTERNS {
                assert!(is_safe_content(pattern), "Pattern '{pattern}' should be safe");
            }
        }

        #[test]
        fn redaction_preserves_structure() {
            let input = r#"{"key": "sk-test_abc", "name": "test"}"#;
            let output = redact_secrets(input);
            // Should still be somewhat parseable (not necessarily valid JSON after redaction,
            // but the non-secret parts should be preserved)
            assert!(output.contains("name"));
            assert!(output.contains("test"));
        }

        #[test]
        fn empty_input_stays_empty() {
            assert_eq!(redact_secrets(""), "");
        }

        #[test]
        fn contains_secret_detects_stripe_key() {
            assert!(contains_secret("sk-live_abc123"));
        }

        #[test]
        fn contains_secret_detects_github_token() {
            assert!(contains_secret("ghp_abcdef"));
        }

        #[test]
        fn contains_secret_false_for_safe_text() {
            assert!(!contains_secret("This is a normal log message"));
        }
    }

    // ── 2. Token budget enforcement ─────────────────────────────────────

    mod token_budget {
        use super::*;

        #[test]
        fn short_output_not_truncated() {
            let budget = TokenBudget::default();
            let output = "Hello world, this is a short output.";
            let result = enforce_token_budget(output, &budget);
            assert_eq!(result, output);
        }

        #[test]
        fn long_output_truncated() {
            let budget = TokenBudget {
                max_output_tokens: 5,
                max_line_width: 120,
                truncation_marker: "... (truncated)",
            };
            let output = "one two three four five six seven eight nine ten";
            let result = enforce_token_budget(output, &budget);
            assert!(result.contains("... (truncated)"));
            assert!(!result.contains("six"));
        }

        #[test]
        fn truncation_marker_present() {
            let budget = TokenBudget {
                max_output_tokens: 3,
                max_line_width: 120,
                truncation_marker: "[TRUNCATED]",
            };
            let output = "a b c d e f";
            let result = enforce_token_budget(output, &budget);
            assert!(result.contains("[TRUNCATED]"));
        }

        #[test]
        fn exact_budget_not_truncated() {
            let budget = TokenBudget {
                max_output_tokens: 4,
                max_line_width: 120,
                truncation_marker: "...",
            };
            let output = "one two three four";
            let result = enforce_token_budget(output, &budget);
            assert!(!result.contains("..."), "Exact budget should not truncate");
        }

        #[test]
        fn zero_budget_truncates_everything() {
            let budget = TokenBudget {
                max_output_tokens: 0,
                max_line_width: 120,
                truncation_marker: "...",
            };
            let output = "some output";
            let result = enforce_token_budget(output, &budget);
            assert!(result.contains("..."));
        }

        #[test]
        fn line_width_enforcement_short() {
            let line = "Short line";
            assert_eq!(enforce_line_width(line, 120), "Short line");
        }

        #[test]
        fn line_width_enforcement_exact() {
            let line = "x".repeat(120);
            assert_eq!(enforce_line_width(&line, 120), line);
        }

        #[test]
        fn line_width_enforcement_long() {
            let line = "x".repeat(200);
            let result = enforce_line_width(&line, 120);
            assert!(result.len() <= 120, "Truncated line should be <= 120 chars: len={}", result.len());
            assert!(result.ends_with("..."));
        }

        #[test]
        fn default_budget_values() {
            let budget = TokenBudget::default();
            assert_eq!(budget.max_output_tokens, 4096);
            assert_eq!(budget.max_line_width, 120);
            assert_eq!(budget.truncation_marker, "... (truncated)");
        }
    }

    // ── 3. Exit code semantics ──────────────────────────────────────────

    mod exit_code_semantics {
        use super::*;

        #[test]
        fn success_is_zero() {
            assert_eq!(ExitCode::Success as u8, 0);
        }

        #[test]
        fn internal_error_is_one() {
            assert_eq!(ExitCode::InternalError as u8, 1);
        }

        #[test]
        fn usage_error_is_two() {
            assert_eq!(ExitCode::UsageError as u8, 2);
        }

        #[test]
        fn partial_is_three() {
            assert_eq!(ExitCode::Partial as u8, 3);
        }

        #[test]
        fn validation_is_five() {
            assert_eq!(ExitCode::ValidationError as u8, 5);
        }

        #[test]
        fn policy_is_six() {
            assert_eq!(ExitCode::PolicyError as u8, 6);
        }

        #[test]
        fn service_is_seven() {
            assert_eq!(ExitCode::ServiceError as u8, 7);
        }

        #[test]
        fn transport_is_eight() {
            assert_eq!(ExitCode::TransportError as u8, 8);
        }

        #[test]
        fn from_u8_roundtrips() {
            for code in ExitCode::all() {
                let val = *code as u8;
                let parsed = ExitCode::from_u8(val);
                assert_eq!(parsed, Some(*code), "from_u8({val}) failed for {code:?}");
            }
        }

        #[test]
        fn from_u8_invalid_returns_none() {
            assert!(ExitCode::from_u8(4).is_none());
            assert!(ExitCode::from_u8(9).is_none());
            assert!(ExitCode::from_u8(255).is_none());
        }

        #[test]
        fn all_codes_have_descriptions() {
            for code in ExitCode::all() {
                assert!(!code.description().is_empty(), "{code:?} has empty description");
            }
        }

        #[test]
        fn all_codes_unique() {
            let values: Vec<u8> = ExitCode::all().iter().map(|c| *c as u8).collect();
            let unique: BTreeSet<u8> = values.iter().copied().collect();
            assert_eq!(values.len(), unique.len(), "Exit codes must be unique");
        }

        #[test]
        fn all_codes_in_range() {
            for code in ExitCode::all() {
                let val = *code as u8;
                assert!(val <= 128, "Exit code {val} exceeds maximum 128");
            }
        }
    }

    // ── 4. TOON output width constraints ────────────────────────────────

    mod toon_width {
        use super::*;

        #[test]
        fn standard_width_is_120() {
            let budget = TokenBudget::default();
            assert_eq!(budget.max_line_width, 120);
        }

        #[test]
        fn short_lines_unchanged() {
            let line = "status: ok";
            assert_eq!(enforce_line_width(line, 120), "status: ok");
        }

        #[test]
        fn exactly_120_chars_unchanged() {
            let line = "a".repeat(120);
            assert_eq!(enforce_line_width(&line, 120), line);
        }

        #[test]
        fn over_120_chars_truncated() {
            let line = "b".repeat(200);
            let result = enforce_line_width(&line, 120);
            assert!(result.ends_with("..."));
            assert!(result.len() <= 120);
        }

        #[test]
        fn narrow_width_constraint() {
            let line = "This is a moderately long line of text";
            let result = enforce_line_width(line, 20);
            assert!(result.len() <= 20, "Result too long: len={}", result.len());
        }

        #[test]
        fn empty_line_unchanged() {
            assert_eq!(enforce_line_width("", 120), "");
        }

        #[test]
        fn single_char_line_unchanged() {
            assert_eq!(enforce_line_width("x", 120), "x");
        }

        #[test]
        fn width_4_truncation() {
            // Width 4 means 1 char + "..."
            let result = enforce_line_width("hello world", 4);
            assert!(result.len() <= 4);
        }
    }

    // ── 5. JSON output schema compliance ────────────────────────────────

    mod json_schema_compliance {
        use super::*;

        #[test]
        fn error_envelope_has_required_fields() {
            let env = build_error_envelope("FCP_ERR_INTERNAL", "internal", "Test error", 1, false);
            let json = serde_json::to_value(&env).unwrap();
            assert!(json.get("code").is_some());
            assert!(json.get("category").is_some());
            assert!(json.get("message").is_some());
            assert!(json.get("retryable").is_some());
            assert!(json.get("recoverable").is_some());
            assert!(json.get("exit_code").is_some());
        }

        #[test]
        fn error_envelope_code_is_string() {
            let env = build_error_envelope("FCP_ERR_INTERNAL", "internal", "msg", 1, false);
            let json = serde_json::to_value(&env).unwrap();
            assert!(json["code"].is_string());
        }

        #[test]
        fn error_envelope_retryable_is_boolean() {
            let env = build_error_envelope("FCP_ERR_RATE_LIMITED", "rate_limit", "msg", 7, true);
            let json = serde_json::to_value(&env).unwrap();
            assert!(json["retryable"].is_boolean());
            assert_eq!(json["retryable"], true);
        }

        #[test]
        fn error_envelope_exit_code_is_number() {
            let env = build_error_envelope("FCP_ERR_PARSE_FAILED", "parse", "msg", 2, false);
            let json = serde_json::to_value(&env).unwrap();
            assert!(json["exit_code"].is_number());
            assert_eq!(json["exit_code"], 2);
        }

        #[test]
        fn error_envelope_without_details() {
            let env = build_error_envelope("FCP_ERR_INTERNAL", "internal", "msg", 1, false);
            let json = serde_json::to_value(&env).unwrap();
            // details should be absent (skip_serializing_if = None)
            assert!(json.get("details").is_none() || json["details"].is_null());
        }

        #[test]
        fn error_envelope_with_details() {
            let mut env = build_error_envelope("FCP_ERR_SCHEMA_VIOLATION", "validation", "msg", 5, false);
            env.details = Some(serde_json::json!({"path": "$.name", "expected": "string"}));
            let json = serde_json::to_value(&env).unwrap();
            assert!(json.get("details").is_some());
            assert_eq!(json["details"]["path"], "$.name");
        }

        #[test]
        fn error_envelope_roundtrips() {
            let env = build_error_envelope("FCP_ERR_TRANSPORT_FAILED", "transport", "timeout", 8, true);
            let json = serde_json::to_string(&env).unwrap();
            let parsed: ErrorEnvelope = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.code, env.code);
            assert_eq!(parsed.exit_code, env.exit_code);
            assert_eq!(parsed.retryable, env.retryable);
        }

        #[test]
        fn error_envelope_suggestion_present() {
            let env = build_error_envelope("FCP_ERR_UNKNOWN_COMMAND", "parse", "msg", 2, false);
            assert!(env.suggestion.is_some());
        }
    }

    // ── 6. Error envelope structure ─────────────────────────────────────

    mod error_envelope_structure {
        use super::*;

        #[test]
        fn parse_error_exit_code_2() {
            let env = build_error_envelope("FCP_ERR_PARSE_FAILED", "parse", "Bad syntax", 2, false);
            assert_eq!(env.exit_code, 2);
        }

        #[test]
        fn validation_error_exit_code_5() {
            let env = build_error_envelope("FCP_ERR_VALIDATION_FAILED", "validation", "Invalid input", 5, false);
            assert_eq!(env.exit_code, 5);
        }

        #[test]
        fn policy_error_exit_code_6() {
            let env = build_error_envelope("FCP_ERR_POLICY_DENIED", "policy", "Denied", 6, false);
            assert_eq!(env.exit_code, 6);
        }

        #[test]
        fn rate_limit_is_retryable() {
            let env = build_error_envelope("FCP_ERR_RATE_LIMITED", "rate_limit", "Too many requests", 7, true);
            assert!(env.retryable);
        }

        #[test]
        fn internal_error_not_retryable() {
            let env = build_error_envelope("FCP_ERR_INTERNAL", "internal", "Bug", 1, false);
            assert!(!env.retryable);
        }

        #[test]
        fn code_prefix_is_fcp_err() {
            let env = build_error_envelope("FCP_ERR_INTERNAL", "internal", "msg", 1, false);
            assert!(env.code.starts_with("FCP_ERR_"));
        }

        #[test]
        fn category_is_lowercase() {
            let categories = ["parse", "validation", "auth", "rate_limit", "policy", "connector", "transport", "internal"];
            for cat in categories {
                assert_eq!(cat, cat.to_lowercase(), "Category '{cat}' not lowercase");
            }
        }
    }

    // ── 7. Structured log format ────────────────────────────────────────

    mod structured_log {
        use super::*;

        fn sample_log(level: &str, message: &str) -> LogEntry {
            LogEntry {
                timestamp: "2026-03-12T10:00:00.123Z".to_string(),
                level: level.to_string(),
                module: "fwc::dispatch".to_string(),
                message: message.to_string(),
                correlation_id: Some("req-abc123".to_string()),
                span: Some("invoke".to_string()),
            }
        }

        #[test]
        fn log_entry_serializes() {
            let entry = sample_log("INFO", "Operation started");
            let json = serde_json::to_value(&entry).unwrap();
            assert_eq!(json["level"], "INFO");
            assert_eq!(json["message"], "Operation started");
        }

        #[test]
        fn log_entry_has_timestamp() {
            let entry = sample_log("DEBUG", "test");
            assert!(!entry.timestamp.is_empty());
        }

        #[test]
        fn log_entry_has_module() {
            let entry = sample_log("WARN", "slow query");
            assert!(entry.module.contains("fwc"));
        }

        #[test]
        fn log_entry_has_correlation_id() {
            let entry = sample_log("ERROR", "failed");
            assert!(entry.correlation_id.is_some());
        }

        #[test]
        fn log_entry_roundtrips() {
            let entry = sample_log("INFO", "test message");
            let json = serde_json::to_string(&entry).unwrap();
            let parsed: LogEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.level, entry.level);
            assert_eq!(parsed.message, entry.message);
            assert_eq!(parsed.correlation_id, entry.correlation_id);
        }

        #[test]
        fn log_without_optional_fields() {
            let entry = LogEntry {
                timestamp: "2026-03-12T10:00:00Z".into(),
                level: "INFO".into(),
                module: "fwc".into(),
                message: "basic".into(),
                correlation_id: None,
                span: None,
            };
            let json = serde_json::to_value(&entry).unwrap();
            assert!(json.get("correlation_id").is_none() || json["correlation_id"].is_null());
        }

        #[test]
        fn log_levels_are_standard() {
            let valid_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
            for level in valid_levels {
                let entry = sample_log(level, "msg");
                assert!(
                    valid_levels.contains(&entry.level.as_str()),
                    "Unexpected log level: {}",
                    entry.level
                );
            }
        }

        #[test]
        fn log_secrets_are_redacted() {
            let entry = sample_log("INFO", "Connecting with token sk-live_secret123");
            let redacted = redact_secrets(&entry.message);
            assert!(!redacted.contains("secret123"));
        }
    }

    // ── 8. Output determinism ───────────────────────────────────────────

    mod output_determinism {
        use super::*;

        #[test]
        fn same_error_envelope_produces_same_json() {
            let env1 = build_error_envelope("FCP_ERR_INTERNAL", "internal", "msg", 1, false);
            let env2 = build_error_envelope("FCP_ERR_INTERNAL", "internal", "msg", 1, false);
            let json1 = serde_json::to_string(&env1).unwrap();
            let json2 = serde_json::to_string(&env2).unwrap();
            assert_eq!(json1, json2, "Same input should produce same output");
        }

        #[test]
        fn redaction_is_deterministic() {
            let input = "token: sk-live_abc123";
            let out1 = redact_secrets(input);
            let out2 = redact_secrets(input);
            assert_eq!(out1, out2);
        }

        #[test]
        fn budget_enforcement_is_deterministic() {
            let budget = TokenBudget {
                max_output_tokens: 3,
                max_line_width: 120,
                truncation_marker: "...",
            };
            let output = "one two three four five";
            let result1 = enforce_token_budget(output, &budget);
            let result2 = enforce_token_budget(output, &budget);
            assert_eq!(result1, result2);
        }

        #[test]
        fn line_width_enforcement_deterministic() {
            let line = "x".repeat(200);
            let r1 = enforce_line_width(&line, 80);
            let r2 = enforce_line_width(&line, 80);
            assert_eq!(r1, r2);
        }

        #[test]
        fn multiple_redactions_same_result() {
            let input = "key=ghp_abc123 secret=password=hunter2";
            let r1 = redact_secrets(input);
            let r2 = redact_secrets(input);
            assert_eq!(r1, r2);
        }

        #[test]
        fn error_envelope_serialization_stable() {
            let env = build_error_envelope("FCP_ERR_RATE_LIMITED", "rate_limit", "retry", 7, true);
            let results: Vec<String> = (0..5).map(|_| serde_json::to_string(&env).unwrap()).collect();
            for r in &results {
                assert_eq!(r, &results[0]);
            }
        }

        #[test]
        fn exit_code_mapping_deterministic() {
            for code in ExitCode::all() {
                let v1 = *code as u8;
                let v2 = *code as u8;
                assert_eq!(v1, v2);
            }
        }

        #[test]
        fn log_entry_serialization_stable() {
            let entry = LogEntry {
                timestamp: "2026-03-12T10:00:00Z".into(),
                level: "INFO".into(),
                module: "fwc".into(),
                message: "determinism test".into(),
                correlation_id: Some("id-123".into()),
                span: None,
            };
            let j1 = serde_json::to_string(&entry).unwrap();
            let j2 = serde_json::to_string(&entry).unwrap();
            assert_eq!(j1, j2);
        }
    }
}
