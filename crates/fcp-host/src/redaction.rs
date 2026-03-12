//! Log redaction for preventing secret material from appearing in output.
//!
//! Provides [`Redacted<T>`] wrapper for values that must never appear in logs,
//! and [`RedactionPolicy`] for configuring which fields are sensitive.
//! All secret-bearing values should be wrapped in `Redacted` to ensure
//! Display/Debug never emit the inner value.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Redacted wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Wrapper that hides the inner value from Display and Debug output.
///
/// Use this for API keys, tokens, passwords, and other secrets that
/// should never appear in logs. The inner value is accessible via
/// [`expose()`](Redacted::expose) for intentional use.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a value, hiding it from Debug/Display.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Intentionally expose the inner value.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Map the inner value while preserving redaction.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Redacted<U> {
        Redacted(f(self.0))
    }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> std::fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: PartialEq> PartialEq for Redacted<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Eq> Eq for Redacted<T> {}

// ─────────────────────────────────────────────────────────────────────────────
// Redaction Policy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy for determining which field names contain sensitive data.
#[derive(Debug, Clone)]
pub struct RedactionPolicy {
    /// Case-insensitive patterns that indicate a sensitive field.
    sensitive_patterns: Vec<String>,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            sensitive_patterns: vec![
                "token".into(),
                "secret".into(),
                "password".into(),
                "api_key".into(),
                "apikey".into(),
                "access_token".into(),
                "refresh_token".into(),
                "client_secret".into(),
                "private_key".into(),
                "credential".into(),
                "bearer".into(),
                "auth".into(),
                "passphrase".into(),
                "signing_key".into(),
                "encryption_key".into(),
            ],
        }
    }
}

impl RedactionPolicy {
    /// Create a policy with custom sensitive patterns.
    #[must_use]
    pub const fn with_patterns(patterns: Vec<String>) -> Self {
        Self {
            sensitive_patterns: patterns,
        }
    }

    /// Add a pattern to the policy.
    pub fn add_pattern(&mut self, pattern: &str) {
        self.sensitive_patterns.push(pattern.to_lowercase());
    }

    /// Check if a field name should be redacted.
    #[must_use]
    pub fn should_redact(&self, field_name: &str) -> bool {
        let normalized = field_name.to_ascii_lowercase();
        self.sensitive_patterns
            .iter()
            .any(|pattern| normalized.contains(pattern.as_str()))
    }

    /// Number of patterns in the policy.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.sensitive_patterns.len()
    }

    /// Redact a value if the field name matches.
    #[must_use]
    pub fn redact_if_sensitive(&self, field_name: &str, value: &str) -> String {
        if self.should_redact(field_name) {
            "[REDACTED]".to_string()
        } else {
            value.to_string()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Redacted JSON Value
// ─────────────────────────────────────────────────────────────────────────────

/// Redact sensitive fields in a JSON value based on the given policy.
#[must_use]
pub fn redact_json(value: serde_json::Value, policy: &RedactionPolicy) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let redacted_map = map
                .into_iter()
                .map(|(key, val)| {
                    if policy.should_redact(&key) {
                        (key, serde_json::Value::String("[REDACTED]".to_string()))
                    } else {
                        (key, redact_json(val, policy))
                    }
                })
                .collect();
            serde_json::Value::Object(redacted_map)
        }
        serde_json::Value::Array(arr) => {
            let redacted_arr = arr.into_iter().map(|v| redact_json(v, policy)).collect();
            serde_json::Value::Array(redacted_arr)
        }
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Redacted ──

    #[test]
    fn redacted_debug_hides_value() {
        let secret = Redacted::new("super-secret-key");
        let debug = format!("{secret:?}");
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn redacted_display_hides_value() {
        let secret = Redacted::new("my-api-token-123");
        let display = format!("{secret}");
        assert_eq!(display, "[REDACTED]");
        assert!(!display.contains("my-api-token"));
    }

    #[test]
    fn redacted_expose_reveals_value() {
        let secret = Redacted::new("the-real-value");
        assert_eq!(*secret.expose(), "the-real-value");
    }

    #[test]
    fn redacted_into_inner() {
        let secret = Redacted::new(42);
        assert_eq!(secret.into_inner(), 42);
    }

    #[test]
    fn redacted_map_transforms() {
        let secret = Redacted::new(10);
        let doubled = secret.map(|v| v * 2);
        assert_eq!(*doubled.expose(), 20);
        assert_eq!(format!("{doubled:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_equality() {
        let a = Redacted::new("same");
        let b = Redacted::new("same");
        let c = Redacted::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn redacted_clone() {
        let original = Redacted::new("cloneable");
        let cloned = original.clone();
        assert_eq!(*cloned.expose(), "cloneable");
    }

    #[test]
    fn redacted_serde_roundtrip() {
        let secret = Redacted::new("secret-value");
        let json = serde_json::to_string(&secret).unwrap();
        // The serialized form DOES contain the value (for persistence),
        // but Debug/Display never do.
        assert!(json.contains("secret-value"));
        let parsed: Redacted<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(*parsed.expose(), "secret-value");
        assert_eq!(format!("{parsed:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_in_format_string() {
        let api_key = Redacted::new("ak_live_12345");
        let msg = format!("Using API key: {api_key}");
        assert_eq!(msg, "Using API key: [REDACTED]");
        assert!(!msg.contains("ak_live"));
    }

    #[test]
    fn redacted_in_struct_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Config {
            host: String,
            api_key: Redacted<String>,
        }
        let config = Config {
            host: "example.com".into(),
            api_key: Redacted::new("secret-key".into()),
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("example.com"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-key"));
    }

    // ── RedactionPolicy ──

    #[test]
    fn default_policy_catches_common_secrets() {
        let policy = RedactionPolicy::default();
        assert!(policy.should_redact("api_key"));
        assert!(policy.should_redact("API_KEY"));
        assert!(policy.should_redact("access_token"));
        assert!(policy.should_redact("client_secret"));
        assert!(policy.should_redact("password"));
        assert!(policy.should_redact("bearer_token"));
        assert!(policy.should_redact("private_key"));
        assert!(policy.should_redact("my_credential_store"));
    }

    #[test]
    fn default_policy_allows_non_secrets() {
        let policy = RedactionPolicy::default();
        assert!(!policy.should_redact("name"));
        assert!(!policy.should_redact("host"));
        assert!(!policy.should_redact("port"));
        assert!(!policy.should_redact("version"));
        assert!(!policy.should_redact("endpoint"));
    }

    #[test]
    fn custom_policy_patterns() {
        let policy = RedactionPolicy::with_patterns(vec!["ssn".into(), "account_number".into()]);
        assert!(policy.should_redact("ssn"));
        assert!(policy.should_redact("user_ssn"));
        assert!(policy.should_redact("account_number"));
        assert!(!policy.should_redact("api_key")); // Not in custom patterns.
    }

    #[test]
    fn policy_add_pattern() {
        let mut policy = RedactionPolicy::default();
        let initial_count = policy.pattern_count();
        policy.add_pattern("custom_secret");
        assert_eq!(policy.pattern_count(), initial_count + 1);
        assert!(policy.should_redact("my_custom_secret_field"));
    }

    #[test]
    fn policy_case_insensitive() {
        let policy = RedactionPolicy::default();
        assert!(policy.should_redact("API_KEY"));
        assert!(policy.should_redact("Api_Key"));
        assert!(policy.should_redact("api_key"));
        assert!(policy.should_redact("PASSWORD"));
        assert!(policy.should_redact("Password"));
    }

    #[test]
    fn policy_redact_if_sensitive() {
        let policy = RedactionPolicy::default();
        assert_eq!(
            policy.redact_if_sensitive("api_key", "sk-12345"),
            "[REDACTED]"
        );
        assert_eq!(
            policy.redact_if_sensitive("host", "example.com"),
            "example.com"
        );
    }

    #[test]
    fn policy_pattern_count() {
        let policy = RedactionPolicy::default();
        assert!(policy.pattern_count() >= 10);
    }

    // ── redact_json ──

    #[test]
    fn redact_json_flat_object() {
        let json = serde_json::json!({
            "host": "example.com",
            "api_key": "sk-12345",
            "port": 443
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["host"], "example.com");
        assert_eq!(obj["api_key"], "[REDACTED]");
        assert_eq!(obj["port"], 443);
    }

    #[test]
    fn redact_json_nested_object() {
        let json = serde_json::json!({
            "database": {
                "host": "db.example.com",
                "password": "p4ssw0rd",
                "port": 5432
            }
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        let db = &redacted["database"];
        assert_eq!(db["host"], "db.example.com");
        assert_eq!(db["password"], "[REDACTED]");
        assert_eq!(db["port"], 5432);
    }

    #[test]
    fn redact_json_array() {
        let json = serde_json::json!([
            {"name": "svc1", "token": "t1"},
            {"name": "svc2", "token": "t2"}
        ]);
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        let arr = redacted.as_array().unwrap();
        assert_eq!(arr[0]["name"], "svc1");
        assert_eq!(arr[0]["token"], "[REDACTED]");
        assert_eq!(arr[1]["name"], "svc2");
        assert_eq!(arr[1]["token"], "[REDACTED]");
    }

    #[test]
    fn redact_json_preserves_primitives() {
        let json = serde_json::json!("just a string");
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted, "just a string");
    }

    #[test]
    fn redact_json_empty_object() {
        let json = serde_json::json!({});
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert!(redacted.as_object().unwrap().is_empty());
    }

    #[test]
    fn redact_json_deeply_nested() {
        let json = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "secret": "deep-secret"
                    }
                }
            }
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["level1"]["level2"]["level3"]["secret"], "[REDACTED]");
    }

    #[test]
    fn redact_json_multiple_sensitive_fields() {
        let json = serde_json::json!({
            "api_key": "key1",
            "client_secret": "secret1",
            "access_token": "token1",
            "name": "visible"
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["api_key"], "[REDACTED]");
        assert_eq!(obj["client_secret"], "[REDACTED]");
        assert_eq!(obj["access_token"], "[REDACTED]");
        assert_eq!(obj["name"], "visible");
    }

    #[test]
    fn redact_json_null_value_for_sensitive_field() {
        let json = serde_json::json!({
            "password": null,
            "name": "test"
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        // Even null passwords get redacted to prevent information leakage.
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["name"], "test");
    }

    #[test]
    fn redact_json_mixed_array_and_objects() {
        let json = serde_json::json!({
            "configs": [
                {"token": "t1", "url": "https://a.com"},
                {"token": "t2", "url": "https://b.com"}
            ],
            "api_key": "global-key"
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["configs"][0]["token"], "[REDACTED]");
        assert_eq!(redacted["configs"][0]["url"], "https://a.com");
        assert_eq!(redacted["configs"][1]["token"], "[REDACTED]");
    }
}
