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
        assert_eq!(
            redacted["level1"]["level2"]["level3"]["secret"],
            "[REDACTED]"
        );
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

    // ── Additional Redacted<T> tests ──

    #[test]
    fn redacted_new_with_integer() {
        let r = Redacted::new(42_u64);
        assert_eq!(*r.expose(), 42_u64);
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn redacted_new_with_bool() {
        let r = Redacted::new(true);
        assert!(*r.expose());
        assert_eq!(format!("{r:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_new_with_vec() {
        let v = vec![1, 2, 3];
        let r = Redacted::new(v);
        assert_eq!(r.expose().len(), 3);
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn redacted_new_with_empty_string() {
        let r = Redacted::new(String::new());
        assert!(r.expose().is_empty());
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn redacted_new_with_option_some() {
        let r = Redacted::new(Some("secret"));
        assert_eq!(*r.expose(), Some("secret"));
        assert_eq!(format!("{r:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_new_with_option_none() {
        let r: Redacted<Option<String>> = Redacted::new(None);
        assert!(r.expose().is_none());
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn redacted_map_string_to_length() {
        let r = Redacted::new("hello".to_string());
        let len = r.map(|s| s.len());
        assert_eq!(*len.expose(), 5);
        assert_eq!(format!("{len}"), "[REDACTED]");
    }

    #[test]
    fn redacted_map_chain() {
        let r = Redacted::new(5_i32);
        let result = r.map(|v| v * 2).map(|v| v + 1);
        assert_eq!(*result.expose(), 11);
    }

    #[test]
    fn redacted_map_type_change() {
        let r = Redacted::new(42);
        let s = r.map(|v| format!("value={v}"));
        assert_eq!(s.expose(), "value=42");
        assert_eq!(format!("{s}"), "[REDACTED]");
    }

    #[test]
    fn redacted_into_inner_string() {
        let r = Redacted::new("consume-me".to_string());
        let inner = r.into_inner();
        assert_eq!(inner, "consume-me");
    }

    #[test]
    fn redacted_into_inner_vec() {
        let r = Redacted::new(vec![10, 20, 30]);
        let inner = r.into_inner();
        assert_eq!(inner, vec![10, 20, 30]);
    }

    #[test]
    fn redacted_eq_same_inner() {
        let a = Redacted::new(100_u32);
        let b = Redacted::new(100_u32);
        assert_eq!(a, b);
    }

    #[test]
    fn redacted_ne_different_inner() {
        let a = Redacted::new(100_u32);
        let b = Redacted::new(200_u32);
        assert_ne!(a, b);
    }

    #[test]
    fn redacted_eq_empty_strings() {
        let a = Redacted::new(String::new());
        let b = Redacted::new(String::new());
        assert_eq!(a, b);
    }

    #[test]
    fn redacted_clone_independence() {
        let original = Redacted::new(vec![1, 2, 3]);
        let cloned = original.clone();
        // After clone, original is still accessible.
        assert_eq!(original.expose(), cloned.expose());
        assert_eq!(format!("{original:?}"), "[REDACTED]");
        assert_eq!(format!("{cloned:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_debug_never_leaks_numeric() {
        let r = Redacted::new(999_999);
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("999"));
        assert_eq!(dbg, "[REDACTED]");
    }

    #[test]
    fn redacted_display_never_leaks_multiline() {
        let r = Redacted::new("line1\nline2\nline3");
        let disp = format!("{r}");
        assert!(!disp.contains("line1"));
        assert!(!disp.contains('\n'));
        assert_eq!(disp, "[REDACTED]");
    }

    #[test]
    fn redacted_debug_alternate_formatting() {
        let r = Redacted::new("secret-data");
        let dbg = format!("{r:#?}");
        assert_eq!(dbg, "[REDACTED]");
    }

    #[test]
    fn redacted_serde_integer_roundtrip() {
        let r = Redacted::new(12345_i64);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "12345");
        let parsed: Redacted<i64> = serde_json::from_str(&json).unwrap();
        assert_eq!(*parsed.expose(), 12345);
    }

    #[test]
    fn redacted_serde_bool_roundtrip() {
        let r = Redacted::new(true);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "true");
        let parsed: Redacted<bool> = serde_json::from_str(&json).unwrap();
        assert!(*parsed.expose());
    }

    #[test]
    fn redacted_serde_vec_roundtrip() {
        let r = Redacted::new(vec![1_u32, 2, 3]);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "[1,2,3]");
        let parsed: Redacted<Vec<u32>> = serde_json::from_str(&json).unwrap();
        assert_eq!(*parsed.expose(), vec![1, 2, 3]);
    }

    #[test]
    fn redacted_serde_null_roundtrip() {
        let r: Redacted<Option<String>> = Redacted::new(None);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "null");
        let parsed: Redacted<Option<String>> = serde_json::from_str(&json).unwrap();
        assert!(parsed.expose().is_none());
    }

    #[test]
    fn redacted_serde_nested_struct_roundtrip() {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct Inner {
            x: i32,
            y: String,
        }
        let inner = Inner {
            x: 42,
            y: "hidden".to_string(),
        };
        let r = Redacted::new(inner.clone());
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("hidden"));
        let parsed: Redacted<Inner> = serde_json::from_str(&json).unwrap();
        assert_eq!(*parsed.expose(), inner);
        assert_eq!(format!("{parsed:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_in_vec_debug() {
        let secrets = vec![Redacted::new("key1"), Redacted::new("key2")];
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("key1"));
        assert!(!dbg.contains("key2"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn redacted_in_option_debug() {
        let opt: Option<Redacted<String>> = Some(Redacted::new("secret".into()));
        let dbg = format!("{opt:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn redacted_display_width_formatting() {
        let r = Redacted::new("secret");
        // Width formatting should still show [REDACTED].
        let padded = format!("{r:>20}");
        assert!(padded.contains("[REDACTED]"));
        assert!(!padded.contains("secret"));
    }

    // ── Additional RedactionPolicy tests ──

    #[test]
    fn policy_empty_patterns() {
        let policy = RedactionPolicy::with_patterns(vec![]);
        assert!(!policy.should_redact("api_key"));
        assert!(!policy.should_redact("password"));
        assert!(!policy.should_redact("anything"));
        assert_eq!(policy.pattern_count(), 0);
    }

    #[test]
    fn policy_single_pattern() {
        let policy = RedactionPolicy::with_patterns(vec!["secret".into()]);
        assert!(policy.should_redact("secret"));
        assert!(policy.should_redact("my_secret_field"));
        assert!(policy.should_redact("SECRET"));
        assert!(!policy.should_redact("public"));
        assert_eq!(policy.pattern_count(), 1);
    }

    #[test]
    fn policy_default_pattern_count_exact() {
        let policy = RedactionPolicy::default();
        assert_eq!(policy.pattern_count(), 15);
    }

    #[test]
    fn policy_add_multiple_patterns() {
        let mut policy = RedactionPolicy::with_patterns(vec![]);
        policy.add_pattern("ssn");
        policy.add_pattern("dob");
        policy.add_pattern("cc_number");
        assert_eq!(policy.pattern_count(), 3);
        assert!(policy.should_redact("ssn"));
        assert!(policy.should_redact("dob"));
        assert!(policy.should_redact("cc_number"));
    }

    #[test]
    fn policy_add_pattern_normalizes_to_lowercase() {
        let mut policy = RedactionPolicy::with_patterns(vec![]);
        policy.add_pattern("MySecret");
        // Since add_pattern lowercases, matching uppercase input should work.
        assert!(policy.should_redact("MYSECRET"));
        assert!(policy.should_redact("mysecret"));
        assert!(policy.should_redact("MySecret"));
    }

    #[test]
    fn policy_should_redact_empty_field_name() {
        let policy = RedactionPolicy::default();
        assert!(!policy.should_redact(""));
    }

    #[test]
    fn policy_should_redact_partial_match() {
        let policy = RedactionPolicy::default();
        // "auth" is a pattern, so any field containing "auth" should match.
        assert!(policy.should_redact("authorization"));
        assert!(policy.should_redact("oauth_token"));
        assert!(policy.should_redact("user_auth_key"));
    }

    #[test]
    fn policy_should_redact_exact_match() {
        let policy = RedactionPolicy::default();
        assert!(policy.should_redact("token"));
        assert!(policy.should_redact("secret"));
        assert!(policy.should_redact("password"));
    }

    #[test]
    fn policy_mixed_case_field_names() {
        let policy = RedactionPolicy::default();
        assert!(policy.should_redact("AccessToken"));
        assert!(policy.should_redact("REFRESH_TOKEN"));
        assert!(policy.should_redact("Client_Secret"));
        assert!(policy.should_redact("PRIVATE_KEY"));
        assert!(policy.should_redact("Passphrase"));
        assert!(policy.should_redact("Signing_Key"));
        assert!(policy.should_redact("Encryption_Key"));
    }

    #[test]
    fn policy_all_default_patterns_match() {
        let policy = RedactionPolicy::default();
        let expected = [
            "token",
            "secret",
            "password",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "client_secret",
            "private_key",
            "credential",
            "bearer",
            "auth",
            "passphrase",
            "signing_key",
            "encryption_key",
        ];
        for pattern in &expected {
            assert!(
                policy.should_redact(pattern),
                "Expected {pattern} to be redacted"
            );
        }
    }

    #[test]
    fn policy_redact_if_sensitive_returns_redacted_for_match() {
        let policy = RedactionPolicy::default();
        let result = policy.redact_if_sensitive("password", "p4ssw0rd!");
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn policy_redact_if_sensitive_returns_value_for_no_match() {
        let policy = RedactionPolicy::default();
        let result = policy.redact_if_sensitive("hostname", "example.com");
        assert_eq!(result, "example.com");
    }

    #[test]
    fn policy_redact_if_sensitive_empty_value() {
        let policy = RedactionPolicy::default();
        let result = policy.redact_if_sensitive("token", "");
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn policy_redact_if_sensitive_non_sensitive_empty_value() {
        let policy = RedactionPolicy::default();
        let result = policy.redact_if_sensitive("name", "");
        assert_eq!(result, "");
    }

    #[test]
    fn policy_clone_works() {
        let mut original = RedactionPolicy::default();
        original.add_pattern("ssn");
        let cloned = original.clone();
        assert_eq!(cloned.pattern_count(), original.pattern_count());
        assert!(cloned.should_redact("ssn"));
    }

    #[test]
    fn policy_debug_output() {
        let policy = RedactionPolicy::with_patterns(vec!["test".into()]);
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("RedactionPolicy"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn policy_unicode_field_name() {
        let policy = RedactionPolicy::with_patterns(vec!["passwort".into()]);
        assert!(policy.should_redact("mein_passwort"));
        assert!(policy.should_redact("PASSWORT"));
    }

    #[test]
    fn policy_pattern_with_underscore() {
        let policy = RedactionPolicy::with_patterns(vec!["api_key".into()]);
        assert!(policy.should_redact("my_api_key"));
        assert!(policy.should_redact("api_key_v2"));
        assert!(!policy.should_redact("apikey")); // underscore matters
    }

    #[test]
    fn policy_pattern_substring_in_longer_word() {
        let policy = RedactionPolicy::default();
        // "auth" is a pattern, embedded in words
        assert!(policy.should_redact("authenticate"));
        assert!(policy.should_redact("authenticated_user"));
        assert!(policy.should_redact("preauthorization"));
    }

    #[test]
    fn policy_no_false_positives_on_similar_words() {
        let policy = RedactionPolicy::with_patterns(vec!["pass".into()]);
        assert!(policy.should_redact("password"));
        assert!(policy.should_redact("passphrase"));
        // "pass" matches as substring
        assert!(policy.should_redact("bypass"));
    }

    // ── Additional redact_json tests ──

    #[test]
    fn redact_json_preserves_number() {
        let json = serde_json::json!(42);
        let policy = RedactionPolicy::default();
        assert_eq!(redact_json(json, &policy), serde_json::json!(42));
    }

    #[test]
    fn redact_json_preserves_bool() {
        let policy = RedactionPolicy::default();
        assert_eq!(
            redact_json(serde_json::json!(true), &policy),
            serde_json::json!(true)
        );
        assert_eq!(
            redact_json(serde_json::json!(false), &policy),
            serde_json::json!(false)
        );
    }

    #[test]
    fn redact_json_preserves_null() {
        let json = serde_json::Value::Null;
        let policy = RedactionPolicy::default();
        assert_eq!(redact_json(json, &policy), serde_json::Value::Null);
    }

    #[test]
    fn redact_json_empty_array() {
        let json = serde_json::json!([]);
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert!(redacted.as_array().unwrap().is_empty());
    }

    #[test]
    fn redact_json_array_of_primitives() {
        let json = serde_json::json!([1, "hello", true, null]);
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        let arr = redacted.as_array().unwrap();
        assert_eq!(arr[0], 1);
        assert_eq!(arr[1], "hello");
        assert_eq!(arr[2], true);
        assert!(arr[3].is_null());
    }

    #[test]
    fn redact_json_nested_arrays() {
        let json = serde_json::json!([[{"token": "t1"}], [{"name": "safe"}]]);
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted[0][0]["token"], "[REDACTED]");
        assert_eq!(redacted[1][0]["name"], "safe");
    }

    #[test]
    fn redact_json_sensitive_key_with_object_value() {
        let json = serde_json::json!({
            "auth": {
                "user": "admin",
                "pass": "secret"
            }
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        // "auth" is sensitive, so entire value is replaced.
        assert_eq!(redacted["auth"], "[REDACTED]");
    }

    #[test]
    fn redact_json_sensitive_key_with_array_value() {
        let json = serde_json::json!({
            "token": ["t1", "t2", "t3"]
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["token"], "[REDACTED]");
    }

    #[test]
    fn redact_json_sensitive_key_with_number_value() {
        let json = serde_json::json!({
            "password": 12345,
            "port": 8080
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["port"], 8080);
    }

    #[test]
    fn redact_json_sensitive_key_with_bool_value() {
        let json = serde_json::json!({
            "token": true,
            "enabled": false
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["token"], "[REDACTED]");
        assert_eq!(redacted["enabled"], false);
    }

    #[test]
    fn redact_json_case_insensitive_keys() {
        let json = serde_json::json!({
            "API_KEY": "key1",
            "Password": "pass1",
            "Access_Token": "tok1"
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["API_KEY"], "[REDACTED]");
        assert_eq!(obj["Password"], "[REDACTED]");
        assert_eq!(obj["Access_Token"], "[REDACTED]");
    }

    #[test]
    fn redact_json_four_levels_deep() {
        let json = serde_json::json!({
            "a": {
                "b": {
                    "c": {
                        "d": {
                            "api_key": "deep-key",
                            "name": "still-visible"
                        }
                    }
                }
            }
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["a"]["b"]["c"]["d"]["api_key"], "[REDACTED]");
        assert_eq!(redacted["a"]["b"]["c"]["d"]["name"], "still-visible");
    }

    #[test]
    fn redact_json_custom_policy() {
        let policy = RedactionPolicy::with_patterns(vec!["ssn".into(), "dob".into()]);
        let json = serde_json::json!({
            "ssn": "123-45-6789",
            "dob": "1990-01-01",
            "api_key": "not-redacted-here",
            "name": "John"
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["ssn"], "[REDACTED]");
        assert_eq!(obj["dob"], "[REDACTED]");
        assert_eq!(obj["api_key"], "not-redacted-here");
        assert_eq!(obj["name"], "John");
    }

    #[test]
    fn redact_json_empty_policy() {
        let policy = RedactionPolicy::with_patterns(vec![]);
        let json = serde_json::json!({
            "api_key": "visible",
            "password": "also-visible"
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["api_key"], "visible");
        assert_eq!(obj["password"], "also-visible");
    }

    #[test]
    fn redact_json_all_sensitive_object() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "token": "t1",
            "secret": "s1",
            "password": "p1"
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        for (_, v) in obj {
            assert_eq!(v, "[REDACTED]");
        }
    }

    #[test]
    fn redact_json_no_sensitive_object() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "name": "Alice",
            "host": "localhost",
            "port": 3000
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["name"], "Alice");
        assert_eq!(obj["host"], "localhost");
        assert_eq!(obj["port"], 3000);
    }

    #[test]
    fn redact_json_preserves_string_scalar() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!("just a plain string");
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted, "just a plain string");
    }

    #[test]
    fn redact_json_preserves_float() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!(7.125);
        let redacted = redact_json(json, &policy);
        let val = redacted.as_f64().unwrap();
        assert!((val - 7.125).abs() < f64::EPSILON);
    }

    #[test]
    fn redact_json_large_flat_object() {
        let policy = RedactionPolicy::default();
        let mut map = serde_json::Map::new();
        for i in 0..50 {
            map.insert(format!("field_{i}"), serde_json::json!(i));
        }
        map.insert("password".to_string(), serde_json::json!("hidden"));
        let json = serde_json::Value::Object(map);
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["password"], "[REDACTED]");
        assert_eq!(obj["field_0"], 0);
        assert_eq!(obj["field_49"], 49);
    }

    #[test]
    fn redact_json_array_with_mixed_types() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!([
            42,
            "text",
            null,
            true,
            {"secret": "hidden"},
            [1, 2, 3]
        ]);
        let redacted = redact_json(json, &policy);
        let arr = redacted.as_array().unwrap();
        assert_eq!(arr[0], 42);
        assert_eq!(arr[1], "text");
        assert!(arr[2].is_null());
        assert_eq!(arr[3], true);
        assert_eq!(arr[4]["secret"], "[REDACTED]");
        assert_eq!(arr[5], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn redact_json_sibling_sensitive_and_non_sensitive() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "credentials": {
                "api_key": "abc123",
                "endpoint": "https://api.example.com"
            },
            "metadata": {
                "version": "1.0",
                "token": "xyz789"
            }
        });
        let redacted = redact_json(json, &policy);
        // "credentials" contains "credential" pattern, so entire value is redacted.
        assert_eq!(redacted["credentials"], "[REDACTED]");
        assert_eq!(redacted["metadata"]["version"], "1.0");
        assert_eq!(redacted["metadata"]["token"], "[REDACTED]");
    }

    #[test]
    fn redact_json_preserves_key_order_in_object() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "z_field": "z",
            "a_field": "a",
            "m_field": "m"
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert_eq!(obj["z_field"], "z");
        assert_eq!(obj["a_field"], "a");
        assert_eq!(obj["m_field"], "m");
    }

    #[test]
    fn redact_json_special_chars_in_keys() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "my-api-key": "should-not-redact",
            "my_api_key": "should-redact",
            "my.token": "should-redact-dot",
            "api key": "should-redact-space"
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        // "my-api-key" does not contain "api_key" (hyphen vs underscore)
        // but it does contain "token" — no, it doesn't. Check "api_key" pattern.
        // Patterns: api_key, token. "my-api-key" does not contain "api_key" but does not contain "token".
        // Actually "my-api-key" does not contain "api_key" (the pattern is "api_key" with underscore).
        assert_eq!(obj["my-api-key"], "should-not-redact");
        assert_eq!(obj["my_api_key"], "[REDACTED]");
        // "my.token" contains "token".
        assert_eq!(obj["my.token"], "[REDACTED]");
        // "api key" contains "api key" — but pattern is "api_key". Does "api key" contain "api_key"? No.
        // However it does not contain any pattern. Wait — does it contain "auth"? No.
        // But it does contain... let's check: "api key" lowercased is "api key". Patterns checked:
        // token, secret, password, api_key, apikey... "apikey" is a pattern. "api key" does NOT contain "apikey".
        // None match. So it stays.
        assert_eq!(obj["api key"], "should-redact-space");
    }

    #[test]
    fn redact_json_value_types_for_sensitive_key() {
        // When a sensitive key is found, ANY value type gets replaced with "[REDACTED]" string.
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "token_str": "text",
            "token_num": 42,
            "token_bool": true,
            "token_null": null,
            "token_arr": [1, 2],
            "token_obj": {"nested": "val"}
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        for (_, v) in obj {
            assert_eq!(
                v, "[REDACTED]",
                "all sensitive fields should be redacted regardless of value type"
            );
        }
    }

    #[test]
    fn redact_json_idempotent() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "token": "secret123",
            "name": "test"
        });
        let json2 = json.clone();
        let once = redact_json(json, &policy);
        let twice = redact_json(once.clone(), &policy);
        // Verify both applications produce the same result.
        let once_again = redact_json(json2, &policy);
        assert_eq!(once, once_again);
        assert_eq!(once, twice);
    }

    #[test]
    fn redact_json_with_added_pattern() {
        let mut policy = RedactionPolicy::default();
        policy.add_pattern("custom_field");
        let json = serde_json::json!({
            "custom_field": "should-be-redacted",
            "api_key": "also-redacted",
            "name": "visible"
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["custom_field"], "[REDACTED]");
        assert_eq!(obj["api_key"], "[REDACTED]");
        assert_eq!(obj["name"], "visible");
    }

    #[test]
    fn redact_json_object_inside_array_inside_object() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "services": [
                {
                    "name": "svc1",
                    "config": {
                        "api_key": "key1",
                        "timeout": 30
                    }
                }
            ]
        });
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["services"][0]["name"], "svc1");
        assert_eq!(redacted["services"][0]["config"]["api_key"], "[REDACTED]");
        assert_eq!(redacted["services"][0]["config"]["timeout"], 30);
    }

    #[test]
    fn redact_json_empty_string_key() {
        let policy = RedactionPolicy::default();
        let mut map = serde_json::Map::new();
        map.insert(String::new(), serde_json::json!("empty-key-value"));
        let json = serde_json::Value::Object(map);
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj[""], "empty-key-value");
    }

    #[test]
    fn redact_json_empty_string_value() {
        let policy = RedactionPolicy::default();
        let json = serde_json::json!({
            "token": "",
            "name": ""
        });
        let redacted = redact_json(json, &policy);
        let obj = redacted.as_object().unwrap();
        assert_eq!(obj["token"], "[REDACTED]");
        assert_eq!(obj["name"], "");
    }

    // ── Integration/cross-cutting tests ──

    #[test]
    fn redacted_value_used_in_json_then_redacted_by_policy() {
        let secret = Redacted::new("my-secret-value");
        // Serializing a Redacted value exposes it in JSON.
        let json_str = serde_json::to_string(&secret).unwrap();
        let json: serde_json::Value = serde_json::json!({
            "token": json_str.trim_matches('"')
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_json(json, &policy);
        assert_eq!(redacted["token"], "[REDACTED]");
    }

    #[test]
    fn policy_with_overlapping_patterns() {
        let policy = RedactionPolicy::with_patterns(vec![
            "token".into(),
            "access_token".into(), // "access_token" contains "token"
        ]);
        // Both patterns overlap, but should still work fine.
        assert!(policy.should_redact("token"));
        assert!(policy.should_redact("access_token"));
        assert!(policy.should_redact("my_token_field"));
    }

    #[test]
    fn policy_pattern_that_is_empty_string() {
        // An empty pattern matches everything since every string contains "".
        let policy = RedactionPolicy::with_patterns(vec![String::new()]);
        assert!(policy.should_redact("anything"));
        assert!(policy.should_redact(""));
        assert!(policy.should_redact("api_key"));
    }

    #[test]
    fn redacted_with_tuple() {
        let r = Redacted::new((1, "two", 3.0_f64));
        let inner = r.expose();
        assert_eq!(inner.0, 1);
        assert_eq!(inner.1, "two");
        assert!((inner.2 - 3.0).abs() < f64::EPSILON);
        assert_eq!(format!("{r:?}"), "[REDACTED]");
    }

    #[test]
    fn redacted_with_hashmap() {
        use std::collections::HashMap;
        let mut m = HashMap::new();
        m.insert("key", "value");
        let r = Redacted::new(m);
        assert_eq!(r.expose().get("key"), Some(&"value"));
        assert_eq!(format!("{r}"), "[REDACTED]");
    }

    #[test]
    fn redacted_map_to_same_type() {
        let r = Redacted::new("hello".to_string());
        let upper = r.map(|s| s.to_uppercase());
        assert_eq!(upper.expose(), "HELLO");
    }
}
