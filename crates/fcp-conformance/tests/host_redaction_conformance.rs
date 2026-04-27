//! `fcp_host::redaction` forensic-safety conformance.
//!
//! `Redacted<T>`, `RedactionPolicy`, and `redact_json` are the
//! cross-crate primitives every fcp-host caller relies on to keep
//! secret material out of logs and triage payloads. From the
//! conformance vantage three contracts matter:
//!
//! 1. **Wire string is exactly `[REDACTED]`.** Triage tools, log
//!    grep audits, and incident-response playbooks all depend on
//!    this exact literal — drift to "redacted" / "***" / "<hidden>"
//!    silently breaks every existing alerting rule.
//! 2. **Default policy pattern set is NORMATIVE.** Removing or
//!    misnaming a baseline pattern (e.g., dropping
//!    `refresh_token`) silently un-redacts a class of secrets.
//! 3. **`redact_json` redacts by KEY name only, not by value
//!    contents.** A value containing the substring "password"
//!    MUST NOT be touched if its key is benign — otherwise free-form
//!    text gets corrupted. Conversely, a sensitive key MUST nuke
//!    the whole subtree, not just inspect it.
//!
//! Properties pinned (NORMATIVE):
//!
//! - `Redacted<T>` Display + Debug both emit `[REDACTED]` exactly.
//! - `Redacted<T>` serde is transparent — values DO survive a
//!   round-trip (the redaction is a logging concern, not a
//!   serialization concern).
//! - `expose()`, `into_inner()`, `map()` round-trip the inner value.
//! - Default policy contains the documented baseline patterns.
//! - `should_redact` is case-insensitive substring match.
//! - `redact_json` recurses through objects + arrays.
//! - `redact_json` replaces the whole value at a sensitive key
//!   (object subtrees, arrays, numbers — not just strings).
//! - `redact_json` looks at KEYS only, never at value bodies.
//! - `redact_json` preserves top-level non-object primitives.

use fcp_host::{Redacted, RedactionPolicy, redact_json};
use serde_json::json;

const REDACTED_LITERAL: &str = "[REDACTED]";

#[test]
fn redacted_display_emits_exact_literal_for_string_inner() {
    let secret = Redacted::new("super-secret-123");
    assert_eq!(
        format!("{secret}"),
        REDACTED_LITERAL,
        "Display MUST emit exactly '[REDACTED]' — alerting rules depend on the literal"
    );
}

#[test]
fn redacted_debug_emits_exact_literal_for_string_inner() {
    let secret = Redacted::new("super-secret-123");
    assert_eq!(
        format!("{secret:?}"),
        REDACTED_LITERAL,
        "Debug MUST emit exactly '[REDACTED]' — log greps depend on the literal"
    );
}

#[test]
fn redacted_display_hides_inner_for_non_string_types() {
    // Inner can be any T — Display formatter still says [REDACTED].
    let secret_int = Redacted::new(42_u64);
    let secret_vec = Redacted::new(vec![1_u8, 2, 3]);
    assert_eq!(format!("{secret_int}"), REDACTED_LITERAL);
    assert_eq!(format!("{secret_vec}"), REDACTED_LITERAL);
}

#[test]
fn redacted_debug_inside_struct_does_not_leak_inner() {
    // The classic incident: a Debug-derived struct field accidentally
    // emits its inner. Wrapping in `Redacted` MUST mask it even when
    // the parent struct uses `#[derive(Debug)]`.
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Config {
        host: String,
        api_key: Redacted<String>,
    }
    let c = Config {
        host: "example.com".into(),
        api_key: Redacted::new("ak_live_THE_REAL_KEY".into()),
    };
    let dbg = format!("{c:?}");
    assert!(dbg.contains("example.com"), "host MUST appear");
    assert!(
        dbg.contains(REDACTED_LITERAL),
        "redacted marker MUST appear: {dbg}"
    );
    assert!(
        !dbg.contains("ak_live"),
        "raw key prefix MUST NOT leak: {dbg}"
    );
    assert!(
        !dbg.contains("THE_REAL_KEY"),
        "raw key body MUST NOT leak: {dbg}"
    );
}

#[test]
fn redacted_expose_returns_reference_to_inner() {
    let secret = Redacted::new("the-real".to_string());
    assert_eq!(secret.expose(), "the-real");
}

#[test]
fn redacted_into_inner_consumes_and_returns_value() {
    let secret = Redacted::new(123_i64);
    assert_eq!(secret.into_inner(), 123);
}

#[test]
fn redacted_map_preserves_redaction_after_transform() {
    let secret = Redacted::new(10_u32);
    let doubled = secret.map(|v| v * 2);
    assert_eq!(*doubled.expose(), 20);
    assert_eq!(
        format!("{doubled:?}"),
        REDACTED_LITERAL,
        "map MUST keep the redaction wrapper — inner change MUST NOT leak"
    );
}

#[test]
fn redacted_partial_eq_compares_inner_values() {
    let a = Redacted::new("same");
    let b = Redacted::new("same");
    let c = Redacted::new("different");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn redacted_serde_is_transparent_to_value() {
    // Documented contract: redaction is for logs, NOT for
    // persistence. Serde MUST preserve the inner value end-to-end
    // so configs/state can round-trip.
    let secret = Redacted::new("persist-me".to_string());
    let json_str = serde_json::to_string(&secret).expect("serialize");
    assert!(
        json_str.contains("persist-me"),
        "serde transparent: serialized form MUST contain the inner value; got {json_str}"
    );
    let parsed: Redacted<String> = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.expose().as_str(), "persist-me");
    // But Debug still hides.
    assert_eq!(format!("{parsed:?}"), REDACTED_LITERAL);
}

#[test]
fn default_policy_includes_documented_baseline_patterns() {
    // Drift here = a class of secrets quietly stops being redacted.
    // Pin every documented baseline pattern by sample field name.
    let policy = RedactionPolicy::default();
    let baseline = [
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
    for field in baseline {
        assert!(
            policy.should_redact(field),
            "default policy MUST redact baseline pattern '{field}'"
        );
    }
}

#[test]
fn default_policy_pattern_count_is_at_least_baseline_size() {
    let policy = RedactionPolicy::default();
    assert!(
        policy.pattern_count() >= 15,
        "default policy MUST contain ≥15 baseline patterns; got {}",
        policy.pattern_count()
    );
}

#[test]
fn should_redact_is_case_insensitive() {
    let policy = RedactionPolicy::default();
    for v in ["api_key", "API_KEY", "Api_Key", "aPi_KeY"] {
        assert!(
            policy.should_redact(v),
            "should_redact MUST be case-insensitive — '{v}' MUST match"
        );
    }
}

#[test]
fn should_redact_is_substring_match_not_full_equality() {
    // Documented contract: 'api_key' pattern matches 'my_api_key',
    // 'user_api_keys', etc. Otherwise renames break the policy.
    let policy = RedactionPolicy::default();
    assert!(policy.should_redact("user_api_key"));
    assert!(policy.should_redact("api_key_v2"));
    assert!(policy.should_redact("MyAccessTokenField"));
    assert!(policy.should_redact("client_secret_id"));
}

#[test]
fn should_redact_returns_false_for_non_sensitive_field_names() {
    let policy = RedactionPolicy::default();
    for name in ["host", "name", "port", "version", "endpoint", "id"] {
        assert!(
            !policy.should_redact(name),
            "non-sensitive field '{name}' MUST NOT be redacted by default policy"
        );
    }
}

#[test]
fn custom_policy_with_patterns_replaces_default_baseline() {
    let policy = RedactionPolicy::with_patterns(vec!["ssn".into(), "account".into()]);
    assert!(policy.should_redact("ssn"));
    assert!(policy.should_redact("account_number"));
    assert!(
        !policy.should_redact("api_key"),
        "with_patterns MUST replace defaults — baseline 'api_key' MUST NOT auto-match"
    );
}

#[test]
fn add_pattern_increases_pattern_count() {
    let mut policy = RedactionPolicy::default();
    let initial = policy.pattern_count();
    policy.add_pattern("custom_secret");
    assert_eq!(policy.pattern_count(), initial + 1);
    assert!(policy.should_redact("my_custom_secret_v2"));
}

#[test]
fn add_pattern_lowercases_input() {
    // Stored lowercase + comparison lowercase = should_redact must
    // succeed even if the user added the pattern in MIXED CASE.
    let mut policy = RedactionPolicy::with_patterns(vec![]);
    policy.add_pattern("MyCustomSecretField");
    assert!(
        policy.should_redact("mycustomsecretfield"),
        "add_pattern MUST lowercase its input so case doesn't matter at query time"
    );
}

#[test]
fn redact_if_sensitive_returns_redacted_for_match() {
    let policy = RedactionPolicy::default();
    assert_eq!(
        policy.redact_if_sensitive("api_key", "ak_live_xyz"),
        REDACTED_LITERAL
    );
}

#[test]
fn redact_if_sensitive_returns_value_unchanged_for_non_match() {
    let policy = RedactionPolicy::default();
    assert_eq!(
        policy.redact_if_sensitive("host", "example.com"),
        "example.com"
    );
}

#[test]
fn redact_json_redacts_only_at_sensitive_keys_not_in_values() {
    // KEY-based redaction: a value containing the WORD "password"
    // MUST NOT be touched if its key is benign. Otherwise free-form
    // text gets corrupted (incident notes, error messages, etc.).
    let value = json!({
        "note": "the user reported a password reset issue",
        "host": "example.com"
    });
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(
        redacted["note"],
        "the user reported a password reset issue",
        "redact_json MUST inspect KEYS only — value bodies MUST be left alone"
    );
    assert_eq!(redacted["host"], "example.com");
}

#[test]
fn redact_json_replaces_whole_object_at_sensitive_key() {
    // If a sensitive key holds an OBJECT, redact_json replaces the
    // ENTIRE subtree with "[REDACTED]" — not recurse into it. Otherwise
    // an attacker could nest a secret under a sensitive parent and
    // dodge redaction by structuring the payload.
    let value = json!({
        "credential": {
            "user": "alice",
            "session_id": "deadbeef"
        }
    });
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(
        redacted["credential"], REDACTED_LITERAL,
        "redact_json MUST replace the whole subtree at a sensitive key with the literal"
    );
}

#[test]
fn redact_json_replaces_whole_array_at_sensitive_key() {
    let value = json!({
        "tokens": ["t1", "t2", "t3"]
    });
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(
        redacted["tokens"], REDACTED_LITERAL,
        "redact_json MUST replace the whole array at a sensitive key"
    );
}

#[test]
fn redact_json_replaces_numeric_value_at_sensitive_key() {
    // Even numbers/booleans get nuked when key is sensitive — the
    // contract is on the KEY, not on the value type.
    let value = json!({"secret": 12345});
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(redacted["secret"], REDACTED_LITERAL);
}

#[test]
fn redact_json_recurses_through_nested_objects() {
    let value = json!({
        "outer": {
            "host": "db.example.com",
            "password": "p4ssw0rd",
            "port": 5432
        }
    });
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    let inner = &redacted["outer"];
    assert_eq!(inner["host"], "db.example.com");
    assert_eq!(inner["password"], REDACTED_LITERAL);
    assert_eq!(inner["port"], 5432);
}

#[test]
fn redact_json_recurses_through_arrays_of_objects() {
    let value = json!([
        {"name": "svc1", "token": "t1"},
        {"name": "svc2", "token": "t2"}
    ]);
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    let arr = redacted.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["name"], "svc1");
    assert_eq!(arr[0]["token"], REDACTED_LITERAL);
    assert_eq!(arr[1]["name"], "svc2");
    assert_eq!(arr[1]["token"], REDACTED_LITERAL);
}

#[test]
fn redact_json_preserves_top_level_string_primitive() {
    let value = json!("just a string with the word password in it");
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(
        redacted, "just a string with the word password in it",
        "top-level non-object MUST be returned unchanged"
    );
}

#[test]
fn redact_json_preserves_top_level_number_primitive() {
    let value = json!(42);
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(redacted, 42);
}

#[test]
fn redact_json_preserves_empty_object_and_empty_array() {
    let policy = RedactionPolicy::default();
    let empty_obj = redact_json(json!({}), &policy);
    let empty_arr = redact_json(json!([]), &policy);
    assert_eq!(empty_obj, json!({}));
    assert_eq!(empty_arr, json!([]));
}

#[test]
fn redact_json_does_not_mutate_non_sensitive_keys_alongside_sensitive() {
    // Mixed object: sensitive AND non-sensitive keys side by side.
    // Each MUST be processed independently — redacting one MUST NOT
    // affect the other.
    let value = json!({
        "host": "example.com",
        "api_key": "ak_live_xyz",
        "port": 443,
        "metadata": {"region": "us-west", "tier": "prod"}
    });
    let policy = RedactionPolicy::default();
    let redacted = redact_json(value, &policy);
    assert_eq!(redacted["host"], "example.com");
    assert_eq!(redacted["api_key"], REDACTED_LITERAL);
    assert_eq!(redacted["port"], 443);
    assert_eq!(redacted["metadata"]["region"], "us-west");
    assert_eq!(redacted["metadata"]["tier"], "prod");
}

#[test]
fn redact_json_with_custom_policy_only_uses_custom_patterns() {
    // Confirm cross-policy isolation: a custom policy MUST NOT pick
    // up baseline patterns from the default.
    let policy = RedactionPolicy::with_patterns(vec!["ssn".into()]);
    let value = json!({
        "ssn": "111-22-3333",
        "api_key": "should-survive-custom-policy"
    });
    let redacted = redact_json(value, &policy);
    assert_eq!(redacted["ssn"], REDACTED_LITERAL);
    assert_eq!(
        redacted["api_key"], "should-survive-custom-policy",
        "custom policy MUST NOT redact baseline patterns it didn't include"
    );
}

#[test]
fn redact_json_is_idempotent_for_already_redacted_payload() {
    // Pass a payload through redaction twice — second pass MUST be
    // a no-op. The literal "[REDACTED]" is itself a string at a
    // sensitive key but its KEY remains sensitive and replacement
    // value is constant.
    let value = json!({"api_key": "ak_live_xyz", "host": "example.com"});
    let policy = RedactionPolicy::default();
    let once = redact_json(value, &policy);
    let twice = redact_json(once.clone(), &policy);
    assert_eq!(once, twice, "redact_json MUST be idempotent");
}
