//! Default scrub rules for differential connector tests.
//!
//! The rules intentionally normalize provider-assigned identifiers and
//! timestamps while preserving semantically meaningful values for the
//! structural diff pass.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Number, Value};

/// Result of applying one scrub operation to a JSON value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ScrubReport {
    /// Number of field or string rewrites applied.
    pub hits: usize,
}

impl ScrubReport {
    #[must_use]
    pub const fn none() -> Self {
        Self { hits: 0 }
    }
}

/// A single JSON scrub rule.
pub trait ScrubRule: Send + Sync {
    /// Stable rule identifier used in fixtures and diagnostics.
    fn name(&self) -> &'static str;

    /// Apply this rule to `value` at the given JSON path.
    fn scrub_value(&self, path: &[String], value: &mut Value) -> ScrubReport;
}

/// RFC 4122 version 4 UUID scrubber.
#[derive(Debug, Clone, Copy, Default)]
pub struct UuidV4Rule;

impl ScrubRule for UuidV4Rule {
    fn name(&self) -> &'static str {
        "uuid_v4"
    }

    fn scrub_value(&self, _path: &[String], value: &mut Value) -> ScrubReport {
        scrub_json_string(value, |input| {
            replace_regex(uuid_v4_regex(), input, "<UUID>")
        })
    }
}

/// RFC3339 timestamp scrubber.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rfc3339TimestampRule;

impl ScrubRule for Rfc3339TimestampRule {
    fn name(&self) -> &'static str {
        "rfc3339_timestamp"
    }

    fn scrub_value(&self, _path: &[String], value: &mut Value) -> ScrubReport {
        scrub_json_string(value, |input| replace_regex(rfc3339_regex(), input, "<TS>"))
    }
}

/// Unix epoch seconds scrubber for the current connector-fixture window.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixSeconds2026Rule;

impl ScrubRule for UnixSeconds2026Rule {
    fn name(&self) -> &'static str {
        "unix_seconds_2026"
    }

    fn scrub_value(&self, _path: &[String], value: &mut Value) -> ScrubReport {
        scrub_epoch_value(value, EpochUnit::Seconds)
    }
}

/// Unix epoch milliseconds scrubber for the current connector-fixture window.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixMillis2026Rule;

impl ScrubRule for UnixMillis2026Rule {
    fn name(&self) -> &'static str {
        "unix_millis_2026"
    }

    fn scrub_value(&self, _path: &[String], value: &mut Value) -> ScrubReport {
        scrub_epoch_value(value, EpochUnit::Millis)
    }
}

/// Bearer token scrubber that preserves the auth scheme.
#[derive(Debug, Clone, Copy, Default)]
pub struct BearerTokenPrefixRule;

impl ScrubRule for BearerTokenPrefixRule {
    fn name(&self) -> &'static str {
        "bearer_token_prefix"
    }

    fn scrub_value(&self, _path: &[String], value: &mut Value) -> ScrubReport {
        scrub_json_string(value, |input| {
            replace_regex(bearer_token_regex(), input, "Bearer <TOKEN>")
        })
    }
}

/// HTTP `ETag` scrubber that preserves the optional weak `W/` prefix.
#[derive(Debug, Clone, Copy, Default)]
pub struct EtagRule;

impl ScrubRule for EtagRule {
    fn name(&self) -> &'static str {
        "etag"
    }

    fn scrub_value(&self, _path: &[String], value: &mut Value) -> ScrubReport {
        scrub_json_string(value, |input| {
            replace_regex(etag_regex(), input, "\"<ETAG>\"")
        })
    }
}

/// Provider request/connection/id scrubber.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionIdRule;

impl ScrubRule for ConnectionIdRule {
    fn name(&self) -> &'static str {
        "connection_id"
    }

    fn scrub_value(&self, path: &[String], value: &mut Value) -> ScrubReport {
        if is_provider_id_path(path) {
            return scrub_any_scalar_id(value);
        }

        scrub_json_string(value, |input| {
            replace_regex(connection_id_regex(), input, "<CONN_ID>")
        })
    }
}

/// Construct the default scrub-rule set in the spec order.
#[must_use]
pub fn default_scrub_rules() -> Vec<Box<dyn ScrubRule>> {
    vec![
        Box::new(UuidV4Rule),
        Box::new(Rfc3339TimestampRule),
        Box::new(UnixSeconds2026Rule),
        Box::new(UnixMillis2026Rule),
        Box::new(BearerTokenPrefixRule),
        Box::new(EtagRule),
        Box::new(ConnectionIdRule),
    ]
}

fn scrub_json_string(
    value: &mut Value,
    scrub: impl FnOnce(&str) -> (String, usize),
) -> ScrubReport {
    let Value::String(input) = value else {
        return ScrubReport::none();
    };
    let (replacement, hits) = scrub(input);
    if hits > 0 {
        *input = replacement;
    }
    ScrubReport { hits }
}

fn replace_regex(regex: &Regex, input: &str, replacement: &str) -> (String, usize) {
    let hits = regex.find_iter(input).count();
    if hits == 0 {
        return (input.to_string(), 0);
    }
    (regex.replace_all(input, replacement).into_owned(), hits)
}

#[derive(Debug, Clone, Copy)]
enum EpochUnit {
    Seconds,
    Millis,
}

fn scrub_epoch_value(value: &mut Value, unit: EpochUnit) -> ScrubReport {
    match value {
        Value::String(input) => {
            let (replacement, hits) = scrub_epoch_tokens(input, unit);
            if hits > 0 {
                *input = replacement;
            }
            ScrubReport { hits }
        }
        Value::Number(number) if epoch_number_matches(number, unit) => {
            *value = Value::String(match unit {
                EpochUnit::Seconds => "<UNIX>".to_string(),
                EpochUnit::Millis => "<UNIX_MS>".to_string(),
            });
            ScrubReport { hits: 1 }
        }
        _ => ScrubReport::none(),
    }
}

fn scrub_epoch_tokens(input: &str, unit: EpochUnit) -> (String, usize) {
    let mut output = String::with_capacity(input.len());
    let mut current_digits = String::new();
    let mut hits = 0;

    for ch in input.chars() {
        if ch.is_ascii_digit() {
            current_digits.push(ch);
            continue;
        }
        flush_epoch_digits(&mut output, &mut current_digits, unit, &mut hits);
        output.push(ch);
    }
    flush_epoch_digits(&mut output, &mut current_digits, unit, &mut hits);

    if hits == 0 {
        (input.to_string(), 0)
    } else {
        (output, hits)
    }
}

fn flush_epoch_digits(output: &mut String, digits: &mut String, unit: EpochUnit, hits: &mut usize) {
    if digits.is_empty() {
        return;
    }

    if let Ok(value) = digits.parse::<u64>() {
        let matches = match unit {
            EpochUnit::Seconds => {
                digits.len() == 10 && (1_600_000_000..=1_799_999_999).contains(&value)
            }
            EpochUnit::Millis => {
                digits.len() == 13 && (1_600_000_000_000..=1_799_999_999_999).contains(&value)
            }
        };
        if matches {
            output.push_str(match unit {
                EpochUnit::Seconds => "<UNIX>",
                EpochUnit::Millis => "<UNIX_MS>",
            });
            *hits += 1;
            digits.clear();
            return;
        }
    }

    output.push_str(digits);
    digits.clear();
}

fn epoch_number_matches(number: &Number, unit: EpochUnit) -> bool {
    number.as_u64().is_some_and(|value| match unit {
        EpochUnit::Seconds => (1_600_000_000..=1_799_999_999).contains(&value),
        EpochUnit::Millis => (1_600_000_000_000..=1_799_999_999_999).contains(&value),
    })
}

fn scrub_any_scalar_id(value: &mut Value) -> ScrubReport {
    match value {
        Value::String(input) if !input.is_empty() => {
            *input = "<CONN_ID>".to_string();
            ScrubReport { hits: 1 }
        }
        Value::Number(_) => {
            *value = Value::String("<CONN_ID>".to_string());
            ScrubReport { hits: 1 }
        }
        _ => ScrubReport::none(),
    }
}

fn is_provider_id_path(path: &[String]) -> bool {
    let Some(field) = path.last() else {
        return false;
    };
    let normalized = field.replace('-', "_");
    normalized == "id"
        || normalized == "request_id"
        || normalized == "connection_id"
        || normalized == "connectionId"
        || normalized.ends_with("_id")
}

fn uuid_v4_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
            .expect("valid uuid v4 regex")
    })
}

fn rfc3339_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")
            .expect("valid rfc3339 regex")
    })
}

fn bearer_token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"Bearer\s+[A-Za-z0-9._\-/+]{20,}").expect("valid bearer token regex")
    })
}

fn etag_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#""[0-9a-f]{8,}""#).expect("valid etag regex"))
}

fn connection_id_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b(?:req|cnx)_[A-Za-z0-9._-]+\b").expect("valid id regex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_fixture_scrub_cases_match_default_rules() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/differential/scrub_inputs.json"
        ))
        .expect("golden fixture parses");
        let cases = fixture["cases"].as_array().expect("cases array");
        let rules = default_scrub_rules();

        for case in cases {
            let rule_name = case["rule"].as_str().expect("rule name");
            let input = case["input"].as_str().expect("input string");
            let expected = case["expected"].as_str().expect("expected string");
            let rule = rules
                .iter()
                .find(|rule| rule.name() == rule_name)
                .unwrap_or_else(|| panic!("rule {rule_name} exists"));
            let mut value = Value::String(input.to_string());
            let hits = rule.scrub_value(&[], &mut value).hits;
            assert!(hits > 0, "case {rule_name} should scrub at least once");
            assert_eq!(
                value,
                Value::String(expected.to_string()),
                "case {rule_name}"
            );
        }
    }

    #[test]
    fn connection_id_rule_scrubs_provider_id_fields() {
        let mut value = serde_json::json!({
            "id": 42,
            "request_id": "abc",
            "nested": { "connection_id": "live-uuid-9a2b3c4d" }
        });
        scrub_recursive(&ConnectionIdRule, &mut value, &mut Vec::new());
        assert_eq!(
            value,
            serde_json::json!({
                "id": "<CONN_ID>",
                "request_id": "<CONN_ID>",
                "nested": { "connection_id": "<CONN_ID>" }
            })
        );
    }

    fn scrub_recursive(rule: &dyn ScrubRule, value: &mut Value, path: &mut Vec<String>) -> usize {
        let mut hits = rule.scrub_value(path, value).hits;
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    path.push(key.clone());
                    hits += scrub_recursive(rule, child, path);
                    path.pop();
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter_mut().enumerate() {
                    path.push(format!("[{index}]"));
                    hits += scrub_recursive(rule, child, path);
                    path.pop();
                }
            }
            _ => {}
        }
        hits
    }
}
