//! Differential testing harness for loopback-vs-live connector responses.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::differential_scrub::{ScrubRule, default_scrub_rules};

/// Side of a differential comparison.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Side {
    /// The loopback fixture response.
    Loopback,
    /// The live provider response.
    Live,
}

/// Result of comparing loopback and live response bytes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DifferentialResult {
    /// Responses are structurally equivalent after scrub rules.
    Equivalent,
    /// Responses differ after scrubbing.
    Divergent {
        /// Human-readable field-path summary.
        diff_summary: String,
        /// Number of scrub applications on the loopback response.
        loopback_scrub_hits: usize,
        /// Number of scrub applications on the live response.
        live_scrub_hits: usize,
    },
    /// One side was not parseable JSON.
    ParseError {
        /// Side that failed parsing.
        side: Side,
        /// Parser error string.
        error: String,
    },
}

/// Loopback-vs-live response comparator.
pub struct DifferentialHarness {
    scrubs: Vec<Box<dyn ScrubRule>>,
}

impl Default for DifferentialHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl DifferentialHarness {
    /// Build a harness with the default scrub-rule set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scrubs: default_scrub_rules(),
        }
    }

    /// Add a connector-specific scrub rule.
    #[must_use]
    pub fn with_scrub<R: ScrubRule + 'static>(mut self, rule: R) -> Self {
        self.scrubs.push(Box::new(rule));
        self
    }

    /// Compare two JSON response byte slices after applying scrub rules.
    #[must_use]
    pub fn compare(&self, loopback: &[u8], live: &[u8]) -> DifferentialResult {
        let mut loopback_value = match serde_json::from_slice::<Value>(loopback) {
            Ok(value) => value,
            Err(error) => {
                return DifferentialResult::ParseError {
                    side: Side::Loopback,
                    error: error.to_string(),
                };
            }
        };
        let mut live_value = match serde_json::from_slice::<Value>(live) {
            Ok(value) => value,
            Err(error) => {
                return DifferentialResult::ParseError {
                    side: Side::Live,
                    error: error.to_string(),
                };
            }
        };

        let loopback_scrub_hits = self.scrub_value(&mut loopback_value);
        let live_scrub_hits = self.scrub_value(&mut live_value);
        if loopback_value == live_value {
            return DifferentialResult::Equivalent;
        }

        let diffs = diff_values(&loopback_value, &live_value);
        DifferentialResult::Divergent {
            diff_summary: format_diff_summary(&diffs),
            loopback_scrub_hits,
            live_scrub_hits,
        }
    }

    /// Apply configured scrub rules to an already parsed JSON value.
    pub fn scrub_value(&self, value: &mut Value) -> usize {
        scrub_recursive(&self.scrubs, value, &mut Vec::new())
    }
}

fn scrub_recursive(
    rules: &[Box<dyn ScrubRule>],
    value: &mut Value,
    path: &mut Vec<String>,
) -> usize {
    let mut hits = rules
        .iter()
        .map(|rule| rule.scrub_value(path, value).hits)
        .sum();

    match value {
        Value::Object(map) => {
            for (key, child) in map {
                path.push(key.clone());
                hits += scrub_recursive(rules, child, path);
                path.pop();
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter_mut().enumerate() {
                path.push(format!("[{index}]"));
                hits += scrub_recursive(rules, child, path);
                path.pop();
            }
        }
        _ => {}
    }

    hits
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct FieldDiff {
    path: String,
    detail: String,
}

fn diff_values(loopback: &Value, live: &Value) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();
    diff_at_path(loopback, live, &mut Vec::new(), &mut diffs);
    diffs
}

fn diff_at_path(
    loopback: &Value,
    live: &Value,
    path: &mut Vec<String>,
    diffs: &mut Vec<FieldDiff>,
) {
    match (loopback, live) {
        (Value::Object(loopback_map), Value::Object(live_map)) => {
            let keys = loopback_map
                .keys()
                .chain(live_map.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            for key in keys {
                path.push(key.clone());
                match (loopback_map.get(&key), live_map.get(&key)) {
                    (Some(loopback_child), Some(live_child)) => {
                        diff_at_path(loopback_child, live_child, path, diffs);
                    }
                    (Some(loopback_child), None) => diffs.push(FieldDiff {
                        path: format_path(path),
                        detail: format!("present only on loopback: {}", compact(loopback_child)),
                    }),
                    (None, Some(live_child)) => diffs.push(FieldDiff {
                        path: format_path(path),
                        detail: format!("present only on live: {}", compact(live_child)),
                    }),
                    (None, None) => {}
                }
                path.pop();
            }
        }
        (Value::Array(loopback_array), Value::Array(live_array)) => {
            if loopback_array.len() != live_array.len() {
                diffs.push(FieldDiff {
                    path: format_path(path),
                    detail: format!(
                        "array length differs: loopback={} live={}",
                        loopback_array.len(),
                        live_array.len()
                    ),
                });
            }
            for (index, (loopback_child, live_child)) in
                loopback_array.iter().zip(live_array).enumerate()
            {
                path.push(format!("[{index}]"));
                diff_at_path(loopback_child, live_child, path, diffs);
                path.pop();
            }
        }
        _ if loopback != live => diffs.push(FieldDiff {
            path: format_path(path),
            detail: format!("loopback={} live={}", compact(loopback), compact(live)),
        }),
        _ => {}
    }
}

fn format_path(path: &[String]) -> String {
    if path.is_empty() {
        return "$".to_string();
    }

    let mut output = String::new();
    for segment in path {
        if !segment.starts_with('[') && !output.is_empty() {
            output.push('.');
        }
        output.push_str(segment);
    }
    output
}

fn compact(value: &Value) -> String {
    const LIMIT: usize = 160;
    let mut text = serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_string());
    if text.len() > LIMIT {
        text.truncate(LIMIT);
        text.push_str("...");
    }
    text
}

fn format_diff_summary(diffs: &[FieldDiff]) -> String {
    if diffs.is_empty() {
        return "values differ but no field path was identified".to_string();
    }

    let mut parts = diffs
        .iter()
        .take(8)
        .map(|diff| format!("field `{}`: {}", diff.path, diff.detail))
        .collect::<Vec<_>>();
    if diffs.len() > parts.len() {
        parts.push(format!(
            "{} additional field diffs omitted",
            diffs.len() - parts.len()
        ));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_byte_equal_after_scrub() {
        let loopback = br#"{
            "id": "fixture-uuid-7c3e9f1a",
            "created_at": "2026-05-13T18:42:31Z",
            "amount": 12.50,
            "currency": "USD"
        }"#;
        let live = br#"{
            "id": "live-uuid-9a2b3c4d",
            "created_at": "2026-05-13T19:00:00Z",
            "amount": 12.50,
            "currency": "USD"
        }"#;

        assert_eq!(
            DifferentialHarness::new().compare(loopback, live),
            DifferentialResult::Equivalent
        );
    }

    #[test]
    fn test_diff_byte_inequal_signals_failure() {
        let loopback = br#"{"id":"u1","amount":12.5,"currency":"USD"}"#;
        let live = br#"{"id":"u2","amount":12.5,"currency":"EUR"}"#;

        let result = DifferentialHarness::new().compare(loopback, live);
        let DifferentialResult::Divergent { diff_summary, .. } = result else {
            panic!("expected divergent result");
        };
        assert!(
            diff_summary.contains("currency"),
            "summary should point at semantic field: {diff_summary}"
        );
    }

    #[test]
    fn parse_error_identifies_live_side() {
        let result = DifferentialHarness::new().compare(br#"{"id":"u1"}"#, b"<html>503</html>");
        assert!(matches!(
            result,
            DifferentialResult::ParseError {
                side: Side::Live,
                ..
            }
        ));
    }

    #[test]
    fn golden_fixture_diff_cases_match_expected_verdicts() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/differential/scrub_inputs.json"
        ))
        .expect("golden fixture parses");
        let cases = fixture["diff_cases"].as_array().expect("diff cases array");
        let harness = DifferentialHarness::new();

        for case in cases {
            let name = case["name"].as_str().expect("case name");
            let loopback = serde_json::to_vec(&case["loopback"]).expect("serialize loopback");
            let live = case.get("live_raw").map_or_else(
                || serde_json::to_vec(&case["live"]).expect("serialize live"),
                |raw| raw.as_str().expect("raw live string").as_bytes().to_vec(),
            );
            let result = harness.compare(&loopback, &live);
            match case["expected_verdict"].as_str().expect("expected verdict") {
                "equivalent" => assert_eq!(result, DifferentialResult::Equivalent, "{name}"),
                "divergent" => {
                    let DifferentialResult::Divergent { diff_summary, .. } = result else {
                        panic!("{name} should diverge");
                    };
                    let expected_field = case["expected_field"].as_str().expect("field");
                    assert!(
                        diff_summary.contains(expected_field),
                        "{name} summary should include {expected_field}: {diff_summary}"
                    );
                }
                "parse_error" => {
                    let DifferentialResult::ParseError { side, .. } = result else {
                        panic!("{name} should parse-error");
                    };
                    assert_eq!(format!("{side:?}"), case["expected_side"].as_str().unwrap());
                }
                other => panic!("unknown expected verdict {other}"),
            }
        }
    }
}
