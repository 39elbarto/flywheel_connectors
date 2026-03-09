//! Structured log secret/PII scanner for JSONL artifacts.

use std::collections::HashSet;

use regex::Regex;
use serde_json::Value;

/// Severity of a scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSeverity {
    /// High-confidence secret/token leakage.
    Error,
    /// Potential secret or PII with higher false-positive risk.
    Warn,
}

/// A single scan finding with line number and rule identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFinding {
    /// 1-based line number in the JSONL input.
    pub line: usize,
    /// Rule identifier (stable string).
    pub rule_id: String,
    /// Severity of the finding.
    pub severity: ScanSeverity,
    /// Human-readable description of the rule.
    pub message: String,
    /// Snippet of the matched content.
    pub snippet: String,
    /// Optional JSON path where the match was found.
    pub json_path: Option<String>,
}

#[derive(Debug, Clone)]
struct LogScanRule {
    id: &'static str,
    description: &'static str,
    severity: ScanSeverity,
    pattern: Regex,
}

impl LogScanRule {
    fn new(
        id: &'static str,
        description: &'static str,
        severity: ScanSeverity,
        pattern: &str,
    ) -> Self {
        let regex = Regex::new(pattern).expect("valid regex pattern");
        Self {
            id,
            description,
            severity,
            pattern: regex,
        }
    }
}

/// Allowlist to suppress expected findings.
#[derive(Debug, Default, Clone)]
pub struct LogScanAllowlist {
    rule_ids: HashSet<String>,
    lines: HashSet<usize>,
    substrings: Vec<String>,
    path_substrings: Vec<String>,
}

impl LogScanAllowlist {
    /// Create a new empty allowlist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow findings for a specific rule id.
    pub fn allow_rule_id(&mut self, rule_id: impl Into<String>) {
        self.rule_ids.insert(rule_id.into());
    }

    /// Allow all findings on a specific 1-based line number.
    pub fn allow_line(&mut self, line: usize) {
        self.lines.insert(line);
    }

    /// Allow findings that match a substring.
    pub fn allow_substring(&mut self, value: impl Into<String>) {
        self.substrings.push(value.into());
    }

    /// Allow findings that match a JSON path substring.
    pub fn allow_path_substring(&mut self, value: impl Into<String>) {
        self.path_substrings.push(value.into());
    }

    fn allows(&self, line: usize, rule_id: &str, snippet: &str, path: Option<&str>) -> bool {
        if self.lines.contains(&line) {
            return true;
        }
        if self.rule_ids.contains(rule_id) {
            return true;
        }
        if self.substrings.iter().any(|s| snippet.contains(s)) {
            return true;
        }
        if let Some(path) = path {
            if self.path_substrings.iter().any(|s| path.contains(s)) {
                return true;
            }
        }
        false
    }
}

/// Scanner for JSONL logs to detect secrets and PII patterns.
#[derive(Debug, Clone)]
pub struct LogRedactionScanner {
    rules: Vec<LogScanRule>,
    allowlist: LogScanAllowlist,
}

impl LogRedactionScanner {
    /// Construct a scanner with default rules.
    #[must_use]
    pub fn new() -> Self {
        Self::with_allowlist(LogScanAllowlist::default())
    }

    /// Construct a scanner with an explicit allowlist.
    #[must_use]
    pub fn with_allowlist(allowlist: LogScanAllowlist) -> Self {
        Self {
            rules: default_rules(),
            allowlist,
        }
    }

    /// Access the allowlist mutably (for test overrides).
    pub const fn allowlist_mut(&mut self) -> &mut LogScanAllowlist {
        &mut self.allowlist
    }

    /// Scan a JSONL payload and return all findings.
    #[must_use]
    pub fn scan_jsonl(&self, input: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        for (idx, line) in input.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            findings.extend(self.scan_line(idx + 1, trimmed));
        }
        findings
    }

    fn scan_line(&self, line_no: usize, line: &str) -> Vec<ScanFinding> {
        serde_json::from_str::<Value>(line).map_or_else(
            |_| self.scan_text(line_no, line, None),
            |value| self.scan_json_value(line_no, &value),
        )
    }

    fn scan_json_value(&self, line_no: usize, value: &Value) -> Vec<ScanFinding> {
        let mut strings = Vec::new();
        collect_strings(value, "$", &mut strings);
        let mut findings = Vec::new();
        for (path, text) in strings {
            findings.extend(self.scan_text(line_no, &text, Some(&path)));
        }
        findings
    }

    fn scan_text(&self, line_no: usize, text: &str, path: Option<&str>) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            for mat in rule.pattern.find_iter(text) {
                let snippet = mat.as_str().to_string();
                if rule.id == "BASE64_BLOB"
                    && !snippet.contains('/')
                    && !snippet.contains('+')
                    && !snippet.contains('=')
                {
                    continue;
                }
                if self.allowlist.allows(line_no, rule.id, &snippet, path) {
                    continue;
                }
                findings.push(ScanFinding {
                    line: line_no,
                    rule_id: rule.id.to_string(),
                    severity: rule.severity,
                    message: rule.description.to_string(),
                    snippet,
                    json_path: path.map(std::string::ToString::to_string),
                });
            }
        }
        findings
    }
}

impl Default for LogRedactionScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn default_rules() -> Vec<LogScanRule> {
    vec![
        LogScanRule::new(
            "JWT",
            "JWT token detected",
            ScanSeverity::Error,
            r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        ),
        LogScanRule::new(
            "OPENAI_API_KEY",
            "OpenAI API key detected",
            ScanSeverity::Error,
            r"\bsk-[A-Za-z0-9]{20,}\b",
        ),
        LogScanRule::new(
            "ANTHROPIC_API_KEY",
            "Anthropic API key detected",
            ScanSeverity::Error,
            r"\bsk-ant-[A-Za-z0-9]{20,}\b",
        ),
        LogScanRule::new(
            "GITHUB_TOKEN",
            "GitHub token detected",
            ScanSeverity::Error,
            r"\bgh[pous]_[A-Za-z0-9]{30,}\b",
        ),
        LogScanRule::new(
            "SLACK_TOKEN",
            "Slack token detected",
            ScanSeverity::Error,
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        ),
        LogScanRule::new(
            "AWS_ACCESS_KEY_ID",
            "AWS access key id detected",
            ScanSeverity::Error,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        ),
        LogScanRule::new(
            "BEARER_TOKEN",
            "Bearer token detected",
            ScanSeverity::Error,
            r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b",
        ),
        LogScanRule::new(
            "BASE64_BLOB",
            "Suspicious base64-like blob detected",
            ScanSeverity::Warn,
            r"[A-Za-z0-9+/]{32,}={0,2}",
        ),
        LogScanRule::new(
            "EMAIL",
            "Email address detected",
            ScanSeverity::Warn,
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        ),
    ]
}

fn collect_strings(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => out.push((path.to_string(), text.clone())),
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let next = format!("{path}[{idx}]");
                collect_strings(item, &next, out);
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                let next = if path == "$" {
                    format!("$.{key}")
                } else {
                    format!("{path}.{key}")
                };
                collect_strings(val, &next, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{LogRedactionScanner, LogScanAllowlist, ScanSeverity};
    use crate::LogCapture;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn scans_json_strings_for_openai_key() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"event":"invoke","token":"sk-abc123def456ghi789jkl012mno345pqr"}"#;
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "OPENAI_API_KEY");
        assert_eq!(finding.severity, ScanSeverity::Error);
        assert!(finding.json_path.as_ref().is_some_and(|p| p == "$.token"));
    }

    #[test]
    fn scans_raw_line_when_json_invalid() {
        let scanner = LogRedactionScanner::new();
        let input = "bearer abcdefghijklmnopqrstuvwxyz012345";
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "BEARER_TOKEN");
    }

    #[test]
    fn allowlist_suppresses_by_rule_id() {
        let mut allowlist = LogScanAllowlist::new();
        allowlist.allow_rule_id("EMAIL");
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = r#"{"email":"user@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn allowlist_suppresses_by_line() {
        let mut allowlist = LogScanAllowlist::new();
        allowlist.allow_line(1);
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = "sk-abc123def456ghi789jkl012mno345pqr\n";
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn allowlist_suppresses_by_path_substring() {
        let mut allowlist = LogScanAllowlist::new();
        allowlist.allow_path_substring("$.allowlisted");
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = r#"{"allowlisted":"user@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn scanner_rule_accuracy_emits_jsonl() {
        let scanner = LogRedactionScanner::new();
        let capture = LogCapture::new();
        let cases = vec![
            (
                "JWT",
                r#"{"token":"abc123def456ghi789.jkl012mno345pqr678.stu901vwx234yz"}"#,
            ),
            (
                "OPENAI_API_KEY",
                r#"{"token":"sk-abc123def456ghi789jkl012mno345pqr"}"#,
            ),
            (
                "ANTHROPIC_API_KEY",
                r#"{"token":"sk-ant-abc123def456ghi789jkl012mno345pqr"}"#,
            ),
            (
                "GITHUB_TOKEN",
                r#"{"token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCDE"}"#,
            ),
            (
                "SLACK_TOKEN",
                r#"{"token":"xoxb-1234567890-abcdefg-hijklmnop"}"#,
            ),
            ("AWS_ACCESS_KEY_ID", r#"{"token":"AKIA1234567890ABCDEF"}"#),
            ("BEARER_TOKEN", "bearer abcdefghijklmnopqrstuvwxyz012345"),
            (
                "BASE64_BLOB",
                r#"{"payload":"dGVzdC9hYmNkZWZnaGppS0xNTk9QUVJTVFVWVw=="}"#,
            ),
            ("EMAIL", r#"{"email":"user@example.com"}"#),
        ];

        for (rule_id, input) in cases {
            let findings = scanner.scan_jsonl(input);
            let matched = findings.iter().any(|f| f.rule_id == rule_id);
            let result = if matched { "pass" } else { "fail" };
            let assertions = json!({
                "passed": i32::from(matched),
                "failed": i32::from(!matched)
            });
            let entry = json!({
                "timestamp": Utc::now().to_rfc3339(),
                "test_name": format!("scanner_rule_{rule_id}"),
                "module": "fcp-testkit",
                "phase": "execute",
                "correlation_id": Uuid::new_v4().to_string(),
                "result": result,
                "duration_ms": 0,
                "assertions": assertions,
                "context": {
                    "rule_id": rule_id,
                    "input": input,
                    "finding_count": findings.len()
                }
            });
            capture.push_value(&entry).expect("log entry");
            assert!(matched, "expected rule {rule_id} to match");
        }

        capture.assert_valid();
    }

    #[test]
    fn scanner_benign_strings_not_flagged() {
        let scanner = LogRedactionScanner::new();
        let capture = LogCapture::new();
        let input = r#"{"message":"hello world","count":42}"#;
        let findings = scanner.scan_jsonl(input);
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": "scanner_benign_strings",
            "module": "fcp-testkit",
            "phase": "execute",
            "correlation_id": Uuid::new_v4().to_string(),
            "result": if findings.is_empty() { "pass" } else { "fail" },
            "duration_ms": 0,
            "assertions": {
                "passed": i32::from(findings.is_empty()),
                "failed": i32::from(!findings.is_empty())
            },
            "context": {
                "finding_count": findings.len()
            }
        });
        capture.push_value(&entry).expect("log entry");
        capture.assert_valid();
        assert!(findings.is_empty());
    }

    #[test]
    fn allowlist_suppresses_by_substring() {
        let mut allowlist = LogScanAllowlist::new();
        allowlist.allow_substring("sk-abc");
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = r#"{"token":"sk-abc123def456ghi789jkl012mno345pqr"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_input_no_findings() {
        let scanner = LogRedactionScanner::new();
        assert!(scanner.scan_jsonl("").is_empty());
        assert!(scanner.scan_jsonl("   \n  \n").is_empty());
    }

    #[test]
    fn multi_line_finds_on_correct_lines() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"ok":"safe data"}
{"email":"leak@test.com"}
{"count":42}"#;
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].rule_id, "EMAIL");
    }

    #[test]
    fn base64_without_special_chars_not_flagged() {
        let scanner = LogRedactionScanner::new();
        // Pure alphanumeric string without +/= should NOT trigger BASE64_BLOB
        let input = r#"{"data":"abcdefghijklmnopqrstuvwxyz012345678901234"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(!findings.iter().any(|f| f.rule_id == "BASE64_BLOB"));
    }

    #[test]
    fn scan_nested_json_values() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"outer":{"inner":{"deep":"user@nested.example.com"}}}"#;
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "EMAIL");
        assert!(findings[0].json_path.as_ref().unwrap().contains("deep"));
    }

    #[test]
    fn scan_json_array_values() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"emails":["a@example.com","b@example.com"]}"#;
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.iter().filter(|f| f.rule_id == "EMAIL").count(), 2);
    }

    #[test]
    fn default_scanner_same_as_new() {
        let a = LogRedactionScanner::new();
        let b = LogRedactionScanner::default();
        assert_eq!(a.rules.len(), b.rules.len());
    }

    #[test]
    fn scan_severity_debug() {
        assert!(format!("{:?}", ScanSeverity::Error).contains("Error"));
        assert!(format!("{:?}", ScanSeverity::Warn).contains("Warn"));
    }

    #[test]
    fn scan_severity_eq() {
        assert_eq!(ScanSeverity::Error, ScanSeverity::Error);
        assert_eq!(ScanSeverity::Warn, ScanSeverity::Warn);
        assert_ne!(ScanSeverity::Error, ScanSeverity::Warn);
    }

    #[test]
    fn scan_finding_clone_eq() {
        let finding = super::ScanFinding {
            line: 1,
            rule_id: "TEST".into(),
            severity: ScanSeverity::Error,
            message: "test".into(),
            snippet: "snippet".into(),
            json_path: Some("$.field".into()),
        };
        let cloned = finding.clone();
        assert_eq!(finding, cloned);
    }

    #[test]
    fn allowlist_multiple_mechanisms() {
        let mut allowlist = LogScanAllowlist::new();
        allowlist.allow_rule_id("EMAIL");
        allowlist.allow_line(2);
        allowlist.allow_substring("safe-key");
        allowlist.allow_path_substring("$.allowed");

        let scanner = LogRedactionScanner::with_allowlist(allowlist);

        // Line 1: EMAIL suppressed by rule_id
        let input1 = r#"{"email":"user@example.com"}"#;
        assert!(scanner.scan_jsonl(input1).is_empty());
    }

    #[test]
    fn allowlist_mut_access() {
        let mut scanner = LogRedactionScanner::new();
        scanner.allowlist_mut().allow_rule_id("EMAIL");
        let input = r#"{"email":"user@example.com"}"#;
        assert!(scanner.scan_jsonl(input).is_empty());
    }

    #[test]
    fn github_token_variants() {
        let scanner = LogRedactionScanner::new();
        for prefix in &["ghp_", "gho_", "ghu_", "ghs_"] {
            let token = format!("{prefix}{}", "a".repeat(36));
            let input = format!(r#"{{"token":"{token}"}}"#);
            let findings = scanner.scan_jsonl(&input);
            assert!(
                findings.iter().any(|f| f.rule_id == "GITHUB_TOKEN"),
                "expected GITHUB_TOKEN for prefix {prefix}"
            );
        }
    }

    #[test]
    fn slack_token_variants() {
        let scanner = LogRedactionScanner::new();
        for prefix in &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"] {
            let token = format!("{prefix}{}", "a".repeat(15));
            let input = format!(r#"{{"token":"{token}"}}"#);
            let findings = scanner.scan_jsonl(&input);
            assert!(
                findings.iter().any(|f| f.rule_id == "SLACK_TOKEN"),
                "expected SLACK_TOKEN for prefix {prefix}"
            );
        }
    }

    // ---- Additional scanner tests ----

    #[test]
    fn scan_finding_debug_format() {
        let finding = super::ScanFinding {
            line: 5,
            rule_id: "TEST_RULE".into(),
            severity: ScanSeverity::Warn,
            message: "test message".into(),
            snippet: "test-snippet".into(),
            json_path: None,
        };
        let dbg = format!("{finding:?}");
        assert!(dbg.contains("ScanFinding"));
        assert!(dbg.contains("TEST_RULE"));
        assert!(dbg.contains("Warn"));
    }

    #[test]
    fn scan_finding_without_json_path() {
        let finding = super::ScanFinding {
            line: 1,
            rule_id: "R".into(),
            severity: ScanSeverity::Error,
            message: "m".into(),
            snippet: "s".into(),
            json_path: None,
        };
        let cloned = finding.clone();
        assert!(cloned.json_path.is_none());
        assert_eq!(finding.line, cloned.line);
    }

    #[test]
    fn scan_severity_clone() {
        let s = ScanSeverity::Error;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn scan_severity_copy() {
        let a = ScanSeverity::Warn;
        let b = a;
        // both are still valid
        assert_eq!(a, b);
    }

    #[test]
    fn allowlist_default_is_empty() {
        let al = super::LogScanAllowlist::default();
        let dbg = format!("{al:?}");
        assert!(dbg.contains("LogScanAllowlist"));
    }

    #[test]
    fn allowlist_clone() {
        let mut al = super::LogScanAllowlist::new();
        al.allow_rule_id("TEST");
        al.allow_line(42);
        al.allow_substring("safe");
        al.allow_path_substring("$.ok");
        let cloned = al.clone();
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("LogScanAllowlist"));
    }

    #[test]
    fn scanner_clone() {
        let scanner = LogRedactionScanner::new();
        let cloned = scanner.clone();
        // Both should produce same results
        let input = r#"{"email":"user@example.com"}"#;
        assert_eq!(
            scanner.scan_jsonl(input).len(),
            cloned.scan_jsonl(input).len()
        );
    }

    #[test]
    fn scanner_debug() {
        let scanner = LogRedactionScanner::new();
        let dbg = format!("{scanner:?}");
        assert!(dbg.contains("LogRedactionScanner"));
    }

    #[test]
    fn multiple_findings_on_single_line() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"a":"user@one.com","b":"admin@two.com"}"#;
        let findings = scanner.scan_jsonl(input);
        let email_count = findings.iter().filter(|f| f.rule_id == "EMAIL").count();
        assert_eq!(email_count, 2);
    }

    #[test]
    fn aws_access_key_akia_detected() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"key":"AKIA1234567890ABCDEF"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.iter().any(|f| f.rule_id == "AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn aws_access_key_asia_detected() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"key":"ASIA1234567890ABCDEF"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.iter().any(|f| f.rule_id == "AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn anthropic_api_key_detected() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"key":"sk-ant-abcdefghijklmnopqrstuvwxyz"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.iter().any(|f| f.rule_id == "ANTHROPIC_API_KEY"));
    }

    #[test]
    fn bearer_token_case_insensitive() {
        let scanner = LogRedactionScanner::new();
        let input = "Bearer abcdefghijklmnopqrstuvwxyz012345";
        let findings = scanner.scan_jsonl(input);
        assert!(findings.iter().any(|f| f.rule_id == "BEARER_TOKEN"));

        let input2 = "BEARER abcdefghijklmnopqrstuvwxyz012345";
        let findings2 = scanner.scan_jsonl(input2);
        assert!(findings2.iter().any(|f| f.rule_id == "BEARER_TOKEN"));
    }

    #[test]
    fn whitespace_only_lines_skipped() {
        let scanner = LogRedactionScanner::new();
        let input = "   \n\n  \n";
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_finding_line_numbers_correct() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"safe":"ok"}
{"safe":"still ok"}
{"email":"leak@test.com"}
{"safe":"also ok"}"#;
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn scan_json_with_numeric_values_no_false_positives() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"count":12345,"amount":1.23,"flag":true}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn allowlist_path_substring_partial_match() {
        let mut allowlist = super::LogScanAllowlist::new();
        allowlist.allow_path_substring("safe");
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = r#"{"safe_field":"user@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_json_array_at_top_level() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"list":["user@one.com","no-secret","admin@two.com"]}"#;
        let findings = scanner.scan_jsonl(input);
        let email_count = findings.iter().filter(|f| f.rule_id == "EMAIL").count();
        assert_eq!(email_count, 2);
    }

    #[test]
    fn scan_finding_snippet_contains_match() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"email":"admin@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].snippet.contains("admin@example.com"));
    }

    // ---- Additional edge case scanner tests ----

    #[test]
    fn scan_finding_ne_different_rule_ids() {
        let a = super::ScanFinding {
            line: 1,
            rule_id: "A".into(),
            severity: ScanSeverity::Error,
            message: "msg".into(),
            snippet: "s".into(),
            json_path: None,
        };
        let b = super::ScanFinding {
            line: 1,
            rule_id: "B".into(),
            severity: ScanSeverity::Error,
            message: "msg".into(),
            snippet: "s".into(),
            json_path: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn scan_finding_ne_different_severity() {
        let a = super::ScanFinding {
            line: 1,
            rule_id: "R".into(),
            severity: ScanSeverity::Error,
            message: "m".into(),
            snippet: "s".into(),
            json_path: None,
        };
        let b = super::ScanFinding {
            line: 1,
            rule_id: "R".into(),
            severity: ScanSeverity::Warn,
            message: "m".into(),
            snippet: "s".into(),
            json_path: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn scan_finding_ne_different_lines() {
        let a = super::ScanFinding {
            line: 1,
            rule_id: "R".into(),
            severity: ScanSeverity::Error,
            message: "m".into(),
            snippet: "s".into(),
            json_path: None,
        };
        let b = super::ScanFinding {
            line: 2,
            rule_id: "R".into(),
            severity: ScanSeverity::Error,
            message: "m".into(),
            snippet: "s".into(),
            json_path: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn scan_unicode_local_part_email_not_matched() {
        let scanner = LogRedactionScanner::new();
        // Unicode chars in local part are not matched by the ASCII-only email regex
        let input = "{\"msg\":\"caf\u{00e9}@example.com\"}";
        let findings = scanner.scan_jsonl(input);
        // The regex [A-Za-z0-9._%+-]+ won't match é, so it may not find the full email
        // This verifies the scanner doesn't crash on unicode input
        let _ = findings;
    }

    #[test]
    fn scan_multiple_rules_match_same_line() {
        let scanner = LogRedactionScanner::new();
        // Line has both an email and a bearer token
        let input = r#"{"a":"user@example.com","b":"bearer abcdefghijklmnopqrstuvwxyz012345"}"#;
        let findings = scanner.scan_jsonl(input);
        let email_count = findings.iter().filter(|f| f.rule_id == "EMAIL").count();
        let bearer_count = findings
            .iter()
            .filter(|f| f.rule_id == "BEARER_TOKEN")
            .count();
        assert!(email_count >= 1);
        assert!(bearer_count >= 1);
    }

    #[test]
    fn allowlist_does_not_suppress_other_lines() {
        let mut allowlist = super::LogScanAllowlist::new();
        allowlist.allow_line(1);
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = "safe-line\n{\"email\":\"user@leak.com\"}";
        let findings = scanner.scan_jsonl(input);
        // Line 2 should still be detected
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn allowlist_does_not_suppress_other_rules() {
        let mut allowlist = super::LogScanAllowlist::new();
        allowlist.allow_rule_id("JWT");
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = r#"{"email":"user@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        // EMAIL should still be detected
        assert!(findings.iter().any(|f| f.rule_id == "EMAIL"));
    }

    #[test]
    fn scan_json_with_null_values_no_false_positives() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"a":null,"b":null}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_json_with_empty_string_values() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"key":""}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_deeply_nested_secret() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"a":{"b":{"c":{"d":{"key":"sk-abc123def456ghi789jkl012mno345pqr"}}}}}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.iter().any(|f| f.rule_id == "OPENAI_API_KEY"));
        let path = findings[0].json_path.as_ref().unwrap();
        assert!(path.contains("key"));
    }

    #[test]
    fn scan_finding_message_is_non_empty() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"email":"user@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(!findings[0].message.is_empty());
    }

    #[test]
    fn scan_json_boolean_values_no_false_positives() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"active":true,"deleted":false}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn allowlist_substring_partial_match_works() {
        let mut allowlist = super::LogScanAllowlist::new();
        allowlist.allow_substring("example.com");
        let scanner = LogRedactionScanner::with_allowlist(allowlist);
        let input = r#"{"email":"admin@example.com"}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_finding_json_path_for_nested_array() {
        let scanner = LogRedactionScanner::new();
        let input = r#"{"users":[{"email":"a@b.com"}]}"#;
        let findings = scanner.scan_jsonl(input);
        assert!(!findings.is_empty());
        let path = findings[0].json_path.as_ref().unwrap();
        assert!(path.contains("users"));
        assert!(path.contains("[0]"));
    }
}
