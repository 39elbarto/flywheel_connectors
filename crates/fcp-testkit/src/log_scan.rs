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
}
