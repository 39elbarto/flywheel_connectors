//! Requirements index parser and validation.
//!
//! Parses `docs/STANDARD_Requirements_Index.md` and validates that all referenced
//! bead IDs exist in the project's beads database.
//!
//! # Format
//!
//! The requirements index contains markdown tables with rows like:
//! ```markdown
//! | **Owners** | `flywheel_connectors-1n78.21`, `bd-3frf` |
//! | **Tests** | `flywheel_connectors-1n78.21.1` (golden vectors) |
//! ```
//!
//! The parser extracts backtick-quoted bead IDs and validates them.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::Path;

/// A parsed requirement entry from the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementEntry {
    /// Section title (e.g., "§1: Introduction").
    pub section: String,
    /// Line number where this entry starts.
    pub line_number: usize,
    /// Owner bead IDs extracted from the Owners row.
    pub owners: Vec<String>,
    /// Test bead IDs extracted from the Tests row.
    pub tests: Vec<String>,
    /// Notes text (informational).
    pub notes: Option<String>,
}

/// Validation error for a requirements entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Section where the error occurred.
    pub section: String,
    /// Line number (if available).
    pub line_number: Option<usize>,
    /// Error type (e.g., `missing_bead`, `duplicate_entry`).
    pub error_type: String,
    /// The problematic bead ID or value.
    pub value: String,
    /// Human-readable message.
    pub message: String,
}

/// Validation warning (non-blocking issues).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationWarning {
    /// Section where the warning occurred.
    pub section: String,
    /// Line number (if available).
    pub line_number: Option<usize>,
    /// Warning type.
    pub warning_type: String,
    /// Human-readable message.
    pub message: String,
}

/// Validation report output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Total entries parsed.
    pub total_entries: usize,
    /// Unique bead IDs referenced.
    pub unique_beads: usize,
    /// Missing bead IDs (referenced but not found).
    pub missing_beads: Vec<String>,
    /// All errors found.
    pub errors: Vec<ValidationError>,
    /// All warnings found.
    pub warnings: Vec<ValidationWarning>,
    /// Parsed entries for reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<RequirementEntry>>,
}

impl ValidationReport {
    /// Returns true if validation passed (no errors).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Parser for the requirements index markdown.
#[derive(Debug, Default)]
pub struct RequirementsIndexParser {
    entries: Vec<RequirementEntry>,
    all_bead_ids: HashSet<String>,
}

impl RequirementsIndexParser {
    /// Create a new parser.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a requirements index file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> std::io::Result<()> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        self.parse_reader(reader)
    }

    /// Parse from a reader.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails.
    pub fn parse_reader<R: BufRead>(&mut self, reader: R) -> std::io::Result<()> {
        let mut current_section = String::new();
        let mut in_table = false;
        let mut table_start_line = 0;
        let mut current_owners = Vec::new();
        let mut current_tests = Vec::new();
        let mut current_notes = None;

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result?;
            let line_number = line_num + 1; // 1-indexed

            // Detect section headers (## §N: Title)
            if let Some(stripped) = line.strip_prefix("## ") {
                // Save previous entry if we were in a table
                if in_table && (!current_owners.is_empty() || !current_tests.is_empty()) {
                    self.save_entry(
                        &current_section,
                        table_start_line,
                        &current_owners,
                        &current_tests,
                        &current_notes,
                    );
                }
                current_section = stripped.trim().to_string();
                in_table = false;
                current_owners.clear();
                current_tests.clear();
                current_notes = None;
            }

            // Detect table rows
            if line.starts_with('|') && line.contains('|') {
                if !in_table {
                    in_table = true;
                    table_start_line = line_number;
                }

                // Parse table row
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                if cells.len() >= 3 {
                    let aspect = cells[1].trim();
                    let details = cells[2].trim();

                    if aspect.contains("Owners") {
                        current_owners = extract_bead_ids(details);
                        for id in &current_owners {
                            self.all_bead_ids.insert(id.clone());
                        }
                    } else if aspect.contains("Tests") {
                        current_tests = extract_bead_ids(details);
                        for id in &current_tests {
                            self.all_bead_ids.insert(id.clone());
                        }
                    } else if aspect.contains("Notes") {
                        current_notes = Some(details.to_string());
                    }
                }
            } else if in_table && line.starts_with("---") {
                // Table separator - save entry and reset
                if !current_owners.is_empty() || !current_tests.is_empty() {
                    self.save_entry(
                        &current_section,
                        table_start_line,
                        &current_owners,
                        &current_tests,
                        &current_notes,
                    );
                }
                in_table = false;
                current_owners.clear();
                current_tests.clear();
                current_notes = None;
            }
        }

        // Save final entry if any
        if in_table && (!current_owners.is_empty() || !current_tests.is_empty()) {
            self.save_entry(
                &current_section,
                table_start_line,
                &current_owners,
                &current_tests,
                &current_notes,
            );
        }

        Ok(())
    }

    #[allow(clippy::ref_option)]
    fn save_entry(
        &mut self,
        section: &str,
        line_number: usize,
        owners: &[String],
        tests: &[String],
        notes: &Option<String>,
    ) {
        self.entries.push(RequirementEntry {
            section: section.to_string(),
            line_number,
            owners: owners.to_vec(),
            tests: tests.to_vec(),
            notes: notes.clone(),
        });
    }

    /// Get all parsed entries.
    #[must_use]
    pub fn entries(&self) -> &[RequirementEntry] {
        &self.entries
    }

    /// Get all unique bead IDs referenced.
    #[must_use]
    pub const fn all_bead_ids(&self) -> &HashSet<String> {
        &self.all_bead_ids
    }

    /// Validate against a set of known bead IDs.
    #[must_use]
    pub fn validate(&self, known_beads: &HashSet<String>) -> ValidationReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut missing_beads = HashSet::new();

        // Check each referenced bead exists
        for entry in &self.entries {
            for bead_id in entry.owners.iter().chain(entry.tests.iter()) {
                if !known_beads.contains(bead_id) {
                    missing_beads.insert(bead_id.clone());
                    errors.push(ValidationError {
                        section: entry.section.clone(),
                        line_number: Some(entry.line_number),
                        error_type: "missing_bead".to_string(),
                        value: bead_id.clone(),
                        message: format!("Bead ID `{bead_id}` not found in beads database"),
                    });
                }
            }

            // Warn if no owners specified
            if entry.owners.is_empty() {
                warnings.push(ValidationWarning {
                    section: entry.section.clone(),
                    line_number: Some(entry.line_number),
                    warning_type: "missing_owners".to_string(),
                    message: "No owner beads specified".to_string(),
                });
            }
        }

        // Check for duplicate entries
        let mut seen_sections: HashMap<String, usize> = HashMap::new();
        for entry in &self.entries {
            if let Some(prev_line) = seen_sections.get(&entry.section) {
                warnings.push(ValidationWarning {
                    section: entry.section.clone(),
                    line_number: Some(entry.line_number),
                    warning_type: "duplicate_section".to_string(),
                    message: format!("Section appears multiple times (first at line {prev_line})"),
                });
            } else {
                seen_sections.insert(entry.section.clone(), entry.line_number);
            }
        }

        let mut missing_beads: Vec<String> = missing_beads.into_iter().collect();
        missing_beads.sort();

        ValidationReport {
            total_entries: self.entries.len(),
            unique_beads: self.all_bead_ids.len(),
            missing_beads,
            errors,
            warnings,
            entries: None,
        }
    }
}

/// Extract bead IDs from a table cell.
///
/// Looks for backtick-quoted identifiers matching bead ID patterns.
fn extract_bead_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();

    // Match backtick-quoted identifiers
    let mut in_backtick = false;
    let mut current = String::new();

    for ch in text.chars() {
        if ch == '`' {
            if in_backtick {
                // End of backtick span - check if it's a bead ID
                if is_bead_id(&current) {
                    ids.push(current.clone());
                }
                current.clear();
            }
            in_backtick = !in_backtick;
        } else if in_backtick {
            current.push(ch);
        }
    }

    ids
}

/// Check if a string looks like a bead ID.
///
/// Bead IDs match patterns like:
/// - `flywheel_connectors-1n78`
/// - `flywheel_connectors-1n78.21`
/// - `bd-3frf`
fn is_bead_id(s: &str) -> bool {
    // Must contain a hyphen
    if !s.contains('-') {
        return false;
    }

    // Split on hyphen and check parts
    let parts: Vec<&str> = s.splitn(2, '-').collect();
    if parts.len() != 2 {
        return false;
    }

    let prefix = parts[0];
    let suffix = parts[1];

    // Known prefixes
    let known_prefixes = ["flywheel_connectors", "bd"];
    if !known_prefixes.contains(&prefix) {
        return false;
    }

    // Suffix should be alphanumeric with optional dots
    suffix
        .chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
}

/// Load bead IDs from a JSONL file (beads export format).
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_beads_from_jsonl<P: AsRef<Path>>(path: P) -> std::io::Result<HashSet<String>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut beads = HashSet::new();

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSONL entry
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
                beads.insert(id.to_string());
            }
        }
    }

    Ok(beads)
}

/// Load bead IDs by running `br list --json`.
///
/// # Errors
///
/// Returns an error if the command fails or output cannot be parsed.
pub fn load_beads_from_br_list() -> std::io::Result<HashSet<String>> {
    let output = std::process::Command::new("br")
        .args(["list", "--json"])
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "br list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut beads = HashSet::new();

    // br list --json outputs a JSON array
    if let Ok(array) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(entries) = array.as_array() {
            for entry in entries {
                if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
                    beads.insert(id.to_string());
                }
            }
        }
    }

    Ok(beads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bead_ids_basic() {
        let text = "`flywheel_connectors-1n78.21`, `bd-3frf` (golden vectors)";
        let ids = extract_bead_ids(text);
        assert_eq!(ids, vec!["flywheel_connectors-1n78.21", "bd-3frf"]);
    }

    #[test]
    fn extract_bead_ids_empty() {
        assert!(extract_bead_ids("n/a").is_empty());
        assert!(extract_bead_ids("").is_empty());
    }

    #[test]
    fn extract_bead_ids_non_bead() {
        // Regular code spans should not be extracted
        let text = "`ObjectHeader` rules and `ZoneId` semantics";
        assert!(extract_bead_ids(text).is_empty());
    }

    #[test]
    fn is_bead_id_valid() {
        assert!(is_bead_id("flywheel_connectors-1n78"));
        assert!(is_bead_id("flywheel_connectors-1n78.21"));
        assert!(is_bead_id("flywheel_connectors-1n78.21.1"));
        assert!(is_bead_id("bd-3frf"));
        assert!(is_bead_id("bd-gz2y"));
    }

    #[test]
    fn is_bead_id_invalid() {
        assert!(!is_bead_id("ObjectHeader"));
        assert!(!is_bead_id("ZoneId"));
        assert!(!is_bead_id("some-random-thing"));
        assert!(!is_bead_id(""));
    }

    #[test]
    fn parse_simple_table() {
        let content = r"
## §1: Introduction

| Aspect | Details |
|--------|---------|
| **Owners** | `flywheel_connectors-1n78.1` |
| **Tests** | n/a |
| **Notes** | Test notes. |

---
";

        let mut parser = RequirementsIndexParser::new();
        parser.parse_reader(content.as_bytes()).unwrap();

        assert_eq!(parser.entries().len(), 1);
        let entry = &parser.entries()[0];
        assert_eq!(entry.section, "§1: Introduction");
        assert_eq!(entry.owners, vec!["flywheel_connectors-1n78.1"]);
        assert!(entry.tests.is_empty());
    }

    #[test]
    fn validate_missing_beads() {
        let mut parser = RequirementsIndexParser::new();
        let content = r"
## §1: Test

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-9xyz` |
| **Tests** | `bd-8abc` |

---
";
        parser.parse_reader(content.as_bytes()).unwrap();

        let known: HashSet<String> = HashSet::new();
        let report = parser.validate(&known);

        assert!(!report.is_valid());
        assert_eq!(report.errors.len(), 2);
        assert_eq!(
            report.missing_beads,
            vec!["bd-8abc".to_string(), "bd-9xyz".to_string()]
        );
    }

    #[test]
    fn validate_all_found() {
        let mut parser = RequirementsIndexParser::new();
        let content = r"
## §1: Test

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-test` |
| **Tests** | `bd-test2` |

---
";
        parser.parse_reader(content.as_bytes()).unwrap();

        let mut known = HashSet::new();
        known.insert("bd-test".to_string());
        known.insert("bd-test2".to_string());

        let report = parser.validate(&known);
        assert!(report.is_valid());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Comprehensive tests per bd-6gaj: whitespace, malformed rows, structured JSONL
    // ─────────────────────────────────────────────────────────────────────────────

    use std::fmt::Write as _;

    use chrono::Utc;
    use fcp_testkit::LogCapture;
    use serde_json::json;
    use uuid::Uuid;

    /// Helper to emit a structured JSONL test result.
    fn emit_test_result(
        capture: &LogCapture,
        test_name: &str,
        passed: bool,
        context: &serde_json::Value,
    ) {
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": test_name,
            "module": "fcp-conformance::reqcheck",
            "phase": "execute",
            "correlation_id": Uuid::new_v4().to_string(),
            "result": if passed { "pass" } else { "fail" },
            "duration_ms": 0,
            "assertions": {
                "passed": i32::from(passed),
                "failed": i32::from(!passed)
            },
            "context": context
        });
        capture.push_value(&entry).expect("log entry serialization");
    }

    #[test]
    fn parse_table_with_varying_whitespace() {
        let capture = LogCapture::new();

        // Table with extra whitespace around cell values
        let content = r"
## §1: Whitespace Test

|   Aspect   |   Details   |
|----------|---------|
|  **Owners**  |   `bd-ws1`  |
|  **Tests**   |   `bd-ws2`  |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        let passed = result.is_ok()
            && parser.entries().len() == 1
            && parser.entries()[0].owners == vec!["bd-ws1"]
            && parser.entries()[0].tests == vec!["bd-ws2"];

        emit_test_result(
            &capture,
            "parse_table_varying_whitespace",
            passed,
            &json!({
                "entries_count": parser.entries().len(),
                "owners": parser.entries().first().map(|e| &e.owners),
                "tests": parser.entries().first().map(|e| &e.tests),
            }),
        );

        capture.assert_valid();
        assert!(passed, "Failed to parse table with varying whitespace");
    }

    #[test]
    fn parse_table_with_tabs_and_spaces() {
        let capture = LogCapture::new();

        // Table with mixed tabs and spaces
        let content = "
## §2: Mixed Tabs

| Aspect\t| Details |
|--------|---------|
| **Owners**\t| `bd-tab1` |
| **Tests** |\t`bd-tab2` |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        let passed = result.is_ok()
            && parser.entries().len() == 1
            && parser.entries()[0].owners.contains(&"bd-tab1".to_string())
            && parser.entries()[0].tests.contains(&"bd-tab2".to_string());

        emit_test_result(
            &capture,
            "parse_table_tabs_and_spaces",
            passed,
            &json!({
                "entries_count": parser.entries().len(),
                "parse_ok": result.is_ok(),
            }),
        );

        capture.assert_valid();
        assert!(passed, "Failed to parse table with mixed tabs and spaces");
    }

    #[test]
    fn parse_empty_table_rows() {
        let capture = LogCapture::new();

        // Table with empty rows (should be handled gracefully)
        let content = r"
## §3: Empty Rows

| Aspect | Details |
|--------|---------|
| **Owners** | |
| **Tests** | |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        // Should parse without error, even if no beads are extracted
        let passed = result.is_ok();
        let entries = parser.entries();
        let first_entry = entries.first();
        let owners_empty = first_entry.is_none_or(|e| e.owners.is_empty());
        let tests_empty = first_entry.is_none_or(|e| e.tests.is_empty());

        emit_test_result(
            &capture,
            "parse_empty_table_rows",
            passed && owners_empty && tests_empty,
            &json!({
                "parse_ok": result.is_ok(),
                "owners_empty": owners_empty,
                "tests_empty": tests_empty,
            }),
        );

        capture.assert_valid();
        assert!(
            result.is_ok(),
            "Should parse tables with empty cells gracefully"
        );
    }

    #[test]
    fn parse_malformed_row_missing_pipes() {
        let capture = LogCapture::new();

        // Row missing closing pipe - should still parse what it can
        let content = r"
## §4: Malformed

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-mal1`
| **Tests** | `bd-mal2` |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        // Parser should not crash; it may or may not extract all IDs
        let passed = result.is_ok();

        emit_test_result(
            &capture,
            "parse_malformed_row_missing_pipes",
            passed,
            &json!({
                "parse_ok": result.is_ok(),
                "entries_count": parser.entries().len(),
            }),
        );

        capture.assert_valid();
        assert!(result.is_ok(), "Should handle malformed rows gracefully");
    }

    #[test]
    fn parse_multiple_beads_in_single_cell() {
        let capture = LogCapture::new();

        // Multiple bead IDs in a single cell
        let content = r"
## §5: Multiple Beads

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-multi1`, `bd-multi2`, `flywheel_connectors-abc1` |
| **Tests** | `bd-test1` (unit), `bd-test2` (integration) |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        let passed = result.is_ok();
        let entry = parser.entries().first();
        let owners_count = entry.map_or(0, |e| e.owners.len());
        let tests_count = entry.map_or(0, |e| e.tests.len());

        emit_test_result(
            &capture,
            "parse_multiple_beads_single_cell",
            passed && owners_count == 3 && tests_count == 2,
            &json!({
                "parse_ok": result.is_ok(),
                "owners_count": owners_count,
                "tests_count": tests_count,
                "expected_owners": 3,
                "expected_tests": 2,
            }),
        );

        capture.assert_valid();
        assert!(result.is_ok());
        assert_eq!(owners_count, 3, "Should extract 3 owner bead IDs");
        assert_eq!(tests_count, 2, "Should extract 2 test bead IDs");
    }

    #[test]
    fn detect_invalid_bead_id_prefix() {
        let capture = LogCapture::new();

        // Bead IDs with unknown prefixes should be rejected
        let invalid_ids = ["unknown-abc123", "random-xyz", "test-9999", "foo-bar"];

        let mut all_rejected = true;
        for id in &invalid_ids {
            if is_bead_id(id) {
                all_rejected = false;
            }
        }

        emit_test_result(
            &capture,
            "detect_invalid_bead_id_prefix",
            all_rejected,
            &json!({
                "tested_ids": invalid_ids,
                "all_rejected": all_rejected,
            }),
        );

        capture.assert_valid();
        assert!(all_rejected, "Invalid prefixes should be rejected");
    }

    #[test]
    fn detect_valid_bead_id_patterns() {
        let capture = LogCapture::new();

        // Valid bead ID patterns
        let valid_ids = [
            "bd-a1b2",
            "bd-xyz",
            "bd-123",
            "bd-a.1",
            "bd-a.1.2",
            "flywheel_connectors-abc",
            "flywheel_connectors-1n78",
            "flywheel_connectors-1n78.21",
            "flywheel_connectors-1n78.21.3",
        ];

        let mut all_valid = true;
        let mut failed_ids = Vec::new();
        for id in &valid_ids {
            if !is_bead_id(id) {
                all_valid = false;
                failed_ids.push(*id);
            }
        }

        emit_test_result(
            &capture,
            "detect_valid_bead_id_patterns",
            all_valid,
            &json!({
                "tested_ids": valid_ids,
                "all_valid": all_valid,
                "failed_ids": failed_ids,
            }),
        );

        capture.assert_valid();
        assert!(
            all_valid,
            "All valid bead IDs should be recognized: {failed_ids:?}"
        );
    }

    #[test]
    fn validate_warns_on_missing_owners() {
        let capture = LogCapture::new();

        let content = r"
## §6: No Owners

| Aspect | Details |
|--------|---------|
| **Owners** | n/a |
| **Tests** | `bd-noown` |

---
";
        let mut parser = RequirementsIndexParser::new();
        parser.parse_reader(content.as_bytes()).unwrap();

        let mut known = HashSet::new();
        known.insert("bd-noown".to_string());

        let report = parser.validate(&known);

        let has_warning = report
            .warnings
            .iter()
            .any(|w| w.warning_type == "missing_owners");

        emit_test_result(
            &capture,
            "validate_warns_missing_owners",
            has_warning,
            &json!({
                "warnings_count": report.warnings.len(),
                "has_missing_owners_warning": has_warning,
            }),
        );

        capture.assert_valid();
        assert!(has_warning, "Should warn when no owners are specified");
    }

    #[test]
    fn validate_warns_on_duplicate_sections() {
        let capture = LogCapture::new();

        let content = r"
## §7: Dup Section

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-dup1` |

---

## §7: Dup Section

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-dup2` |

---
";
        let mut parser = RequirementsIndexParser::new();
        parser.parse_reader(content.as_bytes()).unwrap();

        let mut known = HashSet::new();
        known.insert("bd-dup1".to_string());
        known.insert("bd-dup2".to_string());

        let report = parser.validate(&known);

        let has_dup_warning = report
            .warnings
            .iter()
            .any(|w| w.warning_type == "duplicate_section");

        emit_test_result(
            &capture,
            "validate_warns_duplicate_sections",
            has_dup_warning,
            &json!({
                "entries_count": parser.entries().len(),
                "warnings_count": report.warnings.len(),
                "has_duplicate_warning": has_dup_warning,
            }),
        );

        capture.assert_valid();
        assert!(has_dup_warning, "Should warn on duplicate section names");
    }

    #[test]
    fn parse_table_with_unicode_content() {
        let capture = LogCapture::new();

        // Table with unicode characters in notes
        let content = r"
## §8: Unicode

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-uni1` |
| **Tests** | `bd-uni2` |
| **Notes** | Contains émojis 🎉 and ümlauts |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        let passed = result.is_ok();
        let entry = parser.entries().first();
        let has_notes = entry.is_some_and(|e| e.notes.is_some());

        emit_test_result(
            &capture,
            "parse_table_unicode_content",
            passed && has_notes,
            &json!({
                "parse_ok": result.is_ok(),
                "has_notes": has_notes,
            }),
        );

        capture.assert_valid();
        assert!(result.is_ok(), "Should parse unicode content");
        assert!(has_notes, "Should preserve notes with unicode");
    }

    #[test]
    fn parse_consecutive_tables_without_separator() {
        let capture = LogCapture::new();

        // Two tables without --- separator
        let content = r"
## §9: First

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-first` |

## §10: Second

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-second` |

---
";
        let mut parser = RequirementsIndexParser::new();
        let result = parser.parse_reader(content.as_bytes());

        let entries_count = parser.entries().len();
        let passed = result.is_ok() && entries_count == 2;

        emit_test_result(
            &capture,
            "parse_consecutive_tables",
            passed,
            &json!({
                "parse_ok": result.is_ok(),
                "entries_count": entries_count,
                "expected_count": 2,
            }),
        );

        capture.assert_valid();
        assert!(result.is_ok());
        assert_eq!(entries_count, 2, "Should parse both consecutive tables");
    }

    #[test]
    fn validation_report_summary_accuracy() {
        let capture = LogCapture::new();

        let content = r"
## §11: Summary Test

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-sum1`, `bd-sum2` |
| **Tests** | `bd-sum3` |

---

## §12: More Beads

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-sum4` |
| **Tests** | `bd-sum5`, `bd-sum1` |

---
";
        let mut parser = RequirementsIndexParser::new();
        parser.parse_reader(content.as_bytes()).unwrap();

        // Only some beads are known
        let mut known = HashSet::new();
        known.insert("bd-sum1".to_string());
        known.insert("bd-sum3".to_string());

        let report = parser.validate(&known);

        let total_entries_correct = report.total_entries == 2;
        // Unique beads: bd-sum1, bd-sum2, bd-sum3, bd-sum4, bd-sum5 = 5
        let unique_beads_correct = report.unique_beads == 5;
        // Missing: bd-sum2, bd-sum4, bd-sum5 = 3
        let missing_count_correct = report.missing_beads.len() == 3;
        // Errors for each missing bead reference (2 in first entry, 2 in second)
        let errors_present = !report.errors.is_empty();

        let passed = total_entries_correct
            && unique_beads_correct
            && missing_count_correct
            && errors_present;

        emit_test_result(
            &capture,
            "validation_report_summary",
            passed,
            &json!({
                "total_entries": report.total_entries,
                "unique_beads": report.unique_beads,
                "missing_beads_count": report.missing_beads.len(),
                "errors_count": report.errors.len(),
                "warnings_count": report.warnings.len(),
                "is_valid": report.is_valid(),
            }),
        );

        capture.assert_valid();
        assert!(total_entries_correct, "total_entries should be 2");
        assert!(unique_beads_correct, "unique_beads should be 5");
        assert!(missing_count_correct, "missing_beads should be 3");
    }

    #[test]
    fn extract_bead_ids_with_nested_backticks() {
        let capture = LogCapture::new();

        // Edge case: nested or adjacent backticks
        let text = "``bd-nested`` and `bd-normal` and ``` triple ```";
        let ids = extract_bead_ids(text);

        // Should only extract valid single-backtick spans
        let contains_normal = ids.contains(&"bd-normal".to_string());
        // Double/triple backticks may or may not extract - just verify no panic
        let passed = contains_normal;

        emit_test_result(
            &capture,
            "extract_bead_ids_nested_backticks",
            passed,
            &json!({
                "input": text,
                "extracted_ids": ids,
                "contains_normal": contains_normal,
            }),
        );

        capture.assert_valid();
        assert!(contains_normal, "Should extract `bd-normal`");
    }

    #[test]
    fn parse_large_table_performance() {
        let capture = LogCapture::new();

        // Generate a table with many entries
        let mut content = String::new();
        for i in 0..50 {
            let _ = write!(
                content,
                r"
## §{i}: Section {i}

| Aspect | Details |
|--------|---------|
| **Owners** | `bd-perf{i}` |
| **Tests** | `bd-test{i}` |

---
"
            );
        }

        let mut parser = RequirementsIndexParser::new();
        let start = std::time::Instant::now();
        let result = parser.parse_reader(content.as_bytes());
        let duration = start.elapsed();

        let passed = result.is_ok() && parser.entries().len() == 50;

        emit_test_result(
            &capture,
            "parse_large_table_performance",
            passed,
            &json!({
                "parse_ok": result.is_ok(),
                "entries_count": parser.entries().len(),
                "duration_ms": duration.as_millis(),
                "expected_entries": 50,
            }),
        );

        capture.assert_valid();
        assert!(result.is_ok());
        assert_eq!(parser.entries().len(), 50, "Should parse all 50 entries");
        // Should complete quickly (under 100ms for 50 entries)
        assert!(duration.as_millis() < 100, "Parsing should be fast");
    }
}
