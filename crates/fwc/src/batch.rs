//! Map-over-inputs: apply one operation to N inputs in parallel.
//!
//! Parses batch input sources (inline JSON array, JSONL file, template + items),
//! plans parallel execution with concurrency control, and produces structured
//! per-item results in NDJSON format.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Error handling mode ─────────────────────────────────────────────────

/// What to do when an individual item fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Stop the entire batch on first failure.
    Abort,
    /// Skip the failed item and continue with remaining.
    Continue,
}

impl OnError {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "abort" => Some(Self::Abort),
            "continue" => Some(Self::Continue),
            _ => None,
        }
    }
}

impl std::fmt::Display for OnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abort => f.write_str("abort"),
            Self::Continue => f.write_str("continue"),
        }
    }
}

// ── Input sources ───────────────────────────────────────────────────────

/// A batch of inputs to apply to a single operation.
#[derive(Debug, Clone)]
pub struct BatchInputs {
    pub items: Vec<Value>,
}

impl BatchInputs {
    /// Parse from an inline JSON array string.
    pub fn from_json_array(json: &str) -> Result<Self, String> {
        let value: Value =
            serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
        let Some(arr) = value.as_array() else {
            return Err("expected a JSON array of inputs".to_owned());
        };
        if arr.is_empty() {
            return Err("input array is empty".to_owned());
        }
        Ok(Self {
            items: arr.clone(),
        })
    }

    /// Parse from a JSONL string (one JSON object per line).
    pub fn from_jsonl(content: &str) -> Result<Self, String> {
        let mut items = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line)
                .map_err(|e| format!("invalid JSON on line {}: {e}", i + 1))?;
            items.push(value);
        }
        if items.is_empty() {
            return Err("JSONL input is empty".to_owned());
        }
        Ok(Self { items })
    }

    /// Generate from a template and comma-separated items.
    ///
    /// Template uses `{{item}}` as placeholder.
    pub fn from_template(template: &str, items_csv: &str) -> Result<Self, String> {
        if !template.contains("{{item}}") {
            return Err("template must contain {{item}} placeholder".to_owned());
        }
        let mut items = Vec::new();
        for item in items_csv.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let rendered = template.replace("{{item}}", item);
            let value: Value = serde_json::from_str(&rendered)
                .map_err(|e| format!("template produced invalid JSON for item '{item}': {e}"))?;
            items.push(value);
        }
        if items.is_empty() {
            return Err("no items provided".to_owned());
        }
        Ok(Self { items })
    }

    /// Number of items in the batch.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ── Batch result ────────────────────────────────────────────────────────

/// Status of a single item in the batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Success,
    Error,
    Skipped,
}

/// Result of executing a single item in the batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResult {
    /// Zero-based index in the input array.
    pub index: usize,
    /// Execution status.
    pub status: ItemStatus,
    /// Result value (if success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error details (if error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Summary of a batch execution.
#[derive(Debug, Clone, Serialize)]
pub struct BatchSummary {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl BatchSummary {
    pub fn from_results(results: &[ItemResult]) -> Self {
        let mut succeeded = 0;
        let mut failed = 0;
        let mut skipped = 0;
        for r in results {
            match r.status {
                ItemStatus::Success => succeeded += 1,
                ItemStatus::Error => failed += 1,
                ItemStatus::Skipped => skipped += 1,
            }
        }
        Self {
            total: results.len(),
            succeeded,
            failed,
            skipped,
        }
    }
}

// ── Batch plan ──────────────────────────────────────────────────────────

/// Plan for a batch execution (for dry-run / preview).
#[derive(Debug, Clone, Serialize)]
pub struct BatchPlan {
    /// Operation to apply.
    pub operation: String,
    /// Number of inputs to process.
    pub input_count: usize,
    /// Maximum concurrency.
    pub concurrency: usize,
    /// Error handling mode.
    pub on_error: OnError,
    /// First few input previews.
    pub preview_inputs: Vec<Value>,
}

/// Render batch results as NDJSON (one line per result).
pub fn results_to_ndjson(results: &[ItemResult]) -> String {
    let mut output = String::new();
    for result in results {
        if let Ok(line) = serde_json::to_string(result) {
            output.push_str(&line);
            output.push('\n');
        }
    }
    output
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── from_json_array ─────────────────────────────────────────────

    #[test]
    fn parse_json_array_simple() {
        let inputs = BatchInputs::from_json_array(
            r#"[{"owner":"o","repo":"r","number":1},{"owner":"o","repo":"r","number":2}]"#,
        )
        .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["number"], 1);
    }

    #[test]
    fn parse_json_array_single() {
        let inputs = BatchInputs::from_json_array(r#"[{"key": "val"}]"#).unwrap();
        assert_eq!(inputs.len(), 1);
    }

    #[test]
    fn parse_json_array_empty_error() {
        let err = BatchInputs::from_json_array("[]").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_json_array_not_array() {
        let err = BatchInputs::from_json_array(r#"{"key": "val"}"#).unwrap_err();
        assert!(err.contains("array"));
    }

    #[test]
    fn parse_json_array_invalid_json() {
        let err = BatchInputs::from_json_array("not json").unwrap_err();
        assert!(err.contains("invalid JSON"));
    }

    // ── from_jsonl ──────────────────────────────────────────────────

    #[test]
    fn parse_jsonl_multiple_lines() {
        let content = r#"{"a":1}
{"a":2}
{"a":3}"#;
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[1]["a"], 2);
    }

    #[test]
    fn parse_jsonl_with_blank_lines() {
        let content = r#"{"a":1}

{"a":2}
"#;
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn parse_jsonl_empty_error() {
        let err = BatchInputs::from_jsonl("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_jsonl_invalid_line() {
        let err = BatchInputs::from_jsonl("not json\n{\"a\":1}").unwrap_err();
        assert!(err.contains("line 1"));
    }

    // ── from_template ───────────────────────────────────────────────

    #[test]
    fn template_generates_items() {
        let inputs = BatchInputs::from_template(
            r#"{"owner":"octocat","repo":"hello-world","issue_number":{{item}}}"#,
            "1,2,3",
        )
        .unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[0]["issue_number"], 1);
        assert_eq!(inputs.items[2]["issue_number"], 3);
    }

    #[test]
    fn template_trims_whitespace() {
        let inputs = BatchInputs::from_template(
            r#"{"id":{{item}}}"#,
            " 1 , 2 , 3 ",
        )
        .unwrap();
        assert_eq!(inputs.len(), 3);
    }

    #[test]
    fn template_skips_empty_items() {
        let inputs = BatchInputs::from_template(
            r#"{"id":{{item}}}"#,
            "1,,2",
        )
        .unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn template_string_items() {
        let inputs = BatchInputs::from_template(
            r#"{"name":"{{item}}"}"#,
            "alice,bob,carol",
        )
        .unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[0]["name"], "alice");
    }

    #[test]
    fn template_missing_placeholder_error() {
        let err = BatchInputs::from_template(r#"{"id":1}"#, "1,2,3").unwrap_err();
        assert!(err.contains("{{item}}"));
    }

    #[test]
    fn template_no_items_error() {
        let err = BatchInputs::from_template(r#"{"id":{{item}}}"#, "").unwrap_err();
        assert!(err.contains("no items"));
    }

    #[test]
    fn template_invalid_json_error() {
        let err =
            BatchInputs::from_template(r#"{"id":{{item}}"#, "1").unwrap_err();
        assert!(err.contains("invalid JSON"));
    }

    // ── BatchInputs methods ─────────────────────────────────────────

    #[test]
    fn batch_len_and_is_empty() {
        let inputs = BatchInputs::from_json_array(r#"[1,2,3]"#).unwrap();
        assert_eq!(inputs.len(), 3);
        assert!(!inputs.is_empty());
    }

    // ── ItemResult serialization ────────────────────────────────────

    #[test]
    fn item_result_success_serializes() {
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!({"id": 42})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"success\""));
        assert!(json.contains("\"index\":0"));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn item_result_error_serializes() {
        let result = ItemResult {
            index: 1,
            status: ItemStatus::Error,
            result: None,
            error: Some(json!({"code": "FCP_ERR_NOT_FOUND"})),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("FCP_ERR_NOT_FOUND"));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn item_result_skipped_serializes() {
        let result = ItemResult {
            index: 2,
            status: ItemStatus::Skipped,
            result: None,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"skipped\""));
    }

    #[test]
    fn item_result_roundtrip() {
        let result = ItemResult {
            index: 5,
            status: ItemStatus::Success,
            result: Some(json!({"data": "value"})),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ItemResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, 5);
        assert_eq!(back.status, ItemStatus::Success);
    }

    // ── BatchSummary ────────────────────────────────────────────────

    #[test]
    fn batch_summary_all_success() {
        let results = vec![
            ItemResult {
                index: 0,
                status: ItemStatus::Success,
                result: Some(json!({})),
                error: None,
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Success,
                result: Some(json!({})),
                error: None,
            },
        ];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.skipped, 0);
    }

    #[test]
    fn batch_summary_mixed() {
        let results = vec![
            ItemResult {
                index: 0,
                status: ItemStatus::Success,
                result: Some(json!({})),
                error: None,
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!({})),
            },
            ItemResult {
                index: 2,
                status: ItemStatus::Skipped,
                result: None,
                error: None,
            },
        ];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.skipped, 1);
    }

    #[test]
    fn batch_summary_empty() {
        let summary = BatchSummary::from_results(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.succeeded, 0);
    }

    // ── results_to_ndjson ───────────────────────────────────────────

    #[test]
    fn ndjson_output_format() {
        let results = vec![
            ItemResult {
                index: 0,
                status: ItemStatus::Success,
                result: Some(json!({"id": 1})),
                error: None,
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!({"msg": "fail"})),
            },
        ];
        let ndjson = results_to_ndjson(&results);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["index"], 0);
        assert_eq!(first["status"], "success");
    }

    #[test]
    fn ndjson_empty() {
        let ndjson = results_to_ndjson(&[]);
        assert!(ndjson.is_empty());
    }

    // ── OnError ─────────────────────────────────────────────────────

    #[test]
    fn on_error_parse() {
        assert_eq!(OnError::parse("abort"), Some(OnError::Abort));
        assert_eq!(OnError::parse("continue"), Some(OnError::Continue));
        assert_eq!(OnError::parse("invalid"), None);
    }

    #[test]
    fn on_error_display() {
        assert_eq!(OnError::Abort.to_string(), "abort");
        assert_eq!(OnError::Continue.to_string(), "continue");
    }

    #[test]
    fn on_error_roundtrip() {
        for mode in [OnError::Abort, OnError::Continue] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: OnError = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    // ── BatchPlan ───────────────────────────────────────────────────

    #[test]
    fn batch_plan_serializes() {
        let plan = BatchPlan {
            operation: "github.get_issue".to_owned(),
            input_count: 5,
            concurrency: 3,
            on_error: OnError::Continue,
            preview_inputs: vec![json!({"number": 1}), json!({"number": 2})],
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["operation"], "github.get_issue");
        assert_eq!(json["input_count"], 5);
        assert_eq!(json["concurrency"], 3);
        assert_eq!(json["on_error"], "continue");
        assert_eq!(json["preview_inputs"].as_array().unwrap().len(), 2);
    }

    // ── ItemStatus equality ─────────────────────────────────────────

    #[test]
    fn item_status_equality() {
        assert_eq!(ItemStatus::Success, ItemStatus::Success);
        assert_ne!(ItemStatus::Success, ItemStatus::Error);
        assert_ne!(ItemStatus::Error, ItemStatus::Skipped);
    }

    // ── BatchSummary serialization ──────────────────────────────────

    #[test]
    fn batch_summary_serializes() {
        let summary = BatchSummary {
            total: 10,
            succeeded: 8,
            failed: 1,
            skipped: 1,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["total"], 10);
        assert_eq!(json["succeeded"], 8);
        assert_eq!(json["failed"], 1);
        assert_eq!(json["skipped"], 1);
    }
}
