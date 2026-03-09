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
        let value: Value = serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
        let Some(arr) = value.as_array() else {
            return Err("expected a JSON array of inputs".to_owned());
        };
        if arr.is_empty() {
            return Err("input array is empty".to_owned());
        }
        Ok(Self { items: arr.clone() })
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
        let inputs = BatchInputs::from_template(r#"{"id":{{item}}}"#, " 1 , 2 , 3 ").unwrap();
        assert_eq!(inputs.len(), 3);
    }

    #[test]
    fn template_skips_empty_items() {
        let inputs = BatchInputs::from_template(r#"{"id":{{item}}}"#, "1,,2").unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn template_string_items() {
        let inputs =
            BatchInputs::from_template(r#"{"name":"{{item}}"}"#, "alice,bob,carol").unwrap();
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
        let err = BatchInputs::from_template(r#"{"id":{{item}}"#, "1").unwrap_err();
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

    // ── Additional from_json_array tests ───────────────────────────

    #[test]
    fn parse_json_array_nested_objects() {
        let inputs = BatchInputs::from_json_array(
            r#"[{"spec":{"replicas":3}},{"spec":{"replicas":5}}]"#,
        )
        .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["spec"]["replicas"], 3);
        assert_eq!(inputs.items[1]["spec"]["replicas"], 5);
    }

    #[test]
    fn parse_json_array_mixed_types() {
        let inputs = BatchInputs::from_json_array(r#"[1, "two", true, null, {"k":"v"}]"#).unwrap();
        assert_eq!(inputs.len(), 5);
        assert_eq!(inputs.items[0], json!(1));
        assert_eq!(inputs.items[1], json!("two"));
        assert_eq!(inputs.items[2], json!(true));
        assert_eq!(inputs.items[3], json!(null));
        assert!(inputs.items[4].is_object());
    }

    #[test]
    fn parse_json_array_large_batch() {
        let arr: Vec<Value> = (0..100).map(|i| json!({"index": i})).collect();
        let json_str = serde_json::to_string(&arr).unwrap();
        let inputs = BatchInputs::from_json_array(&json_str).unwrap();
        assert_eq!(inputs.len(), 100);
        assert_eq!(inputs.items[99]["index"], 99);
    }

    #[test]
    fn parse_json_array_whitespace_tolerant() {
        let inputs = BatchInputs::from_json_array("  [ { \"a\" : 1 } ]  ").unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs.items[0]["a"], 1);
    }

    #[test]
    fn parse_json_array_scalar_not_object_error() {
        let err = BatchInputs::from_json_array("\"just a string\"").unwrap_err();
        assert!(err.contains("array"));
    }

    #[test]
    fn parse_json_array_number_not_array_error() {
        let err = BatchInputs::from_json_array("42").unwrap_err();
        assert!(err.contains("array"));
    }

    // ── Additional from_jsonl tests ────────────────────────────────

    #[test]
    fn parse_jsonl_single_line() {
        let inputs = BatchInputs::from_jsonl(r#"{"id":42}"#).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs.items[0]["id"], 42);
    }

    #[test]
    fn parse_jsonl_whitespace_lines_only_error() {
        let err = BatchInputs::from_jsonl("   \n  \n  ").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_jsonl_trims_whitespace_per_line() {
        let content = r#"  {"a":1}
    {"a":2}   "#;
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn parse_jsonl_error_on_second_line() {
        let err = BatchInputs::from_jsonl("{\"a\":1}\nnot json\n{\"a\":3}").unwrap_err();
        assert!(err.contains("line 2"));
    }

    #[test]
    fn parse_jsonl_arrays_and_scalars() {
        let content = "[1,2,3]\n\"hello\"\n42";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 3);
        assert!(inputs.items[0].is_array());
        assert!(inputs.items[1].is_string());
        assert!(inputs.items[2].is_number());
    }

    // ── Additional from_template tests ─────────────────────────────

    #[test]
    fn template_with_boolean_items() {
        let inputs =
            BatchInputs::from_template(r#"{"active":{{item}}}"#, "true,false").unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["active"], true);
        assert_eq!(inputs.items[1]["active"], false);
    }

    #[test]
    fn template_only_empty_items_error() {
        let err = BatchInputs::from_template(r#"{"id":{{item}}}"#, ",,").unwrap_err();
        assert!(err.contains("no items"));
    }

    #[test]
    fn template_large_batch() {
        let csv: String = (1..=50).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let inputs = BatchInputs::from_template(r#"{"num":{{item}}}"#, &csv).unwrap();
        assert_eq!(inputs.len(), 50);
        assert_eq!(inputs.items[49]["num"], 50);
    }

    #[test]
    fn template_item_with_special_chars() {
        let inputs =
            BatchInputs::from_template(r#"{"name":"{{item}}"}"#, "alice bob,carol-dean").unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["name"], "alice bob");
        assert_eq!(inputs.items[1]["name"], "carol-dean");
    }

    // ── Additional BatchSummary tests ──────────────────────────────

    #[test]
    fn batch_summary_all_failed() {
        let results = vec![
            ItemResult { index: 0, status: ItemStatus::Error, result: None, error: Some(json!("e1")) },
            ItemResult { index: 1, status: ItemStatus::Error, result: None, error: Some(json!("e2")) },
            ItemResult { index: 2, status: ItemStatus::Error, result: None, error: Some(json!("e3")) },
        ];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 3);
        assert_eq!(summary.skipped, 0);
    }

    #[test]
    fn batch_summary_all_skipped() {
        let results = vec![
            ItemResult { index: 0, status: ItemStatus::Skipped, result: None, error: None },
            ItemResult { index: 1, status: ItemStatus::Skipped, result: None, error: None },
        ];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.skipped, 2);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 0);
    }

    #[test]
    fn batch_summary_large_batch() {
        let mut results = Vec::new();
        for i in 0..100 {
            let status = match i % 3 {
                0 => ItemStatus::Success,
                1 => ItemStatus::Error,
                _ => ItemStatus::Skipped,
            };
            results.push(ItemResult { index: i, status, result: None, error: None });
        }
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 100);
        assert_eq!(summary.succeeded, 34);
        assert_eq!(summary.failed, 33);
        assert_eq!(summary.skipped, 33);
    }

    // ── Additional results_to_ndjson tests ─────────────────────────

    #[test]
    fn ndjson_single_result() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!({"created": true})),
            error: None,
        }];
        let ndjson = results_to_ndjson(&results);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 1);
        let parsed: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["status"], "success");
        assert_eq!(parsed["result"]["created"], true);
    }

    #[test]
    fn ndjson_each_line_is_valid_json() {
        let results = vec![
            ItemResult { index: 0, status: ItemStatus::Success, result: Some(json!(1)), error: None },
            ItemResult { index: 1, status: ItemStatus::Error, result: None, error: Some(json!("err")) },
            ItemResult { index: 2, status: ItemStatus::Skipped, result: None, error: None },
        ];
        let ndjson = results_to_ndjson(&results);
        for line in ndjson.lines() {
            if !line.is_empty() {
                let parsed: Value = serde_json::from_str(line).unwrap();
                assert!(parsed.is_object());
            }
        }
    }

    #[test]
    fn ndjson_preserves_order() {
        let results: Vec<ItemResult> = (0..5)
            .map(|i| ItemResult {
                index: i,
                status: ItemStatus::Success,
                result: Some(json!({"idx": i})),
                error: None,
            })
            .collect();
        let ndjson = results_to_ndjson(&results);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 5);
        for (i, line) in lines.iter().enumerate() {
            let parsed: Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["index"], i);
        }
    }

    // ── OnError additional tests ───────────────────────────────────

    #[test]
    fn on_error_serde_abort() {
        let json = serde_json::to_string(&OnError::Abort).unwrap();
        assert_eq!(json, "\"abort\"");
        let back: OnError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, OnError::Abort);
    }

    #[test]
    fn on_error_serde_continue() {
        let json = serde_json::to_string(&OnError::Continue).unwrap();
        assert_eq!(json, "\"continue\"");
        let back: OnError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, OnError::Continue);
    }

    #[test]
    fn on_error_parse_case_sensitive() {
        assert_eq!(OnError::parse("Abort"), None);
        assert_eq!(OnError::parse("CONTINUE"), None);
        assert_eq!(OnError::parse(""), None);
    }

    #[test]
    fn on_error_debug_impl() {
        let debug = format!("{:?}", OnError::Abort);
        assert!(debug.contains("Abort"));
        let debug = format!("{:?}", OnError::Continue);
        assert!(debug.contains("Continue"));
    }

    #[test]
    fn on_error_clone_and_copy() {
        let original = OnError::Abort;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    // ── BatchPlan additional tests ─────────────────────────────────

    #[test]
    fn batch_plan_serializes_abort_mode() {
        let plan = BatchPlan {
            operation: "slack.send_message".to_owned(),
            input_count: 10,
            concurrency: 1,
            on_error: OnError::Abort,
            preview_inputs: vec![json!({"channel": "general"})],
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["on_error"], "abort");
        assert_eq!(json["input_count"], 10);
        assert_eq!(json["concurrency"], 1);
    }

    #[test]
    fn batch_plan_empty_preview() {
        let plan = BatchPlan {
            operation: "test.op".to_owned(),
            input_count: 0,
            concurrency: 1,
            on_error: OnError::Continue,
            preview_inputs: vec![],
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json["preview_inputs"].as_array().unwrap().is_empty());
    }

    // ── ItemResult additional tests ────────────────────────────────

    #[test]
    fn item_result_with_complex_result_value() {
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!({"nested": {"deep": [1, 2, 3]}, "tags": ["a", "b"]})),
            error: None,
        };
        let json_str = serde_json::to_string(&result).unwrap();
        let back: ItemResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.result.unwrap()["nested"]["deep"][2], 3);
    }

    #[test]
    fn item_result_with_both_result_and_error() {
        // Technically allowed by the struct; test serialization handles it
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Error,
            result: Some(json!({"partial": true})),
            error: Some(json!({"code": "PARTIAL_FAILURE"})),
        };
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("partial"));
        assert!(json_str.contains("PARTIAL_FAILURE"));
    }

    #[test]
    fn item_result_large_index() {
        let result = ItemResult {
            index: 999_999,
            status: ItemStatus::Success,
            result: Some(json!({})),
            error: None,
        };
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("999999"));
        let back: ItemResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.index, 999_999);
    }

    // ── ItemStatus additional tests ────────────────────────────────

    #[test]
    fn item_status_serde_roundtrip_all_variants() {
        for status in [ItemStatus::Success, ItemStatus::Error, ItemStatus::Skipped] {
            let json = serde_json::to_string(&status).unwrap();
            let back: ItemStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn item_status_clone() {
        let original = ItemStatus::Error;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn item_status_debug_format() {
        let debug = format!("{:?}", ItemStatus::Skipped);
        assert!(debug.contains("Skipped"));
    }

    // ── BatchInputs clone and debug ────────────────────────────────

    #[test]
    fn batch_inputs_clone() {
        let inputs = BatchInputs::from_json_array(r#"[1,2,3]"#).unwrap();
        let cloned = inputs.clone();
        assert_eq!(inputs.len(), cloned.len());
        assert_eq!(inputs.items, cloned.items);
    }

    #[test]
    fn batch_inputs_debug() {
        let inputs = BatchInputs::from_json_array(r#"[{"a":1}]"#).unwrap();
        let debug = format!("{inputs:?}");
        assert!(debug.contains("BatchInputs"));
    }
}
