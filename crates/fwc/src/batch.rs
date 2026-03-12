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
        let inputs =
            BatchInputs::from_json_array(r#"[{"spec":{"replicas":3}},{"spec":{"replicas":5}}]"#)
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
        let inputs = BatchInputs::from_template(r#"{"active":{{item}}}"#, "true,false").unwrap();
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
        let csv: String = (1..=50)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
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
            ItemResult {
                index: 0,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!("e1")),
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!("e2")),
            },
            ItemResult {
                index: 2,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!("e3")),
            },
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
            ItemResult {
                index: 0,
                status: ItemStatus::Skipped,
                result: None,
                error: None,
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Skipped,
                result: None,
                error: None,
            },
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
            results.push(ItemResult {
                index: i,
                status,
                result: None,
                error: None,
            });
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
            ItemResult {
                index: 0,
                status: ItemStatus::Success,
                result: Some(json!(1)),
                error: None,
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!("err")),
            },
            ItemResult {
                index: 2,
                status: ItemStatus::Skipped,
                result: None,
                error: None,
            },
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

    // ── from_json_array extended edge cases ─────────────────────────

    #[test]
    fn parse_json_array_unicode_values() {
        let inputs =
            BatchInputs::from_json_array(r#"[{"name":"日本語"},{"name":"émojis 🎉"}]"#).unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["name"], "日本語");
    }

    #[test]
    fn parse_json_array_deeply_nested() {
        let inputs =
            BatchInputs::from_json_array(r#"[{"a":{"b":{"c":{"d":{"e":42}}}}}]"#).unwrap();
        assert_eq!(inputs.items[0]["a"]["b"]["c"]["d"]["e"], 42);
    }

    #[test]
    fn parse_json_array_null_values() {
        let inputs = BatchInputs::from_json_array(r#"[null, null]"#).unwrap();
        assert_eq!(inputs.len(), 2);
        assert!(inputs.items[0].is_null());
        assert!(inputs.items[1].is_null());
    }

    #[test]
    fn parse_json_array_boolean_not_array() {
        let err = BatchInputs::from_json_array("true").unwrap_err();
        assert!(err.contains("array"));
    }

    #[test]
    fn parse_json_array_null_not_array() {
        let err = BatchInputs::from_json_array("null").unwrap_err();
        assert!(err.contains("array"));
    }

    #[test]
    fn parse_json_array_trailing_comma_error() {
        let err = BatchInputs::from_json_array("[1, 2,]").unwrap_err();
        assert!(err.contains("invalid JSON"));
    }

    #[test]
    fn parse_json_array_array_of_arrays() {
        let inputs = BatchInputs::from_json_array("[[1,2],[3,4],[5,6]]").unwrap();
        assert_eq!(inputs.len(), 3);
        assert!(inputs.items[0].is_array());
        assert_eq!(inputs.items[2][1], 6);
    }

    #[test]
    fn parse_json_array_empty_objects() {
        let inputs = BatchInputs::from_json_array("[{},{},{}]").unwrap();
        assert_eq!(inputs.len(), 3);
        assert!(inputs.items[0].as_object().unwrap().is_empty());
    }

    #[test]
    fn parse_json_array_float_values() {
        let inputs = BatchInputs::from_json_array("[3.14, 2.718, 1.0]").unwrap();
        assert_eq!(inputs.len(), 3);
        let first = inputs.items[0].as_f64().unwrap();
        assert!((first - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_json_array_empty_string_elements() {
        let inputs = BatchInputs::from_json_array(r#"["", "a", ""]"#).unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[0], "");
        assert_eq!(inputs.items[1], "a");
    }

    #[test]
    fn parse_json_array_negative_numbers() {
        let inputs = BatchInputs::from_json_array("[-1, -99, 0]").unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[0], -1);
        assert_eq!(inputs.items[1], -99);
    }

    // ── from_jsonl extended edge cases ──────────────────────────────

    #[test]
    fn parse_jsonl_trailing_newline() {
        let content = "{\"a\":1}\n{\"a\":2}\n";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn parse_jsonl_multiple_blank_lines_between() {
        let content = "{\"a\":1}\n\n\n\n{\"a\":2}";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn parse_jsonl_large_batch() {
        let lines: String = (0..200)
            .map(|i| format!("{{\"id\":{i}}}"))
            .collect::<Vec<_>>()
            .join("\n");
        let inputs = BatchInputs::from_jsonl(&lines).unwrap();
        assert_eq!(inputs.len(), 200);
        assert_eq!(inputs.items[199]["id"], 199);
    }

    #[test]
    fn parse_jsonl_error_line_number_with_blanks() {
        // Blank lines are skipped, but line number still reflects original position
        let err = BatchInputs::from_jsonl("{\"a\":1}\n\nbad json\n{\"a\":3}").unwrap_err();
        assert!(err.contains("line 3"));
    }

    #[test]
    fn parse_jsonl_unicode_content() {
        let content = "{\"text\":\"こんにちは\"}\n{\"text\":\"世界\"}";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["text"], "こんにちは");
    }

    #[test]
    fn parse_jsonl_nested_objects() {
        let content = "{\"outer\":{\"inner\":42}}\n{\"outer\":{\"inner\":99}}";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.items[0]["outer"]["inner"], 42);
        assert_eq!(inputs.items[1]["outer"]["inner"], 99);
    }

    #[test]
    fn parse_jsonl_boolean_values() {
        let content = "true\nfalse\ntrue";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[0], true);
        assert_eq!(inputs.items[1], false);
    }

    #[test]
    fn parse_jsonl_null_values() {
        let content = "null\nnull";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        assert_eq!(inputs.len(), 2);
        assert!(inputs.items[0].is_null());
    }

    #[test]
    fn parse_jsonl_error_on_last_line() {
        let err = BatchInputs::from_jsonl("{\"a\":1}\n{\"a\":2}\nnot json").unwrap_err();
        assert!(err.contains("line 3"));
    }

    // ── from_template extended edge cases ───────────────────────────

    #[test]
    fn template_single_item() {
        let inputs = BatchInputs::from_template(r#"{"id":{{item}}}"#, "42").unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs.items[0]["id"], 42);
    }

    #[test]
    fn template_multiple_placeholder_occurrences() {
        let inputs = BatchInputs::from_template(
            r#"{"key":"{{item}}","label":"{{item}}_label"}"#,
            "alpha,beta",
        )
        .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["key"], "alpha");
        assert_eq!(inputs.items[0]["label"], "alpha_label");
        assert_eq!(inputs.items[1]["key"], "beta");
    }

    #[test]
    fn template_negative_numbers() {
        let inputs =
            BatchInputs::from_template(r#"{"offset":{{item}}}"#, "-10,-20,-30").unwrap();
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs.items[0]["offset"], -10);
        assert_eq!(inputs.items[2]["offset"], -30);
    }

    #[test]
    fn template_float_numbers() {
        let inputs =
            BatchInputs::from_template(r#"{"value":{{item}}}"#, "1.5,2.7,3.14").unwrap();
        assert_eq!(inputs.len(), 3);
        let v = inputs.items[2]["value"].as_f64().unwrap();
        assert!((v - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn template_null_items() {
        let inputs = BatchInputs::from_template(r#"{"data":{{item}}}"#, "null,null").unwrap();
        assert_eq!(inputs.len(), 2);
        assert!(inputs.items[0]["data"].is_null());
    }

    #[test]
    fn template_json_object_items_no_inner_commas() {
        // Items without inner commas work fine with CSV splitting
        let inputs = BatchInputs::from_template(
            r#"{"payload":{{item}}}"#,
            r#"{"x":1},{"x":2}"#,
        )
        .unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["payload"]["x"], 1);
        assert_eq!(inputs.items[1]["payload"]["x"], 2);
    }

    #[test]
    fn template_only_whitespace_items() {
        let err = BatchInputs::from_template(r#"{"id":{{item}}}"#, " , , ").unwrap_err();
        assert!(err.contains("no items"));
    }

    #[test]
    fn template_items_with_leading_trailing_commas() {
        let inputs = BatchInputs::from_template(r#"{"id":{{item}}}"#, ",1,2,").unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs.items[0]["id"], 1);
        assert_eq!(inputs.items[1]["id"], 2);
    }

    // ── BatchInputs direct construction and methods ─────────────────

    #[test]
    fn batch_inputs_direct_construction() {
        let inputs = BatchInputs {
            items: vec![json!(1), json!(2), json!(3)],
        };
        assert_eq!(inputs.len(), 3);
        assert!(!inputs.is_empty());
    }

    #[test]
    fn batch_inputs_empty_direct() {
        let inputs = BatchInputs { items: vec![] };
        assert_eq!(inputs.len(), 0);
        assert!(inputs.is_empty());
    }

    #[test]
    fn batch_inputs_items_are_accessible() {
        let inputs = BatchInputs::from_json_array(r#"[{"x":10},{"x":20}]"#).unwrap();
        let first = &inputs.items[0];
        assert_eq!(first["x"], 10);
        let second = &inputs.items[1];
        assert_eq!(second["x"], 20);
    }

    // ── ItemResult deserialization from raw JSON ────────────────────

    #[test]
    fn item_result_deserialize_success() {
        let json = r#"{"index":3,"status":"success","result":{"id":99}}"#;
        let result: ItemResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.index, 3);
        assert_eq!(result.status, ItemStatus::Success);
        assert_eq!(result.result.unwrap()["id"], 99);
        assert!(result.error.is_none());
    }

    #[test]
    fn item_result_deserialize_error() {
        let json = r#"{"index":7,"status":"error","error":{"msg":"timeout"}}"#;
        let result: ItemResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.index, 7);
        assert_eq!(result.status, ItemStatus::Error);
        assert!(result.result.is_none());
        assert_eq!(result.error.unwrap()["msg"], "timeout");
    }

    #[test]
    fn item_result_deserialize_skipped() {
        let json = r#"{"index":0,"status":"skipped"}"#;
        let result: ItemResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.index, 0);
        assert_eq!(result.status, ItemStatus::Skipped);
        assert!(result.result.is_none());
        assert!(result.error.is_none());
    }

    #[test]
    fn item_result_deserialize_invalid_status() {
        let json = r#"{"index":0,"status":"unknown"}"#;
        let err = serde_json::from_str::<ItemResult>(json);
        assert!(err.is_err());
    }

    #[test]
    fn item_result_clone() {
        let result = ItemResult {
            index: 5,
            status: ItemStatus::Success,
            result: Some(json!({"key": "value"})),
            error: None,
        };
        let cloned = result.clone();
        assert_eq!(cloned.index, 5);
        assert_eq!(cloned.status, ItemStatus::Success);
        assert_eq!(cloned.result.unwrap()["key"], "value");
    }

    #[test]
    fn item_result_debug() {
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Error,
            result: None,
            error: Some(json!("oops")),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("ItemResult"));
        assert!(debug.contains("Error"));
    }

    #[test]
    fn item_result_null_result_value() {
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!(null)),
            error: None,
        };
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("\"result\":null"));
        // serde deserializes JSON null into Option<Value> as None (not Some(Null))
        let back: ItemResult = serde_json::from_str(&json_str).unwrap();
        assert!(back.result.is_none());
    }

    #[test]
    fn item_result_string_error_value() {
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Error,
            result: None,
            error: Some(json!("simple error message")),
        };
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("simple error message"));
    }

    #[test]
    fn item_result_zero_index() {
        let result = ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!(true)),
            error: None,
        };
        let json_str = serde_json::to_string(&result).unwrap();
        let back: ItemResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.index, 0);
    }

    // ── ItemStatus serialization values ─────────────────────────────

    #[test]
    fn item_status_serializes_to_snake_case() {
        assert_eq!(serde_json::to_string(&ItemStatus::Success).unwrap(), "\"success\"");
        assert_eq!(serde_json::to_string(&ItemStatus::Error).unwrap(), "\"error\"");
        assert_eq!(serde_json::to_string(&ItemStatus::Skipped).unwrap(), "\"skipped\"");
    }

    #[test]
    fn item_status_deserialize_invalid() {
        let err = serde_json::from_str::<ItemStatus>("\"pending\"");
        assert!(err.is_err());
    }

    #[test]
    fn item_status_deserialize_case_sensitive() {
        let err = serde_json::from_str::<ItemStatus>("\"Success\"");
        assert!(err.is_err());
    }

    // ── OnError extended tests ──────────────────────────────────────

    #[test]
    fn on_error_parse_empty_string() {
        assert_eq!(OnError::parse(""), None);
    }

    #[test]
    fn on_error_parse_whitespace() {
        assert_eq!(OnError::parse(" abort"), None);
        assert_eq!(OnError::parse("continue "), None);
    }

    #[test]
    fn on_error_display_roundtrip() {
        for mode in [OnError::Abort, OnError::Continue] {
            let displayed = mode.to_string();
            let parsed = OnError::parse(&displayed).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn on_error_deserialize_invalid() {
        let err = serde_json::from_str::<OnError>("\"stop\"");
        assert!(err.is_err());
    }

    #[test]
    fn on_error_deserialize_from_number_fails() {
        let err = serde_json::from_str::<OnError>("42");
        assert!(err.is_err());
    }

    // ── BatchSummary extended tests ─────────────────────────────────

    #[test]
    fn batch_summary_single_success() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!({})),
            error: None,
        }];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.skipped, 0);
    }

    #[test]
    fn batch_summary_single_error() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Error,
            result: None,
            error: Some(json!("err")),
        }];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn batch_summary_single_skipped() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Skipped,
            result: None,
            error: None,
        }];
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 1);
        assert_eq!(summary.skipped, 1);
    }

    #[test]
    fn batch_summary_counts_add_up() {
        let results: Vec<ItemResult> = (0..50)
            .map(|i| ItemResult {
                index: i,
                status: if i % 5 == 0 {
                    ItemStatus::Skipped
                } else if i % 3 == 0 {
                    ItemStatus::Error
                } else {
                    ItemStatus::Success
                },
                result: None,
                error: None,
            })
            .collect();
        let summary = BatchSummary::from_results(&results);
        assert_eq!(
            summary.succeeded + summary.failed + summary.skipped,
            summary.total
        );
        assert_eq!(summary.total, 50);
    }

    #[test]
    fn batch_summary_clone() {
        let summary = BatchSummary {
            total: 5,
            succeeded: 3,
            failed: 1,
            skipped: 1,
        };
        let cloned = summary.clone();
        assert_eq!(cloned.total, 5);
        assert_eq!(cloned.succeeded, 3);
        assert_eq!(cloned.failed, 1);
        assert_eq!(cloned.skipped, 1);
    }

    #[test]
    fn batch_summary_debug() {
        let summary = BatchSummary {
            total: 10,
            succeeded: 7,
            failed: 2,
            skipped: 1,
        };
        let debug = format!("{summary:?}");
        assert!(debug.contains("BatchSummary"));
        assert!(debug.contains("10"));
    }

    #[test]
    fn batch_summary_serialization_has_all_fields() {
        let summary = BatchSummary {
            total: 4,
            succeeded: 2,
            failed: 1,
            skipped: 1,
        };
        let json = serde_json::to_value(&summary).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("total"));
        assert!(obj.contains_key("succeeded"));
        assert!(obj.contains_key("failed"));
        assert!(obj.contains_key("skipped"));
        assert_eq!(obj.len(), 4);
    }

    // ── BatchPlan extended tests ────────────────────────────────────

    #[test]
    fn batch_plan_clone() {
        let plan = BatchPlan {
            operation: "test.op".to_owned(),
            input_count: 3,
            concurrency: 2,
            on_error: OnError::Continue,
            preview_inputs: vec![json!(1), json!(2)],
        };
        let cloned = plan.clone();
        assert_eq!(cloned.operation, "test.op");
        assert_eq!(cloned.input_count, 3);
        assert_eq!(cloned.concurrency, 2);
        assert_eq!(cloned.on_error, OnError::Continue);
        assert_eq!(cloned.preview_inputs.len(), 2);
    }

    #[test]
    fn batch_plan_debug() {
        let plan = BatchPlan {
            operation: "github.list_issues".to_owned(),
            input_count: 10,
            concurrency: 5,
            on_error: OnError::Abort,
            preview_inputs: vec![],
        };
        let debug = format!("{plan:?}");
        assert!(debug.contains("BatchPlan"));
        assert!(debug.contains("github.list_issues"));
    }

    #[test]
    fn batch_plan_serialization_all_fields() {
        let plan = BatchPlan {
            operation: "op".to_owned(),
            input_count: 7,
            concurrency: 4,
            on_error: OnError::Continue,
            preview_inputs: vec![json!("a")],
        };
        let json = serde_json::to_value(&plan).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("operation"));
        assert!(obj.contains_key("input_count"));
        assert!(obj.contains_key("concurrency"));
        assert!(obj.contains_key("on_error"));
        assert!(obj.contains_key("preview_inputs"));
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn batch_plan_large_preview() {
        let previews: Vec<Value> = (0..20).map(|i| json!({"idx": i})).collect();
        let plan = BatchPlan {
            operation: "bulk.process".to_owned(),
            input_count: 1000,
            concurrency: 10,
            on_error: OnError::Continue,
            preview_inputs: previews,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["preview_inputs"].as_array().unwrap().len(), 20);
        assert_eq!(json["input_count"], 1000);
    }

    #[test]
    fn batch_plan_concurrency_one() {
        let plan = BatchPlan {
            operation: "serial.op".to_owned(),
            input_count: 5,
            concurrency: 1,
            on_error: OnError::Abort,
            preview_inputs: vec![json!({"step": 1})],
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["concurrency"], 1);
    }

    // ── results_to_ndjson extended tests ────────────────────────────

    #[test]
    fn ndjson_large_batch() {
        let results: Vec<ItemResult> = (0..100)
            .map(|i| ItemResult {
                index: i,
                status: ItemStatus::Success,
                result: Some(json!({"n": i})),
                error: None,
            })
            .collect();
        let ndjson = results_to_ndjson(&results);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 100);
    }

    #[test]
    fn ndjson_all_statuses() {
        let results = vec![
            ItemResult {
                index: 0,
                status: ItemStatus::Success,
                result: Some(json!("ok")),
                error: None,
            },
            ItemResult {
                index: 1,
                status: ItemStatus::Error,
                result: None,
                error: Some(json!("fail")),
            },
            ItemResult {
                index: 2,
                status: ItemStatus::Skipped,
                result: None,
                error: None,
            },
        ];
        let ndjson = results_to_ndjson(&results);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 3);
        let p0: Value = serde_json::from_str(lines[0]).unwrap();
        let p1: Value = serde_json::from_str(lines[1]).unwrap();
        let p2: Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(p0["status"], "success");
        assert_eq!(p1["status"], "error");
        assert_eq!(p2["status"], "skipped");
    }

    #[test]
    fn ndjson_with_unicode_data() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!({"name": "日本語テスト"})),
            error: None,
        }];
        let ndjson = results_to_ndjson(&results);
        let parsed: Value = serde_json::from_str(ndjson.trim()).unwrap();
        assert_eq!(parsed["result"]["name"], "日本語テスト");
    }

    #[test]
    fn ndjson_ends_with_newline() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Success,
            result: Some(json!(1)),
            error: None,
        }];
        let ndjson = results_to_ndjson(&results);
        assert!(ndjson.ends_with('\n'));
    }

    #[test]
    fn ndjson_no_result_or_error_fields_when_none() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Skipped,
            result: None,
            error: None,
        }];
        let ndjson = results_to_ndjson(&results);
        let line = ndjson.trim();
        assert!(!line.contains("\"result\""));
        assert!(!line.contains("\"error\""));
    }

    #[test]
    fn ndjson_error_field_present_when_set() {
        let results = vec![ItemResult {
            index: 0,
            status: ItemStatus::Error,
            result: None,
            error: Some(json!({"code": 500})),
        }];
        let ndjson = results_to_ndjson(&results);
        let line = ndjson.trim();
        assert!(line.contains("\"error\""));
        assert!(!line.contains("\"result\""));
    }

    // ── Cross-cutting integration-style tests ───────────────────────

    #[test]
    fn json_array_to_summary_pipeline() {
        let inputs = BatchInputs::from_json_array(r#"[{"a":1},{"a":2},{"a":3}]"#).unwrap();
        let results: Vec<ItemResult> = inputs
            .items
            .iter()
            .enumerate()
            .map(|(i, _)| ItemResult {
                index: i,
                status: if i == 1 {
                    ItemStatus::Error
                } else {
                    ItemStatus::Success
                },
                result: if i != 1 { Some(json!("ok")) } else { None },
                error: if i == 1 { Some(json!("fail")) } else { None },
            })
            .collect();
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 2);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn jsonl_to_ndjson_pipeline() {
        let content = "{\"id\":1}\n{\"id\":2}\n{\"id\":3}";
        let inputs = BatchInputs::from_jsonl(content).unwrap();
        let results: Vec<ItemResult> = inputs
            .items
            .iter()
            .enumerate()
            .map(|(i, v)| ItemResult {
                index: i,
                status: ItemStatus::Success,
                result: Some(v.clone()),
                error: None,
            })
            .collect();
        let ndjson = results_to_ndjson(&results);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let parsed: Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["index"], i);
            assert_eq!(parsed["result"]["id"], i + 1);
        }
    }

    #[test]
    fn template_to_plan_pipeline() {
        let inputs =
            BatchInputs::from_template(r#"{"repo":"{{item}}"}"#, "alpha,beta,gamma").unwrap();
        let plan = BatchPlan {
            operation: "github.get_repo".to_owned(),
            input_count: inputs.len(),
            concurrency: 2,
            on_error: OnError::Continue,
            preview_inputs: inputs.items[..2].to_vec(),
        };
        assert_eq!(plan.input_count, 3);
        assert_eq!(plan.preview_inputs.len(), 2);
        assert_eq!(plan.preview_inputs[0]["repo"], "alpha");
    }

    #[test]
    fn full_pipeline_template_to_ndjson() {
        let inputs =
            BatchInputs::from_template(r#"{"n":{{item}}}"#, "10,20,30,40,50").unwrap();
        assert_eq!(inputs.len(), 5);
        let results: Vec<ItemResult> = inputs
            .items
            .iter()
            .enumerate()
            .map(|(i, _)| ItemResult {
                index: i,
                status: ItemStatus::Success,
                result: Some(json!({"processed": true})),
                error: None,
            })
            .collect();
        let ndjson = results_to_ndjson(&results);
        let summary = BatchSummary::from_results(&results);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.succeeded, 5);
        let lines: Vec<&str> = ndjson.trim().split('\n').collect();
        assert_eq!(lines.len(), 5);
    }
}
