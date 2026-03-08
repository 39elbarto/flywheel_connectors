use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
pub enum OutputFormat {
    Json,
    Jsonl,
    #[default]
    Toon,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Toon => "toon",
        }
    }
}

/// Render a JSON value according to the chosen output format.
///
/// All formats produce deterministic output for a given input:
/// - **Toon**: token-efficient, agent-readable (default)
/// - **Json**: pretty-printed with stable key ordering (`serde_json` sorts keys
///   for `BTreeMap` and preserves insertion order for `serde_json::Map`)
/// - **Jsonl**: compact single-line JSON
pub fn render(value: Value, format: OutputFormat) -> Result<String> {
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&value)?,
        OutputFormat::Jsonl => serde_json::to_string(&value)?,
        OutputFormat::Toon => toon::encode(value, None),
    };

    Ok(format!("{rendered}\n"))
}

/// Token-efficiency statistics comparing TOON vs JSON representations.
#[derive(Clone, Debug, Serialize)]
pub struct TokenStats {
    /// The format selected for the current render.
    pub selected_format: &'static str,
    /// Byte length of the selected output format.
    pub selected_bytes: usize,
    /// The most byte-efficient format for this payload.
    pub recommended_format: &'static str,
    /// Byte length of the recommended output format.
    pub recommended_bytes: usize,
    /// Byte length of the TOON-encoded output.
    pub toon_bytes: usize,
    /// Byte length of the pretty-printed JSON output.
    pub json_bytes: usize,
    /// Byte length of the compact (JSONL) output.
    pub jsonl_bytes: usize,
    /// Byte savings of TOON vs pretty JSON.
    pub toon_json_saved_bytes: i64,
    /// Byte savings of TOON vs compact JSONL.
    pub toon_jsonl_saved_bytes: i64,
    /// TOON-to-JSON byte ratio (lower is better for TOON).
    pub toon_json_ratio: f64,
    /// Approximate TOON savings vs JSON as a percentage.
    pub savings_pct: f64,
}

/// Compute token-efficiency statistics for a value across all output formats.
pub fn token_stats(value: &Value, selected_format: OutputFormat) -> TokenStats {
    let toon_out = toon::encode(value.clone(), None);
    let pretty_out = serde_json::to_string_pretty(value).unwrap_or_default();
    let compact_out = serde_json::to_string(value).unwrap_or_default();

    let toon_len = toon_out.len();
    let pretty_len = pretty_out.len();
    let compact_len = compact_out.len();
    let selected_bytes = match selected_format {
        OutputFormat::Json => pretty_len,
        OutputFormat::Jsonl => compact_len,
        OutputFormat::Toon => toon_len,
    };
    let recommended = [
        (OutputFormat::Toon, toon_len),
        (OutputFormat::Jsonl, compact_len),
        (OutputFormat::Json, pretty_len),
    ]
    .into_iter()
    .min_by_key(|(_, len)| *len)
    .unwrap_or((OutputFormat::Toon, toon_len));

    #[allow(clippy::cast_precision_loss)]
    let toon_json_ratio = if pretty_len > 0 {
        toon_len as f64 / pretty_len as f64
    } else {
        1.0
    };
    let savings_pct = (1.0 - toon_json_ratio) * 100.0;

    TokenStats {
        selected_format: selected_format.as_str(),
        selected_bytes,
        recommended_format: recommended.0.as_str(),
        recommended_bytes: recommended.1,
        toon_bytes: toon_len,
        json_bytes: pretty_len,
        jsonl_bytes: compact_len,
        toon_json_saved_bytes: signed_len_delta(pretty_len, toon_len),
        toon_jsonl_saved_bytes: signed_len_delta(compact_len, toon_len),
        toon_json_ratio,
        savings_pct,
    }
}

fn signed_len_delta(lhs: usize, rhs: usize) -> i64 {
    match (i64::try_from(lhs), i64::try_from(rhs)) {
        (Ok(lhs), Ok(rhs)) => lhs - rhs,
        _ if lhs >= rhs => i64::MAX,
        _ => i64::MIN,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{OutputFormat, render, token_stats};

    // ── Basic format rendering ──────────────────────────────────────────

    #[test]
    fn json_render_starts_like_json() {
        let text = render(json!({ "status": "ok" }), OutputFormat::Json).unwrap();
        assert!(text.trim_start().starts_with('{'));
    }

    #[test]
    fn jsonl_render_is_single_line_json() {
        let text = render(json!({ "status": "ok" }), OutputFormat::Jsonl).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.trim_end().starts_with('{'));
    }

    #[test]
    fn toon_render_is_not_json_shaped() {
        let text = render(json!({ "status": "ok" }), OutputFormat::Toon).unwrap();
        assert!(text.contains("status"));
        assert!(!text.trim_start().starts_with('{'));
    }

    // ── Trailing newline contract ───────────────────────────────────────

    #[test]
    fn all_formats_end_with_newline() {
        let v = json!({"a": 1});
        for fmt in [OutputFormat::Json, OutputFormat::Jsonl, OutputFormat::Toon] {
            let text = render(v.clone(), fmt).unwrap();
            assert!(
                text.ends_with('\n'),
                "format {fmt:?} missing trailing newline"
            );
        }
    }

    // ── Deterministic output ────────────────────────────────────────────

    #[test]
    fn json_output_is_deterministic_across_calls() {
        let v = json!({"z_key": 1, "a_key": 2, "m_key": 3});
        let first = render(v.clone(), OutputFormat::Json).unwrap();
        let second = render(v, OutputFormat::Json).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn toon_output_is_deterministic_across_calls() {
        let v = json!({"z_key": 1, "a_key": 2, "m_key": 3});
        let first = render(v.clone(), OutputFormat::Toon).unwrap();
        let second = render(v, OutputFormat::Toon).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn jsonl_output_is_deterministic_across_calls() {
        let v = json!({"items": [1, 2, 3], "meta": {"count": 3}});
        let first = render(v.clone(), OutputFormat::Jsonl).unwrap();
        let second = render(v, OutputFormat::Jsonl).unwrap();
        assert_eq!(first, second);
    }

    // ── JSON completeness ───────────────────────────────────────────────

    #[test]
    fn json_round_trips_complex_value() {
        let v = json!({
            "status": "ok",
            "connectors": [
                {"id": "github", "ops": 12, "enabled": true},
                {"id": "slack", "ops": 8, "enabled": false}
            ],
            "metadata": {"version": "1.0", "count": null}
        });
        let text = render(v.clone(), OutputFormat::Json).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn jsonl_round_trips_complex_value() {
        let v = json!({
            "error": {"type": "validation", "message": "missing field"},
            "exit_code": 5
        });
        let text = render(v.clone(), OutputFormat::Jsonl).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v, parsed);
    }

    // ── TOON content preservation ───────────────────────────────────────

    #[test]
    fn toon_preserves_all_keys_and_values() {
        let v = json!({
            "connector": "github",
            "operation": "issues.create",
            "risk": "medium"
        });
        let text = render(v, OutputFormat::Toon).unwrap();
        assert!(text.contains("connector"));
        assert!(text.contains("github"));
        assert!(text.contains("operation"));
        assert!(text.contains("issues.create"));
        assert!(text.contains("risk"));
        assert!(text.contains("medium"));
    }

    #[test]
    fn toon_handles_nested_objects() {
        let v = json!({"outer": {"inner": {"deep": "value"}}});
        let text = render(v, OutputFormat::Toon).unwrap();
        assert!(text.contains("deep"));
        assert!(text.contains("value"));
    }

    #[test]
    fn toon_handles_arrays() {
        let v = json!({"items": ["alpha", "beta", "gamma"]});
        let text = render(v, OutputFormat::Toon).unwrap();
        assert!(text.contains("alpha"));
        assert!(text.contains("gamma"));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn render_empty_object_json_formats() {
        for fmt in [OutputFormat::Json, OutputFormat::Jsonl] {
            let text = render(json!({}), fmt).unwrap();
            assert!(
                !text.trim().is_empty(),
                "format {fmt:?} produced empty for {{}}"
            );
        }
    }

    #[test]
    fn render_empty_object_toon_is_minimal() {
        // TOON may render empty objects as empty (no keys = no output).
        let text = render(json!({}), OutputFormat::Toon).unwrap();
        // Just verify it doesn't error — TOON legitimately elides empty objects.
        assert!(text.len() <= 2, "TOON empty object should be minimal");
    }

    #[test]
    fn render_null_value() {
        let text = render(json!(null), OutputFormat::Json).unwrap();
        assert!(text.trim() == "null");
    }

    #[test]
    fn render_scalar_string() {
        let text = render(json!("hello"), OutputFormat::Json).unwrap();
        assert!(text.contains("hello"));
    }

    #[test]
    fn render_large_number() {
        let v = json!({"big": 9_999_999_999_i64, "small": -1});
        let text = render(v, OutputFormat::Jsonl).unwrap();
        assert!(text.contains("9999999999"));
        assert!(text.contains("-1"));
    }

    #[test]
    fn render_unicode_content() {
        let v = json!({"greeting": "こんにちは", "emoji": "🦀"});
        let text = render(v, OutputFormat::Json).unwrap();
        assert!(text.contains("こんにちは"));
        assert!(text.contains("🦀"));
    }

    #[test]
    fn render_boolean_values() {
        let v = json!({"enabled": true, "paused": false});
        for fmt in [OutputFormat::Json, OutputFormat::Jsonl, OutputFormat::Toon] {
            let text = render(v.clone(), fmt).unwrap();
            assert!(text.contains("true"), "format {fmt:?} missing true");
            assert!(text.contains("false"), "format {fmt:?} missing false");
        }
    }

    // ── Default format ──────────────────────────────────────────────────

    #[test]
    fn default_format_is_toon() {
        assert_eq!(OutputFormat::default(), OutputFormat::Toon);
    }

    #[test]
    fn format_enum_equality() {
        assert_ne!(OutputFormat::Json, OutputFormat::Toon);
        assert_ne!(OutputFormat::Json, OutputFormat::Jsonl);
        assert_ne!(OutputFormat::Toon, OutputFormat::Jsonl);
    }

    // ── Token stats ─────────────────────────────────────────────────────

    #[test]
    fn token_stats_toon_is_shorter_than_json_for_structured_output() {
        let v = json!({
            "status": "ok",
            "connectors": [
                {"id": "github", "operations": 12, "enabled": true, "zone": "z:work"},
                {"id": "slack", "operations": 8, "enabled": false, "zone": "z:community"},
                {"id": "notion", "operations": 15, "enabled": true, "zone": "z:work"}
            ],
            "metadata": {"format": "toon", "version": "1.0"}
        });
        let stats = token_stats(&v, OutputFormat::Toon);
        assert!(
            stats.toon_bytes < stats.json_bytes,
            "TOON ({}) should be shorter than JSON ({})",
            stats.toon_bytes,
            stats.json_bytes,
        );
        assert!(stats.savings_pct > 0.0);
        assert_eq!(stats.selected_format, "toon");
        assert_eq!(stats.selected_bytes, stats.toon_bytes);
    }

    #[test]
    fn token_stats_ratio_is_bounded() {
        let v = json!({"key": "value"});
        let stats = token_stats(&v, OutputFormat::Json);
        assert!(stats.toon_json_ratio > 0.0);
        assert!(
            stats.toon_json_ratio <= 2.0,
            "ratio {} out of range",
            stats.toon_json_ratio
        );
        assert_eq!(stats.selected_format, "json");
        assert_eq!(stats.selected_bytes, stats.json_bytes);
    }

    #[test]
    fn token_stats_jsonl_is_shorter_than_pretty_json() {
        let v = json!({"a": 1, "b": [1, 2, 3], "c": {"d": "e"}});
        let stats = token_stats(&v, OutputFormat::Jsonl);
        assert!(
            stats.jsonl_bytes < stats.json_bytes,
            "JSONL ({}) should be shorter than JSON ({})",
            stats.jsonl_bytes,
            stats.json_bytes,
        );
        assert_eq!(stats.selected_format, "jsonl");
        assert_eq!(stats.selected_bytes, stats.jsonl_bytes);
    }

    #[test]
    fn token_stats_empty_object() {
        let stats = token_stats(&json!({}), OutputFormat::Toon);
        // TOON may elide empty objects (0 bytes); JSON always has "{}".
        assert!(stats.json_bytes > 0);
        assert!(stats.jsonl_bytes > 0);
    }

    #[test]
    fn token_stats_large_payload() {
        let items: Vec<Value> = (0..50)
            .map(|i| {
                json!({
                    "id": format!("item-{i}"),
                    "value": i * 17,
                    "active": i % 2 == 0
                })
            })
            .collect();
        let v = json!({"items": items, "total": 50});
        let stats = token_stats(&v, OutputFormat::Toon);
        assert!(
            stats.savings_pct > 0.0,
            "large payload should show TOON savings"
        );
    }

    #[test]
    fn token_stats_reports_recommended_format() {
        let v = json!({"a": 1, "b": 2, "c": [1, 2, 3]});
        let stats = token_stats(&v, OutputFormat::Toon);
        assert!(!stats.recommended_format.is_empty());
        assert!(stats.recommended_bytes <= stats.json_bytes);
        assert!(stats.recommended_bytes <= stats.jsonl_bytes.max(stats.toon_bytes));
    }

    // ── Error payload structure ──────────────────────────────────────────

    #[test]
    fn error_payload_renders_consistently_across_formats() {
        let error_payload = json!({
            "status": "error",
            "error": {
                "type": "validation",
                "message": "Missing required field: connector",
                "recoverable": true,
                "did_you_mean": ["github", "gitlab"],
                "examples": ["fwc invoke github issues.create --file payload.json"],
                "next_actions": ["Specify a connector with --connector=<id>"]
            },
            "input": {
                "received": ["fwc", "invoke"],
                "normalized": ["fwc", "invoke"]
            }
        });

        // JSON: parseable, contains all fields
        let json_text = render(error_payload.clone(), OutputFormat::Json).unwrap();
        let reparsed: Value = serde_json::from_str(json_text.trim()).unwrap();
        assert_eq!(reparsed["error"]["type"], "validation");
        assert_eq!(reparsed["error"]["recoverable"], true);
        assert!(reparsed["error"]["did_you_mean"].as_array().unwrap().len() == 2);

        // JSONL: same data, compact
        let compact_text = render(error_payload.clone(), OutputFormat::Jsonl).unwrap();
        let reparsed_l: Value = serde_json::from_str(compact_text.trim()).unwrap();
        assert_eq!(
            reparsed_l["error"]["message"],
            "Missing required field: connector"
        );

        // TOON: contains key fields (not necessarily parseable as JSON)
        let toon_text = render(error_payload, OutputFormat::Toon).unwrap();
        assert!(toon_text.contains("validation"));
        assert!(toon_text.contains("recoverable"));
        assert!(toon_text.contains("github"));
    }

    // ── Format-specific structure tests ──────────────────────────────────

    #[test]
    fn json_uses_indentation() {
        let v = json!({"a": {"b": 1}});
        let text = render(v, OutputFormat::Json).unwrap();
        // Pretty-printed JSON has newlines and spaces
        assert!(text.contains('\n'));
        assert!(text.lines().count() > 1);
    }

    #[test]
    fn jsonl_has_no_internal_newlines() {
        let v = json!({"a": {"b": [1, 2, 3]}, "c": "d"});
        let text = render(v, OutputFormat::Jsonl).unwrap();
        // Only trailing newline, no internal ones
        assert_eq!(text.trim().lines().count(), 1);
    }
}
