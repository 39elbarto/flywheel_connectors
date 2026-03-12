use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use handlebars::{handlebars_helper, no_escape, Handlebars};
use jaq_core::{
    load::{Arena, File, Loader},
    Ctx, RcIter,
};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
pub enum OutputFormat {
    Json,
    Jsonl,
    /// Newline-delimited JSON: arrays emit one object per line.
    Ndjson,
    #[default]
    Toon,
    /// ASCII table with aligned columns.
    Table,
    /// Comma-separated values.
    Csv,
    /// Tab-separated values.
    Tsv,
    /// Markdown table.
    Markdown,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Ndjson => "ndjson",
            Self::Toon => "toon",
            Self::Table => "table",
            Self::Csv => "csv",
            Self::Tsv => "tsv",
            Self::Markdown => "markdown",
        }
    }

    /// Whether this format is a tabular format.
    pub const fn is_tabular(self) -> bool {
        matches!(self, Self::Table | Self::Csv | Self::Tsv | Self::Markdown)
    }

    /// Whether this format preserves JSON semantics after rendering.
    #[allow(dead_code)]
    pub const fn is_json_like(self) -> bool {
        matches!(self, Self::Json | Self::Jsonl | Self::Ndjson)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RenderOptions {
    pub template: Option<TemplateRender>,
    pub extract: Option<ExtractRender>,
    /// Explicit column list for tabular formats.
    pub tabular_columns: Vec<String>,
    /// Sort by this column in tabular formats.
    pub tabular_sort_by: Option<String>,
    /// Maximum rows for tabular formats (0 = unlimited).
    pub tabular_limit: usize,
    /// Suppress headers in tabular formats.
    pub tabular_no_headers: bool,
}

impl RenderOptions {
    pub const fn has_template(&self) -> bool {
        self.template.is_some()
    }

    pub const fn has_extract(&self) -> bool {
        self.extract.is_some()
    }

    pub const fn has_transform(&self) -> bool {
        self.template.is_some() || self.extract.is_some()
    }

    pub fn without_extract(&self) -> Self {
        Self {
            template: self.template.clone(),
            extract: None,
            tabular_columns: self.tabular_columns.clone(),
            tabular_sort_by: self.tabular_sort_by.clone(),
            tabular_limit: self.tabular_limit,
            tabular_no_headers: self.tabular_no_headers,
        }
    }

    pub fn transform_metadata(&self) -> Option<Value> {
        self.template
            .as_ref()
            .map(TemplateRender::metadata)
            .or_else(|| self.extract.as_ref().map(ExtractRender::metadata))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateRender {
    template: String,
    source: TemplateSource,
    origin: Option<PathBuf>,
}

impl TemplateRender {
    pub fn inline(template: impl Into<String>) -> Result<Self> {
        let template = template.into();
        validate_template(&template).context("failed to parse inline template")?;
        Ok(Self {
            template,
            source: TemplateSource::Inline,
            origin: None,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let template = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read template file `{}`", path.display()))?;
        validate_template(&template)
            .with_context(|| format!("failed to parse template file `{}`", path.display()))?;
        Ok(Self {
            template,
            source: TemplateSource::File,
            origin: Some(path),
        })
    }

    fn metadata(&self) -> Value {
        json!({
            "kind": "handlebars",
            "source": self.source.as_str(),
            "path": self.origin.as_ref().map(|path| path.display().to_string()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractRender {
    filter: String,
}

impl ExtractRender {
    pub fn inline(filter: impl Into<String>) -> Result<Self> {
        let filter = filter.into();
        validate_extract_filter(&filter).context("failed to parse jq filter")?;
        Ok(Self { filter })
    }

    fn metadata(&self) -> Value {
        json!({
            "kind": "jq",
            "engine": "jaq",
            "filter": self.filter,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateSource {
    Inline,
    File,
}

impl TemplateSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::File => "file",
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
#[allow(dead_code)]
pub fn render(value: Value, format: OutputFormat) -> Result<String> {
    render_with_options(value, format, &RenderOptions::default())
}

pub fn apply_extract_filter(value: &Value, filter: &str) -> Result<Value> {
    let extract = ExtractRender::inline(filter)?;
    render_extract(value, &extract)
}

/// Render a JSON value according to the chosen output format plus any
/// post-processing transforms such as Handlebars templating.
pub fn render_with_options(
    mut value: Value,
    format: OutputFormat,
    options: &RenderOptions,
) -> Result<String> {
    if let Some(extract) = &options.extract {
        value = render_extract(&value, extract)?;
    }

    if let Some(template) = &options.template {
        let rendered = render_template(&value, template)?;
        return Ok(ensure_trailing_newline(rendered));
    }

    if format.is_tabular() {
        return render_tabular_value(&value, format, options);
    }

    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&value)?,
        OutputFormat::Jsonl => serde_json::to_string(&value)?,
        OutputFormat::Ndjson => render_ndjson(&value),
        OutputFormat::Toon => toon::encode(value, None),
        // Tabular formats handled above.
        OutputFormat::Table | OutputFormat::Csv | OutputFormat::Tsv | OutputFormat::Markdown => {
            unreachable!()
        }
    };

    Ok(ensure_trailing_newline(rendered))
}

/// Render a JSON value in a tabular format (table, CSV, TSV, or Markdown).
fn render_tabular_value(
    value: &Value,
    format: OutputFormat,
    options: &RenderOptions,
) -> Result<String> {
    use crate::format_table::{render_tabular, TabularFormat, TabularOptions};

    let tab_fmt = match format {
        OutputFormat::Table => TabularFormat::Table,
        OutputFormat::Csv => TabularFormat::Csv,
        OutputFormat::Tsv => TabularFormat::Tsv,
        OutputFormat::Markdown => TabularFormat::Markdown,
        _ => unreachable!(),
    };

    let tab_opts = TabularOptions {
        columns: options.tabular_columns.clone(),
        sort_by: options.tabular_sort_by.clone(),
        limit: options.tabular_limit,
        no_headers: options.tabular_no_headers,
    };

    // If data isn't tabular, fall back to JSON.
    if let Ok(rendered) = render_tabular(value, tab_fmt, &tab_opts) {
        Ok(ensure_trailing_newline(rendered))
    } else {
        let rendered = serde_json::to_string_pretty(value)?;
        Ok(ensure_trailing_newline(rendered))
    }
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
        OutputFormat::Toon => toon_len,
        // All other formats approximate as compact.
        OutputFormat::Jsonl
        | OutputFormat::Ndjson
        | OutputFormat::Table
        | OutputFormat::Csv
        | OutputFormat::Tsv
        | OutputFormat::Markdown => compact_len,
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

/// Render NDJSON: arrays emit one JSON object per line, others act like JSONL.
fn render_ndjson(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let mut out = String::new();
            for item in items {
                if let Ok(line) = serde_json::to_string(item) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            out
        }
        // For objects, look for a well-known data array field and stream its items.
        Value::Object(map) => {
            for key in &[
                "items",
                "results",
                "data",
                "rows",
                "entries",
                "records",
                "connectors",
                "operations",
                "issues",
                "messages",
            ] {
                if let Some(Value::Array(items)) = map.get(*key) {
                    let mut out = String::new();
                    for item in items {
                        if let Ok(line) = serde_json::to_string(item) {
                            out.push_str(&line);
                            out.push('\n');
                        }
                    }
                    return out;
                }
            }
            // No array field found — emit the whole object as one line.
            serde_json::to_string(value).unwrap_or_default()
        }
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn ensure_trailing_newline(rendered: String) -> String {
    if rendered.ends_with('\n') {
        rendered
    } else {
        format!("{rendered}\n")
    }
}

fn validate_extract_filter(filter: &str) -> Result<()> {
    let arena = Arena::default();
    let loader = Loader::new(jaq_std::defs().chain(jaq_json::defs()));
    let modules = loader
        .load(
            &arena,
            File {
                code: filter,
                path: (),
            },
        )
        .map_err(|errors| anyhow!("failed to parse jq filter: {errors:?}"))?;
    jaq_core::Compiler::default()
        .with_funs(jaq_std::funs().chain(jaq_json::funs()))
        .compile(modules)
        .map_err(|errors| anyhow!("failed to compile jq filter: {errors:?}"))?;
    Ok(())
}

fn render_extract(value: &Value, extract: &ExtractRender) -> Result<Value> {
    let arena = Arena::default();
    let loader = Loader::new(jaq_std::defs().chain(jaq_json::defs()));
    let modules = loader
        .load(
            &arena,
            File {
                code: &extract.filter,
                path: (),
            },
        )
        .map_err(|errors| anyhow!("failed to parse jq filter: {errors:?}"))?;
    let filter = jaq_core::Compiler::default()
        .with_funs(jaq_std::funs().chain(jaq_json::funs()))
        .compile(modules)
        .map_err(|errors| anyhow!("failed to compile jq filter: {errors:?}"))?;
    let inputs = RcIter::new(core::iter::empty());
    let mut outputs = Vec::new();

    for output in filter.run((Ctx::new([], &inputs), jaq_json::Val::from(value.clone()))) {
        let output = output.map_err(|e| anyhow!("failed to evaluate jq filter: {e:?}"))?;
        outputs.push(serde_json::Value::from(output));
    }

    Ok(match outputs.len() {
        0 => Value::Null,
        1 => outputs.into_iter().next().unwrap_or(Value::Null),
        _ => Value::Array(outputs),
    })
}

fn render_template(value: &Value, template: &TemplateRender) -> Result<String> {
    let registry = template_registry();
    registry
        .render_template(&template.template, value)
        .context("failed to render Handlebars template")
}

fn validate_template(template: &str) -> Result<()> {
    let mut registry = template_registry();
    registry
        .register_template_string("__fwc_validate__", template)
        .context("template syntax error")
}

fn template_registry() -> Handlebars<'static> {
    handlebars_helper!(json_helper: |value: Json| serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_owned()));
    handlebars_helper!(compact_helper: |value: Json| serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned()));
    handlebars_helper!(count_helper: |value: Json| u64::try_from(count_value(value)).unwrap_or(u64::MAX));
    handlebars_helper!(truncate_helper: |value: str, max: u64| truncate_text(value, usize::try_from(max).unwrap_or(usize::MAX)));
    handlebars_helper!(timeago_helper: |value: str| humanize_timestamp(value, Utc::now()));
    handlebars_helper!(if_eq_helper: |left: Json, right: Json| left == right);

    let mut registry = Handlebars::new();
    registry.register_escape_fn(no_escape);
    registry.set_strict_mode(true);
    registry.register_helper("json", Box::new(json_helper));
    registry.register_helper("compact", Box::new(compact_helper));
    registry.register_helper("count", Box::new(count_helper));
    registry.register_helper("truncate", Box::new(truncate_helper));
    registry.register_helper("timeago", Box::new(timeago_helper));
    registry.register_helper("if_eq", Box::new(if_eq_helper));
    registry
}

fn count_value(value: &Value) -> usize {
    match value {
        Value::Array(items) => items.len(),
        Value::Object(entries) => entries.len(),
        Value::String(text) => text.chars().count(),
        Value::Null => 0,
        Value::Bool(_) | Value::Number(_) => 1,
    }
}

fn truncate_text(value: &str, max: usize) -> String {
    let len = value.chars().count();
    if len <= max {
        return value.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        return "…".to_owned();
    }

    value.chars().take(max - 1).collect::<String>() + "…"
}

fn humanize_timestamp(value: &str, now: DateTime<Utc>) -> String {
    DateTime::parse_from_rfc3339(value).map_or_else(
        |_| value.to_owned(),
        |timestamp| relative_time_label(timestamp.with_timezone(&Utc), now),
    )
}

fn relative_time_label(target: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let delta = target.signed_duration_since(now);
    let seconds = delta.num_seconds();
    if seconds.unsigned_abs() < 5 {
        return "just now".to_owned();
    }

    let (magnitude, unit) = match seconds.unsigned_abs() {
        0..=59 => (seconds.unsigned_abs(), "s"),
        60..=3_599 => (seconds.unsigned_abs() / 60, "m"),
        3_600..=86_399 => (seconds.unsigned_abs() / 3_600, "h"),
        86_400..=604_799 => (seconds.unsigned_abs() / 86_400, "d"),
        value => (value / 604_800, "w"),
    };

    if seconds.is_positive() {
        format!("in {magnitude}{unit}")
    } else {
        format!("{magnitude}{unit} ago")
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::{Duration, Utc};
    use serde_json::{json, Value};

    use crate::error_taxonomy::{FcpErrorCode, StructuredError};

    use super::{
        humanize_timestamp, relative_time_label, render, render_with_options, token_stats,
        ExtractRender, OutputFormat, RenderOptions, TemplateRender, TemplateSource,
    };

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

    #[test]
    fn structured_error_payload_preserves_live_refusal_guidance_across_formats() {
        let error = StructuredError::new(
            FcpErrorCode::FcpErrMissingCapabilityToken,
            "Live invoke requires a capability token",
        )
        .with_details(json!({
            "command_mode": "live-runtime",
            "reason": "missing_capability_token",
        }));
        let payload = json!({
            "status": "error",
            "error": error.to_value(),
        });

        let json_text = render(payload.clone(), OutputFormat::Json).unwrap();
        let reparsed: Value = serde_json::from_str(json_text.trim()).unwrap();
        assert_eq!(
            reparsed["error"]["code"],
            "FCP_ERR_MISSING_CAPABILITY_TOKEN"
        );
        assert_eq!(reparsed["error"]["details"]["command_mode"], "live-runtime");
        assert_eq!(
            reparsed["error"]["recovery"]["command"],
            "fwc invoke --capability-token <token>"
        );

        let jsonl_text = render(payload.clone(), OutputFormat::Jsonl).unwrap();
        let reparsed_jsonl: Value = serde_json::from_str(jsonl_text.trim()).unwrap();
        assert_eq!(reparsed_jsonl["error"]["category"], "auth");
        assert_eq!(
            reparsed_jsonl["error"]["details"]["reason"],
            "missing_capability_token"
        );

        let toon_text = render(payload, OutputFormat::Toon).unwrap();
        assert!(toon_text.contains("FCP_ERR_MISSING_CAPABILITY_TOKEN"));
        assert!(toon_text.contains("live-runtime"));
        assert!(toon_text.contains("--capability-token"));
        assert!(toon_text.contains("simulate"));
    }

    #[test]
    fn structured_error_payload_for_elevation_required_avoids_offline_hint_in_toon() {
        let error = StructuredError::new(
            FcpErrorCode::FcpErrElevationRequired,
            "Live invoke requires approval",
        )
        .with_details(json!({
            "command_mode": "live-runtime",
            "reason": "elevation_required",
        }));
        let payload = json!({
            "status": "error",
            "error": error.to_value(),
            "next_actions": ["Request approval from the issuing authority"],
        });

        let toon_text = render(payload, OutputFormat::Toon).unwrap();
        assert!(toon_text.contains("FCP_ERR_ELEVATION_REQUIRED"));
        assert!(toon_text.contains("--approval-token"));
        assert!(!toon_text.contains("--offline"));
        assert!(!toon_text.contains("placeholder"));
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

    // ── Template transforms ─────────────────────────────────────────────

    #[test]
    fn template_render_interpolates_nested_fields() {
        let template = TemplateRender::inline("{{connector.slug}} => {{connector.name}}").unwrap();
        let text = render_with_options(
            json!({"connector": {"slug": "github", "name": "GitHub"}}),
            OutputFormat::Toon,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "github => GitHub\n");
    }

    #[test]
    fn template_render_supports_each_and_if_eq_helpers() {
        let template = TemplateRender::inline(
            "{{#each issues}}{{#if (if_eq state \"open\")}}#{{number}} {{title}}\n{{/if}}{{/each}}",
        )
        .unwrap();
        let text = render_with_options(
            json!({
                "issues": [
                    {"number": 1, "title": "open", "state": "open"},
                    {"number": 2, "title": "closed", "state": "closed"}
                ]
            }),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "#1 open\n");
    }

    #[test]
    fn template_render_supports_json_compact_count_and_truncate_helpers() {
        let template = TemplateRender::inline(
            "{{count items}}|{{truncate title 6}}|{{compact meta}}|{{json meta}}",
        )
        .unwrap();
        let text = render_with_options(
            json!({
                "items": [1, 2, 3],
                "title": "connector",
                "meta": {"risk": "low"}
            }),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert!(text.starts_with("3|conne…|{\"risk\":\"low\"}|{\n"));
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn template_render_supports_timeago_helper() {
        let template = TemplateRender::inline("{{timeago ts}}").unwrap();
        let ts = (Utc::now() - Duration::hours(2)).to_rfc3339();
        let text = render_with_options(
            json!({ "ts": ts }),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "2h ago\n");
    }

    #[test]
    fn template_render_reports_missing_fields_in_strict_mode() {
        let template = TemplateRender::inline("{{connector.slug}}").unwrap();
        let error = render_with_options(
            json!({"status": "ok"}),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .expect_err("missing template field should fail");

        assert!(
            error
                .to_string()
                .contains("failed to render Handlebars template"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn template_render_loads_from_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fwc-render-{unique}.hbs"));
        std::fs::write(&path, "{{connector.slug}} from file").unwrap();

        let template = TemplateRender::from_file(&path).unwrap();
        assert_eq!(template.source, TemplateSource::File);

        let text = render_with_options(
            json!({"connector": {"slug": "github"}}),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "github from file\n");
    }

    #[test]
    fn template_metadata_captures_source_kind_and_path() {
        let inline = TemplateRender::inline("{{status}}").unwrap();
        assert_eq!(inline.metadata()["source"], "inline");

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fwc-render-metadata-{unique}.hbs"));
        std::fs::write(&path, "{{status}}").unwrap();
        let from_file = TemplateRender::from_file(&path).unwrap();
        assert_eq!(from_file.metadata()["source"], "file");
        assert_eq!(from_file.metadata()["path"], path.display().to_string());
    }

    #[test]
    fn invalid_inline_template_is_rejected() {
        let error = TemplateRender::inline("{{#if status}}").expect_err("template should fail");
        assert!(
            error
                .to_string()
                .contains("failed to parse inline template"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn invalid_template_file_is_rejected() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("fwc-render-invalid-{unique}.hbs"));
        std::fs::write(&path, "{{#if status}}").unwrap();
        let error = TemplateRender::from_file(&path).expect_err("template should fail");
        assert!(
            error.to_string().contains(&format!(
                "failed to parse template file `{}`",
                path.display()
            )),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn extract_render_selects_nested_field() {
        let extract = ExtractRender::inline(".connector.slug").unwrap();
        let text = render_with_options(
            json!({"connector": {"slug": "github", "name": "GitHub"}}),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "\"github\"\n");
    }

    #[test]
    fn extract_render_supports_array_indexing() {
        let extract = ExtractRender::inline(".issues[0].title").unwrap();
        let text = render_with_options(
            json!({
                "issues": [
                    {"title": "open", "number": 1},
                    {"title": "closed", "number": 2}
                ]
            }),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "\"open\"\n");
    }

    #[test]
    fn extract_render_supports_object_construction() {
        let extract = ExtractRender::inline(".issues[] | {title, number}").unwrap();
        let text = render_with_options(
            json!({
                "issues": [
                    {"title": "open", "number": 1, "state": "open"},
                    {"title": "closed", "number": 2, "state": "closed"}
                ]
            }),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        let payload: Value = serde_json::from_str(&text).unwrap();

        assert_eq!(
            payload,
            json!([
                {"title": "open", "number": 1},
                {"title": "closed", "number": 2}
            ])
        );
    }

    #[test]
    fn extract_render_supports_length_queries() {
        let extract = ExtractRender::inline(".issues | length").unwrap();
        let text = render_with_options(
            json!({
                "issues": [
                    {"title": "open"},
                    {"title": "closed"}
                ]
            }),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "2\n");
    }

    #[test]
    fn extract_render_returns_null_for_empty_results() {
        let extract = ExtractRender::inline(".issues[] | select(.state == \"missing\")").unwrap();
        let text = render_with_options(
            json!({
                "issues": [
                    {"title": "open", "state": "open"},
                    {"title": "closed", "state": "closed"}
                ]
            }),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();

        assert_eq!(text, "null\n");
    }

    #[test]
    fn invalid_extract_filter_is_rejected() {
        let error = ExtractRender::inline(".issues[").expect_err("filter should fail");
        assert!(
            error.to_string().contains("failed to parse jq filter"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn humanize_timestamp_falls_back_to_original_value_for_invalid_input() {
        assert_eq!(
            humanize_timestamp("not-a-timestamp", Utc::now()),
            "not-a-timestamp"
        );
    }

    #[test]
    fn relative_time_label_handles_future_values() {
        let now = Utc::now();
        let label = relative_time_label(now + Duration::minutes(15), now);
        assert_eq!(label, "in 15m");
    }

    // ── NDJSON rendering ────────────────────────────────────────────

    #[test]
    fn ndjson_array_emits_one_line_per_item() {
        let data = json!([{"a": 1}, {"a": 2}, {"a": 3}]);
        let text = render(data, OutputFormat::Ndjson).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"a\":1") || lines[0].contains("\"a\": 1"));
    }

    #[test]
    fn ndjson_single_object_emits_one_line() {
        let data = json!({"status": "ok"});
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn ndjson_wrapper_object_with_items_streams_items() {
        let data = json!({
            "total": 2,
            "items": [{"id": 1}, {"id": 2}]
        });
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn ndjson_empty_array() {
        let data = json!([]);
        let text = render(data, OutputFormat::Ndjson).unwrap();
        // Empty array produces empty string, trailing newline added.
        assert!(text.trim().is_empty() || text == "\n");
    }

    #[test]
    fn ndjson_each_line_is_valid_json() {
        let data = json!([
            {"name": "alice", "score": 10},
            {"name": "bob", "score": 20},
        ]);
        let text = render(data, OutputFormat::Ndjson).unwrap();
        for line in text.lines() {
            if !line.is_empty() {
                let parsed: Value =
                    serde_json::from_str(line).expect("each NDJSON line should be valid JSON");
                assert!(parsed.is_object());
            }
        }
    }

    #[test]
    fn ndjson_scalar_value() {
        let data = json!("hello");
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.trim(), "\"hello\"");
    }

    #[test]
    fn ndjson_wrapper_connectors_field() {
        let data = json!({
            "status": "ok",
            "connectors": [
                {"slug": "github"},
                {"slug": "slack"},
            ]
        });
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("github"));
        assert!(text.contains("slack"));
    }

    // ── OutputFormat methods ───────────────────────────────────────

    #[test]
    fn format_as_str_all_variants() {
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Jsonl.as_str(), "jsonl");
        assert_eq!(OutputFormat::Ndjson.as_str(), "ndjson");
        assert_eq!(OutputFormat::Toon.as_str(), "toon");
        assert_eq!(OutputFormat::Table.as_str(), "table");
        assert_eq!(OutputFormat::Csv.as_str(), "csv");
        assert_eq!(OutputFormat::Tsv.as_str(), "tsv");
        assert_eq!(OutputFormat::Markdown.as_str(), "markdown");
    }

    #[test]
    fn format_is_tabular() {
        assert!(!OutputFormat::Json.is_tabular());
        assert!(!OutputFormat::Jsonl.is_tabular());
        assert!(!OutputFormat::Ndjson.is_tabular());
        assert!(!OutputFormat::Toon.is_tabular());
        assert!(OutputFormat::Table.is_tabular());
        assert!(OutputFormat::Csv.is_tabular());
        assert!(OutputFormat::Tsv.is_tabular());
        assert!(OutputFormat::Markdown.is_tabular());
    }

    #[test]
    fn format_is_json_like() {
        assert!(OutputFormat::Json.is_json_like());
        assert!(OutputFormat::Jsonl.is_json_like());
        assert!(OutputFormat::Ndjson.is_json_like());
        assert!(!OutputFormat::Toon.is_json_like());
        assert!(!OutputFormat::Table.is_json_like());
        assert!(!OutputFormat::Csv.is_json_like());
        assert!(!OutputFormat::Tsv.is_json_like());
        assert!(!OutputFormat::Markdown.is_json_like());
    }

    // ── RenderOptions tests ───────────────────────────────────────

    #[test]
    fn render_options_default() {
        let opts = RenderOptions::default();
        assert!(!opts.has_template());
        assert!(!opts.has_extract());
        assert!(!opts.has_transform());
        assert!(opts.tabular_columns.is_empty());
        assert!(opts.tabular_sort_by.is_none());
        assert_eq!(opts.tabular_limit, 0);
        assert!(!opts.tabular_no_headers);
    }

    #[test]
    fn render_options_has_template() {
        let opts = RenderOptions {
            template: Some(TemplateRender::inline("{{status}}").unwrap()),
            ..RenderOptions::default()
        };
        assert!(opts.has_template());
        assert!(opts.has_transform());
    }

    #[test]
    fn render_options_has_extract() {
        let opts = RenderOptions {
            extract: Some(ExtractRender::inline(".status").unwrap()),
            ..RenderOptions::default()
        };
        assert!(opts.has_extract());
        assert!(opts.has_transform());
    }

    #[test]
    fn render_options_without_extract() {
        let opts = RenderOptions {
            template: Some(TemplateRender::inline("{{status}}").unwrap()),
            extract: Some(ExtractRender::inline(".status").unwrap()),
            tabular_columns: vec!["a".to_owned()],
            tabular_sort_by: Some("b".to_owned()),
            tabular_limit: 10,
            tabular_no_headers: true,
        };
        let without = opts.without_extract();
        assert!(without.template.is_some());
        assert!(without.extract.is_none());
        assert_eq!(without.tabular_columns, vec!["a".to_owned()]);
        assert_eq!(without.tabular_sort_by, Some("b".to_owned()));
        assert_eq!(without.tabular_limit, 10);
        assert!(without.tabular_no_headers);
    }

    #[test]
    fn render_options_transform_metadata_template() {
        let opts = RenderOptions {
            template: Some(TemplateRender::inline("{{status}}").unwrap()),
            ..RenderOptions::default()
        };
        let meta = opts.transform_metadata().unwrap();
        assert_eq!(meta["kind"], "handlebars");
    }

    #[test]
    fn render_options_transform_metadata_extract() {
        let opts = RenderOptions {
            extract: Some(ExtractRender::inline(".status").unwrap()),
            ..RenderOptions::default()
        };
        let meta = opts.transform_metadata().unwrap();
        assert_eq!(meta["kind"], "jq");
        assert_eq!(meta["engine"], "jaq");
    }

    #[test]
    fn render_options_transform_metadata_none() {
        let opts = RenderOptions::default();
        assert!(opts.transform_metadata().is_none());
    }

    // ── TemplateSource tests ──────────────────────────────────────

    #[test]
    fn template_source_as_str() {
        assert_eq!(TemplateSource::Inline.as_str(), "inline");
        assert_eq!(TemplateSource::File.as_str(), "file");
    }

    #[test]
    fn template_source_serde() {
        let json = serde_json::to_string(&TemplateSource::Inline).unwrap();
        assert_eq!(json, "\"inline\"");
        let json = serde_json::to_string(&TemplateSource::File).unwrap();
        assert_eq!(json, "\"file\"");
    }

    // ── Additional extract tests ──────────────────────────────────

    #[test]
    fn extract_render_supports_keys() {
        let extract = ExtractRender::inline(".data | keys").unwrap();
        let text = render_with_options(
            json!({"data": {"alpha": 1, "beta": 2}}),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(text.trim()).unwrap();
        assert!(parsed.as_array().unwrap().contains(&json!("alpha")));
        assert!(parsed.as_array().unwrap().contains(&json!("beta")));
    }

    #[test]
    fn extract_render_supports_map() {
        let extract = ExtractRender::inline("[.items[] | . * 2]").unwrap();
        let text = render_with_options(
            json!({"items": [1, 2, 3]}),
            OutputFormat::Json,
            &RenderOptions {
                extract: Some(extract),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed, json!([2, 4, 6]));
    }

    #[test]
    fn extract_metadata_captures_filter() {
        let extract = ExtractRender::inline(".foo").unwrap();
        let meta = extract.metadata();
        assert_eq!(meta["kind"], "jq");
        assert_eq!(meta["engine"], "jaq");
        assert_eq!(meta["filter"], ".foo");
    }

    // ── Additional NDJSON rendering ───────────────────────────────

    #[test]
    fn ndjson_wrapper_results_field() {
        let data = json!({
            "count": 2,
            "results": [{"id": 1}, {"id": 2}]
        });
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn ndjson_wrapper_data_field() {
        let data = json!({
            "meta": {},
            "data": [{"x": 1}]
        });
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn ndjson_wrapper_operations_field() {
        let data = json!({
            "operations": [{"id": "op1"}, {"id": "op2"}, {"id": "op3"}]
        });
        let text = render(data, OutputFormat::Ndjson).unwrap();
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn ndjson_wrapper_no_recognized_array_field() {
        let data = json!({
            "custom_field": [1, 2, 3]
        });
        let text = render(data, OutputFormat::Ndjson).unwrap();
        // Falls back to emitting the whole object as one line
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn ndjson_null_value() {
        let text = render(json!(null), OutputFormat::Ndjson).unwrap();
        assert_eq!(text.trim(), "null");
    }

    #[test]
    fn ndjson_number_value() {
        let text = render(json!(42), OutputFormat::Ndjson).unwrap();
        assert_eq!(text.trim(), "42");
    }

    // ── relative_time_label tests ─────────────────────────────────

    #[test]
    fn relative_time_label_just_now() {
        let now = Utc::now();
        let label = relative_time_label(now, now);
        assert_eq!(label, "just now");
    }

    #[test]
    fn relative_time_label_seconds_ago() {
        let now = Utc::now();
        let label = relative_time_label(now - Duration::seconds(30), now);
        assert_eq!(label, "30s ago");
    }

    #[test]
    fn relative_time_label_minutes_ago() {
        let now = Utc::now();
        let label = relative_time_label(now - Duration::minutes(5), now);
        assert_eq!(label, "5m ago");
    }

    #[test]
    fn relative_time_label_hours_ago() {
        let now = Utc::now();
        let label = relative_time_label(now - Duration::hours(3), now);
        assert_eq!(label, "3h ago");
    }

    #[test]
    fn relative_time_label_days_ago() {
        let now = Utc::now();
        let label = relative_time_label(now - Duration::days(2), now);
        assert_eq!(label, "2d ago");
    }

    #[test]
    fn relative_time_label_weeks_ago() {
        let now = Utc::now();
        let label = relative_time_label(now - Duration::weeks(3), now);
        assert_eq!(label, "3w ago");
    }

    #[test]
    fn relative_time_label_future_seconds() {
        let now = Utc::now();
        let label = relative_time_label(now + Duration::seconds(45), now);
        assert_eq!(label, "in 45s");
    }

    #[test]
    fn relative_time_label_future_days() {
        let now = Utc::now();
        let label = relative_time_label(now + Duration::days(7), now);
        assert_eq!(label, "in 1w");
    }

    // ── TokenStats additional tests ───────────────────────────────

    #[test]
    fn token_stats_serializes() {
        let v = json!({"key": "value"});
        let stats = token_stats(&v, OutputFormat::Toon);
        let json = serde_json::to_value(&stats).unwrap();
        assert!(json.get("selected_format").is_some());
        assert!(json.get("toon_bytes").is_some());
        assert!(json.get("json_bytes").is_some());
        assert!(json.get("savings_pct").is_some());
    }

    #[test]
    fn token_stats_null_value() {
        let stats = token_stats(&json!(null), OutputFormat::Json);
        assert!(stats.json_bytes > 0);
        assert_eq!(stats.selected_format, "json");
    }

    #[test]
    fn token_stats_string_value() {
        let stats = token_stats(&json!("hello world"), OutputFormat::Jsonl);
        assert!(stats.jsonl_bytes > 0);
        assert_eq!(stats.selected_format, "jsonl");
    }

    // ── Template with helpers ─────────────────────────────────────

    #[test]
    fn template_render_simple_interpolation() {
        let template = TemplateRender::inline("Hello {{name}}!").unwrap();
        let text = render_with_options(
            json!({"name": "World"}),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        assert_eq!(text, "Hello World!\n");
    }

    #[test]
    fn template_render_each_helper() {
        let template = TemplateRender::inline("{{#each items}}{{this}}\n{{/each}}").unwrap();
        let text = render_with_options(
            json!({"items": ["a", "b", "c"]}),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        assert!(text.contains('a'));
        assert!(text.contains('b'));
        assert!(text.contains('c'));
    }

    #[test]
    fn template_render_if_helper() {
        let template = TemplateRender::inline("{{#if active}}ON{{else}}OFF{{/if}}").unwrap();
        let text_on = render_with_options(
            json!({"active": true}),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template.clone()),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        assert_eq!(text_on.trim(), "ON");

        let text_off = render_with_options(
            json!({"active": false}),
            OutputFormat::Json,
            &RenderOptions {
                template: Some(template),
                ..RenderOptions::default()
            },
        )
        .unwrap();
        assert_eq!(text_off.trim(), "OFF");
    }

    // ── Edge case renders ─────────────────────────────────────────

    #[test]
    fn render_deeply_nested_json() {
        let v = json!({"a": {"b": {"c": {"d": {"e": "deep"}}}}});
        let text = render(v.clone(), OutputFormat::Json).unwrap();
        let parsed: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn render_array_of_scalars() {
        let v = json!([1, "two", true, null]);
        let text = render(v.clone(), OutputFormat::Json).unwrap();
        let parsed: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn render_empty_string() {
        let text = render(json!(""), OutputFormat::Json).unwrap();
        assert_eq!(text.trim(), "\"\"");
    }

    #[test]
    fn render_empty_array() {
        let text = render(json!([]), OutputFormat::Json).unwrap();
        assert_eq!(text.trim(), "[]");
    }

    #[test]
    fn render_special_chars_in_strings() {
        let v = json!({"msg": "line1\nline2\ttab"});
        let text = render(v.clone(), OutputFormat::Json).unwrap();
        let parsed: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn render_negative_and_float_numbers() {
        let v = json!({"neg": -42, "pi": 1.23});
        let text = render(v.clone(), OutputFormat::Jsonl).unwrap();
        let parsed: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed, v);
    }

    // ── Format equality and debug ─────────────────────────────────

    #[test]
    fn format_debug_impl() {
        let debug = format!("{:?}", OutputFormat::Json);
        assert!(debug.contains("Json"));
    }

    #[test]
    fn format_clone_and_copy() {
        let original = OutputFormat::Csv;
        let copied = original;
        assert_eq!(original, copied);
    }
}
