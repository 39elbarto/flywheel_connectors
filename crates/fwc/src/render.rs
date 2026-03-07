use anyhow::Result;
use clap::ValueEnum;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Jsonl,
    #[default]
    Toon,
}

pub fn render(value: Value, format: OutputFormat) -> Result<String> {
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&value)?,
        OutputFormat::Jsonl => serde_json::to_string(&value)?,
        OutputFormat::Toon => toon::encode(value, None),
    };

    Ok(format!("{rendered}\n"))
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, render};

    #[test]
    fn json_render_starts_like_json() {
        let text = render(serde_json::json!({ "status": "ok" }), OutputFormat::Json).unwrap();
        assert!(text.trim_start().starts_with('{'));
    }

    #[test]
    fn jsonl_render_is_single_line_json() {
        let text = render(serde_json::json!({ "status": "ok" }), OutputFormat::Jsonl).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.trim_end().starts_with('{'));
    }

    #[test]
    fn toon_render_is_not_json_shaped() {
        let text = render(serde_json::json!({ "status": "ok" }), OutputFormat::Toon).unwrap();
        assert!(text.contains("status"));
        assert!(!text.trim_start().starts_with('{'));
    }
}
