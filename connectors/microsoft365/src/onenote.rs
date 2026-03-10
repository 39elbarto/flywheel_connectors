//! OneNote-specific request models and content helpers.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};

const MAX_LIST_TOP: u32 = 100;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListNotebooksInput {
    pub user_id: String,
    #[serde(default)]
    pub top: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSectionsInput {
    pub user_id: String,
    #[serde(default)]
    pub notebook_id: Option<String>,
    #[serde(default)]
    pub section_group_id: Option<String>,
    #[serde(default)]
    pub top: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPagesInput {
    pub user_id: String,
    pub section_id: String,
    #[serde(default)]
    pub top: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetPageInput {
    pub user_id: String,
    pub page_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetPageContentInput {
    pub user_id: String,
    pub page_id: String,
    #[serde(default)]
    pub include_ids: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePageInput {
    pub user_id: String,
    pub section_id: String,
    pub html: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageContentCommand {
    pub target: String,
    pub action: String,
    #[serde(default)]
    pub position: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePageInput {
    pub user_id: String,
    pub page_id: String,
    pub commands: Vec<PageContentCommand>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OneNotePageContent {
    pub html: String,
    pub plain_text: String,
}

impl ListNotebooksInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.list_notebooks")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_top(parsed.top)?;
        Ok(parsed)
    }
}

impl ListSectionsInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.list_sections")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_optional_non_empty(parsed.notebook_id.as_deref(), "notebook_id")?;
        validate_optional_non_empty(parsed.section_group_id.as_deref(), "section_group_id")?;
        validate_top(parsed.top)?;
        Ok(parsed)
    }
}

impl ListPagesInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.list_pages")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.section_id, "section_id")?;
        validate_top(parsed.top)?;
        Ok(parsed)
    }
}

impl GetPageInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.get_page")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.page_id, "page_id")?;
        Ok(parsed)
    }
}

impl GetPageContentInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.get_page_content")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.page_id, "page_id")?;
        Ok(parsed)
    }
}

impl CreatePageInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.create_page")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.section_id, "section_id")?;
        validate_non_empty(&parsed.html, "html")?;
        Ok(parsed)
    }
}

impl UpdatePageInput {
    pub fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.onenote.update_page")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.page_id, "page_id")?;
        if parsed.commands.is_empty() {
            return Err(invalid_request(
                "commands must contain at least one OneNote content change",
            ));
        }
        for command in &parsed.commands {
            command.validate()?;
        }
        Ok(parsed)
    }
}

impl PageContentCommand {
    fn validate(&self) -> FcpResult<()> {
        validate_non_empty(&self.target, "commands[].target")?;
        validate_non_empty(&self.action, "commands[].action")?;
        if let Some(position) = self.position.as_deref() {
            validate_non_empty(position, "commands[].position")?;
        }
        Ok(())
    }
}

impl OneNotePageContent {
    #[must_use]
    pub fn from_html(html: String) -> Self {
        let plain_text = html_to_plain_text(&html);
        Self { html, plain_text }
    }
}

fn parse_input<T>(value: serde_json::Value, operation: &str) -> FcpResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {operation} input: {error}"),
    })
}

fn validate_non_empty(value: &str, field: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(invalid_request(&format!("{field} must not be empty")));
    }
    Ok(())
}

fn validate_optional_non_empty(value: Option<&str>, field: &str) -> FcpResult<()> {
    if let Some(value) = value {
        validate_non_empty(value, field)?;
    }
    Ok(())
}

fn validate_top(top: Option<u32>) -> FcpResult<()> {
    if let Some(top) = top
        && !(1..=MAX_LIST_TOP).contains(&top)
    {
        return Err(invalid_request(&format!(
            "top must be between 1 and {MAX_LIST_TOP}"
        )));
    }
    Ok(())
}

fn invalid_request(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.to_string(),
    }
}

#[must_use]
pub fn html_to_plain_text(html: &str) -> String {
    let mut stripped = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag_name = String::new();

    for ch in html.chars() {
        if in_tag {
            if ch == '>' {
                if should_insert_break(&tag_name) {
                    push_break(&mut stripped);
                }
                in_tag = false;
                tag_name.clear();
            } else {
                tag_name.push(ch);
            }
            continue;
        }

        if ch == '<' {
            in_tag = true;
            tag_name.clear();
            continue;
        }

        stripped.push(ch);
    }

    normalize_plain_text(&decode_html_entities(&stripped))
}

fn should_insert_break(raw_tag: &str) -> bool {
    let normalized = raw_tag
        .trim_start_matches('/')
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    matches!(
        normalized.as_str(),
        "br" | "div"
            | "p"
            | "li"
            | "tr"
            | "table"
            | "section"
            | "article"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
    )
}

fn push_break(target: &mut String) {
    if target.ends_with('\n') || target.is_empty() {
        return;
    }
    target.push('\n');
}

fn decode_html_entities(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' {
            output.push(ch);
            continue;
        }

        let mut entity = String::new();
        while let Some(next) = chars.peek().copied() {
            if next == ';' || entity.len() >= 16 {
                break;
            }
            entity.push(next);
            chars.next();
        }

        if chars.peek() == Some(&';') {
            chars.next();
        } else {
            output.push('&');
            output.push_str(&entity);
            continue;
        }

        if let Some(decoded) = decode_entity(&entity) {
            output.push(decoded);
        } else {
            output.push('&');
            output.push_str(&entity);
            output.push(';');
        }
    }

    output
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" | "#39" => Some('\''),
        "nbsp" => Some(' '),
        _ if entity.starts_with("#x") || entity.starts_with("#X") => {
            u32::from_str_radix(&entity[2..], 16)
                .ok()
                .and_then(char::from_u32)
        }
        _ if entity.starts_with('#') => entity[1..].parse::<u32>().ok().and_then(char::from_u32),
        _ => None,
    }
}

fn normalize_plain_text(input: &str) -> String {
    let mut normalized = String::new();
    let mut prev_was_space = false;
    let mut prev_was_newline = false;

    for ch in input.chars() {
        if ch == '\r' {
            continue;
        }

        if ch == '\n' {
            while normalized.ends_with(' ') {
                normalized.pop();
            }
            if !prev_was_newline && !normalized.is_empty() {
                normalized.push('\n');
            }
            prev_was_newline = true;
            prev_was_space = false;
            continue;
        }

        if ch.is_whitespace() {
            if normalized.is_empty() || prev_was_space || prev_was_newline {
                continue;
            }
            normalized.push(' ');
            prev_was_space = true;
            continue;
        }

        normalized.push(ch);
        prev_was_space = false;
        prev_was_newline = false;
    }

    normalized.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_page_input_rejects_empty_html() {
        let result = CreatePageInput::parse(json!({
            "user_id": "me",
            "section_id": "section-123",
            "html": "   "
        }));
        assert!(result.is_err());
    }

    #[test]
    fn update_page_input_rejects_empty_commands() {
        let result = UpdatePageInput::parse(json!({
            "user_id": "me",
            "page_id": "page-123",
            "commands": []
        }));
        assert!(result.is_err());
    }

    #[test]
    fn html_to_plain_text_extracts_readable_text() {
        let html = "<html><body><h1>Release &amp; QA</h1><p>Status: <b>green</b></p><div>Ship&nbsp;today</div></body></html>";
        let text = html_to_plain_text(html);
        assert_eq!(text, "Release & QA\nStatus: green\nShip today");
    }

    #[test]
    fn page_content_from_html_includes_plain_text() {
        let content = OneNotePageContent::from_html("<p>Hello<br>World</p>".to_string());
        assert_eq!(content.plain_text, "Hello\nWorld");
        assert_eq!(content.html, "<p>Hello<br>World</p>");
    }

    #[test]
    fn list_top_rejects_values_over_graph_limit() {
        let result = ListPagesInput::parse(json!({
            "user_id": "me",
            "section_id": "section-123",
            "top": 101
        }));
        assert!(result.is_err());
    }
}
