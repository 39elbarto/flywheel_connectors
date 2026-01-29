//! Safe formatting helpers with fallback to plaintext.
//!
//! These helpers are intentionally conservative: when formatting cannot be
//! validated confidently, they fall back to plaintext to avoid message loss.

/// Supported formatting modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatMode {
    /// Plaintext (no formatting).
    Plain,
    /// HTML formatting.
    Html,
    /// `MarkdownV2` formatting (Telegram-style).
    MarkdownV2,
}

impl FormatMode {
    /// Returns the connector parse mode string, if any.
    #[must_use]
    pub const fn as_parse_mode(self) -> Option<&'static str> {
        match self {
            Self::Plain => None,
            Self::Html => Some("HTML"),
            Self::MarkdownV2 => Some("MarkdownV2"),
        }
    }
}

/// Result of rendering with fallback handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderResult {
    /// The rendered output (formatted or plaintext fallback).
    pub rendered: String,
    /// The parse mode to use, if any. `None` indicates plaintext.
    pub parse_mode_used: Option<FormatMode>,
}

/// Formatting validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// HTML markup failed basic validation.
    InvalidHtml,
    /// Markdown markup failed basic validation.
    InvalidMarkdown,
    /// Disallowed control characters were present.
    ControlChars,
}

/// Safe formatter with fallback behavior.
pub struct Formatter;

impl Formatter {
    /// Render input with the requested mode, falling back to plaintext on errors.
    #[must_use]
    pub fn render_with_fallback(input: &str, mode: FormatMode) -> RenderResult {
        Self::render(input, mode).map_or_else(
            |_| RenderResult {
                rendered: fallback_plaintext(input, mode),
                parse_mode_used: None,
            },
            |rendered| RenderResult {
                rendered,
                parse_mode_used: match mode {
                    FormatMode::Plain => None,
                    _ => Some(mode),
                },
            },
        )
    }

    fn render(input: &str, mode: FormatMode) -> Result<String, FormatError> {
        match mode {
            FormatMode::Plain => Ok(escape_control_chars(input)),
            FormatMode::Html => {
                validate_html(input)?;
                Ok(input.to_string())
            }
            FormatMode::MarkdownV2 => {
                validate_markdown(input)?;
                Ok(input.to_string())
            }
        }
    }
}

fn validate_html(input: &str) -> Result<(), FormatError> {
    if contains_disallowed_control(input) {
        return Err(FormatError::ControlChars);
    }

    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '<' => {
                let mut found = false;
                loop {
                    match chars.next() {
                        Some('>') => {
                            found = true;
                            break;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                if !found {
                    return Err(FormatError::InvalidHtml);
                }
            }
            '&' => {
                let mut entity = String::new();
                let mut found = false;
                loop {
                    match chars.next() {
                        Some(';') => {
                            found = true;
                            break;
                        }
                        Some(next) => {
                            if entity.len() > 10 {
                                return Err(FormatError::InvalidHtml);
                            }
                            entity.push(next);
                        }
                        None => break,
                    }
                }
                if !found || !is_valid_entity(&entity) {
                    return Err(FormatError::InvalidHtml);
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_markdown(input: &str) -> Result<(), FormatError> {
    if contains_disallowed_control(input) {
        return Err(FormatError::ControlChars);
    }

    let mut escape = false;
    for ch in input.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
        }
    }

    if escape {
        return Err(FormatError::InvalidMarkdown);
    }

    Ok(())
}

fn contains_disallowed_control(input: &str) -> bool {
    input
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
}

fn fallback_plaintext(input: &str, mode: FormatMode) -> String {
    let stripped = match mode {
        FormatMode::Plain => input.to_string(),
        FormatMode::Html => strip_html(input),
        FormatMode::MarkdownV2 => strip_markdown(input),
    };

    escape_control_chars(&stripped)
}

fn strip_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if in_tag {
            if ch == '>' {
                in_tag = false;
            }
            continue;
        }

        match ch {
            '<' => {
                in_tag = true;
            }
            '&' => {
                let mut entity = String::new();
                let mut found = false;
                loop {
                    match chars.next() {
                        Some(';') => {
                            found = true;
                            break;
                        }
                        Some(next) => {
                            if entity.len() > 10 {
                                break;
                            }
                            entity.push(next);
                        }
                        None => break,
                    }
                }

                if found {
                    if let Some(decoded) = decode_entity(&entity) {
                        out.push(decoded);
                    } else {
                        out.push('&');
                        out.push_str(&entity);
                        out.push(';');
                    }
                } else {
                    out.push('&');
                    out.push_str(&entity);
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn strip_markdown(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut escape = false;

    for ch in input.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }

        if ch == '\\' {
            escape = true;
            continue;
        }

        if is_markdown_control(ch) {
            continue;
        }

        out.push(ch);
    }

    out
}

const fn is_markdown_control(ch: char) -> bool {
    matches!(
        ch,
        '*' | '_'
            | '`'
            | '~'
            | '['
            | ']'
            | '('
            | ')'
            | '>'
            | '#'
            | '+'
            | '-'
            | '='
            | '|'
            | '{'
            | '}'
            | '.'
            | '!'
    )
}

fn escape_control_chars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_valid_entity(entity: &str) -> bool {
    matches!(entity, "amp" | "lt" | "gt" | "quot" | "apos") || is_numeric_entity(entity)
}

fn is_numeric_entity(entity: &str) -> bool {
    if let Some(rest) = entity.strip_prefix("#x") {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    if let Some(rest) = entity.strip_prefix('#') {
        return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit());
    }
    false
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => decode_numeric_entity(entity),
    }
}

fn decode_numeric_entity(entity: &str) -> Option<char> {
    if let Some(rest) = entity.strip_prefix("#x") {
        let value = u32::from_str_radix(rest, 16).ok()?;
        return char::from_u32(value);
    }
    if let Some(rest) = entity.strip_prefix('#') {
        let value = rest.parse::<u32>().ok()?;
        return char::from_u32(value);
    }
    None
}
