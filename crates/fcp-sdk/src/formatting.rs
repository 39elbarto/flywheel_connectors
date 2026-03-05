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

    /// Force plaintext fallback for a given mode, stripping markup where possible.
    #[must_use]
    pub fn render_plaintext_fallback(input: &str, mode: FormatMode) -> RenderResult {
        RenderResult {
            rendered: fallback_plaintext(input, mode),
            parse_mode_used: None,
        }
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

/// High-level classification for external service errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Message formatting or parsing failed (safe to fallback to plaintext).
    ParseError,
    /// Rate limit exceeded; retry should be delayed.
    RateLimit,
    /// Transient failure (timeouts, network issues).
    Transient,
    /// Non-retryable failure.
    Terminal,
}

/// Classify a free-form error message into a high-level category.
#[must_use]
pub fn classify_error_message(message: &str) -> ErrorClass {
    let lower = message.to_lowercase();

    if is_parse_error_message(&lower) {
        return ErrorClass::ParseError;
    }

    if lower.contains("rate limit")
        || lower.contains("rate-limit")
        || lower.contains("too many requests")
        || lower.contains("retry after")
        || lower.contains("http 429")
    {
        return ErrorClass::RateLimit;
    }

    if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("temporarily")
        || lower.contains("temporary")
        || lower.contains("unavailable")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("network error")
        || lower.contains("http 502")
        || lower.contains("http 503")
        || lower.contains("http 504")
    {
        return ErrorClass::Transient;
    }

    ErrorClass::Terminal
}

/// Returns true if a message indicates a formatting/markup parse failure.
#[must_use]
pub fn is_parse_error_message(message: &str) -> bool {
    let lower = message.to_lowercase();
    is_parse_error_message_lower(&lower)
}

fn is_parse_error_message_lower(lower: &str) -> bool {
    lower.contains("can't parse entities")
        || lower.contains("parse entities")
        || lower.contains("find end of the entity")
        || (lower.contains("markdown") && lower.contains("parse"))
        || lower.contains("invalid markdown")
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
        if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_control_chars() {
        assert_eq!(escape_control_chars("Hello\nWorld"), "Hello\nWorld");
        assert_eq!(escape_control_chars("Hello\r\nWorld"), "Hello\r\nWorld");
        assert_eq!(escape_control_chars("Hello\tWorld"), "Hello\tWorld");
        assert_eq!(escape_control_chars("Hello\x00World"), "Hello\\u{0}World");
        assert_eq!(escape_control_chars("Hello\x1bWorld"), "Hello\\u{1b}World");
    }

    // ---- FormatMode ----

    #[test]
    fn format_mode_as_parse_mode() {
        assert_eq!(FormatMode::Plain.as_parse_mode(), None);
        assert_eq!(FormatMode::Html.as_parse_mode(), Some("HTML"));
        assert_eq!(FormatMode::MarkdownV2.as_parse_mode(), Some("MarkdownV2"));
    }

    #[test]
    fn format_mode_eq() {
        assert_eq!(FormatMode::Plain, FormatMode::Plain);
        assert_ne!(FormatMode::Plain, FormatMode::Html);
        assert_ne!(FormatMode::Html, FormatMode::MarkdownV2);
    }

    // ---- validate_html ----

    #[test]
    fn validate_html_valid_tags() {
        assert!(validate_html("<b>bold</b>").is_ok());
        assert!(validate_html("<i>italic</i>").is_ok());
        assert!(validate_html("no tags at all").is_ok());
    }

    #[test]
    fn validate_html_unclosed_tag() {
        // A truly unclosed tag: `<b` without closing `>`
        assert!(matches!(
            validate_html("hello <b"),
            Err(FormatError::InvalidHtml)
        ));
    }

    #[test]
    fn validate_html_valid_named_entities() {
        assert!(validate_html("&amp; &lt; &gt; &quot; &apos;").is_ok());
    }

    #[test]
    fn validate_html_valid_numeric_entities() {
        assert!(validate_html("&#65;").is_ok()); // 'A'
        assert!(validate_html("&#x41;").is_ok()); // 'A' hex
    }

    #[test]
    fn validate_html_invalid_entity_no_semicolon() {
        assert!(matches!(
            validate_html("&amp no semicolon"),
            Err(FormatError::InvalidHtml)
        ));
    }

    #[test]
    fn validate_html_invalid_entity_name() {
        assert!(matches!(
            validate_html("&bogus;"),
            Err(FormatError::InvalidHtml)
        ));
    }

    #[test]
    fn validate_html_entity_too_long() {
        assert!(matches!(
            validate_html("&verylonginvalidname;"),
            Err(FormatError::InvalidHtml)
        ));
    }

    #[test]
    fn validate_html_control_chars_rejected() {
        assert!(matches!(
            validate_html("hello\x00world"),
            Err(FormatError::ControlChars)
        ));
    }

    // ---- validate_markdown ----

    #[test]
    fn validate_markdown_valid() {
        assert!(validate_markdown("hello world").is_ok());
        assert!(validate_markdown("escaped \\* star").is_ok());
        assert!(validate_markdown("multiple \\_ \\~ escapes").is_ok());
    }

    #[test]
    fn validate_markdown_trailing_backslash() {
        assert!(matches!(
            validate_markdown("trailing \\"),
            Err(FormatError::InvalidMarkdown)
        ));
    }

    #[test]
    fn validate_markdown_control_chars_rejected() {
        assert!(matches!(
            validate_markdown("hello\x01world"),
            Err(FormatError::ControlChars)
        ));
    }

    // ---- Formatter::render_with_fallback ----

    #[test]
    fn render_plain_passthrough() {
        let result = Formatter::render_with_fallback("hello", FormatMode::Plain);
        assert_eq!(result.rendered, "hello");
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_plain_escapes_control() {
        let result = Formatter::render_with_fallback("hi\x00there", FormatMode::Plain);
        assert!(result.rendered.contains("\\u{0}"));
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_html_valid() {
        let result = Formatter::render_with_fallback("<b>bold</b>", FormatMode::Html);
        assert_eq!(result.rendered, "<b>bold</b>");
        assert_eq!(result.parse_mode_used, Some(FormatMode::Html));
    }

    #[test]
    fn render_html_invalid_falls_back() {
        // Truly invalid: `<b` without closing `>`
        let result = Formatter::render_with_fallback("hello <b", FormatMode::Html);
        // Should fall back to plaintext with HTML stripped
        assert!(!result.rendered.contains("<b"));
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_markdown_valid() {
        let result = Formatter::render_with_fallback("hello \\*world\\*", FormatMode::MarkdownV2);
        assert_eq!(result.rendered, "hello \\*world\\*");
        assert_eq!(result.parse_mode_used, Some(FormatMode::MarkdownV2));
    }

    #[test]
    fn render_markdown_invalid_falls_back() {
        let result = Formatter::render_with_fallback("trailing \\", FormatMode::MarkdownV2);
        // Should fall back to plaintext with markdown stripped
        assert!(result.parse_mode_used.is_none());
    }

    // ---- Formatter::render_plaintext_fallback ----

    #[test]
    fn render_plaintext_fallback_plain() {
        let result = Formatter::render_plaintext_fallback("hello", FormatMode::Plain);
        assert_eq!(result.rendered, "hello");
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_plaintext_fallback_html() {
        let result = Formatter::render_plaintext_fallback("<b>bold</b>", FormatMode::Html);
        assert_eq!(result.rendered, "bold");
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_plaintext_fallback_markdown() {
        let result = Formatter::render_plaintext_fallback("hello *world*", FormatMode::MarkdownV2);
        assert!(!result.rendered.contains('*'));
        assert!(result.parse_mode_used.is_none());
    }

    // ---- strip_html ----

    #[test]
    fn strip_html_removes_tags() {
        assert_eq!(strip_html("<b>bold</b>"), "bold");
        assert_eq!(strip_html("<i>italic</i> text"), "italic text");
        assert_eq!(strip_html("no tags"), "no tags");
    }

    #[test]
    fn strip_html_decodes_named_entities() {
        assert_eq!(strip_html("&amp;"), "&");
        assert_eq!(strip_html("&lt;"), "<");
        assert_eq!(strip_html("&gt;"), ">");
        assert_eq!(strip_html("&quot;"), "\"");
        assert_eq!(strip_html("&apos;"), "'");
    }

    #[test]
    fn strip_html_decodes_numeric_entities() {
        assert_eq!(strip_html("&#65;"), "A");
        assert_eq!(strip_html("&#x41;"), "A");
    }

    #[test]
    fn strip_html_unknown_entity_preserved() {
        // Unknown named entity is preserved literally
        let result = strip_html("&bogus;");
        assert_eq!(result, "&bogus;");
    }

    #[test]
    fn strip_html_unclosed_entity() {
        // When there's no `;`, strip_html consumes chars into the entity buffer
        // up to the 10-char limit, then outputs `&` + buffer contents.
        // "amp no sem" is 10 chars, then "icolon" remains as regular text.
        let result = strip_html("&amp no semicolon");
        assert!(result.starts_with("&amp no sem"));
    }

    // ---- strip_markdown ----

    #[test]
    fn strip_markdown_removes_controls() {
        assert_eq!(strip_markdown("*bold*"), "bold");
        assert_eq!(strip_markdown("_italic_"), "italic");
        assert_eq!(strip_markdown("`code`"), "code");
        assert_eq!(strip_markdown("~strike~"), "strike");
    }

    #[test]
    fn strip_markdown_preserves_escaped() {
        assert_eq!(strip_markdown("\\*literal\\*"), "*literal*");
        assert_eq!(strip_markdown("\\_underscore\\_"), "_underscore_");
    }

    #[test]
    fn strip_markdown_removes_all_control_chars() {
        // All markdown control chars should be removed
        let controls = "*_`~[]()>#+-=|{}.!";
        assert_eq!(strip_markdown(controls), "");
    }

    // ---- is_markdown_control ----

    #[test]
    fn is_markdown_control_positive() {
        for ch in "*_`~[]()>#+-=|{}.!".chars() {
            assert!(is_markdown_control(ch), "expected {ch:?} to be control");
        }
    }

    #[test]
    fn is_markdown_control_negative() {
        for ch in "abcABC123 \n\t".chars() {
            assert!(
                !is_markdown_control(ch),
                "expected {ch:?} not to be control"
            );
        }
    }

    // ---- classify_error_message ----

    #[test]
    fn classify_parse_errors() {
        assert_eq!(
            classify_error_message("Can't parse entities"),
            ErrorClass::ParseError
        );
        assert_eq!(
            classify_error_message("can't find end of the entity"),
            ErrorClass::ParseError
        );
        assert_eq!(
            classify_error_message("invalid markdown in text"),
            ErrorClass::ParseError
        );
        assert_eq!(
            classify_error_message("Markdown parse failed"),
            ErrorClass::ParseError
        );
    }

    #[test]
    fn classify_rate_limits() {
        assert_eq!(
            classify_error_message("Rate limit exceeded"),
            ErrorClass::RateLimit
        );
        assert_eq!(
            classify_error_message("rate-limit reached"),
            ErrorClass::RateLimit
        );
        assert_eq!(
            classify_error_message("Too many requests"),
            ErrorClass::RateLimit
        );
        assert_eq!(
            classify_error_message("retry after 30s"),
            ErrorClass::RateLimit
        );
        assert_eq!(
            classify_error_message("HTTP 429 error"),
            ErrorClass::RateLimit
        );
    }

    #[test]
    fn classify_transient() {
        assert_eq!(
            classify_error_message("Connection timeout"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("request timed out"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("temporarily unavailable"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("service unavailable"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("connection reset by peer"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("connection refused"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("network error occurred"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("HTTP 502 Bad Gateway"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("HTTP 503 Service Unavailable"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("HTTP 504 Gateway Timeout"),
            ErrorClass::Transient
        );
        assert_eq!(
            classify_error_message("temporary failure"),
            ErrorClass::Transient
        );
    }

    #[test]
    fn classify_terminal() {
        assert_eq!(classify_error_message("not found"), ErrorClass::Terminal);
        assert_eq!(
            classify_error_message("access denied"),
            ErrorClass::Terminal
        );
        assert_eq!(
            classify_error_message("invalid API key"),
            ErrorClass::Terminal
        );
    }

    #[test]
    fn classify_case_insensitive() {
        assert_eq!(
            classify_error_message("RATE LIMIT EXCEEDED"),
            ErrorClass::RateLimit
        );
        assert_eq!(
            classify_error_message("CONNECTION TIMEOUT"),
            ErrorClass::Transient
        );
    }

    // ---- is_parse_error_message ----

    #[test]
    fn is_parse_error_positive() {
        assert!(is_parse_error_message("Can't parse entities in text"));
        assert!(is_parse_error_message("can't find end of the entity"));
        assert!(is_parse_error_message("invalid markdown formatting"));
    }

    #[test]
    fn is_parse_error_negative() {
        assert!(!is_parse_error_message("rate limit exceeded"));
        assert!(!is_parse_error_message("unknown error"));
    }

    // ---- contains_disallowed_control ----

    #[test]
    fn disallowed_control_chars() {
        assert!(contains_disallowed_control("hello\x00world"));
        assert!(contains_disallowed_control("bell\x07here"));
        assert!(contains_disallowed_control("escape\x1b[0m"));
    }

    #[test]
    fn allowed_control_chars() {
        assert!(!contains_disallowed_control("hello\nworld"));
        assert!(!contains_disallowed_control("hello\r\nworld"));
        assert!(!contains_disallowed_control("hello\tworld"));
        assert!(!contains_disallowed_control("no controls"));
    }

    // ---- entity helpers ----

    #[test]
    fn is_valid_entity_named() {
        assert!(is_valid_entity("amp"));
        assert!(is_valid_entity("lt"));
        assert!(is_valid_entity("gt"));
        assert!(is_valid_entity("quot"));
        assert!(is_valid_entity("apos"));
        assert!(!is_valid_entity("bogus"));
    }

    #[test]
    fn is_valid_entity_numeric() {
        assert!(is_valid_entity("#65"));
        assert!(is_valid_entity("#x41"));
        assert!(!is_valid_entity("#"));
        assert!(!is_valid_entity("#x"));
        assert!(!is_valid_entity("#xGG"));
    }

    #[test]
    fn decode_entity_named() {
        assert_eq!(decode_entity("amp"), Some('&'));
        assert_eq!(decode_entity("lt"), Some('<'));
        assert_eq!(decode_entity("gt"), Some('>'));
        assert_eq!(decode_entity("quot"), Some('"'));
        assert_eq!(decode_entity("apos"), Some('\''));
        assert_eq!(decode_entity("bogus"), None);
    }

    #[test]
    fn decode_entity_numeric() {
        assert_eq!(decode_entity("#65"), Some('A'));
        assert_eq!(decode_entity("#x41"), Some('A'));
        assert_eq!(decode_entity("#0"), Some('\0'));
        assert_eq!(decode_entity("#xZZ"), None);
    }

    // ---- RenderResult ----

    #[test]
    fn render_result_eq() {
        let a = RenderResult {
            rendered: "hello".into(),
            parse_mode_used: None,
        };
        let b = RenderResult {
            rendered: "hello".into(),
            parse_mode_used: None,
        };
        assert_eq!(a, b);
    }

    // ---- FormatError ----

    #[test]
    fn format_error_variants() {
        let e1 = FormatError::InvalidHtml;
        let e2 = FormatError::InvalidMarkdown;
        let e3 = FormatError::ControlChars;
        assert_ne!(e1, e2);
        assert_ne!(e2, e3);
        assert_eq!(e1, FormatError::InvalidHtml);
    }

    // ---- ErrorClass ----

    #[test]
    fn error_class_variants() {
        assert_ne!(ErrorClass::ParseError, ErrorClass::RateLimit);
        assert_ne!(ErrorClass::Transient, ErrorClass::Terminal);
        assert_eq!(ErrorClass::ParseError, ErrorClass::ParseError);
    }

    // ---- escape_control_chars edge cases ----

    #[test]
    fn escape_control_chars_empty() {
        assert_eq!(escape_control_chars(""), "");
    }

    #[test]
    fn escape_control_chars_only_allowed() {
        assert_eq!(escape_control_chars("\n\r\t"), "\n\r\t");
    }
}
