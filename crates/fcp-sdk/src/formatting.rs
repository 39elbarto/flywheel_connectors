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
            continue;
        }
        if is_markdown_control(ch) {
            return Err(FormatError::InvalidMarkdown);
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
        // Without a parse_mode Telegram renders this literally, so preserve the
        // original user text instead of dropping punctuation on fallback.
        FormatMode::MarkdownV2 => input.to_string(),
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

#[cfg(test)]
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
        // Should fall back to plaintext
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_markdown_unescaped_controls_fall_back_to_plaintext() {
        let input = "*bold* [click](https://example.com)";
        let result = Formatter::render_with_fallback(input, FormatMode::MarkdownV2);
        assert_eq!(result.rendered, input);
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
        assert_eq!(result.rendered, "hello *world*");
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

    // ── NEW: FormatMode ───────────────────────────────────────────────

    #[test]
    fn format_mode_debug() {
        let debug = format!("{:?}", FormatMode::Plain);
        assert!(debug.contains("Plain"));
        let debug = format!("{:?}", FormatMode::Html);
        assert!(debug.contains("Html"));
        let debug = format!("{:?}", FormatMode::MarkdownV2);
        assert!(debug.contains("MarkdownV2"));
    }

    #[test]
    fn format_mode_copy() {
        let mode = FormatMode::Html;
        let copied = mode;
        assert_eq!(mode, copied);
    }

    // ── NEW: validate_html edge cases ─────────────────────────────────

    #[test]
    fn validate_html_empty_string() {
        assert!(validate_html("").is_ok());
    }

    #[test]
    fn validate_html_nested_tags() {
        assert!(validate_html("<b><i>bold italic</i></b>").is_ok());
    }

    #[test]
    fn validate_html_self_closing_tag() {
        assert!(validate_html("<br/>").is_ok());
    }

    #[test]
    fn validate_html_mixed_entities_and_tags() {
        assert!(validate_html("<b>&amp;</b>").is_ok());
    }

    #[test]
    fn validate_html_entity_at_end_of_string() {
        // Ampersand at end without semicolon
        assert!(matches!(
            validate_html("hello &"),
            Err(FormatError::InvalidHtml)
        ));
    }

    // ── NEW: validate_markdown edge cases ─────────────────────────────

    #[test]
    fn validate_markdown_empty_string() {
        assert!(validate_markdown("").is_ok());
    }

    #[test]
    fn validate_markdown_double_escape() {
        // Two escapes: \\ followed by nothing special
        assert!(validate_markdown("escaped backslash \\\\").is_ok());
    }

    #[test]
    fn validate_markdown_escape_at_end_of_long_string() {
        let mut input = "a".repeat(1000);
        input.push('\\');
        assert!(matches!(
            validate_markdown(&input),
            Err(FormatError::InvalidMarkdown)
        ));
    }

    // ── NEW: Formatter render edge cases ──────────────────────────────

    #[test]
    fn render_with_fallback_html_control_chars_falls_back() {
        let result = Formatter::render_with_fallback("<b>hello\x00world</b>", FormatMode::Html);
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_with_fallback_markdown_control_chars_falls_back() {
        let result = Formatter::render_with_fallback("hello\x01world", FormatMode::MarkdownV2);
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_with_fallback_plain_preserves_newlines() {
        let result = Formatter::render_with_fallback("line1\nline2\nline3", FormatMode::Plain);
        assert_eq!(result.rendered, "line1\nline2\nline3");
    }

    #[test]
    fn render_plaintext_fallback_strips_complex_html() {
        let result = Formatter::render_plaintext_fallback(
            "<a href=\"http://example.com\">link</a>",
            FormatMode::Html,
        );
        assert_eq!(result.rendered, "link");
    }

    // ── NEW: strip_html edge cases ────────────────────────────────────

    #[test]
    fn strip_html_empty_string() {
        assert_eq!(strip_html(""), "");
    }

    #[test]
    fn strip_html_multiple_entities() {
        assert_eq!(strip_html("&amp;&lt;&gt;"), "&<>");
    }

    #[test]
    fn strip_html_unclosed_tag_at_end() {
        // Tag never closes — strip_html just skips content inside the "tag"
        let result = strip_html("before<unclosed");
        assert_eq!(result, "before");
    }

    #[test]
    fn strip_html_numeric_hex_entity() {
        assert_eq!(strip_html("&#x48;&#x69;"), "Hi");
    }

    // ── NEW: strip_markdown edge cases ────────────────────────────────

    #[test]
    fn strip_markdown_empty_string() {
        assert_eq!(strip_markdown(""), "");
    }

    #[test]
    fn strip_markdown_plain_text_unchanged() {
        assert_eq!(strip_markdown("hello world 123"), "hello world 123");
    }

    #[test]
    fn strip_markdown_mixed_escapes_and_controls() {
        assert_eq!(strip_markdown("\\*bold* \\~strike~"), "*bold ~strike");
    }

    // ── NEW: classify_error_message edge cases ────────────────────────

    #[test]
    fn classify_empty_string() {
        assert_eq!(classify_error_message(""), ErrorClass::Terminal);
    }

    #[test]
    fn classify_parse_entities_partial_match() {
        assert_eq!(
            classify_error_message("error: parse entities failed"),
            ErrorClass::ParseError
        );
    }

    #[test]
    fn classify_mixed_case_parse_error() {
        assert_eq!(
            classify_error_message("INVALID MARKDOWN detected"),
            ErrorClass::ParseError
        );
    }

    // ── NEW: is_parse_error_message edge cases ────────────────────────

    #[test]
    fn is_parse_error_message_empty() {
        assert!(!is_parse_error_message(""));
    }

    #[test]
    fn is_parse_error_combined_markdown_parse() {
        assert!(is_parse_error_message("Markdown parse error occurred"));
    }

    // ── NEW: decode_numeric_entity edge cases ─────────────────────────

    #[test]
    fn decode_numeric_entity_space() {
        assert_eq!(decode_numeric_entity("#32"), Some(' '));
    }

    #[test]
    fn decode_numeric_entity_invalid_hex() {
        assert!(decode_numeric_entity("#xZZZZ").is_none());
    }

    #[test]
    fn decode_numeric_entity_emoji_codepoint() {
        // U+1F600 is a grinning face emoji
        assert!(decode_numeric_entity("#x1F600").is_some());
    }

    #[test]
    fn decode_numeric_entity_plain_text() {
        assert!(decode_numeric_entity("hello").is_none());
    }

    // ── NEW: RenderResult ─────────────────────────────────────────────

    #[test]
    fn render_result_ne() {
        let a = RenderResult {
            rendered: "hello".into(),
            parse_mode_used: None,
        };
        let b = RenderResult {
            rendered: "world".into(),
            parse_mode_used: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn render_result_clone() {
        let a = RenderResult {
            rendered: "test".into(),
            parse_mode_used: Some(FormatMode::Html),
        };
        let b = a.clone();
        assert_eq!(a.rendered, b.rendered);
        assert_eq!(a.parse_mode_used, b.parse_mode_used);
    }

    #[test]
    fn render_result_debug() {
        let r = RenderResult {
            rendered: "hello".into(),
            parse_mode_used: None,
        };
        let debug = format!("{r:?}");
        assert!(debug.contains("RenderResult"));
    }

    // ── NEW: FormatError ──────────────────────────────────────────────

    #[test]
    fn format_error_debug() {
        let e = FormatError::InvalidHtml;
        let debug = format!("{e:?}");
        assert!(debug.contains("InvalidHtml"));
    }

    #[test]
    fn format_error_clone() {
        let e = FormatError::ControlChars;
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    // ── NEW: ErrorClass ───────────────────────────────────────────────

    #[test]
    fn error_class_debug() {
        let e = ErrorClass::RateLimit;
        let debug = format!("{e:?}");
        assert!(debug.contains("RateLimit"));
    }

    #[test]
    fn error_class_copy() {
        let e = ErrorClass::Transient;
        let copied = e;
        assert_eq!(e, copied);
    }

    // ── NEW: is_numeric_entity ────────────────────────────────────────

    #[test]
    fn is_numeric_entity_empty_prefix() {
        assert!(!is_numeric_entity("#"));
        assert!(!is_numeric_entity("#x"));
    }

    #[test]
    fn is_numeric_entity_valid_decimal() {
        assert!(is_numeric_entity("#123"));
    }

    #[test]
    fn is_numeric_entity_valid_hex() {
        assert!(is_numeric_entity("#xFF"));
    }

    // ── NEW: validate_html additional edge cases ──────────────────────

    #[test]
    fn validate_html_only_tag() {
        assert!(validate_html("<br>").is_ok());
    }

    #[test]
    fn validate_html_adjacent_entities() {
        assert!(validate_html("&amp;&lt;&gt;&quot;&apos;").is_ok());
    }

    #[test]
    fn validate_html_tag_with_attributes() {
        assert!(validate_html("<a href=\"url\">text</a>").is_ok());
    }

    #[test]
    fn validate_html_ampersand_alone_at_eof() {
        // Bare & at end of input — no semicolon found before EOF
        let result = validate_html("test &");
        assert!(result.is_err());
    }

    #[test]
    fn validate_html_tab_and_newline_allowed() {
        assert!(validate_html("line1\nline2\ttab").is_ok());
    }

    // ── NEW: validate_markdown additional edge cases ──────────────────

    #[test]
    fn validate_markdown_only_backslash_pairs() {
        assert!(validate_markdown("\\\\\\\\").is_ok());
    }

    #[test]
    fn validate_markdown_escape_then_normal() {
        assert!(validate_markdown("\\*hello").is_ok());
    }

    // ── NEW: strip_html additional edge cases ─────────────────────────

    #[test]
    fn strip_html_preserves_text_between_tags() {
        assert_eq!(strip_html("a<b>b</b>c"), "abc");
    }

    #[test]
    fn strip_html_consecutive_tags() {
        assert_eq!(strip_html("<b></b><i></i>"), "");
    }

    #[test]
    fn strip_html_entity_long_no_semicolon() {
        // Entity name exceeds 10 chars — buffer fills then breaks
        let result = strip_html("&averylonginvalidname");
        assert!(result.contains('&'));
    }

    // ── NEW: strip_markdown additional edge cases ─────────────────────

    #[test]
    fn strip_markdown_trailing_escape_char() {
        // Trailing backslash — escape flag is true at end, nothing to output
        assert_eq!(strip_markdown("text\\"), "text");
    }

    #[test]
    fn strip_markdown_consecutive_controls() {
        assert_eq!(strip_markdown("***bold***"), "bold");
    }

    // ── NEW: classify_error_message priority ──────────────────────────

    #[test]
    fn classify_parse_takes_priority_over_rate_limit() {
        // "parse entities" should classify as ParseError even if "rate limit" also present
        assert_eq!(
            classify_error_message("can't parse entities due to rate limit"),
            ErrorClass::ParseError
        );
    }

    #[test]
    fn classify_http_429_string() {
        assert_eq!(
            classify_error_message("HTTP 429 Too Many Requests"),
            ErrorClass::RateLimit
        );
    }

    // ── NEW: decode_entity edge cases ─────────────────────────────────

    #[test]
    fn decode_entity_empty_string() {
        assert_eq!(decode_entity(""), None);
    }

    #[test]
    fn decode_numeric_entity_zero() {
        assert_eq!(decode_numeric_entity("#0"), Some('\0'));
    }

    #[test]
    fn decode_numeric_entity_large_invalid_codepoint() {
        // 0xFFFFFFFF is not a valid Unicode scalar
        assert_eq!(decode_numeric_entity("#xFFFFFFFF"), None);
    }

    // ── NEW: is_valid_entity additional edge cases ────────────────────

    #[test]
    fn is_valid_entity_empty_string() {
        assert!(!is_valid_entity(""));
    }

    #[test]
    fn is_valid_entity_numeric_decimal_zero() {
        assert!(is_valid_entity("#0"));
    }

    // ── NEW: fallback_plaintext edge cases ────────────────────────────

    #[test]
    fn fallback_plaintext_plain_with_control_chars() {
        let result = fallback_plaintext("text\x00here", FormatMode::Plain);
        assert!(result.contains("\\u{0}"));
    }

    #[test]
    fn fallback_plaintext_html_strips_and_escapes() {
        let result = fallback_plaintext("<b>bold\x00</b>", FormatMode::Html);
        assert_eq!(result, "bold\\u{0}");
    }

    #[test]
    fn fallback_plaintext_markdown_strips_and_escapes() {
        let result = fallback_plaintext("*bold*\x01text", FormatMode::MarkdownV2);
        assert!(result.contains("*bold*"));
        assert!(result.contains("\\u{1}"));
    }

    // ── EXPANDED: FormatMode clone/copy/eq exhaustive ────────────────

    #[test]
    fn format_mode_copy_all_variants() {
        let plain = FormatMode::Plain;
        let copied = plain;
        assert_eq!(plain, copied);

        let html = FormatMode::Html;
        let copied = html;
        assert_eq!(html, copied);

        let md = FormatMode::MarkdownV2;
        let copied = md;
        assert_eq!(md, copied);
    }

    #[test]
    fn format_mode_ne_exhaustive_pairs() {
        assert_ne!(FormatMode::Plain, FormatMode::Html);
        assert_ne!(FormatMode::Plain, FormatMode::MarkdownV2);
        assert_ne!(FormatMode::Html, FormatMode::MarkdownV2);
    }

    // ── EXPANDED: validate_html boundary conditions ─────────────────

    #[test]
    fn validate_html_empty_tag() {
        // `<>` is technically a valid tag (has `<` followed by `>`)
        assert!(validate_html("<>").is_ok());
    }

    #[test]
    fn validate_html_multiple_unclosed_tags() {
        assert!(matches!(
            validate_html("<b><i"),
            Err(FormatError::InvalidHtml)
        ));
    }

    #[test]
    fn validate_html_entity_exactly_at_limit() {
        // Entity name with exactly 10 chars is allowed (11 triggers error)
        // "0123456789" is 10 chars — not a valid name, but length is OK
        assert!(matches!(
            validate_html("&0123456789;"),
            Err(FormatError::InvalidHtml) // valid length but invalid name
        ));
    }

    #[test]
    fn validate_html_entity_exceeds_limit_by_one() {
        // 11 chars triggers the > 10 check
        assert!(matches!(
            validate_html("&01234567890;"),
            Err(FormatError::InvalidHtml)
        ));
    }

    #[test]
    fn validate_html_numeric_hex_entity_inline() {
        assert!(validate_html("char &#x20; space").is_ok());
    }

    #[test]
    fn validate_html_numeric_decimal_entity_inline() {
        assert!(validate_html("char &#32; space").is_ok());
    }

    #[test]
    fn validate_html_tag_then_entity() {
        assert!(validate_html("<b>&amp;</b>").is_ok());
    }

    #[test]
    fn validate_html_entity_then_tag() {
        assert!(validate_html("&amp;<b>x</b>").is_ok());
    }

    #[test]
    fn validate_html_only_whitespace() {
        assert!(validate_html("   \n\t  ").is_ok());
    }

    #[test]
    fn validate_html_bell_char() {
        assert!(matches!(
            validate_html("text\x07more"),
            Err(FormatError::ControlChars)
        ));
    }

    #[test]
    fn validate_html_form_feed_rejected() {
        assert!(matches!(
            validate_html("text\x0Cmore"),
            Err(FormatError::ControlChars)
        ));
    }

    // ── EXPANDED: validate_markdown boundary conditions ──────────────

    #[test]
    fn validate_markdown_single_backslash_then_normal_char() {
        assert!(validate_markdown("\\a").is_ok());
    }

    #[test]
    fn validate_markdown_three_backslashes_trailing() {
        // \\\ — first two form a pair, third is dangling
        assert!(matches!(
            validate_markdown("\\\\\\"),
            Err(FormatError::InvalidMarkdown)
        ));
    }

    #[test]
    fn validate_markdown_only_whitespace() {
        assert!(validate_markdown("   \n\t  ").is_ok());
    }

    #[test]
    fn validate_markdown_bell_char() {
        assert!(matches!(
            validate_markdown("text\x07more"),
            Err(FormatError::ControlChars)
        ));
    }

    #[test]
    fn validate_markdown_unicode_ok() {
        assert!(validate_markdown("hello \u{1F600} world").is_ok());
    }

    // ── EXPANDED: Formatter render edge cases ────────────────────────

    #[test]
    fn render_with_fallback_empty_string_plain() {
        let result = Formatter::render_with_fallback("", FormatMode::Plain);
        assert_eq!(result.rendered, "");
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_with_fallback_empty_string_html() {
        let result = Formatter::render_with_fallback("", FormatMode::Html);
        assert_eq!(result.rendered, "");
        assert_eq!(result.parse_mode_used, Some(FormatMode::Html));
    }

    #[test]
    fn render_with_fallback_empty_string_markdown() {
        let result = Formatter::render_with_fallback("", FormatMode::MarkdownV2);
        assert_eq!(result.rendered, "");
        assert_eq!(result.parse_mode_used, Some(FormatMode::MarkdownV2));
    }

    #[test]
    fn render_with_fallback_html_valid_entities() {
        let result = Formatter::render_with_fallback("&amp; &lt;", FormatMode::Html);
        assert_eq!(result.rendered, "&amp; &lt;");
        assert_eq!(result.parse_mode_used, Some(FormatMode::Html));
    }

    #[test]
    fn render_with_fallback_html_invalid_entity_fallback() {
        let result = Formatter::render_with_fallback("&bogus;", FormatMode::Html);
        // Invalid entity causes fallback
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_with_fallback_markdown_double_escape() {
        let result = Formatter::render_with_fallback("\\\\", FormatMode::MarkdownV2);
        assert_eq!(result.rendered, "\\\\");
        assert_eq!(result.parse_mode_used, Some(FormatMode::MarkdownV2));
    }

    #[test]
    fn render_with_fallback_plain_multiple_control_chars() {
        let result = Formatter::render_with_fallback("\x00\x01\x02\x03", FormatMode::Plain);
        assert!(result.rendered.contains("\\u{0}"));
        assert!(result.rendered.contains("\\u{1}"));
        assert!(result.rendered.contains("\\u{2}"));
        assert!(result.rendered.contains("\\u{3}"));
        assert!(result.parse_mode_used.is_none());
    }

    #[test]
    fn render_plaintext_fallback_html_entities_decoded() {
        let result =
            Formatter::render_plaintext_fallback("5 &gt; 3 &amp; 2 &lt; 4", FormatMode::Html);
        assert_eq!(result.rendered, "5 > 3 & 2 < 4");
    }

    #[test]
    fn render_plaintext_fallback_markdown_escapes_preserved() {
        let result = Formatter::render_plaintext_fallback("\\*star\\*", FormatMode::MarkdownV2);
        assert_eq!(result.rendered, "\\*star\\*");
    }

    // ── EXPANDED: strip_html complex scenarios ──────────────────────

    #[test]
    fn strip_html_deeply_nested() {
        assert_eq!(strip_html("<div><p><b>deep</b></p></div>"), "deep");
    }

    #[test]
    fn strip_html_entity_then_eof() {
        // Entity name starts but file ends — no semicolon
        let result = strip_html("start &amp");
        assert!(result.starts_with("start &amp"));
    }

    #[test]
    fn strip_html_multiple_entities_inline() {
        assert_eq!(strip_html("&lt;tag&gt;"), "<tag>");
    }

    #[test]
    fn strip_html_unknown_entity_passthrough() {
        // Unknown entity with semicolon is preserved literally
        assert_eq!(strip_html("&nbsp;"), "&nbsp;");
    }

    #[test]
    fn strip_html_numeric_entity_newline() {
        // &#10; is newline
        assert_eq!(strip_html("&#10;"), "\n");
    }

    #[test]
    fn strip_html_tag_with_special_chars() {
        assert_eq!(
            strip_html("<img src=\"http://example.com/a.png\" alt=\"pic\"/>text"),
            "text"
        );
    }

    // ── EXPANDED: strip_markdown complex scenarios ───────────────────

    #[test]
    fn strip_markdown_escaped_backslash_then_control() {
        // \\* — the \\ becomes a literal backslash, then * is a control and stripped
        assert_eq!(strip_markdown("\\\\*"), "\\");
    }

    #[test]
    fn strip_markdown_escape_non_control() {
        // \a — the backslash escapes 'a', outputting 'a'
        assert_eq!(strip_markdown("\\a"), "a");
    }

    #[test]
    fn strip_markdown_unicode_preserved() {
        assert_eq!(strip_markdown("hello \u{1F600}"), "hello \u{1F600}");
    }

    #[test]
    fn strip_markdown_all_controls_between_text() {
        assert_eq!(strip_markdown("a*b_c`d~e[f]g(h)i"), "abcdefghi");
    }

    // ── EXPANDED: classify_error_message additional patterns ─────────

    #[test]
    fn classify_parse_entities_upper() {
        assert_eq!(
            classify_error_message("CAN'T PARSE ENTITIES"),
            ErrorClass::ParseError
        );
    }

    #[test]
    fn classify_find_end_of_entity() {
        assert_eq!(
            classify_error_message("could not find end of the entity starting at byte 5"),
            ErrorClass::ParseError
        );
    }

    #[test]
    fn classify_rate_limit_with_retry_after() {
        assert_eq!(
            classify_error_message("Retry After: 60 seconds"),
            ErrorClass::RateLimit
        );
    }

    #[test]
    fn classify_rate_hyphenated() {
        assert_eq!(
            classify_error_message("rate-limited for 30s"),
            ErrorClass::RateLimit
        );
    }

    #[test]
    fn classify_too_many_requests_lower() {
        assert_eq!(
            classify_error_message("too many requests from this IP"),
            ErrorClass::RateLimit
        );
    }

    #[test]
    fn classify_http_502() {
        assert_eq!(
            classify_error_message("received HTTP 502"),
            ErrorClass::Transient
        );
    }

    #[test]
    fn classify_http_503() {
        assert_eq!(
            classify_error_message("received HTTP 503"),
            ErrorClass::Transient
        );
    }

    #[test]
    fn classify_connection_reset() {
        assert_eq!(
            classify_error_message("error: connection reset"),
            ErrorClass::Transient
        );
    }

    #[test]
    fn classify_network_error() {
        assert_eq!(
            classify_error_message("a network error occurred during request"),
            ErrorClass::Transient
        );
    }

    #[test]
    fn classify_terminal_auth_error() {
        assert_eq!(
            classify_error_message("authentication failed: bad credentials"),
            ErrorClass::Terminal
        );
    }

    #[test]
    fn classify_terminal_forbidden() {
        assert_eq!(
            classify_error_message("HTTP 403 Forbidden"),
            ErrorClass::Terminal
        );
    }

    // ── EXPANDED: is_parse_error_message additional patterns ─────────

    #[test]
    fn is_parse_error_find_end_entity() {
        assert!(is_parse_error_message(
            "can't find end of the entity at pos 5"
        ));
    }

    #[test]
    fn is_parse_error_markdown_and_parse() {
        assert!(is_parse_error_message("failed to parse markdown content"));
    }

    #[test]
    fn is_parse_error_not_matched_by_timeout() {
        assert!(!is_parse_error_message("connection timeout"));
    }

    #[test]
    fn is_parse_error_case_insensitive() {
        assert!(is_parse_error_message("CAN'T PARSE ENTITIES in message"));
    }

    // ── EXPANDED: contains_disallowed_control thorough ───────────────

    #[test]
    fn disallowed_control_vertical_tab() {
        assert!(contains_disallowed_control("hello\x0Bworld"));
    }

    #[test]
    fn disallowed_control_backspace() {
        assert!(contains_disallowed_control("hello\x08world"));
    }

    #[test]
    fn disallowed_control_delete() {
        assert!(contains_disallowed_control("hello\x7Fworld"));
    }

    #[test]
    fn allowed_control_empty() {
        assert!(!contains_disallowed_control(""));
    }

    #[test]
    fn allowed_control_only_printable_and_whitespace() {
        assert!(!contains_disallowed_control("abc 123 !@#\n\r\t"));
    }

    // ── EXPANDED: decode_entity / decode_numeric_entity ──────────────

    #[test]
    fn decode_numeric_entity_max_valid_char() {
        // U+10FFFF is the max valid Unicode scalar value
        assert!(decode_numeric_entity("#x10FFFF").is_some());
    }

    #[test]
    fn decode_numeric_entity_surrogate_invalid() {
        // U+D800 is a surrogate, not a valid scalar
        assert!(decode_numeric_entity("#xD800").is_none());
    }

    #[test]
    fn decode_numeric_entity_decimal_large_valid() {
        // 9999 = U+270F (pencil)
        assert!(decode_numeric_entity("#9999").is_some());
    }

    #[test]
    fn decode_numeric_entity_just_hash_x() {
        assert!(decode_numeric_entity("#x").is_none());
    }

    #[test]
    fn decode_numeric_entity_just_hash() {
        assert!(decode_numeric_entity("#").is_none());
    }

    #[test]
    fn decode_entity_unknown_named() {
        assert_eq!(decode_entity("nbsp"), None);
        assert_eq!(decode_entity("copy"), None);
        assert_eq!(decode_entity("reg"), None);
    }

    // ── EXPANDED: is_valid_entity ────────────────────────────────────

    #[test]
    fn is_valid_entity_hex_mixed_case() {
        assert!(is_valid_entity("#xaB"));
        assert!(is_valid_entity("#xFf"));
    }

    #[test]
    fn is_valid_entity_decimal_large() {
        assert!(is_valid_entity("#999999"));
    }

    #[test]
    fn is_valid_entity_not_a_number() {
        assert!(!is_valid_entity("#abc"));
    }

    // ── EXPANDED: is_markdown_control completeness ──────────────────

    #[test]
    fn is_markdown_control_every_char() {
        let controls = [
            '*', '_', '`', '~', '[', ']', '(', ')', '>', '#', '+', '-', '=', '|', '{', '}', '.',
            '!',
        ];
        for ch in &controls {
            assert!(
                is_markdown_control(*ch),
                "expected {ch:?} to be markdown control"
            );
        }
    }

    #[test]
    fn is_markdown_control_non_ascii() {
        assert!(!is_markdown_control('\u{00E9}')); // e-acute
        assert!(!is_markdown_control('\u{1F600}')); // emoji
    }

    #[test]
    fn is_markdown_control_space_and_digits() {
        assert!(!is_markdown_control(' '));
        assert!(!is_markdown_control('0'));
        assert!(!is_markdown_control('9'));
    }

    // ── EXPANDED: ErrorClass clone/debug exhaustive ──────────────────

    #[test]
    fn error_class_copy_all_variants() {
        let pe = ErrorClass::ParseError;
        let copied = pe;
        assert_eq!(pe, copied);

        let rl = ErrorClass::RateLimit;
        let copied = rl;
        assert_eq!(rl, copied);

        let tr = ErrorClass::Transient;
        let copied = tr;
        assert_eq!(tr, copied);

        let te = ErrorClass::Terminal;
        let copied = te;
        assert_eq!(te, copied);
    }

    #[test]
    fn error_class_debug_all_variants() {
        assert!(format!("{:?}", ErrorClass::ParseError).contains("ParseError"));
        assert!(format!("{:?}", ErrorClass::RateLimit).contains("RateLimit"));
        assert!(format!("{:?}", ErrorClass::Transient).contains("Transient"));
        assert!(format!("{:?}", ErrorClass::Terminal).contains("Terminal"));
    }

    // ── EXPANDED: FormatError clone/debug exhaustive ─────────────────

    #[test]
    fn format_error_clone_all_variants() {
        let ih = FormatError::InvalidHtml;
        let cloned = ih.clone();
        assert_eq!(ih, cloned);

        let im = FormatError::InvalidMarkdown;
        let cloned = im.clone();
        assert_eq!(im, cloned);

        let cc = FormatError::ControlChars;
        let cloned = cc.clone();
        assert_eq!(cc, cloned);
    }

    #[test]
    fn format_error_debug_all_variants() {
        assert!(format!("{:?}", FormatError::InvalidHtml).contains("InvalidHtml"));
        assert!(format!("{:?}", FormatError::InvalidMarkdown).contains("InvalidMarkdown"));
        assert!(format!("{:?}", FormatError::ControlChars).contains("ControlChars"));
    }

    // ── EXPANDED: RenderResult field combinations ────────────────────

    #[test]
    fn render_result_ne_by_parse_mode() {
        let a = RenderResult {
            rendered: "same".into(),
            parse_mode_used: None,
        };
        let b = RenderResult {
            rendered: "same".into(),
            parse_mode_used: Some(FormatMode::Html),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn render_result_eq_with_mode() {
        let a = RenderResult {
            rendered: "test".into(),
            parse_mode_used: Some(FormatMode::MarkdownV2),
        };
        let b = RenderResult {
            rendered: "test".into(),
            parse_mode_used: Some(FormatMode::MarkdownV2),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn render_result_debug_with_mode() {
        let r = RenderResult {
            rendered: "formatted".into(),
            parse_mode_used: Some(FormatMode::Html),
        };
        let debug = format!("{r:?}");
        assert!(debug.contains("formatted"));
        assert!(debug.contains("Html"));
    }

    // ── EXPANDED: escape_control_chars additional ────────────────────

    #[test]
    fn escape_control_chars_mixed() {
        let result = escape_control_chars("a\x00b\nc\x1bd\te");
        assert_eq!(result, "a\\u{0}b\nc\\u{1b}d\te");
    }

    #[test]
    fn escape_control_chars_unicode_preserved() {
        let input = "caf\u{00E9} \u{1F600}";
        assert_eq!(escape_control_chars(input), input);
    }

    #[test]
    fn escape_control_chars_all_allowed_whitespace() {
        assert_eq!(escape_control_chars("\n\r\t\n\r\t"), "\n\r\t\n\r\t");
    }

    // ── EXPANDED: fallback_plaintext additional ──────────────────────

    #[test]
    fn fallback_plaintext_empty_all_modes() {
        assert_eq!(fallback_plaintext("", FormatMode::Plain), "");
        assert_eq!(fallback_plaintext("", FormatMode::Html), "");
        assert_eq!(fallback_plaintext("", FormatMode::MarkdownV2), "");
    }

    #[test]
    fn fallback_plaintext_html_complex() {
        let result = fallback_plaintext("<div><b>&amp;</b> &lt;tag&gt;</div>", FormatMode::Html);
        assert_eq!(result, "& <tag>");
    }

    #[test]
    fn fallback_plaintext_markdown_with_escapes_and_controls() {
        let result = fallback_plaintext("\\*hello* _world_", FormatMode::MarkdownV2);
        assert_eq!(result, "\\*hello* _world_");
    }

    // ── EXPANDED: Formatter::render (private) via render_with_fallback

    #[test]
    fn render_html_with_only_entities_valid() {
        let result = Formatter::render_with_fallback("&amp;&lt;&gt;", FormatMode::Html);
        assert_eq!(result.parse_mode_used, Some(FormatMode::Html));
        assert_eq!(result.rendered, "&amp;&lt;&gt;");
    }

    #[test]
    fn render_markdown_with_multiple_escapes() {
        let input = "\\*\\*\\*";
        let result = Formatter::render_with_fallback(input, FormatMode::MarkdownV2);
        assert_eq!(result.parse_mode_used, Some(FormatMode::MarkdownV2));
        assert_eq!(result.rendered, input);
    }

    #[test]
    fn render_plain_long_string() {
        let long_input = "a".repeat(10_000);
        let result = Formatter::render_with_fallback(&long_input, FormatMode::Plain);
        assert_eq!(result.rendered.len(), 10_000);
    }

    #[test]
    fn render_html_bare_ampersand_mid_text() {
        // "a & b" — bare ampersand without semicolon triggers fallback
        let result = Formatter::render_with_fallback("a & b", FormatMode::Html);
        assert!(result.parse_mode_used.is_none());
    }
}
