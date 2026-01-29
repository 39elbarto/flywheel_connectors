use fcp_sdk::formatting::{ErrorClass, FormatMode, Formatter, classify_error_message};

#[test]
fn html_valid_keeps_parse_mode() {
    let input = "<b>Hello</b>";
    let result = Formatter::render_with_fallback(input, FormatMode::Html);

    assert_eq!(result.parse_mode_used, Some(FormatMode::Html));
    assert_eq!(result.rendered, input);
}

#[test]
fn html_invalid_falls_back() {
    let input = "Fish & chips";
    let result = Formatter::render_with_fallback(input, FormatMode::Html);

    assert_eq!(result.parse_mode_used, None);
    assert_eq!(result.rendered, "Fish & chips");
}

#[test]
fn markdown_trailing_escape_falls_back() {
    let input = "Hello\\";
    let result = Formatter::render_with_fallback(input, FormatMode::MarkdownV2);

    assert_eq!(result.parse_mode_used, None);
    assert_eq!(result.rendered, "Hello");
}

#[test]
fn forced_plaintext_strips_html() {
    let input = "<b>Hello</b>";
    let result = Formatter::render_plaintext_fallback(input, FormatMode::Html);

    assert_eq!(result.parse_mode_used, None);
    assert_eq!(result.rendered, "Hello");
}

#[test]
fn plain_escapes_control_chars() {
    let input = "hi\u{0007}";
    let result = Formatter::render_with_fallback(input, FormatMode::Plain);

    assert_eq!(result.parse_mode_used, None);
    assert!(result.rendered.contains("\\u{7}"));
}

#[test]
fn classify_parse_error() {
    let message = "Bad Request: can't parse entities: Character '<' is reserved";
    assert_eq!(classify_error_message(message), ErrorClass::ParseError);
}

#[test]
fn classify_rate_limit_error() {
    let message = "Too Many Requests: retry after 5";
    assert_eq!(classify_error_message(message), ErrorClass::RateLimit);
}

#[test]
fn classify_transient_error() {
    let message = "Connection reset by peer";
    assert_eq!(classify_error_message(message), ErrorClass::Transient);
}

#[test]
fn classify_terminal_error() {
    let message = "Forbidden: bot was blocked by the user";
    assert_eq!(classify_error_message(message), ErrorClass::Terminal);
}
