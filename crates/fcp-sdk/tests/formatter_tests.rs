use fcp_sdk::formatting::{FormatMode, Formatter};

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
fn plain_escapes_control_chars() {
    let input = "hi\u{0007}";
    let result = Formatter::render_with_fallback(input, FormatMode::Plain);

    assert_eq!(result.parse_mode_used, None);
    assert!(result.rendered.contains("\\u{7}"));
}
