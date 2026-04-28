use std::{str::FromStr, time::Duration};

use fcp_core::{RetryDirective, RetryDirectiveParseError};

#[test]
fn retry_directive_display_formats_are_canonical() {
    let cases = [
        (RetryDirective::Immediate, "immediate"),
        (RetryDirective::Backoff, "backoff"),
        (
            RetryDirective::RetryAfter(Duration::from_millis(1_500)),
            "retry-after=1500ms",
        ),
        (RetryDirective::Terminal, "terminal"),
    ];

    for (directive, expected) in cases {
        assert_eq!(directive.to_string(), expected);
    }
}

#[test]
fn retry_directive_display_from_str_roundtrips() {
    let directives = [
        RetryDirective::Immediate,
        RetryDirective::Backoff,
        RetryDirective::RetryAfter(Duration::ZERO),
        RetryDirective::RetryAfter(Duration::from_millis(42)),
        RetryDirective::RetryAfter(Duration::from_secs(60)),
        RetryDirective::Terminal,
    ];

    for directive in directives {
        let displayed = directive.to_string();
        let parsed = RetryDirective::from_str(&displayed)
            .unwrap_or_else(|err| panic!("parse {displayed:?}: {err}"));

        assert_eq!(parsed, directive, "{displayed}");
    }
}

#[test]
fn retry_directive_from_str_parses_retry_after_milliseconds() {
    let parsed = "retry-after=2500ms"
        .parse::<RetryDirective>()
        .expect("retry-after milliseconds directive should parse");

    assert_eq!(
        parsed,
        RetryDirective::RetryAfter(Duration::from_millis(2_500))
    );
    assert_eq!(parsed.retry_after(), Some(Duration::from_millis(2_500)));
}

#[test]
fn retry_after_header_delta_seconds_parse_as_retry_after_directive() {
    let parsed =
        RetryDirective::parse_retry_after("30").expect("Retry-After delta-seconds should parse");

    assert_eq!(parsed, RetryDirective::RetryAfter(Duration::from_secs(30)));
    assert_eq!(parsed.to_string(), "retry-after=30000ms");
}

#[test]
fn retry_after_parser_rejects_non_delta_seconds() {
    for invalid in ["", " 30", "30s", "-1", "Wed, 21 Oct 2015 07:28:00 GMT"] {
        assert_eq!(
            RetryDirective::parse_retry_after(invalid),
            Err(RetryDirectiveParseError::InvalidDuration),
            "{invalid:?}"
        );
    }
}

#[test]
fn retry_directive_from_str_rejects_noncanonical_shapes() {
    let cases = [
        ("retry-after=1s", RetryDirectiveParseError::InvalidFormat),
        ("retry-after=ms", RetryDirectiveParseError::InvalidDuration),
        (
            "retry-after=-1ms",
            RetryDirectiveParseError::InvalidDuration,
        ),
        ("retry-after=1", RetryDirectiveParseError::InvalidFormat),
        ("retry_after=1ms", RetryDirectiveParseError::InvalidFormat),
        ("Immediate", RetryDirectiveParseError::InvalidFormat),
    ];

    for (input, expected_error) in cases {
        assert_eq!(
            input.parse::<RetryDirective>(),
            Err(expected_error),
            "{input:?}"
        );
    }
}
