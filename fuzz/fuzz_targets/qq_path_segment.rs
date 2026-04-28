#![no_main]
//! QQ connector path-segment sanitizer fuzz target.
//!
//! Drives the guard used before QQ channel, guild, group, and user IDs are
//! interpolated into REST URL paths. Structured cases keep traversal,
//! separator, percent-encoded traversal, whitespace, and ordinary ID shapes in
//! the corpus.

use arbitrary::{Arbitrary, Unstructured};
use fcp_qq::client::sanitize_path_segment;
use libfuzzer_sys::fuzz_target;

const MAX_SEGMENT_BYTES: usize = 1024;

#[derive(Arbitrary, Debug)]
struct QqPathSegmentFuzz<'a> {
    mode: u8,
    raw: &'a [u8],
    prefix: &'a [u8],
    suffix: &'a [u8],
    marker_variant: u8,
}

fn bounded(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_SEGMENT_BYTES)]
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bounded(bytes)).into_owned()
}

fn forbidden_marker(raw: u8) -> &'static str {
    match raw % 10 {
        0 => "../admin",
        1 => "foo/bar",
        2 => "foo\\bar",
        3 => "foo%2fbar",
        4 => "foo%2Fbar",
        5 => "foo%5cbar",
        6 => "foo%5Cbar",
        7 => "foo%2e%2e",
        8 => "%2E%2E",
        _ => "",
    }
}

fn valid_seed(raw: u8) -> &'static str {
    match raw % 5 {
        0 => "channel-id-42",
        1 => "guild_123456",
        2 => "group-abc-001",
        3 => "user.2026",
        _ => "abc123",
    }
}

fn candidate(input: &QqPathSegmentFuzz<'_>) -> String {
    match input.mode % 4 {
        0 => lossy(input.raw),
        1 => format!(
            "{}{}{}",
            lossy(input.prefix),
            forbidden_marker(input.marker_variant),
            lossy(input.suffix)
        ),
        2 => valid_seed(input.marker_variant).to_string(),
        _ => format!(
            "{}{}{}",
            valid_seed(input.marker_variant),
            lossy(input.raw),
            valid_seed(input.mode)
        ),
    }
}

fn contains_forbidden_path_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = QqPathSegmentFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw.len() > MAX_SEGMENT_BYTES
        || input.prefix.len() > MAX_SEGMENT_BYTES
        || input.suffix.len() > MAX_SEGMENT_BYTES
    {
        return;
    }

    let candidate = candidate(&input);
    let accepted = sanitize_path_segment(&candidate, "id").is_ok();

    if candidate.trim().is_empty() || contains_forbidden_path_marker(&candidate) {
        assert!(!accepted);
    }
});
