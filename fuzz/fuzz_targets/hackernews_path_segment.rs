#![no_main]
//! Hacker News connector path-segment parser fuzz target.
//!
//! Drives the guard used before Hacker News user IDs are interpolated into REST
//! URL paths. Structured cases keep traversal, separator, NUL, whitespace, and
//! ordinary HN username shapes in the corpus.

use arbitrary::{Arbitrary, Unstructured};
use fcp_hackernews::client::__fuzz;
use libfuzzer_sys::fuzz_target;

const MAX_SEGMENT_BYTES: usize = 1024;

#[derive(Arbitrary, Debug)]
struct HackerNewsPathSegmentFuzz<'a> {
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
    match raw % 8 {
        0 => "../admin",
        1 => "foo/bar",
        2 => "foo\\bar",
        3 => "..",
        4 => "name\0tail",
        5 => "",
        6 => " ",
        _ => "\t",
    }
}

fn valid_seed(raw: u8) -> &'static str {
    match raw % 5 {
        0 => "pg",
        1 => "jl",
        2 => "dang",
        3 => "user-123",
        _ => "hn_user",
    }
}

fn candidate(input: &HackerNewsPathSegmentFuzz<'_>) -> String {
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
    value.contains('/') || value.contains('\\') || value.contains("..") || value.contains('\0')
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = HackerNewsPathSegmentFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    if input.raw.len() > MAX_SEGMENT_BYTES
        || input.prefix.len() > MAX_SEGMENT_BYTES
        || input.suffix.len() > MAX_SEGMENT_BYTES
    {
        return;
    }

    let candidate = candidate(&input);
    let accepted = __fuzz::sanitize_path_segment_candidate(&candidate);

    if candidate.trim().is_empty() || contains_forbidden_path_marker(&candidate) {
        assert!(!accepted);
    }
});
