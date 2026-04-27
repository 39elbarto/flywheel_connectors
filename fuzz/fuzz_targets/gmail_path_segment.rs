#![no_main]
//! Gmail connector path-segment parser fuzz target.
//!
//! Drives the same guard used before Gmail message, thread, and draft IDs are
//! interpolated into REST URL paths. The target mixes raw UTF-8-ish fuzz input
//! with structure-aware traversal encodings so separators, dot segments,
//! percent-encoded separators, controls, whitespace, and ordinary Gmail IDs all
//! stay covered.

use arbitrary::{Arbitrary, Unstructured};
use fcp_gmail::client::__fuzz;
use libfuzzer_sys::fuzz_target;

const MAX_SEGMENT_BYTES: usize = 1024;

#[derive(Arbitrary, Debug)]
struct GmailPathSegmentFuzz<'a> {
    mode: u8,
    raw: &'a [u8],
    prefix: &'a [u8],
    suffix: &'a [u8],
    traversal_variant: u8,
}

fn bounded(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_SEGMENT_BYTES)]
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bounded(bytes)).into_owned()
}

fn traversal(raw: u8) -> &'static str {
    match raw % 10 {
        0 => "../admin",
        1 => "foo/bar",
        2 => "foo\\bar",
        3 => "foo%2fbar",
        4 => "foo%2Fbar",
        5 => "foo%5cbar",
        6 => "foo%5Cbar",
        7 => "..",
        8 => " ",
        _ => "",
    }
}

fn valid_seed(raw: u8) -> &'static str {
    match raw % 5 {
        0 => "18d04b7e3c5a8f2d",
        1 => "msg-abc-123",
        2 => "thread_001",
        3 => "draft.r1234567890",
        _ => "Label_1",
    }
}

fn candidate(input: &GmailPathSegmentFuzz<'_>) -> String {
    match input.mode % 4 {
        0 => lossy(input.raw),
        1 => format!(
            "{}{}{}",
            lossy(input.prefix),
            traversal(input.traversal_variant),
            lossy(input.suffix)
        ),
        2 => valid_seed(input.traversal_variant).to_string(),
        _ => format!(
            "{}{}{}",
            valid_seed(input.traversal_variant),
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
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = GmailPathSegmentFuzz::arbitrary(&mut unstructured) else {
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
