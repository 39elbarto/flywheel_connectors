#![no_main]
//! Google Docs connector path-segment parser fuzz target.
//!
//! Exercises the guard used before Docs document IDs are interpolated into REST
//! URL paths. Structured cases keep traversal, query/fragment, percent-encoded,
//! double-encoded, and ordinary document ID shapes covered.

use arbitrary::{Arbitrary, Unstructured};
use fcp_google_docs::client::__fuzz;
use libfuzzer_sys::fuzz_target;

const MAX_SEGMENT_BYTES: usize = 1024;

#[derive(Arbitrary, Debug)]
struct DocsPathSegmentFuzz<'a> {
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
    match raw % 15 {
        0 => "../admin",
        1 => "foo/bar",
        2 => "foo\\bar",
        3 => "foo%2fbar",
        4 => "foo%2Fbar",
        5 => "foo%5cbar",
        6 => "foo%5Cbar",
        7 => "doc?alt=media",
        8 => "doc#frag",
        9 => "doc%3Falt=media",
        10 => "doc%23frag",
        11 => "doc%252Fbar",
        12 => "doc%2523frag",
        13 => "..",
        _ => "",
    }
}

fn valid_seed(raw: u8) -> &'static str {
    match raw % 5 {
        0 => "1abc-xyz_123",
        1 => "1FAIpQLScdocExampleId",
        2 => "doc.id-2026",
        3 => "shared_doc_001",
        _ => "draft-1A2B3C",
    }
}

fn candidate(input: &DocsPathSegmentFuzz<'_>) -> String {
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
        || value.contains('?')
        || value.contains('#')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%3f")
        || lower.contains("%23")
        || lower.contains("%25")
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = DocsPathSegmentFuzz::arbitrary(&mut unstructured) else {
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
