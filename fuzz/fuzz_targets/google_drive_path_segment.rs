#![no_main]
//! Google Drive connector path-segment parser fuzz target.
//!
//! Exercises the guard used before Drive file IDs are interpolated into REST
//! URL paths. The structured cases keep traversal, separator, query/fragment,
//! percent-encoding, and ordinary Drive ID shapes in the corpus.

use arbitrary::{Arbitrary, Unstructured};
use fcp_google_drive::client::__fuzz;
use libfuzzer_sys::fuzz_target;

const MAX_SEGMENT_BYTES: usize = 1024;

#[derive(Arbitrary, Debug)]
struct DrivePathSegmentFuzz<'a> {
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
        7 => "file?alt=media",
        8 => "file#frag",
        9 => "file%3Falt=media",
        10 => "file%23frag",
        11 => "file%252Fbar",
        12 => "file%2523frag",
        13 => "..",
        _ => "",
    }
}

fn valid_seed(raw: u8) -> &'static str {
    match raw % 5 {
        0 => "1AbC_def-123",
        1 => "0BwwA4oUTeiV1TGRPeTVjaWRDY1E",
        2 => "drive.file.id",
        3 => "folder_001",
        _ => "shared-file-2026",
    }
}

fn candidate(input: &DrivePathSegmentFuzz<'_>) -> String {
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
    let Ok(input) = DrivePathSegmentFuzz::arbitrary(&mut unstructured) else {
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
