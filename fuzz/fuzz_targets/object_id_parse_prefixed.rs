#![no_main]

//! Fuzz target for the human-facing `ObjectId::parse_prefixed` parser.
//!
//! `object_id_verifier` covers keyed object-id verification, but not the
//! manifest/user-facing parser that accepts either raw hex or `objectid:<hex>`.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::ObjectId;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    bytes: [u8; 32],
    spelling: u8,
}

fn truncate_at_char_boundary(s: &str) -> &str {
    if s.len() <= MAX_INPUT_LEN {
        return s;
    }

    let mut end = MAX_INPUT_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn assert_roundtrip(candidate: &str, expected: ObjectId) {
    let parsed = ObjectId::parse_prefixed(candidate).expect("generated object id must parse");
    assert_eq!(parsed, expected);
    assert_eq!(parsed.as_bytes(), expected.as_bytes());

    let rendered = parsed.to_prefixed_string();
    let reparsed = ObjectId::parse_prefixed(&rendered).expect("rendered ObjectId must parse again");
    assert_eq!(reparsed, parsed);
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);

    if let Ok(parsed) = ObjectId::parse_prefixed(candidate) {
        let rendered = parsed.to_prefixed_string();
        assert!(
            rendered.starts_with("objectid:"),
            "ObjectId::to_prefixed_string must keep objectid: prefix"
        );
        let reparsed =
            ObjectId::parse_prefixed(&rendered).expect("accepted ObjectId must render parseably");
        assert_eq!(
            reparsed, parsed,
            "ObjectId parse -> render -> parse round-trip lost bytes"
        );
    }

    let expected = ObjectId::from_bytes(input.bytes);
    let lower_hex = hex::encode(input.bytes);
    let upper_hex = lower_hex.to_ascii_uppercase();
    match input.spelling % 3 {
        0 => assert_roundtrip(&lower_hex, expected),
        1 => assert_roundtrip(&upper_hex, expected),
        _ => assert_roundtrip(&format!("objectid:{lower_hex}"), expected),
    }
});
