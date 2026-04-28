#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::HashAlgorithm;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 128;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    variant: u8,
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

fn seeded_algorithm(discriminant: u8) -> HashAlgorithm {
    match discriminant % 2 {
        0 => HashAlgorithm::Blake3_256,
        _ => HashAlgorithm::Sha256,
    }
}

fn assert_roundtrip(algorithm: HashAlgorithm, expected: &str) {
    assert_eq!(algorithm.as_str(), expected);

    let json = serde_json::to_string(&algorithm).expect("HashAlgorithm must serialize to JSON");
    assert_eq!(json, format!("\"{expected}\""));
    assert_eq!(
        serde_json::from_str::<HashAlgorithm>(&json).expect("JSON HashAlgorithm must deserialize"),
        algorithm
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(&algorithm, &mut cbor).expect("HashAlgorithm must serialize to CBOR");
    assert_eq!(
        ciborium::from_reader::<HashAlgorithm, _>(&cbor[..])
            .expect("CBOR HashAlgorithm must deserialize"),
        algorithm
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    match seeded_algorithm(input.variant) {
        HashAlgorithm::Blake3_256 => assert_roundtrip(HashAlgorithm::Blake3_256, "blake3-256"),
        HashAlgorithm::Sha256 => assert_roundtrip(HashAlgorithm::Sha256, "sha256"),
    }

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);
    let quoted = serde_json::to_string(candidate).expect("candidate string must serialize");

    let parsed = serde_json::from_str::<HashAlgorithm>(&quoted);
    match candidate {
        "blake3-256" => assert_eq!(
            parsed.expect("blake3-256 must deserialize"),
            HashAlgorithm::Blake3_256
        ),
        "sha256" => assert_eq!(
            parsed.expect("sha256 must deserialize"),
            HashAlgorithm::Sha256
        ),
        _ => assert!(
            parsed.is_err(),
            "non-canonical HashAlgorithm string accepted"
        ),
    }
});
