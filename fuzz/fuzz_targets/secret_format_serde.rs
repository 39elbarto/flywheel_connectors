#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::SecretFormat;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 128;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    variant: u8,
    index: u8,
    threshold: u8,
    total: u8,
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

fn seeded_format(input: &Input) -> SecretFormat {
    match input.variant % 3 {
        0 => SecretFormat::Raw,
        1 => SecretFormat::WrappedKey,
        _ => SecretFormat::ThresholdShare {
            index: input.index,
            threshold: input.threshold,
            total: input.total,
        },
    }
}

fn assert_roundtrip(format: SecretFormat) {
    let json = serde_json::to_string(&format).expect("SecretFormat must serialize to JSON");
    assert_eq!(
        serde_json::from_str::<SecretFormat>(&json).expect("JSON SecretFormat must deserialize"),
        format
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(&format, &mut cbor).expect("SecretFormat must serialize to CBOR");
    assert_eq!(
        ciborium::from_reader::<SecretFormat, _>(&cbor[..])
            .expect("CBOR SecretFormat must deserialize"),
        format
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    assert_roundtrip(seeded_format(&input));
    assert_roundtrip(SecretFormat::Raw);
    assert_roundtrip(SecretFormat::WrappedKey);
    assert_roundtrip(SecretFormat::ThresholdShare {
        index: 1,
        threshold: 2,
        total: 3,
    });

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);
    let quoted = serde_json::to_string(candidate).expect("candidate string must serialize");

    let parsed = serde_json::from_str::<SecretFormat>(&quoted);
    match candidate {
        "raw" => assert_eq!(parsed.expect("raw must deserialize"), SecretFormat::Raw),
        "wrapped_key" => assert_eq!(
            parsed.expect("wrapped_key must deserialize"),
            SecretFormat::WrappedKey
        ),
        _ => assert!(
            parsed.is_err(),
            "non-canonical SecretFormat string accepted"
        ),
    }
});
