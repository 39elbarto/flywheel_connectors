#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::SbomFormat;
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

fn seeded_format(discriminant: u8) -> SbomFormat {
    match discriminant % 2 {
        0 => SbomFormat::Cyclonedx,
        _ => SbomFormat::Spdx,
    }
}

fn assert_roundtrip(format: SbomFormat, expected_json: &str) {
    let json = serde_json::to_string(&format).expect("SbomFormat must serialize to JSON");
    assert_eq!(json, format!("\"{expected_json}\""));
    assert_eq!(
        serde_json::from_str::<SbomFormat>(&json).expect("JSON SbomFormat must deserialize"),
        format
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(&format, &mut cbor).expect("SbomFormat must serialize to CBOR");
    assert_eq!(
        ciborium::from_reader::<SbomFormat, _>(&cbor[..])
            .expect("CBOR SbomFormat must deserialize"),
        format
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    match seeded_format(input.variant) {
        SbomFormat::Cyclonedx => assert_roundtrip(SbomFormat::Cyclonedx, "cyclonedx"),
        SbomFormat::Spdx => assert_roundtrip(SbomFormat::Spdx, "spdx"),
    }

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);
    let quoted = serde_json::to_string(candidate).expect("candidate string must serialize");

    let parsed = serde_json::from_str::<SbomFormat>(&quoted);
    match candidate {
        "cyclonedx" => assert_eq!(
            parsed.expect("cyclonedx must deserialize"),
            SbomFormat::Cyclonedx
        ),
        "spdx" => assert_eq!(parsed.expect("spdx must deserialize"), SbomFormat::Spdx),
        _ => assert!(parsed.is_err(), "non-canonical SbomFormat string accepted"),
    }
});
