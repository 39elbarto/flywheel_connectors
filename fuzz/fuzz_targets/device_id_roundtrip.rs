#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::DeviceId;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
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

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);

    let from_new = DeviceId::new(candidate.to_owned());
    let from_str = DeviceId::from(candidate);
    let from_string = DeviceId::from(candidate.to_owned());

    assert_eq!(from_new.as_str(), candidate);
    assert_eq!(from_str, from_new);
    assert_eq!(from_string, from_new);
    assert_eq!(from_new.to_string(), candidate);

    let json = serde_json::to_string(&from_new).expect("DeviceId must serialize to JSON");
    assert_eq!(
        serde_json::from_str::<DeviceId>(&json).expect("JSON DeviceId must deserialize"),
        from_new
    );

    let mut cbor = Vec::new();
    ciborium::into_writer(&from_new, &mut cbor).expect("DeviceId must serialize to CBOR");
    assert_eq!(
        ciborium::from_reader::<DeviceId, _>(&cbor[..]).expect("CBOR DeviceId must deserialize"),
        from_new
    );
});
