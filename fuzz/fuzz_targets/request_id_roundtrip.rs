#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ProvisioningSessionId, RequestId};
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

fn assert_json_roundtrip<T>(value: &T)
where
    T: std::fmt::Debug + Eq + serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(value).expect("identifier must serialize to JSON");
    let decoded = serde_json::from_str::<T>(&json).expect("identifier JSON must deserialize");
    assert_eq!(&decoded, value);
}

fn assert_cbor_roundtrip<T>(value: &T)
where
    T: std::fmt::Debug + Eq + serde::Serialize + serde::de::DeserializeOwned,
{
    let mut cbor = Vec::new();
    ciborium::into_writer(value, &mut cbor).expect("identifier must serialize to CBOR");
    let decoded =
        ciborium::from_reader::<T, _>(&cbor[..]).expect("identifier CBOR must deserialize");
    assert_eq!(&decoded, value);
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);

    let request_from_new = RequestId::new(candidate.to_owned());
    let request_from_str = RequestId::from(candidate);
    let request_from_string = RequestId::from(candidate.to_owned());

    assert_eq!(request_from_new.0.as_str(), candidate);
    assert_eq!(request_from_str, request_from_new);
    assert_eq!(request_from_string, request_from_new);
    assert_eq!(request_from_new.to_string(), candidate);
    assert_json_roundtrip(&request_from_new);
    assert_cbor_roundtrip(&request_from_new);

    let session_from_new = ProvisioningSessionId::new(candidate.to_owned());
    let session_from_str = ProvisioningSessionId::from(candidate);
    let session_from_string = ProvisioningSessionId::from(candidate.to_owned());

    assert_eq!(session_from_new.as_str(), candidate);
    assert_eq!(session_from_str, session_from_new);
    assert_eq!(session_from_string, session_from_new);
    assert_eq!(session_from_new.to_string(), candidate);
    assert_json_roundtrip(&session_from_new);
    assert_cbor_roundtrip(&session_from_new);
});
