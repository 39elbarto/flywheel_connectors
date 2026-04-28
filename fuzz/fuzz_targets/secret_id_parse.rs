#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{SecretId, Uuid};
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
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);

    let secret_id = SecretId::parse(candidate);
    let uuid = Uuid::parse_str(candidate);
    assert_eq!(
        secret_id.is_ok(),
        uuid.is_ok(),
        "SecretId::parse must accept exactly UUID parser inputs"
    );

    if let (Ok(secret_id), Ok(uuid)) = (secret_id, uuid) {
        assert_eq!(secret_id.as_uuid(), &uuid);
        assert_eq!(SecretId::from_uuid(uuid), secret_id);

        let displayed = secret_id.to_string();
        assert_eq!(
            SecretId::parse(&displayed).expect("displayed SecretId must parse"),
            secret_id
        );

        let json = serde_json::to_string(&secret_id).expect("SecretId must serialize");
        assert_eq!(
            serde_json::from_str::<SecretId>(&json).expect("serialized SecretId must parse"),
            secret_id
        );
    }
});
