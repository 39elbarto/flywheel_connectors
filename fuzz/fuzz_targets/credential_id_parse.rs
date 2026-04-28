#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{CredentialId, Uuid};
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

    let credential_id = CredentialId::parse(candidate);
    let uuid = Uuid::parse_str(candidate);
    assert_eq!(
        credential_id.is_ok(),
        uuid.is_ok(),
        "CredentialId::parse must accept exactly UUID parser inputs"
    );

    if let (Ok(credential_id), Ok(uuid)) = (credential_id, uuid) {
        assert_eq!(credential_id.as_uuid(), &uuid);
        assert_eq!(CredentialId::from_uuid(uuid), credential_id);

        let displayed = credential_id.to_string();
        assert_eq!(
            CredentialId::parse(&displayed).expect("displayed CredentialId must parse"),
            credential_id
        );

        let json = serde_json::to_string(&credential_id).expect("CredentialId must serialize");
        assert_eq!(
            serde_json::from_str::<CredentialId>(&json)
                .expect("serialized CredentialId must parse"),
            credential_id
        );
    }
});
